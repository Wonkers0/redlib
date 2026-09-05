// SPDX-License-Identifier: AGPL-3.0-only
//
// Upstream traffic telemetry, served at `/.metrics`.
//
// `/.health` answers "is this instance working". This answers "where is the
// bandwidth going". The proxy dashboard bills bytes but counts CONNECT
// tunnels, not HTTP requests, so its request column is uncorrelated with real
// load and its bytes-per-request figure is meaningless. Everything here is
// measured at the point we actually read a Reddit response, so the counts are
// real requests and the bytes are the ones we pay for.
//
// Three things it has to answer that nothing else can:
//   1. Which upstream endpoint spends the bytes (with a size distribution, not
//      just a mean - one 40 MB comment tree hides behind a thousand small
//      listings in an average).
//   2. Which *inbound* redlib route caused the call, so scout search traffic
//      can be told apart from classifier `get_subreddit` / author lookups.
//   3. How often we re-fetch a path we already fetched, which is the only
//      direct measure of the dedup gap the response cache is meant to close.

use hyper::{Body, Request, Response};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, RwLock};
use time::{macros::format_description, OffsetDateTime};

/// Samples retained per bucket for percentile estimation. Percentiles come
/// from a reservoir rather than a full log: bounded memory, and unbiased for
/// any window length, which matters when one endpoint sees a thousand times
/// the traffic of another. Totals and counts stay exact regardless.
///
/// One reservoir per hour, rotated, rather than one for all time. A single
/// reservoir samples uniformly over every observation since process start, so
/// its percentiles would silently drift from "the last day" to "all time" the
/// longer the process ran - which is exactly the question this is meant to
/// answer. Merging the last `WINDOW_HOURS` slots keeps them on a real window.
const SAMPLES_PER_HOUR: usize = 512;

/// Hours of percentile samples retained - the same 24h horizon as `per_minute`.
const WINDOW_HOURS: usize = 24;

/// Distinct full paths tracked for the re-fetch and top-talker tables. Past
/// this we stop admitting new paths but keep counting the ones already held,
/// so a pathological cardinality spike degrades the leaderboard rather than
/// the process. `paths_evicted` reports when this bites.
const MAX_TRACKED_PATHS: usize = 50_000;

/// Minute buckets in the rolling window - 24h exactly, which is the horizon
/// this was built to diagnose.
const WINDOW_MINUTES: usize = 1440;

tokio::task_local! {
	/// The redlib route serving the request that triggered an upstream call.
	/// A task-local rather than a threaded-through argument because `json()`
	/// is reached from a dozen call sites, and every one of them is already
	/// inside the request's own task.
	pub static INBOUND_ROUTE: String;
}

/// Reads the current inbound route, or `"-"` outside a request (the token
/// refresh daemon and the startup subreddit probes both call upstream).
fn current_route() -> String {
	INBOUND_ROUTE.try_with(|route| route.clone()).unwrap_or_else(|_| "-".to_string())
}

#[derive(Default)]
struct Bucket {
	requests: u64,
	/// Bytes as they crossed the wire - what the proxy bills. Taken from
	/// content-length, which for a compressed response is the compressed size.
	wire_bytes: u64,
	/// Bytes after decompression - what we actually parsed. The ratio between
	/// the two is the proof that compression is or isn't working.
	json_bytes: u64,
	wire_missing: u64,
	cache_hits: u64,
	cache_misses: u64,
	errors: u64,
	status: HashMap<u16, u64>,
	/// One reservoir per hour slot, indexed by hour-since-epoch modulo
	/// `WINDOW_HOURS`. A slot whose stamp is stale has been lapped and is
	/// cleared on first touch rather than swept, so there is no timer.
	hours: Vec<HourSlot>,
}

/// An hour's worth of samples for one bucket.
#[derive(Default, Clone)]
struct HourSlot {
	stamp: u64,
	/// Observations seen in this slot, which is the `n` the reservoir needs.
	/// Distinct from the bucket's lifetime `requests`.
	seen: u64,
	wire: Vec<u64>,
	duration: Vec<u64>,
}

impl Bucket {
	/// Reservoir sampling (Vitter's R) within one hour slot. `seen` is the
	/// count *including* this observation, so the first `SAMPLES_PER_HOUR`
	/// always land.
	fn sample(target: &mut Vec<u64>, seen: u64, value: u64) {
		if target.len() < SAMPLES_PER_HOUR {
			target.push(value);
			return;
		}
		let index = fastrand::u64(..seen);
		if (index as usize) < SAMPLES_PER_HOUR {
			target[index as usize] = value;
		}
	}

	/// The slot for the current hour, cleared first if it belongs to a
	/// previous day.
	fn slot(&mut self, hour: u64) -> &mut HourSlot {
		if self.hours.is_empty() {
			self.hours.resize(WINDOW_HOURS, HourSlot::default());
		}
		let slot = &mut self.hours[(hour as usize) % WINDOW_HOURS];
		if slot.stamp != hour {
			slot.stamp = hour;
			slot.seen = 0;
			slot.wire.clear();
			slot.duration.clear();
		}
		slot
	}

	/// Samples from the last `WINDOW_HOURS`, merged. Slots lapped by a full
	/// window are skipped rather than cleared - `record` clears them on touch.
	fn window_samples(&self, hour: u64) -> (Vec<u64>, Vec<u64>) {
		let mut wire = Vec::new();
		let mut duration = Vec::new();
		for slot in &self.hours {
			if slot.stamp == 0 || hour.saturating_sub(slot.stamp) >= WINDOW_HOURS as u64 {
				continue;
			}
			wire.extend_from_slice(&slot.wire);
			duration.extend_from_slice(&slot.duration);
		}
		(wire, duration)
	}

	fn record(&mut self, obs: &Observation, hour: u64) {
		self.requests += 1;
		self.json_bytes += obs.json_bytes;

		let billed = match obs.wire_bytes {
			Some(bytes) => bytes,
			// Chunked responses arrive without a content-length. Counting them
			// as zero would understate the bill, so they are tallied
			// separately and the decompressed size stands in for the sample.
			None => {
				self.wire_missing += 1;
				obs.json_bytes
			}
		};
		self.wire_bytes += billed;

		let duration = obs.duration_ms;
		let slot = self.slot(hour);
		slot.seen += 1;
		let seen = slot.seen;
		Self::sample(&mut slot.wire, seen, billed);
		Self::sample(&mut slot.duration, seen, duration);

		*self.status.entry(obs.status).or_insert(0) += 1;
		if obs.is_error {
			self.errors += 1;
		}
	}
}

/// One completed upstream fetch.
#[derive(Clone)]
pub struct Observation {
	pub endpoint: String,
	pub path: String,
	pub status: u16,
	pub wire_bytes: Option<u64>,
	pub json_bytes: u64,
	pub duration_ms: u64,
	pub is_error: bool,
}

#[derive(Default)]
struct PathStat {
	requests: u64,
	wire_bytes: u64,
}

#[derive(Default)]
struct Minute {
	stamp: u64,
	requests: u64,
	wire_bytes: u64,
}

#[derive(Default)]
struct State {
	by_endpoint: HashMap<String, Bucket>,
	by_route: HashMap<String, Bucket>,
	paths: HashMap<String, PathStat>,
	paths_evicted: u64,
	minutes: Vec<Minute>,
}

static STATE: LazyLock<RwLock<State>> = LazyLock::new(|| {
	let mut state = State::default();
	state.minutes.resize_with(WINDOW_MINUTES, Minute::default);
	RwLock::new(state)
});

static STARTED_AT: LazyLock<u64> = LazyLock::new(now_secs);

/// Every call into `json()`, cached or not. The gap between this and
/// `CACHE_MISSES` is the response cache's real hit rate.
static JSON_CALLS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
	OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

fn iso(secs: u64) -> Option<String> {
	if secs == 0 {
		return None;
	}
	let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
	OffsetDateTime::from_unix_timestamp(secs as i64).ok().and_then(|t| t.format(&format).ok())
}

/// Whether telemetry is collecting. Off by default: it holds full request
/// paths, which name the subreddits and posts an instance's users read.
///
/// Read straight from the environment rather than through `config::get_setting`,
/// which only resolves names present in `Config` and would silently answer
/// `None` for this one. Operational toggles go through the env, as
/// `REDLIB_BEARER_TOKEN` does.
static ENABLED: LazyLock<bool> =
	LazyLock::new(|| matches!(std::env::var("REDLIB_TELEMETRY").as_deref(), Ok("on" | "true" | "1")));

pub fn enabled() -> bool {
	*ENABLED
}

pub fn init() {
	if enabled() {
		LazyLock::force(&STATE);
		LazyLock::force(&STARTED_AT);
	}
}

/// Collapses a concrete upstream path to a template, so the thousands of
/// distinct comment threads aggregate into one `/comments/:id` row. Reddit's
/// paths are shallow and positional, which makes a rule table simpler and far
/// more predictable than guessing at which segments look like ids.
pub fn normalize_upstream(path: &str) -> String {
	let path = path.split('?').next().unwrap_or(path);
	let path = path.strip_suffix(".json").unwrap_or(path);
	let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

	match segments.as_slice() {
		["r", _, "comments", ..] => "/r/:sub/comments/:id".into(),
		["r", _, "wiki", ..] => "/r/:sub/wiki/:page".into(),
		["r", _, "about", ..] => "/r/:sub/about".into(),
		["r", _, "search"] => "/r/:sub/search".into(),
		["r", _, sort] => format!("/r/:sub/{sort}"),
		["r", _] => "/r/:sub".into(),
		["comments", ..] => "/comments/:id".into(),
		["user", _, "about"] => "/user/:name/about".into(),
		["user", _, listing] => format!("/user/:name/{listing}"),
		["user", _] => "/user/:name".into(),
		["search"] => "/search".into(),
		["subreddits", "search"] => "/subreddits/search".into(),
		[] => "/".into(),
		other => format!("/{}", other.join("/")),
	}
}

/// Rebuilds a route template from a matched path and its captured params, by
/// substituting each captured value back out. `route-recognizer` hands us the
/// params but not the pattern they came from.
pub fn normalize_inbound(path: &str, params: &route_recognizer::Params) -> String {
	let mut route = path.to_string();
	for (key, value) in params.iter() {
		if !value.is_empty() {
			route = route.replace(value, &format!(":{key}"));
		}
	}
	route
}

/// Records a call into the response cache, hit or miss. Tracked per endpoint
/// as well as globally: a low hit rate concentrated in one endpoint is a
/// different fix from one spread evenly across all of them.
pub fn note_json_call(path: &str) {
	if !enabled() {
		return;
	}
	JSON_CALLS.fetch_add(1, Ordering::Relaxed);
	if let Ok(mut state) = STATE.write() {
		state.by_endpoint.entry(normalize_upstream(path)).or_default().cache_hits += 1;
	}
}

/// Records a cache miss - i.e. a call that will actually reach Reddit. The
/// hit tally is decremented here rather than incremented on the hit path,
/// because the cache macro gives us no hook that fires only on a hit.
pub fn note_cache_miss(path: &str) {
	if !enabled() {
		return;
	}
	CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
	if let Ok(mut state) = STATE.write() {
		let bucket = state.by_endpoint.entry(normalize_upstream(path)).or_default();
		bucket.cache_hits = bucket.cache_hits.saturating_sub(1);
		bucket.cache_misses += 1;
	}
}

/// Records a completed upstream fetch against the endpoint, the inbound route
/// that caused it, the path leaderboard and the rolling minute window.
pub fn record(obs: Observation) {
	if !enabled() {
		return;
	}

	let route = current_route();
	let Ok(mut state) = STATE.write() else { return };

	let hour = now_secs() / 3600;
	state.by_endpoint.entry(obs.endpoint.clone()).or_default().record(&obs, hour);
	state.by_route.entry(route).or_default().record(&obs, hour);

	let billed = obs.wire_bytes.unwrap_or(obs.json_bytes);

	// Admit new paths only while there is room; existing ones keep counting.
	let known = state.paths.contains_key(&obs.path);
	if known || state.paths.len() < MAX_TRACKED_PATHS {
		let stat = state.paths.entry(obs.path.clone()).or_default();
		stat.requests += 1;
		stat.wire_bytes += billed;
	} else {
		state.paths_evicted += 1;
	}

	let stamp = now_secs() / 60;
	let slot = (stamp as usize) % WINDOW_MINUTES;
	let minute = &mut state.minutes[slot];
	// A stale slot is one lapped by a full window; reset rather than add, so
	// yesterday's traffic never shows up in today's curve.
	if minute.stamp != stamp {
		minute.stamp = stamp;
		minute.requests = 0;
		minute.wire_bytes = 0;
	}
	minute.requests += 1;
	minute.wire_bytes += billed;
}

/// Percentiles by nearest-rank over a copy of the reservoir.
fn percentiles(samples: &[u64]) -> serde_json::Value {
	if samples.is_empty() {
		return json!(null);
	}
	let mut sorted = samples.to_vec();
	sorted.sort_unstable();

	let at = |q: f64| -> u64 {
		let rank = (q * sorted.len() as f64).ceil() as usize;
		sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
	};

	json!({
		"p25": at(0.25),
		"p50": at(0.50),
		"p75": at(0.75),
		"p90": at(0.90),
		"p95": at(0.95),
		"p99": at(0.99),
		"max": sorted[sorted.len() - 1],
		"samples": sorted.len(),
	})
}

fn bucket_json(name: &str, bucket: &Bucket, total_bytes: u64, hour: u64) -> serde_json::Value {
	let (wire_samples, duration_samples) = bucket.window_samples(hour);
	let cache_calls = bucket.cache_hits + bucket.cache_misses;
	let cache_hit_rate = if cache_calls == 0 { 0.0 } else { bucket.cache_hits as f64 / cache_calls as f64 };

	json!({
		"name": name,
		"requests": bucket.requests,
		"wire_bytes": bucket.wire_bytes,
		"json_bytes": bucket.json_bytes,
		"share_of_wire_bytes": if total_bytes == 0 { 0.0 } else { bucket.wire_bytes as f64 / total_bytes as f64 },
		"mean_wire_bytes": if bucket.requests == 0 { 0 } else { bucket.wire_bytes / bucket.requests },
		// >1 means compression is working; ~1 means we are paying for plaintext.
		"compression_ratio": if bucket.wire_bytes == 0 { 0.0 } else { bucket.json_bytes as f64 / bucket.wire_bytes as f64 },
		"responses_without_content_length": bucket.wire_missing,
		"errors": bucket.errors,
		"cache_hits": bucket.cache_hits,
		"cache_misses": bucket.cache_misses,
		"cache_hit_rate": cache_hit_rate,
		"status": bucket.status.iter().map(|(k, v)| (k.to_string(), *v)).collect::<HashMap<String, u64>>(),
		// Percentiles describe the last WINDOW_HOURS; the counters above are
		// lifetime. Both are wanted, so the report says which is which.
		"wire_bytes_percentiles": percentiles(&wire_samples),
		"duration_ms_percentiles": percentiles(&duration_samples),
	})
}

/// Handles the `/.metrics` endpoint. Inherits the instance bearer token: it is
/// not on the auth exemption list in `server.rs`, unlike `/.health`.
pub async fn metrics(_req: Request<Body>) -> Result<Response<Body>, String> {
	if !enabled() {
		let body = json!({ "enabled": false, "hint": "set REDLIB_TELEMETRY=on" });
		return Response::builder()
			.status(503)
			.header("content-type", "application/json")
			.header("cache-control", "no-store")
			.body(Body::from(body.to_string()))
			.map_err(|err| format!("{err}"));
	}

	let body = serde_json::to_string(&snapshot()).map_err(|err| format!("{err}"))?;
	Response::builder()
		.status(200)
		.header("content-type", "application/json")
		.header("cache-control", "no-store")
		.body(Body::from(body))
		.map_err(|err| format!("{err}"))
}

fn snapshot() -> serde_json::Value {
	let Ok(state) = STATE.read() else {
		return json!({ "error": "telemetry state poisoned" });
	};

	let total_bytes: u64 = state.by_endpoint.values().map(|b| b.wire_bytes).sum();
	let total_requests: u64 = state.by_endpoint.values().map(|b| b.requests).sum();

	let mut endpoints: Vec<_> = state.by_endpoint.iter().collect();
	endpoints.sort_by_key(|(_, b)| std::cmp::Reverse(b.wire_bytes));

	let mut routes: Vec<_> = state.by_route.iter().collect();
	routes.sort_by_key(|(_, b)| std::cmp::Reverse(b.wire_bytes));

	// The two path leaderboards answer different questions: heaviest is "what
	// costs the most", refetched is "what did we pay for more than once".
	let mut by_bytes: Vec<_> = state.paths.iter().collect();
	by_bytes.sort_by_key(|(_, s)| std::cmp::Reverse(s.wire_bytes));

	let mut by_repeat: Vec<_> = state.paths.iter().filter(|(_, s)| s.requests > 1).collect();
	by_repeat.sort_by_key(|(_, s)| std::cmp::Reverse(s.requests));

	let repeated_requests: u64 = state.paths.values().filter(|s| s.requests > 1).map(|s| s.requests - 1).sum();
	let repeated_bytes: u64 = state
		.paths
		.values()
		.filter(|s| s.requests > 1)
		.map(|s| s.wire_bytes - (s.wire_bytes / s.requests))
		.sum();

	let calls = JSON_CALLS.load(Ordering::Relaxed);
	let misses = CACHE_MISSES.load(Ordering::Relaxed);

	let hour = now_secs() / 3600;
	let current = now_secs() / 60;
	let mut minutes: Vec<serde_json::Value> = state
		.minutes
		.iter()
		.filter(|m| m.stamp != 0 && current.saturating_sub(m.stamp) < WINDOW_MINUTES as u64)
		.map(|m| json!({ "minute": iso(m.stamp * 60), "requests": m.requests, "wire_bytes": m.wire_bytes }))
		.collect();
	minutes.sort_by(|a, b| a["minute"].as_str().cmp(&b["minute"].as_str()));

	json!({
		"enabled": true,
		"collecting_since": iso(*STARTED_AT),
		// Counters and totals are lifetime; percentiles and per_minute cover
		// this window. Said plainly so a long-lived process is not misread.
		"percentile_window_hours": WINDOW_HOURS,
		"uptime_seconds": now_secs().saturating_sub(*STARTED_AT),
		"totals": {
			"upstream_requests": total_requests,
			"upstream_wire_bytes": total_bytes,
			"upstream_json_bytes": state.by_endpoint.values().map(|b| b.json_bytes).sum::<u64>(),
			"errors": state.by_endpoint.values().map(|b| b.errors).sum::<u64>(),
		},
		// The claim under test: a 100-entry / 30s cache at this request rate
		// has an effectively zero hit rate.
		"response_cache": {
			"calls": calls,
			"hits": calls.saturating_sub(misses),
			"misses": misses,
			"hit_rate": if calls == 0 { 0.0 } else { calls.saturating_sub(misses) as f64 / calls as f64 },
		},
		// Bytes spent on paths fetched more than once in the window. This is
		// the ceiling on what a bigger cache or cross-feed dedup could save.
		"duplication": {
			"distinct_paths": state.paths.len(),
			"redundant_requests": repeated_requests,
			"redundant_wire_bytes": repeated_bytes,
			"redundant_share_of_bytes": if total_bytes == 0 { 0.0 } else { repeated_bytes as f64 / total_bytes as f64 },
			"paths_untracked_over_cap": state.paths_evicted,
		},
		"by_upstream_endpoint": endpoints.iter().map(|(name, b)| bucket_json(name, b, total_bytes, hour)).collect::<Vec<_>>(),
		"by_inbound_route": routes.iter().map(|(name, b)| bucket_json(name, b, total_bytes, hour)).collect::<Vec<_>>(),
		"heaviest_paths": by_bytes.iter().take(50)
			.map(|(path, s)| json!({ "path": path, "requests": s.requests, "wire_bytes": s.wire_bytes }))
			.collect::<Vec<_>>(),
		"most_refetched_paths": by_repeat.iter().take(50)
			.map(|(path, s)| json!({ "path": path, "requests": s.requests, "wire_bytes": s.wire_bytes }))
			.collect::<Vec<_>>(),
		"per_minute": minutes,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use sealed_test::prelude::*;

	#[test]
	fn normalizes_upstream_paths() {
		assert_eq!(normalize_upstream("/r/rust/comments/abc123/title.json?raw_json=1"), "/r/:sub/comments/:id");
		assert_eq!(normalize_upstream("/comments/abc123.json?sort=top"), "/comments/:id");
		assert_eq!(normalize_upstream("/r/rust/about.json?raw_json=1"), "/r/:sub/about");
		assert_eq!(normalize_upstream("/r/rust/hot.json?raw_json=1"), "/r/:sub/hot");
		assert_eq!(normalize_upstream("/user/spez/about.json"), "/user/:name/about");
		assert_eq!(normalize_upstream("/user/spez/submitted.json?raw_json=1"), "/user/:name/submitted");
		assert_eq!(normalize_upstream("/r/rust/search.json?q=x"), "/r/:sub/search");
		assert_eq!(normalize_upstream("/search.json?q=x"), "/search");
	}

	#[test]
	fn percentiles_are_nearest_rank() {
		let samples: Vec<u64> = (1..=100).collect();
		let p = percentiles(&samples);
		assert_eq!(p["p50"], 50);
		assert_eq!(p["p99"], 99);
		assert_eq!(p["max"], 100);
	}

	#[test]
	fn percentiles_of_nothing_are_null() {
		assert!(percentiles(&[]).is_null());
	}

	/// End-to-end over the real recording path: enable collection, feed a
	/// skewed mix of observations, and assert the snapshot separates the one
	/// fat endpoint from the many thin ones - which is the whole point of
	/// reporting percentiles rather than a mean.
	#[sealed_test(env = [("REDLIB_TELEMETRY", "on")])]
	fn snapshot_reports_bytes_and_duplication_by_endpoint() {
		assert!(enabled(), "toggle must be read from the environment");

		// One heavy comment thread, fetched three times over (the dedup gap).
		for _ in 0..3 {
			record(Observation {
				endpoint: normalize_upstream("/comments/abc.json"),
				path: "/comments/abc".into(),
				status: 200,
				wire_bytes: Some(4_000_000),
				json_bytes: 32_000_000,
				duration_ms: 900,
				is_error: false,
			});
		}
		// A spread of small subreddit lookups, each distinct.
		for n in 0..50u64 {
			record(Observation {
				endpoint: normalize_upstream("/r/rust/about.json"),
				path: format!("/r/sub{n}/about"),
				status: 200,
				wire_bytes: Some(2_000),
				json_bytes: 9_000,
				duration_ms: 40,
				is_error: false,
			});
		}

		let snap = snapshot();
		assert_eq!(snap["totals"]["upstream_requests"], 53);
		assert_eq!(snap["totals"]["upstream_wire_bytes"], 12_100_000);

		// Heaviest endpoint sorts first, and its percentiles are its own -
		// not diluted by the 50 small calls.
		let top = &snap["by_upstream_endpoint"][0];
		assert_eq!(top["name"], "/comments/:id");
		assert_eq!(top["requests"], 3);
		assert_eq!(top["wire_bytes_percentiles"]["p50"], 4_000_000);
		assert_eq!(top["compression_ratio"], 8.0);

		let small = &snap["by_upstream_endpoint"][1];
		assert_eq!(small["name"], "/r/:sub/about");
		assert_eq!(small["wire_bytes_percentiles"]["p99"], 2_000);

		// Two of the three thread fetches were redundant.
		assert_eq!(snap["duplication"]["distinct_paths"], 51);
		assert_eq!(snap["duplication"]["redundant_requests"], 2);
		assert_eq!(snap["duplication"]["redundant_wire_bytes"], 8_000_000);

		// Traffic lands in the rolling window, not just the totals.
		let minutes = snap["per_minute"].as_array().expect("per_minute is an array");
		assert_eq!(minutes.iter().map(|m| m["requests"].as_u64().unwrap()).sum::<u64>(), 53);
	}

	#[sealed_test(env = [("REDLIB_TELEMETRY", "on")])]
	fn cache_hit_rate_counts_hits_as_calls_minus_misses() {
		// Three calls, one of which reached Reddit.
		note_json_call("/comments/abc.json");
		note_cache_miss("/comments/abc.json");
		note_json_call("/comments/abc.json");
		note_json_call("/comments/abc.json");

		let snap = snapshot();
		assert_eq!(snap["response_cache"]["calls"], 3);
		assert_eq!(snap["response_cache"]["misses"], 1);
		assert_eq!(snap["response_cache"]["hits"], 2);

		let bucket = &snap["by_upstream_endpoint"][0];
		assert_eq!(bucket["cache_hits"], 2);
		assert_eq!(bucket["cache_misses"], 1);
	}

	/// The reason for rotating reservoirs at all: yesterday's sizes must not
	/// survive into today's percentiles.
	#[test]
	fn percentile_window_drops_hours_older_than_the_window() {
		let mut bucket = Bucket::default();
		let hour = 1_000_000u64;

		let old = Observation {
			endpoint: "/comments/:id".into(),
			path: "/comments/old".into(),
			status: 200,
			wire_bytes: Some(9_000_000),
			json_bytes: 9_000_000,
			duration_ms: 5,
			is_error: false,
		};
		let new = Observation { wire_bytes: Some(1_000), path: "/comments/new".into(), ..old.clone() };

		bucket.record(&old, hour);
		assert_eq!(bucket.window_samples(hour).0, vec![9_000_000]);

		// One hour later both are in the window.
		bucket.record(&new, hour + 1);
		let (mut wire, _) = bucket.window_samples(hour + 1);
		wire.sort_unstable();
		assert_eq!(wire, vec![1_000, 9_000_000]);

        // A full window on, the old hour has aged out but the newer one has not.
		let (wire, _) = bucket.window_samples(hour + WINDOW_HOURS as u64);
		assert_eq!(wire, vec![1_000]);

		// Beyond the window, nothing survives - while the lifetime counters do.
		assert!(bucket.window_samples(hour + WINDOW_HOURS as u64 + 1).0.is_empty());
		assert_eq!(bucket.requests, 2);
		assert_eq!(bucket.wire_bytes, 9_001_000);
	}

	/// A slot reused a full day later must be cleared, not appended to.
	#[test]
	fn lapped_hour_slot_is_reset_rather_than_appended() {
		let mut bucket = Bucket::default();
		let obs = Observation {
			endpoint: "/comments/:id".into(),
			path: "/comments/a".into(),
			status: 200,
			wire_bytes: Some(500),
			json_bytes: 500,
			duration_ms: 1,
			is_error: false,
		};

		let hour = 1_000_000u64;
		bucket.record(&obs, hour);
		// Same slot index, exactly one window later.
		bucket.record(&obs, hour + WINDOW_HOURS as u64);

		let (wire, _) = bucket.window_samples(hour + WINDOW_HOURS as u64);
		assert_eq!(wire, vec![500], "the lapped slot kept a stale sample");
	}

	#[test]
	fn disabled_by_default_records_nothing() {
		assert!(!enabled());
		record(Observation {
			endpoint: "/comments/:id".into(),
			path: "/comments/abc".into(),
			status: 200,
			wire_bytes: Some(1_000),
			json_bytes: 1_000,
			duration_ms: 1,
			is_error: false,
		});
		assert_eq!(snapshot()["totals"]["upstream_requests"], 0);
	}
}
