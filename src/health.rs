// SPDX-License-Identifier: AGPL-3.0-only
//
// Operational health for this instance, served at `/.health`.
//
// Railway can only tell us the process is listening. Since a failed OAuth
// roll-over now leaves us up but degraded rather than exiting, "listening" and
// "working" came apart - this endpoint is what closes that gap. It reports the
// OAuth token's age and backend, Reddit's own rate-limit accounting as of the
// last upstream response, and whether the most recent upstream call succeeded.

use crate::client::{OAUTH_CLIENT, OAUTH_IS_ROLLING_OVER, OAUTH_RATELIMIT_REMAINING};
use hyper::{Body, Request, Response};
use serde_json::json;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{LazyLock, RwLock};
use time::{macros::format_description, OffsetDateTime};

/// Rate-limit headroom below which we call the instance degraded. The client
/// spawns a roll-over under 10, so sitting at or below that means roll-over is
/// not keeping up.
const RATELIMIT_DEGRADED_BELOW: u16 = 10;

/// How long a roll-over may stay in flight before we treat it as wedged. A
/// healthy one completes in seconds; the retry backoff holds the flag across a
/// failure, so a long-held flag means we are failing repeatedly.
const ROLLOVER_STUCK_AFTER_SECS: u64 = 300;

static STARTED_AT: LazyLock<u64> = LazyLock::new(now_secs);

static TOKEN_ISSUED_AT: AtomicU64 = AtomicU64::new(0);
static LAST_ROLLOVER_OK_AT: AtomicU64 = AtomicU64::new(0);
static LAST_ROLLOVER_FAIL_AT: AtomicU64 = AtomicU64::new(0);
static ROLLOVER_FAILURES: AtomicU64 = AtomicU64::new(0);

static RATELIMIT_RESET_AT: AtomicU64 = AtomicU64::new(0);
static RATELIMIT_USED: AtomicU16 = AtomicU16::new(0);
static RATELIMIT_SEEN_AT: AtomicU64 = AtomicU64::new(0);

static UPSTREAM_LAST_STATUS: AtomicU16 = AtomicU16::new(0);
static UPSTREAM_OK_AT: AtomicU64 = AtomicU64::new(0);
static UPSTREAM_ERR_AT: AtomicU64 = AtomicU64::new(0);
static UPSTREAM_REQUESTS: AtomicU64 = AtomicU64::new(0);
static UPSTREAM_ERRORS: AtomicU64 = AtomicU64::new(0);

static UPSTREAM_LAST_ERROR: RwLock<Option<String>> = RwLock::new(None);

/// Stamp the process start time. Called during startup so uptime is measured
/// from boot rather than from the first health check.
pub fn init() {
	LazyLock::force(&STARTED_AT);
}

fn now_secs() -> u64 {
	OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

/// Format a stored timestamp as UTC ISO-8601. Zero means "never happened".
fn iso(secs: u64) -> Option<String> {
	if secs == 0 {
		return None;
	}
	let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
	OffsetDateTime::from_unix_timestamp(secs as i64).ok().and_then(|t| t.format(&format).ok())
}

/// Seconds elapsed since a stored timestamp, or `None` if it never happened.
fn age(secs: u64) -> Option<u64> {
	if secs == 0 {
		None
	} else {
		Some(now_secs().saturating_sub(secs))
	}
}

/// Record that a fresh OAuth token is now in use.
pub fn note_token_issued() {
	TOKEN_ISSUED_AT.store(now_secs(), Ordering::SeqCst);
}

/// Record a roll-over that produced a new client.
pub fn note_rollover_success() {
	LAST_ROLLOVER_OK_AT.store(now_secs(), Ordering::SeqCst);
	note_token_issued();
}

/// Record a roll-over that exhausted both backends and kept the old client.
pub fn note_rollover_failure() {
	LAST_ROLLOVER_FAIL_AT.store(now_secs(), Ordering::SeqCst);
	ROLLOVER_FAILURES.fetch_add(1, Ordering::SeqCst);
}

/// Record Reddit's rate-limit headers from an upstream response.
pub fn note_ratelimit(reset_in: Option<f32>, used: Option<f32>) {
	let now = now_secs();
	if let Some(reset_in) = reset_in {
		RATELIMIT_RESET_AT.store(now.saturating_add(reset_in.max(0.0).round() as u64), Ordering::SeqCst);
	}
	if let Some(used) = used {
		RATELIMIT_USED.store(used.max(0.0).round() as u16, Ordering::SeqCst);
	}
	RATELIMIT_SEEN_AT.store(now, Ordering::SeqCst);
}

/// Record the outcome of an upstream Reddit request.
pub fn note_upstream(status: u16, error: Option<String>) {
	UPSTREAM_REQUESTS.fetch_add(1, Ordering::SeqCst);
	UPSTREAM_LAST_STATUS.store(status, Ordering::SeqCst);

	match error {
		Some(message) => {
			UPSTREAM_ERRORS.fetch_add(1, Ordering::SeqCst);
			UPSTREAM_ERR_AT.store(now_secs(), Ordering::SeqCst);
			if let Ok(mut slot) = UPSTREAM_LAST_ERROR.write() {
				*slot = Some(message);
			}
		}
		None => {
			UPSTREAM_OK_AT.store(now_secs(), Ordering::SeqCst);
		}
	}
}

/// Handles the `/.health` endpoint.
pub async fn health(_req: Request<Body>) -> Result<Response<Body>, String> {
	let body = serde_json::to_string(&snapshot()).map_err(|err| format!("{err}"))?;

	Response::builder()
		.status(200)
		.header("content-type", "application/json")
		.header("cache-control", "no-store")
		.body(Body::from(body))
		.map_err(|err| format!("{err}"))
}

fn snapshot() -> serde_json::Value {
	let client = OAUTH_CLIENT.load_full();
	let remaining = OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst);
	let rolling_over = OAUTH_IS_ROLLING_OVER.load(Ordering::SeqCst);

	let token_age = age(TOKEN_ISSUED_AT.load(Ordering::SeqCst));
	let expires_in = client.expires_in();

	// A roll-over that has been in flight far longer than a healthy one takes
	// is stuck. We date it from the last failure, since the retry backoff holds
	// the flag; with no failure recorded yet, fall back to process start.
	let rollover_since = match LAST_ROLLOVER_FAIL_AT.load(Ordering::SeqCst) {
		0 => *STARTED_AT,
		at => at,
	};
	let rollover_stuck = rolling_over && age(rollover_since).unwrap_or(0) > ROLLOVER_STUCK_AFTER_SECS;

	// The token outliving its own expiry means the refresh daemon is not
	// running - requests will start failing once Reddit notices.
	let token_expired = matches!(token_age, Some(a) if a > expires_in);

	let ok_at = UPSTREAM_OK_AT.load(Ordering::SeqCst);
	let err_at = UPSTREAM_ERR_AT.load(Ordering::SeqCst);
	let last_call_failed = err_at > 0 && err_at >= ok_at;

	let degraded = rollover_stuck || token_expired || last_call_failed || remaining <= RATELIMIT_DEGRADED_BELOW;

	// Name what is wrong, so the dashboard and the page it sends can say why
	// rather than just showing a red dot.
	let mut reasons: Vec<&str> = Vec::new();
	if rollover_stuck {
		reasons.push("oauth_rollover_stuck");
	}
	if token_expired {
		reasons.push("oauth_token_expired");
	}
	if last_call_failed {
		reasons.push("last_upstream_request_failed");
	}
	if remaining <= RATELIMIT_DEGRADED_BELOW {
		reasons.push("ratelimit_exhausted");
	}

	let reset_at = RATELIMIT_RESET_AT.load(Ordering::SeqCst);

	json!({
		"status": if degraded { "degraded" } else { "ok" },
		"reasons": reasons,
		"version": env!("CARGO_PKG_VERSION"),
		"uptime_seconds": age(*STARTED_AT).unwrap_or(0),
		"oauth": {
			"backend": client.backend_kind(),
			"token_age_seconds": token_age,
			"token_expires_in_seconds": expires_in,
			"rolling_over": rolling_over,
			"last_rollover_success": iso(LAST_ROLLOVER_OK_AT.load(Ordering::SeqCst)),
			"last_rollover_failure": iso(LAST_ROLLOVER_FAIL_AT.load(Ordering::SeqCst)),
			"rollover_failures_total": ROLLOVER_FAILURES.load(Ordering::SeqCst),
		},
		"ratelimit": {
			"remaining": remaining,
			"used": RATELIMIT_USED.load(Ordering::SeqCst),
			"resets_in_seconds": reset_at.checked_sub(now_secs()).filter(|_| reset_at > 0),
			"last_seen": iso(RATELIMIT_SEEN_AT.load(Ordering::SeqCst)),
		},
		"upstream": {
			"last_status": match UPSTREAM_LAST_STATUS.load(Ordering::SeqCst) {
				0 => None,
				status => Some(status),
			},
			"last_success": iso(ok_at),
			"last_error": iso(err_at),
			"last_error_message": UPSTREAM_LAST_ERROR.read().ok().and_then(|slot| slot.clone()),
			"requests_total": UPSTREAM_REQUESTS.load(Ordering::SeqCst),
			"errors_total": UPSTREAM_ERRORS.load(Ordering::SeqCst),
		},
	})
}
