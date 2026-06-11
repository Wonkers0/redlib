//! REST API (JSON) for Redlib.
//!
//! These handlers reuse the same data-fetching logic as the HTML front-end
//! (see [`crate::utils::Post::fetch`], [`crate::subreddit::subreddit`], etc.)
//! but serialize the resulting structs to JSON instead of rendering Askama
//! templates. All endpoints live under `/api/v1`.

#![allow(clippy::cmp_owned)]

use crate::client::json;
use crate::post::parse_comments;
use crate::search::search_subreddits;
use crate::subreddit::{can_access_quarantine, subreddit};
use crate::user::user;
use crate::utils::{param, parse_post, Post};
use crate::server::RequestExt;
use hyper::{Body, Request, Response};
use std::collections::HashSet;

// HELPERS

/// Build a JSON response with the given status code from any serializable value.
fn json_response<T: serde::Serialize>(status: u16, value: &T) -> Result<Response<Body>, String> {
	let body = serde_json::to_string(value).map_err(|e| format!("Failed to serialize response: {e}"))?;
	Response::builder()
		.status(status)
		.header("content-type", "application/json")
		.body(body.into())
		.map_err(|e| e.to_string())
}

/// Build a `200 OK` JSON response.
fn ok_json<T: serde::Serialize>(value: &T) -> Result<Response<Body>, String> {
	json_response(200, value)
}

/// Build a JSON error response, mapping known upstream error strings to a
/// sensible HTTP status code.
fn api_error(msg: &str) -> Result<Response<Body>, String> {
	let status = match msg {
		"private" | "quarantined" | "gated" => 403,
		"banned" | "No posts found" => 404,
		_ => 502,
	};
	json_response(status, &serde_json::json!({ "error": msg }))
}

/// Build a `400 Bad Request` JSON response for a client-side error.
fn bad_request(msg: &str) -> Result<Response<Body>, String> {
	json_response(400, &serde_json::json!({ "error": msg }))
}

// ENDPOINTS

/// `GET /api/v1` — list the available endpoints.
pub async fn index(_req: Request<Body>) -> Result<Response<Body>, String> {
	ok_json(&serde_json::json!({
		"version": env!("CARGO_PKG_VERSION"),
		"endpoints": {
			"subreddit": "/api/v1/r/{subreddit}[/{sort}]?after=&t=",
			"post":      "/api/v1/r/{subreddit}/comments/{id}  (also /api/v1/comments/{id})",
			"user":      "/api/v1/user/{name}[/{listing}]?sort=&after=&t=",
			"search":    "/api/v1/search?q=  (also /api/v1/r/{subreddit}/search?q=)",
		},
	}))
}

/// `GET /api/v1/r/:sub[/:sort]` — a subreddit's post listing with metadata.
///
/// Supports multireddits (`a+b+c`) and the special `popular`/`all` feeds, plus
/// the usual `after`/`t` query parameters for pagination and time-filtering.
pub async fn subreddit_listing(req: Request<Body>) -> Result<Response<Body>, String> {
	let sub_name = req.param("sub").unwrap_or_default();
	let sort = req.param("sort").unwrap_or_else(|| "hot".to_string());
	let quarantined = can_access_quarantine(&req, &sub_name);
	let query = req.uri().query().unwrap_or_default();

	let path = format!("/r/{}/{sort}.json?{query}&raw_json=1", sub_name.replace('+', "%2B"));

	// Subreddit metadata only exists for a single, real subreddit.
	let sub_meta = if !sub_name.contains('+') && sub_name != "popular" && sub_name != "all" {
		subreddit(&sub_name, quarantined).await.ok()
	} else {
		None
	};

	match Post::fetch(&path, quarantined).await {
		Ok((posts, after)) => ok_json(&serde_json::json!({
			"subreddit": sub_meta,
			"sort": sort,
			"posts": posts,
			"after": after,
		})),
		Err(msg) => api_error(&msg),
	}
}

/// `GET /api/v1/r/:sub/comments/:id` (and `/api/v1/comments/:id`) — a single
/// post together with its (nested) comment tree.
pub async fn post_item(req: Request<Body>) -> Result<Response<Body>, String> {
	let sub = req.param("sub").unwrap_or_default();
	let id = req.param("id").unwrap_or_default();
	let quarantined = can_access_quarantine(&req, &sub);
	let query = req.uri().query().unwrap_or_default();

	let path = if sub.is_empty() {
		format!("/comments/{id}.json?{query}&raw_json=1")
	} else {
		format!("/r/{sub}/comments/{id}.json?{query}&raw_json=1")
	};

	match json(path, quarantined).await {
		Ok(response) => {
			let post = parse_post(&response[0]["data"]["children"][0]).await;
			// API consumers don't carry cookie-based filters, so pass an empty set.
			let filters = HashSet::new();
			let comments = parse_comments(&response[1], &post.permalink, &post.author.name, "", &filters, &req);
			ok_json(&serde_json::json!({ "post": post, "comments": comments }))
		}
		Err(msg) => api_error(&msg),
	}
}

/// `GET /api/v1/user/:name[/:listing]` — a user's profile metadata and their
/// overview/submitted/comments listing.
pub async fn user_profile(req: Request<Body>) -> Result<Response<Body>, String> {
	let name = req.param("name").unwrap_or_default();
	let listing = req.param("listing").unwrap_or_else(|| "overview".to_string());
	let query = req.uri().query().unwrap_or_default();

	let path = format!("/user/{name}/{listing}.json?{query}&raw_json=1");
	let user_meta = user(&name).await.ok();

	match Post::fetch(&path, false).await {
		Ok((posts, after)) => ok_json(&serde_json::json!({
			"user": user_meta,
			"listing": listing,
			"posts": posts,
			"after": after,
		})),
		Err(msg) => api_error(&msg),
	}
}

/// `GET /api/v1/search` (and `/api/v1/r/:sub/search`) — search posts, and
/// (unless `restrict_sr` is set) matching subreddits. Requires `q`.
pub async fn search_endpoint(req: Request<Body>) -> Result<Response<Body>, String> {
	let sub = req.param("sub").unwrap_or_default();
	let quarantined = can_access_quarantine(&req, &sub);
	let query = req.uri().query().unwrap_or_default();
	let query_str = format!("?{query}");

	let q = param(&query_str, "q").unwrap_or_default();
	if q.is_empty() {
		return bad_request("Missing required query parameter: q");
	}

	let path = if sub.is_empty() {
		format!("/search.json?{query}&raw_json=1")
	} else {
		format!("/r/{sub}/search.json?{query}&raw_json=1")
	};

	let typed = param(&query_str, "type").unwrap_or_default();
	let subreddits = if param(&query_str, "restrict_sr").is_none() {
		search_subreddits(&q, &typed).await
	} else {
		Vec::new()
	};

	match Post::fetch(&path, quarantined).await {
		Ok((posts, after)) => ok_json(&serde_json::json!({
			"query": q,
			"posts": posts,
			"subreddits": subreddits,
			"after": after,
		})),
		Err(msg) => api_error(&msg),
	}
}
