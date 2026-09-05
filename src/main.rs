// Global specifiers
#![forbid(unsafe_code)]
#![allow(clippy::cmp_owned)]

use clap::{Arg, ArgAction, Command};
use pretty_env_logger::env_logger;
use std::sync::LazyLock;

use futures_lite::FutureExt;
use hyper::header::HeaderValue;
use log::{info, warn};
use redlib::client::{proxy, rate_limit_check};
use redlib::server;
use redlib::utils::error;
use redlib::{api, config, headers, health, instance_info, telemetry};

use redlib::client::OAUTH_CLIENT;

#[tokio::main]
async fn main() {
	// Load environment variables
	_ = dotenvy::dotenv();

	// Initialize logger
	init_logger();

	let matches = Command::new("Redlib")
		.version(env!("CARGO_PKG_VERSION"))
		.about("Private front-end for Reddit written in Rust ")
		.arg(Arg::new("ipv4-only").short('4').long("ipv4-only").help("Listen on IPv4 only").num_args(0))
		.arg(Arg::new("ipv6-only").short('6').long("ipv6-only").help("Listen on IPv6 only").num_args(0))
		.arg(
			Arg::new("redirect-https")
				.short('r')
				.long("redirect-https")
				.help("Redirect all HTTP requests to HTTPS (no longer functional)")
				.num_args(0),
		)
		.arg(
			Arg::new("address")
				.short('a')
				.long("address")
				.value_name("ADDRESS")
				.help("Sets address to listen on")
				.default_value("[::]")
				.num_args(1),
		)
		.arg(
			Arg::new("port")
				.short('p')
				.long("port")
				.value_name("PORT")
				.env("PORT")
				.help("Port to listen on")
				.default_value("8080")
				.action(ArgAction::Set)
				.num_args(1),
		)
		.arg(
			Arg::new("hsts")
				.short('H')
				.long("hsts")
				.value_name("EXPIRE_TIME")
				.help("HSTS header to tell browsers that this site should only be accessed over HTTPS")
				.default_value("604800")
				.num_args(1),
		)
		.get_matches();

	match rate_limit_check().await {
		Ok(()) => {
			info!("[✅] Rate limit check passed");
		}
		Err(e) => {
			let mut message = format!("Rate limit check failed: {e}");
			message += "\nThis may cause issues with the rate limit.";
			message += "\nPlease report this error with the above information.";
			message += "\nhttps://github.com/redlib-org/redlib/issues/new?assignees=sigaloid&labels=bug&title=%F0%9F%90%9B+Bug+Report%3A+Rate+limit+mismatch";
			warn!("{}", message);
			eprintln!("{message}");
		}
	}

	let address = matches.get_one::<String>("address").unwrap();
	let port = matches.get_one::<String>("port").unwrap();
	let hsts = matches.get_one("hsts").map(|m: &String| m.as_str());

	let ipv4_only = std::env::var("IPV4_ONLY").is_ok() || matches.get_flag("ipv4-only");
	let ipv6_only = std::env::var("IPV6_ONLY").is_ok() || matches.get_flag("ipv6-only");

	let listener = if ipv4_only {
		format!("0.0.0.0:{port}")
	} else if ipv6_only {
		format!("[::]:{port}")
	} else {
		[address, ":", port].concat()
	};

	println!("Starting Redlib...");

	// Begin constructing a server
	let mut app = server::Server::new();

	// Force evaluation of statics. In instance_info case, we need to evaluate
	// the timestamp so deploy date is accurate - in config case, we need to
	// evaluate the configuration to avoid paying penalty at first request -
	// in OAUTH case, we need to retrieve the token to avoid paying penalty
	// at first request

	health::init();
	telemetry::init();

	info!("Evaluating config.");
	LazyLock::force(&config::CONFIG);
	info!("Evaluating instance info.");
	LazyLock::force(&instance_info::INSTANCE_INFO);
	info!("Creating OAUTH client.");
	LazyLock::force(&OAUTH_CLIENT);

	// Define default headers (added to all responses)
	app.default_headers = headers! {
		"Referrer-Policy" => "no-referrer",
		"X-Content-Type-Options" => "nosniff",
		"X-Frame-Options" => "DENY",
		"Content-Security-Policy" => "default-src 'none'; font-src 'self'; script-src 'self' blob:; manifest-src 'self'; media-src 'self' data: blob: about:; style-src 'self' 'unsafe-inline'; base-uri 'none'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; connect-src 'self'; worker-src blob:;"
	};

	if let Some(expire_time) = hsts {
		if let Ok(val) = HeaderValue::from_str(&format!("max-age={expire_time}")) {
			app.default_headers.insert("Strict-Transport-Security", val);
		}
	}

	// Proxy media through Redlib
	app.at("/vid/:id/:size").get(|r| proxy(r, "https://v.redd.it/{id}/DASH_{size}").boxed());
	app.at("/hls/:id/*path").get(|r| proxy(r, "https://v.redd.it/{id}/{path}").boxed());
	app.at("/img/*path").get(|r| proxy(r, "https://i.redd.it/{path}").boxed());
	app.at("/thumb/:point/:id").get(|r| proxy(r, "https://{point}.thumbs.redditmedia.com/{id}").boxed());
	app.at("/emoji/:id/:name").get(|r| proxy(r, "https://emoji.redditmedia.com/{id}/{name}").boxed());
	app
		.at("/emote/:subreddit_id/:filename")
		.get(|r| proxy(r, "https://reddit-econ-prod-assets-permanent.s3.amazonaws.com/asset-manager/{subreddit_id}/{filename}").boxed());
	app
		.at("/preview/:loc/award_images/:fullname/:id")
		.get(|r| proxy(r, "https://{loc}view.redd.it/award_images/{fullname}/{id}").boxed());
	app.at("/preview/:loc/:id").get(|r| proxy(r, "https://{loc}view.redd.it/{id}").boxed());
	app.at("/style/*path").get(|r| proxy(r, "https://styles.redditmedia.com/{path}").boxed());
	app.at("/static/*path").get(|r| proxy(r, "https://www.redditstatic.com/{path}").boxed());

	// Operational health, for the status dashboard. Deliberately outside the
	// bearer-token gate so an unauthenticated probe can still tell up from
	// degraded - it exposes no Reddit content, only our own counters.
	app.at("/.health").get(|r| health::health(r).boxed());

	// Upstream traffic telemetry. Unlike /.health this stays *inside* the
	// bearer-token gate: it reports the paths we fetched, which name the
	// subreddits and posts this instance's users read.
	app.at("/.metrics").get(|r| telemetry::metrics(r).boxed());

	// REST API (JSON) under /api/v1
	app.at("/api/v1").get(|r| api::index(r).boxed());
	app.at("/api/v1/search").get(|r| api::search_endpoint(r).boxed());
	app.at("/api/v1/comments/:id").get(|r| api::post_item(r).boxed());
	app.at("/api/v1/user/:name").get(|r| api::user_profile(r).boxed());
	app.at("/api/v1/user/:name/:listing").get(|r| api::user_profile(r).boxed());
	app.at("/api/v1/r/:sub").get(|r| api::subreddit_listing(r).boxed());
	app.at("/api/v1/r/:sub/search").get(|r| api::search_endpoint(r).boxed());
	app.at("/api/v1/r/:sub/comments/:id").get(|r| api::post_item(r).boxed());
	app.at("/api/v1/r/:sub/:sort").get(|r| api::subreddit_listing(r).boxed());

	// Default service in case no routes match
	app.at("/*").get(|req| error(req, "Nothing here").boxed());

	println!("Running Redlib v{} on {listener}!", env!("CARGO_PKG_VERSION"));

	let server = app.listen(&listener);

	// Run this server for... forever!
	if let Err(e) = server.await {
		eprintln!("Server error: {e}");
	}
}


/// env_logger sends every record to stderr, whatever its level. Log collectors
/// that infer severity from the stream then paint an entire run red, which
/// hides the errors among the INFO lines rather than highlighting them.
/// Errors keep stderr; everything else goes to stdout.
struct SplitByLevel {
	out: env_logger::Logger,
	err: env_logger::Logger,
}

impl log::Log for SplitByLevel {
	fn enabled(&self, metadata: &log::Metadata) -> bool {
		self.out.enabled(metadata) || self.err.enabled(metadata)
	}

	fn log(&self, record: &log::Record) {
		if record.level() == log::Level::Error {
			self.err.log(record);
		} else {
			self.out.log(record);
		}
	}

	fn flush(&self) {
		self.out.flush();
		self.err.flush();
	}
}

fn init_logger() {
	// Same filter source as pretty_env_logger::init().
	let filters = std::env::var("RUST_LOG").unwrap_or_default();
	let build = |target| {
		pretty_env_logger::formatted_builder()
			.parse_filters(&filters)
			.target(target)
			.build()
	};

	let logger = SplitByLevel {
		out: build(env_logger::Target::Stdout),
		err: build(env_logger::Target::Stderr),
	};

	let max_level = logger.out.filter();
	if log::set_boxed_logger(Box::new(logger)).is_ok() {
		log::set_max_level(max_level);
	}
}
