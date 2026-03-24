//! Geonode proxy source.
//!
//! Dynamically generates upstream proxy credentials by encoding session and
//! geo-targeting parameters into the upstream proxy username — no external API
//! call is needed at request time.
//!
//! Username formats:
//! - Rotating:             `{username}`
//! - Rotating + country:   `{username}-country-{CC}`
//! - Sticky:               `{username}-session-{id}-sessTime-{min}`
//! - Sticky + country:     `{username}-session-{id}-sessTime-{min}-country-{CC}`

mod config;
mod source;
mod username;

pub use config::GeonodeConfig;
pub use source::{build_source, GeonodeSource};
