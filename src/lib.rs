#![forbid(unsafe_code)]

pub mod audit;
pub mod authz;
pub mod capabilities;
pub mod config;
pub mod identity;
pub mod lifecycle;
pub mod pairing;
pub mod process_status;
pub mod protocol;
pub mod repository_status;
pub mod resources;
pub mod runtime;
mod security;
pub mod service_status;
pub mod store;
pub mod transport;
pub mod update;
pub mod workload;

#[doc(hidden)]
#[must_use]
pub fn security_running_as_root() -> bool {
    security::running_as_root()
}

#[doc(hidden)]
#[must_use]
pub const fn security_platform_supported() -> bool {
    security::platform_security_supported()
}
