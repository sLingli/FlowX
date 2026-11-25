#[cfg(not(windows))]
compile_error!("FlowX only supports Windows.");

#[cfg(windows)]
pub mod api;
#[cfg(windows)]
pub mod cli;
#[cfg(windows)]
pub mod config;
#[cfg(windows)]
pub mod dns;
#[cfg(windows)]
pub mod i18n;
#[cfg(windows)]
pub mod inbound;
#[cfg(windows)]
pub mod interceptor;
#[cfg(windows)]
pub mod monitor;
#[cfg(windows)]
pub mod outbound;
#[cfg(windows)]
pub mod router;
#[cfg(windows)]
pub mod transparent;
