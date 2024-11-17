//--------------------------------------------------------------------------------------------------

#[cfg(feature = "axum-extract")]
pub mod extract;
#[cfg(feature = "axum-extract")]
pub mod internal;
mod role;
#[cfg(feature = "axum-extract")]
mod types;

pub use role::Role;
#[cfg(feature = "axum-extract")]
pub use types::*;

//--------------------------------------------------------------------------------------------------
