mod babybear;

pub mod ffi;
pub mod groth16_bn254;
pub mod plonk_bn254;
pub mod proof;
pub mod witness;

pub use groth16_bn254::*;
pub use plonk_bn254::*;
pub use proof::*;
pub use witness::*;

/// The global version for gnark components.
pub const VERSION: &str = "v4.0.0-rc.3";
