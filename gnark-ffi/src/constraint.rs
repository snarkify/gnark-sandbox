use serde::{Deserialize, Serialize};

/// A simplified version of the constraints structure needed for gnark
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub id: usize,
    pub description: String,
}

/// Configuration for the constraint system
pub mod ir {
    use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, PrimeField};
    use serde::{Deserialize, Serialize};

    /// Configuration trait for the constraint system
    pub trait Config {
        type F: Field;
        type EF: ExtensionField<Base = Self::F>;
        type N: PrimeField;
    }

    /// Witness for the circuit
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Witness<C: Config> {
        pub vars: Vec<C::N>,
        pub felts: Vec<C::F>,
        pub exts: Vec<C::EF>,
        pub vkey_hash: C::N,
        pub committed_values_digest: C::N,
    }
}