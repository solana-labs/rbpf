//! This module defines an example user error definition

use crate::{ebpf::UserDefinedError, verifier::VerifierError};
use thiserror::Error;

/// User defined error
#[derive(Debug, Error)]
pub enum UserError {
    /// Verifier error
    #[error("VerifierError")]
    VerifierError(VerifierError),
}
impl UserDefinedError for UserError {}
