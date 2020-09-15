//! This module defines an example user error definition

use crate::{error::UserDefinedError, verifier::VerifierError};

/// User defined error
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserError {
    /// Verifier error
    #[error("VerifierError")]
    VerifierError(VerifierError),
}
impl UserDefinedError for UserError {}
