//! Error types for the iodisco library

use std::io;
use thiserror::Error;

/// Main error type for iodisco operations
#[derive(Error, Debug)]
pub enum DiscoveryError {
    /// No GPU device found on the system
    #[error("No GPU device found")]
    NoDevice,

    /// Failed to open device
    #[error("Failed to open device: {0}")]
    DeviceOpen(io::Error),

    /// No matching GPU profile found
    #[error("No matching GPU profile found")]
    NoProfile,

    /// Discovery operation failed
    #[error("Discovery error: {0}")]
    Discovery(String),

    /// Invalid parameter or configuration
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// IOCTL execution failed
    #[error("IOCTL execution failed: {0}")]
    IoctlFailed(io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// System permission error
    #[error("Permission denied: {0}")]
    Permission(String),

    /// Profile parsing error
    #[error("Profile error: {0}")]
    Profile(String),

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<io::Error> for DiscoveryError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::PermissionDenied => {
                DiscoveryError::Permission(err.to_string())
            }
            io::ErrorKind::NotFound => {
                DiscoveryError::NoDevice
            }
            _ => DiscoveryError::DeviceOpen(err),
        }
    }
}

/// Result type for iodisco operations
pub type DiscoveryResult<T> = std::result::Result<T, DiscoveryError>;

/// Alias for API compatibility
pub type GpuInfoError = DiscoveryError;