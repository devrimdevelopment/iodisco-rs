//! IOCTL profile management
//!
//! This module handles loading and managing GPU IOCTL profiles.
//! Profiles define which IOCTL commands to use for specific GPU models.

mod mali;
mod adreno;

pub use mali::load_mali_profiles;
pub use adreno::load_adreno_profiles;

use serde::{Deserialize, Serialize};

/// IOCTL profile for a GPU model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoctlProfile {
    /// GPU vendor
    pub vendor: String,
    /// GPU model name
    pub model: String,
    /// Detection IOCTLs for identifying this GPU
    pub detection_ioctls: Vec<IoctlDefinition>,
    /// Version query IOCTL (optional)
    pub version_ioctl: Option<IoctlDefinition>,
    /// GPU info query IOCTL (optional)
    pub gpu_info_ioctl: Option<IoctlDefinition>,
    /// Features query IOCTL (optional)
    pub features_ioctl: Option<IoctlDefinition>,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

/// Definition of an IOCTL command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoctlDefinition {
    /// IOCTL name
    pub name: String,
    /// Command number
    pub cmd: u32,
    /// Expected buffer size
    pub buffer_size: u16,
    /// Data parser function name
    pub parser: String,
    /// Additional parameters
    pub params: serde_json::Value,
}