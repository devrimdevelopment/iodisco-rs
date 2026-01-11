//! # IODISCO - IOCTL Discovery for GPU Information
//!
//! A unified, lightweight Rust library for querying GPU hardware metadata
//! on Linux and Android systems via direct kernel IOCTL communication.
//!
//! ## Features
//!
//! - **ARM Mali support** via kernel ioctls
//! - **Qualcomm Adreno support** via KGSL
//! - **Smart auto-detection** of GPU driver nodes
//! - **Two-phase operation**: Fast profile matching or full discovery
//! - **Profile system** with community-contributed device signatures
//! - **JSON export** for sharing discovery results
//! - **Parallel scanning** for faster discovery
//! - **No root required** – works in normal user-space
//!
//! ## Quick Start
//!
//! ```rust
//! use iodisco;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let gpu_info = iodisco::get_gpu_info()?;
//!     println!("GPU: {} {}", gpu_info.vendor, gpu_info.model);
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod api;
pub mod discovery;
pub mod error;
pub mod profiles;
pub mod mappings;

// Re-export main API for easy access
pub use api::{get_gpu_info, get_gpu_info_with_device, GpuInfo, GpuInfoError};
pub use discovery::{scan_device, DiscoveryConfig, DiscoveryResult};
pub use error::DiscoveryError;
pub use mappings::{identify_mali_gpu, identify_adreno_gpu, GpuVendor};
pub use profiles::{load_mali_profiles, load_adreno_profiles, IoctlProfile};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Main entry point for high-level GPU information
///
/// This function automatically detects the GPU device and returns
/// structured information about it using pre-defined profiles.
///
/// # Example
///
/// ```no_run
/// use iodisco;
///
/// match iodisco::get_gpu_info() {
///     Ok(info) => {
///         println!("Found GPU: {} {}", info.vendor, info.model);
///     }
///     Err(iodisco::GpuInfoError::NoProfile) => {
///         eprintln!("GPU not recognized. Consider running discovery mode.");
///     }
///     Err(e) => {
///         eprintln!("Error: {}", e);
///     }
/// }
/// ```

/// Initialize the library with custom configuration
///
/// # Example
///
/// ```no_run
/// use iodisco;
///
/// // Optional initialization for custom logging or configuration
/// iodisco::init();
/// ```
pub fn init() {
    // Placeholder for future initialization logic
    // Could setup logging, load custom profiles, etc.
}

/// Scan for available GPU devices on the system
///
/// Returns a list of device paths that might contain GPU drivers.
///
/// # Example
///
/// ```no_run
/// use iodisco;
///
/// let devices = iodisco::scan_devices();
/// for device in devices {
///     println!("Found GPU device: {}", device);
/// }
/// ```
pub fn scan_devices() -> Vec<String> {
    discovery::find_gpu_devices()
}

/// Run a quick compatibility check
///
/// Returns `true` if the system appears to have a supported GPU.
///
/// # Example
///
/// ```no_run
/// use iodisco;
///
/// if iodisco::is_supported() {
///     println!("System has a supported GPU");
/// } else {
///     println!("No supported GPU detected");
/// }
/// ```
pub fn is_supported() -> bool {
    !scan_devices().is_empty()
}

/// Get library information
///
/// # Example
///
/// ```no_run
/// use iodisco;
///
/// println!("Using iodisco v{}", iodisco::version());
/// ```
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert!(!version().is_empty());
    }

    #[test]
    fn test_init() {
        // Just ensure it compiles and runs without panic
        init();
    }

    #[test]
    fn test_is_supported() {
        // This is a runtime check, just ensure it compiles
        let _ = is_supported();
    }

    #[test]
    fn test_scan_devices() {
        // Just ensure it compiles
        let devices = scan_devices();
        // We can't assert anything about the result as it depends on the system
        let _ = devices;
    }
}

/// Prelude module for convenient imports
///
/// # Example
///
/// ```no_run
/// use iodisco::prelude::*;
///
/// let gpu_info = get_gpu_info()?;
/// ```
pub mod prelude {
    pub use crate::api::{get_gpu_info, get_gpu_info_with_device, GpuInfo, GpuInfoError};
    pub use crate::discovery::{scan_device, DiscoveryConfig, DiscoveryResult};
    pub use crate::mappings::{identify_adreno_gpu, identify_mali_gpu, GpuVendor};
    pub use crate::{init, is_supported, scan_devices, version};
}