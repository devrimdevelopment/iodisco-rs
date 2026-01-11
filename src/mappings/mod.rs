//! Hardware database for GPU model identification

pub mod mali;
// pub mod adreno;  // commented out – only Mali is currently implemented

// Re-exports for convenient usage
pub use mali::{
    MaliGpuModel,
    GpuTier,
    identify_mali_gpu,
    MALI_GPU_MODELS,
};

pub mod adreno;
pub use adreno::{AdrenoGpuModel, identify_adreno_gpu};

// Optional: Add Adreno later by uncommenting
// pub use adreno::{AdrenoGpuModel, identify_adreno_gpu};

/// Known GPU vendors supported by this library
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GpuVendor {
    /// ARM Mali GPUs
    Mali,
    /// Qualcomm Adreno GPUs (not yet fully implemented)
    Adreno,
    /// Unknown or unsupported vendor
    Unknown,
}

impl std::fmt::Display for GpuVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuVendor::Mali => write!(f, "ARM Mali"),
            GpuVendor::Adreno => write!(f, "Qualcomm Adreno"),
            GpuVendor::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Extract the hardware ID (lower 16 bits) from a 32-bit Mali GPU identifier
///
/// Format: [variant:8 | core_count:8 | hw_id:16]
pub fn parse_mali_gpu_id(gpu_id: u32) -> u16 {
    (gpu_id & 0xFFFF) as u16
}

/// Extract the number of shader cores from a 32-bit Mali GPU identifier
pub fn parse_mali_core_count(gpu_id: u32) -> u8 {
    ((gpu_id >> 16) & 0xFF) as u8
}

/// Extract the variant number from a 32-bit Mali GPU identifier
pub fn parse_mali_variant(gpu_id: u32) -> u8 {
    ((gpu_id >> 24) & 0xFF) as u8
}