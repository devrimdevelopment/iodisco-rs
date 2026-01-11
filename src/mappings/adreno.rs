//! Placeholder for Qualcomm Adreno GPU identification
//! (Support is experimental/not implemented yet)

/// Stub function: Always returns None until real Adreno identification is implemented
///
/// In the future, this could parse GPU ID from KGSL ioctls, registers, or devicetree.
/// For now it safely returns None so the high-level API doesn't panic.
pub fn identify_adreno_gpu(_data: &[u8]) -> Option<&'static AdrenoGpuModel> {
    None
}

/// Minimal placeholder type for Adreno GPU models
/// (expand later when real support is added)
#[derive(Debug, Clone)]
pub struct AdrenoGpuModel {
    /// Marketing name (e.g. "Adreno 740")
    pub name: &'static str,

    /// Architecture / generation
    pub architecture: &'static str,

    // Add more fields (tier, performance specs, etc.) when needed
}