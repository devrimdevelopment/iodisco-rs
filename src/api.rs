//! High-level API for GPU information retrieval

use crate::profiles::{load_mali_profiles, load_adreno_profiles};
use crate::discovery::{IoctlDiscovery, DiscoveryConfig};
use crate::mappings::{GpuVendor, identify_mali_gpu, identify_adreno_gpu};
use crate::error::DiscoveryError;
use serde::{Serialize, Deserialize};
use std::io;

pub type GpuInfoError = DiscoveryError;

/// Structured GPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    /// GPU vendor (Mali, Adreno, etc.)
    pub vendor: String,
    /// GPU model name
    pub model: String,
    /// Architecture generation
    pub architecture: Option<String>,
    /// Driver version
    pub driver_version: Option<String>,
    /// GPU hardware ID
    pub gpu_id: Option<u32>,
    /// Number of shader cores
    pub cores: Option<u8>,
    /// Feature flags
    pub features: Vec<String>,
    /// Detected IOCTLs
    pub detected_ioctls: Vec<DetectedIoctl>,
    /// Additional metadata
    pub metadata: serde_json::Value,
    /// Architecture version (major.minor)
    pub arch_version: Option<String>,
    /// Core mask (bitmask of active cores)
    pub core_mask: Option<u32>,
    /// L2 cache count
    pub l2_cache_count: Option<u8>,
    /// Total L2 cache size in bytes
    pub l2_cache_size: Option<u32>,
    /// Memory bus width in bits
    pub bus_width: Option<u16>,
    /// Engine count per core
    pub engines_per_core: Option<u8>,
    /// FP32 FMAs per cycle per core
    pub fp32_fmas_per_core: Option<u16>,
    /// FP16 FMAs per cycle per core
    pub fp16_fmas_per_core: Option<u16>,
    /// Texels per cycle per core
    pub texels_per_core: Option<u16>,
    /// Pixels per cycle per core
    pub pixels_per_core: Option<u16>,
}

/// Information about a detected IOCTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedIoctl {
    /// IOCTL name if known
    pub name: String,
    /// Command number
    pub cmd: u32,
    /// Whether the IOCTL works
    pub works: bool,
    /// Whether it returns data
    pub returns_data: bool,
    /// Error number if failed
    pub errno: Option<i32>,
    /// Return value from ioctl
    pub return_value: Option<i32>,
}

/// Get GPU information with automatic device detection
///
/// This is the main entry point for most applications.
pub fn get_gpu_info() -> Result<GpuInfo, GpuInfoError> {
    get_gpu_info_with_device(None)
}

/// Get GPU information with a specific device path
pub fn get_gpu_info_with_device(device_path: Option<&str>) -> Result<GpuInfo, GpuInfoError> {
    // 1. Find or use specified device
    let device = if let Some(path) = device_path {
        path.to_string()
    } else {
        crate::discovery::find_gpu_device()
            .ok_or(GpuInfoError::NoDevice)?
    };

    // 2. Load all available profiles
    let mut all_profiles = load_mali_profiles();
    all_profiles.extend(load_adreno_profiles());

    // 3. Try each profile until one matches
    for profile in all_profiles {
        if let Some(gpu_info) = try_profile(&device, &profile) {
            return Ok(gpu_info);
        }
    }

    Err(GpuInfoError::NoProfile)
}

/// Try to match a device against a profile
fn try_profile(device_path: &str, profile: &crate::profiles::IoctlProfile) -> Option<GpuInfo> {
    // Open device with quick options (no full discovery)
    let mut discovery = IoctlDiscovery::open(device_path, DiscoveryConfig::quick().into())
        .ok()?;

    // Test signature IOCTLs from profile
    let mut working_ioctls = Vec::new();
    let mut all_signatures_match = true;

    for ioctl_def in &profile.detection_ioctls {
        let cmd = ioctl_def.cmd;
        let result = discovery.test_single_ioctl(cmd);

        // Handle the Result properly
        match result {
            Ok(test_result) => {
                working_ioctls.push(DetectedIoctl {
                    name: ioctl_def.name.clone(),
                    cmd,
                    works: test_result.is_success(),
                    returns_data: test_result.returns_data,
                    errno: if test_result.errno != 0 { Some(test_result.errno) } else { None },
                    return_value: Some(test_result.result),
                });

                // Robust detection: Check if IOCTL exists (not necessarily works)
                if !test_result.exists() {
                    all_signatures_match = false;
                    break;
                }
            }
            Err(_) => {
                // IOCTL failed to execute
                all_signatures_match = false;
                break;
            }
        }
    }

    if !all_signatures_match {
        return None;
    }

    // Profile matches! Collect additional information
    let mut gpu_info = GpuInfo {
        vendor: profile.vendor.clone(),
        model: profile.model.clone(),
        architecture: None,
        driver_version: None,
        gpu_id: None,
        cores: None,
        features: Vec::new(),
        detected_ioctls: working_ioctls,
        metadata: profile.metadata.clone(),
        arch_version: None,
        core_mask: None,
        l2_cache_count: None,
        l2_cache_size: None,
        bus_width: None,
        engines_per_core: None,
        fp32_fmas_per_core: None,
        fp16_fmas_per_core: None,
        texels_per_core: None,
        pixels_per_core: None,
    };

    // Parse metadata from profile
    if let Some(arch) = profile.metadata.get("architecture").and_then(|v| v.as_str()) {
        gpu_info.architecture = Some(arch.to_string());
    }

    if let Some(cores) = profile.metadata.get("core_count").and_then(|v| v.as_u64()) {
        gpu_info.cores = Some(cores as u8);
    }

    if let Some(core_mask) = profile.metadata.get("core_mask").and_then(|v| v.as_u64()) {
        gpu_info.core_mask = Some(core_mask as u32);
    }

    if let Some(arch_version) = profile.metadata.get("arch_version").and_then(|v| v.as_str()) {
        gpu_info.arch_version = Some(arch_version.to_string());
    }

    if let Some(l2_count) = profile.metadata.get("l2_cache_count").and_then(|v| v.as_u64()) {
        gpu_info.l2_cache_count = Some(l2_count as u8);
    }

    if let Some(l2_size) = profile.metadata.get("l2_cache_size").and_then(|v| v.as_u64()) {
        gpu_info.l2_cache_size = Some(l2_size as u32);
    }

    if let Some(bus_width) = profile.metadata.get("bus_width").and_then(|v| v.as_u64()) {
        gpu_info.bus_width = Some(bus_width as u16);
    }

    if let Some(engines) = profile.metadata.get("engines_per_core").and_then(|v| v.as_u64()) {
        gpu_info.engines_per_core = Some(engines as u8);
    }

    if let Some(fp32) = profile.metadata.get("fp32_fmas_per_core").and_then(|v| v.as_u64()) {
        gpu_info.fp32_fmas_per_core = Some(fp32 as u16);
    }

    if let Some(fp16) = profile.metadata.get("fp16_fmas_per_core").and_then(|v| v.as_u64()) {
        gpu_info.fp16_fmas_per_core = Some(fp16 as u16);
    }

    if let Some(texels) = profile.metadata.get("texels_per_core").and_then(|v| v.as_u64()) {
        gpu_info.texels_per_core = Some(texels as u16);
    }

    if let Some(pixels) = profile.metadata.get("pixels_per_core").and_then(|v| v.as_u64()) {
        gpu_info.pixels_per_core = Some(pixels as u16);
    }

    // Try to get version information if defined in profile
    if let Some(version_ioctl) = &profile.version_ioctl {
        match discovery.test_single_ioctl(version_ioctl.cmd) {
            Ok(result) => {
                if result.exists() {
                    // Try to execute with buffer
                    match discovery.execute_ioctl(version_ioctl.cmd, version_ioctl.buffer_size as usize) {
                        Ok(version_data) => {
                            let version_info = parse_version(&version_data, &version_ioctl.parser, result.result);
                            if let Some(version_str) = version_info {
                                gpu_info.driver_version = Some(version_str);
                            }
                        }
                        Err(_) => {
                            // Failed to execute with buffer, but IOCTL exists
                        }
                    }
                }
            }
            Err(_) => {
                // Version IOCTL failed
            }
        }
    }

    // Try to get GPU ID for hardware mapping
    if let Some(info_ioctl) = &profile.gpu_info_ioctl {
        match discovery.execute_ioctl(info_ioctl.cmd, info_ioctl.buffer_size as usize) {
            Ok(gpu_data) => {
                if let Some(gpu_id) = extract_gpu_id(&gpu_data, &info_ioctl.parser) {
                    gpu_info.gpu_id = Some(gpu_id);

                    // Use hardware database to get more details
                    match profile.vendor.as_str() {
                        "Mali" => {
                            if let Some(model_info) = identify_mali_gpu(gpu_id) {
                                gpu_info.architecture = Some(model_info.architecture.to_string());

                                // Override model name from mapping if available
                                if model_info.name != "Unknown" {
                                    gpu_info.model = model_info.name.to_string();
                                }

                                // Override cores from model if not set
                                if gpu_info.cores.is_none() {
                                    gpu_info.cores = Some(model_info.min_cores);
                                }

                                // Add performance specs from model (only if not already set by profile)
                                if gpu_info.engines_per_core.is_none() {
                                    gpu_info.engines_per_core = Some(model_info.execution_engines);
                                }
                                if gpu_info.fp32_fmas_per_core.is_none() {
                                    gpu_info.fp32_fmas_per_core = Some(model_info.fma_per_engine as u16);
                                }
                                if gpu_info.texels_per_core.is_none() {
                                    gpu_info.texels_per_core = Some(model_info.texels_per_cycle as u16);
                                }
                                if gpu_info.pixels_per_core.is_none() {
                                    gpu_info.pixels_per_core = Some(model_info.pixels_per_cycle as u16);
                                }

                                // Estimate FP16 (usually 2x FP32 for Mali)
                                if gpu_info.fp16_fmas_per_core.is_none() {
                                    gpu_info.fp16_fmas_per_core = Some((model_info.fma_per_engine * 2) as u16);
                                }
                            }
                        }
                        "Adreno" => {
                            if let Some(model_info) = identify_adreno_gpu(&gpu_data) {
                                gpu_info.architecture = Some(model_info.architecture.to_string());

                                // Override model name from mapping
                                gpu_info.model = model_info.name.to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {
                // Failed to get GPU info
            }
        }
    }

    // Try to get feature/property information
    if let Some(features_ioctl) = &profile.features_ioctl {
        match discovery.execute_ioctl(features_ioctl.cmd, features_ioctl.buffer_size as usize) {
            Ok(features_data) => {
                let features = parse_features(&features_data, &features_ioctl.parser);
                gpu_info.features = features;
            }
            Err(_) => {
                // Failed to get features
            }
        }
    }

    // Calculate derived values if we have core count and per-core specs
    if let (Some(cores), Some(fp32_per_core)) = (gpu_info.cores, gpu_info.fp32_fmas_per_core) {
        let total_fp32 = fp32_per_core as u32 * cores as u32;
        if let Some(fp16_per_core) = gpu_info.fp16_fmas_per_core {
            let total_fp16 = fp16_per_core as u32 * cores as u32;

            // Add to metadata if not already present
            if !gpu_info.metadata.is_object() {
                gpu_info.metadata = serde_json::json!({});
            }

            if let serde_json::Value::Object(ref mut map) = gpu_info.metadata {
                map.insert("total_fp32_fmas".to_string(), serde_json::Value::Number(total_fp32.into()));
                map.insert("total_fp16_fmas".to_string(), serde_json::Value::Number(total_fp16.into()));

                if let (Some(texels_per_core), Some(pixels_per_core)) = (gpu_info.texels_per_core, gpu_info.pixels_per_core) {
                    let total_texels = texels_per_core as u32 * cores as u32;
                    let total_pixels = pixels_per_core as u32 * cores as u32;
                    map.insert("total_texels_per_cycle".to_string(), serde_json::Value::Number(total_texels.into()));
                    map.insert("total_pixels_per_cycle".to_string(), serde_json::Value::Number(total_pixels.into()));
                }
            }
        }
    }

    Some(gpu_info)
}

/// Parse version from raw data using generic parser
fn parse_version(data: &[u8], parser: &str, ret_val: i32) -> Option<String> {
    match parser {
        // Generic parser: Extract version from return value (major in high byte, minor in low byte)
        "parse_version_return_value" => {
            Some(format!("{}.{}", (ret_val >> 8) as u8, ret_val as u8 & 0xFF))
        }
        // Generic parser: First 8 bytes as two u32 (major, minor)
        "parse_version_two_u32" => {
            if data.len() >= 8 {
                let major = u32::from_le_bytes(data[0..4].try_into().ok()?);
                let minor = u32::from_le_bytes(data[4..8].try_into().ok()?);
                Some(format!("{}.{}", major, minor))
            } else {
                None
            }
        }
        // Generic parser: First 4 bytes as version code
        "parse_version_u32" => {
            if data.len() >= 4 {
                let version = u32::from_le_bytes(data[0..4].try_into().ok()?);
                Some(format!("{}", version))
            } else {
                None
            }
        }
        // Unknown parser - return None
        _ => None,
    }
}

/// Extract GPU ID from raw data using generic parser
fn extract_gpu_id(data: &[u8], parser: &str) -> Option<u32> {
    match parser {
        // Generic parser: First 4 bytes as GPU ID
        "parse_gpu_id_u32" => {
            if data.len() >= 4 {
                Some(u32::from_le_bytes(data[0..4].try_into().ok()?))
            } else {
                None
            }
        }
        // Generic parser: First 4 bytes as little-endian GPU ID
        "parse_gpu_id_le" => {
            if data.len() >= 4 {
                Some(u32::from_le_bytes(data[0..4].try_into().ok()?))
            } else {
                None
            }
        }
        // Generic parser: First 4 bytes as big-endian GPU ID
        "parse_gpu_id_be" => {
            if data.len() >= 4 {
                Some(u32::from_be_bytes(data[0..4].try_into().ok()?))
            } else {
                None
            }
        }
        // Unknown parser - return None
        _ => None,
    }
}

/// Parse feature flags from raw data using generic parser
fn parse_features(data: &[u8], parser: &str) -> Vec<String> {
    match parser {
        // Generic parser: 4-byte bitmask with named bits
        "parse_features_bitmask" => {
            if data.len() >= 4 {
                let features = u32::from_le_bytes(data[0..4].try_into().unwrap());
                parse_bitmask_to_features(features)
            } else {
                Vec::new()
            }
        }
        // Generic parser: Raw hex value
        "parse_features_hex" => {
            if data.len() >= 4 {
                let features = u32::from_le_bytes(data[0..4].try_into().unwrap());
                vec![format!("0x{:08x}", features)]
            } else {
                Vec::new()
            }
        }
        // Unknown parser - return empty
        _ => Vec::new(),
    }
}

/// Helper: Convert bitmask to feature names (generic for all GPUs)
fn parse_bitmask_to_features(bitmask: u32) -> Vec<String> {
    let mut features = Vec::new();

    // Generic bit names - profiles can override or extend
    for i in 0..32 {
        if bitmask & (1 << i) != 0 {
            features.push(format!("BIT_{}", i));
        }
    }

    // If we have known special bits, name them
    if bitmask & (1 << 0) != 0 {
        if let Some(pos) = features.iter().position(|f| f == "BIT_0") {
            features[pos] = "JOB_CHAINING".to_string();
        }
    }

    if bitmask & (1 << 1) != 0 {
        if let Some(pos) = features.iter().position(|f| f == "BIT_1") {
            features[pos] = "TILER".to_string();
        }
    }

    if bitmask & (1 << 2) != 0 {
        if let Some(pos) = features.iter().position(|f| f == "BIT_2") {
            features[pos] = "COHERENCY".to_string();
        }
    }

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_return_value() {
        // Test return value 749 = 0x2ED = 0x02 0xED = 2.237
        let result = parse_version(&[], "parse_version_return_value", 749);
        assert_eq!(result, Some("2.237".to_string()));

        // Test return value 711 = 0x2C7 = 0x02 0xC7 = 2.199
        let result = parse_version(&[], "parse_version_return_value", 711);
        assert_eq!(result, Some("2.199".to_string()));

        // Test return value 256 = 0x100 = 1.0
        let result = parse_version(&[], "parse_version_return_value", 256);
        assert_eq!(result, Some("1.0".to_string()));
    }

    #[test]
    fn test_parse_version_two_u32() {
        let data = [10, 0, 0, 0, 6, 0, 0, 0]; // Mali 10.6
        let result = parse_version(&data, "parse_version_two_u32", 0);
        assert_eq!(result, Some("10.6".to_string()));
    }

    #[test]
    fn test_extract_gpu_id_u32() {
        let data = [0x00, 0xc0, 0x00, 0x00]; // Mali-G720 ID: 0xc000
        let result = extract_gpu_id(&data, "parse_gpu_id_u32");
        assert_eq!(result, Some(0x0000c000));

        let data = [0x21, 0x00, 0x00, 0x00]; // ID: 0x21
        let result = extract_gpu_id(&data, "parse_gpu_id_u32");
        assert_eq!(result, Some(0x21));
    }
}