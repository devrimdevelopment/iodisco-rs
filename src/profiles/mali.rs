//! ARM Mali GPU profiles
//!
//! Contains IOCTL profiles for various Mali GPU models.

use super::{IoctlProfile, IoctlDefinition};

/// Load all embedded Mali profiles
pub fn load_mali_profiles() -> Vec<IoctlProfile> {
    let mut profiles = Vec::new();

    // Add all Mali profiles
    profiles.push(create_mali_g71_profile());
    profiles.push(create_mali_g720_profile());
    profiles.push(create_generic_mali_profile());

    profiles
}

/// Create Mali-G71 profile based on libgpuinfo strace (Samsung SM-T510)
fn create_mali_g71_profile() -> IoctlProfile {
    IoctlProfile {
        vendor: "Mali".to_string(),
        model: "Mali-G71".to_string(),
        detection_ioctls: vec![
            IoctlDefinition {
                name: "GET_PROPS_00".to_string(),
                cmd: 0xC0048000,
                buffer_size: 4,
                parser: "parse_features_bitmask".to_string(),
                params: serde_json::json!({
                    "expected_core_mask": "0x3"
                }),
            },
            IoctlDefinition {
                name: "VERSION_CHECK".to_string(),
                cmd: 0x40108003,
                buffer_size: 16,
                parser: "parse_version_return_value".to_string(),
                params: serde_json::json!({
                    "expected_return": 711
                }),
            },
        ],
        version_ioctl: Some(IoctlDefinition {
            name: "VERSION_CHECK".to_string(),
            cmd: 0x40108003,
            buffer_size: 16,
            parser: "parse_version_return_value".to_string(),
            params: serde_json::json!({}),
        }),
        gpu_info_ioctl: Some(IoctlDefinition {
            name: "GET_GPU_INFO".to_string(),
            cmd: 0x8004800c,
            buffer_size: 4,
            parser: "parse_gpu_id_u32".to_string(),
            params: serde_json::json!({}),
        }),
        features_ioctl: Some(IoctlDefinition {
            name: "GET_PROPS_00".to_string(),
            cmd: 0xC0048000,
            buffer_size: 4,
            parser: "parse_features_bitmask".to_string(),
            params: serde_json::json!({}),
        }),
        metadata: serde_json::json!({
            "architecture": "Bifrost",
            "model_number": "0x6000",
            "core_count": 2,
            "core_mask": "0x3",
            "arch_version": "6.0",
            "l2_cache_count": 1,
            "l2_cache_size": 262144,
            "bus_width": 128,
            "engines_per_core": 3,
            "fp32_fmas_per_core": 12,
            "fp16_fmas_per_core": 24,
            "texels_per_core": 1,
            "pixels_per_core": 1,
            "confirmed_by": "libgpuinfo_strace",
            "device": "Samsung SM-T510",
            "android_version": "11",
            "kernel_version": "4.4.177",
            "return_value_0x40108003": 711,
            "raw_features_0xC0048000": "0x001b000b",
            "raw_gpu_id_0x8004800c": "0x00000021"
        }),
    }
}

/// Create Mali-G720 profile based on libgpuinfo strace (Xiaomi device)
fn create_mali_g720_profile() -> IoctlProfile {
    IoctlProfile {
        vendor: "Mali".to_string(),
        model: "Mali-G720".to_string(),
        detection_ioctls: vec![
            IoctlDefinition {
                name: "GET_PROPS_34".to_string(),
                cmd: 0xC0048034,
                buffer_size: 4,
                parser: "parse_features_bitmask".to_string(),
                params: serde_json::json!({}),
            },
            IoctlDefinition {
                name: "VERSION_CHECK".to_string(),
                cmd: 0x40108003,
                buffer_size: 16,
                parser: "parse_version_return_value".to_string(),
                params: serde_json::json!({
                    "expected_return": 749
                }),
            },
        ],
        version_ioctl: Some(IoctlDefinition {
            name: "VERSION_CHECK".to_string(),
            cmd: 0x40108003,
            buffer_size: 16,
            parser: "parse_version_return_value".to_string(),
            params: serde_json::json!({}),
        }),
        gpu_info_ioctl: Some(IoctlDefinition {
            name: "GET_GPU_INFO".to_string(),
            cmd: 0xC010800B,
            buffer_size: 16,
            parser: "parse_gpu_id_u32".to_string(),
            params: serde_json::json!({}),
        }),
        features_ioctl: Some(IoctlDefinition {
            name: "GET_PROPS_34".to_string(),
            cmd: 0xC0048034,
            buffer_size: 4,
            parser: "parse_features_bitmask".to_string(),
            params: serde_json::json!({}),
        }),
        metadata: serde_json::json!({
            "architecture": "Arm 5th Gen",
            "model_number": "0xc000",
            "core_count": 7,
            "core_mask": "0x150055",
            "arch_version": "12.8",
            "l2_cache_count": 4,
            "l2_cache_size": 2097152,
            "bus_width": 256,
            "engines_per_core": 2,
            "fp32_fmas_per_core": 128,
            "fp16_fmas_per_core": 256,
            "texels_per_core": 8,
            "pixels_per_core": 4,
            "confirmed_by": "libgpuinfo_strace",
            "device": "Xiaomi device",
            "android_version": "16",
            "return_value_0x40108003": 749
        }),
    }
}

/// Create generic Mali profile for unknown devices
fn create_generic_mali_profile() -> IoctlProfile {
    IoctlProfile {
        vendor: "Mali".to_string(),
        model: "Generic Mali".to_string(),
        detection_ioctls: vec![
            IoctlDefinition {
                name: "GET_VERSION".to_string(),
                cmd: 0x40108003,
                buffer_size: 16,
                parser: "parse_version_return_value".to_string(),
                params: serde_json::json!({}),
            },
        ],
        version_ioctl: Some(IoctlDefinition {
            name: "GET_VERSION".to_string(),
            cmd: 0x40108003,
            buffer_size: 16,
            parser: "parse_version_return_value".to_string(),
            params: serde_json::json!({}),
        }),
        gpu_info_ioctl: Some(IoctlDefinition {
            name: "GET_GPU_INFO".to_string(),
            cmd: 0x4008800B,
            buffer_size: 64,
            parser: "parse_gpu_id_u32".to_string(),
            params: serde_json::json!({}),
        }),
        features_ioctl: None,
        metadata: serde_json::json!({
            "confidence": 0.5,
            "description": "Generic Mali profile for unknown devices"
        }),
    }
}