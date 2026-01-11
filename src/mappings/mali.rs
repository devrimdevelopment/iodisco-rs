//! ARM Mali GPU model database

use serde::{Serialize, Deserialize};

/// Mali GPU model information used for identification, classification and performance estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliGpuModel {
    /// Hardware ID (lower 16 bits of GPU_ID register)
    pub id: u16,
    /// Mask for hardware ID comparison (0xFFF0 for older Midgard, 0xFFFF for newer)
    pub id_mask: u16,
    /// Minimum number of cores required for this marketing name/variant
    pub min_cores: u8,
    /// Marketing name (e.g. "Mali-G78", "Immortalis-G715")
    pub name: &'static str,
    /// Architecture generation/family
    pub architecture: &'static str,
    /// Performance/power tier classification
    pub tier: GpuTier,
    /// Number of shader execution engines per core
    pub execution_engines: u8,
    /// Number of FP32 FMA operations per engine per cycle
    pub fma_per_engine: u16,
    /// Texels processed per cycle per core
    pub texels_per_cycle: u8,
    /// Pixels processed per cycle per core
    pub pixels_per_cycle: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GpuTier {
    /// Very low-end / ultra power efficient
    UltraLowPower,
    /// Low/mid-range power efficient
    LowPower,
    /// Mainstream performance class
    Mainstream,
    /// Flagship / high performance
    HighPerformance,
}

/// Complete database of known Mali GPU models
pub const MALI_GPU_MODELS: &[MaliGpuModel] = &[
    // Midgard Architecture
    MaliGpuModel { id: 0x6956, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T600",   architecture: "Midgard", tier: GpuTier::UltraLowPower, execution_engines: 2, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0620, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T620",   architecture: "Midgard", tier: GpuTier::UltraLowPower, execution_engines: 2, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0720, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T720",   architecture: "Midgard", tier: GpuTier::UltraLowPower, execution_engines: 1, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0750, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T760",   architecture: "Midgard", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0820, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T820",   architecture: "Midgard", tier: GpuTier::UltraLowPower, execution_engines: 1, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0830, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T830",   architecture: "Midgard", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0860, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T860",   architecture: "Midgard", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x0880, id_mask: 0xFFF0, min_cores: 1, name: "Mali-T880",   architecture: "Midgard", tier: GpuTier::LowPower,      execution_engines: 3, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },

    // Bifrost Architecture
    MaliGpuModel { id: 0x6000, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G71",    architecture: "Bifrost", tier: GpuTier::Mainstream,    execution_engines: 3, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x6001, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G72",    architecture: "Bifrost", tier: GpuTier::Mainstream,    execution_engines: 3, fma_per_engine: 4,  texels_per_cycle: 1, pixels_per_cycle: 1 },
    MaliGpuModel { id: 0x7000, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G51",    architecture: "Bifrost", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 4,  texels_per_cycle: 2, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x7001, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G76",    architecture: "Bifrost", tier: GpuTier::Mainstream,    execution_engines: 3, fma_per_engine: 8,  texels_per_cycle: 2, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x7002, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G52",    architecture: "Bifrost", tier: GpuTier::LowPower,      execution_engines: 3, fma_per_engine: 8,  texels_per_cycle: 2, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x7003, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G31",    architecture: "Bifrost", tier: GpuTier::UltraLowPower, execution_engines: 1, fma_per_engine: 4,  texels_per_cycle: 2, pixels_per_cycle: 2 },

    // Valhall Architecture
    MaliGpuModel { id: 0x9000, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G77",    architecture: "Valhall", tier: GpuTier::Mainstream,    execution_engines: 2, fma_per_engine: 16, texels_per_cycle: 4, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x9001, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G57",    architecture: "Valhall", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 16, texels_per_cycle: 4, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x9003, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G57",    architecture: "Valhall", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 16, texels_per_cycle: 4, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x9004, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G68",    architecture: "Valhall", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 16, texels_per_cycle: 4, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x9002, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G78",    architecture: "Valhall", tier: GpuTier::Mainstream,    execution_engines: 2, fma_per_engine: 16, texels_per_cycle: 4, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0x9005, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G78AE",  architecture: "Valhall", tier: GpuTier::Mainstream,    execution_engines: 2, fma_per_engine: 16, texels_per_cycle: 4, pixels_per_cycle: 2 },
    MaliGpuModel { id: 0xa002, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G710",   architecture: "Valhall", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 32, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xa007, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G610",   architecture: "Valhall", tier: GpuTier::Mainstream,    execution_engines: 2, fma_per_engine: 32, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xa003, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G510",   architecture: "Valhall", tier: GpuTier::LowPower,      execution_engines: 2, fma_per_engine: 32, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xa004, id_mask: 0xFFFF, min_cores: 1, name: "Mali-G310",   architecture: "Valhall", tier: GpuTier::UltraLowPower, execution_engines: 2, fma_per_engine: 32, texels_per_cycle: 8, pixels_per_cycle: 4 },

    // 5th Generation / Immortalis
    MaliGpuModel { id: 0xb002, id_mask: 0xFFFF, min_cores: 10, name: "Immortalis-G715", architecture: "Valhall",     tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xb002, id_mask: 0xFFFF, min_cores: 7,  name: "Mali-G715",       architecture: "Valhall",     tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xb002, id_mask: 0xFFFF, min_cores: 1,  name: "Mali-G615",       architecture: "Valhall",     tier: GpuTier::LowPower,        execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xb003, id_mask: 0xFFFF, min_cores: 1,  name: "Mali-G615",       architecture: "Valhall",     tier: GpuTier::LowPower,        execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xc000, id_mask: 0xFFFF, min_cores: 10, name: "Immortalis-G720", architecture: "Arm 5th Gen", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xc000, id_mask: 0xFFFF, min_cores: 6,  name: "Mali-G720",       architecture: "Arm 5th Gen", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xc000, id_mask: 0xFFFF, min_cores: 1,  name: "Mali-G620",       architecture: "Arm 5th Gen", tier: GpuTier::LowPower,        execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xc001, id_mask: 0xFFFF, min_cores: 1,  name: "Mali-G620",       architecture: "Arm 5th Gen", tier: GpuTier::LowPower,        execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xd000, id_mask: 0xFFFF, min_cores: 10, name: "Immortalis-G925", architecture: "Arm 5th Gen", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xd000, id_mask: 0xFFFF, min_cores: 6,  name: "Mali-G725",       architecture: "Arm 5th Gen", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xd001, id_mask: 0xFFFF, min_cores: 1,  name: "Mali-G625",       architecture: "Arm 5th Gen", tier: GpuTier::LowPower,        execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xe000, id_mask: 0xFFFF, min_cores: 10, name: "Mali G1-Ultra",   architecture: "Arm 5th Gen", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xe001, id_mask: 0xFFFF, min_cores: 6,  name: "Mali G1-Premium", architecture: "Arm 5th Gen", tier: GpuTier::HighPerformance, execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
    MaliGpuModel { id: 0xe003, id_mask: 0xFFFF, min_cores: 1,  name: "Mali G1-Pro",     architecture: "Arm 5th Gen", tier: GpuTier::Mainstream,    execution_engines: 2, fma_per_engine: 64, texels_per_cycle: 8, pixels_per_cycle: 4 },
];

/// Try to identify a Mali GPU model from the combined 32-bit GPU identifier
///
/// Returns the best matching model where core count ≥ min_cores
pub fn identify_mali_gpu(gpu_id: u32) -> Option<&'static MaliGpuModel> {
    let hw_id = (gpu_id & 0xFFFF) as u16;
    let core_count = ((gpu_id >> 16) & 0xFF) as u8;

    for model in MALI_GPU_MODELS {
        if (hw_id & model.id_mask) == (model.id & model.id_mask) {
            if core_count >= model.min_cores {
                return Some(model);
            }
        }
    }

    None
}