//! IOCTL discovery engine for GPU devices

mod analyzer;
mod scanner;

use serde::{Deserialize, Serialize};

pub use analyzer::{DetailedAnalyzer, PatternAnalyzer};
pub use scanner::{DiscoveryOptions, Interpretation, IoctlDiscovery, IoctlResult, IoctlTestResult};

use std::fs;
use std::io;

/// Scan a GPU device for available IOCTLs
///
/// # Arguments
/// * `device_path` - Optional device path. If None, auto-detects.
/// * `config` - Optional discovery configuration
///
/// # Returns
/// Discovery result containing all found IOCTLs
pub fn scan_device(
    device_path: Option<&str>,
    config: Option<DiscoveryConfig>,
) -> io::Result<DiscoveryResult> {
    let device = if let Some(path) = device_path {
        path.to_string()
    } else {
        find_gpu_device()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No GPU device found"))?
    };

    let options = config.unwrap_or_default();

    // Clone verbosity before moving options
    let verbosity = options.verbosity;

    let mut discovery = IoctlDiscovery::open(&device, options.into())?;

    // Scan common Mali types
    let types_to_scan = vec![0x80u8, 0x64, 0x46, 0x4B, 0x54, 0x6D];
    for ty in types_to_scan {
        if let Err(e) = discovery.scan_type(ty) {
            // Use the cloned verbosity
            if verbosity.is_at_least(Verbosity::Normal) {
                eprintln!("Warning: Failed to scan type 0x{:02x}: {}", ty, e);
            }
            // Continue with next type
        }
    }

    Ok(DiscoveryResult { discovery })
}

/// Find all GPU devices on the system
pub fn find_gpu_devices() -> Vec<String> {
    let mut devices = Vec::new();

    // Check Mali devices
    for i in 0..10 {
        let path = format!("/dev/mali{}", i);
        if fs::metadata(&path).is_ok() {
            devices.push(path);
        }
    }

    // Check Adreno/KGSL devices
    for i in 0..4 {
        let path = format!("/dev/kgsl-3d{}", i);
        if fs::metadata(&path).is_ok() {
            devices.push(path);
        }
    }

    // Check DRI render nodes
    for i in 128..138 {
        let path = format!("/dev/dri/renderD{}", i);
        if fs::metadata(&path).is_ok() {
            devices.push(path);
        }
    }

    devices
}

/// Find the most likely GPU device
pub fn find_gpu_device() -> Option<String> {
    let devices = find_gpu_devices();
    devices.into_iter().next()
}

/// Discovery result wrapper
pub struct DiscoveryResult {
    discovery: IoctlDiscovery,
}

impl DiscoveryResult {
    /// Print results to stdout
    pub fn print_results(&self) {
        self.discovery.print_results();
    }

    /// Export results to JSON file
    pub fn export_json(&self, path: &str) -> io::Result<()> {
        self.discovery.export_json(path)
    }

    /// Get all IOCTL results
    pub fn results(&self) -> &[IoctlResult] {
        &self.discovery.results
    }

    /// Generate a profile template from discovery results
    pub fn generate_profile_template(&self, output_path: &str) -> io::Result<()> {
        self.discovery.generate_profile_template(output_path)
    }

    /// Get the total number of IOCTL calls made
    pub fn get_call_count(&self) -> u32 {
        self.discovery.get_call_count()
    }
}

/// Discovery configuration (public API)
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Verbosity level
    pub verbosity: Verbosity,
    /// Maximum results per category
    pub max_results: usize,
    /// Skip detailed analysis
    pub skip_details: bool,
    /// Focus on specific NR values
    pub focus_nr: Option<Vec<u8>>,
    /// Use parallel scanning
    pub parallel: bool,

    /// Safety: explicitly allowed ioctl types
    pub allow_types: Option<Vec<u8>>,
    /// Safety: denied ioctl types
    pub deny_types: Vec<u8>,
    /// Safety: warn only about dangerous types
    pub warn_only_on_dangerous: bool,
    /// Safety: attempt to find exact argument size
    pub try_find_size: bool,

    /// Rate limiting: delay between calls in ms
    pub delay_between_calls_ms: u64,
    /// Rate limiting: max calls per second
    pub max_calls_per_second: Option<u32>,
    /// Rate limiting: max total calls
    pub max_total_calls: Option<u32>,

    /// Size discovery: max attempts
    pub max_size_discovery_attempts: u8,
    /// Size discovery: candidate sizes
    pub size_discovery_candidates: Vec<u16>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            verbosity: Verbosity::Normal,
            max_results: 10,
            skip_details: false,
            focus_nr: None,
            parallel: false,

            allow_types: None,
            deny_types: vec![0x12, 0x88, 0x8B, 0xFD, 0xFE, 0xFF],
            warn_only_on_dangerous: false,
            try_find_size: false,

            delay_between_calls_ms: 0,
            max_calls_per_second: Some(1000),
            max_total_calls: Some(10000),

            max_size_discovery_attempts: 5,
            size_discovery_candidates: vec![4, 8, 16, 24, 32, 40, 48, 64, 80, 96, 128, 256],
        }
    }
}

impl DiscoveryConfig {
    /// Quick options for profile matching (fast, minimal output)
    pub fn quick() -> Self {
        Self {
            verbosity: Verbosity::Minimal,
            max_results: 5,
            skip_details: true,
            parallel: false,
            warn_only_on_dangerous: false,
            max_calls_per_second: Some(100),
            max_total_calls: Some(1000),
            ..Default::default()
        }
    }

    /// Debug options for full discovery
    pub fn debug() -> Self {
        Self {
            verbosity: Verbosity::Debug,
            max_results: usize::MAX,
            skip_details: false,
            parallel: false,
            warn_only_on_dangerous: true,
            max_calls_per_second: Some(500),
            max_total_calls: Some(5000),
            ..Default::default()
        }
    }

    /// Embedded options for safe, minimal scanning
    pub fn embedded() -> Self {
        Self {
            verbosity: Verbosity::Minimal,
            max_results: 3,
            skip_details: true,
            parallel: false,
            warn_only_on_dangerous: false,
            max_calls_per_second: Some(50),
            max_total_calls: Some(500),
            deny_types: vec![0x12, 0x88, 0x8B, 0xFD, 0xFE, 0xFF, 0x00, 0x01],
            ..Default::default()
        }
    }
}

impl Into<DiscoveryOptions> for DiscoveryConfig {
    fn into(self) -> DiscoveryOptions {
        DiscoveryOptions {
            verbosity: self.verbosity,
            max_results: self.max_results,
            skip_details: self.skip_details,
            focus_nr: self.focus_nr,
            parallel: self.parallel,

            allow_types: self.allow_types,
            deny_types: self.deny_types,
            warn_only_on_dangerous: self.warn_only_on_dangerous,
            try_find_size: self.try_find_size,

            delay_between_calls_ms: self.delay_between_calls_ms,
            max_calls_per_second: self.max_calls_per_second,
            max_total_calls: self.max_total_calls,

            max_size_discovery_attempts: self.max_size_discovery_attempts,
            size_discovery_candidates: self.size_discovery_candidates,
        }
    }
}

/// Verbosity level for output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize, Deserialize
pub enum Verbosity {
    /// Minimal output - only summary
    Minimal,
    /// Normal output - key findings
    Normal,
    /// Detailed output - all results
    Detailed,
    /// Debug output - everything including progress
    Debug,
}

impl Verbosity {
    /// Get numeric value for comparison
    pub fn value(&self) -> u8 {
        match self {
            Verbosity::Minimal => 0,
            Verbosity::Normal => 1,
            Verbosity::Detailed => 2,
            Verbosity::Debug => 3,
        }
    }

    /// Check if verbosity is at least the given level
    pub fn is_at_least(&self, level: Verbosity) -> bool {
        self.value() >= level.value()
    }
}
