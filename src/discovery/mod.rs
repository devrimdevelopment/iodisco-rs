//! IOCTL discovery engine for GPU devices

mod scanner;
mod analyzer;

pub use scanner::{IoctlDiscovery, IoctlResult, Interpretation};
pub use analyzer::{DetailedAnalyzer, PatternAnalyzer};

use std::fs;
use std::io;

/// Scan a GPU device for available IOCTLs
///
/// # Arguments
/// * `device_path` - Optional device path. If None, auto-detects.
///
/// # Returns
/// Discovery result containing all found IOCTLs
pub fn scan_device(device_path: Option<&str>) -> io::Result<DiscoveryResult> {
    let device = if let Some(path) = device_path {
        path.to_string()
    } else {
        find_gpu_device().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No GPU device found")
        })?
    };

    let options = DiscoveryConfig::default();
    let mut discovery = IoctlDiscovery::open(&device, options.into())?;

    // Scan common Mali types
    let types_to_scan = vec![0x80u8, 0x64, 0x46, 0x4B, 0x54, 0x6D];
    for ty in types_to_scan {
        discovery.scan_type(ty);
    }

    Ok(discovery.into())
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

impl From<IoctlDiscovery> for DiscoveryResult {
    fn from(discovery: IoctlDiscovery) -> Self {
        Self { discovery }
    }
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
}

/// Discovery configuration
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
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            verbosity: Verbosity::Normal,
            max_results: 10,
            skip_details: false,
            focus_nr: None,
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
            focus_nr: None,
        }
    }

    /// Debug options for full discovery
    pub fn debug() -> Self {
        Self {
            verbosity: Verbosity::Debug,
            max_results: usize::MAX,
            skip_details: false,
            focus_nr: None,
        }
    }
}

impl Into<scanner::DiscoveryOptions> for DiscoveryConfig {
    fn into(self) -> scanner::DiscoveryOptions {
        scanner::DiscoveryOptions {
            verbosity: self.verbosity,
            max_results: self.max_results,
            skip_details: self.skip_details,
            focus_nr: self.focus_nr,
            parallel: false,
        }
    }
}

/// Verbosity level for output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    fn value(&self) -> u8 {
        match self {
            Verbosity::Minimal => 0,
            Verbosity::Normal => 1,
            Verbosity::Detailed => 2,
            Verbosity::Debug => 3,
        }
    }

    fn is_at_least(&self, level: Verbosity) -> bool {
        self.value() >= level.value()
    }
}