//! IOCTL discovery engine for GPU devices

mod scanner;
mod analyzer;

pub use scanner::{IoctlDiscovery, IoctlResult, Interpretation, IoctlTestResult, DiscoveryOptions as ScannerOptions};
pub use analyzer::{DetailedAnalyzer, PatternAnalyzer};

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
pub fn scan_device(device_path: Option<&str>, config: Option<DiscoveryConfig>) -> io::Result<DiscoveryResult> {
    let device = if let Some(path) = device_path {
        path.to_string()
    } else {
        find_gpu_device().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No GPU device found")
        })?
    };

    let options = config.unwrap_or_default();
    let mut discovery = IoctlDiscovery::open(&device, options.into())?;

    // Scan common GPU types based on safety configuration
    let mut types_to_scan = vec![];
    
    // Always try these common types (they're generally safe)
    types_to_scan.push(0x80u8); // Common Mali type
    
    // Only scan additional types if allowed by safety settings
    if discovery.is_allowed(0x64) {
        types_to_scan.push(0x64);
    }
    if discovery.is_allowed(0x46) {
        types_to_scan.push(0x46);
    }
    if discovery.is_allowed(0x4B) {
        types_to_scan.push(0x4B);
    }
    if discovery.is_allowed(0x54) {
        types_to_scan.push(0x54);
    }
    if discovery.is_allowed(0x6D) {
        types_to_scan.push(0x6D);
    }

    for ty in types_to_scan {
        if let Err(e) = discovery.scan_type(ty) {
            if options.verbosity.is_at_least(Verbosity::Normal) {
                eprintln!("⚠️  Warning: Failed to scan type 0x{:02x}: {}", ty, e);
            }
            // Continue with next type on error
        }
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
    
    /// Get the discovery scanner instance
    pub fn scanner(&self) -> &IoctlDiscovery {
        &self.discovery
    }
    
    /// Get the number of IOCTL calls made
    pub fn call_count(&self) -> u32 {
        self.discovery.get_call_count()
    }
}

/// Discovery configuration (user-friendly wrapper)
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
    /// Allow specific IOCTL types (overrides safety defaults)
    pub allow_types: Option<Vec<u8>>,
    /// Deny specific IOCTL types (added to defaults)
    pub deny_types: Option<Vec<u8>>,
    /// Only warn about dangerous types instead of failing
    pub warn_only_on_dangerous: bool,
    /// Try to discover correct buffer sizes
    pub try_find_size: bool,
    /// Delay between IOCTL calls in milliseconds
    pub delay_between_calls_ms: u64,
    /// Maximum calls per second (None = unlimited)
    pub max_calls_per_second: Option<u32>,
    /// Maximum total calls for the scan
    pub max_total_calls: Option<u32>,
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
            deny_types: None,
            warn_only_on_dangerous: false,
            try_find_size: false,
            delay_between_calls_ms: 0,
            max_calls_per_second: Some(1000),
            max_total_calls: Some(10000),
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
            parallel: false,
            allow_types: None,
            deny_types: None,
            warn_only_on_dangerous: false,
            try_find_size: false,
            delay_between_calls_ms: 0,
            max_calls_per_second: Some(100),
            max_total_calls: Some(1000),
        }
    }

    /// Debug options for full discovery
    pub fn debug() -> Self {
        Self {
            verbosity: Verbosity::Debug,
            max_results: usize::MAX,
            skip_details: false,
            focus_nr: None,
            parallel: false,
            allow_types: None,
            deny_types: None,
            warn_only_on_dangerous: true, // Allow more in debug mode
            try_find_size: true, // Enable size discovery in debug
            delay_between_calls_ms: 1, // Small delay to prevent flooding
            max_calls_per_second: Some(500),
            max_total_calls: Some(5000),
        }
    }
    
    /// Safe options for embedded systems
    pub fn embedded() -> Self {
        Self {
            verbosity: Verbosity::Minimal,
            max_results: 3,
            skip_details: true,
            focus_nr: None,
            parallel: false,
            allow_types: None,
            deny_types: Some(vec![0x12, 0x88, 0x8B, 0xFD, 0xFE, 0xFF, 0x00, 0x01]), // Extended blacklist
            warn_only_on_dangerous: false,
            try_find_size: false,
            delay_between_calls_ms: 10, // Conservative delay
            max_calls_per_second: Some(50),
            max_total_calls: Some(500),
        }
    }
    
    /// Aggressive options for comprehensive scanning
    pub fn aggressive() -> Self {
        Self {
            verbosity: Verbosity::Detailed,
            max_results: usize::MAX,
            skip_details: false,
            focus_nr: None,
            parallel: true,
            allow_types: None,
            deny_types: Some(vec![]), // Empty deny list
            warn_only_on_dangerous: true,
            try_find_size: true,
            delay_between_calls_ms: 0,
            max_calls_per_second: None, // No limit
            max_total_calls: None, // No limit
        }
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_results == 0 {
            return Err("max_results must be at least 1".to_string());
        }
        
        if let Some(max_calls) = self.max_calls_per_second {
            if max_calls == 0 {
                return Err("max_calls_per_second must be at least 1".to_string());
            }
        }
        
        if let Some(max_total) = self.max_total_calls {
            if max_total == 0 {
                return Err("max_total_calls must be at least 1".to_string());
            }
        }
        
        if self.try_find_size && !self.warn_only_on_dangerous {
            return Err("try_find_size requires warn_only_on_dangerous=true for safety".to_string());
        }
        
        Ok(())
    }
}

impl Into<ScannerOptions> for DiscoveryConfig {
    fn into(self) -> ScannerOptions {
        // Start with scanner defaults
        let mut scanner_options = ScannerOptions::default();
        
        // Override with user settings
        scanner_options.verbosity = self.verbosity;
        scanner_options.max_results = self.max_results;
        scanner_options.skip_details = self.skip_details;
        scanner_options.focus_nr = self.focus_nr;
        scanner_options.parallel = self.parallel;
        scanner_options.warn_only_on_dangerous = self.warn_only_on_dangerous;
        scanner_options.try_find_size = self.try_find_size;
        scanner_options.delay_between_calls_ms = self.delay_between_calls_ms;
        scanner_options.max_calls_per_second = self.max_calls_per_second;
        scanner_options.max_total_calls = self.max_total_calls;
        
        // Handle allow/deny types
        if let Some(allow_types) = self.allow_types {
            scanner_options.allow_types = Some(allow_types);
            scanner_options.deny_types = vec![]; // Clear deny list when allow list is specified
        } else if let Some(additional_deny) = self.deny_types {
            // Add to existing deny list
            scanner_options.deny_types.extend(additional_deny);
            scanner_options.deny_types.sort();
            scanner_options.deny_types.dedup();
        }
        
        scanner_options
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
    /// Get numeric value for comparison
    pub fn value(&self) -> u8 {
        match self {
            Verbosity::Minimal => 0,
            Verbosity::Normal => 1,
            Verbosity::Detailed => 2,
            Verbosity::Debug => 3,
        }
    }

    /// Check if this verbosity is at least the given level
    pub fn is_at_least(&self, level: Verbosity) -> bool {
        self.value() >= level.value()
    }
}

// Also need to update the public API functions in lib.rs and api.rs
// to accept the new DiscoveryConfig parameter

/// Convenience function to scan with default configuration
pub fn scan_device_default(device_path: Option<&str>) -> io::Result<DiscoveryResult> {
    scan_device(device_path, None)
}