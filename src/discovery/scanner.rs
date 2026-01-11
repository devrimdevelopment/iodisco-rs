//! Systematic and safe IOCTL scanner with comprehensive safety features

use std::fs;
use std::io::{self, Write};
use libc;
use std::os::unix::io::RawFd;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU32, Ordering};
use serde::{Serialize, Deserialize};
use crate::discovery::Verbosity;
use chrono;

/// IOCTL discovery scanner with built-in safety mechanisms
pub struct IoctlDiscovery {
    fd: RawFd,
    pub results: Vec<IoctlResult>,
    options: DiscoveryOptions,
    call_counter: AtomicU32,
    last_call_time: Instant,
    // Keep buffers alive for kernel to write into
    active_buffers: Vec<Box<[u8]>>,
}

/// Configuration options for the discovery process
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Verbosity level for output
    pub verbosity: Verbosity,
    /// Maximum results to show per category
    pub max_results: usize,
    /// Skip detailed analysis
    pub skip_details: bool,
    /// Focus on specific NR values
    pub focus_nr: Option<Vec<u8>>,
    /// Use parallel scanning (experimental)
    pub parallel: bool,
    
    /// Safety: explicitly allowed ioctl types (takes precedence over deny list)
    pub allow_types: Option<Vec<u8>>,
    /// Safety: denied ioctl types (only applied when allow_types is None)
    pub deny_types: Vec<u8>,
    /// Safety: when true, only warn about dangerous types instead of failing
    pub warn_only_on_dangerous: bool,
    /// Safety: when true, attempt to find exact argument size on EFAULT
    pub try_find_size: bool,
    
    /// Rate limiting: delay between ioctl calls in milliseconds
    pub delay_between_calls_ms: u64,
    /// Rate limiting: maximum calls per second (None = unlimited)
    pub max_calls_per_second: Option<u32>,
    /// Rate limiting: maximum total calls for entire scan
    pub max_total_calls: Option<u32>,
    
    /// Size discovery: maximum attempts for size discovery
    pub max_size_discovery_attempts: u8,
    /// Size discovery: candidate sizes to try
    pub size_discovery_candidates: Vec<u16>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            verbosity: Verbosity::Normal,
            max_results: 10,
            skip_details: false,
            focus_nr: None,
            parallel: false,
            
            allow_types: None,
            // Known dangerous / high-risk ioctl type ranges
            // May cause data corruption, crashes, hardware damage, etc.
            deny_types: vec![0x12, 0x88, 0x8B, 0xFD, 0xFE, 0xFF],
            warn_only_on_dangerous: false,
            try_find_size: false, // Disabled by default for safety
            
            delay_between_calls_ms: 0,
            max_calls_per_second: Some(1000), // Reasonable default: 1000 calls/sec
            max_total_calls: Some(10000),     // Limit total scan to 10k calls
            
            max_size_discovery_attempts: 5,
            size_discovery_candidates: vec![4, 8, 16, 24, 32, 40, 48, 64, 80, 96, 128, 256],
        }
    }
}

impl DiscoveryOptions {
    /// Validate configuration options
    pub fn validate(&self) -> Result<(), String> {
        // Check for conflicting options
        if self.allow_types.is_some() && !self.deny_types.is_empty() {
            return Err("Cannot specify both allow_types and deny_types - use one or the other".to_string());
        }
        
        // Validate size discovery safety
        if self.try_find_size && !self.warn_only_on_dangerous {
            return Err("try_find_size requires warn_only_on_dangerous=true for safety".to_string());
        }
        
        // Validate max_results
        if self.max_results == 0 {
            return Err("max_results must be at least 1".to_string());
        }
        
        // Validate rate limiting
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
        
        // Validate size discovery attempts
        if self.max_size_discovery_attempts == 0 {
            return Err("max_size_discovery_attempts must be at least 1".to_string());
        }
        
        Ok(())
    }
    
    /// Quick options for safe, minimal scanning
    pub fn quick() -> Self {
        Self {
            verbosity: Verbosity::Minimal,
            max_results: 5,
            skip_details: true,
            warn_only_on_dangerous: false,
            max_calls_per_second: Some(100),
            max_total_calls: Some(1000),
            ..Default::default()
        }
    }
    
    /// Debug options for full discovery (with safety)
    pub fn debug() -> Self {
        Self {
            verbosity: Verbosity::Debug,
            max_results: usize::MAX,
            skip_details: false,
            warn_only_on_dangerous: true,  // Allow more access in debug mode
            max_calls_per_second: Some(500),
            max_total_calls: Some(5000),
            ..Default::default()
        }
    }
    
    /// Options for embedded/safe scanning
    pub fn embedded() -> Self {
        Self {
            verbosity: Verbosity::Minimal,
            max_results: 3,
            skip_details: true,
            warn_only_on_dangerous: false,
            max_calls_per_second: Some(50),  // Very conservative
            max_total_calls: Some(500),      // Very limited
            deny_types: vec![0x12, 0x88, 0x8B, 0xFD, 0xFE, 0xFF, 0x00, 0x01], // Extended blacklist
            ..Default::default()
        }
    }
}

/// Single IOCTL test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoctlResult {
    /// Full IOCTL command number
    pub cmd: u32,
    /// Direction bits (0=NONE, 1=WRITE, 2=READ, 3=READ|WRITE)
    pub dir: u8,
    /// Type/magic number field
    pub ty: u8,
    /// Command number within type
    pub nr: u8,
    /// Size of the argument structure (original or discovered)
    pub size: u16,
    /// Result when called with NULL pointer argument
    pub null_result: (i32, i32), // (return value, errno)
    /// Result when called with pointer argument (if tested)
    pub ptr_result: Option<(i32, i32)>,
    /// Interpretation of the result
    pub interpretation: Interpretation,
    /// If size was auto-discovered, store the found size here
    pub discovered_size: Option<u16>,
    /// Timestamp of when this test was performed
    pub timestamp: Option<String>,
    /// Whether this IOCTL is considered potentially dangerous
    pub is_potentially_dangerous: bool,
}

impl IoctlResult {
    /// Create a new IoctlResult with optional discovered size
    pub fn new(
        cmd: u32,
        dir: u8,
        ty: u8,
        nr: u8,
        size: u16,
        null_result: (i32, i32),
        ptr_result: Option<(i32, i32)>,
        interpretation: Interpretation,
        discovered_size: Option<u16>,
        is_potentially_dangerous: bool,
    ) -> Self {
        Self {
            cmd,
            dir,
            ty,
            nr,
            size,
            null_result,
            ptr_result,
            interpretation,
            discovered_size,
            timestamp: Some(chrono::Local::now().to_rfc3339()),
            is_potentially_dangerous,
        }
    }
    
    /// Check if this IOCTL appears to be valid (exists and might work)
    pub fn is_valid(&self) -> bool {
        !matches!(self.interpretation, Interpretation::NotExist)
    }
    
    /// Check if this IOCTL call was successful
    pub fn is_successful(&self) -> bool {
        matches!(self.interpretation, Interpretation::Success)
    }
}

/// Interpretation of an IOCTL call result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Interpretation {
    /// IOCTL does not exist (usually ENOTTY)
    NotExist,
    /// IOCTL exists but returned an error
    Exists,
    /// Permission denied (EPERM / EACCES)
    Permission,
    /// Call succeeded (return value >= 0)
    Success,
    /// Other/unknown error code
    Unknown(i32),
}

/// Structured result of IOCTL test
#[derive(Debug)]
pub struct IoctlTestResult {
    pub cmd: u32,
    pub result: i32,
    pub errno: i32,
    pub returns_data: bool,
}

impl IoctlTestResult {
    /// Check if IOCTL was successful for general purposes
    pub fn is_success(&self) -> bool {
        // Standard: Success, EFAULT, or EINVAL
        self.errno == 0 || self.errno == 14 || self.errno == 22
    }

    /// Check if IOCTL exists (for profile detection)
    pub fn exists(&self) -> bool {
        match self.errno {
            0 | 14 | 22 => true,  // Success or parameter errors
            1 => true,             // EPERM: exists, but no rights
            25 => false,           // ENOTTY: does not exist
            _ => false,            // Other errors: conservative
        }
    }
}

impl IoctlDiscovery {
    /// Open device file for IOCTL discovery with safety checks
    pub fn open(device: &str, options: DiscoveryOptions) -> io::Result<Self> {
        // Validate options before opening device
        options.validate()?;
        
        let c_path = std::ffi::CString::new(device)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Always try read-only first (safer)
        let mut fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            // Only try read-write if we have to and warnings are enabled
            if options.warn_only_on_dangerous {
                if options.verbosity.is_at_least(Verbosity::Normal) {
                    eprintln!("⚠️  Falling back to O_RDWR mode (read-only failed)");
                }
                fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
            }
        }

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            results: Vec::new(),
            options,
            call_counter: AtomicU32::new(0),
            last_call_time: Instant::now(),
            active_buffers: Vec::new(),
        })
    }

    /// Validate configuration
    pub fn validate_configuration(&self) -> Result<(), String> {
        self.options.validate()
    }

    /// Close the device file descriptor
    pub fn close(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
        // Clear buffers when closing
        self.active_buffers.clear();
    }

    /// Execute single ioctl call with rate limiting and safety checks
    pub fn test_ioctl(&self, cmd: u32, arg: usize) -> io::Result<(i32, i32)> {
        // Rate limiting
        self.enforce_rate_limit()?;
        
        // Check device health before call
        if !self.is_device_alive() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Device appears to be unresponsive"
            ));
        }
        
        let result = unsafe { libc::ioctl(self.fd, cmd as i32, arg) };
        let errno = if result < 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        
        Ok((result, errno))
    }

    /// Test single IOCTL command and return structured test result
    pub fn test_single_ioctl(&self, cmd: u32) -> io::Result<IoctlTestResult> {
        let (result, errno) = self.test_ioctl(cmd, 0)?;
        
        Ok(IoctlTestResult {
            cmd,
            result,
            errno,
            returns_data: errno != 25, // ENOTTY = does not exist
        })
    }

    /// Execute IOCTL with buffer and return the resulting data (if any)
    pub fn execute_ioctl(&mut self, cmd: u32, buffer_size: usize) -> io::Result<Vec<u8>> {
        // Create buffer and keep it alive
        let buffer = vec![0u8; buffer_size].into_boxed_slice();
        let ptr = buffer.as_ptr() as usize;
        
        // Store buffer to keep it alive
        self.active_buffers.push(buffer);
        
        let result = unsafe { libc::ioctl(self.fd, cmd as i32, ptr) };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            // Retrieve the buffer data
            if let Some(buffer) = self.active_buffers.pop() {
                Ok(buffer.to_vec())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Buffer lost - this should not happen"
                ))
            }
        }
    }

    /// Analyze one specific IOCTL combination
    fn analyze_ioctl(&mut self, dir: u8, ty: u8, nr: u8, size: u16) -> io::Result<()> {
        let is_dangerous = self.is_potentially_dangerous(ty);
        let cmd = ((dir as u32) << 30) | ((size as u32) << 16) | ((ty as u32) << 8) | (nr as u32);

        // Test with null pointer first
        let null_result = self.test_ioctl(cmd, 0)?;

        let mut ptr_result = None;
        let mut discovered_size = None;
        let mut final_interpretation = Interpretation::NotExist;

        if null_result.1 != 25 {  // Not ENOTTY - exists in some form
            // Test with buffer of specified size
            let buffer = vec![0u8; size as usize].into_boxed_slice();
            let ptr = buffer.as_ptr() as usize;
            self.active_buffers.push(buffer); // Keep buffer alive
            
            ptr_result = Some(self.test_ioctl(cmd, ptr)?);
            
            let initial_ptr = ptr_result.unwrap_or(null_result);
            final_interpretation = match initial_ptr {
                (_, 25) => Interpretation::NotExist,
                (_, 1) | (_, 13) => Interpretation::Permission,
                (_, 14) | (_, 22) => Interpretation::Exists,
                (r, 0) if r >= 0 => Interpretation::Success,
                (_, err) => Interpretation::Unknown(err),
            };

            // Optional size discovery (only if enabled and safe)
            if self.options.try_find_size 
                && !is_dangerous 
                && initial_ptr.1 == 14  // EFAULT
            {
                // Try to discover correct size
                if let Some(found_size) = self.try_discover_size(dir, ty, nr, size)? {
                    discovered_size = Some(found_size);
                    // Update cmd and result with discovered size
                    let new_cmd = ((dir as u32) << 30) | ((found_size as u32) << 16) | ((ty as u32) << 8) | (nr as u32);
                    let new_buffer = vec![0u8; found_size as usize].into_boxed_slice();
                    let new_ptr = new_buffer.as_ptr() as usize;
                    self.active_buffers.push(new_buffer);
                    
                    ptr_result = Some(self.test_ioctl(new_cmd, new_ptr)?);
                    
                    // Re-evaluate interpretation with new size
                    final_interpretation = match ptr_result.unwrap() {
                        (r, 0) if r >= 0 => Interpretation::Success,
                        (_, 22) => Interpretation::Exists,
                        (_, err) => Interpretation::Unknown(err),
                    };
                }
            }
        }

        self.results.push(IoctlResult::new(
            cmd,
            dir,
            ty,
            nr,
            size,
            null_result,
            ptr_result,
            final_interpretation,
            discovered_size,
            is_dangerous,
        ));

        Ok(())
    }

    /// Try to discover correct buffer size for an IOCTL
    fn try_discover_size(&mut self, dir: u8, ty: u8, nr: u8, original_size: u16) -> io::Result<Option<u16>> {
        let mut attempts = 0;
        
        for &test_size in &self.options.size_discovery_candidates {
            if test_size == original_size { 
                continue; 
            }
            
            if attempts >= self.options.max_size_discovery_attempts {
                break;
            }
            
            let cmd = ((dir as u32) << 30) | ((test_size as u32) << 16) | ((ty as u32) << 8) | (nr as u32);
            let buffer = vec![0u8; test_size as usize].into_boxed_slice();
            let ptr = buffer.as_ptr() as usize;
            self.active_buffers.push(buffer);
            
            let result = self.test_ioctl(cmd, ptr)?;
            
            if result.1 == 0 && result.0 >= 0 {  // Success
                return Ok(Some(test_size));
            } else if result.1 == 22 {  // EINVAL - possible match
                return Ok(Some(test_size));
            }
            
            attempts += 1;
        }
        
        Ok(None)
    }

    /// Check if given type is considered potentially dangerous
    pub fn is_potentially_dangerous(&self, ty: u8) -> bool {
        self.options.deny_types.contains(&ty)
    }

    /// Check whether scanning this type is allowed
    pub fn is_allowed(&self, ty: u8) -> bool {
        // Whitelist takes precedence
        if let Some(allowed) = &self.options.allow_types {
            return allowed.contains(&ty);
        }
        // Otherwise apply blacklist
        !self.is_potentially_dangerous(ty)
    }

    /// Get risk description for a type
    pub fn get_risk_description(&self, ty: u8) -> Option<&'static str> {
        match ty {
            0xFF => Some("HIGH RISK: May cause hardware damage or system crashes"),
            0xFD => Some("MEDIUM RISK: May cause driver instability or data corruption"),
            0xFE => Some("UNKNOWN RISK: Experimental or undocumented functionality"),
            0x88 => Some("MEDIUM RISK: Memory operations that could cause instability"),
            0x8B => Some("MEDIUM RISK: Potential hardware configuration changes"),
            0x12 => Some("MEDIUM RISK: May trigger hardware resets"),
            _ => None,
        }
    }

    /// Scan all possible IOCTLs for one specific type/magic number
    pub fn scan_type(&mut self, ty: u8) -> io::Result<()> {
        if !self.is_allowed(ty) {
            let msg = if let Some(risk_desc) = self.get_risk_description(ty) {
                format!("IOCTL type 0x{:02x}: {}", ty, risk_desc)
            } else {
                format!("IOCTL type 0x{:02x} is not allowed by configuration", ty)
            };

            if self.options.warn_only_on_dangerous {
                if self.options.verbosity.is_at_least(Verbosity::Normal) {
                    eprintln!("⚠️  WARNING: {}", msg);
                    eprintln!("   Continuing at user's risk...");
                }
                // Log warning
                self.log_warning(&msg);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{}\nUse 'allow_types' configuration or 'warn_only_on_dangerous' to override", msg)
                ));
            }
        }

        if self.options.verbosity.is_at_least(Verbosity::Debug) {
            println!("🔍 Scanning Type 0x{:02x}...", ty);
        }

        let sizes = [1u16, 2, 4, 8, 16, 32, 64, 128];
        let dirs = [0u8, 1, 2, 3];

        for nr in 0x00..=0xFFu8 {
            // Check if we should focus on specific NR values
            if let Some(focus_nrs) = &self.options.focus_nr {
                if !focus_nrs.contains(&nr) {
                    continue;
                }
            }

            if self.options.verbosity.is_at_least(Verbosity::Debug) && nr % 16 == 0 {
                print!(".");
                let _ = io::stdout().flush();
            }

            for &size in &sizes {
                for &dir in &dirs {
                    if let Err(e) = self.analyze_ioctl(dir, ty, nr, size) {
                        if self.options.verbosity.is_at_least(Verbosity::Normal) {
                            eprintln!("Error analyzing 0x{:02x}.{:02x}: {}", ty, nr, e);
                        }
                        // Continue with next NR on error
                        break;
                    }
                }
            }
        }

        if self.options.verbosity.is_at_least(Verbosity::Debug) {
            println!();
        }

        Ok(())
    }

    /// Print discovery results
    pub fn print_results(&self) {
        if self.options.verbosity == Verbosity::Minimal {
            self.print_minimal_summary();
            return;
        }
        
        println!("\n📊 DISCOVERY RESULTS:");
        println!("======================");
        
        // Categorize results
        let (dangerous, safe): (Vec<&IoctlResult>, Vec<&IoctlResult>) = 
            self.results.iter().partition(|r| r.is_potentially_dangerous);
        
        if !dangerous.is_empty() && self.options.verbosity.is_at_least(Verbosity::Normal) {
            println!("\n⚠️  POTENTIALLY DANGEROUS IOCTLs ({}):", dangerous.len());
            for result in dangerous.iter().take(self.options.max_results.min(5)) {
                println!("  0x{:08x} (type=0x{:02x}, nr=0x{:02x}) - {}",
                        result.cmd, result.ty, result.nr,
                        self.get_risk_description(result.ty).unwrap_or("Unknown risk"));
            }
            if dangerous.len() > 5 {
                println!("    ... and {} more dangerous IOCTLs", dangerous.len() - 5);
            }
        }
        
        // Group safe results by interpretation
        let mut by_status = HashMap::new();
        for result in &safe {
            let status = match &result.interpretation {
                Interpretation::NotExist => "Not existent",
                Interpretation::Exists => "Exists (EFAULT/EINVAL)",
                Interpretation::Permission => "Permission-Gated",
                Interpretation::Success => "Successful",
                Interpretation::Unknown(e) => &format!("Unknown (errno={})", e),
            };
            by_status.entry(status.to_string()).or_insert_with(Vec::new).push(result);
        }
        
        // Show interesting categories first
        let categories = ["Successful", "Exists (EFAULT/EINVAL)", "Permission-Gated", "Unknown"];
        for category in &categories {
            if let Some(results) = by_status.get(*category) {
                let max_show = if self.options.verbosity == Verbosity::Normal {
                    self.options.max_results
                } else {
                    results.len()
                };
                
                println!("\n{} ({}):", category, results.len());
                for result in results.iter().take(max_show) {
                    let disc_size = if let Some(ds) = result.discovered_size {
                        format!(" (discovered: {})", ds)
                    } else {
                        String::new()
                    };
                    println!("  0x{:08x}: type=0x{:02x}, nr=0x{:02x}, size={}{}, dir={}",
                            result.cmd, result.ty, result.nr, result.size, disc_size,
                            match result.dir { 
                                0 => "NONE", 1 => "WRITE", 2 => "READ", 3 => "READ|WRITE", _ => "??" 
                            });
                }
                if results.len() > max_show && self.options.verbosity == Verbosity::Normal {
                    println!("    ... and {} more", results.len() - max_show);
                }
            }
        }
        
        // Statistics
        let total = self.results.len();
        let not_exist = by_status.get("Not existent").map_or(0, |v| v.len());
        let exists = total - not_exist;
        
        println!("\n📈 STATISTICS:");
        println!("  Total tested: {} IOCTLs", total);
        println!("  Not existent: {} IOCTLs", not_exist);
        println!("  Potentially existent: {} IOCTLs", exists);
        println!("  Dangerous types found: {} IOCTLs", dangerous.len());
        
        if !dangerous.is_empty() {
            println!("  ⚠️  WARNING: {} potentially dangerous IOCTLs were tested!", dangerous.len());
        }
        
        // Find most common type
        let mut type_count = HashMap::new();
        for result in &self.results {
            if result.is_valid() {
                *type_count.entry(result.ty).or_insert(0) += 1;
            }
        }
        
        if let Some((best_type, count)) = type_count.iter().max_by_key(|(_, &c)| c) {
            println!("  Most common type: 0x{:02x} ({} valid IOCTLs)", best_type, count);
        }
    }

    /// Print minimal summary
    fn print_minimal_summary(&self) {
        let mut by_status = HashMap::new();
        let dangerous_count = self.results.iter()
            .filter(|r| r.is_potentially_dangerous)
            .count();
        
        for result in &self.results {
            let status = match &result.interpretation {
                Interpretation::NotExist => "NotExist",
                Interpretation::Exists => "Exists",
                Interpretation::Permission => "Permission",
                Interpretation::Success => "Success",
                Interpretation::Unknown(_) => "Unknown",
            };
            *by_status.entry(status).or_insert(0) += 1;
        }
        
        println!("\n📊 MINIMAL SUMMARY:");
        println!("  Total: {}", self.results.len());
        for (status, count) in &by_status {
            println!("  {}: {}", status, count);
        }
        if dangerous_count > 0 {
            println!("  ⚠️ Dangerous: {}", dangerous_count);
        }
    }

    /// Find the type with most working IOCTLs
    pub fn find_best_type(&self) -> Option<u8> {
        let mut type_scores = HashMap::new();
        for result in &self.results {
            if result.is_valid() && !result.is_potentially_dangerous {
                *type_scores.entry(result.ty).or_insert(0) += 1;
            }
        }
        type_scores.iter().max_by_key(|(_, &score)| score).map(|(&ty, _)| ty)
    }

    /// Get interesting NR values for a type
    pub fn get_interesting_nrs(&self, ty: u8) -> Vec<u8> {
        let mut nrs = HashMap::new();
        for result in &self.results {
            if result.ty == ty && result.is_valid() && !result.is_potentially_dangerous {
                nrs.entry(result.nr).or_insert(true);
            }
        }
        let mut sorted_nrs: Vec<u8> = nrs.keys().cloned().collect();
        sorted_nrs.sort();
        sorted_nrs
    }

    /// Export results to JSON
    pub fn export_json(&self, path: &str) -> io::Result<()> {
        use std::fs::File;
        
        #[derive(Serialize)]
        struct JsonOutput {
            results: Vec<IoctlResult>,
            statistics: JsonStatistics,
            metadata: JsonMetadata,
        }
        
        #[derive(Serialize)]
        struct JsonStatistics {
            total: usize,
            not_existent: usize,
            potentially_existent: usize,
            dangerous: usize,
            successful: usize,
        }
        
        #[derive(Serialize)]
        struct JsonMetadata {
            timestamp: String,
            iodisco_version: &'static str,
            options: DiscoveryOptions,
        }
        
        let not_existent = self.results.iter()
            .filter(|r| matches!(&r.interpretation, Interpretation::NotExist))
            .count();
        
        let dangerous = self.results.iter()
            .filter(|r| r.is_potentially_dangerous)
            .count();
        
        let successful = self.results.iter()
            .filter(|r| matches!(&r.interpretation, Interpretation::Success))
            .count();
        
        let output = JsonOutput {
            results: self.results.clone(),
            statistics: JsonStatistics {
                total: self.results.len(),
                not_existent,
                potentially_existent: self.results.len() - not_existent,
                dangerous,
                successful,
            },
            metadata: JsonMetadata {
                timestamp: chrono::Local::now().to_rfc3339(),
                iodisco_version: crate::VERSION,
                options: self.options.clone(),
            },
        };
        
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, &output)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        Ok(())
    }

    /// Generate profile template
    pub fn generate_profile_template(&self, output_path: &str) -> io::Result<()> {
        use std::fs::File;
        
        #[derive(Serialize)]
        struct ProfileTemplate {
            profile_version: String,
            vendor: String,
            model: String,
            description: String,
            detection_ioctls: Vec<DetectedIoctlTemplate>,
            info_ioctls: Vec<IoctlTemplate>,
            metadata: serde_json::Value,
        }
        
        #[derive(Serialize)]
        struct DetectedIoctlTemplate {
            name: String,
            cmd: String,
            size: u16,
            discovered_size: Option<u16>,
            dir: String,
            interpretation: String,
            is_dangerous: bool,
        }
        
        #[derive(Serialize)]
        struct IoctlTemplate {
            name: String,
            cmd: String,
            expected_size: u16,
            description: String,
        }
        
        // Find working IOCTLs (safe ones only)
        let working_ioctls: Vec<&IoctlResult> = self.results.iter()
            .filter(|r| r.is_successful() && !r.is_potentially_dangerous)
            .collect();
        
        let detection_ioctls: Vec<DetectedIoctlTemplate> = working_ioctls.iter()
            .take(5)
            .map(|r| DetectedIoctlTemplate {
                name: format!("unknown_{:02x}_{:02x}", r.ty, r.nr),
                cmd: format!("0x{:08x}", r.cmd),
                size: r.size,
                discovered_size: r.discovered_size,
                dir: match r.dir {
                    0 => "NONE".to_string(),
                    1 => "WRITE".to_string(),
                    2 => "READ".to_string(),
                    3 => "READ|WRITE".to_string(),
                    _ => "UNKNOWN".to_string(),
                },
                interpretation: "Success".to_string(),
                is_dangerous: r.is_potentially_dangerous,
            })
            .collect();
        
        let template = ProfileTemplate {
            profile_version: "1.0.0".to_string(),
            vendor: "Unknown".to_string(),
            model: "Unknown Model".to_string(),
            description: "Auto-generated profile. Please fill in details.".to_string(),
            detection_ioctls,
            info_ioctls: vec![],
            metadata: serde_json::json!({
                "generated_at": chrono::Local::now().to_rfc3339(),
                "total_results": self.results.len(),
                "successful_results": working_ioctls.len(),
            }),
        };
        
        let file = File::create(output_path)?;
        serde_json::to_writer_pretty(file, &template)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        Ok(())
    }

    // ========== SAFETY METHODS ==========
    
    /// Enforce rate limiting between calls
    fn enforce_rate_limit(&self) -> io::Result<()> {
        let current_calls = self.call_counter.fetch_add(1, Ordering::SeqCst);
        
        // Check total calls limit
        if let Some(max_total) = self.options.max_total_calls {
            if current_calls >= max_total {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Exceeded maximum call limit of {}", max_total)
                ));
            }
        }
        
        // Check calls per second
        if let Some(max_per_second) = self.options.max_calls_per_second {
            let elapsed = self.last_call_time.elapsed();
            if elapsed < Duration::from_secs(1) {
                // Simpler rate limiting - just sleep a bit
                std::thread::sleep(Duration::from_millis(1000 / max_per_second as u64));
            }
        }
        
        // Enforce delay between calls
        if self.options.delay_between_calls_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.options.delay_between_calls_ms));
        }
        
        Ok(())
    }
    
    /// Check if device is still responsive
    fn is_device_alive(&self) -> bool {
        unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            libc::fstat(self.fd, &mut stat) == 0
        }
    }
    
    /// Log warning message
    fn log_warning(&self, message: &str) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/iodisco_warnings.log") 
        {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(file, "[{}] {}", timestamp, message);
        }
    }
    
    /// Get total number of IOCTL calls made
    pub fn get_call_count(&self) -> u32 {
        self.call_counter.load(Ordering::SeqCst)
    }
}

// Implement Drop to ensure device is closed
impl Drop for IoctlDiscovery {
    fn drop(&mut self) {
        self.close();
    }
}