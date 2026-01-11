//! Systematic IOCTL scanner

use std::fs;
use std::io::{self, Write};
use libc;
use std::os::unix::io::RawFd;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::discovery::Verbosity;

/// IOCTL discovery scanner
pub struct IoctlDiscovery {
    fd: RawFd,
    pub results: Vec<IoctlResult>,
    options: DiscoveryOptions,
}

/// Configuration options for the discovery process
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub verbosity: Verbosity,
    pub max_results: usize,
    pub skip_details: bool,
    pub focus_nr: Option<Vec<u8>>,
    pub parallel: bool,
    /// Explicitly allowed ioctl types (takes precedence over deny list)
    pub allow_types: Option<Vec<u8>>,
    /// Denied ioctl types (only applied when allow_types is None)
    pub deny_types: Vec<u8>,
    /// When true, only warn about dangerous types instead of failing
    pub warn_only_on_dangerous: bool,
    /// When true, attempt to find exact argument size on EFAULT (limited and optional)
    pub try_find_size: bool,
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
        }
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

impl IoctlDiscovery {
    /// Open device file for IOCTL discovery
    pub fn open(device: &str, options: DiscoveryOptions) -> io::Result<Self> {
        let c_path = std::ffi::CString::new(device)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Try read-only first, then read-write
        let mut fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        }

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            results: Vec::new(),
            options,
        })
    }

    /// Close the device file descriptor
    pub fn close(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }

    /// Execute single ioctl call and return (return_value, errno)
    pub fn test_ioctl(&self, cmd: u32, arg: usize) -> (i32, i32) {
        let result = unsafe { libc::ioctl(self.fd, cmd as i32, arg) };
        let errno = if result < 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        (result, errno)
    }

    /// Test single IOCTL command and return structured test result
    pub fn test_single_ioctl(&self, cmd: u32) -> IoctlTestResult {
        let (result, errno) = self.test_ioctl(cmd, 0);
        IoctlTestResult {
            cmd,
            result,
            errno,
            returns_data: errno != 25, // ENOTTY = does not exist
        }
    }

    /// Execute IOCTL with buffer and return the resulting data (if any)
    pub fn execute_ioctl(&self, cmd: u32, buffer_size: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; buffer_size];
        let ptr_arg = buffer.as_mut_ptr() as usize;
        let result = unsafe { libc::ioctl(self.fd, cmd as i32, ptr_arg) };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(buffer)
        }
    }

    /// Analyze one specific IOCTL combination
    fn analyze_ioctl(&mut self, dir: u8, ty: u8, nr: u8, size: u16) {
        let cmd = ((dir as u32) << 30) | ((size as u32) << 16) | ((ty as u32) << 8) | (nr as u32);

        let null_result = self.test_ioctl(cmd, 0);

        let mut ptr_result = None;
        let mut discovered_size = None;
        let mut final_interpretation = Interpretation::NotExist;

        if null_result.1 != 25 {  // Not ENOTTY - exists in some form
            // First try with provided size
            let mut buffer = vec![0u8; size as usize];
            let ptr_arg = buffer.as_mut_ptr() as usize;
            ptr_result = Some(self.test_ioctl(cmd, ptr_arg));

            let initial_ptr = ptr_result.unwrap_or(null_result);
            final_interpretation = match initial_ptr {
                (_, 25) => Interpretation::NotExist,
                (_, 1) | (_, 13) => Interpretation::Permission,
                (_, 14) | (_, 22) => Interpretation::Exists,
                (r, 0) if r >= 0 => Interpretation::Success,
                (_, err) => Interpretation::Unknown(err),
            };

            // Optional limited size discovery on EFAULT (only if enabled and initial was EFAULT)
            if self.options.try_find_size && initial_ptr.1 == 14 {  // EFAULT
                // Limited set of common structure sizes (powers of 2 + offsets)
                let candidate_sizes: [u16; 12] = [4, 8, 16, 24, 32, 40, 48, 64, 80, 96, 128, 256];

                for &test_size in &candidate_sizes {
                    if test_size == size { continue; }  // Skip already tested

                    let new_cmd = ((dir as u32) << 30) | ((test_size as u32) << 16) | ((ty as u32) << 8) | (nr as u32);
                    let mut test_buffer = vec![0u8; test_size as usize];
                    let test_ptr_arg = test_buffer.as_mut_ptr() as usize;
                    let test_result = self.test_ioctl(new_cmd, test_ptr_arg);

                    if test_result.1 == 0 && test_result.0 >= 0 {  // Success
                        discovered_size = Some(test_size);
                        ptr_result = Some(test_result);
                        final_interpretation = Interpretation::Success;
                        break;  // Stop on first success
                    } else if test_result.1 == 22 {  // EINVAL - possible match but invalid data
                        discovered_size = Some(test_size);
                        ptr_result = Some(test_result);
                        final_interpretation = Interpretation::Exists;
                        break;  // Conservative: stop on EINVAL as potential match
                    }
                    // Continue on EFAULT or other errors
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
        ));
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

    /// Scan all possible IOCTLs for one specific type/magic number
    pub fn scan_type(&mut self, ty: u8) -> io::Result<()> {
        if !self.is_allowed(ty) {
            let msg = format!("IOCTL type 0x{:02x} is considered potentially dangerous", ty);

            if self.options.warn_only_on_dangerous {
                eprintln!("⚠️  WARNING: {}", msg);
                eprintln!("     Continuing because warn_only_on_dangerous is enabled");
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} (use allow_types or warn_only_on_dangerous to override)", msg)
                ));
            }
        }

        if self.options.verbosity.is_at_least(Verbosity::Debug) {
            println!("🔍 Scanning Type 0x{:02x}...", ty);
        }

        let sizes = [1u16, 2, 4, 8, 16, 32, 64, 128];
        let dirs = [0u8, 1, 2, 3];

        for nr in 0x00..=0xFFu8 {
            if self.options.verbosity.is_at_least(Verbosity::Debug) && nr % 16 == 0 {
                print!(".");
                let _ = io::stdout().flush();
            }

            for &size in &sizes {
                for &dir in &dirs {
                    self.analyze_ioctl(dir, ty, nr, size);
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
        let mut by_status = HashMap::new();
        for result in &self.results {
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
                    println!(" 0x{:08x}: type=0x{:02x}, nr=0x{:02x}, size={}{}, dir={}",
                            result.cmd, result.ty, result.nr, result.size, disc_size,
                            match result.dir { 0 => "NONE", 1 => "WRITE", 2 => "READ", 3 => "READ|WRITE", _ => "??" });
                }
                if results.len() > max_show && self.options.verbosity == Verbosity::Normal {
                    println!(" ... and {} more", results.len() - max_show);
                }
            }
        }
        // Statistics
        let total = self.results.len();
        let not_exist = by_status.get("Not existent").map_or(0, |v| v.len());
        let exists = total - not_exist;
        println!("\n📈 STATISTICS:");
        println!(" Total tested: {} IOCTLs", total);
        println!(" Not existent: {} IOCTLs", not_exist);
        println!(" Potentially existent: {} IOCTLs", exists);
        let mut type_count = HashMap::new();
        for result in &self.results {
            if !matches!(&result.interpretation, Interpretation::NotExist) {
                *type_count.entry(result.ty).or_insert(0) += 1;
            }
        }
        if let Some((best_type, count)) = type_count.iter().max_by_key(|(_, &c)| c) {
            println!(" Most common type: 0x{:02x} ({} IOCTLs)", best_type, count);
        }
    }

    /// Print minimal summary
    fn print_minimal_summary(&self) {
        let mut by_status = HashMap::new();
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
        println!(" Total: {}", self.results.len());
        for (status, count) in &by_status {
            println!(" {}: {}", status, count);
        }
    }

    /// Find the type with most working IOCTLs
    pub fn find_best_type(&self) -> Option<u8> {
        let mut type_scores = HashMap::new();
        for result in &self.results {
            if !matches!(&result.interpretation, Interpretation::NotExist) {
                *type_scores.entry(result.ty).or_insert(0) += 1;
            }
        }
        type_scores.iter().max_by_key(|(_, &score)| score).map(|(&ty, _)| ty)
    }

    /// Get interesting NR values for a type
    pub fn get_interesting_nrs(&self, ty: u8) -> Vec<u8> {
        let mut nrs = HashMap::new();
        for result in &self.results {
            if result.ty == ty && !matches!(&result.interpretation, Interpretation::NotExist) {
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
        }
        #[derive(Serialize)]
        struct JsonStatistics {
            total: usize,
            not_existent: usize,
            potentially_existent: usize,
        }
        let not_existent = self.results.iter()
            .filter(|r| matches!(&r.interpretation, Interpretation::NotExist))
            .count();
        let output = JsonOutput {
            results: self.results.clone(),
            statistics: JsonStatistics {
                total: self.results.len(),
                not_existent,
                potentially_existent: self.results.len() - not_existent,
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
            vendor: String,
            model: String,
            description: String,
            detection_ioctls: Vec<DetectedIoctlTemplate>,
            info_ioctls: Vec<IoctlTemplate>,
        }
        #[derive(Serialize)]
        struct DetectedIoctlTemplate {
            cmd: String,
            size: u16,
            dir: String,
            interpretation: String,
            discovered_size: Option<u16>,
        }
        #[derive(Serialize)]
        struct IoctlTemplate {
            name: String,
            cmd: String,
            expected_size: u16,
            description: String,
        }
        // Find working IOCTLs
        let working_ioctls: Vec<&IoctlResult> = self.results.iter()
            .filter(|r| matches!(&r.interpretation, Interpretation::Success))
            .collect();
        let detection_ioctls: Vec<DetectedIoctlTemplate> = working_ioctls.iter()
            .take(5)
            .map(|r| DetectedIoctlTemplate {
                cmd: format!("0x{:08x}", r.cmd),
                size: r.size,
                dir: match r.dir {
                    0 => "NONE".to_string(),
                    1 => "WRITE".to_string(),
                    2 => "READ".to_string(),
                    3 => "READ|WRITE".to_string(),
                    _ => "UNKNOWN".to_string(),
                },
                interpretation: "Success".to_string(),
                discovered_size: r.discovered_size,
            })
            .collect();
        let template = ProfileTemplate {
            vendor: "Unknown".to_string(),
            model: "Unknown Model".to_string(),
            description: "Auto-generated profile. Please fill in details.".to_string(),
            detection_ioctls,
            info_ioctls: vec![],
        };
        let file = File::create(output_path)?;
        serde_json::to_writer_pretty(file, &template)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }
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
    /// More permissive than is_success()
    pub fn exists(&self) -> bool {
        match self.errno {
            0 | 14 | 22 => true, // Success or parameter errors
            1 => true, // EPERM: exists, but no rights
            25 => false, // ENOTTY: does not exist
            _ => false, // Other errors: conservative
        }
    }
}