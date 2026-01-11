//! Advanced analysis tools for IOCTL discovery

use std::collections::HashMap;
use std::io;
use libc;
use std::os::unix::io::RawFd;
use crate::discovery::{Verbosity, IoctlResult};

/// Detailed analyzer for specific IOCTL types
pub struct DetailedAnalyzer {
    fd: RawFd,
    type_to_test: u8,
    interesting_nrs: Vec<u8>,
    verbosity: Verbosity,
}

impl DetailedAnalyzer {
    /// Create new analyzer
    pub fn new(fd: RawFd, type_to_test: u8, interesting_nrs: Vec<u8>, verbosity: Verbosity) -> Self {
        Self { fd, type_to_test, interesting_nrs, verbosity }
    }

    /// Bruteforce size analysis
    pub fn analyze_size_bruteforce(&self) -> HashMap<u8, Vec<u16>> {
        if self.verbosity == Verbosity::Minimal {
            return HashMap::new();
        }

        if self.verbosity.is_at_least(Verbosity::Normal) {
            println!("\n🎯 SIZE BRUTEFORCE FOR TYPE 0x{:02x}", self.type_to_test);
        }

        let mut size_map = HashMap::new();
        let sizes = [1u16, 2, 4, 8, 12, 16, 20, 24, 28, 32, 48, 64, 128];

        for &nr in &self.interesting_nrs {
            let show_details = self.verbosity.is_at_least(Verbosity::Detailed);

            if show_details {
                println!("\nnr=0x{:02x}:", nr);
            }

            let mut working_sizes = Vec::new();

            for &size in &sizes {
                let mut buffer = vec![0u8; size as usize];
                if size >= 4 {
                    let magic = 0xDEADBEEFu32.to_ne_bytes();
                    buffer[0..4].copy_from_slice(&magic);
                }

                let cmd = ((3u32 << 30) | ((size as u32) << 16) |
                          ((self.type_to_test as u32) << 8) | (nr as u32)) as i32;

                let result = unsafe { libc::ioctl(self.fd, cmd, buffer.as_mut_ptr()) };
                let errno = if result < 0 {
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                } else {
                    0
                };

                if show_details {
                    match errno {
                        0 => println!("  Size={:3}: ✅ result={}", size, result),
                        22 => println!("  Size={:3}: ⚠️  EINVAL", size),
                        14 => println!("  Size={:3}: ⚠️  EFAULT", size),
                        1 | 13 => println!("  Size={:3}: 🔒 Permission", size),
                        _ => {}
                    }
                }

                if errno == 0 {
                    working_sizes.push(size);
                }
            }

            if !working_sizes.is_empty() {
                size_map.insert(nr, working_sizes);
            }
        }

        size_map
    }
}

/// Pattern analyzer for IOCTL results
pub struct PatternAnalyzer {
    patterns: HashMap<String, Vec<u8>>,
}

impl PatternAnalyzer {
    /// Create new pattern analyzer
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
        }
    }

    /// Analyze results for patterns
    pub fn analyze_results(&mut self, results: &[IoctlResult]) {
        // Group by error patterns
        let mut error_patterns = HashMap::new();

        for result in results {
            let pattern = match result.interpretation {
                crate::discovery::Interpretation::NotExist => "NOT_EXIST",
                crate::discovery::Interpretation::Exists => "EXISTS",
                crate::discovery::Interpretation::Permission => "PERMISSION",
                crate::discovery::Interpretation::Success => "SUCCESS",
                crate::discovery::Interpretation::Unknown(e) => &format!("UNKNOWN_{}", e),
            };

            error_patterns
                .entry(pattern.to_string())
                .or_insert_with(Vec::new)
                .push(result.nr);
        }

        // Detect consecutive ranges
        for (pattern, mut nrs) in error_patterns {
            nrs.sort_unstable();
            nrs.dedup();

            if nrs.len() > 3 {
                let ranges = self.find_consecutive_ranges(&nrs);
                if !ranges.is_empty() {
                    self.patterns.insert(pattern, ranges);
                }
            }
        }
    }

    /// Find consecutive number ranges
    fn find_consecutive_ranges(&self, nrs: &[u8]) -> Vec<u8> {
        if nrs.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut start = nrs[0];
        let mut prev = nrs[0];

        for &nr in &nrs[1..] {
            if nr != prev + 1 {
                if start != prev {
                    ranges.push(start);
                    ranges.push(prev);
                }
                start = nr;
            }
            prev = nr;
        }

        if start != prev {
            ranges.push(start);
            ranges.push(prev);
        }

        ranges
    }

    /// Print detected patterns
    pub fn print_patterns(&self) {
        println!("\n🔍 PATTERN ANALYSIS:");
        println!("===================");

        if self.patterns.is_empty() {
            println!("No significant patterns detected.");
            return;
        }

        for (pattern, ranges) in &self.patterns {
            println!("{} pattern:", pattern);
            for chunk in ranges.chunks(2) {
                if chunk.len() == 2 {
                    println!("  Range: 0x{:02x}-0x{:02x}", chunk[0], chunk[1]);
                }
            }
        }
    }
}