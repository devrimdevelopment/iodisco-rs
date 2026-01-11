use iodisco::discovery::{IoctlDiscovery, DiscoveryConfig};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 Mali IOCTL Raw Data Analyzer");
    println!("===============================\n");

    let discovery = IoctlDiscovery::open("/dev/mali0", DiscoveryConfig::default().into())?;

    // Deine vier interessanten IOCTLs aus der Discovery
    let test_ioctls = [
        (0x40108003, "GET_VERSION", vec![8, 16, 32, 64]),
        (0xc0048034, "GET_FEATURES", vec![4, 8, 16]),
        (0xc0108038, "GET_GPU_INFO", vec![16, 32, 64, 128]),
        (0xc0108039, "GET_MEMORY_INFO", vec![16, 32, 64]),
    ];

    for (cmd, name, sizes) in &test_ioctls {
        println!("\n🔍 Testing {} (0x{:08x}):", name, cmd);
        println!("{}", "─".repeat(50));

        let mut best_result = None;

        for &size in sizes {
            print!("  Size={:3}: ", size);
            io::stdout().flush()?;

            match discovery.execute_ioctl(*cmd, size) {
                Ok(data) => {
                    println!("✅ Success ({} bytes)", data.len());

                    // Hex-Dump der ersten Bytes
                    print!("      Hex: ");
                    for i in 0..std::cmp::min(8, data.len()) {
                        print!("{:02x} ", data[i]);
                    }
                    if data.len() > 8 {
                        print!("...");
                    }
                    println!();

                    // Als u32 Werte interpretieren
                    if data.len() >= 4 {
                        let mut u32_values = Vec::new();
                        for chunk in data.chunks(4) {
                            if chunk.len() == 4 {
                                let val = u32::from_le_bytes(chunk.try_into().unwrap());
                                u32_values.push(val);
                            }
                        }
                        print!("      As u32 (LE): ");
                        for (i, val) in u32_values.iter().enumerate().take(4) {
                            print!("[{}]=0x{:08x}({}) ", i, val, val);
                        }
                        println!();
                    }

                    best_result = Some((size, data));
                }
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(-1);
                    println!("❌ Error {}: {}", errno, e);
                }
            }
        }

        // Bestes Ergebnis speichern
        if let Some((best_size, data)) = best_result {
            println!("  📊 Best result with size {}:", best_size);
            hex_dump(&data, 64); // Erste 64 Bytes dumpen
        }
    }

    println!("\n🎯 Additional analysis:");
    println!("{}", "─".repeat(50));

    // Test mit verschiedenen Pattern im Buffer
    println!("\n🧪 Testing with pattern in buffer:");
    test_with_patterns(&discovery)?;

    Ok(())
}

fn hex_dump(data: &[u8], max_bytes: usize) {
    let limit = std::cmp::min(data.len(), max_bytes);

    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        let addr = i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();

        // Padding für unvollständige Zeilen
        let mut hex_line = hex.join(" ");
        if chunk.len() < 16 {
            hex_line.push_str(&"   ".repeat(16 - chunk.len()));
        }

        let ascii: String = chunk.iter()
            .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
            .collect();

        println!("    {:04x}: {}  {}", addr, hex_line, ascii);
    }

    if data.len() > limit {
        println!("    ... and {} more bytes", data.len() - limit);
    }
}

fn test_with_patterns(discovery: &IoctlDiscovery) -> Result<(), Box<dyn std::error::Error>> {
    // Test GET_VERSION mit verschiedenen Buffer-Inhalten
    let test_cmds = [
        (0x40108003, "GET_VERSION", 16),
        (0xc0108038, "GET_GPU_INFO", 64),
    ];

    for (cmd, name, size) in &test_cmds {
        println!("\n  Testing {} with patterns:", name);

        let patterns = [
            ("Zeroed", vec![0u8; *size]),
            ("0xFF", vec![0xFFu8; *size]),
            ("Incrementing", (0..*size as u8).collect()),
            ("Magic 0xDEADBEEF", {
                let mut buf = vec![0u8; *size];
                if buf.len() >= 8 {
                    buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
                    buf[4..8].copy_from_slice(&0xCAFEBABEu32.to_le_bytes());
                }
                buf
            }),
        ];

        for (pattern_name, mut buffer) in patterns {
            print!("    Pattern '{}': ", pattern_name);
            io::stdout().flush()?;

            let result = discovery.test_single_ioctl(*cmd);

            if result.errno == 0 || result.errno == 14 || result.errno == 22 {
                print!("✅ Works (errno={})", result.errno);

                // Jetzt mit Buffer versuchen
                match discovery.execute_ioctl(*cmd, buffer.len()) {
                    Ok(response) => {
                        println!(" → Returns {} bytes", response.len());

                        // Zeige Veränderungen im Buffer
                        if buffer.len() >= 4 && response.len() >= 4 {
                            let before = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
                            let after = u32::from_le_bytes(response[0..4].try_into().unwrap());
                            if before != after {
                                println!("      Buffer changed: 0x{:08x} → 0x{:08x}", before, after);
                            }
                        }
                    }
                    Err(e) => {
                        println!(" → Exec failed: {}", e);
                    }
                }
            } else {
                println!("❌ Error {}", result.errno);
            }
        }
    }

    Ok(())
}