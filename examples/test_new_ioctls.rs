use iodisco::discovery::{IoctlDiscovery, DiscoveryConfig};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing new IOCTLs from discovery");
    println!("====================================\n");

    let discovery = IoctlDiscovery::open("/dev/mali0", DiscoveryConfig::default().into())?;

    // IOCTLs aus deiner Discovery
    let ioctls_to_test = [
        (0xc0048000, "UNKNOWN_00", "type=0x80, nr=0x00, size=4, dir=READ|WRITE"),
        (0x40048001, "SET_FLAGS?", "type=0x80, nr=0x01, size=4, dir=WRITE"),
        (0x40108003, "VERSION_CHECK", "type=0x80, nr=0x03, size=16, dir=WRITE"),
        (0x8004800c, "UNKNOWN_0C", "type=0x80, nr=0x0c, size=4, dir=READ"),
        (0x4010800d, "UNKNOWN_0D", "type=0x80, nr=0x0d, size=16, dir=WRITE"),
    ];

    for (cmd, name, info) in &ioctls_to_test {
        println!("🔍 {} (0x{:08x})", name, cmd);
        println!("   Info: {}", info);

        // Größen testen
        let sizes = match *cmd {
            0x40108003 | 0x4010800d => vec![8, 16, 32, 64],  // Vermutlich größere Buffer
            0xc0048000 | 0x40048001 | 0x8004800c => vec![4, 8, 16],  // Kleinere Buffer
            _ => vec![4, 8, 16, 32],
        };

        for &size in &sizes {
            print!("   Size {}: ", size);
            io::stdout().flush()?;

            match discovery.execute_ioctl(*cmd, size) {
                Ok(data) => {
                    println!("✅ {} bytes returned", data.len());

                    // Hex-Dump der ersten Bytes
                    let display_len = std::cmp::min(16, data.len());
                    print!("      Data: ");
                    for i in 0..display_len {
                        print!("{:02x} ", data[i]);
                    }
                    if data.len() > display_len {
                        print!("...");
                    }
                    println!();

                    // Als u32 interpretieren wenn möglich
                    if data.len() >= 4 {
                        let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
                        println!("      As u32: 0x{:08x} ({})", val, val);

                        // Spezielle Analyse für bekannte IOCTLs
                        if *cmd == 0x40108003 {
                            // Version IOCTL - libgpuinfo bekam 749 zurück
                            println!("      Version hint: major={}, minor={}",
                                (val >> 16) & 0xFFFF, val & 0xFFFF);
                        }
                    }
                }
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(-1);
                    println!("❌ Error {}: {}", errno, e);
                }
            }
        }
        println!();
    }

    // Teste auch den Return-Wert (nicht nur Buffer)
    println!("📊 Testing return values (no buffer):");
    for (cmd, name, _) in &ioctls_to_test {
        let result = discovery.test_single_ioctl(*cmd);
        println!("   {}: ret={}, errno={}", name, result.result, result.errno);
    }

    Ok(())
}