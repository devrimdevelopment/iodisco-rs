use iodisco::discovery::{IoctlDiscovery, DiscoveryConfig};

fn test_version_with_magic() -> Result<(), Box<dyn std::error::Error>> {
    let discovery = IoctlDiscovery::open("/dev/mali0", DiscoveryConfig::default().into())?;

    println!("🧪 Testing VERSION_CHECK with different buffers");

    let test_patterns = [
        ("Zero", vec![0u8; 16]),
        ("Magic 0xDEADBEEF", {
            let mut buf = vec![0u8; 16];
            buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
            buf[4..8].copy_from_slice(&0xCAFEBABEu32.to_le_bytes());
            buf
        }),
        ("Version request struct", {
            // Mali Version Request Struktur aus libGPUInfo
            let mut buf = vec![0u8; 16];
            // Vielleicht: api_version = 1?
            buf[0..4].copy_from_slice(&1u32.to_le_bytes());
            buf
        }),
    ];

    for (name, mut buffer) in test_patterns {
        println!("\n🔍 Pattern: {}", name);

        match discovery.execute_ioctl(0x40108003, buffer.len()) {
            Ok(data) => {
                println!("  ✅ Returned {} bytes", data.len());
                if !data.iter().all(|&b| b == 0) {
                    println!("  ⭐ NON-ZERO DATA!");
                    for i in 0..std::cmp::min(16, data.len()) {
                        print!("{:02x} ", data[i]);
                    }
                    println!();
                }
            }
            Err(e) => {
                println!("  ❌ Error: {}", e);
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    test_version_with_magic()
}