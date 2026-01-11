use iodisco::profiles::{load_mali_profiles, IoctlProfile};
use iodisco::discovery::{IoctlDiscovery, DiscoveryConfig};
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Debugging Profile Matching");
    println!("=============================\n");

    // Device öffnen
    let discovery = IoctlDiscovery::open("/dev/mali0", DiscoveryConfig::quick().into())?;

    // Alle Mali Profile laden
    let profiles = load_mali_profiles();

    println!("Loaded {} Mali profiles:", profiles.len());
    for (i, profile) in profiles.iter().enumerate() {
        println!("{}. {} - {}", i + 1, profile.vendor, profile.model);
    }

    println!("\n🔬 Testing each profile:");

    for (i, profile) in profiles.iter().enumerate() {
        println!("\n--- Profile {}: {} ---", i + 1, profile.model);

        let mut all_match = true;

        for ioctl_def in &profile.detection_ioctls {
            let result = discovery.test_single_ioctl(ioctl_def.cmd);

            println!("  {} (0x{:08x}):", ioctl_def.name, ioctl_def.cmd);
            println!("    Result: ret={}, errno={}", result.result, result.errno);
            println!("    Success: {}", result.is_success());

            if !result.is_success() {
                all_match = false;
                println!("    ❌ Failed to match!");
            } else {
                println!("    ✅ Matched!");

                // Extra: Test mit Buffer
                match discovery.execute_ioctl(ioctl_def.cmd, ioctl_def.buffer_size as usize) {
                    Ok(data) => {
                        println!("    Buffer data ({} bytes):", data.len());
                        if data.len() >= 4 {
                            let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
                            println!("    First 4 bytes: 0x{:08x} ({})", val, val);
                        }
                    }
                    Err(e) => {
                        println!("    Buffer test failed: {}", e);
                    }
                }
            }
        }

        println!("  Overall match: {}", if all_match { "✅ YES" } else { "❌ NO" });
    }

    // Extra: Teste spezifische IOCTLs die wir kennen
    println!("\n📊 Known IOCTLs from strace:");
    let known_ioctls = [
        (0xC0048000, "GET_PROPS_00 (core mask?)"),
        (0x40048001, "SET_FLAGS?"),
        (0x40108003, "VERSION_CHECK"),
        (0x8004800c, "GET_GPU_INFO? (returns 0x21)"),
    ];

    for (cmd, description) in &known_ioctls {
        let result = discovery.test_single_ioctl(*cmd);
        println!("  {} (0x{:08x}):", description, cmd);
        println!("    ret={}, errno={}, success={}",
            result.result, result.errno, result.is_success());
    }

    Ok(())
}