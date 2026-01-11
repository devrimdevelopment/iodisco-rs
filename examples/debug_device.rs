use iodisco;
use std::process;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Device Debug Tool");
    println!("===================\n");

    // 1. Device finden
    println!("1. Scanning for devices...");
    let devices = iodisco::scan_devices();

    if devices.is_empty() {
        println!("   ❌ No GPU devices found!");
        return Ok(());
    }

    println!("   ✅ Found {} device(s):", devices.len());
    for device in &devices {
        println!("      • {}", device);
    }

    // 2. Quick Discovery auf erstem Device
    println!("\n2. Running quick discovery on '{}'...", devices[0]);

    match iodisco::discovery::scan_device(Some(&devices[0])) {
        Ok(result) => {
            println!("   ✅ Discovery successful!");

            // Kurze Zusammenfassung
            let results = result.results();
            let successful: Vec<_> = results.iter()
                .filter(|r| matches!(r.interpretation, iodisco::discovery::Interpretation::Success))
                .collect();

            println!("   📊 Found {} successful IOCTLs:", successful.len());

            // Zeige Top 5 erfolgreiche IOCTLs
            for result in successful.iter().take(5) {
                println!("      • 0x{:08x}: type=0x{:02x}, nr=0x{:02x}, size={}",
                    result.cmd, result.ty, result.nr, result.size);
            }

            if successful.len() > 5 {
                println!("      ... and {} more", successful.len() - 5);
            }

            // 3. Profile-Template generieren
            println!("\n3. Generating profile template...");
            match result.generate_profile_template("new_device_profile.json") {
                Ok(_) => println!("   ✅ Template saved to 'new_device_profile.json'"),
                Err(e) => println!("   ❌ Failed to generate template: {}", e),
            }
        }
        Err(e) => {
            println!("   ❌ Discovery failed: {}", e);
        }
    }

    // 4. IOCTL Explorer starten (optional)
    println!("\n4. Next steps:");
    println!("   • Check 'new_device_profile.json' for working IOCTLs");
    println!("   • Run: cargo run --example test_ioctls");
    println!("   • Submit profile to improve iodisco!");

    Ok(())
}