//! Advanced example showing full discovery workflow

use iodisco::discovery;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 iodisco Advanced Discovery Example");
    println!("=====================================\n");

    // Scan for devices
    println!("Scanning for GPU devices...");
    let devices = iodisco::scan_devices();

    if devices.is_empty() {
        println!("❌ No GPU devices found!");
        return Ok(());
    }

    println!("Found {} device(s):", devices.len());
    for device in &devices {
        println!("  • {}", device);
    }

    // Run discovery on first device
    println!("\nRunning discovery on {}...", devices[0]);
    
    // FIX: Add the config parameter (use None for defaults)
    let result = discovery::scan_device(Some(&devices[0]), None)?;

    // Print results
    result.print_results();

    // Export to JSON
    result.export_json("discovery_results.json")?;
    println!("\n✅ Results exported to discovery_results.json");

    // Generate profile template
    result.generate_profile_template("new_profile_template.json")?;
    println!("✅ Profile template generated: new_profile_template.json");

    println!("\n💡 Submit the generated template to improve iodisco!");

    Ok(())
}