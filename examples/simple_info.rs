//! Simple example showing basic GPU information retrieval

use iodisco;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📱 iodisco GPU Information Example");
    println!("==================================\n");

    match iodisco::get_gpu_info() {
        Ok(info) => {
            println!("✅ GPU Found!");
            println!("  Vendor: {}", info.vendor);
            println!("  Model: {}", info.model);

            if let Some(arch) = info.architecture {
                println!("  Architecture: {}", arch);
            }

            if let Some(version) = info.driver_version {
                println!("  Driver Version: {}", version);
            }

            if let Some(cores) = info.cores {
                println!("  Cores: {}", cores);
            }

            println!("  Detected IOCTLs: {}", info.detected_ioctls.len());
        }
        Err(iodisco::GpuInfoError::NoProfile) => {
            println!("❌ GPU not recognized by any profile.");
            println!("   Run discovery mode to identify it:");
            println!("   cargo run --bin iodisco-bin -- discover");
        }
        Err(e) => {
            println!("❌ Error: {}", e);
        }
    }

    Ok(())
}