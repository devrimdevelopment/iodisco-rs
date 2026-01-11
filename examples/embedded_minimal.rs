//! Example for embedded systems with minimal features
//! Build with: cargo build --example embedded_minimal --no-default-features --features mali

use iodisco;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal initialization
    println!("iodisco v{}", iodisco::version());
    
    // Try to get GPU info with minimal footprint
    match iodisco::get_gpu_info() {
        Ok(info) => {
            println!("Found GPU: {} {}", info.vendor, info.model);
            if let Some(cores) = info.cores {
                println!("Cores: {}", cores);
            }
        }
        Err(e) => {
            println!("No GPU detected or error: {}", e);
        }
    }
    
    Ok(())
}