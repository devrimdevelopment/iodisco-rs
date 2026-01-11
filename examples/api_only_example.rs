use iodisco;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Dieser Code kompiliert nur mit feature "api-only" oder "mali"/"adreno"
    match iodisco::get_gpu_info() {
        Ok(gpu) => {
            println!("Vendor: {}", gpu.vendor);
            println!("Model: {}", gpu.model);
            if let Some(cores) = gpu.cores {
                println!("Cores: {}", cores);
            }
        }
        Err(e) => {
            println!("Fehler: {}", e);
        }
    }

    Ok(())
}
