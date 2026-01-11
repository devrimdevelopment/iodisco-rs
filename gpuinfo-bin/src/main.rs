//! Minimal GPU info CLI tool

use std::process;

fn main() {
    match iodisco::get_gpu_info() {
        Ok(gpu) => {
            // One-line output
            print!("{} {}", gpu.vendor, gpu.model);

            if let Some(cores) = gpu.cores {
                print!(" ({} cores)", cores);
            }

            if let Some(arch) = gpu.architecture {
                print!(" [{}]", arch);
            }

            println!();
            process::exit(0);
        }
        Err(iodisco::GpuInfoError::NoDevice) => {
            eprintln!("no_gpu");
            process::exit(1);
        }
        Err(iodisco::GpuInfoError::NoProfile) => {
            eprintln!("unknown_gpu");
            process::exit(2);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(3);
        }
    }
}
