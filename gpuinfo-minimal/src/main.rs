//! Minimal GPU info CLI tool

use std::process;

fn main() {
    match iodisco::get_gpu_info() {
        Ok(gpu) => println!("{} {}", gpu.vendor, gpu.model),
        Err(_) => std::process::exit(1),
    }
}
