use iodisco;

fn main() {
    match iodisco::get_gpu_info_static() {
        Ok(gpu) => println!("GPU: {} {}", gpu.vendor, gpu.model),
        Err(e) => eprintln!("Error: {}", e),
    }
}
