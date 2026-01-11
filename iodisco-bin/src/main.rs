//! Command-line interface for iodisco

use clap::{Parser, Subcommand, ValueEnum};
use iodisco;

#[derive(Parser)]
#[command(name = "iodisco")]
#[command(version = iodisco::VERSION)]
#[command(about = "IOCTL discovery tool for GPU information", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output verbosity
    #[arg(short, long, value_enum, default_value_t = Verbosity::Normal)]
    verbosity: Verbosity,
}

#[derive(Subcommand)]
enum Commands {
    /// Get GPU information (quick profile matching)
    Info {
        /// Specific device path (auto-detect if not specified)
        #[arg(short, long)]
        device: Option<String>,

        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Discover IOCTLs on unknown GPUs
    Discover {
        /// Specific device path
        #[arg(short, long)]
        device: Option<String>,

        /// Export results to JSON file
        #[arg(long)]
        json_output: Option<String>,

        /// Maximum results per category
        #[arg(short, long, default_value_t = 10)]
        max_results: usize,

        /// Skip detailed analysis
        #[arg(long)]
        skip_details: bool,
    },

    /// Generate profile template from discovery results
    GenerateProfile {
        /// Input JSON file from discovery
        #[arg(short, long)]
        from: String,

        /// Output profile file
        #[arg(short, long, default_value = "new_profile.json")]
        output: String,

        /// Device model name
        #[arg(long)]
        device_model: Option<String>,
    },

    /// List available GPU devices
    Devices,

    /// Show version information
    Version,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Verbosity {
    Minimal,
    Normal,
    Detailed,
    Debug,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Info { device, format } => {
            let result = iodisco::get_gpu_info_with_device(device.as_deref());

            match result {
                Ok(info) => match format {
                    OutputFormat::Text => print_gpu_info_text(&info),
                    OutputFormat::Json => print_gpu_info_json(&info)?,
                },
                Err(e) => {
                    eprintln!("Error: {}", e);
                    if let iodisco::GpuInfoError::NoProfile = e {
                        eprintln!("\n💡 Try running: iodisco discover");
                    }
                }
            }
        }

        Commands::Discover { device, json_output, max_results, skip_details } => {
            println!("🔍 Starting IOCTL discovery...");

            // TODO: Pass options to discovery
            let result = iodisco::discovery::scan_device(device.as_deref())?;

            result.print_results();

            if let Some(json_path) = json_output {
                result.export_json(json_path)?;
                println!("\n✅ Results exported to: {}", json_path);
            }

            println!("\n💡 Consider submitting your results to improve iodisco!");
        }

        Commands::GenerateProfile { from, output, device_model } => {
            println!("📝 Generating profile template...");
            // TODO: Implement profile generation from JSON
            println!("Feature coming soon!");
        }

        Commands::Devices => {
            let devices = iodisco::scan_devices();
            if devices.is_empty() {
                println!("❌ No GPU devices found.");
            } else {
                println!("📱 Found {} GPU device(s):", devices.len());
                for device in devices {
                    println!("  • {}", device);
                }
            }
        }

        Commands::Version => {
            println!("iodisco v{}", iodisco::version());
            println!("Library for GPU IOCTL discovery");
        }
    }

    Ok(())
}

fn print_gpu_info_text(info: &iodisco::GpuInfo) {
    println!("📊 GPU Information:");
    println!("===================");
    println!("Vendor: {}", info.vendor);
    println!("Model: {}", info.model);

    if let Some(arch) = &info.architecture {
        println!("Architecture: {}", arch);
    }

    if let Some(version) = &info.driver_version {
        println!("Driver Version: {}", version);
    }

    if let Some(cores) = info.cores {
        println!("Cores: {}", cores);
    }

    if let Some(gpu_id) = info.gpu_id {
        println!("GPU ID: 0x{:08x}", gpu_id);
    }

    println!("Detected IOCTLs: {}", info.detected_ioctls.len());

    if !info.features.is_empty() {
        println!("Features: {}", info.features.join(", "));
    }
}

fn print_gpu_info_json(info: &iodisco::GpuInfo) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(info)?;
    println!("{}", json);
    Ok(())
}