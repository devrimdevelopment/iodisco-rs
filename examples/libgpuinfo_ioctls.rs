use iodisco::discovery::{IoctlDiscovery, DiscoveryConfig};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let discovery = IoctlDiscovery::open("/dev/mali0", DiscoveryConfig::default().into())?;

    println!("🔬 Testing exact libgpuinfo IOCTLs:");
    println!("==================================\n");

    // Die drei IOCTLs aus strace
    let ioctls = [
        (0xC0048034, "GET_PROPS (nr=0x34)", 4),
        (0x40048001, "SET_FLAGS? (nr=0x01)", 4),
        (0x40108003, "VERSION_CHECK (nr=0x03)", 16),
    ];

    for (cmd, name, size) in &ioctls {
        println!("🔍 {} (0x{:08x}):", name, cmd);

        // Test mit null Buffer (wie in strace)
        let (ret_null, errno_null) = discovery.test_ioctl(*cmd, 0);
        print!("  Null buffer: ret={}, errno={} - ", ret_null, errno_null);
        match errno_null {
            0 => println!("✅ Success"),
            1 => println!("❌ EPERM"),
            _ => println!("⚠️  Other"),
        }

        // Test mit echtem Buffer
        let mut buffer = vec![0u8; *size];
        let ptr = buffer.as_mut_ptr() as usize;
        let (ret, errno) = discovery.test_ioctl(*cmd, ptr);

        print!("  With buffer ({} bytes): ret={}, errno={} - ", size, ret, errno);
        match errno {
            0 => {
                println!("✅ Success");
                println!("    Buffer (hex): {:?}", buffer);
                println!("    Return value analysis: {}", ret);

                // Spezielle Analyse für 0x40108003
                if *cmd == 0x40108003 {
                    println!("    ⚠️  libgpuinfo got 749, we got {}", ret);
                    // 749 = 0x2ED = 0x02ED = 749 decimal
                    // Vielleicht: major=0x02, minor=0xED? (2.237)
                    // Oder: version = 749?
                }
            }
            _ => println!("❌ Failed"),
        }
        println!();
    }

    // Teste auch GET_GPUINFO (nr=0x0B) - wird vielleicht intern verwendet
    println!("🔍 GET_GPUINFO (nr=0x0B) variants:");
    let sizes = [4, 8, 16, 32, 64];
    for &size in &sizes {
        let cmd = ((3u32 << 30) | ((size as u32) << 16) | (0x80 << 8) | 0x0B) as u32;
        let mut buffer = vec![0u8; size];
        let ptr = buffer.as_mut_ptr() as usize;
        let (ret, errno) = discovery.test_ioctl(cmd, ptr);

        if errno == 0 {
            println!("  Size {}: ✅ ret={}, buffer: {:?}", size, ret, &buffer[..std::cmp::min(8, buffer.len())]);
        }
    }

    Ok(())
}