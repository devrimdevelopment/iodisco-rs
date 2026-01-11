# Security Considerations

iodisco performs read-only operations on kernel drivers:
- No writes to GPU control registers
- Only queries hardware identification data
- Requires video/render group membership, not root
- Uses safe Rust abstractions over raw ioctls

Use in production systems with caution and test on your specific hardware.