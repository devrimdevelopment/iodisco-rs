iodisco performs primarily read-only operations on GPU drivers in minimal-safe mode:
- Does not write GPU registers or modify persistent hardware state.
- Queries only identification and capability information.
- Requires membership in video/render group; root is not needed.
- Uses Rust abstractions to reduce memory safety risks.

⚠️ WARNING: Experimental/professional modes may execute IOCTLs that could alter hardware state or trigger driver behavior. Use in production systems with caution and test on your specific hardware.
