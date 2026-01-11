#[cfg(test)]
mod integration_tests {
    use iodisco;
    
    #[test]
    fn test_library_initialization() {
        iodisco::init();
        assert!(!iodisco::version().is_empty());
    }
    
    #[test]
    fn test_api_compilation() {
        // Test that API compiles and runs without panicking
        let _ = iodisco::get_gpu_info();
        let _ = iodisco::is_supported();
        let _ = iodisco::scan_devices();
    }
}