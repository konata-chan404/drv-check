use std::path::Path;

// Include the Report struct and related types and functions from the "report.rs" module
mod report;
use report::{Report, ImportSet};

fn main() {
    // Specify the path to the driver file you want to analyze
    let driver_path = Path::new("C:\\Users\\Yael\\drv-check\\7475bfea6ea1cd54029208ed59b96c6b.sys");

    let import_set: ImportSet = vec![
        "MmMapIoSpace".to_string(),
        "MmMapIoSpaceEx".to_string(),
        "MmMapLockedPages".to_string(),
        "MmMapLockedPagesSpecifyCache".to_string(),
        "MmMapLockedPagesWithReservedMapping".to_string(),
        "ZwMapViewOfSection".to_string(),
        // "IoCreateDevice".to_string(), // Uncomment if required
        // "MmCopyVirtualMemory".to_string(), // Uncomment if required
        "MmCopyMemory".to_string(),
        "EnumerateDebuggingDevices".to_string(),
    ];

    // Call the Report::from_driver function to analyze the driver
    match Report::from_driver(driver_path, import_set) {
        Ok(report) => {
            // Display the report
            println!("Driver Name: {}", report.name);
            println!("Driver Hash: {}", report.hash);
            println!("Found Imports: {:?}", report.found_imports);
            println!("Matching Imports: {:?}", report.matching_imports);

        }
        Err(error_code) => {
            eprintln!("Error: An error occurred with code {}", error_code);
            // Handle the error appropriately
        }
    }
}
