use std::path::PathBuf;
use structopt::StructOpt;
use std::fs;

// Include the Report struct and related types and functions from the "report.rs" module
mod report;
use report::{Report, ImportSet};

/// CLI options definition using structopt
#[derive(Debug, StructOpt)]
struct Opt {
    /// The path to the driver file or directory to analyze
    #[structopt(parse(from_os_str))]
    path: PathBuf,

    /// List of imports to check for
    #[structopt(short, long)]
    imports: Vec<String>,
}

fn main() {
    // Parse CLI options
    let opt = Opt::from_args();

    // Load the ImportSet from CLI options or use the default set if none provided
    let import_set: ImportSet = if !opt.imports.is_empty() {
        opt.imports
    } else {
        vec![
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
        ]
    };

    // Call the analyze function with the provided path and import set
    analyze(&opt.path, import_set);
}

fn analyze(path: &std::path::Path, import_set: ImportSet) {
    if path.is_file() {
        // Handle single driver file
        match Report::from_driver(path, import_set) {
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
    } else if path.is_dir() {
        // Handle directory containing multiple drivers
        let entries = fs::read_dir(path).expect("Failed to read directory");
        for entry in entries {
            if let Ok(entry) = entry {
                let driver_path = entry.path();
                if driver_path.is_file() {
                    println!("Analyzing: {}", driver_path.to_string_lossy());
                    match Report::from_driver(&driver_path, import_set.clone()) {
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
            }
        }
    } else {
        eprintln!("Error: The provided path does not exist or is not a file/directory");
    }
}
