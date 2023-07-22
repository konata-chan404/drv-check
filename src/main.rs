use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

// Add the logger
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

// Include the Report struct and related types and functions from the "report.rs" module
mod report;
use report::{default_import_set, ImportSet, Report};

/// CLI options definition using structopt
#[derive(Debug, StructOpt)]
struct Opt {
    /// The path to the driver file or directory to analyze
    #[structopt(parse(from_os_str))]
    path: PathBuf,

    /// Path to a JSON file containing the import set (optional)
    #[structopt(short, long, parse(from_os_str))]
    imports: Option<PathBuf>,
}

fn main() {
    // Initialize the logger
    pretty_env_logger::init();

    // Parse CLI options
    let opt = Opt::from_args();

    // Read the import set from the JSON file if provided, otherwise use the default set
    let import_set = match opt.imports {
        Some(imports_file) => {
            let import_set_json =
                fs::read_to_string(&imports_file).expect("Failed to read import set file");
            serde_json::from_str(&import_set_json).expect("Failed to parse import set JSON")
        }
        None => default_import_set(),
    };

    // Call the analyze function with the provided path and import set
    analyze(&opt.path, import_set);
}

/// Analyzes the driver file or directory and generates reports for each driver.
///
/// # Arguments
///
/// * `path` - The path to the driver file or directory to analyze.
/// * `import_set` - The set of import names to check for.
fn analyze(path: &std::path::Path, import_set: ImportSet) {
    // Enable verbose logging
    info!("Starting analysis...");

    let mut reports = Vec::new();

    if path.is_file() {
        // Handle single driver file
        match Report::from_driver(path, import_set) {
            Ok(report) => {
                reports.push(report);
            }
            Err(error_code) => {
                // Log the error with file path
                error!(
                    "Error {:#?} while analyzing file {}",
                    error_code,
                    path.to_string_lossy()
                );
                // Handle the error appropriately
                return;
            }
        }
    } else if path.is_dir() {
        // Handle directory containing multiple drivers
        let entries = fs::read_dir(path).expect("Failed to read directory");
        for entry in entries {
            if let Ok(entry) = entry {
                let driver_path = entry.path();
                if driver_path.is_file() {
                    // Enable verbose logging for each analysis
                    match Report::from_driver(&driver_path, import_set.clone()) {
                        Ok(report) => {
                            reports.push(report);
                        }
                        Err(error_code) => {
                            // Log the error with file path
                            error!(
                                "Error {:#?} while analyzing file {}",
                                error_code,
                                driver_path.to_string_lossy()
                            );
                            // Handle the error appropriately
                        }
                    }
                }
            }
        }
    } else {
        // Log the error
        error!("Error: The provided path does not exist or is not a file/directory");
        return;
    }

    // Print the reports as a JSON list
    println!("{}", serde_json::to_string_pretty(&reports).unwrap());
}
