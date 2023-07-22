use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

use pelite::image::IMAGE_SUBSYSTEM_NATIVE;
use pelite::pe::*;
use pelite::FileMap;

use sha2::{Digest, Sha256};

/// Struct representing a report for a driver analysis.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    /// Name of the driver file.
    pub name: String,
    /// SHA256 hash of the driver file.
    pub hash: String,
    /// Imports found in the driver that match the provided import set.
    pub found_imports: Vec<Import>,
    /// Imports from the import set that match those found in the driver.
    pub matching_imports: Vec<Import>,
}

/// Struct representing an import entry in the driver.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Import {
    #[serde(with = "SerHex::<StrictPfx>")]
    /// Virtual address of the import.
    pub va: u64,
    /// Hint of the import.
    pub hint: usize,
    /// Name of the import.
    pub name: String,
}

/// Type representing a set of import names.
pub type ImportSet = Vec<String>;

impl Report {
    /// Analyzes a driver and generates a report.
    ///
    /// # Arguments
    ///
    /// * `driver` - The path to the driver file.
    /// * `import_set` - The set of import names to check for.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the generated report or an error.
    pub fn from_driver(driver: &Path, import_set: ImportSet) -> Result<Report, ReportError> {
        // Enable verbose logging for the analysis
        log::info!("Analyzing driver: {}", driver.to_string_lossy());

        // Open the driver file and map it to memory
        let file_map = FileMap::open(driver).map_err(|_| ReportError::FileOpenError)?;
        // Parse the PE file headers
        let pe = PeFile::from_bytes(file_map.as_ref()).map_err(|_| ReportError::PeFileError)?;

        // Ensure that the driver has the correct subsystem (IMAGE_SUBSYSTEM_NATIVE)
        let nt_headers = pe.nt_headers();
        if nt_headers.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE {
            return Err(ReportError::InvalidSubsystem);
        }

        // Extract the import data from the PE file
        let imports = pe.imports().map_err(|_| ReportError::ImportsError)?;

        // Prepare lists to store matching and found import entries
        let mut matching_imports = Vec::new();
        let mut found_imports = Vec::new();

        // Iterate through the import data
        for desc in imports {
            // Check if the DLL name is "ntoskrnl.exe"
            let dll_name = desc.dll_name().map_err(|_| ReportError::DllNameError)?;
            if dll_name.to_str().unwrap() != "ntoskrnl.exe" {
                continue;
            }

            // Iterate through the import entries for this DLL
            for (va, import) in Iterator::zip(
                desc.iat().map_err(|_| ReportError::IatError)?,
                desc.int().map_err(|_| ReportError::IntError)?,
            ) {
                // Extract the import entry for the IAT and INT
                let import = import.map_err(|_| ReportError::ImportError)?;
                match import {
                    // For Import::ByName, extract the import name and hint
                    pelite::pe64::imports::Import::ByName { hint, name } => {
                        // Create a new Import struct for the entry
                        let imp = Import {
                            va: *va,
                            hint,
                            name: name.to_string(),
                        };

                        // Check if the import name is in the provided import set
                        if import_set.contains(&imp.name) {
                            // If it matches, add it to the matching_imports list
                            matching_imports.push(imp.clone());
                        }
                        // Add the import to the found_imports list
                        found_imports.push(imp);
                    }
                    _ => {
                        // Ignore other import types
                    }
                }
            }
        }

        // Calculate the SHA256 hash of the driver file
        let mut hasher = Sha256::new();
        hasher.update(fs::read(driver).map_err(|_| ReportError::FileReadError)?);
        let hash = format!("{:x}", hasher.finalize_reset());

        // Create a new Report with the analysis results
        Ok(Report {
            name: driver.to_string_lossy().to_string(),
            hash,
            found_imports,
            matching_imports,
        })
    }
}

/// Custom error enum for the Report module
#[derive(Debug)]
pub enum ReportError {
    FileOpenError,
    FileReadError,
    PeFileError,
    ImportsError,
    InvalidSubsystem,
    DllNameError,
    IatError,
    IntError,
    ImportError,
}

/// Returns the default import set.
pub fn default_import_set() -> ImportSet {
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
}
