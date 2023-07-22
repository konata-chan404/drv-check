use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

use pelite::image::IMAGE_SUBSYSTEM_NATIVE;
use pelite::pe::*;
use pelite::FileMap;

use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    pub name: String,
    pub hash: String,
    pub found_imports: Vec<Import>,
    pub matching_imports: Vec<Import>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Import {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub va: u64,
    pub hint: usize,
    pub name: String,
}

pub type ImportSet = Vec<String>;

impl Report {
    pub fn from_driver(driver: &Path, import_set: ImportSet) -> Result<Report, i32> {
        let file_map = FileMap::open(driver).map_err(|_| -1)?;
        let pe = PeFile::from_bytes(file_map.as_ref()).map_err(|_| -1)?;

        let nt_headers = pe.nt_headers();
        if nt_headers.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE {
            return Err(-1);
        }

        let imports = pe.imports().map_err(|_| -1)?;

        let mut matching_imports = Vec::new();
        let mut found_imports = Vec::new();

        for desc in imports {
            let dll_name = desc.dll_name().unwrap();
            if dll_name.to_str().unwrap() != "ntoskrnl.exe" {
                continue;
            }

            for (va, import) in Iterator::zip(desc.iat().ok().unwrap(), desc.int().ok().unwrap()) {
                if let Some(import) = import.ok() {
                    match import {
                        pelite::pe64::imports::Import::ByName { hint, name } => {
                            let imp = Import {
                                va: *va,
                                hint,
                                name: name.to_string(),
                            };

                            if import_set.contains(&imp.name) {
                                matching_imports.push(imp);
                            } else {
                                found_imports.push(imp);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(fs::read(driver).unwrap());
        let hash = format!("{:x}", hasher.finalize_reset());

        Ok(Report {
            name: driver.to_string_lossy().to_string(),
            hash,
            found_imports,
            matching_imports,
        })
    }
}
