//! Offline conversion and differential checks for the daily workflow.
#[path = "daily/compare.rs"]
mod compare;
#[path = "daily/records.rs"]
mod records;
#[path = "daily/sources.rs"]
mod sources;

use std::{error::Error, fs, path::Path};

use serde::{Serialize, de::DeserializeOwned};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("decoding {}: {e}", path.display()).into())
}

fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)
        .map_err(|e| format!("writing {}: {e}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|e| format!("replacing {}: {e}", path.display()).into())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, input, output] if command == "convert" => {
            sources::run(Path::new(input), Path::new(output))
        }
        [command, input, output] if command == "compare" => {
            if let Err(error) = compare::run(Path::new(input), Path::new(output)) {
                write(
                    &Path::new(output).join("differential.json"),
                    &serde_json::json!({
                        "status":"failed", "reason":error.to_string(), "errors":[error.to_string()], "rules":[], "counts":{}, "coverage":{}
                    }),
                )?;
            }
            Ok(())
        }
        _ => Err("usage: daily <convert|compare> INPUT_DIRECTORY OUTPUT_DIRECTORY".into()),
    }
}
