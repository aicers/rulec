//! Converts a local ET Open archive and prints its summary as JSON.
//!
//! Usage: cargo run --example et_open_summary -- bundle.tar.gz [version-number]

use std::{error::Error, io};

use rulec::{Blocklist, convert_et_open};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: et_open_summary bundle.tar.gz [version-number]")?;
    let number = args.next().map(|value| value.parse::<u64>()).transpose()?;
    if args.next().is_some() {
        return Err("usage: et_open_summary bundle.tar.gz [version-number]".into());
    }
    let bundle = std::fs::read(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("reading ET Open bundle {path}: {error}"),
        )
    })?;
    let converted = convert_et_open(&bundle, number, &Blocklist::builtin()?)?;
    println!("{}", serde_json::to_string_pretty(&converted.summary)?);
    Ok(())
}
