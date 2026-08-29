use std::env;
use std::process::{Command, ExitCode};

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let args: Vec<_> = env::args_os().skip(1).collect();

    if args.is_empty() {
        let output = Command::new(&protoc).arg("--version").output()?;
        if !output.status.success() {
            return Ok(ExitCode::from(output.status.code().unwrap_or(1) as u8));
        }
        let version = String::from_utf8(output.stdout)?.trim().to_owned();
        println!(
            "{{\"path\":{:?},\"version\":{:?}}}",
            protoc.to_string_lossy(),
            version
        );
        return Ok(ExitCode::SUCCESS);
    }

    let status = Command::new(protoc).args(args).status()?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}
