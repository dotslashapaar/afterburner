use std::process::Command;
use std::path::PathBuf;

fn main() ->Result<(), anyhow::Error> {
    let target = "bpfel-unknown-none";

    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);

    let root = dir.parent().expect("Could not find workspace root");

    let status = Command::new("cargo")
        .current_dir(root)
        .args(&[
            "build",
            "--package", "afterburner-ebpf",
            "--target", target,
            "--release",
            "-Z", "build-std=core"
        ])
        .status()?;

    if !status.success(){
        anyhow::bail!("Failed to build eBPF program");
    }

    println!("eBPF Program Compiled Successfully");
    Ok(())
}
