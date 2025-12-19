use std::path::PathBuf;
use std::process::Command;

fn main(){
    let target = "bpfel-unknown-none";

    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("env::var"));

    let root = dir.parent().expect("Could not find workspace root");

    let status = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "--package",
            "afterburner-ebpf",
            "--target",
            target,
            "--release",
            "-Z",
            "build-std=core",
        ])
        .status()
        .expect("status");

    if !status.success() {
        panic!("Failed to build eBPF program");
    }

    println!("eBPF Program Compiled Successfully");
}
