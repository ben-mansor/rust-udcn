use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    // Location of the eBPF crate
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_dir = manifest_dir.join("../rust-udcn-ebpf");

    // Determine build profile (debug/release)
    let profile = env::var("PROFILE").unwrap();

    // Build the eBPF crate for the bpfel-unknown-none target
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--target").arg("bpfel-unknown-none");
    if profile == "release" {
        cmd.arg("--release");
    }
    let status = cmd
        .current_dir(&ebpf_dir)
        .status()
        .expect("failed to build eBPF program");
    if !status.success() {
        panic!("eBPF build failed");
    }

    // Copy the resulting object file to OUT_DIR
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile_dir = if profile == "release" {
        "release"
    } else {
        "debug"
    };
    let src = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile_dir)
        .join("rust_udcn_ebpf.o");
    let dst = out_dir.join("rust_udcn_ebpf.o");
    fs::create_dir_all(&out_dir).unwrap();
    fs::copy(&src, &dst).expect("failed to copy eBPF object");

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
}
