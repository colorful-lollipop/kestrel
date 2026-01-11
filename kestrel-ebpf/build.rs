use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/main.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");

    // Only build eBPF programs when not running tests/docs
    // to avoid requiring clang/bpf tools in all environments
    let is_test = std::env::var("CARGO_CFG_TEST").is_ok();
    let is_docs = std::env::var("DOCS_RS").is_ok();

    if is_test || is_docs {
        println!("cargo:warning=Skipping eBPF compilation in test/docs mode");
        return;
    }

    // Check if clang is available
    let has_clang = Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !has_clang {
        println!("cargo:warning=clang not found, skipping eBPF compilation");
        println!("cargo:warning=eBPF programs will not be available");
        return;
    }

    // Compile eBPF program
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let bpf_src = PathBuf::from("src/bpf/main.bpf.c");
    let bpf_obj = out_dir.join("main.bpf.o");

    let clang_version = std::env::var("CLANG_VERSION").ok();
    let clang_cmd = clang_version.as_ref().map(|v| format!("clang-{}", v)).unwrap_or_else(|| "clang".to_string());

    let status = Command::new(&clang_cmd)
        .arg("-g")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(&bpf_src)
        .arg("-o")
        .arg(&bpf_obj)
        .arg("-D__TARGET_ARCH_x86")
        .arg("-I/usr/include/x86_64-linux-gnu")
        .arg("-Wall")
        .arg("-Werror")
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:info=eBPF program compiled successfully");
        }
        Ok(_) => {
            println!("cargo:warning=Failed to compile eBPF program (clang failed)");
            println!("cargo:warning=eBPF programs will not be available");
        }
        Err(e) => {
            println!("cargo:warning=Failed to run clang: {}", e);
            println!("cargo:warning=eBPF programs will not be available");
        }
    }
}
