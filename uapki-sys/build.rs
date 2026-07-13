//! Builds and links UAPKI for the FFI bindings.
//!
//! The UAPKI C code is wired in as a git submodule at `uapki-sys/uapki`.
//! build.rs compiles it with cmake into libuapki.a + libuapkic.a + libuapkif.a
//! and links them.
//!
//! Override: `UAPKI_SRC_DIR` — use a different UAPKI source directory instead
//! of the submodule.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=UAPKI_SRC_DIR");
    println!("cargo:rerun-if-env-changed=CXXSTDLIB");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let src = match env::var("UAPKI_SRC_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => {
            let sub = manifest.join("uapki");
            if !sub.join("AUTHORS").exists() {
                update_submodules(&manifest);
            }
            fail_on_empty_directory(&sub);
            sub
        }
    };
    // Rebuild on any UAPKI source change.
    println!("cargo:rerun-if-changed={}", src.join("library").display());

    // Build UAPKI. The fork disables LTO for this build type in its CMakeLists
    // (a GCC-LTO archive holds only bitcode, no real symbols, which the
    // downstream LLVM linker can't resolve), so a plain Release build produces
    // ordinary objects any linker reads.
    let dst = cmake::Config::new(src.join("library"))
        .profile("Release")
        .define("UAPKI_LIBS_TYPE", "STATIC")
        .build_target("uapki")
        .build();
    let lib_dir = dst.join("build").join("out");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    link_uapki_static();
    link_system_deps();
}

/// Links the three UAPKI archives.
fn link_uapki_static() {
    for l in ["uapki", "uapkif", "uapkic"] {
        println!("cargo:rustc-link-lib=static={l}");
    }
}

/// UAPKI system dependencies: curl (HTTP for OCSP/TSP — symbols are present
/// in the archive even when offline), the C++ runtime, and dl where needed.
fn link_system_deps() {
    println!("cargo:rustc-link-lib=dylib=curl");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    cpp_link_stdlib(&target_os);
    // dl is needed by UAPKI's cm-providers on Linux/Android
    if target_os == "linux" || target_os == "android" {
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}

/// Links the C++ standard library. Honors the CXXSTDLIB override, otherwise
/// picks per platform.
fn cpp_link_stdlib(target_os: &str) {
    if let Ok(stdlib) = env::var("CXXSTDLIB") {
        if !stdlib.is_empty() {
            println!("cargo:rustc-link-lib=dylib={stdlib}");
        }
        return;
    }
    match target_os {
        "macos" | "ios" | "freebsd" | "openbsd" => {
            println!("cargo:rustc-link-lib=dylib=c++");
        }
        "aix" => {
            println!("cargo:rustc-link-lib=dylib=c++");
            println!("cargo:rustc-link-lib=dylib=c++abi");
        }
        // linux, android and the rest of the GNU world
        _ => println!("cargo:rustc-link-lib=dylib=stdc++"),
    }
}

fn update_submodules(manifest: &Path) {
    // repo root is one level above uapki-sys
    let repo_root = manifest.parent().unwrap_or(manifest);
    let status = Command::new("git")
        .current_dir(repo_root)
        .args(["submodule", "update", "--init", "uapki-sys/uapki"])
        .status();
    match status.map(|s| (s.success(), s.code())) {
        Ok((true, _)) => {}
        Ok((false, Some(c))) => panic!("`git submodule update` failed with exit code {c}"),
        Ok((false, None)) => panic!("`git submodule update` was killed by a signal"),
        Err(e) => panic!("failed to run `git submodule update`: {e}"),
    }
}

fn fail_on_empty_directory(dir: &Path) {
    if !dir.join("AUTHORS").exists() {
        panic!(
            "UAPKI directory ({}) is empty — the submodule was not checked out.\n\
             Run: git submodule update --init --recursive\n\
             or set UAPKI_SRC_DIR to a UAPKI source directory.",
            dir.display()
        );
    }
}
