//! Builds UAPKI with static linking.
//!
//! The UAPKI C code is wired in as a git submodule at `uapki-sys/uapki`.
//! build.rs compiles it with cmake into STATIC libraries
//! (libuapki.a + libuapkic.a + libuapkif.a) and links them directly.
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

    // Build UAPKI static libraries WITHOUT LTO.
    //
    // UAPKI hardcodes -flto in CMAKE_<lang>_FLAGS_RELEASE (both the clang and
    // gcc branches). A GCC-LTO static archive holds only GIMPLE bitcode (slim
    // objects, no real symbols), which rust-lld can't consume — so the shim's
    // symbols come out "undefined" at the final link on Linux.
    //
    // A plain `set(... -flto)` can't be beaten by a -D override, and clearing
    // CMAKE_BUILD_TYPE doesn't help because the cmake crate forces "Release".
    // So we pick a custom build type UAPKI doesn't special-case (its _RELEASE
    // flags never apply) and supply our own optimization via the base flags.
    let dst = cmake::Config::new(src.join("library"))
        .profile("RelNoLTO")
        .define("UAPKI_LIBS_TYPE", "STATIC")
        .cflag("-O2")
        .cflag("-fPIC")
        .cxxflag("-O2")
        .cxxflag("-fPIC")
        .build_target("uapki")
        .build();
    let lib_dir = dst.join("build").join("out");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    link_uapki_static();
    link_system_deps();
}

/// Links the three UAPKI static archives.
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
    // dl is needed for dlopen (UAPKI cm-providers) on Linux/Android
    if target_os == "linux" || target_os == "android" {
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}

/// Links the C++ standard library. Honors the CXXSTDLIB override, otherwise
/// picks per platform (as cc-rs / librocksdb-sys do).
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
