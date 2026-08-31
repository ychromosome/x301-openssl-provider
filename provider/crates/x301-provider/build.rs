//! Native-shim build contract.
//!
//! Sources: Cargo build-script environment/link directives and the OpenSSL
//! provider header ABI for the selected major-3 or major-4 reference prefix.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn require_exact_environment(name: &str, expected: &str) {
    let actual = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert_eq!(actual, expected, "unsafe {name} selection");
}

fn canonical_directory(name: &str) -> PathBuf {
    let raw = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert!(
        !raw.chars().any(char::is_control),
        "{name} contains a control character"
    );
    let path = fs::canonicalize(&raw)
        .unwrap_or_else(|error| panic!("cannot canonicalize {name}: {error}"));
    assert!(path.is_dir(), "{name} is not a directory");
    let printable = path
        .to_str()
        .unwrap_or_else(|| panic!("{name} is not valid UTF-8"));
    assert!(
        !printable.chars().any(char::is_control),
        "canonical {name} contains a control character"
    );
    path
}

fn reject_native_injection_environment() {
    const EXACT: &[&str] = &[
        "ARFLAGS",
        "CFLAGS",
        "CCC_OVERRIDE_OPTIONS",
        "CCC_PRINT_BINDINGS",
        "CCC_PRINT_OPTIONS",
        "COMPILER_PATH",
        "CPPFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "CRATE_CC_NO_DEFAULTS",
        "CC_ENABLE_DEBUG_OUTPUT",
        "GCC_EXEC_PREFIX",
        "HOST_ARFLAGS",
        "HOST_CFLAGS",
        "TARGET_ARFLAGS",
        "TARGET_CFLAGS",
    ];

    for (name, _) in env::vars_os() {
        let Some(name) = name.to_str() else {
            panic!("non-UTF-8 environment variable name");
        };
        let prefixed = [
            "CC_",
            "CXX_",
            "AR_",
            "RANLIB_",
            "CFLAGS_",
            "CPPFLAGS_",
            "CXXFLAGS_",
            "LDFLAGS_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix));
        assert!(
            !prefixed && !EXACT.contains(&name),
            "native build override is forbidden: {name}"
        );
    }
}

fn main() {
    println!("cargo:rerun-if-changed=c/provider_shim.c");
    println!("cargo:rerun-if-changed=c/hybrid_kem.c");
    println!("cargo:rerun-if-changed=../ed301-eddsa-provider/c/param_helpers.h");
    println!("cargo:rerun-if-changed=c/provider_internal.h");
    for name in [
        "X301_HERMETIC_PROVIDER_BUILD",
        "OPENSSL_INCLUDE_DIR",
        "OPENSSL_LIB_DIR",
        "CC",
        "AR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    require_exact_environment("X301_HERMETIC_PROVIDER_BUILD", "1");
    let fuzz_coverage = env::var_os("CARGO_FEATURE_TEST_FUZZ_COVERAGE").is_some();
    let compiler_path = if fuzz_coverage {
        "/usr/bin/clang"
    } else {
        "/usr/bin/gcc"
    };
    require_exact_environment("CC", compiler_path);
    require_exact_environment("AR", "/usr/bin/ar");
    reject_native_injection_environment();
    let include_dir = canonical_directory("OPENSSL_INCLUDE_DIR");
    let lib_dir = canonical_directory("OPENSSL_LIB_DIR");

    let output_dir = canonical_directory("OUT_DIR");
    let object = output_dir.join("provider_shim.o");
    let hybrid_object = output_dir.join("hybrid_kem.o");
    let archive = output_dir.join("libx301_provider_shim.a");
    let hybrid = env::var_os("CARGO_FEATURE_TLS_X301_MLKEM1024").is_some();
    let sanitizer = env::var_os("CARGO_FEATURE_TEST_SANITIZER").is_some();
    assert!(
        !(sanitizer && fuzz_coverage),
        "sanitizer and fuzz-coverage variants must remain separate"
    );
    let mut compiler = Command::new(compiler_path);
    compiler
        .arg("-std=c11")
        .arg("-fPIC")
        .arg("-fvisibility=hidden")
        .arg("-fstack-protector-strong")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-I")
        .arg(&include_dir)
        .arg("-c")
        .arg("c/provider_shim.c")
        .arg("-o")
        .arg(&object);
    if sanitizer {
        compiler
            .arg("-fsanitize=address,undefined")
            .arg("-fno-sanitize-recover=all")
            .arg("-fno-omit-frame-pointer");
    }
    if fuzz_coverage {
        compiler.arg("-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp");
    }
    if env::var_os("CARGO_FEATURE_TEST_FAILPOINT").is_some() {
        compiler.arg("-DX301_TEST_FAILPOINT_ARTIFACT=1");
    }
    if hybrid {
        compiler.arg("-DX301_ENABLE_HYBRID_MLKEM1024=1");
    }
    assert!(
        compiler
            .status()
            .expect("failed to execute /usr/bin/gcc")
            .success(),
        "C provider shim compilation failed"
    );
    if hybrid {
        let mut hybrid_compiler = Command::new(compiler_path);
        hybrid_compiler
            .arg("-std=c11")
            .arg("-fPIC")
            .arg("-fvisibility=hidden")
            .arg("-fstack-protector-strong")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg("-DX301_ENABLE_HYBRID_MLKEM1024=1")
            .arg("-I")
            .arg(&include_dir)
            .arg("-c")
            .arg("c/hybrid_kem.c")
            .arg("-o")
            .arg(&hybrid_object);
        if sanitizer {
            hybrid_compiler
                .arg("-fsanitize=address,undefined")
                .arg("-fno-sanitize-recover=all")
                .arg("-fno-omit-frame-pointer");
        }
        if fuzz_coverage {
            hybrid_compiler.arg("-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp");
        }
        assert!(
            hybrid_compiler
                .status()
                .expect("failed to execute /usr/bin/gcc")
                .success(),
            "C hybrid KEM compilation failed"
        );
    }
    let mut archiver = Command::new("/usr/bin/ar");
    archiver.arg("crs").arg(&archive).arg(&object);
    if hybrid {
        archiver.arg(&hybrid_object);
    }
    assert!(
        archiver
            .status()
            .expect("failed to execute /usr/bin/ar")
            .success(),
        "C provider shim archive failed"
    );

    println!(
        "cargo:rustc-link-search=native={}",
        output_dir
            .to_str()
            .expect("canonical OUT_DIR must remain UTF-8")
    );
    println!("cargo:rustc-link-lib=static=x301_provider_shim");
    if sanitizer {
        /*
         * Test-only native instrumentation.  Stable Rust does not expose a
         * supported whole-crate sanitizer switch, so Valgrind remains the
         * independent Rust/FFI memory-safety lane.  These libraries bind the
         * instrumented C provider boundary and hybrid parser into the DSO.
         */
        println!("cargo:rustc-link-lib=asan");
        println!("cargo:rustc-link-lib=ubsan");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir
            .to_str()
            .expect("canonical OPENSSL_LIB_DIR must remain UTF-8")
    );
    println!("cargo:rustc-link-lib=crypto");
}
