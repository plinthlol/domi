use std::{env, fs, path::PathBuf};

fn main() {
    uniffi::generate_scaffolding("src/domi.udl").unwrap();

    // Edition 2024 made `#[no_mangle]` an unsafe attribute, so it must be
    // written `#[unsafe(no_mangle)]`. UniFFI 0.28 still emits the edition-2021
    // spelling into OUT_DIR, which is generated fresh on every build and so
    // cannot be fixed in place. Rewrite it before the scaffolding is compiled.
    let scaffold = PathBuf::from(env::var("OUT_DIR").unwrap()).join("domi.uniffi.rs");
    let src = fs::read_to_string(&scaffold).unwrap();
    let patched = src.replace("#[no_mangle]", "#[unsafe(no_mangle)]");
    if patched != src {
        fs::write(&scaffold, patched).unwrap();
    }
}