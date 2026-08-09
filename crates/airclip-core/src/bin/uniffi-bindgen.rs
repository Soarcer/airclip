//! Binding generator, invoked by scripts/gen-ios-bindings.sh.
//!
//! UniFFI's proc-macro mode reads the metadata baked into the compiled library, so the
//! generator has to be built from this same crate — a standalone `uniffi-bindgen` binary
//! would not see our exports.

fn main() {
    uniffi::uniffi_bindgen_main()
}
