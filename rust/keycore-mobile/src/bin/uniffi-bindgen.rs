// Library-mode UniFFI bindings generator.
//
// UniFFI does not ship a standalone `uniffi-bindgen` binary pinned to each
// `uniffi` release, so the documented pattern is to re-expose its CLI entry
// point from the crate that owns the matching `uniffi` version. Run with:
//
//   cargo run -p keycore-mobile --features cli --bin uniffi-bindgen -- \
//       generate --library target/debug/libkeycore_mobile.so \
//       --language kotlin --out-dir bindings-kotlin
//
// This target is gated behind the `cli` feature (see Cargo.toml) so the
// clap/bindgen dependency tree never enters ordinary host builds.

fn main() {
    uniffi::uniffi_bindgen_main()
}
