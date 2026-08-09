#!/usr/bin/env bash
# Regenerate UniFFI Swift bindings + xcframework (ARCHITECTURE §7).
#
# Runs on macOS — cargo needs the iOS SDK to link, and xcodebuild is macOS-only. The
# maintainer develops on Windows, so in practice this runs on the CI macOS runner; see
# .github/workflows/ci.yml.
#
# Output is checked in (ARCHITECTURE §2) so an Xcode build never has to run Rust. CI
# re-runs this and fails on any diff, which is why every step below must be
# deterministic — notably --no-format, since swift-format's availability and version
# vary by machine and would otherwise produce spurious diffs.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
LIB=libairclip_core.a
OUT=apps/ios/Generated
XCFRAMEWORK=apps/ios/AirClipCore.xcframework

echo "==> building airclip-core for ${#TARGETS[@]} iOS targets"
for t in "${TARGETS[@]}"; do
  rustup target add "$t" >/dev/null 2>&1 || true
  cargo build -p airclip-core --release --features ffi --target "$t"
done

echo "==> generating Swift bindings"
rm -rf "$OUT"
mkdir -p "$OUT"
# --library reads metadata out of the compiled staticlib, which is how proc-macro
# UniFFI works; there is no .udl file to point at.
cargo run -p airclip-core --features ffi --bin uniffi-bindgen -- \
  generate --library "target/${TARGETS[0]}/release/${LIB}" \
  --language swift --out-dir "$OUT" --no-format

# xcodebuild requires the headers directory to contain `module.modulemap` under that
# exact name; UniFFI emits <ModuleName>FFI.modulemap.
HEADERS=$(mktemp -d)
cp "$OUT"/*.h "$HEADERS/"
cp "$OUT"/AirClipCoreFFI.modulemap "$HEADERS/module.modulemap"

echo "==> assembling xcframework"
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/release/${LIB}" -headers "$HEADERS" \
  -library "target/aarch64-apple-ios-sim/release/${LIB}" -headers "$HEADERS" \
  -output "$XCFRAMEWORK"
rm -rf "$HEADERS"

echo "OK: bindings in $OUT, xcframework at $XCFRAMEWORK"
