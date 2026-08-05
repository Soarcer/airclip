#!/usr/bin/env bash
# Regenerate UniFFI Swift bindings + xcframework. Run on macOS after any change to src/ffi.rs.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
for t in "${TARGETS[@]}"; do
  cargo build -p airclip-core --release --features ffi --target "$t"
done

cargo run -p airclip-core --features ffi --bin uniffi-bindgen -- \
  generate --library "target/${TARGETS[0]}/release/libairclip_core.a" \
  --language swift --out-dir apps/ios/Generated

rm -rf apps/ios/AirClipCore.xcframework
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/release/libairclip_core.a" -headers apps/ios/Generated \
  -library "target/aarch64-apple-ios-sim/release/libairclip_core.a" -headers apps/ios/Generated \
  -output apps/ios/AirClipCore.xcframework
echo "OK: bindings + xcframework regenerated"
