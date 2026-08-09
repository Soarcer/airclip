# AirClip iOS

The Xcode project is **generated**, not committed. `project.yml` is the source of truth;
targets, entitlements and Info.plist keys are all declared there.

This is deliberate: the maintainer develops on Windows, and creating targets and App
Groups through the Xcode GUI would be the one step impossible from that machine. It also
keeps `project.pbxproj` — the usual source of unmergeable conflicts — out of git entirely.

## Build

Everything below runs on macOS (or the CI macOS runner, which does exactly this on every
push — see `.github/workflows/ci.yml`).

```bash
brew install xcodegen

# 1. Build the Rust core for iOS and regenerate the Swift bindings + xcframework.
./scripts/gen-ios-bindings.sh

# 2. Generate the Xcode project.
cd apps/ios && xcodegen generate

# 3. Build (or open AirClip.xcodeproj).
xcodebuild build -project AirClip.xcodeproj -scheme AirClip \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO
```

Step 1 is required before step 2: the app links `AirClipCore.xcframework`, so the project
will not open cleanly without it.

## Layout

```
apps/ios/
  project.yml            XcodeGen spec — edit this, not the .xcodeproj
  Generated/             UniFFI Swift bindings (checked in; CI fails if stale)
  AirClip/
    AirClipApp.swift     app entry + launch failure path
    AirClip.entitlements Keychain access group + App Group
    Core/
      CoreController.swift      owns CoreHandle, publishes state to SwiftUI
      KeychainStore.swift       KeystoreDelegate over the Keychain
      LocalNetworkDiscovery.swift  NWBrowser -> add_peer_hint
    Views/
      HomeView.swift            status, beam button, staged clips
      PairView.swift            QR scan -> SAS comparison -> paired
      SettingsView.swift        device id, forget PC, privacy copy
  AirClipSendIntent/     T-08
  AirClipKeyboard/       T-09
```

Extension targets are added to `project.yml` by T-08/T-09 — declaring a target whose
sources do not exist yet breaks the build.

## Signing

Simulator builds need none (`CODE_SIGNING_ALLOWED=NO`). Device and TestFlight builds use
App Store Connect API keys from CI rather than a signing identity on any one machine.

## Before changing anything here

Read `../../docs/IOS-PLATFORM-NOTES.md`. Several obvious designs are impossible on iOS,
and the ones that look like workarounds are usually load-bearing — the paste chip,
`AfterFirstUnlock` Keychain accessibility, and the keyboard never touching the pasteboard
all exist for documented reasons.
