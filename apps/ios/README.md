# AirClip iOS

Xcode project is created locally (not generated here). Setup:

1. Xcode → new iOS App "AirClip", org ID `com.narrion`, SwiftUI, iOS 17 floor.
2. Add targets: App Intents Extension `AirClipSendIntent`, Custom Keyboard Extension `AirClipKeyboard` (RequestsOpenAccess YES), Share Extension `AirClipShare`.
3. All targets: App Group `group.com.narrion.airclip` + Keychain Sharing (same group).
4. Run `../../scripts/gen-ios-bindings.sh`, drag `AirClipCore.xcframework` + `Generated/*.swift` into the project (all targets).
5. App Info.plist: `NSBonjourServices` = `_airclip._tcp`, `NSLocalNetworkUsageDescription`, `NSCameraUsageDescription` (pairing QR).
6. Swift sources for each target live in the sibling folders here — see docs/PHASE-1-TASKS.md T-07..T-09 for what goes where.

Platform rules that shape everything: ../../docs/IOS-PLATFORM-NOTES.md
