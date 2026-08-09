# Setting up and testing AirClip on a Mac

Written for the project's actual situation: development happens on Windows, and the only
Mac available is an Intel MacBook Pro running a current macOS via OpenCore Legacy Patcher
(OCLP). It works for a stock Mac too — just skip the OCLP notes.

**Use the Mac for development and device testing. Leave release builds to CI.** OCLP is a
community patch and a macOS update can break it; the `ios-app` and `bindings` jobs in
`.github/workflows/ci.yml` already build everything on a current, supported toolchain.

---

## 0. Check the machine first

Five minutes here can save an afternoon.

```bash
sw_vers                                   # macOS version
uname -m                                  # x86_64 = Intel
system_profiler SPHardwareDataType | grep -E "Model Identifier|Memory"
df -h / | tail -1                         # need ~60 GB free
csrutil status                            # OCLP requires SIP disabled — expected
```

**What matters:**

| Check | Needs to be | If not |
|---|---|---|
| Free disk | ≥ 60 GB | Xcode + simulators alone are ~40 GB |
| RAM | 8 GB min, 16 preferred | Builds will swap heavily at 8 |
| macOS | Recent enough for a usable Xcode | See step 1 |

`csrutil status` reporting *disabled* is normal on OCLP and does not affect development.

---

## 1. Install Xcode

**Download from [developer.apple.com/download/all](https://developer.apple.com/download/all),
not the App Store.** The App Store only offers the newest release, which may refuse to
install on your macOS or may be Apple-silicon-only. The developer downloads page lets you
pick a version that matches.

Choose the **highest Xcode version your macOS supports**. Each Xcode requires roughly
"current macOS minus one", and its release notes state the minimum explicitly.

Then:

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license accept
xcodebuild -runFirstLaunch                # installs the platform components
xcodebuild -version                       # confirm
```

> **OCLP note.** Xcode itself is x86_64-native and should run fine. The **iOS Simulator is
> the weak spot** — it needs Metal, and OCLP root-patches graphics on unsupported GPUs, so
> Simulator may be slow or broken. This matters less than it sounds: AirClip must be tested
> on a real iPhone anyway. The Action Button, the paste-permission chip, Local Network
> permission and the keyboard's memory ceiling cannot be exercised in a Simulator.

> **SDK ceiling.** If your macOS caps you at an older Xcode, you get an older iOS SDK. Fine
> for development and device testing. App Store Connect rejects builds made with stale
> SDKs, so **TestFlight uploads may still have to come from CI** — which is the intended
> split anyway.

---

## 2. Install the rest of the toolchain

```bash
# Homebrew (installs to /usr/local on Intel)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/usr/local/bin/brew shellenv)"

brew install xcodegen git

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The iOS Rust targets are added by the build script itself — no need to do it by hand.

---

## 3. Get the code and sanity-check it

```bash
git clone https://github.com/Soarcer/airclip.git
cd airclip

cargo test -p airclip-core        # ~130 tests, all should pass
```

If these fail, stop — the problem is the toolchain, not the iOS setup.

---

## 4. Build the iOS project

```bash
./scripts/gen-ios-bindings.sh     # Rust → iOS, bindings, xcframework (slow first time)
cd apps/ios
xcodegen generate
open AirClip.xcodeproj
```

Order matters: the app links `AirClipCore.xcframework`, so the project will not build
until the script has produced it.

**Never edit the Xcode project.** It is generated from `project.yml` and is gitignored.
To change targets, entitlements or Info.plist keys, edit the spec and re-run `xcodegen`.

---

## 5. Set up signing (once)

1. **Xcode → Settings → Accounts → +** — sign in with the Apple ID that holds your paid
   Developer Program membership.
2. Select the **AirClip** target → **Signing & Capabilities**.
3. Tick **Automatically manage signing** and pick your Team.
4. If the bundle ID `com.narrion.airclip` is unavailable, change it in `project.yml`
   (`PRODUCT_BUNDLE_IDENTIFIER`) and re-run `xcodegen` — **not** in Xcode, or your change
   is lost on the next generate.

Xcode should provision the **App Group** (`group.com.narrion.airclip`) and **Keychain
Sharing** automatically, since both are declared in `AirClip/AirClip.entitlements`. If it
complains, add those capabilities once in the Apple Developer portal for that App ID.

---

## 6. Start the Windows side

On the PC, on the **same Wi-Fi**:

```powershell
cargo run -p airclip-windows -- --pair
```

A pairing window appears with a QR code and the URL is printed to the terminal.

> **The single most likely failure:** Windows Firewall silently blocking inbound TCP
> **49517**. On first run Windows shows a dialog — **allow it on Private networks**. If you
> dismissed it, either re-allow it in Windows Defender Firewall or install via the MSI,
> which adds the rule for you.

Also confirm your Wi-Fi is set to **Private**, not Public — Public blocks inbound
connections regardless of app rules.

---

## 7. Run on the iPhone

1. Plug the iPhone into the MacBook, unlock it, and **Trust This Computer**.
2. In Xcode, pick your iPhone as the run destination (not a Simulator).
3. **⌘R**.
4. First launch on a device: **Settings → General → VPN & Device Management** on the phone,
   and trust your developer certificate.

Two permission prompts will appear — both are required:

- **Local Network** — this is the one that matters. Denying it leaves the app unable to
  reach the PC at all. Settings → AirClip → Local Network if you need to re-enable it.
- **Camera** — for scanning the pairing QR.

---

## 8. Pair

1. Tap **Scan pairing code** on the phone.
2. Point it at the QR in the PC's pairing window.
3. **Four emoji appear on both screens. Compare them.**
   They must be identical. This is the entire defence against a machine-in-the-middle on
   your network (PROTOCOL §7.2) — if they differ, tap *They don't match*.
4. Tap **They match**. The PC window shows a success state.

---

## 9. Test the two flows

**iPhone → PC (SPEC R3/R4):**

1. Copy some text on the iPhone.
2. Open AirClip → **Beam clipboard to PC**.
3. Check the PC clipboard (`Get-Clipboard` in PowerShell, or just paste).
4. Expect a toast on the PC and "Sent to …" in the app.

**PC → iPhone (SPEC R6, in-app form):**

1. Copy something on the PC.
2. In the app, pull down to refresh **From your PC**.
3. Tap the clip — it goes onto the iPhone's clipboard, ready to paste.

> The Action Button and keyboard-extension flows are **T-08 and T-09**, not yet built. This
> step tests the in-app equivalents of the same core calls.

---

## 10. Close out T-07's acceptance criteria

These are the four checks the task list still owes, and they all need this setup:

| Criterion | How |
|---|---|
| Pair against the real Windows agent | Step 8 |
| SAS emoji match on both sides | Step 8 — compare them properly |
| Pairing survives relaunch | Force-quit the app, reopen — it should still show Paired without re-scanning |
| Unreachable state within ~3 s | Turn on Airplane Mode (or quit the PC agent), tap Beam — expect a clear error fast, never a silent failure or an indefinite spinner |

If all four pass, tick T-07 in `docs/PHASE-1-TASKS.md`.

---

## Troubleshooting

**"Your PC isn't reachable on this Wi-Fi"**
1. Windows Firewall — inbound TCP 49517 on Private networks. Most common cause by far.
2. Both devices on the same network and the same band/VLAN. Many routers have **AP/client
   isolation** on guest networks, which blocks device-to-device traffic entirely.
3. Agent actually running (`--pair` or plain) and showing "listening" in its log.

The QR's addresses are used directly for pairing and are reused for the first beams after
pairing, so a successful pair followed by failing beams points at mDNS, not the firewall.
Later app launches rely on mDNS discovery; manual host entry is SPEC R10, a planned P1
follow-up.

**Local Network permission was denied**
Settings → AirClip → Local Network. The app's Home screen also surfaces this state with a
direct link, since a denial otherwise looks like a hang.

**`xcodegen: command not found`**
`eval "$(/usr/local/bin/brew shellenv)"` — Homebrew on Intel installs to `/usr/local`, and
a fresh shell may not have it on PATH.

**Simulator won't launch / renders wrong (OCLP)**
Expected. Use the physical device.

**Xcode won't install or refuses to launch**
Your macOS is likely below that Xcode's minimum. Drop one major version from the developer
downloads page.

**Bindings look stale after changing Rust**
Re-run `./scripts/gen-ios-bindings.sh`, then `xcodegen generate`. CI fails any commit whose
checked-in bindings do not match the Rust that generates them.
