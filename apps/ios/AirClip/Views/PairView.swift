import AVFoundation
import SwiftUI

/// QR scan → SAS comparison → paired (PROTOCOL §7).
///
/// The SAS step is the whole security story: an active MITM is caught here and nowhere
/// else, so the copy is deliberately blunt about what a mismatch means and "they don't
/// match" is as prominent as confirming.
struct PairView: View {
    @EnvironmentObject private var core: CoreController
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Pair with PC")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            core.cancelPairing()
                            dismiss()
                        }
                    }
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch core.pairingPhase {
        case .idle, .scanning:
            scanner
        case .connecting:
            centred {
                ProgressView()
                Text("Connecting to your PC…").foregroundStyle(.secondary)
            }
        case let .confirming(emoji):
            confirmation(emoji: emoji)
        case let .paired(name):
            centred {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.green)
                Text("Paired with \(name)").font(.headline)
                Button("Done") { dismiss() }.buttonStyle(.borderedProminent)
            }
        case let .failed(reason):
            centred {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.orange)
                Text("Pairing failed").font(.headline)
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("Try again") { core.cancelPairing() }
            }
        }
    }

    private var scanner: some View {
        ZStack {
            QRScannerView { scanned in
                // The core rejects anything that is not a valid airclip:// payload, so
                // no validation is duplicated here.
                core.beginPairing(qrURL: scanned)
            }
            .ignoresSafeArea()

            VStack {
                Spacer()
                Text("Point the camera at the code on your PC")
                    .font(.footnote)
                    .padding(10)
                    .background(.ultraThinMaterial, in: Capsule())
                    .padding(.bottom, 40)
            }
        }
    }

    private func confirmation(emoji: [String]) -> some View {
        VStack(spacing: 24) {
            Text("Do these match your PC?")
                .font(.title3.weight(.semibold))

            Text(emoji.joined(separator: "  "))
                .font(.system(size: 52))
                .accessibilityLabel(emoji.joined(separator: ", "))

            Text("If they don't match, someone may be intercepting your connection. Tap \u{201C}They don't match\u{201D}.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            VStack(spacing: 12) {
                Button {
                    core.confirmPairing()
                } label: {
                    Text("They match").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                Button(role: .destructive) {
                    core.cancelPairing()
                    dismiss()
                } label: {
                    Text("They don't match").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal)
        }
        .padding()
    }

    private func centred<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: 16) { content() }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
    }
}

/// Thin AVFoundation QR scanner.
///
/// AVFoundation rather than VisionKit's DataScannerViewController: the latter is
/// unavailable on devices without the Neural Engine, and pairing must work on every
/// iPhone that runs iOS 17.
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onScan = onScan
        return controller
    }

    func updateUIViewController(_: ScannerViewController, context _: Context) {}

    final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onScan: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var previewLayer: AVCaptureVideoPreviewLayer?
        private var hasScanned = false

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            configureSession()
        }

        private func configureSession() {
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input)
            else { return }
            session.addInput(input)

            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]

            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            view.layer.addSublayer(layer)
            previewLayer = layer
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            previewLayer?.frame = view.bounds
        }

        override func viewWillAppear(_ animated: Bool) {
            super.viewWillAppear(animated)
            guard !session.isRunning else { return }
            // startRunning blocks; the docs are explicit that it must not run on the
            // main queue.
            Task.detached { [session] in session.startRunning() }
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            if session.isRunning { session.stopRunning() }
        }

        func metadataOutput(
            _: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from _: AVCaptureConnection
        ) {
            // A QR code produces many frames a second; without this the core would be
            // handed the same payload dozens of times.
            guard !hasScanned,
                  let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  let value = object.stringValue
            else { return }
            hasScanned = true
            session.stopRunning()
            onScan?(value)
        }
    }
}
