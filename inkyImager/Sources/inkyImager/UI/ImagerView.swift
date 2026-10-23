import SwiftUI
import ImagerCore

@MainActor
struct ImagerView: View {
    @ObservedObject var model: ImagerModel
    @State private var passwordVisible = false

    private let ink = Color(red: 0.10, green: 0.11, blue: 0.12)
    private let canvas = Color(red: 0.96, green: 0.96, blue: 0.95)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                imageCard
                wifiCard
                storageCard
                footer
            }
            .padding(24)
            .frame(maxWidth: 760)
            .frame(maxWidth: .infinity)
        }
        .background(canvas)
        .foregroundStyle(ink)
        .tint(ink)
        .preferredColorScheme(.light)
        .frame(minWidth: 660, minHeight: 620)
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "sdcard")
                .font(.system(size: 25, weight: .medium))
                .frame(width: 48, height: 48)
                .background(.white, in: RoundedRectangle(cornerRadius: 14))
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text("inkyImager")
                    .font(.system(size: 29, weight: .semibold))
                    .tracking(-0.8)
                Text("Préparez la carte SD de votre cadre.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.bottom, 2)
    }

    private var imageCard: some View {
        card {
            HStack(spacing: 14) {
                Image(systemName: "photo.on.rectangle.angled")
                    .font(.system(size: 23, weight: .regular))
                    .frame(width: 44, height: 44)
                    .foregroundStyle(.white)
                    .background(ink, in: RoundedRectangle(cornerRadius: 12))
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 4) {
                    Text("InkyOS")
                        .font(.system(size: 16, weight: .semibold))
                    Text("Le système de votre cadre photo.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                Spacer(minLength: 12)

                VStack(alignment: .trailing, spacing: 5) {
                    Text("Image intégrée")
                        .font(.system(size: 11, weight: .medium))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(canvas, in: Capsule())
                    if !model.imageVersion.isEmpty {
                        Text(model.imageVersion)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var wifiCard: some View {
        card {
            VStack(alignment: .leading, spacing: 14) {
                sectionTitle("Votre Wi-Fi", symbol: "wifi")

                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        fieldLabel("Nom du réseau")
                        TextField("Nom du Wi-Fi", text: $model.ssid)
                            .textFieldStyle(.roundedBorder)
                            .accessibilityLabel("Nom du réseau Wi-Fi")
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        fieldLabel("Mot de passe")
                        HStack(spacing: 6) {
                            Group {
                                if passwordVisible {
                                    TextField("Mot de passe du Wi-Fi", text: $model.password)
                                } else {
                                    SecureField("Mot de passe du Wi-Fi", text: $model.password)
                                }
                            }
                            .textFieldStyle(.roundedBorder)
                            .accessibilityLabel("Mot de passe du Wi-Fi")

                            Button {
                                passwordVisible.toggle()
                            } label: {
                                Image(systemName: passwordVisible ? "eye.slash" : "eye")
                                    .font(.system(size: 13))
                                    .frame(width: 24, height: 24)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.secondary)
                            .help(passwordVisible ? "Masquer le mot de passe" : "Afficher le mot de passe")
                            .accessibilityLabel(passwordVisible ? "Masquer le mot de passe" : "Afficher le mot de passe")
                        }
                    }
                }
                .disabled(model.isBusy || model.ejectPending)

                HStack(spacing: 6) {
                    Image(systemName: "globe.europe.africa")
                        .accessibilityHidden(true)
                    Text("Pays : \(countryName)")
                    Spacer(minLength: 12)
                    Text("Wi-Fi 2,4 GHz")
                }
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            }
        }
    }

    private var storageCard: some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    sectionTitle("Votre carte SD", symbol: "sdcard")
                    Spacer()
                    Button {
                        model.refreshDevices()
                    } label: {
                        Label("Actualiser", systemImage: "arrow.clockwise")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .buttonStyle(.borderless)
                    .disabled(model.isBusy || model.ejectPending)
                    .help("Rechercher les cartes SD connectées")
                }

                Picker("Carte SD", selection: $model.selectedDeviceID) {
                    Text(model.devices.isEmpty ? "Insérez une carte SD" : "Choisir une carte SD")
                        .tag(Optional<String>.none)
                    ForEach(model.devices) { device in
                        Text("\(device.name) · \(capacity(device.capacity))")
                            .tag(Optional(device.id))
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .frame(maxWidth: .infinity, alignment: .leading)
                .disabled(model.isBusy || model.ejectPending || model.devices.isEmpty)
                .accessibilityLabel("Carte SD à installer")

                if model.devices.isEmpty {
                    Text("Branchez votre carte, puis cliquez sur Actualiser.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !model.isBusy && !model.ejectPending && model.phase != .finished {
                Label("Toutes les données de la carte choisie seront effacées.", systemImage: "exclamationmark.circle")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }

            Button {
                passwordVisible = false
                model.startFlash()
            } label: {
                HStack(spacing: 9) {
                    if model.isBusy {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    } else {
                        Image(systemName: model.ejectPending ? "eject" : "arrow.down.to.line")
                    }
                    Text(model.isBusy ? phaseTitle : (model.ejectPending ? "Éjecter la carte vérifiée" : "Flasher la carte"))
                        .font(.system(size: 14, weight: .semibold))
                }
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .foregroundStyle(.white)
                .background(ink.opacity(model.canFlash || model.isBusy ? 1 : 0.30),
                            in: RoundedRectangle(cornerRadius: 13))
                .contentShape(RoundedRectangle(cornerRadius: 13))
            }
            .buttonStyle(.plain)
            .disabled(!model.canFlash || model.isBusy)
            .accessibilityHint(model.ejectPending ? "Termine l’éjection de la carte déjà vérifiée." : "Efface la carte choisie et installe InkyOS avec votre Wi-Fi.")

            if model.isBusy {
                VStack(alignment: .leading, spacing: 7) {
                    ProgressView(value: min(max(model.progress, 0), 1))
                        .accessibilityLabel("Progression de l’installation")
                    HStack {
                        Text(model.statusMessage.isEmpty ? phaseTitle : model.statusMessage)
                        Spacer(minLength: 8)
                        Text("\(Int(min(max(model.progress, 0), 1) * 100)) %")
                            .monospacedDigit()
                    }
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                }
            } else if model.ejectPending {
                Label {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Carte vérifiée, éjection à terminer.")
                            .font(.system(size: 13, weight: .semibold))
                        Text("Terminez l’éjection avant de retirer la carte.")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(Color(red: 0.66, green: 0.43, blue: 0.12))
                }
                .padding(.top, 2)
                .accessibilityElement(children: .combine)
            } else if model.phase == .finished {
                Label {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Votre carte est prête.")
                            .font(.system(size: 13, weight: .semibold))
                        Text(model.statusMessage.isEmpty ? "Vous pouvez la retirer et allumer votre cadre." : model.statusMessage)
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(Color(red: 0.18, green: 0.46, blue: 0.32))
                }
                .padding(.top, 2)
                .accessibilityElement(children: .combine)
            } else if let error = model.errorMessage, !error.isEmpty {
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Color(red: 0.68, green: 0.19, blue: 0.17))
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                    .accessibilityElement(children: .combine)
            } else if !model.statusMessage.isEmpty {
                Text(model.statusMessage)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var phaseTitle: String {
        switch model.phase {
        case .idle: "Prête à installer"
        case .preparing: "Préparation de l’image…"
        case .writing: "Écriture de la carte…"
        case .verifying: "Vérification de la carte…"
        case .configuring: "Configuration du Wi-Fi…"
        case .ejecting: "Éjection de la carte…"
        case .finished: model.ejectPending ? "Carte vérifiée" : "Carte prête"
        case .failed: "Installation interrompue"
        }
    }

    private var countryName: String {
        if model.country.uppercased() == "FR" { return "France" }
        return Locale(identifier: "fr_FR").localizedString(forRegionCode: model.country.uppercased())
            ?? model.country.uppercased()
    }

    private func fieldLabel(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 12, weight: .medium))
    }

    private func sectionTitle(_ title: String, symbol: String) -> some View {
        Label(title, systemImage: symbol)
            .font(.system(size: 15, weight: .semibold))
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        content()
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(18)
            .background(.white, in: RoundedRectangle(cornerRadius: 20))
            .overlay {
                RoundedRectangle(cornerRadius: 20)
                    .strokeBorder(ink.opacity(0.07), lineWidth: 1)
            }
    }

    private func capacity(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
