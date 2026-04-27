import Cocoa
import GhosttyKit

extension NSAppearance {
    /// Returns true if the appearance is some kind of dark.
    var isDark: Bool {
        return name.rawValue.lowercased().contains("dark")
    }

    /// The libghostty color scheme matching this appearance.
    var ghosttyColorScheme: ghostty_color_scheme_e {
        isDark ? GHOSTTY_COLOR_SCHEME_DARK : GHOSTTY_COLOR_SCHEME_LIGHT
    }

    /// Initialize a desired NSAppearance for the Ghostty configuration.
    convenience init?(ghosttyConfig config: Ghostty.Config) {
        guard let theme = config.windowTheme else { return nil }
        switch theme {
        case "dark":
            self.init(named: .darkAqua)

        case "light":
            self.init(named: .aqua)

        case "auto":
            let color = OSColor(config.backgroundColor)
            if color.isLightColor {
                self.init(named: .aqua)
            } else {
                self.init(named: .darkAqua)
            }

        default:
            return nil
        }
    }

    /// Returns the effective appearance Ghostty should use for color-scheme
    /// decisions. If the config doesn't force a window appearance, the caller
    /// supplies the system/app fallback appearance.
    static func ghosttyEffectiveAppearance(
        for config: Ghostty.Config,
        fallback fallbackAppearance: NSAppearance
    ) -> NSAppearance {
        .init(ghosttyConfig: config) ?? fallbackAppearance
    }

    /// Returns the effective appearance using the current application's
    /// appearance as the fallback.
    static func ghosttyEffectiveAppearance(for config: Ghostty.Config) -> NSAppearance {
        ghosttyEffectiveAppearance(for: config, fallback: NSApplication.shared.effectiveAppearance)
    }
}
