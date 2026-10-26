import SwiftUI

struct UsageRingView: View {
    let content: NotchContentView.CollapsedRingContent
    var diameter: CGFloat = 15
    var lineWidth: CGFloat = 3
    var isStale: Bool = false
    /// Anneau intérieur (second compte), dessiné dans le même emplacement.
    var inner: NotchContentView.CollapsedRingContent?
    var innerIsStale: Bool = false

    @State private var drawProgress: CGFloat = 0

    private var clampedPercentage: Int {
        switch content {
        case .percentage(let percentage): min(max(percentage, 0), 100)
        case .unlimited: 0
        }
    }

    private var isUnlimited: Bool {
        content == .unlimited
    }

    private func color(_ percentage: Int, stale: Bool) -> Color {
        let base: Color
        switch percentage {
        case ..<50: base = TerminalColors.green
        case ..<80: base = TerminalColors.amber
        default: base = TerminalColors.red
        }
        return stale ? base.opacity(0.5) : base
    }

    private var ringColor: Color { color(clampedPercentage, stale: isStale) }

    private var innerPercentage: Int? {
        guard case .percentage(let p) = inner else { return nil }
        return min(max(p, 0), 100)
    }

    private func ring(_ percentage: Int, color: Color, size: CGFloat, width: CGFloat, track: Double = 0.28) -> some View {
        ZStack {
            UsageRingArc(fraction: Double(drawProgress))
                .stroke(color.opacity(track), style: StrokeStyle(lineWidth: width, lineCap: .butt))
            UsageRingArc(fraction: Double(percentage) / 100 * Double(drawProgress))
                .stroke(color, style: StrokeStyle(lineWidth: width, lineCap: .round))
        }
        .frame(width: size, height: size)
    }

    var body: some View {
        ZStack {
            if isUnlimited {
                Image(systemName: "infinity")
                    .font(.system(size: diameter * 0.85, weight: .bold))
                    .foregroundStyle(ringColor)
                    .opacity(Double(drawProgress))
                    .accessibilityLabel(String(localized: "No spending cap"))
            } else {
                ring(clampedPercentage, color: ringColor, size: diameter, width: lineWidth)
                if let innerPercentage {
                    ring(innerPercentage, color: color(innerPercentage, stale: innerIsStale), size: diameter - 8.5, width: 2.5, track: 0.35)
                }
            }
        }
        .frame(width: isUnlimited ? nil : diameter, height: diameter)
        .fixedSize()
        .onAppear {
            withAnimation(.spring(response: 0.7, dampingFraction: 0.65)) { drawProgress = 1 }
        }
        .animation(.easeInOut(duration: 0.3), value: clampedPercentage)
    }
}

private struct UsageRingArc: Shape {
    var fraction: Double

    var animatableData: Double {
        get { fraction }
        set { fraction = newValue }
    }

    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        path.addArc(
            center: center,
            radius: radius,
            startAngle: .degrees(-90),
            endAngle: .degrees(-90 + 360 * fraction),
            clockwise: false
        )
        return path
    }
}

#Preview {
    HStack(spacing: 12) {
        UsageRingView(content: .percentage(25))
        UsageRingView(content: .percentage(65))
        UsageRingView(content: .percentage(95))
        UsageRingView(content: .unlimited)
        UsageRingView(content: .unlimited, isStale: true)
        UsageRingView(content: .percentage(65), inner: .percentage(30))
        UsageRingView(content: .percentage(90), inner: .percentage(55), innerIsStale: true)
    }
    .padding()
    .background(Color.black)
}
