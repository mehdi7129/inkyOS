import AppKit
import Foundation

let output = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        let factor = CGFloat(pixels) / 1024
        let transform = NSAffineTransform(); transform.scale(by: factor); transform.concat()
        NSColor(calibratedWhite: 0.96, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: 32, y: 32, width: 960, height: 960), xRadius: 210, yRadius: 210).fill()
        let card = NSBezierPath()
        card.move(to: NSPoint(x: 310, y: 195)); card.line(to: NSPoint(x: 714, y: 195))
        card.curve(to: NSPoint(x: 754, y: 235), controlPoint1: NSPoint(x: 744, y: 195), controlPoint2: NSPoint(x: 754, y: 205))
        card.line(to: NSPoint(x: 754, y: 710)); card.line(to: NSPoint(x: 624, y: 840))
        card.line(to: NSPoint(x: 310, y: 840))
        card.curve(to: NSPoint(x: 270, y: 800), controlPoint1: NSPoint(x: 280, y: 840), controlPoint2: NSPoint(x: 270, y: 830))
        card.line(to: NSPoint(x: 270, y: 235))
        card.curve(to: NSPoint(x: 310, y: 195), controlPoint1: NSPoint(x: 270, y: 205), controlPoint2: NSPoint(x: 280, y: 195))
        card.close(); NSColor(calibratedWhite: 0.10, alpha: 1).setFill(); card.fill()
        NSColor(calibratedWhite: 0.73, alpha: 1).setFill()
        for x in [330, 390, 450, 510] { NSBezierPath(roundedRect: NSRect(x: x, y: 720, width: 35, height: 75), xRadius: 8, yRadius: 8).fill() }
        let text = "iK" as NSString
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 210, weight: .semibold), .foregroundColor: NSColor.white]
        let bounds = text.size(withAttributes: attributes)
        text.draw(at: NSPoint(x: 512 - bounds.width / 2, y: 355), withAttributes: attributes)
        NSGraphicsContext.restoreGraphicsState()
        let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
        try bitmap.representation(using: .png, properties: [:])!.write(to: output.appendingPathComponent(name))
    }
}
