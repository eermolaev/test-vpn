import CoreImage
import Foundation

/// Decodes QR codes from images (Files, Photos).
enum QRDecoder {
    static func decode(url: URL) -> String? {
        guard let image = CIImage(contentsOf: url) else { return nil }
        return decode(image)
    }

    static func decode(data: Data) -> String? {
        guard let image = CIImage(data: data) else { return nil }
        return decode(image)
    }

    private static func decode(_ image: CIImage) -> String? {
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        if let code = detector?.features(in: image).compactMap({ ($0 as? CIQRCodeFeature)?.messageString }).first {
            return code
        }
        // Light-on-dark codes (dark-theme screenshots) are found after inverting.
        let inverted = image.applyingFilter("CIColorInvert")
        return detector?.features(in: inverted).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first
    }
}
