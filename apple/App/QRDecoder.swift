import CoreImage
import Foundation

/// Decodes QR codes from image files (macOS and iOS photo import).
enum QRDecoder {
    static func decode(url: URL) -> String? {
        guard let image = CIImage(contentsOf: url) else { return nil }
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let features = detector?.features(in: image) ?? []
        return features.compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first
    }
}
