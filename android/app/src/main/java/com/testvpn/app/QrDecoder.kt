package com.testvpn.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer

/** Finds and decodes a QR code in an image (a photo or a screenshot). */
object QrDecoder {
    /** Long side the image is scaled to; dense QR codes (vpn:// keys) need detail. */
    private const val MAX_SIDE = 2048

    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )

    /** Returns the text of the QR code, or null if none was found. Call off the main thread. */
    fun decode(ctx: Context, uri: Uri): String? {
        val bitmap = load(ctx, uri) ?: return null
        try {
            // Retry smaller: on large photos a small QR code is found more easily.
            for (scale in listOf(1.0, 0.5)) {
                val b = if (scale == 1.0) bitmap else Bitmap.createScaledBitmap(
                    bitmap, (bitmap.width * scale).toInt().coerceAtLeast(1), (bitmap.height * scale).toInt().coerceAtLeast(1), true,
                )
                decode(b)?.let { return it }
                if (b !== bitmap) b.recycle()
            }
            return null
        } finally {
            bitmap.recycle()
        }
    }

    private fun decode(bitmap: Bitmap): String? {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
        // Light-on-dark codes (dark themes) need the inverted image.
        for (src in listOf(source, source.invert())) {
            decode(src)?.let { return it }
        }
        return null
    }

    private fun decode(src: LuminanceSource): String? {
        val reader = MultiFormatReader().apply { setHints(hints) }
        for (binary in listOf(BinaryBitmap(HybridBinarizer(src)), BinaryBitmap(GlobalHistogramBinarizer(src)))) {
            try {
                return reader.decodeWithState(binary).text
            } catch (_: NotFoundException) {
            } catch (_: Exception) {
                // Checksum or format errors: try the next binarizer.
            } finally {
                reader.reset()
            }
        }
        return null
    }

    /** Loads the image scaled down to at most [MAX_SIDE] pixels on the long side. */
    private fun load(ctx: Context, uri: Uri): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        ctx.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= MAX_SIDE) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        return ctx.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }
    }
}
