package com.notcvnt.rknhardering

internal enum class LauncherIconVariant(
    val aliasClass: String,
    val prefValue: String,
) {
    ORIGINAL("com.notcvnt.rknhardering.LauncherOriginal", "original"),
    CLASSIC("com.notcvnt.rknhardering.LauncherClassic", "classic"),
    PROTANOPIA("com.notcvnt.rknhardering.LauncherProtanopia", "protanopia"),
    DEUTERANOPIA("com.notcvnt.rknhardering.LauncherDeuteranopia", "deuteranopia"),
    TRITANOPIA("com.notcvnt.rknhardering.LauncherTritanopia", "tritanopia"),
    MONOCHROME("com.notcvnt.rknhardering.LauncherMonochrome", "monochrome");

    companion object {
        fun fromCvd(
            mode: ColorVisionMode,
            redGreenSub: LauncherIconVariant?,
        ): LauncherIconVariant {
            return when (mode) {
                ColorVisionMode.OFF -> ORIGINAL
                ColorVisionMode.RED_GREEN ->
                    redGreenSub?.takeIf { it == PROTANOPIA } ?: DEUTERANOPIA
                ColorVisionMode.BLUE_YELLOW -> TRITANOPIA
                ColorVisionMode.ACHROMATOPSIA -> MONOCHROME
            }
        }

        fun resolve(
            iconStyleClassic: Boolean,
            mode: ColorVisionMode,
            redGreenSub: LauncherIconVariant?,
        ): LauncherIconVariant {
            if (iconStyleClassic) return CLASSIC
            return fromCvd(mode, redGreenSub)
        }
    }
}
