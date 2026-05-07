package com.notcvnt.rknhardering

import org.junit.Assert.assertEquals
import org.junit.Test

class LauncherIconVariantTest {

    @Test
    fun `maps color vision modes to launcher icon variants`() {
        assertEquals(
            LauncherIconVariant.ORIGINAL,
            LauncherIconVariant.fromCvd(ColorVisionMode.OFF, LauncherIconVariant.PROTANOPIA),
        )
        assertEquals(
            LauncherIconVariant.DEUTERANOPIA,
            LauncherIconVariant.fromCvd(ColorVisionMode.RED_GREEN, null),
        )
        assertEquals(
            LauncherIconVariant.PROTANOPIA,
            LauncherIconVariant.fromCvd(ColorVisionMode.RED_GREEN, LauncherIconVariant.PROTANOPIA),
        )
        assertEquals(
            LauncherIconVariant.DEUTERANOPIA,
            LauncherIconVariant.fromCvd(ColorVisionMode.RED_GREEN, LauncherIconVariant.DEUTERANOPIA),
        )
        assertEquals(
            LauncherIconVariant.DEUTERANOPIA,
            LauncherIconVariant.fromCvd(ColorVisionMode.RED_GREEN, LauncherIconVariant.ORIGINAL),
        )
        assertEquals(
            LauncherIconVariant.TRITANOPIA,
            LauncherIconVariant.fromCvd(ColorVisionMode.BLUE_YELLOW, LauncherIconVariant.PROTANOPIA),
        )
        assertEquals(
            LauncherIconVariant.MONOCHROME,
            LauncherIconVariant.fromCvd(ColorVisionMode.ACHROMATOPSIA, LauncherIconVariant.PROTANOPIA),
        )
    }

    @Test
    fun `resolve returns CLASSIC when icon style is classic regardless of CVD`() {
        assertEquals(
            LauncherIconVariant.CLASSIC,
            LauncherIconVariant.resolve(
                iconStyleClassic = true,
                mode = ColorVisionMode.OFF,
                redGreenSub = null,
            ),
        )
        assertEquals(
            LauncherIconVariant.CLASSIC,
            LauncherIconVariant.resolve(
                iconStyleClassic = true,
                mode = ColorVisionMode.RED_GREEN,
                redGreenSub = LauncherIconVariant.DEUTERANOPIA,
            ),
        )
        assertEquals(
            LauncherIconVariant.CLASSIC,
            LauncherIconVariant.resolve(
                iconStyleClassic = true,
                mode = ColorVisionMode.ACHROMATOPSIA,
                redGreenSub = null,
            ),
        )
    }

    @Test
    fun `resolve delegates to fromCvd when icon style is new`() {
        assertEquals(
            LauncherIconVariant.ORIGINAL,
            LauncherIconVariant.resolve(
                iconStyleClassic = false,
                mode = ColorVisionMode.OFF,
                redGreenSub = null,
            ),
        )
        assertEquals(
            LauncherIconVariant.DEUTERANOPIA,
            LauncherIconVariant.resolve(
                iconStyleClassic = false,
                mode = ColorVisionMode.RED_GREEN,
                redGreenSub = null,
            ),
        )
        assertEquals(
            LauncherIconVariant.MONOCHROME,
            LauncherIconVariant.resolve(
                iconStyleClassic = false,
                mode = ColorVisionMode.ACHROMATOPSIA,
                redGreenSub = null,
            ),
        )
    }
}
