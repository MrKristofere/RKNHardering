package com.notcvnt.rknhardering

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class LauncherIconManagerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        resetLauncherAliases()
        LauncherIconManager.setComponentEnabledSettingForTests = null
    }

    @After
    fun tearDown() {
        LauncherIconManager.setComponentEnabledSettingForTests = null
        resetLauncherAliases()
    }

    @Test
    fun `apply enables target alias and disables other aliases`() {
        assertTrue(LauncherIconManager.apply(context, LauncherIconVariant.TRITANOPIA))

        LauncherIconVariant.entries.forEach { variant ->
            val expected = if (variant == LauncherIconVariant.TRITANOPIA) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            }
            assertEquals(expected, componentState(variant))
        }
    }

    @Test
    fun `apply is idempotent for the same target`() {
        val calls = mutableListOf<Pair<ComponentName, Int>>()
        LauncherIconManager.setComponentEnabledSettingForTests = { pm, component, state ->
            calls += component to state
            pm.setComponentEnabledSetting(component, state, PackageManager.DONT_KILL_APP)
        }

        assertTrue(LauncherIconManager.apply(context, LauncherIconVariant.PROTANOPIA))
        val firstCallCount = calls.size
        assertTrue(LauncherIconManager.apply(context, LauncherIconVariant.PROTANOPIA))

        assertEquals(firstCallCount, calls.size)
    }

    @Test
    fun `current returns enabled variant`() {
        LauncherIconManager.apply(context, LauncherIconVariant.MONOCHROME)

        assertEquals(LauncherIconVariant.MONOCHROME, LauncherIconManager.current(context))
    }

    @Test
    fun `current returns original when no alias is enabled`() {
        LauncherIconVariant.entries.forEach { variant ->
            context.packageManager.setComponentEnabledSetting(
                componentName(variant),
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP,
            )
        }

        assertEquals(LauncherIconVariant.ORIGINAL, LauncherIconManager.current(context))
    }

    @Test
    fun `apply enables CLASSIC and disables all other variants`() {
        assertTrue(LauncherIconManager.apply(context, LauncherIconVariant.CLASSIC))

        LauncherIconVariant.entries.forEach { variant ->
            val expected = if (variant == LauncherIconVariant.CLASSIC) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            }
            assertEquals(expected, componentState(variant))
        }
    }

    @Test
    fun `apply returns false when package manager rejects alias toggle`() {
        LauncherIconManager.setComponentEnabledSettingForTests = { _, _, _ ->
            throw SecurityException("blocked")
        }

        assertFalse(LauncherIconManager.apply(context, LauncherIconVariant.DEUTERANOPIA))
    }

    private fun resetLauncherAliases() {
        LauncherIconVariant.entries.forEach { variant ->
            context.packageManager.setComponentEnabledSetting(
                componentName(variant),
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                PackageManager.DONT_KILL_APP,
            )
        }
    }

    private fun componentState(variant: LauncherIconVariant): Int {
        return context.packageManager.getComponentEnabledSetting(componentName(variant))
    }

    private fun componentName(variant: LauncherIconVariant): ComponentName {
        return ComponentName(context.packageName, variant.aliasClass)
    }
}
