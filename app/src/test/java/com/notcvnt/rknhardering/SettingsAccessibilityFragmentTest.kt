package com.notcvnt.rknhardering

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.edit
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.chip.Chip
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class SettingsAccessibilityFragmentTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        AppUiSettings.prefs(context).edit().clear().commit()
        resetLauncherAliases()
        LauncherIconManager.setComponentEnabledSettingForTests = null
    }

    @After
    fun tearDown() {
        LauncherIconManager.setComponentEnabledSettingForTests = null
        resetLauncherAliases()
    }

    @Test
    fun `selecting red green applies deuteranopia launcher icon`() {
        val scenario = accessibilityFragment()

        scenario.root.findViewById<Chip>(R.id.chipColorVisionRedGreen).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(LauncherIconVariant.DEUTERANOPIA, LauncherIconManager.current(context))
        assertEquals(
            scenario.activity.getString(R.string.settings_color_vision_icon_changed_warning),
            latestSnackbarText(scenario.activity.findViewById(android.R.id.content)),
        )
    }

    @Test
    fun `ten easter egg taps unlock protanopia sub group`() {
        val scenario = accessibilityFragment()
        scenario.root.findViewById<Chip>(R.id.chipColorVisionRedGreen).performClick()
        val tapZone = scenario.root.findViewById<View>(R.id.easterEggTapZone)

        repeat(10) { tapZone.performClick() }
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(
            AppUiSettings.prefs(context)
                .getBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, false),
        )
        assertEquals(View.VISIBLE, scenario.root.findViewById<View>(R.id.redGreenSubGroupContainer).visibility)
    }

    @Test
    fun `fewer than ten easter egg taps keep protanopia locked`() {
        val scenario = accessibilityFragment()
        val tapZone = scenario.root.findViewById<View>(R.id.easterEggTapZone)

        repeat(9) { tapZone.performClick() }

        assertFalse(
            AppUiSettings.prefs(context)
                .getBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, false),
        )
        assertEquals(View.GONE, scenario.root.findViewById<View>(R.id.redGreenSubGroupContainer).visibility)
    }

    @Test
    fun `selecting protanopia sub variant applies protanopia launcher icon`() {
        AppUiSettings.prefs(context).edit {
            putString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.RED_GREEN.prefValue)
            putBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, true)
            putString(SettingsPrefs.PREF_RED_GREEN_ICON_VARIANT, LauncherIconVariant.DEUTERANOPIA.prefValue)
        }
        val scenario = accessibilityFragment()

        scenario.root.findViewById<Chip>(R.id.chipRedGreenProtanopia).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(LauncherIconVariant.PROTANOPIA, LauncherIconManager.current(context))
    }

    @Test
    fun `switching from red green to achromatopsia hides sub group and applies monochrome icon`() {
        AppUiSettings.prefs(context).edit {
            putString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.RED_GREEN.prefValue)
            putBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, true)
        }
        val scenario = accessibilityFragment()

        scenario.root.findViewById<Chip>(R.id.chipColorVisionAchromatopsia).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(View.GONE, scenario.root.findViewById<View>(R.id.redGreenSubGroupContainer).visibility)
        assertEquals(LauncherIconVariant.MONOCHROME, LauncherIconManager.current(context))
    }

    @Test
    fun `changing CVD mode when classic icon style is set does not change launcher icon`() {
        AppUiSettings.prefs(context).edit {
            putString(SettingsPrefs.PREF_ICON_STYLE, "classic")
        }
        LauncherIconManager.apply(context, LauncherIconVariant.CLASSIC)

        val scenario = accessibilityFragment()
        scenario.root.findViewById<Chip>(R.id.chipColorVisionRedGreen).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(LauncherIconVariant.CLASSIC, LauncherIconManager.current(context))
    }

    private fun accessibilityFragment(): AccessibilityScenario {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsAccessibilityFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsAccessibilityFragment
        return AccessibilityScenario(activity, fragment.requireView())
    }

    private fun latestSnackbarText(root: View): String {
        return findSnackbarText(root)?.text?.toString().orEmpty()
    }

    private fun findSnackbarText(view: View): TextView? {
        if (view.id == com.google.android.material.R.id.snackbar_text) {
            return view as TextView
        }
        if (view is ViewGroup) {
            for (index in 0 until view.childCount) {
                findSnackbarText(view.getChildAt(index))?.let { return it }
            }
        }
        return null
    }

    private fun resetLauncherAliases() {
        LauncherIconVariant.entries.forEach { variant ->
            context.packageManager.setComponentEnabledSetting(
                ComponentName(context.packageName, variant.aliasClass),
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                PackageManager.DONT_KILL_APP,
            )
        }
    }

    private data class AccessibilityScenario(
        val activity: SettingsActivity,
        val root: View,
    )
}
