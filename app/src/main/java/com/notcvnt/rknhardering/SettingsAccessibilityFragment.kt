package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.core.content.edit
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import com.google.android.material.chip.ChipGroup
import com.google.android.material.snackbar.Snackbar

internal class SettingsAccessibilityFragment : Fragment(R.layout.fragment_settings_accessibility) {

    private lateinit var prefs: SharedPreferences
    private lateinit var chipGroupColorVision: ChipGroup
    private lateinit var chipGroupRedGreenIcon: ChipGroup
    private var easterEggTapCount = 0

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        chipGroupColorVision = view.findViewById(R.id.chipGroupColorVision)
        chipGroupRedGreenIcon = view.findViewById(R.id.chipGroupRedGreenIcon)
        loadSettings(view)
        setupListeners(view)
    }

    private fun loadSettings(root: View) {
        val mode = currentMode()
        chipGroupColorVision.check(chipIdForMode(mode))
        chipGroupRedGreenIcon.check(chipIdForRedGreenSubVariant(redGreenSubVariantFromPrefs()))
        renderPreview(root, mode)
        refreshRedGreenSubGroup(root, mode)
    }

    private fun setupListeners(root: View) {
        chipGroupColorVision.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val mode = modeForChipId(checkedIds.first())
            prefs.edit { putString(SettingsPrefs.PREF_COLOR_VISION_MODE, mode.prefValue) }
            renderPreview(root, mode)
            refreshRedGreenSubGroup(root, mode)
            applyLauncherIcon(root, mode)
        }

        chipGroupRedGreenIcon.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val variant = when (checkedIds.first()) {
                R.id.chipRedGreenProtanopia -> LauncherIconVariant.PROTANOPIA
                else -> LauncherIconVariant.DEUTERANOPIA
            }
            prefs.edit { putString(SettingsPrefs.PREF_RED_GREEN_ICON_VARIANT, variant.prefValue) }
            applyLauncherIcon(root, currentMode())
        }

        root.findViewById<View>(R.id.easterEggTapZone).setOnClickListener {
            if (prefs.getBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, false)) {
                return@setOnClickListener
            }
            easterEggTapCount++
            if (easterEggTapCount >= EASTER_EGG_TAP_TARGET) {
                prefs.edit {
                    putBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, true)
                    putString(SettingsPrefs.PREF_RED_GREEN_ICON_VARIANT, LauncherIconVariant.DEUTERANOPIA.prefValue)
                }
                Snackbar.make(root, R.string.settings_easter_egg_protanopia_unlocked, Snackbar.LENGTH_LONG).show()
                refreshRedGreenSubGroup(root, currentMode())
            }
        }
    }

    private fun currentMode(): ColorVisionMode {
        return ColorVisionMode.fromPref(
            prefs.getString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.OFF.prefValue),
        )
    }

    private fun renderPreview(root: View, mode: ColorVisionMode) {
        renderPreviewStatus(
            root,
            StatusSemantic.CLEAN,
            R.id.previewStatusCleanRow,
            R.id.previewStatusCleanIndicator,
            R.id.previewStatusCleanText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.REVIEW,
            R.id.previewStatusReviewRow,
            R.id.previewStatusReviewIndicator,
            R.id.previewStatusReviewText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.DETECTED,
            R.id.previewStatusDetectedRow,
            R.id.previewStatusDetectedIndicator,
            R.id.previewStatusDetectedText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.ERROR,
            R.id.previewStatusErrorRow,
            R.id.previewStatusErrorIndicator,
            R.id.previewStatusErrorText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.NEUTRAL,
            R.id.previewStatusNeutralRow,
            R.id.previewStatusNeutralIndicator,
            R.id.previewStatusNeutralText,
            mode,
        )
    }

    private fun renderPreviewStatus(
        root: View,
        status: StatusSemantic,
        rowId: Int,
        indicatorId: Int,
        textId: Int,
        mode: ColorVisionMode,
    ) {
        val visual = StatusVisualResolver.resolve(requireContext(), status, mode)
        val label = getString(visual.labelRes)
        root.findViewById<View>(indicatorId).background =
            StatusVisualResolver.indicatorDrawable(requireContext(), status, mode)
        root.findViewById<TextView>(textId).apply {
            text = label
            setTextColor(visual.accentColor)
        }
        root.findViewById<View>(rowId).contentDescription =
            getString(R.string.settings_accessibility_status_preview_content, label)
    }

    private fun refreshRedGreenSubGroup(root: View, mode: ColorVisionMode) {
        val unlocked = prefs.getBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, false)
        root.findViewById<View>(R.id.redGreenSubGroupContainer).isVisible =
            mode == ColorVisionMode.RED_GREEN && unlocked
    }

    private fun applyLauncherIcon(root: View, mode: ColorVisionMode) {
        val iconStyleClassic = prefs.getString(SettingsPrefs.PREF_ICON_STYLE, "new") == "classic"
        val target = LauncherIconVariant.resolve(iconStyleClassic, mode, redGreenSubVariantFromPrefs())
        val message = if (LauncherIconManager.apply(requireContext(), target)) {
            R.string.settings_color_vision_icon_changed_warning
        } else {
            R.string.settings_color_vision_icon_change_failed
        }
        Snackbar.make(root, message, Snackbar.LENGTH_LONG).show()
    }

    private fun redGreenSubVariantFromPrefs(): LauncherIconVariant {
        val unlocked = prefs.getBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, false)
        if (!unlocked) return LauncherIconVariant.DEUTERANOPIA
        return when (prefs.getString(SettingsPrefs.PREF_RED_GREEN_ICON_VARIANT, LauncherIconVariant.DEUTERANOPIA.prefValue)) {
            LauncherIconVariant.PROTANOPIA.prefValue -> LauncherIconVariant.PROTANOPIA
            else -> LauncherIconVariant.DEUTERANOPIA
        }
    }

    private fun chipIdForMode(mode: ColorVisionMode): Int {
        return when (mode) {
            ColorVisionMode.OFF -> R.id.chipColorVisionOff
            ColorVisionMode.RED_GREEN -> R.id.chipColorVisionRedGreen
            ColorVisionMode.BLUE_YELLOW -> R.id.chipColorVisionBlueYellow
            ColorVisionMode.ACHROMATOPSIA -> R.id.chipColorVisionAchromatopsia
        }
    }

    private fun modeForChipId(chipId: Int): ColorVisionMode {
        return when (chipId) {
            R.id.chipColorVisionRedGreen -> ColorVisionMode.RED_GREEN
            R.id.chipColorVisionBlueYellow -> ColorVisionMode.BLUE_YELLOW
            R.id.chipColorVisionAchromatopsia -> ColorVisionMode.ACHROMATOPSIA
            else -> ColorVisionMode.OFF
        }
    }

    private fun chipIdForRedGreenSubVariant(variant: LauncherIconVariant): Int {
        return when (variant) {
            LauncherIconVariant.PROTANOPIA -> R.id.chipRedGreenProtanopia
            else -> R.id.chipRedGreenDeuteranopia
        }
    }

    private companion object {
        const val EASTER_EGG_TAP_TARGET = 10
    }
}
