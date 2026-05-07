package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.CategoryResult
import java.util.Collections
import java.util.WeakHashMap

data class LocationSignalsDiagnostics(
    val fineLocationPermissionGranted: Boolean,
    val nearbyWifiPermissionGranted: Boolean,
    val locationServicesEnabled: Boolean,
    val telephonyRadioAccessAvailable: Boolean,
    val wifiFeatureAvailable: Boolean,
    val networkRequestsEnabled: Boolean,
    val cellRawInfoCount: Int,
    val cellRawInfoTypes: List<String>,
    val cellCandidateRadios: List<String>,
    val beaconDbCellCandidatesUsedCount: Int,
    val beaconDbUnsupportedCellRadios: List<String>,
    val beaconDbWifiCandidatesUsedCount: Int,
    val wifiAccessPointCandidatesCount: Int,
    val wifiCachedScanCandidatesCount: Int,
    val wifiFreshScanCandidatesCount: Int?,
    val wifiConnectedCandidateAvailable: Boolean,
    val bssidSource: String?,
    val bssidUnavailableReason: String?,
)

object LocationSignalsDiagnosticsRegistry {
    private val diagnosticsByCategory =
        Collections.synchronizedMap(WeakHashMap<CategoryResult, LocationSignalsDiagnostics>())

    fun attach(category: CategoryResult, diagnostics: LocationSignalsDiagnostics): CategoryResult {
        diagnosticsByCategory[category] = diagnostics
        return category
    }

    fun find(category: CategoryResult): LocationSignalsDiagnostics? {
        return diagnosticsByCategory[category]
    }
}
