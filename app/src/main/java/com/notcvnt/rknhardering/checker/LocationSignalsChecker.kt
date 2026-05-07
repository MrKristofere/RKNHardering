package com.notcvnt.rknhardering.checker

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.Geocoder
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyManager
import android.telephony.gsm.GsmCellLocation
import androidx.annotation.DoNotInline
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import java.util.Locale

object LocationSignalsChecker {

    data class SimCardInfo(
        val slotIndex: Int,
        val subscriptionId: Int,
        val simMcc: String?,
        val simCountryIso: String?,
        val operatorName: String?,
        val isRoaming: Boolean?,
    )

    private data class CellCollectionResult(
        val candidates: List<CellLookupCandidate> = emptyList(),
        val rawInfoCount: Int = 0,
        val rawInfoTypes: List<String> = emptyList(),
        val candidateRadios: List<String> = emptyList(),
    )

    private data class WifiCollectionResult(
        val candidates: List<WifiLookupCandidate> = emptyList(),
        val cachedScanCandidatesCount: Int = 0,
        val freshScanCandidatesCount: Int? = null,
        val connectedCandidateAvailable: Boolean = false,
    )

    private data class BssidCollectionResult(
        val bssid: String?,
        val source: String?,
        val unavailableReason: String?,
    )

    internal data class LocationSnapshot(
        val networkMcc: String?,
        val networkCountryIso: String?,
        val networkOperatorName: String?,
        val simCards: List<SimCardInfo>,
        val cellCountryCode: String?,
        val cellLookupSummary: String?,
        val cellCandidatesCount: Int,
        val wifiAccessPointCandidatesCount: Int,
        val bssid: String?,
        val cellLookupPermissionGranted: Boolean,
        val wifiPermissionGranted: Boolean,
        val locationServicesEnabled: Boolean = true,
        val telephonyRadioAccessAvailable: Boolean = true,
        val wifiFeatureAvailable: Boolean = true,
        val nearbyWifiPermissionGranted: Boolean = true,
        val networkRequestsEnabled: Boolean = true,
        val cellRawInfoCount: Int = 0,
        val cellRawInfoTypes: List<String> = emptyList(),
        val cellCandidateRadios: List<String> = emptyList(),
        val beaconDbCellCandidatesUsedCount: Int = 0,
        val beaconDbUnsupportedCellRadios: List<String> = emptyList(),
        val beaconDbWifiCandidatesUsedCount: Int = 0,
        val wifiCachedScanCandidatesCount: Int = 0,
        val wifiFreshScanCandidatesCount: Int? = null,
        val wifiConnectedCandidateAvailable: Boolean = false,
        val bssidSource: String? = null,
        val bssidUnavailableReason: String? = null,
    )

    private const val RUSSIA_MCC = "250"
    private const val PLACEHOLDER_BSSID = "02:00:00:00:00:00"
    private const val CELL_INFO_TIMEOUT_MS = 3_000L
    private const val WIFI_SCAN_TIMEOUT_MS = 3_000L
    private const val MAX_CELL_TOWERS = 6
    private const val MAX_WIFI_ACCESS_POINTS = 12
    private const val MAX_NR_CELL_ID = 68_719_476_735L

    suspend fun check(
        context: Context,
        networkRequestsEnabled: Boolean = true,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): CategoryResult = withContext(Dispatchers.IO) {
        evaluate(collectSnapshot(context, networkRequestsEnabled, resolverConfig))
    }

    private suspend fun collectSnapshot(
        context: Context,
        networkRequestsEnabled: Boolean,
        resolverConfig: DnsResolverConfig,
    ): LocationSnapshot {
        val fineLocationGranted = hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        val nearbyWifiGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            hasPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            true
        }
        val cellLookupPermissionGranted = fineLocationGranted
        val wifiPermissionGranted = fineLocationGranted && nearbyWifiGranted
        val locationServicesEnabled = isLocationEnabled(context)
        val telephonyRadioAccessAvailable = hasTelephonyRadioAccess(context)
        val wifiFeatureAvailable = context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)

        var networkMcc: String? = null
        var networkCountryIso: String? = null
        var networkOperatorName: String? = null
        var cellCountryCode: String? = null
        var cellLookupSummary: String? = null
        var cellCandidatesCount = 0
        var wifiAccessPointCandidatesCount = 0

        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        runCatching {
            val networkOperator = tm.networkOperator
            if (!networkOperator.isNullOrEmpty() && networkOperator.length >= 3) {
                networkMcc = networkOperator.substring(0, 3)
            }
            networkCountryIso = tm.networkCountryIso?.takeIf { it.isNotEmpty() }
            networkOperatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() }
        }

        val simCards = collectSimCards(context, tm)

        val cellCollection = if (cellLookupPermissionGranted && locationServicesEnabled && telephonyRadioAccessAvailable) {
            collectCellCandidates(context, tm, simCards).also { cellCandidatesCount = it.candidates.size }
        } else {
            CellCollectionResult()
        }
        val cellCandidates = cellCollection.candidates
        val wifiCollection = if (wifiPermissionGranted && locationServicesEnabled && wifiFeatureAvailable) {
            collectWifiCandidates(context).also { wifiAccessPointCandidatesCount = it.candidates.size }
        } else {
            WifiCollectionResult()
        }
        val wifiCandidates = wifiCollection.candidates

        val beaconDbClient = BeaconDbClient(countryResolver = { lat, lon ->
            reverseGeocodeCountry(context, lat, lon)
        }, resolverConfig = resolverConfig)
        val beaconDbInput = beaconDbClient.inputDiagnostics(cellCandidates, wifiCandidates)
        val beaconDbCellCandidatesUsedCount = beaconDbInput.supportedCellCount
        val beaconDbUnsupportedCellRadios = beaconDbInput.unsupportedCellRadios
        val beaconDbWifiCandidatesUsedCount = beaconDbInput.wifiUsedCount

        if ((cellLookupPermissionGranted || wifiPermissionGranted) && networkRequestsEnabled) {
            val lookup = beaconDbClient.lookup(cellCandidates, wifiCandidates)
            cellCountryCode = lookup.countryCode
            cellLookupSummary = buildString {
                append(lookup.summary)
                if (lookup.latitude != null && lookup.longitude != null) {
                    append(" (${lookup.latitude}, ${lookup.longitude})")
                }
            }
        }

        val bssidResult = if (wifiPermissionGranted && locationServicesEnabled && wifiFeatureAvailable) {
            collectBssid(context, wifiCandidates)
        } else {
            BssidCollectionResult(bssid = null, source = null, unavailableReason = null)
        }

        return LocationSnapshot(
            networkMcc = networkMcc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simCards = simCards,
            cellCountryCode = cellCountryCode,
            cellLookupSummary = cellLookupSummary,
            cellCandidatesCount = cellCandidatesCount,
            wifiAccessPointCandidatesCount = wifiAccessPointCandidatesCount,
            bssid = bssidResult.bssid,
            cellLookupPermissionGranted = cellLookupPermissionGranted,
            wifiPermissionGranted = wifiPermissionGranted,
            locationServicesEnabled = locationServicesEnabled,
            telephonyRadioAccessAvailable = telephonyRadioAccessAvailable,
            wifiFeatureAvailable = wifiFeatureAvailable,
            nearbyWifiPermissionGranted = nearbyWifiGranted,
            networkRequestsEnabled = networkRequestsEnabled,
            cellRawInfoCount = cellCollection.rawInfoCount,
            cellRawInfoTypes = cellCollection.rawInfoTypes,
            cellCandidateRadios = cellCollection.candidateRadios,
            beaconDbCellCandidatesUsedCount = beaconDbCellCandidatesUsedCount,
            beaconDbUnsupportedCellRadios = beaconDbUnsupportedCellRadios,
            beaconDbWifiCandidatesUsedCount = beaconDbWifiCandidatesUsedCount,
            wifiCachedScanCandidatesCount = wifiCollection.cachedScanCandidatesCount,
            wifiFreshScanCandidatesCount = wifiCollection.freshScanCandidatesCount,
            wifiConnectedCandidateAvailable = wifiCollection.connectedCandidateAvailable,
            bssidSource = bssidResult.source,
            bssidUnavailableReason = bssidResult.unavailableReason,
        )
    }

    private fun hasPermission(context: Context, permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun isLocationEnabled(context: Context): Boolean {
        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return true
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                locationManager.isLocationEnabled
            } else {
                @Suppress("DEPRECATION")
                locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                    locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
            }
        }.getOrDefault(true)
    }

    private fun hasTelephonyRadioAccess(context: Context): Boolean {
        val packageManager = context.packageManager
        return packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS) ||
            packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
    }

    private fun collectSimCards(context: Context, tm: TelephonyManager): List<SimCardInfo> {
        val subscriptions = if (hasPermission(context, Manifest.permission.READ_PHONE_STATE)) {
            getActiveSubscriptions(context)
        } else {
            null
        }

        if (!subscriptions.isNullOrEmpty()) {
            return subscriptions.mapNotNull { info ->
                runCatching {
                    val subTm = tm.createForSubscriptionId(info.subscriptionId)
                    val simOperator = subTm.simOperator
                    val simMcc = if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                        simOperator.substring(0, 3)
                    } else null
                    SimCardInfo(
                        slotIndex = info.simSlotIndex,
                        subscriptionId = info.subscriptionId,
                        simMcc = simMcc,
                        simCountryIso = subTm.simCountryIso?.takeIf { it.isNotEmpty() },
                        operatorName = subTm.networkOperatorName?.takeIf { it.isNotEmpty() },
                        isRoaming = subTm.isNetworkRoaming,
                    )
                }.getOrNull()
            }
        }

        // Fallback: single-SIM device or permission denied
        return runCatching {
            val simOperator = tm.simOperator
            val simMcc = if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                simOperator.substring(0, 3)
            } else null
            listOf(
                SimCardInfo(
                    slotIndex = 0,
                    subscriptionId = -1,
                    simMcc = simMcc,
                    simCountryIso = tm.simCountryIso?.takeIf { it.isNotEmpty() },
                    operatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() },
                    isRoaming = tm.isNetworkRoaming,
                )
            )
        }.getOrElse { emptyList() }
    }

    @Suppress("MissingPermission")
    private fun getActiveSubscriptions(context: Context): List<android.telephony.SubscriptionInfo>? {
        val subscriptionManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE)
                as? android.telephony.SubscriptionManager
        return runCatching { subscriptionManager?.activeSubscriptionInfoList }.getOrNull()
    }

    private suspend fun collectCellCandidates(
        context: Context,
        tm: TelephonyManager,
        simCards: List<SimCardInfo>,
    ): CellCollectionResult {
        if (!hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)) {
            return CellCollectionResult()
        }
        val subscriptionManagers = simCards
            .mapNotNull { it.subscriptionId.takeIf { subscriptionId -> subscriptionId >= 0 } }
            .distinct()
            .mapNotNull { subscriptionId ->
                runCatching { tm.createForSubscriptionId(subscriptionId) }.getOrNull()
            }
        val managers = (listOf(tm) + subscriptionManagers).distinct()
        val cellInfo = managers.flatMap { collectCellInfo(context, it) }
        val rawInfoTypes = cellInfo
            .map(::cellInfoTypeName)
            .distinct()
            .sorted()
        val candidates = cellInfo
            .mapNotNull(::toLookupCandidate)
            .distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId, it.newRadioCellId) }
            .sortedWith(
                compareByDescending<CellLookupCandidate> { it.registered }
                    .thenByDescending { it.signalStrength ?: Int.MIN_VALUE },
            )
            .take(MAX_CELL_TOWERS)

        if (candidates.isNotEmpty()) {
            return CellCollectionResult(
                candidates = candidates,
                rawInfoCount = cellInfo.size,
                rawInfoTypes = rawInfoTypes,
                candidateRadios = summarizeCellRadios(candidates),
            )
        }

        val legacyCandidates = managers
            .mapNotNull(::legacyGsmCellCandidate)
            .distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId, it.newRadioCellId) }
            .take(MAX_CELL_TOWERS)
        return CellCollectionResult(
            candidates = legacyCandidates,
            rawInfoCount = cellInfo.size,
            rawInfoTypes = rawInfoTypes,
            candidateRadios = summarizeCellRadios(legacyCandidates),
        )
    }

    private suspend fun collectCellInfo(
        context: Context,
        tm: TelephonyManager,
    ): List<CellInfo> {
        return (requestFreshCellInfo(context, tm) + getCachedCellInfo(tm))
            .distinctBy { it.toString() }
    }

    @Suppress("MissingPermission")
    private suspend fun requestFreshCellInfo(
        context: Context,
        tm: TelephonyManager,
    ): List<CellInfo> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return emptyList()
        }

        return withTimeoutOrNull(CELL_INFO_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val completed = AtomicBoolean(false)
                val requested = runCatching {
                    tm.requestCellInfoUpdate(
                        context.mainExecutor,
                        object : TelephonyManager.CellInfoCallback() {
                            override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                                resumeOnce(continuation, completed, cellInfo.toList())
                            }

                            override fun onError(errorCode: Int, detail: Throwable?) {
                                resumeOnce(continuation, completed, emptyList())
                            }
                        },
                    )
                }.isSuccess

                continuation.invokeOnCancellation {
                    completed.set(true)
                }

                if (!requested) {
                    resumeOnce(continuation, completed, emptyList())
                }
            }
        } ?: emptyList()
    }

    @Suppress("MissingPermission")
    private fun getCachedCellInfo(tm: TelephonyManager): List<CellInfo> {
        return runCatching { tm.allCellInfo.orEmpty() }.getOrDefault(emptyList())
    }

    @Suppress("DEPRECATION", "MissingPermission")
    private fun legacyGsmCellCandidate(tm: TelephonyManager): CellLookupCandidate? {
        val operator = normalizeOperatorCode(tm.networkOperator)?.takeIf { it.length >= 4 } ?: return null
        val location = runCatching { tm.cellLocation as? GsmCellLocation }.getOrNull() ?: return null
        val areaCode = normalizeCellValue(location.lac) ?: return null
        val cellId = normalizeCellValue(location.cid) ?: return null
        return CellLookupCandidate(
            radio = "gsm",
            mcc = operator.substring(0, 3),
            mnc = operator.substring(3),
            areaCode = areaCode,
            cellId = cellId,
            registered = true,
        )
    }

    private fun toLookupCandidate(info: CellInfo): CellLookupCandidate? {
        return when (info) {
            is CellInfoGsm -> {
                val identity = info.cellIdentity
                val mcc = gsmMcc(identity) ?: return null
                val mnc = gsmMnc(identity) ?: return null
                val areaCode = normalizeCellValue(identity.lac) ?: return null
                val cellId = normalizeCellValue(identity.cid) ?: return null
                CellLookupCandidate(
                    radio = "gsm",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoLte -> {
                val identity = info.cellIdentity
                val mcc = lteMcc(identity) ?: return null
                val mnc = lteMnc(identity) ?: return null
                val areaCode = normalizeCellValue(identity.tac) ?: return null
                val cellId = normalizeCellValue(identity.ci) ?: return null
                CellLookupCandidate(
                    radio = "lte",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoWcdma -> {
                val identity = info.cellIdentity
                val mcc = wcdmaMcc(identity) ?: return null
                val mnc = wcdmaMnc(identity) ?: return null
                val areaCode = normalizeCellValue(identity.lac) ?: return null
                val cellId = normalizeCellValue(identity.cid) ?: return null
                CellLookupCandidate(
                    radio = "wcdma",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            else -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Api29Impl.nrCandidate(info)
            } else {
                null
            }
        }
    }

    private suspend fun collectWifiCandidates(context: Context): WifiCollectionResult {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val cachedCandidates = currentWifiCandidates(wifiManager)
        val refreshedCandidates = requestFreshWifiScan(context, wifiManager)
        val connectedCandidate = currentWifiConnectionCandidate(context, wifiManager)

        return WifiCollectionResult(
            candidates = mergeWifiCandidates(
                cached = cachedCandidates,
                refreshed = refreshedCandidates.orEmpty(),
                connected = connectedCandidate,
            ),
            cachedScanCandidatesCount = cachedCandidates.size,
            freshScanCandidatesCount = refreshedCandidates?.size,
            connectedCandidateAvailable = connectedCandidate != null,
        )
    }

    private fun summarizeCellRadios(candidates: List<CellLookupCandidate>): List<String> {
        return candidates
            .map { it.radio.lowercase(Locale.US) }
            .distinct()
            .sorted()
    }

    private fun cellInfoTypeName(info: CellInfo): String {
        return info.javaClass.simpleName
            .removePrefix("CellInfo")
            .takeIf { it.isNotBlank() }
            ?.lowercase(Locale.US)
            ?: info.javaClass.name
    }

    private fun collectBssid(
        context: Context,
        wifiCandidates: List<WifiLookupCandidate>,
    ): BssidCollectionResult {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = getWifiInfo(context, wifiManager)
        val normalizedBssid = normalizeMacAddress(wifiInfo?.bssid)
        if (normalizedBssid != null) {
            return BssidCollectionResult(
                bssid = normalizedBssid,
                source = "connected Wi-Fi info",
                unavailableReason = null,
            )
        }

        val singleScanCandidate = wifiCandidates.singleOrNull()
        if (singleScanCandidate != null) {
            val reason = when {
                wifiInfo == null -> "Wi-Fi info unavailable; using the only scan candidate"
                wifiInfo.bssid == PLACEHOLDER_BSSID -> "connected Wi-Fi info is redacted by Android; using the only scan candidate"
                else -> "connected Wi-Fi BSSID is unavailable; using the only scan candidate"
            }
            return BssidCollectionResult(
                bssid = singleScanCandidate.macAddress,
                source = "single Wi-Fi scan candidate",
                unavailableReason = reason,
            )
        }

        val reason = when {
            wifiInfo == null -> "Wi-Fi info unavailable"
            wifiInfo.bssid == PLACEHOLDER_BSSID -> "connected Wi-Fi info is redacted by Android"
            wifiInfo.bssid.isNullOrBlank() -> "connected Wi-Fi BSSID is empty"
            else -> "connected Wi-Fi BSSID is invalid"
        }
        return BssidCollectionResult(
            bssid = null,
            source = null,
            unavailableReason = reason,
        )
    }

    @Suppress("MissingPermission", "DEPRECATION")
    private suspend fun requestFreshWifiScan(
        context: Context,
        wifiManager: WifiManager,
    ): List<WifiLookupCandidate>? {
        val appContext = context.applicationContext
        return withTimeoutOrNull(WIFI_SCAN_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val completed = AtomicBoolean(false)
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(receiverContext: Context?, intent: Intent?) {
                        if (intent?.action != WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                            return
                        }
                        runCatching { appContext.unregisterReceiver(this) }
                        resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                    }
                }

                val registered = runCatching {
                    ContextCompat.registerReceiver(
                        appContext,
                        receiver,
                        IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
                        ContextCompat.RECEIVER_NOT_EXPORTED,
                    )
                }.isSuccess

                if (!registered) {
                    resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                    return@suspendCancellableCoroutine
                }

                continuation.invokeOnCancellation {
                    completed.set(true)
                    runCatching { appContext.unregisterReceiver(receiver) }
                }

                val started = runCatching { wifiManager.startScan() }.getOrDefault(false)
                if (!started) {
                    runCatching { appContext.unregisterReceiver(receiver) }
                    resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                }
            }
        }
    }

    @Suppress("MissingPermission")
    private fun currentWifiCandidates(wifiManager: WifiManager): List<WifiLookupCandidate> {
        return runCatching {
            wifiManager.scanResults
                ?.mapNotNull(::toWifiLookupCandidate)
                .orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun currentWifiConnectionCandidate(
        context: Context,
        wifiManager: WifiManager,
    ): WifiLookupCandidate? {
        val wifiInfo = getWifiInfo(context, wifiManager) ?: return null
        val macAddress = normalizeMacAddress(wifiInfo.bssid) ?: return null
        val ssid = normalizeSsid(wifiInfo.ssid)
        if (ssid?.endsWith("_nomap", ignoreCase = true) == true) return null
        return WifiLookupCandidate(
            macAddress = macAddress,
            frequency = wifiInfo.frequency.takeIf { it > 0 },
            signalStrength = normalizeSignalStrength(wifiInfo.rssi),
        )
    }

    internal fun mergeWifiCandidates(
        cached: List<WifiLookupCandidate>,
        refreshed: List<WifiLookupCandidate>,
        connected: WifiLookupCandidate?,
    ): List<WifiLookupCandidate> {
        return (cached + refreshed + listOfNotNull(connected))
            .groupBy { it.macAddress }
            .values
            .mapNotNull { candidates ->
                candidates.maxWithOrNull(
                    compareBy<WifiLookupCandidate> { it.signalStrength ?: Int.MIN_VALUE }
                        .thenBy { it.frequency ?: 0 },
                )
            }
            .sortedByDescending { it.signalStrength ?: Int.MIN_VALUE }
            .take(MAX_WIFI_ACCESS_POINTS)
    }

    private fun toWifiLookupCandidate(scanResult: ScanResult): WifiLookupCandidate? {
        val macAddress = normalizeMacAddress(scanResult.BSSID) ?: return null
        val ssid = normalizeSsid(scanResultSsid(scanResult)) ?: return null
        if (ssid.endsWith("_nomap", ignoreCase = true)) return null

        return WifiLookupCandidate(
            macAddress = macAddress,
            frequency = scanResult.frequency.takeIf { it > 0 },
            signalStrength = normalizeSignalStrength(scanResult.level),
        )
    }

    private fun normalizeOperatorCode(value: String?): String? {
        return value?.takeIf { it.isNotBlank() && it.all(Char::isDigit) }
    }

    private fun normalizeOperatorCode(value: Int): String? {
        return value
            .takeIf { it in 0 until Int.MAX_VALUE }
            ?.toString()
            ?.let(::normalizeOperatorCode)
    }

    private fun scanResultSsid(scanResult: ScanResult): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Api33Impl.scanResultSsid(scanResult)
        } else {
            @Suppress("DEPRECATION")
            scanResult.SSID
        }
    }

    @Suppress("DEPRECATION")
    private fun gsmMcc(identity: android.telephony.CellIdentityGsm): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.gsmMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun gsmMnc(identity: android.telephony.CellIdentityGsm): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.gsmMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    @Suppress("DEPRECATION")
    private fun lteMcc(identity: android.telephony.CellIdentityLte): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.lteMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun lteMnc(identity: android.telephony.CellIdentityLte): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.lteMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    @Suppress("DEPRECATION")
    private fun wcdmaMcc(identity: android.telephony.CellIdentityWcdma): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.wcdmaMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun wcdmaMnc(identity: android.telephony.CellIdentityWcdma): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.wcdmaMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    // Keep newer cell identity accessors isolated so older devices never resolve them.
    @RequiresApi(Build.VERSION_CODES.Q)
    private object Api29Impl {
        @DoNotInline
        fun nrCandidate(info: CellInfo): CellLookupCandidate? {
            if (info !is android.telephony.CellInfoNr) return null
            val identity = info.cellIdentity as? android.telephony.CellIdentityNr ?: return null
            val mcc = normalizeOperatorCode(identity.mccString) ?: return null
            val mnc = normalizeOperatorCode(identity.mncString) ?: return null
            val areaCode = normalizeCellValue(identity.tac) ?: return null
            val newRadioCellId = normalizeNewRadioCellValue(identity.nci) ?: return null
            return CellLookupCandidate(
                radio = "nr",
                mcc = mcc,
                mnc = mnc,
                areaCode = areaCode,
                newRadioCellId = newRadioCellId,
                registered = info.isRegistered,
                signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
            )
        }
    }

    // Keep API 28-only operator accessors isolated so pre-P devices never resolve them.
    @RequiresApi(Build.VERSION_CODES.P)
    private object Api28Impl {
        @DoNotInline
        fun gsmMcc(identity: android.telephony.CellIdentityGsm): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun gsmMnc(identity: android.telephony.CellIdentityGsm): String? {
            return normalizeOperatorCode(identity.mncString)
        }

        @DoNotInline
        fun lteMcc(identity: android.telephony.CellIdentityLte): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun lteMnc(identity: android.telephony.CellIdentityLte): String? {
            return normalizeOperatorCode(identity.mncString)
        }

        @DoNotInline
        fun wcdmaMcc(identity: android.telephony.CellIdentityWcdma): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun wcdmaMnc(identity: android.telephony.CellIdentityWcdma): String? {
            return normalizeOperatorCode(identity.mncString)
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private object Api33Impl {
        @DoNotInline
        fun scanResultSsid(scanResult: ScanResult): String? {
            return scanResult.wifiSsid
                ?.toString()
                ?.trim('"')
        }
    }

    private fun normalizeCellValue(value: Int): Long? {
        return value.toLong().takeIf { it in 0 until Int.MAX_VALUE.toLong() }
    }

    private fun normalizeNewRadioCellValue(value: Long): Long? {
        return value.takeIf { it in 0..MAX_NR_CELL_ID }
    }

    private fun normalizeSignalStrength(value: Int): Int? {
        return value.takeIf { it in -150..0 }
    }

    private fun normalizeMacAddress(value: String?): String? {
        val normalized = value?.trim()?.lowercase(Locale.US) ?: return null
        if (normalized == PLACEHOLDER_BSSID) return null
        if (!MAC_ADDRESS_REGEX.matches(normalized)) return null
        return normalized
    }

    private fun normalizeSsid(value: String?): String? {
        val normalized = value?.trim().orEmpty()
        return normalized.takeIf {
            it.isNotEmpty() && !it.equals("<unknown ssid>", ignoreCase = true)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun <T> resumeOnce(
        continuation: CancellableContinuation<T>,
        completed: AtomicBoolean,
        value: T,
    ) {
        if (!completed.compareAndSet(false, true)) {
            return
        }
        continuation.resume(value) { }
    }

    @Suppress("DEPRECATION")
    private fun reverseGeocodeCountry(context: Context, latitude: Double, longitude: Double): String? {
        return runCatching {
            if (!Geocoder.isPresent()) {
                null
            } else {
                Geocoder(context, Locale.US)
                    .getFromLocation(latitude, longitude, 1)
                    ?.firstOrNull()
                    ?.countryCode
                    ?.uppercase(Locale.US)
            }
        }.getOrNull()
    }

    @Suppress("DEPRECATION")
    private fun getBssid(context: Context): String? {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return getWifiInfo(context, wifiManager)?.bssid
    }

    @Suppress("DEPRECATION")
    private fun getWifiInfo(context: Context, wifiManager: WifiManager): WifiInfo? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val caps = network?.let { cm.getNetworkCapabilities(it) }
            val transportInfo = caps
                ?.takeIf { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
                ?.transportInfo as? WifiInfo
            transportInfo ?: wifiManager.connectionInfo
        } else {
            wifiManager.connectionInfo
        }
    }

    internal fun evaluate(snapshot: LocationSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        if (snapshot.networkMcc == null) {
            findings += Finding("PLMN: network MCC is unavailable")
        } else {
            val networkCountry = snapshot.networkCountryIso?.uppercase(Locale.US) ?: "N/A"
            val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC

            findings += Finding(
                description = "Network operator: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)",
                isInformational = true,
            )
            findings += Finding(
                description = "Network MCC: ${snapshot.networkMcc}",
                isInformational = true,
            )
            if (networkIsRussia) {
                findings += Finding("network_mcc_ru:true")
            }

            for (sim in snapshot.simCards) {
                val simCountry = sim.simCountryIso?.uppercase(Locale.US) ?: "N/A"
                val operatorPart = sim.operatorName?.let { ", $it" } ?: ""
                findings += Finding(
                    description = "SIM[${sim.slotIndex}] MCC: ${sim.simMcc ?: "N/A"} ($simCountry)$operatorPart",
                    isInformational = true,
                )
                when (sim.isRoaming) {
                    true -> findings += Finding("SIM[${sim.slotIndex}] Roaming: yes", isInformational = true)
                    false -> findings += Finding("SIM[${sim.slotIndex}] Roaming: no", isInformational = true)
                    null -> Unit
                }
            }

            if (!networkIsRussia) {
                val matchingSim = snapshot.simCards.firstOrNull { it.simMcc == snapshot.networkMcc }
                val confidence = if (matchingSim?.isRoaming == true) {
                    EvidenceConfidence.LOW
                } else {
                    EvidenceConfidence.MEDIUM
                }
                val description = "Network MCC ${snapshot.networkMcc} ($networkCountry) is not Russia"
                findings += Finding(
                    description = description,
                    needsReview = true,
                    source = EvidenceSource.LOCATION_SIGNALS,
                    confidence = confidence,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.LOCATION_SIGNALS,
                    detected = true,
                    confidence = confidence,
                    description = description,
                )
                needsReview = true
            }
        }

        if (!snapshot.locationServicesEnabled) {
            findings += Finding("Location services: disabled")
        }

        if (!snapshot.cellLookupPermissionGranted) {
            findings += Finding("Cell lookup: ACCESS_FINE_LOCATION permission is not granted")
        } else if (!snapshot.locationServicesEnabled) {
            findings += Finding("Cell lookup: system location is disabled")
        } else if (!snapshot.telephonyRadioAccessAvailable) {
            findings += Finding("Cell lookup: telephony radio access is unavailable")
        } else {
            findings += Finding("Cell lookup candidates: ${snapshot.cellCandidatesCount}")
            if (snapshot.cellCandidatesCount == 0) {
                findings += Finding("Cell lookup: base station identifiers are unavailable")
            }
        }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("Wi-Fi scan: permissions are not granted")
        } else if (!snapshot.locationServicesEnabled) {
            findings += Finding("Wi-Fi scan: system location is disabled")
        } else if (!snapshot.wifiFeatureAvailable) {
            findings += Finding("Wi-Fi scan: Wi-Fi feature is unavailable")
        } else {
            findings += Finding("Wi-Fi scan candidates: ${snapshot.wifiAccessPointCandidatesCount}")
            if (snapshot.wifiAccessPointCandidatesCount == 0) {
                findings += Finding("Wi-Fi scan: access points are unavailable")
            }
        }

        snapshot.cellCountryCode?.let { countryCode ->
            findings += Finding("Cell lookup country: $countryCode")
            if (countryCode == "RU") {
                findings += Finding("cell_country_ru:true")
                findings += Finding("location_country_ru:true")
            }
        }
        snapshot.cellLookupSummary?.let { findings += Finding(it) }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("BSSID: permission is not granted")
        } else if (!snapshot.locationServicesEnabled) {
            findings += Finding("BSSID: system location is disabled")
        } else if (!snapshot.wifiFeatureAvailable) {
            findings += Finding("BSSID: Wi-Fi feature is unavailable")
        } else if (snapshot.bssid == null || snapshot.bssid == PLACEHOLDER_BSSID) {
            findings += Finding("BSSID: unavailable")
        } else {
            findings += Finding("BSSID: ${snapshot.bssid}")
        }

        val detected = evidence.any {
            it.detected && it.confidence >= EvidenceConfidence.MEDIUM
        }

        val result = CategoryResult(
            name = "Location signals",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
        return LocationSignalsDiagnosticsRegistry.attach(
            result,
            LocationSignalsDiagnostics(
                fineLocationPermissionGranted = snapshot.cellLookupPermissionGranted,
                nearbyWifiPermissionGranted = snapshot.nearbyWifiPermissionGranted,
                locationServicesEnabled = snapshot.locationServicesEnabled,
                telephonyRadioAccessAvailable = snapshot.telephonyRadioAccessAvailable,
                wifiFeatureAvailable = snapshot.wifiFeatureAvailable,
                networkRequestsEnabled = snapshot.networkRequestsEnabled,
                cellRawInfoCount = snapshot.cellRawInfoCount,
                cellRawInfoTypes = snapshot.cellRawInfoTypes,
                cellCandidateRadios = snapshot.cellCandidateRadios,
                beaconDbCellCandidatesUsedCount = snapshot.beaconDbCellCandidatesUsedCount,
                beaconDbUnsupportedCellRadios = snapshot.beaconDbUnsupportedCellRadios,
                beaconDbWifiCandidatesUsedCount = snapshot.beaconDbWifiCandidatesUsedCount,
                wifiAccessPointCandidatesCount = snapshot.wifiAccessPointCandidatesCount,
                wifiCachedScanCandidatesCount = snapshot.wifiCachedScanCandidatesCount,
                wifiFreshScanCandidatesCount = snapshot.wifiFreshScanCandidatesCount,
                wifiConnectedCandidateAvailable = snapshot.wifiConnectedCandidateAvailable,
                bssidSource = snapshot.bssidSource,
                bssidUnavailableReason = snapshot.bssidUnavailableReason,
            ),
        )
    }

    private val MAC_ADDRESS_REGEX = Regex("^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
}
