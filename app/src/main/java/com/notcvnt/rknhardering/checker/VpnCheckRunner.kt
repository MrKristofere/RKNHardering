package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.CheckResult

object VpnCheckRunner {

    suspend fun run(context: Context): CheckResult {
        val geoIp = GeoIpChecker.check()
        val directSigns = DirectSignsChecker.check(context)
        val indirectSigns = IndirectSignsChecker.check(context)

        val verdict = VerdictEngine.evaluate(
            geoIpDetected = geoIp.detected,
            directDetected = directSigns.detected,
            indirectDetected = indirectSigns.detected
        )

        return CheckResult(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            verdict = verdict
        )
    }
}
