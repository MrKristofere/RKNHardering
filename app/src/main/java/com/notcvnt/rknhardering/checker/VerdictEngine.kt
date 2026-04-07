package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.Verdict

object VerdictEngine {

    /**
     * Table 2 (Section 9) decision matrix:
     *
     * GeoIP | Direct | Indirect | Verdict
     * ------|--------|----------|--------
     *   -   |   -    |    -     | NOT_DETECTED
     *   -   |   +    |    -     | NOT_DETECTED
     *   -   |   -    |    +     | NOT_DETECTED
     *   +   |   -    |    -     | NEEDS_REVIEW
     *   -   |   +    |    +     | NEEDS_REVIEW
     *   +   |   +    |    -     | DETECTED
     *   +   |   -    |    +     | DETECTED
     *   +   |   +    |    +     | DETECTED
     */
    fun evaluate(geoIpDetected: Boolean, directDetected: Boolean, indirectDetected: Boolean): Verdict {
        return when {
            geoIpDetected && (directDetected || indirectDetected) -> Verdict.DETECTED
            geoIpDetected -> Verdict.NEEDS_REVIEW
            directDetected && indirectDetected -> Verdict.NEEDS_REVIEW
            else -> Verdict.NOT_DETECTED
        }
    }
}
