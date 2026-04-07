package com.notcvnt.rknhardering.model

data class Finding(val description: String, val detected: Boolean)

data class CategoryResult(
    val name: String,
    val detected: Boolean,
    val findings: List<Finding>
)

enum class Verdict {
    NOT_DETECTED,
    NEEDS_REVIEW,
    DETECTED
}

data class CheckResult(
    val geoIp: CategoryResult,
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val verdict: Verdict
)
