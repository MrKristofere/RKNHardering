package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object GeoIpChecker {

    private const val API_URL =
        "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,proxy,hosting,query"

    suspend fun check(): CategoryResult = withContext(Dispatchers.IO) {
        try {
            val json = fetchJson()
            if (json.optString("status") != "success") {
                return@withContext errorResult("ip-api вернул ошибку")
            }
            evaluate(json)
        } catch (e: Exception) {
            errorResult("Не удалось получить данные GeoIP: ${e.message}")
        }
    }

    private fun fetchJson(): JSONObject {
        val connection = URL(API_URL).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        try {
            val body = connection.inputStream.bufferedReader().readText()
            return JSONObject(body)
        } finally {
            connection.disconnect()
        }
    }

    private fun evaluate(json: JSONObject): CategoryResult {
        val findings = mutableListOf<Finding>()
        val ip = json.optString("query", "N/A")
        val country = json.optString("country", "N/A")
        val countryCode = json.optString("countryCode", "")
        val isp = json.optString("isp", "N/A")
        val org = json.optString("org", "N/A")
        val asn = json.optString("as", "N/A")
        val isProxy = json.optBoolean("proxy", false)
        val isHosting = json.optBoolean("hosting", false)

        findings.add(Finding("IP: $ip", false))
        findings.add(Finding("Страна: $country ($countryCode)", false))
        findings.add(Finding("ISP: $isp", false))
        findings.add(Finding("Организация: $org", false))
        findings.add(Finding("ASN: $asn", false))

        val foreignIp = countryCode.isNotEmpty() && countryCode != "RU"
        findings.add(
            Finding(
                "IP вне России: ${if (foreignIp) "да ($countryCode)" else "нет"}",
                foreignIp
            )
        )

        findings.add(
            Finding(
                "IP принадлежит хостинг-провайдеру: ${if (isHosting) "да" else "нет"}",
                isHosting
            )
        )

        findings.add(
            Finding(
                "IP в базе известных прокси/VPN: ${if (isProxy) "да" else "нет"}",
                isProxy
            )
        )

        val detected = foreignIp || isHosting || isProxy
        return CategoryResult(
            name = "GeoIP",
            detected = detected,
            findings = findings
        )
    }

    private fun errorResult(message: String): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding(message, false))
        )
    }
}
