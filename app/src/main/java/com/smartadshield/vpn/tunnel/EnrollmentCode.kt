package com.smartadshield.vpn.tunnel

import org.json.JSONObject
import java.util.Base64

/**
 * `SHIELD1:<base64(json)>` — produced by the Oracle stack output `enrollment_code`
 * (or by server/install.sh). Contains the API URL, the enrollment token and the
 * SHA-256 pin of the API certificate. It is a credential: stored encrypted only.
 */
object EnrollmentCode {
    const val PREFIX = "SHIELD1:"

    fun parse(raw: String): Result<Enrollment> = runCatching {
        val compact = raw.filterNot { it.isWhitespace() }
        require(compact.startsWith(PREFIX)) { "الرمز يجب أن يبدأ بـ SHIELD1:" }
        val b64 = compact.removePrefix(PREFIX)
        val bytes = try {
            Base64.getDecoder().decode(b64)
        } catch (_: IllegalArgumentException) {
            Base64.getUrlDecoder().decode(b64)
        }
        val o = JSONObject(String(bytes, Charsets.UTF_8))
        require(o.optInt("v", 1) == 1) { "إصدار رمز غير مدعوم" }
        val api = o.getString("api").trimEnd('/')
        require(api.startsWith("https://")) { "عنوان API يجب أن يكون https" }
        val tok = o.getString("tok")
        require(tok.length >= 32) { "رمز المصادقة قصير" }
        val pin = o.getString("pin").lowercase()
        require(pin.matches(Regex("[0-9a-f]{64}"))) { "بصمة الشهادة غير صالحة" }
        Enrollment(
            apiBase = api,
            serverIp = o.optString("ip").ifBlank { api.removePrefix("https://").substringBefore(':') },
            token = tok,
            certPinSha256Hex = pin,
            name = o.optString("name").ifBlank { "Shield Gateway" },
        )
    }
}
