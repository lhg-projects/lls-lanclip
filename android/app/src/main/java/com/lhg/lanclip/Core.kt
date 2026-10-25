package com.lhg.lanclip

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** 组密钥/设备身份 + 与桌面端一致的 HMAC 签名（internal/api/auth.go）。 */
object Crypto {
    const val KEY_LEN = 32

    fun mac(key: ByteArray, data: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(key, "HmacSHA256"))
        return m.doFinal(data)
    }

    fun hex(b: ByteArray): String = buildString { for (x in b) append("%02x".format(x)) }

    /** 常显 PIN：HMAC(groupKey,"lanclip-pin-v1") 前 4 字节 mod 1e6。 */
    fun pin(key: ByteArray): String {
        val d = mac(key, "lanclip-pin-v1".toByteArray())
        val n = ((d[0].toInt() and 0xff) shl 24) or ((d[1].toInt() and 0xff) shl 16) or
            ((d[2].toInt() and 0xff) shl 8) or (d[3].toInt() and 0xff)
        return "%06d".format(n % 1000000)
    }

    /** HTTP 面鉴权头（与 Go 端 api.Sign 完全一致）。 */
    fun signHeaders(key: ByteArray, method: String, path: String, body: ByteArray): Pair<String, String> {
        val ts = System.currentTimeMillis().toString()
        val bodyHash = hex(java.security.MessageDigest.getInstance("SHA-256").digest(body))
        val sig = hex(mac(key, "$ts\n$method\n$path\n$bodyHash".toByteArray()))
        return ts to "LANCLIP $sig"
    }
}

/** 持久化：组密钥、设备 ID/名字、手动对端列表。 */
object Store {
    private const val PREFS = "lanclip"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun groupKey(ctx: Context): ByteArray? {
        val b64 = prefs(ctx).getString("group_key", null) ?: return null
        return try {
            Base64.decode(b64, Base64.NO_WRAP).also { if (it.size != Crypto.KEY_LEN) return null }
        } catch (_: Exception) {
            null
        }
    }

    fun setGroupKey(ctx: Context, key: ByteArray) {
        prefs(ctx).edit().putString("group_key", Base64.encodeToString(key, Base64.NO_WRAP)).apply()
    }

    fun deviceId(ctx: Context): String {
        prefs(ctx).getString("device_id", null)?.let { return it }
        val b = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val id = Crypto.hex(b)
        prefs(ctx).edit().putString("device_id", id).apply()
        return id
    }

    fun deviceName(ctx: Context): String {
        prefs(ctx).getString("device_name", null)?.let { if (it.isNotBlank()) return it }
        val def = android.os.Build.MODEL ?: "android"
        prefs(ctx).edit().putString("device_name", def).apply()
        return def
    }

    fun setDeviceName(ctx: Context, name: String) =
        prefs(ctx).edit().putString("device_name", name.trim()).apply()

    fun manualPeers(ctx: Context): List<String> {
        val raw = prefs(ctx).getString("manual_peers", "") ?: ""
        return raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    fun addManualPeer(ctx: Context, addr: String) {
        val cur = manualPeers(ctx).toMutableSet()
        if (addr.isNotBlank()) cur.add(addr.trim())
        prefs(ctx).edit().putString("manual_peers", cur.joinToString(",")).apply()
    }

    fun appendLog(ctx: Context, line: String) {
        val cur = prefs(ctx).getString("log", "") ?: ""
        val stamp = java.text.SimpleDateFormat("MM-dd HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        val next = (cur.split('\n') + "[$stamp] $line").takeLast(200).joinToString("\n")
        prefs(ctx).edit().putString("log", next).apply()
    }

    fun log(ctx: Context): String = prefs(ctx).getString("log", "") ?: ""
}

data class Peer(
    val name: String,
    val id: String,
    val platform: String,
    val host: String,
    val port: Int,
) {
    val addr get() = "$host:$port"

    // Android 端只走 HTTP 面：桌面端 api 路径，安卓对端互通
    val baseUrl get() = "http://$addr"

    fun describe(): String = "$name [$platform] $addr"
}

/** 极简 JSON 事件，供 UI 刷新。 */
class EventLog(private val ctx: Context) {
    fun add(line: String) = Store.appendLog(ctx, line)
}

/** 收到的文件清单（Download/lanclip + 相册 lanclip）。 */
object Received {
    fun listDownloads(ctx: Context): List<File> {
        val dir = File(android.os.Environment.getExternalStoragePublicDirectory(
            android.os.Environment.DIRECTORY_DOWNLOADS), "lanclip")
        return dir.listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()
    }
}

// 解析桌面端 /api/peers 返回
fun parsePeers(json: String): List<Peer> {
    val arr = JSONArray(json)
    val out = mutableListOf<Peer>()
    for (i in 0 until arr.length()) {
        val o = arr.getJSONObject(i)
        val name = o.optString("DeviceName", o.optString("name", "?"))
        val id = o.optString("DeviceID", o.optString("id", ""))
        val plat = o.optString("Platform", o.optString("platform", "?"))
        val addr = o.optString("Addr", o.optString("addr", ""))
        if (addr.isBlank()) continue
        val host = addr.substringBeforeLast(':')
        val port = addr.substringAfterLast(':').toIntOrNull() ?: 47717
        out.add(Peer(name, id, plat, host, port))
    }
    return out
}

fun JSONObject.optStringOrNull(k: String): String? = optString(k).takeIf { it.isNotEmpty() }
