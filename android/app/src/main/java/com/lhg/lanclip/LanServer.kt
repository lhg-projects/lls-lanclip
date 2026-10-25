package com.lhg.lanclip

import android.content.Intent
import fi.iki.elonen.NanoHTTPD
import org.json.JSONObject

/**
 * 手机上的 HTTP 面（端口 47717，与 mDNS 注册一致）：
 * 桌面端 / 其他安卓端用它把文本/截图/文件推过来。
 * 鉴权与桌面端一致：LANCLIP HMAC（回环豁免不需要——手机没有回环调用方）。
 */
class LanServer(
    private val port: Int,
    private val key: ByteArray,
    private val onText: (String, String) -> Unit,      // (text, from)
    private val onImage: (ByteArray, String) -> Unit,  // (png, name)
    private val onFile: (String, ByteArray) -> Unit,   // (name, content)
) : NanoHTTPD(port) {

    override fun serve(session: IHTTPSession): Response {
        val path = session.uri
        try {
            if (!verify(session, path)) {
                return newFixedLengthResponse(Response.Status.UNAUTHORIZED, "application/json", """{"error":"unauthorized"}""")
            }
            when (path) {
                "/api/ping" -> {
                    val o = JSONObject().put("app", "lanclip").put("platform", "android")
                    return newFixedLengthResponse(Response.Status.OK, "application/json", o.toString())
                }
                "/api/peers" -> {
                    // 手机不维护对端列表给外人；返回自身信息即可满足探活
                    val o = JSONObject()
                        .put("DeviceName", Store.deviceName(NanoCtx.app))
                        .put("DeviceID", Store.deviceId(NanoCtx.app))
                        .put("Platform", "android")
                        .put("Addr", ":$port")
                    return newFixedLengthResponse(Response.Status.OK, "application/json", "[$o]")
                }
                "/api/send-text" -> {
                    val body = readBody(session)
                    val o = JSONObject(String(body))
                    val text = o.optString("text")
                    if (text.isEmpty()) return bad("bad request")
                    onText(text, session.headers["remote-addr"] ?: "?")
                    return okSent()
                }
                "/api/shot" -> {
                    val body = readBody(session, limit = 40L * 1024 * 1024)
                    val o = JSONObject(String(body))
                    val b64 = o.optString("png_base64")
                    if (b64.isEmpty()) return bad("bad png_base64")
                    val png = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                    onImage(png, o.optString("name", "clipboard.png"))
                    return okSent()
                }
                "/api/send-file" -> {
                    val (name, content) = readMultipart(session)
                    if (content.isEmpty()) return bad("missing file")
                    onFile(name ?: "file", content)
                    return okSent()
                }
                else -> return newFixedLengthResponse(Response.Status.NOT_FOUND, "application/json", """{"error":"not found"}""")
            }
        } catch (e: Exception) {
            return bad(e.message ?: "error")
        }
    }

    private fun okSent() = newFixedLengthResponse(Response.Status.OK, "application/json", """{"sent":1}""")
    private fun bad(msg: String) = newFixedLengthResponse(Response.Status.BAD_REQUEST, "application/json", """{"error":"$msg"}""")

    private fun verify(session: IHTTPSession, path: String): Boolean {
        val ts = session.headers["x-lanclip-ts"] ?: return false
        val tsL = ts.toLongOrNull() ?: return false
        val now = System.currentTimeMillis()
        if (kotlin.math.abs(now - tsL) > 2 * 60 * 1000) return false
        val body = if (session.method == Method.POST) readBody(session) else ByteArray(0)
        val method = when (session.method) {
            Method.GET -> "GET"
            Method.POST -> "POST"
            else -> return false
        }
        val (_, want) = Crypto.signHeaders(key, method, path, body)
        val got = session.headers["authorization"] ?: return false
        return want == got
    }

    private val bodyCache = HashMap<Any, ByteArray>()

    /** NanoHTTPD 的 POST 必须走 parseBody 才能安全拿到原始体；按 session 缓存。 */
    private fun readBody(session: IHTTPSession, limit: Long = 128L * 1024 * 1024): ByteArray {
        bodyCache[session]?.let { return it }
        val files = HashMap<String, String>()
        session.parseBody(files) // consumes the stream; body bytes end up in "postData" for non-multipart
        val b = when {
            session.headers["content-type"]?.contains("multipart/form-data") == true ->
                session.inputStream.readBytes() // multipart parsed below from raw; parseBody leaves remainder
            else -> (files["postData"] ?: "").toByteArray()
        }
        check(b.size <= limit) { "body too large" }
        bodyCache[session] = b
        return b
    }

    /** 极简 multipart 解析：取第一个 filename 的文件字段。 */
    private fun readMultipart(session: IHTTPSession): Pair<String?, ByteArray> {
        val body = readBody(session, limit = 128L * 1024 * 1024)
        val ct = session.headers["content-type"] ?: ""
        val boundary = Regex("boundary=([^;]+)").find(ct)?.groupValues?.get(1)?.trim('"') ?: return null to body
        val delim = "--$boundary".toByteArray()
        var i = indexOf(body, delim, 0)
        if (i < 0) return null to body
        while (true) {
            val partStart = i + delim.size
            // skip trailing -- of final boundary
            if (partStart + 1 < body.size && body[partStart] == '-'.code.toByte() && body[partStart + 1] == '-'.code.toByte()) {
                return null to ByteArray(0)
            }
            // headers end at \r\n\r\n
            val hdrEnd = indexOf(body, "\r\n\r\n".toByteArray(), partStart)
            if (hdrEnd < 0) return null to ByteArray(0)
            val headers = String(body, partStart, hdrEnd - partStart, Charsets.UTF_8)
            val next = indexOf(body, delim, hdrEnd + 4)
            val contentEnd = if (next < 0) body.size else next - 2 // strip \r\n before boundary
            val content = body.copyOfRange(hdrEnd + 4, contentEnd)
            if (headers.contains("filename=")) {
                val name = Regex("filename=\"([^\"]*)\"").find(headers)?.groupValues?.get(1)
                return name to content
            }
            if (next < 0) return null to ByteArray(0)
            i = next
        }
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray, from: Int): Int {
        if (needle.isEmpty()) return from
        outer@ for (i in from..hay.size - needle.size) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}

/** NanoHTTPD 回调里拿 Context 的通道（Service 启动时注入）。 */
object NanoCtx {
    @Volatile lateinit var app: android.content.Context
}

fun notifyReceived(ctx: android.content.Context, title: String, text: String, intent: Intent? = null) {
    val nm = ctx.getSystemService(android.content.Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
    val ch = android.app.NotificationChannel("recv", "收到内容", android.app.NotificationManager.IMPORTANCE_DEFAULT)
    nm.createNotificationChannel(ch)
    val b = android.app.Notification.Builder(ctx, "recv")
        .setSmallIcon(android.R.drawable.stat_sys_download_done)
        .setContentTitle(title)
        .setContentText(text)
        .setAutoCancel(true)
    intent?.let { pi ->
        b.setContentIntent(android.app.PendingIntent.getActivity(ctx, 0, pi, android.app.PendingIntent.FLAG_IMMUTABLE))
    }
    nm.notify(System.currentTimeMillis().toInt() and 0xffff, b.build())
}
