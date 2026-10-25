package com.lhg.lanclip

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/** 对端 HTTP 客户端：全部带组密钥 HMAC（与桌面 Go 端 internal/api 对齐）。 */
class LanClient(private val key: ByteArray) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(4, TimeUnit.SECONDS)
        .writeTimeout(120, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .build()

    private fun call(peer: Peer, method: String, path: String, body: ByteArray?, contentType: String?): Pair<Int, String> {
        val (ts, auth) = Crypto.signHeaders(key, method, path, body ?: ByteArray(0))
        val rb = body?.let { it.toRequestBody(contentType?.toMediaType()) }
        val req = Request.Builder()
            .url(peer.baseUrl + path)
            .method(method, rb)
            .header("X-Lanclip-Ts", ts)
            .header("Authorization", auth)
            .apply { contentType?.let { h -> header("Content-Type", h) } }
            .build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string() ?: ""
            if (!resp.isSuccessful) throw IllegalStateException("HTTP ${resp.code}: $txt")
            return resp.code to txt
        }
    }

    fun ping(peer: Peer): Boolean = try {
        call(peer, "GET", "/api/ping", null, null); true
    } catch (_: Exception) {
        false
    }

    fun sendText(peer: Peer, text: String) {
        val body = JSONObject().put("text", text).toString().toByteArray()
        call(peer, "POST", "/api/send-text", body, "application/json")
    }

    /** png: 图片字节；桌面端收到直接进剪贴板。 */
    fun sendImage(peer: Peer, png: ByteArray, name: String = "screenshot.png") {
        val b64 = android.util.Base64.encodeToString(png, android.util.Base64.NO_WRAP)
        val body = JSONObject().put("png_base64", b64).put("name", name).toString().toByteArray()
        call(peer, "POST", "/api/shot", body, "application/json")
    }

    fun sendFile(peer: Peer, name: String, content: ByteArray) {
        val boundary = "lanclipBOUNDARY7351029384756"
        val head = ("--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"file\"; filename=\"$name\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n").toByteArray()
        val tail = ("\r\n--$boundary--\r\n").toByteArray()
        val body = head + content + tail
        call(peer, "POST", "/api/send-file", body, "multipart/form-data; boundary=$boundary")
    }

    fun peers(peer: Peer): List<Peer> = try {
        val (_, txt) = call(peer, "GET", "/api/peers", null, null)
        parsePeers(txt)
    } catch (_: Exception) {
        emptyList()
    }
}

/** 接收侧：把收到的内容落到系统位置。 */
object Receiver {
    fun saveTextToClipboard(ctx: Context, text: String) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("lanclip", text))
    }

    /** 存入相册 Pictures/lanclip/，返回可分享的 content URI。 */
    fun saveImage(ctx: Context, png: ByteArray): Uri? {
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, "lanclip-${System.currentTimeMillis()}.png")
            put(MediaStore.Images.Media.MIME_TYPE, "image/png")
            if (Build.VERSION.SDK_INT >= 29) {
                put(MediaStore.Images.Media.RELATIVE_PATH, "${Environment.DIRECTORY_PICTURES}/lanclip")
            }
        }
        return try {
            val uri = ctx.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values) ?: return null
            ctx.contentResolver.openOutputStream(uri)?.use { it.write(png) }
            uri
        } catch (_: Exception) {
            null
        }
    }

    /** 存入公共下载目录 Download/lanclip/。 */
    fun saveDownload(ctx: Context, name: String, content: ByteArray): File? {
        return try {
            val dir = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                "lanclip",
            )
            dir.mkdirs()
            val safe = name.replace(Regex("[/\\\\:\\*\\?\"<>|\\x00]"), "_").take(180).ifEmpty { "file" }
            var f = File(dir, safe)
            var i = 1
            while (f.exists()) {
                val base = safe.substringBeforeLast('.')
                val ext = safe.substringAfterLast('.', "")
                f = File(dir, if (ext.isEmpty()) "${base}-${i++}" else "${base}-${i++}.$ext")
            }
            f.writeBytes(content)
            f
        } catch (_: Exception) {
            null
        }
    }
}
