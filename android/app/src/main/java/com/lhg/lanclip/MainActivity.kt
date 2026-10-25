package com.lhg.lanclip

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private val io = Executors.newCachedThreadPool()
    private lateinit var tvStatus: TextView
    private lateinit var tvPin: TextView
    private lateinit var spPeers: android.widget.Spinner
    private lateinit var tvLog: TextView
    private var peers: List<Peer> = emptyList()

    private val refresh = object : Runnable {
        override fun run() {
            refreshUi()
            if (!isFinishing) android.os.Handler(mainLooper).postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        title = "LanClip"

        tvStatus = findViewById(R.id.tvStatus)
        tvPin = findViewById(R.id.tvPin)
        spPeers = findViewById(R.id.spPeers)
        tvLog = findViewById(R.id.tvLog)
        tvLog.movementMethod = ScrollingMovementMethod()

        // 首次：配对（粘贴桌面端 lanclip key-export 的 base64）
        if (Store.groupKey(this) == null) showPairDialog(firstTime = true)
        refreshHeader()

        findViewById<Button>(R.id.btnStart).setOnClickListener { startSync() }
        findViewById<Button>(R.id.btnSendClip).setOnClickListener { sendClipboardText() }
        findViewById<Button>(R.id.btnPickFile).setOnClickListener { pickAndSendFile() }
        findViewById<Button>(R.id.btnAddPeer).setOnClickListener {
            val et = findViewById<EditText>(R.id.etPeer)
            val addr = et.text.toString().trim()
            if (addr.isNotEmpty()) {
                Store.addManualPeer(this, addr)
                et.setText("")
                toast("已添加 $addr")
            }
        }
        findViewById<Button>(R.id.btnPair).setOnClickListener { showPairDialog(firstTime = false) }
        findViewById<Button>(R.id.btnLogs).setOnClickListener {
            tvLog.text = Store.log(this)
        }

        // 分享进入（其他 App 分享文本/图片/文件给 LanClip）
        handleShare(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShare(intent)
    }

    private fun handleShare(intent: Intent?) {
        val action = intent?.action
        if (action != Intent.ACTION_SEND && action != Intent.ACTION_SEND_MULTIPLE) return
        if (Store.groupKey(this) == null) {
            toast("请先配对"); showPairDialog(firstTime = true); return
        }
        startSync(quiet = true)
        val items = mutableListOf<SharedItem>()
        intent.getStringExtra(Intent.EXTRA_TEXT)?.let { items.add(SharedItem.Text(it)) }
        (intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM))?.forEach { items.add(SharedItem.Uri(it)) }
        if (items.isEmpty()) return
        pickTargetAndSend(items)
    }

    private fun startSync(quiet: Boolean = false) {
        if (Store.groupKey(this) == null) {
            showPairDialog(firstTime = true); return
        }
        if (LanclipService.running) {
            if (!quiet) toast("服务已在运行")
            return
        }
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.READ_MEDIA_IMAGES) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.READ_MEDIA_IMAGES), 2)
        }
        ContextCompat.startForegroundServiceCompat(this)
        if (!quiet) toast("同步服务已启动")
        refreshHeader()
    }

    private fun refreshHeader() {
        val key = Store.groupKey(this)
        if (key == null) {
            tvStatus.text = "状态：未配对（点「配对」导入密钥）"
            tvPin.text = "PIN: ------"
        } else {
            tvStatus.text = if (LanclipService.running) "状态：同步中（端口 ${LanclipService.PORT}）" else "状态：已配对，服务未启动"
            tvPin.text = "PIN: ${Crypto.pin(key)}（须与电脑一致）"
        }
    }

    private fun refreshUi() {
        refreshHeader()
        val nsd = LanclipService.nsd
        peers = nsd?.allPeers(this) ?: emptyList()
        val names = peers.map { it.describe() }.toMutableList()
        if (names.isEmpty()) names.add("（未发现设备，可手动加 IP）")
        val sel = spPeers.selectedItemPosition
        spPeers.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, names)
        if (sel in names.indices) spPeers.setSelection(sel)
    }

    private fun selectedPeers(): List<Peer> {
        val i = spPeers.selectedItemPosition
        return if (i in peers.indices) listOf(peers[i]) else peers
    }

    private fun sendClipboardText() {
        val key = Store.groupKey(this) ?: return showPairDialog(true)
        val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val text = cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
        if (text.isEmpty()) return toast("剪贴板为空")
        startSync(quiet = true)
        val targets = selectedPeers().ifEmpty { return toast("没有可用对端") }
        io.execute {
            val cl = LanClient(key)
            var ok = 0
            for (p in targets) {
                try { cl.sendText(p, text); ok++ } catch (e: Exception) { Store.appendLog(this, "文本→${p.name}: ${e.message}") }
            }
            runOnUiThread { toast("已发送到 $ok 台设备") }
            if (ok > 0) Store.appendLog(this, "发送文本 → $ok 台: ${text.take(30)}")
        }
    }

    private val pickFile = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.GetContent(),
    ) { uri: Uri? ->
        val key = Store.groupKey(this) ?: return@registerForActivityResult
        if (uri != null) sendUris(listOf(uri), key)
    }

    private fun pickAndSendFile() {
        if (Store.groupKey(this) == null) return showPairDialog(true)
        startSync(quiet = true)
        pickFile.launch("*/*")
    }

    private fun sendUris(uris: List<Uri>, key: ByteArray) {
        val targets = selectedPeers().ifEmpty { return toast("没有可用对端") }
        val cr = contentResolver
        io.execute {
            val cl = LanClient(key)
            for (uri in uris) {
                val name = queryName(cr, uri) ?: "file"
                val bytes = cr.openInputStream(uri)?.use { it.readBytes() } ?: continue
                var ok = 0
                for (p in targets) {
                    try { cl.sendFile(p, name, bytes); ok++ } catch (e: Exception) { Store.appendLog(this@MainActivity, "文件→${p.name}: ${e.message}") }
                }
                if (ok > 0) Store.appendLog(this@MainActivity, "发送文件 $name (${"%.1f".format(bytes.size / 1024.0)}KB) → $ok 台")
            }
            runOnUiThread { toast("发送完成") }
        }
    }

    private fun queryName(cr: android.content.ContentResolver, uri: Uri): String? {
        cr.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) return c.getString(0)
        }
        return uri.lastPathSegment
    }

    private fun pickTargetAndSend(items: List<SharedItem>) {
        val key = Store.groupKey(this) ?: return
        val names = LanclipService.nsd?.allPeers(this)?.map { it.describe() } ?: emptyList()
        if (names.isEmpty()) return toast("未发现设备")
        AlertDialog.Builder(this)
            .setTitle("发送到哪台设备？")
            .setItems(names.toTypedArray()) { _, which ->
                val target = LanclipService.nsd!!.allPeers(this)[which]
                io.execute {
                    val cl = LanClient(key)
                    for (it in items) {
                        try {
                            when (it) {
                                is SharedItem.Text -> cl.sendText(target, it.text)
                                is SharedItem.Uri -> {
                                    val name = queryName(contentResolver, it.uri) ?: "file"
                                    val bytes = contentResolver.openInputStream(it.uri)?.use { s -> s.readBytes() } ?: continue
                                    if (name.endsWith(".png") || name.endsWith(".jpg") || name.endsWith(".jpeg")) {
                                        cl.sendImage(target, bytes, name)
                                    } else {
                                        cl.sendFile(target, name, bytes)
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            Store.appendLog(this, "分享→${target.name}: ${e.message}")
                        }
                    }
                    runOnUiThread { toast("已发送到 ${target.name}") }
                }
            }
            .show()
    }

    private fun showPairDialog(firstTime: Boolean) {
        val input = EditText(this).apply { hint = "粘贴 lanclip key-export 输出的 base64" }
        AlertDialog.Builder(this)
            .setTitle(if (firstTime) "配对：粘贴密钥" else "重新配对")
            .setMessage("在已配对的电脑上运行：\nlanclip key-export\n把输出粘贴到下面。配对后两边的 PIN 必须一致。")
            .setView(input)
            .setPositiveButton("导入") { _, _ ->
                val b64 = input.text.toString().trim()
                val key = try {
                    android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                } catch (_: Exception) {
                    null
                }
                if (key == null || key.size != Crypto.KEY_LEN) {
                    toast("密钥无效"); return@setPositiveButton
                }
                Store.setGroupKey(this, key)
                toast("配对成功，PIN=${Crypto.pin(key)}")
                refreshHeader()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    override fun onResume() {
        super.onResume()
        refresh.run()
    }

    override fun onPause() {
        super.onPause()
        android.os.Handler(mainLooper).removeCallbacks(refresh)
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()

    sealed class SharedItem {
        data class Text(val text: String) : SharedItem()
        data class Uri(val uri: android.net.Uri) : SharedItem()
    }
}

/** startForegroundService 的兼容封装。 */
object ContextCompat {
    fun startForegroundServiceCompat(ctx: android.content.Context) {
        val i = Intent(ctx, LanclipService::class.java)
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            ctx.startForegroundService(i)
        } else {
            ctx.startService(i)
        }
    }
}
