package com.lhg.lanclip

import android.app.Service
import android.content.Intent
import android.database.ContentObserver
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.provider.MediaStore

/**
 * 前台常驻服务：HTTP 服务端（接收）+ mDNS 注册/发现 + 截图监听（发送）。
 * 手机系统限制：后台无法读剪贴板，所以"手机→电脑"的文本靠 App 内一键发送
 * 或系统分享菜单；截图（ContentObserver）不受此限，全自动推送。
 */
class LanclipService : Service() {

    companion object {
        const val PORT = 47717
        @Volatile var running = false
        @Volatile var nsd: NsdHelper? = null
    }

    private var server: LanServer? = null
    private var shotObs: ContentObserver? = null
    private var client: LanClient? = null
    private var lastShotTs = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        NanoCtx.app = applicationContext
        val key = Store.groupKey(this) ?: run {
            stopSelf(); return
        }
        running = true
        client = LanClient(key)

        startForegroundCompat()
        startServer(key)
        startNsd()
        startShotObserver()
        Store.appendLog(this, "服务已启动（端口 $PORT）")
    }

    private fun startForegroundCompat() {
        val pi = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            android.app.PendingIntent.FLAG_IMMUTABLE,
        )
        val ch = android.app.NotificationChannel("svc", "同步服务", android.app.NotificationManager.IMPORTANCE_LOW)
        (getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager).createNotificationChannel(ch)
        val n = android.app.Notification.Builder(this, "svc")
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("LanClip 同步中")
            .setContentText("接收端口 $PORT · 截图自动推送")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(1, n)
        }
    }

    private fun startServer(key: ByteArray) {
        val srv = LanServer(
            PORT, key,
            onText = { text, from ->
                Receiver.saveTextToClipboard(applicationContext, text)
                Store.appendLog(this, "收到文本（已进剪贴板）: ${text.take(40)}")
                notifyReceived(this, "LanClip 收到文本", text.take(60))
            },
            onImage = { png, _ ->
                val uri = Receiver.saveImage(applicationContext, png)
                Store.appendLog(this, "收到图片 ${png.size / 1024}KB → 相册 Pictures/lanclip")
                notifyReceived(
                    this, "LanClip 收到截图",
                    "已存入相册 lanclip 相册（${png.size / 1024}KB），点击查看",
                    Intent(Intent.ACTION_VIEW).setDataAndType(uri, "image/png"),
                )
            },
            onFile = { name, content ->
                val f = Receiver.saveDownload(applicationContext, name, content)
                Store.appendLog(this, "收到文件 $name (${content.size / 1024}KB) → Download/lanclip")
                notifyReceived(this, "LanClip 收到文件", "$name 已存入 Download/lanclip")
            },
        )
        try {
            srv.start()
            server = srv
        } catch (e: Exception) {
            Store.appendLog(this, "HTTP 服务启动失败: ${e.message}")
        }
    }

    private fun startNsd() {
        val n = NsdHelper(this)
        n.register(PORT)
        n.discover()
        n.onChanged = { /* UI 通过 Main.Refresh.tick 拉取 */ }
        nsd = n
    }

    /** 截图观察：MediaStore 里 Pictures/Screenshots 新增 → 推给全部对端。 */
    private fun startShotObserver() {
        lastShotTs = System.currentTimeMillis() / 1000
        val obs = object : ContentObserver(null) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                handleNewScreenshots()
            }
        }
        contentResolver.registerContentObserver(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, true, obs)
        shotObs = obs
    }

    private fun handleNewScreenshots() {
        val key = Store.groupKey(this) ?: return
        val cl = client ?: return
        val proj = arrayOf(MediaStore.Images.Media._ID, MediaStore.Images.Media.DATE_ADDED, MediaStore.Images.Media.DISPLAY_NAME)
        val sel = "${MediaStore.Images.Media.RELATIVE_PATH} LIKE ? AND ${MediaStore.Images.Media.DATE_ADDED} > ?"
        Thread {
            try {
                contentResolver.query(
                    MediaStore.Images.Media.EXTERNAL_CONTENT_URI, proj,
                    sel, arrayOf("Pictures/Screenshots%", lastShotTs.toString()), null,
                )?.use { c ->
                    val idxId = c.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
                    val idxTs = c.getColumnIndexOrThrow(MediaStore.Images.Media.DATE_ADDED)
                    val idxName = c.getColumnIndexOrThrow(MediaStore.Images.Media.DISPLAY_NAME)
                    while (c.moveToNext()) {
                        val ts = c.getLong(idxTs)
                        if (ts <= lastShotTs) continue
                        lastShotTs = ts
                        val id = c.getLong(idxId)
                        val name = c.getString(idxName) ?: "screenshot.png"
                        val uri = Uri.withAppendedPath(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, id.toString())
                        val png = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: continue
                        val targets = nsd?.allPeers(this) ?: emptyList()
                        var sent = 0
                        for (p in targets) {
                            try {
                                cl.sendImage(p, png, name); sent++
                            } catch (e: Exception) {
                                Store.appendLog(this, "截图→${p.name} 失败: ${e.message}")
                            }
                        }
                        if (sent > 0) Store.appendLog(this, "截图 $name → $sent 台设备")
                    }
                }
            } catch (_: Exception) {
            }
        }.start()
    }

    override fun onDestroy() {
        running = false
        shotObs?.let { contentResolver.unregisterContentObserver(it) }
        server?.stop()
        nsd?.unregister(); nsd?.stopDiscover()
        Store.appendLog(this, "服务已停止")
        super.onDestroy()
    }
}
