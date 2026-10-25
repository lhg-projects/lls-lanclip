package com.lhg.lanclip

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper

/** mDNS：注册自己（TXT 带 pt=android 让桌面端走 HTTP 路由）+ 发现对端。 */
class NsdHelper(private val ctx: Context) {
    private val nsd = ctx.getSystemService(Context.NSD_SERVICE) as NsdManager
    private var regListener: NsdManager.RegistrationListener? = null
    private var discListener: NsdManager.DiscoveryListener? = null

    val peers = LinkedHashMap<String, Peer>() // id -> peer
    var onChanged: (() -> Unit)? = null

    private val main = Handler(Looper.getMainLooper())

    fun register(port: Int) {
        val info = NsdServiceInfo().apply {
            serviceName = "${Store.deviceName(ctx)}-${Store.deviceId(ctx).take(6)}"
            serviceType = "_lanclip._tcp."
            setPort(port)
            setAttribute("id", Store.deviceId(ctx))
            setAttribute("pt", "android")
            setAttribute("ver", "0.5.0")
        }
        val l = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(si: NsdServiceInfo) {}
            override fun onRegistrationFailed(si: NsdServiceInfo, e: Int) {}
            override fun onServiceUnregistered(si: NsdServiceInfo) {}
            override fun onUnregistrationFailed(si: NsdServiceInfo, e: Int) {}
        }
        regListener = l
        nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, l)
    }

    fun unregister() {
        regListener?.let { try { nsd.unregisterService(it) } catch (_: Exception) {} }
        regListener = null
    }

    fun discover() {
        val l = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(s: String) {}
            override fun onDiscoveryStopped(s: String) {}
            override fun onStartDiscoveryFailed(s: String, e: Int) {}
            override fun onStopDiscoveryFailed(s: String, e: Int) {}
            override fun onServiceLost(si: NsdServiceInfo) {
                val id = si.attributes["id"]?.toString(Charsets.UTF_8)
                if (id != null) {
                    peers.remove(id)
                    fire()
                }
            }

            override fun onServiceFound(si: NsdServiceInfo) {
                nsd.resolveService(si, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(i: NsdServiceInfo, e: Int) {}
                    override fun onServiceResolved(i: NsdServiceInfo) {
                        val id = i.attributes["id"]?.toString(Charsets.UTF_8) ?: return
                        if (id == Store.deviceId(ctx)) return
                        val name = i.serviceName ?: "?"
                        val plat = i.attributes["pt"]?.toString(Charsets.UTF_8) ?: "?"
                        val host = i.host?.hostAddress ?: return
                        peers[id] = Peer(name, id, plat, host, i.port)
                        fire()
                    }
                })
            }
        }
        discListener = l
        nsd.discoverServices("_lanclip._tcp.", NsdManager.PROTOCOL_DNS_SD, l)
    }

    fun stopDiscover() {
        discListener?.let { try { nsd.stopServiceDiscovery(it) } catch (_: Exception) {} }
        discListener = null
    }

    /** 合并 mDNS 与手动 IP。 */
    fun allPeers(ctx: Context): List<Peer> {
        val out = LinkedHashMap(peers)
        for (addr in Store.manualPeers(ctx)) {
            val host = addr.substringBeforeLast(':')
            val port = addr.substringAfterLast(':').toIntOrNull() ?: 47717
            val id = "manual-$addr"
            out[id] = Peer(addr, id, "?", host, port)
        }
        return out.values.toList()
    }

    private fun fire() = main.post { onChanged?.let { it() } }
}
