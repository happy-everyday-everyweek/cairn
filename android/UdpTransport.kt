package org.cairn.demo

import android.util.Log
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException

/**
 * UDP channel for cairn.
 *
 * The library produces frames; this class is the only thing that knows they
 * travel in datagrams. It keeps one socket and one receive loop, and it never
 * inspects a frame's contents, so a Bluetooth or Wi-Fi Direct transport can
 * replace it without touching the protocol.
 */
class UdpTransport(
    private val port: Int,
    private val onFrame: (ByteArray) -> Unit,
    private val onError: (String) -> Unit
) {
    private var socket: DatagramSocket? = null
    private var thread: Thread? = null
    @Volatile private var running = false

    val localPort: Int
        get() = socket?.localPort ?: -1

    fun start() {
        if (running) return
        val s = DatagramSocket(port)
        s.soTimeout = 500
        s.broadcast = true
        socket = s
        running = true

        thread = Thread {
            val buf = ByteArray(70_000)
            while (running) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    s.receive(packet)
                    onFrame(buf.copyOf(packet.length))
                } catch (timeout: SocketTimeoutException) {
                    // Nothing arrived. The loop is also the shutdown check.
                } catch (e: IOException) {
                    if (running) onError("receive failed: ${e.message}")
                    break
                }
            }
        }.also { it.name = "cairn-udp"; it.start() }
    }

    fun send(data: ByteArray, host: String, targetPort: Int) {
        val s = socket ?: return
        try {
            val address = InetAddress.getByName(host)
            s.send(DatagramPacket(data, data.size, address, targetPort))
        } catch (e: IOException) {
            onError("send failed: ${e.message}")
        }
    }

    /** Announces on the local subnet so peers can answer with their key. */
    fun broadcast(data: ByteArray, targetPort: Int) {
        val s = socket ?: return
        try {
            val all = InetAddress.getByName("255.255.255.255")
            s.send(DatagramPacket(data, data.size, all, targetPort))
        } catch (e: IOException) {
            Log.w(TAG, "broadcast failed: ${e.message}")
        }
    }

    fun stop() {
        running = false
        socket?.close()
        socket = null
        thread?.join(1000)
        thread = null
    }

    private companion object {
        const val TAG = "CairnUdp"
    }
}