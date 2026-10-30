package org.cairn.demo

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets

/**
 * Minimal demonstration activity: discovery, handshake, chat and file transfer
 * between two phones on the same network.
 *
 * This class is deliberately plain. It builds its views in code so the demo needs
 * no layout resources, and it keeps every protocol decision in the native library.
 * What is left here is button wiring and log output, which is exactly what an
 * application layer should have to write.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var logView: TextView
    private lateinit var peerField: EditText
    private lateinit var messageField: EditText
    private lateinit var statusView: TextView

    private var handle = 0L
    private var transport: UdpTransport? = null
    private val ui = Handler(Looper.getMainLooper())

    private val stateOut = IntArray(2)
    private var peerHost: String? = null
    private var peerPort = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        handle = CairnNative.nativeCreate(deviceName(), PORT)
        if (handle == 0L) {
            finish()
            return
        }

        setContentView(buildUi())
        statusView.text = getString(R.string.fingerprint, CairnNative.nativeFingerprint(handle))
        startTransport()
    }

    override fun onDestroy() {
        super.onDestroy()
        transport?.stop()
        transport = null
        if (handle != 0L) {
            CairnNative.nativeDestroy(handle)
            handle = 0L
        }
    }

    private fun buildUi(): ScrollView {
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        statusView = TextView(this).apply {
            setPadding(32, 32, 32, 16)
            textSize = 16f
        }
        logView = TextView(this).apply {
            setPadding(32, 16, 32, 16)
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
        }
        peerField = EditText(this).apply {
            hint = getString(R.string.hint_peer)
            setSingleLine()
        }
        messageField = EditText(this).apply {
            hint = getString(R.string.hint_message)
            setSingleLine()
        }

        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        buttons.addView(button(R.string.action_discover) { discover() })
        buttons.addView(button(R.string.action_connect) { connect() })
        buttons.addView(button(R.string.action_send) { sendMessage() })
        buttons.addView(button(R.string.action_file) { sendFile() })

        root.addView(statusView)
        root.addView(peerField)
        root.addView(messageField)
        root.addView(buttons)
        root.addView(logView)
        return ScrollView(this).apply { addView(root) }
    }

    private fun button(labelRes: Int, action: () -> Unit): Button =
        Button(this).apply {
            text = getString(labelRes)
            setOnClickListener { action() }
        }

    private fun print(line: String) {
        ui.post { logView.append("$line\n") }
    }

    private fun startTransport() {
        val t = UdpTransport(
            port = PORT,
            onFrame = { bytes -> onDatagram(bytes) },
            onError = { message -> print("error: $message") }
        )
        try {
            t.start()
        } catch (e: Exception) {
            print("cannot bind udp $PORT: ${e.message}")
            return
        }
        transport = t
        print("udp ${t.localPort} ready")
    }

    /** Every datagram is either a beacon or a frame; the library decides which. */
    private fun onDatagram(bytes: ByteArray) {
        val now = CairnNative.nativeTimeMs().toInt()

        val peer = runCatching { CairnNative.nativeOnBeacon(handle, bytes, now) }.getOrNull()
        if (peer != null) {
            print("beacon: ${peer[0]} ${peer[1].take(8)}...:${peer[2]}")
            peerPort = peer[2].toIntOrNull() ?: PORT
            replyWithKey(peerHost ?: "255.255.255.255", peerPort)
            return
        }

        val reply = CairnNative.nativeOnFrame(handle, bytes, now, stateOut)
        if (stateOut[0] != CairnNative.OK) {
            print("frame rejected: ${CairnNative.nativeStatusString(stateOut[0])}")
            return
        }
        if (stateOut[1] == 1 && !readyShown) {
            readyShown = true
            ui.post {
                statusView.text =
                    getString(R.string.ready, CairnNative.nativeFingerprint(handle))
            }
        }
        reply?.let { sendRaw(it) }
        CairnNative.nativeTakeMessage(handle)?.let {
            print("message: ${String(it, StandardCharsets.UTF_8)}")
        }
    }

    private var readyShown = false

    private fun replyWithKey(host: String, port: Int) {
        val key = CairnNative.nativeAnnounceKey(handle, CairnNative.nativeTimeMs().toInt())
        key?.let { transport?.send(it, host, port) }
    }

    private fun sendRaw(frame: ByteArray) {
        val host = peerHost ?: return
        transport?.send(frame, host, peerPort)
    }

    private fun discover() {
        val beacon = CairnNative.nativeBeacon(handle) ?: return
        transport?.broadcast(beacon, PORT)
        print("beacon broadcast")
    }

    private fun connect() {
        val host = peerField.text?.toString()?.trim().orEmpty()
        if (host.isEmpty()) {
            print("enter the peer address first")
            return
        }
        peerHost = host
        if (peerPort == 0) peerPort = PORT
        replyWithKey(host, peerPort)
    }

    private fun sendMessage() {
        val text = messageField.text?.toString().orEmpty()
        if (text.isEmpty()) return
        val frame = CairnNative.nativeSend(handle, text.toByteArray(StandardCharsets.UTF_8))
        if (frame == null) {
            print("channel not ready")
            return
        }
        sendRaw(frame)
        messageField.setText("")
    }

    /**
     * Streams a synthetic 64 KiB file so the transfer path is exercised without
     * needing storage permission. A real application would read from a stream.
     */
    private fun sendFile() {
        val total = 64L * 1024L
        val meta = CairnNative.nativeOfferFile(handle, total) ?: run {
            print("channel not ready")
            return
        }
        sendRaw(meta)

        val payload = ByteArray(CHUNK) { (it % 251).toByte() }
        val indexOut = IntArray(1)
        var guard = 0
        while (guard++ < 64) {
            val chunk = CairnNative.nativeNextChunk(handle, payload, indexOut) ?: break
            sendRaw(chunk)
            print("chunk ${indexOut[0]}, ${CairnNative.nativeTransferProgress(handle)} confirmed")
            if (CairnNative.nativeTransferComplete(handle)) break
        }
        val done = CairnNative.nativeTransferComplete(handle)
        print("transfer ${if (done) "complete" else "incomplete"}")
    }

    private fun deviceName(): String = android.os.Build.MODEL?.take(24) ?: "android"

    private companion object {
        const val PORT = 9400
        const val CHUNK = 16 * 1024
    }
}