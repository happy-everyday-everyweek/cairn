package org.cairn.demo

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.method.ScrollingMovementMethod
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets

/**
 * The demo: type a code on two phones, tap Pair, then send text or a file.
 *
 * Everything protocol shaped is one native call. What is left here is a code field, a
 * log view, two worker threads (one to pair, one to pump), and a multicast lock, which
 * some devices need before they will deliver broadcast packets to an app.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var logView: TextView
    private lateinit var codeField: EditText
    private lateinit var statusView: TextView

    private var handle = 0L
    private var worker: Thread? = null
    @Volatile private var running = false

    private val ui = Handler(Looper.getMainLooper())
    private var multicastLock: WifiManager.MulticastLock? = null

    private val eventSink = object {
        @Suppress("unused")
        fun onMessage(data: ByteArray) {
            print("message: ${String(data, StandardCharsets.UTF_8)}")
        }

        @Suppress("unused")
        fun onChunk(index: Int, data: ByteArray) {
            print("chunk $index (${data.size} bytes)")
        }

        @Suppress("unused")
        fun onReady() {
            print("paired")
            ui.post { statusView.text = getString(R.string.status_ready) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
        takeMulticastLock()

        handle = Cairn.nativeOpen(deviceName(), eventSink)
        if (handle == 0L) {
            print("cannot open a node")
            return
        }
        statusView.text = getString(R.string.status_idle, Cairn.nativeFingerprint(handle))
    }

    override fun onDestroy() {
        super.onDestroy()
        running = false
        worker?.interrupt()
        worker = null
        if (handle != 0L) {
            Cairn.nativeClose(handle)
            handle = 0L
        }
        multicastLock?.release()
        multicastLock = null
    }

    private fun buildUi(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }

        statusView = TextView(this).apply { textSize = 15f }

        codeField = EditText(this).apply {
            hint = getString(R.string.hint_code)
            setSingleLine()
        }

        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        buttons.addView(button(R.string.action_pair) { startPairing() })
        buttons.addView(button(R.string.action_send) { sendText() })
        buttons.addView(button(R.string.action_file) { sendFile() })

        logView = TextView(this).apply {
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
            movementMethod = ScrollingMovementMethod()
        }

        root.addView(statusView)
        root.addView(codeField)
        root.addView(buttons)
        root.addView(logView)
        return root
    }

    private fun button(label: Int, action: () -> Unit): Button =
        Button(this).apply {
            text = getString(label)
            setOnClickListener { action() }
        }

    private fun print(line: String) {
        ui.post { logView.append("$line\n") }
    }

    private fun takeMulticastLock() {
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return
        multicastLock = wifi.createMulticastLock("cairn").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    /**
     * Pairing blocks, so it runs off the UI thread. Once it returns, the same thread
     * keeps calling poll, which is where the callbacks fire.
     */
    private fun startPairing() {
        if (handle == 0L || running) return

        val code = codeField.text?.toString()?.trim().orEmpty()
        if (code.length < 4) {
            print("enter at least four digits")
            return
        }

        running = true
        worker = Thread {
            print("pairing with $code")
            val rc = Cairn.nativePair(handle, code, PAIR_TIMEOUT_MS)
            if (rc != Cairn.OK) {
                print("pairing failed: ${Cairn.nativeError(rc)}")
                running = false
                return@Thread
            }
            print("paired, waiting for traffic")
            ui.post { statusView.text = getString(R.string.status_ready) }

            while (running) {
                Cairn.nativePoll(handle, POLL_SLICE_MS)
            }
        }.also { it.name = "cairn-pair"; it.start() }
    }

    private fun sendText() {
        if (!pairReady()) return
        val rc = Cairn.nativeSend(handle, "hello from cairn".toByteArray(StandardCharsets.UTF_8))
        print(if (rc == Cairn.OK) "sent" else "send failed: ${Cairn.nativeError(rc)}")
    }

    /**
     * Sends a synthetic file so the transfer path can be exercised without asking for
     * storage permission. A real app would read from a stream here.
     */
    private fun sendFile() {
        if (!pairReady()) return

        val total = FILE_BYTES
        val rc = Cairn.nativeSendFile(handle, total)
        if (rc != Cairn.OK) {
            print("offer failed: ${Cairn.nativeError(rc)}")
            return
        }

        val chunk = ByteArray(CHUNK_BYTES) { (it % 251).toByte() }
        var guard = 0
        while (guard++ < 64) {
            val sent = Cairn.nativeSendChunk(handle, chunk, CHUNK_TIMEOUT_MS)
            if (sent != Cairn.OK) {
                print("chunk failed: ${Cairn.nativeError(sent)}")
                return
            }
            print("progress ${Cairn.nativeProgress(handle)}%")
            if (Cairn.nativeTransferDone(handle)) break
        }
        print("transfer ${if (Cairn.nativeTransferDone(handle)) "complete" else "incomplete"}")
    }

    private fun pairReady(): Boolean {
        if (handle == 0L || !Cairn.nativeReady(handle)) {
            print("not paired yet")
            return false
        }
        return true
    }

    private fun deviceName(): String = android.os.Build.MODEL?.take(24) ?: "android"

    private companion object {
        const val PAIR_TIMEOUT_MS = 30_000
        const val POLL_SLICE_MS = 200
        const val FILE_BYTES = 64L * 1024L
        const val CHUNK_BYTES = 16 * 1024
        const val CHUNK_TIMEOUT_MS = 5_000
    }
}
