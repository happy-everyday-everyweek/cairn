package org.cairn.demo

/**
 * The whole native surface: one function per facade call, nothing else.
 *
 * Handles are pointers into native memory; nativeClose must be called or the node and
 * its keys leak. There is deliberately no socket class here, because the facade owns
 * its own transport and opens it in nativeOpen.
 */
object Cairn {

    init {
        System.loadLibrary("cairn")
    }

    external fun nativeOpen(name: String, listener: Any): Long
    external fun nativeClose(handle: Long)

    external fun nativeFingerprint(handle: Long): String?

    /** Blocks up to timeoutMs. Returns 0 on success, negative otherwise. */
    external fun nativePair(handle: Long, code: String, timeoutMs: Int): Int

    /** Drives the state machine; callbacks fire here. */
    external fun nativePoll(handle: Long, timeoutMs: Int)
    external fun nativeReady(handle: Long): Boolean

    external fun nativeSend(handle: Long, data: ByteArray): Int

    external fun nativeSendFile(handle: Long, total: Long): Int
    external fun nativeSendChunk(handle: Long, data: ByteArray, timeoutMs: Int): Int
    external fun nativeTransferDone(handle: Long): Boolean
    external fun nativeProgress(handle: Long): Int

    external fun nativeError(code: Int): String

    const val OK = 0
}
