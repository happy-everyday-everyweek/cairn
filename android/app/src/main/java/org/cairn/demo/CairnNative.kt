package org.cairn.demo

/**
 * Thin declaration layer over the native library.
 *
 * Every method here is a direct mapping of one cairn C function. Handles are
 * pointers into native heap memory; [nativeDestroy] must be called or the node
 * leaks. Nothing in this file makes policy decisions: the state machine, the
 * retry timing and the UI live above it.
 */
object CairnNative {

    init {
        System.loadLibrary("cairn")
    }

    // lifecycle
    external fun nativeCreate(name: String?, port: Int): Long
    external fun nativeDestroy(handle: Long)

    // identity
    external fun nativeFingerprint(handle: Long): String?
    external fun nativeSafetyCode(handle: Long, peerPubkey: ByteArray): String?

    // discovery
    external fun nativeBeacon(handle: Long): ByteArray?
    /** Returns {name, idHex, port} for a decoded beacon. */
    external fun nativeOnBeacon(handle: Long, beacon: ByteArray, nowMs: Int): Array<String>?

    // protocol
    external fun nativeAnnounceKey(handle: Long, nowMs: Int): ByteArray?
    external fun nativeConnect(handle: Long, peerPubkey: ByteArray, nowMs: Int): ByteArray?
    /** Returns the reply frame, and fills stateOut with {status, readyFlag}. */
    external fun nativeOnFrame(
        handle: Long,
        frame: ByteArray,
        nowMs: Int,
        stateOut: IntArray
    ): ByteArray?

    external fun nativeIsReady(handle: Long): Boolean
    external fun nativeSend(handle: Long, data: ByteArray): ByteArray?
    external fun nativeTakeMessage(handle: Long): ByteArray?

    // transfer
    external fun nativeOfferFile(handle: Long, totalBytes: Long): ByteArray?
    external fun nativeNextChunk(handle: Long, chunk: ByteArray, indexOut: IntArray): ByteArray?
    external fun nativeTransferProgress(handle: Long): Int
    external fun nativeTransferComplete(handle: Long): Boolean

    // misc
    external fun nativeStatusString(code: Int): String
    external fun nativeTimeMs(): Long

    /** Status code returned by the library when everything worked. */
    const val OK = 0
}