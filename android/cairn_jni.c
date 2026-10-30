/* cairn Android JNI bridge.
 *
 * The Kotlin side owns everything Android specific: the socket, the foreground
 * service, the BluetoothGatt callbacks, the UI. This file only exposes the
 * protocol, because marshalling a negotiation state machine across JNI would be
 * a larger surface than the library itself.
 *
 * Conventions:
 *   - a returned int is a cairn_status, 0 meaning success
 *   - byte arrays are copied in and out, never retained
 *   - a handle is a pointer to a heap struct, freed by nativeDestroy
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cairn/cairn.h"
#include "cairn/crypto.h"
#include "cairn/discovery.h"
#include "cairn/identity.h"
#include "cairn/node.h"
#include "cairn/platform.h"
#include "cairn/transfer.h"
#include "cairn/wire.h"

/* Wraps a node so Kotlin can hold on to it. */
typedef struct {
    cairn_node node;
    cairn_identity identity;
} android_node;

static jbyteArray to_bytes(JNIEnv *env, const void *data, size_t len)
{
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)data);
    return arr;
}

static jint copy_in(JNIEnv *env, jbyteArray src, void *dst, size_t cap, size_t *out)
{
    jsize len;

    if (src == NULL) return CAIRN_ERR_ARG;
    len = (*env)->GetArrayLength(env, src);
    if ((size_t)len > cap) return CAIRN_ERR_BUFFER;
    (*env)->GetByteArrayRegion(env, src, 0, len, (jbyte *)dst);
    if (out != NULL) *out = (size_t)len;
    return CAIRN_OK;
}

/* Returns the first peer that reached READY, or -1. */
static int first_ready(const cairn_node *n)
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->peers[i].state == CAIRN_PEER_READY) return i;
    return -1;
}

/* --------------------------------------------------------------- lifecycle */

JNIEXPORT jlong JNICALL
Java_org_cairn_demo_CairnNative_nativeCreate(JNIEnv *env, jclass cls,
                                             jstring name, jint port)
{
    android_node *h;
    const char *utf = NULL;
    int rc;

    (void)cls;
    h = (android_node *)calloc(1, sizeof *h);
    if (h == NULL) return 0;

    rc = cairn_identity_generate(&h->identity);
    if (rc != CAIRN_OK) {
        free(h);
        return 0;
    }

    if (name != NULL) utf = (*env)->GetStringUTFChars(env, name, NULL);
    rc = cairn_node_init(&h->node, &h->identity, utf != NULL ? utf : "android",
                         (uint16_t)port);
    if (utf != NULL) (*env)->ReleaseStringUTFChars(env, name, utf);

    if (rc != CAIRN_OK) {
        cairn_identity_clear(&h->identity);
        free(h);
        return 0;
    }
    return (jlong)(intptr_t)h;
}

JNIEXPORT void JNICALL
Java_org_cairn_demo_CairnNative_nativeDestroy(JNIEnv *env, jclass cls, jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (h == NULL) return;
    cairn_node_clear(&h->node);
    cairn_identity_clear(&h->identity);
    free(h);
}

/* ---------------------------------------------------------------- identity */

/* The six group fingerprint, for the pairing screen. */
JNIEXPORT jstring JNICALL
Java_org_cairn_demo_CairnNative_nativeFingerprint(JNIEnv *env, jclass cls, jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t fp[CAIRN_FP_BYTES];
    char text[18];

    (void)cls;
    if (h == NULL) return NULL;
    if (cairn_identity_fingerprint(fp, &h->identity) != CAIRN_OK) return NULL;
    if (cairn_fingerprint_text(text, fp) != CAIRN_OK) return NULL;
    return (*env)->NewStringUTF(env, text);
}

/* The six digit code both devices must show to confirm the pairing. */
JNIEXPORT jstring JNICALL
Java_org_cairn_demo_CairnNative_nativeSafetyCode(JNIEnv *env, jclass cls,
                                                 jlong handle, jbyteArray peer_pubkey)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t wire[CAIRN_PUBKEY_BYTES];
    cairn_pubkey peer;
    uint8_t mine[CAIRN_FP_BYTES], theirs[CAIRN_FP_BYTES];
    char code[CAIRN_SAFETY_CODE_BYTES];
    size_t len = 0;

    (void)cls;
    if (h == NULL) return NULL;
    if (copy_in(env, peer_pubkey, wire, sizeof wire, &len) != CAIRN_OK) return NULL;
    if (len != CAIRN_PUBKEY_BYTES) return NULL;
    if (cairn_pubkey_decode(&peer, wire) != CAIRN_OK) return NULL;
    if (cairn_identity_fingerprint(mine, &h->identity) != CAIRN_OK) return NULL;
    if (cairn_pubkey_fingerprint(theirs, &peer) != CAIRN_OK) return NULL;
    if (cairn_safety_code(code, mine, theirs) != CAIRN_OK) return NULL;
    return (*env)->NewStringUTF(env, code);
}

/* --------------------------------------------------------------- discovery */

JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeBeacon(JNIEnv *env, jclass cls, jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t buf[CAIRN_BEACON_MAX];
    size_t len = 0;

    (void)cls;
    if (h == NULL) return NULL;
    if (cairn_node_beacon(&h->node, buf, sizeof buf, &len) != CAIRN_OK) return NULL;
    return to_bytes(env, buf, len);
}

/* Returns {name, id hex, port} so Kotlin can list the peer. */
JNIEXPORT jobjectArray JNICALL
Java_org_cairn_demo_CairnNative_nativeOnBeacon(JNIEnv *env, jclass cls,
                                               jlong handle, jbyteArray beacon,
                                               jint now_ms)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t buf[CAIRN_BEACON_MAX];
    cairn_beacon b;
    size_t len = 0;
    jobjectArray out;
    jclass str_cls;
    char idhex[CAIRN_ID_BYTES * 2 + 1];
    char port[8];
    int i;

    (void)cls;
    if (h == NULL) return NULL;
    if (copy_in(env, beacon, buf, sizeof buf, &len) != CAIRN_OK) return NULL;
    if (cairn_beacon_decode(&b, buf, len) != CAIRN_OK) return NULL;
    if (cairn_node_on_beacon(&h->node, buf, len, (uint32_t)now_ms) != CAIRN_OK) return NULL;

    for (i = 0; i < CAIRN_ID_BYTES; i++)
        snprintf(idhex + (size_t)i * 2, 3, "%02x", b.id[i]);
    snprintf(port, sizeof port, "%u", b.port);

    str_cls = (*env)->FindClass(env, "java/lang/String");
    if (str_cls == NULL) return NULL;
    out = (*env)->NewObjectArray(env, 3, str_cls, NULL);
    if (out == NULL) return NULL;
    (*env)->SetObjectArrayElement(env, out, 0, (*env)->NewStringUTF(env, b.name));
    (*env)->SetObjectArrayElement(env, out, 1, (*env)->NewStringUTF(env, idhex));
    (*env)->SetObjectArrayElement(env, out, 2, (*env)->NewStringUTF(env, port));
    return out;
}

/* ---------------------------------------------------------------- protocol */

JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeAnnounceKey(JNIEnv *env, jclass cls,
                                                  jlong handle, jint now_ms)
{
    android_node *h = (android_node *)(intptr_t)handle;
    cairn_outbox out;

    (void)cls;
    (void)now_ms;
    if (h == NULL) return NULL;
    if (cairn_node_announce_key(&h->node, NULL, &out) != CAIRN_OK) return NULL;
    return to_bytes(env, out.buf, out.len);
}

/* Starts a handshake against a full public key learned from a KEY frame. */
JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeConnect(JNIEnv *env, jclass cls, jlong handle,
                                              jbyteArray peer_pubkey, jint now_ms)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t wire[CAIRN_PUBKEY_BYTES];
    cairn_pubkey peer;
    cairn_outbox out;
    size_t len = 0;

    (void)cls;
    if (h == NULL) return NULL;
    if (copy_in(env, peer_pubkey, wire, sizeof wire, &len) != CAIRN_OK) return NULL;
    if (len != CAIRN_PUBKEY_BYTES) return NULL;
    if (cairn_pubkey_decode(&peer, wire) != CAIRN_OK) return NULL;
    if (cairn_node_add_peer(&h->node, &peer, NULL) != CAIRN_OK) return NULL;
    if (cairn_node_connect(&h->node, peer.id, (uint32_t)now_ms, &out) != CAIRN_OK)
        return NULL;
    return to_bytes(env, out.buf, out.len);
}

/* Feeds one inbound frame. The reply goes back as bytes, or NULL when there is
 * nothing to send. state_out receives {status, ready}. */
JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeOnFrame(JNIEnv *env, jclass cls, jlong handle,
                                              jbyteArray frame, jint now_ms,
                                              jintArray state_out)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
    cairn_frame f;
    cairn_outbox reply;
    size_t used = 0, len = 0;
    int rc;

    (void)cls;
    if (h == NULL) return NULL;
    if (copy_in(env, frame, buf, sizeof buf, &len) != CAIRN_OK) return NULL;
    if (cairn_frame_decode(&f, &used, buf, len) != CAIRN_OK) return NULL;

    memset(&reply, 0, sizeof reply);
    rc = cairn_node_on_frame(&h->node, &f, (uint32_t)now_ms, &reply);

    if (state_out != NULL) {
        jint values[2];
        values[0] = rc;
        values[1] = first_ready(&h->node) >= 0 ? 1 : 0;
        (*env)->SetIntArrayRegion(env, state_out, 0, 2, values);
    }

    if (rc != CAIRN_OK || reply.len == 0) return NULL;
    return to_bytes(env, reply.buf, reply.len);
}

JNIEXPORT jboolean JNICALL
Java_org_cairn_demo_CairnNative_nativeIsReady(JNIEnv *env, jclass cls, jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (h == NULL) return JNI_FALSE;
    return first_ready(&h->node) >= 0 ? JNI_TRUE : JNI_FALSE;
}

/* Sends one message to the first ready peer. */
JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeSend(JNIEnv *env, jclass cls, jlong handle,
                                           jbyteArray data)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t msg[CAIRN_NODE_MAX_PAYLOAD];
    cairn_outbox out;
    size_t len = 0;
    int idx;

    (void)cls;
    if (h == NULL) return NULL;
    if (copy_in(env, data, msg, sizeof msg, &len) != CAIRN_OK) return NULL;

    idx = first_ready(&h->node);
    if (idx < 0) return NULL;
    if (cairn_node_send(&h->node, h->node.peers[idx].id, msg, len, &out) != CAIRN_OK)
        return NULL;
    return to_bytes(env, out.buf, out.len);
}

/* Returns the plaintext of the last inbound message, or NULL when none. */
JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeTakeMessage(JNIEnv *env, jclass cls, jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;
    int i;

    (void)cls;
    if (h == NULL) return NULL;
    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
        if (h->node.peers[i].last_plain_len > 0) {
            jbyteArray arr = to_bytes(env, h->node.peers[i].last_plain,
                                      h->node.peers[i].last_plain_len);
            /* Consumed on read, so the same message is never shown twice. */
            h->node.peers[i].last_plain_len = 0;
            return arr;
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- transfer */

JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeOfferFile(JNIEnv *env, jclass cls, jlong handle,
                                                jlong total_bytes)
{
    android_node *h = (android_node *)(intptr_t)handle;
    cairn_outbox out;
    int idx;

    (void)cls;
    if (h == NULL) return NULL;
    idx = first_ready(&h->node);
    if (idx < 0) return NULL;
    if (cairn_node_offer_file(&h->node, h->node.peers[idx].id,
                              (uint64_t)total_bytes, &out) != CAIRN_OK)
        return NULL;
    return to_bytes(env, out.buf, out.len);
}

/* Returns the next sealed chunk, or NULL when every chunk is confirmed. */
JNIEXPORT jbyteArray JNICALL
Java_org_cairn_demo_CairnNative_nativeNextChunk(JNIEnv *env, jclass cls, jlong handle,
                                                jbyteArray chunk, jintArray index_out)
{
    android_node *h = (android_node *)(intptr_t)handle;
    uint8_t buf[CAIRN_CHUNK_BYTES];
    cairn_outbox out;
    size_t len = 0, want = 0;
    uint32_t index = 0;
    int idx;

    (void)cls;
    if (h == NULL) return NULL;
    if (copy_in(env, chunk, buf, sizeof buf, &len) != CAIRN_OK) return NULL;

    idx = first_ready(&h->node);
    if (idx < 0) return NULL;
    if (cairn_transfer_next_chunk(&h->node.peers[idx].transfer, &index, &want)
        != CAIRN_OK)
        return NULL;
    if (len < want) return NULL;
    if (cairn_node_pump_transfer(&h->node, h->node.peers[idx].id, buf, want, &out)
        != CAIRN_OK)
        return NULL;
    if (index_out != NULL) {
        jint v = (jint)index;
        (*env)->SetIntArrayRegion(env, index_out, 0, 1, &v);
    }
    return to_bytes(env, out.buf, out.len);
}

JNIEXPORT jint JNICALL
Java_org_cairn_demo_CairnNative_nativeTransferProgress(JNIEnv *env, jclass cls,
                                                        jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;
    int idx;

    (void)env;
    (void)cls;
    if (h == NULL) return 0;
    idx = first_ready(&h->node);
    if (idx < 0) return 0;
    return (jint)cairn_transfer_progress(&h->node.peers[idx].transfer);
}

JNIEXPORT jboolean JNICALL
Java_org_cairn_demo_CairnNative_nativeTransferComplete(JNIEnv *env, jclass cls,
                                                        jlong handle)
{
    android_node *h = (android_node *)(intptr_t)handle;
    int idx;

    (void)env;
    (void)cls;
    if (h == NULL) return JNI_FALSE;
    idx = first_ready(&h->node);
    if (idx < 0) return JNI_FALSE;
    return cairn_transfer_complete(&h->node.peers[idx].transfer) ? JNI_TRUE : JNI_FALSE;
}

/* -------------------------------------------------------------------- misc */

JNIEXPORT jstring JNICALL
Java_org_cairn_demo_CairnNative_nativeStatusString(JNIEnv *env, jclass cls, jint code)
{
    (void)cls;
    return (*env)->NewStringUTF(env, cairn_status_string(code));
}

JNIEXPORT jlong JNICALL
Java_org_cairn_demo_CairnNative_nativeTimeMs(JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;
    return (jlong)cairn_time_ms();
}