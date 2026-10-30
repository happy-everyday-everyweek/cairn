/* cairn Android JNI bridge.
 *
 * Thin by design: every function maps to one call of the facade in cairn/cairn.h, and
 * nothing here makes a protocol decision. The facade owns the socket, so the Kotlin
 * side only supplies a listener for events and a name for the beacon.
 *
 * The facade invokes callbacks from inside cairn_poll, which Kotlin calls on a worker
 * thread. That thread is already attached to the VM, so most calls need no attach; the
 * attach path below covers the case where that ever changes.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cairn/cairn.h"

typedef struct {
    cairn_node *node;
    JavaVM *vm;
    jobject listener;      /* global reference, released in nativeClose */
    jmethodID on_message;  /* (byte[])V */
    jmethodID on_chunk;    /* (int, byte[])V */
    jmethodID on_ready;    /* ()V */
} bridge;

static JNIEnv *env_for(bridge *b, int *attached)
{
    JNIEnv *env = NULL;

    *attached = 0;
    if ((*b->vm)->GetEnv(b->vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) return env;
    if ((*b->vm)->AttachCurrentThread(b->vm, &env, NULL) != JNI_OK) return NULL;
    *attached = 1;
    return env;
}

static void env_done(bridge *b, int attached)
{
    if (attached) (*b->vm)->DetachCurrentThread(b->vm);
}

static jbyteArray make_array(JNIEnv *env, const void *data, size_t len)
{
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);

    if (arr == NULL) return NULL;
    if (len > 0)
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)data);
    return arr;
}

/* A Java exception must never unwind through C, so every callback clears one. */
static void clear_exception(JNIEnv *env)
{
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

static void cb_message(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                       const void *data, size_t len)
{
    bridge *b = (bridge *)user;
    int attached;
    JNIEnv *env = env_for(b, &attached);
    jbyteArray arr;

    (void)peer;
    if (env == NULL) return;

    arr = make_array(env, data, len);
    if (arr != NULL) {
        (*env)->CallVoidMethod(env, b->listener, b->on_message, arr);
        (*env)->DeleteLocalRef(env, arr);
    }
    clear_exception(env);
    env_done(b, attached);
}

static void cb_chunk(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                     uint32_t index, const void *data, size_t len)
{
    bridge *b = (bridge *)user;
    int attached;
    JNIEnv *env = env_for(b, &attached);
    jbyteArray arr;

    (void)peer;
    if (env == NULL) return;

    arr = make_array(env, data, len);
    if (arr != NULL) {
        (*env)->CallVoidMethod(env, b->listener, b->on_chunk, (jint)index, arr);
        (*env)->DeleteLocalRef(env, arr);
    }
    clear_exception(env);
    env_done(b, attached);
}

static void cb_ready(void *user, const uint8_t peer[CAIRN_ID_BYTES])
{
    bridge *b = (bridge *)user;
    int attached;
    JNIEnv *env = env_for(b, &attached);

    (void)peer;
    if (env == NULL) return;
    (*env)->CallVoidMethod(env, b->listener, b->on_ready);
    clear_exception(env);
    env_done(b, attached);
}

JNIEXPORT jlong JNICALL
Java_org_cairn_demo_Cairn_nativeOpen(JNIEnv *env, jclass cls, jstring name, jobject listener)
{
    bridge *b;
    cairn_io io;
    jclass listener_class;
    const char *utf = NULL;

    (void)cls;
    if (listener == NULL) return 0;

    b = (bridge *)calloc(1, sizeof *b);
    if (b == NULL) return 0;

    if ((*env)->GetJavaVM(env, &b->vm) != JNI_OK) {
        free(b);
        return 0;
    }

    b->listener = (*env)->NewGlobalRef(env, listener);
    if (b->listener == NULL) {
        free(b);
        return 0;
    }

    listener_class = (*env)->GetObjectClass(env, listener);
    if (listener_class == NULL) {
        (*env)->DeleteGlobalRef(env, b->listener);
        free(b);
        return 0;
    }

    b->on_message = (*env)->GetMethodID(env, listener_class, "onMessage", "([B)V");
    b->on_chunk = (*env)->GetMethodID(env, listener_class, "onChunk", "(I[B)V");
    b->on_ready = (*env)->GetMethodID(env, listener_class, "onReady", "()V");
    (*env)->DeleteLocalRef(env, listener_class);

    if (b->on_message == NULL || b->on_chunk == NULL || b->on_ready == NULL) {
        clear_exception(env);
        (*env)->DeleteGlobalRef(env, b->listener);
        free(b);
        return 0;
    }

    memset(&io, 0, sizeof io);
    io.on_message = cb_message;
    io.on_chunk = cb_chunk;
    io.on_ready = cb_ready;
    io.user = b;
    /* io.send stays NULL: the facade then uses its own socket, which is why the
     * Kotlin side no longer needs one. */

    if (name != NULL) utf = (*env)->GetStringUTFChars(env, name, NULL);
    b->node = cairn_open(utf != NULL ? utf : "cairn", &io);
    if (utf != NULL) (*env)->ReleaseStringUTFChars(env, name, utf);

    if (b->node == NULL) {
        (*env)->DeleteGlobalRef(env, b->listener);
        free(b);
        return 0;
    }
    return (jlong)(intptr_t)b;
}

JNIEXPORT void JNICALL
Java_org_cairn_demo_Cairn_nativeClose(JNIEnv *env, jclass cls, jlong handle)
{
    bridge *b = (bridge *)(intptr_t)handle;

    (void)cls;
    if (b == NULL) return;
    if (b->node != NULL) cairn_close(b->node);
    if (b->listener != NULL) (*env)->DeleteGlobalRef(env, b->listener);
    free(b);
}

JNIEXPORT jstring JNICALL
Java_org_cairn_demo_Cairn_nativeFingerprint(JNIEnv *env, jclass cls, jlong handle)
{
    bridge *b = (bridge *)(intptr_t)handle;
    char text[18];

    (void)cls;
    if (b == NULL || b->node == NULL) return NULL;
    if (cairn_fingerprint(b->node, text) != CAIRN_OK) return NULL;
    return (*env)->NewStringUTF(env, text);
}

JNIEXPORT jint JNICALL
Java_org_cairn_demo_Cairn_nativePair(JNIEnv *env, jclass cls, jlong handle,
                                     jstring code, jint timeout_ms)
{
    bridge *b = (bridge *)(intptr_t)handle;
    const char *utf;
    int rc;

    (void)cls;
    if (b == NULL || b->node == NULL || code == NULL) return CAIRN_ERR_ARG;

    utf = (*env)->GetStringUTFChars(env, code, NULL);
    if (utf == NULL) return CAIRN_ERR_ARG;
    rc = cairn_pair_wait(b->node, utf, (uint32_t)timeout_ms);
    (*env)->ReleaseStringUTFChars(env, code, utf);
    return rc;
}

JNIEXPORT void JNICALL
Java_org_cairn_demo_Cairn_nativePoll(JNIEnv *env, jclass cls, jlong handle, jint timeout_ms)
{
    bridge *b = (bridge *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (b == NULL || b->node == NULL) return;
    (void)cairn_poll(b->node, (uint32_t)timeout_ms);
}

JNIEXPORT jboolean JNICALL
Java_org_cairn_demo_Cairn_nativeReady(JNIEnv *env, jclass cls, jlong handle)
{
    bridge *b = (bridge *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (b == NULL || b->node == NULL) return JNI_FALSE;
    return cairn_is_ready(b->node) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_org_cairn_demo_Cairn_nativeSend(JNIEnv *env, jclass cls, jlong handle, jbyteArray data)
{
    bridge *b = (bridge *)(intptr_t)handle;
    jsize len;
    uint8_t *buf;
    int rc;

    (void)cls;
    if (b == NULL || b->node == NULL || data == NULL) return CAIRN_ERR_ARG;

    len = (*env)->GetArrayLength(env, data);
    buf = (uint8_t *)malloc((size_t)len > 0 ? (size_t)len : 1);
    if (buf == NULL) return CAIRN_ERR_MEMORY;

    (*env)->GetByteArrayRegion(env, data, 0, len, (jbyte *)buf);
    rc = cairn_send(b->node, buf, (size_t)len);
    free(buf);
    return rc;
}

JNIEXPORT jint JNICALL
Java_org_cairn_demo_Cairn_nativeSendFile(JNIEnv *env, jclass cls, jlong handle, jlong total)
{
    bridge *b = (bridge *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (b == NULL || b->node == NULL) return CAIRN_ERR_ARG;
    return cairn_send_file(b->node, (uint64_t)total);
}

JNIEXPORT jint JNICALL
Java_org_cairn_demo_Cairn_nativeSendChunk(JNIEnv *env, jclass cls, jlong handle,
                                          jbyteArray data, jint timeout_ms)
{
    bridge *b = (bridge *)(intptr_t)handle;
    jsize len;
    uint8_t *buf;
    int rc;

    (void)cls;
    if (b == NULL || b->node == NULL || data == NULL) return CAIRN_ERR_ARG;

    len = (*env)->GetArrayLength(env, data);
    buf = (uint8_t *)malloc((size_t)len > 0 ? (size_t)len : 1);
    if (buf == NULL) return CAIRN_ERR_MEMORY;

    (*env)->GetByteArrayRegion(env, data, 0, len, (jbyte *)buf);
    rc = cairn_send_chunk(b->node, buf, (size_t)len, (uint32_t)timeout_ms);
    free(buf);
    return rc;
}

JNIEXPORT jboolean JNICALL
Java_org_cairn_demo_Cairn_nativeTransferDone(JNIEnv *env, jclass cls, jlong handle)
{
    bridge *b = (bridge *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (b == NULL || b->node == NULL) return JNI_FALSE;
    return cairn_transfer_done(b->node) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_org_cairn_demo_Cairn_nativeProgress(JNIEnv *env, jclass cls, jlong handle)
{
    bridge *b = (bridge *)(intptr_t)handle;

    (void)env;
    (void)cls;
    if (b == NULL || b->node == NULL) return 0;
    return (jint)cairn_progress(b->node);
}

JNIEXPORT jstring JNICALL
Java_org_cairn_demo_Cairn_nativeError(JNIEnv *env, jclass cls, jint code)
{
    (void)cls;
    return (*env)->NewStringUTF(env, cairn_strerror(code));
}
