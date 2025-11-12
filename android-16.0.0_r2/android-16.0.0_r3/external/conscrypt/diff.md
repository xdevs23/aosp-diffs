```diff
diff --git a/Android.bp b/Android.bp
index 5c89f982..82827f06 100644
--- a/Android.bp
+++ b/Android.bp
@@ -217,6 +217,34 @@ java_aconfig_library {
     ],
 }
 
+aconfig_declarations {
+    name: "networksecurity-aconfig-flags",
+    package: "com.android.org.conscrypt.net.flags",
+    container: "com.android.conscrypt",
+    srcs: ["networksecurity.aconfig"],
+    exportable: true,
+    visibility: [
+        "//frameworks/base",
+    ],
+}
+
+java_aconfig_library {
+    name: "networksecurity-aconfig-flags-lib",
+    aconfig_declarations: "networksecurity-aconfig-flags",
+    system_modules: "core-all-system-modules",
+    sdk_version: "none",
+    patch_module: "java.base",
+    apex_available: [
+        "com.android.conscrypt",
+    ],
+    min_sdk_version: "30",
+    installable: false,
+    visibility: [
+        "//cts/tests/tests/networksecurityconfig:__subpackages__",
+        "//frameworks/base",
+    ],
+}
+
 cc_binary_host {
     name: "conscrypt_generate_constants",
     srcs: ["constants/src/gen/cpp/generate_constants.cc"],
@@ -244,12 +272,21 @@ genrule {
     tools: ["conscrypt_generate_constants"],
 }
 
+genrule {
+    name: "conscrypt_generated_blocklist",
+    out: ["com/android/org/conscrypt/StaticBlocklist.java"],
+    srcs: ["constants/src/gen/java/cert_verify_proc_blocklist.inc"],
+    tool_files: ["constants/src/gen/java/generate_blocklist.awk"],
+    cmd: "awk -v package=com.android.org.conscrypt -f $(location constants/src/gen/java/generate_blocklist.awk) $(in) > $(out)",
+}
+
 filegroup {
     name: "conscrypt_java_files",
     srcs: [
         "repackaged/common/src/main/java/**/*.java",
         "repackaged/platform/src/main/java/**/*.java",
         ":conscrypt_generated_constants",
+        ":conscrypt_generated_blocklist",
     ],
 }
 
@@ -290,6 +327,8 @@ java_library {
     ],
     static_libs: [
         "conscrypt-aconfig-flags-lib",
+        "conscrypt-statslog-java",
+        "networksecurity-aconfig-flags-lib",
     ],
 
     // Conscrypt can be updated independently from the other core libraries so it must only depend
@@ -387,9 +426,11 @@ java_sdk_library {
         ":conscrypt_java_files",
         ":conscrypt_public_api_files",
         ":framework-metalava-annotations",
+        ":visible_api_surface_annotation_files",
     ],
     aconfig_declarations: [
         "conscrypt-aconfig-flags",
+        "networksecurity-aconfig-flags",
     ],
     api_dir: "api/platform",
     api_only: true,
@@ -420,6 +461,7 @@ java_sdk_library {
     unsafe_ignore_missing_latest_api: true,
     libs: [
         "conscrypt-aconfig-flags-lib",
+        "networksecurity-aconfig-flags-lib",
     ],
 }
 
@@ -449,9 +491,11 @@ java_sdk_library {
     ],
     libs: [
         "conscrypt-aconfig-flags-lib",
+        "networksecurity-aconfig-flags-lib",
     ],
     aconfig_declarations: [
         "conscrypt-aconfig-flags",
+        "networksecurity-aconfig-flags",
     ],
 
     // The base name for the artifacts that are automatically published to the
@@ -726,6 +770,7 @@ filegroup {
         "repackaged/platform/src/test/java/com/android/org/conscrypt/ct/*.java",
         "repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java",
         "repackaged/common/src/test/java/com/android/org/conscrypt/ct/*.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/securityconfig/*.java",
     ],
 }
 
@@ -939,3 +984,26 @@ module_exports {
         },
     },
 }
+
+java_library {
+    name: "conscrypt-statslog-java",
+    srcs: [
+        ":conscrypt-statslog-java-gen",
+    ],
+    libs: [
+        "framework-statsd.stubs.module_lib",
+        "androidx.annotation_annotation",
+    ],
+    sdk_version: "system_server_current",
+    min_sdk_version: "30",
+    apex_available: [
+        "com.android.conscrypt",
+    ],
+}
+
+genrule {
+    name: "conscrypt-statslog-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module conscrypt --javaPackage com.android.org.conscrypt.metrics --javaClass ConscryptStatsLog",
+    out: ["repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java"],
+}
diff --git a/apex/Android.bp b/apex/Android.bp
index ad85aed8..c9173b31 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -88,6 +88,10 @@ apex {
         "cacerts_apex",
     ],
     min_sdk_version: "30",
+    licenses: [
+        "external_conscrypt_license",
+        "opensourcerequest",
+    ],
 }
 
 // Encapsulate the contributions made by the com.android.conscrypt to the bootclasspath.
diff --git a/common/src/jni/main/cpp/conscrypt/native_crypto.cc b/common/src/jni/main/cpp/conscrypt/native_crypto.cc
index ba926480..63c62b3a 100644
--- a/common/src/jni/main/cpp/conscrypt/native_crypto.cc
+++ b/common/src/jni/main/cpp/conscrypt/native_crypto.cc
@@ -54,6 +54,7 @@
 #include <optional>
 #include <type_traits>
 #include <vector>
+#include "jni.h"
 
 using conscrypt::AppData;
 using conscrypt::BioInputStream;
@@ -2622,8 +2623,7 @@ static void NativeCrypto_EVP_MD_CTX_cleanup(JNIEnv* env, jclass, jobject ctxRef)
     }
 }
 
-static void NativeCrypto_EVP_MD_CTX_destroy(JNIEnv* env, jclass, jlong ctxRef) {
-    CHECK_ERROR_QUEUE_ON_RETURN;
+static void NativeCrypto_EVP_MD_CTX_destroy(CRITICAL_JNI_PARAMS_COMMA jlong ctxRef) {
     EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxRef);
     JNI_TRACE_MD("EVP_MD_CTX_destroy(%p)", ctx);
 
@@ -7753,8 +7753,7 @@ static SSL_SESSION* server_session_requested_callback(SSL* ssl, const uint8_t* i
     return ssl_session_ptr;
 }
 
-static jint NativeCrypto_EVP_has_aes_hardware(JNIEnv* env, jclass) {
-    CHECK_ERROR_QUEUE_ON_RETURN;
+static jint NativeCrypto_EVP_has_aes_hardware(CRITICAL_JNI_PARAMS) {
     int ret = 0;
     ret = EVP_has_aes_hardware();
     JNI_TRACE("EVP_has_aes_hardware => %d", ret);
@@ -9999,9 +9998,8 @@ static jlong NativeCrypto_SSL_get_timeout(JNIEnv* env, jclass, jlong ssl_address
     return result;
 }
 
-static jint NativeCrypto_SSL_get_signature_algorithm_key_type(JNIEnv* env, jclass,
+static jint NativeCrypto_SSL_get_signature_algorithm_key_type(CRITICAL_JNI_PARAMS_COMMA
                                                               jint signatureAlg) {
-    CHECK_ERROR_QUEUE_ON_RETURN;
     return SSL_get_signature_algorithm_key_type(signatureAlg);
 }
 
@@ -10474,7 +10472,7 @@ static jint NativeCrypto_SSL_get_error(JNIEnv* env, jclass, jlong ssl_address,
     return SSL_get_error(ssl, ret);
 }
 
-static void NativeCrypto_SSL_clear_error(JNIEnv*, jclass) {
+static void NativeCrypto_SSL_clear_error(CRITICAL_JNI_PARAMS) {
     ERR_clear_error();
 }
 
diff --git a/common/src/jni/main/include/conscrypt/jniutil.h b/common/src/jni/main/include/conscrypt/jniutil.h
index 7ae567db..9b84801d 100644
--- a/common/src/jni/main/include/conscrypt/jniutil.h
+++ b/common/src/jni/main/include/conscrypt/jniutil.h
@@ -27,6 +27,14 @@
 namespace conscrypt {
 namespace jniutil {
 
+#ifdef __ANDROID__
+    #define CRITICAL_JNI_PARAMS
+    #define CRITICAL_JNI_PARAMS_COMMA
+#else
+    #define CRITICAL_JNI_PARAMS JNIEnv*, jclass
+    #define CRITICAL_JNI_PARAMS_COMMA JNIEnv*, jclass,
+#endif
+
 extern JavaVM* gJavaVM;
 extern jclass cryptoUpcallsClass;
 extern jclass openSslInputStreamClass;
diff --git a/common/src/main/java/org/conscrypt/NativeCrypto.java b/common/src/main/java/org/conscrypt/NativeCrypto.java
index 2ce8284f..a3148274 100644
--- a/common/src/main/java/org/conscrypt/NativeCrypto.java
+++ b/common/src/main/java/org/conscrypt/NativeCrypto.java
@@ -16,6 +16,8 @@
 
 package org.conscrypt;
 
+import dalvik.annotation.optimization.CriticalNative;
+import dalvik.annotation.optimization.FastNative;
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.io.OutputStream;
@@ -46,18 +48,19 @@ import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
 
 /**
  * Provides the Java side of our JNI glue for OpenSSL.
- * <p>
- * Note: Many methods in this class take a reference to a Java object that holds a
- * native pointer in the form of a long in addition to the long itself and don't use
- * the Java object in the native implementation.  This is to prevent the Java object
- * from becoming eligible for GC while the native method is executing.  See
- * <a href="https://github.com/google/error-prone/blob/master/docs/bugpattern/UnsafeFinalization.md">this</a>
+ *
+ * <p>Note: Many methods in this class take a reference to a Java object that holds a native pointer
+ * in the form of a long in addition to the long itself and don't use the Java object in the native
+ * implementation. This is to prevent the Java object from becoming eligible for GC while the native
+ * method is executing. See <a
+ * href="https://github.com/google/error-prone/blob/master/docs/bugpattern/UnsafeFinalization.md">this</a>
  * for more details.
  */
 @Internal
 public final class NativeCrypto {
     // --- OpenSSL library initialization --------------------------------------
     private static final UnsatisfiedLinkError loadError;
+
     static {
         UnsatisfiedLinkError error = null;
         try {
@@ -72,11 +75,12 @@ public final class NativeCrypto {
         setTlsV1DeprecationStatus(Platform.isTlsV1Deprecated(), Platform.isTlsV1Supported());
     }
 
-    private native static void clinit();
+    @FastNative
+    private static native void clinit();
 
     /**
-     * Checks to see whether or not the native library was successfully loaded. If not, throws
-     * the {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
+     * Checks to see whether or not the native library was successfully loaded. If not, throws the
+     * {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
      */
     static void checkAvailability() {
         if (loadError != null) {
@@ -86,360 +90,415 @@ public final class NativeCrypto {
 
     // --- DSA/RSA public/private key handling functions -----------------------
 
+    @FastNative
     static native long EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q,
             byte[] dmp1, byte[] dmq1, byte[] iqmp);
 
-    static native int EVP_PKEY_type(NativeRef.EVP_PKEY pkey);
+    @FastNative static native int EVP_PKEY_type(NativeRef.EVP_PKEY pkey);
 
-    static native String EVP_PKEY_print_public(NativeRef.EVP_PKEY pkeyRef);
+    @FastNative static native String EVP_PKEY_print_public(NativeRef.EVP_PKEY pkeyRef);
 
-    static native String EVP_PKEY_print_params(NativeRef.EVP_PKEY pkeyRef);
+    @FastNative static native String EVP_PKEY_print_params(NativeRef.EVP_PKEY pkeyRef);
 
-    static native void EVP_PKEY_free(long pkey);
+    @FastNative static native void EVP_PKEY_free(long pkey);
 
-    static native int EVP_PKEY_cmp(NativeRef.EVP_PKEY pkey1, NativeRef.EVP_PKEY pkey2);
+    @FastNative static native int EVP_PKEY_cmp(NativeRef.EVP_PKEY pkey1, NativeRef.EVP_PKEY pkey2);
 
-    static native byte[] EVP_marshal_private_key(NativeRef.EVP_PKEY pkey);
+    @FastNative static native byte[] EVP_marshal_private_key(NativeRef.EVP_PKEY pkey);
 
-    static native long EVP_parse_private_key(byte[] data) throws ParsingException;
+    @FastNative static native long EVP_parse_private_key(byte[] data) throws ParsingException;
 
-    static native byte[] EVP_marshal_public_key(NativeRef.EVP_PKEY pkey);
+    @FastNative static native byte[] EVP_marshal_public_key(NativeRef.EVP_PKEY pkey);
 
+    @FastNative
     static native byte[] EVP_raw_X25519_private_key(byte[] data)
             throws ParsingException, InvalidKeyException;
 
-    static native long EVP_parse_public_key(byte[] data) throws ParsingException;
+    @FastNative static native long EVP_parse_public_key(byte[] data) throws ParsingException;
 
-    static native long PEM_read_bio_PUBKEY(long bioCtx);
+    @FastNative static native long PEM_read_bio_PUBKEY(long bioCtx);
 
-    static native long PEM_read_bio_PrivateKey(long bioCtx);
+    @FastNative static native long PEM_read_bio_PrivateKey(long bioCtx);
 
-    static native long getRSAPrivateKeyWrapper(PrivateKey key, byte[] modulus);
+    @FastNative static native long getRSAPrivateKeyWrapper(PrivateKey key, byte[] modulus);
 
+    @FastNative
     static native long getECPrivateKeyWrapper(PrivateKey key, NativeRef.EC_GROUP ecGroupRef);
 
-    static native long RSA_generate_key_ex(int modulusBits, byte[] publicExponent);
+    @FastNative static native long RSA_generate_key_ex(int modulusBits, byte[] publicExponent);
 
-    static native int RSA_size(NativeRef.EVP_PKEY pkey);
+    @FastNative static native int RSA_size(NativeRef.EVP_PKEY pkey);
 
+    @FastNative
     static native int RSA_private_encrypt(
             int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey, int padding);
 
+    @FastNative
     static native int RSA_public_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
             int padding) throws BadPaddingException, SignatureException;
 
+    @FastNative
     static native int RSA_public_encrypt(
             int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey, int padding);
 
+    @FastNative
     static native int RSA_private_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
             int padding) throws BadPaddingException, SignatureException;
 
     /*
      * Returns array of {n, e}
      */
-    static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);
+    @FastNative static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);
 
     /*
      * Returns array of {n, e, d, p, q, dmp1, dmq1, iqmp}
      */
-    static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);
+    @FastNative static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);
 
     // --- ChaCha20 -----------------------
 
     /*
      * Returns the encrypted or decrypted version of the data.
      */
+    @FastNative
     static native void chacha20_encrypt_decrypt(byte[] in, int inOffset, byte[] out, int outOffset,
             int length, byte[] key, byte[] nonce, int blockCounter);
 
     // --- EC functions --------------------------
 
+    @FastNative
     static native long EVP_PKEY_new_EC_KEY(
             NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pubkeyRef, byte[] privkey);
 
-    static native long EC_GROUP_new_by_curve_name(String curveName);
+    @FastNative static native long EC_GROUP_new_by_curve_name(String curveName);
 
+    @FastNative
     static native long EC_GROUP_new_arbitrary(
             byte[] p, byte[] a, byte[] b, byte[] x, byte[] y, byte[] order, int cofactor);
 
-    static native String EC_GROUP_get_curve_name(NativeRef.EC_GROUP groupRef);
+    @FastNative static native String EC_GROUP_get_curve_name(NativeRef.EC_GROUP groupRef);
 
-    static native byte[][] EC_GROUP_get_curve(NativeRef.EC_GROUP groupRef);
+    @FastNative static native byte[][] EC_GROUP_get_curve(NativeRef.EC_GROUP groupRef);
 
-    static native void EC_GROUP_clear_free(long groupRef);
+    @FastNative static native void EC_GROUP_clear_free(long groupRef);
 
-    static native long EC_GROUP_get_generator(NativeRef.EC_GROUP groupRef);
+    @FastNative static native long EC_GROUP_get_generator(NativeRef.EC_GROUP groupRef);
 
-    static native byte[] EC_GROUP_get_order(NativeRef.EC_GROUP groupRef);
+    @FastNative static native byte[] EC_GROUP_get_order(NativeRef.EC_GROUP groupRef);
 
-    static native int EC_GROUP_get_degree(NativeRef.EC_GROUP groupRef);
+    @FastNative static native int EC_GROUP_get_degree(NativeRef.EC_GROUP groupRef);
 
-    static native byte[] EC_GROUP_get_cofactor(NativeRef.EC_GROUP groupRef);
+    @FastNative static native byte[] EC_GROUP_get_cofactor(NativeRef.EC_GROUP groupRef);
 
-    static native long EC_POINT_new(NativeRef.EC_GROUP groupRef);
+    @FastNative static native long EC_POINT_new(NativeRef.EC_GROUP groupRef);
 
-    static native void EC_POINT_clear_free(long pointRef);
+    @FastNative static native void EC_POINT_clear_free(long pointRef);
 
+    @FastNative
     static native byte[][] EC_POINT_get_affine_coordinates(
             NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pointRef);
 
+    @FastNative
     static native void EC_POINT_set_affine_coordinates(
             NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pointRef, byte[] x, byte[] y);
 
-    static native long EC_KEY_generate_key(NativeRef.EC_GROUP groupRef);
+    @FastNative static native long EC_KEY_generate_key(NativeRef.EC_GROUP groupRef);
 
-    static native long EC_KEY_get1_group(NativeRef.EVP_PKEY pkeyRef);
+    @FastNative static native long EC_KEY_get1_group(NativeRef.EVP_PKEY pkeyRef);
 
-    static native byte[] EC_KEY_get_private_key(NativeRef.EVP_PKEY keyRef);
+    @FastNative static native byte[] EC_KEY_get_private_key(NativeRef.EVP_PKEY keyRef);
 
-    static native long EC_KEY_get_public_key(NativeRef.EVP_PKEY keyRef);
+    @FastNative static native long EC_KEY_get_public_key(NativeRef.EVP_PKEY keyRef);
 
+    @FastNative
     static native byte[] EC_KEY_marshal_curve_name(NativeRef.EC_GROUP groupRef) throws IOException;
 
-    static native long EC_KEY_parse_curve_name(byte[] encoded) throws IOException;
+    @FastNative static native long EC_KEY_parse_curve_name(byte[] encoded) throws IOException;
 
+    @FastNative
     static native int ECDH_compute_key(byte[] out, int outOffset, NativeRef.EVP_PKEY publicKeyRef,
             NativeRef.EVP_PKEY privateKeyRef) throws InvalidKeyException, IndexOutOfBoundsException;
 
-    static native int ECDSA_size(NativeRef.EVP_PKEY pkey);
+    @FastNative static native int ECDSA_size(NativeRef.EVP_PKEY pkey);
 
-    static native int ECDSA_sign(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
+    @FastNative static native int ECDSA_sign(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
 
-    static native int ECDSA_verify(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
+    @FastNative static native int ECDSA_verify(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
 
     // --- Curve25519 --------------
 
-    static native boolean X25519(byte[] out, byte[] privateKey, byte[] publicKey) throws InvalidKeyException;
+    @FastNative
+    static native boolean X25519(byte[] out, byte[] privateKey, byte[] publicKey)
+            throws InvalidKeyException;
 
-    static native void X25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
+    @FastNative static native void X25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
 
-    static native void ED25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
+    @FastNative static native void ED25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
 
     // --- Message digest functions --------------
 
     // These return const references
-    static native long EVP_get_digestbyname(String name);
+    @FastNative static native long EVP_get_digestbyname(String name);
 
-    static native int EVP_MD_size(long evp_md_const);
+    @FastNative static native int EVP_MD_size(long evp_md_const);
 
     // --- Message digest context functions --------------
 
-    static native long EVP_MD_CTX_create();
+    @FastNative static native long EVP_MD_CTX_create();
 
-    static native void EVP_MD_CTX_cleanup(NativeRef.EVP_MD_CTX ctx);
+    @FastNative static native void EVP_MD_CTX_cleanup(NativeRef.EVP_MD_CTX ctx);
 
-    static native void EVP_MD_CTX_destroy(long ctx);
+    @CriticalNative static native void EVP_MD_CTX_destroy(long ctx);
 
+    @FastNative
     static native int EVP_MD_CTX_copy_ex(
             NativeRef.EVP_MD_CTX dst_ctx, NativeRef.EVP_MD_CTX src_ctx);
 
     // --- Digest handling functions -------------------------------------------
 
-    static native int EVP_DigestInit_ex(NativeRef.EVP_MD_CTX ctx, long evp_md);
+    @FastNative static native int EVP_DigestInit_ex(NativeRef.EVP_MD_CTX ctx, long evp_md);
 
+    @FastNative
     static native void EVP_DigestUpdate(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native void EVP_DigestUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);
 
+    @FastNative
     static native int EVP_DigestFinal_ex(NativeRef.EVP_MD_CTX ctx, byte[] hash, int offset);
 
     // --- Signature handling functions ----------------------------------------
 
+    @FastNative
     static native long EVP_DigestSignInit(
             NativeRef.EVP_MD_CTX ctx, long evpMdRef, NativeRef.EVP_PKEY key);
 
+    @FastNative
     static native long EVP_DigestVerifyInit(
             NativeRef.EVP_MD_CTX ctx, long evpMdRef, NativeRef.EVP_PKEY key);
 
+    @FastNative
     static native void EVP_DigestSignUpdate(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native void EVP_DigestSignUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);
 
+    @FastNative
     static native void EVP_DigestVerifyUpdate(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native void EVP_DigestVerifyUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);
 
-    static native byte[] EVP_DigestSignFinal(NativeRef.EVP_MD_CTX ctx);
+    @FastNative static native byte[] EVP_DigestSignFinal(NativeRef.EVP_MD_CTX ctx);
 
+    @FastNative
     static native boolean EVP_DigestVerifyFinal(NativeRef.EVP_MD_CTX ctx, byte[] signature,
             int offset, int length) throws IndexOutOfBoundsException;
 
+    @FastNative
     static native byte[] EVP_DigestSign(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native boolean EVP_DigestVerify(NativeRef.EVP_MD_CTX ctx, byte[] sigBuffer,
             int sigOffset, int sigLen, byte[] dataBuffer, int dataOffset, int dataLen);
 
+    @FastNative
     static native long EVP_PKEY_encrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;
 
+    @FastNative
     static native int EVP_PKEY_encrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
             byte[] input, int inOffset, int inLength)
             throws IndexOutOfBoundsException, BadPaddingException;
 
+    @FastNative
     static native long EVP_PKEY_decrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;
 
+    @FastNative
     static native int EVP_PKEY_decrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
             byte[] input, int inOffset, int inLength)
             throws IndexOutOfBoundsException, BadPaddingException;
 
-    static native void EVP_PKEY_CTX_free(long pkeyCtx);
+    @FastNative static native void EVP_PKEY_CTX_free(long pkeyCtx);
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_padding(long ctx, int pad)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_pss_saltlen(long ctx, int len)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_mgf1_md(long ctx, long evpMdRef)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_oaep_md(long ctx, long evpMdRef)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_oaep_label(long ctx, byte[] label)
             throws InvalidAlgorithmParameterException;
 
     // --- Block ciphers -------------------------------------------------------
 
     // These return const references
-    static native long EVP_get_cipherbyname(String string);
+    @FastNative static native long EVP_get_cipherbyname(String string);
 
+    @FastNative
     static native void EVP_CipherInit_ex(NativeRef.EVP_CIPHER_CTX ctx, long evpCipher, byte[] key,
             byte[] iv, boolean encrypting);
 
+    @FastNative
     static native int EVP_CipherUpdate(NativeRef.EVP_CIPHER_CTX ctx, byte[] out, int outOffset,
             byte[] in, int inOffset, int inLength) throws IndexOutOfBoundsException;
 
+    @FastNative
     static native int EVP_CipherFinal_ex(NativeRef.EVP_CIPHER_CTX ctx, byte[] out, int outOffset)
             throws BadPaddingException, IllegalBlockSizeException;
 
-    static native int EVP_CIPHER_iv_length(long evpCipher);
+    @FastNative static native int EVP_CIPHER_iv_length(long evpCipher);
 
-    static native long EVP_CIPHER_CTX_new();
+    @FastNative static native long EVP_CIPHER_CTX_new();
 
-    static native int EVP_CIPHER_CTX_block_size(NativeRef.EVP_CIPHER_CTX ctx);
+    @FastNative static native int EVP_CIPHER_CTX_block_size(NativeRef.EVP_CIPHER_CTX ctx);
 
-    static native int get_EVP_CIPHER_CTX_buf_len(NativeRef.EVP_CIPHER_CTX ctx);
+    @FastNative static native int get_EVP_CIPHER_CTX_buf_len(NativeRef.EVP_CIPHER_CTX ctx);
 
-    static native boolean get_EVP_CIPHER_CTX_final_used(NativeRef.EVP_CIPHER_CTX ctx);
+    @FastNative static native boolean get_EVP_CIPHER_CTX_final_used(NativeRef.EVP_CIPHER_CTX ctx);
 
+    @FastNative
     static native void EVP_CIPHER_CTX_set_padding(
             NativeRef.EVP_CIPHER_CTX ctx, boolean enablePadding);
 
+    @FastNative
     static native void EVP_CIPHER_CTX_set_key_length(NativeRef.EVP_CIPHER_CTX ctx, int keyBitSize);
 
-    static native void EVP_CIPHER_CTX_free(long ctx);
+    @FastNative static native void EVP_CIPHER_CTX_free(long ctx);
 
     // --- AEAD ----------------------------------------------------------------
-    static native long EVP_aead_aes_128_gcm();
+    @FastNative static native long EVP_aead_aes_128_gcm();
 
-    static native long EVP_aead_aes_256_gcm();
+    @FastNative static native long EVP_aead_aes_256_gcm();
 
-    static native long EVP_aead_chacha20_poly1305();
+    @FastNative static native long EVP_aead_chacha20_poly1305();
 
-    static native long EVP_aead_aes_128_gcm_siv();
+    @FastNative static native long EVP_aead_aes_128_gcm_siv();
 
-    static native long EVP_aead_aes_256_gcm_siv();
+    @FastNative static native long EVP_aead_aes_256_gcm_siv();
 
-    static native int EVP_AEAD_max_overhead(long evpAead);
+    @FastNative static native int EVP_AEAD_max_overhead(long evpAead);
 
-    static native int EVP_AEAD_nonce_length(long evpAead);
+    @FastNative static native int EVP_AEAD_nonce_length(long evpAead);
 
+    @FastNative
     static native int EVP_AEAD_CTX_seal(long evpAead, byte[] key, int tagLengthInBytes, byte[] out,
             int outOffset, byte[] nonce, byte[] in, int inOffset, int inLength, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
-    static native int EVP_AEAD_CTX_seal_buf(long evpAead, byte[] key, int tagLengthInBytes, ByteBuffer out,
-                                            byte[] nonce, ByteBuffer input, byte[] ad)
+    @FastNative
+    static native int EVP_AEAD_CTX_seal_buf(long evpAead, byte[] key, int tagLengthInBytes,
+            ByteBuffer out, byte[] nonce, ByteBuffer input, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
+    @FastNative
     static native int EVP_AEAD_CTX_open(long evpAead, byte[] key, int tagLengthInBytes, byte[] out,
             int outOffset, byte[] nonce, byte[] in, int inOffset, int inLength, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
-    static native int EVP_AEAD_CTX_open_buf(long evpAead, byte[] key, int tagLengthInBytes, ByteBuffer out,
-                                            byte[] nonce, ByteBuffer input, byte[] ad)
+    @FastNative
+    static native int EVP_AEAD_CTX_open_buf(long evpAead, byte[] key, int tagLengthInBytes,
+            ByteBuffer out, byte[] nonce, ByteBuffer input, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
     // --- CMAC functions ------------------------------------------------------
 
-    static native long CMAC_CTX_new();
+    @FastNative static native long CMAC_CTX_new();
 
-    static native void CMAC_CTX_free(long ctx);
+    @FastNative static native void CMAC_CTX_free(long ctx);
 
-    static native void CMAC_Init(NativeRef.CMAC_CTX ctx, byte[] key);
+    @FastNative static native void CMAC_Init(NativeRef.CMAC_CTX ctx, byte[] key);
 
+    @FastNative
     static native void CMAC_Update(NativeRef.CMAC_CTX ctx, byte[] in, int inOffset, int inLength);
 
+    @FastNative
     static native void CMAC_UpdateDirect(NativeRef.CMAC_CTX ctx, long inPtr, int inLength);
 
-    static native byte[] CMAC_Final(NativeRef.CMAC_CTX ctx);
+    @FastNative static native byte[] CMAC_Final(NativeRef.CMAC_CTX ctx);
 
-    static native void CMAC_Reset(NativeRef.CMAC_CTX ctx);
+    @FastNative static native void CMAC_Reset(NativeRef.CMAC_CTX ctx);
 
     // --- HMAC functions ------------------------------------------------------
 
-    static native long HMAC_CTX_new();
+    @FastNative static native long HMAC_CTX_new();
 
-    static native void HMAC_CTX_free(long ctx);
+    @FastNative static native void HMAC_CTX_free(long ctx);
 
-    static native void HMAC_Init_ex(NativeRef.HMAC_CTX ctx, byte[] key, long evp_md);
+    @FastNative static native void HMAC_Init_ex(NativeRef.HMAC_CTX ctx, byte[] key, long evp_md);
 
+    @FastNative
     static native void HMAC_Update(NativeRef.HMAC_CTX ctx, byte[] in, int inOffset, int inLength);
 
+    @FastNative
     static native void HMAC_UpdateDirect(NativeRef.HMAC_CTX ctx, long inPtr, int inLength);
 
-    static native byte[] HMAC_Final(NativeRef.HMAC_CTX ctx);
+    @FastNative static native byte[] HMAC_Final(NativeRef.HMAC_CTX ctx);
 
-    static native void HMAC_Reset(NativeRef.HMAC_CTX ctx);
+    @FastNative static native void HMAC_Reset(NativeRef.HMAC_CTX ctx);
 
     // --- HPKE functions ------------------------------------------------------
+    @FastNative
     static native byte[] EVP_HPKE_CTX_export(
             NativeRef.EVP_HPKE_CTX ctx, byte[] exporterCtx, int length);
 
-    static native void EVP_HPKE_CTX_free(long ctx);
+    @FastNative static native void EVP_HPKE_CTX_free(long ctx);
 
+    @FastNative
     static native byte[] EVP_HPKE_CTX_open(
             NativeRef.EVP_HPKE_CTX ctx, byte[] ciphertext, byte[] aad) throws BadPaddingException;
 
+    @FastNative
     static native byte[] EVP_HPKE_CTX_seal(
             NativeRef.EVP_HPKE_CTX ctx, byte[] plaintext, byte[] aad);
 
+    @FastNative
     static native Object EVP_HPKE_CTX_setup_base_mode_recipient(
             int kem, int kdf, int aead, byte[] privateKey, byte[] enc, byte[] info);
 
     static Object EVP_HPKE_CTX_setup_base_mode_recipient(
             HpkeSuite suite, byte[] privateKey, byte[] enc, byte[] info) {
-        return EVP_HPKE_CTX_setup_base_mode_recipient(
-                suite.getKem().getId(), suite.getKdf().getId(), suite.getAead().getId(),
-                privateKey, enc, info);
+        return EVP_HPKE_CTX_setup_base_mode_recipient(suite.getKem().getId(),
+                suite.getKdf().getId(), suite.getAead().getId(), privateKey, enc, info);
     }
 
+    @FastNative
     static native Object[] EVP_HPKE_CTX_setup_base_mode_sender(
             int kem, int kdf, int aead, byte[] publicKey, byte[] info);
 
     static Object[] EVP_HPKE_CTX_setup_base_mode_sender(
             HpkeSuite suite, byte[] publicKey, byte[] info) {
-        return EVP_HPKE_CTX_setup_base_mode_sender(
-                suite.getKem().getId(), suite.getKdf().getId(), suite.getAead().getId(),
-                publicKey, info);
+        return EVP_HPKE_CTX_setup_base_mode_sender(suite.getKem().getId(), suite.getKdf().getId(),
+                suite.getAead().getId(), publicKey, info);
     }
+
+    @FastNative
     static native Object[] EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
             int kem, int kdf, int aead, byte[] publicKey, byte[] info, byte[] seed);
 
     static Object[] EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
             HpkeSuite suite, byte[] publicKey, byte[] info, byte[] seed) {
-        return EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
-                suite.getKem().getId(), suite.getKdf().getId(), suite.getAead().getId(),
-                publicKey, info, seed);
+        return EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(suite.getKem().getId(),
+                suite.getKdf().getId(), suite.getAead().getId(), publicKey, info, seed);
     }
 
     // --- RAND ----------------------------------------------------------------
 
-    static native void RAND_bytes(byte[] output);
+    @FastNative static native void RAND_bytes(byte[] output);
 
     // --- X509_NAME -----------------------------------------------------------
 
@@ -450,6 +509,7 @@ public final class NativeCrypto {
     public static int X509_NAME_hash_old(X500Principal principal) {
         return X509_NAME_hash(principal, "MD5");
     }
+
     private static int X509_NAME_hash(X500Principal principal, String algorithm) {
         try {
             byte[] digest = MessageDigest.getInstance(algorithm).digest(principal.getEncoded());
@@ -466,98 +526,117 @@ public final class NativeCrypto {
     /** Used to request get_X509_GENERAL_NAME_stack get the "altname" field. */
     static final int GN_STACK_SUBJECT_ALT_NAME = 1;
 
-    /**
-     * Used to request get_X509_GENERAL_NAME_stack get the issuerAlternativeName
-     * extension.
-     */
+    /** Used to request get_X509_GENERAL_NAME_stack get the issuerAlternativeName extension. */
     static final int GN_STACK_ISSUER_ALT_NAME = 2;
 
-    /**
-     * Used to request only non-critical types in get_X509*_ext_oids.
-     */
+    /** Used to request only non-critical types in get_X509*_ext_oids. */
     static final int EXTENSION_TYPE_NON_CRITICAL = 0;
 
-    /**
-     * Used to request only critical types in get_X509*_ext_oids.
-     */
+    /** Used to request only critical types in get_X509*_ext_oids. */
     static final int EXTENSION_TYPE_CRITICAL = 1;
 
-    static native long d2i_X509_bio(long bioCtx);
+    @FastNative static native long d2i_X509_bio(long bioCtx);
 
-    static native long d2i_X509(byte[] encoded) throws ParsingException;
+    @FastNative static native long d2i_X509(byte[] encoded) throws ParsingException;
 
-    static native long PEM_read_bio_X509(long bioCtx);
+    @FastNative static native long PEM_read_bio_X509(long bioCtx);
 
-    static native byte[] i2d_X509(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native byte[] i2d_X509(long x509ctx, OpenSSLX509Certificate holder);
 
     /** Takes an X509 context not an X509_PUBKEY context. */
-    static native byte[] i2d_X509_PUBKEY(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native byte[] i2d_X509_PUBKEY(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native byte[] ASN1_seq_pack_X509(long[] x509CertRefs);
+    @FastNative static native byte[] ASN1_seq_pack_X509(long[] x509CertRefs);
 
-    static native long[] ASN1_seq_unpack_X509_bio(long bioRef) throws ParsingException;
+    @FastNative static native long[] ASN1_seq_unpack_X509_bio(long bioRef) throws ParsingException;
 
-    static native void X509_free(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native void X509_free(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native int X509_cmp(long x509ctx1, OpenSSLX509Certificate holder, long x509ctx2, OpenSSLX509Certificate holder2);
+    @FastNative
+    static native int X509_cmp(long x509ctx1, OpenSSLX509Certificate holder, long x509ctx2,
+            OpenSSLX509Certificate holder2);
 
-    static native void X509_print_ex(long bioCtx, long x509ctx, OpenSSLX509Certificate holder, long nmflag, long certflag);
+    @FastNative
+    static native void X509_print_ex(
+            long bioCtx, long x509ctx, OpenSSLX509Certificate holder, long nmflag, long certflag);
 
+    @FastNative
     static native byte[] X509_get_issuer_name(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] X509_get_subject_name(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native String get_X509_sig_alg_oid(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] get_X509_sig_alg_parameter(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native boolean[] get_X509_issuerUID(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native boolean[] get_X509_subjectUID(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native long X509_get_pubkey(long x509ctx, OpenSSLX509Certificate holder)
             throws NoSuchAlgorithmException, InvalidKeyException;
 
+    @FastNative
     static native String get_X509_pubkey_oid(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] X509_get_ext_oid(long x509ctx, OpenSSLX509Certificate holder, String oid);
 
-    static native String[] get_X509_ext_oids(long x509ctx, OpenSSLX509Certificate holder, int critical);
+    @FastNative
+    static native String[] get_X509_ext_oids(
+            long x509ctx, OpenSSLX509Certificate holder, int critical);
 
-    static native Object[][] get_X509_GENERAL_NAME_stack(long x509ctx, OpenSSLX509Certificate holder, int type)
-            throws CertificateParsingException;
+    @FastNative
+    static native Object[][] get_X509_GENERAL_NAME_stack(long x509ctx,
+            OpenSSLX509Certificate holder, int type) throws CertificateParsingException;
 
+    @FastNative
     static native boolean[] get_X509_ex_kusage(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native String[] get_X509_ex_xkusage(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native int get_X509_ex_pathlen(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native int get_X509_ex_pathlen(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native long X509_get_notBefore(long x509ctx, OpenSSLX509Certificate holder)
             throws ParsingException;
 
+    @FastNative
     static native long X509_get_notAfter(long x509ctx, OpenSSLX509Certificate holder)
             throws ParsingException;
 
-    static native long X509_get_version(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native long X509_get_version(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] X509_get_serialNumber(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native void X509_verify(long x509ctx, OpenSSLX509Certificate holder, NativeRef.EVP_PKEY pkeyCtx)
-            throws BadPaddingException, IllegalBlockSizeException;
-
-    static native byte[] get_X509_tbs_cert(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative
+    static native void X509_verify(long x509ctx, OpenSSLX509Certificate holder,
+            NativeRef.EVP_PKEY pkeyCtx) throws BadPaddingException, IllegalBlockSizeException;
 
+    @FastNative static native byte[] get_X509_tbs_cert(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native byte[] get_X509_tbs_cert_without_ext(long x509ctx, OpenSSLX509Certificate holder, String oid);
+    @FastNative
+    static native byte[] get_X509_tbs_cert_without_ext(
+            long x509ctx, OpenSSLX509Certificate holder, String oid);
 
+    @FastNative
     static native byte[] get_X509_signature(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native int get_X509_ex_flags(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native int get_X509_ex_flags(long x509ctx, OpenSSLX509Certificate holder);
 
     // Used by Android platform TrustedCertificateStore.
     @SuppressWarnings("unused")
-    static native int X509_check_issued(long ctx, OpenSSLX509Certificate holder, long ctx2, OpenSSLX509Certificate holder2);
+    @FastNative
+    static native int X509_check_issued(
+            long ctx, OpenSSLX509Certificate holder, long ctx2, OpenSSLX509Certificate holder2);
 
     // --- PKCS7 ---------------------------------------------------------------
 
@@ -568,250 +647,248 @@ public final class NativeCrypto {
     static final int PKCS7_CRLS = 2;
 
     /** Returns an array of X509 or X509_CRL pointers. */
-    static native long[] d2i_PKCS7_bio(long bioCtx, int which) throws ParsingException;
+    @FastNative static native long[] d2i_PKCS7_bio(long bioCtx, int which) throws ParsingException;
 
     /** Returns an array of X509 or X509_CRL pointers. */
-    static native byte[] i2d_PKCS7(long[] certs);
+    @FastNative static native byte[] i2d_PKCS7(long[] certs);
 
     /** Returns an array of X509 or X509_CRL pointers. */
-    static native long[] PEM_read_bio_PKCS7(long bioCtx, int which);
+    @FastNative static native long[] PEM_read_bio_PKCS7(long bioCtx, int which);
 
     // --- X509_CRL ------------------------------------------------------------
 
-    static native long d2i_X509_CRL_bio(long bioCtx);
+    @FastNative static native long d2i_X509_CRL_bio(long bioCtx);
 
-    static native long PEM_read_bio_X509_CRL(long bioCtx);
+    @FastNative static native long PEM_read_bio_X509_CRL(long bioCtx);
 
-    static native byte[] i2d_X509_CRL(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native byte[] i2d_X509_CRL(long x509CrlCtx, OpenSSLX509CRL holder);
 
-    static native void X509_CRL_free(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native void X509_CRL_free(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native void X509_CRL_print(long bioCtx, long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native String get_X509_CRL_sig_alg_oid(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native byte[] get_X509_CRL_sig_alg_parameter(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native byte[] X509_CRL_get_issuer_name(long x509CrlCtx, OpenSSLX509CRL holder);
 
     /** Returns X509_REVOKED reference that is not duplicated! */
-    static native long X509_CRL_get0_by_cert(long x509CrlCtx, OpenSSLX509CRL holder, long x509Ctx, OpenSSLX509Certificate holder2);
+    @FastNative
+    static native long X509_CRL_get0_by_cert(
+            long x509CrlCtx, OpenSSLX509CRL holder, long x509Ctx, OpenSSLX509Certificate holder2);
 
     /** Returns X509_REVOKED reference that is not duplicated! */
-    static native long X509_CRL_get0_by_serial(long x509CrlCtx, OpenSSLX509CRL holder, byte[] serial);
+    @FastNative
+    static native long X509_CRL_get0_by_serial(
+            long x509CrlCtx, OpenSSLX509CRL holder, byte[] serial);
 
     /** Returns an array of X509_REVOKED that are owned by the caller. */
-    static native long[] X509_CRL_get_REVOKED(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native long[] X509_CRL_get_REVOKED(long x509CrlCtx, OpenSSLX509CRL holder);
 
-    static native String[] get_X509_CRL_ext_oids(long x509Crlctx, OpenSSLX509CRL holder, int critical);
+    @FastNative
+    static native String[] get_X509_CRL_ext_oids(
+            long x509Crlctx, OpenSSLX509CRL holder, int critical);
 
+    @FastNative
     static native byte[] X509_CRL_get_ext_oid(long x509CrlCtx, OpenSSLX509CRL holder, String oid);
 
-    static native long X509_CRL_get_version(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native long X509_CRL_get_version(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native long X509_CRL_get_ext(long x509CrlCtx, OpenSSLX509CRL holder, String oid);
 
-    static native byte[] get_X509_CRL_signature(long x509ctx, OpenSSLX509CRL holder);
+    @FastNative static native byte[] get_X509_CRL_signature(long x509ctx, OpenSSLX509CRL holder);
 
-    static native void X509_CRL_verify(long x509CrlCtx, OpenSSLX509CRL holder,
-        NativeRef.EVP_PKEY pkeyCtx) throws BadPaddingException, SignatureException,
-        NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException;
+    @FastNative
+    static native void X509_CRL_verify(
+            long x509CrlCtx, OpenSSLX509CRL holder, NativeRef.EVP_PKEY pkeyCtx)
+            throws BadPaddingException, SignatureException, NoSuchAlgorithmException,
+                   InvalidKeyException, IllegalBlockSizeException;
 
-    static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native long X509_CRL_get_lastUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
             throws ParsingException;
 
+    @FastNative
     static native long X509_CRL_get_nextUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
             throws ParsingException;
 
     // --- X509_REVOKED --------------------------------------------------------
 
-    static native long X509_REVOKED_dup(long x509RevokedCtx);
+    @FastNative static native long X509_REVOKED_dup(long x509RevokedCtx);
 
-    static native byte[] i2d_X509_REVOKED(long x509RevokedCtx);
+    @FastNative static native byte[] i2d_X509_REVOKED(long x509RevokedCtx);
 
-    static native String[] get_X509_REVOKED_ext_oids(long x509ctx, int critical);
+    @FastNative static native String[] get_X509_REVOKED_ext_oids(long x509ctx, int critical);
 
-    static native byte[] X509_REVOKED_get_ext_oid(long x509RevokedCtx, String oid);
+    @FastNative static native byte[] X509_REVOKED_get_ext_oid(long x509RevokedCtx, String oid);
 
-    static native byte[] X509_REVOKED_get_serialNumber(long x509RevokedCtx);
+    @FastNative static native byte[] X509_REVOKED_get_serialNumber(long x509RevokedCtx);
 
-    static native long X509_REVOKED_get_ext(long x509RevokedCtx, String oid);
+    @FastNative static native long X509_REVOKED_get_ext(long x509RevokedCtx, String oid);
 
     /** Returns ASN1_TIME reference. */
-    static native long get_X509_REVOKED_revocationDate(long x509RevokedCtx);
+    @FastNative static native long get_X509_REVOKED_revocationDate(long x509RevokedCtx);
 
-    static native void X509_REVOKED_print(long bioRef, long x509RevokedCtx);
+    @FastNative static native void X509_REVOKED_print(long bioRef, long x509RevokedCtx);
 
     // --- X509_EXTENSION ------------------------------------------------------
 
-    static native int X509_supported_extension(long x509ExtensionRef);
+    @FastNative static native int X509_supported_extension(long x509ExtensionRef);
 
     // --- SPAKE ---------------------------------------------------------------
 
     /**
-     * Sets the SPAKE credential for the given SSL context using a password.
-     * Used for both client and server.
+     * Sets the SPAKE credential for the given SSL context using a password. Used for both client
+     * and server.
      */
-    static native void SSL_CTX_set_spake_credential(
-            byte[] context,
-            byte[] pw_array,
-            byte[] id_prover_array,
-            byte[] id_verifier_array,
-            boolean is_client,
-            int handshake_limit,
-            long ssl_ctx,
-            AbstractSessionContext holder)
-        throws SSLException;
+    @FastNative
+    static native void SSL_CTX_set_spake_credential(byte[] context, byte[] pw_array,
+            byte[] id_prover_array, byte[] id_verifier_array, boolean is_client,
+            int handshake_limit, long ssl_ctx, AbstractSessionContext holder) throws SSLException;
 
     // --- ASN1_TIME -----------------------------------------------------------
 
-    static native void ASN1_TIME_to_Calendar(long asn1TimeCtx, Calendar cal) throws ParsingException;
+    @FastNative
+    static native void ASN1_TIME_to_Calendar(long asn1TimeCtx, Calendar cal)
+            throws ParsingException;
 
     // --- ASN1 Encoding -------------------------------------------------------
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_read_* functions to read the ASN.1-encoded data in val.  The returned object must
-     * be freed after use by calling asn1_read_free.
+     * asn1_read_* functions to read the ASN.1-encoded data in val. The returned object must be
+     * freed after use by calling asn1_read_free.
      */
-    static native long asn1_read_init(byte[] val) throws IOException;
+    @FastNative static native long asn1_read_init(byte[] val) throws IOException;
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_read_* functions to read the ASN.1 sequence pointed to by cbsRef.  The returned
-     * object must be freed after use by calling asn1_read_free.
+     * asn1_read_* functions to read the ASN.1 sequence pointed to by cbsRef. The returned object
+     * must be freed after use by calling asn1_read_free.
      */
-    static native long asn1_read_sequence(long cbsRef) throws IOException;
+    @FastNative static native long asn1_read_sequence(long cbsRef) throws IOException;
 
     /**
-     * Returns whether the next object in the given reference is explicitly tagged with the
-     * given tag number.
+     * Returns whether the next object in the given reference is explicitly tagged with the given
+     * tag number.
      */
+    @FastNative
     static native boolean asn1_read_next_tag_is(long cbsRef, int tag) throws IOException;
 
     /**
-     * Allocates and returns an opaque reference to an object that can be used with
-     * other asn1_read_* functions to read the ASN.1 data pointed to by cbsRef.  The returned
-     * object must be freed after use by calling asn1_read_free.
+     * Allocates and returns an opaque reference to an object that can be used with other
+     * asn1_read_* functions to read the ASN.1 data pointed to by cbsRef. The returned object must
+     * be freed after use by calling asn1_read_free.
      */
-    static native long asn1_read_tagged(long cbsRef) throws IOException;
+    @FastNative static native long asn1_read_tagged(long cbsRef) throws IOException;
 
-    /**
-     * Returns the contents of an ASN.1 octet string from the given reference.
-     */
-    static native byte[] asn1_read_octetstring(long cbsRef) throws IOException;
+    /** Returns the contents of an ASN.1 octet string from the given reference. */
+    @FastNative static native byte[] asn1_read_octetstring(long cbsRef) throws IOException;
 
     /**
-     * Returns an ASN.1 integer from the given reference.  If the integer doesn't fit
-     * in a uint64, this method will throw an IOException.
+     * Returns an ASN.1 integer from the given reference. If the integer doesn't fit in a uint64,
+     * this method will throw an IOException.
      */
-    static native long asn1_read_uint64(long cbsRef) throws IOException;
+    @FastNative static native long asn1_read_uint64(long cbsRef) throws IOException;
 
-    /**
-     * Consumes an ASN.1 NULL from the given reference.
-     */
-    static native void asn1_read_null(long cbsRef) throws IOException;
+    /** Consumes an ASN.1 NULL from the given reference. */
+    @FastNative static native void asn1_read_null(long cbsRef) throws IOException;
 
     /**
      * Returns an ASN.1 OID in dotted-decimal notation (eg, "1.3.14.3.2.26" for SHA-1) from the
      * given reference.
      */
-    static native String asn1_read_oid(long cbsRef) throws IOException;
+    @FastNative static native String asn1_read_oid(long cbsRef) throws IOException;
 
-    /**
-     * Returns whether or not the given reference has been read completely.
-     */
-    static native boolean asn1_read_is_empty(long cbsRef);
+    /** Returns whether or not the given reference has been read completely. */
+    @FastNative static native boolean asn1_read_is_empty(long cbsRef);
 
     /**
-     * Frees any resources associated with the given reference.  After calling, the reference
-     * must not be used again.  This may be called with a zero reference, in which case nothing
-     * will be done.
+     * Frees any resources associated with the given reference. After calling, the reference must
+     * not be used again. This may be called with a zero reference, in which case nothing will be
+     * done.
      */
-    static native void asn1_read_free(long cbsRef);
+    @FastNative static native void asn1_read_free(long cbsRef);
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_write_* functions to write ASN.1-encoded data.  The returned object must be finalized
-     * after use by calling either asn1_write_finish or asn1_write_cleanup, and its resources
-     * must be freed by calling asn1_write_free.
+     * asn1_write_* functions to write ASN.1-encoded data. The returned object must be finalized
+     * after use by calling either asn1_write_finish or asn1_write_cleanup, and its resources must
+     * be freed by calling asn1_write_free.
      */
-    static native long asn1_write_init() throws IOException;
+    @FastNative static native long asn1_write_init() throws IOException;
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_write_* functions to write an ASN.1 sequence into the given reference.  The returned
-     * reference may only be used until the next call on the parent reference.  The returned
-     * object must be freed after use by calling asn1_write_free.
+     * asn1_write_* functions to write an ASN.1 sequence into the given reference. The returned
+     * reference may only be used until the next call on the parent reference. The returned object
+     * must be freed after use by calling asn1_write_free.
      */
-    static native long asn1_write_sequence(long cbbRef) throws IOException;
+    @FastNative static native long asn1_write_sequence(long cbbRef) throws IOException;
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_write_* functions to write a explicitly-tagged ASN.1 object with the given tag
-     * into the given reference. The returned reference may only be used until the next
-     * call on the parent reference.  The returned object must be freed after use by
-     * calling asn1_write_free.
+     * asn1_write_* functions to write a explicitly-tagged ASN.1 object with the given tag into the
+     * given reference. The returned reference may only be used until the next call on the parent
+     * reference. The returned object must be freed after use by calling asn1_write_free.
      */
-    static native long asn1_write_tag(long cbbRef, int tag) throws IOException;
+    @FastNative static native long asn1_write_tag(long cbbRef, int tag) throws IOException;
 
-    /**
-     * Writes the given data into the given reference as an ASN.1-encoded octet string.
-     */
+    /** Writes the given data into the given reference as an ASN.1-encoded octet string. */
+    @FastNative
     static native void asn1_write_octetstring(long cbbRef, byte[] data) throws IOException;
 
-    /**
-     * Writes the given value into the given reference as an ASN.1-encoded integer.
-     */
-    static native void asn1_write_uint64(long cbbRef, long value) throws IOException;
+    /** Writes the given value into the given reference as an ASN.1-encoded integer. */
+    @FastNative static native void asn1_write_uint64(long cbbRef, long value) throws IOException;
 
-    /**
-     * Writes a NULL value into the given reference.
-     */
-    static native void asn1_write_null(long cbbRef) throws IOException;
+    /** Writes a NULL value into the given reference. */
+    @FastNative static native void asn1_write_null(long cbbRef) throws IOException;
 
-    /**
-     * Writes the given OID (which must be in dotted-decimal notation) into the given reference.
-     */
-    static native void asn1_write_oid(long cbbRef, String oid) throws IOException;
+    /** Writes the given OID (which must be in dotted-decimal notation) into the given reference. */
+    @FastNative static native void asn1_write_oid(long cbbRef, String oid) throws IOException;
 
     /**
      * Flushes the given reference, invalidating any child references and completing their
-     * operations.  This must be called if the child references are to be freed before
-     * asn1_write_finish is called on the ultimate parent.  The child references must still
-     * be freed.
+     * operations. This must be called if the child references are to be freed before
+     * asn1_write_finish is called on the ultimate parent. The child references must still be freed.
      */
-    static native void asn1_write_flush(long cbbRef) throws IOException;
+    @FastNative static native void asn1_write_flush(long cbbRef) throws IOException;
 
     /**
-     * Completes any in-progress operations and returns the ASN.1-encoded data.  Either this
-     * or asn1_write_cleanup must be called on any reference returned from asn1_write_init
-     * before it is freed.
+     * Completes any in-progress operations and returns the ASN.1-encoded data. Either this or
+     * asn1_write_cleanup must be called on any reference returned from asn1_write_init before it is
+     * freed.
      */
-    static native byte[] asn1_write_finish(long cbbRef) throws IOException;
+    @FastNative static native byte[] asn1_write_finish(long cbbRef) throws IOException;
 
     /**
-     * Cleans up intermediate state in the given reference.  Either this or asn1_write_finish
-     * must be called on any reference returned from asn1_write_init before it is freed.
+     * Cleans up intermediate state in the given reference. Either this or asn1_write_finish must be
+     * called on any reference returned from asn1_write_init before it is freed.
      */
-    static native void asn1_write_cleanup(long cbbRef);
+    @FastNative static native void asn1_write_cleanup(long cbbRef);
 
     /**
-     * Frees resources associated with the given reference.  After calling, the reference
-     * must not be used again.  This may be called with a zero reference, in which case nothing
-     * will be done.
+     * Frees resources associated with the given reference. After calling, the reference must not be
+     * used again. This may be called with a zero reference, in which case nothing will be done.
      */
-    static native void asn1_write_free(long cbbRef);
+    @FastNative static native void asn1_write_free(long cbbRef);
 
     // --- BIO stream creation -------------------------------------------------
 
+    @FastNative
     static native long create_BIO_InputStream(OpenSSLBIOInputStream is, boolean isFinite);
 
-    static native long create_BIO_OutputStream(OutputStream os);
+    @FastNative static native long create_BIO_OutputStream(OutputStream os);
 
-    static native void BIO_free_all(long bioRef);
+    @FastNative static native void BIO_free_all(long bioRef);
 
     // --- SSL handling --------------------------------------------------------
 
@@ -836,27 +913,22 @@ public final class NativeCrypto {
     // OpenSSL-style names.
     private static final Set<String> SUPPORTED_LEGACY_CIPHER_SUITES_SET = new HashSet<String>();
 
-    static final Set<String> SUPPORTED_TLS_1_3_CIPHER_SUITES_SET = new HashSet<String>(
-            Arrays.asList(SUPPORTED_TLS_1_3_CIPHER_SUITES));
+    static final Set<String> SUPPORTED_TLS_1_3_CIPHER_SUITES_SET =
+            new HashSet<String>(Arrays.asList(SUPPORTED_TLS_1_3_CIPHER_SUITES));
 
     /**
-     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV is RFC 5746's renegotiation
-     * indication signaling cipher suite value. It is not a real
-     * cipher suite. It is just an indication in the default and
-     * supported cipher suite lists indicates that the implementation
-     * supports secure renegotiation.
-     * <p>
-     * In the RI, its presence means that the SCSV is sent in the
-     * cipher suite list to indicate secure renegotiation support and
-     * its absense means to send an empty TLS renegotiation info
+     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV is RFC 5746's renegotiation indication signaling cipher
+     * suite value. It is not a real cipher suite. It is just an indication in the default and
+     * supported cipher suite lists indicates that the implementation supports secure renegotiation.
+     *
+     * <p>In the RI, its presence means that the SCSV is sent in the cipher suite list to indicate
+     * secure renegotiation support and its absense means to send an empty TLS renegotiation info
      * extension instead.
-     * <p>
-     * However, OpenSSL doesn't provide an API to give this level of
-     * control, instead always sending the SCSV and always including
-     * the empty renegotiation info if TLS is used (as opposed to
-     * SSL). So we simply allow TLS_EMPTY_RENEGOTIATION_INFO_SCSV to
-     * be passed for compatibility as to provide the hint that we
-     * support secure renegotiation.
+     *
+     * <p>However, OpenSSL doesn't provide an API to give this level of control, instead always
+     * sending the SCSV and always including the empty renegotiation info if TLS is used (as opposed
+     * to SSL). So we simply allow TLS_EMPTY_RENEGOTIATION_INFO_SCSV to be passed for compatibility
+     * as to provide the hint that we support secure renegotiation.
      */
     static final String TLS_EMPTY_RENEGOTIATION_INFO_SCSV = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
 
@@ -876,15 +948,14 @@ public final class NativeCrypto {
     }
 
     /**
-     * TLS_FALLBACK_SCSV is from
-     * https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00
-     * to indicate to the server that this is a fallback protocol
-     * request.
+     * TLS_FALLBACK_SCSV is from https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00 to
+     * indicate to the server that this is a fallback protocol request.
      */
     private static final String TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV";
 
     private static final boolean HAS_AES_HARDWARE;
     private static final String[] SUPPORTED_TLS_1_2_CIPHER_SUITES;
+
     static {
         if (loadError == null) {
             // If loadError is not null, it means the native code was not loaded, so
@@ -918,12 +989,12 @@ public final class NativeCrypto {
     }
 
     /**
-     * Returns 1 if the BoringSSL believes the CPU has AES accelerated hardware
-     * instructions. Used to determine cipher suite ordering.
+     * Returns 1 if the BoringSSL believes the CPU has AES accelerated hardware instructions. Used
+     * to determine cipher suite ordering.
      */
-    static native int EVP_has_aes_hardware();
+    @CriticalNative static native int EVP_has_aes_hardware();
 
-    static native long SSL_CTX_new();
+    @FastNative static native long SSL_CTX_new();
 
     // IMPLEMENTATION NOTE: The default list of cipher suites is a trade-off between what we'd like
     // to use and what servers currently support. We strive to be secure enough by default. We thus
@@ -944,39 +1015,40 @@ public final class NativeCrypto {
     // prevent apps from connecting to servers they were previously able to connect to.
 
     /** X.509 based cipher suites enabled by default (if requested), in preference order. */
-    static final String[] DEFAULT_X509_CIPHER_SUITES = HAS_AES_HARDWARE ?
-            new String[] {
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
-                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_RSA_WITH_AES_256_CBC_SHA",
-            } :
-            new String[] {
-                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
-                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_RSA_WITH_AES_256_CBC_SHA",
-            };
+    static final String[] DEFAULT_X509_CIPHER_SUITES =
+            HAS_AES_HARDWARE
+                    ? new String[] {
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
+                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_RSA_WITH_AES_256_CBC_SHA",
+                    }
+                    : new String[] {
+                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
+                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_RSA_WITH_AES_256_CBC_SHA",
+                    };
 
     /** TLS-PSK cipher suites enabled by default (if requested), in preference order. */
     static final String[] DEFAULT_PSK_CIPHER_SUITES = new String[] {
@@ -993,22 +1065,33 @@ public final class NativeCrypto {
     };
 
     static String[] getSupportedCipherSuites() {
-        return SSLUtils.concat(SUPPORTED_TLS_1_3_CIPHER_SUITES, SUPPORTED_TLS_1_2_CIPHER_SUITES.clone());
+        return SSLUtils.concat(
+                SUPPORTED_TLS_1_3_CIPHER_SUITES, SUPPORTED_TLS_1_2_CIPHER_SUITES.clone());
     }
 
-    static native void SSL_CTX_free(long ssl_ctx, AbstractSessionContext holder);
+    @FastNative static native void SSL_CTX_free(long ssl_ctx, AbstractSessionContext holder);
 
-    static native void SSL_CTX_set_session_id_context(long ssl_ctx, AbstractSessionContext holder, byte[] sid_ctx);
+    @FastNative
+    static native void SSL_CTX_set_session_id_context(
+            long ssl_ctx, AbstractSessionContext holder, byte[] sid_ctx);
 
-    static native long SSL_CTX_set_timeout(long ssl_ctx, AbstractSessionContext holder, long seconds);
+    @FastNative
+    static native long SSL_CTX_set_timeout(
+            long ssl_ctx, AbstractSessionContext holder, long seconds);
 
+    @FastNative
     static native long SSL_new(long ssl_ctx, AbstractSessionContext holder) throws SSLException;
 
-    static native void SSL_enable_tls_channel_id(long ssl, NativeSsl ssl_holder) throws SSLException;
+    @FastNative
+    static native void SSL_enable_tls_channel_id(long ssl, NativeSsl ssl_holder)
+            throws SSLException;
 
+    @FastNative
     static native byte[] SSL_get_tls_channel_id(long ssl, NativeSsl ssl_holder) throws SSLException;
 
-    static native void SSL_set1_tls_channel_id(long ssl, NativeSsl ssl_holder, NativeRef.EVP_PKEY pkey);
+    @FastNative
+    static native void SSL_set1_tls_channel_id(
+            long ssl, NativeSsl ssl_holder, NativeRef.EVP_PKEY pkey);
 
     /**
      * Sets the local certificates and private key.
@@ -1018,75 +1101,92 @@ public final class NativeCrypto {
      * @param pkey a reference to the private key.
      * @throws SSLException if a problem occurs setting the cert/key.
      */
-    static native void setLocalCertsAndPrivateKey(long ssl, NativeSsl ssl_holder, byte[][] encodedCertificates,
-        NativeRef.EVP_PKEY pkey) throws SSLException;
+    @FastNative
+    static native void setLocalCertsAndPrivateKey(long ssl, NativeSsl ssl_holder,
+            byte[][] encodedCertificates, NativeRef.EVP_PKEY pkey) throws SSLException;
 
-    static native void SSL_set_client_CA_list(long ssl, NativeSsl ssl_holder, byte[][] asn1DerEncodedX500Principals)
-            throws SSLException;
+    @FastNative
+    static native void SSL_set_client_CA_list(long ssl, NativeSsl ssl_holder,
+            byte[][] asn1DerEncodedX500Principals) throws SSLException;
 
-    static native long SSL_set_mode(long ssl, NativeSsl ssl_holder, long mode);
+    @FastNative static native long SSL_set_mode(long ssl, NativeSsl ssl_holder, long mode);
 
-    static native long SSL_set_options(long ssl, NativeSsl ssl_holder, long options);
+    @FastNative static native long SSL_set_options(long ssl, NativeSsl ssl_holder, long options);
 
-    static native long SSL_clear_options(long ssl, NativeSsl ssl_holder, long options);
+    @FastNative static native long SSL_clear_options(long ssl, NativeSsl ssl_holder, long options);
 
-    static native int SSL_set_protocol_versions(long ssl, NativeSsl ssl_holder, int min_version, int max_version);
+    @FastNative
+    static native int SSL_set_protocol_versions(
+            long ssl, NativeSsl ssl_holder, int min_version, int max_version);
 
+    @FastNative
     static native void SSL_enable_signed_cert_timestamps(long ssl, NativeSsl ssl_holder);
 
+    @FastNative
     static native byte[] SSL_get_signed_cert_timestamp_list(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_set_signed_cert_timestamp_list(long ssl, NativeSsl ssl_holder, byte[] list);
+    @FastNative
+    static native void SSL_set_signed_cert_timestamp_list(
+            long ssl, NativeSsl ssl_holder, byte[] list);
 
-    static native void SSL_enable_ocsp_stapling(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_enable_ocsp_stapling(long ssl, NativeSsl ssl_holder);
 
-    static native byte[] SSL_get_ocsp_response(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] SSL_get_ocsp_response(long ssl, NativeSsl ssl_holder);
 
+    @FastNative
     static native void SSL_set_ocsp_response(long ssl, NativeSsl ssl_holder, byte[] response);
 
-    static native byte[] SSL_get_tls_unique(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] SSL_get_tls_unique(long ssl, NativeSsl ssl_holder);
 
-    static native byte[] SSL_export_keying_material(long ssl, NativeSsl ssl_holder, byte[] label, byte[] context, int num_bytes) throws SSLException;
+    @FastNative
+    static native byte[] SSL_export_keying_material(long ssl, NativeSsl ssl_holder, byte[] label,
+            byte[] context, int num_bytes) throws SSLException;
 
-    static native void SSL_use_psk_identity_hint(long ssl, NativeSsl ssl_holder, String identityHint) throws SSLException;
+    @FastNative
+    static native void SSL_use_psk_identity_hint(
+            long ssl, NativeSsl ssl_holder, String identityHint) throws SSLException;
 
-    static native void set_SSL_psk_client_callback_enabled(long ssl, NativeSsl ssl_holder, boolean enabled);
+    @FastNative
+    static native void set_SSL_psk_client_callback_enabled(
+            long ssl, NativeSsl ssl_holder, boolean enabled);
 
-    static native void set_SSL_psk_server_callback_enabled(long ssl, NativeSsl ssl_holder, boolean enabled);
+    @FastNative
+    static native void set_SSL_psk_server_callback_enabled(
+            long ssl, NativeSsl ssl_holder, boolean enabled);
 
     public static void setTlsV1DeprecationStatus(boolean deprecated, boolean supported) {
         if (deprecated) {
             TLSV12_PROTOCOLS = new String[] {
-                SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
             };
             TLSV13_PROTOCOLS = new String[] {
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         } else {
             TLSV12_PROTOCOLS = new String[] {
-                DEPRECATED_PROTOCOL_TLSV1,
-                DEPRECATED_PROTOCOL_TLSV1_1,
-                SUPPORTED_PROTOCOL_TLSV1_2,
+                    DEPRECATED_PROTOCOL_TLSV1,
+                    DEPRECATED_PROTOCOL_TLSV1_1,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
             };
             TLSV13_PROTOCOLS = new String[] {
-                DEPRECATED_PROTOCOL_TLSV1,
-                DEPRECATED_PROTOCOL_TLSV1_1,
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    DEPRECATED_PROTOCOL_TLSV1,
+                    DEPRECATED_PROTOCOL_TLSV1_1,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         }
         if (supported) {
             SUPPORTED_PROTOCOLS = new String[] {
-                DEPRECATED_PROTOCOL_TLSV1,
-                DEPRECATED_PROTOCOL_TLSV1_1,
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    DEPRECATED_PROTOCOL_TLSV1,
+                    DEPRECATED_PROTOCOL_TLSV1_1,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         } else {
             SUPPORTED_PROTOCOLS = new String[] {
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         }
     }
@@ -1122,6 +1222,7 @@ public final class NativeCrypto {
     private static class Range {
         public final String min;
         public final String max;
+
         public Range(String min, String max) {
             this.min = min;
             this.max = max;
@@ -1158,7 +1259,7 @@ public final class NativeCrypto {
         checkEnabledProtocols(protocols);
         Range range = getProtocolRange(protocols);
         SSL_set_protocol_versions(
-            ssl, ssl_holder, getProtocolConstant(range.min), getProtocolConstant(range.max));
+                ssl, ssl_holder, getProtocolConstant(range.min), getProtocolConstant(range.max));
     }
 
     private static int getProtocolConstant(String protocol) {
@@ -1190,6 +1291,7 @@ public final class NativeCrypto {
         return protocols;
     }
 
+    @FastNative
     static native void SSL_set_cipher_lists(long ssl, NativeSsl ssl_holder, String[] ciphers);
 
     /**
@@ -1197,10 +1299,10 @@ public final class NativeCrypto {
      *
      * @return array of {@code SSL_CIPHER} references.
      */
-    static native long[] SSL_get_ciphers(long ssl, NativeSsl ssl_holder);
+    @FastNative static native long[] SSL_get_ciphers(long ssl, NativeSsl ssl_holder);
 
-    static void setEnabledCipherSuites(long ssl, NativeSsl ssl_holder, String[] cipherSuites,
-            String[] protocols) {
+    static void setEnabledCipherSuites(
+            long ssl, NativeSsl ssl_holder, String[] cipherSuites, String[] protocols) {
         checkEnabledCipherSuites(cipherSuites);
         String maxProtocol = getProtocolRange(protocols).max;
         List<String> opensslSuites = new ArrayList<String>();
@@ -1214,13 +1316,14 @@ public final class NativeCrypto {
             // for more discussion.
             if (cipherSuite.equals(TLS_FALLBACK_SCSV)
                     && (maxProtocol.equals(DEPRECATED_PROTOCOL_TLSV1)
-                        || maxProtocol.equals(DEPRECATED_PROTOCOL_TLSV1_1))) {
+                            || maxProtocol.equals(DEPRECATED_PROTOCOL_TLSV1_1))) {
                 SSL_set_mode(ssl, ssl_holder, NativeConstants.SSL_MODE_SEND_FALLBACK_SCSV);
                 continue;
             }
             opensslSuites.add(cipherSuiteFromJava(cipherSuite));
         }
-        SSL_set_cipher_lists(ssl, ssl_holder, opensslSuites.toArray(new String[opensslSuites.size()]));
+        SSL_set_cipher_lists(
+                ssl, ssl_holder, opensslSuites.toArray(new String[opensslSuites.size()]));
     }
 
     static String[] checkEnabledCipherSuites(String[] cipherSuites) {
@@ -1257,94 +1360,100 @@ public final class NativeCrypto {
         return cipherSuites;
     }
 
-    static native void SSL_set_accept_state(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_set_accept_state(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_set_connect_state(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_set_connect_state(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_set_verify(long ssl, NativeSsl ssl_holder, int mode);
+    @FastNative static native void SSL_set_verify(long ssl, NativeSsl ssl_holder, int mode);
 
+    @FastNative
     static native void SSL_set_session(long ssl, NativeSsl ssl_holder, long sslSessionNativePointer)
             throws SSLException;
 
+    @FastNative
     static native void SSL_set_session_creation_enabled(
             long ssl, NativeSsl ssl_holder, boolean creationEnabled) throws SSLException;
 
-    static native boolean SSL_session_reused(long ssl, NativeSsl ssl_holder);
+    @FastNative static native boolean SSL_session_reused(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_accept_renegotiations(long ssl, NativeSsl ssl_holder) throws SSLException;
+    @FastNative
+    static native void SSL_accept_renegotiations(long ssl, NativeSsl ssl_holder)
+            throws SSLException;
 
+    @FastNative
     static native void SSL_set_tlsext_host_name(long ssl, NativeSsl ssl_holder, String hostname)
             throws SSLException;
-    static native String SSL_get_servername(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_do_handshake(
-            long ssl, NativeSsl ssl_holder, FileDescriptor fd, SSLHandshakeCallbacks shc, int timeoutMillis)
+    @FastNative static native String SSL_get_servername(long ssl, NativeSsl ssl_holder);
+
+    static native void SSL_do_handshake(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
+            SSLHandshakeCallbacks shc, int timeoutMillis)
             throws SSLException, SocketTimeoutException, CertificateException;
 
-    public static native String SSL_get_current_cipher(long ssl, NativeSsl ssl_holder);
+    @FastNative public static native String SSL_get_current_cipher(long ssl, NativeSsl ssl_holder);
 
-    public static native String SSL_get_version(long ssl, NativeSsl ssl_holder);
+    @FastNative public static native String SSL_get_version(long ssl, NativeSsl ssl_holder);
 
-    /**
-     * Returns the peer certificate chain.
-     */
-    static native byte[][] SSL_get0_peer_certificates(long ssl, NativeSsl ssl_holder);
+    /** Returns the peer certificate chain. */
+    @FastNative static native byte[][] SSL_get0_peer_certificates(long ssl, NativeSsl ssl_holder);
 
     /**
      * Reads with the native SSL_read function from the encrypted data stream
+     *
      * @return -1 if error or the end of the stream is reached.
      */
-    static native int SSL_read(long ssl, NativeSsl ssl_holder, FileDescriptor fd, SSLHandshakeCallbacks shc,
-            byte[] b, int off, int len, int readTimeoutMillis) throws IOException;
+    static native int SSL_read(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
+            SSLHandshakeCallbacks shc, byte[] b, int off, int len, int readTimeoutMillis)
+            throws IOException;
 
-    /**
-     * Writes with the native SSL_write function to the encrypted data stream.
-     */
+    /** Writes with the native SSL_write function to the encrypted data stream. */
     static native void SSL_write(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
             SSLHandshakeCallbacks shc, byte[] b, int off, int len, int writeTimeoutMillis)
             throws IOException;
 
-    static native void SSL_interrupt(long ssl, NativeSsl ssl_holder);
-    static native void SSL_shutdown(
-            long ssl, NativeSsl ssl_holder, FileDescriptor fd, SSLHandshakeCallbacks shc) throws IOException;
+    @FastNative static native void SSL_interrupt(long ssl, NativeSsl ssl_holder);
 
-    static native int SSL_get_shutdown(long ssl, NativeSsl ssl_holder);
+    static native void SSL_shutdown(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
+            SSLHandshakeCallbacks shc) throws IOException;
+
+    @FastNative static native int SSL_get_shutdown(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_free(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_free(long ssl, NativeSsl ssl_holder);
 
-    static native long SSL_get_time(long ssl, NativeSsl ssl_holder);
+    @FastNative static native long SSL_get_time(long ssl, NativeSsl ssl_holder);
 
-    static native long SSL_set_timeout(long ssl, NativeSsl ssl_holder, long millis);
+    @FastNative static native long SSL_set_timeout(long ssl, NativeSsl ssl_holder, long millis);
 
-    static native long SSL_get_timeout(long ssl, NativeSsl ssl_holder);
+    @FastNative static native long SSL_get_timeout(long ssl, NativeSsl ssl_holder);
 
-    static native int SSL_get_signature_algorithm_key_type(int signatureAlg);
+    @CriticalNative static native int SSL_get_signature_algorithm_key_type(int signatureAlg);
 
-    static native byte[] SSL_session_id(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] SSL_session_id(long ssl, NativeSsl ssl_holder);
 
-    static native byte[] SSL_SESSION_session_id(long sslSessionNativePointer);
+    @FastNative static native byte[] SSL_SESSION_session_id(long sslSessionNativePointer);
 
-    static native long SSL_SESSION_get_time(long sslSessionNativePointer);
+    @FastNative static native long SSL_SESSION_get_time(long sslSessionNativePointer);
 
-    static native long SSL_SESSION_get_timeout(long sslSessionNativePointer);
+    @FastNative static native long SSL_SESSION_get_timeout(long sslSessionNativePointer);
 
-    static native String SSL_SESSION_get_version(long sslSessionNativePointer);
+    @FastNative static native String SSL_SESSION_get_version(long sslSessionNativePointer);
 
-    static native String SSL_SESSION_cipher(long sslSessionNativePointer);
+    @FastNative static native String SSL_SESSION_cipher(long sslSessionNativePointer);
 
+    @FastNative
     static native boolean SSL_SESSION_should_be_single_use(long sslSessionNativePointer);
 
-    static native void SSL_SESSION_up_ref(long sslSessionNativePointer);
+    @FastNative static native void SSL_SESSION_up_ref(long sslSessionNativePointer);
 
-    static native void SSL_SESSION_free(long sslSessionNativePointer);
+    @FastNative static native void SSL_SESSION_free(long sslSessionNativePointer);
 
-    static native byte[] i2d_SSL_SESSION(long sslSessionNativePointer);
+    @FastNative static native byte[] i2d_SSL_SESSION(long sslSessionNativePointer);
 
-    static native long d2i_SSL_SESSION(byte[] data) throws IOException;
+    @FastNative static native long d2i_SSL_SESSION(byte[] data) throws IOException;
 
     /**
-     * A collection of callbacks from the native OpenSSL code that are
-     * related to the SSL handshake initiated by SSL_do_handshake.
+     * A collection of callbacks from the native OpenSSL code that are related to the SSL handshake
+     * initiated by SSL_do_handshake.
      */
     interface SSLHandshakeCallbacks {
         /**
@@ -1352,7 +1461,6 @@ public final class NativeCrypto {
          *
          * @param certificateChain chain of X.509 certificates in their encoded form
          * @param authMethod auth algorithm name
-         *
          * @throws CertificateException if the certificate is untrusted
          */
         @SuppressWarnings("unused")
@@ -1373,9 +1481,9 @@ public final class NativeCrypto {
                 throws CertificateEncodingException, SSLException;
 
         /**
-         * Called when acting as a server during ClientHello processing before a decision
-         * to resume a session is made. This allows the selection of the correct server
-         * certificate based on things like Server Name Indication (SNI).
+         * Called when acting as a server during ClientHello processing before a decision to resume
+         * a session is made. This allows the selection of the correct server certificate based on
+         * things like Server Name Indication (SNI).
          *
          * @throws IOException if there was an error during certificate selection.
          */
@@ -1386,13 +1494,12 @@ public final class NativeCrypto {
          * exchange.
          *
          * @param identityHint PSK identity hint provided by the server or {@code null} if no hint
-         *        provided.
+         *     provided.
          * @param identity buffer to be populated with PSK identity (NULL-terminated modified UTF-8)
-         *        by this method. This identity will be provided to the server.
+         *     by this method. This identity will be provided to the server.
          * @param key buffer to be populated with key material by this method.
-         *
          * @return number of bytes this method stored in the {@code key} buffer or {@code 0} if an
-         *         error occurred in which case the handshake will be aborted.
+         *     error occurred in which case the handshake will be aborted.
          */
         int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key);
 
@@ -1400,33 +1507,30 @@ public final class NativeCrypto {
          * Gets the key to be used in server mode for this connection in Pre-Shared Key (PSK) key
          * exchange.
          *
-         * @param identityHint PSK identity hint provided by this server to the client or
-         *        {@code null} if no hint was provided.
+         * @param identityHint PSK identity hint provided by this server to the client or {@code
+         *     null} if no hint was provided.
          * @param identity PSK identity provided by the client.
          * @param key buffer to be populated with key material by this method.
-         *
          * @return number of bytes this method stored in the {@code key} buffer or {@code 0} if an
-         *         error occurred in which case the handshake will be aborted.
+         *     error occurred in which case the handshake will be aborted.
          */
         int serverPSKKeyRequested(String identityHint, String identity, byte[] key);
 
-        /**
-         * Called when SSL state changes. This could be handshake completion.
-         */
+        /** Called when SSL state changes. This could be handshake completion. */
         @SuppressWarnings("unused") void onSSLStateChange(int type, int val);
 
         /**
-         * Called when a new session has been established and may be added to the session cache.
-         * The callee is responsible for incrementing the reference count on the returned session.
+         * Called when a new session has been established and may be added to the session cache. The
+         * callee is responsible for incrementing the reference count on the returned session.
          */
         @SuppressWarnings("unused") void onNewSessionEstablished(long sslSessionNativePtr);
 
         /**
-         * Called for servers where TLS < 1.3 (TLS 1.3 uses session tickets rather than
-         * application session caches).
+         * Called for servers where TLS < 1.3 (TLS 1.3 uses session tickets rather than application
+         * session caches).
          *
-         * <p/>Looks up the session by ID in the application's session cache. If a valid session
-         * is returned, this callback is responsible for incrementing the reference count (and any
+         * <p>Looks up the session by ID in the application's session cache. If a valid session is
+         * returned, this callback is responsible for incrementing the reference count (and any
          * required synchronization).
          *
          * @param id the ID of the session to find.
@@ -1436,7 +1540,7 @@ public final class NativeCrypto {
 
         /**
          * Called when acting as a server, the socket has an {@link
-         * ApplicationProtocolSelectorAdapter} associated with it,  and the application protocol
+         * ApplicationProtocolSelectorAdapter} associated with it, and the application protocol
          * needs to be selected.
          *
          * @param applicationProtocols list of application protocols in length-prefix format
@@ -1445,139 +1549,136 @@ public final class NativeCrypto {
         @SuppressWarnings("unused") int selectApplicationProtocol(byte[] applicationProtocols);
     }
 
-    static native String SSL_CIPHER_get_kx_name(long cipherAddress);
+    @FastNative static native String SSL_CIPHER_get_kx_name(long cipherAddress);
 
-    static native String[] get_cipher_names(String selection);
+    @FastNative static native String[] get_cipher_names(String selection);
 
-    public static native byte[] get_ocsp_single_extension(
-            byte[] ocspResponse, String oid, long x509Ref, OpenSSLX509Certificate holder, long issuerX509Ref, OpenSSLX509Certificate holder2);
+    @FastNative
+    public static native byte[] get_ocsp_single_extension(byte[] ocspResponse, String oid,
+            long x509Ref, OpenSSLX509Certificate holder, long issuerX509Ref,
+            OpenSSLX509Certificate holder2);
 
     /**
-     * Returns the starting address of the memory region referenced by the provided direct
-     * {@link Buffer} or {@code 0} if the provided buffer is not direct or if such access to direct
-     * buffers is not supported by the platform.
+     * Returns the starting address of the memory region referenced by the provided direct {@link
+     * Buffer} or {@code 0} if the provided buffer is not direct or if such access to direct buffers
+     * is not supported by the platform.
      *
      * <p>NOTE: This method ignores the buffer's current {@code position}.
      */
-    static native long getDirectBufferAddress(Buffer buf);
+    @FastNative static native long getDirectBufferAddress(Buffer buf);
 
-    static native long SSL_BIO_new(long ssl, NativeSsl ssl_holder) throws SSLException;
+    @FastNative static native long SSL_BIO_new(long ssl, NativeSsl ssl_holder) throws SSLException;
 
-    static native int SSL_get_error(long ssl, NativeSsl ssl_holder, int ret);
+    @FastNative static native int SSL_get_error(long ssl, NativeSsl ssl_holder, int ret);
 
-    static native void SSL_clear_error();
+    @CriticalNative static native void SSL_clear_error();
 
-    static native int SSL_pending_readable_bytes(long ssl, NativeSsl ssl_holder);
+    @FastNative static native int SSL_pending_readable_bytes(long ssl, NativeSsl ssl_holder);
 
-    static native int SSL_pending_written_bytes_in_BIO(long bio);
+    @FastNative static native int SSL_pending_written_bytes_in_BIO(long bio);
 
-    /**
-     * Returns the maximum overhead, in bytes, of sealing a record with SSL.
-     */
-    static native int SSL_max_seal_overhead(long ssl, NativeSsl ssl_holder);
+    /** Returns the maximum overhead, in bytes, of sealing a record with SSL. */
+    @FastNative static native int SSL_max_seal_overhead(long ssl, NativeSsl ssl_holder);
 
     /**
      * Enables ALPN for this TLS endpoint and sets the list of supported ALPN protocols in
      * wire-format (length-prefixed 8-bit strings).
      */
+    @FastNative
     static native void setApplicationProtocols(
             long ssl, NativeSsl ssl_holder, boolean client, byte[] protocols) throws IOException;
 
     /**
      * Called for a server endpoint only. Enables ALPN and indicates that the {@link
-     * SSLHandshakeCallbacks#selectApplicationProtocol} will be called to select the
-     * correct protocol during a handshake. Calling this method overrides
-     * {@link #setApplicationProtocols(long, NativeSsl, boolean, byte[])}.
+     * SSLHandshakeCallbacks#selectApplicationProtocol} will be called to select the correct
+     * protocol during a handshake. Calling this method overrides {@link
+     * #setApplicationProtocols(long, NativeSsl, boolean, byte[])}.
      */
-    static native void setHasApplicationProtocolSelector(long ssl, NativeSsl ssl_holder, boolean hasSelector)
-            throws IOException;
+    @FastNative
+    static native void setHasApplicationProtocolSelector(
+            long ssl, NativeSsl ssl_holder, boolean hasSelector) throws IOException;
 
     /**
-     * Returns the selected ALPN protocol. If the server did not select a
-     * protocol, {@code null} will be returned.
+     * Returns the selected ALPN protocol. If the server did not select a protocol, {@code null}
+     * will be returned.
      */
-    static native byte[] getApplicationProtocol(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] getApplicationProtocol(long ssl, NativeSsl ssl_holder);
 
     /**
      * Variant of the {@link #SSL_do_handshake} used by {@link ConscryptEngine}. This differs
-     * slightly from the raw BoringSSL API in that it returns the SSL error code from the
-     * operation, rather than the return value from {@code SSL_do_handshake}. This is done in
-     * order to allow to properly handle SSL errors and propagate useful exceptions.
+     * slightly from the raw BoringSSL API in that it returns the SSL error code from the operation,
+     * rather than the return value from {@code SSL_do_handshake}. This is done in order to allow to
+     * properly handle SSL errors and propagate useful exceptions.
      *
      * @return Returns the SSL error code for the operation when the error was {@code
-     * SSL_ERROR_NONE}, {@code SSL_ERROR_WANT_READ}, or {@code SSL_ERROR_WANT_WRITE}.
+     *     SSL_ERROR_NONE}, {@code SSL_ERROR_WANT_READ}, or {@code SSL_ERROR_WANT_WRITE}.
      * @throws IOException when the error code is anything except those returned by this method.
      */
-    static native int ENGINE_SSL_do_handshake(long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc)
-            throws IOException;
+    static native int ENGINE_SSL_do_handshake(
+            long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc) throws IOException;
 
     /**
      * Variant of the {@link #SSL_read} for a direct {@link java.nio.ByteBuffer} used by {@link
      * ConscryptEngine}.
      *
-     * @return if positive, represents the number of bytes read into the given buffer.
-     * Returns {@code -SSL_ERROR_WANT_READ} if more data is needed. Returns
-     * {@code -SSL_ERROR_WANT_WRITE} if data needs to be written out to flush the BIO.
-     *
+     * @return if positive, represents the number of bytes read into the given buffer. Returns
+     *     {@code -SSL_ERROR_WANT_READ} if more data is needed. Returns {@code
+     *     -SSL_ERROR_WANT_WRITE} if data needs to be written out to flush the BIO.
      * @throws java.io.InterruptedIOException if the read was interrupted.
      * @throws java.io.EOFException if the end of stream has been reached.
      * @throws CertificateException if the application's certificate verification callback failed.
-     * Only occurs during handshake processing.
+     *     Only occurs during handshake processing.
      * @throws SSLException if any other error occurs.
      */
-    static native int ENGINE_SSL_read_direct(long ssl, NativeSsl ssl_holder, long address, int length,
-            SSLHandshakeCallbacks shc) throws IOException, CertificateException;
+    static native int ENGINE_SSL_read_direct(long ssl, NativeSsl ssl_holder, long address,
+            int length, SSLHandshakeCallbacks shc) throws IOException, CertificateException;
 
     /**
      * Variant of the {@link #SSL_write} for a direct {@link java.nio.ByteBuffer} used by {@link
      * ConscryptEngine}. This version does not lock or and does no error pre-processing.
      */
-    static native int ENGINE_SSL_write_direct(long ssl, NativeSsl ssl_holder, long address, int length,
-            SSLHandshakeCallbacks shc) throws IOException;
+    static native int ENGINE_SSL_write_direct(long ssl, NativeSsl ssl_holder, long address,
+            int length, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Writes data from the given direct {@link java.nio.ByteBuffer} to the BIO.
-     */
-    static native int ENGINE_SSL_write_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef, long pos, int length,
-            SSLHandshakeCallbacks shc) throws IOException;
+    /** Writes data from the given direct {@link java.nio.ByteBuffer} to the BIO. */
+    static native int ENGINE_SSL_write_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef,
+            long pos, int length, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Reads data from the given BIO into a direct {@link java.nio.ByteBuffer}.
-     */
-    static native int ENGINE_SSL_read_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef, long address, int len,
-            SSLHandshakeCallbacks shc) throws IOException;
+    /** Reads data from the given BIO into a direct {@link java.nio.ByteBuffer}. */
+    static native int ENGINE_SSL_read_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef,
+            long address, int len, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Forces the SSL object to process any data pending in the BIO.
-     */
-    static native void ENGINE_SSL_force_read(long ssl, NativeSsl ssl_holder,
-            SSLHandshakeCallbacks shc) throws IOException;
+    /** Forces the SSL object to process any data pending in the BIO. */
+    static native void ENGINE_SSL_force_read(
+            long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc) throws IOException;
 
     /**
      * Variant of the {@link #SSL_shutdown} used by {@link ConscryptEngine}. This version does not
      * lock.
      */
-    static native void ENGINE_SSL_shutdown(long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc)
-            throws IOException;
+    static native void ENGINE_SSL_shutdown(
+            long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Generates a key from a password and salt using Scrypt.
-     */
-    static native byte[] Scrypt_generate_key(byte[] password, byte[] salt, int n, int r, int p, int key_len);
+    /** Generates a key from a password and salt using Scrypt. */
+    @FastNative
+    static native byte[] Scrypt_generate_key(
+            byte[] password, byte[] salt, int n, int r, int p, int key_len);
 
-    /**
-     * Return {@code true} if BoringSSL has been built in FIPS mode.
-     */
-    static native boolean usesBoringSsl_FIPS_mode();
+    /** Return {@code true} if BoringSSL has been built in FIPS mode. */
+    @CriticalNative static native boolean usesBoringSsl_FIPS_mode();
 
-    /**
-     * Used for testing only.
-     */
-    static native int BIO_read(long bioRef, byte[] buffer) throws IOException;
+    /** Used for testing only. */
+    @FastNative static native int BIO_read(long bioRef, byte[] buffer) throws IOException;
+
+    @FastNative
     static native void BIO_write(long bioRef, byte[] buffer, int offset, int length)
             throws IOException, IndexOutOfBoundsException;
-    static native long SSL_clear_mode(long ssl, NativeSsl ssl_holder, long mode);
-    static native long SSL_get_mode(long ssl, NativeSsl ssl_holder);
-    static native long SSL_get_options(long ssl, NativeSsl ssl_holder);
-    static native long SSL_get1_session(long ssl, NativeSsl ssl_holder);
+
+    @FastNative static native long SSL_clear_mode(long ssl, NativeSsl ssl_holder, long mode);
+
+    @FastNative static native long SSL_get_mode(long ssl, NativeSsl ssl_holder);
+
+    @FastNative static native long SSL_get_options(long ssl, NativeSsl ssl_holder);
+
+    @FastNative static native long SSL_get1_session(long ssl, NativeSsl ssl_holder);
 }
diff --git a/common/src/main/java/org/conscrypt/NativeSsl.java b/common/src/main/java/org/conscrypt/NativeSsl.java
index d0671dab..406c68f2 100644
--- a/common/src/main/java/org/conscrypt/NativeSsl.java
+++ b/common/src/main/java/org/conscrypt/NativeSsl.java
@@ -309,14 +309,11 @@ final class NativeSsl {
                     + " and " + NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1
                     + " are no longer supported and were filtered from the list");
         }
-        // We can use default cipher suites for SPAKE.
+        NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
+        // We only set the cipher suites if we are not using SPAKE.
         if (!parameters.isSpake()) {
-            NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
             NativeCrypto.setEnabledCipherSuites(
-                ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
-        } else {
-            // SPAKE only supports TLSv1.3.
-            NativeCrypto.setEnabledProtocols(ssl, this, new String[] {"TLSv1.3"});
+                    ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
         }
 
         if (parameters.applicationProtocols.length > 0) {
diff --git a/common/src/main/java/org/conscrypt/OpenSSLX509CertificateFactory.java b/common/src/main/java/org/conscrypt/OpenSSLX509CertificateFactory.java
index 5f29a90c..7d68908b 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLX509CertificateFactory.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLX509CertificateFactory.java
@@ -41,6 +41,11 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
     private static final byte[] PKCS7_MARKER = new byte[] {
             '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ', 'P', 'K', 'C', 'S', '7'
     };
+    private static final byte[] PEM_MARKER = new byte[] {
+            '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' '
+    };
+    private static final int DASH = 45; // Value of '-'
+    private static final int VALUE_0 = 0x30; // Value of '0'
 
     private static final int PUSHBACK_SIZE = 64;
 
@@ -62,7 +67,7 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
 
     private static boolean isMaybePkcs7(byte[] header) {
         // The outer tag must be SEQUENCE.
-        if (header.length < 2 || header[0] != 0x30) {
+        if (header.length < 2 || header[0] != VALUE_0) {
             return false;
         }
 
@@ -112,9 +117,9 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
 
             final PushbackInputStream pbis = new PushbackInputStream(inStream, PUSHBACK_SIZE);
             try {
-                final byte[] buffer = new byte[PKCS7_MARKER.length];
+                byte[] buffer = new byte[PKCS7_MARKER.length];
 
-                final int len = pbis.read(buffer);
+                int len = pbis.read(buffer);
                 if (len < 0) {
                     /* No need to reset here. The stream was empty or EOF. */
                     throw new ParsingException("inStream is empty");
@@ -124,16 +129,34 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
                 if (buffer[0] == '-') {
                     return fromX509PemInputStream(pbis);
                 }
-
                 if (isMaybePkcs7(buffer)) {
                     List<? extends T> certs = fromPkcs7DerInputStream(pbis);
                     if (certs.size() == 0) {
                         return null;
                     }
                     return certs.get(0);
-                } else {
+                }
+                if (buffer[0] == VALUE_0) {
                     return fromX509DerInputStream(pbis);
                 }
+                int value = 0;
+                buffer = new byte[PEM_MARKER.length];
+                while (value != -1) {
+                    value = pbis.read();
+                    if (value == DASH) {
+                        pbis.unread(value);
+                        len = pbis.read(buffer);
+                        if (len < PEM_MARKER.length) {
+                            throw new ParsingException("No certificate found");
+                        }
+                        pbis.unread(buffer, 0, len);
+                        if (Arrays.equals(buffer, PEM_MARKER)) {
+                            return fromX509PemInputStream(pbis);
+                        }
+                        pbis.read();
+                    }
+                }
+                throw new ParsingException("No certificate found");
             } catch (Exception e) {
                 if (markable) {
                     try {
diff --git a/common/src/main/java/org/conscrypt/SSLParametersImpl.java b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
index e6605a17..d5b8d199 100644
--- a/common/src/main/java/org/conscrypt/SSLParametersImpl.java
+++ b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
@@ -167,8 +167,10 @@ final class SSLParametersImpl implements Cloneable {
         }
 
         // initialize the list of cipher suites and protocols enabled by default
-        if (protocols == null) {
-          enabledProtocols = NativeCrypto.getDefaultProtocols().clone();
+        if (isSpake()) {
+            enabledProtocols = new String[] {NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3};
+        } else if (protocols == null) {
+            enabledProtocols = NativeCrypto.getDefaultProtocols().clone();
         } else {
             String[] filteredProtocols =
                     filterFromProtocols(protocols, Arrays.asList(Platform.isTlsV1Filtered()
@@ -345,6 +347,8 @@ final class SSLParametersImpl implements Cloneable {
     void setEnabledProtocols(String[] protocols) {
         if (protocols == null) {
             throw new IllegalArgumentException("protocols == null");
+        } else if (isSpake()) {
+            return;
         }
         String[] filteredProtocols =
                 filterFromProtocols(protocols, Arrays.asList(!Platform.isTlsV1Filtered()
diff --git a/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java b/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java
index 75499a82..77811400 100644
--- a/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java
+++ b/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java
@@ -58,8 +58,8 @@ public class CertificateTransparency {
         return Platform.reasonCTVerificationRequired(host);
     }
 
-    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
-            throws CertificateException {
+    private void checkCTInternal(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData,
+            String host) throws CertificateException {
         if (logStore.getState() != LogStore.State.COMPLIANT) {
             /* Fail open. For some reason, the LogStore is not usable. It could
              * be because there is no log list available or that the log list
@@ -82,4 +82,17 @@ public class CertificateTransparency {
                     + compliance.name());
         }
     }
+
+    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
+            throws CertificateException {
+        boolean dryRun = (reasonCTVerificationRequired(host)
+                == CertificateTransparencyVerificationReason.DRY_RUN);
+        try {
+            checkCTInternal(chain, ocspData, tlsData, host);
+        } catch (CertificateException e) {
+            if (!dryRun) {
+                throw e;
+            }
+        }
+    }
 }
diff --git a/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java b/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
index 0c7fab7a..6729175e 100644
--- a/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
+++ b/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
@@ -16,6 +16,7 @@
 
 package org.conscrypt.metrics;
 
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DRY_RUN;
 import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN;
 import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN;
 import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN;
@@ -30,7 +31,8 @@ public enum CertificateTransparencyVerificationReason {
     UNKNOWN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN),
     APP_OPT_IN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN),
     DOMAIN_OPT_IN(
-            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN);
+            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN),
+    DRY_RUN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DRY_RUN);
 
     final int id;
 
diff --git a/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java b/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
index a94a4e76..80c4a89d 100644
--- a/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
+++ b/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
@@ -179,6 +179,8 @@ public final class ConscryptStatsLog {
     public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
     public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN = 3;
     public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN = 4;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DRY_RUN = 5;
+
 
     // Values for CertificateTransparencyVerificationReported.policy_compatibility_version
     public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_UNKNOWN = 0;
diff --git a/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java b/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
index d39d0de0..9043d9a5 100644
--- a/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
+++ b/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
@@ -36,30 +36,8 @@ import org.conscrypt.ct.LogStore;
 import org.conscrypt.ct.PolicyCompliance;
 import org.conscrypt.ct.VerificationResult;
 
-import java.lang.Thread.UncaughtExceptionHandler;
-import java.util.concurrent.ArrayBlockingQueue;
-import java.util.concurrent.ExecutorService;
-import java.util.concurrent.Executors;
-import java.util.concurrent.ThreadFactory;
-import java.util.concurrent.ThreadPoolExecutor;
-import java.util.concurrent.TimeUnit;
-
 @Internal
 public final class StatsLogImpl implements StatsLog {
-    private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
-        @Override
-        public Thread newThread(Runnable r) {
-            Thread thread = new Thread(r, "ConscryptStatsLog");
-            thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
-                @Override
-                public void uncaughtException(Thread t, Throwable e) {
-                    // Ignore
-                }
-            });
-            return thread;
-        }
-    });
-
     private static final StatsLog INSTANCE = new StatsLogImpl();
     private StatsLogImpl() {}
     public static StatsLog getInstance() {
@@ -135,38 +113,43 @@ public final class StatsLogImpl implements StatsLog {
         }
     }
 
+    private static final boolean sdkVersionBiggerThan32;
+
+    static {
+        sdkVersionBiggerThan32 = Platform.isSdkGreater(32);
+    }
+
+    @SuppressWarnings("NewApi")
     private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
             int source, int[] uids) {
-        e.execute(new Runnable() {
-            @Override
-            public void run() {
-                ConscryptStatsLog.write(
-                        atomId, success, protocol, cipherSuite, duration, source, uids);
-            }
-        });
+        if (!sdkVersionBiggerThan32) {
+            final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+            builder.writeInt(atomId);
+            builder.writeBoolean(success);
+            builder.writeInt(protocol);
+            builder.writeInt(cipherSuite);
+            builder.writeInt(duration);
+            builder.writeInt(source);
+
+            builder.usePooledBuffer();
+            ReflexiveStatsLog.write(builder.build());
+        } else {
+            ConscryptStatsLog.write(
+                atomId, success, protocol, cipherSuite, duration, source, uids);
+        }
     }
 
     private void write(int atomId, int status, int loadedCompatVersion,
             int minCompatVersionAvailable, int majorVersion, int minorVersion) {
-        e.execute(new Runnable() {
-            @Override
-            public void run() {
-                ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
-                        minCompatVersionAvailable, majorVersion, minorVersion);
-            }
-        });
+        ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
+                minCompatVersionAvailable, majorVersion, minorVersion);
     }
 
     private void write(int atomId, int verificationResult, int verificationReason,
             int policyCompatVersion, int majorVersion, int minorVersion, int numEmbeddedScts,
             int numOcspScts, int numTlsScts) {
-        e.execute(new Runnable() {
-            @Override
-            public void run() {
-                ConscryptStatsLog.write(atomId, verificationResult, verificationReason,
-                        policyCompatVersion, majorVersion, minorVersion, numEmbeddedScts,
-                        numOcspScts, numTlsScts);
-            }
-        });
+        ConscryptStatsLog.write(atomId, verificationResult, verificationReason,
+                policyCompatVersion, majorVersion, minorVersion, numEmbeddedScts,
+                numOcspScts, numTlsScts);
     }
 }
diff --git a/common/src/main/java/org/conscrypt/securityconfig/ApplicationConfig.java b/common/src/main/java/org/conscrypt/securityconfig/ApplicationConfig.java
new file mode 100644
index 00000000..f51560f5
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/securityconfig/ApplicationConfig.java
@@ -0,0 +1,124 @@
+/*
+ * Copyright (C) 2015 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.securityconfig;
+
+import javax.net.ssl.X509TrustManager;
+
+/**
+ * An application's network security configuration.
+ *
+ * <p>{@link #getConfigForHostname(String)} provides a means to obtain network security
+ * configuration to be used for communicating with a specific hostname.
+ */
+public final class ApplicationConfig {
+    private static ApplicationConfig sInstance;
+    private static Object sLock = new Object();
+
+    private X509TrustManager mTrustManager;
+
+    private boolean mInitialized;
+    private final Object mLock = new Object();
+
+    /** Constructs a new {@code ApplicationConfig} instance. */
+    public ApplicationConfig() {
+        mInitialized = false;
+    }
+
+    public boolean hasPerDomainConfigs() {
+        ensureInitialized();
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /**
+     * Returns the {@link X509TrustManager} that implements the checking of trust anchors and
+     * certificate pinning based on this configuration.
+     */
+    public X509TrustManager getTrustManager() {
+        ensureInitialized();
+        return mTrustManager;
+    }
+
+    /**
+     * Returns {@code true} if cleartext traffic is permitted for this application, which is the
+     * case only if all configurations permit cleartext traffic. For finer-grained policy use {@link
+     * #isCleartextTrafficPermitted(String)}.
+     */
+    public boolean isCleartextTrafficPermitted() {
+        ensureInitialized();
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /**
+     * Returns {@code true} if cleartext traffic is permitted for this application when connecting
+     * to {@code hostname}.
+     */
+    public boolean isCleartextTrafficPermitted(String hostname) {
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /**
+     * Returns {@code true} if Certificate Transparency information is required to be verified by
+     * the client in TLS connections to {@code hostname}.
+     *
+     * <p>See RFC6962 section 3.3 for more details.
+     *
+     * @param hostname hostname to check whether certificate transparency verification is required
+     * @return {@code true} if certificate transparency verification is required and {@code false}
+     *     otherwise
+     */
+    public boolean isCertificateTransparencyVerificationRequired(String hostname) {
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /** Handle an update to the system or user certificate stores. */
+    public void handleTrustStorageUpdate() {}
+
+    private void ensureInitialized() {
+        synchronized (mLock) {
+            if (mInitialized) {
+                return;
+            }
+            mInitialized = true;
+        }
+    }
+
+    /**
+     * Sets the default {@link ApplicationConfig} instance.
+     *
+     * @param config the {@link ApplicationConfig} to set as the default instance.
+     */
+    public static void setDefaultInstance(ApplicationConfig config) {
+        synchronized (sLock) {
+            sInstance = config;
+        }
+    }
+
+    /**
+     * Gets the default {@link ApplicationConfig} instance.
+     *
+     * @return the default {@link ApplicationConfig} instance.
+     */
+    public static ApplicationConfig getDefaultInstance() {
+        synchronized (sLock) {
+            return sInstance;
+        }
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/securityconfig/NetworkSecurityConfigProvider.java b/common/src/main/java/org/conscrypt/securityconfig/NetworkSecurityConfigProvider.java
new file mode 100644
index 00000000..7bddff81
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/securityconfig/NetworkSecurityConfigProvider.java
@@ -0,0 +1,85 @@
+/*
+ * Copyright (C) 2015 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.securityconfig;
+
+import java.security.Provider;
+import java.security.Security;
+import java.util.logging.Logger;
+
+/** Security Provider backed by the app's Network Security Config. */
+public final class NetworkSecurityConfigProvider extends Provider {
+    private static final String LOG_TAG = "nsconfig";
+    private static final Logger logger = Logger.getLogger(LOG_TAG);
+    private static final String PREFIX =
+            NetworkSecurityConfigProvider.class.getPackage().getName() + ".";
+
+    public NetworkSecurityConfigProvider() {
+        // TODO: More clever name than this
+        super("AndroidNSSP", 1.0, "Android Network Security Policy Provider");
+        put("TrustManagerFactory.PKIX", PREFIX + "RootTrustManagerFactorySpi");
+        put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
+    }
+
+    /**
+     * Installs the NetworkSecurityConfigProvider as the highest priority provider.
+     *
+     * <p>If the provider cannot be installed with highest priority, the installation will still
+     * complete but this method will throw an exception.
+     */
+    public static void install() {
+        ApplicationConfig config = new ApplicationConfig();
+        ApplicationConfig.setDefaultInstance(config);
+        int pos = Security.insertProviderAt(new NetworkSecurityConfigProvider(), 1);
+        if (pos != 1) {
+            // TODO(b/404518910): remove the provider if the installation fails.
+            throw new RuntimeException("Failed to install provider as highest priority provider."
+                    + " Provider was installed at position " + pos);
+        }
+    }
+
+    /**
+     * The network security config needs to be aware of multiple applications in the same process to
+     * handle discrepancies.
+     *
+     * <p>For such a shared process, conflicting values of usesCleartextTraffic are resolved as
+     * follows:
+     *
+     * <p>1. Throws a RuntimeException if the shared process with conflicting usesCleartextTraffic
+     * values have per domain rules, otherwise
+     *
+     * <p>2. Sets the default instance to the least strict config.
+     *
+     * @param processName the name of the process hosting mutiple applications.
+     */
+    public static void handleNewApplication(String processName) {
+        ApplicationConfig config = new ApplicationConfig();
+        ApplicationConfig defaultConfig = ApplicationConfig.getDefaultInstance();
+        if (defaultConfig != null) {
+            if (defaultConfig.isCleartextTrafficPermitted()
+                    != config.isCleartextTrafficPermitted()) {
+                logger.warning((processName == null ? "Unknown process" : processName)
+                        + ": New config does not match the previously set config.");
+
+                if (defaultConfig.hasPerDomainConfigs() || config.hasPerDomainConfigs()) {
+                    throw new RuntimeException("Found multiple conflicting per-domain rules");
+                }
+                config = defaultConfig.isCleartextTrafficPermitted() ? defaultConfig : config;
+            }
+        }
+        ApplicationConfig.setDefaultInstance(config);
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/securityconfig/UserCertificateSource.java b/common/src/main/java/org/conscrypt/securityconfig/UserCertificateSource.java
new file mode 100644
index 00000000..d6180915
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/securityconfig/UserCertificateSource.java
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2015 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.securityconfig;
+
+import java.security.cert.X509Certificate;
+
+/** {@link CertificateSource} based on the user-installed trusted CA store. */
+public final class UserCertificateSource {
+    private static class NoPreloadHolder {
+        private static final UserCertificateSource INSTANCE = new UserCertificateSource();
+    }
+
+    /**
+     * Returns the singleton instance of {@link UserCertificateSource}.
+     *
+     * @return the singleton instance of {@link UserCertificateSource}.
+     */
+    public static UserCertificateSource getInstance() {
+        return NoPreloadHolder.INSTANCE;
+    }
+
+    // TODO(sandrom): move to DirectoryCertificateSource super class
+    public X509Certificate findBySubjectAndPublicKey(final X509Certificate cert) {
+        return null;
+    }
+
+    // TODO(sandrom): move to DirectoryCertificateSource super class
+    public void handleTrustStorageUpdate() {}
+}
diff --git a/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java b/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java
index 93b88b81..990ef87f 100644
--- a/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java
+++ b/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java
@@ -26,6 +26,7 @@ import java.io.IOException;
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
+import java.util.concurrent.atomic.AtomicInteger;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -48,20 +49,24 @@ public class NativeCryptoArgTest {
      * so we can get past the first check and test the second one.
      */
     private static final long NOT_NULL = 4L;
+    private static final int EXPECTED_TEST_CASES = 6;
+    /* The tests check how many methods get invoked. By the time all tests are
+     * run, a minimum number of methods should have been tested. The choice of
+     * number is based on the historic value.
+     * TODO: Find a more definite number to use here.*/
+    private static final int MIN_EXPECTED_TESTED_METHODS = 190;
     private static final String CONSCRYPT_PACKAGE = NativeCryptoArgTest.class.getCanonicalName()
             .substring(0, NativeCryptoArgTest.class.getCanonicalName().lastIndexOf('.') + 1);
+    /* Count how many test cases are run. Once all the expected cases are run,
+     * we can check that the minimum number of methods were tested. */
+    private static final AtomicInteger testCaseCount = new AtomicInteger(EXPECTED_TEST_CASES);
     private static final Set<String> testedMethods = new HashSet<>();
     private final Map<String, Class<?>> classCache = new HashMap<>();
     private final Map<String, Method> methodMap = buildMethodMap();
 
-    @AfterClass
-    public static void after() {
-        // TODO(prb): Temporary hacky check - remove
-        assertTrue(testedMethods.size() >= 190);
-    }
-
     @Test
     public void ecMethods() throws Throwable {
+        markTestRun();
         String[] illegalArgMethods = new String[] {
                 "EC_GROUP_new_arbitrary"
         };
@@ -85,10 +90,12 @@ public class NativeCryptoArgTest {
 
         filter = MethodFilter.nameFilter("EC_ methods (IOException)", ioExMethods);
         testMethods(filter, IOException.class);
+        checkMethodsTested();
     }
 
     @Test
     public void macMethods() throws Throwable {
+        markTestRun();
         // All of the non-void HMAC and CMAC methods throw NPE when passed a null pointer
         MethodFilter filter = MethodFilter.newBuilder("HMAC methods")
                 .hasPrefix("HMAC_")
@@ -103,10 +110,12 @@ public class NativeCryptoArgTest {
                 .expectSize(5)
                 .build();
         testMethods(filter, NullPointerException.class);
+        checkMethodsTested();
     }
 
     @Test
     public void sslMethods() throws Throwable {
+        markTestRun();
         // These methods don't throw on a null first arg as they can get called before the
         // connection is fully initialised. However if the first arg is non-NULL, any subsequent
         // null args should throw NPE.
@@ -146,10 +155,12 @@ public class NativeCryptoArgTest {
         expectNPE("SSL_shutdown", NOT_NULL, null, new FileDescriptor(), null);
         expectNPE("ENGINE_SSL_shutdown", NOT_NULL, null, null);
         expectVoid("SSL_set_session", NOT_NULL, null, NULL);
+        checkMethodsTested();
     }
 
     @Test
     public void evpMethods() throws Throwable {
+        markTestRun();
         String[] illegalArgMethods = new String[] {
                 "EVP_AEAD_CTX_open_buf",
                 "EVP_AEAD_CTX_seal_buf",
@@ -182,10 +193,12 @@ public class NativeCryptoArgTest {
 
         filter = MethodFilter.nameFilter("EVP methods (non-throwing)", nonThrowingMethods);
         testMethods(filter, null);
+        checkMethodsTested();
     }
 
     @Test
     public void x509Methods() throws Throwable {
+        markTestRun();
         // A number of X509 methods have a native pointer as arg 0 and an
         // OpenSSLX509Certificate or OpenSSLX509CRL as arg 1.
         MethodFilter filter = MethodFilter.newBuilder("X509 methods")
@@ -221,10 +234,12 @@ public class NativeCryptoArgTest {
         expectNPE("X509_print_ex", NULL, NULL, null, NULL, NULL);
         expectNPE("X509_print_ex", NOT_NULL, NULL, null, NULL, NULL);
         expectNPE("X509_print_ex", NULL, NOT_NULL, null, NULL, NULL);
+        checkMethodsTested();
     }
 
     @Test
     public void spake2Methods() throws Throwable {
+        markTestRun();
         expectNPE("SSL_CTX_set_spake_credential",
                 null, new byte[0], new byte[0], new byte[0], false, 1, NOT_NULL, null);
         expectNPE("SSL_CTX_set_spake_credential",
@@ -233,6 +248,7 @@ public class NativeCryptoArgTest {
                 new byte[0], new byte[0], null, new byte[0], false, 1, NOT_NULL, null);
         expectNPE("SSL_CTX_set_spake_credential",
                 new byte[0], new byte[0], new byte[0], null, false, 1, NOT_NULL, null);
+        checkMethodsTested();
     }
 
     private void testMethods(MethodFilter filter, Class<? extends Throwable> exceptionClass)
@@ -274,6 +290,22 @@ public class NativeCryptoArgTest {
         return result;
     }
 
+    private static void markTestRun() {
+        int count = testCaseCount.get();
+        while (count > 0 && !testCaseCount.compareAndSet(count, count - 1)) {
+            count = testCaseCount.get();
+        }
+    }
+
+    private static void checkMethodsTested() {
+        if (testCaseCount.get() == 0) {
+            // Since we ran enough test cases, we should now have a minimum
+            // number of methods tested. Validate that these methods were indeed
+            // called.
+            assertTrue(testedMethods.size() >= MIN_EXPECTED_TESTED_METHODS);
+        }
+    }
+
     private void expectVoid(String methodName, Object... args) throws Throwable {
         invokeAndExpect(null, methodName, args);
     }
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
index 2382f28b..3be913b5 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
@@ -1223,7 +1223,8 @@ public class SSLSocketVersionCompatibilityTest {
         }
     }
 
-    @Test(expected = SocketTimeoutException.class)
+    @Test
+    @Ignore("Broken test: See b/408399060")
     public void test_SSLSocket_setSoWriteTimeout() throws Exception {
         // Only run this test on Linux since it relies on non-posix methods.
         assumeTrue("Test only runs on Linux. Current OS: " + osName(), isLinux());
diff --git a/common/src/test/java/org/conscrypt/securityconfig/XmlConfigTests.java b/common/src/test/java/org/conscrypt/securityconfig/XmlConfigTests.java
new file mode 100644
index 00000000..c3968777
--- /dev/null
+++ b/common/src/test/java/org/conscrypt/securityconfig/XmlConfigTests.java
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.securityconfig;
+
+import static org.junit.Assert.assertFalse;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class XmlConfigTests {
+    @Test
+    public void testEmptyConfigFile() {
+        ApplicationConfig appConfig = new ApplicationConfig();
+        // Check defaults.
+        assertFalse(appConfig.hasPerDomainConfigs());
+        assertFalse(appConfig.isCleartextTrafficPermitted());
+    }
+}
diff --git a/conscrypt.aconfig b/conscrypt.aconfig
index 497e630e..4777c29a 100644
--- a/conscrypt.aconfig
+++ b/conscrypt.aconfig
@@ -43,3 +43,12 @@ flag {
     is_fixed_read_only: true
     is_exported: true
 }
+
+flag {
+    namespace: "core_libraries"
+    name: "use_chromium_cert_blocklist"
+    description: "This flag controls whether conscrypt will use the new certificate blocklist"
+    bug: "340363351"
+    # APIs provided by a mainline module can only use a frozen flag.
+    is_fixed_read_only: true
+}
diff --git a/constants/src/gen/java/README.md b/constants/src/gen/java/README.md
new file mode 100644
index 00000000..a8d6dd35
--- /dev/null
+++ b/constants/src/gen/java/README.md
@@ -0,0 +1,7 @@
+# Updating the blocklist based on Chromium's source code
+
+1. Copy the latest version of `cert_verify_proc_blocklist.inc` from [Chromium's
+   repository](https://source.chromium.org/chromium/chromium/src/+/main:net/cert/cert_verify_proc_blocklist.inc)
+   into this directory.
+2. Build, flash and run: `atest CtsLibcoreTestCases`.
+
diff --git a/constants/src/gen/java/cert_verify_proc_blocklist.inc b/constants/src/gen/java/cert_verify_proc_blocklist.inc
new file mode 100644
index 00000000..3e6dcdb5
--- /dev/null
+++ b/constants/src/gen/java/cert_verify_proc_blocklist.inc
@@ -0,0 +1,447 @@
+// Copyright 2016 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+// The certificate(s) that were misissued, and which represent these SPKIs,
+// are stored within net/data/ssl/blocklist. Further details about the
+// rationale is documented in net/data/ssl/blocklist/README.md
+static constexpr uint8_t
+    kSPKIBlockList[][crypto::kSHA256Length] = {
+        // 2740d956b1127b791aa1b3cc644a4dbedba76186a23638b95102351a834ea861.pem
+        {0x04, 0xdd, 0xe9, 0xaa, 0x9a, 0x79, 0xf6, 0x14, 0x98, 0x68, 0x23,
+         0x25, 0xfa, 0x08, 0x70, 0x27, 0x67, 0x07, 0xfb, 0x9c, 0xa9, 0x53,
+         0x84, 0x12, 0x0b, 0x46, 0x89, 0x32, 0x68, 0x49, 0x4f, 0xc9},
+        // 91e5cc32910686c5cac25c18cc805696c7b33868c280caf0c72844a2a8eb91e2.pem
+        {0x0c, 0x43, 0xea, 0x8b, 0xcd, 0xe9, 0xfc, 0x3b, 0xca, 0x16, 0x56,
+         0x64, 0xac, 0x82, 0x15, 0x56, 0x7e, 0x34, 0x89, 0xd5, 0x39, 0x3a,
+         0x0c, 0x81, 0xe1, 0xa7, 0x91, 0x41, 0x99, 0x2e, 0x19, 0x53},
+        // ead610e6e90b439f2ecb51628b0932620f6ef340bd843fca38d3181b8f4ba197.pem
+        {0x12, 0x13, 0x23, 0x60, 0xa3, 0x3b, 0xfd, 0xc6, 0xc3, 0xbf, 0x7b,
+         0x7f, 0xab, 0x26, 0xa1, 0x68, 0x48, 0x74, 0xe7, 0x2c, 0x12, 0x63,
+         0xc1, 0xf5, 0xde, 0x56, 0x5b, 0xb4, 0x9e, 0xf0, 0x37, 0x53},
+        // 4bf6bb839b03b72839329b4ea70bb1b2f0d07e014d9d24aa9cc596114702bee3.pem
+        {0x12, 0x7d, 0xa2, 0x7a, 0x9e, 0x45, 0xf0, 0x82, 0x28, 0x0b, 0x31,
+         0xbf, 0x1e, 0x56, 0x15, 0x20, 0x38, 0x9f, 0x96, 0x65, 0x90, 0x93,
+         0xb2, 0x69, 0x7c, 0x40, 0xfe, 0x86, 0x00, 0x23, 0x6c, 0x8c},
+        // 0f912fd7be760be25afbc56bdc09cd9e5dcc9c6f6a55a778aefcb6aa30e31554.pem
+        {0x13, 0x0a, 0xd4, 0xe0, 0x63, 0x35, 0x21, 0x29, 0x05, 0x31, 0xb6,
+         0x65, 0x1f, 0x57, 0x59, 0xb0, 0xbc, 0x7b, 0xc6, 0x56, 0x70, 0x9f,
+         0xf8, 0xf3, 0x65, 0xc2, 0x14, 0x3b, 0x03, 0x89, 0xb6, 0xf6},
+        // 91018fcd3e0dc73f48d011a123f604d846d66821c58304474f949d7449dd600a.pem
+        {0x15, 0xe7, 0xae, 0x40, 0xcc, 0x4b, 0x3f, 0x72, 0x22, 0xa5, 0xa6,
+         0xfe, 0x3e, 0x7d, 0xc4, 0x7f, 0x6e, 0x46, 0xee, 0x9a, 0x22, 0x51,
+         0x83, 0x9d, 0xb2, 0x96, 0xd6, 0x2a, 0xda, 0x2a, 0x0d, 0xf7},
+        // c7ba6567de93a798ae1faa791e712d378fae1f93c4397fea441bb7cbe6fd5995.pem
+        {0x15, 0x28, 0x39, 0x7d, 0xa2, 0x12, 0x89, 0x0a, 0x83, 0x0b, 0x0b,
+         0x95, 0xa5, 0x99, 0x68, 0xce, 0xf2, 0x34, 0x77, 0x37, 0x79, 0xdf,
+         0x51, 0x81, 0xcf, 0x10, 0xfa, 0x64, 0x75, 0x34, 0xbb, 0x65},
+        // 1af56c98ff043ef92bebff54cebb4dd67a25ba956c817f3e6dd3c1e52eb584c1.key
+        {0x1a, 0xf5, 0x6c, 0x98, 0xff, 0x04, 0x3e, 0xf9, 0x2b, 0xeb, 0xff,
+         0x54, 0xce, 0xbb, 0x4d, 0xd6, 0x7a, 0x25, 0xba, 0x95, 0x6c, 0x81,
+         0x7f, 0x3e, 0x6d, 0xd3, 0xc1, 0xe5, 0x2e, 0xb5, 0x84, 0xc1},
+        // e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7.pem
+        {0x1f, 0x42, 0x24, 0xce, 0xc8, 0x4f, 0xc9, 0x9c, 0xed, 0x88, 0x1f,
+         0xf6, 0xfc, 0xfd, 0x3e, 0x21, 0xf8, 0xc5, 0x19, 0xc5, 0x47, 0xaa,
+         0x6a, 0x5d, 0xd3, 0xde, 0x24, 0x73, 0x02, 0xce, 0x50, 0xd1},
+        // e54e9fc27e7350ff63a77764a40267b7e95ae5df3ed7df5336e8f8541356c845.pem
+        {0x25, 0xda, 0x1a, 0xd5, 0x8b, 0xbf, 0xcf, 0xb2, 0x27, 0xd8, 0x72,
+         0x3b, 0x18, 0x57, 0xd4, 0xc1, 0x8e, 0x7b, 0xaa, 0x74, 0x17, 0xb4,
+         0xf9, 0xef, 0xf9, 0x36, 0x6b, 0x5e, 0x86, 0x9f, 0x8b, 0x39},
+        // 159ca03a88897c8f13817a212629df84ce824709492b8c9adb8e5437d2fc72be.pem
+        {0x2c, 0x99, 0x8e, 0x76, 0x11, 0x60, 0xc3, 0xb0, 0x6d, 0x82, 0xfa,
+         0xa9, 0xfd, 0xc7, 0x54, 0x5d, 0x9b, 0xda, 0x9e, 0xb6, 0x03, 0x10,
+         0xf9, 0x92, 0xaa, 0x51, 0x0a, 0x62, 0x80, 0xb7, 0x42, 0x45},
+        // 82a4cedbc7f61ce5cb04482aa27ea3145bb0cea58ab63ba1931a1654bfbdbb4f.pem
+        {0x2d, 0xc4, 0xcb, 0x59, 0x1f, 0x7e, 0xf0, 0x66, 0x34, 0x41, 0x64,
+         0x6b, 0xcf, 0x5c, 0x0e, 0x9d, 0xbc, 0xde, 0xd7, 0x7c, 0xa0, 0x29,
+         0x45, 0x19, 0x3c, 0xef, 0xc6, 0xed, 0xb1, 0x74, 0x06, 0x14},
+        // d0d672c2547d574ae055d9e78a993ddbcc74044c4253fbfaca573a67d368e1db.pem
+        {0x30, 0xef, 0xe4, 0x13, 0x82, 0x47, 0x6c, 0x33, 0x80, 0xf0, 0x2f,
+         0x7e, 0x23, 0xe6, 0x6b, 0xa2, 0xf8, 0x67, 0xb0, 0x59, 0xee, 0x1e,
+         0xa6, 0x87, 0x96, 0xb4, 0x41, 0xb8, 0x5b, 0x5d, 0x12, 0x56},
+        // 32ecc96f912f96d889e73088cd031c7ded2c651c805016157a23b6f32f798a3b.key
+        {0x32, 0xec, 0xc9, 0x6f, 0x91, 0x2f, 0x96, 0xd8, 0x89, 0xe7, 0x30,
+         0x88, 0xcd, 0x03, 0x1c, 0x7d, 0xed, 0x2c, 0x65, 0x1c, 0x80, 0x50,
+         0x16, 0x15, 0x7a, 0x23, 0xb6, 0xf3, 0x2f, 0x79, 0x8a, 0x3b},
+        // 4aefc3d39ef59e4d4b0304b20f53a8af2efb69edece66def74494abfc10a2d66.pem
+        {0x36, 0xea, 0x96, 0x12, 0x8c, 0x89, 0x83, 0x9f, 0xb6, 0x21, 0xf8,
+         0xad, 0x0e, 0x1e, 0xe0, 0xb9, 0xc2, 0x20, 0x6f, 0x62, 0xab, 0x7b,
+         0x4d, 0xa2, 0xc6, 0x76, 0x58, 0x93, 0xc9, 0xb7, 0xce, 0xd2},
+        // d487a56f83b07482e85e963394c1ecc2c9e51d0903ee946b02c301581ed99e16.pem
+        {0x38, 0x1a, 0x3f, 0xc7, 0xa8, 0xb0, 0x82, 0xfa, 0x28, 0x61, 0x3a,
+         0x4d, 0x07, 0xf2, 0xc7, 0x55, 0x3f, 0x4e, 0x19, 0x18, 0xee, 0x07,
+         0xca, 0xa9, 0xe8, 0xb7, 0xce, 0xde, 0x5a, 0x9c, 0xa0, 0x6a},
+        // 0ef7c54a3af101a2cfedb0c9f36fe8214d51a504fdc2ad1e243019cefd7d03c2.pem
+        {0x38, 0x3e, 0x0e, 0x13, 0x7c, 0x37, 0xbf, 0xb9, 0xdb, 0x29, 0xf9,
+         0xa8, 0xe4, 0x5e, 0x9f, 0xf8, 0xdd, 0x4c, 0x30, 0xe4, 0x40, 0xfe,
+         0xc2, 0xac, 0xd3, 0xdb, 0xa7, 0xb6, 0xc7, 0x20, 0xb9, 0x93},
+        // cb954e9d80a3e520ac71f1a84511657f2f309d172d0bb55e0ec2c236e74ff4b4.pem
+        {0x39, 0x4c, 0xff, 0x58, 0x9e, 0x68, 0x93, 0x12, 0xcf, 0xc0, 0x71,
+         0xee, 0x0b, 0xc1, 0x9f, 0xe4, 0xc6, 0x06, 0x21, 0x6c, 0xe5, 0x43,
+         0x42, 0x9d, 0xe6, 0xdb, 0x62, 0xe4, 0x2d, 0xbb, 0x3b, 0xc1},
+        // 42187727be39faf667aeb92bf0cc4e268f6e2ead2cefbec575bdc90430024f69.pem
+        {0x3e, 0xdb, 0xd9, 0xac, 0xe6, 0x39, 0xba, 0x1a, 0x2d, 0x4a, 0xd0,
+         0x47, 0x18, 0x71, 0x1f, 0xda, 0x23, 0xe8, 0x59, 0xb2, 0xfb, 0xf5,
+         0xd1, 0x37, 0xd4, 0x24, 0x04, 0x5e, 0x79, 0x19, 0xdf, 0xb9},
+        // 294f55ef3bd7244c6ff8a68ab797e9186ec27582751a791515e3292e48372d61.pem
+        {0x45, 0x5b, 0x87, 0xe9, 0x6f, 0x1c, 0xea, 0x2f, 0x8b, 0x6d, 0xae,
+         0x08, 0x08, 0xec, 0x24, 0x73, 0x8f, 0xd9, 0x2b, 0x7f, 0xd3, 0x06,
+         0x75, 0x71, 0x98, 0xbf, 0x38, 0x9d, 0x75, 0x5c, 0x0b, 0x6c},
+        // 3ab0fcc7287454c405863e3aa204fea8eb0c50a524d2a7e15524a830cd4ab0fe.pem
+        {0x49, 0x0b, 0x6e, 0xc6, 0xbe, 0xb2, 0xd6, 0x03, 0x47, 0x20, 0xb5,
+         0x14, 0x9b, 0x6b, 0x29, 0xcd, 0x35, 0x51, 0x59, 0x88, 0xcc, 0x16,
+         0xaf, 0x85, 0x41, 0x48, 0xb0, 0x7b, 0x9b, 0x1f, 0x8a, 0x11},
+        // b6fe9151402bad1c06d7e66db67a26aa7356f2e6c644dbcf9f98968ff632e1b7.pem
+        {0x4b, 0xb8, 0xf3, 0x5b, 0xa1, 0xe1, 0x26, 0xf8, 0xdd, 0xe1, 0xb0,
+         0xc4, 0x20, 0x62, 0x5e, 0xd8, 0x6d, 0xce, 0x61, 0xa7, 0xbd, 0xda,
+         0xdb, 0xde, 0xa9, 0xab, 0xa5, 0x78, 0xff, 0x13, 0x14, 0x5e},
+        // fa5a828c9a7e732692682e60b14c634309cbb2bb79eb12aef44318d853ee97e3.pem
+        {0x4c, 0xdb, 0x06, 0x0f, 0x3c, 0xfe, 0x4c, 0x3d, 0x3f, 0x5e, 0x31,
+         0xc3, 0x00, 0xfd, 0x68, 0xa9, 0x1e, 0x0d, 0x1e, 0x5f, 0x46, 0xb6,
+         0x4e, 0x48, 0x95, 0xf2, 0x0e, 0x1b, 0x5c, 0xf8, 0x26, 0x9f},
+        // ef3cb417fc8ebf6f97876c9e4ece39de1ea5fe649141d1028b7d11c0b2298ced.pem
+        {0x4e, 0xad, 0xa9, 0xb5, 0x31, 0x1e, 0x71, 0x81, 0x99, 0xd9, 0x8e,
+         0xa8, 0x2b, 0x95, 0x00, 0x5c, 0xba, 0x93, 0x19, 0x8a, 0xb1, 0xf9,
+         0x7e, 0xfc, 0xbe, 0x8d, 0xc6, 0x20, 0x16, 0x28, 0xf8, 0xaf},
+        // c1d80ce474a51128b77e794a98aa2d62a0225da3f419e5c7ed73dfbf660e7109.pem
+        {0x4f, 0x71, 0x62, 0xb9, 0x74, 0x49, 0x1c, 0x98, 0x58, 0x5e, 0xc2,
+         0x8f, 0xe7, 0x59, 0xaa, 0x00, 0xc3, 0x30, 0xd0, 0xb4, 0x65, 0x19,
+         0x0a, 0x89, 0x6c, 0xc4, 0xb6, 0x16, 0x23, 0x18, 0x31, 0xfc},
+        // 7abd72a323c9d179c722564f4e27a51dd4afd24006b38a40ce918b94960bcf18.pem
+        {0x57, 0x80, 0x94, 0x46, 0xea, 0xf1, 0x14, 0x84, 0x38, 0x54, 0xfe,
+         0x63, 0x6e, 0xd9, 0xbc, 0xb5, 0x52, 0xe3, 0xc6, 0x16, 0x66, 0x3b,
+         0xc4, 0x4c, 0xc9, 0x5a, 0xcf, 0x56, 0x50, 0x01, 0x6d, 0x3e},
+        // 817d4e05063d5942869c47d8504dc56a5208f7569c3d6d67f3457cfe921b3e29.pem
+        {0x5c, 0x72, 0x2c, 0xb7, 0x0f, 0xb3, 0x11, 0xf2, 0x1e, 0x0d, 0xa0,
+         0xe7, 0xd1, 0x2e, 0xbc, 0x8e, 0x05, 0xf6, 0x07, 0x96, 0xbc, 0x49,
+         0xcf, 0x51, 0x18, 0x49, 0xd5, 0xbc, 0x62, 0x03, 0x03, 0x82},
+        // 79f69a47cfd6c4b4ceae8030d04b49f6171d3b5d6c812f58d040e586f1cb3f14.pem
+        // 933f7d8cda9f0d7c8bfd3c22bf4653f4161fd38ccdcf66b22e95a2f49c2650f8.pem
+        // f8a5ff189fedbfe34e21103389a68340174439ad12974a4e8d4d784d1f3a0faa.pem
+        {0x5e, 0x53, 0xf2, 0x64, 0x67, 0xf8, 0x94, 0xfd, 0xe5, 0x3b, 0x3f,
+         0xa4, 0x06, 0xa4, 0x40, 0xcb, 0xb3, 0xb0, 0x76, 0xbb, 0x5b, 0x75,
+         0x8f, 0xe4, 0x83, 0x4a, 0xd6, 0x65, 0x00, 0x20, 0x89, 0x07},
+        // 2d11e736f0427fd6ba4b372755d34a0edd8d83f7e9e7f6c01b388c9b7afa850d.pem
+        {0x6a, 0xdb, 0x8e, 0x3e, 0x05, 0x54, 0x60, 0x92, 0x2d, 0x15, 0x01,
+         0xcb, 0x97, 0xf9, 0x4c, 0x6a, 0x02, 0xe3, 0x9c, 0x8f, 0x27, 0x74,
+         0xca, 0x40, 0x88, 0x25, 0xb7, 0xb5, 0x83, 0x79, 0xdc, 0x14},
+        // 2a33f5b48176523fd3c0d854f20093417175bfd498ef354cc7f38b54adabaf1a.pem
+        {0x70, 0x7d, 0x36, 0x4e, 0x72, 0xae, 0x52, 0x14, 0x31, 0xdd, 0x95,
+         0x38, 0x97, 0xf9, 0xc4, 0x84, 0x6d, 0x5b, 0x8c, 0x32, 0x42, 0x98,
+         0xfe, 0x53, 0xfb, 0xd4, 0xad, 0xa1, 0xf2, 0xd1, 0x15, 0x7f},
+        // f4a5984324de98bd979ef181a100cf940f2166173319a86a0d9d7c8fac3b0a8f.pem
+        {0x71, 0x65, 0xe9, 0x91, 0xad, 0xe7, 0x91, 0x6d, 0x86, 0xb4, 0x66,
+         0xab, 0xeb, 0xb6, 0xe4, 0x57, 0xca, 0x93, 0x1c, 0x80, 0x4e, 0x58,
+         0xce, 0x1f, 0xba, 0xba, 0xe5, 0x09, 0x15, 0x6f, 0xfb, 0x43},
+        // 3ae699d94e8febdacb86d4f90d40903333478e65e0655c432451197e33fa07f2.pem
+        {0x78, 0x1a, 0x4c, 0xf2, 0xe9, 0x24, 0x52, 0xf3, 0xee, 0x01, 0xd0,
+         0xc3, 0x81, 0xa4, 0x21, 0x4f, 0x39, 0x04, 0x16, 0x5c, 0x39, 0x0a,
+         0xdb, 0xd6, 0x1f, 0xcd, 0x11, 0x24, 0x4e, 0x09, 0xb2, 0xdc},
+        // 8b45da1c06f791eb0cabf26be588f5fb23165c2e614bf885562d0dce50b29b02.pem
+        {0x7a, 0xed, 0xdd, 0xf3, 0x6b, 0x18, 0xf8, 0xac, 0xb7, 0x37, 0x9f,
+         0xe1, 0xce, 0x18, 0x32, 0x12, 0xb2, 0x35, 0x0d, 0x07, 0x88, 0xab,
+         0xe0, 0xe8, 0x24, 0x57, 0xbe, 0x9b, 0xad, 0xad, 0x6d, 0x54},
+        // 5a885db19c01d912c5759388938cafbbdf031ab2d48e91ee15589b42971d039c.pem
+        {0x7a, 0xfe, 0x4b, 0x07, 0x1a, 0x2f, 0x1f, 0x46, 0xf8, 0xba, 0x94,
+         0x4a, 0x26, 0xd5, 0x84, 0xd5, 0x96, 0x0b, 0x92, 0xfb, 0x48, 0xc3,
+         0xba, 0x1b, 0x7c, 0xab, 0x84, 0x90, 0x5f, 0x32, 0xaa, 0xcd},
+        // c43807a64c51a3fbde5421011698013d8b46f4e315c46186dc23aea2670cd34f.pem
+        {0x7c, 0xd2, 0x95, 0xb7, 0x55, 0x44, 0x80, 0x8a, 0xbd, 0x94, 0x09,
+         0x46, 0x6f, 0x08, 0x37, 0xc5, 0xaa, 0xdc, 0x02, 0xe3, 0x3b, 0x61,
+         0x50, 0xc6, 0x64, 0x4d, 0xe0, 0xa0, 0x96, 0x59, 0xf2, 0x3c},
+        // f3bae5e9c0adbfbfb6dbf7e04e74be6ead3ca98a5604ffe591cea86c241848ec.pem
+        {0x7d, 0x5e, 0x3f, 0x50, 0x50, 0x81, 0x97, 0xb9, 0xa4, 0x78, 0xb1,
+         0x13, 0x40, 0xb7, 0xdc, 0xe2, 0x0a, 0x3c, 0x4d, 0xe4, 0x9c, 0x48,
+         0xc9, 0xa2, 0x94, 0x15, 0x8a, 0x89, 0x5c, 0x44, 0xa2, 0x1b},
+        // b8686723e415534bc0dbd16326f9486f85b0b0799bf6639334e61daae67f36cd.pem
+        {0x7e, 0x70, 0x58, 0xea, 0x35, 0xad, 0x43, 0x59, 0x65, 0x41, 0x59,
+         0x97, 0x3f, 0x56, 0x01, 0x87, 0xf1, 0x6d, 0x19, 0xc5, 0x14, 0xb9,
+         0x39, 0xc5, 0x05, 0x56, 0x72, 0xd1, 0xd2, 0xa5, 0x18, 0xac},
+        // 5e8e77aafdda2ba5ce442f27d8246650bbd6508befbeda35966a4dc7e6174edc.pem
+        {0x87, 0xbf, 0xd8, 0xaf, 0xa3, 0xaf, 0x5b, 0x42, 0x9d, 0x09, 0xa9,
+         0xaa, 0x54, 0xee, 0x61, 0x36, 0x4f, 0x5a, 0xe1, 0x11, 0x31, 0xe4,
+         0x38, 0xfc, 0x41, 0x09, 0x53, 0x43, 0xcd, 0x16, 0xb1, 0x35},
+        // 0c258a12a5674aef25f28ba7dcfaeceea348e541e6f5cc4ee63b71b361606ac3.pem
+        {0x8a, 0x2a, 0xff, 0xbd, 0x1a, 0x1c, 0x5d, 0x1b, 0xdc, 0xcb, 0xb7,
+         0xf5, 0x48, 0xba, 0x99, 0x5f, 0x96, 0x68, 0x06, 0xb3, 0xfd, 0x0c,
+         0x3a, 0x00, 0xfa, 0xe2, 0xe5, 0x2f, 0x3c, 0x85, 0x39, 0x89},
+        // 61c0fc2e38b5b6f9071b42cee54a9013d858b6697c68b460948551b3249576a1.pem
+        {0x8e, 0x12, 0xd0, 0xcb, 0x3b, 0x7d, 0xf3, 0xea, 0x22, 0x57, 0x57,
+         0x94, 0x89, 0xfd, 0x86, 0x58, 0xc9, 0x56, 0x03, 0xea, 0x6c, 0xf4,
+         0xb7, 0x31, 0x63, 0xa4, 0x1e, 0xb7, 0xb7, 0xe9, 0x3f, 0xee},
+        // ddd8ab9178c99cbd9685ea4ae66dc28bfdc9a5a8a166f7f69ad0b5042ad6eb28.pem
+        {0x8f, 0x59, 0x1f, 0x7a, 0xa4, 0xdc, 0x3e, 0xfe, 0x94, 0x90, 0xc3,
+         0x8a, 0x46, 0x92, 0xc9, 0x01, 0x1e, 0xd1, 0x28, 0xf1, 0xde, 0x59,
+         0x55, 0x69, 0x40, 0x6d, 0x77, 0xb6, 0xfa, 0x1f, 0x6b, 0x4c},
+        // 136335439334a7698016a0d324de72284e079d7b5220bb8fbd747816eebebaca.pem
+        {0x92, 0x7a, 0x1b, 0x85, 0x62, 0x28, 0x05, 0x76, 0xd0, 0x48, 0xc5,
+         0x03, 0x21, 0xad, 0xa4, 0x3d, 0x87, 0x03, 0xd2, 0xd9, 0x52, 0x1a,
+         0x18, 0xc2, 0x8b, 0x8c, 0x46, 0xcc, 0x6a, 0xae, 0x4e, 0xfd},
+        // 450f1b421bb05c8609854884559c323319619e8b06b001ea2dcbb74a23aa3be2.pem
+        {0x93, 0xca, 0x2d, 0x43, 0x6c, 0xae, 0x7f, 0x68, 0xd2, 0xb4, 0x25,
+         0x6c, 0xa1, 0x75, 0xc9, 0x85, 0xce, 0x39, 0x92, 0x6d, 0xc9, 0xf7,
+         0xee, 0xae, 0xec, 0xf2, 0xf8, 0x97, 0x0f, 0xb9, 0x78, 0x02},
+        // e757fd60d8dd4c26f77aca6a87f63ea4d38d0b736c7f79b56cad932d4c400fb5.pem
+        {0x96, 0x2e, 0x4b, 0x54, 0xbb, 0x98, 0xa7, 0xee, 0x5d, 0x5f, 0xeb,
+         0x96, 0x33, 0xf9, 0x91, 0xd3, 0xc3, 0x30, 0x0e, 0x95, 0x14, 0xda,
+         0xde, 0x7b, 0x0d, 0x4f, 0x82, 0x8c, 0x79, 0x4f, 0x8e, 0x87},
+        // 3d3d823fad13dfeef32da580166d4a4992bed5a22d695d12c8b08cc3463c67a2.pem
+        {0x96, 0x8d, 0xba, 0x69, 0xfb, 0xff, 0x15, 0xbf, 0x37, 0x62, 0x08,
+         0x94, 0x31, 0xad, 0xe5, 0xa7, 0xea, 0xd4, 0xb7, 0xea, 0xf1, 0xbe,
+         0x70, 0x02, 0x68, 0x10, 0xbc, 0x57, 0xd1, 0xc6, 0x4f, 0x6e},
+        // 1f17f2cbb109f01c885c94d9e74a48625ae9659665d6d7e7bc5a10332976370f.pem
+        {0x99, 0xba, 0x47, 0x84, 0xf9, 0xb0, 0x85, 0x12, 0x90, 0x2e, 0xb0,
+         0xc3, 0xc8, 0x6d, 0xf0, 0xec, 0x04, 0x9e, 0xac, 0x9b, 0x65, 0xf7,
+         0x7a, 0x9b, 0xa4, 0x2b, 0xe9, 0xd6, 0xeb, 0xce, 0x32, 0x0f},
+        // a8e1dfd9cd8e470aa2f443914f931cfd61c323e94d75827affee985241c35ce5.pem
+        {0x9b, 0x8a, 0x93, 0xde, 0xcc, 0xcf, 0xba, 0xfc, 0xf4, 0xd0, 0x4d,
+         0x34, 0x42, 0x12, 0x8f, 0xb3, 0x52, 0x18, 0xcf, 0xe4, 0x37, 0xa3,
+         0xd8, 0xd0, 0x32, 0x8c, 0x99, 0xf8, 0x90, 0x89, 0xe4, 0x50},
+        // 8253da6738b60c5c0bb139c78e045428a0c841272abdcb952f95ff05ed1ab476.pem
+        {0x9c, 0x59, 0xa3, 0xcc, 0xae, 0xa4, 0x69, 0x98, 0x42, 0xb0, 0x68,
+         0xcf, 0xc5, 0x2c, 0xf9, 0x45, 0xdb, 0x51, 0x98, 0x69, 0x57, 0xc8,
+         0x32, 0xcd, 0xb1, 0x8c, 0xa7, 0x38, 0x49, 0xfb, 0xb9, 0xee},
+        // 7d8ce822222b90c0b14342c7a8145d1f24351f4d1a1fe0edfd312ee73fb00149.pem
+        {0x9d, 0x98, 0xa1, 0xfb, 0x60, 0x53, 0x8c, 0x4c, 0xc4, 0x85, 0x7f,
+         0xf1, 0xa8, 0xc8, 0x03, 0x4f, 0xaf, 0x6f, 0xc5, 0x92, 0x09, 0x3f,
+         0x61, 0x99, 0x94, 0xb2, 0xc8, 0x13, 0xd2, 0x50, 0xb8, 0x64},
+        // 1c01c6f4dbb2fefc22558b2bca32563f49844acfc32b7be4b0ff599f9e8c7af7.pem
+        {0x9d, 0xd5, 0x5f, 0xc5, 0x73, 0xf5, 0x46, 0xcb, 0x6a, 0x38, 0x31,
+         0xd1, 0x11, 0x2d, 0x87, 0x10, 0xa6, 0xf4, 0xf8, 0x2d, 0xc8, 0x7f,
+         0x5f, 0xae, 0x9d, 0x3a, 0x1a, 0x02, 0x8d, 0xd3, 0x6e, 0x4b},
+        // 487afc8d0d411b2a05561a2a6f35918f4040e5570c4c73ee323cc50583bcfbb7.pem
+        {0xa0, 0xcf, 0x53, 0xf4, 0x22, 0x65, 0x1e, 0x39, 0x31, 0x7a, 0xe3,
+         0x1a, 0xf6, 0x45, 0x77, 0xbe, 0x45, 0x0f, 0xa3, 0x76, 0xe2, 0x89,
+         0xed, 0x83, 0x42, 0xb7, 0xfc, 0x13, 0x3c, 0x69, 0x74, 0x19},
+        // 0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217.pem
+        // 4fee0163686ecbd65db968e7494f55d84b25486d438e9de558d629d28cd4d176.pem
+        // 8a1bd21661c60015065212cc98b1abb50dfd14c872a208e66bae890f25c448af.pem
+        {0xa9, 0x03, 0xaf, 0x8c, 0x07, 0xbb, 0x91, 0xb0, 0xd9, 0xe3, 0xf3,
+         0xa3, 0x0c, 0x6d, 0x53, 0x33, 0x9f, 0xc5, 0xbd, 0x47, 0xe5, 0xd6,
+         0xbd, 0xb4, 0x76, 0x59, 0x88, 0x60, 0xc0, 0x68, 0xa0, 0x24},
+        // a2e3bdaacaaf2d2e8204b3bc7eddc805d54d3ab8bdfe7bf102c035f67d8f898a.pem
+        {0xa9, 0xb5, 0x5a, 0x9b, 0x55, 0x31, 0xbb, 0xf7, 0xc7, 0x1a, 0x1e,
+         0x49, 0x20, 0xef, 0xe7, 0x96, 0xc2, 0xb6, 0x79, 0x68, 0xf5, 0x5a,
+         0x6c, 0xe5, 0xcb, 0x62, 0x17, 0x2e, 0xd9, 0x94, 0x5b, 0xca},
+        // 5472692abe5d02cd22eae3e0a0077f17802721d6576cde1cba2263ee803410c5.pem
+        {0xaf, 0x59, 0x15, 0x18, 0xe2, 0xe6, 0xc6, 0x0e, 0xbb, 0xfc, 0x09,
+         0x07, 0xaf, 0xaa, 0x49, 0xbc, 0x40, 0x51, 0xd4, 0x5e, 0x7f, 0x21,
+         0x4a, 0xbf, 0xee, 0x75, 0x12, 0xee, 0x00, 0xf6, 0x61, 0xed},
+        // 1df696f021ab1c3ace9a376b07ed7256a40214cd3396d7934087614924e2d7ef.pem
+        {0xb1, 0x3f, 0xa2, 0xe6, 0x13, 0x1a, 0x88, 0x8a, 0x01, 0xf3, 0xd6,
+         0x20, 0x56, 0xfb, 0x0e, 0xfb, 0xe9, 0x99, 0xeb, 0x6b, 0x6e, 0x14,
+         0x92, 0x76, 0x13, 0xe0, 0x2b, 0xa8, 0xb8, 0xfb, 0x04, 0x6e},
+        // b8c1b957c077ea76e00b0f45bff5ae3acb696f221d2e062164fe37125e5a8d25.pem
+        {0xb3, 0x18, 0x2e, 0x28, 0x9a, 0xe3, 0x4d, 0xdf, 0x2b, 0xe6, 0x43,
+         0xab, 0x79, 0xc2, 0x44, 0x30, 0x16, 0x05, 0xfa, 0x0f, 0x1e, 0xaa,
+         0xe6, 0xd1, 0x0f, 0xb9, 0x29, 0x60, 0x0a, 0xf8, 0x4d, 0xf0},
+        // be144b56fb1163c49c9a0e6b5a458df6b29f7e6449985960c178a4744624b7bc.pem
+        {0xb4, 0xd5, 0xc9, 0x20, 0x41, 0x5e, 0xd0, 0xcc, 0x4f, 0x5d, 0xbc,
+         0x7f, 0x54, 0x26, 0x36, 0x76, 0x2e, 0x80, 0xda, 0x66, 0x25, 0xf3,
+         0x3f, 0x2b, 0x6a, 0xd6, 0xdb, 0x68, 0xbd, 0xba, 0xb2, 0x9a},
+        // 00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2.pem
+        {0xb5, 0xba, 0x8d, 0xd7, 0xf8, 0x95, 0x64, 0xc2, 0x88, 0x9d, 0x3d,
+         0x64, 0x53, 0xc8, 0x49, 0x98, 0xc7, 0x78, 0x24, 0x91, 0x9b, 0x64,
+         0xea, 0x08, 0x35, 0xaa, 0x62, 0x98, 0x65, 0x91, 0xbe, 0x50},
+        // 04f1bec36951bc1454a904ce32890c5da3cde1356b7900f6e62dfa2041ebad51.pem
+        {0xb8, 0x9b, 0xcb, 0xb8, 0xac, 0xd4, 0x74, 0xc1, 0xbe, 0xa7, 0xda,
+         0xd6, 0x50, 0x37, 0xf4, 0x8d, 0xce, 0xcc, 0x9d, 0xfa, 0xa0, 0x61,
+         0x2c, 0x3c, 0x24, 0x45, 0x95, 0x64, 0x19, 0xdf, 0x32, 0xfe},
+        // d8888f4a84f74c974dffb573a1bf5bbbacd1713b905096f8eb015062bf396c4d.pem
+        {0xc0, 0xed, 0x20, 0x53, 0x46, 0xbb, 0xbd, 0xe0, 0x6e, 0xb5, 0x60,
+         0xf5, 0xce, 0xe0, 0x2a, 0x36, 0x34, 0xe2, 0x47, 0x4a, 0x7e, 0x76,
+         0xcf, 0x8f, 0xbe, 0xf5, 0x63, 0xbb, 0x11, 0x7d, 0xd0, 0xe3},
+        // 372447c43185c38edd2ce0e9c853f9ac1576ddd1704c2f54d96076c089cb4227.pem
+        {0xc1, 0x73, 0xf0, 0x62, 0x64, 0x56, 0xca, 0x85, 0x4f, 0xf2, 0xa7,
+         0xf0, 0xb1, 0x33, 0xa7, 0xcf, 0x4d, 0x02, 0x11, 0xe5, 0x52, 0xf2,
+         0x4b, 0x3e, 0x33, 0xad, 0xe8, 0xc5, 0x9f, 0x0a, 0x42, 0x4c},
+        // c4387d45364a313fbfe79812b35b815d42852ab03b06f11589638021c8f2cb44.key
+        {0xc4, 0x38, 0x7d, 0x45, 0x36, 0x4a, 0x31, 0x3f, 0xbf, 0xe7, 0x98,
+         0x12, 0xb3, 0x5b, 0x81, 0x5d, 0x42, 0x85, 0x2a, 0xb0, 0x3b, 0x06,
+         0xf1, 0x15, 0x89, 0x63, 0x80, 0x21, 0xc8, 0xf2, 0xcb, 0x44},
+        // 8290cc3fc1c3aac3239782c141ace8f88aeef4e9576a43d01867cf19d025be66.pem
+        // 9532e8b504964331c271f3f5f10070131a08bf8ba438978ce394c34feeae246f.pem
+        {0xc6, 0x01, 0x23, 0x4e, 0x2b, 0x93, 0x25, 0xdc, 0x92, 0xe3, 0xea,
+         0xba, 0xc1, 0x96, 0x00, 0xb0, 0xb4, 0x99, 0x47, 0xd4, 0xd0, 0x4d,
+         0x8c, 0x99, 0xd3, 0x21, 0x27, 0x49, 0x3e, 0xa0, 0x28, 0xf8},
+        // 0753e940378c1bd5e3836e395daea5cb839e5046f1bd0eae1951cf10fec7c965.pem
+        {0xc6, 0x3d, 0x68, 0xc6, 0x48, 0xa1, 0x8b, 0x77, 0x64, 0x1c, 0x42,
+         0x7a, 0x66, 0x9d, 0x61, 0xc9, 0x76, 0x8a, 0x55, 0xf4, 0xfc, 0xd0,
+         0x32, 0x2e, 0xac, 0x96, 0xc5, 0x77, 0x00, 0x29, 0x9c, 0xf1},
+        // 53d48e7b8869a3314f213fd2e0178219ca09022dbe50053bf6f76fccd61e8112.pem
+        {0xc8, 0xfd, 0xdc, 0x75, 0xcb, 0x1b, 0xdb, 0xb5, 0x8c, 0x07, 0xb4,
+         0xea, 0x84, 0x72, 0x87, 0xf6, 0x26, 0x65, 0x9d, 0xd6, 0x6b, 0xc1,
+         0x0a, 0x26, 0xad, 0xd9, 0xb5, 0x75, 0xb3, 0xa0, 0xa3, 0x8d},
+        // ec30c9c3065a06bb07dc5b1c6b497f370c1ca65c0f30c08e042ba6bcecc78f2c.pem
+        {0xcd, 0xee, 0x9f, 0x33, 0x05, 0x57, 0x2a, 0x67, 0x7e, 0x1a, 0x6c,
+         0x82, 0xdc, 0x1e, 0x02, 0xa3, 0x5b, 0x11, 0xca, 0xe6, 0xa6, 0x84,
+         0x33, 0x8c, 0x9f, 0x37, 0xfe, 0x1a, 0xc8, 0xda, 0xec, 0x23},
+        // 063e4afac491dfd332f3089b8542e94617d893d7fe944e10a7937ee29d9693c0.pem
+        {0xce, 0xd4, 0x39, 0x02, 0xab, 0x5f, 0xb5, 0x7b, 0x44, 0x23, 0x22,
+         0xdc, 0x0e, 0x17, 0x2a, 0x4f, 0xb5, 0x5f, 0x71, 0x78, 0xb8, 0x08,
+         0xf9, 0x4e, 0x78, 0x0a, 0x6f, 0xd6, 0xcc, 0x6b, 0xd8, 0x18},
+        // c71f33c36d8efeefbed9d44e85e21cfe96b36fb0e132c52dca2415868492bf8a.pem
+        {0xd3, 0x1e, 0xc3, 0x92, 0x85, 0xb7, 0xa5, 0x31, 0x9d, 0x01, 0x57,
+         0xdb, 0x42, 0x0e, 0xd8, 0x7c, 0x74, 0x3e, 0x33, 0x3b, 0xbc, 0x77,
+         0xf8, 0x77, 0x1f, 0x70, 0x46, 0x4f, 0x43, 0x6a, 0x60, 0x49},
+        // 9ed8f9b0e8e42a1656b8e1dd18f42ba42dc06fe52686173ba2fc70e756f207dc.pem
+        // a686fee577c88ab664d0787ecdfff035f4806f3de418dc9e4d516324fff02083.pem
+        // fdedb5bdfcb67411513a61aee5cb5b5d7c52af06028efc996cc1b05b1d6cea2b.pem
+        {0xd3, 0x4b, 0x25, 0x5b, 0x2f, 0xe7, 0xd1, 0xa0, 0x96, 0x56, 0xcb,
+         0xab, 0x64, 0x09, 0xf7, 0x3c, 0x79, 0x6e, 0xc7, 0xd6, 0x6a, 0xf7,
+         0x36, 0x53, 0xec, 0xc3, 0x9a, 0xf9, 0x78, 0x29, 0x73, 0x10},
+        // 4b22d5a6aec99f3cdb79aa5ec06838479cd5ecba7164f7f22dc1d65f63d85708.pem
+        {0xd6, 0xa1, 0x84, 0x43, 0xd3, 0x48, 0xdb, 0x99, 0x4f, 0x93, 0x4c,
+         0xcd, 0x8e, 0x63, 0x5d, 0x83, 0x3a, 0x27, 0xac, 0x1e, 0x56, 0xf8,
+         0xaf, 0xaf, 0x7c, 0x97, 0xcb, 0x4f, 0x43, 0xea, 0xb6, 0x8b},
+        // d6f034bd94aa233f0297eca4245b283973e447aa590f310c77f48fdf83112254.pem
+        {0xdb, 0x15, 0xc0, 0x06, 0x2b, 0x52, 0x0f, 0x31, 0x8a, 0x19, 0xda,
+         0xcf, 0xec, 0xd6, 0x4f, 0x9e, 0x7a, 0x3f, 0xbe, 0x60, 0x9f, 0xd5,
+         0x86, 0x79, 0x6f, 0x20, 0xae, 0x02, 0x8e, 0x8e, 0x30, 0x58},
+        // 2a4397aafa6227fa11f9f9d76ecbb022b0a4494852c2b93fb2085c8afb19b62a.pem
+        {0xdb, 0x1d, 0x13, 0xec, 0x42, 0xa2, 0xcb, 0xa3, 0x67, 0x3b, 0xa6,
+         0x7a, 0xf2, 0xde, 0xf8, 0x12, 0xe9, 0xc3, 0x55, 0x66, 0x61, 0x75,
+         0x76, 0xd9, 0x5b, 0x4d, 0x6f, 0xac, 0xe3, 0xef, 0x0a, 0xe8},
+        // 3946901f46b0071e90d78279e82fababca177231a704be72c5b0e8918566ea66.pem
+        {0xdd, 0x3e, 0xeb, 0x77, 0x9b, 0xee, 0x07, 0xf9, 0xef, 0xda, 0xc3,
+         0x82, 0x40, 0x8b, 0x28, 0xd1, 0x42, 0xfa, 0x84, 0x2c, 0x78, 0xe8,
+         0xbc, 0x0e, 0x33, 0x34, 0x8d, 0x57, 0xb9, 0x2f, 0x05, 0x83},
+        // c67d722c1495be02cbf9ef1159f5ca4aa782dc832dc6aa60c9aa076a0ad1e69d.pem
+        {0xde, 0x8f, 0x05, 0x07, 0x4e, 0xc0, 0x31, 0x8e, 0x7e, 0x7e, 0x8d,
+         0x31, 0x90, 0xda, 0xe8, 0xb0, 0x08, 0x94, 0xf0, 0xe8, 0xdd, 0xdf,
+         0xd3, 0x91, 0x3d, 0x01, 0x75, 0x9b, 0x4f, 0x79, 0xb0, 0x5d},
+        // c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea.pem
+        // e17890ee09a3fbf4f48b9c414a17d637b7a50647e9bc752322727fcc1742a911.pem
+        {0xe4, 0x2f, 0x24, 0xbd, 0x4d, 0x37, 0xf4, 0xaa, 0x2e, 0x56, 0xb9,
+         0x79, 0xd8, 0x3d, 0x1e, 0x65, 0x21, 0x9f, 0xe0, 0xe9, 0xe3, 0xa3,
+         0x82, 0xa1, 0xb3, 0xcb, 0x66, 0xc9, 0x39, 0x55, 0xde, 0x75},
+        // e4f9a3235df7330255f36412bc849fb630f8519961ec3538301deb896c953da5.pem
+        {0xe6, 0xe1, 0x36, 0xc8, 0x61, 0x54, 0xf3, 0x2c, 0x3e, 0x49, 0xf4,
+         0x7c, 0xfc, 0x6b, 0x33, 0x8f, 0xf2, 0xdc, 0x61, 0xce, 0x14, 0xfc,
+         0x75, 0x89, 0xb3, 0xb5, 0x6a, 0x14, 0x50, 0x13, 0x27, 0x01},
+        // 3e26492e20b52de79e15766e6cb4251a1d566b0dbfb225aa7d08dda1dcebbf0a.pem
+        {0xe7, 0xb9, 0x32, 0xae, 0x7e, 0x9b, 0xdc, 0x70, 0x1d, 0x77, 0x1d,
+         0x6f, 0x39, 0xe8, 0xa6, 0x53, 0x44, 0x9e, 0xea, 0x43, 0xbd, 0xb4,
+         0x7b, 0xd9, 0x10, 0x22, 0x95, 0x0d, 0x91, 0x79, 0xd8, 0x7e},
+        // 5ccaf9f8f2bb3a0d215922eca383354b6ee3c62407ed32e30f6fb2618edeea10.pem
+        {0xe8, 0x49, 0xc7, 0x17, 0x6c, 0x93, 0xdf, 0x65, 0xf6, 0x4b, 0x61,
+         0x69, 0x82, 0x36, 0x6e, 0x56, 0x63, 0x11, 0x78, 0x12, 0xb6, 0xfa,
+         0x2b, 0xc0, 0xc8, 0xfa, 0x8a, 0xea, 0xee, 0x41, 0x81, 0xcc},
+        // ea08c8d45d52ca593de524f0513ca6418da9859f7b08ef13ff9dd7bf612d6a37.key
+        {0xea, 0x08, 0xc8, 0xd4, 0x5d, 0x52, 0xca, 0x59, 0x3d, 0xe5, 0x24,
+         0xf0, 0x51, 0x3c, 0xa6, 0x41, 0x8d, 0xa9, 0x85, 0x9f, 0x7b, 0x08,
+         0xef, 0x13, 0xff, 0x9d, 0xd7, 0xbf, 0x61, 0x2d, 0x6a, 0x37},
+        // d40e9c86cd8fe468c1776959f49ea774fa548684b6c406f3909261f4dce2575c.pem
+        {0xea, 0x87, 0xf4, 0x62, 0xde, 0xef, 0xff, 0xbd, 0x77, 0x75, 0xaa,
+         0x2a, 0x4b, 0x7e, 0x0f, 0xcb, 0x91, 0xc2, 0x2e, 0xee, 0x6d, 0xf6,
+         0x9e, 0xd9, 0x01, 0x00, 0xcc, 0xc7, 0x3b, 0x31, 0x14, 0x76},
+        // 60911c79835c3739432d08c45df64311e06985c5889dc5420ce3d142c8c7ef58.pem
+        {0xef, 0x55, 0x12, 0x84, 0x71, 0x52, 0x32, 0xde, 0x92, 0xe2, 0x46,
+         0xc3, 0x23, 0x32, 0x93, 0x62, 0xb1, 0x32, 0x49, 0x3b, 0xb1, 0x6b,
+         0x58, 0x9e, 0x47, 0x75, 0x52, 0x0b, 0xeb, 0x87, 0x1a, 0x56},
+        // 31c8fd37db9b56e708b03d1f01848b068c6da66f36fb5d82c008c6040fa3e133.pem
+        {0xf0, 0x34, 0xf6, 0x42, 0xca, 0x1d, 0x9e, 0x88, 0xe9, 0xef, 0xea,
+         0xfc, 0xb1, 0x5c, 0x7c, 0x93, 0x7a, 0xa1, 0x9e, 0x04, 0xb0, 0x80,
+         0xf2, 0x73, 0x35, 0xe1, 0xda, 0x70, 0xd1, 0xca, 0x12, 0x01},
+        // 83618f932d6947744d5ecca299d4b2820c01483947bd16be814e683f7436be24.pem
+        {0xf2, 0xbb, 0xe0, 0x4c, 0x5d, 0xc7, 0x0d, 0x76, 0x3e, 0x89, 0xc5,
+         0xa0, 0x52, 0x70, 0x48, 0xcd, 0x9e, 0xcd, 0x39, 0xeb, 0x62, 0x1e,
+         0x20, 0x72, 0xff, 0x9a, 0x5f, 0x84, 0x32, 0x57, 0x1a, 0xa0},
+        // 2a3699deca1e9fd099ba45de8489e205977c9f2a5e29d5dd747381eec0744d71.pem
+        {0xf3, 0x0e, 0x8f, 0x61, 0x01, 0x1d, 0x65, 0x87, 0x3c, 0xcb, 0x81,
+         0xb4, 0x0f, 0xa6, 0x21, 0x97, 0x49, 0xb9, 0x94, 0xf0, 0x1f, 0xa2,
+         0x4d, 0x02, 0x01, 0xd5, 0x21, 0xc2, 0x43, 0x56, 0x03, 0xca},
+        // 0d90cd8e35209b4cefebdd62b644bed8eb55c74dddff26e75caf8ae70491f0bd.pem
+        {0xf5, 0x29, 0x3d, 0x47, 0xed, 0x38, 0xd4, 0xc3, 0x1b, 0x2d, 0x42,
+         0xde, 0xe3, 0xb5, 0xb3, 0xac, 0xe9, 0x7c, 0xa2, 0x6c, 0xa2, 0xac,
+         0x03, 0x65, 0xe3, 0x62, 0x2e, 0xe8, 0x02, 0x13, 0x1f, 0xbb},
+        // 67ed4b703d15dc555f8c444b3a05a32579cb7599bd19c9babe10c584ea327ae0.pem
+        {0xfa, 0x00, 0xbe, 0xc7, 0x3d, 0xd9, 0x97, 0x95, 0xdf, 0x11, 0x62,
+         0xc7, 0x89, 0x98, 0x70, 0x04, 0xc2, 0x6c, 0xbf, 0x90, 0xaf, 0x4d,
+         0xb4, 0x42, 0xf6, 0x62, 0x20, 0xde, 0x41, 0x35, 0x4a, 0xc9},
+        // a25a19546819d048000ef9c6577c4bcd8d2155b1e4346a4599d6c8b79799d4a1.pem
+        {0xfc, 0xd7, 0x6c, 0xca, 0x23, 0x47, 0xe5, 0xcd, 0x5b, 0x39, 0x34,
+         0x7f, 0x51, 0xcf, 0x43, 0x65, 0x4b, 0x69, 0xa2, 0xbf, 0xc9, 0x07,
+         0x36, 0x70, 0xa6, 0xbe, 0x47, 0xd8, 0x70, 0x1e, 0x6e, 0x0e},
+        // 44a244105569a730791f509b24c3d7838a462216bb0f560ef87fbe76c2e6005a.pem
+        {0xb0, 0xfc, 0xce, 0x78, 0xc1, 0x66, 0x4e, 0x29, 0x35, 0x44, 0xc1,
+         0x43, 0xe3, 0xd2, 0x68, 0x9f, 0x72, 0x3f, 0x5b, 0x6e, 0x63, 0x17,
+         0x10, 0x7e, 0x16, 0x3d, 0x22, 0xba, 0x80, 0x69, 0x79, 0x4a},
+        // 0230a604d99220e5612ee7862ab9f7a6e18e4f1ac4c9e27075788cc5220169ab.pem
+        {0xc5, 0x62, 0x17, 0xb7, 0xa8, 0x28, 0xc7, 0x34, 0x1c, 0x0a, 0xe7,
+         0xa5, 0x90, 0xd8, 0x79, 0x0d, 0x4d, 0xef, 0x53, 0x66, 0x52, 0xe6,
+         0x0a, 0xe5, 0xb8, 0xbd, 0xfa, 0x26, 0x97, 0x8f, 0xe0, 0x9c},
+        // 06fd20629c143b9eab28d2799caefc5d23fde267d16c631e3f5b8b4bab3f68e6.pem
+        {0xe4, 0x7c, 0x5c, 0xd2, 0xdc, 0x8b, 0xab, 0xb4, 0xe5, 0x3f, 0x8a,
+         0x49, 0x83, 0x92, 0x02, 0x75, 0xef, 0x6f, 0xfa, 0xac, 0xb0, 0x89,
+         0xe8, 0x7a, 0x2c, 0x1f, 0xbe, 0x5a, 0x58, 0x5f, 0x05, 0xed},
+        // 0bd39de4793cdc117138f47708aa4d583acf67adb059a0d91f668d1803bf6489.pem
+        {0x39, 0x73, 0x65, 0x88, 0xb9, 0x4a, 0x4c, 0xe7, 0x67, 0xf7, 0x31,
+         0xca, 0xd5, 0x3f, 0x4c, 0xbe, 0x44, 0x13, 0x7e, 0x32, 0x1e, 0xad,
+         0xca, 0xef, 0x8c, 0xe7, 0x9a, 0x22, 0x9b, 0xbc, 0xa9, 0x89},
+        // c95c133b68319ee516b5f41e377f589878af1556567cc2834ef03b1d10830fd3.pem
+        {0xea, 0x12, 0x70, 0x5d, 0xe7, 0xc4, 0x8f, 0x6f, 0xcc, 0xe2, 0xcb,
+         0x8d, 0xbc, 0x54, 0x2e, 0x0f, 0xc3, 0x8a, 0xc3, 0x8e, 0x08, 0x88,
+         0x0d, 0xd0, 0x4a, 0x02, 0xef, 0x67, 0xc9, 0x3a, 0xe1, 0x35},
+        // 29abf614b2870ed70df11225e9ae2068e3074eb9845ae252c2064e31ce9fe8a1.pem
+        {0xa6, 0xac, 0xa1, 0xec, 0x98, 0x09, 0xcc, 0x5b, 0x48, 0x21, 0xff,
+         0x9d, 0x29, 0xc5, 0xeb, 0xe6, 0x51, 0x96, 0x0b, 0x91, 0xb1, 0xf1,
+         0x9c, 0xc8, 0x9b, 0x55, 0xef, 0x87, 0x81, 0x8a, 0x95, 0x09},
+        // c530fadc9bfa265e63b755cc6ee04c2d70d60bb916ce2f331dc7359362571b25.pem
+        {0x02, 0xa9, 0x5f, 0x43, 0x43, 0x10, 0x19, 0xe9, 0xdc, 0x22, 0x5f,
+         0x05, 0xf4, 0x19, 0x33, 0x01, 0x90, 0xde, 0xb4, 0xa3, 0xf1, 0x86,
+         0x9c, 0xaa, 0xc9, 0x84, 0x2b, 0x40, 0x3d, 0xcb, 0xee, 0x77},
+        // 89107c8e50e029b7b5f4ff0ccd2956bcc9d0c8ba2bfb6a58374ed63a6b034a30.pem
+        {0x89, 0x28, 0xc5, 0x93, 0x98, 0xb0, 0xf1, 0x71, 0xc0, 0xf9, 0x6f,
+         0xda, 0xe6, 0xab, 0x8d, 0xd0, 0xf4, 0x8e, 0xe0, 0x6d, 0x17, 0x4d,
+         0xa1, 0x0c, 0x40, 0x4a, 0xc0, 0x01, 0x43, 0xc7, 0xa7, 0x49},
+};
+
+// Hashes of SubjectPublicKeyInfos known to be used for interception by a
+// party other than the device or machine owner.
+static constexpr uint8_t kKnownInterceptionList[][crypto::kSHA256Length] = {
+    // 1df696f021ab1c3ace9a376b07ed7256a40214cd3396d7934087614924e2d7ef.pem
+    {0xb1, 0x3f, 0xa2, 0xe6, 0x13, 0x1a, 0x88, 0x8a, 0x01, 0xf3, 0xd6, 0x20,
+     0x56, 0xfb, 0x0e, 0xfb, 0xe9, 0x99, 0xeb, 0x6b, 0x6e, 0x14, 0x92, 0x76,
+     0x13, 0xe0, 0x2b, 0xa8, 0xb8, 0xfb, 0x04, 0x6e},
+    // 61c0fc2e38b5b6f9071b42cee54a9013d858b6697c68b460948551b3249576a1.pem
+    {0x8e, 0x12, 0xd0, 0xcb, 0x3b, 0x7d, 0xf3, 0xea, 0x22, 0x57, 0x57, 0x94,
+     0x89, 0xfd, 0x86, 0x58, 0xc9, 0x56, 0x03, 0xea, 0x6c, 0xf4, 0xb7, 0x31,
+     0x63, 0xa4, 0x1e, 0xb7, 0xb7, 0xe9, 0x3f, 0xee},
+    // 143315c857a9386973ed16840899c3f96b894a7a612c444efb691f14b0dedd87.pem
+    {0xa4, 0xe9, 0xaf, 0x01, 0x41, 0x6e, 0x3a, 0x02, 0x9b, 0x5d, 0x35, 0xe5,
+     0xb1, 0x19, 0xde, 0x00, 0xcf, 0xe1, 0x56, 0xc5, 0xcf, 0x95, 0xfc, 0x82,
+     0x3c, 0xf6, 0xd0, 0x5e, 0x3c, 0x1a, 0x82, 0x37},
+    // 44a244105569a730791f509b24c3d7838a462216bb0f560ef87fbe76c2e6005a.pem
+    {0xb0, 0xfc, 0xce, 0x78, 0xc1, 0x66, 0x4e, 0x29, 0x35, 0x44, 0xc1, 0x43,
+     0xe3, 0xd2, 0x68, 0x9f, 0x72, 0x3f, 0x5b, 0x6e, 0x63, 0x17, 0x10, 0x7e,
+     0x16, 0x3d, 0x22, 0xba, 0x80, 0x69, 0x79, 0x4a},
+    // 0230a604d99220e5612ee7862ab9f7a6e18e4f1ac4c9e27075788cc5220169ab.pem
+    {0xc5, 0x62, 0x17, 0xb7, 0xa8, 0x28, 0xc7, 0x34, 0x1c, 0x0a, 0xe7, 0xa5,
+     0x90, 0xd8, 0x79, 0x0d, 0x4d, 0xef, 0x53, 0x66, 0x52, 0xe6, 0x0a, 0xe5,
+     0xb8, 0xbd, 0xfa, 0x26, 0x97, 0x8f, 0xe0, 0x9c},
+    // 06fd20629c143b9eab28d2799caefc5d23fde267d16c631e3f5b8b4bab3f68e6.pem
+    {0xe4, 0x7c, 0x5c, 0xd2, 0xdc, 0x8b, 0xab, 0xb4, 0xe5, 0x3f, 0x8a, 0x49,
+     0x83, 0x92, 0x02, 0x75, 0xef, 0x6f, 0xfa, 0xac, 0xb0, 0x89, 0xe8, 0x7a,
+     0x2c, 0x1f, 0xbe, 0x5a, 0x58, 0x5f, 0x05, 0xed},
+    // 0bd39de4793cdc117138f47708aa4d583acf67adb059a0d91f668d1803bf6489.pem
+    {0x39, 0x73, 0x65, 0x88, 0xb9, 0x4a, 0x4c, 0xe7, 0x67, 0xf7, 0x31,
+     0xca, 0xd5, 0x3f, 0x4c, 0xbe, 0x44, 0x13, 0x7e, 0x32, 0x1e, 0xad,
+     0xca, 0xef, 0x8c, 0xe7, 0x9a, 0x22, 0x9b, 0xbc, 0xa9, 0x89},
+    // c95c133b68319ee516b5f41e377f589878af1556567cc2834ef03b1d10830fd3.pem
+    {0xea, 0x12, 0x70, 0x5d, 0xe7, 0xc4, 0x8f, 0x6f, 0xcc, 0xe2, 0xcb, 0x8d,
+     0xbc, 0x54, 0x2e, 0x0f, 0xc3, 0x8a, 0xc3, 0x8e, 0x08, 0x88, 0x0d, 0xd0,
+     0x4a, 0x02, 0xef, 0x67, 0xc9, 0x3a, 0xe1, 0x35},
+    // c530fadc9bfa265e63b755cc6ee04c2d70d60bb916ce2f331dc7359362571b25.pem
+    {0x02, 0xa9, 0x5f, 0x43, 0x43, 0x10, 0x19, 0xe9, 0xdc, 0x22, 0x5f, 0x05,
+     0xf4, 0x19, 0x33, 0x01, 0x90, 0xde, 0xb4, 0xa3, 0xf1, 0x86, 0x9c, 0xaa,
+     0xc9, 0x84, 0x2b, 0x40, 0x3d, 0xcb, 0xee, 0x77},
+    // 89107c8e50e029b7b5f4ff0ccd2956bcc9d0c8ba2bfb6a58374ed63a6b034a30.pem
+    {0x89, 0x28, 0xc5, 0x93, 0x98, 0xb0, 0xf1, 0x71, 0xc0, 0xf9, 0x6f,
+     0xda, 0xe6, 0xab, 0x8d, 0xd0, 0xf4, 0x8e, 0xe0, 0x6d, 0x17, 0x4d,
+     0xa1, 0x0c, 0x40, 0x4a, 0xc0, 0x01, 0x43, 0xc7, 0xa7, 0x49},
+    // 3472e4f16c570e0dd388aaaa4a64a34a4b939f1ca770996b5be0037c1aded9c1.pem
+    {0x34, 0x72, 0xe4, 0xf1, 0x6c, 0x57, 0x0e, 0x0d, 0xd3, 0x88, 0xaa,
+     0xaa, 0x4a, 0x64, 0xa3, 0x4a, 0x4b, 0x93, 0x9f, 0x1c, 0xa7, 0x70,
+     0x99, 0x6b, 0x5b, 0xe0, 0x03, 0x7c, 0x1a, 0xde, 0xd9, 0xc1}
+};
diff --git a/constants/src/gen/java/generate_blocklist.awk b/constants/src/gen/java/generate_blocklist.awk
new file mode 100644
index 00000000..f5c58b85
--- /dev/null
+++ b/constants/src/gen/java/generate_blocklist.awk
@@ -0,0 +1,106 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+BEGIN {
+  inSPKIBlockList = 0
+  inKnownInterceptionList = 0
+  currentHash = 0
+  if (! package) {
+    package = "org.conscrypt"
+  }
+}
+
+# Keep track of which block definition we are in now.
+/kSPKIBlockList\[\]\[crypto::kSHA256Length\] = {/ {
+  inSPKIBlockList = 1
+}
+/kKnownInterceptionList\[\]\[crypto::kSHA256Length\] = {/ {
+  inKnownInterceptionList = 1
+}
+/};/ {
+  if (inSPKIBlockList)
+    inSPKIBlockList = 0
+  if (inKnownInterceptionList)
+    inKnownInterceptionList= 0
+}
+
+# Extract the bytes from the public key hashes.
+/\{0x/ { currentHash = "" }
+/0x/ {
+  newLine = $0
+  gsub(/[ {}]/, "", newLine)
+  gsub(/0x/, "", newLine)
+  currentHash = currentHash newLine
+}
+/\},/ {
+  if (inSPKIBlockList)
+    hashes[currentHash] = 1
+  if (inKnownInterceptionList)
+    hashes[currentHash] = 0
+  currentHash = 0
+}
+
+END {
+  # Make sure we are out of the declaration blocks.
+  if (inSPKIBlockList || inKnownInterceptionList)
+    exit 1
+
+  # Only keep the hashes that are only in kSPKIBlockList.
+  for (h in hashes) {
+    if (hashes[h]) {
+      blockedHashes[i++] = h
+    }
+  }
+
+  # Generate the Java class.
+  print "/*"
+  print " * Copyright (C) 2024 The Android Open Source Project"
+  print " *"
+  print " * Licensed under the Apache License, Version 2.0 (the \"License\");"
+  print " * you may not use this file except in compliance with the License."
+  print " * You may obtain a copy of the License at"
+  print " *"
+  print " *     http://www.apache.org/licenses/LICENSE-2.0"
+  print " *"
+  print " * Unless required by applicable law or agreed to in writing, software"
+  print " * distributed under the License is distributed on an \"AS IS\" BASIS,"
+  print " * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."
+  print " * See the License for the specific language governing permissions and"
+  print " * limitations under the License."
+  print " */"
+  print ""
+  print "/* This file was generated by generate_blocklist.awk. Do not modify. */"
+  print ""
+  print "package", package ";"
+  print ""
+  print "final class StaticBlocklist {"
+  print "    static final byte[][] PUBLIC_KEYS = {"
+  ORS = ""
+  for (h in blockedHashes) {
+    print "       {\n       "
+    n = split(blockedHashes[h], splitHash, ",")
+    for (i=1; i<=n; i++) {
+      if (splitHash[i] != "") {
+        print "(byte) 0x" splitHash[i] ", "
+        if (i % 8 == 0) {
+          print "\n       "
+        }
+      }
+    }
+    print "},\n"
+  }
+  ORS = "\n"
+  print "    };"
+  print "}"
+}
diff --git a/networksecurity.aconfig b/networksecurity.aconfig
new file mode 100644
index 00000000..de50705c
--- /dev/null
+++ b/networksecurity.aconfig
@@ -0,0 +1,43 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+package: "com.android.org.conscrypt.net.flags"
+container: "com.android.conscrypt"
+
+flag {
+    name: "certificate_transparency_default_enabled"
+    namespace: "network_security"
+    description: "This flag controls the default state of Certificate Transparency for targetSdk version C and up"
+    bug: "407952621"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "certificate_transparency_dry_run"
+    namespace: "network_security"
+    description: "This flag controls whether Conscrypt will trigger a dry-run of the verification, even for apps that have not enabled CT"
+    bug: "401453445"
+    # APIs provided by a mainline module can only use a frozen flag.
+    is_fixed_read_only: true
+}
+
+flag {
+    name: "network_security_config"
+    namespace: "network_security"
+    description: "This flag controls whether the NetworkSecurityConfig is provided by Conscrypt"
+    bug: "404518910"
+    is_fixed_read_only: true
+    is_exported: true
+}
diff --git a/openjdk/src/main/java/dalvik/annotation/optimization/CriticalNative.java b/openjdk/src/main/java/dalvik/annotation/optimization/CriticalNative.java
new file mode 100644
index 00000000..591c6a53
--- /dev/null
+++ b/openjdk/src/main/java/dalvik/annotation/optimization/CriticalNative.java
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package dalvik.annotation.optimization;
+
+import org.conscrypt.Internal;
+
+import java.lang.annotation.Documented;
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Stub annotation for CriticalNative methods that only work on Android.
+ */
+@Internal
+@Retention(RetentionPolicy.SOURCE)
+@Target({ElementType.METHOD})
+@Documented
+public @interface CriticalNative {}
\ No newline at end of file
diff --git a/openjdk/src/main/java/dalvik/annotation/optimization/FastNative.java b/openjdk/src/main/java/dalvik/annotation/optimization/FastNative.java
new file mode 100644
index 00000000..2c6d6927
--- /dev/null
+++ b/openjdk/src/main/java/dalvik/annotation/optimization/FastNative.java
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package dalvik.annotation.optimization;
+
+import org.conscrypt.Internal;
+
+import java.lang.annotation.Documented;
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Stub annotation for FastNative methods that only work on Android.
+ */
+@Internal
+@Retention(RetentionPolicy.SOURCE)
+@Target({ElementType.METHOD})
+@Documented
+public @interface FastNative {}
\ No newline at end of file
diff --git a/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java b/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java
index 305b74b8..5f0a30cc 100644
--- a/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java
+++ b/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java
@@ -18,6 +18,8 @@ package org.conscrypt;
 
 import static java.nio.charset.StandardCharsets.UTF_8;
 
+import org.conscrypt.flags.Flags;
+
 import java.io.ByteArrayOutputStream;
 import java.io.Closeable;
 import java.io.FileNotFoundException;
@@ -41,6 +43,8 @@ import java.util.logging.Logger;
 @Internal
 public final class CertBlocklistImpl implements CertBlocklist {
     private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());
+    private static final String DIGEST_SHA1 = "SHA-1";
+    private static final String DIGEST_SHA256 = "SHA-256";
 
     private final Set<BigInteger> serialBlocklist;
     private final Set<ByteArray> sha1PubkeyBlocklist;
@@ -82,9 +86,9 @@ public final class CertBlocklistImpl implements CertBlocklist {
         String defaultPubkeySha256BlocklistPath = blocklistRoot + "pubkey_sha256_blocklist.txt";
 
         Set<ByteArray> sha1PubkeyBlocklist =
-                readPublicKeyBlockList(defaultPubkeyBlocklistPath, "SHA-1");
+                readPublicKeyBlockList(defaultPubkeyBlocklistPath, DIGEST_SHA1);
         Set<ByteArray> sha256PubkeyBlocklist =
-                readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, "SHA-256");
+                readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, DIGEST_SHA256);
         Set<BigInteger> serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
         return new CertBlocklistImpl(serialBlocklist, sha1PubkeyBlocklist, sha256PubkeyBlocklist);
     }
@@ -177,58 +181,119 @@ public final class CertBlocklistImpl implements CertBlocklist {
         return Collections.unmodifiableSet(bl);
     }
 
-    static final byte[][] SHA1_BUILTINS = {
+    // clang-format off
+    static final byte[] SHA1_BUILTIN = {
             // Blocklist test cert for CTS. The cert and key can be found in
             // src/test/resources/blocklist_test_ca.pem and
             // src/test/resources/blocklist_test_ca_key.pem.
-            "bae78e6bed65a2bf60ddedde7fd91e825865e93d".getBytes(UTF_8),
-            // From
-            // http://src.chromium.org/viewvc/chrome/branches/782/src/net/base/x509_certificate.cc?r1=98750&r2=98749&pathrev=98750
-            // C=NL, O=DigiNotar, CN=DigiNotar Root CA/emailAddress=info@diginotar.nl
-            "410f36363258f30b347d12ce4863e433437806a8".getBytes(UTF_8),
-            // Subject: CN=DigiNotar Cyber CA
-            // Issuer: CN=GTE CyberTrust Global Root
-            "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37".getBytes(UTF_8),
-            // Subject: CN=DigiNotar Services 1024 CA
-            // Issuer: CN=Entrust.net
-            "e23b8d105f87710a68d9248050ebefc627be4ca6".getBytes(UTF_8),
-            // Subject: CN=DigiNotar PKIoverheid CA Organisatie - G2
-            // Issuer: CN=Staat der Nederlanden Organisatie CA - G2
-            "7b2e16bc39bcd72b456e9f055d1de615b74945db".getBytes(UTF_8),
-            // Subject: CN=DigiNotar PKIoverheid CA Overheid en Bedrijven
-            // Issuer: CN=Staat der Nederlanden Overheid CA
-            "e8f91200c65cee16e039b9f883841661635f81c5".getBytes(UTF_8),
-            // From http://src.chromium.org/viewvc/chrome?view=rev&revision=108479
-            // Subject: O=Digicert Sdn. Bhd.
-            // Issuer: CN=GTE CyberTrust Global Root
-            "0129bcd5b448ae8d2496d1c3e19723919088e152".getBytes(UTF_8),
-            // Subject: CN=e-islem.kktcmerkezbankasi.org/emailAddress=ileti@kktcmerkezbankasi.org
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "5f3ab33d55007054bc5e3e5553cd8d8465d77c61".getBytes(UTF_8),
-            // Subject: CN=*.EGO.GOV.TR 93
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "783333c9687df63377efceddd82efa9101913e8e".getBytes(UTF_8),
-            // Subject: Subject: C=FR, O=DG Tr\xC3\xA9sor, CN=AC DG Tr\xC3\xA9sor SSL
-            // Issuer: C=FR, O=DGTPE, CN=AC DGTPE Signature Authentification
-            "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf".getBytes(UTF_8),
+            // bae78e6bed65a2bf60ddedde7fd91e825865e93d
+          (byte) 0xba, (byte) 0xe7, (byte) 0x8e, (byte) 0x6b, (byte) 0xed,
+          (byte) 0x65, (byte) 0xa2, (byte) 0xbf, (byte) 0x60, (byte) 0xdd,
+          (byte) 0xed, (byte) 0xde, (byte) 0x7f, (byte) 0xd9, (byte) 0x1e,
+          (byte) 0x82, (byte) 0x58, (byte) 0x65, (byte) 0xe9, (byte) 0x3d,
+    };
+
+    static final byte[][] SHA1_DEPRECATED_BUILTINS = {
+        // "410f36363258f30b347d12ce4863e433437806a8"
+        {
+            (byte) 0x41, (byte) 0x0f, (byte) 0x36, (byte) 0x36, (byte) 0x32,
+            (byte) 0x58, (byte) 0xf3, (byte) 0x0b, (byte) 0x34, (byte) 0x7d,
+            (byte) 0x12, (byte) 0xce, (byte) 0x48, (byte) 0x63, (byte) 0xe4,
+            (byte) 0x33, (byte) 0x43, (byte) 0x78, (byte) 0x06, (byte) 0xa8,
+        },
+        // "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37"
+        {
+            (byte) 0xba, (byte) 0x3e, (byte) 0x7b, (byte) 0xd3, (byte) 0x8c,
+            (byte) 0xd7, (byte) 0xe1, (byte) 0xe6, (byte) 0xb9, (byte) 0xcd,
+            (byte) 0x4c, (byte) 0x21, (byte) 0x99, (byte) 0x62, (byte) 0xe5,
+            (byte) 0x9d, (byte) 0x7a, (byte) 0x2f, (byte) 0x4e, (byte) 0x37,
+        },
+        // "e23b8d105f87710a68d9248050ebefc627be4ca6"
+        {
+            (byte) 0xe2, (byte) 0x3b, (byte) 0x8d, (byte) 0x10, (byte) 0x5f,
+            (byte) 0x87, (byte) 0x71, (byte) 0x0a, (byte) 0x68, (byte) 0xd9,
+            (byte) 0x24, (byte) 0x80, (byte) 0x50, (byte) 0xeb, (byte) 0xef,
+            (byte) 0xc6, (byte) 0x27, (byte) 0xbe, (byte) 0x4c, (byte) 0xa6,
+        },
+        // "7b2e16bc39bcd72b456e9f055d1de615b74945db"
+        {
+            (byte) 0x7b, (byte) 0x2e, (byte) 0x16, (byte) 0xbc, (byte) 0x39,
+            (byte) 0xbc, (byte) 0xd7, (byte) 0x2b, (byte) 0x45, (byte) 0x6e,
+            (byte) 0x9f, (byte) 0x05, (byte) 0x5d, (byte) 0x1d, (byte) 0xe6,
+            (byte) 0x15, (byte) 0xb7, (byte) 0x49, (byte) 0x45, (byte) 0xdb,
+        },
+        // "e8f91200c65cee16e039b9f883841661635f81c5"
+        {
+            (byte) 0xe8, (byte) 0xf9, (byte) 0x12, (byte) 0x00, (byte) 0xc6,
+            (byte) 0x5c, (byte) 0xee, (byte) 0x16, (byte) 0xe0, (byte) 0x39,
+            (byte) 0xb9, (byte) 0xf8, (byte) 0x83, (byte) 0x84, (byte) 0x16,
+            (byte) 0x61, (byte) 0x63, (byte) 0x5f, (byte) 0x81, (byte) 0xc5,
+        },
+        // "0129bcd5b448ae8d2496d1c3e19723919088e152"
+        {
+            (byte) 0x01, (byte) 0x29, (byte) 0xbc, (byte) 0xd5, (byte) 0xb4,
+            (byte) 0x48, (byte) 0xae, (byte) 0x8d, (byte) 0x24, (byte) 0x96,
+            (byte) 0xd1, (byte) 0xc3, (byte) 0xe1, (byte) 0x97, (byte) 0x23,
+            (byte) 0x91, (byte) 0x90, (byte) 0x88, (byte) 0xe1, (byte) 0x52,
+        },
+        // "5f3ab33d55007054bc5e3e5553cd8d8465d77c61"
+        {
+            (byte) 0x5f, (byte) 0x3a, (byte) 0xb3, (byte) 0x3d, (byte) 0x55,
+            (byte) 0x00, (byte) 0x70, (byte) 0x54, (byte) 0xbc, (byte) 0x5e,
+            (byte) 0x3e, (byte) 0x55, (byte) 0x53, (byte) 0xcd, (byte) 0x8d,
+            (byte) 0x84, (byte) 0x65, (byte) 0xd7, (byte) 0x7c, (byte) 0x61,
+        },
+        // "783333c9687df63377efceddd82efa9101913e8e"
+        {
+            (byte) 0x78, (byte) 0x33, (byte) 0x33, (byte) 0xc9, (byte) 0x68,
+            (byte) 0x7d, (byte) 0xf6, (byte) 0x33, (byte) 0x77, (byte) 0xef,
+            (byte) 0xce, (byte) 0xdd, (byte) 0xd8, (byte) 0x2e, (byte) 0xfa,
+            (byte) 0x91, (byte) 0x01, (byte) 0x91, (byte) 0x3e, (byte) 0x8e,
+        },
+        // "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf"
+        {
+            (byte) 0x3e, (byte) 0xcf, (byte) 0x4b, (byte) 0xbb, (byte) 0xe4,
+            (byte) 0x60, (byte) 0x96, (byte) 0xd5, (byte) 0x14, (byte) 0xbb,
+            (byte) 0x53, (byte) 0x9b, (byte) 0xb9, (byte) 0x13, (byte) 0xd7,
+            (byte) 0x7a, (byte) 0xa4, (byte) 0xef, (byte) 0x31, (byte) 0xbf,
+        },
     };
 
-    static final byte[][] SHA256_BUILTINS = {
+    static final byte[] SHA256_BUILTIN = {
             // Blocklist test cert for CTS. The cert and key can be found in
             // src/test/resources/blocklist_test_ca2.pem and
             // src/test/resources/blocklist_test_ca2_key.pem.
-            "809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd".getBytes(UTF_8),
+            // 809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd
+          (byte) 0x80, (byte) 0x99, (byte) 0x64, (byte) 0xb1, (byte) 0x5e,
+          (byte) 0x9b, (byte) 0xd3, (byte) 0x12, (byte) 0x99, (byte) 0x3d,
+          (byte) 0x99, (byte) 0x84, (byte) 0x04, (byte) 0x55, (byte) 0x51,
+          (byte) 0xf5, (byte) 0x03, (byte) 0xf2, (byte) 0xcf, (byte) 0x8e,
+          (byte) 0x68, (byte) 0xf3, (byte) 0x91, (byte) 0x88, (byte) 0x92,
+          (byte) 0x1b, (byte) 0xa3, (byte) 0x0f, (byte) 0xe6, (byte) 0x23,
+          (byte) 0xf9, (byte) 0xfd,
     };
+    // clang-format on
 
     private static Set<ByteArray> readPublicKeyBlockList(String path, String hashType) {
-        Set<ByteArray> bl;
+        Set<ByteArray> bl = new HashSet<ByteArray>();
 
         switch (hashType) {
-            case "SHA-1":
-                bl = new HashSet<ByteArray>(toByteArrays(SHA1_BUILTINS));
+            case DIGEST_SHA1:
+                bl.add(new ByteArray(SHA1_BUILTIN));
+                if (!Flags.useChromiumCertBlocklist()) {
+                    for (byte[] staticPubKey : SHA1_DEPRECATED_BUILTINS) {
+                        bl.add(new ByteArray(staticPubKey));
+                    }
+                }
                 break;
-            case "SHA-256":
-                bl = new HashSet<ByteArray>(toByteArrays(SHA256_BUILTINS));
+            case DIGEST_SHA256:
+                bl.add(new ByteArray(SHA256_BUILTIN));
+                if (Flags.useChromiumCertBlocklist()) {
+                    // Blocklist statically included in Conscrypt. See constants/.
+                    for (byte[] staticPubKey : StaticBlocklist.PUBLIC_KEYS) {
+                        bl.add(new ByteArray(staticPubKey));
+                    }
+                }
                 break;
             default:
                 throw new RuntimeException(
@@ -242,17 +307,18 @@ public final class CertBlocklistImpl implements CertBlocklist {
             logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
             return bl;
         }
+
         // The hashes are encoded with hexadecimal values. There should be
         // twice as many characters as the digest length in bytes.
         int hashLength = md.getDigestLength() * 2;
 
-        // attempt to augment it with values taken from gservices
+        // Attempt to augment it with values taken from /data/misc/keychain.
         String pubkeyBlocklist = readBlocklist(path);
         if (!pubkeyBlocklist.equals("")) {
             for (String value : pubkeyBlocklist.split(",", -1)) {
                 value = value.trim();
                 if (isPubkeyHash(value, hashLength)) {
-                    bl.add(new ByteArray(value.getBytes(UTF_8)));
+                    bl.add(new ByteArray(Hex.decodeHex(value)));
                 } else {
                     logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                 }
@@ -271,7 +337,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
             logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
             return false;
         }
-        ByteArray out = new ByteArray(toHex(md.digest(encodedPublicKey)));
+        ByteArray out = new ByteArray(md.digest(encodedPublicKey));
         if (blocklist.contains(out)) {
             return true;
         }
@@ -290,13 +356,13 @@ public final class CertBlocklistImpl implements CertBlocklist {
             return cachedResult.booleanValue();
         }
         if (!sha1PubkeyBlocklist.isEmpty()) {
-            if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, "SHA-1")) {
+            if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, DIGEST_SHA1)) {
                 cache.put(cacheKey, true);
                 return true;
             }
         }
         if (!sha256PubkeyBlocklist.isEmpty()) {
-            if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, "SHA-256")) {
+            if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, DIGEST_SHA256)) {
                 cache.put(cacheKey, true);
                 return true;
             }
@@ -305,31 +371,8 @@ public final class CertBlocklistImpl implements CertBlocklist {
         return false;
     }
 
-    private static final byte[] HEX_TABLE = { (byte) '0', (byte) '1', (byte) '2', (byte) '3',
-        (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'a',
-        (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'};
-
-    private static byte[] toHex(byte[] in) {
-        byte[] out = new byte[in.length * 2];
-        int outIndex = 0;
-        for (int i = 0; i < in.length; i++) {
-            int value = in[i] & 0xff;
-            out[outIndex++] = HEX_TABLE[value >> 4];
-            out[outIndex++] = HEX_TABLE[value & 0xf];
-        }
-        return out;
-    }
-
     @Override
     public boolean isSerialNumberBlockListed(BigInteger serial) {
         return serialBlocklist.contains(serial);
     }
-
-    private static List<ByteArray> toByteArrays(byte[]... allBytes) {
-        List<ByteArray> byteArrays = new ArrayList<>(allBytes.length + 1);
-        for (byte[] bytes : allBytes) {
-            byteArrays.add(new ByteArray(bytes));
-        }
-        return byteArrays;
-    }
 }
diff --git a/platform/src/main/java/org/conscrypt/Hex.java b/platform/src/main/java/org/conscrypt/Hex.java
index af789224..540c6629 100644
--- a/platform/src/main/java/org/conscrypt/Hex.java
+++ b/platform/src/main/java/org/conscrypt/Hex.java
@@ -20,23 +20,12 @@ package org.conscrypt;
  * Helper class for dealing with hexadecimal strings.
  */
 @Internal
-// public for testing by TrustedCertificateStoreTest
 public final class Hex {
     private Hex() {}
 
     private final static char[] DIGITS = {
             '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
 
-    public static String bytesToHexString(byte[] bytes) {
-        char[] buf = new char[bytes.length * 2];
-        int c = 0;
-        for (byte b : bytes) {
-            buf[c++] = DIGITS[(b >> 4) & 0xf];
-            buf[c++] = DIGITS[b & 0xf];
-        }
-        return new String(buf);
-    }
-
     public static String intToHexString(int i, int minWidth) {
         int bufLen = 8;  // Max number of hex digits in an int
         char[] buf = new char[bufLen];
@@ -48,4 +37,33 @@ public final class Hex {
 
         return new String(buf, cursor, bufLen - cursor);
     }
+
+    public static byte[] decodeHex(String encoded) throws IllegalArgumentException {
+        if ((encoded.length() % 2) != 0) {
+            throw new IllegalArgumentException("Invalid input length: " + encoded.length());
+        }
+
+        int resultLengthBytes = encoded.length() / 2;
+        byte[] result = new byte[resultLengthBytes];
+
+        int resultOffset = 0;
+        int i = 0;
+        for (int len = encoded.length(); i < len; i += 2) {
+            result[resultOffset++] =
+                    (byte) ((toDigit(encoded.charAt(i)) << 4) | toDigit(encoded.charAt(i + 1)));
+        }
+
+        return result;
+    }
+
+    private static int toDigit(char pseudoCodePoint) throws IllegalArgumentException {
+        if ('0' <= pseudoCodePoint && pseudoCodePoint <= '9') {
+            return pseudoCodePoint - '0';
+        } else if ('a' <= pseudoCodePoint && pseudoCodePoint <= 'f') {
+            return 10 + (pseudoCodePoint - 'a');
+        } else if ('A' <= pseudoCodePoint && pseudoCodePoint <= 'F') {
+            return 10 + (pseudoCodePoint - 'A');
+        }
+        throw new IllegalArgumentException("Illegal char: " + pseudoCodePoint);
+    }
 }
diff --git a/platform/src/main/java/org/conscrypt/Platform.java b/platform/src/main/java/org/conscrypt/Platform.java
index a7ec76d7..30e6ec51 100644
--- a/platform/src/main/java/org/conscrypt/Platform.java
+++ b/platform/src/main/java/org/conscrypt/Platform.java
@@ -486,8 +486,13 @@ final public class Platform {
 
     public static boolean isCTVerificationRequired(String hostname) {
         if (Flags.certificateTransparencyPlatform()) {
-            return NetworkSecurityPolicy.getInstance()
-                    .isCertificateTransparencyVerificationRequired(hostname);
+            if (NetworkSecurityPolicy.getInstance().isCertificateTransparencyVerificationRequired(
+                        hostname)) {
+                return true;
+            }
+            if (org.conscrypt.net.flags.Flags.certificateTransparencyDryRun()) {
+                return true;
+            }
         }
         return false;
     }
@@ -499,6 +504,8 @@ final public class Platform {
         } else if (NetworkSecurityPolicy.getInstance()
                            .isCertificateTransparencyVerificationRequired(hostname)) {
             return CertificateTransparencyVerificationReason.DOMAIN_OPT_IN;
+        } else if (org.conscrypt.net.flags.Flags.certificateTransparencyDryRun()) {
+            return CertificateTransparencyVerificationReason.DRY_RUN;
         }
         return CertificateTransparencyVerificationReason.UNKNOWN;
     }
diff --git a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
index e34f119b..1ac57d31 100644
--- a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
+++ b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
@@ -53,8 +53,7 @@ public class LogStoreImpl implements LogStore {
     private static final int COMPAT_VERSION = 2;
     private static final Path logListPrefix;
     private static final Path logListSuffix;
-    private static final long LOG_LIST_CHECK_INTERVAL_IN_NS =
-            10L * 60 * 1_000 * 1_000_000; // 10 minutes
+    private static final long LOG_LIST_CHECK_INTERVAL_IN_MS = 10L * 60 * 1_000; // 10 minutes
 
     static {
         String androidData = System.getenv("ANDROID_DATA");
@@ -79,7 +78,7 @@ public class LogStoreImpl implements LogStore {
     static class SystemTimeSupplier implements Supplier<Long> {
         @Override
         public Long get() {
-            return System.nanoTime();
+            return System.currentTimeMillis();
         }
     }
 
@@ -183,7 +182,8 @@ public class LogStoreImpl implements LogStore {
 
     private synchronized void resetLogListIfRequired() {
         long now = clock.get();
-        if (this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_NS > now) {
+        if (now >= this.logListLastChecked
+                && now < this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_MS) {
             return;
         }
         this.logListLastChecked = now;
@@ -254,7 +254,7 @@ public class LogStoreImpl implements LogStore {
         return State.LOADED;
     }
 
-    private static void addLogsToMap(JSONArray logs, String operatorName, int logType,
+    private void addLogsToMap(JSONArray logs, String operatorName, int logType,
             Map<ByteArray, LogInfo> logsMap) throws JSONException {
         for (int j = 0; j < logs.length(); j++) {
             JSONObject log = logs.getJSONObject(j);
@@ -271,12 +271,21 @@ public class LogStoreImpl implements LogStore {
             }
             LogInfo logInfo = builder.build();
 
+            String logIdFromList = log.getString("log_id");
             // The logId computed using the public key should match the log_id field.
-            byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
+            byte[] logId = Base64.getDecoder().decode(logIdFromList);
             if (!Arrays.equals(logInfo.getID(), logId)) {
                 throw new IllegalArgumentException("logId does not match publicKey");
             }
 
+            //  Verify that the log is in a known state now. This might fail if
+            //  there is an issue with the device's clock which can cause false
+            //  positives when validating SCTs.
+            if (logInfo.getStateAt(clock.get()) == LogInfo.STATE_UNKNOWN) {
+                throw new IllegalArgumentException("Log current state is "
+                        + "unknown, logId: " + logIdFromList);
+            }
+
             logsMap.put(new ByteArray(logId), logInfo);
         }
     }
diff --git a/platform/src/test/java/org/conscrypt/SpakeTest.java b/platform/src/test/java/org/conscrypt/SpakeTest.java
index ce5c7163..a8cda5b2 100644
--- a/platform/src/test/java/org/conscrypt/SpakeTest.java
+++ b/platform/src/test/java/org/conscrypt/SpakeTest.java
@@ -37,12 +37,14 @@ import org.junit.runners.JUnit4;
 import java.net.InetAddress;
 import java.net.InetSocketAddress;
 import java.net.Socket;
+import java.security.InvalidParameterException;
 import java.security.KeyManagementException;
 import java.util.Arrays;
 import java.util.concurrent.Callable;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
+
 import javax.net.SocketFactory;
 import javax.net.ssl.KeyManager;
 import javax.net.ssl.KeyManagerFactory;
@@ -543,6 +545,37 @@ public class SpakeTest {
                 KeyManagementException.class, () -> sslContext.init(null, trustManagers, null));
     }
 
+    @Test
+    public void testSpake2WithoutTls13Invalid() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", password)
+                                    .build();
+
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        sockets.getFirst().setEnabledProtocols(new String[] {"TLSv1.2"});
+        sockets.getSecond().setEnabledProtocols(new String[] {"TLSv1.2"});
+
+        connectSockets(sockets);
+        sendData(sockets);
+        closeSockets(sockets);
+    }
+
     private <T> Future<T> runAsync(Callable<T> callable) {
         return executor.submit(callable);
     }
diff --git a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
index 62cc8e0a..8c8c5958 100644
--- a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
+++ b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
@@ -77,22 +77,24 @@ public class LogStoreImplTest {
 
     /* Time supplier that can be set to any arbitrary time */
     static class TimeSupplier implements Supplier<Long> {
-        private long currentTimeInNs;
+        private long currentTimeInMs;
 
-        TimeSupplier(long currentTimeInNs) {
-            this.currentTimeInNs = currentTimeInNs;
+        TimeSupplier(long currentTimeInMs) {
+            this.currentTimeInMs = currentTimeInMs;
         }
 
         @Override
         public Long get() {
-            return currentTimeInNs;
+            return currentTimeInMs;
         }
 
-        public void setCurrentTimeInNs(long currentTimeInNs) {
-            this.currentTimeInNs = currentTimeInNs;
+        public void setCurrentTimeInMs(long currentTimeInMs) {
+            this.currentTimeInMs = currentTimeInMs;
         }
     }
 
+    private static final long JAN2024 = 1704103200000L;
+    private static final long JAN2022 = 1641031200000L;
     // clang-format off
     static final String validLogList = "" +
 "{" +
@@ -168,7 +170,7 @@ public class LogStoreImplTest {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": 1727734767000" +
+"              \"timestamp\": 1667328840000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
@@ -199,7 +201,8 @@ public class LogStoreImplTest {
     public void loadValidLogList_returnsCompliantState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         logList = writeLogList(validLogList);
-        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                 + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
                 + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
@@ -228,7 +231,22 @@ public class LogStoreImplTest {
         FakeStatsLog metrics = new FakeStatsLog();
         String content = "}}";
         logList = writeLogList(content);
-        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+
+        assertEquals(
+                "The log state should be malformed", LogStore.State.MALFORMED, store.getState());
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
+        assertEquals("The metric update for log list state should be malformed",
+                LogStore.State.MALFORMED, metrics.states.get(0));
+    }
+
+    @Test
+    public void loadFutureLogList_returnsMalformedState() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList); // The logs are usable from 2024 onwards.
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2022);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
 
         assertEquals(
                 "The log state should be malformed", LogStore.State.MALFORMED, store.getState());
@@ -241,7 +259,9 @@ public class LogStoreImplTest {
     public void loadMissingLogList_returnsNotFoundState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         Path missingLogList = Paths.get("missing_dir", "missing_subdir", "does_not_exist_log_list");
-        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
+        LogStore store =
+                new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics, fakeTime);
 
         assertEquals(
                 "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
@@ -260,7 +280,7 @@ public class LogStoreImplTest {
         Files.deleteIfExists(logList);
         Files.deleteIfExists(parentDir);
         Files.deleteIfExists(grandparentDir);
-        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
         LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         assertEquals(
                 "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
@@ -271,13 +291,38 @@ public class LogStoreImplTest {
         Files.write(logList, validLogList.getBytes());
 
         // Assert
-        // 10ns < 10min, we should not check the log list yet.
-        fakeTime.setCurrentTimeInNs(10);
+        // 5min < 10min, we should not check the log list yet.
+        fakeTime.setCurrentTimeInMs(JAN2024 + 5L * 60 * 1000);
         assertEquals(
                 "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
 
         // 12min, the log list should be reloadable.
-        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
+        assertEquals(
+                "The log state should be compliant", LogStore.State.COMPLIANT, store.getState());
+    }
+
+    @Test
+    public void loadMissingThenTimeTravelBackwardsAndThenFoundLogList_logListIsLoaded()
+            throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        // Allocate a temporary file path and delete it. We keep the temporary
+        // path so that we can add a valid log list later on.
+        logList = writeLogList("");
+        Files.deleteIfExists(logList);
+        Files.deleteIfExists(parentDir);
+        Files.deleteIfExists(grandparentDir);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024 + 100L * 60 * 1000);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals(
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+
+        Files.createDirectory(grandparentDir);
+        Files.createDirectory(parentDir);
+        Files.write(logList, validLogList.getBytes());
+        // Move back in time.
+        fakeTime.setCurrentTimeInMs(JAN2024);
+
         assertEquals(
                 "The log state should be compliant", LogStore.State.COMPLIANT, store.getState());
     }
@@ -286,13 +331,13 @@ public class LogStoreImplTest {
     public void loadExistingAndThenRemovedLogList_logListIsNotFound() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         logList = writeLogList(validLogList);
-        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
         LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
 
         Files.delete(logList);
         // 12min, the log list should be reloadable.
-        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
 
         assertEquals(
                 "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
@@ -302,7 +347,7 @@ public class LogStoreImplTest {
     public void loadExistingLogListAndThenMoveDirectory_logListIsNotFound() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         logList = writeLogList(validLogList);
-        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
         LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
 
@@ -311,7 +356,7 @@ public class LogStoreImplTest {
         Files.move(oldParentDir, parentDir);
         logList = parentDir.resolve("log_list.json");
         // 12min, the log list should be reloadable.
-        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
 
         assertEquals(
                 "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
index c702820e..8722ebee 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
@@ -19,6 +19,9 @@ package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
 
+import dalvik.annotation.optimization.CriticalNative;
+import dalvik.annotation.optimization.FastNative;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.io.OutputStream;
@@ -49,12 +52,12 @@ import javax.security.auth.x500.X500Principal;
 
 /**
  * Provides the Java side of our JNI glue for OpenSSL.
- * <p>
- * Note: Many methods in this class take a reference to a Java object that holds a
- * native pointer in the form of a long in addition to the long itself and don't use
- * the Java object in the native implementation.  This is to prevent the Java object
- * from becoming eligible for GC while the native method is executing.  See
- * <a href="https://github.com/google/error-prone/blob/master/docs/bugpattern/UnsafeFinalization.md">this</a>
+ *
+ * <p>Note: Many methods in this class take a reference to a Java object that holds a native pointer
+ * in the form of a long in addition to the long itself and don't use the Java object in the native
+ * implementation. This is to prevent the Java object from becoming eligible for GC while the native
+ * method is executing. See <a
+ * href="https://github.com/google/error-prone/blob/master/docs/bugpattern/UnsafeFinalization.md">this</a>
  * for more details.
  * @hide This class is not part of the Android public SDK API
  */
@@ -62,6 +65,7 @@ import javax.security.auth.x500.X500Principal;
 public final class NativeCrypto {
     // --- OpenSSL library initialization --------------------------------------
     private static final UnsatisfiedLinkError loadError;
+
     static {
         UnsatisfiedLinkError error = null;
         try {
@@ -76,11 +80,11 @@ public final class NativeCrypto {
         setTlsV1DeprecationStatus(Platform.isTlsV1Deprecated(), Platform.isTlsV1Supported());
     }
 
-    private native static void clinit();
+    @FastNative private static native void clinit();
 
     /**
-     * Checks to see whether or not the native library was successfully loaded. If not, throws
-     * the {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
+     * Checks to see whether or not the native library was successfully loaded. If not, throws the
+     * {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
      */
     static void checkAvailability() {
         if (loadError != null) {
@@ -91,225 +95,275 @@ public final class NativeCrypto {
     // --- DSA/RSA public/private key handling functions -----------------------
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q,
             byte[] dmp1, byte[] dmq1, byte[] iqmp);
 
-    static native int EVP_PKEY_type(NativeRef.EVP_PKEY pkey);
+    @FastNative static native int EVP_PKEY_type(NativeRef.EVP_PKEY pkey);
 
-    static native String EVP_PKEY_print_public(NativeRef.EVP_PKEY pkeyRef);
+    @FastNative static native String EVP_PKEY_print_public(NativeRef.EVP_PKEY pkeyRef);
 
-    static native String EVP_PKEY_print_params(NativeRef.EVP_PKEY pkeyRef);
+    @FastNative static native String EVP_PKEY_print_params(NativeRef.EVP_PKEY pkeyRef);
 
-    @android.compat.annotation.UnsupportedAppUsage static native void EVP_PKEY_free(long pkey);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native void EVP_PKEY_free(long pkey);
 
-    static native int EVP_PKEY_cmp(NativeRef.EVP_PKEY pkey1, NativeRef.EVP_PKEY pkey2);
+    @FastNative static native int EVP_PKEY_cmp(NativeRef.EVP_PKEY pkey1, NativeRef.EVP_PKEY pkey2);
 
-    static native byte[] EVP_marshal_private_key(NativeRef.EVP_PKEY pkey);
+    @FastNative static native byte[] EVP_marshal_private_key(NativeRef.EVP_PKEY pkey);
 
-    static native long EVP_parse_private_key(byte[] data) throws ParsingException;
+    @FastNative static native long EVP_parse_private_key(byte[] data) throws ParsingException;
 
-    static native byte[] EVP_marshal_public_key(NativeRef.EVP_PKEY pkey);
+    @FastNative static native byte[] EVP_marshal_public_key(NativeRef.EVP_PKEY pkey);
 
+    @FastNative
     static native byte[] EVP_raw_X25519_private_key(byte[] data)
             throws ParsingException, InvalidKeyException;
 
-    static native long EVP_parse_public_key(byte[] data) throws ParsingException;
+    @FastNative static native long EVP_parse_public_key(byte[] data) throws ParsingException;
 
-    static native long PEM_read_bio_PUBKEY(long bioCtx);
+    @FastNative static native long PEM_read_bio_PUBKEY(long bioCtx);
 
-    static native long PEM_read_bio_PrivateKey(long bioCtx);
+    @FastNative static native long PEM_read_bio_PrivateKey(long bioCtx);
 
-    static native long getRSAPrivateKeyWrapper(PrivateKey key, byte[] modulus);
+    @FastNative static native long getRSAPrivateKeyWrapper(PrivateKey key, byte[] modulus);
 
+    @FastNative
     static native long getECPrivateKeyWrapper(PrivateKey key, NativeRef.EC_GROUP ecGroupRef);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long RSA_generate_key_ex(int modulusBits, byte[] publicExponent);
 
-    static native int RSA_size(NativeRef.EVP_PKEY pkey);
+    @FastNative static native int RSA_size(NativeRef.EVP_PKEY pkey);
 
+    @FastNative
     static native int RSA_private_encrypt(
             int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey, int padding);
 
+    @FastNative
     static native int RSA_public_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
             int padding) throws BadPaddingException, SignatureException;
 
+    @FastNative
     static native int RSA_public_encrypt(
             int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey, int padding);
 
+    @FastNative
     static native int RSA_private_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
             int padding) throws BadPaddingException, SignatureException;
 
     /*
      * Returns array of {n, e}
      */
-    static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);
+    @FastNative static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);
 
     /*
      * Returns array of {n, e, d, p, q, dmp1, dmq1, iqmp}
      */
-    static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);
+    @FastNative static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);
 
     // --- ChaCha20 -----------------------
 
     /*
      * Returns the encrypted or decrypted version of the data.
      */
+    @FastNative
     static native void chacha20_encrypt_decrypt(byte[] in, int inOffset, byte[] out, int outOffset,
             int length, byte[] key, byte[] nonce, int blockCounter);
 
     // --- EC functions --------------------------
 
+    @FastNative
     static native long EVP_PKEY_new_EC_KEY(
             NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pubkeyRef, byte[] privkey);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long EC_GROUP_new_by_curve_name(String curveName);
 
+    @FastNative
     static native long EC_GROUP_new_arbitrary(
             byte[] p, byte[] a, byte[] b, byte[] x, byte[] y, byte[] order, int cofactor);
 
-    static native String EC_GROUP_get_curve_name(NativeRef.EC_GROUP groupRef);
+    @FastNative static native String EC_GROUP_get_curve_name(NativeRef.EC_GROUP groupRef);
 
-    static native byte[][] EC_GROUP_get_curve(NativeRef.EC_GROUP groupRef);
+    @FastNative static native byte[][] EC_GROUP_get_curve(NativeRef.EC_GROUP groupRef);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native void EC_GROUP_clear_free(long groupRef);
 
-    static native long EC_GROUP_get_generator(NativeRef.EC_GROUP groupRef);
+    @FastNative static native long EC_GROUP_get_generator(NativeRef.EC_GROUP groupRef);
 
-    static native byte[] EC_GROUP_get_order(NativeRef.EC_GROUP groupRef);
+    @FastNative static native byte[] EC_GROUP_get_order(NativeRef.EC_GROUP groupRef);
 
-    static native int EC_GROUP_get_degree(NativeRef.EC_GROUP groupRef);
+    @FastNative static native int EC_GROUP_get_degree(NativeRef.EC_GROUP groupRef);
 
-    static native byte[] EC_GROUP_get_cofactor(NativeRef.EC_GROUP groupRef);
+    @FastNative static native byte[] EC_GROUP_get_cofactor(NativeRef.EC_GROUP groupRef);
 
-    static native long EC_POINT_new(NativeRef.EC_GROUP groupRef);
+    @FastNative static native long EC_POINT_new(NativeRef.EC_GROUP groupRef);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native void EC_POINT_clear_free(long pointRef);
 
+    @FastNative
     static native byte[][] EC_POINT_get_affine_coordinates(
             NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pointRef);
 
+    @FastNative
     static native void EC_POINT_set_affine_coordinates(
             NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pointRef, byte[] x, byte[] y);
 
-    static native long EC_KEY_generate_key(NativeRef.EC_GROUP groupRef);
+    @FastNative static native long EC_KEY_generate_key(NativeRef.EC_GROUP groupRef);
 
-    static native long EC_KEY_get1_group(NativeRef.EVP_PKEY pkeyRef);
+    @FastNative static native long EC_KEY_get1_group(NativeRef.EVP_PKEY pkeyRef);
 
-    static native byte[] EC_KEY_get_private_key(NativeRef.EVP_PKEY keyRef);
+    @FastNative static native byte[] EC_KEY_get_private_key(NativeRef.EVP_PKEY keyRef);
 
-    static native long EC_KEY_get_public_key(NativeRef.EVP_PKEY keyRef);
+    @FastNative static native long EC_KEY_get_public_key(NativeRef.EVP_PKEY keyRef);
 
+    @FastNative
     static native byte[] EC_KEY_marshal_curve_name(NativeRef.EC_GROUP groupRef) throws IOException;
 
-    static native long EC_KEY_parse_curve_name(byte[] encoded) throws IOException;
+    @FastNative static native long EC_KEY_parse_curve_name(byte[] encoded) throws IOException;
 
+    @FastNative
     static native int ECDH_compute_key(byte[] out, int outOffset, NativeRef.EVP_PKEY publicKeyRef,
             NativeRef.EVP_PKEY privateKeyRef) throws InvalidKeyException, IndexOutOfBoundsException;
 
-    static native int ECDSA_size(NativeRef.EVP_PKEY pkey);
+    @FastNative static native int ECDSA_size(NativeRef.EVP_PKEY pkey);
 
-    static native int ECDSA_sign(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
+    @FastNative static native int ECDSA_sign(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
 
-    static native int ECDSA_verify(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
+    @FastNative static native int ECDSA_verify(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);
 
     // --- Curve25519 --------------
 
+    @FastNative
     static native boolean X25519(byte[] out, byte[] privateKey, byte[] publicKey)
             throws InvalidKeyException;
 
-    static native void X25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
+    @FastNative static native void X25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
 
-    static native void ED25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
+    @FastNative static native void ED25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
 
     // --- Message digest functions --------------
 
     // These return const references
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long EVP_get_digestbyname(String name);
 
-    @android.compat.annotation.UnsupportedAppUsage static native int EVP_MD_size(long evp_md_const);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native int EVP_MD_size(long evp_md_const);
 
     // --- Message digest context functions --------------
 
-    @android.compat.annotation.UnsupportedAppUsage static native long EVP_MD_CTX_create();
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native long EVP_MD_CTX_create();
 
-    static native void EVP_MD_CTX_cleanup(NativeRef.EVP_MD_CTX ctx);
+    @FastNative static native void EVP_MD_CTX_cleanup(NativeRef.EVP_MD_CTX ctx);
 
-    @android.compat.annotation.UnsupportedAppUsage static native void EVP_MD_CTX_destroy(long ctx);
+    @android.compat.annotation.UnsupportedAppUsage
+    @CriticalNative
+    static native void EVP_MD_CTX_destroy(long ctx);
 
+    @FastNative
     static native int EVP_MD_CTX_copy_ex(
             NativeRef.EVP_MD_CTX dst_ctx, NativeRef.EVP_MD_CTX src_ctx);
 
     // --- Digest handling functions -------------------------------------------
 
-    static native int EVP_DigestInit_ex(NativeRef.EVP_MD_CTX ctx, long evp_md);
+    @FastNative static native int EVP_DigestInit_ex(NativeRef.EVP_MD_CTX ctx, long evp_md);
 
+    @FastNative
     static native void EVP_DigestUpdate(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native void EVP_DigestUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);
 
+    @FastNative
     static native int EVP_DigestFinal_ex(NativeRef.EVP_MD_CTX ctx, byte[] hash, int offset);
 
     // --- Signature handling functions ----------------------------------------
 
+    @FastNative
     static native long EVP_DigestSignInit(
             NativeRef.EVP_MD_CTX ctx, long evpMdRef, NativeRef.EVP_PKEY key);
 
+    @FastNative
     static native long EVP_DigestVerifyInit(
             NativeRef.EVP_MD_CTX ctx, long evpMdRef, NativeRef.EVP_PKEY key);
 
+    @FastNative
     static native void EVP_DigestSignUpdate(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native void EVP_DigestSignUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);
 
+    @FastNative
     static native void EVP_DigestVerifyUpdate(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native void EVP_DigestVerifyUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);
 
-    static native byte[] EVP_DigestSignFinal(NativeRef.EVP_MD_CTX ctx);
+    @FastNative static native byte[] EVP_DigestSignFinal(NativeRef.EVP_MD_CTX ctx);
 
+    @FastNative
     static native boolean EVP_DigestVerifyFinal(NativeRef.EVP_MD_CTX ctx, byte[] signature,
             int offset, int length) throws IndexOutOfBoundsException;
 
+    @FastNative
     static native byte[] EVP_DigestSign(
             NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
 
+    @FastNative
     static native boolean EVP_DigestVerify(NativeRef.EVP_MD_CTX ctx, byte[] sigBuffer,
             int sigOffset, int sigLen, byte[] dataBuffer, int dataOffset, int dataLen);
 
+    @FastNative
     static native long EVP_PKEY_encrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;
 
+    @FastNative
     static native int EVP_PKEY_encrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
             byte[] input, int inOffset, int inLength)
             throws IndexOutOfBoundsException, BadPaddingException;
 
+    @FastNative
     static native long EVP_PKEY_decrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;
 
+    @FastNative
     static native int EVP_PKEY_decrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
             byte[] input, int inOffset, int inLength)
             throws IndexOutOfBoundsException, BadPaddingException;
 
-    static native void EVP_PKEY_CTX_free(long pkeyCtx);
+    @FastNative static native void EVP_PKEY_CTX_free(long pkeyCtx);
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_padding(long ctx, int pad)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_pss_saltlen(long ctx, int len)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_mgf1_md(long ctx, long evpMdRef)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_oaep_md(long ctx, long evpMdRef)
             throws InvalidAlgorithmParameterException;
 
+    @FastNative
     static native void EVP_PKEY_CTX_set_rsa_oaep_label(long ctx, byte[] label)
             throws InvalidAlgorithmParameterException;
 
@@ -317,110 +371,131 @@ public final class NativeCrypto {
 
     // These return const references
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long EVP_get_cipherbyname(String string);
 
+    @FastNative
     static native void EVP_CipherInit_ex(NativeRef.EVP_CIPHER_CTX ctx, long evpCipher, byte[] key,
             byte[] iv, boolean encrypting);
 
+    @FastNative
     static native int EVP_CipherUpdate(NativeRef.EVP_CIPHER_CTX ctx, byte[] out, int outOffset,
             byte[] in, int inOffset, int inLength) throws IndexOutOfBoundsException;
 
+    @FastNative
     static native int EVP_CipherFinal_ex(NativeRef.EVP_CIPHER_CTX ctx, byte[] out, int outOffset)
             throws BadPaddingException, IllegalBlockSizeException;
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native int EVP_CIPHER_iv_length(long evpCipher);
 
-    @android.compat.annotation.UnsupportedAppUsage static native long EVP_CIPHER_CTX_new();
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native long EVP_CIPHER_CTX_new();
 
-    static native int EVP_CIPHER_CTX_block_size(NativeRef.EVP_CIPHER_CTX ctx);
+    @FastNative static native int EVP_CIPHER_CTX_block_size(NativeRef.EVP_CIPHER_CTX ctx);
 
-    static native int get_EVP_CIPHER_CTX_buf_len(NativeRef.EVP_CIPHER_CTX ctx);
+    @FastNative static native int get_EVP_CIPHER_CTX_buf_len(NativeRef.EVP_CIPHER_CTX ctx);
 
-    static native boolean get_EVP_CIPHER_CTX_final_used(NativeRef.EVP_CIPHER_CTX ctx);
+    @FastNative static native boolean get_EVP_CIPHER_CTX_final_used(NativeRef.EVP_CIPHER_CTX ctx);
 
+    @FastNative
     static native void EVP_CIPHER_CTX_set_padding(
             NativeRef.EVP_CIPHER_CTX ctx, boolean enablePadding);
 
+    @FastNative
     static native void EVP_CIPHER_CTX_set_key_length(NativeRef.EVP_CIPHER_CTX ctx, int keyBitSize);
 
-    static native void EVP_CIPHER_CTX_free(long ctx);
+    @FastNative static native void EVP_CIPHER_CTX_free(long ctx);
 
     // --- AEAD ----------------------------------------------------------------
-    static native long EVP_aead_aes_128_gcm();
+    @FastNative static native long EVP_aead_aes_128_gcm();
 
-    static native long EVP_aead_aes_256_gcm();
+    @FastNative static native long EVP_aead_aes_256_gcm();
 
-    static native long EVP_aead_chacha20_poly1305();
+    @FastNative static native long EVP_aead_chacha20_poly1305();
 
-    static native long EVP_aead_aes_128_gcm_siv();
+    @FastNative static native long EVP_aead_aes_128_gcm_siv();
 
-    static native long EVP_aead_aes_256_gcm_siv();
+    @FastNative static native long EVP_aead_aes_256_gcm_siv();
 
-    static native int EVP_AEAD_max_overhead(long evpAead);
+    @FastNative static native int EVP_AEAD_max_overhead(long evpAead);
 
-    static native int EVP_AEAD_nonce_length(long evpAead);
+    @FastNative static native int EVP_AEAD_nonce_length(long evpAead);
 
+    @FastNative
     static native int EVP_AEAD_CTX_seal(long evpAead, byte[] key, int tagLengthInBytes, byte[] out,
             int outOffset, byte[] nonce, byte[] in, int inOffset, int inLength, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
+    @FastNative
     static native int EVP_AEAD_CTX_seal_buf(long evpAead, byte[] key, int tagLengthInBytes,
             ByteBuffer out, byte[] nonce, ByteBuffer input, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
+    @FastNative
     static native int EVP_AEAD_CTX_open(long evpAead, byte[] key, int tagLengthInBytes, byte[] out,
             int outOffset, byte[] nonce, byte[] in, int inOffset, int inLength, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
+    @FastNative
     static native int EVP_AEAD_CTX_open_buf(long evpAead, byte[] key, int tagLengthInBytes,
             ByteBuffer out, byte[] nonce, ByteBuffer input, byte[] ad)
             throws ShortBufferException, BadPaddingException;
 
     // --- CMAC functions ------------------------------------------------------
 
-    static native long CMAC_CTX_new();
+    @FastNative static native long CMAC_CTX_new();
 
-    static native void CMAC_CTX_free(long ctx);
+    @FastNative static native void CMAC_CTX_free(long ctx);
 
-    static native void CMAC_Init(NativeRef.CMAC_CTX ctx, byte[] key);
+    @FastNative static native void CMAC_Init(NativeRef.CMAC_CTX ctx, byte[] key);
 
+    @FastNative
     static native void CMAC_Update(NativeRef.CMAC_CTX ctx, byte[] in, int inOffset, int inLength);
 
+    @FastNative
     static native void CMAC_UpdateDirect(NativeRef.CMAC_CTX ctx, long inPtr, int inLength);
 
-    static native byte[] CMAC_Final(NativeRef.CMAC_CTX ctx);
+    @FastNative static native byte[] CMAC_Final(NativeRef.CMAC_CTX ctx);
 
-    static native void CMAC_Reset(NativeRef.CMAC_CTX ctx);
+    @FastNative static native void CMAC_Reset(NativeRef.CMAC_CTX ctx);
 
     // --- HMAC functions ------------------------------------------------------
 
-    static native long HMAC_CTX_new();
+    @FastNative static native long HMAC_CTX_new();
 
-    static native void HMAC_CTX_free(long ctx);
+    @FastNative static native void HMAC_CTX_free(long ctx);
 
-    static native void HMAC_Init_ex(NativeRef.HMAC_CTX ctx, byte[] key, long evp_md);
+    @FastNative static native void HMAC_Init_ex(NativeRef.HMAC_CTX ctx, byte[] key, long evp_md);
 
+    @FastNative
     static native void HMAC_Update(NativeRef.HMAC_CTX ctx, byte[] in, int inOffset, int inLength);
 
+    @FastNative
     static native void HMAC_UpdateDirect(NativeRef.HMAC_CTX ctx, long inPtr, int inLength);
 
-    static native byte[] HMAC_Final(NativeRef.HMAC_CTX ctx);
+    @FastNative static native byte[] HMAC_Final(NativeRef.HMAC_CTX ctx);
 
-    static native void HMAC_Reset(NativeRef.HMAC_CTX ctx);
+    @FastNative static native void HMAC_Reset(NativeRef.HMAC_CTX ctx);
 
     // --- HPKE functions ------------------------------------------------------
+    @FastNative
     static native byte[] EVP_HPKE_CTX_export(
             NativeRef.EVP_HPKE_CTX ctx, byte[] exporterCtx, int length);
 
-    static native void EVP_HPKE_CTX_free(long ctx);
+    @FastNative static native void EVP_HPKE_CTX_free(long ctx);
 
+    @FastNative
     static native byte[] EVP_HPKE_CTX_open(
             NativeRef.EVP_HPKE_CTX ctx, byte[] ciphertext, byte[] aad) throws BadPaddingException;
 
+    @FastNative
     static native byte[] EVP_HPKE_CTX_seal(
             NativeRef.EVP_HPKE_CTX ctx, byte[] plaintext, byte[] aad);
 
+    @FastNative
     static native Object EVP_HPKE_CTX_setup_base_mode_recipient(
             int kem, int kdf, int aead, byte[] privateKey, byte[] enc, byte[] info);
 
@@ -430,6 +505,7 @@ public final class NativeCrypto {
                 suite.getKdf().getId(), suite.getAead().getId(), privateKey, enc, info);
     }
 
+    @FastNative
     static native Object[] EVP_HPKE_CTX_setup_base_mode_sender(
             int kem, int kdf, int aead, byte[] publicKey, byte[] info);
 
@@ -438,6 +514,8 @@ public final class NativeCrypto {
         return EVP_HPKE_CTX_setup_base_mode_sender(suite.getKem().getId(), suite.getKdf().getId(),
                 suite.getAead().getId(), publicKey, info);
     }
+
+    @FastNative
     static native Object[] EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
             int kem, int kdf, int aead, byte[] publicKey, byte[] info, byte[] seed);
 
@@ -449,7 +527,9 @@ public final class NativeCrypto {
 
     // --- RAND ----------------------------------------------------------------
 
-    @android.compat.annotation.UnsupportedAppUsage static native void RAND_bytes(byte[] output);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native void RAND_bytes(byte[] output);
 
     // --- X509_NAME -----------------------------------------------------------
 
@@ -460,6 +540,7 @@ public final class NativeCrypto {
     public static int X509_NAME_hash_old(X500Principal principal) {
         return X509_NAME_hash(principal, "MD5");
     }
+
     private static int X509_NAME_hash(X500Principal principal, String algorithm) {
         try {
             byte[] digest = MessageDigest.getInstance(algorithm).digest(principal.getEncoded());
@@ -476,102 +557,127 @@ public final class NativeCrypto {
     /** Used to request get_X509_GENERAL_NAME_stack get the "altname" field. */
     static final int GN_STACK_SUBJECT_ALT_NAME = 1;
 
-    /**
-     * Used to request get_X509_GENERAL_NAME_stack get the issuerAlternativeName
-     * extension.
-     */
+    /** Used to request get_X509_GENERAL_NAME_stack get the issuerAlternativeName extension. */
     static final int GN_STACK_ISSUER_ALT_NAME = 2;
 
-    /**
-     * Used to request only non-critical types in get_X509*_ext_oids.
-     */
+    /** Used to request only non-critical types in get_X509*_ext_oids. */
     static final int EXTENSION_TYPE_NON_CRITICAL = 0;
 
-    /**
-     * Used to request only critical types in get_X509*_ext_oids.
-     */
+    /** Used to request only critical types in get_X509*_ext_oids. */
     static final int EXTENSION_TYPE_CRITICAL = 1;
 
-    @android.compat.annotation.UnsupportedAppUsage static native long d2i_X509_bio(long bioCtx);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native long d2i_X509_bio(long bioCtx);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long d2i_X509(byte[] encoded) throws ParsingException;
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long PEM_read_bio_X509(long bioCtx);
 
-    static native byte[] i2d_X509(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native byte[] i2d_X509(long x509ctx, OpenSSLX509Certificate holder);
 
     /** Takes an X509 context not an X509_PUBKEY context. */
-    static native byte[] i2d_X509_PUBKEY(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native byte[] i2d_X509_PUBKEY(long x509ctx, OpenSSLX509Certificate holder);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native byte[] ASN1_seq_pack_X509(long[] x509CertRefs);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long[] ASN1_seq_unpack_X509_bio(long bioRef) throws ParsingException;
 
-    static native void X509_free(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native void X509_free(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native int X509_cmp(long x509ctx1, OpenSSLX509Certificate holder, long x509ctx2, OpenSSLX509Certificate holder2);
+    @FastNative
+    static native int X509_cmp(long x509ctx1, OpenSSLX509Certificate holder, long x509ctx2,
+            OpenSSLX509Certificate holder2);
 
-    static native void X509_print_ex(long bioCtx, long x509ctx, OpenSSLX509Certificate holder, long nmflag, long certflag);
+    @FastNative
+    static native void X509_print_ex(
+            long bioCtx, long x509ctx, OpenSSLX509Certificate holder, long nmflag, long certflag);
 
+    @FastNative
     static native byte[] X509_get_issuer_name(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] X509_get_subject_name(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native String get_X509_sig_alg_oid(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] get_X509_sig_alg_parameter(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native boolean[] get_X509_issuerUID(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native boolean[] get_X509_subjectUID(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native long X509_get_pubkey(long x509ctx, OpenSSLX509Certificate holder)
             throws NoSuchAlgorithmException, InvalidKeyException;
 
+    @FastNative
     static native String get_X509_pubkey_oid(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] X509_get_ext_oid(long x509ctx, OpenSSLX509Certificate holder, String oid);
 
-    static native String[] get_X509_ext_oids(long x509ctx, OpenSSLX509Certificate holder, int critical);
+    @FastNative
+    static native String[] get_X509_ext_oids(
+            long x509ctx, OpenSSLX509Certificate holder, int critical);
 
-    static native Object[][] get_X509_GENERAL_NAME_stack(long x509ctx, OpenSSLX509Certificate holder, int type)
-            throws CertificateParsingException;
+    @FastNative
+    static native Object[][] get_X509_GENERAL_NAME_stack(long x509ctx,
+            OpenSSLX509Certificate holder, int type) throws CertificateParsingException;
 
+    @FastNative
     static native boolean[] get_X509_ex_kusage(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native String[] get_X509_ex_xkusage(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native int get_X509_ex_pathlen(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native int get_X509_ex_pathlen(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native long X509_get_notBefore(long x509ctx, OpenSSLX509Certificate holder)
             throws ParsingException;
 
+    @FastNative
     static native long X509_get_notAfter(long x509ctx, OpenSSLX509Certificate holder)
             throws ParsingException;
 
-    static native long X509_get_version(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native long X509_get_version(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] X509_get_serialNumber(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native void X509_verify(long x509ctx, OpenSSLX509Certificate holder,
             NativeRef.EVP_PKEY pkeyCtx) throws BadPaddingException, IllegalBlockSizeException;
 
-    static native byte[] get_X509_tbs_cert(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native byte[] get_X509_tbs_cert(long x509ctx, OpenSSLX509Certificate holder);
 
+    @FastNative
     static native byte[] get_X509_tbs_cert_without_ext(
             long x509ctx, OpenSSLX509Certificate holder, String oid);
 
+    @FastNative
     static native byte[] get_X509_signature(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native int get_X509_ex_flags(long x509ctx, OpenSSLX509Certificate holder);
+    @FastNative static native int get_X509_ex_flags(long x509ctx, OpenSSLX509Certificate holder);
 
     // Used by Android platform TrustedCertificateStore.
     @SuppressWarnings("unused")
-    static native int X509_check_issued(long ctx, OpenSSLX509Certificate holder, long ctx2, OpenSSLX509Certificate holder2);
+    @FastNative
+    static native int X509_check_issued(
+            long ctx, OpenSSLX509Certificate holder, long ctx2, OpenSSLX509Certificate holder2);
 
     // --- PKCS7 ---------------------------------------------------------------
 
@@ -583,118 +689,144 @@ public final class NativeCrypto {
 
     /** Returns an array of X509 or X509_CRL pointers. */
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long[] d2i_PKCS7_bio(long bioCtx, int which) throws ParsingException;
 
     /** Returns an array of X509 or X509_CRL pointers. */
-    @android.compat.annotation.UnsupportedAppUsage static native byte[] i2d_PKCS7(long[] certs);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native byte[] i2d_PKCS7(long[] certs);
 
     /** Returns an array of X509 or X509_CRL pointers. */
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long[] PEM_read_bio_PKCS7(long bioCtx, int which);
 
     // --- X509_CRL ------------------------------------------------------------
 
-    @android.compat.annotation.UnsupportedAppUsage static native long d2i_X509_CRL_bio(long bioCtx);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native long d2i_X509_CRL_bio(long bioCtx);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long PEM_read_bio_X509_CRL(long bioCtx);
 
-    static native byte[] i2d_X509_CRL(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native byte[] i2d_X509_CRL(long x509CrlCtx, OpenSSLX509CRL holder);
 
-    static native void X509_CRL_free(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native void X509_CRL_free(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native void X509_CRL_print(long bioCtx, long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native String get_X509_CRL_sig_alg_oid(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native byte[] get_X509_CRL_sig_alg_parameter(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native byte[] X509_CRL_get_issuer_name(long x509CrlCtx, OpenSSLX509CRL holder);
 
     /** Returns X509_REVOKED reference that is not duplicated! */
-    static native long X509_CRL_get0_by_cert(long x509CrlCtx, OpenSSLX509CRL holder, long x509Ctx, OpenSSLX509Certificate holder2);
+    @FastNative
+    static native long X509_CRL_get0_by_cert(
+            long x509CrlCtx, OpenSSLX509CRL holder, long x509Ctx, OpenSSLX509Certificate holder2);
 
     /** Returns X509_REVOKED reference that is not duplicated! */
-    static native long X509_CRL_get0_by_serial(long x509CrlCtx, OpenSSLX509CRL holder, byte[] serial);
+    @FastNative
+    static native long X509_CRL_get0_by_serial(
+            long x509CrlCtx, OpenSSLX509CRL holder, byte[] serial);
 
     /** Returns an array of X509_REVOKED that are owned by the caller. */
-    static native long[] X509_CRL_get_REVOKED(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native long[] X509_CRL_get_REVOKED(long x509CrlCtx, OpenSSLX509CRL holder);
 
-    static native String[] get_X509_CRL_ext_oids(long x509Crlctx, OpenSSLX509CRL holder, int critical);
+    @FastNative
+    static native String[] get_X509_CRL_ext_oids(
+            long x509Crlctx, OpenSSLX509CRL holder, int critical);
 
+    @FastNative
     static native byte[] X509_CRL_get_ext_oid(long x509CrlCtx, OpenSSLX509CRL holder, String oid);
 
-    static native long X509_CRL_get_version(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native long X509_CRL_get_version(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native long X509_CRL_get_ext(long x509CrlCtx, OpenSSLX509CRL holder, String oid);
 
-    static native byte[] get_X509_CRL_signature(long x509ctx, OpenSSLX509CRL holder);
+    @FastNative static native byte[] get_X509_CRL_signature(long x509ctx, OpenSSLX509CRL holder);
 
-    static native void X509_CRL_verify(long x509CrlCtx, OpenSSLX509CRL holder,
-            NativeRef.EVP_PKEY pkeyCtx) throws BadPaddingException, SignatureException,
-                                               NoSuchAlgorithmException, InvalidKeyException,
-                                               IllegalBlockSizeException;
+    @FastNative
+    static native void X509_CRL_verify(
+            long x509CrlCtx, OpenSSLX509CRL holder, NativeRef.EVP_PKEY pkeyCtx)
+            throws BadPaddingException, SignatureException, NoSuchAlgorithmException,
+                   InvalidKeyException, IllegalBlockSizeException;
 
-    static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx, OpenSSLX509CRL holder);
+    @FastNative static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx, OpenSSLX509CRL holder);
 
+    @FastNative
     static native long X509_CRL_get_lastUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
             throws ParsingException;
 
+    @FastNative
     static native long X509_CRL_get_nextUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
             throws ParsingException;
 
     // --- X509_REVOKED --------------------------------------------------------
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long X509_REVOKED_dup(long x509RevokedCtx);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native byte[] i2d_X509_REVOKED(long x509RevokedCtx);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native String[] get_X509_REVOKED_ext_oids(long x509ctx, int critical);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native byte[] X509_REVOKED_get_ext_oid(long x509RevokedCtx, String oid);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native byte[] X509_REVOKED_get_serialNumber(long x509RevokedCtx);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long X509_REVOKED_get_ext(long x509RevokedCtx, String oid);
 
     /** Returns ASN1_TIME reference. */
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long get_X509_REVOKED_revocationDate(long x509RevokedCtx);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native void X509_REVOKED_print(long bioRef, long x509RevokedCtx);
 
     // --- X509_EXTENSION ------------------------------------------------------
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native int X509_supported_extension(long x509ExtensionRef);
 
     // --- SPAKE ---------------------------------------------------------------
 
     /**
-     * Sets the SPAKE credential for the given SSL context using a password.
-     * Used for both client and server.
+     * Sets the SPAKE credential for the given SSL context using a password. Used for both client
+     * and server.
      */
-    static native void SSL_CTX_set_spake_credential(
-            byte[] context,
-            byte[] pw_array,
-            byte[] id_prover_array,
-            byte[] id_verifier_array,
-            boolean is_client,
-            int handshake_limit,
-            long ssl_ctx,
-            AbstractSessionContext holder)
-        throws SSLException;
+    @FastNative
+    static native void SSL_CTX_set_spake_credential(byte[] context, byte[] pw_array,
+            byte[] id_prover_array, byte[] id_verifier_array, boolean is_client,
+            int handshake_limit, long ssl_ctx, AbstractSessionContext holder) throws SSLException;
 
     // --- ASN1_TIME -----------------------------------------------------------
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native void ASN1_TIME_to_Calendar(long asn1TimeCtx, Calendar cal)
             throws ParsingException;
 
@@ -702,147 +834,136 @@ public final class NativeCrypto {
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_read_* functions to read the ASN.1-encoded data in val.  The returned object must
-     * be freed after use by calling asn1_read_free.
+     * asn1_read_* functions to read the ASN.1-encoded data in val. The returned object must be
+     * freed after use by calling asn1_read_free.
      */
-    static native long asn1_read_init(byte[] val) throws IOException;
+    @FastNative static native long asn1_read_init(byte[] val) throws IOException;
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_read_* functions to read the ASN.1 sequence pointed to by cbsRef.  The returned
-     * object must be freed after use by calling asn1_read_free.
+     * asn1_read_* functions to read the ASN.1 sequence pointed to by cbsRef. The returned object
+     * must be freed after use by calling asn1_read_free.
      */
-    static native long asn1_read_sequence(long cbsRef) throws IOException;
+    @FastNative static native long asn1_read_sequence(long cbsRef) throws IOException;
 
     /**
-     * Returns whether the next object in the given reference is explicitly tagged with the
-     * given tag number.
+     * Returns whether the next object in the given reference is explicitly tagged with the given
+     * tag number.
      */
+    @FastNative
     static native boolean asn1_read_next_tag_is(long cbsRef, int tag) throws IOException;
 
     /**
-     * Allocates and returns an opaque reference to an object that can be used with
-     * other asn1_read_* functions to read the ASN.1 data pointed to by cbsRef.  The returned
-     * object must be freed after use by calling asn1_read_free.
+     * Allocates and returns an opaque reference to an object that can be used with other
+     * asn1_read_* functions to read the ASN.1 data pointed to by cbsRef. The returned object must
+     * be freed after use by calling asn1_read_free.
      */
-    static native long asn1_read_tagged(long cbsRef) throws IOException;
+    @FastNative static native long asn1_read_tagged(long cbsRef) throws IOException;
 
-    /**
-     * Returns the contents of an ASN.1 octet string from the given reference.
-     */
-    static native byte[] asn1_read_octetstring(long cbsRef) throws IOException;
+    /** Returns the contents of an ASN.1 octet string from the given reference. */
+    @FastNative static native byte[] asn1_read_octetstring(long cbsRef) throws IOException;
 
     /**
-     * Returns an ASN.1 integer from the given reference.  If the integer doesn't fit
-     * in a uint64, this method will throw an IOException.
+     * Returns an ASN.1 integer from the given reference. If the integer doesn't fit in a uint64,
+     * this method will throw an IOException.
      */
-    static native long asn1_read_uint64(long cbsRef) throws IOException;
+    @FastNative static native long asn1_read_uint64(long cbsRef) throws IOException;
 
-    /**
-     * Consumes an ASN.1 NULL from the given reference.
-     */
-    static native void asn1_read_null(long cbsRef) throws IOException;
+    /** Consumes an ASN.1 NULL from the given reference. */
+    @FastNative static native void asn1_read_null(long cbsRef) throws IOException;
 
     /**
      * Returns an ASN.1 OID in dotted-decimal notation (eg, "1.3.14.3.2.26" for SHA-1) from the
      * given reference.
      */
-    static native String asn1_read_oid(long cbsRef) throws IOException;
+    @FastNative static native String asn1_read_oid(long cbsRef) throws IOException;
 
-    /**
-     * Returns whether or not the given reference has been read completely.
-     */
-    static native boolean asn1_read_is_empty(long cbsRef);
+    /** Returns whether or not the given reference has been read completely. */
+    @FastNative static native boolean asn1_read_is_empty(long cbsRef);
 
     /**
-     * Frees any resources associated with the given reference.  After calling, the reference
-     * must not be used again.  This may be called with a zero reference, in which case nothing
-     * will be done.
+     * Frees any resources associated with the given reference. After calling, the reference must
+     * not be used again. This may be called with a zero reference, in which case nothing will be
+     * done.
      */
-    static native void asn1_read_free(long cbsRef);
+    @FastNative static native void asn1_read_free(long cbsRef);
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_write_* functions to write ASN.1-encoded data.  The returned object must be finalized
-     * after use by calling either asn1_write_finish or asn1_write_cleanup, and its resources
-     * must be freed by calling asn1_write_free.
+     * asn1_write_* functions to write ASN.1-encoded data. The returned object must be finalized
+     * after use by calling either asn1_write_finish or asn1_write_cleanup, and its resources must
+     * be freed by calling asn1_write_free.
      */
-    static native long asn1_write_init() throws IOException;
+    @FastNative static native long asn1_write_init() throws IOException;
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_write_* functions to write an ASN.1 sequence into the given reference.  The returned
-     * reference may only be used until the next call on the parent reference.  The returned
-     * object must be freed after use by calling asn1_write_free.
+     * asn1_write_* functions to write an ASN.1 sequence into the given reference. The returned
+     * reference may only be used until the next call on the parent reference. The returned object
+     * must be freed after use by calling asn1_write_free.
      */
-    static native long asn1_write_sequence(long cbbRef) throws IOException;
+    @FastNative static native long asn1_write_sequence(long cbbRef) throws IOException;
 
     /**
      * Allocates and returns an opaque reference to an object that can be used with other
-     * asn1_write_* functions to write a explicitly-tagged ASN.1 object with the given tag
-     * into the given reference. The returned reference may only be used until the next
-     * call on the parent reference.  The returned object must be freed after use by
-     * calling asn1_write_free.
+     * asn1_write_* functions to write a explicitly-tagged ASN.1 object with the given tag into the
+     * given reference. The returned reference may only be used until the next call on the parent
+     * reference. The returned object must be freed after use by calling asn1_write_free.
      */
-    static native long asn1_write_tag(long cbbRef, int tag) throws IOException;
+    @FastNative static native long asn1_write_tag(long cbbRef, int tag) throws IOException;
 
-    /**
-     * Writes the given data into the given reference as an ASN.1-encoded octet string.
-     */
+    /** Writes the given data into the given reference as an ASN.1-encoded octet string. */
+    @FastNative
     static native void asn1_write_octetstring(long cbbRef, byte[] data) throws IOException;
 
-    /**
-     * Writes the given value into the given reference as an ASN.1-encoded integer.
-     */
-    static native void asn1_write_uint64(long cbbRef, long value) throws IOException;
+    /** Writes the given value into the given reference as an ASN.1-encoded integer. */
+    @FastNative static native void asn1_write_uint64(long cbbRef, long value) throws IOException;
 
-    /**
-     * Writes a NULL value into the given reference.
-     */
-    static native void asn1_write_null(long cbbRef) throws IOException;
+    /** Writes a NULL value into the given reference. */
+    @FastNative static native void asn1_write_null(long cbbRef) throws IOException;
 
-    /**
-     * Writes the given OID (which must be in dotted-decimal notation) into the given reference.
-     */
-    static native void asn1_write_oid(long cbbRef, String oid) throws IOException;
+    /** Writes the given OID (which must be in dotted-decimal notation) into the given reference. */
+    @FastNative static native void asn1_write_oid(long cbbRef, String oid) throws IOException;
 
     /**
      * Flushes the given reference, invalidating any child references and completing their
-     * operations.  This must be called if the child references are to be freed before
-     * asn1_write_finish is called on the ultimate parent.  The child references must still
-     * be freed.
+     * operations. This must be called if the child references are to be freed before
+     * asn1_write_finish is called on the ultimate parent. The child references must still be freed.
      */
-    static native void asn1_write_flush(long cbbRef) throws IOException;
+    @FastNative static native void asn1_write_flush(long cbbRef) throws IOException;
 
     /**
-     * Completes any in-progress operations and returns the ASN.1-encoded data.  Either this
-     * or asn1_write_cleanup must be called on any reference returned from asn1_write_init
-     * before it is freed.
+     * Completes any in-progress operations and returns the ASN.1-encoded data. Either this or
+     * asn1_write_cleanup must be called on any reference returned from asn1_write_init before it is
+     * freed.
      */
-    static native byte[] asn1_write_finish(long cbbRef) throws IOException;
+    @FastNative static native byte[] asn1_write_finish(long cbbRef) throws IOException;
 
     /**
-     * Cleans up intermediate state in the given reference.  Either this or asn1_write_finish
-     * must be called on any reference returned from asn1_write_init before it is freed.
+     * Cleans up intermediate state in the given reference. Either this or asn1_write_finish must be
+     * called on any reference returned from asn1_write_init before it is freed.
      */
-    static native void asn1_write_cleanup(long cbbRef);
+    @FastNative static native void asn1_write_cleanup(long cbbRef);
 
     /**
-     * Frees resources associated with the given reference.  After calling, the reference
-     * must not be used again.  This may be called with a zero reference, in which case nothing
-     * will be done.
+     * Frees resources associated with the given reference. After calling, the reference must not be
+     * used again. This may be called with a zero reference, in which case nothing will be done.
      */
-    static native void asn1_write_free(long cbbRef);
+    @FastNative static native void asn1_write_free(long cbbRef);
 
     // --- BIO stream creation -------------------------------------------------
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long create_BIO_InputStream(OpenSSLBIOInputStream is, boolean isFinite);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long create_BIO_OutputStream(OutputStream os);
 
-    @android.compat.annotation.UnsupportedAppUsage static native void BIO_free_all(long bioRef);
+    @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
+    static native void BIO_free_all(long bioRef);
 
     // --- SSL handling --------------------------------------------------------
 
@@ -867,27 +988,22 @@ public final class NativeCrypto {
     // OpenSSL-style names.
     private static final Set<String> SUPPORTED_LEGACY_CIPHER_SUITES_SET = new HashSet<String>();
 
-    static final Set<String> SUPPORTED_TLS_1_3_CIPHER_SUITES_SET = new HashSet<String>(
-            Arrays.asList(SUPPORTED_TLS_1_3_CIPHER_SUITES));
+    static final Set<String> SUPPORTED_TLS_1_3_CIPHER_SUITES_SET =
+            new HashSet<String>(Arrays.asList(SUPPORTED_TLS_1_3_CIPHER_SUITES));
 
     /**
-     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV is RFC 5746's renegotiation
-     * indication signaling cipher suite value. It is not a real
-     * cipher suite. It is just an indication in the default and
-     * supported cipher suite lists indicates that the implementation
-     * supports secure renegotiation.
-     * <p>
-     * In the RI, its presence means that the SCSV is sent in the
-     * cipher suite list to indicate secure renegotiation support and
-     * its absense means to send an empty TLS renegotiation info
+     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV is RFC 5746's renegotiation indication signaling cipher
+     * suite value. It is not a real cipher suite. It is just an indication in the default and
+     * supported cipher suite lists indicates that the implementation supports secure renegotiation.
+     *
+     * <p>In the RI, its presence means that the SCSV is sent in the cipher suite list to indicate
+     * secure renegotiation support and its absense means to send an empty TLS renegotiation info
      * extension instead.
-     * <p>
-     * However, OpenSSL doesn't provide an API to give this level of
-     * control, instead always sending the SCSV and always including
-     * the empty renegotiation info if TLS is used (as opposed to
-     * SSL). So we simply allow TLS_EMPTY_RENEGOTIATION_INFO_SCSV to
-     * be passed for compatibility as to provide the hint that we
-     * support secure renegotiation.
+     *
+     * <p>However, OpenSSL doesn't provide an API to give this level of control, instead always
+     * sending the SCSV and always including the empty renegotiation info if TLS is used (as opposed
+     * to SSL). So we simply allow TLS_EMPTY_RENEGOTIATION_INFO_SCSV to be passed for compatibility
+     * as to provide the hint that we support secure renegotiation.
      */
     static final String TLS_EMPTY_RENEGOTIATION_INFO_SCSV = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
 
@@ -907,15 +1023,14 @@ public final class NativeCrypto {
     }
 
     /**
-     * TLS_FALLBACK_SCSV is from
-     * https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00
-     * to indicate to the server that this is a fallback protocol
-     * request.
+     * TLS_FALLBACK_SCSV is from https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00 to
+     * indicate to the server that this is a fallback protocol request.
      */
     private static final String TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV";
 
     private static final boolean HAS_AES_HARDWARE;
     private static final String[] SUPPORTED_TLS_1_2_CIPHER_SUITES;
+
     static {
         if (loadError == null) {
             // If loadError is not null, it means the native code was not loaded, so
@@ -949,12 +1064,12 @@ public final class NativeCrypto {
     }
 
     /**
-     * Returns 1 if the BoringSSL believes the CPU has AES accelerated hardware
-     * instructions. Used to determine cipher suite ordering.
+     * Returns 1 if the BoringSSL believes the CPU has AES accelerated hardware instructions. Used
+     * to determine cipher suite ordering.
      */
-    static native int EVP_has_aes_hardware();
+    @CriticalNative static native int EVP_has_aes_hardware();
 
-    @android.compat.annotation.UnsupportedAppUsage static native long SSL_CTX_new();
+    @android.compat.annotation.UnsupportedAppUsage @FastNative static native long SSL_CTX_new();
 
     // IMPLEMENTATION NOTE: The default list of cipher suites is a trade-off between what we'd like
     // to use and what servers currently support. We strive to be secure enough by default. We thus
@@ -975,39 +1090,40 @@ public final class NativeCrypto {
     // prevent apps from connecting to servers they were previously able to connect to.
 
     /** X.509 based cipher suites enabled by default (if requested), in preference order. */
-    static final String[] DEFAULT_X509_CIPHER_SUITES = HAS_AES_HARDWARE ?
-            new String[] {
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
-                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_RSA_WITH_AES_256_CBC_SHA",
-            } :
-            new String[] {
-                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
-                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
-                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
-                    "TLS_RSA_WITH_AES_128_CBC_SHA",
-                    "TLS_RSA_WITH_AES_256_CBC_SHA",
-            };
+    static final String[] DEFAULT_X509_CIPHER_SUITES =
+            HAS_AES_HARDWARE
+                    ? new String[] {
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
+                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_RSA_WITH_AES_256_CBC_SHA",
+                    }
+                    : new String[] {
+                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
+                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
+                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
+                        "TLS_RSA_WITH_AES_128_CBC_SHA",
+                        "TLS_RSA_WITH_AES_256_CBC_SHA",
+                    };
 
     /** TLS-PSK cipher suites enabled by default (if requested), in preference order. */
     static final String[] DEFAULT_PSK_CIPHER_SUITES = new String[] {
@@ -1024,22 +1140,33 @@ public final class NativeCrypto {
     };
 
     static String[] getSupportedCipherSuites() {
-        return SSLUtils.concat(SUPPORTED_TLS_1_3_CIPHER_SUITES, SUPPORTED_TLS_1_2_CIPHER_SUITES.clone());
+        return SSLUtils.concat(
+                SUPPORTED_TLS_1_3_CIPHER_SUITES, SUPPORTED_TLS_1_2_CIPHER_SUITES.clone());
     }
 
-    static native void SSL_CTX_free(long ssl_ctx, AbstractSessionContext holder);
+    @FastNative static native void SSL_CTX_free(long ssl_ctx, AbstractSessionContext holder);
 
-    static native void SSL_CTX_set_session_id_context(long ssl_ctx, AbstractSessionContext holder, byte[] sid_ctx);
+    @FastNative
+    static native void SSL_CTX_set_session_id_context(
+            long ssl_ctx, AbstractSessionContext holder, byte[] sid_ctx);
 
-    static native long SSL_CTX_set_timeout(long ssl_ctx, AbstractSessionContext holder, long seconds);
+    @FastNative
+    static native long SSL_CTX_set_timeout(
+            long ssl_ctx, AbstractSessionContext holder, long seconds);
 
+    @FastNative
     static native long SSL_new(long ssl_ctx, AbstractSessionContext holder) throws SSLException;
 
-    static native void SSL_enable_tls_channel_id(long ssl, NativeSsl ssl_holder) throws SSLException;
+    @FastNative
+    static native void SSL_enable_tls_channel_id(long ssl, NativeSsl ssl_holder)
+            throws SSLException;
 
+    @FastNative
     static native byte[] SSL_get_tls_channel_id(long ssl, NativeSsl ssl_holder) throws SSLException;
 
-    static native void SSL_set1_tls_channel_id(long ssl, NativeSsl ssl_holder, NativeRef.EVP_PKEY pkey);
+    @FastNative
+    static native void SSL_set1_tls_channel_id(
+            long ssl, NativeSsl ssl_holder, NativeRef.EVP_PKEY pkey);
 
     /**
      * Sets the local certificates and private key.
@@ -1049,75 +1176,92 @@ public final class NativeCrypto {
      * @param pkey a reference to the private key.
      * @throws SSLException if a problem occurs setting the cert/key.
      */
-    static native void setLocalCertsAndPrivateKey(long ssl, NativeSsl ssl_holder, byte[][] encodedCertificates,
-        NativeRef.EVP_PKEY pkey) throws SSLException;
+    @FastNative
+    static native void setLocalCertsAndPrivateKey(long ssl, NativeSsl ssl_holder,
+            byte[][] encodedCertificates, NativeRef.EVP_PKEY pkey) throws SSLException;
 
-    static native void SSL_set_client_CA_list(long ssl, NativeSsl ssl_holder, byte[][] asn1DerEncodedX500Principals)
-            throws SSLException;
+    @FastNative
+    static native void SSL_set_client_CA_list(long ssl, NativeSsl ssl_holder,
+            byte[][] asn1DerEncodedX500Principals) throws SSLException;
 
-    static native long SSL_set_mode(long ssl, NativeSsl ssl_holder, long mode);
+    @FastNative static native long SSL_set_mode(long ssl, NativeSsl ssl_holder, long mode);
 
-    static native long SSL_set_options(long ssl, NativeSsl ssl_holder, long options);
+    @FastNative static native long SSL_set_options(long ssl, NativeSsl ssl_holder, long options);
 
-    static native long SSL_clear_options(long ssl, NativeSsl ssl_holder, long options);
+    @FastNative static native long SSL_clear_options(long ssl, NativeSsl ssl_holder, long options);
 
-    static native int SSL_set_protocol_versions(long ssl, NativeSsl ssl_holder, int min_version, int max_version);
+    @FastNative
+    static native int SSL_set_protocol_versions(
+            long ssl, NativeSsl ssl_holder, int min_version, int max_version);
 
+    @FastNative
     static native void SSL_enable_signed_cert_timestamps(long ssl, NativeSsl ssl_holder);
 
+    @FastNative
     static native byte[] SSL_get_signed_cert_timestamp_list(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_set_signed_cert_timestamp_list(long ssl, NativeSsl ssl_holder, byte[] list);
+    @FastNative
+    static native void SSL_set_signed_cert_timestamp_list(
+            long ssl, NativeSsl ssl_holder, byte[] list);
 
-    static native void SSL_enable_ocsp_stapling(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_enable_ocsp_stapling(long ssl, NativeSsl ssl_holder);
 
-    static native byte[] SSL_get_ocsp_response(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] SSL_get_ocsp_response(long ssl, NativeSsl ssl_holder);
 
+    @FastNative
     static native void SSL_set_ocsp_response(long ssl, NativeSsl ssl_holder, byte[] response);
 
-    static native byte[] SSL_get_tls_unique(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] SSL_get_tls_unique(long ssl, NativeSsl ssl_holder);
 
-    static native byte[] SSL_export_keying_material(long ssl, NativeSsl ssl_holder, byte[] label, byte[] context, int num_bytes) throws SSLException;
+    @FastNative
+    static native byte[] SSL_export_keying_material(long ssl, NativeSsl ssl_holder, byte[] label,
+            byte[] context, int num_bytes) throws SSLException;
 
-    static native void SSL_use_psk_identity_hint(long ssl, NativeSsl ssl_holder, String identityHint) throws SSLException;
+    @FastNative
+    static native void SSL_use_psk_identity_hint(
+            long ssl, NativeSsl ssl_holder, String identityHint) throws SSLException;
 
-    static native void set_SSL_psk_client_callback_enabled(long ssl, NativeSsl ssl_holder, boolean enabled);
+    @FastNative
+    static native void set_SSL_psk_client_callback_enabled(
+            long ssl, NativeSsl ssl_holder, boolean enabled);
 
-    static native void set_SSL_psk_server_callback_enabled(long ssl, NativeSsl ssl_holder, boolean enabled);
+    @FastNative
+    static native void set_SSL_psk_server_callback_enabled(
+            long ssl, NativeSsl ssl_holder, boolean enabled);
 
     public static void setTlsV1DeprecationStatus(boolean deprecated, boolean supported) {
         if (deprecated) {
             TLSV12_PROTOCOLS = new String[] {
-                SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
             };
             TLSV13_PROTOCOLS = new String[] {
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         } else {
             TLSV12_PROTOCOLS = new String[] {
-                DEPRECATED_PROTOCOL_TLSV1,
-                DEPRECATED_PROTOCOL_TLSV1_1,
-                SUPPORTED_PROTOCOL_TLSV1_2,
+                    DEPRECATED_PROTOCOL_TLSV1,
+                    DEPRECATED_PROTOCOL_TLSV1_1,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
             };
             TLSV13_PROTOCOLS = new String[] {
-                DEPRECATED_PROTOCOL_TLSV1,
-                DEPRECATED_PROTOCOL_TLSV1_1,
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    DEPRECATED_PROTOCOL_TLSV1,
+                    DEPRECATED_PROTOCOL_TLSV1_1,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         }
         if (supported) {
             SUPPORTED_PROTOCOLS = new String[] {
-                DEPRECATED_PROTOCOL_TLSV1,
-                DEPRECATED_PROTOCOL_TLSV1_1,
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    DEPRECATED_PROTOCOL_TLSV1,
+                    DEPRECATED_PROTOCOL_TLSV1_1,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         } else {
             SUPPORTED_PROTOCOLS = new String[] {
-                SUPPORTED_PROTOCOL_TLSV1_2,
-                SUPPORTED_PROTOCOL_TLSV1_3,
+                    SUPPORTED_PROTOCOL_TLSV1_2,
+                    SUPPORTED_PROTOCOL_TLSV1_3,
             };
         }
     }
@@ -1153,6 +1297,7 @@ public final class NativeCrypto {
     private static class Range {
         public final String min;
         public final String max;
+
         public Range(String min, String max) {
             this.min = min;
             this.max = max;
@@ -1221,6 +1366,7 @@ public final class NativeCrypto {
         return protocols;
     }
 
+    @FastNative
     static native void SSL_set_cipher_lists(long ssl, NativeSsl ssl_holder, String[] ciphers);
 
     /**
@@ -1228,7 +1374,7 @@ public final class NativeCrypto {
      *
      * @return array of {@code SSL_CIPHER} references.
      */
-    static native long[] SSL_get_ciphers(long ssl, NativeSsl ssl_holder);
+    @FastNative static native long[] SSL_get_ciphers(long ssl, NativeSsl ssl_holder);
 
     static void setEnabledCipherSuites(
             long ssl, NativeSsl ssl_holder, String[] cipherSuites, String[] protocols) {
@@ -1251,7 +1397,8 @@ public final class NativeCrypto {
             }
             opensslSuites.add(cipherSuiteFromJava(cipherSuite));
         }
-        SSL_set_cipher_lists(ssl, ssl_holder, opensslSuites.toArray(new String[opensslSuites.size()]));
+        SSL_set_cipher_lists(
+                ssl, ssl_holder, opensslSuites.toArray(new String[opensslSuites.size()]));
     }
 
     static String[] checkEnabledCipherSuites(String[] cipherSuites) {
@@ -1288,101 +1435,114 @@ public final class NativeCrypto {
         return cipherSuites;
     }
 
-    static native void SSL_set_accept_state(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_set_accept_state(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_set_connect_state(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_set_connect_state(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_set_verify(long ssl, NativeSsl ssl_holder, int mode);
+    @FastNative static native void SSL_set_verify(long ssl, NativeSsl ssl_holder, int mode);
 
+    @FastNative
     static native void SSL_set_session(long ssl, NativeSsl ssl_holder, long sslSessionNativePointer)
             throws SSLException;
 
+    @FastNative
     static native void SSL_set_session_creation_enabled(
             long ssl, NativeSsl ssl_holder, boolean creationEnabled) throws SSLException;
 
-    static native boolean SSL_session_reused(long ssl, NativeSsl ssl_holder);
+    @FastNative static native boolean SSL_session_reused(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_accept_renegotiations(long ssl, NativeSsl ssl_holder) throws SSLException;
+    @FastNative
+    static native void SSL_accept_renegotiations(long ssl, NativeSsl ssl_holder)
+            throws SSLException;
 
+    @FastNative
     static native void SSL_set_tlsext_host_name(long ssl, NativeSsl ssl_holder, String hostname)
             throws SSLException;
-    static native String SSL_get_servername(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_do_handshake(
-            long ssl, NativeSsl ssl_holder, FileDescriptor fd, SSLHandshakeCallbacks shc, int timeoutMillis)
+    @FastNative static native String SSL_get_servername(long ssl, NativeSsl ssl_holder);
+
+    static native void SSL_do_handshake(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
+            SSLHandshakeCallbacks shc, int timeoutMillis)
             throws SSLException, SocketTimeoutException, CertificateException;
 
-    public static native String SSL_get_current_cipher(long ssl, NativeSsl ssl_holder);
+    @FastNative public static native String SSL_get_current_cipher(long ssl, NativeSsl ssl_holder);
 
-    public static native String SSL_get_version(long ssl, NativeSsl ssl_holder);
+    @FastNative public static native String SSL_get_version(long ssl, NativeSsl ssl_holder);
 
-    /**
-     * Returns the peer certificate chain.
-     */
-    static native byte[][] SSL_get0_peer_certificates(long ssl, NativeSsl ssl_holder);
+    /** Returns the peer certificate chain. */
+    @FastNative static native byte[][] SSL_get0_peer_certificates(long ssl, NativeSsl ssl_holder);
 
     /**
      * Reads with the native SSL_read function from the encrypted data stream
+     *
      * @return -1 if error or the end of the stream is reached.
      */
-    static native int SSL_read(long ssl, NativeSsl ssl_holder, FileDescriptor fd, SSLHandshakeCallbacks shc,
-            byte[] b, int off, int len, int readTimeoutMillis) throws IOException;
+    static native int SSL_read(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
+            SSLHandshakeCallbacks shc, byte[] b, int off, int len, int readTimeoutMillis)
+            throws IOException;
 
-    /**
-     * Writes with the native SSL_write function to the encrypted data stream.
-     */
+    /** Writes with the native SSL_write function to the encrypted data stream. */
     static native void SSL_write(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
             SSLHandshakeCallbacks shc, byte[] b, int off, int len, int writeTimeoutMillis)
             throws IOException;
 
-    static native void SSL_interrupt(long ssl, NativeSsl ssl_holder);
-    static native void SSL_shutdown(
-            long ssl, NativeSsl ssl_holder, FileDescriptor fd, SSLHandshakeCallbacks shc) throws IOException;
+    @FastNative static native void SSL_interrupt(long ssl, NativeSsl ssl_holder);
+
+    static native void SSL_shutdown(long ssl, NativeSsl ssl_holder, FileDescriptor fd,
+            SSLHandshakeCallbacks shc) throws IOException;
 
-    static native int SSL_get_shutdown(long ssl, NativeSsl ssl_holder);
+    @FastNative static native int SSL_get_shutdown(long ssl, NativeSsl ssl_holder);
 
-    static native void SSL_free(long ssl, NativeSsl ssl_holder);
+    @FastNative static native void SSL_free(long ssl, NativeSsl ssl_holder);
 
-    static native long SSL_get_time(long ssl, NativeSsl ssl_holder);
+    @FastNative static native long SSL_get_time(long ssl, NativeSsl ssl_holder);
 
-    static native long SSL_set_timeout(long ssl, NativeSsl ssl_holder, long millis);
+    @FastNative static native long SSL_set_timeout(long ssl, NativeSsl ssl_holder, long millis);
 
-    static native long SSL_get_timeout(long ssl, NativeSsl ssl_holder);
+    @FastNative static native long SSL_get_timeout(long ssl, NativeSsl ssl_holder);
 
-    static native int SSL_get_signature_algorithm_key_type(int signatureAlg);
+    @CriticalNative static native int SSL_get_signature_algorithm_key_type(int signatureAlg);
 
-    static native byte[] SSL_session_id(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] SSL_session_id(long ssl, NativeSsl ssl_holder);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native byte[] SSL_SESSION_session_id(long sslSessionNativePointer);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long SSL_SESSION_get_time(long sslSessionNativePointer);
 
-    static native long SSL_SESSION_get_timeout(long sslSessionNativePointer);
+    @FastNative static native long SSL_SESSION_get_timeout(long sslSessionNativePointer);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native String SSL_SESSION_get_version(long sslSessionNativePointer);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native String SSL_SESSION_cipher(long sslSessionNativePointer);
 
+    @FastNative
     static native boolean SSL_SESSION_should_be_single_use(long sslSessionNativePointer);
 
-    static native void SSL_SESSION_up_ref(long sslSessionNativePointer);
+    @FastNative static native void SSL_SESSION_up_ref(long sslSessionNativePointer);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native void SSL_SESSION_free(long sslSessionNativePointer);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native byte[] i2d_SSL_SESSION(long sslSessionNativePointer);
 
     @android.compat.annotation.UnsupportedAppUsage
+    @FastNative
     static native long d2i_SSL_SESSION(byte[] data) throws IOException;
 
     /**
-     * A collection of callbacks from the native OpenSSL code that are
-     * related to the SSL handshake initiated by SSL_do_handshake.
+     * A collection of callbacks from the native OpenSSL code that are related to the SSL handshake
+     * initiated by SSL_do_handshake.
      */
     interface SSLHandshakeCallbacks {
         /**
@@ -1390,7 +1550,6 @@ public final class NativeCrypto {
          *
          * @param certificateChain chain of X.509 certificates in their encoded form
          * @param authMethod auth algorithm name
-         *
          * @throws CertificateException if the certificate is untrusted
          */
         @SuppressWarnings("unused")
@@ -1411,9 +1570,9 @@ public final class NativeCrypto {
                 throws CertificateEncodingException, SSLException;
 
         /**
-         * Called when acting as a server during ClientHello processing before a decision
-         * to resume a session is made. This allows the selection of the correct server
-         * certificate based on things like Server Name Indication (SNI).
+         * Called when acting as a server during ClientHello processing before a decision to resume
+         * a session is made. This allows the selection of the correct server certificate based on
+         * things like Server Name Indication (SNI).
          *
          * @throws IOException if there was an error during certificate selection.
          */
@@ -1424,13 +1583,12 @@ public final class NativeCrypto {
          * exchange.
          *
          * @param identityHint PSK identity hint provided by the server or {@code null} if no hint
-         *        provided.
+         *     provided.
          * @param identity buffer to be populated with PSK identity (NULL-terminated modified UTF-8)
-         *        by this method. This identity will be provided to the server.
+         *     by this method. This identity will be provided to the server.
          * @param key buffer to be populated with key material by this method.
-         *
          * @return number of bytes this method stored in the {@code key} buffer or {@code 0} if an
-         *         error occurred in which case the handshake will be aborted.
+         *     error occurred in which case the handshake will be aborted.
          */
         int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key);
 
@@ -1438,33 +1596,30 @@ public final class NativeCrypto {
          * Gets the key to be used in server mode for this connection in Pre-Shared Key (PSK) key
          * exchange.
          *
-         * @param identityHint PSK identity hint provided by this server to the client or
-         *        {@code null} if no hint was provided.
+         * @param identityHint PSK identity hint provided by this server to the client or {@code
+         *     null} if no hint was provided.
          * @param identity PSK identity provided by the client.
          * @param key buffer to be populated with key material by this method.
-         *
          * @return number of bytes this method stored in the {@code key} buffer or {@code 0} if an
-         *         error occurred in which case the handshake will be aborted.
+         *     error occurred in which case the handshake will be aborted.
          */
         int serverPSKKeyRequested(String identityHint, String identity, byte[] key);
 
-        /**
-         * Called when SSL state changes. This could be handshake completion.
-         */
+        /** Called when SSL state changes. This could be handshake completion. */
         @SuppressWarnings("unused") void onSSLStateChange(int type, int val);
 
         /**
-         * Called when a new session has been established and may be added to the session cache.
-         * The callee is responsible for incrementing the reference count on the returned session.
+         * Called when a new session has been established and may be added to the session cache. The
+         * callee is responsible for incrementing the reference count on the returned session.
          */
         @SuppressWarnings("unused") void onNewSessionEstablished(long sslSessionNativePtr);
 
         /**
-         * Called for servers where TLS < 1.3 (TLS 1.3 uses session tickets rather than
-         * application session caches).
+         * Called for servers where TLS < 1.3 (TLS 1.3 uses session tickets rather than application
+         * session caches).
          *
-         * <p/>Looks up the session by ID in the application's session cache. If a valid session
-         * is returned, this callback is responsible for incrementing the reference count (and any
+         * <p>Looks up the session by ID in the application's session cache. If a valid session is
+         * returned, this callback is responsible for incrementing the reference count (and any
          * required synchronization).
          *
          * @param id the ID of the session to find.
@@ -1474,7 +1629,7 @@ public final class NativeCrypto {
 
         /**
          * Called when acting as a server, the socket has an {@link
-         * ApplicationProtocolSelectorAdapter} associated with it,  and the application protocol
+         * ApplicationProtocolSelectorAdapter} associated with it, and the application protocol
          * needs to be selected.
          *
          * @param applicationProtocols list of application protocols in length-prefix format
@@ -1483,140 +1638,136 @@ public final class NativeCrypto {
         @SuppressWarnings("unused") int selectApplicationProtocol(byte[] applicationProtocols);
     }
 
-    static native String SSL_CIPHER_get_kx_name(long cipherAddress);
+    @FastNative static native String SSL_CIPHER_get_kx_name(long cipherAddress);
 
-    static native String[] get_cipher_names(String selection);
+    @FastNative static native String[] get_cipher_names(String selection);
 
-    public static native byte[] get_ocsp_single_extension(
-            byte[] ocspResponse, String oid, long x509Ref, OpenSSLX509Certificate holder, long issuerX509Ref, OpenSSLX509Certificate holder2);
+    @FastNative
+    public static native byte[] get_ocsp_single_extension(byte[] ocspResponse, String oid,
+            long x509Ref, OpenSSLX509Certificate holder, long issuerX509Ref,
+            OpenSSLX509Certificate holder2);
 
     /**
-     * Returns the starting address of the memory region referenced by the provided direct
-     * {@link Buffer} or {@code 0} if the provided buffer is not direct or if such access to direct
-     * buffers is not supported by the platform.
+     * Returns the starting address of the memory region referenced by the provided direct {@link
+     * Buffer} or {@code 0} if the provided buffer is not direct or if such access to direct buffers
+     * is not supported by the platform.
      *
      * <p>NOTE: This method ignores the buffer's current {@code position}.
      */
-    static native long getDirectBufferAddress(Buffer buf);
+    @FastNative static native long getDirectBufferAddress(Buffer buf);
 
-    static native long SSL_BIO_new(long ssl, NativeSsl ssl_holder) throws SSLException;
+    @FastNative static native long SSL_BIO_new(long ssl, NativeSsl ssl_holder) throws SSLException;
 
-    static native int SSL_get_error(long ssl, NativeSsl ssl_holder, int ret);
+    @FastNative static native int SSL_get_error(long ssl, NativeSsl ssl_holder, int ret);
 
-    static native void SSL_clear_error();
+    @CriticalNative static native void SSL_clear_error();
 
-    static native int SSL_pending_readable_bytes(long ssl, NativeSsl ssl_holder);
+    @FastNative static native int SSL_pending_readable_bytes(long ssl, NativeSsl ssl_holder);
 
-    static native int SSL_pending_written_bytes_in_BIO(long bio);
+    @FastNative static native int SSL_pending_written_bytes_in_BIO(long bio);
 
-    /**
-     * Returns the maximum overhead, in bytes, of sealing a record with SSL.
-     */
-    static native int SSL_max_seal_overhead(long ssl, NativeSsl ssl_holder);
+    /** Returns the maximum overhead, in bytes, of sealing a record with SSL. */
+    @FastNative static native int SSL_max_seal_overhead(long ssl, NativeSsl ssl_holder);
 
     /**
      * Enables ALPN for this TLS endpoint and sets the list of supported ALPN protocols in
      * wire-format (length-prefixed 8-bit strings).
      */
+    @FastNative
     static native void setApplicationProtocols(
             long ssl, NativeSsl ssl_holder, boolean client, byte[] protocols) throws IOException;
 
     /**
      * Called for a server endpoint only. Enables ALPN and indicates that the {@link
-     * SSLHandshakeCallbacks#selectApplicationProtocol} will be called to select the
-     * correct protocol during a handshake. Calling this method overrides
-     * {@link #setApplicationProtocols(long, NativeSsl, boolean, byte[])}.
+     * SSLHandshakeCallbacks#selectApplicationProtocol} will be called to select the correct
+     * protocol during a handshake. Calling this method overrides {@link
+     * #setApplicationProtocols(long, NativeSsl, boolean, byte[])}.
      */
+    @FastNative
     static native void setHasApplicationProtocolSelector(
             long ssl, NativeSsl ssl_holder, boolean hasSelector) throws IOException;
 
     /**
-     * Returns the selected ALPN protocol. If the server did not select a
-     * protocol, {@code null} will be returned.
+     * Returns the selected ALPN protocol. If the server did not select a protocol, {@code null}
+     * will be returned.
      */
-    static native byte[] getApplicationProtocol(long ssl, NativeSsl ssl_holder);
+    @FastNative static native byte[] getApplicationProtocol(long ssl, NativeSsl ssl_holder);
 
     /**
      * Variant of the {@link #SSL_do_handshake} used by {@link ConscryptEngine}. This differs
-     * slightly from the raw BoringSSL API in that it returns the SSL error code from the
-     * operation, rather than the return value from {@code SSL_do_handshake}. This is done in
-     * order to allow to properly handle SSL errors and propagate useful exceptions.
+     * slightly from the raw BoringSSL API in that it returns the SSL error code from the operation,
+     * rather than the return value from {@code SSL_do_handshake}. This is done in order to allow to
+     * properly handle SSL errors and propagate useful exceptions.
      *
      * @return Returns the SSL error code for the operation when the error was {@code
-     * SSL_ERROR_NONE}, {@code SSL_ERROR_WANT_READ}, or {@code SSL_ERROR_WANT_WRITE}.
+     *     SSL_ERROR_NONE}, {@code SSL_ERROR_WANT_READ}, or {@code SSL_ERROR_WANT_WRITE}.
      * @throws IOException when the error code is anything except those returned by this method.
      */
-    static native int ENGINE_SSL_do_handshake(long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc)
-            throws IOException;
+    static native int ENGINE_SSL_do_handshake(
+            long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc) throws IOException;
 
     /**
      * Variant of the {@link #SSL_read} for a direct {@link java.nio.ByteBuffer} used by {@link
      * ConscryptEngine}.
      *
-     * @return if positive, represents the number of bytes read into the given buffer.
-     * Returns {@code -SSL_ERROR_WANT_READ} if more data is needed. Returns
-     * {@code -SSL_ERROR_WANT_WRITE} if data needs to be written out to flush the BIO.
-     *
+     * @return if positive, represents the number of bytes read into the given buffer. Returns
+     *     {@code -SSL_ERROR_WANT_READ} if more data is needed. Returns {@code
+     *     -SSL_ERROR_WANT_WRITE} if data needs to be written out to flush the BIO.
      * @throws java.io.InterruptedIOException if the read was interrupted.
      * @throws java.io.EOFException if the end of stream has been reached.
      * @throws CertificateException if the application's certificate verification callback failed.
-     * Only occurs during handshake processing.
+     *     Only occurs during handshake processing.
      * @throws SSLException if any other error occurs.
      */
-    static native int ENGINE_SSL_read_direct(long ssl, NativeSsl ssl_holder, long address, int length,
-            SSLHandshakeCallbacks shc) throws IOException, CertificateException;
+    static native int ENGINE_SSL_read_direct(long ssl, NativeSsl ssl_holder, long address,
+            int length, SSLHandshakeCallbacks shc) throws IOException, CertificateException;
 
     /**
      * Variant of the {@link #SSL_write} for a direct {@link java.nio.ByteBuffer} used by {@link
      * ConscryptEngine}. This version does not lock or and does no error pre-processing.
      */
-    static native int ENGINE_SSL_write_direct(long ssl, NativeSsl ssl_holder, long address, int length,
-            SSLHandshakeCallbacks shc) throws IOException;
+    static native int ENGINE_SSL_write_direct(long ssl, NativeSsl ssl_holder, long address,
+            int length, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Writes data from the given direct {@link java.nio.ByteBuffer} to the BIO.
-     */
-    static native int ENGINE_SSL_write_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef, long pos, int length,
-            SSLHandshakeCallbacks shc) throws IOException;
+    /** Writes data from the given direct {@link java.nio.ByteBuffer} to the BIO. */
+    static native int ENGINE_SSL_write_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef,
+            long pos, int length, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Reads data from the given BIO into a direct {@link java.nio.ByteBuffer}.
-     */
-    static native int ENGINE_SSL_read_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef, long address, int len,
-            SSLHandshakeCallbacks shc) throws IOException;
+    /** Reads data from the given BIO into a direct {@link java.nio.ByteBuffer}. */
+    static native int ENGINE_SSL_read_BIO_direct(long ssl, NativeSsl ssl_holder, long bioRef,
+            long address, int len, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Forces the SSL object to process any data pending in the BIO.
-     */
-    static native void ENGINE_SSL_force_read(long ssl, NativeSsl ssl_holder,
-            SSLHandshakeCallbacks shc) throws IOException;
+    /** Forces the SSL object to process any data pending in the BIO. */
+    static native void ENGINE_SSL_force_read(
+            long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc) throws IOException;
 
     /**
      * Variant of the {@link #SSL_shutdown} used by {@link ConscryptEngine}. This version does not
      * lock.
      */
-    static native void ENGINE_SSL_shutdown(long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc)
-            throws IOException;
+    static native void ENGINE_SSL_shutdown(
+            long ssl, NativeSsl ssl_holder, SSLHandshakeCallbacks shc) throws IOException;
 
-    /**
-     * Generates a key from a password and salt using Scrypt.
-     */
+    /** Generates a key from a password and salt using Scrypt. */
+    @FastNative
     static native byte[] Scrypt_generate_key(
             byte[] password, byte[] salt, int n, int r, int p, int key_len);
 
-    /**
-     * Return {@code true} if BoringSSL has been built in FIPS mode.
-     */
-    static native boolean usesBoringSsl_FIPS_mode();
+    /** Return {@code true} if BoringSSL has been built in FIPS mode. */
+    @CriticalNative static native boolean usesBoringSsl_FIPS_mode();
 
-    /**
-     * Used for testing only.
-     */
-    static native int BIO_read(long bioRef, byte[] buffer) throws IOException;
+    /** Used for testing only. */
+    @FastNative static native int BIO_read(long bioRef, byte[] buffer) throws IOException;
+
+    @FastNative
     static native void BIO_write(long bioRef, byte[] buffer, int offset, int length)
             throws IOException, IndexOutOfBoundsException;
-    static native long SSL_clear_mode(long ssl, NativeSsl ssl_holder, long mode);
-    static native long SSL_get_mode(long ssl, NativeSsl ssl_holder);
-    static native long SSL_get_options(long ssl, NativeSsl ssl_holder);
-    static native long SSL_get1_session(long ssl, NativeSsl ssl_holder);
+
+    @FastNative static native long SSL_clear_mode(long ssl, NativeSsl ssl_holder, long mode);
+
+    @FastNative static native long SSL_get_mode(long ssl, NativeSsl ssl_holder);
+
+    @FastNative static native long SSL_get_options(long ssl, NativeSsl ssl_holder);
+
+    @FastNative static native long SSL_get1_session(long ssl, NativeSsl ssl_holder);
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
index c618ebe7..1bb2fd4f 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
@@ -310,14 +310,11 @@ final class NativeSsl {
                     + " and " + NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1
                     + " are no longer supported and were filtered from the list");
         }
-        // We can use default cipher suites for SPAKE.
+        NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
+        // We only set the cipher suites if we are not using SPAKE.
         if (!parameters.isSpake()) {
-            NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
             NativeCrypto.setEnabledCipherSuites(
-                ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
-        } else {
-            // SPAKE only supports TLSv1.3.
-            NativeCrypto.setEnabledProtocols(ssl, this, new String[] {"TLSv1.3"});
+                    ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
         }
 
         if (parameters.applicationProtocols.length > 0) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherRSA.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherRSA.java
index 39102120..fe3db039 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherRSA.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherRSA.java
@@ -39,6 +39,7 @@ import java.security.spec.PKCS8EncodedKeySpec;
 import java.security.spec.X509EncodedKeySpec;
 import java.util.Arrays;
 import java.util.Locale;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.Cipher;
 import javax.crypto.CipherSpi;
@@ -453,7 +454,6 @@ public abstract class OpenSSLCipherRSA extends CipherSpi {
             oaepMd = mgf1Md = defaultMd;
             oaepMdSizeBytes = defaultMdSizeBytes;
         }
-
         @Override
         protected AlgorithmParameters engineGetParameters() {
             if (!isInitialized()) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherAES.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherAES.java
index ee65b309..1efd3536 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherAES.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherAES.java
@@ -20,6 +20,7 @@ package com.android.org.conscrypt;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.util.Locale;
+
 import javax.crypto.NoSuchPaddingException;
 
 /**
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherDESEDE.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherDESEDE.java
index 9e8d50c1..0f95e6b3 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherDESEDE.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipherDESEDE.java
@@ -20,6 +20,7 @@ package com.android.org.conscrypt;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.util.Locale;
+
 import javax.crypto.NoSuchPaddingException;
 
 /**
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CertificateFactory.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CertificateFactory.java
index 1907738f..d3922db9 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CertificateFactory.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CertificateFactory.java
@@ -43,6 +43,11 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
     private static final byte[] PKCS7_MARKER = new byte[] {
             '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ', 'P', 'K', 'C', 'S', '7'
     };
+    private static final byte[] PEM_MARKER = new byte[] {
+            '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' '
+    };
+    private static final int DASH = 45; // Value of '-'
+    private static final int VALUE_0 = 0x30; // Value of '0'
 
     private static final int PUSHBACK_SIZE = 64;
 
@@ -64,7 +69,7 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
 
     private static boolean isMaybePkcs7(byte[] header) {
         // The outer tag must be SEQUENCE.
-        if (header.length < 2 || header[0] != 0x30) {
+        if (header.length < 2 || header[0] != VALUE_0) {
             return false;
         }
 
@@ -114,9 +119,9 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
 
             final PushbackInputStream pbis = new PushbackInputStream(inStream, PUSHBACK_SIZE);
             try {
-                final byte[] buffer = new byte[PKCS7_MARKER.length];
+                byte[] buffer = new byte[PKCS7_MARKER.length];
 
-                final int len = pbis.read(buffer);
+                int len = pbis.read(buffer);
                 if (len < 0) {
                     /* No need to reset here. The stream was empty or EOF. */
                     throw new ParsingException("inStream is empty");
@@ -126,16 +131,34 @@ public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
                 if (buffer[0] == '-') {
                     return fromX509PemInputStream(pbis);
                 }
-
                 if (isMaybePkcs7(buffer)) {
                     List<? extends T> certs = fromPkcs7DerInputStream(pbis);
                     if (certs.size() == 0) {
                         return null;
                     }
                     return certs.get(0);
-                } else {
+                }
+                if (buffer[0] == VALUE_0) {
                     return fromX509DerInputStream(pbis);
                 }
+                int value = 0;
+                buffer = new byte[PEM_MARKER.length];
+                while (value != -1) {
+                    value = pbis.read();
+                    if (value == DASH) {
+                        pbis.unread(value);
+                        len = pbis.read(buffer);
+                        if (len < PEM_MARKER.length) {
+                            throw new ParsingException("No certificate found");
+                        }
+                        pbis.unread(buffer, 0, len);
+                        if (Arrays.equals(buffer, PEM_MARKER)) {
+                            return fromX509PemInputStream(pbis);
+                        }
+                        pbis.read();
+                    }
+                }
+                throw new ParsingException("No certificate found");
             } catch (Exception e) {
                 if (markable) {
                     try {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
index 848d6fb3..f8f87625 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
@@ -169,8 +169,10 @@ final class SSLParametersImpl implements Cloneable {
         }
 
         // initialize the list of cipher suites and protocols enabled by default
-        if (protocols == null) {
-          enabledProtocols = NativeCrypto.getDefaultProtocols().clone();
+        if (isSpake()) {
+            enabledProtocols = new String[] {NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3};
+        } else if (protocols == null) {
+            enabledProtocols = NativeCrypto.getDefaultProtocols().clone();
         } else {
             String[] filteredProtocols =
                     filterFromProtocols(protocols, Arrays.asList(Platform.isTlsV1Filtered()
@@ -350,6 +352,8 @@ final class SSLParametersImpl implements Cloneable {
     void setEnabledProtocols(String[] protocols) {
         if (protocols == null) {
             throw new IllegalArgumentException("protocols == null");
+        } else if (isSpake()) {
+            return;
         }
         String[] filteredProtocols =
                 filterFromProtocols(protocols, Arrays.asList(!Platform.isTlsV1Filtered()
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java
index baf553e6..33fb35e4 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java
@@ -60,8 +60,8 @@ public class CertificateTransparency {
         return Platform.reasonCTVerificationRequired(host);
     }
 
-    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
-            throws CertificateException {
+    private void checkCTInternal(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData,
+            String host) throws CertificateException {
         if (logStore.getState() != LogStore.State.COMPLIANT) {
             /* Fail open. For some reason, the LogStore is not usable. It could
              * be because there is no log list available or that the log list
@@ -84,4 +84,17 @@ public class CertificateTransparency {
                     + compliance.name());
         }
     }
+
+    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
+            throws CertificateException {
+        boolean dryRun = (reasonCTVerificationRequired(host)
+                == CertificateTransparencyVerificationReason.DRY_RUN);
+        try {
+            checkCTInternal(chain, ocspData, tlsData, host);
+        } catch (CertificateException e) {
+            if (!dryRun) {
+                throw e;
+            }
+        }
+    }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
index c862d048..e750ad21 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
@@ -17,6 +17,7 @@
 
 package com.android.org.conscrypt.metrics;
 
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DRY_RUN;
 import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN;
 import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN;
 import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN;
@@ -32,7 +33,8 @@ public enum CertificateTransparencyVerificationReason {
     UNKNOWN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN),
     APP_OPT_IN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN),
     DOMAIN_OPT_IN(
-            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN);
+            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN),
+    DRY_RUN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DRY_RUN);
 
     final int id;
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
deleted file mode 100644
index a38311c2..00000000
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
+++ /dev/null
@@ -1,246 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.org.conscrypt.metrics;
-
-import com.android.org.conscrypt.Internal;
-
-/**
- * Reimplement with reflection calls the logging class,
- * generated by frameworks/statsd.
- * <p>
- * In case an atom is updated, generate the new wrapper with stats-log-api-gen
- * tool as shown below and update the write methods to use ReflexiveStatsEvent
- * and ReflexiveStatsLog.
- * <p>
- * $ stats-log-api-gen \
- *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
- *   --module conscrypt \
- *   --javaPackage org.conscrypt.metrics \
- *   --javaClass ConscryptStatsLog
- * <p>
- * This class is swapped with the generated wrapper for GMSCore. For this
- * reason, the methods defined here should be identical to the generated
- * methods from the wrapper. Do not add new method here, do not change the type
- * of the parameters.
- * @hide This class is not part of the Android public SDK API
- **/
-@Internal
-public final class ConscryptStatsLog {
-    // clang-format off
-
-    // Constants for atom codes.
-
-    /**
-     * TlsHandshakeReported tls_handshake_reported<br>
-     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
-     */
-    public static final int TLS_HANDSHAKE_REPORTED = 317;
-
-    /**
-     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed<br>
-     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status, int loaded_compat_version, int min_compat_version, int major_version, int minor_version);<br>
-     */
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
-
-    /**
-     * ConscryptServiceUsed conscrypt_service_used<br>
-     * Usage: StatsLog.write(StatsLog.CONSCRYPT_SERVICE_USED, int algorithm, int cipher, int mode, int padding);<br>
-     */
-    public static final int CONSCRYPT_SERVICE_USED = 965;
-
-    /**
-     * CertificateTransparencyVerificationReported certificate_transparency_verification_reported<br>
-     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, int result, int reason, int policy_compatibility_version, int major_version, int minor_version, int num_cert_scts, int num_ocsp_scts, int num_tls_scts);<br>
-     */
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED = 989;
-
-    // Constants for enum values.
-
-    // Values for TlsHandshakeReported.protocol
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__UNKNOWN_PROTO = 0;
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__SSL_V3 = 1;
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1 = 2;
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_1 = 3;
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_2 = 4;
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_3 = 5;
-    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_PROTO_FAILED = 65535;
-
-    // Values for TlsHandshakeReported.cipher_suite
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__UNKNOWN_CIPHER_SUITE = 0;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_128_CBC_SHA = 47;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_256_CBC_SHA = 53;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_PSK_WITH_AES_128_CBC_SHA = 140;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_PSK_WITH_AES_256_CBC_SHA = 141;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_128_GCM_SHA256 = 156;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_256_GCM_SHA384 = 157;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_AES_128_GCM_SHA256 = 4865;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_AES_256_GCM_SHA384 = 4866;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_CHACHA20_POLY1305_SHA256 = 4867;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 49161;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 49162;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 49171;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 49172;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 49195;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 49196;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 49199;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 49200;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 49205;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 49206;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 52393;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52396;
-    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_CIPHER_FAILED = 65535;
-
-    // Values for TlsHandshakeReported.source
-    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN = 0;
-    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE = 1;
-    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS = 2;
-    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED = 3;
-
-    // Values for CertificateTransparencyLogListStateChanged.status
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN = 0;
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS = 1;
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND = 2;
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED = 3;
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED = 4;
-
-    // Values for CertificateTransparencyLogListStateChanged.loaded_compat_version
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__LOADED_COMPAT_VERSION__COMPAT_VERSION_UNKNOWN = 0;
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__LOADED_COMPAT_VERSION__COMPAT_VERSION_V1 = 1;
-
-    // Values for CertificateTransparencyLogListStateChanged.min_compat_version
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__MIN_COMPAT_VERSION__COMPAT_VERSION_UNKNOWN = 0;
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__MIN_COMPAT_VERSION__COMPAT_VERSION_V1 = 1;
-
-    // Values for ConscryptServiceUsed.algorithm
-    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__UNKNOWN_ALGORITHM = 0;
-    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__CIPHER = 1;
-    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__SIGNATURE = 2;
-
-    // Values for ConscryptServiceUsed.cipher
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__UNKNOWN_CIPHER = 0;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__AES = 1;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DES = 2;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DESEDE = 3;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DSA = 4;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__BLOWFISH = 5;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__CHACHA20 = 6;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__RSA = 7;
-    public static final int CONSCRYPT_SERVICE_USED__CIPHER__ARC4 = 8;
-
-    // Values for ConscryptServiceUsed.mode
-    public static final int CONSCRYPT_SERVICE_USED__MODE__NO_MODE = 0;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__CBC = 1;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__CTR = 2;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__ECB = 3;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__CFB = 4;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__CTS = 5;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__GCM = 6;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__GCM_SIV = 7;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__OFB = 8;
-    public static final int CONSCRYPT_SERVICE_USED__MODE__POLY1305 = 9;
-
-    // Values for ConscryptServiceUsed.padding
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__NO_PADDING = 0;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA512 = 1;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA384 = 2;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA256 = 3;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA224 = 4;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA1 = 5;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__PKCS1 = 6;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__PKCS5 = 7;
-    public static final int CONSCRYPT_SERVICE_USED__PADDING__ISO10126 = 8;
-
-    // Values for CertificateTransparencyVerificationReported.result
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN = 0;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS = 1;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_GENERIC_FAILURE = 2;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND = 3;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT = 4;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE = 5;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT = 6;
-
-    // Values for CertificateTransparencyVerificationReported.reason
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN = 0;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DEVICE_WIDE_ENABLED = 1;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN = 3;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN = 4;
-
-    // Values for CertificateTransparencyVerificationReported.policy_compatibility_version
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_UNKNOWN = 0;
-    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_V1 = 1;
-
-    // Write methods
-    public static void write(int code, boolean arg1, int arg2, int arg3, int arg4, int arg5, int[] arg6) {
-        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
-        builder.setAtomId(code);
-        builder.writeBoolean(arg1);
-        builder.writeInt(arg2);
-        builder.writeInt(arg3);
-        builder.writeInt(arg4);
-        builder.writeInt(arg5);
-        builder.writeIntArray(null == arg6 ? new int[0] : arg6);
-
-        builder.usePooledBuffer();
-        ReflexiveStatsLog.write(builder.build());
-    }
-
-    public static void write(int code, int arg1, int arg2, int arg3, int arg4) {
-        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
-        builder.setAtomId(code);
-        builder.writeInt(arg1);
-        builder.writeInt(arg2);
-        builder.writeInt(arg3);
-        builder.writeInt(arg4);
-
-        builder.usePooledBuffer();
-        ReflexiveStatsLog.write(builder.build());
-    }
-
-    public static void write(int code, int arg1, int arg2, int arg3, int arg4, int arg5) {
-        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
-        builder.setAtomId(code);
-        builder.writeInt(arg1);
-        builder.writeInt(arg2);
-        builder.writeInt(arg3);
-        builder.writeInt(arg4);
-        builder.writeInt(arg5);
-
-        builder.usePooledBuffer();
-        ReflexiveStatsLog.write(builder.build());
-    }
-
-    public static void write(int code, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8) {
-        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
-        builder.setAtomId(code);
-        builder.writeInt(arg1);
-        builder.writeInt(arg2);
-        builder.writeInt(arg3);
-        builder.writeInt(arg4);
-        builder.writeInt(arg5);
-        builder.writeInt(arg6);
-        builder.writeInt(arg7);
-        builder.writeInt(arg8);
-
-        builder.usePooledBuffer();
-        ReflexiveStatsLog.write(builder.build());
-    }
-
-    // clang-format on
-}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
index c26069d6..0883e94b 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
@@ -37,33 +37,11 @@ import com.android.org.conscrypt.ct.LogStore;
 import com.android.org.conscrypt.ct.PolicyCompliance;
 import com.android.org.conscrypt.ct.VerificationResult;
 
-import java.lang.Thread.UncaughtExceptionHandler;
-import java.util.concurrent.ArrayBlockingQueue;
-import java.util.concurrent.ExecutorService;
-import java.util.concurrent.Executors;
-import java.util.concurrent.ThreadFactory;
-import java.util.concurrent.ThreadPoolExecutor;
-import java.util.concurrent.TimeUnit;
-
 /**
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
 public final class StatsLogImpl implements StatsLog {
-    private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
-        @Override
-        public Thread newThread(Runnable r) {
-            Thread thread = new Thread(r, "ConscryptStatsLog");
-            thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
-                @Override
-                public void uncaughtException(Thread t, Throwable e) {
-                    // Ignore
-                }
-            });
-            return thread;
-        }
-    });
-
     private static final StatsLog INSTANCE = new StatsLogImpl();
     private StatsLogImpl() {}
     public static StatsLog getInstance() {
@@ -139,38 +117,41 @@ public final class StatsLogImpl implements StatsLog {
         }
     }
 
+    private static final boolean sdkVersionBiggerThan32;
+
+    static {
+        sdkVersionBiggerThan32 = Platform.isSdkGreater(32);
+    }
+
+    @SuppressWarnings("NewApi")
     private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
             int source, int[] uids) {
-        e.execute(new Runnable() {
-            @Override
-            public void run() {
-                ConscryptStatsLog.write(
-                        atomId, success, protocol, cipherSuite, duration, source, uids);
-            }
-        });
+        if (!sdkVersionBiggerThan32) {
+            final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+            builder.writeInt(atomId);
+            builder.writeBoolean(success);
+            builder.writeInt(protocol);
+            builder.writeInt(cipherSuite);
+            builder.writeInt(duration);
+            builder.writeInt(source);
+
+            builder.usePooledBuffer();
+            ReflexiveStatsLog.write(builder.build());
+        } else {
+            ConscryptStatsLog.write(atomId, success, protocol, cipherSuite, duration, source, uids);
+        }
     }
 
     private void write(int atomId, int status, int loadedCompatVersion,
             int minCompatVersionAvailable, int majorVersion, int minorVersion) {
-        e.execute(new Runnable() {
-            @Override
-            public void run() {
-                ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
-                        minCompatVersionAvailable, majorVersion, minorVersion);
-            }
-        });
+        ConscryptStatsLog.write(atomId, status, loadedCompatVersion, minCompatVersionAvailable,
+                majorVersion, minorVersion);
     }
 
     private void write(int atomId, int verificationResult, int verificationReason,
             int policyCompatVersion, int majorVersion, int minorVersion, int numEmbeddedScts,
             int numOcspScts, int numTlsScts) {
-        e.execute(new Runnable() {
-            @Override
-            public void run() {
-                ConscryptStatsLog.write(atomId, verificationResult, verificationReason,
-                        policyCompatVersion, majorVersion, minorVersion, numEmbeddedScts,
-                        numOcspScts, numTlsScts);
-            }
-        });
+        ConscryptStatsLog.write(atomId, verificationResult, verificationReason, policyCompatVersion,
+                majorVersion, minorVersion, numEmbeddedScts, numOcspScts, numTlsScts);
     }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/ApplicationConfig.java b/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/ApplicationConfig.java
new file mode 100644
index 00000000..4ac002da
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/ApplicationConfig.java
@@ -0,0 +1,126 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2015 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.org.conscrypt.securityconfig;
+
+import javax.net.ssl.X509TrustManager;
+
+/**
+ * An application's network security configuration.
+ *
+ * <p>{@link #getConfigForHostname(String)} provides a means to obtain network security
+ * configuration to be used for communicating with a specific hostname.
+ * @hide This class is not part of the Android public SDK API
+ */
+public final class ApplicationConfig {
+    private static ApplicationConfig sInstance;
+    private static Object sLock = new Object();
+
+    private X509TrustManager mTrustManager;
+
+    private boolean mInitialized;
+    private final Object mLock = new Object();
+
+    /** Constructs a new {@code ApplicationConfig} instance. */
+    public ApplicationConfig() {
+        mInitialized = false;
+    }
+
+    public boolean hasPerDomainConfigs() {
+        ensureInitialized();
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /**
+     * Returns the {@link X509TrustManager} that implements the checking of trust anchors and
+     * certificate pinning based on this configuration.
+     */
+    public X509TrustManager getTrustManager() {
+        ensureInitialized();
+        return mTrustManager;
+    }
+
+    /**
+     * Returns {@code true} if cleartext traffic is permitted for this application, which is the
+     * case only if all configurations permit cleartext traffic. For finer-grained policy use {@link
+     * #isCleartextTrafficPermitted(String)}.
+     */
+    public boolean isCleartextTrafficPermitted() {
+        ensureInitialized();
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /**
+     * Returns {@code true} if cleartext traffic is permitted for this application when connecting
+     * to {@code hostname}.
+     */
+    public boolean isCleartextTrafficPermitted(String hostname) {
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /**
+     * Returns {@code true} if Certificate Transparency information is required to be verified by
+     * the client in TLS connections to {@code hostname}.
+     *
+     * <p>See RFC6962 section 3.3 for more details.
+     *
+     * @param hostname hostname to check whether certificate transparency verification is required
+     * @return {@code true} if certificate transparency verification is required and {@code false}
+     *     otherwise
+     */
+    public boolean isCertificateTransparencyVerificationRequired(String hostname) {
+        // TODO(b/397646538): implement
+        return false;
+    }
+
+    /** Handle an update to the system or user certificate stores. */
+    public void handleTrustStorageUpdate() {}
+
+    private void ensureInitialized() {
+        synchronized (mLock) {
+            if (mInitialized) {
+                return;
+            }
+            mInitialized = true;
+        }
+    }
+
+    /**
+     * Sets the default {@link ApplicationConfig} instance.
+     *
+     * @param config the {@link ApplicationConfig} to set as the default instance.
+     */
+    public static void setDefaultInstance(ApplicationConfig config) {
+        synchronized (sLock) {
+            sInstance = config;
+        }
+    }
+
+    /**
+     * Gets the default {@link ApplicationConfig} instance.
+     *
+     * @return the default {@link ApplicationConfig} instance.
+     */
+    public static ApplicationConfig getDefaultInstance() {
+        synchronized (sLock) {
+            return sInstance;
+        }
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/NetworkSecurityConfigProvider.java b/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/NetworkSecurityConfigProvider.java
new file mode 100644
index 00000000..a523abb9
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/NetworkSecurityConfigProvider.java
@@ -0,0 +1,89 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2015 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.org.conscrypt.securityconfig;
+
+import java.security.Provider;
+import java.security.Security;
+import java.util.logging.Logger;
+
+/**
+ * Security Provider backed by the app's Network Security Config.
+ * @hide This class is not part of the Android public SDK API
+ */
+public final class NetworkSecurityConfigProvider extends Provider {
+    private static final String LOG_TAG = "nsconfig";
+    private static final Logger logger = Logger.getLogger(LOG_TAG);
+    private static final String PREFIX =
+            NetworkSecurityConfigProvider.class.getPackage().getName() + ".";
+
+    public NetworkSecurityConfigProvider() {
+        // TODO: More clever name than this
+        super("AndroidNSSP", 1.0, "Android Network Security Policy Provider");
+        put("TrustManagerFactory.PKIX", PREFIX + "RootTrustManagerFactorySpi");
+        put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
+    }
+
+    /**
+     * Installs the NetworkSecurityConfigProvider as the highest priority provider.
+     *
+     * <p>If the provider cannot be installed with highest priority, the installation will still
+     * complete but this method will throw an exception.
+     */
+    public static void install() {
+        ApplicationConfig config = new ApplicationConfig();
+        ApplicationConfig.setDefaultInstance(config);
+        int pos = Security.insertProviderAt(new NetworkSecurityConfigProvider(), 1);
+        if (pos != 1) {
+            // TODO(b/404518910): remove the provider if the installation fails.
+            throw new RuntimeException("Failed to install provider as highest priority provider."
+                    + " Provider was installed at position " + pos);
+        }
+    }
+
+    /**
+     * The network security config needs to be aware of multiple applications in the same process to
+     * handle discrepancies.
+     *
+     * <p>For such a shared process, conflicting values of usesCleartextTraffic are resolved as
+     * follows:
+     *
+     * <p>1. Throws a RuntimeException if the shared process with conflicting usesCleartextTraffic
+     * values have per domain rules, otherwise
+     *
+     * <p>2. Sets the default instance to the least strict config.
+     *
+     * @param processName the name of the process hosting mutiple applications.
+     */
+    public static void handleNewApplication(String processName) {
+        ApplicationConfig config = new ApplicationConfig();
+        ApplicationConfig defaultConfig = ApplicationConfig.getDefaultInstance();
+        if (defaultConfig != null) {
+            if (defaultConfig.isCleartextTrafficPermitted()
+                    != config.isCleartextTrafficPermitted()) {
+                logger.warning((processName == null ? "Unknown process" : processName)
+                        + ": New config does not match the previously set config.");
+
+                if (defaultConfig.hasPerDomainConfigs() || config.hasPerDomainConfigs()) {
+                    throw new RuntimeException("Found multiple conflicting per-domain rules");
+                }
+                config = defaultConfig.isCleartextTrafficPermitted() ? defaultConfig : config;
+            }
+        }
+        ApplicationConfig.setDefaultInstance(config);
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/UserCertificateSource.java b/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/UserCertificateSource.java
new file mode 100644
index 00000000..33a6cd46
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/securityconfig/UserCertificateSource.java
@@ -0,0 +1,47 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2015 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.org.conscrypt.securityconfig;
+
+import java.security.cert.X509Certificate;
+
+/**
+ * {@link CertificateSource} based on the user-installed trusted CA store.
+ * @hide This class is not part of the Android public SDK API
+ */
+public final class UserCertificateSource {
+    private static class NoPreloadHolder {
+        private static final UserCertificateSource INSTANCE = new UserCertificateSource();
+    }
+
+    /**
+     * Returns the singleton instance of {@link UserCertificateSource}.
+     *
+     * @return the singleton instance of {@link UserCertificateSource}.
+     */
+    public static UserCertificateSource getInstance() {
+        return NoPreloadHolder.INSTANCE;
+    }
+
+    // TODO(sandrom): move to DirectoryCertificateSource super class
+    public X509Certificate findBySubjectAndPublicKey(final X509Certificate cert) {
+        return null;
+    }
+
+    // TODO(sandrom): move to DirectoryCertificateSource super class
+    public void handleTrustStorageUpdate() {}
+}
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java
index fecc9b4c..0749e36f 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java
@@ -27,6 +27,7 @@ import java.io.IOException;
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
+import java.util.concurrent.atomic.AtomicInteger;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -52,20 +53,24 @@ public class NativeCryptoArgTest {
      * so we can get past the first check and test the second one.
      */
     private static final long NOT_NULL = 4L;
+    private static final int EXPECTED_TEST_CASES = 6;
+    /* The tests check how many methods get invoked. By the time all tests are
+     * run, a minimum number of methods should have been tested. The choice of
+     * number is based on the historic value.
+     * TODO: Find a more definite number to use here.*/
+    private static final int MIN_EXPECTED_TESTED_METHODS = 190;
     private static final String CONSCRYPT_PACKAGE = NativeCryptoArgTest.class.getCanonicalName()
             .substring(0, NativeCryptoArgTest.class.getCanonicalName().lastIndexOf('.') + 1);
+    /* Count how many test cases are run. Once all the expected cases are run,
+     * we can check that the minimum number of methods were tested. */
+    private static final AtomicInteger testCaseCount = new AtomicInteger(EXPECTED_TEST_CASES);
     private static final Set<String> testedMethods = new HashSet<>();
     private final Map<String, Class<?>> classCache = new HashMap<>();
     private final Map<String, Method> methodMap = buildMethodMap();
 
-    @AfterClass
-    public static void after() {
-        // TODO(prb): Temporary hacky check - remove
-        assertTrue(testedMethods.size() >= 190);
-    }
-
     @Test
     public void ecMethods() throws Throwable {
+        markTestRun();
         String[] illegalArgMethods = new String[] {
                 "EC_GROUP_new_arbitrary"
         };
@@ -89,10 +94,12 @@ public class NativeCryptoArgTest {
 
         filter = MethodFilter.nameFilter("EC_ methods (IOException)", ioExMethods);
         testMethods(filter, IOException.class);
+        checkMethodsTested();
     }
 
     @Test
     public void macMethods() throws Throwable {
+        markTestRun();
         // All of the non-void HMAC and CMAC methods throw NPE when passed a null pointer
         MethodFilter filter = MethodFilter.newBuilder("HMAC methods")
                 .hasPrefix("HMAC_")
@@ -107,10 +114,12 @@ public class NativeCryptoArgTest {
                 .expectSize(5)
                 .build();
         testMethods(filter, NullPointerException.class);
+        checkMethodsTested();
     }
 
     @Test
     public void sslMethods() throws Throwable {
+        markTestRun();
         // These methods don't throw on a null first arg as they can get called before the
         // connection is fully initialised. However if the first arg is non-NULL, any subsequent
         // null args should throw NPE.
@@ -150,10 +159,12 @@ public class NativeCryptoArgTest {
         expectNPE("SSL_shutdown", NOT_NULL, null, new FileDescriptor(), null);
         expectNPE("ENGINE_SSL_shutdown", NOT_NULL, null, null);
         expectVoid("SSL_set_session", NOT_NULL, null, NULL);
+        checkMethodsTested();
     }
 
     @Test
     public void evpMethods() throws Throwable {
+        markTestRun();
         String[] illegalArgMethods = new String[] {"EVP_AEAD_CTX_open_buf", "EVP_AEAD_CTX_seal_buf",
                 "EVP_HPKE_CTX_setup_base_mode_recipient", "EVP_HPKE_CTX_setup_base_mode_sender",
                 "EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing", "EVP_PKEY_new_RSA"};
@@ -181,10 +192,12 @@ public class NativeCryptoArgTest {
 
         filter = MethodFilter.nameFilter("EVP methods (non-throwing)", nonThrowingMethods);
         testMethods(filter, null);
+        checkMethodsTested();
     }
 
     @Test
     public void x509Methods() throws Throwable {
+        markTestRun();
         // A number of X509 methods have a native pointer as arg 0 and an
         // OpenSSLX509Certificate or OpenSSLX509CRL as arg 1.
         MethodFilter filter = MethodFilter.newBuilder("X509 methods")
@@ -220,10 +233,12 @@ public class NativeCryptoArgTest {
         expectNPE("X509_print_ex", NULL, NULL, null, NULL, NULL);
         expectNPE("X509_print_ex", NOT_NULL, NULL, null, NULL, NULL);
         expectNPE("X509_print_ex", NULL, NOT_NULL, null, NULL, NULL);
+        checkMethodsTested();
     }
 
     @Test
     public void spake2Methods() throws Throwable {
+        markTestRun();
         expectNPE("SSL_CTX_set_spake_credential",
                 null, new byte[0], new byte[0], new byte[0], false, 1, NOT_NULL, null);
         expectNPE("SSL_CTX_set_spake_credential",
@@ -232,6 +247,7 @@ public class NativeCryptoArgTest {
                 new byte[0], new byte[0], null, new byte[0], false, 1, NOT_NULL, null);
         expectNPE("SSL_CTX_set_spake_credential",
                 new byte[0], new byte[0], new byte[0], null, false, 1, NOT_NULL, null);
+        checkMethodsTested();
     }
 
     private void testMethods(MethodFilter filter, Class<? extends Throwable> exceptionClass)
@@ -273,6 +289,22 @@ public class NativeCryptoArgTest {
         return result;
     }
 
+    private static void markTestRun() {
+        int count = testCaseCount.get();
+        while (count > 0 && !testCaseCount.compareAndSet(count, count - 1)) {
+            count = testCaseCount.get();
+        }
+    }
+
+    private static void checkMethodsTested() {
+        if (testCaseCount.get() == 0) {
+            // Since we ran enough test cases, we should now have a minimum
+            // number of methods tested. Validate that these methods were indeed
+            // called.
+            assertTrue(testedMethods.size() >= MIN_EXPECTED_TESTED_METHODS);
+        }
+    }
+
     private void expectVoid(String methodName, Object... args) throws Throwable {
         invokeAndExpect(null, methodName, args);
     }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
index f23ff38a..c40ae6bb 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
@@ -1226,7 +1226,8 @@ public class SSLSocketVersionCompatibilityTest {
         }
     }
 
-    @Test(expected = SocketTimeoutException.class)
+    @Test
+    @Ignore("Broken test: See b/408399060")
     public void test_SSLSocket_setSoWriteTimeout() throws Exception {
         // Only run this test on Linux since it relies on non-posix methods.
         assumeTrue("Test only runs on Linux. Current OS: " + osName(), isLinux());
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/securityconfig/XmlConfigTests.java b/repackaged/common/src/test/java/com/android/org/conscrypt/securityconfig/XmlConfigTests.java
new file mode 100644
index 00000000..4319fa43
--- /dev/null
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/securityconfig/XmlConfigTests.java
@@ -0,0 +1,38 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.org.conscrypt.securityconfig;
+
+import static org.junit.Assert.assertFalse;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class XmlConfigTests {
+    @Test
+    public void testEmptyConfigFile() {
+        ApplicationConfig appConfig = new ApplicationConfig();
+        // Check defaults.
+        assertFalse(appConfig.hasPerDomainConfigs());
+        assertFalse(appConfig.isCleartextTrafficPermitted());
+    }
+}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java
index 6e4c1c3b..771e444c 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java
@@ -19,6 +19,8 @@ package com.android.org.conscrypt;
 
 import static java.nio.charset.StandardCharsets.UTF_8;
 
+import com.android.org.conscrypt.flags.Flags;
+
 import java.io.ByteArrayOutputStream;
 import java.io.Closeable;
 import java.io.FileNotFoundException;
@@ -45,6 +47,8 @@ import java.util.logging.Logger;
 @Internal
 public final class CertBlocklistImpl implements CertBlocklist {
     private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());
+    private static final String DIGEST_SHA1 = "SHA-1";
+    private static final String DIGEST_SHA256 = "SHA-256";
 
     private final Set<BigInteger> serialBlocklist;
     private final Set<ByteArray> sha1PubkeyBlocklist;
@@ -86,9 +90,9 @@ public final class CertBlocklistImpl implements CertBlocklist {
         String defaultPubkeySha256BlocklistPath = blocklistRoot + "pubkey_sha256_blocklist.txt";
 
         Set<ByteArray> sha1PubkeyBlocklist =
-                readPublicKeyBlockList(defaultPubkeyBlocklistPath, "SHA-1");
+                readPublicKeyBlockList(defaultPubkeyBlocklistPath, DIGEST_SHA1);
         Set<ByteArray> sha256PubkeyBlocklist =
-                readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, "SHA-256");
+                readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, DIGEST_SHA256);
         Set<BigInteger> serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
         return new CertBlocklistImpl(serialBlocklist, sha1PubkeyBlocklist, sha256PubkeyBlocklist);
     }
@@ -181,58 +185,119 @@ public final class CertBlocklistImpl implements CertBlocklist {
         return Collections.unmodifiableSet(bl);
     }
 
-    static final byte[][] SHA1_BUILTINS = {
+    // clang-format off
+    static final byte[] SHA1_BUILTIN = {
             // Blocklist test cert for CTS. The cert and key can be found in
             // src/test/resources/blocklist_test_ca.pem and
             // src/test/resources/blocklist_test_ca_key.pem.
-            "bae78e6bed65a2bf60ddedde7fd91e825865e93d".getBytes(UTF_8),
-            // From
-            // http://src.chromium.org/viewvc/chrome/branches/782/src/net/base/x509_certificate.cc?r1=98750&r2=98749&pathrev=98750
-            // C=NL, O=DigiNotar, CN=DigiNotar Root CA/emailAddress=info@diginotar.nl
-            "410f36363258f30b347d12ce4863e433437806a8".getBytes(UTF_8),
-            // Subject: CN=DigiNotar Cyber CA
-            // Issuer: CN=GTE CyberTrust Global Root
-            "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37".getBytes(UTF_8),
-            // Subject: CN=DigiNotar Services 1024 CA
-            // Issuer: CN=Entrust.net
-            "e23b8d105f87710a68d9248050ebefc627be4ca6".getBytes(UTF_8),
-            // Subject: CN=DigiNotar PKIoverheid CA Organisatie - G2
-            // Issuer: CN=Staat der Nederlanden Organisatie CA - G2
-            "7b2e16bc39bcd72b456e9f055d1de615b74945db".getBytes(UTF_8),
-            // Subject: CN=DigiNotar PKIoverheid CA Overheid en Bedrijven
-            // Issuer: CN=Staat der Nederlanden Overheid CA
-            "e8f91200c65cee16e039b9f883841661635f81c5".getBytes(UTF_8),
-            // From http://src.chromium.org/viewvc/chrome?view=rev&revision=108479
-            // Subject: O=Digicert Sdn. Bhd.
-            // Issuer: CN=GTE CyberTrust Global Root
-            "0129bcd5b448ae8d2496d1c3e19723919088e152".getBytes(UTF_8),
-            // Subject: CN=e-islem.kktcmerkezbankasi.org/emailAddress=ileti@kktcmerkezbankasi.org
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "5f3ab33d55007054bc5e3e5553cd8d8465d77c61".getBytes(UTF_8),
-            // Subject: CN=*.EGO.GOV.TR 93
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "783333c9687df63377efceddd82efa9101913e8e".getBytes(UTF_8),
-            // Subject: Subject: C=FR, O=DG Tr\xC3\xA9sor, CN=AC DG Tr\xC3\xA9sor SSL
-            // Issuer: C=FR, O=DGTPE, CN=AC DGTPE Signature Authentification
-            "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf".getBytes(UTF_8),
+            // bae78e6bed65a2bf60ddedde7fd91e825865e93d
+          (byte) 0xba, (byte) 0xe7, (byte) 0x8e, (byte) 0x6b, (byte) 0xed,
+          (byte) 0x65, (byte) 0xa2, (byte) 0xbf, (byte) 0x60, (byte) 0xdd,
+          (byte) 0xed, (byte) 0xde, (byte) 0x7f, (byte) 0xd9, (byte) 0x1e,
+          (byte) 0x82, (byte) 0x58, (byte) 0x65, (byte) 0xe9, (byte) 0x3d,
+    };
+
+    static final byte[][] SHA1_DEPRECATED_BUILTINS = {
+        // "410f36363258f30b347d12ce4863e433437806a8"
+        {
+            (byte) 0x41, (byte) 0x0f, (byte) 0x36, (byte) 0x36, (byte) 0x32,
+            (byte) 0x58, (byte) 0xf3, (byte) 0x0b, (byte) 0x34, (byte) 0x7d,
+            (byte) 0x12, (byte) 0xce, (byte) 0x48, (byte) 0x63, (byte) 0xe4,
+            (byte) 0x33, (byte) 0x43, (byte) 0x78, (byte) 0x06, (byte) 0xa8,
+        },
+        // "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37"
+        {
+            (byte) 0xba, (byte) 0x3e, (byte) 0x7b, (byte) 0xd3, (byte) 0x8c,
+            (byte) 0xd7, (byte) 0xe1, (byte) 0xe6, (byte) 0xb9, (byte) 0xcd,
+            (byte) 0x4c, (byte) 0x21, (byte) 0x99, (byte) 0x62, (byte) 0xe5,
+            (byte) 0x9d, (byte) 0x7a, (byte) 0x2f, (byte) 0x4e, (byte) 0x37,
+        },
+        // "e23b8d105f87710a68d9248050ebefc627be4ca6"
+        {
+            (byte) 0xe2, (byte) 0x3b, (byte) 0x8d, (byte) 0x10, (byte) 0x5f,
+            (byte) 0x87, (byte) 0x71, (byte) 0x0a, (byte) 0x68, (byte) 0xd9,
+            (byte) 0x24, (byte) 0x80, (byte) 0x50, (byte) 0xeb, (byte) 0xef,
+            (byte) 0xc6, (byte) 0x27, (byte) 0xbe, (byte) 0x4c, (byte) 0xa6,
+        },
+        // "7b2e16bc39bcd72b456e9f055d1de615b74945db"
+        {
+            (byte) 0x7b, (byte) 0x2e, (byte) 0x16, (byte) 0xbc, (byte) 0x39,
+            (byte) 0xbc, (byte) 0xd7, (byte) 0x2b, (byte) 0x45, (byte) 0x6e,
+            (byte) 0x9f, (byte) 0x05, (byte) 0x5d, (byte) 0x1d, (byte) 0xe6,
+            (byte) 0x15, (byte) 0xb7, (byte) 0x49, (byte) 0x45, (byte) 0xdb,
+        },
+        // "e8f91200c65cee16e039b9f883841661635f81c5"
+        {
+            (byte) 0xe8, (byte) 0xf9, (byte) 0x12, (byte) 0x00, (byte) 0xc6,
+            (byte) 0x5c, (byte) 0xee, (byte) 0x16, (byte) 0xe0, (byte) 0x39,
+            (byte) 0xb9, (byte) 0xf8, (byte) 0x83, (byte) 0x84, (byte) 0x16,
+            (byte) 0x61, (byte) 0x63, (byte) 0x5f, (byte) 0x81, (byte) 0xc5,
+        },
+        // "0129bcd5b448ae8d2496d1c3e19723919088e152"
+        {
+            (byte) 0x01, (byte) 0x29, (byte) 0xbc, (byte) 0xd5, (byte) 0xb4,
+            (byte) 0x48, (byte) 0xae, (byte) 0x8d, (byte) 0x24, (byte) 0x96,
+            (byte) 0xd1, (byte) 0xc3, (byte) 0xe1, (byte) 0x97, (byte) 0x23,
+            (byte) 0x91, (byte) 0x90, (byte) 0x88, (byte) 0xe1, (byte) 0x52,
+        },
+        // "5f3ab33d55007054bc5e3e5553cd8d8465d77c61"
+        {
+            (byte) 0x5f, (byte) 0x3a, (byte) 0xb3, (byte) 0x3d, (byte) 0x55,
+            (byte) 0x00, (byte) 0x70, (byte) 0x54, (byte) 0xbc, (byte) 0x5e,
+            (byte) 0x3e, (byte) 0x55, (byte) 0x53, (byte) 0xcd, (byte) 0x8d,
+            (byte) 0x84, (byte) 0x65, (byte) 0xd7, (byte) 0x7c, (byte) 0x61,
+        },
+        // "783333c9687df63377efceddd82efa9101913e8e"
+        {
+            (byte) 0x78, (byte) 0x33, (byte) 0x33, (byte) 0xc9, (byte) 0x68,
+            (byte) 0x7d, (byte) 0xf6, (byte) 0x33, (byte) 0x77, (byte) 0xef,
+            (byte) 0xce, (byte) 0xdd, (byte) 0xd8, (byte) 0x2e, (byte) 0xfa,
+            (byte) 0x91, (byte) 0x01, (byte) 0x91, (byte) 0x3e, (byte) 0x8e,
+        },
+        // "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf"
+        {
+            (byte) 0x3e, (byte) 0xcf, (byte) 0x4b, (byte) 0xbb, (byte) 0xe4,
+            (byte) 0x60, (byte) 0x96, (byte) 0xd5, (byte) 0x14, (byte) 0xbb,
+            (byte) 0x53, (byte) 0x9b, (byte) 0xb9, (byte) 0x13, (byte) 0xd7,
+            (byte) 0x7a, (byte) 0xa4, (byte) 0xef, (byte) 0x31, (byte) 0xbf,
+        },
     };
 
-    static final byte[][] SHA256_BUILTINS = {
+    static final byte[] SHA256_BUILTIN = {
             // Blocklist test cert for CTS. The cert and key can be found in
             // src/test/resources/blocklist_test_ca2.pem and
             // src/test/resources/blocklist_test_ca2_key.pem.
-            "809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd".getBytes(UTF_8),
+            // 809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd
+          (byte) 0x80, (byte) 0x99, (byte) 0x64, (byte) 0xb1, (byte) 0x5e,
+          (byte) 0x9b, (byte) 0xd3, (byte) 0x12, (byte) 0x99, (byte) 0x3d,
+          (byte) 0x99, (byte) 0x84, (byte) 0x04, (byte) 0x55, (byte) 0x51,
+          (byte) 0xf5, (byte) 0x03, (byte) 0xf2, (byte) 0xcf, (byte) 0x8e,
+          (byte) 0x68, (byte) 0xf3, (byte) 0x91, (byte) 0x88, (byte) 0x92,
+          (byte) 0x1b, (byte) 0xa3, (byte) 0x0f, (byte) 0xe6, (byte) 0x23,
+          (byte) 0xf9, (byte) 0xfd,
     };
+    // clang-format on
 
     private static Set<ByteArray> readPublicKeyBlockList(String path, String hashType) {
-        Set<ByteArray> bl;
+        Set<ByteArray> bl = new HashSet<ByteArray>();
 
         switch (hashType) {
-            case "SHA-1":
-                bl = new HashSet<ByteArray>(toByteArrays(SHA1_BUILTINS));
+            case DIGEST_SHA1:
+                bl.add(new ByteArray(SHA1_BUILTIN));
+                if (!Flags.useChromiumCertBlocklist()) {
+                    for (byte[] staticPubKey : SHA1_DEPRECATED_BUILTINS) {
+                        bl.add(new ByteArray(staticPubKey));
+                    }
+                }
                 break;
-            case "SHA-256":
-                bl = new HashSet<ByteArray>(toByteArrays(SHA256_BUILTINS));
+            case DIGEST_SHA256:
+                bl.add(new ByteArray(SHA256_BUILTIN));
+                if (Flags.useChromiumCertBlocklist()) {
+                    // Blocklist statically included in Conscrypt. See constants/.
+                    for (byte[] staticPubKey : StaticBlocklist.PUBLIC_KEYS) {
+                        bl.add(new ByteArray(staticPubKey));
+                    }
+                }
                 break;
             default:
                 throw new RuntimeException(
@@ -246,17 +311,18 @@ public final class CertBlocklistImpl implements CertBlocklist {
             logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
             return bl;
         }
+
         // The hashes are encoded with hexadecimal values. There should be
         // twice as many characters as the digest length in bytes.
         int hashLength = md.getDigestLength() * 2;
 
-        // attempt to augment it with values taken from gservices
+        // Attempt to augment it with values taken from /data/misc/keychain.
         String pubkeyBlocklist = readBlocklist(path);
         if (!pubkeyBlocklist.equals("")) {
             for (String value : pubkeyBlocklist.split(",", -1)) {
                 value = value.trim();
                 if (isPubkeyHash(value, hashLength)) {
-                    bl.add(new ByteArray(value.getBytes(UTF_8)));
+                    bl.add(new ByteArray(Hex.decodeHex(value)));
                 } else {
                     logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                 }
@@ -275,7 +341,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
             logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
             return false;
         }
-        ByteArray out = new ByteArray(toHex(md.digest(encodedPublicKey)));
+        ByteArray out = new ByteArray(md.digest(encodedPublicKey));
         if (blocklist.contains(out)) {
             return true;
         }
@@ -294,13 +360,13 @@ public final class CertBlocklistImpl implements CertBlocklist {
             return cachedResult.booleanValue();
         }
         if (!sha1PubkeyBlocklist.isEmpty()) {
-            if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, "SHA-1")) {
+            if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, DIGEST_SHA1)) {
                 cache.put(cacheKey, true);
                 return true;
             }
         }
         if (!sha256PubkeyBlocklist.isEmpty()) {
-            if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, "SHA-256")) {
+            if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, DIGEST_SHA256)) {
                 cache.put(cacheKey, true);
                 return true;
             }
@@ -309,31 +375,8 @@ public final class CertBlocklistImpl implements CertBlocklist {
         return false;
     }
 
-    private static final byte[] HEX_TABLE = { (byte) '0', (byte) '1', (byte) '2', (byte) '3',
-        (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'a',
-        (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'};
-
-    private static byte[] toHex(byte[] in) {
-        byte[] out = new byte[in.length * 2];
-        int outIndex = 0;
-        for (int i = 0; i < in.length; i++) {
-            int value = in[i] & 0xff;
-            out[outIndex++] = HEX_TABLE[value >> 4];
-            out[outIndex++] = HEX_TABLE[value & 0xf];
-        }
-        return out;
-    }
-
     @Override
     public boolean isSerialNumberBlockListed(BigInteger serial) {
         return serialBlocklist.contains(serial);
     }
-
-    private static List<ByteArray> toByteArrays(byte[]... allBytes) {
-        List<ByteArray> byteArrays = new ArrayList<>(allBytes.length + 1);
-        for (byte[] bytes : allBytes) {
-            byteArrays.add(new ByteArray(bytes));
-        }
-        return byteArrays;
-    }
 }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java
index fd5b1a6b..b72b0b13 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java
@@ -22,23 +22,12 @@ package com.android.org.conscrypt;
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
-// public for testing by TrustedCertificateStoreTest
 public final class Hex {
     private Hex() {}
 
     private final static char[] DIGITS = {
             '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
 
-    public static String bytesToHexString(byte[] bytes) {
-        char[] buf = new char[bytes.length * 2];
-        int c = 0;
-        for (byte b : bytes) {
-            buf[c++] = DIGITS[(b >> 4) & 0xf];
-            buf[c++] = DIGITS[b & 0xf];
-        }
-        return new String(buf);
-    }
-
     public static String intToHexString(int i, int minWidth) {
         int bufLen = 8;  // Max number of hex digits in an int
         char[] buf = new char[bufLen];
@@ -50,4 +39,33 @@ public final class Hex {
 
         return new String(buf, cursor, bufLen - cursor);
     }
+
+    public static byte[] decodeHex(String encoded) throws IllegalArgumentException {
+        if ((encoded.length() % 2) != 0) {
+            throw new IllegalArgumentException("Invalid input length: " + encoded.length());
+        }
+
+        int resultLengthBytes = encoded.length() / 2;
+        byte[] result = new byte[resultLengthBytes];
+
+        int resultOffset = 0;
+        int i = 0;
+        for (int len = encoded.length(); i < len; i += 2) {
+            result[resultOffset++] =
+                    (byte) ((toDigit(encoded.charAt(i)) << 4) | toDigit(encoded.charAt(i + 1)));
+        }
+
+        return result;
+    }
+
+    private static int toDigit(char pseudoCodePoint) throws IllegalArgumentException {
+        if ('0' <= pseudoCodePoint && pseudoCodePoint <= '9') {
+            return pseudoCodePoint - '0';
+        } else if ('a' <= pseudoCodePoint && pseudoCodePoint <= 'f') {
+            return 10 + (pseudoCodePoint - 'a');
+        } else if ('A' <= pseudoCodePoint && pseudoCodePoint <= 'F') {
+            return 10 + (pseudoCodePoint - 'A');
+        }
+        throw new IllegalArgumentException("Illegal char: " + pseudoCodePoint);
+    }
 }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
index 1b7d605f..f09d2230 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
@@ -490,8 +490,13 @@ final public class Platform {
 
     public static boolean isCTVerificationRequired(String hostname) {
         if (Flags.certificateTransparencyPlatform()) {
-            return NetworkSecurityPolicy.getInstance()
-                    .isCertificateTransparencyVerificationRequired(hostname);
+            if (NetworkSecurityPolicy.getInstance().isCertificateTransparencyVerificationRequired(
+                        hostname)) {
+                return true;
+            }
+            if (com.android.org.conscrypt.net.flags.Flags.certificateTransparencyDryRun()) {
+                return true;
+            }
         }
         return false;
     }
@@ -503,6 +508,8 @@ final public class Platform {
         } else if (NetworkSecurityPolicy.getInstance()
                            .isCertificateTransparencyVerificationRequired(hostname)) {
             return CertificateTransparencyVerificationReason.DOMAIN_OPT_IN;
+        } else if (com.android.org.conscrypt.net.flags.Flags.certificateTransparencyDryRun()) {
+            return CertificateTransparencyVerificationReason.DRY_RUN;
         }
         return CertificateTransparencyVerificationReason.UNKNOWN;
     }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
index 4bb1f8e7..75401365 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
@@ -58,8 +58,7 @@ public class LogStoreImpl implements LogStore {
     private static final int COMPAT_VERSION = 2;
     private static final Path logListPrefix;
     private static final Path logListSuffix;
-    private static final long LOG_LIST_CHECK_INTERVAL_IN_NS =
-            10L * 60 * 1_000 * 1_000_000; // 10 minutes
+    private static final long LOG_LIST_CHECK_INTERVAL_IN_MS = 10L * 60 * 1_000; // 10 minutes
 
     static {
         String androidData = System.getenv("ANDROID_DATA");
@@ -84,7 +83,7 @@ public class LogStoreImpl implements LogStore {
     static class SystemTimeSupplier implements Supplier<Long> {
         @Override
         public Long get() {
-            return System.nanoTime();
+            return System.currentTimeMillis();
         }
     }
 
@@ -188,7 +187,8 @@ public class LogStoreImpl implements LogStore {
 
     private synchronized void resetLogListIfRequired() {
         long now = clock.get();
-        if (this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_NS > now) {
+        if (now >= this.logListLastChecked
+                && now < this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_MS) {
             return;
         }
         this.logListLastChecked = now;
@@ -259,7 +259,7 @@ public class LogStoreImpl implements LogStore {
         return State.LOADED;
     }
 
-    private static void addLogsToMap(JSONArray logs, String operatorName, int logType,
+    private void addLogsToMap(JSONArray logs, String operatorName, int logType,
             Map<ByteArray, LogInfo> logsMap) throws JSONException {
         for (int j = 0; j < logs.length(); j++) {
             JSONObject log = logs.getJSONObject(j);
@@ -276,12 +276,21 @@ public class LogStoreImpl implements LogStore {
             }
             LogInfo logInfo = builder.build();
 
+            String logIdFromList = log.getString("log_id");
             // The logId computed using the public key should match the log_id field.
-            byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
+            byte[] logId = Base64.getDecoder().decode(logIdFromList);
             if (!Arrays.equals(logInfo.getID(), logId)) {
                 throw new IllegalArgumentException("logId does not match publicKey");
             }
 
+            //  Verify that the log is in a known state now. This might fail if
+            //  there is an issue with the device's clock which can cause false
+            //  positives when validating SCTs.
+            if (logInfo.getStateAt(clock.get()) == LogInfo.STATE_UNKNOWN) {
+                throw new IllegalArgumentException("Log current state is "
+                        + "unknown, logId: " + logIdFromList);
+            }
+
             logsMap.put(new ByteArray(logId), logInfo);
         }
     }
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java
index b17f5eee..5db18b3b 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java
@@ -39,6 +39,7 @@ import org.junit.runners.JUnit4;
 import java.net.InetAddress;
 import java.net.InetSocketAddress;
 import java.net.Socket;
+import java.security.InvalidParameterException;
 import java.security.KeyManagementException;
 import java.util.Arrays;
 import java.util.concurrent.Callable;
@@ -549,6 +550,37 @@ public class SpakeTest {
                 KeyManagementException.class, () -> sslContext.init(null, trustManagers, null));
     }
 
+    @Test
+    public void testSpake2WithoutTls13Invalid() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", password)
+                                    .build();
+
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        sockets.getFirst().setEnabledProtocols(new String[] {"TLSv1.2"});
+        sockets.getSecond().setEnabledProtocols(new String[] {"TLSv1.2"});
+
+        connectSockets(sockets);
+        sendData(sockets);
+        closeSockets(sockets);
+    }
+
     private <T> Future<T> runAsync(Callable<T> callable) {
         return executor.submit(callable);
     }
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
index 516e95cb..4eed56ac 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
@@ -82,22 +82,24 @@ public class LogStoreImplTest {
 
     /* Time supplier that can be set to any arbitrary time */
     static class TimeSupplier implements Supplier<Long> {
-        private long currentTimeInNs;
+        private long currentTimeInMs;
 
-        TimeSupplier(long currentTimeInNs) {
-            this.currentTimeInNs = currentTimeInNs;
+        TimeSupplier(long currentTimeInMs) {
+            this.currentTimeInMs = currentTimeInMs;
         }
 
         @Override
         public Long get() {
-            return currentTimeInNs;
+            return currentTimeInMs;
         }
 
-        public void setCurrentTimeInNs(long currentTimeInNs) {
-            this.currentTimeInNs = currentTimeInNs;
+        public void setCurrentTimeInMs(long currentTimeInMs) {
+            this.currentTimeInMs = currentTimeInMs;
         }
     }
 
+    private static final long JAN2024 = 1704103200000L;
+    private static final long JAN2022 = 1641031200000L;
     // clang-format off
     static final String validLogList = "" +
 "{" +
@@ -173,7 +175,7 @@ public class LogStoreImplTest {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": 1727734767000" +
+"              \"timestamp\": 1667328840000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
@@ -204,7 +206,8 @@ public class LogStoreImplTest {
     public void loadValidLogList_returnsCompliantState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         logList = writeLogList(validLogList);
-        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                 + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
                 + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
@@ -233,7 +236,22 @@ public class LogStoreImplTest {
         FakeStatsLog metrics = new FakeStatsLog();
         String content = "}}";
         logList = writeLogList(content);
-        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+
+        assertEquals(
+                "The log state should be malformed", LogStore.State.MALFORMED, store.getState());
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
+        assertEquals("The metric update for log list state should be malformed",
+                LogStore.State.MALFORMED, metrics.states.get(0));
+    }
+
+    @Test
+    public void loadFutureLogList_returnsMalformedState() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList); // The logs are usable from 2024 onwards.
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2022);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
 
         assertEquals(
                 "The log state should be malformed", LogStore.State.MALFORMED, store.getState());
@@ -246,7 +264,9 @@ public class LogStoreImplTest {
     public void loadMissingLogList_returnsNotFoundState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         Path missingLogList = Paths.get("missing_dir", "missing_subdir", "does_not_exist_log_list");
-        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
+        LogStore store =
+                new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics, fakeTime);
 
         assertEquals(
                 "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
@@ -265,7 +285,7 @@ public class LogStoreImplTest {
         Files.deleteIfExists(logList);
         Files.deleteIfExists(parentDir);
         Files.deleteIfExists(grandparentDir);
-        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
         LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         assertEquals(
                 "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
@@ -276,13 +296,38 @@ public class LogStoreImplTest {
         Files.write(logList, validLogList.getBytes());
 
         // Assert
-        // 10ns < 10min, we should not check the log list yet.
-        fakeTime.setCurrentTimeInNs(10);
+        // 5min < 10min, we should not check the log list yet.
+        fakeTime.setCurrentTimeInMs(JAN2024 + 5L * 60 * 1000);
         assertEquals(
                 "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
 
         // 12min, the log list should be reloadable.
-        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
+        assertEquals(
+                "The log state should be compliant", LogStore.State.COMPLIANT, store.getState());
+    }
+
+    @Test
+    public void loadMissingThenTimeTravelBackwardsAndThenFoundLogList_logListIsLoaded()
+            throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        // Allocate a temporary file path and delete it. We keep the temporary
+        // path so that we can add a valid log list later on.
+        logList = writeLogList("");
+        Files.deleteIfExists(logList);
+        Files.deleteIfExists(parentDir);
+        Files.deleteIfExists(grandparentDir);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024 + 100L * 60 * 1000);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals(
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+
+        Files.createDirectory(grandparentDir);
+        Files.createDirectory(parentDir);
+        Files.write(logList, validLogList.getBytes());
+        // Move back in time.
+        fakeTime.setCurrentTimeInMs(JAN2024);
+
         assertEquals(
                 "The log state should be compliant", LogStore.State.COMPLIANT, store.getState());
     }
@@ -291,13 +336,13 @@ public class LogStoreImplTest {
     public void loadExistingAndThenRemovedLogList_logListIsNotFound() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         logList = writeLogList(validLogList);
-        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
         LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
 
         Files.delete(logList);
         // 12min, the log list should be reloadable.
-        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
 
         assertEquals(
                 "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
@@ -307,7 +352,7 @@ public class LogStoreImplTest {
     public void loadExistingLogListAndThenMoveDirectory_logListIsNotFound() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         logList = writeLogList(validLogList);
-        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
         LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
         assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
 
@@ -316,7 +361,7 @@ public class LogStoreImplTest {
         Files.move(oldParentDir, parentDir);
         logList = parentDir.resolve("log_list.json");
         // 12min, the log list should be reloadable.
-        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
 
         assertEquals(
                 "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
diff --git a/srcgen/generate_android_src.sh b/srcgen/generate_android_src.sh
index fc03064c..85e10400 100755
--- a/srcgen/generate_android_src.sh
+++ b/srcgen/generate_android_src.sh
@@ -46,6 +46,9 @@ source ${ANDROID_BUILD_TOP}/tools/currysrc/scripts/repackage-common.sh
 rm -fr ${REPACKAGED_DIR}/common/src/test/java/com/android/org/conscrypt/ConscryptSuite.java
 rm -fr ${REPACKAGED_DIR}/common/src/test/java/com/android/org/conscrypt/ConscryptJava7Suite.java
 
+# Remove the StatsLog class that is generated by a build rule.
+rm ${REPACKAGED_DIR}/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
+
 # Remove any leftovers from older directory layout
 rm -fr openjdk-integ-tests ${REPACKAGED_DIR}/openjdk-integ-tests
 
```

