```diff
diff --git a/common/src/main/java/org/conscrypt/NativeCrypto.java b/common/src/main/java/org/conscrypt/NativeCrypto.java
index 5c7d3283..ca978649 100644
--- a/common/src/main/java/org/conscrypt/NativeCrypto.java
+++ b/common/src/main/java/org/conscrypt/NativeCrypto.java
@@ -862,10 +862,8 @@ public final class NativeCrypto {
         if (loadError == null) {
             // If loadError is not null, it means the native code was not loaded, so
             // get_cipher_names will throw UnsatisfiedLinkError. Populate the list of supported
-            // ciphers with BoringSSL's default, and also explicitly include 3DES.
-            // https://boringssl-review.googlesource.com/c/boringssl/+/59425 will remove 3DES
-            // from BoringSSL's default, but Conscrypt isn't quite ready to remove it yet.
-            String[] allCipherSuites = get_cipher_names("ALL:3DES");
+            // ciphers with BoringSSL's default.
+            String[] allCipherSuites = get_cipher_names("ALL");
 
             // get_cipher_names returns an array where even indices are the standard name and odd
             // indices are the OpenSSL name.
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
index 159787cb..e3189d0b 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
@@ -894,10 +894,8 @@ public final class NativeCrypto {
         if (loadError == null) {
             // If loadError is not null, it means the native code was not loaded, so
             // get_cipher_names will throw UnsatisfiedLinkError. Populate the list of supported
-            // ciphers with BoringSSL's default, and also explicitly include 3DES.
-            // https://boringssl-review.googlesource.com/c/boringssl/+/59425 will remove 3DES
-            // from BoringSSL's default, but Conscrypt isn't quite ready to remove it yet.
-            String[] allCipherSuites = get_cipher_names("ALL:3DES");
+            // ciphers with BoringSSL's default.
+            String[] allCipherSuites = get_cipher_names("ALL");
 
             // get_cipher_names returns an array where even indices are the standard name and odd
             // indices are the OpenSSL name.
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
index 6402f8b0..8d49bf64 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
@@ -256,7 +256,6 @@ public final class StandardNames {
         addOpenSsl("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
         addOpenSsl("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
         addOpenSsl("TLS_RSA_WITH_AES_128_CBC_SHA");
-        addOpenSsl("SSL_RSA_WITH_3DES_EDE_CBC_SHA");
 
         // TLSv1.2 cipher suites
         addOpenSsl("TLS_RSA_WITH_AES_128_GCM_SHA256");
diff --git a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
index ac9d895c..9d0af787 100644
--- a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
+++ b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
@@ -254,7 +254,6 @@ public final class StandardNames {
         addOpenSsl("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
         addOpenSsl("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
         addOpenSsl("TLS_RSA_WITH_AES_128_CBC_SHA");
-        addOpenSsl("SSL_RSA_WITH_3DES_EDE_CBC_SHA");
 
         // TLSv1.2 cipher suites
         addOpenSsl("TLS_RSA_WITH_AES_128_GCM_SHA256");
```

