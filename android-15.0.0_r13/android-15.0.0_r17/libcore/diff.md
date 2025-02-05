```diff
diff --git a/support/src/test/java/libcore/java/security/StandardNames.java b/support/src/test/java/libcore/java/security/StandardNames.java
index 3eb6d10810d..fe088a10829 100644
--- a/support/src/test/java/libcore/java/security/StandardNames.java
+++ b/support/src/test/java/libcore/java/security/StandardNames.java
@@ -770,13 +770,6 @@ public final class StandardNames {
                             "SSL_RSA_WITH_RC4_128_SHA",
                             "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
                             "TLS_ECDH_RSA_WITH_RC4_128_SHA",
-                            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
-                            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
-                            "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
-                            "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
-                            "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
-                            "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
-                            "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                             "SSL_RSA_WITH_RC4_128_MD5",
                             "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
             : CpuFeatures.isAesHardwareAccelerated() ? CIPHER_SUITES_ANDROID_AES_HARDWARE
@@ -787,19 +780,19 @@ public final class StandardNames {
     private static final Map<String, Integer> MINIMUM_KEY_SIZE;
     static {
         PRIVATE_KEY_SPEC_CLASSES = new HashMap<>();
-        PUBLIC_KEY_SPEC_CLASSES = new HashMap<>();
-        MINIMUM_KEY_SIZE = new HashMap<>();
         PRIVATE_KEY_SPEC_CLASSES.put("RSA", RSAPrivateCrtKeySpec.class);
-        PUBLIC_KEY_SPEC_CLASSES.put("RSA", RSAPublicKeySpec.class);
-        MINIMUM_KEY_SIZE.put("RSA", 512);
         PRIVATE_KEY_SPEC_CLASSES.put("DSA", DSAPrivateKeySpec.class);
-        PUBLIC_KEY_SPEC_CLASSES.put("DSA", DSAPublicKeySpec.class);
-        MINIMUM_KEY_SIZE.put("DSA", 512);
         PRIVATE_KEY_SPEC_CLASSES.put("DH", DHPrivateKeySpec.class);
-        PUBLIC_KEY_SPEC_CLASSES.put("DH", DHPublicKeySpec.class);
-        MINIMUM_KEY_SIZE.put("DH", 256);
         PRIVATE_KEY_SPEC_CLASSES.put("EC", ECPrivateKeySpec.class);
+        PUBLIC_KEY_SPEC_CLASSES = new HashMap<>();
+        PUBLIC_KEY_SPEC_CLASSES.put("RSA", RSAPublicKeySpec.class);
+        PUBLIC_KEY_SPEC_CLASSES.put("DSA", DSAPublicKeySpec.class);
+        PUBLIC_KEY_SPEC_CLASSES.put("DH", DHPublicKeySpec.class);
         PUBLIC_KEY_SPEC_CLASSES.put("EC", ECPublicKeySpec.class);
+        MINIMUM_KEY_SIZE = new HashMap<>();
+        MINIMUM_KEY_SIZE.put("RSA", 512);
+        MINIMUM_KEY_SIZE.put("DSA", 512);
+        MINIMUM_KEY_SIZE.put("DH", 256);
         MINIMUM_KEY_SIZE.put("EC", 256);
     }
 
```

