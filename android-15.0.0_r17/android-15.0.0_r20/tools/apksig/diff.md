```diff
diff --git a/src/apksigner/java/com/android/apksigner/help_lineage.txt b/src/apksigner/java/com/android/apksigner/help_lineage.txt
index 8fe410b..9481b50 100644
--- a/src/apksigner/java/com/android/apksigner/help_lineage.txt
+++ b/src/apksigner/java/com/android/apksigner/help_lineage.txt
@@ -185,5 +185,5 @@ $ apksigner lineage --in /path/to/existing/lineage --out /path/to/new/file \
     --set-auth false
 
 2. Display details about the signing certificates and their capabilities in the lineage:
-$ apksigner lineage --in /path/to/existing/lineage --print-certs -v
+$ apksigner lineage --in /path/to/existing/lineage_or_apk --print-certs -v
 
diff --git a/src/main/java/com/android/apksig/SigningCertificateLineage.java b/src/main/java/com/android/apksig/SigningCertificateLineage.java
index 1af64f8..1af8fd4 100644
--- a/src/main/java/com/android/apksig/SigningCertificateLineage.java
+++ b/src/main/java/com/android/apksig/SigningCertificateLineage.java
@@ -942,10 +942,6 @@ public class SigningCertificateLineage {
 
         private final int mCallerConfiguredFlags;
 
-        private SignerCapabilities(int flags) {
-            this(flags, 0);
-        }
-
         private SignerCapabilities(int flags, int callerConfiguredFlags) {
             mFlags = flags;
             mCallerConfiguredFlags = callerConfiguredFlags;
diff --git a/src/main/java/com/android/apksig/apk/ApkUtils.java b/src/main/java/com/android/apksig/apk/ApkUtils.java
index 156ea17..1a0db19 100644
--- a/src/main/java/com/android/apksig/apk/ApkUtils.java
+++ b/src/main/java/com/android/apksig/apk/ApkUtils.java
@@ -353,6 +353,10 @@ public abstract class ApkUtils {
      * @throws CodenameMinSdkVersionException if the {@code codename} is not supported
      */
     static int getMinSdkVersionForCodename(String codename) throws CodenameMinSdkVersionException {
+        if ("Baklava".equals(codename)) {
+            return 34; // VIC (35) was the version before Baklava, return VIC version minus one
+        }
+
         char firstChar = codename.isEmpty() ? ' ' : codename.charAt(0);
         // Codenames are case-sensitive. Only codenames starting with A-Z are supported for now.
         // We only look at the first letter of the codename as this is the most important letter.
@@ -373,7 +377,7 @@ public abstract class ApkUtils {
             // element at insertionIndex (if present) is greater than firstChar.
             int insertionIndex = -1 - searchResult; // insertionIndex is in [0; array length]
             if (insertionIndex == 0) {
-                // 'A' or 'B' -- never released to public
+                // 'A' or 'B' (not Baklava) -- never released to public
                 return 1;
             } else {
                 // The element at insertionIndex - 1 is the newest older codename.
diff --git a/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java b/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
index bc9831d..82899ca 100644
--- a/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
+++ b/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
@@ -943,7 +943,13 @@ public class ApkSigningBlockUtils {
             int blockId = apkSigningBlockBuffer.getInt();
             // Since the block ID has already been read from the signature block read the next
             // blockLength - 4 bytes as the value.
-            byte[] blockValue = new byte[(int) blockLength - 4];
+            byte[] blockValue = null;
+            try {
+                blockValue = new byte[(int) blockLength - 4];
+            } catch (OutOfMemoryError e) {
+                throw new IOException(
+                        "Signature block with ID " + blockId + " is too large: " + blockLength, e);
+            }
             apkSigningBlockBuffer.get(blockValue);
             signatureBlocks.add(Pair.of(blockValue, blockId));
         }
diff --git a/src/main/java/com/android/apksig/internal/util/VerityTreeBuilder.java b/src/main/java/com/android/apksig/internal/util/VerityTreeBuilder.java
index 81026ba..5c1f407 100644
--- a/src/main/java/com/android/apksig/internal/util/VerityTreeBuilder.java
+++ b/src/main/java/com/android/apksig/internal/util/VerityTreeBuilder.java
@@ -28,13 +28,11 @@ import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
-
 import java.util.ArrayList;
 import java.util.concurrent.ArrayBlockingQueue;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Phaser;
 import java.util.concurrent.ThreadPoolExecutor;
-import java.util.concurrent.TimeUnit;
 
 /**
  * VerityTreeBuilder is used to generate the root hash of verity tree built from the input file.
@@ -60,10 +58,6 @@ public class VerityTreeBuilder implements AutoCloseable {
      * Typical prefetch size.
      */
     private final static int MAX_PREFETCH_CHUNKS = 1024;
-    /**
-     * Minimum chunks to be processed by a single worker task.
-     */
-    private final static int MIN_CHUNKS_PER_WORKER = 8;
 
     /**
      * Digest algorithm (JCA Digest algorithm name) used in the tree.
diff --git a/src/test/java/com/android/apksig/ApkSignerTest.java b/src/test/java/com/android/apksig/ApkSignerTest.java
index c48e027..a2ecf8d 100644
--- a/src/test/java/com/android/apksig/ApkSignerTest.java
+++ b/src/test/java/com/android/apksig/ApkSignerTest.java
@@ -2029,6 +2029,31 @@ public class ApkSignerTest {
                 EC_P256_SIGNER_RESOURCE_NAME);
     }
 
+    @Test
+    public void testOtherSignersSignaturesPreserved_v2BlockSizeLargerThanHeap_throwsException()
+            throws Exception {
+        // TODO(b/319479290) make the test run with a specific max heap size
+        assumeTrue(Runtime.getRuntime().maxMemory() < 2147483647L);
+        // When a V2 signature is appended to an existing signature, the bytes of the existing
+        // block have to be obtained to create a new signature block with the requested signature
+        // appended. If the existing signature block is larger than the heap size, then an
+        // OutOfMemory error will be thrown when attempting to allocate the byte array for the
+        // block. This test uses a modified APK with a nearly 2GB signature block length to verify
+        // that the OutOfMemory error is handled when allocating the array and an
+        // IllegalArgumentException is thrown instead.
+        List<ApkSigner.SignerConfig> ecP256SignerConfig = Collections.singletonList(
+                getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME));
+
+        assertThrows(IllegalArgumentException.class, () ->
+                sign("incorrect-v2-block-size.apk",
+                        new ApkSigner.Builder(ecP256SignerConfig)
+                                .setV1SigningEnabled(true)
+                                .setV2SigningEnabled(true)
+                                .setV3SigningEnabled(false)
+                                .setV4SigningEnabled(false)
+                                .setOtherSignersSignaturesPreserved(true)));
+    }
+
     @Test
     public void testSetMinSdkVersionForRotation_lessThanT_noV31Block() throws Exception {
         // The V3.1 signing block is intended to allow APK signing key rotation to target T+, but
diff --git a/src/test/resources/com/android/apksig/incorrect-v2-block-size.apk b/src/test/resources/com/android/apksig/incorrect-v2-block-size.apk
new file mode 100644
index 0000000..75a6a0e
Binary files /dev/null and b/src/test/resources/com/android/apksig/incorrect-v2-block-size.apk differ
```

