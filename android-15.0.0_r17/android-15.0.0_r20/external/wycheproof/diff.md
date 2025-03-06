```diff
diff --git a/keystore-cts/OWNERS b/keystore-cts/OWNERS
index aad2496..2727f50 100644
--- a/keystore-cts/OWNERS
+++ b/keystore-cts/OWNERS
@@ -1,9 +1,9 @@
 # Bug Component 1084732
 
 # EMEA, Primary reviewers
-eranm@google.com
+cvlasov@google.com
 drysdale@google.com
 
 # US
-jdanis@google.com
+ascull@google.com
 sethmo@google.com
diff --git a/keystore-cts/java/com/google/security/wycheproof/testcases/JsonMacTest.java b/keystore-cts/java/com/google/security/wycheproof/testcases/JsonMacTest.java
index d813d02..a311798 100644
--- a/keystore-cts/java/com/google/security/wycheproof/testcases/JsonMacTest.java
+++ b/keystore-cts/java/com/google/security/wycheproof/testcases/JsonMacTest.java
@@ -29,15 +29,19 @@ import javax.crypto.spec.SecretKeySpec;
 import org.junit.After;
 import org.junit.Test;
 import org.junit.Ignore;
+import android.os.Build;
 import android.security.keystore.KeyProtection;
 import android.security.keystore.KeyProperties;
 import java.io.IOException;
 import android.keystore.cts.util.KeyStoreUtil;
+import android.keystore.cts.util.TestUtils;
+import android.util.Log;
 
 /** This test uses test vectors in JSON format to test MAC primitives. */
 public class JsonMacTest {
   private static final String EXPECTED_PROVIDER_NAME = TestUtil.EXPECTED_CRYPTO_OP_PROVIDER_NAME;
   private static final String KEY_ALIAS_1 = "Key1";
+  private static final String TAG = JsonMacTest.class.getSimpleName();
 
   @After
   public void tearDown() throws Exception {
@@ -135,6 +139,11 @@ public class JsonMacTest {
         byte[] key = getBytes(testcase, "key");
         byte[] msg = getBytes(testcase, "msg");
         byte[] expectedTag = getBytes(testcase, "tag");
+        // Skip empty bytes on older devices that cannot handle them.
+        if ((msg.length == 0) && (TestUtils.getVendorApiLevel() <= Build.VERSION_CODES.P)) {
+            Log.d(TAG, "Skipping test for unsupported input on pre-Q launch device.");
+            continue;
+        }
         // Strongbox only supports key size from 8 to 32 bytes.
         if (isStrongBox && (key.length < 8 || key.length > 32)) {
           continue;
```

