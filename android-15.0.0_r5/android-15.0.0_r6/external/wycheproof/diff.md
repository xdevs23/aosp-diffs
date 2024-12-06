```diff
diff --git a/Android.bp b/Android.bp
index 4e3e0f9..90fe907 100644
--- a/Android.bp
+++ b/Android.bp
@@ -46,7 +46,7 @@ java_library_static {
     sdk_version: "current",
     libs: [
         "bouncycastle-repackaged-unbundled",
-        "conscrypt.module.platform.api",
+        "conscrypt.module.platform.api.stubs",
         "junit",
     ],
 }
diff --git a/METADATA b/METADATA
index d97975c..b34c32f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,3 +1,15 @@
+name: "wycheproof"
+description: "Project Wycheproof tests crypto libraries against known attacks."
 third_party {
   license_type: NOTICE
+  last_upgrade_date {
+    year: 2017
+    month: 3
+    day: 17
+  }
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/wycheproof"
+    version: "c89a32e2ce9e165423a632388513f8c972cdbdbb"
+  }
 }
diff --git a/keystore-cts/java/com/google/security/wycheproof/testcases/RsaEncryptionTest.java b/keystore-cts/java/com/google/security/wycheproof/testcases/RsaEncryptionTest.java
index ed291e0..08628e7 100644
--- a/keystore-cts/java/com/google/security/wycheproof/testcases/RsaEncryptionTest.java
+++ b/keystore-cts/java/com/google/security/wycheproof/testcases/RsaEncryptionTest.java
@@ -13,8 +13,10 @@
  */
 package com.google.security.wycheproof;
 
+import static android.os.Build.VERSION_CODES.TIRAMISU;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeTrue;
 
 import com.google.gson.JsonElement;
 import com.google.gson.JsonObject;
@@ -37,6 +39,7 @@ import org.junit.Test;
 import android.security.keystore.KeyProtection;
 import android.security.keystore.KeyProperties;
 import android.keystore.cts.util.KeyStoreUtil;
+import android.keystore.cts.util.TestUtils;
 
 /**
  * RSA encryption tests
@@ -82,7 +85,7 @@ public class RsaEncryptionTest {
     KeyFactory kf;
     kf = KeyFactory.getInstance("RSA");
     byte[] encoded = TestUtil.hexToBytes(object.get("privateKeyPkcs8").getAsString());
-    BigInteger modulus = new BigInteger(TestUtil.hexToBytes(object.get("n").getAsString()));  
+    BigInteger modulus = new BigInteger(TestUtil.hexToBytes(object.get("n").getAsString()));
     BigInteger exponent = new BigInteger(TestUtil.hexToBytes(object.get("e").getAsString()));
 
     PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
@@ -107,7 +110,7 @@ public class RsaEncryptionTest {
    * attack depends on how much information is leaked when decrypting an invalid ciphertext.
    * The test vectors with invalid padding contain a flag "InvalidPkcs1Padding".
    * The test below expects that all test vectors with this flag throw an indistinguishable
-   * exception. 
+   * exception.
    *
    * <p><b>References:</b>
    *
@@ -215,8 +218,11 @@ public class RsaEncryptionTest {
   public void testDecryption2048() throws Exception {
     testDecryption("rsa_pkcs1_2048_test.json");
   }
+
   @Test
   public void testDecryption2048_StrongBox() throws Exception {
+    assumeTrue("If the VSR level is > T the test will run, otherwise it will be ignored.",
+        TestUtils.getVendorApiLevel() > TIRAMISU);
     KeyStoreUtil.assumeStrongBox();
     testDecryption("rsa_pkcs1_2048_test.json", true);
   }
@@ -230,4 +236,5 @@ public class RsaEncryptionTest {
   public void testDecryption4096() throws Exception {
     testDecryption("rsa_pkcs1_4096_test.json");
   }
+
 }
diff --git a/keystore-cts/java/com/google/security/wycheproof/testcases/RsaOaepTest.java b/keystore-cts/java/com/google/security/wycheproof/testcases/RsaOaepTest.java
index f9c3612..652aa14 100644
--- a/keystore-cts/java/com/google/security/wycheproof/testcases/RsaOaepTest.java
+++ b/keystore-cts/java/com/google/security/wycheproof/testcases/RsaOaepTest.java
@@ -13,6 +13,7 @@
  */
 package com.google.security.wycheproof;
 
+import static android.os.Build.VERSION_CODES.TIRAMISU;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assume.assumeTrue;
@@ -401,6 +402,8 @@ public class RsaOaepTest {
   }
   @Test
   public void testRsaOaep2048Sha256Mgf1Sha1_StrongBox() throws Exception {
+    assumeTrue("If the VSR level is > T the test will run, otherwise it will be ignored.",
+        TestUtils.getVendorApiLevel() > TIRAMISU);
     testOaep("rsa_oaep_2048_sha256_mgf1sha1_test.json", false, true);
   }
 
```

