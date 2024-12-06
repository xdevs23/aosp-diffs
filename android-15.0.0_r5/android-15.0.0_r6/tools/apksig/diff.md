```diff
diff --git a/src/apksigner/java/com/android/apksigner/ApkSignerTool.java b/src/apksigner/java/com/android/apksigner/ApkSignerTool.java
index 33ae656..519fe66 100644
--- a/src/apksigner/java/com/android/apksigner/ApkSignerTool.java
+++ b/src/apksigner/java/com/android/apksigner/ApkSignerTool.java
@@ -680,6 +680,10 @@ public class ApkSignerTool {
                             verbose, printCertsPem);
                 }
             }
+            if (sourceStampInfo != null && verbose) {
+                System.out.println(
+                        "Source Stamp Timestamp: " + sourceStampInfo.getTimestampEpochSeconds());
+            }
         } else {
             System.err.println("DOES NOT VERIFY");
         }
diff --git a/src/main/java/com/android/apksig/internal/apk/v4/V4SchemeSigner.java b/src/main/java/com/android/apksig/internal/apk/v4/V4SchemeSigner.java
index 7bf952d..416cf87 100644
--- a/src/main/java/com/android/apksig/internal/apk/v4/V4SchemeSigner.java
+++ b/src/main/java/com/android/apksig/internal/apk/v4/V4SchemeSigner.java
@@ -180,9 +180,6 @@ public abstract class V4SchemeSigner {
         if (signerConfig.certificates.isEmpty()) {
             throw new SignatureException("No certificates configured for signer");
         }
-        if (signerConfig.certificates.size() != 1) {
-            throw new CertificateEncodingException("Should only have one certificate");
-        }
 
         // Collecting data for signing.
         final PublicKey publicKey = signerConfig.certificates.get(0).getPublicKey();
diff --git a/src/test/java/com/android/apksig/ApkSignerTest.java b/src/test/java/com/android/apksig/ApkSignerTest.java
index 6661e23..c48e027 100644
--- a/src/test/java/com/android/apksig/ApkSignerTest.java
+++ b/src/test/java/com/android/apksig/ApkSignerTest.java
@@ -25,6 +25,7 @@ import static com.android.apksig.apk.ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_
 import static com.android.apksig.apk.ApkUtils.findZipSections;
 import static com.android.apksig.internal.util.Resources.EC_P256_2_SIGNER_RESOURCE_NAME;
 import static com.android.apksig.internal.util.Resources.EC_P256_SIGNER_RESOURCE_NAME;
+import static com.android.apksig.internal.util.Resources.FIRST_AND_SECOND_RSA_2048_SIGNER_RESOURCE_NAME;
 import static com.android.apksig.internal.util.Resources.FIRST_RSA_2048_SIGNER_CERT_WITH_NEGATIVE_MODULUS;
 import static com.android.apksig.internal.util.Resources.FIRST_RSA_2048_SIGNER_RESOURCE_NAME;
 import static com.android.apksig.internal.util.Resources.FIRST_RSA_4096_SIGNER_RESOURCE_NAME;
@@ -3436,6 +3437,34 @@ public class ApkSignerTest {
                 FIRST_RSA_4096_SIGNER_RESOURCE_NAME);
     }
 
+    @Test
+    public void testV4_certificateChainInSignerConfig_v4UsesCurrentSigner() throws Exception {
+        // The APK SignerConfig supports a certificate chain as input; this chain represents the
+        // current signing certificate, the previous issuer of this certificate, and any previous
+        // issuers back to the root. As long as the current signer for the SignerConfig is
+        // specified as the first certificate, all of the certificates in the chain should be
+        // stored in the length-prefixed sequence of X.509 certificates. To remain consistent
+        // with SigningConfigs for previous signature schemes, the V4 signature scheme should also
+        // accept SigningConfigs with a certificate chain; while the entire chain will not be
+        // stored in the V4 signature, this will allow SignerConfig instances with certificate
+        // chains to be used across all signature schemes. For more details about the certificate
+        // chain in the V3 signature block, see
+        // https://source.android.com/docs/security/features/apksigning/v3#format
+        List<ApkSigner.SignerConfig> rsa2048SignerConfig = Arrays.asList(
+                getDefaultSignerConfigFromResources(
+                        FIRST_AND_SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
+
+        File signedApk = sign("original.apk",
+                new ApkSigner.Builder(rsa2048SignerConfig)
+                        .setV1SigningEnabled(true)
+                        .setV2SigningEnabled(true)
+                        .setV3SigningEnabled(true)
+                        .setV4SigningEnabled(true));
+        ApkVerifier.Result result = verify(signedApk, null);
+
+        assertResultContainsV4Signers(result, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
+    }
+
     @Test
     public void
     testSourceStampTimestamp_signWithSourceStampAndTimestampDefault_validTimestampValue()
diff --git a/src/test/java/com/android/apksig/internal/util/Resources.java b/src/test/java/com/android/apksig/internal/util/Resources.java
index e647cfe..5120544 100644
--- a/src/test/java/com/android/apksig/internal/util/Resources.java
+++ b/src/test/java/com/android/apksig/internal/util/Resources.java
@@ -60,6 +60,11 @@ public final class Resources {
     public static final String FIRST_RSA_1024_SIGNER_RESOURCE_NAME = "rsa-1024";
     public static final String SECOND_RSA_1024_SIGNER_RESOURCE_NAME = "rsa-1024_2";
 
+    // This resource uses a PEM certificate file containing the certificate chain with both the
+    // first and second RSA-2048 signers. This resource should be used for any tests that require
+    // a certificate chain in the SignerConfig.
+    public static final String FIRST_AND_SECOND_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048-2-1";
+
     public static final String FIRST_RSA_4096_SIGNER_RESOURCE_NAME = "rsa-4096";
 
     public static final String EC_P256_SIGNER_RESOURCE_NAME = "ec-p256";
diff --git a/src/test/resources/com/android/apksig/rsa-2048-2-1.pk8 b/src/test/resources/com/android/apksig/rsa-2048-2-1.pk8
new file mode 100644
index 0000000..5a572ff
Binary files /dev/null and b/src/test/resources/com/android/apksig/rsa-2048-2-1.pk8 differ
diff --git a/src/test/resources/com/android/apksig/rsa-2048-2-1.x509.pem b/src/test/resources/com/android/apksig/rsa-2048-2-1.x509.pem
new file mode 100644
index 0000000..b14fae4
--- /dev/null
+++ b/src/test/resources/com/android/apksig/rsa-2048-2-1.x509.pem
@@ -0,0 +1,37 @@
+-----BEGIN CERTIFICATE-----
+MIIC+zCCAeOgAwIBAgIJANh7AUYJKp9PMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
+BAMMCHJzYS0yMDQ4MB4XDTE4MDYxOTAwMDUwMFoXDTI4MDYxNjAwMDUwMFowFTET
+MBEGA1UEAwwKcnNhLTIwNDhfMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
+ggEBALgwhcEJHldw5BD4tZP3aeeYyi8FCVx68WvuRcpJ1IwCbXd03giTyc3Y8Olr
+7D67Y5aLdCW+XE8Z9pNHd43dXe9aRN6kcbhVynzVfe5PKCeYt3dVYgxh8eQqO6A5
+f6DpJjF1jkqRmR6BipsDw5t8PwiiJ03jnoaepdGvnQpwxHEf7izWte+XHBPbJH6A
+vqXCUVlHw+CpI4J2NhZqfSa60F4y5heKF4mF4+97JPODopVeFXvS1VctYEY3ycsB
+uumZy3Q9Lp2E07KP7SP7oKAegg0uReqeqVcofBQESP4iMefw86QhqkTysfG3q3Sf
+RmmbTLnovAxSjjQZ5oZzGJuBQXECAwEAAaNQME4wHQYDVR0OBBYEFD/NVrkySRE2
+6bctYSVM+os/31yRMB8GA1UdIwQYMBaAFBcCLXMQfzibORLraiGzAYZZLB1vMAwG
+A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACIYKbWz0byV8hCwVhK3UGrI
+PV6+DWAbRrx74y0cqhlPIyroOdSSEsmGythQMMVdvkvHGLqdA9gwQqYkNkWFQQqp
+Cfj9+YJdEKTKJtMO/ZTATJyN0ACEXr5YQo9ivAASY2pfiTfQXbPGsEhycuG3gJ1Y
+rTC3imERhkHomf8ZvTJEwSOF0bQYNg/Ar2nNYNdf3oCrrylLIxUaq0pp/5CrvZT4
+SMKLBfimirfxGS31Z9TEuvDma1Rn2xwfDOhmiSvC30PK/xPsN1xvallHtJDmTdNV
+M4E7Z5hDyCOQ3y1o3VHr73dZnA0M0WdM7JIH9Vcs+R0otFdyXrfeMw4YvMZ0/Qc=
+-----END CERTIFICATE-----
+-----BEGIN CERTIFICATE-----
+MIIC+TCCAeGgAwIBAgIJAI41MGzdARX3MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
+BAMMCHJzYS0yMDQ4MB4XDTE2MDMzMTE0NTc0OVoXDTQzMDgxNzE0NTc0OVowEzER
+MA8GA1UEAwwIcnNhLTIwNDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
+AQDQ4JI1EJ239V4wss0jpVlZMudh2/kARCVdoBgsRQuvc2RNnO23Eyynlt9UN+Dc
+NRdQIhbCpVTjdEl/bePECHlqg9NE3frAj5GebiUdWL6A/idKsZA1nAKyIgxxjcnu
++38OcrlO6XOm36euxGfd/ULrghZGXzMVFq4uLiIv3DqFkUcIlE0BvUiUoNwpopV4
+MKj1GQgoaEObJG5xkMBKO6vg36VfJ3s3V3r48uJxYGhhBZEB0EpoXLd4i0piAB8S
+MLb0Ek6wA/HZ8A2rdnStk1wl/83OM1jO0uB3hyfJpqIijlvNGnrloYyyOIqS0LGH
+nxSJD7goASH2Ef0h4yxbsOvHAgMBAAGjUDBOMB0GA1UdDgQWBBQXAi1zEH84mzkS
+62ohswGGWSwdbzAfBgNVHSMEGDAWgBQXAi1zEH84mzkS62ohswGGWSwdbzAMBgNV
+HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAB92T5toLkF6dLl65/boH5Qvub
+5wfIk0AD12T3t3kYWQFOH0YDCHNL3SfmrjYM/CwNJAd1KuCL5AZcn0km/n0SFXt5
+8Ps/MBcb0eK1fYezeEehKUyt5IBgDTKeQOel6So8rGuQRrDf/WV8rt6fugkIODFx
+sB3oj4ESaGXbvmvWD6q4a3koq/nV26kALchnAr7/FTNq3HEIQ1BDr9pldVh1gEV/
+ohHKcQP4M22Es7lredzpIcb5K6Ko/UtwsSRtHnoOjwmb+L/FsgAJsekmcJG5TK1X
+ciIsrrNFDCYzf/d9O1PD/V95kB7460qMzrGWZpc3mLe+OnmVMq6c4omOtIKl
+-----END CERTIFICATE-----
+
```

