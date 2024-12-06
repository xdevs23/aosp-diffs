```diff
diff --git a/Android.bp b/Android.bp
index f56f10e1..d217dcf7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -89,6 +89,8 @@ java_library {
     visibility: [
         "//art/build/apex",
         "//art/build/sdk",
+        "//art/tools/ahat",
+        "//art/tools/fuzzer",
         "//libcore:__subpackages__",
         "//packages/modules/ArtPrebuilt",
     ],
@@ -186,7 +188,7 @@ unbundled_visibility = [
     "//packages/apps/RemoteProvisioner/tests/unittests",
     "//packages/modules/Connectivity/tests/cts/net",
     "//packages/modules/RemoteKeyProvisioning/app/tests/unit",
-    "//packages/modules/Virtualization/service_vm/test_apk",
+    "//packages/modules/Virtualization/tests/vm_attestation",
     "//packages/modules/Wifi/service",
     "//packages/modules/Wifi/service/tests/wifitests",
     "//libcore",
diff --git a/bcprov/src/main/java/org/bouncycastle/jce/provider/CertBlocklist.java b/bcprov/src/main/java/org/bouncycastle/jce/provider/CertBlocklist.java
deleted file mode 100644
index 48e5ba07..00000000
--- a/bcprov/src/main/java/org/bouncycastle/jce/provider/CertBlocklist.java
+++ /dev/null
@@ -1,234 +0,0 @@
-/*
- * Copyright (C) 2012 The Android Open Source Project
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
-
-package org.bouncycastle.jce.provider;
-
-import java.io.Closeable;
-import java.io.ByteArrayOutputStream;
-import java.io.FileNotFoundException;
-import java.io.IOException;
-import java.io.RandomAccessFile;
-import java.math.BigInteger;
-import java.security.PublicKey;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.HashSet;
-import java.util.Set;
-import java.util.logging.Level;
-import java.util.logging.Logger;
-import org.bouncycastle.crypto.Digest;
-import org.bouncycastle.crypto.digests.AndroidDigestFactory;
-import org.bouncycastle.util.encoders.Hex;
-
-public class CertBlocklist {
-    private static final Logger logger = Logger.getLogger(CertBlocklist.class.getName());
-
-    // public for testing
-    public final Set<BigInteger> serialBlocklist;
-    public final Set<byte[]> pubkeyBlocklist;
-
-    public CertBlocklist() {
-        String androidData = System.getenv("ANDROID_DATA");
-        String blocklistRoot = androidData + "/misc/keychain/";
-        // TODO(b/162575432): change these paths to use inclusive language
-        String defaultPubkeyBlocklistPath = blocklistRoot + "pubkey_blacklist.txt";
-        String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";
-
-        pubkeyBlocklist = readPublicKeyBlockList(defaultPubkeyBlocklistPath);
-        serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
-    }
-
-    /** Test only interface, not for public use */
-    public CertBlocklist(String pubkeyBlocklistPath, String serialBlocklistPath) {
-        pubkeyBlocklist = readPublicKeyBlockList(pubkeyBlocklistPath);
-        serialBlocklist = readSerialBlockList(serialBlocklistPath);
-    }
-
-    private static boolean isHex(String value) {
-        try {
-            new BigInteger(value, 16);
-            return true;
-        } catch (NumberFormatException e) {
-            logger.log(Level.WARNING, "Could not parse hex value " + value, e);
-            return false;
-        }
-    }
-
-    private static boolean isPubkeyHash(String value) {
-        if (value.length() != 40) {
-            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
-            return false;
-        }
-        return isHex(value);
-    }
-
-    private static String readBlocklist(String path) {
-        try {
-            return readFileAsString(path);
-        } catch (FileNotFoundException ignored) {
-        } catch (IOException e) {
-            logger.log(Level.WARNING, "Could not read blocklist", e);
-        }
-        return "";
-    }
-
-    // From IoUtils.readFileAsString
-    private static String readFileAsString(String path) throws IOException {
-        return readFileAsBytes(path).toString("UTF-8");
-    }
-
-    // Based on IoUtils.readFileAsBytes
-    private static ByteArrayOutputStream readFileAsBytes(String path) throws IOException {
-        RandomAccessFile f = null;
-        try {
-            f = new RandomAccessFile(path, "r");
-            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) f.length());
-            byte[] buffer = new byte[8192];
-            while (true) {
-                int byteCount = f.read(buffer);
-                if (byteCount == -1) {
-                    return bytes;
-                }
-                bytes.write(buffer, 0, byteCount);
-            }
-        } finally {
-            closeQuietly(f);
-        }
-    }
-
-    // Base on IoUtils.closeQuietly
-    private static void closeQuietly(Closeable closeable) {
-        if (closeable != null) {
-            try {
-                closeable.close();
-            } catch (RuntimeException rethrown) {
-                throw rethrown;
-            } catch (Exception ignored) {
-            }
-        }
-    }
-
-    private static Set<BigInteger> readSerialBlockList(String path) {
-
-        /* Start out with a base set of known bad values.
-         *
-         * WARNING: Do not add short serials to this list!
-         *
-         * Since this currently doesn't compare the serial + issuer, you
-         * should only add serials that have enough entropy here. Short
-         * serials may inadvertently match a certificate that was issued
-         * not in compliance with the Baseline Requirements.
-         */
-        Set<BigInteger> bl = new HashSet<BigInteger>(Arrays.asList(
-            // From http://src.chromium.org/viewvc/chrome/trunk/src/net/base/x509_certificate.cc?revision=78748&view=markup
-            // Not a real certificate. For testing only.
-            new BigInteger("077a59bcd53459601ca6907267a6dd1c", 16),
-            new BigInteger("047ecbe9fca55f7bd09eae36e10cae1e", 16),
-            new BigInteger("d8f35f4eb7872b2dab0692e315382fb0", 16),
-            new BigInteger("b0b7133ed096f9b56fae91c874bd3ac0", 16),
-            new BigInteger("9239d5348f40d1695a745470e1f23f43", 16),
-            new BigInteger("e9028b9578e415dc1a710a2b88154447", 16),
-            new BigInteger("d7558fdaf5f1105bb213282b707729a3", 16),
-            new BigInteger("f5c86af36162f13a64f54f6dc9587c06", 16),
-            new BigInteger("392a434f0e07df1f8aa305de34e0c229", 16),
-            new BigInteger("3e75ced46b693021218830ae86a82a71", 16)
-        ));
-
-        // attempt to augment it with values taken from gservices
-        String serialBlocklist = readBlocklist(path);
-        if (!serialBlocklist.equals("")) {
-            for(String value : serialBlocklist.split(",")) {
-                try {
-                    bl.add(new BigInteger(value, 16));
-                } catch (NumberFormatException e) {
-                    logger.log(Level.WARNING, "Tried to blocklist invalid serial number " + value, e);
-                }
-            }
-        }
-
-        // whether that succeeds or fails, send it on its merry way
-        return Collections.unmodifiableSet(bl);
-    }
-
-    private static Set<byte[]> readPublicKeyBlockList(String path) {
-
-        // start out with a base set of known bad values
-        Set<byte[]> bl = new HashSet<byte[]>(Arrays.asList(
-            // From http://src.chromium.org/viewvc/chrome/branches/782/src/net/base/x509_certificate.cc?r1=98750&r2=98749&pathrev=98750
-            // C=NL, O=DigiNotar, CN=DigiNotar Root CA/emailAddress=info@diginotar.nl
-            "410f36363258f30b347d12ce4863e433437806a8".getBytes(),
-            // Subject: CN=DigiNotar Cyber CA
-            // Issuer: CN=GTE CyberTrust Global Root
-            "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37".getBytes(),
-            // Subject: CN=DigiNotar Services 1024 CA
-            // Issuer: CN=Entrust.net
-            "e23b8d105f87710a68d9248050ebefc627be4ca6".getBytes(),
-            // Subject: CN=DigiNotar PKIoverheid CA Organisatie - G2
-            // Issuer: CN=Staat der Nederlanden Organisatie CA - G2
-            "7b2e16bc39bcd72b456e9f055d1de615b74945db".getBytes(),
-            // Subject: CN=DigiNotar PKIoverheid CA Overheid en Bedrijven
-            // Issuer: CN=Staat der Nederlanden Overheid CA
-            "e8f91200c65cee16e039b9f883841661635f81c5".getBytes(),
-            // From http://src.chromium.org/viewvc/chrome?view=rev&revision=108479
-            // Subject: O=Digicert Sdn. Bhd.
-            // Issuer: CN=GTE CyberTrust Global Root
-            "0129bcd5b448ae8d2496d1c3e19723919088e152".getBytes(),
-            // Subject: CN=e-islem.kktcmerkezbankasi.org/emailAddress=ileti@kktcmerkezbankasi.org
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "5f3ab33d55007054bc5e3e5553cd8d8465d77c61".getBytes(),
-            // Subject: CN=*.EGO.GOV.TR 93
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "783333c9687df63377efceddd82efa9101913e8e".getBytes(),
-            // Subject: Subject: C=FR, O=DG Tr\xC3\xA9sor, CN=AC DG Tr\xC3\xA9sor SSL
-            // Issuer: C=FR, O=DGTPE, CN=AC DGTPE Signature Authentification
-            "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf".getBytes()
-        ));
-
-        // attempt to augment it with values taken from gservices
-        String pubkeyBlocklist = readBlocklist(path);
-        if (!pubkeyBlocklist.equals("")) {
-            for (String value : pubkeyBlocklist.split(",")) {
-                value = value.trim();
-                if (isPubkeyHash(value)) {
-                    bl.add(value.getBytes());
-                } else {
-                    logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
-                }
-            }
-        }
-
-        return bl;
-    }
-
-    public boolean isPublicKeyBlockListed(PublicKey publicKey) {
-        byte[] encoded = publicKey.getEncoded();
-        Digest digest = AndroidDigestFactory.getSHA1();
-        digest.update(encoded, 0, encoded.length);
-        byte[] out = new byte[digest.getDigestSize()];
-        digest.doFinal(out, 0);
-        for (byte[] blocklisted : pubkeyBlocklist) {
-            if (Arrays.equals(blocklisted, Hex.encode(out))) {
-                return true;
-            }
-        }
-        return false;
-    }
-
-    public boolean isSerialNumberBlockListed(BigInteger serial) {
-        return serialBlocklist.contains(serial);
-    }
-
-}
diff --git a/bcprov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java b/bcprov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
index b142f973..ab8f761e 100644
--- a/bcprov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
+++ b/bcprov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
@@ -55,11 +55,6 @@ public class PKIXCertPathValidatorSpi
     {
         this.isForCRLCheck = isForCRLCheck;
     }
-    // BEGIN Android-added: Avoid loading blocklist during class init
-    private static class NoPreloadHolder {
-        private final static CertBlocklist blocklist = new CertBlocklist();
-    }
-    // END Android-added: Avoid loading blocklist during class init
 
     public CertPathValidatorResult engineValidate(
             CertPath certPath,
@@ -115,22 +110,6 @@ public class PKIXCertPathValidatorSpi
         {
             throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
         }
-        // BEGIN Android-added: Support blocklisting known-bad certs
-        {
-            X509Certificate cert = (X509Certificate) certs.get(0);
-
-            if (cert != null) {
-                BigInteger serial = cert.getSerialNumber();
-                if (NoPreloadHolder.blocklist.isSerialNumberBlockListed(serial)) {
-                    // emulate CRL exception message in RFC3280CertPathUtilities.checkCRLs
-                    String message = "Certificate revocation of serial 0x" + serial.toString(16);
-                    System.out.println(message);
-                    AnnotatedException e = new AnnotatedException(message);
-                    throw new CertPathValidatorException(e.getMessage(), e, certPath, 0);
-                }
-            }
-        }
-        // END Android-added: Support blocklisting known-bad certs
 
         //
         // (b)
@@ -326,15 +305,6 @@ public class PKIXCertPathValidatorSpi
 
         for (index = certs.size() - 1; index >= 0; index--)
         {
-            // BEGIN Android-added: Support blocklisting known-bad certs
-            if (NoPreloadHolder.blocklist.isPublicKeyBlockListed(workingPublicKey)) {
-                // emulate CRL exception message in RFC3280CertPathUtilities.checkCRLs
-                String message = "Certificate revocation of public key " + workingPublicKey;
-                System.out.println(message);
-                AnnotatedException e = new AnnotatedException(message);
-                throw new CertPathValidatorException(e.getMessage(), e, certPath, index);
-            }
-            // END Android-added: Support blocklisting known-bad certs
             // try
             // {
             //
diff --git a/proguard.flags b/proguard.flags
index 1dae437e..039fdbee 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -178,9 +178,35 @@
 -keep class com.android.org.bouncycastle.util.encoders.Hex { public *; }
 
 # Classes only accessed from tests in CtsLibcoreTestCases
-# tests.com.android.org.bouncycastle.jce.provider.CertBlocklistTest
--keep class com.android.org.bouncycastle.jce.provider.CertBlocklist { public *; }
--keep class com.android.org.bouncycastle.util.encoders.Base64 { public *; }
 # tests.com.android.org.bouncycastle.crypto.digests
 -keep class com.android.org.bouncycastle.crypto.digests.*Digest { public *; }
 -keep class com.android.org.bouncycastle.crypto.digests.OpenSSLDigest$* { public *; }
+
+# Unsupported usage by vendors, from b/356844860#comment19 and b/365088430#comment5
+-keep class com.android.org.bouncycastle.asn1.ASN1EncodableVector { public *; }
+-keep class com.android.org.bouncycastle.asn1.ASN1InputStream { public *; }
+-keep class com.android.org.bouncycastle.asn1.ASN1Integer {}
+-keep class com.android.org.bouncycastle.asn1.ASN1Object { public *; }
+-keep class com.android.org.bouncycastle.asn1.ASN1OctetString { public *; }
+-keep class com.android.org.bouncycastle.asn1.ASN1Sequence {}
+-keep class com.android.org.bouncycastle.asn1.DERBitString {}
+-keep class com.android.org.bouncycastle.asn1.DERNull {}
+-keep class com.android.org.bouncycastle.asn1.DEROctetString { public *; }
+-keep class com.android.org.bouncycastle.asn1.DERSequence {}
+-keep class com.android.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers {}
+-keep class com.android.org.bouncycastle.asn1.x509.AlgorithmIdentifier {}
+-keep class com.android.org.bouncycastle.asn1.x509.BasicConstraints { public *; }
+-keep class com.android.org.bouncycastle.asn1.x509.Certificate { public *; }
+-keep class com.android.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo { public *; }
+-keep class com.android.org.bouncycastle.asn1.x509.Time {}
+-keep class com.android.org.bouncycastle.asn1.x509.V3TBSCertificateGenerator { public *; }
+-keep class com.android.org.bouncycastle.asn1.x509.X509Name { public *; }
+-keep class com.android.org.bouncycastle.asn1.x9.X9ObjectIdentifiers {}
+-keep class com.android.org.bouncycastle.jce.ECNamedCurveTable { public *; }
+-keep class com.android.org.bouncycastle.jce.X509Principal {}
+-keep class com.android.org.bouncycastle.jce.provider.X509CertificateObject {}
+-keep class com.android.org.bouncycastle.jce.spec.ECParameterSpec { public *; }
+-keep class com.android.org.bouncycastle.math.ec.ECCurve { public *; }
+-keep class com.android.org.bouncycastle.math.ec.ECPoint { public *; }
+-keep class com.android.org.bouncycastle.util.BigIntegers { public *; }
+-keep class com.android.org.bouncycastle.x509.X509V3CertificateGenerator { public *; }
diff --git a/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/CertBlocklist.java b/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/CertBlocklist.java
deleted file mode 100644
index a7689e08..00000000
--- a/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/CertBlocklist.java
+++ /dev/null
@@ -1,238 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2012 The Android Open Source Project
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
-
-package com.android.org.bouncycastle.jce.provider;
-
-import java.io.Closeable;
-import java.io.ByteArrayOutputStream;
-import java.io.FileNotFoundException;
-import java.io.IOException;
-import java.io.RandomAccessFile;
-import java.math.BigInteger;
-import java.security.PublicKey;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.HashSet;
-import java.util.Set;
-import java.util.logging.Level;
-import java.util.logging.Logger;
-import com.android.org.bouncycastle.crypto.Digest;
-import com.android.org.bouncycastle.crypto.digests.AndroidDigestFactory;
-import com.android.org.bouncycastle.util.encoders.Hex;
-
-/**
- * @hide This class is not part of the Android public SDK API
- */
-public class CertBlocklist {
-    private static final Logger logger = Logger.getLogger(CertBlocklist.class.getName());
-
-    // public for testing
-    public final Set<BigInteger> serialBlocklist;
-    public final Set<byte[]> pubkeyBlocklist;
-
-    public CertBlocklist() {
-        String androidData = System.getenv("ANDROID_DATA");
-        String blocklistRoot = androidData + "/misc/keychain/";
-        // TODO(b/162575432): change these paths to use inclusive language
-        String defaultPubkeyBlocklistPath = blocklistRoot + "pubkey_blacklist.txt";
-        String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";
-
-        pubkeyBlocklist = readPublicKeyBlockList(defaultPubkeyBlocklistPath);
-        serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
-    }
-
-    /** Test only interface, not for public use */
-    public CertBlocklist(String pubkeyBlocklistPath, String serialBlocklistPath) {
-        pubkeyBlocklist = readPublicKeyBlockList(pubkeyBlocklistPath);
-        serialBlocklist = readSerialBlockList(serialBlocklistPath);
-    }
-
-    private static boolean isHex(String value) {
-        try {
-            new BigInteger(value, 16);
-            return true;
-        } catch (NumberFormatException e) {
-            logger.log(Level.WARNING, "Could not parse hex value " + value, e);
-            return false;
-        }
-    }
-
-    private static boolean isPubkeyHash(String value) {
-        if (value.length() != 40) {
-            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
-            return false;
-        }
-        return isHex(value);
-    }
-
-    private static String readBlocklist(String path) {
-        try {
-            return readFileAsString(path);
-        } catch (FileNotFoundException ignored) {
-        } catch (IOException e) {
-            logger.log(Level.WARNING, "Could not read blocklist", e);
-        }
-        return "";
-    }
-
-    // From IoUtils.readFileAsString
-    private static String readFileAsString(String path) throws IOException {
-        return readFileAsBytes(path).toString("UTF-8");
-    }
-
-    // Based on IoUtils.readFileAsBytes
-    private static ByteArrayOutputStream readFileAsBytes(String path) throws IOException {
-        RandomAccessFile f = null;
-        try {
-            f = new RandomAccessFile(path, "r");
-            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) f.length());
-            byte[] buffer = new byte[8192];
-            while (true) {
-                int byteCount = f.read(buffer);
-                if (byteCount == -1) {
-                    return bytes;
-                }
-                bytes.write(buffer, 0, byteCount);
-            }
-        } finally {
-            closeQuietly(f);
-        }
-    }
-
-    // Base on IoUtils.closeQuietly
-    private static void closeQuietly(Closeable closeable) {
-        if (closeable != null) {
-            try {
-                closeable.close();
-            } catch (RuntimeException rethrown) {
-                throw rethrown;
-            } catch (Exception ignored) {
-            }
-        }
-    }
-
-    private static Set<BigInteger> readSerialBlockList(String path) {
-
-        /* Start out with a base set of known bad values.
-         *
-         * WARNING: Do not add short serials to this list!
-         *
-         * Since this currently doesn't compare the serial + issuer, you
-         * should only add serials that have enough entropy here. Short
-         * serials may inadvertently match a certificate that was issued
-         * not in compliance with the Baseline Requirements.
-         */
-        Set<BigInteger> bl = new HashSet<BigInteger>(Arrays.asList(
-            // From http://src.chromium.org/viewvc/chrome/trunk/src/net/base/x509_certificate.cc?revision=78748&view=markup
-            // Not a real certificate. For testing only.
-            new BigInteger("077a59bcd53459601ca6907267a6dd1c", 16),
-            new BigInteger("047ecbe9fca55f7bd09eae36e10cae1e", 16),
-            new BigInteger("d8f35f4eb7872b2dab0692e315382fb0", 16),
-            new BigInteger("b0b7133ed096f9b56fae91c874bd3ac0", 16),
-            new BigInteger("9239d5348f40d1695a745470e1f23f43", 16),
-            new BigInteger("e9028b9578e415dc1a710a2b88154447", 16),
-            new BigInteger("d7558fdaf5f1105bb213282b707729a3", 16),
-            new BigInteger("f5c86af36162f13a64f54f6dc9587c06", 16),
-            new BigInteger("392a434f0e07df1f8aa305de34e0c229", 16),
-            new BigInteger("3e75ced46b693021218830ae86a82a71", 16)
-        ));
-
-        // attempt to augment it with values taken from gservices
-        String serialBlocklist = readBlocklist(path);
-        if (!serialBlocklist.equals("")) {
-            for(String value : serialBlocklist.split(",")) {
-                try {
-                    bl.add(new BigInteger(value, 16));
-                } catch (NumberFormatException e) {
-                    logger.log(Level.WARNING, "Tried to blocklist invalid serial number " + value, e);
-                }
-            }
-        }
-
-        // whether that succeeds or fails, send it on its merry way
-        return Collections.unmodifiableSet(bl);
-    }
-
-    private static Set<byte[]> readPublicKeyBlockList(String path) {
-
-        // start out with a base set of known bad values
-        Set<byte[]> bl = new HashSet<byte[]>(Arrays.asList(
-            // From http://src.chromium.org/viewvc/chrome/branches/782/src/net/base/x509_certificate.cc?r1=98750&r2=98749&pathrev=98750
-            // C=NL, O=DigiNotar, CN=DigiNotar Root CA/emailAddress=info@diginotar.nl
-            "410f36363258f30b347d12ce4863e433437806a8".getBytes(),
-            // Subject: CN=DigiNotar Cyber CA
-            // Issuer: CN=GTE CyberTrust Global Root
-            "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37".getBytes(),
-            // Subject: CN=DigiNotar Services 1024 CA
-            // Issuer: CN=Entrust.net
-            "e23b8d105f87710a68d9248050ebefc627be4ca6".getBytes(),
-            // Subject: CN=DigiNotar PKIoverheid CA Organisatie - G2
-            // Issuer: CN=Staat der Nederlanden Organisatie CA - G2
-            "7b2e16bc39bcd72b456e9f055d1de615b74945db".getBytes(),
-            // Subject: CN=DigiNotar PKIoverheid CA Overheid en Bedrijven
-            // Issuer: CN=Staat der Nederlanden Overheid CA
-            "e8f91200c65cee16e039b9f883841661635f81c5".getBytes(),
-            // From http://src.chromium.org/viewvc/chrome?view=rev&revision=108479
-            // Subject: O=Digicert Sdn. Bhd.
-            // Issuer: CN=GTE CyberTrust Global Root
-            "0129bcd5b448ae8d2496d1c3e19723919088e152".getBytes(),
-            // Subject: CN=e-islem.kktcmerkezbankasi.org/emailAddress=ileti@kktcmerkezbankasi.org
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "5f3ab33d55007054bc5e3e5553cd8d8465d77c61".getBytes(),
-            // Subject: CN=*.EGO.GOV.TR 93
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "783333c9687df63377efceddd82efa9101913e8e".getBytes(),
-            // Subject: Subject: C=FR, O=DG Tr\xC3\xA9sor, CN=AC DG Tr\xC3\xA9sor SSL
-            // Issuer: C=FR, O=DGTPE, CN=AC DGTPE Signature Authentification
-            "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf".getBytes()
-        ));
-
-        // attempt to augment it with values taken from gservices
-        String pubkeyBlocklist = readBlocklist(path);
-        if (!pubkeyBlocklist.equals("")) {
-            for (String value : pubkeyBlocklist.split(",")) {
-                value = value.trim();
-                if (isPubkeyHash(value)) {
-                    bl.add(value.getBytes());
-                } else {
-                    logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
-                }
-            }
-        }
-
-        return bl;
-    }
-
-    public boolean isPublicKeyBlockListed(PublicKey publicKey) {
-        byte[] encoded = publicKey.getEncoded();
-        Digest digest = AndroidDigestFactory.getSHA1();
-        digest.update(encoded, 0, encoded.length);
-        byte[] out = new byte[digest.getDigestSize()];
-        digest.doFinal(out, 0);
-        for (byte[] blocklisted : pubkeyBlocklist) {
-            if (Arrays.equals(blocklisted, Hex.encode(out))) {
-                return true;
-            }
-        }
-        return false;
-    }
-
-    public boolean isSerialNumberBlockListed(BigInteger serial) {
-        return serialBlocklist.contains(serial);
-    }
-
-}
diff --git a/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java b/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
index 497d7d6d..6f51df35 100644
--- a/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
+++ b/repackaged/bcprov/src/main/java/com/android/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
@@ -57,11 +57,6 @@ public class PKIXCertPathValidatorSpi
     {
         this.isForCRLCheck = isForCRLCheck;
     }
-    // BEGIN Android-added: Avoid loading blocklist during class init
-    private static class NoPreloadHolder {
-        private final static CertBlocklist blocklist = new CertBlocklist();
-    }
-    // END Android-added: Avoid loading blocklist during class init
 
     public CertPathValidatorResult engineValidate(
             CertPath certPath,
@@ -117,22 +112,6 @@ public class PKIXCertPathValidatorSpi
         {
             throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
         }
-        // BEGIN Android-added: Support blocklisting known-bad certs
-        {
-            X509Certificate cert = (X509Certificate) certs.get(0);
-
-            if (cert != null) {
-                BigInteger serial = cert.getSerialNumber();
-                if (NoPreloadHolder.blocklist.isSerialNumberBlockListed(serial)) {
-                    // emulate CRL exception message in RFC3280CertPathUtilities.checkCRLs
-                    String message = "Certificate revocation of serial 0x" + serial.toString(16);
-                    System.out.println(message);
-                    AnnotatedException e = new AnnotatedException(message);
-                    throw new CertPathValidatorException(e.getMessage(), e, certPath, 0);
-                }
-            }
-        }
-        // END Android-added: Support blocklisting known-bad certs
 
         //
         // (b)
@@ -328,15 +307,6 @@ public class PKIXCertPathValidatorSpi
 
         for (index = certs.size() - 1; index >= 0; index--)
         {
-            // BEGIN Android-added: Support blocklisting known-bad certs
-            if (NoPreloadHolder.blocklist.isPublicKeyBlockListed(workingPublicKey)) {
-                // emulate CRL exception message in RFC3280CertPathUtilities.checkCRLs
-                String message = "Certificate revocation of public key " + workingPublicKey;
-                System.out.println(message);
-                AnnotatedException e = new AnnotatedException(message);
-                throw new CertPathValidatorException(e.getMessage(), e, certPath, index);
-            }
-            // END Android-added: Support blocklisting known-bad certs
             // try
             // {
             //
diff --git a/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/CertBlocklist.java b/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/CertBlocklist.java
deleted file mode 100644
index 185f4b69..00000000
--- a/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/CertBlocklist.java
+++ /dev/null
@@ -1,238 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2012 The Android Open Source Project
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
-
-package com.android.internal.org.bouncycastle.jce.provider;
-
-import java.io.Closeable;
-import java.io.ByteArrayOutputStream;
-import java.io.FileNotFoundException;
-import java.io.IOException;
-import java.io.RandomAccessFile;
-import java.math.BigInteger;
-import java.security.PublicKey;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.HashSet;
-import java.util.Set;
-import java.util.logging.Level;
-import java.util.logging.Logger;
-import com.android.internal.org.bouncycastle.crypto.Digest;
-import com.android.internal.org.bouncycastle.crypto.digests.AndroidDigestFactory;
-import com.android.internal.org.bouncycastle.util.encoders.Hex;
-
-/**
- * @hide This class is not part of the Android public SDK API
- */
-public class CertBlocklist {
-    private static final Logger logger = Logger.getLogger(CertBlocklist.class.getName());
-
-    // public for testing
-    public final Set<BigInteger> serialBlocklist;
-    public final Set<byte[]> pubkeyBlocklist;
-
-    public CertBlocklist() {
-        String androidData = System.getenv("ANDROID_DATA");
-        String blocklistRoot = androidData + "/misc/keychain/";
-        // TODO(b/162575432): change these paths to use inclusive language
-        String defaultPubkeyBlocklistPath = blocklistRoot + "pubkey_blacklist.txt";
-        String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";
-
-        pubkeyBlocklist = readPublicKeyBlockList(defaultPubkeyBlocklistPath);
-        serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
-    }
-
-    /** Test only interface, not for public use */
-    public CertBlocklist(String pubkeyBlocklistPath, String serialBlocklistPath) {
-        pubkeyBlocklist = readPublicKeyBlockList(pubkeyBlocklistPath);
-        serialBlocklist = readSerialBlockList(serialBlocklistPath);
-    }
-
-    private static boolean isHex(String value) {
-        try {
-            new BigInteger(value, 16);
-            return true;
-        } catch (NumberFormatException e) {
-            logger.log(Level.WARNING, "Could not parse hex value " + value, e);
-            return false;
-        }
-    }
-
-    private static boolean isPubkeyHash(String value) {
-        if (value.length() != 40) {
-            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
-            return false;
-        }
-        return isHex(value);
-    }
-
-    private static String readBlocklist(String path) {
-        try {
-            return readFileAsString(path);
-        } catch (FileNotFoundException ignored) {
-        } catch (IOException e) {
-            logger.log(Level.WARNING, "Could not read blocklist", e);
-        }
-        return "";
-    }
-
-    // From IoUtils.readFileAsString
-    private static String readFileAsString(String path) throws IOException {
-        return readFileAsBytes(path).toString("UTF-8");
-    }
-
-    // Based on IoUtils.readFileAsBytes
-    private static ByteArrayOutputStream readFileAsBytes(String path) throws IOException {
-        RandomAccessFile f = null;
-        try {
-            f = new RandomAccessFile(path, "r");
-            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) f.length());
-            byte[] buffer = new byte[8192];
-            while (true) {
-                int byteCount = f.read(buffer);
-                if (byteCount == -1) {
-                    return bytes;
-                }
-                bytes.write(buffer, 0, byteCount);
-            }
-        } finally {
-            closeQuietly(f);
-        }
-    }
-
-    // Base on IoUtils.closeQuietly
-    private static void closeQuietly(Closeable closeable) {
-        if (closeable != null) {
-            try {
-                closeable.close();
-            } catch (RuntimeException rethrown) {
-                throw rethrown;
-            } catch (Exception ignored) {
-            }
-        }
-    }
-
-    private static Set<BigInteger> readSerialBlockList(String path) {
-
-        /* Start out with a base set of known bad values.
-         *
-         * WARNING: Do not add short serials to this list!
-         *
-         * Since this currently doesn't compare the serial + issuer, you
-         * should only add serials that have enough entropy here. Short
-         * serials may inadvertently match a certificate that was issued
-         * not in compliance with the Baseline Requirements.
-         */
-        Set<BigInteger> bl = new HashSet<BigInteger>(Arrays.asList(
-            // From http://src.chromium.org/viewvc/chrome/trunk/src/net/base/x509_certificate.cc?revision=78748&view=markup
-            // Not a real certificate. For testing only.
-            new BigInteger("077a59bcd53459601ca6907267a6dd1c", 16),
-            new BigInteger("047ecbe9fca55f7bd09eae36e10cae1e", 16),
-            new BigInteger("d8f35f4eb7872b2dab0692e315382fb0", 16),
-            new BigInteger("b0b7133ed096f9b56fae91c874bd3ac0", 16),
-            new BigInteger("9239d5348f40d1695a745470e1f23f43", 16),
-            new BigInteger("e9028b9578e415dc1a710a2b88154447", 16),
-            new BigInteger("d7558fdaf5f1105bb213282b707729a3", 16),
-            new BigInteger("f5c86af36162f13a64f54f6dc9587c06", 16),
-            new BigInteger("392a434f0e07df1f8aa305de34e0c229", 16),
-            new BigInteger("3e75ced46b693021218830ae86a82a71", 16)
-        ));
-
-        // attempt to augment it with values taken from gservices
-        String serialBlocklist = readBlocklist(path);
-        if (!serialBlocklist.equals("")) {
-            for(String value : serialBlocklist.split(",")) {
-                try {
-                    bl.add(new BigInteger(value, 16));
-                } catch (NumberFormatException e) {
-                    logger.log(Level.WARNING, "Tried to blocklist invalid serial number " + value, e);
-                }
-            }
-        }
-
-        // whether that succeeds or fails, send it on its merry way
-        return Collections.unmodifiableSet(bl);
-    }
-
-    private static Set<byte[]> readPublicKeyBlockList(String path) {
-
-        // start out with a base set of known bad values
-        Set<byte[]> bl = new HashSet<byte[]>(Arrays.asList(
-            // From http://src.chromium.org/viewvc/chrome/branches/782/src/net/base/x509_certificate.cc?r1=98750&r2=98749&pathrev=98750
-            // C=NL, O=DigiNotar, CN=DigiNotar Root CA/emailAddress=info@diginotar.nl
-            "410f36363258f30b347d12ce4863e433437806a8".getBytes(),
-            // Subject: CN=DigiNotar Cyber CA
-            // Issuer: CN=GTE CyberTrust Global Root
-            "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37".getBytes(),
-            // Subject: CN=DigiNotar Services 1024 CA
-            // Issuer: CN=Entrust.net
-            "e23b8d105f87710a68d9248050ebefc627be4ca6".getBytes(),
-            // Subject: CN=DigiNotar PKIoverheid CA Organisatie - G2
-            // Issuer: CN=Staat der Nederlanden Organisatie CA - G2
-            "7b2e16bc39bcd72b456e9f055d1de615b74945db".getBytes(),
-            // Subject: CN=DigiNotar PKIoverheid CA Overheid en Bedrijven
-            // Issuer: CN=Staat der Nederlanden Overheid CA
-            "e8f91200c65cee16e039b9f883841661635f81c5".getBytes(),
-            // From http://src.chromium.org/viewvc/chrome?view=rev&revision=108479
-            // Subject: O=Digicert Sdn. Bhd.
-            // Issuer: CN=GTE CyberTrust Global Root
-            "0129bcd5b448ae8d2496d1c3e19723919088e152".getBytes(),
-            // Subject: CN=e-islem.kktcmerkezbankasi.org/emailAddress=ileti@kktcmerkezbankasi.org
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "5f3ab33d55007054bc5e3e5553cd8d8465d77c61".getBytes(),
-            // Subject: CN=*.EGO.GOV.TR 93
-            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
-            "783333c9687df63377efceddd82efa9101913e8e".getBytes(),
-            // Subject: Subject: C=FR, O=DG Tr\xC3\xA9sor, CN=AC DG Tr\xC3\xA9sor SSL
-            // Issuer: C=FR, O=DGTPE, CN=AC DGTPE Signature Authentification
-            "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf".getBytes()
-        ));
-
-        // attempt to augment it with values taken from gservices
-        String pubkeyBlocklist = readBlocklist(path);
-        if (!pubkeyBlocklist.equals("")) {
-            for (String value : pubkeyBlocklist.split(",")) {
-                value = value.trim();
-                if (isPubkeyHash(value)) {
-                    bl.add(value.getBytes());
-                } else {
-                    logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
-                }
-            }
-        }
-
-        return bl;
-    }
-
-    public boolean isPublicKeyBlockListed(PublicKey publicKey) {
-        byte[] encoded = publicKey.getEncoded();
-        Digest digest = AndroidDigestFactory.getSHA1();
-        digest.update(encoded, 0, encoded.length);
-        byte[] out = new byte[digest.getDigestSize()];
-        digest.doFinal(out, 0);
-        for (byte[] blocklisted : pubkeyBlocklist) {
-            if (Arrays.equals(blocklisted, Hex.encode(out))) {
-                return true;
-            }
-        }
-        return false;
-    }
-
-    public boolean isSerialNumberBlockListed(BigInteger serial) {
-        return serialBlocklist.contains(serial);
-    }
-
-}
diff --git a/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java b/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
index fe1bd4f3..67d3595d 100644
--- a/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
+++ b/repackaged_platform/bcprov/src/main/java/com/android/internal/org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.java
@@ -57,11 +57,6 @@ public class PKIXCertPathValidatorSpi
     {
         this.isForCRLCheck = isForCRLCheck;
     }
-    // BEGIN Android-added: Avoid loading blocklist during class init
-    private static class NoPreloadHolder {
-        private final static CertBlocklist blocklist = new CertBlocklist();
-    }
-    // END Android-added: Avoid loading blocklist during class init
 
     public CertPathValidatorResult engineValidate(
             CertPath certPath,
@@ -117,22 +112,6 @@ public class PKIXCertPathValidatorSpi
         {
             throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
         }
-        // BEGIN Android-added: Support blocklisting known-bad certs
-        {
-            X509Certificate cert = (X509Certificate) certs.get(0);
-
-            if (cert != null) {
-                BigInteger serial = cert.getSerialNumber();
-                if (NoPreloadHolder.blocklist.isSerialNumberBlockListed(serial)) {
-                    // emulate CRL exception message in RFC3280CertPathUtilities.checkCRLs
-                    String message = "Certificate revocation of serial 0x" + serial.toString(16);
-                    System.out.println(message);
-                    AnnotatedException e = new AnnotatedException(message);
-                    throw new CertPathValidatorException(e.getMessage(), e, certPath, 0);
-                }
-            }
-        }
-        // END Android-added: Support blocklisting known-bad certs
 
         //
         // (b)
@@ -328,15 +307,6 @@ public class PKIXCertPathValidatorSpi
 
         for (index = certs.size() - 1; index >= 0; index--)
         {
-            // BEGIN Android-added: Support blocklisting known-bad certs
-            if (NoPreloadHolder.blocklist.isPublicKeyBlockListed(workingPublicKey)) {
-                // emulate CRL exception message in RFC3280CertPathUtilities.checkCRLs
-                String message = "Certificate revocation of public key " + workingPublicKey;
-                System.out.println(message);
-                AnnotatedException e = new AnnotatedException(message);
-                throw new CertPathValidatorException(e.getMessage(), e, certPath, index);
-            }
-            // END Android-added: Support blocklisting known-bad certs
             // try
             // {
             //
```

