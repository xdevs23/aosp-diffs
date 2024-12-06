```diff
diff --git a/.clang-format b/.clang-format
index 1f39c81a..c05d06f8 100644
--- a/.clang-format
+++ b/.clang-format
@@ -13,5 +13,15 @@ BasedOnStyle: Google
 ColumnLimit: 100
 IndentWidth: 4
 ContinuationIndentWidth: 8
-...
-
+JavaImportGroups:
+- android
+- androidx
+- com.android
+- dalvik
+- libcore
+- com
+- junit
+- net
+- org
+- java
+- javax
diff --git a/Android.bp b/Android.bp
index d2aea1af..b5702902 100644
--- a/Android.bp
+++ b/Android.bp
@@ -185,6 +185,31 @@ cc_library_host_shared {
     },
 }
 
+aconfig_declarations {
+    name: "conscrypt-aconfig-flags",
+    package: "com.android.org.conscrypt",
+    container: "com.android.conscrypt",
+    srcs: ["conscrypt.aconfig"],
+}
+
+java_aconfig_library {
+    name: "conscrypt-aconfig-flags-lib",
+    aconfig_declarations: "conscrypt-aconfig-flags",
+    system_modules: "art-module-intra-core-api-stubs-system-modules",
+    libs: [
+        "aconfig-annotations-lib-sdk-none",
+        "unsupportedappusage",
+    ],
+    sdk_version: "none",
+    patch_module: "java.base",
+    apex_available: [
+        "com.android.conscrypt",
+    ],
+    min_sdk_version: "30",
+    installable: false,
+    visibility: ["//visibility:private"],
+}
+
 cc_binary_host {
     name: "conscrypt_generate_constants",
     srcs: ["constants/src/gen/cpp/generate_constants.cc"],
@@ -253,6 +278,9 @@ java_library {
     ],
 
     libs: ["unsupportedappusage"],
+    static_libs: [
+        "conscrypt-aconfig-flags-lib",
+    ],
 
     // Conscrypt can be updated independently from the other core libraries so it must only depend
     // on public SDK and intra-core APIs.
@@ -480,6 +508,12 @@ java_sdk_library {
     sdk_version: "none",
     system_modules: "art-module-intra-core-api-stubs-system-modules",
 
+    // This module's output stubs contain apis defined in "conscrypt.module.public.api.stubs",
+    // but adding "conscrypt.module.public.api" as a dependency of this module leads to circular
+    // dependency and requires further bootstrapping. Thus, disable stubs generation from the
+    // api signature files and generate stubs from the source Java files instead.
+    build_from_text_stub: false,
+
     // Don't copy any output files to the dist.
     no_dist: true,
 }
@@ -506,7 +540,10 @@ cc_library_shared {
     name: "libjavacrypto",
     host_supported: true,
     defaults: ["libjavacrypto-defaults"],
-
+    visibility: [
+        ":__subpackages__",
+        "//art/tools/ahat",
+    ],
     cflags: ["-DJNI_JARJAR_PREFIX=com/android/"],
     header_libs: ["libnativehelper_header_only"],
     shared_libs: ["liblog"],
@@ -591,6 +628,7 @@ java_library {
         "common/src/main/java/**/HpkeSpi.java",
         "common/src/main/java/**/HpkeSuite.java",
         "common/src/main/java/**/Internal.java",
+        "common/src/main/java/**/Preconditions.java",
         "common/src/main/java/**/XdhKeySpec.java",
     ],
     jarjar_rules: "conscrypt-lite-jarjar-rules.txt",
@@ -617,6 +655,25 @@ cc_library_static {
     stl: "c++_shared",
 }
 
+java_library {
+    name: "conscrypt-test-support",
+    visibility: [
+        "//frameworks/base/apct-tests/perftests/core",
+    ],
+    device_supported: true,
+    host_supported: true,
+    srcs: [
+        "testing/src/main/java/**/*.java",
+        ":conscrypt-unbundled_generated_constants",
+    ],
+    libs: [
+        "junit",
+        "bouncycastle-unbundled",
+        "bouncycastle-bcpkix-unbundled",
+        "bouncycastle-ocsp-unbundled",
+    ],
+}
+
 // Make the conscrypt-tests library.
 java_test {
     name: "conscrypt-tests",
@@ -627,8 +684,12 @@ java_test {
     ],
     hostdex: true,
     srcs: [
-        "repackaged/platform/src/test/java/**/*.java",
-        "repackaged/common/src/test/java/**/*.java",
+        "repackaged/platform/src/test/java/com/android/org/conscrypt/TrustedCertificateStoreTest.java",
+        "repackaged/platform/src/test/java/com/android/org/conscrypt/metrics/*.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/*.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/metrics/*.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/java/**/*.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/javax/**/*.java",
         "repackaged/testing/src/main/java/**/*.java",
         "publicapi/src/test/java/**/*.java",
     ],
@@ -671,6 +732,46 @@ java_test {
     java_version: "1.8",
 }
 
+// Conscrypt private tests. These tests relies on private APIs. Prefer adding
+// your test to conscrypt-tests if possible, as these will be executed as part
+// of CTS (see CtsLibcoreTestCases).
+android_test {
+    name: "ConscryptPrivateTestCases",
+    srcs: [
+        "repackaged/platform/src/test/java/com/android/org/conscrypt/ct/*.java",
+        "repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/ct/*.java",
+        "repackaged/testing/src/main/java/**/*.java",
+    ],
+
+    java_resource_dirs: [
+        // Resource directories do not need repackaging.
+        "openjdk/src/test/resources",
+        "common/src/test/resources",
+    ],
+
+    platform_apis: true,
+    manifest: "AndroidManifest-private.xml",
+    test_config: "AndroidTest-private.xml",
+    libs: [
+        "conscrypt",
+        "core-test-rules",
+        "junit",
+        "mockito-target-minus-junit4",
+        "framework-statsd.stubs.module_lib",
+    ],
+
+    static_libs: [
+        "androidx.test.runner",
+        "androidx.test.rules",
+        "bouncycastle-unbundled",
+        "bouncycastle-bcpkix-unbundled",
+        "bouncycastle-ocsp-unbundled",
+    ],
+    java_version: "1.8",
+    test_suites: ["general-tests"],
+}
+
 // Make the conscrypt-benchmarks library.
 java_test {
     name: "conscrypt-benchmarks",
diff --git a/android-stub/src/main/java/javax/net/ssl/ExtendedSSLSession.java b/AndroidManifest-private.xml
similarity index 50%
rename from android-stub/src/main/java/javax/net/ssl/ExtendedSSLSession.java
rename to AndroidManifest-private.xml
index c8991709..377bd97a 100644
--- a/android-stub/src/main/java/javax/net/ssl/ExtendedSSLSession.java
+++ b/AndroidManifest-private.xml
@@ -1,5 +1,6 @@
-/*
- * Copyright 2016 The Android Open Source Project
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -12,25 +13,14 @@
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
- */
+ -->
 
-package javax.net.ssl;
-
-import java.util.List;
-
-/**
- * This is a stub class used for compiling against.
- */
-public abstract class ExtendedSSLSession implements SSLSession {
-
-    protected ExtendedSSLSession() {
-    }
-
-    public abstract String[] getLocalSupportedSignatureAlgorithms();
-
-    public abstract String[] getPeerSupportedSignatureAlgorithms();
-
-    public List<SNIServerName> getRequestedServerNames() {
-        return null;
-    }
-}
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android.conscrypt.tests">
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="android.conscrypt.tests"
+                     android:label="Conscrypt private test cases">
+    </instrumentation>
+</manifest>
diff --git a/AndroidTest-private.xml b/AndroidTest-private.xml
new file mode 100644
index 00000000..ea31fab1
--- /dev/null
+++ b/AndroidTest-private.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config for conscrypt private test cases">
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <!-- this has just the instrumentation which acts as the tests we want to run -->
+        <option name="test-file-name" value="ConscryptPrivateTestCases.apk" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="android.conscrypt.tests" />
+        <option name="hidden-api-checks" value="false"/>
+    </test>
+</configuration>
diff --git a/BUILDING.md b/BUILDING.md
index 952abf4f..7ac7f8e9 100644
--- a/BUILDING.md
+++ b/BUILDING.md
@@ -110,8 +110,7 @@ mkdir build64
 cd build64
 cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ^
       -DCMAKE_BUILD_TYPE=Release ^
-      -DCMAKE_C_FLAGS_RELEASE=/MT ^
-      -DCMAKE_CXX_FLAGS_RELEASE=/MT ^
+      -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
       -GNinja ..
 ninja
 ```
diff --git a/README.md b/README.md
index c63c5edd..3a7a8247 100644
--- a/README.md
+++ b/README.md
@@ -28,8 +28,8 @@ similar performance.
 
 Download
 -------------
-Conscrypt supports **Java 7** or later on OpenJDK and **Gingerbread (API Level
-9)** or later on Android.  The build artifacts are available on Maven Central.
+Conscrypt supports **Java 8** or later on OpenJDK and **KitKat (API Level
+19)** or later on Android.  The build artifacts are available on Maven Central.
 
 ### Download JARs
 You can download
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 00000000..59d91def
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,40 @@
+{
+  "presubmit": [
+    {
+      "name": "CtsLibcoreTestCases",
+      "options": [
+        {
+          "include-filter": "com.android.org.conscrypt"
+        },
+        {
+          "include-filter": "libcore.java.security"
+        },
+        {
+          "include-filter": "libcore.javax.net"
+        },
+        {
+          "include-filter": "libcore.java.net"
+        },
+        {
+          "include-filter": "android.net.ssl"
+        }
+      ]
+    },
+    {
+      "name": "CtsSecurityTestCases",
+      "options": [
+        {
+          "include-filter": "android.security.cts.CertBlocklistTest"
+        },
+        {
+          "include-filter": "android.security.cts.CertBlocklistFileTest"
+        }
+      ]
+    }
+  ],
+  "postsubmit": [
+    {
+      "name": "ConscryptPrivateTestCases"
+    }
+  ]
+}
diff --git a/android-stub/src/main/java/javax/net/ssl/SNIHostName.java b/android-stub/src/main/java/javax/net/ssl/SNIHostName.java
deleted file mode 100644
index 559ff95f..00000000
--- a/android-stub/src/main/java/javax/net/ssl/SNIHostName.java
+++ /dev/null
@@ -1,30 +0,0 @@
-/*
- * Copyright 2016 The Android Open Source Project
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
-package javax.net.ssl;
-
-/**
- * Stub class for compiling unbundled.
- */
-public final class SNIHostName extends SNIServerName {
-    public SNIHostName(String hostname) {
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    public String getAsciiName() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-}
diff --git a/android-stub/src/main/java/javax/net/ssl/SNIServerName.java b/android-stub/src/main/java/javax/net/ssl/SNIServerName.java
deleted file mode 100644
index 2ed8e52b..00000000
--- a/android-stub/src/main/java/javax/net/ssl/SNIServerName.java
+++ /dev/null
@@ -1,30 +0,0 @@
-/*
- * Copyright 2016 The Android Open Source Project
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
-package javax.net.ssl;
-
-/**
- * Stub class for compiling unbundled.
- */
-public class SNIServerName {
-    protected SNIServerName() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    public final int getType() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-}
diff --git a/android-stub/src/main/java/javax/net/ssl/StandardConstants.java b/android-stub/src/main/java/javax/net/ssl/StandardConstants.java
deleted file mode 100644
index 03e33c82..00000000
--- a/android-stub/src/main/java/javax/net/ssl/StandardConstants.java
+++ /dev/null
@@ -1,28 +0,0 @@
-/*
- * Copyright 2016 The Android Open Source Project
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
-package javax.net.ssl;
-
-/**
- * Stub class for compiling unbundled.
- */
-public final class StandardConstants {
-    private StandardConstants() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    public static final int SNI_HOST_NAME = 0;
-}
diff --git a/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/NativeCrypto.java b/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/NativeCrypto.java
deleted file mode 100644
index 7ace28d6..00000000
--- a/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/NativeCrypto.java
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright 2015 The Android Open Source Project
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
-package org.apache.harmony.xnet.provider.jsse;
-
-import java.security.cert.CertificateEncodingException;
-import java.security.cert.CertificateException;
-import javax.net.ssl.SSLException;
-
-final class NativeCrypto {
-    public interface SSLHandshakeCallbacks {
-        /**
-         * Verify that we trust the certificate chain is trusted.
-         *
-         * @param asn1DerEncodedCertificateChain A chain of ASN.1 DER encoded certificates
-         * @param authMethod auth algorithm name
-         *
-         * @throws CertificateException if the certificate is untrusted
-         */
-        void verifyCertificateChain(byte[][] asn1DerEncodedCertificateChain,
-                String authMethod) throws CertificateException;
-        /**
-         * Called on an SSL client when the server requests (or
-         * requires a certificate). The client can respond by using
-         * SSL_use_certificate and SSL_use_PrivateKey to set a
-         * certificate if has an appropriate one available, similar to
-         * how the server provides its certificate.
-         *
-         * @param keyTypes key types supported by the server,
-         * convertible to strings with #keyType
-         * @param asn1DerEncodedX500Principals CAs known to the server
-         */
-        void clientCertificateRequested(
-                byte[] keyTypes, byte[][] asn1DerEncodedX500Principals)
-                throws CertificateEncodingException, SSLException;
-        /**
-         * Called when SSL handshake is completed. Note that this can
-         * be after SSL_do_handshake returns when handshake cutthrough
-         * is enabled.
-         */
-        void handshakeCompleted();
-    }
-}
diff --git a/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/OpenSSLSocketImpl.java b/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/OpenSSLSocketImpl.java
deleted file mode 100644
index 77c510e2..00000000
--- a/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/OpenSSLSocketImpl.java
+++ /dev/null
@@ -1,279 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package org.apache.harmony.xnet.provider.jsse;
-import java.io.FileDescriptor;
-import java.io.IOException;
-import java.io.InputStream;
-import java.io.OutputStream;
-import java.net.InetAddress;
-import java.net.Socket;
-import java.net.SocketException;
-import java.security.PrivateKey;
-import java.security.cert.CertificateEncodingException;
-import java.security.cert.CertificateException;
-import javax.net.ssl.HandshakeCompletedListener;
-import javax.net.ssl.SSLException;
-import javax.net.ssl.SSLSession;
-
-/**
- * Implementation of the class OpenSSLSocketImpl based on OpenSSL.
- * <p>
- * Extensions to SSLSocket include:
- * <ul>
- * <li>handshake timeout
- * <li>session tickets
- * <li>Server Name Indication
- * </ul>
- */
-public class OpenSSLSocketImpl
-        extends javax.net.ssl.SSLSocket implements NativeCrypto.SSLHandshakeCallbacks {
-    protected OpenSSLSocketImpl(SSLParametersImpl sslParameters) throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    protected OpenSSLSocketImpl(SSLParametersImpl sslParameters, String[] enabledProtocols,
-            String[] enabledCipherSuites) throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    protected OpenSSLSocketImpl(String host, int port, SSLParametersImpl sslParameters)
-            throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    protected OpenSSLSocketImpl(InetAddress address, int port, SSLParametersImpl sslParameters)
-            throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    protected OpenSSLSocketImpl(String host, int port, InetAddress clientAddress, int clientPort,
-            SSLParametersImpl sslParameters) throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    protected OpenSSLSocketImpl(InetAddress address, int port, InetAddress clientAddress,
-            int clientPort, SSLParametersImpl sslParameters) throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    protected OpenSSLSocketImpl(Socket socket, String host, int port, boolean autoClose,
-            SSLParametersImpl sslParameters) throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public synchronized void startHandshake() throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / client_cert_cb
-    @Override
-    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
-            throws CertificateEncodingException, SSLException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / info_callback
-    @Override
-    public void handshakeCompleted() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks
-    @Override
-    public void verifyCertificateChain(byte[][] bytes, String authMethod)
-            throws CertificateException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public InputStream getInputStream() throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public OutputStream getOutputStream() throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public SSLSession getSession() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public boolean getEnableSessionCreation() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setEnableSessionCreation(boolean flag) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public String[] getSupportedCipherSuites() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public String[] getEnabledCipherSuites() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setEnabledCipherSuites(String[] suites) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public String[] getSupportedProtocols() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public String[] getEnabledProtocols() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setEnabledProtocols(String[] protocols) {
-        throw new RuntimeException("Stub!");
-    }
-
-    public void setUseSessionTickets(boolean useSessionTickets) {
-        throw new RuntimeException("Stub!");
-    }
-
-    public void setHostname(String hostname) {
-        throw new RuntimeException("Stub!");
-    }
-
-    public void setChannelIdEnabled(boolean enabled) {
-        throw new RuntimeException("Stub!");
-    }
-
-    public byte[] getChannelId() throws SSLException {
-        throw new RuntimeException("Stub!");
-    }
-
-    public void setChannelIdPrivateKey(PrivateKey privateKey) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public boolean getUseClientMode() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setUseClientMode(boolean mode) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public boolean getWantClientAuth() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public boolean getNeedClientAuth() {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setNeedClientAuth(boolean need) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setWantClientAuth(boolean want) {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void sendUrgentData(int data) throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @Override
-    public void setOOBInline(boolean on) throws SocketException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    @Override
-    public void setSoTimeout(int readTimeoutMilliseconds) throws SocketException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    @Override
-    public int getSoTimeout() throws SocketException {
-        throw new RuntimeException("Stub!");
-    }
-
-    /**
-     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
-     */
-    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
-        throw new RuntimeException("Stub!");
-    }
-
-    /**
-     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
-     */
-    public int getSoWriteTimeout() throws SocketException {
-        throw new RuntimeException("Stub!");
-    }
-
-    /**
-     * Set the handshake timeout on this socket.  This timeout is specified in
-     * milliseconds and will be used only during the handshake process.
-     */
-    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
-        throw new RuntimeException("Stub!");
-    }
-
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    @Override
-    public void close() throws IOException {
-        throw new RuntimeException("Stub!");
-    }
-
-    public FileDescriptor getFileDescriptor$() {
-        throw new RuntimeException("Stub!");
-    }
-
-    public byte[] getNpnSelectedProtocol() {
-        throw new RuntimeException("Stub!");
-    }
-
-    public void setNpnProtocols(byte[] npnProtocols) {
-        throw new RuntimeException("Stub!");
-    }
-}
diff --git a/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/SSLParametersImpl.java b/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/SSLParametersImpl.java
deleted file mode 100644
index 2c8231ce..00000000
--- a/android-stub/src/main/java/org/apache/harmony/xnet/provider/jsse/SSLParametersImpl.java
+++ /dev/null
@@ -1,23 +0,0 @@
-/*
- * Copyright 2015 The Android Open Source Project
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
-package org.apache.harmony.xnet.provider.jsse;
-
-class SSLParametersImpl {
-    public static SSLParametersImpl getDefault() {
-        throw new RuntimeException("Stub!");
-    }
-}
diff --git a/android/src/main/java/org/conscrypt/Platform.java b/android/src/main/java/org/conscrypt/Platform.java
index 5b0ebed7..b6f80765 100644
--- a/android/src/main/java/org/conscrypt/Platform.java
+++ b/android/src/main/java/org/conscrypt/Platform.java
@@ -62,8 +62,8 @@ import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.ct.CTLogStore;
-import org.conscrypt.ct.CTPolicy;
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.Policy;
 import org.conscrypt.metrics.CipherSuite;
 import org.conscrypt.metrics.ConscryptStatsLog;
 import org.conscrypt.metrics.Protocol;
@@ -577,9 +577,7 @@ final class Platform {
      * Wrap the SocketFactory with the platform wrapper if needed for compatability.
      */
     public static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
-        if (Build.VERSION.SDK_INT < 19) {
-            return new PreKitKatPlatformOpenSSLSocketAdapterFactory(factory);
-        } else if (Build.VERSION.SDK_INT < 22) {
+        if (Build.VERSION.SDK_INT < 22) {
             return new KitKatPlatformOpenSSLSocketAdapterFactory(factory);
         }
         return factory;
@@ -673,36 +671,20 @@ final class Platform {
      */
 
     public static CloseGuard closeGuardGet() {
-        if (Build.VERSION.SDK_INT < 14) {
-            return null;
-        }
-
         return CloseGuard.get();
     }
 
     public static void closeGuardOpen(Object guardObj, String message) {
-        if (Build.VERSION.SDK_INT < 14) {
-            return;
-        }
-
         CloseGuard guard = (CloseGuard) guardObj;
         guard.open(message);
     }
 
     public static void closeGuardClose(Object guardObj) {
-        if (Build.VERSION.SDK_INT < 14) {
-            return;
-        }
-
         CloseGuard guard = (CloseGuard) guardObj;
         guard.close();
     }
 
     public static void closeGuardWarnIfOpen(Object guardObj) {
-        if (Build.VERSION.SDK_INT < 14) {
-            return;
-        }
-
         CloseGuard guard = (CloseGuard) guardObj;
         guard.warnIfOpen();
     }
@@ -904,11 +886,11 @@ final class Platform {
         return null;
     }
 
-    static CTLogStore newDefaultLogStore() {
+    static LogStore newDefaultLogStore() {
         return null;
     }
 
-    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
+    static Policy newDefaultPolicy() {
         return null;
     }
 
diff --git a/android/src/main/java/org/conscrypt/PreKitKatPlatformOpenSSLSocketAdapterFactory.java b/android/src/main/java/org/conscrypt/PreKitKatPlatformOpenSSLSocketAdapterFactory.java
deleted file mode 100644
index 33315b85..00000000
--- a/android/src/main/java/org/conscrypt/PreKitKatPlatformOpenSSLSocketAdapterFactory.java
+++ /dev/null
@@ -1,35 +0,0 @@
-/*
- * Copyright 2015 The Android Open Source Project
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
-package org.conscrypt;
-
-import java.io.IOException;
-import java.net.Socket;
-
-/**
- * A {@link javax.net.ssl.SSLSocketFactory} which creates unbundled conscrypt SSLSockets and wraps
- * them into pre-KitKat platform SSLSockets.
- */
-public class PreKitKatPlatformOpenSSLSocketAdapterFactory extends BaseOpenSSLSocketAdapterFactory {
-    public PreKitKatPlatformOpenSSLSocketAdapterFactory(OpenSSLSocketFactoryImpl delegate) {
-        super(delegate);
-    }
-
-    @Override
-    protected Socket wrap(OpenSSLSocketImpl socket) throws IOException {
-        return new PreKitKatPlatformOpenSSLSocketImplAdapter(socket);
-    }
-}
diff --git a/android/src/main/java/org/conscrypt/PreKitKatPlatformOpenSSLSocketImplAdapter.java b/android/src/main/java/org/conscrypt/PreKitKatPlatformOpenSSLSocketImplAdapter.java
deleted file mode 100644
index a050a2c3..00000000
--- a/android/src/main/java/org/conscrypt/PreKitKatPlatformOpenSSLSocketImplAdapter.java
+++ /dev/null
@@ -1,458 +0,0 @@
-/*
- * Copyright 2015 The Android Open Source Project
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
-package org.conscrypt;
-
-import java.io.FileDescriptor;
-import java.io.IOException;
-import java.io.InputStream;
-import java.io.OutputStream;
-import java.net.InetAddress;
-import java.net.SocketAddress;
-import java.net.SocketException;
-import java.nio.channels.SocketChannel;
-import java.security.PrivateKey;
-import java.security.cert.CertificateEncodingException;
-import java.security.cert.CertificateException;
-import javax.net.ssl.HandshakeCompletedListener;
-import javax.net.ssl.SSLException;
-import javax.net.ssl.SSLParameters;
-import javax.net.ssl.SSLSession;
-
-/**
- * This class delegates all calls to an {@code org.conscrypt.OpenSSLSocketImpl}.
- * This is to work around code that checks that the socket is an
- * {@code org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl} before
- * calling methods, such as setting SNI. This is only for Pre-Kitkat devices.
- *
- * It delegates all public methods in Socket, SSLSocket, and OpenSSLSocket from
- * JB.
- */
-public class PreKitKatPlatformOpenSSLSocketImplAdapter
-        extends org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl {
-
-
-    private final AbstractConscryptSocket delegate;
-
-    public PreKitKatPlatformOpenSSLSocketImplAdapter(AbstractConscryptSocket delegate)
-            throws IOException {
-        super(null);
-        this.delegate = delegate;
-    }
-
-    // Socket methods.
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public void close() throws IOException {
-        delegate.close();
-    }
-
-    @Override
-    public InputStream getInputStream() throws IOException {
-        return delegate.getInputStream();
-    }
-
-    @Override
-    public int getLocalPort() {
-        return delegate.getLocalPort();
-    }
-
-    @Override
-    public OutputStream getOutputStream() throws IOException {
-        return delegate.getOutputStream();
-    }
-
-    @Override
-    public int getPort() {
-        return delegate.getPort();
-    }
-
-    @Override
-    public void connect(SocketAddress sockaddr, int timeout) throws IOException {
-        delegate.connect(sockaddr, timeout);
-    }
-
-    @Override
-    public void connect(SocketAddress sockaddr) throws IOException {
-        delegate.connect(sockaddr);
-    }
-
-    @Override
-    public void bind(SocketAddress sockaddr) throws IOException {
-        delegate.bind(sockaddr);
-    }
-
-    @Override
-    public SocketAddress getRemoteSocketAddress() {
-        return delegate.getRemoteSocketAddress();
-    }
-
-    @Override
-    public SocketAddress getLocalSocketAddress() {
-        return delegate.getLocalSocketAddress();
-    }
-
-    @Override
-    public InetAddress getLocalAddress() {
-        return delegate.getLocalAddress();
-    }
-
-    @Override
-    public InetAddress getInetAddress() {
-        return delegate.getInetAddress();
-    }
-
-    @Override
-    public String toString() {
-        return delegate.toString();
-    }
-
-    @Override
-    public void setSoLinger(boolean on, int linger) throws SocketException {
-        delegate.setSoLinger(on, linger);
-    }
-
-    @Override
-    public void setTcpNoDelay(boolean on) throws SocketException {
-        delegate.setTcpNoDelay(on);
-    }
-
-    @Override
-    public void setReuseAddress(boolean on) throws SocketException {
-        delegate.setReuseAddress(on);
-    }
-
-    @Override
-    public void setKeepAlive(boolean on) throws SocketException {
-        delegate.setKeepAlive(on);
-    }
-
-    @Override
-    public void setTrafficClass(int tos) throws SocketException {
-        delegate.setTrafficClass(tos);
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public void setSoTimeout(int to) throws SocketException {
-        delegate.setSoTimeout(to);
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public void setSendBufferSize(int size) throws SocketException {
-        delegate.setSendBufferSize(size);
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public void setReceiveBufferSize(int size) throws SocketException {
-        delegate.setReceiveBufferSize(size);
-    }
-
-    @Override
-    public boolean getTcpNoDelay() throws SocketException {
-        return delegate.getTcpNoDelay();
-    }
-
-    @Override
-    public boolean getReuseAddress() throws SocketException {
-        return delegate.getReuseAddress();
-    }
-
-    @Override
-    public boolean getKeepAlive() throws SocketException {
-        return delegate.getKeepAlive();
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public int getSoTimeout() throws SocketException {
-        return delegate.getSoTimeout();
-    }
-
-    @Override
-    public int getSoLinger() throws SocketException {
-        return delegate.getSoLinger();
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public int getSendBufferSize() throws SocketException {
-        return delegate.getSendBufferSize();
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public int getReceiveBufferSize() throws SocketException {
-        return delegate.getReceiveBufferSize();
-    }
-
-    @Override
-    public boolean isConnected() {
-        return delegate.isConnected();
-    }
-
-    @Override
-    public boolean isClosed() {
-        return delegate.isClosed();
-    }
-
-    @Override
-    public boolean isBound() {
-        return delegate.isBound();
-    }
-
-    @Override
-    public boolean isOutputShutdown() {
-        return delegate.isOutputShutdown();
-    }
-
-    @Override
-    public boolean isInputShutdown() {
-        return delegate.isInputShutdown();
-    }
-
-    @Override
-    public void shutdownInput() throws IOException {
-        delegate.shutdownInput();
-    }
-
-    @Override
-    public void shutdownOutput() throws IOException {
-        delegate.shutdownOutput();
-    }
-
-    @Override
-    public void setOOBInline(boolean oobinline) throws SocketException {
-        delegate.setOOBInline(oobinline);
-    }
-
-    @Override
-    public boolean getOOBInline() throws SocketException {
-        return delegate.getOOBInline();
-    }
-
-    @Override
-    public int getTrafficClass() throws SocketException {
-        return delegate.getTrafficClass();
-    }
-
-    @Override
-    public void sendUrgentData(int value) throws IOException {
-        delegate.sendUrgentData(value);
-    }
-
-    @Override
-    public SocketChannel getChannel() {
-        return delegate.getChannel();
-    }
-
-    @Override
-    public FileDescriptor getFileDescriptor$() {
-        return delegate.getFileDescriptor$();
-    }
-
-    @Override
-    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
-        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
-    }
-
-    // SSLSocket methods.
-
-    @Override
-    public String[] getSupportedCipherSuites() {
-        return delegate.getSupportedCipherSuites();
-    }
-
-    @Override
-    public String[] getEnabledCipherSuites() {
-        return delegate.getEnabledCipherSuites();
-    }
-
-    @Override
-    public void setEnabledCipherSuites(String[] suites) {
-        delegate.setEnabledCipherSuites(suites);
-    }
-
-    @Override
-    public String[] getSupportedProtocols() {
-        return delegate.getSupportedProtocols();
-    }
-    @Override
-    public String[] getEnabledProtocols() {
-        return delegate.getEnabledProtocols();
-    }
-
-    @Override
-    public void setEnabledProtocols(String[] protocols) {
-        delegate.setEnabledProtocols(protocols);
-    }
-
-    @Override
-    public SSLSession getSession() {
-        return delegate.getSession();
-    }
-
-    @Override
-    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
-        delegate.addHandshakeCompletedListener(listener);
-    }
-
-    @Override
-    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
-        delegate.removeHandshakeCompletedListener(listener);
-    }
-
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public void startHandshake() throws IOException {
-        delegate.startHandshake();
-    }
-
-    @Override
-    public void setUseClientMode(boolean mode) {
-        delegate.setUseClientMode(mode);
-    }
-
-    @Override
-    public boolean getUseClientMode() {
-        return delegate.getUseClientMode();
-    }
-
-    @Override
-    public void setNeedClientAuth(boolean need) {
-        delegate.setNeedClientAuth(need);
-    }
-
-    @Override
-    public void setWantClientAuth(boolean want) {
-        delegate.setWantClientAuth(want);
-    }
-
-    @Override
-    public boolean getNeedClientAuth() {
-        return delegate.getNeedClientAuth();
-    }
-
-    @Override
-    public boolean getWantClientAuth() {
-        return delegate.getWantClientAuth();
-    }
-
-    @Override
-    public void setEnableSessionCreation(boolean flag) {
-        delegate.setEnableSessionCreation(flag);
-    }
-
-    @Override
-    public boolean getEnableSessionCreation() {
-        return delegate.getEnableSessionCreation();
-    }
-
-    @Override
-    public SSLParameters getSSLParameters() {
-        return delegate.getSSLParameters();
-    }
-
-    @Override
-    public void setSSLParameters(SSLParameters p) {
-        delegate.setSSLParameters(p);
-    }
-
-    // OpenSSLSocket methods.
-    @Override
-    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
-            throws CertificateEncodingException, SSLException {
-        throw new RuntimeException("Shouldn't be here!");
-    }
-
-    @Override
-    public void handshakeCompleted() {
-        throw new RuntimeException("Shouldn't be here!");
-    }
-
-    @Override
-    public void verifyCertificateChain(byte[][] bytes, String authMethod)
-            throws CertificateException {
-        throw new RuntimeException("Shouldn't be here!");
-    }
-
-    @Override
-    public void setUseSessionTickets(boolean useSessionTickets) {
-        delegate.setUseSessionTickets(useSessionTickets);
-    }
-
-    @Override
-    public void setHostname(String hostname) {
-        delegate.setHostname(hostname);
-    }
-
-    @Override
-    public void setChannelIdEnabled(boolean enabled) {
-        delegate.setChannelIdEnabled(enabled);
-    }
-
-    @Override
-    public byte[] getChannelId() throws SSLException {
-        return delegate.getChannelId();
-    }
-
-    @Override
-    public void setChannelIdPrivateKey(PrivateKey privateKey) {
-        delegate.setChannelIdPrivateKey(privateKey);
-    }
-
-    @Override
-    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
-        delegate.setSoWriteTimeout(writeTimeoutMilliseconds);
-    }
-
-    @Override
-    public int getSoWriteTimeout() throws SocketException {
-        return delegate.getSoWriteTimeout();
-    }
-
-    @Override
-    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
-        delegate.setHandshakeTimeout(handshakeTimeoutMilliseconds);
-    }
-
-    @Override
-    @SuppressWarnings("deprecation")
-    public byte[] getNpnSelectedProtocol() {
-        return delegate.getNpnSelectedProtocol();
-    }
-
-    @Override
-    @SuppressWarnings("deprecation")
-    public void setNpnProtocols(byte[] npnProtocols) {
-        delegate.setNpnProtocols(npnProtocols);
-    }
-
-    // These aren't in the Platform's OpenSSLSocketImpl but we have them to support duck typing.
-
-    @SuppressWarnings("deprecation")
-    public byte[] getAlpnSelectedProtocol() {
-        return delegate.getAlpnSelectedProtocol();
-    }
-
-    @SuppressWarnings("deprecation")
-    public void setAlpnProtocols(byte[] alpnProtocols) {
-        delegate.setAlpnProtocols(alpnProtocols);
-    }
-}
diff --git a/api-doclet/build.gradle b/api-doclet/build.gradle
index 2ada3d55..d83fffcd 100644
--- a/api-doclet/build.gradle
+++ b/api-doclet/build.gradle
@@ -1,21 +1,18 @@
+plugins {
+    id 'org.jetbrains.kotlin.jvm' version '2.0.0'
+}
+
 description = 'Conscrypt: API Doclet'
 
+kotlin {
+    jvmToolchain(11)
+}
 
-java {
-    toolchain {
-        // Force Java 8 for the doclet.
-        languageVersion = JavaLanguageVersion.of(8)
-    }
-    // Java 8 doclets depend on the JDK's tools.jar
-    def compilerMetadata = javaToolchains.compilerFor(toolchain).get().metadata
-    def jdkHome = compilerMetadata.getInstallationPath()
-    def toolsJar = jdkHome.file("lib/tools.jar")
-    dependencies {
-        implementation files(toolsJar)
-    }
+dependencies {
+    implementation "org.jetbrains.kotlin:kotlin-stdlib-jdk8"
 }
 
-tasks.withType(Javadoc) {
-    // TODO(prb): Update doclet to Java 11.
+tasks.withType(Javadoc).configureEach {
+    // No need to javadoc the Doclet....
     enabled = false
 }
diff --git a/api-doclet/src/main/java/org/conscrypt/doclet/FilterDoclet.java b/api-doclet/src/main/java/org/conscrypt/doclet/FilterDoclet.java
deleted file mode 100644
index abf83397..00000000
--- a/api-doclet/src/main/java/org/conscrypt/doclet/FilterDoclet.java
+++ /dev/null
@@ -1,151 +0,0 @@
-/*
- * Copyright (C) 2010 Google Inc.
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- * http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-/*
- * Originally from Doclava project at
- * https://android.googlesource.com/platform/external/doclava/+/master/src/com/google/doclava/Doclava.java
- */
-
-package org.conscrypt.doclet;
-
-import com.sun.javadoc.*;
-import com.sun.tools.doclets.standard.Standard;
-import com.sun.tools.javadoc.Main;
-import java.io.FileNotFoundException;
-import java.lang.reflect.Array;
-import java.lang.reflect.InvocationHandler;
-import java.lang.reflect.InvocationTargetException;
-import java.lang.reflect.Method;
-import java.lang.reflect.Proxy;
-import java.util.ArrayList;
-import java.util.List;
-
-/**
- * This Doclet filters out all classes, methods, fields, etc. that have the {@code @Internal}
- * annotation on them.
- */
-public class FilterDoclet extends com.sun.tools.doclets.standard.Standard {
-    public static void main(String[] args) throws FileNotFoundException {
-        String name = FilterDoclet.class.getName();
-        Main.execute(name, args);
-    }
-
-    public static boolean start(RootDoc rootDoc) {
-        return Standard.start((RootDoc) filterHidden(rootDoc, RootDoc.class));
-    }
-
-    /**
-     * Returns true if the given element has an @Internal annotation.
-     */
-    private static boolean hasHideAnnotation(ProgramElementDoc doc) {
-        for (AnnotationDesc ann : doc.annotations()) {
-            if (ann.annotationType().qualifiedTypeName().equals("org.conscrypt.Internal")) {
-                return true;
-            }
-        }
-        return false;
-    }
-
-    /**
-     * Returns true if the given element is hidden.
-     */
-    private static boolean isHidden(Doc doc) {
-        // Methods, fields, constructors.
-        if (doc instanceof MemberDoc) {
-            return hasHideAnnotation((MemberDoc) doc);
-        }
-        // Classes, interfaces, enums, annotation types.
-        if (doc instanceof ClassDoc) {
-            // Check the class doc and containing class docs if this is a
-            // nested class.
-            ClassDoc current = (ClassDoc) doc;
-            do {
-                if (hasHideAnnotation(current)) {
-                    return true;
-                }
-                current = current.containingClass();
-            } while (current != null);
-        }
-        return false;
-    }
-
-    /**
-     * Filters out hidden elements.
-     */
-    private static Object filterHidden(Object o, Class<?> expected) {
-        if (o == null) {
-            return null;
-        }
-
-        Class<?> type = o.getClass();
-        if (type.getName().startsWith("com.sun.")) {
-            // TODO: Implement interfaces from superclasses, too.
-            return Proxy.newProxyInstance(
-                    type.getClassLoader(), type.getInterfaces(), new HideHandler(o));
-        } else if (o instanceof Object[]) {
-            Class<?> componentType = expected.getComponentType();
-            if (componentType == null) {
-                return o;
-            }
-
-            Object[] array = (Object[]) o;
-            List<Object> list = new ArrayList<Object>(array.length);
-            for (Object entry : array) {
-                if ((entry instanceof Doc) && isHidden((Doc) entry)) {
-                    continue;
-                }
-                list.add(filterHidden(entry, componentType));
-            }
-            return list.toArray((Object[]) Array.newInstance(componentType, list.size()));
-        } else {
-            return o;
-        }
-    }
-
-    /**
-     * Filters hidden elements.
-     */
-    private static class HideHandler implements InvocationHandler {
-        private final Object target;
-
-        public HideHandler(Object target) {
-            this.target = target;
-        }
-
-        @Override
-        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
-            String methodName = method.getName();
-            if (args != null) {
-                if (methodName.equals("compareTo") || methodName.equals("equals")
-                        || methodName.equals("overrides") || methodName.equals("subclassOf")) {
-                    args[0] = unwrap(args[0]);
-                }
-            }
-
-            try {
-                return filterHidden(method.invoke(target, args), method.getReturnType());
-            } catch (InvocationTargetException e) {
-                e.printStackTrace();
-                throw e.getTargetException();
-            }
-        }
-
-        private static Object unwrap(Object proxy) {
-            if (proxy instanceof Proxy)
-                return ((HideHandler) Proxy.getInvocationHandler(proxy)).target;
-            return proxy;
-        }
-    }
-}
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt
new file mode 100644
index 00000000..811d13a3
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt
@@ -0,0 +1,76 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+import javax.lang.model.element.Element
+import javax.lang.model.element.TypeElement
+import kotlin.streams.toList
+
+class ClassIndex {
+    private val index = mutableMapOf<String, ClassInfo>()
+
+    private fun put(classInfo: ClassInfo) {
+        index[classInfo.qualifiedName] = classInfo
+    }
+
+    fun put(element: Element) {
+        put(ClassInfo(element as TypeElement))
+    }
+
+    fun get(qualifiedName: String) = index[qualifiedName]
+    fun contains(qualifiedName: String) = index.containsKey(qualifiedName)
+    fun find(name: String) = if (contains(name)) get(name) else findSimple(name)
+    private fun findSimple(name: String) = classes().firstOrNull { it.simpleName == name } // XXX dups
+
+    fun classes(): Collection<ClassInfo> = index.values
+
+    fun addVisible(elements: Set<Element>) {
+        elements
+            .filterIsInstance<TypeElement>()
+            .filter(Element::isVisibleType)
+            .forEach(::put)
+    }
+
+    private fun packages(): List<String> = index.values.stream()
+        .map { it.packageName }
+        .distinct()
+        .sorted()
+        .toList()
+
+    private fun classesForPackage(packageName: String) = index.values.stream()
+        .filter { it.packageName == packageName }
+        .sorted()
+        .toList()
+
+    fun generateHtml():String = html {
+        packages().forEach { packageName ->
+            div("package-section") {
+                h2("Package $packageName", "package-name")
+                ul("class-list") {
+                    classesForPackage(packageName)
+                        .forEach { c ->
+                            li {
+                                a(c.fileName, c.simpleName)
+                            }
+                        }
+
+                }
+            }
+        }
+    }
+}
+
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt
new file mode 100644
index 00000000..582885ba
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt
@@ -0,0 +1,136 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+import javax.lang.model.element.Element
+import javax.lang.model.element.ExecutableElement
+import javax.lang.model.element.TypeElement
+
+
+data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
+    val simpleName = element.simpleName.toString()
+    val qualifiedName = element.qualifiedName.toString()
+    val packageName = FilterDoclet.elementUtils.getPackageOf(element).qualifiedName.toString()
+    val fileName = qualifiedName.replace('.', '/') + ".html"
+
+    override fun compareTo(other: ClassInfo) = qualifiedName.compareTo(other.qualifiedName)
+
+    private fun description() = html {
+        div("class-description") {
+            compose {
+                element.commentsAndTagTrees()
+            }
+        }
+    }
+
+    private fun fields() = html {
+        val fields = element.children(Element::isVisibleField)
+        if (fields.isNotEmpty()) {
+            h2("Fields")
+            fields.forEach { field ->
+                div("member") {
+                    h4(field.simpleName.toString())
+                    compose {
+                        field.commentsAndTagTrees()
+                    }
+                }
+            }
+        }
+    }
+
+    private fun nestedClasses() = html {
+        val nested = element.children(Element::isVisibleType)
+        nested.takeIf { it.isNotEmpty() }?.let {
+            h2("Nested Classes")
+            nested.forEach { cls ->
+                div("member") {
+                    h4(cls.simpleName.toString())
+                    compose {
+                        cls.commentsAndTagTrees()
+                    }
+                }
+            }
+        }
+    }
+
+    private fun method(method: ExecutableElement) = html {
+        div("member") {
+            h4(method.simpleName.toString())
+            pre(method.methodSignature(), "method-signature")
+            div("description") {
+                compose {
+                    method.commentTree()
+                }
+                val params = method.paramTags()
+                val throwns = method.throwTags()
+                val returns = if (method.isConstructor())
+                    emptyList()
+                else
+                    method.returnTag(method.returnType)
+
+                if(params.size + returns.size + throwns.size > 0) {
+                    div("params") {
+                        table("params-table") {
+                            rowGroup(params, title = "Parameters", colspan = 2) {
+                                td {text(it.first)}
+                                td {text(it.second)}
+                            }
+                            rowGroup(returns, title = "Returns", colspan = 2) {
+                                td {text(it.first)}
+                                td {text(it.second)}
+                            }
+                            rowGroup(throwns, title = "Throws", colspan = 2) {
+                                td {text(it.first)}
+                                td {text(it.second)}
+                            }
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun executables(title: String, filter: (Element) -> Boolean) = html {
+        val methods = element.children(filter)
+        if (methods.isNotEmpty()) {
+            h2(title)
+            methods.forEach {
+                compose {
+                    method(it as ExecutableElement)
+                }
+            }
+        }
+    }
+
+    private fun constructors() = executables("Constructors", Element::isVisibleConstructor)
+    private fun methods() = executables("Public Methods", Element::isVisibleMethod)
+
+    fun generateHtml() = html {
+        div("package-name") { text("Package: $packageName") }
+        h1(simpleName)
+        pre(element.signature(), "class-signature")
+
+        compose {
+            description() +
+                    fields() +
+                    constructors() +
+                    methods() +
+                    nestedClasses()
+        }
+    }
+}
+
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/DocTreeUtils.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/DocTreeUtils.kt
new file mode 100644
index 00000000..e3ccf8cc
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/DocTreeUtils.kt
@@ -0,0 +1,110 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+import org.conscrypt.doclet.FilterDoclet.Companion.baseUrl
+import com.sun.source.doctree.DocCommentTree
+import com.sun.source.doctree.DocTree
+import com.sun.source.doctree.EndElementTree
+import com.sun.source.doctree.LinkTree
+import com.sun.source.doctree.LiteralTree
+import com.sun.source.doctree.ParamTree
+import com.sun.source.doctree.ReturnTree
+import com.sun.source.doctree.SeeTree
+import com.sun.source.doctree.StartElementTree
+import com.sun.source.doctree.TextTree
+import com.sun.source.doctree.ThrowsTree
+import org.conscrypt.doclet.FilterDoclet.Companion.classIndex
+import org.conscrypt.doclet.FilterDoclet.Companion.docTrees
+import javax.lang.model.element.Element
+import javax.lang.model.type.TypeMirror
+
+fun renderDocTreeList(treeList: List<DocTree>):String =
+    treeList.joinToString("\n", transform = ::renderDocTree)
+
+fun renderDocTree(docTree: DocTree): String = when (docTree) {
+    is TextTree -> docTree.body
+    is LinkTree -> {
+        val reference = docTree.reference.toString()
+        val label = if (docTree.label.isEmpty()) {
+            reference
+        } else {
+            renderDocTreeList(docTree.label)
+        }
+        createLink(reference, label)
+    }
+    is StartElementTree, is EndElementTree -> docTree.toString()
+    is LiteralTree -> "<code>${docTree.body}</code>"
+    else -> error("[${docTree.javaClass} / ${docTree.kind} --- ${docTree}]")
+}
+
+fun createLink(reference: String, label: String) = html {
+    val parts = reference.split('#')
+    val className = parts[0]
+    val anchor = if (parts.size > 1) "#${parts[1]}" else ""
+    val classInfo = classIndex.find(className)
+    val href = if (classInfo != null)
+        "${classInfo.simpleName}.html$anchor"
+    else
+        "$baseUrl${className.replace('.', '/')}.html$anchor"
+
+    a(href, label)
+}
+
+fun renderBlockTagList(tagList: List<DocTree>): String =
+    tagList.joinToString("\n", transform = ::renderBlockTag)
+
+fun renderBlockTag(tag: DocTree) = when (tag) {
+    is ParamTree, is ReturnTree, is ThrowsTree -> error("Unexpected block tag: $tag")
+    is SeeTree -> html {
+        br()
+        p {
+            strong("See: ")
+            text(renderDocTreeList(tag.reference))
+        }
+    }
+    else -> tag.toString()
+}
+
+inline fun <reified T> Element.filterTags() =
+    docTree()?.blockTags?.filterIsInstance<T>() ?: emptyList()
+
+fun Element.paramTags() = filterTags<ParamTree>()
+    .map { it.name.toString() to renderDocTreeList(it.description) }
+    .toList()
+
+
+fun Element.returnTag(returnType: TypeMirror): List<Pair<String, String>> {
+    val list = mutableListOf<Pair<String, String>>()
+    val descriptions  = filterTags<ReturnTree>()
+        .map {  renderDocTreeList(it.description) }
+        .singleOrNull()
+
+    if (descriptions != null) {
+        list.add(returnType.toString() to descriptions)
+    }
+    return list
+}
+
+fun Element.throwTags() = filterTags<ThrowsTree>()
+    .map { it.exceptionName.toString() to renderDocTreeList(it.description) }
+    .toList()
+
+fun Element.docTree(): DocCommentTree? = docTrees.getDocCommentTree(this)
+fun Element.commentTree() = docTree()?.let { renderDocTreeList(it.fullBody) } ?: ""
+fun Element.tagTree() = docTree()?.let { renderBlockTagList(it.blockTags) } ?: ""
+fun Element.commentsAndTagTrees() = commentTree() + tagTree()
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt
new file mode 100644
index 00000000..a9fcd00e
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt
@@ -0,0 +1,119 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+import com.sun.source.doctree.UnknownBlockTagTree
+import java.util.Locale
+import javax.lang.model.element.Element
+import javax.lang.model.element.ElementKind
+import javax.lang.model.element.ExecutableElement
+import javax.lang.model.element.Modifier
+import javax.lang.model.element.TypeElement
+import javax.lang.model.element.VariableElement
+import javax.lang.model.type.TypeMirror
+
+fun Element.isType() = isClass() || isInterface() || isEnum()
+fun Element.isClass() = this is TypeElement && kind == ElementKind.CLASS
+fun Element.isEnum() = this is TypeElement && kind == ElementKind.ENUM
+fun Element.isInterface() = this is TypeElement && kind == ElementKind.INTERFACE
+fun Element.isExecutable() = this is ExecutableElement
+fun Element.isField() = this is VariableElement
+
+fun Element.isVisibleType() = isType() && isVisible()
+fun Element.isVisibleMethod() = isExecutable() && isVisible() && kind == ElementKind.METHOD
+fun Element.isVisibleConstructor() = isExecutable() && isVisible() && kind == ElementKind.CONSTRUCTOR
+fun Element.isVisibleField() = isField() && isVisible()
+fun Element.isPublic() = modifiers.contains(Modifier.PUBLIC)
+fun Element.isPrivate() = !isPublic() // Ignore protected for now :)
+fun Element.isHidden() = isPrivate() || hasHideMarker() || parentIsHidden()
+fun Element.isVisible() = !isHidden()
+fun Element.hasHideMarker() = hasAnnotation("org.conscrypt.Internal") || hasHideTag()
+fun Element.children(filterFunction: (Element) -> Boolean) = enclosedElements
+    .filter(filterFunction)
+    .toList()
+
+fun Element.parentIsHidden(): Boolean
+        = if (enclosingElement.isType()) enclosingElement.isHidden() else false
+
+fun Element.hasAnnotation(annotationName: String): Boolean = annotationMirrors
+    .map { it.annotationType.toString() }
+    .any { it == annotationName }
+
+
+fun Element.hasHideTag(): Boolean {
+    return docTree()?.blockTags?.any {
+        tag -> tag is UnknownBlockTagTree && tag.tagName == "hide"
+    } ?: false
+}
+
+fun ExecutableElement.isConstructor() = kind == ElementKind.CONSTRUCTOR
+fun ExecutableElement.name() = if (isConstructor()) parentName() else simpleName.toString()
+fun ExecutableElement.parentName() = enclosingElement.simpleName.toString()
+
+fun ExecutableElement.methodSignature(): String {
+    val modifiers = modifiers.joinToString(" ")
+    val returnType = if (isConstructor()) "" else "${formatType(returnType)} "
+
+    val typeParams = typeParameters.takeIf { it.isNotEmpty() }
+        ?.joinToString(separator = ", ", prefix = "<", postfix = ">") {
+            it.asType().toString() } ?: ""
+
+    val parameters = parameters.joinToString(", ") { param ->
+        "${formatType(param.asType())} ${param.simpleName}"
+    }
+
+    val exceptions = thrownTypes
+        .joinToString(", ")
+        .prefixIfNotEmpty(" throws ")
+    return "$modifiers $typeParams$returnType${simpleName}($parameters)$exceptions"
+}
+
+fun formatType(typeMirror: TypeMirror): String {
+    return if (typeMirror.kind.isPrimitive) {
+        typeMirror.toString()
+    } else {
+        typeMirror.toString()
+            .split('.')
+            .last()
+    }
+}
+
+fun TypeElement.signature(): String {
+    val modifiers = modifiers.joinToString(" ")
+    val kind = this.kind.toString().lowercase(Locale.getDefault())
+
+    val superName = superDisplayName(superclass)
+
+    val interfaces = interfaces
+        .joinToString(", ")
+        .prefixIfNotEmpty(" implements ")
+
+    return "$modifiers $kind $simpleName$superName$interfaces"
+}
+
+fun superDisplayName(mirror: TypeMirror): String {
+    return when (mirror.toString()) {
+        "none", "java.lang.Object" -> ""
+        else -> " extends $mirror "
+    }
+}
+
+private fun String.prefixIfNotEmpty(prefix: String): String
+        = if (isNotEmpty()) prefix + this else this
+
+private fun String.suffixIfNotEmpty(prefix: String): String
+        = if (isNotEmpty()) this + prefix else this
\ No newline at end of file
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt
new file mode 100644
index 00000000..77db33ff
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt
@@ -0,0 +1,154 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+import com.sun.source.util.DocTrees
+import jdk.javadoc.doclet.Doclet
+import jdk.javadoc.doclet.DocletEnvironment
+import jdk.javadoc.doclet.Reporter
+import java.nio.file.Files
+import java.nio.file.Path
+import java.nio.file.Paths
+import java.util.Locale
+import javax.lang.model.SourceVersion
+import javax.lang.model.util.Elements
+import javax.lang.model.util.Types
+
+class FilterDoclet : Doclet {
+    companion object {
+        lateinit var docTrees: DocTrees
+        lateinit var elementUtils: Elements
+        lateinit var typeUtils: Types
+        lateinit var outputPath: Path
+        var baseUrl: String = "https://docs.oracle.com/javase/8/docs/api/"
+        val CSS_FILENAME = "styles.css"
+        var outputDir = "."
+        var docTitle = "DTITLE"
+        var windowTitle = "WTITLE"
+        var noTimestamp: Boolean = false
+        val classIndex = ClassIndex()
+    }
+
+    override fun init(locale: Locale?, reporter: Reporter?) = Unit // TODO
+    override fun getName() = "FilterDoclet"
+    override fun getSupportedSourceVersion() = SourceVersion.latest()
+
+    override fun run(environment: DocletEnvironment): Boolean {
+        docTrees = environment.docTrees
+        elementUtils = environment.elementUtils
+        typeUtils = environment.typeUtils
+        outputPath = Paths.get(outputDir)
+        Files.createDirectories(outputPath)
+
+        classIndex.addVisible(environment.includedElements)
+
+        try {
+            generateClassFiles()
+            generateIndex()
+            return true
+        } catch (e: Exception) {
+            System.err.println("Error generating documentation: " + e.message)
+            e.printStackTrace()
+            return false
+        }
+    }
+
+    private fun generateClassFiles() = classIndex.classes().forEach(::generateClassFile)
+
+    private fun generateIndex() {
+        val indexPath = outputPath.resolve("index.html")
+
+        html {
+            body(
+                title = docTitle,
+                stylesheet = relativePath(indexPath, CSS_FILENAME),
+            ) {
+                div("index-container") {
+                    h1(docTitle, "index-title")
+                    compose {
+                        classIndex.generateHtml()
+                    }
+                }
+            }
+        }.let {
+            Files.newBufferedWriter(indexPath).use { writer ->
+                writer.write(it)
+            }
+        }
+    }
+
+    private fun generateClassFile(classInfo: ClassInfo) {
+        val classFilePath = outputPath.resolve(classInfo.fileName)
+        Files.createDirectories(classFilePath.parent)
+        val simpleName = classInfo.simpleName
+
+        html {
+            body(
+                title = "$simpleName - conscrypt-openjdk API",
+                stylesheet = relativePath(classFilePath, CSS_FILENAME),
+            ) {
+                compose {
+                    classInfo.generateHtml()
+                }
+            }
+        }.let {
+            Files.newBufferedWriter(classFilePath).use { writer ->
+                writer.write(it)
+            }
+        }
+    }
+
+    private fun relativePath(from: Path, to: String): String {
+        val fromDir = from.parent
+        val toPath = Paths.get(outputDir).resolve(to)
+
+        if (fromDir == null) {
+            return to
+        }
+
+        val relativePath = fromDir.relativize(toPath)
+        return relativePath.toString().replace('\\', '/')
+    }
+
+    override fun getSupportedOptions(): Set<Doclet.Option> {
+        return setOf<Doclet.Option>(
+            StringOption(
+                "-d",
+                "<directory>",
+                "Destination directory for output files"
+            ) { d: String -> outputDir = d },
+            StringOption(
+                "-doctitle",
+                "<title>",
+                "Document title"
+            ) { t: String -> docTitle = t },
+            StringOption(
+                "-windowtitle",
+                "<title>",
+                "Window title"
+            ) { w: String -> windowTitle = w },
+            StringOption(
+                "-link",
+                "<link>",
+                "Link"
+            ) { l: String -> baseUrl = l },
+            BooleanOption(
+                "-notimestamp",
+                "Something"
+            ) { noTimestamp = true })
+    }
+}
\ No newline at end of file
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt
new file mode 100644
index 00000000..0c2758b2
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt
@@ -0,0 +1,284 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+private typealias Block = HtmlBuilder.() -> Unit
+private fun Block.render(): String = HtmlBuilder().apply(this).toString()
+
+class HtmlBuilder {
+    private val content = StringBuilder()
+    override fun toString() = content.toString()
+
+    fun text(fragment: () -> String): StringBuilder = text(fragment())
+    fun text(text: String): StringBuilder = content.append(text)
+    fun compose(fragment: () -> String) {
+        content.append(fragment())
+    }
+
+    fun body(title: String, stylesheet: String, content: Block) {
+        text("""
+             <!DOCTYPE html>
+             <html><head>
+               <link rel="stylesheet" type="text/css" href="$stylesheet">
+               <meta charset="UTF-8">
+               <title>$title</title>
+             </head>
+             <body>""".trimIndent() +
+             content.render() +
+             "</body></html>")
+    }
+
+    private fun tagBlock(
+        tag: String, cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block)
+    {
+        content.append("\n<$tag")
+        cssClass?.let { content.append(""" class="$it"""") }
+        colspan?.let { content.append(""" colspan="$it"""") }
+        id?.let { content.append(""" id="$it"""") }
+        content.append(">")
+        content.append(block.render())
+        content.append("</$tag>\n")
+    }
+
+    fun div(cssClass: String? = null, id: String? = null, block: Block) =
+        tagBlock("div", cssClass = cssClass, colspan = null, id, block)
+    fun ul(cssClass: String? = null, id: String? = null, block: Block) =
+        tagBlock("ul", cssClass = cssClass, colspan = null, id, block)
+    fun ol(cssClass: String? = null, id: String? = null, block: Block) =
+        tagBlock("ol", cssClass = cssClass, colspan = null, id, block)
+    fun table(cssClass: String? = null, id: String? = null, block: Block) =
+        tagBlock("table", cssClass = cssClass, colspan = null, id, block)
+    fun tr(cssClass: String? = null, id: String? = null, block: Block) =
+        tagBlock("tr", cssClass = cssClass, colspan = null, id, block)
+    fun th(cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block) =
+        tagBlock("th", cssClass, colspan, id, block)
+    fun td(cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block) =
+        tagBlock("td", cssClass, colspan, id, block)
+
+    private fun tagValue(tag: String, value: String, cssClass: String? = null) {
+        val classText = cssClass?.let { """ class="$it"""" } ?: ""
+        content.append("<$tag$classText>$value</$tag>\n")
+    }
+
+    fun h1(heading: String, cssClass: String? = null) = tagValue("h1", heading, cssClass)
+    fun h1(cssClass: String? = null, block: Block) = h1(block.render(), cssClass)
+    fun h2(heading: String, cssClass: String? = null) = tagValue("h2", heading, cssClass)
+    fun h2(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
+    fun h3(heading: String, cssClass: String? = null) = tagValue("h3", heading, cssClass)
+    fun h3(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
+    fun h4(heading: String, cssClass: String? = null) = tagValue("h4", heading, cssClass)
+    fun h4(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
+    fun h5(heading: String, cssClass: String? = null) = tagValue("h5", heading, cssClass)
+    fun h5(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
+
+    fun p(text: String, cssClass: String? = null) = tagValue("p", text, cssClass)
+    fun p(cssClass: String? = null, block: Block) = p(block.render(), cssClass)
+    fun b(text: String, cssClass: String? = null) = tagValue("b", text, cssClass)
+    fun b(cssClass: String? = null, block: Block) = b(block.render(), cssClass)
+    fun pre(text: String, cssClass: String? = null) = tagValue("pre", text, cssClass)
+    fun pre(cssClass: String? = null, block: Block) = pre(block.render(), cssClass)
+    fun code(text: String, cssClass: String? = null) = tagValue("code", text, cssClass)
+    fun code(cssClass: String? = null, block: Block) = code(block.render(), cssClass)
+    fun strong(text: String, cssClass: String? = null) = tagValue("strong", text, cssClass)
+    fun strong(cssClass: String? = null, block: Block) = strong(block.render(), cssClass)
+
+    fun br() = content.append("<br/>\n")
+    fun a(href: String, label: String) {
+        content.append("""<a href="$href">$label</a>""")
+    }
+    fun a(href: String, block: Block) = a(href, block.render())
+    fun a(href: String) = a(href, href)
+
+    fun li(text: String, cssClass: String? = null) = tagValue("li", text, cssClass)
+    fun li(cssClass: String? = null, block: Block) = li(block.render(), cssClass)
+
+    fun <T> items(collection: Iterable<T>, cssClass: String? = null,
+                  transform: HtmlBuilder.(T) -> Unit = { text(it.toString()) }) {
+        collection.forEach {
+            li(cssClass = cssClass) { transform(it) }
+        }
+    }
+
+    fun <T> row(item: T, rowClass: String? = null, cellClass: String? = null,
+                span: Int? = null,
+                transform: HtmlBuilder.(T) -> Unit = { td {it.toString() } }) {
+        tr(cssClass = rowClass) {
+            transform(item)
+        }
+    }
+    fun <T> rowGroup(rows: Collection<T>, title: String? = null, rowClass: String? = null, cellClass: String? = null,
+                 colspan: Int? = null,
+                transform: HtmlBuilder.(T) -> Unit) {
+        if(rows.isNotEmpty()) {
+            title?.let {
+                tr {
+                    th(colspan = colspan) {
+                        strong(it)
+                    }
+                }
+            }
+            rows.forEach {
+                tr {
+                    transform(it)
+                }
+            }
+        }
+    }
+}
+
+fun html(block: Block) = block.render()
+
+fun exampleSubfunction() = html {
+    h1("Headings from exampleSubfunction")
+    listOf("one", "two", "three").forEach {
+        h1(it)
+    }
+}
+
+fun example() = html {
+    val fruits = listOf("Apple", "Banana", "Cherry")
+    body(
+        stylesheet = "path/to/stylesheet.css",
+        title = "Page Title"
+    ) {
+        div(cssClass = "example-class") {
+            text {
+                "This is a div"
+            }
+            h1 {
+                text("Heading1a")
+            }
+            h2 {
+                a("www.google.com", "Heading with a link")
+            }
+            h3("Heading with CSS class", "my-class")
+            h2("h2", "my-class")
+            p("Hello world")
+            compose {
+                exampleSubfunction()
+            }
+            br()
+            a("www.google.com") {
+                text("a link with ")
+                b("bold")
+                text(" text.")
+            }
+
+        }
+        h1("Lists")
+
+        h2("Unordered list:")
+        ul {
+            li("First item")
+            li("Second item")
+            li {
+                text { "Complex item with " }
+                b { text { "bold text" } }
+            }
+            ul {
+                li("First nested item")
+                li("Second nested item")
+            }
+        }
+
+        h2("Ordered list:")
+        ol {
+            li("First item")
+            li("Second item")
+            li {
+                text { "Item with a " }
+                a(href = "https://example.com") { text { "link" } }
+            }
+        }
+        h2("List item iteration")
+        ul {
+            // Default
+            items(fruits)
+            // Text transform
+            items(fruits) {
+                text("I like ${it}.")
+            }
+            // HTML transform with a CSS class
+            items(fruits, "myclass") {
+                a("www.google.com") {
+                    b(it)
+                }
+            }
+        }
+        ol("ol-class") {
+            items((1..5).asIterable()) {
+                text("Item $it")
+            }
+        }
+    }
+    val data1 = listOf(1, 2)
+    val data2 = "3" to "4"
+    val data3 = listOf(
+        "tag1" to "Some value",
+        "tag2" to "Next Value",
+        "tag3" to "Another value"
+    )
+
+    table("table-class") {
+        tr {
+            th {
+                text("First column")
+            }
+            th {
+                text("Second column")
+
+            }
+        }
+        tr("tr-class") {
+            td("td-class") {
+                text("Data 1")
+            }
+            td(colspan = 2, id = "foo") {
+                    text("Data 2")
+            }
+        }
+        tr {
+            td() {
+                text("Data 3")
+            }
+        }
+        row(data1, "c1") {
+            a(href="www.google.com") { text("$it") }
+        }
+        row(data2) { p:Pair<String, String> ->
+            td {
+                text(p.first)
+            }
+            td {
+                text(p.second)
+            }
+
+        }
+        rowGroup(data3, title = "Row Group", colspan=2) { p: Pair<String, String> ->
+            td {
+                text(p.first)
+            }
+            td {
+                text(p.second)
+            }
+        }
+    }
+}
+
+fun main() {
+    example().let(::println)
+}
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/Options.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/Options.kt
new file mode 100644
index 00000000..3fc57b0f
--- /dev/null
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/Options.kt
@@ -0,0 +1,53 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package org.conscrypt.doclet
+
+import jdk.javadoc.doclet.Doclet.Option
+import java.util.function.Consumer
+
+abstract class BaseOption(private val name: String) : Option {
+    override  fun getKind() = Option.Kind.STANDARD
+    override fun getNames(): List<String> = listOf(name)
+}
+
+class StringOption(name: String,
+                   private val parameters: String,
+                   private val description: String,
+                   private val action: Consumer<String>
+) : BaseOption(name) {
+    override fun getArgumentCount() = 1
+    override fun getDescription(): String = description
+    override fun getParameters(): String = parameters
+
+    override fun process(option: String, arguments: MutableList<String>): Boolean {
+        action.accept(arguments[0])
+        return true
+    }
+}
+
+class BooleanOption(name: String,
+                    private val description: String,
+                    private val action: Runnable): BaseOption(name) {
+    override fun getArgumentCount() = 0
+    override fun getDescription(): String = description
+    override fun getParameters(): String = ""
+
+    override fun process(option: String, arguments: MutableList<String>): Boolean {
+        action.run()
+        return true
+    }
+}
diff --git a/api-doclet/src/main/resources/styles.css b/api-doclet/src/main/resources/styles.css
new file mode 100644
index 00000000..262f64ed
--- /dev/null
+++ b/api-doclet/src/main/resources/styles.css
@@ -0,0 +1,147 @@
+body {
+    font-family: Arial, sans-serif;
+    line-height: 1.2;
+    color: #333;
+    /* max-width: 800px; */
+    margin: 0 auto;
+    padding: 10px;
+}
+.method {
+    margin-bottom: 30px;
+    border-bottom: 1px solid #eee;
+    padding-bottom: 20px;
+}
+.body h3 {
+    font-size: 24px;
+    underline: true
+}
+.method-name {
+    color: #2c3e50;
+    font-size: 24px;
+    margin-bottom: 10px;
+}
+.method-signature .class-signature {
+    background-color: #f7f9fa;
+    border: 1px solid #e1e4e8;
+    border-radius: 3px;
+    padding: 12px;
+    font-family: monospace;
+    font-size: 14px;
+    overflow-x: auto;
+}
+.description {
+    margin: 15px 0;
+    padding: 10px;
+    background-color: #f8f8f8;
+}
+.params {
+    margin-top: 20px;
+}
+.params h5 {
+    color: #2c3e50;
+    font-size: 16px;
+}
+.params-table {
+    border-collapse: collapse;
+}
+.params-table th, .params-table td {
+    border: 1px solid #ddd;
+    padding: 12px;
+    text-align: left;
+}
+.params-table th {
+    background-color: #f2f2f2;
+    font-weight: bold;
+}
+.params-table tr:nth-child(even) {
+    background-color: #f8f8f8;
+}
+.constructor {
+    margin-bottom: 30px;
+    border-bottom: 1px solid #eee;
+    padding-bottom: 20px;
+}
+.constructor-name {
+    color: #2c3e50;
+    font-size: 24px;
+    margin-bottom: 10px;
+}
+.constructor-signature {
+    background-color: #f7f9fa;
+    border: 1px solid #e1e4e8;
+    border-radius: 3px;
+    padding: 10px;
+    font-family: monospace;
+    font-size: 14px;
+    overflow-x: auto;
+}
+/* Index page styles */
+.index-container {
+    margin: 0 auto;
+    padding: 20px;
+}
+.index-title {
+    color: #2c3e50;
+    font-size: 32px;
+    margin-bottom: 20px;
+    border-bottom: 2px solid #3498db;
+    padding-bottom: 10px;
+}
+.package-section {
+    margin-bottom: 30px;
+}
+.package-name {
+    color: #2c3e50;
+    font-size: 12px;
+    margin-bottom: 10px;
+    padding: 10px;
+}
+.class-list {
+    list-style-type: none;
+    padding-left: 20px;
+}
+.class-list li {
+    margin-bottom: 5px;
+}
+.class-list a {
+    color: #3498db;
+    text-decoration: none;
+}
+.class-list a:hover {
+    text-decoration: underline;
+}
+.header {
+    font-size: 28px;
+    color: #2c3e50;
+    margin-bottom: 20px;
+}
+
+.class-description {
+    margin: 20px 0;
+    padding: 15px;
+    background-color: #f8f9fa;
+    font-size: 16px;
+    line-height: 1.6;
+}
+
+.class-description p {
+    margin-bottom: 10px;
+}
+
+.class-description code {
+    background-color: #e9ecef;
+    padding: 2px 4px;
+    border-radius: 4px;
+    font-family: monospace;
+}
+
+.package-name {
+    font-family: monospace;
+    font-size: 14px;
+    color: #6c757d;
+    background-color: #f1f3f5;
+    padding: 5px 10px;
+    border-radius: 4px;
+    margin-bottom: 20px;
+    display: inline-block;
+}
diff --git a/build.gradle b/build.gradle
index e504bbc0..cd5d4582 100644
--- a/build.gradle
+++ b/build.gradle
@@ -3,8 +3,7 @@ import org.gradle.util.VersionNumber
 
 buildscript {
     ext.android_tools = 'com.android.tools.build:gradle:7.4.0'
-    ext.errorproneVersion = '2.4.0'
-    ext.errorproneJavacVersion = '9+181-r4173-1'
+    ext.errorproneVersion = '2.31.0'
     repositories {
         google()
         mavenCentral()
@@ -19,8 +18,8 @@ buildscript {
 plugins {
     // Add dependency for build script so we can access Git from our
     // build script.
-    id 'org.ajoberstar.grgit' version '3.1.1'
-    id 'net.ltgt.errorprone' version '1.3.0'
+    id 'org.ajoberstar.grgit' version '5.2.2'
+    id 'net.ltgt.errorprone' version '4.0.0'
     id "com.google.osdetector" version "1.7.3"
     id "biz.aQute.bnd.builder" version "6.4.0" apply false
 }
@@ -139,7 +138,6 @@ subprojects {
 
     dependencies {
         errorprone("com.google.errorprone:error_prone_core:$errorproneVersion")
-        errorproneJavac("com.google.errorprone:javac:$errorproneJavacVersion")
     }
 
     tasks.register("generateProperties", WriteProperties) {
@@ -156,9 +154,7 @@ subprojects {
     if (!androidProject) {
         java {
             toolchain {
-                // Compile with a real JDK 8 so we don't end up with accidental dependencies
-                // on Java 11 bootclasspath, e.g. ByteBuffer.flip().
-                languageVersion = JavaLanguageVersion.of(8)
+                languageVersion = JavaLanguageVersion.of(11)
             }
         }
 
@@ -166,6 +162,8 @@ subprojects {
             t.configure {
                 options.compilerArgs += ["-Xlint:all", "-Xlint:-options", '-Xmaxwarns', '9999999']
                 options.encoding = "UTF-8"
+                options.release = 8
+
                 if (rootProject.hasProperty('failOnWarnings') && rootProject.failOnWarnings.toBoolean()) {
                     options.compilerArgs += ["-Werror"]
                 }
@@ -190,14 +188,7 @@ subprojects {
 
         javadoc.options {
             encoding = 'UTF-8'
-            links 'https://docs.oracle.com/javase/8/docs/api/'
-        }
-
-        // All non-Android projects build with Java 8, so disable doclint as it's noisy.
-        allprojects {
-            tasks.withType(Javadoc) {
-                options.addStringOption('Xdoclint:none', '-quiet')
-            }
+            links 'https://docs.oracle.com/en/java/javase/21/docs/api/java.base/'
         }
 
         tasks.register("javadocJar", Jar) {
diff --git a/common/src/jni/main/include/conscrypt/app_data.h b/common/src/jni/main/include/conscrypt/app_data.h
index 8ccd90bc..9f64f94d 100644
--- a/common/src/jni/main/include/conscrypt/app_data.h
+++ b/common/src/jni/main/include/conscrypt/app_data.h
@@ -238,7 +238,7 @@ class AppData {
 
     void clearApplicationProtocols() {
         if (applicationProtocolsData != nullptr) {
-            delete applicationProtocolsData;
+            delete[] applicationProtocolsData;
             applicationProtocolsData = nullptr;
             applicationProtocolsLength = static_cast<size_t>(-1);
         }
diff --git a/common/src/main/java/org/conscrypt/ArrayUtils.java b/common/src/main/java/org/conscrypt/ArrayUtils.java
index 99a1eb58..63fa5a87 100644
--- a/common/src/main/java/org/conscrypt/ArrayUtils.java
+++ b/common/src/main/java/org/conscrypt/ArrayUtils.java
@@ -21,6 +21,7 @@ import java.util.Arrays;
 /**
  * Compatibility utility for Arrays.
  */
+@Internal
 public final class ArrayUtils {
     private ArrayUtils() {}
 
@@ -73,4 +74,11 @@ public final class ArrayUtils {
         }
         return result;
     }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static <T> boolean isEmpty(T[] array) {
+        return array == null || array.length == 0;
+    }
 }
diff --git a/common/src/main/java/org/conscrypt/ByteArray.java b/common/src/main/java/org/conscrypt/ByteArray.java
index bfc544f9..3e97eb5f 100644
--- a/common/src/main/java/org/conscrypt/ByteArray.java
+++ b/common/src/main/java/org/conscrypt/ByteArray.java
@@ -21,11 +21,12 @@ import java.util.Arrays;
 /**
  * Byte array wrapper for hashtable use. Implements equals() and hashCode().
  */
-final class ByteArray {
+@Internal
+public final class ByteArray {
     private final byte[] bytes;
     private final int hashCode;
 
-    ByteArray(byte[] bytes) {
+    public ByteArray(byte[] bytes) {
         this.bytes = bytes;
         this.hashCode = Arrays.hashCode(bytes);
     }
@@ -37,6 +38,9 @@ final class ByteArray {
 
     @Override
     public boolean equals(Object o) {
+        if (o == this) {
+            return true;
+        }
         if (!(o instanceof ByteArray)) {
             return false;
         }
diff --git a/common/src/main/java/org/conscrypt/Hkdf.java b/common/src/main/java/org/conscrypt/Hkdf.java
new file mode 100644
index 00000000..b84ba071
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/Hkdf.java
@@ -0,0 +1,124 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * limitations under the License
+ */
+
+package org.conscrypt;
+
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.util.Objects;
+
+import javax.crypto.Mac;
+import javax.crypto.spec.SecretKeySpec;
+
+/**
+ * Hkdf - perform HKDF key derivation operations per RFC 5869.
+ * <p>
+ * Instances should be instantiated using the standard JCA name for the required HMAC.
+ * <p>
+ * Each invocation of expand or extract uses a new Mac instance and so instances
+ * of Hkdf are thread-safe.</p>
+ */
+public final class Hkdf {
+    // HMAC algorithm to use.
+    private final String hmacName;
+    private final int macLength;
+
+    /**
+     * Creates an Hkdf instance which will use hmacName as the name for the underlying
+     * HMAC algorithm, which will be located using normal JCA precedence rules.
+     * <p>
+     * @param hmacName the name of the HMAC algorithm to use
+     * @throws NoSuchAlgorithmException if hmacName is not a valid HMAC name
+     */
+    public Hkdf(String hmacName) throws  NoSuchAlgorithmException {
+        Objects.requireNonNull(hmacName);
+        this.hmacName = hmacName;
+
+        // Stash the MAC length with the bonus that we'll fail fast here if no such algorithm.
+        macLength = Mac.getInstance(hmacName).getMacLength();
+    }
+
+    // Visible for testing.
+    public int getMacLength() {
+        return macLength;
+    }
+
+    /**
+     * Performs an HKDF extract operation as specified in RFC 5869.
+     *
+     * @param salt the salt to use
+     * @param ikm initial keying material
+     * @return a pseudorandom key suitable for use in expand operations
+     * @throws InvalidKeyException if the salt is not suitable for use as an HMAC key
+     * @throws NoSuchAlgorithmException if the Mac algorithm is no longer available
+     */
+
+    public byte[] extract(byte[] salt, byte[] ikm)
+        throws InvalidKeyException, NoSuchAlgorithmException {
+        Objects.requireNonNull(salt);
+        Objects.requireNonNull(ikm);
+        Preconditions.checkArgument(ikm.length > 0, "Empty keying material");
+        if (salt.length == 0) {
+            salt = new byte[getMacLength()];
+        }
+        return getMac(salt).doFinal(ikm);
+    }
+
+    /**
+     * Performs an HKDF expand operation as specified in RFC 5869.
+     *
+     * @param prk a pseudorandom key of at least HashLen octets, usually the output from the
+     *            extract step. Where HashLen is the key size of the underlying Mac
+     * @param info optional context and application specific information, can be zero length
+     * @param length length of output keying material in bytes (<= 255*HashLen)
+     * @return output of keying material of length bytes
+     * @throws InvalidKeyException if prk is not suitable for use as an HMAC key
+     * @throws IllegalArgumentException if length is out of the allowed range
+     * @throws NoSuchAlgorithmException if the Mac algorithm is no longer available
+     */
+    public byte[] expand(byte[] prk, byte[] info, int length)
+        throws InvalidKeyException, NoSuchAlgorithmException {
+        Objects.requireNonNull(prk);
+        Objects.requireNonNull(info);
+        Preconditions.checkArgument(length >= 0, "Negative length");
+        Preconditions.checkArgument(length < 255 * getMacLength(), "Length too long");
+        Mac mac = getMac(prk);
+        int macLength = getMacLength();
+
+        byte[] t = new byte[0];
+        byte[] output = new byte[length];
+        int outputOffset = 0;
+        byte[] counter = new byte[] { 0x00 };
+        while (outputOffset < length) {
+            counter[0]++;
+            mac.update(t);
+            mac.update(info);
+            t = mac.doFinal(counter);
+            int size = Math.min(macLength, length - outputOffset);
+            System.arraycopy(t, 0, output, outputOffset, size);
+            outputOffset += size;
+        }
+        return output;
+    }
+
+    private Mac getMac(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
+        // Can potentially throw NoSuchAlgorithmException if the there has been a change
+        // in installed Providers.
+        Mac mac = Mac.getInstance(hmacName);
+        mac.init(new SecretKeySpec(key, "RAW"));
+        return mac; // https://www.youtube.com/watch?v=uB1D9wWxd2w
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/HpkeContext.java b/common/src/main/java/org/conscrypt/HpkeContext.java
index 4317796e..355997f0 100644
--- a/common/src/main/java/org/conscrypt/HpkeContext.java
+++ b/common/src/main/java/org/conscrypt/HpkeContext.java
@@ -23,8 +23,6 @@ import java.security.Security;
 
 /**
  * Hybrid Public Key Encryption (HPKE) sender APIs.
- *
- * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
  * <p>
  * Base class for HPKE sender and recipient contexts.
  * <p>
@@ -36,6 +34,7 @@ import java.security.Security;
  * to use for seal and open operations.
  *
  * Secret key material based on the context may also be generated and exported as per RFC 9180.
+ * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">RFC 9180 (HPKE)</a>
  */
 public abstract class HpkeContext {
   protected final HpkeSpi spi;
diff --git a/common/src/main/java/org/conscrypt/HpkeImpl.java b/common/src/main/java/org/conscrypt/HpkeImpl.java
index a09f3df4..3c62611c 100644
--- a/common/src/main/java/org/conscrypt/HpkeImpl.java
+++ b/common/src/main/java/org/conscrypt/HpkeImpl.java
@@ -34,6 +34,7 @@ import javax.crypto.BadPaddingException;
  * Implementation of {@link HpkeSpi}.  Should not be used directly, but rather by one
  * of the subclasses of {@link HpkeContext}.
  */
+@Internal
 public class HpkeImpl implements HpkeSpi {
   private final HpkeSuite hpkeSuite;
 
diff --git a/common/src/main/java/org/conscrypt/NativeCrypto.java b/common/src/main/java/org/conscrypt/NativeCrypto.java
index d017f9e4..5c7d3283 100644
--- a/common/src/main/java/org/conscrypt/NativeCrypto.java
+++ b/common/src/main/java/org/conscrypt/NativeCrypto.java
@@ -524,9 +524,11 @@ public final class NativeCrypto {
 
     static native int get_X509_ex_pathlen(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native long X509_get_notBefore(long x509ctx, OpenSSLX509Certificate holder);
+    static native long X509_get_notBefore(long x509ctx, OpenSSLX509Certificate holder)
+            throws ParsingException;
 
-    static native long X509_get_notAfter(long x509ctx, OpenSSLX509Certificate holder);
+    static native long X509_get_notAfter(long x509ctx, OpenSSLX509Certificate holder)
+            throws ParsingException;
 
     static native long X509_get_version(long x509ctx, OpenSSLX509Certificate holder);
 
@@ -607,9 +609,11 @@ public final class NativeCrypto {
 
     static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx, OpenSSLX509CRL holder);
 
-    static native long X509_CRL_get_lastUpdate(long x509CrlCtx, OpenSSLX509CRL holder);
+    static native long X509_CRL_get_lastUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
+            throws ParsingException;
 
-    static native long X509_CRL_get_nextUpdate(long x509CrlCtx, OpenSSLX509CRL holder);
+    static native long X509_CRL_get_nextUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
+            throws ParsingException;
 
     // --- X509_REVOKED --------------------------------------------------------
 
@@ -787,6 +791,7 @@ public final class NativeCrypto {
     static final String OBSOLETE_PROTOCOL_SSLV3 = "SSLv3";
     static final String DEPRECATED_PROTOCOL_TLSV1 = "TLSv1";
     static final String DEPRECATED_PROTOCOL_TLSV1_1 = "TLSv1.1";
+
     private static final String SUPPORTED_PROTOCOL_TLSV1_2 = "TLSv1.2";
     static final String SUPPORTED_PROTOCOL_TLSV1_3 = "TLSv1.3";
 
diff --git a/common/src/main/java/org/conscrypt/OpenSSLKey.java b/common/src/main/java/org/conscrypt/OpenSSLKey.java
index e5e81f7c..4249b8ef 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLKey.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLKey.java
@@ -32,7 +32,8 @@ import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
 /**
  * Represents a BoringSSL {@code EVP_PKEY}.
  */
-final class OpenSSLKey {
+@Internal
+public final class OpenSSLKey {
     private final NativeRef.EVP_PKEY ctx;
 
     private final boolean wrapped;
@@ -255,7 +256,7 @@ final class OpenSSLKey {
      *
      * @throws InvalidKeyException if parsing fails
      */
-    static OpenSSLKey fromPublicKeyPemInputStream(InputStream is)
+    public static OpenSSLKey fromPublicKeyPemInputStream(InputStream is)
             throws InvalidKeyException {
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
         try {
@@ -272,7 +273,7 @@ final class OpenSSLKey {
         }
     }
 
-    PublicKey getPublicKey() throws NoSuchAlgorithmException {
+    public PublicKey getPublicKey() throws NoSuchAlgorithmException {
         switch (NativeCrypto.EVP_PKEY_type(ctx)) {
             case NativeConstants.EVP_PKEY_RSA:
                 return new OpenSSLRSAPublicKey(this);
diff --git a/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java b/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java
index d3983cdb..ad974941 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java
@@ -40,6 +40,7 @@ import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.TimeZone;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.security.auth.x500.X500Principal;
diff --git a/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java b/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java
index 3998a25a..76849914 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java
@@ -47,6 +47,7 @@ import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.TimeZone;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.security.auth.x500.X500Principal;
diff --git a/common/src/main/java/org/conscrypt/SSLParametersImpl.java b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
index 846414bd..3efa1c98 100644
--- a/common/src/main/java/org/conscrypt/SSLParametersImpl.java
+++ b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
@@ -149,13 +149,12 @@ final class SSLParametersImpl implements Cloneable {
           enabledProtocols = NativeCrypto.getDefaultProtocols().clone();
         } else {
             String[] filteredProtocols =
-                    filterFromProtocols(protocols, Arrays.asList(!Platform.isTlsV1Filtered()
-                        ? new String[0]
-                        : new String[] {
+                    filterFromProtocols(protocols, Arrays.asList(Platform.isTlsV1Filtered()
+                        ? new String[] {
                             NativeCrypto.OBSOLETE_PROTOCOL_SSLV3,
                             NativeCrypto.DEPRECATED_PROTOCOL_TLSV1,
-                            NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1,
-                        }));
+                            NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1,}
+                        : new String[0]));
             isEnabledProtocolsFiltered = protocols.length != filteredProtocols.length;
             enabledProtocols = NativeCrypto.checkEnabledProtocols(filteredProtocols).clone();
         }
diff --git a/common/src/main/java/org/conscrypt/TrustManagerImpl.java b/common/src/main/java/org/conscrypt/TrustManagerImpl.java
index 1bacf7ec..31937ef8 100644
--- a/common/src/main/java/org/conscrypt/TrustManagerImpl.java
+++ b/common/src/main/java/org/conscrypt/TrustManagerImpl.java
@@ -34,6 +34,12 @@
 
 package org.conscrypt;
 
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.Policy;
+import org.conscrypt.ct.PolicyCompliance;
+import org.conscrypt.ct.VerificationResult;
+import org.conscrypt.ct.Verifier;
+
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.net.Socket;
@@ -63,16 +69,13 @@ import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.logging.Logger;
+
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.X509ExtendedTrustManager;
-import org.conscrypt.ct.CTLogStore;
-import org.conscrypt.ct.CTPolicy;
-import org.conscrypt.ct.CTVerificationResult;
-import org.conscrypt.ct.CTVerifier;
 
 /**
  *
@@ -139,8 +142,9 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private final Exception err;
     private final CertificateFactory factory;
     private final CertBlocklist blocklist;
-    private CTVerifier ctVerifier;
-    private CTPolicy ctPolicy;
+    private LogStore ctLogStore;
+    private Verifier ctVerifier;
+    private Policy ctPolicy;
 
     private ConscryptHostnameVerifier hostnameVerifier;
 
@@ -163,18 +167,16 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this(keyStore, manager, certStore, null);
     }
 
-    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager,
-            ConscryptCertStore certStore,
-                            CertBlocklist blocklist) {
+    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
+            CertBlocklist blocklist) {
         this(keyStore, manager, certStore, blocklist, null, null, null);
     }
 
     /**
      * For testing only.
      */
-    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager,
-                            ConscryptCertStore certStore, CertBlocklist blocklist, CTLogStore ctLogStore,
-                            CTVerifier ctVerifier, CTPolicy ctPolicy) {
+    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
+            CertBlocklist blocklist, LogStore ctLogStore, Verifier ctVerifier, Policy ctPolicy) {
         CertPathValidator validatorLocal = null;
         CertificateFactory factoryLocal = null;
         KeyStore rootKeyStoreLocal = null;
@@ -214,7 +216,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
 
         if (ctPolicy == null) {
-            ctPolicy = Platform.newDefaultPolicy(ctLogStore);
+            ctPolicy = Platform.newDefaultPolicy();
         }
 
         this.pinManager = manager;
@@ -227,8 +229,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this.acceptedIssuers = acceptedIssuersLocal;
         this.err = errLocal;
         this.blocklist = blocklist;
-        this.ctVerifier = new CTVerifier(ctLogStore);
+        this.ctLogStore = ctLogStore;
+        this.ctVerifier = new Verifier(ctLogStore);
         this.ctPolicy = ctPolicy;
+        if (ctLogStore != null) {
+            ctLogStore.setPolicy(ctPolicy);
+        }
     }
 
     @SuppressWarnings("JdkObsolete")  // KeyStore#aliases is the only API available
@@ -680,7 +686,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
             if (!clientAuth &&
                     (ctEnabledOverride || (host != null && Platform
                             .isCTVerificationRequired(host)))) {
-                checkCT(host, wholeChain, ocspData, tlsSctData);
+                checkCT(wholeChain, ocspData, tlsSctData);
             }
 
             if (untrustedChain.isEmpty()) {
@@ -726,15 +732,23 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
     }
 
-    private void checkCT(String host, List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
+    private void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
             throws CertificateException {
-        CTVerificationResult result =
+        if (ctLogStore.getState() != LogStore.State.COMPLIANT) {
+            /* Fail open. For some reason, the LogStore is not usable. It could
+             * be because there is no log list available or that the log list
+             * is too old (according to the policy). */
+            return;
+        }
+        VerificationResult result =
                 ctVerifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);
 
-        if (!ctPolicy.doesResultConformToPolicy(result, host,
-                    chain.toArray(new X509Certificate[chain.size()]))) {
+        X509Certificate leaf = chain.get(0);
+        PolicyCompliance compliance = ctPolicy.doesResultConformToPolicy(result, leaf);
+        if (compliance != PolicyCompliance.COMPLY) {
             throw new CertificateException(
-                    "Certificate chain does not conform to required transparency policy.");
+                    "Certificate chain does not conform to required transparency policy: "
+                    + compliance.name());
         }
     }
 
@@ -1025,12 +1039,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     }
 
     // Replace the CTVerifier. For testing only.
-    public void setCTVerifier(CTVerifier verifier) {
+    public void setCTVerifier(Verifier verifier) {
         this.ctVerifier = verifier;
     }
 
     // Replace the CTPolicy. For testing only.
-    public void setCTPolicy(CTPolicy policy) {
+    public void setCTPolicy(Policy policy) {
         this.ctPolicy = policy;
     }
 }
diff --git a/common/src/main/java/org/conscrypt/XdhKeySpec.java b/common/src/main/java/org/conscrypt/XdhKeySpec.java
index 9848ae74..f2f1f43e 100644
--- a/common/src/main/java/org/conscrypt/XdhKeySpec.java
+++ b/common/src/main/java/org/conscrypt/XdhKeySpec.java
@@ -6,7 +6,7 @@ import java.util.Objects;
 
 /**
  * External Diffie–Hellman key spec holding a key which could be either a public or private key.
- *
+ * <p>
  * Subclasses {@code EncodedKeySpec} using the non-Standard "raw" format.  The XdhKeyFactory
  * class utilises this in order to create XDH keys from raw bytes and to return them
  * as an XdhKeySpec allowing the raw key material to be extracted from an XDH key.
diff --git a/common/src/main/java/org/conscrypt/ct/CTLogInfo.java b/common/src/main/java/org/conscrypt/ct/CTLogInfo.java
deleted file mode 100644
index c2e312a9..00000000
--- a/common/src/main/java/org/conscrypt/ct/CTLogInfo.java
+++ /dev/null
@@ -1,145 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package org.conscrypt.ct;
-
-import java.security.InvalidKeyException;
-import java.security.MessageDigest;
-import java.security.NoSuchAlgorithmException;
-import java.security.PublicKey;
-import java.security.Signature;
-import java.security.SignatureException;
-import java.util.Arrays;
-import org.conscrypt.Internal;
-
-/**
- * Properties about a Certificate Transparency Log.
- * This object stores information about a CT log, its public key, description and URL.
- * It allows verification of SCTs against the log's public key.
- */
-@Internal
-public class CTLogInfo {
-    private final byte[] logId;
-    private final PublicKey publicKey;
-    private final String description;
-    private final String url;
-
-    public CTLogInfo(PublicKey publicKey, String description, String url) {
-        try {
-            this.logId = MessageDigest.getInstance("SHA-256")
-                .digest(publicKey.getEncoded());
-        } catch (NoSuchAlgorithmException e) {
-            // SHA-256 is guaranteed to be available
-            throw new RuntimeException(e);
-        }
-
-        this.publicKey = publicKey;
-        this.description = description;
-        this.url = url;
-    }
-
-    /**
-     * Get the log's ID, that is the SHA-256 hash of it's public key
-     */
-    public byte[] getID() {
-        return logId;
-    }
-
-    public PublicKey getPublicKey() {
-        return publicKey;
-    }
-
-    public String getDescription() {
-        return description;
-    }
-
-    public String getUrl() {
-        return url;
-    }
-
-    @Override
-    public boolean equals(Object other) {
-        if (this == other) {
-            return true;
-        }
-        if (!(other instanceof CTLogInfo)) {
-            return false;
-        }
-
-        CTLogInfo that = (CTLogInfo)other;
-        return
-            this.publicKey.equals(that.publicKey) &&
-            this.description.equals(that.description) &&
-            this.url.equals(that.url);
-    }
-
-    @Override
-    public int hashCode() {
-        int hash = 1;
-        hash = hash * 31 + publicKey.hashCode();
-        hash = hash * 31 + description.hashCode();
-        hash = hash * 31 + url.hashCode();
-
-        return hash;
-    }
-
-    /**
-     * Verify the signature of a signed certificate timestamp for the given certificate entry
-     * against the log's public key.
-     *
-     * @return the result of the verification
-     */
-    public VerifiedSCT.Status verifySingleSCT(SignedCertificateTimestamp sct,
-                                              CertificateEntry entry) {
-        if (!Arrays.equals(sct.getLogID(), getID())) {
-            return VerifiedSCT.Status.UNKNOWN_LOG;
-        }
-
-        byte[] toVerify;
-        try {
-            toVerify = sct.encodeTBS(entry);
-        } catch (SerializationException e) {
-            return VerifiedSCT.Status.INVALID_SCT;
-        }
-
-        Signature signature;
-        try {
-            String algorithm = sct.getSignature().getAlgorithm();
-            signature = Signature.getInstance(algorithm);
-        } catch (NoSuchAlgorithmException e) {
-            return VerifiedSCT.Status.INVALID_SCT;
-        }
-
-        try {
-            signature.initVerify(publicKey);
-        } catch (InvalidKeyException e) {
-            return VerifiedSCT.Status.INVALID_SCT;
-        }
-
-        try {
-            signature.update(toVerify);
-            if (!signature.verify(sct.getSignature().getSignature())) {
-                return VerifiedSCT.Status.INVALID_SIGNATURE;
-            }
-            return VerifiedSCT.Status.VALID;
-        } catch (SignatureException e) {
-            // This only happens if the signature is not initialized,
-            // but we call initVerify just before, so it should never do
-            throw new RuntimeException(e);
-        }
-    }
-}
-
diff --git a/common/src/main/java/org/conscrypt/ct/CertificateEntry.java b/common/src/main/java/org/conscrypt/ct/CertificateEntry.java
index 72ed5306..137ded1e 100644
--- a/common/src/main/java/org/conscrypt/ct/CertificateEntry.java
+++ b/common/src/main/java/org/conscrypt/ct/CertificateEntry.java
@@ -61,8 +61,8 @@ public class CertificateEntry {
         } else if (entryType == LogEntryType.X509_ENTRY && issuerKeyHash != null) {
             throw new IllegalArgumentException("unexpected issuerKeyHash for X509 entry.");
         }
-        
-        if (issuerKeyHash != null && issuerKeyHash.length != CTConstants.ISSUER_KEY_HASH_LENGTH) {
+
+        if (issuerKeyHash != null && issuerKeyHash.length != Constants.ISSUER_KEY_HASH_LENGTH) {
             throw new IllegalArgumentException("issuerKeyHash must be 32 bytes long");
         }
 
@@ -83,11 +83,11 @@ public class CertificateEntry {
     public static CertificateEntry createForPrecertificate(OpenSSLX509Certificate leaf,
             OpenSSLX509Certificate issuer) throws CertificateException {
         try {
-            if (!leaf.getNonCriticalExtensionOIDs().contains(CTConstants.X509_SCT_LIST_OID)) {
+            if (!leaf.getNonCriticalExtensionOIDs().contains(Constants.X509_SCT_LIST_OID)) {
                 throw new CertificateException("Certificate does not contain embedded signed timestamps");
             }
 
-            byte[] tbs = leaf.getTBSCertificateWithoutExtension(CTConstants.X509_SCT_LIST_OID);
+            byte[] tbs = leaf.getTBSCertificateWithoutExtension(Constants.X509_SCT_LIST_OID);
 
             byte[] issuerKey = issuer.getPublicKey().getEncoded();
             MessageDigest md = MessageDigest.getInstance("SHA-256");
@@ -124,11 +124,11 @@ public class CertificateEntry {
      * TLS encode the CertificateEntry structure.
      */
     public void encode(OutputStream output) throws SerializationException {
-        Serialization.writeNumber(output, entryType.ordinal(), CTConstants.LOG_ENTRY_TYPE_LENGTH);
+        Serialization.writeNumber(output, entryType.ordinal(), Constants.LOG_ENTRY_TYPE_LENGTH);
         if (entryType == LogEntryType.PRECERT_ENTRY) {
             Serialization.writeFixedBytes(output, issuerKeyHash);
         }
-        Serialization.writeVariableBytes(output, certificate, CTConstants.CERTIFICATE_LENGTH_BYTES);
+        Serialization.writeVariableBytes(output, certificate, Constants.CERTIFICATE_LENGTH_BYTES);
     }
 }
 
diff --git a/common/src/main/java/org/conscrypt/ct/CTConstants.java b/common/src/main/java/org/conscrypt/ct/Constants.java
similarity index 98%
rename from common/src/main/java/org/conscrypt/ct/CTConstants.java
rename to common/src/main/java/org/conscrypt/ct/Constants.java
index 76133d9e..71bcab2b 100644
--- a/common/src/main/java/org/conscrypt/ct/CTConstants.java
+++ b/common/src/main/java/org/conscrypt/ct/Constants.java
@@ -19,7 +19,7 @@ package org.conscrypt.ct;
 import org.conscrypt.Internal;
 
 @Internal
-public class CTConstants {
+public class Constants {
     public static final String X509_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";
     public static final String OCSP_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.5";
 
@@ -41,4 +41,3 @@ public class CTConstants {
 
     public static final int ISSUER_KEY_HASH_LENGTH = 32;
 }
-
diff --git a/common/src/main/java/org/conscrypt/ct/DigitallySigned.java b/common/src/main/java/org/conscrypt/ct/DigitallySigned.java
index b5f44786..15720d96 100644
--- a/common/src/main/java/org/conscrypt/ct/DigitallySigned.java
+++ b/common/src/main/java/org/conscrypt/ct/DigitallySigned.java
@@ -107,10 +107,9 @@ public class DigitallySigned {
         throws SerializationException {
         try {
             return new DigitallySigned(
-                Serialization.readNumber(input, CTConstants.HASH_ALGORITHM_LENGTH),
-                Serialization.readNumber(input, CTConstants.SIGNATURE_ALGORITHM_LENGTH),
-                Serialization.readVariableBytes(input, CTConstants.SIGNATURE_LENGTH_BYTES)
-            );
+                    Serialization.readNumber(input, Constants.HASH_ALGORITHM_LENGTH),
+                    Serialization.readNumber(input, Constants.SIGNATURE_ALGORITHM_LENGTH),
+                    Serialization.readVariableBytes(input, Constants.SIGNATURE_LENGTH_BYTES));
         } catch (IllegalArgumentException e) {
             throw new SerializationException(e);
         }
diff --git a/common/src/main/java/org/conscrypt/ct/LogInfo.java b/common/src/main/java/org/conscrypt/ct/LogInfo.java
new file mode 100644
index 00000000..99c8139d
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/ct/LogInfo.java
@@ -0,0 +1,228 @@
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
+package org.conscrypt.ct;
+
+import java.security.InvalidKeyException;
+import java.security.MessageDigest;
+import java.security.NoSuchAlgorithmException;
+import java.security.PublicKey;
+import java.security.Signature;
+import java.security.SignatureException;
+import java.util.Arrays;
+import java.util.Objects;
+import org.conscrypt.Internal;
+
+/**
+ * Properties about a Certificate Transparency Log.
+ * This object stores information about a CT log, its public key, description and URL.
+ * It allows verification of SCTs against the log's public key.
+ */
+@Internal
+public class LogInfo {
+    public static final int STATE_UNKNOWN = 0;
+    public static final int STATE_PENDING = 1;
+    public static final int STATE_QUALIFIED = 2;
+    public static final int STATE_USABLE = 3;
+    public static final int STATE_READONLY = 4;
+    public static final int STATE_RETIRED = 5;
+    public static final int STATE_REJECTED = 6;
+
+    private final byte[] logId;
+    private final PublicKey publicKey;
+    private final int state;
+    private final long stateTimestamp;
+    private final String description;
+    private final String url;
+    private final String operator;
+
+    private LogInfo(Builder builder) {
+        /* Based on the required fields for the log list schema v3. Notably,
+         * the state may be absent. The logId must match the public key, this
+         * is validated in the builder. */
+        Objects.requireNonNull(builder.logId);
+        Objects.requireNonNull(builder.publicKey);
+        Objects.requireNonNull(builder.url);
+        Objects.requireNonNull(builder.operator);
+
+        this.logId = builder.logId;
+        this.publicKey = builder.publicKey;
+        this.state = builder.state;
+        this.stateTimestamp = builder.stateTimestamp;
+        this.description = builder.description;
+        this.url = builder.url;
+        this.operator = builder.operator;
+    }
+
+    public static class Builder {
+        private byte[] logId;
+        private PublicKey publicKey;
+        private int state;
+        private long stateTimestamp;
+        private String description;
+        private String url;
+        private String operator;
+
+        public Builder setPublicKey(PublicKey publicKey) {
+            Objects.requireNonNull(publicKey);
+            this.publicKey = publicKey;
+            try {
+                this.logId = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
+            } catch (NoSuchAlgorithmException e) {
+                // SHA-256 is guaranteed to be available
+                throw new RuntimeException(e);
+            }
+            return this;
+        }
+
+        public Builder setState(int state, long timestamp) {
+            if (state < 0 || state > STATE_REJECTED) {
+                throw new IllegalArgumentException("invalid state value");
+            }
+            this.state = state;
+            this.stateTimestamp = timestamp;
+            return this;
+        }
+
+        public Builder setDescription(String description) {
+            Objects.requireNonNull(description);
+            this.description = description;
+            return this;
+        }
+
+        public Builder setUrl(String url) {
+            Objects.requireNonNull(url);
+            this.url = url;
+            return this;
+        }
+
+        public Builder setOperator(String operator) {
+            Objects.requireNonNull(operator);
+            this.operator = operator;
+            return this;
+        }
+
+        public LogInfo build() {
+            return new LogInfo(this);
+        }
+    }
+
+    /**
+     * Get the log's ID, that is the SHA-256 hash of it's public key
+     */
+    public byte[] getID() {
+        return logId;
+    }
+
+    public PublicKey getPublicKey() {
+        return publicKey;
+    }
+
+    public String getDescription() {
+        return description;
+    }
+
+    public String getUrl() {
+        return url;
+    }
+
+    public int getState() {
+        return state;
+    }
+
+    public int getStateAt(long when) {
+        if (when >= this.stateTimestamp) {
+            return state;
+        }
+        return STATE_UNKNOWN;
+    }
+
+    public long getStateTimestamp() {
+        return stateTimestamp;
+    }
+
+    public String getOperator() {
+        return operator;
+    }
+
+    @Override
+    public boolean equals(Object other) {
+        if (this == other) {
+            return true;
+        }
+        if (!(other instanceof LogInfo)) {
+            return false;
+        }
+
+        LogInfo that = (LogInfo) other;
+        return this.state == that.state && this.description.equals(that.description)
+                && this.url.equals(that.url) && this.operator.equals(that.operator)
+                && this.stateTimestamp == that.stateTimestamp
+                && Arrays.equals(this.logId, that.logId);
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(
+                Arrays.hashCode(logId), description, url, state, stateTimestamp, operator);
+    }
+
+    /**
+     * Verify the signature of a signed certificate timestamp for the given certificate entry
+     * against the log's public key.
+     *
+     * @return the result of the verification
+     */
+    public VerifiedSCT.Status verifySingleSCT(
+            SignedCertificateTimestamp sct, CertificateEntry entry) {
+        if (!Arrays.equals(sct.getLogID(), getID())) {
+            return VerifiedSCT.Status.UNKNOWN_LOG;
+        }
+
+        byte[] toVerify;
+        try {
+            toVerify = sct.encodeTBS(entry);
+        } catch (SerializationException e) {
+            return VerifiedSCT.Status.INVALID_SCT;
+        }
+
+        Signature signature;
+        try {
+            String algorithm = sct.getSignature().getAlgorithm();
+            signature = Signature.getInstance(algorithm);
+        } catch (NoSuchAlgorithmException e) {
+            return VerifiedSCT.Status.INVALID_SCT;
+        }
+
+        try {
+            signature.initVerify(publicKey);
+        } catch (InvalidKeyException e) {
+            return VerifiedSCT.Status.INVALID_SCT;
+        }
+
+        try {
+            signature.update(toVerify);
+            if (!signature.verify(sct.getSignature().getSignature())) {
+                return VerifiedSCT.Status.INVALID_SIGNATURE;
+            }
+            return VerifiedSCT.Status.VALID;
+        } catch (SignatureException e) {
+            // This only happens if the signature is not initialized,
+            // but we call initVerify just before, so it should never do
+            throw new RuntimeException(e);
+        }
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/ct/LogStore.java b/common/src/main/java/org/conscrypt/ct/LogStore.java
new file mode 100644
index 00000000..10e099c3
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/ct/LogStore.java
@@ -0,0 +1,39 @@
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
+package org.conscrypt.ct;
+
+import org.conscrypt.Internal;
+
+@Internal
+public interface LogStore {
+    public enum State {
+        UNINITIALIZED,
+        NOT_FOUND,
+        MALFORMED,
+        LOADED,
+        COMPLIANT,
+        NON_COMPLIANT,
+    }
+
+    void setPolicy(Policy policy);
+
+    State getState();
+
+    long getTimestamp();
+
+    LogInfo getKnownLog(byte[] logId);
+}
diff --git a/common/src/main/java/org/conscrypt/ct/CTPolicy.java b/common/src/main/java/org/conscrypt/ct/Policy.java
similarity index 81%
rename from common/src/main/java/org/conscrypt/ct/CTPolicy.java
rename to common/src/main/java/org/conscrypt/ct/Policy.java
index 455cabdc..5b3d95aa 100644
--- a/common/src/main/java/org/conscrypt/ct/CTPolicy.java
+++ b/common/src/main/java/org/conscrypt/ct/Policy.java
@@ -20,7 +20,7 @@ import java.security.cert.X509Certificate;
 import org.conscrypt.Internal;
 
 @Internal
-public interface CTPolicy {
-    boolean doesResultConformToPolicy(CTVerificationResult result, String hostname,
-            X509Certificate[] chain);
+public interface Policy {
+    boolean isLogStoreCompliant(LogStore store);
+    PolicyCompliance doesResultConformToPolicy(VerificationResult result, X509Certificate leaf);
 }
diff --git a/common/src/main/java/org/conscrypt/ct/CTLogStore.java b/common/src/main/java/org/conscrypt/ct/PolicyCompliance.java
similarity index 81%
rename from common/src/main/java/org/conscrypt/ct/CTLogStore.java
rename to common/src/main/java/org/conscrypt/ct/PolicyCompliance.java
index bf30d66d..d889ee75 100644
--- a/common/src/main/java/org/conscrypt/ct/CTLogStore.java
+++ b/common/src/main/java/org/conscrypt/ct/PolicyCompliance.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2015 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -19,7 +19,8 @@ package org.conscrypt.ct;
 import org.conscrypt.Internal;
 
 @Internal
-public interface CTLogStore {
-    CTLogInfo getKnownLog(byte[] logId);
+public enum PolicyCompliance {
+    COMPLY,
+    NOT_ENOUGH_SCTS,
+    NOT_ENOUGH_DIVERSE_SCTS
 }
-
diff --git a/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java b/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java
index d23f9ed1..8ad3788b 100644
--- a/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java
+++ b/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java
@@ -87,19 +87,16 @@ public class SignedCertificateTimestamp {
      */
     public static SignedCertificateTimestamp decode(InputStream input, Origin origin)
             throws SerializationException {
-        int version = Serialization.readNumber(input, CTConstants.VERSION_LENGTH);
+        int version = Serialization.readNumber(input, Constants.VERSION_LENGTH);
         if (version != Version.V1.ordinal()) {
             throw new SerializationException("Unsupported SCT version " + version);
         }
 
-        return new SignedCertificateTimestamp(
-            Version.V1,
-            Serialization.readFixedBytes(input, CTConstants.LOGID_LENGTH),
-            Serialization.readLong(input, CTConstants.TIMESTAMP_LENGTH),
-            Serialization.readVariableBytes(input, CTConstants.EXTENSIONS_LENGTH_BYTES),
-            DigitallySigned.decode(input),
-            origin
-        );
+        return new SignedCertificateTimestamp(Version.V1,
+                Serialization.readFixedBytes(input, Constants.LOGID_LENGTH),
+                Serialization.readLong(input, Constants.TIMESTAMP_LENGTH),
+                Serialization.readVariableBytes(input, Constants.EXTENSIONS_LENGTH_BYTES),
+                DigitallySigned.decode(input), origin);
     }
 
     /**
@@ -115,12 +112,12 @@ public class SignedCertificateTimestamp {
      */
     public void encodeTBS(OutputStream output, CertificateEntry certEntry)
             throws SerializationException {
-        Serialization.writeNumber(output, version.ordinal(), CTConstants.VERSION_LENGTH);
+        Serialization.writeNumber(output, version.ordinal(), Constants.VERSION_LENGTH);
         Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.ordinal(),
-                                          CTConstants.SIGNATURE_TYPE_LENGTH);
-        Serialization.writeNumber(output, timestamp, CTConstants.TIMESTAMP_LENGTH);
+                Constants.SIGNATURE_TYPE_LENGTH);
+        Serialization.writeNumber(output, timestamp, Constants.TIMESTAMP_LENGTH);
         certEntry.encode(output);
-        Serialization.writeVariableBytes(output, extensions, CTConstants.EXTENSIONS_LENGTH_BYTES);
+        Serialization.writeVariableBytes(output, extensions, Constants.EXTENSIONS_LENGTH_BYTES);
     }
 
     /**
diff --git a/common/src/main/java/org/conscrypt/ct/CTVerificationResult.java b/common/src/main/java/org/conscrypt/ct/VerificationResult.java
similarity index 74%
rename from common/src/main/java/org/conscrypt/ct/CTVerificationResult.java
rename to common/src/main/java/org/conscrypt/ct/VerificationResult.java
index b21e9acb..354b16a5 100644
--- a/common/src/main/java/org/conscrypt/ct/CTVerificationResult.java
+++ b/common/src/main/java/org/conscrypt/ct/VerificationResult.java
@@ -21,13 +21,21 @@ import java.util.Collections;
 import java.util.List;
 import org.conscrypt.Internal;
 
+/**
+ * Container for verified SignedCertificateTimestamp.
+ *
+ * getValidSCTs returns SCTs which were found to match a known log and for
+ * which the signature has been verified. There is no guarantee on the state of
+ * the log (e.g., getLogInfo.getState() may return STATE_UNKNOWN). Further
+ * verification on the compliance with the policy is performed in PolicyImpl.
+ */
 @Internal
-public class CTVerificationResult {
+public class VerificationResult {
     private final ArrayList<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>();
     private final ArrayList<VerifiedSCT> invalidSCTs = new ArrayList<VerifiedSCT>();
 
     public void add(VerifiedSCT result) {
-        if (result.status == VerifiedSCT.Status.VALID) {
+        if (result.isValid()) {
             validSCTs.add(result);
         } else {
             invalidSCTs.add(result);
@@ -42,4 +50,3 @@ public class CTVerificationResult {
         return Collections.unmodifiableList(invalidSCTs);
     }
 }
-
diff --git a/common/src/main/java/org/conscrypt/ct/VerifiedSCT.java b/common/src/main/java/org/conscrypt/ct/VerifiedSCT.java
index 7eaf45d1..6c9c0082 100644
--- a/common/src/main/java/org/conscrypt/ct/VerifiedSCT.java
+++ b/common/src/main/java/org/conscrypt/ct/VerifiedSCT.java
@@ -16,6 +16,7 @@
 
 package org.conscrypt.ct;
 
+import java.util.Objects;
 import org.conscrypt.Internal;
 
 /**
@@ -30,12 +31,61 @@ public final class VerifiedSCT {
         INVALID_SCT
     }
 
-    public final SignedCertificateTimestamp sct;
-    public final Status status;
+    private final SignedCertificateTimestamp sct;
+    private final Status status;
+    private final LogInfo logInfo;
 
-    public VerifiedSCT(SignedCertificateTimestamp sct, Status status) {
-        this.sct = sct;
-        this.status = status;
+    private VerifiedSCT(Builder builder) {
+        Objects.requireNonNull(builder.sct);
+        Objects.requireNonNull(builder.status);
+        if (builder.status == Status.VALID) {
+            Objects.requireNonNull(builder.logInfo);
+        }
+
+        this.sct = builder.sct;
+        this.status = builder.status;
+        this.logInfo = builder.logInfo;
+    }
+
+    public SignedCertificateTimestamp getSct() {
+        return sct;
+    }
+
+    public Status getStatus() {
+        return status;
+    }
+
+    public boolean isValid() {
+        return status == Status.VALID;
+    }
+
+    public LogInfo getLogInfo() {
+        return logInfo;
+    }
+
+    public static class Builder {
+        private SignedCertificateTimestamp sct;
+        private Status status;
+        private LogInfo logInfo;
+
+        public Builder(SignedCertificateTimestamp sct) {
+            this.sct = sct;
+        }
+
+        public Builder setStatus(Status status) {
+            this.status = status;
+            return this;
+        }
+
+        public Builder setLogInfo(LogInfo logInfo) {
+            Objects.requireNonNull(logInfo);
+            this.logInfo = logInfo;
+            return this;
+        }
+
+        public VerifiedSCT build() {
+            return new VerifiedSCT(this);
+        }
     }
 }
 
diff --git a/common/src/main/java/org/conscrypt/ct/CTVerifier.java b/common/src/main/java/org/conscrypt/ct/Verifier.java
similarity index 73%
rename from common/src/main/java/org/conscrypt/ct/CTVerifier.java
rename to common/src/main/java/org/conscrypt/ct/Verifier.java
index 2f1f79b4..79d90d90 100644
--- a/common/src/main/java/org/conscrypt/ct/CTVerifier.java
+++ b/common/src/main/java/org/conscrypt/ct/Verifier.java
@@ -27,18 +27,18 @@ import org.conscrypt.NativeCrypto;
 import org.conscrypt.OpenSSLX509Certificate;
 
 @Internal
-public class CTVerifier {
-    private final CTLogStore store;
+public class Verifier {
+    private final LogStore store;
 
-    public CTVerifier(CTLogStore store) {
+    public Verifier(LogStore store) {
         this.store = store;
     }
 
-    public CTVerificationResult verifySignedCertificateTimestamps(List<X509Certificate> chain,
+    public VerificationResult verifySignedCertificateTimestamps(List<X509Certificate> chain,
             byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
         OpenSSLX509Certificate[] certs = new OpenSSLX509Certificate[chain.size()];
         int i = 0;
-        for(X509Certificate cert : chain) {
+        for (X509Certificate cert : chain) {
             certs[i++] = OpenSSLX509Certificate.fromCertificate(cert);
         }
         return verifySignedCertificateTimestamps(certs, tlsData, ocspData);
@@ -50,7 +50,7 @@ public class CTVerifier {
      * response, and verified against the list of known logs.
      * @throws IllegalArgumentException if the chain is empty
      */
-    public CTVerificationResult verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain,
+    public VerificationResult verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain,
             byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
         if (chain.length == 0) {
             throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
@@ -58,7 +58,7 @@ public class CTVerifier {
 
         OpenSSLX509Certificate leaf = chain[0];
 
-        CTVerificationResult result = new CTVerificationResult();
+        VerificationResult result = new VerificationResult();
         List<SignedCertificateTimestamp> tlsScts = getSCTsFromTLSExtension(tlsData);
         verifyExternalSCTs(tlsScts, leaf, result);
 
@@ -75,8 +75,7 @@ public class CTVerifier {
      * The result of the verification for each sct is added to {@code result}.
      */
     private void verifyEmbeddedSCTs(List<SignedCertificateTimestamp> scts,
-                                    OpenSSLX509Certificate[] chain,
-                                    CTVerificationResult result) {
+            OpenSSLX509Certificate[] chain, VerificationResult result) {
         // Avoid creating the cert entry if we don't need it
         if (scts.isEmpty()) {
             return;
@@ -99,10 +98,7 @@ public class CTVerifier {
             return;
         }
 
-        for (SignedCertificateTimestamp sct: scts) {
-            VerifiedSCT.Status status = verifySingleSCT(sct, precertEntry);
-            result.add(new VerifiedSCT(sct, status));
-        }
+        verifySCTs(scts, precertEntry, result);
     }
 
     /**
@@ -111,8 +107,7 @@ public class CTVerifier {
      * The result of the verification for each sct is added to {@code result}.
      */
     private void verifyExternalSCTs(List<SignedCertificateTimestamp> scts,
-                                    OpenSSLX509Certificate leaf,
-                                    CTVerificationResult result) {
+            OpenSSLX509Certificate leaf, VerificationResult result) {
         // Avoid creating the cert entry if we don't need it
         if (scts.isEmpty()) {
             return;
@@ -126,32 +121,38 @@ public class CTVerifier {
             return;
         }
 
-        for (SignedCertificateTimestamp sct: scts) {
-            VerifiedSCT.Status status = verifySingleSCT(sct, x509Entry);
-            result.add(new VerifiedSCT(sct, status));
-        }
+        verifySCTs(scts, x509Entry, result);
     }
 
     /**
-     * Verify a single SCT for the given Certificate Entry
+     * Verify a list of SCTs.
      */
-    private VerifiedSCT.Status verifySingleSCT(SignedCertificateTimestamp sct,
-                                                         CertificateEntry certEntry) {
-        CTLogInfo log = store.getKnownLog(sct.getLogID());
-        if (log == null) {
-            return VerifiedSCT.Status.UNKNOWN_LOG;
+    private void verifySCTs(List<SignedCertificateTimestamp> scts, CertificateEntry certEntry,
+            VerificationResult result) {
+        for (SignedCertificateTimestamp sct : scts) {
+            VerifiedSCT.Builder builder = new VerifiedSCT.Builder(sct);
+            LogInfo log = store.getKnownLog(sct.getLogID());
+            if (log == null) {
+                builder.setStatus(VerifiedSCT.Status.UNKNOWN_LOG);
+            } else {
+                VerifiedSCT.Status status = log.verifySingleSCT(sct, certEntry);
+                builder.setStatus(status);
+                if (status == VerifiedSCT.Status.VALID) {
+                    builder.setLogInfo(log);
+                }
+            }
+            result.add(builder.build());
         }
-
-        return log.verifySingleSCT(sct, certEntry);
     }
 
     /**
      * Add every SCT in {@code scts} to {@code result} with INVALID_SCT as status
      */
-    private void markSCTsAsInvalid(List<SignedCertificateTimestamp> scts,
-                                   CTVerificationResult result) {
-        for (SignedCertificateTimestamp sct: scts) {
-            result.add(new VerifiedSCT(sct, VerifiedSCT.Status.INVALID_SCT));
+    private void markSCTsAsInvalid(
+            List<SignedCertificateTimestamp> scts, VerificationResult result) {
+        for (SignedCertificateTimestamp sct : scts) {
+            VerifiedSCT.Builder builder = new VerifiedSCT.Builder(sct);
+            result.add(builder.setStatus(VerifiedSCT.Status.INVALID_SCT).build());
         }
     }
 
@@ -163,24 +164,25 @@ public class CTVerifier {
      * @param origin used to create the SignedCertificateTimestamp instances.
      */
     @SuppressWarnings("MixedMutabilityReturnType")
-    private static List<SignedCertificateTimestamp> getSCTsFromSCTList(byte[] data,
-            SignedCertificateTimestamp.Origin origin) {
+    private static List<SignedCertificateTimestamp> getSCTsFromSCTList(
+            byte[] data, SignedCertificateTimestamp.Origin origin) {
         if (data == null) {
             return Collections.emptyList();
         }
 
         byte[][] sctList;
         try {
-            sctList = Serialization.readList(data, CTConstants.SCT_LIST_LENGTH_BYTES,
-                                             CTConstants.SERIALIZED_SCT_LENGTH_BYTES);
+            sctList = Serialization.readList(
+                    data, Constants.SCT_LIST_LENGTH_BYTES, Constants.SERIALIZED_SCT_LENGTH_BYTES);
         } catch (SerializationException e) {
             return Collections.emptyList();
         }
 
         List<SignedCertificateTimestamp> scts = new ArrayList<SignedCertificateTimestamp>();
-        for (byte[] encodedSCT: sctList) {
-            try  {
-                SignedCertificateTimestamp sct = SignedCertificateTimestamp.decode(encodedSCT, origin);
+        for (byte[] encodedSCT : sctList) {
+            try {
+                SignedCertificateTimestamp sct =
+                        SignedCertificateTimestamp.decode(encodedSCT, origin);
                 scts.add(sct);
             } catch (SerializationException e) {
                 // Ignore errors
@@ -210,23 +212,21 @@ public class CTVerifier {
      *              issuer in order to identify the relevant SingleResponse from the OCSP response,
      *              or an empty list is returned
      */
-    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(byte[] data,
-            OpenSSLX509Certificate[] chain) {
+    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(
+            byte[] data, OpenSSLX509Certificate[] chain) {
         if (data == null || chain.length < 2) {
             return Collections.emptyList();
         }
 
-        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, CTConstants.OCSP_SCT_LIST_OID,
-                chain[0].getContext(), chain[0],
-                chain[1].getContext(), chain[1]);
+        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, Constants.OCSP_SCT_LIST_OID,
+                chain[0].getContext(), chain[0], chain[1].getContext(), chain[1]);
         if (extData == null) {
             return Collections.emptyList();
         }
 
         try {
             return getSCTsFromSCTList(
-                    Serialization.readDEROctetString(
-                      Serialization.readDEROctetString(extData)),
+                    Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
                     SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
         } catch (SerializationException e) {
             return Collections.emptyList();
@@ -240,19 +240,17 @@ public class CTVerifier {
      * to be parsed, an empty list is returned. Individual SCTs which fail to be parsed are ignored.
      */
     private List<SignedCertificateTimestamp> getSCTsFromX509Extension(OpenSSLX509Certificate leaf) {
-        byte[] extData = leaf.getExtensionValue(CTConstants.X509_SCT_LIST_OID);
+        byte[] extData = leaf.getExtensionValue(Constants.X509_SCT_LIST_OID);
         if (extData == null) {
             return Collections.emptyList();
         }
 
         try {
             return getSCTsFromSCTList(
-                    Serialization.readDEROctetString(
-                      Serialization.readDEROctetString(extData)),
+                    Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
                     SignedCertificateTimestamp.Origin.EMBEDDED);
         } catch (SerializationException e) {
             return Collections.emptyList();
         }
     }
 }
-
diff --git a/common/src/test/java/org/conscrypt/HkdfTest.java b/common/src/test/java/org/conscrypt/HkdfTest.java
new file mode 100644
index 00000000..3acbdce2
--- /dev/null
+++ b/common/src/test/java/org/conscrypt/HkdfTest.java
@@ -0,0 +1,96 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * limitations under the License
+ */
+
+package org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.NoSuchAlgorithmException;
+import java.util.List;
+
+import javax.crypto.Mac;
+
+@RunWith(JUnit4.class)
+public class HkdfTest {
+    private final String SHA256 = "HmacSHA256";
+
+    @Test
+    public void constructor() throws Exception {
+        assertThrows(NullPointerException.class, () ->  new Hkdf(null));
+        assertThrows(NoSuchAlgorithmException.class, () -> new Hkdf("No such MAC"));
+
+        Hkdf hkdf = new Hkdf(SHA256);
+        assertEquals(Mac.getInstance(SHA256).getMacLength(), hkdf.getMacLength());
+    }
+
+    @Test
+    public void extract() throws Exception {
+        Hkdf hkdf = new Hkdf(SHA256);
+        assertThrows(NullPointerException.class, () -> hkdf.extract(null, new byte[0]));
+        assertThrows(NullPointerException.class, () -> hkdf.extract(new byte[0], null));
+        assertThrows(NullPointerException.class, () -> hkdf.extract(null, null));
+        assertThrows(IllegalArgumentException.class, () -> hkdf.extract(new byte[0], new byte[0]));
+    }
+
+    @Test
+    public void expand() throws Exception {
+        Hkdf hkdf = new Hkdf(SHA256);
+        int macLen = hkdf.getMacLength();
+        assertThrows(NullPointerException.class, () -> hkdf.expand(null, new byte[0], 1));
+        assertThrows(NullPointerException.class, () -> hkdf.expand(new byte[macLen], null, 1));
+        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
+        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
+        // Negative length
+        assertThrows(IllegalArgumentException.class,
+            () -> hkdf.expand(new byte[macLen], new byte[0], -1));
+        // PRK too small
+        assertThrows(IllegalArgumentException.class,
+            () -> hkdf.expand(new byte[0], new byte[0], 1));
+        // Length too large
+        assertThrows(IllegalArgumentException.class,
+            () -> hkdf.expand(new byte[macLen], new byte[0], 255 * macLen + 1));
+    }
+
+    @Test
+    public void testVectors() throws Exception {
+        List<TestVector> vectors = TestUtils.readTestVectors("crypto/hkdf.txt");
+
+        for (TestVector vector : vectors) {
+            String errMsg =  vector.getString("name");
+            String macName = vector.getString("hash");
+            byte[] ikm = vector.getBytes("ikm");
+            byte[] salt = vector.getBytesOrEmpty("salt");
+            byte[] prk_expected = vector.getBytes("prk");
+
+            Hkdf hkdf = new Hkdf(macName);
+            byte[] prk = hkdf.extract(salt, ikm);
+            assertArrayEquals(errMsg, prk_expected, prk);
+
+            byte[] info = vector.getBytes("info");
+            int length = vector.getInt("l");
+            byte[] okm_expected = vector.getBytes("okm");
+
+            byte[] okm = hkdf.expand(prk, info, length);
+            assertArrayEquals(errMsg, okm_expected, okm);
+        }
+    }
+}
diff --git a/common/src/test/java/org/conscrypt/ct/SerializationTest.java b/common/src/test/java/org/conscrypt/ct/SerializationTest.java
index a4c71cea..2d4a1123 100644
--- a/common/src/test/java/org/conscrypt/ct/SerializationTest.java
+++ b/common/src/test/java/org/conscrypt/ct/SerializationTest.java
@@ -20,16 +20,20 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
-import java.io.ByteArrayOutputStream;
-import java.util.Arrays;
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.io.ByteArrayOutputStream;
+import java.util.Arrays;
+
 @RunWith(JUnit4.class)
 public class SerializationTest {
-
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_SignedCertificateTimestamp() throws Exception {
         byte[] in = new byte[] {
             0x00,                            // version
@@ -59,6 +63,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_invalid_SignedCertificateTimestamp() throws Exception {
         byte[] sct = new byte[] {
             0x00,                            // version
@@ -92,6 +97,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_DigitallySigned() throws Exception {
         byte[] in = new byte[] {
             0x04, 0x03,            // hash & signature algorithm
@@ -106,6 +112,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_invalid_DigitallySigned() throws Exception {
         try {
             DigitallySigned.decode(new byte[] {
@@ -143,6 +150,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_encode_CertificateEntry_X509Certificate() throws Exception {
         // Use a dummy certificate. It doesn't matter, CertificateEntry doesn't care about the contents.
         CertificateEntry entry = CertificateEntry.createForX509Certificate(new byte[] { 0x12, 0x34, 0x56, 0x78 });
@@ -157,6 +165,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_encode_CertificateEntry_PreCertificate() throws Exception {
         // Use a dummy certificate and issuer key hash. It doesn't matter,
         // CertificateEntry doesn't care about the contents.
@@ -176,6 +185,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_readDEROctetString() throws Exception {
         byte[] in, expected;
 
@@ -222,4 +232,3 @@ public class SerializationTest {
         assertEquals(Arrays.toString(expected), Arrays.toString(actual));
     }
 }
-
diff --git a/common/src/test/java/org/conscrypt/ct/CTVerifierTest.java b/common/src/test/java/org/conscrypt/ct/VerifierTest.java
similarity index 60%
rename from common/src/test/java/org/conscrypt/ct/CTVerifierTest.java
rename to common/src/test/java/org/conscrypt/ct/VerifierTest.java
index 9aaf8dbe..e99832da 100644
--- a/common/src/test/java/org/conscrypt/ct/CTVerifierTest.java
+++ b/common/src/test/java/org/conscrypt/ct/VerifierTest.java
@@ -20,8 +20,9 @@ import static org.conscrypt.TestUtils.openTestFile;
 import static org.conscrypt.TestUtils.readTestFile;
 import static org.junit.Assert.assertEquals;
 
-import java.security.PublicKey;
-import java.util.Arrays;
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
 import org.conscrypt.OpenSSLX509Certificate;
 import org.conscrypt.TestUtils;
 import org.junit.Before;
@@ -29,26 +30,48 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.security.PublicKey;
+import java.util.Arrays;
+
 @RunWith(JUnit4.class)
-public class CTVerifierTest {
+public class VerifierTest {
     private OpenSSLX509Certificate ca;
     private OpenSSLX509Certificate cert;
     private OpenSSLX509Certificate certEmbedded;
-    private CTVerifier ctVerifier;
+    private Verifier ctVerifier;
 
     @Before
     public void setUp() throws Exception {
         ca = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
         cert = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
-        certEmbedded = OpenSSLX509Certificate.fromX509PemInputStream(
-                openTestFile("cert-ct-embedded.pem"));
+        certEmbedded =
+                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem"));
 
         PublicKey key = TestUtils.readPublicKeyPemFile("ct-server-key-public.pem");
 
-        final CTLogInfo log = new CTLogInfo(key, "Test Log", "foo");
-        CTLogStore store = new CTLogStore() {
+        final LogInfo log = new LogInfo.Builder()
+                                    .setPublicKey(key)
+                                    .setDescription("Test Log")
+                                    .setUrl("http://example.com")
+                                    .setOperator("LogOperator")
+                                    .setState(LogInfo.STATE_USABLE, 1643709600000L)
+                                    .build();
+        LogStore store = new LogStore() {
+            @Override
+            public void setPolicy(Policy policy) {}
+
             @Override
-            public CTLogInfo getKnownLog(byte[] logId) {
+            public State getState() {
+                return LogStore.State.COMPLIANT;
+            }
+
+            @Override
+            public long getTimestamp() {
+                return 0;
+            }
+
+            @Override
+            public LogInfo getKnownLog(byte[] logId) {
                 if (Arrays.equals(logId, log.getID())) {
                     return log;
                 } else {
@@ -57,120 +80,125 @@ public class CTVerifierTest {
             }
         };
 
-        ctVerifier = new CTVerifier(store);
+        ctVerifier = new Verifier(store);
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withOCSPResponse() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] ocspResponse = readTestFile("ocsp-response.der");
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withTLSExtension() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list");
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withEmbeddedExtension() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { certEmbedded, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {certEmbedded, ca};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
+        VerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withoutTimestamp() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
+        VerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withInvalidSignature() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(1, result.getInvalidSCTs().size());
-        assertEquals(VerifiedSCT.Status.INVALID_SIGNATURE,
-                     result.getInvalidSCTs().get(0).status);
+        assertEquals(
+                VerifiedSCT.Status.INVALID_SIGNATURE, result.getInvalidSCTs().get(0).getStatus());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withUnknownLog() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-unknown");
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(1, result.getInvalidSCTs().size());
-        assertEquals(VerifiedSCT.Status.UNKNOWN_LOG,
-                     result.getInvalidSCTs().get(0).status);
+        assertEquals(VerifiedSCT.Status.UNKNOWN_LOG, result.getInvalidSCTs().get(0).getStatus());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withInvalidEncoding() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         // Just some garbage data which will fail to deserialize
-        byte[] tlsExtension = new byte[] { 1, 2, 3, 4 };
+        byte[] tlsExtension = new byte[] {1, 2, 3, 4};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withInvalidOCSPResponse() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         // Just some garbage data which will fail to deserialize
-        byte[] ocspResponse = new byte[] { 1, 2, 3, 4 };
+        byte[] ocspResponse = new byte[] {1, 2, 3, 4};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withMultipleTimestamps() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");
         byte[] ocspResponse = readTestFile("ocsp-response.der");
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, ocspResponse);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, ocspResponse);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(1, result.getInvalidSCTs().size());
         assertEquals(SignedCertificateTimestamp.Origin.OCSP_RESPONSE,
-                     result.getValidSCTs().get(0).sct.getOrigin());
+                result.getValidSCTs().get(0).getSct().getOrigin());
         assertEquals(SignedCertificateTimestamp.Origin.TLS_EXTENSION,
-                     result.getInvalidSCTs().get(0).sct.getOrigin());
+                result.getInvalidSCTs().get(0).getSct().getOrigin());
     }
 }
-
diff --git a/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java b/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java
index 581e866d..1af048c4 100644
--- a/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java
@@ -18,6 +18,7 @@ package org.conscrypt.java.security.cert;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
@@ -361,6 +362,26 @@ public class X509CertificateTest {
             + "mmi08cueFV7mHzJSYV51yRQ=\n"
             + "-----END CERTIFICATE-----\n";
 
+    private static final String UTCTIME_WITH_OFFSET = "-----BEGIN CERTIFICATE-----\n" +
+            "MIIDPzCCAicCAgERMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAlVTMRMwEQYD\n" +
+            "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MR8wHQYDVQQK\n" +
+            "DBZHb29nbGUgQXV0b21vdGl2ZSBMaW5rMCYXETE0MDcwNDAwMDAwMC0wNzAwFxE0\n" +
+            "ODA4MDExMDIxMjMtMDcwMDBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv\n" +
+            "cm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEeMBwGA1UECgwVQW5kcm9pZC1B\n" +
+            "dXRvLUludGVybmFsMQswCQYDVQQLDAIwMTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
+            "ADCCAQoCggEBAOWghAac2eJLbi/ijgZGRB6/MuaBVfOImkQddBJUhXbnskTJB/JI\n" +
+            "12Ea22E5GeVN8CkWULAZT28yDWqsKMyq9BzpjpsHc9TKxMYqrIn0HP7mIJcBu5z7\n" +
+            "K8DoXqc86encncJlkGeuQkUA68yyp7RG7eQ6XoBHEjNmyvX13Y8NY5sPUHfLfmp6\n" +
+            "A2n+Jdmecq3L0GS84ctdNtnp2zSopTy0L1Gp6+lrnuOPAYZeV+Ei2jAvhycvuSoB\n" +
+            "yV6rT9wvREvC2TDncurMwR6ws44+ZStqkhnvDLhV04ray5aPplQwwB9GELFCYSRk\n" +
+            "56sm57uYSJj/LlmOMcvyBmUHVJ7MLxgtlykCAwEAATANBgkqhkiG9w0BAQsFAAOC\n" +
+            "AQEA1Bs8v6HuAIiBdhGDGHzZJDwO6lW0LheBqsGLG9KsVvIVrTMPP9lpdTPjStGn\n" +
+            "en1RIce4R4l3YTBwxOadLMkf8rymAE5JNjPsWlBue7eI4TFFw/cvnKxcTQ61bC4i\n" +
+            "2uosyDI5VfrXm38zYcZoK4TFtMhNyx6aYSEClWB9MjHa+n6eR3dLBCg1kMGqGdZ/\n" +
+            "AoK0UEkyI3UFU8sW86iaS4dvPSaQ+z0tmfUzbrc5ZSk4hYCeUYvuyd2ShxjKmxvD\n" +
+            "0K8A7gKLY0jP8Zp+6rYBcpxc7cylWMbdlhFTHAGiKI+XeQ/9u+RPeocZsn5jGlDt\n" +
+            "K3ftMoWFce+baNq/WcMzRj04AA==\n" +
+            "-----END CERTIFICATE-----\n";
     private static Date dateFromUTC(int year, int month, int day, int hour, int minute, int second)
             throws Exception {
         Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
@@ -726,4 +747,24 @@ public class X509CertificateTest {
             }
         });
     }
+
+    // Ensure we don't reject certificates with UTCTIME fields with offsets for now: b/311260068
+    @Test
+    public void utcTimeWithOffset() throws Exception {
+        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
+        tester.skipProvider("SUN") // Sun and BC interpret the offset, Conscrypt just drops it...
+                .skipProvider("BC")
+                .run(new ServiceTester.Test() {
+            @Override
+            public void test(Provider p, String algorithm) throws Exception {
+                X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
+                assertDatesEqual(
+                        dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0),
+                        c.getNotBefore());
+                assertDatesEqual(
+                        dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23),
+                        c.getNotAfter());
+            }
+        });
+    }
 }
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLContextTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLContextTest.java
index f24d8648..3ed4dd3d 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLContextTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLContextTest.java
@@ -16,6 +16,7 @@
 
 package org.conscrypt.javax.net.ssl;
 
+import static org.conscrypt.TestUtils.isTlsV1Supported;
 import static org.conscrypt.TestUtils.isWindows;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
@@ -122,9 +123,11 @@ public class SSLContextTest {
     public void test_SSLContext_allProtocols() throws Exception {
         SSLConfigurationAsserts.assertSSLContextDefaultConfiguration(SSLContext.getDefault());
 
-        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS_ALL) {
+        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
             SSLContext sslContext = SSLContext.getInstance(protocol);
-            sslContext.init(null, null, null);
+            if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
+                sslContext.init(null, null, null);
+            }
         }
     }
 
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSessionTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSessionTest.java
index 9f99c1f8..e6bb7c84 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSessionTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSessionTest.java
@@ -16,6 +16,7 @@
 
 package org.conscrypt.javax.net.ssl;
 
+import static org.conscrypt.TestUtils.isWindows;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
@@ -24,6 +25,7 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
 
 import java.lang.reflect.Field;
 import java.lang.reflect.Method;
@@ -81,6 +83,9 @@ public class SSLSessionTest {
 
     @Test
     public void test_SSLSession_getCreationTime() {
+        // TODO(prb) seems to fail regularly on Windows with sTime <= t1
+        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());
+
         // We use OpenSSL, which only returns times accurate to the nearest second.
         // NativeCrypto just multiplies by 1000, which looks like truncation, which
         // would make it appear as if the OpenSSL side of things was created before
diff --git a/common/src/test/resources/crypto/hkdf.txt b/common/src/test/resources/crypto/hkdf.txt
new file mode 100644
index 00000000..98acbb6b
--- /dev/null
+++ b/common/src/test/resources/crypto/hkdf.txt
@@ -0,0 +1,63 @@
+# Test vectors from RFC 5869
+
+Name = Basic test case with SHA-256
+Hash = HmacSHA256
+IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
+salt = 000102030405060708090a0b0c
+info = f0f1f2f3f4f5f6f7f8f9
+L    = 42
+PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
+OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
+
+Name = Test with SHA-256 and longer inputs/outputs
+Hash = HmacSHA256
+IKM  = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
+salt = 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
+info = b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+L    = 82
+PRK  = 06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244
+OKM  = b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87
+
+Name = Test with SHA-256 and zero-length salt/info
+Hash = HmacSHA256
+IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
+salt =
+info =
+L    = 42
+PRK  = 19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04
+OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
+
+Name = Basic test case with SHA-1
+Hash = HmacSHA1
+IKM  = 0b0b0b0b0b0b0b0b0b0b0b
+salt = 000102030405060708090a0b0c
+info = f0f1f2f3f4f5f6f7f8f9
+L    = 42
+PRK  = 9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243
+OKM  = 085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896
+
+Name = Test with SHA-1 and longer inputs/outputs
+Hash = HmacSHA1
+IKM  = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
+salt = 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
+info = b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+L    = 82
+PRK  = 8adae09a2a307059478d309b26c4115a224cfaf6
+OKM  = 0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4
+
+Name = Test with SHA-1 and zero-length salt/info
+Hash = HmacSHA1
+IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
+salt =
+info =
+L    = 42
+PRK  = da8c8a73c7fa77288ec6f5e7c297786aa0d32d01
+OKM  = 0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918
+
+Name = Test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length info
+Hash = HmacSHA1
+IKM  = 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
+info =
+L    = 42
+PRK  = 2adccada18779e7c2077ad2eb19d3f3e731385dd
+OKM  = 2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48
diff --git a/conscrypt.aconfig b/conscrypt.aconfig
new file mode 100644
index 00000000..781a626a
--- /dev/null
+++ b/conscrypt.aconfig
@@ -0,0 +1,26 @@
+# Copyright (C) 2024 The Android Open Source Project
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
+package: "com.android.org.conscrypt"
+container: "com.android.conscrypt"
+
+flag {
+    namespace: "core_libraries"
+    name: "certificate_transparency_platform"
+    description: "This flag controls whether conscrypt will interpret the NetworkSecurityConfig for Certificate Transparency"
+    bug: "319829948"
+    # APIs provided by a mainline module can only use a frozen flag.
+    is_fixed_read_only: true
+}
+
diff --git a/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java b/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java
new file mode 100644
index 00000000..e7ca0f19
--- /dev/null
+++ b/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java
@@ -0,0 +1,97 @@
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
+package libcore.net;
+
+/**
+ * Network security policy for this process/application.
+ *
+ * <p>Network stacks/components are expected to honor this policy. Components which can use the
+ * Android framework API should be accessing this policy via the framework's
+ * {@code android.security.NetworkSecurityPolicy} instead of via this class.
+ *
+ * <p>The policy currently consists of a single flag: whether cleartext network traffic is
+ * permitted. See {@link #isCleartextTrafficPermitted()}.
+ */
+public abstract class NetworkSecurityPolicy {
+    private static volatile NetworkSecurityPolicy instance = new DefaultNetworkSecurityPolicy();
+
+    public static NetworkSecurityPolicy getInstance() {
+        return instance;
+    }
+
+    public static void setInstance(NetworkSecurityPolicy policy) {
+        if (policy == null) {
+            throw new NullPointerException("policy == null");
+        }
+        instance = policy;
+    }
+
+    /**
+     * Returns {@code true} if cleartext network traffic (e.g. HTTP, FTP, XMPP, IMAP, SMTP --
+     * without TLS or STARTTLS) is permitted for all network communications of this process.
+     *
+     * <p>{@link #isCleartextTrafficPermitted(String)} should be used to determine if cleartext
+     * traffic is permitted for a specific host.
+     *
+     * <p>When cleartext network traffic is not permitted, the platform's components (e.g. HTTP
+     * stacks, {@code WebView}, {@code MediaPlayer}) will refuse this process's requests to use
+     * cleartext traffic. Third-party libraries are encouraged to do the same.
+     *
+     * <p>This flag is honored on a best effort basis because it's impossible to prevent all
+     * cleartext traffic from an application given the level of access provided to applications on
+     * Android. For example, there's no expectation that {@link java.net.Socket} API will honor this
+     * flag. Luckily, most network traffic from apps is handled by higher-level network stacks which
+     * can be made to honor this flag. Platform-provided network stacks (e.g. HTTP and FTP) honor
+     * this flag from day one, and well-established third-party network stacks will eventually
+     * honor it.
+     */
+    public abstract boolean isCleartextTrafficPermitted();
+
+    /**
+     * Returns {@code true} if cleartext network traffic (e.g. HTTP, FTP, XMPP, IMAP, SMTP --
+     * without TLS or STARTTLS) is permitted for communicating with {@code hostname} for this
+     * process.
+     *
+     * <p>See {@link #isCleartextTrafficPermitted} for more details.
+     */
+    public abstract boolean isCleartextTrafficPermitted(String hostname);
+
+    /**
+     * Returns {@code true} if Certificate Transparency information is required to be presented by
+     * the server and verified by the client in TLS connections to {@code hostname}.
+     *
+     * <p>See RFC6962 section 3.3 for more details.
+     */
+    public abstract boolean isCertificateTransparencyVerificationRequired(String hostname);
+
+    public static final class DefaultNetworkSecurityPolicy extends NetworkSecurityPolicy {
+        @Override
+        public boolean isCleartextTrafficPermitted() {
+            return true;
+        }
+
+        @Override
+        public boolean isCleartextTrafficPermitted(String hostname) {
+            return isCleartextTrafficPermitted();
+        }
+
+        @Override
+        public boolean isCertificateTransparencyVerificationRequired(String hostname) {
+            return false;
+        }
+    }
+}
diff --git a/openjdk/build.gradle b/openjdk/build.gradle
index af31b634..1dc0884a 100644
--- a/openjdk/build.gradle
+++ b/openjdk/build.gradle
@@ -129,7 +129,6 @@ ext {
 }
 
 sourceSets {
-
     main {
         java {
             srcDirs += "${rootDir}/common/src/main/java"
@@ -346,9 +345,17 @@ jacocoTestReport {
 
 javadoc {
     dependsOn(configurations.publicApiDocs)
-    // TODO(prb): Update doclet to Java 11.
-    // options.doclet = "org.conscrypt.doclet.FilterDoclet"
-    // options.docletpath = configurations.publicApiDocs.files as List
+    options.showFromPublic()
+    options.doclet = "org.conscrypt.doclet.FilterDoclet"
+    options.docletpath = configurations.publicApiDocs.files as List
+    failOnError false
+
+    doLast {
+        copy {
+            from "$rootDir/api-doclet/src/main/resources/styles.css"
+            into "$buildDir/docs/javadoc"
+        }
+    }
 }
 
 def jniIncludeDir() {
diff --git a/openjdk/src/main/java/org/conscrypt/Platform.java b/openjdk/src/main/java/org/conscrypt/Platform.java
index 306574cd..e50a8ce8 100644
--- a/openjdk/src/main/java/org/conscrypt/Platform.java
+++ b/openjdk/src/main/java/org/conscrypt/Platform.java
@@ -55,7 +55,6 @@ import java.security.AlgorithmParameters;
 import java.security.KeyStore;
 import java.security.KeyStoreException;
 import java.security.NoSuchAlgorithmException;
-import java.security.PrivateKey;
 import java.security.PrivilegedAction;
 import java.security.Provider;
 import java.security.Security;
@@ -79,9 +78,8 @@ import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.ct.CTLogStore;
-import org.conscrypt.ct.CTPolicy;
-import sun.security.x509.AlgorithmId;
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.Policy;
 
 /**
  * Platform-specific methods for OpenJDK.
@@ -540,13 +538,26 @@ final class Platform {
     @SuppressWarnings("unused")
     static String oidToAlgorithmName(String oid) {
         try {
-            return AlgorithmId.get(oid).getName();
-        } catch (Exception e) {
-            return oid;
-        } catch (IllegalAccessError e) {
-            // This can happen under JPMS because AlgorithmId isn't exported by java.base
-            return oid;
+            Class<?> algorithmIdClass = Class.forName("sun.security.x509.AlgorithmId");
+            Method getMethod = algorithmIdClass.getDeclaredMethod("get", String.class);
+            getMethod.setAccessible(true);
+            Method getNameMethod = algorithmIdClass.getDeclaredMethod("getName");
+            getNameMethod.setAccessible(true);
+
+            Object algIdObj = getMethod.invoke(null, oid);
+            return (String) getNameMethod.invoke(algIdObj);
+        } catch (InvocationTargetException e) {
+            Throwable cause = e.getCause();
+            if (cause instanceof RuntimeException) {
+                throw(RuntimeException) cause;
+            } else if (cause instanceof Error) {
+                throw(Error) cause;
+            }
+            throw new RuntimeException(e);
+        } catch (Exception ignored) {
+            //Ignored
         }
+        return oid;
     }
 
     /*
@@ -707,11 +718,11 @@ final class Platform {
         return null;
     }
 
-    static CTLogStore newDefaultLogStore() {
+    static LogStore newDefaultLogStore() {
         return null;
     }
 
-    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
+    static Policy newDefaultPolicy() {
         return null;
     }
 
diff --git a/openjdk/src/test/java/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java b/openjdk/src/test/java/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java
index 1c0c2bc3..0fc32fea 100644
--- a/openjdk/src/test/java/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java
+++ b/openjdk/src/test/java/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java
@@ -24,10 +24,13 @@ import java.nio.charset.Charset;
 import javax.net.ssl.SSLEngine;
 import org.junit.Before;
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
+@RunWith(JUnit4.class)
 public class ApplicationProtocolSelectorAdapterTest {
     private static Charset US_ASCII = Charset.forName("US-ASCII");
     private static final String[] PROTOCOLS = new String[] {"a", "b", "c"};
diff --git a/openjdk/src/test/java/org/conscrypt/ConscryptOpenJdkSuite.java b/openjdk/src/test/java/org/conscrypt/ConscryptOpenJdkSuite.java
index d5401e36..f5ae14bc 100644
--- a/openjdk/src/test/java/org/conscrypt/ConscryptOpenJdkSuite.java
+++ b/openjdk/src/test/java/org/conscrypt/ConscryptOpenJdkSuite.java
@@ -18,8 +18,8 @@ package org.conscrypt;
 
 import static org.conscrypt.TestUtils.installConscryptAsDefaultProvider;
 
-import org.conscrypt.ct.CTVerifierTest;
 import org.conscrypt.ct.SerializationTest;
+import org.conscrypt.ct.VerifierTest;
 import org.conscrypt.java.security.AlgorithmParameterGeneratorTestDH;
 import org.conscrypt.java.security.AlgorithmParameterGeneratorTestDSA;
 import org.conscrypt.java.security.AlgorithmParametersPSSTest;
@@ -111,7 +111,7 @@ import org.junit.runners.Suite;
         TestSessionBuilderTest.class,
         TrustManagerImplTest.class,
         // org.conscrypt.ct tests
-        CTVerifierTest.class,
+        VerifierTest.class,
         SerializationTest.class,
         // java.security tests
         CertificateFactoryTest.class,
diff --git a/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java b/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
index adb91843..4ffc56f6 100644
--- a/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
+++ b/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
@@ -25,6 +25,9 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThat;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
+import static org.junit.Assume.assumeTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.when;
 
@@ -639,6 +642,7 @@ public class ConscryptSocketTest {
 
     @Test
     public void test_setEnabledProtocols_FiltersSSLv3_HandshakeException() throws Exception {
+        assumeTrue(TestUtils.isTlsV1Filtered());
         TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
 
         connection.clientHooks = new ClientHooks() {
@@ -653,15 +657,55 @@ public class ConscryptSocketTest {
         };
 
         connection.doHandshake();
-        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
+        assertTrue("Expected SSLHandshakeException, but got "
+                + connection.clientException.getClass().getSimpleName()
+                + ": " + connection.clientException.getMessage(),
+                connection.clientException instanceof SSLHandshakeException);
         assertTrue(
                 connection.clientException.getMessage().contains("SSLv3 is no longer supported"));
-        assertThat(connection.serverException, instanceOf(SSLHandshakeException.class));
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.serverException.getClass().getSimpleName()
+                        + ": " + connection.serverException.getMessage(),
+                connection.serverException instanceof SSLHandshakeException);
 
         assertFalse(connection.clientHooks.isHandshakeCompleted);
         assertFalse(connection.serverHooks.isHandshakeCompleted);
     }
 
+    @Test
+    public void test_setEnabledProtocols_RejectsSSLv3_IfNotFiltered() throws Exception {
+        assumeFalse(TestUtils.isTlsV1Filtered());
+        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
+
+        connection.clientHooks = new ClientHooks() {
+            @Override
+            public AbstractConscryptSocket createSocket(ServerSocket listener) throws IOException {
+                try (AbstractConscryptSocket socket = super.createSocket(listener)) {
+                    socket.setEnabledProtocols(new String[]{"SSLv3"});
+                    fail("SSLv3 should be rejected");
+                    return socket;
+                }
+            }
+        };
+
+        connection.doHandshake();
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.clientException.getClass().getSimpleName()
+                        + ": " + connection.clientException.getMessage(),
+                connection.clientException instanceof IllegalArgumentException);
+        assertTrue(
+                connection.clientException.getMessage().contains("SSLv3 is not supported"));
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.serverException.getClass().getSimpleName()
+                        + ": " + connection.serverException.getMessage(),
+                connection.serverException instanceof SSLHandshakeException);
+
+        assertFalse(connection.clientHooks.isHandshakeCompleted);
+        assertFalse(connection.serverHooks.isHandshakeCompleted);
+    }
+
+
+
     @Test
     public void savedSessionWorksAfterClose() throws Exception {
         String alpnProtocol = "spdy/2";
diff --git a/openjdk/src/test/java/org/conscrypt/MockSessionBuilder.java b/openjdk/src/test/java/org/conscrypt/MockSessionBuilder.java
index c7a8de88..43ce4c02 100644
--- a/openjdk/src/test/java/org/conscrypt/MockSessionBuilder.java
+++ b/openjdk/src/test/java/org/conscrypt/MockSessionBuilder.java
@@ -77,7 +77,7 @@ final class MockSessionBuilder {
         when(session.getId()).thenReturn(id);
         when(session.isValid()).thenReturn(valid);
         when(session.isSingleUse()).thenReturn(singleUse);
-        when(session.getProtocol()).thenReturn(TestUtils.highestCommonProtocol());
+        when(session.getProtocol()).thenReturn(TestUtils.getSupportedProtocols()[0]);
         when(session.getPeerHost()).thenReturn(host);
         when(session.getPeerPort()).thenReturn(port);
         when(session.getCipherSuite()).thenReturn(cipherSuite);
diff --git a/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java b/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
index 0a02e91d..c4db6e66 100644
--- a/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
+++ b/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
@@ -26,6 +26,7 @@ import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 import static org.conscrypt.NativeConstants.TLS1_1_VERSION;
 import static org.conscrypt.NativeConstants.TLS1_2_VERSION;
 import static org.conscrypt.NativeConstants.TLS1_VERSION;
+import static org.conscrypt.TestUtils.isWindows;
 import static org.conscrypt.TestUtils.openTestFile;
 import static org.conscrypt.TestUtils.readTestFile;
 import static org.junit.Assert.assertEquals;
@@ -35,6 +36,7 @@ import static org.junit.Assert.assertNotSame;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.when;
 
@@ -111,84 +113,49 @@ public class NativeCryptoTest {
     private static byte[] CHANNEL_ID;
     private static Method m_Platform_getFileDescriptor;
 
+    private static RSAPrivateCrtKey TEST_RSA_KEY;
+
     @BeforeClass
-    public static void getPlatformMethods() throws Exception {
+    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
+    public static void initStatics() throws Exception {
         Class<?> c_Platform = TestUtils.conscryptClass("Platform");
         m_Platform_getFileDescriptor =
                 c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
         m_Platform_getFileDescriptor.setAccessible(true);
-    }
 
-    private static OpenSSLKey getServerPrivateKey() {
-        initCerts();
-        return SERVER_PRIVATE_KEY;
-    }
+        PrivateKeyEntry serverPrivateKeyEntry = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
+        SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
+        SERVER_CERTIFICATES_HOLDER = encodeCertificateList(serverPrivateKeyEntry.getCertificateChain());
+        SERVER_CERTIFICATE_REFS = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);
+        ENCODED_SERVER_CERTIFICATES = getEncodedCertificates(SERVER_CERTIFICATES_HOLDER);
 
-    private static long[] getServerCertificateRefs() {
-        initCerts();
-        return SERVER_CERTIFICATE_REFS;
-    }
-
-    private static byte[][] getEncodedServerCertificates() {
-        initCerts();
-        return ENCODED_SERVER_CERTIFICATES;
-    }
+        PrivateKeyEntry clientPrivateKeyEntry = TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
+        CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
+        CLIENT_CERTIFICATES_HOLDER = encodeCertificateList(clientPrivateKeyEntry.getCertificateChain());
+        CLIENT_CERTIFICATE_REFS = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);
+        ENCODED_CLIENT_CERTIFICATES = getEncodedCertificates(CLIENT_CERTIFICATES_HOLDER);
 
-    private static OpenSSLKey getClientPrivateKey() {
-        initCerts();
-        return CLIENT_PRIVATE_KEY;
-    }
+        KeyStore ks = TestKeyStore.getClient().keyStore;
+        String caCertAlias = ks.aliases().nextElement();
+        X509Certificate certificate = (X509Certificate) ks.getCertificate(caCertAlias);
+        X500Principal principal = certificate.getIssuerX500Principal();
+        CA_PRINCIPALS = new byte[][] { principal.getEncoded() };
 
-    private static long[] getClientCertificateRefs() {
-        initCerts();
-        return CLIENT_CERTIFICATE_REFS;
-    }
+        // NIST P-256 aka SECG secp256r1 aka X9.62 prime256v1
+        OpenSSLECGroupContext openSslSpec = OpenSSLECGroupContext.getCurveByName("prime256v1");
+        BigInteger s = new BigInteger(
+                "229cdbbf489aea584828a261a23f9ff8b0f66f7ccac98bf2096ab3aee41497c5", 16);
+        CHANNEL_ID_PRIVATE_KEY = new OpenSSLECPrivateKey(new ECPrivateKeySpec(s, openSslSpec.getECParameterSpec()))
+                .getOpenSSLKey();
 
-    private static byte[][] getEncodedClientCertificates() {
-        initCerts();
-        return ENCODED_CLIENT_CERTIFICATES;
-    }
+        // Channel ID is the concatenation of the X and Y coordinates of the public key.
+        CHANNEL_ID = new BigInteger(
+                "702b07871fd7955c320b26f15e244e47eed60272124c92b9ebecf0b42f90069b"
+                        + "ab53592ebfeb4f167dbf3ce61513afb0e354c479b1c1b69874fa471293494f77",
+                16).toByteArray();
 
-    private static byte[][] getCaPrincipals() {
-        initCerts();
-        return CA_PRINCIPALS;
-    }
-
-    /**
-     * Lazily create shared test certificates.
-     */
-    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
-    private static synchronized void initCerts() {
-        if (SERVER_PRIVATE_KEY != null) {
-            return;
-        }
-
-        try {
-            PrivateKeyEntry serverPrivateKeyEntry =
-                    TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
-            SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
-            SERVER_CERTIFICATES_HOLDER =
-                    encodeCertificateList(serverPrivateKeyEntry.getCertificateChain());
-            SERVER_CERTIFICATE_REFS = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);
-            ENCODED_SERVER_CERTIFICATES = getEncodedCertificates(SERVER_CERTIFICATES_HOLDER);
-
-            PrivateKeyEntry clientPrivateKeyEntry =
-                    TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
-            CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
-            CLIENT_CERTIFICATES_HOLDER =
-                    encodeCertificateList(clientPrivateKeyEntry.getCertificateChain());
-            CLIENT_CERTIFICATE_REFS = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);
-            ENCODED_CLIENT_CERTIFICATES = getEncodedCertificates(CLIENT_CERTIFICATES_HOLDER);
-
-            KeyStore ks = TestKeyStore.getClient().keyStore;
-            String caCertAlias = ks.aliases().nextElement();
-            X509Certificate certificate = (X509Certificate) ks.getCertificate(caCertAlias);
-            X500Principal principal = certificate.getIssuerX500Principal();
-            CA_PRINCIPALS = new byte[][] {principal.getEncoded()};
-            initChannelIdKey();
-        } catch (Exception e) {
-            throw new RuntimeException(e);
-        }
+        // RSA keys are slow to generate, so prefer to reuse the key when possible.
+        TEST_RSA_KEY = generateRsaKey();
     }
 
     private static long[] getCertificateReferences(OpenSSLX509Certificate[] certs) {
@@ -220,29 +187,9 @@ public class NativeCryptoTest {
         return openSslCerts;
     }
 
-    private static synchronized void initChannelIdKey() throws Exception {
-        if (CHANNEL_ID_PRIVATE_KEY != null) {
-            return;
-        }
-
-        // NIST P-256 aka SECG secp256r1 aka X9.62 prime256v1
-        OpenSSLECGroupContext openSslSpec = OpenSSLECGroupContext.getCurveByName("prime256v1");
-        BigInteger s = new BigInteger(
-                "229cdbbf489aea584828a261a23f9ff8b0f66f7ccac98bf2096ab3aee41497c5", 16);
-        CHANNEL_ID_PRIVATE_KEY =
-                new OpenSSLECPrivateKey(new ECPrivateKeySpec(s, openSslSpec.getECParameterSpec()))
-                        .getOpenSSLKey();
-
-        // Channel ID is the concatenation of the X and Y coordinates of the public key.
-        CHANNEL_ID = new BigInteger(
-                "702b07871fd7955c320b26f15e244e47eed60272124c92b9ebecf0b42f90069b"
-                        + "ab53592ebfeb4f167dbf3ce61513afb0e354c479b1c1b69874fa471293494f77",
-                16).toByteArray();
-    }
-
     private static RSAPrivateCrtKey generateRsaKey() throws Exception {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
-        kpg.initialize(512);
+        kpg.initialize(2048);
 
         KeyPair keyPair = kpg.generateKeyPair();
         return (RSAPrivateCrtKey) keyPair.getPrivate();
@@ -287,7 +234,7 @@ public class NativeCryptoTest {
 
     @Test(expected = NullPointerException.class)
     public void EVP_PKEY_cmp_withNullShouldThrow() throws Exception {
-        RSAPrivateCrtKey privKey1 = generateRsaKey();
+        RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
         assertNotSame(NULL, pkey1);
         NativeCrypto.EVP_PKEY_cmp(pkey1, null);
@@ -295,7 +242,7 @@ public class NativeCryptoTest {
 
     @Test
     public void test_EVP_PKEY_cmp() throws Exception {
-        RSAPrivateCrtKey privKey1 = generateRsaKey();
+        RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
 
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
         assertNotSame(NULL, pkey1);
@@ -303,6 +250,7 @@ public class NativeCryptoTest {
         NativeRef.EVP_PKEY pkey1_copy = getRsaPkey(privKey1);
         assertNotSame(NULL, pkey1_copy);
 
+        // Generate a different key.
         NativeRef.EVP_PKEY pkey2 = getRsaPkey(generateRsaKey());
         assertNotSame(NULL, pkey2);
 
@@ -392,7 +340,7 @@ public class NativeCryptoTest {
     @Test(expected = NullPointerException.class)
     public void setLocalCertsAndPrivateKey_withNullSSLShouldThrow() throws Exception {
         NativeCrypto.setLocalCertsAndPrivateKey(
-                NULL, null, getEncodedServerCertificates(), getServerPrivateKey().getNativeRef());
+                NULL, null, ENCODED_SERVER_CERTIFICATES, SERVER_PRIVATE_KEY.getNativeRef());
     }
 
     @Test(expected = NullPointerException.class)
@@ -400,7 +348,7 @@ public class NativeCryptoTest {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
         try {
-            NativeCrypto.setLocalCertsAndPrivateKey(s, null, null, getServerPrivateKey().getNativeRef());
+            NativeCrypto.setLocalCertsAndPrivateKey(s, null, null, SERVER_PRIVATE_KEY.getNativeRef());
         } finally {
             NativeCrypto.SSL_free(s, null);
             NativeCrypto.SSL_CTX_free(c, null);
@@ -412,7 +360,7 @@ public class NativeCryptoTest {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
         try {
-            NativeCrypto.setLocalCertsAndPrivateKey(s, null, getEncodedServerCertificates(), null);
+            NativeCrypto.setLocalCertsAndPrivateKey(s, null, ENCODED_SERVER_CERTIFICATES, null);
         } finally {
             NativeCrypto.SSL_free(s, null);
             NativeCrypto.SSL_CTX_free(c, null);
@@ -425,7 +373,7 @@ public class NativeCryptoTest {
         long s = NativeCrypto.SSL_new(c, null);
 
         NativeCrypto.setLocalCertsAndPrivateKey(
-                s, null, getEncodedServerCertificates(), getServerPrivateKey().getNativeRef());
+                s, null, ENCODED_SERVER_CERTIFICATES, SERVER_PRIVATE_KEY.getNativeRef());
 
         NativeCrypto.SSL_free(s, null);
         NativeCrypto.SSL_CTX_free(c, null);
@@ -438,8 +386,6 @@ public class NativeCryptoTest {
 
     @Test(expected = NullPointerException.class)
     public void SSL_set1_tls_channel_id_withNullKeyShouldThrow() throws Exception {
-        initChannelIdKey();
-
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
         try {
@@ -452,8 +398,6 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_use_PrivateKey_for_tls_channel_id() throws Exception {
-        initChannelIdKey();
-
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
 
@@ -1090,7 +1034,7 @@ public class NativeCryptoTest {
         // normal client and server case
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -1098,7 +1042,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1127,7 +1071,7 @@ public class NativeCryptoTest {
             }
         }, null, null);
         Future<TestSSLHandshakeCallbacks> server1 = handshake(listener, 0,
-                false, new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+                false, new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                         callbacks.onNewSessionEstablishedSaveSession = true;
@@ -1137,7 +1081,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback1 = server1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback1.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback1.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback1.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback1.authMethod);
         assertFalse(serverCallback1.verifyCertificateChainCalled);
         assertFalse(clientCallback1.clientCertificateRequestedCalled);
@@ -1167,7 +1111,7 @@ public class NativeCryptoTest {
             }
         }, null, null);
         Future<TestSSLHandshakeCallbacks> server2 = handshake(listener, 0,
-                false, new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+                false, new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public long beforeHandshake(long c) throws SSLException {
                         long sslNativePtr = super.beforeHandshake(c);
@@ -1179,7 +1123,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback2 = server2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback2.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback2.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback2.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback2.authMethod);
         assertFalse(serverCallback2.verifyCertificateChainCalled);
         assertFalse(clientCallback2.clientCertificateRequestedCalled);
@@ -1210,14 +1154,14 @@ public class NativeCryptoTest {
                     throws CertificateEncodingException, SSLException {
                 super.clientCertificateRequested(s);
                 NativeCrypto.setLocalCertsAndPrivateKey(
-                        s, null, getEncodedClientCertificates(), getClientPrivateKey().getNativeRef());
+                        s, null, ENCODED_CLIENT_CERTIFICATES, CLIENT_PRIVATE_KEY.getNativeRef());
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public long beforeHandshake(long c) throws SSLException {
                 long s = super.beforeHandshake(c);
-                NativeCrypto.SSL_set_client_CA_list(s, null, getCaPrincipals());
+                NativeCrypto.SSL_set_client_CA_list(s, null, CA_PRINCIPALS);
                 NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_PEER);
                 return s;
             }
@@ -1229,11 +1173,11 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertTrue(serverCallback.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getClientCertificateRefs(), serverCallback.certificateChainRefs);
+                CLIENT_CERTIFICATE_REFS, serverCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", serverCallback.authMethod);
 
         assertTrue(clientCallback.clientCertificateRequestedCalled);
@@ -1242,7 +1186,7 @@ public class NativeCryptoTest {
         assertEquals(new HashSet<String>(Arrays.asList("EC", "RSA")),
                 SSLUtils.getSupportedClientKeyTypes(
                         clientCallback.keyTypes, clientCallback.signatureAlgs));
-        assertEqualPrincipals(getCaPrincipals(), clientCallback.asn1DerEncodedX500Principals);
+        assertEqualPrincipals(CA_PRINCIPALS, clientCallback.asn1DerEncodedX500Principals);
         assertFalse(serverCallback.clientCertificateRequestedCalled);
 
         assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
@@ -1263,11 +1207,11 @@ public class NativeCryptoTest {
         final ServerSocket listener = newServerSocket();
         try {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public long beforeHandshake(long c) throws SSLException {
                     long s = super.beforeHandshake(c);
-                    NativeCrypto.SSL_set_client_CA_list(s, null, getCaPrincipals());
+                    NativeCrypto.SSL_set_client_CA_list(s, null, CA_PRINCIPALS);
                     NativeCrypto.SSL_set_verify(
                             s, null, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                     return s;
@@ -1292,7 +1236,7 @@ public class NativeCryptoTest {
         Socket serverSocket = null;
         try {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, 1, true, cHooks, null, null);
             Future<TestSSLHandshakeCallbacks> server =
@@ -1315,7 +1259,7 @@ public class NativeCryptoTest {
         Socket clientSocket = null;
         try {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, -1, true, cHooks, null, null);
             Future<TestSSLHandshakeCallbacks> server =
@@ -1333,15 +1277,13 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_do_handshake_with_channel_id_normal() throws Exception {
-        initChannelIdKey();
-
         // Normal handshake with TLS Channel ID.
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
         cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
         // TLS Channel ID currently requires ECDHE-based key exchanges.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
-        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        ServerHooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         sHooks.channelIdEnabled = true;
         sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
@@ -1351,7 +1293,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1372,15 +1314,13 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_do_handshake_with_channel_id_not_supported_by_server() throws Exception {
-        initChannelIdKey();
-
         // Client tries to use TLS Channel ID but the server does not enable/offer the extension.
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
         cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
         // TLS Channel ID currently requires ECDHE-based key exchanges.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
-        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        ServerHooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         sHooks.channelIdEnabled = false;
         sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
@@ -1390,7 +1330,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1411,15 +1351,13 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_do_handshake_with_channel_id_not_enabled_by_client() throws Exception {
-        initChannelIdKey();
-
         // Client does not use TLS Channel ID when the server has the extension enabled/offered.
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
         cHooks.channelIdPrivateKey = null;
         // TLS Channel ID currently requires ECDHE-based key exchanges.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
-        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        ServerHooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         sHooks.channelIdEnabled = true;
         sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
@@ -1429,7 +1367,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
         assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+                SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1676,7 +1614,7 @@ public class NativeCryptoTest {
             }
         };
 
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public long beforeHandshake(long c) throws SSLException {
                 long s = super.beforeHandshake(c);
@@ -1719,7 +1657,7 @@ public class NativeCryptoTest {
             }
         };
 
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public long beforeHandshake(long c) throws SSLException {
                 long s = super.beforeHandshake(c);
@@ -1802,7 +1740,7 @@ public class NativeCryptoTest {
                     }
                 };
                 Hooks sHooks = new ServerHooks(
-                        getServerPrivateKey(), getEncodedServerCertificates()) {
+                        SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public long getContext() throws SSLException {
                         return serverContext;
@@ -1842,7 +1780,7 @@ public class NativeCryptoTest {
                     }
                 };
                 Hooks sHooks = new ServerHooks(
-                        getServerPrivateKey(), getEncodedServerCertificates()) {
+                        SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public long getContext() throws SSLException {
                         return serverContext;
@@ -1894,7 +1832,7 @@ public class NativeCryptoTest {
                     return s;
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, 0, true, cHooks, null, null);
             @SuppressWarnings("unused")
@@ -1917,7 +1855,7 @@ public class NativeCryptoTest {
         // negative test case for SSL_set_session_creation_enabled(false) on server
         {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public long beforeHandshake(long c) throws SSLException {
                     long s = super.beforeHandshake(c);
@@ -2002,7 +1940,7 @@ public class NativeCryptoTest {
                 return s;
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                     SSLHandshakeCallbacks callback) throws Exception {
@@ -2033,7 +1971,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2068,7 +2006,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2101,7 +2039,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2140,7 +2078,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2195,11 +2133,11 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                     SSLHandshakeCallbacks callback) throws Exception {
                 byte[][] cc = NativeCrypto.SSL_get0_peer_certificates(s, null);
-                assertEqualByteArrays(getEncodedServerCertificates(), cc);
+                assertEqualByteArrays(ENCODED_SERVER_CERTIFICATES, cc);
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2211,7 +2149,7 @@ public class NativeCryptoTest {
     public void test_SSL_cipher_names() throws Exception {
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         // Both legacy and standard names are accepted.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-GCM-SHA256");
         sHooks.enabledCipherSuites =
@@ -2300,7 +2238,7 @@ public class NativeCryptoTest {
                     super.afterHandshake(session, s, c, sock, fd, callback);
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public void afterHandshake(long session, long s, long c, Socket sock,
                         FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2326,7 +2264,7 @@ public class NativeCryptoTest {
                     fail();
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public void afterHandshake(long session, long s, long c, Socket sock,
                         FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2427,7 +2365,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, final long s, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2543,7 +2481,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2558,8 +2496,10 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_SESSION_get_time() throws Exception {
-        final ServerSocket listener = newServerSocket();
+        // TODO(prb) seems to fail regularly on Windows with time < System.currentTimeMillis()
+        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());
 
+        final ServerSocket listener = newServerSocket();
         {
             Hooks cHooks = new Hooks() {
                 @Override
@@ -2571,7 +2511,7 @@ public class NativeCryptoTest {
                     super.afterHandshake(session, s, c, sock, fd, callback);
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, 0, true, cHooks, null, null);
             Future<TestSSLHandshakeCallbacks> server =
@@ -2599,7 +2539,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2628,7 +2568,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2672,7 +2612,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2747,11 +2687,7 @@ public class NativeCryptoTest {
 
     @Test
     public void test_EVP_DigestSignInit() throws Exception {
-        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
-        kpg.initialize(512);
-
-        KeyPair kp = kpg.generateKeyPair();
-        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) kp.getPrivate();
+        RSAPrivateCrtKey privKey = TEST_RSA_KEY;
 
         NativeRef.EVP_PKEY pkey;
         pkey = new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
@@ -3067,7 +3003,7 @@ public class NativeCryptoTest {
     }
 
     private static long getRawPkeyCtxForEncrypt() throws Exception {
-        return NativeCrypto.EVP_PKEY_encrypt_init(getRsaPkey(generateRsaKey()));
+        return NativeCrypto.EVP_PKEY_encrypt_init(getRsaPkey(TEST_RSA_KEY));
     }
 
     private static NativeRef.EVP_PKEY_CTX getPkeyCtxForEncrypt() throws Exception {
diff --git a/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java b/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java
index d6dac202..dc7044f0 100644
--- a/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java
+++ b/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java
@@ -23,29 +23,64 @@ import junit.framework.TestCase;
 public class OpenSSLKeyTest extends TestCase {
     static final String RSA_PUBLIC_KEY =
         "-----BEGIN PUBLIC KEY-----\n" +
-        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOHsK2E2FLYfEMWEVH/rJMTqDZLLLysh\n" +
-        "AH5odcfhYdF9xvFFU9rqJT7zXUDH4SjdhZGUUAO5IOC1e8ZIyRsbiY0CAwEAAQ==\n" +
+        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3G7PGpfZx68wTY9eLb4b\n" +
+        "th3Y7MXgh1A2oqB202KTiClKy9Y+Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c\n" +
+        "0wj2e3kxwS/wiMjoYXIcbFW0iN6g1F6n71Zykf0uOE8DZKCffzjmld+Ia5M4qKsC\n" +
+        "gW4TTUODGVChBUTKui4b7Q8qsBOUTXm7SeyuZcZRChZ2w9aICZ3OR1qHnG0EXvgs\n" +
+        "0ZhCIgvtVQPaEwqMWaGYQKa8hW9X3KUvY6D8fQkQdhY2j5m/y2757tNsQWhH7l/C\n" +
+        "gdH/2F7qa3+V1yTqj9ihceLq1/FxAZkd6q7G9YE8ZyvtoKU86o6+4arMELQi86QF\n" +
+        "cQIDAQAB\n" +
         "-----END PUBLIC KEY-----";
 
     static final String RSA_PRIVATE_KEY =
         "-----BEGIN RSA PRIVATE KEY-----\n" +
-        "MIIBOgIBAAJBAOHsK2E2FLYfEMWEVH/rJMTqDZLLLyshAH5odcfhYdF9xvFFU9rq\n" +
-        "JT7zXUDH4SjdhZGUUAO5IOC1e8ZIyRsbiY0CAwEAAQJBALcu+oGJC0QcbknpIWbT\n" +
-        "L+4mZTkYXLeYu8DDTHT0j47+6eEyYBOoRGcZDdlMWquvFIrV48RSot0GPh1MBE1p\n" +
-        "lKECIQD4krM4UshCwUHH9ZVkoxcPsxzPTTW7ukky4RZVN6mgWQIhAOisOAXVVjon\n" +
-        "fbGNQ6CezH7oOttEeZmiWCu48AVCyixVAiAaDZ41OA//Vywi3i2jV6iyH47Ud347\n" +
-        "R+ImMAtcMTJZOQIgF0+Z1UvIdc8bErzad68xQc22h91WaYQQXWEL+xrz8nkCIDcA\n" +
-        "MpCP/H5qTCj/l5rxQg+/NUGCg2pHHNLL+cy5N5RM\n" +
+        "MIIEpAIBAAKCAQEA3G7PGpfZx68wTY9eLb4bth3Y7MXgh1A2oqB202KTiClKy9Y+\n" +
+        "Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c0wj2e3kxwS/wiMjoYXIcbFW0iN6g\n" +
+        "1F6n71Zykf0uOE8DZKCffzjmld+Ia5M4qKsCgW4TTUODGVChBUTKui4b7Q8qsBOU\n" +
+        "TXm7SeyuZcZRChZ2w9aICZ3OR1qHnG0EXvgs0ZhCIgvtVQPaEwqMWaGYQKa8hW9X\n" +
+        "3KUvY6D8fQkQdhY2j5m/y2757tNsQWhH7l/CgdH/2F7qa3+V1yTqj9ihceLq1/Fx\n" +
+        "AZkd6q7G9YE8ZyvtoKU86o6+4arMELQi86QFcQIDAQABAoIBABkX4iqoU6nYJxsF\n" +
+        "MZbqd9QdBLc7dWph9r4/nxdENwA+lx2qN3Ny703xv+VH7u2ZSVxwvH0ZqPqn9Dwk\n" +
+        "UatAmfLqJ8j5jHDuCKdBm7aQG203unQER/G1Ds//ms5EsJDHad74K//7FcDE8A4y\n" +
+        "9bW5tfDO+5KFl3R3ycTERoG4QwSSyb8qGbA5Xo+C+9EK9ldE5f7tnryXpG/iCHem\n" +
+        "NanAF+Jxof1GanaCD6xQDug4ReEqZrWWwtco89qfNNSXEpH05hPmgl35UKO9RQn5\n" +
+        "07EtowT+WwDEQ/8zMmuL+z/hEf1LiHKCLH8oMtr6D+ENmroiMQhJ6XjlHIqp2nvB\n" +
+        "wHUR2IMCgYEA++hWbdHxZ3I+QvBIjUKF6OfWkN0ZHVWU9ZNTZoG4ggdxlm5XN+C7\n" +
+        "tohumtChIU0oNkdG38akyN5HlTg+tbd7E0ZgBnYMwAsEEXt5aEoFtFAxEorI26zr\n" +
+        "uvWqRwXNFVKTuC9+JFZvFiteYMSWzryn8dS2cNVG1hswGa1kf0Xg218CgYEA4AOS\n" +
+        "F1snvadqxocM7U8LpY8mSeXV5PayZN87GLFaK41G/zD0l+mVZAWZld9ux+rR/2OP\n" +
+        "uPWZWtn/+4v2DERukA0jerGdFocCv1s893Stoz/oVapCW0h6pa+Fa6EX2nuqNST0\n" +
+        "bE/dbHhfYditfoGQhQlOLmqrJc+B6jaOt+m7oS8CgYBVvwxMbX4inDydRHUtwEsc\n" +
+        "sG3U+a2m0o7V2MQ2zEkl2arMbdq6ZoD+7QnZINL4Ju9dKn3xhghpZ2AuZurRqBb4\n" +
+        "xKfDC0Pjytwjp0f4O9odOn65tQwR2paTGTRQ4KSicW1e8KubauB9R13kyoYa8RSp\n" +
+        "uKIxXieykaaZ1u+ycvLLOQKBgQC1PU5SRTbm82+pBZTI3t4eaa3htekTISD+CbnH\n" +
+        "ZZ39hIT/bH1H9v0d+oXjQu1fI7YZOVULoPEdFylLPFaqYCdPtsGQv+jHVB498bRm\n" +
+        "xOjDHq57uI+NSRupt1Nr297vroPsEWULyKXt34nUITllE7B4Yin11el4YuXKN6/K\n" +
+        "Tnm2kwKBgQC6Qy/DiFeF5uf0xnAkh0HFjzL+F3isIUV5l31jzna2sJSKridm+Hst\n" +
+        "mnaNDu/BKViEvSof3IpW8f7PSzskc4+Fos1KMdCkxG3bNrym8OLdWi+J4NjTbbCa\n" +
+        "sudhqm8rNr8zWFAEZ48jpcv7whYfkjCIh4z0uVNOq9dspolJaW14yg==\n" +
         "-----END RSA PRIVATE KEY-----";
 
     static final BigInteger RSA_MODULUS = new BigInteger(
-        "e1ec2b613614b61f10c584547feb24c4ea0d92cb2f2b21007e6875c7e161d17d" +
-        "c6f14553daea253ef35d40c7e128dd8591945003b920e0b57bc648c91b1b898d", 16);
+        "dc6ecf1a97d9c7af304d8f5e2dbe1bb61dd8ecc5e0875036a2a076d362938829" +
+        "4acbd63e67e1c2c792885d77327158c07e12bba86f85fd755e1344e9cd1f1cd3" +
+        "08f67b7931c12ff088c8e861721c6c55b488dea0d45ea7ef567291fd2e384f03" +
+        "64a09f7f38e695df886b9338a8ab02816e134d43831950a10544caba2e1bed0f" +
+        "2ab013944d79bb49ecae65c6510a1676c3d688099dce475a879c6d045ef82cd1" +
+        "9842220bed5503da130a8c59a19840a6bc856f57dca52f63a0fc7d0910761636" +
+        "8f99bfcb6ef9eed36c416847ee5fc281d1ffd85eea6b7f95d724ea8fd8a171e2" +
+        "ead7f17101991deaaec6f5813c672beda0a53cea8ebee1aacc10b422f3a40571", 16);
 
     static final BigInteger RSA_PUBLIC_EXPONENT = new BigInteger("10001", 16);
     static final BigInteger RSA_PRIVATE_EXPONENT = new BigInteger(
-        "b72efa81890b441c6e49e92166d32fee266539185cb798bbc0c34c74f48f8efe" +
-        "e9e1326013a84467190dd94c5aabaf148ad5e3c452a2dd063e1d4c044d6994a1", 16);
+        "1917e22aa853a9d8271b053196ea77d41d04b73b756a61f6be3f9f174437003e" +
+        "971daa377372ef4df1bfe547eeed99495c70bc7d19a8faa7f43c2451ab4099f2" +
+        "ea27c8f98c70ee08a7419bb6901b6d37ba740447f1b50ecfff9ace44b090c769" +
+        "def82bfffb15c0c4f00e32f5b5b9b5f0cefb9285977477c9c4c44681b8430492" +
+        "c9bf2a19b0395e8f82fbd10af65744e5feed9ebc97a46fe20877a635a9c017e2" +
+        "71a1fd466a76820fac500ee83845e12a66b596c2d728f3da9f34d4971291f4e6" +
+        "13e6825df950a3bd4509f9d3b12da304fe5b00c443ff33326b8bfb3fe111fd4b" +
+        "8872822c7f2832dafa0fe10d9aba22310849e978e51c8aa9da7bc1c07511d883", 16);
 
     public void test_fromPublicKeyPemInputStream() throws Exception {
         ByteArrayInputStream is = new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes("UTF-8"));
diff --git a/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java b/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java
index c510e0d2..ec5150a0 100644
--- a/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java
+++ b/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java
@@ -17,6 +17,11 @@
 package org.conscrypt;
 
 import static org.conscrypt.TestUtils.openTestFile;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
@@ -29,10 +34,15 @@ import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
 import java.util.Arrays;
-import junit.framework.TestCase;
 import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
-
-public class OpenSSLX509CertificateTest extends TestCase {
+import org.junit.Ignore;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class OpenSSLX509CertificateTest {
+  @Test
     public void testSerialization_NoContextDeserialization() throws Exception {
         // Set correct serialVersionUID
         {
@@ -113,6 +123,7 @@ public class OpenSSLX509CertificateTest extends TestCase {
         return OpenSSLX509Certificate.fromX509PemInputStream(openTestFile(name));
     }
 
+    @Test
     public void test_deletingCTPoisonExtension() throws Exception {
         /* certPoisoned has an extra poison extension.
          * With the extension, the certificates have different TBS.
@@ -130,6 +141,7 @@ public class OpenSSLX509CertificateTest extends TestCase {
                 cert.getTBSCertificate()));
     }
 
+    @Test
     public void test_deletingExtensionMakesCopy() throws Exception {
         /* Calling getTBSCertificateWithoutExtension should not modify the original certificate.
          * Make sure the extension is still present in the original object.
@@ -141,6 +153,7 @@ public class OpenSSLX509CertificateTest extends TestCase {
         assertTrue(certPoisoned.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
     }
 
+    @Test
     public void test_deletingMissingExtension() throws Exception {
         /* getTBSCertificateWithoutExtension should throw on a certificate without the extension.
          */
diff --git a/openjdk/src/test/java/org/conscrypt/PlatformTest.java b/openjdk/src/test/java/org/conscrypt/PlatformTest.java
index 06543594..170eb6e3 100644
--- a/openjdk/src/test/java/org/conscrypt/PlatformTest.java
+++ b/openjdk/src/test/java/org/conscrypt/PlatformTest.java
@@ -36,10 +36,13 @@ import javax.net.ssl.SSLParameters;
 import org.conscrypt.testing.FailingSniMatcher;
 import org.conscrypt.testing.RestrictedAlgorithmConstraints;
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 /**
  * Test for Platform
  */
+@RunWith(JUnit4.class)
 public class PlatformTest {
     private static final Method SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD;
     private static final Method SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD;
diff --git a/openjdk/src/test/java/org/conscrypt/TestSessionBuilderTest.java b/openjdk/src/test/java/org/conscrypt/TestSessionBuilderTest.java
index 9971a3fe..f00a9466 100644
--- a/openjdk/src/test/java/org/conscrypt/TestSessionBuilderTest.java
+++ b/openjdk/src/test/java/org/conscrypt/TestSessionBuilderTest.java
@@ -19,7 +19,10 @@ package org.conscrypt;
 import static org.junit.Assert.assertArrayEquals;
 
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
+@RunWith(JUnit4.class)
 public class TestSessionBuilderTest {
     @Test
     public void buildsValidBasicSession() {
diff --git a/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java b/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java
index 697e3b33..305b74b8 100644
--- a/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java
+++ b/platform/src/main/java/org/conscrypt/CertBlocklistImpl.java
@@ -43,9 +43,9 @@ public final class CertBlocklistImpl implements CertBlocklist {
     private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());
 
     private final Set<BigInteger> serialBlocklist;
-    private final Set<ByteString> sha1PubkeyBlocklist;
-    private final Set<ByteString> sha256PubkeyBlocklist;
-    private Map<ByteString, Boolean> cache;
+    private final Set<ByteArray> sha1PubkeyBlocklist;
+    private final Set<ByteArray> sha256PubkeyBlocklist;
+    private Map<ByteArray, Boolean> cache;
 
     /**
      * Number of entries in the cache. The cache contains public keys which are
@@ -57,15 +57,15 @@ public final class CertBlocklistImpl implements CertBlocklist {
     /**
      * public for testing only.
      */
-    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> sha1PubkeyBlocklist) {
+    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteArray> sha1PubkeyBlocklist) {
         this(serialBlocklist, sha1PubkeyBlocklist, Collections.emptySet());
     }
 
-    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> sha1PubkeyBlocklist,
-            Set<ByteString> sha256PubkeyBlocklist) {
-        this.cache = Collections.synchronizedMap(new LinkedHashMap<ByteString, Boolean>() {
+    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteArray> sha1PubkeyBlocklist,
+            Set<ByteArray> sha256PubkeyBlocklist) {
+        this.cache = Collections.synchronizedMap(new LinkedHashMap<ByteArray, Boolean>() {
             @Override
-            protected boolean removeEldestEntry(Map.Entry<ByteString, Boolean> eldest) {
+            protected boolean removeEldestEntry(Map.Entry<ByteArray, Boolean> eldest) {
                 return size() > CACHE_SIZE;
             }
         });
@@ -81,9 +81,9 @@ public final class CertBlocklistImpl implements CertBlocklist {
         String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";
         String defaultPubkeySha256BlocklistPath = blocklistRoot + "pubkey_sha256_blocklist.txt";
 
-        Set<ByteString> sha1PubkeyBlocklist =
+        Set<ByteArray> sha1PubkeyBlocklist =
                 readPublicKeyBlockList(defaultPubkeyBlocklistPath, "SHA-1");
-        Set<ByteString> sha256PubkeyBlocklist =
+        Set<ByteArray> sha256PubkeyBlocklist =
                 readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, "SHA-256");
         Set<BigInteger> serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
         return new CertBlocklistImpl(serialBlocklist, sha1PubkeyBlocklist, sha256PubkeyBlocklist);
@@ -220,15 +220,15 @@ public final class CertBlocklistImpl implements CertBlocklist {
             "809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd".getBytes(UTF_8),
     };
 
-    private static Set<ByteString> readPublicKeyBlockList(String path, String hashType) {
-        Set<ByteString> bl;
+    private static Set<ByteArray> readPublicKeyBlockList(String path, String hashType) {
+        Set<ByteArray> bl;
 
         switch (hashType) {
             case "SHA-1":
-                bl = new HashSet<ByteString>(toByteStrings(SHA1_BUILTINS));
+                bl = new HashSet<ByteArray>(toByteArrays(SHA1_BUILTINS));
                 break;
             case "SHA-256":
-                bl = new HashSet<ByteString>(toByteStrings(SHA256_BUILTINS));
+                bl = new HashSet<ByteArray>(toByteArrays(SHA256_BUILTINS));
                 break;
             default:
                 throw new RuntimeException(
@@ -252,7 +252,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
             for (String value : pubkeyBlocklist.split(",", -1)) {
                 value = value.trim();
                 if (isPubkeyHash(value, hashLength)) {
-                    bl.add(new ByteString(value.getBytes(UTF_8)));
+                    bl.add(new ByteArray(value.getBytes(UTF_8)));
                 } else {
                     logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                 }
@@ -263,7 +263,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
     }
 
     private static boolean isPublicKeyBlockListed(
-            ByteString encodedPublicKey, Set<ByteString> blocklist, String hashType) {
+            byte[] encodedPublicKey, Set<ByteArray> blocklist, String hashType) {
         MessageDigest md;
         try {
             md = MessageDigest.getInstance(hashType);
@@ -271,7 +271,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
             logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
             return false;
         }
-        ByteString out = new ByteString(toHex(md.digest(encodedPublicKey.bytes)));
+        ByteArray out = new ByteArray(toHex(md.digest(encodedPublicKey)));
         if (blocklist.contains(out)) {
             return true;
         }
@@ -280,24 +280,28 @@ public final class CertBlocklistImpl implements CertBlocklist {
 
     @Override
     public boolean isPublicKeyBlockListed(PublicKey publicKey) {
-        ByteString encodedPublicKey = new ByteString(publicKey.getEncoded());
-        Boolean cachedResult = cache.get(encodedPublicKey);
+        byte[] encodedPublicKey = publicKey.getEncoded();
+        // cacheKey is a view on encodedPublicKey. Because it is used as a key
+        // for a Map, its underlying array (encodedPublicKey) should not be
+        // modified.
+        ByteArray cacheKey = new ByteArray(encodedPublicKey);
+        Boolean cachedResult = cache.get(cacheKey);
         if (cachedResult != null) {
             return cachedResult.booleanValue();
         }
         if (!sha1PubkeyBlocklist.isEmpty()) {
             if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, "SHA-1")) {
-                cache.put(encodedPublicKey, true);
+                cache.put(cacheKey, true);
                 return true;
             }
         }
         if (!sha256PubkeyBlocklist.isEmpty()) {
             if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, "SHA-256")) {
-                cache.put(encodedPublicKey, true);
+                cache.put(cacheKey, true);
                 return true;
             }
         }
-        cache.put(encodedPublicKey, false);
+        cache.put(cacheKey, false);
         return false;
     }
 
@@ -321,37 +325,11 @@ public final class CertBlocklistImpl implements CertBlocklist {
         return serialBlocklist.contains(serial);
     }
 
-    private static List<ByteString> toByteStrings(byte[]... allBytes) {
-        List<ByteString> byteStrings = new ArrayList<>(allBytes.length + 1);
+    private static List<ByteArray> toByteArrays(byte[]... allBytes) {
+        List<ByteArray> byteArrays = new ArrayList<>(allBytes.length + 1);
         for (byte[] bytes : allBytes) {
-            byteStrings.add(new ByteString(bytes));
-        }
-        return byteStrings;
-    }
-
-    private static class ByteString {
-        final byte[] bytes;
-
-        public ByteString(byte[] bytes) {
-            this.bytes = bytes;
-        }
-
-        @Override
-        public boolean equals(Object o) {
-            if (o == this) {
-                return true;
-            }
-            if (!(o instanceof ByteString)) {
-                return false;
-            }
-
-            ByteString other = (ByteString) o;
-            return Arrays.equals(bytes, other.bytes);
-        }
-
-        @Override
-        public int hashCode() {
-            return Arrays.hashCode(bytes);
+            byteArrays.add(new ByteArray(bytes));
         }
+        return byteArrays;
     }
 }
diff --git a/platform/src/main/java/org/conscrypt/InternalUtil.java b/platform/src/main/java/org/conscrypt/InternalUtil.java
deleted file mode 100644
index 39558c4e..00000000
--- a/platform/src/main/java/org/conscrypt/InternalUtil.java
+++ /dev/null
@@ -1,46 +0,0 @@
-/*
- * Copyright 2017 The Android Open Source Project
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
-package org.conscrypt;
-
-import java.io.InputStream;
-import java.security.InvalidKeyException;
-import java.security.NoSuchAlgorithmException;
-import java.security.PublicKey;
-import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
-
-/**
- * Helper to initialize the JNI libraries. This version runs when compiled
- * as part of the platform.
- */
-@Internal
-public final class InternalUtil {
-    public static PublicKey logKeyToPublicKey(byte[] logKey)
-            throws NoSuchAlgorithmException {
-        try {
-            return new OpenSSLKey(NativeCrypto.EVP_parse_public_key(logKey)).getPublicKey();
-        } catch (ParsingException e) {
-            throw new NoSuchAlgorithmException(e);
-        }
-    }
-
-    public static PublicKey readPublicKeyPem(InputStream pem) throws InvalidKeyException, NoSuchAlgorithmException {
-        return OpenSSLKey.fromPublicKeyPemInputStream(pem).getPublicKey();
-    }
-
-    private InternalUtil() {
-    }
-}
diff --git a/platform/src/main/java/org/conscrypt/Platform.java b/platform/src/main/java/org/conscrypt/Platform.java
index bf78e1c9..4b994a68 100644
--- a/platform/src/main/java/org/conscrypt/Platform.java
+++ b/platform/src/main/java/org/conscrypt/Platform.java
@@ -62,10 +62,11 @@ import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.ct.CTLogStore;
-import org.conscrypt.ct.CTLogStoreImpl;
-import org.conscrypt.ct.CTPolicy;
-import org.conscrypt.ct.CTPolicyImpl;
+import libcore.net.NetworkSecurityPolicy;
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.LogStoreImpl;
+import org.conscrypt.ct.Policy;
+import org.conscrypt.ct.PolicyImpl;
 import org.conscrypt.metrics.CipherSuite;
 import org.conscrypt.metrics.ConscryptStatsLog;
 import org.conscrypt.metrics.OptionalMethod;
@@ -463,6 +464,10 @@ final class Platform {
     }
 
     static boolean isCTVerificationRequired(String hostname) {
+        if (Flags.certificateTransparencyPlatform()) {
+            return NetworkSecurityPolicy.getInstance()
+                    .isCertificateTransparencyVerificationRequired(hostname);
+        }
         return false;
     }
 
@@ -488,12 +493,12 @@ final class Platform {
         return CertBlocklistImpl.getDefault();
     }
 
-    static CTLogStore newDefaultLogStore() {
-        return new CTLogStoreImpl();
+    static LogStore newDefaultLogStore() {
+        return new LogStoreImpl();
     }
 
-    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
-        return new CTPolicyImpl(logStore, 2);
+    static Policy newDefaultPolicy() {
+        return new PolicyImpl();
     }
 
     static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
diff --git a/platform/src/main/java/org/conscrypt/TrustedCertificateStore.java b/platform/src/main/java/org/conscrypt/TrustedCertificateStore.java
index 14df3764..bcf78164 100644
--- a/platform/src/main/java/org/conscrypt/TrustedCertificateStore.java
+++ b/platform/src/main/java/org/conscrypt/TrustedCertificateStore.java
@@ -35,6 +35,7 @@ import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Set;
 import javax.security.auth.x500.X500Principal;
+import org.conscrypt.ArrayUtils;
 import org.conscrypt.io.IoUtils;
 import org.conscrypt.metrics.OptionalMethod;
 
@@ -116,7 +117,7 @@ public class TrustedCertificateStore implements ConscryptCertStore {
             if ((System.getProperty("system.certs.enabled") != null)
                     && (System.getProperty("system.certs.enabled")).equals("true"))
                 return false;
-            if (updatableDir.exists() && !(updatableDir.list().length == 0))
+            if (updatableDir.exists() && !(ArrayUtils.isEmpty(updatableDir.list())))
                 return true;
             return false;
         }
diff --git a/platform/src/main/java/org/conscrypt/ct/CTLogStoreImpl.java b/platform/src/main/java/org/conscrypt/ct/CTLogStoreImpl.java
deleted file mode 100644
index 0f37a8d0..00000000
--- a/platform/src/main/java/org/conscrypt/ct/CTLogStoreImpl.java
+++ /dev/null
@@ -1,258 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package org.conscrypt.ct;
-
-import java.io.ByteArrayInputStream;
-import java.io.File;
-import java.io.FileInputStream;
-import java.io.FileNotFoundException;
-import java.io.InputStream;
-import java.nio.ByteBuffer;
-import java.nio.charset.Charset;
-import java.nio.charset.StandardCharsets;
-import java.security.InvalidKeyException;
-import java.security.NoSuchAlgorithmException;
-import java.security.PublicKey;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.HashSet;
-import java.util.Scanner;
-import java.util.Set;
-import org.conscrypt.Internal;
-import org.conscrypt.InternalUtil;
-
-@Internal
-public class CTLogStoreImpl implements CTLogStore {
-    private static final Charset US_ASCII = StandardCharsets.US_ASCII;
-
-    /**
-     * Thrown when parsing of a log file fails.
-     */
-    public static class InvalidLogFileException extends Exception {
-        public InvalidLogFileException() {
-        }
-
-        public InvalidLogFileException(String message) {
-            super(message);
-        }
-
-        public InvalidLogFileException(String message, Throwable cause) {
-            super(message, cause);
-        }
-
-        public InvalidLogFileException(Throwable cause) {
-            super(cause);
-        }
-    }
-
-    private static final File defaultUserLogDir;
-    private static final File defaultSystemLogDir;
-    // Lazy loaded by CTLogStoreImpl()
-    private static volatile CTLogInfo[] defaultFallbackLogs = null;
-    static {
-        String ANDROID_DATA = System.getenv("ANDROID_DATA");
-        String ANDROID_ROOT = System.getenv("ANDROID_ROOT");
-        defaultUserLogDir = new File(ANDROID_DATA + "/misc/keychain/trusted_ct_logs/current/");
-        defaultSystemLogDir = new File(ANDROID_ROOT + "/etc/security/ct_known_logs/");
-    }
-
-    private final File userLogDir;
-    private final File systemLogDir;
-    private final CTLogInfo[] fallbackLogs;
-
-    private final HashMap<ByteBuffer, CTLogInfo> logCache = new HashMap<>();
-    private final Set<ByteBuffer> missingLogCache
-            = Collections.synchronizedSet(new HashSet<ByteBuffer>());
-
-    public CTLogStoreImpl() {
-        this(defaultUserLogDir,
-             defaultSystemLogDir,
-             getDefaultFallbackLogs());
-    }
-
-    public CTLogStoreImpl(File userLogDir, File systemLogDir, CTLogInfo[] fallbackLogs) {
-        this.userLogDir = userLogDir;
-        this.systemLogDir = systemLogDir;
-        this.fallbackLogs = fallbackLogs;
-    }
-
-    @Override
-    public CTLogInfo getKnownLog(byte[] logId) {
-        ByteBuffer buf = ByteBuffer.wrap(logId);
-        CTLogInfo log = logCache.get(buf);
-        if (log != null) {
-            return log;
-        }
-        if (missingLogCache.contains(buf)) {
-            return null;
-        }
-
-        log = findKnownLog(logId);
-        if (log != null) {
-            logCache.put(buf, log);
-        } else {
-            missingLogCache.add(buf);
-        }
-
-        return log;
-    }
-
-    private CTLogInfo findKnownLog(byte[] logId) {
-        String filename = hexEncode(logId);
-        try {
-            return loadLog(new File(userLogDir, filename));
-        } catch (InvalidLogFileException e) {
-            return null;
-        } catch (FileNotFoundException e) {
-            // Ignored
-        }
-
-        try {
-            return loadLog(new File(systemLogDir, filename));
-        } catch (InvalidLogFileException e) {
-            return null;
-        } catch (FileNotFoundException e) {
-            // Ignored
-        }
-
-        // If the updateable logs dont exist then use the fallback logs.
-        if (!userLogDir.exists()) {
-            for (CTLogInfo log: fallbackLogs) {
-                if (Arrays.equals(logId, log.getID())) {
-                    return log;
-                }
-            }
-        }
-        return null;
-    }
-
-    public static CTLogInfo[] getDefaultFallbackLogs() {
-        CTLogInfo[] result = defaultFallbackLogs;
-        if (result == null) {
-            // single-check idiom
-            defaultFallbackLogs = result = createDefaultFallbackLogs();
-        }
-        return result;
-    }
-
-    private static CTLogInfo[] createDefaultFallbackLogs() {
-        CTLogInfo[] logs = new CTLogInfo[KnownLogs.LOG_COUNT];
-        for (int i = 0; i < KnownLogs.LOG_COUNT; i++) {
-            try {
-                PublicKey key = InternalUtil.logKeyToPublicKey(KnownLogs.LOG_KEYS[i]);
-
-                logs[i] = new CTLogInfo(key,
-                                        KnownLogs.LOG_DESCRIPTIONS[i],
-                                        KnownLogs.LOG_URLS[i]);
-            } catch (NoSuchAlgorithmException e) {
-                throw new RuntimeException(e);
-            }
-        }
-
-        defaultFallbackLogs = logs;
-        return logs;
-    }
-
-    /**
-     * Load a CTLogInfo from a file.
-     * @throws FileNotFoundException if the file does not exist
-     * @throws InvalidLogFileException if the file could not be parsed properly
-     * @return a CTLogInfo or null if the file is empty
-     */
-    public static CTLogInfo loadLog(File file) throws FileNotFoundException,
-                                                      InvalidLogFileException {
-        return loadLog(new FileInputStream(file));
-    }
-
-    /**
-     * Load a CTLogInfo from a textual representation. Closes {@code input} upon completion
-     * of loading.
-     *
-     * @throws InvalidLogFileException if the input could not be parsed properly
-     * @return a CTLogInfo or null if the input is empty
-     */
-    public static CTLogInfo loadLog(InputStream input) throws InvalidLogFileException {
-        final Scanner scan = new Scanner(input, "UTF-8");
-        scan.useDelimiter("\n");
-
-        String description = null;
-        String url = null;
-        String key = null;
-        try {
-            // If the scanner can't even read one token then the file must be empty/blank
-            if (!scan.hasNext()) {
-                return null;
-            }
-
-            while (scan.hasNext()) {
-                String[] parts = scan.next().split(":", 2);
-                if (parts.length < 2) {
-                    continue;
-                }
-
-                String name = parts[0];
-                String value = parts[1];
-                switch (name) {
-                    case "description":
-                        description = value;
-                        break;
-                    case "url":
-                        url = value;
-                        break;
-                    case "key":
-                        key = value;
-                        break;
-                }
-            }
-        } finally {
-            scan.close();
-        }
-
-        if (description == null || url == null || key == null) {
-            throw new InvalidLogFileException("Missing one of 'description', 'url' or 'key'");
-        }
-
-        PublicKey pubkey;
-        try {
-            pubkey = InternalUtil.readPublicKeyPem(new ByteArrayInputStream(
-                    ("-----BEGIN PUBLIC KEY-----\n" +
-                        key + "\n" +
-                        "-----END PUBLIC KEY-----").getBytes(US_ASCII)));
-        } catch (InvalidKeyException e) {
-            throw new InvalidLogFileException(e);
-        } catch (NoSuchAlgorithmException e) {
-            throw new InvalidLogFileException(e);
-        }
-
-        return new CTLogInfo(pubkey, description, url);
-    }
-
-    private final static char[] HEX_DIGITS = new char[] {
-        '0', '1', '2', '3', '4', '5', '6', '7',
-        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
-    };
-
-    private static String hexEncode(byte[] data) {
-        StringBuilder sb = new StringBuilder(data.length * 2);
-        for (byte b: data) {
-            sb.append(HEX_DIGITS[(b >> 4) & 0x0f]);
-            sb.append(HEX_DIGITS[b & 0x0f]);
-        }
-        return sb.toString();
-    }
-}
diff --git a/platform/src/main/java/org/conscrypt/ct/CTPolicyImpl.java b/platform/src/main/java/org/conscrypt/ct/CTPolicyImpl.java
deleted file mode 100644
index 3faca6f7..00000000
--- a/platform/src/main/java/org/conscrypt/ct/CTPolicyImpl.java
+++ /dev/null
@@ -1,47 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package org.conscrypt.ct;
-
-import java.security.cert.X509Certificate;
-import java.util.HashSet;
-import java.util.Set;
-import org.conscrypt.Internal;
-
-@Internal
-public class CTPolicyImpl implements CTPolicy {
-    private final CTLogStore logStore;
-    private final int minimumLogCount;
-
-    public CTPolicyImpl(CTLogStore logStore, int minimumLogCount) {
-        this.logStore = logStore;
-        this.minimumLogCount = minimumLogCount;
-    }
-
-    @Override
-    public boolean doesResultConformToPolicy(CTVerificationResult result, String hostname,
-                                             X509Certificate[] chain) {
-        Set<CTLogInfo> logSet = new HashSet<>();
-        for (VerifiedSCT verifiedSCT: result.getValidSCTs()) {
-            CTLogInfo log = logStore.getKnownLog(verifiedSCT.sct.getLogID());
-            if (log != null) {
-                logSet.add(log);
-            }
-        }
-
-        return logSet.size() >= minimumLogCount;
-    }
-}
diff --git a/platform/src/main/java/org/conscrypt/ct/KnownLogs.java b/platform/src/main/java/org/conscrypt/ct/KnownLogs.java
deleted file mode 100644
index dba00cb6..00000000
--- a/platform/src/main/java/org/conscrypt/ct/KnownLogs.java
+++ /dev/null
@@ -1,134 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-/* This file is generated by print_log_list.py
- * https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py */
-
-package org.conscrypt.ct;
-
-import org.conscrypt.Internal;
-
-@Internal
-public final class KnownLogs {
-    public static final int LOG_COUNT = 8;
-    public static final String[] LOG_DESCRIPTIONS = new String[] {
-        "Google 'Pilot' log",
-        "Google 'Aviator' log",
-        "DigiCert Log Server",
-        "Google 'Rocketeer' log",
-        "Certly.IO log",
-        "Izenpe log",
-        "Symantec log",
-        "Venafi log",
-    };
-    public static final String[] LOG_URLS = new String[] {
-        "ct.googleapis.com/pilot",
-        "ct.googleapis.com/aviator",
-        "ct1.digicert-ct.com/log",
-        "ct.googleapis.com/rocketeer",
-        "log.certly.io",
-        "ct.izenpe.com",
-        "ct.ws.symantec.com",
-        "ctlog.api.venafi.com",
-    };
-    public static final byte[][] LOG_KEYS = new byte[][] {
-        // Google 'Pilot' log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 125, -88, 75, 18, 41, -128, -93, 61, -83,
-            -45, 90, 119, -72, -52, -30, -120, -77, -91, -3, -15, -45, 12, -51, 24,
-            12, -24, 65, 70, -24, -127, 1, 27, 21, -31, 75, -15, 27, 98, -35, 54, 10,
-            8, 24, -70, -19, 11, 53, -124, -48, -98, 64, 60, 45, -98, -101, -126,
-            101, -67, 31, 4, 16, 65, 76, -96
-        },
-        // Google 'Aviator' log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, -41, -12, -52, 105, -78, -28, 14, -112,
-            -93, -118, -22, 90, 112, 9, 79, -17, 19, 98, -48, -115, 73, 96, -1, 27,
-            64, 80, 7, 12, 109, 113, -122, -38, 37, 73, -115, 101, -31, 8, 13, 71,
-            52, 107, -67, 39, -68, -106, 33, 62, 52, -11, -121, 118, 49, -79, 127,
-            29, -55, -123, 59, 13, -9, 31, 63, -23
-        },
-        // DigiCert Log Server
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 2, 70, -59, -66, 27, -69, -126, 64, 22,
-            -24, -63, -46, -84, 25, 105, 19, 89, -8, -8, 112, -123, 70, 64, -71, 56,
-            -80, 35, -126, -88, 100, 76, 127, -65, -69, 52, -97, 74, 95, 40, -118,
-            -49, 25, -60, 0, -10, 54, 6, -109, 101, -19, 76, -11, -87, 33, 98, 90,
-            -40, -111, -21, 56, 36, 64, -84, -24
-        },
-        // Google 'Rocketeer' log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 32, 91, 24, -56, 60, -63, -117, -77, 49,
-            8, 0, -65, -96, -112, 87, 43, -73, 71, -116, 111, -75, 104, -80, -114,
-            -112, 120, -23, -96, 115, -22, 79, 40, 33, 46, -100, -64, -12, 22, 27,
-            -86, -7, -43, -41, -87, -128, -61, 78, 47, 82, 60, -104, 1, 37, 70, 36,
-            37, 40, 35, 119, 45, 5, -62, 64, 122
-        },
-        // Certly.IO log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 11, 35, -53, -123, 98, -104, 97, 72, 4,
-            115, -21, 84, 93, -13, -48, 7, -116, 45, 25, 45, -116, 54, -11, -21,
-            -113, 1, 66, 10, 124, -104, 38, 39, -63, -75, -35, -110, -109, -80, -82,
-            -8, -101, 61, 12, -40, 76, 78, 29, -7, 21, -5, 71, 104, 123, -70, 102,
-            -73, 37, -100, -48, 74, -62, 102, -37, 72
-        },
-        // Izenpe log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 39, 100, 57, 12, 45, -36, 80, 24, -8, 33,
-            0, -94, 14, -19, 44, -22, 62, 117, -70, -97, -109, 100, 9, 0, 17, -60,
-            17, 23, -85, 92, -49, 15, 116, -84, -75, -105, -112, -109, 0, 91, -72,
-            -21, -9, 39, 61, -39, -78, 10, -127, 95, 47, 13, 117, 56, -108, 55, -103,
-            30, -10, 7, 118, -32, -18, -66
-        },
-        // Symantec log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, -106, -22, -84, 28, 70, 12, 27, 85, -36,
-            13, -4, -75, -108, 39, 70, 87, 66, 112, 58, 105, 24, -30, -65, 59, -60,
-            -37, -85, -96, -12, -74, 108, -64, 83, 63, 77, 66, 16, 51, -16, 88, -105,
-            -113, 107, -66, 114, -12, 42, -20, 28, 66, -86, 3, 47, 26, 126, 40, 53,
-            118, -103, 8, 61, 33, 20, -122
-        },
-        // Venafi log
-        new byte[] {
-            48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0,
-            3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -94, 90, 72, 31,
-            23, 82, -107, 53, -53, -93, 91, 58, 31, 83, -126, 118, -108, -93, -1,
-            -128, -14, 28, 55, 60, -64, -79, -67, -63, 89, -117, -85, 45, 101, -109,
-            -41, -13, -32, 4, -43, -102, 111, -65, -42, 35, 118, 54, 79, 35, -103,
-            -53, 84, 40, -83, -116, 21, 75, 101, 89, 118, 65, 74, -100, -90, -9, -77,
-            59, 126, -79, -91, 73, -92, 23, 81, 108, -128, -36, 42, -112, 80, 75,
-            -120, 36, -23, -91, 18, 50, -109, 4, 72, -112, 2, -6, 95, 14, 48, -121,
-            -114, 85, 118, 5, -18, 42, 76, -50, -93, 106, 105, 9, 110, 37, -83, -126,
-            118, 15, -124, -110, -6, 56, -42, -122, 78, 36, -113, -101, -80, 114,
-            -53, -98, -30, 107, 63, -31, 109, -55, 37, 117, 35, -120, -95, 24, 88, 6,
-            35, 51, 120, -38, 0, -48, 56, -111, 103, -46, -90, 125, 39, -105, 103,
-            90, -63, -13, 47, 23, -26, -22, -46, 91, -24, -127, -51, -3, -110, 104,
-            -25, -13, 6, -16, -23, 114, -124, -18, 1, -91, -79, -40, 51, -38, -50,
-            -125, -91, -37, -57, -49, -42, 22, 126, -112, 117, 24, -65, 22, -36, 50,
-            59, 109, -115, -85, -126, 23, 31, -119, 32, -115, 29, -102, -26, 77, 35,
-            8, -33, 120, 111, -58, 5, -65, 95, -82, -108, -105, -37, 95, 100, -44,
-            -18, 22, -117, -93, -124, 108, 113, 43, -15, -85, 127, 93, 13, 50, -18,
-            4, -30, -112, -20, 65, -97, -5, 57, -63, 2, 3, 1, 0, 1
-        },
-    };
-}
diff --git a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
new file mode 100644
index 00000000..b7141d4c
--- /dev/null
+++ b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
@@ -0,0 +1,231 @@
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
+package org.conscrypt.ct;
+
+import static java.nio.charset.StandardCharsets.US_ASCII;
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import org.conscrypt.ByteArray;
+import org.conscrypt.Internal;
+import org.conscrypt.OpenSSLKey;
+import org.json.JSONArray;
+import org.json.JSONException;
+import org.json.JSONObject;
+
+import java.io.ByteArrayInputStream;
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.NoSuchFileException;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.security.PublicKey;
+import java.text.DateFormat;
+import java.text.ParseException;
+import java.text.SimpleDateFormat;
+import java.util.Arrays;
+import java.util.Base64;
+import java.util.Collections;
+import java.util.Date;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.logging.Level;
+import java.util.logging.Logger;
+
+@Internal
+public class LogStoreImpl implements LogStore {
+    private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
+    public static final String V3_PATH = "/misc/keychain/ct/v3/log_list.json";
+    private static final Path defaultLogList;
+
+    static {
+        String ANDROID_DATA = System.getenv("ANDROID_DATA");
+        defaultLogList = Paths.get(ANDROID_DATA, V3_PATH);
+    }
+
+    private final Path logList;
+    private State state;
+    private Policy policy;
+    private String version;
+    private long timestamp;
+    private Map<ByteArray, LogInfo> logs;
+
+    public LogStoreImpl() {
+        this(defaultLogList);
+    }
+
+    public LogStoreImpl(Path logList) {
+        this.state = State.UNINITIALIZED;
+        this.logList = logList;
+    }
+
+    @Override
+    public State getState() {
+        ensureLogListIsLoaded();
+        return state;
+    }
+
+    @Override
+    public long getTimestamp() {
+        return timestamp;
+    }
+
+    @Override
+    public void setPolicy(Policy policy) {
+        this.policy = policy;
+    }
+
+    @Override
+    public LogInfo getKnownLog(byte[] logId) {
+        if (logId == null) {
+            return null;
+        }
+        if (!ensureLogListIsLoaded()) {
+            return null;
+        }
+        ByteArray buf = new ByteArray(logId);
+        LogInfo log = logs.get(buf);
+        if (log != null) {
+            return log;
+        }
+        return null;
+    }
+
+    /* Ensures the log list is loaded.
+     * Returns true if the log list is usable.
+     */
+    private boolean ensureLogListIsLoaded() {
+        synchronized (this) {
+            if (state == State.UNINITIALIZED) {
+                state = loadLogList();
+            }
+            if (state == State.LOADED && policy != null) {
+                state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
+            }
+            return state == State.COMPLIANT;
+        }
+    }
+
+    private State loadLogList() {
+        byte[] content;
+        try {
+            content = Files.readAllBytes(logList);
+        } catch (IOException e) {
+            return State.NOT_FOUND;
+        }
+        if (content == null) {
+            return State.NOT_FOUND;
+        }
+        JSONObject json;
+        try {
+            json = new JSONObject(new String(content, UTF_8));
+        } catch (JSONException e) {
+            logger.log(Level.WARNING, "Unable to parse log list", e);
+            return State.MALFORMED;
+        }
+        HashMap<ByteArray, LogInfo> logsMap = new HashMap<>();
+        try {
+            version = json.getString("version");
+            timestamp = parseTimestamp(json.getString("log_list_timestamp"));
+            JSONArray operators = json.getJSONArray("operators");
+            for (int i = 0; i < operators.length(); i++) {
+                JSONObject operator = operators.getJSONObject(i);
+                String operatorName = operator.getString("name");
+                JSONArray logs = operator.getJSONArray("logs");
+                for (int j = 0; j < logs.length(); j++) {
+                    JSONObject log = logs.getJSONObject(j);
+
+                    LogInfo.Builder builder =
+                            new LogInfo.Builder()
+                                    .setDescription(log.getString("description"))
+                                    .setPublicKey(parsePubKey(log.getString("key")))
+                                    .setUrl(log.getString("url"))
+                                    .setOperator(operatorName);
+
+                    JSONObject stateObject = log.optJSONObject("state");
+                    if (stateObject != null) {
+                        String state = stateObject.keys().next();
+                        String stateTimestamp =
+                                stateObject.getJSONObject(state).getString("timestamp");
+                        builder.setState(parseState(state), parseTimestamp(stateTimestamp));
+                    }
+
+                    LogInfo logInfo = builder.build();
+                    byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
+
+                    // The logId computed using the public key should match the log_id field.
+                    if (!Arrays.equals(logInfo.getID(), logId)) {
+                        throw new IllegalArgumentException("logId does not match publicKey");
+                    }
+
+                    logsMap.put(new ByteArray(logId), logInfo);
+                }
+            }
+        } catch (JSONException | IllegalArgumentException e) {
+            logger.log(Level.WARNING, "Unable to parse log list", e);
+            return State.MALFORMED;
+        }
+        this.logs = Collections.unmodifiableMap(logsMap);
+        return State.LOADED;
+    }
+
+    private static int parseState(String state) {
+        switch (state) {
+            case "pending":
+                return LogInfo.STATE_PENDING;
+            case "qualified":
+                return LogInfo.STATE_QUALIFIED;
+            case "usable":
+                return LogInfo.STATE_USABLE;
+            case "readonly":
+                return LogInfo.STATE_READONLY;
+            case "retired":
+                return LogInfo.STATE_RETIRED;
+            case "rejected":
+                return LogInfo.STATE_REJECTED;
+            default:
+                throw new IllegalArgumentException("Unknown log state: " + state);
+        }
+    }
+
+    // ISO 8601
+    private static DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
+
+    @SuppressWarnings("JavaUtilDate")
+    private static long parseTimestamp(String timestamp) {
+        try {
+            Date date = dateFormatter.parse(timestamp);
+            return date.getTime();
+        } catch (ParseException e) {
+            throw new IllegalArgumentException(e);
+        }
+    }
+
+    private static PublicKey parsePubKey(String key) {
+        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----")
+                             .getBytes(US_ASCII);
+        PublicKey pubkey;
+        try {
+            pubkey = OpenSSLKey.fromPublicKeyPemInputStream(new ByteArrayInputStream(pem))
+                             .getPublicKey();
+        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
+            throw new IllegalArgumentException(e);
+        }
+        return pubkey;
+    }
+}
diff --git a/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java b/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
new file mode 100644
index 00000000..8bcd4633
--- /dev/null
+++ b/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
@@ -0,0 +1,188 @@
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
+package org.conscrypt.ct;
+
+import org.conscrypt.Internal;
+
+import java.security.cert.X509Certificate;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.HashSet;
+import java.util.Iterator;
+import java.util.List;
+import java.util.Set;
+import java.util.concurrent.TimeUnit;
+
+@Internal
+public class PolicyImpl implements Policy {
+    @Override
+    public boolean isLogStoreCompliant(LogStore store) {
+        long now = System.currentTimeMillis();
+        return isLogStoreCompliantAt(store, now);
+    }
+
+    public boolean isLogStoreCompliantAt(LogStore store, long atTime) {
+        long storeTimestamp = store.getTimestamp();
+        long seventyDaysInMs = 70L * 24 * 60 * 60 * 1000;
+        if (storeTimestamp + seventyDaysInMs < atTime) {
+            // Expired log list.
+            return false;
+        } else if (storeTimestamp > atTime) {
+            // Log list from the future. It is likely that the device has an
+            // incorrect time.
+            return false;
+        }
+        return true;
+    }
+
+    @Override
+    public PolicyCompliance doesResultConformToPolicy(
+            VerificationResult result, X509Certificate leaf) {
+        long now = System.currentTimeMillis();
+        return doesResultConformToPolicyAt(result, leaf, now);
+    }
+
+    public PolicyCompliance doesResultConformToPolicyAt(
+            VerificationResult result, X509Certificate leaf, long atTime) {
+        List<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>(result.getValidSCTs());
+        /* While the log list supports logs without a state, these entries are
+         * not supported by the log policy. Filter them out. */
+        filterOutUnknown(validSCTs);
+        /* Filter out any SCT issued after a log was retired */
+        filterOutAfterRetired(validSCTs);
+
+        Set<VerifiedSCT> embeddedValidSCTs = new HashSet<>();
+        Set<VerifiedSCT> ocspOrTLSValidSCTs = new HashSet<>();
+        for (VerifiedSCT vsct : validSCTs) {
+            if (vsct.getSct().getOrigin() == SignedCertificateTimestamp.Origin.EMBEDDED) {
+                embeddedValidSCTs.add(vsct);
+            } else {
+                ocspOrTLSValidSCTs.add(vsct);
+            }
+        }
+        if (embeddedValidSCTs.size() > 0) {
+            return conformEmbeddedSCTs(embeddedValidSCTs, leaf, atTime);
+        }
+        return PolicyCompliance.NOT_ENOUGH_SCTS;
+    }
+
+    private void filterOutUnknown(List<VerifiedSCT> scts) {
+        Iterator<VerifiedSCT> it = scts.iterator();
+        while (it.hasNext()) {
+            VerifiedSCT vsct = it.next();
+            if (vsct.getLogInfo().getState() == LogInfo.STATE_UNKNOWN) {
+                it.remove();
+            }
+        }
+    }
+
+    private void filterOutAfterRetired(List<VerifiedSCT> scts) {
+        /* From the policy:
+         *
+         * In order to contribute to a certificate’s CT Compliance, an SCT must
+         * have been issued before the Log’s Retired timestamp, if one exists.
+         * Chrome uses the earliest SCT among all SCTs presented to evaluate CT
+         * compliance against CT Log Retired timestamps. This accounts for edge
+         * cases in which a CT Log becomes Retired during the process of
+         * submitting certificate logging requests.
+         */
+
+        if (scts.size() < 1) {
+            return;
+        }
+        long minTimestamp = scts.get(0).getSct().getTimestamp();
+        for (VerifiedSCT vsct : scts) {
+            long ts = vsct.getSct().getTimestamp();
+            if (ts < minTimestamp) {
+                minTimestamp = ts;
+            }
+        }
+        Iterator<VerifiedSCT> it = scts.iterator();
+        while (it.hasNext()) {
+            VerifiedSCT vsct = it.next();
+            if (vsct.getLogInfo().getState() == LogInfo.STATE_RETIRED
+                    && minTimestamp > vsct.getLogInfo().getStateTimestamp()) {
+                it.remove();
+            }
+        }
+    }
+
+    private PolicyCompliance conformEmbeddedSCTs(
+            Set<VerifiedSCT> embeddedValidSCTs, X509Certificate leaf, long atTime) {
+        /* 1. At least one Embedded SCT from a CT Log that was Qualified,
+         *    Usable, or ReadOnly at the time of check;
+         */
+        boolean found = false;
+        for (VerifiedSCT vsct : embeddedValidSCTs) {
+            LogInfo log = vsct.getLogInfo();
+            switch (log.getStateAt(atTime)) {
+                case LogInfo.STATE_QUALIFIED:
+                case LogInfo.STATE_USABLE:
+                case LogInfo.STATE_READONLY:
+                    found = true;
+            }
+        }
+        if (!found) {
+            return PolicyCompliance.NOT_ENOUGH_SCTS;
+        }
+
+        /* 2. There are Embedded SCTs from at least N distinct CT Logs that
+         *    were Qualified, Usable, ReadOnly, or Retired at the time of check,
+         *    where N is defined in the following table;
+         *
+         *    Certificate Lifetime    Number of SCTs from distinct CT Logs
+         *         <= 180 days                        2
+         *          > 180 days                        3
+         */
+        Set<LogInfo> validLogs = new HashSet<>();
+        int numberSCTsRequired;
+        long certLifetimeMs = leaf.getNotAfter().getTime() - leaf.getNotBefore().getTime();
+        long certLifetimeDays = TimeUnit.DAYS.convert(certLifetimeMs, TimeUnit.MILLISECONDS);
+        if (certLifetimeDays <= 180) {
+            numberSCTsRequired = 2;
+        } else {
+            numberSCTsRequired = 3;
+        }
+        for (VerifiedSCT vsct : embeddedValidSCTs) {
+            LogInfo log = vsct.getLogInfo();
+            switch (log.getStateAt(atTime)) {
+                case LogInfo.STATE_QUALIFIED:
+                case LogInfo.STATE_USABLE:
+                case LogInfo.STATE_READONLY:
+                case LogInfo.STATE_RETIRED:
+                    validLogs.add(log);
+            }
+        }
+        if (validLogs.size() < numberSCTsRequired) {
+            return PolicyCompliance.NOT_ENOUGH_SCTS;
+        }
+
+        /* 3. Among the SCTs satisfying requirements 1 and 2, at least two SCTs
+         *    must be issued from distinct CT Log Operators as recognized by
+         *    Chrome.
+         */
+        Set<String> operators = new HashSet<>();
+        for (LogInfo logInfo : validLogs) {
+            operators.add(logInfo.getOperator());
+        }
+        if (operators.size() < 2) {
+            return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
+        }
+
+        return PolicyCompliance.COMPLY;
+    }
+}
diff --git a/platform/src/test/java/org/conscrypt/ct/CTLogStoreImplTest.java b/platform/src/test/java/org/conscrypt/ct/CTLogStoreImplTest.java
deleted file mode 100644
index f95a3e67..00000000
--- a/platform/src/test/java/org/conscrypt/ct/CTLogStoreImplTest.java
+++ /dev/null
@@ -1,204 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package org.conscrypt.ct;
-
-import static java.nio.charset.StandardCharsets.UTF_8;
-
-import java.io.BufferedWriter;
-import java.io.ByteArrayInputStream;
-import java.io.File;
-import java.io.FileNotFoundException;
-import java.io.FileOutputStream;
-import java.io.IOException;
-import java.io.OutputStreamWriter;
-import java.io.PrintWriter;
-import java.nio.charset.StandardCharsets;
-import java.security.PublicKey;
-import junit.framework.TestCase;
-import org.conscrypt.InternalUtil;
-
-public class CTLogStoreImplTest extends TestCase {
-    private static final String[] LOG_KEYS = new String[] {
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3U" +
-        "yEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErEULmlBnX9L/+AK20hLYzPMFozYx" +
-        "pP0Wm1ylqGkPEwuDKn9DSpNSOym49SN77BLGuAXu9twOW/qT+ddIYVBEIw==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP6PGcXmjlyCBz2ZFUuUjrgbZLaEF" +
-        "gfLUkt2cEqlSbb4vTuB6WWmgC9h0L6PN6JF0CPcajpBKGlTI15242a8d4g==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER3qB0NADsP1szXxe4EagrD/ryPVh" +
-        "Y/azWbKyXcK12zhXnO8WH2U4QROVUMctFXLflIzw0EivdRN9t7UH1Od30w==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY0ww9JqeJvzVtKNTPVb3JZa7s0ZV" +
-        "duH3PpshpMS5XVoPRSjSQCph6f3HjUcM3c4N2hpa8OFbrFFy37ttUrgD+A=="
-    };
-    private static final String[] LOG_FILENAMES = new String[] {
-        "df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d764",
-        "84f8ae3f613b13407a75fa2893b93ab03b18d86c455fe7c241ae020033216446",
-        "89baa01a445100009d8f9a238947115b30702275aafee675a7d94b6b09287619",
-        "57456bffe268e49a190dce4318456034c2b4958f3c0201bed5a366737d1e74ca",
-        "896c898ced4b8e6547fa351266caae4ca304f1c1ec2b623c2ee259c5452147b0"
-    };
-
-    private static final CTLogInfo[] LOGS;
-    private static final String[] LOGS_SERIALIZED;
-
-    static {
-        try {
-            int logCount = LOG_KEYS.length;
-            LOGS = new CTLogInfo[logCount];
-            LOGS_SERIALIZED = new String[logCount];
-            for (int i = 0; i < logCount; i++) {
-                PublicKey key = InternalUtil.readPublicKeyPem(new ByteArrayInputStream(
-                    ("-----BEGIN PUBLIC KEY-----\n" +
-                     LOG_KEYS[i] + "\n" +
-                     "-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII)));
-                String description = String.format("Test Log %d", i);
-                String url = String.format("log%d.example.com", i);
-                LOGS[i] = new CTLogInfo(key, description, url);
-                LOGS_SERIALIZED[i] = String.format("description:%s\nurl:%s\nkey:%s",
-                    description, url, LOG_KEYS[i]);
-            }
-        } catch (Exception e) {
-            throw new RuntimeException(e);
-        }
-    }
-
-    /* CTLogStoreImpl loads the list of logs lazily when they are first needed
-     * to avoid any overhead when CT is disabled.
-     * This test simply forces the logs to be loaded to make sure it doesn't
-     * fail, as all of the other tests use a different log store.
-     */
-    public void test_getDefaultFallbackLogs() {
-        CTLogInfo[] knownLogs = CTLogStoreImpl.getDefaultFallbackLogs();
-        assertEquals(KnownLogs.LOG_COUNT, knownLogs.length);
-    }
-
-    public void test_loadLog() throws Exception {
-        CTLogInfo log = CTLogStoreImpl.loadLog(
-                new ByteArrayInputStream(LOGS_SERIALIZED[0].getBytes(StandardCharsets.US_ASCII)));
-        assertEquals(LOGS[0], log);
-
-        File testFile = writeFile(LOGS_SERIALIZED[0]);
-        log = CTLogStoreImpl.loadLog(testFile);
-        assertEquals(LOGS[0], log);
-
-        // Empty log file, used to mask fallback logs
-        assertEquals(null, CTLogStoreImpl.loadLog(new ByteArrayInputStream(new byte[0])));
-        try {
-            CTLogStoreImpl.loadLog(new ByteArrayInputStream(
-                    "randomgarbage".getBytes(StandardCharsets.US_ASCII)));
-            fail("InvalidLogFileException not thrown");
-        } catch (CTLogStoreImpl.InvalidLogFileException e) {}
-
-        try {
-            CTLogStoreImpl.loadLog(new File("/nonexistent"));
-            fail("FileNotFoundException not thrown");
-        } catch (FileNotFoundException e) {}
-    }
-
-    public void test_getKnownLog() throws Exception {
-        File userDir = createTempDirectory();
-        userDir.deleteOnExit();
-
-        File systemDir = createTempDirectory();
-        systemDir.deleteOnExit();
-
-        CTLogInfo[] fallback = new CTLogInfo[] { LOGS[2], LOGS[3] };
-
-        CTLogStore store = new CTLogStoreImpl(userDir, systemDir, fallback);
-
-        /* Add logs 0 and 1 to the user and system directories respectively
-         * Log 2 & 3 are part of the fallbacks
-         * But mask log 3 with an empty file in the user directory.
-         * Log 4 is not in the store
-         */
-        File log0File = new File(userDir, LOG_FILENAMES[0]);
-        File log1File = new File(systemDir, LOG_FILENAMES[1]);
-        File log3File = new File(userDir, LOG_FILENAMES[3]);
-        File log4File = new File(userDir, LOG_FILENAMES[4]);
-
-        writeFile(log0File, LOGS_SERIALIZED[0]);
-        writeFile(log1File, LOGS_SERIALIZED[1]);
-        writeFile(log3File, "");
-
-        // Logs 01 are present, log 2 is in the fallback and unused, log 3 is present but masked,
-        // log 4 is missing
-        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
-        assertEquals(LOGS[1], store.getKnownLog(LOGS[1].getID()));
-        // Fallback logs are not used if the userDir is present.
-        assertEquals(null, store.getKnownLog(LOGS[2].getID()));
-        assertEquals(null, store.getKnownLog(LOGS[3].getID()));
-        assertEquals(null, store.getKnownLog(LOGS[4].getID()));
-
-        /* Test whether CTLogStoreImpl caches properly
-         * Modify the files on the disk, the result of the store should not change
-         * Delete log 0, mask log 1, add log 4
-         */
-        log0File.delete();
-        writeFile(log1File, "");
-        writeFile(log4File, LOGS_SERIALIZED[4]);
-
-        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
-        assertEquals(LOGS[1], store.getKnownLog(LOGS[1].getID()));
-        assertEquals(null, store.getKnownLog(LOGS[4].getID()));
-
-        // Test that fallback logs are used when the userDir doesn't exist.
-        File doesntExist = new File("/doesnt/exist/");
-        store = new CTLogStoreImpl(doesntExist, doesntExist, fallback);
-        assertEquals(LOGS[2], store.getKnownLog(LOGS[2].getID()));
-        assertEquals(LOGS[3], store.getKnownLog(LOGS[3].getID()));
-    }
-
-    /**
-     * Create a temporary file and write to it.
-     * The file will be deleted on exit.
-     * @param contents The data to be written to the file
-     * @return A reference to the temporary file
-     */
-    private File writeFile(String contents) throws IOException {
-        File file = File.createTempFile("test", null);
-        file.deleteOnExit();
-        writeFile(file, contents);
-        return file;
-    }
-
-    private static void writeFile(File file, String contents) throws FileNotFoundException {
-        PrintWriter writer = new PrintWriter(
-                new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), UTF_8)),
-                false);
-        try {
-            writer.write(contents);
-        } finally {
-            writer.close();
-        }
-    }
-
-    /*
-     * This is NOT safe, as another process could create a file between delete() and mkdir()
-     * It should be fine for tests though
-     */
-    private static File createTempDirectory() throws IOException {
-        File folder = File.createTempFile("test", "");
-        folder.delete();
-        folder.mkdir();
-        return folder;
-    }
-}
-
diff --git a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
new file mode 100644
index 00000000..e2ec155f
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
@@ -0,0 +1,151 @@
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
+package org.conscrypt.ct;
+
+import static java.nio.charset.StandardCharsets.US_ASCII;
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
+import junit.framework.TestCase;
+
+import org.conscrypt.OpenSSLKey;
+
+import java.io.ByteArrayInputStream;
+import java.io.File;
+import java.io.FileNotFoundException;
+import java.io.FileOutputStream;
+import java.io.FileWriter;
+import java.io.IOException;
+import java.io.OutputStreamWriter;
+import java.io.PrintWriter;
+import java.security.PublicKey;
+import java.util.Base64;
+
+public class LogStoreImplTest extends TestCase {
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void test_loadLogList() throws Exception {
+        // clang-format off
+        String content = "" +
+"{" +
+"  \"version\": \"1.1\"," +
+"  \"log_list_timestamp\": \"2024-01-01T11:55:12Z\"," +
+"  \"operators\": [" +
+"    {" +
+"      \"name\": \"Operator 1\"," +
+"      \"email\": [\"ct@operator1.com\"]," +
+"      \"logs\": [" +
+"        {" +
+"          \"description\": \"Operator 1 'Test2024' log\"," +
+"          \"log_id\": \"7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA==\"," +
+"          \"url\": \"https://operator1.example.com/logs/test2024/\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": \"2022-11-01T18:54:00Z\"" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
+"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"          }" +
+"        }," +
+"        {" +
+"          \"description\": \"Operator 1 'Test2025' log\"," +
+"          \"log_id\": \"TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqOTblJji4WiH5AltIDUzODyvFKrXCBjw/Rab0/98J4LUh7dOJEY7+66+yCNSICuqRAX+VPnV8R1Fmg==\"," +
+"          \"url\": \"https://operator1.example.com/logs/test2025/\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": \"2023-11-26T12:00:00Z\"" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": \"2025-01-01T00:00:00Z\"," +
+"            \"end_exclusive\": \"2025-07-01T00:00:00Z\"" +
+"          }" +
+"        }" +
+"      ]" +
+"    }," +
+"    {" +
+"      \"name\": \"Operator 2\"," +
+"      \"email\": [\"ct@operator2.com\"]," +
+"      \"logs\": [" +
+"        {" +
+"          \"description\": \"Operator 2 'Test2024' Log\"," +
+"          \"log_id\": \"2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe4/mizX+OpIpLayKjVGKJfyTttegiyk3cR0zyswz6ii5H+Ksw6ld3Ze+9p6UJd02gdHrXSnDK0TxW8oVSA==\"," +
+"          \"url\": \"https://operator2.example.com/logs/test2024/\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": \"2022-11-30T17:00:00Z\"" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
+"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"          }" +
+"        }" +
+"      ]" +
+"    }" +
+"  ]" +
+"}";
+        // clang-format on
+
+        File logList = writeFile(content);
+        LogStore store = new LogStoreImpl(logList.toPath());
+        store.setPolicy(new PolicyImpl() {
+            @Override
+            public boolean isLogStoreCompliant(LogStore store) {
+                return true;
+            }
+        });
+
+        assertNull("A null logId should return null", store.getKnownLog(null));
+
+        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
+                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
+                + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
+                + "\n-----END PUBLIC KEY-----\n")
+                             .getBytes(US_ASCII);
+        ByteArrayInputStream is = new ByteArrayInputStream(pem);
+
+        LogInfo log1 =
+                new LogInfo.Builder()
+                        .setPublicKey(OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey())
+                        .setDescription("Operator 1 'Test2024' log")
+                        .setUrl("https://operator1.example.com/logs/test2024/")
+                        .setState(LogInfo.STATE_USABLE, 1667328840000L)
+                        .setOperator("Operator 1")
+                        .build();
+        byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
+        assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
+    }
+
+    private File writeFile(String content) throws IOException {
+        File file = File.createTempFile("test", null);
+        file.deleteOnExit();
+        try (FileWriter fw = new FileWriter(file)) {
+            fw.write(content);
+        }
+        return file;
+    }
+}
diff --git a/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java b/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
new file mode 100644
index 00000000..f023615d
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
@@ -0,0 +1,326 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package org.conscrypt.ct;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
+import org.conscrypt.java.security.cert.FakeX509Certificate;
+import org.junit.Assume;
+import org.junit.BeforeClass;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.PublicKey;
+import java.security.cert.X509Certificate;
+
+@RunWith(JUnit4.class)
+public class PolicyImplTest {
+    private static final String OPERATOR1 = "operator 1";
+    private static final String OPERATOR2 = "operator 2";
+    private static LogInfo usableOp1Log1;
+    private static LogInfo usableOp1Log2;
+    private static LogInfo retiredOp1LogOld;
+    private static LogInfo retiredOp1LogNew;
+    private static LogInfo usableOp2Log;
+    private static LogInfo retiredOp2Log;
+    private static SignedCertificateTimestamp embeddedSCT;
+
+    /* Some test dates. By default:
+     *  - The verification is occurring in January 2024;
+     *  - The log list was created in December 2023;
+     *  - The SCTs were generated in January 2023; and
+     *  - The logs got into their state in January 2022.
+     * Other dates are used to exercise edge cases.
+     */
+    private static final long JAN2025 = 1735725600000L;
+    private static final long JAN2024 = 1704103200000L;
+    private static final long DEC2023 = 1701424800000L;
+    private static final long JUN2023 = 1672999200000L;
+    private static final long JAN2023 = 1672567200000L;
+    private static final long JAN2022 = 1641031200000L;
+
+    private static class FakePublicKey implements PublicKey {
+        static final long serialVersionUID = 1;
+        final byte[] key;
+
+        FakePublicKey(byte[] key) {
+            this.key = key;
+        }
+
+        @Override
+        public byte[] getEncoded() {
+            return this.key;
+        }
+
+        @Override
+        public String getAlgorithm() {
+            return "";
+        }
+
+        @Override
+        public String getFormat() {
+            return "";
+        }
+    }
+
+    @BeforeClass
+    public static void setUp() {
+        /* Defines LogInfo for the tests. Only a subset of the attributes are
+         * expected to be used, namely the LogID (based on the public key), the
+         * operator name and the log state.
+         */
+        usableOp1Log1 = new LogInfo.Builder()
+                                .setPublicKey(new FakePublicKey(new byte[] {0x01}))
+                                .setUrl("")
+                                .setOperator(OPERATOR1)
+                                .setState(LogInfo.STATE_USABLE, JAN2022)
+                                .build();
+        usableOp1Log2 = new LogInfo.Builder()
+                                .setPublicKey(new FakePublicKey(new byte[] {0x02}))
+                                .setUrl("")
+                                .setOperator(OPERATOR1)
+                                .setState(LogInfo.STATE_USABLE, JAN2022)
+                                .build();
+        retiredOp1LogOld = new LogInfo.Builder()
+                                   .setPublicKey(new FakePublicKey(new byte[] {0x03}))
+                                   .setUrl("")
+                                   .setOperator(OPERATOR1)
+                                   .setState(LogInfo.STATE_RETIRED, JAN2022)
+                                   .build();
+        retiredOp1LogNew = new LogInfo.Builder()
+                                   .setPublicKey(new FakePublicKey(new byte[] {0x06}))
+                                   .setUrl("")
+                                   .setOperator(OPERATOR1)
+                                   .setState(LogInfo.STATE_RETIRED, JUN2023)
+                                   .build();
+        usableOp2Log = new LogInfo.Builder()
+                               .setPublicKey(new FakePublicKey(new byte[] {0x04}))
+                               .setUrl("")
+                               .setOperator(OPERATOR2)
+                               .setState(LogInfo.STATE_USABLE, JAN2022)
+                               .build();
+        retiredOp2Log = new LogInfo.Builder()
+                                .setPublicKey(new FakePublicKey(new byte[] {0x05}))
+                                .setUrl("")
+                                .setOperator(OPERATOR2)
+                                .setState(LogInfo.STATE_RETIRED, JAN2022)
+                                .build();
+        /* The origin of the SCT and its timestamp are used during the
+         * evaluation for policy compliance. The signature is validated at the
+         * previous step (see the Verifier class).
+         */
+        embeddedSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
+                JAN2023, null, null, SignedCertificateTimestamp.Origin.EMBEDDED);
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void emptyVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+        VerificationResult result = new VerificationResult();
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("An empty VerificationResult", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void validVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two valid SCTs from different operators", PolicyCompliance.COMPLY,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void validWithRetiredVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogNew)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid, one retired SCTs from different operators",
+                PolicyCompliance.COMPLY, p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    public void invalidWithRetiredVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogOld)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid, one retired (before SCT timestamp) SCTs from different operators",
+                PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidOneSctVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid SCT", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidTwoSctsVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogNew)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two retired SCTs from different operators", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidTwoSctsSameOperatorVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log2)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two SCTs from the same operator", PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void validRecentLogStore() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        LogStore store = new LogStoreImpl() {
+            @Override
+            public long getTimestamp() {
+                return DEC2023;
+            }
+        };
+        assertTrue("A recent log list is compliant", p.isLogStoreCompliantAt(store, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidFutureLogStore() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        LogStore store = new LogStoreImpl() {
+            @Override
+            public long getTimestamp() {
+                return JAN2025;
+            }
+        };
+        assertFalse("A future log list is non-compliant", p.isLogStoreCompliantAt(store, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidOldLogStore() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        LogStore store = new LogStoreImpl() {
+            @Override
+            public long getTimestamp() {
+                return JAN2023;
+            }
+        };
+        assertFalse("A expired log list is non-compliant", p.isLogStoreCompliantAt(store, JAN2024));
+    }
+}
diff --git a/publicapi/src/main/java/android/net/ssl/TEST_MAPPING b/publicapi/src/main/java/android/net/ssl/TEST_MAPPING
deleted file mode 100644
index 996e0e78..00000000
--- a/publicapi/src/main/java/android/net/ssl/TEST_MAPPING
+++ /dev/null
@@ -1,12 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "CtsLibcoreTestCases",
-      "options": [
-        {
-          "include-filter": "android.net.ssl"
-        }
-      ]
-    }
-  ]
-}
\ No newline at end of file
diff --git a/repackaged/benchmark-base/src/main/java/com/android/org/conscrypt/ServerSocketBenchmark.java b/repackaged/benchmark-base/src/main/java/com/android/org/conscrypt/ServerSocketBenchmark.java
index 03a97157..15860f2e 100644
--- a/repackaged/benchmark-base/src/main/java/com/android/org/conscrypt/ServerSocketBenchmark.java
+++ b/repackaged/benchmark-base/src/main/java/com/android/org/conscrypt/ServerSocketBenchmark.java
@@ -19,9 +19,11 @@ package com.android.org.conscrypt;
 
 import static com.android.org.conscrypt.TestUtils.getCommonProtocolSuites;
 import static com.android.org.conscrypt.TestUtils.newTextMessage;
+
 import static org.junit.Assert.assertEquals;
 
 import com.android.org.conscrypt.ServerEndpoint.MessageProcessor;
+
 import java.io.IOException;
 import java.io.OutputStream;
 import java.net.SocketException;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java
index ea6d9896..d601a509 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java
@@ -718,7 +718,8 @@ abstract class AbstractConscryptSocket extends SSLSocket {
     @android.compat.annotation.
     UnsupportedAppUsage(maxTargetSdk = dalvik.annotation.compat.VersionCodes.Q,
             publicAlternatives =
-                    "Use {@code javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
+                    "Use {@code "
+                    + "javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
     @Deprecated
     abstract void
     setAlpnProtocols(String[] alpnProtocols);
@@ -734,7 +735,8 @@ abstract class AbstractConscryptSocket extends SSLSocket {
     @android.compat.annotation.
     UnsupportedAppUsage(maxTargetSdk = dalvik.annotation.compat.VersionCodes.Q,
             publicAlternatives =
-                    "Use {@code javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
+                    "Use {@code "
+                    + "javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
     @Deprecated
     abstract void
     setAlpnProtocols(byte[] alpnProtocols);
@@ -747,7 +749,8 @@ abstract class AbstractConscryptSocket extends SSLSocket {
     @android.compat.annotation.
     UnsupportedAppUsage(maxTargetSdk = dalvik.annotation.compat.VersionCodes.Q,
             publicAlternatives =
-                    "Use {@code javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
+                    "Use {@code "
+                    + "javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
     @SuppressWarnings("MissingOverride") // For compiling pre Java 9.
     abstract void
     setApplicationProtocols(String[] protocols);
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
index 2a3857eb..58bedbcc 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
@@ -25,6 +25,7 @@ import java.util.Map;
 import java.util.NoSuchElementException;
 import java.util.concurrent.locks.ReadWriteLock;
 import java.util.concurrent.locks.ReentrantReadWriteLock;
+
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSessionContext;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AddressUtils.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AddressUtils.java
index bdd7c973..046e87d0 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AddressUtils.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AddressUtils.java
@@ -26,9 +26,25 @@ final class AddressUtils {
     /*
      * Regex that matches valid IPv4 and IPv6 addresses.
      */
-    private static final String IP_PATTERN =
-            "^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9]))|"
-            + "(?i:(?:(?:[0-9a-f]{1,4}:){7}(?:[0-9a-f]{1,4}|:))|(?:(?:[0-9a-f]{1,4}:){6}(?::[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(?:(?:[0-9a-f]{1,4}:){5}(?:(?:(?::[0-9a-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(?:(?:[0-9a-f]{1,4}:){4}(?:(?:(?::[0-9a-f]{1,4}){1,3})|(?:(?::[0-9a-f]{1,4})?:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(?:(?:[0-9a-f]{1,4}:){3}(?:(?:(?::[0-9a-f]{1,4}){1,4})|(?:(?::[0-9a-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(?:(?:[0-9a-f]{1,4}:){2}(?:(?:(?::[0-9a-f]{1,4}){1,5})|(?:(?::[0-9a-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(?:(?:[0-9a-f]{1,4}:){1}(?:(?:(?::[0-9a-f]{1,4}){1,6})|(?:(?::[0-9a-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(?::(?:(?:(?::[0-9a-f]{1,4}){1,7})|(?:(?::[0-9a-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(?:%.+)?$";
+    private static final String IP_PATTERN = "^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){"
+                                             + "3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9]))|"
+            + "(?i:(?:(?:[0-9a-f]{1,4}:){7}(?:[0-9a-f]{1,4}|:))|(?:(?:[0-9a-f]{1,4}:){6}(?::[0-9a-"
+              + "f]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4]["
+              + "0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(?:(?:[0-9a-f]{1,4}:){5}(?:(?:(?::[0-9a-f]{"
+              + "1,4}){1,2})|:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2["
+              + "0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(?:(?:[0-9a-f]{1,4}:){4}(?:(?:(?::[0-"
+              + "9a-f]{1,4}){1,3})|(?:(?::[0-9a-f]{1,4})?:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-"
+              + "9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(?:(?:[0-"
+              + "9a-f]{1,4}:){3}(?:(?:(?::[0-9a-f]{1,4}){1,4})|(?:(?::[0-9a-f]{1,4}){0,2}:(?:(?:25["
+              + "0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|"
+              + "[1-9]?[0-9])){3}))|:))|(?:(?:[0-9a-f]{1,4}:){2}(?:(?:(?::[0-9a-f]{1,4}){1,5})|(?:("
+              + "?::[0-9a-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:"
+              + "25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(?:(?:[0-9a-f]{1,4}:){1}(?:"
+              + "(?:(?::[0-9a-f]{1,4}){1,6})|(?:(?::[0-9a-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4][0-9]|"
+              + "1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})"
+              + ")|:))|(?::(?:(?:(?::[0-9a-f]{1,4}){1,7})|(?:(?::[0-9a-f]{1,4}){0,5}:(?:(?:25[0-5]|"
+              + "2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]"
+              + "?[0-9])){3}))|:)))(?:%.+)?$";
 
     private static Pattern ipPattern;
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java
index 0580889f..f1cd5bcc 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java
@@ -23,6 +23,7 @@ import java.util.Arrays;
  * Compatibility utility for Arrays.
  * @hide This class is not part of the Android public SDK API
  */
+@Internal
 public final class ArrayUtils {
     private ArrayUtils() {}
 
@@ -75,4 +76,11 @@ public final class ArrayUtils {
         }
         return result;
     }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static <T> boolean isEmpty(T[] array) {
+        return array == null || array.length == 0;
+    }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ByteArray.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ByteArray.java
index 6bd104d9..e6fb15d0 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ByteArray.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ByteArray.java
@@ -21,12 +21,14 @@ import java.util.Arrays;
 
 /**
  * Byte array wrapper for hashtable use. Implements equals() and hashCode().
+ * @hide This class is not part of the Android public SDK API
  */
-final class ByteArray {
+@Internal
+public final class ByteArray {
     private final byte[] bytes;
     private final int hashCode;
 
-    ByteArray(byte[] bytes) {
+    public ByteArray(byte[] bytes) {
         this.bytes = bytes;
         this.hashCode = Arrays.hashCode(bytes);
     }
@@ -38,6 +40,9 @@ final class ByteArray {
 
     @Override
     public boolean equals(Object o) {
+        if (o == this) {
+            return true;
+        }
         if (!(o instanceof ByteArray)) {
             return false;
         }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java b/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
index ba51136a..3013640c 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
@@ -17,6 +17,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.io.IoUtils;
+
 import java.io.IOException;
 import java.io.InputStream;
 import java.nio.ByteBuffer;
@@ -25,6 +26,7 @@ import java.security.PrivateKey;
 import java.security.Provider;
 import java.security.cert.X509Certificate;
 import java.util.Properties;
+
 import javax.net.ssl.HostnameVerifier;
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SSLContext;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java
index 46c03a9d..b8fc5193 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java
@@ -55,8 +55,10 @@ import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY;
 import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;
 import static com.android.org.conscrypt.SSLUtils.calculateOutNetBufSize;
 import static com.android.org.conscrypt.SSLUtils.toSSLHandshakeException;
+
 import static java.lang.Math.max;
 import static java.lang.Math.min;
+
 import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;
 import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
 import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_WRAP;
@@ -69,6 +71,7 @@ import static javax.net.ssl.SSLEngineResult.Status.OK;
 import com.android.org.conscrypt.NativeRef.SSL_SESSION;
 import com.android.org.conscrypt.NativeSsl.BioWrapper;
 import com.android.org.conscrypt.SSLParametersImpl.AliasChooser;
+
 import java.io.IOException;
 import java.io.InterruptedIOException;
 import java.nio.ByteBuffer;
@@ -81,6 +84,7 @@ import java.security.cert.X509Certificate;
 import java.security.interfaces.ECKey;
 import java.security.spec.ECParameterSpec;
 import java.util.Arrays;
+
 import javax.crypto.SecretKey;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLEngineResult;
@@ -1496,7 +1500,7 @@ final class ConscryptEngine extends AbstractConscryptEngine implements NativeCry
                             return pendingNetResult != null
                                     ? pendingNetResult
                                     : new SSLEngineResult(getEngineStatus(), NEED_UNWRAP,
-                                            bytesConsumed, bytesProduced);
+                                              bytesConsumed, bytesProduced);
                         case SSL_ERROR_WANT_WRITE:
                             // SSL_ERROR_WANT_WRITE typically means that the underlying
                             // transport is not writable
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
index 9d87c8ed..0a1933fa 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
@@ -23,6 +23,7 @@ import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_ST
 import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_NEW;
 import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY;
 import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;
+
 import static javax.net.ssl.SSLEngineResult.Status.CLOSED;
 import static javax.net.ssl.SSLEngineResult.Status.OK;
 
@@ -37,6 +38,7 @@ import java.nio.ByteBuffer;
 import java.security.PrivateKey;
 import java.security.cert.CertificateException;
 import java.security.cert.X509Certificate;
+
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLEngineResult;
 import javax.net.ssl.SSLEngineResult.HandshakeStatus;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java
index 72b98ef5..129e37f2 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java
@@ -26,6 +26,7 @@ import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSH
 
 import com.android.org.conscrypt.ExternalSession.Provider;
 import com.android.org.conscrypt.NativeRef.SSL_SESSION;
+
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
@@ -39,6 +40,7 @@ import java.security.cert.CertificateException;
 import java.security.cert.X509Certificate;
 import java.security.interfaces.ECKey;
 import java.security.spec.ECParameterSpec;
+
 import javax.crypto.SecretKey;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/FileClientSessionCache.java b/repackaged/common/src/main/java/com/android/org/conscrypt/FileClientSessionCache.java
index 248eee1a..1ae48844 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/FileClientSessionCache.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/FileClientSessionCache.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.io.IoUtils;
+
 import java.io.DataInputStream;
 import java.io.File;
 import java.io.FileInputStream;
@@ -33,6 +34,7 @@ import java.util.Set;
 import java.util.TreeSet;
 import java.util.logging.Level;
 import java.util.logging.Logger;
+
 import javax.net.ssl.SSLSession;
 
 /**
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/Hkdf.java b/repackaged/common/src/main/java/com/android/org/conscrypt/Hkdf.java
new file mode 100644
index 00000000..8a58e243
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/Hkdf.java
@@ -0,0 +1,126 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * limitations under the License
+ */
+
+package com.android.org.conscrypt;
+
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.util.Objects;
+
+import javax.crypto.Mac;
+import javax.crypto.spec.SecretKeySpec;
+
+/**
+ * Hkdf - perform HKDF key derivation operations per RFC 5869.
+ * <p>
+ * Instances should be instantiated using the standard JCA name for the required HMAC.
+ * <p>
+ * Each invocation of expand or extract uses a new Mac instance and so instances
+ * of Hkdf are thread-safe.</p>
+ * @hide This class is not part of the Android public SDK API
+ */
+public final class Hkdf {
+    // HMAC algorithm to use.
+    private final String hmacName;
+    private final int macLength;
+
+    /**
+     * Creates an Hkdf instance which will use hmacName as the name for the underlying
+     * HMAC algorithm, which will be located using normal JCA precedence rules.
+     * <p>
+     * @param hmacName the name of the HMAC algorithm to use
+     * @throws NoSuchAlgorithmException if hmacName is not a valid HMAC name
+     */
+    public Hkdf(String hmacName) throws  NoSuchAlgorithmException {
+        Objects.requireNonNull(hmacName);
+        this.hmacName = hmacName;
+
+        // Stash the MAC length with the bonus that we'll fail fast here if no such algorithm.
+        macLength = Mac.getInstance(hmacName).getMacLength();
+    }
+
+    // Visible for testing.
+    public int getMacLength() {
+        return macLength;
+    }
+
+    /**
+     * Performs an HKDF extract operation as specified in RFC 5869.
+     *
+     * @param salt the salt to use
+     * @param ikm initial keying material
+     * @return a pseudorandom key suitable for use in expand operations
+     * @throws InvalidKeyException if the salt is not suitable for use as an HMAC key
+     * @throws NoSuchAlgorithmException if the Mac algorithm is no longer available
+     */
+
+    public byte[] extract(byte[] salt, byte[] ikm)
+        throws InvalidKeyException, NoSuchAlgorithmException {
+        Objects.requireNonNull(salt);
+        Objects.requireNonNull(ikm);
+        Preconditions.checkArgument(ikm.length > 0, "Empty keying material");
+        if (salt.length == 0) {
+            salt = new byte[getMacLength()];
+        }
+        return getMac(salt).doFinal(ikm);
+    }
+
+    /**
+     * Performs an HKDF expand operation as specified in RFC 5869.
+     *
+     * @param prk a pseudorandom key of at least HashLen octets, usually the output from the
+     *            extract step. Where HashLen is the key size of the underlying Mac
+     * @param info optional context and application specific information, can be zero length
+     * @param length length of output keying material in bytes (<= 255*HashLen)
+     * @return output of keying material of length bytes
+     * @throws InvalidKeyException if prk is not suitable for use as an HMAC key
+     * @throws IllegalArgumentException if length is out of the allowed range
+     * @throws NoSuchAlgorithmException if the Mac algorithm is no longer available
+     */
+    public byte[] expand(byte[] prk, byte[] info, int length)
+        throws InvalidKeyException, NoSuchAlgorithmException {
+        Objects.requireNonNull(prk);
+        Objects.requireNonNull(info);
+        Preconditions.checkArgument(length >= 0, "Negative length");
+        Preconditions.checkArgument(length < 255 * getMacLength(), "Length too long");
+        Mac mac = getMac(prk);
+        int macLength = getMacLength();
+
+        byte[] t = new byte[0];
+        byte[] output = new byte[length];
+        int outputOffset = 0;
+        byte[] counter = new byte[] { 0x00 };
+        while (outputOffset < length) {
+            counter[0]++;
+            mac.update(t);
+            mac.update(info);
+            t = mac.doFinal(counter);
+            int size = Math.min(macLength, length - outputOffset);
+            System.arraycopy(t, 0, output, outputOffset, size);
+            outputOffset += size;
+        }
+        return output;
+    }
+
+    private Mac getMac(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
+        // Can potentially throw NoSuchAlgorithmException if the there has been a change
+        // in installed Providers.
+        Mac mac = Mac.getInstance(hmacName);
+        mac.init(new SecretKeySpec(key, "RAW"));
+        return mac; // https://www.youtube.com/watch?v=uB1D9wWxd2w
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeContext.java b/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeContext.java
index 4fd0ad67..94024505 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeContext.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeContext.java
@@ -24,8 +24,6 @@ import java.security.Security;
 
 /**
  * Hybrid Public Key Encryption (HPKE) sender APIs.
- *
- * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
  * <p>
  * Base class for HPKE sender and recipient contexts.
  * <p>
@@ -37,6 +35,7 @@ import java.security.Security;
  * to use for seal and open operations.
  *
  * Secret key material based on the context may also be generated and exported as per RFC 9180.
+ * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">RFC 9180 (HPKE)</a>
  * @hide This class is not part of the Android public SDK API
  */
 public abstract class HpkeContext {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeImpl.java
index 2c0bbab5..e6bbdfb6 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/HpkeImpl.java
@@ -36,174 +36,178 @@ import javax.crypto.BadPaddingException;
  * of the subclasses of {@link HpkeContext}.
  * @hide This class is not part of the Android public SDK API
  */
+@Internal
 public class HpkeImpl implements HpkeSpi {
-  private final HpkeSuite hpkeSuite;
-
-  private NativeRef.EVP_HPKE_CTX ctx;
-  private byte[] encapsulated = null;
-
-  public HpkeImpl(HpkeSuite hpkeSuite) {
-    this.hpkeSuite = hpkeSuite;
-  }
-
-  @Override
-  public void engineInitSender(PublicKey recipientKey, byte[] info, PrivateKey senderKey,
-          byte[] psk, byte[] psk_id) throws InvalidKeyException {
-    checkNotInitialised();
-    checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
-    if (recipientKey == null) {
-        throw new InvalidKeyException("null recipient key");
-    } else if (!(recipientKey instanceof OpenSSLX25519PublicKey)) {
-        throw new InvalidKeyException(
-                "Unsupported recipient key class: " + recipientKey.getClass());
-    }
-    final byte[] recipientKeyBytes = ((OpenSSLX25519PublicKey) recipientKey).getU();
-
-    final Object[] result =
-            NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(hpkeSuite, recipientKeyBytes, info);
-    ctx = (NativeRef.EVP_HPKE_CTX) result[0];
-    encapsulated = (byte[]) result[1];
-  }
-
-  @Override
-  public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info,
-          PrivateKey senderKey, byte[] psk, byte[] psk_id, byte[] sKe) throws InvalidKeyException {
-    checkNotInitialised();
-    Objects.requireNonNull(sKe);
-    checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
-    if (recipientKey == null) {
-        throw new InvalidKeyException("null recipient key");
-    } else if (!(recipientKey instanceof OpenSSLX25519PublicKey)) {
-        throw new InvalidKeyException(
-                "Unsupported recipient key class: " + recipientKey.getClass());
-    }
-    final byte[] recipientKeyBytes = ((OpenSSLX25519PublicKey) recipientKey).getU();
-
-    final Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
-            hpkeSuite, recipientKeyBytes, info, sKe);
-    ctx = (NativeRef.EVP_HPKE_CTX) result[0];
-    encapsulated = (byte[]) result[1];
-  }
-
-  @Override
-  public void engineInitRecipient(byte[] encapsulated, PrivateKey recipientKey,
-          byte[] info, PublicKey senderKey, byte[] psk, byte[] psk_id) throws InvalidKeyException {
-    checkNotInitialised();
-    checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
-    Preconditions.checkNotNull(encapsulated, "null encapsulated data");
-    if (encapsulated.length != hpkeSuite.getKem().getEncapsulatedLength()) {
-        throw new InvalidKeyException("Invalid encapsulated length: " + encapsulated.length);
-    }
-
-    if (recipientKey == null) {
-        throw new InvalidKeyException("null recipient key");
-    } else if (!(recipientKey instanceof OpenSSLX25519PrivateKey)) {
-        throw new InvalidKeyException(
-                "Unsupported recipient key class: " + recipientKey.getClass());
-    }
-    final byte[] recipientKeyBytes = ((OpenSSLX25519PrivateKey) recipientKey).getU();
-
-    ctx = (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
-            hpkeSuite, recipientKeyBytes, encapsulated, info);
-  }
-
-  private void checkArgumentsForBaseModeOnly(Key senderKey, byte[] psk, byte[] psk_id) {
-    if (senderKey != null) {
-      throw new UnsupportedOperationException("Asymmetric authentication not supported");
-    }
-    // PSK args can only be null if the application passed them in.
-    Objects.requireNonNull(psk);
-    Objects.requireNonNull(psk_id);
-    if (psk.length > 0 || psk_id.length > 0) {
-      throw new UnsupportedOperationException("PSK authentication not supported");
-    }
-  }
-
-  @Override
-  public byte[] engineSeal(byte[] plaintext, byte[] aad) {
-    checkIsSender();
-    Preconditions.checkNotNull(plaintext, "null plaintext");
-    return NativeCrypto.EVP_HPKE_CTX_seal(ctx, plaintext, aad);
-  }
-
-  @Override
-  public byte[] engineExport(int length, byte[] exporterContext) {
-    checkInitialised();
-    long maxLength = hpkeSuite.getKdf().maxExportLength();
-    if (length < 0 || length > maxLength) {
-        throw new IllegalArgumentException(
-                "Export length must be between 0 and " + maxLength + ", but was " + length);
-    }
-    return NativeCrypto.EVP_HPKE_CTX_export(ctx, exporterContext, length);
-  }
-
-  @Override
-  public byte[] engineOpen(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
-    checkIsRecipient();
-    Preconditions.checkNotNull(ciphertext, "null ciphertext");
-    try {
-      return NativeCrypto.EVP_HPKE_CTX_open(ctx, ciphertext, aad);
-    } catch (BadPaddingException e) {
-      throw new HpkeDecryptException(e.getMessage());
-    }
-  }
-
-  private void checkInitialised() {
-    if (ctx == null) {
-      throw new IllegalStateException("Not initialised");
-    }
-  }
-
-  private void checkNotInitialised() {
-    if (ctx != null) {
-      throw new IllegalStateException("Already initialised");
-    }
-  }
-
-  private void checkIsSender() {
-    checkInitialised();
-    if (encapsulated == null) {
-      throw new IllegalStateException("Internal error");
-    }
-  }
-
-  private void checkIsRecipient() {
-    checkInitialised();
-    if (encapsulated != null) {
-      throw new IllegalStateException("Internal error");
-    }
-  }
-
-  @Override
-  public byte[] getEncapsulated() {
-    checkIsSender();
-    return encapsulated;
-  }
-
-  /**
- * @hide This class is not part of the Android public SDK API
- */
-public static class X25519_AES_128 extends HpkeImpl {
-    public X25519_AES_128() {
-      super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
+    private final HpkeSuite hpkeSuite;
+
+    private NativeRef.EVP_HPKE_CTX ctx;
+    private byte[] encapsulated = null;
+
+    public HpkeImpl(HpkeSuite hpkeSuite) {
+        this.hpkeSuite = hpkeSuite;
     }
-  }
 
-  /**
- * @hide This class is not part of the Android public SDK API
- */
-public static class X25519_AES_256 extends HpkeImpl {
-    public X25519_AES_256() {
-      super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
+    @Override
+    public void engineInitSender(PublicKey recipientKey, byte[] info, PrivateKey senderKey,
+            byte[] psk, byte[] psk_id) throws InvalidKeyException {
+        checkNotInitialised();
+        checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
+        if (recipientKey == null) {
+            throw new InvalidKeyException("null recipient key");
+        } else if (!(recipientKey instanceof OpenSSLX25519PublicKey)) {
+            throw new InvalidKeyException(
+                    "Unsupported recipient key class: " + recipientKey.getClass());
+        }
+        final byte[] recipientKeyBytes = ((OpenSSLX25519PublicKey) recipientKey).getU();
+
+        final Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
+                hpkeSuite, recipientKeyBytes, info);
+        ctx = (NativeRef.EVP_HPKE_CTX) result[0];
+        encapsulated = (byte[]) result[1];
     }
-  }
 
-  /**
- * @hide This class is not part of the Android public SDK API
- */
-public static class X25519_CHACHA20 extends HpkeImpl {
-    public X25519_CHACHA20() {
-      super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305));
+    @Override
+    public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info,
+            PrivateKey senderKey, byte[] psk, byte[] psk_id, byte[] sKe)
+            throws InvalidKeyException {
+        checkNotInitialised();
+        Objects.requireNonNull(sKe);
+        checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
+        if (recipientKey == null) {
+            throw new InvalidKeyException("null recipient key");
+        } else if (!(recipientKey instanceof OpenSSLX25519PublicKey)) {
+            throw new InvalidKeyException(
+                    "Unsupported recipient key class: " + recipientKey.getClass());
+        }
+        final byte[] recipientKeyBytes = ((OpenSSLX25519PublicKey) recipientKey).getU();
+
+        final Object[] result =
+                NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
+                        hpkeSuite, recipientKeyBytes, info, sKe);
+        ctx = (NativeRef.EVP_HPKE_CTX) result[0];
+        encapsulated = (byte[]) result[1];
+    }
+
+    @Override
+    public void engineInitRecipient(byte[] encapsulated, PrivateKey recipientKey, byte[] info,
+            PublicKey senderKey, byte[] psk, byte[] psk_id) throws InvalidKeyException {
+        checkNotInitialised();
+        checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
+        Preconditions.checkNotNull(encapsulated, "null encapsulated data");
+        if (encapsulated.length != hpkeSuite.getKem().getEncapsulatedLength()) {
+            throw new InvalidKeyException("Invalid encapsulated length: " + encapsulated.length);
+        }
+
+        if (recipientKey == null) {
+            throw new InvalidKeyException("null recipient key");
+        } else if (!(recipientKey instanceof OpenSSLX25519PrivateKey)) {
+            throw new InvalidKeyException(
+                    "Unsupported recipient key class: " + recipientKey.getClass());
+        }
+        final byte[] recipientKeyBytes = ((OpenSSLX25519PrivateKey) recipientKey).getU();
+
+        ctx = (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
+                hpkeSuite, recipientKeyBytes, encapsulated, info);
+    }
+
+    private void checkArgumentsForBaseModeOnly(Key senderKey, byte[] psk, byte[] psk_id) {
+        if (senderKey != null) {
+            throw new UnsupportedOperationException("Asymmetric authentication not supported");
+        }
+        // PSK args can only be null if the application passed them in.
+        Objects.requireNonNull(psk);
+        Objects.requireNonNull(psk_id);
+        if (psk.length > 0 || psk_id.length > 0) {
+            throw new UnsupportedOperationException("PSK authentication not supported");
+        }
+    }
+
+    @Override
+    public byte[] engineSeal(byte[] plaintext, byte[] aad) {
+        checkIsSender();
+        Preconditions.checkNotNull(plaintext, "null plaintext");
+        return NativeCrypto.EVP_HPKE_CTX_seal(ctx, plaintext, aad);
+    }
+
+    @Override
+    public byte[] engineExport(int length, byte[] exporterContext) {
+        checkInitialised();
+        long maxLength = hpkeSuite.getKdf().maxExportLength();
+        if (length < 0 || length > maxLength) {
+            throw new IllegalArgumentException(
+                    "Export length must be between 0 and " + maxLength + ", but was " + length);
+        }
+        return NativeCrypto.EVP_HPKE_CTX_export(ctx, exporterContext, length);
+    }
+
+    @Override
+    public byte[] engineOpen(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
+        checkIsRecipient();
+        Preconditions.checkNotNull(ciphertext, "null ciphertext");
+        try {
+            return NativeCrypto.EVP_HPKE_CTX_open(ctx, ciphertext, aad);
+        } catch (BadPaddingException e) {
+            throw new HpkeDecryptException(e.getMessage());
+        }
+    }
+
+    private void checkInitialised() {
+        if (ctx == null) {
+            throw new IllegalStateException("Not initialised");
+        }
+    }
+
+    private void checkNotInitialised() {
+        if (ctx != null) {
+            throw new IllegalStateException("Already initialised");
+        }
+    }
+
+    private void checkIsSender() {
+        checkInitialised();
+        if (encapsulated == null) {
+            throw new IllegalStateException("Internal error");
+        }
+    }
+
+    private void checkIsRecipient() {
+        checkInitialised();
+        if (encapsulated != null) {
+            throw new IllegalStateException("Internal error");
+        }
+    }
+
+    @Override
+    public byte[] getEncapsulated() {
+        checkIsSender();
+        return encapsulated;
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class X25519_AES_128 extends HpkeImpl {
+        public X25519_AES_128() {
+            super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
+        }
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class X25519_AES_256 extends HpkeImpl {
+        public X25519_AES_256() {
+            super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
+        }
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class X25519_CHACHA20 extends HpkeImpl {
+        public X25519_CHACHA20() {
+            super(new HpkeSuite(
+                    KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305));
+        }
     }
-  }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/KeyManagerFactoryImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/KeyManagerFactoryImpl.java
index 1551e41e..4b496e3e 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/KeyManagerFactoryImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/KeyManagerFactoryImpl.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.io.IoUtils;
+
 import java.io.File;
 import java.io.FileInputStream;
 import java.io.FileNotFoundException;
@@ -28,6 +29,7 @@ import java.security.KeyStoreException;
 import java.security.NoSuchAlgorithmException;
 import java.security.UnrecoverableKeyException;
 import java.security.cert.CertificateException;
+
 import javax.net.ssl.KeyManager;
 import javax.net.ssl.KeyManagerFactorySpi;
 import javax.net.ssl.ManagerFactoryParameters;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
index 6cec9aa0..159787cb 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.io.OutputStream;
@@ -39,6 +40,7 @@ import java.util.Calendar;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.crypto.ShortBufferException;
@@ -536,9 +538,11 @@ public final class NativeCrypto {
 
     static native int get_X509_ex_pathlen(long x509ctx, OpenSSLX509Certificate holder);
 
-    static native long X509_get_notBefore(long x509ctx, OpenSSLX509Certificate holder);
+    static native long X509_get_notBefore(long x509ctx, OpenSSLX509Certificate holder)
+            throws ParsingException;
 
-    static native long X509_get_notAfter(long x509ctx, OpenSSLX509Certificate holder);
+    static native long X509_get_notAfter(long x509ctx, OpenSSLX509Certificate holder)
+            throws ParsingException;
 
     static native long X509_get_version(long x509ctx, OpenSSLX509Certificate holder);
 
@@ -624,9 +628,11 @@ public final class NativeCrypto {
 
     static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx, OpenSSLX509CRL holder);
 
-    static native long X509_CRL_get_lastUpdate(long x509CrlCtx, OpenSSLX509CRL holder);
+    static native long X509_CRL_get_lastUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
+            throws ParsingException;
 
-    static native long X509_CRL_get_nextUpdate(long x509CrlCtx, OpenSSLX509CRL holder);
+    static native long X509_CRL_get_nextUpdate(long x509CrlCtx, OpenSSLX509CRL holder)
+            throws ParsingException;
 
     // --- X509_REVOKED --------------------------------------------------------
 
@@ -817,6 +823,7 @@ public final class NativeCrypto {
     static final String OBSOLETE_PROTOCOL_SSLV3 = "SSLv3";
     static final String DEPRECATED_PROTOCOL_TLSV1 = "TLSv1";
     static final String DEPRECATED_PROTOCOL_TLSV1_1 = "TLSv1.1";
+
     private static final String SUPPORTED_PROTOCOL_TLSV1_2 = "TLSv1.2";
     static final String SUPPORTED_PROTOCOL_TLSV1_3 = "TLSv1.3";
 
@@ -1052,9 +1059,9 @@ public final class NativeCrypto {
     private static final String[] ENABLED_PROTOCOLS_TLSV1 = Platform.isTlsV1Deprecated()
             ? new String[0]
             : new String[] {
-                    DEPRECATED_PROTOCOL_TLSV1,
-                    DEPRECATED_PROTOCOL_TLSV1_1,
-            };
+                      DEPRECATED_PROTOCOL_TLSV1,
+                      DEPRECATED_PROTOCOL_TLSV1_1,
+              };
 
     private static final String[] SUPPORTED_PROTOCOLS_TLSV1 = Platform.isTlsV1Supported()
             ? new String[] {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
index cf78741a..284894b1 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
@@ -29,6 +29,7 @@ import static com.android.org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 import com.android.org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
 import com.android.org.conscrypt.SSLParametersImpl.AliasChooser;
 import com.android.org.conscrypt.SSLParametersImpl.PSKCallbacks;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.io.UnsupportedEncodingException;
@@ -45,6 +46,7 @@ import java.util.HashSet;
 import java.util.Set;
 import java.util.concurrent.locks.ReadWriteLock;
 import java.util.concurrent.locks.ReentrantReadWriteLock;
+
 import javax.crypto.SecretKey;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPrivateKey.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPrivateKey.java
index 6bb0c724..25c15ee3 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPrivateKey.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPrivateKey.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.io.IOException;
 import java.io.NotSerializableException;
 import java.io.ObjectInputStream;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPublicKey.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPublicKey.java
index 37fd102b..77effa8a 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPublicKey.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLECPublicKey.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.io.IOException;
 import java.io.NotSerializableException;
 import java.io.ObjectInputStream;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLKey.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLKey.java
index 9034c31c..d470c3ae 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLKey.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLKey.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.io.InputStream;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
@@ -32,8 +33,10 @@ import java.security.spec.X509EncodedKeySpec;
 
 /**
  * Represents a BoringSSL {@code EVP_PKEY}.
+ * @hide This class is not part of the Android public SDK API
  */
-final class OpenSSLKey {
+@Internal
+public final class OpenSSLKey {
     private final NativeRef.EVP_PKEY ctx;
 
     private final boolean wrapped;
@@ -259,7 +262,7 @@ final class OpenSSLKey {
      *
      * @throws InvalidKeyException if parsing fails
      */
-    static OpenSSLKey fromPublicKeyPemInputStream(InputStream is)
+    public static OpenSSLKey fromPublicKeyPemInputStream(InputStream is)
             throws InvalidKeyException {
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
         try {
@@ -277,7 +280,7 @@ final class OpenSSLKey {
     }
 
     @android.compat.annotation.UnsupportedAppUsage
-    PublicKey getPublicKey() throws NoSuchAlgorithmException {
+    public PublicKey getPublicKey() throws NoSuchAlgorithmException {
         switch (NativeCrypto.EVP_PKEY_type(ctx)) {
             case NativeConstants.EVP_PKEY_RSA:
                 return new OpenSSLRSAPublicKey(this);
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLServerSocketFactoryImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLServerSocketFactoryImpl.java
index b066bac2..c478186e 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLServerSocketFactoryImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLServerSocketFactoryImpl.java
@@ -21,6 +21,7 @@ import java.io.IOException;
 import java.net.InetAddress;
 import java.net.ServerSocket;
 import java.security.KeyManagementException;
+
 import javax.net.ServerSocketFactory;
 import javax.net.ssl.SSLServerSocketFactory;
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java
index 420d934a..ef603bec 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java
@@ -160,7 +160,8 @@ public abstract class OpenSSLSocketImpl extends AbstractConscryptSocket {
     @android.compat.annotation.
     UnsupportedAppUsage(maxTargetSdk = dalvik.annotation.compat.VersionCodes.Q,
             publicAlternatives =
-                    "Use {@code javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
+                    "Use {@code "
+                    + "javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
     @Override
     @Deprecated
     public final void
@@ -188,7 +189,8 @@ public abstract class OpenSSLSocketImpl extends AbstractConscryptSocket {
     @android.compat.annotation.
     UnsupportedAppUsage(maxTargetSdk = dalvik.annotation.compat.VersionCodes.Q,
             publicAlternatives =
-                    "Use {@code javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
+                    "Use {@code "
+                    + "javax.net.ssl.SSLParameters#setApplicationProtocols(java.lang.String[])}.")
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
     @Override
     @Deprecated
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX25519PrivateKey.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX25519PrivateKey.java
index a4599d1f..6e49e493 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX25519PrivateKey.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX25519PrivateKey.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.security.InvalidKeyException;
 import java.security.PrivateKey;
 import java.security.spec.EncodedKeySpec;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java
index da20605e..95e1210d 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.InputStream;
@@ -42,6 +43,7 @@ import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.TimeZone;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.security.auth.x500.X500Principal;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java
index f1471756..97097701 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
 import java.io.ByteArrayOutputStream;
 import java.io.InputStream;
 import java.math.BigInteger;
@@ -49,6 +50,7 @@ import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.TimeZone;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.security.auth.x500.X500Principal;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
index 7c1d4a89..62f5625f 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
@@ -150,13 +150,12 @@ final class SSLParametersImpl implements Cloneable {
           enabledProtocols = NativeCrypto.getDefaultProtocols().clone();
         } else {
             String[] filteredProtocols =
-                    filterFromProtocols(protocols, Arrays.asList(!Platform.isTlsV1Filtered()
-                        ? new String[0]
-                        : new String[] {
+                    filterFromProtocols(protocols, Arrays.asList(Platform.isTlsV1Filtered()
+                        ? new String[] {
                             NativeCrypto.OBSOLETE_PROTOCOL_SSLV3,
                             NativeCrypto.DEPRECATED_PROTOCOL_TLSV1,
-                            NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1,
-                        }));
+                            NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1,}
+                        : new String[0]));
             isEnabledProtocolsFiltered = protocols.length != filteredProtocols.length;
             enabledProtocols = NativeCrypto.checkEnabledProtocols(filteredProtocols).clone();
         }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLUtils.java b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLUtils.java
index daf6607a..df488735 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLUtils.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLUtils.java
@@ -39,6 +39,7 @@ import static com.android.org.conscrypt.NativeConstants.SSL3_RT_CHANGE_CIPHER_SP
 import static com.android.org.conscrypt.NativeConstants.SSL3_RT_HANDSHAKE;
 import static com.android.org.conscrypt.NativeConstants.SSL3_RT_HEADER_LENGTH;
 import static com.android.org.conscrypt.NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
+
 import static java.lang.Math.min;
 import static java.nio.charset.StandardCharsets.US_ASCII;
 
@@ -51,6 +52,7 @@ import java.util.Arrays;
 import java.util.HashSet;
 import java.util.LinkedHashSet;
 import java.util.Set;
+
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.SSLPeerUnverifiedException;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/TEST_MAPPING b/repackaged/common/src/main/java/com/android/org/conscrypt/TEST_MAPPING
deleted file mode 100644
index 70cd8ee0..00000000
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/TEST_MAPPING
+++ /dev/null
@@ -1,21 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "CtsLibcoreTestCases",
-      "options": [
-        {
-          "include-filter": "com.android.org.conscrypt"
-        },
-        {
-          "include-filter": "libcore.java.security"
-        },
-        {
-          "include-filter": "libcore.javax.net"
-        },
-        {
-          "include-filter": "libcore.java.net"
-        }
-      ]
-    }
-  ]
-}
\ No newline at end of file
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
index 76c8efd4..5be2d6ba 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
@@ -35,10 +35,12 @@
 
 package com.android.org.conscrypt;
 
-import com.android.org.conscrypt.ct.CTLogStore;
-import com.android.org.conscrypt.ct.CTPolicy;
-import com.android.org.conscrypt.ct.CTVerificationResult;
-import com.android.org.conscrypt.ct.CTVerifier;
+import com.android.org.conscrypt.ct.LogStore;
+import com.android.org.conscrypt.ct.Policy;
+import com.android.org.conscrypt.ct.PolicyCompliance;
+import com.android.org.conscrypt.ct.VerificationResult;
+import com.android.org.conscrypt.ct.Verifier;
+
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.net.Socket;
@@ -68,6 +70,7 @@ import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.logging.Logger;
+
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLParameters;
@@ -140,8 +143,9 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private final Exception err;
     private final CertificateFactory factory;
     private final CertBlocklist blocklist;
-    private CTVerifier ctVerifier;
-    private CTPolicy ctPolicy;
+    private LogStore ctLogStore;
+    private Verifier ctVerifier;
+    private Policy ctPolicy;
 
     private ConscryptHostnameVerifier hostnameVerifier;
 
@@ -176,8 +180,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
      * For testing only.
      */
     public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
-            CertBlocklist blocklist, CTLogStore ctLogStore, CTVerifier ctVerifier,
-            CTPolicy ctPolicy) {
+            CertBlocklist blocklist, LogStore ctLogStore, Verifier ctVerifier, Policy ctPolicy) {
         CertPathValidator validatorLocal = null;
         CertificateFactory factoryLocal = null;
         KeyStore rootKeyStoreLocal = null;
@@ -217,7 +220,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
 
         if (ctPolicy == null) {
-            ctPolicy = Platform.newDefaultPolicy(ctLogStore);
+            ctPolicy = Platform.newDefaultPolicy();
         }
 
         this.pinManager = manager;
@@ -230,8 +233,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this.acceptedIssuers = acceptedIssuersLocal;
         this.err = errLocal;
         this.blocklist = blocklist;
-        this.ctVerifier = new CTVerifier(ctLogStore);
+        this.ctLogStore = ctLogStore;
+        this.ctVerifier = new Verifier(ctLogStore);
         this.ctPolicy = ctPolicy;
+        if (ctLogStore != null) {
+            ctLogStore.setPolicy(ctPolicy);
+        }
     }
 
     @SuppressWarnings("JdkObsolete") // KeyStore#aliases is the only API available
@@ -691,7 +698,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
             if (!clientAuth &&
                     (ctEnabledOverride || (host != null && Platform
                             .isCTVerificationRequired(host)))) {
-                checkCT(host, wholeChain, ocspData, tlsSctData);
+                checkCT(wholeChain, ocspData, tlsSctData);
             }
 
             if (untrustedChain.isEmpty()) {
@@ -737,15 +744,23 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
     }
 
-    private void checkCT(String host, List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
+    private void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
             throws CertificateException {
-        CTVerificationResult result =
+        if (ctLogStore.getState() != LogStore.State.COMPLIANT) {
+            /* Fail open. For some reason, the LogStore is not usable. It could
+             * be because there is no log list available or that the log list
+             * is too old (according to the policy). */
+            return;
+        }
+        VerificationResult result =
                 ctVerifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);
 
-        if (!ctPolicy.doesResultConformToPolicy(result, host,
-                    chain.toArray(new X509Certificate[chain.size()]))) {
+        X509Certificate leaf = chain.get(0);
+        PolicyCompliance compliance = ctPolicy.doesResultConformToPolicy(result, leaf);
+        if (compliance != PolicyCompliance.COMPLY) {
             throw new CertificateException(
-                    "Certificate chain does not conform to required transparency policy.");
+                    "Certificate chain does not conform to required transparency policy: "
+                    + compliance.name());
         }
     }
 
@@ -1036,12 +1051,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     }
 
     // Replace the CTVerifier. For testing only.
-    public void setCTVerifier(CTVerifier verifier) {
+    public void setCTVerifier(Verifier verifier) {
         this.ctVerifier = verifier;
     }
 
     // Replace the CTPolicy. For testing only.
-    public void setCTPolicy(CTPolicy policy) {
+    public void setCTPolicy(Policy policy) {
         this.ctPolicy = policy;
     }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/XdhKeySpec.java b/repackaged/common/src/main/java/com/android/org/conscrypt/XdhKeySpec.java
index 287b2f43..9b2070f1 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/XdhKeySpec.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/XdhKeySpec.java
@@ -7,7 +7,7 @@ import java.util.Objects;
 
 /**
  * External Diffie–Hellman key spec holding a key which could be either a public or private key.
- *
+ * <p>
  * Subclasses {@code EncodedKeySpec} using the non-Standard "raw" format.  The XdhKeyFactory
  * class utilises this in order to create XDH keys from raw bytes and to return them
  * as an XdhKeySpec allowing the raw key material to be extracted from an XDH key.
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTLogInfo.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTLogInfo.java
deleted file mode 100644
index 348f5ccd..00000000
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTLogInfo.java
+++ /dev/null
@@ -1,147 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package com.android.org.conscrypt.ct;
-
-import java.security.InvalidKeyException;
-import java.security.MessageDigest;
-import java.security.NoSuchAlgorithmException;
-import java.security.PublicKey;
-import java.security.Signature;
-import java.security.SignatureException;
-import java.util.Arrays;
-import com.android.org.conscrypt.Internal;
-
-/**
- * Properties about a Certificate Transparency Log.
- * This object stores information about a CT log, its public key, description and URL.
- * It allows verification of SCTs against the log's public key.
- * @hide This class is not part of the Android public SDK API
- */
-@Internal
-public class CTLogInfo {
-    private final byte[] logId;
-    private final PublicKey publicKey;
-    private final String description;
-    private final String url;
-
-    public CTLogInfo(PublicKey publicKey, String description, String url) {
-        try {
-            this.logId = MessageDigest.getInstance("SHA-256")
-                .digest(publicKey.getEncoded());
-        } catch (NoSuchAlgorithmException e) {
-            // SHA-256 is guaranteed to be available
-            throw new RuntimeException(e);
-        }
-
-        this.publicKey = publicKey;
-        this.description = description;
-        this.url = url;
-    }
-
-    /**
-     * Get the log's ID, that is the SHA-256 hash of it's public key
-     */
-    public byte[] getID() {
-        return logId;
-    }
-
-    public PublicKey getPublicKey() {
-        return publicKey;
-    }
-
-    public String getDescription() {
-        return description;
-    }
-
-    public String getUrl() {
-        return url;
-    }
-
-    @Override
-    public boolean equals(Object other) {
-        if (this == other) {
-            return true;
-        }
-        if (!(other instanceof CTLogInfo)) {
-            return false;
-        }
-
-        CTLogInfo that = (CTLogInfo)other;
-        return
-            this.publicKey.equals(that.publicKey) &&
-            this.description.equals(that.description) &&
-            this.url.equals(that.url);
-    }
-
-    @Override
-    public int hashCode() {
-        int hash = 1;
-        hash = hash * 31 + publicKey.hashCode();
-        hash = hash * 31 + description.hashCode();
-        hash = hash * 31 + url.hashCode();
-
-        return hash;
-    }
-
-    /**
-     * Verify the signature of a signed certificate timestamp for the given certificate entry
-     * against the log's public key.
-     *
-     * @return the result of the verification
-     */
-    public VerifiedSCT.Status verifySingleSCT(SignedCertificateTimestamp sct,
-                                              CertificateEntry entry) {
-        if (!Arrays.equals(sct.getLogID(), getID())) {
-            return VerifiedSCT.Status.UNKNOWN_LOG;
-        }
-
-        byte[] toVerify;
-        try {
-            toVerify = sct.encodeTBS(entry);
-        } catch (SerializationException e) {
-            return VerifiedSCT.Status.INVALID_SCT;
-        }
-
-        Signature signature;
-        try {
-            String algorithm = sct.getSignature().getAlgorithm();
-            signature = Signature.getInstance(algorithm);
-        } catch (NoSuchAlgorithmException e) {
-            return VerifiedSCT.Status.INVALID_SCT;
-        }
-
-        try {
-            signature.initVerify(publicKey);
-        } catch (InvalidKeyException e) {
-            return VerifiedSCT.Status.INVALID_SCT;
-        }
-
-        try {
-            signature.update(toVerify);
-            if (!signature.verify(sct.getSignature().getSignature())) {
-                return VerifiedSCT.Status.INVALID_SIGNATURE;
-            }
-            return VerifiedSCT.Status.VALID;
-        } catch (SignatureException e) {
-            // This only happens if the signature is not initialized,
-            // but we call initVerify just before, so it should never do
-            throw new RuntimeException(e);
-        }
-    }
-}
-
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java
index 84dabe71..ac889236 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java
@@ -66,8 +66,8 @@ public class CertificateEntry {
         } else if (entryType == LogEntryType.X509_ENTRY && issuerKeyHash != null) {
             throw new IllegalArgumentException("unexpected issuerKeyHash for X509 entry.");
         }
-        
-        if (issuerKeyHash != null && issuerKeyHash.length != CTConstants.ISSUER_KEY_HASH_LENGTH) {
+
+        if (issuerKeyHash != null && issuerKeyHash.length != Constants.ISSUER_KEY_HASH_LENGTH) {
             throw new IllegalArgumentException("issuerKeyHash must be 32 bytes long");
         }
 
@@ -88,11 +88,11 @@ public class CertificateEntry {
     public static CertificateEntry createForPrecertificate(OpenSSLX509Certificate leaf,
             OpenSSLX509Certificate issuer) throws CertificateException {
         try {
-            if (!leaf.getNonCriticalExtensionOIDs().contains(CTConstants.X509_SCT_LIST_OID)) {
+            if (!leaf.getNonCriticalExtensionOIDs().contains(Constants.X509_SCT_LIST_OID)) {
                 throw new CertificateException("Certificate does not contain embedded signed timestamps");
             }
 
-            byte[] tbs = leaf.getTBSCertificateWithoutExtension(CTConstants.X509_SCT_LIST_OID);
+            byte[] tbs = leaf.getTBSCertificateWithoutExtension(Constants.X509_SCT_LIST_OID);
 
             byte[] issuerKey = issuer.getPublicKey().getEncoded();
             MessageDigest md = MessageDigest.getInstance("SHA-256");
@@ -129,11 +129,11 @@ public class CertificateEntry {
      * TLS encode the CertificateEntry structure.
      */
     public void encode(OutputStream output) throws SerializationException {
-        Serialization.writeNumber(output, entryType.ordinal(), CTConstants.LOG_ENTRY_TYPE_LENGTH);
+        Serialization.writeNumber(output, entryType.ordinal(), Constants.LOG_ENTRY_TYPE_LENGTH);
         if (entryType == LogEntryType.PRECERT_ENTRY) {
             Serialization.writeFixedBytes(output, issuerKeyHash);
         }
-        Serialization.writeVariableBytes(output, certificate, CTConstants.CERTIFICATE_LENGTH_BYTES);
+        Serialization.writeVariableBytes(output, certificate, Constants.CERTIFICATE_LENGTH_BYTES);
     }
 }
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTConstants.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/Constants.java
similarity index 98%
rename from repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTConstants.java
rename to repackaged/common/src/main/java/com/android/org/conscrypt/ct/Constants.java
index f25a4146..837c9002 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTConstants.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/Constants.java
@@ -23,7 +23,7 @@ import com.android.org.conscrypt.Internal;
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
-public class CTConstants {
+public class Constants {
     public static final String X509_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";
     public static final String OCSP_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.5";
 
@@ -45,4 +45,3 @@ public class CTConstants {
 
     public static final int ISSUER_KEY_HASH_LENGTH = 32;
 }
-
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/DigitallySigned.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/DigitallySigned.java
index ea626662..9418a4bc 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/DigitallySigned.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/DigitallySigned.java
@@ -115,10 +115,9 @@ public class DigitallySigned {
         throws SerializationException {
         try {
             return new DigitallySigned(
-                Serialization.readNumber(input, CTConstants.HASH_ALGORITHM_LENGTH),
-                Serialization.readNumber(input, CTConstants.SIGNATURE_ALGORITHM_LENGTH),
-                Serialization.readVariableBytes(input, CTConstants.SIGNATURE_LENGTH_BYTES)
-            );
+                    Serialization.readNumber(input, Constants.HASH_ALGORITHM_LENGTH),
+                    Serialization.readNumber(input, Constants.SIGNATURE_ALGORITHM_LENGTH),
+                    Serialization.readVariableBytes(input, Constants.SIGNATURE_LENGTH_BYTES));
         } catch (IllegalArgumentException e) {
             throw new SerializationException(e);
         }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java
new file mode 100644
index 00000000..c2a8498a
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java
@@ -0,0 +1,234 @@
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
+package com.android.org.conscrypt.ct;
+
+import com.android.org.conscrypt.Internal;
+
+import java.security.InvalidKeyException;
+import java.security.MessageDigest;
+import java.security.NoSuchAlgorithmException;
+import java.security.PublicKey;
+import java.security.Signature;
+import java.security.SignatureException;
+import java.util.Arrays;
+import java.util.Objects;
+
+/**
+ * Properties about a Certificate Transparency Log.
+ * This object stores information about a CT log, its public key, description and URL.
+ * It allows verification of SCTs against the log's public key.
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class LogInfo {
+    public static final int STATE_UNKNOWN = 0;
+    public static final int STATE_PENDING = 1;
+    public static final int STATE_QUALIFIED = 2;
+    public static final int STATE_USABLE = 3;
+    public static final int STATE_READONLY = 4;
+    public static final int STATE_RETIRED = 5;
+    public static final int STATE_REJECTED = 6;
+
+    private final byte[] logId;
+    private final PublicKey publicKey;
+    private final int state;
+    private final long stateTimestamp;
+    private final String description;
+    private final String url;
+    private final String operator;
+
+    private LogInfo(Builder builder) {
+        /* Based on the required fields for the log list schema v3. Notably,
+         * the state may be absent. The logId must match the public key, this
+         * is validated in the builder. */
+        Objects.requireNonNull(builder.logId);
+        Objects.requireNonNull(builder.publicKey);
+        Objects.requireNonNull(builder.url);
+        Objects.requireNonNull(builder.operator);
+
+        this.logId = builder.logId;
+        this.publicKey = builder.publicKey;
+        this.state = builder.state;
+        this.stateTimestamp = builder.stateTimestamp;
+        this.description = builder.description;
+        this.url = builder.url;
+        this.operator = builder.operator;
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class Builder {
+        private byte[] logId;
+        private PublicKey publicKey;
+        private int state;
+        private long stateTimestamp;
+        private String description;
+        private String url;
+        private String operator;
+
+        public Builder setPublicKey(PublicKey publicKey) {
+            Objects.requireNonNull(publicKey);
+            this.publicKey = publicKey;
+            try {
+                this.logId = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
+            } catch (NoSuchAlgorithmException e) {
+                // SHA-256 is guaranteed to be available
+                throw new RuntimeException(e);
+            }
+            return this;
+        }
+
+        public Builder setState(int state, long timestamp) {
+            if (state < 0 || state > STATE_REJECTED) {
+                throw new IllegalArgumentException("invalid state value");
+            }
+            this.state = state;
+            this.stateTimestamp = timestamp;
+            return this;
+        }
+
+        public Builder setDescription(String description) {
+            Objects.requireNonNull(description);
+            this.description = description;
+            return this;
+        }
+
+        public Builder setUrl(String url) {
+            Objects.requireNonNull(url);
+            this.url = url;
+            return this;
+        }
+
+        public Builder setOperator(String operator) {
+            Objects.requireNonNull(operator);
+            this.operator = operator;
+            return this;
+        }
+
+        public LogInfo build() {
+            return new LogInfo(this);
+        }
+    }
+
+    /**
+     * Get the log's ID, that is the SHA-256 hash of it's public key
+     */
+    public byte[] getID() {
+        return logId;
+    }
+
+    public PublicKey getPublicKey() {
+        return publicKey;
+    }
+
+    public String getDescription() {
+        return description;
+    }
+
+    public String getUrl() {
+        return url;
+    }
+
+    public int getState() {
+        return state;
+    }
+
+    public int getStateAt(long when) {
+        if (when >= this.stateTimestamp) {
+            return state;
+        }
+        return STATE_UNKNOWN;
+    }
+
+    public long getStateTimestamp() {
+        return stateTimestamp;
+    }
+
+    public String getOperator() {
+        return operator;
+    }
+
+    @Override
+    public boolean equals(Object other) {
+        if (this == other) {
+            return true;
+        }
+        if (!(other instanceof LogInfo)) {
+            return false;
+        }
+
+        LogInfo that = (LogInfo) other;
+        return this.state == that.state && this.description.equals(that.description)
+                && this.url.equals(that.url) && this.operator.equals(that.operator)
+                && this.stateTimestamp == that.stateTimestamp
+                && Arrays.equals(this.logId, that.logId);
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(
+                Arrays.hashCode(logId), description, url, state, stateTimestamp, operator);
+    }
+
+    /**
+     * Verify the signature of a signed certificate timestamp for the given certificate entry
+     * against the log's public key.
+     *
+     * @return the result of the verification
+     */
+    public VerifiedSCT.Status verifySingleSCT(
+            SignedCertificateTimestamp sct, CertificateEntry entry) {
+        if (!Arrays.equals(sct.getLogID(), getID())) {
+            return VerifiedSCT.Status.UNKNOWN_LOG;
+        }
+
+        byte[] toVerify;
+        try {
+            toVerify = sct.encodeTBS(entry);
+        } catch (SerializationException e) {
+            return VerifiedSCT.Status.INVALID_SCT;
+        }
+
+        Signature signature;
+        try {
+            String algorithm = sct.getSignature().getAlgorithm();
+            signature = Signature.getInstance(algorithm);
+        } catch (NoSuchAlgorithmException e) {
+            return VerifiedSCT.Status.INVALID_SCT;
+        }
+
+        try {
+            signature.initVerify(publicKey);
+        } catch (InvalidKeyException e) {
+            return VerifiedSCT.Status.INVALID_SCT;
+        }
+
+        try {
+            signature.update(toVerify);
+            if (!signature.verify(sct.getSignature().getSignature())) {
+                return VerifiedSCT.Status.INVALID_SIGNATURE;
+            }
+            return VerifiedSCT.Status.VALID;
+        } catch (SignatureException e) {
+            // This only happens if the signature is not initialized,
+            // but we call initVerify just before, so it should never do
+            throw new RuntimeException(e);
+        }
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
new file mode 100644
index 00000000..0e5d0e8a
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
@@ -0,0 +1,46 @@
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
+package com.android.org.conscrypt.ct;
+
+import com.android.org.conscrypt.Internal;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public interface LogStore {
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public enum State {
+        UNINITIALIZED,
+        NOT_FOUND,
+        MALFORMED,
+        LOADED,
+        COMPLIANT,
+        NON_COMPLIANT,
+    }
+
+    void setPolicy(Policy policy);
+
+    State getState();
+
+    long getTimestamp();
+
+    LogInfo getKnownLog(byte[] logId);
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTPolicy.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/Policy.java
similarity index 83%
rename from repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTPolicy.java
rename to repackaged/common/src/main/java/com/android/org/conscrypt/ct/Policy.java
index 9057e7ac..90c5466e 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTPolicy.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/Policy.java
@@ -24,7 +24,7 @@ import com.android.org.conscrypt.Internal;
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
-public interface CTPolicy {
-    boolean doesResultConformToPolicy(CTVerificationResult result, String hostname,
-            X509Certificate[] chain);
+public interface Policy {
+    boolean isLogStoreCompliant(LogStore store);
+    PolicyCompliance doesResultConformToPolicy(VerificationResult result, X509Certificate leaf);
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTLogStore.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java
similarity index 84%
rename from repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTLogStore.java
rename to repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java
index 0f6b715b..5f1a02a5 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTLogStore.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java
@@ -1,6 +1,6 @@
 /* GENERATED SOURCE. DO NOT MODIFY. */
 /*
- * Copyright (C) 2015 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -23,7 +23,8 @@ import com.android.org.conscrypt.Internal;
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
-public interface CTLogStore {
-    CTLogInfo getKnownLog(byte[] logId);
+public enum PolicyCompliance {
+    COMPLY,
+    NOT_ENOUGH_SCTS,
+    NOT_ENOUGH_DIVERSE_SCTS
 }
-
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java
index 218603ba..ae312c99 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java
@@ -98,19 +98,16 @@ public class SignedCertificateTimestamp {
      */
     public static SignedCertificateTimestamp decode(InputStream input, Origin origin)
             throws SerializationException {
-        int version = Serialization.readNumber(input, CTConstants.VERSION_LENGTH);
+        int version = Serialization.readNumber(input, Constants.VERSION_LENGTH);
         if (version != Version.V1.ordinal()) {
             throw new SerializationException("Unsupported SCT version " + version);
         }
 
-        return new SignedCertificateTimestamp(
-            Version.V1,
-            Serialization.readFixedBytes(input, CTConstants.LOGID_LENGTH),
-            Serialization.readLong(input, CTConstants.TIMESTAMP_LENGTH),
-            Serialization.readVariableBytes(input, CTConstants.EXTENSIONS_LENGTH_BYTES),
-            DigitallySigned.decode(input),
-            origin
-        );
+        return new SignedCertificateTimestamp(Version.V1,
+                Serialization.readFixedBytes(input, Constants.LOGID_LENGTH),
+                Serialization.readLong(input, Constants.TIMESTAMP_LENGTH),
+                Serialization.readVariableBytes(input, Constants.EXTENSIONS_LENGTH_BYTES),
+                DigitallySigned.decode(input), origin);
     }
 
     /**
@@ -126,12 +123,12 @@ public class SignedCertificateTimestamp {
      */
     public void encodeTBS(OutputStream output, CertificateEntry certEntry)
             throws SerializationException {
-        Serialization.writeNumber(output, version.ordinal(), CTConstants.VERSION_LENGTH);
+        Serialization.writeNumber(output, version.ordinal(), Constants.VERSION_LENGTH);
         Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.ordinal(),
-                                          CTConstants.SIGNATURE_TYPE_LENGTH);
-        Serialization.writeNumber(output, timestamp, CTConstants.TIMESTAMP_LENGTH);
+                Constants.SIGNATURE_TYPE_LENGTH);
+        Serialization.writeNumber(output, timestamp, Constants.TIMESTAMP_LENGTH);
         certEntry.encode(output);
-        Serialization.writeVariableBytes(output, extensions, CTConstants.EXTENSIONS_LENGTH_BYTES);
+        Serialization.writeVariableBytes(output, extensions, Constants.EXTENSIONS_LENGTH_BYTES);
     }
 
     /**
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/TEST_MAPPING b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/TEST_MAPPING
deleted file mode 100644
index e73a39ae..00000000
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/TEST_MAPPING
+++ /dev/null
@@ -1,12 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "CtsLibcoreTestCases",
-      "options": [
-        {
-          "include-filter": "com.android.org.conscrypt.ct"
-        }
-      ]
-    }
-  ]
-}
\ No newline at end of file
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTVerificationResult.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java
similarity index 77%
rename from repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTVerificationResult.java
rename to repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java
index bfa1f596..7a2e5df1 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTVerificationResult.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java
@@ -23,15 +23,21 @@ import java.util.List;
 import com.android.org.conscrypt.Internal;
 
 /**
+ * Container for verified SignedCertificateTimestamp.
+ *
+ * getValidSCTs returns SCTs which were found to match a known log and for
+ * which the signature has been verified. There is no guarantee on the state of
+ * the log (e.g., getLogInfo.getState() may return STATE_UNKNOWN). Further
+ * verification on the compliance with the policy is performed in PolicyImpl.
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
-public class CTVerificationResult {
+public class VerificationResult {
     private final ArrayList<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>();
     private final ArrayList<VerifiedSCT> invalidSCTs = new ArrayList<VerifiedSCT>();
 
     public void add(VerifiedSCT result) {
-        if (result.status == VerifiedSCT.Status.VALID) {
+        if (result.isValid()) {
             validSCTs.add(result);
         } else {
             invalidSCTs.add(result);
@@ -46,4 +52,3 @@ public class CTVerificationResult {
         return Collections.unmodifiableList(invalidSCTs);
     }
 }
-
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerifiedSCT.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerifiedSCT.java
index e68a98c3..2fa0351d 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerifiedSCT.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerifiedSCT.java
@@ -19,6 +19,8 @@ package com.android.org.conscrypt.ct;
 
 import com.android.org.conscrypt.Internal;
 
+import java.util.Objects;
+
 /**
  * Verification result for a single SCT.
  * @hide This class is not part of the Android public SDK API
@@ -35,12 +37,64 @@ public final class VerifiedSCT {
         INVALID_SCT
     }
 
-    public final SignedCertificateTimestamp sct;
-    public final Status status;
+    private final SignedCertificateTimestamp sct;
+    private final Status status;
+    private final LogInfo logInfo;
+
+    private VerifiedSCT(Builder builder) {
+        Objects.requireNonNull(builder.sct);
+        Objects.requireNonNull(builder.status);
+        if (builder.status == Status.VALID) {
+            Objects.requireNonNull(builder.logInfo);
+        }
+
+        this.sct = builder.sct;
+        this.status = builder.status;
+        this.logInfo = builder.logInfo;
+    }
+
+    public SignedCertificateTimestamp getSct() {
+        return sct;
+    }
+
+    public Status getStatus() {
+        return status;
+    }
+
+    public boolean isValid() {
+        return status == Status.VALID;
+    }
+
+    public LogInfo getLogInfo() {
+        return logInfo;
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class Builder {
+        private SignedCertificateTimestamp sct;
+        private Status status;
+        private LogInfo logInfo;
+
+        public Builder(SignedCertificateTimestamp sct) {
+            this.sct = sct;
+        }
+
+        public Builder setStatus(Status status) {
+            this.status = status;
+            return this;
+        }
+
+        public Builder setLogInfo(LogInfo logInfo) {
+            Objects.requireNonNull(logInfo);
+            this.logInfo = logInfo;
+            return this;
+        }
 
-    public VerifiedSCT(SignedCertificateTimestamp sct, Status status) {
-        this.sct = sct;
-        this.status = status;
+        public VerifiedSCT build() {
+            return new VerifiedSCT(this);
+        }
     }
 }
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTVerifier.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/Verifier.java
similarity index 74%
rename from repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTVerifier.java
rename to repackaged/common/src/main/java/com/android/org/conscrypt/ct/Verifier.java
index 3d6945ff..9770dcff 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CTVerifier.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/Verifier.java
@@ -31,18 +31,18 @@ import com.android.org.conscrypt.OpenSSLX509Certificate;
  * @hide This class is not part of the Android public SDK API
  */
 @Internal
-public class CTVerifier {
-    private final CTLogStore store;
+public class Verifier {
+    private final LogStore store;
 
-    public CTVerifier(CTLogStore store) {
+    public Verifier(LogStore store) {
         this.store = store;
     }
 
-    public CTVerificationResult verifySignedCertificateTimestamps(List<X509Certificate> chain,
+    public VerificationResult verifySignedCertificateTimestamps(List<X509Certificate> chain,
             byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
         OpenSSLX509Certificate[] certs = new OpenSSLX509Certificate[chain.size()];
         int i = 0;
-        for(X509Certificate cert : chain) {
+        for (X509Certificate cert : chain) {
             certs[i++] = OpenSSLX509Certificate.fromCertificate(cert);
         }
         return verifySignedCertificateTimestamps(certs, tlsData, ocspData);
@@ -54,7 +54,7 @@ public class CTVerifier {
      * response, and verified against the list of known logs.
      * @throws IllegalArgumentException if the chain is empty
      */
-    public CTVerificationResult verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain,
+    public VerificationResult verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain,
             byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
         if (chain.length == 0) {
             throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
@@ -62,7 +62,7 @@ public class CTVerifier {
 
         OpenSSLX509Certificate leaf = chain[0];
 
-        CTVerificationResult result = new CTVerificationResult();
+        VerificationResult result = new VerificationResult();
         List<SignedCertificateTimestamp> tlsScts = getSCTsFromTLSExtension(tlsData);
         verifyExternalSCTs(tlsScts, leaf, result);
 
@@ -79,8 +79,7 @@ public class CTVerifier {
      * The result of the verification for each sct is added to {@code result}.
      */
     private void verifyEmbeddedSCTs(List<SignedCertificateTimestamp> scts,
-                                    OpenSSLX509Certificate[] chain,
-                                    CTVerificationResult result) {
+            OpenSSLX509Certificate[] chain, VerificationResult result) {
         // Avoid creating the cert entry if we don't need it
         if (scts.isEmpty()) {
             return;
@@ -103,10 +102,7 @@ public class CTVerifier {
             return;
         }
 
-        for (SignedCertificateTimestamp sct: scts) {
-            VerifiedSCT.Status status = verifySingleSCT(sct, precertEntry);
-            result.add(new VerifiedSCT(sct, status));
-        }
+        verifySCTs(scts, precertEntry, result);
     }
 
     /**
@@ -115,8 +111,7 @@ public class CTVerifier {
      * The result of the verification for each sct is added to {@code result}.
      */
     private void verifyExternalSCTs(List<SignedCertificateTimestamp> scts,
-                                    OpenSSLX509Certificate leaf,
-                                    CTVerificationResult result) {
+            OpenSSLX509Certificate leaf, VerificationResult result) {
         // Avoid creating the cert entry if we don't need it
         if (scts.isEmpty()) {
             return;
@@ -130,32 +125,38 @@ public class CTVerifier {
             return;
         }
 
-        for (SignedCertificateTimestamp sct: scts) {
-            VerifiedSCT.Status status = verifySingleSCT(sct, x509Entry);
-            result.add(new VerifiedSCT(sct, status));
-        }
+        verifySCTs(scts, x509Entry, result);
     }
 
     /**
-     * Verify a single SCT for the given Certificate Entry
+     * Verify a list of SCTs.
      */
-    private VerifiedSCT.Status verifySingleSCT(SignedCertificateTimestamp sct,
-                                                         CertificateEntry certEntry) {
-        CTLogInfo log = store.getKnownLog(sct.getLogID());
-        if (log == null) {
-            return VerifiedSCT.Status.UNKNOWN_LOG;
+    private void verifySCTs(List<SignedCertificateTimestamp> scts, CertificateEntry certEntry,
+            VerificationResult result) {
+        for (SignedCertificateTimestamp sct : scts) {
+            VerifiedSCT.Builder builder = new VerifiedSCT.Builder(sct);
+            LogInfo log = store.getKnownLog(sct.getLogID());
+            if (log == null) {
+                builder.setStatus(VerifiedSCT.Status.UNKNOWN_LOG);
+            } else {
+                VerifiedSCT.Status status = log.verifySingleSCT(sct, certEntry);
+                builder.setStatus(status);
+                if (status == VerifiedSCT.Status.VALID) {
+                    builder.setLogInfo(log);
+                }
+            }
+            result.add(builder.build());
         }
-
-        return log.verifySingleSCT(sct, certEntry);
     }
 
     /**
      * Add every SCT in {@code scts} to {@code result} with INVALID_SCT as status
      */
-    private void markSCTsAsInvalid(List<SignedCertificateTimestamp> scts,
-                                   CTVerificationResult result) {
-        for (SignedCertificateTimestamp sct: scts) {
-            result.add(new VerifiedSCT(sct, VerifiedSCT.Status.INVALID_SCT));
+    private void markSCTsAsInvalid(
+            List<SignedCertificateTimestamp> scts, VerificationResult result) {
+        for (SignedCertificateTimestamp sct : scts) {
+            VerifiedSCT.Builder builder = new VerifiedSCT.Builder(sct);
+            result.add(builder.setStatus(VerifiedSCT.Status.INVALID_SCT).build());
         }
     }
 
@@ -175,16 +176,17 @@ public class CTVerifier {
 
         byte[][] sctList;
         try {
-            sctList = Serialization.readList(data, CTConstants.SCT_LIST_LENGTH_BYTES,
-                                             CTConstants.SERIALIZED_SCT_LENGTH_BYTES);
+            sctList = Serialization.readList(
+                    data, Constants.SCT_LIST_LENGTH_BYTES, Constants.SERIALIZED_SCT_LENGTH_BYTES);
         } catch (SerializationException e) {
             return Collections.emptyList();
         }
 
         List<SignedCertificateTimestamp> scts = new ArrayList<SignedCertificateTimestamp>();
-        for (byte[] encodedSCT: sctList) {
-            try  {
-                SignedCertificateTimestamp sct = SignedCertificateTimestamp.decode(encodedSCT, origin);
+        for (byte[] encodedSCT : sctList) {
+            try {
+                SignedCertificateTimestamp sct =
+                        SignedCertificateTimestamp.decode(encodedSCT, origin);
                 scts.add(sct);
             } catch (SerializationException e) {
                 // Ignore errors
@@ -214,23 +216,21 @@ public class CTVerifier {
      *              issuer in order to identify the relevant SingleResponse from the OCSP response,
      *              or an empty list is returned
      */
-    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(byte[] data,
-            OpenSSLX509Certificate[] chain) {
+    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(
+            byte[] data, OpenSSLX509Certificate[] chain) {
         if (data == null || chain.length < 2) {
             return Collections.emptyList();
         }
 
-        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, CTConstants.OCSP_SCT_LIST_OID,
-                chain[0].getContext(), chain[0],
-                chain[1].getContext(), chain[1]);
+        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, Constants.OCSP_SCT_LIST_OID,
+                chain[0].getContext(), chain[0], chain[1].getContext(), chain[1]);
         if (extData == null) {
             return Collections.emptyList();
         }
 
         try {
             return getSCTsFromSCTList(
-                    Serialization.readDEROctetString(
-                      Serialization.readDEROctetString(extData)),
+                    Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
                     SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
         } catch (SerializationException e) {
             return Collections.emptyList();
@@ -244,19 +244,17 @@ public class CTVerifier {
      * to be parsed, an empty list is returned. Individual SCTs which fail to be parsed are ignored.
      */
     private List<SignedCertificateTimestamp> getSCTsFromX509Extension(OpenSSLX509Certificate leaf) {
-        byte[] extData = leaf.getExtensionValue(CTConstants.X509_SCT_LIST_OID);
+        byte[] extData = leaf.getExtensionValue(Constants.X509_SCT_LIST_OID);
         if (extData == null) {
             return Collections.emptyList();
         }
 
         try {
             return getSCTsFromSCTList(
-                    Serialization.readDEROctetString(
-                      Serialization.readDEROctetString(extData)),
+                    Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
                     SignedCertificateTimestamp.Origin.EMBEDDED);
         } catch (SerializationException e) {
             return Collections.emptyList();
         }
     }
 }
-
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/OptionalMethod.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/OptionalMethod.java
index 97692cd6..88a4d251 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/OptionalMethod.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/OptionalMethod.java
@@ -17,6 +17,7 @@
 package com.android.org.conscrypt.metrics;
 
 import com.android.org.conscrypt.Internal;
+
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java
index 1ede21d0..74dcd43f 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java
@@ -30,6 +30,7 @@ import static com.android.org.conscrypt.HpkeFixture.createDefaultHpkeContextReci
 import static com.android.org.conscrypt.HpkeFixture.createDefaultHpkeContextSender;
 import static com.android.org.conscrypt.HpkeTestVectorsTest.getHpkeEncryptionRecords;
 import static com.android.org.conscrypt.TestUtils.encodeHex;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
@@ -40,6 +41,13 @@ import static org.junit.Assert.assertTrue;
 import com.android.org.conscrypt.HpkeTestVectorsTest.HpkeData;
 import com.android.org.conscrypt.HpkeTestVectorsTest.HpkeEncryptionData;
 import com.android.org.conscrypt.java.security.DefaultKeys;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.nio.charset.StandardCharsets;
 import java.security.GeneralSecurityException;
 import java.security.InvalidKeyException;
@@ -49,11 +57,6 @@ import java.security.Provider;
 import java.security.PublicKey;
 import java.security.Security;
 import java.util.List;
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * Tests for DuckTypedHpkeSpiTest. Essentially the same as the tests for HpkeContext but
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/HkdfTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/HkdfTest.java
new file mode 100644
index 00000000..514d0774
--- /dev/null
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/HkdfTest.java
@@ -0,0 +1,100 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * limitations under the License
+ */
+
+package com.android.org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.NoSuchAlgorithmException;
+import java.util.List;
+
+import javax.crypto.Mac;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class HkdfTest {
+    private final String SHA256 = "HmacSHA256";
+
+    @Test
+    public void constructor() throws Exception {
+        assertThrows(NullPointerException.class, () ->  new Hkdf(null));
+        assertThrows(NoSuchAlgorithmException.class, () -> new Hkdf("No such MAC"));
+
+        Hkdf hkdf = new Hkdf(SHA256);
+        assertEquals(Mac.getInstance(SHA256).getMacLength(), hkdf.getMacLength());
+    }
+
+    @Test
+    public void extract() throws Exception {
+        Hkdf hkdf = new Hkdf(SHA256);
+        assertThrows(NullPointerException.class, () -> hkdf.extract(null, new byte[0]));
+        assertThrows(NullPointerException.class, () -> hkdf.extract(new byte[0], null));
+        assertThrows(NullPointerException.class, () -> hkdf.extract(null, null));
+        assertThrows(IllegalArgumentException.class, () -> hkdf.extract(new byte[0], new byte[0]));
+    }
+
+    @Test
+    public void expand() throws Exception {
+        Hkdf hkdf = new Hkdf(SHA256);
+        int macLen = hkdf.getMacLength();
+        assertThrows(NullPointerException.class, () -> hkdf.expand(null, new byte[0], 1));
+        assertThrows(NullPointerException.class, () -> hkdf.expand(new byte[macLen], null, 1));
+        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
+        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
+        // Negative length
+        assertThrows(IllegalArgumentException.class,
+            () -> hkdf.expand(new byte[macLen], new byte[0], -1));
+        // PRK too small
+        assertThrows(IllegalArgumentException.class,
+            () -> hkdf.expand(new byte[0], new byte[0], 1));
+        // Length too large
+        assertThrows(IllegalArgumentException.class,
+            () -> hkdf.expand(new byte[macLen], new byte[0], 255 * macLen + 1));
+    }
+
+    @Test
+    public void testVectors() throws Exception {
+        List<TestVector> vectors = TestUtils.readTestVectors("crypto/hkdf.txt");
+
+        for (TestVector vector : vectors) {
+            String errMsg =  vector.getString("name");
+            String macName = vector.getString("hash");
+            byte[] ikm = vector.getBytes("ikm");
+            byte[] salt = vector.getBytesOrEmpty("salt");
+            byte[] prk_expected = vector.getBytes("prk");
+
+            Hkdf hkdf = new Hkdf(macName);
+            byte[] prk = hkdf.extract(salt, ikm);
+            assertArrayEquals(errMsg, prk_expected, prk);
+
+            byte[] info = vector.getBytes("info");
+            int length = vector.getInt("l");
+            byte[] okm_expected = vector.getBytes("okm");
+
+            byte[] okm = hkdf.expand(prk, info, length);
+            assertArrayEquals(errMsg, okm_expected, okm);
+        }
+    }
+}
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextRecipientTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextRecipientTest.java
index 545a6964..4fb899ef 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextRecipientTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextRecipientTest.java
@@ -30,12 +30,18 @@ import static com.android.org.conscrypt.HpkeFixture.DEFAULT_SUITE_NAME;
 import static com.android.org.conscrypt.HpkeFixture.createDefaultHpkeContextRecipient;
 import static com.android.org.conscrypt.HpkeFixture.createPrivateKey;
 import static com.android.org.conscrypt.TestUtils.decodeHex;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertThrows;
 
 import com.android.org.conscrypt.java.security.DefaultKeys;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.nio.charset.StandardCharsets;
 import java.security.GeneralSecurityException;
 import java.security.InvalidKeyException;
@@ -43,9 +49,6 @@ import java.security.NoSuchAlgorithmException;
 import java.security.NoSuchProviderException;
 import java.security.PrivateKey;
 import java.security.Provider;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextSenderTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextSenderTest.java
index f3d9fc22..9902a283 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextSenderTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/HpkeContextSenderTest.java
@@ -25,20 +25,23 @@ import static com.android.org.conscrypt.HpkeFixture.DEFAULT_PK;
 import static com.android.org.conscrypt.HpkeFixture.DEFAULT_SK;
 import static com.android.org.conscrypt.HpkeFixture.DEFAULT_SUITE_NAME;
 import static com.android.org.conscrypt.HpkeFixture.createDefaultHpkeContextSender;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertThrows;
 
 import com.android.org.conscrypt.java.security.DefaultKeys;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.nio.charset.StandardCharsets;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.NoSuchProviderException;
 import java.security.Provider;
 import java.security.PublicKey;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/TrustManagerImplTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/TrustManagerImplTest.java
index ea58efb9..db413cc1 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/TrustManagerImplTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/TrustManagerImplTest.java
@@ -23,6 +23,11 @@ import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.java.security.TestKeyStore;
 import com.android.org.conscrypt.javax.net.ssl.TestHostnameVerifier;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.IOException;
 import java.security.KeyStore;
 import java.security.Principal;
@@ -31,6 +36,7 @@ import java.security.cert.CertificateException;
 import java.security.cert.X509Certificate;
 import java.util.Arrays;
 import java.util.List;
+
 import javax.net.ssl.HandshakeCompletedListener;
 import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLPeerUnverifiedException;
@@ -38,9 +44,6 @@ import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSessionContext;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.X509TrustManager;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/SerializationTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/SerializationTest.java
index 7dabf847..8c40636e 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/SerializationTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/SerializationTest.java
@@ -21,19 +21,23 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
-import java.io.ByteArrayOutputStream;
-import java.util.Arrays;
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.io.ByteArrayOutputStream;
+import java.util.Arrays;
+
 /**
  * @hide This class is not part of the Android public SDK API
  */
 @RunWith(JUnit4.class)
 public class SerializationTest {
-
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_SignedCertificateTimestamp() throws Exception {
         byte[] in = new byte[] {
             0x00,                            // version
@@ -63,6 +67,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_invalid_SignedCertificateTimestamp() throws Exception {
         byte[] sct = new byte[] {
             0x00,                            // version
@@ -96,6 +101,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_DigitallySigned() throws Exception {
         byte[] in = new byte[] {
             0x04, 0x03,            // hash & signature algorithm
@@ -110,6 +116,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_decode_invalid_DigitallySigned() throws Exception {
         try {
             DigitallySigned.decode(new byte[] {
@@ -147,6 +154,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_encode_CertificateEntry_X509Certificate() throws Exception {
         // Use a dummy certificate. It doesn't matter, CertificateEntry doesn't care about the contents.
         CertificateEntry entry = CertificateEntry.createForX509Certificate(new byte[] { 0x12, 0x34, 0x56, 0x78 });
@@ -161,6 +169,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_encode_CertificateEntry_PreCertificate() throws Exception {
         // Use a dummy certificate and issuer key hash. It doesn't matter,
         // CertificateEntry doesn't care about the contents.
@@ -180,6 +189,7 @@ public class SerializationTest {
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_readDEROctetString() throws Exception {
         byte[] in, expected;
 
@@ -226,4 +236,3 @@ public class SerializationTest {
         assertEquals(Arrays.toString(expected), Arrays.toString(actual));
     }
 }
-
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/CTVerifierTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
similarity index 61%
rename from repackaged/common/src/test/java/com/android/org/conscrypt/ct/CTVerifierTest.java
rename to repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
index d0d42657..9e4df89d 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/CTVerifierTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
@@ -19,40 +19,65 @@ package com.android.org.conscrypt.ct;
 
 import static com.android.org.conscrypt.TestUtils.openTestFile;
 import static com.android.org.conscrypt.TestUtils.readTestFile;
+
 import static org.junit.Assert.assertEquals;
 
-import java.security.PublicKey;
-import java.util.Arrays;
 import com.android.org.conscrypt.OpenSSLX509Certificate;
 import com.android.org.conscrypt.TestUtils;
+
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.security.PublicKey;
+import java.util.Arrays;
+
 /**
  * @hide This class is not part of the Android public SDK API
  */
 @RunWith(JUnit4.class)
-public class CTVerifierTest {
+public class VerifierTest {
     private OpenSSLX509Certificate ca;
     private OpenSSLX509Certificate cert;
     private OpenSSLX509Certificate certEmbedded;
-    private CTVerifier ctVerifier;
+    private Verifier ctVerifier;
 
     @Before
     public void setUp() throws Exception {
         ca = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
         cert = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
-        certEmbedded = OpenSSLX509Certificate.fromX509PemInputStream(
-                openTestFile("cert-ct-embedded.pem"));
+        certEmbedded =
+                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem"));
 
         PublicKey key = TestUtils.readPublicKeyPemFile("ct-server-key-public.pem");
 
-        final CTLogInfo log = new CTLogInfo(key, "Test Log", "foo");
-        CTLogStore store = new CTLogStore() {
+        final LogInfo log = new LogInfo.Builder()
+                                    .setPublicKey(key)
+                                    .setDescription("Test Log")
+                                    .setUrl("http://example.com")
+                                    .setOperator("LogOperator")
+                                    .setState(LogInfo.STATE_USABLE, 1643709600000L)
+                                    .build();
+        LogStore store = new LogStore() {
             @Override
-            public CTLogInfo getKnownLog(byte[] logId) {
+            public void setPolicy(Policy policy) {}
+
+            @Override
+            public State getState() {
+                return LogStore.State.COMPLIANT;
+            }
+
+            @Override
+            public long getTimestamp() {
+                return 0;
+            }
+
+            @Override
+            public LogInfo getKnownLog(byte[] logId) {
                 if (Arrays.equals(logId, log.getID())) {
                     return log;
                 } else {
@@ -61,120 +86,125 @@ public class CTVerifierTest {
             }
         };
 
-        ctVerifier = new CTVerifier(store);
+        ctVerifier = new Verifier(store);
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withOCSPResponse() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] ocspResponse = readTestFile("ocsp-response.der");
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withTLSExtension() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list");
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withEmbeddedExtension() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { certEmbedded, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {certEmbedded, ca};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
+        VerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withoutTimestamp() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
+        VerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withInvalidSignature() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(1, result.getInvalidSCTs().size());
-        assertEquals(VerifiedSCT.Status.INVALID_SIGNATURE,
-                     result.getInvalidSCTs().get(0).status);
+        assertEquals(
+                VerifiedSCT.Status.INVALID_SIGNATURE, result.getInvalidSCTs().get(0).getStatus());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withUnknownLog() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-unknown");
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(1, result.getInvalidSCTs().size());
-        assertEquals(VerifiedSCT.Status.UNKNOWN_LOG,
-                     result.getInvalidSCTs().get(0).status);
+        assertEquals(VerifiedSCT.Status.UNKNOWN_LOG, result.getInvalidSCTs().get(0).getStatus());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withInvalidEncoding() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         // Just some garbage data which will fail to deserialize
-        byte[] tlsExtension = new byte[] { 1, 2, 3, 4 };
+        byte[] tlsExtension = new byte[] {1, 2, 3, 4};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withInvalidOCSPResponse() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         // Just some garbage data which will fail to deserialize
-        byte[] ocspResponse = new byte[] { 1, 2, 3, 4 };
+        byte[] ocspResponse = new byte[] {1, 2, 3, 4};
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
         assertEquals(0, result.getValidSCTs().size());
         assertEquals(0, result.getInvalidSCTs().size());
     }
 
     @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void test_verifySignedCertificateTimestamps_withMultipleTimestamps() throws Exception {
-        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { cert, ca };
+        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};
 
         byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");
         byte[] ocspResponse = readTestFile("ocsp-response.der");
 
-        CTVerificationResult result =
-            ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, ocspResponse);
+        VerificationResult result =
+                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, ocspResponse);
         assertEquals(1, result.getValidSCTs().size());
         assertEquals(1, result.getInvalidSCTs().size());
         assertEquals(SignedCertificateTimestamp.Origin.OCSP_RESPONSE,
-                     result.getValidSCTs().get(0).sct.getOrigin());
+                result.getValidSCTs().get(0).getSct().getOrigin());
         assertEquals(SignedCertificateTimestamp.Origin.TLS_EXTENSION,
-                     result.getInvalidSCTs().get(0).sct.getOrigin());
+                result.getInvalidSCTs().get(0).getSct().getOrigin());
     }
 }
-
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestAES.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestAES.java
index 020b4363..a32b7af0 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestAES.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestAES.java
@@ -20,15 +20,20 @@ import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 
 import com.android.org.conscrypt.TestUtils;
-import java.security.AlgorithmParameters;
-import java.security.Provider;
-import javax.crypto.spec.IvParameterSpec;
+
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.junit.ClassRule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+
+import java.security.AlgorithmParameters;
+import java.security.Provider;
+
+import javax.crypto.spec.IvParameterSpec;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestDESede.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestDESede.java
index f42c69c0..c78a8c60 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestDESede.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestDESede.java
@@ -20,15 +20,20 @@ import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 
 import com.android.org.conscrypt.TestUtils;
-import java.security.AlgorithmParameters;
-import java.security.Provider;
-import javax.crypto.spec.IvParameterSpec;
+
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.junit.ClassRule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+
+import java.security.AlgorithmParameters;
+import java.security.Provider;
+
+import javax.crypto.spec.IvParameterSpec;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestEC.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestEC.java
index 9747e9c3..c5126b51 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestEC.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestEC.java
@@ -20,18 +20,22 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 
 import com.android.org.conscrypt.TestUtils;
-import java.security.AlgorithmParameters;
-import java.security.Provider;
-import java.security.spec.ECGenParameterSpec;
-import java.security.spec.InvalidParameterSpecException;
-import java.util.Arrays;
-import java.util.List;
+
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.junit.ClassRule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+
+import java.security.AlgorithmParameters;
+import java.security.Provider;
+import java.security.spec.ECGenParameterSpec;
+import java.security.spec.InvalidParameterSpecException;
+import java.util.Arrays;
+import java.util.List;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestGCM.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestGCM.java
index 17055412..0a302161 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestGCM.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestGCM.java
@@ -21,15 +21,20 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 
 import com.android.org.conscrypt.TestUtils;
-import java.security.AlgorithmParameters;
-import java.security.Provider;
-import javax.crypto.spec.GCMParameterSpec;
+
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.junit.ClassRule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+
+import java.security.AlgorithmParameters;
+import java.security.Provider;
+
+import javax.crypto.spec.GCMParameterSpec;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestOAEP.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestOAEP.java
index 594a4569..04b8d6b4 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestOAEP.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/AlgorithmParametersTestOAEP.java
@@ -20,18 +20,23 @@ import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 
 import com.android.org.conscrypt.TestUtils;
-import java.security.AlgorithmParameters;
-import java.security.Provider;
-import java.security.spec.MGF1ParameterSpec;
-import javax.crypto.spec.OAEPParameterSpec;
-import javax.crypto.spec.PSource;
-import javax.crypto.spec.PSource.PSpecified;
+
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.junit.ClassRule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+
+import java.security.AlgorithmParameters;
+import java.security.Provider;
+import java.security.spec.MGF1ParameterSpec;
+
+import javax.crypto.spec.OAEPParameterSpec;
+import javax.crypto.spec.PSource;
+import javax.crypto.spec.PSource.PSpecified;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestEC.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestEC.java
index de48861a..d9604bcd 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestEC.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestEC.java
@@ -16,6 +16,14 @@
  */
 package com.android.org.conscrypt.java.security;
 
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.security.KeyPair;
 import java.security.NoSuchAlgorithmException;
 import java.security.interfaces.ECPrivateKey;
@@ -25,12 +33,7 @@ import java.security.spec.ECPublicKeySpec;
 import java.security.spec.InvalidKeySpecException;
 import java.util.Arrays;
 import java.util.List;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestRSA.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestRSA.java
index b4287f90..d51af4c8 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestRSA.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyFactoryTestRSA.java
@@ -21,6 +21,14 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.ObjectInputStream;
@@ -41,12 +49,6 @@ import java.security.spec.RSAPublicKeySpec;
 import java.security.spec.X509EncodedKeySpec;
 import java.util.Arrays;
 import java.util.List;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java
index 34b6c189..ede2f5a4 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java
@@ -22,6 +22,15 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.TestUtils;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.ObjectInputStream;
@@ -52,15 +61,11 @@ import java.util.List;
 import java.util.Locale;
 import java.util.Map;
 import java.util.Set;
+
 import javax.crypto.interfaces.DHPrivateKey;
 import javax.crypto.interfaces.DHPublicKey;
 import javax.crypto.spec.DHParameterSpec;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java
index d5d3fd05..36f7b680 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java
@@ -20,18 +20,22 @@ package com.android.org.conscrypt.java.security;
 import static org.junit.Assert.assertEquals;
 
 import com.android.org.conscrypt.TestUtils;
-import java.security.MessageDigest;
-import java.security.NoSuchAlgorithmException;
-import java.security.Provider;
-import java.util.Arrays;
-import java.util.HashMap;
-import java.util.Map;
+
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.junit.ClassRule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+
+import java.security.MessageDigest;
+import java.security.NoSuchAlgorithmException;
+import java.security.Provider;
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.Map;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java
index 06b4f62f..6e12df1b 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java
@@ -28,6 +28,15 @@ import com.android.org.conscrypt.Conscrypt;
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.testing.BrokenProvider;
 import com.android.org.conscrypt.testing.OpaqueProvider;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.math.BigInteger;
 import java.nio.ByteBuffer;
 import java.nio.charset.Charset;
@@ -73,12 +82,7 @@ import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java
index 9146ca91..b0171e4a 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java
@@ -28,6 +28,20 @@ import static org.junit.Assert.fail;
 import com.android.org.conscrypt.Conscrypt;
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.java.security.StandardNames;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
+import org.bouncycastle.asn1.x509.BasicConstraints;
+import org.bouncycastle.asn1.x509.Extension;
+import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
+import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.FilterInputStream;
@@ -60,18 +74,9 @@ import java.util.GregorianCalendar;
 import java.util.Iterator;
 import java.util.List;
 import java.util.TimeZone;
+
 import javax.security.auth.x500.X500Principal;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
-import org.bouncycastle.asn1.x509.BasicConstraints;
-import org.bouncycastle.asn1.x509.Extension;
-import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
-import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java
index ac3ee2bf..095abb65 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java
@@ -25,6 +25,15 @@ import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.TestUtils;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.nio.charset.StandardCharsets;
 import java.security.Provider;
@@ -35,12 +44,7 @@ import java.security.cert.X509CRL;
 import java.security.cert.X509CRLEntry;
 import java.security.cert.X509Certificate;
 import java.util.Collections;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
index 30e73fdf..73b92b21 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
@@ -19,12 +19,22 @@ package com.android.org.conscrypt.java.security.cert;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.TestUtils;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.math.BigInteger;
 import java.nio.charset.Charset;
@@ -45,13 +55,9 @@ import java.util.Comparator;
 import java.util.Date;
 import java.util.List;
 import java.util.TimeZone;
+
 import javax.security.auth.x500.X500Principal;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.Pair;
 import tests.util.ServiceTester;
 
@@ -363,6 +369,26 @@ public class X509CertificateTest {
             + "mmi08cueFV7mHzJSYV51yRQ=\n"
             + "-----END CERTIFICATE-----\n";
 
+    private static final String UTCTIME_WITH_OFFSET = "-----BEGIN CERTIFICATE-----\n"
+            + "MIIDPzCCAicCAgERMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAlVTMRMwEQYD\n"
+            + "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MR8wHQYDVQQK\n"
+            + "DBZHb29nbGUgQXV0b21vdGl2ZSBMaW5rMCYXETE0MDcwNDAwMDAwMC0wNzAwFxE0\n"
+            + "ODA4MDExMDIxMjMtMDcwMDBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv\n"
+            + "cm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEeMBwGA1UECgwVQW5kcm9pZC1B\n"
+            + "dXRvLUludGVybmFsMQswCQYDVQQLDAIwMTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
+            + "ADCCAQoCggEBAOWghAac2eJLbi/ijgZGRB6/MuaBVfOImkQddBJUhXbnskTJB/JI\n"
+            + "12Ea22E5GeVN8CkWULAZT28yDWqsKMyq9BzpjpsHc9TKxMYqrIn0HP7mIJcBu5z7\n"
+            + "K8DoXqc86encncJlkGeuQkUA68yyp7RG7eQ6XoBHEjNmyvX13Y8NY5sPUHfLfmp6\n"
+            + "A2n+Jdmecq3L0GS84ctdNtnp2zSopTy0L1Gp6+lrnuOPAYZeV+Ei2jAvhycvuSoB\n"
+            + "yV6rT9wvREvC2TDncurMwR6ws44+ZStqkhnvDLhV04ray5aPplQwwB9GELFCYSRk\n"
+            + "56sm57uYSJj/LlmOMcvyBmUHVJ7MLxgtlykCAwEAATANBgkqhkiG9w0BAQsFAAOC\n"
+            + "AQEA1Bs8v6HuAIiBdhGDGHzZJDwO6lW0LheBqsGLG9KsVvIVrTMPP9lpdTPjStGn\n"
+            + "en1RIce4R4l3YTBwxOadLMkf8rymAE5JNjPsWlBue7eI4TFFw/cvnKxcTQ61bC4i\n"
+            + "2uosyDI5VfrXm38zYcZoK4TFtMhNyx6aYSEClWB9MjHa+n6eR3dLBCg1kMGqGdZ/\n"
+            + "AoK0UEkyI3UFU8sW86iaS4dvPSaQ+z0tmfUzbrc5ZSk4hYCeUYvuyd2ShxjKmxvD\n"
+            + "0K8A7gKLY0jP8Zp+6rYBcpxc7cylWMbdlhFTHAGiKI+XeQ/9u+RPeocZsn5jGlDt\n"
+            + "K3ftMoWFce+baNq/WcMzRj04AA==\n"
+            + "-----END CERTIFICATE-----\n";
     private static Date dateFromUTC(int year, int month, int day, int hour, int minute, int second)
             throws Exception {
         Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
@@ -730,4 +756,22 @@ public class X509CertificateTest {
             }
         });
     }
+
+    // Ensure we don't reject certificates with UTCTIME fields with offsets for now: b/311260068
+    @Test
+    public void utcTimeWithOffset() throws Exception {
+        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
+        tester.skipProvider("SUN") // Sun and BC interpret the offset, Conscrypt just drops it...
+                .skipProvider("BC")
+                .run(new ServiceTester.Test() {
+                    @Override
+                    public void test(Provider p, String algorithm) throws Exception {
+                        X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
+                        assertDatesEqual(
+                                dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0), c.getNotBefore());
+                        assertDatesEqual(
+                                dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23), c.getNotAfter());
+                    }
+                });
+    }
 }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java
index 2c09f041..5bb092f6 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java
@@ -18,10 +18,17 @@
 package com.android.org.conscrypt.javax.crypto;
 
 import static com.android.org.conscrypt.TestUtils.decodeHex;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 
 import com.android.org.conscrypt.TestUtils;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.nio.ByteBuffer;
 import java.security.AlgorithmParameters;
 import java.security.InvalidAlgorithmParameterException;
@@ -35,14 +42,11 @@ import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
+
 import javax.crypto.Cipher;
 import javax.crypto.spec.GCMParameterSpec;
 import javax.crypto.spec.IvParameterSpec;
 import javax.crypto.spec.SecretKeySpec;
-import org.junit.BeforeClass;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * Test for basic compliance for ciphers.  This test uses reference vectors produced by
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java
index bc428902..8a27e182 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java
@@ -29,6 +29,20 @@ import com.android.org.conscrypt.Conscrypt;
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.java.security.StandardNames;
 import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
+import org.bouncycastle.asn1.x509.KeyUsage;
+import org.junit.Assume;
+import org.junit.BeforeClass;
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayOutputStream;
 import java.io.PrintStream;
 import java.math.BigInteger;
@@ -60,6 +74,7 @@ import java.util.List;
 import java.util.Locale;
 import java.util.Map;
 import java.util.Set;
+
 import javax.crypto.AEADBadTagException;
 import javax.crypto.BadPaddingException;
 import javax.crypto.Cipher;
@@ -75,17 +90,6 @@ import javax.crypto.spec.PBEKeySpec;
 import javax.crypto.spec.PBEParameterSpec;
 import javax.crypto.spec.PSource;
 import javax.crypto.spec.SecretKeySpec;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import libcore.test.annotation.NonCts;
-import libcore.test.reasons.NonCtsReasons;
-import org.bouncycastle.asn1.x509.KeyUsage;
-import org.junit.Assume;
-import org.junit.BeforeClass;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ECDHKeyAgreementTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ECDHKeyAgreementTest.java
index a357ecb6..125fa1ce 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ECDHKeyAgreementTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ECDHKeyAgreementTest.java
@@ -26,6 +26,18 @@ import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.Conscrypt;
 import com.android.org.conscrypt.TestUtils;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import junit.framework.AssertionFailedError;
+
+import org.junit.BeforeClass;
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.security.GeneralSecurityException;
@@ -49,17 +61,10 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Comparator;
 import java.util.List;
+
 import javax.crypto.KeyAgreement;
 import javax.crypto.SecretKey;
 import javax.crypto.ShortBufferException;
-import junit.framework.AssertionFailedError;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.BeforeClass;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * Tests for all registered Elliptic Curve Diffie-Hellman {@link KeyAgreement} providers.
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java
index bc350159..aa6e5e39 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java
@@ -22,21 +22,26 @@ import static org.junit.Assert.assertNotNull;
 
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.java.security.StandardNames;
+
+import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
+import org.junit.BeforeClass;
+import org.junit.ClassRule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.security.Provider;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
+
 import javax.crypto.KeyGenerator;
 import javax.crypto.SecretKey;
-import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
-import org.junit.BeforeClass;
-import org.junit.ClassRule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ScryptTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ScryptTest.java
index b20c79d6..e88f8b0a 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ScryptTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/ScryptTest.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt.javax.crypto;
 
 import static com.android.org.conscrypt.TestUtils.decodeHex;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
@@ -25,20 +26,23 @@ import static org.junit.Assert.assertNotNull;
 
 import com.android.org.conscrypt.ScryptKeySpec;
 import com.android.org.conscrypt.TestUtils;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.security.spec.KeySpec;
 import java.util.List;
+
 import javax.crypto.Cipher;
 import javax.crypto.SecretKey;
 import javax.crypto.SecretKeyFactory;
 import javax.crypto.spec.SecretKeySpec;
-import org.junit.BeforeClass;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
-import org.junit.runners.Parameterized.Parameter;
-import org.junit.runners.Parameterized.Parameters;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
index d882211f..8bdf3372 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
@@ -25,6 +25,13 @@ import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.VeryBasicHttpServer;
+
+import org.junit.After;
+import org.junit.Ignore;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.IOException;
 import java.net.HttpURLConnection;
 import java.net.InetAddress;
@@ -37,15 +44,11 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
+
 import javax.net.ssl.HostnameVerifier;
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocketFactory;
-import org.junit.After;
-import org.junit.Ignore;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLContextTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLContextTest.java
index fedae1f9..080f8297 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLContextTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLContextTest.java
@@ -17,7 +17,9 @@
 
 package com.android.org.conscrypt.javax.net.ssl;
 
+import static com.android.org.conscrypt.TestUtils.isTlsV1Supported;
 import static com.android.org.conscrypt.TestUtils.isWindows;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNotSame;
@@ -29,6 +31,13 @@ import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.java.security.StandardNames;
+
+import junit.framework.AssertionFailedError;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.IOException;
 import java.security.AccessController;
 import java.security.InvalidAlgorithmParameterException;
@@ -47,6 +56,7 @@ import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.concurrent.Callable;
+
 import javax.net.ServerSocketFactory;
 import javax.net.SocketFactory;
 import javax.net.ssl.KeyManager;
@@ -64,10 +74,6 @@ import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.TrustManagerFactorySpi;
 import javax.net.ssl.X509KeyManager;
-import junit.framework.AssertionFailedError;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -126,9 +132,11 @@ public class SSLContextTest {
     public void test_SSLContext_allProtocols() throws Exception {
         SSLConfigurationAsserts.assertSSLContextDefaultConfiguration(SSLContext.getDefault());
 
-        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS_ALL) {
+        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
             SSLContext sslContext = SSLContext.getInstance(protocol);
-            sslContext.init(null, null, null);
+            if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
+                sslContext.init(null, null, null);
+            }
         }
     }
 
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineTest.java
index f3b51486..5e08c8c3 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineTest.java
@@ -18,6 +18,7 @@
 package com.android.org.conscrypt.javax.net.ssl;
 
 import static com.android.org.conscrypt.TestUtils.UTF_8;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -30,6 +31,11 @@ import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.TestUtils.BufferType;
 import com.android.org.conscrypt.java.security.StandardNames;
 import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.IOException;
 import java.net.Socket;
 import java.nio.ByteBuffer;
@@ -40,6 +46,7 @@ import java.util.Arrays;
 import java.util.HashSet;
 import java.util.List;
 import java.util.concurrent.atomic.AtomicInteger;
+
 import javax.crypto.SecretKey;
 import javax.crypto.spec.SecretKeySpec;
 import javax.net.ssl.KeyManager;
@@ -54,9 +61,6 @@ import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.X509ExtendedKeyManager;
 import javax.net.ssl.X509ExtendedTrustManager;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineVersionCompatibilityTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineVersionCompatibilityTest.java
index 24621c5a..fef64c3e 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineVersionCompatibilityTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLEngineVersionCompatibilityTest.java
@@ -19,7 +19,7 @@ package com.android.org.conscrypt.javax.net.ssl;
 
 import static com.android.org.conscrypt.TestUtils.UTF_8;
 import static com.android.org.conscrypt.TestUtils.assumeJava8;
-import static java.util.Collections.singleton;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -30,6 +30,8 @@ import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.junit.Assume.assumeTrue;
 
+import static java.util.Collections.singleton;
+
 import com.android.org.conscrypt.Conscrypt;
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.java.security.TestKeyStore;
@@ -42,6 +44,11 @@ import com.android.org.conscrypt.tlswire.handshake.HelloExtension;
 import com.android.org.conscrypt.tlswire.handshake.ServerNameHelloExtension;
 import com.android.org.conscrypt.tlswire.record.TlsProtocols;
 import com.android.org.conscrypt.tlswire.record.TlsRecord;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+
 import java.io.ByteArrayInputStream;
 import java.io.DataInputStream;
 import java.nio.ByteBuffer;
@@ -58,6 +65,7 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.atomic.AtomicBoolean;
 import java.util.concurrent.atomic.AtomicReference;
+
 import javax.net.ssl.ExtendedSSLSession;
 import javax.net.ssl.HostnameVerifier;
 import javax.net.ssl.HttpsURLConnection;
@@ -75,9 +83,6 @@ import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.X509ExtendedKeyManager;
 import javax.net.ssl.X509TrustManager;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
 
 /**
  * Tests for SSLSocket classes that ensure the TLS 1.2 and TLS 1.3 implementations
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSessionTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSessionTest.java
index f80dea48..e4c3693a 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSessionTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSessionTest.java
@@ -17,6 +17,8 @@
 
 package com.android.org.conscrypt.javax.net.ssl;
 
+import static com.android.org.conscrypt.TestUtils.isWindows;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
@@ -25,6 +27,15 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
+
+import com.android.org.conscrypt.TestUtils;
+import com.android.org.conscrypt.java.security.StandardNames;
+import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 import java.lang.reflect.Field;
 import java.lang.reflect.Method;
@@ -35,17 +46,12 @@ import java.util.concurrent.ExecutionException;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
+
 import javax.net.ssl.SSLPeerUnverifiedException;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSessionBindingEvent;
 import javax.net.ssl.SSLSessionBindingListener;
 import javax.net.ssl.SSLSocket;
-import com.android.org.conscrypt.TestUtils;
-import com.android.org.conscrypt.java.security.StandardNames;
-import com.android.org.conscrypt.java.security.TestKeyStore;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -85,6 +91,9 @@ public class SSLSessionTest {
 
     @Test
     public void test_SSLSession_getCreationTime() {
+        // TODO(prb) seems to fail regularly on Windows with sTime <= t1
+        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());
+
         // We use OpenSSL, which only returns times accurate to the nearest second.
         // NativeCrypto just multiplies by 1000, which looks like truncation, which
         // would make it appear as if the OpenSSL side of things was created before
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java
index 7940ee92..e816ac5f 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java
@@ -17,7 +17,6 @@
 
 package com.android.org.conscrypt.javax.net.ssl;
 
-import static java.nio.charset.StandardCharsets.UTF_8;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -27,6 +26,8 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 
+import static java.nio.charset.StandardCharsets.UTF_8;
+
 import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.java.security.StandardNames;
 import com.android.org.conscrypt.java.security.TestKeyStore;
@@ -38,6 +39,12 @@ import com.android.org.conscrypt.tlswire.handshake.EllipticCurve;
 import com.android.org.conscrypt.tlswire.handshake.EllipticCurvesHelloExtension;
 import com.android.org.conscrypt.tlswire.handshake.HelloExtension;
 import com.android.org.conscrypt.tlswire.util.TlsProtocolVersion;
+
+import org.junit.After;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.EOFException;
 import java.io.IOException;
 import java.io.InputStream;
@@ -60,6 +67,7 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicInteger;
+
 import javax.crypto.SecretKey;
 import javax.crypto.spec.SecretKeySpec;
 import javax.net.ssl.KeyManager;
@@ -72,10 +80,7 @@ import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.X509ExtendedTrustManager;
-import org.junit.After;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.net.DelegatingSSLSocketFactory;
 import tests.util.ForEachRunner;
 import tests.util.Pair;
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
index 12479b10..945e1e28 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
@@ -17,9 +17,6 @@
 
 package com.android.org.conscrypt.javax.net.ssl;
 
-import libcore.junit.util.SwitchTargetSdkVersionRule;
-import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
-
 import static com.android.org.conscrypt.TestUtils.UTF_8;
 import static com.android.org.conscrypt.TestUtils.isLinux;
 import static com.android.org.conscrypt.TestUtils.isOsx;
@@ -28,6 +25,7 @@ import static com.android.org.conscrypt.TestUtils.isTlsV1Filtered;
 import static com.android.org.conscrypt.TestUtils.isTlsV1Supported;
 import static com.android.org.conscrypt.TestUtils.isWindows;
 import static com.android.org.conscrypt.TestUtils.osName;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -54,6 +52,19 @@ import com.android.org.conscrypt.tlswire.handshake.HelloExtension;
 import com.android.org.conscrypt.tlswire.handshake.ServerNameHelloExtension;
 import com.android.org.conscrypt.tlswire.record.TlsProtocols;
 import com.android.org.conscrypt.tlswire.record.TlsRecord;
+
+import libcore.junit.util.SwitchTargetSdkVersionRule;
+import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Ignore;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+
 import java.io.ByteArrayInputStream;
 import java.io.DataInputStream;
 import java.io.IOException;
@@ -86,6 +97,7 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.ThreadFactory;
 import java.util.concurrent.TimeUnit;
+
 import javax.crypto.SecretKey;
 import javax.crypto.spec.SecretKeySpec;
 import javax.net.ServerSocketFactory;
@@ -113,14 +125,7 @@ import javax.net.ssl.TrustManager;
 import javax.net.ssl.X509ExtendedKeyManager;
 import javax.net.ssl.X509KeyManager;
 import javax.net.ssl.X509TrustManager;
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Ignore;
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.rules.TestRule;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+
 import tests.net.DelegatingSSLSocketFactory;
 import tests.util.ForEachRunner;
 import tests.util.Pair;
diff --git a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
index 9297eb30..e0f94348 100644
--- a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
@@ -37,6 +37,9 @@ import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
 
+import com.android.org.conscrypt.ct.LogStore;
+import com.android.org.conscrypt.ct.Policy;
+
 import java.io.File;
 import java.io.FileDescriptor;
 import java.io.IOException;
@@ -56,7 +59,6 @@ import java.security.AlgorithmParameters;
 import java.security.KeyStore;
 import java.security.KeyStoreException;
 import java.security.NoSuchAlgorithmException;
-import java.security.PrivateKey;
 import java.security.PrivilegedAction;
 import java.security.Provider;
 import java.security.Security;
@@ -71,6 +73,7 @@ import java.util.EnumSet;
 import java.util.List;
 import java.util.Locale;
 import java.util.Set;
+
 import javax.crypto.spec.GCMParameterSpec;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLParameters;
@@ -80,9 +83,6 @@ import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
-import com.android.org.conscrypt.ct.CTLogStore;
-import com.android.org.conscrypt.ct.CTPolicy;
-import sun.security.x509.AlgorithmId;
 
 /**
  * Platform-specific methods for OpenJDK.
@@ -541,13 +541,26 @@ final class Platform {
     @SuppressWarnings("unused")
     static String oidToAlgorithmName(String oid) {
         try {
-            return AlgorithmId.get(oid).getName();
-        } catch (Exception e) {
-            return oid;
-        } catch (IllegalAccessError e) {
-            // This can happen under JPMS because AlgorithmId isn't exported by java.base
-            return oid;
+            Class<?> algorithmIdClass = Class.forName("sun.security.x509.AlgorithmId");
+            Method getMethod = algorithmIdClass.getDeclaredMethod("get", String.class);
+            getMethod.setAccessible(true);
+            Method getNameMethod = algorithmIdClass.getDeclaredMethod("getName");
+            getNameMethod.setAccessible(true);
+
+            Object algIdObj = getMethod.invoke(null, oid);
+            return (String) getNameMethod.invoke(algIdObj);
+        } catch (InvocationTargetException e) {
+            Throwable cause = e.getCause();
+            if (cause instanceof RuntimeException) {
+                throw (RuntimeException) cause;
+            } else if (cause instanceof Error) {
+                throw (Error) cause;
+            }
+            throw new RuntimeException(e);
+        } catch (Exception ignored) {
+            // Ignored
         }
+        return oid;
     }
 
     /*
@@ -708,11 +721,11 @@ final class Platform {
         return null;
     }
 
-    static CTLogStore newDefaultLogStore() {
+    static LogStore newDefaultLogStore() {
         return null;
     }
 
-    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
+    static Policy newDefaultPolicy() {
         return null;
     }
 
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java
index f16d2800..cb39a144 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ApplicationProtocolSelectorAdapterTest.java
@@ -21,17 +21,22 @@ import static org.junit.Assert.assertEquals;
 import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.when;
 
-import java.nio.charset.Charset;
-import javax.net.ssl.SSLEngine;
 import org.junit.Before;
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
+import java.nio.charset.Charset;
+
+import javax.net.ssl.SSLEngine;
+
 /**
  * @hide This class is not part of the Android public SDK API
  */
+@RunWith(JUnit4.class)
 public class ApplicationProtocolSelectorAdapterTest {
     private static Charset US_ASCII = Charset.forName("US-ASCII");
     private static final String[] PROTOCOLS = new String[] {"a", "b", "c"};
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptEngineTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptEngineTest.java
index e1f4a13a..c7f91523 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptEngineTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptEngineTest.java
@@ -22,6 +22,7 @@ import static com.android.org.conscrypt.TestUtils.getJdkProvider;
 import static com.android.org.conscrypt.TestUtils.highestCommonProtocol;
 import static com.android.org.conscrypt.TestUtils.initSslContext;
 import static com.android.org.conscrypt.TestUtils.newTextMessage;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -31,6 +32,15 @@ import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.when;
 
 import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+import org.mockito.ArgumentMatchers;
+import org.mockito.Mockito;
+
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.nio.ByteBuffer;
@@ -39,6 +49,7 @@ import java.security.Provider;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
+
 import javax.net.ssl.SSLContext;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLEngineResult;
@@ -47,13 +58,6 @@ import javax.net.ssl.SSLEngineResult.Status;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.SSLSession;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
-import org.junit.runners.Parameterized.Parameter;
-import org.junit.runners.Parameterized.Parameters;
-import org.mockito.ArgumentMatchers;
-import org.mockito.Mockito;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptOpenJdkSuite.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptOpenJdkSuite.java
index eba53b37..c194f1f3 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptOpenJdkSuite.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptOpenJdkSuite.java
@@ -19,8 +19,8 @@ package com.android.org.conscrypt;
 
 import static com.android.org.conscrypt.TestUtils.installConscryptAsDefaultProvider;
 
-import com.android.org.conscrypt.ct.CTVerifierTest;
 import com.android.org.conscrypt.ct.SerializationTest;
+import com.android.org.conscrypt.ct.VerifierTest;
 import com.android.org.conscrypt.java.security.AlgorithmParameterGeneratorTestDH;
 import com.android.org.conscrypt.java.security.AlgorithmParameterGeneratorTestDSA;
 import com.android.org.conscrypt.java.security.AlgorithmParametersPSSTest;
@@ -115,7 +115,7 @@ import org.junit.runners.Suite;
         TestSessionBuilderTest.class,
         TrustManagerImplTest.class,
         // org.conscrypt.ct tests
-        CTVerifierTest.class,
+        VerifierTest.class,
         SerializationTest.class,
         // java.security tests
         CertificateFactoryTest.class,
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
index 2d169ab1..bd890b6b 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
@@ -19,6 +19,7 @@ package com.android.org.conscrypt;
 
 import static com.android.org.conscrypt.TestUtils.openTestFile;
 import static com.android.org.conscrypt.TestUtils.readTestFile;
+
 import static org.hamcrest.CoreMatchers.instanceOf;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
@@ -26,9 +27,23 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThat;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
+import static org.junit.Assume.assumeTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.when;
 
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Ignore;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+import org.mockito.ArgumentMatchers;
+import org.mockito.Mockito;
+
 import java.io.IOException;
 import java.lang.reflect.Field;
 import java.net.InetAddress;
@@ -49,6 +64,7 @@ import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
+
 import javax.net.ssl.HandshakeCompletedEvent;
 import javax.net.ssl.HandshakeCompletedListener;
 import javax.net.ssl.KeyManager;
@@ -59,16 +75,6 @@ import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Ignore;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
-import org.junit.runners.Parameterized.Parameter;
-import org.junit.runners.Parameterized.Parameters;
-import org.mockito.ArgumentMatchers;
-import org.mockito.Mockito;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -650,6 +656,7 @@ public class ConscryptSocketTest {
 
     @Test
     public void test_setEnabledProtocols_FiltersSSLv3_HandshakeException() throws Exception {
+        assumeTrue(TestUtils.isTlsV1Filtered());
         TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
 
         connection.clientHooks = new ClientHooks() {
@@ -664,10 +671,47 @@ public class ConscryptSocketTest {
         };
 
         connection.doHandshake();
-        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.clientException.getClass().getSimpleName() + ": "
+                        + connection.clientException.getMessage(),
+                connection.clientException instanceof SSLHandshakeException);
         assertTrue(
                 connection.clientException.getMessage().contains("SSLv3 is no longer supported"));
-        assertThat(connection.serverException, instanceOf(SSLHandshakeException.class));
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.serverException.getClass().getSimpleName() + ": "
+                        + connection.serverException.getMessage(),
+                connection.serverException instanceof SSLHandshakeException);
+
+        assertFalse(connection.clientHooks.isHandshakeCompleted);
+        assertFalse(connection.serverHooks.isHandshakeCompleted);
+    }
+
+    @Test
+    public void test_setEnabledProtocols_RejectsSSLv3_IfNotFiltered() throws Exception {
+        assumeFalse(TestUtils.isTlsV1Filtered());
+        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
+
+        connection.clientHooks = new ClientHooks() {
+            @Override
+            public AbstractConscryptSocket createSocket(ServerSocket listener) throws IOException {
+                try (AbstractConscryptSocket socket = super.createSocket(listener)) {
+                    socket.setEnabledProtocols(new String[] {"SSLv3"});
+                    fail("SSLv3 should be rejected");
+                    return socket;
+                }
+            }
+        };
+
+        connection.doHandshake();
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.clientException.getClass().getSimpleName() + ": "
+                        + connection.clientException.getMessage(),
+                connection.clientException instanceof IllegalArgumentException);
+        assertTrue(connection.clientException.getMessage().contains("SSLv3 is not supported"));
+        assertTrue("Expected SSLHandshakeException, but got "
+                        + connection.serverException.getClass().getSimpleName() + ": "
+                        + connection.serverException.getMessage(),
+                connection.serverException instanceof SSLHandshakeException);
 
         assertFalse(connection.clientHooks.isHandshakeCompleted);
         assertFalse(connection.serverHooks.isHandshakeCompleted);
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptTest.java
index 59cd9d9b..deb03c71 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptTest.java
@@ -24,13 +24,16 @@ import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.java.security.StandardNames;
-import java.security.Provider;
-import java.security.Security;
-import javax.net.ssl.SSLContext;
+
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.security.Provider;
+import java.security.Security;
+
+import javax.net.ssl.SSLContext;
+
 /**
  * @hide This class is not part of the Android public SDK API
  */
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/MockSessionBuilder.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/MockSessionBuilder.java
index aafc5951..073d2152 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/MockSessionBuilder.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/MockSessionBuilder.java
@@ -78,7 +78,7 @@ final class MockSessionBuilder {
         when(session.getId()).thenReturn(id);
         when(session.isValid()).thenReturn(valid);
         when(session.isSingleUse()).thenReturn(singleUse);
-        when(session.getProtocol()).thenReturn(TestUtils.highestCommonProtocol());
+        when(session.getProtocol()).thenReturn(TestUtils.getSupportedProtocols()[0]);
         when(session.getPeerHost()).thenReturn(host);
         when(session.getPeerPort()).thenReturn(port);
         when(session.getCipherSuite()).thenReturn(cipherSuite);
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
index ea274a1c..5531e7fd 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
@@ -27,8 +27,10 @@ import static com.android.org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 import static com.android.org.conscrypt.NativeConstants.TLS1_1_VERSION;
 import static com.android.org.conscrypt.NativeConstants.TLS1_2_VERSION;
 import static com.android.org.conscrypt.NativeConstants.TLS1_VERSION;
+import static com.android.org.conscrypt.TestUtils.isWindows;
 import static com.android.org.conscrypt.TestUtils.openTestFile;
 import static com.android.org.conscrypt.TestUtils.readTestFile;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
@@ -36,6 +38,7 @@ import static org.junit.Assert.assertNotSame;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.when;
 
@@ -44,6 +47,14 @@ import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
 import com.android.org.conscrypt.io.IoUtils;
 import com.android.org.conscrypt.java.security.StandardNames;
 import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.ArgumentMatchers;
+import org.mockito.Mockito;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.FileDescriptor;
@@ -78,17 +89,12 @@ import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
+
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.SSLProtocolException;
 import javax.security.auth.x500.X500Principal;
-import org.junit.BeforeClass;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-import org.mockito.ArgumentMatchers;
-import org.mockito.Mockito;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -115,84 +121,55 @@ public class NativeCryptoTest {
     private static byte[] CHANNEL_ID;
     private static Method m_Platform_getFileDescriptor;
 
+    private static RSAPrivateCrtKey TEST_RSA_KEY;
+
     @BeforeClass
-    public static void getPlatformMethods() throws Exception {
+    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
+    public static void initStatics() throws Exception {
         Class<?> c_Platform = TestUtils.conscryptClass("Platform");
         m_Platform_getFileDescriptor =
                 c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
         m_Platform_getFileDescriptor.setAccessible(true);
-    }
 
-    private static OpenSSLKey getServerPrivateKey() {
-        initCerts();
-        return SERVER_PRIVATE_KEY;
-    }
-
-    private static long[] getServerCertificateRefs() {
-        initCerts();
-        return SERVER_CERTIFICATE_REFS;
-    }
-
-    private static byte[][] getEncodedServerCertificates() {
-        initCerts();
-        return ENCODED_SERVER_CERTIFICATES;
-    }
+        PrivateKeyEntry serverPrivateKeyEntry =
+                TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
+        SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
+        SERVER_CERTIFICATES_HOLDER =
+                encodeCertificateList(serverPrivateKeyEntry.getCertificateChain());
+        SERVER_CERTIFICATE_REFS = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);
+        ENCODED_SERVER_CERTIFICATES = getEncodedCertificates(SERVER_CERTIFICATES_HOLDER);
+
+        PrivateKeyEntry clientPrivateKeyEntry =
+                TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
+        CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
+        CLIENT_CERTIFICATES_HOLDER =
+                encodeCertificateList(clientPrivateKeyEntry.getCertificateChain());
+        CLIENT_CERTIFICATE_REFS = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);
+        ENCODED_CLIENT_CERTIFICATES = getEncodedCertificates(CLIENT_CERTIFICATES_HOLDER);
+
+        KeyStore ks = TestKeyStore.getClient().keyStore;
+        String caCertAlias = ks.aliases().nextElement();
+        X509Certificate certificate = (X509Certificate) ks.getCertificate(caCertAlias);
+        X500Principal principal = certificate.getIssuerX500Principal();
+        CA_PRINCIPALS = new byte[][] {principal.getEncoded()};
 
-    private static OpenSSLKey getClientPrivateKey() {
-        initCerts();
-        return CLIENT_PRIVATE_KEY;
-    }
-
-    private static long[] getClientCertificateRefs() {
-        initCerts();
-        return CLIENT_CERTIFICATE_REFS;
-    }
-
-    private static byte[][] getEncodedClientCertificates() {
-        initCerts();
-        return ENCODED_CLIENT_CERTIFICATES;
-    }
-
-    private static byte[][] getCaPrincipals() {
-        initCerts();
-        return CA_PRINCIPALS;
-    }
+        // NIST P-256 aka SECG secp256r1 aka X9.62 prime256v1
+        OpenSSLECGroupContext openSslSpec = OpenSSLECGroupContext.getCurveByName("prime256v1");
+        BigInteger s = new BigInteger(
+                "229cdbbf489aea584828a261a23f9ff8b0f66f7ccac98bf2096ab3aee41497c5", 16);
+        CHANNEL_ID_PRIVATE_KEY =
+                new OpenSSLECPrivateKey(new ECPrivateKeySpec(s, openSslSpec.getECParameterSpec()))
+                        .getOpenSSLKey();
 
-    /**
-     * Lazily create shared test certificates.
-     */
-    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
-    private static synchronized void initCerts() {
-        if (SERVER_PRIVATE_KEY != null) {
-            return;
-        }
+        // Channel ID is the concatenation of the X and Y coordinates of the public key.
+        CHANNEL_ID = new BigInteger(
+                "702b07871fd7955c320b26f15e244e47eed60272124c92b9ebecf0b42f90069b"
+                        + "ab53592ebfeb4f167dbf3ce61513afb0e354c479b1c1b69874fa471293494f77",
+                16)
+                             .toByteArray();
 
-        try {
-            PrivateKeyEntry serverPrivateKeyEntry =
-                    TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
-            SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
-            SERVER_CERTIFICATES_HOLDER =
-                    encodeCertificateList(serverPrivateKeyEntry.getCertificateChain());
-            SERVER_CERTIFICATE_REFS = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);
-            ENCODED_SERVER_CERTIFICATES = getEncodedCertificates(SERVER_CERTIFICATES_HOLDER);
-
-            PrivateKeyEntry clientPrivateKeyEntry =
-                    TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
-            CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
-            CLIENT_CERTIFICATES_HOLDER =
-                    encodeCertificateList(clientPrivateKeyEntry.getCertificateChain());
-            CLIENT_CERTIFICATE_REFS = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);
-            ENCODED_CLIENT_CERTIFICATES = getEncodedCertificates(CLIENT_CERTIFICATES_HOLDER);
-
-            KeyStore ks = TestKeyStore.getClient().keyStore;
-            String caCertAlias = ks.aliases().nextElement();
-            X509Certificate certificate = (X509Certificate) ks.getCertificate(caCertAlias);
-            X500Principal principal = certificate.getIssuerX500Principal();
-            CA_PRINCIPALS = new byte[][] {principal.getEncoded()};
-            initChannelIdKey();
-        } catch (Exception e) {
-            throw new RuntimeException(e);
-        }
+        // RSA keys are slow to generate, so prefer to reuse the key when possible.
+        TEST_RSA_KEY = generateRsaKey();
     }
 
     private static long[] getCertificateReferences(OpenSSLX509Certificate[] certs) {
@@ -224,29 +201,9 @@ public class NativeCryptoTest {
         return openSslCerts;
     }
 
-    private static synchronized void initChannelIdKey() throws Exception {
-        if (CHANNEL_ID_PRIVATE_KEY != null) {
-            return;
-        }
-
-        // NIST P-256 aka SECG secp256r1 aka X9.62 prime256v1
-        OpenSSLECGroupContext openSslSpec = OpenSSLECGroupContext.getCurveByName("prime256v1");
-        BigInteger s = new BigInteger(
-                "229cdbbf489aea584828a261a23f9ff8b0f66f7ccac98bf2096ab3aee41497c5", 16);
-        CHANNEL_ID_PRIVATE_KEY =
-                new OpenSSLECPrivateKey(new ECPrivateKeySpec(s, openSslSpec.getECParameterSpec()))
-                        .getOpenSSLKey();
-
-        // Channel ID is the concatenation of the X and Y coordinates of the public key.
-        CHANNEL_ID = new BigInteger(
-                "702b07871fd7955c320b26f15e244e47eed60272124c92b9ebecf0b42f90069b"
-                        + "ab53592ebfeb4f167dbf3ce61513afb0e354c479b1c1b69874fa471293494f77",
-                16).toByteArray();
-    }
-
     private static RSAPrivateCrtKey generateRsaKey() throws Exception {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
-        kpg.initialize(512);
+        kpg.initialize(2048);
 
         KeyPair keyPair = kpg.generateKeyPair();
         return (RSAPrivateCrtKey) keyPair.getPrivate();
@@ -291,7 +248,7 @@ public class NativeCryptoTest {
 
     @Test(expected = NullPointerException.class)
     public void EVP_PKEY_cmp_withNullShouldThrow() throws Exception {
-        RSAPrivateCrtKey privKey1 = generateRsaKey();
+        RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
         assertNotSame(NULL, pkey1);
         NativeCrypto.EVP_PKEY_cmp(pkey1, null);
@@ -299,7 +256,7 @@ public class NativeCryptoTest {
 
     @Test
     public void test_EVP_PKEY_cmp() throws Exception {
-        RSAPrivateCrtKey privKey1 = generateRsaKey();
+        RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
 
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
         assertNotSame(NULL, pkey1);
@@ -307,6 +264,7 @@ public class NativeCryptoTest {
         NativeRef.EVP_PKEY pkey1_copy = getRsaPkey(privKey1);
         assertNotSame(NULL, pkey1_copy);
 
+        // Generate a different key.
         NativeRef.EVP_PKEY pkey2 = getRsaPkey(generateRsaKey());
         assertNotSame(NULL, pkey2);
 
@@ -396,7 +354,7 @@ public class NativeCryptoTest {
     @Test(expected = NullPointerException.class)
     public void setLocalCertsAndPrivateKey_withNullSSLShouldThrow() throws Exception {
         NativeCrypto.setLocalCertsAndPrivateKey(
-                NULL, null, getEncodedServerCertificates(), getServerPrivateKey().getNativeRef());
+                NULL, null, ENCODED_SERVER_CERTIFICATES, SERVER_PRIVATE_KEY.getNativeRef());
     }
 
     @Test(expected = NullPointerException.class)
@@ -404,7 +362,8 @@ public class NativeCryptoTest {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
         try {
-            NativeCrypto.setLocalCertsAndPrivateKey(s, null, null, getServerPrivateKey().getNativeRef());
+            NativeCrypto.setLocalCertsAndPrivateKey(
+                    s, null, null, SERVER_PRIVATE_KEY.getNativeRef());
         } finally {
             NativeCrypto.SSL_free(s, null);
             NativeCrypto.SSL_CTX_free(c, null);
@@ -416,7 +375,7 @@ public class NativeCryptoTest {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
         try {
-            NativeCrypto.setLocalCertsAndPrivateKey(s, null, getEncodedServerCertificates(), null);
+            NativeCrypto.setLocalCertsAndPrivateKey(s, null, ENCODED_SERVER_CERTIFICATES, null);
         } finally {
             NativeCrypto.SSL_free(s, null);
             NativeCrypto.SSL_CTX_free(c, null);
@@ -429,7 +388,7 @@ public class NativeCryptoTest {
         long s = NativeCrypto.SSL_new(c, null);
 
         NativeCrypto.setLocalCertsAndPrivateKey(
-                s, null, getEncodedServerCertificates(), getServerPrivateKey().getNativeRef());
+                s, null, ENCODED_SERVER_CERTIFICATES, SERVER_PRIVATE_KEY.getNativeRef());
 
         NativeCrypto.SSL_free(s, null);
         NativeCrypto.SSL_CTX_free(c, null);
@@ -442,8 +401,6 @@ public class NativeCryptoTest {
 
     @Test(expected = NullPointerException.class)
     public void SSL_set1_tls_channel_id_withNullKeyShouldThrow() throws Exception {
-        initChannelIdKey();
-
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
         try {
@@ -456,8 +413,6 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_use_PrivateKey_for_tls_channel_id() throws Exception {
-        initChannelIdKey();
-
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
 
@@ -1099,15 +1054,14 @@ public class NativeCryptoTest {
         // normal client and server case
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
         TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1136,7 +1090,7 @@ public class NativeCryptoTest {
             }
         }, null, null);
         Future<TestSSLHandshakeCallbacks> server1 = handshake(listener, 0,
-                false, new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+                false, new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                         callbacks.onNewSessionEstablishedSaveSession = true;
@@ -1145,8 +1099,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks clientCallback1 = client1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback1 = server1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback1.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback1.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback1.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback1.authMethod);
         assertFalse(serverCallback1.verifyCertificateChainCalled);
         assertFalse(clientCallback1.clientCertificateRequestedCalled);
@@ -1176,7 +1129,7 @@ public class NativeCryptoTest {
             }
         }, null, null);
         Future<TestSSLHandshakeCallbacks> server2 = handshake(listener, 0,
-                false, new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+                false, new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public long beforeHandshake(long c) throws SSLException {
                         long sslNativePtr = super.beforeHandshake(c);
@@ -1187,8 +1140,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks clientCallback2 = client2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback2 = server2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback2.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback2.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback2.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback2.authMethod);
         assertFalse(serverCallback2.verifyCertificateChainCalled);
         assertFalse(clientCallback2.clientCertificateRequestedCalled);
@@ -1219,14 +1171,14 @@ public class NativeCryptoTest {
                     throws CertificateEncodingException, SSLException {
                 super.clientCertificateRequested(s);
                 NativeCrypto.setLocalCertsAndPrivateKey(
-                        s, null, getEncodedClientCertificates(), getClientPrivateKey().getNativeRef());
+                        s, null, ENCODED_CLIENT_CERTIFICATES, CLIENT_PRIVATE_KEY.getNativeRef());
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public long beforeHandshake(long c) throws SSLException {
                 long s = super.beforeHandshake(c);
-                NativeCrypto.SSL_set_client_CA_list(s, null, getCaPrincipals());
+                NativeCrypto.SSL_set_client_CA_list(s, null, CA_PRINCIPALS);
                 NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_PEER);
                 return s;
             }
@@ -1237,12 +1189,10 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertTrue(serverCallback.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getClientCertificateRefs(), serverCallback.certificateChainRefs);
+        assertEqualCertificateChains(CLIENT_CERTIFICATE_REFS, serverCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", serverCallback.authMethod);
 
         assertTrue(clientCallback.clientCertificateRequestedCalled);
@@ -1251,7 +1201,7 @@ public class NativeCryptoTest {
         assertEquals(new HashSet<String>(Arrays.asList("EC", "RSA")),
                 SSLUtils.getSupportedClientKeyTypes(
                         clientCallback.keyTypes, clientCallback.signatureAlgs));
-        assertEqualPrincipals(getCaPrincipals(), clientCallback.asn1DerEncodedX500Principals);
+        assertEqualPrincipals(CA_PRINCIPALS, clientCallback.asn1DerEncodedX500Principals);
         assertFalse(serverCallback.clientCertificateRequestedCalled);
 
         assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
@@ -1272,11 +1222,11 @@ public class NativeCryptoTest {
         final ServerSocket listener = newServerSocket();
         try {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public long beforeHandshake(long c) throws SSLException {
                     long s = super.beforeHandshake(c);
-                    NativeCrypto.SSL_set_client_CA_list(s, null, getCaPrincipals());
+                    NativeCrypto.SSL_set_client_CA_list(s, null, CA_PRINCIPALS);
                     NativeCrypto.SSL_set_verify(
                             s, null, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                     return s;
@@ -1301,7 +1251,7 @@ public class NativeCryptoTest {
         Socket serverSocket = null;
         try {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, 1, true, cHooks, null, null);
             Future<TestSSLHandshakeCallbacks> server =
@@ -1324,7 +1274,7 @@ public class NativeCryptoTest {
         Socket clientSocket = null;
         try {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, -1, true, cHooks, null, null);
             Future<TestSSLHandshakeCallbacks> server =
@@ -1342,15 +1292,13 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_do_handshake_with_channel_id_normal() throws Exception {
-        initChannelIdKey();
-
         // Normal handshake with TLS Channel ID.
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
         cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
         // TLS Channel ID currently requires ECDHE-based key exchanges.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
-        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        ServerHooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         sHooks.channelIdEnabled = true;
         sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
@@ -1359,8 +1307,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1381,15 +1328,13 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_do_handshake_with_channel_id_not_supported_by_server() throws Exception {
-        initChannelIdKey();
-
         // Client tries to use TLS Channel ID but the server does not enable/offer the extension.
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
         cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
         // TLS Channel ID currently requires ECDHE-based key exchanges.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
-        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        ServerHooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         sHooks.channelIdEnabled = false;
         sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
@@ -1398,8 +1343,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1420,15 +1364,13 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_do_handshake_with_channel_id_not_enabled_by_client() throws Exception {
-        initChannelIdKey();
-
         // Client does not use TLS Channel ID when the server has the extension enabled/offered.
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
         cHooks.channelIdPrivateKey = null;
         // TLS Channel ID currently requires ECDHE-based key exchanges.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
-        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        ServerHooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         sHooks.channelIdEnabled = true;
         sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
@@ -1437,8 +1379,7 @@ public class NativeCryptoTest {
         TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
         assertTrue(clientCallback.verifyCertificateChainCalled);
-        assertEqualCertificateChains(
-                getServerCertificateRefs(), clientCallback.certificateChainRefs);
+        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
         assertEquals("ECDHE_RSA", clientCallback.authMethod);
         assertFalse(serverCallback.verifyCertificateChainCalled);
         assertFalse(clientCallback.clientCertificateRequestedCalled);
@@ -1685,7 +1626,7 @@ public class NativeCryptoTest {
             }
         };
 
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public long beforeHandshake(long c) throws SSLException {
                 long s = super.beforeHandshake(c);
@@ -1728,7 +1669,7 @@ public class NativeCryptoTest {
             }
         };
 
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public long beforeHandshake(long c) throws SSLException {
                 long s = super.beforeHandshake(c);
@@ -1810,8 +1751,7 @@ public class NativeCryptoTest {
                         clientSession[0] = session;
                     }
                 };
-                Hooks sHooks = new ServerHooks(
-                        getServerPrivateKey(), getEncodedServerCertificates()) {
+                Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public long getContext() throws SSLException {
                         return serverContext;
@@ -1850,8 +1790,7 @@ public class NativeCryptoTest {
                         super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                     }
                 };
-                Hooks sHooks = new ServerHooks(
-                        getServerPrivateKey(), getEncodedServerCertificates()) {
+                Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
                     public long getContext() throws SSLException {
                         return serverContext;
@@ -1903,7 +1842,7 @@ public class NativeCryptoTest {
                     return s;
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, 0, true, cHooks, null, null);
             @SuppressWarnings("unused")
@@ -1926,7 +1865,7 @@ public class NativeCryptoTest {
         // negative test case for SSL_set_session_creation_enabled(false) on server
         {
             Hooks cHooks = new Hooks();
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public long beforeHandshake(long c) throws SSLException {
                     long s = super.beforeHandshake(c);
@@ -2011,7 +1950,7 @@ public class NativeCryptoTest {
                 return s;
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                     SSLHandshakeCallbacks callback) throws Exception {
@@ -2042,7 +1981,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2077,7 +2016,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2110,7 +2049,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2149,7 +2088,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2204,11 +2143,11 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                     SSLHandshakeCallbacks callback) throws Exception {
                 byte[][] cc = NativeCrypto.SSL_get0_peer_certificates(s, null);
-                assertEqualByteArrays(getEncodedServerCertificates(), cc);
+                assertEqualByteArrays(ENCODED_SERVER_CERTIFICATES, cc);
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2220,7 +2159,7 @@ public class NativeCryptoTest {
     public void test_SSL_cipher_names() throws Exception {
         final ServerSocket listener = newServerSocket();
         Hooks cHooks = new Hooks();
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         // Both legacy and standard names are accepted.
         cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-GCM-SHA256");
         sHooks.enabledCipherSuites =
@@ -2309,7 +2248,7 @@ public class NativeCryptoTest {
                     super.afterHandshake(session, s, c, sock, fd, callback);
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public void afterHandshake(long session, long s, long c, Socket sock,
                         FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2335,7 +2274,7 @@ public class NativeCryptoTest {
                     fail();
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                 @Override
                 public void afterHandshake(long session, long s, long c, Socket sock,
                         FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2436,7 +2375,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
             @Override
             public void afterHandshake(long session, final long s, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
@@ -2552,7 +2491,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2567,8 +2506,10 @@ public class NativeCryptoTest {
 
     @Test
     public void test_SSL_SESSION_get_time() throws Exception {
-        final ServerSocket listener = newServerSocket();
+        // TODO(prb) seems to fail regularly on Windows with time < System.currentTimeMillis()
+        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());
 
+        final ServerSocket listener = newServerSocket();
         {
             Hooks cHooks = new Hooks() {
                 @Override
@@ -2580,7 +2521,7 @@ public class NativeCryptoTest {
                     super.afterHandshake(session, s, c, sock, fd, callback);
                 }
             };
-            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
             Future<TestSSLHandshakeCallbacks> client =
                     handshake(listener, 0, true, cHooks, null, null);
             Future<TestSSLHandshakeCallbacks> server =
@@ -2608,7 +2549,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2637,7 +2578,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2681,7 +2622,7 @@ public class NativeCryptoTest {
                 super.afterHandshake(session, s, c, sock, fd, callback);
             }
         };
-        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
+        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -2756,11 +2697,7 @@ public class NativeCryptoTest {
 
     @Test
     public void test_EVP_DigestSignInit() throws Exception {
-        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
-        kpg.initialize(512);
-
-        KeyPair kp = kpg.generateKeyPair();
-        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) kp.getPrivate();
+        RSAPrivateCrtKey privKey = TEST_RSA_KEY;
 
         NativeRef.EVP_PKEY pkey;
         pkey = new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
@@ -3076,7 +3013,7 @@ public class NativeCryptoTest {
     }
 
     private static long getRawPkeyCtxForEncrypt() throws Exception {
-        return NativeCrypto.EVP_PKEY_encrypt_init(getRsaPkey(generateRsaKey()));
+        return NativeCrypto.EVP_PKEY_encrypt_init(getRsaPkey(TEST_RSA_KEY));
     }
 
     private static NativeRef.EVP_PKEY_CTX getPkeyCtxForEncrypt() throws Exception {
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java
index 51e70771..e5233190 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java
@@ -25,31 +25,66 @@ import junit.framework.TestCase;
  * @hide This class is not part of the Android public SDK API
  */
 public class OpenSSLKeyTest extends TestCase {
-    static final String RSA_PUBLIC_KEY =
-        "-----BEGIN PUBLIC KEY-----\n" +
-        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOHsK2E2FLYfEMWEVH/rJMTqDZLLLysh\n" +
-        "AH5odcfhYdF9xvFFU9rqJT7zXUDH4SjdhZGUUAO5IOC1e8ZIyRsbiY0CAwEAAQ==\n" +
-        "-----END PUBLIC KEY-----";
+    static final String RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
+            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3G7PGpfZx68wTY9eLb4b\n"
+            + "th3Y7MXgh1A2oqB202KTiClKy9Y+Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c\n"
+            + "0wj2e3kxwS/wiMjoYXIcbFW0iN6g1F6n71Zykf0uOE8DZKCffzjmld+Ia5M4qKsC\n"
+            + "gW4TTUODGVChBUTKui4b7Q8qsBOUTXm7SeyuZcZRChZ2w9aICZ3OR1qHnG0EXvgs\n"
+            + "0ZhCIgvtVQPaEwqMWaGYQKa8hW9X3KUvY6D8fQkQdhY2j5m/y2757tNsQWhH7l/C\n"
+            + "gdH/2F7qa3+V1yTqj9ihceLq1/FxAZkd6q7G9YE8ZyvtoKU86o6+4arMELQi86QF\n"
+            + "cQIDAQAB\n"
+            + "-----END PUBLIC KEY-----";
 
-    static final String RSA_PRIVATE_KEY =
-        "-----BEGIN RSA PRIVATE KEY-----\n" +
-        "MIIBOgIBAAJBAOHsK2E2FLYfEMWEVH/rJMTqDZLLLyshAH5odcfhYdF9xvFFU9rq\n" +
-        "JT7zXUDH4SjdhZGUUAO5IOC1e8ZIyRsbiY0CAwEAAQJBALcu+oGJC0QcbknpIWbT\n" +
-        "L+4mZTkYXLeYu8DDTHT0j47+6eEyYBOoRGcZDdlMWquvFIrV48RSot0GPh1MBE1p\n" +
-        "lKECIQD4krM4UshCwUHH9ZVkoxcPsxzPTTW7ukky4RZVN6mgWQIhAOisOAXVVjon\n" +
-        "fbGNQ6CezH7oOttEeZmiWCu48AVCyixVAiAaDZ41OA//Vywi3i2jV6iyH47Ud347\n" +
-        "R+ImMAtcMTJZOQIgF0+Z1UvIdc8bErzad68xQc22h91WaYQQXWEL+xrz8nkCIDcA\n" +
-        "MpCP/H5qTCj/l5rxQg+/NUGCg2pHHNLL+cy5N5RM\n" +
-        "-----END RSA PRIVATE KEY-----";
+    static final String RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
+            + "MIIEpAIBAAKCAQEA3G7PGpfZx68wTY9eLb4bth3Y7MXgh1A2oqB202KTiClKy9Y+\n"
+            + "Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c0wj2e3kxwS/wiMjoYXIcbFW0iN6g\n"
+            + "1F6n71Zykf0uOE8DZKCffzjmld+Ia5M4qKsCgW4TTUODGVChBUTKui4b7Q8qsBOU\n"
+            + "TXm7SeyuZcZRChZ2w9aICZ3OR1qHnG0EXvgs0ZhCIgvtVQPaEwqMWaGYQKa8hW9X\n"
+            + "3KUvY6D8fQkQdhY2j5m/y2757tNsQWhH7l/CgdH/2F7qa3+V1yTqj9ihceLq1/Fx\n"
+            + "AZkd6q7G9YE8ZyvtoKU86o6+4arMELQi86QFcQIDAQABAoIBABkX4iqoU6nYJxsF\n"
+            + "MZbqd9QdBLc7dWph9r4/nxdENwA+lx2qN3Ny703xv+VH7u2ZSVxwvH0ZqPqn9Dwk\n"
+            + "UatAmfLqJ8j5jHDuCKdBm7aQG203unQER/G1Ds//ms5EsJDHad74K//7FcDE8A4y\n"
+            + "9bW5tfDO+5KFl3R3ycTERoG4QwSSyb8qGbA5Xo+C+9EK9ldE5f7tnryXpG/iCHem\n"
+            + "NanAF+Jxof1GanaCD6xQDug4ReEqZrWWwtco89qfNNSXEpH05hPmgl35UKO9RQn5\n"
+            + "07EtowT+WwDEQ/8zMmuL+z/hEf1LiHKCLH8oMtr6D+ENmroiMQhJ6XjlHIqp2nvB\n"
+            + "wHUR2IMCgYEA++hWbdHxZ3I+QvBIjUKF6OfWkN0ZHVWU9ZNTZoG4ggdxlm5XN+C7\n"
+            + "tohumtChIU0oNkdG38akyN5HlTg+tbd7E0ZgBnYMwAsEEXt5aEoFtFAxEorI26zr\n"
+            + "uvWqRwXNFVKTuC9+JFZvFiteYMSWzryn8dS2cNVG1hswGa1kf0Xg218CgYEA4AOS\n"
+            + "F1snvadqxocM7U8LpY8mSeXV5PayZN87GLFaK41G/zD0l+mVZAWZld9ux+rR/2OP\n"
+            + "uPWZWtn/+4v2DERukA0jerGdFocCv1s893Stoz/oVapCW0h6pa+Fa6EX2nuqNST0\n"
+            + "bE/dbHhfYditfoGQhQlOLmqrJc+B6jaOt+m7oS8CgYBVvwxMbX4inDydRHUtwEsc\n"
+            + "sG3U+a2m0o7V2MQ2zEkl2arMbdq6ZoD+7QnZINL4Ju9dKn3xhghpZ2AuZurRqBb4\n"
+            + "xKfDC0Pjytwjp0f4O9odOn65tQwR2paTGTRQ4KSicW1e8KubauB9R13kyoYa8RSp\n"
+            + "uKIxXieykaaZ1u+ycvLLOQKBgQC1PU5SRTbm82+pBZTI3t4eaa3htekTISD+CbnH\n"
+            + "ZZ39hIT/bH1H9v0d+oXjQu1fI7YZOVULoPEdFylLPFaqYCdPtsGQv+jHVB498bRm\n"
+            + "xOjDHq57uI+NSRupt1Nr297vroPsEWULyKXt34nUITllE7B4Yin11el4YuXKN6/K\n"
+            + "Tnm2kwKBgQC6Qy/DiFeF5uf0xnAkh0HFjzL+F3isIUV5l31jzna2sJSKridm+Hst\n"
+            + "mnaNDu/BKViEvSof3IpW8f7PSzskc4+Fos1KMdCkxG3bNrym8OLdWi+J4NjTbbCa\n"
+            + "sudhqm8rNr8zWFAEZ48jpcv7whYfkjCIh4z0uVNOq9dspolJaW14yg==\n"
+            + "-----END RSA PRIVATE KEY-----";
 
-    static final BigInteger RSA_MODULUS = new BigInteger(
-        "e1ec2b613614b61f10c584547feb24c4ea0d92cb2f2b21007e6875c7e161d17d" +
-        "c6f14553daea253ef35d40c7e128dd8591945003b920e0b57bc648c91b1b898d", 16);
+    static final BigInteger RSA_MODULUS =
+            new BigInteger("dc6ecf1a97d9c7af304d8f5e2dbe1bb61dd8ecc5e0875036a2a076d362938829"
+                            + "4acbd63e67e1c2c792885d77327158c07e12bba86f85fd755e1344e9cd1f1cd3"
+                            + "08f67b7931c12ff088c8e861721c6c55b488dea0d45ea7ef567291fd2e384f03"
+                            + "64a09f7f38e695df886b9338a8ab02816e134d43831950a10544caba2e1bed0f"
+                            + "2ab013944d79bb49ecae65c6510a1676c3d688099dce475a879c6d045ef82cd1"
+                            + "9842220bed5503da130a8c59a19840a6bc856f57dca52f63a0fc7d0910761636"
+                            + "8f99bfcb6ef9eed36c416847ee5fc281d1ffd85eea6b7f95d724ea8fd8a171e2"
+                            + "ead7f17101991deaaec6f5813c672beda0a53cea8ebee1aacc10b422f3a40571",
+                    16);
 
     static final BigInteger RSA_PUBLIC_EXPONENT = new BigInteger("10001", 16);
-    static final BigInteger RSA_PRIVATE_EXPONENT = new BigInteger(
-        "b72efa81890b441c6e49e92166d32fee266539185cb798bbc0c34c74f48f8efe" +
-        "e9e1326013a84467190dd94c5aabaf148ad5e3c452a2dd063e1d4c044d6994a1", 16);
+    static final BigInteger RSA_PRIVATE_EXPONENT =
+            new BigInteger("1917e22aa853a9d8271b053196ea77d41d04b73b756a61f6be3f9f174437003e"
+                            + "971daa377372ef4df1bfe547eeed99495c70bc7d19a8faa7f43c2451ab4099f2"
+                            + "ea27c8f98c70ee08a7419bb6901b6d37ba740447f1b50ecfff9ace44b090c769"
+                            + "def82bfffb15c0c4f00e32f5b5b9b5f0cefb9285977477c9c4c44681b8430492"
+                            + "c9bf2a19b0395e8f82fbd10af65744e5feed9ebc97a46fe20877a635a9c017e2"
+                            + "71a1fd466a76820fac500ee83845e12a66b596c2d728f3da9f34d4971291f4e6"
+                            + "13e6825df950a3bd4509f9d3b12da304fe5b00c443ff33326b8bfb3fe111fd4b"
+                            + "8872822c7f2832dafa0fe10d9aba22310849e978e51c8aa9da7bc1c07511d883",
+                    16);
 
     public void test_fromPublicKeyPemInputStream() throws Exception {
         ByteArrayInputStream is = new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes("UTF-8"));
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java
index ab89f450..ec4089eb 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java
@@ -19,7 +19,19 @@ package com.android.org.conscrypt;
 
 import static com.android.org.conscrypt.TestUtils.openTestFile;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+
+import org.junit.Ignore;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.FileNotFoundException;
@@ -31,12 +43,13 @@ import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
 import java.util.Arrays;
-import junit.framework.TestCase;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class OpenSSLX509CertificateTest extends TestCase {
+@RunWith(JUnit4.class)
+public class OpenSSLX509CertificateTest {
+    @Test
     public void testSerialization_NoContextDeserialization() throws Exception {
         // Set correct serialVersionUID
         {
@@ -118,6 +131,7 @@ public class OpenSSLX509CertificateTest extends TestCase {
         return OpenSSLX509Certificate.fromX509PemInputStream(openTestFile(name));
     }
 
+    @Test
     public void test_deletingCTPoisonExtension() throws Exception {
         /* certPoisoned has an extra poison extension.
          * With the extension, the certificates have different TBS.
@@ -135,6 +149,7 @@ public class OpenSSLX509CertificateTest extends TestCase {
                         cert.getTBSCertificate()));
     }
 
+    @Test
     public void test_deletingExtensionMakesCopy() throws Exception {
         /* Calling getTBSCertificateWithoutExtension should not modify the original certificate.
          * Make sure the extension is still present in the original object.
@@ -146,6 +161,7 @@ public class OpenSSLX509CertificateTest extends TestCase {
         assertTrue(certPoisoned.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
     }
 
+    @Test
     public void test_deletingMissingExtension() throws Exception {
         /* getTBSCertificateWithoutExtension should throw on a certificate without the extension.
          */
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/PlatformTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/PlatformTest.java
index abaf9966..d237c928 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/PlatformTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/PlatformTest.java
@@ -19,12 +19,18 @@ package com.android.org.conscrypt;
 
 import static com.android.org.conscrypt.TestUtils.assumeJava8;
 import static com.android.org.conscrypt.TestUtils.isJavaVersion;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 
 import com.android.org.conscrypt.testing.FailingSniMatcher;
 import com.android.org.conscrypt.testing.RestrictedAlgorithmConstraints;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.lang.reflect.Method;
 import java.net.Socket;
 import java.util.ArrayList;
@@ -32,16 +38,17 @@ import java.util.Collection;
 import java.util.Collections;
 import java.util.HashSet;
 import java.util.List;
+
 import javax.net.ssl.SNIHostName;
 import javax.net.ssl.SNIMatcher;
 import javax.net.ssl.SNIServerName;
 import javax.net.ssl.SSLParameters;
-import org.junit.Test;
 
 /**
  * Test for Platform
  * @hide This class is not part of the Android public SDK API
  */
+@RunWith(JUnit4.class)
 public class PlatformTest {
     private static final Method SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD;
     private static final Method SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD;
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/TestSessionBuilderTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/TestSessionBuilderTest.java
index 624110f4..3909a894 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/TestSessionBuilderTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/TestSessionBuilderTest.java
@@ -20,10 +20,13 @@ package com.android.org.conscrypt;
 import static org.junit.Assert.assertArrayEquals;
 
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
+@RunWith(JUnit4.class)
 public class TestSessionBuilderTest {
     @Test
     public void buildsValidBasicSession() {
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java
index d9e11c53..6e4c1c3b 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/CertBlocklistImpl.java
@@ -47,9 +47,9 @@ public final class CertBlocklistImpl implements CertBlocklist {
     private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());
 
     private final Set<BigInteger> serialBlocklist;
-    private final Set<ByteString> sha1PubkeyBlocklist;
-    private final Set<ByteString> sha256PubkeyBlocklist;
-    private Map<ByteString, Boolean> cache;
+    private final Set<ByteArray> sha1PubkeyBlocklist;
+    private final Set<ByteArray> sha256PubkeyBlocklist;
+    private Map<ByteArray, Boolean> cache;
 
     /**
      * Number of entries in the cache. The cache contains public keys which are
@@ -61,15 +61,15 @@ public final class CertBlocklistImpl implements CertBlocklist {
     /**
      * public for testing only.
      */
-    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> sha1PubkeyBlocklist) {
+    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteArray> sha1PubkeyBlocklist) {
         this(serialBlocklist, sha1PubkeyBlocklist, Collections.emptySet());
     }
 
-    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> sha1PubkeyBlocklist,
-            Set<ByteString> sha256PubkeyBlocklist) {
-        this.cache = Collections.synchronizedMap(new LinkedHashMap<ByteString, Boolean>() {
+    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteArray> sha1PubkeyBlocklist,
+            Set<ByteArray> sha256PubkeyBlocklist) {
+        this.cache = Collections.synchronizedMap(new LinkedHashMap<ByteArray, Boolean>() {
             @Override
-            protected boolean removeEldestEntry(Map.Entry<ByteString, Boolean> eldest) {
+            protected boolean removeEldestEntry(Map.Entry<ByteArray, Boolean> eldest) {
                 return size() > CACHE_SIZE;
             }
         });
@@ -85,9 +85,9 @@ public final class CertBlocklistImpl implements CertBlocklist {
         String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";
         String defaultPubkeySha256BlocklistPath = blocklistRoot + "pubkey_sha256_blocklist.txt";
 
-        Set<ByteString> sha1PubkeyBlocklist =
+        Set<ByteArray> sha1PubkeyBlocklist =
                 readPublicKeyBlockList(defaultPubkeyBlocklistPath, "SHA-1");
-        Set<ByteString> sha256PubkeyBlocklist =
+        Set<ByteArray> sha256PubkeyBlocklist =
                 readPublicKeyBlockList(defaultPubkeySha256BlocklistPath, "SHA-256");
         Set<BigInteger> serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
         return new CertBlocklistImpl(serialBlocklist, sha1PubkeyBlocklist, sha256PubkeyBlocklist);
@@ -224,15 +224,15 @@ public final class CertBlocklistImpl implements CertBlocklist {
             "809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd".getBytes(UTF_8),
     };
 
-    private static Set<ByteString> readPublicKeyBlockList(String path, String hashType) {
-        Set<ByteString> bl;
+    private static Set<ByteArray> readPublicKeyBlockList(String path, String hashType) {
+        Set<ByteArray> bl;
 
         switch (hashType) {
             case "SHA-1":
-                bl = new HashSet<ByteString>(toByteStrings(SHA1_BUILTINS));
+                bl = new HashSet<ByteArray>(toByteArrays(SHA1_BUILTINS));
                 break;
             case "SHA-256":
-                bl = new HashSet<ByteString>(toByteStrings(SHA256_BUILTINS));
+                bl = new HashSet<ByteArray>(toByteArrays(SHA256_BUILTINS));
                 break;
             default:
                 throw new RuntimeException(
@@ -256,7 +256,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
             for (String value : pubkeyBlocklist.split(",", -1)) {
                 value = value.trim();
                 if (isPubkeyHash(value, hashLength)) {
-                    bl.add(new ByteString(value.getBytes(UTF_8)));
+                    bl.add(new ByteArray(value.getBytes(UTF_8)));
                 } else {
                     logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                 }
@@ -267,7 +267,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
     }
 
     private static boolean isPublicKeyBlockListed(
-            ByteString encodedPublicKey, Set<ByteString> blocklist, String hashType) {
+            byte[] encodedPublicKey, Set<ByteArray> blocklist, String hashType) {
         MessageDigest md;
         try {
             md = MessageDigest.getInstance(hashType);
@@ -275,7 +275,7 @@ public final class CertBlocklistImpl implements CertBlocklist {
             logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
             return false;
         }
-        ByteString out = new ByteString(toHex(md.digest(encodedPublicKey.bytes)));
+        ByteArray out = new ByteArray(toHex(md.digest(encodedPublicKey)));
         if (blocklist.contains(out)) {
             return true;
         }
@@ -284,24 +284,28 @@ public final class CertBlocklistImpl implements CertBlocklist {
 
     @Override
     public boolean isPublicKeyBlockListed(PublicKey publicKey) {
-        ByteString encodedPublicKey = new ByteString(publicKey.getEncoded());
-        Boolean cachedResult = cache.get(encodedPublicKey);
+        byte[] encodedPublicKey = publicKey.getEncoded();
+        // cacheKey is a view on encodedPublicKey. Because it is used as a key
+        // for a Map, its underlying array (encodedPublicKey) should not be
+        // modified.
+        ByteArray cacheKey = new ByteArray(encodedPublicKey);
+        Boolean cachedResult = cache.get(cacheKey);
         if (cachedResult != null) {
             return cachedResult.booleanValue();
         }
         if (!sha1PubkeyBlocklist.isEmpty()) {
             if (isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, "SHA-1")) {
-                cache.put(encodedPublicKey, true);
+                cache.put(cacheKey, true);
                 return true;
             }
         }
         if (!sha256PubkeyBlocklist.isEmpty()) {
             if (isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, "SHA-256")) {
-                cache.put(encodedPublicKey, true);
+                cache.put(cacheKey, true);
                 return true;
             }
         }
-        cache.put(encodedPublicKey, false);
+        cache.put(cacheKey, false);
         return false;
     }
 
@@ -325,37 +329,11 @@ public final class CertBlocklistImpl implements CertBlocklist {
         return serialBlocklist.contains(serial);
     }
 
-    private static List<ByteString> toByteStrings(byte[]... allBytes) {
-        List<ByteString> byteStrings = new ArrayList<>(allBytes.length + 1);
+    private static List<ByteArray> toByteArrays(byte[]... allBytes) {
+        List<ByteArray> byteArrays = new ArrayList<>(allBytes.length + 1);
         for (byte[] bytes : allBytes) {
-            byteStrings.add(new ByteString(bytes));
-        }
-        return byteStrings;
-    }
-
-    private static class ByteString {
-        final byte[] bytes;
-
-        public ByteString(byte[] bytes) {
-            this.bytes = bytes;
-        }
-
-        @Override
-        public boolean equals(Object o) {
-            if (o == this) {
-                return true;
-            }
-            if (!(o instanceof ByteString)) {
-                return false;
-            }
-
-            ByteString other = (ByteString) o;
-            return Arrays.equals(bytes, other.bytes);
-        }
-
-        @Override
-        public int hashCode() {
-            return Arrays.hashCode(bytes);
+            byteArrays.add(new ByteArray(bytes));
         }
+        return byteArrays;
     }
 }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/InternalUtil.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/InternalUtil.java
deleted file mode 100644
index bf3f0433..00000000
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/InternalUtil.java
+++ /dev/null
@@ -1,48 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright 2017 The Android Open Source Project
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
-package com.android.org.conscrypt;
-
-import java.io.InputStream;
-import java.security.InvalidKeyException;
-import java.security.NoSuchAlgorithmException;
-import java.security.PublicKey;
-import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
-
-/**
- * Helper to initialize the JNI libraries. This version runs when compiled
- * as part of the platform.
- * @hide This class is not part of the Android public SDK API
- */
-@Internal
-public final class InternalUtil {
-    public static PublicKey logKeyToPublicKey(byte[] logKey)
-            throws NoSuchAlgorithmException {
-        try {
-            return new OpenSSLKey(NativeCrypto.EVP_parse_public_key(logKey)).getPublicKey();
-        } catch (ParsingException e) {
-            throw new NoSuchAlgorithmException(e);
-        }
-    }
-
-    public static PublicKey readPublicKeyPem(InputStream pem) throws InvalidKeyException, NoSuchAlgorithmException {
-        return OpenSSLKey.fromPublicKeyPemInputStream(pem).getPublicKey();
-    }
-
-    private InternalUtil() {
-    }
-}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
index 59bc8100..247c8bfe 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
@@ -19,22 +19,28 @@ package com.android.org.conscrypt;
 
 import static android.system.OsConstants.SOL_SOCKET;
 import static android.system.OsConstants.SO_SNDTIMEO;
+
 import static com.android.org.conscrypt.metrics.Source.SOURCE_MAINLINE;
 
 import android.system.ErrnoException;
 import android.system.Os;
 import android.system.StructTimeval;
-import com.android.org.conscrypt.ct.CTLogStore;
-import com.android.org.conscrypt.ct.CTLogStoreImpl;
-import com.android.org.conscrypt.ct.CTPolicy;
-import com.android.org.conscrypt.ct.CTPolicyImpl;
+
+import com.android.org.conscrypt.ct.LogStore;
+import com.android.org.conscrypt.ct.LogStoreImpl;
+import com.android.org.conscrypt.ct.Policy;
+import com.android.org.conscrypt.ct.PolicyImpl;
 import com.android.org.conscrypt.metrics.CipherSuite;
 import com.android.org.conscrypt.metrics.ConscryptStatsLog;
 import com.android.org.conscrypt.metrics.OptionalMethod;
 import com.android.org.conscrypt.metrics.Protocol;
+
 import dalvik.system.BlockGuard;
 import dalvik.system.CloseGuard;
 import dalvik.system.VMRuntime;
+
+import libcore.net.NetworkSecurityPolicy;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.lang.System;
@@ -59,6 +65,7 @@ import java.security.spec.InvalidParameterSpecException;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.List;
+
 import javax.crypto.spec.GCMParameterSpec;
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SNIHostName;
@@ -71,6 +78,7 @@ import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
+
 import sun.security.x509.AlgorithmId;
 
 final class Platform {
@@ -464,6 +472,10 @@ final class Platform {
     }
 
     static boolean isCTVerificationRequired(String hostname) {
+        if (Flags.certificateTransparencyPlatform()) {
+            return NetworkSecurityPolicy.getInstance()
+                    .isCertificateTransparencyVerificationRequired(hostname);
+        }
         return false;
     }
 
@@ -489,12 +501,12 @@ final class Platform {
         return CertBlocklistImpl.getDefault();
     }
 
-    static CTLogStore newDefaultLogStore() {
-        return new CTLogStoreImpl();
+    static LogStore newDefaultLogStore() {
+        return new LogStoreImpl();
     }
 
-    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
-        return new CTPolicyImpl(logStore, 2);
+    static Policy newDefaultPolicy() {
+        return new PolicyImpl();
     }
 
     static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/TEST_MAPPING b/repackaged/platform/src/main/java/com/android/org/conscrypt/TEST_MAPPING
deleted file mode 100644
index 04c40624..00000000
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "external/conscrypt/repackaged/common/src/main/java/com/android/org/conscrypt"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/TrustedCertificateStore.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/TrustedCertificateStore.java
index 7967ab81..0143a569 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/TrustedCertificateStore.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/TrustedCertificateStore.java
@@ -17,8 +17,10 @@
 
 package com.android.org.conscrypt;
 
+import com.android.org.conscrypt.ArrayUtils;
 import com.android.org.conscrypt.io.IoUtils;
 import com.android.org.conscrypt.metrics.OptionalMethod;
+
 import java.io.BufferedInputStream;
 import java.io.File;
 import java.io.FileInputStream;
@@ -37,6 +39,7 @@ import java.util.HashSet;
 import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Set;
+
 import javax.security.auth.x500.X500Principal;
 
 /**
@@ -120,7 +123,7 @@ public class TrustedCertificateStore implements ConscryptCertStore {
             if ((System.getProperty("system.certs.enabled") != null)
                     && (System.getProperty("system.certs.enabled")).equals("true"))
                 return false;
-            if (updatableDir.exists() && !(updatableDir.list().length == 0))
+            if (updatableDir.exists() && !(ArrayUtils.isEmpty(updatableDir.list())))
                 return true;
             return false;
         }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/CTLogStoreImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/CTLogStoreImpl.java
deleted file mode 100644
index d34b683c..00000000
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/CTLogStoreImpl.java
+++ /dev/null
@@ -1,263 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package com.android.org.conscrypt.ct;
-
-import com.android.org.conscrypt.Internal;
-import com.android.org.conscrypt.InternalUtil;
-import java.io.ByteArrayInputStream;
-import java.io.File;
-import java.io.FileInputStream;
-import java.io.FileNotFoundException;
-import java.io.InputStream;
-import java.nio.ByteBuffer;
-import java.nio.charset.Charset;
-import java.nio.charset.StandardCharsets;
-import java.security.InvalidKeyException;
-import java.security.NoSuchAlgorithmException;
-import java.security.PublicKey;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.HashSet;
-import java.util.Scanner;
-import java.util.Set;
-
-/**
- * @hide This class is not part of the Android public SDK API
- */
-@Internal
-public class CTLogStoreImpl implements CTLogStore {
-    private static final Charset US_ASCII = StandardCharsets.US_ASCII;
-
-    /**
-     * Thrown when parsing of a log file fails.
-     * @hide This class is not part of the Android public SDK API
-     */
-    public static class InvalidLogFileException extends Exception {
-        public InvalidLogFileException() {
-        }
-
-        public InvalidLogFileException(String message) {
-            super(message);
-        }
-
-        public InvalidLogFileException(String message, Throwable cause) {
-            super(message, cause);
-        }
-
-        public InvalidLogFileException(Throwable cause) {
-            super(cause);
-        }
-    }
-
-    private static final File defaultUserLogDir;
-    private static final File defaultSystemLogDir;
-    // Lazy loaded by CTLogStoreImpl()
-    private static volatile CTLogInfo[] defaultFallbackLogs = null;
-    static {
-        String ANDROID_DATA = System.getenv("ANDROID_DATA");
-        String ANDROID_ROOT = System.getenv("ANDROID_ROOT");
-        defaultUserLogDir = new File(ANDROID_DATA + "/misc/keychain/trusted_ct_logs/current/");
-        defaultSystemLogDir = new File(ANDROID_ROOT + "/etc/security/ct_known_logs/");
-    }
-
-    private final File userLogDir;
-    private final File systemLogDir;
-    private final CTLogInfo[] fallbackLogs;
-
-    private final HashMap<ByteBuffer, CTLogInfo> logCache = new HashMap<>();
-    private final Set<ByteBuffer> missingLogCache =
-            Collections.synchronizedSet(new HashSet<ByteBuffer>());
-
-    public CTLogStoreImpl() {
-        this(defaultUserLogDir,
-             defaultSystemLogDir,
-             getDefaultFallbackLogs());
-    }
-
-    public CTLogStoreImpl(File userLogDir, File systemLogDir, CTLogInfo[] fallbackLogs) {
-        this.userLogDir = userLogDir;
-        this.systemLogDir = systemLogDir;
-        this.fallbackLogs = fallbackLogs;
-    }
-
-    @Override
-    public CTLogInfo getKnownLog(byte[] logId) {
-        ByteBuffer buf = ByteBuffer.wrap(logId);
-        CTLogInfo log = logCache.get(buf);
-        if (log != null) {
-            return log;
-        }
-        if (missingLogCache.contains(buf)) {
-            return null;
-        }
-
-        log = findKnownLog(logId);
-        if (log != null) {
-            logCache.put(buf, log);
-        } else {
-            missingLogCache.add(buf);
-        }
-
-        return log;
-    }
-
-    private CTLogInfo findKnownLog(byte[] logId) {
-        String filename = hexEncode(logId);
-        try {
-            return loadLog(new File(userLogDir, filename));
-        } catch (InvalidLogFileException e) {
-            return null;
-        } catch (FileNotFoundException e) {
-            // Ignored
-        }
-
-        try {
-            return loadLog(new File(systemLogDir, filename));
-        } catch (InvalidLogFileException e) {
-            return null;
-        } catch (FileNotFoundException e) {
-            // Ignored
-        }
-
-        // If the updateable logs dont exist then use the fallback logs.
-        if (!userLogDir.exists()) {
-            for (CTLogInfo log: fallbackLogs) {
-                if (Arrays.equals(logId, log.getID())) {
-                    return log;
-                }
-            }
-        }
-        return null;
-    }
-
-    public static CTLogInfo[] getDefaultFallbackLogs() {
-        CTLogInfo[] result = defaultFallbackLogs;
-        if (result == null) {
-            // single-check idiom
-            defaultFallbackLogs = result = createDefaultFallbackLogs();
-        }
-        return result;
-    }
-
-    private static CTLogInfo[] createDefaultFallbackLogs() {
-        CTLogInfo[] logs = new CTLogInfo[KnownLogs.LOG_COUNT];
-        for (int i = 0; i < KnownLogs.LOG_COUNT; i++) {
-            try {
-                PublicKey key = InternalUtil.logKeyToPublicKey(KnownLogs.LOG_KEYS[i]);
-
-                logs[i] = new CTLogInfo(key,
-                                        KnownLogs.LOG_DESCRIPTIONS[i],
-                                        KnownLogs.LOG_URLS[i]);
-            } catch (NoSuchAlgorithmException e) {
-                throw new RuntimeException(e);
-            }
-        }
-
-        defaultFallbackLogs = logs;
-        return logs;
-    }
-
-    /**
-     * Load a CTLogInfo from a file.
-     * @throws FileNotFoundException if the file does not exist
-     * @throws InvalidLogFileException if the file could not be parsed properly
-     * @return a CTLogInfo or null if the file is empty
-     */
-    public static CTLogInfo loadLog(File file) throws FileNotFoundException,
-                                                      InvalidLogFileException {
-        return loadLog(new FileInputStream(file));
-    }
-
-    /**
-     * Load a CTLogInfo from a textual representation. Closes {@code input} upon completion
-     * of loading.
-     *
-     * @throws InvalidLogFileException if the input could not be parsed properly
-     * @return a CTLogInfo or null if the input is empty
-     */
-    public static CTLogInfo loadLog(InputStream input) throws InvalidLogFileException {
-        final Scanner scan = new Scanner(input, "UTF-8");
-        scan.useDelimiter("\n");
-
-        String description = null;
-        String url = null;
-        String key = null;
-        try {
-            // If the scanner can't even read one token then the file must be empty/blank
-            if (!scan.hasNext()) {
-                return null;
-            }
-
-            while (scan.hasNext()) {
-                String[] parts = scan.next().split(":", 2);
-                if (parts.length < 2) {
-                    continue;
-                }
-
-                String name = parts[0];
-                String value = parts[1];
-                switch (name) {
-                    case "description":
-                        description = value;
-                        break;
-                    case "url":
-                        url = value;
-                        break;
-                    case "key":
-                        key = value;
-                        break;
-                }
-            }
-        } finally {
-            scan.close();
-        }
-
-        if (description == null || url == null || key == null) {
-            throw new InvalidLogFileException("Missing one of 'description', 'url' or 'key'");
-        }
-
-        PublicKey pubkey;
-        try {
-            pubkey = InternalUtil.readPublicKeyPem(new ByteArrayInputStream(
-                    ("-----BEGIN PUBLIC KEY-----\n" +
-                        key + "\n" +
-                        "-----END PUBLIC KEY-----").getBytes(US_ASCII)));
-        } catch (InvalidKeyException e) {
-            throw new InvalidLogFileException(e);
-        } catch (NoSuchAlgorithmException e) {
-            throw new InvalidLogFileException(e);
-        }
-
-        return new CTLogInfo(pubkey, description, url);
-    }
-
-    private final static char[] HEX_DIGITS = new char[] {
-        '0', '1', '2', '3', '4', '5', '6', '7',
-        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
-    };
-
-    private static String hexEncode(byte[] data) {
-        StringBuilder sb = new StringBuilder(data.length * 2);
-        for (byte b: data) {
-            sb.append(HEX_DIGITS[(b >> 4) & 0x0f]);
-            sb.append(HEX_DIGITS[b & 0x0f]);
-        }
-        return sb.toString();
-    }
-}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/CTPolicyImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/CTPolicyImpl.java
deleted file mode 100644
index aa22b950..00000000
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/CTPolicyImpl.java
+++ /dev/null
@@ -1,51 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package com.android.org.conscrypt.ct;
-
-import java.security.cert.X509Certificate;
-import java.util.HashSet;
-import java.util.Set;
-import com.android.org.conscrypt.Internal;
-
-/**
- * @hide This class is not part of the Android public SDK API
- */
-@Internal
-public class CTPolicyImpl implements CTPolicy {
-    private final CTLogStore logStore;
-    private final int minimumLogCount;
-
-    public CTPolicyImpl(CTLogStore logStore, int minimumLogCount) {
-        this.logStore = logStore;
-        this.minimumLogCount = minimumLogCount;
-    }
-
-    @Override
-    public boolean doesResultConformToPolicy(CTVerificationResult result, String hostname,
-                                             X509Certificate[] chain) {
-        Set<CTLogInfo> logSet = new HashSet<>();
-        for (VerifiedSCT verifiedSCT: result.getValidSCTs()) {
-            CTLogInfo log = logStore.getKnownLog(verifiedSCT.sct.getLogID());
-            if (log != null) {
-                logSet.add(log);
-            }
-        }
-
-        return logSet.size() >= minimumLogCount;
-    }
-}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/KnownLogs.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/KnownLogs.java
deleted file mode 100644
index 7d6dca11..00000000
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/KnownLogs.java
+++ /dev/null
@@ -1,138 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-/* This file is generated by print_log_list.py
- * https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py */
-
-package com.android.org.conscrypt.ct;
-
-import com.android.org.conscrypt.Internal;
-
-/**
- * @hide This class is not part of the Android public SDK API
- */
-@Internal
-public final class KnownLogs {
-    public static final int LOG_COUNT = 8;
-    public static final String[] LOG_DESCRIPTIONS = new String[] {
-        "Google 'Pilot' log",
-        "Google 'Aviator' log",
-        "DigiCert Log Server",
-        "Google 'Rocketeer' log",
-        "Certly.IO log",
-        "Izenpe log",
-        "Symantec log",
-        "Venafi log",
-    };
-    public static final String[] LOG_URLS = new String[] {
-        "ct.googleapis.com/pilot",
-        "ct.googleapis.com/aviator",
-        "ct1.digicert-ct.com/log",
-        "ct.googleapis.com/rocketeer",
-        "log.certly.io",
-        "ct.izenpe.com",
-        "ct.ws.symantec.com",
-        "ctlog.api.venafi.com",
-    };
-    public static final byte[][] LOG_KEYS = new byte[][] {
-        // Google 'Pilot' log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 125, -88, 75, 18, 41, -128, -93, 61, -83,
-            -45, 90, 119, -72, -52, -30, -120, -77, -91, -3, -15, -45, 12, -51, 24,
-            12, -24, 65, 70, -24, -127, 1, 27, 21, -31, 75, -15, 27, 98, -35, 54, 10,
-            8, 24, -70, -19, 11, 53, -124, -48, -98, 64, 60, 45, -98, -101, -126,
-            101, -67, 31, 4, 16, 65, 76, -96
-        },
-        // Google 'Aviator' log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, -41, -12, -52, 105, -78, -28, 14, -112,
-            -93, -118, -22, 90, 112, 9, 79, -17, 19, 98, -48, -115, 73, 96, -1, 27,
-            64, 80, 7, 12, 109, 113, -122, -38, 37, 73, -115, 101, -31, 8, 13, 71,
-            52, 107, -67, 39, -68, -106, 33, 62, 52, -11, -121, 118, 49, -79, 127,
-            29, -55, -123, 59, 13, -9, 31, 63, -23
-        },
-        // DigiCert Log Server
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 2, 70, -59, -66, 27, -69, -126, 64, 22,
-            -24, -63, -46, -84, 25, 105, 19, 89, -8, -8, 112, -123, 70, 64, -71, 56,
-            -80, 35, -126, -88, 100, 76, 127, -65, -69, 52, -97, 74, 95, 40, -118,
-            -49, 25, -60, 0, -10, 54, 6, -109, 101, -19, 76, -11, -87, 33, 98, 90,
-            -40, -111, -21, 56, 36, 64, -84, -24
-        },
-        // Google 'Rocketeer' log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 32, 91, 24, -56, 60, -63, -117, -77, 49,
-            8, 0, -65, -96, -112, 87, 43, -73, 71, -116, 111, -75, 104, -80, -114,
-            -112, 120, -23, -96, 115, -22, 79, 40, 33, 46, -100, -64, -12, 22, 27,
-            -86, -7, -43, -41, -87, -128, -61, 78, 47, 82, 60, -104, 1, 37, 70, 36,
-            37, 40, 35, 119, 45, 5, -62, 64, 122
-        },
-        // Certly.IO log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 11, 35, -53, -123, 98, -104, 97, 72, 4,
-            115, -21, 84, 93, -13, -48, 7, -116, 45, 25, 45, -116, 54, -11, -21,
-            -113, 1, 66, 10, 124, -104, 38, 39, -63, -75, -35, -110, -109, -80, -82,
-            -8, -101, 61, 12, -40, 76, 78, 29, -7, 21, -5, 71, 104, 123, -70, 102,
-            -73, 37, -100, -48, 74, -62, 102, -37, 72
-        },
-        // Izenpe log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, 39, 100, 57, 12, 45, -36, 80, 24, -8, 33,
-            0, -94, 14, -19, 44, -22, 62, 117, -70, -97, -109, 100, 9, 0, 17, -60,
-            17, 23, -85, 92, -49, 15, 116, -84, -75, -105, -112, -109, 0, 91, -72,
-            -21, -9, 39, 61, -39, -78, 10, -127, 95, 47, 13, 117, 56, -108, 55, -103,
-            30, -10, 7, 118, -32, -18, -66
-        },
-        // Symantec log
-        new byte[] {
-            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
-            -50, 61, 3, 1, 7, 3, 66, 0, 4, -106, -22, -84, 28, 70, 12, 27, 85, -36,
-            13, -4, -75, -108, 39, 70, 87, 66, 112, 58, 105, 24, -30, -65, 59, -60,
-            -37, -85, -96, -12, -74, 108, -64, 83, 63, 77, 66, 16, 51, -16, 88, -105,
-            -113, 107, -66, 114, -12, 42, -20, 28, 66, -86, 3, 47, 26, 126, 40, 53,
-            118, -103, 8, 61, 33, 20, -122
-        },
-        // Venafi log
-        new byte[] {
-            48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0,
-            3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -94, 90, 72, 31,
-            23, 82, -107, 53, -53, -93, 91, 58, 31, 83, -126, 118, -108, -93, -1,
-            -128, -14, 28, 55, 60, -64, -79, -67, -63, 89, -117, -85, 45, 101, -109,
-            -41, -13, -32, 4, -43, -102, 111, -65, -42, 35, 118, 54, 79, 35, -103,
-            -53, 84, 40, -83, -116, 21, 75, 101, 89, 118, 65, 74, -100, -90, -9, -77,
-            59, 126, -79, -91, 73, -92, 23, 81, 108, -128, -36, 42, -112, 80, 75,
-            -120, 36, -23, -91, 18, 50, -109, 4, 72, -112, 2, -6, 95, 14, 48, -121,
-            -114, 85, 118, 5, -18, 42, 76, -50, -93, 106, 105, 9, 110, 37, -83, -126,
-            118, 15, -124, -110, -6, 56, -42, -122, 78, 36, -113, -101, -80, 114,
-            -53, -98, -30, 107, 63, -31, 109, -55, 37, 117, 35, -120, -95, 24, 88, 6,
-            35, 51, 120, -38, 0, -48, 56, -111, 103, -46, -90, 125, 39, -105, 103,
-            90, -63, -13, 47, 23, -26, -22, -46, 91, -24, -127, -51, -3, -110, 104,
-            -25, -13, 6, -16, -23, 114, -124, -18, 1, -91, -79, -40, 51, -38, -50,
-            -125, -91, -37, -57, -49, -42, 22, 126, -112, 117, 24, -65, 22, -36, 50,
-            59, 109, -115, -85, -126, 23, 31, -119, 32, -115, 29, -102, -26, 77, 35,
-            8, -33, 120, 111, -58, 5, -65, 95, -82, -108, -105, -37, 95, 100, -44,
-            -18, 22, -117, -93, -124, 108, 113, 43, -15, -85, 127, 93, 13, 50, -18,
-            4, -30, -112, -20, 65, -97, -5, 57, -63, 2, 3, 1, 0, 1
-        },
-    };
-}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
new file mode 100644
index 00000000..be57cb71
--- /dev/null
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
@@ -0,0 +1,236 @@
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
+package com.android.org.conscrypt.ct;
+
+import static java.nio.charset.StandardCharsets.US_ASCII;
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import com.android.org.conscrypt.ByteArray;
+import com.android.org.conscrypt.Internal;
+import com.android.org.conscrypt.OpenSSLKey;
+
+import org.json.JSONArray;
+import org.json.JSONException;
+import org.json.JSONObject;
+
+import java.io.ByteArrayInputStream;
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.NoSuchFileException;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.security.PublicKey;
+import java.text.DateFormat;
+import java.text.ParseException;
+import java.text.SimpleDateFormat;
+import java.util.Arrays;
+import java.util.Base64;
+import java.util.Collections;
+import java.util.Date;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.logging.Level;
+import java.util.logging.Logger;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class LogStoreImpl implements LogStore {
+    private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
+    public static final String V3_PATH = "/misc/keychain/ct/v3/log_list.json";
+    private static final Path defaultLogList;
+
+    static {
+        String ANDROID_DATA = System.getenv("ANDROID_DATA");
+        defaultLogList = Paths.get(ANDROID_DATA, V3_PATH);
+    }
+
+    private final Path logList;
+    private State state;
+    private Policy policy;
+    private String version;
+    private long timestamp;
+    private Map<ByteArray, LogInfo> logs;
+
+    public LogStoreImpl() {
+        this(defaultLogList);
+    }
+
+    public LogStoreImpl(Path logList) {
+        this.state = State.UNINITIALIZED;
+        this.logList = logList;
+    }
+
+    @Override
+    public State getState() {
+        ensureLogListIsLoaded();
+        return state;
+    }
+
+    @Override
+    public long getTimestamp() {
+        return timestamp;
+    }
+
+    @Override
+    public void setPolicy(Policy policy) {
+        this.policy = policy;
+    }
+
+    @Override
+    public LogInfo getKnownLog(byte[] logId) {
+        if (logId == null) {
+            return null;
+        }
+        if (!ensureLogListIsLoaded()) {
+            return null;
+        }
+        ByteArray buf = new ByteArray(logId);
+        LogInfo log = logs.get(buf);
+        if (log != null) {
+            return log;
+        }
+        return null;
+    }
+
+    /* Ensures the log list is loaded.
+     * Returns true if the log list is usable.
+     */
+    private boolean ensureLogListIsLoaded() {
+        synchronized (this) {
+            if (state == State.UNINITIALIZED) {
+                state = loadLogList();
+            }
+            if (state == State.LOADED && policy != null) {
+                state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
+            }
+            return state == State.COMPLIANT;
+        }
+    }
+
+    private State loadLogList() {
+        byte[] content;
+        try {
+            content = Files.readAllBytes(logList);
+        } catch (IOException e) {
+            return State.NOT_FOUND;
+        }
+        if (content == null) {
+            return State.NOT_FOUND;
+        }
+        JSONObject json;
+        try {
+            json = new JSONObject(new String(content, UTF_8));
+        } catch (JSONException e) {
+            logger.log(Level.WARNING, "Unable to parse log list", e);
+            return State.MALFORMED;
+        }
+        HashMap<ByteArray, LogInfo> logsMap = new HashMap<>();
+        try {
+            version = json.getString("version");
+            timestamp = parseTimestamp(json.getString("log_list_timestamp"));
+            JSONArray operators = json.getJSONArray("operators");
+            for (int i = 0; i < operators.length(); i++) {
+                JSONObject operator = operators.getJSONObject(i);
+                String operatorName = operator.getString("name");
+                JSONArray logs = operator.getJSONArray("logs");
+                for (int j = 0; j < logs.length(); j++) {
+                    JSONObject log = logs.getJSONObject(j);
+
+                    LogInfo.Builder builder =
+                            new LogInfo.Builder()
+                                    .setDescription(log.getString("description"))
+                                    .setPublicKey(parsePubKey(log.getString("key")))
+                                    .setUrl(log.getString("url"))
+                                    .setOperator(operatorName);
+
+                    JSONObject stateObject = log.optJSONObject("state");
+                    if (stateObject != null) {
+                        String state = stateObject.keys().next();
+                        String stateTimestamp =
+                                stateObject.getJSONObject(state).getString("timestamp");
+                        builder.setState(parseState(state), parseTimestamp(stateTimestamp));
+                    }
+
+                    LogInfo logInfo = builder.build();
+                    byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
+
+                    // The logId computed using the public key should match the log_id field.
+                    if (!Arrays.equals(logInfo.getID(), logId)) {
+                        throw new IllegalArgumentException("logId does not match publicKey");
+                    }
+
+                    logsMap.put(new ByteArray(logId), logInfo);
+                }
+            }
+        } catch (JSONException | IllegalArgumentException e) {
+            logger.log(Level.WARNING, "Unable to parse log list", e);
+            return State.MALFORMED;
+        }
+        this.logs = Collections.unmodifiableMap(logsMap);
+        return State.LOADED;
+    }
+
+    private static int parseState(String state) {
+        switch (state) {
+            case "pending":
+                return LogInfo.STATE_PENDING;
+            case "qualified":
+                return LogInfo.STATE_QUALIFIED;
+            case "usable":
+                return LogInfo.STATE_USABLE;
+            case "readonly":
+                return LogInfo.STATE_READONLY;
+            case "retired":
+                return LogInfo.STATE_RETIRED;
+            case "rejected":
+                return LogInfo.STATE_REJECTED;
+            default:
+                throw new IllegalArgumentException("Unknown log state: " + state);
+        }
+    }
+
+    // ISO 8601
+    private static DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
+
+    @SuppressWarnings("JavaUtilDate")
+    private static long parseTimestamp(String timestamp) {
+        try {
+            Date date = dateFormatter.parse(timestamp);
+            return date.getTime();
+        } catch (ParseException e) {
+            throw new IllegalArgumentException(e);
+        }
+    }
+
+    private static PublicKey parsePubKey(String key) {
+        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----")
+                             .getBytes(US_ASCII);
+        PublicKey pubkey;
+        try {
+            pubkey = OpenSSLKey.fromPublicKeyPemInputStream(new ByteArrayInputStream(pem))
+                             .getPublicKey();
+        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
+            throw new IllegalArgumentException(e);
+        }
+        return pubkey;
+    }
+}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
new file mode 100644
index 00000000..a1b0edef
--- /dev/null
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
@@ -0,0 +1,192 @@
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
+package com.android.org.conscrypt.ct;
+
+import com.android.org.conscrypt.Internal;
+
+import java.security.cert.X509Certificate;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.HashSet;
+import java.util.Iterator;
+import java.util.List;
+import java.util.Set;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class PolicyImpl implements Policy {
+    @Override
+    public boolean isLogStoreCompliant(LogStore store) {
+        long now = System.currentTimeMillis();
+        return isLogStoreCompliantAt(store, now);
+    }
+
+    public boolean isLogStoreCompliantAt(LogStore store, long atTime) {
+        long storeTimestamp = store.getTimestamp();
+        long seventyDaysInMs = 70L * 24 * 60 * 60 * 1000;
+        if (storeTimestamp + seventyDaysInMs < atTime) {
+            // Expired log list.
+            return false;
+        } else if (storeTimestamp > atTime) {
+            // Log list from the future. It is likely that the device has an
+            // incorrect time.
+            return false;
+        }
+        return true;
+    }
+
+    @Override
+    public PolicyCompliance doesResultConformToPolicy(
+            VerificationResult result, X509Certificate leaf) {
+        long now = System.currentTimeMillis();
+        return doesResultConformToPolicyAt(result, leaf, now);
+    }
+
+    public PolicyCompliance doesResultConformToPolicyAt(
+            VerificationResult result, X509Certificate leaf, long atTime) {
+        List<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>(result.getValidSCTs());
+        /* While the log list supports logs without a state, these entries are
+         * not supported by the log policy. Filter them out. */
+        filterOutUnknown(validSCTs);
+        /* Filter out any SCT issued after a log was retired */
+        filterOutAfterRetired(validSCTs);
+
+        Set<VerifiedSCT> embeddedValidSCTs = new HashSet<>();
+        Set<VerifiedSCT> ocspOrTLSValidSCTs = new HashSet<>();
+        for (VerifiedSCT vsct : validSCTs) {
+            if (vsct.getSct().getOrigin() == SignedCertificateTimestamp.Origin.EMBEDDED) {
+                embeddedValidSCTs.add(vsct);
+            } else {
+                ocspOrTLSValidSCTs.add(vsct);
+            }
+        }
+        if (embeddedValidSCTs.size() > 0) {
+            return conformEmbeddedSCTs(embeddedValidSCTs, leaf, atTime);
+        }
+        return PolicyCompliance.NOT_ENOUGH_SCTS;
+    }
+
+    private void filterOutUnknown(List<VerifiedSCT> scts) {
+        Iterator<VerifiedSCT> it = scts.iterator();
+        while (it.hasNext()) {
+            VerifiedSCT vsct = it.next();
+            if (vsct.getLogInfo().getState() == LogInfo.STATE_UNKNOWN) {
+                it.remove();
+            }
+        }
+    }
+
+    private void filterOutAfterRetired(List<VerifiedSCT> scts) {
+        /* From the policy:
+         *
+         * In order to contribute to a certificate’s CT Compliance, an SCT must
+         * have been issued before the Log’s Retired timestamp, if one exists.
+         * Chrome uses the earliest SCT among all SCTs presented to evaluate CT
+         * compliance against CT Log Retired timestamps. This accounts for edge
+         * cases in which a CT Log becomes Retired during the process of
+         * submitting certificate logging requests.
+         */
+
+        if (scts.size() < 1) {
+            return;
+        }
+        long minTimestamp = scts.get(0).getSct().getTimestamp();
+        for (VerifiedSCT vsct : scts) {
+            long ts = vsct.getSct().getTimestamp();
+            if (ts < minTimestamp) {
+                minTimestamp = ts;
+            }
+        }
+        Iterator<VerifiedSCT> it = scts.iterator();
+        while (it.hasNext()) {
+            VerifiedSCT vsct = it.next();
+            if (vsct.getLogInfo().getState() == LogInfo.STATE_RETIRED
+                    && minTimestamp > vsct.getLogInfo().getStateTimestamp()) {
+                it.remove();
+            }
+        }
+    }
+
+    private PolicyCompliance conformEmbeddedSCTs(
+            Set<VerifiedSCT> embeddedValidSCTs, X509Certificate leaf, long atTime) {
+        /* 1. At least one Embedded SCT from a CT Log that was Qualified,
+         *    Usable, or ReadOnly at the time of check;
+         */
+        boolean found = false;
+        for (VerifiedSCT vsct : embeddedValidSCTs) {
+            LogInfo log = vsct.getLogInfo();
+            switch (log.getStateAt(atTime)) {
+                case LogInfo.STATE_QUALIFIED:
+                case LogInfo.STATE_USABLE:
+                case LogInfo.STATE_READONLY:
+                    found = true;
+            }
+        }
+        if (!found) {
+            return PolicyCompliance.NOT_ENOUGH_SCTS;
+        }
+
+        /* 2. There are Embedded SCTs from at least N distinct CT Logs that
+         *    were Qualified, Usable, ReadOnly, or Retired at the time of check,
+         *    where N is defined in the following table;
+         *
+         *    Certificate Lifetime    Number of SCTs from distinct CT Logs
+         *         <= 180 days                        2
+         *          > 180 days                        3
+         */
+        Set<LogInfo> validLogs = new HashSet<>();
+        int numberSCTsRequired;
+        long certLifetimeMs = leaf.getNotAfter().getTime() - leaf.getNotBefore().getTime();
+        long certLifetimeDays = TimeUnit.DAYS.convert(certLifetimeMs, TimeUnit.MILLISECONDS);
+        if (certLifetimeDays <= 180) {
+            numberSCTsRequired = 2;
+        } else {
+            numberSCTsRequired = 3;
+        }
+        for (VerifiedSCT vsct : embeddedValidSCTs) {
+            LogInfo log = vsct.getLogInfo();
+            switch (log.getStateAt(atTime)) {
+                case LogInfo.STATE_QUALIFIED:
+                case LogInfo.STATE_USABLE:
+                case LogInfo.STATE_READONLY:
+                case LogInfo.STATE_RETIRED:
+                    validLogs.add(log);
+            }
+        }
+        if (validLogs.size() < numberSCTsRequired) {
+            return PolicyCompliance.NOT_ENOUGH_SCTS;
+        }
+
+        /* 3. Among the SCTs satisfying requirements 1 and 2, at least two SCTs
+         *    must be issued from distinct CT Log Operators as recognized by
+         *    Chrome.
+         */
+        Set<String> operators = new HashSet<>();
+        for (LogInfo logInfo : validLogs) {
+            operators.add(logInfo.getOperator());
+        }
+        if (operators.size() < 2) {
+            return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
+        }
+
+        return PolicyCompliance.COMPLY;
+    }
+}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/TEST_MAPPING b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/TEST_MAPPING
deleted file mode 100644
index 34120cbf..00000000
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "external/conscrypt/repackaged/common/src/main/java/com/android/org/conscrypt/ct"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/TrustedCertificateStoreTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/TrustedCertificateStoreTest.java
index f0fd50f7..384bb21f 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/TrustedCertificateStoreTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/TrustedCertificateStoreTest.java
@@ -26,6 +26,15 @@ import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
 import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.File;
@@ -55,14 +64,8 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
+
 import javax.security.auth.x500.X500Principal;
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
-import org.junit.runners.Parameterized.Parameter;
-import org.junit.runners.Parameterized.Parameters;
 
 /**
  * @hide This class is not part of the Android public SDK API
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/CTLogStoreImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/CTLogStoreImplTest.java
deleted file mode 100644
index c7e6efab..00000000
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/CTLogStoreImplTest.java
+++ /dev/null
@@ -1,208 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-package com.android.org.conscrypt.ct;
-
-import static java.nio.charset.StandardCharsets.UTF_8;
-
-import com.android.org.conscrypt.InternalUtil;
-import java.io.BufferedWriter;
-import java.io.ByteArrayInputStream;
-import java.io.File;
-import java.io.FileNotFoundException;
-import java.io.FileOutputStream;
-import java.io.IOException;
-import java.io.OutputStreamWriter;
-import java.io.PrintWriter;
-import java.nio.charset.StandardCharsets;
-import java.security.PublicKey;
-import junit.framework.TestCase;
-
-/**
- * @hide This class is not part of the Android public SDK API
- */
-public class CTLogStoreImplTest extends TestCase {
-    private static final String[] LOG_KEYS = new String[] {
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3U" +
-        "yEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErEULmlBnX9L/+AK20hLYzPMFozYx" +
-        "pP0Wm1ylqGkPEwuDKn9DSpNSOym49SN77BLGuAXu9twOW/qT+ddIYVBEIw==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP6PGcXmjlyCBz2ZFUuUjrgbZLaEF" +
-        "gfLUkt2cEqlSbb4vTuB6WWmgC9h0L6PN6JF0CPcajpBKGlTI15242a8d4g==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER3qB0NADsP1szXxe4EagrD/ryPVh" +
-        "Y/azWbKyXcK12zhXnO8WH2U4QROVUMctFXLflIzw0EivdRN9t7UH1Od30w==",
-
-        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY0ww9JqeJvzVtKNTPVb3JZa7s0ZV" +
-        "duH3PpshpMS5XVoPRSjSQCph6f3HjUcM3c4N2hpa8OFbrFFy37ttUrgD+A=="
-    };
-    private static final String[] LOG_FILENAMES = new String[] {
-        "df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d764",
-        "84f8ae3f613b13407a75fa2893b93ab03b18d86c455fe7c241ae020033216446",
-        "89baa01a445100009d8f9a238947115b30702275aafee675a7d94b6b09287619",
-        "57456bffe268e49a190dce4318456034c2b4958f3c0201bed5a366737d1e74ca",
-        "896c898ced4b8e6547fa351266caae4ca304f1c1ec2b623c2ee259c5452147b0"
-    };
-
-    private static final CTLogInfo[] LOGS;
-    private static final String[] LOGS_SERIALIZED;
-
-    static {
-        try {
-            int logCount = LOG_KEYS.length;
-            LOGS = new CTLogInfo[logCount];
-            LOGS_SERIALIZED = new String[logCount];
-            for (int i = 0; i < logCount; i++) {
-                PublicKey key = InternalUtil.readPublicKeyPem(new ByteArrayInputStream(
-                        ("-----BEGIN PUBLIC KEY-----\n" + LOG_KEYS[i] + "\n"
-                                + "-----END PUBLIC KEY-----\n")
-                                .getBytes(StandardCharsets.US_ASCII)));
-                String description = String.format("Test Log %d", i);
-                String url = String.format("log%d.example.com", i);
-                LOGS[i] = new CTLogInfo(key, description, url);
-                LOGS_SERIALIZED[i] = String.format("description:%s\nurl:%s\nkey:%s",
-                    description, url, LOG_KEYS[i]);
-            }
-        } catch (Exception e) {
-            throw new RuntimeException(e);
-        }
-    }
-
-    /* CTLogStoreImpl loads the list of logs lazily when they are first needed
-     * to avoid any overhead when CT is disabled.
-     * This test simply forces the logs to be loaded to make sure it doesn't
-     * fail, as all of the other tests use a different log store.
-     */
-    public void test_getDefaultFallbackLogs() {
-        CTLogInfo[] knownLogs = CTLogStoreImpl.getDefaultFallbackLogs();
-        assertEquals(KnownLogs.LOG_COUNT, knownLogs.length);
-    }
-
-    public void test_loadLog() throws Exception {
-        CTLogInfo log = CTLogStoreImpl.loadLog(
-                new ByteArrayInputStream(LOGS_SERIALIZED[0].getBytes(StandardCharsets.US_ASCII)));
-        assertEquals(LOGS[0], log);
-
-        File testFile = writeFile(LOGS_SERIALIZED[0]);
-        log = CTLogStoreImpl.loadLog(testFile);
-        assertEquals(LOGS[0], log);
-
-        // Empty log file, used to mask fallback logs
-        assertEquals(null, CTLogStoreImpl.loadLog(new ByteArrayInputStream(new byte[0])));
-        try {
-            CTLogStoreImpl.loadLog(
-                    new ByteArrayInputStream("randomgarbage".getBytes(StandardCharsets.US_ASCII)));
-            fail("InvalidLogFileException not thrown");
-        } catch (CTLogStoreImpl.InvalidLogFileException e) {}
-
-        try {
-            CTLogStoreImpl.loadLog(new File("/nonexistent"));
-            fail("FileNotFoundException not thrown");
-        } catch (FileNotFoundException e) {}
-    }
-
-    public void test_getKnownLog() throws Exception {
-        File userDir = createTempDirectory();
-        userDir.deleteOnExit();
-
-        File systemDir = createTempDirectory();
-        systemDir.deleteOnExit();
-
-        CTLogInfo[] fallback = new CTLogInfo[] { LOGS[2], LOGS[3] };
-
-        CTLogStore store = new CTLogStoreImpl(userDir, systemDir, fallback);
-
-        /* Add logs 0 and 1 to the user and system directories respectively
-         * Log 2 & 3 are part of the fallbacks
-         * But mask log 3 with an empty file in the user directory.
-         * Log 4 is not in the store
-         */
-        File log0File = new File(userDir, LOG_FILENAMES[0]);
-        File log1File = new File(systemDir, LOG_FILENAMES[1]);
-        File log3File = new File(userDir, LOG_FILENAMES[3]);
-        File log4File = new File(userDir, LOG_FILENAMES[4]);
-
-        writeFile(log0File, LOGS_SERIALIZED[0]);
-        writeFile(log1File, LOGS_SERIALIZED[1]);
-        writeFile(log3File, "");
-
-        // Logs 01 are present, log 2 is in the fallback and unused, log 3 is present but masked,
-        // log 4 is missing
-        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
-        assertEquals(LOGS[1], store.getKnownLog(LOGS[1].getID()));
-        // Fallback logs are not used if the userDir is present.
-        assertEquals(null, store.getKnownLog(LOGS[2].getID()));
-        assertEquals(null, store.getKnownLog(LOGS[3].getID()));
-        assertEquals(null, store.getKnownLog(LOGS[4].getID()));
-
-        /* Test whether CTLogStoreImpl caches properly
-         * Modify the files on the disk, the result of the store should not change
-         * Delete log 0, mask log 1, add log 4
-         */
-        log0File.delete();
-        writeFile(log1File, "");
-        writeFile(log4File, LOGS_SERIALIZED[4]);
-
-        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
-        assertEquals(LOGS[1], store.getKnownLog(LOGS[1].getID()));
-        assertEquals(null, store.getKnownLog(LOGS[4].getID()));
-
-        // Test that fallback logs are used when the userDir doesn't exist.
-        File doesntExist = new File("/doesnt/exist/");
-        store = new CTLogStoreImpl(doesntExist, doesntExist, fallback);
-        assertEquals(LOGS[2], store.getKnownLog(LOGS[2].getID()));
-        assertEquals(LOGS[3], store.getKnownLog(LOGS[3].getID()));
-    }
-
-    /**
-     * Create a temporary file and write to it.
-     * The file will be deleted on exit.
-     * @param contents The data to be written to the file
-     * @return A reference to the temporary file
-     */
-    private File writeFile(String contents) throws IOException {
-        File file = File.createTempFile("test", null);
-        file.deleteOnExit();
-        writeFile(file, contents);
-        return file;
-    }
-
-    private static void writeFile(File file, String contents) throws FileNotFoundException {
-        PrintWriter writer = new PrintWriter(
-                new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), UTF_8)),
-                false);
-        try {
-            writer.write(contents);
-        } finally {
-            writer.close();
-        }
-    }
-
-    /*
-     * This is NOT safe, as another process could create a file between delete() and mkdir()
-     * It should be fine for tests though
-     */
-    private static File createTempDirectory() throws IOException {
-        File folder = File.createTempFile("test", "");
-        folder.delete();
-        folder.mkdir();
-        return folder;
-    }
-}
-
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
new file mode 100644
index 00000000..2b8f3790
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
@@ -0,0 +1,155 @@
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
+package com.android.org.conscrypt.ct;
+
+import static java.nio.charset.StandardCharsets.US_ASCII;
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import com.android.org.conscrypt.OpenSSLKey;
+
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
+import junit.framework.TestCase;
+
+import java.io.ByteArrayInputStream;
+import java.io.File;
+import java.io.FileNotFoundException;
+import java.io.FileOutputStream;
+import java.io.FileWriter;
+import java.io.IOException;
+import java.io.OutputStreamWriter;
+import java.io.PrintWriter;
+import java.security.PublicKey;
+import java.util.Base64;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+public class LogStoreImplTest extends TestCase {
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void test_loadLogList() throws Exception {
+        // clang-format off
+        String content = "" +
+"{" +
+"  \"version\": \"1.1\"," +
+"  \"log_list_timestamp\": \"2024-01-01T11:55:12Z\"," +
+"  \"operators\": [" +
+"    {" +
+"      \"name\": \"Operator 1\"," +
+"      \"email\": [\"ct@operator1.com\"]," +
+"      \"logs\": [" +
+"        {" +
+"          \"description\": \"Operator 1 'Test2024' log\"," +
+"          \"log_id\": \"7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA==\"," +
+"          \"url\": \"https://operator1.example.com/logs/test2024/\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": \"2022-11-01T18:54:00Z\"" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
+"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"          }" +
+"        }," +
+"        {" +
+"          \"description\": \"Operator 1 'Test2025' log\"," +
+"          \"log_id\": \"TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqOTblJji4WiH5AltIDUzODyvFKrXCBjw/Rab0/98J4LUh7dOJEY7+66+yCNSICuqRAX+VPnV8R1Fmg==\"," +
+"          \"url\": \"https://operator1.example.com/logs/test2025/\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": \"2023-11-26T12:00:00Z\"" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": \"2025-01-01T00:00:00Z\"," +
+"            \"end_exclusive\": \"2025-07-01T00:00:00Z\"" +
+"          }" +
+"        }" +
+"      ]" +
+"    }," +
+"    {" +
+"      \"name\": \"Operator 2\"," +
+"      \"email\": [\"ct@operator2.com\"]," +
+"      \"logs\": [" +
+"        {" +
+"          \"description\": \"Operator 2 'Test2024' Log\"," +
+"          \"log_id\": \"2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe4/mizX+OpIpLayKjVGKJfyTttegiyk3cR0zyswz6ii5H+Ksw6ld3Ze+9p6UJd02gdHrXSnDK0TxW8oVSA==\"," +
+"          \"url\": \"https://operator2.example.com/logs/test2024/\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": \"2022-11-30T17:00:00Z\"" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
+"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"          }" +
+"        }" +
+"      ]" +
+"    }" +
+"  ]" +
+"}";
+        // clang-format on
+
+        File logList = writeFile(content);
+        LogStore store = new LogStoreImpl(logList.toPath());
+        store.setPolicy(new PolicyImpl() {
+            @Override
+            public boolean isLogStoreCompliant(LogStore store) {
+                return true;
+            }
+        });
+
+        assertNull("A null logId should return null", store.getKnownLog(null));
+
+        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
+                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
+                + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
+                + "\n-----END PUBLIC KEY-----\n")
+                             .getBytes(US_ASCII);
+        ByteArrayInputStream is = new ByteArrayInputStream(pem);
+
+        LogInfo log1 =
+                new LogInfo.Builder()
+                        .setPublicKey(OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey())
+                        .setDescription("Operator 1 'Test2024' log")
+                        .setUrl("https://operator1.example.com/logs/test2024/")
+                        .setState(LogInfo.STATE_USABLE, 1667328840000L)
+                        .setOperator("Operator 1")
+                        .build();
+        byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
+        assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
+    }
+
+    private File writeFile(String content) throws IOException {
+        File file = File.createTempFile("test", null);
+        file.deleteOnExit();
+        try (FileWriter fw = new FileWriter(file)) {
+            fw.write(content);
+        }
+        return file;
+    }
+}
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
new file mode 100644
index 00000000..0c0d7f13
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
@@ -0,0 +1,331 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.org.conscrypt.ct;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import com.android.org.conscrypt.java.security.cert.FakeX509Certificate;
+
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
+import org.junit.Assume;
+import org.junit.BeforeClass;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.PublicKey;
+import java.security.cert.X509Certificate;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class PolicyImplTest {
+    private static final String OPERATOR1 = "operator 1";
+    private static final String OPERATOR2 = "operator 2";
+    private static LogInfo usableOp1Log1;
+    private static LogInfo usableOp1Log2;
+    private static LogInfo retiredOp1LogOld;
+    private static LogInfo retiredOp1LogNew;
+    private static LogInfo usableOp2Log;
+    private static LogInfo retiredOp2Log;
+    private static SignedCertificateTimestamp embeddedSCT;
+
+    /* Some test dates. By default:
+     *  - The verification is occurring in January 2024;
+     *  - The log list was created in December 2023;
+     *  - The SCTs were generated in January 2023; and
+     *  - The logs got into their state in January 2022.
+     * Other dates are used to exercise edge cases.
+     */
+    private static final long JAN2025 = 1735725600000L;
+    private static final long JAN2024 = 1704103200000L;
+    private static final long DEC2023 = 1701424800000L;
+    private static final long JUN2023 = 1672999200000L;
+    private static final long JAN2023 = 1672567200000L;
+    private static final long JAN2022 = 1641031200000L;
+
+    private static class FakePublicKey implements PublicKey {
+        static final long serialVersionUID = 1;
+        final byte[] key;
+
+        FakePublicKey(byte[] key) {
+            this.key = key;
+        }
+
+        @Override
+        public byte[] getEncoded() {
+            return this.key;
+        }
+
+        @Override
+        public String getAlgorithm() {
+            return "";
+        }
+
+        @Override
+        public String getFormat() {
+            return "";
+        }
+    }
+
+    @BeforeClass
+    public static void setUp() {
+        /* Defines LogInfo for the tests. Only a subset of the attributes are
+         * expected to be used, namely the LogID (based on the public key), the
+         * operator name and the log state.
+         */
+        usableOp1Log1 = new LogInfo.Builder()
+                                .setPublicKey(new FakePublicKey(new byte[] {0x01}))
+                                .setUrl("")
+                                .setOperator(OPERATOR1)
+                                .setState(LogInfo.STATE_USABLE, JAN2022)
+                                .build();
+        usableOp1Log2 = new LogInfo.Builder()
+                                .setPublicKey(new FakePublicKey(new byte[] {0x02}))
+                                .setUrl("")
+                                .setOperator(OPERATOR1)
+                                .setState(LogInfo.STATE_USABLE, JAN2022)
+                                .build();
+        retiredOp1LogOld = new LogInfo.Builder()
+                                   .setPublicKey(new FakePublicKey(new byte[] {0x03}))
+                                   .setUrl("")
+                                   .setOperator(OPERATOR1)
+                                   .setState(LogInfo.STATE_RETIRED, JAN2022)
+                                   .build();
+        retiredOp1LogNew = new LogInfo.Builder()
+                                   .setPublicKey(new FakePublicKey(new byte[] {0x06}))
+                                   .setUrl("")
+                                   .setOperator(OPERATOR1)
+                                   .setState(LogInfo.STATE_RETIRED, JUN2023)
+                                   .build();
+        usableOp2Log = new LogInfo.Builder()
+                               .setPublicKey(new FakePublicKey(new byte[] {0x04}))
+                               .setUrl("")
+                               .setOperator(OPERATOR2)
+                               .setState(LogInfo.STATE_USABLE, JAN2022)
+                               .build();
+        retiredOp2Log = new LogInfo.Builder()
+                                .setPublicKey(new FakePublicKey(new byte[] {0x05}))
+                                .setUrl("")
+                                .setOperator(OPERATOR2)
+                                .setState(LogInfo.STATE_RETIRED, JAN2022)
+                                .build();
+        /* The origin of the SCT and its timestamp are used during the
+         * evaluation for policy compliance. The signature is validated at the
+         * previous step (see the Verifier class).
+         */
+        embeddedSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
+                JAN2023, null, null, SignedCertificateTimestamp.Origin.EMBEDDED);
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void emptyVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+        VerificationResult result = new VerificationResult();
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("An empty VerificationResult", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void validVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two valid SCTs from different operators", PolicyCompliance.COMPLY,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void validWithRetiredVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogNew)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid, one retired SCTs from different operators",
+                PolicyCompliance.COMPLY, p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    public void invalidWithRetiredVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogOld)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid, one retired (before SCT timestamp) SCTs from different operators",
+                PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidOneSctVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid SCT", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidTwoSctsVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogNew)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two retired SCTs from different operators", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidTwoSctsSameOperatorVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log2)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two SCTs from the same operator", PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void validRecentLogStore() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        LogStore store = new LogStoreImpl() {
+            @Override
+            public long getTimestamp() {
+                return DEC2023;
+            }
+        };
+        assertTrue("A recent log list is compliant", p.isLogStoreCompliantAt(store, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidFutureLogStore() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        LogStore store = new LogStoreImpl() {
+            @Override
+            public long getTimestamp() {
+                return JAN2025;
+            }
+        };
+        assertFalse("A future log list is non-compliant", p.isLogStoreCompliantAt(store, JAN2024));
+    }
+
+    @Test
+    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidOldLogStore() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        LogStore store = new LogStoreImpl() {
+            @Override
+            public long getTimestamp() {
+                return JAN2023;
+            }
+        };
+        assertFalse("A expired log list is non-compliant", p.isLogStoreCompliantAt(store, JAN2024));
+    }
+}
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/ChannelType.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/ChannelType.java
index a1a77c10..bc658d65 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/ChannelType.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/ChannelType.java
@@ -40,24 +40,24 @@ import javax.net.ssl.SSLSocketFactory;
 public enum ChannelType {
     NONE {
         @Override
-        SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                 throws IOException {
             return clientMode(factory.createSocket(address, port));
         }
 
         @Override
-        ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException {
+        public ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException {
             return factory.createServerSocket(0, 50, InetAddress.getLoopbackAddress());
         }
 
         @Override
-        SSLSocket accept(ServerSocket socket, SSLSocketFactory unused) throws IOException {
+        public SSLSocket accept(ServerSocket socket, SSLSocketFactory unused) throws IOException {
             return serverMode(socket.accept());
         }
     },
     NO_CHANNEL {
         @Override
-        SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                 throws IOException {
             Socket wrapped = new Socket(address, port);
             assertNull(wrapped.getChannel());
@@ -66,13 +66,13 @@ public enum ChannelType {
         }
 
         @Override
-        ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
+        public ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
             return ServerSocketFactory.getDefault().createServerSocket(
                     0, 50, InetAddress.getLoopbackAddress());
         }
 
         @Override
-        SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
+        public SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
             assertFalse(serverSocket instanceof SSLServerSocket);
             Socket wrapped = serverSocket.accept();
             assertNull(wrapped.getChannel());
@@ -83,21 +83,21 @@ public enum ChannelType {
     },
     CHANNEL {
         @Override
-        SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                 throws IOException {
             Socket wrapped = SocketChannel.open(new InetSocketAddress(address, port)).socket();
             return clientMode(factory.createSocket(wrapped, address.getHostName(), port, true));
         }
 
         @Override
-        ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
+        public ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
             return ServerSocketChannel.open()
                     .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                     .socket();
         }
 
         @Override
-        SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
+        public SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
             assertFalse(serverSocket instanceof SSLServerSocket);
             ServerSocketChannel serverChannel = serverSocket.getChannel();
 
@@ -113,10 +113,10 @@ public enum ChannelType {
         }
     };
 
-    abstract SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+    public abstract SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
             throws IOException;
-    abstract ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException;
-    abstract SSLSocket accept(ServerSocket socket, SSLSocketFactory factory) throws IOException;
+    public abstract ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException;
+    public abstract SSLSocket accept(ServerSocket socket, SSLSocketFactory factory) throws IOException;
 
     private static SSLSocket clientMode(Socket socket) {
         SSLSocket sslSocket = (SSLSocket) socket;
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java
index 93972d39..21ee838b 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java
@@ -24,6 +24,10 @@ import static org.junit.Assert.fail;
 import com.android.org.conscrypt.java.security.StandardNames;
 import com.android.org.conscrypt.java.security.TestKeyStore;
 import com.android.org.conscrypt.testing.Streams;
+
+import org.bouncycastle.jce.provider.BouncyCastleProvider;
+import org.junit.Assume;
+
 import java.io.BufferedReader;
 import java.io.FileNotFoundException;
 import java.io.IOException;
@@ -56,6 +60,7 @@ import java.util.Locale;
 import java.util.Random;
 import java.util.Set;
 import java.util.function.Predicate;
+
 import javax.net.ssl.SSLContext;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLEngineResult;
@@ -64,8 +69,6 @@ import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLServerSocketFactory;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
-import org.bouncycastle.jce.provider.BouncyCastleProvider;
-import org.junit.Assume;
 
 /**
  * Utility methods to support testing.
@@ -128,18 +131,22 @@ public final class TestUtils {
 
     private static Provider getNonConscryptTlsProvider() {
         for (String protocol : DESIRED_JDK_PROTOCOLS) {
-            for (Provider p : Security.getProviders()) {
-                if (!p.getClass().getPackage().getName().contains("conscrypt")
-                        && hasSslContext(p, protocol)) {
-                    return p;
-                }
+            Provider p = getNonConscryptProviderFor("SSLContext", protocol);
+            if (p != null) {
+                return p;
             }
         }
         return new BouncyCastleProvider();
     }
 
-    private static boolean hasSslContext(Provider p, String protocol) {
-        return p.get("SSLContext." + protocol) != null;
+    static Provider getNonConscryptProviderFor(String type, String algorithm) {
+        for (Provider p : Security.getProviders()) {
+            if (!p.getClass().getPackage().getName().contains("conscrypt")
+                    && (p.getService(type, algorithm) != null)) {
+                return p;
+            }
+        }
+        return null;
     }
 
     static Provider getJdkProvider() {
@@ -300,6 +307,38 @@ public final class TestUtils {
         return lines;
     }
 
+    public static List<TestVector> readTestVectors(String resourceName) throws IOException {
+        InputStream stream = openTestFile(resourceName);
+        List<TestVector> result = new ArrayList<>();
+        TestVector current = null;
+        try (BufferedReader reader =
+                        new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
+            String line;
+            int lineNumber = 0;
+            while ((line = reader.readLine()) != null) {
+                lineNumber++;
+                if (line.isEmpty() || line.startsWith("#")) {
+                    continue;
+                }
+                int index = line.indexOf('=');
+                if (index < 0) {
+                    throw new IllegalStateException("No = found: line " + lineNumber);
+                }
+                String label = line.substring(0, index).trim().toLowerCase();
+                String value = line.substring(index + 1).trim();
+                if ("name".equals(label)) {
+                    current = new TestVector();
+                    result.add(current);
+                } else if (current == null) {
+                    throw new IllegalStateException(
+                            "Vectors must start with a name: line " + lineNumber);
+                }
+                current.put(label, value);
+            }
+        }
+        return result;
+    }
+
     /**
      * Looks up the conscrypt class for the given simple name (i.e. no package prefix).
      */
@@ -325,7 +364,7 @@ public final class TestUtils {
         }
     }
 
-    static SSLSocketFactory setUseEngineSocket(
+    public static SSLSocketFactory setUseEngineSocket(
             SSLSocketFactory conscryptFactory, boolean useEngineSocket) {
         try {
             Class<?> clazz = conscryptClass("Conscrypt");
@@ -338,7 +377,7 @@ public final class TestUtils {
         }
     }
 
-    static SSLServerSocketFactory setUseEngineSocket(
+    public static SSLServerSocketFactory setUseEngineSocket(
             SSLServerSocketFactory conscryptFactory, boolean useEngineSocket) {
         try {
             Class<?> clazz = conscryptClass("Conscrypt");
@@ -428,6 +467,11 @@ public final class TestUtils {
                 .toArray(String[] ::new);
     }
 
+    public static String[] getSupportedProtocols() {
+        return getSupportedProtocols(newClientSslContext(getConscryptProvider()))
+                .toArray(new String[0]);
+    }
+
     public static List<String> getSupportedProtocols(SSLContext ctx) {
         return Arrays.asList(ctx.getDefaultSSLParameters().getProtocols());
     }
@@ -478,12 +522,12 @@ public final class TestUtils {
         return msg;
     }
 
-    static SSLContext newClientSslContext(Provider provider) {
+    public static SSLContext newClientSslContext(Provider provider) {
         SSLContext context = newContext(provider);
         return initClientSslContext(context);
     }
 
-    static SSLContext newServerSslContext(Provider provider) {
+    public static SSLContext newServerSslContext(Provider provider) {
         SSLContext context = newContext(provider);
         return initServerSslContext(context);
     }
@@ -826,26 +870,23 @@ public final class TestUtils {
         Assume.assumeTrue(findClass("java.security.spec.XECPrivateKeySpec") != null);
     }
 
-    // Find base method via reflection due to possible version skew on Android
-    // and visibility issues when building with Gradle.
+    // Find base method via reflection due to visibility issues when building with Gradle.
     public static boolean isTlsV1Deprecated() {
         try {
             return (Boolean) conscryptClass("Platform")
                     .getDeclaredMethod("isTlsV1Deprecated")
                     .invoke(null);
-        } catch (NoSuchMethodException e) {
-            return false;
-        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
-            throw new IllegalStateException("Reflection failure", e);
+        } catch (Exception e) {
+            throw new RuntimeException(e);
         }
     }
 
     // Find base method via reflection due to possible version skew on Android
     // and visibility issues when building with Gradle.
-    public static boolean isTlsV1Supported() {
+    public static boolean isTlsV1Filtered() {
         try {
             return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Supported")
+                    .getDeclaredMethod("isTlsV1Filtered")
                     .invoke(null);
         } catch (NoSuchMethodException e) {
             return true;
@@ -856,13 +897,13 @@ public final class TestUtils {
 
     // Find base method via reflection due to possible version skew on Android
     // and visibility issues when building with Gradle.
-    public static boolean isTlsV1Filtered() {
+    public static boolean isTlsV1Supported() {
         try {
             return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Filtered")
+                    .getDeclaredMethod("isTlsV1Supported")
                     .invoke(null);
         } catch (NoSuchMethodException e) {
-            return true;
+            return false;
         } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
             throw new IllegalStateException("Reflection failure", e);
         }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/TestVector.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/TestVector.java
new file mode 100644
index 00000000..bb525fbe
--- /dev/null
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/TestVector.java
@@ -0,0 +1,58 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.org.conscrypt;
+
+import static com.android.org.conscrypt.TestUtils.decodeHex;
+
+import java.util.HashMap;
+import java.util.Map;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+public final class TestVector {
+    private final Map<String, String> map = new HashMap<>();
+
+    public void put(String label, String value) {
+        map.put(label, value);
+    }
+    public String getString(String label) {
+        return map.get(label);
+    }
+
+    public byte[] getBytes(String label) {
+        return decodeHex(getString(label));
+    }
+
+    public byte[] getBytesOrEmpty(String label) {
+        return contains(label) ? getBytes(label) : new byte[0];
+    }
+
+    public int getInt(String label) {
+        return Integer.parseInt(getString(label));
+    }
+
+    public boolean contains(String label) {
+        return map.containsKey(label);
+    }
+
+    @Override
+    public String toString() {
+        return map.toString();
+    }
+}
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/DefaultKeys.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/DefaultKeys.java
index 0ce676ff..fc018979 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/DefaultKeys.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/DefaultKeys.java
@@ -17,6 +17,7 @@
 package com.android.org.conscrypt.java.security;
 
 import com.android.org.conscrypt.TestUtils;
+
 import java.security.KeyFactory;
 import java.security.NoSuchAlgorithmException;
 import java.security.PrivateKey;
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
index 6d289509..6402f8b0 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
@@ -22,6 +22,7 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 
 import com.android.org.conscrypt.TestUtils;
+
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.HashMap;
@@ -169,8 +170,6 @@ public final class StandardNames {
     }
 
     public static final String SSL_CONTEXT_PROTOCOLS_DEFAULT = "Default";
-    public static final Set<String> SSL_CONTEXT_PROTOCOLS_ALL =
-            new HashSet<String>(Arrays.asList("TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"));
     public static final Set<String> SSL_CONTEXT_PROTOCOLS = new HashSet<String>(
             Arrays.asList(SSL_CONTEXT_PROTOCOLS_DEFAULT, "TLS", "TLSv1.2", "TLSv1.3"));
     public static final Set<String> SSL_CONTEXT_PROTOCOLS_WITH_DEFAULT_CONFIG = new HashSet<String>(
@@ -182,6 +181,10 @@ public final class StandardNames {
             SSL_CONTEXT_PROTOCOLS_DEPRECATED.add("TLSv1");
             SSL_CONTEXT_PROTOCOLS_DEPRECATED.add("TLSv1.1");
         }
+        if (!TestUtils.isTlsV1Supported()) {
+            assertTrue("Can't have this without that", TestUtils.isTlsV1Deprecated());
+            SSL_CONTEXT_PROTOCOLS.removeAll(SSL_CONTEXT_PROTOCOLS_DEPRECATED);
+        }
     }
 
     public static final Set<String> KEY_TYPES = new HashSet<String>(
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java
new file mode 100644
index 00000000..f4b55f3a
--- /dev/null
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java
@@ -0,0 +1,171 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.org.conscrypt.java.security.cert;
+
+import java.math.BigInteger;
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.security.NoSuchProviderException;
+import java.security.Principal;
+import java.security.PublicKey;
+import java.security.SignatureException;
+import java.security.cert.CertificateEncodingException;
+import java.security.cert.CertificateException;
+import java.security.cert.CertificateExpiredException;
+import java.security.cert.CertificateNotYetValidException;
+import java.security.cert.X509Certificate;
+import java.util.Date;
+import java.util.Set;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+public class FakeX509Certificate extends X509Certificate {
+    @Override
+    public void checkValidity()
+            throws CertificateExpiredException, CertificateNotYetValidException {}
+
+    @Override
+    public void checkValidity(Date date)
+            throws CertificateExpiredException, CertificateNotYetValidException {}
+
+    @Override
+    public int getBasicConstraints() {
+        return 0;
+    }
+
+    @Override
+    public Principal getIssuerDN() {
+        return new MockPrincipal();
+    }
+
+    @Override
+    public boolean[] getIssuerUniqueID() {
+        return null;
+    }
+
+    @Override
+    public boolean[] getKeyUsage() {
+        return null;
+    }
+
+    @Override
+    public Date getNotAfter() {
+        return new Date(System.currentTimeMillis());
+    }
+
+    @Override
+    public Date getNotBefore() {
+        return new Date(System.currentTimeMillis() - 1000);
+    }
+
+    @Override
+    public BigInteger getSerialNumber() {
+        return null;
+    }
+
+    @Override
+    public String getSigAlgName() {
+        return null;
+    }
+
+    @Override
+    public String getSigAlgOID() {
+        return null;
+    }
+
+    @Override
+    public byte[] getSigAlgParams() {
+        return null;
+    }
+
+    @Override
+    public byte[] getSignature() {
+        return null;
+    }
+
+    @Override
+    public Principal getSubjectDN() {
+        return new MockPrincipal();
+    }
+
+    class MockPrincipal implements Principal {
+        public String getName() {
+            return null;
+        }
+    }
+    @Override
+    public boolean[] getSubjectUniqueID() {
+        return null;
+    }
+
+    @Override
+    public byte[] getTBSCertificate() throws CertificateEncodingException {
+        return null;
+    }
+
+    @Override
+    public int getVersion() {
+        return 0;
+    }
+
+    @Override
+    public byte[] getEncoded() throws CertificateEncodingException {
+        return null;
+    }
+
+    @Override
+    public PublicKey getPublicKey() {
+        return null;
+    }
+
+    @Override
+    public String toString() {
+        return null;
+    }
+
+    @Override
+    public void verify(PublicKey key)
+            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
+                   NoSuchProviderException, SignatureException {}
+
+    @Override
+    public void verify(PublicKey key, String sigProvider)
+            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
+                   NoSuchProviderException, SignatureException {}
+
+    @Override
+    public Set<String> getCriticalExtensionOIDs() {
+        return null;
+    }
+
+    @Override
+    public byte[] getExtensionValue(String oid) {
+        return null;
+    }
+
+    @Override
+    public Set<String> getNonCriticalExtensionOIDs() {
+        return null;
+    }
+
+    @Override
+    public boolean hasUnsupportedCriticalExtension() {
+        return false;
+    }
+}
diff --git a/testing/build.gradle b/testing/build.gradle
index 37969bc8..fafd5faa 100644
--- a/testing/build.gradle
+++ b/testing/build.gradle
@@ -24,3 +24,8 @@ dependencies {
             libraries.bouncycastle_provider,
             libraries.junit
 }
+
+// No public methods here.
+tasks.withType(Javadoc).configureEach {
+    enabled = false
+}
diff --git a/testing/src/main/java/org/conscrypt/ChannelType.java b/testing/src/main/java/org/conscrypt/ChannelType.java
index 09dd582b..23e09a08 100644
--- a/testing/src/main/java/org/conscrypt/ChannelType.java
+++ b/testing/src/main/java/org/conscrypt/ChannelType.java
@@ -38,24 +38,24 @@ import javax.net.ssl.SSLSocketFactory;
 public enum ChannelType {
     NONE {
         @Override
-        SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                 throws IOException {
             return clientMode(factory.createSocket(address, port));
         }
 
         @Override
-        ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException {
+        public ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException {
             return factory.createServerSocket(0, 50, InetAddress.getLoopbackAddress());
         }
 
         @Override
-        SSLSocket accept(ServerSocket socket, SSLSocketFactory unused) throws IOException {
+        public SSLSocket accept(ServerSocket socket, SSLSocketFactory unused) throws IOException {
             return serverMode(socket.accept());
         }
     },
     NO_CHANNEL {
         @Override
-        SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                 throws IOException {
             Socket wrapped = new Socket(address, port);
             assertNull(wrapped.getChannel());
@@ -64,13 +64,13 @@ public enum ChannelType {
         }
 
         @Override
-        ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
+        public ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
             return ServerSocketFactory.getDefault().createServerSocket(
                     0, 50, InetAddress.getLoopbackAddress());
         }
 
         @Override
-        SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
+        public SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
             assertFalse(serverSocket instanceof SSLServerSocket);
             Socket wrapped = serverSocket.accept();
             assertNull(wrapped.getChannel());
@@ -81,21 +81,21 @@ public enum ChannelType {
     },
     CHANNEL {
         @Override
-        SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                 throws IOException {
             Socket wrapped = SocketChannel.open(new InetSocketAddress(address, port)).socket();
             return clientMode(factory.createSocket(wrapped, address.getHostName(), port, true));
         }
 
         @Override
-        ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
+        public ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
             return ServerSocketChannel.open()
                     .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                     .socket();
         }
 
         @Override
-        SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
+        public SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
             assertFalse(serverSocket instanceof SSLServerSocket);
             ServerSocketChannel serverChannel = serverSocket.getChannel();
 
@@ -111,10 +111,10 @@ public enum ChannelType {
         }
     };
 
-    abstract SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
+    public abstract SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
             throws IOException;
-    abstract ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException;
-    abstract SSLSocket accept(ServerSocket socket, SSLSocketFactory factory) throws IOException;
+    public abstract ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException;
+    public abstract SSLSocket accept(ServerSocket socket, SSLSocketFactory factory) throws IOException;
 
     private static SSLSocket clientMode(Socket socket) {
         SSLSocket sslSocket = (SSLSocket) socket;
diff --git a/testing/src/main/java/org/conscrypt/TestUtils.java b/testing/src/main/java/org/conscrypt/TestUtils.java
index d9ea00bf..7b3231d1 100644
--- a/testing/src/main/java/org/conscrypt/TestUtils.java
+++ b/testing/src/main/java/org/conscrypt/TestUtils.java
@@ -123,18 +123,22 @@ public final class TestUtils {
 
     private static Provider getNonConscryptTlsProvider() {
         for (String protocol : DESIRED_JDK_PROTOCOLS) {
-            for (Provider p : Security.getProviders()) {
-                if (!p.getClass().getPackage().getName().contains("conscrypt")
-                        && hasSslContext(p, protocol)) {
-                    return p;
-                }
+            Provider p = getNonConscryptProviderFor("SSLContext", protocol);
+            if (p != null) {
+                return p;
             }
         }
         return new BouncyCastleProvider();
     }
 
-    private static boolean hasSslContext(Provider p, String protocol) {
-        return p.get("SSLContext." + protocol) != null;
+    static Provider getNonConscryptProviderFor(String type, String algorithm) {
+        for (Provider p : Security.getProviders()) {
+            if (!p.getClass().getPackage().getName().contains("conscrypt")
+                && (p.getService(type, algorithm) != null)) {
+                return p;
+            }
+        }
+        return null;
     }
 
     static Provider getJdkProvider() {
@@ -294,6 +298,38 @@ public final class TestUtils {
         return lines;
     }
 
+    public static List<TestVector> readTestVectors(String resourceName) throws IOException {
+        InputStream stream = openTestFile(resourceName);
+        List<TestVector> result = new ArrayList<>();
+        TestVector current = null;
+        try (BufferedReader reader
+                 = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
+            String line;
+            int lineNumber = 0;
+            while ((line = reader.readLine()) != null) {
+                lineNumber++;
+                if (line.isEmpty() || line.startsWith("#")) {
+                    continue;
+                }
+                int index = line.indexOf('=');
+                if (index < 0) {
+                    throw new IllegalStateException("No = found: line " + lineNumber);
+                }
+                String label = line.substring(0, index).trim().toLowerCase();
+                String value = line.substring(index + 1).trim();
+                if ("name".equals(label)) {
+                    current = new TestVector();
+                    result.add(current);
+                } else if (current == null) {
+                    throw new IllegalStateException("Vectors must start with a name: line "
+                        + lineNumber);
+                }
+                current.put(label, value);
+            }
+        }
+        return result;
+    }
+
     /**
      * Looks up the conscrypt class for the given simple name (i.e. no package prefix).
      */
@@ -319,7 +355,7 @@ public final class TestUtils {
         }
     }
 
-    static SSLSocketFactory setUseEngineSocket(
+    public static SSLSocketFactory setUseEngineSocket(
             SSLSocketFactory conscryptFactory, boolean useEngineSocket) {
         try {
             Class<?> clazz = conscryptClass("Conscrypt");
@@ -332,7 +368,7 @@ public final class TestUtils {
         }
     }
 
-    static SSLServerSocketFactory setUseEngineSocket(
+    public static SSLServerSocketFactory setUseEngineSocket(
             SSLServerSocketFactory conscryptFactory, boolean useEngineSocket) {
         try {
             Class<?> clazz = conscryptClass("Conscrypt");
@@ -421,6 +457,11 @@ public final class TestUtils {
             .toArray(String[]::new);
     }
 
+    public static String[] getSupportedProtocols() {
+        return getSupportedProtocols(newClientSslContext(getConscryptProvider()))
+                .toArray(new String[0]);
+    }
+
     public static List<String> getSupportedProtocols(SSLContext ctx) {
         return Arrays.asList(ctx.getDefaultSSLParameters().getProtocols());
     }
@@ -472,12 +513,12 @@ public final class TestUtils {
         return msg;
     }
 
-    static SSLContext newClientSslContext(Provider provider) {
+    public static SSLContext newClientSslContext(Provider provider) {
         SSLContext context = newContext(provider);
         return initClientSslContext(context);
     }
 
-    static SSLContext newServerSslContext(Provider provider) {
+    public static SSLContext newServerSslContext(Provider provider) {
         SSLContext context = newContext(provider);
         return initServerSslContext(context);
     }
@@ -820,26 +861,23 @@ public final class TestUtils {
         Assume.assumeTrue(findClass("java.security.spec.XECPrivateKeySpec") != null);
     }
 
-    // Find base method via reflection due to possible version skew on Android
-    // and visibility issues when building with Gradle.
+    // Find base method via reflection due to visibility issues when building with Gradle.
     public static boolean isTlsV1Deprecated() {
         try {
             return (Boolean) conscryptClass("Platform")
                     .getDeclaredMethod("isTlsV1Deprecated")
                     .invoke(null);
-        } catch (NoSuchMethodException e) {
-            return false;
-        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
-            throw new IllegalStateException("Reflection failure", e);
+        } catch (Exception e) {
+            throw new RuntimeException(e);
         }
     }
 
     // Find base method via reflection due to possible version skew on Android
     // and visibility issues when building with Gradle.
-    public static boolean isTlsV1Supported() {
+    public static boolean isTlsV1Filtered() {
         try {
             return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Supported")
+                    .getDeclaredMethod("isTlsV1Filtered")
                     .invoke(null);
         } catch (NoSuchMethodException e) {
             return true;
@@ -850,15 +888,16 @@ public final class TestUtils {
 
     // Find base method via reflection due to possible version skew on Android
     // and visibility issues when building with Gradle.
-    public static boolean isTlsV1Filtered() {
+    public static boolean isTlsV1Supported() {
         try {
             return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Filtered")
+                    .getDeclaredMethod("isTlsV1Supported")
                     .invoke(null);
         } catch (NoSuchMethodException e) {
-            return true;
+            return false;
         } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
             throw new IllegalStateException("Reflection failure", e);
         }
     }
+
 }
diff --git a/testing/src/main/java/org/conscrypt/TestVector.java b/testing/src/main/java/org/conscrypt/TestVector.java
new file mode 100644
index 00000000..fc8b1569
--- /dev/null
+++ b/testing/src/main/java/org/conscrypt/TestVector.java
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package org.conscrypt;
+
+import static org.conscrypt.TestUtils.decodeHex;
+
+import java.util.HashMap;
+import java.util.Map;
+
+public final class TestVector {
+    private final Map<String, String> map = new HashMap<>();
+
+    public void put(String label, String value) {
+        map.put(label, value);
+    }
+    public String getString(String label) {
+        return map.get(label);
+    }
+
+    public byte[] getBytes(String label) {
+        return decodeHex(getString(label));
+    }
+
+    public byte[] getBytesOrEmpty(String label) {
+        return contains(label) ? getBytes(label) : new byte[0];
+    }
+
+    public int getInt(String label) {
+        return Integer.parseInt(getString(label));
+    }
+
+    public boolean contains(String label) {
+        return map.containsKey(label);
+    }
+
+    @Override
+    public String toString() {
+        return map.toString();
+    }
+}
diff --git a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
index 4c480ec5..ac9d895c 100644
--- a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
+++ b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
@@ -168,8 +168,6 @@ public final class StandardNames {
     }
 
     public static final String SSL_CONTEXT_PROTOCOLS_DEFAULT = "Default";
-    public static final Set<String> SSL_CONTEXT_PROTOCOLS_ALL =
-            new HashSet<String>(Arrays.asList("TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"));
     public static final Set<String> SSL_CONTEXT_PROTOCOLS = new HashSet<String>(
             Arrays.asList(SSL_CONTEXT_PROTOCOLS_DEFAULT, "TLS", "TLSv1.2", "TLSv1.3"));
     public static final Set<String> SSL_CONTEXT_PROTOCOLS_WITH_DEFAULT_CONFIG = new HashSet<String>(
@@ -181,6 +179,10 @@ public final class StandardNames {
             SSL_CONTEXT_PROTOCOLS_DEPRECATED.add("TLSv1");
             SSL_CONTEXT_PROTOCOLS_DEPRECATED.add("TLSv1.1");
         }
+        if (!TestUtils.isTlsV1Supported()) {
+            assertTrue("Can't have this without that", TestUtils.isTlsV1Deprecated());
+            SSL_CONTEXT_PROTOCOLS.removeAll(SSL_CONTEXT_PROTOCOLS_DEPRECATED);
+        }
     }
 
     public static final Set<String> KEY_TYPES = new HashSet<String>(
diff --git a/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java b/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java
new file mode 100644
index 00000000..ed61cc42
--- /dev/null
+++ b/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java
@@ -0,0 +1,167 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package org.conscrypt.java.security.cert;
+
+import java.math.BigInteger;
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.security.NoSuchProviderException;
+import java.security.Principal;
+import java.security.PublicKey;
+import java.security.SignatureException;
+import java.security.cert.CertificateEncodingException;
+import java.security.cert.CertificateException;
+import java.security.cert.CertificateExpiredException;
+import java.security.cert.CertificateNotYetValidException;
+import java.security.cert.X509Certificate;
+import java.util.Date;
+import java.util.Set;
+
+public class FakeX509Certificate extends X509Certificate {
+    @Override
+    public void checkValidity()
+            throws CertificateExpiredException, CertificateNotYetValidException {}
+
+    @Override
+    public void checkValidity(Date date)
+            throws CertificateExpiredException, CertificateNotYetValidException {}
+
+    @Override
+    public int getBasicConstraints() {
+        return 0;
+    }
+
+    @Override
+    public Principal getIssuerDN() {
+        return new MockPrincipal();
+    }
+
+    @Override
+    public boolean[] getIssuerUniqueID() {
+        return null;
+    }
+
+    @Override
+    public boolean[] getKeyUsage() {
+        return null;
+    }
+
+    @Override
+    public Date getNotAfter() {
+        return new Date(System.currentTimeMillis());
+    }
+
+    @Override
+    public Date getNotBefore() {
+        return new Date(System.currentTimeMillis() - 1000);
+    }
+
+    @Override
+    public BigInteger getSerialNumber() {
+        return null;
+    }
+
+    @Override
+    public String getSigAlgName() {
+        return null;
+    }
+
+    @Override
+    public String getSigAlgOID() {
+        return null;
+    }
+
+    @Override
+    public byte[] getSigAlgParams() {
+        return null;
+    }
+
+    @Override
+    public byte[] getSignature() {
+        return null;
+    }
+
+    @Override
+    public Principal getSubjectDN() {
+        return new MockPrincipal();
+    }
+
+    class MockPrincipal implements Principal {
+        public String getName() {
+            return null;
+        }
+    }
+    @Override
+    public boolean[] getSubjectUniqueID() {
+        return null;
+    }
+
+    @Override
+    public byte[] getTBSCertificate() throws CertificateEncodingException {
+        return null;
+    }
+
+    @Override
+    public int getVersion() {
+        return 0;
+    }
+
+    @Override
+    public byte[] getEncoded() throws CertificateEncodingException {
+        return null;
+    }
+
+    @Override
+    public PublicKey getPublicKey() {
+        return null;
+    }
+
+    @Override
+    public String toString() {
+        return null;
+    }
+
+    @Override
+    public void verify(PublicKey key)
+            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
+                   NoSuchProviderException, SignatureException {}
+
+    @Override
+    public void verify(PublicKey key, String sigProvider)
+            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
+                   NoSuchProviderException, SignatureException {}
+
+    @Override
+    public Set<String> getCriticalExtensionOIDs() {
+        return null;
+    }
+
+    @Override
+    public byte[] getExtensionValue(String oid) {
+        return null;
+    }
+
+    @Override
+    public Set<String> getNonCriticalExtensionOIDs() {
+        return null;
+    }
+
+    @Override
+    public boolean hasUnsupportedCriticalExtension() {
+        return false;
+    }
+}
```

