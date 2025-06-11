```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index d7d5c096..9d8afe0c 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -27,6 +27,27 @@ jobs:
           include-hidden-files: true
           if-no-files-found: error
 
+  clang_format_check:
+    # Only run on pull requests.
+    if: ${{ startsWith(github.ref, 'refs/pull/') }}
+    runs-on: ubuntu-latest
+
+    steps:
+      - name: Checkout repository
+        uses: actions/checkout@v4
+        with:
+          fetch-depth: 0
+
+      - name: Get git-clang-format
+        # Uses the most recent clang-format on Ubuntu.
+        run: |
+          sudo apt-get -qq update
+          sudo apt-get -qq install -y --no-install-recommends clang-format
+
+      - name: Run git-clang-format against source branch
+        run: |
+          git clang-format --style=file --diff origin/$GITHUB_BASE_REF '*.c' '*.h' '*.cc' '*.cpp' '*.java'
+
   build:
     needs: boringssl_clone
 
@@ -83,11 +104,6 @@ jobs:
           brew update || echo update failed
           brew install ninja || echo update failed
 
-      - name: install Go
-        uses: actions/setup-go@v5
-        with:
-          go-version: '1.20'
-
       - name: Setup Windows environment
         if: runner.os == 'Windows'
         run: |
@@ -172,10 +188,7 @@ jobs:
 
       - name: Test with Gradle
         shell: bash
-        run: ./gradlew test -PcheckErrorQueue
-
-      - name: Other checks with Gradle
-        shell: bash
+        timeout-minutes: 15
         run: ./gradlew check -PcheckErrorQueue
 
       - name: Publish to local Maven repo
@@ -209,6 +222,20 @@ jobs:
     steps:
       - uses: actions/checkout@v4
 
+      - name: Setup Linux environment
+        run: |
+          echo "CC=clang" >> $GITHUB_ENV
+          echo "CXX=clang++" >> $GITHUB_ENV
+
+          sudo dpkg --add-architecture i386
+          sudo add-apt-repository ppa:openjdk-r/ppa
+          sudo apt-get -qq update
+          sudo apt-get -qq install -y --no-install-recommends \
+            gcc-multilib \
+            g++-multilib \
+            ninja-build \
+            openjdk-11-jre-headless
+
       - name: Set runner-specific environment variables
         shell: bash
         run: |
@@ -221,15 +248,30 @@ jobs:
           name: boringssl-source
           path: ${{ runner.temp }}/boringssl
 
-      - name: Make fake BoringSSL directories
+      - name: Checkout BoringSSL master branch
         shell: bash
         run: |
-          # TODO: remove this when the check is only performed when building.
-          # BoringSSL is not needed during the UberJAR build, but the
-          # assertion to check happens regardless of whether the project
-          # needs it.
-          mkdir -p "${{ runner.temp }}/boringssl/build64"
-          mkdir -p "${{ runner.temp }}/boringssl/include"
+          cd "$BORINGSSL_HOME"
+          git checkout --progress --force -B master
+
+      - name: Build BoringSSL 64-bit Linux
+        run: |
+          mkdir -p "$BORINGSSL_HOME/build64"
+          pushd "$BORINGSSL_HOME/build64"
+          cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -GNinja ..
+          ninja
+          popd
+
+      # TODO(prb) remove build dependency above and go back to this.
+      # - name: Make fake BoringSSL directories
+      #   shell: bash
+      #   run: |
+      #     # TODO: remove this when the check is only performed when building.
+      #     # BoringSSL is not needed during the UberJAR build, but the
+      #     # assertion to check happens regardless of whether the project
+      #     # needs it.
+      #     mkdir -p "${{ runner.temp }}/boringssl/build64"
+      #     mkdir -p "${{ runner.temp }}/boringssl/include"
 
       - name: Download Maven repository for Linux
         uses: actions/download-artifact@v4
@@ -321,7 +363,29 @@ jobs:
           DIR="$(find m2/org/conscrypt/conscrypt-openjdk-uber -maxdepth 1 -mindepth 1 -type d -print)"
           VERSION="${DIR##*/}"
           TESTJAR="$(find testjar -name '*-tests.jar')"
-          java -jar junit-platform-console-standalone.jar execute -cp "$DIR/conscrypt-openjdk-uber-$VERSION.jar${{ matrix.separator }}$TESTJAR" -n='org.conscrypt.ConscryptOpenJdkSuite' --scan-classpath --reports-dir=results --fail-if-no-tests
+          # SIGTERM handler, e.g. for when tests hang and time out.
+          # Send SIGQUIT to test process to get thread dump, give it
+          # a few seconds to complete and then kill it.
+          dump_threads() {
+            echo "Generating stack dump."
+            ps -fp "$TESTPID"
+            kill -QUIT "$TESTPID"
+            sleep 3
+            kill -KILL "$TESTPID"
+            exit 1
+          }
+          java -jar junit-platform-console-standalone.jar execute -cp "$DIR/conscrypt-openjdk-uber-$VERSION.jar${{ matrix.separator }}$TESTJAR" -n='org.conscrypt.ConscryptOpenJdkSuite' --scan-classpath --reports-dir=results --fail-if-no-tests &
+          case $(uname -s) in
+            Darwin|Linux)
+              trap dump_threads SIGTERM SIGINT
+              ;;
+            *)
+              # TODO: Probably won't work on Windows but thread dumps
+              # work there already.
+              ;;
+          esac
+          TESTPID=$!
+          wait "$TESTPID"
 
       - name: Archive test results
         if: ${{ always() }}
diff --git a/Android.bp b/Android.bp
index 44141e3a..5c89f982 100644
--- a/Android.bp
+++ b/Android.bp
@@ -144,6 +144,7 @@ cc_library {
 cc_library_host_shared {
     name: "libconscrypt_openjdk_jni",
     visibility: [
+        "//build/make/tools/otatools_package",
         "//build/make/tools/signapk",
         "//cts/hostsidetests/library", // from CtsUseNativeLibraryBuildPackage
         "//tools/apksig",
@@ -199,10 +200,10 @@ aconfig_declarations {
 java_aconfig_library {
     name: "conscrypt-aconfig-flags-lib",
     aconfig_declarations: "conscrypt-aconfig-flags",
-    system_modules: "art-module-intra-core-api-stubs-system-modules",
+    system_modules: "core-all-system-modules",
     libs: [
         "aconfig-annotations-lib-sdk-none",
-        "unsupportedappusage",
+        "aconfig_storage_stub_none",
     ],
     sdk_version: "none",
     patch_module: "java.base",
@@ -385,9 +386,14 @@ java_sdk_library {
     srcs: [
         ":conscrypt_java_files",
         ":conscrypt_public_api_files",
+        ":framework-metalava-annotations",
+    ],
+    aconfig_declarations: [
+        "conscrypt-aconfig-flags",
     ],
     api_dir: "api/platform",
     api_only: true,
+    annotations_enabled: true,
     api_lint: {
         enabled: true,
     },
@@ -397,6 +403,12 @@ java_sdk_library {
         "--show-unannotated",
         "--show-single-annotation libcore.api.CorePlatformApi\\(status=libcore.api.CorePlatformApi.Status.STABLE\\)",
     ],
+
+    public: {
+        // Select api-surface defined in build/soong/java/metalava/main-config.xml
+        api_surface: "core-platform-plus-public",
+    },
+
     hostdex: true,
 
     sdk_version: "none",
@@ -433,6 +445,13 @@ java_sdk_library {
     ],
     srcs: [
         ":conscrypt_public_api_files",
+        ":framework-metalava-annotations",
+    ],
+    libs: [
+        "conscrypt-aconfig-flags-lib",
+    ],
+    aconfig_declarations: [
+        "conscrypt-aconfig-flags",
     ],
 
     // The base name for the artifacts that are automatically published to the
@@ -512,11 +531,17 @@ java_sdk_library {
     ],
     api_dir: "api/intra",
     api_only: true,
+    annotations_enabled: true,
     droiddoc_options: [
         "--hide-annotation libcore.api.Hide",
         "--show-single-annotation libcore.api.IntraCoreApi",
     ],
 
+    public: {
+        // Select api-surface defined in build/soong/java/metalava/main-config.xml
+        api_surface: "intra-core",
+    },
+
     sdk_version: "none",
     system_modules: "art-module-intra-core-api-stubs-system-modules",
 
diff --git a/OWNERS b/OWNERS
index 73617ea1..459b9fe8 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 # Bug component: 684135
 include platform/libcore:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/android-stub/src/main/java/android/crypto/hpke/HpkeSpi.java b/android-stub/src/main/java/android/crypto/hpke/HpkeSpi.java
new file mode 100644
index 00000000..98c0f607
--- /dev/null
+++ b/android-stub/src/main/java/android/crypto/hpke/HpkeSpi.java
@@ -0,0 +1,206 @@
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
+package android.crypto.hpke;
+
+import java.security.GeneralSecurityException;
+import java.security.InvalidKeyException;
+import java.security.PrivateKey;
+import java.security.PublicKey;
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+
+/**
+ * Service Provider Interface for HPKE client API classes to communicate with implementations
+ * of HPKE as described in RFC 9180.
+ * <p>
+ * There are no standard Java Cryptography Architecture names or interface classes for HPKE,
+ * but instances of this class can be obtained by calling
+ * {@code Provider.getService("ConscryptHpke", String SuiteName)} where {@code suiteName}
+ * is the name of the HPKE suite, e.g.
+ * {@code "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM"}.
+ */
+public interface HpkeSpi {
+    /**
+     * Initialises an HPKE SPI in one of the sender modes described in RFC 9180.
+     * <p>
+     * If {@code senderKey} is supplied then Asymmetric Key Authentication will be used,
+     * (MODE_AUTH)
+     * <p>
+     * If {@code psk} and {@code psk_id} are supplied then Pre-Shared Key Authentication
+     * will be used (MODE_PSK).
+     * <p>
+     * If all of {@code senderKey}, {@code psk} and {@code psk_id} are supplied then both
+     * Key and PSK authentication will be used (MODE_PSK_AUTH).
+     * <p>
+     * If neither is supplied then no sender authentication will be used (MODE_BASE).
+     * <p>
+     * Note that only base mode is currently supported on Android.
+     * <p>
+     * Public and private keys must be supplied in a format that can be used by the
+     * implementation.  An instance of the {@code "XDH"} {@link java.security.KeyFactory} can
+     * be used to translate {@code KeySpecs} or keys from another {@link java.security.Provider}
+     *
+     * @param recipientKey public key of the recipient
+     * @param info application-supplied information, may be null or empty
+     * @param senderKey private key of the sender, for symmetric auth modes only, else null
+     * @param psk pre-shared key, for PSK auth modes only, else null
+     * @param psk_id pre-shared key ID, for PSK auth modes only, else null
+     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
+     * @throws UnsupportedOperationException if the mode is not supported by this implementation
+     * @throws IllegalStateException if this SPI has already been initialised
+     */
+    void engineInitSender(
+            @NonNull PublicKey recipientKey,
+            @Nullable byte[] info,
+            @Nullable PrivateKey senderKey,
+            @Nullable byte[] psk,
+            @Nullable byte[] psk_id)
+            throws InvalidKeyException;
+
+    /**
+     * Initialises an HPKE SPI in one of the sender modes described in RFC 9180 with
+     * a predefined random seed to allow testing against known test vectors.
+     * <p>
+     * This mode provides absolutely no security and should only be used for testing
+     * purposes.
+     * <p>
+     * If {@code senderKey} is supplied then Asymmetric Key Authentication will be used,
+     * (MODE_AUTH)
+     * <p>
+     * If {@code psk} and {@code psk_id} are supplied then Pre-Shared Key Authentication
+     * will be used (MODE_PSK).
+     * <p>
+     * If all of {@code senderKey}, {@code psk} and {@code psk_id} are supplied then both
+     * Key and PSK authentication will be used (MODE_AUTH_PSK).
+     * <p>
+     * If neither is supplied then no sender authentication will be used (MODE_BASE).
+     * <p>
+     * Note that only base mode is currently supported on Android.
+     * <p>
+     * Public and private keys must be supplied in a format that can be used by the
+     * implementation.  An instance of the {@code "XDH"} {@link java.security.KeyFactory} can
+     * be used to translate {@code KeySpecs} or keys from another {@link java.security.Provider}
+     *
+     *
+     * @param recipientKey public key of the recipient
+     * @param info application-supplied information, may be null or empty
+     * @param senderKey private key of the sender, for symmetric auth modes only, else null
+     * @param psk pre-shared key, for PSK auth modes only, else null
+     * @param psk_id pre-shared key ID, for PSK auth modes only, else null
+     * @param sKe Predetermined random seed, should only be used for validation against
+     *            known test vectors
+     * @throws InvalidKeyException if recipientKey is null or an unsupported key format or senderKey
+     *            is an unsupported key format
+     * @throws UnsupportedOperationException if the mode is not supported by this implementation
+     * @throws IllegalStateException if this SPI has already been initialised
+     */
+    void engineInitSenderWithSeed(
+            @NonNull PublicKey recipientKey,
+            @Nullable byte[] info,
+            @Nullable PrivateKey senderKey,
+            @Nullable byte[] psk,
+            @Nullable byte[] psk_id,
+            @NonNull byte[] sKe)
+            throws InvalidKeyException;
+
+    /**
+     * Initialises an HPKE SPI in one of the recipient modes described in RFC 9180.
+     * <p>
+     * If {@code senderKey} is supplied then Asymmetric Key Authentication will be used,
+     * (MODE_AUTH)
+     * <p>
+     * If {@code psk} and {@code psk_id} are supplied then Pre-Shared Key Authentication
+     * will be used (MODE_PSK).
+     * <p>
+     * If all of {@code senderKey}, {@code psk} and {@code psk_id} are supplied then both
+     * Key and PSK authentication will be used (MODE_AUTH_PSK).
+     * <p>
+     * If neither is supplied then no sender authentication will be used (MODE_BASE).
+     * <p>
+     * Note that only base mode is currently supported on Android.
+     * <p>
+     * Public and private keys must be supplied in a format that can be used by the
+     * implementation.  An instance of the {@code "XDH"} {@link java.security.KeyFactory} can
+     * be used to translate {@code KeySpecs} or keys from another {@link java.security.Provider}
+     *
+     * @param encapsulated encapsulated ephemeral key from a sender
+     * @param recipientKey private key of the recipient
+     * @param info application-supplied information, may be null or empty
+     * @param senderKey public key of sender, for asymmetric auth modes only, else null
+     * @param psk pre-shared key, for PSK auth modes only, else null
+     * @param psk_id pre-shared key ID, for PSK auth modes only, else null
+     * @throws InvalidKeyException if recipientKey is null or an unsupported key format or senderKey
+     *         is an unsupported key format
+     * @throws UnsupportedOperationException if the mode is not supported by this implementation
+     * @throws IllegalStateException if this SPI has already been initialised
+     */
+    void engineInitRecipient(
+            @NonNull byte[] encapsulated,
+            @NonNull PrivateKey recipientKey,
+            @Nullable byte[] info,
+            @Nullable PublicKey senderKey,
+            @Nullable byte[] psk,
+            @Nullable byte[] psk_id)
+            throws InvalidKeyException;
+
+    /**
+     * Seals a message, using the internal key schedule maintained by an HPKE sender SPI.
+     *
+     * @param plaintext the plaintext
+     * @param aad optional associated data, may be null or empty
+     * @return the ciphertext
+     * @throws NullPointerException if the plaintext is null
+     * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
+     *         as a recipient
+     */
+    @NonNull byte[] engineSeal(@NonNull byte[] plaintext, @Nullable byte[] aad);
+
+    /**
+     * Opens a message, using the internal key schedule maintained by an HPKE recipient SPI.
+     *
+     * @param ciphertext the ciphertext
+     * @param aad optional associated data, may be null or empty
+     * @return the plaintext
+     * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
+     *         as a sender
+     * @throws GeneralSecurityException on decryption failures
+     */
+    @NonNull byte[] engineOpen(@NonNull byte[] ciphertext, @Nullable byte[] aad)
+            throws GeneralSecurityException;
+
+    /**
+     * Exports secret key material from this SPI as described in RFC 9180.
+     *
+     * @param length  expected output length
+     * @param context optional context string, may be null or empty
+     * @return exported value
+     * @throws IllegalArgumentException if the length is not valid for the KDF in use
+     * @throws IllegalStateException if this SPI has not been initialised
+     *
+     */
+    @NonNull byte[] engineExport(int length, @Nullable byte[] context);
+
+    /**
+     * Returns the encapsulated key material for an HPKE sender.
+     *
+     * @return the key material
+     * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
+     *         as a recipient
+     */
+    @NonNull byte[] getEncapsulated();
+}
diff --git a/android-stub/src/main/java/android/pake/PakeClientKeyManagerParameters.java b/android-stub/src/main/java/android/pake/PakeClientKeyManagerParameters.java
new file mode 100644
index 00000000..9694f12f
--- /dev/null
+++ b/android-stub/src/main/java/android/pake/PakeClientKeyManagerParameters.java
@@ -0,0 +1,119 @@
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
+package android.net.ssl;
+
+import static java.util.Objects.requireNonNull;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidParameterException;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.List;
+
+import javax.net.ssl.ManagerFactoryParameters;
+
+/**
+ * Parameters for configuring a {@code KeyManager} that supports PAKE (Password
+ * Authenticated Key Exchange).
+ *
+ * <p>This class holds the necessary information for the {@code KeyManager} to perform PAKE
+ * authentication, including the IDs of the client and server involved and the available PAKE
+ * options.</p>
+ *
+ * <p>Instances of this class are immutable. Use the {@link Builder} to create
+ * instances.</p>
+ *
+ * @hide
+ */
+public final class PakeClientKeyManagerParameters implements ManagerFactoryParameters {
+    /**
+     * Returns the client identifier.
+     *
+     * @return The client identifier.
+     */
+    public @Nullable byte[] getClientId() {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * Returns the server identifier.
+     *
+     * @return The server identifier.
+     */
+    public @Nullable byte[] getServerId() {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * Returns a copy of the list of available PAKE options.
+     *
+     * @return A copy of the list of available PAKE options.
+     */
+    public @NonNull List<PakeOption> getOptions() {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * A builder for creating {@link PakeClientKeyManagerParameters} instances.
+     *
+     * @hide
+     */
+    public static final class Builder {
+        /**
+         * Sets the ID of the client involved in the PAKE exchange.
+         *
+         * @param clientId The ID of the client involved in the PAKE exchange.
+         * @return This builder.
+         */
+        public @NonNull Builder setClientId(@Nullable byte[] clientId) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Sets the ID of the server involved in the PAKE exchange.
+         *
+         * @param serverId The ID of the server involved in the PAKE exchange.
+         * @return This builder.
+         */
+        public @NonNull Builder setServerId(@Nullable byte[] serverId) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Adds a PAKE option.
+         *
+         * @param option The PAKE option to add.
+         * @return This builder.
+         * @throws InvalidParameterException If an option with the same algorithm already exists.
+         */
+        public @NonNull Builder addOption(@NonNull PakeOption option) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Builds a new {@link PakeClientKeyManagerParameters} instance.
+         *
+         * @return A new {@link PakeClientKeyManagerParameters} instance.
+         * @throws InvalidParameterException If no PAKE options are provided.
+         */
+        public @NonNull PakeClientKeyManagerParameters build() {
+            throw new RuntimeException("Stub!");
+        }
+    }
+}
diff --git a/android-stub/src/main/java/android/pake/PakeOption.java b/android-stub/src/main/java/android/pake/PakeOption.java
new file mode 100644
index 00000000..f9d5a008
--- /dev/null
+++ b/android-stub/src/main/java/android/pake/PakeOption.java
@@ -0,0 +1,98 @@
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
+package android.net.ssl;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidParameterException;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.Map;
+
+/**
+ * An class representing a PAKE (Password Authenticated Key Exchange)
+ * option for TLS connections.
+ *
+ * <p>Instances of this class are immutable. Use the {@link Builder} to create
+ * instances.</p>
+ *
+ * @hide
+ */
+public final class PakeOption {
+    /**
+     * Returns the algorithm of the PAKE algorithm.
+     *
+     * @return The algorithm of the PAKE algorithm.
+     */
+    public @NonNull String getAlgorithm() {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * Returns the message component with the given key.
+     *
+     * @param key The algorithm of the component.
+     * @return The component data, or {@code null} if no component with the given
+     *         key exists.
+     */
+    public @Nullable byte[] getMessageComponent(@NonNull String key) {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * A builder for creating {@link PakeOption} instances.
+     *
+     * @hide
+     */
+    public static final class Builder {
+        /**
+         * Constructor for the builder.
+         *
+         * @param algorithm The algorithm of the PAKE algorithm.
+         * @throws InvalidParameterException If the algorithm is invalid.
+         */
+        public Builder(@NonNull String algorithm) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Adds a message component.
+         *
+         * @param key The algorithm of the component.
+         * @param value The component data.
+         * @return This builder.
+         * @throws InvalidParameterException If the key is invalid.
+         */
+        public @NonNull Builder addMessageComponent(@NonNull String key, @Nullable byte[] value) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Builds a new {@link PakeOption} instance.
+         *
+         * <p>This method performs validation to ensure that the message components
+         * are consistent with the PAKE algorithm.</p>
+         *
+         * @return A new {@link PakeOption} instance.
+         * @throws InvalidParameterException If the message components are invalid.
+         */
+        public @NonNull PakeOption build() {
+            throw new RuntimeException("Stub!");
+        }
+    }
+}
diff --git a/android-stub/src/main/java/android/pake/PakeServerKeyManagerParameters.java b/android-stub/src/main/java/android/pake/PakeServerKeyManagerParameters.java
new file mode 100644
index 00000000..a0fd8680
--- /dev/null
+++ b/android-stub/src/main/java/android/pake/PakeServerKeyManagerParameters.java
@@ -0,0 +1,156 @@
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
+package android.net.ssl;
+
+import static java.util.Objects.requireNonNull;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidParameterException;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+import javax.net.ssl.ManagerFactoryParameters;
+
+/**
+ * Parameters for configuring a {@code KeyManager} that supports PAKE
+ * (Password Authenticated Key Exchange) on the server side.
+ *
+ * <p>This class holds the necessary information for the {@code KeyManager} to perform PAKE
+ * authentication, including a mapping of client and server IDs (links) to their corresponding PAKE
+ * options.</p>
+ *
+ * <p>Instances of this class are immutable. Use the {@link Builder} to create
+ * instances.</p>
+ *
+ * @hide
+ */
+public final class PakeServerKeyManagerParameters implements ManagerFactoryParameters {
+    /**
+     * Returns a set of the links.
+     *
+     * @return The known links.
+     */
+    public @NonNull Set<Link> getLinks() {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * Returns an unmodifiable list of PAKE options for the given {@link Link}.
+     *
+     * @param link The link for which to retrieve the options. Should have been obtained through
+     *             {@link #getLinks}.
+     * @return An unmodifiable list of PAKE options for the given link.
+     */
+    public @NonNull List<PakeOption> getOptions(@NonNull Link link) {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * Returns an unmodifiable list of PAKE options for the given client-server pair.
+     *
+     * @param clientId The client identifier for the link.
+     * @param serverId The server identifier for the link.
+     * @return An unmodifiable list of PAKE options for the given link.
+     */
+    public @NonNull List<PakeOption> getOptions(
+            @Nullable byte[] clientId, @Nullable byte[] serverId) {
+        throw new RuntimeException("Stub!");
+    }
+
+    /**
+     * A PAKE link class combining the client and server IDs.
+     *
+     * @hide
+     */
+    public static final class Link {
+        /**
+         * Constructs a {@code Link} object.
+         *
+         * @param clientId The client identifier for the link.
+         * @param serverId The server identifier for the link.
+         */
+        private Link(@Nullable byte[] clientId, @Nullable byte[] serverId) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Returns the client identifier for the link.
+         *
+         * @return The client identifier for the link.
+         */
+        public @Nullable byte[] getClientId() {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Returns the server identifier for the link.
+         *
+         * @return The server identifier for the link.
+         */
+        public @Nullable byte[] getServerId() {
+            throw new RuntimeException("Stub!");
+        }
+
+        @Override
+        public boolean equals(Object o) {
+            throw new RuntimeException("Stub!");
+        }
+
+        @Override
+        public int hashCode() {
+            throw new RuntimeException("Stub!");
+        }
+    }
+
+    /**
+     * A builder for creating {@link PakeServerKeyManagerParameters} instances.
+     *
+     * @hide
+     */
+    public static final class Builder {
+        /**
+         * Adds PAKE options for the given client and server IDs.
+         * Only the first link for SPAKE2PLUS_PRERELEASE will be used.
+         *
+         * @param clientId The client ID.
+         * @param serverId The server ID.
+         * @param options The list of PAKE options to add.
+         * @return This builder.
+         * @throws InvalidParameterException If the provided options are invalid.
+         */
+        public @NonNull Builder setOptions(@Nullable byte[] clientId, @Nullable byte[] serverId,
+                @NonNull List<PakeOption> options) {
+            throw new RuntimeException("Stub!");
+        }
+
+        /**
+         * Builds a new {@link PakeServerKeyManagerParameters} instance.
+         *
+         * @return A new {@link PakeServerKeyManagerParameters} instance.
+         * @throws InvalidParameterException If no links are provided.
+         */
+        public @NonNull PakeServerKeyManagerParameters build() {
+            throw new RuntimeException("Stub!");
+        }
+    }
+}
diff --git a/android/build.gradle b/android/build.gradle
index bddeb741..3b8439c0 100644
--- a/android/build.gradle
+++ b/android/build.gradle
@@ -1,11 +1,5 @@
-buildscript {
-    repositories {
-        google()
-        mavenCentral()
-    }
-    dependencies {
-        classpath libs.android.tools
-    }
+plugins {
+    alias(libs.plugins.android.library)
 }
 
 description = 'Conscrypt: Android'
@@ -21,157 +15,146 @@ ext {
     androidCmakeVersion = '3.22.1'
 }
 
-if (androidSdkInstalled) {
-    apply plugin: 'com.android.library'
+// Since we're not taking a direct dependency on the constants module, we need to add an
+// explicit task dependency to make sure the code is generated.
+evaluationDependsOn(':conscrypt-constants')
 
-    // Since we're not taking a direct dependency on the constants module, we need to add an
-    // explicit task dependency to make sure the code is generated.
-    evaluationDependsOn(':conscrypt-constants')
+android {
+    namespace "org.conscrypt"
 
-    android {
-        namespace "org.conscrypt"
+    compileSdkVersion androidTargetSdkVersion
+    ndkVersion androidNdkVersion
 
-        compileSdkVersion androidTargetSdkVersion
-        ndkVersion androidNdkVersion
+    compileOptions {
+        sourceCompatibility androidMinJavaVersion
+        targetCompatibility androidMinJavaVersion
+    }
 
-        compileOptions {
-            sourceCompatibility androidMinJavaVersion
-            targetCompatibility androidMinJavaVersion
-        }
+    defaultConfig {
+        minSdkVersion androidMinSdkVersion
+        targetSdkVersion androidTargetSdkVersion
+        versionCode androidVersionCode
+        versionName androidVersionName
 
-        defaultConfig {
-            minSdkVersion androidMinSdkVersion
-            targetSdkVersion androidTargetSdkVersion
-            versionCode androidVersionCode
-            versionName androidVersionName
-
-            testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
-
-            consumerProguardFiles 'proguard-rules.pro'
-
-            externalNativeBuild {
-                cmake {
-                    arguments '-DANDROID=True',
-                            '-DANDROID_STL=c++_static',
-                            "-DBORINGSSL_HOME=$boringsslHome",
-                            "-DCMAKE_CXX_STANDARD=17",
-                            '-DCMAKE_SHARED_LINKER_FLAGS=-z max-page-size=16384'
-                    cFlags '-fvisibility=hidden',
-                            '-DBORINGSSL_SHARED_LIBRARY',
-                            '-DBORINGSSL_IMPLEMENTATION',
-                            '-DOPENSSL_SMALL',
-                            '-D_XOPEN_SOURCE=700',
-                            '-Wno-unused-parameter'
-                    targets 'conscrypt_jni'
-                }
-            }
-            ndk {
-                abiFilters 'x86', 'x86_64', 'armeabi-v7a', 'arm64-v8a'
+        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
+
+        consumerProguardFiles 'proguard-rules.pro'
+
+        externalNativeBuild {
+            cmake {
+                arguments '-DANDROID=True',
+                        '-DANDROID_STL=c++_static',
+                        "-DBORINGSSL_HOME=$boringsslHome",
+                        "-DCMAKE_CXX_STANDARD=17",
+                        '-DCMAKE_SHARED_LINKER_FLAGS=-z max-page-size=16384'
+                cFlags '-fvisibility=hidden',
+                        '-DBORINGSSL_SHARED_LIBRARY',
+                        '-DBORINGSSL_IMPLEMENTATION',
+                        '-DOPENSSL_SMALL',
+                        '-D_XOPEN_SOURCE=700',
+                        '-Wno-unused-parameter'
+                targets 'conscrypt_jni'
             }
         }
-        buildTypes {
-            release {
-                minifyEnabled false
-                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
-            }
+        ndk {
+            abiFilters 'x86', 'x86_64', 'armeabi-v7a', 'arm64-v8a'
         }
-        sourceSets.main {
-            java {
-                srcDirs = [
-                        "${rootDir}/common/src/main/java",
-                        "src/main/java"
-                ]
-                // Requires evaluationDependsOn(':conscrypt-constants') above.
-                srcDirs += project(':conscrypt-constants').sourceSets.main.java.srcDirs
-            }
-            resources {
-                srcDirs += "build/generated/resources"
-            }
+    }
+    buildTypes {
+        release {
+            minifyEnabled false
+            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
         }
-        externalNativeBuild {
-            cmake {
-                path 'CMakeLists.txt'
-                version androidCmakeVersion
-            }
+    }
+    sourceSets.main {
+        java {
+            srcDirs = [
+                    "${rootDir}/common/src/main/java",
+                    "src/main/java"
+            ]
+            // Requires evaluationDependsOn(':conscrypt-constants') above.
+            srcDirs += project(':conscrypt-constants').sourceSets.main.java.srcDirs
         }
-        lintOptions {
-            lintConfig file('lint.xml')
+        resources {
+            srcDirs += "build/generated/resources"
         }
-
-        publishing {
-            singleVariant("release") {
-                withSourcesJar()
-            }
+    }
+    externalNativeBuild {
+        cmake {
+            path 'CMakeLists.txt'
+            version androidCmakeVersion
         }
     }
-
-    configurations {
-        publicApiDocs
+    lintOptions {
+        lintConfig file('lint.xml')
     }
 
-    preBuild {
-        dependsOn generateProperties
+    publishing {
+        singleVariant("release") {
+            withSourcesJar()
+        }
     }
+}
 
-    dependencies {
-        publicApiDocs project(':conscrypt-api-doclet')
-        androidTestImplementation('androidx.test.espresso:espresso-core:3.1.1', {
-            exclude module: 'support-annotations'
-            exclude module: 'support-v4'
-            exclude module: 'support-v13'
-            exclude module: 'recyclerview-v7'
-            exclude module: 'appcompat-v7'
-            exclude module: 'design'
-        })
-        compileOnly project(':conscrypt-android-stub')
-
-        // Adds the constants module as a dependency so that we can include its generated source
-        compileOnly project(':conscrypt-constants')
-    }
+configurations {
+    publicApiDocs
+}
 
-    def javadocs = tasks.register("javadocs", Javadoc) {
-        dependsOn configurations.publicApiDocs
-        source = android.sourceSets.main.java.srcDirs
-        classpath += project.files(android.getBootClasspath().join(File.pathSeparator)) +
-                project(':conscrypt-android-stub').sourceSets.main.output
-        options {
-            showFromPublic()
-            encoding = 'UTF-8'
-            doclet = "org.conscrypt.doclet.FilterDoclet"
-            links = ['https://docs.oracle.com/en/java/javase/21/docs/api/java.base/']
-            docletpath = configurations.publicApiDocs.files as List
-        }
-        failOnError false
+preBuild {
+    dependsOn generateProperties
+}
 
-        doLast {
-            copy {
-                from "$rootDir/api-doclet/src/main/resources/styles.css"
-                into "$buildDir/docs/javadoc"
-            }
-        }
+dependencies {
+    publicApiDocs project(':conscrypt-api-doclet')
+    androidTestImplementation('androidx.test.espresso:espresso-core:3.1.1', {
+        exclude module: 'support-annotations'
+        exclude module: 'support-v4'
+        exclude module: 'support-v13'
+        exclude module: 'recyclerview-v7'
+        exclude module: 'appcompat-v7'
+        exclude module: 'design'
+    })
+    compileOnly project(':conscrypt-android-stub')
+
+    // Adds the constants module as a dependency so that we can include its generated source
+    compileOnly project(':conscrypt-constants')
+}
+
+def javadocs = tasks.register("javadocs", Javadoc) {
+    dependsOn configurations.publicApiDocs
+    source = android.sourceSets.main.java.srcDirs
+    classpath += project.files(android.getBootClasspath().join(File.pathSeparator)) +
+            project(':conscrypt-android-stub').sourceSets.main.output
+    options {
+        showFromPublic()
+        encoding = 'UTF-8'
+        doclet = "org.conscrypt.doclet.FilterDoclet"
+        links = ['https://docs.oracle.com/en/java/javase/21/docs/api/java.base/']
+        docletpath = configurations.publicApiDocs.files as List
     }
+    failOnError false
 
-    def javadocsJar = tasks.register("javadocsJar", Jar) {
-        dependsOn javadocs
-        archiveClassifier = 'javadoc'
-        from {
-            javadocs.get().destinationDir
+    doLast {
+        copy {
+            from "$rootDir/api-doclet/src/main/resources/styles.css"
+            into "$buildDir/docs/javadoc"
         }
     }
+}
 
-    afterEvaluate {
-        apply from: "$rootDir/gradle/publishing.gradle"
-        publishing.publications.maven {
-            pom.packaging = 'aar'
-            from components.release
-            artifact javadocsJar.get()
-        }
+def javadocsJar = tasks.register("javadocsJar", Jar) {
+    dependsOn javadocs
+    archiveClassifier = 'javadoc'
+    from {
+        javadocs.get().destinationDir
     }
-} else {
-    logger.warn('Android SDK has not been detected. The Android module will not be built.')
+}
 
-    // Disable all tasks
-    tasks.configureEach {
-        it.enabled = false
+afterEvaluate {
+    apply from: "$rootDir/gradle/publishing.gradle"
+    publishing.publications.maven {
+        pom.packaging = 'aar'
+        from components.release
+        artifact javadocsJar.get()
     }
 }
diff --git a/android/src/main/java/org/conscrypt/Platform.java b/android/src/main/java/org/conscrypt/Platform.java
index 3ebc1c21..c4e447a4 100644
--- a/android/src/main/java/org/conscrypt/Platform.java
+++ b/android/src/main/java/org/conscrypt/Platform.java
@@ -27,8 +27,10 @@ import android.util.Log;
 import dalvik.system.BlockGuard;
 import dalvik.system.CloseGuard;
 
-import org.conscrypt.ct.LogStore;
-import org.conscrypt.ct.Policy;
+import org.conscrypt.NativeCrypto;
+import org.conscrypt.ct.CertificateTransparency;
+import org.conscrypt.metrics.CertificateTransparencyVerificationReason;
+import org.conscrypt.metrics.NoopStatsLog;
 import org.conscrypt.metrics.Source;
 import org.conscrypt.metrics.StatsLog;
 import org.conscrypt.metrics.StatsLogImpl;
@@ -69,7 +71,6 @@ import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.NativeCrypto;
 
 /**
  * Platform-specific methods for unbundled Android.
@@ -873,6 +874,11 @@ final public class Platform {
         return enable;
     }
 
+    public static CertificateTransparencyVerificationReason reasonCTVerificationRequired(
+            String hostname) {
+        return CertificateTransparencyVerificationReason.UNKNOWN;
+    }
+
     static boolean supportsConscryptCertStore() {
         return false;
     }
@@ -899,11 +905,7 @@ final public class Platform {
         return null;
     }
 
-    static LogStore newDefaultLogStore() {
-        return null;
-    }
-
-    static Policy newDefaultPolicy() {
+    static CertificateTransparency newDefaultCertificateTransparency() {
         return null;
     }
 
@@ -947,7 +949,7 @@ final public class Platform {
         if (Build.VERSION.SDK_INT >= 30) {
             return StatsLogImpl.getInstance();
         }
-        return null;
+        return NoopStatsLog.getInstance();
     }
 
     public static Source getStatsSource() {
@@ -975,4 +977,11 @@ final public class Platform {
     public static boolean isTlsV1Supported() {
         return ENABLED_TLS_V1;
     }
+    public static boolean isPakeSupported() {
+        return false;
+    }
+
+    public static boolean isSdkGreater(int sdk) {
+        return Build.VERSION.SDK_INT > sdk;
+    }
 }
diff --git a/apex/ca-certificates/files/068570d1.0 b/apex/ca-certificates/files/068570d1.0
new file mode 100644
index 00000000..81ca163c
--- /dev/null
+++ b/apex/ca-certificates/files/068570d1.0
@@ -0,0 +1,56 @@
+-----BEGIN CERTIFICATE-----
+MIICejCCAgCgAwIBAgIQMZch7a+JQn81QYehZ1ZMbTAKBggqhkjOPQQDAzBuMQsw
+CQYDVQQGEwJFUzEcMBoGA1UECgwTRmlybWFwcm9mZXNpb25hbCBTQTEYMBYGA1UE
+YQwPVkFURVMtQTYyNjM0MDY4MScwJQYDVQQDDB5GSVJNQVBST0ZFU0lPTkFMIENB
+IFJPT1QtQSBXRUIwHhcNMjIwNDA2MDkwMTM2WhcNNDcwMzMxMDkwMTM2WjBuMQsw
+CQYDVQQGEwJFUzEcMBoGA1UECgwTRmlybWFwcm9mZXNpb25hbCBTQTEYMBYGA1UE
+YQwPVkFURVMtQTYyNjM0MDY4MScwJQYDVQQDDB5GSVJNQVBST0ZFU0lPTkFMIENB
+IFJPT1QtQSBXRUIwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARHU+osEaR3xyrq89Zf
+e9MEkVz6iMYiuYMQYneEMy3pA4jU4DP37XcsSmDq5G+tbbT4TIqk5B/K6k84Si6C
+cyvHZpsKjECcfIr28jlgst7L7Ljkb+qbXbdTkBgyVcUgt5SjYzBhMA8GA1UdEwEB
+/wQFMAMBAf8wHwYDVR0jBBgwFoAUk+FDY1w8ndYn81LsF7Kpryz3dvgwHQYDVR0O
+BBYEFJPhQ2NcPJ3WJ/NS7Beyqa8s93b4MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjO
+PQQDAwNoADBlAjAdfKR7w4l1M+E7qUW/Runpod3JIha3RxEL2Jq68cgLcFBTApFw
+hVmpHqTm6iMxoAACMQD94vizrxa5HnPEluPBMBnYfubDl94cT7iJLzPrSA8Z94dG
+XSaQpYXFuXqUPoeovQA=
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            31:97:21:ed:af:89:42:7f:35:41:87:a1:67:56:4c:6d
+    Signature Algorithm: ecdsa-with-SHA384
+        Issuer: C=ES, O=Firmaprofesional SA/2.5.4.97=VATES-A62634068, CN=FIRMAPROFESIONAL CA ROOT-A WEB
+        Validity
+            Not Before: Apr  6 09:01:36 2022 GMT
+            Not After : Mar 31 09:01:36 2047 GMT
+        Subject: C=ES, O=Firmaprofesional SA/2.5.4.97=VATES-A62634068, CN=FIRMAPROFESIONAL CA ROOT-A WEB
+        Subject Public Key Info:
+            Public Key Algorithm: id-ecPublicKey
+                Public-Key: (P-384)
+                pub:
+                    04:47:53:ea:2c:11:a4:77:c7:2a:ea:f3:d6:5f:7b:
+                    d3:04:91:5c:fa:88:c6:22:b9:83:10:62:77:84:33:
+                    2d:e9:03:88:d4:e0:33:f7:ed:77:2c:4a:60:ea:e4:
+                    6f:ad:6d:b4:f8:4c:8a:a4:e4:1f:ca:ea:4f:38:4a:
+                    2e:82:73:2b:c7:66:9b:0a:8c:40:9c:7c:8a:f6:f2:
+                    39:60:b2:de:cb:ec:b8:e4:6f:ea:9b:5d:b7:53:90:
+                    18:32:55:c5:20:b7:94
+        X509v3 extensions:
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Authority Key Identifier: 
+                keyid:93:E1:43:63:5C:3C:9D:D6:27:F3:52:EC:17:B2:A9:AF:2C:F7:76:F8
+
+            X509v3 Subject Key Identifier: 
+                93:E1:43:63:5C:3C:9D:D6:27:F3:52:EC:17:B2:A9:AF:2C:F7:76:F8
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+    Signature Algorithm: ecdsa-with-SHA384
+         30:65:02:30:1d:7c:a4:7b:c3:89:75:33:e1:3b:a9:45:bf:46:
+         e9:e9:a1:dd:c9:22:16:b7:47:11:0b:d8:9a:ba:f1:c8:0b:70:
+         50:53:02:91:70:85:59:a9:1e:a4:e6:ea:23:31:a0:00:02:31:
+         00:fd:e2:f8:b3:af:16:b9:1e:73:c4:96:e3:c1:30:19:d8:7e:
+         e6:c3:97:de:1c:4f:b8:89:2f:33:eb:48:0f:19:f7:87:46:5d:
+         26:90:a5:85:c5:b9:7a:94:3e:87:a8:bd:00
+SHA1 Fingerprint=A8:31:11:74:A6:14:15:0D:CA:77:DD:0E:E4:0C:5D:58:FC:A0:72:A5
diff --git a/apex/ca-certificates/files/47b283f6.0 b/apex/ca-certificates/files/47b283f6.0
new file mode 100644
index 00000000..406f9350
--- /dev/null
+++ b/apex/ca-certificates/files/47b283f6.0
@@ -0,0 +1,124 @@
+-----BEGIN CERTIFICATE-----
+MIIFjTCCA3WgAwIBAgIQQAE0jMIAAAAAAAAAATzyxjANBgkqhkiG9w0BAQwFADBQ
+MQswCQYDVQQGEwJUVzESMBAGA1UEChMJVEFJV0FOLUNBMRAwDgYDVQQLEwdSb290
+IENBMRswGQYDVQQDExJUV0NBIENZQkVSIFJvb3QgQ0EwHhcNMjIxMTIyMDY1NDI5
+WhcNNDcxMTIyMTU1OTU5WjBQMQswCQYDVQQGEwJUVzESMBAGA1UEChMJVEFJV0FO
+LUNBMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJUV0NBIENZQkVSIFJvb3Qg
+Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDG+Moe2Qkgfh1sTs6P
+40czRJzHyWmqOlt47nDSkvgEs1JSHWdyKKHfi12VCv7qze33Kc7wb3+szT3vsxxF
+avcokPFhV8UMxKNQXd7UtcsZyoC5dc4pztKFIuwCY8xEMCDa6pFbVuYdHNWdZsc/
+34bKS1PE2Y2yHer43CdTo0fhYcx9tbD47nORxc5zb87uEB8aBs/pJ2DFTxnk684i
+JkXXYJndzk834H/nY62wuFm40AZoNWDTNq5xQwTxaWV4fPMf88oon1oglWa0zbfu
+j3ikRRjpJi+NmykosaS3Om251Bw4ckVYsV7r8Cibt4LK/c/WMw+f+5eesRycnupf
+Xtuq3VTpMCEobY5583WSjCb+3MX2w7DfRFlDo7YDKPYIMKoNM+HvnKkHIuNZW0CP
+2oi3aQiotyMuRAlZN1vH4xfyIutuOVLF3lSnmMlLIJXcRolftBL5hSmO68gnFSDA
+S9TMfAxsNAwmmyYxpjyn9tnQS6Jk/zuZQXLB4HCX8SS7K8R0IrGsayIyJNN4KsDA
+oS/xUgXJP+92ZuJF2A09rZXIx4kmyA+upwMu+8Ff+iDhcK2wZSA3M2Cw1a/XDBzC
+kHDXShi8fgGwsOsVHkQGzaRP6AzRwyAQ4VRlnrZR0Bp2a0JaWHY06rc3Ga4udfmW
+5cFZ95RXKSWNOkyrTZpB0F8mAwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYD
+VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSdhWEUfMFib5do5E83QOGt4A1WNzAd
+BgNVHQ4EFgQUnYVhFHzBYm+XaORPN0DhreANVjcwDQYJKoZIhvcNAQEMBQADggIB
+AGSPesRiDrWIzLjHhg6hShbNcAu3p4ULs3a2D6f/CIsLJc+o1IN1KriWiLb73y0t
+tGlTITVX1olNc79pj3CjYcya2x6a4CD4bLubIp1dhDGaLIrdaqHXKGnK/nZVekZn
+68xDiBaiA9a5F/gZbG0jAn/xX9AKKSM70aoK7akXJlQKTcKlTfjF/biBzysseKNn
+TKkHmvPfXvt89YnNdJdhEGoHK4Fa0o635yDRIG4kqIQnoVesqlVYL9zZyvpoBJ7t
+RCT5dEA7IzOrg1oYJkK2bVS1FmAwbLGg+LhBoF1JSdJlBTrq/p1hvIbZv97Tujqx
+f36SNI7JAG7cmL3c7IAFrQI932XtCwP39xaEBDG6k5TY8hL4iuO/Qq+n1M0RFxbI
+Qh0UqEL20kCGoE8jypZFVmAGzbdVAaYBlGX+bgUJurSkquLvWL69J1bY73NxW0Qz
+8ppy6rBePm6pUlvscG21h483XjyMnM7k8M4MZ0HMzvaAq07MTFb1wWFZk7Q+ptq4
+NxKfKjLji7gh7MMrZQzvIt6IKTtM1/r+t+FHvpw+PoP7UV31aPcuIYXcv/Fa4nzX
+xeSDwWrruoBa3lwtcHb4yOWHh8qgnaHlIhInD0Q9HWzq1MKLL295q39QpsQZp6F6
+t5b5wR9iWqJDB0BeJsas7a5wFsWqynKKTbDPAYsDP27X
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            40:01:34:8c:c2:00:00:00:00:00:00:00:01:3c:f2:c6
+    Signature Algorithm: sha384WithRSAEncryption
+        Issuer: C=TW, O=TAIWAN-CA, OU=Root CA, CN=TWCA CYBER Root CA
+        Validity
+            Not Before: Nov 22 06:54:29 2022 GMT
+            Not After : Nov 22 15:59:59 2047 GMT
+        Subject: C=TW, O=TAIWAN-CA, OU=Root CA, CN=TWCA CYBER Root CA
+        Subject Public Key Info:
+            Public Key Algorithm: rsaEncryption
+                Public-Key: (4096 bit)
+                Modulus:
+                    00:c6:f8:ca:1e:d9:09:20:7e:1d:6c:4e:ce:8f:e3:
+                    47:33:44:9c:c7:c9:69:aa:3a:5b:78:ee:70:d2:92:
+                    f8:04:b3:52:52:1d:67:72:28:a1:df:8b:5d:95:0a:
+                    fe:ea:cd:ed:f7:29:ce:f0:6f:7f:ac:cd:3d:ef:b3:
+                    1c:45:6a:f7:28:90:f1:61:57:c5:0c:c4:a3:50:5d:
+                    de:d4:b5:cb:19:ca:80:b9:75:ce:29:ce:d2:85:22:
+                    ec:02:63:cc:44:30:20:da:ea:91:5b:56:e6:1d:1c:
+                    d5:9d:66:c7:3f:df:86:ca:4b:53:c4:d9:8d:b2:1d:
+                    ea:f8:dc:27:53:a3:47:e1:61:cc:7d:b5:b0:f8:ee:
+                    73:91:c5:ce:73:6f:ce:ee:10:1f:1a:06:cf:e9:27:
+                    60:c5:4f:19:e4:eb:ce:22:26:45:d7:60:99:dd:ce:
+                    4f:37:e0:7f:e7:63:ad:b0:b8:59:b8:d0:06:68:35:
+                    60:d3:36:ae:71:43:04:f1:69:65:78:7c:f3:1f:f3:
+                    ca:28:9f:5a:20:95:66:b4:cd:b7:ee:8f:78:a4:45:
+                    18:e9:26:2f:8d:9b:29:28:b1:a4:b7:3a:6d:b9:d4:
+                    1c:38:72:45:58:b1:5e:eb:f0:28:9b:b7:82:ca:fd:
+                    cf:d6:33:0f:9f:fb:97:9e:b1:1c:9c:9e:ea:5f:5e:
+                    db:aa:dd:54:e9:30:21:28:6d:8e:79:f3:75:92:8c:
+                    26:fe:dc:c5:f6:c3:b0:df:44:59:43:a3:b6:03:28:
+                    f6:08:30:aa:0d:33:e1:ef:9c:a9:07:22:e3:59:5b:
+                    40:8f:da:88:b7:69:08:a8:b7:23:2e:44:09:59:37:
+                    5b:c7:e3:17:f2:22:eb:6e:39:52:c5:de:54:a7:98:
+                    c9:4b:20:95:dc:46:89:5f:b4:12:f9:85:29:8e:eb:
+                    c8:27:15:20:c0:4b:d4:cc:7c:0c:6c:34:0c:26:9b:
+                    26:31:a6:3c:a7:f6:d9:d0:4b:a2:64:ff:3b:99:41:
+                    72:c1:e0:70:97:f1:24:bb:2b:c4:74:22:b1:ac:6b:
+                    22:32:24:d3:78:2a:c0:c0:a1:2f:f1:52:05:c9:3f:
+                    ef:76:66:e2:45:d8:0d:3d:ad:95:c8:c7:89:26:c8:
+                    0f:ae:a7:03:2e:fb:c1:5f:fa:20:e1:70:ad:b0:65:
+                    20:37:33:60:b0:d5:af:d7:0c:1c:c2:90:70:d7:4a:
+                    18:bc:7e:01:b0:b0:eb:15:1e:44:06:cd:a4:4f:e8:
+                    0c:d1:c3:20:10:e1:54:65:9e:b6:51:d0:1a:76:6b:
+                    42:5a:58:76:34:ea:b7:37:19:ae:2e:75:f9:96:e5:
+                    c1:59:f7:94:57:29:25:8d:3a:4c:ab:4d:9a:41:d0:
+                    5f:26:03
+                Exponent: 65537 (0x10001)
+        X509v3 extensions:
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Authority Key Identifier: 
+                keyid:9D:85:61:14:7C:C1:62:6F:97:68:E4:4F:37:40:E1:AD:E0:0D:56:37
+
+            X509v3 Subject Key Identifier: 
+                9D:85:61:14:7C:C1:62:6F:97:68:E4:4F:37:40:E1:AD:E0:0D:56:37
+    Signature Algorithm: sha384WithRSAEncryption
+         64:8f:7a:c4:62:0e:b5:88:cc:b8:c7:86:0e:a1:4a:16:cd:70:
+         0b:b7:a7:85:0b:b3:76:b6:0f:a7:ff:08:8b:0b:25:cf:a8:d4:
+         83:75:2a:b8:96:88:b6:fb:df:2d:2d:b4:69:53:21:35:57:d6:
+         89:4d:73:bf:69:8f:70:a3:61:cc:9a:db:1e:9a:e0:20:f8:6c:
+         bb:9b:22:9d:5d:84:31:9a:2c:8a:dd:6a:a1:d7:28:69:ca:fe:
+         76:55:7a:46:67:eb:cc:43:88:16:a2:03:d6:b9:17:f8:19:6c:
+         6d:23:02:7f:f1:5f:d0:0a:29:23:3b:d1:aa:0a:ed:a9:17:26:
+         54:0a:4d:c2:a5:4d:f8:c5:fd:b8:81:cf:2b:2c:78:a3:67:4c:
+         a9:07:9a:f3:df:5e:fb:7c:f5:89:cd:74:97:61:10:6a:07:2b:
+         81:5a:d2:8e:b7:e7:20:d1:20:6e:24:a8:84:27:a1:57:ac:aa:
+         55:58:2f:dc:d9:ca:fa:68:04:9e:ed:44:24:f9:74:40:3b:23:
+         33:ab:83:5a:18:26:42:b6:6d:54:b5:16:60:30:6c:b1:a0:f8:
+         b8:41:a0:5d:49:49:d2:65:05:3a:ea:fe:9d:61:bc:86:d9:bf:
+         de:d3:ba:3a:b1:7f:7e:92:34:8e:c9:00:6e:dc:98:bd:dc:ec:
+         80:05:ad:02:3d:df:65:ed:0b:03:f7:f7:16:84:04:31:ba:93:
+         94:d8:f2:12:f8:8a:e3:bf:42:af:a7:d4:cd:11:17:16:c8:42:
+         1d:14:a8:42:f6:d2:40:86:a0:4f:23:ca:96:45:56:60:06:cd:
+         b7:55:01:a6:01:94:65:fe:6e:05:09:ba:b4:a4:aa:e2:ef:58:
+         be:bd:27:56:d8:ef:73:71:5b:44:33:f2:9a:72:ea:b0:5e:3e:
+         6e:a9:52:5b:ec:70:6d:b5:87:8f:37:5e:3c:8c:9c:ce:e4:f0:
+         ce:0c:67:41:cc:ce:f6:80:ab:4e:cc:4c:56:f5:c1:61:59:93:
+         b4:3e:a6:da:b8:37:12:9f:2a:32:e3:8b:b8:21:ec:c3:2b:65:
+         0c:ef:22:de:88:29:3b:4c:d7:fa:fe:b7:e1:47:be:9c:3e:3e:
+         83:fb:51:5d:f5:68:f7:2e:21:85:dc:bf:f1:5a:e2:7c:d7:c5:
+         e4:83:c1:6a:eb:ba:80:5a:de:5c:2d:70:76:f8:c8:e5:87:87:
+         ca:a0:9d:a1:e5:22:12:27:0f:44:3d:1d:6c:ea:d4:c2:8b:2f:
+         6f:79:ab:7f:50:a6:c4:19:a7:a1:7a:b7:96:f9:c1:1f:62:5a:
+         a2:43:07:40:5e:26:c6:ac:ed:ae:70:16:c5:aa:ca:72:8a:4d:
+         b0:cf:01:8b:03:3f:6e:d7
+SHA1 Fingerprint=F6:B1:1C:1A:83:38:E9:7B:DB:B3:A8:C8:33:24:E0:2D:9C:7F:26:66
diff --git a/apex/ca-certificates/files/5d139d02.0 b/apex/ca-certificates/files/5d139d02.0
new file mode 100644
index 00000000..8c10fa2e
--- /dev/null
+++ b/apex/ca-certificates/files/5d139d02.0
@@ -0,0 +1,79 @@
+-----BEGIN CERTIFICATE-----
+MIIDcjCCAlqgAwIBAgIUZvnHwa/swlG07VOX5uaCwysckBYwDQYJKoZIhvcNAQEL
+BQAwUTELMAkGA1UEBhMCSlAxIzAhBgNVBAoTGkN5YmVydHJ1c3QgSmFwYW4gQ28u
+LCBMdGQuMR0wGwYDVQQDExRTZWN1cmVTaWduIFJvb3QgQ0ExMjAeFw0yMDA0MDgw
+NTM2NDZaFw00MDA0MDgwNTM2NDZaMFExCzAJBgNVBAYTAkpQMSMwIQYDVQQKExpD
+eWJlcnRydXN0IEphcGFuIENvLiwgTHRkLjEdMBsGA1UEAxMUU2VjdXJlU2lnbiBS
+b290IENBMTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6OcE3emhF
+KxS06+QT61d1I02PJC0W6K6OyX2kVzsqdiUzg2zqMoqUm048luT9Ub+ZyZN+v/mt
+p7JIKwccJ/VMvHASd6SFVLX9kHrko+RRWAPNEHl57muTH2SOa2SroxPjcf59q5zd
+J1M3s6oYwlkm7Fsf0uZlfO+TvdhYXAvA42VvPMfKWeP+bl+sg779XSVOKik71gur
+FzJ4pOE+lEa+Ym6b3kaosRbnhW70CEBFEaCeVESE99g2zvVQR9wsMJvuwPWW0v4J
+hscGWa5Pro4RmHvzC1KqYiaqId+OJTN5lxZJjfU+1UefNzFJM3IFTQy2VYzxV4+K
+h9GtxRESOaCtAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
+AgEGMB0GA1UdDgQWBBRXNPN0zwRL1SXm8UC2LEzZLemgrTANBgkqhkiG9w0BAQsF
+AAOCAQEAPrvbFxbS8hQBICw4g0utvsqFepq2m2um4fylOqyttCg6r9cBg0krY6Ld
+mmQOmFxv3Y67ilQiLUoT865AQ9tPkbeGGuwAtEGBpE/6aouIs3YIcipJQMPTw4WJ
+mBClnW8Zt7vPemVV2zfrPIpyMpcemik+rY3moxtt9XUa5rBouVui7mlHJzWhhpmA
+8zNL4WukJsPvdFlseqJkth5Ew1DgDzk9qTPxpfPSvWKErI4cqc1avTc7bgoitPQV
+55FYxTpE05Uo2cBl6XLK0A+9H7MV2anjpEcJnuDLN/v9vZfVvhgaaaI5gdka9at/
+yOPiZwud9AzqVN/Ssq+xIvEg37xEHA==
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            66:f9:c7:c1:af:ec:c2:51:b4:ed:53:97:e6:e6:82:c3:2b:1c:90:16
+    Signature Algorithm: sha256WithRSAEncryption
+        Issuer: C=JP, O=Cybertrust Japan Co., Ltd., CN=SecureSign Root CA12
+        Validity
+            Not Before: Apr  8 05:36:46 2020 GMT
+            Not After : Apr  8 05:36:46 2040 GMT
+        Subject: C=JP, O=Cybertrust Japan Co., Ltd., CN=SecureSign Root CA12
+        Subject Public Key Info:
+            Public Key Algorithm: rsaEncryption
+                Public-Key: (2048 bit)
+                Modulus:
+                    00:ba:39:c1:37:7a:68:45:2b:14:b4:eb:e4:13:eb:
+                    57:75:23:4d:8f:24:2d:16:e8:ae:8e:c9:7d:a4:57:
+                    3b:2a:76:25:33:83:6c:ea:32:8a:94:9b:4e:3c:96:
+                    e4:fd:51:bf:99:c9:93:7e:bf:f9:ad:a7:b2:48:2b:
+                    07:1c:27:f5:4c:bc:70:12:77:a4:85:54:b5:fd:90:
+                    7a:e4:a3:e4:51:58:03:cd:10:79:79:ee:6b:93:1f:
+                    64:8e:6b:64:ab:a3:13:e3:71:fe:7d:ab:9c:dd:27:
+                    53:37:b3:aa:18:c2:59:26:ec:5b:1f:d2:e6:65:7c:
+                    ef:93:bd:d8:58:5c:0b:c0:e3:65:6f:3c:c7:ca:59:
+                    e3:fe:6e:5f:ac:83:be:fd:5d:25:4e:2a:29:3b:d6:
+                    0b:ab:17:32:78:a4:e1:3e:94:46:be:62:6e:9b:de:
+                    46:a8:b1:16:e7:85:6e:f4:08:40:45:11:a0:9e:54:
+                    44:84:f7:d8:36:ce:f5:50:47:dc:2c:30:9b:ee:c0:
+                    f5:96:d2:fe:09:86:c7:06:59:ae:4f:ae:8e:11:98:
+                    7b:f3:0b:52:aa:62:26:aa:21:df:8e:25:33:79:97:
+                    16:49:8d:f5:3e:d5:47:9f:37:31:49:33:72:05:4d:
+                    0c:b6:55:8c:f1:57:8f:8a:87:d1:ad:c5:11:12:39:
+                    a0:ad
+                Exponent: 65537 (0x10001)
+        X509v3 extensions:
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+            X509v3 Subject Key Identifier: 
+                57:34:F3:74:CF:04:4B:D5:25:E6:F1:40:B6:2C:4C:D9:2D:E9:A0:AD
+    Signature Algorithm: sha256WithRSAEncryption
+         3e:bb:db:17:16:d2:f2:14:01:20:2c:38:83:4b:ad:be:ca:85:
+         7a:9a:b6:9b:6b:a6:e1:fc:a5:3a:ac:ad:b4:28:3a:af:d7:01:
+         83:49:2b:63:a2:dd:9a:64:0e:98:5c:6f:dd:8e:bb:8a:54:22:
+         2d:4a:13:f3:ae:40:43:db:4f:91:b7:86:1a:ec:00:b4:41:81:
+         a4:4f:fa:6a:8b:88:b3:76:08:72:2a:49:40:c3:d3:c3:85:89:
+         98:10:a5:9d:6f:19:b7:bb:cf:7a:65:55:db:37:eb:3c:8a:72:
+         32:97:1e:9a:29:3e:ad:8d:e6:a3:1b:6d:f5:75:1a:e6:b0:68:
+         b9:5b:a2:ee:69:47:27:35:a1:86:99:80:f3:33:4b:e1:6b:a4:
+         26:c3:ef:74:59:6c:7a:a2:64:b6:1e:44:c3:50:e0:0f:39:3d:
+         a9:33:f1:a5:f3:d2:bd:62:84:ac:8e:1c:a9:cd:5a:bd:37:3b:
+         6e:0a:22:b4:f4:15:e7:91:58:c5:3a:44:d3:95:28:d9:c0:65:
+         e9:72:ca:d0:0f:bd:1f:b3:15:d9:a9:e3:a4:47:09:9e:e0:cb:
+         37:fb:fd:bd:97:d5:be:18:1a:69:a2:39:81:d9:1a:f5:ab:7f:
+         c8:e3:e2:67:0b:9d:f4:0c:ea:54:df:d2:b2:af:b1:22:f1:20:
+         df:bc:44:1c
+SHA1 Fingerprint=7A:22:1E:3D:DE:1B:06:AC:9E:C8:47:70:16:8E:3C:E5:F7:6B:06:F4
diff --git a/apex/ca-certificates/files/6b483515.0 b/apex/ca-certificates/files/6b483515.0
new file mode 100644
index 00000000..c5a0e5a4
--- /dev/null
+++ b/apex/ca-certificates/files/6b483515.0
@@ -0,0 +1,52 @@
+-----BEGIN CERTIFICATE-----
+MIICQjCCAcmgAwIBAgIQNjqWjMlcsljN0AFdxeVXADAKBggqhkjOPQQDAzBjMQsw
+CQYDVQQGEwJERTEnMCUGA1UECgweRGV1dHNjaGUgVGVsZWtvbSBTZWN1cml0eSBH
+bWJIMSswKQYDVQQDDCJUZWxla29tIFNlY3VyaXR5IFRMUyBFQ0MgUm9vdCAyMDIw
+MB4XDTIwMDgyNTA3NDgyMFoXDTQ1MDgyNTIzNTk1OVowYzELMAkGA1UEBhMCREUx
+JzAlBgNVBAoMHkRldXRzY2hlIFRlbGVrb20gU2VjdXJpdHkgR21iSDErMCkGA1UE
+AwwiVGVsZWtvbSBTZWN1cml0eSBUTFMgRUNDIFJvb3QgMjAyMDB2MBAGByqGSM49
+AgEGBSuBBAAiA2IABM6//leov9Wq9xCazbzREaK9Z0LMkOsVGJDZos0MKiXrPk/O
+tdKPD/M12kOLAoC+b1EkHQ9rK8qfwm9QMuU3ILYg/4gND21Ju9sGpIeQkpT0CdDP
+f8iAC8GXs7s1J8nCG6NCMEAwHQYDVR0OBBYEFONyzG6VmUex5rNhTNHLq+O6zd6f
+MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
+MGQCMHVSi7ekEE+uShCLsoRbQuHmKjYC2qBuGT8lv9pZMo7k+5Dck2TOrbRBR2Di
+z6fLHgIwN0GMZt9Ba9aDAEH9L1r3ULRn0SyocddDypwnJJGDSA3PzfdUga/sf+Rn
+27iQ7t0l
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            36:3a:96:8c:c9:5c:b2:58:cd:d0:01:5d:c5:e5:57:00
+    Signature Algorithm: ecdsa-with-SHA384
+        Issuer: C=DE, O=Deutsche Telekom Security GmbH, CN=Telekom Security TLS ECC Root 2020
+        Validity
+            Not Before: Aug 25 07:48:20 2020 GMT
+            Not After : Aug 25 23:59:59 2045 GMT
+        Subject: C=DE, O=Deutsche Telekom Security GmbH, CN=Telekom Security TLS ECC Root 2020
+        Subject Public Key Info:
+            Public Key Algorithm: id-ecPublicKey
+                Public-Key: (P-384)
+                pub:
+                    04:ce:bf:fe:57:a8:bf:d5:aa:f7:10:9a:cd:bc:d1:
+                    11:a2:bd:67:42:cc:90:eb:15:18:90:d9:a2:cd:0c:
+                    2a:25:eb:3e:4f:ce:b5:d2:8f:0f:f3:35:da:43:8b:
+                    02:80:be:6f:51:24:1d:0f:6b:2b:ca:9f:c2:6f:50:
+                    32:e5:37:20:b6:20:ff:88:0d:0f:6d:49:bb:db:06:
+                    a4:87:90:92:94:f4:09:d0:cf:7f:c8:80:0b:c1:97:
+                    b3:bb:35:27:c9:c2:1b
+        X509v3 extensions:
+            X509v3 Subject Key Identifier: 
+                E3:72:CC:6E:95:99:47:B1:E6:B3:61:4C:D1:CB:AB:E3:BA:CD:DE:9F
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+    Signature Algorithm: ecdsa-with-SHA384
+         30:64:02:30:75:52:8b:b7:a4:10:4f:ae:4a:10:8b:b2:84:5b:
+         42:e1:e6:2a:36:02:da:a0:6e:19:3f:25:bf:da:59:32:8e:e4:
+         fb:90:dc:93:64:ce:ad:b4:41:47:60:e2:cf:a7:cb:1e:02:30:
+         37:41:8c:66:df:41:6b:d6:83:00:41:fd:2f:5a:f7:50:b4:67:
+         d1:2c:a8:71:d7:43:ca:9c:27:24:91:83:48:0d:cf:cd:f7:54:
+         81:af:ec:7f:e4:67:db:b8:90:ee:dd:25
+SHA1 Fingerprint=C0:F8:96:C5:A9:3B:01:06:21:07:DA:18:42:48:BC:E9:9D:88:D5:EC
diff --git a/apex/ca-certificates/files/6f7454b3.0 b/apex/ca-certificates/files/6f7454b3.0
deleted file mode 100644
index 7e1a2d38..00000000
--- a/apex/ca-certificates/files/6f7454b3.0
+++ /dev/null
@@ -1,120 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIFfzCCA2egAwIBAgIJAOF8N0D9G/5nMA0GCSqGSIb3DQEBDAUAMF0xCzAJBgNV
-BAYTAkpQMSUwIwYDVQQKExxTRUNPTSBUcnVzdCBTeXN0ZW1zIENPLixMVEQuMScw
-JQYDVQQDEx5TZWN1cml0eSBDb21tdW5pY2F0aW9uIFJvb3RDQTMwHhcNMTYwNjE2
-MDYxNzE2WhcNMzgwMTE4MDYxNzE2WjBdMQswCQYDVQQGEwJKUDElMCMGA1UEChMc
-U0VDT00gVHJ1c3QgU3lzdGVtcyBDTy4sTFRELjEnMCUGA1UEAxMeU2VjdXJpdHkg
-Q29tbXVuaWNhdGlvbiBSb290Q0EzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
-CgKCAgEA48lySfcw3gl8qUCBWNO0Ot26YQ+TUG5pPDXC7ltzkBtnTCHsXzW7OT4r
-CmDvu20rhvtxosis5FaU+cmvsXLUIKx00rgVrVH+hXShuRD+BYD5UpOzQD11EKzA
-lrenfna84xtSGc4RHwsENPXY9Wk8d/Nk9A2qhd7gCVAEF5aEt8iKvE1y/By7z/MG
-TfmfZPd+pmaGNXHIEYBMwXFAWB6+oHP2/D5Q4eAvJj1+XCO1eXDe+uDRpdYMQXF7
-9+qMHIjH7Iv10S9VlkZ8WjtYO/u62C21Jdp6Ts9EriGmnpjKIG58u4iFW/vAEGK7
-8vknR+/RiTlDxN/e4UG/VHMgly1s2vPUB6PmudhvrvyMGS7TZ2crldtYXLVqAvO4
-g160a75BflcJdURQVc1aEWEhCmHCqYj9E7wtiS/NYeCVvsq1e+F7NGcLH7YMx3we
-GVPKp7FKFSBWFHA9K4IsD50VHUeAR/94mQ4xr28+j+2GaR57GIgUssL8gjMunEst
-+3A7caoreyYn8xrC3PsXuKHqy6C0rtOUfnrQq8PsOC0RLoi/1D+tEjtCrI8Cbn3M
-0V9hvqG8OmpI6iZVIhZdXw3/JzOfGAN0iltSIEdrRU0id4xVJ/CvHozJgyJUt5rQ
-T9nO/NkuHJYosQLTA70lUhw0Zk8jq/R3gpYd0VcwCBEF/VfR2ccCAwEAAaNCMEAw
-HQYDVR0OBBYEFGQUfPxYchamCik0FW8qy7z8r6irMA4GA1UdDwEB/wQEAwIBBjAP
-BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDAUAA4ICAQDcAiMI4u8hOscNtybS
-YpOnpSNyByCCYN8Y11StaSWSntkUz5m5UoHPrmyKO1o5yGwBQ8IibQLwYs1OY0PA
-FNr0Y/Dq9HHuTofjcan0yVflLl8cebsjqodEV+m9NU1Bu0soo5iyG9kLFwfl9+qd
-9XbXv8S2gVj/yP9kaWJ5rW4OH3/uHWnlt3Jxs/6lATWUVCvAUm2PVcTJ0rjLyjQI
-UYWg9by0F1jqClx6vWPGOi//lkkZhOpn2ASxYfQAW0q3nHE3GYV5v4GwxxMOdnE+
-OoAGrgYWp421wsTL/0ClXI2lyTrtcoHKXJg80jQDdwj98ClZXSEIx2C/pHF7uNke
-gr4Jr2VvKKu/S7XuPghHJ6APbw+LP6yVGPO5DtxnVW5inkYO0QR4ynKudtml+LLf
-iAlhi+8kTtFZP1rUPcmTPCtk9YENFpb3ksP+MW/oKjJ0DvRMmEoYDjBU1cXrvMUV
-nuiZIesnKwkK2/HmcBhWuwzkvvnoEKQTkrgc4NtnHVMDpCKn3F2SEDzq//wbEBrD
-2NCcnWXL0CsnMQMeNuE9dnUM/0Umud1RvCPHX9jYhxBAEg09ODfnRDwYwFMJZI//
-1ZqmfHAuc1Uh6N//g7kdPjIe1qZ9LPFm6Vwdp6POXiUyK+OVrCoHzrQoeIY8Laad
-TdJ0MN1kURXbg4NR16/9M51NZg==
------END CERTIFICATE-----
-Certificate:
-    Data:
-        Version: 3 (0x2)
-        Serial Number: 16247922307909811815 (0xe17c3740fd1bfe67)
-    Signature Algorithm: sha384WithRSAEncryption
-        Issuer: C=JP, O=SECOM Trust Systems CO.,LTD., CN=Security Communication RootCA3
-        Validity
-            Not Before: Jun 16 06:17:16 2016 GMT
-            Not After : Jan 18 06:17:16 2038 GMT
-        Subject: C=JP, O=SECOM Trust Systems CO.,LTD., CN=Security Communication RootCA3
-        Subject Public Key Info:
-            Public Key Algorithm: rsaEncryption
-                Public-Key: (4096 bit)
-                Modulus:
-                    00:e3:c9:72:49:f7:30:de:09:7c:a9:40:81:58:d3:
-                    b4:3a:dd:ba:61:0f:93:50:6e:69:3c:35:c2:ee:5b:
-                    73:90:1b:67:4c:21:ec:5f:35:bb:39:3e:2b:0a:60:
-                    ef:bb:6d:2b:86:fb:71:a2:c8:ac:e4:56:94:f9:c9:
-                    af:b1:72:d4:20:ac:74:d2:b8:15:ad:51:fe:85:74:
-                    a1:b9:10:fe:05:80:f9:52:93:b3:40:3d:75:10:ac:
-                    c0:96:b7:a7:7e:76:bc:e3:1b:52:19:ce:11:1f:0b:
-                    04:34:f5:d8:f5:69:3c:77:f3:64:f4:0d:aa:85:de:
-                    e0:09:50:04:17:96:84:b7:c8:8a:bc:4d:72:fc:1c:
-                    bb:cf:f3:06:4d:f9:9f:64:f7:7e:a6:66:86:35:71:
-                    c8:11:80:4c:c1:71:40:58:1e:be:a0:73:f6:fc:3e:
-                    50:e1:e0:2f:26:3d:7e:5c:23:b5:79:70:de:fa:e0:
-                    d1:a5:d6:0c:41:71:7b:f7:ea:8c:1c:88:c7:ec:8b:
-                    f5:d1:2f:55:96:46:7c:5a:3b:58:3b:fb:ba:d8:2d:
-                    b5:25:da:7a:4e:cf:44:ae:21:a6:9e:98:ca:20:6e:
-                    7c:bb:88:85:5b:fb:c0:10:62:bb:f2:f9:27:47:ef:
-                    d1:89:39:43:c4:df:de:e1:41:bf:54:73:20:97:2d:
-                    6c:da:f3:d4:07:a3:e6:b9:d8:6f:ae:fc:8c:19:2e:
-                    d3:67:67:2b:95:db:58:5c:b5:6a:02:f3:b8:83:5e:
-                    b4:6b:be:41:7e:57:09:75:44:50:55:cd:5a:11:61:
-                    21:0a:61:c2:a9:88:fd:13:bc:2d:89:2f:cd:61:e0:
-                    95:be:ca:b5:7b:e1:7b:34:67:0b:1f:b6:0c:c7:7c:
-                    1e:19:53:ca:a7:b1:4a:15:20:56:14:70:3d:2b:82:
-                    2c:0f:9d:15:1d:47:80:47:ff:78:99:0e:31:af:6f:
-                    3e:8f:ed:86:69:1e:7b:18:88:14:b2:c2:fc:82:33:
-                    2e:9c:4b:2d:fb:70:3b:71:aa:2b:7b:26:27:f3:1a:
-                    c2:dc:fb:17:b8:a1:ea:cb:a0:b4:ae:d3:94:7e:7a:
-                    d0:ab:c3:ec:38:2d:11:2e:88:bf:d4:3f:ad:12:3b:
-                    42:ac:8f:02:6e:7d:cc:d1:5f:61:be:a1:bc:3a:6a:
-                    48:ea:26:55:22:16:5d:5f:0d:ff:27:33:9f:18:03:
-                    74:8a:5b:52:20:47:6b:45:4d:22:77:8c:55:27:f0:
-                    af:1e:8c:c9:83:22:54:b7:9a:d0:4f:d9:ce:fc:d9:
-                    2e:1c:96:28:b1:02:d3:03:bd:25:52:1c:34:66:4f:
-                    23:ab:f4:77:82:96:1d:d1:57:30:08:11:05:fd:57:
-                    d1:d9:c7
-                Exponent: 65537 (0x10001)
-        X509v3 extensions:
-            X509v3 Subject Key Identifier: 
-                64:14:7C:FC:58:72:16:A6:0A:29:34:15:6F:2A:CB:BC:FC:AF:A8:AB
-            X509v3 Key Usage: critical
-                Certificate Sign, CRL Sign
-            X509v3 Basic Constraints: critical
-                CA:TRUE
-    Signature Algorithm: sha384WithRSAEncryption
-         dc:02:23:08:e2:ef:21:3a:c7:0d:b7:26:d2:62:93:a7:a5:23:
-         72:07:20:82:60:df:18:d7:54:ad:69:25:92:9e:d9:14:cf:99:
-         b9:52:81:cf:ae:6c:8a:3b:5a:39:c8:6c:01:43:c2:22:6d:02:
-         f0:62:cd:4e:63:43:c0:14:da:f4:63:f0:ea:f4:71:ee:4e:87:
-         e3:71:a9:f4:c9:57:e5:2e:5f:1c:79:bb:23:aa:87:44:57:e9:
-         bd:35:4d:41:bb:4b:28:a3:98:b2:1b:d9:0b:17:07:e5:f7:ea:
-         9d:f5:76:d7:bf:c4:b6:81:58:ff:c8:ff:64:69:62:79:ad:6e:
-         0e:1f:7f:ee:1d:69:e5:b7:72:71:b3:fe:a5:01:35:94:54:2b:
-         c0:52:6d:8f:55:c4:c9:d2:b8:cb:ca:34:08:51:85:a0:f5:bc:
-         b4:17:58:ea:0a:5c:7a:bd:63:c6:3a:2f:ff:96:49:19:84:ea:
-         67:d8:04:b1:61:f4:00:5b:4a:b7:9c:71:37:19:85:79:bf:81:
-         b0:c7:13:0e:76:71:3e:3a:80:06:ae:06:16:a7:8d:b5:c2:c4:
-         cb:ff:40:a5:5c:8d:a5:c9:3a:ed:72:81:ca:5c:98:3c:d2:34:
-         03:77:08:fd:f0:29:59:5d:21:08:c7:60:bf:a4:71:7b:b8:d9:
-         1e:82:be:09:af:65:6f:28:ab:bf:4b:b5:ee:3e:08:47:27:a0:
-         0f:6f:0f:8b:3f:ac:95:18:f3:b9:0e:dc:67:55:6e:62:9e:46:
-         0e:d1:04:78:ca:72:ae:76:d9:a5:f8:b2:df:88:09:61:8b:ef:
-         24:4e:d1:59:3f:5a:d4:3d:c9:93:3c:2b:64:f5:81:0d:16:96:
-         f7:92:c3:fe:31:6f:e8:2a:32:74:0e:f4:4c:98:4a:18:0e:30:
-         54:d5:c5:eb:bc:c5:15:9e:e8:99:21:eb:27:2b:09:0a:db:f1:
-         e6:70:18:56:bb:0c:e4:be:f9:e8:10:a4:13:92:b8:1c:e0:db:
-         67:1d:53:03:a4:22:a7:dc:5d:92:10:3c:ea:ff:fc:1b:10:1a:
-         c3:d8:d0:9c:9d:65:cb:d0:2b:27:31:03:1e:36:e1:3d:76:75:
-         0c:ff:45:26:b9:dd:51:bc:23:c7:5f:d8:d8:87:10:40:12:0d:
-         3d:38:37:e7:44:3c:18:c0:53:09:64:8f:ff:d5:9a:a6:7c:70:
-         2e:73:55:21:e8:df:ff:83:b9:1d:3e:32:1e:d6:a6:7d:2c:f1:
-         66:e9:5c:1d:a7:a3:ce:5e:25:32:2b:e3:95:ac:2a:07:ce:b4:
-         28:78:86:3c:2d:a6:9d:4d:d2:74:30:dd:64:51:15:db:83:83:
-         51:d7:af:fd:33:9d:4d:66
-SHA1 Fingerprint=C3:03:C8:22:74:92:E5:61:A2:9C:5F:79:91:2B:1E:44:13:91:30:3A
diff --git a/apex/ca-certificates/files/8761519c.0 b/apex/ca-certificates/files/8761519c.0
new file mode 100644
index 00000000..2a42141d
--- /dev/null
+++ b/apex/ca-certificates/files/8761519c.0
@@ -0,0 +1,121 @@
+-----BEGIN CERTIFICATE-----
+MIIFcjCCA1qgAwIBAgIUZNtaDCBO6Ncpd8hQJ6JaJ90t8sswDQYJKoZIhvcNAQEM
+BQAwUTELMAkGA1UEBhMCSlAxIzAhBgNVBAoTGkN5YmVydHJ1c3QgSmFwYW4gQ28u
+LCBMdGQuMR0wGwYDVQQDExRTZWN1cmVTaWduIFJvb3QgQ0ExNDAeFw0yMDA0MDgw
+NzA2MTlaFw00NTA0MDgwNzA2MTlaMFExCzAJBgNVBAYTAkpQMSMwIQYDVQQKExpD
+eWJlcnRydXN0IEphcGFuIENvLiwgTHRkLjEdMBsGA1UEAxMUU2VjdXJlU2lnbiBS
+b290IENBMTQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDF0nqh1oq/
+FjHQmNE6lPxauG4iwWL3pwon71D2LrGeaBLwbCRjOfHw3xDG3rdSINVSW0KZnvOg
+vlIfX8xnbacuUKLBl422+JX1sLrcneC+y9/3OPJH9aaakpUqYllQC6KxNedlsmGy
+6pJxaeQp8E+BgQQ8sqVb1MWoWWd7VRxJq3qdwudzTe/NCcLEVxLbAQ4jeQkHO6Lo
+/IrPj8BGJJw4J+CDnRugv3gVEOuGTgpa/d/aLIJ+7sr2KeH6caH3iGicnPCNvg9J
+kdjqOvn90Ghx2+m1K06Ckm9mH+Dw3EzsytHqunQG+bOEkJTRX45zGRBdAuVwpcAQ
+0BB8b8VYSbSwbprafZX1zNoCr7gsfXmPvkPx+SgojQlD+Ajda8iLLCSxjVIHvXib
+y8posqTdDEx5YMaZ0ZPxMBoH064iwurO8YQJzOAUbn8/ftKChazcqRZOhaBgy/ac
+18izju3Gm5h1DVXoX+WViwKkrkMpKBGk5hIwAUt1ax5mnXkvpXYvHUC0bcl9eQjs
+0Wq2XSqypWa9a4X0dFbD9ed1Uigspf9mR6XU/v6eVL9lfgHWMI+lNpyiUBzuOIAB
+SMbHdPTGrMNASRZhdCyvjG817XsYAFs2PJxQDcqSMxDxJklt33UkN4Ii1+iW/RVL
+ApY+B3KVfqs9TC7XyvDf4Fg/LS8EmjijAQIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
+AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUBpOjCl4oaTeqYR3r6/wtbyPk
+86AwDQYJKoZIhvcNAQEMBQADggIBAJaAcgkGfpzMkwQWu6A6jZJOtxEaCnFxEM0E
+rX+lRVAQZk5KQaID2RFPeje5S+LGjzJmdSX7684/AykmjbgWHfYfM25I5uj4V7Ib
+ed87hwriZLoAymzvftAj63iP/2SbNDefNWWipAA9EiOWWF3KY4fGoweITedpdopT
+zfFP7ELyk+OZpDc8h7hi2/DsHzc/N19DzFGdtfCXwreFamgLRB7lUe6TzktuhsHS
+DCRZNhqfLJGP4xjblJUK7ZGqDpncllPjYYPGFrojutzdfhrGe0K22VoF3Jpf1d+4
+2kd92jjbrDnVHmtsKheMYc2xbXIBw8MgAGJoFjHVdqqGuw6qnsb58Nn4DSEC5MUo
+FlkRudlpcyqSeLiSV5sI8jrlL5WwWLdrIBRtFO8KvH7YVdiI2i/6GaX7i+B/OfVy
+K4XELKzvGUWSTLNhB9xNH27SgRNcmvMSZ4PPmz+Ln52kuaiWA3rF7iDeM9ovnhp6
+dB7h7sxaOgTdsxoEqBRjrLdHEoOabPXm6RUVkRqEGQ6UROcSjiVbgGcZ3GOTEAtl
+Lor6CZpO2oYofaphNdgOpygau1LgePhsumywbrmHXumZNTfxPWQrqaA0k89jL9WB
+365jJ6UeTo3cKXhZ+PmhIIynJkBugnLNeLLIjzwec+fBH7/PzqUqm9tEZDKgu39c
+JRNItX+S
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            64:db:5a:0c:20:4e:e8:d7:29:77:c8:50:27:a2:5a:27:dd:2d:f2:cb
+    Signature Algorithm: sha384WithRSAEncryption
+        Issuer: C=JP, O=Cybertrust Japan Co., Ltd., CN=SecureSign Root CA14
+        Validity
+            Not Before: Apr  8 07:06:19 2020 GMT
+            Not After : Apr  8 07:06:19 2045 GMT
+        Subject: C=JP, O=Cybertrust Japan Co., Ltd., CN=SecureSign Root CA14
+        Subject Public Key Info:
+            Public Key Algorithm: rsaEncryption
+                Public-Key: (4096 bit)
+                Modulus:
+                    00:c5:d2:7a:a1:d6:8a:bf:16:31:d0:98:d1:3a:94:
+                    fc:5a:b8:6e:22:c1:62:f7:a7:0a:27:ef:50:f6:2e:
+                    b1:9e:68:12:f0:6c:24:63:39:f1:f0:df:10:c6:de:
+                    b7:52:20:d5:52:5b:42:99:9e:f3:a0:be:52:1f:5f:
+                    cc:67:6d:a7:2e:50:a2:c1:97:8d:b6:f8:95:f5:b0:
+                    ba:dc:9d:e0:be:cb:df:f7:38:f2:47:f5:a6:9a:92:
+                    95:2a:62:59:50:0b:a2:b1:35:e7:65:b2:61:b2:ea:
+                    92:71:69:e4:29:f0:4f:81:81:04:3c:b2:a5:5b:d4:
+                    c5:a8:59:67:7b:55:1c:49:ab:7a:9d:c2:e7:73:4d:
+                    ef:cd:09:c2:c4:57:12:db:01:0e:23:79:09:07:3b:
+                    a2:e8:fc:8a:cf:8f:c0:46:24:9c:38:27:e0:83:9d:
+                    1b:a0:bf:78:15:10:eb:86:4e:0a:5a:fd:df:da:2c:
+                    82:7e:ee:ca:f6:29:e1:fa:71:a1:f7:88:68:9c:9c:
+                    f0:8d:be:0f:49:91:d8:ea:3a:f9:fd:d0:68:71:db:
+                    e9:b5:2b:4e:82:92:6f:66:1f:e0:f0:dc:4c:ec:ca:
+                    d1:ea:ba:74:06:f9:b3:84:90:94:d1:5f:8e:73:19:
+                    10:5d:02:e5:70:a5:c0:10:d0:10:7c:6f:c5:58:49:
+                    b4:b0:6e:9a:da:7d:95:f5:cc:da:02:af:b8:2c:7d:
+                    79:8f:be:43:f1:f9:28:28:8d:09:43:f8:08:dd:6b:
+                    c8:8b:2c:24:b1:8d:52:07:bd:78:9b:cb:ca:68:b2:
+                    a4:dd:0c:4c:79:60:c6:99:d1:93:f1:30:1a:07:d3:
+                    ae:22:c2:ea:ce:f1:84:09:cc:e0:14:6e:7f:3f:7e:
+                    d2:82:85:ac:dc:a9:16:4e:85:a0:60:cb:f6:9c:d7:
+                    c8:b3:8e:ed:c6:9b:98:75:0d:55:e8:5f:e5:95:8b:
+                    02:a4:ae:43:29:28:11:a4:e6:12:30:01:4b:75:6b:
+                    1e:66:9d:79:2f:a5:76:2f:1d:40:b4:6d:c9:7d:79:
+                    08:ec:d1:6a:b6:5d:2a:b2:a5:66:bd:6b:85:f4:74:
+                    56:c3:f5:e7:75:52:28:2c:a5:ff:66:47:a5:d4:fe:
+                    fe:9e:54:bf:65:7e:01:d6:30:8f:a5:36:9c:a2:50:
+                    1c:ee:38:80:01:48:c6:c7:74:f4:c6:ac:c3:40:49:
+                    16:61:74:2c:af:8c:6f:35:ed:7b:18:00:5b:36:3c:
+                    9c:50:0d:ca:92:33:10:f1:26:49:6d:df:75:24:37:
+                    82:22:d7:e8:96:fd:15:4b:02:96:3e:07:72:95:7e:
+                    ab:3d:4c:2e:d7:ca:f0:df:e0:58:3f:2d:2f:04:9a:
+                    38:a3:01
+                Exponent: 65537 (0x10001)
+        X509v3 extensions:
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+            X509v3 Subject Key Identifier: 
+                06:93:A3:0A:5E:28:69:37:AA:61:1D:EB:EB:FC:2D:6F:23:E4:F3:A0
+    Signature Algorithm: sha384WithRSAEncryption
+         96:80:72:09:06:7e:9c:cc:93:04:16:bb:a0:3a:8d:92:4e:b7:
+         11:1a:0a:71:71:10:cd:04:ad:7f:a5:45:50:10:66:4e:4a:41:
+         a2:03:d9:11:4f:7a:37:b9:4b:e2:c6:8f:32:66:75:25:fb:eb:
+         ce:3f:03:29:26:8d:b8:16:1d:f6:1f:33:6e:48:e6:e8:f8:57:
+         b2:1b:79:df:3b:87:0a:e2:64:ba:00:ca:6c:ef:7e:d0:23:eb:
+         78:8f:ff:64:9b:34:37:9f:35:65:a2:a4:00:3d:12:23:96:58:
+         5d:ca:63:87:c6:a3:07:88:4d:e7:69:76:8a:53:cd:f1:4f:ec:
+         42:f2:93:e3:99:a4:37:3c:87:b8:62:db:f0:ec:1f:37:3f:37:
+         5f:43:cc:51:9d:b5:f0:97:c2:b7:85:6a:68:0b:44:1e:e5:51:
+         ee:93:ce:4b:6e:86:c1:d2:0c:24:59:36:1a:9f:2c:91:8f:e3:
+         18:db:94:95:0a:ed:91:aa:0e:99:dc:96:53:e3:61:83:c6:16:
+         ba:23:ba:dc:dd:7e:1a:c6:7b:42:b6:d9:5a:05:dc:9a:5f:d5:
+         df:b8:da:47:7d:da:38:db:ac:39:d5:1e:6b:6c:2a:17:8c:61:
+         cd:b1:6d:72:01:c3:c3:20:00:62:68:16:31:d5:76:aa:86:bb:
+         0e:aa:9e:c6:f9:f0:d9:f8:0d:21:02:e4:c5:28:16:59:11:b9:
+         d9:69:73:2a:92:78:b8:92:57:9b:08:f2:3a:e5:2f:95:b0:58:
+         b7:6b:20:14:6d:14:ef:0a:bc:7e:d8:55:d8:88:da:2f:fa:19:
+         a5:fb:8b:e0:7f:39:f5:72:2b:85:c4:2c:ac:ef:19:45:92:4c:
+         b3:61:07:dc:4d:1f:6e:d2:81:13:5c:9a:f3:12:67:83:cf:9b:
+         3f:8b:9f:9d:a4:b9:a8:96:03:7a:c5:ee:20:de:33:da:2f:9e:
+         1a:7a:74:1e:e1:ee:cc:5a:3a:04:dd:b3:1a:04:a8:14:63:ac:
+         b7:47:12:83:9a:6c:f5:e6:e9:15:15:91:1a:84:19:0e:94:44:
+         e7:12:8e:25:5b:80:67:19:dc:63:93:10:0b:65:2e:8a:fa:09:
+         9a:4e:da:86:28:7d:aa:61:35:d8:0e:a7:28:1a:bb:52:e0:78:
+         f8:6c:ba:6c:b0:6e:b9:87:5e:e9:99:35:37:f1:3d:64:2b:a9:
+         a0:34:93:cf:63:2f:d5:81:df:ae:63:27:a5:1e:4e:8d:dc:29:
+         78:59:f8:f9:a1:20:8c:a7:26:40:6e:82:72:cd:78:b2:c8:8f:
+         3c:1e:73:e7:c1:1f:bf:cf:ce:a5:2a:9b:db:44:64:32:a0:bb:
+         7f:5c:25:13:48:b5:7f:92
+SHA1 Fingerprint=DD:50:C0:F7:79:B3:64:2E:74:A2:B8:9D:9F:D3:40:DD:BB:F0:F2:4F
diff --git a/apex/ca-certificates/files/8f6cd7bb.0 b/apex/ca-certificates/files/8f6cd7bb.0
new file mode 100644
index 00000000..d5210dfb
--- /dev/null
+++ b/apex/ca-certificates/files/8f6cd7bb.0
@@ -0,0 +1,51 @@
+-----BEGIN CERTIFICATE-----
+MIICIzCCAamgAwIBAgIUFhXHw9hJp75pDIqI7fBw+d23PocwCgYIKoZIzj0EAwMw
+UTELMAkGA1UEBhMCSlAxIzAhBgNVBAoTGkN5YmVydHJ1c3QgSmFwYW4gQ28uLCBM
+dGQuMR0wGwYDVQQDExRTZWN1cmVTaWduIFJvb3QgQ0ExNTAeFw0yMDA0MDgwODMy
+NTZaFw00NTA0MDgwODMyNTZaMFExCzAJBgNVBAYTAkpQMSMwIQYDVQQKExpDeWJl
+cnRydXN0IEphcGFuIENvLiwgTHRkLjEdMBsGA1UEAxMUU2VjdXJlU2lnbiBSb290
+IENBMTUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQLUHSNZDKZmbPSYAi4Io5GdCx4
+wCtELW1fHcmuS1Iggz24FG1Th2CeX2yF2wYUleDHKP+dX+Sq8bOLbe1PL0vJSpSR
+ZHX+AezB2Ot6lHhWGENfa4HL9rzatAy2KZMIaY+jQjBAMA8GA1UdEwEB/wQFMAMB
+Af8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTrQciu/NWeUUj1vYv0hyCTQSvT
+9DAKBggqhkjOPQQDAwNoADBlAjEA2S6Jfl5OpBEHvVnCB96rMjhTKkZEBhd6zlHp
+4P9mLQlO4E/0BdGF9jVg3PVys0Z9AjBEmEYagoUeYWmJSwdLZrWeqrqgHkHZAXQ6
+bkU6iYAZezKYVWOr62Nuk22rGwlgMU4=
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            16:15:c7:c3:d8:49:a7:be:69:0c:8a:88:ed:f0:70:f9:dd:b7:3e:87
+    Signature Algorithm: ecdsa-with-SHA384
+        Issuer: C=JP, O=Cybertrust Japan Co., Ltd., CN=SecureSign Root CA15
+        Validity
+            Not Before: Apr  8 08:32:56 2020 GMT
+            Not After : Apr  8 08:32:56 2045 GMT
+        Subject: C=JP, O=Cybertrust Japan Co., Ltd., CN=SecureSign Root CA15
+        Subject Public Key Info:
+            Public Key Algorithm: id-ecPublicKey
+                Public-Key: (P-384)
+                pub:
+                    04:0b:50:74:8d:64:32:99:99:b3:d2:60:08:b8:22:
+                    8e:46:74:2c:78:c0:2b:44:2d:6d:5f:1d:c9:ae:4b:
+                    52:20:83:3d:b8:14:6d:53:87:60:9e:5f:6c:85:db:
+                    06:14:95:e0:c7:28:ff:9d:5f:e4:aa:f1:b3:8b:6d:
+                    ed:4f:2f:4b:c9:4a:94:91:64:75:fe:01:ec:c1:d8:
+                    eb:7a:94:78:56:18:43:5f:6b:81:cb:f6:bc:da:b4:
+                    0c:b6:29:93:08:69:8f
+        X509v3 extensions:
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+            X509v3 Subject Key Identifier: 
+                EB:41:C8:AE:FC:D5:9E:51:48:F5:BD:8B:F4:87:20:93:41:2B:D3:F4
+    Signature Algorithm: ecdsa-with-SHA384
+         30:65:02:31:00:d9:2e:89:7e:5e:4e:a4:11:07:bd:59:c2:07:
+         de:ab:32:38:53:2a:46:44:06:17:7a:ce:51:e9:e0:ff:66:2d:
+         09:4e:e0:4f:f4:05:d1:85:f6:35:60:dc:f5:72:b3:46:7d:02:
+         30:44:98:46:1a:82:85:1e:61:69:89:4b:07:4b:66:b5:9e:aa:
+         ba:a0:1e:41:d9:01:74:3a:6e:45:3a:89:80:19:7b:32:98:55:
+         63:ab:eb:63:6e:93:6d:ab:1b:09:60:31:4e
+SHA1 Fingerprint=CB:BA:83:C8:C1:5A:5D:F1:F9:73:6F:CA:D7:EF:28:13:06:4A:07:7D
diff --git a/apex/ca-certificates/files/ab5346f4.0 b/apex/ca-certificates/files/ab5346f4.0
deleted file mode 100644
index cd7e3787..00000000
--- a/apex/ca-certificates/files/ab5346f4.0
+++ /dev/null
@@ -1,78 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIDbTCCAlWgAwIBAgIBATANBgkqhkiG9w0BAQUFADBYMQswCQYDVQQGEwJKUDEr
-MCkGA1UEChMiSmFwYW4gQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcywgSW5jLjEcMBoG
-A1UEAxMTU2VjdXJlU2lnbiBSb290Q0ExMTAeFw0wOTA0MDgwNDU2NDdaFw0yOTA0
-MDgwNDU2NDdaMFgxCzAJBgNVBAYTAkpQMSswKQYDVQQKEyJKYXBhbiBDZXJ0aWZp
-Y2F0aW9uIFNlcnZpY2VzLCBJbmMuMRwwGgYDVQQDExNTZWN1cmVTaWduIFJvb3RD
-QTExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/XeqpRyQBTvLTJsz
-i1oURaTnkBbR31fSIRCkF/3frNYfp+TbfPfs37gD2pRY/V1yfIw/XwFndBWW4wI8
-h9uuywGOwvNmxoVF9ALGOrVisq/6nL+k5tSAMJjzDbaTj6nU2DbysPyKyiyhFTOV
-MdrAG/LuYpmGYz+/3ZMqg6h2uRMft85OQoWPIucuGvKVCbIFtUROd6EgvanyTgp9
-UK31BQ1FT0Zx/Sg+U/sE2C3XZR1KG/rPO7AxmjVuyIsG0wCR8pQIZUyxNAYAeoni
-8McDWc/V1uinMrPmmECGxc0nEovMe863ETxiYAcjPitAbpSACW22s293bzUIUPsC
-h8U+iQIDAQABo0IwQDAdBgNVHQ4EFgQUW/hNT7KlhtQ60vFjmqC+CfZXt94wDgYD
-VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEB
-AKChOBZmLqdWHyGcBvod7bkixTgm2E5P7KN/ed5GIaGHd48HCJqypMWvDzKYC3xm
-KbabfSVSSUOrTC4rbnpwrxYO4wJs+0LmGJ1F2FXI6Dvd5+H0LgscNFxsWEr7jIhQ
-X5Ucv+2rIrVls4W6ng+4reV6G4pQOh29Dbx7VFALuUKvVaAYga1lme++5Jy/xIWr
-QbJUb9wlze144o4MjQlJ3WN7WmmWAiGovVJZ6X01y8hSyn+B/tlr0/cR7SXf+Of5
-pPpyl4RTDaXQMhhRdlkUbA/r7F+AjHVDg8OFmP9Mni0N5HeDk061lgeLKBObjBmN
-QSdJQO7e5iNEOdyhIta6A/I=
------END CERTIFICATE-----
-Certificate:
-    Data:
-        Version: 3 (0x2)
-        Serial Number: 1 (0x1)
-    Signature Algorithm: sha1WithRSAEncryption
-        Issuer: C=JP, O=Japan Certification Services, Inc., CN=SecureSign RootCA11
-        Validity
-            Not Before: Apr  8 04:56:47 2009 GMT
-            Not After : Apr  8 04:56:47 2029 GMT
-        Subject: C=JP, O=Japan Certification Services, Inc., CN=SecureSign RootCA11
-        Subject Public Key Info:
-            Public Key Algorithm: rsaEncryption
-                Public-Key: (2048 bit)
-                Modulus:
-                    00:fd:77:aa:a5:1c:90:05:3b:cb:4c:9b:33:8b:5a:
-                    14:45:a4:e7:90:16:d1:df:57:d2:21:10:a4:17:fd:
-                    df:ac:d6:1f:a7:e4:db:7c:f7:ec:df:b8:03:da:94:
-                    58:fd:5d:72:7c:8c:3f:5f:01:67:74:15:96:e3:02:
-                    3c:87:db:ae:cb:01:8e:c2:f3:66:c6:85:45:f4:02:
-                    c6:3a:b5:62:b2:af:fa:9c:bf:a4:e6:d4:80:30:98:
-                    f3:0d:b6:93:8f:a9:d4:d8:36:f2:b0:fc:8a:ca:2c:
-                    a1:15:33:95:31:da:c0:1b:f2:ee:62:99:86:63:3f:
-                    bf:dd:93:2a:83:a8:76:b9:13:1f:b7:ce:4e:42:85:
-                    8f:22:e7:2e:1a:f2:95:09:b2:05:b5:44:4e:77:a1:
-                    20:bd:a9:f2:4e:0a:7d:50:ad:f5:05:0d:45:4f:46:
-                    71:fd:28:3e:53:fb:04:d8:2d:d7:65:1d:4a:1b:fa:
-                    cf:3b:b0:31:9a:35:6e:c8:8b:06:d3:00:91:f2:94:
-                    08:65:4c:b1:34:06:00:7a:89:e2:f0:c7:03:59:cf:
-                    d5:d6:e8:a7:32:b3:e6:98:40:86:c5:cd:27:12:8b:
-                    cc:7b:ce:b7:11:3c:62:60:07:23:3e:2b:40:6e:94:
-                    80:09:6d:b6:b3:6f:77:6f:35:08:50:fb:02:87:c5:
-                    3e:89
-                Exponent: 65537 (0x10001)
-        X509v3 extensions:
-            X509v3 Subject Key Identifier: 
-                5B:F8:4D:4F:B2:A5:86:D4:3A:D2:F1:63:9A:A0:BE:09:F6:57:B7:DE
-            X509v3 Key Usage: critical
-                Certificate Sign, CRL Sign
-            X509v3 Basic Constraints: critical
-                CA:TRUE
-    Signature Algorithm: sha1WithRSAEncryption
-         a0:a1:38:16:66:2e:a7:56:1f:21:9c:06:fa:1d:ed:b9:22:c5:
-         38:26:d8:4e:4f:ec:a3:7f:79:de:46:21:a1:87:77:8f:07:08:
-         9a:b2:a4:c5:af:0f:32:98:0b:7c:66:29:b6:9b:7d:25:52:49:
-         43:ab:4c:2e:2b:6e:7a:70:af:16:0e:e3:02:6c:fb:42:e6:18:
-         9d:45:d8:55:c8:e8:3b:dd:e7:e1:f4:2e:0b:1c:34:5c:6c:58:
-         4a:fb:8c:88:50:5f:95:1c:bf:ed:ab:22:b5:65:b3:85:ba:9e:
-         0f:b8:ad:e5:7a:1b:8a:50:3a:1d:bd:0d:bc:7b:54:50:0b:b9:
-         42:af:55:a0:18:81:ad:65:99:ef:be:e4:9c:bf:c4:85:ab:41:
-         b2:54:6f:dc:25:cd:ed:78:e2:8e:0c:8d:09:49:dd:63:7b:5a:
-         69:96:02:21:a8:bd:52:59:e9:7d:35:cb:c8:52:ca:7f:81:fe:
-         d9:6b:d3:f7:11:ed:25:df:f8:e7:f9:a4:fa:72:97:84:53:0d:
-         a5:d0:32:18:51:76:59:14:6c:0f:eb:ec:5f:80:8c:75:43:83:
-         c3:85:98:ff:4c:9e:2d:0d:e4:77:83:93:4e:b5:96:07:8b:28:
-         13:9b:8c:19:8d:41:27:49:40:ee:de:e6:23:44:39:dc:a1:22:
-         d6:ba:03:f2
-SHA1 Fingerprint=3B:C4:9F:48:F8:F3:73:A0:9C:1E:BD:F8:5B:B1:C3:65:C7:D8:11:B3
diff --git a/apex/ca-certificates/files/ee37c333.0 b/apex/ca-certificates/files/ee37c333.0
new file mode 100644
index 00000000..7b5498c9
--- /dev/null
+++ b/apex/ca-certificates/files/ee37c333.0
@@ -0,0 +1,125 @@
+-----BEGIN CERTIFICATE-----
+MIIFszCCA5ugAwIBAgIQIZxULej27HF3+k7ow3BXlzANBgkqhkiG9w0BAQwFADBj
+MQswCQYDVQQGEwJERTEnMCUGA1UECgweRGV1dHNjaGUgVGVsZWtvbSBTZWN1cml0
+eSBHbWJIMSswKQYDVQQDDCJUZWxla29tIFNlY3VyaXR5IFRMUyBSU0EgUm9vdCAy
+MDIzMB4XDTIzMDMyODEyMTY0NVoXDTQ4MDMyNzIzNTk1OVowYzELMAkGA1UEBhMC
+REUxJzAlBgNVBAoMHkRldXRzY2hlIFRlbGVrb20gU2VjdXJpdHkgR21iSDErMCkG
+A1UEAwwiVGVsZWtvbSBTZWN1cml0eSBUTFMgUlNBIFJvb3QgMjAyMzCCAiIwDQYJ
+KoZIhvcNAQEBBQADggIPADCCAgoCggIBAO01oYGA88tKaVvC+1GDrib94W7zgRJ9
+cUD/h3VCKSHtgVIs3xLBGYSJwb3FKNXVS2xE1kzbB5ZKVXrKNoIENqil/Cf2SfHV
+cp6R+SPWcHu79ZvB7JPPGeplfohwoHP89v+1VmLhc2o0mD6CuKyVU/QBoCcHcqMA
+U6DksquDOFczJZSfvkgdmOGjup5czQRxUX11eKvzWarE4GC+j4NSuHUaQTXtvPM6
+Y+mpFEXX5lLRbtLevOP1Czvm4MS9Q2QTps70mDdsipWol8hHD/BeEIvnHRz+sTug
+BTNoBUGCwQMrAcjnj02r6LX2zWtEtefdi+zqJbQAIldNsLGyMcEWzv/9FIS3R/qy
+8XDe24tsNlikfLMR0cN3f1+2JeANxdKz+bi4d9s3cXFH42AYTyS2dTd4uaNir73J
+co4vzLuu2+QVUhkHM/tqty1LkCiCc/4YizWN26cEar7qwU02OxY2kTLvtkCJkUPg
+8qKrBC7m8kwOFjQgrIfBLX7JZkcXFBGk8/ehJImr2BrIoVyxo/eMbcgByU/J7MT8
+rFEz0ciD0cmfHdRHNCk+y7AO+oMLKFjlKdw/fKifybYKu6boRhYPluV75Gp6SG12
+mAWl3G0eQh5C2hrgUve1g8Aae3g1LDj1H/1Joy7SWWO/gLCMk3PLNaaZlSJhZQNg
++y+TS/qanIA7AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUtqeX
+gj10hZv3PJ+TmpV5dVKMbUcwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS2
+p5eCPXSFm/c8n5OalXl1UoxtRzANBgkqhkiG9w0BAQwFAAOCAgEAqMxhpr51nhVQ
+pGv7qHBFfLp+sVr8WyP6Cnf4mHGCDG3gXkaqk/QeoMPhk9tLrbKmXauw1GLLXrtm
+9S3ul0A8Yute1hTWjOKWi0FpkzXmuZlrYrShF2Y0pmtjxrlO8iLpWA1WQdH6DErw
+M807u20hOq6OcrXDSvvpfeWxm4bu4uB9tPcy/SKE8YXJN3nptT+/XOR0so8RYgDd
+GGah2XsjX/GO1WfoVNpbOms2b/mBsTNHM3dA+VKq3dSDz4V4mZqTuXNnQkYRIer+
+CqkbGmVps4+uFrb2S1ayLfmlyOw7YqPta9BO1UAJpB+Y1zqlklkg5LB9zVtzaL1t
+xKITDmcZuI1CfmwMmm6gJC3VRRvcxAIU/oVbZZfKTpBQCHpCNfnqwmbU+AGuHrS+
+w6jv/naaoqYfRvaE7fzbzsQCzndILIyy7MMAo+wsVRjBfhnu4S/yrYObnqsZ38aK
+L4x35bcF7DvB7L6Gs4a8wPfc5+pbrrLMtTWGS9DiP7bY+A4A7l3j941Y/8+LN+lj
+X273CXE2whJdV/LItM3z7gLfEdxquVeEHVlNjM7IDiPCtyaaEBRx/pOyiriA8A4Q
+ntOoUAw3gi/q4Iqd4Sw5/7W0cwDk90imc6y/st53BIe0o82bNSQ3+pCTE4FCxpgm
+dTdmQRCsu/WU48IxK63nI1bMNSWSs1A=
+-----END CERTIFICATE-----
+Certificate:
+    Data:
+        Version: 3 (0x2)
+        Serial Number:
+            21:9c:54:2d:e8:f6:ec:71:77:fa:4e:e8:c3:70:57:97
+    Signature Algorithm: sha384WithRSAEncryption
+        Issuer: C=DE, O=Deutsche Telekom Security GmbH, CN=Telekom Security TLS RSA Root 2023
+        Validity
+            Not Before: Mar 28 12:16:45 2023 GMT
+            Not After : Mar 27 23:59:59 2048 GMT
+        Subject: C=DE, O=Deutsche Telekom Security GmbH, CN=Telekom Security TLS RSA Root 2023
+        Subject Public Key Info:
+            Public Key Algorithm: rsaEncryption
+                Public-Key: (4096 bit)
+                Modulus:
+                    00:ed:35:a1:81:80:f3:cb:4a:69:5b:c2:fb:51:83:
+                    ae:26:fd:e1:6e:f3:81:12:7d:71:40:ff:87:75:42:
+                    29:21:ed:81:52:2c:df:12:c1:19:84:89:c1:bd:c5:
+                    28:d5:d5:4b:6c:44:d6:4c:db:07:96:4a:55:7a:ca:
+                    36:82:04:36:a8:a5:fc:27:f6:49:f1:d5:72:9e:91:
+                    f9:23:d6:70:7b:bb:f5:9b:c1:ec:93:cf:19:ea:65:
+                    7e:88:70:a0:73:fc:f6:ff:b5:56:62:e1:73:6a:34:
+                    98:3e:82:b8:ac:95:53:f4:01:a0:27:07:72:a3:00:
+                    53:a0:e4:b2:ab:83:38:57:33:25:94:9f:be:48:1d:
+                    98:e1:a3:ba:9e:5c:cd:04:71:51:7d:75:78:ab:f3:
+                    59:aa:c4:e0:60:be:8f:83:52:b8:75:1a:41:35:ed:
+                    bc:f3:3a:63:e9:a9:14:45:d7:e6:52:d1:6e:d2:de:
+                    bc:e3:f5:0b:3b:e6:e0:c4:bd:43:64:13:a6:ce:f4:
+                    98:37:6c:8a:95:a8:97:c8:47:0f:f0:5e:10:8b:e7:
+                    1d:1c:fe:b1:3b:a0:05:33:68:05:41:82:c1:03:2b:
+                    01:c8:e7:8f:4d:ab:e8:b5:f6:cd:6b:44:b5:e7:dd:
+                    8b:ec:ea:25:b4:00:22:57:4d:b0:b1:b2:31:c1:16:
+                    ce:ff:fd:14:84:b7:47:fa:b2:f1:70:de:db:8b:6c:
+                    36:58:a4:7c:b3:11:d1:c3:77:7f:5f:b6:25:e0:0d:
+                    c5:d2:b3:f9:b8:b8:77:db:37:71:71:47:e3:60:18:
+                    4f:24:b6:75:37:78:b9:a3:62:af:bd:c9:72:8e:2f:
+                    cc:bb:ae:db:e4:15:52:19:07:33:fb:6a:b7:2d:4b:
+                    90:28:82:73:fe:18:8b:35:8d:db:a7:04:6a:be:ea:
+                    c1:4d:36:3b:16:36:91:32:ef:b6:40:89:91:43:e0:
+                    f2:a2:ab:04:2e:e6:f2:4c:0e:16:34:20:ac:87:c1:
+                    2d:7e:c9:66:47:17:14:11:a4:f3:f7:a1:24:89:ab:
+                    d8:1a:c8:a1:5c:b1:a3:f7:8c:6d:c8:01:c9:4f:c9:
+                    ec:c4:fc:ac:51:33:d1:c8:83:d1:c9:9f:1d:d4:47:
+                    34:29:3e:cb:b0:0e:fa:83:0b:28:58:e5:29:dc:3f:
+                    7c:a8:9f:c9:b6:0a:bb:a6:e8:46:16:0f:96:e5:7b:
+                    e4:6a:7a:48:6d:76:98:05:a5:dc:6d:1e:42:1e:42:
+                    da:1a:e0:52:f7:b5:83:c0:1a:7b:78:35:2c:38:f5:
+                    1f:fd:49:a3:2e:d2:59:63:bf:80:b0:8c:93:73:cb:
+                    35:a6:99:95:22:61:65:03:60:fb:2f:93:4b:fa:9a:
+                    9c:80:3b
+                Exponent: 65537 (0x10001)
+        X509v3 extensions:
+            X509v3 Key Usage: critical
+                Certificate Sign, CRL Sign
+            X509v3 Subject Key Identifier: 
+                B6:A7:97:82:3D:74:85:9B:F7:3C:9F:93:9A:95:79:75:52:8C:6D:47
+            X509v3 Basic Constraints: critical
+                CA:TRUE
+            X509v3 Authority Key Identifier: 
+                keyid:B6:A7:97:82:3D:74:85:9B:F7:3C:9F:93:9A:95:79:75:52:8C:6D:47
+
+    Signature Algorithm: sha384WithRSAEncryption
+         a8:cc:61:a6:be:75:9e:15:50:a4:6b:fb:a8:70:45:7c:ba:7e:
+         b1:5a:fc:5b:23:fa:0a:77:f8:98:71:82:0c:6d:e0:5e:46:aa:
+         93:f4:1e:a0:c3:e1:93:db:4b:ad:b2:a6:5d:ab:b0:d4:62:cb:
+         5e:bb:66:f5:2d:ee:97:40:3c:62:eb:5e:d6:14:d6:8c:e2:96:
+         8b:41:69:93:35:e6:b9:99:6b:62:b4:a1:17:66:34:a6:6b:63:
+         c6:b9:4e:f2:22:e9:58:0d:56:41:d1:fa:0c:4a:f0:33:cd:3b:
+         bb:6d:21:3a:ae:8e:72:b5:c3:4a:fb:e9:7d:e5:b1:9b:86:ee:
+         e2:e0:7d:b4:f7:32:fd:22:84:f1:85:c9:37:79:e9:b5:3f:bf:
+         5c:e4:74:b2:8f:11:62:00:dd:18:66:a1:d9:7b:23:5f:f1:8e:
+         d5:67:e8:54:da:5b:3a:6b:36:6f:f9:81:b1:33:47:33:77:40:
+         f9:52:aa:dd:d4:83:cf:85:78:99:9a:93:b9:73:67:42:46:11:
+         21:ea:fe:0a:a9:1b:1a:65:69:b3:8f:ae:16:b6:f6:4b:56:b2:
+         2d:f9:a5:c8:ec:3b:62:a3:ed:6b:d0:4e:d5:40:09:a4:1f:98:
+         d7:3a:a5:92:59:20:e4:b0:7d:cd:5b:73:68:bd:6d:c4:a2:13:
+         0e:67:19:b8:8d:42:7e:6c:0c:9a:6e:a0:24:2d:d5:45:1b:dc:
+         c4:02:14:fe:85:5b:65:97:ca:4e:90:50:08:7a:42:35:f9:ea:
+         c2:66:d4:f8:01:ae:1e:b4:be:c3:a8:ef:fe:76:9a:a2:a6:1f:
+         46:f6:84:ed:fc:db:ce:c4:02:ce:77:48:2c:8c:b2:ec:c3:00:
+         a3:ec:2c:55:18:c1:7e:19:ee:e1:2f:f2:ad:83:9b:9e:ab:19:
+         df:c6:8a:2f:8c:77:e5:b7:05:ec:3b:c1:ec:be:86:b3:86:bc:
+         c0:f7:dc:e7:ea:5b:ae:b2:cc:b5:35:86:4b:d0:e2:3f:b6:d8:
+         f8:0e:00:ee:5d:e3:f7:8d:58:ff:cf:8b:37:e9:63:5f:6e:f7:
+         09:71:36:c2:12:5d:57:f2:c8:b4:cd:f3:ee:02:df:11:dc:6a:
+         b9:57:84:1d:59:4d:8c:ce:c8:0e:23:c2:b7:26:9a:10:14:71:
+         fe:93:b2:8a:b8:80:f0:0e:10:9e:d3:a8:50:0c:37:82:2f:ea:
+         e0:8a:9d:e1:2c:39:ff:b5:b4:73:00:e4:f7:48:a6:73:ac:bf:
+         b2:de:77:04:87:b4:a3:cd:9b:35:24:37:fa:90:93:13:81:42:
+         c6:98:26:75:37:66:41:10:ac:bb:f5:94:e3:c2:31:2b:ad:e7:
+         23:56:cc:35:25:92:b3:50
+SHA1 Fingerprint=54:D3:AC:B3:BD:57:56:F6:85:9D:CE:E5:C3:21:E2:D4:AD:83:D0:93
diff --git a/apex/ca-certificates/files/f0cd152c.0 b/apex/ca-certificates/files/f0cd152c.0
deleted file mode 100644
index b55103f7..00000000
--- a/apex/ca-certificates/files/f0cd152c.0
+++ /dev/null
@@ -1,125 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIGSzCCBDOgAwIBAgIRANm1Q3+vqTkPAAAAAFVlrVgwDQYJKoZIhvcNAQELBQAw
-gb4xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQL
-Ex9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykg
-MjAxNSBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxMjAw
-BgNVBAMTKUVudHJ1c3QgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEc0
-MB4XDTE1MDUyNzExMTExNloXDTM3MTIyNzExNDExNlowgb4xCzAJBgNVBAYTAlVT
-MRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9TZWUgd3d3LmVudHJ1
-c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykgMjAxNSBFbnRydXN0LCBJ
-bmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxMjAwBgNVBAMTKUVudHJ1c3Qg
-Um9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEc0MIICIjANBgkqhkiG9w0B
-AQEFAAOCAg8AMIICCgKCAgEAsewsQu7i0TD/pZJH4i3DumSXbcr3DbVZwbPLqGgZ
-2K+EbTBwXX7zLtJTmeH+H17ZSK9dE43b/2MzTdMAArzE+NEGCJR5WIoV3imz/f3E
-T+iq4qA7ec2/a0My3dl0ELn39GjUu9CH1apLiipvKgS1sqbHoHrmSKvS0VnM1n4j
-5pds8ELl3FFLFUHtSUrJ3hCX1nbB76W1NhSXNdh4IjVS70O92yfbYVaCNNzLiGAM
-C1rlLAHGVK/XqsEQe9IFWrhAnoanw5CGAlZSCXqc0ieCU0plUmr1POeo8pyvi73T
-DtTUXm6Hnmo9RR3RXRv06QqsYJn7ibT/mCzPfB3pAqoEmh643IhuJbNsZvc8kPNX
-wbMv9W3y+8qh+CmdRouzavbmZwe+LGcKKh9asj5XxNMhIWNlUpEbsZmOeX7m640A
-2Vqq6nPopIICR5b+W45UYaPrL0swsIsjdXJ8ITzI9vF01Bx7owVV7rtNOzK+mndm
-nqxpkCIHH2E6lr7lmk/MBTwoWdPBDFSoWWG9yHJM6Nyfh3+9nEg2XpWjDrk4JFX8
-dWbrAuMINClKxuMrLzOg2qOGpRKX/YAr2hRC45K9PvJdXmd0LhyIRyk0X+IyqJwl
-N4y6mACXi0mWHv0liqzc2thddG5msP9E36EYxr5ILzeUePiVSj9/E15dWf10hkNj
-c0kCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD
-VR0OBBYEFJ84xFYjwznooHFs6FRM5Og6sb9nMA0GCSqGSIb3DQEBCwUAA4ICAQAS
-5UKme4sPDORGpbZgQIeMJX6tuGguW8ZAdjwD+MlZ9POrYs4QjbRaZIxowLByQzTS
-Gwv2LFPSypBLhmb8qoMi9IsabyZIrHZ3CL/FmFz0Jomee8O5ZDIBf9PD3Vht7LGr
-hFV0d4QEJ1JrhkzO3bll/9bGXp+aEJlLdWr+aumXIOTkdnrG0CSqkM0gkLpHZPt/
-B7NTeLUKYvJzQ85BK4FqLoUWlFPUa19yIqtRLULVAJyZv967lDtX/Zr1hstWO1uI
-AeV8KEsD+UmDfLJ/fOPtjqF/YFOOVZ1QNBIPt5d7bIdKROf1beyAN/BYGW5KaHbw
-H5Lk6rWS02FREAutp9lfx1/cH6NcjKF+m7ee01ZvZl4HliDtC3T7Zk6LERXpgUl+
-b7DUUH8i119lAg2m9IUe2K4GS0qn0jFmwvjO5QimpAKWRGhXxNUzzxkvFMSUHHuk
-2fCfDrGA4tGeEWSpiBE6doLlYsKA2KSD7ZPvfC+QsDJMlhVoSFLUmQjAJOgc47Ol
-IQ6SwJAfzyBfyjs4x7dtOvPmRLgOMWuIjnDrnBdSqEGULoe256YSxXXfW8AKbnuk
-5F6G+TaU33fD6Q3AOfF5u0aOq0NZJ7cguyPpVkAh7DE9ZapD8j3fcEThuk0mEDuY
-n/PIjhs4ViFqUZPTkcpG2om3PVODLAgfi49T3f+sHw==
------END CERTIFICATE-----
-Certificate:
-    Data:
-        Version: 3 (0x2)
-        Serial Number:
-            d9:b5:43:7f:af:a9:39:0f:00:00:00:00:55:65:ad:58
-    Signature Algorithm: sha256WithRSAEncryption
-        Issuer: C=US, O=Entrust, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2015 Entrust, Inc. - for authorized use only, CN=Entrust Root Certification Authority - G4
-        Validity
-            Not Before: May 27 11:11:16 2015 GMT
-            Not After : Dec 27 11:41:16 2037 GMT
-        Subject: C=US, O=Entrust, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2015 Entrust, Inc. - for authorized use only, CN=Entrust Root Certification Authority - G4
-        Subject Public Key Info:
-            Public Key Algorithm: rsaEncryption
-                Public-Key: (4096 bit)
-                Modulus:
-                    00:b1:ec:2c:42:ee:e2:d1:30:ff:a5:92:47:e2:2d:
-                    c3:ba:64:97:6d:ca:f7:0d:b5:59:c1:b3:cb:a8:68:
-                    19:d8:af:84:6d:30:70:5d:7e:f3:2e:d2:53:99:e1:
-                    fe:1f:5e:d9:48:af:5d:13:8d:db:ff:63:33:4d:d3:
-                    00:02:bc:c4:f8:d1:06:08:94:79:58:8a:15:de:29:
-                    b3:fd:fd:c4:4f:e8:aa:e2:a0:3b:79:cd:bf:6b:43:
-                    32:dd:d9:74:10:b9:f7:f4:68:d4:bb:d0:87:d5:aa:
-                    4b:8a:2a:6f:2a:04:b5:b2:a6:c7:a0:7a:e6:48:ab:
-                    d2:d1:59:cc:d6:7e:23:e6:97:6c:f0:42:e5:dc:51:
-                    4b:15:41:ed:49:4a:c9:de:10:97:d6:76:c1:ef:a5:
-                    b5:36:14:97:35:d8:78:22:35:52:ef:43:bd:db:27:
-                    db:61:56:82:34:dc:cb:88:60:0c:0b:5a:e5:2c:01:
-                    c6:54:af:d7:aa:c1:10:7b:d2:05:5a:b8:40:9e:86:
-                    a7:c3:90:86:02:56:52:09:7a:9c:d2:27:82:53:4a:
-                    65:52:6a:f5:3c:e7:a8:f2:9c:af:8b:bd:d3:0e:d4:
-                    d4:5e:6e:87:9e:6a:3d:45:1d:d1:5d:1b:f4:e9:0a:
-                    ac:60:99:fb:89:b4:ff:98:2c:cf:7c:1d:e9:02:aa:
-                    04:9a:1e:b8:dc:88:6e:25:b3:6c:66:f7:3c:90:f3:
-                    57:c1:b3:2f:f5:6d:f2:fb:ca:a1:f8:29:9d:46:8b:
-                    b3:6a:f6:e6:67:07:be:2c:67:0a:2a:1f:5a:b2:3e:
-                    57:c4:d3:21:21:63:65:52:91:1b:b1:99:8e:79:7e:
-                    e6:eb:8d:00:d9:5a:aa:ea:73:e8:a4:82:02:47:96:
-                    fe:5b:8e:54:61:a3:eb:2f:4b:30:b0:8b:23:75:72:
-                    7c:21:3c:c8:f6:f1:74:d4:1c:7b:a3:05:55:ee:bb:
-                    4d:3b:32:be:9a:77:66:9e:ac:69:90:22:07:1f:61:
-                    3a:96:be:e5:9a:4f:cc:05:3c:28:59:d3:c1:0c:54:
-                    a8:59:61:bd:c8:72:4c:e8:dc:9f:87:7f:bd:9c:48:
-                    36:5e:95:a3:0e:b9:38:24:55:fc:75:66:eb:02:e3:
-                    08:34:29:4a:c6:e3:2b:2f:33:a0:da:a3:86:a5:12:
-                    97:fd:80:2b:da:14:42:e3:92:bd:3e:f2:5d:5e:67:
-                    74:2e:1c:88:47:29:34:5f:e2:32:a8:9c:25:37:8c:
-                    ba:98:00:97:8b:49:96:1e:fd:25:8a:ac:dc:da:d8:
-                    5d:74:6e:66:b0:ff:44:df:a1:18:c6:be:48:2f:37:
-                    94:78:f8:95:4a:3f:7f:13:5e:5d:59:fd:74:86:43:
-                    63:73:49
-                Exponent: 65537 (0x10001)
-        X509v3 extensions:
-            X509v3 Basic Constraints: critical
-                CA:TRUE
-            X509v3 Key Usage: critical
-                Certificate Sign, CRL Sign
-            X509v3 Subject Key Identifier: 
-                9F:38:C4:56:23:C3:39:E8:A0:71:6C:E8:54:4C:E4:E8:3A:B1:BF:67
-    Signature Algorithm: sha256WithRSAEncryption
-         12:e5:42:a6:7b:8b:0f:0c:e4:46:a5:b6:60:40:87:8c:25:7e:
-         ad:b8:68:2e:5b:c6:40:76:3c:03:f8:c9:59:f4:f3:ab:62:ce:
-         10:8d:b4:5a:64:8c:68:c0:b0:72:43:34:d2:1b:0b:f6:2c:53:
-         d2:ca:90:4b:86:66:fc:aa:83:22:f4:8b:1a:6f:26:48:ac:76:
-         77:08:bf:c5:98:5c:f4:26:89:9e:7b:c3:b9:64:32:01:7f:d3:
-         c3:dd:58:6d:ec:b1:ab:84:55:74:77:84:04:27:52:6b:86:4c:
-         ce:dd:b9:65:ff:d6:c6:5e:9f:9a:10:99:4b:75:6a:fe:6a:e9:
-         97:20:e4:e4:76:7a:c6:d0:24:aa:90:cd:20:90:ba:47:64:fb:
-         7f:07:b3:53:78:b5:0a:62:f2:73:43:ce:41:2b:81:6a:2e:85:
-         16:94:53:d4:6b:5f:72:22:ab:51:2d:42:d5:00:9c:99:bf:de:
-         bb:94:3b:57:fd:9a:f5:86:cb:56:3b:5b:88:01:e5:7c:28:4b:
-         03:f9:49:83:7c:b2:7f:7c:e3:ed:8e:a1:7f:60:53:8e:55:9d:
-         50:34:12:0f:b7:97:7b:6c:87:4a:44:e7:f5:6d:ec:80:37:f0:
-         58:19:6e:4a:68:76:f0:1f:92:e4:ea:b5:92:d3:61:51:10:0b:
-         ad:a7:d9:5f:c7:5f:dc:1f:a3:5c:8c:a1:7e:9b:b7:9e:d3:56:
-         6f:66:5e:07:96:20:ed:0b:74:fb:66:4e:8b:11:15:e9:81:49:
-         7e:6f:b0:d4:50:7f:22:d7:5f:65:02:0d:a6:f4:85:1e:d8:ae:
-         06:4b:4a:a7:d2:31:66:c2:f8:ce:e5:08:a6:a4:02:96:44:68:
-         57:c4:d5:33:cf:19:2f:14:c4:94:1c:7b:a4:d9:f0:9f:0e:b1:
-         80:e2:d1:9e:11:64:a9:88:11:3a:76:82:e5:62:c2:80:d8:a4:
-         83:ed:93:ef:7c:2f:90:b0:32:4c:96:15:68:48:52:d4:99:08:
-         c0:24:e8:1c:e3:b3:a5:21:0e:92:c0:90:1f:cf:20:5f:ca:3b:
-         38:c7:b7:6d:3a:f3:e6:44:b8:0e:31:6b:88:8e:70:eb:9c:17:
-         52:a8:41:94:2e:87:b6:e7:a6:12:c5:75:df:5b:c0:0a:6e:7b:
-         a4:e4:5e:86:f9:36:94:df:77:c3:e9:0d:c0:39:f1:79:bb:46:
-         8e:ab:43:59:27:b7:20:bb:23:e9:56:40:21:ec:31:3d:65:aa:
-         43:f2:3d:df:70:44:e1:ba:4d:26:10:3b:98:9f:f3:c8:8e:1b:
-         38:56:21:6a:51:93:d3:91:ca:46:da:89:b7:3d:53:83:2c:08:
-         1f:8b:8f:53:dd:ff:ac:1f
-SHA1 Fingerprint=14:88:4E:86:26:37:B0:26:AF:59:62:5C:40:77:EC:35:29:BA:96:01
diff --git a/api/public/system-current.txt b/api/public/system-current.txt
index d802177e..bb06bfe2 100644
--- a/api/public/system-current.txt
+++ b/api/public/system-current.txt
@@ -1 +1,47 @@
 // Signature format: 2.0
+package android.net.ssl {
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public final class PakeClientKeyManagerParameters implements javax.net.ssl.ManagerFactoryParameters {
+    method @Nullable public byte[] getClientId();
+    method @NonNull public java.util.List<android.net.ssl.PakeOption> getOptions();
+    method @Nullable public byte[] getServerId();
+  }
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public static final class PakeClientKeyManagerParameters.Builder {
+    ctor public PakeClientKeyManagerParameters.Builder();
+    method @NonNull public android.net.ssl.PakeClientKeyManagerParameters.Builder addOption(@NonNull android.net.ssl.PakeOption);
+    method @NonNull public android.net.ssl.PakeClientKeyManagerParameters build();
+    method @NonNull public android.net.ssl.PakeClientKeyManagerParameters.Builder setClientId(@Nullable byte[]);
+    method @NonNull public android.net.ssl.PakeClientKeyManagerParameters.Builder setServerId(@Nullable byte[]);
+  }
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public final class PakeOption {
+    method @NonNull public String getAlgorithm();
+    method @Nullable public byte[] getMessageComponent(@NonNull String);
+  }
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public static final class PakeOption.Builder {
+    ctor public PakeOption.Builder(@NonNull String);
+    method @NonNull public android.net.ssl.PakeOption.Builder addMessageComponent(@NonNull String, @Nullable byte[]);
+    method @NonNull public android.net.ssl.PakeOption build();
+  }
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public final class PakeServerKeyManagerParameters implements javax.net.ssl.ManagerFactoryParameters {
+    method @NonNull public java.util.Set<android.net.ssl.PakeServerKeyManagerParameters.Link> getLinks();
+    method @NonNull public java.util.List<android.net.ssl.PakeOption> getOptions(@NonNull android.net.ssl.PakeServerKeyManagerParameters.Link);
+    method @NonNull public java.util.List<android.net.ssl.PakeOption> getOptions(@Nullable byte[], @Nullable byte[]);
+  }
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public static final class PakeServerKeyManagerParameters.Builder {
+    ctor public PakeServerKeyManagerParameters.Builder();
+    method @NonNull public android.net.ssl.PakeServerKeyManagerParameters build();
+    method @NonNull public android.net.ssl.PakeServerKeyManagerParameters.Builder setOptions(@Nullable byte[], @Nullable byte[], @NonNull java.util.List<android.net.ssl.PakeOption>);
+  }
+
+  @FlaggedApi("com.android.org.conscrypt.flags.spake2plus_api") public static final class PakeServerKeyManagerParameters.Link {
+    method @Nullable public byte[] getClientId();
+    method @Nullable public byte[] getServerId();
+  }
+
+}
+
diff --git a/benchmark-android/build.gradle b/benchmark-android/build.gradle
index 7981a281..42d7913d 100644
--- a/benchmark-android/build.gradle
+++ b/benchmark-android/build.gradle
@@ -1,11 +1,5 @@
-buildscript {
-    repositories {
-        google()
-        mavenCentral()
-    }
-    dependencies {
-        classpath libs.android.tools
-    }
+plugins {
+    alias(libs.plugins.android.library)
 }
 
 description = 'Conscrypt: Android Benchmarks'
@@ -19,190 +13,179 @@ ext {
     androidTargetSdkVersion = 26
 }
 
-if (androidSdkInstalled) {
-    apply plugin: 'com.android.library'
-
-    android {
-        namespace "org.conscrypt"
-        compileSdkVersion androidTargetSdkVersion
+android {
+    namespace "org.conscrypt"
+    compileSdkVersion androidTargetSdkVersion
 
-        defaultConfig {
-            minSdkVersion androidMinSdkVersion
-            targetSdkVersion androidTargetSdkVersion
-            versionCode androidVersionCode
-            versionName androidVersionName
-        }
-        lintOptions {
-            // Some Caliper classes reference packages that don't exist on Android
-            disable 'InvalidPackage'
-        }
-        sourceSets.main {
-            java {
-                srcDirs = [
-                        "src/main/java"
-                ]
-            }
+    defaultConfig {
+        minSdkVersion androidMinSdkVersion
+        targetSdkVersion androidTargetSdkVersion
+        versionCode androidVersionCode
+        versionName androidVersionName
+    }
+    lintOptions {
+        // Some Caliper classes reference packages that don't exist on Android
+        disable 'InvalidPackage'
+    }
+    sourceSets.main {
+        java {
+            srcDirs = [
+                    "src/main/java"
+            ]
         }
     }
+}
 
-    configurations {
-        // For the depsJar task, we need to create a config we can pull libraries from to
-        // make the complete JAR. Some we do not want the transitive dependencies because
-        // they are already included on the Android system.
-        depsJarApi
-        depsJarApi.transitive = true
+configurations {
+    // For the depsJar task, we need to create a config we can pull libraries from to
+    // make the complete JAR. Some we do not want the transitive dependencies because
+    // they are already included on the Android system.
+    depsJarApi
+    depsJarApi.transitive = true
 
-        depsJarImplementation
-        depsJarImplementation.transitive = false
+    depsJarImplementation
+    depsJarImplementation.transitive = false
 
-        implementation.extendsFrom(depsJarApi)
-        implementation.extendsFrom(depsJarImplementation)
-    }
+    implementation.extendsFrom(depsJarApi)
+    implementation.extendsFrom(depsJarImplementation)
+}
 
-    dependencies {
-        depsJarApi project(path: ':conscrypt-android'),
-                   libs.bouncycastle.provider,
-                   libs.bouncycastle.apis
+dependencies {
+    depsJarApi project(path: ':conscrypt-android'),
+               libs.bouncycastle.provider,
+               libs.bouncycastle.apis
 
-        depsJarImplementation project(':conscrypt-benchmark-base'),
-                              project(path: ":conscrypt-testing", configuration: "shadow"),
-                              project(':conscrypt-libcore-stub')
+    depsJarImplementation project(':conscrypt-benchmark-base'),
+                          project(path: ":conscrypt-testing", configuration: "shadow"),
+                          project(':conscrypt-libcore-stub')
 
-        implementation libs.caliper
-    }
+    implementation libs.caliper
+}
 
-    // This task bundles up everything we're going to send to the device into a single jar.
-    // We need to include all the Conscrypt code plus the Bouncy Castle jar because the platform
-    // version of Bouncy Castle is jarjared.
-    //
-    // Since we're examining the contents of the archive files, we need to prevent evaluation of
-    // the .aar and .jar contents before the actual archives are built. To do this we create a
-    // configure task where the "from" contents is set inside a doLast stanza to ensure it is run
-    // after the execution phase of the "assemble" task.
-    def configureDepsJar = tasks.register("configureDepsJar") {
-        dependsOn assemble, \
-                  configurations.depsJarApi.artifacts, \
-                  configurations.depsJarImplementation.artifacts
-        doLast {
-            depsJar.from {
-                [
-                    configurations.depsJarApi,
-                    configurations.depsJarImplementation,
-                    configurations.archives.artifacts.file
-                ].collect { config ->
-                    config.findResults { archive ->
-                        // For Android library archives (.aar), we need to expand the classes.jar
-                        // inside as well as including all the jni libraries.
-                        if (archive.name.endsWith(".aar")) {
-                            [
-                                zipTree(archive).matching {
-                                    include 'classes.jar'
-                                }.collect { file ->
-                                    zipTree(file)
-                                },
-                                zipTree(archive).matching {
-                                    include '**/*.so'
-                                }
-                            ]
-                        } else if (archive.name.endsWith(".jar")) {
-                            // Bouncy Castle signs their jar, which causes our combined jar to fail
-                            // to verify.  Just strip out the signature files.
+// This task bundles up everything we're going to send to the device into a single jar.
+// We need to include all the Conscrypt code plus the Bouncy Castle jar because the platform
+// version of Bouncy Castle is jarjared.
+//
+// Since we're examining the contents of the archive files, we need to prevent evaluation of
+// the .aar and .jar contents before the actual archives are built. To do this we create a
+// configure task where the "from" contents is set inside a doLast stanza to ensure it is run
+// after the execution phase of the "assemble" task.
+def configureDepsJar = tasks.register("configureDepsJar") {
+    dependsOn assemble, \
+              configurations.depsJarApi.artifacts, \
+              configurations.depsJarImplementation.artifacts
+    doLast {
+        depsJar.from {
+            [
+                configurations.depsJarApi,
+                configurations.depsJarImplementation,
+                configurations.archives.artifacts.file
+            ].collect { config ->
+                config.findResults { archive ->
+                    // For Android library archives (.aar), we need to expand the classes.jar
+                    // inside as well as including all the jni libraries.
+                    if (archive.name.endsWith(".aar")) {
+                        [
                             zipTree(archive).matching {
-                                exclude 'META-INF/*.SF'
-                                exclude 'META-INF/*.DSA'
-                                exclude 'META-INF/*.EC'
-                                exclude 'META-INF/*.RSA'
+                                include 'classes.jar'
+                            }.collect { file ->
+                                zipTree(file)
+                            },
+                            zipTree(archive).matching {
+                                include '**/*.so'
                             }
+                        ]
+                    } else if (archive.name.endsWith(".jar")) {
+                        // Bouncy Castle signs their jar, which causes our combined jar to fail
+                        // to verify.  Just strip out the signature files.
+                        zipTree(archive).matching {
+                            exclude 'META-INF/*.SF'
+                            exclude 'META-INF/*.DSA'
+                            exclude 'META-INF/*.EC'
+                            exclude 'META-INF/*.RSA'
                         }
                     }
                 }
             }
         }
     }
+}
 
-    def depsJar = tasks.register("depsJar", Jar) {
-        dependsOn configureDepsJar
-        archiveName = 'bundled-deps.jar'
-    }
+def depsJar = tasks.register("depsJar", Jar) {
+    dependsOn configureDepsJar
+    archiveName = 'bundled-deps.jar'
+}
 
-    def getAndroidDeviceAbi = tasks.register("getAndroidDeviceAbi") {
-        doLast {
-            new ByteArrayOutputStream().withStream { os ->
-                def result = exec {
-                    executable android.adbExecutable
-                    args 'shell', 'getprop', 'ro.product.cpu.abi'
-                    standardOutput = os
-                }
-                project.ext.androidDeviceAbi = os.toString().trim()
-                project.ext.androidDevice64Bit = androidDeviceAbi.contains('64')
+def getAndroidDeviceAbi = tasks.register("getAndroidDeviceAbi") {
+    doLast {
+        new ByteArrayOutputStream().withStream { os ->
+            def result = exec {
+                executable android.adbExecutable
+                args 'shell', 'getprop', 'ro.product.cpu.abi'
+                standardOutput = os
             }
+            project.ext.androidDeviceAbi = os.toString().trim()
+            project.ext.androidDevice64Bit = androidDeviceAbi.contains('64')
         }
     }
+}
 
-    def configureExtractNativeLib = tasks.register("configureExtractNativeLib") {
-        dependsOn getAndroidDeviceAbi, depsJar
-        doLast {
-            extractNativeLib.from {
-                zipTree(depsJar.archivePath).matching {
-                    include "jni/${androidDeviceAbi}/*.so"
-                }.collect {
-                    // Using collect flattens out the directory.
-                    it
-                }
+def configureExtractNativeLib = tasks.register("configureExtractNativeLib") {
+    dependsOn getAndroidDeviceAbi, depsJar
+    doLast {
+        extractNativeLib.from {
+            zipTree(depsJar.archivePath).matching {
+                include "jni/${androidDeviceAbi}/*.so"
+            }.collect {
+                // Using collect flattens out the directory.
+                it
             }
         }
     }
+}
 
-    def extractNativeLib = tasks.register("extractNativeLib", Copy) {
-        dependsOn configureExtractNativeLib
-        into "$buildDir/extracted-native-libs"
-    }
+def extractNativeLib = tasks.register("extractNativeLib", Copy) {
+    dependsOn configureExtractNativeLib
+    into "$buildDir/extracted-native-libs"
+}
 
-    def configurePushNativeLibrary = tasks.register("configurePushNativeLibrary") {
-        dependsOn extractNativeLib
-        doLast {
-            project.ext.nativeLibPath = "/system/lib${androidDevice64Bit ? '64' : ''}/libconscrypt_jni.so"
-            pushNativeLibrary.args 'push', "${extractNativeLib.destinationDir}/libconscrypt_jni.so", nativeLibPath
-        }
+def configurePushNativeLibrary = tasks.register("configurePushNativeLibrary") {
+    dependsOn extractNativeLib
+    doLast {
+        project.ext.nativeLibPath = "/system/lib${androidDevice64Bit ? '64' : ''}/libconscrypt_jni.so"
+        pushNativeLibrary.args 'push', "${extractNativeLib.destinationDir}/libconscrypt_jni.so", nativeLibPath
     }
+}
 
-    def pushNativeLibrary = tasks.register("pushNativeLibrary", Exec) {
-        dependsOn configurePushNativeLibrary
-        pushNativeLibrary.executable android.adbExecutable
-    }
+def pushNativeLibrary = tasks.register("pushNativeLibrary", Exec) {
+    dependsOn configurePushNativeLibrary
+    pushNativeLibrary.executable android.adbExecutable
+}
 
-    def runBenchmarks = tasks.register("runBenchmarks") {
-        dependsOn depsJar, pushNativeLibrary
-        doLast {
-            // Execute the benchmarks
-            exec {
-                workingDir "${rootDir}"
-                environment PATH: "${android.sdkDirectory}/build-tools/${android.buildToolsVersion}:$System.env.PATH"
-                environment JACK_JAR: "${android.sdkDirectory}/build-tools/${android.buildToolsVersion}/jack.jar"
-
-                executable 'java'
-                args '-cp', 'benchmark-android/vogar.jar', 'vogar.Vogar'
-                args '--classpath', depsJar.archivePath
-                args '--benchmark'
-                args '--language=JN'
-                args '--mode=app_process'
-                args 'org.conscrypt.CaliperAlpnBenchmark'
-                args 'org.conscrypt.CaliperClientSocketBenchmark'
-                args 'org.conscrypt.CaliperEngineHandshakeBenchmark'
-                args 'org.conscrypt.CaliperEngineWrapBenchmark'
-            }
-            // Clean up the native library
-            exec {
-                executable android.adbExecutable
-                args 'shell', 'rm', '-f', nativeLibPath
-            }
+def runBenchmarks = tasks.register("runBenchmarks") {
+    dependsOn depsJar, pushNativeLibrary
+    doLast {
+        // Execute the benchmarks
+        exec {
+            workingDir "${rootDir}"
+            environment PATH: "${android.sdkDirectory}/build-tools/${android.buildToolsVersion}:$System.env.PATH"
+            environment JACK_JAR: "${android.sdkDirectory}/build-tools/${android.buildToolsVersion}/jack.jar"
+
+            executable 'java'
+            args '-cp', 'benchmark-android/vogar.jar', 'vogar.Vogar'
+            args '--classpath', depsJar.archivePath
+            args '--benchmark'
+            args '--language=JN'
+            args '--mode=app_process'
+            args 'org.conscrypt.CaliperAlpnBenchmark'
+            args 'org.conscrypt.CaliperClientSocketBenchmark'
+            args 'org.conscrypt.CaliperEngineHandshakeBenchmark'
+            args 'org.conscrypt.CaliperEngineWrapBenchmark'
+        }
+        // Clean up the native library
+        exec {
+            executable android.adbExecutable
+            args 'shell', 'rm', '-f', nativeLibPath
         }
-    }
-} else {
-    logger.warn('Android SDK has not been detected. The Android Benchmark module will not be built.')
-
-    // Disable all tasks
-    tasks.configureEach {
-        it.enabled = false
     }
 }
diff --git a/build.gradle b/build.gradle
index 2c259d49..5f813791 100644
--- a/build.gradle
+++ b/build.gradle
@@ -1,20 +1,9 @@
 import org.ajoberstar.grgit.Grgit
 import org.gradle.util.VersionNumber
 
-buildscript {
-    repositories {
-        google()
-        mavenCentral()
-    }
-    dependencies {
-        // This must be applied in the root project otherwise each subproject will
-        // have it in a different ClassLoader.
-        classpath libs.android.tools
-    }
-}
-
 plugins {
     alias libs.plugins.bnd apply false
+    alias libs.plugins.android.library apply false
     alias libs.plugins.errorprone
     alias libs.plugins.grgit
     alias libs.plugins.osdetector
diff --git a/common/src/jni/main/cpp/conscrypt/jniutil.cc b/common/src/jni/main/cpp/conscrypt/jniutil.cc
index dbc02c01..27e6b77b 100644
--- a/common/src/jni/main/cpp/conscrypt/jniutil.cc
+++ b/common/src/jni/main/cpp/conscrypt/jniutil.cc
@@ -264,6 +264,12 @@ int throwIllegalBlockSizeException(JNIEnv* env, const char* message) {
             env, "javax/crypto/IllegalBlockSizeException", message);
 }
 
+int throwIllegalStateException(JNIEnv* env, const char* message) {
+    JNI_TRACE("throwIllegalStateException %s", message);
+    return conscrypt::jniutil::throwException(
+            env, "java/lang/IllegalStateException", message);
+}
+
 int throwShortBufferException(JNIEnv* env, const char* message) {
     JNI_TRACE("throwShortBufferException %s", message);
     return conscrypt::jniutil::throwException(
@@ -406,6 +412,30 @@ int throwForX509Error(JNIEnv* env, int reason, const char* message,
     }
 }
 
+int throwForCryptoError(JNIEnv* env, int reason, const char* message,
+                      int (*defaultThrow)(JNIEnv*, const char*)) {
+    switch (reason) {
+        case ERR_R_INTERNAL_ERROR:
+            return throwIOException(env, message);
+            break;
+        default:
+            return defaultThrow(env, message);
+            break;
+    }
+}
+
+int throwForSslError(JNIEnv* env, int reason, const char* message,
+                      int (*defaultThrow)(JNIEnv*, const char*)) {
+    switch (reason) {
+        case ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED:
+            return throwIllegalStateException(env, message);
+            break;
+        default:
+            return defaultThrow(env, message);
+            break;
+    }
+}
+
 void throwExceptionFromBoringSSLError(JNIEnv* env, CONSCRYPT_UNUSED const char* location,
                                       int (*defaultThrow)(JNIEnv*, const char*)) {
     const char* file;
@@ -449,6 +479,12 @@ void throwExceptionFromBoringSSLError(JNIEnv* env, CONSCRYPT_UNUSED const char*
             case ERR_LIB_DSA:
                 throwInvalidKeyException(env, message);
                 break;
+            case ERR_LIB_CRYPTO:
+                throwForCryptoError(env, reason, message, defaultThrow);
+                break;
+            case ERR_LIB_SSL:
+                throwForSslError(env, reason, message, defaultThrow);
+                break;
             default:
                 defaultThrow(env, message);
                 break;
diff --git a/common/src/jni/main/cpp/conscrypt/native_crypto.cc b/common/src/jni/main/cpp/conscrypt/native_crypto.cc
index 784b7069..ba926480 100644
--- a/common/src/jni/main/cpp/conscrypt/native_crypto.cc
+++ b/common/src/jni/main/cpp/conscrypt/native_crypto.cc
@@ -2562,6 +2562,42 @@ static void NativeCrypto_X25519_keypair(JNIEnv* env, jclass, jbyteArray outPubli
     JNI_TRACE("X25519_keypair(%p, %p) => success", outPublicArray, outPrivateArray);
 }
 
+static void NativeCrypto_ED25519_keypair(JNIEnv* env, jclass, jbyteArray outPublicArray,
+                                         jbyteArray outPrivateArray) {
+    CHECK_ERROR_QUEUE_ON_RETURN;
+    JNI_TRACE("ED25519_keypair(%p, %p)", outPublicArray, outPrivateArray);
+
+    ScopedByteArrayRW outPublic(env, outPublicArray);
+    if (outPublic.get() == nullptr) {
+        JNI_TRACE("ED25519_keypair(%p, %p) can't get output public key buffer", outPublicArray,
+                  outPrivateArray);
+        return;
+    }
+
+    ScopedByteArrayRW outPrivate(env, outPrivateArray);
+    if (outPrivate.get() == nullptr) {
+        JNI_TRACE("ED25519_keypair(%p, %p) can't get output private key buffer", outPublicArray,
+                  outPrivateArray);
+        return;
+    }
+
+    if (outPublic.size() != ED25519_PUBLIC_KEY_LEN) {
+        conscrypt::jniutil::throwIllegalArgumentException(env,
+                                                          "Output public key array length != 32");
+        return;
+    }
+
+    if (outPrivate.size() != ED25519_PRIVATE_KEY_LEN) {
+        conscrypt::jniutil::throwIllegalArgumentException(env,
+                                                          "Output private key array length != 64");
+        return;
+    }
+
+    ED25519_keypair(reinterpret_cast<uint8_t*>(outPublic.get()),
+                    reinterpret_cast<uint8_t*>(outPrivate.get()));
+    JNI_TRACE("ED25519_keypair(%p, %p) => success", outPublicArray, outPrivateArray);
+}
+
 static jlong NativeCrypto_EVP_MD_CTX_create(JNIEnv* env, jclass) {
     CHECK_ERROR_QUEUE_ON_RETURN;
     JNI_TRACE_MD("EVP_MD_CTX_create()");
@@ -2760,7 +2796,9 @@ static jlong evpDigestSignVerifyInit(JNIEnv* env,
     }
     JNI_TRACE("%s(%p, %p, %p) <- ptr", jniName, mdCtx, md, pkey);
 
-    if (md == nullptr) {
+    // For ED25519, md must be null, see
+    // https://github.com/google/boringssl/blob/master/include/openssl/evp.h
+    if (md == nullptr && (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519)) {
         JNI_TRACE("ctx=%p %s => md == null", mdCtx, jniName);
         conscrypt::jniutil::throwNullPointerException(env, "md == null");
         return 0;
@@ -3034,6 +3072,137 @@ static jboolean NativeCrypto_EVP_DigestVerifyFinal(JNIEnv* env, jclass, jobject
     return result;
 }
 
+static jbyteArray NativeCrypto_EVP_DigestSign(JNIEnv* env, jclass, jobject evpMdCtxRef,
+                                              jbyteArray inJavaBytes, jint inOffset,
+                                              jint inLength) {
+    CHECK_ERROR_QUEUE_ON_RETURN;
+
+    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
+    JNI_TRACE_MD("%s(%p, %p, %d, %d)", "EVP_DigestSign", mdCtx, inJavaBytes, inOffset, inLength);
+
+    if (mdCtx == nullptr) {
+        return nullptr;
+    }
+
+    if (inJavaBytes == nullptr) {
+        conscrypt::jniutil::throwNullPointerException(env, "inBytes");
+        return nullptr;
+    }
+
+    size_t array_size = static_cast<size_t>(env->GetArrayLength(inJavaBytes));
+    if (ARRAY_CHUNK_INVALID(array_size, inOffset, inLength)) {
+        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
+                                           "inBytes");
+        return nullptr;
+    }
+
+    jint in_offset = inOffset;
+    jint in_size = inLength;
+
+    jbyte* array_elements = env->GetByteArrayElements(inJavaBytes, nullptr);
+    if (array_elements == nullptr) {
+        conscrypt::jniutil::throwOutOfMemory(env, "Unable to obtain elements of inBytes");
+        return nullptr;
+    }
+    const unsigned char* buf = reinterpret_cast<const unsigned char*>(array_elements);
+    const unsigned char* inStart = buf + in_offset;
+    size_t inLen = static_cast<size_t>(in_size);
+
+    size_t maxLen;
+    if (EVP_DigestSign(mdCtx, nullptr, &maxLen, inStart, inLen) != 1) {
+        JNI_TRACE("ctx=%p EVP_DigestSign => threw exception", mdCtx);
+        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestSign");
+        return nullptr;
+    }
+
+    std::unique_ptr<unsigned char[]> buffer(new unsigned char[maxLen]);
+    if (buffer.get() == nullptr) {
+        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate signature buffer");
+        return nullptr;
+    }
+    size_t actualLen(maxLen);
+    if (EVP_DigestSign(mdCtx, buffer.get(), &actualLen, inStart, inLen) != 1) {
+        JNI_TRACE("ctx=%p EVP_DigestSign => threw exception", mdCtx);
+        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestSign");
+        return nullptr;
+    }
+    if (actualLen > maxLen) {
+        JNI_TRACE("ctx=%p EVP_DigestSign => signature too long: %zd vs %zd", mdCtx, actualLen,
+                  maxLen);
+        conscrypt::jniutil::throwRuntimeException(env, "EVP_DigestSign signature too long");
+        return nullptr;
+    }
+
+    ScopedLocalRef<jbyteArray> sigJavaBytes(env, env->NewByteArray(static_cast<jint>(actualLen)));
+    if (sigJavaBytes.get() == nullptr) {
+        conscrypt::jniutil::throwOutOfMemory(env, "Failed to allocate signature byte[]");
+        return nullptr;
+    }
+    env->SetByteArrayRegion(sigJavaBytes.get(), 0, static_cast<jint>(actualLen),
+                            reinterpret_cast<jbyte*>(buffer.get()));
+
+    JNI_TRACE("EVP_DigestSign(%p) => %p", mdCtx, sigJavaBytes.get());
+    return sigJavaBytes.release();
+}
+
+static jboolean NativeCrypto_EVP_DigestVerify(JNIEnv* env, jclass, jobject evpMdCtxRef,
+                                              jbyteArray signature, jint sigOffset, jint sigLen,
+                                              jbyteArray data, jint dataOffset, jint dataLen) {
+    CHECK_ERROR_QUEUE_ON_RETURN;
+    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
+    JNI_TRACE("EVP_DigestVerify(%p)", mdCtx);
+
+    if (mdCtx == nullptr) {
+        return 0;
+    }
+
+    ScopedByteArrayRO sigBytes(env, signature);
+    if (sigBytes.get() == nullptr) {
+        return 0;
+    }
+
+    if (ARRAY_OFFSET_LENGTH_INVALID(sigBytes, sigOffset, sigLen)) {
+        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
+                                           "signature");
+        return 0;
+    }
+
+    ScopedByteArrayRO dataBytes(env, data);
+    if (dataBytes.get() == nullptr) {
+        return 0;
+    }
+
+    if (ARRAY_OFFSET_LENGTH_INVALID(dataBytes, dataOffset, dataLen)) {
+        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException", "data");
+        return 0;
+    }
+
+    const unsigned char* sigBuf = reinterpret_cast<const unsigned char*>(sigBytes.get());
+    const unsigned char* dataBuf = reinterpret_cast<const unsigned char*>(dataBytes.get());
+    int err = EVP_DigestVerify(mdCtx, sigBuf + sigOffset, static_cast<size_t>(sigLen),
+                               dataBuf + dataOffset, static_cast<size_t>(dataLen));
+    jboolean result;
+    if (err == 1) {
+        // Signature verified
+        result = 1;
+    } else if (err == 0) {
+        // Signature did not verify
+        result = 0;
+    } else {
+        // Error while verifying signature
+        JNI_TRACE("ctx=%p EVP_DigestVerify => threw exception", mdCtx);
+        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestVerify");
+        return 0;
+    }
+
+    // If the signature did not verify, BoringSSL error queue contains an error (BAD_SIGNATURE).
+    // Clear the error queue to prevent its state from affecting future operations.
+    ERR_clear_error();
+
+    JNI_TRACE("EVP_DigestVerify(%p) => %d", mdCtx, result);
+    return result;
+}
+
 static jint evpPkeyEncryptDecrypt(JNIEnv* env,
                                   int (*encrypt_decrypt_func)(EVP_PKEY_CTX*, uint8_t*, size_t*,
                                                               const uint8_t*, size_t),
@@ -10888,6 +11057,131 @@ static jbyteArray NativeCrypto_Scrypt_generate_key(JNIEnv* env, jclass, jbyteArr
     return key_bytes;
 }
 
+/**
+ * SPAKE2+ support
+ */
+
+#define SPAKE2PLUS_PW_VERIFIER_SIZE 32
+#define SPAKE2PLUS_REGISTRATION_RECORD_SIZE 65
+
+static void NativeCrypto_SSL_CTX_set_spake_credential(JNIEnv* env, jclass,
+                                                      jbyteArray context, jbyteArray pw_array,
+                                                      jbyteArray id_prover_array,
+                                                      jbyteArray id_verifier_array,
+                                                      jboolean is_client,
+                                                      jint handshake_limit,
+                                                      jlong ssl_ctx_address,
+                                                      CONSCRYPT_UNUSED jobject holder) {
+    CHECK_ERROR_QUEUE_ON_RETURN;
+
+    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
+
+    if (ssl_ctx == nullptr) {
+        JNI_TRACE("SSL_CTX_set_spake_credential => ssl_ctx == null");
+        return;
+    }
+
+    JNI_TRACE("SSL_CTX_set_spake_credential(%p, %p, %p, %p, %d, %d, %p)", context, pw_array,
+              id_prover_array, id_verifier_array, is_client, handshake_limit,
+              ssl_ctx);
+
+    if (context == nullptr || pw_array == nullptr || id_prover_array == nullptr ||
+        id_verifier_array == nullptr) {
+        conscrypt::jniutil::throwNullPointerException(env, "Input parameters cannot be null");
+        return;
+    }
+
+    ScopedByteArrayRO context_bytes(env, context);
+    if (context_bytes.get() == nullptr) {
+        JNI_TRACE("ctx=%p SSL_CTX_set_spake_credential => threw exception", ssl_ctx);
+        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate buffer for context");
+        return;
+    }
+
+    ScopedByteArrayRO pw_bytes(env, pw_array);
+    if (pw_bytes.get() == nullptr) {
+        JNI_TRACE("ctx=%p SSL_CTX_set_spake_credential => threw exception", ssl_ctx);
+        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate buffer for pw_array");
+        return;
+    }
+
+    ScopedByteArrayRO id_prover_bytes(env, id_prover_array);
+    if (id_prover_bytes.get() == nullptr) {
+        JNI_TRACE("ctx=%p SSL_CTX_set_spake_credential => threw exception", ssl_ctx);
+        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate buffer for id_prover_array");
+        return;
+    }
+
+    ScopedByteArrayRO id_verifier_bytes(env, id_verifier_array);
+    if (id_verifier_bytes.get() == nullptr) {
+        JNI_TRACE("ctx=%p SSL_CTX_set_spake_credential => threw exception", ssl_ctx);
+        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate buffer for id_verifier_array");
+        return;
+    }
+
+    uint8_t pw_verifier_w0[SPAKE2PLUS_PW_VERIFIER_SIZE];
+    uint8_t pw_verifier_w1[SPAKE2PLUS_PW_VERIFIER_SIZE];
+    uint8_t registration_record[SPAKE2PLUS_REGISTRATION_RECORD_SIZE];
+    int ret = SSL_spake2plusv1_register(
+                /* out_pw_verifier_w0= */ pw_verifier_w0,
+                /* out_pw_verifier_w1= */ pw_verifier_w1,
+                /* out_registration_record= */ registration_record,
+                /* pw= */ reinterpret_cast<const uint8_t*>(pw_bytes.get()),
+                /* pw_len= */ pw_bytes.size(),
+                /* id_prover= */ reinterpret_cast<const uint8_t*>(id_prover_bytes.get()),
+                /* id_prover_len= */ id_prover_bytes.size(),
+                /* id_verifier= */ reinterpret_cast<const uint8_t*>(id_verifier_bytes.get()),
+                /* id_verifier_len= */ id_verifier_bytes.size());
+    if (ret != 1) {
+        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "SSL_spake2plusv1_register failed");
+        return;
+    }
+
+    bssl::UniquePtr<SSL_CREDENTIAL> creds;
+    if (is_client) {
+        bssl::UniquePtr<SSL_CREDENTIAL> creds_client(SSL_CREDENTIAL_new_spake2plusv1_client(
+            /* context= */ reinterpret_cast<const uint8_t*>(context_bytes.get()),
+            /* context_len= */ context_bytes.size(),
+            /* client_identity= */ reinterpret_cast<const uint8_t*>(id_prover_bytes.get()),
+            /* client_identity_len= */ id_prover_bytes.size(),
+            /* server_identity= */ reinterpret_cast<const uint8_t*>(id_verifier_bytes.get()),
+            /* server_identity_len= */ id_verifier_bytes.size(),
+            /* attempts= */ handshake_limit,
+            /* w0= */ pw_verifier_w0,
+            /* w0_len= */ sizeof(pw_verifier_w0),
+            /* w1= */ pw_verifier_w1,
+            /* w1_len= */ sizeof(pw_verifier_w1)));
+            creds = std::move(creds_client);
+    } else {
+        bssl::UniquePtr<SSL_CREDENTIAL> creds_server(SSL_CREDENTIAL_new_spake2plusv1_server(
+            /* context= */ reinterpret_cast<const uint8_t*>(context_bytes.get()),
+            /* context_len= */ context_bytes.size(),
+            /* client_identity= */ reinterpret_cast<const uint8_t*>(id_prover_bytes.get()),
+            /* client_identity_len= */ id_prover_bytes.size(),
+            /* server_identity= */ reinterpret_cast<const uint8_t*>(id_verifier_bytes.get()),
+            /* server_identity_len= */ id_verifier_bytes.size(),
+            /* attempts= */ handshake_limit,
+            /* w0= */ pw_verifier_w0,
+            /* w0_len= */ sizeof(pw_verifier_w0),
+            /* registration_record= */ registration_record,
+            /* registration_record_len= */ sizeof(registration_record)));
+            creds = std::move(creds_server);
+    }
+    if (creds == nullptr) {
+        conscrypt::jniutil::throwSSLExceptionStr(
+                env, "SSL_CREDENTIAL_new_spake2plusv1 failed");
+        return;
+    }
+    ret = SSL_CTX_add1_credential(ssl_ctx, creds.get());
+    if (ret != 1) {
+        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "SSL_CTX_add1_credential failed");
+        return;
+    }
+    JNI_TRACE("SSL_CTX_set_spake_credential (%p, %p, %p, %p, %d, %d, %p) => %p", context, pw_array,
+            id_prover_array, id_verifier_array, is_client, handshake_limit, ssl_ctx, creds.get());
+    return;
+}
+
 // TESTING METHODS BEGIN
 
 static int NativeCrypto_BIO_read(JNIEnv* env, jclass, jlong bioRef, jbyteArray outputJavaBytes) {
@@ -11119,6 +11413,7 @@ static JNINativeMethod sNativeCryptoMethods[] = {
         CONSCRYPT_NATIVE_METHOD(ECDSA_verify, "([B[B" REF_EVP_PKEY ")I"),
         CONSCRYPT_NATIVE_METHOD(X25519, "([B[B[B)Z"),
         CONSCRYPT_NATIVE_METHOD(X25519_keypair, "([B[B)V"),
+        CONSCRYPT_NATIVE_METHOD(ED25519_keypair, "([B[B)V"),
         CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_create, "()J"),
         CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_cleanup, "(" REF_EVP_MD_CTX ")V"),
         CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_destroy, "(J)V"),
@@ -11137,6 +11432,8 @@ static JNINativeMethod sNativeCryptoMethods[] = {
         CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyUpdate, "(" REF_EVP_MD_CTX "[BII)V"),
         CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyUpdateDirect, "(" REF_EVP_MD_CTX "JI)V"),
         CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyFinal, "(" REF_EVP_MD_CTX "[BII)Z"),
+        CONSCRYPT_NATIVE_METHOD(EVP_DigestSign, "(" REF_EVP_MD_CTX "[BII)[B"),
+        CONSCRYPT_NATIVE_METHOD(EVP_DigestVerify, "(" REF_EVP_MD_CTX "[BII[BII)Z"),
         CONSCRYPT_NATIVE_METHOD(EVP_PKEY_encrypt_init, "(" REF_EVP_PKEY ")J"),
         CONSCRYPT_NATIVE_METHOD(EVP_PKEY_encrypt, "(" REF_EVP_PKEY_CTX "[BI[BII)I"),
         CONSCRYPT_NATIVE_METHOD(EVP_PKEY_decrypt_init, "(" REF_EVP_PKEY ")J"),
@@ -11176,8 +11473,10 @@ static JNINativeMethod sNativeCryptoMethods[] = {
         CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_free, "(J)V"),
         CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_open, "(" REF_EVP_HPKE_CTX "[B[B)[B"),
         CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_seal, "(" REF_EVP_HPKE_CTX "[B[B)[B"),
-        CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_setup_base_mode_recipient, "(III[B[B[B)Ljava/lang/Object;"),
-        CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_setup_base_mode_sender, "(III[B[B)[Ljava/lang/Object;"),
+        CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_setup_base_mode_recipient,
+                                "(III[B[B[B)Ljava/lang/Object;"),
+        CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_setup_base_mode_sender,
+                                "(III[B[B)[Ljava/lang/Object;"),
         CONSCRYPT_NATIVE_METHOD(EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing,
                                 "(III[B[B[B)[Ljava/lang/Object;"),
         CONSCRYPT_NATIVE_METHOD(HMAC_CTX_new, "()J"),
@@ -11366,6 +11665,7 @@ static JNINativeMethod sNativeCryptoMethods[] = {
         CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_shutdown, "(J" REF_SSL SSL_CALLBACKS ")V"),
         CONSCRYPT_NATIVE_METHOD(usesBoringSsl_FIPS_mode, "()Z"),
         CONSCRYPT_NATIVE_METHOD(Scrypt_generate_key, "([B[BIIII)[B"),
+        CONSCRYPT_NATIVE_METHOD(SSL_CTX_set_spake_credential, "([B[B[B[BZIJ" REF_SSL_CTX ")V"),
 
         // Used for testing only.
         CONSCRYPT_NATIVE_METHOD(BIO_read, "(J[B)I"),
diff --git a/common/src/jni/main/include/conscrypt/jniutil.h b/common/src/jni/main/include/conscrypt/jniutil.h
index 68ce128d..7ae567db 100644
--- a/common/src/jni/main/include/conscrypt/jniutil.h
+++ b/common/src/jni/main/include/conscrypt/jniutil.h
@@ -195,6 +195,11 @@ extern int throwNullPointerException(JNIEnv* env, const char* msg);
  */
 extern int throwOutOfMemory(JNIEnv* env, const char* message);
 
+/**
+ * Throws an IllegalArgumentException with the given string as a message.
+ */
+extern int throwIllegalArgumentException(JNIEnv* env, const char* message);
+
 /**
  * Throws a BadPaddingException with the given string as a message.
  */
diff --git a/common/src/main/java/org/conscrypt/AbstractSessionContext.java b/common/src/main/java/org/conscrypt/AbstractSessionContext.java
index d4ac04fb..0d9bec02 100644
--- a/common/src/main/java/org/conscrypt/AbstractSessionContext.java
+++ b/common/src/main/java/org/conscrypt/AbstractSessionContext.java
@@ -47,7 +47,6 @@ abstract class AbstractSessionContext implements SSLSessionContext {
 
     private final ReadWriteLock lock = new ReentrantReadWriteLock();
 
-
     private final Map<ByteArray, NativeSslSession> sessions =
             new LinkedHashMap<ByteArray, NativeSslSession>() {
                 @Override
@@ -206,6 +205,32 @@ abstract class AbstractSessionContext implements SSLSessionContext {
         return (sslCtxNativePointer != 0);
     }
 
+    void initSpake(SSLParametersImpl parameters) throws SSLException {
+        Spake2PlusKeyManager spakeKeyManager = parameters.getSpake2PlusKeyManager();
+        byte[] context = spakeKeyManager.getContext();
+        byte[] idProverArray = spakeKeyManager.getIdProver();
+        byte[] idVerifierArray = spakeKeyManager.getIdVerifier();
+        byte[] pwArray = spakeKeyManager.getPassword();
+        boolean isClient = spakeKeyManager.isClient();
+        int handshakeLimit = spakeKeyManager.getHandshakeLimit();
+        lock.writeLock().lock();
+        try {
+            if (isValid()) {
+                NativeCrypto.SSL_CTX_set_spake_credential(
+                            context,
+                            pwArray,
+                            idProverArray,
+                            idVerifierArray,
+                            isClient,
+                            handshakeLimit,
+                            sslCtxNativePointer,
+                            this);
+            }
+        } finally {
+            lock.writeLock().unlock();
+        }
+    }
+
     /**
      * Returns a native pointer to a new SSL object in this SSL_CTX.
      */
diff --git a/common/src/main/java/org/conscrypt/Conscrypt.java b/common/src/main/java/org/conscrypt/Conscrypt.java
index 53bc16e7..c8829263 100644
--- a/common/src/main/java/org/conscrypt/Conscrypt.java
+++ b/common/src/main/java/org/conscrypt/Conscrypt.java
@@ -160,8 +160,8 @@ public final class Conscrypt {
         private String name = Platform.getDefaultProviderName();
         private boolean provideTrustManager = Platform.provideTrustManagerByDefault();
         private String defaultTlsProtocol = NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3;
-        private boolean deprecatedTlsV1 = true;
-        private boolean enabledTlsV1 = false;
+        private boolean deprecatedTlsV1 = Platform.isTlsV1Deprecated();
+        private boolean enabledTlsV1 = Platform.isTlsV1Supported();
 
         private ProviderBuilder() {}
 
diff --git a/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java b/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java
index af64d998..a448dcad 100644
--- a/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java
+++ b/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java
@@ -110,7 +110,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
     private static ConscryptEngine newEngine(
             SSLParametersImpl sslParameters, final ConscryptEngineSocket socket) {
         SSLParametersImpl modifiedParams;
-        if (Platform.supportsX509ExtendedTrustManager()) {
+        if (sslParameters.isSpake()) {
+            modifiedParams = sslParameters.cloneWithSpake();
+        } else if (Platform.supportsX509ExtendedTrustManager()) {
             modifiedParams = sslParameters.cloneWithTrustManager(
                 getDelegatingTrustManager(sslParameters.getX509TrustManager(), socket));
         } else {
@@ -302,11 +304,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
                 case STATE_READY_HANDSHAKE_CUT_THROUGH:
                     if (handshakeStartedMillis > 0) {
                         StatsLog statsLog = Platform.getStatsLog();
-                        if (statsLog != null) {
-                            statsLog.countTlsHandshake(true, engine.getSession().getProtocol(),
-                                    engine.getSession().getCipherSuite(),
-                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
-                        }
+                        statsLog.countTlsHandshake(true, engine.getSession().getProtocol(),
+                                engine.getSession().getCipherSuite(),
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
@@ -319,12 +319,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
                 case STATE_CLOSED:
                     if (handshakeStartedMillis > 0) {
                         StatsLog statsLog = Platform.getStatsLog();
-                        if (statsLog != null) {
-                            // Handshake was in progress and so must have failed.
-                            statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED",
-                                    "TLS_CIPHER_FAILED",
-                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
-                        }
+                        // Handshake was in progress and so must have failed.
+                        statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED", "TLS_CIPHER_FAILED",
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
@@ -827,6 +824,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
         @Override
         public int read(byte[] b, int off, int len) throws IOException {
             waitForHandshake();
+            if (len == 0) {
+                return 0;
+            }
             synchronized (readLock) {
                 return readUntilDataAvailable(b, off, len);
             }
diff --git a/common/src/main/java/org/conscrypt/NativeCrypto.java b/common/src/main/java/org/conscrypt/NativeCrypto.java
index f33acbce..2ce8284f 100644
--- a/common/src/main/java/org/conscrypt/NativeCrypto.java
+++ b/common/src/main/java/org/conscrypt/NativeCrypto.java
@@ -69,6 +69,7 @@ public final class NativeCrypto {
             error = t;
         }
         loadError = error;
+        setTlsV1DeprecationStatus(Platform.isTlsV1Deprecated(), Platform.isTlsV1Supported());
     }
 
     private native static void clinit();
@@ -212,6 +213,8 @@ public final class NativeCrypto {
 
     static native void X25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
 
+    static native void ED25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
+
     // --- Message digest functions --------------
 
     // These return const references
@@ -264,6 +267,12 @@ public final class NativeCrypto {
     static native boolean EVP_DigestVerifyFinal(NativeRef.EVP_MD_CTX ctx, byte[] signature,
             int offset, int length) throws IndexOutOfBoundsException;
 
+    static native byte[] EVP_DigestSign(
+            NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
+
+    static native boolean EVP_DigestVerify(NativeRef.EVP_MD_CTX ctx, byte[] sigBuffer,
+            int sigOffset, int sigLen, byte[] dataBuffer, int dataOffset, int dataLen);
+
     static native long EVP_PKEY_encrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;
 
     static native int EVP_PKEY_encrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
@@ -639,6 +648,23 @@ public final class NativeCrypto {
 
     static native int X509_supported_extension(long x509ExtensionRef);
 
+    // --- SPAKE ---------------------------------------------------------------
+
+    /**
+     * Sets the SPAKE credential for the given SSL context using a password.
+     * Used for both client and server.
+     */
+    static native void SSL_CTX_set_spake_credential(
+            byte[] context,
+            byte[] pw_array,
+            byte[] id_prover_array,
+            byte[] id_verifier_array,
+            boolean is_client,
+            int handshake_limit,
+            long ssl_ctx,
+            AbstractSessionContext holder)
+        throws SSLException;
+
     // --- ASN1_TIME -----------------------------------------------------------
 
     static native void ASN1_TIME_to_Calendar(long asn1TimeCtx, Calendar cal) throws ParsingException;
@@ -961,6 +987,11 @@ public final class NativeCrypto {
             "TLS_PSK_WITH_AES_256_CBC_SHA",
     };
 
+    /** TLS-SPAKE */
+    static final String[] DEFAULT_SPAKE_CIPHER_SUITES = new String[] {
+            "TLS1_3_NAMED_PAKE_SPAKE2PLUSV1",
+    };
+
     static String[] getSupportedCipherSuites() {
         return SSLUtils.concat(SUPPORTED_TLS_1_3_CIPHER_SUITES, SUPPORTED_TLS_1_2_CIPHER_SUITES.clone());
     }
@@ -1208,6 +1239,11 @@ public final class NativeCrypto {
             if (SUPPORTED_TLS_1_2_CIPHER_SUITES_SET.contains(cipherSuites[i])) {
                 continue;
             }
+            // Not sure if we need to do this for SPAKE, but the SPAKE cipher suite
+            // not registered at the moment.
+            if (DEFAULT_SPAKE_CIPHER_SUITES[0] == cipherSuites[i]) {
+                continue;
+            }
 
             // For backwards compatibility, it's allowed for |cipherSuite| to
             // be an OpenSSL-style cipher-suite name.
@@ -1324,18 +1360,16 @@ public final class NativeCrypto {
                 throws CertificateException;
 
         /**
-         * Called on an SSL client when the server requests (or
-         * requires a certificate). The client can respond by using
-         * SSL_use_certificate and SSL_use_PrivateKey to set a
-         * certificate if has an appropriate one available, similar to
-         * how the server provides its certificate.
+         * Called on an SSL client when the server requests (or requires a certificate). The client
+         * can respond by using SSL_use_certificate and SSL_use_PrivateKey to set a certificate if
+         * has an appropriate one available, similar to how the server provides its certificate.
          *
-         * @param keyTypes key types supported by the server,
-         * convertible to strings with #keyType
+         * @param keyTypes key types supported by the server, convertible to strings with #keyType
          * @param asn1DerEncodedX500Principals CAs known to the server
          */
-        @SuppressWarnings("unused") void clientCertificateRequested(byte[] keyTypes, int[] signatureAlgs,
-                byte[][] asn1DerEncodedX500Principals)
+        @SuppressWarnings("unused")
+        void clientCertificateRequested(
+                byte[] keyTypes, int[] signatureAlgs, byte[][] asn1DerEncodedX500Principals)
                 throws CertificateEncodingException, SSLException;
 
         /**
diff --git a/common/src/main/java/org/conscrypt/NativeSsl.java b/common/src/main/java/org/conscrypt/NativeSsl.java
index 51ae8456..d0671dab 100644
--- a/common/src/main/java/org/conscrypt/NativeSsl.java
+++ b/common/src/main/java/org/conscrypt/NativeSsl.java
@@ -25,6 +25,10 @@ import static org.conscrypt.NativeConstants.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
 import static org.conscrypt.NativeConstants.SSL_VERIFY_NONE;
 import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 
+import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
+import org.conscrypt.SSLParametersImpl.AliasChooser;
+import org.conscrypt.SSLParametersImpl.PSKCallbacks;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.net.SocketException;
@@ -39,15 +43,13 @@ import java.util.HashSet;
 import java.util.Set;
 import java.util.concurrent.locks.ReadWriteLock;
 import java.util.concurrent.locks.ReentrantReadWriteLock;
+
 import javax.crypto.SecretKey;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.X509KeyManager;
 import javax.net.ssl.X509TrustManager;
 import javax.security.auth.x500.X500Principal;
-import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
-import org.conscrypt.SSLParametersImpl.AliasChooser;
-import org.conscrypt.SSLParametersImpl.PSKCallbacks;
 
 /**
  * A utility wrapper that abstracts operations on the underlying native SSL instance.
@@ -307,9 +309,15 @@ final class NativeSsl {
                     + " and " + NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1
                     + " are no longer supported and were filtered from the list");
         }
-        NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
-        NativeCrypto.setEnabledCipherSuites(
-            ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
+        // We can use default cipher suites for SPAKE.
+        if (!parameters.isSpake()) {
+            NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
+            NativeCrypto.setEnabledCipherSuites(
+                ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
+        } else {
+            // SPAKE only supports TLSv1.3.
+            NativeCrypto.setEnabledProtocols(ssl, this, new String[] {"TLSv1.3"});
+        }
 
         if (parameters.applicationProtocols.length > 0) {
             NativeCrypto.setApplicationProtocols(ssl, this, isClient(), parameters.applicationProtocols);
@@ -349,7 +357,9 @@ final class NativeSsl {
         // with TLSv1 and SSLv3).
         NativeCrypto.SSL_set_mode(ssl, this, SSL_MODE_CBC_RECORD_SPLITTING);
 
-        setCertificateValidation();
+        if (!parameters.isSpake()) {
+            setCertificateValidation();
+        }
         setTlsChannelId(channelIdPrivateKey);
     }
 
diff --git a/common/src/main/java/org/conscrypt/OpenSSLAeadCipher.java b/common/src/main/java/org/conscrypt/OpenSSLAeadCipher.java
index 1b201cc2..7d346d50 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLAeadCipher.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLAeadCipher.java
@@ -241,7 +241,7 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
             throw new IllegalArgumentException("Cannot write to Read Only ByteBuffer");
         }
         if (bufCount != 0) {
-            return super.engineDoFinal(input, output);// traditional case
+            return super.engineDoFinal(input, output); // traditional case
         }
         int bytesWritten;
         if (!input.isDirect()) {
@@ -268,26 +268,44 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
         return bytesWritten;
     }
 
+    @Override
+    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
+            throws IllegalBlockSizeException, BadPaddingException {
+        final int maximumLen = getOutputSizeForFinal(inputLen);
+        /* Assume that we'll output exactly on a byte boundary. */
+        final byte[] output = new byte[maximumLen];
+
+        int bytesWritten;
+        try {
+            bytesWritten = doFinalInternal(input, inputOffset, inputLen, output, 0);
+        } catch (ShortBufferException e) {
+            /* This should not happen since we sized our own buffer. */
+            throw new RuntimeException("our calculated buffer was too small", e);
+        }
+
+        if (bytesWritten == output.length) {
+            return output;
+        } else if (bytesWritten == 0) {
+            return EmptyArray.BYTE;
+        } else {
+            return Arrays.copyOf(output, bytesWritten);
+        }
+    }
+
     @Override
     protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
             int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
-        BadPaddingException {
-        // Because the EVP_AEAD updateInternal processes input but doesn't create any output
-        // (and thus can't check the output buffer), we need to add this check before the
-        // superclass' processing to ensure that updateInternal is never called if the
-        // output buffer isn't large enough.
-        if (output != null) {
-            if (getOutputSizeForFinal(inputLen) > output.length - outputOffset) {
-                throw new ShortBufferWithoutStackTraceException("Insufficient output space");
-            }
+            BadPaddingException {
+        if (output == null) {
+            throw new NullPointerException("output == null");
         }
-        return super.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
+        if (getOutputSizeForFinal(inputLen) > output.length - outputOffset) {
+            throw new ShortBufferWithoutStackTraceException("Insufficient output space");
+        }
+        return doFinalInternal(input, inputOffset, inputLen, output, outputOffset);
     }
 
-    @Override
-    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
-            int outputOffset, int maximumLen) throws ShortBufferException {
-        checkInitialization();
+    void appendToBuf(byte[] input, int inputOffset, int inputLen) {
         if (buf == null) {
             throw new IllegalStateException("Cipher not initialized");
         }
@@ -298,6 +316,13 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
             System.arraycopy(input, inputOffset, buf, this.bufCount, inputLen);
             this.bufCount += inputLen;
         }
+    }
+
+    @Override
+    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
+            int outputOffset, int maximumLen) throws ShortBufferException {
+        checkInitialization();
+        appendToBuf(input, inputOffset, inputLen);
         return 0;
     }
 
@@ -351,18 +376,39 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
         return bytesWritten;
     }
 
-    @Override
-    int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
+    int doFinalInternal(byte[] input, int inputOffset, int inputLen,
+            byte[] output, int outputOffset)
             throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
         checkInitialization();
+
+        byte[] in;
+        int inOffset;
+        int inLen;
+        if (bufCount > 0) {
+            if (inputLen > 0) {
+                appendToBuf(input, inputOffset, inputLen);
+            }
+            in = buf;
+            inOffset = 0;
+            inLen = bufCount;
+        } else {
+            if (inputLen == 0 && input == null) {
+                in = EmptyArray.BYTE; // input can be null when inputLen == 0
+            } else {
+                in = input;
+            }
+            inOffset = inputOffset;
+            inLen = inputLen;
+        }
+
         final int bytesWritten;
         try {
             if (isEncrypting()) {
                 bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(evpAead, encodedKey,
-                        tagLengthInBytes, output, outputOffset, iv, buf, 0, bufCount, aad);
+                        tagLengthInBytes, output, outputOffset, iv, in, inOffset, inLen, aad);
             } else {
                 bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey,
-                        tagLengthInBytes, output, outputOffset, iv, buf, 0, bufCount, aad);
+                        tagLengthInBytes, output, outputOffset, iv, in, inOffset, inLen, aad);
             }
         } catch (BadPaddingException e) {
             throwAEADBadTagExceptionIfAvailable(e.getMessage(), e.getCause());
@@ -390,12 +436,6 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
         return 0;
     }
 
-    @Override
-    int getOutputSizeForFinal(int inputLen) {
-        return bufCount + inputLen
-                + (isEncrypting() ? NativeCrypto.EVP_AEAD_max_overhead(evpAead) : 0);
-    }
-
     // Intentionally missing Override to compile on old versions of Android
     @SuppressWarnings("MissingOverride")
     protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
@@ -430,3 +470,4 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
     abstract long getEVP_AEAD(int keyLength) throws InvalidKeyException;
 
 }
+
diff --git a/common/src/main/java/org/conscrypt/OpenSSLCipher.java b/common/src/main/java/org/conscrypt/OpenSSLCipher.java
index 3e398480..005a64ae 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLCipher.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLCipher.java
@@ -151,16 +151,6 @@ public abstract class OpenSSLCipher extends CipherSpi {
     abstract int updateInternal(byte[] input, int inputOffset, int inputLen,
             byte[] output, int outputOffset, int maximumLen) throws ShortBufferException;
 
-    /**
-     * API-specific implementation of the final block. The {@code maximumLen}
-     * will be the maximum length of the possible output as returned by
-     * {@link #getOutputSizeForFinal(int)}. The return value must be the number
-     * of bytes processed and placed into {@code output}. On error, an exception
-     * must be thrown.
-     */
-    abstract int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
-            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException;
-
     /**
      * Returns the standard name for the particular algorithm.
      */
@@ -349,64 +339,6 @@ public abstract class OpenSSLCipher extends CipherSpi {
         return updateInternal(input, inputOffset, inputLen, output, outputOffset, maximumLen);
     }
 
-    @Override
-    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
-            throws IllegalBlockSizeException, BadPaddingException {
-        final int maximumLen = getOutputSizeForFinal(inputLen);
-        /* Assume that we'll output exactly on a byte boundary. */
-        final byte[] output = new byte[maximumLen];
-
-        int bytesWritten;
-        if (inputLen > 0) {
-            try {
-                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
-            } catch (ShortBufferException e) {
-                /* This should not happen since we sized our own buffer. */
-                throw new RuntimeException("our calculated buffer was too small", e);
-            }
-        } else {
-            bytesWritten = 0;
-        }
-
-        try {
-            bytesWritten += doFinalInternal(output, bytesWritten, maximumLen - bytesWritten);
-        } catch (ShortBufferException e) {
-            /* This should not happen since we sized our own buffer. */
-            throw new RuntimeException("our calculated buffer was too small", e);
-        }
-
-        if (bytesWritten == output.length) {
-            return output;
-        } else if (bytesWritten == 0) {
-            return EmptyArray.BYTE;
-        } else {
-            return Arrays.copyOfRange(output, 0, bytesWritten);
-        }
-    }
-
-    @Override
-    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
-            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
-            BadPaddingException {
-        if (output == null) {
-            throw new NullPointerException("output == null");
-        }
-
-        int maximumLen = getOutputSizeForFinal(inputLen);
-
-        final int bytesWritten;
-        if (inputLen > 0) {
-            bytesWritten = updateInternal(input, inputOffset, inputLen, output, outputOffset,
-                    maximumLen);
-            outputOffset += bytesWritten;
-            maximumLen -= bytesWritten;
-        } else {
-            bytesWritten = 0;
-        }
-
-        return bytesWritten + doFinalInternal(output, outputOffset, maximumLen);
-    }
-
     @Override
     protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
         try {
diff --git a/common/src/main/java/org/conscrypt/OpenSSLCipherChaCha20.java b/common/src/main/java/org/conscrypt/OpenSSLCipherChaCha20.java
index ddbd1700..22bbe60c 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLCipherChaCha20.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLCipherChaCha20.java
@@ -21,6 +21,9 @@ import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.SecureRandom;
 import java.security.spec.AlgorithmParameterSpec;
+import java.util.Arrays;
+import javax.crypto.BadPaddingException;
+import javax.crypto.IllegalBlockSizeException;
 import javax.crypto.NoSuchPaddingException;
 import javax.crypto.ShortBufferException;
 import javax.crypto.spec.IvParameterSpec;
@@ -101,9 +104,58 @@ public class OpenSSLCipherChaCha20 extends OpenSSLCipher {
     }
 
     @Override
-    int doFinalInternal(byte[] output, int outputOffset, int maximumLen) {
+    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
+            throws IllegalBlockSizeException, BadPaddingException {
+        final int maximumLen = getOutputSizeForFinal(inputLen);
+        /* Assume that we'll output exactly on a byte boundary. */
+        final byte[] output = new byte[maximumLen];
+
+        int bytesWritten;
+        if (inputLen > 0) {
+            try {
+                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
+            } catch (ShortBufferException e) {
+                /* This should not happen since we sized our own buffer. */
+                throw new RuntimeException("our calculated buffer was too small", e);
+            }
+        } else {
+            bytesWritten = 0;
+        }
+
         reset();
-        return 0;
+
+        if (bytesWritten == output.length) {
+            return output;
+        } else if (bytesWritten == 0) {
+            return EmptyArray.BYTE;
+        } else {
+            return Arrays.copyOfRange(output, 0, bytesWritten);
+        }
+    }
+
+    @Override
+    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
+            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
+            BadPaddingException {
+        if (output == null) {
+            throw new NullPointerException("output == null");
+        }
+
+        int maximumLen = getOutputSizeForFinal(inputLen);
+
+        final int bytesWritten;
+        if (inputLen > 0) {
+            bytesWritten = updateInternal(input, inputOffset, inputLen, output, outputOffset,
+                    maximumLen);
+            outputOffset += bytesWritten;
+            maximumLen -= bytesWritten;
+        } else {
+            bytesWritten = 0;
+        }
+
+        reset();
+
+        return bytesWritten;
     }
 
     private void reset() {
diff --git a/common/src/main/java/org/conscrypt/OpenSSLEvpCipher.java b/common/src/main/java/org/conscrypt/OpenSSLEvpCipher.java
index f5271271..b53efe83 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLEvpCipher.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLEvpCipher.java
@@ -20,6 +20,7 @@ import java.security.InvalidAlgorithmParameterException;
 import java.security.InvalidKeyException;
 import java.security.SecureRandom;
 import java.security.spec.AlgorithmParameterSpec;
+import java.util.Arrays;
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.crypto.ShortBufferException;
@@ -127,7 +128,6 @@ public abstract class OpenSSLEvpCipher extends OpenSSLCipher {
         return outputOffset - intialOutputOffset;
     }
 
-    @Override
     int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
             throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
         /* Remember this so we can tell how many characters were written. */
@@ -163,6 +163,64 @@ public abstract class OpenSSLEvpCipher extends OpenSSLCipher {
         return outputOffset - initialOutputOffset;
     }
 
+    @Override
+    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
+            throws IllegalBlockSizeException, BadPaddingException {
+        final int maximumLen = getOutputSizeForFinal(inputLen);
+        /* Assume that we'll output exactly on a byte boundary. */
+        final byte[] output = new byte[maximumLen];
+
+        int bytesWritten;
+        if (inputLen > 0) {
+            try {
+                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
+            } catch (ShortBufferException e) {
+                /* This should not happen since we sized our own buffer. */
+                throw new RuntimeException("our calculated buffer was too small", e);
+            }
+        } else {
+            bytesWritten = 0;
+        }
+
+        try {
+            bytesWritten += doFinalInternal(output, bytesWritten, maximumLen - bytesWritten);
+        } catch (ShortBufferException e) {
+            /* This should not happen since we sized our own buffer. */
+            throw new RuntimeException("our calculated buffer was too small", e);
+        }
+
+        if (bytesWritten == output.length) {
+            return output;
+        } else if (bytesWritten == 0) {
+            return EmptyArray.BYTE;
+        } else {
+            return Arrays.copyOfRange(output, 0, bytesWritten);
+        }
+    }
+
+    @Override
+    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
+            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
+            BadPaddingException {
+        if (output == null) {
+            throw new NullPointerException("output == null");
+        }
+
+        int maximumLen = getOutputSizeForFinal(inputLen);
+
+        final int bytesWritten;
+        if (inputLen > 0) {
+            bytesWritten = updateInternal(input, inputOffset, inputLen, output, outputOffset,
+                    maximumLen);
+            outputOffset += bytesWritten;
+            maximumLen -= bytesWritten;
+        } else {
+            bytesWritten = 0;
+        }
+
+        return bytesWritten + doFinalInternal(output, outputOffset, maximumLen);
+    }
+
     @Override
     int getOutputSizeForFinal(int inputLen) {
         if (modeBlockSize == 1) {
diff --git a/common/src/main/java/org/conscrypt/OpenSSLProvider.java b/common/src/main/java/org/conscrypt/OpenSSLProvider.java
index 00f545af..6ae6d8c4 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLProvider.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLProvider.java
@@ -530,13 +530,38 @@ public final class OpenSSLProvider extends Provider {
         put("CertificateFactory.X509", PREFIX + "OpenSSLX509CertificateFactory");
         put("Alg.Alias.CertificateFactory.X.509", "X509");
 
-        /* === HPKE - Conscrypt internal only === */
+        /* === HPKE === */
+        String baseClass = classExists("android.crypto.hpke.HpkeSpi")
+                ? PREFIX + "AndroidHpkeSpi"
+                : PREFIX + "HpkeImpl";
+
         put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
-            PREFIX + "HpkeImpl$X25519_AES_128");
+                baseClass + "$X25519_AES_128");
+        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
+                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM");
         put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
-            PREFIX + "HpkeImpl$X25519_AES_256");
+                baseClass + "$X25519_AES_256");
+        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
+                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM");
         put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305",
-            PREFIX + "HpkeImpl$X25519_CHACHA20");
+                baseClass + "$X25519_CHACHA20");
+        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_GhpkeCHACHA20POLY1305",
+                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305");
+
+        /* === PAKE === */
+        if (Platform.isPakeSupported()) {
+            put("TrustManagerFactory.PAKE", PREFIX + "PakeTrustManagerFactory");
+            put("KeyManagerFactory.PAKE", PREFIX + "PakeKeyManagerFactory");
+        }
+    }
+
+    private boolean classExists(String classname) {
+        try {
+            Class.forName(classname);
+        } catch (ClassNotFoundException e) {
+            return false;
+        }
+        return true;
     }
 
     private void putMacImplClass(String algorithm, String className) {
diff --git a/common/src/main/java/org/conscrypt/SSLParametersImpl.java b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
index abb09e9c..e6605a17 100644
--- a/common/src/main/java/org/conscrypt/SSLParametersImpl.java
+++ b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
@@ -69,6 +69,10 @@ final class SSLParametersImpl implements Cloneable {
     private final PSKKeyManager pskKeyManager;
     // source of X.509 certificate based authentication trust decisions or null if not provided
     private final X509TrustManager x509TrustManager;
+    // source of Spake trust or null if not provided
+    private final Spake2PlusTrustManager spake2PlusTrustManager;
+    // source of Spake authentication or null if not provided
+    private final Spake2PlusKeyManager spake2PlusKeyManager;
 
     // protocols enabled for SSL connection
     String[] enabledProtocols;
@@ -125,22 +129,41 @@ final class SSLParametersImpl implements Cloneable {
             throws KeyManagementException {
         this.serverSessionContext = serverSessionContext;
         this.clientSessionContext = clientSessionContext;
-
         // initialize key managers
         if (kms == null) {
             x509KeyManager = getDefaultX509KeyManager();
             // There's no default PSK key manager
             pskKeyManager = null;
+            spake2PlusKeyManager = null;
         } else {
             x509KeyManager = findFirstX509KeyManager(kms);
             pskKeyManager = findFirstPSKKeyManager(kms);
+            spake2PlusKeyManager = findFirstSpake2PlusKeyManager(kms);
+            if (spake2PlusKeyManager != null) {
+                if (x509KeyManager != null || pskKeyManager != null) {
+                    throw new KeyManagementException(
+                            "Spake2PlusManagers should not be set with X509KeyManager,"
+                            + " x509TrustManager or PSKKeyManager");
+                }
+                setUseClientMode(spake2PlusKeyManager.isClient());
+            }
         }
 
         // initialize x509TrustManager
         if (tms == null) {
             x509TrustManager = getDefaultX509TrustManager();
+            spake2PlusTrustManager = null;
         } else {
             x509TrustManager = findFirstX509TrustManager(tms);
+            spake2PlusTrustManager = findFirstSpake2PlusTrustManager(tms);
+            if (spake2PlusTrustManager != null && x509TrustManager != null) {
+                throw new KeyManagementException(
+                        "Spake2PlusTrustManager should not be set with X509TrustManager");
+            }
+        }
+        if ((spake2PlusTrustManager != null) != (spake2PlusKeyManager != null)) {
+            throw new KeyManagementException(
+                    "Spake2PlusTrustManager and Spake2PlusKeyManager should be set together");
         }
 
         // initialize the list of cipher suites and protocols enabled by default
@@ -159,32 +182,38 @@ final class SSLParametersImpl implements Cloneable {
         }
         boolean x509CipherSuitesNeeded = (x509KeyManager != null) || (x509TrustManager != null);
         boolean pskCipherSuitesNeeded = pskKeyManager != null;
-        enabledCipherSuites = getDefaultCipherSuites(
-                x509CipherSuitesNeeded, pskCipherSuitesNeeded);
+        enabledCipherSuites =
+                getDefaultCipherSuites(x509CipherSuitesNeeded, pskCipherSuitesNeeded, isSpake());
 
         // We ignore the SecureRandom passed in by the caller. The native code below
         // directly accesses /dev/urandom, which makes it irrelevant.
+
+        if (isSpake()) {
+            initSpake();
+        }
     }
 
     // Copy constructor for the purposes of changing the final fields
-    @SuppressWarnings("deprecation")  // for PSKKeyManager
+    @SuppressWarnings("deprecation") // for PSKKeyManager
     private SSLParametersImpl(ClientSessionContext clientSessionContext,
-        ServerSessionContext serverSessionContext,
-        X509KeyManager x509KeyManager,
-        PSKKeyManager pskKeyManager,
-        X509TrustManager x509TrustManager,
-        SSLParametersImpl sslParams) {
+            ServerSessionContext serverSessionContext, X509KeyManager x509KeyManager,
+            PSKKeyManager pskKeyManager, X509TrustManager x509TrustManager,
+            Spake2PlusTrustManager spake2PlusTrustManager,
+            Spake2PlusKeyManager spake2PlusKeyManager, SSLParametersImpl sslParams) {
         this.clientSessionContext = clientSessionContext;
         this.serverSessionContext = serverSessionContext;
         this.x509KeyManager = x509KeyManager;
         this.pskKeyManager = pskKeyManager;
         this.x509TrustManager = x509TrustManager;
+        this.spake2PlusKeyManager = spake2PlusKeyManager;
+        this.spake2PlusTrustManager = spake2PlusTrustManager;
 
         this.enabledProtocols =
-            (sslParams.enabledProtocols == null) ? null : sslParams.enabledProtocols.clone();
+                (sslParams.enabledProtocols == null) ? null : sslParams.enabledProtocols.clone();
         this.isEnabledProtocolsFiltered = sslParams.isEnabledProtocolsFiltered;
-        this.enabledCipherSuites =
-            (sslParams.enabledCipherSuites == null) ? null : sslParams.enabledCipherSuites.clone();
+        this.enabledCipherSuites = (sslParams.enabledCipherSuites == null)
+                ? null
+                : sslParams.enabledCipherSuites.clone();
         this.client_mode = sslParams.client_mode;
         this.need_client_auth = sslParams.need_client_auth;
         this.want_client_auth = sslParams.want_client_auth;
@@ -193,17 +222,29 @@ final class SSLParametersImpl implements Cloneable {
         this.useCipherSuitesOrder = sslParams.useCipherSuitesOrder;
         this.ctVerificationEnabled = sslParams.ctVerificationEnabled;
         this.sctExtension =
-            (sslParams.sctExtension == null) ? null : sslParams.sctExtension.clone();
+                (sslParams.sctExtension == null) ? null : sslParams.sctExtension.clone();
         this.ocspResponse =
-            (sslParams.ocspResponse == null) ? null : sslParams.ocspResponse.clone();
-        this.applicationProtocols =
-            (sslParams.applicationProtocols == null) ? null : sslParams.applicationProtocols.clone();
+                (sslParams.ocspResponse == null) ? null : sslParams.ocspResponse.clone();
+        this.applicationProtocols = (sslParams.applicationProtocols == null)
+                ? null
+                : sslParams.applicationProtocols.clone();
         this.applicationProtocolSelector = sslParams.applicationProtocolSelector;
         this.useSessionTickets = sslParams.useSessionTickets;
         this.useSni = sslParams.useSni;
         this.channelIdEnabled = sslParams.channelIdEnabled;
     }
 
+    /**
+     * Initializes the SSL credential for the Spake.
+     */
+    void initSpake() throws KeyManagementException {
+        try {
+            getSessionContext().initSpake(this);
+        } catch (Exception e) {
+            throw new KeyManagementException("Spake initialization failed " + e.getMessage());
+        }
+    }
+
     static SSLParametersImpl getDefault() throws KeyManagementException {
         SSLParametersImpl result = defaultParameters;
         if (result == null) {
@@ -232,6 +273,13 @@ final class SSLParametersImpl implements Cloneable {
         return clientSessionContext;
     }
 
+    /*
+     * Returns the server session context.
+     */
+    ServerSessionContext getServerSessionContext() {
+        return serverSessionContext;
+    }
+
     /**
      * Returns X.509 key manager or null for none.
      */
@@ -247,6 +295,13 @@ final class SSLParametersImpl implements Cloneable {
         return pskKeyManager;
     }
 
+    /*
+     * Returns Spake key manager or null for none.
+     */
+    Spake2PlusKeyManager getSpake2PlusKeyManager() {
+        return spake2PlusKeyManager;
+    }
+
     /*
      * Returns X.509 trust manager or null for none.
      */
@@ -497,7 +552,8 @@ final class SSLParametersImpl implements Cloneable {
      * For abstracting the X509KeyManager calls between
      * X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)
      * and
-     * X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[], javax.net.ssl.SSLEngine)
+     * X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[],
+     * javax.net.ssl.SSLEngine)
      */
     interface AliasChooser {
         String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
@@ -531,8 +587,13 @@ final class SSLParametersImpl implements Cloneable {
     }
 
     SSLParametersImpl cloneWithTrustManager(X509TrustManager newTrustManager) {
-        return new SSLParametersImpl(clientSessionContext, serverSessionContext,
-            x509KeyManager, pskKeyManager, newTrustManager, this);
+        return new SSLParametersImpl(clientSessionContext, serverSessionContext, x509KeyManager,
+                pskKeyManager, newTrustManager, null, null, this);
+    }
+
+    SSLParametersImpl cloneWithSpake() {
+        return new SSLParametersImpl(clientSessionContext, serverSessionContext, null, null, null,
+                spake2PlusTrustManager, spake2PlusKeyManager, this);
     }
 
     private static X509KeyManager getDefaultX509KeyManager() throws KeyManagementException {
@@ -595,11 +656,22 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
+    /*
+     * Returns the first Spake2PlusKeyManager element in the provided array.
+     */
+    private static Spake2PlusKeyManager findFirstSpake2PlusKeyManager(KeyManager[] kms) {
+        for (KeyManager km : kms) {
+            if (km instanceof Spake2PlusKeyManager) {
+                return (Spake2PlusKeyManager) km;
+            }
+        }
+        return null;
+    }
+
     /*
      * Returns the default X.509 trust manager.
      */
-    static X509TrustManager getDefaultX509TrustManager()
-            throws KeyManagementException {
+    static X509TrustManager getDefaultX509TrustManager() throws KeyManagementException {
         X509TrustManager result = defaultX509TrustManager;
         if (result == null) {
             // single-check idiom
@@ -641,6 +713,18 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
+    /*
+     * Returns the first Spake2PlusTrustManager element in the provided array.
+     */
+    private static Spake2PlusTrustManager findFirstSpake2PlusTrustManager(TrustManager[] tms) {
+        for (TrustManager tm : tms) {
+            if (tm instanceof Spake2PlusTrustManager) {
+                return (Spake2PlusTrustManager) tm;
+            }
+        }
+        return null;
+    }
+
     String getEndpointIdentificationAlgorithm() {
         return endpointIdentificationAlgorithm;
     }
@@ -676,9 +760,8 @@ final class SSLParametersImpl implements Cloneable {
         this.useCipherSuitesOrder = useCipherSuitesOrder;
     }
 
-    private static String[] getDefaultCipherSuites(
-            boolean x509CipherSuitesNeeded,
-            boolean pskCipherSuitesNeeded) {
+    private static String[] getDefaultCipherSuites(boolean x509CipherSuitesNeeded,
+            boolean pskCipherSuitesNeeded, boolean spake2PlusCipherSuitesNeeded) {
         if (x509CipherSuitesNeeded) {
             // X.509 based cipher suites need to be listed.
             if (pskCipherSuitesNeeded) {
@@ -723,4 +806,8 @@ final class SSLParametersImpl implements Cloneable {
         }
         return Platform.isCTVerificationRequired(hostname);
     }
+
+    boolean isSpake() {
+        return spake2PlusKeyManager != null;
+    }
 }
diff --git a/common/src/main/java/org/conscrypt/Spake2PlusKeyManager.java b/common/src/main/java/org/conscrypt/Spake2PlusKeyManager.java
new file mode 100644
index 00000000..5bc2dd15
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/Spake2PlusKeyManager.java
@@ -0,0 +1,80 @@
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
+package org.conscrypt;
+
+import java.security.Principal;
+import java.util.List;
+
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.SSLEngine;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class Spake2PlusKeyManager implements KeyManager {
+    private final byte[] context;
+    private final byte[] password;
+    private final byte[] idProver;
+    private final byte[] idVerifier;
+    private final boolean isClient;
+    private final int handshakeLimit;
+
+    Spake2PlusKeyManager(byte[] context, byte[] password, byte[] idProver,
+            byte[] idVerifier, boolean isClient, int handshakeLimit) {
+        this.context = context == null ? new byte[0] : context;
+        this.password = password;
+        this.idProver = idProver == null ? new byte[0] : idProver;
+        this.idVerifier = idVerifier == null ? new byte[0] : idVerifier;
+        this.isClient = isClient;
+        this.handshakeLimit = handshakeLimit;
+    }
+
+    public String chooseEngineAlias(String keyType, Principal[] issuers,
+            SSLEngine engine) {
+        throw new UnsupportedOperationException("Not implemented");
+    }
+
+    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
+            SSLEngine engine) {
+        throw new UnsupportedOperationException("Not implemented");
+    }
+
+    public byte[] getContext() {
+        return context;
+    }
+
+    public byte[] getPassword() {
+        return password;
+    }
+
+    public byte[] getIdProver() {
+        return idProver;
+    }
+
+    public byte[] getIdVerifier() {
+        return idVerifier;
+    }
+
+    public boolean isClient() {
+        return isClient;
+    }
+
+    public int getHandshakeLimit() {
+        return handshakeLimit;
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/Spake2PlusTrustManager.java b/common/src/main/java/org/conscrypt/Spake2PlusTrustManager.java
new file mode 100644
index 00000000..9ef29c1a
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/Spake2PlusTrustManager.java
@@ -0,0 +1,32 @@
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
+package org.conscrypt;
+
+import javax.net.ssl.TrustManager;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class Spake2PlusTrustManager implements TrustManager {
+    Spake2PlusTrustManager() {}
+
+    public void checkClientTrusted() {}
+
+    public void checkServerTrusted() {}
+}
+
diff --git a/common/src/main/java/org/conscrypt/TrustManagerImpl.java b/common/src/main/java/org/conscrypt/TrustManagerImpl.java
index 24b63ab9..0bb60414 100644
--- a/common/src/main/java/org/conscrypt/TrustManagerImpl.java
+++ b/common/src/main/java/org/conscrypt/TrustManagerImpl.java
@@ -34,12 +34,6 @@
 
 package org.conscrypt;
 
-import org.conscrypt.ct.LogStore;
-import org.conscrypt.ct.Policy;
-import org.conscrypt.ct.PolicyCompliance;
-import org.conscrypt.ct.VerificationResult;
-import org.conscrypt.ct.Verifier;
-
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.net.Socket;
@@ -141,15 +135,10 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private final Exception err;
     private final CertificateFactory factory;
     private final CertBlocklist blocklist;
-    private final LogStore ctLogStore;
-    private Verifier ctVerifier;
-    private Policy ctPolicy;
+    private final org.conscrypt.ct.CertificateTransparency ct;
 
     private ConscryptHostnameVerifier hostnameVerifier;
 
-    // Forces CT verification to always to done. For tests.
-    private boolean ctEnabledOverride;
-
     /**
      * Creates X509TrustManager based on a keystore
      */
@@ -157,25 +146,21 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this(keyStore, null);
     }
 
+    /* Implicitly used by CertPinManagerTest in CTS.
+     * TODO: remove in favor of the constructor below.
+     */
     public TrustManagerImpl(KeyStore keyStore, CertPinManager manager) {
         this(keyStore, manager, null);
     }
 
     public TrustManagerImpl(KeyStore keyStore, CertPinManager manager,
             ConscryptCertStore certStore) {
-        this(keyStore, manager, certStore, null);
+        this(keyStore, manager, certStore, null, null);
     }
 
-    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
-            CertBlocklist blocklist) {
-        this(keyStore, manager, certStore, blocklist, null, null, null);
-    }
-
-    /**
-     * For testing only.
-     */
-    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
-            CertBlocklist blocklist, LogStore ctLogStore, Verifier ctVerifier, Policy ctPolicy) {
+    private TrustManagerImpl(KeyStore keyStore, CertPinManager manager,
+            ConscryptCertStore certStore, CertBlocklist blocklist,
+            org.conscrypt.ct.CertificateTransparency ct) {
         CertPathValidator validatorLocal = null;
         CertificateFactory factoryLocal = null;
         KeyStore rootKeyStoreLocal = null;
@@ -205,16 +190,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
             errLocal = e;
         }
 
+        if (ct == null) {
+            ct = Platform.newDefaultCertificateTransparency();
+        }
         if (blocklist == null) {
             blocklist = Platform.newDefaultBlocklist();
         }
-        if (ctLogStore == null) {
-            ctLogStore = Platform.newDefaultLogStore();
-        }
-
-        if (ctPolicy == null) {
-            ctPolicy = Platform.newDefaultPolicy();
-        }
 
         this.pinManager = manager;
         this.rootKeyStore = rootKeyStoreLocal;
@@ -226,12 +207,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this.acceptedIssuers = acceptedIssuersLocal;
         this.err = errLocal;
         this.blocklist = blocklist;
-        this.ctLogStore = ctLogStore;
-        this.ctVerifier = new Verifier(ctLogStore);
-        this.ctPolicy = ctPolicy;
-        if (ctLogStore != null) {
-            ctLogStore.setPolicy(ctPolicy);
-        }
+        this.ct = ct;
     }
 
     @SuppressWarnings("JdkObsolete")  // KeyStore#aliases is the only API available
@@ -687,11 +663,9 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                 checkBlocklist(cert);
             }
 
-            // Check CT (if required).
-            if (!clientAuth &&
-                    (ctEnabledOverride || (host != null && Platform
-                            .isCTVerificationRequired(host)))) {
-                checkCT(wholeChain, ocspData, tlsSctData);
+            // Check Certificate Transparency (if required).
+            if (!clientAuth && host != null && ct != null && ct.isCTVerificationRequired(host)) {
+                ct.checkCT(wholeChain, ocspData, tlsSctData, host);
             }
 
             if (untrustedChain.isEmpty()) {
@@ -737,26 +711,6 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
     }
 
-    private void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
-            throws CertificateException {
-        if (ctLogStore.getState() != LogStore.State.COMPLIANT) {
-            /* Fail open. For some reason, the LogStore is not usable. It could
-             * be because there is no log list available or that the log list
-             * is too old (according to the policy). */
-            return;
-        }
-        VerificationResult result =
-                ctVerifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);
-
-        X509Certificate leaf = chain.get(0);
-        PolicyCompliance compliance = ctPolicy.doesResultConformToPolicy(result, leaf);
-        if (compliance != PolicyCompliance.COMPLY) {
-            throw new CertificateException(
-                    "Certificate chain does not conform to required transparency policy: "
-                    + compliance.name());
-        }
-    }
-
     /**
      * Sets the OCSP response data that was possibly stapled to the TLS response.
      */
@@ -1038,18 +992,4 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
         return Platform.getDefaultHostnameVerifier();
     }
-
-    public void setCTEnabledOverride(boolean enabled) {
-        this.ctEnabledOverride = enabled;
-    }
-
-    // Replace the CTVerifier. For testing only.
-    public void setCTVerifier(Verifier verifier) {
-        this.ctVerifier = verifier;
-    }
-
-    // Replace the CTPolicy. For testing only.
-    public void setCTPolicy(Policy policy) {
-        this.ctPolicy = policy;
-    }
 }
diff --git a/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java b/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java
new file mode 100644
index 00000000..75499a82
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/ct/CertificateTransparency.java
@@ -0,0 +1,85 @@
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
+import org.conscrypt.Internal;
+import org.conscrypt.Platform;
+import org.conscrypt.metrics.CertificateTransparencyVerificationReason;
+import org.conscrypt.metrics.StatsLog;
+
+import java.security.cert.CertificateException;
+import java.security.cert.X509Certificate;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * Certificate Transparency subsystem. The implementation contains references
+ * to its log store, its policy and its verifier.
+ */
+@Internal
+public class CertificateTransparency {
+    private LogStore logStore;
+    private Verifier verifier;
+    private Policy policy;
+    private StatsLog statsLog;
+
+    public CertificateTransparency(
+            LogStore logStore, Policy policy, Verifier verifier, StatsLog statsLog) {
+        Objects.requireNonNull(logStore);
+        Objects.requireNonNull(policy);
+        Objects.requireNonNull(verifier);
+        Objects.requireNonNull(statsLog);
+
+        this.logStore = logStore;
+        this.policy = policy;
+        this.verifier = verifier;
+        this.statsLog = statsLog;
+    }
+
+    public boolean isCTVerificationRequired(String host) {
+        return Platform.isCTVerificationRequired(host);
+    }
+
+    public CertificateTransparencyVerificationReason reasonCTVerificationRequired(String host) {
+        return Platform.reasonCTVerificationRequired(host);
+    }
+
+    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
+            throws CertificateException {
+        if (logStore.getState() != LogStore.State.COMPLIANT) {
+            /* Fail open. For some reason, the LogStore is not usable. It could
+             * be because there is no log list available or that the log list
+             * is too old (according to the policy). */
+            statsLog.reportCTVerificationResult(logStore,
+                    /* VerificationResult */ null,
+                    /* PolicyCompliance */ null, reasonCTVerificationRequired(host));
+            return;
+        }
+        VerificationResult result =
+                verifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);
+
+        X509Certificate leaf = chain.get(0);
+        PolicyCompliance compliance = policy.doesResultConformToPolicy(result, leaf);
+        statsLog.reportCTVerificationResult(
+                logStore, result, compliance, reasonCTVerificationRequired(host));
+        if (compliance != PolicyCompliance.COMPLY) {
+            throw new CertificateException(
+                    "Certificate chain does not conform to required transparency policy: "
+                    + compliance.name());
+        }
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/ct/LogInfo.java b/common/src/main/java/org/conscrypt/ct/LogInfo.java
index 99c8139d..9225ac4d 100644
--- a/common/src/main/java/org/conscrypt/ct/LogInfo.java
+++ b/common/src/main/java/org/conscrypt/ct/LogInfo.java
@@ -41,13 +41,17 @@ public class LogInfo {
     public static final int STATE_RETIRED = 5;
     public static final int STATE_REJECTED = 6;
 
+    public static final int TYPE_UNKNOWN = 0;
+    public static final int TYPE_RFC6962 = 1;
+    public static final int TYPE_STATIC_CT_API = 2;
+
     private final byte[] logId;
     private final PublicKey publicKey;
     private final int state;
     private final long stateTimestamp;
     private final String description;
-    private final String url;
     private final String operator;
+    private final int type;
 
     private LogInfo(Builder builder) {
         /* Based on the required fields for the log list schema v3. Notably,
@@ -55,7 +59,6 @@ public class LogInfo {
          * is validated in the builder. */
         Objects.requireNonNull(builder.logId);
         Objects.requireNonNull(builder.publicKey);
-        Objects.requireNonNull(builder.url);
         Objects.requireNonNull(builder.operator);
 
         this.logId = builder.logId;
@@ -63,8 +66,8 @@ public class LogInfo {
         this.state = builder.state;
         this.stateTimestamp = builder.stateTimestamp;
         this.description = builder.description;
-        this.url = builder.url;
         this.operator = builder.operator;
+        this.type = builder.type;
     }
 
     public static class Builder {
@@ -73,8 +76,8 @@ public class LogInfo {
         private int state;
         private long stateTimestamp;
         private String description;
-        private String url;
         private String operator;
+        private int type;
 
         public Builder setPublicKey(PublicKey publicKey) {
             Objects.requireNonNull(publicKey);
@@ -103,18 +106,20 @@ public class LogInfo {
             return this;
         }
 
-        public Builder setUrl(String url) {
-            Objects.requireNonNull(url);
-            this.url = url;
-            return this;
-        }
-
         public Builder setOperator(String operator) {
             Objects.requireNonNull(operator);
             this.operator = operator;
             return this;
         }
 
+        public Builder setType(int type) {
+            if (type < 0 || type > TYPE_STATIC_CT_API) {
+                throw new IllegalArgumentException("invalid type value");
+            }
+            this.type = type;
+            return this;
+        }
+
         public LogInfo build() {
             return new LogInfo(this);
         }
@@ -135,10 +140,6 @@ public class LogInfo {
         return description;
     }
 
-    public String getUrl() {
-        return url;
-    }
-
     public int getState() {
         return state;
     }
@@ -158,6 +159,10 @@ public class LogInfo {
         return operator;
     }
 
+    public int getType() {
+        return type;
+    }
+
     @Override
     public boolean equals(Object other) {
         if (this == other) {
@@ -169,15 +174,14 @@ public class LogInfo {
 
         LogInfo that = (LogInfo) other;
         return this.state == that.state && this.description.equals(that.description)
-                && this.url.equals(that.url) && this.operator.equals(that.operator)
-                && this.stateTimestamp == that.stateTimestamp
-                && Arrays.equals(this.logId, that.logId);
+                && this.operator.equals(that.operator) && this.stateTimestamp == that.stateTimestamp
+                && this.type == that.type && Arrays.equals(this.logId, that.logId);
     }
 
     @Override
     public int hashCode() {
         return Objects.hash(
-                Arrays.hashCode(logId), description, url, state, stateTimestamp, operator);
+                Arrays.hashCode(logId), description, state, stateTimestamp, operator, type);
     }
 
     /**
diff --git a/common/src/main/java/org/conscrypt/ct/LogStore.java b/common/src/main/java/org/conscrypt/ct/LogStore.java
index 70208ad8..1e614dc9 100644
--- a/common/src/main/java/org/conscrypt/ct/LogStore.java
+++ b/common/src/main/java/org/conscrypt/ct/LogStore.java
@@ -29,8 +29,6 @@ public interface LogStore {
         NON_COMPLIANT,
     }
 
-    void setPolicy(Policy policy);
-
     State getState();
 
     int getMajorVersion();
diff --git a/common/src/main/java/org/conscrypt/ct/PolicyCompliance.java b/common/src/main/java/org/conscrypt/ct/PolicyCompliance.java
index d889ee75..7fa48f5a 100644
--- a/common/src/main/java/org/conscrypt/ct/PolicyCompliance.java
+++ b/common/src/main/java/org/conscrypt/ct/PolicyCompliance.java
@@ -22,5 +22,6 @@ import org.conscrypt.Internal;
 public enum PolicyCompliance {
     COMPLY,
     NOT_ENOUGH_SCTS,
-    NOT_ENOUGH_DIVERSE_SCTS
+    NOT_ENOUGH_DIVERSE_SCTS,
+    NO_RFC6962_LOG
 }
diff --git a/common/src/main/java/org/conscrypt/ct/VerificationResult.java b/common/src/main/java/org/conscrypt/ct/VerificationResult.java
index 354b16a5..3187e3db 100644
--- a/common/src/main/java/org/conscrypt/ct/VerificationResult.java
+++ b/common/src/main/java/org/conscrypt/ct/VerificationResult.java
@@ -16,10 +16,12 @@
 
 package org.conscrypt.ct;
 
+import org.conscrypt.Internal;
+
 import java.util.ArrayList;
 import java.util.Collections;
+import java.util.EnumMap;
 import java.util.List;
-import org.conscrypt.Internal;
 
 /**
  * Container for verified SignedCertificateTimestamp.
@@ -31,8 +33,10 @@ import org.conscrypt.Internal;
  */
 @Internal
 public class VerificationResult {
-    private final ArrayList<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>();
-    private final ArrayList<VerifiedSCT> invalidSCTs = new ArrayList<VerifiedSCT>();
+    private final List<VerifiedSCT> validSCTs = new ArrayList<>();
+    private final List<VerifiedSCT> invalidSCTs = new ArrayList<>();
+    private final EnumMap<SignedCertificateTimestamp.Origin, Integer> count =
+            new EnumMap<>(SignedCertificateTimestamp.Origin.class);
 
     public void add(VerifiedSCT result) {
         if (result.isValid()) {
@@ -40,6 +44,13 @@ public class VerificationResult {
         } else {
             invalidSCTs.add(result);
         }
+        SignedCertificateTimestamp.Origin origin = result.getSct().getOrigin();
+        Integer value = count.get(origin);
+        if (value == null) {
+            count.put(origin, 1);
+        } else {
+            count.put(origin, value + 1);
+        }
     }
 
     public List<VerifiedSCT> getValidSCTs() {
@@ -49,4 +60,18 @@ public class VerificationResult {
     public List<VerifiedSCT> getInvalidSCTs() {
         return Collections.unmodifiableList(invalidSCTs);
     }
+
+    public int numCertSCTs() {
+        Integer num = count.get(SignedCertificateTimestamp.Origin.EMBEDDED);
+        return (num == null ? 0 : num.intValue());
+    }
+
+    public int numOCSPSCTs() {
+        Integer num = count.get(SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
+        return (num == null ? 0 : num.intValue());
+    }
+    public int numTlsSCTs() {
+        Integer num = count.get(SignedCertificateTimestamp.Origin.TLS_EXTENSION);
+        return (num == null ? 0 : num.intValue());
+    }
 }
diff --git a/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java b/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
new file mode 100644
index 00000000..0c7fab7a
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
@@ -0,0 +1,44 @@
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
+package org.conscrypt.metrics;
+
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN;
+
+import org.conscrypt.Internal;
+
+/**
+ * Certificate Transparency Verification Reason.
+ */
+@Internal
+public enum CertificateTransparencyVerificationReason {
+    UNKNOWN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN),
+    APP_OPT_IN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN),
+    DOMAIN_OPT_IN(
+            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN);
+
+    final int id;
+
+    public int getId() {
+        return this.id;
+    }
+
+    private CertificateTransparencyVerificationReason(int id) {
+        this.id = id;
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java b/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
new file mode 100644
index 00000000..a94a4e76
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
@@ -0,0 +1,244 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+package org.conscrypt.metrics;
+
+import org.conscrypt.Internal;
+
+/**
+ * Reimplement with reflection calls the logging class,
+ * generated by frameworks/statsd.
+ * <p>
+ * In case an atom is updated, generate the new wrapper with stats-log-api-gen
+ * tool as shown below and update the write methods to use ReflexiveStatsEvent
+ * and ReflexiveStatsLog.
+ * <p>
+ * $ stats-log-api-gen \
+ *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
+ *   --module conscrypt \
+ *   --javaPackage org.conscrypt.metrics \
+ *   --javaClass ConscryptStatsLog
+ * <p>
+ * This class is swapped with the generated wrapper for GMSCore. For this
+ * reason, the methods defined here should be identical to the generated
+ * methods from the wrapper. Do not add new method here, do not change the type
+ * of the parameters.
+ **/
+@Internal
+public final class ConscryptStatsLog {
+    // clang-format off
+
+    // Constants for atom codes.
+
+    /**
+     * TlsHandshakeReported tls_handshake_reported<br>
+     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
+     */
+    public static final int TLS_HANDSHAKE_REPORTED = 317;
+
+    /**
+     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed<br>
+     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status, int loaded_compat_version, int min_compat_version, int major_version, int minor_version);<br>
+     */
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
+
+    /**
+     * ConscryptServiceUsed conscrypt_service_used<br>
+     * Usage: StatsLog.write(StatsLog.CONSCRYPT_SERVICE_USED, int algorithm, int cipher, int mode, int padding);<br>
+     */
+    public static final int CONSCRYPT_SERVICE_USED = 965;
+
+    /**
+     * CertificateTransparencyVerificationReported certificate_transparency_verification_reported<br>
+     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, int result, int reason, int policy_compatibility_version, int major_version, int minor_version, int num_cert_scts, int num_ocsp_scts, int num_tls_scts);<br>
+     */
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED = 989;
+
+    // Constants for enum values.
+
+    // Values for TlsHandshakeReported.protocol
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__UNKNOWN_PROTO = 0;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__SSL_V3 = 1;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1 = 2;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_1 = 3;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_2 = 4;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_3 = 5;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_PROTO_FAILED = 65535;
+
+    // Values for TlsHandshakeReported.cipher_suite
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__UNKNOWN_CIPHER_SUITE = 0;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_128_CBC_SHA = 47;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_256_CBC_SHA = 53;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_PSK_WITH_AES_128_CBC_SHA = 140;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_PSK_WITH_AES_256_CBC_SHA = 141;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_128_GCM_SHA256 = 156;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_256_GCM_SHA384 = 157;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_AES_128_GCM_SHA256 = 4865;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_AES_256_GCM_SHA384 = 4866;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_CHACHA20_POLY1305_SHA256 = 4867;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 49161;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 49162;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 49171;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 49172;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 49195;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 49196;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 49199;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 49200;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 49205;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 49206;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 52393;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52396;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_CIPHER_FAILED = 65535;
+
+    // Values for TlsHandshakeReported.source
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN = 0;
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE = 1;
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS = 2;
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED = 3;
+
+    // Values for CertificateTransparencyLogListStateChanged.status
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS = 1;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND = 2;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED = 3;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED = 4;
+
+    // Values for CertificateTransparencyLogListStateChanged.loaded_compat_version
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__LOADED_COMPAT_VERSION__COMPAT_VERSION_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__LOADED_COMPAT_VERSION__COMPAT_VERSION_V1 = 1;
+
+    // Values for CertificateTransparencyLogListStateChanged.min_compat_version
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__MIN_COMPAT_VERSION__COMPAT_VERSION_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__MIN_COMPAT_VERSION__COMPAT_VERSION_V1 = 1;
+
+    // Values for ConscryptServiceUsed.algorithm
+    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__UNKNOWN_ALGORITHM = 0;
+    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__CIPHER = 1;
+    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__SIGNATURE = 2;
+
+    // Values for ConscryptServiceUsed.cipher
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__UNKNOWN_CIPHER = 0;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__AES = 1;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DES = 2;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DESEDE = 3;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DSA = 4;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__BLOWFISH = 5;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__CHACHA20 = 6;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__RSA = 7;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__ARC4 = 8;
+
+    // Values for ConscryptServiceUsed.mode
+    public static final int CONSCRYPT_SERVICE_USED__MODE__NO_MODE = 0;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CBC = 1;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CTR = 2;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__ECB = 3;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CFB = 4;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CTS = 5;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__GCM = 6;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__GCM_SIV = 7;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__OFB = 8;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__POLY1305 = 9;
+
+    // Values for ConscryptServiceUsed.padding
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__NO_PADDING = 0;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA512 = 1;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA384 = 2;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA256 = 3;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA224 = 4;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA1 = 5;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__PKCS1 = 6;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__PKCS5 = 7;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__ISO10126 = 8;
+
+    // Values for CertificateTransparencyVerificationReported.result
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS = 1;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_GENERIC_FAILURE = 2;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND = 3;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT = 4;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE = 5;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT = 6;
+
+    // Values for CertificateTransparencyVerificationReported.reason
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DEVICE_WIDE_ENABLED = 1;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN = 3;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN = 4;
+
+    // Values for CertificateTransparencyVerificationReported.policy_compatibility_version
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_V1 = 1;
+
+    // Write methods
+    public static void write(int code, boolean arg1, int arg2, int arg3, int arg4, int arg5, int[] arg6) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeBoolean(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+        builder.writeInt(arg5);
+        builder.writeIntArray(null == arg6 ? new int[0] : arg6);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    public static void write(int code, int arg1, int arg2, int arg3, int arg4) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeInt(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    public static void write(int code, int arg1, int arg2, int arg3, int arg4, int arg5) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeInt(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+        builder.writeInt(arg5);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    public static void write(int code, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeInt(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+        builder.writeInt(arg5);
+        builder.writeInt(arg6);
+        builder.writeInt(arg7);
+        builder.writeInt(arg8);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    // clang-format on
+}
diff --git a/common/src/main/java/org/conscrypt/metrics/NoopStatsLog.java b/common/src/main/java/org/conscrypt/metrics/NoopStatsLog.java
new file mode 100644
index 00000000..f6befdbb
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/metrics/NoopStatsLog.java
@@ -0,0 +1,37 @@
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
+package org.conscrypt.metrics;
+
+import org.conscrypt.Internal;
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.PolicyCompliance;
+import org.conscrypt.ct.VerificationResult;
+
+@Internal
+public class NoopStatsLog implements StatsLog {
+    private static final StatsLog INSTANCE = new NoopStatsLog();
+    public static StatsLog getInstance() {
+        return INSTANCE;
+    }
+
+    public void countTlsHandshake(
+            boolean success, String protocol, String cipherSuite, long duration) {}
+
+    public void updateCTLogListStatusChanged(LogStore logStore) {}
+
+    public void reportCTVerificationResult(LogStore logStore, VerificationResult result,
+            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason) {}
+}
diff --git a/common/src/main/java/org/conscrypt/metrics/ReflexiveStatsEvent.java b/common/src/main/java/org/conscrypt/metrics/ReflexiveStatsEvent.java
index 1280a310..e5a32d39 100644
--- a/common/src/main/java/org/conscrypt/metrics/ReflexiveStatsEvent.java
+++ b/common/src/main/java/org/conscrypt/metrics/ReflexiveStatsEvent.java
@@ -16,6 +16,7 @@
 package org.conscrypt.metrics;
 
 import org.conscrypt.Internal;
+import org.conscrypt.Platform;
 
 /**
  * Reflection wrapper around android.util.StatsEvent.
@@ -24,14 +25,12 @@ import org.conscrypt.Internal;
 public class ReflexiveStatsEvent {
     private static final OptionalMethod newBuilder;
     private static final Class<?> c_statsEvent;
-    private static final Object sdkVersion;
     private static final boolean sdkVersionBiggerThan32;
 
     static {
-        sdkVersion = getSdkVersion();
         c_statsEvent = initStatsEventClass();
         newBuilder = new OptionalMethod(c_statsEvent, "newBuilder");
-        sdkVersionBiggerThan32 = (sdkVersion != null) && ((int) sdkVersion > 32);
+        sdkVersionBiggerThan32 = Platform.isSdkGreater(32);
     }
 
     private static Class<?> initStatsEventClass() {
@@ -56,6 +55,8 @@ public class ReflexiveStatsEvent {
         return new ReflexiveStatsEvent.Builder();
     }
 
+    /* Used by older CTS test */
+    @Deprecated
     public static ReflexiveStatsEvent buildEvent(int atomId, boolean success, int protocol,
             int cipherSuite, int duration, int source, int[] uids) {
         ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
@@ -65,15 +66,15 @@ public class ReflexiveStatsEvent {
         builder.writeInt(cipherSuite);
         builder.writeInt(duration);
         builder.writeInt(source);
-        if (sdkVersionBiggerThan32) {
-          builder.writeIntArray(uids);
-        }
+        builder.writeIntArray(uids);
         builder.usePooledBuffer();
         return builder.build();
     }
 
-    public static ReflexiveStatsEvent buildEvent(int atomId, boolean success, int protocol,
-            int cipherSuite, int duration, int source) {
+    /* Used by older CTS test */
+    @Deprecated
+    public static ReflexiveStatsEvent buildEvent(
+            int atomId, boolean success, int protocol, int cipherSuite, int duration, int source) {
         ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
         builder.setAtomId(atomId);
         builder.writeBoolean(success);
@@ -85,18 +86,6 @@ public class ReflexiveStatsEvent {
         return builder.build();
     }
 
-
-    static Object getSdkVersion() {
-        try {
-            OptionalMethod getSdkVersion =
-                    new OptionalMethod(Class.forName("dalvik.system.VMRuntime"),
-                                        "getSdkVersion");
-            return getSdkVersion.invokeStatic();
-        } catch (ClassNotFoundException e) {
-            return null;
-        }
-    }
-
     public static final class Builder {
         private static final Class<?> c_statsEvent_Builder;
         private static final OptionalMethod setAtomId;
@@ -150,7 +139,9 @@ public class ReflexiveStatsEvent {
         }
 
         public Builder writeIntArray(final int[] values) {
-            writeIntArray.invoke(this.builder, values);
+            if (sdkVersionBiggerThan32) {
+                writeIntArray.invoke(this.builder, values);
+            }
             return this;
         }
 
@@ -159,4 +150,4 @@ public class ReflexiveStatsEvent {
             return new ReflexiveStatsEvent(statsEvent);
         }
     }
-}
\ No newline at end of file
+}
diff --git a/common/src/main/java/org/conscrypt/metrics/Source.java b/common/src/main/java/org/conscrypt/metrics/Source.java
index 09bf2e42..60ab0f70 100644
--- a/common/src/main/java/org/conscrypt/metrics/Source.java
+++ b/common/src/main/java/org/conscrypt/metrics/Source.java
@@ -15,6 +15,11 @@
  */
 package org.conscrypt.metrics;
 
+import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS;
+import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE;
+import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED;
+import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN;
+
 import org.conscrypt.Internal;
 
 /**
@@ -24,8 +29,18 @@ import org.conscrypt.Internal;
  */
 @Internal
 public enum Source {
-    SOURCE_UNKNOWN,
-    SOURCE_MAINLINE,
-    SOURCE_GMS,
-    SOURCE_UNBUNDLED;
-}
\ No newline at end of file
+    SOURCE_UNKNOWN(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN),
+    SOURCE_MAINLINE(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE),
+    SOURCE_GMS(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS),
+    SOURCE_UNBUNDLED(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED);
+
+    final int id;
+
+    public int getId() {
+        return this.id;
+    }
+
+    private Source(int id) {
+        this.id = id;
+    }
+}
diff --git a/common/src/main/java/org/conscrypt/metrics/StatsLog.java b/common/src/main/java/org/conscrypt/metrics/StatsLog.java
index 81f15d5e..2a4c38cd 100644
--- a/common/src/main/java/org/conscrypt/metrics/StatsLog.java
+++ b/common/src/main/java/org/conscrypt/metrics/StatsLog.java
@@ -17,6 +17,8 @@ package org.conscrypt.metrics;
 
 import org.conscrypt.Internal;
 import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.PolicyCompliance;
+import org.conscrypt.ct.VerificationResult;
 
 @Internal
 public interface StatsLog {
@@ -24,4 +26,7 @@ public interface StatsLog {
             boolean success, String protocol, String cipherSuite, long duration);
 
     public void updateCTLogListStatusChanged(LogStore logStore);
+
+    public void reportCTVerificationResult(LogStore logStore, VerificationResult result,
+            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason);
 }
diff --git a/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java b/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
index a47bac9d..d39d0de0 100644
--- a/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
+++ b/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
@@ -15,9 +15,26 @@
  */
 package org.conscrypt.metrics;
 
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
+import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
+import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED;
+
 import org.conscrypt.Internal;
 import org.conscrypt.Platform;
 import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.PolicyCompliance;
+import org.conscrypt.ct.VerificationResult;
 
 import java.lang.Thread.UncaughtExceptionHandler;
 import java.util.concurrent.ArrayBlockingQueue;
@@ -27,41 +44,12 @@ import java.util.concurrent.ThreadFactory;
 import java.util.concurrent.ThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
 
-/**
- * Reimplement with reflection calls the logging class,
- * generated by frameworks/statsd.
- * <p>
- * In case atom is changed, generate new wrapper with stats-log-api-gen
- * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
- * newEvent() method.
- * <p>
- * $ stats-log-api-gen \
- *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
- *   --module conscrypt \
- *   --javaPackage org.conscrypt.metrics \
- *   --javaClass StatsLog
- **/
 @Internal
 public final class StatsLogImpl implements StatsLog {
-    /**
-     * TlsHandshakeReported tls_handshake_reported
-     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int
-     * cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
-     */
-    public static final int TLS_HANDSHAKE_REPORTED = 317;
-
-    /**
-     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
-     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status,
-     * int loaded_compat_version, int min_compat_version_available, int major_version, int
-     * minor_version);<br>
-     */
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
-
     private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
         @Override
         public Thread newThread(Runnable r) {
-            Thread thread = new Thread(r);
+            Thread thread = new Thread(r, "ConscryptStatsLog");
             thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
                 @Override
                 public void uncaughtException(Thread t, Throwable e) {
@@ -85,33 +73,24 @@ public final class StatsLogImpl implements StatsLog {
         CipherSuite suite = CipherSuite.forName(cipherSuite);
 
         write(TLS_HANDSHAKE_REPORTED, success, proto.getId(), suite.getId(), (int) duration,
-                Platform.getStatsSource().ordinal(), Platform.getUids());
+                Platform.getStatsSource().getId(), Platform.getUids());
     }
 
     private static int logStoreStateToMetricsState(LogStore.State state) {
-        /* These constants must match the atom LogListStatus
-         * from frameworks/proto_logging/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
-         */
-        final int METRIC_UNKNOWN = 0;
-        final int METRIC_SUCCESS = 1;
-        final int METRIC_NOT_FOUND = 2;
-        final int METRIC_PARSING_FAILED = 3;
-        final int METRIC_EXPIRED = 4;
-
         switch (state) {
             case UNINITIALIZED:
             case LOADED:
-                return METRIC_UNKNOWN;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
             case NOT_FOUND:
-                return METRIC_NOT_FOUND;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
             case MALFORMED:
-                return METRIC_PARSING_FAILED;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
             case COMPLIANT:
-                return METRIC_SUCCESS;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
             case NON_COMPLIANT:
-                return METRIC_EXPIRED;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
         }
-        return METRIC_UNKNOWN;
+        return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
     }
 
     @Override
@@ -122,15 +101,47 @@ public final class StatsLogImpl implements StatsLog {
                 logStore.getMinorVersion());
     }
 
+    private static int policyComplianceToMetrics(
+            VerificationResult result, PolicyCompliance compliance) {
+        if (compliance == PolicyCompliance.COMPLY) {
+            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
+        } else if (result.getValidSCTs().size() == 0) {
+            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
+        } else if (compliance == PolicyCompliance.NOT_ENOUGH_SCTS
+                || compliance == PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS
+                || compliance == PolicyCompliance.NO_RFC6962_LOG) {
+            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
+        }
+        return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
+    }
+
+    @Override
+    public void reportCTVerificationResult(LogStore store, VerificationResult result,
+            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason) {
+        if (store.getState() == LogStore.State.NOT_FOUND
+                || store.getState() == LogStore.State.MALFORMED) {
+            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
+                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE,
+                    reason.getId(), 0, 0, 0, 0, 0, 0);
+        } else if (store.getState() == LogStore.State.NON_COMPLIANT) {
+            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
+                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT,
+                    reason.getId(), 0, 0, 0, 0, 0, 0);
+        } else if (store.getState() == LogStore.State.COMPLIANT) {
+            int comp = policyComplianceToMetrics(result, compliance);
+            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, comp, reason.getId(),
+                    store.getCompatVersion(), store.getMajorVersion(), store.getMinorVersion(),
+                    result.numCertSCTs(), result.numOCSPSCTs(), result.numTlsSCTs());
+        }
+    }
+
     private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
             int source, int[] uids) {
         e.execute(new Runnable() {
             @Override
             public void run() {
-                ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
+                ConscryptStatsLog.write(
                         atomId, success, protocol, cipherSuite, duration, source, uids);
-
-                ReflexiveStatsLog.write(event);
             }
         });
     }
@@ -140,15 +151,21 @@ public final class StatsLogImpl implements StatsLog {
         e.execute(new Runnable() {
             @Override
             public void run() {
-                ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
-                builder.setAtomId(atomId);
-                builder.writeInt(status);
-                builder.writeInt(loadedCompatVersion);
-                builder.writeInt(minCompatVersionAvailable);
-                builder.writeInt(majorVersion);
-                builder.writeInt(minorVersion);
-                builder.usePooledBuffer();
-                ReflexiveStatsLog.write(builder.build());
+                ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
+                        minCompatVersionAvailable, majorVersion, minorVersion);
+            }
+        });
+    }
+
+    private void write(int atomId, int verificationResult, int verificationReason,
+            int policyCompatVersion, int majorVersion, int minorVersion, int numEmbeddedScts,
+            int numOcspScts, int numTlsScts) {
+        e.execute(new Runnable() {
+            @Override
+            public void run() {
+                ConscryptStatsLog.write(atomId, verificationResult, verificationReason,
+                        policyCompatVersion, majorVersion, minorVersion, numEmbeddedScts,
+                        numOcspScts, numTlsScts);
             }
         });
     }
diff --git a/common/src/test/java/org/conscrypt/DuckTypedHpkeSpiTest.java b/common/src/test/java/org/conscrypt/DuckTypedHpkeSpiTest.java
index 3d30f9fe..d2a6d70b 100644
--- a/common/src/test/java/org/conscrypt/DuckTypedHpkeSpiTest.java
+++ b/common/src/test/java/org/conscrypt/DuckTypedHpkeSpiTest.java
@@ -248,9 +248,8 @@ public class DuckTypedHpkeSpiTest {
         // Verify the SPI is indeed foreign.
         assertTrue(duckTyped.getDelegate() instanceof HpkeForeignSpi);
 
-        // And that it is delegating to a real HpkeImpl, so we can test it.
-        HpkeForeignSpi foreign = (HpkeForeignSpi) duckTyped.getDelegate();
-        assertTrue(foreign.realSpi instanceof HpkeImpl);
+        // And that it is delegating to a real implementation, so we can test it.
+        assertNotNull(duckTyped.getDelegate());
     }
 
     // Provides HpkeContext instances that use a "foreign" SPI, that is one that isn't
diff --git a/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java b/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java
index 1f032e95..93b88b81 100644
--- a/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java
+++ b/common/src/test/java/org/conscrypt/NativeCryptoArgTest.java
@@ -223,6 +223,18 @@ public class NativeCryptoArgTest {
         expectNPE("X509_print_ex", NULL, NOT_NULL, null, NULL, NULL);
     }
 
+    @Test
+    public void spake2Methods() throws Throwable {
+        expectNPE("SSL_CTX_set_spake_credential",
+                null, new byte[0], new byte[0], new byte[0], false, 1, NOT_NULL, null);
+        expectNPE("SSL_CTX_set_spake_credential",
+                new byte[0], null, new byte[0], new byte[0], false, 1, NOT_NULL, null);
+        expectNPE("SSL_CTX_set_spake_credential",
+                new byte[0], new byte[0], null, new byte[0], false, 1, NOT_NULL, null);
+        expectNPE("SSL_CTX_set_spake_credential",
+                new byte[0], new byte[0], new byte[0], null, false, 1, NOT_NULL, null);
+    }
+
     private void testMethods(MethodFilter filter, Class<? extends Throwable> exceptionClass)
             throws Throwable {
         List<Method> methods = filter.filter(methodMap.values());
diff --git a/common/src/test/java/org/conscrypt/ct/VerifierTest.java b/common/src/test/java/org/conscrypt/ct/VerifierTest.java
index 016da7f2..78fed5b5 100644
--- a/common/src/test/java/org/conscrypt/ct/VerifierTest.java
+++ b/common/src/test/java/org/conscrypt/ct/VerifierTest.java
@@ -52,14 +52,11 @@ public class VerifierTest {
         final LogInfo log = new LogInfo.Builder()
                                     .setPublicKey(key)
                                     .setDescription("Test Log")
-                                    .setUrl("http://example.com")
+                                    .setType(LogInfo.TYPE_RFC6962)
                                     .setOperator("LogOperator")
                                     .setState(LogInfo.STATE_USABLE, 1643709600000L)
                                     .build();
         LogStore store = new LogStore() {
-            @Override
-            public void setPolicy(Policy policy) {}
-
             @Override
             public State getState() {
                 return LogStore.State.COMPLIANT;
diff --git a/common/src/test/java/org/conscrypt/javax/crypto/CipherBasicsTest.java b/common/src/test/java/org/conscrypt/javax/crypto/CipherBasicsTest.java
index 4aef5bb8..8fc873f9 100644
--- a/common/src/test/java/org/conscrypt/javax/crypto/CipherBasicsTest.java
+++ b/common/src/test/java/org/conscrypt/javax/crypto/CipherBasicsTest.java
@@ -22,6 +22,7 @@ import static org.junit.Assert.assertEquals;
 
 import java.nio.ByteBuffer;
 import java.security.AlgorithmParameters;
+import java.security.GeneralSecurityException;
 import java.security.InvalidAlgorithmParameterException;
 import java.security.InvalidKeyException;
 import java.security.Key;
@@ -85,6 +86,118 @@ public final class CipherBasicsTest {
         TestUtils.assumeAllowsUnsignedCrypto();
     }
 
+    private enum CallPattern {
+        DO_FINAL,
+        DO_FINAL_WITH_OFFSET,
+        UPDATE_DO_FINAL,
+        MULTIPLE_UPDATE_DO_FINAL,
+        UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY,
+        UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY_AND_OFFSET,
+        DO_FINAL_WITH_INPUT_OUTPUT_ARRAY,
+        DO_FINAL_WITH_INPUT_OUTPUT_ARRAY_AND_OFFSET,
+        UPDATE_DO_FINAL_WITH_INPUT_OUTPUT_ARRAY
+    }
+
+    /** Concatenates the given arrays into a single array.*/
+    byte[] concatArrays(byte[]... arrays) {
+        int length = 0;
+        for (byte[] array : arrays) {
+            if (array == null) {
+                continue;
+            }
+            length += array.length;
+        }
+        byte[] result = new byte[length];
+        int pos = 0;
+        for (byte[] array : arrays) {
+            if (array == null) {
+                continue;
+            }
+            System.arraycopy(array, 0, result, pos, array.length);
+            pos += array.length;
+        }
+        return result;
+    }
+
+    /** Calls an initialized cipher with different equivalent call patterns. */
+    private byte[] callCipher(
+            Cipher cipher, byte[] input, int expectedOutputLength, CallPattern callPattern)
+            throws GeneralSecurityException {
+        switch (callPattern) {
+            case DO_FINAL: {
+                return cipher.doFinal(input);
+            }
+            case DO_FINAL_WITH_OFFSET: {
+                byte[] inputCopy = new byte[input.length + 100];
+                int inputOffset = 42;
+                System.arraycopy(input, 0, inputCopy, inputOffset, input.length);
+                return cipher.doFinal(inputCopy, inputOffset, input.length);
+            }
+            case UPDATE_DO_FINAL: {
+                byte[] output1 = cipher.update(input);
+                byte[] output2 = cipher.doFinal();
+                return concatArrays(output1, output2);
+            }
+            case MULTIPLE_UPDATE_DO_FINAL: {
+                int input1Length = input.length / 2;
+                int input2Length = input.length - input1Length;
+                byte[] output1 = cipher.update(input, /*inputOffset= */ 0, input1Length);
+                int input2Offset = input1Length;
+                byte[] output2 = cipher.update(input, input2Offset, input2Length);
+                byte[] output3 = cipher.update(new byte[0]);
+                byte[] output4 = cipher.doFinal();
+                return concatArrays(output1, output2, output3, output4);
+            }
+            case UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY: {
+                byte[] output1 = cipher.update(input);
+                int output1Length = (output1 == null) ? 0 : output1.length;
+                byte[] output2 = new byte[expectedOutputLength - output1Length];
+                int written = cipher.doFinal(output2, /*outputOffset= */ 0);
+                assertEquals(expectedOutputLength - output1Length, written);
+                return concatArrays(output1, output2);
+            }
+            case UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY_AND_OFFSET: {
+                byte[] output1 = cipher.update(input);
+                int output1Length = (output1 == null) ? 0 : output1.length;
+                byte[] output2WithOffset = new byte[expectedOutputLength + 100];
+                int outputOffset = 42;
+                int written = cipher.doFinal(output2WithOffset, outputOffset);
+                assertEquals(expectedOutputLength - output1Length, written);
+                byte[] output2 = Arrays.copyOfRange(output2WithOffset, outputOffset, outputOffset + written);
+                return concatArrays(output1, output2);
+            }
+            case DO_FINAL_WITH_INPUT_OUTPUT_ARRAY: {
+                byte[] output = new byte[expectedOutputLength];
+                int written = cipher.doFinal(input, /*inputOffset= */ 0, input.length, output);
+                assertEquals(expectedOutputLength, written);
+                return output;
+            }
+            case DO_FINAL_WITH_INPUT_OUTPUT_ARRAY_AND_OFFSET: {
+                byte[] inputWithOffset = new byte[input.length + 100];
+                int inputOffset = 37;
+                System.arraycopy(input, 0, inputWithOffset, inputOffset, input.length);
+                byte[] outputWithOffset = new byte[expectedOutputLength + 100];
+                int outputOffset = 21;
+                int written = cipher.doFinal(
+                    inputWithOffset, inputOffset, input.length, outputWithOffset, outputOffset);
+                return Arrays.copyOfRange(outputWithOffset, outputOffset, outputOffset + written);
+            }
+            case UPDATE_DO_FINAL_WITH_INPUT_OUTPUT_ARRAY: {
+                int input1Length = input.length / 2;
+                byte[] output = new byte[expectedOutputLength];
+                int written1 = cipher.update(input, /*inputOffset= */ 0, input1Length, output);
+                int input2Offset = input1Length;
+                int input2Length = input.length - input1Length;
+                int outputOffset = written1;
+                int written2 = cipher.doFinal(
+                    input, input2Offset, input2Length, output, outputOffset);
+                assertEquals(expectedOutputLength, written1 + written2);
+                return output;
+            }
+        }
+        throw new IllegalArgumentException("Unsupported CallPattern: " + callPattern);
+    }
+
     @Test
     public void testBasicEncryption() throws Exception {
         for (Provider p : Security.getProviders()) {
@@ -132,25 +245,36 @@ public final class CipherBasicsTest {
                     }
 
                     try {
-                        cipher.init(Cipher.ENCRYPT_MODE, key, params);
-                        assertEquals("Provider " + p.getName()
+                        for (CallPattern callPattern: CallPattern.values()) {
+                            cipher.init(Cipher.ENCRYPT_MODE, key, params);
+                            assertEquals("Provider " + p.getName()
                                         + ", algorithm " + transformation
                                         + " reported the wrong output size",
                                 ciphertext.length, cipher.getOutputSize(plaintext.length));
-                        assertArrayEquals("Provider " + p.getName()
-                                + ", algorithm " + transformation
-                                + " failed on encryption, data is " + Arrays.toString(line),
-                                ciphertext, cipher.doFinal(plaintext));
-
-                        cipher.init(Cipher.DECRYPT_MODE, key, params);
-                        assertEquals("Provider " + p.getName()
-                                        + ", algorithm " + transformation
-                                        + " reported the wrong output size",
-                                plaintext.length, cipher.getOutputSize(ciphertext.length));
-                        assertArrayEquals("Provider " + p.getName()
-                                + ", algorithm " + transformation
-                                + " failed on decryption, data is " + Arrays.toString(line),
-                                plaintext, cipher.doFinal(ciphertext));
+                            byte[] encrypted = callCipher(
+                                cipher, plaintext, ciphertext.length, callPattern);
+                            assertArrayEquals(
+                                "Provider " + p.getName() + ", algorithm " + transformation
+                                    + ", CallPattern " + callPattern
+                                    + " failed on encryption, data is " + Arrays.toString(line),
+                                ciphertext, encrypted);
+
+                            cipher.init(Cipher.DECRYPT_MODE, key, params);
+                            byte[] decrypted;
+                            try {
+                                decrypted = callCipher(
+                                    cipher, ciphertext, plaintext.length, callPattern);
+                            } catch (GeneralSecurityException e) {
+                                throw new GeneralSecurityException("Provider " + p.getName()
+                                + ", algorithm " + transformation + ", CallPattern " + callPattern
+                                + " failed on decryption, data is " + Arrays.toString(line), e);
+                            }
+                            assertArrayEquals(
+                                "Provider " + p.getName() + ", algorithm " + transformation
+                                    + ", CallPattern " + callPattern
+                                    + " failed on decryption, data is " + Arrays.toString(line),
+                                plaintext, decrypted);
+                        }
                     } catch (InvalidKeyException e) {
                         // Some providers may not support raw SecretKeySpec keys, that's allowed
                     }
@@ -159,37 +283,73 @@ public final class CipherBasicsTest {
         }
     }
 
+    private static AlgorithmParameterSpec modifiedParams(AlgorithmParameterSpec params) {
+        if (params instanceof IvParameterSpec) {
+            IvParameterSpec ivSpec = (IvParameterSpec) params;
+            byte[] iv = ivSpec.getIV();
+            iv[0] = (byte) (iv[0] ^ 1);
+            return new IvParameterSpec(iv);
+        } else if (params instanceof GCMParameterSpec) {
+            GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
+            byte[] iv = gcmSpec.getIV();
+            iv[0] = (byte) (iv[0] ^ 1);
+            return new GCMParameterSpec(gcmSpec.getTLen(), iv);
+        } else {
+            throw new IllegalArgumentException("Unsupported AlgorithmParameterSpec: " + params);
+        }
+    }
+
+    static final byte[] EMPTY_AAD = new byte[0];
+
     public void arrayBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] plaintext,
                                      byte[] ciphertext, Key key, AlgorithmParameterSpec params,
                                      String transformation, Provider p, String[] line) throws Exception {
-        cipher.init(Cipher.ENCRYPT_MODE, key, params);
-        if (aad.length > 0) {
-            cipher.updateAAD(aad);
-        }
-        byte[] combinedOutput = new byte[ciphertext.length + tag.length];
-        assertEquals("Provider " + p.getName()
-                        + ", algorithm " + transformation
-                        + " reported the wrong output size",
-                combinedOutput.length, cipher.getOutputSize(plaintext.length));
-        System.arraycopy(ciphertext, 0, combinedOutput, 0, ciphertext.length);
-        System.arraycopy(tag, 0, combinedOutput, ciphertext.length, tag.length);
-        assertArrayEquals("Provider " + p.getName()
-                + ", algorithm " + transformation
+        byte[] combinedCiphertext = new byte[ciphertext.length + tag.length];
+        System.arraycopy(ciphertext, 0, combinedCiphertext, 0, ciphertext.length);
+        System.arraycopy(tag, 0, combinedCiphertext, ciphertext.length, tag.length);
+
+        for (CallPattern callPattern: CallPattern.values()) {
+            // We first initialize the cipher with a modified IV to make sure that we don't trigger
+            // an IV reuse check.
+            cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));
+
+            cipher.init(Cipher.ENCRYPT_MODE, key, params);
+            if (aad.length > 0) {
+                cipher.updateAAD(aad);
+            }
+            assertEquals("Provider " + p.getName()
+                            + ", algorithm " + transformation
+                            + " reported the wrong output size",
+                    combinedCiphertext.length, cipher.getOutputSize(plaintext.length));
+            byte[] encrypted = callCipher(cipher, plaintext, combinedCiphertext.length, callPattern);
+            assertArrayEquals("Provider " + p.getName()
+                + ", algorithm " + transformation + ", CallPattern " + callPattern
                 + " failed on encryption, data is " + Arrays.toString(line),
-                combinedOutput, cipher.doFinal(plaintext));
-
-        cipher.init(Cipher.DECRYPT_MODE, key, params);
-        if (aad.length > 0) {
-            cipher.updateAAD(aad);
+                combinedCiphertext, encrypted);
         }
-        assertEquals("Provider " + p.getName()
-                        + ", algorithm " + transformation
-                        + " reported the wrong output size",
-                plaintext.length, cipher.getOutputSize(combinedOutput.length));
-        assertArrayEquals("Provider " + p.getName()
-                + ", algorithm " + transformation
+
+        for (CallPattern callPattern: CallPattern.values()) {
+            cipher.init(Cipher.DECRYPT_MODE, key, params);
+            if (aad.length > 0) {
+                cipher.updateAAD(aad);
+            }
+            assertEquals("Provider " + p.getName()
+                            + ", algorithm " + transformation
+                            + " reported the wrong output size",
+                    plaintext.length, cipher.getOutputSize(combinedCiphertext.length));
+            byte[] decrypted;
+            try {
+                decrypted = callCipher(cipher, combinedCiphertext, plaintext.length, callPattern);
+            } catch (GeneralSecurityException e) {
+                throw new GeneralSecurityException("Provider " + p.getName()
+                + ", algorithm " + transformation + ", CallPattern " + callPattern
+                + " failed on decryption, data is " + Arrays.toString(line), e);
+            }
+            assertArrayEquals("Provider " + p.getName()
+                + ", algorithm " + transformation + ", CallPattern " + callPattern
                 + " failed on decryption, data is " + Arrays.toString(line),
-                plaintext, cipher.doFinal(combinedOutput));
+                plaintext, decrypted);
+        }
     }
 
     @Test
@@ -255,6 +415,12 @@ public final class CipherBasicsTest {
                     } catch (InvalidAlgorithmParameterException e) {
                         // Some providers may not support all tag lengths or nonce lengths,
                         // that's allowed
+                        if (e.getMessage().contains("IV must not be re-used")) {
+                            throw new AssertionError(
+                                "The same IV was used twice and therefore some tests did not run." +
+                                "Provider = " + p.getName() + ", algorithm = " + transformation,
+                                e);
+                        }
                     }
                 }
             }
@@ -264,6 +430,10 @@ public final class CipherBasicsTest {
     public void sharedBufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] _plaintext,
                                       byte[] _ciphertext, Key key, AlgorithmParameterSpec params,
                                       String transformation, Provider p) throws Exception {
+        // We first initialize the cipher with a modified IV to make sure that we don't trigger
+        // an IV reuse check.
+        cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));
+
         cipher.init(Cipher.ENCRYPT_MODE, key, params);
         if (aad.length > 0) {
             cipher.updateAAD(aad);
@@ -314,6 +484,10 @@ public final class CipherBasicsTest {
     public void bufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] _plaintext,
                                            byte[] _ciphertext, Key key, AlgorithmParameterSpec params,
                                            String transformation, Provider p, boolean inBoolDirect, boolean outBoolDirect) throws Exception {
+        // We first initialize the cipher with a modified IV to make sure that we don't trigger
+        // an IV reuse check.
+        cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));
+
         cipher.init(Cipher.ENCRYPT_MODE, key, params);
         if (aad.length > 0) {
             cipher.updateAAD(aad);
@@ -486,3 +660,4 @@ public final class CipherBasicsTest {
         }
     }
 }
+
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java
index a4ad95b2..75c0d531 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java
@@ -16,12 +16,23 @@
 
 package org.conscrypt.javax.net.ssl;
 
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
+import org.conscrypt.KeyManagerFactoryImpl;
+import org.conscrypt.TestUtils;
+import org.conscrypt.java.security.StandardNames;
+import org.conscrypt.java.security.TestKeyStore;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
@@ -42,6 +53,7 @@ import java.security.cert.X509Certificate;
 import java.util.Arrays;
 import java.util.Date;
 import java.util.Enumeration;
+
 import javax.net.ssl.KeyManager;
 import javax.net.ssl.KeyManagerFactory;
 import javax.net.ssl.KeyStoreBuilderParameters;
@@ -145,6 +157,11 @@ public class KeyManagerFactoryTest {
             }
         }
 
+        if (kmf.getAlgorithm().equals("PAKE")) {
+            assertThrows(KeyStoreException.class, () -> kmf.init(null, null));
+            return; // Functional testing is in PakeKeyManagerFactoryTest
+        }
+
         // init with null for default behavior
         kmf.init(null, null);
         test_KeyManagerFactory_getKeyManagers(kmf, true);
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketTest.java
index ba842852..1493177a 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketTest.java
@@ -16,7 +16,6 @@
 
 package org.conscrypt.javax.net.ssl;
 
-import static java.nio.charset.StandardCharsets.UTF_8;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -26,6 +25,24 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import org.conscrypt.TestUtils;
+import org.conscrypt.java.security.StandardNames;
+import org.conscrypt.java.security.TestKeyStore;
+import org.conscrypt.tlswire.TlsTester;
+import org.conscrypt.tlswire.handshake.CipherSuite;
+import org.conscrypt.tlswire.handshake.ClientHello;
+import org.conscrypt.tlswire.handshake.CompressionMethod;
+import org.conscrypt.tlswire.handshake.EllipticCurve;
+import org.conscrypt.tlswire.handshake.EllipticCurvesHelloExtension;
+import org.conscrypt.tlswire.handshake.HelloExtension;
+import org.conscrypt.tlswire.util.TlsProtocolVersion;
+import org.junit.After;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.EOFException;
 import java.io.IOException;
 import java.io.InputStream;
@@ -48,33 +65,24 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicInteger;
+
 import javax.crypto.SecretKey;
 import javax.crypto.spec.SecretKeySpec;
 import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactory;
+import javax.net.ssl.ManagerFactoryParameters;
 import javax.net.ssl.SSLContext;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLProtocolException;
+import javax.net.ssl.SSLServerSocket;
 import javax.net.ssl.SSLSession;
+import javax.net.ssl.SSLServerSocket;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.X509ExtendedTrustManager;
-import org.conscrypt.TestUtils;
-import org.conscrypt.java.security.StandardNames;
-import org.conscrypt.java.security.TestKeyStore;
-import org.conscrypt.tlswire.TlsTester;
-import org.conscrypt.tlswire.handshake.CipherSuite;
-import org.conscrypt.tlswire.handshake.ClientHello;
-import org.conscrypt.tlswire.handshake.CompressionMethod;
-import org.conscrypt.tlswire.handshake.EllipticCurve;
-import org.conscrypt.tlswire.handshake.EllipticCurvesHelloExtension;
-import org.conscrypt.tlswire.handshake.HelloExtension;
-import org.conscrypt.tlswire.util.TlsProtocolVersion;
-import org.junit.After;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.net.DelegatingSSLSocketFactory;
 import tests.util.ForEachRunner;
 import tests.util.Pair;
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java
index e730c76a..8d53a08f 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java
@@ -39,6 +39,7 @@ import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.X509TrustManager;
 import org.bouncycastle.asn1.x509.KeyPurposeId;
 import org.conscrypt.Conscrypt;
+import org.conscrypt.Spake2PlusTrustManager;
 import org.conscrypt.java.security.StandardNames;
 import org.conscrypt.java.security.TestKeyStore;
 import org.junit.Test;
@@ -84,19 +85,24 @@ public class TrustManagerFactoryTest {
         assertNotNull(tmf.getProvider());
 
         // before init
-        try {
-            tmf.getTrustManagers();
-            fail();
-        } catch (IllegalStateException expected) {
-            // Ignored.
-        }
+        if (!tmf.getAlgorithm().equals("PAKE")) {
+            try {
+                tmf.getTrustManagers();
+                fail();
+            } catch (IllegalStateException expected) {
+                // Ignored.
+            }
 
-        // init with null ManagerFactoryParameters
-        try {
+            // init with null ManagerFactoryParameters
+            try {
+                tmf.init((ManagerFactoryParameters) null);
+                fail();
+            } catch (InvalidAlgorithmParameterException expected) {
+                // Ignored.
+            }
+        } else {
             tmf.init((ManagerFactoryParameters) null);
-            fail();
-        } catch (InvalidAlgorithmParameterException expected) {
-            // Ignored.
+            test_TrustManagerFactory_getTrustManagers(tmf);
         }
 
         // init with useless ManagerFactoryParameters
@@ -138,8 +144,10 @@ public class TrustManagerFactoryTest {
         test_TrustManagerFactory_getTrustManagers(tmf);
 
         // init with specific key store
-        tmf.init(getTestKeyStore().keyStore);
-        test_TrustManagerFactory_getTrustManagers(tmf);
+        if (!tmf.getAlgorithm().equals("PAKE")) {
+            tmf.init(getTestKeyStore().keyStore);
+            test_TrustManagerFactory_getTrustManagers(tmf);
+        }
     }
 
     private void test_TrustManagerFactory_getTrustManagers(TrustManagerFactory tmf)
@@ -152,9 +160,17 @@ public class TrustManagerFactoryTest {
             if (trustManager instanceof X509TrustManager) {
                 test_X509TrustManager(tmf.getProvider(), (X509TrustManager) trustManager);
             }
+            if (trustManager instanceof Spake2PlusTrustManager) {
+                test_pakeTrustManager((Spake2PlusTrustManager) trustManager);
+            }
         }
     }
 
+    private void test_pakeTrustManager(Spake2PlusTrustManager tm) throws Exception {
+        tm.checkClientTrusted();
+        tm.checkServerTrusted();
+    }
+
     private void test_X509TrustManager(Provider p, X509TrustManager tm) throws Exception {
         for (String keyType : KEY_TYPES) {
             X509Certificate[] issuers = tm.getAcceptedIssuers();
@@ -231,6 +247,9 @@ public class TrustManagerFactoryTest {
                 @Override
                 public void test(Provider p, String algorithm) throws Exception {
                     TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
+                    if (tmf.getAlgorithm() == "PAKE") {
+                        return;
+                    }
                     tmf.init(keyStore);
                     TrustManager[] trustManagers = tmf.getTrustManagers();
                     for (TrustManager trustManager : trustManagers) {
diff --git a/constants/build.gradle b/constants/build.gradle
index 40a74453..8f6c4593 100644
--- a/constants/build.gradle
+++ b/constants/build.gradle
@@ -36,6 +36,7 @@ model {
             binaries.all {
                 if (toolChain in VisualCpp) {
                     cppCompiler.define "WIN32_LEAN_AND_MEAN"
+                    cppCompiler.args "/std:c++17"
                 } else if (toolChain in Clang || toolChain in Gcc) {
                     cppCompiler.args "-std=c++17"
                 }
diff --git a/constants/src/gen/cpp/generate_constants.cc b/constants/src/gen/cpp/generate_constants.cc
index 515202de..64440012 100644
--- a/constants/src/gen/cpp/generate_constants.cc
+++ b/constants/src/gen/cpp/generate_constants.cc
@@ -61,6 +61,7 @@ int main(int argc, char **argv) {
 
   CONST(EVP_PKEY_RSA);
   CONST(EVP_PKEY_EC);
+  CONST(EVP_PKEY_ED25519);
 
   CONST(RSA_PKCS1_PADDING);
   CONST(RSA_NO_PADDING);
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index d0120071..52240f44 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -1,5 +1,5 @@
 [versions]
-android-tools = "7.4.2"
+agp = "7.4.2"
 bnd = "6.4.0"
 bouncycastle = "1.67"
 caliper = "1.0-beta-2"
@@ -18,6 +18,7 @@ shadow = "7.1.2"
 task-tree = "3.0.0"
 
 [plugins]
+android-library = { id = "com.android.library", version.ref = "agp" }
 bnd = { id = "biz.aQute.bnd.builder", version.ref = "bnd" }
 errorprone = { id = "net.ltgt.errorprone", version.ref = "errorprone-plugin" }
 grgit = { id = "org.ajoberstar.grgit", version.ref = "grgit" }
@@ -28,7 +29,6 @@ task-tree = { id = "com.dorongold.task-tree", version.ref = "task-tree" }
 
 [libraries]
 # Android tooling
-android-tools = { module = "com.android.tools.build:gradle", version.ref = "android-tools" }
 caliper = { module = "com.google.caliper:caliper", version.ref = "caliper" }
 
 # Bouncycastle
diff --git a/libcore-stub/src/main/java/libcore/util/NonNull.java b/libcore-stub/src/main/java/libcore/util/NonNull.java
new file mode 100644
index 00000000..ee71458f
--- /dev/null
+++ b/libcore-stub/src/main/java/libcore/util/NonNull.java
@@ -0,0 +1,37 @@
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
+package libcore.util;
+
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.PARAMETER;
+import static java.lang.annotation.ElementType.TYPE_USE;
+import static java.lang.annotation.RetentionPolicy.SOURCE;
+
+import java.lang.annotation.Documented;
+import java.lang.annotation.Retention;
+import java.lang.annotation.Target;
+
+/**
+ * Denotes that a type use can never be null.
+ * <p>
+ * This is a marker annotation and it has no specific attributes.
+ * @hide
+ */
+@Documented
+@Retention(SOURCE)
+@Target({FIELD, METHOD, PARAMETER, TYPE_USE})
+public @interface NonNull {}
diff --git a/libcore-stub/src/main/java/libcore/util/Nullable.java b/libcore-stub/src/main/java/libcore/util/Nullable.java
new file mode 100644
index 00000000..7db7d753
--- /dev/null
+++ b/libcore-stub/src/main/java/libcore/util/Nullable.java
@@ -0,0 +1,37 @@
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
+package libcore.util;
+
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.PARAMETER;
+import static java.lang.annotation.ElementType.TYPE_USE;
+import static java.lang.annotation.RetentionPolicy.SOURCE;
+
+import java.lang.annotation.Documented;
+import java.lang.annotation.Retention;
+import java.lang.annotation.Target;
+
+/**
+ * Denotes that a type use can be a null.
+ * <p>
+ * This is a marker annotation and it has no specific attributes.
+ * @hide
+ */
+@Documented
+@Retention(SOURCE)
+@Target({FIELD, METHOD, PARAMETER, TYPE_USE})
+public @interface Nullable {}
diff --git a/openjdk-uber/build.gradle b/openjdk-uber/build.gradle
index 80ffac40..652afebc 100644
--- a/openjdk-uber/build.gradle
+++ b/openjdk-uber/build.gradle
@@ -1,12 +1,14 @@
 description = 'Conscrypt: OpenJdk UberJAR'
 
+Directory buildTop = layout.buildDirectory.get()
 ext {
     buildUberJar = Boolean.parseBoolean(System.getProperty('org.conscrypt.openjdk.buildUberJar', 'false'))
     uberJarClassifiers = (System.getProperty('org.conscrypt.openjdk.uberJarClassifiers',
             'osx-x86_64,osx-aarch_64,linux-x86_64,windows-x86_64')).split(',')
-    classesDir = "${buildDir}/classes"
-    resourcesDir = "${buildDir}/resources"
-    sourcesDir = "${buildDir}/sources"
+    classesDir = buildTop.dir('classes')
+    resourcesDir = buildTop.dir('resources')
+    sourcesDir = buildTop.dir('sources')
+    javadocDir = buildTop.dir('docs/javadoc')
 }
 
 if (buildUberJar) {
@@ -20,6 +22,7 @@ if (buildUberJar) {
     jar {
         from classesDir
         from resourcesDir
+        from javadocDir
     }
 
     sourcesJar {
@@ -68,10 +71,9 @@ if (buildUberJar) {
     }
 
     def copySources = tasks.register("copySources", Copy) {
-        dependsOn ":conscrypt-openjdk:sourcesJar"
-        from {
-            project(":conscrypt-openjdk").sourceSets.main.java
-        }
+        dependsOn copyJavadocs
+        dependsOn ":conscrypt-constants:runGen"
+        from project(":conscrypt-openjdk").sourceSets.main.java
         into file(sourcesDir)
         duplicatesStrategy = DuplicatesStrategy.EXCLUDE
     }
@@ -79,6 +81,20 @@ if (buildUberJar) {
         dependsOn copySources
     }
 
+    def copyJavadocs = tasks.register("copyJavadocs", Copy) {
+        dependsOn ':conscrypt-openjdk:javadoc'
+        from project(':conscrypt-openjdk').layout.buildDirectory
+        include('docs/**/*')
+        into layout.buildDirectory
+        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
+    }
+    tasks.named('javadocJar').configure {
+        dependsOn copyJavadocs
+    }
+    tasks.named('jar').configure {
+        dependsOn copyJavadocs
+    }
+
     // Note that this assumes that the version of BoringSSL for each
     // artifact exactly matches the one on the current system.
     jar.manifest {
diff --git a/openjdk/build.gradle b/openjdk/build.gradle
index cdb51a50..b6608b2e 100644
--- a/openjdk/build.gradle
+++ b/openjdk/build.gradle
@@ -177,6 +177,11 @@ processResources {
     dependsOn generateProperties
 }
 
+sourcesJar {
+    dependsOn generateProperties
+    dependsOn ':conscrypt-constants:runGen'
+}
+
 tasks.register("platformJar", Jar) {
     from sourceSets.platform.output
 }
@@ -323,7 +328,6 @@ def testFdSocket = tasks.register("testFdSocket", Test) {
     systemProperties = test.systemProperties
     systemProperty "org.conscrypt.useEngineSocketByDefault", false
 }
-check.dependsOn testFdSocket
 
 // Tests that involve interoperation with the OpenJDK TLS provider (generally to
 // test renegotiation, since we don't support initiating renegotiation but do
@@ -540,4 +544,4 @@ boolean isExecutableOnPath(executable) {
         }
     }
     return false
-}
\ No newline at end of file
+}
diff --git a/openjdk/src/main/java/org/conscrypt/Platform.java b/openjdk/src/main/java/org/conscrypt/Platform.java
index 55f871c0..269d284b 100644
--- a/openjdk/src/main/java/org/conscrypt/Platform.java
+++ b/openjdk/src/main/java/org/conscrypt/Platform.java
@@ -36,10 +36,13 @@ import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
 
-import org.conscrypt.ct.LogStore;
-import org.conscrypt.ct.Policy;
+import org.conscrypt.NativeCrypto;
+import org.conscrypt.ct.CertificateTransparency;
+import org.conscrypt.metrics.CertificateTransparencyVerificationReason;
+import org.conscrypt.metrics.NoopStatsLog;
 import org.conscrypt.metrics.Source;
 import org.conscrypt.metrics.StatsLog;
+import org.conscrypt.metrics.StatsLogImpl;
 
 import java.io.File;
 import java.io.FileDescriptor;
@@ -84,7 +87,6 @@ import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.NativeCrypto;
 
 /**
  * Platform-specific methods for OpenJDK.
@@ -97,7 +99,7 @@ final public class Platform {
     private static final Method GET_CURVE_NAME_METHOD;
     static boolean DEPRECATED_TLS_V1 = true;
     static boolean ENABLED_TLS_V1 = false;
-    private static boolean FILTERED_TLS_V1 = true;
+    private static boolean FILTERED_TLS_V1 = false;
 
     static {
         NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
@@ -649,7 +651,7 @@ final public class Platform {
      * - conscrypt.ct.enforce.com.*
      * - conscrypt.ct.enforce.*
      */
-    static boolean isCTVerificationRequired(String hostname) {
+    public static boolean isCTVerificationRequired(String hostname) {
         if (hostname == null) {
             return false;
         }
@@ -681,6 +683,11 @@ final public class Platform {
         return enable;
     }
 
+    public static CertificateTransparencyVerificationReason reasonCTVerificationRequired(
+            String hostname) {
+        return CertificateTransparencyVerificationReason.UNKNOWN;
+    }
+
     static boolean supportsConscryptCertStore() {
         return false;
     }
@@ -745,11 +752,7 @@ final public class Platform {
         return null;
     }
 
-    static LogStore newDefaultLogStore() {
-        return null;
-    }
-
-    static Policy newDefaultPolicy() {
+    static CertificateTransparency newDefaultCertificateTransparency() {
         return null;
     }
 
@@ -830,12 +833,12 @@ final public class Platform {
     }
 
     public static StatsLog getStatsLog() {
-        return null;
+        return NoopStatsLog.getInstance();
     }
 
     @SuppressWarnings("unused")
     public static Source getStatsSource() {
-        return null;
+        return Source.SOURCE_UNKNOWN;
     }
 
     @SuppressWarnings("unused")
@@ -858,4 +861,12 @@ final public class Platform {
     public static boolean isTlsV1Supported() {
         return ENABLED_TLS_V1;
     }
+
+    public static boolean isPakeSupported() {
+        return false;
+    }
+
+    public static boolean isSdkGreater(int sdk) {
+        return false;
+    }
 }
diff --git a/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java b/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
index 8594cd47..cd83a843 100644
--- a/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
+++ b/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
@@ -663,7 +663,7 @@ public class ConscryptSocketTest {
                 + ": " + connection.clientException.getMessage(),
                 connection.clientException instanceof SSLHandshakeException);
         assertTrue(
-                connection.clientException.getMessage().contains("SSLv3 is no longer supported"));
+                connection.clientException.getMessage().contains("SSLv3"));
         assertTrue("Expected SSLHandshakeException, but got "
                         + connection.serverException.getClass().getSimpleName()
                         + ": " + connection.serverException.getMessage(),
@@ -731,18 +731,28 @@ public class ConscryptSocketTest {
     @Test
     public void dataFlows() throws Exception {
         final TestConnection connection =
-                new TestConnection(new X509Certificate[] {cert, ca}, certKey);
+                new TestConnection(new X509Certificate[]{cert, ca}, certKey);
         connection.doHandshakeSuccess();
+        // Max app data size that will fit in a single TLS record.
+        int maxDataSize = connection.client.getSession().getApplicationBufferSize();
 
-        // Basic data flow assurance.  Send random buffers in each direction, each less than 16K
-        // so should fit in a single TLS packet.  50% chance of sending in each direction on
-        // each iteration to randomize the flow.
+        // Zero sized reads and writes. InputStream.read() allows zero size reads
+        // to succeed even when no data is available.
+        sendData(connection.client, connection.server, randomBuffer(0));
+        sendData(connection.server, connection.client, randomBuffer(0));
+
+        // Completely full record.
+        sendData(connection.client, connection.server, randomBuffer(maxDataSize));
+        sendData(connection.server, connection.client, randomBuffer(maxDataSize));
+
+        // Random workout. Send random sized buffers in each direction, 50% chance of sending in
+        // each direction  on each iteration to randomize the flow.
         for (int i = 0; i < 50; i++) {
             if (random.nextBoolean()) {
-                sendData(connection.client, connection.server, randomBuffer());
+                sendData(connection.client, connection.server, randomSizeBuffer(maxDataSize));
             }
             if (random.nextBoolean()) {
-                sendData(connection.server, connection.client, randomBuffer());
+                sendData(connection.server, connection.client, randomSizeBuffer(maxDataSize));
             }
         }
     }
@@ -751,16 +761,20 @@ public class ConscryptSocketTest {
             throws Exception {
         final byte[] received = new byte[data.length];
 
-        Future<Integer> readFuture = executor.submit(
-                () -> destination.getInputStream().read(received));
-
         source.getOutputStream().write(data);
-        assertEquals(data.length, (int) readFuture.get());
+        assertEquals(data.length, destination.getInputStream().read(received));
         assertArrayEquals(data, received);
     }
 
-    private byte[] randomBuffer() {
-        byte[] buffer = new byte[random.nextInt(16 * 1024)];
+    // Returns a random sized buffer containing random data.
+    // Zero and maxSize are valid possible sizes for the returned buffer.
+    private byte[] randomSizeBuffer(int maxSize) {
+        return randomBuffer(random.nextInt(maxSize + 1));
+    }
+
+    // Returns a buffer of random data of the size requested.
+    private byte[] randomBuffer(int size) {
+        byte[] buffer = new byte[size];
         random.nextBytes(buffer);
         return buffer;
     }
diff --git a/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java b/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java
index 7fc6a36a..2db44b47 100644
--- a/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java
+++ b/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java
@@ -16,6 +16,12 @@
 
 package org.conscrypt;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertSame;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.fail;
+
 import java.lang.reflect.InvocationHandler;
 import java.lang.reflect.Method;
 import java.lang.reflect.Proxy;
@@ -30,34 +36,36 @@ import javax.net.ssl.SSLContext;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
-import junit.framework.TestCase;
 
-public class DuckTypedPSKKeyManagerTest extends TestCase {
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class DuckTypedPSKKeyManagerTest {
     private SSLSocket mSSLSocket;
     private SSLEngine mSSLEngine;
 
-    @Override
-    protected void setUp() throws Exception {
-        super.setUp();
+    @Before
+    public void setUp() throws Exception {
         SSLContext sslContext = SSLContext.getDefault();
         SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
         mSSLSocket = (SSLSocket) sslSocketFactory.createSocket();
         mSSLEngine = sslContext.createSSLEngine();
     }
 
-    @Override
-    protected void tearDown() throws Exception {
-        try {
-            if (mSSLSocket != null) {
-                try {
-                    mSSLSocket.close();
-                } catch (Exception ignored) {}
-            }
-        } finally {
-            super.tearDown();
+    @After
+    public void tearDown() throws Exception {
+        if (mSSLSocket != null) {
+            try {
+                mSSLSocket.close();
+            } catch (Exception ignored) {}
         }
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingFailsWhenOneMethodMissing() throws Exception {
         try {
@@ -66,6 +74,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         } catch (NoSuchMethodException expected) {}
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingFailsWhenOneMethodReturnTypeIncompatible() throws Exception {
         try {
@@ -75,12 +84,14 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         } catch (NoSuchMethodException expected) {}
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingSucceedsWhenAllMethodsPresentWithExactReturnTypes() throws Exception {
         assertNotNull(DuckTypedPSKKeyManager.getInstance(
                 new KeyManagerOfferingAllPSKKeyManagerMethodsWithExactReturnTypes()));
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingSucceedsWhenAllMethodsPresentWithDifferentButCompatibleReturnTypes()
             throws Exception {
@@ -88,6 +99,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
                 new KeyManagerOfferingAllPSKKeyManagerMethodsWithCompatibleReturnTypes()));
     }
 
+    @Test
     public void testMethodInvocationDelegation() throws Exception {
         // IMPLEMENTATION NOTE: We create a DuckTypedPSKKeyManager wrapping a Reflection Proxy,
         // invoke each method of the PSKKeyManager interface on the DuckTypedPSKKeyManager instance,
@@ -162,6 +174,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[2]);
     }
 
+    @Test
     public void testMethodInvocationDelegationWithDifferentButCompatibleReturnType()
             throws Exception {
         // Check that nothing blows up when we invoke getKey which is declared to return
diff --git a/openjdk/src/test/java/org/conscrypt/FileClientSessionCacheTest.java b/openjdk/src/test/java/org/conscrypt/FileClientSessionCacheTest.java
index 1a296f66..1b66b6cb 100644
--- a/openjdk/src/test/java/org/conscrypt/FileClientSessionCacheTest.java
+++ b/openjdk/src/test/java/org/conscrypt/FileClientSessionCacheTest.java
@@ -16,13 +16,20 @@
 
 package org.conscrypt;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.fail;
+
 import java.io.File;
 import java.io.IOException;
-import junit.framework.TestCase;
 import org.conscrypt.javax.net.ssl.FakeSSLSession;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
-public class FileClientSessionCacheTest extends TestCase {
+@RunWith(JUnit4.class)
+public class FileClientSessionCacheTest {
 
+    @Test
     public void testMaxSize() throws IOException, InterruptedException {
         String tmpDir = System.getProperty("java.io.tmpdir");
         if (tmpDir == null) {
diff --git a/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java b/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
index af2e9ca7..4fc77865 100644
--- a/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
+++ b/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
@@ -26,20 +26,35 @@ import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 import static org.conscrypt.NativeConstants.TLS1_1_VERSION;
 import static org.conscrypt.NativeConstants.TLS1_2_VERSION;
 import static org.conscrypt.NativeConstants.TLS1_VERSION;
+import static org.conscrypt.TestUtils.decodeHex;
 import static org.conscrypt.TestUtils.isWindows;
 import static org.conscrypt.TestUtils.openTestFile;
 import static org.conscrypt.TestUtils.readTestFile;
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.when;
 
+import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
+import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+import org.conscrypt.io.IoUtils;
+import org.conscrypt.java.security.StandardNames;
+import org.conscrypt.java.security.TestKeyStore;
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
@@ -74,22 +89,12 @@ import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
+
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.SSLProtocolException;
 import javax.security.auth.x500.X500Principal;
-import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
-import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
-import org.conscrypt.io.IoUtils;
-import org.conscrypt.java.security.StandardNames;
-import org.conscrypt.java.security.TestKeyStore;
-import org.junit.BeforeClass;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-import org.mockito.ArgumentMatchers;
-import org.mockito.Mockito;
 
 @RunWith(JUnit4.class)
 public class NativeCryptoTest {
@@ -125,13 +130,15 @@ public class NativeCryptoTest {
             m_Platform_getFileDescriptor.setAccessible(true);
         }
 
-        PrivateKeyEntry serverPrivateKeyEntry = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
+        PrivateKeyEntry serverPrivateKeyEntry =
+                TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
         SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
         SERVER_CERTIFICATES_HOLDER = encodeCertificateList(serverPrivateKeyEntry.getCertificateChain());
         SERVER_CERTIFICATE_REFS = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);
         ENCODED_SERVER_CERTIFICATES = getEncodedCertificates(SERVER_CERTIFICATES_HOLDER);
 
-        PrivateKeyEntry clientPrivateKeyEntry = TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
+        PrivateKeyEntry clientPrivateKeyEntry =
+                TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
         CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
         CLIENT_CERTIFICATES_HOLDER = encodeCertificateList(clientPrivateKeyEntry.getCertificateChain());
         CLIENT_CERTIFICATE_REFS = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);
@@ -2716,6 +2723,79 @@ public class NativeCryptoTest {
         }
     }
 
+    @Test
+    public void test_ED25519_keypair_works() throws Exception {
+        byte[] publicKeyBytes = new byte[32];
+        byte[] privateKeyBytes = new byte[64];
+        NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes);
+
+        byte[] publicKeyBytes2 = new byte[32];
+        byte[] privateKeyBytes2 = new byte[64];
+        NativeCrypto.ED25519_keypair(publicKeyBytes2, privateKeyBytes2);
+
+        // keys must be random
+        assertNotEquals(publicKeyBytes, publicKeyBytes2);
+        assertNotEquals(privateKeyBytes, privateKeyBytes2);
+    }
+
+    @Test
+    public void test_ED25519_keypair_32BytePrivateKey_throws() throws Exception {
+        byte[] publicKeyBytes = new byte[32];
+        byte[] privateKeyBytes = new byte[32];
+        assertThrows(IllegalArgumentException.class,
+                () -> NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes));
+    }
+
+    @Test
+    public void test_EVP_DigestSign_Ed25519_works() throws Exception {
+        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
+        // PKCS#8 encoding for Ed25519 is defined in https://datatracker.ietf.org/doc/html/rfc8410
+        byte[] pkcs8EncodedPrivateKey = decodeHex(
+                // PKCS#8 header
+                "302e020100300506032b657004220420"
+                // raw private key
+                + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
+        byte[] data = decodeHex("");
+        byte[] expectedSig =
+                decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
+                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
+
+        NativeRef.EVP_PKEY privateKey =
+                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_private_key(pkcs8EncodedPrivateKey));
+
+        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
+
+        NativeCrypto.EVP_DigestSignInit(ctx, 0, privateKey);
+        byte[] sig = NativeCrypto.EVP_DigestSign(ctx, data, 0, data.length);
+
+        assertArrayEquals(expectedSig, sig);
+    }
+
+    @Test
+    public void test_EVP_DigestVerify_Ed25519_works() throws Exception {
+        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
+        // X.509 encoding for Ed25519 is defined in https://datatracker.ietf.org/doc/html/rfc8410
+        byte[] x509EncodedPublicKey = decodeHex(
+                // X.509 header
+                "302a300506032b6570032100"
+                // raw public key
+                + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
+        byte[] data = decodeHex("");
+        byte[] sig = decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
+                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
+
+        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
+
+        NativeRef.EVP_PKEY publicKey =
+                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_public_key(x509EncodedPublicKey));
+
+        NativeCrypto.EVP_DigestVerifyInit(ctx, 0, publicKey);
+        boolean result =
+                NativeCrypto.EVP_DigestVerify(ctx, sig, 0, sig.length, data, 0, data.length);
+
+        assertTrue(result);
+    }
+
     @Test(expected = NullPointerException.class)
     public void get_RSA_private_params_NullArgument() throws Exception {
         NativeCrypto.get_RSA_private_params(null);
diff --git a/platform/build.gradle b/platform/build.gradle
index 95f280fc..bb8cf0ae 100644
--- a/platform/build.gradle
+++ b/platform/build.gradle
@@ -1,11 +1,5 @@
-buildscript {
-    repositories {
-        google()
-        mavenCentral()
-    }
-    dependencies {
-        classpath(libs.android.tools)
-    }
+plugins {
+    alias(libs.plugins.android.library)
 }
 
 description = 'Conscrypt: Android Platform'
@@ -20,103 +14,91 @@ ext {
     androidTargetSdkVersion = 26
 }
 
-if (androidSdkInstalled) {
-    apply plugin: 'com.android.library'
-
-    android {
-        namespace "org.conscrypt"
-        compileSdkVersion androidTargetSdkVersion
+android {
+    namespace "org.conscrypt"
+    compileSdkVersion androidTargetSdkVersion
 
-        compileOptions {
-            sourceCompatibility androidMinJavaVersion;
-            targetCompatibility androidMinJavaVersion
-        }
+    compileOptions {
+        sourceCompatibility androidMinJavaVersion;
+        targetCompatibility androidMinJavaVersion
+    }
 
-        defaultConfig {
-            minSdkVersion androidMinSdkVersion
-            targetSdkVersion androidTargetSdkVersion
-            versionCode androidVersionCode
-            versionName androidVersionName
+    defaultConfig {
+        minSdkVersion androidMinSdkVersion
+        targetSdkVersion androidTargetSdkVersion
+        versionCode androidVersionCode
+        versionName androidVersionName
 
-            testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
+        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
 
-            consumerProguardFiles 'proguard-rules.pro'
+        consumerProguardFiles 'proguard-rules.pro'
 
-            externalNativeBuild {
-                cmake {
-                    arguments '-DANDROID=True',
-                            '-DANDROID_STL=c++_static',
-                            "-DBORINGSSL_HOME=$boringsslHome"
-                    cFlags '-fvisibility=hidden',
-                            '-DBORINGSSL_SHARED_LIBRARY',
-                            '-DBORINGSSL_IMPLEMENTATION',
-                            '-DOPENSSL_SMALL',
-                            '-D_XOPEN_SOURCE=700',
-                            '-Wno-unused-parameter'
-                }
-            }
-            ndk {
-                abiFilters 'x86', 'x86_64', 'armeabi-v7a', 'arm64-v8a'
+        externalNativeBuild {
+            cmake {
+                arguments '-DANDROID=True',
+                        '-DANDROID_STL=c++_static',
+                        "-DBORINGSSL_HOME=$boringsslHome"
+                cFlags '-fvisibility=hidden',
+                        '-DBORINGSSL_SHARED_LIBRARY',
+                        '-DBORINGSSL_IMPLEMENTATION',
+                        '-DOPENSSL_SMALL',
+                        '-D_XOPEN_SOURCE=700',
+                        '-Wno-unused-parameter'
             }
         }
-        buildTypes {
-            release {
-                minifyEnabled false
-                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
-            }
+        ndk {
+            abiFilters 'x86', 'x86_64', 'armeabi-v7a', 'arm64-v8a'
         }
-        sourceSets {
-            main {
-                java {
-                    srcDirs = [
-                            "${rootDir}/common/src/main/java",
-                            "src/main/java",
-                    ]
-                    excludes = [ 'org/conscrypt/Platform.java' ]
-                }
-            }
+    }
+    buildTypes {
+        release {
+            minifyEnabled false
+            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
         }
-        lintOptions {
-            lintConfig file('lint.xml')
+    }
+    sourceSets {
+        main {
+            java {
+                srcDirs = [
+                        "${rootDir}/common/src/main/java",
+                        "src/main/java",
+                ]
+                excludes = [ 'org/conscrypt/Platform.java' ]
+            }
         }
     }
-
-    configurations {
-        publicApiDocs
+    lintOptions {
+        lintConfig file('lint.xml')
     }
+}
 
-    dependencies {
-        implementation project(path: ':conscrypt-openjdk', configuration: 'platform')
-        publicApiDocs project(':conscrypt-api-doclet')
-        androidTestImplementation('androidx.test.espresso:espresso-core:3.1.1', {
-            exclude module: 'support-annotations'
-            exclude module: 'support-v4'
-            exclude module: 'support-v13'
-            exclude module: 'recyclerview-v7'
-            exclude module: 'appcompat-v7'
-            exclude module: 'design'
-        })
-        testCompileOnly project(':conscrypt-android-stub'),
-                        project(':conscrypt-libcore-stub')
-        testImplementation project(path: ":conscrypt-testing", configuration: "shadow"),
-                           libs.junit
-        compileOnly project(':conscrypt-android-stub'),
-                    project(':conscrypt-libcore-stub')
-
-        // Adds the constants module as a dependency so that we can include its generated source
-        compileOnly project(':conscrypt-constants')
-    }
+configurations {
+    publicApiDocs
+}
 
-    // Disable running the tests.
-    tasks.withType(Test).configureEach {
-        enabled = false
-    }
+dependencies {
+    implementation project(path: ':conscrypt-openjdk', configuration: 'platform')
+    publicApiDocs project(':conscrypt-api-doclet')
+    androidTestImplementation('androidx.test.espresso:espresso-core:3.1.1', {
+        exclude module: 'support-annotations'
+        exclude module: 'support-v4'
+        exclude module: 'support-v13'
+        exclude module: 'recyclerview-v7'
+        exclude module: 'appcompat-v7'
+        exclude module: 'design'
+    })
+    testCompileOnly project(':conscrypt-android-stub'),
+                    project(':conscrypt-libcore-stub')
+    testImplementation project(path: ":conscrypt-testing", configuration: "shadow"),
+                       libs.junit
+    compileOnly project(':conscrypt-android-stub'),
+                project(':conscrypt-libcore-stub')
 
-} else {
-    logger.warn('Android SDK has not been detected. The Android Platform module will not be built.')
+    // Adds the constants module as a dependency so that we can include its generated source
+    compileOnly project(':conscrypt-constants')
+}
 
-    // Disable all tasks
-    tasks.configureEach {
-        it.enabled = false
-    }
+// Disable running the tests.
+tasks.withType(Test).configureEach {
+    enabled = false
 }
diff --git a/platform/src/main/java/org/conscrypt/AndroidHpkeSpi.java b/platform/src/main/java/org/conscrypt/AndroidHpkeSpi.java
new file mode 100644
index 00000000..d54d57c8
--- /dev/null
+++ b/platform/src/main/java/org/conscrypt/AndroidHpkeSpi.java
@@ -0,0 +1,105 @@
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
+package org.conscrypt;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.GeneralSecurityException;
+import java.security.InvalidKeyException;
+import java.security.PrivateKey;
+import java.security.PublicKey;
+
+/**
+ * Delegating wrapper for HpkeImpl that inherits the Android platform's SPI
+ * as well as Conscrypt's own.
+ */
+@SuppressWarnings("NewApi")
+public class AndroidHpkeSpi implements android.crypto.hpke.HpkeSpi, org.conscrypt.HpkeSpi {
+    private final org.conscrypt.HpkeSpi delegate;
+
+    public AndroidHpkeSpi(org.conscrypt.HpkeSpi delegate) {
+        this.delegate = delegate;
+    }
+
+    @Override
+    public void engineInitSender(PublicKey recipientKey, @Nullable byte[] info,
+            PrivateKey senderKey, @Nullable byte[] psk, @Nullable byte[] psk_id)
+            throws InvalidKeyException {
+        delegate.engineInitSender(recipientKey, info, senderKey, psk, psk_id);
+    }
+
+    @Override
+    public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info,
+            PrivateKey senderKey, byte[] psk, byte[] psk_id, byte[] sKe)
+            throws InvalidKeyException {
+        delegate.engineInitSenderForTesting(recipientKey, info, senderKey, psk, psk_id, sKe);
+    }
+
+    @Override
+    public void engineInitSenderWithSeed(PublicKey recipientKey, @Nullable byte[] info,
+            PrivateKey senderKey, @Nullable byte[] psk, @Nullable byte[] psk_id,
+            @NonNull byte[] sKe) throws InvalidKeyException {
+        delegate.engineInitSenderForTesting(recipientKey, info, senderKey, psk, psk_id, sKe);
+    }
+
+    @Override
+    public void engineInitRecipient(@NonNull byte[] encapsulated, PrivateKey recipientKey,
+            @Nullable byte[] info, PublicKey senderKey, @Nullable byte[] psk,
+            @Nullable byte[] psk_id) throws InvalidKeyException {
+        delegate.engineInitRecipient(encapsulated, recipientKey, info, senderKey, psk, psk_id);
+    }
+
+    @Override
+    public @NonNull byte[] engineSeal(@NonNull byte[] plaintext, @Nullable byte[] aad) {
+        return delegate.engineSeal(plaintext, aad);
+    }
+
+    @Override
+    public @NonNull byte[] engineOpen(@NonNull byte[] ciphertext, @Nullable byte[] aad)
+            throws GeneralSecurityException {
+        return delegate.engineOpen(ciphertext, aad);
+    }
+
+    @Override
+    public @NonNull byte[] engineExport(int length, @Nullable byte[] context) {
+        return delegate.engineExport(length, context);
+    }
+
+    @Override
+    public @NonNull byte[] getEncapsulated() {
+        return delegate.getEncapsulated();
+    }
+
+    public static class X25519_AES_128 extends AndroidHpkeSpi {
+        public X25519_AES_128() {
+            super(new HpkeImpl.X25519_AES_128());
+        }
+    }
+
+    public static class X25519_AES_256 extends AndroidHpkeSpi {
+        public X25519_AES_256() {
+            super(new HpkeImpl.X25519_AES_256());
+        }
+    }
+
+    public static class X25519_CHACHA20 extends AndroidHpkeSpi {
+        public X25519_CHACHA20() {
+            super(new HpkeImpl.X25519_CHACHA20());
+        }
+    }
+}
diff --git a/platform/src/main/java/org/conscrypt/Hex.java b/platform/src/main/java/org/conscrypt/Hex.java
index 54542680..af789224 100644
--- a/platform/src/main/java/org/conscrypt/Hex.java
+++ b/platform/src/main/java/org/conscrypt/Hex.java
@@ -21,7 +21,6 @@ package org.conscrypt;
  */
 @Internal
 // public for testing by TrustedCertificateStoreTest
-// TODO(nathanmittler): Move to InternalUtil?
 public final class Hex {
     private Hex() {}
 
diff --git a/platform/src/main/java/org/conscrypt/PakeKeyManagerFactory.java b/platform/src/main/java/org/conscrypt/PakeKeyManagerFactory.java
new file mode 100644
index 00000000..5c8373f8
--- /dev/null
+++ b/platform/src/main/java/org/conscrypt/PakeKeyManagerFactory.java
@@ -0,0 +1,163 @@
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
+package org.conscrypt;
+
+import static android.net.ssl.PakeServerKeyManagerParameters.Link;
+
+import static java.util.Objects.requireNonNull;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeOption;
+import android.net.ssl.PakeServerKeyManagerParameters;
+
+import org.conscrypt.io.IoUtils;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileNotFoundException;
+import java.io.IOException;
+import java.security.InvalidAlgorithmParameterException;
+import java.security.KeyStore;
+import java.security.KeyStoreException;
+import java.security.NoSuchAlgorithmException;
+import java.security.UnrecoverableKeyException;
+import java.security.cert.CertificateException;
+import java.util.List;
+import java.util.Set;
+
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactorySpi;
+import javax.net.ssl.ManagerFactoryParameters;
+
+/**
+ * PakeKeyManagerFactory implementation.
+ * @see KeyManagerFactorySpi
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class PakeKeyManagerFactory extends KeyManagerFactorySpi {
+    PakeClientKeyManagerParameters clientParams;
+    PakeServerKeyManagerParameters serverParams;
+    private static final int MAX_HANDSHAKE_LIMIT = 24;
+
+    /**
+     * @see KeyManagerFactorySpi#engineInit(KeyStore ks, char[] password)
+     */
+    @Override
+    public void engineInit(KeyStore ks, char[] password)
+            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
+        throw new KeyStoreException("KeyStore not supported");
+    }
+
+    /**
+     * @see KeyManagerFactorySpi#engineInit(ManagerFactoryParameters spec)
+     */
+    @Override
+    public void engineInit(ManagerFactoryParameters spec)
+            throws InvalidAlgorithmParameterException {
+        if (clientParams != null || serverParams != null) {
+            throw new IllegalStateException("PakeKeyManagerFactory is already initialized");
+        }
+        if (spec == null) {
+            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters cannot be null");
+        }
+        if (spec instanceof PakeClientKeyManagerParameters) {
+            clientParams = (PakeClientKeyManagerParameters) spec;
+        } else if (spec instanceof PakeServerKeyManagerParameters) {
+            serverParams = (PakeServerKeyManagerParameters) spec;
+        } else {
+            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
+        }
+    }
+
+    /**
+     * @see KeyManagerFactorySpi#engineGetKeyManagers()
+     */
+    @Override
+    public KeyManager[] engineGetKeyManagers() {
+        if (clientParams == null && serverParams == null) {
+            throw new IllegalStateException("PakeKeyManagerFactory is not initialized");
+        }
+        if (clientParams != null) {
+            return initClient();
+        } else {
+            return initServer();
+        }
+    }
+
+    private static int getHandshakeLimit(PakeOption option, String limitName) {
+        byte[] limit = option.getMessageComponent(limitName);
+        if (limit == null) {
+            return 1;
+        }
+        int handshakeLimit = limit[0];
+        // This should never happen, but just in case, we set the limit to 1.
+        if (handshakeLimit < 1 || handshakeLimit > MAX_HANDSHAKE_LIMIT) {
+            return 1;
+        }
+        return handshakeLimit;
+    }
+
+    private KeyManager[] initClient() {
+        List<PakeOption> options = clientParams.getOptions();
+        for (PakeOption option : options) {
+            if (!option.getAlgorithm().equals("SPAKE2PLUS_PRERELEASE")) {
+                continue;
+            }
+            byte[] idProver = clientParams.getClientId();
+            byte[] idVerifier = clientParams.getServerId();
+            byte[] context = option.getMessageComponent("context");
+            byte[] password = option.getMessageComponent("password");
+            int clientHandshakeLimit = getHandshakeLimit(option, "client-handshake-limit");
+            if (password != null) {
+                return new KeyManager[] {new Spake2PlusKeyManager(
+                        context, password, idProver, idVerifier, true, clientHandshakeLimit)};
+            }
+            break;
+        }
+        return new KeyManager[] {};
+    }
+
+    private KeyManager[] initServer() {
+        Set<Link> links = serverParams.getLinks();
+        for (Link link : links) {
+            List<PakeOption> options = serverParams.getOptions(link);
+            for (PakeOption option : options) {
+                if (!option.getAlgorithm().equals("SPAKE2PLUS_PRERELEASE")) {
+                    continue;
+                }
+                byte[] idProver = link.getClientId();
+                byte[] idVerifier = link.getServerId();
+                byte[] context = option.getMessageComponent("context");
+                byte[] password = option.getMessageComponent("password");
+                int serverHandshakeLimit = getHandshakeLimit(option, "server-handshake-limit");
+                if (password != null) {
+                    return new KeyManager[] {
+                        new Spake2PlusKeyManager(
+                                context,
+                                password,
+                                idProver,
+                                idVerifier,
+                                false,
+                                serverHandshakeLimit)
+                    };
+                }
+                break;
+            }
+        }
+        return new KeyManager[] {};
+    }
+}
diff --git a/platform/src/main/java/org/conscrypt/PakeTrustManagerFactory.java b/platform/src/main/java/org/conscrypt/PakeTrustManagerFactory.java
new file mode 100644
index 00000000..f281e019
--- /dev/null
+++ b/platform/src/main/java/org/conscrypt/PakeTrustManagerFactory.java
@@ -0,0 +1,69 @@
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
+package org.conscrypt;
+
+import static java.util.Objects.requireNonNull;
+
+import java.security.InvalidAlgorithmParameterException;
+import java.security.KeyManagementException;
+import java.security.KeyStore;
+import java.security.KeyStoreException;
+import java.security.NoSuchAlgorithmException;
+import java.security.Provider;
+import java.security.Security;
+import java.security.cert.CertificateException;
+
+import javax.net.ssl.ManagerFactoryParameters;
+import javax.net.ssl.TrustManager;
+import javax.net.ssl.TrustManagerFactory;
+import javax.net.ssl.TrustManagerFactorySpi;
+
+/**
+ * A factory for creating {@link SpakeTrustManager} instances that use SPAKE2.
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class PakeTrustManagerFactory extends TrustManagerFactorySpi {
+    /**
+     * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(KeyStore)
+     */
+    @Override
+    public void engineInit(KeyStore ks) throws KeyStoreException {
+        if (ks != null) {
+            throw new KeyStoreException("KeyStore not supported");
+        }
+    }
+
+    /**
+     * @see javax.net.ssl#engineInit(ManagerFactoryParameters)
+     */
+    @Override
+    public void engineInit(ManagerFactoryParameters spec)
+            throws InvalidAlgorithmParameterException {
+        if (spec != null) {
+            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
+        }
+    }
+
+    /**
+     * @see javax.net.ssl#engineGetTrustManagers()
+     */
+    @Override
+    public TrustManager[] engineGetTrustManagers() {
+        return new TrustManager[] {new Spake2PlusTrustManager()};
+    }
+}
diff --git a/platform/src/main/java/org/conscrypt/Platform.java b/platform/src/main/java/org/conscrypt/Platform.java
index 17164747..a7ec76d7 100644
--- a/platform/src/main/java/org/conscrypt/Platform.java
+++ b/platform/src/main/java/org/conscrypt/Platform.java
@@ -29,11 +29,14 @@ import dalvik.system.VMRuntime;
 
 import libcore.net.NetworkSecurityPolicy;
 
+import org.conscrypt.NativeCrypto;
+import org.conscrypt.ct.CertificateTransparency;
 import org.conscrypt.ct.LogStore;
 import org.conscrypt.ct.LogStoreImpl;
 import org.conscrypt.ct.Policy;
 import org.conscrypt.ct.PolicyImpl;
 import org.conscrypt.flags.Flags;
+import org.conscrypt.metrics.CertificateTransparencyVerificationReason;
 import org.conscrypt.metrics.OptionalMethod;
 import org.conscrypt.metrics.Source;
 import org.conscrypt.metrics.StatsLog;
@@ -76,8 +79,7 @@ import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
-import libcore.net.NetworkSecurityPolicy;
-import org.conscrypt.NativeCrypto;
+
 import sun.security.x509.AlgorithmId;
 
 @Internal
@@ -482,7 +484,7 @@ final public class Platform {
         return true;
     }
 
-    static boolean isCTVerificationRequired(String hostname) {
+    public static boolean isCTVerificationRequired(String hostname) {
         if (Flags.certificateTransparencyPlatform()) {
             return NetworkSecurityPolicy.getInstance()
                     .isCertificateTransparencyVerificationRequired(hostname);
@@ -490,6 +492,17 @@ final public class Platform {
         return false;
     }
 
+    public static CertificateTransparencyVerificationReason reasonCTVerificationRequired(
+            String hostname) {
+        if (NetworkSecurityPolicy.getInstance().isCertificateTransparencyVerificationRequired("")) {
+            return CertificateTransparencyVerificationReason.APP_OPT_IN;
+        } else if (NetworkSecurityPolicy.getInstance()
+                           .isCertificateTransparencyVerificationRequired(hostname)) {
+            return CertificateTransparencyVerificationReason.DOMAIN_OPT_IN;
+        }
+        return CertificateTransparencyVerificationReason.UNKNOWN;
+    }
+
     static boolean supportsConscryptCertStore() {
         return true;
     }
@@ -512,12 +525,11 @@ final public class Platform {
         return CertBlocklistImpl.getDefault();
     }
 
-    static LogStore newDefaultLogStore() {
-        return new LogStoreImpl();
-    }
-
-    static Policy newDefaultPolicy() {
-        return new PolicyImpl();
+    static CertificateTransparency newDefaultCertificateTransparency() {
+        org.conscrypt.ct.Policy policy = new org.conscrypt.ct.PolicyImpl();
+        org.conscrypt.ct.LogStore logStore = new org.conscrypt.ct.LogStoreImpl(policy);
+        org.conscrypt.ct.Verifier verifier = new org.conscrypt.ct.Verifier(logStore);
+        return new CertificateTransparency(logStore, policy, verifier, getStatsLog());
     }
 
     static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
@@ -580,6 +592,10 @@ final public class Platform {
         return ENABLED_TLS_V1;
     }
 
+    public static boolean isPakeSupported() {
+        return true;
+    }
+
     static Object getTargetSdkVersion() {
         try {
             Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
@@ -595,4 +611,21 @@ final public class Platform {
             throw new RuntimeException(e);
         }
     }
+
+    public static boolean isSdkGreater(int sdk) {
+        try {
+            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
+            Method getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime");
+            Method getSdkVersionMethod =
+                        vmRuntimeClass.getDeclaredMethod("getSdkVersion");
+            Object vmRuntime = getRuntimeMethod.invoke(null);
+            Object sdkVersion = getSdkVersionMethod.invoke(vmRuntime);
+            return (sdkVersion != null) && ((int) sdkVersion > sdk);
+        } catch (IllegalAccessException |
+          NullPointerException | InvocationTargetException | NoSuchMethodException e) {
+            return false;
+        } catch (Exception e) {
+            throw new RuntimeException(e);
+        }
+    }
 }
diff --git a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
index f01e402a..e34f119b 100644
--- a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
+++ b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
@@ -43,23 +43,24 @@ import java.util.Collections;
 import java.util.Date;
 import java.util.HashMap;
 import java.util.Map;
+import java.util.function.Supplier;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 
 @Internal
 public class LogStoreImpl implements LogStore {
     private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
-    private static final String BASE_PATH = "misc/keychain/ct";
-    private static final int COMPAT_VERSION = 1;
-    private static final String CURRENT = "current";
-    private static final String LOG_LIST_FILENAME = "log_list.json";
-    private static final Path DEFAULT_LOG_LIST;
+    private static final int COMPAT_VERSION = 2;
+    private static final Path logListPrefix;
+    private static final Path logListSuffix;
+    private static final long LOG_LIST_CHECK_INTERVAL_IN_NS =
+            10L * 60 * 1_000 * 1_000_000; // 10 minutes
 
     static {
         String androidData = System.getenv("ANDROID_DATA");
-        String compatVersion = String.format("v%d", COMPAT_VERSION);
-        DEFAULT_LOG_LIST =
-                Paths.get(androidData, BASE_PATH, compatVersion, CURRENT, LOG_LIST_FILENAME);
+        // /data/misc/keychain/ct/v1/current/log_list.json
+        logListPrefix = Paths.get(androidData, "misc", "keychain", "ct");
+        logListSuffix = Paths.get("current", "log_list.json");
     }
 
     private final Path logList;
@@ -70,19 +71,41 @@ public class LogStoreImpl implements LogStore {
     private int minorVersion;
     private long timestamp;
     private Map<ByteArray, LogInfo> logs;
+    private long logListLastModified;
+    private Supplier<Long> clock;
+    private long logListLastChecked;
 
-    public LogStoreImpl() {
-        this(DEFAULT_LOG_LIST);
+    /* We do not have access to InstantSource. Implement a similar pattern using Supplier. */
+    static class SystemTimeSupplier implements Supplier<Long> {
+        @Override
+        public Long get() {
+            return System.nanoTime();
+        }
+    }
+
+    private static Path getPathForCompatVersion(int compatVersion) {
+        String version = String.format("v%d", compatVersion);
+        return logListPrefix.resolve(version).resolve(logListSuffix);
+    }
+
+    public LogStoreImpl(Policy policy) {
+        this(policy, getPathForCompatVersion(COMPAT_VERSION));
+    }
+
+    public LogStoreImpl(Policy policy, Path logList) {
+        this(policy, logList, Platform.getStatsLog());
     }
 
-    public LogStoreImpl(Path logList) {
-        this(logList, Platform.getStatsLog());
+    public LogStoreImpl(Policy policy, Path logList, StatsLog metrics) {
+        this(policy, logList, metrics, new SystemTimeSupplier());
     }
 
-    public LogStoreImpl(Path logList, StatsLog metrics) {
+    public LogStoreImpl(Policy policy, Path logList, StatsLog metrics, Supplier<Long> clock) {
         this.state = State.UNINITIALIZED;
+        this.policy = policy;
         this.logList = logList;
         this.metrics = metrics;
+        this.clock = clock;
     }
 
     @Override
@@ -108,8 +131,7 @@ public class LogStoreImpl implements LogStore {
 
     @Override
     public int getCompatVersion() {
-        // Currently, there is only one compatibility version supported. If we
-        // are loaded or initialized, it means the expected compatibility
+        // If we are loaded or initialized, it means the expected compatibility
         // version was found.
         if (state == State.LOADED || state == State.COMPLIANT || state == State.NON_COMPLIANT) {
             return COMPAT_VERSION;
@@ -119,14 +141,12 @@ public class LogStoreImpl implements LogStore {
 
     @Override
     public int getMinCompatVersionAvailable() {
+        if (Files.exists(getPathForCompatVersion(1))) {
+            return 1;
+        }
         return getCompatVersion();
     }
 
-    @Override
-    public void setPolicy(Policy policy) {
-        this.policy = policy;
-    }
-
     @Override
     public LogInfo getKnownLog(byte[] logId) {
         if (logId == null) {
@@ -146,26 +166,54 @@ public class LogStoreImpl implements LogStore {
     /* Ensures the log list is loaded.
      * Returns true if the log list is usable.
      */
-    private boolean ensureLogListIsLoaded() {
-        synchronized (this) {
-            State previousState = state;
-            if (state == State.UNINITIALIZED) {
-                state = loadLogList();
-            }
-            if (state == State.LOADED && policy != null) {
-                state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
+    private synchronized boolean ensureLogListIsLoaded() {
+        resetLogListIfRequired();
+        State previousState = state;
+        if (state == State.UNINITIALIZED) {
+            state = loadLogList();
+        }
+        if (state == State.LOADED && policy != null) {
+            state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
+        }
+        if (state != previousState) {
+            metrics.updateCTLogListStatusChanged(this);
+        }
+        return state == State.COMPLIANT;
+    }
+
+    private synchronized void resetLogListIfRequired() {
+        long now = clock.get();
+        if (this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_NS > now) {
+            return;
+        }
+        this.logListLastChecked = now;
+        try {
+            long lastModified = Files.getLastModifiedTime(logList).toMillis();
+            if (this.logListLastModified == lastModified) {
+                // The log list has the same last modified timestamp. Keep our
+                // current cached value.
+                return;
             }
-            if (state != previousState && metrics != null) {
-                metrics.updateCTLogListStatusChanged(this);
+        } catch (IOException e) {
+            if (this.logListLastModified == 0) {
+                // The log list is not accessible now and it has never been
+                // previously, there is nothing to do.
+                return;
             }
-            return state == State.COMPLIANT;
         }
+        this.state = State.UNINITIALIZED;
+        this.logs = null;
+        this.timestamp = 0;
+        this.majorVersion = 0;
+        this.minorVersion = 0;
     }
 
     private State loadLogList() {
         byte[] content;
+        long lastModified;
         try {
             content = Files.readAllBytes(logList);
+            lastModified = Files.getLastModifiedTime(logList).toMillis();
         } catch (IOException e) {
             return State.NOT_FOUND;
         }
@@ -188,33 +236,13 @@ public class LogStoreImpl implements LogStore {
             for (int i = 0; i < operators.length(); i++) {
                 JSONObject operator = operators.getJSONObject(i);
                 String operatorName = operator.getString("name");
+
                 JSONArray logs = operator.getJSONArray("logs");
-                for (int j = 0; j < logs.length(); j++) {
-                    JSONObject log = logs.getJSONObject(j);
-
-                    LogInfo.Builder builder =
-                            new LogInfo.Builder()
-                                    .setDescription(log.getString("description"))
-                                    .setPublicKey(parsePubKey(log.getString("key")))
-                                    .setUrl(log.getString("url"))
-                                    .setOperator(operatorName);
-
-                    JSONObject stateObject = log.optJSONObject("state");
-                    if (stateObject != null) {
-                        String state = stateObject.keys().next();
-                        long stateTimestamp = stateObject.getJSONObject(state).getLong("timestamp");
-                        builder.setState(parseState(state), stateTimestamp);
-                    }
-
-                    LogInfo logInfo = builder.build();
-                    byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
-
-                    // The logId computed using the public key should match the log_id field.
-                    if (!Arrays.equals(logInfo.getID(), logId)) {
-                        throw new IllegalArgumentException("logId does not match publicKey");
-                    }
-
-                    logsMap.put(new ByteArray(logId), logInfo);
+                addLogsToMap(logs, operatorName, LogInfo.TYPE_RFC6962, logsMap);
+
+                JSONArray tiledLogs = operator.optJSONArray("tiled_logs");
+                if (tiledLogs != null) {
+                    addLogsToMap(tiledLogs, operatorName, LogInfo.TYPE_STATIC_CT_API, logsMap);
                 }
             }
         } catch (JSONException | IllegalArgumentException e) {
@@ -222,9 +250,37 @@ public class LogStoreImpl implements LogStore {
             return State.MALFORMED;
         }
         this.logs = Collections.unmodifiableMap(logsMap);
+        this.logListLastModified = lastModified;
         return State.LOADED;
     }
 
+    private static void addLogsToMap(JSONArray logs, String operatorName, int logType,
+            Map<ByteArray, LogInfo> logsMap) throws JSONException {
+        for (int j = 0; j < logs.length(); j++) {
+            JSONObject log = logs.getJSONObject(j);
+            LogInfo.Builder builder = new LogInfo.Builder()
+                                              .setDescription(log.getString("description"))
+                                              .setPublicKey(parsePubKey(log.getString("key")))
+                                              .setType(logType)
+                                              .setOperator(operatorName);
+            JSONObject stateObject = log.optJSONObject("state");
+            if (stateObject != null) {
+                String state = stateObject.keys().next();
+                long stateTimestamp = stateObject.getJSONObject(state).getLong("timestamp");
+                builder.setState(parseState(state), stateTimestamp);
+            }
+            LogInfo logInfo = builder.build();
+
+            // The logId computed using the public key should match the log_id field.
+            byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
+            if (!Arrays.equals(logInfo.getID(), logId)) {
+                throw new IllegalArgumentException("logId does not match publicKey");
+            }
+
+            logsMap.put(new ByteArray(logId), logInfo);
+        }
+    }
+
     private static int parseMajorVersion(String version) {
         int pos = version.indexOf(".");
         if (pos == -1) {
diff --git a/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java b/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
index 652745dc..e27d9b75 100644
--- a/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
+++ b/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
@@ -178,7 +178,7 @@ public class PolicyImpl implements Policy {
             return PolicyCompliance.NOT_ENOUGH_SCTS;
         }
 
-        /* 3. Among the SCTs satisfying requirements 1 and 2, at least two SCTs
+        /* 3. Among the SCTs satisfying requirements 2, at least two SCTs
          *    must be issued from distinct CT Log Operators as recognized by
          *    Chrome.
          */
@@ -190,6 +190,20 @@ public class PolicyImpl implements Policy {
             return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
         }
 
+        /* 4. Among the SCTs satisfying requirement 2, at least one SCT must be
+         * issued from a log recognized by Chrome as being RFC6962-compliant.
+         */
+        boolean foundRfc6962Log = false;
+        for (LogInfo logInfo : validLogs) {
+            if (logInfo.getType() == LogInfo.TYPE_RFC6962) {
+                foundRfc6962Log = true;
+                break;
+            }
+        }
+        if (!foundRfc6962Log) {
+            return PolicyCompliance.NO_RFC6962_LOG;
+        }
+
         return PolicyCompliance.COMPLY;
     }
 
@@ -223,6 +237,20 @@ public class PolicyImpl implements Policy {
             return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
         }
 
+        /* 3. Among the SCTs satisfying requirement 1, at least one SCT must be
+         * issued from a log recognized by Chrome as being RFC6962-compliant.
+         */
+        boolean foundRfc6962Log = false;
+        for (LogInfo logInfo : validLogs) {
+            if (logInfo.getType() == LogInfo.TYPE_RFC6962) {
+                foundRfc6962Log = true;
+                break;
+            }
+        }
+        if (!foundRfc6962Log) {
+            return PolicyCompliance.NO_RFC6962_LOG;
+        }
+
         return PolicyCompliance.COMPLY;
     }
 }
diff --git a/platform/src/test/java/org/conscrypt/AndroidHpkeSpiTest.java b/platform/src/test/java/org/conscrypt/AndroidHpkeSpiTest.java
new file mode 100644
index 00000000..2545c2e1
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/AndroidHpkeSpiTest.java
@@ -0,0 +1,57 @@
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
+package org.conscrypt;
+
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.Provider;
+
+@RunWith(JUnit4.class)
+public class AndroidHpkeSpiTest {
+    private static final String[] HPKE_NAMES = new String[]{
+            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
+            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
+            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305"
+    };
+
+    // This only needs to test the wrapper functionality as the implementation and client
+    // APIs are tested elsewhere.  What we're looking for is that HPKE SPI instances returned
+    // by the provider are *always* instances of Conscrypt's HpkeSpi and *always* usable by
+    // a Conscrypt duck typed SPI.  And if the Android platform SPI class is available then
+    // they should also be usable as instances of that.
+    @Test
+    public void functionalTest() throws Exception {
+        Class<?> conscryptSpiClass = HpkeSpi.class;
+        Class<?> platformSpiClass = TestUtils.findClass("android.crypto.hpke.HpkeSpi");
+        Provider provider = TestUtils.getConscryptProvider();
+        for (String algorithm : HPKE_NAMES) {
+            Object spi = provider.getService("ConscryptHpke", algorithm)
+                    .newInstance(null);
+            assertNotNull(spi);
+            if (platformSpiClass != null) {
+                assertTrue(platformSpiClass.isAssignableFrom(spi.getClass()));
+            }
+            assertTrue(conscryptSpiClass.isAssignableFrom(spi.getClass()));
+            assertNotNull(DuckTypedHpkeSpi.newInstance(spi));
+        }
+    }
+}
\ No newline at end of file
diff --git a/platform/src/test/java/org/conscrypt/CertBlocklistTest.java b/platform/src/test/java/org/conscrypt/CertBlocklistTest.java
index 4d9a5c14..4c89e187 100644
--- a/platform/src/test/java/org/conscrypt/CertBlocklistTest.java
+++ b/platform/src/test/java/org/conscrypt/CertBlocklistTest.java
@@ -16,6 +16,9 @@
 
 package org.conscrypt;
 
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
 import java.io.InputStream;
 import java.security.KeyStore;
 import java.security.cert.Certificate;
@@ -24,9 +27,13 @@ import java.security.cert.CertificateFactory;
 import java.security.cert.X509Certificate;
 import java.util.Collection;
 import javax.net.ssl.X509TrustManager;
-import junit.framework.TestCase;
 
-public class CertBlocklistTest extends TestCase {
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class CertBlocklistTest {
 
     private static final String BLOCKLIST_CA = "test_blocklist_ca.pem";
     private static final String BLOCKLIST_CA2 = "test_blocklist_ca2.pem";
@@ -37,6 +44,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Ensure that the test blocklisted CA is actually blocklisted by default.
      */
+    @Test
     public void testBlocklistedPublicKey() throws Exception {
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
         CertBlocklist blocklist = CertBlocklistImpl.getDefault();
@@ -46,6 +54,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Ensure that the test blocklisted CA 2 is actually blocklisted by default.
      */
+    @Test
     public void testBlocklistedPublicKeySHA256() throws Exception {
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA2);
         CertBlocklist blocklist = CertBlocklistImpl.getDefault();
@@ -55,6 +64,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Check that the blocklisted CA is rejected even if it used as a root of trust
      */
+    @Test
     public void testBlocklistedCaUntrusted() throws Exception {
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
         assertUntrusted(new X509Certificate[] {blocklistedCa}, getTrustManager(blocklistedCa));
@@ -63,6 +73,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Check that a chain that is rooted in a blocklisted trusted CA is rejected.
      */
+    @Test
     public void testBlocklistedRootOfTrust() throws Exception {
         // Chain is leaf -> blocklisted
         X509Certificate[] chain = loadCertificates(BLOCKLISTED_CHAIN);
@@ -79,6 +90,7 @@ public class CertBlocklistTest extends TestCase {
      *               \
      *                -------> trusted_ca
      */
+    @Test
     public void testBlocklistedIntermediateFallback() throws Exception {
         X509Certificate[] chain = loadCertificates(BLOCKLISTED_VALID_CHAIN);
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
diff --git a/platform/src/test/java/org/conscrypt/PakeKeyManagerFactoryTest.java b/platform/src/test/java/org/conscrypt/PakeKeyManagerFactoryTest.java
new file mode 100644
index 00000000..5e177706
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/PakeKeyManagerFactoryTest.java
@@ -0,0 +1,145 @@
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
+package org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeServerKeyManagerParameters;
+import android.net.ssl.PakeOption;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.KeyStoreException;
+import java.util.Arrays;
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactory;
+
+@RunWith(JUnit4.class)
+public class PakeKeyManagerFactoryTest {
+    private static final byte[] PASSWORD = new byte[] {1, 2, 3};
+    private static final byte[] CLIENT_ID = new byte[] {2, 3, 4};
+    private static final byte[] SERVER_ID = new byte[] {4, 5, 6};
+
+    @Test
+    public void pakeKeyManagerFactoryTest() throws Exception {
+        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
+        assertThrows(KeyStoreException.class, () -> kmf.init(null, null));
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", PASSWORD)
+                        .build();
+
+        PakeClientKeyManagerParameters params =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        kmf.init(params);
+
+        KeyManager[] keyManagers = kmf.getKeyManagers();
+        assertEquals(1, keyManagers.length);
+
+        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
+        assertArrayEquals(PASSWORD, keyManager.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManager.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManager.getIdVerifier());
+    }
+
+    @Test
+    public void pakeKeyManagerFactoryTestHanshakeLimitClient() throws Exception {
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", PASSWORD)
+                        .addMessageComponent("client-handshake-limit", new byte[] {16})
+                        .build();
+
+        // Client
+        PakeClientKeyManagerParameters paramsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(paramsClient);
+
+        Spake2PlusKeyManager keyManagerClient = (Spake2PlusKeyManager) kmfClient.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerClient.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerClient.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerClient.getIdVerifier());
+        assertEquals(16, keyManagerClient.getHandshakeLimit());
+
+        // Server
+        PakeServerKeyManagerParameters paramsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(paramsServer);
+
+        Spake2PlusKeyManager keyManagerServer = (Spake2PlusKeyManager) kmfServer.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerServer.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerServer.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerServer.getIdVerifier());
+        assertEquals(1, keyManagerServer.getHandshakeLimit());
+    }
+
+    @Test
+    public void pakeKeyManagerFactoryTestHanshakeLimitServer() throws Exception {
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", PASSWORD)
+                        .addMessageComponent("server-handshake-limit", new byte[] {16})
+                        .build();
+
+        // Client
+        PakeClientKeyManagerParameters paramsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(paramsClient);
+
+        Spake2PlusKeyManager keyManagerClient = (Spake2PlusKeyManager) kmfClient.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerClient.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerClient.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerClient.getIdVerifier());
+        assertEquals(1, keyManagerClient.getHandshakeLimit());
+
+        // Server
+        PakeServerKeyManagerParameters paramsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(paramsServer);
+
+        Spake2PlusKeyManager keyManagerServer = (Spake2PlusKeyManager) kmfServer.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerServer.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerServer.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerServer.getIdVerifier());
+        assertEquals(16, keyManagerServer.getHandshakeLimit());
+    }
+}
diff --git a/platform/src/test/java/org/conscrypt/PakeManagerFactoriesTest.java b/platform/src/test/java/org/conscrypt/PakeManagerFactoriesTest.java
new file mode 100644
index 00000000..97ed4610
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/PakeManagerFactoriesTest.java
@@ -0,0 +1,102 @@
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
+package org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeOption;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.InvalidAlgorithmParameterException;
+import java.security.KeyStoreException;
+
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.ManagerFactoryParameters;
+import javax.net.ssl.TrustManager;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+public class PakeManagerFactoriesTest {
+    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
+    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
+
+    @Test
+    public void testEngineInitParameters() throws InvalidAlgorithmParameterException {
+        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();
+
+        byte[] password = new byte[] {1, 2, 3};
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", password)
+                                    .build();
+
+        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));
+
+        PakeClientKeyManagerParameters params =
+                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
+        // Initialize with valid parameters
+        keyManagerFactory.engineInit(params);
+        // Try to initialize again
+        assertThrows(IllegalStateException.class, () -> keyManagerFactory.engineInit(params));
+
+        PakeTrustManagerFactory trustManagerFactory = new PakeTrustManagerFactory();
+        // The trust manager factory does not accept parameters
+        assertThrows(InvalidAlgorithmParameterException.class,
+                () -> trustManagerFactory.engineInit(params));
+        trustManagerFactory.engineInit((ManagerFactoryParameters) null);
+    }
+
+    @Test
+    public void testEngineGetKeyManagers() throws InvalidAlgorithmParameterException {
+        PakeKeyManagerFactory factory = new PakeKeyManagerFactory();
+        assertThrows(IllegalStateException.class, () -> factory.engineGetKeyManagers());
+
+        byte[] password = new byte[] {1, 2, 3};
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", password)
+                                    .build();
+
+        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
+                                                        .setClientId(CLIENT_ID.clone())
+                                                        .setServerId(SERVER_ID.clone())
+                                                        .addOption(option)
+                                                        .build();
+
+        factory.engineInit(params);
+        KeyManager[] keyManagers = factory.engineGetKeyManagers();
+        assertEquals(1, keyManagers.length);
+
+        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
+        assertArrayEquals(password, keyManager.getPassword());
+        assertArrayEquals(new byte[] {4, 5, 6}, keyManager.getIdProver());
+        assertArrayEquals(new byte[] {7, 8, 9}, keyManager.getIdVerifier());
+    }
+
+    @Test
+    public void testEngineGetTrustManagers() {
+        PakeTrustManagerFactory factory = new PakeTrustManagerFactory();
+        TrustManager[] trustManagers = factory.engineGetTrustManagers();
+        assertEquals(1, trustManagers.length);
+        assertEquals(Spake2PlusTrustManager.class, trustManagers[0].getClass());
+    }
+}
diff --git a/platform/src/test/java/org/conscrypt/SpakeTest.java b/platform/src/test/java/org/conscrypt/SpakeTest.java
new file mode 100644
index 00000000..ce5c7163
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/SpakeTest.java
@@ -0,0 +1,549 @@
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
+package org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeOption;
+import android.net.ssl.PakeServerKeyManagerParameters;
+
+import org.conscrypt.Spake2PlusKeyManager;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.net.InetAddress;
+import java.net.InetSocketAddress;
+import java.net.Socket;
+import java.security.KeyManagementException;
+import java.util.Arrays;
+import java.util.concurrent.Callable;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+import java.util.concurrent.Future;
+import javax.net.SocketFactory;
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactory;
+import javax.net.ssl.ManagerFactoryParameters;
+import javax.net.ssl.SSLContext;
+import javax.net.ssl.SSLEngine;
+import javax.net.ssl.SSLHandshakeException;
+import javax.net.ssl.SSLServerSocket;
+import javax.net.ssl.SSLSocket;
+import javax.net.ssl.SSLSocketFactory;
+import javax.net.ssl.TrustManager;
+import javax.net.ssl.TrustManagerFactory;
+
+import tests.util.Pair;
+
+@RunWith(JUnit4.class)
+public class SpakeTest {
+    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
+    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
+    private final ThreadGroup threadGroup = new ThreadGroup("SpakeTest");
+    private final ExecutorService executor =
+            Executors.newCachedThreadPool(t -> new Thread(threadGroup, t));
+
+    private Pair<SSLContext, SSLContext> createContexts(
+            PakeClientKeyManagerParameters clientParams,
+            PakeServerKeyManagerParameters serverParams)
+            throws Exception {
+        InetAddress hostC = TestUtils.getLoopbackAddress();
+        InetAddress hostS = TestUtils.getLoopbackAddress();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(clientParams);
+        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
+        assertTrue(keyManagersClient.length == 1);
+        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spake2PlusKeyManagerClient =
+                (Spake2PlusKeyManager) keyManagersClient[0];
+        assertTrue(spake2PlusKeyManagerClient.isClient());
+        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
+        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);
+
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(serverParams);
+        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
+        assertTrue(keyManagersServer.length == 1);
+        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
+        assertFalse(spakeKeyManagerServer.isClient());
+
+        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
+        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);
+        return Pair.of(contextClient, contextServer);
+    }
+
+    private SSLContext createClientContext(
+            PakeClientKeyManagerParameters clientParams)
+            throws Exception {
+        InetAddress hostC = TestUtils.getLoopbackAddress();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(clientParams);
+        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
+        assertTrue(keyManagersClient.length == 1);
+        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spake2PlusKeyManagerClient =
+                (Spake2PlusKeyManager) keyManagersClient[0];
+        assertTrue(spake2PlusKeyManagerClient.isClient());
+        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
+        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);
+        return contextClient;
+    }
+
+    private SSLContext createServerContext(
+            PakeServerKeyManagerParameters serverParams)
+            throws Exception {
+        InetAddress hostS = TestUtils.getLoopbackAddress();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(serverParams);
+        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
+        assertTrue(keyManagersServer.length == 1);
+        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
+        assertFalse(spakeKeyManagerServer.isClient());
+
+        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
+        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);
+        return contextServer;
+    }
+
+    private Pair<SSLSocket, SSLSocket> createSockets(Pair<SSLContext, SSLContext> contexts)
+            throws Exception {
+        InetAddress hostC = TestUtils.getLoopbackAddress();
+        InetAddress hostS = TestUtils.getLoopbackAddress();
+        SSLServerSocket serverSocket =
+                (SSLServerSocket)
+                        contexts.getSecond().getServerSocketFactory().createServerSocket();
+        serverSocket.bind(new InetSocketAddress(hostS, 0));
+        SSLSocket client =
+                (SSLSocket)
+                        contexts.getFirst()
+                                .getSocketFactory()
+                                .createSocket(hostC, serverSocket.getLocalPort());
+        SSLSocket server = (SSLSocket) serverSocket.accept();
+
+        assertTrue(client.getUseClientMode());
+        return Pair.of(client, server);
+    }
+
+    private void connectSockets(Pair<SSLSocket, SSLSocket> sockets)
+            throws Exception {
+        SSLSocket client = sockets.getFirst();
+        SSLSocket server = sockets.getSecond();
+        Future<Void> s =
+                runAsync(
+                        () -> {
+                            server.startHandshake();
+                            return null;
+                        });
+        client.startHandshake();
+        s.get();
+    }
+
+    private void sendData(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
+        SSLSocket client = sockets.getFirst();
+        SSLSocket server = sockets.getSecond();
+        byte[] readBytes = new byte[3];
+        server.getOutputStream().write(new byte[] {1, 2, 3});
+        client.getOutputStream().write(new byte[] {4, 5, 6});
+        server.getInputStream().read(readBytes, 0, 3);
+        assertArrayEquals(new byte[] {4, 5, 6}, readBytes);
+        client.getInputStream().read(readBytes, 0, 3);
+        assertArrayEquals(new byte[] {1, 2, 3}, readBytes);
+    }
+
+    private void closeSockets(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
+        sockets.getFirst().close();
+        sockets.getSecond().close();
+    }
+
+    @Test
+    public void testSpake2PlusPassword() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
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
+        connectSockets(sockets);
+        sendData(sockets);
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusPasswordMultipleConnections() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
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
+
+        for (int i = 0; i < 10; i++) {
+            Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+            connectSockets(sockets);
+            sendData(sockets);
+            closeSockets(sockets);
+        }
+    }
+
+    @Test
+    public void testSpake2PlusPasswordHandshakeServerLimit() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+        byte[] password2 = new byte[] {4, 5, 6};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .addMessageComponent("server-handshake-limit", new byte[] {16})
+                        .addMessageComponent("client-handshake-limit", new byte[] {24})
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password2)
+                        .addMessageComponent("server-handshake-limit", new byte[] {16})
+                        .addMessageComponent("client-handshake-limit", new byte[] {24})
+                        .build();
+
+        // Client uses wrong password first
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option2)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+
+        Pair<SSLContext, SSLContext> failingContexts = createContexts(kmfParamsClient, kmfParamsServer);
+
+        // Server handshake limit is 16, so it is ok if 15 connections fail.
+        for (int i = 0; i < 15; i++) {
+            Pair<SSLSocket, SSLSocket> sockets;
+            sockets = createSockets(failingContexts);
+            assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        }
+
+        // 16th connection should succeed (but requires a new client)
+        kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        SSLContext workingClientContext = createClientContext(kmfParamsClient);
+        Pair<SSLContext, SSLContext> workingContexts = Pair.of(workingClientContext, failingContexts.getSecond());
+        Pair<SSLSocket, SSLSocket> workingSockets1 = createSockets(workingContexts);
+        connectSockets(workingSockets1);
+        sendData(workingSockets1);
+        closeSockets(workingSockets1);
+
+        // After one more failure, all connections should fail.
+        Pair<SSLSocket, SSLSocket> failingSockets = createSockets(failingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(failingSockets));
+        Pair<SSLSocket, SSLSocket> workingSockets2 = createSockets(workingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(workingSockets2));
+    }
+
+    @Test
+    public void testSpake2PlusPasswordHandshakeClientLimit() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+        byte[] password2 = new byte[] {4, 5, 6};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .addMessageComponent("server-handshake-limit", new byte[] {24})
+                        .addMessageComponent("client-handshake-limit", new byte[] {16})
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password2)
+                        .addMessageComponent("server-handshake-limit", new byte[] {24})
+                        .addMessageComponent("client-handshake-limit", new byte[] {16})
+                        .build();
+
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        // Server uses wrong password first
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> failingContexts = createContexts(kmfParamsClient, kmfParamsServer);
+
+        // Server handshake limit is 16, so it is ok if 15 connections fail.
+        for (int i = 0; i < 15; i++) {
+            Pair<SSLSocket, SSLSocket> sockets;
+            sockets = createSockets(failingContexts);
+            assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        }
+
+        // 16th connection should succeed (but requires a new server)
+        kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+        SSLContext workingServerContext = createServerContext(kmfParamsServer);
+        Pair<SSLContext, SSLContext> workingContexts = Pair.of(failingContexts.getFirst(), workingServerContext);
+        Pair<SSLSocket, SSLSocket> workingSockets1 = createSockets(workingContexts);
+        connectSockets(workingSockets1);
+        sendData(workingSockets1);
+        closeSockets(workingSockets1);
+
+        // After one more failure, all connections should fail.
+        Pair<SSLSocket, SSLSocket> failingSockets = createSockets(failingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(failingSockets));
+        Pair<SSLSocket, SSLSocket> workingSockets2 = createSockets(workingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(workingSockets2));
+    }
+
+    @Test
+    public void testSpake2PlusMismatchedPassword() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+        byte[] password2 = new byte[] {4, 5, 6};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password2)
+                        .build();
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
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusMismatchedIds() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        // Client ID is different from the one in the server.
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(new byte[] {6})
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusEmptyIds() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(new byte[0])
+                        .setServerId(new byte[0])
+                        .addOption(option)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(new byte[0], new byte[0], Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        connectSockets(sockets);
+        sendData(sockets);
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusAndOthersInvalid() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        PakeClientKeyManagerParameters pakeParams =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
+        kmf.init(pakeParams);
+
+        KeyManager[] keyManagers = kmf.getKeyManagers();
+
+        KeyManagerFactory kmf2 =
+                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
+        kmf2.init(null, null);
+
+        // Add a x509 key manager to the array.
+        KeyManager[] keyManagersWithx509 = Arrays.copyOf(keyManagers, keyManagers.length + 1);
+
+        keyManagersWithx509[keyManagers.length] = kmf2.getKeyManagers()[0];
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+        TrustManager[] trustManagers = tmf.getTrustManagers();
+
+        SSLContext sslContext = SSLContext.getInstance("TlsV1.3");
+        // Should throw due to both SPAKE and x509 key managers
+        assertThrows(
+                KeyManagementException.class,
+                () -> sslContext.init(keyManagersWithx509, trustManagers, null));
+    }
+
+    @Test
+    public void testSpake2PlusNoTrustOrKeyInvalid() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        PakeClientKeyManagerParameters pakeParams =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
+        kmf.init(pakeParams);
+
+        KeyManager[] keyManagers = kmf.getKeyManagers();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+        TrustManager[] trustManagers = tmf.getTrustManagers();
+
+        SSLContext sslContext = SSLContext.getInstance("TlsV1.3");
+        assertThrows(KeyManagementException.class, () -> sslContext.init(keyManagers, null, null));
+
+        assertThrows(
+                KeyManagementException.class, () -> sslContext.init(null, trustManagers, null));
+    }
+
+    private <T> Future<T> runAsync(Callable<T> callable) {
+        return executor.submit(callable);
+    }
+}
diff --git a/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java b/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java
index ca36e0ad..d4b360fb 100644
--- a/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java
+++ b/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java
@@ -163,4 +163,4 @@ public class TlsDeprecationTest {
     public void testInitializeUndeprecatedDisabled_36() {
         assertThrows(RuntimeException.class, () -> TestUtils.getConscryptProvider(false, false));
     }
-}
\ No newline at end of file
+}
diff --git a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
index 719cbf36..62cc8e0a 100644
--- a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
+++ b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
@@ -16,34 +16,35 @@
 
 package org.conscrypt.ct;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
+
 import static java.nio.charset.StandardCharsets.US_ASCII;
 import static java.nio.charset.StandardCharsets.UTF_8;
 
-import junit.framework.TestCase;
-
 import org.conscrypt.OpenSSLKey;
-import org.conscrypt.metrics.StatsLog;
+import org.conscrypt.metrics.NoopStatsLog;
+import org.junit.After;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 import java.io.ByteArrayInputStream;
-import java.io.File;
-import java.io.FileNotFoundException;
-import java.io.FileOutputStream;
-import java.io.FileWriter;
 import java.io.IOException;
-import java.io.OutputStreamWriter;
-import java.io.PrintWriter;
-import java.security.PublicKey;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
 import java.security.cert.X509Certificate;
 import java.util.ArrayList;
 import java.util.Base64;
+import java.util.function.Supplier;
 
-public class LogStoreImplTest extends TestCase {
-    static class FakeStatsLog implements StatsLog {
+@RunWith(JUnit4.class)
+public class LogStoreImplTest {
+    /** FakeStatsLog captures the events being reported */
+    static class FakeStatsLog extends NoopStatsLog {
         public ArrayList<LogStore.State> states = new ArrayList<LogStore.State>();
 
-        @Override
-        public void countTlsHandshake(
-                boolean success, String protocol, String cipherSuite, long duration) {}
         @Override
         public void updateCTLogListStatusChanged(LogStore logStore) {
             states.add(logStore.getState());
@@ -74,9 +75,26 @@ public class LogStoreImplTest extends TestCase {
         }
     };
 
-    public void test_loadValidLogList() throws Exception {
-        // clang-format off
-        String content = "" +
+    /* Time supplier that can be set to any arbitrary time */
+    static class TimeSupplier implements Supplier<Long> {
+        private long currentTimeInNs;
+
+        TimeSupplier(long currentTimeInNs) {
+            this.currentTimeInNs = currentTimeInNs;
+        }
+
+        @Override
+        public Long get() {
+            return currentTimeInNs;
+        }
+
+        public void setCurrentTimeInNs(long currentTimeInNs) {
+            this.currentTimeInNs = currentTimeInNs;
+        }
+    }
+
+    // clang-format off
+    static final String validLogList = "" +
 "{" +
 "  \"version\": \"1.1\"," +
 "  \"log_list_timestamp\": 1704070861000," +
@@ -139,74 +157,171 @@ public class LogStoreImplTest extends TestCase {
 "            \"end_exclusive\": 1735693261000" +
 "          }" +
 "        }" +
+"      ]," +
+"      \"tiled_logs\": [" +
+"        {" +
+"         \"description\": \"Operator 2 'Test2025' log\"," +
+"          \"log_id\": \"DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB/we6GOO/xwxivy4HhkrYFAAPo6e2nc346Wo2o2U+GvoPWSPJz91s/xrEvA3Bk9kWHUUXVZS5morFEzsgdHqPg==\"," +
+"          \"submission_url\": \"https://operator2.example.com/tiled/test2025\"," +
+"          \"monitoring_url\": \"https://operator2.exmaple.com/tiled_monitor/test2025\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": 1727734767000" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": 1767225600000," +
+"            \"end_exclusive\": 1782864000000" +
+"          }" +
+"        }" +
 "      ]" +
 "    }" +
 "  ]" +
 "}";
-        // clang-format on
+    // clang-format on
 
-        FakeStatsLog metrics = new FakeStatsLog();
-        File logList = writeFile(content);
-        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
-        store.setPolicy(alwaysCompliantStorePolicy);
+    Path grandparentDir;
+    Path parentDir;
+    Path logList;
 
-        assertNull("A null logId should return null", store.getKnownLog(null));
+    @After
+    public void tearDown() throws Exception {
+        if (logList != null) {
+            Files.deleteIfExists(logList);
+            Files.deleteIfExists(parentDir);
+            Files.deleteIfExists(grandparentDir);
+        }
+    }
 
+    @Test
+    public void loadValidLogList_returnsCompliantState() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
         byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                 + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
                 + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
                 + "\n-----END PUBLIC KEY-----\n")
                              .getBytes(US_ASCII);
         ByteArrayInputStream is = new ByteArrayInputStream(pem);
-
         LogInfo log1 =
                 new LogInfo.Builder()
                         .setPublicKey(OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey())
                         .setDescription("Operator 1 'Test2024' log")
-                        .setUrl("https://operator1.example.com/logs/test2024/")
+                        .setType(LogInfo.TYPE_RFC6962)
                         .setState(LogInfo.STATE_USABLE, 1667328840000L)
                         .setOperator("Operator 1")
                         .build();
         byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
+
+        assertNull("A null logId should return null", store.getKnownLog(/* logId= */ null));
         assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
-        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
         assertEquals("The metric update for log list state should be compliant",
-                metrics.states.get(0), LogStore.State.COMPLIANT);
+                LogStore.State.COMPLIANT, metrics.states.get(0));
     }
 
-    public void test_loadMalformedLogList() throws Exception {
+    @Test
+    public void loadMalformedLogList_returnsMalformedState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         String content = "}}";
-        File logList = writeFile(content);
-        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
-        store.setPolicy(alwaysCompliantStorePolicy);
+        logList = writeLogList(content);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
 
         assertEquals(
-                "The log state should be malformed", store.getState(), LogStore.State.MALFORMED);
-        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+                "The log state should be malformed", LogStore.State.MALFORMED, store.getState());
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
         assertEquals("The metric update for log list state should be malformed",
-                metrics.states.get(0), LogStore.State.MALFORMED);
+                LogStore.State.MALFORMED, metrics.states.get(0));
     }
 
-    public void test_loadMissingLogList() throws Exception {
+    @Test
+    public void loadMissingLogList_returnsNotFoundState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
-        File logList = new File("does_not_exist");
-        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
-        store.setPolicy(alwaysCompliantStorePolicy);
+        Path missingLogList = Paths.get("missing_dir", "missing_subdir", "does_not_exist_log_list");
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics);
 
         assertEquals(
-                "The log state should be not found", store.getState(), LogStore.State.NOT_FOUND);
-        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
         assertEquals("The metric update for log list state should be not found",
-                metrics.states.get(0), LogStore.State.NOT_FOUND);
+                LogStore.State.NOT_FOUND, metrics.states.get(0));
     }
 
-    private File writeFile(String content) throws IOException {
-        File file = File.createTempFile("test", null);
-        file.deleteOnExit();
-        try (FileWriter fw = new FileWriter(file)) {
-            fw.write(content);
-        }
+    @Test
+    public void loadMissingAndThenFoundLogList_logListIsLoaded() throws Exception {
+        // Arrange
+        FakeStatsLog metrics = new FakeStatsLog();
+        // Allocate a temporary file path and delete it. We keep the temporary
+        // path so that we can add a valid log list later on.
+        logList = writeLogList("");
+        Files.deleteIfExists(logList);
+        Files.deleteIfExists(parentDir);
+        Files.deleteIfExists(grandparentDir);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals(
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+
+        // Act
+        Files.createDirectory(grandparentDir);
+        Files.createDirectory(parentDir);
+        Files.write(logList, validLogList.getBytes());
+
+        // Assert
+        // 10ns < 10min, we should not check the log list yet.
+        fakeTime.setCurrentTimeInNs(10);
+        assertEquals(
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+
+        // 12min, the log list should be reloadable.
+        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        assertEquals(
+                "The log state should be compliant", LogStore.State.COMPLIANT, store.getState());
+    }
+
+    @Test
+    public void loadExistingAndThenRemovedLogList_logListIsNotFound() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
+
+        Files.delete(logList);
+        // 12min, the log list should be reloadable.
+        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+
+        assertEquals(
+                "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
+    }
+
+    @Test
+    public void loadExistingLogListAndThenMoveDirectory_logListIsNotFound() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
+
+        Path oldParentDir = parentDir;
+        parentDir = grandparentDir.resolve("more_current");
+        Files.move(oldParentDir, parentDir);
+        logList = parentDir.resolve("log_list.json");
+        // 12min, the log list should be reloadable.
+        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+
+        assertEquals(
+                "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
+    }
+
+    private Path writeLogList(String content) throws IOException {
+        grandparentDir = Files.createTempDirectory("v1");
+        parentDir = Files.createDirectory(grandparentDir.resolve("current"));
+        Path file = Files.createFile(parentDir.resolve("log_list.json"));
+        Files.write(file, content.getBytes());
         return file;
     }
 }
diff --git a/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java b/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
index cbee4ace..f382f132 100644
--- a/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
+++ b/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
@@ -36,9 +36,11 @@ public class PolicyImplTest {
     private static final String OPERATOR2 = "operator 2";
     private static LogInfo usableOp1Log1;
     private static LogInfo usableOp1Log2;
+    private static LogInfo usableStaticOp1Log;
     private static LogInfo retiredOp1LogOld;
     private static LogInfo retiredOp1LogNew;
     private static LogInfo usableOp2Log;
+    private static LogInfo usableStaticOp2Log;
     private static LogInfo retiredOp2Log;
     private static SignedCertificateTimestamp embeddedSCT;
     private static SignedCertificateTimestamp ocspSCT;
@@ -89,37 +91,49 @@ public class PolicyImplTest {
          */
         usableOp1Log1 = new LogInfo.Builder()
                                 .setPublicKey(new FakePublicKey(new byte[] {0x01}))
-                                .setUrl("")
+                                .setType(LogInfo.TYPE_RFC6962)
                                 .setOperator(OPERATOR1)
                                 .setState(LogInfo.STATE_USABLE, JAN2022)
                                 .build();
         usableOp1Log2 = new LogInfo.Builder()
                                 .setPublicKey(new FakePublicKey(new byte[] {0x02}))
-                                .setUrl("")
+                                .setType(LogInfo.TYPE_RFC6962)
                                 .setOperator(OPERATOR1)
                                 .setState(LogInfo.STATE_USABLE, JAN2022)
                                 .build();
+        usableStaticOp1Log = new LogInfo.Builder()
+                                     .setPublicKey(new FakePublicKey(new byte[] {0x07}))
+                                     .setType(LogInfo.TYPE_STATIC_CT_API)
+                                     .setOperator(OPERATOR1)
+                                     .setState(LogInfo.STATE_USABLE, JAN2022)
+                                     .build();
         retiredOp1LogOld = new LogInfo.Builder()
                                    .setPublicKey(new FakePublicKey(new byte[] {0x03}))
-                                   .setUrl("")
+                                   .setType(LogInfo.TYPE_RFC6962)
                                    .setOperator(OPERATOR1)
                                    .setState(LogInfo.STATE_RETIRED, JAN2022)
                                    .build();
         retiredOp1LogNew = new LogInfo.Builder()
                                    .setPublicKey(new FakePublicKey(new byte[] {0x06}))
-                                   .setUrl("")
+                                   .setType(LogInfo.TYPE_RFC6962)
                                    .setOperator(OPERATOR1)
                                    .setState(LogInfo.STATE_RETIRED, JUN2023)
                                    .build();
         usableOp2Log = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x04}))
-                               .setUrl("")
+                               .setType(LogInfo.TYPE_RFC6962)
                                .setOperator(OPERATOR2)
                                .setState(LogInfo.STATE_USABLE, JAN2022)
                                .build();
+        usableStaticOp2Log = new LogInfo.Builder()
+                                     .setPublicKey(new FakePublicKey(new byte[] {0x08}))
+                                     .setType(LogInfo.TYPE_STATIC_CT_API)
+                                     .setOperator(OPERATOR2)
+                                     .setState(LogInfo.STATE_USABLE, JAN2022)
+                                     .build();
         retiredOp2Log = new LogInfo.Builder()
                                 .setPublicKey(new FakePublicKey(new byte[] {0x05}))
-                                .setUrl("")
+                                .setType(LogInfo.TYPE_RFC6962)
                                 .setOperator(OPERATOR2)
                                 .setState(LogInfo.STATE_RETIRED, JAN2022)
                                 .build();
@@ -371,11 +385,76 @@ public class PolicyImplTest {
                 p.doesResultConformToPolicyAt(result, leaf, JAN2024));
     }
 
+    public void validVerificationResultPartialStatic(SignedCertificateTimestamp sct)
+            throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableStaticOp2Log)
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
+    public void validEmbeddedVerificationResultPartialStatic() throws Exception {
+        validVerificationResultPartialStatic(embeddedSCT);
+    }
+
+    @Test
+    public void validOCSPVerificationResultPartialStatic() throws Exception {
+        validVerificationResultPartialStatic(ocspSCT);
+    }
+
+    public void invalidTwoSctsAllStatic(SignedCertificateTimestamp sct) throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableStaticOp1Log)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableStaticOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two static SCTs", PolicyCompliance.NO_RFC6962_LOG,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    public void invalidEmbeddedTwoSctsAllStaticsVerificationResult() throws Exception {
+        invalidTwoSctsAllStatic(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPTwoSctsAllStaticsVerificationResult() throws Exception {
+        invalidTwoSctsAllStatic(ocspSCT);
+    }
+
     @Test
     public void validRecentLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        LogStore store = new LogStoreImpl() {
+        LogStore store = new LogStoreImpl(p) {
             @Override
             public long getTimestamp() {
                 return DEC2023;
@@ -388,7 +467,7 @@ public class PolicyImplTest {
     public void invalidFutureLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        LogStore store = new LogStoreImpl() {
+        LogStore store = new LogStoreImpl(p) {
             @Override
             public long getTimestamp() {
                 return JAN2025;
@@ -401,7 +480,7 @@ public class PolicyImplTest {
     public void invalidOldLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        LogStore store = new LogStoreImpl() {
+        LogStore store = new LogStoreImpl(p) {
             @Override
             public long getTimestamp() {
                 return JAN2023;
diff --git a/platform/src/test/java/org/conscrypt/metrics/MetricsTest.java b/platform/src/test/java/org/conscrypt/metrics/MetricsTest.java
index 5a7a9e62..6180f621 100644
--- a/platform/src/test/java/org/conscrypt/metrics/MetricsTest.java
+++ b/platform/src/test/java/org/conscrypt/metrics/MetricsTest.java
@@ -19,6 +19,7 @@ package org.conscrypt.metrics;
 import static org.junit.Assert.assertEquals;
 
 import android.util.StatsEvent;
+import org.conscrypt.Platform;
 import org.conscrypt.TestUtils;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -34,10 +35,9 @@ public class MetricsTest {
     public void test_reflexiveEvent() throws Exception {
         TestUtils.assumeStatsLogAvailable();
 
-        Object sdkVersion = getSdkVersion();
         StatsEvent frameworkStatsEvent;
         ReflexiveStatsEvent reflexiveStatsEvent;
-        if ((sdkVersion != null) && ((int) sdkVersion > 32)) {
+        if (Platform.isSdkGreater(32)) {
             frameworkStatsEvent = StatsEvent.newBuilder()
                                                  .setAtomId(TLS_HANDSHAKE_REPORTED)
                                                  .writeBoolean(false)
@@ -48,8 +48,16 @@ public class MetricsTest {
                                                  .writeIntArray(new int[] {0}) // uids
                                                  .usePooledBuffer()
                                                  .build();
-            reflexiveStatsEvent = ReflexiveStatsEvent.buildEvent(
-                TLS_HANDSHAKE_REPORTED, false, 1, 2, 100, 3, new int[] {0});
+            ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder()
+                                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
+                                                          .writeBoolean(false)
+                                                          .writeInt(1) // protocol
+                                                          .writeInt(2) // cipher suite
+                                                          .writeInt(100) // duration
+                                                          .writeInt(3) // source
+                                                          .writeIntArray(new int[] {0}); // uids
+            builder.usePooledBuffer();
+            reflexiveStatsEvent = builder.build();
         } else {
             frameworkStatsEvent = StatsEvent.newBuilder()
                                                  .setAtomId(TLS_HANDSHAKE_REPORTED)
@@ -60,8 +68,15 @@ public class MetricsTest {
                                                  .writeInt(3) // source
                                                  .usePooledBuffer()
                                                  .build();
-            reflexiveStatsEvent = ReflexiveStatsEvent.buildEvent(
-                TLS_HANDSHAKE_REPORTED, false, 1, 2, 100, 3);
+            ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder()
+                                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
+                                                          .writeBoolean(false)
+                                                          .writeInt(1) // protocol
+                                                          .writeInt(2) // cipher suite
+                                                          .writeInt(100) // duration
+                                                          .writeInt(3); // source
+            builder.usePooledBuffer();
+            reflexiveStatsEvent = builder.build();
         }
 
         StatsEvent constructedEvent = (StatsEvent) reflexiveStatsEvent.getStatsEvent();
@@ -97,15 +112,4 @@ public class MetricsTest {
         }
     }
 
-    static Object getSdkVersion() {
-        try {
-            OptionalMethod getSdkVersion =
-                    new OptionalMethod(Class.forName("dalvik.system.VMRuntime"),
-                                        "getSdkVersion");
-            return getSdkVersion.invokeStatic();
-        } catch (ClassNotFoundException e) {
-            return null;
-        }
-    }
-
 }
diff --git a/publicapi/src/main/java/android/net/ssl/PakeClientKeyManagerParameters.java b/publicapi/src/main/java/android/net/ssl/PakeClientKeyManagerParameters.java
new file mode 100644
index 00000000..07680b60
--- /dev/null
+++ b/publicapi/src/main/java/android/net/ssl/PakeClientKeyManagerParameters.java
@@ -0,0 +1,174 @@
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
+package android.net.ssl;
+
+import static java.util.Objects.requireNonNull;
+
+import android.annotation.FlaggedApi;
+import android.annotation.SystemApi;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidParameterException;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.List;
+
+import javax.net.ssl.ManagerFactoryParameters;
+
+/**
+ * Parameters for configuring a {@code KeyManager} that supports PAKE (Password
+ * Authenticated Key Exchange).
+ *
+ * <p>This class holds the necessary information for the {@code KeyManager} to perform PAKE
+ * authentication, including the IDs of the client and server involved and the available PAKE
+ * options.</p>
+ *
+ * <p>Instances of this class are immutable. Use the {@link Builder} to create
+ * instances.</p>
+ *
+ * @hide
+ */
+@SystemApi
+@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+public final class PakeClientKeyManagerParameters implements ManagerFactoryParameters {
+    /**
+     * The ID of the client involved in the PAKE exchange.
+     */
+    private final byte[] clientId;
+
+    /**
+     * The ID of the server involved in the PAKE exchange.
+     */
+    private final byte[] serverId;
+
+    /**
+     * A list of available PAKE options. At least one option needs to be
+     * provided.
+     */
+    private final List<PakeOption> options;
+
+    /**
+     * Private constructor to enforce immutability.
+     *
+     * @param clientId The ID of the client involved in the PAKE exchange.
+     * @param serverId The ID of the server involved in the PAKE exchange.
+     * @param options  A list of available PAKE options.
+     */
+    private PakeClientKeyManagerParameters(
+            byte[] clientId, byte[] serverId, List<PakeOption> options) {
+        this.clientId = clientId;
+        this.serverId = serverId;
+        this.options = Collections.unmodifiableList(new ArrayList<>(options));
+    }
+
+    /**
+     * Returns the client identifier.
+     *
+     * @return The client identifier.
+     */
+    public @Nullable byte[] getClientId() {
+        return clientId;
+    }
+
+    /**
+     * Returns the server identifier.
+     *
+     * @return The server identifier.
+     */
+    public @Nullable byte[] getServerId() {
+        return serverId;
+    }
+
+    /**
+     * Returns a copy of the list of available PAKE options.
+     *
+     * @return A copy of the list of available PAKE options.
+     */
+    public @NonNull List<PakeOption> getOptions() {
+        return new ArrayList<>(options);
+    }
+
+    /**
+     * A builder for creating {@link PakeClientKeyManagerParameters} instances.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public static final class Builder {
+        private byte[] clientId;
+        private byte[] serverId;
+        private List<PakeOption> options = new ArrayList<>();
+
+        /**
+         * Sets the ID of the client involved in the PAKE exchange.
+         *
+         * @param clientId The ID of the client involved in the PAKE exchange.
+         * @return This builder.
+         */
+        public @NonNull Builder setClientId(@Nullable byte[] clientId) {
+            this.clientId = clientId;
+            return this;
+        }
+
+        /**
+         * Sets the ID of the server involved in the PAKE exchange.
+         *
+         * @param serverId The ID of the server involved in the PAKE exchange.
+         * @return This builder.
+         */
+        public @NonNull Builder setServerId(@Nullable byte[] serverId) {
+            this.serverId = serverId;
+            return this;
+        }
+
+        /**
+         * Adds a PAKE option.
+         *
+         * @param option The PAKE option to add.
+         * @return This builder.
+         * @throws InvalidParameterException If an option with the same algorithm already exists.
+         */
+        public @NonNull Builder addOption(@NonNull PakeOption option) {
+            requireNonNull(option, "Option cannot be null.");
+
+            for (PakeOption existingOption : options) {
+                if (existingOption.getAlgorithm().equals(option.getAlgorithm())) {
+                    throw new InvalidParameterException(
+                            "An option with the same algorithm already exists.");
+                }
+            }
+            this.options.add(option);
+            return this;
+        }
+
+        /**
+         * Builds a new {@link PakeClientKeyManagerParameters} instance.
+         *
+         * @return A new {@link PakeClientKeyManagerParameters} instance.
+         * @throws InvalidParameterException If no PAKE options are provided.
+         */
+        public @NonNull PakeClientKeyManagerParameters build() {
+            if (options.isEmpty()) {
+                throw new InvalidParameterException("At least one PAKE option must be provided.");
+            }
+            return new PakeClientKeyManagerParameters(clientId, serverId, options);
+        }
+    }
+}
diff --git a/publicapi/src/main/java/android/net/ssl/PakeOption.java b/publicapi/src/main/java/android/net/ssl/PakeOption.java
new file mode 100644
index 00000000..c5ef8d4f
--- /dev/null
+++ b/publicapi/src/main/java/android/net/ssl/PakeOption.java
@@ -0,0 +1,175 @@
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
+package android.net.ssl;
+
+import android.annotation.FlaggedApi;
+import android.annotation.SystemApi;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidParameterException;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.Map;
+
+/**
+ * An class representing a PAKE (Password Authenticated Key Exchange)
+ * option for TLS connections.
+ *
+ * <p>Instances of this class are immutable. Use the {@link Builder} to create
+ * instances.</p>
+ *
+ * @hide
+ */
+@SystemApi
+@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+public final class PakeOption {
+    private static final int MAX_HANDSHAKE_LIMIT = 24;
+
+    /**
+     * The algorithm of the PAKE algorithm.
+     */
+    private final String algorithm; // For now "SPAKE2PLUS_PRERELEASE" is suported
+
+    /**
+     * A map containing the message components for the PAKE exchange.
+     *
+     * <p>The keys are strings representing the component algorithms (e.g., "password",
+     * "w0", "w1"). The values are byte arrays containing the component data.</p>
+     */
+    private final Map<String, byte[]> messageComponents;
+
+    private PakeOption(String algorithm, Map<String, byte[]> messageComponents) {
+        this.algorithm = algorithm;
+        this.messageComponents = Collections.unmodifiableMap(new HashMap<>(messageComponents));
+    }
+
+    /**
+     * Returns the algorithm of the PAKE algorithm.
+     *
+     * @return The algorithm of the PAKE algorithm.
+     */
+    public @NonNull String getAlgorithm() {
+        return algorithm;
+    }
+
+    /**
+     * Returns the message component with the given key.
+     *
+     * @param key The algorithm of the component.
+     * @return The component data, or {@code null} if no component with the given
+     *         key exists.
+     */
+    public @Nullable byte[] getMessageComponent(@NonNull String key) {
+        return messageComponents.get(key);
+    }
+
+    /**
+     * A builder for creating {@link PakeOption} instances.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public static final class Builder {
+        private String algorithm;
+        private Map<String, byte[]> messageComponents = new HashMap<>();
+
+        /**
+         * Constructor for the builder.
+         *
+         * @param algorithm The algorithm of the PAKE algorithm.
+         * @throws InvalidParameterException If the algorithm is invalid.
+         */
+        public Builder(@NonNull String algorithm) {
+            if (algorithm == null || algorithm.isEmpty()) {
+                throw new InvalidParameterException("Algorithm cannot be null or empty.");
+            }
+            this.algorithm = algorithm;
+        }
+
+        /**
+         * Adds a message component. For SPAKE2+ password is the only required component. For
+         * SPAKE2+ 'client-handshake-limit' and 'server-handshake-limit' are optional and will be obtained using
+         * the first byte found in the input byte array. It must be an integer between 1 and 24. These limits are used to limit the number of unfinished or
+         * failed handshakes that can be performed using this PAKE option. If not specified, the
+         * default limit is 1. Be aware that higher limits increase the security risk of the
+         * connection since there are more opportunities for brute force attacks.
+         *
+         * @param key The algorithm of the component.
+         * @param value The component data.
+         * @return This builder.
+         * @throws InvalidParameterException If the key is invalid.
+         */
+        public @NonNull Builder addMessageComponent(@NonNull String key, @Nullable byte[] value) {
+            if (key == null || key.isEmpty()) {
+                throw new InvalidParameterException("Key cannot be null or empty.");
+            }
+            messageComponents.put(key, value.clone());
+            return this;
+        }
+
+        /**
+         * Builds a new {@link PakeOption} instance.
+         *
+         * <p>This method performs validation to ensure that the message components
+         * are consistent with the PAKE algorithm.</p>
+         *
+         * @return A new {@link PakeOption} instance.
+         * @throws InvalidParameterException If the message components are invalid.
+         */
+        public @NonNull PakeOption build() {
+            if (messageComponents.isEmpty()) {
+                throw new InvalidParameterException("Message components cannot be empty.");
+            }
+            if (algorithm.equals("SPAKE2PLUS_PRERELEASE")) {
+                validateSpake2PlusComponents();
+            }
+
+            return new PakeOption(algorithm, messageComponents);
+        }
+
+        private void validateSpake2PlusComponents() {
+            // For SPAKE2+ password is the only required component.
+            if (!messageComponents.containsKey("password")) {
+                throw new InvalidParameterException(
+                        "For SPAKE2+, 'password' must be present.");
+            }
+            // If 'client-handshake-limit' or 'server-handshake-limit' are present,
+            // they must be integers between 1 and 24.
+            if (messageComponents.containsKey("client-handshake-limit")) {
+                int clientHandshakeLimit =
+                        messageComponents
+                                .get("client-handshake-limit")[0];
+                if (clientHandshakeLimit < 1 || clientHandshakeLimit > MAX_HANDSHAKE_LIMIT) {
+                    throw new InvalidParameterException(
+                            "For SPAKE2+, 'client-handshake-limit' must be between 1 and 24.");
+                }
+            }
+            if (messageComponents.containsKey("server-handshake-limit")) {
+                int serverHandshakeLimit =
+                        messageComponents
+                                .get("server-handshake-limit")[0];
+                if (serverHandshakeLimit < 1 || serverHandshakeLimit > MAX_HANDSHAKE_LIMIT) {
+                    throw new InvalidParameterException(
+                            "For SPAKE2+, 'server-handshake-limit' must be between 1 and 24.");
+                }
+            }
+        }
+    }
+}
diff --git a/publicapi/src/main/java/android/net/ssl/PakeServerKeyManagerParameters.java b/publicapi/src/main/java/android/net/ssl/PakeServerKeyManagerParameters.java
new file mode 100644
index 00000000..72ce7bc8
--- /dev/null
+++ b/publicapi/src/main/java/android/net/ssl/PakeServerKeyManagerParameters.java
@@ -0,0 +1,221 @@
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
+package android.net.ssl;
+
+import static java.util.Objects.requireNonNull;
+
+import android.annotation.FlaggedApi;
+import android.annotation.SystemApi;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidParameterException;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+import javax.net.ssl.ManagerFactoryParameters;
+
+/**
+ * Parameters for configuring a {@code KeyManager} that supports PAKE
+ * (Password Authenticated Key Exchange) on the server side.
+ *
+ * <p>This class holds the necessary information for the {@code KeyManager} to perform PAKE
+ * authentication, including a mapping of client and server IDs (links) to their corresponding PAKE
+ * options.</p>
+ *
+ * <p>Instances of this class are immutable. Use the {@link Builder} to create
+ * instances.</p>
+ *
+ * @hide
+ */
+@SystemApi
+@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+public final class PakeServerKeyManagerParameters implements ManagerFactoryParameters {
+    /**
+     * A map of links to their corresponding PAKE options.
+     */
+    private final Map<Link, List<PakeOption>> links;
+
+    /**
+     * Private constructor to enforce immutability.
+     *
+     * @param links A map of links to their corresponding PAKE options.
+     */
+    private PakeServerKeyManagerParameters(Map<Link, List<PakeOption>> links) {
+        this.links = Collections.unmodifiableMap(new HashMap<>(links));
+    }
+
+    /**
+     * Returns a set of the links.
+     *
+     * @return The known links.
+     */
+    public @NonNull Set<Link> getLinks() {
+        return Collections.unmodifiableSet(links.keySet());
+    }
+
+    /**
+     * Returns an unmodifiable list of PAKE options for the given {@link Link}.
+     *
+     * @param link The link for which to retrieve the options. Should have been obtained through
+     *             {@link #getLinks}.
+     * @return An unmodifiable list of PAKE options for the given link.
+     */
+    public @NonNull List<PakeOption> getOptions(@NonNull Link link) {
+        requireNonNull(link, "Link cannot be null.");
+        List<PakeOption> options = links.get(link);
+        if (options == null) {
+            throw new InvalidParameterException("Link not found.");
+        }
+        return Collections.unmodifiableList(options);
+    }
+
+    /**
+     * Returns an unmodifiable list of PAKE options for the given client-server pair.
+     *
+     * @param clientId The client identifier for the link.
+     * @param serverId The server identifier for the link.
+     * @return An unmodifiable list of PAKE options for the given link.
+     */
+    public @NonNull List<PakeOption> getOptions(
+            @Nullable byte[] clientId, @Nullable byte[] serverId) {
+        return getOptions(new Link(clientId, serverId));
+    }
+
+    /**
+     * A PAKE link class combining the client and server IDs.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public static final class Link {
+        private final byte[] clientId;
+        private final byte[] serverId;
+
+        /**
+         * Constructs a {@code Link} object.
+         *
+         * @param clientId The client identifier for the link.
+         * @param serverId The server identifier for the link.
+         */
+        private Link(@Nullable byte[] clientId, @Nullable byte[] serverId) {
+            this.clientId = clientId;
+            this.serverId = serverId;
+        }
+
+        /**
+         * Returns the client identifier for the link.
+         *
+         * @return The client identifier for the link.
+         */
+        public @Nullable byte[] getClientId() {
+            return clientId;
+        }
+
+        /**
+         * Returns the server identifier for the link.
+         *
+         * @return The server identifier for the link.
+         */
+        public @Nullable byte[] getServerId() {
+            return serverId;
+        }
+
+        @Override
+        public boolean equals(Object o) {
+            if (this == o)
+                return true;
+            if (o == null || getClass() != o.getClass())
+                return false;
+            Link that = (Link) o;
+            return java.util.Arrays.equals(clientId, that.clientId)
+                    && java.util.Arrays.equals(serverId, that.serverId);
+        }
+
+        @Override
+        public int hashCode() {
+            int result = java.util.Arrays.hashCode(clientId);
+            result = 31 * result + java.util.Arrays.hashCode(serverId);
+            return result;
+        }
+    }
+
+    /**
+     * A builder for creating {@link PakeServerKeyManagerParameters} instances.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public static final class Builder {
+        private final Map<Link, List<PakeOption>> links = new HashMap<>();
+
+        /**
+         * Adds PAKE options for the given client and server IDs.
+         * Only the first link for SPAKE2PLUS_PRERELEASE will be used.
+         *
+         * @param clientId The client ID.
+         * @param serverId The server ID.
+         * @param options The list of PAKE options to add.
+         * @return This builder.
+         * @throws InvalidParameterException If the provided options are invalid.
+         */
+        public @NonNull Builder setOptions(@Nullable byte[] clientId, @Nullable byte[] serverId,
+                @NonNull List<PakeOption> options) {
+            requireNonNull(options, "options cannot be null.");
+            if (options.isEmpty()) {
+                throw new InvalidParameterException("options cannot be empty.");
+            }
+
+            Link link = new Link(clientId, serverId);
+            List<PakeOption> storedOptions = new ArrayList<PakeOption>(options.size());
+
+            for (PakeOption option : options) {
+                // Check that options are not duplicated.
+                for (PakeOption previousOption : storedOptions) {
+                    if (previousOption.getAlgorithm().equals(option.getAlgorithm())) {
+                        throw new InvalidParameterException(
+                                "There are multiple options with the same algorithm.");
+                    }
+                }
+                storedOptions.add(option);
+            }
+
+            links.put(link, storedOptions);
+            return this;
+        }
+
+        /**
+         * Builds a new {@link PakeServerKeyManagerParameters} instance.
+         *
+         * @return A new {@link PakeServerKeyManagerParameters} instance.
+         * @throws InvalidParameterException If no links are provided.
+         */
+        public @NonNull PakeServerKeyManagerParameters build() {
+            if (links.isEmpty()) {
+                throw new InvalidParameterException("At least one link must be provided.");
+            }
+            return new PakeServerKeyManagerParameters(links);
+        }
+    }
+}
diff --git a/publicapi/src/test/java/android/net/ssl/PakeClientKeyManagerParametersTest.java b/publicapi/src/test/java/android/net/ssl/PakeClientKeyManagerParametersTest.java
new file mode 100644
index 00000000..e16a64f4
--- /dev/null
+++ b/publicapi/src/test/java/android/net/ssl/PakeClientKeyManagerParametersTest.java
@@ -0,0 +1,126 @@
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
+package android.net.ssl;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
+
+import android.platform.test.annotations.RequiresFlagsEnabled;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.InvalidParameterException;
+import java.util.List;
+
+@RunWith(JUnit4.class)
+public class PakeClientKeyManagerParametersTest {
+    private static final byte[] PASSWORD = new byte[] {1, 2, 3};
+    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
+    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_valid() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", PASSWORD.clone())
+                                    .build();
+        PakeClientKeyManagerParameters params =
+                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
+        assertNull(params.getClientId());
+        assertNull(params.getServerId());
+        assertEquals(1, params.getOptions().size());
+        assertArrayEquals(PASSWORD, params.getOptions().get(0).getMessageComponent("password"));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_withClientId() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", PASSWORD.clone())
+                                    .build();
+        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
+                                                        .setClientId(CLIENT_ID.clone())
+                                                        .addOption(option)
+                                                        .build();
+        assertArrayEquals(CLIENT_ID, params.getClientId());
+        assertNull(params.getServerId());
+        assertEquals(1, params.getOptions().size());
+        assertArrayEquals(PASSWORD, params.getOptions().get(0).getMessageComponent("password"));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_withServerId() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", PASSWORD.clone())
+                                    .build();
+        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
+                                                        .setServerId(SERVER_ID.clone())
+                                                        .addOption(option)
+                                                        .build();
+        assertNull(params.getClientId());
+        assertArrayEquals(SERVER_ID, params.getServerId());
+        assertEquals(1, params.getOptions().size());
+        assertArrayEquals(PASSWORD, params.getOptions().get(0).getMessageComponent("password"));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_nullEndpoints() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", PASSWORD.clone())
+                                    .build();
+        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
+                                                        .setClientId(null)
+                                                        .setServerId(null)
+                                                        .addOption(option)
+                                                        .build();
+        assertNull(params.getClientId());
+        assertNull(params.getServerId());
+        assertEquals(1, params.getOptions().size());
+        assertArrayEquals(PASSWORD, params.getOptions().get(0).getMessageComponent("password"));
+    }
+
+    @Test(expected = InvalidParameterException.class)
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_noOptions() {
+        new PakeClientKeyManagerParameters.Builder().build();
+    }
+
+    @Test(expected = NullPointerException.class)
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_nullOption() {
+        new PakeClientKeyManagerParameters.Builder().addOption(null);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testGetOptions_returnsClone() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", PASSWORD.clone())
+                                    .build();
+        PakeClientKeyManagerParameters params =
+                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
+        List<PakeOption> options = params.getOptions();
+        options.clear(); // Try to modify the returned list
+        assertEquals(1, params.getOptions().size()); // The original list should be unchanged
+    }
+}
diff --git a/publicapi/src/test/java/android/net/ssl/PakeOptionTest.java b/publicapi/src/test/java/android/net/ssl/PakeOptionTest.java
new file mode 100644
index 00000000..cc0f2a94
--- /dev/null
+++ b/publicapi/src/test/java/android/net/ssl/PakeOptionTest.java
@@ -0,0 +1,140 @@
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
+package android.net.ssl;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
+
+import android.platform.test.annotations.RequiresFlagsEnabled;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.InvalidParameterException;
+
+@RunWith(JUnit4.class)
+public class PakeOptionTest {
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_valid() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", new byte[] {1, 2, 3})
+                                    .build();
+        assertEquals("SPAKE2PLUS_PRERELEASE", option.getAlgorithm());
+        assertNotNull(option.getMessageComponent("password"));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_invalidAlgorithm() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder(null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_emptyAlgorithm() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder(""));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_noComponents() {
+        assertThrows(
+                InvalidParameterException.class,
+                () -> new PakeOption.Builder("SPAKE2PLUS_PRERELEASE").build());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_invalidKey() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent(null, new byte[] {1, 2, 3}));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_emptyKey() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("", new byte[] {1, 2, 3}));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_invalidSpake2Plus_passwordWithContext() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("password", new byte[] {1, 2, 3})
+                .addMessageComponent("context", new byte[] {4, 2, 3})
+                .build();
+        assertNotNull(option.getMessageComponent("password"));
+        assertNotNull(option.getMessageComponent("context"));
+        assertNull(option.getMessageComponent("non_existing_key"));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_spake2Plus_passwordWithHandshakeLimits() {
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("password", new byte[] {1, 2, 3})
+                .addMessageComponent("server-handshake-limit", new byte[] {16})
+                .addMessageComponent("client-handshake-limit", new byte[] {16})
+                .build();
+        assertNotNull(option.getMessageComponent("password"));
+        assertNotNull(option.getMessageComponent("server-handshake-limit"));
+        assertNotNull(option.getMessageComponent("client-handshake-limit"));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_spake2Plus_passwordInvalidServerHandshakeLimit1() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("password", new byte[] {1, 2, 3})
+                .addMessageComponent("server-handshake-limit", new byte[] {64})
+                .addMessageComponent("client-handshake-limit", new byte[] {16})
+                .build());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_spake2Plus_passwordInvalidServerHandshakeLimit2() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("password", new byte[] {1, 2, 3})
+                .addMessageComponent("server-handshake-limit", new byte[] {0})
+                .addMessageComponent("client-handshake-limit", new byte[] {16})
+                .build());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_spake2Plus_passwordInvalidClientHandshakeLimit() {
+        assertThrows(InvalidParameterException.class, () ->new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("password", new byte[] {1, 2, 3})
+                .addMessageComponent("server-handshake-limit", new byte[] {16})
+                .addMessageComponent("client-handshake-limit", new byte[] {64})
+                .build());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_invalidSpake2Plus_noPassword() {
+        assertThrows(InvalidParameterException.class, () -> new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                .addMessageComponent("w0", new byte[] {1, 2, 3})
+                .build());
+    }
+}
diff --git a/publicapi/src/test/java/android/net/ssl/PakeServerKeyManagerParametersTest.java b/publicapi/src/test/java/android/net/ssl/PakeServerKeyManagerParametersTest.java
new file mode 100644
index 00000000..04eed01c
--- /dev/null
+++ b/publicapi/src/test/java/android/net/ssl/PakeServerKeyManagerParametersTest.java
@@ -0,0 +1,136 @@
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
+package android.net.ssl;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.platform.test.annotations.RequiresFlagsEnabled;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.InvalidParameterException;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collections;
+import java.util.List;
+import java.util.Set;
+
+@RunWith(JUnit4.class)
+public class PakeServerKeyManagerParametersTest {
+    private static final byte[] CLIENT_ID_1 = new byte[] {1, 2, 3};
+    private static final byte[] SERVER_ID_1 = new byte[] {4, 5, 6};
+    private static final byte[] CLIENT_ID_2 = new byte[] {7, 8, 9};
+    private static final byte[] SERVER_ID_2 = new byte[] {10, 11, 12};
+    private static final byte[] PASSWORD_BYTES = new byte[] {1, 2, 3};
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_valid() {
+        PakeOption option1 = createOption("SPAKE2PLUS_PRERELEASE", "password");
+        PakeOption option2 = createOption("SPAKE2PLUS_PRERELEASE", "password");
+
+        PakeServerKeyManagerParameters params =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID_1, SERVER_ID_1, List.of(option1))
+                        .setOptions(CLIENT_ID_2, SERVER_ID_2, List.of(option2))
+                        .build();
+
+        assertEquals(option1, params.getOptions(CLIENT_ID_1, SERVER_ID_1).get(0));
+        assertEquals(option2, params.getOptions(CLIENT_ID_2, SERVER_ID_2).get(0));
+    }
+
+    @Test(expected = InvalidParameterException.class)
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_noLinks() {
+        new PakeServerKeyManagerParameters.Builder().build();
+    }
+
+    @Test(expected = NullPointerException.class)
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_nullOption() {
+        new PakeServerKeyManagerParameters.Builder().setOptions(
+                CLIENT_ID_1, SERVER_ID_1, List.of((PakeOption) null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_duplicateOptionAlgorithm() {
+        PakeOption option = createOption("SPAKE2PLUS_PRERELEASE", "password");
+        PakeOption sameOption = createOption("SPAKE2PLUS_PRERELEASE", "password");
+        assertThrows(InvalidParameterException.class,
+                ()
+                        -> new PakeServerKeyManagerParameters.Builder().setOptions(
+                                CLIENT_ID_1, SERVER_ID_1, List.of(option, sameOption)));
+    }
+
+    @Test(expected = InvalidParameterException.class)
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testBuilder_linkWithNoOptions() {
+        new PakeServerKeyManagerParameters.Builder().setOptions(
+                CLIENT_ID_1, SERVER_ID_1, new ArrayList());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testGetOptions_nonExistingLink() {
+        PakeOption option1 = createOption("SPAKE2PLUS_PRERELEASE", "password");
+
+        PakeServerKeyManagerParameters params =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID_1, SERVER_ID_1, List.of(option1))
+                        .build();
+
+        assertThrows(
+                InvalidParameterException.class, () -> params.getOptions(CLIENT_ID_2, SERVER_ID_2));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
+    public void testGetLinks() {
+        PakeOption option1 = createOption("SPAKE2PLUS_PRERELEASE", "password");
+        PakeOption option2 = createOption("SPAKE2PLUS_PRERELEASE", "password");
+
+        PakeServerKeyManagerParameters params =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID_1, SERVER_ID_1, List.of(option1))
+                        .setOptions(CLIENT_ID_2, SERVER_ID_2, List.of(option2))
+                        .build();
+
+        for (PakeServerKeyManagerParameters.Link link : params.getLinks()) {
+            if (Arrays.equals(CLIENT_ID_1, link.getClientId())) {
+                assertArrayEquals(SERVER_ID_1, link.getServerId());
+                assertEquals(option1, params.getOptions(link).get(0));
+            } else {
+                assertArrayEquals(CLIENT_ID_2, link.getClientId());
+                assertArrayEquals(SERVER_ID_2, link.getServerId());
+                assertEquals(option2, params.getOptions(link).get(0));
+            }
+        }
+    }
+
+    private static PakeOption createOption(String algorithm, String... keys) {
+        PakeOption.Builder builder = new PakeOption.Builder(algorithm);
+        for (String key : keys) {
+            builder.addMessageComponent(key, PASSWORD_BYTES);
+        }
+        return builder.build();
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
index b4117953..d705eeb0 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
@@ -205,6 +205,32 @@ abstract class AbstractSessionContext implements SSLSessionContext {
         return (sslCtxNativePointer != 0);
     }
 
+    void initSpake(SSLParametersImpl parameters) throws SSLException {
+        Spake2PlusKeyManager spakeKeyManager = parameters.getSpake2PlusKeyManager();
+        byte[] context = spakeKeyManager.getContext();
+        byte[] idProverArray = spakeKeyManager.getIdProver();
+        byte[] idVerifierArray = spakeKeyManager.getIdVerifier();
+        byte[] pwArray = spakeKeyManager.getPassword();
+        boolean isClient = spakeKeyManager.isClient();
+        int handshakeLimit = spakeKeyManager.getHandshakeLimit();
+        lock.writeLock().lock();
+        try {
+            if (isValid()) {
+                NativeCrypto.SSL_CTX_set_spake_credential(
+                            context,
+                            pwArray,
+                            idProverArray,
+                            idVerifierArray,
+                            isClient,
+                            handshakeLimit,
+                            sslCtxNativePointer,
+                            this);
+            }
+        } finally {
+            lock.writeLock().unlock();
+        }
+    }
+
     /**
      * Returns a native pointer to a new SSL object in this SSL_CTX.
      */
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java b/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
index d565d2da..a4b14583 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
@@ -171,8 +171,8 @@ public final class Conscrypt {
         private String name = Platform.getDefaultProviderName();
         private boolean provideTrustManager = Platform.provideTrustManagerByDefault();
         private String defaultTlsProtocol = NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3;
-        private boolean deprecatedTlsV1 = true;
-        private boolean enabledTlsV1 = false;
+        private boolean deprecatedTlsV1 = Platform.isTlsV1Deprecated();
+        private boolean enabledTlsV1 = Platform.isTlsV1Supported();
 
         private ProviderBuilder() {}
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
index 6cd575e4..5af8bbc8 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
@@ -111,7 +111,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
     private static ConscryptEngine newEngine(
             SSLParametersImpl sslParameters, final ConscryptEngineSocket socket) {
         SSLParametersImpl modifiedParams;
-        if (Platform.supportsX509ExtendedTrustManager()) {
+        if (sslParameters.isSpake()) {
+            modifiedParams = sslParameters.cloneWithSpake();
+        } else if (Platform.supportsX509ExtendedTrustManager()) {
             modifiedParams = sslParameters.cloneWithTrustManager(
                     getDelegatingTrustManager(sslParameters.getX509TrustManager(), socket));
         } else {
@@ -310,11 +312,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
                 case STATE_READY_HANDSHAKE_CUT_THROUGH:
                     if (handshakeStartedMillis > 0) {
                         StatsLog statsLog = Platform.getStatsLog();
-                        if (statsLog != null) {
-                            statsLog.countTlsHandshake(true, engine.getSession().getProtocol(),
-                                    engine.getSession().getCipherSuite(),
-                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
-                        }
+                        statsLog.countTlsHandshake(true, engine.getSession().getProtocol(),
+                                engine.getSession().getCipherSuite(),
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
@@ -327,12 +327,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
                 case STATE_CLOSED:
                     if (handshakeStartedMillis > 0) {
                         StatsLog statsLog = Platform.getStatsLog();
-                        if (statsLog != null) {
-                            // Handshake was in progress and so must have failed.
-                            statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED",
-                                    "TLS_CIPHER_FAILED",
-                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
-                        }
+                        // Handshake was in progress and so must have failed.
+                        statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED", "TLS_CIPHER_FAILED",
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
@@ -842,6 +839,9 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
         @Override
         public int read(byte[] b, int off, int len) throws IOException {
             waitForHandshake();
+            if (len == 0) {
+                return 0;
+            }
             synchronized (readLock) {
                 return readUntilDataAvailable(b, off, len);
             }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
index b1b4d70e..c702820e 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
@@ -73,6 +73,7 @@ public final class NativeCrypto {
             error = t;
         }
         loadError = error;
+        setTlsV1DeprecationStatus(Platform.isTlsV1Deprecated(), Platform.isTlsV1Supported());
     }
 
     private native static void clinit();
@@ -222,6 +223,8 @@ public final class NativeCrypto {
 
     static native void X25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
 
+    static native void ED25519_keypair(byte[] outPublicKey, byte[] outPrivateKey);
+
     // --- Message digest functions --------------
 
     // These return const references
@@ -275,6 +278,12 @@ public final class NativeCrypto {
     static native boolean EVP_DigestVerifyFinal(NativeRef.EVP_MD_CTX ctx, byte[] signature,
             int offset, int length) throws IndexOutOfBoundsException;
 
+    static native byte[] EVP_DigestSign(
+            NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);
+
+    static native boolean EVP_DigestVerify(NativeRef.EVP_MD_CTX ctx, byte[] sigBuffer,
+            int sigOffset, int sigLen, byte[] dataBuffer, int dataOffset, int dataLen);
+
     static native long EVP_PKEY_encrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;
 
     static native int EVP_PKEY_encrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
@@ -666,6 +675,23 @@ public final class NativeCrypto {
     @android.compat.annotation.UnsupportedAppUsage
     static native int X509_supported_extension(long x509ExtensionRef);
 
+    // --- SPAKE ---------------------------------------------------------------
+
+    /**
+     * Sets the SPAKE credential for the given SSL context using a password.
+     * Used for both client and server.
+     */
+    static native void SSL_CTX_set_spake_credential(
+            byte[] context,
+            byte[] pw_array,
+            byte[] id_prover_array,
+            byte[] id_verifier_array,
+            boolean is_client,
+            int handshake_limit,
+            long ssl_ctx,
+            AbstractSessionContext holder)
+        throws SSLException;
+
     // --- ASN1_TIME -----------------------------------------------------------
 
     @android.compat.annotation.UnsupportedAppUsage
@@ -992,6 +1018,11 @@ public final class NativeCrypto {
             "TLS_PSK_WITH_AES_256_CBC_SHA",
     };
 
+    /** TLS-SPAKE */
+    static final String[] DEFAULT_SPAKE_CIPHER_SUITES = new String[] {
+            "TLS1_3_NAMED_PAKE_SPAKE2PLUSV1",
+    };
+
     static String[] getSupportedCipherSuites() {
         return SSLUtils.concat(SUPPORTED_TLS_1_3_CIPHER_SUITES, SUPPORTED_TLS_1_2_CIPHER_SUITES.clone());
     }
@@ -1239,6 +1270,11 @@ public final class NativeCrypto {
             if (SUPPORTED_TLS_1_2_CIPHER_SUITES_SET.contains(cipherSuites[i])) {
                 continue;
             }
+            // Not sure if we need to do this for SPAKE, but the SPAKE cipher suite
+            // not registered at the moment.
+            if (DEFAULT_SPAKE_CIPHER_SUITES[0] == cipherSuites[i]) {
+                continue;
+            }
 
             // For backwards compatibility, it's allowed for |cipherSuite| to
             // be an OpenSSL-style cipher-suite name.
@@ -1362,14 +1398,11 @@ public final class NativeCrypto {
                 throws CertificateException;
 
         /**
-         * Called on an SSL client when the server requests (or
-         * requires a certificate). The client can respond by using
-         * SSL_use_certificate and SSL_use_PrivateKey to set a
-         * certificate if has an appropriate one available, similar to
-         * how the server provides its certificate.
+         * Called on an SSL client when the server requests (or requires a certificate). The client
+         * can respond by using SSL_use_certificate and SSL_use_PrivateKey to set a certificate if
+         * has an appropriate one available, similar to how the server provides its certificate.
          *
-         * @param keyTypes key types supported by the server,
-         * convertible to strings with #keyType
+         * @param keyTypes key types supported by the server, convertible to strings with #keyType
          * @param asn1DerEncodedX500Principals CAs known to the server
          */
         @SuppressWarnings("unused")
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
index 6c10fa19..c618ebe7 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
@@ -310,9 +310,15 @@ final class NativeSsl {
                     + " and " + NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1
                     + " are no longer supported and were filtered from the list");
         }
-        NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
-        NativeCrypto.setEnabledCipherSuites(
+        // We can use default cipher suites for SPAKE.
+        if (!parameters.isSpake()) {
+            NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
+            NativeCrypto.setEnabledCipherSuites(
                 ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
+        } else {
+            // SPAKE only supports TLSv1.3.
+            NativeCrypto.setEnabledProtocols(ssl, this, new String[] {"TLSv1.3"});
+        }
 
         if (parameters.applicationProtocols.length > 0) {
             NativeCrypto.setApplicationProtocols(ssl, this, isClient(), parameters.applicationProtocols);
@@ -352,7 +358,9 @@ final class NativeSsl {
         // with TLSv1 and SSLv3).
         NativeCrypto.SSL_set_mode(ssl, this, SSL_MODE_CBC_RECORD_SPLITTING);
 
-        setCertificateValidation();
+        if (!parameters.isSpake()) {
+            setCertificateValidation();
+        }
         setTlsChannelId(channelIdPrivateKey);
     }
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLAeadCipher.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLAeadCipher.java
index 383ba4e9..3e18d78d 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLAeadCipher.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLAeadCipher.java
@@ -272,25 +272,43 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
     }
 
     @Override
-    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
-            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
-        BadPaddingException {
-        // Because the EVP_AEAD updateInternal processes input but doesn't create any output
-        // (and thus can't check the output buffer), we need to add this check before the
-        // superclass' processing to ensure that updateInternal is never called if the
-        // output buffer isn't large enough.
-        if (output != null) {
-            if (getOutputSizeForFinal(inputLen) > output.length - outputOffset) {
-                throw new ShortBufferWithoutStackTraceException("Insufficient output space");
-            }
+    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
+            throws IllegalBlockSizeException, BadPaddingException {
+        final int maximumLen = getOutputSizeForFinal(inputLen);
+        /* Assume that we'll output exactly on a byte boundary. */
+        final byte[] output = new byte[maximumLen];
+
+        int bytesWritten;
+        try {
+            bytesWritten = doFinalInternal(input, inputOffset, inputLen, output, 0);
+        } catch (ShortBufferException e) {
+            /* This should not happen since we sized our own buffer. */
+            throw new RuntimeException("our calculated buffer was too small", e);
+        }
+
+        if (bytesWritten == output.length) {
+            return output;
+        } else if (bytesWritten == 0) {
+            return EmptyArray.BYTE;
+        } else {
+            return Arrays.copyOf(output, bytesWritten);
         }
-        return super.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
     }
 
     @Override
-    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
-            int outputOffset, int maximumLen) throws ShortBufferException {
-        checkInitialization();
+    protected int engineDoFinal(
+            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
+            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
+        if (output == null) {
+            throw new NullPointerException("output == null");
+        }
+        if (getOutputSizeForFinal(inputLen) > output.length - outputOffset) {
+            throw new ShortBufferWithoutStackTraceException("Insufficient output space");
+        }
+        return doFinalInternal(input, inputOffset, inputLen, output, outputOffset);
+    }
+
+    void appendToBuf(byte[] input, int inputOffset, int inputLen) {
         if (buf == null) {
             throw new IllegalStateException("Cipher not initialized");
         }
@@ -301,6 +319,13 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
             System.arraycopy(input, inputOffset, buf, this.bufCount, inputLen);
             this.bufCount += inputLen;
         }
+    }
+
+    @Override
+    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset,
+            int maximumLen) throws ShortBufferException {
+        checkInitialization();
+        appendToBuf(input, inputOffset, inputLen);
         return 0;
     }
 
@@ -354,18 +379,39 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
         return bytesWritten;
     }
 
-    @Override
-    int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
+    int doFinalInternal(
+            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
             throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
         checkInitialization();
+
+        byte[] in;
+        int inOffset;
+        int inLen;
+        if (bufCount > 0) {
+            if (inputLen > 0) {
+                appendToBuf(input, inputOffset, inputLen);
+            }
+            in = buf;
+            inOffset = 0;
+            inLen = bufCount;
+        } else {
+            if (inputLen == 0 && input == null) {
+                in = EmptyArray.BYTE; // input can be null when inputLen == 0
+            } else {
+                in = input;
+            }
+            inOffset = inputOffset;
+            inLen = inputLen;
+        }
+
         final int bytesWritten;
         try {
             if (isEncrypting()) {
-                bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(evpAead, encodedKey,
-                        tagLengthInBytes, output, outputOffset, iv, buf, 0, bufCount, aad);
+                bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(evpAead, encodedKey, tagLengthInBytes,
+                        output, outputOffset, iv, in, inOffset, inLen, aad);
             } else {
-                bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey,
-                        tagLengthInBytes, output, outputOffset, iv, buf, 0, bufCount, aad);
+                bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey, tagLengthInBytes,
+                        output, outputOffset, iv, in, inOffset, inLen, aad);
             }
         } catch (BadPaddingException e) {
             throwAEADBadTagExceptionIfAvailable(e.getMessage(), e.getCause());
@@ -393,12 +439,6 @@ public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
         return 0;
     }
 
-    @Override
-    int getOutputSizeForFinal(int inputLen) {
-        return bufCount + inputLen
-                + (isEncrypting() ? NativeCrypto.EVP_AEAD_max_overhead(evpAead) : 0);
-    }
-
     // Intentionally missing Override to compile on old versions of Android
     @SuppressWarnings("MissingOverride")
     protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipher.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipher.java
index 8b8a90b3..062227a4 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipher.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipher.java
@@ -153,16 +153,6 @@ public abstract class OpenSSLCipher extends CipherSpi {
     abstract int updateInternal(byte[] input, int inputOffset, int inputLen,
             byte[] output, int outputOffset, int maximumLen) throws ShortBufferException;
 
-    /**
-     * API-specific implementation of the final block. The {@code maximumLen}
-     * will be the maximum length of the possible output as returned by
-     * {@link #getOutputSizeForFinal(int)}. The return value must be the number
-     * of bytes processed and placed into {@code output}. On error, an exception
-     * must be thrown.
-     */
-    abstract int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
-            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException;
-
     /**
      * Returns the standard name for the particular algorithm.
      */
@@ -351,64 +341,6 @@ public abstract class OpenSSLCipher extends CipherSpi {
         return updateInternal(input, inputOffset, inputLen, output, outputOffset, maximumLen);
     }
 
-    @Override
-    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
-            throws IllegalBlockSizeException, BadPaddingException {
-        final int maximumLen = getOutputSizeForFinal(inputLen);
-        /* Assume that we'll output exactly on a byte boundary. */
-        final byte[] output = new byte[maximumLen];
-
-        int bytesWritten;
-        if (inputLen > 0) {
-            try {
-                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
-            } catch (ShortBufferException e) {
-                /* This should not happen since we sized our own buffer. */
-                throw new RuntimeException("our calculated buffer was too small", e);
-            }
-        } else {
-            bytesWritten = 0;
-        }
-
-        try {
-            bytesWritten += doFinalInternal(output, bytesWritten, maximumLen - bytesWritten);
-        } catch (ShortBufferException e) {
-            /* This should not happen since we sized our own buffer. */
-            throw new RuntimeException("our calculated buffer was too small", e);
-        }
-
-        if (bytesWritten == output.length) {
-            return output;
-        } else if (bytesWritten == 0) {
-            return EmptyArray.BYTE;
-        } else {
-            return Arrays.copyOfRange(output, 0, bytesWritten);
-        }
-    }
-
-    @Override
-    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
-            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
-            BadPaddingException {
-        if (output == null) {
-            throw new NullPointerException("output == null");
-        }
-
-        int maximumLen = getOutputSizeForFinal(inputLen);
-
-        final int bytesWritten;
-        if (inputLen > 0) {
-            bytesWritten = updateInternal(input, inputOffset, inputLen, output, outputOffset,
-                    maximumLen);
-            outputOffset += bytesWritten;
-            maximumLen -= bytesWritten;
-        } else {
-            bytesWritten = 0;
-        }
-
-        return bytesWritten + doFinalInternal(output, outputOffset, maximumLen);
-    }
-
     @Override
     protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
         try {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherChaCha20.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherChaCha20.java
index 4e686e47..4072a086 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherChaCha20.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLCipherChaCha20.java
@@ -22,6 +22,10 @@ import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.SecureRandom;
 import java.security.spec.AlgorithmParameterSpec;
+import java.util.Arrays;
+
+import javax.crypto.BadPaddingException;
+import javax.crypto.IllegalBlockSizeException;
 import javax.crypto.NoSuchPaddingException;
 import javax.crypto.ShortBufferException;
 import javax.crypto.spec.IvParameterSpec;
@@ -103,9 +107,58 @@ public class OpenSSLCipherChaCha20 extends OpenSSLCipher {
     }
 
     @Override
-    int doFinalInternal(byte[] output, int outputOffset, int maximumLen) {
+    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
+            throws IllegalBlockSizeException, BadPaddingException {
+        final int maximumLen = getOutputSizeForFinal(inputLen);
+        /* Assume that we'll output exactly on a byte boundary. */
+        final byte[] output = new byte[maximumLen];
+
+        int bytesWritten;
+        if (inputLen > 0) {
+            try {
+                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
+            } catch (ShortBufferException e) {
+                /* This should not happen since we sized our own buffer. */
+                throw new RuntimeException("our calculated buffer was too small", e);
+            }
+        } else {
+            bytesWritten = 0;
+        }
+
         reset();
-        return 0;
+
+        if (bytesWritten == output.length) {
+            return output;
+        } else if (bytesWritten == 0) {
+            return EmptyArray.BYTE;
+        } else {
+            return Arrays.copyOfRange(output, 0, bytesWritten);
+        }
+    }
+
+    @Override
+    protected int engineDoFinal(
+            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
+            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
+        if (output == null) {
+            throw new NullPointerException("output == null");
+        }
+
+        int maximumLen = getOutputSizeForFinal(inputLen);
+
+        final int bytesWritten;
+        if (inputLen > 0) {
+            bytesWritten =
+                    updateInternal(input, inputOffset, inputLen, output, outputOffset, maximumLen);
+            outputOffset += bytesWritten;
+            maximumLen -= bytesWritten;
+        } else {
+            bytesWritten = 0;
+        }
+
+        reset();
+
+        return bytesWritten;
     }
 
     private void reset() {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipher.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipher.java
index 765282d6..98bd9a3d 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipher.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLEvpCipher.java
@@ -17,15 +17,18 @@
 
 package com.android.org.conscrypt;
 
+import com.android.org.conscrypt.NativeRef.EVP_CIPHER_CTX;
+
 import java.security.InvalidAlgorithmParameterException;
 import java.security.InvalidKeyException;
 import java.security.SecureRandom;
 import java.security.spec.AlgorithmParameterSpec;
+import java.util.Arrays;
+
 import javax.crypto.BadPaddingException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.crypto.ShortBufferException;
 import javax.crypto.spec.IvParameterSpec;
-import com.android.org.conscrypt.NativeRef.EVP_CIPHER_CTX;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -131,7 +134,6 @@ public abstract class OpenSSLEvpCipher extends OpenSSLCipher {
         return outputOffset - intialOutputOffset;
     }
 
-    @Override
     int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
             throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
         /* Remember this so we can tell how many characters were written. */
@@ -167,6 +169,64 @@ public abstract class OpenSSLEvpCipher extends OpenSSLCipher {
         return outputOffset - initialOutputOffset;
     }
 
+    @Override
+    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
+            throws IllegalBlockSizeException, BadPaddingException {
+        final int maximumLen = getOutputSizeForFinal(inputLen);
+        /* Assume that we'll output exactly on a byte boundary. */
+        final byte[] output = new byte[maximumLen];
+
+        int bytesWritten;
+        if (inputLen > 0) {
+            try {
+                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
+            } catch (ShortBufferException e) {
+                /* This should not happen since we sized our own buffer. */
+                throw new RuntimeException("our calculated buffer was too small", e);
+            }
+        } else {
+            bytesWritten = 0;
+        }
+
+        try {
+            bytesWritten += doFinalInternal(output, bytesWritten, maximumLen - bytesWritten);
+        } catch (ShortBufferException e) {
+            /* This should not happen since we sized our own buffer. */
+            throw new RuntimeException("our calculated buffer was too small", e);
+        }
+
+        if (bytesWritten == output.length) {
+            return output;
+        } else if (bytesWritten == 0) {
+            return EmptyArray.BYTE;
+        } else {
+            return Arrays.copyOfRange(output, 0, bytesWritten);
+        }
+    }
+
+    @Override
+    protected int engineDoFinal(
+            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
+            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
+        if (output == null) {
+            throw new NullPointerException("output == null");
+        }
+
+        int maximumLen = getOutputSizeForFinal(inputLen);
+
+        final int bytesWritten;
+        if (inputLen > 0) {
+            bytesWritten =
+                    updateInternal(input, inputOffset, inputLen, output, outputOffset, maximumLen);
+            outputOffset += bytesWritten;
+            maximumLen -= bytesWritten;
+        } else {
+            bytesWritten = 0;
+        }
+
+        return bytesWritten + doFinalInternal(output, outputOffset, maximumLen);
+    }
+
     @Override
     int getOutputSizeForFinal(int inputLen) {
         if (modeBlockSize == 1) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java
index 7dcdde8f..fc54e934 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java
@@ -531,13 +531,37 @@ public final class OpenSSLProvider extends Provider {
         put("CertificateFactory.X509", PREFIX + "OpenSSLX509CertificateFactory");
         put("Alg.Alias.CertificateFactory.X.509", "X509");
 
-        /* === HPKE - Conscrypt internal only === */
+        /* === HPKE === */
+        String baseClass = classExists("android.crypto.hpke.HpkeSpi") ? PREFIX + "AndroidHpkeSpi"
+                                                                      : PREFIX + "HpkeImpl";
+
         put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
-                PREFIX + "HpkeImpl$X25519_AES_128");
+                baseClass + "$X25519_AES_128");
+        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
+                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM");
         put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
-                PREFIX + "HpkeImpl$X25519_AES_256");
+                baseClass + "$X25519_AES_256");
+        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
+                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM");
         put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305",
-                PREFIX + "HpkeImpl$X25519_CHACHA20");
+                baseClass + "$X25519_CHACHA20");
+        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_GhpkeCHACHA20POLY1305",
+                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305");
+
+        /* === PAKE === */
+        if (Platform.isPakeSupported()) {
+            put("TrustManagerFactory.PAKE", PREFIX + "PakeTrustManagerFactory");
+            put("KeyManagerFactory.PAKE", PREFIX + "PakeKeyManagerFactory");
+        }
+    }
+
+    private boolean classExists(String classname) {
+        try {
+            Class.forName(classname);
+        } catch (ClassNotFoundException e) {
+            return false;
+        }
+        return true;
     }
 
     private void putMacImplClass(String algorithm, String className) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
index 834d20eb..848d6fb3 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
@@ -71,6 +71,10 @@ final class SSLParametersImpl implements Cloneable {
     private final PSKKeyManager pskKeyManager;
     // source of X.509 certificate based authentication trust decisions or null if not provided
     @android.compat.annotation.UnsupportedAppUsage private final X509TrustManager x509TrustManager;
+    // source of Spake trust or null if not provided
+    private final Spake2PlusTrustManager spake2PlusTrustManager;
+    // source of Spake authentication or null if not provided
+    private final Spake2PlusKeyManager spake2PlusKeyManager;
 
     // protocols enabled for SSL connection
     String[] enabledProtocols;
@@ -127,22 +131,41 @@ final class SSLParametersImpl implements Cloneable {
             throws KeyManagementException {
         this.serverSessionContext = serverSessionContext;
         this.clientSessionContext = clientSessionContext;
-
         // initialize key managers
         if (kms == null) {
             x509KeyManager = getDefaultX509KeyManager();
             // There's no default PSK key manager
             pskKeyManager = null;
+            spake2PlusKeyManager = null;
         } else {
             x509KeyManager = findFirstX509KeyManager(kms);
             pskKeyManager = findFirstPSKKeyManager(kms);
+            spake2PlusKeyManager = findFirstSpake2PlusKeyManager(kms);
+            if (spake2PlusKeyManager != null) {
+                if (x509KeyManager != null || pskKeyManager != null) {
+                    throw new KeyManagementException(
+                            "Spake2PlusManagers should not be set with X509KeyManager,"
+                            + " x509TrustManager or PSKKeyManager");
+                }
+                setUseClientMode(spake2PlusKeyManager.isClient());
+            }
         }
 
         // initialize x509TrustManager
         if (tms == null) {
             x509TrustManager = getDefaultX509TrustManager();
+            spake2PlusTrustManager = null;
         } else {
             x509TrustManager = findFirstX509TrustManager(tms);
+            spake2PlusTrustManager = findFirstSpake2PlusTrustManager(tms);
+            if (spake2PlusTrustManager != null && x509TrustManager != null) {
+                throw new KeyManagementException(
+                        "Spake2PlusTrustManager should not be set with X509TrustManager");
+            }
+        }
+        if ((spake2PlusTrustManager != null) != (spake2PlusKeyManager != null)) {
+            throw new KeyManagementException(
+                    "Spake2PlusTrustManager and Spake2PlusKeyManager should be set together");
         }
 
         // initialize the list of cipher suites and protocols enabled by default
@@ -161,11 +184,15 @@ final class SSLParametersImpl implements Cloneable {
         }
         boolean x509CipherSuitesNeeded = (x509KeyManager != null) || (x509TrustManager != null);
         boolean pskCipherSuitesNeeded = pskKeyManager != null;
-        enabledCipherSuites = getDefaultCipherSuites(
-                x509CipherSuitesNeeded, pskCipherSuitesNeeded);
+        enabledCipherSuites =
+                getDefaultCipherSuites(x509CipherSuitesNeeded, pskCipherSuitesNeeded, isSpake());
 
         // We ignore the SecureRandom passed in by the caller. The native code below
         // directly accesses /dev/urandom, which makes it irrelevant.
+
+        if (isSpake()) {
+            initSpake();
+        }
     }
 
     // Copy constructor for the purposes of changing the final fields
@@ -173,12 +200,15 @@ final class SSLParametersImpl implements Cloneable {
     private SSLParametersImpl(ClientSessionContext clientSessionContext,
             ServerSessionContext serverSessionContext, X509KeyManager x509KeyManager,
             PSKKeyManager pskKeyManager, X509TrustManager x509TrustManager,
-            SSLParametersImpl sslParams) {
+            Spake2PlusTrustManager spake2PlusTrustManager,
+            Spake2PlusKeyManager spake2PlusKeyManager, SSLParametersImpl sslParams) {
         this.clientSessionContext = clientSessionContext;
         this.serverSessionContext = serverSessionContext;
         this.x509KeyManager = x509KeyManager;
         this.pskKeyManager = pskKeyManager;
         this.x509TrustManager = x509TrustManager;
+        this.spake2PlusKeyManager = spake2PlusKeyManager;
+        this.spake2PlusTrustManager = spake2PlusTrustManager;
 
         this.enabledProtocols =
                 (sslParams.enabledProtocols == null) ? null : sslParams.enabledProtocols.clone();
@@ -206,6 +236,17 @@ final class SSLParametersImpl implements Cloneable {
         this.channelIdEnabled = sslParams.channelIdEnabled;
     }
 
+    /**
+     * Initializes the SSL credential for the Spake.
+     */
+    void initSpake() throws KeyManagementException {
+        try {
+            getSessionContext().initSpake(this);
+        } catch (Exception e) {
+            throw new KeyManagementException("Spake initialization failed " + e.getMessage());
+        }
+    }
+
     @android.compat.annotation.UnsupportedAppUsage
     static SSLParametersImpl getDefault() throws KeyManagementException {
         SSLParametersImpl result = defaultParameters;
@@ -235,6 +276,13 @@ final class SSLParametersImpl implements Cloneable {
         return clientSessionContext;
     }
 
+    /*
+     * Returns the server session context.
+     */
+    ServerSessionContext getServerSessionContext() {
+        return serverSessionContext;
+    }
+
     /**
      * Returns X.509 key manager or null for none.
      */
@@ -250,6 +298,13 @@ final class SSLParametersImpl implements Cloneable {
         return pskKeyManager;
     }
 
+    /*
+     * Returns Spake key manager or null for none.
+     */
+    Spake2PlusKeyManager getSpake2PlusKeyManager() {
+        return spake2PlusKeyManager;
+    }
+
     /*
      * Returns X.509 trust manager or null for none.
      */
@@ -538,7 +593,12 @@ final class SSLParametersImpl implements Cloneable {
 
     SSLParametersImpl cloneWithTrustManager(X509TrustManager newTrustManager) {
         return new SSLParametersImpl(clientSessionContext, serverSessionContext, x509KeyManager,
-                pskKeyManager, newTrustManager, this);
+                pskKeyManager, newTrustManager, null, null, this);
+    }
+
+    SSLParametersImpl cloneWithSpake() {
+        return new SSLParametersImpl(clientSessionContext, serverSessionContext, null, null, null,
+                spake2PlusTrustManager, spake2PlusKeyManager, this);
     }
 
     private static X509KeyManager getDefaultX509KeyManager() throws KeyManagementException {
@@ -601,6 +661,18 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
+    /*
+     * Returns the first Spake2PlusKeyManager element in the provided array.
+     */
+    private static Spake2PlusKeyManager findFirstSpake2PlusKeyManager(KeyManager[] kms) {
+        for (KeyManager km : kms) {
+            if (km instanceof Spake2PlusKeyManager) {
+                return (Spake2PlusKeyManager) km;
+            }
+        }
+        return null;
+    }
+
     /*
      * Returns the default X.509 trust manager.
      */
@@ -647,6 +719,18 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
+    /*
+     * Returns the first Spake2PlusTrustManager element in the provided array.
+     */
+    private static Spake2PlusTrustManager findFirstSpake2PlusTrustManager(TrustManager[] tms) {
+        for (TrustManager tm : tms) {
+            if (tm instanceof Spake2PlusTrustManager) {
+                return (Spake2PlusTrustManager) tm;
+            }
+        }
+        return null;
+    }
+
     String getEndpointIdentificationAlgorithm() {
         return endpointIdentificationAlgorithm;
     }
@@ -682,9 +766,8 @@ final class SSLParametersImpl implements Cloneable {
         this.useCipherSuitesOrder = useCipherSuitesOrder;
     }
 
-    private static String[] getDefaultCipherSuites(
-            boolean x509CipherSuitesNeeded,
-            boolean pskCipherSuitesNeeded) {
+    private static String[] getDefaultCipherSuites(boolean x509CipherSuitesNeeded,
+            boolean pskCipherSuitesNeeded, boolean spake2PlusCipherSuitesNeeded) {
         if (x509CipherSuitesNeeded) {
             // X.509 based cipher suites need to be listed.
             if (pskCipherSuitesNeeded) {
@@ -729,4 +812,8 @@ final class SSLParametersImpl implements Cloneable {
         }
         return Platform.isCTVerificationRequired(hostname);
     }
+
+    boolean isSpake() {
+        return spake2PlusKeyManager != null;
+    }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/Spake2PlusKeyManager.java b/repackaged/common/src/main/java/com/android/org/conscrypt/Spake2PlusKeyManager.java
new file mode 100644
index 00000000..26e7f128
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/Spake2PlusKeyManager.java
@@ -0,0 +1,82 @@
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
+package com.android.org.conscrypt;
+
+import java.security.Principal;
+import java.util.List;
+
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.SSLEngine;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class Spake2PlusKeyManager implements KeyManager {
+    private final byte[] context;
+    private final byte[] password;
+    private final byte[] idProver;
+    private final byte[] idVerifier;
+    private final boolean isClient;
+    private final int handshakeLimit;
+
+    Spake2PlusKeyManager(byte[] context, byte[] password, byte[] idProver,
+            byte[] idVerifier, boolean isClient, int handshakeLimit) {
+        this.context = context == null ? new byte[0] : context;
+        this.password = password;
+        this.idProver = idProver == null ? new byte[0] : idProver;
+        this.idVerifier = idVerifier == null ? new byte[0] : idVerifier;
+        this.isClient = isClient;
+        this.handshakeLimit = handshakeLimit;
+    }
+
+    public String chooseEngineAlias(String keyType, Principal[] issuers,
+            SSLEngine engine) {
+        throw new UnsupportedOperationException("Not implemented");
+    }
+
+    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
+            SSLEngine engine) {
+        throw new UnsupportedOperationException("Not implemented");
+    }
+
+    public byte[] getContext() {
+        return context;
+    }
+
+    public byte[] getPassword() {
+        return password;
+    }
+
+    public byte[] getIdProver() {
+        return idProver;
+    }
+
+    public byte[] getIdVerifier() {
+        return idVerifier;
+    }
+
+    public boolean isClient() {
+        return isClient;
+    }
+
+    public int getHandshakeLimit() {
+        return handshakeLimit;
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/Spake2PlusTrustManager.java b/repackaged/common/src/main/java/com/android/org/conscrypt/Spake2PlusTrustManager.java
new file mode 100644
index 00000000..fe85efc7
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/Spake2PlusTrustManager.java
@@ -0,0 +1,33 @@
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
+package com.android.org.conscrypt;
+
+import javax.net.ssl.TrustManager;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class Spake2PlusTrustManager implements TrustManager {
+    Spake2PlusTrustManager() {}
+
+    public void checkClientTrusted() {}
+
+    public void checkServerTrusted() {}
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
index a051dade..ffc618ec 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
@@ -35,12 +35,6 @@
 
 package com.android.org.conscrypt;
 
-import com.android.org.conscrypt.ct.LogStore;
-import com.android.org.conscrypt.ct.Policy;
-import com.android.org.conscrypt.ct.PolicyCompliance;
-import com.android.org.conscrypt.ct.VerificationResult;
-import com.android.org.conscrypt.ct.Verifier;
-
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.net.Socket;
@@ -142,15 +136,10 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private final Exception err;
     private final CertificateFactory factory;
     private final CertBlocklist blocklist;
-    private final LogStore ctLogStore;
-    private Verifier ctVerifier;
-    private Policy ctPolicy;
+    private final com.android.org.conscrypt.ct.CertificateTransparency ct;
 
     private ConscryptHostnameVerifier hostnameVerifier;
 
-    // Forces CT verification to always to done. For tests.
-    private boolean ctEnabledOverride;
-
     /**
      * Creates X509TrustManager based on a keystore
      */
@@ -160,6 +149,9 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this(keyStore, null);
     }
 
+    /* Implicitly used by CertPinManagerTest in CTS.
+     * TODO: remove in favor of the constructor below.
+     */
     public TrustManagerImpl(KeyStore keyStore, CertPinManager manager) {
         this(keyStore, manager, null);
     }
@@ -167,19 +159,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
     public TrustManagerImpl(
             KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore) {
-        this(keyStore, manager, certStore, null);
+        this(keyStore, manager, certStore, null, null);
     }
 
-    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
-            CertBlocklist blocklist) {
-        this(keyStore, manager, certStore, blocklist, null, null, null);
-    }
-
-    /**
-     * For testing only.
-     */
-    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
-            CertBlocklist blocklist, LogStore ctLogStore, Verifier ctVerifier, Policy ctPolicy) {
+    private TrustManagerImpl(KeyStore keyStore, CertPinManager manager,
+            ConscryptCertStore certStore, CertBlocklist blocklist,
+            com.android.org.conscrypt.ct.CertificateTransparency ct) {
         CertPathValidator validatorLocal = null;
         CertificateFactory factoryLocal = null;
         KeyStore rootKeyStoreLocal = null;
@@ -209,16 +194,12 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
             errLocal = e;
         }
 
+        if (ct == null) {
+            ct = Platform.newDefaultCertificateTransparency();
+        }
         if (blocklist == null) {
             blocklist = Platform.newDefaultBlocklist();
         }
-        if (ctLogStore == null) {
-            ctLogStore = Platform.newDefaultLogStore();
-        }
-
-        if (ctPolicy == null) {
-            ctPolicy = Platform.newDefaultPolicy();
-        }
 
         this.pinManager = manager;
         this.rootKeyStore = rootKeyStoreLocal;
@@ -230,12 +211,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         this.acceptedIssuers = acceptedIssuersLocal;
         this.err = errLocal;
         this.blocklist = blocklist;
-        this.ctLogStore = ctLogStore;
-        this.ctVerifier = new Verifier(ctLogStore);
-        this.ctPolicy = ctPolicy;
-        if (ctLogStore != null) {
-            ctLogStore.setPolicy(ctPolicy);
-        }
+        this.ct = ct;
     }
 
     @SuppressWarnings("JdkObsolete") // KeyStore#aliases is the only API available
@@ -344,7 +320,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
      * Socket (e.g., Cronet).
      */
     @android.annotation.FlaggedApi(com.android.org.conscrypt.flags.Flags
-                                           .FLAG_CERTIFICATE_TRANSPARENCY_CHECKSERVERTRUSTED_API)
+                    .FLAG_CERTIFICATE_TRANSPARENCY_CHECKSERVERTRUSTED_API)
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
     public List<X509Certificate>
     checkServerTrusted(X509Certificate[] chain, byte[] ocspData, byte[] tlsSctData, String authType,
@@ -703,11 +679,9 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                 checkBlocklist(cert);
             }
 
-            // Check CT (if required).
-            if (!clientAuth &&
-                    (ctEnabledOverride || (host != null && Platform
-                            .isCTVerificationRequired(host)))) {
-                checkCT(wholeChain, ocspData, tlsSctData);
+            // Check Certificate Transparency (if required).
+            if (!clientAuth && host != null && ct != null && ct.isCTVerificationRequired(host)) {
+                ct.checkCT(wholeChain, ocspData, tlsSctData, host);
             }
 
             if (untrustedChain.isEmpty()) {
@@ -753,26 +727,6 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
     }
 
-    private void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
-            throws CertificateException {
-        if (ctLogStore.getState() != LogStore.State.COMPLIANT) {
-            /* Fail open. For some reason, the LogStore is not usable. It could
-             * be because there is no log list available or that the log list
-             * is too old (according to the policy). */
-            return;
-        }
-        VerificationResult result =
-                ctVerifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);
-
-        X509Certificate leaf = chain.get(0);
-        PolicyCompliance compliance = ctPolicy.doesResultConformToPolicy(result, leaf);
-        if (compliance != PolicyCompliance.COMPLY) {
-            throw new CertificateException(
-                    "Certificate chain does not conform to required transparency policy: "
-                    + compliance.name());
-        }
-    }
-
     /**
      * Sets the OCSP response data that was possibly stapled to the TLS response.
      */
@@ -1052,18 +1006,4 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
         return Platform.getDefaultHostnameVerifier();
     }
-
-    public void setCTEnabledOverride(boolean enabled) {
-        this.ctEnabledOverride = enabled;
-    }
-
-    // Replace the CTVerifier. For testing only.
-    public void setCTVerifier(Verifier verifier) {
-        this.ctVerifier = verifier;
-    }
-
-    // Replace the CTPolicy. For testing only.
-    public void setCTPolicy(Policy policy) {
-        this.ctPolicy = policy;
-    }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java
new file mode 100644
index 00000000..baf553e6
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateTransparency.java
@@ -0,0 +1,87 @@
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
+import com.android.org.conscrypt.Internal;
+import com.android.org.conscrypt.Platform;
+import com.android.org.conscrypt.metrics.CertificateTransparencyVerificationReason;
+import com.android.org.conscrypt.metrics.StatsLog;
+
+import java.security.cert.CertificateException;
+import java.security.cert.X509Certificate;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * Certificate Transparency subsystem. The implementation contains references
+ * to its log store, its policy and its verifier.
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class CertificateTransparency {
+    private LogStore logStore;
+    private Verifier verifier;
+    private Policy policy;
+    private StatsLog statsLog;
+
+    public CertificateTransparency(
+            LogStore logStore, Policy policy, Verifier verifier, StatsLog statsLog) {
+        Objects.requireNonNull(logStore);
+        Objects.requireNonNull(policy);
+        Objects.requireNonNull(verifier);
+        Objects.requireNonNull(statsLog);
+
+        this.logStore = logStore;
+        this.policy = policy;
+        this.verifier = verifier;
+        this.statsLog = statsLog;
+    }
+
+    public boolean isCTVerificationRequired(String host) {
+        return Platform.isCTVerificationRequired(host);
+    }
+
+    public CertificateTransparencyVerificationReason reasonCTVerificationRequired(String host) {
+        return Platform.reasonCTVerificationRequired(host);
+    }
+
+    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
+            throws CertificateException {
+        if (logStore.getState() != LogStore.State.COMPLIANT) {
+            /* Fail open. For some reason, the LogStore is not usable. It could
+             * be because there is no log list available or that the log list
+             * is too old (according to the policy). */
+            statsLog.reportCTVerificationResult(logStore,
+                    /* VerificationResult */ null,
+                    /* PolicyCompliance */ null, reasonCTVerificationRequired(host));
+            return;
+        }
+        VerificationResult result =
+                verifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);
+
+        X509Certificate leaf = chain.get(0);
+        PolicyCompliance compliance = policy.doesResultConformToPolicy(result, leaf);
+        statsLog.reportCTVerificationResult(
+                logStore, result, compliance, reasonCTVerificationRequired(host));
+        if (compliance != PolicyCompliance.COMPLY) {
+            throw new CertificateException(
+                    "Certificate chain does not conform to required transparency policy: "
+                    + compliance.name());
+        }
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java
index c2a8498a..38627064 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogInfo.java
@@ -44,13 +44,17 @@ public class LogInfo {
     public static final int STATE_RETIRED = 5;
     public static final int STATE_REJECTED = 6;
 
+    public static final int TYPE_UNKNOWN = 0;
+    public static final int TYPE_RFC6962 = 1;
+    public static final int TYPE_STATIC_CT_API = 2;
+
     private final byte[] logId;
     private final PublicKey publicKey;
     private final int state;
     private final long stateTimestamp;
     private final String description;
-    private final String url;
     private final String operator;
+    private final int type;
 
     private LogInfo(Builder builder) {
         /* Based on the required fields for the log list schema v3. Notably,
@@ -58,7 +62,6 @@ public class LogInfo {
          * is validated in the builder. */
         Objects.requireNonNull(builder.logId);
         Objects.requireNonNull(builder.publicKey);
-        Objects.requireNonNull(builder.url);
         Objects.requireNonNull(builder.operator);
 
         this.logId = builder.logId;
@@ -66,8 +69,8 @@ public class LogInfo {
         this.state = builder.state;
         this.stateTimestamp = builder.stateTimestamp;
         this.description = builder.description;
-        this.url = builder.url;
         this.operator = builder.operator;
+        this.type = builder.type;
     }
 
     /**
@@ -79,8 +82,8 @@ public class LogInfo {
         private int state;
         private long stateTimestamp;
         private String description;
-        private String url;
         private String operator;
+        private int type;
 
         public Builder setPublicKey(PublicKey publicKey) {
             Objects.requireNonNull(publicKey);
@@ -109,18 +112,20 @@ public class LogInfo {
             return this;
         }
 
-        public Builder setUrl(String url) {
-            Objects.requireNonNull(url);
-            this.url = url;
-            return this;
-        }
-
         public Builder setOperator(String operator) {
             Objects.requireNonNull(operator);
             this.operator = operator;
             return this;
         }
 
+        public Builder setType(int type) {
+            if (type < 0 || type > TYPE_STATIC_CT_API) {
+                throw new IllegalArgumentException("invalid type value");
+            }
+            this.type = type;
+            return this;
+        }
+
         public LogInfo build() {
             return new LogInfo(this);
         }
@@ -141,10 +146,6 @@ public class LogInfo {
         return description;
     }
 
-    public String getUrl() {
-        return url;
-    }
-
     public int getState() {
         return state;
     }
@@ -164,6 +165,10 @@ public class LogInfo {
         return operator;
     }
 
+    public int getType() {
+        return type;
+    }
+
     @Override
     public boolean equals(Object other) {
         if (this == other) {
@@ -175,15 +180,14 @@ public class LogInfo {
 
         LogInfo that = (LogInfo) other;
         return this.state == that.state && this.description.equals(that.description)
-                && this.url.equals(that.url) && this.operator.equals(that.operator)
-                && this.stateTimestamp == that.stateTimestamp
-                && Arrays.equals(this.logId, that.logId);
+                && this.operator.equals(that.operator) && this.stateTimestamp == that.stateTimestamp
+                && this.type == that.type && Arrays.equals(this.logId, that.logId);
     }
 
     @Override
     public int hashCode() {
         return Objects.hash(
-                Arrays.hashCode(logId), description, url, state, stateTimestamp, operator);
+                Arrays.hashCode(logId), description, state, stateTimestamp, operator, type);
     }
 
     /**
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
index 7baeb251..8afb9341 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
@@ -36,8 +36,6 @@ public interface LogStore {
         NON_COMPLIANT,
     }
 
-    void setPolicy(Policy policy);
-
     State getState();
 
     int getMajorVersion();
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java
index 5f1a02a5..c38cdae9 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/PolicyCompliance.java
@@ -26,5 +26,6 @@ import com.android.org.conscrypt.Internal;
 public enum PolicyCompliance {
     COMPLY,
     NOT_ENOUGH_SCTS,
-    NOT_ENOUGH_DIVERSE_SCTS
+    NOT_ENOUGH_DIVERSE_SCTS,
+    NO_RFC6962_LOG
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java
index 7a2e5df1..efc2e60e 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/VerificationResult.java
@@ -17,10 +17,12 @@
 
 package com.android.org.conscrypt.ct;
 
+import com.android.org.conscrypt.Internal;
+
 import java.util.ArrayList;
 import java.util.Collections;
+import java.util.EnumMap;
 import java.util.List;
-import com.android.org.conscrypt.Internal;
 
 /**
  * Container for verified SignedCertificateTimestamp.
@@ -33,8 +35,10 @@ import com.android.org.conscrypt.Internal;
  */
 @Internal
 public class VerificationResult {
-    private final ArrayList<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>();
-    private final ArrayList<VerifiedSCT> invalidSCTs = new ArrayList<VerifiedSCT>();
+    private final List<VerifiedSCT> validSCTs = new ArrayList<>();
+    private final List<VerifiedSCT> invalidSCTs = new ArrayList<>();
+    private final EnumMap<SignedCertificateTimestamp.Origin, Integer> count =
+            new EnumMap<>(SignedCertificateTimestamp.Origin.class);
 
     public void add(VerifiedSCT result) {
         if (result.isValid()) {
@@ -42,6 +46,13 @@ public class VerificationResult {
         } else {
             invalidSCTs.add(result);
         }
+        SignedCertificateTimestamp.Origin origin = result.getSct().getOrigin();
+        Integer value = count.get(origin);
+        if (value == null) {
+            count.put(origin, 1);
+        } else {
+            count.put(origin, value + 1);
+        }
     }
 
     public List<VerifiedSCT> getValidSCTs() {
@@ -51,4 +62,18 @@ public class VerificationResult {
     public List<VerifiedSCT> getInvalidSCTs() {
         return Collections.unmodifiableList(invalidSCTs);
     }
+
+    public int numCertSCTs() {
+        Integer num = count.get(SignedCertificateTimestamp.Origin.EMBEDDED);
+        return (num == null ? 0 : num.intValue());
+    }
+
+    public int numOCSPSCTs() {
+        Integer num = count.get(SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
+        return (num == null ? 0 : num.intValue());
+    }
+    public int numTlsSCTs() {
+        Integer num = count.get(SignedCertificateTimestamp.Origin.TLS_EXTENSION);
+        return (num == null ? 0 : num.intValue());
+    }
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
new file mode 100644
index 00000000..c862d048
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/CertificateTransparencyVerificationReason.java
@@ -0,0 +1,46 @@
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
+package com.android.org.conscrypt.metrics;
+
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN;
+
+import com.android.org.conscrypt.Internal;
+
+/**
+ * Certificate Transparency Verification Reason.
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public enum CertificateTransparencyVerificationReason {
+    UNKNOWN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN),
+    APP_OPT_IN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN),
+    DOMAIN_OPT_IN(
+            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN);
+
+    final int id;
+
+    public int getId() {
+        return this.id;
+    }
+
+    private CertificateTransparencyVerificationReason(int id) {
+        this.id = id;
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
new file mode 100644
index 00000000..a38311c2
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
@@ -0,0 +1,246 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+package com.android.org.conscrypt.metrics;
+
+import com.android.org.conscrypt.Internal;
+
+/**
+ * Reimplement with reflection calls the logging class,
+ * generated by frameworks/statsd.
+ * <p>
+ * In case an atom is updated, generate the new wrapper with stats-log-api-gen
+ * tool as shown below and update the write methods to use ReflexiveStatsEvent
+ * and ReflexiveStatsLog.
+ * <p>
+ * $ stats-log-api-gen \
+ *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
+ *   --module conscrypt \
+ *   --javaPackage org.conscrypt.metrics \
+ *   --javaClass ConscryptStatsLog
+ * <p>
+ * This class is swapped with the generated wrapper for GMSCore. For this
+ * reason, the methods defined here should be identical to the generated
+ * methods from the wrapper. Do not add new method here, do not change the type
+ * of the parameters.
+ * @hide This class is not part of the Android public SDK API
+ **/
+@Internal
+public final class ConscryptStatsLog {
+    // clang-format off
+
+    // Constants for atom codes.
+
+    /**
+     * TlsHandshakeReported tls_handshake_reported<br>
+     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
+     */
+    public static final int TLS_HANDSHAKE_REPORTED = 317;
+
+    /**
+     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed<br>
+     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status, int loaded_compat_version, int min_compat_version, int major_version, int minor_version);<br>
+     */
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
+
+    /**
+     * ConscryptServiceUsed conscrypt_service_used<br>
+     * Usage: StatsLog.write(StatsLog.CONSCRYPT_SERVICE_USED, int algorithm, int cipher, int mode, int padding);<br>
+     */
+    public static final int CONSCRYPT_SERVICE_USED = 965;
+
+    /**
+     * CertificateTransparencyVerificationReported certificate_transparency_verification_reported<br>
+     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, int result, int reason, int policy_compatibility_version, int major_version, int minor_version, int num_cert_scts, int num_ocsp_scts, int num_tls_scts);<br>
+     */
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED = 989;
+
+    // Constants for enum values.
+
+    // Values for TlsHandshakeReported.protocol
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__UNKNOWN_PROTO = 0;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__SSL_V3 = 1;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1 = 2;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_1 = 3;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_2 = 4;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_V1_3 = 5;
+    public static final int TLS_HANDSHAKE_REPORTED__PROTOCOL__TLS_PROTO_FAILED = 65535;
+
+    // Values for TlsHandshakeReported.cipher_suite
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__UNKNOWN_CIPHER_SUITE = 0;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_128_CBC_SHA = 47;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_256_CBC_SHA = 53;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_PSK_WITH_AES_128_CBC_SHA = 140;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_PSK_WITH_AES_256_CBC_SHA = 141;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_128_GCM_SHA256 = 156;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_RSA_WITH_AES_256_GCM_SHA384 = 157;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_AES_128_GCM_SHA256 = 4865;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_AES_256_GCM_SHA384 = 4866;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_CHACHA20_POLY1305_SHA256 = 4867;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 49161;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 49162;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 49171;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 49172;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 49195;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 49196;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 49199;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 49200;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 49205;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 49206;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 52393;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52396;
+    public static final int TLS_HANDSHAKE_REPORTED__CIPHER_SUITE__TLS_CIPHER_FAILED = 65535;
+
+    // Values for TlsHandshakeReported.source
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN = 0;
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE = 1;
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS = 2;
+    public static final int TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED = 3;
+
+    // Values for CertificateTransparencyLogListStateChanged.status
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS = 1;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND = 2;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED = 3;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED = 4;
+
+    // Values for CertificateTransparencyLogListStateChanged.loaded_compat_version
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__LOADED_COMPAT_VERSION__COMPAT_VERSION_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__LOADED_COMPAT_VERSION__COMPAT_VERSION_V1 = 1;
+
+    // Values for CertificateTransparencyLogListStateChanged.min_compat_version
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__MIN_COMPAT_VERSION__COMPAT_VERSION_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__MIN_COMPAT_VERSION__COMPAT_VERSION_V1 = 1;
+
+    // Values for ConscryptServiceUsed.algorithm
+    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__UNKNOWN_ALGORITHM = 0;
+    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__CIPHER = 1;
+    public static final int CONSCRYPT_SERVICE_USED__ALGORITHM__SIGNATURE = 2;
+
+    // Values for ConscryptServiceUsed.cipher
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__UNKNOWN_CIPHER = 0;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__AES = 1;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DES = 2;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DESEDE = 3;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__DSA = 4;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__BLOWFISH = 5;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__CHACHA20 = 6;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__RSA = 7;
+    public static final int CONSCRYPT_SERVICE_USED__CIPHER__ARC4 = 8;
+
+    // Values for ConscryptServiceUsed.mode
+    public static final int CONSCRYPT_SERVICE_USED__MODE__NO_MODE = 0;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CBC = 1;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CTR = 2;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__ECB = 3;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CFB = 4;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__CTS = 5;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__GCM = 6;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__GCM_SIV = 7;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__OFB = 8;
+    public static final int CONSCRYPT_SERVICE_USED__MODE__POLY1305 = 9;
+
+    // Values for ConscryptServiceUsed.padding
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__NO_PADDING = 0;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA512 = 1;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA384 = 2;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA256 = 3;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA224 = 4;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__OAEP_SHA1 = 5;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__PKCS1 = 6;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__PKCS5 = 7;
+    public static final int CONSCRYPT_SERVICE_USED__PADDING__ISO10126 = 8;
+
+    // Values for CertificateTransparencyVerificationReported.result
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS = 1;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_GENERIC_FAILURE = 2;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND = 3;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT = 4;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE = 5;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT = 6;
+
+    // Values for CertificateTransparencyVerificationReported.reason
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DEVICE_WIDE_ENABLED = 1;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN = 3;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN = 4;
+
+    // Values for CertificateTransparencyVerificationReported.policy_compatibility_version
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_UNKNOWN = 0;
+    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__POLICY_COMPATIBILITY_VERSION__COMPAT_VERSION_V1 = 1;
+
+    // Write methods
+    public static void write(int code, boolean arg1, int arg2, int arg3, int arg4, int arg5, int[] arg6) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeBoolean(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+        builder.writeInt(arg5);
+        builder.writeIntArray(null == arg6 ? new int[0] : arg6);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    public static void write(int code, int arg1, int arg2, int arg3, int arg4) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeInt(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    public static void write(int code, int arg1, int arg2, int arg3, int arg4, int arg5) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeInt(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+        builder.writeInt(arg5);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    public static void write(int code, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8) {
+        final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+        builder.setAtomId(code);
+        builder.writeInt(arg1);
+        builder.writeInt(arg2);
+        builder.writeInt(arg3);
+        builder.writeInt(arg4);
+        builder.writeInt(arg5);
+        builder.writeInt(arg6);
+        builder.writeInt(arg7);
+        builder.writeInt(arg8);
+
+        builder.usePooledBuffer();
+        ReflexiveStatsLog.write(builder.build());
+    }
+
+    // clang-format on
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/NoopStatsLog.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/NoopStatsLog.java
new file mode 100644
index 00000000..1b2e87ec
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/NoopStatsLog.java
@@ -0,0 +1,41 @@
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
+package com.android.org.conscrypt.metrics;
+
+import com.android.org.conscrypt.Internal;
+import com.android.org.conscrypt.ct.LogStore;
+import com.android.org.conscrypt.ct.PolicyCompliance;
+import com.android.org.conscrypt.ct.VerificationResult;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class NoopStatsLog implements StatsLog {
+    private static final StatsLog INSTANCE = new NoopStatsLog();
+    public static StatsLog getInstance() {
+        return INSTANCE;
+    }
+
+    public void countTlsHandshake(
+            boolean success, String protocol, String cipherSuite, long duration) {}
+
+    public void updateCTLogListStatusChanged(LogStore logStore) {}
+
+    public void reportCTVerificationResult(LogStore logStore, VerificationResult result,
+            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason) {}
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ReflexiveStatsEvent.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ReflexiveStatsEvent.java
index f223363c..7b5c60de 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ReflexiveStatsEvent.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ReflexiveStatsEvent.java
@@ -17,6 +17,7 @@
 package com.android.org.conscrypt.metrics;
 
 import com.android.org.conscrypt.Internal;
+import com.android.org.conscrypt.Platform;
 
 /**
  * Reflection wrapper around android.util.StatsEvent.
@@ -26,14 +27,12 @@ import com.android.org.conscrypt.Internal;
 public class ReflexiveStatsEvent {
     private static final OptionalMethod newBuilder;
     private static final Class<?> c_statsEvent;
-    private static final Object sdkVersion;
     private static final boolean sdkVersionBiggerThan32;
 
     static {
-        sdkVersion = getSdkVersion();
         c_statsEvent = initStatsEventClass();
         newBuilder = new OptionalMethod(c_statsEvent, "newBuilder");
-        sdkVersionBiggerThan32 = (sdkVersion != null) && ((int) sdkVersion > 32);
+        sdkVersionBiggerThan32 = Platform.isSdkGreater(32);
     }
 
     private static Class<?> initStatsEventClass() {
@@ -58,6 +57,8 @@ public class ReflexiveStatsEvent {
         return new ReflexiveStatsEvent.Builder();
     }
 
+    /* Used by older CTS test */
+    @Deprecated
     public static ReflexiveStatsEvent buildEvent(int atomId, boolean success, int protocol,
             int cipherSuite, int duration, int source, int[] uids) {
         ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
@@ -67,15 +68,15 @@ public class ReflexiveStatsEvent {
         builder.writeInt(cipherSuite);
         builder.writeInt(duration);
         builder.writeInt(source);
-        if (sdkVersionBiggerThan32) {
-          builder.writeIntArray(uids);
-        }
+        builder.writeIntArray(uids);
         builder.usePooledBuffer();
         return builder.build();
     }
 
-    public static ReflexiveStatsEvent buildEvent(int atomId, boolean success, int protocol,
-            int cipherSuite, int duration, int source) {
+    /* Used by older CTS test */
+    @Deprecated
+    public static ReflexiveStatsEvent buildEvent(
+            int atomId, boolean success, int protocol, int cipherSuite, int duration, int source) {
         ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
         builder.setAtomId(atomId);
         builder.writeBoolean(success);
@@ -87,17 +88,6 @@ public class ReflexiveStatsEvent {
         return builder.build();
     }
 
-    static Object getSdkVersion() {
-        try {
-            OptionalMethod getSdkVersion =
-                    new OptionalMethod(Class.forName("dalvik.system.VMRuntime"),
-                                        "getSdkVersion");
-            return getSdkVersion.invokeStatic();
-        } catch (ClassNotFoundException e) {
-            return null;
-        }
-    }
-
     /**
      * @hide This class is not part of the Android public SDK API
      */
@@ -154,7 +144,9 @@ public class ReflexiveStatsEvent {
         }
 
         public Builder writeIntArray(final int[] values) {
-            writeIntArray.invoke(this.builder, values);
+            if (sdkVersionBiggerThan32) {
+                writeIntArray.invoke(this.builder, values);
+            }
             return this;
         }
 
@@ -163,4 +155,4 @@ public class ReflexiveStatsEvent {
             return new ReflexiveStatsEvent(statsEvent);
         }
     }
-}
\ No newline at end of file
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/Source.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/Source.java
index 8eafb8cd..9da92f93 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/Source.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/Source.java
@@ -16,6 +16,11 @@
  */
 package com.android.org.conscrypt.metrics;
 
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN;
+
 import com.android.org.conscrypt.Internal;
 
 /**
@@ -26,8 +31,18 @@ import com.android.org.conscrypt.Internal;
  */
 @Internal
 public enum Source {
-    SOURCE_UNKNOWN,
-    SOURCE_MAINLINE,
-    SOURCE_GMS,
-    SOURCE_UNBUNDLED;
-}
\ No newline at end of file
+    SOURCE_UNKNOWN(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN),
+    SOURCE_MAINLINE(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE),
+    SOURCE_GMS(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS),
+    SOURCE_UNBUNDLED(TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNBUNDLED);
+
+    final int id;
+
+    public int getId() {
+        return this.id;
+    }
+
+    private Source(int id) {
+        this.id = id;
+    }
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java
index 8a29a1be..0b13667d 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java
@@ -18,6 +18,8 @@ package com.android.org.conscrypt.metrics;
 
 import com.android.org.conscrypt.Internal;
 import com.android.org.conscrypt.ct.LogStore;
+import com.android.org.conscrypt.ct.PolicyCompliance;
+import com.android.org.conscrypt.ct.VerificationResult;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -28,4 +30,7 @@ public interface StatsLog {
             boolean success, String protocol, String cipherSuite, long duration);
 
     public void updateCTLogListStatusChanged(LogStore logStore);
+
+    public void reportCTVerificationResult(LogStore logStore, VerificationResult result,
+            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason);
 }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
index a4557bad..c26069d6 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
@@ -16,9 +16,26 @@
  */
 package com.android.org.conscrypt.metrics;
 
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
+import static com.android.org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED;
+
 import com.android.org.conscrypt.Internal;
 import com.android.org.conscrypt.Platform;
 import com.android.org.conscrypt.ct.LogStore;
+import com.android.org.conscrypt.ct.PolicyCompliance;
+import com.android.org.conscrypt.ct.VerificationResult;
 
 import java.lang.Thread.UncaughtExceptionHandler;
 import java.util.concurrent.ArrayBlockingQueue;
@@ -29,41 +46,14 @@ import java.util.concurrent.ThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
 
 /**
- * Reimplement with reflection calls the logging class,
- * generated by frameworks/statsd.
- * <p>
- * In case atom is changed, generate new wrapper with stats-log-api-gen
- * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
- * newEvent() method.
- * <p>
- * $ stats-log-api-gen \
- *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
- *   --module conscrypt \
- *   --javaPackage org.conscrypt.metrics \
- *   --javaClass StatsLog
  * @hide This class is not part of the Android public SDK API
- **/
+ */
 @Internal
 public final class StatsLogImpl implements StatsLog {
-    /**
-     * TlsHandshakeReported tls_handshake_reported
-     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int
-     * cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
-     */
-    public static final int TLS_HANDSHAKE_REPORTED = 317;
-
-    /**
-     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
-     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status,
-     * int loaded_compat_version, int min_compat_version_available, int major_version, int
-     * minor_version);<br>
-     */
-    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
-
     private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
         @Override
         public Thread newThread(Runnable r) {
-            Thread thread = new Thread(r);
+            Thread thread = new Thread(r, "ConscryptStatsLog");
             thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
                 @Override
                 public void uncaughtException(Thread t, Throwable e) {
@@ -87,33 +77,24 @@ public final class StatsLogImpl implements StatsLog {
         CipherSuite suite = CipherSuite.forName(cipherSuite);
 
         write(TLS_HANDSHAKE_REPORTED, success, proto.getId(), suite.getId(), (int) duration,
-                Platform.getStatsSource().ordinal(), Platform.getUids());
+                Platform.getStatsSource().getId(), Platform.getUids());
     }
 
     private static int logStoreStateToMetricsState(LogStore.State state) {
-        /* These constants must match the atom LogListStatus
-         * from frameworks/proto_logging/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
-         */
-        final int METRIC_UNKNOWN = 0;
-        final int METRIC_SUCCESS = 1;
-        final int METRIC_NOT_FOUND = 2;
-        final int METRIC_PARSING_FAILED = 3;
-        final int METRIC_EXPIRED = 4;
-
         switch (state) {
             case UNINITIALIZED:
             case LOADED:
-                return METRIC_UNKNOWN;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
             case NOT_FOUND:
-                return METRIC_NOT_FOUND;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
             case MALFORMED:
-                return METRIC_PARSING_FAILED;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
             case COMPLIANT:
-                return METRIC_SUCCESS;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
             case NON_COMPLIANT:
-                return METRIC_EXPIRED;
+                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
         }
-        return METRIC_UNKNOWN;
+        return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
     }
 
     @Override
@@ -124,15 +105,47 @@ public final class StatsLogImpl implements StatsLog {
                 logStore.getMinorVersion());
     }
 
+    private static int policyComplianceToMetrics(
+            VerificationResult result, PolicyCompliance compliance) {
+        if (compliance == PolicyCompliance.COMPLY) {
+            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
+        } else if (result.getValidSCTs().size() == 0) {
+            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
+        } else if (compliance == PolicyCompliance.NOT_ENOUGH_SCTS
+                || compliance == PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS
+                || compliance == PolicyCompliance.NO_RFC6962_LOG) {
+            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
+        }
+        return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
+    }
+
+    @Override
+    public void reportCTVerificationResult(LogStore store, VerificationResult result,
+            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason) {
+        if (store.getState() == LogStore.State.NOT_FOUND
+                || store.getState() == LogStore.State.MALFORMED) {
+            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
+                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE,
+                    reason.getId(), 0, 0, 0, 0, 0, 0);
+        } else if (store.getState() == LogStore.State.NON_COMPLIANT) {
+            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
+                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT,
+                    reason.getId(), 0, 0, 0, 0, 0, 0);
+        } else if (store.getState() == LogStore.State.COMPLIANT) {
+            int comp = policyComplianceToMetrics(result, compliance);
+            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, comp, reason.getId(),
+                    store.getCompatVersion(), store.getMajorVersion(), store.getMinorVersion(),
+                    result.numCertSCTs(), result.numOCSPSCTs(), result.numTlsSCTs());
+        }
+    }
+
     private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
             int source, int[] uids) {
         e.execute(new Runnable() {
             @Override
             public void run() {
-                ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
+                ConscryptStatsLog.write(
                         atomId, success, protocol, cipherSuite, duration, source, uids);
-
-                ReflexiveStatsLog.write(event);
             }
         });
     }
@@ -142,15 +155,21 @@ public final class StatsLogImpl implements StatsLog {
         e.execute(new Runnable() {
             @Override
             public void run() {
-                ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
-                builder.setAtomId(atomId);
-                builder.writeInt(status);
-                builder.writeInt(loadedCompatVersion);
-                builder.writeInt(minCompatVersionAvailable);
-                builder.writeInt(majorVersion);
-                builder.writeInt(minorVersion);
-                builder.usePooledBuffer();
-                ReflexiveStatsLog.write(builder.build());
+                ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
+                        minCompatVersionAvailable, majorVersion, minorVersion);
+            }
+        });
+    }
+
+    private void write(int atomId, int verificationResult, int verificationReason,
+            int policyCompatVersion, int majorVersion, int minorVersion, int numEmbeddedScts,
+            int numOcspScts, int numTlsScts) {
+        e.execute(new Runnable() {
+            @Override
+            public void run() {
+                ConscryptStatsLog.write(atomId, verificationResult, verificationReason,
+                        policyCompatVersion, majorVersion, minorVersion, numEmbeddedScts,
+                        numOcspScts, numTlsScts);
             }
         });
     }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java
index 74dcd43f..22568113 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/DuckTypedHpkeSpiTest.java
@@ -248,9 +248,8 @@ public class DuckTypedHpkeSpiTest {
         // Verify the SPI is indeed foreign.
         assertTrue(duckTyped.getDelegate() instanceof HpkeForeignSpi);
 
-        // And that it is delegating to a real HpkeImpl, so we can test it.
-        HpkeForeignSpi foreign = (HpkeForeignSpi) duckTyped.getDelegate();
-        assertTrue(foreign.realSpi instanceof HpkeImpl);
+        // And that it is delegating to a real implementation, so we can test it.
+        assertNotNull(duckTyped.getDelegate());
     }
 
     // Provides HpkeContext instances that use a "foreign" SPI, that is one that isn't
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java
index e83debcb..fecc9b4c 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/NativeCryptoArgTest.java
@@ -222,6 +222,18 @@ public class NativeCryptoArgTest {
         expectNPE("X509_print_ex", NULL, NOT_NULL, null, NULL, NULL);
     }
 
+    @Test
+    public void spake2Methods() throws Throwable {
+        expectNPE("SSL_CTX_set_spake_credential",
+                null, new byte[0], new byte[0], new byte[0], false, 1, NOT_NULL, null);
+        expectNPE("SSL_CTX_set_spake_credential",
+                new byte[0], null, new byte[0], new byte[0], false, 1, NOT_NULL, null);
+        expectNPE("SSL_CTX_set_spake_credential",
+                new byte[0], new byte[0], null, new byte[0], false, 1, NOT_NULL, null);
+        expectNPE("SSL_CTX_set_spake_credential",
+                new byte[0], new byte[0], new byte[0], null, false, 1, NOT_NULL, null);
+    }
+
     private void testMethods(MethodFilter filter, Class<? extends Throwable> exceptionClass)
             throws Throwable {
         List<Method> methods = filter.filter(methodMap.values());
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
index 0fc1dda7..1e0b7c38 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
@@ -58,14 +58,11 @@ public class VerifierTest {
         final LogInfo log = new LogInfo.Builder()
                                     .setPublicKey(key)
                                     .setDescription("Test Log")
-                                    .setUrl("http://example.com")
+                                    .setType(LogInfo.TYPE_RFC6962)
                                     .setOperator("LogOperator")
                                     .setState(LogInfo.STATE_USABLE, 1643709600000L)
                                     .build();
         LogStore store = new LogStore() {
-            @Override
-            public void setPolicy(Policy policy) {}
-
             @Override
             public State getState() {
                 return LogStore.State.COMPLIANT;
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
index 4f84bf73..7e29fb15 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
@@ -419,7 +419,7 @@ public class X509CertificateTest {
         // Collection, so there is no guarantee of the provider using a particular order. Normalize
         // the order before comparing.
         result.sort(Comparator.comparingInt((Pair<Integer, String> a) -> a.getFirst())
-                            .thenComparing(Pair::getSecond));
+                        .thenComparing(Pair::getSecond));
         return result;
     }
 
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java
index 5bb092f6..2c6688be 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherBasicsTest.java
@@ -31,6 +31,7 @@ import org.junit.runners.JUnit4;
 
 import java.nio.ByteBuffer;
 import java.security.AlgorithmParameters;
+import java.security.GeneralSecurityException;
 import java.security.InvalidAlgorithmParameterException;
 import java.security.InvalidKeyException;
 import java.security.Key;
@@ -90,6 +91,118 @@ public final class CipherBasicsTest {
         TestUtils.assumeAllowsUnsignedCrypto();
     }
 
+    private enum CallPattern {
+        DO_FINAL,
+        DO_FINAL_WITH_OFFSET,
+        UPDATE_DO_FINAL,
+        MULTIPLE_UPDATE_DO_FINAL,
+        UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY,
+        UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY_AND_OFFSET,
+        DO_FINAL_WITH_INPUT_OUTPUT_ARRAY,
+        DO_FINAL_WITH_INPUT_OUTPUT_ARRAY_AND_OFFSET,
+        UPDATE_DO_FINAL_WITH_INPUT_OUTPUT_ARRAY
+    }
+
+    /** Concatenates the given arrays into a single array.*/
+    byte[] concatArrays(byte[]... arrays) {
+        int length = 0;
+        for (byte[] array : arrays) {
+            if (array == null) {
+                continue;
+            }
+            length += array.length;
+        }
+        byte[] result = new byte[length];
+        int pos = 0;
+        for (byte[] array : arrays) {
+            if (array == null) {
+                continue;
+            }
+            System.arraycopy(array, 0, result, pos, array.length);
+            pos += array.length;
+        }
+        return result;
+    }
+
+    /** Calls an initialized cipher with different equivalent call patterns. */
+    private byte[] callCipher(Cipher cipher, byte[] input, int expectedOutputLength,
+            CallPattern callPattern) throws GeneralSecurityException {
+        switch (callPattern) {
+            case DO_FINAL: {
+                return cipher.doFinal(input);
+            }
+            case DO_FINAL_WITH_OFFSET: {
+                byte[] inputCopy = new byte[input.length + 100];
+                int inputOffset = 42;
+                System.arraycopy(input, 0, inputCopy, inputOffset, input.length);
+                return cipher.doFinal(inputCopy, inputOffset, input.length);
+            }
+            case UPDATE_DO_FINAL: {
+                byte[] output1 = cipher.update(input);
+                byte[] output2 = cipher.doFinal();
+                return concatArrays(output1, output2);
+            }
+            case MULTIPLE_UPDATE_DO_FINAL: {
+                int input1Length = input.length / 2;
+                int input2Length = input.length - input1Length;
+                byte[] output1 = cipher.update(input, /*inputOffset= */ 0, input1Length);
+                int input2Offset = input1Length;
+                byte[] output2 = cipher.update(input, input2Offset, input2Length);
+                byte[] output3 = cipher.update(new byte[0]);
+                byte[] output4 = cipher.doFinal();
+                return concatArrays(output1, output2, output3, output4);
+            }
+            case UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY: {
+                byte[] output1 = cipher.update(input);
+                int output1Length = (output1 == null) ? 0 : output1.length;
+                byte[] output2 = new byte[expectedOutputLength - output1Length];
+                int written = cipher.doFinal(output2, /*outputOffset= */ 0);
+                assertEquals(expectedOutputLength - output1Length, written);
+                return concatArrays(output1, output2);
+            }
+            case UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY_AND_OFFSET: {
+                byte[] output1 = cipher.update(input);
+                int output1Length = (output1 == null) ? 0 : output1.length;
+                byte[] output2WithOffset = new byte[expectedOutputLength + 100];
+                int outputOffset = 42;
+                int written = cipher.doFinal(output2WithOffset, outputOffset);
+                assertEquals(expectedOutputLength - output1Length, written);
+                byte[] output2 =
+                        Arrays.copyOfRange(output2WithOffset, outputOffset, outputOffset + written);
+                return concatArrays(output1, output2);
+            }
+            case DO_FINAL_WITH_INPUT_OUTPUT_ARRAY: {
+                byte[] output = new byte[expectedOutputLength];
+                int written = cipher.doFinal(input, /*inputOffset= */ 0, input.length, output);
+                assertEquals(expectedOutputLength, written);
+                return output;
+            }
+            case DO_FINAL_WITH_INPUT_OUTPUT_ARRAY_AND_OFFSET: {
+                byte[] inputWithOffset = new byte[input.length + 100];
+                int inputOffset = 37;
+                System.arraycopy(input, 0, inputWithOffset, inputOffset, input.length);
+                byte[] outputWithOffset = new byte[expectedOutputLength + 100];
+                int outputOffset = 21;
+                int written = cipher.doFinal(
+                        inputWithOffset, inputOffset, input.length, outputWithOffset, outputOffset);
+                return Arrays.copyOfRange(outputWithOffset, outputOffset, outputOffset + written);
+            }
+            case UPDATE_DO_FINAL_WITH_INPUT_OUTPUT_ARRAY: {
+                int input1Length = input.length / 2;
+                byte[] output = new byte[expectedOutputLength];
+                int written1 = cipher.update(input, /*inputOffset= */ 0, input1Length, output);
+                int input2Offset = input1Length;
+                int input2Length = input.length - input1Length;
+                int outputOffset = written1;
+                int written2 =
+                        cipher.doFinal(input, input2Offset, input2Length, output, outputOffset);
+                assertEquals(expectedOutputLength, written1 + written2);
+                return output;
+            }
+        }
+        throw new IllegalArgumentException("Unsupported CallPattern: " + callPattern);
+    }
+
     @Test
     public void testBasicEncryption() throws Exception {
         for (Provider p : Security.getProviders()) {
@@ -137,25 +250,38 @@ public final class CipherBasicsTest {
                     }
 
                     try {
-                        cipher.init(Cipher.ENCRYPT_MODE, key, params);
-                        assertEquals("Provider " + p.getName()
-                                        + ", algorithm " + transformation
-                                        + " reported the wrong output size",
-                                ciphertext.length, cipher.getOutputSize(plaintext.length));
-                        assertArrayEquals("Provider " + p.getName() + ", algorithm "
-                                        + transformation + " failed on encryption, data is "
-                                        + Arrays.toString(line),
-                                ciphertext, cipher.doFinal(plaintext));
-
-                        cipher.init(Cipher.DECRYPT_MODE, key, params);
-                        assertEquals("Provider " + p.getName()
-                                        + ", algorithm " + transformation
-                                        + " reported the wrong output size",
-                                plaintext.length, cipher.getOutputSize(ciphertext.length));
-                        assertArrayEquals("Provider " + p.getName() + ", algorithm "
-                                        + transformation + " failed on decryption, data is "
-                                        + Arrays.toString(line),
-                                plaintext, cipher.doFinal(ciphertext));
+                        for (CallPattern callPattern : CallPattern.values()) {
+                            cipher.init(Cipher.ENCRYPT_MODE, key, params);
+                            assertEquals("Provider " + p.getName() + ", algorithm " + transformation
+                                            + " reported the wrong output size",
+                                    ciphertext.length, cipher.getOutputSize(plaintext.length));
+                            byte[] encrypted =
+                                    callCipher(cipher, plaintext, ciphertext.length, callPattern);
+                            assertArrayEquals("Provider " + p.getName() + ", algorithm "
+                                            + transformation + ", CallPattern " + callPattern
+                                            + " failed on encryption, data is "
+                                            + Arrays.toString(line),
+                                    ciphertext, encrypted);
+
+                            cipher.init(Cipher.DECRYPT_MODE, key, params);
+                            byte[] decrypted;
+                            try {
+                                decrypted = callCipher(
+                                        cipher, ciphertext, plaintext.length, callPattern);
+                            } catch (GeneralSecurityException e) {
+                                throw new GeneralSecurityException("Provider " + p.getName()
+                                                + ", algorithm " + transformation
+                                                + ", CallPattern " + callPattern
+                                                + " failed on decryption, data is "
+                                                + Arrays.toString(line),
+                                        e);
+                            }
+                            assertArrayEquals("Provider " + p.getName() + ", algorithm "
+                                            + transformation + ", CallPattern " + callPattern
+                                            + " failed on decryption, data is "
+                                            + Arrays.toString(line),
+                                    plaintext, decrypted);
+                        }
                     } catch (InvalidKeyException e) {
                         // Some providers may not support raw SecretKeySpec keys, that's allowed
                     }
@@ -164,33 +290,73 @@ public final class CipherBasicsTest {
         }
     }
 
+    private static AlgorithmParameterSpec modifiedParams(AlgorithmParameterSpec params) {
+        if (params instanceof IvParameterSpec) {
+            IvParameterSpec ivSpec = (IvParameterSpec) params;
+            byte[] iv = ivSpec.getIV();
+            iv[0] = (byte) (iv[0] ^ 1);
+            return new IvParameterSpec(iv);
+        } else if (params instanceof GCMParameterSpec) {
+            GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
+            byte[] iv = gcmSpec.getIV();
+            iv[0] = (byte) (iv[0] ^ 1);
+            return new GCMParameterSpec(gcmSpec.getTLen(), iv);
+        } else {
+            throw new IllegalArgumentException("Unsupported AlgorithmParameterSpec: " + params);
+        }
+    }
+
+    static final byte[] EMPTY_AAD = new byte[0];
+
     public void arrayBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] plaintext,
             byte[] ciphertext, Key key, AlgorithmParameterSpec params, String transformation,
             Provider p, String[] line) throws Exception {
-        cipher.init(Cipher.ENCRYPT_MODE, key, params);
-        if (aad.length > 0) {
-            cipher.updateAAD(aad);
+        byte[] combinedCiphertext = new byte[ciphertext.length + tag.length];
+        System.arraycopy(ciphertext, 0, combinedCiphertext, 0, ciphertext.length);
+        System.arraycopy(tag, 0, combinedCiphertext, ciphertext.length, tag.length);
+
+        for (CallPattern callPattern : CallPattern.values()) {
+            // We first initialize the cipher with a modified IV to make sure that we don't trigger
+            // an IV reuse check.
+            cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));
+
+            cipher.init(Cipher.ENCRYPT_MODE, key, params);
+            if (aad.length > 0) {
+                cipher.updateAAD(aad);
+            }
+            assertEquals("Provider " + p.getName() + ", algorithm " + transformation
+                            + " reported the wrong output size",
+                    combinedCiphertext.length, cipher.getOutputSize(plaintext.length));
+            byte[] encrypted =
+                    callCipher(cipher, plaintext, combinedCiphertext.length, callPattern);
+            assertArrayEquals("Provider " + p.getName() + ", algorithm " + transformation
+                            + ", CallPattern " + callPattern + " failed on encryption, data is "
+                            + Arrays.toString(line),
+                    combinedCiphertext, encrypted);
         }
-        byte[] combinedOutput = new byte[ciphertext.length + tag.length];
-        assertEquals("Provider " + p.getName() + ", algorithm " + transformation
-                        + " reported the wrong output size",
-                combinedOutput.length, cipher.getOutputSize(plaintext.length));
-        System.arraycopy(ciphertext, 0, combinedOutput, 0, ciphertext.length);
-        System.arraycopy(tag, 0, combinedOutput, ciphertext.length, tag.length);
-        assertArrayEquals("Provider " + p.getName() + ", algorithm " + transformation
-                        + " failed on encryption, data is " + Arrays.toString(line),
-                combinedOutput, cipher.doFinal(plaintext));
 
-        cipher.init(Cipher.DECRYPT_MODE, key, params);
-        if (aad.length > 0) {
-            cipher.updateAAD(aad);
+        for (CallPattern callPattern : CallPattern.values()) {
+            cipher.init(Cipher.DECRYPT_MODE, key, params);
+            if (aad.length > 0) {
+                cipher.updateAAD(aad);
+            }
+            assertEquals("Provider " + p.getName() + ", algorithm " + transformation
+                            + " reported the wrong output size",
+                    plaintext.length, cipher.getOutputSize(combinedCiphertext.length));
+            byte[] decrypted;
+            try {
+                decrypted = callCipher(cipher, combinedCiphertext, plaintext.length, callPattern);
+            } catch (GeneralSecurityException e) {
+                throw new GeneralSecurityException("Provider " + p.getName() + ", algorithm "
+                                + transformation + ", CallPattern " + callPattern
+                                + " failed on decryption, data is " + Arrays.toString(line),
+                        e);
+            }
+            assertArrayEquals("Provider " + p.getName() + ", algorithm " + transformation
+                            + ", CallPattern " + callPattern + " failed on decryption, data is "
+                            + Arrays.toString(line),
+                    plaintext, decrypted);
         }
-        assertEquals("Provider " + p.getName() + ", algorithm " + transformation
-                        + " reported the wrong output size",
-                plaintext.length, cipher.getOutputSize(combinedOutput.length));
-        assertArrayEquals("Provider " + p.getName() + ", algorithm " + transformation
-                        + " failed on decryption, data is " + Arrays.toString(line),
-                plaintext, cipher.doFinal(combinedOutput));
     }
 
     @Test
@@ -256,6 +422,13 @@ public final class CipherBasicsTest {
                     } catch (InvalidAlgorithmParameterException e) {
                         // Some providers may not support all tag lengths or nonce lengths,
                         // that's allowed
+                        if (e.getMessage().contains("IV must not be re-used")) {
+                            throw new AssertionError("The same IV was used twice and therefore "
+                                                     + "some tests did not run."
+                                            + "Provider = " + p.getName()
+                                            + ", algorithm = " + transformation,
+                                    e);
+                        }
                     }
                 }
             }
@@ -265,6 +438,10 @@ public final class CipherBasicsTest {
     public void sharedBufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag,
             byte[] _plaintext, byte[] _ciphertext, Key key, AlgorithmParameterSpec params,
             String transformation, Provider p) throws Exception {
+        // We first initialize the cipher with a modified IV to make sure that we don't trigger
+        // an IV reuse check.
+        cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));
+
         cipher.init(Cipher.ENCRYPT_MODE, key, params);
         if (aad.length > 0) {
             cipher.updateAAD(aad);
@@ -315,6 +492,10 @@ public final class CipherBasicsTest {
     public void bufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] _plaintext,
             byte[] _ciphertext, Key key, AlgorithmParameterSpec params, String transformation,
             Provider p, boolean inBoolDirect, boolean outBoolDirect) throws Exception {
+        // We first initialize the cipher with a modified IV to make sure that we don't trigger
+        // an IV reuse check.
+        cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));
+
         cipher.init(Cipher.ENCRYPT_MODE, key, params);
         if (aad.length > 0) {
             cipher.updateAAD(aad);
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java
index 3f5bd367..718c9625 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/KeyManagerFactoryTest.java
@@ -17,12 +17,24 @@
 
 package com.android.org.conscrypt.javax.net.ssl;
 
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
+import com.android.org.conscrypt.KeyManagerFactoryImpl;
+import com.android.org.conscrypt.TestUtils;
+import com.android.org.conscrypt.java.security.StandardNames;
+import com.android.org.conscrypt.java.security.TestKeyStore;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
@@ -43,20 +55,14 @@ import java.security.cert.X509Certificate;
 import java.util.Arrays;
 import java.util.Date;
 import java.util.Enumeration;
+
 import javax.net.ssl.KeyManager;
 import javax.net.ssl.KeyManagerFactory;
 import javax.net.ssl.KeyStoreBuilderParameters;
 import javax.net.ssl.ManagerFactoryParameters;
 import javax.net.ssl.X509ExtendedKeyManager;
 import javax.net.ssl.X509KeyManager;
-import com.android.org.conscrypt.KeyManagerFactoryImpl;
-import com.android.org.conscrypt.TestUtils;
-import com.android.org.conscrypt.java.security.StandardNames;
-import com.android.org.conscrypt.java.security.TestKeyStore;
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+
 import tests.util.ServiceTester;
 
 /**
@@ -149,6 +155,11 @@ public class KeyManagerFactoryTest {
             }
         }
 
+        if (kmf.getAlgorithm().equals("PAKE")) {
+            assertThrows(KeyStoreException.class, () -> kmf.init(null, null));
+            return; // Functional testing is in PakeKeyManagerFactoryTest
+        }
+
         // init with null for default behavior
         kmf.init(null, null);
         test_KeyManagerFactory_getKeyManagers(kmf, true);
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java
index e816ac5f..c0086b20 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketTest.java
@@ -71,11 +71,14 @@ import java.util.concurrent.atomic.AtomicInteger;
 import javax.crypto.SecretKey;
 import javax.crypto.spec.SecretKeySpec;
 import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactory;
+import javax.net.ssl.ManagerFactoryParameters;
 import javax.net.ssl.SSLContext;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLHandshakeException;
 import javax.net.ssl.SSLParameters;
 import javax.net.ssl.SSLProtocolException;
+import javax.net.ssl.SSLServerSocket;
 import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
@@ -307,21 +310,21 @@ public class SSLSocketTest {
         try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
             // The TLS 1.3 cipher suites should be enabled by default
             assertTrue(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
-                               .containsAll(StandardNames.CIPHER_SUITES_TLS13));
+                            .containsAll(StandardNames.CIPHER_SUITES_TLS13));
             // Disabling them should be ignored
             ssl.setEnabledCipherSuites(new String[0]);
             assertTrue(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
-                               .containsAll(StandardNames.CIPHER_SUITES_TLS13));
+                            .containsAll(StandardNames.CIPHER_SUITES_TLS13));
 
             ssl.setEnabledCipherSuites(new String[] {
                     TestUtils.pickArbitraryNonTls13Suite(ssl.getSupportedCipherSuites())});
             assertTrue(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
-                               .containsAll(StandardNames.CIPHER_SUITES_TLS13));
+                            .containsAll(StandardNames.CIPHER_SUITES_TLS13));
 
             // Disabling TLS 1.3 should disable 1.3 cipher suites
             ssl.setEnabledProtocols(new String[] {"TLSv1.2"});
             assertFalse(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
-                                .containsAll(StandardNames.CIPHER_SUITES_TLS13));
+                            .containsAll(StandardNames.CIPHER_SUITES_TLS13));
         }
     }
 
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java
index e85787b5..e2408b04 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/TrustManagerFactoryTest.java
@@ -40,6 +40,7 @@ import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.X509TrustManager;
 import org.bouncycastle.asn1.x509.KeyPurposeId;
 import com.android.org.conscrypt.Conscrypt;
+import com.android.org.conscrypt.Spake2PlusTrustManager;
 import com.android.org.conscrypt.java.security.StandardNames;
 import com.android.org.conscrypt.java.security.TestKeyStore;
 import org.junit.Test;
@@ -88,19 +89,24 @@ public class TrustManagerFactoryTest {
         assertNotNull(tmf.getProvider());
 
         // before init
-        try {
-            tmf.getTrustManagers();
-            fail();
-        } catch (IllegalStateException expected) {
-            // Ignored.
-        }
+        if (!tmf.getAlgorithm().equals("PAKE")) {
+            try {
+                tmf.getTrustManagers();
+                fail();
+            } catch (IllegalStateException expected) {
+                // Ignored.
+            }
 
-        // init with null ManagerFactoryParameters
-        try {
+            // init with null ManagerFactoryParameters
+            try {
+                tmf.init((ManagerFactoryParameters) null);
+                fail();
+            } catch (InvalidAlgorithmParameterException expected) {
+                // Ignored.
+            }
+        } else {
             tmf.init((ManagerFactoryParameters) null);
-            fail();
-        } catch (InvalidAlgorithmParameterException expected) {
-            // Ignored.
+            test_TrustManagerFactory_getTrustManagers(tmf);
         }
 
         // init with useless ManagerFactoryParameters
@@ -142,8 +148,10 @@ public class TrustManagerFactoryTest {
         test_TrustManagerFactory_getTrustManagers(tmf);
 
         // init with specific key store
-        tmf.init(getTestKeyStore().keyStore);
-        test_TrustManagerFactory_getTrustManagers(tmf);
+        if (!tmf.getAlgorithm().equals("PAKE")) {
+            tmf.init(getTestKeyStore().keyStore);
+            test_TrustManagerFactory_getTrustManagers(tmf);
+        }
     }
 
     private void test_TrustManagerFactory_getTrustManagers(TrustManagerFactory tmf)
@@ -156,9 +164,17 @@ public class TrustManagerFactoryTest {
             if (trustManager instanceof X509TrustManager) {
                 test_X509TrustManager(tmf.getProvider(), (X509TrustManager) trustManager);
             }
+            if (trustManager instanceof Spake2PlusTrustManager) {
+                test_pakeTrustManager((Spake2PlusTrustManager) trustManager);
+            }
         }
     }
 
+    private void test_pakeTrustManager(Spake2PlusTrustManager tm) throws Exception {
+        tm.checkClientTrusted();
+        tm.checkServerTrusted();
+    }
+
     private void test_X509TrustManager(Provider p, X509TrustManager tm) throws Exception {
         for (String keyType : KEY_TYPES) {
             X509Certificate[] issuers = tm.getAcceptedIssuers();
@@ -235,6 +251,9 @@ public class TrustManagerFactoryTest {
                 @Override
                 public void test(Provider p, String algorithm) throws Exception {
                     TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
+                    if (tmf.getAlgorithm() == "PAKE") {
+                        return;
+                    }
                     tmf.init(keyStore);
                     TrustManager[] trustManagers = tmf.getTrustManagers();
                     for (TrustManager trustManager : trustManagers) {
diff --git a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
index 0d5a7348..de229cc0 100644
--- a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
@@ -38,10 +38,12 @@ import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
 
 import com.android.org.conscrypt.NativeCrypto;
-import com.android.org.conscrypt.ct.LogStore;
-import com.android.org.conscrypt.ct.Policy;
+import com.android.org.conscrypt.ct.CertificateTransparency;
+import com.android.org.conscrypt.metrics.CertificateTransparencyVerificationReason;
+import com.android.org.conscrypt.metrics.NoopStatsLog;
 import com.android.org.conscrypt.metrics.Source;
 import com.android.org.conscrypt.metrics.StatsLog;
+import com.android.org.conscrypt.metrics.StatsLogImpl;
 
 import java.io.File;
 import java.io.FileDescriptor;
@@ -99,7 +101,7 @@ final public class Platform {
     private static final Method GET_CURVE_NAME_METHOD;
     static boolean DEPRECATED_TLS_V1 = true;
     static boolean ENABLED_TLS_V1 = false;
-    private static boolean FILTERED_TLS_V1 = true;
+    private static boolean FILTERED_TLS_V1 = false;
 
     static {
         NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
@@ -651,7 +653,7 @@ final public class Platform {
      * - conscrypt.ct.enforce.com.*
      * - conscrypt.ct.enforce.*
      */
-    static boolean isCTVerificationRequired(String hostname) {
+    public static boolean isCTVerificationRequired(String hostname) {
         if (hostname == null) {
             return false;
         }
@@ -683,6 +685,11 @@ final public class Platform {
         return enable;
     }
 
+    public static CertificateTransparencyVerificationReason reasonCTVerificationRequired(
+            String hostname) {
+        return CertificateTransparencyVerificationReason.UNKNOWN;
+    }
+
     static boolean supportsConscryptCertStore() {
         return false;
     }
@@ -747,11 +754,7 @@ final public class Platform {
         return null;
     }
 
-    static LogStore newDefaultLogStore() {
-        return null;
-    }
-
-    static Policy newDefaultPolicy() {
+    static CertificateTransparency newDefaultCertificateTransparency() {
         return null;
     }
 
@@ -832,12 +835,12 @@ final public class Platform {
     }
 
     public static StatsLog getStatsLog() {
-        return null;
+        return NoopStatsLog.getInstance();
     }
 
     @SuppressWarnings("unused")
     public static Source getStatsSource() {
-        return null;
+        return Source.SOURCE_UNKNOWN;
     }
 
     @SuppressWarnings("unused")
@@ -860,4 +863,12 @@ final public class Platform {
     public static boolean isTlsV1Supported() {
         return ENABLED_TLS_V1;
     }
+
+    public static boolean isPakeSupported() {
+        return false;
+    }
+
+    public static boolean isSdkGreater(int sdk) {
+        return false;
+    }
 }
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
index 81e2a8b8..f89a67fc 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
@@ -675,8 +675,7 @@ public class ConscryptSocketTest {
                         + connection.clientException.getClass().getSimpleName() + ": "
                         + connection.clientException.getMessage(),
                 connection.clientException instanceof SSLHandshakeException);
-        assertTrue(
-                connection.clientException.getMessage().contains("SSLv3 is no longer supported"));
+        assertTrue(connection.clientException.getMessage().contains("SSLv3"));
         assertTrue("Expected SSLHandshakeException, but got "
                         + connection.serverException.getClass().getSimpleName() + ": "
                         + connection.serverException.getMessage(),
@@ -743,16 +742,26 @@ public class ConscryptSocketTest {
         final TestConnection connection =
                 new TestConnection(new X509Certificate[] {cert, ca}, certKey);
         connection.doHandshakeSuccess();
+        // Max app data size that will fit in a single TLS record.
+        int maxDataSize = connection.client.getSession().getApplicationBufferSize();
 
-        // Basic data flow assurance.  Send random buffers in each direction, each less than 16K
-        // so should fit in a single TLS packet.  50% chance of sending in each direction on
-        // each iteration to randomize the flow.
+        // Zero sized reads and writes. InputStream.read() allows zero size reads
+        // to succeed even when no data is available.
+        sendData(connection.client, connection.server, randomBuffer(0));
+        sendData(connection.server, connection.client, randomBuffer(0));
+
+        // Completely full record.
+        sendData(connection.client, connection.server, randomBuffer(maxDataSize));
+        sendData(connection.server, connection.client, randomBuffer(maxDataSize));
+
+        // Random workout. Send random sized buffers in each direction, 50% chance of sending in
+        // each direction  on each iteration to randomize the flow.
         for (int i = 0; i < 50; i++) {
             if (random.nextBoolean()) {
-                sendData(connection.client, connection.server, randomBuffer());
+                sendData(connection.client, connection.server, randomSizeBuffer(maxDataSize));
             }
             if (random.nextBoolean()) {
-                sendData(connection.server, connection.client, randomBuffer());
+                sendData(connection.server, connection.client, randomSizeBuffer(maxDataSize));
             }
         }
     }
@@ -761,16 +770,20 @@ public class ConscryptSocketTest {
             throws Exception {
         final byte[] received = new byte[data.length];
 
-        Future<Integer> readFuture =
-                executor.submit(() -> destination.getInputStream().read(received));
-
         source.getOutputStream().write(data);
-        assertEquals(data.length, (int) readFuture.get());
+        assertEquals(data.length, destination.getInputStream().read(received));
         assertArrayEquals(data, received);
     }
 
-    private byte[] randomBuffer() {
-        byte[] buffer = new byte[random.nextInt(16 * 1024)];
+    // Returns a random sized buffer containing random data.
+    // Zero and maxSize are valid possible sizes for the returned buffer.
+    private byte[] randomSizeBuffer(int maxSize) {
+        return randomBuffer(random.nextInt(maxSize + 1));
+    }
+
+    // Returns a buffer of random data of the size requested.
+    private byte[] randomBuffer(int size) {
+        byte[] buffer = new byte[size];
         random.nextBytes(buffer);
         return buffer;
     }
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java
index 7e11eb7c..83446bd0 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java
@@ -17,7 +17,17 @@
 
 package com.android.org.conscrypt;
 
-import junit.framework.TestCase;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertSame;
+import static org.junit.Assert.fail;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 import java.lang.reflect.InvocationHandler;
 import java.lang.reflect.Method;
@@ -38,32 +48,30 @@ import javax.net.ssl.SSLSocketFactory;
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class DuckTypedPSKKeyManagerTest extends TestCase {
+@RunWith(JUnit4.class)
+public class DuckTypedPSKKeyManagerTest {
     private SSLSocket mSSLSocket;
     private SSLEngine mSSLEngine;
 
-    @Override
-    protected void setUp() throws Exception {
-        super.setUp();
+    @Before
+    public void setUp() throws Exception {
         SSLContext sslContext = SSLContext.getDefault();
         SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
         mSSLSocket = (SSLSocket) sslSocketFactory.createSocket();
         mSSLEngine = sslContext.createSSLEngine();
     }
 
-    @Override
-    protected void tearDown() throws Exception {
-        try {
-            if (mSSLSocket != null) {
-                try {
-                    mSSLSocket.close();
-                } catch (Exception ignored) {}
+    @After
+    public void tearDown() throws Exception {
+        if (mSSLSocket != null) {
+            try {
+                mSSLSocket.close();
+            } catch (Exception ignored) {
             }
-        } finally {
-            super.tearDown();
         }
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingFailsWhenOneMethodMissing() throws Exception {
         try {
@@ -72,6 +80,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         } catch (NoSuchMethodException expected) {}
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingFailsWhenOneMethodReturnTypeIncompatible() throws Exception {
         try {
@@ -81,12 +90,14 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         } catch (NoSuchMethodException expected) {}
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingSucceedsWhenAllMethodsPresentWithExactReturnTypes() throws Exception {
         assertNotNull(DuckTypedPSKKeyManager.getInstance(
                 new KeyManagerOfferingAllPSKKeyManagerMethodsWithExactReturnTypes()));
     }
 
+    @Test
     @SuppressWarnings("deprecation")
     public void testDuckTypingSucceedsWhenAllMethodsPresentWithDifferentButCompatibleReturnTypes()
             throws Exception {
@@ -94,6 +105,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
                 new KeyManagerOfferingAllPSKKeyManagerMethodsWithCompatibleReturnTypes()));
     }
 
+    @Test
     public void testMethodInvocationDelegation() throws Exception {
         // IMPLEMENTATION NOTE: We create a DuckTypedPSKKeyManager wrapping a Reflection Proxy,
         // invoke each method of the PSKKeyManager interface on the DuckTypedPSKKeyManager instance,
@@ -168,6 +180,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[2]);
     }
 
+    @Test
     public void testMethodInvocationDelegationWithDifferentButCompatibleReturnType()
             throws Exception {
         // Check that nothing blows up when we invoke getKey which is declared to return
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/FileClientSessionCacheTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/FileClientSessionCacheTest.java
index 38d2b99f..7c779a9c 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/FileClientSessionCacheTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/FileClientSessionCacheTest.java
@@ -17,16 +17,24 @@
 
 package com.android.org.conscrypt;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.fail;
+
+import com.android.org.conscrypt.javax.net.ssl.FakeSSLSession;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.File;
 import java.io.IOException;
-import junit.framework.TestCase;
-import com.android.org.conscrypt.javax.net.ssl.FakeSSLSession;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class FileClientSessionCacheTest extends TestCase {
-
+@RunWith(JUnit4.class)
+public class FileClientSessionCacheTest {
+    @Test
     public void testMaxSize() throws IOException, InterruptedException {
         String tmpDir = System.getProperty("java.io.tmpdir");
         if (tmpDir == null) {
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
index fc7c18fc..7ec52626 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
@@ -27,15 +27,18 @@ import static com.android.org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 import static com.android.org.conscrypt.NativeConstants.TLS1_1_VERSION;
 import static com.android.org.conscrypt.NativeConstants.TLS1_2_VERSION;
 import static com.android.org.conscrypt.NativeConstants.TLS1_VERSION;
+import static com.android.org.conscrypt.TestUtils.decodeHex;
 import static com.android.org.conscrypt.TestUtils.isWindows;
 import static com.android.org.conscrypt.TestUtils.openTestFile;
 import static com.android.org.conscrypt.TestUtils.readTestFile;
 
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.junit.Assume.assumeFalse;
@@ -2725,6 +2728,79 @@ public class NativeCryptoTest {
         }
     }
 
+    @Test
+    public void test_ED25519_keypair_works() throws Exception {
+        byte[] publicKeyBytes = new byte[32];
+        byte[] privateKeyBytes = new byte[64];
+        NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes);
+
+        byte[] publicKeyBytes2 = new byte[32];
+        byte[] privateKeyBytes2 = new byte[64];
+        NativeCrypto.ED25519_keypair(publicKeyBytes2, privateKeyBytes2);
+
+        // keys must be random
+        assertNotEquals(publicKeyBytes, publicKeyBytes2);
+        assertNotEquals(privateKeyBytes, privateKeyBytes2);
+    }
+
+    @Test
+    public void test_ED25519_keypair_32BytePrivateKey_throws() throws Exception {
+        byte[] publicKeyBytes = new byte[32];
+        byte[] privateKeyBytes = new byte[32];
+        assertThrows(IllegalArgumentException.class,
+                () -> NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes));
+    }
+
+    @Test
+    public void test_EVP_DigestSign_Ed25519_works() throws Exception {
+        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
+        // PKCS#8 encoding for Ed25519 is defined in https://datatracker.ietf.org/doc/html/rfc8410
+        byte[] pkcs8EncodedPrivateKey = decodeHex(
+                // PKCS#8 header
+                "302e020100300506032b657004220420"
+                // raw private key
+                + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
+        byte[] data = decodeHex("");
+        byte[] expectedSig =
+                decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
+                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
+
+        NativeRef.EVP_PKEY privateKey =
+                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_private_key(pkcs8EncodedPrivateKey));
+
+        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
+
+        NativeCrypto.EVP_DigestSignInit(ctx, 0, privateKey);
+        byte[] sig = NativeCrypto.EVP_DigestSign(ctx, data, 0, data.length);
+
+        assertArrayEquals(expectedSig, sig);
+    }
+
+    @Test
+    public void test_EVP_DigestVerify_Ed25519_works() throws Exception {
+        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
+        // X.509 encoding for Ed25519 is defined in https://datatracker.ietf.org/doc/html/rfc8410
+        byte[] x509EncodedPublicKey = decodeHex(
+                // X.509 header
+                "302a300506032b6570032100"
+                // raw public key
+                + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
+        byte[] data = decodeHex("");
+        byte[] sig = decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
+                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
+
+        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
+
+        NativeRef.EVP_PKEY publicKey =
+                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_public_key(x509EncodedPublicKey));
+
+        NativeCrypto.EVP_DigestVerifyInit(ctx, 0, publicKey);
+        boolean result =
+                NativeCrypto.EVP_DigestVerify(ctx, sig, 0, sig.length, data, 0, data.length);
+
+        assertTrue(result);
+    }
+
     @Test(expected = NullPointerException.class)
     public void get_RSA_private_params_NullArgument() throws Exception {
         NativeCrypto.get_RSA_private_params(null);
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/AndroidHpkeSpi.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/AndroidHpkeSpi.java
new file mode 100644
index 00000000..d0339140
--- /dev/null
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/AndroidHpkeSpi.java
@@ -0,0 +1,117 @@
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
+package com.android.org.conscrypt;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.GeneralSecurityException;
+import java.security.InvalidKeyException;
+import java.security.PrivateKey;
+import java.security.PublicKey;
+
+/**
+ * Delegating wrapper for HpkeImpl that inherits the Android platform's SPI
+ * as well as Conscrypt's own.
+ * @hide This class is not part of the Android public SDK API
+ */
+@SuppressWarnings("NewApi")
+public class AndroidHpkeSpi
+        implements android.crypto.hpke.HpkeSpi, com.android.org.conscrypt.HpkeSpi {
+    private final com.android.org.conscrypt.HpkeSpi delegate;
+
+    public AndroidHpkeSpi(com.android.org.conscrypt.HpkeSpi delegate) {
+        this.delegate = delegate;
+    }
+
+    @Override
+    public void engineInitSender(PublicKey recipientKey, @Nullable byte[] info,
+            PrivateKey senderKey, @Nullable byte[] psk, @Nullable byte[] psk_id)
+            throws InvalidKeyException {
+        delegate.engineInitSender(recipientKey, info, senderKey, psk, psk_id);
+    }
+
+    @Override
+    public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info,
+            PrivateKey senderKey, byte[] psk, byte[] psk_id, byte[] sKe)
+            throws InvalidKeyException {
+        delegate.engineInitSenderForTesting(recipientKey, info, senderKey, psk, psk_id, sKe);
+    }
+
+    @Override
+    public void engineInitSenderWithSeed(PublicKey recipientKey, @Nullable byte[] info,
+            PrivateKey senderKey, @Nullable byte[] psk, @Nullable byte[] psk_id,
+            @NonNull byte[] sKe) throws InvalidKeyException {
+        delegate.engineInitSenderForTesting(recipientKey, info, senderKey, psk, psk_id, sKe);
+    }
+
+    @Override
+    public void engineInitRecipient(@NonNull byte[] encapsulated, PrivateKey recipientKey,
+            @Nullable byte[] info, PublicKey senderKey, @Nullable byte[] psk,
+            @Nullable byte[] psk_id) throws InvalidKeyException {
+        delegate.engineInitRecipient(encapsulated, recipientKey, info, senderKey, psk, psk_id);
+    }
+
+    @Override
+    public @NonNull byte[] engineSeal(@NonNull byte[] plaintext, @Nullable byte[] aad) {
+        return delegate.engineSeal(plaintext, aad);
+    }
+
+    @Override
+    public @NonNull byte[] engineOpen(@NonNull byte[] ciphertext, @Nullable byte[] aad)
+            throws GeneralSecurityException {
+        return delegate.engineOpen(ciphertext, aad);
+    }
+
+    @Override
+    public @NonNull byte[] engineExport(int length, @Nullable byte[] context) {
+        return delegate.engineExport(length, context);
+    }
+
+    @Override
+    public @NonNull byte[] getEncapsulated() {
+        return delegate.getEncapsulated();
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class X25519_AES_128 extends AndroidHpkeSpi {
+        public X25519_AES_128() {
+            super(new HpkeImpl.X25519_AES_128());
+        }
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class X25519_AES_256 extends AndroidHpkeSpi {
+        public X25519_AES_256() {
+            super(new HpkeImpl.X25519_AES_256());
+        }
+    }
+
+    /**
+     * @hide This class is not part of the Android public SDK API
+     */
+    public static class X25519_CHACHA20 extends AndroidHpkeSpi {
+        public X25519_CHACHA20() {
+            super(new HpkeImpl.X25519_CHACHA20());
+        }
+    }
+}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java
index cadbf445..fd5b1a6b 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/Hex.java
@@ -23,7 +23,6 @@ package com.android.org.conscrypt;
  */
 @Internal
 // public for testing by TrustedCertificateStoreTest
-// TODO(nathanmittler): Move to InternalUtil?
 public final class Hex {
     private Hex() {}
 
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/PakeKeyManagerFactory.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/PakeKeyManagerFactory.java
new file mode 100644
index 00000000..3b0abd92
--- /dev/null
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/PakeKeyManagerFactory.java
@@ -0,0 +1,165 @@
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
+package com.android.org.conscrypt;
+
+import static android.net.ssl.PakeServerKeyManagerParameters.Link;
+
+import static java.util.Objects.requireNonNull;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeOption;
+import android.net.ssl.PakeServerKeyManagerParameters;
+
+import com.android.org.conscrypt.io.IoUtils;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileNotFoundException;
+import java.io.IOException;
+import java.security.InvalidAlgorithmParameterException;
+import java.security.KeyStore;
+import java.security.KeyStoreException;
+import java.security.NoSuchAlgorithmException;
+import java.security.UnrecoverableKeyException;
+import java.security.cert.CertificateException;
+import java.util.List;
+import java.util.Set;
+
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactorySpi;
+import javax.net.ssl.ManagerFactoryParameters;
+
+/**
+ * PakeKeyManagerFactory implementation.
+ * @see KeyManagerFactorySpi
+ * @hide This class is not part of the Android public SDK API
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class PakeKeyManagerFactory extends KeyManagerFactorySpi {
+    PakeClientKeyManagerParameters clientParams;
+    PakeServerKeyManagerParameters serverParams;
+    private static final int MAX_HANDSHAKE_LIMIT = 24;
+
+    /**
+     * @see KeyManagerFactorySpi#engineInit(KeyStore ks, char[] password)
+     */
+    @Override
+    public void engineInit(KeyStore ks, char[] password)
+            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
+        throw new KeyStoreException("KeyStore not supported");
+    }
+
+    /**
+     * @see KeyManagerFactorySpi#engineInit(ManagerFactoryParameters spec)
+     */
+    @Override
+    public void engineInit(ManagerFactoryParameters spec)
+            throws InvalidAlgorithmParameterException {
+        if (clientParams != null || serverParams != null) {
+            throw new IllegalStateException("PakeKeyManagerFactory is already initialized");
+        }
+        if (spec == null) {
+            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters cannot be null");
+        }
+        if (spec instanceof PakeClientKeyManagerParameters) {
+            clientParams = (PakeClientKeyManagerParameters) spec;
+        } else if (spec instanceof PakeServerKeyManagerParameters) {
+            serverParams = (PakeServerKeyManagerParameters) spec;
+        } else {
+            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
+        }
+    }
+
+    /**
+     * @see KeyManagerFactorySpi#engineGetKeyManagers()
+     */
+    @Override
+    public KeyManager[] engineGetKeyManagers() {
+        if (clientParams == null && serverParams == null) {
+            throw new IllegalStateException("PakeKeyManagerFactory is not initialized");
+        }
+        if (clientParams != null) {
+            return initClient();
+        } else {
+            return initServer();
+        }
+    }
+
+    private static int getHandshakeLimit(PakeOption option, String limitName) {
+        byte[] limit = option.getMessageComponent(limitName);
+        if (limit == null) {
+            return 1;
+        }
+        int handshakeLimit = limit[0];
+        // This should never happen, but just in case, we set the limit to 1.
+        if (handshakeLimit < 1 || handshakeLimit > MAX_HANDSHAKE_LIMIT) {
+            return 1;
+        }
+        return handshakeLimit;
+    }
+
+    private KeyManager[] initClient() {
+        List<PakeOption> options = clientParams.getOptions();
+        for (PakeOption option : options) {
+            if (!option.getAlgorithm().equals("SPAKE2PLUS_PRERELEASE")) {
+                continue;
+            }
+            byte[] idProver = clientParams.getClientId();
+            byte[] idVerifier = clientParams.getServerId();
+            byte[] context = option.getMessageComponent("context");
+            byte[] password = option.getMessageComponent("password");
+            int clientHandshakeLimit = getHandshakeLimit(option, "client-handshake-limit");
+            if (password != null) {
+                return new KeyManager[] {new Spake2PlusKeyManager(
+                        context, password, idProver, idVerifier, true, clientHandshakeLimit)};
+            }
+            break;
+        }
+        return new KeyManager[] {};
+    }
+
+    private KeyManager[] initServer() {
+        Set<Link> links = serverParams.getLinks();
+        for (Link link : links) {
+            List<PakeOption> options = serverParams.getOptions(link);
+            for (PakeOption option : options) {
+                if (!option.getAlgorithm().equals("SPAKE2PLUS_PRERELEASE")) {
+                    continue;
+                }
+                byte[] idProver = link.getClientId();
+                byte[] idVerifier = link.getServerId();
+                byte[] context = option.getMessageComponent("context");
+                byte[] password = option.getMessageComponent("password");
+                int serverHandshakeLimit = getHandshakeLimit(option, "server-handshake-limit");
+                if (password != null) {
+                    return new KeyManager[] {
+                        new Spake2PlusKeyManager(
+                                context,
+                                password,
+                                idProver,
+                                idVerifier,
+                                false,
+                                serverHandshakeLimit)
+                    };
+                }
+                break;
+            }
+        }
+        return new KeyManager[] {};
+    }
+}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/PakeTrustManagerFactory.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/PakeTrustManagerFactory.java
new file mode 100644
index 00000000..9b0c8532
--- /dev/null
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/PakeTrustManagerFactory.java
@@ -0,0 +1,71 @@
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
+package com.android.org.conscrypt;
+
+import static java.util.Objects.requireNonNull;
+
+import java.security.InvalidAlgorithmParameterException;
+import java.security.KeyManagementException;
+import java.security.KeyStore;
+import java.security.KeyStoreException;
+import java.security.NoSuchAlgorithmException;
+import java.security.Provider;
+import java.security.Security;
+import java.security.cert.CertificateException;
+
+import javax.net.ssl.ManagerFactoryParameters;
+import javax.net.ssl.TrustManager;
+import javax.net.ssl.TrustManagerFactory;
+import javax.net.ssl.TrustManagerFactorySpi;
+
+/**
+ * A factory for creating {@link SpakeTrustManager} instances that use SPAKE2.
+ * @hide This class is not part of the Android public SDK API
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public class PakeTrustManagerFactory extends TrustManagerFactorySpi {
+    /**
+     * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(KeyStore)
+     */
+    @Override
+    public void engineInit(KeyStore ks) throws KeyStoreException {
+        if (ks != null) {
+            throw new KeyStoreException("KeyStore not supported");
+        }
+    }
+
+    /**
+     * @see javax.net.ssl#engineInit(ManagerFactoryParameters)
+     */
+    @Override
+    public void engineInit(ManagerFactoryParameters spec)
+            throws InvalidAlgorithmParameterException {
+        if (spec != null) {
+            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
+        }
+    }
+
+    /**
+     * @see javax.net.ssl#engineGetTrustManagers()
+     */
+    @Override
+    public TrustManager[] engineGetTrustManagers() {
+        return new TrustManager[] {new Spake2PlusTrustManager()};
+    }
+}
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
index aa128721..1b7d605f 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
@@ -25,11 +25,13 @@ import android.system.Os;
 import android.system.StructTimeval;
 
 import com.android.org.conscrypt.NativeCrypto;
+import com.android.org.conscrypt.ct.CertificateTransparency;
 import com.android.org.conscrypt.ct.LogStore;
 import com.android.org.conscrypt.ct.LogStoreImpl;
 import com.android.org.conscrypt.ct.Policy;
 import com.android.org.conscrypt.ct.PolicyImpl;
 import com.android.org.conscrypt.flags.Flags;
+import com.android.org.conscrypt.metrics.CertificateTransparencyVerificationReason;
 import com.android.org.conscrypt.metrics.OptionalMethod;
 import com.android.org.conscrypt.metrics.Source;
 import com.android.org.conscrypt.metrics.StatsLog;
@@ -99,10 +101,10 @@ final public class Platform {
      * Runs all the setup for the platform that only needs to run once.
      */
     public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
-        NoPreloadHolder.MAPPER.ping();
         DEPRECATED_TLS_V1 = deprecatedTlsV1;
         ENABLED_TLS_V1 = enabledTlsV1;
         FILTERED_TLS_V1 = !enabledTlsV1;
+        NoPreloadHolder.MAPPER.ping();
         NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
     }
 
@@ -486,7 +488,7 @@ final public class Platform {
         return true;
     }
 
-    static boolean isCTVerificationRequired(String hostname) {
+    public static boolean isCTVerificationRequired(String hostname) {
         if (Flags.certificateTransparencyPlatform()) {
             return NetworkSecurityPolicy.getInstance()
                     .isCertificateTransparencyVerificationRequired(hostname);
@@ -494,6 +496,17 @@ final public class Platform {
         return false;
     }
 
+    public static CertificateTransparencyVerificationReason reasonCTVerificationRequired(
+            String hostname) {
+        if (NetworkSecurityPolicy.getInstance().isCertificateTransparencyVerificationRequired("")) {
+            return CertificateTransparencyVerificationReason.APP_OPT_IN;
+        } else if (NetworkSecurityPolicy.getInstance()
+                           .isCertificateTransparencyVerificationRequired(hostname)) {
+            return CertificateTransparencyVerificationReason.DOMAIN_OPT_IN;
+        }
+        return CertificateTransparencyVerificationReason.UNKNOWN;
+    }
+
     static boolean supportsConscryptCertStore() {
         return true;
     }
@@ -516,12 +529,13 @@ final public class Platform {
         return CertBlocklistImpl.getDefault();
     }
 
-    static LogStore newDefaultLogStore() {
-        return new LogStoreImpl();
-    }
-
-    static Policy newDefaultPolicy() {
-        return new PolicyImpl();
+    static CertificateTransparency newDefaultCertificateTransparency() {
+        com.android.org.conscrypt.ct.Policy policy = new com.android.org.conscrypt.ct.PolicyImpl();
+        com.android.org.conscrypt.ct.LogStore logStore =
+                new com.android.org.conscrypt.ct.LogStoreImpl(policy);
+        com.android.org.conscrypt.ct.Verifier verifier =
+                new com.android.org.conscrypt.ct.Verifier(logStore);
+        return new CertificateTransparency(logStore, policy, verifier, getStatsLog());
     }
 
     static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
@@ -584,6 +598,10 @@ final public class Platform {
         return ENABLED_TLS_V1;
     }
 
+    public static boolean isPakeSupported() {
+        return true;
+    }
+
     static Object getTargetSdkVersion() {
         try {
             Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
@@ -599,4 +617,21 @@ final public class Platform {
             throw new RuntimeException(e);
         }
     }
+
+    public static boolean isSdkGreater(int sdk) {
+        try {
+            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
+            Method getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime");
+            Method getSdkVersionMethod =
+                        vmRuntimeClass.getDeclaredMethod("getSdkVersion");
+            Object vmRuntime = getRuntimeMethod.invoke(null);
+            Object sdkVersion = getSdkVersionMethod.invoke(vmRuntime);
+            return (sdkVersion != null) && ((int) sdkVersion > sdk);
+        } catch (IllegalAccessException |
+          NullPointerException | InvocationTargetException | NoSuchMethodException e) {
+            return false;
+        } catch (Exception e) {
+            throw new RuntimeException(e);
+        }
+    }
 }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
index a9f75df8..4bb1f8e7 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
@@ -45,6 +45,7 @@ import java.util.Collections;
 import java.util.Date;
 import java.util.HashMap;
 import java.util.Map;
+import java.util.function.Supplier;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 
@@ -54,17 +55,17 @@ import java.util.logging.Logger;
 @Internal
 public class LogStoreImpl implements LogStore {
     private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
-    private static final String BASE_PATH = "misc/keychain/ct";
-    private static final int COMPAT_VERSION = 1;
-    private static final String CURRENT = "current";
-    private static final String LOG_LIST_FILENAME = "log_list.json";
-    private static final Path DEFAULT_LOG_LIST;
+    private static final int COMPAT_VERSION = 2;
+    private static final Path logListPrefix;
+    private static final Path logListSuffix;
+    private static final long LOG_LIST_CHECK_INTERVAL_IN_NS =
+            10L * 60 * 1_000 * 1_000_000; // 10 minutes
 
     static {
         String androidData = System.getenv("ANDROID_DATA");
-        String compatVersion = String.format("v%d", COMPAT_VERSION);
-        DEFAULT_LOG_LIST =
-                Paths.get(androidData, BASE_PATH, compatVersion, CURRENT, LOG_LIST_FILENAME);
+        // /data/misc/keychain/ct/v1/current/log_list.json
+        logListPrefix = Paths.get(androidData, "misc", "keychain", "ct");
+        logListSuffix = Paths.get("current", "log_list.json");
     }
 
     private final Path logList;
@@ -75,19 +76,41 @@ public class LogStoreImpl implements LogStore {
     private int minorVersion;
     private long timestamp;
     private Map<ByteArray, LogInfo> logs;
+    private long logListLastModified;
+    private Supplier<Long> clock;
+    private long logListLastChecked;
 
-    public LogStoreImpl() {
-        this(DEFAULT_LOG_LIST);
+    /* We do not have access to InstantSource. Implement a similar pattern using Supplier. */
+    static class SystemTimeSupplier implements Supplier<Long> {
+        @Override
+        public Long get() {
+            return System.nanoTime();
+        }
+    }
+
+    private static Path getPathForCompatVersion(int compatVersion) {
+        String version = String.format("v%d", compatVersion);
+        return logListPrefix.resolve(version).resolve(logListSuffix);
+    }
+
+    public LogStoreImpl(Policy policy) {
+        this(policy, getPathForCompatVersion(COMPAT_VERSION));
+    }
+
+    public LogStoreImpl(Policy policy, Path logList) {
+        this(policy, logList, Platform.getStatsLog());
     }
 
-    public LogStoreImpl(Path logList) {
-        this(logList, Platform.getStatsLog());
+    public LogStoreImpl(Policy policy, Path logList, StatsLog metrics) {
+        this(policy, logList, metrics, new SystemTimeSupplier());
     }
 
-    public LogStoreImpl(Path logList, StatsLog metrics) {
+    public LogStoreImpl(Policy policy, Path logList, StatsLog metrics, Supplier<Long> clock) {
         this.state = State.UNINITIALIZED;
+        this.policy = policy;
         this.logList = logList;
         this.metrics = metrics;
+        this.clock = clock;
     }
 
     @Override
@@ -113,8 +136,7 @@ public class LogStoreImpl implements LogStore {
 
     @Override
     public int getCompatVersion() {
-        // Currently, there is only one compatibility version supported. If we
-        // are loaded or initialized, it means the expected compatibility
+        // If we are loaded or initialized, it means the expected compatibility
         // version was found.
         if (state == State.LOADED || state == State.COMPLIANT || state == State.NON_COMPLIANT) {
             return COMPAT_VERSION;
@@ -124,14 +146,12 @@ public class LogStoreImpl implements LogStore {
 
     @Override
     public int getMinCompatVersionAvailable() {
+        if (Files.exists(getPathForCompatVersion(1))) {
+            return 1;
+        }
         return getCompatVersion();
     }
 
-    @Override
-    public void setPolicy(Policy policy) {
-        this.policy = policy;
-    }
-
     @Override
     public LogInfo getKnownLog(byte[] logId) {
         if (logId == null) {
@@ -151,26 +171,54 @@ public class LogStoreImpl implements LogStore {
     /* Ensures the log list is loaded.
      * Returns true if the log list is usable.
      */
-    private boolean ensureLogListIsLoaded() {
-        synchronized (this) {
-            State previousState = state;
-            if (state == State.UNINITIALIZED) {
-                state = loadLogList();
-            }
-            if (state == State.LOADED && policy != null) {
-                state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
+    private synchronized boolean ensureLogListIsLoaded() {
+        resetLogListIfRequired();
+        State previousState = state;
+        if (state == State.UNINITIALIZED) {
+            state = loadLogList();
+        }
+        if (state == State.LOADED && policy != null) {
+            state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
+        }
+        if (state != previousState) {
+            metrics.updateCTLogListStatusChanged(this);
+        }
+        return state == State.COMPLIANT;
+    }
+
+    private synchronized void resetLogListIfRequired() {
+        long now = clock.get();
+        if (this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_NS > now) {
+            return;
+        }
+        this.logListLastChecked = now;
+        try {
+            long lastModified = Files.getLastModifiedTime(logList).toMillis();
+            if (this.logListLastModified == lastModified) {
+                // The log list has the same last modified timestamp. Keep our
+                // current cached value.
+                return;
             }
-            if (state != previousState && metrics != null) {
-                metrics.updateCTLogListStatusChanged(this);
+        } catch (IOException e) {
+            if (this.logListLastModified == 0) {
+                // The log list is not accessible now and it has never been
+                // previously, there is nothing to do.
+                return;
             }
-            return state == State.COMPLIANT;
         }
+        this.state = State.UNINITIALIZED;
+        this.logs = null;
+        this.timestamp = 0;
+        this.majorVersion = 0;
+        this.minorVersion = 0;
     }
 
     private State loadLogList() {
         byte[] content;
+        long lastModified;
         try {
             content = Files.readAllBytes(logList);
+            lastModified = Files.getLastModifiedTime(logList).toMillis();
         } catch (IOException e) {
             return State.NOT_FOUND;
         }
@@ -193,33 +241,13 @@ public class LogStoreImpl implements LogStore {
             for (int i = 0; i < operators.length(); i++) {
                 JSONObject operator = operators.getJSONObject(i);
                 String operatorName = operator.getString("name");
+
                 JSONArray logs = operator.getJSONArray("logs");
-                for (int j = 0; j < logs.length(); j++) {
-                    JSONObject log = logs.getJSONObject(j);
-
-                    LogInfo.Builder builder =
-                            new LogInfo.Builder()
-                                    .setDescription(log.getString("description"))
-                                    .setPublicKey(parsePubKey(log.getString("key")))
-                                    .setUrl(log.getString("url"))
-                                    .setOperator(operatorName);
-
-                    JSONObject stateObject = log.optJSONObject("state");
-                    if (stateObject != null) {
-                        String state = stateObject.keys().next();
-                        long stateTimestamp = stateObject.getJSONObject(state).getLong("timestamp");
-                        builder.setState(parseState(state), stateTimestamp);
-                    }
-
-                    LogInfo logInfo = builder.build();
-                    byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
-
-                    // The logId computed using the public key should match the log_id field.
-                    if (!Arrays.equals(logInfo.getID(), logId)) {
-                        throw new IllegalArgumentException("logId does not match publicKey");
-                    }
-
-                    logsMap.put(new ByteArray(logId), logInfo);
+                addLogsToMap(logs, operatorName, LogInfo.TYPE_RFC6962, logsMap);
+
+                JSONArray tiledLogs = operator.optJSONArray("tiled_logs");
+                if (tiledLogs != null) {
+                    addLogsToMap(tiledLogs, operatorName, LogInfo.TYPE_STATIC_CT_API, logsMap);
                 }
             }
         } catch (JSONException | IllegalArgumentException e) {
@@ -227,9 +255,37 @@ public class LogStoreImpl implements LogStore {
             return State.MALFORMED;
         }
         this.logs = Collections.unmodifiableMap(logsMap);
+        this.logListLastModified = lastModified;
         return State.LOADED;
     }
 
+    private static void addLogsToMap(JSONArray logs, String operatorName, int logType,
+            Map<ByteArray, LogInfo> logsMap) throws JSONException {
+        for (int j = 0; j < logs.length(); j++) {
+            JSONObject log = logs.getJSONObject(j);
+            LogInfo.Builder builder = new LogInfo.Builder()
+                                              .setDescription(log.getString("description"))
+                                              .setPublicKey(parsePubKey(log.getString("key")))
+                                              .setType(logType)
+                                              .setOperator(operatorName);
+            JSONObject stateObject = log.optJSONObject("state");
+            if (stateObject != null) {
+                String state = stateObject.keys().next();
+                long stateTimestamp = stateObject.getJSONObject(state).getLong("timestamp");
+                builder.setState(parseState(state), stateTimestamp);
+            }
+            LogInfo logInfo = builder.build();
+
+            // The logId computed using the public key should match the log_id field.
+            byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
+            if (!Arrays.equals(logInfo.getID(), logId)) {
+                throw new IllegalArgumentException("logId does not match publicKey");
+            }
+
+            logsMap.put(new ByteArray(logId), logInfo);
+        }
+    }
+
     private static int parseMajorVersion(String version) {
         int pos = version.indexOf(".");
         if (pos == -1) {
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
index 280579f0..4107e550 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
@@ -182,7 +182,7 @@ public class PolicyImpl implements Policy {
             return PolicyCompliance.NOT_ENOUGH_SCTS;
         }
 
-        /* 3. Among the SCTs satisfying requirements 1 and 2, at least two SCTs
+        /* 3. Among the SCTs satisfying requirements 2, at least two SCTs
          *    must be issued from distinct CT Log Operators as recognized by
          *    Chrome.
          */
@@ -194,6 +194,20 @@ public class PolicyImpl implements Policy {
             return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
         }
 
+        /* 4. Among the SCTs satisfying requirement 2, at least one SCT must be
+         * issued from a log recognized by Chrome as being RFC6962-compliant.
+         */
+        boolean foundRfc6962Log = false;
+        for (LogInfo logInfo : validLogs) {
+            if (logInfo.getType() == LogInfo.TYPE_RFC6962) {
+                foundRfc6962Log = true;
+                break;
+            }
+        }
+        if (!foundRfc6962Log) {
+            return PolicyCompliance.NO_RFC6962_LOG;
+        }
+
         return PolicyCompliance.COMPLY;
     }
 
@@ -227,6 +241,20 @@ public class PolicyImpl implements Policy {
             return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
         }
 
+        /* 3. Among the SCTs satisfying requirement 1, at least one SCT must be
+         * issued from a log recognized by Chrome as being RFC6962-compliant.
+         */
+        boolean foundRfc6962Log = false;
+        for (LogInfo logInfo : validLogs) {
+            if (logInfo.getType() == LogInfo.TYPE_RFC6962) {
+                foundRfc6962Log = true;
+                break;
+            }
+        }
+        if (!foundRfc6962Log) {
+            return PolicyCompliance.NO_RFC6962_LOG;
+        }
+
         return PolicyCompliance.COMPLY;
     }
 }
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/AndroidHpkeSpiTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/AndroidHpkeSpiTest.java
new file mode 100644
index 00000000..cb2e1383
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/AndroidHpkeSpiTest.java
@@ -0,0 +1,61 @@
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
+package com.android.org.conscrypt;
+
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.Provider;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class AndroidHpkeSpiTest {
+    private static final String[] HPKE_NAMES = new String[]{
+            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
+            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
+            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305"
+    };
+
+    // This only needs to test the wrapper functionality as the implementation and client
+    // APIs are tested elsewhere.  What we're looking for is that HPKE SPI instances returned
+    // by the provider are *always* instances of Conscrypt's HpkeSpi and *always* usable by
+    // a Conscrypt duck typed SPI.  And if the Android platform SPI class is available then
+    // they should also be usable as instances of that.
+    @Test
+    public void functionalTest() throws Exception {
+        Class<?> conscryptSpiClass = HpkeSpi.class;
+        Class<?> platformSpiClass = TestUtils.findClass("android.crypto.hpke.HpkeSpi");
+        Provider provider = TestUtils.getConscryptProvider();
+        for (String algorithm : HPKE_NAMES) {
+            Object spi = provider.getService("ConscryptHpke", algorithm)
+                    .newInstance(null);
+            assertNotNull(spi);
+            if (platformSpiClass != null) {
+                assertTrue(platformSpiClass.isAssignableFrom(spi.getClass()));
+            }
+            assertTrue(conscryptSpiClass.isAssignableFrom(spi.getClass()));
+            assertNotNull(DuckTypedHpkeSpi.newInstance(spi));
+        }
+    }
+}
\ No newline at end of file
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java
index d0a37c89..033fa0ef 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java
@@ -17,6 +17,13 @@
 
 package com.android.org.conscrypt;
 
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.InputStream;
 import java.security.KeyStore;
 import java.security.cert.Certificate;
@@ -24,14 +31,14 @@ import java.security.cert.CertificateException;
 import java.security.cert.CertificateFactory;
 import java.security.cert.X509Certificate;
 import java.util.Collection;
+
 import javax.net.ssl.X509TrustManager;
-import junit.framework.TestCase;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class CertBlocklistTest extends TestCase {
-
+@RunWith(JUnit4.class)
+public class CertBlocklistTest {
     private static final String BLOCKLIST_CA = "test_blocklist_ca.pem";
     private static final String BLOCKLIST_CA2 = "test_blocklist_ca2.pem";
     private static final String BLOCKLISTED_CHAIN = "blocklist_test_chain.pem";
@@ -41,6 +48,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Ensure that the test blocklisted CA is actually blocklisted by default.
      */
+    @Test
     public void testBlocklistedPublicKey() throws Exception {
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
         CertBlocklist blocklist = CertBlocklistImpl.getDefault();
@@ -50,6 +58,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Ensure that the test blocklisted CA 2 is actually blocklisted by default.
      */
+    @Test
     public void testBlocklistedPublicKeySHA256() throws Exception {
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA2);
         CertBlocklist blocklist = CertBlocklistImpl.getDefault();
@@ -59,6 +68,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Check that the blocklisted CA is rejected even if it used as a root of trust
      */
+    @Test
     public void testBlocklistedCaUntrusted() throws Exception {
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
         assertUntrusted(new X509Certificate[] {blocklistedCa}, getTrustManager(blocklistedCa));
@@ -67,6 +77,7 @@ public class CertBlocklistTest extends TestCase {
     /**
      * Check that a chain that is rooted in a blocklisted trusted CA is rejected.
      */
+    @Test
     public void testBlocklistedRootOfTrust() throws Exception {
         // Chain is leaf -> blocklisted
         X509Certificate[] chain = loadCertificates(BLOCKLISTED_CHAIN);
@@ -83,6 +94,7 @@ public class CertBlocklistTest extends TestCase {
      *               \
      *                -------> trusted_ca
      */
+    @Test
     public void testBlocklistedIntermediateFallback() throws Exception {
         X509Certificate[] chain = loadCertificates(BLOCKLISTED_VALID_CHAIN);
         X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/PakeKeyManagerFactoryTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/PakeKeyManagerFactoryTest.java
new file mode 100644
index 00000000..496c3993
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/PakeKeyManagerFactoryTest.java
@@ -0,0 +1,149 @@
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
+package com.android.org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeServerKeyManagerParameters;
+import android.net.ssl.PakeOption;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.KeyStoreException;
+import java.util.Arrays;
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactory;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class PakeKeyManagerFactoryTest {
+    private static final byte[] PASSWORD = new byte[] {1, 2, 3};
+    private static final byte[] CLIENT_ID = new byte[] {2, 3, 4};
+    private static final byte[] SERVER_ID = new byte[] {4, 5, 6};
+
+    @Test
+    public void pakeKeyManagerFactoryTest() throws Exception {
+        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
+        assertThrows(KeyStoreException.class, () -> kmf.init(null, null));
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", PASSWORD)
+                        .build();
+
+        PakeClientKeyManagerParameters params =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        kmf.init(params);
+
+        KeyManager[] keyManagers = kmf.getKeyManagers();
+        assertEquals(1, keyManagers.length);
+
+        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
+        assertArrayEquals(PASSWORD, keyManager.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManager.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManager.getIdVerifier());
+    }
+
+    @Test
+    public void pakeKeyManagerFactoryTestHanshakeLimitClient() throws Exception {
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", PASSWORD)
+                        .addMessageComponent("client-handshake-limit", new byte[] {16})
+                        .build();
+
+        // Client
+        PakeClientKeyManagerParameters paramsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(paramsClient);
+
+        Spake2PlusKeyManager keyManagerClient = (Spake2PlusKeyManager) kmfClient.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerClient.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerClient.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerClient.getIdVerifier());
+        assertEquals(16, keyManagerClient.getHandshakeLimit());
+
+        // Server
+        PakeServerKeyManagerParameters paramsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(paramsServer);
+
+        Spake2PlusKeyManager keyManagerServer = (Spake2PlusKeyManager) kmfServer.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerServer.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerServer.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerServer.getIdVerifier());
+        assertEquals(1, keyManagerServer.getHandshakeLimit());
+    }
+
+    @Test
+    public void pakeKeyManagerFactoryTestHanshakeLimitServer() throws Exception {
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", PASSWORD)
+                        .addMessageComponent("server-handshake-limit", new byte[] {16})
+                        .build();
+
+        // Client
+        PakeClientKeyManagerParameters paramsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(paramsClient);
+
+        Spake2PlusKeyManager keyManagerClient = (Spake2PlusKeyManager) kmfClient.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerClient.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerClient.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerClient.getIdVerifier());
+        assertEquals(1, keyManagerClient.getHandshakeLimit());
+
+        // Server
+        PakeServerKeyManagerParameters paramsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(paramsServer);
+
+        Spake2PlusKeyManager keyManagerServer = (Spake2PlusKeyManager) kmfServer.getKeyManagers()[0];
+        assertArrayEquals(PASSWORD, keyManagerServer.getPassword());
+        assertArrayEquals(CLIENT_ID, keyManagerServer.getIdProver());
+        assertArrayEquals(SERVER_ID, keyManagerServer.getIdVerifier());
+        assertEquals(16, keyManagerServer.getHandshakeLimit());
+    }
+}
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/PakeManagerFactoriesTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/PakeManagerFactoriesTest.java
new file mode 100644
index 00000000..f47cebae
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/PakeManagerFactoriesTest.java
@@ -0,0 +1,104 @@
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
+package com.android.org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeOption;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.security.InvalidAlgorithmParameterException;
+import java.security.KeyStoreException;
+
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.ManagerFactoryParameters;
+import javax.net.ssl.TrustManager;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ * @hide This class is not part of the Android public SDK API
+ */
+public class PakeManagerFactoriesTest {
+    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
+    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
+
+    @Test
+    public void testEngineInitParameters() throws InvalidAlgorithmParameterException {
+        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();
+
+        byte[] password = new byte[] {1, 2, 3};
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", password)
+                                    .build();
+
+        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));
+
+        PakeClientKeyManagerParameters params =
+                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
+        // Initialize with valid parameters
+        keyManagerFactory.engineInit(params);
+        // Try to initialize again
+        assertThrows(IllegalStateException.class, () -> keyManagerFactory.engineInit(params));
+
+        PakeTrustManagerFactory trustManagerFactory = new PakeTrustManagerFactory();
+        // The trust manager factory does not accept parameters
+        assertThrows(InvalidAlgorithmParameterException.class,
+                () -> trustManagerFactory.engineInit(params));
+        trustManagerFactory.engineInit((ManagerFactoryParameters) null);
+    }
+
+    @Test
+    public void testEngineGetKeyManagers() throws InvalidAlgorithmParameterException {
+        PakeKeyManagerFactory factory = new PakeKeyManagerFactory();
+        assertThrows(IllegalStateException.class, () -> factory.engineGetKeyManagers());
+
+        byte[] password = new byte[] {1, 2, 3};
+        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                                    .addMessageComponent("password", password)
+                                    .build();
+
+        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
+                                                        .setClientId(CLIENT_ID.clone())
+                                                        .setServerId(SERVER_ID.clone())
+                                                        .addOption(option)
+                                                        .build();
+
+        factory.engineInit(params);
+        KeyManager[] keyManagers = factory.engineGetKeyManagers();
+        assertEquals(1, keyManagers.length);
+
+        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
+        assertArrayEquals(password, keyManager.getPassword());
+        assertArrayEquals(new byte[] {4, 5, 6}, keyManager.getIdProver());
+        assertArrayEquals(new byte[] {7, 8, 9}, keyManager.getIdVerifier());
+    }
+
+    @Test
+    public void testEngineGetTrustManagers() {
+        PakeTrustManagerFactory factory = new PakeTrustManagerFactory();
+        TrustManager[] trustManagers = factory.engineGetTrustManagers();
+        assertEquals(1, trustManagers.length);
+        assertEquals(Spake2PlusTrustManager.class, trustManagers[0].getClass());
+    }
+}
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java
new file mode 100644
index 00000000..b17f5eee
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/SpakeTest.java
@@ -0,0 +1,555 @@
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
+package com.android.org.conscrypt;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
+import android.net.ssl.PakeClientKeyManagerParameters;
+import android.net.ssl.PakeOption;
+import android.net.ssl.PakeServerKeyManagerParameters;
+
+import com.android.org.conscrypt.Spake2PlusKeyManager;
+
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.net.InetAddress;
+import java.net.InetSocketAddress;
+import java.net.Socket;
+import java.security.KeyManagementException;
+import java.util.Arrays;
+import java.util.concurrent.Callable;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+import java.util.concurrent.Future;
+
+import javax.net.SocketFactory;
+import javax.net.ssl.KeyManager;
+import javax.net.ssl.KeyManagerFactory;
+import javax.net.ssl.ManagerFactoryParameters;
+import javax.net.ssl.SSLContext;
+import javax.net.ssl.SSLEngine;
+import javax.net.ssl.SSLHandshakeException;
+import javax.net.ssl.SSLServerSocket;
+import javax.net.ssl.SSLSocket;
+import javax.net.ssl.SSLSocketFactory;
+import javax.net.ssl.TrustManager;
+import javax.net.ssl.TrustManagerFactory;
+
+import tests.util.Pair;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class SpakeTest {
+    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
+    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
+    private final ThreadGroup threadGroup = new ThreadGroup("SpakeTest");
+    private final ExecutorService executor =
+            Executors.newCachedThreadPool(t -> new Thread(threadGroup, t));
+
+    private Pair<SSLContext, SSLContext> createContexts(
+            PakeClientKeyManagerParameters clientParams,
+            PakeServerKeyManagerParameters serverParams)
+            throws Exception {
+        InetAddress hostC = TestUtils.getLoopbackAddress();
+        InetAddress hostS = TestUtils.getLoopbackAddress();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(clientParams);
+        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
+        assertTrue(keyManagersClient.length == 1);
+        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spake2PlusKeyManagerClient =
+                (Spake2PlusKeyManager) keyManagersClient[0];
+        assertTrue(spake2PlusKeyManagerClient.isClient());
+        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
+        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);
+
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(serverParams);
+        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
+        assertTrue(keyManagersServer.length == 1);
+        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
+        assertFalse(spakeKeyManagerServer.isClient());
+
+        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
+        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);
+        return Pair.of(contextClient, contextServer);
+    }
+
+    private SSLContext createClientContext(
+            PakeClientKeyManagerParameters clientParams)
+            throws Exception {
+        InetAddress hostC = TestUtils.getLoopbackAddress();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+
+        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
+        kmfClient.init(clientParams);
+        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
+        assertTrue(keyManagersClient.length == 1);
+        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spake2PlusKeyManagerClient =
+                (Spake2PlusKeyManager) keyManagersClient[0];
+        assertTrue(spake2PlusKeyManagerClient.isClient());
+        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
+        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);
+        return contextClient;
+    }
+
+    private SSLContext createServerContext(
+            PakeServerKeyManagerParameters serverParams)
+            throws Exception {
+        InetAddress hostS = TestUtils.getLoopbackAddress();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
+        kmfServer.init(serverParams);
+        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
+        assertTrue(keyManagersServer.length == 1);
+        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
+        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
+        assertFalse(spakeKeyManagerServer.isClient());
+
+        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
+        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);
+        return contextServer;
+    }
+
+    private Pair<SSLSocket, SSLSocket> createSockets(Pair<SSLContext, SSLContext> contexts)
+            throws Exception {
+        InetAddress hostC = TestUtils.getLoopbackAddress();
+        InetAddress hostS = TestUtils.getLoopbackAddress();
+        SSLServerSocket serverSocket =
+                (SSLServerSocket)
+                        contexts.getSecond().getServerSocketFactory().createServerSocket();
+        serverSocket.bind(new InetSocketAddress(hostS, 0));
+        SSLSocket client =
+                (SSLSocket)
+                        contexts.getFirst()
+                                .getSocketFactory()
+                                .createSocket(hostC, serverSocket.getLocalPort());
+        SSLSocket server = (SSLSocket) serverSocket.accept();
+
+        assertTrue(client.getUseClientMode());
+        return Pair.of(client, server);
+    }
+
+    private void connectSockets(Pair<SSLSocket, SSLSocket> sockets)
+            throws Exception {
+        SSLSocket client = sockets.getFirst();
+        SSLSocket server = sockets.getSecond();
+        Future<Void> s =
+                runAsync(
+                        () -> {
+                            server.startHandshake();
+                            return null;
+                        });
+        client.startHandshake();
+        s.get();
+    }
+
+    private void sendData(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
+        SSLSocket client = sockets.getFirst();
+        SSLSocket server = sockets.getSecond();
+        byte[] readBytes = new byte[3];
+        server.getOutputStream().write(new byte[] {1, 2, 3});
+        client.getOutputStream().write(new byte[] {4, 5, 6});
+        server.getInputStream().read(readBytes, 0, 3);
+        assertArrayEquals(new byte[] {4, 5, 6}, readBytes);
+        client.getInputStream().read(readBytes, 0, 3);
+        assertArrayEquals(new byte[] {1, 2, 3}, readBytes);
+    }
+
+    private void closeSockets(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
+        sockets.getFirst().close();
+        sockets.getSecond().close();
+    }
+
+    @Test
+    public void testSpake2PlusPassword() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
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
+        connectSockets(sockets);
+        sendData(sockets);
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusPasswordMultipleConnections() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
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
+
+        for (int i = 0; i < 10; i++) {
+            Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+            connectSockets(sockets);
+            sendData(sockets);
+            closeSockets(sockets);
+        }
+    }
+
+    @Test
+    public void testSpake2PlusPasswordHandshakeServerLimit() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+        byte[] password2 = new byte[] {4, 5, 6};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .addMessageComponent("server-handshake-limit", new byte[] {16})
+                        .addMessageComponent("client-handshake-limit", new byte[] {24})
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password2)
+                        .addMessageComponent("server-handshake-limit", new byte[] {16})
+                        .addMessageComponent("client-handshake-limit", new byte[] {24})
+                        .build();
+
+        // Client uses wrong password first
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option2)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+
+        Pair<SSLContext, SSLContext> failingContexts = createContexts(kmfParamsClient, kmfParamsServer);
+
+        // Server handshake limit is 16, so it is ok if 15 connections fail.
+        for (int i = 0; i < 15; i++) {
+            Pair<SSLSocket, SSLSocket> sockets;
+            sockets = createSockets(failingContexts);
+            assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        }
+
+        // 16th connection should succeed (but requires a new client)
+        kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+        SSLContext workingClientContext = createClientContext(kmfParamsClient);
+        Pair<SSLContext, SSLContext> workingContexts = Pair.of(workingClientContext, failingContexts.getSecond());
+        Pair<SSLSocket, SSLSocket> workingSockets1 = createSockets(workingContexts);
+        connectSockets(workingSockets1);
+        sendData(workingSockets1);
+        closeSockets(workingSockets1);
+
+        // After one more failure, all connections should fail.
+        Pair<SSLSocket, SSLSocket> failingSockets = createSockets(failingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(failingSockets));
+        Pair<SSLSocket, SSLSocket> workingSockets2 = createSockets(workingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(workingSockets2));
+    }
+
+    @Test
+    public void testSpake2PlusPasswordHandshakeClientLimit() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+        byte[] password2 = new byte[] {4, 5, 6};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .addMessageComponent("server-handshake-limit", new byte[] {24})
+                        .addMessageComponent("client-handshake-limit", new byte[] {16})
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password2)
+                        .addMessageComponent("server-handshake-limit", new byte[] {24})
+                        .addMessageComponent("client-handshake-limit", new byte[] {16})
+                        .build();
+
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        // Server uses wrong password first
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> failingContexts = createContexts(kmfParamsClient, kmfParamsServer);
+
+        // Server handshake limit is 16, so it is ok if 15 connections fail.
+        for (int i = 0; i < 15; i++) {
+            Pair<SSLSocket, SSLSocket> sockets;
+            sockets = createSockets(failingContexts);
+            assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        }
+
+        // 16th connection should succeed (but requires a new server)
+        kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
+                        .build();
+        SSLContext workingServerContext = createServerContext(kmfParamsServer);
+        Pair<SSLContext, SSLContext> workingContexts = Pair.of(failingContexts.getFirst(), workingServerContext);
+        Pair<SSLSocket, SSLSocket> workingSockets1 = createSockets(workingContexts);
+        connectSockets(workingSockets1);
+        sendData(workingSockets1);
+        closeSockets(workingSockets1);
+
+        // After one more failure, all connections should fail.
+        Pair<SSLSocket, SSLSocket> failingSockets = createSockets(failingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(failingSockets));
+        Pair<SSLSocket, SSLSocket> workingSockets2 = createSockets(workingContexts);
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(workingSockets2));
+    }
+
+    @Test
+    public void testSpake2PlusMismatchedPassword() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+        byte[] password2 = new byte[] {4, 5, 6};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password2)
+                        .build();
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
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusMismatchedIds() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        // Client ID is different from the one in the server.
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(new byte[] {6})
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusEmptyIds() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+        PakeOption option2 =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        PakeClientKeyManagerParameters kmfParamsClient =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(new byte[0])
+                        .setServerId(new byte[0])
+                        .addOption(option)
+                        .build();
+
+        PakeServerKeyManagerParameters kmfParamsServer =
+                new PakeServerKeyManagerParameters.Builder()
+                        .setOptions(new byte[0], new byte[0], Arrays.asList(option2))
+                        .build();
+
+        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
+        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
+
+        connectSockets(sockets);
+        sendData(sockets);
+        closeSockets(sockets);
+    }
+
+    @Test
+    public void testSpake2PlusAndOthersInvalid() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        PakeClientKeyManagerParameters pakeParams =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
+        kmf.init(pakeParams);
+
+        KeyManager[] keyManagers = kmf.getKeyManagers();
+
+        KeyManagerFactory kmf2 =
+                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
+        kmf2.init(null, null);
+
+        // Add a x509 key manager to the array.
+        KeyManager[] keyManagersWithx509 = Arrays.copyOf(keyManagers, keyManagers.length + 1);
+
+        keyManagersWithx509[keyManagers.length] = kmf2.getKeyManagers()[0];
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+        TrustManager[] trustManagers = tmf.getTrustManagers();
+
+        SSLContext sslContext = SSLContext.getInstance("TlsV1.3");
+        // Should throw due to both SPAKE and x509 key managers
+        assertThrows(
+                KeyManagementException.class,
+                () -> sslContext.init(keyManagersWithx509, trustManagers, null));
+    }
+
+    @Test
+    public void testSpake2PlusNoTrustOrKeyInvalid() throws Exception {
+        byte[] password = new byte[] {1, 2, 3};
+
+        PakeOption option =
+                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
+                        .addMessageComponent("password", password)
+                        .build();
+
+        PakeClientKeyManagerParameters pakeParams =
+                new PakeClientKeyManagerParameters.Builder()
+                        .setClientId(CLIENT_ID.clone())
+                        .setServerId(SERVER_ID.clone())
+                        .addOption(option)
+                        .build();
+
+        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
+        kmf.init(pakeParams);
+
+        KeyManager[] keyManagers = kmf.getKeyManagers();
+
+        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
+        tmf.init((ManagerFactoryParameters) null);
+        TrustManager[] trustManagers = tmf.getTrustManagers();
+
+        SSLContext sslContext = SSLContext.getInstance("TlsV1.3");
+        assertThrows(KeyManagementException.class, () -> sslContext.init(keyManagers, null, null));
+
+        assertThrows(
+                KeyManagementException.class, () -> sslContext.init(null, trustManagers, null));
+    }
+
+    private <T> Future<T> runAsync(Callable<T> callable) {
+        return executor.submit(callable);
+    }
+}
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java
index cbeac011..97f7a221 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java
@@ -17,24 +17,27 @@
 
 package com.android.org.conscrypt;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
+
+import com.android.org.conscrypt.javax.net.ssl.TestSSLContext;
+
 import libcore.junit.util.SwitchTargetSdkVersionRule;
 import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
 
-import java.security.Provider;
-import javax.net.ssl.SSLSocket;
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
-import org.junit.Rule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
-import com.android.org.conscrypt.javax.net.ssl.TestSSLContext;
 
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertTrue;
-import static org.junit.Assert.assertThrows;
-import static org.junit.Assert.fail;
-import static org.junit.Assume.assumeFalse;
+import java.security.Provider;
+
+import javax.net.ssl.SSLSocket;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -87,7 +90,7 @@ public class TlsDeprecationTest {
         TestSSLContext context = TestSSLContext.create();
         final SSLSocket client =
                 (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1",});
+        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
         assertEquals(0, client.getEnabledProtocols().length);
     }
 
@@ -167,4 +170,4 @@ public class TlsDeprecationTest {
     public void testInitializeUndeprecatedDisabled_36() {
         assertThrows(RuntimeException.class, () -> TestUtils.getConscryptProvider(false, false));
     }
-}
\ No newline at end of file
+}
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
index e7b33ac1..516e95cb 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
@@ -17,37 +17,39 @@
 
 package com.android.org.conscrypt.ct;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
+
 import static java.nio.charset.StandardCharsets.US_ASCII;
 import static java.nio.charset.StandardCharsets.UTF_8;
 
 import com.android.org.conscrypt.OpenSSLKey;
-import com.android.org.conscrypt.metrics.StatsLog;
+import com.android.org.conscrypt.metrics.NoopStatsLog;
 
-import junit.framework.TestCase;
+import org.junit.After;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 import java.io.ByteArrayInputStream;
-import java.io.File;
-import java.io.FileNotFoundException;
-import java.io.FileOutputStream;
-import java.io.FileWriter;
 import java.io.IOException;
-import java.io.OutputStreamWriter;
-import java.io.PrintWriter;
-import java.security.PublicKey;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
 import java.security.cert.X509Certificate;
 import java.util.ArrayList;
 import java.util.Base64;
+import java.util.function.Supplier;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class LogStoreImplTest extends TestCase {
-    static class FakeStatsLog implements StatsLog {
+@RunWith(JUnit4.class)
+public class LogStoreImplTest {
+    /** FakeStatsLog captures the events being reported */
+    static class FakeStatsLog extends NoopStatsLog {
         public ArrayList<LogStore.State> states = new ArrayList<LogStore.State>();
 
-        @Override
-        public void countTlsHandshake(
-                boolean success, String protocol, String cipherSuite, long duration) {}
         @Override
         public void updateCTLogListStatusChanged(LogStore logStore) {
             states.add(logStore.getState());
@@ -78,9 +80,26 @@ public class LogStoreImplTest extends TestCase {
         }
     };
 
-    public void test_loadValidLogList() throws Exception {
-        // clang-format off
-        String content = "" +
+    /* Time supplier that can be set to any arbitrary time */
+    static class TimeSupplier implements Supplier<Long> {
+        private long currentTimeInNs;
+
+        TimeSupplier(long currentTimeInNs) {
+            this.currentTimeInNs = currentTimeInNs;
+        }
+
+        @Override
+        public Long get() {
+            return currentTimeInNs;
+        }
+
+        public void setCurrentTimeInNs(long currentTimeInNs) {
+            this.currentTimeInNs = currentTimeInNs;
+        }
+    }
+
+    // clang-format off
+    static final String validLogList = "" +
 "{" +
 "  \"version\": \"1.1\"," +
 "  \"log_list_timestamp\": 1704070861000," +
@@ -143,74 +162,171 @@ public class LogStoreImplTest extends TestCase {
 "            \"end_exclusive\": 1735693261000" +
 "          }" +
 "        }" +
+"      ]," +
+"      \"tiled_logs\": [" +
+"        {" +
+"         \"description\": \"Operator 2 'Test2025' log\"," +
+"          \"log_id\": \"DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=\"," +
+"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB/we6GOO/xwxivy4HhkrYFAAPo6e2nc346Wo2o2U+GvoPWSPJz91s/xrEvA3Bk9kWHUUXVZS5morFEzsgdHqPg==\"," +
+"          \"submission_url\": \"https://operator2.example.com/tiled/test2025\"," +
+"          \"monitoring_url\": \"https://operator2.exmaple.com/tiled_monitor/test2025\"," +
+"          \"mmd\": 86400," +
+"          \"state\": {" +
+"            \"usable\": {" +
+"              \"timestamp\": 1727734767000" +
+"            }" +
+"          }," +
+"          \"temporal_interval\": {" +
+"            \"start_inclusive\": 1767225600000," +
+"            \"end_exclusive\": 1782864000000" +
+"          }" +
+"        }" +
 "      ]" +
 "    }" +
 "  ]" +
 "}";
-        // clang-format on
+    // clang-format on
 
-        FakeStatsLog metrics = new FakeStatsLog();
-        File logList = writeFile(content);
-        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
-        store.setPolicy(alwaysCompliantStorePolicy);
+    Path grandparentDir;
+    Path parentDir;
+    Path logList;
 
-        assertNull("A null logId should return null", store.getKnownLog(null));
+    @After
+    public void tearDown() throws Exception {
+        if (logList != null) {
+            Files.deleteIfExists(logList);
+            Files.deleteIfExists(parentDir);
+            Files.deleteIfExists(grandparentDir);
+        }
+    }
 
+    @Test
+    public void loadValidLogList_returnsCompliantState() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
         byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                 + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
                 + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
                 + "\n-----END PUBLIC KEY-----\n")
                              .getBytes(US_ASCII);
         ByteArrayInputStream is = new ByteArrayInputStream(pem);
-
         LogInfo log1 =
                 new LogInfo.Builder()
                         .setPublicKey(OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey())
                         .setDescription("Operator 1 'Test2024' log")
-                        .setUrl("https://operator1.example.com/logs/test2024/")
+                        .setType(LogInfo.TYPE_RFC6962)
                         .setState(LogInfo.STATE_USABLE, 1667328840000L)
                         .setOperator("Operator 1")
                         .build();
         byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
+
+        assertNull("A null logId should return null", store.getKnownLog(/* logId= */ null));
         assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
-        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
         assertEquals("The metric update for log list state should be compliant",
-                metrics.states.get(0), LogStore.State.COMPLIANT);
+                LogStore.State.COMPLIANT, metrics.states.get(0));
     }
 
-    public void test_loadMalformedLogList() throws Exception {
+    @Test
+    public void loadMalformedLogList_returnsMalformedState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
         String content = "}}";
-        File logList = writeFile(content);
-        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
-        store.setPolicy(alwaysCompliantStorePolicy);
+        logList = writeLogList(content);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics);
 
         assertEquals(
-                "The log state should be malformed", store.getState(), LogStore.State.MALFORMED);
-        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+                "The log state should be malformed", LogStore.State.MALFORMED, store.getState());
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
         assertEquals("The metric update for log list state should be malformed",
-                metrics.states.get(0), LogStore.State.MALFORMED);
+                LogStore.State.MALFORMED, metrics.states.get(0));
     }
 
-    public void test_loadMissingLogList() throws Exception {
+    @Test
+    public void loadMissingLogList_returnsNotFoundState() throws Exception {
         FakeStatsLog metrics = new FakeStatsLog();
-        File logList = new File("does_not_exist");
-        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
-        store.setPolicy(alwaysCompliantStorePolicy);
+        Path missingLogList = Paths.get("missing_dir", "missing_subdir", "does_not_exist_log_list");
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics);
 
         assertEquals(
-                "The log state should be not found", store.getState(), LogStore.State.NOT_FOUND);
-        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+        assertEquals("One metric update should be emitted", 1, metrics.states.size());
         assertEquals("The metric update for log list state should be not found",
-                metrics.states.get(0), LogStore.State.NOT_FOUND);
+                LogStore.State.NOT_FOUND, metrics.states.get(0));
     }
 
-    private File writeFile(String content) throws IOException {
-        File file = File.createTempFile("test", null);
-        file.deleteOnExit();
-        try (FileWriter fw = new FileWriter(file)) {
-            fw.write(content);
-        }
+    @Test
+    public void loadMissingAndThenFoundLogList_logListIsLoaded() throws Exception {
+        // Arrange
+        FakeStatsLog metrics = new FakeStatsLog();
+        // Allocate a temporary file path and delete it. We keep the temporary
+        // path so that we can add a valid log list later on.
+        logList = writeLogList("");
+        Files.deleteIfExists(logList);
+        Files.deleteIfExists(parentDir);
+        Files.deleteIfExists(grandparentDir);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals(
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+
+        // Act
+        Files.createDirectory(grandparentDir);
+        Files.createDirectory(parentDir);
+        Files.write(logList, validLogList.getBytes());
+
+        // Assert
+        // 10ns < 10min, we should not check the log list yet.
+        fakeTime.setCurrentTimeInNs(10);
+        assertEquals(
+                "The log state should be not found", LogStore.State.NOT_FOUND, store.getState());
+
+        // 12min, the log list should be reloadable.
+        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+        assertEquals(
+                "The log state should be compliant", LogStore.State.COMPLIANT, store.getState());
+    }
+
+    @Test
+    public void loadExistingAndThenRemovedLogList_logListIsNotFound() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
+
+        Files.delete(logList);
+        // 12min, the log list should be reloadable.
+        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+
+        assertEquals(
+                "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
+    }
+
+    @Test
+    public void loadExistingLogListAndThenMoveDirectory_logListIsNotFound() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        logList = writeLogList(validLogList);
+        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInNs= */ 0);
+        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
+        assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());
+
+        Path oldParentDir = parentDir;
+        parentDir = grandparentDir.resolve("more_current");
+        Files.move(oldParentDir, parentDir);
+        logList = parentDir.resolve("log_list.json");
+        // 12min, the log list should be reloadable.
+        fakeTime.setCurrentTimeInNs(12L * 60 * 1000 * 1_000_000);
+
+        assertEquals(
+                "The log should have been refreshed", LogStore.State.NOT_FOUND, store.getState());
+    }
+
+    private Path writeLogList(String content) throws IOException {
+        grandparentDir = Files.createTempDirectory("v1");
+        parentDir = Files.createDirectory(grandparentDir.resolve("current"));
+        Path file = Files.createFile(parentDir.resolve("log_list.json"));
+        Files.write(file, content.getBytes());
         return file;
     }
 }
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
index d82efb05..24156459 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
@@ -41,9 +41,11 @@ public class PolicyImplTest {
     private static final String OPERATOR2 = "operator 2";
     private static LogInfo usableOp1Log1;
     private static LogInfo usableOp1Log2;
+    private static LogInfo usableStaticOp1Log;
     private static LogInfo retiredOp1LogOld;
     private static LogInfo retiredOp1LogNew;
     private static LogInfo usableOp2Log;
+    private static LogInfo usableStaticOp2Log;
     private static LogInfo retiredOp2Log;
     private static SignedCertificateTimestamp embeddedSCT;
     private static SignedCertificateTimestamp ocspSCT;
@@ -94,37 +96,49 @@ public class PolicyImplTest {
          */
         usableOp1Log1 = new LogInfo.Builder()
                                 .setPublicKey(new FakePublicKey(new byte[] {0x01}))
-                                .setUrl("")
+                                .setType(LogInfo.TYPE_RFC6962)
                                 .setOperator(OPERATOR1)
                                 .setState(LogInfo.STATE_USABLE, JAN2022)
                                 .build();
         usableOp1Log2 = new LogInfo.Builder()
                                 .setPublicKey(new FakePublicKey(new byte[] {0x02}))
-                                .setUrl("")
+                                .setType(LogInfo.TYPE_RFC6962)
                                 .setOperator(OPERATOR1)
                                 .setState(LogInfo.STATE_USABLE, JAN2022)
                                 .build();
+        usableStaticOp1Log = new LogInfo.Builder()
+                                     .setPublicKey(new FakePublicKey(new byte[] {0x07}))
+                                     .setType(LogInfo.TYPE_STATIC_CT_API)
+                                     .setOperator(OPERATOR1)
+                                     .setState(LogInfo.STATE_USABLE, JAN2022)
+                                     .build();
         retiredOp1LogOld = new LogInfo.Builder()
                                    .setPublicKey(new FakePublicKey(new byte[] {0x03}))
-                                   .setUrl("")
+                                   .setType(LogInfo.TYPE_RFC6962)
                                    .setOperator(OPERATOR1)
                                    .setState(LogInfo.STATE_RETIRED, JAN2022)
                                    .build();
         retiredOp1LogNew = new LogInfo.Builder()
                                    .setPublicKey(new FakePublicKey(new byte[] {0x06}))
-                                   .setUrl("")
+                                   .setType(LogInfo.TYPE_RFC6962)
                                    .setOperator(OPERATOR1)
                                    .setState(LogInfo.STATE_RETIRED, JUN2023)
                                    .build();
         usableOp2Log = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x04}))
-                               .setUrl("")
+                               .setType(LogInfo.TYPE_RFC6962)
                                .setOperator(OPERATOR2)
                                .setState(LogInfo.STATE_USABLE, JAN2022)
                                .build();
+        usableStaticOp2Log = new LogInfo.Builder()
+                                     .setPublicKey(new FakePublicKey(new byte[] {0x08}))
+                                     .setType(LogInfo.TYPE_STATIC_CT_API)
+                                     .setOperator(OPERATOR2)
+                                     .setState(LogInfo.STATE_USABLE, JAN2022)
+                                     .build();
         retiredOp2Log = new LogInfo.Builder()
                                 .setPublicKey(new FakePublicKey(new byte[] {0x05}))
-                                .setUrl("")
+                                .setType(LogInfo.TYPE_RFC6962)
                                 .setOperator(OPERATOR2)
                                 .setState(LogInfo.STATE_RETIRED, JAN2022)
                                 .build();
@@ -376,11 +390,76 @@ public class PolicyImplTest {
                 p.doesResultConformToPolicyAt(result, leaf, JAN2024));
     }
 
+    public void validVerificationResultPartialStatic(SignedCertificateTimestamp sct)
+            throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableStaticOp2Log)
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
+    public void validEmbeddedVerificationResultPartialStatic() throws Exception {
+        validVerificationResultPartialStatic(embeddedSCT);
+    }
+
+    @Test
+    public void validOCSPVerificationResultPartialStatic() throws Exception {
+        validVerificationResultPartialStatic(ocspSCT);
+    }
+
+    public void invalidTwoSctsAllStatic(SignedCertificateTimestamp sct) throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableStaticOp1Log)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableStaticOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two static SCTs", PolicyCompliance.NO_RFC6962_LOG,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
+    public void invalidEmbeddedTwoSctsAllStaticsVerificationResult() throws Exception {
+        invalidTwoSctsAllStatic(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPTwoSctsAllStaticsVerificationResult() throws Exception {
+        invalidTwoSctsAllStatic(ocspSCT);
+    }
+
     @Test
     public void validRecentLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        LogStore store = new LogStoreImpl() {
+        LogStore store = new LogStoreImpl(p) {
             @Override
             public long getTimestamp() {
                 return DEC2023;
@@ -393,7 +472,7 @@ public class PolicyImplTest {
     public void invalidFutureLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        LogStore store = new LogStoreImpl() {
+        LogStore store = new LogStoreImpl(p) {
             @Override
             public long getTimestamp() {
                 return JAN2025;
@@ -406,7 +485,7 @@ public class PolicyImplTest {
     public void invalidOldLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        LogStore store = new LogStoreImpl() {
+        LogStore store = new LogStoreImpl(p) {
             @Override
             public long getTimestamp() {
                 return JAN2023;
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/metrics/MetricsTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/metrics/MetricsTest.java
index bff59ee0..1d4228f1 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/metrics/MetricsTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/metrics/MetricsTest.java
@@ -20,6 +20,7 @@ package com.android.org.conscrypt.metrics;
 import static org.junit.Assert.assertEquals;
 
 import android.util.StatsEvent;
+import com.android.org.conscrypt.Platform;
 import com.android.org.conscrypt.TestUtils;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -38,10 +39,9 @@ public class MetricsTest {
     public void test_reflexiveEvent() throws Exception {
         TestUtils.assumeStatsLogAvailable();
 
-        Object sdkVersion = getSdkVersion();
         StatsEvent frameworkStatsEvent;
         ReflexiveStatsEvent reflexiveStatsEvent;
-        if ((sdkVersion != null) && ((int) sdkVersion > 32)) {
+        if (Platform.isSdkGreater(32)) {
             frameworkStatsEvent = StatsEvent.newBuilder()
                                                  .setAtomId(TLS_HANDSHAKE_REPORTED)
                                                  .writeBoolean(false)
@@ -52,8 +52,16 @@ public class MetricsTest {
                                                  .writeIntArray(new int[] {0}) // uids
                                                  .usePooledBuffer()
                                                  .build();
-            reflexiveStatsEvent = ReflexiveStatsEvent.buildEvent(
-                TLS_HANDSHAKE_REPORTED, false, 1, 2, 100, 3, new int[] {0});
+            ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder()
+                                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
+                                                          .writeBoolean(false)
+                                                          .writeInt(1) // protocol
+                                                          .writeInt(2) // cipher suite
+                                                          .writeInt(100) // duration
+                                                          .writeInt(3) // source
+                                                          .writeIntArray(new int[] {0}); // uids
+            builder.usePooledBuffer();
+            reflexiveStatsEvent = builder.build();
         } else {
             frameworkStatsEvent = StatsEvent.newBuilder()
                                                  .setAtomId(TLS_HANDSHAKE_REPORTED)
@@ -64,8 +72,15 @@ public class MetricsTest {
                                                  .writeInt(3) // source
                                                  .usePooledBuffer()
                                                  .build();
-            reflexiveStatsEvent = ReflexiveStatsEvent.buildEvent(
-                TLS_HANDSHAKE_REPORTED, false, 1, 2, 100, 3);
+            ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder()
+                                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
+                                                          .writeBoolean(false)
+                                                          .writeInt(1) // protocol
+                                                          .writeInt(2) // cipher suite
+                                                          .writeInt(100) // duration
+                                                          .writeInt(3); // source
+            builder.usePooledBuffer();
+            reflexiveStatsEvent = builder.build();
         }
 
         StatsEvent constructedEvent = (StatsEvent) reflexiveStatsEvent.getStatsEvent();
@@ -100,16 +115,4 @@ public class MetricsTest {
             }
         }
     }
-
-    static Object getSdkVersion() {
-        try {
-            OptionalMethod getSdkVersion =
-                    new OptionalMethod(Class.forName("dalvik.system.VMRuntime"),
-                                        "getSdkVersion");
-            return getSdkVersion.invokeStatic();
-        } catch (ClassNotFoundException e) {
-            return null;
-        }
-    }
-
 }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
index 02faf327..818dba92 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
@@ -23,6 +23,7 @@ import static org.junit.Assert.assertTrue;
 
 import com.android.org.conscrypt.TestUtils;
 
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.HashMap;
@@ -464,11 +465,24 @@ public final class StandardNames {
         assertValidCipherSuites(CIPHER_SUITES, cipherSuites);
     }
 
+    private static final List<String> OPTIONAL_CIPHER_SUITES = Arrays.asList(
+            "SSL_RSA_WITH_3DES_EDE_CBC_SHA"
+    );
+
     /**
      * Assert that the provided list of cipher suites matches the supported list.
      */
     public static void assertSupportedCipherSuites(String[] cipherSuites) {
-        assertSupportedCipherSuites(CIPHER_SUITES, cipherSuites);
+        List<String> filteredCipherSuites = new ArrayList<>();
+        for (String cipherSuite : cipherSuites) {
+            if (OPTIONAL_CIPHER_SUITES.contains(cipherSuite)) {
+                continue;
+            }
+            filteredCipherSuites.add(cipherSuite);
+        }
+        String[] filteredCipherSuitesArray = new String[filteredCipherSuites.size()];
+        filteredCipherSuites.toArray(filteredCipherSuitesArray);
+        assertSupportedCipherSuites(CIPHER_SUITES, filteredCipherSuitesArray);
     }
 
     /**
diff --git a/scripts/testLocalUber.sh b/scripts/testLocalUber.sh
index 2699384b..84dbd569 100755
--- a/scripts/testLocalUber.sh
+++ b/scripts/testLocalUber.sh
@@ -101,8 +101,33 @@ cd $CONSCRYPT_HOME
 ./gradlew :conscrypt-openjdk:testJar --console=plain
 test -f "$TESTJAR" || die "Test jar not built."
 
+# SIGTERM handler, e.g. for when tests hang and time out.
+# Send SIGQUIT to test process to get thread dump, give it
+# a few seconds to complete and then kill it.
+dump_threads() {
+    echo "Generating stack dump."
+    ps -fp "$TESTPID"
+    kill -QUIT "$TESTPID"
+    sleep 3
+    kill -KILL "$TESTPID"
+    exit 1
+}
+
 echo "Running tests."
 java $JAVADEBUG -jar "$JUNITJAR" execute -cp "${UBERJAR}:${TESTJAR}" \
-	 -n='org.conscrypt.ConscryptOpenJdkSuite' \
-	 --scan-classpath --reports-dir=. \
-	 --fail-if-no-tests $VERBOSE
+     -n='org.conscrypt.ConscryptOpenJdkSuite' \
+     --scan-classpath --reports-dir=. \
+     --fail-if-no-tests $VERBOSE &
+
+case $(uname -s) in
+    Darwin|Linux)
+        trap dump_threads SIGTERM SIGINT
+        ;;
+    *)
+        # TODO: Probably won't work on Windows but thread dumps
+        # work there already.
+        ;;
+esac
+
+TESTPID=$!
+wait "$TESTPID"
diff --git a/settings.gradle b/settings.gradle
index 2eefbc7a..798dc5bf 100644
--- a/settings.gradle
+++ b/settings.gradle
@@ -1,28 +1,49 @@
+pluginManagement {
+    repositories {
+        google()
+        mavenCentral()
+        gradlePluginPortal()
+    }
+}
+
+dependencyResolutionManagement {
+    repositories {
+        google()
+        mavenCentral()
+    }
+}
+
 rootProject.name = "conscrypt"
-include ":conscrypt-android"
-include ":conscrypt-android-platform"
-include ":conscrypt-android-stub"
+if (System.env.ANDROID_HOME && file(System.env.ANDROID_HOME).exists()) {
+    include ":conscrypt-android"
+    include ":conscrypt-android-platform"
+    include ":conscrypt-android-stub"
+    include ":conscrypt-benchmark-android"
+    include ":conscrypt-libcore-stub"
+
+    project(':conscrypt-android').projectDir = "$rootDir/android" as File
+    project(':conscrypt-android-platform').projectDir = "$rootDir/platform" as File
+    project(':conscrypt-android-stub').projectDir = "$rootDir/android-stub" as File
+    project(':conscrypt-benchmark-android').projectDir = "$rootDir/benchmark-android" as File
+    project(':conscrypt-libcore-stub').projectDir = "$rootDir/libcore-stub" as File
+} else {
+    logger.warn('Android SDK has not been detected. Skipping Android projects.')
+}
+
 include ":conscrypt-api-doclet"
-include ":conscrypt-benchmark-android"
 include ":conscrypt-benchmark-base"
 include ":conscrypt-benchmark-graphs"
 include ":conscrypt-benchmark-jmh"
 include ":conscrypt-constants"
-include ":conscrypt-libcore-stub"
 include ":conscrypt-openjdk"
 include ":conscrypt-openjdk-uber"
 include ":conscrypt-testing"
 
-project(':conscrypt-android').projectDir = "$rootDir/android" as File
-project(':conscrypt-android-platform').projectDir = "$rootDir/platform" as File
-project(':conscrypt-android-stub').projectDir = "$rootDir/android-stub" as File
 project(':conscrypt-api-doclet').projectDir = "$rootDir/api-doclet" as File
-project(':conscrypt-benchmark-android').projectDir = "$rootDir/benchmark-android" as File
 project(':conscrypt-benchmark-base').projectDir = "$rootDir/benchmark-base" as File
 project(':conscrypt-benchmark-graphs').projectDir = "$rootDir/benchmark-graphs" as File
 project(':conscrypt-benchmark-jmh').projectDir = "$rootDir/benchmark-jmh" as File
 project(':conscrypt-constants').projectDir = "$rootDir/constants" as File
-project(':conscrypt-libcore-stub').projectDir = "$rootDir/libcore-stub" as File
 project(':conscrypt-openjdk').projectDir = "$rootDir/openjdk" as File
 project(':conscrypt-openjdk-uber').projectDir = "$rootDir/openjdk-uber" as File
 project(':conscrypt-testing').projectDir = "$rootDir/testing" as File
diff --git a/testing/build.gradle b/testing/build.gradle
index 984c95bc..bae4f8ee 100644
--- a/testing/build.gradle
+++ b/testing/build.gradle
@@ -13,12 +13,7 @@ sourceSets {
 }
 
 dependencies {
-    // Only compile against these. Other modules will embed the generated
-    // constants directly. The stubs libraries should not end up in the
-    // final build.
-    compileOnly project(':conscrypt-constants'),
-                project(':conscrypt-libcore-stub'),
-                project(':conscrypt-android-stub')
+    compileOnly project(':conscrypt-constants')
 
     implementation libs.bouncycastle.apis,
             libs.bouncycastle.provider,
diff --git a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
index 8ae50744..5eb38481 100644
--- a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
+++ b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
@@ -21,6 +21,7 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 
 import java.util.Arrays;
+import java.util.ArrayList;
 import java.util.Collections;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -462,11 +463,24 @@ public final class StandardNames {
         assertValidCipherSuites(CIPHER_SUITES, cipherSuites);
     }
 
+    private static final List<String> OPTIONAL_CIPHER_SUITES = Arrays.asList(
+            "SSL_RSA_WITH_3DES_EDE_CBC_SHA"
+    );
+
     /**
      * Assert that the provided list of cipher suites matches the supported list.
      */
     public static void assertSupportedCipherSuites(String[] cipherSuites) {
-        assertSupportedCipherSuites(CIPHER_SUITES, cipherSuites);
+        List<String> filteredCipherSuites = new ArrayList<>();
+        for (String cipherSuite : cipherSuites) {
+            if (OPTIONAL_CIPHER_SUITES.contains(cipherSuite)) {
+                continue;
+            }
+            filteredCipherSuites.add(cipherSuite);
+        }
+        String[] filteredCipherSuitesArray = new String[filteredCipherSuites.size()];
+        filteredCipherSuites.toArray(filteredCipherSuitesArray);
+        assertSupportedCipherSuites(CIPHER_SUITES, filteredCipherSuitesArray);
     }
 
     /**
```

