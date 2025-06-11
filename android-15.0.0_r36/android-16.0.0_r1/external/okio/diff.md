```diff
diff --git a/.github/workflows/build.yml b/.github/workflows/build.yml
index a4fba896..0d42378e 100644
--- a/.github/workflows/build.yml
+++ b/.github/workflows/build.yml
@@ -30,7 +30,7 @@ jobs:
         uses: actions/checkout@v4
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v1
+        uses: gradle/actions/wrapper-validation@v4
 
       - name: Configure JDK
         uses: actions/setup-java@v4
@@ -43,15 +43,22 @@ jobs:
           ./gradlew -Dkjs=false -Dknative=false -Dkwasm=false -Dtest.java.version=${{ matrix.java-version }} build --stacktrace
 
   emulator:
-    runs-on: macos-latest
+    runs-on: ubuntu-latest
     steps:
+      # https://github.blog/changelog/2023-02-23-hardware-accelerated-android-virtualization-on-actions-windows-and-linux-larger-hosted-runners/
+      - name: Enable KVM group perms
+        run: |
+          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' | sudo tee /etc/udev/rules.d/99-kvm4all.rules
+          sudo udevadm control --reload-rules
+          sudo udevadm trigger --name-match=kvm
+          ls /dev/kvm
       - uses: actions/checkout@v4
-      - uses: actions/setup-java@v4.0.0
+      - uses: actions/setup-java@v4
         with:
           distribution: 'zulu'
           java-version: 19
 
-      - uses: gradle/gradle-build-action@v2
+      - uses: gradle/actions/setup-gradle@v4
 
       - uses: reactivecircus/android-emulator-runner@v2
         with:
@@ -69,7 +76,7 @@ jobs:
         uses: actions/checkout@v4
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v1
+        uses: gradle/actions/wrapper-validation@v4
 
       - name: Configure JDK
         uses: actions/setup-java@v4
@@ -87,14 +94,14 @@ jobs:
     strategy:
       fail-fast: false
       matrix:
-        os: [ macos-11, ubuntu-latest, windows-latest ]
+        os: [ macos-14, ubuntu-latest, windows-latest ]
 
     steps:
       - name: Checkout
         uses: actions/checkout@v4
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v1
+        uses: gradle/actions/wrapper-validation@v4
 
       - name: Configure JDK
         uses: actions/setup-java@v4
@@ -120,7 +127,7 @@ jobs:
           path: '**/build/reports'
 
   publish:
-    runs-on: macos-13
+    runs-on: macos-14
     if: github.repository == 'square/okio' && github.ref == 'refs/heads/master'
     needs: [jvm, all-platforms, emulator]
 
@@ -136,7 +143,7 @@ jobs:
 
       - name: Upload Artifacts
         run: |
-          ./gradlew clean publish --stacktrace
+          ./gradlew publish --stacktrace
         env:
           ORG_GRADLE_PROJECT_mavenCentralUsername: ${{ secrets.SONATYPE_NEXUS_USERNAME }}
           ORG_GRADLE_PROJECT_mavenCentralPassword: ${{ secrets.SONATYPE_NEXUS_PASSWORD }}
diff --git a/.github/workflows/release.yaml b/.github/workflows/release.yaml
new file mode 100644
index 00000000..7c1560b6
--- /dev/null
+++ b/.github/workflows/release.yaml
@@ -0,0 +1,26 @@
+name: release
+
+on:
+  push:
+    tags:
+      - '**'
+
+env:
+  GRADLE_OPTS: "-Dorg.gradle.jvmargs=-Xmx4g -Dorg.gradle.daemon=false -Dkotlin.incremental=false"
+
+jobs:
+  publish:
+    runs-on: macos-14
+
+    steps:
+      - uses: actions/checkout@v4
+      - uses: actions/setup-java@v4
+        with:
+          distribution: 'zulu'
+          java-version: 19
+
+      - run: ./gradlew publish
+        env:
+          ORG_GRADLE_PROJECT_mavenCentralUsername: ${{ secrets.SONATYPE_NEXUS_USERNAME }}
+          ORG_GRADLE_PROJECT_mavenCentralPassword: ${{ secrets.SONATYPE_NEXUS_PASSWORD }}
+          ORG_GRADLE_PROJECT_signingInMemoryKey: ${{ secrets.ARTIFACT_SIGNING_PRIVATE_KEY }}
diff --git a/.gitignore b/.gitignore
index 977efb87..49cdaadf 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,5 +1,6 @@
 .classpath
 .gradle
+.kotlin
 .project
 .settings
 eclipsebin
diff --git a/Android.bp b/Android.bp
index 47a4d56e..08e69edb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -23,12 +23,15 @@ java_library {
     ],
     common_srcs: [
         "okio/src/commonMain/**/*.kt",
+        "okio/src/zlibMain/**/*.kt",
+        "okio/src/systemFileSystemMain/**/*.kt",
     ],
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.ondevicepersonalization",
         "com.android.permission",
         "com.android.virt",
     ],
@@ -37,6 +40,7 @@ java_library {
     ],
     kotlincflags: [
         "-Xmulti-platform",
+        "-Xexpect-actual-classes",
     ],
     sdk_version: "core_current",
     min_sdk_version: "30",
diff --git a/CHANGELOG.md b/CHANGELOG.md
index ad2eaaa3..637ef5a7 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,6 +1,64 @@
 Change Log
 ==========
 
+## Version 3.10.2
+
+_2025-01-08_
+
+ * Fix: `okio-nodefilesystem` artifact is no longer empty.
+
+
+## Version 3.10.1
+
+_2025-01-07_
+
+ * New: `FileSystem.close()` may prevent future access and/or clean up associated resources depending on the backing implementation. `FakeFileSystem` will prevent future operations once closed.
+ * `InputStream`s created from `BufferedSource.inputStream()` now have a more efficient version of `InputStream.transferTo()` which reduces memory copies.
+ * `okio-nodefilesystem` is no longer publised as a JS project, but a Kotlin multiplatform project with only a JS target. ~This change should not affect consumers in any way, and is motivated by the Kotlin Gradle plugin deprecating the JS-only plugin.~ Please use 3.10.2 to ensure this change actually does not affect your builds.
+
+
+## Version 3.10.0
+
+_2025-01-06_
+
+This version is equivalent to the subsequent 3.10.1, but it did not fully publish to Maven Central due to infrastructure problems.
+
+
+## Version 3.9.1
+
+_2024-09-12_
+
+ * Fix: Support paths containing a single dot (".") in `Path.relativeTo`.
+ * Fix: Do not read from the upstream source when a 0-byte read is requested.
+ * Fix: Update kotlinx.datetime to 0.6.0 to correct a Gradle module metadata problem with 0.5.0.
+   Note: this artifact is only used in 'okio-fakefilesystem' and 'okio-nodefilesystem' and not in the Okio core.
+
+
+## Version 3.9.0
+
+_2024-03-12_
+
+ * New: `FileSystem.SYSTEM` can be used in source sets that target both Kotlin/Native and
+   Kotlin/JVM. Previously, we had this symbol in each source set but it wasn't available to
+   common source sets.
+ * New: `COpaquePointer.readByteString(...)` creates a ByteString from a memory address.
+ * New: Support `InflaterSource`, `DeflaterSink`, `GzipSink`, and `GzipSource` in Kotlin/Native.
+ * New: Support openZip() on Kotlin/Native. One known bug in this implementation is that
+   `FileMetadata.lastModifiedAtMillis()` is interpreted as UTC and not the host machine's time zone.
+ * New: Prefer NTFS timestamps in ZIP file systems' metadata. This avoids the time zone problems
+   of ZIP's built-in DOS timestamps, and the 2038 time bombs of ZIP's extended timestamps.
+ * Fix: Don't leak file handles to opened JAR files open in `FileSystem.RESOURCES`.
+ * Fix: Don't throw a `NullPointerException` if `Closeable.use { ... }` returns null.
+
+
+## Version 3.8.0
+
+_2024-02-09_
+
+ * New: `TypedOptions` works like `Options`, but it returns a `T` rather than an index.
+ * Fix: Don't leave sinks open when there's a race in `Pipe.fold()`.
+
+
 ## Version 3.7.0
 
 _2023-12-16_
diff --git a/METADATA b/METADATA
index c45ecd35..dbe01278 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,20 @@
-name: "okio"
-description:
-    "Okio is a library that complements java.io and java.nio to make it much "
-    "easier to access, store, and process your data. It started as a component "
-    "of OkHttp, the capable HTTP client included in Android. It's "
-    "well-exercised and ready to solve new problems."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/okio
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "okio"
+description: "Okio is a library that complements java.io and java.nio to make it much easier to access, store, and process your data. It started as a component of OkHttp, the capable HTTP client included in Android. It\'s well-exercised and ready to solve new problems."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://square.github.io/okio/"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 9
   }
-  url {
-    type: GIT
+  homepage: "https://square.github.io/okio/"
+  identifier {
+    type: "Git"
     value: "https://github.com/square/okio/"
+    version: "3.10.2"
   }
-  version: "3.7.0"
-  last_upgrade_date { year: 2024 month: 1 day: 3 }
-  license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index f8765892..c7c38067 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 file:platform/external/lottie:OWNERS
 kirit@google.com
 olegsh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/android-test/build.gradle.kts b/android-test/build.gradle.kts
index 5f9957ba..a0a971a4 100644
--- a/android-test/build.gradle.kts
+++ b/android-test/build.gradle.kts
@@ -1,3 +1,6 @@
+import com.android.build.gradle.internal.lint.AndroidLintAnalysisTask
+import com.android.build.gradle.internal.lint.AndroidLintTask
+
 plugins {
   id("com.android.library")
   id("org.jetbrains.kotlin.android")
@@ -16,6 +19,8 @@ val isIDE = properties.containsKey("android.injected.invoked.from.ide") ||
   System.getenv("IDEA_INITIAL_DIRECTORY") != null
 
 android {
+  namespace = "com.squareup.okio"
+
   compileOptions {
     sourceCompatibility = JavaVersion.VERSION_1_8
     targetCompatibility = JavaVersion.VERSION_1_8
@@ -58,6 +63,11 @@ android {
   }
 }
 
+// https://issuetracker.google.com/issues/325146674
+tasks.withType<AndroidLintAnalysisTask> {
+  onlyIf { false }
+}
+
 dependencies {
   coreLibraryDesugaring(libs.android.desugar.jdk.libs)
   androidTestImplementation(libs.androidx.test.ext.junit)
diff --git a/android-test/src/main/AndroidManifest.xml b/android-test/src/main/AndroidManifest.xml
index fe95031b..584e1d2f 100644
--- a/android-test/src/main/AndroidManifest.xml
+++ b/android-test/src/main/AndroidManifest.xml
@@ -1,7 +1,7 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     tools:ignore="MissingClass"
-    package="com.squareup.okio">
+    >
 
   <uses-permission android:name="android.permission.INTERNET" />
 
diff --git a/build-support/build.gradle.kts b/build-support/build.gradle.kts
index cd0c3df4..ea79bc78 100644
--- a/build-support/build.gradle.kts
+++ b/build-support/build.gradle.kts
@@ -22,5 +22,5 @@ gradlePlugin {
 }
 
 dependencies {
-  implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.21")
+  implementation(libs.kotlin.gradle.plugin)
 }
diff --git a/build-support/settings.gradle.kts b/build-support/settings.gradle.kts
index 2fcdac38..215a5d58 100644
--- a/build-support/settings.gradle.kts
+++ b/build-support/settings.gradle.kts
@@ -1 +1,7 @@
-// empty.
+dependencyResolutionManagement {
+  versionCatalogs {
+    create("libs") {
+      from(files("../gradle/libs.versions.toml"))
+    }
+  }
+}
diff --git a/build-support/src/main/kotlin/platforms.kt b/build-support/src/main/kotlin/platforms.kt
index 4cfb5ae5..002c49e5 100644
--- a/build-support/src/main/kotlin/platforms.kt
+++ b/build-support/src/main/kotlin/platforms.kt
@@ -125,7 +125,6 @@ fun KotlinMultiplatformExtension.configureOrCreateJsPlatforms() {
       kotlinOptions {
         moduleKind = "umd"
         sourceMap = true
-        metaInfo = true
       }
     }
     nodejs {
diff --git a/build.gradle.kts b/build.gradle.kts
index f564d88a..de613c28 100644
--- a/build.gradle.kts
+++ b/build.gradle.kts
@@ -1,4 +1,4 @@
-import aQute.bnd.gradle.BundleTaskConvention
+import aQute.bnd.gradle.BundleTaskExtension
 import com.diffplug.gradle.spotless.SpotlessExtension
 import com.vanniktech.maven.publish.MavenPublishBaseExtension
 import com.vanniktech.maven.publish.SonatypeHost
@@ -15,6 +15,9 @@ import org.jetbrains.dokka.gradle.DokkaTask
 import org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootExtension
 import org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootPlugin
 import org.jetbrains.kotlin.gradle.targets.js.npm.tasks.KotlinNpmInstallTask
+import org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest
+import org.jetbrains.kotlin.gradle.targets.jvm.tasks.KotlinJvmTest
+import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest
 import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
 
 plugins {
@@ -24,6 +27,7 @@ plugins {
 buildscript {
   dependencies {
     classpath(libs.android.gradle.plugin)
+    classpath(libs.burst.gradle.plugin)
     classpath(libs.dokka)
     classpath(libs.jmh.gradle.plugin)
     classpath(libs.binaryCompatibilityValidator)
@@ -43,7 +47,7 @@ apply(plugin = "com.vanniktech.maven.publish.base")
 
 // When scripts are applied the buildscript classes are not accessible directly therefore we save
 // the class here to make it accessible.
-ext.set("bndBundleTaskConventionClass", BundleTaskConvention::class.java)
+ext.set("bndBundleTaskExtensionClass", BundleTaskExtension::class.java)
 
 allprojects {
   group = project.property("GROUP") as String
@@ -246,3 +250,22 @@ plugins.withType<NodeJsRootPlugin> {
     args += "--ignore-engines"
   }
 }
+
+/**
+ * Set the `OKIO_ROOT` environment variable for tests to access it.
+ * https://publicobject.com/2023/04/16/read-a-project-file-in-a-kotlin-multiplatform-test/
+ */
+allprojects {
+  tasks.withType<KotlinJvmTest>().configureEach {
+    environment("OKIO_ROOT", rootDir)
+  }
+
+  tasks.withType<KotlinNativeTest>().configureEach {
+    environment("SIMCTL_CHILD_OKIO_ROOT", rootDir)
+    environment("OKIO_ROOT", rootDir)
+  }
+
+  tasks.withType<KotlinJsTest>().configureEach {
+    environment("OKIO_ROOT", rootDir.toString())
+  }
+}
diff --git a/docs/index.md b/docs/index.md
index 4fb96f5e..44549698 100644
--- a/docs/index.md
+++ b/docs/index.md
@@ -77,7 +77,7 @@ works and how Okio does it.
 [Ok Multiplatform!][ok_multiplatform_talk] ([slides][ok_multiplatform_slides]): How we changed
 Okio’s implementation language from Java to Kotlin.
 
-[Nerding Out On Okio][apis_talk]: The story of the Okio APIs, their design and tradeoffs, as well 
+[Nerding Out On Okio][apis_talk]: The story of the Okio APIs, their design and tradeoffs, as well
 as implementation notes with animated marbles diagrams.
 
 
@@ -98,7 +98,7 @@ Releases
 Our [change log][changelog] has release history.
 
 ```kotlin
-implementation("com.squareup.okio:okio:3.7.0")
+implementation("com.squareup.okio:okio:3.10.2")
 ```
 
 <details>
@@ -106,11 +106,11 @@ implementation("com.squareup.okio:okio:3.7.0")
 
 ```kotlin
 repositories {
-    maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
+  maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
 }
 
 dependencies {
-   implementation("com.squareup.okio:okio:3.7.0")
+  implementation("com.squareup.okio:okio:3.11.0-SNAPSHOT")
 }
 ```
 
diff --git a/docs/recipes.md b/docs/recipes.md
index acc5dcc7..572dade6 100644
--- a/docs/recipes.md
+++ b/docs/recipes.md
@@ -935,7 +935,7 @@ parameters should both be 16 bytes long.
 [HashingKt]: https://github.com/square/okio/blob/master/samples/src/jvmMain/kotlin/okio/samples/Hashing.kt
 [Hashing]: https://github.com/square/okio/blob/master/samples/src/jvmMain/java/okio/samples/Hashing.java
 [ReadFileLineByLine]: https://github.com/square/okio/blob/master/samples/src/jvmMain/java/okio/samples/ReadFileLineByLine.java
-[ReadFileLineByLineKt]: https://github.com/square/okio/blob/master/samples/src/jvmMain/kotlin/okio/samples/ReadFileLineByLine.kt
+[ReadFileLineByLineKt]: https://github.com/square/okio/blob/master/samples/src/jvmMain/kotlin/okio/samples/ReadJavaIoFileLineByLine.kt
 [SocksProxyServerKt]: https://github.com/square/okio/blob/master/samples/src/jvmMain/kotlin/okio/samples/SocksProxyServer.kt
 [SocksProxyServer]: https://github.com/square/okio/blob/master/samples/src/jvmMain/java/okio/samples/SocksProxyServer.java
 [WriteFile]: https://github.com/square/okio/blob/master/samples/src/jvmMain/java/okio/samples/WriteFile.java
diff --git a/gradle.properties b/gradle.properties
index ed1f6d9a..35b5fd53 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -8,8 +8,8 @@ android.defaults.buildfeatures.renderscript=false
 android.defaults.buildfeatures.resvalues=false
 android.defaults.buildfeatures.shaders=false
 
+kotlin.mpp.commonizerLogLevel=info
 kotlin.mpp.stability.nowarn=true
 
 GROUP=com.squareup.okio
-VERSION_NAME=3.7.0
-kotlin.mpp.commonizerLogLevel=info
+VERSION_NAME=3.10.2
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index ba610822..2b1acf03 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -1,24 +1,27 @@
 [versions]
 jmh = "1.37"
+kotlin = "2.1.0"
 ktlint = "0.48.2"
 
 [libraries]
-android-gradle-plugin = { module = "com.android.tools.build:gradle", version = "7.4.2" }
-android-desugar-jdk-libs = { module = "com.android.tools:desugar_jdk_libs", version = "2.0.4" }
-androidx-test-ext-junit = { module = "androidx.test.ext:junit", version = "1.1.5" }
+android-desugar-jdk-libs = { module = "com.android.tools:desugar_jdk_libs", version = "2.1.4" }
+android-gradle-plugin = { module = "com.android.tools.build:gradle", version = "8.7.3" }
+androidx-test-ext-junit = { module = "androidx.test.ext:junit", version = "1.2.1" }
 androidx-test-runner = { module = "androidx.test:runner", version = "1.5.2" }
-binaryCompatibilityValidator = { module = "org.jetbrains.kotlinx.binary-compatibility-validator:org.jetbrains.kotlinx.binary-compatibility-validator.gradle.plugin", version = "0.13.2" }
-kotlin-test = { module = "org.jetbrains.kotlin:kotlin-test" }
-kotlin-test-junit = { module = "org.jetbrains.kotlin:kotlin-test-junit" }
-kotlin-time = { module = "org.jetbrains.kotlinx:kotlinx-datetime", version = "0.5.0" }
-jmh-gradle-plugin = { module = "me.champeau.jmh:jmh-gradle-plugin", version = "0.7.2" }
+binaryCompatibilityValidator = { module = "org.jetbrains.kotlinx.binary-compatibility-validator:org.jetbrains.kotlinx.binary-compatibility-validator.gradle.plugin", version = "0.17.0" }
+bnd = { module = "biz.aQute.bnd:biz.aQute.bnd.gradle", version = "7.1.0" }
+burst-gradle-plugin = { module = "app.cash.burst:burst-gradle-plugin", version = "2.2.0" }
+dokka = { module = "org.jetbrains.dokka:dokka-gradle-plugin", version = "2.0.0" }
 jmh-core = { module = "org.openjdk.jmh:jmh-core", version.ref = "jmh" }
 jmh-generator = { module = "org.openjdk.jmh:jmh-generator-annprocess", version.ref = "jmh" }
-dokka = { module = "org.jetbrains.dokka:dokka-gradle-plugin", version = "1.9.10" }
-spotless = { module = "com.diffplug.spotless:spotless-plugin-gradle", version = "6.23.3" }
-bnd = { module = "biz.aQute.bnd:biz.aQute.bnd.gradle", version = "6.4.0" }
-vanniktech-publish-plugin = { module = "com.vanniktech:gradle-maven-publish-plugin", version = "0.25.3" }
-test-junit = { module = "junit:junit", version = "4.13.2" }
-test-assertj = { module = "org.assertj:assertj-core", version = "3.24.2" }
-test-assertk = "com.willowtreeapps.assertk:assertk:0.28.0"
+jmh-gradle-plugin = { module = "me.champeau.jmh:jmh-gradle-plugin", version = "0.7.2" }
+kotlin-gradle-plugin = { module = "org.jetbrains.kotlin:kotlin-gradle-plugin", version.ref = "kotlin" }
+kotlin-test = { module = "org.jetbrains.kotlin:kotlin-test" }
+kotlin-test-junit = { module = "org.jetbrains.kotlin:kotlin-test-junit" }
+kotlin-time = { module = "org.jetbrains.kotlinx:kotlinx-datetime", version = "0.6.1" }
+spotless = { module = "com.diffplug.spotless:spotless-plugin-gradle", version = "7.0.1" }
+test-assertj = { module = "org.assertj:assertj-core", version = "3.27.2" }
+test-assertk = "com.willowtreeapps.assertk:assertk:0.28.1"
 test-jimfs = "com.google.jimfs:jimfs:1.3.0"
+test-junit = { module = "junit:junit", version = "4.13.2" }
+vanniktech-publish-plugin = { module = "com.vanniktech:gradle-maven-publish-plugin", version = "0.30.0" }
diff --git a/gradle/wrapper/gradle-wrapper.jar b/gradle/wrapper/gradle-wrapper.jar
index 7f93135c..a4b76b95 100644
Binary files a/gradle/wrapper/gradle-wrapper.jar and b/gradle/wrapper/gradle-wrapper.jar differ
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 3fa8f862..cea7a793 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -1,6 +1,6 @@
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-8.4-bin.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.12-bin.zip
 networkTimeout=10000
 validateDistributionUrl=true
 zipStoreBase=GRADLE_USER_HOME
diff --git a/gradlew b/gradlew
index 1aa94a42..f3b75f3b 100755
--- a/gradlew
+++ b/gradlew
@@ -15,6 +15,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
+# SPDX-License-Identifier: Apache-2.0
+#
 
 ##############################################################################
 #
@@ -55,7 +57,7 @@
 #       Darwin, MinGW, and NonStop.
 #
 #   (3) This script is generated from the Groovy template
-#       https://github.com/gradle/gradle/blob/HEAD/subprojects/plugins/src/main/resources/org/gradle/api/internal/plugins/unixStartScript.txt
+#       https://github.com/gradle/gradle/blob/HEAD/platforms/jvm/plugins-application/src/main/resources/org/gradle/api/internal/plugins/unixStartScript.txt
 #       within the Gradle project.
 #
 #       You can find Gradle at https://github.com/gradle/gradle/.
@@ -84,7 +86,7 @@ done
 # shellcheck disable=SC2034
 APP_BASE_NAME=${0##*/}
 # Discard cd standard output in case $CDPATH is set (https://github.com/gradle/gradle/issues/25036)
-APP_HOME=$( cd "${APP_HOME:-./}" > /dev/null && pwd -P ) || exit
+APP_HOME=$( cd -P "${APP_HOME:-./}" > /dev/null && printf '%s\n' "$PWD" ) || exit
 
 # Use the maximum available, or set MAX_FD != -1 to use that value.
 MAX_FD=maximum
diff --git a/gradlew.bat b/gradlew.bat
index 93e3f59f..9d21a218 100644
--- a/gradlew.bat
+++ b/gradlew.bat
@@ -13,6 +13,8 @@
 @rem See the License for the specific language governing permissions and
 @rem limitations under the License.
 @rem
+@rem SPDX-License-Identifier: Apache-2.0
+@rem
 
 @if "%DEBUG%"=="" @echo off
 @rem ##########################################################################
@@ -43,11 +45,11 @@ set JAVA_EXE=java.exe
 %JAVA_EXE% -version >NUL 2>&1
 if %ERRORLEVEL% equ 0 goto execute
 
-echo.
-echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
-echo.
-echo Please set the JAVA_HOME variable in your environment to match the
-echo location of your Java installation.
+echo. 1>&2
+echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH. 1>&2
+echo. 1>&2
+echo Please set the JAVA_HOME variable in your environment to match the 1>&2
+echo location of your Java installation. 1>&2
 
 goto fail
 
@@ -57,11 +59,11 @@ set JAVA_EXE=%JAVA_HOME%/bin/java.exe
 
 if exist "%JAVA_EXE%" goto execute
 
-echo.
-echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
-echo.
-echo Please set the JAVA_HOME variable in your environment to match the
-echo location of your Java installation.
+echo. 1>&2
+echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME% 1>&2
+echo. 1>&2
+echo Please set the JAVA_HOME variable in your environment to match the 1>&2
+echo location of your Java installation. 1>&2
 
 goto fail
 
diff --git a/kotlin-js-store/yarn.lock b/kotlin-js-store/yarn.lock
index c9f26541..207deee9 100644
--- a/kotlin-js-store/yarn.lock
+++ b/kotlin-js-store/yarn.lock
@@ -26,6 +26,11 @@
   resolved "https://registry.yarnpkg.com/@jridgewell/resolve-uri/-/resolve-uri-3.1.0.tgz#2203b118c157721addfe69d47b70465463066d78"
   integrity sha512-F2msla3tad+Mfht5cJq7LSXcdudKTWCVYUgw6pLFOOHSTtZlj6SWNYAp+AhuqLmWdBO2X5hPrLcu8cVP8fy28w==
 
+"@jridgewell/resolve-uri@^3.1.0":
+  version "3.1.2"
+  resolved "https://registry.yarnpkg.com/@jridgewell/resolve-uri/-/resolve-uri-3.1.2.tgz#7a0ee601f60f99a20c7c7c5ff0c80388c1189bd6"
+  integrity sha512-bRISgCIjP20/tbWSPWMEi54QVPRZExkuD9lJL+UIxUKtwVJA8wW1Trb1jMs1RFXo1CBTNZ/5hpC9QvmKWdopKw==
+
 "@jridgewell/set-array@^1.0.1":
   version "1.1.2"
   resolved "https://registry.yarnpkg.com/@jridgewell/set-array/-/set-array-1.1.2.tgz#7c6cf998d6d20b914c0a55a91ae928ff25965e72"
@@ -49,7 +54,20 @@
   resolved "https://registry.yarnpkg.com/@jridgewell/sourcemap-codec/-/sourcemap-codec-1.4.15.tgz#d7c6e6755c78567a951e04ab52ef0fd26de59f32"
   integrity sha512-eF2rxCRulEKXHTRiDrDy6erMYWqNw4LPdQ8UQA4huuxaQsVeRPFl2oM8oDGxMFhJUWZf9McpLtJasDDZb/Bpeg==
 
-"@jridgewell/trace-mapping@^0.3.17", "@jridgewell/trace-mapping@^0.3.9":
+"@jridgewell/sourcemap-codec@^1.4.14":
+  version "1.5.0"
+  resolved "https://registry.yarnpkg.com/@jridgewell/sourcemap-codec/-/sourcemap-codec-1.5.0.tgz#3188bcb273a414b0d215fd22a58540b989b9409a"
+  integrity sha512-gv3ZRaISU3fjPAgNsriBRqGWQL6quFx04YMPW/zD8XMLsU32mhCCbfbO6KZFLjvYpCZ8zyDEgqsgf+PwPaM7GQ==
+
+"@jridgewell/trace-mapping@^0.3.20":
+  version "0.3.25"
+  resolved "https://registry.yarnpkg.com/@jridgewell/trace-mapping/-/trace-mapping-0.3.25.tgz#15f190e98895f3fc23276ee14bc76b675c2e50f0"
+  integrity sha512-vNk6aEwybGtawWmy/PzwnGDOjCkLWSD2wqvjGGAgOAwCGWySYXfYoxt00IJkTF+8Lb57DwOb3Aa0o9CApepiYQ==
+  dependencies:
+    "@jridgewell/resolve-uri" "^3.1.0"
+    "@jridgewell/sourcemap-codec" "^1.4.14"
+
+"@jridgewell/trace-mapping@^0.3.9":
   version "0.3.18"
   resolved "https://registry.yarnpkg.com/@jridgewell/trace-mapping/-/trace-mapping-0.3.18.tgz#25783b2086daf6ff1dcb53c9249ae480e4dd4cd6"
   integrity sha512-w+niJYzMHdd7USdiH2U6869nqhD2nbfZXND5Yp93qIbEmnDNk7PD48o+YchRVpzMU7M6jVCbenTR7PA1FLQ9pA==
@@ -79,28 +97,12 @@
   dependencies:
     "@types/node" "*"
 
-"@types/eslint-scope@^3.7.3":
-  version "3.7.4"
-  resolved "https://registry.yarnpkg.com/@types/eslint-scope/-/eslint-scope-3.7.4.tgz#37fc1223f0786c39627068a12e94d6e6fc61de16"
-  integrity sha512-9K4zoImiZc3HlIp6AVUDE4CWYx22a+lhSZMYNpbjW04+YF0KWj4pJXnEMjdnFTiQibFFmElcsasJXDbdI/EPhA==
-  dependencies:
-    "@types/eslint" "*"
-    "@types/estree" "*"
-
-"@types/eslint@*":
-  version "8.44.0"
-  resolved "https://registry.yarnpkg.com/@types/eslint/-/eslint-8.44.0.tgz#55818eabb376e2272f77fbf5c96c43137c3c1e53"
-  integrity sha512-gsF+c/0XOguWgaOgvFs+xnnRqt9GwgTvIks36WpE6ueeI4KCEHHd8K/CKHqhOqrJKsYH8m27kRzQEvWXAwXUTw==
-  dependencies:
-    "@types/estree" "*"
-    "@types/json-schema" "*"
-
-"@types/estree@*", "@types/estree@^1.0.0":
-  version "1.0.1"
-  resolved "https://registry.yarnpkg.com/@types/estree/-/estree-1.0.1.tgz#aa22750962f3bf0e79d753d3cc067f010c95f194"
-  integrity sha512-LG4opVs2ANWZ1TJoKc937iMmNstM/d0ae1vNbnBvBhqCSezgVUOzcLCqbI5elV8Vy6WKwKjaqR+zO9VKirBBCA==
+"@types/estree@^1.0.5":
+  version "1.0.6"
+  resolved "https://registry.yarnpkg.com/@types/estree/-/estree-1.0.6.tgz#628effeeae2064a1b4e79f78e81d87b7e5fc7b50"
+  integrity sha512-AYnb1nQyY49te+VRAVgmzfcgjYS91mY5P0TKUDCLEM+gNnA+3T6rWITXRLYCpahpqSQbN5cE+gHpnPyXjHWxcw==
 
-"@types/json-schema@*", "@types/json-schema@^7.0.8":
+"@types/json-schema@^7.0.8":
   version "7.0.12"
   resolved "https://registry.yarnpkg.com/@types/json-schema/-/json-schema-7.0.12.tgz#d70faba7039d5fca54c83c7dbab41051d2b6f6cb"
   integrity sha512-Hr5Jfhc9eYOQNPYO5WLDq/n4jqijdHNlDXjuAQkkt+mWdQR+XJToOHrsD4cPaMXpn6KO7y2+wM8AZEs8VpBLVA==
@@ -110,10 +112,10 @@
   resolved "https://registry.yarnpkg.com/@types/node/-/node-20.4.1.tgz#a6033a8718653c50ac4962977e14d0f984d9527d"
   integrity sha512-JIzsAvJeA/5iY6Y/OxZbv1lUcc8dNSE77lb2gnBH+/PJ3lFR1Ccvgwl5JWnHAkNHcRsT0TbpVOsiMKZ1F/yyJg==
 
-"@webassemblyjs/ast@1.11.6", "@webassemblyjs/ast@^1.11.5":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/ast/-/ast-1.11.6.tgz#db046555d3c413f8966ca50a95176a0e2c642e24"
-  integrity sha512-IN1xI7PwOvLPgjcf180gC1bqn3q/QaOCwYUahIOhbYUu8KA/3tw2RT/T0Gidi1l7Hhj5D/INhJxiICObqpMu4Q==
+"@webassemblyjs/ast@1.12.1", "@webassemblyjs/ast@^1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/ast/-/ast-1.12.1.tgz#bb16a0e8b1914f979f45864c23819cc3e3f0d4bb"
+  integrity sha512-EKfMUOPRRUTy5UII4qJDGPpqfwjOmZ5jeGFwid9mnoqIFK+e0vqoi1qH56JpmZSzEL53jKnNzScdmftJyG5xWg==
   dependencies:
     "@webassemblyjs/helper-numbers" "1.11.6"
     "@webassemblyjs/helper-wasm-bytecode" "1.11.6"
@@ -128,10 +130,10 @@
   resolved "https://registry.yarnpkg.com/@webassemblyjs/helper-api-error/-/helper-api-error-1.11.6.tgz#6132f68c4acd59dcd141c44b18cbebbd9f2fa768"
   integrity sha512-o0YkoP4pVu4rN8aTJgAyj9hC2Sv5UlkzCHhxqWj8butaLvnpdc2jOwh4ewE6CX0txSfLn/UYaV/pheS2Txg//Q==
 
-"@webassemblyjs/helper-buffer@1.11.6":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/helper-buffer/-/helper-buffer-1.11.6.tgz#b66d73c43e296fd5e88006f18524feb0f2c7c093"
-  integrity sha512-z3nFzdcp1mb8nEOFFk8DrYLpHvhKC3grJD2ardfKOzmbmJvEf/tPIqCY+sNcwZIY8ZD7IkB2l7/pqhUhqm7hLA==
+"@webassemblyjs/helper-buffer@1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/helper-buffer/-/helper-buffer-1.12.1.tgz#6df20d272ea5439bf20ab3492b7fb70e9bfcb3f6"
+  integrity sha512-nzJwQw99DNDKr9BVCOZcLuJJUlqkJh+kVzVl6Fmq/tI5ZtEyWT1KZMyOXltXLZJmDtvLCDgwsyrkohEtopTXCw==
 
 "@webassemblyjs/helper-numbers@1.11.6":
   version "1.11.6"
@@ -147,15 +149,15 @@
   resolved "https://registry.yarnpkg.com/@webassemblyjs/helper-wasm-bytecode/-/helper-wasm-bytecode-1.11.6.tgz#bb2ebdb3b83aa26d9baad4c46d4315283acd51e9"
   integrity sha512-sFFHKwcmBprO9e7Icf0+gddyWYDViL8bpPjJJl0WHxCdETktXdmtWLGVzoHbqUcY4Be1LkNfwTmXOJUFZYSJdA==
 
-"@webassemblyjs/helper-wasm-section@1.11.6":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/helper-wasm-section/-/helper-wasm-section-1.11.6.tgz#ff97f3863c55ee7f580fd5c41a381e9def4aa577"
-  integrity sha512-LPpZbSOwTpEC2cgn4hTydySy1Ke+XEu+ETXuoyvuyezHO3Kjdu90KK95Sh9xTbmjrCsUwvWwCOQQNta37VrS9g==
+"@webassemblyjs/helper-wasm-section@1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/helper-wasm-section/-/helper-wasm-section-1.12.1.tgz#3da623233ae1a60409b509a52ade9bc22a37f7bf"
+  integrity sha512-Jif4vfB6FJlUlSbgEMHUyk1j234GTNG9dBJ4XJdOySoj518Xj0oGsNi59cUQF4RRMS9ouBUxDDdyBVfPTypa5g==
   dependencies:
-    "@webassemblyjs/ast" "1.11.6"
-    "@webassemblyjs/helper-buffer" "1.11.6"
+    "@webassemblyjs/ast" "1.12.1"
+    "@webassemblyjs/helper-buffer" "1.12.1"
     "@webassemblyjs/helper-wasm-bytecode" "1.11.6"
-    "@webassemblyjs/wasm-gen" "1.11.6"
+    "@webassemblyjs/wasm-gen" "1.12.1"
 
 "@webassemblyjs/ieee754@1.11.6":
   version "1.11.6"
@@ -176,72 +178,72 @@
   resolved "https://registry.yarnpkg.com/@webassemblyjs/utf8/-/utf8-1.11.6.tgz#90f8bc34c561595fe156603be7253cdbcd0fab5a"
   integrity sha512-vtXf2wTQ3+up9Zsg8sa2yWiQpzSsMyXj0qViVP6xKGCUT8p8YJ6HqI7l5eCnWx1T/FYdsv07HQs2wTFbbof/RA==
 
-"@webassemblyjs/wasm-edit@^1.11.5":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-edit/-/wasm-edit-1.11.6.tgz#c72fa8220524c9b416249f3d94c2958dfe70ceab"
-  integrity sha512-Ybn2I6fnfIGuCR+Faaz7YcvtBKxvoLV3Lebn1tM4o/IAJzmi9AWYIPWpyBfU8cC+JxAO57bk4+zdsTjJR+VTOw==
+"@webassemblyjs/wasm-edit@^1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-edit/-/wasm-edit-1.12.1.tgz#9f9f3ff52a14c980939be0ef9d5df9ebc678ae3b"
+  integrity sha512-1DuwbVvADvS5mGnXbE+c9NfA8QRcZ6iKquqjjmR10k6o+zzsRVesil54DKexiowcFCPdr/Q0qaMgB01+SQ1u6g==
   dependencies:
-    "@webassemblyjs/ast" "1.11.6"
-    "@webassemblyjs/helper-buffer" "1.11.6"
+    "@webassemblyjs/ast" "1.12.1"
+    "@webassemblyjs/helper-buffer" "1.12.1"
     "@webassemblyjs/helper-wasm-bytecode" "1.11.6"
-    "@webassemblyjs/helper-wasm-section" "1.11.6"
-    "@webassemblyjs/wasm-gen" "1.11.6"
-    "@webassemblyjs/wasm-opt" "1.11.6"
-    "@webassemblyjs/wasm-parser" "1.11.6"
-    "@webassemblyjs/wast-printer" "1.11.6"
-
-"@webassemblyjs/wasm-gen@1.11.6":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-gen/-/wasm-gen-1.11.6.tgz#fb5283e0e8b4551cc4e9c3c0d7184a65faf7c268"
-  integrity sha512-3XOqkZP/y6B4F0PBAXvI1/bky7GryoogUtfwExeP/v7Nzwo1QLcq5oQmpKlftZLbT+ERUOAZVQjuNVak6UXjPA==
-  dependencies:
-    "@webassemblyjs/ast" "1.11.6"
+    "@webassemblyjs/helper-wasm-section" "1.12.1"
+    "@webassemblyjs/wasm-gen" "1.12.1"
+    "@webassemblyjs/wasm-opt" "1.12.1"
+    "@webassemblyjs/wasm-parser" "1.12.1"
+    "@webassemblyjs/wast-printer" "1.12.1"
+
+"@webassemblyjs/wasm-gen@1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-gen/-/wasm-gen-1.12.1.tgz#a6520601da1b5700448273666a71ad0a45d78547"
+  integrity sha512-TDq4Ojh9fcohAw6OIMXqiIcTq5KUXTGRkVxbSo1hQnSy6lAM5GSdfwWeSxpAo0YzgsgF182E/U0mDNhuA0tW7w==
+  dependencies:
+    "@webassemblyjs/ast" "1.12.1"
     "@webassemblyjs/helper-wasm-bytecode" "1.11.6"
     "@webassemblyjs/ieee754" "1.11.6"
     "@webassemblyjs/leb128" "1.11.6"
     "@webassemblyjs/utf8" "1.11.6"
 
-"@webassemblyjs/wasm-opt@1.11.6":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-opt/-/wasm-opt-1.11.6.tgz#d9a22d651248422ca498b09aa3232a81041487c2"
-  integrity sha512-cOrKuLRE7PCe6AsOVl7WasYf3wbSo4CeOk6PkrjS7g57MFfVUF9u6ysQBBODX0LdgSvQqRiGz3CXvIDKcPNy4g==
+"@webassemblyjs/wasm-opt@1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-opt/-/wasm-opt-1.12.1.tgz#9e6e81475dfcfb62dab574ac2dda38226c232bc5"
+  integrity sha512-Jg99j/2gG2iaz3hijw857AVYekZe2SAskcqlWIZXjji5WStnOpVoat3gQfT/Q5tb2djnCjBtMocY/Su1GfxPBg==
   dependencies:
-    "@webassemblyjs/ast" "1.11.6"
-    "@webassemblyjs/helper-buffer" "1.11.6"
-    "@webassemblyjs/wasm-gen" "1.11.6"
-    "@webassemblyjs/wasm-parser" "1.11.6"
+    "@webassemblyjs/ast" "1.12.1"
+    "@webassemblyjs/helper-buffer" "1.12.1"
+    "@webassemblyjs/wasm-gen" "1.12.1"
+    "@webassemblyjs/wasm-parser" "1.12.1"
 
-"@webassemblyjs/wasm-parser@1.11.6", "@webassemblyjs/wasm-parser@^1.11.5":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-parser/-/wasm-parser-1.11.6.tgz#bb85378c527df824004812bbdb784eea539174a1"
-  integrity sha512-6ZwPeGzMJM3Dqp3hCsLgESxBGtT/OeCvCZ4TA1JUPYgmhAx38tTPR9JaKy0S5H3evQpO/h2uWs2j6Yc/fjkpTQ==
+"@webassemblyjs/wasm-parser@1.12.1", "@webassemblyjs/wasm-parser@^1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/wasm-parser/-/wasm-parser-1.12.1.tgz#c47acb90e6f083391e3fa61d113650eea1e95937"
+  integrity sha512-xikIi7c2FHXysxXe3COrVUPSheuBtpcfhbpFj4gmu7KRLYOzANztwUU0IbsqvMqzuNK2+glRGWCEqZo1WCLyAQ==
   dependencies:
-    "@webassemblyjs/ast" "1.11.6"
+    "@webassemblyjs/ast" "1.12.1"
     "@webassemblyjs/helper-api-error" "1.11.6"
     "@webassemblyjs/helper-wasm-bytecode" "1.11.6"
     "@webassemblyjs/ieee754" "1.11.6"
     "@webassemblyjs/leb128" "1.11.6"
     "@webassemblyjs/utf8" "1.11.6"
 
-"@webassemblyjs/wast-printer@1.11.6":
-  version "1.11.6"
-  resolved "https://registry.yarnpkg.com/@webassemblyjs/wast-printer/-/wast-printer-1.11.6.tgz#a7bf8dd7e362aeb1668ff43f35cb849f188eff20"
-  integrity sha512-JM7AhRcE+yW2GWYaKeHL5vt4xqee5N2WcezptmgyhNS+ScggqcT1OtXykhAb13Sn5Yas0j2uv9tHgrjwvzAP4A==
+"@webassemblyjs/wast-printer@1.12.1":
+  version "1.12.1"
+  resolved "https://registry.yarnpkg.com/@webassemblyjs/wast-printer/-/wast-printer-1.12.1.tgz#bcecf661d7d1abdaf989d8341a4833e33e2b31ac"
+  integrity sha512-+X4WAlOisVWQMikjbcvY2e0rwPsKQ9F688lksZhBcPycBBuii3O7m8FACbDMWDojpAqvjIncrG8J0XHKyQfVeA==
   dependencies:
-    "@webassemblyjs/ast" "1.11.6"
+    "@webassemblyjs/ast" "1.12.1"
     "@xtuc/long" "4.2.2"
 
-"@webpack-cli/configtest@^2.1.0":
+"@webpack-cli/configtest@^2.1.1":
   version "2.1.1"
   resolved "https://registry.yarnpkg.com/@webpack-cli/configtest/-/configtest-2.1.1.tgz#3b2f852e91dac6e3b85fb2a314fb8bef46d94646"
   integrity sha512-wy0mglZpDSiSS0XHrVR+BAdId2+yxPSoJW8fsna3ZpYSlufjvxnP4YbKTCBZnNIcGN4r6ZPXV55X4mYExOfLmw==
 
-"@webpack-cli/info@^2.0.1":
+"@webpack-cli/info@^2.0.2":
   version "2.0.2"
   resolved "https://registry.yarnpkg.com/@webpack-cli/info/-/info-2.0.2.tgz#cc3fbf22efeb88ff62310cf885c5b09f44ae0fdd"
   integrity sha512-zLHQdI/Qs1UyT5UBdWNqsARasIA+AaF8t+4u2aS2nEpBQh2mWIVb8qAklq0eUENnC5mOItrIB4LiS9xMtph18A==
 
-"@webpack-cli/serve@^2.0.3":
+"@webpack-cli/serve@^2.0.5":
   version "2.0.5"
   resolved "https://registry.yarnpkg.com/@webpack-cli/serve/-/serve-2.0.5.tgz#325db42395cd49fe6c14057f9a900e427df8810e"
   integrity sha512-lqaoKnRYBdo1UgDX8uF24AfGMifWK19TxPmM5FHc2vAGxrJ/qtyUyFBWoY1tISZdelsQ5fBcOusifo5o5wSJxQ==
@@ -256,11 +258,6 @@
   resolved "https://registry.yarnpkg.com/@xtuc/long/-/long-4.2.2.tgz#d291c6a4e97989b5c61d9acf396ae4fe133a718d"
   integrity sha512-NuHqBY1PB/D8xU6s/thBgOAiAP7HOYDQ32+BFZILJ8ivkUkAHQnWfn6WhL79Owj1qmUnoN/YPhktdIoucipkAQ==
 
-abab@^2.0.6:
-  version "2.0.6"
-  resolved "https://registry.yarnpkg.com/abab/-/abab-2.0.6.tgz#41b80f2c871d19686216b82309231cfd3cb3d291"
-  integrity sha512-j2afSsaIENvHZN2B8GOpF566vZ5WVk5opAiMTvWgaQT8DkbOqsTfvNAvHoRGU2zzP8cPoqys+xHTRDWW8L+/BA==
-
 accepts@~1.3.4:
   version "1.3.8"
   resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz#0bf0be125b67014adcb0b0921e62db7bffe16b2e"
@@ -269,10 +266,10 @@ accepts@~1.3.4:
     mime-types "~2.1.34"
     negotiator "0.6.3"
 
-acorn-import-assertions@^1.7.6:
-  version "1.9.0"
-  resolved "https://registry.yarnpkg.com/acorn-import-assertions/-/acorn-import-assertions-1.9.0.tgz#507276249d684797c84e0734ef84860334cfb1ac"
-  integrity sha512-cmMwop9x+8KFhxvKrKfPYmN6/pKTYYHBqLa0DfvVZcKMJWNyWLnaqND7dx/qn66R7ewM1UX5XMaDVP5wlVTaVA==
+acorn-import-attributes@^1.9.5:
+  version "1.9.5"
+  resolved "https://registry.yarnpkg.com/acorn-import-attributes/-/acorn-import-attributes-1.9.5.tgz#7eb1557b1ba05ef18b5ed0ec67591bfab04688ef"
+  integrity sha512-n02Vykv5uA3eHGM/Z2dQrcD56kL8TyDb2p1+0P83PClMnC/nc+anbQRhIOWnSq4Ke/KvDPrY3C9hDtC/A3eHnQ==
 
 acorn@^8.7.1, acorn@^8.8.2:
   version "8.10.0"
@@ -294,10 +291,10 @@ ajv@^6.12.5:
     json-schema-traverse "^0.4.1"
     uri-js "^4.2.2"
 
-ansi-colors@4.1.1:
-  version "4.1.1"
-  resolved "https://registry.yarnpkg.com/ansi-colors/-/ansi-colors-4.1.1.tgz#cbb9ae256bf750af1eab344f229aa27fe94ba348"
-  integrity sha512-JoX0apGbHaUJBNl6yF+p6JAFYZ666/hhCGKN5t9QFjbJQKUU/g8MNbFDbvfrgKXvI1QpZplPOnwIo99lX/AAmA==
+ansi-colors@^4.1.3:
+  version "4.1.3"
+  resolved "https://registry.yarnpkg.com/ansi-colors/-/ansi-colors-4.1.3.tgz#37611340eb2243e70cc604cad35d63270d48781b"
+  integrity sha512-/6w/C21Pm1A7aZitlI5Ni/2J6FFQN8i1Cvz3kHABAAbw93v/NlvKdVOqz7CCWz/3iv/JplRSEEZ83XION15ovw==
 
 ansi-regex@^5.0.1:
   version "5.0.1"
@@ -379,20 +376,20 @@ braces@^3.0.2, braces@~3.0.2:
   dependencies:
     fill-range "^7.0.1"
 
-browser-stdout@1.3.1:
+browser-stdout@^1.3.1:
   version "1.3.1"
   resolved "https://registry.yarnpkg.com/browser-stdout/-/browser-stdout-1.3.1.tgz#baa559ee14ced73452229bad7326467c61fabd60"
   integrity sha512-qhAVI1+Av2X7qelOfAIYwXONood6XlZE/fXaBSmW/T5SzLAmCgzi+eiWE7fUvbHaeNBQH13UftjpXxsfLkMpgw==
 
-browserslist@^4.14.5:
-  version "4.21.9"
-  resolved "https://registry.yarnpkg.com/browserslist/-/browserslist-4.21.9.tgz#e11bdd3c313d7e2a9e87e8b4b0c7872b13897635"
-  integrity sha512-M0MFoZzbUrRU4KNfCrDLnvyE7gub+peetoTid3TBIqtunaDJyXlwhakT+/VkvSXcfIzFfK/nkCs4nmyTmxdNSg==
+browserslist@^4.21.10:
+  version "4.24.0"
+  resolved "https://registry.yarnpkg.com/browserslist/-/browserslist-4.24.0.tgz#a1325fe4bc80b64fda169629fc01b3d6cecd38d4"
+  integrity sha512-Rmb62sR1Zpjql25eSanFGEhAxcFwfA1K0GuQcLoaJBAcENegrQut3hYdhXFF1obQfiDyqIW/cLM5HSJ/9k884A==
   dependencies:
-    caniuse-lite "^1.0.30001503"
-    electron-to-chromium "^1.4.431"
-    node-releases "^2.0.12"
-    update-browserslist-db "^1.0.11"
+    caniuse-lite "^1.0.30001663"
+    electron-to-chromium "^1.5.28"
+    node-releases "^2.0.18"
+    update-browserslist-db "^1.1.0"
 
 buffer-from@^1.0.0:
   version "1.1.2"
@@ -417,10 +414,10 @@ camelcase@^6.0.0:
   resolved "https://registry.yarnpkg.com/camelcase/-/camelcase-6.3.0.tgz#5685b95eb209ac9c0c177467778c9c84df58ba9a"
   integrity sha512-Gmy6FhYlCY7uOElZUSbxo2UCDH8owEk996gkbrpsgGtrJLM3J7jGxl9Ic7Qwwj4ivOE5AWZWRMecDdF7hqGjFA==
 
-caniuse-lite@^1.0.30001503:
-  version "1.0.30001513"
-  resolved "https://registry.yarnpkg.com/caniuse-lite/-/caniuse-lite-1.0.30001513.tgz#382fe5fbfb0f7abbaf8c55ca3ac71a0307a752e9"
-  integrity sha512-pnjGJo7SOOjAGytZZ203Em95MRM8Cr6jhCXNF/FAXTpCTRTECnqQWLpiTRqrFtdYcth8hf4WECUpkezuYsMVww==
+caniuse-lite@^1.0.30001663:
+  version "1.0.30001669"
+  resolved "https://registry.yarnpkg.com/caniuse-lite/-/caniuse-lite-1.0.30001669.tgz#fda8f1d29a8bfdc42de0c170d7f34a9cf19ed7a3"
+  integrity sha512-DlWzFDJqstqtIVx1zeSpIMLjunf5SmwOw0N2Ck/QSQdS8PLS4+9HrLaYei4w8BIAL7IB/UEDu889d8vhCTPA0w==
 
 chalk@^4.1.0:
   version "4.1.2"
@@ -430,7 +427,7 @@ chalk@^4.1.0:
     ansi-styles "^4.1.0"
     supports-color "^7.1.0"
 
-chokidar@3.5.3, chokidar@^3.5.1:
+chokidar@^3.5.1:
   version "3.5.3"
   resolved "https://registry.yarnpkg.com/chokidar/-/chokidar-3.5.3.tgz#1cf37c8707b932bd1af1ae22c0432e2acd1903bd"
   integrity sha512-Dr3sfKRP6oTcjf2JmUmFJfeVMvXBdegxB0iVQ5eb2V10uFJUCAS8OByZdVAyVb8xXNz3GjjTgj9kLWsZTqE6kw==
@@ -445,6 +442,21 @@ chokidar@3.5.3, chokidar@^3.5.1:
   optionalDependencies:
     fsevents "~2.3.2"
 
+chokidar@^3.5.3:
+  version "3.6.0"
+  resolved "https://registry.yarnpkg.com/chokidar/-/chokidar-3.6.0.tgz#197c6cc669ef2a8dc5e7b4d97ee4e092c3eb0d5b"
+  integrity sha512-7VT13fmjotKpGipCW9JEQAusEPE+Ei8nl6/g4FBAmIm0GOOLMua9NDDo/DWp0ZAxCr3cPq5ZpBqmPAQgDda2Pw==
+  dependencies:
+    anymatch "~3.1.2"
+    braces "~3.0.2"
+    glob-parent "~5.1.2"
+    is-binary-path "~2.1.0"
+    is-glob "~4.0.1"
+    normalize-path "~3.0.0"
+    readdirp "~3.6.0"
+  optionalDependencies:
+    fsevents "~2.3.2"
+
 chrome-trace-event@^1.0.2:
   version "1.0.3"
   resolved "https://registry.yarnpkg.com/chrome-trace-event/-/chrome-trace-event-1.0.3.tgz#1015eced4741e15d06664a957dbbf50d041e26ac"
@@ -515,10 +527,10 @@ content-type@~1.0.5:
   resolved "https://registry.yarnpkg.com/content-type/-/content-type-1.0.5.tgz#8b773162656d1d1086784c8f23a54ce6d73d7918"
   integrity sha512-nTjqfcBFEipKdXCv4YDQWCfmcLZKm81ldF0pAopTvyrFGVbcR6P/VAAd5G7N+0tTr8QqiU0tFadD6FK4NtJwOA==
 
-cookie@~0.4.1:
-  version "0.4.2"
-  resolved "https://registry.yarnpkg.com/cookie/-/cookie-0.4.2.tgz#0e41f24de5ecf317947c82fc789e06a884824432"
-  integrity sha512-aSWTXFzaKWkvHO1Ny/s+ePFpvKsPnjc551iI41v3ny/ow6tBG5Vd+FuqGNhh1LxOmVzOlGUriIlOaokOvhaStA==
+cookie@~0.7.2:
+  version "0.7.2"
+  resolved "https://registry.yarnpkg.com/cookie/-/cookie-0.7.2.tgz#556369c472a2ba910f2979891b526b3436237ed7"
+  integrity sha512-yki5XnKuf750l50uGTllt6kKILY4nQ1eNIQatoXEByZ5dWgnKqbnqmTrBE5B4N7lrMJKQ2ytWMiTO2o0v6Ew/w==
 
 cors@~2.8.5:
   version "2.8.5"
@@ -554,13 +566,20 @@ debug@2.6.9:
   dependencies:
     ms "2.0.0"
 
-debug@4.3.4, debug@^4.3.4, debug@~4.3.1, debug@~4.3.2:
+debug@^4.3.4, debug@~4.3.1, debug@~4.3.2:
   version "4.3.4"
   resolved "https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz#1319f6579357f2338d3337d2cdd4914bb5dcc865"
   integrity sha512-PRWFHuSU3eDtQJPvnNY7Jcket1j0t5OuOsFzPPzsekD52Zl8qUfFIPEiswXqIvHWGVHOgX+7G/vCNNhehwxfkQ==
   dependencies:
     ms "2.1.2"
 
+debug@^4.3.5:
+  version "4.3.7"
+  resolved "https://registry.yarnpkg.com/debug/-/debug-4.3.7.tgz#87945b4151a011d76d95a198d7111c865c360a52"
+  integrity sha512-Er2nc/H7RrMXZBFCEim6TCmMk02Z8vLC2Rbi1KEBggpo0fS6l0S1nnapwmIi3yW/+GOJap1Krg4w0Hg80oCqgQ==
+  dependencies:
+    ms "^2.1.3"
+
 decamelize@^4.0.0:
   version "4.0.0"
   resolved "https://registry.yarnpkg.com/decamelize/-/decamelize-4.0.0.tgz#aa472d7bf660eb15f3494efd531cab7f2a709837"
@@ -581,10 +600,10 @@ di@^0.0.1:
   resolved "https://registry.yarnpkg.com/di/-/di-0.0.1.tgz#806649326ceaa7caa3306d75d985ea2748ba913c"
   integrity sha512-uJaamHkagcZtHPqCIHZxnFrXlunQXgBOsZSUOWwFw31QJCAbyTBoHMW75YOTur5ZNx8pIeAKgf6GWIgaqqiLhA==
 
-diff@5.0.0:
-  version "5.0.0"
-  resolved "https://registry.yarnpkg.com/diff/-/diff-5.0.0.tgz#7ed6ad76d859d030787ec35855f5b1daf31d852b"
-  integrity sha512-/VTCrvm5Z0JGty/BWHljh+BAiw3IK+2j87NGMu8Nwc/f48WoDAC395uomO9ZD117ZOBaHmkX1oyLvkVM/aIT3w==
+diff@^5.2.0:
+  version "5.2.0"
+  resolved "https://registry.yarnpkg.com/diff/-/diff-5.2.0.tgz#26ded047cd1179b78b9537d5ef725503ce1ae531"
+  integrity sha512-uIFDxqpRZGZ6ThOk84hEfqWoHx2devRFvpTZcTHur85vImfaxUbTW9Ryh4CpCuDnToOP1CEtXKIgytHBPVff5A==
 
 dom-serialize@^2.2.1:
   version "2.2.1"
@@ -601,10 +620,10 @@ ee-first@1.1.1:
   resolved "https://registry.yarnpkg.com/ee-first/-/ee-first-1.1.1.tgz#590c61156b0ae2f4f0255732a158b266bc56b21d"
   integrity sha512-WMwm9LhRUo+WUaRN+vRuETqG89IgZphVSNkdFgeb6sS/E4OrDIN7t48CAewSHXc6C8lefD8KKfr5vY61brQlow==
 
-electron-to-chromium@^1.4.431:
-  version "1.4.454"
-  resolved "https://registry.yarnpkg.com/electron-to-chromium/-/electron-to-chromium-1.4.454.tgz#774dc7cb5e58576d0125939ec34a4182f3ccc87d"
-  integrity sha512-pmf1rbAStw8UEQ0sr2cdJtWl48ZMuPD9Sto8HVQOq9vx9j2WgDEN6lYoaqFvqEHYOmGA9oRGn7LqWI9ta0YugQ==
+electron-to-chromium@^1.5.28:
+  version "1.5.40"
+  resolved "https://registry.yarnpkg.com/electron-to-chromium/-/electron-to-chromium-1.5.40.tgz#5f6aec13751123c5c3185999ebe3e7bcaf828c2b"
+  integrity sha512-LYm78o6if4zTasnYclgQzxEcgMoIcybWOhkATWepN95uwVVWV0/IW10v+2sIeHE+bIYWipLneTftVyQm45UY7g==
 
 emoji-regex@^8.0.0:
   version "8.0.0"
@@ -616,31 +635,31 @@ encodeurl@~1.0.2:
   resolved "https://registry.yarnpkg.com/encodeurl/-/encodeurl-1.0.2.tgz#ad3ff4c86ec2d029322f5a02c3a9a606c95b3f59"
   integrity sha512-TPJXq8JqFaVYm2CWmPvnP2Iyo4ZSM7/QKcSmuMLDObfpH5fi7RUGmd/rTDf+rut/saiDiQEeVTNgAmJEdAOx0w==
 
-engine.io-parser@~5.1.0:
-  version "5.1.0"
-  resolved "https://registry.yarnpkg.com/engine.io-parser/-/engine.io-parser-5.1.0.tgz#d593d6372d7f79212df48f807b8cace1ea1cb1b8"
-  integrity sha512-enySgNiK5tyZFynt3z7iqBR+Bto9EVVVvDFuTT0ioHCGbzirZVGDGiQjZzEp8hWl6hd5FSVytJGuScX1C1C35w==
+engine.io-parser@~5.2.1:
+  version "5.2.3"
+  resolved "https://registry.yarnpkg.com/engine.io-parser/-/engine.io-parser-5.2.3.tgz#00dc5b97b1f233a23c9398d0209504cf5f94d92f"
+  integrity sha512-HqD3yTBfnBxIrbnM1DoD6Pcq8NECnh8d4As1Qgh0z5Gg3jRRIqijury0CL3ghu/edArpUYiYqQiDUQBIs4np3Q==
 
-engine.io@~6.5.0:
-  version "6.5.1"
-  resolved "https://registry.yarnpkg.com/engine.io/-/engine.io-6.5.1.tgz#59725f8593ccc891abb47f1efcdc52a089525a56"
-  integrity sha512-mGqhI+D7YxS9KJMppR6Iuo37Ed3abhU8NdfgSvJSDUafQutrN+sPTncJYTyM9+tkhSmWodKtVYGPPHyXJEwEQA==
+engine.io@~6.6.0:
+  version "6.6.2"
+  resolved "https://registry.yarnpkg.com/engine.io/-/engine.io-6.6.2.tgz#32bd845b4db708f8c774a4edef4e5c8a98b3da72"
+  integrity sha512-gmNvsYi9C8iErnZdVcJnvCpSKbWTt1E8+JZo8b+daLninywUWi5NQ5STSHZ9rFjFO7imNcvb8Pc5pe/wMR5xEw==
   dependencies:
     "@types/cookie" "^0.4.1"
     "@types/cors" "^2.8.12"
     "@types/node" ">=10.0.0"
     accepts "~1.3.4"
     base64id "2.0.0"
-    cookie "~0.4.1"
+    cookie "~0.7.2"
     cors "~2.8.5"
     debug "~4.3.1"
-    engine.io-parser "~5.1.0"
-    ws "~8.11.0"
+    engine.io-parser "~5.2.1"
+    ws "~8.17.1"
 
-enhanced-resolve@^5.13.0:
-  version "5.15.0"
-  resolved "https://registry.yarnpkg.com/enhanced-resolve/-/enhanced-resolve-5.15.0.tgz#1af946c7d93603eb88e9896cee4904dc012e9c35"
-  integrity sha512-LXYT42KJ7lpIKECr2mAXIaMldcNCh/7E0KBKOu4KSfkHmP+mZmSs+8V5gBAqisWBy0OO4W5Oyys0GO1Y8KtdKg==
+enhanced-resolve@^5.17.1:
+  version "5.17.1"
+  resolved "https://registry.yarnpkg.com/enhanced-resolve/-/enhanced-resolve-5.17.1.tgz#67bfbbcc2f81d511be77d686a90267ef7f898a15"
+  integrity sha512-LMHl3dXhTcfv8gM4kEzIUeTQ+7fpdA0l2tUf34BddXPkz2A5xJ5L/Pchd5BL6rdccM9QGvu0sWZzK1Z1t4wwyg==
   dependencies:
     graceful-fs "^4.2.4"
     tapable "^2.2.0"
@@ -665,12 +684,17 @@ escalade@^3.1.1:
   resolved "https://registry.yarnpkg.com/escalade/-/escalade-3.1.1.tgz#d8cfdc7000965c5a0174b4a82eaa5c0552742e40"
   integrity sha512-k0er2gUkLf8O0zKJiAhmkTnJlTvINGv7ygDNPbeIsX/TJjGJZHuh9B2UxbsaEkmlEo9MfhrSzmhIlhRlI2GXnw==
 
+escalade@^3.2.0:
+  version "3.2.0"
+  resolved "https://registry.yarnpkg.com/escalade/-/escalade-3.2.0.tgz#011a3f69856ba189dffa7dc8fcce99d2a87903e5"
+  integrity sha512-WUj2qlxaQtO4g6Pq5c29GTcWGDyd8itL8zTlipgECz3JesAiiOKotd8JU6otB3PACgG6xkJUyVhboMS+bje/jA==
+
 escape-html@~1.0.3:
   version "1.0.3"
   resolved "https://registry.yarnpkg.com/escape-html/-/escape-html-1.0.3.tgz#0258eae4d3d0c0974de1c169188ef0051d1d1988"
   integrity sha512-NiSupZ4OeuGwr68lGIeym/ksIZMJodUGOSCZ/FSnTxcrekbvqrgdUxlJOMpijaKZVjAJrWrGs/6Jy8OMuyj9ow==
 
-escape-string-regexp@4.0.0:
+escape-string-regexp@^4.0.0:
   version "4.0.0"
   resolved "https://registry.yarnpkg.com/escape-string-regexp/-/escape-string-regexp-4.0.0.tgz#14ba83a5d373e3d311e5afca29cf5bfad965bf34"
   integrity sha512-TtpcNJ3XAzx3Gq8sWRzJaVajRs0uVxA2YAkdb1jm2YkPz4G6egUFAyA3n5vtEIZefPk5Wa4UXbKuS5fKkJWdgA==
@@ -750,14 +774,6 @@ finalhandler@1.1.2:
     statuses "~1.5.0"
     unpipe "~1.0.0"
 
-find-up@5.0.0:
-  version "5.0.0"
-  resolved "https://registry.yarnpkg.com/find-up/-/find-up-5.0.0.tgz#4c92819ecb7083561e4f4a240a86be5198f536fc"
-  integrity sha512-78/PXT1wlLLDgTzDs7sjq9hzz0vXD+zn+7wypEe4fXQxCmdmqfGsEPQxmiCSQI3ajFV91bVSsvNtrJRiW6nGng==
-  dependencies:
-    locate-path "^6.0.0"
-    path-exists "^4.0.0"
-
 find-up@^4.0.0:
   version "4.1.0"
   resolved "https://registry.yarnpkg.com/find-up/-/find-up-4.1.0.tgz#97afe7d6cdc0bc5928584b7c8d7b16e8a9aa5d19"
@@ -766,6 +782,14 @@ find-up@^4.0.0:
     locate-path "^5.0.0"
     path-exists "^4.0.0"
 
+find-up@^5.0.0:
+  version "5.0.0"
+  resolved "https://registry.yarnpkg.com/find-up/-/find-up-5.0.0.tgz#4c92819ecb7083561e4f4a240a86be5198f536fc"
+  integrity sha512-78/PXT1wlLLDgTzDs7sjq9hzz0vXD+zn+7wypEe4fXQxCmdmqfGsEPQxmiCSQI3ajFV91bVSsvNtrJRiW6nGng==
+  dependencies:
+    locate-path "^6.0.0"
+    path-exists "^4.0.0"
+
 flat@^5.0.2:
   version "5.0.2"
   resolved "https://registry.yarnpkg.com/flat/-/flat-5.0.2.tgz#8ca6fe332069ffa9d324c327198c598259ceb241"
@@ -837,31 +861,30 @@ glob-to-regexp@^0.4.1:
   resolved "https://registry.yarnpkg.com/glob-to-regexp/-/glob-to-regexp-0.4.1.tgz#c75297087c851b9a578bd217dd59a92f59fe546e"
   integrity sha512-lkX1HJXwyMcprw/5YUZc2s7DrpAiHB21/V+E1rHUrVNokkvB6bqMzT0VfV6/86ZNabt1k14YOIaT7nDvOX3Iiw==
 
-glob@7.2.0:
-  version "7.2.0"
-  resolved "https://registry.yarnpkg.com/glob/-/glob-7.2.0.tgz#d15535af7732e02e948f4c41628bd910293f6023"
-  integrity sha512-lmLf6gtyrPq8tTjSmrO94wBeQbFR3HbLHbuyD69wuyQkImp2hWqMGB47OX65FBkPffO641IP9jWa1z4ivqG26Q==
+glob@^7.1.3, glob@^7.1.7:
+  version "7.2.3"
+  resolved "https://registry.yarnpkg.com/glob/-/glob-7.2.3.tgz#b8df0fb802bbfa8e89bd1d938b4e16578ed44f2b"
+  integrity sha512-nFR0zLpU2YCaRxwoCJvL6UvCH2JFyFVIvwTLsIf21AuHlMskA1hhTdk+LlYJtOlYt9v6dvszD2BGRqBL+iQK9Q==
   dependencies:
     fs.realpath "^1.0.0"
     inflight "^1.0.4"
     inherits "2"
-    minimatch "^3.0.4"
+    minimatch "^3.1.1"
     once "^1.3.0"
     path-is-absolute "^1.0.0"
 
-glob@^7.1.3, glob@^7.1.7:
-  version "7.2.3"
-  resolved "https://registry.yarnpkg.com/glob/-/glob-7.2.3.tgz#b8df0fb802bbfa8e89bd1d938b4e16578ed44f2b"
-  integrity sha512-nFR0zLpU2YCaRxwoCJvL6UvCH2JFyFVIvwTLsIf21AuHlMskA1hhTdk+LlYJtOlYt9v6dvszD2BGRqBL+iQK9Q==
+glob@^8.1.0:
+  version "8.1.0"
+  resolved "https://registry.yarnpkg.com/glob/-/glob-8.1.0.tgz#d388f656593ef708ee3e34640fdfb99a9fd1c33e"
+  integrity sha512-r8hpEjiQEYlF2QU0df3dS+nxxSIreXQS1qRhMJM0Q5NDdR386C7jb7Hwwod8Fgiuex+k0GFjgft18yvxm5XoCQ==
   dependencies:
     fs.realpath "^1.0.0"
     inflight "^1.0.4"
     inherits "2"
-    minimatch "^3.1.1"
+    minimatch "^5.0.1"
     once "^1.3.0"
-    path-is-absolute "^1.0.0"
 
-graceful-fs@^4.1.2, graceful-fs@^4.1.6, graceful-fs@^4.2.0, graceful-fs@^4.2.10, graceful-fs@^4.2.4, graceful-fs@^4.2.6, graceful-fs@^4.2.9:
+graceful-fs@^4.1.2, graceful-fs@^4.1.6, graceful-fs@^4.2.0, graceful-fs@^4.2.10, graceful-fs@^4.2.11, graceful-fs@^4.2.4, graceful-fs@^4.2.6:
   version "4.2.11"
   resolved "https://registry.yarnpkg.com/graceful-fs/-/graceful-fs-4.2.11.tgz#4183e4e8bf08bb6e05bbb2f7d2e0c8f712ca40e3"
   integrity sha512-RbJ5/jmFcNNCcDV5o9eTnBLJ/HszWV0P73bc+Ff4nS/rJj+YaS6IGyiOL0VoBYX+l1Wrl3k63h/KrH+nhJ0XvQ==
@@ -888,7 +911,7 @@ has@^1.0.3:
   dependencies:
     function-bind "^1.1.1"
 
-he@1.2.0:
+he@^1.2.0:
   version "1.2.0"
   resolved "https://registry.yarnpkg.com/he/-/he-1.2.0.tgz#84ae65fa7eafb165fddb61566ae14baf05664f0f"
   integrity sha512-F/1DnUGPopORZi0ni+CvrCgHQ5FyEAHRLSApuYWMmrbSwoN2Mn/7k+Gl38gJnR7yyDZk6WLXwiGod1JOWNDKGw==
@@ -1030,7 +1053,7 @@ jest-worker@^27.4.5:
     merge-stream "^2.0.0"
     supports-color "^8.0.0"
 
-js-yaml@4.1.0:
+js-yaml@^4.1.0:
   version "4.1.0"
   resolved "https://registry.yarnpkg.com/js-yaml/-/js-yaml-4.1.0.tgz#c1fb65f8f5017901cdd2c951864ba18458a10602"
   integrity sha512-wpxZs9NoxZaJESJGIZTyDEaYpl0FKSA+FB9aJiyemKhMwkxQg63h4T1KJgUGHpTqPDNRcmmYLugrRjJlBtWvRA==
@@ -1075,19 +1098,19 @@ karma-sourcemap-loader@0.4.0:
   dependencies:
     graceful-fs "^4.2.10"
 
-karma-webpack@5.0.0:
-  version "5.0.0"
-  resolved "https://registry.yarnpkg.com/karma-webpack/-/karma-webpack-5.0.0.tgz#2a2c7b80163fe7ffd1010f83f5507f95ef39f840"
-  integrity sha512-+54i/cd3/piZuP3dr54+NcFeKOPnys5QeM1IY+0SPASwrtHsliXUiCL50iW+K9WWA7RvamC4macvvQ86l3KtaA==
+karma-webpack@5.0.1:
+  version "5.0.1"
+  resolved "https://registry.yarnpkg.com/karma-webpack/-/karma-webpack-5.0.1.tgz#4eafd31bbe684a747a6e8f3e4ad373e53979ced4"
+  integrity sha512-oo38O+P3W2mSPCSUrQdySSPv1LvPpXP+f+bBimNomS5sW+1V4SuhCuW8TfJzV+rDv921w2fDSDw0xJbPe6U+kQ==
   dependencies:
     glob "^7.1.3"
-    minimatch "^3.0.4"
+    minimatch "^9.0.3"
     webpack-merge "^4.1.5"
 
-karma@6.4.2:
-  version "6.4.2"
-  resolved "https://registry.yarnpkg.com/karma/-/karma-6.4.2.tgz#a983f874cee6f35990c4b2dcc3d274653714de8e"
-  integrity sha512-C6SU/53LB31BEgRg+omznBEMY4SjHU3ricV6zBcAe1EeILKkeScr+fZXtaI5WyDbkVowJxxAI6h73NcFPmXolQ==
+karma@6.4.4:
+  version "6.4.4"
+  resolved "https://registry.yarnpkg.com/karma/-/karma-6.4.4.tgz#dfa5a426cf5a8b53b43cd54ef0d0d09742351492"
+  integrity sha512-LrtUxbdvt1gOpo3gxG+VAJlJAEMhbWlM4YrFQgql98FwF7+K8K12LYO4hnDdUkNjeztYrOXEMqgTajSWgmtI/w==
   dependencies:
     "@colors/colors" "1.5.0"
     body-parser "^1.19.0"
@@ -1108,7 +1131,7 @@ karma@6.4.2:
     qjobs "^1.2.0"
     range-parser "^1.2.1"
     rimraf "^3.0.2"
-    socket.io "^4.4.1"
+    socket.io "^4.7.2"
     source-map "^0.6.1"
     tmp "^0.2.1"
     ua-parser-js "^0.7.30"
@@ -1119,6 +1142,13 @@ kind-of@^6.0.2:
   resolved "https://registry.yarnpkg.com/kind-of/-/kind-of-6.0.3.tgz#07c05034a6c349fa06e24fa35aa76db4580ce4dd"
   integrity sha512-dcS1ul+9tmeD95T+x28/ehLgd9mENa3LsvDTtzm3vyBEO7RPptvAD+t44WVXaUjTBRcrpFeFlC8WCruUR456hw==
 
+kotlin-web-helpers@2.0.0:
+  version "2.0.0"
+  resolved "https://registry.yarnpkg.com/kotlin-web-helpers/-/kotlin-web-helpers-2.0.0.tgz#b112096b273c1e733e0b86560998235c09a19286"
+  integrity sha512-xkVGl60Ygn/zuLkDPx+oHj7jeLR7hCvoNF99nhwXMn8a3ApB4lLiC9pk4ol4NHPjyoCbvQctBqvzUcp8pkqyWw==
+  dependencies:
+    format-util "^1.0.5"
+
 loader-runner@^4.2.0:
   version "4.3.0"
   resolved "https://registry.yarnpkg.com/loader-runner/-/loader-runner-4.3.0.tgz#c1b4a163b99f614830353b16755e7149ac2314e1"
@@ -1143,7 +1173,7 @@ lodash@^4.17.15, lodash@^4.17.21:
   resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"
   integrity sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==
 
-log-symbols@4.1.0:
+log-symbols@^4.1.0:
   version "4.1.0"
   resolved "https://registry.yarnpkg.com/log-symbols/-/log-symbols-4.1.0.tgz#3fbdbb95b4683ac9fc785111e792e558d4abd503"
   integrity sha512-8XPvpAA8uyhfteu8pIvQxpJZ7SYYdpUivZpGy6sFsBuKRY/7rQGavedeB8aK+Zkyq6upMFVL/9AW6vOYzfRyLg==
@@ -1189,13 +1219,6 @@ mime@^2.5.2:
   resolved "https://registry.yarnpkg.com/mime/-/mime-2.6.0.tgz#a2a682a95cd4d0cb1d6257e28f83da7e35800367"
   integrity sha512-USPkMeET31rOMiarsBNIHZKLGgvKc/LrjofAnBlOttf5ajRvqiRA8QsenbcooctK6d6Ts6aqZXBA+XbkKthiQg==
 
-minimatch@5.0.1:
-  version "5.0.1"
-  resolved "https://registry.yarnpkg.com/minimatch/-/minimatch-5.0.1.tgz#fb9022f7528125187c92bd9e9b6366be1cf3415b"
-  integrity sha512-nLDxIFRyhDblz3qMuq+SoRZED4+miJ/G+tdDrjkkkRnjAsBexeGpgjLEQ0blJy7rHhR2b93rhQY4SvyWu9v03g==
-  dependencies:
-    brace-expansion "^2.0.1"
-
 minimatch@^3.0.4, minimatch@^3.1.1:
   version "3.1.2"
   resolved "https://registry.yarnpkg.com/minimatch/-/minimatch-3.1.2.tgz#19cd194bfd3e428f049a70817c038d89ab4be35b"
@@ -1203,6 +1226,20 @@ minimatch@^3.0.4, minimatch@^3.1.1:
   dependencies:
     brace-expansion "^1.1.7"
 
+minimatch@^5.0.1, minimatch@^5.1.6:
+  version "5.1.6"
+  resolved "https://registry.yarnpkg.com/minimatch/-/minimatch-5.1.6.tgz#1cfcb8cf5522ea69952cd2af95ae09477f122a96"
+  integrity sha512-lKwV/1brpG6mBUFHtb7NUmtABCb2WZZmm2wNiOA5hAb8VdCS4B3dtMWyvcoViccwAW/COERjXLt0zP1zXUN26g==
+  dependencies:
+    brace-expansion "^2.0.1"
+
+minimatch@^9.0.3:
+  version "9.0.5"
+  resolved "https://registry.yarnpkg.com/minimatch/-/minimatch-9.0.5.tgz#d74f9dd6b57d83d8e98cfb82133b03978bc929e5"
+  integrity sha512-G6T0ZX48xgozx7587koeX9Ys2NYy6Gmv//P89sEte9V9whIapMNF4idKxnW2QtCcLiTWlb/wfCabAtAFWhhBow==
+  dependencies:
+    brace-expansion "^2.0.1"
+
 minimist@^1.2.3, minimist@^1.2.6:
   version "1.2.8"
   resolved "https://registry.yarnpkg.com/minimist/-/minimist-1.2.8.tgz#c1a464e7693302e082a075cee0c057741ac4772c"
@@ -1215,32 +1252,31 @@ mkdirp@^0.5.5:
   dependencies:
     minimist "^1.2.6"
 
-mocha@10.2.0:
-  version "10.2.0"
-  resolved "https://registry.yarnpkg.com/mocha/-/mocha-10.2.0.tgz#1fd4a7c32ba5ac372e03a17eef435bd00e5c68b8"
-  integrity sha512-IDY7fl/BecMwFHzoqF2sg/SHHANeBoMMXFlS9r0OXKDssYE1M5O43wUY/9BVPeIvfH2zmEbBfseqN9gBQZzXkg==
-  dependencies:
-    ansi-colors "4.1.1"
-    browser-stdout "1.3.1"
-    chokidar "3.5.3"
-    debug "4.3.4"
-    diff "5.0.0"
-    escape-string-regexp "4.0.0"
-    find-up "5.0.0"
-    glob "7.2.0"
-    he "1.2.0"
-    js-yaml "4.1.0"
-    log-symbols "4.1.0"
-    minimatch "5.0.1"
-    ms "2.1.3"
-    nanoid "3.3.3"
-    serialize-javascript "6.0.0"
-    strip-json-comments "3.1.1"
-    supports-color "8.1.1"
-    workerpool "6.2.1"
-    yargs "16.2.0"
-    yargs-parser "20.2.4"
-    yargs-unparser "2.0.0"
+mocha@10.7.3:
+  version "10.7.3"
+  resolved "https://registry.yarnpkg.com/mocha/-/mocha-10.7.3.tgz#ae32003cabbd52b59aece17846056a68eb4b0752"
+  integrity sha512-uQWxAu44wwiACGqjbPYmjo7Lg8sFrS3dQe7PP2FQI+woptP4vZXSMcfMyFL/e1yFEeEpV4RtyTpZROOKmxis+A==
+  dependencies:
+    ansi-colors "^4.1.3"
+    browser-stdout "^1.3.1"
+    chokidar "^3.5.3"
+    debug "^4.3.5"
+    diff "^5.2.0"
+    escape-string-regexp "^4.0.0"
+    find-up "^5.0.0"
+    glob "^8.1.0"
+    he "^1.2.0"
+    js-yaml "^4.1.0"
+    log-symbols "^4.1.0"
+    minimatch "^5.1.6"
+    ms "^2.1.3"
+    serialize-javascript "^6.0.2"
+    strip-json-comments "^3.1.1"
+    supports-color "^8.1.1"
+    workerpool "^6.5.1"
+    yargs "^16.2.0"
+    yargs-parser "^20.2.9"
+    yargs-unparser "^2.0.0"
 
 ms@2.0.0:
   version "2.0.0"
@@ -1252,16 +1288,11 @@ ms@2.1.2:
   resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz#d09d1f357b443f493382a8eb3ccd183872ae6009"
   integrity sha512-sGkPx+VjMtmA6MX27oA4FBFELFCZZ4S4XqeGOXCv68tT+jb3vk/RyaKWP0PTKyWtmLSM0b+adUTEvbs1PEaH2w==
 
-ms@2.1.3:
+ms@^2.1.3:
   version "2.1.3"
   resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz#574c8138ce1d2b5861f0b44579dbadd60c6615b2"
   integrity sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==
 
-nanoid@3.3.3:
-  version "3.3.3"
-  resolved "https://registry.yarnpkg.com/nanoid/-/nanoid-3.3.3.tgz#fd8e8b7aa761fe807dba2d1b98fb7241bb724a25"
-  integrity sha512-p1sjXuopFs0xg+fPASzQ28agW1oHD7xDsd9Xkf3T15H3c/cifrFHVwrh74PdoklAPi+i7MdRsE47vm2r6JoB+w==
-
 negotiator@0.6.3:
   version "0.6.3"
   resolved "https://registry.yarnpkg.com/negotiator/-/negotiator-0.6.3.tgz#58e323a72fedc0d6f9cd4d31fe49f51479590ccd"
@@ -1272,10 +1303,10 @@ neo-async@^2.6.2:
   resolved "https://registry.yarnpkg.com/neo-async/-/neo-async-2.6.2.tgz#b4aafb93e3aeb2d8174ca53cf163ab7d7308305f"
   integrity sha512-Yd3UES5mWCSqR+qNT93S3UoYUkqAZ9lLg8a7g9rimsWmYGK8cVToA4/sF3RrshdyV3sAGMXVUmpMYOw+dLpOuw==
 
-node-releases@^2.0.12:
-  version "2.0.13"
-  resolved "https://registry.yarnpkg.com/node-releases/-/node-releases-2.0.13.tgz#d5ed1627c23e3461e819b02e57b75e4899b1c81d"
-  integrity sha512-uYr7J37ae/ORWdZeQ1xxMJe3NtdmqMC/JZK+geofDrkLUApKRHPd18/TxtBOJ4A0/+uUIliorNrfYV6s1b02eQ==
+node-releases@^2.0.18:
+  version "2.0.18"
+  resolved "https://registry.yarnpkg.com/node-releases/-/node-releases-2.0.18.tgz#f010e8d35e2fe8d6b2944f03f70213ecedc4ca3f"
+  integrity sha512-d9VeXT4SJ7ZeOqGX6R5EM022wpL+eWPooLI+5UpWn2jCT1aosUQEhQP214x33Wkwx3JQMvIm+tIoVOdodFS40g==
 
 normalize-path@^3.0.0, normalize-path@~3.0.0:
   version "3.0.0"
@@ -1371,10 +1402,10 @@ path-parse@^1.0.7:
   resolved "https://registry.yarnpkg.com/path-parse/-/path-parse-1.0.7.tgz#fbc114b60ca42b30d9daf5858e4bd68bbedb6735"
   integrity sha512-LDJzPVEEEPR+y48z93A0Ed0yXb8pAByGWo/k5YYdYgpY2/2EsOsksJrq7lOHxryrVOn1ejG6oAp8ahvOIQD8sw==
 
-picocolors@^1.0.0:
-  version "1.0.0"
-  resolved "https://registry.yarnpkg.com/picocolors/-/picocolors-1.0.0.tgz#cb5bdc74ff3f51892236eaf79d68bc44564ab81c"
-  integrity sha512-1fygroTLlHu66zi26VoTDv8yRgm0Fccecssto+MhsZ0D/DGW2sm8E8AjW7NU5VVTRt5GxbeZ5qBuJr+HyLYkjQ==
+picocolors@^1.1.0:
+  version "1.1.1"
+  resolved "https://registry.yarnpkg.com/picocolors/-/picocolors-1.1.1.tgz#3d321af3eab939b083c8f929a1d12cda81c26b6b"
+  integrity sha512-xceH2snhtb5M9liqDsmEw56le376mTZkEX/jEb/RxNFyegNul7eNslCXP9FDj/Lcu0X8KEyMceP2ntpaHrDEVA==
 
 picomatch@^2.0.4, picomatch@^2.2.1:
   version "2.3.1"
@@ -1494,7 +1525,7 @@ safe-buffer@^5.1.0:
   resolved "https://registry.yarnpkg.com/safer-buffer/-/safer-buffer-2.1.2.tgz#44fa161b0187b9549dd84bb91802f9bd8385cd6a"
   integrity sha512-YZo3K82SD7Riyi0E1EQPojLz7kpepnSQI9IyPbHHg1XXXevb5dJI7tpyN2ADxGcQbHG7vcyRHk0cbwqcQriUtg==
 
-schema-utils@^3.1.1, schema-utils@^3.1.2:
+schema-utils@^3.1.1, schema-utils@^3.2.0:
   version "3.3.0"
   resolved "https://registry.yarnpkg.com/schema-utils/-/schema-utils-3.3.0.tgz#f50a88877c3c01652a15b622ae9e9795df7a60fe"
   integrity sha512-pN/yOAvcC+5rQ5nERGuwrjLlYvLTbCibnZ1I7B1LaiAz9BRBlE9GMgE/eqV30P7aJQUf7Ddimy/RsbYO/GrVGg==
@@ -1503,13 +1534,6 @@ schema-utils@^3.1.1, schema-utils@^3.1.2:
     ajv "^6.12.5"
     ajv-keywords "^3.5.2"
 
-serialize-javascript@6.0.0:
-  version "6.0.0"
-  resolved "https://registry.yarnpkg.com/serialize-javascript/-/serialize-javascript-6.0.0.tgz#efae5d88f45d7924141da8b5c3a7a7e663fefeb8"
-  integrity sha512-Qr3TosvguFt8ePWqsvRfrKyQXIiW+nGbYpy8XK24NQHE83caxWt+mIymTT19DGFbNWNLfEwsrkSmN64lVWB9ag==
-  dependencies:
-    randombytes "^2.1.0"
-
 serialize-javascript@^6.0.1:
   version "6.0.1"
   resolved "https://registry.yarnpkg.com/serialize-javascript/-/serialize-javascript-6.0.1.tgz#b206efb27c3da0b0ab6b52f48d170b7996458e5c"
@@ -1517,6 +1541,13 @@ serialize-javascript@^6.0.1:
   dependencies:
     randombytes "^2.1.0"
 
+serialize-javascript@^6.0.2:
+  version "6.0.2"
+  resolved "https://registry.yarnpkg.com/serialize-javascript/-/serialize-javascript-6.0.2.tgz#defa1e055c83bf6d59ea805d8da862254eb6a6c2"
+  integrity sha512-Saa1xPByTTq2gdeFZYLLo+RFE35NHZkAbqZeWNd3BpzppeVisAqpDjcp8dyf6uIvEqJRd46jemmyA4iFIeVk8g==
+  dependencies:
+    randombytes "^2.1.0"
+
 setprototypeof@1.2.0:
   version "1.2.0"
   resolved "https://registry.yarnpkg.com/setprototypeof/-/setprototypeof-1.2.0.tgz#66c9a24a73f9fc28cbe66b09fed3d33dcaf1b424"
@@ -1565,16 +1596,16 @@ socket.io-parser@~4.2.4:
     "@socket.io/component-emitter" "~3.1.0"
     debug "~4.3.1"
 
-socket.io@^4.4.1:
-  version "4.7.1"
-  resolved "https://registry.yarnpkg.com/socket.io/-/socket.io-4.7.1.tgz#9009f31bf7be25478895145e92fbc972ad1db900"
-  integrity sha512-W+utHys2w//dhFjy7iQQu9sGd3eokCjGbl2r59tyLqNiJJBdIebn3GAKEXBr3osqHTObJi2die/25bCx2zsaaw==
+socket.io@^4.7.2:
+  version "4.8.0"
+  resolved "https://registry.yarnpkg.com/socket.io/-/socket.io-4.8.0.tgz#33d05ae0915fad1670bd0c4efcc07ccfabebe3b1"
+  integrity sha512-8U6BEgGjQOfGz3HHTYaC/L1GaxDCJ/KM0XTkJly0EhZ5U/du9uNEZy4ZgYzEzIqlx2CMm25CrCqr1ck899eLNA==
   dependencies:
     accepts "~1.3.4"
     base64id "~2.0.0"
     cors "~2.8.5"
     debug "~4.3.2"
-    engine.io "~6.5.0"
+    engine.io "~6.6.0"
     socket.io-adapter "~2.5.2"
     socket.io-parser "~4.2.4"
 
@@ -1583,12 +1614,11 @@ source-map-js@^1.0.2:
   resolved "https://registry.yarnpkg.com/source-map-js/-/source-map-js-1.0.2.tgz#adbc361d9c62df380125e7f161f71c826f1e490c"
   integrity sha512-R0XvVJ9WusLiqTCEiGCmICCMplcCkIwwR11mOSD9CR5u+IXYdiseeEuXCVAjS54zqwkLcPNnmU4OeJ6tUrWhDw==
 
-source-map-loader@4.0.1:
-  version "4.0.1"
-  resolved "https://registry.yarnpkg.com/source-map-loader/-/source-map-loader-4.0.1.tgz#72f00d05f5d1f90f80974eda781cbd7107c125f2"
-  integrity sha512-oqXpzDIByKONVY8g1NUPOTQhe0UTU5bWUl32GSkqK2LjJj0HmwTMVKxcUip0RgAYhY1mqgOxjbQM48a0mmeNfA==
+source-map-loader@5.0.0:
+  version "5.0.0"
+  resolved "https://registry.yarnpkg.com/source-map-loader/-/source-map-loader-5.0.0.tgz#f593a916e1cc54471cfc8851b905c8a845fc7e38"
+  integrity sha512-k2Dur7CbSLcAH73sBcIkV5xjPV4SzqO1NJ7+XaQl8if3VODDUj3FNchNGpqgJSKbvUfJuhVdv8K2Eu8/TNl2eA==
   dependencies:
-    abab "^2.0.6"
     iconv-lite "^0.6.3"
     source-map-js "^1.0.2"
 
@@ -1640,18 +1670,11 @@ strip-ansi@^6.0.0, strip-ansi@^6.0.1:
   dependencies:
     ansi-regex "^5.0.1"
 
-strip-json-comments@3.1.1:
+strip-json-comments@^3.1.1:
   version "3.1.1"
   resolved "https://registry.yarnpkg.com/strip-json-comments/-/strip-json-comments-3.1.1.tgz#31f1281b3832630434831c310c01cccda8cbe006"
   integrity sha512-6fPc+R4ihwqP6N/aIv2f1gMH8lOVtWQHoqC4yK6oSDVVocumAsfCqjkXnqiYMhmMwS/mEHLp7Vehlt3ql6lEig==
 
-supports-color@8.1.1, supports-color@^8.0.0:
-  version "8.1.1"
-  resolved "https://registry.yarnpkg.com/supports-color/-/supports-color-8.1.1.tgz#cd6fc17e28500cff56c1b86c0a7fd4a54a73005c"
-  integrity sha512-MpUEN2OodtUzxvKQl72cUF7RQ5EiHsGvSsVG0ia9c5RbWGL2CI4C7EpPS8UTBIplnlzZiNuV56w+FuNxy3ty2Q==
-  dependencies:
-    has-flag "^4.0.0"
-
 supports-color@^7.1.0:
   version "7.2.0"
   resolved "https://registry.yarnpkg.com/supports-color/-/supports-color-7.2.0.tgz#1b7dcdcb32b8138801b3e478ba6a51caa89648da"
@@ -1659,6 +1682,13 @@ supports-color@^7.1.0:
   dependencies:
     has-flag "^4.0.0"
 
+supports-color@^8.0.0, supports-color@^8.1.1:
+  version "8.1.1"
+  resolved "https://registry.yarnpkg.com/supports-color/-/supports-color-8.1.1.tgz#cd6fc17e28500cff56c1b86c0a7fd4a54a73005c"
+  integrity sha512-MpUEN2OodtUzxvKQl72cUF7RQ5EiHsGvSsVG0ia9c5RbWGL2CI4C7EpPS8UTBIplnlzZiNuV56w+FuNxy3ty2Q==
+  dependencies:
+    has-flag "^4.0.0"
+
 supports-preserve-symlinks-flag@^1.0.0:
   version "1.0.0"
   resolved "https://registry.yarnpkg.com/supports-preserve-symlinks-flag/-/supports-preserve-symlinks-flag-1.0.0.tgz#6eda4bd344a3c94aea376d4cc31bc77311039e09"
@@ -1669,21 +1699,21 @@ tapable@^2.1.1, tapable@^2.2.0:
   resolved "https://registry.yarnpkg.com/tapable/-/tapable-2.2.1.tgz#1967a73ef4060a82f12ab96af86d52fdb76eeca0"
   integrity sha512-GNzQvQTOIP6RyTfE2Qxb8ZVlNmw0n88vp1szwWRimP02mnTsx3Wtn5qRdqY9w2XduFNUgvOwhNnQsjwCp+kqaQ==
 
-terser-webpack-plugin@^5.3.7:
-  version "5.3.9"
-  resolved "https://registry.yarnpkg.com/terser-webpack-plugin/-/terser-webpack-plugin-5.3.9.tgz#832536999c51b46d468067f9e37662a3b96adfe1"
-  integrity sha512-ZuXsqE07EcggTWQjXUj+Aot/OMcD0bMKGgF63f7UxYcu5/AJF53aIpK1YoP5xR9l6s/Hy2b+t1AM0bLNPRuhwA==
+terser-webpack-plugin@^5.3.10:
+  version "5.3.10"
+  resolved "https://registry.yarnpkg.com/terser-webpack-plugin/-/terser-webpack-plugin-5.3.10.tgz#904f4c9193c6fd2a03f693a2150c62a92f40d199"
+  integrity sha512-BKFPWlPDndPs+NGGCr1U59t0XScL5317Y0UReNrHaw9/FwhPENlq6bfgs+4yPfyP51vqC1bQ4rp1EfXW5ZSH9w==
   dependencies:
-    "@jridgewell/trace-mapping" "^0.3.17"
+    "@jridgewell/trace-mapping" "^0.3.20"
     jest-worker "^27.4.5"
     schema-utils "^3.1.1"
     serialize-javascript "^6.0.1"
-    terser "^5.16.8"
+    terser "^5.26.0"
 
-terser@^5.16.8:
-  version "5.18.2"
-  resolved "https://registry.yarnpkg.com/terser/-/terser-5.18.2.tgz#ff3072a0faf21ffd38f99acc9a0ddf7b5f07b948"
-  integrity sha512-Ah19JS86ypbJzTzvUCX7KOsEIhDaRONungA4aYBjEP3JZRf4ocuDzTg4QWZnPn9DEMiMYGJPiSOy7aykoCc70w==
+terser@^5.26.0:
+  version "5.36.0"
+  resolved "https://registry.yarnpkg.com/terser/-/terser-5.36.0.tgz#8b0dbed459ac40ff7b4c9fd5a3a2029de105180e"
+  integrity sha512-IYV9eNMuFAV4THUspIRXkLakHnV6XO7FEdtKjf/mDyrnqUg9LnlOn6/RwRvM9SZjR4GUq8Nk8zj67FzVARr74w==
   dependencies:
     "@jridgewell/source-map" "^0.3.3"
     acorn "^8.8.2"
@@ -1717,10 +1747,10 @@ type-is@~1.6.18:
     media-typer "0.3.0"
     mime-types "~2.1.24"
 
-typescript@5.0.4:
-  version "5.0.4"
-  resolved "https://registry.yarnpkg.com/typescript/-/typescript-5.0.4.tgz#b217fd20119bd61a94d4011274e0ab369058da3b"
-  integrity sha512-cW9T5W9xY37cc+jfEnaUvX91foxtHkza3Nw3wkoF4sSlKn0MONdkdEndig/qPBWXNkmplh3NzayQzCiHM4/hqw==
+typescript@5.5.4:
+  version "5.5.4"
+  resolved "https://registry.yarnpkg.com/typescript/-/typescript-5.5.4.tgz#d9852d6c82bad2d2eda4fd74a5762a8f5909e9ba"
+  integrity sha512-Mtq29sKDAEYP7aljRgtPOpTvOfbwRWlS6dPRzwjdE+C0R4brX/GUyhHSecbHMFLNBLcJIPt9nl9yG5TZ1weH+Q==
 
 ua-parser-js@^0.7.30:
   version "0.7.35"
@@ -1737,13 +1767,13 @@ unpipe@1.0.0, unpipe@~1.0.0:
   resolved "https://registry.yarnpkg.com/unpipe/-/unpipe-1.0.0.tgz#b2bf4ee8514aae6165b4817829d21b2ef49904ec"
   integrity sha512-pjy2bYhSsufwWlKwPc+l3cN7+wuJlK6uz0YdJEOlQDbl6jo/YlPi4mb8agUkVC8BF7V8NuzeyPNqRksA3hztKQ==
 
-update-browserslist-db@^1.0.11:
-  version "1.0.11"
-  resolved "https://registry.yarnpkg.com/update-browserslist-db/-/update-browserslist-db-1.0.11.tgz#9a2a641ad2907ae7b3616506f4b977851db5b940"
-  integrity sha512-dCwEFf0/oT85M1fHBg4F0jtLwJrutGoHSQXCh7u4o2t1drG+c0a9Flnqww6XUKSfQMPpJBRjU8d4RXB09qtvaA==
+update-browserslist-db@^1.1.0:
+  version "1.1.1"
+  resolved "https://registry.yarnpkg.com/update-browserslist-db/-/update-browserslist-db-1.1.1.tgz#80846fba1d79e82547fb661f8d141e0945755fe5"
+  integrity sha512-R8UzCaa9Az+38REPiJ1tXlImTJXlVfgHZsglwBD/k6nj76ctsH1E3q4doGrukiLQd3sGQYu56r5+lo5r94l29A==
   dependencies:
-    escalade "^3.1.1"
-    picocolors "^1.0.0"
+    escalade "^3.2.0"
+    picocolors "^1.1.0"
 
 uri-js@^4.2.2:
   version "4.4.1"
@@ -1767,23 +1797,23 @@ void-elements@^2.0.0:
   resolved "https://registry.yarnpkg.com/void-elements/-/void-elements-2.0.1.tgz#c066afb582bb1cb4128d60ea92392e94d5e9dbec"
   integrity sha512-qZKX4RnBzH2ugr8Lxa7x+0V6XD9Sb/ouARtiasEQCHB1EVU4NXtmHsDDrx1dO4ne5fc3J6EW05BP1Dl0z0iung==
 
-watchpack@^2.4.0:
-  version "2.4.0"
-  resolved "https://registry.yarnpkg.com/watchpack/-/watchpack-2.4.0.tgz#fa33032374962c78113f93c7f2fb4c54c9862a5d"
-  integrity sha512-Lcvm7MGST/4fup+ifyKi2hjyIAwcdI4HRgtvTpIUxBRhB+RFtUh8XtDOxUfctVCnhVi+QQj49i91OyvzkJl6cg==
+watchpack@^2.4.1:
+  version "2.4.2"
+  resolved "https://registry.yarnpkg.com/watchpack/-/watchpack-2.4.2.tgz#2feeaed67412e7c33184e5a79ca738fbd38564da"
+  integrity sha512-TnbFSbcOCcDgjZ4piURLCbJ3nJhznVh9kw6F6iokjiFPl8ONxe9A6nMDVXDiNbrSfLILs6vB07F7wLBrwPYzJw==
   dependencies:
     glob-to-regexp "^0.4.1"
     graceful-fs "^4.1.2"
 
-webpack-cli@5.1.0:
-  version "5.1.0"
-  resolved "https://registry.yarnpkg.com/webpack-cli/-/webpack-cli-5.1.0.tgz#abc4b1f44b50250f2632d8b8b536cfe2f6257891"
-  integrity sha512-a7KRJnCxejFoDpYTOwzm5o21ZXMaNqtRlvS183XzGDUPRdVEzJNImcQokqYZ8BNTnk9DkKiuWxw75+DCCoZ26w==
+webpack-cli@5.1.4:
+  version "5.1.4"
+  resolved "https://registry.yarnpkg.com/webpack-cli/-/webpack-cli-5.1.4.tgz#c8e046ba7eaae4911d7e71e2b25b776fcc35759b"
+  integrity sha512-pIDJHIEI9LR0yxHXQ+Qh95k2EvXpWzZ5l+d+jIo+RdSm9MiHfzazIxwwni/p7+x4eJZuvG1AJwgC4TNQ7NRgsg==
   dependencies:
     "@discoveryjs/json-ext" "^0.5.0"
-    "@webpack-cli/configtest" "^2.1.0"
-    "@webpack-cli/info" "^2.0.1"
-    "@webpack-cli/serve" "^2.0.3"
+    "@webpack-cli/configtest" "^2.1.1"
+    "@webpack-cli/info" "^2.0.2"
+    "@webpack-cli/serve" "^2.0.5"
     colorette "^2.0.14"
     commander "^10.0.1"
     cross-spawn "^7.0.3"
@@ -1814,34 +1844,33 @@ webpack-sources@^3.2.3:
   resolved "https://registry.yarnpkg.com/webpack-sources/-/webpack-sources-3.2.3.tgz#2d4daab8451fd4b240cc27055ff6a0c2ccea0cde"
   integrity sha512-/DyMEOrDgLKKIG0fmvtz+4dUX/3Ghozwgm6iPp8KRhvn+eQf9+Q7GWxVNMk3+uCPWfdXYC4ExGBckIXdFEfH1w==
 
-webpack@5.82.0:
-  version "5.82.0"
-  resolved "https://registry.yarnpkg.com/webpack/-/webpack-5.82.0.tgz#3c0d074dec79401db026b4ba0fb23d6333f88e7d"
-  integrity sha512-iGNA2fHhnDcV1bONdUu554eZx+XeldsaeQ8T67H6KKHl2nUSwX8Zm7cmzOA46ox/X1ARxf7Bjv8wQ/HsB5fxBg==
+webpack@5.94.0:
+  version "5.94.0"
+  resolved "https://registry.yarnpkg.com/webpack/-/webpack-5.94.0.tgz#77a6089c716e7ab90c1c67574a28da518a20970f"
+  integrity sha512-KcsGn50VT+06JH/iunZJedYGUJS5FGjow8wb9c0v5n1Om8O1g4L6LjtfxwlXIATopoQu+vOXXa7gYisWxCoPyg==
   dependencies:
-    "@types/eslint-scope" "^3.7.3"
-    "@types/estree" "^1.0.0"
-    "@webassemblyjs/ast" "^1.11.5"
-    "@webassemblyjs/wasm-edit" "^1.11.5"
-    "@webassemblyjs/wasm-parser" "^1.11.5"
+    "@types/estree" "^1.0.5"
+    "@webassemblyjs/ast" "^1.12.1"
+    "@webassemblyjs/wasm-edit" "^1.12.1"
+    "@webassemblyjs/wasm-parser" "^1.12.1"
     acorn "^8.7.1"
-    acorn-import-assertions "^1.7.6"
-    browserslist "^4.14.5"
+    acorn-import-attributes "^1.9.5"
+    browserslist "^4.21.10"
     chrome-trace-event "^1.0.2"
-    enhanced-resolve "^5.13.0"
+    enhanced-resolve "^5.17.1"
     es-module-lexer "^1.2.1"
     eslint-scope "5.1.1"
     events "^3.2.0"
     glob-to-regexp "^0.4.1"
-    graceful-fs "^4.2.9"
+    graceful-fs "^4.2.11"
     json-parse-even-better-errors "^2.3.1"
     loader-runner "^4.2.0"
     mime-types "^2.1.27"
     neo-async "^2.6.2"
-    schema-utils "^3.1.2"
+    schema-utils "^3.2.0"
     tapable "^2.1.1"
-    terser-webpack-plugin "^5.3.7"
-    watchpack "^2.4.0"
+    terser-webpack-plugin "^5.3.10"
+    watchpack "^2.4.1"
     webpack-sources "^3.2.3"
 
 which@^1.2.1:
@@ -1863,10 +1892,10 @@ wildcard@^2.0.0:
   resolved "https://registry.yarnpkg.com/wildcard/-/wildcard-2.0.1.tgz#5ab10d02487198954836b6349f74fff961e10f67"
   integrity sha512-CC1bOL87PIWSBhDcTrdeLo6eGT7mCFtrg0uIJtqJUFyK+eJnzl8A1niH56uu7KMa5XFrtiV+AQuHO3n7DsHnLQ==
 
-workerpool@6.2.1:
-  version "6.2.1"
-  resolved "https://registry.yarnpkg.com/workerpool/-/workerpool-6.2.1.tgz#46fc150c17d826b86a008e5a4508656777e9c343"
-  integrity sha512-ILEIE97kDZvF9Wb9f6h5aXK4swSlKGUcOEGiIYb2OOu/IrDU9iwj0fD//SsA6E5ibwJxpEvhullJY4Sl4GcpAw==
+workerpool@^6.5.1:
+  version "6.5.1"
+  resolved "https://registry.yarnpkg.com/workerpool/-/workerpool-6.5.1.tgz#060f73b39d0caf97c6db64da004cd01b4c099544"
+  integrity sha512-Fs4dNYcsdpYSAfVxhnl1L5zTksjvOJxtC5hzMNl+1t9B8hTJTdKDyZ5ju7ztgPy+ft9tBFXoOlDNiOT9WUXZlA==
 
 wrap-ansi@^7.0.0:
   version "7.0.0"
@@ -1887,22 +1916,22 @@ ws@~8.11.0:
   resolved "https://registry.yarnpkg.com/ws/-/ws-8.11.0.tgz#6a0d36b8edfd9f96d8b25683db2f8d7de6e8e143"
   integrity sha512-HPG3wQd9sNQoT9xHyNCXoDUa+Xw/VevmY9FoHyQ+g+rrMn4j6FB4np7Z0OhdTgjx6MgQLK7jwSy1YecU1+4Asg==
 
+ws@~8.17.1:
+  version "8.17.1"
+  resolved "https://registry.yarnpkg.com/ws/-/ws-8.17.1.tgz#9293da530bb548febc95371d90f9c878727d919b"
+  integrity sha512-6XQFvXTkbfUOZOKKILFG1PDK2NDQs4azKQl26T0YS5CxqWLgXajbPZ+h4gZekJyRqFU8pvnbAbbs/3TgRPy+GQ==
+
 y18n@^5.0.5:
   version "5.0.8"
   resolved "https://registry.yarnpkg.com/y18n/-/y18n-5.0.8.tgz#7f4934d0f7ca8c56f95314939ddcd2dd91ce1d55"
   integrity sha512-0pfFzegeDWJHJIAmTLRP2DwHjdF5s7jo9tuztdQxAhINCdvS+3nGINqPd00AphqJR/0LhANUS6/+7SCb98YOfA==
 
-yargs-parser@20.2.4:
-  version "20.2.4"
-  resolved "https://registry.yarnpkg.com/yargs-parser/-/yargs-parser-20.2.4.tgz#b42890f14566796f85ae8e3a25290d205f154a54"
-  integrity sha512-WOkpgNhPTlE73h4VFAFsOnomJVaovO8VqLDzy5saChRBFQFBoMYirowyW+Q9HB4HFF4Z7VZTiG3iSzJJA29yRA==
-
-yargs-parser@^20.2.2:
+yargs-parser@^20.2.2, yargs-parser@^20.2.9:
   version "20.2.9"
   resolved "https://registry.yarnpkg.com/yargs-parser/-/yargs-parser-20.2.9.tgz#2eb7dc3b0289718fc295f362753845c41a0c94ee"
   integrity sha512-y11nGElTIV+CT3Zv9t7VKl+Q3hTQoT9a1Qzezhhl6Rp21gJ/IVTW7Z3y9EWXhuUBC2Shnf+DX0antecpAwSP8w==
 
-yargs-unparser@2.0.0:
+yargs-unparser@^2.0.0:
   version "2.0.0"
   resolved "https://registry.yarnpkg.com/yargs-unparser/-/yargs-unparser-2.0.0.tgz#f131f9226911ae5d9ad38c432fe809366c2325eb"
   integrity sha512-7pRTIA9Qc1caZ0bZ6RYRGbHJthJWuakf+WmHK0rVeLkNrrGhfoabBNdue6kdINI6r4if7ocq9aD/n7xwKOdzOA==
@@ -1912,7 +1941,7 @@ yargs-unparser@2.0.0:
     flat "^5.0.2"
     is-plain-obj "^2.1.0"
 
-yargs@16.2.0, yargs@^16.1.1:
+yargs@^16.1.1, yargs@^16.2.0:
   version "16.2.0"
   resolved "https://registry.yarnpkg.com/yargs/-/yargs-16.2.0.tgz#1c82bf0f6b6a66eafce7ef30e376f49a12477f66"
   integrity sha512-D1mvvtDG0L5ft/jGWkLpG1+m0eQxOfaBvTNELraWj22wSVUMWxZUvYgJYcKh6jGGIkJFhH4IZPQhR4TKpc8mBw==
diff --git a/okio-fakefilesystem/api/okio-fakefilesystem.api b/okio-fakefilesystem/api/okio-fakefilesystem.api
index 1d319e43..f921a157 100644
--- a/okio-fakefilesystem/api/okio-fakefilesystem.api
+++ b/okio-fakefilesystem/api/okio-fakefilesystem.api
@@ -8,6 +8,7 @@ public final class okio/fakefilesystem/FakeFileSystem : okio/FileSystem {
 	public fun atomicMove (Lokio/Path;Lokio/Path;)V
 	public fun canonicalize (Lokio/Path;)Lokio/Path;
 	public final fun checkNoOpenFiles ()V
+	public fun close ()V
 	public fun createDirectory (Lokio/Path;Z)V
 	public fun createSymlink (Lokio/Path;Lokio/Path;)V
 	public fun delete (Lokio/Path;Z)V
diff --git a/okio-fakefilesystem/build.gradle.kts b/okio-fakefilesystem/build.gradle.kts
index afebff16..c5eadf06 100644
--- a/okio-fakefilesystem/build.gradle.kts
+++ b/okio-fakefilesystem/build.gradle.kts
@@ -19,7 +19,6 @@ kotlin {
         kotlinOptions {
           moduleKind = "umd"
           sourceMap = true
-          metaInfo = true
         }
       }
       nodejs {
@@ -57,8 +56,8 @@ tasks {
   val jvmJar by getting(Jar::class) {
     // BundleTaskConvention() crashes unless there's a 'main' source set.
     sourceSets.create(SourceSet.MAIN_SOURCE_SET_NAME)
-    val bndConvention = aQute.bnd.gradle.BundleTaskConvention(this)
-    bndConvention.setBnd(
+    val bndExtension = aQute.bnd.gradle.BundleTaskExtension(this)
+    bndExtension.setBnd(
       """
       Export-Package: okio.fakefilesystem
       Automatic-Module-Name: okio.fakefilesystem
@@ -67,7 +66,8 @@ tasks {
     )
     // Call the convention when the task has finished to modify the jar to contain OSGi metadata.
     doLast {
-      bndConvention.buildBundle()
+      bndExtension.buildAction()
+        .execute(this)
     }
   }
 }
diff --git a/okio-fakefilesystem/src/commonMain/kotlin/okio/fakefilesystem/FakeFileSystem.kt b/okio-fakefilesystem/src/commonMain/kotlin/okio/fakefilesystem/FakeFileSystem.kt
index fb2bd655..be9961ba 100644
--- a/okio-fakefilesystem/src/commonMain/kotlin/okio/fakefilesystem/FakeFileSystem.kt
+++ b/okio-fakefilesystem/src/commonMain/kotlin/okio/fakefilesystem/FakeFileSystem.kt
@@ -59,6 +59,12 @@ import okio.fakefilesystem.FakeFileSystem.Operation.WRITE
  * Programs that do not attempt any of the above operations should work fine on both UNIX and
  * Windows systems. Relax these constraints individually or call [emulateWindows] or [emulateUnix];
  * to apply the constraints of a particular operating system.
+ *
+ * Closeable
+ * ---------
+ *
+ * This file system cannot be used after it is closed. Closing it does not close any of its open
+ * streams; those must be closed directly.
  */
 class FakeFileSystem(
   @JvmField
@@ -71,6 +77,9 @@ class FakeFileSystem(
   /** Files that are currently open and need to be closed to avoid resource leaks. */
   private val openFiles = mutableListOf<OpenFile>()
 
+  /** Forbid all access after [close]. */
+  private var closed = false
+
   /**
    * An absolute path with this file system's current working directory. Relative paths will be
    * resolved against this directory when they are used.
@@ -218,6 +227,7 @@ class FakeFileSystem(
 
   /** Don't throw [FileNotFoundException] if the path doesn't identify a file. */
   private fun canonicalizeInternal(path: Path): Path {
+    check(!closed) { "closed" }
     return workingDirectory.resolve(path, normalize = true)
   }
 
@@ -722,9 +732,7 @@ class FakeFileSystem(
       val fileOffsetInt = fileOffset.toInt()
       val toCopy = minOf(file.data.size - fileOffsetInt, byteCount)
       if (toCopy <= 0) return -1
-      for (i in 0 until toCopy) {
-        array[i + arrayOffset] = file.data[i + fileOffsetInt]
-      }
+      file.data.copyInto(fileOffsetInt, array, arrayOffset, toCopy)
       return toCopy
     }
 
@@ -764,5 +772,9 @@ class FakeFileSystem(
     override fun toString() = "FileHandler(${openFile.canonicalPath})"
   }
 
+  override fun close() {
+    closed = true
+  }
+
   override fun toString() = "FakeFileSystem"
 }
diff --git a/okio-nodefilesystem/build.gradle.kts b/okio-nodefilesystem/build.gradle.kts
index 0509e4e5..b69ff328 100644
--- a/okio-nodefilesystem/build.gradle.kts
+++ b/okio-nodefilesystem/build.gradle.kts
@@ -1,9 +1,9 @@
 import com.vanniktech.maven.publish.JavadocJar.Dokka
-import com.vanniktech.maven.publish.KotlinJs
+import com.vanniktech.maven.publish.KotlinMultiplatform
 import com.vanniktech.maven.publish.MavenPublishBaseExtension
 
 plugins {
-  kotlin("js")
+  kotlin("multiplatform")
   id("org.jetbrains.dokka")
   id("com.vanniktech.maven.publish.base")
   id("binary-compatibility-validator")
@@ -16,7 +16,6 @@ kotlin {
         kotlinOptions {
           moduleKind = "umd"
           sourceMap = true
-          metaInfo = true
         }
       }
     }
@@ -37,14 +36,14 @@ kotlin {
         optIn("kotlin.time.ExperimentalTime")
       }
     }
-    val main by getting {
+    commonMain {
       dependencies {
         implementation(projects.okio)
         // Uncomment this to generate fs.fs.module_node.kt. Use it when updating fs.kt.
         // implementation(npm("@types/node", "14.14.16", true))
       }
     }
-    val test by getting {
+    commonTest {
       dependencies {
         implementation(libs.kotlin.test)
         implementation(libs.kotlin.time)
@@ -58,6 +57,6 @@ kotlin {
 
 configure<MavenPublishBaseExtension> {
   configure(
-    KotlinJs(javadocJar = Dokka("dokkaGfm"))
+    KotlinMultiplatform(javadocJar = Dokka("dokkaGfm"))
   )
 }
diff --git a/okio-nodefilesystem/src/main/kotlin/okio/FileSink.kt b/okio-nodefilesystem/src/commonMain/kotlin/okio/FileSink.kt
similarity index 100%
rename from okio-nodefilesystem/src/main/kotlin/okio/FileSink.kt
rename to okio-nodefilesystem/src/commonMain/kotlin/okio/FileSink.kt
diff --git a/okio-nodefilesystem/src/main/kotlin/okio/FileSource.kt b/okio-nodefilesystem/src/commonMain/kotlin/okio/FileSource.kt
similarity index 100%
rename from okio-nodefilesystem/src/main/kotlin/okio/FileSource.kt
rename to okio-nodefilesystem/src/commonMain/kotlin/okio/FileSource.kt
diff --git a/okio-nodefilesystem/src/main/kotlin/okio/FsJs.kt b/okio-nodefilesystem/src/commonMain/kotlin/okio/FsJs.kt
similarity index 99%
rename from okio-nodefilesystem/src/main/kotlin/okio/FsJs.kt
rename to okio-nodefilesystem/src/commonMain/kotlin/okio/FsJs.kt
index 2a308f06..223485a6 100644
--- a/okio-nodefilesystem/src/main/kotlin/okio/FsJs.kt
+++ b/okio-nodefilesystem/src/commonMain/kotlin/okio/FsJs.kt
@@ -50,7 +50,7 @@
  * To declare new external APIs, run Dukat to generate a full set of Node stubs. The easiest way to
  * do this is to add an NPM dependency on `@types/node` in `jsMain`, like this:
  *
- * ```
+ * ```kotlin
  * jsMain {
  *   ...
  *   dependencies {
diff --git a/okio-nodefilesystem/src/main/kotlin/okio/NodeJsFileHandle.kt b/okio-nodefilesystem/src/commonMain/kotlin/okio/NodeJsFileHandle.kt
similarity index 100%
rename from okio-nodefilesystem/src/main/kotlin/okio/NodeJsFileHandle.kt
rename to okio-nodefilesystem/src/commonMain/kotlin/okio/NodeJsFileHandle.kt
diff --git a/okio-nodefilesystem/src/main/kotlin/okio/NodeJsFileSystem.kt b/okio-nodefilesystem/src/commonMain/kotlin/okio/NodeJsFileSystem.kt
similarity index 100%
rename from okio-nodefilesystem/src/main/kotlin/okio/NodeJsFileSystem.kt
rename to okio-nodefilesystem/src/commonMain/kotlin/okio/NodeJsFileSystem.kt
diff --git a/okio-nodefilesystem/src/test/kotlin/okio/NodeJsFileSystemTest.kt b/okio-nodefilesystem/src/commonTest/kotlin/okio/NodeJsFileSystemTest.kt
similarity index 95%
rename from okio-nodefilesystem/src/test/kotlin/okio/NodeJsFileSystemTest.kt
rename to okio-nodefilesystem/src/commonTest/kotlin/okio/NodeJsFileSystemTest.kt
index 3afc3ed6..27664481 100644
--- a/okio-nodefilesystem/src/test/kotlin/okio/NodeJsFileSystemTest.kt
+++ b/okio-nodefilesystem/src/commonTest/kotlin/okio/NodeJsFileSystemTest.kt
@@ -24,4 +24,5 @@ class NodeJsFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = Path.DIRECTORY_SEPARATOR == "\\",
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.DoesNothing,
 )
diff --git a/okio-testing-support/build.gradle.kts b/okio-testing-support/build.gradle.kts
index bdf3506f..874bdf82 100644
--- a/okio-testing-support/build.gradle.kts
+++ b/okio-testing-support/build.gradle.kts
@@ -28,6 +28,10 @@ kotlin {
       }
     }
 
+    val zlibMain by creating {
+      dependsOn(commonMain)
+    }
+
     if (kmpJsEnabled) {
       val jsMain by getting {
         dependsOn(nonWasmMain)
@@ -36,6 +40,7 @@ kotlin {
 
     val jvmMain by getting {
       dependsOn(nonWasmMain)
+      dependsOn(zlibMain)
       dependencies {
         // On the JVM the kotlin-test library resolves to one of three implementations based on
         // which testing framework is in use. JUnit is used downstream, but Gradle can't know that
@@ -48,6 +53,7 @@ kotlin {
       createSourceSet("nativeMain", children = nativeTargets)
         .also { nativeMain ->
           nativeMain.dependsOn(nonWasmMain)
+          nativeMain.dependsOn(zlibMain)
         }
     }
 
diff --git a/okio-testing-support/src/commonMain/kotlin/okio/AbstractFileSystemTest.kt b/okio-testing-support/src/commonMain/kotlin/okio/AbstractFileSystemTest.kt
index 31ec6cba..26a34661 100644
--- a/okio-testing-support/src/commonMain/kotlin/okio/AbstractFileSystemTest.kt
+++ b/okio-testing-support/src/commonMain/kotlin/okio/AbstractFileSystemTest.kt
@@ -40,6 +40,7 @@ abstract class AbstractFileSystemTest(
   val allowClobberingEmptyDirectories: Boolean,
   val allowAtomicMoveFromFileToDirectory: Boolean,
   val allowRenameWhenTargetIsOpen: Boolean = !windowsLimitations,
+  val closeBehavior: CloseBehavior,
   temporaryDirectory: Path,
 ) {
   val base: Path = temporaryDirectory / "${this::class.simpleName}-${randomToken(16)}"
@@ -2553,6 +2554,110 @@ abstract class AbstractFileSystemTest(
     }
   }
 
+  @Test
+  fun readAfterFileSystemClose() {
+    val path = base / "file"
+
+    path.writeUtf8("hello, world!")
+
+    when (closeBehavior) {
+      CloseBehavior.Closes -> {
+        fileSystem.close()
+
+        assertFailsWith<IllegalStateException> {
+          fileSystem.canonicalize(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.exists(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.metadata(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.openReadOnly(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.source(path)
+        }
+      }
+
+      CloseBehavior.DoesNothing -> {
+        fileSystem.close()
+        fileSystem.canonicalize(path)
+        fileSystem.exists(path)
+        fileSystem.metadata(path)
+        fileSystem.openReadOnly(path).use {
+        }
+        fileSystem.source(path).use {
+        }
+      }
+
+      CloseBehavior.Unsupported -> {
+        assertFailsWith<UnsupportedOperationException> {
+          fileSystem.close()
+        }
+      }
+    }
+  }
+
+  @Test
+  fun writeAfterFileSystemClose() {
+    val path = base / "file"
+
+    when (closeBehavior) {
+      CloseBehavior.Closes -> {
+        fileSystem.close()
+
+        assertFailsWith<IllegalStateException> {
+          fileSystem.appendingSink(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.atomicMove(path, base / "file2")
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.createDirectory(base / "directory")
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.delete(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.openReadWrite(path)
+        }
+        assertFailsWith<IllegalStateException> {
+          fileSystem.sink(path)
+        }
+        if (supportsSymlink()) {
+          assertFailsWith<IllegalStateException> {
+            fileSystem.createSymlink(base / "symlink", base)
+          }
+        }
+      }
+
+      CloseBehavior.DoesNothing -> {
+        fileSystem.close()
+
+        fileSystem.appendingSink(path).use {
+        }
+        fileSystem.atomicMove(path, base / "file2")
+        fileSystem.createDirectory(base / "directory")
+        fileSystem.delete(path)
+        fileSystem.sink(path).use {
+        }
+        fileSystem.openReadWrite(path).use {
+        }
+        if (supportsSymlink()) {
+          fileSystem.createSymlink(base / "symlink", base)
+        }
+      }
+
+      CloseBehavior.Unsupported -> {
+        assertFailsWith<UnsupportedOperationException> {
+          fileSystem.close()
+        }
+      }
+    }
+  }
+
   protected fun supportsSymlink(): Boolean {
     if (fileSystem.isFakeFileSystem) return fileSystem.allowSymlinks
     if (windowsLimitations) return false
diff --git a/okio-testing-support/src/commonMain/kotlin/okio/CloseBehavior.kt b/okio-testing-support/src/commonMain/kotlin/okio/CloseBehavior.kt
new file mode 100644
index 00000000..e0ada5e3
--- /dev/null
+++ b/okio-testing-support/src/commonMain/kotlin/okio/CloseBehavior.kt
@@ -0,0 +1,22 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+enum class CloseBehavior {
+  Closes,
+  DoesNothing,
+  Unsupported,
+}
diff --git a/okio-testing-support/src/commonMain/kotlin/okio/TestingCommon.kt b/okio-testing-support/src/commonMain/kotlin/okio/TestingCommon.kt
index d84642ff..d8a5c25e 100644
--- a/okio-testing-support/src/commonMain/kotlin/okio/TestingCommon.kt
+++ b/okio-testing-support/src/commonMain/kotlin/okio/TestingCommon.kt
@@ -19,6 +19,7 @@ import kotlin.random.Random
 import kotlin.test.assertEquals
 import kotlin.time.Duration
 import okio.ByteString.Companion.toByteString
+import okio.Path.Companion.toPath
 
 fun Char.repeat(count: Int): String {
   return toString().repeat(count)
@@ -28,8 +29,8 @@ fun assertArrayEquals(a: ByteArray, b: ByteArray) {
   assertEquals(a.contentToString(), b.contentToString())
 }
 
-fun randomBytes(length: Int): ByteString {
-  val random = Random(0)
+fun randomBytes(length: Int, seed: Int = 0): ByteString {
+  val random = Random(seed)
   val randomBytes = ByteArray(length)
   random.nextBytes(randomBytes)
   return ByteString.of(*randomBytes)
@@ -75,6 +76,8 @@ expect class Instant : Comparable<Instant> {
   operator fun plus(duration: Duration): Instant
 
   operator fun minus(duration: Duration): Instant
+
+  override operator fun compareTo(other: Instant): Int
 }
 
 expect fun fromEpochSeconds(
@@ -90,3 +93,9 @@ expect val FileSystem.allowSymlinks: Boolean
 expect val FileSystem.allowReadsWhileWriting: Boolean
 
 expect var FileSystem.workingDirectory: Path
+
+expect fun getEnv(name: String): String?
+
+val okioRoot: Path by lazy {
+  getEnv("OKIO_ROOT")!!.toPath()
+}
diff --git a/okio-testing-support/src/commonMain/resources/go/NOTICE b/okio-testing-support/src/commonMain/resources/go/NOTICE
new file mode 100644
index 00000000..7b0c14ac
--- /dev/null
+++ b/okio-testing-support/src/commonMain/resources/go/NOTICE
@@ -0,0 +1,5 @@
+The files in this directory are copied from Go:
+https://go.dev/
+
+These files are subject to the 3-Clause BSD License:
+https://github.com/golang/go/blob/master/LICENSE
diff --git a/okio-testing-support/src/commonMain/resources/go/src/archive/zip/testdata/time-winzip.zip b/okio-testing-support/src/commonMain/resources/go/src/archive/zip/testdata/time-winzip.zip
new file mode 100644
index 00000000..f6e8f8ba
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/go/src/archive/zip/testdata/time-winzip.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithEncryption.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithEncryption.zip
new file mode 100644
index 00000000..b12fa404
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithEncryption.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.z01 b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.z01
new file mode 100644
index 00000000..494be846
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.z01 differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.z02 b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.z02
new file mode 100644
index 00000000..a0c36ecf
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.z02 differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.zip
new file mode 100644
index 00000000..6401cbb0
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/cannotReadZipWithSpanning.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/canonicalizationInvalidThrows.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/canonicalizationInvalidThrows.zip
new file mode 100644
index 00000000..60da0105
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/canonicalizationInvalidThrows.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/canonicalizationValid.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/canonicalizationValid.zip
new file mode 100644
index 00000000..60da0105
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/canonicalizationValid.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/emptyZip.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/emptyZip.zip
new file mode 100644
index 00000000..15cb0ecb
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/emptyZip.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/emptyZipWithPrependedData.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/emptyZipWithPrependedData.zip
new file mode 100644
index 00000000..a2ab2628
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/emptyZipWithPrependedData.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/filesOverlap.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/filesOverlap.zip
new file mode 100644
index 00000000..600d2038
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/filesOverlap.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zip64.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zip64.zip
new file mode 100644
index 00000000..8e7631b2
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zip64.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipTooShort.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipTooShort.zip
new file mode 100644
index 00000000..f91c69dc
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipTooShort.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithArchiveComment.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithArchiveComment.zip
new file mode 100644
index 00000000..d18b5009
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithArchiveComment.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithDeflate.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithDeflate.zip
new file mode 100644
index 00000000..72ba9f57
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithDeflate.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithDirectoryModifiedDate.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithDirectoryModifiedDate.zip
new file mode 100644
index 00000000..8546739b
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithDirectoryModifiedDate.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithEmptyDirectory.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithEmptyDirectory.zip
new file mode 100644
index 00000000..4432ce4f
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithEmptyDirectory.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileComments.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileComments.zip
new file mode 100644
index 00000000..56a93d21
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileComments.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileModifiedDate.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileModifiedDate.zip
new file mode 100644
index 00000000..d8cb568f
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileModifiedDate.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileOutOfBoundsModifiedDate.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileOutOfBoundsModifiedDate.zip
new file mode 100644
index 00000000..af89d183
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFileOutOfBoundsModifiedDate.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFiles.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFiles.zip
new file mode 100644
index 00000000..609d062d
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithFiles.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithModifiedDate.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithModifiedDate.zip
new file mode 100644
index 00000000..4f242017
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithModifiedDate.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithStore.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithStore.zip
new file mode 100644
index 00000000..0390eca2
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithStore.zip differ
diff --git a/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithSyntheticDirectory.zip b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithSyntheticDirectory.zip
new file mode 100644
index 00000000..729c922b
Binary files /dev/null and b/okio-testing-support/src/commonMain/resources/okio/zipfilesystem/zipWithSyntheticDirectory.zip differ
diff --git a/okio-testing-support/src/jsMain/kotlin/okio/TestingJs.kt b/okio-testing-support/src/jsMain/kotlin/okio/TestingJs.kt
index 21442a5c..82d7067d 100644
--- a/okio-testing-support/src/jsMain/kotlin/okio/TestingJs.kt
+++ b/okio-testing-support/src/jsMain/kotlin/okio/TestingJs.kt
@@ -20,3 +20,6 @@ actual fun isBrowser(): Boolean {
 }
 
 actual fun isWasm() = false
+
+actual fun getEnv(name: String): String? =
+  js("globalThis.process.env[name]") as String?
diff --git a/okio-testing-support/src/jvmMain/kotlin/okio/TestingJvm.kt b/okio-testing-support/src/jvmMain/kotlin/okio/TestingJvm.kt
index d6e274db..9ad333a2 100644
--- a/okio-testing-support/src/jvmMain/kotlin/okio/TestingJvm.kt
+++ b/okio-testing-support/src/jvmMain/kotlin/okio/TestingJvm.kt
@@ -18,3 +18,5 @@ package okio
 actual fun isBrowser() = false
 
 actual fun isWasm() = false
+
+actual fun getEnv(name: String): String? = System.getenv(name)
diff --git a/okio-testing-support/src/nativeMain/kotlin/okio/TestingNative.kt b/okio-testing-support/src/nativeMain/kotlin/okio/TestingNative.kt
index d6e274db..47de8766 100644
--- a/okio-testing-support/src/nativeMain/kotlin/okio/TestingNative.kt
+++ b/okio-testing-support/src/nativeMain/kotlin/okio/TestingNative.kt
@@ -15,6 +15,13 @@
  */
 package okio
 
+import kotlinx.cinterop.ExperimentalForeignApi
+import kotlinx.cinterop.toKString
+import platform.posix.getenv
+
 actual fun isBrowser() = false
 
 actual fun isWasm() = false
+
+@OptIn(ExperimentalForeignApi::class)
+actual fun getEnv(name: String): String? = getenv(name)?.toKString()
diff --git a/okio-testing-support/src/wasmMain/kotlin/okio/TestingWasm.kt b/okio-testing-support/src/wasmMain/kotlin/okio/TestingWasm.kt
index cb841783..1720c779 100644
--- a/okio-testing-support/src/wasmMain/kotlin/okio/TestingWasm.kt
+++ b/okio-testing-support/src/wasmMain/kotlin/okio/TestingWasm.kt
@@ -37,7 +37,7 @@ actual class Instant(
   actual operator fun minus(duration: Duration) =
     Instant(epochMilliseconds - duration.inWholeMilliseconds)
 
-  override fun compareTo(other: Instant) =
+  actual override fun compareTo(other: Instant) =
     epochMilliseconds.compareTo(other.epochMilliseconds)
 }
 
@@ -59,3 +59,5 @@ actual val FileSystem.allowReadsWhileWriting: Boolean
 actual var FileSystem.workingDirectory: Path
   get() = error("unexpected call")
   set(_) = error("unexpected call")
+
+actual fun getEnv(name: String): String? = error("unexpected call")
diff --git a/okio-wasifilesystem/build.gradle.kts b/okio-wasifilesystem/build.gradle.kts
index aaf43faa..5a363c1c 100644
--- a/okio-wasifilesystem/build.gradle.kts
+++ b/okio-wasifilesystem/build.gradle.kts
@@ -79,29 +79,41 @@ val injectWasiInit by tasks.creating {
       import { WASI } from 'wasi';
       import { argv, env } from 'node:process';
 
-      export const wasi = new WASI({
+      const wasi = new WASI({
         version: 'preview1',
+        args: argv,
         preopens: {
           '/tmp': '$base',
           '/a': '$baseA',
           '/b': '$baseB'
-        }
+        },
+        env,
       });
 
-      const module = await import(/* webpackIgnore: true */'node:module');
-      const require = module.default.createRequire(import.meta.url);
-      const fs = require('fs');
-      const path = require('path');
-      const url = require('url');
-      const filepath = url.fileURLToPath(import.meta.url);
-      const dirpath = path.dirname(filepath);
-      const wasmBuffer = fs.readFileSync(path.resolve(dirpath, './$moduleName.wasm'));
+      const fs = await import('node:fs');
+      const url = await import('node:url');
+      const wasmBuffer = fs.readFileSync(url.fileURLToPath(import.meta.resolve('./okio-parent-okio-wasifilesystem-wasm-wasi-test.wasm')));
       const wasmModule = new WebAssembly.Module(wasmBuffer);
       const wasmInstance = new WebAssembly.Instance(wasmModule, wasi.getImportObject());
 
       wasi.initialize(wasmInstance);
 
-      export default wasmInstance.exports;
+      const exports = wasmInstance.exports
+
+      export default new Proxy(exports, {
+          _shownError: false,
+          get(target, prop) {
+              if (!this._shownError) {
+                  this._shownError = true;
+                  throw new Error("Do not use default import. Use the corresponding named import instead.")
+              }
+          }
+      });
+      export const {
+          startUnitTests,
+          _initialize,
+          memory
+      } = exports;
       """.trimIndent()
     )
   }
diff --git a/okio-wasifilesystem/src/wasmWasiTest/kotlin/okio/WasiFileSystemTest.kt b/okio-wasifilesystem/src/wasmWasiTest/kotlin/okio/WasiFileSystemTest.kt
index b6846b45..a3236117 100644
--- a/okio-wasifilesystem/src/wasmWasiTest/kotlin/okio/WasiFileSystemTest.kt
+++ b/okio-wasifilesystem/src/wasmWasiTest/kotlin/okio/WasiFileSystemTest.kt
@@ -24,4 +24,5 @@ class WasiFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = Path.DIRECTORY_SEPARATOR == "\\",
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = "/tmp".toPath(),
+  closeBehavior = CloseBehavior.DoesNothing,
 )
diff --git a/okio/api/okio.api b/okio/api/okio.api
index b85e1870..e23255ed 100644
--- a/okio/api/okio.api
+++ b/okio/api/okio.api
@@ -141,6 +141,7 @@ public final class okio/Buffer : java/lang/Cloneable, java/nio/channels/ByteChan
 	public fun request (J)Z
 	public fun require (J)V
 	public fun select (Lokio/Options;)I
+	public fun select (Lokio/TypedOptions;)Ljava/lang/Object;
 	public final fun sha1 ()Lokio/ByteString;
 	public final fun sha256 ()Lokio/ByteString;
 	public final fun sha512 ()Lokio/ByteString;
@@ -284,6 +285,7 @@ public abstract interface class okio/BufferedSource : java/nio/channels/Readable
 	public abstract fun request (J)Z
 	public abstract fun require (J)V
 	public abstract fun select (Lokio/Options;)I
+	public abstract fun select (Lokio/TypedOptions;)Ljava/lang/Object;
 	public abstract fun skip (J)V
 }
 
@@ -446,7 +448,7 @@ public final class okio/FileMetadata {
 	public fun toString ()Ljava/lang/String;
 }
 
-public abstract class okio/FileSystem {
+public abstract class okio/FileSystem : java/io/Closeable {
 	public static final field Companion Lokio/FileSystem$Companion;
 	public static final field RESOURCES Lokio/FileSystem;
 	public static final field SYSTEM Lokio/FileSystem;
@@ -460,6 +462,7 @@ public abstract class okio/FileSystem {
 	public static synthetic fun appendingSink$default (Lokio/FileSystem;Lokio/Path;ZILjava/lang/Object;)Lokio/Sink;
 	public abstract fun atomicMove (Lokio/Path;Lokio/Path;)V
 	public abstract fun canonicalize (Lokio/Path;)Lokio/Path;
+	public fun close ()V
 	public fun copy (Lokio/Path;Lokio/Path;)V
 	public final fun createDirectories (Lokio/Path;)V
 	public final fun createDirectories (Lokio/Path;Z)V
@@ -502,6 +505,7 @@ public abstract class okio/ForwardingFileSystem : okio/FileSystem {
 	public fun appendingSink (Lokio/Path;Z)Lokio/Sink;
 	public fun atomicMove (Lokio/Path;Lokio/Path;)V
 	public fun canonicalize (Lokio/Path;)Lokio/Path;
+	public fun close ()V
 	public fun createDirectory (Lokio/Path;Z)V
 	public fun createSymlink (Lokio/Path;Lokio/Path;)V
 	public final fun delegate ()Lokio/FileSystem;
@@ -753,6 +757,10 @@ public abstract interface class okio/Source : java/io/Closeable {
 	public abstract fun timeout ()Lokio/Timeout;
 }
 
+public final class okio/SystemFileSystem {
+	public static final synthetic fun getSYSTEM (Lokio/FileSystem$Companion;)Lokio/FileSystem;
+}
+
 public final class okio/Throttler {
 	public fun <init> ()V
 	public final fun bytesPerSecond (J)V
@@ -790,6 +798,18 @@ public final class okio/Timeout$Companion {
 	public final fun timeout-HG0u8IE (Lokio/Timeout;J)Lokio/Timeout;
 }
 
+public final class okio/TypedOptions : kotlin/collections/AbstractList, java/util/RandomAccess {
+	public static final field Companion Lokio/TypedOptions$Companion;
+	public fun <init> (Ljava/util/List;Lokio/Options;)V
+	public fun get (I)Ljava/lang/Object;
+	public fun getSize ()I
+	public static final fun of (Ljava/lang/Iterable;Lkotlin/jvm/functions/Function1;)Lokio/TypedOptions;
+}
+
+public final class okio/TypedOptions$Companion {
+	public final fun of (Ljava/lang/Iterable;Lkotlin/jvm/functions/Function1;)Lokio/TypedOptions;
+}
+
 public final class okio/Utf8 {
 	public static final fun size (Ljava/lang/String;)J
 	public static final fun size (Ljava/lang/String;I)J
diff --git a/okio/build.gradle.kts b/okio/build.gradle.kts
index cac4a345..88a590a7 100644
--- a/okio/build.gradle.kts
+++ b/okio/build.gradle.kts
@@ -1,4 +1,4 @@
-import aQute.bnd.gradle.BundleTaskConvention
+import aQute.bnd.gradle.BundleTaskExtension
 import com.vanniktech.maven.publish.JavadocJar.Dokka
 import com.vanniktech.maven.publish.KotlinMultiplatform
 import com.vanniktech.maven.publish.MavenPublishBaseExtension
@@ -9,6 +9,7 @@ import org.jetbrains.kotlin.gradle.plugin.mpp.TestExecutable
 
 plugins {
   kotlin("multiplatform")
+  id("app.cash.burst")
   id("org.jetbrains.dokka")
   id("com.vanniktech.maven.publish.base")
   id("build-support")
@@ -47,6 +48,8 @@ plugins {
  *
  * The `hashFunctions` source set builds on all platforms. It ships as a main source set on non-JVM
  * platforms and as a test source set on the JVM platform.
+ *
+ * The `systemFileSystem` source set is used on jvm and native targets, and provides the FileSystem.SYSTEM property.
  */
 kotlin {
   configureOrCreateOkioPlatforms()
@@ -76,6 +79,7 @@ kotlin {
     }
 
     val nonWasmTest by creating {
+      dependsOn(commonTest)
       dependencies {
         implementation(libs.kotlin.time)
         implementation(projects.okioFakefilesystem)
@@ -87,15 +91,33 @@ kotlin {
       dependsOn(commonMain)
     }
 
+    val systemFileSystemMain by creating {
+      dependsOn(commonMain)
+    }
+
     val nonJvmTest by creating {
       dependsOn(commonTest)
     }
 
+    val zlibMain by creating {
+      dependsOn(commonMain)
+    }
+
+    val zlibTest by creating {
+      dependsOn(commonTest)
+      dependencies {
+        implementation(libs.test.assertk)
+      }
+    }
+
     val jvmMain by getting {
+      dependsOn(zlibMain)
+      dependsOn(systemFileSystemMain)
     }
     val jvmTest by getting {
-      kotlin.srcDir("src/jvmTest/hashFunctions")
+      kotlin.srcDir("src/hashFunctions")
       dependsOn(nonWasmTest)
+      dependsOn(zlibTest)
       dependencies {
         implementation(libs.test.junit)
         implementation(libs.test.assertj)
@@ -117,6 +139,8 @@ kotlin {
     if (kmpNativeEnabled) {
       createSourceSet("nativeMain", parent = nonJvmMain)
         .also { nativeMain ->
+          nativeMain.dependsOn(zlibMain)
+          nativeMain.dependsOn(systemFileSystemMain)
           createSourceSet("mingwMain", parent = nativeMain, children = mingwTargets).also { mingwMain ->
             mingwMain.dependsOn(nonAppleMain)
           }
@@ -133,6 +157,7 @@ kotlin {
         .also { nativeTest ->
           nativeTest.dependsOn(nonJvmTest)
           nativeTest.dependsOn(nonWasmTest)
+          nativeTest.dependsOn(zlibTest)
           createSourceSet("appleTest", parent = nativeTest, children = appleTargets)
         }
     }
@@ -167,19 +192,20 @@ kotlin {
 
 tasks {
   val jvmJar by getting(Jar::class) {
-    // BundleTaskConvention() crashes unless there's a 'main' source set.
+    // BundleTaskExtension() crashes unless there's a 'main' source set.
     sourceSets.create(SourceSet.MAIN_SOURCE_SET_NAME)
-    val bndConvention = BundleTaskConvention(this)
-    bndConvention.setBnd(
+    val bndExtension = BundleTaskExtension(this)
+    bndExtension.setBnd(
       """
       Export-Package: okio
       Automatic-Module-Name: okio
       Bundle-SymbolicName: com.squareup.okio
       """,
     )
-    // Call the convention when the task has finished to modify the jar to contain OSGi metadata.
+    // Call the extension when the task has finished to modify the jar to contain OSGi metadata.
     doLast {
-      bndConvention.buildBundle()
+      bndExtension.buildAction()
+        .execute(this)
     }
   }
 }
diff --git a/okio/src/commonMain/kotlin/okio/Base64.kt b/okio/src/commonMain/kotlin/okio/Base64.kt
index 150793cc..b513656f 100644
--- a/okio/src/commonMain/kotlin/okio/Base64.kt
+++ b/okio/src/commonMain/kotlin/okio/Base64.kt
@@ -19,16 +19,13 @@
 package okio
 
 import kotlin.jvm.JvmName
-import kotlin.native.concurrent.SharedImmutable
 import okio.ByteString.Companion.encodeUtf8
 
 /** @author Alexander Y. Kleymenov */
 
-@SharedImmutable
 internal val BASE64 =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".encodeUtf8().data
 
-@SharedImmutable
 internal val BASE64_URL_SAFE =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".encodeUtf8().data
 
diff --git a/okio/src/commonMain/kotlin/okio/Buffer.kt b/okio/src/commonMain/kotlin/okio/Buffer.kt
index 009ed233..f186d2aa 100644
--- a/okio/src/commonMain/kotlin/okio/Buffer.kt
+++ b/okio/src/commonMain/kotlin/okio/Buffer.kt
@@ -15,8 +15,6 @@
  */
 package okio
 
-import kotlin.jvm.JvmField
-
 /**
  * A collection of bytes in memory.
  *
@@ -36,12 +34,6 @@ expect class Buffer() : BufferedSource, BufferedSink {
   var size: Long
     internal set
 
-  override val buffer: Buffer
-
-  override fun emitCompleteSegments(): Buffer
-
-  override fun emit(): Buffer
-
   /** Copy `byteCount` bytes from this, starting at `offset`, to `out`.  */
   fun copyTo(
     out: Buffer,
@@ -76,18 +68,6 @@ expect class Buffer() : BufferedSource, BufferedSink {
   /** Discards `byteCount` bytes from the head of this buffer.  */
   override fun skip(byteCount: Long)
 
-  override fun write(byteString: ByteString): Buffer
-
-  override fun write(byteString: ByteString, offset: Int, byteCount: Int): Buffer
-
-  override fun writeUtf8(string: String): Buffer
-
-  override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int): Buffer
-
-  override fun writeUtf8CodePoint(codePoint: Int): Buffer
-
-  override fun write(source: ByteArray): Buffer
-
   /**
    * Returns a tail segment that we can write at least `minimumCapacity`
    * bytes to, creating it if necessary.
@@ -111,28 +91,6 @@ expect class Buffer() : BufferedSource, BufferedSink {
   /** Returns the 512-bit SHA-512 HMAC of this buffer.  */
   fun hmacSha512(key: ByteString): ByteString
 
-  override fun write(source: ByteArray, offset: Int, byteCount: Int): Buffer
-
-  override fun write(source: Source, byteCount: Long): Buffer
-
-  override fun writeByte(b: Int): Buffer
-
-  override fun writeShort(s: Int): Buffer
-
-  override fun writeShortLe(s: Int): Buffer
-
-  override fun writeInt(i: Int): Buffer
-
-  override fun writeIntLe(i: Int): Buffer
-
-  override fun writeLong(v: Long): Buffer
-
-  override fun writeLongLe(v: Long): Buffer
-
-  override fun writeDecimalLong(v: Long): Buffer
-
-  override fun writeHexadecimalUnsignedLong(v: Long): Buffer
-
   /**
    * Returns a deep copy of this buffer. The returned [Buffer] initially shares the underlying
    * [ByteArray]s. See [UnsafeCursor] for more details.
@@ -149,6 +107,72 @@ expect class Buffer() : BufferedSource, BufferedSink {
 
   fun readAndWriteUnsafe(unsafeCursor: UnsafeCursor = DEFAULT__new_UnsafeCursor): UnsafeCursor
 
+  override val buffer: Buffer
+  override fun close()
+  override fun emit(): Buffer
+  override fun emitCompleteSegments(): Buffer
+  override fun exhausted(): Boolean
+  override fun flush()
+  override fun indexOf(b: Byte): Long
+  override fun indexOf(b: Byte, fromIndex: Long): Long
+  override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long
+  override fun indexOf(bytes: ByteString): Long
+  override fun indexOf(bytes: ByteString, fromIndex: Long): Long
+  override fun indexOfElement(targetBytes: ByteString): Long
+  override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long
+  override fun peek(): BufferedSource
+  override fun rangeEquals(offset: Long, bytes: ByteString): Boolean
+  override fun rangeEquals(offset: Long, bytes: ByteString, bytesOffset: Int, byteCount: Int): Boolean
+  override fun read(sink: Buffer, byteCount: Long): Long
+  override fun read(sink: ByteArray): Int
+  override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int
+  override fun readAll(sink: Sink): Long
+  override fun readByte(): Byte
+  override fun readByteArray(): ByteArray
+  override fun readByteArray(byteCount: Long): ByteArray
+  override fun readByteString(): ByteString
+  override fun readByteString(byteCount: Long): ByteString
+  override fun readDecimalLong(): Long
+  override fun readFully(sink: Buffer, byteCount: Long)
+  override fun readFully(sink: ByteArray)
+  override fun readHexadecimalUnsignedLong(): Long
+  override fun readInt(): Int
+  override fun readIntLe(): Int
+  override fun readLong(): Long
+  override fun readLongLe(): Long
+  override fun readShort(): Short
+  override fun readShortLe(): Short
+  override fun readUtf8(): String
+  override fun readUtf8(byteCount: Long): String
+  override fun readUtf8CodePoint(): Int
+  override fun readUtf8Line(): String?
+  override fun readUtf8LineStrict(): String
+  override fun readUtf8LineStrict(limit: Long): String
+  override fun request(byteCount: Long): Boolean
+  override fun require(byteCount: Long)
+  override fun select(options: Options): Int
+  override fun <T : Any> select(options: TypedOptions<T>): T?
+  override fun timeout(): Timeout
+  override fun write(byteString: ByteString): Buffer
+  override fun write(byteString: ByteString, offset: Int, byteCount: Int): Buffer
+  override fun write(source: Buffer, byteCount: Long)
+  override fun write(source: ByteArray): Buffer
+  override fun write(source: ByteArray, offset: Int, byteCount: Int): Buffer
+  override fun write(source: Source, byteCount: Long): Buffer
+  override fun writeAll(source: Source): Long
+  override fun writeByte(b: Int): Buffer
+  override fun writeDecimalLong(v: Long): Buffer
+  override fun writeHexadecimalUnsignedLong(v: Long): Buffer
+  override fun writeInt(i: Int): Buffer
+  override fun writeIntLe(i: Int): Buffer
+  override fun writeLong(v: Long): Buffer
+  override fun writeLongLe(v: Long): Buffer
+  override fun writeShort(s: Int): Buffer
+  override fun writeShortLe(s: Int): Buffer
+  override fun writeUtf8(string: String): Buffer
+  override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int): Buffer
+  override fun writeUtf8CodePoint(codePoint: Int): Buffer
+
   /**
    * A handle to the underlying data in a buffer. This handle is unsafe because it does not enforce
    * its own invariants. Instead, it assumes a careful user who has studied Okio's implementation
@@ -177,7 +201,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    *
    * New buffers are empty and have no segments:
    *
-   * ```
+   * ```kotlin
    *   val buffer = Buffer()
    * ```
    *
@@ -185,7 +209,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * segment and writes its new data there. The lone segment has an 8 KiB byte array but only 7
    * bytes of data:
    *
-   * ```
+   * ```kotlin
    * buffer.writeUtf8("sealion")
    *
    * // [ 's', 'e', 'a', 'l', 'i', 'o', 'n', '?', '?', '?', ...]
@@ -197,7 +221,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * to us. As bytes are read the data is consumed. The segment tracks this by adjusting its
    * internal indices.
    *
-   * ```
+   * ```kotlin
    * buffer.readUtf8(4) // "seal"
    *
    * // [ 's', 'e', 'a', 'l', 'i', 'o', 'n', '?', '?', '?', ...]
@@ -210,7 +234,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * segments. Each segment has its own start and end indexes tracking where the user's data begins
    * and ends.
    *
-   * ```
+   * ```kotlin
    * val xoxo = new Buffer()
    * xoxo.writeUtf8("xo".repeat(5_000))
    *
@@ -234,7 +258,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * you may see its effects. In this example, one of the "xoxo" segments above is reused in an
    * unrelated buffer:
    *
-   * ```
+   * ```kotlin
    * val abc = new Buffer()
    * abc.writeUtf8("abc")
    *
@@ -247,7 +271,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * share the same underlying byte array. Clones can't write to the shared byte array; instead they
    * allocate a new (private) segment early.
    *
-   * ```
+   * ```kotlin
    * val nana = new Buffer()
    * nana.writeUtf8("na".repeat(2_500))
    * nana.readUtf8(2) // "na"
@@ -291,7 +315,7 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * [use] extension function. In this example we read all of the bytes in a buffer into a byte
    * array:
    *
-   * ```
+   * ```kotlin
    * val bufferBytes = ByteArray(buffer.size.toInt())
    *
    * buffer.readUnsafe().use { cursor ->
@@ -341,19 +365,19 @@ expect class Buffer() : BufferedSource, BufferedSink {
    * [Buffer.readAndWriteUnsafe] that take a cursor and close it after use.
    */
   class UnsafeCursor constructor() : Closeable {
-    @JvmField var buffer: Buffer?
+    var buffer: Buffer?
 
-    @JvmField var readWrite: Boolean
+    var readWrite: Boolean
 
     internal var segment: Segment?
 
-    @JvmField var offset: Long
+    var offset: Long
 
-    @JvmField var data: ByteArray?
+    var data: ByteArray?
 
-    @JvmField var start: Int
+    var start: Int
 
-    @JvmField var end: Int
+    var end: Int
 
     /**
      * Seeks to the next range of bytes, advancing the offset by `end - start`. Returns the size of
diff --git a/okio/src/commonMain/kotlin/okio/BufferedSink.kt b/okio/src/commonMain/kotlin/okio/BufferedSink.kt
index 03c8230a..4f6927ab 100644
--- a/okio/src/commonMain/kotlin/okio/BufferedSink.kt
+++ b/okio/src/commonMain/kotlin/okio/BufferedSink.kt
@@ -44,7 +44,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Encodes `string` in UTF-8 and writes it to this sink.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeUtf8("Uh uh uh!");
    * buffer.writeByte(' ');
@@ -58,7 +59,8 @@ expect sealed interface BufferedSink : Sink {
   /**
    * Encodes the characters at `beginIndex` up to `endIndex` from `string` in UTF-8 and writes it to
    * this sink.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeUtf8("I'm a hacker!\n", 6, 12);
    * buffer.writeByte(' ');
@@ -79,7 +81,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a big-endian short to this sink using two bytes.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeShort(32767);
    * buffer.writeShort(15);
@@ -96,7 +99,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a little-endian short to this sink using two bytes.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeShortLe(32767);
    * buffer.writeShortLe(15);
@@ -113,7 +117,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a big-endian int to this sink using four bytes.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeInt(2147483647);
    * buffer.writeInt(15);
@@ -134,7 +139,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a little-endian int to this sink using four bytes.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeIntLe(2147483647);
    * buffer.writeIntLe(15);
@@ -155,7 +161,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a big-endian long to this sink using eight bytes.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeLong(9223372036854775807L);
    * buffer.writeLong(15);
@@ -184,7 +191,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a little-endian long to this sink using eight bytes.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeLongLe(9223372036854775807L);
    * buffer.writeLongLe(15);
@@ -213,7 +221,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a long to this sink in signed decimal form (i.e., as a string in base 10).
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeDecimalLong(8675309L);
    * buffer.writeByte(' ');
@@ -228,7 +237,8 @@ expect sealed interface BufferedSink : Sink {
 
   /**
    * Writes a long to this sink in hexadecimal form (i.e., as a string in base 16).
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeHexadecimalUnsignedLong(65535L);
    * buffer.writeByte(' ');
@@ -245,7 +255,8 @@ expect sealed interface BufferedSink : Sink {
    * Writes all buffered data to the underlying sink, if one exists. Then that sink is recursively
    * flushed which pushes data as far as possible towards its ultimate destination. Typically that
    * destination is a network socket or file.
-   * ```
+   *
+   * ```java
    * BufferedSink b0 = new Buffer();
    * BufferedSink b1 = Okio.buffer(b0);
    * BufferedSink b2 = Okio.buffer(b1);
@@ -266,7 +277,8 @@ expect sealed interface BufferedSink : Sink {
   /**
    * Writes all buffered data to the underlying sink, if one exists. Like [flush], but weaker. Call
    * this before this buffered sink goes out of scope so that its data can reach its destination.
-   * ```
+   *
+   * ```java
    * BufferedSink b0 = new Buffer();
    * BufferedSink b1 = Okio.buffer(b0);
    * BufferedSink b2 = Okio.buffer(b1);
@@ -294,7 +306,8 @@ expect sealed interface BufferedSink : Sink {
    * this to limit the memory held in the buffer to a single segment. Typically application code
    * will not need to call this: it is only necessary when application code writes directly to this
    * [sink's buffer][buffer].
-   * ```
+   *
+   * ```java
    * BufferedSink b0 = new Buffer();
    * BufferedSink b1 = Okio.buffer(b0);
    * BufferedSink b2 = Okio.buffer(b1);
diff --git a/okio/src/commonMain/kotlin/okio/BufferedSource.kt b/okio/src/commonMain/kotlin/okio/BufferedSource.kt
index 86b4803a..eaddb265 100644
--- a/okio/src/commonMain/kotlin/okio/BufferedSource.kt
+++ b/okio/src/commonMain/kotlin/okio/BufferedSource.kt
@@ -47,7 +47,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes two bytes from this source and returns a big-endian short.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeByte(0x7f)
    *     .writeByte(0xff)
@@ -66,7 +67,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes two bytes from this source and returns a little-endian short.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeByte(0xff)
    *     .writeByte(0x7f)
@@ -85,7 +87,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes four bytes from this source and returns a big-endian int.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeByte(0x7f)
    *     .writeByte(0xff)
@@ -108,7 +111,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes four bytes from this source and returns a little-endian int.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeByte(0xff)
    *     .writeByte(0xff)
@@ -131,7 +135,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes eight bytes from this source and returns a big-endian long.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeByte(0x7f)
    *     .writeByte(0xff)
@@ -162,7 +167,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes eight bytes from this source and returns a little-endian long.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeByte(0xff)
    *     .writeByte(0xff)
@@ -194,7 +200,8 @@ expect sealed interface BufferedSource : Source {
   /**
    * Reads a long from this source in signed decimal form (i.e., as a string in base 10 with
    * optional leading '-'). This will iterate until a non-digit character is found.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeUtf8("8675309 -123 00001");
    *
@@ -213,7 +220,8 @@ expect sealed interface BufferedSource : Source {
   /**
    * Reads a long form this source in hexadecimal form (i.e., as a string in base 16). This will
    * iterate until a non-hexadecimal character is found.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeUtf8("ffff CAFEBABE 10");
    *
@@ -242,13 +250,14 @@ expect sealed interface BufferedSource : Source {
   fun readByteString(byteCount: Long): ByteString
 
   /**
-   * Finds the first string in `options` that is a prefix of this buffer, consumes it from this
-   * buffer, and returns its index. If no byte string in `options` is a prefix of this buffer this
+   * Finds the first byte string in `options` that is a prefix of this buffer, consumes it from this
+   * source, and returns its index. If no byte string in `options` is a prefix of this buffer this
    * returns -1 and no bytes are consumed.
    *
    * This can be used as an alternative to [readByteString] or even [readUtf8] if the set of
    * expected values is known in advance.
-   * ```
+   *
+   * ```java
    * Options FIELDS = Options.of(
    *     ByteString.encodeUtf8("depth="),
    *     ByteString.encodeUtf8("height="),
@@ -268,6 +277,37 @@ expect sealed interface BufferedSource : Source {
    */
   fun select(options: Options): Int
 
+  /**
+   * Finds the first item in [options] whose encoding is a prefix of this buffer, consumes it from
+   * this buffer, and returns it. If no item in [options] is a prefix of this source, this function
+   * returns null and no bytes are consumed.
+   *
+   * This can be used as an alternative to [readByteString] or even [readUtf8] if the set of
+   * expected values is known in advance.
+   *
+   * ```java
+   * TypedOptions<Direction> options = TypedOptions.of(
+   *     Arrays.asList(Direction.values()),
+   *     (direction) -> ByteString.encodeUtf8(direction.name().toLowerCase(Locale.ROOT))
+   * );
+   *
+   * Buffer buffer = new Buffer()
+   *     .writeUtf8("north:100\n")
+   *     .writeUtf8("east:50\n");
+   *
+   * assertEquals(Direction.NORTH, buffer.select(options));
+   * assertEquals(':', buffer.readByte());
+   * assertEquals(100L, buffer.readDecimalLong());
+   * assertEquals('\n', buffer.readByte());
+   *
+   * assertEquals(Direction.EAST, buffer.select(options));
+   * assertEquals(':', buffer.readByte());
+   * assertEquals(50L, buffer.readDecimalLong());
+   * assertEquals('\n', buffer.readByte());
+   * ```
+   */
+  fun <T : Any> select(options: TypedOptions<T>): T?
+
   /** Removes all bytes from this and returns them as a byte array. */
   fun readByteArray(): ByteArray
 
@@ -307,7 +347,8 @@ expect sealed interface BufferedSource : Source {
   /**
    * Removes all bytes from this, decodes them as UTF-8, and returns the string. Returns the empty
    * string if this source is empty.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeUtf8("Uh uh uh!")
    *     .writeByte(' ')
@@ -324,7 +365,8 @@ expect sealed interface BufferedSource : Source {
 
   /**
    * Removes `byteCount` bytes from this, decodes them as UTF-8, and returns the string.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeUtf8("Uh uh uh!")
    *     .writeByte(' ')
@@ -346,7 +388,8 @@ expect sealed interface BufferedSource : Source {
   /**
    * Removes and returns characters up to but not including the next line break. A line break is
    * either `"\n"` or `"\r\n"`; these characters are not included in the result.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer()
    *     .writeUtf8("I'm a hacker!\n")
    *     .writeUtf8("That's what I said: you're a nerd.\n")
@@ -394,7 +437,8 @@ expect sealed interface BufferedSource : Source {
    *
    * This method is safe. No bytes are discarded if the match fails, and the caller is free to try
    * another match:
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeUtf8("12345\r\n");
    *
@@ -428,7 +472,8 @@ expect sealed interface BufferedSource : Source {
    * Returns the index of the first `b` in the buffer at or after `fromIndex`. This expands the
    * buffer as necessary until `b` is found. This reads an unbounded number of bytes into the
    * buffer. Returns -1 if the stream is exhausted before the requested byte is found.
-   * ```
+   *
+   * ```java
    * Buffer buffer = new Buffer();
    * buffer.writeUtf8("Don't move! He can't see us if we don't move.");
    *
@@ -456,7 +501,8 @@ expect sealed interface BufferedSource : Source {
    * expands the buffer as necessary until `bytes` is found. This reads an unbounded number of
    * bytes into the buffer. Returns -1 if the stream is exhausted before the requested bytes are
    * found.
-   * ```
+   *
+   * ```java
    * ByteString MOVE = ByteString.encodeUtf8("move");
    *
    * Buffer buffer = new Buffer();
@@ -476,7 +522,8 @@ expect sealed interface BufferedSource : Source {
    * the bytes in `targetBytes`. This expands the buffer as necessary until a target byte is found.
    * This reads an unbounded number of bytes into the buffer. Returns -1 if the stream is exhausted
    * before the requested byte is found.
-   * ```
+   *
+   * ```java
    * ByteString ANY_VOWEL = ByteString.encodeUtf8("AEOIUaeoiu");
    *
    * Buffer buffer = new Buffer();
@@ -492,7 +539,8 @@ expect sealed interface BufferedSource : Source {
    * Returns true if the bytes at `offset` in this source equal `bytes`. This expands the buffer as
    * necessary until a byte does not match, all bytes are matched, or if the stream is exhausted
    * before enough bytes could determine a match.
-   * ```
+   *
+   * ```java
    * ByteString simonSays = ByteString.encodeUtf8("Simon says:");
    *
    * Buffer standOnOneLeg = new Buffer().writeUtf8("Simon says: Stand on one leg.");
@@ -517,7 +565,7 @@ expect sealed interface BufferedSource : Source {
    *
    * For example, we can use `peek()` to lookahead and read the same data multiple times.
    *
-   * ```
+   * ```kotlin
    * val buffer = Buffer()
    * buffer.writeUtf8("abcdefghi")
    *
diff --git a/okio/src/commonMain/kotlin/okio/ByteString.kt b/okio/src/commonMain/kotlin/okio/ByteString.kt
index 3f4fb82f..d482ad9a 100644
--- a/okio/src/commonMain/kotlin/okio/ByteString.kt
+++ b/okio/src/commonMain/kotlin/okio/ByteString.kt
@@ -16,7 +16,6 @@
 
 package okio
 
-import kotlin.jvm.JvmField
 import kotlin.jvm.JvmName
 import kotlin.jvm.JvmOverloads
 import kotlin.jvm.JvmStatic
@@ -183,7 +182,6 @@ internal constructor(data: ByteArray) : Comparable<ByteString> {
 
   companion object {
     /** A singleton empty `ByteString`. */
-    @JvmField
     val EMPTY: ByteString
 
     /** Returns a new byte string containing a clone of the bytes of `data`. */
diff --git a/okio/src/commonMain/kotlin/okio/FileSystem.kt b/okio/src/commonMain/kotlin/okio/FileSystem.kt
index 9535880b..5797e17b 100644
--- a/okio/src/commonMain/kotlin/okio/FileSystem.kt
+++ b/okio/src/commonMain/kotlin/okio/FileSystem.kt
@@ -79,8 +79,20 @@ package okio
  * because the `Paths.get()` function automatically uses the default (ie. system) file system.
  * In Okio's API paths are just identifiers; you must use a specific `FileSystem` object to do
  * I/O with.
+ *
+ * Closeable
+ * ---------
+ *
+ * Implementations of this interface may need to be closed to release resources.
+ *
+ * It is the file system implementor's responsibility to document whether a file system instance
+ * must be closed, and what happens to its open streams when the file system is closed. For example,
+ * the Java NIO FileSystem closes all of its open streams when the file system is closed.
+ *
+ * The built-in `FileSystem.SYSTEM` implementation does not need to be closed and closing it has no
+ * effect.
  */
-expect abstract class FileSystem() {
+expect abstract class FileSystem() : Closeable {
 
   /**
    * Resolves [path] against the current working directory and symlinks in this file system. The
@@ -376,6 +388,9 @@ expect abstract class FileSystem() {
   @Throws(IOException::class)
   abstract fun createSymlink(source: Path, target: Path)
 
+  @Throws(IOException::class)
+  override fun close()
+
   companion object {
     /**
      * Returns a writable temporary directory on [SYSTEM].
diff --git a/okio/src/commonMain/kotlin/okio/ForwardingFileSystem.kt b/okio/src/commonMain/kotlin/okio/ForwardingFileSystem.kt
index 3548b52b..cdacb80b 100644
--- a/okio/src/commonMain/kotlin/okio/ForwardingFileSystem.kt
+++ b/okio/src/commonMain/kotlin/okio/ForwardingFileSystem.kt
@@ -26,7 +26,7 @@ import kotlin.jvm.JvmName
  * confirm that your program behaves correctly even if its file system operations fail. For example,
  * this subclass fails every access of files named `unlucky.txt`:
  *
- * ```
+ * ```kotlin
  * val faultyFileSystem = object : ForwardingFileSystem(FileSystem.SYSTEM) {
  *   override fun onPathParameter(path: Path, functionName: String, parameterName: String): Path {
  *     if (path.name == "unlucky.txt") throw IOException("synthetic failure!")
@@ -37,7 +37,7 @@ import kotlin.jvm.JvmName
  *
  * You can fail specific operations by overriding them directly:
  *
- * ```
+ * ```kotlin
  * val faultyFileSystem = object : ForwardingFileSystem(FileSystem.SYSTEM) {
  *   override fun delete(path: Path) {
  *     throw IOException("synthetic failure!")
@@ -50,7 +50,7 @@ import kotlin.jvm.JvmName
  * You can extend this to verify which files your program accesses. This is a testing file system
  * that records accesses as they happen:
  *
- * ```
+ * ```kotlin
  * class LoggingFileSystem : ForwardingFileSystem(FileSystem.SYSTEM) {
  *   val log = mutableListOf<String>()
  *
@@ -63,7 +63,7 @@ import kotlin.jvm.JvmName
  *
  * This makes it easy for tests to assert exactly which files were accessed.
  *
- * ```
+ * ```kotlin
  * @Test
  * fun testMergeJsonReports() {
  *   createSampleJsonReports()
@@ -100,6 +100,10 @@ import kotlin.jvm.JvmName
  * **This class forwards only the abstract functions;** non-abstract functions delegate to the
  * other functions of this class. If desired, subclasses may override non-abstract functions to
  * forward them.
+ *
+ * ### Closeable
+ *
+ * Closing this file system closes the delegate file system.
  */
 abstract class ForwardingFileSystem(
   /** [FileSystem] to which this instance is delegating. */
@@ -238,5 +242,10 @@ abstract class ForwardingFileSystem(
     delegate.createSymlink(source, target)
   }
 
+  @Throws(IOException::class)
+  override fun close() {
+    delegate.close()
+  }
+
   override fun toString() = "${this::class.simpleName}($delegate)"
 }
diff --git a/okio/src/commonMain/kotlin/okio/HashingSink.kt b/okio/src/commonMain/kotlin/okio/HashingSink.kt
index d5b8f8db..19431698 100644
--- a/okio/src/commonMain/kotlin/okio/HashingSink.kt
+++ b/okio/src/commonMain/kotlin/okio/HashingSink.kt
@@ -22,7 +22,8 @@ package okio
  *
  * In this example we use `HashingSink` with a [BufferedSink] to make writing to the
  * sink easier.
- * ```
+ *
+ * ```java
  * HashingSink hashingSink = HashingSink.sha256(s);
  * BufferedSink bufferedSink = Okio.buffer(hashingSink);
  *
@@ -41,6 +42,11 @@ expect class HashingSink : Sink {
    */
   val hash: ByteString
 
+  override fun close()
+  override fun flush()
+  override fun timeout(): Timeout
+  override fun write(source: Buffer, byteCount: Long)
+
   companion object {
     /**
      * Returns a sink that uses the obsolete MD5 hash algorithm to produce 128-bit hashes.
diff --git a/okio/src/commonMain/kotlin/okio/HashingSource.kt b/okio/src/commonMain/kotlin/okio/HashingSource.kt
index 52905ea7..95bfe91a 100644
--- a/okio/src/commonMain/kotlin/okio/HashingSource.kt
+++ b/okio/src/commonMain/kotlin/okio/HashingSource.kt
@@ -23,7 +23,8 @@ package okio
  *
  * In this example we use `HashingSource` with a [BufferedSource] to make reading
  * from the source easier.
- * ```
+ *
+ * ```java
  * HashingSource hashingSource = HashingSource.sha256(rawSource);
  * BufferedSource bufferedSource = Okio.buffer(hashingSource);
  *
@@ -42,6 +43,10 @@ expect class HashingSource : Source {
    */
   val hash: ByteString
 
+  override fun close()
+  override fun read(sink: Buffer, byteCount: Long): Long
+  override fun timeout(): Timeout
+
   companion object {
     /**
      * Returns a source that uses the obsolete MD5 hash algorithm to produce 128-bit hashes.
diff --git a/okio/src/commonMain/kotlin/okio/Okio.kt b/okio/src/commonMain/kotlin/okio/Okio.kt
index 861d5112..a0a420bb 100644
--- a/okio/src/commonMain/kotlin/okio/Okio.kt
+++ b/okio/src/commonMain/kotlin/okio/Okio.kt
@@ -49,13 +49,13 @@ private class BlackholeSink : Sink {
 
 /** Execute [block] then close this. This will be closed even if [block] throws. */
 inline fun <T : Closeable?, R> T.use(block: (T) -> R): R {
-  var result: R? = null
   var thrown: Throwable? = null
 
-  try {
-    result = block(this)
+  val result = try {
+    block(this)
   } catch (t: Throwable) {
     thrown = t
+    null
   } finally {
     try {
       this?.close()
@@ -69,5 +69,6 @@ inline fun <T : Closeable?, R> T.use(block: (T) -> R): R {
   }
 
   if (thrown != null) throw thrown
-  return result!!
+  @Suppress("UNCHECKED_CAST")
+  return result as R
 }
diff --git a/okio/src/commonMain/kotlin/okio/Options.kt b/okio/src/commonMain/kotlin/okio/Options.kt
index e8dae6e1..8e8b4c4a 100644
--- a/okio/src/commonMain/kotlin/okio/Options.kt
+++ b/okio/src/commonMain/kotlin/okio/Options.kt
@@ -17,7 +17,11 @@ package okio
 
 import kotlin.jvm.JvmStatic
 
-/** An indexed set of values that may be read with [BufferedSource.select].  */
+/**
+ * An indexed set of values that may be read with [BufferedSource.select].
+ *
+ * Also consider [TypedOptions] to select a typed value _T_.
+ */
 class Options private constructor(
   internal val byteStrings: Array<out ByteString>,
   internal val trie: IntArray,
@@ -40,7 +44,7 @@ class Options private constructor(
       // indexes to the caller's indexes.
       val list = byteStrings.toMutableList()
       list.sort()
-      val indexes = mutableListOf(*byteStrings.map { -1 }.toTypedArray())
+      val indexes = MutableList(list.size) { -1 }
       byteStrings.forEachIndexed { callerIndex, byteString ->
         val sortedIndex = list.binarySearch(byteString)
         indexes[sortedIndex] = callerIndex
@@ -71,10 +75,8 @@ class Options private constructor(
       val trieBytes = Buffer()
       buildTrieRecursive(node = trieBytes, byteStrings = list, indexes = indexes)
 
-      val trie = IntArray(trieBytes.intCount.toInt())
-      var i = 0
-      while (!trieBytes.exhausted()) {
-        trie[i++] = trieBytes.readInt()
+      val trie = IntArray(trieBytes.intCount.toInt()) {
+        trieBytes.readInt()
       }
 
       return Options(byteStrings.copyOf() /* Defensive copy. */, trie)
diff --git a/okio/src/commonMain/kotlin/okio/RealBufferedSink.kt b/okio/src/commonMain/kotlin/okio/RealBufferedSink.kt
index 81032153..65554cbc 100644
--- a/okio/src/commonMain/kotlin/okio/RealBufferedSink.kt
+++ b/okio/src/commonMain/kotlin/okio/RealBufferedSink.kt
@@ -21,4 +21,30 @@ internal expect class RealBufferedSink(
 ) : BufferedSink {
   val sink: Sink
   var closed: Boolean
+
+  override val buffer: Buffer
+  override fun close()
+  override fun emit(): BufferedSink
+  override fun emitCompleteSegments(): BufferedSink
+  override fun flush()
+  override fun timeout(): Timeout
+  override fun write(byteString: ByteString): BufferedSink
+  override fun write(byteString: ByteString, offset: Int, byteCount: Int): BufferedSink
+  override fun write(source: Buffer, byteCount: Long)
+  override fun write(source: ByteArray): BufferedSink
+  override fun write(source: ByteArray, offset: Int, byteCount: Int): BufferedSink
+  override fun write(source: Source, byteCount: Long): BufferedSink
+  override fun writeAll(source: Source): Long
+  override fun writeByte(b: Int): BufferedSink
+  override fun writeDecimalLong(v: Long): BufferedSink
+  override fun writeHexadecimalUnsignedLong(v: Long): BufferedSink
+  override fun writeInt(i: Int): BufferedSink
+  override fun writeIntLe(i: Int): BufferedSink
+  override fun writeLong(v: Long): BufferedSink
+  override fun writeLongLe(v: Long): BufferedSink
+  override fun writeShort(s: Int): BufferedSink
+  override fun writeShortLe(s: Int): BufferedSink
+  override fun writeUtf8(string: String): BufferedSink
+  override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int): BufferedSink
+  override fun writeUtf8CodePoint(codePoint: Int): BufferedSink
 }
diff --git a/okio/src/commonMain/kotlin/okio/RealBufferedSource.kt b/okio/src/commonMain/kotlin/okio/RealBufferedSource.kt
index b6f7322e..a2e58291 100644
--- a/okio/src/commonMain/kotlin/okio/RealBufferedSource.kt
+++ b/okio/src/commonMain/kotlin/okio/RealBufferedSource.kt
@@ -21,4 +21,49 @@ internal expect class RealBufferedSource(
 ) : BufferedSource {
   val source: Source
   var closed: Boolean
+
+  override val buffer: Buffer
+  override fun close()
+  override fun exhausted(): Boolean
+  override fun indexOf(b: Byte): Long
+  override fun indexOf(b: Byte, fromIndex: Long): Long
+  override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long
+  override fun indexOf(bytes: ByteString): Long
+  override fun indexOf(bytes: ByteString, fromIndex: Long): Long
+  override fun indexOfElement(targetBytes: ByteString): Long
+  override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long
+  override fun peek(): BufferedSource
+  override fun rangeEquals(offset: Long, bytes: ByteString): Boolean
+  override fun rangeEquals(offset: Long, bytes: ByteString, bytesOffset: Int, byteCount: Int): Boolean
+  override fun read(sink: Buffer, byteCount: Long): Long
+  override fun read(sink: ByteArray): Int
+  override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int
+  override fun readAll(sink: Sink): Long
+  override fun readByte(): Byte
+  override fun readByteArray(): ByteArray
+  override fun readByteArray(byteCount: Long): ByteArray
+  override fun readByteString(): ByteString
+  override fun readByteString(byteCount: Long): ByteString
+  override fun readDecimalLong(): Long
+  override fun readFully(sink: Buffer, byteCount: Long)
+  override fun readFully(sink: ByteArray)
+  override fun readHexadecimalUnsignedLong(): Long
+  override fun readInt(): Int
+  override fun readIntLe(): Int
+  override fun readLong(): Long
+  override fun readLongLe(): Long
+  override fun readShort(): Short
+  override fun readShortLe(): Short
+  override fun readUtf8(): String
+  override fun readUtf8(byteCount: Long): String
+  override fun readUtf8CodePoint(): Int
+  override fun readUtf8Line(): String?
+  override fun readUtf8LineStrict(): String
+  override fun readUtf8LineStrict(limit: Long): String
+  override fun request(byteCount: Long): Boolean
+  override fun require(byteCount: Long)
+  override fun select(options: Options): Int
+  override fun <T : Any> select(options: TypedOptions<T>): T?
+  override fun skip(byteCount: Long)
+  override fun timeout(): Timeout
 }
diff --git a/okio/src/commonMain/kotlin/okio/TypedOptions.kt b/okio/src/commonMain/kotlin/okio/TypedOptions.kt
new file mode 100644
index 00000000..98a26313
--- /dev/null
+++ b/okio/src/commonMain/kotlin/okio/TypedOptions.kt
@@ -0,0 +1,51 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package okio
+
+import kotlin.jvm.JvmStatic
+
+/**
+ * A list of values that may be read with [BufferedSource.select].
+ *
+ * Also consider [Options] to select an integer index.
+ */
+class TypedOptions<T : Any>(
+  list: List<T>,
+  internal val options: Options,
+) : AbstractList<T>(), RandomAccess {
+  internal val list = list.toList() // Defensive copy.
+
+  init {
+    require(this.list.size == options.size)
+  }
+
+  override val size: Int
+    get() = list.size
+
+  override fun get(index: Int) = list[index]
+
+  companion object {
+    @JvmStatic
+    inline fun <T : Any> of(
+      values: Iterable<T>,
+      encode: (T) -> ByteString,
+    ): TypedOptions<T> {
+      val list = values.toList()
+      val options = Options.of(*Array(list.size) { encode(list[it]) })
+      return TypedOptions(list, options)
+    }
+  }
+}
diff --git a/okio/src/commonMain/kotlin/okio/Util.kt b/okio/src/commonMain/kotlin/okio/Util.kt
index bfd8fec1..9e6e9c50 100644
--- a/okio/src/commonMain/kotlin/okio/Util.kt
+++ b/okio/src/commonMain/kotlin/okio/Util.kt
@@ -18,7 +18,6 @@
 package okio
 
 import kotlin.jvm.JvmName
-import kotlin.native.concurrent.SharedImmutable
 import okio.internal.HEX_DIGIT_CHARS
 
 internal fun checkOffsetAndCount(size: Long, offset: Long, byteCount: Long) {
@@ -167,7 +166,6 @@ internal fun Long.toHexString(): String {
 // for them in the receiving function, then swap in the true default value.
 // https://youtrack.jetbrains.com/issue/KT-45542
 
-@SharedImmutable
 internal val DEFAULT__new_UnsafeCursor = Buffer.UnsafeCursor()
 internal fun resolveDefaultParameter(unsafeCursor: Buffer.UnsafeCursor): Buffer.UnsafeCursor {
   if (unsafeCursor === DEFAULT__new_UnsafeCursor) return Buffer.UnsafeCursor()
diff --git a/okio/src/commonMain/kotlin/okio/internal/Buffer.kt b/okio/src/commonMain/kotlin/okio/internal/Buffer.kt
index 2270fc1d..36315c17 100644
--- a/okio/src/commonMain/kotlin/okio/internal/Buffer.kt
+++ b/okio/src/commonMain/kotlin/okio/internal/Buffer.kt
@@ -21,7 +21,6 @@
 package okio.internal
 
 import kotlin.jvm.JvmName
-import kotlin.native.concurrent.SharedImmutable
 import okio.ArrayIndexOutOfBoundsException
 import okio.Buffer
 import okio.Buffer.UnsafeCursor
@@ -41,7 +40,6 @@ import okio.minOf
 import okio.resolveDefaultParameter
 import okio.toHexString
 
-@SharedImmutable
 internal val HEX_DIGIT_BYTES = "0123456789abcdef".asUtf8ToByteArray()
 
 // Threshold determined empirically via ReadByteStringBenchmark
@@ -461,63 +459,7 @@ internal inline fun Buffer.commonWriteDecimalLong(v: Long): Buffer {
     negative = true
   }
 
-  // Binary search for character width which favors matching lower numbers.
-  var width =
-    if (v < 100000000L) {
-      if (v < 10000L) {
-        if (v < 100L) {
-          if (v < 10L) {
-            1
-          } else {
-            2
-          }
-        } else if (v < 1000L) {
-          3
-        } else {
-          4
-        }
-      } else if (v < 1000000L) {
-        if (v < 100000L) {
-          5
-        } else {
-          6
-        }
-      } else if (v < 10000000L) {
-        7
-      } else {
-        8
-      }
-    } else if (v < 1000000000000L) {
-      if (v < 10000000000L) {
-        if (v < 1000000000L) {
-          9
-        } else {
-          10
-        }
-      } else if (v < 100000000000L) {
-        11
-      } else {
-        12
-      }
-    } else if (v < 1000000000000000L) {
-      if (v < 10000000000000L) {
-        13
-      } else if (v < 100000000000000L) {
-        14
-      } else {
-        15
-      }
-    } else if (v < 100000000000000000L) {
-      if (v < 10000000000000000L) {
-        16
-      } else {
-        17
-      }
-    } else if (v < 1000000000000000000L) {
-      18
-    } else {
-      19
-    }
+  var width = countDigitsIn(v)
   if (negative) {
     ++width
   }
@@ -539,6 +481,34 @@ internal inline fun Buffer.commonWriteDecimalLong(v: Long): Buffer {
   return this
 }
 
+private fun countDigitsIn(v: Long): Int {
+  val guess = ((64 - v.countLeadingZeroBits()) * 10) ushr 5
+  return guess + (if (v > DigitCountToLargestValue[guess]) 1 else 0)
+}
+
+private val DigitCountToLargestValue = longArrayOf(
+  -1, // Every value has more than 0 digits.
+  9L, // For 1 digit (index 1), the largest value is 9.
+  99L,
+  999L,
+  9999L,
+  99999L,
+  999999L,
+  9999999L,
+  99999999L,
+  999999999L,
+  9999999999L,
+  99999999999L,
+  999999999999L,
+  9999999999999L,
+  99999999999999L,
+  999999999999999L,
+  9999999999999999L,
+  99999999999999999L,
+  999999999999999999L, // For 18 digits (index 18), the largest value is 999999999999999999.
+  Long.MAX_VALUE, // For 19 digits (index 19), the largest value is MAX_VALUE.
+)
+
 internal inline fun Buffer.commonWriteHexadecimalUnsignedLong(v: Long): Buffer {
   var v = v
   if (v == 0L) {
diff --git a/okio/src/commonMain/kotlin/okio/internal/BufferedSource.kt b/okio/src/commonMain/kotlin/okio/internal/BufferedSource.kt
new file mode 100644
index 00000000..82ef82b7
--- /dev/null
+++ b/okio/src/commonMain/kotlin/okio/internal/BufferedSource.kt
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:JvmName("-BufferedSource") // A leading '-' hides this class from Java.
+
+package okio.internal
+
+import kotlin.jvm.JvmName
+import okio.BufferedSource
+import okio.TypedOptions
+
+internal inline fun <T : Any> BufferedSource.commonSelect(options: TypedOptions<T>): T? {
+  return when (val index = select(options.options)) {
+    -1 -> null
+    else -> options[index]
+  }
+}
diff --git a/okio/src/commonMain/kotlin/okio/internal/ByteString.kt b/okio/src/commonMain/kotlin/okio/internal/ByteString.kt
index 311c17e5..d8899acd 100644
--- a/okio/src/commonMain/kotlin/okio/internal/ByteString.kt
+++ b/okio/src/commonMain/kotlin/okio/internal/ByteString.kt
@@ -18,7 +18,6 @@
 package okio.internal
 
 import kotlin.jvm.JvmName
-import kotlin.native.concurrent.SharedImmutable
 import okio.BASE64_URL_SAFE
 import okio.Buffer
 import okio.ByteString
@@ -55,7 +54,6 @@ internal inline fun ByteString.commonBase64(): String = data.encodeBase64()
 @Suppress("NOTHING_TO_INLINE")
 internal inline fun ByteString.commonBase64Url() = data.encodeBase64(map = BASE64_URL_SAFE)
 
-@SharedImmutable
 internal val HEX_DIGIT_CHARS =
   charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
 
diff --git a/okio/src/commonMain/kotlin/okio/internal/Path.kt b/okio/src/commonMain/kotlin/okio/internal/Path.kt
index 6910e30b..c5aeb7a7 100644
--- a/okio/src/commonMain/kotlin/okio/internal/Path.kt
+++ b/okio/src/commonMain/kotlin/okio/internal/Path.kt
@@ -18,26 +18,20 @@
 package okio.internal
 
 import kotlin.jvm.JvmName
-import kotlin.native.concurrent.SharedImmutable
 import okio.Buffer
 import okio.ByteString
 import okio.ByteString.Companion.encodeUtf8
 import okio.Path
 import okio.Path.Companion.toPath
 
-@SharedImmutable
 private val SLASH = "/".encodeUtf8()
 
-@SharedImmutable
 private val BACKSLASH = "\\".encodeUtf8()
 
-@SharedImmutable
 private val ANY_SLASH = "/\\".encodeUtf8()
 
-@SharedImmutable
 private val DOT = ".".encodeUtf8()
 
-@SharedImmutable
 private val DOT_DOT = "..".encodeUtf8()
 
 @Suppress("NOTHING_TO_INLINE")
@@ -250,6 +244,11 @@ internal inline fun Path.commonRelativeTo(other: Path): Path {
     "Impossible relative path to resolve: $this and $other"
   }
 
+  if (other.bytes == DOT) {
+    // Anything relative to "." is itself!
+    return this
+  }
+
   val buffer = Buffer()
   val slash = other.slash ?: slash ?: Path.DIRECTORY_SEPARATOR.toSlash()
   for (i in firstNewSegmentIndex until otherSegments.size) {
diff --git a/okio/src/commonMain/kotlin/okio/internal/RealBufferedSource.kt b/okio/src/commonMain/kotlin/okio/internal/RealBufferedSource.kt
index 5b0d55b2..6a919e5f 100644
--- a/okio/src/commonMain/kotlin/okio/internal/RealBufferedSource.kt
+++ b/okio/src/commonMain/kotlin/okio/internal/RealBufferedSource.kt
@@ -39,6 +39,7 @@ internal inline fun RealBufferedSource.commonRead(sink: Buffer, byteCount: Long)
   check(!closed) { "closed" }
 
   if (buffer.size == 0L) {
+    if (byteCount == 0L) return 0L
     val read = source.read(buffer, Segment.SIZE.toLong())
     if (read == -1L) return -1L
   }
@@ -134,6 +135,7 @@ internal inline fun RealBufferedSource.commonRead(sink: ByteArray, offset: Int,
   checkOffsetAndCount(sink.size.toLong(), offset.toLong(), byteCount.toLong())
 
   if (buffer.size == 0L) {
+    if (byteCount == 0) return 0
     val read = source.read(buffer, Segment.SIZE.toLong())
     if (read == -1L) return -1
   }
diff --git a/okio/src/commonTest/kotlin/okio/BufferedSinkFactory.kt b/okio/src/commonTest/kotlin/okio/BufferedSinkFactory.kt
index 8f4f29ae..6793ec0c 100644
--- a/okio/src/commonTest/kotlin/okio/BufferedSinkFactory.kt
+++ b/okio/src/commonTest/kotlin/okio/BufferedSinkFactory.kt
@@ -16,21 +16,19 @@
 
 package okio
 
-internal interface BufferedSinkFactory {
-
-  fun create(data: Buffer): BufferedSink
-
-  companion object {
-    val BUFFER: BufferedSinkFactory = object : BufferedSinkFactory {
-      override fun create(data: Buffer): BufferedSink {
-        return data
-      }
+enum class BufferedSinkFactory {
+  BasicBuffer {
+    override fun create(data: Buffer): BufferedSink {
+      return data
     }
+  },
 
-    val REAL_BUFFERED_SINK: BufferedSinkFactory = object : BufferedSinkFactory {
-      override fun create(data: Buffer): BufferedSink {
-        return (data as Sink).buffer()
-      }
+  SinkBuffer {
+    override fun create(data: Buffer): BufferedSink {
+      return (data as Sink).buffer()
     }
-  }
+  },
+  ;
+
+  abstract fun create(data: Buffer): BufferedSink
 }
diff --git a/okio/src/commonTest/kotlin/okio/BufferedSourceFactory.kt b/okio/src/commonTest/kotlin/okio/BufferedSourceFactory.kt
index 173bb841..a6425ffb 100644
--- a/okio/src/commonTest/kotlin/okio/BufferedSourceFactory.kt
+++ b/okio/src/commonTest/kotlin/okio/BufferedSourceFactory.kt
@@ -16,135 +16,115 @@
 
 package okio
 
-interface BufferedSourceFactory {
-  class Pipe(
-    var sink: BufferedSink,
-    var source: BufferedSource,
-  )
-
-  val isOneByteAtATime: Boolean
-
-  fun pipe(): Pipe
-
-  companion object {
-    val BUFFER: BufferedSourceFactory = object : BufferedSourceFactory {
-
-      override val isOneByteAtATime: Boolean
-        get() = false
-
-      override fun pipe(): Pipe {
-        val buffer = Buffer()
-        return Pipe(
-          buffer,
-          buffer,
-        )
-      }
+enum class BufferedSourceFactory {
+  NewBuffer {
+    override val isOneByteAtATime: Boolean
+      get() = false
+
+    override fun pipe(): Pipe {
+      val buffer = Buffer()
+      return Pipe(
+        buffer,
+        buffer,
+      )
     }
-
-    val REAL_BUFFERED_SOURCE: BufferedSourceFactory = object :
-      BufferedSourceFactory {
-
-      override val isOneByteAtATime: Boolean
-        get() = false
-
-      override fun pipe(): Pipe {
-        val buffer = Buffer()
-        return Pipe(
-          buffer,
-          (buffer as Source).buffer(),
-        )
-      }
+  },
+
+  SourceBuffer {
+    override val isOneByteAtATime: Boolean
+      get() = false
+
+    override fun pipe(): Pipe {
+      val buffer = Buffer()
+      return Pipe(
+        buffer,
+        (buffer as Source).buffer(),
+      )
     }
-
-    /**
-     * A factory deliberately written to create buffers whose internal segments are always 1 byte
-     * long. We like testing with these segments because are likely to trigger bugs!
-     */
-    val ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE: BufferedSourceFactory = object :
-      BufferedSourceFactory {
-
-      override val isOneByteAtATime: Boolean
-        get() = true
-
-      override fun pipe(): Pipe {
-        val buffer = Buffer()
-        return Pipe(
-          buffer,
-          object : Source by buffer {
-            override fun read(sink: Buffer, byteCount: Long): Long {
-              // Read one byte into a new buffer, then clone it so that the segment is shared.
-              // Shared segments cannot be compacted so we'll get a long chain of short segments.
+  },
+
+  /**
+   * A factory deliberately written to create buffers whose internal segments are always 1 byte
+   * long. We like testing with these segments because are likely to trigger bugs!
+   */
+  OneByteAtATimeSource {
+    override val isOneByteAtATime: Boolean
+      get() = true
+
+    override fun pipe(): Pipe {
+      val buffer = Buffer()
+      return Pipe(
+        buffer,
+        object : Source by buffer {
+          override fun read(sink: Buffer, byteCount: Long): Long {
+            // Read one byte into a new buffer, then clone it so that the segment is shared.
+            // Shared segments cannot be compacted so we'll get a long chain of short segments.
+            val box = Buffer()
+            val result = buffer.read(box, minOf(byteCount, 1L))
+            if (result > 0L) sink.write(box.copy(), result)
+            return result
+          }
+        }.buffer(),
+      )
+    }
+  },
+
+  OneByteAtATimeSink {
+    override val isOneByteAtATime: Boolean
+      get() = true
+
+    override fun pipe(): Pipe {
+      val buffer = Buffer()
+      return Pipe(
+        object : Sink by buffer {
+          override fun write(source: Buffer, byteCount: Long) {
+            // Write each byte into a new buffer, then clone it so that the segments are shared.
+            // Shared segments cannot be compacted so we'll get a long chain of short segments.
+            for (i in 0 until byteCount) {
               val box = Buffer()
-              val result = buffer.read(box, minOf(byteCount, 1L))
-              if (result > 0L) sink.write(box.copy(), result)
-              return result
+              box.write(source, 1)
+              buffer.write(box.copy(), 1)
             }
-          }.buffer(),
-        )
-      }
+          }
+        }.buffer(),
+        buffer,
+      )
     }
-
-    val ONE_BYTE_AT_A_TIME_BUFFER: BufferedSourceFactory = object :
-      BufferedSourceFactory {
-
-      override val isOneByteAtATime: Boolean
-        get() = true
-
-      override fun pipe(): Pipe {
-        val buffer = Buffer()
-        return Pipe(
-          object : Sink by buffer {
-            override fun write(source: Buffer, byteCount: Long) {
-              // Write each byte into a new buffer, then clone it so that the segments are shared.
-              // Shared segments cannot be compacted so we'll get a long chain of short segments.
-              for (i in 0 until byteCount) {
-                val box = Buffer()
-                box.write(source, 1)
-                buffer.write(box.copy(), 1)
-              }
-            }
-          }.buffer(),
-          buffer,
-        )
-      }
+  },
+
+  PeekBuffer {
+    override val isOneByteAtATime: Boolean
+      get() = false
+
+    override fun pipe(): Pipe {
+      val buffer = Buffer()
+      return Pipe(
+        buffer,
+        buffer.peek(),
+      )
     }
-
-    val PEEK_BUFFER: BufferedSourceFactory = object : BufferedSourceFactory {
-
-      override val isOneByteAtATime: Boolean
-        get() = false
-
-      override fun pipe(): Pipe {
-        val buffer = Buffer()
-        return Pipe(
-          buffer,
-          buffer.peek(),
-        )
-      }
+  },
+
+  PeekBufferedSource {
+    override val isOneByteAtATime: Boolean
+      get() = false
+
+    override fun pipe(): Pipe {
+      val buffer = Buffer()
+      return Pipe(
+        buffer,
+        (buffer as Source).buffer().peek(),
+      )
     }
+  },
+  ;
 
-    val PEEK_BUFFERED_SOURCE: BufferedSourceFactory = object :
-      BufferedSourceFactory {
+  abstract val isOneByteAtATime: Boolean
 
-      override val isOneByteAtATime: Boolean
-        get() = false
+  abstract fun pipe(): Pipe
 
-      override fun pipe(): Pipe {
-        val buffer = Buffer()
-        return Pipe(
-          buffer,
-          (buffer as Source).buffer().peek(),
-        )
-      }
-    }
-
-    val PARAMETERIZED_TEST_VALUES = mutableListOf<Array<Any>>(
-      arrayOf(BUFFER),
-      arrayOf(REAL_BUFFERED_SOURCE),
-      arrayOf(ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE),
-      arrayOf(ONE_BYTE_AT_A_TIME_BUFFER),
-      arrayOf(PEEK_BUFFER),
-      arrayOf(PEEK_BUFFERED_SOURCE),
-    )
-  }
+  class Pipe(
+    var sink: BufferedSink,
+    var source: BufferedSource,
+  )
 }
diff --git a/okio/src/commonTest/kotlin/okio/ByteStringFactory.kt b/okio/src/commonTest/kotlin/okio/ByteStringFactory.kt
index bbf6cc6d..92ee5c44 100644
--- a/okio/src/commonTest/kotlin/okio/ByteStringFactory.kt
+++ b/okio/src/commonTest/kotlin/okio/ByteStringFactory.kt
@@ -20,34 +20,32 @@ import okio.ByteString.Companion.decodeHex
 import okio.ByteString.Companion.encodeUtf8
 import okio.internal.commonAsUtf8ToByteArray
 
-internal interface ByteStringFactory {
-  fun decodeHex(hex: String): ByteString
-
-  fun encodeUtf8(s: String): ByteString
-
-  companion object {
-    val BYTE_STRING: ByteStringFactory = object : ByteStringFactory {
-      override fun decodeHex(hex: String) = hex.decodeHex()
-      override fun encodeUtf8(s: String) = s.encodeUtf8()
-    }
-
-    val SEGMENTED_BYTE_STRING: ByteStringFactory = object : ByteStringFactory {
-      override fun decodeHex(hex: String) = Buffer().apply { write(hex.decodeHex()) }.snapshot()
-      override fun encodeUtf8(s: String) = Buffer().apply { writeUtf8(s) }.snapshot()
-    }
-
-    val ONE_BYTE_PER_SEGMENT: ByteStringFactory = object : ByteStringFactory {
-      override fun decodeHex(hex: String) = makeSegments(hex.decodeHex())
-      override fun encodeUtf8(s: String) = makeSegments(s.encodeUtf8())
-    }
-
-    // For Kotlin/JVM, the native Java UTF-8 encoder is used. This forces
-    // testing of the Okio encoder used for Kotlin/JS and Kotlin/Native to be
-    // tested on JVM as well.
-    val OKIO_ENCODER: ByteStringFactory = object : ByteStringFactory {
-      override fun decodeHex(hex: String) = hex.decodeHex()
-      override fun encodeUtf8(s: String) =
-        ByteString.of(*s.commonAsUtf8ToByteArray())
-    }
-  }
+enum class ByteStringFactory {
+  BasicByteString {
+    override fun decodeHex(hex: String) = hex.decodeHex()
+    override fun encodeUtf8(s: String) = s.encodeUtf8()
+  },
+
+  SegmentedByteString {
+    override fun decodeHex(hex: String) = Buffer().apply { write(hex.decodeHex()) }.snapshot()
+    override fun encodeUtf8(s: String) = Buffer().apply { writeUtf8(s) }.snapshot()
+  },
+
+  OneBytePerSegment {
+    override fun decodeHex(hex: String) = makeSegments(hex.decodeHex())
+    override fun encodeUtf8(s: String) = makeSegments(s.encodeUtf8())
+  },
+
+  // For Kotlin/JVM, the native Java UTF-8 encoder is used. This forces
+  // testing of the Okio encoder used for Kotlin/JS and Kotlin/Native to be
+  // tested on JVM as well.
+  OkioUtf8Encoder {
+    override fun decodeHex(hex: String) = hex.decodeHex()
+    override fun encodeUtf8(s: String) = ByteString.of(*s.commonAsUtf8ToByteArray())
+  },
+  ;
+
+  abstract fun decodeHex(hex: String): ByteString
+
+  abstract fun encodeUtf8(s: String): ByteString
 }
diff --git a/okio/src/commonTest/kotlin/okio/ByteStringTest.kt b/okio/src/commonTest/kotlin/okio/ByteStringTest.kt
index 9866e14b..da1a8988 100644
--- a/okio/src/commonTest/kotlin/okio/ByteStringTest.kt
+++ b/okio/src/commonTest/kotlin/okio/ByteStringTest.kt
@@ -16,6 +16,7 @@
 
 package okio
 
+import app.cash.burst.Burst
 import kotlin.random.Random
 import kotlin.test.Test
 import kotlin.test.assertEquals
@@ -31,12 +32,8 @@ import okio.ByteString.Companion.encodeUtf8
 import okio.ByteString.Companion.toByteString
 import okio.internal.commonAsUtf8ToByteArray
 
-class ByteStringTest : AbstractByteStringTest(ByteStringFactory.BYTE_STRING)
-class SegmentedByteStringTest : AbstractByteStringTest(ByteStringFactory.SEGMENTED_BYTE_STRING)
-class ByteStringOneBytePerSegmentTest : AbstractByteStringTest(ByteStringFactory.ONE_BYTE_PER_SEGMENT)
-class OkioEncoderTest : AbstractByteStringTest(ByteStringFactory.OKIO_ENCODER)
-
-abstract class AbstractByteStringTest internal constructor(
+@Burst
+class ByteStringTest(
   private val factory: ByteStringFactory,
 ) {
   @Test fun get() {
@@ -229,7 +226,7 @@ abstract class AbstractByteStringTest internal constructor(
   @Test fun toAsciiLowerCaseNoUppercase() {
     val s = factory.encodeUtf8("a1_+")
     assertEquals(s, s.toAsciiLowercase())
-    if (factory === ByteStringFactory.BYTE_STRING) {
+    if (factory === ByteStringFactory.BasicByteString) {
       assertSame(s, s.toAsciiLowercase())
     }
   }
diff --git a/okio/src/commonTest/kotlin/okio/AbstractBufferedSinkTest.kt b/okio/src/commonTest/kotlin/okio/CommonBufferedSinkTest.kt
similarity index 81%
rename from okio/src/commonTest/kotlin/okio/AbstractBufferedSinkTest.kt
rename to okio/src/commonTest/kotlin/okio/CommonBufferedSinkTest.kt
index e922d5f2..e48274c9 100644
--- a/okio/src/commonTest/kotlin/okio/AbstractBufferedSinkTest.kt
+++ b/okio/src/commonTest/kotlin/okio/CommonBufferedSinkTest.kt
@@ -16,16 +16,15 @@
 
 package okio
 
+import app.cash.burst.Burst
 import kotlin.test.Test
 import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
 import okio.ByteString.Companion.decodeHex
 import okio.ByteString.Companion.encodeUtf8
 
-class BufferSinkTest : AbstractBufferedSinkTest(BufferedSinkFactory.BUFFER)
-class RealBufferedSinkTest : AbstractBufferedSinkTest(BufferedSinkFactory.REAL_BUFFERED_SINK)
-
-abstract class AbstractBufferedSinkTest internal constructor(
+@Burst
+class CommonBufferedSinkTest(
   factory: BufferedSinkFactory,
 ) {
   private val data: Buffer = Buffer()
@@ -265,6 +264,42 @@ abstract class AbstractBufferedSinkTest internal constructor(
     assertLongDecimalString("10000000000000000", 10000000000000000L)
     assertLongDecimalString("100000000000000000", 100000000000000000L)
     assertLongDecimalString("1000000000000000000", 1000000000000000000L)
+    assertLongDecimalString("-9", -9L)
+    assertLongDecimalString("-99", -99L)
+    assertLongDecimalString("-999", -999L)
+    assertLongDecimalString("-9999", -9999L)
+    assertLongDecimalString("-99999", -99999L)
+    assertLongDecimalString("-999999", -999999L)
+    assertLongDecimalString("-9999999", -9999999L)
+    assertLongDecimalString("-99999999", -99999999L)
+    assertLongDecimalString("-999999999", -999999999L)
+    assertLongDecimalString("-9999999999", -9999999999L)
+    assertLongDecimalString("-99999999999", -99999999999L)
+    assertLongDecimalString("-999999999999", -999999999999L)
+    assertLongDecimalString("-9999999999999", -9999999999999L)
+    assertLongDecimalString("-99999999999999", -99999999999999L)
+    assertLongDecimalString("-999999999999999", -999999999999999L)
+    assertLongDecimalString("-9999999999999999", -9999999999999999L)
+    assertLongDecimalString("-99999999999999999", -99999999999999999L)
+    assertLongDecimalString("-999999999999999999", -999999999999999999L)
+    assertLongDecimalString("-10", -10L)
+    assertLongDecimalString("-100", -100L)
+    assertLongDecimalString("-1000", -1000L)
+    assertLongDecimalString("-10000", -10000L)
+    assertLongDecimalString("-100000", -100000L)
+    assertLongDecimalString("-1000000", -1000000L)
+    assertLongDecimalString("-10000000", -10000000L)
+    assertLongDecimalString("-100000000", -100000000L)
+    assertLongDecimalString("-1000000000", -1000000000L)
+    assertLongDecimalString("-10000000000", -10000000000L)
+    assertLongDecimalString("-100000000000", -100000000000L)
+    assertLongDecimalString("-1000000000000", -1000000000000L)
+    assertLongDecimalString("-10000000000000", -10000000000000L)
+    assertLongDecimalString("-100000000000000", -100000000000000L)
+    assertLongDecimalString("-1000000000000000", -1000000000000000L)
+    assertLongDecimalString("-10000000000000000", -10000000000000000L)
+    assertLongDecimalString("-100000000000000000", -100000000000000000L)
+    assertLongDecimalString("-1000000000000000000", -1000000000000000000L)
   }
 
   private fun assertLongDecimalString(string: String, value: Long) {
diff --git a/okio/src/commonTest/kotlin/okio/AbstractBufferedSourceTest.kt b/okio/src/commonTest/kotlin/okio/CommonBufferedSourceTest.kt
similarity index 97%
rename from okio/src/commonTest/kotlin/okio/AbstractBufferedSourceTest.kt
rename to okio/src/commonTest/kotlin/okio/CommonBufferedSourceTest.kt
index 70d76cb6..fb8bdf24 100644
--- a/okio/src/commonTest/kotlin/okio/AbstractBufferedSourceTest.kt
+++ b/okio/src/commonTest/kotlin/okio/CommonBufferedSourceTest.kt
@@ -16,6 +16,7 @@
 
 package okio
 
+import app.cash.burst.Burst
 import kotlin.test.Test
 import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
@@ -24,14 +25,8 @@ import kotlin.test.assertTrue
 import okio.ByteString.Companion.decodeHex
 import okio.ByteString.Companion.encodeUtf8
 
-class BufferSourceTest : AbstractBufferedSourceTest(BufferedSourceFactory.BUFFER)
-class RealBufferedSourceTest : AbstractBufferedSourceTest(BufferedSourceFactory.REAL_BUFFERED_SOURCE)
-class OneByteAtATimeBufferedSourceTest : AbstractBufferedSourceTest(BufferedSourceFactory.ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE)
-class OneByteAtATimeBufferTest : AbstractBufferedSourceTest(BufferedSourceFactory.ONE_BYTE_AT_A_TIME_BUFFER)
-class PeekBufferTest : AbstractBufferedSourceTest(BufferedSourceFactory.PEEK_BUFFER)
-class PeekBufferedSourceTest : AbstractBufferedSourceTest(BufferedSourceFactory.PEEK_BUFFERED_SOURCE)
-
-abstract class AbstractBufferedSourceTest internal constructor(
+@Burst
+class CommonBufferedSourceTest(
   private val factory: BufferedSourceFactory,
 ) {
   private val sink: BufferedSink
@@ -289,7 +284,8 @@ abstract class AbstractBufferedSourceTest internal constructor(
 
     // Either 0 or -1 is reasonable here. For consistency with Android's
     // ByteArrayInputStream we return 0.
-    assertEquals(-1, source.read(sink, 0))
+    val readResult = source.read(sink, 0)
+    assertTrue(readResult == 0L || readResult == -1L)
     assertEquals(10, sink.size)
     assertTrue(source.exhausted())
   }
@@ -729,7 +725,7 @@ abstract class AbstractBufferedSourceTest internal constructor(
   }
 
   /**
-   * With [BufferedSourceFactory.ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE], this code was extremely slow.
+   * With [BufferedSourceFactory.OneByteAtATimeSource], this code was extremely slow.
    * https://github.com/square/okio/issues/171
    */
   @Test fun indexOfByteStringAcrossSegmentBoundaries() {
@@ -1246,7 +1242,7 @@ abstract class AbstractBufferedSourceTest internal constructor(
   }
 
   @Test fun rangeEqualsOnlyReadsUntilMismatch() {
-    if (factory !== BufferedSourceFactory.ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE) return // Other sources read in chunks anyway.
+    if (factory !== BufferedSourceFactory.OneByteAtATimeSource) return // Other sources read in chunks anyway.
 
     sink.writeUtf8("A man, a plan, a canal. Panama.")
     sink.emit()
diff --git a/okio/src/commonTest/kotlin/okio/CommonRealBufferedSourceTest.kt b/okio/src/commonTest/kotlin/okio/CommonRealBufferedSourceTest.kt
index 6756c5a5..6cdc1faf 100644
--- a/okio/src/commonTest/kotlin/okio/CommonRealBufferedSourceTest.kt
+++ b/okio/src/commonTest/kotlin/okio/CommonRealBufferedSourceTest.kt
@@ -153,4 +153,31 @@ class CommonRealBufferedSourceTest {
       "write($write3, ${write3.size})",
     )
   }
+
+  @Test fun readZeroBytesIntoBufferDoesNotRefillBuffer() {
+    val source = Buffer()
+    source.writeUtf8("abc")
+
+    val sink = Buffer()
+
+    val bufferedSource = (source as Source).buffer()
+    assertEquals(0L, bufferedSource.read(sink, 0L))
+
+    assertEquals(0, sink.size)
+    assertEquals(0, bufferedSource.buffer.size)
+    assertEquals(3, source.size)
+  }
+
+  @Test fun readZeroBytesIntoByteArrayDoesNotRefillBuffer() {
+    val source = Buffer()
+    source.writeUtf8("abc")
+
+    val sink = ByteArray(1024)
+
+    val bufferedSource = (source as Source).buffer()
+    assertEquals(0, bufferedSource.read(sink, 0, 0))
+
+    assertEquals(0, bufferedSource.buffer.size)
+    assertEquals(3, source.size)
+  }
 }
diff --git a/okio/src/commonTest/kotlin/okio/HashingTest.kt b/okio/src/commonTest/kotlin/okio/HashingTest.kt
index d290dc0c..edadf1e0 100644
--- a/okio/src/commonTest/kotlin/okio/HashingTest.kt
+++ b/okio/src/commonTest/kotlin/okio/HashingTest.kt
@@ -86,11 +86,11 @@ class HashingTest {
   }
 
   @Test fun hmacSha256EmptyBuffer() {
-    assertEquals(HMAC_SHA256_empty, Buffer().sha256())
+    assertEquals(HMAC_SHA256_empty, Buffer().hmacSha256(HMAC_KEY))
   }
 
   @Test fun hmacSha512EmptyBuffer() {
-    assertEquals(HMAC_SHA512_empty, Buffer().sha512())
+    assertEquals(HMAC_SHA512_empty, Buffer().hmacSha512(HMAC_KEY))
   }
 
   @Test fun bufferHashIsNotDestructive() {
@@ -131,11 +131,11 @@ class HashingTest {
     val SHA512_empty =
       "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".decodeHex()
     val HMAC_SHA256_empty =
-      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".decodeHex()
+      "9eeecd4a51b7e5cbfcd63bfa89130944d314c20b5c79979b124143fea006452a".decodeHex()
     val HMAC_SHA256_abc =
       "446d1715583cf1c30dfffbec0df4ff1f9d39d493211ab4c97ed6f3f0eb579b47".decodeHex()
     val HMAC_SHA512_empty =
-      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".decodeHex()
+      "c0bd671885fa6f2eade99e9b81bbc74b8c6aa9ee9e58d7e5c356022d2f0c1cd7a0c75124b88a1a021e4323ce781846d246a379df78c3b955461d1688cc873335".decodeHex()
     val HMAC_SHA512_abc =
       "24391790e7131050b05b606f2079a8983313894a1642a5ed97d094e7cabd00cfaa857d92c1f320ca3b6aaabb84c7155d6f1b10940dc133ded1b40baee8900be6".decodeHex()
     val r32k = randomBytes(32768)
diff --git a/okio/src/commonTest/kotlin/okio/OkioTesting.kt b/okio/src/commonTest/kotlin/okio/OkioTesting.kt
index 8dbdd2a1..62ac1ce5 100644
--- a/okio/src/commonTest/kotlin/okio/OkioTesting.kt
+++ b/okio/src/commonTest/kotlin/okio/OkioTesting.kt
@@ -16,6 +16,11 @@
 package okio
 
 import kotlin.random.Random
+import kotlin.test.assertTrue
+
+fun assertNoEmptySegments(buffer: Buffer) {
+  assertTrue(segmentSizes(buffer).all { it != 0 }, "Expected all segments to be non-empty")
+}
 
 fun segmentSizes(buffer: Buffer): List<Int> {
   var segment = buffer.head ?: return emptyList()
@@ -97,3 +102,5 @@ expect fun assertRelativeToFails(
   b: Path,
   sameAsNio: Boolean = true,
 ): IllegalArgumentException
+
+expect fun <T> withUtc(block: () -> T): T
diff --git a/okio/src/commonTest/kotlin/okio/PathTest.kt b/okio/src/commonTest/kotlin/okio/PathTest.kt
index cb2920d7..78309538 100644
--- a/okio/src/commonTest/kotlin/okio/PathTest.kt
+++ b/okio/src/commonTest/kotlin/okio/PathTest.kt
@@ -551,6 +551,24 @@ class PathTest {
     assertRelativeTo(f, e, ".".toPath())
   }
 
+  @Test
+  fun relativeUnixDot() {
+    val a = "Users/jesse/hello.txt".toPath()
+    val b = ".".toPath()
+    assertRelativeTo(a, b, "../../..".toPath(), sameAsNio = false)
+    assertRelativeTo(b, a, "Users/jesse/hello.txt".toPath(), sameAsNio = false)
+
+    val c = "Users/./jesse/hello.txt".toPath()
+    val d = "Admin/Secret".toPath()
+    assertRelativeTo(c, d, "../../../Admin/Secret".toPath())
+    assertRelativeTo(d, c, "../../Users/jesse/hello.txt".toPath())
+
+    val e = "Users/".toPath()
+    val f = "Users/.".toPath()
+    assertRelativeTo(e, f, ".".toPath())
+    assertRelativeTo(f, e, ".".toPath())
+  }
+
   // Note that we handle the normalized version of the paths when computing relative paths.
   @Test
   fun relativeToUnnormalizedPath() {
diff --git a/okio/src/commonTest/kotlin/okio/TypedOptionsTest.kt b/okio/src/commonTest/kotlin/okio/TypedOptionsTest.kt
new file mode 100644
index 00000000..524bf4f8
--- /dev/null
+++ b/okio/src/commonTest/kotlin/okio/TypedOptionsTest.kt
@@ -0,0 +1,90 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertFailsWith
+import okio.ByteString.Companion.encodeUtf8
+
+class TypedOptionsTest {
+  @Test
+  fun happyPath() {
+    val colors = listOf("Red", "Green", "Blue")
+    val colorOptions = TypedOptions.of(colors) { it.lowercase().encodeUtf8() }
+    val buffer = Buffer().writeUtf8("bluegreenyellow")
+    assertEquals("Blue", buffer.select(colorOptions))
+    assertEquals("greenyellow", buffer.snapshot().utf8())
+    assertEquals("Green", buffer.select(colorOptions))
+    assertEquals("yellow", buffer.snapshot().utf8())
+    assertEquals(null, buffer.select(colorOptions))
+    assertEquals("yellow", buffer.snapshot().utf8())
+  }
+
+  @Test
+  fun typedOptionsConstructor() {
+    val colors = listOf("Red", "Green", "Blue")
+    val colorOptions = TypedOptions(
+      colors,
+      Options.of("red".encodeUtf8(), "green".encodeUtf8(), "blue".encodeUtf8()),
+    )
+    val buffer = Buffer().writeUtf8("bluegreenyellow")
+    assertEquals("Blue", buffer.select(colorOptions))
+    assertEquals("greenyellow", buffer.snapshot().utf8())
+    assertEquals("Green", buffer.select(colorOptions))
+    assertEquals("yellow", buffer.snapshot().utf8())
+    assertEquals(null, buffer.select(colorOptions))
+    assertEquals("yellow", buffer.snapshot().utf8())
+  }
+
+  @Test
+  fun typedOptionsConstructorEnforcesSizeMatch() {
+    val colors = listOf("Red", "Green", "Blue")
+    assertFailsWith<IllegalArgumentException> {
+      TypedOptions(
+        colors,
+        Options.of("red".encodeUtf8(), "green".encodeUtf8()),
+      )
+    }
+  }
+
+  @Test
+  fun listFunctionsWork() {
+    val colors = listOf("Red", "Green", "Blue")
+    val colorOptions = TypedOptions.of(colors) { it.lowercase().encodeUtf8() }
+    assertEquals(3, colorOptions.size)
+    assertEquals("Red", colorOptions[0])
+    assertEquals("Green", colorOptions[1])
+    assertEquals("Blue", colorOptions[2])
+    assertFailsWith<IndexOutOfBoundsException> {
+      colorOptions[3]
+    }
+  }
+
+  /**
+   * Confirm we can mutate the collection used to create our [TypedOptions] without corrupting its
+   * behavior.
+   */
+  @Test
+  fun safeToMutateSourceCollectionAfterConstruction() {
+    val colors = mutableListOf("Red", "Green")
+    val colorOptions = TypedOptions.of(colors) { it.lowercase().encodeUtf8() }
+    colors[0] = "Black"
+
+    val buffer = Buffer().writeUtf8("red")
+    assertEquals("Red", buffer.select(colorOptions))
+  }
+}
diff --git a/okio/src/jsMain/kotlin/okio/FileSystem.kt b/okio/src/jsMain/kotlin/okio/FileSystem.kt
index ea1bb4bf..51c16534 100644
--- a/okio/src/jsMain/kotlin/okio/FileSystem.kt
+++ b/okio/src/jsMain/kotlin/okio/FileSystem.kt
@@ -23,7 +23,7 @@ import okio.internal.commonExists
 import okio.internal.commonListRecursively
 import okio.internal.commonMetadata
 
-actual abstract class FileSystem {
+actual abstract class FileSystem : Closeable {
   actual abstract fun canonicalize(path: Path): Path
 
   actual fun metadata(path: Path): FileMetadata = commonMetadata(path)
@@ -84,6 +84,9 @@ actual abstract class FileSystem {
 
   actual abstract fun createSymlink(source: Path, target: Path)
 
+  actual override fun close() {
+  }
+
   actual companion object {
     actual val SYSTEM_TEMPORARY_DIRECTORY: Path = tmpdir.toPath()
   }
diff --git a/okio/src/jvmMain/kotlin/okio/-JvmPlatform.kt b/okio/src/jvmMain/kotlin/okio/-JvmPlatform.kt
index cf263c45..9c750086 100644
--- a/okio/src/jvmMain/kotlin/okio/-JvmPlatform.kt
+++ b/okio/src/jvmMain/kotlin/okio/-JvmPlatform.kt
@@ -41,3 +41,7 @@ actual typealias EOFException = java.io.EOFException
 actual typealias FileNotFoundException = java.io.FileNotFoundException
 
 actual typealias Closeable = java.io.Closeable
+
+actual typealias Deflater = java.util.zip.Deflater
+
+actual typealias Inflater = java.util.zip.Inflater
diff --git a/okio/src/jvmMain/kotlin/okio/Buffer.kt b/okio/src/jvmMain/kotlin/okio/Buffer.kt
index 88dfaba7..bc4bd1bf 100644
--- a/okio/src/jvmMain/kotlin/okio/Buffer.kt
+++ b/okio/src/jvmMain/kotlin/okio/Buffer.kt
@@ -106,16 +106,16 @@ actual class Buffer : BufferedSource, BufferedSink, Cloneable, ByteChannel {
 
   actual override fun emit() = this // Nowhere to emit to!
 
-  override fun exhausted() = size == 0L
+  actual override fun exhausted() = size == 0L
 
   @Throws(EOFException::class)
-  override fun require(byteCount: Long) {
+  actual override fun require(byteCount: Long) {
     if (size < byteCount) throw EOFException()
   }
 
-  override fun request(byteCount: Long) = size >= byteCount
+  actual override fun request(byteCount: Long) = size >= byteCount
 
-  override fun peek(): BufferedSource {
+  actual override fun peek(): BufferedSource {
     return PeekSource(this).buffer()
   }
 
@@ -252,52 +252,54 @@ actual class Buffer : BufferedSource, BufferedSink, Cloneable, ByteChannel {
   actual fun completeSegmentByteCount(): Long = commonCompleteSegmentByteCount()
 
   @Throws(EOFException::class)
-  override fun readByte(): Byte = commonReadByte()
+  actual override fun readByte(): Byte = commonReadByte()
 
   @JvmName("getByte")
   actual operator fun get(pos: Long): Byte = commonGet(pos)
 
   @Throws(EOFException::class)
-  override fun readShort(): Short = commonReadShort()
+  actual override fun readShort(): Short = commonReadShort()
 
   @Throws(EOFException::class)
-  override fun readInt(): Int = commonReadInt()
+  actual override fun readInt(): Int = commonReadInt()
 
   @Throws(EOFException::class)
-  override fun readLong(): Long = commonReadLong()
+  actual override fun readLong(): Long = commonReadLong()
 
   @Throws(EOFException::class)
-  override fun readShortLe() = readShort().reverseBytes()
+  actual override fun readShortLe() = readShort().reverseBytes()
 
   @Throws(EOFException::class)
-  override fun readIntLe() = readInt().reverseBytes()
+  actual override fun readIntLe() = readInt().reverseBytes()
 
   @Throws(EOFException::class)
-  override fun readLongLe() = readLong().reverseBytes()
+  actual override fun readLongLe() = readLong().reverseBytes()
 
   @Throws(EOFException::class)
-  override fun readDecimalLong(): Long = commonReadDecimalLong()
+  actual override fun readDecimalLong(): Long = commonReadDecimalLong()
 
   @Throws(EOFException::class)
-  override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
+  actual override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
 
-  override fun readByteString(): ByteString = commonReadByteString()
+  actual override fun readByteString(): ByteString = commonReadByteString()
 
   @Throws(EOFException::class)
-  override fun readByteString(byteCount: Long) = commonReadByteString(byteCount)
+  actual override fun readByteString(byteCount: Long) = commonReadByteString(byteCount)
 
-  override fun select(options: Options): Int = commonSelect(options)
+  actual override fun select(options: Options): Int = commonSelect(options)
+
+  actual override fun <T : Any> select(options: TypedOptions<T>): T? = commonSelect(options)
 
   @Throws(EOFException::class)
-  override fun readFully(sink: Buffer, byteCount: Long): Unit = commonReadFully(sink, byteCount)
+  actual override fun readFully(sink: Buffer, byteCount: Long): Unit = commonReadFully(sink, byteCount)
 
   @Throws(IOException::class)
-  override fun readAll(sink: Sink): Long = commonReadAll(sink)
+  actual override fun readAll(sink: Sink): Long = commonReadAll(sink)
 
-  override fun readUtf8() = readString(size, Charsets.UTF_8)
+  actual override fun readUtf8() = readString(size, Charsets.UTF_8)
 
   @Throws(EOFException::class)
-  override fun readUtf8(byteCount: Long) = readString(byteCount, Charsets.UTF_8)
+  actual override fun readUtf8(byteCount: Long) = readString(byteCount, Charsets.UTF_8)
 
   override fun readString(charset: Charset) = readString(size, charset)
 
@@ -326,28 +328,28 @@ actual class Buffer : BufferedSource, BufferedSink, Cloneable, ByteChannel {
   }
 
   @Throws(EOFException::class)
-  override fun readUtf8Line(): String? = commonReadUtf8Line()
+  actual override fun readUtf8Line(): String? = commonReadUtf8Line()
 
   @Throws(EOFException::class)
-  override fun readUtf8LineStrict() = readUtf8LineStrict(Long.MAX_VALUE)
+  actual override fun readUtf8LineStrict() = readUtf8LineStrict(Long.MAX_VALUE)
 
   @Throws(EOFException::class)
-  override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
+  actual override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
 
   @Throws(EOFException::class)
-  override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
+  actual override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
 
-  override fun readByteArray() = commonReadByteArray()
+  actual override fun readByteArray() = commonReadByteArray()
 
   @Throws(EOFException::class)
-  override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
+  actual override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
 
-  override fun read(sink: ByteArray) = commonRead(sink)
+  actual override fun read(sink: ByteArray) = commonRead(sink)
 
   @Throws(EOFException::class)
-  override fun readFully(sink: ByteArray) = commonReadFully(sink)
+  actual override fun readFully(sink: ByteArray) = commonReadFully(sink)
 
-  override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
+  actual override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
     commonRead(sink, offset, byteCount)
 
   @Throws(IOException::class)
@@ -434,7 +436,7 @@ actual class Buffer : BufferedSource, BufferedSink, Cloneable, ByteChannel {
   }
 
   @Throws(IOException::class)
-  override fun writeAll(source: Source): Long = commonWriteAll(source)
+  actual override fun writeAll(source: Source): Long = commonWriteAll(source)
 
   @Throws(IOException::class)
   actual override fun write(source: Source, byteCount: Long): Buffer =
@@ -462,48 +464,49 @@ actual class Buffer : BufferedSource, BufferedSink, Cloneable, ByteChannel {
   internal actual fun writableSegment(minimumCapacity: Int): Segment =
     commonWritableSegment(minimumCapacity)
 
-  override fun write(source: Buffer, byteCount: Long): Unit = commonWrite(source, byteCount)
+  actual override fun write(source: Buffer, byteCount: Long): Unit = commonWrite(source, byteCount)
 
-  override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
+  actual override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
 
-  override fun indexOf(b: Byte) = indexOf(b, 0, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte) = indexOf(b, 0, Long.MAX_VALUE)
 
   /**
    * Returns the index of `b` in this at or beyond `fromIndex`, or -1 if this buffer does not
    * contain `b` in that range.
    */
-  override fun indexOf(b: Byte, fromIndex: Long) = indexOf(b, fromIndex, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte, fromIndex: Long) = indexOf(b, fromIndex, Long.MAX_VALUE)
 
-  override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long = commonIndexOf(b, fromIndex, toIndex)
+  actual override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
+    commonIndexOf(b, fromIndex, toIndex)
 
   @Throws(IOException::class)
-  override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0)
+  actual override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0)
 
   @Throws(IOException::class)
-  override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
+  actual override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
 
-  override fun indexOfElement(targetBytes: ByteString) = indexOfElement(targetBytes, 0L)
+  actual override fun indexOfElement(targetBytes: ByteString) = indexOfElement(targetBytes, 0L)
 
-  override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
+  actual override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
     commonIndexOfElement(targetBytes, fromIndex)
 
-  override fun rangeEquals(offset: Long, bytes: ByteString) =
+  actual override fun rangeEquals(offset: Long, bytes: ByteString) =
     rangeEquals(offset, bytes, 0, bytes.size)
 
-  override fun rangeEquals(
+  actual override fun rangeEquals(
     offset: Long,
     bytes: ByteString,
     bytesOffset: Int,
     byteCount: Int,
   ): Boolean = commonRangeEquals(offset, bytes, bytesOffset, byteCount)
 
-  override fun flush() {}
+  actual override fun flush() {}
 
   override fun isOpen() = true
 
-  override fun close() {}
+  actual override fun close() {}
 
-  override fun timeout() = Timeout.NONE
+  actual override fun timeout() = Timeout.NONE
 
   /**
    * Returns the 128-bit MD5 hash of this buffer.
diff --git a/okio/src/jvmMain/kotlin/okio/BufferedSource.kt b/okio/src/jvmMain/kotlin/okio/BufferedSource.kt
index ca6b94bf..45e6688a 100644
--- a/okio/src/jvmMain/kotlin/okio/BufferedSource.kt
+++ b/okio/src/jvmMain/kotlin/okio/BufferedSource.kt
@@ -79,6 +79,9 @@ actual sealed interface BufferedSource : Source, ReadableByteChannel {
   @Throws(IOException::class)
   actual fun select(options: Options): Int
 
+  @Throws(IOException::class)
+  actual fun <T : Any> select(options: TypedOptions<T>): T?
+
   @Throws(IOException::class)
   actual fun readByteArray(): ByteArray
 
diff --git a/okio/src/jvmMain/kotlin/okio/DeflaterSink.kt b/okio/src/jvmMain/kotlin/okio/DeflaterSink.kt
index 6fcf7d83..2114e1ea 100644
--- a/okio/src/jvmMain/kotlin/okio/DeflaterSink.kt
+++ b/okio/src/jvmMain/kotlin/okio/DeflaterSink.kt
@@ -13,42 +13,22 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
-@file:JvmName("-DeflaterSinkExtensions")
 @file:Suppress("NOTHING_TO_INLINE") // Aliases to public API.
 
 package okio
 
 import java.util.zip.Deflater
 
-/**
- * A sink that uses [DEFLATE](http://tools.ietf.org/html/rfc1951) to
- * compress data written to another source.
- *
- * ### Sync flush
- *
- * Aggressive flushing of this stream may result in reduced compression. Each
- * call to [flush] immediately compresses all currently-buffered data;
- * this early compression may be less effective than compression performed
- * without flushing.
- *
- * This is equivalent to using [Deflater] with the sync flush option.
- * This class does not offer any partial flush mechanism. For best performance,
- * only call [flush] when application behavior requires it.
- */
-class DeflaterSink
-/**
- * This internal constructor shares a buffer with its trusted caller.
- * In general we can't share a BufferedSource because the deflater holds input
- * bytes until they are inflated.
- */
-internal constructor(private val sink: BufferedSink, private val deflater: Deflater) : Sink {
-  constructor(sink: Sink, deflater: Deflater) : this(sink.buffer(), deflater)
+actual class DeflaterSink internal actual constructor(
+  private val sink: BufferedSink,
+  private val deflater: Deflater,
+) : Sink {
+  actual constructor(sink: Sink, deflater: Deflater) : this(sink.buffer(), deflater)
 
   private var closed = false
 
   @Throws(IOException::class)
-  override fun write(source: Buffer, byteCount: Long) {
+  actual override fun write(source: Buffer, byteCount: Long) {
     checkOffsetAndCount(source.size, 0, byteCount)
 
     var remaining = byteCount
@@ -108,18 +88,18 @@ internal constructor(private val sink: BufferedSink, private val deflater: Defla
   }
 
   @Throws(IOException::class)
-  override fun flush() {
+  actual override fun flush() {
     deflate(true)
     sink.flush()
   }
 
-  internal fun finishDeflate() {
+  internal actual fun finishDeflate() {
     deflater.finish()
     deflate(false)
   }
 
   @Throws(IOException::class)
-  override fun close() {
+  actual override fun close() {
     if (closed) return
 
     // Emit deflated data to the underlying sink. If this fails, we still need
@@ -148,15 +128,7 @@ internal constructor(private val sink: BufferedSink, private val deflater: Defla
     if (thrown != null) throw thrown
   }
 
-  override fun timeout(): Timeout = sink.timeout()
+  actual override fun timeout(): Timeout = sink.timeout()
 
   override fun toString() = "DeflaterSink($sink)"
 }
-
-/**
- * Returns an [DeflaterSink] that DEFLATE-compresses data to this [Sink] while writing.
- *
- * @see DeflaterSink
- */
-inline fun Sink.deflate(deflater: Deflater = Deflater()): DeflaterSink =
-  DeflaterSink(this, deflater)
diff --git a/okio/src/jvmMain/kotlin/okio/FileSystem.System.kt b/okio/src/jvmMain/kotlin/okio/FileSystem.System.kt
new file mode 100644
index 00000000..2958eea2
--- /dev/null
+++ b/okio/src/jvmMain/kotlin/okio/FileSystem.System.kt
@@ -0,0 +1,13 @@
+@file:JvmName("SystemFileSystem")
+
+package okio
+
+/*
+ * JVM and native platforms do offer a [SYSTEM] [FileSystem], however we cannot refine an 'expect' companion object.
+ * Therefore an extension property is provided, which on respective platforms (here JVM) will be shadowed by the
+ * original implementation.
+ */
+@Suppress("EXTENSION_SHADOWED_BY_MEMBER")
+actual inline val FileSystem.Companion.SYSTEM: FileSystem
+  @JvmSynthetic
+  get() = SYSTEM
diff --git a/okio/src/jvmMain/kotlin/okio/FileSystem.kt b/okio/src/jvmMain/kotlin/okio/FileSystem.kt
index 7a552cc5..eb97ca0b 100644
--- a/okio/src/jvmMain/kotlin/okio/FileSystem.kt
+++ b/okio/src/jvmMain/kotlin/okio/FileSystem.kt
@@ -25,7 +25,7 @@ import okio.internal.commonExists
 import okio.internal.commonListRecursively
 import okio.internal.commonMetadata
 
-actual abstract class FileSystem {
+actual abstract class FileSystem : Closeable {
   @Throws(IOException::class)
   actual abstract fun canonicalize(path: Path): Path
 
@@ -125,6 +125,10 @@ actual abstract class FileSystem {
   @Throws(IOException::class)
   actual abstract fun createSymlink(source: Path, target: Path)
 
+  @Throws(IOException::class)
+  actual override fun close() {
+  }
+
   actual companion object {
     /**
      * The current process's host file system. Use this instance directly, or dependency inject a
@@ -150,6 +154,8 @@ actual abstract class FileSystem {
      * In applications that compose multiple class loaders, this holds only the resources of
      * whichever class loader includes Okio classes. Use [ClassLoader.asResourceFileSystem] for the
      * resources of a specific class loader.
+     *
+     * This file system does not need to be closed. Calling its close function does nothing.
      */
     @JvmField
     val RESOURCES: FileSystem = ResourceFileSystem(
@@ -157,6 +163,12 @@ actual abstract class FileSystem {
       indexEagerly = false,
     )
 
+    /**
+     * Closing the returned file system will close the underlying [java.nio.file.FileSystem].
+     *
+     * Note that the [default file system][java.nio.file.FileSystems.getDefault] is not closeable
+     * and calling its close function will throw an [UnsupportedOperationException].
+     */
     @JvmName("get")
     @JvmStatic
     fun JavaNioFileSystem.asOkioFileSystem(): FileSystem = NioFileSystemWrappingFileSystem(this)
diff --git a/okio/src/jvmMain/kotlin/okio/HashingSink.kt b/okio/src/jvmMain/kotlin/okio/HashingSink.kt
index 0c097d20..8b178677 100644
--- a/okio/src/jvmMain/kotlin/okio/HashingSink.kt
+++ b/okio/src/jvmMain/kotlin/okio/HashingSink.kt
@@ -28,7 +28,8 @@ import javax.crypto.spec.SecretKeySpec
  *
  * In this example we use `HashingSink` with a [BufferedSink] to make writing to the
  * sink easier.
- * ```
+ *
+ * ```java
  * HashingSink hashingSink = HashingSink.sha256(s);
  * BufferedSink bufferedSink = Okio.buffer(hashingSink);
  *
@@ -65,7 +66,7 @@ actual class HashingSink : ForwardingSink, Sink { // Need to explicitly declare
   )
 
   @Throws(IOException::class)
-  override fun write(source: Buffer, byteCount: Long) {
+  actual override fun write(source: Buffer, byteCount: Long) {
     checkOffsetAndCount(source.size, 0, byteCount)
 
     // Hash byteCount bytes from the prefix of source.
diff --git a/okio/src/jvmMain/kotlin/okio/HashingSource.kt b/okio/src/jvmMain/kotlin/okio/HashingSource.kt
index e3d9191b..4d335589 100644
--- a/okio/src/jvmMain/kotlin/okio/HashingSource.kt
+++ b/okio/src/jvmMain/kotlin/okio/HashingSource.kt
@@ -29,7 +29,8 @@ import javax.crypto.spec.SecretKeySpec
  *
  * In this example we use `HashingSource` with a [BufferedSource] to make reading
  * from the source easier.
- * ```
+ *
+ * ```java
  * HashingSource hashingSource = HashingSource.sha256(rawSource);
  * BufferedSource bufferedSource = Okio.buffer(hashingSource);
  *
@@ -66,7 +67,7 @@ actual class HashingSource : ForwardingSource, Source { // Need to explicitly de
   )
 
   @Throws(IOException::class)
-  override fun read(sink: Buffer, byteCount: Long): Long {
+  actual override fun read(sink: Buffer, byteCount: Long): Long {
     val result = super.read(sink, byteCount)
 
     if (result != -1L) {
diff --git a/okio/src/jvmMain/kotlin/okio/InflaterSource.kt b/okio/src/jvmMain/kotlin/okio/InflaterSource.kt
index 1d72d9d4..a07873d1 100644
--- a/okio/src/jvmMain/kotlin/okio/InflaterSource.kt
+++ b/okio/src/jvmMain/kotlin/okio/InflaterSource.kt
@@ -14,7 +14,6 @@
  * limitations under the License.
  */
 
-@file:JvmName("-InflaterSourceExtensions")
 @file:Suppress("NOTHING_TO_INLINE") // Aliases to public API.
 
 package okio
@@ -23,16 +22,10 @@ import java.io.IOException
 import java.util.zip.DataFormatException
 import java.util.zip.Inflater
 
-/**
- * A source that uses [DEFLATE](http://tools.ietf.org/html/rfc1951) to decompress data read from
- * another source.
- */
-class InflaterSource
-/**
- * This internal constructor shares a buffer with its trusted caller. In general we can't share a
- * `BufferedSource` because the inflater holds input bytes until they are inflated.
- */
-internal constructor(private val source: BufferedSource, private val inflater: Inflater) : Source {
+actual class InflaterSource internal actual constructor(
+  private val source: BufferedSource,
+  private val inflater: Inflater,
+) : Source {
 
   /**
    * When we call Inflater.setInput(), the inflater keeps our byte array until it needs input again.
@@ -41,10 +34,10 @@ internal constructor(private val source: BufferedSource, private val inflater: I
   private var bufferBytesHeldByInflater = 0
   private var closed = false
 
-  constructor(source: Source, inflater: Inflater) : this(source.buffer(), inflater)
+  actual constructor(source: Source, inflater: Inflater) : this(source.buffer(), inflater)
 
   @Throws(IOException::class)
-  override fun read(sink: Buffer, byteCount: Long): Long {
+  actual override fun read(sink: Buffer, byteCount: Long): Long {
     while (true) {
       val bytesInflated = readOrInflate(sink, byteCount)
       if (bytesInflated > 0) return bytesInflated
@@ -126,21 +119,13 @@ internal constructor(private val source: BufferedSource, private val inflater: I
     source.skip(toRelease.toLong())
   }
 
-  override fun timeout(): Timeout = source.timeout()
+  actual override fun timeout(): Timeout = source.timeout()
 
   @Throws(IOException::class)
-  override fun close() {
+  actual override fun close() {
     if (closed) return
     inflater.end()
     closed = true
     source.close()
   }
 }
-
-/**
- * Returns an [InflaterSource] that DEFLATE-decompresses this [Source] while reading.
- *
- * @see InflaterSource
- */
-inline fun Source.inflate(inflater: Inflater = Inflater()): InflaterSource =
-  InflaterSource(this, inflater)
diff --git a/okio/src/jvmMain/kotlin/okio/JvmOkio.kt b/okio/src/jvmMain/kotlin/okio/JvmOkio.kt
index 614c48b9..44a046f2 100644
--- a/okio/src/jvmMain/kotlin/okio/JvmOkio.kt
+++ b/okio/src/jvmMain/kotlin/okio/JvmOkio.kt
@@ -224,9 +224,6 @@ fun Sink.hashingSink(digest: MessageDigest): HashingSink = HashingSink(this, dig
  */
 fun Source.hashingSource(digest: MessageDigest): HashingSource = HashingSource(this, digest)
 
-@Throws(IOException::class)
-fun FileSystem.openZip(zipPath: Path): FileSystem = okio.internal.openZip(zipPath, this)
-
 fun ClassLoader.asResourceFileSystem(): FileSystem = ResourceFileSystem(this, indexEagerly = true)
 
 /**
diff --git a/okio/src/jvmMain/kotlin/okio/NioFileSystemWrappingFileSystem.kt b/okio/src/jvmMain/kotlin/okio/NioFileSystemWrappingFileSystem.kt
index ddf11d81..c1a3c337 100644
--- a/okio/src/jvmMain/kotlin/okio/NioFileSystemWrappingFileSystem.kt
+++ b/okio/src/jvmMain/kotlin/okio/NioFileSystemWrappingFileSystem.kt
@@ -187,5 +187,9 @@ internal class NioFileSystemWrappingFileSystem(private val nioFileSystem: NioFil
     source.resolve().createSymbolicLinkPointingTo(target.resolve())
   }
 
+  override fun close() {
+    nioFileSystem.close()
+  }
+
   override fun toString() = nioFileSystem::class.simpleName!!
 }
diff --git a/okio/src/jvmMain/kotlin/okio/Pipe.kt b/okio/src/jvmMain/kotlin/okio/Pipe.kt
index 0fae4e03..25d9e1c3 100644
--- a/okio/src/jvmMain/kotlin/okio/Pipe.kt
+++ b/okio/src/jvmMain/kotlin/okio/Pipe.kt
@@ -172,6 +172,7 @@ class Pipe(internal val maxBufferSize: Long) {
       // Either the buffer is empty and we can swap and return. Or the buffer is non-empty and we
       // must copy it to sink without holding any locks, then try it all again.
       var closed = false
+      var done = false
       lateinit var sinkBuffer: Buffer
       lock.withLock {
         check(foldedSink == null) { "sink already folded" }
@@ -181,26 +182,30 @@ class Pipe(internal val maxBufferSize: Long) {
           throw IOException("canceled")
         }
 
+        closed = sinkClosed
         if (buffer.exhausted()) {
           sourceClosed = true
           foldedSink = sink
-          return@fold
+          done = true
+          return@withLock
         }
 
-        closed = sinkClosed
         sinkBuffer = Buffer()
         sinkBuffer.write(buffer, buffer.size)
         condition.signalAll() // Notify the sink that it can resume writing.
       }
 
-      var success = false
-      try {
-        sink.write(sinkBuffer, sinkBuffer.size)
+      if (done) {
         if (closed) {
           sink.close()
-        } else {
-          sink.flush()
         }
+        return
+      }
+
+      var success = false
+      try {
+        sink.write(sinkBuffer, sinkBuffer.size)
+        sink.flush()
         success = true
       } finally {
         if (!success) {
diff --git a/okio/src/jvmMain/kotlin/okio/RealBufferedSink.kt b/okio/src/jvmMain/kotlin/okio/RealBufferedSink.kt
index dece38d6..d1665ca7 100644
--- a/okio/src/jvmMain/kotlin/okio/RealBufferedSink.kt
+++ b/okio/src/jvmMain/kotlin/okio/RealBufferedSink.kt
@@ -47,20 +47,20 @@ internal actual class RealBufferedSink actual constructor(
   @JvmField actual var closed: Boolean = false
 
   @Suppress("OVERRIDE_BY_INLINE") // Prevent internal code from calling the getter.
-  override val buffer: Buffer
+  actual override val buffer: Buffer
     inline get() = bufferField
 
   override fun buffer() = bufferField
 
-  override fun write(source: Buffer, byteCount: Long) = commonWrite(source, byteCount)
-  override fun write(byteString: ByteString) = commonWrite(byteString)
-  override fun write(byteString: ByteString, offset: Int, byteCount: Int) =
+  actual override fun write(source: Buffer, byteCount: Long) = commonWrite(source, byteCount)
+  actual override fun write(byteString: ByteString) = commonWrite(byteString)
+  actual override fun write(byteString: ByteString, offset: Int, byteCount: Int) =
     commonWrite(byteString, offset, byteCount)
-  override fun writeUtf8(string: String) = commonWriteUtf8(string)
-  override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int) =
+  actual override fun writeUtf8(string: String) = commonWriteUtf8(string)
+  actual override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int) =
     commonWriteUtf8(string, beginIndex, endIndex)
 
-  override fun writeUtf8CodePoint(codePoint: Int) = commonWriteUtf8CodePoint(codePoint)
+  actual override fun writeUtf8CodePoint(codePoint: Int) = commonWriteUtf8CodePoint(codePoint)
 
   override fun writeString(string: String, charset: Charset): BufferedSink {
     check(!closed) { "closed" }
@@ -79,8 +79,8 @@ internal actual class RealBufferedSink actual constructor(
     return emitCompleteSegments()
   }
 
-  override fun write(source: ByteArray) = commonWrite(source)
-  override fun write(source: ByteArray, offset: Int, byteCount: Int) =
+  actual override fun write(source: ByteArray) = commonWrite(source)
+  actual override fun write(source: ByteArray, offset: Int, byteCount: Int) =
     commonWrite(source, offset, byteCount)
 
   override fun write(source: ByteBuffer): Int {
@@ -90,19 +90,19 @@ internal actual class RealBufferedSink actual constructor(
     return result
   }
 
-  override fun writeAll(source: Source) = commonWriteAll(source)
-  override fun write(source: Source, byteCount: Long): BufferedSink = commonWrite(source, byteCount)
-  override fun writeByte(b: Int) = commonWriteByte(b)
-  override fun writeShort(s: Int) = commonWriteShort(s)
-  override fun writeShortLe(s: Int) = commonWriteShortLe(s)
-  override fun writeInt(i: Int) = commonWriteInt(i)
-  override fun writeIntLe(i: Int) = commonWriteIntLe(i)
-  override fun writeLong(v: Long) = commonWriteLong(v)
-  override fun writeLongLe(v: Long) = commonWriteLongLe(v)
-  override fun writeDecimalLong(v: Long) = commonWriteDecimalLong(v)
-  override fun writeHexadecimalUnsignedLong(v: Long) = commonWriteHexadecimalUnsignedLong(v)
-  override fun emitCompleteSegments() = commonEmitCompleteSegments()
-  override fun emit() = commonEmit()
+  actual override fun writeAll(source: Source) = commonWriteAll(source)
+  actual override fun write(source: Source, byteCount: Long): BufferedSink = commonWrite(source, byteCount)
+  actual override fun writeByte(b: Int) = commonWriteByte(b)
+  actual override fun writeShort(s: Int) = commonWriteShort(s)
+  actual override fun writeShortLe(s: Int) = commonWriteShortLe(s)
+  actual override fun writeInt(i: Int) = commonWriteInt(i)
+  actual override fun writeIntLe(i: Int) = commonWriteIntLe(i)
+  actual override fun writeLong(v: Long) = commonWriteLong(v)
+  actual override fun writeLongLe(v: Long) = commonWriteLongLe(v)
+  actual override fun writeDecimalLong(v: Long) = commonWriteDecimalLong(v)
+  actual override fun writeHexadecimalUnsignedLong(v: Long) = commonWriteHexadecimalUnsignedLong(v)
+  actual override fun emitCompleteSegments() = commonEmitCompleteSegments()
+  actual override fun emit() = commonEmit()
 
   override fun outputStream(): OutputStream {
     return object : OutputStream() {
@@ -131,11 +131,11 @@ internal actual class RealBufferedSink actual constructor(
     }
   }
 
-  override fun flush() = commonFlush()
+  actual override fun flush() = commonFlush()
 
   override fun isOpen() = !closed
 
-  override fun close() = commonClose()
-  override fun timeout() = commonTimeout()
+  actual override fun close() = commonClose()
+  actual override fun timeout() = commonTimeout()
   override fun toString() = commonToString()
 }
diff --git a/okio/src/jvmMain/kotlin/okio/RealBufferedSource.kt b/okio/src/jvmMain/kotlin/okio/RealBufferedSource.kt
index 35f6c353..4b754b0a 100644
--- a/okio/src/jvmMain/kotlin/okio/RealBufferedSource.kt
+++ b/okio/src/jvmMain/kotlin/okio/RealBufferedSource.kt
@@ -17,6 +17,7 @@ package okio
 
 import java.io.IOException
 import java.io.InputStream
+import java.io.OutputStream
 import java.nio.ByteBuffer
 import java.nio.charset.Charset
 import okio.internal.commonClose
@@ -58,24 +59,25 @@ internal actual class RealBufferedSource actual constructor(
   @JvmField actual var closed: Boolean = false
 
   @Suppress("OVERRIDE_BY_INLINE") // Prevent internal code from calling the getter.
-  override val buffer: Buffer
+  actual override val buffer: Buffer
     inline get() = bufferField
 
   override fun buffer() = bufferField
 
-  override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
-  override fun exhausted(): Boolean = commonExhausted()
-  override fun require(byteCount: Long): Unit = commonRequire(byteCount)
-  override fun request(byteCount: Long): Boolean = commonRequest(byteCount)
-  override fun readByte(): Byte = commonReadByte()
-  override fun readByteString(): ByteString = commonReadByteString()
-  override fun readByteString(byteCount: Long): ByteString = commonReadByteString(byteCount)
-  override fun select(options: Options): Int = commonSelect(options)
-  override fun readByteArray(): ByteArray = commonReadByteArray()
-  override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
-  override fun read(sink: ByteArray): Int = read(sink, 0, sink.size)
-  override fun readFully(sink: ByteArray): Unit = commonReadFully(sink)
-  override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
+  actual override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
+  actual override fun exhausted(): Boolean = commonExhausted()
+  actual override fun require(byteCount: Long): Unit = commonRequire(byteCount)
+  actual override fun request(byteCount: Long): Boolean = commonRequest(byteCount)
+  actual override fun readByte(): Byte = commonReadByte()
+  actual override fun readByteString(): ByteString = commonReadByteString()
+  actual override fun readByteString(byteCount: Long): ByteString = commonReadByteString(byteCount)
+  actual override fun select(options: Options): Int = commonSelect(options)
+  actual override fun <T : Any> select(options: TypedOptions<T>): T? = commonSelect(options)
+  actual override fun readByteArray(): ByteArray = commonReadByteArray()
+  actual override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
+  actual override fun read(sink: ByteArray): Int = read(sink, 0, sink.size)
+  actual override fun readFully(sink: ByteArray): Unit = commonReadFully(sink)
+  actual override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
     commonRead(sink, offset, byteCount)
 
   override fun read(sink: ByteBuffer): Int {
@@ -87,10 +89,11 @@ internal actual class RealBufferedSource actual constructor(
     return buffer.read(sink)
   }
 
-  override fun readFully(sink: Buffer, byteCount: Long): Unit = commonReadFully(sink, byteCount)
-  override fun readAll(sink: Sink): Long = commonReadAll(sink)
-  override fun readUtf8(): String = commonReadUtf8()
-  override fun readUtf8(byteCount: Long): String = commonReadUtf8(byteCount)
+  actual override fun readFully(sink: Buffer, byteCount: Long): Unit =
+    commonReadFully(sink, byteCount)
+  actual override fun readAll(sink: Sink): Long = commonReadAll(sink)
+  actual override fun readUtf8(): String = commonReadUtf8()
+  actual override fun readUtf8(byteCount: Long): String = commonReadUtf8(byteCount)
 
   override fun readString(charset: Charset): String {
     buffer.writeAll(source)
@@ -102,45 +105,48 @@ internal actual class RealBufferedSource actual constructor(
     return buffer.readString(byteCount, charset)
   }
 
-  override fun readUtf8Line(): String? = commonReadUtf8Line()
-  override fun readUtf8LineStrict() = readUtf8LineStrict(Long.MAX_VALUE)
-  override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
-  override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
-  override fun readShort(): Short = commonReadShort()
-  override fun readShortLe(): Short = commonReadShortLe()
-  override fun readInt(): Int = commonReadInt()
-  override fun readIntLe(): Int = commonReadIntLe()
-  override fun readLong(): Long = commonReadLong()
-  override fun readLongLe(): Long = commonReadLongLe()
-  override fun readDecimalLong(): Long = commonReadDecimalLong()
-  override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
-  override fun skip(byteCount: Long): Unit = commonSkip(byteCount)
-  override fun indexOf(b: Byte): Long = indexOf(b, 0L, Long.MAX_VALUE)
-  override fun indexOf(b: Byte, fromIndex: Long): Long = indexOf(b, fromIndex, Long.MAX_VALUE)
-  override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
+  actual override fun readUtf8Line(): String? = commonReadUtf8Line()
+  actual override fun readUtf8LineStrict() = readUtf8LineStrict(Long.MAX_VALUE)
+  actual override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
+  actual override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
+  actual override fun readShort(): Short = commonReadShort()
+  actual override fun readShortLe(): Short = commonReadShortLe()
+  actual override fun readInt(): Int = commonReadInt()
+  actual override fun readIntLe(): Int = commonReadIntLe()
+  actual override fun readLong(): Long = commonReadLong()
+  actual override fun readLongLe(): Long = commonReadLongLe()
+  actual override fun readDecimalLong(): Long = commonReadDecimalLong()
+  actual override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
+  actual override fun skip(byteCount: Long): Unit = commonSkip(byteCount)
+  actual override fun indexOf(b: Byte): Long = indexOf(b, 0L, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte, fromIndex: Long): Long =
+    indexOf(b, fromIndex, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
     commonIndexOf(b, fromIndex, toIndex)
 
-  override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0L)
-  override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
-  override fun indexOfElement(targetBytes: ByteString): Long = indexOfElement(targetBytes, 0L)
-  override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
+  actual override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0L)
+  actual override fun indexOf(bytes: ByteString, fromIndex: Long): Long =
+    commonIndexOf(bytes, fromIndex)
+  actual override fun indexOfElement(targetBytes: ByteString): Long =
+    indexOfElement(targetBytes, 0L)
+  actual override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
     commonIndexOfElement(targetBytes, fromIndex)
 
-  override fun rangeEquals(offset: Long, bytes: ByteString) = rangeEquals(
+  actual override fun rangeEquals(offset: Long, bytes: ByteString) = rangeEquals(
     offset,
     bytes,
     0,
     bytes.size,
   )
 
-  override fun rangeEquals(
+  actual override fun rangeEquals(
     offset: Long,
     bytes: ByteString,
     bytesOffset: Int,
     byteCount: Int,
   ): Boolean = commonRangeEquals(offset, bytes, bytesOffset, byteCount)
 
-  override fun peek(): BufferedSource = commonPeek()
+  actual override fun peek(): BufferedSource = commonPeek()
 
   override fun inputStream(): InputStream {
     return object : InputStream() {
@@ -173,12 +179,26 @@ internal actual class RealBufferedSource actual constructor(
       override fun close() = this@RealBufferedSource.close()
 
       override fun toString() = "${this@RealBufferedSource}.inputStream()"
+
+      override fun transferTo(out: OutputStream): Long {
+        if (closed) throw IOException("closed")
+        var count = 0L
+        while (true) {
+          if (buffer.size == 0L) {
+            val read = source.read(buffer, Segment.SIZE.toLong())
+            if (read == -1L) break
+          }
+          count += buffer.size
+          buffer.writeTo(out)
+        }
+        return count
+      }
     }
   }
 
   override fun isOpen() = !closed
 
-  override fun close(): Unit = commonClose()
-  override fun timeout(): Timeout = commonTimeout()
+  actual override fun close(): Unit = commonClose()
+  actual override fun timeout(): Timeout = commonTimeout()
   override fun toString(): String = commonToString()
 }
diff --git a/okio/src/jvmMain/kotlin/okio/Timeout.kt b/okio/src/jvmMain/kotlin/okio/Timeout.kt
index b5f5f359..962bdbdb 100644
--- a/okio/src/jvmMain/kotlin/okio/Timeout.kt
+++ b/okio/src/jvmMain/kotlin/okio/Timeout.kt
@@ -135,7 +135,8 @@ actual open class Timeout {
    *
    * Here's a sample class that uses `awaitSignal()` to await a specific state. Note that the
    * call is made within a loop to avoid unnecessary waiting and to mitigate spurious notifications.
-   * ```
+   *
+   * ```java
    * class Dice {
    *   Random random = new Random();
    *   int latestTotal;
@@ -219,7 +220,8 @@ actual open class Timeout {
    *
    * Here's a sample class that uses `waitUntilNotified()` to await a specific state. Note that the
    * call is made within a loop to avoid unnecessary waiting and to mitigate spurious notifications.
-   * ```
+   *
+   * ```java
    * class Dice {
    *   Random random = new Random();
    *   int latestTotal;
diff --git a/okio/src/jvmMain/kotlin/okio/internal/-ZlibJvm.kt b/okio/src/jvmMain/kotlin/okio/internal/-ZlibJvm.kt
new file mode 100644
index 00000000..d0e8d23c
--- /dev/null
+++ b/okio/src/jvmMain/kotlin/okio/internal/-ZlibJvm.kt
@@ -0,0 +1,38 @@
+// ktlint-disable filename
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+import java.util.Calendar
+import java.util.GregorianCalendar
+
+internal actual val DEFAULT_COMPRESSION = java.util.zip.Deflater.DEFAULT_COMPRESSION
+
+internal actual typealias CRC32 = java.util.zip.CRC32
+
+internal actual fun datePartsToEpochMillis(
+  year: Int,
+  month: Int,
+  day: Int,
+  hour: Int,
+  minute: Int,
+  second: Int,
+): Long {
+  val calendar = GregorianCalendar()
+  calendar.set(Calendar.MILLISECOND, 0)
+  calendar.set(year, month - 1, day, hour, minute, second)
+  return calendar.time.time
+}
diff --git a/okio/src/jvmMain/kotlin/okio/internal/ResourceFileSystem.kt b/okio/src/jvmMain/kotlin/okio/internal/ResourceFileSystem.kt
index efe76801..9223be01 100644
--- a/okio/src/jvmMain/kotlin/okio/internal/ResourceFileSystem.kt
+++ b/okio/src/jvmMain/kotlin/okio/internal/ResourceFileSystem.kt
@@ -17,6 +17,7 @@ package okio.internal
 
 import java.io.File
 import java.io.IOException
+import java.net.JarURLConnection
 import java.net.URI
 import java.net.URL
 import okio.FileHandle
@@ -126,8 +127,12 @@ internal class ResourceFileSystem internal constructor(
     if (!keepPath(file)) throw FileNotFoundException("file not found: $file")
     // Make sure we have a path that doesn't start with '/'.
     val relativePath = ROOT.resolve(file).relativeTo(ROOT)
-    return classLoader.getResourceAsStream(relativePath.toString())?.source()
-      ?: throw FileNotFoundException("file not found: $file")
+    val resource = classLoader.getResource(relativePath.toString()) ?: throw FileNotFoundException("file not found: $file")
+    val urlConnection = resource.openConnection()
+    if (urlConnection is JarURLConnection) {
+      urlConnection.useCaches = false
+    }
+    return urlConnection.getInputStream().source()
   }
 
   override fun sink(file: Path, mustCreate: Boolean): Sink {
diff --git a/okio/src/jvmMain/kotlin/okio/internal/ZipEntry.kt b/okio/src/jvmMain/kotlin/okio/internal/ZipEntry.kt
deleted file mode 100644
index a370aca8..00000000
--- a/okio/src/jvmMain/kotlin/okio/internal/ZipEntry.kt
+++ /dev/null
@@ -1,51 +0,0 @@
-/*
- * Licensed to the Apache Software Foundation (ASF) under one or more
- * contributor license agreements.  See the NOTICE file distributed with
- * this work for additional information regarding copyright ownership.
- * The ASF licenses this file to You under the Apache License, Version 2.0
- * (the "License"); you may not use this file except in compliance with
- * the License.  You may obtain a copy of the License at
- *
- *     http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package okio.internal
-
-import okio.Path
-
-internal class ZipEntry(
-  /**
-   * Absolute path of this entry. If the raw name on disk contains relative paths like `..`, they
-   * are not present in this path.
-   */
-  val canonicalPath: Path,
-
-  /** True if this entry is a directory. When encoded directory entries' names end with `/`. */
-  val isDirectory: Boolean = false,
-
-  /** The comment on this entry. Empty if there is no comment. */
-  val comment: String = "",
-
-  /** The CRC32 of the uncompressed data, or -1 if not set. */
-  val crc: Long = -1L,
-
-  /** The compressed size in bytes, or -1 if unknown. */
-  val compressedSize: Long = -1L,
-
-  /** The uncompressed size in bytes, or -1 if unknown. */
-  val size: Long = -1L,
-
-  /** Either [COMPRESSION_METHOD_DEFLATED] or [COMPRESSION_METHOD_STORED]. */
-  val compressionMethod: Int = -1,
-
-  val lastModifiedAtMillis: Long? = null,
-
-  val offset: Long = -1L,
-) {
-  val children = mutableListOf<Path>()
-}
diff --git a/okio/src/jvmTest/hashFunctions b/okio/src/jvmTest/hashFunctions
deleted file mode 120000
index 1634c79e..00000000
--- a/okio/src/jvmTest/hashFunctions
+++ /dev/null
@@ -1 +0,0 @@
-../hashFunctions/kotlin
\ No newline at end of file
diff --git a/okio/src/jvmTest/kotlin/okio/AwaitSignalTest.kt b/okio/src/jvmTest/kotlin/okio/AwaitSignalTest.kt
index a04e8cfe..4607b600 100644
--- a/okio/src/jvmTest/kotlin/okio/AwaitSignalTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/AwaitSignalTest.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.io.InterruptedIOException
 import java.util.concurrent.TimeUnit
 import java.util.concurrent.locks.Condition
@@ -25,11 +26,8 @@ import org.junit.Assert.assertEquals
 import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
+@Burst
 class AwaitSignalTest(
   factory: TimeoutFactory,
 ) {
@@ -215,10 +213,4 @@ class AwaitSignalTest(
       TimeUnit.MILLISECONDS,
     )
   }
-
-  companion object {
-    @Parameters(name = "{0}")
-    @JvmStatic
-    fun parameters(): List<Array<out Any?>> = TimeoutFactory.entries.map { arrayOf(it) }
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/BufferCursorKotlinTest.kt b/okio/src/jvmTest/kotlin/okio/BufferCursorKotlinTest.kt
index 0b50b005..758469ee 100644
--- a/okio/src/jvmTest/kotlin/okio/BufferCursorKotlinTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/BufferCursorKotlinTest.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import kotlin.test.assertEquals
 import kotlin.test.assertFalse
 import kotlin.test.assertNotSame
@@ -24,23 +25,11 @@ import okio.Buffer.UnsafeCursor
 import okio.TestUtil.deepCopy
 import org.junit.Assume.assumeTrue
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameter
-import org.junit.runners.Parameterized.Parameters
-
-@RunWith(Parameterized::class)
-class BufferCursorKotlinTest {
-  companion object {
-    @Parameters(name = "{0}")
-    @JvmStatic
-    fun parameters(): List<Array<out Any?>> {
-      return BufferFactory.values().map { arrayOf(it) }
-    }
-  }
-
-  @Parameter lateinit var bufferFactory: BufferFactory
 
+@Burst
+class BufferCursorKotlinTest(
+  private val bufferFactory: BufferFactory,
+) {
   @Test fun acquireReadOnlyDoesNotCopySharedDataArray() {
     val buffer = deepCopy(bufferFactory.newBuffer())
     assumeTrue(buffer.size > 0L)
diff --git a/okio/src/jvmTest/kotlin/okio/BufferCursorTest.kt b/okio/src/jvmTest/kotlin/okio/BufferCursorTest.kt
index 54873286..466552c9 100644
--- a/okio/src/jvmTest/kotlin/okio/BufferCursorTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/BufferCursorTest.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.util.Arrays
 import okio.ByteString.Companion.of
 import okio.TestUtil.SEGMENT_SIZE
@@ -27,11 +28,8 @@ import org.junit.Assert.assertNull
 import org.junit.Assert.fail
 import org.junit.Assume.assumeTrue
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
+@Burst
 class BufferCursorTest(
   private var bufferFactory: BufferFactory,
 ) {
@@ -141,7 +139,7 @@ class BufferCursorTest(
 
   @Test
   fun seekWithinSegment() {
-    assumeTrue(bufferFactory === BufferFactory.SMALL_SEGMENTED_BUFFER)
+    assumeTrue(bufferFactory === BufferFactory.SmallSegmentedBuffer)
     val buffer = bufferFactory.newBuffer()
     assertEquals("abcdefghijkl", buffer.clone().readUtf8())
     buffer.readUnsafe().use { cursor ->
@@ -444,16 +442,4 @@ class BufferCursorTest(
       assertEquals(originalSize, cursor.offset)
     }
   }
-
-  companion object {
-    @JvmStatic
-    @Parameters(name = "{0}")
-    fun parameters(): List<Array<Any>> {
-      val result = mutableListOf<Array<Any>>()
-      for (bufferFactory in BufferFactory.values()) {
-        result += arrayOf(bufferFactory)
-      }
-      return result
-    }
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/BufferFactory.kt b/okio/src/jvmTest/kotlin/okio/BufferFactory.kt
index 0e6ce906..4c82a0b4 100644
--- a/okio/src/jvmTest/kotlin/okio/BufferFactory.kt
+++ b/okio/src/jvmTest/kotlin/okio/BufferFactory.kt
@@ -20,26 +20,26 @@ import okio.TestUtil.bufferWithRandomSegmentLayout
 import okio.TestUtil.bufferWithSegments
 
 enum class BufferFactory {
-  EMPTY {
+  Empty {
     override fun newBuffer(): Buffer {
       return Buffer()
     }
   },
 
-  SMALL_BUFFER {
+  SmallBuffer {
     override fun newBuffer(): Buffer {
       return Buffer().writeUtf8("abcde")
     }
   },
 
-  SMALL_SEGMENTED_BUFFER {
+  SmallSegmentedBuffer {
     @Throws(Exception::class)
     override fun newBuffer(): Buffer {
       return bufferWithSegments("abc", "defg", "hijkl")
     }
   },
 
-  LARGE_BUFFER {
+  LargeBuffer {
     @Throws(Exception::class)
     override fun newBuffer(): Buffer {
       val dice = Random(0)
@@ -50,7 +50,7 @@ enum class BufferFactory {
     }
   },
 
-  LARGE_BUFFER_WITH_RANDOM_LAYOUT {
+  LargeBufferWithRandomLayout {
     @Throws(Exception::class)
     override fun newBuffer(): Buffer {
       val dice = Random(0)
diff --git a/okio/src/jvmTest/kotlin/okio/BufferTest.kt b/okio/src/jvmTest/kotlin/okio/BufferTest.kt
index 6f3501bd..36e2689f 100644
--- a/okio/src/jvmTest/kotlin/okio/BufferTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/BufferTest.kt
@@ -25,7 +25,6 @@ import kotlin.text.Charsets.UTF_8
 import okio.ByteString.Companion.decodeHex
 import okio.TestUtil.SEGMENT_POOL_MAX_SIZE
 import okio.TestUtil.SEGMENT_SIZE
-import okio.TestUtil.assertNoEmptySegments
 import okio.TestUtil.bufferWithRandomSegmentLayout
 import okio.TestUtil.segmentPoolByteCount
 import okio.TestUtil.segmentSizes
diff --git a/okio/src/jvmTest/kotlin/okio/BufferedSinkTest.kt b/okio/src/jvmTest/kotlin/okio/BufferedSinkTest.kt
index c9b3d187..c3e731dc 100644
--- a/okio/src/jvmTest/kotlin/okio/BufferedSinkTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/BufferedSinkTest.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.io.EOFException
 import java.math.BigInteger
 import java.nio.ByteBuffer
@@ -27,27 +28,21 @@ import okio.TestUtil.segmentSizes
 import org.junit.Assert.assertEquals
 import org.junit.Assert.fail
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
+@Burst
 class BufferedSinkTest(
   factory: Factory,
 ) {
-  interface Factory {
-    fun create(data: Buffer): BufferedSink
+  enum class Factory {
+    NewBuffer {
+      override fun create(data: Buffer) = data
+    },
+    SinkBuffer {
+      override fun create(data: Buffer) = (data as Sink).buffer()
+    },
+    ;
 
-    companion object {
-      val BUFFER: Factory = object : Factory {
-        override fun create(data: Buffer) = data
-        override fun toString() = "Buffer"
-      }
-      val REAL_BUFFERED_SINK: Factory = object : Factory {
-        override fun create(data: Buffer) = (data as Sink).buffer()
-        override fun toString() = "RealBufferedSink"
-      }
-    }
+    abstract fun create(data: Buffer): BufferedSink
   }
 
   private val data: Buffer = Buffer()
@@ -377,13 +372,4 @@ class BufferedSinkTest(
     val actual = data.readUtf8()
     assertEquals("$value expected $expected but was $actual", actual, expected)
   }
-
-  companion object {
-    @JvmStatic
-    @Parameters(name = "{0}")
-    fun parameters(): List<Array<Any>> = listOf(
-      arrayOf(Factory.BUFFER),
-      arrayOf(Factory.REAL_BUFFERED_SINK),
-    )
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/BufferedSourceTest.kt b/okio/src/jvmTest/kotlin/okio/BufferedSourceTest.kt
index b30944b7..9b42fe1f 100644
--- a/okio/src/jvmTest/kotlin/okio/BufferedSourceTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/BufferedSourceTest.kt
@@ -15,6 +15,12 @@
  */
 package okio
 
+import app.cash.burst.Burst
+import assertk.assertThat
+import assertk.assertions.isEqualTo
+import assertk.assertions.isTrue
+import java.io.ByteArrayInputStream
+import java.io.ByteArrayOutputStream
 import java.io.EOFException
 import java.nio.ByteBuffer
 import java.nio.charset.Charset
@@ -35,124 +41,108 @@ import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
 import org.junit.Assume
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
+@Burst
 class BufferedSourceTest(
   private val factory: Factory,
 ) {
-  interface Factory {
-    fun pipe(): Pipe
-    val isOneByteAtATime: Boolean
-
-    companion object {
-      val BUFFER: Factory = object : Factory {
-        override fun pipe(): Pipe {
-          val buffer = Buffer()
-          return Pipe(buffer, buffer)
-        }
-
-        override val isOneByteAtATime: Boolean get() = false
-
-        override fun toString() = "Buffer"
+  enum class Factory {
+    NewBuffer {
+      override fun pipe(): Pipe {
+        val buffer = Buffer()
+        return Pipe(buffer, buffer)
       }
 
-      val REAL_BUFFERED_SOURCE: Factory = object : Factory {
-        override fun pipe(): Pipe {
-          val buffer = Buffer()
-          return Pipe(
-            sink = buffer,
-            source = (buffer as Source).buffer(),
-          )
-        }
+      override val isOneByteAtATime: Boolean get() = false
+    },
 
-        override val isOneByteAtATime: Boolean get() = false
-
-        override fun toString() = "RealBufferedSource"
+    SourceBuffer {
+      override fun pipe(): Pipe {
+        val buffer = Buffer()
+        return Pipe(
+          sink = buffer,
+          source = (buffer as Source).buffer(),
+        )
       }
 
-      /**
-       * A factory deliberately written to create buffers whose internal segments are always 1 byte
-       * long. We like testing with these segments because are likely to trigger bugs!
-       */
-      val ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE: Factory = object : Factory {
-        override fun pipe(): Pipe {
-          val buffer = Buffer()
-          return Pipe(
-            sink = buffer,
-            source = object : ForwardingSource(buffer) {
-              override fun read(sink: Buffer, byteCount: Long): Long {
-                // Read one byte into a new buffer, then clone it so that the segment is shared.
-                // Shared segments cannot be compacted so we'll get a long chain of short segments.
-                val box = Buffer()
-                val result = super.read(box, Math.min(byteCount, 1L))
-                if (result > 0L) sink.write(box.clone(), result)
-                return result
-              }
-            }.buffer(),
-          )
-        }
-
-        override val isOneByteAtATime: Boolean get() = true
-
-        override fun toString() = "OneByteAtATimeBufferedSource"
+      override val isOneByteAtATime: Boolean get() = false
+    },
+
+    /**
+     * A factory deliberately written to create buffers whose internal segments are always 1 byte
+     * long. We like testing with these segments because are likely to trigger bugs!
+     */
+    OneByteAtATimeSource {
+      override fun pipe(): Pipe {
+        val buffer = Buffer()
+        return Pipe(
+          sink = buffer,
+          source = object : ForwardingSource(buffer) {
+            override fun read(sink: Buffer, byteCount: Long): Long {
+              // Read one byte into a new buffer, then clone it so that the segment is shared.
+              // Shared segments cannot be compacted so we'll get a long chain of short segments.
+              val box = Buffer()
+              val result = super.read(box, Math.min(byteCount, 1L))
+              if (result > 0L) sink.write(box.clone(), result)
+              return result
+            }
+          }.buffer(),
+        )
       }
 
-      val ONE_BYTE_AT_A_TIME_BUFFER: Factory = object : Factory {
-        override fun pipe(): Pipe {
-          val buffer = Buffer()
-          val sink = object : ForwardingSink(buffer) {
-            override fun write(source: Buffer, byteCount: Long) {
-              // Write each byte into a new buffer, then clone it so that the segments are shared.
-              // Shared segments cannot be compacted so we'll get a long chain of short segments.
-              for (i in 0 until byteCount) {
-                val box = Buffer()
-                box.write(source, 1)
-                super.write(box.clone(), 1)
-              }
+      override val isOneByteAtATime: Boolean get() = true
+    },
+
+    OneByteAtATimeSink {
+      override fun pipe(): Pipe {
+        val buffer = Buffer()
+        val sink = object : ForwardingSink(buffer) {
+          override fun write(source: Buffer, byteCount: Long) {
+            // Write each byte into a new buffer, then clone it so that the segments are shared.
+            // Shared segments cannot be compacted so we'll get a long chain of short segments.
+            for (i in 0 until byteCount) {
+              val box = Buffer()
+              box.write(source, 1)
+              super.write(box.clone(), 1)
             }
-          }.buffer()
-          return Pipe(
-            sink = sink,
-            source = buffer,
-          )
-        }
+          }
+        }.buffer()
+        return Pipe(
+          sink = sink,
+          source = buffer,
+        )
+      }
 
-        override val isOneByteAtATime: Boolean get() = true
+      override val isOneByteAtATime: Boolean get() = true
+    },
 
-        override fun toString() = "OneByteAtATimeBuffer"
+    PeekSource {
+      override fun pipe(): Pipe {
+        val buffer = Buffer()
+        return Pipe(
+          sink = buffer,
+          source = buffer.peek(),
+        )
       }
 
-      val PEEK_BUFFER: Factory = object : Factory {
-        override fun pipe(): Pipe {
-          val buffer = Buffer()
-          return Pipe(
-            sink = buffer,
-            source = buffer.peek(),
-          )
-        }
-
-        override val isOneByteAtATime: Boolean get() = false
+      override val isOneByteAtATime: Boolean get() = false
+    },
 
-        override fun toString() = "PeekBuffer"
+    PeekBufferedSource {
+      override fun pipe(): Pipe {
+        val buffer = Buffer()
+        return Pipe(
+          sink = buffer,
+          source = (buffer as Source).buffer().peek(),
+        )
       }
 
-      val PEEK_BUFFERED_SOURCE: Factory = object : Factory {
-        override fun pipe(): Pipe {
-          val buffer = Buffer()
-          return Pipe(
-            sink = buffer,
-            source = (buffer as Source).buffer().peek(),
-          )
-        }
+      override val isOneByteAtATime: Boolean get() = false
+    },
+    ;
 
-        override val isOneByteAtATime: Boolean get() = false
-
-        override fun toString() = "PeekBufferedSource"
-      }
-    }
+    abstract fun pipe(): Pipe
+    abstract val isOneByteAtATime: Boolean
   }
 
   class Pipe(
@@ -371,9 +361,9 @@ class BufferedSourceTest(
     val sink = Buffer()
     sink.writeUtf8("a".repeat(10))
 
-    // Either 0 or -1 is reasonable here. For consistency with Android's
-    // ByteArrayInputStream we return 0.
-    assertEquals(-1, source.read(sink, 0))
+    // Either 0 or -1 is reasonable here.
+    val readResult = source.read(sink, 0)
+    assertTrue(readResult == 0L || readResult == -1L)
     assertEquals(10, sink.size)
     assertTrue(source.exhausted())
   }
@@ -824,7 +814,7 @@ class BufferedSourceTest(
   }
 
   /**
-   * With [Factory.ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE], this code was extremely slow.
+   * With [Factory.OneByteAtATimeSource], this code was extremely slow.
    * https://github.com/square/okio/issues/171
    */
   @Test
@@ -991,6 +981,24 @@ class BufferedSourceTest(
     }
   }
 
+  @Test
+  fun inputStreamTransferTo() {
+    try {
+      ByteArrayInputStream(byteArrayOf(1)).transferTo(ByteArrayOutputStream())
+    } catch (e: NoSuchMethodError) {
+      return // This JDK doesn't have transferTo(). Skip this test.
+    }
+
+    val data = "a".repeat(SEGMENT_SIZE * 3 + 1)
+    sink.writeUtf8(data)
+    sink.emit()
+    val inputStream = source.inputStream()
+    val outputStream = ByteArrayOutputStream()
+    inputStream.transferTo(outputStream)
+    assertThat(source.exhausted()).isTrue()
+    assertThat(outputStream.toByteArray().toUtf8String()).isEqualTo(data)
+  }
+
   @Test
   fun longHexString() {
     assertLongHexString("8000000000000000", -0x7fffffffffffffffL - 1L)
@@ -1418,7 +1426,7 @@ class BufferedSourceTest(
 
   @Test
   fun rangeEqualsOnlyReadsUntilMismatch() {
-    Assume.assumeTrue(factory === Factory.ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE) // Other sources read in chunks anyway.
+    Assume.assumeTrue(factory === Factory.OneByteAtATimeSource) // Other sources read in chunks anyway.
     sink.writeUtf8("A man, a plan, a canal. Panama.")
     sink.emit()
     assertFalse(source.rangeEquals(0, "A man.".encodeUtf8()))
@@ -1485,19 +1493,4 @@ class BufferedSourceTest(
       assertEquals(listOf(3), segmentSizes(source.buffer))
     }
   }
-
-  companion object {
-    @JvmStatic
-    @Parameters(name = "{0}")
-    fun parameters(): List<Array<Any>> {
-      return listOf(
-        arrayOf(Factory.BUFFER),
-        arrayOf(Factory.REAL_BUFFERED_SOURCE),
-        arrayOf(Factory.ONE_BYTE_AT_A_TIME_BUFFERED_SOURCE),
-        arrayOf(Factory.ONE_BYTE_AT_A_TIME_BUFFER),
-        arrayOf(Factory.PEEK_BUFFER),
-        arrayOf(Factory.PEEK_BUFFERED_SOURCE),
-      )
-    }
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/ByteStringJavaTest.kt b/okio/src/jvmTest/kotlin/okio/ByteStringJavaTest.kt
index 490eb425..b5f31fef 100644
--- a/okio/src/jvmTest/kotlin/okio/ByteStringJavaTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/ByteStringJavaTest.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.io.ByteArrayInputStream
 import java.io.ByteArrayOutputStream
 import java.nio.ByteBuffer
@@ -34,57 +35,48 @@ import okio.TestUtil.makeSegments
 import okio.TestUtil.reserialize
 import org.junit.Assert.assertEquals
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameter
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
-class ByteStringJavaTest {
-  interface Factory {
-    fun decodeHex(hex: String): ByteString
-    fun encodeUtf8(s: String): ByteString
-
-    companion object {
-      val BYTE_STRING: Factory = object : Factory {
-        override fun decodeHex(hex: String): ByteString {
-          return hex.decodeHex()
-        }
-
-        override fun encodeUtf8(s: String): ByteString {
-          return s.encodeUtf8()
-        }
+@Burst
+class ByteStringJavaTest(
+  private val factory: Factory,
+) {
+  enum class Factory {
+    BaseByteString {
+      override fun decodeHex(hex: String): ByteString {
+        return hex.decodeHex()
       }
-      val SEGMENTED_BYTE_STRING: Factory = object : Factory {
-        override fun decodeHex(hex: String): ByteString {
-          val buffer = Buffer()
-          buffer.write(hex.decodeHex())
-          return buffer.snapshot()
-        }
 
-        override fun encodeUtf8(s: String): ByteString {
-          val buffer = Buffer()
-          buffer.writeUtf8(s)
-          return buffer.snapshot()
-        }
+      override fun encodeUtf8(s: String): ByteString {
+        return s.encodeUtf8()
+      }
+    },
+    SegmentedByteString {
+      override fun decodeHex(hex: String): ByteString {
+        val buffer = Buffer()
+        buffer.write(hex.decodeHex())
+        return buffer.snapshot()
       }
-      val ONE_BYTE_PER_SEGMENT: Factory = object : Factory {
-        override fun decodeHex(hex: String): ByteString {
-          return makeSegments(hex.decodeHex())
-        }
 
-        override fun encodeUtf8(s: String): ByteString {
-          return makeSegments(s.encodeUtf8())
-        }
+      override fun encodeUtf8(s: String): ByteString {
+        val buffer = Buffer()
+        buffer.writeUtf8(s)
+        return buffer.snapshot()
+      }
+    },
+    OneBytePerSegment {
+      override fun decodeHex(hex: String): ByteString {
+        return makeSegments(hex.decodeHex())
       }
-    }
-  }
 
-  @Parameter(0)
-  lateinit var factory: Factory
+      override fun encodeUtf8(s: String): ByteString {
+        return makeSegments(s.encodeUtf8())
+      }
+    },
+    ;
 
-  @Parameter(1)
-  lateinit var name: String
+    abstract fun decodeHex(hex: String): ByteString
+    abstract fun encodeUtf8(s: String): ByteString
+  }
 
   @Test
   fun ofByteBuffer() {
@@ -264,15 +256,5 @@ class ByteStringJavaTest {
 
   companion object {
     private val bronzeHorseman = "На берегу пустынных волн"
-
-    @JvmStatic
-    @Parameters(name = "{1}")
-    fun parameters(): List<Array<Any>> {
-      return listOf(
-        arrayOf(Factory.BYTE_STRING, "ByteString"),
-        arrayOf(Factory.SEGMENTED_BYTE_STRING, "SegmentedByteString"),
-        arrayOf(Factory.ONE_BYTE_PER_SEGMENT, "SegmentedByteString (one-at-a-time)"),
-      )
-    }
   }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/CipherAlgorithm.kt b/okio/src/jvmTest/kotlin/okio/CipherAlgorithm.kt
index 69415241..ecef16f5 100644
--- a/okio/src/jvmTest/kotlin/okio/CipherAlgorithm.kt
+++ b/okio/src/jvmTest/kotlin/okio/CipherAlgorithm.kt
@@ -19,12 +19,26 @@ import javax.crypto.spec.IvParameterSpec
 import javax.crypto.spec.SecretKeySpec
 import kotlin.random.Random
 
-data class CipherAlgorithm(
+enum class CipherAlgorithm(
   val transformation: String,
   val padding: Boolean,
   val keyLength: Int,
   val ivLength: Int? = null,
 ) {
+  AesCbcNopadding("AES/CBC/NoPadding", false, 16, 16),
+  AesCbcPkcs5padding("AES/CBC/PKCS5Padding", true, 16, 16),
+  AesEcbNopadding("AES/ECB/NoPadding", false, 16),
+  AesEcbPkcs5padding("AES/ECB/PKCS5Padding", true, 16),
+  DesCbcNopadding("DES/CBC/NoPadding", false, 8, 8),
+  DesCbcPkcs5padding("DES/CBC/PKCS5Padding", true, 8, 8),
+  DesEcbNopadding("DES/ECB/NoPadding", false, 8),
+  DesEcbPkcs5padding("DES/ECB/PKCS5Padding", true, 8),
+  DesedeCbcNopadding("DESede/CBC/NoPadding", false, 24, 8),
+  DesedeCbcPkcs5padding("DESede/CBC/PKCS5Padding", true, 24, 8),
+  DesedeEcbNopadding("DESede/ECB/NoPadding", false, 24),
+  DesedeEcbPkcs5padding("DESede/ECB/PKCS5Padding", true, 24),
+  ;
+
   fun createCipherFactory(random: Random): CipherFactory {
     val key = random.nextBytes(keyLength)
     val secretKeySpec = SecretKeySpec(key, transformation.substringBefore('/'))
@@ -40,24 +54,4 @@ data class CipherAlgorithm(
       }
     }
   }
-
-  override fun toString() = transformation
-
-  companion object {
-    val BLOCK_CIPHER_ALGORITHMS
-      get() = listOf(
-        CipherAlgorithm("AES/CBC/NoPadding", false, 16, 16),
-        CipherAlgorithm("AES/CBC/PKCS5Padding", true, 16, 16),
-        CipherAlgorithm("AES/ECB/NoPadding", false, 16),
-        CipherAlgorithm("AES/ECB/PKCS5Padding", true, 16),
-        CipherAlgorithm("DES/CBC/NoPadding", false, 8, 8),
-        CipherAlgorithm("DES/CBC/PKCS5Padding", true, 8, 8),
-        CipherAlgorithm("DES/ECB/NoPadding", false, 8),
-        CipherAlgorithm("DES/ECB/PKCS5Padding", true, 8),
-        CipherAlgorithm("DESede/CBC/NoPadding", false, 24, 8),
-        CipherAlgorithm("DESede/CBC/PKCS5Padding", true, 24, 8),
-        CipherAlgorithm("DESede/ECB/NoPadding", false, 24),
-        CipherAlgorithm("DESede/ECB/PKCS5Padding", true, 24),
-      )
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/CipherSinkTest.kt b/okio/src/jvmTest/kotlin/okio/CipherSinkTest.kt
index 84d27d06..35d93b77 100644
--- a/okio/src/jvmTest/kotlin/okio/CipherSinkTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/CipherSinkTest.kt
@@ -15,20 +15,14 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import kotlin.random.Random
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-
-@RunWith(Parameterized::class)
-class CipherSinkTest(private val cipherAlgorithm: CipherAlgorithm) {
-  companion object {
-    @get:Parameterized.Parameters(name = "{0}")
-    @get:JvmStatic
-    val parameters: List<CipherAlgorithm>
-      get() = CipherAlgorithm.BLOCK_CIPHER_ALGORITHMS
-  }
 
+@Burst
+class CipherSinkTest(
+  private val cipherAlgorithm: CipherAlgorithm,
+) {
   @Test
   fun encrypt() {
     val random = Random(8912860393601532863)
diff --git a/okio/src/jvmTest/kotlin/okio/CipherSourceTest.kt b/okio/src/jvmTest/kotlin/okio/CipherSourceTest.kt
index 16775350..a41cee49 100644
--- a/okio/src/jvmTest/kotlin/okio/CipherSourceTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/CipherSourceTest.kt
@@ -15,20 +15,14 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import kotlin.random.Random
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-
-@RunWith(Parameterized::class)
-class CipherSourceTest(private val cipherAlgorithm: CipherAlgorithm) {
-  companion object {
-    @get:Parameterized.Parameters(name = "{0}")
-    @get:JvmStatic
-    val parameters: List<CipherAlgorithm>
-      get() = CipherAlgorithm.BLOCK_CIPHER_ALGORITHMS
-  }
 
+@Burst
+class CipherSourceTest(
+  private val cipherAlgorithm: CipherAlgorithm,
+) {
   @Test
   fun encrypt() {
     val random = Random(787679144228763091)
diff --git a/okio/src/jvmTest/kotlin/okio/FileHandleFileSystemTest.kt b/okio/src/jvmTest/kotlin/okio/FileHandleFileSystemTest.kt
index 021ffb4c..14f3f911 100644
--- a/okio/src/jvmTest/kotlin/okio/FileHandleFileSystemTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/FileHandleFileSystemTest.kt
@@ -33,6 +33,7 @@ class FileHandleFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = Path.DIRECTORY_SEPARATOR == "\\",
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.DoesNothing,
 ) {
   /**
    * A testing-only file system that implements all reading and writing operations with
@@ -75,6 +76,7 @@ class FileHandleNioJimFileSystemWrapperFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = true,
   allowAtomicMoveFromFileToDirectory = true,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.Closes,
 )
 
 class FileHandleNioDefaultFileSystemWrapperFileSystemTest : AbstractFileSystemTest(
@@ -87,4 +89,5 @@ class FileHandleNioDefaultFileSystemWrapperFileSystemTest : AbstractFileSystemTe
   allowAtomicMoveFromFileToDirectory = false,
   allowRenameWhenTargetIsOpen = Path.DIRECTORY_SEPARATOR != "\\",
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.Unsupported,
 )
diff --git a/okio/src/jvmTest/kotlin/okio/FileLeakTest.kt b/okio/src/jvmTest/kotlin/okio/FileLeakTest.kt
index 5fd18a6b..79d2662f 100644
--- a/okio/src/jvmTest/kotlin/okio/FileLeakTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/FileLeakTest.kt
@@ -15,17 +15,30 @@
  */
 package okio
 
+import java.net.URLClassLoader
+import java.nio.file.Path
 import java.util.zip.ZipEntry
 import java.util.zip.ZipOutputStream
+import kotlin.io.path.ExperimentalPathApi
+import kotlin.io.path.Path
+import kotlin.io.path.exists
+import kotlin.io.path.isDirectory
+import kotlin.io.path.isSymbolicLink
+import kotlin.io.path.readSymbolicLink
+import kotlin.io.path.walk
 import kotlin.test.assertEquals
 import kotlin.test.assertNotNull
 import kotlin.test.assertTrue
 import okio.Path.Companion.toPath
 import okio.fakefilesystem.FakeFileSystem
+import okio.internal.ResourceFileSystem
 import org.junit.After
+import org.junit.Assume.assumeTrue
 import org.junit.Before
 import org.junit.Test
 
+private const val PROC_SELF_FD = "/proc/self/fd"
+
 class FileLeakTest {
 
   private lateinit var fakeFileSystem: FakeFileSystem
@@ -87,6 +100,34 @@ class FileLeakTest {
     zipFileSystem.listRecursively("/".toPath()).toList()
     fakeFileSystem.delete(fakeZip)
   }
+
+  @Test
+  fun fileLeakInResourceFileSystemTest() {
+    assumeTrue("File descriptor symbolic link available only on Linux", Path(PROC_SELF_FD).exists())
+    // Create a test file that will be opened and cached by the classloader
+    val zipPath = ZipBuilder(FileSystem.SYSTEM_TEMPORARY_DIRECTORY / randomToken(16))
+      .addEntry("test.txt", "I'm part of a test!")
+      .addEntry("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
+      .build()
+
+    // Create a custom class loader
+    val urlClassLoader = URLClassLoader.newInstance(arrayOf(zipPath.toFile().toURI().toURL()))
+
+    // Create a resource file system using the given a custom class loader
+    val resourceFileSystem = ResourceFileSystem(
+      classLoader = urlClassLoader,
+      indexEagerly = false,
+    )
+
+    // Trigger the read of the classloader
+    resourceFileSystem.source("test.txt".toPath()).use { it.buffer().readUtf8() }
+
+    // Classloader needs to be closed in order to close the file descriptor to the JAR file
+    urlClassLoader.close()
+
+    // Ensure the underlying URLConnection to the JAR file was not cached
+    zipPath.toNioPath().assetFileNotOpen()
+  }
 }
 
 /**
@@ -109,3 +150,18 @@ private inline fun <R> ZipOutputStream.putEntry(name: String, action: BufferedSi
     closeEntry()
   }
 }
+
+// This is a Linux only test for open file descriptors on the current process
+@OptIn(ExperimentalPathApi::class)
+private fun Path.assetFileNotOpen() {
+  val fds = Path(PROC_SELF_FD)
+  if (fds.isDirectory()) {
+    // Linux: verify that path is not open
+    assertTrue("Resource remained opened: $this") {
+      fds.walk()
+        .filter { it.isSymbolicLink() }
+        .map { it.readSymbolicLink() }
+        .none { it == this }
+    }
+  }
+}
diff --git a/okio/src/jvmTest/kotlin/okio/InflaterSourceTest.kt b/okio/src/jvmTest/kotlin/okio/InflaterSourceTest.kt
index 53273776..8f2212ce 100644
--- a/okio/src/jvmTest/kotlin/okio/InflaterSourceTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/InflaterSourceTest.kt
@@ -15,10 +15,10 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.io.EOFException
 import java.util.zip.DeflaterOutputStream
 import java.util.zip.Inflater
-import okio.BufferedSourceFactory.Companion.PARAMETERIZED_TEST_VALUES
 import okio.ByteString.Companion.decodeBase64
 import okio.ByteString.Companion.encodeUtf8
 import okio.TestUtil.SEGMENT_SIZE
@@ -28,11 +28,8 @@ import org.junit.Assert.assertEquals
 import org.junit.Assert.fail
 import org.junit.Assume.assumeFalse
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
+@Burst
 class InflaterSourceTest(
   private val bufferFactory: BufferedSourceFactory,
 ) {
@@ -202,14 +199,4 @@ class InflaterSourceTest(
     }
     return result
   }
-
-  companion object {
-    /**
-     * Use a parameterized test to control how many bytes the InflaterSource gets with each request
-     * for more bytes.
-     */
-    @JvmStatic
-    @Parameters(name = "{0}")
-    fun parameters(): List<Array<Any>> = PARAMETERIZED_TEST_VALUES
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/JvmSystemFileSystemTest.kt b/okio/src/jvmTest/kotlin/okio/JvmSystemFileSystemTest.kt
index fc4b7c09..ff06ec2f 100644
--- a/okio/src/jvmTest/kotlin/okio/JvmSystemFileSystemTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/JvmSystemFileSystemTest.kt
@@ -37,6 +37,7 @@ class NioSystemFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = Path.DIRECTORY_SEPARATOR == "\\",
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.DoesNothing,
 )
 
 class JvmSystemFileSystemTest : AbstractFileSystemTest(
@@ -46,6 +47,7 @@ class JvmSystemFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = Path.DIRECTORY_SEPARATOR == "\\",
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.DoesNothing,
 ) {
 
   @Test fun checkInterruptedBeforeDeleting() {
@@ -73,6 +75,7 @@ class NioJimFileSystemWrappingFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = true,
   allowAtomicMoveFromFileToDirectory = true,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.Closes,
 )
 
 class NioDefaultFileSystemWrappingFileSystemTest : AbstractFileSystemTest(
@@ -83,4 +86,5 @@ class NioDefaultFileSystemWrappingFileSystemTest : AbstractFileSystemTest(
   allowAtomicMoveFromFileToDirectory = false,
   allowRenameWhenTargetIsOpen = Path.DIRECTORY_SEPARATOR != "\\",
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.Unsupported,
 )
diff --git a/okio/src/jvmTest/kotlin/okio/JvmTesting.kt b/okio/src/jvmTest/kotlin/okio/JvmTesting.kt
index e6b091d7..c135095f 100644
--- a/okio/src/jvmTest/kotlin/okio/JvmTesting.kt
+++ b/okio/src/jvmTest/kotlin/okio/JvmTesting.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import java.util.TimeZone
 import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
 import okio.Path.Companion.toOkioPath
@@ -52,3 +53,13 @@ actual fun assertRelativeToFails(
   // Return okio.
   return assertFailsWith { b.relativeTo(a) }
 }
+
+actual fun <T> withUtc(block: () -> T): T {
+  val original = TimeZone.getDefault()
+  TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
+  try {
+    return block()
+  } finally {
+    TimeZone.setDefault(original)
+  }
+}
diff --git a/okio/src/jvmTest/kotlin/okio/OkioTest.kt b/okio/src/jvmTest/kotlin/okio/OkioTest.kt
index 9514ddd2..5a4cee4b 100644
--- a/okio/src/jvmTest/kotlin/okio/OkioTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/OkioTest.kt
@@ -20,7 +20,6 @@ import java.io.ByteArrayOutputStream
 import java.nio.file.Files
 import kotlin.text.Charsets.UTF_8
 import okio.TestUtil.SEGMENT_SIZE
-import okio.TestUtil.assertNoEmptySegments
 import org.junit.Assert.assertEquals
 import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
diff --git a/okio/src/jvmTest/kotlin/okio/PipeKotlinTest.kt b/okio/src/jvmTest/kotlin/okio/PipeKotlinTest.kt
index ac50f3a0..d4e0bdc5 100644
--- a/okio/src/jvmTest/kotlin/okio/PipeKotlinTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/PipeKotlinTest.kt
@@ -18,6 +18,7 @@ package okio
 import java.io.IOException
 import java.util.concurrent.CountDownLatch
 import java.util.concurrent.TimeUnit
+import java.util.concurrent.atomic.AtomicBoolean
 import kotlin.test.assertFailsWith
 import org.junit.After
 import org.junit.Assert.assertEquals
@@ -129,6 +130,46 @@ class PipeKotlinTest {
     }
   }
 
+  @Test fun closeWhileFolding() {
+    val pipe = Pipe(100L)
+    val writing = CountDownLatch(1)
+    val closed = CountDownLatch(1)
+    val sinkBuffer = Buffer()
+    val sinkClosed = AtomicBoolean()
+    val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
+    pipe.sink.write(Buffer().write(data), data.size.toLong())
+    val foldResult = executorService.submit {
+      val sink = object : Sink {
+        override fun write(source: Buffer, byteCount: Long) {
+          writing.countDown()
+          closed.await()
+          sinkBuffer.write(source, byteCount)
+        }
+
+        override fun flush() {
+          sinkBuffer.flush()
+        }
+
+        override fun timeout(): Timeout {
+          return sinkBuffer.timeout()
+        }
+
+        override fun close() {
+          sinkBuffer.close()
+          sinkClosed.set(true)
+        }
+      }
+      pipe.fold(sink)
+    }
+    writing.await()
+    pipe.sink.close()
+    closed.countDown()
+    foldResult.get()
+
+    assertTrue(sinkClosed.get())
+    assertArrayEquals(data, sinkBuffer.readByteArray())
+  }
+
   @Test fun honorsPipeSinkTimeoutOnWritingWhenItIsSmaller() {
     val pipe = Pipe(4)
     val underlying = TimeoutWritingSink()
diff --git a/okio/src/jvmTest/kotlin/okio/ReadUtf8LineTest.kt b/okio/src/jvmTest/kotlin/okio/ReadUtf8LineTest.kt
index 6f64355b..af3dc230 100644
--- a/okio/src/jvmTest/kotlin/okio/ReadUtf8LineTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/ReadUtf8LineTest.kt
@@ -15,36 +15,45 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.io.EOFException
 import okio.TestUtil.SEGMENT_SIZE
 import org.junit.Assert.assertEquals
 import org.junit.Assert.assertNull
 import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
-import org.junit.Before
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameter
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
-class ReadUtf8LineTest {
-  interface Factory {
-    fun create(data: Buffer): BufferedSource
-  }
-
-  @Parameter
-  lateinit var factory: Factory
-  private lateinit var data: Buffer
-  private lateinit var source: BufferedSource
+@Burst
+class ReadUtf8LineTest(
+  factory: Factory,
+) {
+  enum class Factory {
+    BasicBuffer {
+      override fun create(data: Buffer) = data
+    },
+    Buffered {
+      override fun create(data: Buffer): BufferedSource = RealBufferedSource(data)
+    },
+    SlowBuffered {
+      override fun create(data: Buffer): BufferedSource {
+        return RealBufferedSource(
+          object : ForwardingSource(data) {
+            override fun read(sink: Buffer, byteCount: Long): Long {
+              return super.read(sink, 1L.coerceAtMost(byteCount))
+            }
+          },
+        )
+      }
+    },
+    ;
 
-  @Before
-  fun setUp() {
-    data = Buffer()
-    source = factory.create(data)
+    abstract fun create(data: Buffer): BufferedSource
   }
 
+  private val data: Buffer = Buffer()
+  private val source: BufferedSource = factory.create(data)
+
   @Test
   fun readLines() {
     data.writeUtf8("abc\ndef\n")
@@ -178,40 +187,4 @@ class ReadUtf8LineTest {
     assertEquals("def", source.readUtf8Line())
     assertNull(source.readUtf8Line())
   }
-
-  companion object {
-    @JvmStatic
-    @Parameters(name = "{0}")
-    fun parameters(): List<Array<Any>> {
-      return listOf(
-        arrayOf(
-          object : Factory {
-            override fun create(data: Buffer) = data
-            override fun toString() = "Buffer"
-          },
-        ),
-        arrayOf(
-          object : Factory {
-            override fun create(data: Buffer) = RealBufferedSource(data)
-            override fun toString() = "RealBufferedSource"
-          },
-        ),
-        arrayOf(
-          object : Factory {
-            override fun create(data: Buffer): BufferedSource {
-              return RealBufferedSource(
-                object : ForwardingSource(data) {
-                  override fun read(sink: Buffer, byteCount: Long): Long {
-                    return super.read(sink, 1L.coerceAtMost(byteCount))
-                  }
-                },
-              )
-            }
-
-            override fun toString() = "Slow RealBufferedSource"
-          },
-        ),
-      )
-    }
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/TestUtil.kt b/okio/src/jvmTest/kotlin/okio/TestUtil.kt
index 703986e7..3e5e9547 100644
--- a/okio/src/jvmTest/kotlin/okio/TestUtil.kt
+++ b/okio/src/jvmTest/kotlin/okio/TestUtil.kt
@@ -38,11 +38,6 @@ object TestUtil {
   @JvmStatic
   fun segmentSizes(buffer: Buffer): List<Int> = okio.segmentSizes(buffer)
 
-  @JvmStatic
-  fun assertNoEmptySegments(buffer: Buffer) {
-    assertTrue(segmentSizes(buffer).all { it != 0 }, "Expected all segments to be non-empty")
-  }
-
   @JvmStatic
   fun assertByteArraysEquals(a: ByteArray, b: ByteArray) {
     assertEquals(a.contentToString(), b.contentToString())
diff --git a/okio/src/jvmTest/kotlin/okio/TimeoutFactory.kt b/okio/src/jvmTest/kotlin/okio/TimeoutFactory.kt
index 3a9cac7c..7ab0479f 100644
--- a/okio/src/jvmTest/kotlin/okio/TimeoutFactory.kt
+++ b/okio/src/jvmTest/kotlin/okio/TimeoutFactory.kt
@@ -16,15 +16,15 @@
 package okio
 
 enum class TimeoutFactory {
-  BASE {
+  Base {
     override fun newTimeout() = Timeout()
   },
 
-  FORWARDING {
-    override fun newTimeout() = ForwardingTimeout(BASE.newTimeout())
+  Forwarding {
+    override fun newTimeout() = ForwardingTimeout(Base.newTimeout())
   },
 
-  ASYNC {
+  Async {
     override fun newTimeout() = AsyncTimeout()
   },
   ;
diff --git a/okio/src/jvmTest/kotlin/okio/WaitUntilNotifiedTest.kt b/okio/src/jvmTest/kotlin/okio/WaitUntilNotifiedTest.kt
index 44c6bbfd..41440751 100644
--- a/okio/src/jvmTest/kotlin/okio/WaitUntilNotifiedTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/WaitUntilNotifiedTest.kt
@@ -15,6 +15,7 @@
  */
 package okio
 
+import app.cash.burst.Burst
 import java.io.InterruptedIOException
 import java.util.concurrent.TimeUnit
 import okio.TestUtil.assumeNotWindows
@@ -24,11 +25,8 @@ import org.junit.Assert.assertEquals
 import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
-import org.junit.runners.Parameterized.Parameters
 
-@RunWith(Parameterized::class)
+@Burst
 class WaitUntilNotifiedTest(
   factory: TimeoutFactory,
 ) {
@@ -227,10 +225,4 @@ class WaitUntilNotifiedTest(
       TimeUnit.MILLISECONDS,
     )
   }
-
-  companion object {
-    @Parameters(name = "{0}")
-    @JvmStatic
-    fun parameters(): List<Array<out Any?>> = TimeoutFactory.entries.map { arrayOf(it) }
-  }
 }
diff --git a/okio/src/jvmTest/kotlin/okio/internal/HmacTest.kt b/okio/src/jvmTest/kotlin/okio/internal/HmacTest.kt
index 01666d17..8c31517d 100644
--- a/okio/src/jvmTest/kotlin/okio/internal/HmacTest.kt
+++ b/okio/src/jvmTest/kotlin/okio/internal/HmacTest.kt
@@ -15,57 +15,28 @@
  */
 package okio.internal
 
+import app.cash.burst.Burst
 import javax.crypto.Mac
 import javax.crypto.spec.SecretKeySpec
 import kotlin.random.Random
 import okio.ByteString
 import org.junit.Assert
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
 
 /**
  * Check the [Hmac] implementation against the reference [Mac] JVM implementation.
  */
-@RunWith(Parameterized::class)
-class HmacTest(val parameters: Parameters) {
-
-  companion object {
-    @get:Parameterized.Parameters(name = "{0}")
-    @get:JvmStatic
-    val parameters: List<Parameters>
-      get() {
-        val algorithms = enumValues<Parameters.Algorithm>()
-        val keySizes = listOf(8, 32, 48, 64, 128, 256)
-        val dataSizes = listOf(0, 32, 64, 128, 256, 512)
-        return algorithms.flatMap { algorithm ->
-          keySizes.flatMap { keySize ->
-            dataSizes.map { dataSize ->
-              Parameters(
-                algorithm,
-                keySize,
-                dataSize,
-              )
-            }
-          }
-        }
-      }
-  }
-
-  private val keySize
-    get() = parameters.keySize
-  private val dataSize
-    get() = parameters.dataSize
-  private val algorithm
-    get() = parameters.algorithmName
-
+@Burst
+class HmacTest(
+  keySize: KeySize,
+  dataSize: DataSize,
+  algorithm: Algorithm,
+) {
   private val random = Random(682741861446)
-
-  private val key = random.nextBytes(keySize)
-  private val bytes = random.nextBytes(dataSize)
-  private val mac = parameters.createMac(key)
-
-  private val expected = hmac(algorithm, key, bytes)
+  private val key = random.nextBytes(keySize.size)
+  private val bytes = random.nextBytes(dataSize.size)
+  private val mac = algorithm.HmacFactory(ByteString(key))
+  private val expected = hmac(algorithm.algorithmName, key, bytes)
 
   @Test
   fun hmac() {
@@ -84,27 +55,23 @@ class HmacTest(val parameters: Parameters) {
 
     Assert.assertArrayEquals(expected, hmacValue)
   }
+}
 
-  data class Parameters(
-    val algorithm: Algorithm,
-    val keySize: Int,
-    val dataSize: Int,
-  ) {
-    val algorithmName
-      get() = algorithm.algorithmName
+enum class KeySize(val size: Int) {
+  K8(8), K32(32), K48(48), K64(64), K128(128), K256(256),
+}
 
-    internal fun createMac(key: ByteArray) =
-      algorithm.HmacFactory(ByteString(key))
+enum class DataSize(val size: Int) {
+  V0(0), V32(32), V64(64), V128(128), V256(256), V512(512),
+}
 
-    enum class Algorithm(
-      val algorithmName: String,
-      internal val HmacFactory: (key: ByteString) -> Hmac,
-    ) {
-      SHA_1("HmacSha1", Hmac.Companion::sha1),
-      SHA_256("HmacSha256", Hmac.Companion::sha256),
-      SHA_512("HmacSha512", Hmac.Companion::sha512),
-    }
-  }
+enum class Algorithm(
+  val algorithmName: String,
+  internal val HmacFactory: (key: ByteString) -> Hmac,
+) {
+  Sha1("HmacSha1", Hmac.Companion::sha1),
+  Sha256("HmacSha256", Hmac.Companion::sha256),
+  Sha512("HmacSha512", Hmac.Companion::sha512),
 }
 
 private fun hmac(algorithm: String, key: ByteArray, bytes: ByteArray) =
diff --git a/okio/src/nativeMain/kotlin/okio/Cinterop.kt b/okio/src/nativeMain/kotlin/okio/Cinterop.kt
index a9f3e74f..c5b93c9a 100644
--- a/okio/src/nativeMain/kotlin/okio/Cinterop.kt
+++ b/okio/src/nativeMain/kotlin/okio/Cinterop.kt
@@ -16,12 +16,20 @@
 package okio
 
 import kotlinx.cinterop.ByteVarOf
+import kotlinx.cinterop.COpaquePointer
 import kotlinx.cinterop.CPointer
 import kotlinx.cinterop.get
+import kotlinx.cinterop.readBytes
 import kotlinx.cinterop.set
+import okio.ByteString.Companion.EMPTY
 import platform.posix.ENOENT
 import platform.posix.strerror
 
+/** Copy [count] bytes from the memory at this pointer into a [ByteString]. */
+fun COpaquePointer.readByteString(count: Int): ByteString {
+  return if (count == 0) EMPTY else ByteString(readBytes(count))
+}
+
 internal fun Buffer.writeNullTerminated(bytes: CPointer<ByteVarOf<Byte>>): Buffer = apply {
   var pos = 0
   while (true) {
diff --git a/okio/src/nativeMain/kotlin/okio/DataProcessor.kt b/okio/src/nativeMain/kotlin/okio/DataProcessor.kt
new file mode 100644
index 00000000..c19e3a19
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/DataProcessor.kt
@@ -0,0 +1,242 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+private val emptyByteArray = byteArrayOf()
+
+/**
+ * Transform a stream of source bytes into a stream of target bytes, one segment at a time. The
+ * relationship between input byte count and output byte count is arbitrary: a sequence of input
+ * bytes may produce zero output bytes, or many segments of output bytes.
+ *
+ * To use:
+ *
+ *  1. Create an instance.
+ *
+ *  2. Populate [source] with input data. Set [sourcePos] and [sourceLimit] to a readable slice of
+ *     this array.
+ *
+ *  3. Populate [target] with a destination for output data. Set [targetPos] and [targetLimit] to a
+ *     writable slice of this array.
+ *
+ *  4. Call [process] to read input data from [source] and write output to [target]. This function
+ *     advances [sourcePos] if input data was read and [targetPos] if compressed output was written.
+ *     If the input array is exhausted (`sourcePos == sourceLimit`) or the output array is full
+ *     (`targetPos == targetLimit`), make an adjustment and call [process] again.
+ *
+ *  5. Repeat steps 2 through 4 until the input data is completely exhausted.
+ *
+ *  6. Close the processor.
+ *
+ * See also, the [zlib manual](https://www.zlib.net/manual.html).
+ */
+internal abstract class DataProcessor : Closeable {
+  var source: ByteArray = emptyByteArray
+  var sourcePos: Int = 0
+  var sourceLimit: Int = 0
+
+  var target: ByteArray = emptyByteArray
+  var targetPos: Int = 0
+  var targetLimit: Int = 0
+
+  var closed: Boolean = false
+    protected set
+
+  /** True if the content is self-terminating and has reached the end of the stream. */
+  var finished: Boolean = false
+    internal set
+
+  /**
+   * Returns true if no further calls to [process] are required to complete the operation.
+   * Otherwise, make space available in [target] and call this again.
+   */
+  @Throws(ProtocolException::class)
+  abstract fun process(): Boolean
+
+  /** True if calling [process] may produce more output without more input. */
+  private var callProcess = false
+
+  /**
+   * Consume [sourceExactByteCount] bytes from [source], writing any amount of output to [target].
+   *
+   * Note that 0 is a valid number of bytes to process, and this will cause flush and finish blocks
+   * to be written. For such 0-byte writes [source] may be null.
+   */
+  @Throws(IOException::class)
+  fun writeBytesFromSource(
+    source: Buffer?,
+    sourceExactByteCount: Long,
+    target: BufferedSink,
+  ) {
+    check(!closed) { "closed" }
+
+    var byteCount = 0
+    while (true) {
+      val sourceHead = prepareSource(source, sourceExactByteCount - byteCount)
+      val targetTail = prepareTarget(target)
+      try {
+        callProcess = !process()
+      } finally {
+        byteCount += updateSource(source, sourceHead)
+        updateTarget(target, targetTail)
+      }
+
+      // If we've produced a full segment, emit it. This blocks writing to the target.
+      target.emitCompleteSegments()
+
+      // Keep going until we've consumed the required byte count.
+      if (byteCount < sourceExactByteCount) continue
+
+      // More output is available without consuming more input. Produce it.
+      if (callProcess) continue
+
+      break
+    }
+  }
+
+  /**
+   * Produce up to [targetMaxByteCount] bytes to target, reading any number of bytes from [source].
+   *
+   * @return the total number of bytes produced to [target], or -1L if no bytes were produced.
+   */
+  @Throws(IOException::class)
+  fun readBytesToTarget(
+    source: BufferedSource,
+    targetMaxByteCount: Long,
+    target: Buffer,
+  ): Long {
+    check(!closed) { "closed" }
+
+    var byteCount = 0L
+    while (true) {
+      // Make sure we have input to process. This blocks reading the source.
+      val sourceExhausted = when {
+        !callProcess && byteCount == 0L -> finished || source.exhausted()
+        else -> false
+      }
+
+      val sourceHead = prepareSource(source.buffer)
+      val targetTail = prepareTarget(target, targetMaxByteCount - byteCount)
+      try {
+        callProcess = !process()
+      } finally {
+        updateSource(source.buffer, sourceHead)
+        byteCount += updateTarget(target, targetTail)
+      }
+
+      // Keep going until either we produce 1+ byte of output, or we exhaust the stream.
+      if (!sourceExhausted && byteCount == 0L) continue
+
+      // More output is available without consuming more input. Produce it.
+      if (callProcess && byteCount < targetMaxByteCount) continue
+
+      break
+    }
+
+    return when {
+      byteCount > 0L -> byteCount
+      else -> -1L
+    }
+  }
+
+  /** Tell the processor to read up to [maxByteCount] bytes from the source's first segment. */
+  private fun prepareSource(
+    source: Buffer?,
+    maxByteCount: Long = Long.MAX_VALUE,
+  ): Segment? {
+    val head = source?.buffer?.head
+    if (maxByteCount == 0L || head == null) {
+      sourcePos = 0
+      sourceLimit = 0
+      return null
+    }
+
+    val toProcess = minOf(maxByteCount, head.limit - head.pos).toInt()
+    this.source = head.data
+    this.sourcePos = head.pos
+    this.sourceLimit = head.pos + toProcess
+    return head
+  }
+
+  /**
+   * Track what was consumed from the source, if anything.
+   *
+   * Returns the number of consumed bytes.
+   */
+  private fun updateSource(
+    source: Buffer?,
+    sourceHead: Segment?,
+  ): Int {
+    if (sourceLimit == 0) return 0
+
+    source!!
+    val consumedByteCount = sourcePos - sourceHead!!.pos
+    sourceHead.pos = sourcePos
+    source.size -= consumedByteCount
+
+    // If we used up the head segment, recycle it.
+    if (sourceHead.pos == sourceHead.limit) {
+      source.head = sourceHead.pop()
+      SegmentPool.recycle(sourceHead)
+    }
+
+    this.source = emptyByteArray
+    this.sourcePos = 0
+    this.sourceLimit = 0
+
+    return consumedByteCount
+  }
+
+  /** Tell the processor to write to the target's last segment. */
+  private fun prepareTarget(
+    target: BufferedSink,
+    maxByteCount: Long = Long.MAX_VALUE,
+  ): Segment {
+    val tail = target.buffer.writableSegment(1)
+    val toProcess = minOf(maxByteCount, tail.data.size - tail.limit).toInt()
+    this.target = tail.data
+    this.targetPos = tail.limit
+    this.targetLimit = tail.limit + toProcess
+    return tail
+  }
+
+  /**
+   * Track what was produced on the target, if anything, and emit the bytes to the target stream.
+   *
+   * Returns the number of produced bytes.
+   */
+  private fun updateTarget(
+    target: BufferedSink,
+    tail: Segment,
+  ): Int {
+    val producedByteCount = targetPos - tail.limit
+
+    if (producedByteCount == 0 && tail.pos == tail.limit) {
+      // We allocated a tail segment, but didn't end up needing it. Recycle!
+      target.buffer.head = tail.pop()
+      SegmentPool.recycle(tail)
+    } else {
+      tail.limit = targetPos
+      target.buffer.size += producedByteCount
+    }
+
+    this.target = emptyByteArray
+    this.targetPos = 0
+    this.targetLimit = 0
+
+    return producedByteCount
+  }
+}
diff --git a/okio/src/nativeMain/kotlin/okio/Deflater.kt b/okio/src/nativeMain/kotlin/okio/Deflater.kt
new file mode 100644
index 00000000..f762d932
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/Deflater.kt
@@ -0,0 +1,130 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlinx.cinterop.CPointer
+import kotlinx.cinterop.UByteVar
+import kotlinx.cinterop.UnsafeNumber
+import kotlinx.cinterop.addressOf
+import kotlinx.cinterop.alloc
+import kotlinx.cinterop.free
+import kotlinx.cinterop.nativeHeap
+import kotlinx.cinterop.ptr
+import kotlinx.cinterop.usePinned
+import platform.zlib.Z_DEFAULT_COMPRESSION
+import platform.zlib.Z_DEFAULT_STRATEGY
+import platform.zlib.Z_DEFLATED
+import platform.zlib.Z_FINISH
+import platform.zlib.Z_NO_FLUSH
+import platform.zlib.Z_OK
+import platform.zlib.Z_STREAM_END
+import platform.zlib.Z_STREAM_ERROR
+import platform.zlib.Z_SYNC_FLUSH
+import platform.zlib.deflate
+import platform.zlib.deflateEnd
+import platform.zlib.deflateInit2
+import platform.zlib.z_stream_s
+
+/**
+ * Deflate using Kotlin/Native's built-in zlib bindings. This uses the raw deflate format and omits
+ * the zlib header and trailer, and does not compute a check value.
+ *
+ * Note that you must set [flush] to [Z_FINISH] before the last call to [process]. (It is okay to
+ * call process() when the source is exhausted.)
+ *
+ * See also, the [zlib manual](https://www.zlib.net/manual.html).
+ */
+actual class Deflater actual constructor(
+  level: Int,
+  nowrap: Boolean,
+) {
+  private val zStream: z_stream_s = nativeHeap.alloc<z_stream_s> {
+    zalloc = null
+    zfree = null
+    opaque = null
+    check(
+      deflateInit2(
+        strm = ptr,
+        level = level,
+        method = Z_DEFLATED,
+        windowBits = if (nowrap) -15 else 15, // Negative for raw deflate.
+        memLevel = 8, // Default value.
+        strategy = Z_DEFAULT_STRATEGY,
+      ) == Z_OK,
+    )
+  }
+
+  /** Probably [Z_NO_FLUSH], [Z_FINISH], or [Z_SYNC_FLUSH]. */
+  var flush: Int = Z_NO_FLUSH
+
+  actual constructor() : this(Z_DEFAULT_COMPRESSION, false)
+
+  internal val dataProcessor: DataProcessor = object : DataProcessor() {
+    override fun process(): Boolean {
+      check(!closed) { "closed" }
+      require(0 <= sourcePos && sourcePos <= sourceLimit && sourceLimit <= source.size)
+      require(0 <= targetPos && targetPos <= targetLimit && targetLimit <= target.size)
+
+      source.usePinned { pinnedSource ->
+        target.usePinned { pinnedTarget ->
+          val sourceByteCount = sourceLimit - sourcePos
+          zStream.next_in = when {
+            sourceByteCount > 0 -> pinnedSource.addressOf(sourcePos) as CPointer<UByteVar>
+            else -> null
+          }
+          zStream.avail_in = sourceByteCount.toUInt()
+
+          val targetByteCount = targetLimit - targetPos
+          zStream.next_out = when {
+            targetByteCount > 0 -> pinnedTarget.addressOf(targetPos) as CPointer<UByteVar>
+            else -> null
+          }
+          zStream.avail_out = targetByteCount.toUInt()
+
+          // One of Z_OK, Z_STREAM_END, Z_STREAM_ERROR, or Z_BUF_ERROR.
+          val deflateResult = deflate(zStream.ptr, flush)
+          check(deflateResult != Z_STREAM_ERROR)
+
+          sourcePos += sourceByteCount - zStream.avail_in.toInt()
+          targetPos += targetByteCount - zStream.avail_out.toInt()
+
+          return when (deflateResult) {
+            Z_STREAM_END -> true
+            else -> targetPos < targetLimit
+          }
+        }
+      }
+    }
+
+    override fun close() {
+      if (closed) return
+      closed = true
+
+      deflateEnd(zStream.ptr)
+      nativeHeap.free(zStream)
+    }
+  }
+
+  @OptIn(UnsafeNumber::class)
+  actual fun getBytesRead(): Long {
+    check(!dataProcessor.closed) { "closed" }
+    return zStream.total_in.toLong()
+  }
+
+  actual fun end() {
+    dataProcessor.close()
+  }
+}
diff --git a/okio/src/nativeMain/kotlin/okio/DeflaterSink.kt b/okio/src/nativeMain/kotlin/okio/DeflaterSink.kt
new file mode 100644
index 00000000..496854d2
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/DeflaterSink.kt
@@ -0,0 +1,93 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import platform.zlib.Z_FINISH
+import platform.zlib.Z_NO_FLUSH
+import platform.zlib.Z_SYNC_FLUSH
+
+actual class DeflaterSink internal actual constructor(
+  private val sink: BufferedSink,
+  internal val deflater: Deflater,
+) : Sink {
+  actual constructor(
+    sink: Sink,
+    deflater: Deflater,
+  ) : this(sink.buffer(), deflater)
+
+  @Throws(IOException::class)
+  actual override fun write(source: Buffer, byteCount: Long) {
+    checkOffsetAndCount(source.size, 0, byteCount)
+
+    deflater.flush = Z_NO_FLUSH
+    deflater.dataProcessor.writeBytesFromSource(
+      source = source,
+      sourceExactByteCount = byteCount,
+      target = sink,
+    )
+  }
+
+  @Throws(IOException::class)
+  actual override fun flush() {
+    deflater.flush = Z_SYNC_FLUSH
+    deflater.dataProcessor.writeBytesFromSource(
+      source = null,
+      sourceExactByteCount = 0L,
+      target = sink,
+    )
+
+    sink.flush()
+  }
+
+  actual override fun timeout(): Timeout {
+    return sink.timeout()
+  }
+
+  @Throws(IOException::class)
+  internal actual fun finishDeflate() {
+    deflater.flush = Z_FINISH
+    deflater.dataProcessor.writeBytesFromSource(
+      source = null,
+      sourceExactByteCount = 0L,
+      target = sink,
+    )
+  }
+
+  @Throws(IOException::class)
+  actual override fun close() {
+    if (deflater.dataProcessor.closed) return
+
+    // We must close the deflater and the target, even if flushing fails. Otherwise, we'll leak
+    // resources! (And we re-throw whichever exception we catch first.)
+    var thrown: Throwable? = null
+
+    try {
+      finishDeflate()
+    } catch (e: Throwable) {
+      thrown = e
+    }
+
+    deflater.dataProcessor.close()
+
+    try {
+      sink.close()
+    } catch (e: Throwable) {
+      if (thrown == null) thrown = e
+    }
+
+    if (thrown != null) throw thrown
+  }
+}
diff --git a/okio/src/nativeMain/kotlin/okio/FileSystem.kt b/okio/src/nativeMain/kotlin/okio/FileSystem.kt
index eb1e1653..d575a62a 100644
--- a/okio/src/nativeMain/kotlin/okio/FileSystem.kt
+++ b/okio/src/nativeMain/kotlin/okio/FileSystem.kt
@@ -22,7 +22,7 @@ import okio.internal.commonExists
 import okio.internal.commonListRecursively
 import okio.internal.commonMetadata
 
-actual abstract class FileSystem {
+actual abstract class FileSystem : Closeable {
   @Throws(IOException::class)
   actual abstract fun canonicalize(path: Path): Path
 
@@ -102,6 +102,10 @@ actual abstract class FileSystem {
   @Throws(IOException::class)
   actual abstract fun createSymlink(source: Path, target: Path)
 
+  @Throws(IOException::class)
+  actual override fun close() {
+  }
+
   actual companion object {
     /**
      * The current process's host file system. Use this instance directly, or dependency inject a
@@ -112,3 +116,12 @@ actual abstract class FileSystem {
     actual val SYSTEM_TEMPORARY_DIRECTORY: Path = PLATFORM_TEMPORARY_DIRECTORY
   }
 }
+
+/*
+ * JVM and native platforms do offer a [SYSTEM] [FileSystem], however we cannot refine an 'expect' companion object.
+ * Therefore an extension property is provided, which on respective platforms (here JVM) will be shadowed by the
+ * original implementation.
+ */
+@Suppress("EXTENSION_SHADOWED_BY_MEMBER")
+actual inline val FileSystem.Companion.SYSTEM: FileSystem
+  get() = SYSTEM
diff --git a/okio/src/nativeMain/kotlin/okio/Inflater.kt b/okio/src/nativeMain/kotlin/okio/Inflater.kt
new file mode 100644
index 00000000..82e63ee8
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/Inflater.kt
@@ -0,0 +1,121 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlinx.cinterop.CPointer
+import kotlinx.cinterop.UByteVar
+import kotlinx.cinterop.UnsafeNumber
+import kotlinx.cinterop.addressOf
+import kotlinx.cinterop.alloc
+import kotlinx.cinterop.free
+import kotlinx.cinterop.nativeHeap
+import kotlinx.cinterop.ptr
+import kotlinx.cinterop.usePinned
+import platform.zlib.Z_BUF_ERROR
+import platform.zlib.Z_DATA_ERROR
+import platform.zlib.Z_NO_FLUSH
+import platform.zlib.Z_OK
+import platform.zlib.Z_STREAM_END
+import platform.zlib.inflateEnd
+import platform.zlib.inflateInit2
+import platform.zlib.z_stream_s
+
+/**
+ * Inflate using Kotlin/Native's built-in zlib bindings.
+ */
+actual class Inflater actual constructor(
+  nowrap: Boolean,
+) {
+  private val zStream: z_stream_s = nativeHeap.alloc<z_stream_s> {
+    zalloc = null
+    zfree = null
+    opaque = null
+    check(
+      inflateInit2(
+        strm = ptr,
+        windowBits = if (nowrap) -15 else 15, // Negative for raw deflate.
+      ) == Z_OK,
+    )
+  }
+
+  internal val dataProcessor: DataProcessor = object : DataProcessor() {
+    @Throws(ProtocolException::class)
+    override fun process(): Boolean {
+      check(!closed) { "closed" }
+      require(0 <= sourcePos && sourcePos <= sourceLimit && sourceLimit <= source.size)
+      require(0 <= targetPos && targetPos <= targetLimit && targetLimit <= target.size)
+
+      source.usePinned { pinnedSource ->
+        target.usePinned { pinnedTarget ->
+          val sourceByteCount = sourceLimit - sourcePos
+          zStream.next_in = when {
+            sourceByteCount > 0 -> pinnedSource.addressOf(sourcePos) as CPointer<UByteVar>
+            else -> null
+          }
+          zStream.avail_in = sourceByteCount.toUInt()
+
+          val targetByteCount = targetLimit - targetPos
+          zStream.next_out = when {
+            targetByteCount > 0 -> pinnedTarget.addressOf(targetPos) as CPointer<UByteVar>
+            else -> null
+          }
+          zStream.avail_out = targetByteCount.toUInt()
+
+          val inflateResult = platform.zlib.inflate(zStream.ptr, Z_NO_FLUSH)
+
+          sourcePos += sourceByteCount - zStream.avail_in.toInt()
+          targetPos += targetByteCount - zStream.avail_out.toInt()
+
+          when (inflateResult) {
+            Z_OK, Z_BUF_ERROR -> {
+              return targetPos < targetLimit
+            }
+
+            Z_STREAM_END -> {
+              finished = true
+              return true
+            }
+
+            Z_DATA_ERROR -> throw ProtocolException("Z_DATA_ERROR")
+
+            // One of Z_NEED_DICT, Z_STREAM_ERROR, Z_MEM_ERROR.
+            else -> throw ProtocolException("unexpected inflate result: $inflateResult")
+          }
+        }
+      }
+    }
+
+    override fun close() {
+      if (closed) return
+      closed = true
+
+      inflateEnd(zStream.ptr)
+      nativeHeap.free(zStream)
+    }
+  }
+
+  actual constructor() : this(false)
+
+  @OptIn(UnsafeNumber::class)
+  actual fun getBytesWritten(): Long {
+    check(!dataProcessor.closed) { "closed" }
+    return zStream.total_out.toLong()
+  }
+
+  actual fun end() {
+    dataProcessor.close()
+  }
+}
diff --git a/okio/src/nativeMain/kotlin/okio/InflaterSource.kt b/okio/src/nativeMain/kotlin/okio/InflaterSource.kt
new file mode 100644
index 00000000..04351b96
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/InflaterSource.kt
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+actual class InflaterSource internal actual constructor(
+  internal val source: BufferedSource,
+  internal val inflater: Inflater,
+) : Source {
+  actual constructor(
+    source: Source,
+    inflater: Inflater,
+  ) : this(source.buffer(), inflater)
+
+  @Throws(IOException::class)
+  actual override fun read(sink: Buffer, byteCount: Long): Long {
+    require(byteCount >= 0L) { "byteCount < 0: $byteCount" }
+
+    return inflater.dataProcessor.readBytesToTarget(
+      source = source,
+      targetMaxByteCount = byteCount,
+      target = sink,
+    )
+  }
+
+  actual override fun timeout(): Timeout {
+    return source.timeout()
+  }
+
+  actual override fun close() {
+    if (inflater.dataProcessor.closed) return
+
+    inflater.dataProcessor.close()
+
+    source.close()
+  }
+}
diff --git a/okio/src/nativeMain/kotlin/okio/internal/-ZlibNative.kt b/okio/src/nativeMain/kotlin/okio/internal/-ZlibNative.kt
new file mode 100644
index 00000000..ac853399
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/internal/-ZlibNative.kt
@@ -0,0 +1,78 @@
+// ktlint-disable filename
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+internal actual val DEFAULT_COMPRESSION: Int = platform.zlib.Z_DEFAULT_COMPRESSION
+
+/**
+ * Roll our own date math because Kotlin doesn't include a built-in date math API, and the
+ * kotlinx.datetime library doesn't offer a stable release at this time.
+ *
+ * Also, we don't necessarily want to take on that dependency for Okio.
+ *
+ * This implementation assumes UTC.
+ *
+ * This code is broken for years before 1970. It doesn't implement subtraction for leap years.
+ *
+ * This code is broken for out-of-range values. For example, it doesn't correctly implement leap
+ * year offsets when the month is -24 or when the day is -365.
+ */
+internal actual fun datePartsToEpochMillis(
+  year: Int,
+  month: Int,
+  day: Int,
+  hour: Int,
+  minute: Int,
+  second: Int,
+): Long {
+  // Make sure month is in 1..12, adding or subtracting years as necessary.
+  val rawMonth = month
+  val month = (month - 1).mod(12) + 1
+  val year = year + (rawMonth - month) / 12
+
+  // Start with the cumulative number of days elapsed preceding the current year.
+  var dayCount = (year - 1970) * 365L
+
+  // Adjust by leap years. Years that divide 4 are leap years, unless they divide 100 but not 400.
+  val leapYear = if (month > 2) year else year - 1
+  dayCount += (leapYear - 1968) / 4 - (leapYear - 1900) / 100 + (leapYear - 1600) / 400
+
+  // Add the cumulative number of days elapsed preceding the current month.
+  dayCount += when (month) {
+    1 -> 0
+    2 -> 31
+    3 -> 59
+    4 -> 90
+    5 -> 120
+    6 -> 151
+    7 -> 181
+    8 -> 212
+    9 -> 243
+    10 -> 273
+    11 -> 304
+    else -> 334
+  }
+
+  // Add the cumulative number of days that precede the current day.
+  dayCount += (day - 1)
+
+  // Add hours + minutes + seconds for the current day.
+  val hourCount = dayCount * 24 + hour
+  val minuteCount = hourCount * 60 + minute
+  val secondCount = minuteCount * 60 + second
+  return secondCount * 1_000L
+}
diff --git a/okio/src/nativeMain/kotlin/okio/internal/CRC32.kt b/okio/src/nativeMain/kotlin/okio/internal/CRC32.kt
new file mode 100644
index 00000000..4abe0723
--- /dev/null
+++ b/okio/src/nativeMain/kotlin/okio/internal/CRC32.kt
@@ -0,0 +1,46 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+import kotlinx.cinterop.CValuesRef
+import kotlinx.cinterop.UnsafeNumber
+import kotlinx.cinterop.addressOf
+import kotlinx.cinterop.usePinned
+import platform.zlib.crc32
+import platform.zlib.uBytefVar
+
+@OptIn(UnsafeNumber::class)
+actual class CRC32 {
+  private var crc = crc32(0u, null, 0u)
+
+  actual fun update(content: ByteArray, offset: Int, byteCount: Int) {
+    content.usePinned {
+      crc = crc32(crc, it.addressOf(offset) as CValuesRef<uBytefVar>, byteCount.toUInt())
+    }
+  }
+
+  actual fun update(content: ByteArray) {
+    update(content, 0, content.size)
+  }
+
+  actual fun getValue(): Long {
+    return crc.toLong()
+  }
+
+  actual fun reset() {
+    crc = crc32(0u, null, 0u)
+  }
+}
diff --git a/okio/src/nativeTest/kotlin/okio/ByteStringCinteropTest.kt b/okio/src/nativeTest/kotlin/okio/ByteStringCinteropTest.kt
new file mode 100644
index 00000000..7c1832c6
--- /dev/null
+++ b/okio/src/nativeTest/kotlin/okio/ByteStringCinteropTest.kt
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertSame
+import kotlinx.cinterop.allocArray
+import kotlinx.cinterop.memScoped
+import kotlinx.cinterop.plus
+import kotlinx.cinterop.value
+import okio.ByteString.Companion.EMPTY
+import okio.ByteString.Companion.encodeUtf8
+import platform.posix.uint8_tVar
+
+class ByteStringCinteropTest {
+  @Test fun pointerToByteStringZeroDoesNotRead() = memScoped {
+    val pointer = allocArray<uint8_tVar>(0)
+    val bytes = pointer.readByteString(0)
+    // Can't find a way to determine that readBytes was not called, so assume that if EMPTY was
+    // returned there was a short-circuit.
+    assertSame(EMPTY, bytes)
+  }
+
+  @Test fun pointerToByteString() = memScoped {
+    val pointer = allocArray<uint8_tVar>(26L) { index ->
+      value = ('a'.code + index).toUByte()
+    }
+    val bytes = pointer.plus(5)!!.readByteString(15)
+    assertEquals("fghijklmnopqrst".encodeUtf8(), bytes)
+  }
+}
diff --git a/okio/src/nativeTest/kotlin/okio/DeflaterSinkTest.kt b/okio/src/nativeTest/kotlin/okio/DeflaterSinkTest.kt
new file mode 100644
index 00000000..58855c57
--- /dev/null
+++ b/okio/src/nativeTest/kotlin/okio/DeflaterSinkTest.kt
@@ -0,0 +1,113 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertFailsWith
+import kotlin.test.assertTrue
+
+class DeflaterSinkTest {
+  @Test
+  fun deflateIntoSinkThatThrowsOnWrite() {
+    val throwingSink = ThrowingSink()
+
+    val content = randomBytes(1024 * 32)
+    val source = Buffer().write(content)
+
+    val deflaterSink = throwingSink.deflate()
+
+    throwingSink.nextException = IOException("boom")
+    assertFailsWith<IOException> {
+      deflaterSink.write(source, source.size)
+    }
+
+    // We didn't lose any data. This isn't how real programs recover in practice, but it
+    // demonstrates that no segments are unaccounted for after an exception
+    deflaterSink.write(source, source.size)
+    deflaterSink.close()
+
+    assertEquals(content, inflate(throwingSink.data))
+  }
+
+  @Test
+  fun deflateIntoSinkThatThrowsOnFlush() {
+    val throwingSink = ThrowingSink()
+
+    val content = randomBytes(1024 * 32)
+    val source = Buffer().write(content)
+
+    val deflaterSink = throwingSink.deflate()
+    deflaterSink.write(source, source.size)
+
+    throwingSink.nextException = IOException("boom")
+    assertFailsWith<IOException> {
+      deflaterSink.flush()
+    }
+
+    deflaterSink.close()
+
+    assertEquals(content, inflate(throwingSink.data))
+  }
+
+  @Test
+  fun deflateIntoSinkThatThrowsOnClose() {
+    val throwingSink = ThrowingSink()
+
+    val content = randomBytes(1024 * 32)
+    val source = Buffer().write(content)
+
+    val deflaterSink = throwingSink.deflate()
+    deflaterSink.write(source, source.size)
+
+    throwingSink.nextException = IOException("boom")
+    assertFailsWith<IOException> {
+      deflaterSink.close()
+    }
+
+    assertTrue(deflaterSink.deflater.dataProcessor.closed)
+    assertTrue(throwingSink.closed)
+  }
+
+  class ThrowingSink : Sink {
+    val data = Buffer()
+    var nextException: Throwable? = null
+    var closed = false
+
+    override fun write(source: Buffer, byteCount: Long) {
+      nextException?.let { nextException = null; throw it }
+      data.write(source, byteCount)
+    }
+
+    override fun flush() {
+      nextException?.let { nextException = null; throw it }
+      data.flush()
+    }
+
+    override fun timeout() = Timeout.NONE
+
+    override fun close() {
+      closed = true
+      nextException?.let { nextException = null; throw it }
+    }
+  }
+
+  private fun inflate(deflated: Buffer): ByteString {
+    return deflated.inflate().buffer().use { inflaterSource ->
+      inflaterSource.readByteString()
+    }
+  }
+}
diff --git a/okio/src/nativeTest/kotlin/okio/DeflaterTest.kt b/okio/src/nativeTest/kotlin/okio/DeflaterTest.kt
new file mode 100644
index 00000000..2173bd64
--- /dev/null
+++ b/okio/src/nativeTest/kotlin/okio/DeflaterTest.kt
@@ -0,0 +1,259 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertFailsWith
+import kotlin.test.assertFalse
+import kotlin.test.assertTrue
+import okio.ByteString.Companion.decodeBase64
+import okio.ByteString.Companion.encodeUtf8
+import okio.ByteString.Companion.toByteString
+import platform.zlib.Z_BEST_COMPRESSION
+import platform.zlib.Z_FINISH
+import platform.zlib.Z_NO_FLUSH
+import platform.zlib.Z_SYNC_FLUSH
+
+class DeflaterTest {
+  @Test
+  fun happyPath() {
+    val content = "God help us, we're in the hands of engineers."
+    val deflater = Deflater()
+    deflater.dataProcessor.apply {
+      source = content.encodeUtf8().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      deflater.flush = Z_FINISH
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      assertTrue(process())
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(content.length.toLong(), deflater.getBytesRead())
+      val deflated = target.toByteString(0, targetPos)
+
+      // Golden compressed output.
+      assertEquals(
+        "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s=".decodeBase64(),
+        deflated,
+      )
+
+      deflater.end()
+    }
+  }
+
+  @Test
+  fun happyPathNoWrap() {
+    val content = "God help us, we're in the hands of engineers."
+    val deflater = Deflater(nowrap = true)
+    deflater.dataProcessor.apply {
+      source = content.encodeUtf8().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      deflater.flush = Z_FINISH
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      assertTrue(process())
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(content.length.toLong(), deflater.getBytesRead())
+      val deflated = target.toByteString(0, targetPos)
+
+      // Golden compressed output.
+      assertEquals(
+        "c89PUchIzSlQKC3WUShPVS9KVcjMUyjJSFXISMxLKVbIT1NIzUvPzEtNLSrWAwA=".decodeBase64(),
+        deflated,
+      )
+
+      deflater.end()
+    }
+  }
+
+  @Test
+  fun deflateInParts() {
+    val contentA = "God help us, we're in the hands"
+    val contentB = " of engineers."
+    val deflater = Deflater()
+    deflater.dataProcessor.apply {
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      source = contentA.encodeUtf8().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      assertTrue(process())
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(contentA.length.toLong(), deflater.getBytesRead())
+
+      source = contentB.encodeUtf8().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      deflater.flush = Z_FINISH
+      assertTrue(process())
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals((contentA + contentB).length.toLong(), deflater.getBytesRead())
+
+      val deflated = target.toByteString(0, targetPos)
+
+      // Golden compressed output.
+      assertEquals(
+        "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s=".decodeBase64(),
+        deflated,
+      )
+
+      deflater.end()
+    }
+  }
+
+  @Test
+  fun deflateInsufficientSpaceInTargetWithoutSourceFinished() {
+    val targetBuffer = Buffer()
+
+    val content = "God help us, we're in the hands of engineers."
+    val deflater = Deflater()
+    deflater.dataProcessor.apply {
+      source = content.encodeUtf8().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+
+      target = ByteArray(10)
+      targetPos = 0
+      targetLimit = target.size
+      deflater.flush = Z_SYNC_FLUSH
+      assertFalse(process())
+      assertEquals(targetLimit, targetPos)
+      assertEquals(content.length.toLong(), deflater.getBytesRead())
+      targetBuffer.write(target)
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+      deflater.flush = Z_NO_FLUSH
+      assertTrue(process())
+      assertEquals(sourcePos, sourceLimit)
+      assertEquals(content.length.toLong(), deflater.getBytesRead())
+      targetBuffer.write(target, 0, targetPos)
+
+      deflater.flush = Z_FINISH
+      assertTrue(process())
+
+      // Golden compressed output.
+      assertEquals(
+        "eJxyz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYD".decodeBase64(),
+        targetBuffer.readByteString(),
+      )
+
+      deflater.end()
+    }
+  }
+
+  @Test
+  fun deflateInsufficientSpaceInTargetWithSourceFinished() {
+    val targetBuffer = Buffer()
+
+    val content = "God help us, we're in the hands of engineers."
+    val deflater = Deflater()
+    deflater.dataProcessor.apply {
+      source = content.encodeUtf8().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      deflater.flush = Z_FINISH
+
+      target = ByteArray(10)
+      targetPos = 0
+      targetLimit = target.size
+      assertFalse(process())
+      assertEquals(targetLimit, targetPos)
+      assertEquals(content.length.toLong(), deflater.getBytesRead())
+      targetBuffer.write(target)
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+      assertTrue(process())
+      assertEquals(sourcePos, sourceLimit)
+      assertEquals(content.length.toLong(), deflater.getBytesRead())
+      targetBuffer.write(target, 0, targetPos)
+
+      // Golden compressed output.
+      assertEquals(
+        "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s=".decodeBase64(),
+        targetBuffer.readByteString(),
+      )
+
+      deflater.end()
+    }
+  }
+
+  @Test
+  fun deflateEmptySource() {
+    val deflater = Deflater()
+    deflater.dataProcessor.apply {
+      deflater.flush = Z_FINISH
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      assertTrue(process())
+      assertEquals(0L, deflater.getBytesRead())
+      val deflated = target.toByteString(0, targetPos)
+
+      // Golden compressed output.
+      assertEquals(
+        "eJwDAAAAAAE=".decodeBase64(),
+        deflated,
+      )
+
+      deflater.end()
+    }
+  }
+
+  @Test
+  fun cannotDeflateAfterEnd() {
+    val deflater = Deflater()
+    deflater.end()
+
+    assertFailsWith<IllegalStateException> {
+      deflater.dataProcessor.process()
+    }
+  }
+
+  @Test
+  fun cannotGetBytesReadAfterEnd() {
+    val deflater = Deflater()
+    deflater.end()
+
+    assertFailsWith<IllegalStateException> {
+      deflater.getBytesRead()
+    }
+  }
+
+  @Test
+  fun endIsIdemptent() {
+    val deflater = Deflater()
+    deflater.end()
+    deflater.end()
+  }
+
+  private fun Deflater(nowrap: Boolean) = Deflater(Z_BEST_COMPRESSION, nowrap)
+}
diff --git a/okio/src/nativeTest/kotlin/okio/InflateDeflateTest.kt b/okio/src/nativeTest/kotlin/okio/InflateDeflateTest.kt
new file mode 100644
index 00000000..b7998153
--- /dev/null
+++ b/okio/src/nativeTest/kotlin/okio/InflateDeflateTest.kt
@@ -0,0 +1,96 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertTrue
+import okio.ByteString.Companion.toByteString
+import platform.zlib.Z_BEST_COMPRESSION
+
+class InflateDeflateTest {
+  /** The compressed data is 0.1% of the size of the original. */
+  @Test
+  fun deflateInflate_compressionRatio0_01() {
+    deflateInflate(
+      contentList = Array(16) {
+        ByteArray(1024 * 64) { 0 }.toByteString()
+      },
+      goldenCompressedSize = 1_330,
+    )
+  }
+
+  /** The compressed data is 100% of the size of the original. */
+  @Test
+  fun deflateInflate_compressionRatio100_0() {
+    deflateInflate(
+      contentList = Array(16) {
+        randomBytes(1024 * 64, seed = it)
+      },
+      goldenCompressedSize = 1_048_978,
+    )
+  }
+
+  /** The compressed data is 700% of the size of the original. */
+  @Test
+  fun deflateInflate_compressionRatio700_0() {
+    deflateInflate(
+      contentList = Array(1024 * 64) {
+        randomBytes(1, seed = it)
+      },
+      goldenCompressedSize = 458_959,
+    )
+  }
+
+  @Test
+  fun deflateInflateEmpty() {
+    deflateInflate(
+      contentList = arrayOf(),
+      goldenCompressedSize = 2,
+    )
+  }
+
+  private fun deflateInflate(
+    contentList: Array<ByteString>,
+    goldenCompressedSize: Long,
+  ) {
+    val data = Buffer()
+
+    val deflaterSink = DeflaterSink(
+      sink = data,
+      deflater = Deflater(level = Z_BEST_COMPRESSION, nowrap = true),
+    )
+    deflaterSink.buffer().use {
+      for (c in contentList) {
+        it.write(c)
+        it.flush()
+      }
+    }
+
+    assertEquals(goldenCompressedSize, data.size)
+
+    val inflaterSource = InflaterSource(
+      source = data,
+      inflater = Inflater(nowrap = true),
+    )
+    inflaterSource.buffer().use {
+      for (content in contentList) {
+        assertEquals(content, it.readByteString(content.size.toLong()))
+      }
+      assertTrue(it.exhausted())
+    }
+  }
+}
diff --git a/okio/src/nativeTest/kotlin/okio/InflaterSourceTest.kt b/okio/src/nativeTest/kotlin/okio/InflaterSourceTest.kt
new file mode 100644
index 00000000..d28db137
--- /dev/null
+++ b/okio/src/nativeTest/kotlin/okio/InflaterSourceTest.kt
@@ -0,0 +1,180 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertFailsWith
+import kotlin.test.assertTrue
+
+class InflaterSourceTest {
+  @Test
+  fun inflateFromSourceThatThrowsOnRead() {
+    val content = randomBytes(1024 * 32)
+
+    val throwingSource = ThrowingSource()
+    deflate(throwingSource.data, content)
+
+    val inflaterSource = throwingSource.inflate()
+
+    val sink = Buffer()
+    throwingSource.nextException = IOException("boom")
+    assertFailsWith<IOException> {
+      inflaterSource.read(sink, Long.MAX_VALUE)
+    }
+    assertEquals(0, sink.size)
+
+    // We didn't lose any data. This isn't how real programs recover in practice, but it
+    // demonstrates that no segments are unaccounted for after an exception
+    assertEquals(content, inflaterSource.buffer().readByteString())
+    inflaterSource.close()
+    assertNoEmptySegments(throwingSource.data)
+    assertNoEmptySegments(sink)
+  }
+
+  @Test
+  fun inflateSourceThrowsOnClose() {
+    val content = randomBytes(1024 * 32)
+
+    val throwingSource = ThrowingSource()
+    deflate(throwingSource.data, content)
+
+    val inflaterSource = throwingSource.inflate()
+    val bufferedInflaterSource = inflaterSource.buffer()
+    assertEquals(content, bufferedInflaterSource.readByteString())
+
+    throwingSource.nextException = IOException("boom")
+    assertFailsWith<IOException> {
+      inflaterSource.close()
+    }
+
+    assertTrue(throwingSource.closed)
+    assertTrue(inflaterSource.inflater.dataProcessor.closed)
+    assertNoEmptySegments(throwingSource.data)
+    assertNoEmptySegments(bufferedInflaterSource.buffer)
+  }
+
+  @Test
+  fun inflateInvalidThrows() {
+    // Half valid deflated data + and half 0xff.
+    val invalidData = Buffer()
+      .apply {
+        val deflatedData = Buffer()
+        deflate(deflatedData, randomBytes(1024 * 32))
+        write(deflatedData, deflatedData.size / 2)
+
+        write(ByteArray(deflatedData.size.toInt() / 2) { -128 })
+      }
+
+    val inflaterSource = invalidData.inflate()
+    val bufferedInflaterSource = inflaterSource.buffer()
+    assertFailsWith<IOException> {
+      bufferedInflaterSource.readByteString()
+    }
+
+    bufferedInflaterSource.close()
+    assertTrue(inflaterSource.inflater.dataProcessor.closed)
+    assertNoEmptySegments(invalidData.buffer)
+    assertNoEmptySegments(bufferedInflaterSource.buffer)
+  }
+
+  /**
+   * Confirm that [InflaterSource.read] doesn't read from its source stream until it's necessary
+   * to do so. (When it does read from the source, it reads a full segment.)
+   */
+  @Test
+  fun readsFromSourceDoNotOccurUntilNecessary() {
+    val deflatedData = Buffer()
+    deflate(deflatedData, randomBytes(1024 * 32, seed = 0))
+
+    val inflaterSource = deflatedData.inflate()
+
+    // These index values discovered experimentally.
+    val sink = Buffer()
+    inflaterSource.read(sink, 8184)
+    assertEquals(24 * 1024 + 16, deflatedData.size)
+
+    inflaterSource.read(sink, 1)
+    assertEquals(24 * 1024 + 16, deflatedData.size)
+
+    inflaterSource.read(sink, 1)
+    assertEquals(16 * 1024 + 16, deflatedData.size)
+
+    inflaterSource.read(sink, 1)
+    assertEquals(16 * 1024 + 16, deflatedData.size)
+  }
+
+  @Test
+  fun readsFromSourceDoNotOccurAfterExhausted() {
+    val content = randomBytes(1024 * 32, seed = 0)
+
+    val throwingSource = ThrowingSource()
+    deflate(throwingSource.data, content)
+
+    val inflaterSource = throwingSource.inflate()
+    val bufferedInflaterSource = inflaterSource.buffer()
+
+    assertEquals(content, bufferedInflaterSource.readByteString())
+
+    throwingSource.nextException = IOException("boom")
+    assertTrue(bufferedInflaterSource.exhausted()) // Doesn't throw!
+    throwingSource.nextException = null
+
+    inflaterSource.close()
+  }
+
+  @Test
+  fun trailingDataIgnored() {
+    val content = randomBytes(1024 * 32)
+
+    val deflatedData = Buffer()
+    deflate(deflatedData, content)
+    deflatedData.write(ByteArray(1024 * 32))
+
+    val inflaterSource = deflatedData.inflate()
+    val bufferedInflaterSource = inflaterSource.buffer()
+
+    assertEquals(content, bufferedInflaterSource.readByteString())
+    assertTrue(bufferedInflaterSource.exhausted())
+    assertEquals(24_592, deflatedData.size) // One trailing segment is consumed.
+
+    inflaterSource.close()
+  }
+
+  class ThrowingSource : Source {
+    val data = Buffer()
+    var nextException: Throwable? = null
+    var closed = false
+
+    override fun read(sink: Buffer, byteCount: Long): Long {
+      nextException?.let { nextException = null; throw it }
+      return data.read(sink, byteCount)
+    }
+
+    override fun timeout() = Timeout.NONE
+
+    override fun close() {
+      closed = true
+      nextException?.let { nextException = null; throw it }
+    }
+  }
+
+  private fun deflate(sink: BufferedSink, content: ByteString) {
+    sink.deflate().buffer().use { deflaterSink ->
+      deflaterSink.write(content)
+    }
+  }
+}
diff --git a/okio/src/nativeTest/kotlin/okio/InflaterTest.kt b/okio/src/nativeTest/kotlin/okio/InflaterTest.kt
new file mode 100644
index 00000000..4ff488d8
--- /dev/null
+++ b/okio/src/nativeTest/kotlin/okio/InflaterTest.kt
@@ -0,0 +1,270 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertFailsWith
+import kotlin.test.assertFalse
+import kotlin.test.assertTrue
+import okio.ByteString.Companion.decodeBase64
+import okio.ByteString.Companion.decodeHex
+import okio.ByteString.Companion.toByteString
+
+class InflaterTest {
+  @Test
+  fun happyPath() {
+    val expected = "God help us, we're in the hands of engineers."
+    val inflater = Inflater()
+    inflater.dataProcessor.apply {
+      source = "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s="
+        .decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      assertTrue(process())
+      assertTrue(finished)
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(expected.length.toLong(), inflater.getBytesWritten())
+
+      val inflated = target.toByteString(0, targetPos)
+      assertEquals(
+        expected,
+        inflated.utf8(),
+      )
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun happyPathNoWrap() {
+    val content = "God help us, we're in the hands of engineers."
+    val inflater = Inflater(nowrap = true)
+    inflater.dataProcessor.apply {
+      source = "c89PUchIzSlQKC3WUShPVS9KVcjMUyjJSFXISMxLKVbIT1NIzUvPzEtNLSrWAwA="
+        .decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      assertTrue(process())
+      assertTrue(finished)
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(content.length.toLong(), inflater.getBytesWritten())
+
+      val inflated = target.toByteString(0, targetPos)
+      assertEquals(
+        content,
+        inflated.utf8(),
+      )
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun inflateInParts() {
+    val content = "God help us, we're in the hands of engineers."
+    val inflater = Inflater()
+    inflater.dataProcessor.apply {
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      source = "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxT".decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      assertTrue(process())
+      assertFalse(finished)
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(21, inflater.getBytesWritten())
+
+      source = "KMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s=".decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      assertTrue(process())
+      assertTrue(finished)
+      assertEquals(sourceLimit, sourcePos)
+      assertEquals(content.length.toLong(), inflater.getBytesWritten())
+
+      val inflated = target.toByteString(0, targetPos)
+      assertEquals(
+        content,
+        inflated.utf8(),
+      )
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun inflateInsufficientSpaceInTarget() {
+    val targetBuffer = Buffer()
+
+    val content = "God help us, we're in the hands of engineers."
+    val inflater = Inflater()
+    inflater.dataProcessor.apply {
+      source = "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s="
+        .decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+
+      target = ByteArray(31)
+      targetPos = 0
+      targetLimit = target.size
+      assertFalse(process())
+      assertFalse(finished)
+      assertEquals(targetLimit, targetPos)
+      targetBuffer.write(target)
+      assertEquals(31, inflater.getBytesWritten())
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+      assertTrue(process())
+      assertTrue(finished)
+      assertEquals(sourcePos, sourceLimit)
+      targetBuffer.write(target, 0, targetPos)
+      assertEquals(content.length.toLong(), inflater.getBytesWritten())
+
+      assertEquals(
+        content,
+        targetBuffer.readUtf8(),
+      )
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun inflateEmptyContent() {
+    val inflater = Inflater()
+    inflater.dataProcessor.apply {
+      source = "eJwDAAAAAAE=".decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      assertTrue(process())
+      assertTrue(finished)
+      assertEquals(0L, inflater.getBytesWritten())
+
+      val inflated = target.toByteString(0, targetPos)
+      assertEquals(
+        "",
+        inflated.utf8(),
+      )
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun inflateInPartsStartingWithEmptySource() {
+    val content = "God help us, we're in the hands of engineers."
+    val inflater = Inflater()
+    val dataProcessor = inflater.dataProcessor
+    dataProcessor.apply {
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      source = ByteArray(256)
+      sourcePos = 0
+      sourceLimit = 0
+      assertTrue(process())
+      assertFalse(finished)
+      assertEquals(0, inflater.getBytesWritten())
+
+      source = "eJxzz09RyEjNKVAoLdZRKE9VL0pVyMxTKMlIVchIzEspVshPU0jNS8/MS00tKtYDAF6CD5s="
+        .decodeBase64()!!.toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      assertTrue(process())
+      assertTrue(finished)
+      assertEquals(content.length.toLong(), inflater.getBytesWritten())
+
+      val inflated = target.toByteString(0, targetPos)
+      assertEquals(
+        content,
+        inflated.utf8(),
+      )
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun inflateInvalidData() {
+    val inflater = Inflater()
+    val dataProcessor = inflater.dataProcessor
+    dataProcessor.apply {
+      target = ByteArray(256)
+      targetPos = 0
+      targetLimit = target.size
+
+      source = "ffffffffffffffff".decodeHex().toByteArray()
+      sourcePos = 0
+      sourceLimit = source.size
+      val exception = assertFailsWith<ProtocolException> {
+        process()
+      }
+      assertFalse(finished)
+      assertEquals("Z_DATA_ERROR", exception.message)
+      assertEquals(0L, inflater.getBytesWritten())
+
+      inflater.end()
+    }
+  }
+
+  @Test
+  fun cannotInflateAfterEnd() {
+    val inflater = Inflater()
+    inflater.end()
+
+    assertFailsWith<IllegalStateException> {
+      inflater.dataProcessor.process()
+    }
+  }
+
+  @Test
+  fun cannotGetBytesWrittenAfterEnd() {
+    val inflater = Inflater()
+    inflater.end()
+
+    assertFailsWith<IllegalStateException> {
+      inflater.getBytesWritten()
+    }
+  }
+
+  @Test
+  fun endIsIdemptent() {
+    val inflater = Inflater()
+    inflater.end()
+    inflater.end()
+  }
+}
diff --git a/okio/src/nativeTest/kotlin/okio/NativeSystemFileSystemTest.kt b/okio/src/nativeTest/kotlin/okio/NativeSystemFileSystemTest.kt
index e4db5eff..68bd596b 100644
--- a/okio/src/nativeTest/kotlin/okio/NativeSystemFileSystemTest.kt
+++ b/okio/src/nativeTest/kotlin/okio/NativeSystemFileSystemTest.kt
@@ -24,4 +24,5 @@ class NativeSystemFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = Path.DIRECTORY_SEPARATOR == "\\",
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = FileSystem.SYSTEM_TEMPORARY_DIRECTORY,
+  closeBehavior = CloseBehavior.DoesNothing,
 )
diff --git a/okio/src/nonJvmMain/kotlin/okio/Buffer.kt b/okio/src/nonJvmMain/kotlin/okio/Buffer.kt
index 8dfb5622..4a3f6d4d 100644
--- a/okio/src/nonJvmMain/kotlin/okio/Buffer.kt
+++ b/okio/src/nonJvmMain/kotlin/okio/Buffer.kt
@@ -80,15 +80,15 @@ actual class Buffer : BufferedSource, BufferedSink {
 
   actual override fun emit(): Buffer = this // Nowhere to emit to!
 
-  override fun exhausted(): Boolean = size == 0L
+  actual override fun exhausted(): Boolean = size == 0L
 
-  override fun require(byteCount: Long) {
+  actual override fun require(byteCount: Long) {
     if (size < byteCount) throw EOFException(null)
   }
 
-  override fun request(byteCount: Long): Boolean = size >= byteCount
+  actual override fun request(byteCount: Long): Boolean = size >= byteCount
 
-  override fun peek(): BufferedSource = PeekSource(this).buffer()
+  actual override fun peek(): BufferedSource = PeekSource(this).buffer()
 
   actual fun copyTo(
     out: Buffer,
@@ -105,55 +105,57 @@ actual class Buffer : BufferedSource, BufferedSink {
 
   actual fun completeSegmentByteCount(): Long = commonCompleteSegmentByteCount()
 
-  override fun readByte(): Byte = commonReadByte()
+  actual override fun readByte(): Byte = commonReadByte()
 
-  override fun readShort(): Short = commonReadShort()
+  actual override fun readShort(): Short = commonReadShort()
 
-  override fun readInt(): Int = commonReadInt()
+  actual override fun readInt(): Int = commonReadInt()
 
-  override fun readLong(): Long = commonReadLong()
+  actual override fun readLong(): Long = commonReadLong()
 
-  override fun readShortLe(): Short = readShort().reverseBytes()
+  actual override fun readShortLe(): Short = readShort().reverseBytes()
 
-  override fun readIntLe(): Int = readInt().reverseBytes()
+  actual override fun readIntLe(): Int = readInt().reverseBytes()
 
-  override fun readLongLe(): Long = readLong().reverseBytes()
+  actual override fun readLongLe(): Long = readLong().reverseBytes()
 
-  override fun readDecimalLong(): Long = commonReadDecimalLong()
+  actual override fun readDecimalLong(): Long = commonReadDecimalLong()
 
-  override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
+  actual override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
 
-  override fun readByteString(): ByteString = commonReadByteString()
+  actual override fun readByteString(): ByteString = commonReadByteString()
 
-  override fun readByteString(byteCount: Long): ByteString = commonReadByteString(byteCount)
+  actual override fun readByteString(byteCount: Long): ByteString = commonReadByteString(byteCount)
 
-  override fun readFully(sink: Buffer, byteCount: Long): Unit = commonReadFully(sink, byteCount)
+  actual override fun readFully(sink: Buffer, byteCount: Long): Unit = commonReadFully(sink, byteCount)
 
-  override fun readAll(sink: Sink): Long = commonReadAll(sink)
+  actual override fun readAll(sink: Sink): Long = commonReadAll(sink)
 
-  override fun readUtf8(): String = readUtf8(size)
+  actual override fun readUtf8(): String = readUtf8(size)
 
-  override fun readUtf8(byteCount: Long): String = commonReadUtf8(byteCount)
+  actual override fun readUtf8(byteCount: Long): String = commonReadUtf8(byteCount)
 
-  override fun readUtf8Line(): String? = commonReadUtf8Line()
+  actual override fun readUtf8Line(): String? = commonReadUtf8Line()
 
-  override fun readUtf8LineStrict(): String = readUtf8LineStrict(Long.MAX_VALUE)
+  actual override fun readUtf8LineStrict(): String = readUtf8LineStrict(Long.MAX_VALUE)
 
-  override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
+  actual override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
 
-  override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
+  actual override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
 
-  override fun select(options: Options): Int = commonSelect(options)
+  actual override fun select(options: Options): Int = commonSelect(options)
 
-  override fun readByteArray(): ByteArray = commonReadByteArray()
+  actual override fun <T : Any> select(options: TypedOptions<T>): T? = commonSelect(options)
 
-  override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
+  actual override fun readByteArray(): ByteArray = commonReadByteArray()
 
-  override fun read(sink: ByteArray): Int = commonRead(sink)
+  actual override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
 
-  override fun readFully(sink: ByteArray): Unit = commonReadFully(sink)
+  actual override fun read(sink: ByteArray): Int = commonRead(sink)
 
-  override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
+  actual override fun readFully(sink: ByteArray): Unit = commonReadFully(sink)
+
+  actual override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
     commonRead(sink, offset, byteCount)
 
   actual fun clear(): Unit = commonClear()
@@ -181,7 +183,7 @@ actual class Buffer : BufferedSource, BufferedSink {
   actual override fun write(source: ByteArray, offset: Int, byteCount: Int): Buffer =
     commonWrite(source, offset, byteCount)
 
-  override fun writeAll(source: Source): Long = commonWriteAll(source)
+  actual override fun writeAll(source: Source): Long = commonWriteAll(source)
 
   actual override fun write(source: Source, byteCount: Long): Buffer =
     commonWrite(source, byteCount)
@@ -205,41 +207,41 @@ actual class Buffer : BufferedSource, BufferedSink {
   actual override fun writeHexadecimalUnsignedLong(v: Long): Buffer =
     commonWriteHexadecimalUnsignedLong(v)
 
-  override fun write(source: Buffer, byteCount: Long): Unit = commonWrite(source, byteCount)
+  actual override fun write(source: Buffer, byteCount: Long): Unit = commonWrite(source, byteCount)
 
-  override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
+  actual override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
 
-  override fun indexOf(b: Byte): Long = indexOf(b, 0, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte): Long = indexOf(b, 0, Long.MAX_VALUE)
 
-  override fun indexOf(b: Byte, fromIndex: Long): Long = indexOf(b, fromIndex, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte, fromIndex: Long): Long = indexOf(b, fromIndex, Long.MAX_VALUE)
 
-  override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
+  actual override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
     commonIndexOf(b, fromIndex, toIndex)
 
-  override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0)
+  actual override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0)
 
-  override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
+  actual override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
 
-  override fun indexOfElement(targetBytes: ByteString): Long = indexOfElement(targetBytes, 0L)
+  actual override fun indexOfElement(targetBytes: ByteString): Long = indexOfElement(targetBytes, 0L)
 
-  override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
+  actual override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
     commonIndexOfElement(targetBytes, fromIndex)
 
-  override fun rangeEquals(offset: Long, bytes: ByteString): Boolean =
+  actual override fun rangeEquals(offset: Long, bytes: ByteString): Boolean =
     rangeEquals(offset, bytes, 0, bytes.size)
 
-  override fun rangeEquals(
+  actual override fun rangeEquals(
     offset: Long,
     bytes: ByteString,
     bytesOffset: Int,
     byteCount: Int,
   ): Boolean = commonRangeEquals(offset, bytes, bytesOffset, byteCount)
 
-  override fun flush() = Unit
+  actual override fun flush() = Unit
 
-  override fun close() = Unit
+  actual override fun close() = Unit
 
-  override fun timeout(): Timeout = Timeout.NONE
+  actual override fun timeout(): Timeout = Timeout.NONE
 
   override fun equals(other: Any?): Boolean = commonEquals(other)
 
diff --git a/okio/src/nonJvmMain/kotlin/okio/BufferedSource.kt b/okio/src/nonJvmMain/kotlin/okio/BufferedSource.kt
index 369a3e63..44622233 100644
--- a/okio/src/nonJvmMain/kotlin/okio/BufferedSource.kt
+++ b/okio/src/nonJvmMain/kotlin/okio/BufferedSource.kt
@@ -50,6 +50,8 @@ actual sealed interface BufferedSource : Source {
 
   actual fun select(options: Options): Int
 
+  actual fun <T : Any> select(options: TypedOptions<T>): T?
+
   actual fun readByteArray(): ByteArray
 
   actual fun readByteArray(byteCount: Long): ByteArray
diff --git a/okio/src/nonJvmMain/kotlin/okio/HashingSink.kt b/okio/src/nonJvmMain/kotlin/okio/HashingSink.kt
index fd86acf9..15e4b9ae 100644
--- a/okio/src/nonJvmMain/kotlin/okio/HashingSink.kt
+++ b/okio/src/nonJvmMain/kotlin/okio/HashingSink.kt
@@ -27,7 +27,7 @@ actual class HashingSink internal constructor(
   private val hashFunction: HashFunction,
 ) : Sink {
 
-  override fun write(source: Buffer, byteCount: Long) {
+  actual override fun write(source: Buffer, byteCount: Long) {
     checkOffsetAndCount(source.size, 0, byteCount)
 
     // Hash byteCount bytes from the prefix of source.
@@ -44,11 +44,11 @@ actual class HashingSink internal constructor(
     sink.write(source, byteCount)
   }
 
-  override fun flush() = sink.flush()
+  actual override fun flush() = sink.flush()
 
-  override fun timeout(): Timeout = sink.timeout()
+  actual override fun timeout(): Timeout = sink.timeout()
 
-  override fun close() = sink.close()
+  actual override fun close() = sink.close()
 
   /**
    * Returns the hash of the bytes accepted thus far and resets the internal state of this sink.
diff --git a/okio/src/nonJvmMain/kotlin/okio/HashingSource.kt b/okio/src/nonJvmMain/kotlin/okio/HashingSource.kt
index 40e4a628..dae96c6b 100644
--- a/okio/src/nonJvmMain/kotlin/okio/HashingSource.kt
+++ b/okio/src/nonJvmMain/kotlin/okio/HashingSource.kt
@@ -27,7 +27,7 @@ actual class HashingSource internal constructor(
   private val hashFunction: HashFunction,
 ) : Source {
 
-  override fun read(sink: Buffer, byteCount: Long): Long {
+  actual override fun read(sink: Buffer, byteCount: Long): Long {
     val result = source.read(sink, byteCount)
 
     if (result != -1L) {
@@ -54,10 +54,10 @@ actual class HashingSource internal constructor(
     return result
   }
 
-  override fun timeout(): Timeout =
+  actual override fun timeout(): Timeout =
     source.timeout()
 
-  override fun close() =
+  actual override fun close() =
     source.close()
 
   actual val hash: ByteString
diff --git a/okio/src/nonJvmMain/kotlin/okio/RealBufferedSink.kt b/okio/src/nonJvmMain/kotlin/okio/RealBufferedSink.kt
index 8b09c7f4..f41cd6eb 100644
--- a/okio/src/nonJvmMain/kotlin/okio/RealBufferedSink.kt
+++ b/okio/src/nonJvmMain/kotlin/okio/RealBufferedSink.kt
@@ -40,36 +40,36 @@ internal actual class RealBufferedSink actual constructor(
   actual val sink: Sink,
 ) : BufferedSink {
   actual var closed: Boolean = false
-  override val buffer = Buffer()
+  actual override val buffer = Buffer()
 
-  override fun write(source: Buffer, byteCount: Long) = commonWrite(source, byteCount)
-  override fun write(byteString: ByteString) = commonWrite(byteString)
-  override fun write(byteString: ByteString, offset: Int, byteCount: Int) =
+  actual override fun write(source: Buffer, byteCount: Long) = commonWrite(source, byteCount)
+  actual override fun write(byteString: ByteString) = commonWrite(byteString)
+  actual override fun write(byteString: ByteString, offset: Int, byteCount: Int) =
     commonWrite(byteString, offset, byteCount)
-  override fun writeUtf8(string: String) = commonWriteUtf8(string)
-  override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int) =
+  actual override fun writeUtf8(string: String) = commonWriteUtf8(string)
+  actual override fun writeUtf8(string: String, beginIndex: Int, endIndex: Int) =
     commonWriteUtf8(string, beginIndex, endIndex)
 
-  override fun writeUtf8CodePoint(codePoint: Int) = commonWriteUtf8CodePoint(codePoint)
-  override fun write(source: ByteArray) = commonWrite(source)
-  override fun write(source: ByteArray, offset: Int, byteCount: Int) =
+  actual override fun writeUtf8CodePoint(codePoint: Int) = commonWriteUtf8CodePoint(codePoint)
+  actual override fun write(source: ByteArray) = commonWrite(source)
+  actual override fun write(source: ByteArray, offset: Int, byteCount: Int) =
     commonWrite(source, offset, byteCount)
 
-  override fun writeAll(source: Source) = commonWriteAll(source)
-  override fun write(source: Source, byteCount: Long): BufferedSink = commonWrite(source, byteCount)
-  override fun writeByte(b: Int) = commonWriteByte(b)
-  override fun writeShort(s: Int) = commonWriteShort(s)
-  override fun writeShortLe(s: Int) = commonWriteShortLe(s)
-  override fun writeInt(i: Int) = commonWriteInt(i)
-  override fun writeIntLe(i: Int) = commonWriteIntLe(i)
-  override fun writeLong(v: Long) = commonWriteLong(v)
-  override fun writeLongLe(v: Long) = commonWriteLongLe(v)
-  override fun writeDecimalLong(v: Long) = commonWriteDecimalLong(v)
-  override fun writeHexadecimalUnsignedLong(v: Long) = commonWriteHexadecimalUnsignedLong(v)
-  override fun emitCompleteSegments() = commonEmitCompleteSegments()
-  override fun emit() = commonEmit()
-  override fun flush() = commonFlush()
-  override fun close() = commonClose()
-  override fun timeout() = commonTimeout()
+  actual override fun writeAll(source: Source) = commonWriteAll(source)
+  actual override fun write(source: Source, byteCount: Long): BufferedSink = commonWrite(source, byteCount)
+  actual override fun writeByte(b: Int) = commonWriteByte(b)
+  actual override fun writeShort(s: Int) = commonWriteShort(s)
+  actual override fun writeShortLe(s: Int) = commonWriteShortLe(s)
+  actual override fun writeInt(i: Int) = commonWriteInt(i)
+  actual override fun writeIntLe(i: Int) = commonWriteIntLe(i)
+  actual override fun writeLong(v: Long) = commonWriteLong(v)
+  actual override fun writeLongLe(v: Long) = commonWriteLongLe(v)
+  actual override fun writeDecimalLong(v: Long) = commonWriteDecimalLong(v)
+  actual override fun writeHexadecimalUnsignedLong(v: Long) = commonWriteHexadecimalUnsignedLong(v)
+  actual override fun emitCompleteSegments() = commonEmitCompleteSegments()
+  actual override fun emit() = commonEmit()
+  actual override fun flush() = commonFlush()
+  actual override fun close() = commonClose()
+  actual override fun timeout() = commonTimeout()
   override fun toString() = commonToString()
 }
diff --git a/okio/src/nonJvmMain/kotlin/okio/RealBufferedSource.kt b/okio/src/nonJvmMain/kotlin/okio/RealBufferedSource.kt
index 93ad10f0..5bb7ced7 100644
--- a/okio/src/nonJvmMain/kotlin/okio/RealBufferedSource.kt
+++ b/okio/src/nonJvmMain/kotlin/okio/RealBufferedSource.kt
@@ -50,67 +50,71 @@ internal actual class RealBufferedSource actual constructor(
   actual val source: Source,
 ) : BufferedSource {
   actual var closed: Boolean = false
-  override val buffer: Buffer = Buffer()
+  actual override val buffer: Buffer = Buffer()
 
-  override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
-  override fun exhausted(): Boolean = commonExhausted()
-  override fun require(byteCount: Long): Unit = commonRequire(byteCount)
-  override fun request(byteCount: Long): Boolean = commonRequest(byteCount)
-  override fun readByte(): Byte = commonReadByte()
-  override fun readByteString(): ByteString = commonReadByteString()
-  override fun readByteString(byteCount: Long): ByteString = commonReadByteString(byteCount)
-  override fun select(options: Options): Int = commonSelect(options)
-  override fun readByteArray(): ByteArray = commonReadByteArray()
-  override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
-  override fun read(sink: ByteArray): Int = read(sink, 0, sink.size)
-  override fun readFully(sink: ByteArray): Unit = commonReadFully(sink)
-  override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
+  actual override fun read(sink: Buffer, byteCount: Long): Long = commonRead(sink, byteCount)
+  actual override fun exhausted(): Boolean = commonExhausted()
+  actual override fun require(byteCount: Long): Unit = commonRequire(byteCount)
+  actual override fun request(byteCount: Long): Boolean = commonRequest(byteCount)
+  actual override fun readByte(): Byte = commonReadByte()
+  actual override fun readByteString(): ByteString = commonReadByteString()
+  actual override fun readByteString(byteCount: Long): ByteString = commonReadByteString(byteCount)
+  actual override fun select(options: Options): Int = commonSelect(options)
+  actual override fun <T : Any> select(options: TypedOptions<T>): T? = commonSelect(options)
+  actual override fun readByteArray(): ByteArray = commonReadByteArray()
+  actual override fun readByteArray(byteCount: Long): ByteArray = commonReadByteArray(byteCount)
+  actual override fun read(sink: ByteArray): Int = read(sink, 0, sink.size)
+  actual override fun readFully(sink: ByteArray): Unit = commonReadFully(sink)
+  actual override fun read(sink: ByteArray, offset: Int, byteCount: Int): Int =
     commonRead(sink, offset, byteCount)
 
-  override fun readFully(sink: Buffer, byteCount: Long): Unit = commonReadFully(sink, byteCount)
-  override fun readAll(sink: Sink): Long = commonReadAll(sink)
-  override fun readUtf8(): String = commonReadUtf8()
-  override fun readUtf8(byteCount: Long): String = commonReadUtf8(byteCount)
-  override fun readUtf8Line(): String? = commonReadUtf8Line()
-  override fun readUtf8LineStrict() = readUtf8LineStrict(Long.MAX_VALUE)
-  override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
-  override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
-  override fun readShort(): Short = commonReadShort()
-  override fun readShortLe(): Short = commonReadShortLe()
-  override fun readInt(): Int = commonReadInt()
-  override fun readIntLe(): Int = commonReadIntLe()
-  override fun readLong(): Long = commonReadLong()
-  override fun readLongLe(): Long = commonReadLongLe()
-  override fun readDecimalLong(): Long = commonReadDecimalLong()
-  override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
-  override fun skip(byteCount: Long): Unit = commonSkip(byteCount)
-  override fun indexOf(b: Byte): Long = indexOf(b, 0L, Long.MAX_VALUE)
-  override fun indexOf(b: Byte, fromIndex: Long): Long = indexOf(b, fromIndex, Long.MAX_VALUE)
-  override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
+  actual override fun readFully(sink: Buffer, byteCount: Long): Unit =
+    commonReadFully(sink, byteCount)
+  actual override fun readAll(sink: Sink): Long = commonReadAll(sink)
+  actual override fun readUtf8(): String = commonReadUtf8()
+  actual override fun readUtf8(byteCount: Long): String = commonReadUtf8(byteCount)
+  actual override fun readUtf8Line(): String? = commonReadUtf8Line()
+  actual override fun readUtf8LineStrict() = readUtf8LineStrict(Long.MAX_VALUE)
+  actual override fun readUtf8LineStrict(limit: Long): String = commonReadUtf8LineStrict(limit)
+  actual override fun readUtf8CodePoint(): Int = commonReadUtf8CodePoint()
+  actual override fun readShort(): Short = commonReadShort()
+  actual override fun readShortLe(): Short = commonReadShortLe()
+  actual override fun readInt(): Int = commonReadInt()
+  actual override fun readIntLe(): Int = commonReadIntLe()
+  actual override fun readLong(): Long = commonReadLong()
+  actual override fun readLongLe(): Long = commonReadLongLe()
+  actual override fun readDecimalLong(): Long = commonReadDecimalLong()
+  actual override fun readHexadecimalUnsignedLong(): Long = commonReadHexadecimalUnsignedLong()
+  actual override fun skip(byteCount: Long): Unit = commonSkip(byteCount)
+  actual override fun indexOf(b: Byte): Long = indexOf(b, 0L, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte, fromIndex: Long): Long =
+    indexOf(b, fromIndex, Long.MAX_VALUE)
+  actual override fun indexOf(b: Byte, fromIndex: Long, toIndex: Long): Long =
     commonIndexOf(b, fromIndex, toIndex)
 
-  override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0L)
-  override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
-  override fun indexOfElement(targetBytes: ByteString): Long = indexOfElement(targetBytes, 0L)
-  override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
+  actual override fun indexOf(bytes: ByteString): Long = indexOf(bytes, 0L)
+  actual override fun indexOf(bytes: ByteString, fromIndex: Long): Long = commonIndexOf(bytes, fromIndex)
+  actual override fun indexOfElement(targetBytes: ByteString): Long =
+    indexOfElement(targetBytes, 0L)
+  actual override fun indexOfElement(targetBytes: ByteString, fromIndex: Long): Long =
     commonIndexOfElement(targetBytes, fromIndex)
 
-  override fun rangeEquals(offset: Long, bytes: ByteString) = rangeEquals(
+  actual override fun rangeEquals(offset: Long, bytes: ByteString) = rangeEquals(
     offset,
     bytes,
     0,
     bytes.size,
   )
 
-  override fun rangeEquals(
+  actual override fun rangeEquals(
     offset: Long,
     bytes: ByteString,
     bytesOffset: Int,
     byteCount: Int,
   ): Boolean = commonRangeEquals(offset, bytes, bytesOffset, byteCount)
 
-  override fun peek(): BufferedSource = commonPeek()
-  override fun close(): Unit = commonClose()
-  override fun timeout(): Timeout = commonTimeout()
+  actual override fun peek(): BufferedSource = commonPeek()
+  actual override fun close(): Unit = commonClose()
+  actual override fun timeout(): Timeout = commonTimeout()
   override fun toString(): String = commonToString()
 }
diff --git a/okio/src/nonJvmTest/kotlin/okio/NonJvmTesting.kt b/okio/src/nonJvmTest/kotlin/okio/NonJvmTesting.kt
index a5e9a780..0483999b 100644
--- a/okio/src/nonJvmTest/kotlin/okio/NonJvmTesting.kt
+++ b/okio/src/nonJvmTest/kotlin/okio/NonJvmTesting.kt
@@ -36,3 +36,7 @@ actual fun assertRelativeToFails(
 ): IllegalArgumentException {
   return assertFailsWith { b.relativeTo(a) }
 }
+
+actual fun <T> withUtc(block: () -> T): T {
+  return block()
+}
diff --git a/okio/src/nonWasmTest/kotlin/okio/FakeFileSystemTest.kt b/okio/src/nonWasmTest/kotlin/okio/FakeFileSystemTest.kt
index 07dfad8d..6a86b0a4 100644
--- a/okio/src/nonWasmTest/kotlin/okio/FakeFileSystemTest.kt
+++ b/okio/src/nonWasmTest/kotlin/okio/FakeFileSystemTest.kt
@@ -51,6 +51,7 @@ abstract class FakeFileSystemTest internal constructor(
   allowClobberingEmptyDirectories = fakeFileSystem.allowClobberingEmptyDirectories,
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = temporaryDirectory,
+  closeBehavior = CloseBehavior.Closes,
 ) {
   private val fakeClock: FakeClock = fakeFileSystem.clock as FakeClock
 
diff --git a/okio/src/nonWasmTest/kotlin/okio/ForwardingFileSystemTest.kt b/okio/src/nonWasmTest/kotlin/okio/ForwardingFileSystemTest.kt
index 6b7e089b..6b2fb526 100644
--- a/okio/src/nonWasmTest/kotlin/okio/ForwardingFileSystemTest.kt
+++ b/okio/src/nonWasmTest/kotlin/okio/ForwardingFileSystemTest.kt
@@ -30,6 +30,7 @@ class ForwardingFileSystemTest : AbstractFileSystemTest(
   allowClobberingEmptyDirectories = false,
   allowAtomicMoveFromFileToDirectory = false,
   temporaryDirectory = "/".toPath(),
+  closeBehavior = CloseBehavior.Closes,
 ) {
   @Test
   fun pathBlocking() {
@@ -169,4 +170,19 @@ class ForwardingFileSystemTest : AbstractFileSystemTest(
 
     assertEquals(listOf("metadataOrNull(path=$source)", "metadataOrNull($target)"), log)
   }
+
+  /** Closing the ForwardingFileSystem closes the delegate. */
+  @Test
+  fun closeForwards() {
+    val delegate = FakeFileSystem()
+
+    val forwardingFileSystem = object : ForwardingFileSystem(delegate) {
+    }
+
+    forwardingFileSystem.close()
+
+    assertFailsWith<IllegalStateException> {
+      delegate.list(base)
+    }
+  }
 }
diff --git a/okio/src/nonWasmTest/kotlin/okio/UseTest.kt b/okio/src/nonWasmTest/kotlin/okio/UseTest.kt
index a36cf068..3cf713b3 100644
--- a/okio/src/nonWasmTest/kotlin/okio/UseTest.kt
+++ b/okio/src/nonWasmTest/kotlin/okio/UseTest.kt
@@ -1,6 +1,7 @@
 package okio
 
 import kotlin.test.Test
+import kotlin.test.assertNull
 import okio.Path.Companion.toPath
 import okio.fakefilesystem.FakeFileSystem
 
@@ -25,4 +26,13 @@ class UseTest {
 
     fakeFileSystem.checkNoOpenFiles()
   }
+
+  @Test
+  fun acceptsNullReturn() {
+    val result = object : Closeable {
+      override fun close() {}
+    }.use { null }
+
+    assertNull(result)
+  }
 }
diff --git a/okio/src/systemFileSystemMain/kotlin/okio/FileSystem.System.kt b/okio/src/systemFileSystemMain/kotlin/okio/FileSystem.System.kt
new file mode 100644
index 00000000..0bc7e4da
--- /dev/null
+++ b/okio/src/systemFileSystemMain/kotlin/okio/FileSystem.System.kt
@@ -0,0 +1,7 @@
+package okio
+
+/*
+ * The current process's host file system. Use this instance directly, or dependency inject a
+ * [FileSystem] to make code testable.
+ */
+expect val FileSystem.Companion.SYSTEM: FileSystem
diff --git a/okio/src/wasmMain/kotlin/okio/FileSystem.kt b/okio/src/wasmMain/kotlin/okio/FileSystem.kt
index 2152a91b..190bba8b 100644
--- a/okio/src/wasmMain/kotlin/okio/FileSystem.kt
+++ b/okio/src/wasmMain/kotlin/okio/FileSystem.kt
@@ -23,7 +23,7 @@ import okio.internal.commonExists
 import okio.internal.commonListRecursively
 import okio.internal.commonMetadata
 
-actual abstract class FileSystem {
+actual abstract class FileSystem : Closeable {
   actual abstract fun canonicalize(path: Path): Path
 
   actual fun metadata(path: Path): FileMetadata = commonMetadata(path)
@@ -84,6 +84,9 @@ actual abstract class FileSystem {
 
   actual abstract fun createSymlink(source: Path, target: Path)
 
+  actual override fun close() {
+  }
+
   actual companion object {
     actual val SYSTEM_TEMPORARY_DIRECTORY: Path = "/tmp".toPath()
   }
diff --git a/okio/src/zlibMain/kotlin/okio/Deflater.kt b/okio/src/zlibMain/kotlin/okio/Deflater.kt
new file mode 100644
index 00000000..e561f041
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/Deflater.kt
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+/**
+ * @param nowrap true to skip the ZLIB header and checksum.
+ */
+expect class Deflater(
+  level: Int,
+  nowrap: Boolean,
+) {
+  /** Creates a deflater that expects to read a ZLIB header and checksum. */
+  constructor()
+
+  fun getBytesRead(): Long
+
+  fun end()
+}
diff --git a/okio/src/zlibMain/kotlin/okio/DeflaterSink.kt b/okio/src/zlibMain/kotlin/okio/DeflaterSink.kt
new file mode 100644
index 00000000..b81e7dd0
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/DeflaterSink.kt
@@ -0,0 +1,63 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+@file:JvmName("-DeflaterSinkExtensions")
+
+package okio
+
+import kotlin.jvm.JvmName
+
+/**
+ * A sink that uses [DEFLATE](http://tools.ietf.org/html/rfc1951) to
+ * compress data written to another source.
+ *
+ * ### Sync flush
+ *
+ * Aggressive flushing of this stream may result in reduced compression. Each
+ * call to [flush] immediately compresses all currently-buffered data;
+ * this early compression may be less effective than compression performed
+ * without flushing.
+ *
+ * This is equivalent to using [Deflater] with the sync flush option.
+ * This class does not offer any partial flush mechanism. For best performance,
+ * only call [flush] when application behavior requires it.
+ */
+expect class DeflaterSink
+/**
+ * This internal constructor shares a buffer with its trusted caller. In general, we can't share a
+ * BufferedSource because the deflater holds input bytes until they are inflated.
+ */
+internal constructor(
+  sink: BufferedSink,
+  deflater: Deflater,
+) : Sink {
+  constructor(sink: Sink, deflater: Deflater)
+
+  internal fun finishDeflate()
+
+  override fun write(source: Buffer, byteCount: Long)
+  override fun flush()
+  override fun timeout(): Timeout
+  override fun close()
+}
+
+/**
+ * Returns an [DeflaterSink] that DEFLATE-compresses data to this [Sink] while writing.
+ *
+ * @see DeflaterSink
+ */
+inline fun Sink.deflate(deflater: Deflater = Deflater()): DeflaterSink =
+  DeflaterSink(this, deflater)
diff --git a/okio/src/jvmMain/kotlin/okio/GzipSink.kt b/okio/src/zlibMain/kotlin/okio/GzipSink.kt
similarity index 93%
rename from okio/src/jvmMain/kotlin/okio/GzipSink.kt
rename to okio/src/zlibMain/kotlin/okio/GzipSink.kt
index 1b5cbc63..fa3cf162 100644
--- a/okio/src/jvmMain/kotlin/okio/GzipSink.kt
+++ b/okio/src/zlibMain/kotlin/okio/GzipSink.kt
@@ -19,10 +19,9 @@
 
 package okio
 
-import java.io.IOException
-import java.util.zip.CRC32
-import java.util.zip.Deflater
-import java.util.zip.Deflater.DEFAULT_COMPRESSION
+import kotlin.jvm.JvmName
+import okio.internal.CRC32
+import okio.internal.DEFAULT_COMPRESSION
 
 /**
  * A sink that uses [GZIP](http://www.ietf.org/rfc/rfc1952.txt) to
@@ -119,8 +118,8 @@ class GzipSink(sink: Sink) : Sink {
   }
 
   private fun writeFooter() {
-    sink.writeIntLe(crc.value.toInt()) // CRC of original data.
-    sink.writeIntLe(deflater.bytesRead.toInt()) // Length of original data.
+    sink.writeIntLe(crc.getValue().toInt()) // CRC of original data.
+    sink.writeIntLe(deflater.getBytesRead().toInt()) // Length of original data.
   }
 
   /** Updates the CRC with the given bytes. */
diff --git a/okio/src/jvmMain/kotlin/okio/GzipSource.kt b/okio/src/zlibMain/kotlin/okio/GzipSource.kt
similarity index 93%
rename from okio/src/jvmMain/kotlin/okio/GzipSource.kt
rename to okio/src/zlibMain/kotlin/okio/GzipSource.kt
index 1cc4172a..27b65d40 100644
--- a/okio/src/jvmMain/kotlin/okio/GzipSource.kt
+++ b/okio/src/zlibMain/kotlin/okio/GzipSource.kt
@@ -19,10 +19,8 @@
 
 package okio
 
-import java.io.EOFException
-import java.io.IOException
-import java.util.zip.CRC32
-import java.util.zip.Inflater
+import kotlin.jvm.JvmName
+import okio.internal.CRC32
 
 /**
  * A source that uses [GZIP](http://www.ietf.org/rfc/rfc1952.txt) to
@@ -150,7 +148,7 @@ class GzipSource(source: Source) : Source {
     // | CRC16 |
     // +---+---+
     if (fhcrc) {
-      checkEqual("FHCRC", source.readShortLe().toInt(), crc.value.toShort().toInt())
+      checkEqual("FHCRC", source.readShortLe().toInt(), crc.getValue().toShort().toInt())
       crc.reset()
     }
   }
@@ -161,8 +159,8 @@ class GzipSource(source: Source) : Source {
     // +---+---+---+---+---+---+---+---+
     // |     CRC32     |     ISIZE     |
     // +---+---+---+---+---+---+---+---+
-    checkEqual("CRC", source.readIntLe(), crc.value.toInt())
-    checkEqual("ISIZE", source.readIntLe(), inflater.bytesWritten.toInt())
+    checkEqual("CRC", source.readIntLe(), crc.getValue().toInt())
+    checkEqual("ISIZE", source.readIntLe(), inflater.getBytesWritten().toInt())
   }
 
   override fun timeout(): Timeout = source.timeout()
@@ -194,7 +192,11 @@ class GzipSource(source: Source) : Source {
 
   private fun checkEqual(name: String, expected: Int, actual: Int) {
     if (actual != expected) {
-      throw IOException("%s: actual 0x%08x != expected 0x%08x".format(name, actual, expected))
+      throw IOException(
+        "$name: " +
+          "actual 0x${actual.toHexString().padStart(8, '0')} != " +
+          "expected 0x${expected.toHexString().padStart(8, '0')}",
+      )
     }
   }
 }
diff --git a/okio/src/zlibMain/kotlin/okio/Inflater.kt b/okio/src/zlibMain/kotlin/okio/Inflater.kt
new file mode 100644
index 00000000..600804a7
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/Inflater.kt
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio
+
+/**
+ * @param nowrap true to omit the ZLIB header and checksum.
+ */
+expect class Inflater(
+  nowrap: Boolean,
+) {
+  /** Creates an inflater that writes a ZLIB header and checksum. */
+  constructor()
+
+  fun getBytesWritten(): Long
+
+  fun end()
+}
diff --git a/okio/src/zlibMain/kotlin/okio/InflaterSource.kt b/okio/src/zlibMain/kotlin/okio/InflaterSource.kt
new file mode 100644
index 00000000..01bfc8ef
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/InflaterSource.kt
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+@file:JvmName("-InflaterSourceExtensions")
+
+package okio
+
+import kotlin.jvm.JvmName
+
+/**
+ * A source that uses [DEFLATE](http://tools.ietf.org/html/rfc1951) to decompress data read from
+ * another source.
+ */
+expect class InflaterSource
+/**
+ * This internal constructor shares a buffer with its trusted caller. In general, we can't share a
+ * `BufferedSource` because the inflater holds input bytes until they are inflated.
+ */
+internal constructor(
+  source: BufferedSource,
+  inflater: Inflater,
+) : Source {
+  constructor(source: Source, inflater: Inflater)
+
+  override fun read(sink: Buffer, byteCount: Long): Long
+  override fun timeout(): Timeout
+  override fun close()
+}
+
+/**
+ * Returns an [InflaterSource] that DEFLATE-decompresses this [Source] while reading.
+ *
+ * @see InflaterSource
+ */
+inline fun Source.inflate(inflater: Inflater = Inflater()): InflaterSource =
+  InflaterSource(this, inflater)
diff --git a/okio/src/jvmMain/kotlin/okio/ZipFileSystem.kt b/okio/src/zlibMain/kotlin/okio/ZipFileSystem.kt
similarity index 62%
rename from okio/src/jvmMain/kotlin/okio/ZipFileSystem.kt
rename to okio/src/zlibMain/kotlin/okio/ZipFileSystem.kt
index 2c8d9ea5..88972fb2 100644
--- a/okio/src/jvmMain/kotlin/okio/ZipFileSystem.kt
+++ b/okio/src/zlibMain/kotlin/okio/ZipFileSystem.kt
@@ -16,8 +16,6 @@
  */
 package okio
 
-import java.io.FileNotFoundException
-import java.util.zip.Inflater
 import okio.Path.Companion.toPath
 import okio.internal.COMPRESSION_METHOD_STORED
 import okio.internal.FixedLengthSource
@@ -26,41 +24,8 @@ import okio.internal.readLocalHeader
 import okio.internal.skipLocalHeader
 
 /**
- * Read only access to a [zip file][zip_format] and common [extra fields][extra_fields].
- *
- * Zip Timestamps
- * --------------
- *
- * The base zip format tracks the [last modified timestamp][FileMetadata.lastModifiedAtMillis]. It
- * does not track [created timestamps][FileMetadata.createdAtMillis] or [last accessed
- * timestamps][FileMetadata.lastAccessedAtMillis]. This format has limitations:
- *
- *  * Timestamps are 16-bit values stored with 2-second precision. Some zip encoders (WinZip, PKZIP)
- *    round up to the nearest 2 seconds; other encoders (Java) round down.
- *
- *  * Timestamps before 1980-01-01 cannot be represented. They cannot represent dates after
- *    2107-12-31.
- *
- *  * Timestamps are stored in local time with no time zone offset. If the time zone offset changes
- *    – due to daylight savings time or the zip file being sent to another time zone – file times
- *    will be incorrect. The file time will be shifted by the difference in time zone offsets
- *    between the encoder and decoder.
- *
- * The zip format has optional extensions for timestamps.
- *
- *  * UNIX timestamps (0x000d) support both last-access time and last modification time. These
- *    timestamps are stored with 1-second precision using UTC.
- *
- *  * NTFS timestamps (0x000a) support creation time, last access time, and last modified time.
- *    These timestamps are stored with 100-millisecond precision using UTC.
- *
- *  * Extended timestamps (0x5455) are stored as signed 32-bit timestamps with 1-second precision.
- *    These cannot express dates beyond 2038-01-19.
- *
- * This class currently supports base timestamps and extended timestamps.
- *
- * [zip_format]: https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE_6.2.0.txt
- * [extra_fields]: https://opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld
+ * Read only access to a [zip file](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE_6.2.0.txt)
+ * and common [extra fields](https://opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld).
  */
 internal class ZipFileSystem internal constructor(
   private val zipPath: Path,
@@ -83,27 +48,29 @@ internal class ZipFileSystem internal constructor(
 
   override fun metadataOrNull(path: Path): FileMetadata? {
     val canonicalPath = canonicalizeInternal(path)
-    val entry = entries[canonicalPath] ?: return null
-
-    val basicMetadata = FileMetadata(
-      isRegularFile = !entry.isDirectory,
-      isDirectory = entry.isDirectory,
-      symlinkTarget = null,
-      size = if (entry.isDirectory) null else entry.size,
-      createdAtMillis = null,
-      lastModifiedAtMillis = entry.lastModifiedAtMillis,
-      lastAccessedAtMillis = null,
-    )
+    val centralDirectoryEntry = entries[canonicalPath] ?: return null
+
+    val fullEntry = when {
+      centralDirectoryEntry.offset != -1L -> {
+        fileSystem.openReadOnly(zipPath).use { fileHandle ->
+          return@use fileHandle.source(centralDirectoryEntry.offset).buffer().use { source ->
+            source.readLocalHeader(centralDirectoryEntry)
+          }
+        }
+      }
 
-    if (entry.offset == -1L) {
-      return basicMetadata
+      else -> centralDirectoryEntry
     }
 
-    return fileSystem.openReadOnly(zipPath).use { fileHandle ->
-      return@use fileHandle.source(entry.offset).buffer().use { source ->
-        source.readLocalHeader(basicMetadata)
-      }
-    }
+    return FileMetadata(
+      isRegularFile = !fullEntry.isDirectory,
+      isDirectory = fullEntry.isDirectory,
+      symlinkTarget = null,
+      size = if (fullEntry.isDirectory) null else fullEntry.size,
+      createdAtMillis = fullEntry.createdAtMillis,
+      lastModifiedAtMillis = fullEntry.lastModifiedAtMillis,
+      lastAccessedAtMillis = fullEntry.lastAccessedAtMillis,
+    )
   }
 
   override fun openReadOnly(file: Path): FileHandle {
diff --git a/okio/src/zlibMain/kotlin/okio/ZlibOkio.kt b/okio/src/zlibMain/kotlin/okio/ZlibOkio.kt
new file mode 100644
index 00000000..827e001d
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/ZlibOkio.kt
@@ -0,0 +1,35 @@
+/*
+ * Copyright (C) 2014 Square, Inc.
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
+@file:JvmMultifileClass
+@file:JvmName("Okio")
+
+package okio
+
+import kotlin.jvm.JvmMultifileClass
+import kotlin.jvm.JvmName
+
+/**
+ * Returns a new read-only file system.
+ *
+ * This function processes the ZIP file's central directory and builds an index of its files and
+ * their offsets within the ZIP. If the ZIP file is changed after this function returns, this
+ * file system will be broken and may return inconsistent data or crash when it is accessed.
+ *
+ * Closing the returned file system is not necessary and does nothing.
+ */
+@Throws(IOException::class)
+fun FileSystem.openZip(zipPath: Path): FileSystem = okio.internal.openZip(zipPath, this)
diff --git a/okio/src/zlibMain/kotlin/okio/internal/-Zlib.kt b/okio/src/zlibMain/kotlin/okio/internal/-Zlib.kt
new file mode 100644
index 00000000..b31c9e15
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/internal/-Zlib.kt
@@ -0,0 +1,38 @@
+// ktlint-disable filename
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+internal expect val DEFAULT_COMPRESSION: Int
+
+/**
+ * Note that this inherits the local time zone.
+ *
+ * @param year such as 1970 or 2024
+ * @param month a value in the range 1 (January) through 12 (December).
+ * @param day a value in the range 1 through 31.
+ * @param hour a value in the range 0 through 23.
+ * @param minute a value in the range 0 through 59.
+ * @param second a value in the range 0 through 59.
+ */
+internal expect fun datePartsToEpochMillis(
+  year: Int,
+  month: Int,
+  day: Int,
+  hour: Int,
+  minute: Int,
+  second: Int,
+): Long
diff --git a/okio/src/zlibMain/kotlin/okio/internal/CRC32.kt b/okio/src/zlibMain/kotlin/okio/internal/CRC32.kt
new file mode 100644
index 00000000..a987fda1
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/internal/CRC32.kt
@@ -0,0 +1,23 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+expect class CRC32() {
+  fun update(content: ByteArray, offset: Int, byteCount: Int)
+  fun update(content: ByteArray)
+  fun getValue(): Long
+  fun reset()
+}
diff --git a/okio/src/jvmMain/kotlin/okio/internal/FixedLengthSource.kt b/okio/src/zlibMain/kotlin/okio/internal/FixedLengthSource.kt
similarity index 100%
rename from okio/src/jvmMain/kotlin/okio/internal/FixedLengthSource.kt
rename to okio/src/zlibMain/kotlin/okio/internal/FixedLengthSource.kt
diff --git a/okio/src/zlibMain/kotlin/okio/internal/ZipEntry.kt b/okio/src/zlibMain/kotlin/okio/internal/ZipEntry.kt
new file mode 100644
index 00000000..4050b918
--- /dev/null
+++ b/okio/src/zlibMain/kotlin/okio/internal/ZipEntry.kt
@@ -0,0 +1,137 @@
+/*
+ * Licensed to the Apache Software Foundation (ASF) under one or more
+ * contributor license agreements.  See the NOTICE file distributed with
+ * this work for additional information regarding copyright ownership.
+ * The ASF licenses this file to You under the Apache License, Version 2.0
+ * (the "License"); you may not use this file except in compliance with
+ * the License.  You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package okio.internal
+
+import okio.FileMetadata
+import okio.Path
+
+/**
+ * This class prefers NTFS timestamps, then extended timestamps, then the base ZIP timestamps.
+ */
+internal class ZipEntry(
+  /**
+   * Absolute path of this entry. If the raw name on disk contains relative paths like `..`, they
+   * are not present in this path.
+   */
+  val canonicalPath: Path,
+
+  /** True if this entry is a directory. When encoded directory entries' names end with `/`. */
+  val isDirectory: Boolean = false,
+
+  /** The comment on this entry. Empty if there is no comment. */
+  val comment: String = "",
+
+  /** The CRC32 of the uncompressed data, or -1 if not set. */
+  val crc: Long = -1L,
+
+  /** The compressed size in bytes, or -1 if unknown. */
+  val compressedSize: Long = -1L,
+
+  /** The uncompressed size in bytes, or -1 if unknown. */
+  val size: Long = -1L,
+
+  /** Either [COMPRESSION_METHOD_DEFLATED] or [COMPRESSION_METHOD_STORED]. */
+  val compressionMethod: Int = -1,
+
+  val offset: Long = -1L,
+
+  /**
+   * The base ZIP format tracks the [last modified timestamp][FileMetadata.lastModifiedAtMillis]. It
+   * does not track [created timestamps][FileMetadata.createdAtMillis] or [last accessed
+   * timestamps][FileMetadata.lastAccessedAtMillis].
+   *
+   * This format has severe limitations:
+   *
+   *  * Timestamps are 16-bit values stored with 2-second precision. Some zip encoders (WinZip,
+   *    PKZIP) round up to the nearest 2 seconds; other encoders (Java) round down.
+   *
+   *  * Timestamps before 1980-01-01 cannot be represented. They cannot represent dates after
+   *    2107-12-31.
+   *
+   *  * Timestamps are stored in local time with no time zone offset. If the time zone offset
+   *    changes – due to daylight savings time or the zip file being sent to another time zone –
+   *    file times will be incorrect. The file time will be shifted by the difference in time zone
+   *    offsets between the encoder and decoder.
+   */
+  val dosLastModifiedAtDate: Int = -1,
+  val dosLastModifiedAtTime: Int = -1,
+
+  /**
+   * NTFS timestamps (0x000a) support creation time, last access time, and last modified time.
+   * These timestamps are stored with 100-millisecond precision using UTC.
+   */
+  val ntfsLastModifiedAtFiletime: Long? = null,
+  val ntfsLastAccessedAtFiletime: Long? = null,
+  val ntfsCreatedAtFiletime: Long? = null,
+
+  /**
+   * Extended timestamps (0x5455) are stored as signed 32-bit timestamps with 1-second precision.
+   * These cannot express dates beyond 2038-01-19.
+   */
+  val extendedLastModifiedAtSeconds: Int? = null,
+  val extendedLastAccessedAtSeconds: Int? = null,
+  val extendedCreatedAtSeconds: Int? = null,
+) {
+  val children = mutableListOf<Path>()
+
+  internal fun copy(
+    extendedLastModifiedAtSeconds: Int?,
+    extendedLastAccessedAtSeconds: Int?,
+    extendedCreatedAtSeconds: Int?,
+  ) = ZipEntry(
+    canonicalPath = canonicalPath,
+    isDirectory = isDirectory,
+    comment = comment,
+    crc = crc,
+    compressedSize = compressedSize,
+    size = size,
+    compressionMethod = compressionMethod,
+    offset = offset,
+    dosLastModifiedAtDate = dosLastModifiedAtDate,
+    dosLastModifiedAtTime = dosLastModifiedAtTime,
+    ntfsLastModifiedAtFiletime = ntfsLastModifiedAtFiletime,
+    ntfsLastAccessedAtFiletime = ntfsLastAccessedAtFiletime,
+    ntfsCreatedAtFiletime = ntfsCreatedAtFiletime,
+    extendedLastModifiedAtSeconds = extendedLastModifiedAtSeconds,
+    extendedLastAccessedAtSeconds = extendedLastAccessedAtSeconds,
+    extendedCreatedAtSeconds = extendedCreatedAtSeconds,
+  )
+
+  internal val lastAccessedAtMillis: Long?
+    get() = when {
+      ntfsLastAccessedAtFiletime != null -> filetimeToEpochMillis(ntfsLastAccessedAtFiletime)
+      extendedLastAccessedAtSeconds != null -> extendedLastAccessedAtSeconds * 1000L
+      else -> null
+    }
+
+  internal val lastModifiedAtMillis: Long?
+    get() = when {
+      ntfsLastModifiedAtFiletime != null -> filetimeToEpochMillis(ntfsLastModifiedAtFiletime)
+      extendedLastModifiedAtSeconds != null -> extendedLastModifiedAtSeconds * 1000L
+      dosLastModifiedAtTime != -1 -> {
+        dosDateTimeToEpochMillis(dosLastModifiedAtDate, dosLastModifiedAtTime)
+      }
+      else -> null
+    }
+
+  internal val createdAtMillis: Long?
+    get() = when {
+      ntfsCreatedAtFiletime != null -> filetimeToEpochMillis(ntfsCreatedAtFiletime)
+      extendedCreatedAtSeconds != null -> extendedCreatedAtSeconds * 1000L
+      else -> null
+    }
+}
diff --git a/okio/src/jvmMain/kotlin/okio/internal/ZipFiles.kt b/okio/src/zlibMain/kotlin/okio/internal/ZipFiles.kt
similarity index 79%
rename from okio/src/jvmMain/kotlin/okio/internal/ZipFiles.kt
rename to okio/src/zlibMain/kotlin/okio/internal/ZipFiles.kt
index 02b6a848..5b1348f2 100644
--- a/okio/src/jvmMain/kotlin/okio/internal/ZipFiles.kt
+++ b/okio/src/zlibMain/kotlin/okio/internal/ZipFiles.kt
@@ -16,16 +16,14 @@
  */
 package okio.internal
 
-import java.util.Calendar
-import java.util.GregorianCalendar
 import okio.BufferedSource
-import okio.FileMetadata
 import okio.FileSystem
 import okio.IOException
 import okio.Path
 import okio.Path.Companion.toPath
 import okio.ZipFileSystem
 import okio.buffer
+import okio.use
 
 private const val LOCAL_FILE_HEADER_SIGNATURE = 0x4034b50
 private const val CENTRAL_FILE_HEADER_SIGNATURE = 0x2014b50
@@ -49,6 +47,7 @@ private const val BIT_FLAG_UNSUPPORTED_MASK = BIT_FLAG_ENCRYPTED
 private const val MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE = 0xffffffffL
 
 private const val HEADER_ID_ZIP64_EXTENDED_INFO = 0x1
+private const val HEADER_ID_NTFS_EXTRA = 0x000a
 private const val HEADER_ID_EXTENDED_TIMESTAMP = 0x5455
 
 /**
@@ -125,7 +124,7 @@ internal fun openZip(
     val entries = mutableListOf<ZipEntry>()
     fileHandle.source(record.centralDirectoryOffset).buffer().use { source ->
       for (i in 0 until record.entryCount) {
-        val entry = source.readEntry()
+        val entry = source.readCentralDirectoryZipEntry()
         if (entry.offset >= record.centralDirectoryOffset) {
           throw IOException("bad zip: local file header offset >= central directory offset")
         }
@@ -187,7 +186,7 @@ private fun buildIndex(entries: List<ZipEntry>): Map<Path, ZipEntry> {
 
 /** When this returns, [this] will be positioned at the start of the next entry. */
 @Throws(IOException::class)
-internal fun BufferedSource.readEntry(): ZipEntry {
+internal fun BufferedSource.readCentralDirectoryZipEntry(): ZipEntry {
   val signature = readIntLe()
   if (signature != CENTRAL_FILE_HEADER_SIGNATURE) {
     throw IOException(
@@ -202,10 +201,8 @@ internal fun BufferedSource.readEntry(): ZipEntry {
   }
 
   val compressionMethod = readShortLe().toInt() and 0xffff
-  val time = readShortLe().toInt() and 0xffff
-  val date = readShortLe().toInt() and 0xffff
-  // TODO(jwilson): decode NTFS and UNIX extra metadata to return better timestamps.
-  val lastModifiedAtMillis = dosDateTimeToEpochMillis(date, time)
+  val dosLastModifiedTime = readShortLe().toInt() and 0xffff
+  val dosLastModifiedDate = readShortLe().toInt() and 0xffff
 
   // These are 32-bit values in the file, but 64-bit fields in this object.
   val crc = readIntLe().toLong() and 0xffffffffL
@@ -228,6 +225,10 @@ internal fun BufferedSource.readEntry(): ZipEntry {
     return@run result
   }
 
+  var ntfsLastModifiedAtFiletime: Long? = null
+  var ntfsLastAccessedAtFiletime: Long? = null
+  var ntfsCreatedAtFiletime: Long? = null
+
   var hasZip64Extra = false
   readExtra(extraSize) { headerId, dataSize ->
     when (headerId) {
@@ -246,6 +247,33 @@ internal fun BufferedSource.readEntry(): ZipEntry {
         compressedSize = if (compressedSize == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) readLongLe() else 0L
         offset = if (offset == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) readLongLe() else 0L
       }
+
+      HEADER_ID_NTFS_EXTRA -> {
+        if (dataSize < 4L) {
+          throw IOException("bad zip: NTFS extra too short")
+        }
+        skip(4L)
+
+        // Reads the NTFS extra metadata. This metadata recursively does a tag and length scheme
+        // inside of ZIP extras' own tag and length scheme. So we do readExtra() again.
+        readExtra((dataSize - 4L).toInt()) { attributeId, attributeSize ->
+          when (attributeId) {
+            0x1 -> {
+              if (ntfsLastModifiedAtFiletime != null) {
+                throw IOException("bad zip: NTFS extra attribute tag 0x0001 repeated")
+              }
+
+              if (attributeSize != 24L) {
+                throw IOException("bad zip: NTFS extra attribute tag 0x0001 size != 24")
+              }
+
+              ntfsLastModifiedAtFiletime = readLongLe()
+              ntfsLastAccessedAtFiletime = readLongLe()
+              ntfsCreatedAtFiletime = readLongLe()
+            }
+          }
+        }
+      }
     }
   }
 
@@ -265,8 +293,12 @@ internal fun BufferedSource.readEntry(): ZipEntry {
     compressedSize = compressedSize,
     size = size,
     compressionMethod = compressionMethod,
-    lastModifiedAtMillis = lastModifiedAtMillis,
     offset = offset,
+    dosLastModifiedAtDate = dosLastModifiedDate,
+    dosLastModifiedAtTime = dosLastModifiedTime,
+    ntfsLastModifiedAtFiletime = ntfsLastModifiedAtFiletime,
+    ntfsLastAccessedAtFiletime = ntfsLastAccessedAtFiletime,
+    ntfsCreatedAtFiletime = ntfsCreatedAtFiletime,
   )
 }
 
@@ -352,19 +384,17 @@ internal fun BufferedSource.skipLocalHeader() {
   readOrSkipLocalHeader(null)
 }
 
-internal fun BufferedSource.readLocalHeader(basicMetadata: FileMetadata): FileMetadata {
-  return readOrSkipLocalHeader(basicMetadata)!!
+internal fun BufferedSource.readLocalHeader(centralDirectoryZipEntry: ZipEntry): ZipEntry {
+  return readOrSkipLocalHeader(centralDirectoryZipEntry)!!
 }
 
 /**
- * If [basicMetadata] is null this will return null. Otherwise it will return a new header which
- * updates [basicMetadata] with information from the local header.
+ * If [centralDirectoryZipEntry] is null this will return null. Otherwise, it will return a new
+ * entry which unions [centralDirectoryZipEntry] with information from the local header.
  */
-private fun BufferedSource.readOrSkipLocalHeader(basicMetadata: FileMetadata?): FileMetadata? {
-  var lastModifiedAtMillis = basicMetadata?.lastModifiedAtMillis
-  var lastAccessedAtMillis: Long? = null
-  var createdAtMillis: Long? = null
-
+private fun BufferedSource.readOrSkipLocalHeader(
+  centralDirectoryZipEntry: ZipEntry?,
+): ZipEntry? {
   val signature = readIntLe()
   if (signature != LOCAL_FILE_HEADER_SIGNATURE) {
     throw IOException(
@@ -381,11 +411,15 @@ private fun BufferedSource.readOrSkipLocalHeader(basicMetadata: FileMetadata?):
   val extraSize = readShortLe().toInt() and 0xffff
   skip(fileNameLength)
 
-  if (basicMetadata == null) {
+  if (centralDirectoryZipEntry == null) {
     skip(extraSize.toLong())
     return null
   }
 
+  var extendedLastModifiedAtSeconds: Int? = null
+  var extendedLastAccessedAtSeconds: Int? = null
+  var extendedCreatedAtSeconds: Int? = null
+
   readExtra(extraSize) { headerId, dataSize ->
     when (headerId) {
       HEADER_ID_EXTENDED_TIMESTAMP -> {
@@ -408,44 +442,54 @@ private fun BufferedSource.readOrSkipLocalHeader(basicMetadata: FileMetadata?):
           throw IOException("bad zip: extended timestamp extra too short")
         }
 
-        if (hasLastModifiedAtMillis) lastModifiedAtMillis = readIntLe() * 1000L
-        if (hasLastAccessedAtMillis) lastAccessedAtMillis = readIntLe() * 1000L
-        if (hasCreatedAtMillis) createdAtMillis = readIntLe() * 1000L
+        if (hasLastModifiedAtMillis) extendedLastModifiedAtSeconds = readIntLe()
+        if (hasLastAccessedAtMillis) extendedLastAccessedAtSeconds = readIntLe()
+        if (hasCreatedAtMillis) extendedCreatedAtSeconds = readIntLe()
       }
     }
   }
 
-  return FileMetadata(
-    isRegularFile = basicMetadata.isRegularFile,
-    isDirectory = basicMetadata.isDirectory,
-    symlinkTarget = null,
-    size = basicMetadata.size,
-    createdAtMillis = createdAtMillis,
-    lastModifiedAtMillis = lastModifiedAtMillis,
-    lastAccessedAtMillis = lastAccessedAtMillis,
+  return centralDirectoryZipEntry.copy(
+    extendedLastModifiedAtSeconds = extendedLastModifiedAtSeconds,
+    extendedLastAccessedAtSeconds = extendedLastAccessedAtSeconds,
+    extendedCreatedAtSeconds = extendedCreatedAtSeconds,
   )
 }
 
+/**
+ * Converts from the Microsoft [filetime] format to the Java epoch millis format.
+ *
+ *  * Filetime's unit is 100 nanoseconds, and 0 is 1601-01-01T00:00:00Z.
+ *  * Java epoch millis' unit is 1 millisecond, and 0 is 1970-01-01T00:00:00Z.
+ *
+ * See also https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
+ */
+internal fun filetimeToEpochMillis(filetime: Long): Long {
+  // There's 11,644,473,600,000 milliseconds between 1601-01-01T00:00:00Z and 1970-01-01T00:00:00Z.
+  //   val years = 1_970 − 1_601
+  //   val leapYears = floor(years / 4) − floor(years / 100)
+  //   val days = (years * 365) + leapYears
+  //   val millis = days * 24 * 60 * 60 * 1_000
+  return filetime / 10_000 - 11_644_473_600_000L
+}
+
 /**
  * Converts a 32-bit DOS date+time to milliseconds since epoch. Note that this function interprets
  * a value with no time zone as a value with the local time zone.
  */
-private fun dosDateTimeToEpochMillis(date: Int, time: Int): Long? {
+internal fun dosDateTimeToEpochMillis(date: Int, time: Int): Long? {
   if (time == -1) {
     return null
   }
 
-  // Note that this inherits the local time zone.
-  val cal = GregorianCalendar()
-  cal.set(Calendar.MILLISECOND, 0)
-  val year = 1980 + (date shr 9 and 0x7f)
-  val month = date shr 5 and 0xf
-  val day = date and 0x1f
-  val hour = time shr 11 and 0x1f
-  val minute = time shr 5 and 0x3f
-  val second = time and 0x1f shl 1
-  cal.set(year, month - 1, day, hour, minute, second)
-  return cal.time.time
+  return datePartsToEpochMillis(
+    year = 1980 + (date shr 9 and 0x7f),
+    month = date shr 5 and 0xf,
+    day = date and 0x1f,
+    hour = time shr 11 and 0x1f,
+    minute = time shr 5 and 0x3f,
+    second = time and 0x1f shl 1,
+  )
 }
 
 private class EocdRecord(
diff --git a/okio/src/jvmTest/kotlin/okio/GzipKotlinTest.kt b/okio/src/zlibTest/kotlin/okio/GzipKotlinTest.kt
similarity index 98%
rename from okio/src/jvmTest/kotlin/okio/GzipKotlinTest.kt
rename to okio/src/zlibTest/kotlin/okio/GzipKotlinTest.kt
index dfe7182a..e1624142 100644
--- a/okio/src/jvmTest/kotlin/okio/GzipKotlinTest.kt
+++ b/okio/src/zlibTest/kotlin/okio/GzipKotlinTest.kt
@@ -16,9 +16,9 @@
 
 package okio
 
+import kotlin.test.Test
 import kotlin.test.assertEquals
 import okio.ByteString.Companion.decodeHex
-import org.junit.Test
 
 class GzipKotlinTest {
   @Test fun sink() {
diff --git a/okio/src/jvmTest/kotlin/okio/GzipSinkTest.kt b/okio/src/zlibTest/kotlin/okio/GzipSinkTest.kt
similarity index 87%
rename from okio/src/jvmTest/kotlin/okio/GzipSinkTest.kt
rename to okio/src/zlibTest/kotlin/okio/GzipSinkTest.kt
index b3fe171a..5f045b38 100644
--- a/okio/src/jvmTest/kotlin/okio/GzipSinkTest.kt
+++ b/okio/src/zlibTest/kotlin/okio/GzipSinkTest.kt
@@ -15,11 +15,9 @@
  */
 package okio
 
-import java.io.IOException
-import okio.TestUtil.SEGMENT_SIZE
-import org.junit.Assert.assertEquals
-import org.junit.Assert.fail
-import org.junit.Test
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.fail
 
 class GzipSinkTest {
   @Test
@@ -41,7 +39,7 @@ class GzipSinkTest {
     mockSink.scheduleThrow(0, IOException("first"))
     mockSink.scheduleThrow(1, IOException("second"))
     val gzipSink = GzipSink(mockSink)
-    gzipSink.write(Buffer().writeUtf8("a".repeat(SEGMENT_SIZE)), SEGMENT_SIZE.toLong())
+    gzipSink.write(Buffer().writeUtf8("a".repeat(Segment.SIZE)), Segment.SIZE.toLong())
     try {
       gzipSink.close()
       fail()
diff --git a/okio/src/jvmTest/kotlin/okio/GzipSourceTest.kt b/okio/src/zlibTest/kotlin/okio/GzipSourceTest.kt
similarity index 90%
rename from okio/src/jvmTest/kotlin/okio/GzipSourceTest.kt
rename to okio/src/zlibTest/kotlin/okio/GzipSourceTest.kt
index 812aab14..95aa9d35 100644
--- a/okio/src/jvmTest/kotlin/okio/GzipSourceTest.kt
+++ b/okio/src/zlibTest/kotlin/okio/GzipSourceTest.kt
@@ -15,17 +15,15 @@
  */
 package okio
 
-import java.io.IOException
-import java.util.zip.CRC32
-import kotlin.text.Charsets.UTF_8
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlin.test.assertFalse
+import kotlin.test.assertTrue
+import kotlin.test.fail
 import okio.ByteString.Companion.decodeHex
+import okio.ByteString.Companion.encodeUtf8
 import okio.ByteString.Companion.of
-import okio.TestUtil.reverseBytes
-import org.junit.Assert.assertEquals
-import org.junit.Assert.assertFalse
-import org.junit.Assert.assertTrue
-import org.junit.Assert.fail
-import org.junit.Test
+import okio.internal.CRC32
 
 class GzipSourceTest {
   @Test
@@ -44,7 +42,7 @@ class GzipSourceTest {
     hcrc.update(gzipHeader.toByteArray())
     val gzipped = Buffer()
     gzipped.write(gzipHeader)
-    gzipped.writeShort(hcrc.value.toShort().reverseBytes().toInt()) // little endian
+    gzipped.writeShort(hcrc.getValue().toShort().reverseBytes().toInt()) // little endian
     gzipped.write(deflated)
     gzipped.write(gzipTrailer)
     assertGzipped(gzipped)
@@ -55,7 +53,7 @@ class GzipSourceTest {
     val gzipped = Buffer()
     gzipped.write(gzipHeaderWithFlags(0x04.toByte()))
     gzipped.writeShort(7.toShort().reverseBytes().toInt()) // little endian extra length
-    gzipped.write("blubber".toByteArray(UTF_8), 0, 7)
+    gzipped.write("blubber".encodeUtf8().toByteArray(), 0, 7)
     gzipped.write(deflated)
     gzipped.write(gzipTrailer)
     assertGzipped(gzipped)
@@ -65,7 +63,7 @@ class GzipSourceTest {
   fun gunzip_withName() {
     val gzipped = Buffer()
     gzipped.write(gzipHeaderWithFlags(0x08.toByte()))
-    gzipped.write("foo.txt".toByteArray(UTF_8), 0, 7)
+    gzipped.write("foo.txt".encodeUtf8().toByteArray(), 0, 7)
     gzipped.writeByte(0) // zero-terminated
     gzipped.write(deflated)
     gzipped.write(gzipTrailer)
@@ -76,7 +74,7 @@ class GzipSourceTest {
   fun gunzip_withComment() {
     val gzipped = Buffer()
     gzipped.write(gzipHeaderWithFlags(0x10.toByte()))
-    gzipped.write("rubbish".toByteArray(UTF_8), 0, 7)
+    gzipped.write("rubbish".encodeUtf8().toByteArray(), 0, 7)
     gzipped.writeByte(0) // zero-terminated
     gzipped.write(deflated)
     gzipped.write(gzipTrailer)
@@ -92,10 +90,10 @@ class GzipSourceTest {
     val gzipped = Buffer()
     gzipped.write(gzipHeaderWithFlags(0x1c.toByte()))
     gzipped.writeShort(7.toShort().reverseBytes().toInt()) // little endian extra length
-    gzipped.write("blubber".toByteArray(UTF_8), 0, 7)
-    gzipped.write("foo.txt".toByteArray(UTF_8), 0, 7)
+    gzipped.write("blubber".encodeUtf8().toByteArray(), 0, 7)
+    gzipped.write("foo.txt".encodeUtf8().toByteArray(), 0, 7)
     gzipped.writeByte(0) // zero-terminated
-    gzipped.write("rubbish".toByteArray(UTF_8), 0, 7)
+    gzipped.write("rubbish".encodeUtf8().toByteArray(), 0, 7)
     gzipped.writeByte(0) // zero-terminated
     gzipped.write(deflated)
     gzipped.write(gzipTrailer)
diff --git a/okio/src/zlibTest/kotlin/okio/ZipFileSystemGoTest.kt b/okio/src/zlibTest/kotlin/okio/ZipFileSystemGoTest.kt
new file mode 100644
index 00000000..07943c4b
--- /dev/null
+++ b/okio/src/zlibTest/kotlin/okio/ZipFileSystemGoTest.kt
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package okio
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import kotlinx.datetime.Instant
+import okio.Path.Companion.toPath
+
+/**
+ * Test using sample data from Go's test suite.
+ *
+ * https://github.com/golang/go/blob/6f5d77454e31be8af11a7e2bcda36d200fda07c5/src/archive/zip/reader_test.go
+ */
+class ZipFileSystemGoTest {
+  private val fileSystem = FileSystem.SYSTEM
+  private var base = okioRoot / "okio-testing-support" /
+    "src/commonMain/resources/go/src/archive/zip/testdata"
+
+  @Test
+  fun timeWinzip() {
+    val zipFileSystem = fileSystem.openZip(base / "time-winzip.zip")
+    val fileMetadata = zipFileSystem.metadata("test.txt".toPath())
+    assertEquals(
+      Instant.parse("2017-11-01T04:11:57.244Z"),
+      Instant.fromEpochMilliseconds(fileMetadata.createdAtMillis!!),
+    )
+    assertEquals(
+      Instant.parse("2017-11-01T04:11:57.244Z"),
+      Instant.fromEpochMilliseconds(fileMetadata.lastModifiedAtMillis!!),
+    )
+    assertEquals(
+      Instant.parse("2017-11-01T04:13:19.623Z"),
+      Instant.fromEpochMilliseconds(fileMetadata.lastAccessedAtMillis!!),
+    )
+  }
+}
diff --git a/okio/src/jvmTest/kotlin/okio/ZipFileSystemTest.kt b/okio/src/zlibTest/kotlin/okio/ZipFileSystemTest.kt
similarity index 66%
rename from okio/src/jvmTest/kotlin/okio/ZipFileSystemTest.kt
rename to okio/src/zlibTest/kotlin/okio/ZipFileSystemTest.kt
index fd7aa46b..6919988e 100644
--- a/okio/src/jvmTest/kotlin/okio/ZipFileSystemTest.kt
+++ b/okio/src/zlibTest/kotlin/okio/ZipFileSystemTest.kt
@@ -15,55 +15,55 @@
  */
 package okio
 
+import assertk.assertThat
+import assertk.assertions.containsExactly
+import assertk.assertions.containsExactlyInAnyOrder
+import assertk.assertions.isEmpty
+import assertk.assertions.isEqualTo
+import assertk.assertions.isFalse
+import assertk.assertions.isGreaterThan
+import assertk.assertions.isLessThan
+import assertk.assertions.isNotNull
+import assertk.assertions.isNull
+import assertk.assertions.isTrue
+import kotlin.test.Test
 import kotlin.test.assertFailsWith
 import kotlinx.datetime.Instant
-import okio.ByteString.Companion.decodeHex
 import okio.ByteString.Companion.encodeUtf8
 import okio.Path.Companion.toPath
-import org.assertj.core.api.Assertions.assertThat
-import org.junit.Before
-import org.junit.Test
 
 class ZipFileSystemTest {
   private val fileSystem = FileSystem.SYSTEM
-  private var base = FileSystem.SYSTEM_TEMPORARY_DIRECTORY / randomToken(16)
-
-  @Before
-  fun setUp() {
-    fileSystem.createDirectory(base)
-  }
+  private var base = okioRoot / "okio-testing-support/src/commonMain/resources/okio/zipfilesystem"
 
   @Test
   fun emptyZip() {
-    // ZipBuilder cannot write empty zips.
-    val zipPath = base / "empty.zip"
-    fileSystem.write(zipPath) {
-      write("504b0506000000000000000000000000000000000000".decodeHex())
-    }
-
-    val zipFileSystem = fileSystem.openZip(zipPath)
+    val zipFileSystem = fileSystem.openZip(base / "emptyZip.zip")
     assertThat(zipFileSystem.list("/".toPath())).isEmpty()
   }
 
   @Test
   fun emptyZipWithPrependedData() {
-    // ZipBuilder cannot write empty zips.
-    val zipPath = base / "empty.zip"
-    fileSystem.write(zipPath) {
-      writeUtf8("Hello I'm junk data prepended to the ZIP!")
-      write("504b0506000000000000000000000000000000000000".decodeHex())
-    }
-
-    val zipFileSystem = fileSystem.openZip(zipPath)
+    val zipFileSystem = fileSystem.openZip(base / "emptyZipWithPrependedData.zip")
     assertThat(zipFileSystem.list("/".toPath())).isEmpty()
   }
 
+  /**
+   * ```
+   * echo "Hello World" > hello.txt
+   *
+   * mkdir -p directory/subdirectory
+   * echo "Another file!" > directory/subdirectory/child.txt
+   *
+   * zip \
+   *   zipWithFiles.zip \
+   *   hello.txt \
+   *   directory/subdirectory/child.txt
+   * ```
+   */
   @Test
   fun zipWithFiles() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("hello.txt", "Hello World")
-      .addEntry("directory/subdirectory/child.txt", "Another file!")
-      .build()
+    val zipPath = base / "zipWithFiles.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.read("hello.txt".toPath()) { readUtf8() })
@@ -73,7 +73,7 @@ class ZipFileSystemTest {
       .isEqualTo("Another file!")
 
     assertThat(zipFileSystem.list("/".toPath()))
-      .hasSameElementsAs(listOf("/hello.txt".toPath(), "/directory".toPath()))
+      .containsExactlyInAnyOrder("/hello.txt".toPath(), "/directory".toPath())
     assertThat(zipFileSystem.list("/directory".toPath()))
       .containsExactly("/directory/subdirectory".toPath())
     assertThat(zipFileSystem.list("/directory/subdirectory".toPath()))
@@ -83,31 +83,52 @@ class ZipFileSystemTest {
   /**
    * Note that the zip tool does not compress files that don't benefit from it. Examples above like
    * 'Hello World' are stored, not deflated.
+   *
+   * ```
+   * echo "Android
+   * Android
+   * ... <1000 times>
+   * Android
+   * " > a.txt
+   *
+   * zip \
+   *   --compression-method \
+   *   deflate \
+   *   zipWithDeflate.zip \
+   *   a.txt
+   * ```
    */
   @Test
   fun zipWithDeflate() {
     val content = "Android\n".repeat(1000)
-    val zipPath = ZipBuilder(base)
-      .addEntry("a.txt", content)
-      .addOption("--compression-method")
-      .addOption("deflate")
-      .build()
-    assertThat(fileSystem.metadata(zipPath).size).isLessThan(content.length.toLong())
+    val zipPath = base / "zipWithDeflate.zip"
+    assertThat(fileSystem.metadata(zipPath).size).isNotNull().isLessThan(content.length.toLong())
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.read("a.txt".toPath()) { readUtf8() })
       .isEqualTo(content)
   }
 
+  /**
+   * ```
+   * echo "Android
+   * Android
+   * ... <1000 times>
+   * Android
+   * " > a.txt
+   *
+   * zip \
+   *   --compression-method \
+   *   store \
+   *   zipWithStore.zip \
+   *   a.txt
+   * ```
+   */
   @Test
   fun zipWithStore() {
     val content = "Android\n".repeat(1000)
-    val zipPath = ZipBuilder(base)
-      .addEntry("a.txt", content)
-      .addOption("--compression-method")
-      .addOption("store")
-      .build()
-    assertThat(fileSystem.metadata(zipPath).size).isGreaterThan(content.length.toLong())
+    val zipPath = base / "zipWithStore.zip"
+    assertThat(fileSystem.metadata(zipPath).size).isNotNull().isGreaterThan(content.length.toLong())
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.read("a.txt".toPath()) { readUtf8() })
@@ -117,13 +138,22 @@ class ZipFileSystemTest {
   /**
    * Confirm we can read zip files that have file comments, even if these comments are not exposed
    * in the public API.
+   *
+   * ```
+   * echo "Android" > a.txt
+   *
+   * echo "Banana" > b.txt
+   *
+   * zip \
+   *   --entry-comments \
+   *   zipWithFileComments.zip \
+   *   a.txt \
+   *   b.txt
+   * ```
    */
   @Test
   fun zipWithFileComments() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("a.txt", "Android", comment = "A is for Android")
-      .addEntry("b.txt", "Banana", comment = "B or not to Be")
-      .build()
+    val zipPath = base / "zipWithFileComments.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.read("a.txt".toPath()) { readUtf8() })
@@ -133,22 +163,25 @@ class ZipFileSystemTest {
       .isEqualTo("Banana")
   }
 
+  /**
+   * ```
+   * echo "Android" > a.txt
+   * touch -m -t 200102030405.06 a.txt
+   * touch -a -t 200102030405.07 a.txt
+   *
+   * echo "Banana" > b.txt
+   * touch -m -t 200908070605.04 b.txt
+   * touch -a -t 200908070605.03 b.txt
+   *
+   * zip \
+   *   zipWithFileModifiedDate.zip \
+   *   a.txt \
+   *   b.txt
+   * ```
+   */
   @Test
   fun zipWithFileModifiedDate() {
-    val zipPath = ZipBuilder(base)
-      .addEntry(
-        path = "a.txt",
-        content = "Android",
-        modifiedAt = "200102030405.06",
-        accessedAt = "200102030405.07",
-      )
-      .addEntry(
-        path = "b.txt",
-        content = "Banana",
-        modifiedAt = "200908070605.04",
-        accessedAt = "200908070605.03",
-      )
-      .build()
+    val zipPath = base / "zipWithFileModifiedDate.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     zipFileSystem.metadata("a.txt".toPath())
@@ -172,23 +205,27 @@ class ZipFileSystemTest {
       }
   }
 
-  /** Confirm we suffer UNIX limitations on our date format. */
+  /**
+   * Confirm we suffer UNIX limitations on our date format.
+   *
+   * ```
+   * echo "Android" > a.txt
+   * touch -m -t 196912310000.00 a.txt
+   * touch -a -t 196912300000.00 a.txt
+   *
+   * echo "Banana" > b.txt
+   * touch -m -t 203801190314.07 b.txt
+   * touch -a -t 203801190314.08 b.txt
+   *
+   * zip \
+   *   zipWithFileOutOfBoundsModifiedDate.zip \
+   *   a.txt \
+   *   b.txt
+   * ```
+   */
   @Test
   fun zipWithFileOutOfBoundsModifiedDate() {
-    val zipPath = ZipBuilder(base)
-      .addEntry(
-        path = "a.txt",
-        content = "Android",
-        modifiedAt = "196912310000.00",
-        accessedAt = "196912300000.00",
-      )
-      .addEntry(
-        path = "b.txt",
-        content = "Banana",
-        modifiedAt = "203801190314.07", // Last UNIX date representable in 31 bits.
-        accessedAt = "203801190314.08", // Overflows!
-      )
-      .build()
+    val zipPath = base / "zipWithFileOutOfBoundsModifiedDate.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     println(Instant.fromEpochMilliseconds(-2147483648000L))
@@ -219,25 +256,29 @@ class ZipFileSystemTest {
    * Directories are optional in the zip file. But if we want metadata on them they must be stored.
    * Note that this test adds the directories last; otherwise adding child files to them will cause
    * their modified at times to change.
+   *
+   * ```
+   * mkdir -p a
+   * echo "Android" > a/a.txt
+   * touch -m -t 200102030405.06 a
+   * touch -a -t 200102030405.07 a
+   *
+   * mkdir -p b
+   * echo "Android" > b/b.txt
+   * touch -m -t 200908070605.04 b
+   * touch -a -t 200908070605.03 b
+   *
+   * zip \
+   *   zipWithDirectoryModifiedDate.zip \
+   *   a/a.txt \
+   *   a \
+   *   b/b.txt \
+   *   b
+   * ```
    */
   @Test
   fun zipWithDirectoryModifiedDate() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("a/a.txt", "Android")
-      .addEntry(
-        path = "a",
-        directory = true,
-        modifiedAt = "200102030405.06",
-        accessedAt = "200102030405.07",
-      )
-      .addEntry("b/b.txt", "Android")
-      .addEntry(
-        path = "b",
-        directory = true,
-        modifiedAt = "200908070605.04",
-        accessedAt = "200908070605.03",
-      )
-      .build()
+    val zipPath = base / "zipWithDirectoryModifiedDate.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     zipFileSystem.metadata("a".toPath())
@@ -263,16 +304,21 @@ class ZipFileSystemTest {
     assertThat(zipFileSystem.list("b".toPath())).containsExactly("/b/b.txt".toPath())
   }
 
+  /**
+   * ```
+   * mkdir -p a
+   * echo "Android" > a/a.txt
+   * touch -m -t 197001010001.00 a/a.txt
+   * touch -a -t 197001010002.00 a/a.txt
+   *
+   * zip \
+   *   zipWithModifiedDate.zip \
+   *   a/a.txt
+   * ```
+   */
   @Test
   fun zipWithModifiedDate() {
-    val zipPath = ZipBuilder(base)
-      .addEntry(
-        "a/a.txt",
-        modifiedAt = "197001010001.00",
-        accessedAt = "197001010002.00",
-        content = "Android",
-      )
-      .build()
+    val zipPath = base / "zipWithModifiedDate.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     zipFileSystem.metadata("a/a.txt".toPath())
@@ -283,17 +329,22 @@ class ZipFileSystemTest {
       }
   }
 
-  /** Build a very small zip file with just a single empty directory. */
+  /**
+   * Build a very small zip file with just a single empty directory.
+   *
+   * ```
+   * mkdir -p a
+   * touch -m -t 200102030405.06 a
+   * touch -a -t 200102030405.07 a
+   *
+   * zip \
+   *   zipWithEmptyDirectory.zip \
+   *   a
+   * ```
+   */
   @Test
   fun zipWithEmptyDirectory() {
-    val zipPath = ZipBuilder(base)
-      .addEntry(
-        path = "a",
-        directory = true,
-        modifiedAt = "200102030405.06",
-        accessedAt = "200102030405.07",
-      )
-      .build()
+    val zipPath = base / "zipWithEmptyDirectory.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     zipFileSystem.metadata("a".toPath())
@@ -311,16 +362,26 @@ class ZipFileSystemTest {
   /**
    * The `--no-dir-entries` option causes the zip file to omit the directories from the encoded
    * file. Our implementation synthesizes these missing directories automatically.
+   *
+   * ```
+   * mkdir -p a
+   * echo "Android" > a/a.txt
+   *
+   * mkdir -p b
+   * echo "Android" > b/b.txt
+   *
+   * zip \
+   *   --no-dir-entries \
+   *   zipWithSyntheticDirectory.zip \
+   *   a/a.txt \
+   *   a \
+   *   b/b.txt \
+   *   b
+   * ```
    */
   @Test
   fun zipWithSyntheticDirectory() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("a/a.txt", "Android")
-      .addEntry("a", directory = true)
-      .addEntry("b/b.txt", "Android")
-      .addEntry("b", directory = true)
-      .addOption("--no-dir-entries")
-      .build()
+    val zipPath = base / "zipWithSyntheticDirectory.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     zipFileSystem.metadata("a".toPath())
@@ -349,12 +410,16 @@ class ZipFileSystemTest {
   /**
    * Force a file to be encoded with zip64 metadata. We use a pipe to force the zip command to
    * create a zip64 archive; otherwise we'd need to add a very large file to get this format.
+   *
+   * ```
+   * zip \
+   *   zip64.zip \
+   *   -
+   * ```
    */
   @Test
   fun zip64() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("-", "Android", zip64 = true)
-      .build()
+    val zipPath = base / "zip64.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.read("-".toPath()) { readUtf8() })
@@ -364,50 +429,76 @@ class ZipFileSystemTest {
   /**
    * Confirm we can read zip files with a full-archive comment, even if this comment is not surfaced
    * in our API.
+   *
+   * ```
+   * echo "Android" > a.txt
+   *
+   * zip \
+   *   --archive-comment \
+   *   zipWithArchiveComment.zip \
+   *   a.txt
+   * ```
    */
   @Test
   fun zipWithArchiveComment() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("a.txt", "Android")
-      .archiveComment("this comment applies to the entire archive")
-      .build()
+    val zipPath = base / "zipWithArchiveComment.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.read("a.txt".toPath()) { readUtf8() })
       .isEqualTo("Android")
   }
 
+  /**
+   * ```
+   * echo "(...128 KiB...)" > large_file.txt
+   *
+   * zip \
+   *   --split-size \
+   *   64k \
+   *   cannotReadZipWithSpanning.zip \
+   *   large_file.txt
+   * ```
+   */
   @Test
   fun cannotReadZipWithSpanning() {
     // Spanned archives must be at least 64 KiB.
-    val largeFile = randomToken(length = 128 * 1024)
-    val zipPath = ZipBuilder(base)
-      .addEntry("large_file.txt", largeFile)
-      .addOption("--split-size")
-      .addOption("64k")
-      .build()
+    val zipPath = base / "cannotReadZipWithSpanning.zip"
     assertFailsWith<IOException> {
       fileSystem.openZip(zipPath)
     }
   }
 
+  /**
+   * ```
+   * echo "Android" > a.txt
+   *
+   * zip \
+   *   --password \
+   *   secret \
+   *   cannotReadZipWithEncryption.zip \
+   *   a.txt
+   * ```
+   */
   @Test
   fun cannotReadZipWithEncryption() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("a.txt", "Android")
-      .addOption("--password")
-      .addOption("secret")
-      .build()
+    val zipPath = base / "cannotReadZipWithEncryption.zip"
     assertFailsWith<IOException> {
       fileSystem.openZip(zipPath)
     }
   }
 
+  /**
+   * ```
+   * echo "Android" > a.txt
+   *
+   * zip \
+   *   zipTooShort.zip \
+   *   a.txt
+   * ```
+   */
   @Test
   fun zipTooShort() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("a.txt", "Android")
-      .build()
+    val zipPath = base / "zipTooShort.zip"
 
     val prefix = fileSystem.read(zipPath) { readByteString(20) }
     fileSystem.write(zipPath) { write(prefix) }
@@ -423,15 +514,23 @@ class ZipFileSystemTest {
    * `META-INF/kotlin-gradle-statistics.kotlin_module`.
    *
    * We used to crash on duplicates, but they are common in practice so now we prefer the last
-   * entry. This behavior is consistent with both [java.util.zip.ZipFile] and
-   * [java.nio.file.FileSystem].
+   * entry. This behavior is consistent with both `java.util.zip.ZipFile` and
+   * `java.nio.file.FileSystem`.
+   *
+   * ```
+   * echo "This is the first hello.txt" > hello.txt
+   *
+   * echo "This is the second hello.txt" > xxxxx.xxx
+   *
+   * zip \
+   *   filesOverlap.zip \
+   *   hello.txt \
+   *   xxxxx.xxx
+   * ```
    */
   @Test
   fun filesOverlap() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("hello.txt", "This is the first hello.txt")
-      .addEntry("xxxxx.xxx", "This is the second hello.txt")
-      .build()
+    val zipPath = base / "filesOverlap.zip"
     val original = fileSystem.read(zipPath) { readByteString() }
     val rewritten = original.replaceAll("xxxxx.xxx".encodeUtf8(), "hello.txt".encodeUtf8())
     fileSystem.write(zipPath) { write(rewritten) }
@@ -443,12 +542,22 @@ class ZipFileSystemTest {
       .containsExactly("/hello.txt".toPath())
   }
 
+  /**
+   * ```
+   * echo "Hello World" > hello.txt
+   *
+   * mkdir -p directory
+   * echo "Another file!" > directory/child.txt
+   *
+   * zip \
+   *   canonicalizationValid.zip \
+   *   hello.txt \
+   *   directory/child.txt
+   * ```
+   */
   @Test
   fun canonicalizationValid() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("hello.txt", "Hello World")
-      .addEntry("directory/child.txt", "Another file!")
-      .build()
+    val zipPath = base / "canonicalizationValid.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertThat(zipFileSystem.canonicalize("/".toPath())).isEqualTo("/".toPath())
@@ -462,12 +571,22 @@ class ZipFileSystemTest {
     assertThat(zipFileSystem.canonicalize("directory/whevs/../child.txt".toPath())).isEqualTo("/directory/child.txt".toPath())
   }
 
+  /**
+   * ```
+   * echo "Hello World" > hello.txt
+   *
+   * mkdir -p directory
+   * echo "Another file!" > directory/child.txt
+   *
+   * zip \
+   *   canonicalizationInvalidThrows.zip \
+   *   hello.txt \
+   *   directory/child.txt
+   * ```
+   */
   @Test
   fun canonicalizationInvalidThrows() {
-    val zipPath = ZipBuilder(base)
-      .addEntry("hello.txt", "Hello World")
-      .addEntry("directory/child.txt", "Another file!")
-      .build()
+    val zipPath = base / "canonicalizationInvalidThrows.zip"
     val zipFileSystem = fileSystem.openZip(zipPath)
 
     assertFailsWith<FileNotFoundException> {
diff --git a/okio/src/zlibTest/kotlin/okio/internal/CRC32Test.kt b/okio/src/zlibTest/kotlin/okio/internal/CRC32Test.kt
new file mode 100644
index 00000000..b8b9a544
--- /dev/null
+++ b/okio/src/zlibTest/kotlin/okio/internal/CRC32Test.kt
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+
+class CRC32Test {
+  @Test fun happyPath() {
+    val crc32 = CRC32()
+    crc32.update("hello world!".encodeToByteArray())
+    assertEquals(0x3B4C26D, crc32.getValue())
+  }
+
+  @Test fun multipleUpdates() {
+    val crc32 = CRC32()
+    crc32.update("hello ".encodeToByteArray())
+    crc32.update("world!".encodeToByteArray())
+    assertEquals(0x3B4C26D, crc32.getValue())
+  }
+
+  @Test fun resetClearsState() {
+    val crc32 = CRC32()
+    crc32.update("unused".encodeToByteArray())
+    crc32.reset()
+
+    crc32.update("hello ".encodeToByteArray())
+    crc32.update("world!".encodeToByteArray())
+    assertEquals(0x3B4C26D, crc32.getValue())
+  }
+
+  @Test fun offsetAndByteCountAreHonored() {
+    val crc32 = CRC32()
+    crc32.update("well hello there".encodeToByteArray(), 5, 6)
+    crc32.update("city! world! universe!".encodeToByteArray(), 6, 6)
+    assertEquals(0x3B4C26D, crc32.getValue())
+  }
+
+  @Test fun emptyInput() {
+    val crc32 = CRC32()
+    assertEquals(0x0, crc32.getValue())
+  }
+}
diff --git a/okio/src/zlibTest/kotlin/okio/internal/DatePartsToEpochMillisTest.kt b/okio/src/zlibTest/kotlin/okio/internal/DatePartsToEpochMillisTest.kt
new file mode 100644
index 00000000..20340498
--- /dev/null
+++ b/okio/src/zlibTest/kotlin/okio/internal/DatePartsToEpochMillisTest.kt
@@ -0,0 +1,261 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.internal
+
+import kotlin.test.Test
+import kotlin.test.assertEquals
+import okio.withUtc
+
+class DatePartsToEpochMillisTest {
+  /**
+   * Test every day from 1970-01-01 (epochMillis = 0) until 2200-01-01. Note that this includes the
+   * full range of ZIP DOS dates (1980-01-01 until 2107-12-31).
+   */
+  @Test
+  fun everySingleDay() {
+    val dateTester = DateTester()
+    while (dateTester.year < 2200) {
+      dateTester.addDay()
+      dateTester.check()
+    }
+  }
+
+  /** Test the boundaries of the ZIP DOS date format. */
+  @Test
+  fun dosDateRange() {
+    assertEquals(
+      (365 * 10 + 2) * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1980, month = 1, day = 1),
+    )
+    assertEquals(
+      (365 * 138 + 33) * (24 * 60 * 60 * 1000L) - 1_000L,
+      datePartsToEpochMillisUtc(
+        year = 2107,
+        month = 12,
+        day = 31,
+        hour = 23,
+        minute = 59,
+        second = 59,
+      ),
+    )
+  }
+
+  @Test
+  fun monthOutOfBounds() {
+    // Month -21 is the same as March, 22 months ago.
+    assertEquals(
+      (-365 + -365 + 31 + 28) * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(month = -21, day = 1),
+    )
+
+    // Month -12 is the same as December, 13 months ago.
+    assertEquals(
+      (-365 + -31) * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = -12, day = 1),
+    )
+
+    // Month -11 is the same as January, 12 months ago.
+    assertEquals(
+      -365 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = -11, day = 1),
+    )
+
+    // Month -1 is the same as November, 2 months ago.
+    assertEquals(
+      (-31 + -30) * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = -1, day = 1),
+    )
+
+    // Month 0 is the same as December, 1 month ago.
+    assertEquals(
+      -31 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 0, day = 1),
+    )
+
+    // Month 13 is the same as January, 12 months from now.
+    assertEquals(
+      365 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 13, day = 1),
+    )
+
+    // Month 24 is the same as December, 23 months from now
+    assertEquals(
+      (365 + 365 - 31) * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 24, day = 1),
+    )
+
+    // Month 25 is the same as January, 24 months from now
+    assertEquals(
+      (365 + 365) * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 25, day = 1),
+    )
+  }
+
+  @Test
+  fun dayOutOfBounds() {
+    // Day -364 is the same as January 1 of the previous year.
+    assertEquals(
+      -365 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 1, day = -364),
+    )
+
+    // Day -1 is the same as December 30 of the previous year.
+    assertEquals(
+      -2 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 1, day = -1),
+    )
+
+    // Day 0 is the same as December 31 of the previous year.
+    assertEquals(
+      -1 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 1, day = 0),
+    )
+
+    // Day 32 is the same as February 1.
+    assertEquals(
+      31 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 1, day = 32),
+    )
+
+    // Day 33 is the same as February 2.
+    assertEquals(
+      32 * (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(year = 1970, month = 1, day = 33),
+    )
+  }
+
+  @Test
+  fun hourOutOfBounds() {
+    assertEquals(
+      (-24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(hour = -24),
+    )
+    assertEquals(
+      (-1 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(hour = -1),
+    )
+    assertEquals(
+      (24 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(hour = 24),
+    )
+    assertEquals(
+      (25 * 60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(hour = 25),
+    )
+  }
+
+  @Test
+  fun minuteOutOfBounds() {
+    assertEquals(
+      (-1 * 60 * 1000L),
+      datePartsToEpochMillisUtc(minute = -1),
+    )
+    assertEquals(
+      (60 * 60 * 1000L),
+      datePartsToEpochMillisUtc(minute = 60),
+    )
+    assertEquals(
+      (61 * 60 * 1000L),
+      datePartsToEpochMillisUtc(minute = 61),
+    )
+  }
+
+  @Test
+  fun secondOutOfBounds() {
+    assertEquals(
+      (-1 * 1000L),
+      datePartsToEpochMillisUtc(hour = 0, second = -1),
+    )
+    assertEquals(
+      (60 * 1000L),
+      datePartsToEpochMillisUtc(hour = 0, second = 60),
+    )
+    assertEquals(
+      (61 * 1000L),
+      datePartsToEpochMillisUtc(hour = 0, second = 61),
+    )
+  }
+
+  private class DateTester {
+    var epochMillis = 0L
+    var year = 1970
+    var month = 1
+    var day = 1
+
+    fun addDay() {
+      day++
+      epochMillis += 24L * 60 * 60 * 1000
+
+      val monthSize = when (month) {
+        1 -> 31
+        2 -> {
+          when {
+            year % 400 == 0 -> 29
+            year % 100 == 0 -> 28
+            year % 4 == 0 -> 29
+            else -> 28
+          }
+        }
+
+        3 -> 31
+        4 -> 30
+        5 -> 31
+        6 -> 30
+        7 -> 31
+        8 -> 31
+        9 -> 30
+        10 -> 31
+        11 -> 30
+        12 -> 31
+        else -> error("unexpected month $month")
+      }
+
+      if (day > monthSize) {
+        day -= monthSize
+        month++
+        if (month > 12) {
+          month -= 12
+          year++
+        }
+      }
+    }
+
+    fun check() {
+      assertEquals(
+        expected = epochMillis,
+        actual = datePartsToEpochMillisUtc(
+          year = year,
+          month = month,
+          day = day,
+        ),
+        message = "y=$year m=$month d=$day",
+      )
+    }
+  }
+}
+
+fun datePartsToEpochMillisUtc(
+  year: Int = 1970,
+  month: Int = 1,
+  day: Int = 1,
+  hour: Int = 0,
+  minute: Int = 0,
+  second: Int = 0,
+): Long {
+  return withUtc {
+    datePartsToEpochMillis(year, month, day, hour, minute, second)
+  }
+}
diff --git a/renovate.json b/renovate.json
index 1a2efbb4..a0972cbf 100644
--- a/renovate.json
+++ b/renovate.json
@@ -1,7 +1,7 @@
 {
   "$schema": "https://docs.renovatebot.com/renovate-schema.json",
   "extends": [
-    "config:base"
+    "config:recommended"
   ],
   "semanticCommits": "disabled"
 }
diff --git a/samples/src/jvmMain/kotlin/okio/samples/TeeSink.kt b/samples/src/jvmMain/kotlin/okio/samples/TeeSink.kt
new file mode 100644
index 00000000..0ddffbf9
--- /dev/null
+++ b/samples/src/jvmMain/kotlin/okio/samples/TeeSink.kt
@@ -0,0 +1,80 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
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
+package okio.samples
+
+import okio.Buffer
+import okio.FileSystem
+import okio.Path.Companion.toPath
+import okio.Sink
+import okio.Timeout
+import okio.buffer
+import okio.sink
+
+/**
+ * A sink that writes all input to both [sinkA] and [sinkB].
+ */
+class TeeSink(
+  private val sinkA: Sink,
+  private val sinkB: Sink,
+) : Sink {
+  private val timeout = Timeout()
+
+  override fun write(source: Buffer, byteCount: Long) {
+    // Writing to sink mutates source. Work around that.
+    sinkA.timeout().intersectWith(timeout) {
+      val buffer = Buffer()
+      source.copyTo(buffer, byteCount = byteCount)
+      sinkA.write(buffer, byteCount)
+    }
+
+    sinkB.timeout().intersectWith(timeout) {
+      sinkB.write(source, byteCount)
+    }
+  }
+
+  override fun flush() {
+    sinkA.flush()
+    sinkB.flush()
+  }
+
+  override fun close() {
+    try {
+      sinkA.close()
+    } catch (tA: Throwable) {
+      try {
+        sinkB.close()
+      } catch (tB: Throwable) {
+        tA.addSuppressed(tB)
+      }
+      throw tA
+    }
+
+    sinkB.close()
+  }
+
+  override fun timeout() = sinkA.timeout()
+}
+
+fun main() {
+  val a = System.out.sink()
+  val b = FileSystem.SYSTEM.sink("tee.txt".toPath())
+
+  TeeSink(a, b).buffer().use { teeSink ->
+    teeSink.writeUtf8("hello\n")
+    teeSink.flush()
+    teeSink.writeUtf8("world!")
+  }
+}
diff --git a/settings.gradle.kts b/settings.gradle.kts
index b07a4b81..1ff0a5ad 100644
--- a/settings.gradle.kts
+++ b/settings.gradle.kts
@@ -18,7 +18,7 @@ include(":samples")
 
 // The Android test module doesn't work in IntelliJ. Use Android Studio or the command line.
 if (System.getProperties().containsKey("android.injected.invoked.from.ide") ||
-  System.getenv("ANDROID_SDK_ROOT") != null) {
+  System.getenv("ANDROID_HOME") != null) {
   include(":android-test")
 }
 
```

