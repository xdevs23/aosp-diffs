```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index da82e7d..500e97f 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -11,8 +11,9 @@ on:
   push:
     branches:
       - main
-    tags-ignore:
-      - v* # release tags are automatically generated after a successful CI build, no need to run CI against them
+    tags:
+      - 3.*
+      - 4.*
   pull_request:
     branches:
       - main
@@ -80,7 +81,7 @@ jobs:
     needs: [build] # build job must pass before we can release
 
     if: github.event_name == 'push'
-        && github.ref == 'refs/heads/main'
+        && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/3.') || startsWith(github.ref, 'refs/tags/4.'))
         && github.repository == 'mockito/mockito-kotlin'
         && !contains(toJSON(github.event.commits.*.message), '[skip release]')
 
@@ -97,7 +98,7 @@ jobs:
         java-version: 8
 
     - name: Build and release
-      run: ./gradlew githubRelease publishToSonatype closeAndReleaseStagingRepository
+      run: ./gradlew githubRelease publishToSonatype closeAndReleaseStagingRepository releaseSummary
       env:
         GITHUB_TOKEN: ${{secrets.GITHUB_TOKEN}}
         NEXUS_TOKEN_USER: ${{secrets.NEXUS_TOKEN_USER}}
diff --git a/METADATA b/METADATA
index d7158a6..9304625 100644
--- a/METADATA
+++ b/METADATA
@@ -1,14 +1,19 @@
-name: "mockito-kotlin"
-description:
-    "Mockito for Kotlin"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/mockito-kotlin
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "mockito-kotlin"
+description: "Mockito for Kotlin"
 third_party {
-  url {
-    type: GIT
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 3
+    day: 14
+  }
+  identifier {
+    type: "Git"
     value: "https://github.com/mockito/mockito-kotlin"
+    version: "4.1.0"
   }
-  version: "2.2.11"
-  last_upgrade_date { year: 2023 month: 6 day: 13 }
-  license_type: NOTICE
 }
-
diff --git a/OWNERS b/OWNERS
index 88f0700..8b4c54b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 romam@google.com
 farivar@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index abac3de..32678c7 100644
--- a/README.md
+++ b/README.md
@@ -1,11 +1,12 @@
 # Mockito-Kotlin
 [ ![Download](https://maven-badges.herokuapp.com/maven-central/org.mockito.kotlin/mockito-kotlin/badge.svg) ](https://maven-badges.herokuapp.com/maven-central/org.mockito.kotlin/mockito-kotlin)
+[![Nexus Snapshot](https://img.shields.io/nexus/s/org.mockito.kotlin/mockito-kotlin?server=https%3A%2F%2Fs01.oss.sonatype.org%2F)](https://s01.oss.sonatype.org/content/repositories/snapshots/org/mockito/kotlin/mockito-kotlin/)
 
 A small library that provides helper functions to work with [Mockito](https://github.com/mockito/mockito) in Kotlin.
 
 ## Install
 
-Mockito-Kotlin is available on Maven Central and JCenter.
+Mockito-Kotlin is available on Maven Central.
 For Gradle users, add the following to your `build.gradle`, replacing `x.x.x` with the latest version:
 
 ```groovy
@@ -39,27 +40,21 @@ For more info and samples, see the [Wiki](https://github.com/mockito/mockito-kot
 
 Mockito-Kotlin is built with Gradle.
 
- - `./gradlew build` builds the project
+ - `./gradlew build` builds and tests the project
  - `./gradlew publishToMavenLocal` installs the maven artifacts in your local repository
- - `./gradlew assemble && ./gradlew test` runs the test suite (See Testing below)
+ - `./gradlew check` runs the test suite (See Testing below)
 
 ### Versioning
 
-Mockito-Kotlin roughly follows SEMVER; version names are parsed from 
-git tags using `git describe`.
+Mockito-Kotlin roughly follows SEMVER
 
 ### Testing
 
 Mockito-Kotlin's test suite is located in a separate `tests` module,
 to allow running the tests using several Kotlin versions whilst still
-keeping the base module at a recent version.  
+keeping the base module at a recent version.
 
-Testing thus must be done in two stages: one to build the base artifact
-to test against, and the actual execution of the tests against the 
-built artifact:
-
- - `./gradlew assemble` builds the base artifact
- - `./gradlew test` runs the tests against the built artifact.
+ - `./gradlew check` runs the checks including tests.
 
 Usually it is enough to test only using the default Kotlin versions; 
 CI will test against multiple versions.
diff --git a/RELEASING.md b/RELEASING.md
index 3f0140c..d15b413 100644
--- a/RELEASING.md
+++ b/RELEASING.md
@@ -1,3 +1,12 @@
 # Releasing
 
-Every change on the main development branch is released to Maven Central.
\ No newline at end of file
+1. Every change on the main development branch is released as -SNAPSHOT version
+to Sonatype snapshot repo at https://s01.oss.sonatype.org/content/repositories/snapshots/org/mockito/kotlin/mockito-kotlin.
+2. In order to release a non-snapshot version to Maven Central push an annotated tag, for example:
+```
+git tag -a -m "Release 3.4.5" 3.4.5
+git push origin 3.4.5
+```
+3. At the moment, you **may not create releases from GitHub Web UI**.
+Doing so will make the CI build fail because the CI creates the changelog and posts to GitHub releases.
+In the future supporting this would be nice but currently please make releases by pushing from CLI.
diff --git a/build.gradle b/build.gradle
index 3e55fa8..b249424 100644
--- a/build.gradle
+++ b/build.gradle
@@ -4,16 +4,14 @@ buildscript {
         maven { url "https://plugins.gradle.org/m2/" }
     }
     dependencies {
-        classpath "org.shipkit:shipkit-changelog:1.+"
-        classpath "org.shipkit:shipkit-auto-version:1.+"
+        classpath "org.shipkit:shipkit-changelog:1.2.0"
+        classpath "org.shipkit:shipkit-auto-version:1.2.2"
+        classpath "io.github.gradle-nexus:publish-plugin:1.0.0"
     }
 }
 
-plugins {
-    id "io.github.gradle-nexus.publish-plugin" version "1.0.0"
-}
-
-apply plugin: "org.shipkit.shipkit-auto-version"
+apply plugin: "io.github.gradle-nexus.publish-plugin"
+apply plugin: 'org.shipkit.shipkit-auto-version'
 apply plugin: "org.shipkit.shipkit-changelog"
 apply plugin: "org.shipkit.shipkit-github-release"
 
@@ -22,7 +20,7 @@ allprojects {
 }
 
 tasks.named("generateChangelog") {
-    previousRevision = project.ext.'shipkit-auto-version.previous-tag'
+    previousRevision = project.ext.'shipkit-auto-version.previous-version'
     githubToken = System.getenv("GITHUB_TOKEN")
     repository = "mockito/mockito-kotlin"
     releaseTag = project.version
@@ -42,7 +40,8 @@ tasks.named("githubRelease") {
 nexusPublishing {
     repositories {
         if (System.getenv("NEXUS_TOKEN_PWD")) {
-            sonatype { // Publishing to: https://s01.oss.sonatype.org (faster instance)
+            sonatype {
+                // Publishing to: https://s01.oss.sonatype.org (faster instance)
                 nexusUrl = uri("https://s01.oss.sonatype.org/service/local/")
                 snapshotRepositoryUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
 
@@ -52,3 +51,32 @@ nexusPublishing {
         }
     }
 }
+
+def isSnapshot = version.endsWith("-SNAPSHOT")
+
+if (isSnapshot) {
+    println "Building a -SNAPSHOT version (Github release and Maven Central tasks are skipped)"
+    tasks.named("githubRelease") {
+        //snapshot versions do not produce changelog / Github releases
+        enabled = false
+    }
+    tasks.named("closeAndReleaseStagingRepository") {
+        //snapshot binaries are available in Sonatype without the need to close the staging repo
+        enabled = false
+    }
+}
+
+tasks.register("releaseSummary") {
+    doLast {
+        if (isSnapshot) {
+            println "RELEASE SUMMARY\n" +
+                    "  SNAPSHOTS released to: https://s01.oss.sonatype.org/content/repositories/snapshots/org/mockito/kotlin/mockito-kotlin\n" +
+                    "  Release to Maven Central: SKIPPED FOR SNAPSHOTS\n" +
+                    "  Github releases: SKIPPED FOR SNAPSHOTS"
+        } else {
+            println "RELEASE SUMMARY\n" +
+                    "  Release to Maven Central (available after delay): https://repo1.maven.org/maven2/org/mockito/kotlin/mockito-kotlin/\n" +
+                    "  Github releases: https://github.com/mockito/mockito-kotlin/releases"
+        }
+    }
+}
diff --git a/gradle/publishing.gradle b/gradle/publishing.gradle
index 6bb5f1a..177c973 100644
--- a/gradle/publishing.gradle
+++ b/gradle/publishing.gradle
@@ -1,3 +1,4 @@
+//Maven publication plugins & configuration
 apply plugin: 'maven-publish'
 
 task javadocJar(type: Jar, dependsOn: javadoc) {
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 28ff446..ec991f9 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -1,5 +1,5 @@
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-6.8.1-bin.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-6.9.2-bin.zip
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
diff --git a/mockito-kotlin/build.gradle b/mockito-kotlin/build.gradle
index 6c726db..30c3aea 100644
--- a/mockito-kotlin/build.gradle
+++ b/mockito-kotlin/build.gradle
@@ -3,11 +3,10 @@ apply from: '../gradle/publishing.gradle'
 apply plugin: 'org.jetbrains.dokka'
 
 buildscript {
-    ext.kotlin_version = "1.3.50"
+    ext.kotlin_version = "1.4.20"
 
     repositories {
         mavenCentral()
-        jcenter()
     }
 
     dependencies {
@@ -18,20 +17,20 @@ buildscript {
 
 repositories {
     mavenCentral()
-    jcenter()
 }
 
 dependencies {
     compileOnly "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
     compileOnly 'org.jetbrains.kotlinx:kotlinx-coroutines-core:1.0.0'
 
-    compile "org.mockito:mockito-core:2.23.0"
+    compile "org.mockito:mockito-core:4.5.1"
 
-    testCompile 'junit:junit:4.12'
-    testCompile 'com.nhaarman:expect.kt:1.0.0'
+    testCompile 'junit:junit:4.13.2'
+    testCompile 'com.nhaarman:expect.kt:1.0.1'
 
     testCompile  "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
-    testCompile 'org.jetbrains.kotlinx:kotlinx-coroutines-core:1.0.0'
+    testCompile  "org.jetbrains.kotlin:kotlin-test:$kotlin_version"
+    testCompile 'org.jetbrains.kotlinx:kotlinx-coroutines-core:1.3.0'
 
     testImplementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.0.0"
 }
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/BDDMockito.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/BDDMockito.kt
index 867f4c1..9363b1e 100644
--- a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/BDDMockito.kt
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/BDDMockito.kt
@@ -28,7 +28,9 @@ package org.mockito.kotlin
 import org.mockito.BDDMockito
 import org.mockito.BDDMockito.BDDMyOngoingStubbing
 import org.mockito.invocation.InvocationOnMock
+import org.mockito.kotlin.internal.SuspendableAnswer
 import org.mockito.stubbing.Answer
+import kotlin.reflect.KClass
 
 /**
  * Alias for [BDDMockito.given].
@@ -65,6 +67,13 @@ infix fun <T> BDDMyOngoingStubbing<T>.willAnswer(value: (InvocationOnMock) -> T?
     return willAnswer { value(it) }
 }
 
+/**
+ * Alias for [BBDMyOngoingStubbing.willAnswer], accepting a suspend lambda.
+ */
+infix fun <T> BDDMyOngoingStubbing<T>.willSuspendableAnswer(value: suspend (InvocationOnMock) -> T?): BDDMockito.BDDMyOngoingStubbing<T> {
+    return willAnswer(SuspendableAnswer(value))
+}
+
 /**
  * Alias for [BBDMyOngoingStubbing.willReturn].
  */
@@ -79,3 +88,34 @@ infix fun <T> BDDMyOngoingStubbing<T>.willThrow(value: () -> Throwable): BDDMock
     return willThrow(value())
 }
 
+/**
+ * Sets a Throwable type to be thrown when the method is called.
+ *
+ * Alias for [BDDMyOngoingStubbing.willThrow]
+ */
+infix fun <T> BDDMyOngoingStubbing<T>.willThrow(t: KClass<out Throwable>): BDDMyOngoingStubbing<T> {
+    return willThrow(t.java)
+}
+
+/**
+ * Sets Throwable classes to be thrown when the method is called.
+ *
+ * Alias for [BDDMyOngoingStubbing.willThrow]
+ */
+fun <T> BDDMyOngoingStubbing<T>.willThrow(
+    t: KClass<out Throwable>,
+    vararg ts: KClass<out Throwable>
+): BDDMyOngoingStubbing<T> {
+    return willThrow(t.java, *ts.map { it.java }.toTypedArray())
+}
+
+/**
+ * Sets consecutive return values to be returned when the method is called.
+ * Same as [BDDMyOngoingStubbing.willReturn], but accepts list instead of varargs.
+ */
+inline infix fun <reified T> BDDMyOngoingStubbing<T>.willReturnConsecutively(ts: List<T>): BDDMyOngoingStubbing<T> {
+    return willReturn(
+          ts[0],
+          *ts.drop(1).toTypedArray()
+    )
+}
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/KInOrder.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/KInOrder.kt
new file mode 100644
index 0000000..152148e
--- /dev/null
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/KInOrder.kt
@@ -0,0 +1,47 @@
+/*
+ * The MIT License
+ *
+ * Copyright (c) 2018 Niek Haarman
+ * Copyright (c) 2007 Mockito contributors
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a copy
+ * of this software and associated documentation files (the "Software"), to deal
+ * in the Software without restriction, including without limitation the rights
+ * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
+ * copies of the Software, and to permit persons to whom the Software is
+ * furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+ * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+ * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
+ * THE SOFTWARE.
+ */
+
+package org.mockito.kotlin
+
+import org.mockito.InOrder
+import org.mockito.verification.VerificationMode
+
+interface KInOrder: InOrder {
+    /**
+     * Verifies certain suspending behavior <b>happened once</b> in order.
+     *
+     * Warning: Only one method call can be verified in the function.
+     * Subsequent method calls are ignored!
+     */
+    fun <T> verifyBlocking(mock: T, f: suspend T.() -> Unit)
+
+    /**
+     * Verifies certain suspending behavior happened at least once / exact number of times / never in order.
+     *
+     * Warning: Only one method call can be verified in the function.
+     * Subsequent method calls are ignored!
+     */
+    fun <T> verifyBlocking(mock: T, mode: VerificationMode, f: suspend T.() -> Unit)
+}
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/LenientStubber.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/LenientStubber.kt
new file mode 100644
index 0000000..1a9236b
--- /dev/null
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/LenientStubber.kt
@@ -0,0 +1,38 @@
+/*
+ * The MIT License
+ *
+ * Copyright (c) 2018 Niek Haarman
+ * Copyright (c) 2007 Mockito contributors
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a copy
+ * of this software and associated documentation files (the "Software"), to deal
+ * in the Software without restriction, including without limitation the rights
+ * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
+ * copies of the Software, and to permit persons to whom the Software is
+ * furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+ * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+ * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
+ * THE SOFTWARE.
+ */
+
+package org.mockito.kotlin
+
+import org.mockito.stubbing.LenientStubber
+import org.mockito.stubbing.OngoingStubbing
+
+inline fun <reified T : Any> LenientStubber.whenever(methodCall: T): OngoingStubbing<T> {
+    return `when`(methodCall)
+}
+
+inline fun <reified T : Any> LenientStubber.whenever(methodCall: () -> T): OngoingStubbing<T> {
+    return whenever(methodCall())
+}
+
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Matchers.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Matchers.kt
index a17da95..631c551 100644
--- a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Matchers.kt
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Matchers.kt
@@ -27,36 +27,36 @@ package org.mockito.kotlin
 
 import org.mockito.kotlin.internal.createInstance
 import org.mockito.ArgumentMatcher
-import org.mockito.Mockito
+import org.mockito.ArgumentMatchers
 
 /** Object argument that is equal to the given value. */
 fun <T> eq(value: T): T {
-    return Mockito.eq(value) ?: value
+    return ArgumentMatchers.eq(value) ?: value
 }
 
 /**  Object argument that is the same as the given value. */
 fun <T> same(value: T): T {
-    return Mockito.same(value) ?: value
+    return ArgumentMatchers.same(value) ?: value
 }
 
 /** Matches any object, excluding nulls. */
 inline fun <reified T : Any> any(): T {
-    return Mockito.any(T::class.java) ?: createInstance()
+    return ArgumentMatchers.any(T::class.java) ?: createInstance()
 }
 
 /** Matches anything, including nulls. */
 inline fun <reified T : Any> anyOrNull(): T {
-    return Mockito.any<T>() ?: createInstance()
+    return ArgumentMatchers.any<T>() ?: createInstance()
 }
 
 /** Matches any vararg object, including nulls. */
 inline fun <reified T : Any> anyVararg(): T {
-    return Mockito.any<T>() ?: createInstance()
+    return ArgumentMatchers.any<T>() ?: createInstance()
 }
 
 /** Matches any array of type T. */
 inline fun <reified T : Any?> anyArray(): Array<T> {
-    return Mockito.any(Array<T>::class.java) ?: arrayOf()
+    return ArgumentMatchers.any(Array<T>::class.java) ?: arrayOf()
 }
 
 /**
@@ -66,7 +66,7 @@ inline fun <reified T : Any?> anyArray(): Array<T> {
  * @param predicate An extension function on [T] that returns `true` when a [T] matches the predicate.
  */
 inline fun <reified T : Any> argThat(noinline predicate: T.() -> Boolean): T {
-    return Mockito.argThat { arg: T? -> arg?.predicate() ?: false } ?: createInstance(
+    return ArgumentMatchers.argThat { arg: T? -> arg?.predicate() ?: false } ?: createInstance(
           T::class
     )
 }
@@ -78,7 +78,7 @@ inline fun <reified T : Any> argThat(noinline predicate: T.() -> Boolean): T {
  * @param matcher The ArgumentMatcher on [T] to be registered.
  */
 inline fun <reified T : Any> argThat(matcher: ArgumentMatcher<T>): T {
-    return Mockito.argThat(matcher) ?: createInstance()
+    return ArgumentMatchers.argThat(matcher) ?: createInstance()
 }
 
 /**
@@ -107,26 +107,26 @@ inline fun <reified T : Any> argWhere(noinline predicate: (T) -> Boolean): T {
  * Argument that implements the given class.
  */
 inline fun <reified T : Any> isA(): T {
-    return Mockito.isA(T::class.java) ?: createInstance()
+    return ArgumentMatchers.isA(T::class.java) ?: createInstance()
 }
 
 /**
  * `null` argument.
  */
-fun <T : Any> isNull(): T? = Mockito.isNull()
+fun <T : Any> isNull(): T? = ArgumentMatchers.isNull()
 
 /**
  * Not `null` argument.
  */
 fun <T : Any> isNotNull(): T? {
-    return Mockito.isNotNull()
+    return ArgumentMatchers.isNotNull()
 }
 
 /**
  * Not `null` argument.
  */
 fun <T : Any> notNull(): T? {
-    return Mockito.notNull()
+    return ArgumentMatchers.notNull()
 }
 
 /**
@@ -134,6 +134,6 @@ fun <T : Any> notNull(): T? {
  * selected fields from a class.
  */
 inline fun <reified T : Any> refEq(value: T, vararg excludeFields: String): T {
-    return Mockito.refEq<T>(value, *excludeFields) ?: createInstance()
+    return ArgumentMatchers.refEq<T>(value, *excludeFields) ?: createInstance()
 }
 
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/OngoingStubbing.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/OngoingStubbing.kt
index 3d97ce1..d259a8f 100644
--- a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/OngoingStubbing.kt
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/OngoingStubbing.kt
@@ -27,9 +27,9 @@ package org.mockito.kotlin
 
 import org.mockito.Mockito
 import org.mockito.invocation.InvocationOnMock
+import org.mockito.kotlin.internal.SuspendableAnswer
 import org.mockito.stubbing.Answer
 import org.mockito.stubbing.OngoingStubbing
-import kotlin.DeprecationLevel.ERROR
 import kotlin.reflect.KClass
 
 
@@ -124,3 +124,7 @@ infix fun <T> OngoingStubbing<T>.doAnswer(answer: Answer<*>): OngoingStubbing<T>
 infix fun <T> OngoingStubbing<T>.doAnswer(answer: (InvocationOnMock) -> T?): OngoingStubbing<T> {
     return thenAnswer(answer)
 }
+
+infix fun <T> OngoingStubbing<T>.doSuspendableAnswer(answer: suspend (InvocationOnMock) -> T?): OngoingStubbing<T> {
+    return thenAnswer(SuspendableAnswer(answer))
+}
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Verification.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Verification.kt
index e79dd92..04a477c 100644
--- a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Verification.kt
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/Verification.kt
@@ -29,6 +29,7 @@ import org.mockito.kotlin.internal.createInstance
 import kotlinx.coroutines.runBlocking
 import org.mockito.InOrder
 import org.mockito.Mockito
+import org.mockito.kotlin.internal.KInOrderDecorator
 import org.mockito.verification.VerificationAfterDelay
 import org.mockito.verification.VerificationMode
 import org.mockito.verification.VerificationWithTimeout
@@ -84,10 +85,10 @@ fun <T> verifyNoMoreInteractions(vararg mocks: T) {
 /**
  * Verifies that no interactions happened on given mocks beyond the previously verified interactions.
  *
- * Alias for [Mockito.verifyZeroInteractions].
+ * Alias for [Mockito.verifyNoInteractions].
  */
-fun verifyZeroInteractions(vararg mocks: Any) {
-    Mockito.verifyZeroInteractions(*mocks)
+fun verifyNoInteractions(vararg mocks: Any) {
+    Mockito.verifyNoInteractions(*mocks)
 }
 
 /**
@@ -188,32 +189,33 @@ fun ignoreStubs(vararg mocks: Any): Array<out Any> {
 }
 
 /**
- * Creates [InOrder] object that allows verifying mocks in order.
+ * Creates [KInOrder] object that allows verifying mocks in order.
  *
- * Alias for [Mockito.inOrder].
+ * Wrapper for [Mockito.inOrder] that also allows to verify suspending method calls.
  */
-fun inOrder(vararg mocks: Any): InOrder {
-    return Mockito.inOrder(*mocks)!!
+fun inOrder(vararg mocks: Any): KInOrder {
+    return KInOrderDecorator(Mockito.inOrder(*mocks)!!)
 }
 
 /**
- * Creates [InOrder] object that allows verifying mocks in order.
+ * Creates [KInOrder] object that allows verifying mocks in order.
  * Accepts a lambda to allow easy evaluation.
  *
- * Alias for [Mockito.inOrder].
+ * Wrapper for [Mockito.inOrder] that also allows to verify suspending method calls.
  */
 inline fun inOrder(
     vararg mocks: Any,
-    evaluation: InOrder.() -> Unit
+    evaluation: KInOrder.() -> Unit
 ) {
-    Mockito.inOrder(*mocks).evaluation()
+    KInOrderDecorator(Mockito.inOrder(*mocks)).evaluation()
 }
 
 /**
- * Allows [InOrder] verification for a single mocked instance:
+ * Allows [KInOrder] verification for a single mocked instance:
  *
  * mock.inOrder {
  *    verify().foo()
+ *    verifyBlocking { bar() }
  * }
  *
  */
@@ -221,9 +223,33 @@ inline fun <T> T.inOrder(block: InOrderOnType<T>.() -> Any) {
     block.invoke(InOrderOnType(this))
 }
 
-class InOrderOnType<T>(private val t: T) : InOrder by inOrder(t as Any) {
+class InOrderOnType<T>(private val t: T) : KInOrder by inOrder(t as Any) {
 
+    /**
+     * Verifies certain behavior <b>happened once</b> in order.
+     */
     fun verify(): T = verify(t)
+
+    /**
+     * Verifies certain behavior happened at least once / exact number of times / never in order.
+     */
+    fun verify(mode: VerificationMode): T = verify(t, mode)
+
+    /**
+     * Verifies certain suspending behavior <b>happened once</b> in order.
+     *
+     * Warning: Only one method call can be verified in the function.
+     * Subsequent method calls are ignored!
+     */
+    fun verifyBlocking(f: suspend T.() -> Unit) = verifyBlocking(t, f)
+
+    /**
+     * Verifies certain suspending behavior happened at least once / exact number of times / never in order.
+     *
+     * Warning: Only one method call can be verified in the function.
+     * Subsequent method calls are ignored!
+     */
+    fun verifyBlocking(mode: VerificationMode, f: suspend T.() -> Unit) = verifyBlocking(t, mode, f)
 }
 
 /**
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/internal/KInOrderDecorator.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/internal/KInOrderDecorator.kt
new file mode 100644
index 0000000..6f591f4
--- /dev/null
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/internal/KInOrderDecorator.kt
@@ -0,0 +1,43 @@
+/*
+ * The MIT License
+ *
+ * Copyright (c) 2018 Niek Haarman
+ * Copyright (c) 2007 Mockito contributors
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a copy
+ * of this software and associated documentation files (the "Software"), to deal
+ * in the Software without restriction, including without limitation the rights
+ * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
+ * copies of the Software, and to permit persons to whom the Software is
+ * furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+ * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+ * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
+ * THE SOFTWARE.
+ */
+
+package org.mockito.kotlin.internal
+
+import kotlinx.coroutines.runBlocking
+import org.mockito.InOrder
+import org.mockito.kotlin.KInOrder
+import org.mockito.verification.VerificationMode
+
+class KInOrderDecorator(private val inOrder: InOrder) : KInOrder, InOrder by inOrder {
+    override fun <T> verifyBlocking(mock: T, f: suspend T.() -> Unit) {
+        val m = verify(mock)
+        runBlocking { m.f() }
+    }
+
+    override fun <T> verifyBlocking(mock: T, mode: VerificationMode, f: suspend T.() -> Unit) {
+        val m = verify(mock, mode)
+        runBlocking { m.f() }
+    }
+}
diff --git a/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/internal/SuspendableAnswer.kt b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/internal/SuspendableAnswer.kt
new file mode 100644
index 0000000..3544cf6
--- /dev/null
+++ b/mockito-kotlin/src/main/kotlin/org/mockito/kotlin/internal/SuspendableAnswer.kt
@@ -0,0 +1,50 @@
+/*
+ * The MIT License
+ *
+ * Copyright (c) 2018 Niek Haarman
+ * Copyright (c) 2007 Mockito contributors
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a copy
+ * of this software and associated documentation files (the "Software"), to deal
+ * in the Software without restriction, including without limitation the rights
+ * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
+ * copies of the Software, and to permit persons to whom the Software is
+ * furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+ * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+ * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
+ * THE SOFTWARE.
+ */
+
+package org.mockito.kotlin.internal
+
+import org.mockito.internal.invocation.InterceptedInvocation
+import org.mockito.invocation.InvocationOnMock
+import org.mockito.stubbing.Answer
+import kotlin.coroutines.Continuation
+import kotlin.coroutines.intrinsics.startCoroutineUninterceptedOrReturn
+
+/**
+ * This class properly wraps suspendable lambda into [Answer]
+ */
+@Suppress("UNCHECKED_CAST")
+internal class SuspendableAnswer<T>(
+    private val body: suspend (InvocationOnMock) -> T?
+) : Answer<T> {
+    override fun answer(invocation: InvocationOnMock?): T {
+        //all suspend functions/lambdas has Continuation as the last argument.
+        //InvocationOnMock does not see last argument
+        val rawInvocation = invocation as InterceptedInvocation
+        val continuation = rawInvocation.rawArguments.last() as Continuation<T?>
+
+        // https://youtrack.jetbrains.com/issue/KT-33766#focus=Comments-27-3707299.0-0
+        return body.startCoroutineUninterceptedOrReturn(invocation, continuation) as T
+    }
+}
diff --git a/mockito-kotlin/src/test/kotlin/org/mockito/kotlin/BDDMockitoKtTest.kt b/mockito-kotlin/src/test/kotlin/org/mockito/kotlin/BDDMockitoKtTest.kt
new file mode 100644
index 0000000..0686efe
--- /dev/null
+++ b/mockito-kotlin/src/test/kotlin/org/mockito/kotlin/BDDMockitoKtTest.kt
@@ -0,0 +1,79 @@
+package org.mockito.kotlin
+
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertEquals
+import org.junit.Test
+import kotlin.test.assertFailsWith
+
+class BDDMockitoKtTest {
+
+    @Test
+    fun willSuspendableAnswer_withoutArgument() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        given(fixture.suspending()).willSuspendableAnswer {
+            withContext(Dispatchers.Default) { 42 }
+        }
+
+        assertEquals(42, fixture.suspending())
+        then(fixture).should().suspending()
+        Unit
+    }
+
+    @Test
+    fun willSuspendableAnswer_witArgument() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        given(fixture.suspendingWithArg(any())).willSuspendableAnswer {
+            withContext(Dispatchers.Default) { it.getArgument<Int>(0) }
+        }
+
+        assertEquals(42, fixture.suspendingWithArg(42))
+        then(fixture).should().suspendingWithArg(42)
+        Unit
+    }
+
+    @Test
+    fun willThrow_kclass_single() {
+        val fixture: SomeInterface = mock()
+
+        given(fixture.foo()).willThrow(RuntimeException::class)
+
+        assertFailsWith(RuntimeException::class) {
+            fixture.foo()
+        }
+    }
+
+    @Test
+    fun willThrow_kclass_multiple() {
+        val fixture: SomeInterface = mock()
+
+        given(fixture.foo()).willThrow(RuntimeException::class, IllegalArgumentException::class)
+
+        assertFailsWith(RuntimeException::class) {
+            fixture.foo()
+        }
+        assertFailsWith(IllegalArgumentException::class) {
+            fixture.foo()
+        }
+    }
+
+    @Test
+    fun willReturnConsecutively() {
+        val fixture: SomeInterface = mock()
+
+        given(fixture.foo()).willReturnConsecutively(listOf(42, 24))
+
+        assertEquals(42, fixture.foo())
+        assertEquals(24, fixture.foo())
+    }
+}
+
+interface SomeInterface {
+    fun foo(): Int
+
+    suspend fun suspending(): Int
+    suspend fun suspendingWithArg(arg: Int): Int
+}
diff --git a/mockito-kotlin/src/test/kotlin/test/CoroutinesTest.kt b/mockito-kotlin/src/test/kotlin/test/CoroutinesTest.kt
index 5ca6eb6..c43d426 100644
--- a/mockito-kotlin/src/test/kotlin/test/CoroutinesTest.kt
+++ b/mockito-kotlin/src/test/kotlin/test/CoroutinesTest.kt
@@ -7,8 +7,14 @@ import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.withContext
+import kotlinx.coroutines.*
+import kotlinx.coroutines.channels.actor
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertThrows
 import org.junit.Test
+import org.mockito.InOrder
 import org.mockito.kotlin.*
+import java.util.*
 
 
 class CoroutinesTest {
@@ -157,11 +163,234 @@ class CoroutinesTest {
             verify(testSubject).suspending()
         }
     }
+
+    @Test
+    fun answerWithSuspendFunction() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        whenever(fixture.suspendingWithArg(any())).doSuspendableAnswer {
+            withContext(Dispatchers.Default) { it.getArgument<Int>(0) }
+        }
+
+        assertEquals(5, fixture.suspendingWithArg(5))
+    }
+
+    @Test
+    fun inplaceAnswerWithSuspendFunction() = runBlocking {
+        val fixture: SomeInterface = mock {
+            onBlocking { suspendingWithArg(any()) } doSuspendableAnswer {
+                withContext(Dispatchers.Default) { it.getArgument<Int>(0) }
+            }
+        }
+
+        assertEquals(5, fixture.suspendingWithArg(5))
+    }
+
+    @Test
+    fun callFromSuspendFunction() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        whenever(fixture.suspendingWithArg(any())).doSuspendableAnswer {
+            withContext(Dispatchers.Default) { it.getArgument<Int>(0) }
+        }
+
+        val result = async {
+            val answer = fixture.suspendingWithArg(5)
+
+            Result.success(answer)
+        }
+
+        assertEquals(5, result.await().getOrThrow())
+    }
+
+    @Test
+    fun callFromActor() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        whenever(fixture.suspendingWithArg(any())).doSuspendableAnswer {
+            withContext(Dispatchers.Default) { it.getArgument<Int>(0) }
+        }
+
+        val actor = actor<Optional<Int>> {
+            for (element in channel) {
+                fixture.suspendingWithArg(element.get())
+            }
+        }
+
+        actor.send(Optional.of(10))
+        actor.close()
+
+        verify(fixture).suspendingWithArg(10)
+
+        Unit
+    }
+
+    @Test
+    fun answerWithSuspendFunctionWithoutArgs() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        whenever(fixture.suspending()).doSuspendableAnswer {
+            withContext(Dispatchers.Default) { 42 }
+        }
+
+        assertEquals(42, fixture.suspending())
+    }
+
+    @Test
+    fun willAnswerWithControlledSuspend() = runBlocking {
+        val fixture: SomeInterface = mock()
+
+        val job = Job()
+
+        whenever(fixture.suspending()).doSuspendableAnswer {
+            job.join()
+            5
+        }
+
+        val asyncTask = async {
+            fixture.suspending()
+        }
+
+        job.complete()
+
+        withTimeout(100) {
+            assertEquals(5, asyncTask.await())
+        }
+    }
+
+    @Test
+    fun inOrderRemainsCompatible() {
+        /* Given */
+        val fixture: SomeInterface = mock()
+
+        /* When */
+        val inOrder = inOrder(fixture)
+
+        /* Then */
+        expect(inOrder).toBeInstanceOf<InOrder>()
+    }
+
+    @Test
+    fun inOrderSuspendingCalls() {
+        /* Given */
+        val fixtureOne: SomeInterface = mock()
+        val fixtureTwo: SomeInterface = mock()
+
+        /* When */
+        runBlocking {
+            fixtureOne.suspending()
+            fixtureTwo.suspending()
+        }
+
+        /* Then */
+        val inOrder = inOrder(fixtureOne, fixtureTwo)
+        inOrder.verifyBlocking(fixtureOne) { suspending() }
+        inOrder.verifyBlocking(fixtureTwo) { suspending() }
+    }
+
+    @Test
+    fun inOrderSuspendingCallsFailure() {
+        /* Given */
+        val fixtureOne: SomeInterface = mock()
+        val fixtureTwo: SomeInterface = mock()
+
+        /* When */
+        runBlocking {
+            fixtureOne.suspending()
+            fixtureTwo.suspending()
+        }
+
+        /* Then */
+        val inOrder = inOrder(fixtureOne, fixtureTwo)
+        inOrder.verifyBlocking(fixtureTwo) { suspending() }
+        assertThrows(AssertionError::class.java) {
+            inOrder.verifyBlocking(fixtureOne) { suspending() }
+        }
+    }
+
+    @Test
+    fun inOrderBlockSuspendingCalls() {
+        /* Given */
+        val fixtureOne: SomeInterface = mock()
+        val fixtureTwo: SomeInterface = mock()
+
+        /* When */
+        runBlocking {
+            fixtureOne.suspending()
+            fixtureTwo.suspending()
+        }
+
+        /* Then */
+        inOrder(fixtureOne, fixtureTwo) {
+            verifyBlocking(fixtureOne) { suspending() }
+            verifyBlocking(fixtureTwo) { suspending() }
+        }
+    }
+
+    @Test
+    fun inOrderBlockSuspendingCallsFailure() {
+        /* Given */
+        val fixtureOne: SomeInterface = mock()
+        val fixtureTwo: SomeInterface = mock()
+
+        /* When */
+        runBlocking {
+            fixtureOne.suspending()
+            fixtureTwo.suspending()
+        }
+
+        /* Then */
+        inOrder(fixtureOne, fixtureTwo) {
+            verifyBlocking(fixtureTwo) { suspending() }
+            assertThrows(AssertionError::class.java) {
+                verifyBlocking(fixtureOne) { suspending() }
+            }
+        }
+    }
+
+    @Test
+    fun inOrderOnObjectSuspendingCalls() {
+        /* Given */
+        val fixture: SomeInterface = mock()
+
+        /* When */
+        runBlocking {
+            fixture.suspendingWithArg(1)
+            fixture.suspendingWithArg(2)
+        }
+
+        /* Then */
+        fixture.inOrder {
+            verifyBlocking { suspendingWithArg(1) }
+            verifyBlocking { suspendingWithArg(2) }
+        }
+    }
+
+    @Test
+    fun inOrderOnObjectSuspendingCallsFailure() {
+        /* Given */
+        val fixture: SomeInterface = mock()
+
+        /* When */
+        runBlocking {
+            fixture.suspendingWithArg(1)
+            fixture.suspendingWithArg(2)
+        }
+
+        /* Then */
+        fixture.inOrder {
+            verifyBlocking { suspendingWithArg(2) }
+            assertThrows(AssertionError::class.java) {
+                verifyBlocking { suspendingWithArg(1) }
+            }
+        }
+    }
 }
 
 interface SomeInterface {
 
     suspend fun suspending(): Int
+    suspend fun suspendingWithArg(arg: Int): Int
     fun nonsuspending(): Int
 }
 
diff --git a/tests/build.gradle b/tests/build.gradle
index 24ab716..66dcabb 100644
--- a/tests/build.gradle
+++ b/tests/build.gradle
@@ -1,5 +1,5 @@
 buildscript {
-    ext.kotlin_version = System.getenv("KOTLIN_VERSION") ?: '1.3.50'
+    ext.kotlin_version = System.getenv("KOTLIN_VERSION") ?: '1.4.20'
     println "$project uses Kotlin $kotlin_version"
 
     repositories {
@@ -15,15 +15,14 @@ apply plugin: 'kotlin'
 
 repositories {
     mavenCentral()
-    jcenter()
 }
 
 dependencies {
     compile files("${rootProject.projectDir}/mockito-kotlin/build/libs/mockito-kotlin-${version}.jar")
 
     compile "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
-    compile "org.mockito:mockito-core:2.23.0"
+    compile "org.mockito:mockito-core:4.5.1"
 
-    testCompile "junit:junit:4.12"
-    testCompile "com.nhaarman:expect.kt:1.0.0"
+    testCompile 'junit:junit:4.13.2'
+    testCompile "com.nhaarman:expect.kt:1.0.1"
 }
\ No newline at end of file
diff --git a/tests/src/test/kotlin/test/LenientStubberTest.kt b/tests/src/test/kotlin/test/LenientStubberTest.kt
new file mode 100644
index 0000000..d3e67fe
--- /dev/null
+++ b/tests/src/test/kotlin/test/LenientStubberTest.kt
@@ -0,0 +1,37 @@
+package test
+
+import org.junit.Assert
+import org.junit.Rule
+import org.junit.Test
+import org.mockito.Mockito.lenient
+import org.mockito.junit.MockitoJUnit
+import org.mockito.junit.MockitoRule
+import org.mockito.kotlin.any
+import org.mockito.kotlin.doReturn
+import org.mockito.kotlin.mock
+import org.mockito.kotlin.whenever
+import org.mockito.quality.Strictness
+
+
+open class LenientStubberTest {
+    @get:Rule
+    val rule: MockitoRule = MockitoJUnit.rule().strictness(Strictness.STRICT_STUBS)
+
+    @Test
+    fun unused_and_lenient_stubbings() {
+        val mock = mock<MutableList<String>>()
+        lenient().whenever(mock.add("one")).doReturn(true)
+        whenever(mock[any()]).doReturn("hello")
+
+        Assert.assertEquals("List should contain hello", "hello", mock[1])
+    }
+
+    @Test
+    fun unused_and_lenient_stubbings_with_unit() {
+        val mock = mock<MutableList<String>>()
+        lenient().whenever { mock.add("one") }.doReturn(true)
+        whenever(mock[any()]).doReturn("hello")
+
+        Assert.assertEquals("List should contain hello", "hello", mock[1])
+    }
+}
diff --git a/tests/src/test/kotlin/test/MockingTest.kt b/tests/src/test/kotlin/test/MockingTest.kt
index 43e6413..f0f9f64 100644
--- a/tests/src/test/kotlin/test/MockingTest.kt
+++ b/tests/src/test/kotlin/test/MockingTest.kt
@@ -12,6 +12,8 @@ import org.mockito.kotlin.whenever
 import org.junit.Test
 import org.mockito.Mockito
 import org.mockito.exceptions.verification.WantedButNotInvoked
+import org.mockito.invocation.DescribedInvocation
+import org.mockito.kotlin.argumentCaptor
 import org.mockito.listeners.InvocationListener
 import org.mockito.mock.SerializableMode.BASIC
 import java.io.PrintStream
@@ -182,7 +184,10 @@ class MockingTest : TestBase() {
             fail("Expected an exception")
         } catch (e: WantedButNotInvoked) {
             /* Then */
-            verify(out).println("methods.stringResult();")
+            argumentCaptor<DescribedInvocation>().apply {
+                verify(out).println(capture())
+                expect(lastValue.toString()).toBe("methods.stringResult();")
+            }
         }
     }
 
@@ -314,7 +319,10 @@ class MockingTest : TestBase() {
             fail("Expected an exception")
         } catch (e: WantedButNotInvoked) {
             /* Then */
-            verify(out).println("methods.stringResult();")
+            argumentCaptor<DescribedInvocation>().apply {
+                verify(out).println(capture())
+                expect(lastValue.toString()).toBe("methods.stringResult();")
+            }
         }
     }
 
diff --git a/tests/src/test/kotlin/test/VerifyTest.kt b/tests/src/test/kotlin/test/VerifyTest.kt
index 0a93832..1af73fd 100644
--- a/tests/src/test/kotlin/test/VerifyTest.kt
+++ b/tests/src/test/kotlin/test/VerifyTest.kt
@@ -4,7 +4,7 @@ import org.mockito.kotlin.any
 import org.mockito.kotlin.mock
 import org.mockito.kotlin.verify
 import org.junit.Test
-import org.mockito.exceptions.verification.TooLittleActualInvocations
+import org.mockito.exceptions.verification.TooFewActualInvocations
 import org.mockito.exceptions.verification.junit.ArgumentsAreDifferent
 
 class VerifyTest : TestBase() {
@@ -30,7 +30,7 @@ class VerifyTest : TestBase() {
         }
     }
 
-    @Test(expected = TooLittleActualInvocations::class)
+    @Test(expected = TooFewActualInvocations::class)
     fun verifyFailsWithWrongCount() {
         val iface = mock<TestInterface>()
 
diff --git a/update_source.sh b/update_source.sh
deleted file mode 100644
index 52848d2..0000000
--- a/update_source.sh
+++ /dev/null
@@ -1,53 +0,0 @@
-#!/bin/bash
-#
-# Copyright 2023 The Android Open Source Project.
-#
-# Retrieves the current mockito-kotlin source code into the current directory
-
-# Force stop on first error.
-set -e
-
-if [ $# -ne 1 ]; then
-    echo "$0 <version>" >&2
-    exit 1;
-fi
-
-if [ -z "$ANDROID_BUILD_TOP" ]; then
-    echo "Missing environment variables. Did you run build/envsetup.sh and lunch?" >&2
-    exit 1
-fi
-
-VERSION=${1}
-
-SOURCE="git://github.com/mockito/mockito-kotlin.git"
-INCLUDE="
-    LICENSE
-    mockito-kotlin/src/main
-    "
-
-working_dir="$(mktemp -d)"
-trap "echo \"Removing temporary directory\"; rm -rf $working_dir" EXIT
-
-echo "Fetching mockito-kotlin source into $working_dir"
-git clone $SOURCE $working_dir/source
-(cd $working_dir/source; git checkout $VERSION)
-
-for include in ${INCLUDE}; do
-  echo "Updating $include"
-  rm -rf $include
-  mkdir -p $(dirname $include)
-  cp -R $working_dir/source/$include $include
-done;
-
-echo "Done"
-
-# Update the version.
-perl -pi -e "s|^Version: .*$|Version: ${VERSION}|" "README.version"
-
-# Remove any documentation about local modifications.
-mv README.version README.tmp
-grep -B 100 "Local Modifications" README.tmp > README.version
-echo "        None" >> README.version
-rm README.tmp
-
-echo "Done"
diff --git a/version.properties b/version.properties
index 708e7ad..34fe97c 100644
--- a/version.properties
+++ b/version.properties
@@ -1,4 +1 @@
-# Version of the produced binaries.
-# The version is inferred by shipkit-auto-version Gradle plugin (https://github.com/shipkit/shipkit-auto-version)
-version=2.2.*
-tagPrefix=
\ No newline at end of file
+tagPrefix=
```

