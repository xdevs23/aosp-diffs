```diff
diff --git a/CHANGES.md b/CHANGES.md
index 1303cb4..1aca540 100644
--- a/CHANGES.md
+++ b/CHANGES.md
@@ -1,5 +1,61 @@
 # Change log for kotlinx.atomicfu
 
+# Version 0.23.1
+
+* Updated Kotlin to 1.9.21 (#361).
+* Update to Kotlin 1.9.21 fixes regression with klib incompatibility (#365).
+
+# Version 0.23.0
+
+* Updated Kotlin to 1.9.20 (#361).
+* Updated Gradle version to 8.3.
+* Supported transformations for Native targets 🎉 (#363) .
+* Introduced WebAssembly target (`wasmJs` and `wasmWasi`) 🎉 (#334).
+* Improved integration testing for `atomicfu-gradle-plugin` (#345).
+* Updated implementation of native atomics (#336).
+* Got rid of `previous-compilation-data.bin` file in META-INF (#344).
+
+# Version 0.22.0
+
+* Updated Kotlin to 1.9.0 (#330).
+* Updated gradle version to 8.1 (#319).
+* Updated kotlinx.metadata version 0.7.0 (#327).
+* Conditionally removed targets that are removed after 1.9.20 (iosArm32, watchosX86). (#320).
+* Removed obsolete no longer supported kotlin.mpp.enableCompatibilityMetadataVariant (#326).
+* Complied with new compiler restriction on actual declaration annotations (#325).
+
+# Version 0.21.0
+
+* Updated Kotlin to 1.8.20.
+* Updated Gradle to 7.3 (#300).
+* Updated kotlinx.metadata version to 0.6.0 (#281).
+* Minimal supported KGP(1.7.0) and Gradle(7.0) versions are set since this release.
+* Removed JS Legacy configurations for KGP >= 1.9.0 (#296).
+* Fixed class duplication (from original and transformed directories) in Jar (#301).
+* Original class directories are not modified in case of compiler plugin application (#312).
+
+# Version 0.20.2
+
+* Fix for unresolved `kotlinx-atomicfu-runtime` dependency error (https://youtrack.jetbrains.com/issue/KT-57235),
+please see the corresponding PR for more comments (#290).
+
+# Version 0.20.1
+
+* Fixed passing `kotlinx-atomicfu-runtime` dependency to the runtime classpath (#283).
+* AV/LV set to 1.4 to be compatible with Gradle 7 (#287).
+* Enable cinterop commonization (#282).
+
+# Version 0.20.0
+
+* Update Kotlin to 1.8.10.
+* Support all official K/N targets (#275).
+
+# Version 0.19.0
+
+* Update Kotlin to 1.8.0.
+* Update LV to 1.8 (#270).
+* Prepare atomicfu for including to the Kotlin Aggregate build (#265).
+
 # Version 0.18.5
 
 * Support JVM IR compiler plugin (#246).
diff --git a/license/LICENSE.txt b/LICENSE.txt
similarity index 100%
rename from license/LICENSE.txt
rename to LICENSE.txt
diff --git a/METADATA b/METADATA
index ef605b9..d894cca 100644
--- a/METADATA
+++ b/METADATA
@@ -1,23 +1,20 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update kotlinx.atomicfu
-# For more info, check https://cs.android.com/android/platform/superproject/+/master:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/kotlinx.atomicfu
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "kotlinx.atomicfu"
 description: "The idiomatic way to use atomic operations in Kotlin."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/Kotlin/kotlinx.atomicfu"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/Kotlin/kotlinx.atomicfu"
-  }
-  version: "0.18.5"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2022
-    month: 11
-    day: 1
+    year: 2024
+    month: 10
+    day: 17
+  }
+  homepage: "https://github.com/Kotlin/kotlinx.atomicfu"
+  identifier {
+    type: "Git"
+    value: "https://github.com/Kotlin/kotlinx.atomicfu"
+    version: "0.23.1"
   }
 }
diff --git a/README.md b/README.md
index e3dd5b3..104c60c 100644
--- a/README.md
+++ b/README.md
@@ -3,15 +3,16 @@
 [![Kotlin Beta](https://kotl.in/badges/beta.svg)](https://kotlinlang.org/docs/components-stability.html)
 [![JetBrains official project](https://jb.gg/badges/official.svg)](https://confluence.jetbrains.com/display/ALL/JetBrains+on+GitHub)
 [![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
-[![Maven Central](https://img.shields.io/maven-central/v/org.jetbrains.kotlinx/atomicfu)](https://search.maven.org/artifact/org.jetbrains.kotlinx/atomicfu/0.18.5/pom)
+[![Maven Central](https://img.shields.io/maven-central/v/org.jetbrains.kotlinx/atomicfu)](https://search.maven.org/artifact/org.jetbrains.kotlinx/atomicfu/0.23.1/pom)
 
 >Note on Beta status: the plugin is in its active development phase and changes from release to release.
 >We do provide a compatibility of atomicfu-transformed artifacts between releases, but we do not provide 
 >strict compatibility guarantees on plugin API and its general stability between Kotlin versions.
 
-**Atomicfu** is a multiplatform library that provides the idiomatic and effective way of using atomic operations in Kotlin.
+**Atomicfu** is a multiplatform library that provides the idiomatic and efficient way of using atomic operations in Kotlin.
 
 ## Table of contents
+- [Requirements](#requirements)
 - [Features](#features)
 - [Example](#example)
 - [Quickstart](#quickstart)
@@ -31,15 +32,22 @@
   - [Tracing operations](#tracing-operations)
 - [Kotlin/Native support](#kotlin-native-support)
 
+## Requirements
+
+Starting from version `0.23.1` of the library your project is required to use:
+
+* Gradle `7.0` or newer
+
+* Kotlin `1.7.0` or newer
 
 ## Features
 
+* Complete multiplatform support: JVM, Native, JS and Wasm (since Kotlin 1.9.20).
 * Code it like a boxed value `atomic(0)`, but run it in production efficiently:
-  * as `java.util.concurrent.atomic.AtomicXxxFieldUpdater` on Kotlin/JVM 
-  * as a plain unboxed value on Kotlin/JS
-* Multiplatform: write common Kotlin code with atomics that compiles for Kotlin JVM, JS, and Native backends:
-    * Compile-only dependency for JVM and JS (no runtime dependencies)
-    * Compile and runtime dependency for Kotlin/Native 
+  * For **JVM**: an atomic value is represented as a plain value atomically updated with `java.util.concurrent.atomic.AtomicXxxFieldUpdater` from the Java standard library.
+  * For **JS**: an atomic value is represented as a plain value.
+  * For **Native**: atomic operations are delegated to Kotlin/Native atomic intrinsics.
+  * For **Wasm**: an atomic value is not transformed, it remains boxed, and `kotlinx-atomicfu` library is used as a runtime dependency.
 * Use Kotlin-specific extensions (e.g. inline `loop`, `update`, `updateAndGet` functions).
 * Use atomic arrays, user-defined extensions on atomics and locks (see [more features](#more-features)).
 * [Tracing operations](#tracing-operations) for debugging.
@@ -111,7 +119,7 @@ buildscript {
     }
 
     dependencies {
-      classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.18.5")
+      classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.23.1")
     }
 }
 
@@ -128,7 +136,7 @@ buildscript {
         mavenCentral()
     }
     dependencies {
-        classpath 'org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.18.5'
+        classpath 'org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.23.1'
     }
 }
   
@@ -146,7 +154,7 @@ Maven configuration is supported for JVM projects.
 
 ```xml
 <properties>
-     <atomicfu.version>0.18.5</atomicfu.version>
+     <atomicfu.version>0.23.1</atomicfu.version>
 </properties> 
 ```
 
@@ -224,6 +232,13 @@ which is then transformed to a regular `classes` directory to be used later by t
 * Declare atomic variables as `private val` or `internal val`. You can use just (public) `val`, 
   but make sure they are not directly accessed outside of your Kotlin module (outside of the source set).
   Access to the atomic variable itself shall be encapsulated.
+* To expose the value of an atomic property to the public, use a delegated property declared in the same scope
+  (see [atomic delegates](#atomic-delegates) section for details):
+
+```kotlin
+private val _foo = atomic<T>(initial) // private atomic, convention is to name it with leading underscore
+public var foo: T by _foo            // public delegated property (val/var)
+```
 * Only simple operations on atomic variables _directly_ are supported. 
   * Do not read references on atomic variables into local variables,
     e.g. `top.compareAndSet(...)` is ok, while `val tmp = top; tmp...` is not. 
@@ -232,24 +247,14 @@ which is then transformed to a regular `classes` directory to be used later by t
   i.e. `top.value = complex_expression` and `top.compareAndSet(cur, complex_expression)` are not supported 
   (more specifically, `complex_expression` should not have branches in its compiled representation).
   Extract `complex_expression` into a variable when needed.
-* Use the following convention if you need to expose the value of atomic property to the public:
-
-```kotlin
-private val _foo = atomic<T>(initial) // private atomic, convention is to name it with leading underscore
-public var foo: T by _foo            // public delegated property (val/var)
-```
-
-## Transformation modes
 
-Basically, Atomicfu library provides an effective usage of atomic values by performing the transformations of the compiled code.
-For JVM and JS there 2 transformation modes available: 
-* **Post-compilation transformation** that modifies the compiled bytecode or `*.js` files. 
-* **IR transformation** that is performed by the atomicfu compiler plugin.
+## Atomicfu compiler plugin
 
-### Atomicfu compiler plugin
-
-Compiler plugin transformation is less fragile than transformation of the compiled sources 
-as it depends on the compiler IR tree.
+To provide a user-friendly atomic API on the frontend and efficient usage of atomic values on the backend kotlinx-atomicfu library uses the compiler plugin to transform 
+IR for all the target backends: 
+* **JVM**: atomics are replaced with `java.util.concurrent.atomic.AtomicXxxFieldUpdater`.
+* **Native**: atomics are implemented via atomic intrinsics on Kotlin/Native.
+* **JS**: atomics are unboxed and represented as plain values.
 
 To turn on IR transformation set these properties in your `gradle.properties` file:
 
@@ -258,6 +263,7 @@ To turn on IR transformation set these properties in your `gradle.properties` fi
 
 ```groovy
 kotlinx.atomicfu.enableJvmIrTransformation=true // for JVM IR transformation
+kotlinx.atomicfu.enableNativeIrTransformation=true // for Native IR transformation
 kotlinx.atomicfu.enableJsIrTransformation=true // for JS IR transformation
 ```
 
@@ -289,7 +295,7 @@ To set configuration options you should create `atomicfu` section in a `build.gr
 like this:
 ```groovy
 atomicfu {
-  dependenciesVersion = '0.18.5'
+  dependenciesVersion = '0.23.1'
 }
 ```
 
@@ -311,7 +317,7 @@ To turn off transformation for Kotlin/JS set option `transformJs` to `false`.
 Here are all available configuration options (with their defaults):
 ```groovy
 atomicfu {
-  dependenciesVersion = '0.18.5' // set to null to turn-off auto dependencies
+  dependenciesVersion = '0.23.1' // set to null to turn-off auto dependencies
   transformJvm = true // set to false to turn off JVM transformation
   jvmVariant = "FU" // JVM transformation variant: FU,VH, or BOTH
   transformJs = true // set to false to turn off JVM transformation
@@ -338,6 +344,24 @@ a[i].value = x // set value
 a[i].compareAndSet(expect, update) // do atomic operations
 ```
 
+### Atomic delegates
+
+You can expose the value of an atomic property to the public, using a delegated property 
+declared in the same scope:
+
+```kotlin
+private val _foo = atomic<T>(initial) // private atomic, convention is to name it with leading underscore
+public var foo: T by _foo            // public delegated property (val/var)
+```
+
+You can also delegate a property to the atomic factory invocation, that is equal to declaring a volatile property:  
+
+```kotlin
+public var foo: T by atomic(0)
+```
+
+This feature is only supported for the IR transformation mode, see the [atomicfu compiler plugin](#atomicfu-compiler-plugin) section for details.
+
 ### User-defined extensions on atomics
 
 You can define you own extension functions on `AtomicXxx` types but they must be `inline` and they cannot
@@ -413,3 +437,5 @@ Since Kotlin/Native does not generally provide binary compatibility between vers
 you should use the same version of Kotlin compiler as was used to build AtomicFU.
 See [gradle.properties](gradle.properties) in AtomicFU project for its `kotlin_version`.
 
+Available Kotlin/Native targets are based on non-deprecated official targets [Tier list](https://kotlinlang.org/docs/native-target-support.html)
+ with the corresponding compatibility guarantees.
diff --git a/atomicfu-gradle-plugin/api/atomicfu-gradle-plugin.api b/atomicfu-gradle-plugin/api/atomicfu-gradle-plugin.api
new file mode 100644
index 0000000..2d1773f
--- /dev/null
+++ b/atomicfu-gradle-plugin/api/atomicfu-gradle-plugin.api
@@ -0,0 +1,51 @@
+public class kotlinx/atomicfu/plugin/gradle/AtomicFUGradlePlugin : org/gradle/api/Plugin {
+	public fun <init> ()V
+	public synthetic fun apply (Ljava/lang/Object;)V
+	public fun apply (Lorg/gradle/api/Project;)V
+}
+
+public final class kotlinx/atomicfu/plugin/gradle/AtomicFUPluginExtension {
+	public fun <init> (Ljava/lang/String;)V
+	public final fun getDependenciesVersion ()Ljava/lang/String;
+	public final fun getJvmVariant ()Ljava/lang/String;
+	public final fun getTransformJs ()Z
+	public final fun getTransformJvm ()Z
+	public final fun getVerbose ()Z
+	public final fun setDependenciesVersion (Ljava/lang/String;)V
+	public final fun setJvmVariant (Ljava/lang/String;)V
+	public final fun setTransformJs (Z)V
+	public final fun setTransformJvm (Z)V
+	public final fun setVerbose (Z)V
+}
+
+public abstract class kotlinx/atomicfu/plugin/gradle/AtomicFUTransformJsTask : org/gradle/api/internal/ConventionTask {
+	public field inputFiles Lorg/gradle/api/file/FileCollection;
+	public fun <init> ()V
+	public abstract fun getDestinationDirectory ()Lorg/gradle/api/file/DirectoryProperty;
+	public final fun getInputFiles ()Lorg/gradle/api/file/FileCollection;
+	public final fun getOutputDir ()Ljava/io/File;
+	public final fun getVerbose ()Z
+	public final fun setInputFiles (Lorg/gradle/api/file/FileCollection;)V
+	public final fun setOutputDir (Ljava/io/File;)V
+	public final fun setVerbose (Z)V
+	public final fun transform ()V
+}
+
+public abstract class kotlinx/atomicfu/plugin/gradle/AtomicFUTransformTask : org/gradle/api/internal/ConventionTask {
+	public field classPath Lorg/gradle/api/file/FileCollection;
+	public field inputFiles Lorg/gradle/api/file/FileCollection;
+	public fun <init> ()V
+	public final fun getClassPath ()Lorg/gradle/api/file/FileCollection;
+	public abstract fun getDestinationDirectory ()Lorg/gradle/api/file/DirectoryProperty;
+	public final fun getInputFiles ()Lorg/gradle/api/file/FileCollection;
+	public final fun getJvmVariant ()Ljava/lang/String;
+	public final fun getOutputDir ()Ljava/io/File;
+	public final fun getVerbose ()Z
+	public final fun setClassPath (Lorg/gradle/api/file/FileCollection;)V
+	public final fun setInputFiles (Lorg/gradle/api/file/FileCollection;)V
+	public final fun setJvmVariant (Ljava/lang/String;)V
+	public final fun setOutputDir (Ljava/io/File;)V
+	public final fun setVerbose (Z)V
+	public final fun transform ()V
+}
+
diff --git a/atomicfu-gradle-plugin/build.gradle b/atomicfu-gradle-plugin/build.gradle
index 5312551..4c43f93 100644
--- a/atomicfu-gradle-plugin/build.gradle
+++ b/atomicfu-gradle-plugin/build.gradle
@@ -5,17 +5,11 @@
 apply plugin: 'kotlin'
 apply plugin: 'java-gradle-plugin'
 
-if (rootProject.ext.jvm_ir_enabled) {
-    kotlin.target.compilations.all {
-        kotlinOptions.useIR = true
-    }
-}
-
 // Gradle plugin must be compiled targeting the same Kotlin version as used by Gradle
-kotlin.sourceSets.all {
+kotlin.sourceSets.configureEach {
     languageSettings {
-        apiVersion = "1.4"
-        languageVersion = "1.4"
+        languageVersion = KotlinConfiguration.getOverridingKotlinLanguageVersion(project) ?: "1.4"
+        apiVersion = KotlinConfiguration.getOverridingKotlinApiVersion(project) ?: "1.4"
     }
 }
 
@@ -27,7 +21,8 @@ dependencies {
     compileOnly gradleApi()
     compileOnly 'org.jetbrains.kotlin:kotlin-stdlib'
     compileOnly "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
-    // atomicfu compiler plugin dependency will be loaded to kotlinCompilerPluginClasspath
+    // Atomicfu compiler plugin dependency will be loaded to kotlinCompilerPluginClasspath
+    // Atomicfu plugin will only be applied if the flag is set kotlinx.atomicfu.enableJsIrTransformation=true
     implementation "org.jetbrains.kotlin:atomicfu:$kotlin_version"
 
     testImplementation gradleTestKit()
@@ -84,7 +79,21 @@ task createClasspathManifest {
     }
 }
 
+task createKotlinRepoUrlResource {
+    def customKotlinRepoUrl = KotlinConfiguration.getCustomKotlinRepositoryURL(project)
+    if (customKotlinRepoUrl == null) return
+
+    def outputDir = file("$buildDir/$name")
+    outputs.dir outputDir
+
+    doLast {
+        outputDir.mkdirs()
+        file("$outputDir/kotlin-repo-url.txt").text = customKotlinRepoUrl
+    }
+}
+
 // Add the classpath file to the test runtime classpath
 dependencies {
-    testRuntime files(createClasspathManifest)
+    testRuntimeOnly files(createClasspathManifest)
+    testRuntimeOnly files(createKotlinRepoUrlResource)
 }
diff --git a/atomicfu-gradle-plugin/src/main/kotlin/kotlinx/atomicfu/plugin/gradle/AtomicFUGradlePlugin.kt b/atomicfu-gradle-plugin/src/main/kotlin/kotlinx/atomicfu/plugin/gradle/AtomicFUGradlePlugin.kt
index b77e95b..3d2b933 100644
--- a/atomicfu-gradle-plugin/src/main/kotlin/kotlinx/atomicfu/plugin/gradle/AtomicFUGradlePlugin.kt
+++ b/atomicfu-gradle-plugin/src/main/kotlin/kotlinx/atomicfu/plugin/gradle/AtomicFUGradlePlugin.kt
@@ -8,21 +8,22 @@ import kotlinx.atomicfu.transformer.*
 import org.gradle.api.*
 import org.gradle.api.file.*
 import org.gradle.api.internal.*
-import org.gradle.api.plugins.*
+import org.gradle.api.provider.Provider
+import org.gradle.api.provider.ProviderFactory
 import org.gradle.api.tasks.*
-import org.gradle.api.tasks.compile.*
 import org.gradle.api.tasks.testing.*
 import org.gradle.jvm.tasks.*
+import org.gradle.util.*
 import org.jetbrains.kotlin.gradle.dsl.*
 import org.jetbrains.kotlin.gradle.dsl.KotlinCompile
 import org.jetbrains.kotlin.gradle.plugin.*
 import java.io.*
 import java.util.*
-import java.util.concurrent.*
 import org.jetbrains.kotlin.gradle.targets.js.*
 import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrTarget
 import org.jetbrains.kotlin.gradle.tasks.*
 import org.jetbrains.kotlinx.atomicfu.gradle.*
+import javax.inject.Inject
 
 private const val EXTENSION_NAME = "atomicfu"
 private const val ORIGINAL_DIR_NAME = "originalClassesDir"
@@ -34,9 +35,13 @@ private const val TEST_IMPLEMENTATION_CONFIGURATION = "testImplementation"
 private const val ENABLE_JS_IR_TRANSFORMATION_LEGACY = "kotlinx.atomicfu.enableIrTransformation"
 private const val ENABLE_JS_IR_TRANSFORMATION = "kotlinx.atomicfu.enableJsIrTransformation"
 private const val ENABLE_JVM_IR_TRANSFORMATION = "kotlinx.atomicfu.enableJvmIrTransformation"
+private const val ENABLE_NATIVE_IR_TRANSFORMATION = "kotlinx.atomicfu.enableNativeIrTransformation"
+private const val MIN_SUPPORTED_GRADLE_VERSION = "7.0"
+private const val MIN_SUPPORTED_KGP_VERSION = "1.7.0"
 
 open class AtomicFUGradlePlugin : Plugin<Project> {
     override fun apply(project: Project) = project.run {
+        checkCompatibility()
         val pluginVersion = rootProject.buildscript.configurations.findByName("classpath")
             ?.allDependencies?.find { it.name == "atomicfu-gradle-plugin" }?.version
         extensions.add(EXTENSION_NAME, AtomicFUPluginExtension(pluginVersion))
@@ -46,6 +51,51 @@ open class AtomicFUGradlePlugin : Plugin<Project> {
     }
 }
 
+private fun Project.checkCompatibility() {
+    val currentGradleVersion = GradleVersion.current()
+    val kotlinVersion = getKotlinVersion()
+    val minSupportedVersion = GradleVersion.version(MIN_SUPPORTED_GRADLE_VERSION)
+    if (currentGradleVersion < minSupportedVersion) {
+        throw GradleException(
+            "The current Gradle version is not compatible with Atomicfu gradle plugin. " +
+                    "Please use Gradle $MIN_SUPPORTED_GRADLE_VERSION or newer, or the previous version of Atomicfu gradle plugin."
+        )
+    }
+    if (!kotlinVersion.atLeast(1, 7, 0)) {
+        throw GradleException(
+            "The current Kotlin gradle plugin version is not compatible with Atomicfu gradle plugin. " +
+                    "Please use Kotlin $MIN_SUPPORTED_KGP_VERSION or newer, or the previous version of Atomicfu gradle plugin."
+        )
+    }
+}
+
+private fun Project.applyAtomicfuCompilerPlugin() {
+    val kotlinVersion = getKotlinVersion()
+    // for KGP >= 1.7.20:
+    // compiler plugin for JS IR is applied via the property `kotlinx.atomicfu.enableJsIrTransformation`
+    // compiler plugin for JVM IR is applied via the property `kotlinx.atomicfu.enableJvmIrTransformation`
+    if (kotlinVersion.atLeast(1, 7, 20)) {
+        plugins.apply(AtomicfuKotlinGradleSubplugin::class.java)
+        extensions.getByType(AtomicfuKotlinGradleSubplugin.AtomicfuKotlinGradleExtension::class.java).apply {
+            isJsIrTransformationEnabled = rootProject.getBooleanProperty(ENABLE_JS_IR_TRANSFORMATION)
+            isJvmIrTransformationEnabled = rootProject.getBooleanProperty(ENABLE_JVM_IR_TRANSFORMATION)
+            if (kotlinVersion.atLeast(1, 9, 20)) {
+                // Native IR transformation is available since Kotlin 1.9.20
+                isNativeIrTransformationEnabled = rootProject.getBooleanProperty(ENABLE_NATIVE_IR_TRANSFORMATION)   
+            }
+        }
+    } else {
+        // for KGP >= 1.6.20 && KGP <= 1.7.20:
+        // compiler plugin for JS IR is applied via the property `kotlinx.atomicfu.enableIrTransformation`
+        // compiler plugin for JVM IR is not supported yet
+        if (kotlinVersion.atLeast(1, 6, 20)) {
+            if (rootProject.getBooleanProperty(ENABLE_JS_IR_TRANSFORMATION_LEGACY)) {
+                plugins.apply(AtomicfuKotlinGradleSubplugin::class.java)
+            }
+        }
+    }
+}
+
 private fun Project.configureDependencies() {
     withPluginWhenEvaluatedDependencies("kotlin") { version ->
         dependencies.add(
@@ -60,35 +110,34 @@ private fun Project.configureDependencies() {
             getAtomicfuDependencyNotation(Platform.JS, version)
         )
         dependencies.add(TEST_IMPLEMENTATION_CONFIGURATION, getAtomicfuDependencyNotation(Platform.JS, version))
-        addCompilerPluginDependency()
+        addJsCompilerPluginRuntimeDependency()
     }
     withPluginWhenEvaluatedDependencies("kotlin-multiplatform") { version ->
+        addJsCompilerPluginRuntimeDependency()
         configureMultiplatformPluginDependencies(version)
     }
 }
 
-private fun Project.configureTasks() {
-    val config = config
-    withPluginWhenEvaluated("kotlin") {
-        if (config.transformJvm) {
-            // skip transformation task if ir transformation is enabled
-            if (rootProject.getBooleanProperty(ENABLE_JVM_IR_TRANSFORMATION)) return@withPluginWhenEvaluated
-            configureJvmTransformation("compileTestKotlin") { sourceSet, transformedDir, originalDir ->
-                createJvmTransformTask(sourceSet).configureJvmTask(
-                    sourceSet.compileClasspath,
-                    sourceSet.classesTaskName,
-                    transformedDir,
-                    originalDir,
-                    config
-                )
-            }
-        }
+private fun Project.configureMultiplatformPluginDependencies(version: String) {
+    val multiplatformExtension = kotlinExtension as? KotlinMultiplatformExtension ?: error("Expected kotlin multiplatform extension")
+    val atomicfuDependency = "org.jetbrains.kotlinx:atomicfu:$version"
+    multiplatformExtension.sourceSets.getByName("commonMain").dependencies {
+        compileOnly(atomicfuDependency)
     }
-    withPluginWhenEvaluated("org.jetbrains.kotlin.js") {
-        if (config.transformJs) configureJsTransformation()
+    multiplatformExtension.sourceSets.getByName("commonTest").dependencies {
+        implementation(atomicfuDependency)
     }
-    withPluginWhenEvaluated("kotlin-multiplatform") {
-        configureMultiplatformTransformation()
+    // Include atomicfu as a dependency for publication when transformation for the target is disabled
+    multiplatformExtension.targets.all { target ->
+        if (isTransformationDisabled(target)) {
+            target.compilations.all { compilation ->
+                compilation
+                    .defaultSourceSet
+                    .dependencies {
+                        implementation(atomicfuDependency)
+                    }
+            }
+        }
     }
 }
 
@@ -110,29 +159,6 @@ private fun KotlinVersion.atLeast(major: Int, minor: Int, patch: Int) =
 // kotlinx-atomicfu compiler plugin is available for KGP >= 1.6.20
 private fun Project.isCompilerPluginAvailable() = getKotlinVersion().atLeast(1, 6, 20)
 
-private fun Project.applyAtomicfuCompilerPlugin() {
-    val kotlinVersion = getKotlinVersion()
-    // for KGP >= 1.7.20:
-    // compiler plugin for JS IR is applied via the property `kotlinx.atomicfu.enableJsIrTransformation`
-    // compiler plugin for JVM IR is applied via the property `kotlinx.atomicfu.enableJvmIrTransformation`
-    if (kotlinVersion.atLeast(1, 7, 20)) {
-        plugins.apply(AtomicfuKotlinGradleSubplugin::class.java)
-        extensions.getByType(AtomicfuKotlinGradleSubplugin.AtomicfuKotlinGradleExtension::class.java).apply {
-            isJsIrTransformationEnabled = rootProject.getBooleanProperty(ENABLE_JS_IR_TRANSFORMATION)
-            isJvmIrTransformationEnabled = rootProject.getBooleanProperty(ENABLE_JVM_IR_TRANSFORMATION)
-        }
-    } else {
-        // for KGP >= 1.6.20 && KGP <= 1.7.20:
-        // compiler plugin for JS IR is applied via the property `kotlinx.atomicfu.enableIrTransformation`
-        // compiler plugin for JVM IR is not supported yet
-        if (kotlinVersion.atLeast(1, 6, 20)) {
-            if (rootProject.getBooleanProperty(ENABLE_JS_IR_TRANSFORMATION_LEGACY)) {
-                plugins.apply(AtomicfuKotlinGradleSubplugin::class.java)
-            }
-        }
-    }
-}
-
 private fun Project.getBooleanProperty(name: String) =
     rootProject.findProperty(name)?.toString()?.toBooleanStrict() ?: false
 
@@ -146,20 +172,39 @@ private fun Project.needsJsIrTransformation(target: KotlinTarget): Boolean =
     (rootProject.getBooleanProperty(ENABLE_JS_IR_TRANSFORMATION) || rootProject.getBooleanProperty(ENABLE_JS_IR_TRANSFORMATION_LEGACY))
             && target.isJsIrTarget()
 
-private fun KotlinTarget.isJsIrTarget() = (this is KotlinJsTarget && this.irTarget != null) || this is KotlinJsIrTarget
+private fun Project.needsJvmIrTransformation(target: KotlinTarget): Boolean =
+    rootProject.getBooleanProperty(ENABLE_JVM_IR_TRANSFORMATION) &&
+            (target.platformType == KotlinPlatformType.jvm || target.platformType == KotlinPlatformType.androidJvm)
+
+private fun Project.needsNativeIrTransformation(target: KotlinTarget): Boolean =
+    rootProject.getBooleanProperty(ENABLE_NATIVE_IR_TRANSFORMATION) &&
+            (target.platformType == KotlinPlatformType.native)
 
-private fun Project.addCompilerPluginDependency() {
+
+private fun KotlinTarget.isJsIrTarget() =
+    (this is KotlinJsTarget && this.irTarget != null) ||
+            (this is KotlinJsIrTarget && this.platformType != KotlinPlatformType.wasm)
+
+private fun Project.isTransformationDisabled(target: KotlinTarget): Boolean {
+    val platformType = target.platformType
+    return !config.transformJvm && (platformType == KotlinPlatformType.jvm || platformType == KotlinPlatformType.androidJvm) ||
+            !config.transformJs && platformType == KotlinPlatformType.js ||
+            platformType == KotlinPlatformType.wasm ||
+            !needsNativeIrTransformation(target) && platformType == KotlinPlatformType.native
+}
+
+// Adds kotlinx-atomicfu-runtime as an implementation dependency to the JS IR target:
+// it provides inline methods that replace atomic methods from the library and is needed at runtime.
+private fun Project.addJsCompilerPluginRuntimeDependency() {
     if (isCompilerPluginAvailable()) {
         withKotlinTargets { target ->
-            if (needsJsIrTransformation(target)) {
+            if (target.isJsIrTarget()) {
                 target.compilations.forEach { kotlinCompilation ->
                     kotlinCompilation.dependencies {
                         if (getKotlinVersion().atLeast(1, 7, 10)) {
-                            // since Kotlin 1.7.10 we can add `atomicfu-runtime` dependency directly
+                            // since Kotlin 1.7.10 `kotlinx-atomicfu-runtime` is published and should be added directly
                             implementation("org.jetbrains.kotlin:kotlinx-atomicfu-runtime:${getKotlinPluginVersion()}")
                         } else {
-                            // add atomicfu compiler plugin dependency
-                            // to provide the `atomicfu-runtime` library used during compiler plugin transformation
                             implementation("org.jetbrains.kotlin:atomicfu:${getKotlinPluginVersion()}")
                         }
                     }
@@ -184,12 +229,6 @@ private fun String.compilationNameToType(): CompilationType? = when (this) {
     else -> null
 }
 
-private fun String.sourceSetNameToType(): CompilationType? = when (this) {
-    SourceSet.MAIN_SOURCE_SET_NAME -> CompilationType.MAIN
-    SourceSet.TEST_SOURCE_SET_NAME -> CompilationType.TEST
-    else -> null
-}
-
 private val Project.config: AtomicFUPluginExtension
     get() = extensions.findByName(EXTENSION_NAME) as? AtomicFUPluginExtension ?: AtomicFUPluginExtension(null)
 
@@ -198,7 +237,7 @@ private fun getAtomicfuDependencyNotation(platform: Platform, version: String):
 
 // Note "afterEvaluate" does nothing when the project is already in executed state, so we need
 // a special check for this case
-fun <T> Project.whenEvaluated(fn: Project.() -> T) {
+private fun <T> Project.whenEvaluated(fn: Project.() -> T) {
     if (state.executed) {
         fn()
     } else {
@@ -206,17 +245,17 @@ fun <T> Project.whenEvaluated(fn: Project.() -> T) {
     }
 }
 
-fun Project.withPluginWhenEvaluated(plugin: String, fn: Project.() -> Unit) {
+private fun Project.withPluginWhenEvaluated(plugin: String, fn: Project.() -> Unit) {
     pluginManager.withPlugin(plugin) { whenEvaluated(fn) }
 }
 
-fun Project.withPluginWhenEvaluatedDependencies(plugin: String, fn: Project.(version: String) -> Unit) {
+private fun Project.withPluginWhenEvaluatedDependencies(plugin: String, fn: Project.(version: String) -> Unit) {
     withPluginWhenEvaluated(plugin) {
         config.dependenciesVersion?.let { fn(it) }
     }
 }
 
-fun Project.withKotlinTargets(fn: (KotlinTarget) -> Unit) {
+private fun Project.withKotlinTargets(fn: (KotlinTarget) -> Unit) {
     extensions.findByType(KotlinTargetsContainer::class.java)?.let { kotlinExtension ->
         // find all compilations given sourceSet belongs to
         kotlinExtension.targets
@@ -237,13 +276,44 @@ private fun KotlinCompile<*>.setFriendPaths(friendPathsFileCollection: FileColle
     }
 }
 
-fun Project.configureJsTransformation() =
-    configureTransformationForTarget((kotlinExtension as KotlinJsProjectExtension).js())
+private fun Project.configureTasks() {
+    val config = config
+    withPluginWhenEvaluated("kotlin") {
+        if (config.transformJvm) configureJvmTransformation()
+    }
+    withPluginWhenEvaluated("org.jetbrains.kotlin.js") {
+        if (config.transformJs) configureJsTransformation()
+    }
+    withPluginWhenEvaluated("kotlin-multiplatform") {
+        configureMultiplatformTransformation()
+    }
+}
 
-fun Project.configureMultiplatformTransformation() =
+private fun Project.configureJvmTransformation() {
+    if (kotlinExtension is KotlinJvmProjectExtension || kotlinExtension is KotlinAndroidProjectExtension) {
+        val target = (kotlinExtension as KotlinSingleTargetExtension<*>).target
+        if (!needsJvmIrTransformation(target)) {
+            configureTransformationForTarget(target)   
+        }
+    }
+}
+
+private fun Project.configureJsTransformation() {
+    val target = (kotlinExtension as KotlinJsProjectExtension).js()
+    if (!needsJsIrTransformation(target)) {
+        configureTransformationForTarget(target)
+    }
+}
+
+private fun Project.configureMultiplatformTransformation() =
     withKotlinTargets { target ->
-        if (target.platformType == KotlinPlatformType.common || target.platformType == KotlinPlatformType.native) {
-            return@withKotlinTargets // skip the common & native targets -- no transformation for them
+        // Skip transformation for common, native and wasm targets or in case IR transformation by the compiler plugin is enabled (for JVM or JS targets)
+        if (target.platformType == KotlinPlatformType.common || 
+            target.platformType == KotlinPlatformType.native ||
+            target.platformType == KotlinPlatformType.wasm ||
+            needsJvmIrTransformation(target) || needsJsIrTransformation(target)
+           ) {
+            return@withKotlinTargets
         }
         configureTransformationForTarget(target)
     }
@@ -256,234 +326,141 @@ private fun Project.configureTransformationForTarget(target: KotlinTarget) {
             ?: return@compilations // skip unknown compilations
         val classesDirs = compilation.output.classesDirs
         // make copy of original classes directory
-        val originalClassesDirs: FileCollection =
-            project.files(classesDirs.from.toTypedArray()).filter { it.exists() }
+        @Suppress("UNCHECKED_CAST")
+        val compilationTask = compilation.compileTaskProvider as TaskProvider<KotlinCompileTool>
+        val originalDestinationDirectory = project.layout.buildDirectory
+            .dir("classes/atomicfu-orig/${target.name}/${compilation.name}")
+        compilationTask.configure {
+            if (it is Kotlin2JsCompile) {
+                @Suppress("INVISIBLE_REFERENCE", "INVISIBLE_MEMBER", "EXPOSED_PARAMETER_TYPE")
+                it.defaultDestinationDirectory.value(originalDestinationDirectory)
+            } else {
+                it.destinationDirectory.value(originalDestinationDirectory)
+            }
+        }
+        val originalClassesDirs: FileCollection = project.objects.fileCollection().from(
+            compilationTask.flatMap { it.destinationDirectory }
+        )
         originalDirsByCompilation[compilation] = originalClassesDirs
-        val transformedClassesDir =
-            project.buildDir.resolve("classes/atomicfu/${target.name}/${compilation.name}")
+        val transformedClassesDir = project.layout.buildDirectory
+            .dir("classes/atomicfu/${target.name}/${compilation.name}")
         val transformTask = when (target.platformType) {
             KotlinPlatformType.jvm, KotlinPlatformType.androidJvm -> {
-                // skip transformation task if transformation is turned off or ir transformation is enabled
-                if (!config.transformJvm || rootProject.getBooleanProperty(ENABLE_JVM_IR_TRANSFORMATION)) return@compilations
-                project.createJvmTransformTask(compilation).configureJvmTask(
-                    compilation.compileDependencyFiles,
-                    compilation.compileAllTaskName,
-                    transformedClassesDir,
-                    originalClassesDirs,
-                    config
-                )
+                // create transformation task only if transformation is required and JVM IR compiler transformation is not enabled
+                if (config.transformJvm) {
+                    project.registerJvmTransformTask(compilation)
+                        .configureJvmTask(
+                            compilation.compileDependencyFiles,
+                            compilation.compileAllTaskName,
+                            transformedClassesDir,
+                            originalClassesDirs,
+                            config
+                        )
+                        .also {
+                            compilation.defaultSourceSet.kotlin.compiledBy(it, AtomicFUTransformTask::destinationDirectory)
+                        }
+                } else null
             }
             KotlinPlatformType.js -> {
-                // skip when js transformation is not needed or when IR is transformed
-                if (!config.transformJs || (needsJsIrTransformation(target))) {
-                    return@compilations
-                }
-                project.createJsTransformTask(compilation).configureJsTask(
-                    compilation.compileAllTaskName,
-                    transformedClassesDir,
-                    originalClassesDirs,
-                    config
-                )
+                // create transformation task only if transformation is required and JS IR compiler transformation is not enabled
+                if (config.transformJs && !needsJsIrTransformation(target)) {
+                    project.registerJsTransformTask(compilation)
+                        .configureJsTask(
+                            compilation.compileAllTaskName,
+                            transformedClassesDir,
+                            originalClassesDirs,
+                            config
+                        )
+                        .also {
+                            compilation.defaultSourceSet.kotlin.compiledBy(it, AtomicFUTransformJsTask::destinationDirectory)
+                        }
+                } else null
             }
             else -> error("Unsupported transformation platform '${target.platformType}'")
         }
-        //now transformTask is responsible for compiling this source set into the classes directory
-        classesDirs.setFrom(transformedClassesDir)
-        classesDirs.builtBy(transformTask)
-        (tasks.findByName(target.artifactsTaskName) as? Jar)?.apply {
-            setupJarManifest(multiRelease = config.jvmVariant.toJvmVariant() == JvmVariant.BOTH)
+        if (transformTask != null) {
+            //now transformTask is responsible for compiling this source set into the classes directory
+            compilation.defaultSourceSet.kotlin.destinationDirectory.value(transformedClassesDir)
+            classesDirs.setFrom(transformedClassesDir)
+            classesDirs.setBuiltBy(listOf(transformTask))
+            tasks.withType(Jar::class.java).configureEach {
+                if (name == target.artifactsTaskName) {
+                    it.setupJarManifest(multiRelease = config.jvmVariant.toJvmVariant() == JvmVariant.BOTH)
+                }
+            }
         }
         // test should compile and run against original production binaries
         if (compilationType == CompilationType.TEST) {
             val mainCompilation =
                 compilation.target.compilations.getByName(KotlinCompilation.MAIN_COMPILATION_NAME)
-            val originalMainClassesDirs = project.files(
-                // use Callable because there is no guarantee that main is configured before test
-                Callable { originalDirsByCompilation[mainCompilation]!! }
+            val originalMainClassesDirs = project.objects.fileCollection().from(
+                mainCompilation.compileTaskProvider.flatMap { (it as KotlinCompileTool).destinationDirectory }
             )
-
-            // KGP >= 1.7.0 has breaking changes in task hierarchy:
-            // https://youtrack.jetbrains.com/issue/KT-32805#focus=Comments-27-5915479.0-0
-            val (majorVersion, minorVersion) = getKotlinPluginVersion()
-                .split('.')
-                .take(2)
-                .map { it.toInt() }
-            if (majorVersion == 1 && minorVersion < 7) {
-                (tasks.findByName(compilation.compileKotlinTaskName) as? AbstractCompile)?.classpath =
-                    originalMainClassesDirs + compilation.compileDependencyFiles - mainCompilation.output.classesDirs
-            } else {
-                (tasks.findByName(compilation.compileKotlinTaskName) as? AbstractKotlinCompileTool<*>)
-                    ?.libraries
-                    ?.setFrom(
-                        originalMainClassesDirs + compilation.compileDependencyFiles - mainCompilation.output.classesDirs
-                    )
+            // compilationTask.destinationDirectory was changed from build/classes/kotlin/main to build/classes/atomicfu-orig/main,
+            // so we need to update libraries
+            (tasks.findByName(compilation.compileKotlinTaskName) as? AbstractKotlinCompileTool<*>)
+                ?.libraries
+                ?.setFrom(
+                    originalMainClassesDirs + compilation.compileDependencyFiles
+                )
+            if (transformTask != null) {
+                // if transform task was not created, then originalMainClassesDirs == mainCompilation.output.classesDirs
+                (tasks.findByName("${target.name}${compilation.name.capitalize()}") as? Test)?.classpath =
+                    originalMainClassesDirs + (compilation as KotlinCompilationToRunnableFiles).runtimeDependencyFiles - mainCompilation.output.classesDirs
             }
-
-            (tasks.findByName("${target.name}${compilation.name.capitalize()}") as? Test)?.classpath =
-                originalMainClassesDirs + (compilation as KotlinCompilationToRunnableFiles).runtimeDependencyFiles - mainCompilation.output.classesDirs
-
             compilation.compileKotlinTask.setFriendPaths(originalMainClassesDirs)
         }
     }
 }
 
-fun Project.sourceSetsByCompilation(): Map<KotlinSourceSet, List<KotlinCompilation<*>>> {
-    val sourceSetsByCompilation = hashMapOf<KotlinSourceSet, MutableList<KotlinCompilation<*>>>()
-    withKotlinTargets { target ->
-        target.compilations.forEach { compilation ->
-            compilation.allKotlinSourceSets.forEach { sourceSet ->
-                sourceSetsByCompilation.getOrPut(sourceSet) { mutableListOf() }.add(compilation)
-            }
-        }
-    }
-    return sourceSetsByCompilation
-}
-
-fun Project.configureMultiplatformPluginDependencies(version: String) {
-    if (rootProject.getBooleanProperty("kotlin.mpp.enableGranularSourceSetsMetadata")) {
-        addCompilerPluginDependency()
-        val mainConfigurationName = project.extensions.getByType(KotlinMultiplatformExtension::class.java).sourceSets
-            .getByName(KotlinSourceSet.COMMON_MAIN_SOURCE_SET_NAME)
-            .compileOnlyConfigurationName
-        dependencies.add(mainConfigurationName, getAtomicfuDependencyNotation(Platform.MULTIPLATFORM, version))
-
-        val testConfigurationName = project.extensions.getByType(KotlinMultiplatformExtension::class.java).sourceSets
-            .getByName(KotlinSourceSet.COMMON_TEST_SOURCE_SET_NAME)
-            .implementationConfigurationName
-        dependencies.add(testConfigurationName, getAtomicfuDependencyNotation(Platform.MULTIPLATFORM, version))
-
-        // For each source set that is only used in Native compilations, add an implementation dependency so that it
-        // gets published and is properly consumed as a transitive dependency:
-        sourceSetsByCompilation().forEach { (sourceSet, compilations) ->
-            val isSharedNativeSourceSet = compilations.all {
-                it.platformType == KotlinPlatformType.common || it.platformType == KotlinPlatformType.native
-            }
-            if (isSharedNativeSourceSet) {
-                val configuration = sourceSet.implementationConfigurationName
-                dependencies.add(configuration, getAtomicfuDependencyNotation(Platform.MULTIPLATFORM, version))
-            }
-        }
-    } else {
-        sourceSetsByCompilation().forEach { (sourceSet, compilations) ->
-            addCompilerPluginDependency()
-            val platformTypes = compilations.map { it.platformType }.toSet()
-            val compilationNames = compilations.map { it.compilationName }.toSet()
-            if (compilationNames.size != 1)
-                error("Source set '${sourceSet.name}' of project '$name' is part of several compilations $compilationNames")
-            val compilationType = compilationNames.single().compilationNameToType()
-                ?: return@forEach // skip unknown compilations
-            val platform =
-                if (platformTypes.size > 1) Platform.MULTIPLATFORM else // mix of platform types -> "common"
-                    when (platformTypes.single()) {
-                        KotlinPlatformType.common -> Platform.MULTIPLATFORM
-                        KotlinPlatformType.jvm, KotlinPlatformType.androidJvm -> Platform.JVM
-                        KotlinPlatformType.js -> Platform.JS
-                        KotlinPlatformType.native, KotlinPlatformType.wasm -> Platform.NATIVE
-                    }
-            val configurationName = when {
-                // impl dependency for native (there is no transformation)
-                platform == Platform.NATIVE -> sourceSet.implementationConfigurationName
-                // compileOnly dependency for main compilation (commonMain, jvmMain, jsMain)
-                compilationType == CompilationType.MAIN -> sourceSet.compileOnlyConfigurationName
-                // impl dependency for tests
-                else -> sourceSet.implementationConfigurationName
-            }
-            dependencies.add(configurationName, getAtomicfuDependencyNotation(platform, version))
-        }
-    }
-}
-
-fun Project.configureJvmTransformation(
-    testTaskName: String,
-    createTransformTask: (sourceSet: SourceSet, transformedDir: File, originalDir: FileCollection) -> Task
-) {
-    val config = config
-    sourceSets.all { sourceSet ->
-        val compilationType = sourceSet.name.sourceSetNameToType()
-            ?: return@all // skip unknown types
-        val classesDirs = (sourceSet.output.classesDirs as ConfigurableFileCollection).from as Collection<Any>
-        // make copy of original classes directory
-        val originalClassesDirs: FileCollection = project.files(classesDirs.toTypedArray()).filter { it.exists() }
-        (sourceSet as ExtensionAware).extensions.add(ORIGINAL_DIR_NAME, originalClassesDirs)
-        val transformedClassesDir =
-            project.buildDir.resolve("classes/atomicfu/${sourceSet.name}")
-        // make transformedClassesDir the source path for output.classesDirs
-        (sourceSet.output.classesDirs as ConfigurableFileCollection).setFrom(transformedClassesDir)
-        val transformTask = createTransformTask(sourceSet, transformedClassesDir, originalClassesDirs)
-        //now transformTask is responsible for compiling this source set into the classes directory
-        sourceSet.compiledBy(transformTask)
-        (tasks.findByName(sourceSet.jarTaskName) as? Jar)?.apply {
-            setupJarManifest(multiRelease = config.jvmVariant.toJvmVariant() == JvmVariant.BOTH)
-        }
-        // test should compile and run against original production binaries
-        if (compilationType == CompilationType.TEST) {
-            val mainSourceSet = sourceSets.getByName(SourceSet.MAIN_SOURCE_SET_NAME)
-            val originalMainClassesDirs = project.files(
-                // use Callable because there is no guarantee that main is configured before test
-                Callable { (mainSourceSet as ExtensionAware).extensions.getByName(ORIGINAL_DIR_NAME) as FileCollection }
-            )
-
-            (tasks.findByName(testTaskName) as? AbstractCompile)?.run {
-                classpath =
-                    originalMainClassesDirs + sourceSet.compileClasspath - mainSourceSet.output.classesDirs
-
-                (this as? KotlinCompile<*>)?.setFriendPaths(originalMainClassesDirs)
-            }
-
-            // todo: fix test runtime classpath for JS?
-            (tasks.findByName(JavaPlugin.TEST_TASK_NAME) as? Test)?.classpath =
-                originalMainClassesDirs + sourceSet.runtimeClasspath - mainSourceSet.output.classesDirs
-        }
-    }
-}
-
-fun String.toJvmVariant(): JvmVariant = enumValueOf(toUpperCase(Locale.US))
+private fun String.toJvmVariant(): JvmVariant = enumValueOf(toUpperCase(Locale.US))
 
-fun Project.createJvmTransformTask(compilation: KotlinCompilation<*>): AtomicFUTransformTask =
-    tasks.create(
+private fun Project.registerJvmTransformTask(compilation: KotlinCompilation<*>): TaskProvider<AtomicFUTransformTask> =
+    tasks.register(
         "transform${compilation.target.name.capitalize()}${compilation.name.capitalize()}Atomicfu",
         AtomicFUTransformTask::class.java
     )
 
-fun Project.createJsTransformTask(compilation: KotlinCompilation<*>): AtomicFUTransformJsTask =
-    tasks.create(
+private fun Project.registerJsTransformTask(compilation: KotlinCompilation<*>): TaskProvider<AtomicFUTransformJsTask> =
+    tasks.register(
         "transform${compilation.target.name.capitalize()}${compilation.name.capitalize()}Atomicfu",
         AtomicFUTransformJsTask::class.java
     )
 
-fun Project.createJvmTransformTask(sourceSet: SourceSet): AtomicFUTransformTask =
-    tasks.create(sourceSet.getTaskName("transform", "atomicfuClasses"), AtomicFUTransformTask::class.java)
-
-fun AtomicFUTransformTask.configureJvmTask(
+private fun TaskProvider<AtomicFUTransformTask>.configureJvmTask(
     classpath: FileCollection,
     classesTaskName: String,
-    transformedClassesDir: File,
+    transformedClassesDir: Provider<Directory>,
     originalClassesDir: FileCollection,
     config: AtomicFUPluginExtension
-): ConventionTask =
+): TaskProvider<AtomicFUTransformTask> =
     apply {
-        dependsOn(classesTaskName)
-        classPath = classpath
-        inputFiles = originalClassesDir
-        outputDir = transformedClassesDir
-        jvmVariant = config.jvmVariant
-        verbose = config.verbose
+        configure {
+            it.dependsOn(classesTaskName)
+            it.classPath = classpath
+            it.inputFiles = originalClassesDir
+            it.destinationDirectory.value(transformedClassesDir)
+            it.jvmVariant = config.jvmVariant
+            it.verbose = config.verbose
+        }
     }
 
-fun AtomicFUTransformJsTask.configureJsTask(
+private fun TaskProvider<AtomicFUTransformJsTask>.configureJsTask(
     classesTaskName: String,
-    transformedClassesDir: File,
+    transformedClassesDir: Provider<Directory>,
     originalClassesDir: FileCollection,
     config: AtomicFUPluginExtension
-): ConventionTask =
+): TaskProvider<AtomicFUTransformJsTask> =
     apply {
-        dependsOn(classesTaskName)
-        inputFiles = originalClassesDir
-        outputDir = transformedClassesDir
-        verbose = config.verbose
+        configure {
+            it.dependsOn(classesTaskName)
+            it.inputFiles = originalClassesDir
+            it.destinationDirectory.value(transformedClassesDir)
+            it.verbose = config.verbose
+        }
     }
 
-fun Jar.setupJarManifest(multiRelease: Boolean) {
+private fun Jar.setupJarManifest(multiRelease: Boolean) {
     if (multiRelease) {
         manifest.attributes.apply {
             put("Multi-Release", "true")
@@ -491,9 +468,6 @@ fun Jar.setupJarManifest(multiRelease: Boolean) {
     }
 }
 
-val Project.sourceSets: SourceSetContainer
-    get() = convention.getPlugin(JavaPluginConvention::class.java).sourceSets
-
 class AtomicFUPluginExtension(pluginVersion: String?) {
     var dependenciesVersion = pluginVersion
     var transformJvm = true
@@ -503,13 +477,29 @@ class AtomicFUPluginExtension(pluginVersion: String?) {
 }
 
 @CacheableTask
-open class AtomicFUTransformTask : ConventionTask() {
+abstract class AtomicFUTransformTask : ConventionTask() {
+    @get:Inject
+    internal abstract val providerFactory: ProviderFactory
+
+    @get:Inject
+    internal abstract val projectLayout: ProjectLayout
+
     @PathSensitive(PathSensitivity.RELATIVE)
     @InputFiles
     lateinit var inputFiles: FileCollection
 
-    @OutputDirectory
-    lateinit var outputDir: File
+    @Suppress("unused")
+    @Deprecated(
+        message = "Replaced with 'destinationDirectory'",
+        replaceWith = ReplaceWith("destinationDirectory")
+    )
+    @get:Internal
+    var outputDir: File
+        get() = destinationDirectory.get().asFile
+        set(value) { destinationDirectory.value(projectLayout.dir(providerFactory.provider { value })) }
+
+    @get:OutputDirectory
+    abstract val destinationDirectory: DirectoryProperty
 
     @Classpath
     @InputFiles
@@ -525,7 +515,7 @@ open class AtomicFUTransformTask : ConventionTask() {
     fun transform() {
         val cp = classPath.files.map { it.absolutePath }
         inputFiles.files.forEach { inputDir ->
-            AtomicFUTransformer(cp, inputDir, outputDir).let { t ->
+            AtomicFUTransformer(cp, inputDir, destinationDirectory.get().asFile).let { t ->
                 t.jvmVariant = jvmVariant.toJvmVariant()
                 t.verbose = verbose
                 t.transform()
@@ -535,13 +525,30 @@ open class AtomicFUTransformTask : ConventionTask() {
 }
 
 @CacheableTask
-open class AtomicFUTransformJsTask : ConventionTask() {
+abstract class AtomicFUTransformJsTask : ConventionTask() {
+
+    @get:Inject
+    internal abstract val providerFactory: ProviderFactory
+
+    @get:Inject
+    internal abstract val projectLayout: ProjectLayout
+
     @PathSensitive(PathSensitivity.RELATIVE)
     @InputFiles
     lateinit var inputFiles: FileCollection
 
-    @OutputDirectory
-    lateinit var outputDir: File
+    @Suppress("unused")
+    @Deprecated(
+        message = "Replaced with 'destinationDirectory'",
+        replaceWith = ReplaceWith("destinationDirectory")
+    )
+    @get:Internal
+    var outputDir: File
+        get() = destinationDirectory.get().asFile
+        set(value) { destinationDirectory.value(projectLayout.dir(providerFactory.provider { value })) }
+
+    @get:OutputDirectory
+    abstract val destinationDirectory: DirectoryProperty
 
     @Input
     var verbose = false
@@ -549,7 +556,7 @@ open class AtomicFUTransformJsTask : ConventionTask() {
     @TaskAction
     fun transform() {
         inputFiles.files.forEach { inputDir ->
-            AtomicFUTransformerJS(inputDir, outputDir).let { t ->
+            AtomicFUTransformerJS(inputDir, destinationDirectory.get().asFile).let { t ->
                 t.verbose = verbose
                 t.transform()
             }
diff --git a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/Assert.kt b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/Assert.kt
index f55e38a..191dbac 100644
--- a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/Assert.kt
+++ b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/Assert.kt
@@ -28,5 +28,9 @@ internal fun BuildResult.assertTaskUpToDate(task: String) {
 }
 
 private fun BuildResult.assertTaskOutcome(taskOutcome: TaskOutcome, taskName: String) {
-    assertEquals(taskOutcome, task(taskName)?.outcome)
+    assertEquals(
+        taskOutcome,
+        task(taskName)?.outcome,
+        "Task $taskName does not have ${taskOutcome.name} outcome"
+    )
 }
diff --git a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/TestDsl.kt b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/TestDsl.kt
index 2541b41..ed11b10 100644
--- a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/TestDsl.kt
+++ b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/internal/TestDsl.kt
@@ -127,6 +127,12 @@ internal class Runner {
 internal fun readFileList(fileName: String): String =
     getFile(fileName).readText()
 
+internal fun getFileOrNull(fileName: String): File? {
+    return BaseKotlinGradleTest::class.java.classLoader.getResource(fileName)?.let {
+        resource -> File(resource.toURI())
+    }
+}
+
 internal fun getFile(fileName: String): File {
     val resource = BaseKotlinGradleTest::class.java.classLoader.getResource(fileName)
         ?: throw IllegalStateException("Could not find resource '$fileName'")
diff --git a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/BaseKotlinGradleTest.kt b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/BaseKotlinGradleTest.kt
index e9ff7bb..7ae5bdc 100644
--- a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/BaseKotlinGradleTest.kt
+++ b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/BaseKotlinGradleTest.kt
@@ -26,6 +26,9 @@ abstract class BaseKotlinGradleTest(private val projectName: String) {
         createProject()
         runner {
             arguments.add(":build")
+            getFileOrNull("kotlin-repo-url.txt")?.let { kotlinRepoURLResource ->
+                arguments.add("-Pkotlin_repo_url=${kotlinRepoURLResource.readText()}")
+            }
         }
     }
 
diff --git a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JsProjectTest.kt b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JsProjectTest.kt
deleted file mode 100644
index 0b34955..0000000
--- a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JsProjectTest.kt
+++ /dev/null
@@ -1,49 +0,0 @@
-package kotlinx.atomicfu.plugin.gradle.test
-
-import kotlinx.atomicfu.plugin.gradle.internal.*
-import kotlinx.atomicfu.plugin.gradle.internal.BaseKotlinScope
-import org.junit.Test
-
-/**
- * Test that ensures correctness of `atomicfu-gradle-plugin` application to the JS project:
- * - post-compilation js transformation tasks are created
- *   (legacy transformation is tested here, compiler plugin is not applied).
- * - original non-transformed classes are not left in compile/runtime classpath.
- */
-class JsLegacyTransformationTest : BaseKotlinGradleTest("js-simple") {
-
-    override fun BaseKotlinScope.createProject() {
-        buildGradleKts {
-            resolve("projects/js-simple/js-simple.gradle.kts")
-        }
-        settingsGradleKts {
-            resolve("projects/js-simple/settings.gradle.kts")
-        }
-        dir("src/main/kotlin") {}
-        kotlin("IntArithmetic.kt", "main") {
-            resolve("projects/js-simple/src/main/kotlin/IntArithmetic.kt")
-        }
-        dir("src/test/kotlin") {}
-        kotlin("ArithmeticTest.kt", "test") {
-            resolve("projects/js-simple/src/test/kotlin/ArithmeticTest.kt")
-        }
-    }
-
-    @Test
-    fun testPluginApplication() =
-        checkTaskOutcomes(
-            executedTasks = listOf(
-                ":compileKotlinJs",
-                ":transformJsMainAtomicfu",
-                ":compileTestKotlinJs",
-                ":transformJsTestAtomicfu"
-            ),
-            excludedTasks = emptyList()
-        )
-
-    @Test
-    fun testClasspath() {
-        runner.build()
-        checkJsCompilationClasspath()
-    }
-}
diff --git a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JvmProjectTest.kt b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JvmProjectTest.kt
index 2545e0e..282df80 100644
--- a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JvmProjectTest.kt
+++ b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/JvmProjectTest.kt
@@ -35,9 +35,9 @@ class JvmLegacyTransformationTest : BaseKotlinGradleTest("jvm-simple") {
         checkTaskOutcomes(
             executedTasks = listOf(
                 ":compileKotlin",
-                ":transformAtomicfuClasses",
+                ":transformMainAtomicfu",
                 ":compileTestKotlin",
-                ":transformTestAtomicfuClasses"
+                ":transformTestAtomicfu"
             ),
             excludedTasks = emptyList()
         )
@@ -46,7 +46,7 @@ class JvmLegacyTransformationTest : BaseKotlinGradleTest("jvm-simple") {
     fun testClasspath() {
         runner.build()
         checkJvmCompilationClasspath(
-            originalClassFile = "build/classes/kotlin/main/IntArithmetic.class",
+            originalClassFile = "build/classes/atomicfu-orig/main/IntArithmetic.class",
             transformedClassFile = "build/classes/atomicfu/main/IntArithmetic.class"
         )
     }
@@ -95,8 +95,8 @@ class JvmIrTransformationTest : BaseKotlinGradleTest("jvm-simple") {
                 ":compileTestKotlin"
             ),
             excludedTasks = listOf(
-                ":transformAtomicfuClasses",
-                ":transformTestAtomicfuClasses"
+                ":transformAtomicfu",
+                ":transformTestAtomicfu"
             )
         )
 
diff --git a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/MppProjectTest.kt b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/MppProjectTest.kt
index e95b091..3e1f608 100644
--- a/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/MppProjectTest.kt
+++ b/atomicfu-gradle-plugin/src/test/kotlin/kotlinx/atomicfu/plugin/gradle/test/MppProjectTest.kt
@@ -3,63 +3,6 @@ package kotlinx.atomicfu.plugin.gradle.test
 import kotlinx.atomicfu.plugin.gradle.internal.*
 import org.junit.*
 
-/**
- * Test that ensures correctness of `atomicfu-gradle-plugin` application to the MPP project:
- * - post-compilation bytecode transformation tasks are created
- *   (legacy transformation is tested here, compiler plugin is not applied).
- * - original non-transformed classes are not left in compile/runtime classpath.
- * - no `kotlinx/atomicfu` references are left in the transformed bytecode.
- */
-class MppLegacyTransformationTest : BaseKotlinGradleTest("mpp-simple") {
-
-    override fun BaseKotlinScope.createProject() {
-        buildGradleKts {
-            resolve("projects/mpp-simple/mpp-simple.gradle.kts")
-        }
-        settingsGradleKts {
-            resolve("projects/mpp-simple/settings.gradle.kts")
-        }
-        dir("src/commonMain/kotlin") {}
-        kotlin("IntArithmetic.kt", "commonMain") {
-            resolve("projects/mpp-simple/src/commonMain/kotlin/IntArithmetic.kt")
-        }
-        dir("src/commonTest/kotlin") {}
-        kotlin("ArithmeticTest.kt", "commonTest") {
-            resolve("projects/mpp-simple/src/commonTest/kotlin/ArithmeticTest.kt")
-        }
-    }
-
-    @Test
-    fun testPluginApplication() =
-        checkTaskOutcomes(
-            executedTasks = listOf(
-                ":compileKotlinJvm",
-                ":compileTestKotlinJvm",
-                ":transformJvmMainAtomicfu",
-                ":transformJvmTestAtomicfu",
-                ":compileKotlinJs",
-                ":transformJsMainAtomicfu"
-            ),
-            excludedTasks = emptyList()
-        )
-
-    @Test
-    fun testClasspath() {
-        runner.build()
-        checkJvmCompilationClasspath(
-            originalClassFile = "build/classes/kotlin/jvm/main/IntArithmetic.class",
-            transformedClassFile = "build/classes/atomicfu/jvm/main/IntArithmetic.class"
-        )
-        checkJsCompilationClasspath()
-    }
-
-    @Test
-    fun testAtomicfuReferences() {
-        runner.build()
-        checkBytecode("build/classes/atomicfu/jvm/main/IntArithmetic.class")
-    }
-}
-
 /**
  * Test that ensures correctness of `atomicfu-gradle-plugin` application to the MPP project,
  * - JVM IR compiler plugin transformation (kotlinx.atomicfu.enableJvmIrTransformation=true)
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/js-simple.gradle.kts b/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/js-simple.gradle.kts
deleted file mode 100644
index 37a41e5..0000000
--- a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/js-simple.gradle.kts
+++ /dev/null
@@ -1,38 +0,0 @@
-import kotlinx.atomicfu.plugin.gradle.*
-
-buildscript {
-    dependencies {
-        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.17.0")
-    }
-}
-
-plugins {
-    kotlin("js")
-}
-
-apply(plugin = "kotlinx-atomicfu")
-
-repositories {
-    mavenLocal()
-    mavenCentral()
-}
-
-dependencies {
-    implementation(kotlin("stdlib-js"))
-    implementation(kotlin("test-junit"))
-    implementation("org.jetbrains.kotlin:kotlin-test-js")
-}
-
-kotlin {
-    js {
-        nodejs()
-    }
-
-    tasks.named("compileTestKotlinJs") {
-        doLast {
-            file("$buildDir/test_compile_js_classpath.txt").writeText(
-                target.compilations["test"].compileDependencyFiles.joinToString("\n")
-            )
-        }
-    }
-}
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/settings.gradle.kts b/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/settings.gradle.kts
deleted file mode 100644
index bd39e74..0000000
--- a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/settings.gradle.kts
+++ /dev/null
@@ -1 +0,0 @@
-rootProject.name = "js-simple"
\ No newline at end of file
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/src/main/kotlin/IntArithmetic.kt b/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/src/main/kotlin/IntArithmetic.kt
deleted file mode 100644
index 5becfff..0000000
--- a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/src/main/kotlin/IntArithmetic.kt
+++ /dev/null
@@ -1,16 +0,0 @@
-/*
- * Copyright 2017-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
- */
-
-import kotlinx.atomicfu.*
-
-class IntArithmetic {
-    val _x = atomic(0)
-    val x get() = _x.value
-}
-
-fun doWork(a: IntArithmetic) {
-    a._x.getAndSet(3)
-    a._x.compareAndSet(3, 8)
-}
-
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/jvm-simple.gradle.kts b/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/jvm-simple.gradle.kts
index db644ef..4a6b008 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/jvm-simple.gradle.kts
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/jvm-simple.gradle.kts
@@ -15,6 +15,7 @@ apply(plugin = "kotlinx-atomicfu")
 
 repositories {
     mavenCentral()
+    (properties["kotlin_repo_url"] as? String)?.let { maven(it) }
 }
 
 dependencies {
@@ -23,6 +24,11 @@ dependencies {
 }
 
 kotlin {
+    java {
+        targetCompatibility = JavaVersion.VERSION_1_8
+        sourceCompatibility = JavaVersion.VERSION_1_8
+    }
+
     tasks.compileTestKotlin {
         doLast {
             file("$buildDir/test_compile_jvm_classpath.txt").writeText(
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/main/kotlin/IntArithmetic.kt b/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/main/kotlin/IntArithmetic.kt
index 13d0fd6..5140825 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/main/kotlin/IntArithmetic.kt
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/main/kotlin/IntArithmetic.kt
@@ -5,13 +5,13 @@
 import kotlinx.atomicfu.*
 
 class IntArithmetic {
-    val _x = atomic(0)
+    private val _x = atomic(0)
     val x get() = _x.value
-}
 
-fun doWork(a: IntArithmetic) {
-    a._x.getAndSet(3)
-    a._x.compareAndSet(3, 8)
+    fun doWork() {
+        _x.getAndSet(3)
+        _x.compareAndSet(3, 8)
+    }
 }
 
 // minimal example that forces ASM to call AtomicFUTransformer.CW.getCommonSuperClass
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/test/kotlin/ArithmeticTest.kt b/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/test/kotlin/ArithmeticTest.kt
index ab10e9b..e75e8ea 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/test/kotlin/ArithmeticTest.kt
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/jvm-simple/src/test/kotlin/ArithmeticTest.kt
@@ -8,7 +8,7 @@ class ArithmeticTest {
     @Test
     fun testInt() {
         val a = IntArithmetic()
-        doWork(a)
+        a.doWork()
         check(a.x == 8)
     }
 }
\ No newline at end of file
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_js_legacy b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_js_legacy
new file mode 100644
index 0000000..31585e0
--- /dev/null
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_js_legacy
@@ -0,0 +1 @@
+kotlin.js.compiler=legacy
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_jvm b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_jvm
index fa37a2c..399d39c 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_jvm
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/gradle.properties_jvm
@@ -1 +1,2 @@
 kotlinx.atomicfu.enableJvmIrTransformation=true
+kotlin.js.compiler=ir
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/mpp-simple.gradle.kts b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/mpp-simple.gradle.kts
index ed15d3d..64aff01 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/mpp-simple.gradle.kts
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/mpp-simple.gradle.kts
@@ -14,6 +14,7 @@ apply(plugin = "kotlinx-atomicfu")
 
 repositories {
     mavenCentral()
+    (properties["kotlin_repo_url"] as? String)?.let { maven(it) }
 }
 
 kotlin {
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonMain/kotlin/IntArithmetic.kt b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonMain/kotlin/IntArithmetic.kt
index 13d0fd6..5140825 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonMain/kotlin/IntArithmetic.kt
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonMain/kotlin/IntArithmetic.kt
@@ -5,13 +5,13 @@
 import kotlinx.atomicfu.*
 
 class IntArithmetic {
-    val _x = atomic(0)
+    private val _x = atomic(0)
     val x get() = _x.value
-}
 
-fun doWork(a: IntArithmetic) {
-    a._x.getAndSet(3)
-    a._x.compareAndSet(3, 8)
+    fun doWork() {
+        _x.getAndSet(3)
+        _x.compareAndSet(3, 8)
+    }
 }
 
 // minimal example that forces ASM to call AtomicFUTransformer.CW.getCommonSuperClass
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonTest/kotlin/ArithmeticTest.kt b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonTest/kotlin/ArithmeticTest.kt
index ab10e9b..e75e8ea 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonTest/kotlin/ArithmeticTest.kt
+++ b/atomicfu-gradle-plugin/src/test/resources/projects/mpp-simple/src/commonTest/kotlin/ArithmeticTest.kt
@@ -8,7 +8,7 @@ class ArithmeticTest {
     @Test
     fun testInt() {
         val a = IntArithmetic()
-        doWork(a)
+        a.doWork()
         check(a.x == 8)
     }
 }
\ No newline at end of file
diff --git a/atomicfu-maven-plugin/api/atomicfu-maven-plugin.api b/atomicfu-maven-plugin/api/atomicfu-maven-plugin.api
new file mode 100644
index 0000000..ad76fe2
--- /dev/null
+++ b/atomicfu-maven-plugin/api/atomicfu-maven-plugin.api
@@ -0,0 +1,19 @@
+public final class kotlinx/atomicfu/plugin/TransformMojo : org/apache/maven/plugin/AbstractMojo {
+	public field classpath Ljava/util/List;
+	public field input Ljava/io/File;
+	public field jvmVariant Lkotlinx/atomicfu/transformer/JvmVariant;
+	public field output Ljava/io/File;
+	public fun <init> ()V
+	public fun execute ()V
+	public final fun getClasspath ()Ljava/util/List;
+	public final fun getInput ()Ljava/io/File;
+	public final fun getJvmVariant ()Lkotlinx/atomicfu/transformer/JvmVariant;
+	public final fun getOutput ()Ljava/io/File;
+	public final fun getVerbose ()Z
+	public final fun setClasspath (Ljava/util/List;)V
+	public final fun setInput (Ljava/io/File;)V
+	public final fun setJvmVariant (Lkotlinx/atomicfu/transformer/JvmVariant;)V
+	public final fun setOutput (Ljava/io/File;)V
+	public final fun setVerbose (Z)V
+}
+
diff --git a/atomicfu-maven-plugin/build.gradle b/atomicfu-maven-plugin/build.gradle
index a165769..5756df9 100644
--- a/atomicfu-maven-plugin/build.gradle
+++ b/atomicfu-maven-plugin/build.gradle
@@ -3,72 +3,35 @@
  */
 
 apply plugin: 'kotlin'
-apply plugin: 'maven'
+apply plugin: 'maven-publish'
 
 apply from: rootProject.file('gradle/compile-options.gradle')
 
 ext.configureKotlin()
 
 dependencies {
-    compile "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
-    compile project(":atomicfu-transformer")
-    compile "org.apache.maven:maven-core:$maven_version"
-    compile "org.apache.maven:maven-plugin-api:$maven_version"
-    compile 'org.apache.maven.plugin-tools:maven-plugin-annotations:3.5'
+    api "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
+    api project(":atomicfu-transformer")
+    api "org.apache.maven:maven-core:$maven_version"
+    api "org.apache.maven:maven-plugin-api:$maven_version"
+    api 'org.apache.maven.plugin-tools:maven-plugin-annotations:3.5'
 }
 
-def pomFile = file("$buildDir/pom.xml")
 def outputDir = compileKotlin.destinationDirectory
-def buildSnapshots = rootProject.properties['build_snapshot_train'] != null
 
-evaluationDependsOn(':atomicfu-transformer')
-
-task generatePomFile(dependsOn: [compileKotlin, ':atomicfu-transformer:publishToMavenLocal']) {
-    def buildDir = project.buildDir // because Maven model also has "project"
-    outputs.file(pomFile)
-    doLast {
-        install.repositories.mavenInstaller.pom.with {
-            groupId = project.group
-            artifactId = project.name
-            version = project.version
-            packaging = 'maven-plugin'
-
-            withXml {
-                asNode().with {
-                    appendNode('build').with {
-                        appendNode('directory', buildDir)
-                        appendNode('outputDirectory', outputDir.get().getAsFile())
-                    }
-                    appendNode('properties').with {
-                        appendNode('project.build.sourceEncoding', 'UTF-8')
-                    }
-                    appendNode('repositories').with {
-                        appendNode('repository').with {
-                            appendNode('id', 'dev')
-                            appendNode('url', 'https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev')
-                        }
-
-                        if (buildSnapshots) {
-                            appendNode('repository').with {
-                                appendNode('id', 'kotlin-snapshots')
-                                appendNode('url', "https://oss.sonatype.org/content/repositories/snapshots")
-                            }
-                        }
-                    }
-                }
-            }
-        }
-        install.repositories.mavenInstaller.pom.writeTo(pomFile)
-        assert pomFile.file, "$pomFile: was not generated"
-        logger.info("POM is generated in $pomFile")
+publishing.publications {
+    maven(MavenPublication) {
+        MavenPomConfiguration.configureMavenPluginPomAttributes(pom, project, outputDir.get().getAsFile().path)
     }
 }
 
 String mavenUserHome = System.getProperty("maven.user.home")
 String mavenRepoLocal = System.getProperty("maven.repo.local")
 
+def pomFile = tasks.named("generatePomFileForMavenPublication", GenerateMavenPom).map { it.destination }.get()
+
 // runs the plugin description generator
-task generatePluginDescriptor(type: Exec, dependsOn: generatePomFile) {
+task generatePluginDescriptor(type: Exec, dependsOn: [generatePomFileForMavenPublication, ':atomicfu-transformer:publishToMavenLocal']) {
     def pluginDescriptorFile = outputDir.file('META-INF/maven/plugin.xml')
 
     workingDir projectDir
@@ -77,11 +40,11 @@ task generatePluginDescriptor(type: Exec, dependsOn: generatePomFile) {
     if (mavenUserHome != null) args.add("-Dmaven.user.home=${new File(mavenUserHome).getAbsolutePath()}")
     if (mavenRepoLocal != null) args.add("-Dmaven.repo.local=${new File(mavenRepoLocal).getAbsolutePath()}")
     args.addAll([
-        '--settings', './settings.xml',
-        '--errors',
-        '--batch-mode',
-        '--file', pomFile.toString(),
-        'org.apache.maven.plugins:maven-plugin-plugin:3.5.1:descriptor'
+            '--settings', './settings.xml',
+            '--errors',
+            '--batch-mode',
+            '--file', pomFile.toString(),
+            'org.apache.maven.plugins:maven-plugin-plugin:3.5.1:descriptor'
     ])
     commandLine args
     doLast {
diff --git a/atomicfu-transformer/api/atomicfu-transformer.api b/atomicfu-transformer/api/atomicfu-transformer.api
new file mode 100644
index 0000000..1faeac7
--- /dev/null
+++ b/atomicfu-transformer/api/atomicfu-transformer.api
@@ -0,0 +1,235 @@
+public final class kotlinx/atomicfu/transformer/AbortKt {
+	public static final fun abort (Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;)Ljava/lang/Void;
+	public static synthetic fun abort$default (Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;ILjava/lang/Object;)Ljava/lang/Void;
+}
+
+public final class kotlinx/atomicfu/transformer/AbortTransform : java/lang/Exception {
+	public fun <init> (Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;)V
+	public synthetic fun <init> (Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public final fun getI ()Lorg/objectweb/asm/tree/AbstractInsnNode;
+}
+
+public final class kotlinx/atomicfu/transformer/AsmUtilKt {
+	public static final fun accessToInvokeOpcode (I)I
+	public static final fun atIndex (Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/tree/InsnList;)Ljava/lang/String;
+	public static final fun forVarLoads (ILorg/objectweb/asm/tree/LabelNode;Lorg/objectweb/asm/tree/LabelNode;Lkotlin/jvm/functions/Function1;)V
+	public static final fun getInsnOrNull (Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/tree/AbstractInsnNode;Lkotlin/jvm/functions/Function1;)Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public static final fun getLine (Lorg/objectweb/asm/tree/AbstractInsnNode;)Ljava/lang/Integer;
+	public static final fun getNextUseful (Lorg/objectweb/asm/tree/AbstractInsnNode;)Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public static final fun getOwnerPackageName (Ljava/lang/String;)Ljava/lang/String;
+	public static final fun getThisOrPrevUseful (Lorg/objectweb/asm/tree/AbstractInsnNode;)Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public static final fun isAload (Lorg/objectweb/asm/tree/AbstractInsnNode;I)Z
+	public static final fun isAreturn (Lorg/objectweb/asm/tree/AbstractInsnNode;)Z
+	public static final fun isGetField (Lorg/objectweb/asm/tree/AbstractInsnNode;Ljava/lang/String;)Z
+	public static final fun isGetFieldOrGetStatic (Lorg/objectweb/asm/tree/AbstractInsnNode;)Z
+	public static final fun isGetStatic (Lorg/objectweb/asm/tree/AbstractInsnNode;Ljava/lang/String;)Z
+	public static final fun isInvokeVirtual (Lorg/objectweb/asm/tree/AbstractInsnNode;)Z
+	public static final fun isReturn (Lorg/objectweb/asm/tree/AbstractInsnNode;)Z
+	public static final fun isTypeReturn (Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/Type;)Z
+	public static final fun listUseful (Lorg/objectweb/asm/tree/InsnList;I)Ljava/util/List;
+	public static synthetic fun listUseful$default (Lorg/objectweb/asm/tree/InsnList;IILjava/lang/Object;)Ljava/util/List;
+	public static final fun localVar (Lorg/objectweb/asm/tree/MethodNode;ILorg/objectweb/asm/tree/AbstractInsnNode;)Lorg/objectweb/asm/tree/LocalVariableNode;
+	public static final fun nextVarLoad (ILorg/objectweb/asm/tree/AbstractInsnNode;)Lorg/objectweb/asm/tree/VarInsnNode;
+	public static final fun toText (Lorg/objectweb/asm/tree/AbstractInsnNode;)Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformer : kotlinx/atomicfu/transformer/AtomicFUTransformerBase {
+	public fun <init> (Ljava/util/List;Ljava/io/File;Ljava/io/File;Lkotlinx/atomicfu/transformer/JvmVariant;)V
+	public synthetic fun <init> (Ljava/util/List;Ljava/io/File;Ljava/io/File;Lkotlinx/atomicfu/transformer/JvmVariant;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public final fun getJvmVariant ()Lkotlinx/atomicfu/transformer/JvmVariant;
+	public final fun setJvmVariant (Lkotlinx/atomicfu/transformer/JvmVariant;)V
+	public fun transform ()V
+}
+
+public abstract class kotlinx/atomicfu/transformer/AtomicFUTransformerBase {
+	public fun <init> (Ljava/io/File;Ljava/io/File;)V
+	protected final fun debug (Ljava/lang/String;Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;)V
+	public static synthetic fun debug$default (Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase;Ljava/lang/String;Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;ILjava/lang/Object;)V
+	protected final fun div (Ljava/io/File;Ljava/lang/String;)Ljava/io/File;
+	protected final fun error (Ljava/lang/String;Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;)V
+	public static synthetic fun error$default (Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase;Ljava/lang/String;Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;ILjava/lang/Object;)V
+	public final fun getInputDir ()Ljava/io/File;
+	protected final fun getLastError ()Ljava/lang/Throwable;
+	public final fun getOutputDir ()Ljava/io/File;
+	protected final fun getTransformed ()Z
+	public final fun getVerbose ()Z
+	protected final fun info (Ljava/lang/String;Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;)V
+	public static synthetic fun info$default (Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase;Ljava/lang/String;Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;ILjava/lang/Object;)V
+	protected final fun isClassFile (Ljava/io/File;)Z
+	protected final fun mkdirsAndWrite (Ljava/io/File;[B)V
+	public final fun setInputDir (Ljava/io/File;)V
+	protected final fun setLastError (Ljava/lang/Throwable;)V
+	public final fun setOutputDir (Ljava/io/File;)V
+	protected final fun setTransformed (Z)V
+	public final fun setVerbose (Z)V
+	protected final fun toOutputFile (Ljava/io/File;)Ljava/io/File;
+	public abstract fun transform ()V
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo {
+	public fun <init> (Lkotlinx/atomicfu/transformer/MethodId;Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/tree/InsnList;)V
+	public synthetic fun <init> (Lkotlinx/atomicfu/transformer/MethodId;Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/tree/InsnList;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public final fun component1 ()Lkotlinx/atomicfu/transformer/MethodId;
+	public final fun component2 ()Ljava/lang/String;
+	public final fun component3 ()Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public final fun component4 ()Lorg/objectweb/asm/tree/InsnList;
+	public final fun copy (Lkotlinx/atomicfu/transformer/MethodId;Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/tree/InsnList;)Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;
+	public static synthetic fun copy$default (Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;Lkotlinx/atomicfu/transformer/MethodId;Ljava/lang/String;Lorg/objectweb/asm/tree/AbstractInsnNode;Lorg/objectweb/asm/tree/InsnList;ILjava/lang/Object;)Lkotlinx/atomicfu/transformer/AtomicFUTransformerBase$SourceInfo;
+	public fun equals (Ljava/lang/Object;)Z
+	public final fun getI ()Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public final fun getInsnList ()Lorg/objectweb/asm/tree/InsnList;
+	public final fun getMethod ()Lkotlinx/atomicfu/transformer/MethodId;
+	public final fun getSource ()Ljava/lang/String;
+	public fun hashCode ()I
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS : kotlinx/atomicfu/transformer/AtomicFUTransformerBase {
+	public fun <init> (Ljava/io/File;Ljava/io/File;)V
+	public fun transform ()V
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$AtomicConstructorDetector : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$AtomicOperationsInliner : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$DelegatedPropertyAccessorsVisitor : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$DependencyEraser : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$FieldDelegatesVisitor : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$ReceiverResolver : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;Ljava/lang/String;)V
+	public final fun getReceiver ()Lorg/mozilla/javascript/ast/AstNode;
+	public final fun setReceiver (Lorg/mozilla/javascript/ast/AstNode;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$TopLevelDelegatedFieldsAccessorVisitor : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJS$TransformVisitor : org/mozilla/javascript/ast/NodeVisitor {
+	public fun <init> (Lkotlinx/atomicfu/transformer/AtomicFUTransformerJS;)V
+	public fun visit (Lorg/mozilla/javascript/ast/AstNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerJSKt {
+	public static final fun main ([Ljava/lang/String;)V
+}
+
+public final class kotlinx/atomicfu/transformer/AtomicFUTransformerKt {
+	public static final fun main ([Ljava/lang/String;)V
+}
+
+public final class kotlinx/atomicfu/transformer/FieldId {
+	public fun <init> (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
+	public final fun component1 ()Ljava/lang/String;
+	public final fun component2 ()Ljava/lang/String;
+	public final fun component3 ()Ljava/lang/String;
+	public final fun copy (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lkotlinx/atomicfu/transformer/FieldId;
+	public static synthetic fun copy$default (Lkotlinx/atomicfu/transformer/FieldId;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lkotlinx/atomicfu/transformer/FieldId;
+	public fun equals (Ljava/lang/Object;)Z
+	public final fun getDesc ()Ljava/lang/String;
+	public final fun getName ()Ljava/lang/String;
+	public final fun getOwner ()Ljava/lang/String;
+	public fun hashCode ()I
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/transformer/FieldInfo {
+	public fun <init> (Lkotlinx/atomicfu/transformer/FieldId;Lorg/objectweb/asm/Type;Z)V
+	public synthetic fun <init> (Lkotlinx/atomicfu/transformer/FieldId;Lorg/objectweb/asm/Type;ZILkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public final fun getAccessors ()Ljava/util/Set;
+	public final fun getFieldId ()Lkotlinx/atomicfu/transformer/FieldId;
+	public final fun getFieldType ()Lorg/objectweb/asm/Type;
+	public final fun getFuName ()Ljava/lang/String;
+	public final fun getFuType ()Lorg/objectweb/asm/Type;
+	public final fun getHasAtomicOps ()Z
+	public final fun getHasExternalAccess ()Z
+	public final fun getName ()Ljava/lang/String;
+	public final fun getOwner ()Ljava/lang/String;
+	public final fun getOwnerType ()Lorg/objectweb/asm/Type;
+	public final fun getPrimitiveType (Z)Lorg/objectweb/asm/Type;
+	public final fun getRefVolatileClassName ()Ljava/lang/String;
+	public final fun getStaticRefVolatileField ()Ljava/lang/String;
+	public final fun getTypeInfo ()Lkotlinx/atomicfu/transformer/TypeInfo;
+	public final fun isArray ()Z
+	public final fun isStatic ()Z
+	public final fun setHasAtomicOps (Z)V
+	public final fun setHasExternalAccess (Z)V
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/transformer/FlowAnalyzer {
+	public fun <init> (Lorg/objectweb/asm/tree/AbstractInsnNode;)V
+	public final fun execute ()Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public final fun getInitStart (I)Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public final fun getUncheckedCastInsn ()Lorg/objectweb/asm/tree/AbstractInsnNode;
+	public final fun getValueArgInitLast ()Lorg/objectweb/asm/tree/AbstractInsnNode;
+}
+
+public final class kotlinx/atomicfu/transformer/JvmVariant : java/lang/Enum {
+	public static final field BOTH Lkotlinx/atomicfu/transformer/JvmVariant;
+	public static final field FU Lkotlinx/atomicfu/transformer/JvmVariant;
+	public static final field VH Lkotlinx/atomicfu/transformer/JvmVariant;
+	public static fun getEntries ()Lkotlin/enums/EnumEntries;
+	public static fun valueOf (Ljava/lang/String;)Lkotlinx/atomicfu/transformer/JvmVariant;
+	public static fun values ()[Lkotlinx/atomicfu/transformer/JvmVariant;
+}
+
+public final class kotlinx/atomicfu/transformer/MetadataTransformer {
+	public fun <init> (Ljava/util/Set;Ljava/util/Set;)V
+	public final fun transformMetadata (Lorg/objectweb/asm/tree/AnnotationNode;)Z
+}
+
+public final class kotlinx/atomicfu/transformer/MetadataTransformerKt {
+	public static final field KOTLIN_METADATA_DESC Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/transformer/MethodId {
+	public fun <init> (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
+	public final fun component1 ()Ljava/lang/String;
+	public final fun component2 ()Ljava/lang/String;
+	public final fun component3 ()Ljava/lang/String;
+	public final fun component4 ()I
+	public final fun copy (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lkotlinx/atomicfu/transformer/MethodId;
+	public static synthetic fun copy$default (Lkotlinx/atomicfu/transformer/MethodId;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/Object;)Lkotlinx/atomicfu/transformer/MethodId;
+	public fun equals (Ljava/lang/Object;)Z
+	public final fun getDesc ()Ljava/lang/String;
+	public final fun getInvokeOpcode ()I
+	public final fun getName ()Ljava/lang/String;
+	public final fun getOwner ()Ljava/lang/String;
+	public fun hashCode ()I
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/transformer/TransformerException : java/lang/Exception {
+	public fun <init> (Ljava/lang/String;Ljava/lang/Throwable;)V
+	public synthetic fun <init> (Ljava/lang/String;Ljava/lang/Throwable;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
+}
+
+public final class kotlinx/atomicfu/transformer/TypeInfo {
+	public fun <init> (Lorg/objectweb/asm/Type;Lorg/objectweb/asm/Type;Lorg/objectweb/asm/Type;)V
+	public final fun getFuType ()Lorg/objectweb/asm/Type;
+	public final fun getOriginalType ()Lorg/objectweb/asm/Type;
+	public final fun getTransformedType ()Lorg/objectweb/asm/Type;
+}
+
diff --git a/atomicfu-transformer/build.gradle b/atomicfu-transformer/build.gradle
index c6304f0..be54052 100644
--- a/atomicfu-transformer/build.gradle
+++ b/atomicfu-transformer/build.gradle
@@ -9,13 +9,13 @@ apply from: rootProject.file('gradle/compile-options.gradle')
 ext.configureKotlin()
 
 dependencies {
-    compile "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
-    compile "org.ow2.asm:asm:$asm_version"
-    compile "org.ow2.asm:asm-commons:$asm_version"
-    compile "org.ow2.asm:asm-tree:$asm_version"
-    compile "org.ow2.asm:asm-util:$asm_version"
-    compile "org.slf4j:slf4j-api:$slf4j_version"
-    runtime "org.slf4j:slf4j-simple:$slf4j_version"
-    compile "org.mozilla:rhino:1.7.10"
-    compile "org.jetbrains.kotlinx:kotlinx-metadata-jvm:$kotlinx_metadata_version"
-}
\ No newline at end of file
+    api "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
+    api "org.ow2.asm:asm:$asm_version"
+    api "org.ow2.asm:asm-commons:$asm_version"
+    api "org.ow2.asm:asm-tree:$asm_version"
+    api "org.ow2.asm:asm-util:$asm_version"
+    api "org.slf4j:slf4j-api:$slf4j_version"
+    runtimeOnly "org.slf4j:slf4j-simple:$slf4j_version"
+    api "org.mozilla:rhino:1.7.10"
+    api "org.jetbrains.kotlinx:kotlinx-metadata-jvm:$kotlinx_metadata_version"
+}
diff --git a/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/AtomicFUTransformer.kt b/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/AtomicFUTransformer.kt
index a138422..18bba6b 100644
--- a/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/AtomicFUTransformer.kt
+++ b/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/AtomicFUTransformer.kt
@@ -1001,6 +1001,31 @@ class AtomicFUTransformer(
                     i = next
                 }
             }
+            // fix for languageVersion 1.7: check if there is checkNotNull invocation
+            var startInsn: AbstractInsnNode = getter
+            val checkNotNull = when {
+                getter.next?.opcode == DUP && getter.next?.next?.opcode == LDC -> FlowAnalyzer(getter.next?.next).getUncheckedCastInsn()
+                getter.next?.opcode == ASTORE -> {
+                    startInsn = getter.next
+                    val v = (getter.next as VarInsnNode).`var`
+                    var aload: AbstractInsnNode = getter.next
+                    while (!(aload is VarInsnNode && aload.opcode == ALOAD && aload.`var` == v)) {
+                        aload = aload.next
+                    }
+                    if (aload.next.opcode == LDC) {
+                        FlowAnalyzer(aload.next).getUncheckedCastInsn()
+                    } else null
+                }
+                else -> null
+            }
+            if (checkNotNull != null) {
+                var i: AbstractInsnNode = checkNotNull
+                while (i != startInsn) {
+                    val prev = i.previous
+                    instructions.remove(i)
+                    i = prev
+                }
+            }
         }
 
         private fun fixupLoadedAtomicVar(f: FieldInfo, ld: FieldInsnNode): AbstractInsnNode? {
diff --git a/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/FlowAnalyzer.kt b/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/FlowAnalyzer.kt
index d5b98a5..2565bea 100644
--- a/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/FlowAnalyzer.kt
+++ b/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/FlowAnalyzer.kt
@@ -77,6 +77,20 @@ class FlowAnalyzer(
         return i ?: abort("Backward flow control falls after the beginning of the method")
     }
 
+    fun getUncheckedCastInsn(): AbstractInsnNode? {
+        var i = start
+        depth = 1
+        while (i != null) {
+            cur = i
+            executeOne(i)
+            if (depth == 0 && i is MethodInsnNode && i.owner == "kotlin/jvm/internal/Intrinsics" && i.name == "checkNotNull") {
+                return i
+            }
+            i = i.next
+        }
+        return null
+    }
+
     fun getValueArgInitLast(): AbstractInsnNode {
         var i = start
         val valueArgSize = Type.getArgumentTypes((start as MethodInsnNode).desc)[0].size
diff --git a/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/MetadataTransformer.kt b/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/MetadataTransformer.kt
index 13c5366..ea393e4 100644
--- a/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/MetadataTransformer.kt
+++ b/atomicfu-transformer/src/main/kotlin/kotlinx/atomicfu/transformer/MetadataTransformer.kt
@@ -23,7 +23,7 @@ class MetadataTransformer(
     @Suppress("UNCHECKED_CAST")
     fun transformMetadata(metadataAnnotation: AnnotationNode): Boolean {
         val map = metadataAnnotation.asMap()
-        val hdr = KotlinClassHeader(
+        val metadata = Metadata(
             kind = map["k"] as Int?,
             metadataVersion = (map["mv"] as? List<Int>)?.toIntArray(),
             data1 = (map["d1"] as? List<String>)?.toTypedArray(),
@@ -32,31 +32,32 @@ class MetadataTransformer(
             packageName = map["pn"] as String?,
             extraInt = map["xi"] as Int?
         )
-        val result = when (val metadata = KotlinClassMetadata.read(hdr)) {
+        val transformedMetadata = when (val kotlinClassMetadata = KotlinClassMetadata.read(metadata)) {
             is KotlinClassMetadata.Class -> {
                 val w = KotlinClassMetadata.Class.Writer()
-                metadata.accept(ClassFilter(w))
-                w.write(hdr.metadataVersion, hdr.extraInt)
+                kotlinClassMetadata.accept(ClassFilter(w))
+                val transformedKotlinClassMetadata = w.write(metadata.metadataVersion, metadata.extraInt)
+                KotlinClassMetadata.writeClass(transformedKotlinClassMetadata.kmClass)
             }
             is KotlinClassMetadata.FileFacade -> {
                 val w = KotlinClassMetadata.FileFacade.Writer()
-                metadata.accept(PackageFilter(w))
-                w.write(hdr.metadataVersion, hdr.extraInt)
+                kotlinClassMetadata.accept(PackageFilter(w))
+                val transformedKotlinClassMetadata = w.write(metadata.metadataVersion, metadata.extraInt)
+                KotlinClassMetadata.writeFileFacade(transformedKotlinClassMetadata.kmPackage)
             }
             is KotlinClassMetadata.MultiFileClassPart -> {
                 val w = KotlinClassMetadata.MultiFileClassPart.Writer()
-                metadata.accept(PackageFilter(w))
-                w.write(metadata.facadeClassName, hdr.metadataVersion, hdr.extraInt)
+                kotlinClassMetadata.accept(PackageFilter(w))
+                val transformedKotlinClassMetadata = w.write(kotlinClassMetadata.facadeClassName, metadata.metadataVersion, metadata.extraInt)
+                KotlinClassMetadata.writeMultiFileClassPart(transformedKotlinClassMetadata.kmPackage, transformedKotlinClassMetadata.facadeClassName)
             }
             else -> return false // not transformed
         }
         if (!transformed) return false
-        result.apply {
-            with (metadataAnnotation) {
-                // read resulting header & update annotation data
-                setKey("d1", header.data1.toList())
-                setKey("d2", header.data2.toList())
-            }
+        with (metadataAnnotation) {
+            // read resulting header & update annotation data
+            setKey("d1", transformedMetadata.data1.toList())
+            setKey("d2", transformedMetadata.data2.toList())
         }
         return true // transformed
     }
@@ -208,7 +209,7 @@ private val SynchronizedObjectAlias = KmClassifier.TypeAlias("kotlinx/atomicfu/l
 
 private val ReentrantLockAlias = KmClassifier.TypeAlias("kotlinx/atomicfu/locks/ReentrantLock")
 private val ReentrantLockType = KmType(0).apply {
-    classifier = KmClassifier.Class("java/util/concurrent/locks/ReentrantLock")        
+    classifier = KmClassifier.Class("java/util/concurrent/locks/ReentrantLock")
 }
 
 @Suppress("UNCHECKED_CAST")
diff --git a/atomicfu/api/atomicfu.api b/atomicfu/api/atomicfu.api
new file mode 100644
index 0000000..e142817
--- /dev/null
+++ b/atomicfu/api/atomicfu.api
@@ -0,0 +1,137 @@
+public final class kotlinx/atomicfu/AtomicArray {
+	public final fun get (I)Lkotlinx/atomicfu/AtomicRef;
+	public final fun getSize ()I
+}
+
+public final class kotlinx/atomicfu/AtomicBoolean {
+	public final fun compareAndSet (ZZ)Z
+	public final fun getAndSet (Z)Z
+	public final fun getTrace ()Lkotlinx/atomicfu/TraceBase;
+	public final fun getValue ()Z
+	public final fun lazySet (Z)V
+	public final fun setValue (Z)V
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/AtomicBooleanArray {
+	public fun <init> (I)V
+	public final fun get (I)Lkotlinx/atomicfu/AtomicBoolean;
+	public final fun getSize ()I
+}
+
+public final class kotlinx/atomicfu/AtomicFU {
+	public static final fun atomic (I)Lkotlinx/atomicfu/AtomicInt;
+	public static final fun atomic (ILkotlinx/atomicfu/TraceBase;)Lkotlinx/atomicfu/AtomicInt;
+	public static final fun atomic (J)Lkotlinx/atomicfu/AtomicLong;
+	public static final fun atomic (JLkotlinx/atomicfu/TraceBase;)Lkotlinx/atomicfu/AtomicLong;
+	public static final fun atomic (Ljava/lang/Object;)Lkotlinx/atomicfu/AtomicRef;
+	public static final fun atomic (Ljava/lang/Object;Lkotlinx/atomicfu/TraceBase;)Lkotlinx/atomicfu/AtomicRef;
+	public static final fun atomic (Z)Lkotlinx/atomicfu/AtomicBoolean;
+	public static final fun atomic (ZLkotlinx/atomicfu/TraceBase;)Lkotlinx/atomicfu/AtomicBoolean;
+	public static synthetic fun atomic$default (ILkotlinx/atomicfu/TraceBase;ILjava/lang/Object;)Lkotlinx/atomicfu/AtomicInt;
+	public static synthetic fun atomic$default (JLkotlinx/atomicfu/TraceBase;ILjava/lang/Object;)Lkotlinx/atomicfu/AtomicLong;
+	public static synthetic fun atomic$default (Ljava/lang/Object;Lkotlinx/atomicfu/TraceBase;ILjava/lang/Object;)Lkotlinx/atomicfu/AtomicRef;
+	public static synthetic fun atomic$default (ZLkotlinx/atomicfu/TraceBase;ILjava/lang/Object;)Lkotlinx/atomicfu/AtomicBoolean;
+}
+
+public final class kotlinx/atomicfu/AtomicFU_commonKt {
+	public static final fun atomicArrayOfNulls (I)Lkotlinx/atomicfu/AtomicArray;
+	public static final fun getAndUpdate (Lkotlinx/atomicfu/AtomicBoolean;Lkotlin/jvm/functions/Function1;)Z
+	public static final fun getAndUpdate (Lkotlinx/atomicfu/AtomicInt;Lkotlin/jvm/functions/Function1;)I
+	public static final fun getAndUpdate (Lkotlinx/atomicfu/AtomicLong;Lkotlin/jvm/functions/Function1;)J
+	public static final fun getAndUpdate (Lkotlinx/atomicfu/AtomicRef;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;
+	public static final fun loop (Lkotlinx/atomicfu/AtomicBoolean;Lkotlin/jvm/functions/Function1;)Ljava/lang/Void;
+	public static final fun loop (Lkotlinx/atomicfu/AtomicInt;Lkotlin/jvm/functions/Function1;)Ljava/lang/Void;
+	public static final fun loop (Lkotlinx/atomicfu/AtomicLong;Lkotlin/jvm/functions/Function1;)Ljava/lang/Void;
+	public static final fun loop (Lkotlinx/atomicfu/AtomicRef;Lkotlin/jvm/functions/Function1;)Ljava/lang/Void;
+	public static final fun update (Lkotlinx/atomicfu/AtomicBoolean;Lkotlin/jvm/functions/Function1;)V
+	public static final fun update (Lkotlinx/atomicfu/AtomicInt;Lkotlin/jvm/functions/Function1;)V
+	public static final fun update (Lkotlinx/atomicfu/AtomicLong;Lkotlin/jvm/functions/Function1;)V
+	public static final fun update (Lkotlinx/atomicfu/AtomicRef;Lkotlin/jvm/functions/Function1;)V
+	public static final fun updateAndGet (Lkotlinx/atomicfu/AtomicBoolean;Lkotlin/jvm/functions/Function1;)Z
+	public static final fun updateAndGet (Lkotlinx/atomicfu/AtomicInt;Lkotlin/jvm/functions/Function1;)I
+	public static final fun updateAndGet (Lkotlinx/atomicfu/AtomicLong;Lkotlin/jvm/functions/Function1;)J
+	public static final fun updateAndGet (Lkotlinx/atomicfu/AtomicRef;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;
+}
+
+public final class kotlinx/atomicfu/AtomicInt {
+	public final fun addAndGet (I)I
+	public final fun compareAndSet (II)Z
+	public final fun decrementAndGet ()I
+	public final fun getAndAdd (I)I
+	public final fun getAndDecrement ()I
+	public final fun getAndIncrement ()I
+	public final fun getAndSet (I)I
+	public final fun getTrace ()Lkotlinx/atomicfu/TraceBase;
+	public final fun getValue ()I
+	public final fun incrementAndGet ()I
+	public final fun lazySet (I)V
+	public final fun minusAssign (I)V
+	public final fun plusAssign (I)V
+	public final fun setValue (I)V
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/AtomicIntArray {
+	public fun <init> (I)V
+	public final fun get (I)Lkotlinx/atomicfu/AtomicInt;
+	public final fun getSize ()I
+}
+
+public final class kotlinx/atomicfu/AtomicLong {
+	public final fun addAndGet (J)J
+	public final fun compareAndSet (JJ)Z
+	public final fun decrementAndGet ()J
+	public final fun getAndAdd (J)J
+	public final fun getAndDecrement ()J
+	public final fun getAndIncrement ()J
+	public final fun getAndSet (J)J
+	public final fun getTrace ()Lkotlinx/atomicfu/TraceBase;
+	public final fun getValue ()J
+	public final fun incrementAndGet ()J
+	public final fun lazySet (J)V
+	public final fun minusAssign (J)V
+	public final fun plusAssign (J)V
+	public final fun setValue (J)V
+	public fun toString ()Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/AtomicLongArray {
+	public fun <init> (I)V
+	public final fun get (I)Lkotlinx/atomicfu/AtomicLong;
+	public final fun getSize ()I
+}
+
+public final class kotlinx/atomicfu/AtomicRef {
+	public final fun compareAndSet (Ljava/lang/Object;Ljava/lang/Object;)Z
+	public final fun getAndSet (Ljava/lang/Object;)Ljava/lang/Object;
+	public final fun getTrace ()Lkotlinx/atomicfu/TraceBase;
+	public final fun getValue ()Ljava/lang/Object;
+	public final fun lazySet (Ljava/lang/Object;)V
+	public final fun setValue (Ljava/lang/Object;)V
+	public fun toString ()Ljava/lang/String;
+}
+
+public class kotlinx/atomicfu/TraceBase {
+	public fun append (Ljava/lang/Object;)V
+	public fun append (Ljava/lang/Object;Ljava/lang/Object;)V
+	public fun append (Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
+	public fun append (Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
+}
+
+public final class kotlinx/atomicfu/TraceBase$None : kotlinx/atomicfu/TraceBase {
+	public static final field INSTANCE Lkotlinx/atomicfu/TraceBase$None;
+}
+
+public class kotlinx/atomicfu/TraceFormat {
+	public fun <init> ()V
+	public fun format (ILjava/lang/Object;)Ljava/lang/String;
+}
+
+public final class kotlinx/atomicfu/TraceKt {
+	public static final fun Trace (ILkotlinx/atomicfu/TraceFormat;)Lkotlinx/atomicfu/TraceBase;
+	public static synthetic fun Trace$default (ILkotlinx/atomicfu/TraceFormat;ILjava/lang/Object;)Lkotlinx/atomicfu/TraceBase;
+	public static final fun getTraceFormatDefault ()Lkotlinx/atomicfu/TraceFormat;
+	public static final fun named (Lkotlinx/atomicfu/TraceBase;Ljava/lang/String;)Lkotlinx/atomicfu/TraceBase;
+}
+
diff --git a/atomicfu/build.gradle b/atomicfu/build.gradle
index 063c9a3..d20bb34 100644
--- a/atomicfu/build.gradle
+++ b/atomicfu/build.gradle
@@ -2,6 +2,8 @@
  * Copyright 2016-2020 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
+import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile
+
 apply plugin: 'kotlin-multiplatform'
 apply from: rootProject.file("gradle/targets.gradle")
 
@@ -17,6 +19,7 @@ ext {
     }
 }
 
+
 kotlin {
     targets {
         delegate.metaClass.addTarget = { preset ->
@@ -25,9 +28,9 @@ kotlin {
     }
 
     // JS -- always
-    js {
+    js(IR) {
         moduleName = "kotlinx-atomicfu"
-        // TODO: Commented out because browser tests do not work on TeamCity
+        // TODO: commented out because browser tests do not work on TeamCity
         // browser()
         nodejs()
     }
@@ -35,6 +38,15 @@ kotlin {
     // JVM -- always
     jvm()
 
+    // Wasm -- always
+    wasmJs {
+        nodejs()
+    }
+
+    wasmWasi {
+        nodejs()
+    }
+
     sourceSets {
         commonMain {
             dependencies {
@@ -47,7 +59,13 @@ kotlin {
                 implementation 'org.jetbrains.kotlin:kotlin-test-annotations-common'
             }
         }
+
+        jsAndWasmSharedMain {
+            dependsOn(sourceSets.commonMain)
+        }
+
         jsMain {
+            dependsOn(sourceSets.jsAndWasmSharedMain)
             dependencies {
                 implementation 'org.jetbrains.kotlin:kotlin-stdlib-js'
             }
@@ -57,6 +75,32 @@ kotlin {
                 implementation 'org.jetbrains.kotlin:kotlin-test-js'
             }
         }
+
+        wasmJsMain {
+            dependsOn(sourceSets.jsAndWasmSharedMain)
+            dependencies {
+                implementation 'org.jetbrains.kotlin:kotlin-stdlib-wasm-js'
+            }
+        }
+
+        wasmJsTest {
+            dependencies {
+                implementation 'org.jetbrains.kotlin:kotlin-test-wasm-js'
+            }
+        }
+
+        wasmWasiMain {
+            dependsOn(sourceSets.jsAndWasmSharedMain)
+            dependencies {
+                implementation 'org.jetbrains.kotlin:kotlin-stdlib-wasm-wasi'
+            }
+        }
+        wasmWasiTest {
+            dependencies {
+                implementation 'org.jetbrains.kotlin:kotlin-test-wasm-wasi'
+            }
+        }
+
         jvmMain {
             dependencies {
                 implementation 'org.jetbrains.kotlin:kotlin-stdlib'
@@ -80,23 +124,34 @@ if (rootProject.ext.native_targets_enabled) {
             if (project.ext.ideaActive) {
                 addNative(fromPreset(project.ext.ideaPreset, 'native'))
             } else {
+                // Support of all non-deprecated targets from official tier list: https://kotlinlang.org/docs/native-target-support.html
+
+                // Tier #1
                 addTarget(presets.linuxX64)
-                addTarget(presets.iosArm64)
-                addTarget(presets.iosArm32)
-                addTarget(presets.iosX64)
                 addTarget(presets.macosX64)
-                addTarget(presets.mingwX64)
-                addTarget(presets.tvosArm64)
-                addTarget(presets.tvosX64)
-                addTarget(presets.watchosArm32)
-                addTarget(presets.watchosArm64)
-                addTarget(presets.watchosX86)
-                addTarget(presets.watchosX64)
-
+                addTarget(presets.macosArm64)
                 addTarget(presets.iosSimulatorArm64)
+                addTarget(presets.iosX64)
+
+                // Tier #2
+                addTarget(presets.linuxArm64)
                 addTarget(presets.watchosSimulatorArm64)
+                addTarget(presets.watchosX64)
+                addTarget(presets.watchosArm32)
+                addTarget(presets.watchosArm64)
                 addTarget(presets.tvosSimulatorArm64)
-                addTarget(presets.macosArm64)
+                addTarget(presets.tvosX64)
+                addTarget(presets.tvosArm64)
+                addTarget(presets.iosArm64)
+
+
+                // Tier #3
+                addTarget(presets.androidNativeArm32)
+                addTarget(presets.androidNativeArm64)
+                addTarget(presets.androidNativeX86)
+                addTarget(presets.androidNativeX64)
+                addTarget(presets.mingwX64)
+                addTarget(presets.watchosDeviceArm64)
             }
         }
 
@@ -124,21 +179,6 @@ if (rootProject.ext.native_targets_enabled) {
             }
         }
     }
-
-    // Hack for publishing as HMPP: pack the cinterop klib as a source set:
-    if (!project.ext.ideaActive) {
-        kotlin.sourceSets {
-            nativeInterop
-            nativeMain.dependsOn(nativeInterop)
-        }
-
-        apply from: "$rootDir/gradle/interop-as-source-set-klib.gradle"
-
-        registerInteropAsSourceSetOutput(
-                kotlin.linuxX64().compilations["main"].cinterops["interop"],
-                kotlin.sourceSets["nativeInterop"]
-        )
-    }
 }
 
 configurations {
@@ -147,72 +187,12 @@ configurations {
 
 apply from: rootProject.file('gradle/compile-options.gradle')
 
-ext.configureKotlin(true)
+ext.configureKotlin()
 
 dependencies {
     transformer project(":atomicfu-transformer")
 }
 
-// ==== CONFIGURE JS =====
-
-def compileJsLegacy = tasks.hasProperty("compileKotlinJsLegacy")
-        ? compileKotlinJsLegacy
-        : compileKotlinJs
-
-tasks.withType(compileJsLegacy.getClass()) {
-    kotlinOptions {
-        moduleKind = "umd"
-        sourceMap = true
-        metaInfo = true
-    }
-}
-
-apply from: file("$rootProject.projectDir/gradle/node-js.gradle")
-apply from: file("$rootProject.projectDir/gradle/publish-npm-js.gradle")
-
-// Workaround the problem with Node downloading
-repositories.whenObjectAdded {
-    if (it instanceof IvyArtifactRepository) {
-        metadataSources {
-            artifact()
-        }
-    }
-}
-
-def compileTestJsLegacy = tasks.hasProperty("compileTestKotlinJsLegacy")
-        ? compileTestKotlinJsLegacy
-        : compileTestKotlinJs
-
-def transformedJsFile = compileTestJsLegacy.kotlinOptions.outputFile
-compileTestJsLegacy.configure {
-    kotlinOptions {
-        // NOTE: Module base-name must be equal to the package name declared in package.json
-        def baseName = "kotlinx-atomicfu"
-        outputFile = new File(new File(outputFile).parent, baseName + ".js")
-    }
-}
-def originalJsFile = compileTestJsLegacy.kotlinOptions.outputFile
-
-task transformJS(type: JavaExec, dependsOn: [compileTestJsLegacy]) {
-    main = "kotlinx.atomicfu.transformer.AtomicFUTransformerJSKt"
-    args = [originalJsFile, transformedJsFile]
-    classpath = configurations.transformer
-    inputs.file(originalJsFile)
-    outputs.file(transformedJsFile)
-}
-
-if (project.tasks.findByName('jsLegacyNodeTest')) {
-    jsLegacyNodeTest.dependsOn transformJS
-    jsLegacyNodeTest.configure {
-        inputFileProperty.set(new File(transformedJsFile))
-    }
-} else {
-    jsNodeTest.dependsOn transformJS
-    jsNodeTest.configure {
-        inputFileProperty.set(new File(transformedJsFile))
-    }
-}
-
 // ==== CONFIGURE JVM =====
 
 def classesPreAtomicFuDir = file("$buildDir/classes/kotlin/jvm/test")
@@ -276,19 +256,11 @@ transformedTestVH.onlyIf {
     JavaVersion.current().ordinal() >= JavaVersion.VERSION_1_9.ordinal()
 }
 
-task testAtomicfuReferenceJs(type: Test, dependsOn: [compileTestKotlinJvm, transformJS]) {
-    environment "transformedJsFile", transformedJsFile
-    classpath = files(configurations.jvmTestRuntimeClasspath, classesPreAtomicFuDir)
-    testClassesDirs = project.files(classesPreAtomicFuDir)
-    include '**/AtomicfuReferenceJsTest.*'
-    filter { setFailOnNoMatchingTests(false) }
-}
-
 task jvmTestAll(dependsOn: [
-        transformedTestFU_current,
-        transformedTestBOTH_current,
-        transformedTestVH,
-        testAtomicfuReferenceJs])
+    transformedTestFU_current,
+    transformedTestBOTH_current,
+    transformedTestVH
+])
 
 tasks.withType(Test) {
     testLogging {
@@ -299,15 +271,16 @@ tasks.withType(Test) {
 
 task compileJavaModuleInfo(type: JavaCompile) {
     def moduleName = "kotlinx.atomicfu" // this module's name
-    def compileKotlinJvm = kotlin.targets["jvm"].compilations["main"].compileKotlinTask
+    def compilation = kotlin.targets["jvm"].compilations["main"]
+    def compileKotlinTask = compilation.compileTaskProvider.get() as KotlinJvmCompile
+    def targetDir = compileKotlinTask.destinationDirectory.dir("../java9")
     def sourceDir = file("src/jvmMain/java9/")
-    def targetDir = compileKotlinJvm.destinationDirectory.map { it.dir("../java9/") }
 
     // Use a Java 11 compiler for the module info.
     javaCompiler.set(project.javaToolchains.compilerFor { languageVersion.set(JavaLanguageVersion.of(11)) })
 
     // Always compile kotlin classes before the module descriptor.
-    dependsOn(compileKotlinJvm)
+    dependsOn(compileKotlinTask)
 
     // Add the module-info source file.
     source(sourceDir)
@@ -317,7 +290,7 @@ task compileJavaModuleInfo(type: JavaCompile) {
     // but it currently won't compile to a module-info.class file.
     // Note that module checking only works on JDK 9+,
     // because the JDK built-in base modules are not available in earlier versions.
-    def javaVersion = compileKotlinJvm.kotlinJavaToolchain.javaVersion.getOrNull()
+    def javaVersion = compileKotlinTask.kotlinJavaToolchain.javaVersion.getOrNull()
     if (javaVersion?.isJava9Compatible() == true) {
         logger.info("Module-info checking is enabled; $compileKotlinJvm is compiled using Java $javaVersion")
         compileKotlinJvm.source(sourceDir)
@@ -341,11 +314,11 @@ task compileJavaModuleInfo(type: JavaCompile) {
     options.compilerArgs.add("-Xlint:-requires-transitive-automatic")
 
     // Patch the compileKotlinJvm output classes into the compilation so exporting packages works correctly.
-    options.compilerArgs.addAll(["--patch-module", "$moduleName=${compileKotlinJvm.destinationDirectory.get().getAsFile()}"])
+    options.compilerArgs.addAll(["--patch-module", "$moduleName=${compileKotlinTask.destinationDirectory.get().getAsFile()}"])
 
     // Use the classpath of the compileKotlinJvm task.
     // Also ensure that the module path is used instead of classpath.
-    classpath = compileKotlinJvm.classpath
+    classpath = compileKotlinTask.libraries
     modularity.inferModulePath.set(true)
 
     doFirst {
@@ -358,7 +331,7 @@ tasks.named("jvmJar") {
     manifest {
         attributes(["Multi-Release": true])
     }
-    from(compileJavaModuleInfo) {
+    from(compileJavaModuleInfo.destinationDirectory) {
         into("META-INF/versions/9/")
     }
 }
@@ -382,3 +355,10 @@ tasks.matching { it.name == "generatePomFileForKotlinMultiplatformPublication" }
     dependsOn(tasks["generatePomFileForJvmPublication"])
 }
 
+// Workaround for https://youtrack.jetbrains.com/issue/KT-58303:
+// the `clean` task can't delete the expanded.lock file on Windows as it's still held by Gradle, failing the build
+tasks.clean {
+    setDelete(layout.buildDirectory.asFileTree.matching {
+        exclude("tmp/.cache/expanded/expanded.lock")
+    })
+}
diff --git a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/AtomicFU.common.kt b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/AtomicFU.common.kt
index 39950e6..2c97ddc 100644
--- a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/AtomicFU.common.kt
+++ b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/AtomicFU.common.kt
@@ -6,7 +6,6 @@
 
 package kotlinx.atomicfu
 
-import kotlin.js.JsName
 import kotlin.internal.InlineOnly
 import kotlinx.atomicfu.TraceBase.None
 import kotlin.reflect.KProperty
@@ -110,7 +109,7 @@ public expect fun atomic(initial: Boolean): AtomicBoolean
 /**
  * Creates array of AtomicRef<T> of specified size, where each element is initialised with null value
  */
-@JsName(ATOMIC_ARRAY_OF_NULLS)
+@OptionalJsName(ATOMIC_ARRAY_OF_NULLS)
 public fun <T> atomicArrayOfNulls(size: Int): AtomicArray<T?> = AtomicArray(size)
 
 // ==================================== AtomicRef ====================================
@@ -508,15 +507,15 @@ public inline fun AtomicLong.updateAndGet(function: (Long) -> Long): Long {
 /**
  * Creates a new array of AtomicInt values of the specified size, where each element is initialised with 0
  */
-@JsName(ATOMIC_INT_ARRAY)
+@OptionalJsName(ATOMIC_INT_ARRAY)
 public class AtomicIntArray(size: Int) {
     private val array = Array(size) { atomic(0) }
 
-    @JsName(ARRAY_SIZE)
+    @OptionalJsName(ARRAY_SIZE)
     public val size: Int
         get() = array.size
 
-    @JsName(ARRAY_ELEMENT_GET)
+    @OptionalJsName(ARRAY_ELEMENT_GET)
     public operator fun get(index: Int): AtomicInt = array[index]
 }
 
@@ -525,15 +524,15 @@ public class AtomicIntArray(size: Int) {
 /**
  * Creates a new array of AtomicLong values of the specified size, where each element is initialised with 0L
  */
-@JsName(ATOMIC_LONG_ARRAY)
+@OptionalJsName(ATOMIC_LONG_ARRAY)
 public class AtomicLongArray(size: Int) {
     private val array = Array(size) { atomic(0L) }
 
-    @JsName(ARRAY_SIZE)
+    @OptionalJsName(ARRAY_SIZE)
     public val size: Int
         get() = array.size
 
-    @JsName(ARRAY_ELEMENT_GET)
+    @OptionalJsName(ARRAY_ELEMENT_GET)
     public operator fun get(index: Int): AtomicLong = array[index]
 }
 
@@ -542,29 +541,29 @@ public class AtomicLongArray(size: Int) {
 /**
  * Creates a new array of AtomicBoolean values of the specified size, where each element is initialised with false
  */
-@JsName(ATOMIC_BOOLEAN_ARRAY)
+@OptionalJsName(ATOMIC_BOOLEAN_ARRAY)
 public class AtomicBooleanArray(size: Int) {
     private val array = Array(size) { atomic(false) }
 
-    @JsName(ARRAY_SIZE)
+    @OptionalJsName(ARRAY_SIZE)
     public val size: Int
         get() = array.size
 
-    @JsName(ARRAY_ELEMENT_GET)
+    @OptionalJsName(ARRAY_ELEMENT_GET)
     public operator fun get(index: Int): AtomicBoolean = array[index]
 }
 
 
 // ==================================== AtomicArray ====================================
 
-@JsName(ATOMIC_REF_ARRAY)
+@OptionalJsName(ATOMIC_REF_ARRAY)
 public class AtomicArray<T> internal constructor(size: Int) {
     private val array = Array(size) { atomic<T?>(null) }
 
-    @JsName(ARRAY_SIZE)
+    @OptionalJsName(ARRAY_SIZE)
     public val size: Int
         get() = array.size
 
-    @JsName(ARRAY_ELEMENT_GET)
+    @OptionalJsName(ARRAY_ELEMENT_GET)
     public operator fun get(index: Int): AtomicRef<T?> = array[index]
 }
diff --git a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/MangledJsNames.kt b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/MangledJsNames.kt
index 99b4298..8c37d01 100644
--- a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/MangledJsNames.kt
+++ b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/MangledJsNames.kt
@@ -1,7 +1,7 @@
 package kotlinx.atomicfu
 
 /**
- * All atomicfu declarations are annotated with [@JsName][kotlin.js.JsName] to have specific names in JS output.
+ * All atomicfu declarations are annotated with [@OptionalJsName][kotlin.js.JsName] to have specific names in JS output.
  * JS output transformer relies on these mangled names to erase all atomicfu references.
  */
 
diff --git a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/OptionalJsName.kt b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/OptionalJsName.kt
new file mode 100644
index 0000000..e4e1b44
--- /dev/null
+++ b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/OptionalJsName.kt
@@ -0,0 +1,17 @@
+package kotlinx.atomicfu
+
+/**
+ * This annotation actualized with JsName in JS platform and not actualized in others.
+ */
+@OptIn(ExperimentalMultiplatform::class)
+@OptionalExpectation
+@Retention(AnnotationRetention.BINARY)
+@Target(
+    AnnotationTarget.CLASS,
+    AnnotationTarget.FUNCTION,
+    AnnotationTarget.PROPERTY,
+    AnnotationTarget.CONSTRUCTOR,
+    AnnotationTarget.PROPERTY_GETTER,
+    AnnotationTarget.PROPERTY_SETTER
+)
+expect annotation class OptionalJsName(val name: String)
diff --git a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/Trace.common.kt b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/Trace.common.kt
index 4cc1e40..4d3a935 100644
--- a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/Trace.common.kt
+++ b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/Trace.common.kt
@@ -6,7 +6,6 @@
 
 package kotlinx.atomicfu
 
-import kotlin.js.JsName
 import kotlin.internal.InlineOnly
 
 /**
@@ -66,30 +65,30 @@ public expect val traceFormatDefault: TraceFormat
 /**
  * Base class for implementations of `Trace`.
  */
-@JsName(TRACE_BASE_CONSTRUCTOR)
+@OptionalJsName(TRACE_BASE_CONSTRUCTOR)
 public open class TraceBase internal constructor() {
     /**
      * Accepts the logging [event] and appends it to the trace.
      */
-    @JsName(TRACE_APPEND_1)
+    @OptionalJsName(TRACE_APPEND_1)
     public open fun append(event: Any) {}
 
     /**
      * Accepts the logging events [event1], [event2] and appends them to the trace.
      */
-    @JsName(TRACE_APPEND_2)
+    @OptionalJsName(TRACE_APPEND_2)
     public open fun append(event1: Any, event2: Any) {}
 
     /**
      * Accepts the logging events [event1], [event2], [event3] and appends them to the trace.
      */
-    @JsName(TRACE_APPEND_3)
+    @OptionalJsName(TRACE_APPEND_3)
     public open fun append(event1: Any, event2: Any, event3: Any) {}
 
     /**
      * Accepts the logging events [event1], [event2], [event3], [event4] and appends them to the trace.
      */
-    @JsName(TRACE_APPEND_4)
+    @OptionalJsName(TRACE_APPEND_4)
     public open fun append(event1: Any, event2: Any, event3: Any, event4: Any) {}
 
     /**
diff --git a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/TraceFormat.kt b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/TraceFormat.kt
index dd8d0de..17dc1be 100644
--- a/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/TraceFormat.kt
+++ b/atomicfu/src/commonMain/kotlin/kotlinx/atomicfu/TraceFormat.kt
@@ -12,12 +12,12 @@ import kotlin.js.JsName
 /**
  * Trace string formatter.
  */
-@JsName(TRACE_FORMAT_CLASS)
+@OptionalJsName(TRACE_FORMAT_CLASS)
 public open class TraceFormat {
     /**
      * Formats trace at the given [index] with the given [event] of Any type.
      */
-    @JsName(TRACE_FORMAT_FORMAT_FUNCTION)
+    @OptionalJsName(TRACE_FORMAT_FORMAT_FUNCTION)
     public open fun format(index: Int, event: Any): String = "$index: $event"
 }
 
diff --git a/atomicfu/src/commonTest/kotlin/kotlinx/atomicfu/test/DelegatedPropertiesTest.kt b/atomicfu/src/commonTest/kotlin/kotlinx/atomicfu/test/DelegatedPropertiesTest.kt
deleted file mode 100644
index 4521c09..0000000
--- a/atomicfu/src/commonTest/kotlin/kotlinx/atomicfu/test/DelegatedPropertiesTest.kt
+++ /dev/null
@@ -1,257 +0,0 @@
-@file:Suppress("INVISIBLE_REFERENCE", "INVISIBLE_MEMBER")
-
-package kotlinx.atomicfu.test
-
-import kotlinx.atomicfu.atomic
-import kotlin.test.*
-
-private val topLevelIntOriginalAtomic = atomic(77)
-var topLevelIntDelegatedProperty: Int by topLevelIntOriginalAtomic
-
-private val _topLevelLong = atomic(55555555555)
-var topLevelDelegatedPropertyLong: Long by _topLevelLong
-
-private val _topLevelBoolean = atomic(false)
-var topLevelDelegatedPropertyBoolean: Boolean by _topLevelBoolean
-
-private val _topLevelRef = atomic(listOf("a", "b"))
-var topLevelDelegatedPropertyRef: List<String> by _topLevelRef
-
-var vTopLevelInt by atomic(77)
-
-var vTopLevelLong by atomic(777777777)
-
-var vTopLevelBoolean by atomic(false)
-
-var vTopLevelRef by atomic(listOf("a", "b"))
-
-class DelegatedProperties {
-    private val _a = atomic(42)
-    var a: Int by _a
-
-    private val _l = atomic(55555555555)
-    var l: Long by _l
-
-    private val _b = atomic(false)
-    var b: Boolean by _b
-
-    private val _ref = atomic(A(B(77)))
-    var ref: A by _ref
-
-    var vInt by atomic(77)
-
-    var vLong by atomic(777777777)
-
-    var vBoolean by atomic(false)
-
-    var vRef by atomic(A(B(77)))
-
-    @Test
-    fun testDelegatedAtomicInt() {
-        assertEquals(42, a)
-        _a.compareAndSet(42, 56)
-        assertEquals(56, a)
-        a = 77
-        _a.compareAndSet(77,  66)
-        assertEquals(66, _a.value)
-        assertEquals(66, a)
-    }
-
-    @Test
-    fun testDelegatedAtomicLong() {
-        assertEquals(55555555555, l)
-        _l.getAndIncrement()
-        assertEquals(55555555556, l)
-        l = 7777777777777
-        assertTrue(_l.compareAndSet(7777777777777, 66666666666))
-        assertEquals(66666666666, _l.value)
-        assertEquals(66666666666, l)
-    }
-
-    @Test
-    fun testDelegatedAtomicBoolean() {
-        assertEquals(false, b)
-        _b.lazySet(true)
-        assertEquals(true, b)
-        b = false
-        assertTrue(_b.compareAndSet(false, true))
-        assertEquals(true, _b.value)
-        assertEquals(true, b)
-    }
-
-    @Test
-    fun testDelegatedAtomicRef() {
-        assertEquals(77, ref.b.n)
-        _ref.lazySet(A(B(66)))
-        assertEquals(66, ref.b.n)
-        assertTrue(_ref.compareAndSet(_ref.value, A(B(56))))
-        assertEquals(56, ref.b.n)
-        ref = A(B(99))
-        assertEquals(99, _ref.value.b.n)
-    }
-
-    @Test
-    fun testVolatileInt() {
-        assertEquals(77, vInt)
-        vInt = 55
-        assertEquals(110, vInt * 2)
-    }
-
-    @Test
-    fun testVolatileLong() {
-        assertEquals(777777777, vLong)
-        vLong = 55
-        assertEquals(55, vLong)
-    }
-
-    @Test
-    fun testVolatileBoolean() {
-        assertEquals(false, vBoolean)
-        vBoolean = true
-        assertEquals(true, vBoolean)
-    }
-
-    @Test
-    fun testVolatileRef() {
-        assertEquals(77, vRef.b.n)
-        vRef = A(B(99))
-        assertEquals(99, vRef.b.n)
-    }
-
-    @Test
-    fun testTopLevelDelegatedPropertiesInt() {
-        assertEquals(77, topLevelIntDelegatedProperty)
-        topLevelIntOriginalAtomic.compareAndSet(77, 56)
-        assertEquals(56, topLevelIntDelegatedProperty)
-        topLevelIntDelegatedProperty = 88
-        topLevelIntOriginalAtomic.compareAndSet(88,  66)
-        assertEquals(66, topLevelIntOriginalAtomic.value)
-        assertEquals(66, topLevelIntDelegatedProperty)
-    }
-
-    @Test
-    fun testTopLevelDelegatedPropertiesLong() {
-        assertEquals(55555555555, topLevelDelegatedPropertyLong)
-        _topLevelLong.getAndIncrement()
-        assertEquals(55555555556, topLevelDelegatedPropertyLong)
-        topLevelDelegatedPropertyLong = 7777777777777
-        assertTrue(_topLevelLong.compareAndSet(7777777777777, 66666666666))
-        assertEquals(66666666666, _topLevelLong.value)
-        assertEquals(66666666666, topLevelDelegatedPropertyLong)
-    }
-
-    @Test
-    fun testTopLevelDelegatedPropertiesBoolean() {
-        assertEquals(false, topLevelDelegatedPropertyBoolean)
-        _topLevelBoolean.lazySet(true)
-        assertEquals(true, topLevelDelegatedPropertyBoolean)
-        topLevelDelegatedPropertyBoolean = false
-        assertTrue(_topLevelBoolean.compareAndSet(false, true))
-        assertEquals(true, _topLevelBoolean.value)
-        assertEquals(true, topLevelDelegatedPropertyBoolean)
-    }
-
-    @Test
-    fun testTopLevelDelegatedPropertiesRef() {
-        assertEquals("b", topLevelDelegatedPropertyRef[1])
-        _topLevelRef.lazySet(listOf("c"))
-        assertEquals("c", topLevelDelegatedPropertyRef[0])
-        topLevelDelegatedPropertyRef = listOf("d", "e")
-        assertEquals("e", _topLevelRef.value[1])
-    }
-
-    @Test
-    fun testVolatileTopLevelInt() {
-        assertEquals(77, vTopLevelInt)
-        vTopLevelInt = 55
-        assertEquals(110, vTopLevelInt * 2)
-    }
-
-    @Test
-    fun testVolatileTopLevelLong() {
-        assertEquals(777777777, vTopLevelLong)
-        vTopLevelLong = 55
-        assertEquals(55, vTopLevelLong)
-    }
-
-    @Test
-    fun testVolatileTopLevelBoolean() {
-        assertEquals(false, vTopLevelBoolean)
-        vTopLevelBoolean = true
-        assertEquals(true, vTopLevelBoolean)
-    }
-
-    @Test
-    fun testVolatileTopLevelRef() {
-        assertEquals("a", vTopLevelRef[0])
-        vTopLevelRef = listOf("c")
-        assertEquals("c", vTopLevelRef[0])
-    }
-
-    class A (val b: B)
-    class B (val n: Int)
-}
-
-class ExposedDelegatedPropertiesAccessorsTest {
-
-    private inner class A {
-        private val _node = atomic<Node?>(null)
-        var node: Node? by _node
-
-        fun cas(expect: Node, update: Node) = _node.compareAndSet(expect, update)
-    }
-
-    private class Node(val n: Int)
-
-    @Test
-    fun testDelegatedPropertiesAccessors() {
-        val a = A()
-        val update = Node(5)
-        a.node = update
-        assertTrue(a.cas(update, Node(6)))
-        assertEquals(6, a.node?.n)
-    }
-
-    @Test
-    fun testAccessors() {
-        val cl = DelegatedProperties()
-        assertEquals(42, cl.a)
-        cl.a = 66
-        assertEquals(66, cl.a)
-        assertEquals(55555555555, cl.l)
-        cl.l = 66666666
-        assertEquals(66666666, cl.l)
-        assertEquals(false, cl.b)
-        cl.b = true
-        assertEquals(true, cl.b)
-    }
-
-    @Test
-    fun testVolatileProperties() {
-        val cl = DelegatedProperties()
-        assertEquals(77, cl.vInt)
-        cl.vInt = 99
-        assertEquals(99, cl.vInt)
-    }
-}
-
-class ClashedNamesTest {
-    private class A1 {
-        val _a = atomic(0)
-        val a: Int by _a
-    }
-
-    private class A2 {
-        val _a = atomic(0)
-        val a: Int by _a
-    }
-
-    @Test
-    fun testClashedDelegatedPropertiesNames() {
-        val a1Class = A1()
-        val a2Class = A2()
-        a1Class._a.compareAndSet(0, 77)
-        assertEquals(77, a1Class.a)
-        assertEquals(0, a2Class.a)
-    }
-}
\ No newline at end of file
diff --git a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/AtomicFU.kt b/atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
similarity index 77%
rename from atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
rename to atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
index da1e7b6..403a6ef 100644
--- a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
+++ b/atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
@@ -2,57 +2,66 @@
  * Copyright 2017-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-@file:Suppress("NOTHING_TO_INLINE", "RedundantVisibilityModifier", "CanBePrimaryConstructorProperty")
+@file:Suppress(
+    "NOTHING_TO_INLINE",
+    "RedundantVisibilityModifier",
+    "CanBePrimaryConstructorProperty",
+    "INVISIBLE_REFERENCE",
+    "INVISIBLE_MEMBER"
+)
 
 package kotlinx.atomicfu
 
-import kotlin.reflect.KProperty
 import kotlinx.atomicfu.TraceBase.None
+import kotlin.internal.InlineOnly
+import kotlin.reflect.KProperty
 
-@JsName(ATOMIC_REF_FACTORY)
+@OptionalJsName(ATOMIC_REF_FACTORY)
 public actual fun <T> atomic(initial: T, trace: TraceBase): AtomicRef<T> = AtomicRef<T>(initial)
 
-@JsName(ATOMIC_REF_FACTORY_BINARY_COMPATIBILITY)
+@OptionalJsName(ATOMIC_REF_FACTORY_BINARY_COMPATIBILITY)
 public actual fun <T> atomic(initial: T): AtomicRef<T> = atomic(initial, None)
 
-@JsName(ATOMIC_INT_FACTORY)
+@OptionalJsName(ATOMIC_INT_FACTORY)
 public actual fun atomic(initial: Int, trace: TraceBase): AtomicInt = AtomicInt(initial)
 
-@JsName(ATOMIC_INT_FACTORY_BINARY_COMPATIBILITY)
+@OptionalJsName(ATOMIC_INT_FACTORY_BINARY_COMPATIBILITY)
 public actual fun atomic(initial: Int): AtomicInt = atomic(initial, None)
 
-@JsName(ATOMIC_LONG_FACTORY)
+@OptionalJsName(ATOMIC_LONG_FACTORY)
 public actual fun atomic(initial: Long, trace: TraceBase): AtomicLong = AtomicLong(initial)
 
-@JsName(ATOMIC_LONG_FACTORY_BINARY_COMPATIBILITY)
+@OptionalJsName(ATOMIC_LONG_FACTORY_BINARY_COMPATIBILITY)
 public actual fun atomic(initial: Long): AtomicLong = atomic(initial, None)
 
-@JsName(ATOMIC_BOOLEAN_FACTORY)
+@OptionalJsName(ATOMIC_BOOLEAN_FACTORY)
 public actual fun atomic(initial: Boolean, trace: TraceBase): AtomicBoolean = AtomicBoolean(initial)
 
-@JsName(ATOMIC_BOOLEAN_FACTORY_BINARY_COMPATIBILITY)
+@OptionalJsName(ATOMIC_BOOLEAN_FACTORY_BINARY_COMPATIBILITY)
 public actual fun atomic(initial: Boolean): AtomicBoolean = atomic(initial, None)
 
 // ==================================== AtomicRef ====================================
 
 public actual class AtomicRef<T> internal constructor(value: T) {
-    @JsName(ATOMIC_VALUE)
+    @OptionalJsName(ATOMIC_VALUE)
     public actual var value: T = value
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): T = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: T) { this.value = value }
 
     public actual inline fun lazySet(value: T) { this.value = value }
 
-    @JsName(COMPARE_AND_SET)
+    @OptionalJsName(COMPARE_AND_SET)
     public actual fun compareAndSet(expect: T, update: T): Boolean {
         if (value !== expect) return false
         value = update
         return true
     }
 
-    @JsName(GET_AND_SET)
+    @OptionalJsName(GET_AND_SET)
     public actual fun getAndSet(value: T): T {
         val oldValue = this.value
         this.value = value
@@ -65,25 +74,27 @@ public actual class AtomicRef<T> internal constructor(value: T) {
 // ==================================== AtomicBoolean ====================================
 
 public actual class AtomicBoolean internal constructor(value: Boolean) {
-    @JsName(ATOMIC_VALUE)
+    @OptionalJsName(ATOMIC_VALUE)
     public actual var value: Boolean = value
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Boolean = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Boolean) { this.value = value }
 
     public actual inline fun lazySet(value: Boolean) {
         this.value = value
     }
 
-    @JsName(COMPARE_AND_SET)
+    @OptionalJsName(COMPARE_AND_SET)
     public actual fun compareAndSet(expect: Boolean, update: Boolean): Boolean {
         if (value != expect) return false
         value = update
         return true
     }
 
-    @JsName(GET_AND_SET)
+    @OptionalJsName(GET_AND_SET)
     public actual fun getAndSet(value: Boolean): Boolean {
         val oldValue = this.value
         this.value = value
@@ -96,52 +107,54 @@ public actual class AtomicBoolean internal constructor(value: Boolean) {
 // ==================================== AtomicInt ====================================
 
 public actual class AtomicInt internal constructor(value: Int) {
-    @JsName(ATOMIC_VALUE)
+    @OptionalJsName(ATOMIC_VALUE)
     public actual var value: Int = value
 
+    @InlineOnly
     actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Int = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Int) { this.value = value }
 
     public actual inline fun lazySet(value: Int) { this.value = value }
 
-    @JsName(COMPARE_AND_SET)
+    @OptionalJsName(COMPARE_AND_SET)
     public actual fun compareAndSet(expect: Int, update: Int): Boolean {
         if (value != expect) return false
         value = update
         return true
     }
 
-    @JsName(GET_AND_SET)
+    @OptionalJsName(GET_AND_SET)
     public actual fun getAndSet(value: Int): Int {
         val oldValue = this.value
         this.value = value
         return oldValue
     }
 
-    @JsName(GET_AND_INCREMENT)
+    @OptionalJsName(GET_AND_INCREMENT)
     public actual fun getAndIncrement(): Int = value++
 
-    @JsName(GET_AND_DECREMENT)
+    @OptionalJsName(GET_AND_DECREMENT)
     public actual fun getAndDecrement(): Int = value--
 
-    @JsName(GET_AND_ADD)
+    @OptionalJsName(GET_AND_ADD)
     public actual fun getAndAdd(delta: Int): Int {
         val oldValue = value
         value += delta
         return oldValue
     }
 
-    @JsName(ADD_AND_GET)
+    @OptionalJsName(ADD_AND_GET)
     public actual fun addAndGet(delta: Int): Int {
         value += delta
         return value
     }
 
-    @JsName(INCREMENT_AND_GET)
+    @OptionalJsName(INCREMENT_AND_GET)
     public actual fun incrementAndGet(): Int = ++value
 
-    @JsName(DECREMENT_AND_GET)
+    @OptionalJsName(DECREMENT_AND_GET)
     public actual fun decrementAndGet(): Int = --value
 
     public actual inline operator fun plusAssign(delta: Int) { getAndAdd(delta) }
@@ -154,52 +167,54 @@ public actual class AtomicInt internal constructor(value: Int) {
 // ==================================== AtomicLong ====================================
 
 public actual class AtomicLong internal constructor(value: Long) {
-    @JsName(ATOMIC_VALUE)
+    @OptionalJsName(ATOMIC_VALUE)
     public actual var value: Long = value
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Long = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Long) { this.value = value }
 
     public actual inline fun lazySet(value: Long) { this.value = value }
 
-    @JsName(COMPARE_AND_SET)
+    @OptionalJsName(COMPARE_AND_SET)
     public actual fun compareAndSet(expect: Long, update: Long): Boolean {
         if (value != expect) return false
         value = update
         return true
     }
 
-    @JsName(GET_AND_SET)
+    @OptionalJsName(GET_AND_SET)
     public actual fun getAndSet(value: Long): Long {
         val oldValue = this.value
         this.value = value
         return oldValue
     }
 
-    @JsName(GET_AND_INCREMENT_LONG)
+    @OptionalJsName(GET_AND_INCREMENT_LONG)
     public actual fun getAndIncrement(): Long = value++
 
-    @JsName(GET_AND_DECREMENT_LONG)
+    @OptionalJsName(GET_AND_DECREMENT_LONG)
     public actual fun getAndDecrement(): Long = value--
 
-    @JsName(GET_AND_ADD_LONG)
+    @OptionalJsName(GET_AND_ADD_LONG)
     public actual fun getAndAdd(delta: Long): Long {
         val oldValue = value
         value += delta
         return oldValue
     }
 
-    @JsName(ADD_AND_GET_LONG)
+    @OptionalJsName(ADD_AND_GET_LONG)
     public actual fun addAndGet(delta: Long): Long {
         value += delta
         return value
     }
 
-    @JsName(INCREMENT_AND_GET_LONG)
+    @OptionalJsName(INCREMENT_AND_GET_LONG)
     public actual fun incrementAndGet(): Long = ++value
 
-    @JsName(DECREMENT_AND_GET_LONG)
+    @OptionalJsName(DECREMENT_AND_GET_LONG)
     public actual fun decrementAndGet(): Long = --value
 
     public actual inline operator fun plusAssign(delta: Long) { getAndAdd(delta) }
diff --git a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/Trace.kt b/atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/Trace.kt
similarity index 84%
rename from atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/Trace.kt
rename to atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/Trace.kt
index 03a4338..b232b2c 100644
--- a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/Trace.kt
+++ b/atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/Trace.kt
@@ -5,10 +5,10 @@
 package kotlinx.atomicfu
 
 @Suppress("FunctionName")
-@JsName(TRACE_FACTORY_FUNCTION)
+@OptionalJsName(TRACE_FACTORY_FUNCTION)
 public actual fun Trace(size: Int, format: TraceFormat): TraceBase = TraceBase.None
 
-@JsName(TRACE_NAMED)
+@OptionalJsName(TRACE_NAMED)
 public actual fun TraceBase.named(name: String): TraceBase = TraceBase.None
 
 public actual val traceFormatDefault: TraceFormat = TraceFormat()
\ No newline at end of file
diff --git a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt b/atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
similarity index 76%
rename from atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
rename to atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
index 7d8c450..3a025d5 100644
--- a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
+++ b/atomicfu/src/jsAndWasmSharedMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
@@ -2,9 +2,10 @@ package kotlinx.atomicfu.locks
 
 import kotlinx.atomicfu.REENTRANT_LOCK
 
+@Suppress("ACTUAL_CLASSIFIER_MUST_HAVE_THE_SAME_MEMBERS_AS_NON_FINAL_EXPECT_CLASSIFIER_WARNING")
 public actual typealias SynchronizedObject = Any
 
-@JsName(REENTRANT_LOCK)
+@kotlinx.atomicfu.OptionalJsName(REENTRANT_LOCK)
 public val Lock = ReentrantLock()
 
 @Suppress("NOTHING_TO_INLINE")
@@ -19,4 +20,4 @@ public actual class ReentrantLock {
 
 public actual inline fun <T> ReentrantLock.withLock(block: () -> T) = block()
 
-public actual inline fun <T> synchronized(lock: SynchronizedObject, block: () -> T): T = block()
\ No newline at end of file
+public actual inline fun <T> synchronized(lock: SynchronizedObject, block: () -> T): T = block()
diff --git a/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/OptionalJsName.kt b/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/OptionalJsName.kt
new file mode 100644
index 0000000..67cc2ef
--- /dev/null
+++ b/atomicfu/src/jsMain/kotlin/kotlinx/atomicfu/OptionalJsName.kt
@@ -0,0 +1,3 @@
+package kotlinx.atomicfu
+
+actual typealias OptionalJsName = JsName
diff --git a/atomicfu/src/jvmMain/kotlin/kotlinx/atomicfu/AtomicFU.kt b/atomicfu/src/jvmMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
index ddaf1dc..c76fd13 100644
--- a/atomicfu/src/jvmMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
+++ b/atomicfu/src/jvmMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
@@ -3,7 +3,7 @@
  */
 
 @file:JvmName("AtomicFU")
-@file:Suppress("NOTHING_TO_INLINE", "RedundantVisibilityModifier")
+@file:Suppress("NOTHING_TO_INLINE", "RedundantVisibilityModifier", "INVISIBLE_REFERENCE", "INVISIBLE_MEMBER")
 
 package kotlinx.atomicfu
 
@@ -12,6 +12,7 @@ import java.util.concurrent.atomic.AtomicLongFieldUpdater
 import java.util.concurrent.atomic.AtomicReferenceFieldUpdater
 import kotlin.reflect.KProperty
 import kotlinx.atomicfu.TraceBase.None
+import kotlin.internal.InlineOnly
 
 /**
  * Creates atomic reference with a given [initial] value.
@@ -84,8 +85,10 @@ public actual class AtomicRef<T> internal constructor(value: T, val trace: Trace
             if (trace !== None) trace { "set($value)" }
         }
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): T = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: T) { this.value = value }
 
     /**
@@ -135,8 +138,10 @@ public actual class AtomicBoolean internal constructor(v: Boolean, val trace: Tr
     @Volatile
     private var _value: Int = if (v) 1 else 0
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Boolean = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Boolean) { this.value = value }
 
     /**
@@ -204,8 +209,10 @@ public actual class AtomicInt internal constructor(value: Int, val trace: TraceB
             if (trace !== None) trace { "set($value)" }
         }
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Int = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Int) { this.value = value }
 
     /**
@@ -327,8 +334,10 @@ public actual class AtomicLong internal constructor(value: Long, val trace: Trac
             if (trace !== None) trace { "set($value)" }
         }
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Long = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Long) { this.value = value }
 
     /**
diff --git a/atomicfu/src/jvmTest/kotlin/kotlinx/atomicfu/test/AtomicfuBytecodeTest.kt b/atomicfu/src/jvmTest/kotlin/kotlinx/atomicfu/test/AtomicfuBytecodeTest.kt
index 958cf5f..0b09749 100644
--- a/atomicfu/src/jvmTest/kotlin/kotlinx/atomicfu/test/AtomicfuBytecodeTest.kt
+++ b/atomicfu/src/jvmTest/kotlin/kotlinx/atomicfu/test/AtomicfuBytecodeTest.kt
@@ -34,12 +34,6 @@ class AtomicfuBytecodeTest {
     @Test
     fun testTraceUseBytecode() = checkBytecode(TraceUseTest::class.java, listOf(KOTLINX_ATOMICFU))
 
-    /**
-     * Test [DelegatedProperties].
-     */
-    @Test
-    fun testDelegatedPropertiesBytecode() = checkBytecode(DelegatedProperties::class.java, listOf(KOTLIN_REFLECTION))
-
     private fun checkBytecode(javaClass: Class<*>, strings: List<String>) {
         val resourceName = javaClass.name.replace('.', '/') + ".class"
         val bytes = javaClass.classLoader.getResourceAsStream(resourceName)!!.use { it.readBytes() }
diff --git a/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/AtomicFU.kt b/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
index b369540..8a2d0bd 100644
--- a/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
+++ b/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/AtomicFU.kt
@@ -2,17 +2,24 @@
  * Copyright 2017-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-@file:Suppress("NOTHING_TO_INLINE", "RedundantVisibilityModifier", "CanBePrimaryConstructorProperty")
+@file:Suppress(
+    "NOTHING_TO_INLINE",
+    "RedundantVisibilityModifier",
+    "CanBePrimaryConstructorProperty",
+    "INVISIBLE_REFERENCE",
+    "INVISIBLE_MEMBER"
+)
 
 package kotlinx.atomicfu
 
-import kotlin.native.concurrent.AtomicInt as KAtomicInt
-import kotlin.native.concurrent.AtomicLong as KAtomicLong
-import kotlin.native.concurrent.FreezableAtomicReference as KAtomicRef
+import kotlin.concurrent.AtomicInt as KAtomicInt
+import kotlin.concurrent.AtomicLong as KAtomicLong
+import kotlin.concurrent.AtomicReference as KAtomicRef
 import kotlin.native.concurrent.isFrozen
 import kotlin.native.concurrent.freeze
 import kotlin.reflect.KProperty
 import kotlinx.atomicfu.TraceBase.None
+import kotlin.internal.InlineOnly
 
 public actual fun <T> atomic(initial: T, trace: TraceBase): AtomicRef<T> = AtomicRef<T>(KAtomicRef(initial))
 public actual fun <T> atomic(initial: T): AtomicRef<T> = atomic(initial, None)
@@ -26,7 +33,7 @@ public actual fun atomic(initial: Boolean): AtomicBoolean = atomic(initial, None
 // ==================================== AtomicRef ====================================
 
 @Suppress("ACTUAL_WITHOUT_EXPECT")
-public actual value class AtomicRef<T> internal constructor(@PublishedApi internal val a: KAtomicRef<T>) {
+public actual class AtomicRef<T> internal constructor(@PublishedApi internal val a: KAtomicRef<T>) {
     public actual inline var value: T
         get() = a.value
         set(value) {
@@ -34,8 +41,10 @@ public actual value class AtomicRef<T> internal constructor(@PublishedApi intern
             a.value = value
         }
 
+    @InlineOnly
     public actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): T = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: T) { this.value = value }
 
     public actual inline fun lazySet(value: T) {
@@ -53,7 +62,7 @@ public actual value class AtomicRef<T> internal constructor(@PublishedApi intern
         while (true) {
             val cur = a.value
             if (cur === value) return cur
-            if (a.compareAndSwap(cur, value) === cur) return cur
+            if (a.compareAndExchange(cur, value) === cur) return cur
         }
     }
 
@@ -63,7 +72,7 @@ public actual value class AtomicRef<T> internal constructor(@PublishedApi intern
 // ==================================== AtomicBoolean ====================================
 
 @Suppress("ACTUAL_WITHOUT_EXPECT")
-public actual value class AtomicBoolean internal constructor(@PublishedApi internal val a: KAtomicInt) {
+public actual class AtomicBoolean internal constructor(@PublishedApi internal val a: KAtomicInt) {
     public actual inline var value: Boolean
         get() = a.value != 0
         set(value) { a.value = if (value) 1 else 0 }
@@ -95,13 +104,15 @@ public actual value class AtomicBoolean internal constructor(@PublishedApi inter
 // ==================================== AtomicInt ====================================
 
 @Suppress("ACTUAL_WITHOUT_EXPECT")
-public actual value class AtomicInt internal constructor(@PublishedApi internal val a: KAtomicInt) {
+public actual class AtomicInt internal constructor(@PublishedApi internal val a: KAtomicInt) {
     public actual inline var value: Int
         get() = a.value
         set(value) { a.value = value }
 
+    @InlineOnly
     actual inline operator fun getValue(thisRef: Any?, property: KProperty<*>): Int = value
 
+    @InlineOnly
     public actual inline operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Int) { this.value = value }
 
     public actual inline fun lazySet(value: Int) { a.value = value }
@@ -133,7 +144,7 @@ public actual value class AtomicInt internal constructor(@PublishedApi internal
 // ==================================== AtomicLong ====================================
 
 @Suppress("ACTUAL_WITHOUT_EXPECT")
-public actual value class AtomicLong internal constructor(@PublishedApi internal val a: KAtomicLong) {
+public actual class AtomicLong internal constructor(@PublishedApi internal val a: KAtomicLong) {
     public actual inline var value: Long
         get() = a.value
         set(value) { a.value = value }
@@ -155,12 +166,12 @@ public actual value class AtomicLong internal constructor(@PublishedApi internal
         }
     }
 
-    public actual inline fun getAndIncrement(): Long = a.addAndGet(1) - 1
-    public actual inline fun getAndDecrement(): Long = a.addAndGet(-1) + 1
+    public actual inline fun getAndIncrement(): Long = a.addAndGet(1L) - 1
+    public actual inline fun getAndDecrement(): Long = a.addAndGet(-1L) + 1
     public actual inline fun getAndAdd(delta: Long): Long = a.addAndGet(delta) - delta
     public actual inline fun addAndGet(delta: Long): Long = a.addAndGet(delta)
-    public actual inline fun incrementAndGet(): Long = a.addAndGet(1)
-    public actual inline fun decrementAndGet(): Long = a.addAndGet(-1)
+    public actual inline fun incrementAndGet(): Long = a.addAndGet(1L)
+    public actual inline fun decrementAndGet(): Long = a.addAndGet(-1L)
 
     public actual inline operator fun plusAssign(delta: Long) { getAndAdd(delta) }
     public actual inline operator fun minusAssign(delta: Long) { getAndAdd(-delta) }
diff --git a/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt b/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
index 76e5d7a..968bbdf 100644
--- a/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
+++ b/atomicfu/src/nativeMain/kotlin/kotlinx/atomicfu/locks/Synchronized.kt
@@ -3,9 +3,13 @@ package kotlinx.atomicfu.locks
 import platform.posix.*
 import interop.*
 import kotlinx.cinterop.*
-import kotlin.native.concurrent.*
+import kotlin.concurrent.*
 import kotlin.native.internal.NativePtr
 import kotlinx.atomicfu.locks.SynchronizedObject.Status.*
+import kotlin.concurrent.AtomicNativePtr
+import kotlin.concurrent.AtomicReference
+import kotlin.native.SharedImmutable
+import kotlin.native.concurrent.*
 
 public actual open class SynchronizedObject {
 
@@ -217,4 +221,4 @@ class MutexPool(capacity: Int) {
                 return oldTop
         }
     }
-}
\ No newline at end of file
+}
diff --git a/atomicfu/src/nativeTest/kotlin/kotlinx/atomicfu/locks/SynchronizedTest.kt b/atomicfu/src/nativeTest/kotlin/kotlinx/atomicfu/locks/SynchronizedTest.kt
index a1a718c..01c843b 100644
--- a/atomicfu/src/nativeTest/kotlin/kotlinx/atomicfu/locks/SynchronizedTest.kt
+++ b/atomicfu/src/nativeTest/kotlin/kotlinx/atomicfu/locks/SynchronizedTest.kt
@@ -1,5 +1,6 @@
 package kotlinx.atomicfu.locks
 
+import kotlin.concurrent.AtomicInt
 import kotlin.native.concurrent.*
 import kotlin.test.*
 
diff --git a/build.gradle b/build.gradle
index 09a62fe..1d986db 100644
--- a/build.gradle
+++ b/build.gradle
@@ -5,86 +5,97 @@
 import org.jetbrains.kotlin.konan.target.HostManager
 
 buildscript {
+    def overridingKotlinVersion = KotlinConfiguration.getOverridingKotlinVersion(project)
+    if (overridingKotlinVersion != null) { project.kotlin_version = overridingKotlinVersion }
+
     /*
-     * These property group is used to build kotlinx.atomicfu against Kotlin compiler snapshot.
-     * How does it work:
-     * When build_snapshot_train is set to true, kotlin_version property is overridden with kotlin_snapshot_version,
-     * Additionally, mavenLocal and Sonatype snapshots are added to repository list (the former is required for AFU and public
-     * the latter is required for compiler snapshots).
+     * This property group is used to build kotlinx.atomicfu against Kotlin compiler snapshots.
+     * When build_snapshot_train is set to true, kotlin_version property is overridden with kotlin_snapshot_version.
+     * Additionally, mavenLocal and Sonatype snapshots are added to repository list
+     * (the former is required for AFU and public, the latter is required for compiler snapshots).
      * DO NOT change the name of these properties without adapting kotlinx.train build chain.
      */
-    def prop = rootProject.properties['build_snapshot_train']
-    ext.build_snapshot_train = prop != null && prop != ""
+    def buildSnapshotTrainGradleProperty = project.findProperty("build_snapshot_train")
+    ext.build_snapshot_train = buildSnapshotTrainGradleProperty != null && buildSnapshotTrainGradleProperty != ""
     if (build_snapshot_train) {
-        ext.kotlin_version = rootProject.properties['kotlin_snapshot_version']
-        if (kotlin_version == null) {
-            throw new IllegalArgumentException("'kotlin_snapshot_version' should be defined when building with snapshot compiler")
+        project.kotlin_version = project.findProperty("kotlin_snapshot_version")
+        if (project.kotlin_version == null) {
+            throw new IllegalArgumentException("'kotlin_snapshot_version' should be defined when building with a snapshot compiler")
         }
         repositories {
-            mavenLocal()
             maven { url "https://oss.sonatype.org/content/repositories/snapshots" }
         }
     }
-    // These two flags are enabled in train builds for JVM IR compiler testing
-    ext.jvm_ir_enabled = rootProject.properties['enable_jvm_ir'] != null
-    ext.native_targets_enabled = rootProject.properties['disable_native_targets'] == null
 
     repositories {
-        jcenter()
-        maven { url "https://plugins.gradle.org/m2/" }
-        // Future replacement for kotlin-dev, with cache redirector
-        maven { url "https://cache-redirector.jetbrains.com/maven.pkg.jetbrains.space/kotlin/p/kotlin/dev" }
-        maven { url "https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev" }
+        mavenCentral()
+        gradlePluginPortal()
+        KotlinConfiguration.addCustomKotlinRepositoryIfEnabled(delegate, project)
     }
-    
+
     dependencies {
         classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
-        classpath "com.moowork.gradle:gradle-node-plugin:$gradle_node_version"
+        classpath "com.github.node-gradle:gradle-node-plugin:$gradle_node_version"
     }
+
+    ext.native_targets_enabled = !project.hasProperty("disable_native_targets")
+}
+
+plugins {
+    id 'org.jetbrains.kotlinx.binary-compatibility-validator' version '0.13.2'
 }
 
 allprojects {
     // the only place where HostManager could be instantiated
     project.ext.hostManager = new HostManager()
+
+    def overridingKotlinVersion = KotlinConfiguration.getOverridingKotlinVersion(project)
+    if (overridingKotlinVersion != null) { project.kotlin_version = overridingKotlinVersion }
+
     if (build_snapshot_train) {
-        kotlin_version = rootProject.properties['kotlin_snapshot_version']
+        project.kotlin_version = project.findProperty("kotlin_snapshot_version")
         repositories {
-            mavenLocal()
             maven { url "https://oss.sonatype.org/content/repositories/snapshots" }
         }
     }
 
-    println "Using Kotlin $kotlin_version for project $it"
+    logger.info("Using Kotlin compiler ${project.kotlin_version} for project ${project.name}")
+
     repositories {
-        jcenter()
-        // Future replacement for kotlin-dev, with cache redirector
-        maven { url "https://cache-redirector.jetbrains.com/maven.pkg.jetbrains.space/kotlin/p/kotlin/dev" }
-        maven { url "https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev" }
+        mavenCentral()
+        KotlinConfiguration.addCustomKotlinRepositoryIfEnabled(delegate, project)
     }
 
-    def deployVersion = properties['DeployVersion']
-    if (deployVersion != null) version = deployVersion
+    def deployVersion = project.findProperty("DeployVersion")
+    if (deployVersion != null) project.version = deployVersion
 
-    // 'atomicfu-native' check is a kludge so that existing YouTrack config works, todo: remove
-    if (project != rootProject && project.name != 'atomicfu-native') {
+    // atomicfu-native check is a kludge so that existing YouTrack config works, todo: remove
+    if (project != rootProject && project.name != "atomicfu-native") {
         apply from: rootProject.file("gradle/publishing.gradle")
     }
 
-    // This fixes "org.gradle.jvm.version" in Gradle metadata
-    plugins.withType(JavaPlugin) {
+    // this fixes "org.gradle.jvm.version" in Gradle metadata
+    plugins.withType(JavaPlugin).configureEach {
         java {
-            sourceCompatibility = JavaVersion.VERSION_1_8
-            targetCompatibility = JavaVersion.VERSION_1_8
+            toolchain {
+                languageVersion.set(JavaLanguageVersion.of(8))
+            }
         }
     }
+
+    tasks.withType(org.jetbrains.kotlin.gradle.tasks.Kotlin2JsCompile).configureEach {
+        compilerOptions { freeCompilerArgs.add("-Xpartial-linkage-loglevel=ERROR") }
+    }
+    tasks.withType(org.jetbrains.kotlin.gradle.tasks.KotlinNativeCompile).configureEach {
+        compilerOptions { freeCompilerArgs.add("-Xpartial-linkage-loglevel=ERROR") }
+    }
 }
 
-println("Using Kotlin compiler version: $org.jetbrains.kotlin.config.KotlinCompilerVersion.VERSION")
 if (build_snapshot_train) {
     afterEvaluate {
         println "Manifest of kotlin-compiler-embeddable.jar for atomicfu"
         configure(subprojects.findAll { it.name == "atomicfu" }) {
-            configurations.matching { it.name == "kotlinCompilerClasspath" }.all {
+            configurations.matching { it.name == "kotlinCompilerClasspath" }.configureEach {
                 resolvedConfiguration.getFiles().findAll { it.name.contains("kotlin-compiler-embeddable") }.each {
                     def manifest = zipTree(it).matching {
                         include 'META-INF/MANIFEST.MF'
@@ -101,3 +112,15 @@ if (build_snapshot_train) {
 
 // main deployment task
 task deploy(dependsOn: getTasksByName("publish", true) + getTasksByName("publishNpm", true))
+
+// Right now it is used for switching nodejs version which is supports generated wasm bytecode
+extensions.findByType(org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootExtension.class).with {
+    // canary nodejs that supports recent Wasm GC changes
+    it.nodeVersion = '21.0.0-v8-canary202309167e82ab1fa2'
+    it.nodeDownloadBaseUrl = 'https://nodejs.org/download/v8-canary'
+}
+
+// We need to ignore unsupported engines (i.e. canary) for npm
+tasks.withType(org.jetbrains.kotlin.gradle.targets.js.npm.tasks.KotlinNpmInstallTask).configureEach {
+    args.add("--ignore-engines")
+}
diff --git a/buildSrc/build.gradle.kts b/buildSrc/build.gradle.kts
index 8b6b358..876c922 100644
--- a/buildSrc/build.gradle.kts
+++ b/buildSrc/build.gradle.kts
@@ -1,14 +1,7 @@
-import org.jetbrains.kotlin.gradle.plugin.*
-import java.util.*
-
 plugins {
     `kotlin-dsl`
 }
 
 repositories {
-    jcenter()
-}
-
-kotlinDslPluginOptions {
-    experimentalWarning.set(false)
+    mavenCentral()
 }
diff --git a/buildSrc/src/main/kotlin/KotlinConfiguration.kt b/buildSrc/src/main/kotlin/KotlinConfiguration.kt
new file mode 100644
index 0000000..eccac26
--- /dev/null
+++ b/buildSrc/src/main/kotlin/KotlinConfiguration.kt
@@ -0,0 +1,112 @@
+@file:JvmName("KotlinConfiguration")
+
+import org.gradle.api.Project
+import org.gradle.api.artifacts.dsl.RepositoryHandler
+import java.net.URI
+import java.util.logging.Logger
+
+/*
+ * Functions in this file are responsible for configuring atomicfu build
+ * against a custom development version of Kotlin compiler.
+ * Such configuration is used in Kotlin aggregate builds and builds of Kotlin user projects
+ * in order to check whether not-yet-released changes are compatible with our libraries
+ * (aka "integration testing that substitutes lack of unit testing").
+ */
+
+private val LOGGER: Logger = Logger.getLogger("Kotlin settings logger")
+
+/**
+ * Should be used for running against a non-released Kotlin compiler on a system test level.
+ *
+ * @return a custom repository with development builds of the Kotlin compiler taken from:
+ *
+ * 1. the Kotlin community project Gradle plugin,
+ * 2. or `kotlin_repo_url` Gradle property (from command line or from `gradle.properties`),
+ *
+ * or null otherwise
+ */
+fun getCustomKotlinRepositoryURL(project: Project): String? {
+    val communityPluginKotlinRepoURL = project.findProperty("community.project.kotlin.repo") as? String
+    val gradlePropertyKotlinRepoURL = project.findProperty("kotlin_repo_url") as? String
+    val kotlinRepoURL = when {
+        communityPluginKotlinRepoURL != null -> communityPluginKotlinRepoURL
+        gradlePropertyKotlinRepoURL != null -> gradlePropertyKotlinRepoURL
+        else -> return null
+    }
+    LOGGER.info("A custom Kotlin repository $kotlinRepoURL was found for project ${project.name}")
+    return kotlinRepoURL
+}
+
+/**
+ * Should be used for running against a non-released Kotlin compiler on a system test level.
+ *
+ * Adds a custom repository with development builds of the Kotlin compiler to [repositoryHandler]
+ * if the URL is provided (see [getCustomKotlinRepositoryURL]).
+ */
+fun addCustomKotlinRepositoryIfEnabled(repositoryHandler: RepositoryHandler, project: Project) {
+    val kotlinRepoURL = getCustomKotlinRepositoryURL(project) ?: return
+    repositoryHandler.maven { url = URI.create(kotlinRepoURL) }
+
+}
+
+/**
+ * Should be used for running against a non-released Kotlin compiler on a system test level.
+ *
+ * @return a Kotlin version taken from the Kotlin community project Gradle plugin,
+ *         or null otherwise
+ */
+fun getOverridingKotlinVersion(project: Project): String? {
+    val communityPluginKotlinVersion = project.findProperty("community.project.kotlin.version") as? String
+    // add any other ways of overriding the Kotlin version here
+    val kotlinVersion = when {
+        communityPluginKotlinVersion != null -> communityPluginKotlinVersion
+        // add any other ways of overriding the Kotlin version here
+        else -> return null
+    }
+    LOGGER.info("An overriding Kotlin version of $kotlinVersion was found for project ${project.name}")
+    return kotlinVersion
+}
+
+/**
+ * Should be used for running against a non-released Kotlin compiler on a system test level.
+ *
+ * @return a Kotlin language version taken from:
+ *
+ * 1. the Kotlin community project Gradle plugin,
+ * 2. or `kotlin_language_version` Gradle property (from command line or from `gradle.properties`),
+ *
+ * or null otherwise
+ */
+fun getOverridingKotlinLanguageVersion(project: Project): String? {
+    val communityPluginLanguageVersion = project.findProperty("community.project.kotlin.languageVersion") as? String
+    val gradlePropertyLanguageVersion = project.findProperty("kotlin_language_version") as? String
+    val languageVersion = when {
+        communityPluginLanguageVersion != null -> communityPluginLanguageVersion
+        gradlePropertyLanguageVersion != null -> gradlePropertyLanguageVersion
+        else -> return null
+    }
+    LOGGER.info("An overriding Kotlin language version of $languageVersion was found for project ${project.name}")
+    return languageVersion
+}
+
+/**
+ * Should be used for running against a non-released Kotlin compiler on a system test level.
+ *
+ * @return a Kotlin API version taken from:
+ *
+ * 1. the Kotlin community project Gradle plugin,
+ * 2. or `kotlin_language_version` Gradle property (from command line or from `gradle.properties`),
+ *
+ * or null otherwise
+ */
+fun getOverridingKotlinApiVersion(project: Project): String? {
+    val communityPluginApiVersion = project.findProperty("community.project.kotlin.apiVersion") as? String
+    val gradlePropertyApiVersion = project.findProperty("kotlin_api_version") as? String
+    val apiVersion = when {
+        communityPluginApiVersion != null -> communityPluginApiVersion
+        gradlePropertyApiVersion != null -> gradlePropertyApiVersion
+        else -> return null
+    }
+    LOGGER.info("An overriding Kotlin api version of $apiVersion was found for project ${project.name}")
+    return apiVersion
+}
diff --git a/buildSrc/src/main/kotlin/MavenPomConfiguration.kt b/buildSrc/src/main/kotlin/MavenPomConfiguration.kt
new file mode 100644
index 0000000..42d128d
--- /dev/null
+++ b/buildSrc/src/main/kotlin/MavenPomConfiguration.kt
@@ -0,0 +1,40 @@
+@file:JvmName("MavenPomConfiguration")
+
+import org.gradle.api.*
+import org.gradle.api.publish.maven.*
+
+fun MavenPom.configureMavenPluginPomAttributes(
+    project: Project,
+    outputDir: String
+) {
+    val customKotlinRepoURL = getCustomKotlinRepositoryURL(project)
+    val buildSnapshots = project.hasProperty("build_snapshot_train")
+    name.set(project.name)
+    packaging = "maven-plugin"
+    description.set("Atomicfu Maven Plugin")
+
+    withXml {
+        with(asNode()) {
+            with(appendNode("build")) {
+                appendNode("directory", project.buildDir)
+                appendNode("outputDirectory", outputDir)
+            }
+            appendNode("properties")
+                .appendNode("project.build.sourceEncoding", "UTF-8")
+            with(appendNode("repositories")) {
+                if (!customKotlinRepoURL.isNullOrEmpty()) {
+                    with(appendNode("repository")) {
+                        appendNode("id", "dev")
+                        appendNode("url", customKotlinRepoURL)
+                    }
+                }
+                if (buildSnapshots) {
+                    with(appendNode("repository")) {
+                        appendNode("id", "kotlin-snapshots")
+                        appendNode("url", "https://oss.sonatype.org/content/repositories/snapshots")
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/buildSrc/src/main/kotlin/Publishing.kt b/buildSrc/src/main/kotlin/Publishing.kt
index 3db911f..2af4950 100644
--- a/buildSrc/src/main/kotlin/Publishing.kt
+++ b/buildSrc/src/main/kotlin/Publishing.kt
@@ -45,12 +45,10 @@ fun MavenPom.configureMavenCentralMetadata(project: Project) {
 }
 
 fun mavenRepositoryUri(): URI {
-    // TODO -SNAPSHOT detection can be made here as well
     val repositoryId: String? = System.getenv("libs.repository.id")
     return if (repositoryId == null) {
         // Using implicitly created staging, for MPP it's likely to be a mistake because
         // publication on TeamCity will create 3 independent staging repositories
-        System.err.println("Warning: using an implicitly created staging for atomicfu")
         URI("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
     } else {
         URI("https://oss.sonatype.org/service/local/staging/deployByRepositoryId/$repositoryId")
diff --git a/gradle.properties b/gradle.properties
index 903d60d..443b6ee 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -2,18 +2,19 @@
 # Copyright 2016-2020 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
 #
 
-version=0.18.5-SNAPSHOT
+version=0.23.1-SNAPSHOT
 group=org.jetbrains.kotlinx
 
-kotlin_version=1.7.20
+kotlin_version=1.9.21
+
 asm_version=9.3
 slf4j_version=1.8.0-alpha2
 junit_version=4.12
-kotlinx_metadata_version=0.5.0
+kotlinx_metadata_version=0.7.0
 
 maven_version=3.5.3
 
-gradle_node_version=1.2.0
+gradle_node_version=3.1.1
 node_version=8.11.1
 npm_version=5.7.1
 mocha_version=4.1.0
@@ -21,13 +22,9 @@ mocha_headless_chrome_version=1.8.2
 mocha_teamcity_reporter_version=2.2.2
 source_map_support_version=0.5.3
 
-kotlin.incremental.multiplatform=true
 kotlin.native.ignoreDisabledTargets=true
 
-kotlin.js.compiler=both
-
-kotlin.mpp.enableGranularSourceSetsMetadata=true
-kotlin.mpp.enableCompatibilityMetadataVariant=true
+kotlin.mpp.enableCInteropCommonization=true
 
 # Workaround for Bintray treating .sha512 files as artifacts
 # https://github.com/gradle/gradle/issues/11412
diff --git a/gradle/compile-options.gradle b/gradle/compile-options.gradle
index b6ce532..3ae24e3 100644
--- a/gradle/compile-options.gradle
+++ b/gradle/compile-options.gradle
@@ -1,26 +1,16 @@
-
 /*
  * Copyright 2017-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-ext.configureKotlin = { isMultiplatform ->
-    if (rootProject.ext.jvm_ir_enabled) {
-        println "Using JVM IR compiler for project $project.name"
-        if (isMultiplatform) {
-            kotlin.jvm().compilations.all {
-                kotlinOptions.useIR = true
-            }
-        } else {
-            kotlin.target.compilations.all {
-                kotlinOptions.useIR = true
-            }
-        }
-    }
-
-    kotlin.sourceSets.all {
+ext.configureKotlin = {
+    kotlin.sourceSets.configureEach {
         languageSettings {
-            apiVersion = "1.4"
-            languageVersion = "1.4"
+            def overridingKotlinLanguageVersion = KotlinConfiguration.getOverridingKotlinLanguageVersion(project)
+            if (overridingKotlinLanguageVersion != null) { languageVersion = overridingKotlinLanguageVersion }
+            def overridingKotlinApiVersion = KotlinConfiguration.getOverridingKotlinApiVersion(project)
+            if (overridingKotlinApiVersion != null) { apiVersion = overridingKotlinApiVersion }
+
+            optIn('kotlinx.cinterop.ExperimentalForeignApi')
         }
     }
 }
diff --git a/gradle/interop-as-source-set-klib.gradle b/gradle/interop-as-source-set-klib.gradle
deleted file mode 100644
index 25cb0c2..0000000
--- a/gradle/interop-as-source-set-klib.gradle
+++ /dev/null
@@ -1,55 +0,0 @@
-/*
- * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
- */
-
-project.ext.registerInteropAsSourceSetOutput = { interop, sourceSet ->
-    afterEvaluate {
-        def cinteropTask = tasks.named(interop.interopProcessingTaskName)
-        def cinteropKlib = cinteropTask.map { it.outputFile }
-        def fakeCinteropCompilation = kotlin.targets["metadata"].compilations[sourceSet.name]
-        def destination = fakeCinteropCompilation.compileKotlinTask.destinationDirectory
-
-        def tempDir = "$buildDir/tmp/${sourceSet.name}UnpackedInteropKlib"
-
-        def prepareKlibTaskProvider = tasks.register("prepare${sourceSet.name.capitalize()}InteropKlib", Sync) {
-            from(files(zipTree(cinteropKlib).matching {
-                exclude("targets/**", "default/targets/**")
-            }).builtBy(cinteropTask))
-
-            into(tempDir)
-
-            doLast {
-                def manifest140 = file("$tempDir/default/manifest")
-                def manifest1371 = file("$tempDir/manifest")
-                def manifest = manifest140.exists() ? manifest140 : manifest1371
-
-                def lines = manifest.readLines()
-                def modifiedLines = lines.collect { line ->
-                    line.startsWith("depends=") ? "depends=stdlib ${manifest == manifest140 ? 'org.jetbrains.kotlin.native.platform.posix' : 'posix'}" :
-                            line.startsWith("native_targets=") ? "native_targets=" :
-                                    line
-                }
-                manifest.text = modifiedLines.join("\n")
-            }
-        }
-
-        def copyCinteropTaskProvider = tasks.register("copy${sourceSet.name.capitalize()}CinteropKlib",  Zip) {
-            from(fileTree(tempDir).builtBy(prepareKlibTaskProvider))
-            destinationDirectory.set(destination)
-            archiveFileName.set("${project.name}_${fakeCinteropCompilation.name}.klib")
-            dependsOn cinteropTask
-        }
-
-        fakeCinteropCompilation.output.classesDirs.from(files().builtBy(copyCinteropTaskProvider))
-
-        kotlin.sourceSets.matching {
-            def visited = new HashSet()
-            def visit
-            visit = { s -> if (visited.add(s)) s.dependsOn.each { visit(it) } }
-            visit(it)
-            sourceSet in visited
-        }.all {
-            project.dependencies.add(implementationMetadataConfigurationName, files(cinteropKlib))
-        }
-    }
-}
diff --git a/gradle/node-js.gradle b/gradle/node-js.gradle
index 6766dee..921bdcf 100644
--- a/gradle/node-js.gradle
+++ b/gradle/node-js.gradle
@@ -2,7 +2,8 @@
  * Copyright 2017-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-apply plugin: 'com.moowork.node'
+apply plugin: 'com.github.node-gradle.node'
+
 
 node {
     version = "$node_version"
diff --git a/gradle/publishing.gradle b/gradle/publishing.gradle
index e9e4372..01c74b3 100644
--- a/gradle/publishing.gradle
+++ b/gradle/publishing.gradle
@@ -4,7 +4,6 @@
 
 // Configures publishing of Maven artifacts to Bintray
 
-apply plugin: 'maven'
 apply plugin: 'maven-publish'
 apply plugin: 'signing'
 
@@ -31,7 +30,7 @@ publishing {
     repositories { // this: closure
         PublishingKt.configureMavenPublication(delegate, project)
     }
-    
+
     if (!isMultiplatform) {
         // Configure java publications for non-MPP projects
         publications {
@@ -56,10 +55,27 @@ publishing {
     publications.all {
         PublishingKt.configureMavenCentralMetadata(pom, project)
         PublishingKt.signPublicationIfKeyPresent(project, it)
-
         // add empty javadocs
         if (it.name != "kotlinMultiplatform") { // The root module gets the JVM's javadoc JAR
             it.artifact(javadocJar)
         }
     }
+
+    tasks.withType(AbstractPublishToMaven).configureEach {
+        dependsOn(tasks.withType(Sign))
+    }
+
+    // NOTE: This is a temporary WA, see KT-61313.
+    tasks.withType(Sign).configureEach { signTask ->
+        def pubName = name.takeBetween("sign", "Publication")
+
+        // Task ':linkDebugTest<platform>' uses this output of task ':sign<platform>Publication' without declaring an explicit or implicit dependency
+        tasks.findByName("linkDebugTest$pubName")?.configure {
+            mustRunAfter(signTask)
+        }
+        // Task ':compileTestKotlin<platform>' uses this output of task ':sign<platform>Publication' without declaring an explicit or implicit dependency
+        tasks.findByName("compileTestKotlin$pubName")?.configure {
+            mustRunAfter(signTask)
+        }
+    }
 }
diff --git a/gradle/wrapper/gradle-wrapper.jar b/gradle/wrapper/gradle-wrapper.jar
index 28861d2..033e24c 100644
Binary files a/gradle/wrapper/gradle-wrapper.jar and b/gradle/wrapper/gradle-wrapper.jar differ
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 0904b9b..ac72c34 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -1,5 +1,7 @@
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.3-bin.zip
+networkTimeout=10000
+validateDistributionUrl=true
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-6.8.3-all.zip
diff --git a/gradlew b/gradlew
index cccdd3d..fcb6fca 100755
--- a/gradlew
+++ b/gradlew
@@ -1,78 +1,126 @@
-#!/usr/bin/env sh
+#!/bin/sh
+
+#
+# Copyright © 2015-2021 the original authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
 
 ##############################################################################
-##
-##  Gradle start up script for UN*X
-##
+#
+#   Gradle start up script for POSIX generated by Gradle.
+#
+#   Important for running:
+#
+#   (1) You need a POSIX-compliant shell to run this script. If your /bin/sh is
+#       noncompliant, but you have some other compliant shell such as ksh or
+#       bash, then to run this script, type that shell name before the whole
+#       command line, like:
+#
+#           ksh Gradle
+#
+#       Busybox and similar reduced shells will NOT work, because this script
+#       requires all of these POSIX shell features:
+#         * functions;
+#         * expansions «$var», «${var}», «${var:-default}», «${var+SET}»,
+#           «${var#prefix}», «${var%suffix}», and «$( cmd )»;
+#         * compound commands having a testable exit status, especially «case»;
+#         * various built-in commands including «command», «set», and «ulimit».
+#
+#   Important for patching:
+#
+#   (2) This script targets any POSIX shell, so it avoids extensions provided
+#       by Bash, Ksh, etc; in particular arrays are avoided.
+#
+#       The "traditional" practice of packing multiple parameters into a
+#       space-separated string is a well documented source of bugs and security
+#       problems, so this is (mostly) avoided, by progressively accumulating
+#       options in "$@", and eventually passing that to Java.
+#
+#       Where the inherited environment variables (DEFAULT_JVM_OPTS, JAVA_OPTS,
+#       and GRADLE_OPTS) rely on word-splitting, this is performed explicitly;
+#       see the in-line comments for details.
+#
+#       There are tweaks for specific operating systems such as AIX, CygWin,
+#       Darwin, MinGW, and NonStop.
+#
+#   (3) This script is generated from the Groovy template
+#       https://github.com/gradle/gradle/blob/HEAD/subprojects/plugins/src/main/resources/org/gradle/api/internal/plugins/unixStartScript.txt
+#       within the Gradle project.
+#
+#       You can find Gradle at https://github.com/gradle/gradle/.
+#
 ##############################################################################
 
 # Attempt to set APP_HOME
+
 # Resolve links: $0 may be a link
-PRG="$0"
-# Need this for relative symlinks.
-while [ -h "$PRG" ] ; do
-    ls=`ls -ld "$PRG"`
-    link=`expr "$ls" : '.*-> \(.*\)$'`
-    if expr "$link" : '/.*' > /dev/null; then
-        PRG="$link"
-    else
-        PRG=`dirname "$PRG"`"/$link"
-    fi
+app_path=$0
+
+# Need this for daisy-chained symlinks.
+while
+    APP_HOME=${app_path%"${app_path##*/}"}  # leaves a trailing /; empty if no leading path
+    [ -h "$app_path" ]
+do
+    ls=$( ls -ld "$app_path" )
+    link=${ls#*' -> '}
+    case $link in             #(
+      /*)   app_path=$link ;; #(
+      *)    app_path=$APP_HOME$link ;;
+    esac
 done
-SAVED="`pwd`"
-cd "`dirname \"$PRG\"`/" >/dev/null
-APP_HOME="`pwd -P`"
-cd "$SAVED" >/dev/null
-
-APP_NAME="Gradle"
-APP_BASE_NAME=`basename "$0"`
 
-# Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
-DEFAULT_JVM_OPTS=""
+# This is normally unused
+# shellcheck disable=SC2034
+APP_BASE_NAME=${0##*/}
+APP_HOME=$( cd "${APP_HOME:-./}" && pwd -P ) || exit
 
 # Use the maximum available, or set MAX_FD != -1 to use that value.
-MAX_FD="maximum"
+MAX_FD=maximum
 
 warn () {
     echo "$*"
-}
+} >&2
 
 die () {
     echo
     echo "$*"
     echo
     exit 1
-}
+} >&2
 
 # OS specific support (must be 'true' or 'false').
 cygwin=false
 msys=false
 darwin=false
 nonstop=false
-case "`uname`" in
-  CYGWIN* )
-    cygwin=true
-    ;;
-  Darwin* )
-    darwin=true
-    ;;
-  MINGW* )
-    msys=true
-    ;;
-  NONSTOP* )
-    nonstop=true
-    ;;
+case "$( uname )" in                #(
+  CYGWIN* )         cygwin=true  ;; #(
+  Darwin* )         darwin=true  ;; #(
+  MSYS* | MINGW* )  msys=true    ;; #(
+  NONSTOP* )        nonstop=true ;;
 esac
 
 CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar
 
+
 # Determine the Java command to use to start the JVM.
 if [ -n "$JAVA_HOME" ] ; then
     if [ -x "$JAVA_HOME/jre/sh/java" ] ; then
         # IBM's JDK on AIX uses strange locations for the executables
-        JAVACMD="$JAVA_HOME/jre/sh/java"
+        JAVACMD=$JAVA_HOME/jre/sh/java
     else
-        JAVACMD="$JAVA_HOME/bin/java"
+        JAVACMD=$JAVA_HOME/bin/java
     fi
     if [ ! -x "$JAVACMD" ] ; then
         die "ERROR: JAVA_HOME is set to an invalid directory: $JAVA_HOME
@@ -81,92 +129,120 @@ Please set the JAVA_HOME variable in your environment to match the
 location of your Java installation."
     fi
 else
-    JAVACMD="java"
-    which java >/dev/null 2>&1 || die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
+    JAVACMD=java
+    if ! command -v java >/dev/null 2>&1
+    then
+        die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
 
 Please set the JAVA_HOME variable in your environment to match the
 location of your Java installation."
+    fi
 fi
 
 # Increase the maximum file descriptors if we can.
-if [ "$cygwin" = "false" -a "$darwin" = "false" -a "$nonstop" = "false" ] ; then
-    MAX_FD_LIMIT=`ulimit -H -n`
-    if [ $? -eq 0 ] ; then
-        if [ "$MAX_FD" = "maximum" -o "$MAX_FD" = "max" ] ; then
-            MAX_FD="$MAX_FD_LIMIT"
-        fi
-        ulimit -n $MAX_FD
-        if [ $? -ne 0 ] ; then
-            warn "Could not set maximum file descriptor limit: $MAX_FD"
-        fi
-    else
-        warn "Could not query maximum file descriptor limit: $MAX_FD_LIMIT"
-    fi
+if ! "$cygwin" && ! "$darwin" && ! "$nonstop" ; then
+    case $MAX_FD in #(
+      max*)
+        # In POSIX sh, ulimit -H is undefined. That's why the result is checked to see if it worked.
+        # shellcheck disable=SC3045
+        MAX_FD=$( ulimit -H -n ) ||
+            warn "Could not query maximum file descriptor limit"
+    esac
+    case $MAX_FD in  #(
+      '' | soft) :;; #(
+      *)
+        # In POSIX sh, ulimit -n is undefined. That's why the result is checked to see if it worked.
+        # shellcheck disable=SC3045
+        ulimit -n "$MAX_FD" ||
+            warn "Could not set maximum file descriptor limit to $MAX_FD"
+    esac
 fi
 
-# For Darwin, add options to specify how the application appears in the dock
-if $darwin; then
-    GRADLE_OPTS="$GRADLE_OPTS \"-Xdock:name=$APP_NAME\" \"-Xdock:icon=$APP_HOME/media/gradle.icns\""
-fi
+# Collect all arguments for the java command, stacking in reverse order:
+#   * args from the command line
+#   * the main class name
+#   * -classpath
+#   * -D...appname settings
+#   * --module-path (only if needed)
+#   * DEFAULT_JVM_OPTS, JAVA_OPTS, and GRADLE_OPTS environment variables.
+
+# For Cygwin or MSYS, switch paths to Windows format before running java
+if "$cygwin" || "$msys" ; then
+    APP_HOME=$( cygpath --path --mixed "$APP_HOME" )
+    CLASSPATH=$( cygpath --path --mixed "$CLASSPATH" )
+
+    JAVACMD=$( cygpath --unix "$JAVACMD" )
 
-# For Cygwin, switch paths to Windows format before running java
-if $cygwin ; then
-    APP_HOME=`cygpath --path --mixed "$APP_HOME"`
-    CLASSPATH=`cygpath --path --mixed "$CLASSPATH"`
-    JAVACMD=`cygpath --unix "$JAVACMD"`
-
-    # We build the pattern for arguments to be converted via cygpath
-    ROOTDIRSRAW=`find -L / -maxdepth 1 -mindepth 1 -type d 2>/dev/null`
-    SEP=""
-    for dir in $ROOTDIRSRAW ; do
-        ROOTDIRS="$ROOTDIRS$SEP$dir"
-        SEP="|"
-    done
-    OURCYGPATTERN="(^($ROOTDIRS))"
-    # Add a user-defined pattern to the cygpath arguments
-    if [ "$GRADLE_CYGPATTERN" != "" ] ; then
-        OURCYGPATTERN="$OURCYGPATTERN|($GRADLE_CYGPATTERN)"
-    fi
     # Now convert the arguments - kludge to limit ourselves to /bin/sh
-    i=0
-    for arg in "$@" ; do
-        CHECK=`echo "$arg"|egrep -c "$OURCYGPATTERN" -`
-        CHECK2=`echo "$arg"|egrep -c "^-"`                                 ### Determine if an option
-
-        if [ $CHECK -ne 0 ] && [ $CHECK2 -eq 0 ] ; then                    ### Added a condition
-            eval `echo args$i`=`cygpath --path --ignore --mixed "$arg"`
-        else
-            eval `echo args$i`="\"$arg\""
+    for arg do
+        if
+            case $arg in                                #(
+              -*)   false ;;                            # don't mess with options #(
+              /?*)  t=${arg#/} t=/${t%%/*}              # looks like a POSIX filepath
+                    [ -e "$t" ] ;;                      #(
+              *)    false ;;
+            esac
+        then
+            arg=$( cygpath --path --ignore --mixed "$arg" )
         fi
-        i=$((i+1))
+        # Roll the args list around exactly as many times as the number of
+        # args, so each arg winds up back in the position where it started, but
+        # possibly modified.
+        #
+        # NB: a `for` loop captures its iteration list before it begins, so
+        # changing the positional parameters here affects neither the number of
+        # iterations, nor the values presented in `arg`.
+        shift                   # remove old arg
+        set -- "$@" "$arg"      # push replacement arg
     done
-    case $i in
-        (0) set -- ;;
-        (1) set -- "$args0" ;;
-        (2) set -- "$args0" "$args1" ;;
-        (3) set -- "$args0" "$args1" "$args2" ;;
-        (4) set -- "$args0" "$args1" "$args2" "$args3" ;;
-        (5) set -- "$args0" "$args1" "$args2" "$args3" "$args4" ;;
-        (6) set -- "$args0" "$args1" "$args2" "$args3" "$args4" "$args5" ;;
-        (7) set -- "$args0" "$args1" "$args2" "$args3" "$args4" "$args5" "$args6" ;;
-        (8) set -- "$args0" "$args1" "$args2" "$args3" "$args4" "$args5" "$args6" "$args7" ;;
-        (9) set -- "$args0" "$args1" "$args2" "$args3" "$args4" "$args5" "$args6" "$args7" "$args8" ;;
-    esac
 fi
 
-# Escape application args
-save () {
-    for i do printf %s\\n "$i" | sed "s/'/'\\\\''/g;1s/^/'/;\$s/\$/' \\\\/" ; done
-    echo " "
-}
-APP_ARGS=$(save "$@")
-
-# Collect all arguments for the java command, following the shell quoting and substitution rules
-eval set -- $DEFAULT_JVM_OPTS $JAVA_OPTS $GRADLE_OPTS "\"-Dorg.gradle.appname=$APP_BASE_NAME\"" -classpath "\"$CLASSPATH\"" org.gradle.wrapper.GradleWrapperMain "$APP_ARGS"
 
-# by default we should be in the correct project dir, but when run from Finder on Mac, the cwd is wrong
-if [ "$(uname)" = "Darwin" ] && [ "$HOME" = "$PWD" ]; then
-  cd "$(dirname "$0")"
+# Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
+DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'
+
+# Collect all arguments for the java command;
+#   * $DEFAULT_JVM_OPTS, $JAVA_OPTS, and $GRADLE_OPTS can contain fragments of
+#     shell script including quotes and variable substitutions, so put them in
+#     double quotes to make sure that they get re-expanded; and
+#   * put everything else in single quotes, so that it's not re-expanded.
+
+set -- \
+        "-Dorg.gradle.appname=$APP_BASE_NAME" \
+        -classpath "$CLASSPATH" \
+        org.gradle.wrapper.GradleWrapperMain \
+        "$@"
+
+# Stop when "xargs" is not available.
+if ! command -v xargs >/dev/null 2>&1
+then
+    die "xargs is not available"
 fi
 
+# Use "xargs" to parse quoted args.
+#
+# With -n1 it outputs one arg per line, with the quotes and backslashes removed.
+#
+# In Bash we could simply go:
+#
+#   readarray ARGS < <( xargs -n1 <<<"$var" ) &&
+#   set -- "${ARGS[@]}" "$@"
+#
+# but POSIX shell has neither arrays nor command substitution, so instead we
+# post-process each arg (as a line of input to sed) to backslash-escape any
+# character that might be a shell metacharacter, then use eval to reverse
+# that process (while maintaining the separation between arguments), and wrap
+# the whole thing up as a single "set" statement.
+#
+# This will of course break if any of these variables contains a newline or
+# an unmatched quote.
+#
+
+eval "set -- $(
+        printf '%s\n' "$DEFAULT_JVM_OPTS $JAVA_OPTS $GRADLE_OPTS" |
+        xargs -n1 |
+        sed ' s~[^-[:alnum:]+,./:=@_]~\\&~g; ' |
+        tr '\n' ' '
+    )" '"$@"'
+
 exec "$JAVACMD" "$@"
diff --git a/gradlew.bat b/gradlew.bat
index f955316..93e3f59 100644
--- a/gradlew.bat
+++ b/gradlew.bat
@@ -1,4 +1,20 @@
-@if "%DEBUG%" == "" @echo off
+@rem
+@rem Copyright 2015 the original author or authors.
+@rem
+@rem Licensed under the Apache License, Version 2.0 (the "License");
+@rem you may not use this file except in compliance with the License.
+@rem You may obtain a copy of the License at
+@rem
+@rem      https://www.apache.org/licenses/LICENSE-2.0
+@rem
+@rem Unless required by applicable law or agreed to in writing, software
+@rem distributed under the License is distributed on an "AS IS" BASIS,
+@rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+@rem See the License for the specific language governing permissions and
+@rem limitations under the License.
+@rem
+
+@if "%DEBUG%"=="" @echo off
 @rem ##########################################################################
 @rem
 @rem  Gradle startup script for Windows
@@ -9,19 +25,23 @@
 if "%OS%"=="Windows_NT" setlocal
 
 set DIRNAME=%~dp0
-if "%DIRNAME%" == "" set DIRNAME=.
+if "%DIRNAME%"=="" set DIRNAME=.
+@rem This is normally unused
 set APP_BASE_NAME=%~n0
 set APP_HOME=%DIRNAME%
 
+@rem Resolve any "." and ".." in APP_HOME to make it shorter.
+for %%i in ("%APP_HOME%") do set APP_HOME=%%~fi
+
 @rem Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
-set DEFAULT_JVM_OPTS=
+set DEFAULT_JVM_OPTS="-Xmx64m" "-Xms64m"
 
 @rem Find java.exe
 if defined JAVA_HOME goto findJavaFromJavaHome
 
 set JAVA_EXE=java.exe
 %JAVA_EXE% -version >NUL 2>&1
-if "%ERRORLEVEL%" == "0" goto init
+if %ERRORLEVEL% equ 0 goto execute
 
 echo.
 echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
@@ -35,7 +55,7 @@ goto fail
 set JAVA_HOME=%JAVA_HOME:"=%
 set JAVA_EXE=%JAVA_HOME%/bin/java.exe
 
-if exist "%JAVA_EXE%" goto init
+if exist "%JAVA_EXE%" goto execute
 
 echo.
 echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
@@ -45,38 +65,26 @@ echo location of your Java installation.
 
 goto fail
 
-:init
-@rem Get command-line arguments, handling Windows variants
-
-if not "%OS%" == "Windows_NT" goto win9xME_args
-
-:win9xME_args
-@rem Slurp the command line arguments.
-set CMD_LINE_ARGS=
-set _SKIP=2
-
-:win9xME_args_slurp
-if "x%~1" == "x" goto execute
-
-set CMD_LINE_ARGS=%*
-
 :execute
 @rem Setup the command line
 
 set CLASSPATH=%APP_HOME%\gradle\wrapper\gradle-wrapper.jar
 
+
 @rem Execute Gradle
-"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %GRADLE_OPTS% "-Dorg.gradle.appname=%APP_BASE_NAME%" -classpath "%CLASSPATH%" org.gradle.wrapper.GradleWrapperMain %CMD_LINE_ARGS%
+"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %GRADLE_OPTS% "-Dorg.gradle.appname=%APP_BASE_NAME%" -classpath "%CLASSPATH%" org.gradle.wrapper.GradleWrapperMain %*
 
 :end
 @rem End local scope for the variables with windows NT shell
-if "%ERRORLEVEL%"=="0" goto mainEnd
+if %ERRORLEVEL% equ 0 goto mainEnd
 
 :fail
 rem Set variable GRADLE_EXIT_CONSOLE if you need the _script_ return code instead of
 rem the _cmd.exe /c_ return code!
-if  not "" == "%GRADLE_EXIT_CONSOLE%" exit 1
-exit /b 1
+set EXIT_CODE=%ERRORLEVEL%
+if %EXIT_CODE% equ 0 set EXIT_CODE=1
+if not ""=="%GRADLE_EXIT_CONSOLE%" exit %EXIT_CODE%
+exit /b %EXIT_CODE%
 
 :mainEnd
 if "%OS%"=="Windows_NT" endlocal
diff --git a/integration-testing/api/integration-testing.api b/integration-testing/api/integration-testing.api
new file mode 100644
index 0000000..e69de29
diff --git a/integration-testing/build.gradle.kts b/integration-testing/build.gradle.kts
new file mode 100644
index 0000000..0a4392f
--- /dev/null
+++ b/integration-testing/build.gradle.kts
@@ -0,0 +1,91 @@
+import org.jetbrains.kotlin.gradle.utils.NativeCompilerDownloader
+
+plugins {
+    kotlin("jvm")
+}
+
+repositories {
+    mavenLocal()
+    maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
+    mavenCentral()
+}
+
+java {
+    toolchain {
+        languageVersion.set(JavaLanguageVersion.of(11))
+    }
+}
+
+kotlin {
+    jvmToolchain(11)
+}
+
+val kotlin_version = providers.gradleProperty("kotlin_version").orNull
+val atomicfu_snapshot_version = providers.gradleProperty("version").orNull
+
+sourceSets {
+    create("mavenTest") {
+        compileClasspath += files(sourceSets.main.get().output, configurations.testRuntimeClasspath)
+        runtimeClasspath += output + compileClasspath
+    }
+
+    create("functionalTest") {
+        compileClasspath += files(sourceSets.main.get().output, configurations.testRuntimeClasspath)
+        runtimeClasspath += output + compileClasspath
+    }
+}
+
+dependencies {
+    // common dependencies
+    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
+    testImplementation("org.jetbrains.kotlin:kotlin-test")
+    implementation("org.jetbrains.kotlin:kotlin-script-runtime")
+    implementation(kotlin("script-runtime"))
+
+    // mavenTest dependencies
+    "mavenTestImplementation"("org.jetbrains.kotlinx:atomicfu-jvm:$atomicfu_snapshot_version")
+
+    // functionalTest dependencies
+    "functionalTestImplementation"(gradleTestKit())
+    "functionalTestApi"("org.ow2.asm:asm:9.3")
+    "functionalTestApi"("org.ow2.asm:asm-commons:9.3")
+}
+
+val mavenTest by tasks.registering(Test::class) {
+    testClassesDirs = sourceSets["mavenTest"].output.classesDirs
+    classpath = sourceSets["mavenTest"].runtimeClasspath
+    
+    dependsOn(":atomicfu:publishToMavenLocal")
+    
+    outputs.upToDateWhen { false }
+}
+
+val functionalTest by tasks.registering(Test::class) {
+    testClassesDirs = sourceSets["functionalTest"].output.classesDirs
+    classpath = sourceSets["functionalTest"].runtimeClasspath
+
+    systemProperties["kotlinVersion"] = kotlin_version
+    systemProperties["atomicfuVersion"] = atomicfu_snapshot_version
+
+    dependsOn(":atomicfu-gradle-plugin:publishToMavenLocal")
+    // atomicfu-transformer and atomicfu artifacts should also be published as it's required by atomicfu-gradle-plugin.
+    dependsOn(":atomicfu-transformer:publishToMavenLocal")
+    dependsOn(":atomicfu:publishToMavenLocal")
+    
+    outputs.upToDateWhen { false }
+}
+
+tasks.check { dependsOn(mavenTest, functionalTest) }
+
+// Setup K/N infrastructure to use klib utility in tests
+// TODO: klib checks are skipped for now because of this problem KT-61143
+val Project.konanHome: String
+get() = rootProject.properties["kotlin.native.home"]?.toString()
+        ?: NativeCompilerDownloader(project).compilerDirectory.absolutePath
+
+val embeddableJar = File(project.konanHome).resolve("konan/lib/kotlin-native-compiler-embeddable.jar")
+
+tasks.withType<Test> {
+    // Pass the path to native jars
+    systemProperty("kotlin.native.jar", embeddableJar)
+}
diff --git a/integration-testing/examples/jvm-sample/build.gradle.kts b/integration-testing/examples/jvm-sample/build.gradle.kts
new file mode 100644
index 0000000..29bdde6
--- /dev/null
+++ b/integration-testing/examples/jvm-sample/build.gradle.kts
@@ -0,0 +1,50 @@
+buildscript {
+    repositories {
+        mavenLocal()
+    }
+
+    dependencies {
+        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:${libs.versions.atomicfuVersion.get()}")
+    }
+}
+
+group = "kotlinx.atomicfu.examples"
+version = "DUMMY_VERSION"
+
+plugins {
+    kotlin("jvm") version libs.versions.kotlinVersion.get()
+    `maven-publish`
+}
+
+apply(plugin = "kotlinx-atomicfu")
+
+repositories {
+    mavenCentral()
+    maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
+    mavenLocal()
+}
+
+dependencies {
+    implementation(kotlin("stdlib"))
+    implementation(kotlin("test-junit"))
+}
+
+publishing {
+    repositories {
+        /**
+         * Maven repository in build directory to store artifacts for using in functional tests.
+         */
+        maven("build/.m2/") {
+            name = "local"
+        }
+    }
+
+    publications {
+        create<MavenPublication>("maven") {
+            groupId = "kotlinx.atomicfu.examples"
+            artifactId = "jvm-sample"
+
+            from(components["kotlin"])
+        }
+    }
+}
diff --git a/integration-testing/examples/jvm-sample/gradle.properties b/integration-testing/examples/jvm-sample/gradle.properties
new file mode 100644
index 0000000..b75bc9e
--- /dev/null
+++ b/integration-testing/examples/jvm-sample/gradle.properties
@@ -0,0 +1,5 @@
+##
+## Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+##
+kotlin_version=1.9.20
+atomicfu_version=0.23.1-SNAPSHOT
diff --git a/integration-testing/examples/jvm-sample/settings.gradle.kts b/integration-testing/examples/jvm-sample/settings.gradle.kts
new file mode 100644
index 0000000..126a058
--- /dev/null
+++ b/integration-testing/examples/jvm-sample/settings.gradle.kts
@@ -0,0 +1,19 @@
+pluginManagement {
+    repositories {
+        mavenLocal()
+        mavenCentral()
+        maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
+        gradlePluginPortal()
+    }
+}
+
+dependencyResolutionManagement {
+    versionCatalogs {
+        create("libs") {
+            version("atomicfuVersion", providers.gradleProperty("atomicfu_version").orNull)
+            version("kotlinVersion", providers.gradleProperty("kotlin_version").orNull)
+        }
+    }
+}
+
+rootProject.name = "jvm-sample"
diff --git a/integration-testing/examples/jvm-sample/src/main/kotlin/Sample.kt b/integration-testing/examples/jvm-sample/src/main/kotlin/Sample.kt
new file mode 100644
index 0000000..ad0d421
--- /dev/null
+++ b/integration-testing/examples/jvm-sample/src/main/kotlin/Sample.kt
@@ -0,0 +1,19 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+import kotlinx.atomicfu.*
+import kotlin.test.assertEquals
+import kotlin.test.assertTrue
+
+class IntArithmetic {
+    private val _x = atomic(0)
+    val x get() = _x.value
+
+    fun doWork(finalValue: Int) {
+        assertEquals(0, x)
+        assertEquals(0, _x.getAndSet(3))
+        assertEquals(3, x)
+        assertTrue(_x.compareAndSet(3, finalValue))
+    }
+}
diff --git a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/src/test/kotlin/ArithmeticTest.kt b/integration-testing/examples/jvm-sample/src/test/kotlin/SampleTest.kt
similarity index 56%
rename from atomicfu-gradle-plugin/src/test/resources/projects/js-simple/src/test/kotlin/ArithmeticTest.kt
rename to integration-testing/examples/jvm-sample/src/test/kotlin/SampleTest.kt
index ab10e9b..8aa5d9a 100644
--- a/atomicfu-gradle-plugin/src/test/resources/projects/js-simple/src/test/kotlin/ArithmeticTest.kt
+++ b/integration-testing/examples/jvm-sample/src/test/kotlin/SampleTest.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright 2017-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
 import kotlin.test.*
@@ -8,7 +8,7 @@ class ArithmeticTest {
     @Test
     fun testInt() {
         val a = IntArithmetic()
-        doWork(a)
-        check(a.x == 8)
+        a.doWork(1234)
+        assertEquals(1234, a.x)
     }
-}
\ No newline at end of file
+}
diff --git a/integration-testing/examples/mpp-sample/build.gradle.kts b/integration-testing/examples/mpp-sample/build.gradle.kts
new file mode 100644
index 0000000..f7bb99b
--- /dev/null
+++ b/integration-testing/examples/mpp-sample/build.gradle.kts
@@ -0,0 +1,75 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+buildscript {
+    repositories {
+        mavenLocal()
+        mavenCentral()
+    }
+
+    dependencies {
+        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:${libs.versions.atomicfuVersion.get()}")
+    }
+}
+
+group = "kotlinx.atomicfu.examples"
+version = "DUMMY_VERSION"
+
+plugins {
+    kotlin("multiplatform") version libs.versions.kotlinVersion.get()
+    `maven-publish`
+}
+
+apply(plugin = "kotlinx-atomicfu")
+
+repositories {
+    mavenCentral()
+    maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
+    mavenLocal()
+}
+
+kotlin {
+    jvm()
+    
+    js()
+    
+    wasmJs {}
+    wasmWasi {}
+    
+    macosArm64()
+    macosX64()
+    linuxArm64()
+    linuxX64()
+    mingwX64()
+
+    sourceSets {
+        commonMain {
+            dependencies {
+                implementation(kotlin("stdlib"))
+                implementation(kotlin("test-junit"))
+            }
+        }
+        commonTest {}
+    }
+}
+
+publishing {
+    repositories {
+        /**
+         * Maven repository in build directory to store artifacts for using in functional tests.
+         */
+        maven("build/.m2/") {
+            name = "local"
+        }
+    }
+
+    publications {
+        create<MavenPublication>("maven") {
+            groupId = "kotlinx.atomicfu.examples"
+            artifactId = "mpp-sample"
+
+            from(components["kotlin"])
+        }
+    }
+}
diff --git a/integration-testing/examples/mpp-sample/gradle.properties b/integration-testing/examples/mpp-sample/gradle.properties
new file mode 100644
index 0000000..b75bc9e
--- /dev/null
+++ b/integration-testing/examples/mpp-sample/gradle.properties
@@ -0,0 +1,5 @@
+##
+## Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+##
+kotlin_version=1.9.20
+atomicfu_version=0.23.1-SNAPSHOT
diff --git a/integration-testing/examples/mpp-sample/settings.gradle.kts b/integration-testing/examples/mpp-sample/settings.gradle.kts
new file mode 100644
index 0000000..ff220e9
--- /dev/null
+++ b/integration-testing/examples/mpp-sample/settings.gradle.kts
@@ -0,0 +1,19 @@
+pluginManagement {
+    repositories {
+        mavenLocal()
+        mavenCentral()
+        maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
+        gradlePluginPortal()
+    }
+}
+
+dependencyResolutionManagement {
+    versionCatalogs {
+        create("libs") {
+            version("atomicfuVersion", providers.gradleProperty("atomicfu_version").orNull)
+            version("kotlinVersion", providers.gradleProperty("kotlin_version").orNull)
+        }
+    }
+}
+
+rootProject.name = "mpp-sample"
diff --git a/integration-testing/examples/mpp-sample/src/commonMain/kotlin/IntArithmetic.kt b/integration-testing/examples/mpp-sample/src/commonMain/kotlin/IntArithmetic.kt
new file mode 100644
index 0000000..e7401e9
--- /dev/null
+++ b/integration-testing/examples/mpp-sample/src/commonMain/kotlin/IntArithmetic.kt
@@ -0,0 +1,18 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+import kotlinx.atomicfu.*
+import kotlin.test.*
+
+class IntArithmetic {
+    private val _x = atomic(0)
+    val x get() = _x.value
+
+    fun doWork(finalValue: Int) {
+        assertEquals(0, x)
+        assertEquals(0, _x.getAndSet(3))
+        assertEquals(3, x)
+        assertTrue(_x.compareAndSet(3, finalValue))
+    }
+}
diff --git a/integration-testing/examples/mpp-sample/src/commonTest/kotlin/IntArithmeticTest.kt b/integration-testing/examples/mpp-sample/src/commonTest/kotlin/IntArithmeticTest.kt
new file mode 100644
index 0000000..a40d0d4
--- /dev/null
+++ b/integration-testing/examples/mpp-sample/src/commonTest/kotlin/IntArithmeticTest.kt
@@ -0,0 +1,15 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+import kotlin.test.*
+
+class IntArithmeticTest {
+
+    @Test
+    fun testInt() {
+        val a = IntArithmetic()
+        a.doWork(1234)
+        assertEquals(1234, a.x)
+    }
+}
diff --git a/integration-testing/settings.gradle b/integration-testing/settings.gradle
new file mode 100644
index 0000000..f2cf545
--- /dev/null
+++ b/integration-testing/settings.gradle
@@ -0,0 +1,13 @@
+pluginManagement {
+    repositories {
+        mavenCentral()
+        maven { url "https://plugins.gradle.org/m2/" }
+        maven { url "https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev" }
+        mavenLocal()
+    }
+}
+
+include 'mavenTest'
+include 'functionalTest'
+
+rootProject.name = "integration-testing"
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/JvmProjectTest.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/JvmProjectTest.kt
new file mode 100644
index 0000000..54198c7
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/JvmProjectTest.kt
@@ -0,0 +1,30 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.cases
+
+import kotlinx.atomicfu.gradle.plugin.test.framework.checker.*
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.*
+import kotlin.test.Test
+
+class JvmProjectTest {
+
+    private val jvmSample: GradleBuild = createGradleBuildFromSources("jvm-sample")
+
+    @Test
+    fun testJvmWithEnabledIrTransformation() {
+        jvmSample.enableJvmIrTransformation = true
+        jvmSample.checkJvmCompileOnlyDependencies()
+        jvmSample.checkConsumableDependencies()
+        jvmSample.buildAndCheckBytecode()
+    }
+
+    @Test
+    fun testJvmWithDisabledIrTransformation() {
+        jvmSample.enableJvmIrTransformation = false
+        jvmSample.checkJvmCompileOnlyDependencies()
+        jvmSample.checkConsumableDependencies()
+        jvmSample.buildAndCheckBytecode()
+    }
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/MppProjectTest.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/MppProjectTest.kt
new file mode 100644
index 0000000..9810eed
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/MppProjectTest.kt
@@ -0,0 +1,69 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package test
+
+import kotlinx.atomicfu.gradle.plugin.test.framework.checker.*
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.*
+import kotlin.test.*
+
+class MppProjectTest {
+    private val mppSample: GradleBuild = createGradleBuildFromSources("mpp-sample")
+
+    @Test
+    fun testMppWithEnabledJvmIrTransformation() {
+        mppSample.enableJvmIrTransformation = true
+        mppSample.checkMppJvmCompileOnlyDependencies()
+        mppSample.checkConsumableDependencies()
+        mppSample.buildAndCheckBytecode()
+    }
+
+    @Test
+    fun testMppWithDisabledJvmIrTransformation() {
+        mppSample.enableJvmIrTransformation = false
+        mppSample.checkMppJvmCompileOnlyDependencies()
+        mppSample.checkConsumableDependencies()
+        mppSample.buildAndCheckBytecode()
+    }
+
+    // TODO: JS klib will be checked for kotlinx.atomicfu references when this issue KT-61143 is fixed.
+    @Test
+    fun testMppWithEnabledJsIrTransformation() {
+        mppSample.enableJsIrTransformation = true
+        assertTrue(mppSample.cleanAndBuild().isSuccessful)
+        mppSample.checkConsumableDependencies()
+    }
+
+    @Test
+    fun testMppWithDisabledJsIrTransformation() {
+        mppSample.enableJsIrTransformation = false
+        assertTrue(mppSample.cleanAndBuild().isSuccessful)
+        mppSample.checkConsumableDependencies()
+    }
+    
+    @Test
+    fun testMppWasmBuild() {
+        assertTrue(mppSample.cleanAndBuild().isSuccessful)
+        mppSample.checkMppWasmJsImplementationDependencies()
+        mppSample.checkMppWasmWasiImplementationDependencies()
+    }
+
+    @Test
+    fun testMppNativeWithEnabledIrTransformation() {
+        mppSample.enableNativeIrTransformation = true
+        assertTrue(mppSample.cleanAndBuild().isSuccessful)
+        mppSample.checkMppNativeCompileOnlyDependencies()
+        // TODO: klib checks are skipped for now because of this problem KT-61143
+        //mppSample.buildAndCheckNativeKlib()
+    }
+
+    @Test
+    fun testMppNativeWithDisabledIrTransformation() {
+        mppSample.enableNativeIrTransformation = false
+        assertTrue(mppSample.cleanAndBuild().isSuccessful)
+        mppSample.checkMppNativeImplementationDependencies()
+        // TODO: klib checks are skipped for now because of this problem KT-61143
+        //mppSample.buildAndCheckNativeKlib()
+    }
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/smoke/ArtifactCheckerSmokeTest.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/smoke/ArtifactCheckerSmokeTest.kt
new file mode 100644
index 0000000..a9c5b1c
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/smoke/ArtifactCheckerSmokeTest.kt
@@ -0,0 +1,82 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.cases.smoke
+
+import kotlinx.atomicfu.gradle.plugin.test.framework.checker.ArtifactChecker
+import java.io.File
+import java.nio.file.Files
+import kotlin.test.*
+import kotlin.text.*
+
+class ArtifactCheckerSmokeTest {
+    val tempDir = Files.createTempDirectory("sample").toFile()
+    
+    private class MyArtifactChecker(tempDir: File) : ArtifactChecker(tempDir) {
+        private val atomicfuString = "public final void doWork(int);\n" +
+                "    descriptor: (I)V\n" +
+                "    flags: (0x0011) ACC_PUBLIC, ACC_FINAL\n" +
+                "    Code:\n" +
+                "      stack=3, locals=2, args_size=2\n" +
+                "         0: aload_0\n" +
+                "         1: getfield      #18                 // Field _x:Lkotlinx/atomicfu/AtomicInt;\n" +
+                "         4: iconst_0\n" +
+                "         5: sipush        556\n" +
+                "         8: invokevirtual #28                 // Method kotlinx/atomicfu/AtomicInt.compareAndSet:(II)Z\n" +
+                "        11: pop\n" +
+                "        12: return\n" +
+                "      LineNumberTable:\n" +
+                "        line 14: 0\n" +
+                "        line 19: 12\n" +
+                "      LocalVariableTable:\n" +
+                "        Start  Length  Slot  Name   Signature\n" +
+                "            0      13     0  this   LIntArithmetic;\n" +
+                "            0      13     1 finalValue   I"
+        
+        
+        val noAtomicfuString = "  public final void doWork(int);\n" +
+                "    descriptor: (I)V\n" +
+                "    flags: (0x0011) ACC_PUBLIC, ACC_FINAL\n" +
+                "    Code:\n" +
+                "      stack=4, locals=2, args_size=2\n" +
+                "         0: aload_0\n" +
+                "         1: getstatic     #22                 // Field _x\$FU:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;\n" +
+                "         4: swap\n" +
+                "         5: iconst_0\n" +
+                "         6: sipush        556\n" +
+                "         9: invokevirtual #28                 // Method java/util/concurrent/atomic/AtomicIntegerFieldUpdater.compareAndSet:(Ljava/lang/Object;II)Z\n" +
+                "        12: pop\n" +
+                "        13: return\n" +
+                "      LineNumberTable:\n" +
+                "        line 14: 0\n" +
+                "        line 19: 13\n" +
+                "      LocalVariableTable:\n" +
+                "        Start  Length  Slot  Name   Signature\n" +
+                "            0      14     0  this   LIntArithmetic;\n" +
+                "            0      14     1 finalValue   I"
+        
+        val metadataString = "RuntimeVisibleAnnotations:\n" +
+                "  0: #32(#33=[I#34,I#35,I#36],#37=I#34,#38=I#39,#40=[s#41],#42=[s#20,s#43,s#6,s#15,s#16,s#21,s#43,s#29,s#43,s#44])\n" +
+                "    kotlin.Metadata(\n" +
+                "      mv=[1,9,0]\n" +
+                "      k=1\n" +
+                "      xi=48\n" +
+                "      d1=[\"\\u0000\\u001e\\n\\u0002\\u0018\\u0002\\n\\u0002\\u0010\\u0000\\n\\u0002\\b\\u0002\\n\\u0002\\u0018\\u0002\\n\\u0000\\n\\u0002\\u0010\\u0002\\n\\u0000\\n\\u0002\\u0010\\b\\n\\u0000\\u0018\\u00002\\u00020\\u0001B\\u0005¢\\u0006\\u0002\\u0010\\u0002J\\u000e\\u0010\\u0005\\u001a\\u00020\\u00062\\u0006\\u0010\\u0007\\u001a\\u00020\\bR\\u000e\\u0010\\u0003\\u001a\\u00020\\u0004X\\u0082\\u0004¢\\u0006\\u0002\\n\\u0000¨\\u0006\\t\"]\n" +
+                "      d2=[\"LIntArithmetic;\",\"\",\"()V\",\"_x\",\"Lkotlinx/atomicfu/AtomicInt;\",\"doWork\",\"\",\"finalValue\",\"\",\"jvm-sample\"]\n" +
+                "    )"
+        
+        override fun checkReferences() {
+            assertTrue(atomicfuString.toByteArray().findAtomicfuRef())
+            assertFalse(noAtomicfuString.toByteArray().findAtomicfuRef())
+            assertTrue(metadataString.toByteArray().findAtomicfuRef())
+        }
+    }
+    
+    private val checker = MyArtifactChecker(tempDir)
+    
+    @Test
+    fun testAtomicfuReferenciesLookup() {
+        checker.checkReferences()
+    }
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/smoke/DependencyCheckerTest.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/smoke/DependencyCheckerTest.kt
new file mode 100644
index 0000000..929fb08
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/cases/smoke/DependencyCheckerTest.kt
@@ -0,0 +1,89 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.cases.smoke
+
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.BuildResult
+import java.io.File
+import kotlin.test.*
+
+class DependencyParserSmokeTest {
+    private val tempFile = File.createTempFile("sample", null)
+    
+    private val dependencies = "> Task :dependencies\n" +
+            "\n" +
+            "------------------------------------------------------------\n" +
+            "Root project 'jvm-sample'\n" +
+            "------------------------------------------------------------\n" +
+            "compileClasspath - Compile classpath for null/main.\n" +
+            "+--- org.jetbrains.kotlinx:atomicfu-jvm:0.23.1-SNAPSHOT\n" +
+            "+--- org.jetbrains.kotlin:kotlin-stdlib:1.9.0\n" +
+            "|    +--- org.jetbrains.kotlin:kotlin-stdlib-common:1.9.0\n" +
+            "|    \\--- org.jetbrains:annotations:13.0\n" +
+            "\\--- org.jetbrains.kotlin:kotlin-test-junit:1.9.0\n" +
+            "     +--- org.jetbrains.kotlin:kotlin-test:1.9.0\n" +
+            "     |    \\--- org.jetbrains.kotlin:kotlin-stdlib:1.9.0 (*)\n" +
+            "     \\--- junit:junit:4.13.2\n" +
+            "          \\--- org.hamcrest:hamcrest-core:1.3\n" +
+            "\n" +
+            "compileOnly - Compile only dependencies for null/main. (n)\n" +
+            "\\--- org.jetbrains.kotlinx:atomicfu-jvm:0.23.1-SNAPSHOT (n)\n" +
+            "\n" +
+            "compileOnlyDependenciesMetadata\n" +
+            "\\--- org.jetbrains.kotlinx:atomicfu-jvm:0.23.1-SNAPSHOT\n" +
+            "\n" +
+            "default - Configuration for default artifacts. (n)\n" +
+            "No dependencies\n" +
+            "\n" +
+            "implementation - Implementation only dependencies for null/main. (n)\n" +
+            "+--- org.jetbrains.kotlin:kotlin-stdlib (n)\n" +
+            "\\--- org.jetbrains.kotlin:kotlin-test-junit (n)\n" +
+            "\n" +
+            "implementationDependenciesMetadata\n" +
+            "+--- org.jetbrains.kotlin:kotlin-stdlib:1.9.0\n" +
+            "|    +--- org.jetbrains.kotlin:kotlin-stdlib-common:1.9.0\n" +
+            "|    \\--- org.jetbrains:annotations:13.0\n" +
+            "\\--- org.jetbrains.kotlin:kotlin-test-junit:1.9.0\n" +
+            "     +--- org.jetbrains.kotlin:kotlin-test:1.9.0\n" +
+            "     |    +--- org.jetbrains.kotlin:kotlin-test-common:1.9.0\n" +
+            "     |    |    \\--- org.jetbrains.kotlin:kotlin-stdlib-common:1.9.0\n" +
+            "     |    \\--- org.jetbrains.kotlin:kotlin-test-annotations-common:1.9.0\n" +
+            "     |         \\--- org.jetbrains.kotlin:kotlin-stdlib-common:1.9.0\n" +
+            "     \\--- junit:junit:4.13.2\n" +
+            "          \\--- org.hamcrest:hamcrest-core:1.3\n" +
+            "\n"
+    
+    @Test
+    fun testGetDependenciesForConfig() {
+        tempFile.bufferedWriter().use { out ->
+            out.write(dependencies)
+        }
+        val buildResult = BuildResult(0, tempFile)
+        assertEquals(
+            listOf(
+                "org.jetbrains.kotlin:kotlin-stdlib", 
+                "org.jetbrains.kotlin:kotlin-test-junit"
+            ),
+            buildResult.getDependenciesForConfig("implementation")
+        )
+        assertEquals(
+            emptyList(),
+            buildResult.getDependenciesForConfig("default")
+        )
+        assertEquals(
+            listOf(
+                "org.jetbrains.kotlinx:atomicfu-jvm:0.23.1-SNAPSHOT",
+                "org.jetbrains.kotlin:kotlin-stdlib:1.9.0",
+                "org.jetbrains.kotlin:kotlin-stdlib-common:1.9.0",
+                "org.jetbrains:annotations:13.0",
+                "org.jetbrains.kotlin:kotlin-test-junit:1.9.0",
+                "org.jetbrains.kotlin:kotlin-test:1.9.0",
+                "org.jetbrains.kotlin:kotlin-stdlib:1.9.0",
+                "junit:junit:4.13.2",
+                "org.hamcrest:hamcrest-core:1.3"
+            ),
+            buildResult.getDependenciesForConfig("compileClasspath")
+        )
+    }
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/checker/ArtifactChecker.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/checker/ArtifactChecker.kt
new file mode 100644
index 0000000..4f504fc
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/checker/ArtifactChecker.kt
@@ -0,0 +1,123 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.framework.checker
+
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.GradleBuild
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.cleanAndBuild
+import org.objectweb.asm.*
+import java.io.File
+import java.net.URLClassLoader
+import kotlin.test.assertFalse
+
+internal abstract class ArtifactChecker(private val targetDir: File) {
+
+    private val ATOMIC_FU_REF = "Lkotlinx/atomicfu/".toByteArray()
+    protected val KOTLIN_METADATA_DESC = "Lkotlin/Metadata;"
+
+    protected val projectName = targetDir.name.substringBeforeLast("-")
+
+    val buildDir
+        get() = targetDir.resolve("build").also {
+            require(it.exists() && it.isDirectory) { "Could not find `build/` directory in the target directory of the project $projectName: ${targetDir.path}" }
+        }
+
+    abstract fun checkReferences()
+
+    protected fun ByteArray.findAtomicfuRef(): Boolean {
+        loop@for (i in 0 .. this.size - ATOMIC_FU_REF.size) {
+            for (j in ATOMIC_FU_REF.indices) {
+                if (this[i + j] != ATOMIC_FU_REF[j]) continue@loop
+            }
+            return true
+        }
+        return false
+    }
+}
+
+private class BytecodeChecker(targetDir: File) : ArtifactChecker(targetDir) {
+
+    override fun checkReferences() {
+        val atomicfuDir = buildDir.resolve("classes/atomicfu/")
+        (if (atomicfuDir.exists() && atomicfuDir.isDirectory) atomicfuDir else buildDir).let {
+            it.walkBottomUp().filter { it.isFile && it.name.endsWith(".class") }.forEach { clazz ->
+                assertFalse(clazz.readBytes().eraseMetadata().findAtomicfuRef(), "Found kotlinx/atomicfu in class file ${clazz.path}")
+            }
+        }
+    }
+
+    // The atomicfu compiler plugin does not remove atomic properties from metadata,
+    // so for now we check that there are no ATOMIC_FU_REF left in the class bytecode excluding metadata.
+    // This may be reverted after the fix in the compiler plugin transformer (See #254).
+    private fun ByteArray.eraseMetadata(): ByteArray {
+        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
+        ClassReader(this).accept(object : ClassVisitor(Opcodes.ASM9, cw) {
+            override fun visitAnnotation(descriptor: String?, visible: Boolean): AnnotationVisitor? {
+                return if (descriptor == KOTLIN_METADATA_DESC) null else super.visitAnnotation(descriptor, visible)
+            }
+        }, ClassReader.SKIP_FRAMES)
+        return cw.toByteArray()
+    }
+}
+
+private class KlibChecker(targetDir: File) : ArtifactChecker(targetDir) {
+
+    val nativeJar = System.getProperty("kotlin.native.jar")
+
+    val classLoader: ClassLoader = URLClassLoader(arrayOf(File(nativeJar).toURI().toURL()), this.javaClass.classLoader)
+
+    private fun invokeKlibTool(
+        kotlinNativeClassLoader: ClassLoader?,
+        klibFile: File,
+        functionName: String,
+        hasOutput: Boolean,
+        vararg args: Any
+    ): String {
+        val libraryClass = Class.forName("org.jetbrains.kotlin.cli.klib.Library", true, kotlinNativeClassLoader)
+        val entryPoint = libraryClass.declaredMethods.single { it.name == functionName }
+        val lib = libraryClass.getDeclaredConstructor(String::class.java, String::class.java, String::class.java)
+            .newInstance(klibFile.canonicalPath, null, "host")
+
+        val output = StringBuilder()
+
+        // This is a hack. It would be better to get entryPoint properly
+        if (args.isNotEmpty()) {
+            entryPoint.invoke(lib, output, *args)
+        } else if (hasOutput) {
+            entryPoint.invoke(lib, output)
+        } else {
+            entryPoint.invoke(lib)
+        }
+        return output.toString()
+    }
+
+    override fun checkReferences() {
+        val classesDir = buildDir.resolve("classes/kotlin/")
+        if (classesDir.exists() && classesDir.isDirectory) {
+            classesDir.walkBottomUp().singleOrNull { it.isFile && it.name == "$projectName.klib" }?.let { klib ->
+                val klibIr = invokeKlibTool(
+                    kotlinNativeClassLoader = classLoader,
+                    klibFile = klib,
+                    functionName = "ir",
+                    hasOutput = true,
+                    false
+                )
+                assertFalse(klibIr.toByteArray().findAtomicfuRef(), "Found kotlinx/atomicfu in klib ${klib.path}:\n $klibIr")
+            } ?: error(" Native klib $projectName.klib is not found in $classesDir")
+        }
+    }
+}
+
+internal fun GradleBuild.buildAndCheckBytecode() {
+    val buildResult = cleanAndBuild()
+    require(buildResult.isSuccessful) { "Build of the project $projectName failed:\n ${buildResult.output}" }
+    BytecodeChecker(this.targetDir).checkReferences()
+}
+
+// TODO: klib checks are skipped for now because of this problem KT-61143
+internal fun GradleBuild.buildAndCheckNativeKlib() {
+    val buildResult = cleanAndBuild()
+    require(buildResult.isSuccessful) { "Build of the project $projectName failed:\n ${buildResult.output}" }
+    KlibChecker(this.targetDir).checkReferences()
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/checker/DependenciesChecker.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/checker/DependenciesChecker.kt
new file mode 100644
index 0000000..55eb9e3
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/checker/DependenciesChecker.kt
@@ -0,0 +1,94 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.framework.checker
+
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.*
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.GradleBuild
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.atomicfuVersion
+import kotlinx.atomicfu.gradle.plugin.test.framework.runner.dependencies
+
+private val commonAtomicfuDependency = "org.jetbrains.kotlinx:atomicfu:$atomicfuVersion"
+private val jvmAtomicfuDependency = "org.jetbrains.kotlinx:atomicfu-jvm:$atomicfuVersion"
+
+private fun GradleBuild.checkAtomicfuDependencyIsPresent(configurations: List<String>, atomicfuDependency: String) {
+    val dependencies = dependencies()
+    for (config in configurations) {
+        val configDependencies = dependencies.getDependenciesForConfig(config)
+        check(configDependencies.contains(atomicfuDependency)) { "Expected $atomicfuDependency in configuration $config, but it was not found." }
+    }
+}
+
+private fun GradleBuild.checkAtomicfuDependencyIsAbsent(configurations: List<String>, atomicfuDependency: String) {
+    val dependencies = dependencies()
+    for (config in configurations) {
+        val configDependencies = dependencies.getDependenciesForConfig(config)
+        check(!configDependencies.contains(atomicfuDependency)) { "Dependency $atomicfuDependency should be compileOnly, but it was found in the configuration: $config" }
+    }
+}
+
+/**
+ * For JVM there are 4 final configurations:
+ * compileClasspath — compile dependencies
+ * runtimeClasspath — runtime dependencies
+ * apiElements — compile dependencies that will be included in publication
+ * runtimeElements — runtime dependencies that will be included in publication
+ *
+ * The functions below check that `org.jetbrains.kotlinx:atomicfu` dependency is only included in compile configurations.
+ */
+
+// Checks a simple JVM project with a single target
+internal fun GradleBuild.checkJvmCompileOnlyDependencies() {
+    checkAtomicfuDependencyIsPresent(listOf("compileClasspath"), jvmAtomicfuDependency)
+    checkAtomicfuDependencyIsAbsent(listOf("runtimeClasspath", "apiElements", "runtimeElements"), jvmAtomicfuDependency)
+}
+
+// Checks JVM target of an MPP project
+internal fun GradleBuild.checkMppJvmCompileOnlyDependencies() {
+    checkAtomicfuDependencyIsPresent(listOf("jvmCompileClasspath"), commonAtomicfuDependency)
+    checkAtomicfuDependencyIsAbsent(listOf("jvmRuntimeClasspath", "jvmApiElements", "jvmRuntimeElements"), commonAtomicfuDependency)
+}
+
+// Checks wasmJs target of an MPP project
+internal fun GradleBuild.checkMppWasmJsImplementationDependencies() {
+    checkAtomicfuDependencyIsPresent(listOf("wasmJsCompileClasspath", "wasmJsRuntimeClasspath"), commonAtomicfuDependency)
+}
+
+internal fun GradleBuild.checkMppWasmWasiImplementationDependencies() {
+    checkAtomicfuDependencyIsPresent(listOf("wasmWasiCompileClasspath", "wasmWasiRuntimeClasspath"), commonAtomicfuDependency)
+}
+
+// Checks Native target of an MPP project
+internal fun GradleBuild.checkMppNativeCompileOnlyDependencies() {
+    // Here the name of the native target is hardcoded because the tested mpp-sample project declares this target and
+    // KGP generates the same set of dependencies for every declared native target ([mingwX64|linuxX64|macosX64...]CompileKlibraries)
+    checkAtomicfuDependencyIsPresent(listOf("macosX64CompileKlibraries"), commonAtomicfuDependency)
+    checkAtomicfuDependencyIsAbsent(listOf("macosX64MainImplementation"), commonAtomicfuDependency)
+}
+
+// Checks Native target of an MPP project
+internal fun GradleBuild.checkMppNativeImplementationDependencies() {
+    checkAtomicfuDependencyIsPresent(listOf("macosX64CompileKlibraries", "macosX64MainImplementation"), commonAtomicfuDependency)
+}
+
+// Some dependencies may be not resolvable but consumable and will not be present in the output of :dependencies task,
+// in this case we should check .pom or .module file of the published project.
+// This method checks if the .module file in the sample project publication contains org.jetbrains.kotlinx:atomicfu dependency included.
+// It searches for:
+// "group": "org.jetbrains.kotlinx",
+// "module": "atomicfu-*", atomicfu or atomicfu-jvm
+internal fun GradleBuild.checkConsumableDependencies() {
+    publishToLocalRepository()
+    val moduleFile = getSampleProjectJarModuleFile(targetDir, projectName)
+    val lines = moduleFile.readText().lines()
+    var index = 0
+    while (index < lines.size) {
+        val line = lines[index]
+        if (line.contains("\"group\": \"org.jetbrains.kotlinx\"") &&
+            lines[index + 1].contains("\"module\": \"atomicfu")) {
+            error("org.jetbrains.kotlinx.atomicfu dependency found in the .module file ${moduleFile.path}")
+        }
+        index++
+    }
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/BuildRunner.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/BuildRunner.kt
new file mode 100644
index 0000000..4fada6e
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/BuildRunner.kt
@@ -0,0 +1,63 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.framework.runner
+
+import java.io.File
+import java.nio.file.Files
+
+internal class GradleBuild(val projectName: String, val targetDir: File) {
+    var enableJvmIrTransformation = false
+    var enableJsIrTransformation = false
+    var enableNativeIrTransformation = false
+
+    private val properties
+        get() = buildList {
+            add("-P$KOTLIN_VERSION=$kotlinVersion")
+            add("-P${ATOMICFU_VERSION}=$atomicfuVersion")
+            add("-P$ENABLE_JVM_IR_TRANSFORMATION=$enableJvmIrTransformation")
+            add("-P$ENABLE_JS_IR_TRANSFORMATION=$enableJsIrTransformation")
+            add("-P$ENABLE_NATIVE_IR_TRANSFORMATION=$enableNativeIrTransformation")
+        }
+
+    private var runCount = 0
+
+    fun runGradle(commands: List<String>): BuildResult =
+        buildGradleByShell(runCount++, commands, properties).also {
+            require(it.isSuccessful) { "Running $commands on project $projectName FAILED with error:\n" + it.output }
+        }
+}
+
+internal class BuildResult(exitCode: Int, private val logFile: File) {
+    val isSuccessful: Boolean = exitCode == 0
+
+    val output: String by lazy { logFile.readText() }
+
+    // Gets the list of dependencies for the given configuration
+    fun getDependenciesForConfig(configuration: String): List<String> {
+        val lines = output.lines()
+        val result = mutableListOf<String>()
+        var index = 0
+        while (index < lines.size) {
+            val line = lines[index++]
+            if (line.substringBefore(" ") == configuration) break
+        }
+        while(index < lines.size) {
+            val line = lines[index++]
+            if (line.isBlank() || line == "No dependencies") break
+            // trim leading indentations (\---) and symbols in the end (*):
+            // \--- org.jetbrains.kotlinx:atomicfu:0.22.0-SNAPSHOT (n)
+            result.add(line.dropWhile { !it.isLetterOrDigit() }.substringBefore(" "))
+        }
+        return result
+    }
+}
+
+internal fun createGradleBuildFromSources(projectName: String): GradleBuild {
+    val projectDir = projectExamplesDir.resolve(projectName)
+    val targetDir = Files.createTempDirectory("${projectName.substringAfterLast('/')}-").toFile().apply {
+        projectDir.copyRecursively(this)
+    }
+    return GradleBuild(projectName, targetDir)
+}
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Commands.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Commands.kt
new file mode 100644
index 0000000..f9f2845
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Commands.kt
@@ -0,0 +1,12 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.framework.runner
+
+internal fun GradleBuild.cleanAndBuild(): BuildResult = runGradle(listOf("clean", "build"))
+
+internal fun GradleBuild.dependencies(): BuildResult = runGradle(listOf("dependencies"))
+
+internal fun GradleBuild.publishToLocalRepository(): BuildResult =
+    runGradle(listOf("clean", "publishMavenPublicationToLocalRepository"))
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Environment.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Environment.kt
new file mode 100644
index 0000000..87bef24
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Environment.kt
@@ -0,0 +1,31 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.framework.runner
+
+import java.io.File
+
+internal const val ATOMICFU_VERSION = "atomicfu_version"
+internal const val KOTLIN_VERSION = "kotlin_version"
+internal const val ENABLE_JVM_IR_TRANSFORMATION = "kotlinx.atomicfu.enableJvmIrTransformation"
+internal const val ENABLE_JS_IR_TRANSFORMATION = "kotlinx.atomicfu.enableJsIrTransformation"
+internal const val ENABLE_NATIVE_IR_TRANSFORMATION = "kotlinx.atomicfu.enableNativeIrTransformation"
+internal const val DUMMY_VERSION = "DUMMY_VERSION"
+
+internal val atomicfuVersion = System.getProperty("atomicfuVersion")
+internal val kotlinVersion = System.getProperty("kotlinVersion")
+
+internal val gradleWrapperDir = File("..")
+
+internal val projectExamplesDir = File("examples")
+
+internal fun getLocalRepoDir(targetDir: File): File =
+    targetDir.resolve("build/.m2/").also {
+        require(it.exists() && it.isDirectory) { "Could not find local repository `build/.m2/` in the project directory: ${targetDir.path}" }
+    }
+
+// The project is published in the local repo directory /build/.m2/ with DUMMY_VERSION
+internal fun getSampleProjectJarModuleFile(targetDir: File, projectName: String): File =
+    getLocalRepoDir(targetDir).resolve("kotlinx/atomicfu/examples/$projectName/$DUMMY_VERSION").walkBottomUp()
+        .singleOrNull { it.name.endsWith(".module") }  ?: error("Could not find jar module file in local repository of the project $projectName: ${getLocalRepoDir(targetDir)}")
diff --git a/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Utils.kt b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Utils.kt
new file mode 100644
index 0000000..cd5f1ac
--- /dev/null
+++ b/integration-testing/src/functionalTest/kotlin/kotlinx.atomicfu.gradle.plugin.test/framework/runner/Utils.kt
@@ -0,0 +1,34 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.atomicfu.gradle.plugin.test.framework.runner
+
+import java.io.File
+
+internal fun GradleBuild.buildGradleByShell(
+    runIndex: Int,
+    commands: List<String>,
+    properties: List<String>
+): BuildResult {
+    val logFile = targetDir.resolve("build-$runIndex.log")
+
+    val gradleCommands = buildSystemCommand(targetDir, commands, properties)
+
+    val builder = ProcessBuilder(gradleCommands)
+    builder.directory(gradleWrapperDir)
+    builder.redirectErrorStream(true)
+    builder.redirectOutput(logFile)
+    val process = builder.start()
+    val exitCode = process.waitFor()
+    return BuildResult(exitCode, logFile)
+}
+
+private fun buildSystemCommand(projectDir: File, commands: List<String>, properties: List<String>): List<String> {
+    return if (isWindows)
+        listOf("cmd", "/C", "gradlew.bat", "-p", projectDir.canonicalPath) + commands + properties
+    else
+        listOf("/bin/bash", "gradlew", "-p", projectDir.canonicalPath) + commands + properties
+}
+
+private val isWindows: Boolean = System.getProperty("os.name")!!.contains("Windows")   
diff --git a/integration-testing/src/mavenTest/kotlin/MavenPublicationMetaInfValidator.kt b/integration-testing/src/mavenTest/kotlin/MavenPublicationMetaInfValidator.kt
new file mode 100644
index 0000000..845e38d
--- /dev/null
+++ b/integration-testing/src/mavenTest/kotlin/MavenPublicationMetaInfValidator.kt
@@ -0,0 +1,33 @@
+/*
+ * Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+import java.util.jar.JarFile
+import kotlin.test.Test
+import kotlin.test.fail
+
+class MavenPublicationMetaInfValidator {
+    @Test
+    fun testMetaInfContents() {
+        val clazz = Class.forName("kotlinx.atomicfu.AtomicFU")
+        JarFile(clazz.protectionDomain.codeSource.location.file).compareMetaInfContents(
+            setOf(
+                "MANIFEST.MF",
+                "atomicfu.kotlin_module",
+                "versions/9/module-info.class"
+            )
+        )
+    }
+
+    private fun JarFile.compareMetaInfContents(expected: Set<String>) {
+        val actual = entries().toList()
+                .filter { !it.isDirectory && it.realName.contains("META-INF")}
+                .map { it.realName.substringAfter("META-INF/") }
+                .toSet()
+        if (actual != expected) {
+            val intersection = actual.intersect(expected)
+            fail("Mismatched files: " + (actual.subtract(intersection) + expected.subtract(intersection)))
+        }
+        close()
+    }
+}
\ No newline at end of file
diff --git a/settings.gradle b/settings.gradle
index ab0e0a9..040a80d 100644
--- a/settings.gradle
+++ b/settings.gradle
@@ -1,8 +1,7 @@
-enableFeaturePreview('GRADLE_METADATA')
-
 include 'atomicfu'
 include 'atomicfu-transformer'
 include 'atomicfu-gradle-plugin'
 include 'atomicfu-maven-plugin'
 
-include 'atomicfu-native' // this is a kludge so that existing YouTrack config works, todo: remove
\ No newline at end of file
+include 'atomicfu-native' // this is a kludge so that existing YouTrack config works, todo: remove
+include 'integration-testing'
```

