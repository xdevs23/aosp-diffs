```diff
diff --git a/Android.bp b/Android.bp
index 51b86357..5c8164ba 100644
--- a/Android.bp
+++ b/Android.bp
@@ -5,21 +5,22 @@ java_library {
     srcs: ["core/jvmMain/src/kotlinx/serialization/**/*.kt"],
     common_srcs: ["core/commonMain/src/kotlinx/serialization/**/*.kt"],
     kotlincflags: [
-        "-Xmulti-platform",
         "-Xexpect-actual-classes",
-        "-opt-in=kotlin.ExperimentalStdlibApi",
+        "-Xmulti-platform",
         "-opt-in=kotlin.ExperimentalMultiplatform",
-        "-opt-in=kotlinx.serialization.internal.CoreFriendModuleApi",
+        "-opt-in=kotlin.ExperimentalStdlibApi",
         "-opt-in=kotlinx.serialization.ExperimentalSerializationApi",
         "-opt-in=kotlinx.serialization.InternalSerializationApi",
+        "-opt-in=kotlinx.serialization.internal.CoreFriendModuleApi",
+        "-opt-in=kotlinx.serialization.SealedSerializationApi",
     ],
     optimize: {
         proguard_flags_files: ["rules/*"],
         export_proguard_flags_files: true,
     },
     apex_available: [
-        "//apex_available:platform",
         "//apex_available:anyapex",
+        "//apex_available:platform",
     ],
 }
 
@@ -30,18 +31,19 @@ java_library {
     srcs: ["formats/json/jvmMain/src/kotlinx/serialization/**/*.kt"],
     common_srcs: ["formats/json/commonMain/src/kotlinx/serialization/**/*.kt"],
     kotlincflags: [
-        "-Xmulti-platform",
         "-Xexpect-actual-classes",
-        "-opt-in=kotlin.ExperimentalStdlibApi",
+        "-Xmulti-platform",
         "-opt-in=kotlin.ExperimentalMultiplatform",
-        "-opt-in=kotlinx.serialization.internal.CoreFriendModuleApi",
-        "-opt-in=kotlinx.serialization.json.internal.JsonFriendModuleApi",
+        "-opt-in=kotlin.ExperimentalStdlibApi",
         "-opt-in=kotlinx.serialization.ExperimentalSerializationApi",
         "-opt-in=kotlinx.serialization.InternalSerializationApi",
+        "-opt-in=kotlinx.serialization.internal.CoreFriendModuleApi",
+        "-opt-in=kotlinx.serialization.json.internal.JsonFriendModuleApi",
+        "-opt-in=kotlinx.serialization.SealedSerializationApi",
     ],
     static_libs: ["kotlinx_serialization_core"],
     apex_available: [
-        "//apex_available:platform",
         "//apex_available:anyapex",
+        "//apex_available:platform",
     ],
 }
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 2916b536..8c9a3422 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,3 +1,73 @@
+1.8.0 / 2025-01-06
+==================
+
+This release contains all of the changes from 1.8.0-RC. Kotlin 2.1.0 is used as a default, while upcoming 2.1.10 is also supported.
+Also added small bugfixes, including speedup of ProtoWireType.from (#2879).
+
+1.8.0-RC / 2024-12-10
+==================
+
+This is a release candidate for the next version. It is based on Kotlin 2.1.0 and includes a few new features, as well
+as bugfixes and improvements:
+
+## `@JsonIgnoreUnknownKeys` annotation
+
+Previously, only global setting `JsonBuilder.ignoreUnknownKeys` controlled whether Json parser would throw exception if
+input contained a property that was not declared in a `@Serializable` class.
+There were [a lot of complaints](https://github.com/Kotlin/kotlinx.serialization/issues/1420) that this setting is not
+flexible enough.
+To address them, we added new `@JsonIgnoreUnknownKeys` annotation that can be applied on a per-class basis.
+With this annotation, it is possible to allow unknown properties for annotated classes, while
+general decoding methods (such as `Json.decodeFromString` and others) would still reject them for everything else.
+See details in the corresponding [PR](https://github.com/Kotlin/kotlinx.serialization/pull/2874).
+
+## Stabilization of `SerialDescriptor` API and `@SealedSerializationApi` annotation
+
+`SerialDescriptor`, `SerialKind`, and related API has been around for a long time and has proven itself useful.
+The main reason `@ExperimentalSerializationApi` was on SerialDescriptor's properties is that we wanted to discourage
+people from subclassing it.
+Fortunately, Kotlin 2.1 provides a special mechanism for such a
+case — [SubclassOptInRequired](https://kotlinlang.org/docs/opt-in-requirements.html#opt-in-to-inherit-from-a-class-or-interface).
+New `kotlinx.serialization.SealedSerializationApi` annotation designates APIs
+as public for use, but closed for implementation — the case for SerialDescriptor, which is a non-sealed interface for
+technical reasons.
+Now you can use most of `SerialDescriptor` and its builders API without the need to opt-in into experimental
+serialization API.
+See the [PR](https://github.com/Kotlin/kotlinx.serialization/pull/2827) for more details.
+
+_Note_: All `SerialKind`s are stable API now, except `PolymorphicKind` — we may want to expand it in the future.
+
+## Generate Java 8's default method implementations in interfaces
+
+**TL;DR This change ensures better binary compatibility in the future for library. You should not experience any
+difference from it.**
+
+kotlinx.serialization library contains a lot of interfaces with default method implementations. Historically, Kotlin
+compiled a synthetic `DefaultImpls` class for them.
+[Starting from Kotlin 1.4](https://blog.jetbrains.com/kotlin/2020/07/kotlin-1-4-m3-generating-default-methods-in-interfaces/),
+it was possible to compile them using as Java 8's `default` methods to ensure
+that new methods can still be added to interfaces without the need for implementors to recompile.
+To preserve binary compatibility with existing clients, a special `all-compatbility` mode is supported in compiler
+to generate both `default` methods and synthetic `DefaultImpls` class.
+
+Now, kotlinx.serialization finally makes use of this `all-compatibility` mode,
+which potentially allows us to add new methods to interfaces such as `SerialDescriptor`, `Encoder`, `Decoder`, etc.,
+without breaking existing clients. This change is expected to have no effect on existing clients, and no action from
+your side is required.
+Note that Kotlin 2.2 plans to enable `all-compatibility`
+mode [by default](https://youtrack.jetbrains.com/issue/KTLC-269).
+
+## Other bugfixes and improvements
+
+* Correctly skip structures with Cbor.ignoreUnknownKeys setting (#2873)
+* Handle missing system property without NPE (#2867)
+* Fixed keeping INSTANCE field and serializer function for serializable objects in R8 full mode (#2865)
+* Correctly parse invalid numbers in JsonLiteral.long and other extensions (#2852)
+* Correctly handle serial name conflict for different classes in SerializersModule.overwriteWith (#2856)
+* Add inline reified version of encodeToString as a Json member to streamline the experience for newcomers. (#2853)
+* Do not check kind or discriminator collisions for subclasses' polymorphic serializers if Json.classDiscriminatorMode
+  is set to NONE (#2833)
+
 1.7.3 / 2024-09-19
 ==================
 
diff --git a/METADATA b/METADATA
index 3ef55dae..23593e63 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 2
-    day: 17
+    month: 3
+    day: 10
   }
   identifier {
     type: "Git"
     value: "https://github.com/Kotlin/kotlinx.serialization"
-    version: "v1.7.3"
+    version: "v1.8.0"
     primary_source: true
   }
 }
diff --git a/README.md b/README.md
index c451e413..c22bd65a 100644
--- a/README.md
+++ b/README.md
@@ -4,8 +4,8 @@
 [![JetBrains official project](https://jb.gg/badges/official.svg)](https://confluence.jetbrains.com/display/ALL/JetBrains+on+GitHub)
 [![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
 [![TeamCity build](https://img.shields.io/teamcity/http/teamcity.jetbrains.com/s/KotlinTools_KotlinxSerialization_Ko.svg)](https://teamcity.jetbrains.com/viewType.html?buildTypeId=KotlinTools_KotlinxSerialization_Ko&guest=1)
-[![Kotlin](https://img.shields.io/badge/kotlin-2.0.20-blue.svg?logo=kotlin)](http://kotlinlang.org)
-[![Maven Central](https://img.shields.io/maven-central/v/org.jetbrains.kotlinx/kotlinx-serialization-core/1.7.3)](https://central.sonatype.com/artifact/org.jetbrains.kotlinx/kotlinx-serialization-core/1.7.3)
+[![Kotlin](https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
+[![Maven Central](https://img.shields.io/maven-central/v/org.jetbrains.kotlinx/kotlinx-serialization-core/1.8.0)](https://central.sonatype.com/artifact/org.jetbrains.kotlinx/kotlinx-serialization-core/1.8.0)
 [![KDoc link](https://img.shields.io/badge/API_reference-KDoc-blue)](https://kotlinlang.org/api/kotlinx.serialization/)
 [![Slack channel](https://img.shields.io/badge/chat-slack-blue.svg?logo=slack)](https://kotlinlang.slack.com/messages/serialization/)
 
@@ -95,8 +95,8 @@ Kotlin DSL:
 
 ```kotlin
 plugins {
-    kotlin("jvm") version "2.0.20" // or kotlin("multiplatform") or any other kotlin plugin
-    kotlin("plugin.serialization") version "2.0.20"
+    kotlin("jvm") version "2.1.0" // or kotlin("multiplatform") or any other kotlin plugin
+    kotlin("plugin.serialization") version "2.1.0"
 }
 ```       
 
@@ -104,8 +104,8 @@ Groovy DSL:
 
 ```gradle
 plugins {
-    id 'org.jetbrains.kotlin.multiplatform' version '2.0.20'
-    id 'org.jetbrains.kotlin.plugin.serialization' version '2.0.20'
+    id 'org.jetbrains.kotlin.multiplatform' version '2.1.0'
+    id 'org.jetbrains.kotlin.plugin.serialization' version '2.1.0'
 }
 ```
 
@@ -123,7 +123,7 @@ buildscript {
     repositories { mavenCentral() }
 
     dependencies {
-        val kotlinVersion = "2.0.20"
+        val kotlinVersion = "2.1.0"
         classpath(kotlin("gradle-plugin", version = kotlinVersion))
         classpath(kotlin("serialization", version = kotlinVersion))
     }
@@ -134,7 +134,7 @@ Groovy DSL:
 
 ```gradle
 buildscript {
-    ext.kotlin_version = '2.0.20'
+    ext.kotlin_version = '2.1.0'
     repositories { mavenCentral() }
 
     dependencies {
@@ -164,7 +164,7 @@ repositories {
 }
 
 dependencies {
-    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
+    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")
 }
 ```
 
@@ -176,7 +176,7 @@ repositories {
 }
 
 dependencies {
-    implementation "org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3"
+    implementation "org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0"
 }
 ```
 
@@ -266,8 +266,8 @@ Ensure the proper version of Kotlin and serialization version:
 
 ```xml
 <properties>
-    <kotlin.version>2.0.20</kotlin.version>
-    <serialization.version>1.7.3</serialization.version>
+    <kotlin.version>2.1.0</kotlin.version>
+    <serialization.version>1.8.0</serialization.version>
 </properties>
 ```
 
diff --git a/benchmark/src/jmh/kotlin/kotlinx/benchmarks/protobuf/ProtoMapBenchmark.kt b/benchmark/src/jmh/kotlin/kotlinx/benchmarks/protobuf/ProtoMapBenchmark.kt
new file mode 100644
index 00000000..f3de66d4
--- /dev/null
+++ b/benchmark/src/jmh/kotlin/kotlinx/benchmarks/protobuf/ProtoMapBenchmark.kt
@@ -0,0 +1,32 @@
+/*
+ * Copyright 2017-2024 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.benchmarks.protobuf
+
+import kotlinx.serialization.Serializable
+import kotlinx.serialization.encodeToByteArray
+import kotlinx.serialization.protobuf.ProtoBuf
+import org.openjdk.jmh.annotations.*
+import java.util.concurrent.TimeUnit
+
+@Warmup(iterations = 5, time = 1)
+@Measurement(iterations = 5, time = 1)
+@BenchmarkMode(Mode.Throughput)
+@OutputTimeUnit(TimeUnit.MILLISECONDS)
+@State(Scope.Benchmark)
+@Fork(1)
+open class ProtoMapBenchmark {
+
+    @Serializable
+    class Holder(val map: Map<String, Int>)
+
+    private val value = Holder((0..128).associateBy { it.toString() })
+    private val bytes = ProtoBuf.encodeToByteArray(value)
+
+    @Benchmark
+    fun toBytes() = ProtoBuf.encodeToByteArray(Holder.serializer(), value)
+
+    @Benchmark
+    fun fromBytes() = ProtoBuf.decodeFromByteArray(Holder.serializer(), bytes)
+}
diff --git a/buildSrc/src/main/kotlin/source-sets-conventions.gradle.kts b/buildSrc/src/main/kotlin/source-sets-conventions.gradle.kts
index 1b2a75e8..311df3fb 100644
--- a/buildSrc/src/main/kotlin/source-sets-conventions.gradle.kts
+++ b/buildSrc/src/main/kotlin/source-sets-conventions.gradle.kts
@@ -32,7 +32,7 @@ kotlin {
         @OptIn(ExperimentalKotlinGradlePluginApi::class)
         compilerOptions {
             jvmTarget = JvmTarget.JVM_1_8
-            freeCompilerArgs.add("-Xjdk-release=1.8")
+            freeCompilerArgs.addAll("-Xjdk-release=1.8", "-Xjvm-default=all-compatibility")
         }
     }
     jvmToolchain(jdkToolchainVersion)
@@ -64,12 +64,24 @@ kotlin {
     sourceSets.all {
         kotlin.srcDirs("$name/src")
         resources.srcDirs("$name/resources")
-        languageSettings {
-            progressiveMode = true
+    }
 
-            optIn("kotlin.ExperimentalMultiplatform")
-            optIn("kotlinx.serialization.InternalSerializationApi")
+    compilerOptions {
+        // These configuration replaces 'languageSettings' config on line 67
+        progressiveMode.set(true)
+        optIn.addAll(
+            listOf(
+                "kotlin.ExperimentalMultiplatform",
+                "kotlin.ExperimentalSubclassOptIn",
+                "kotlinx.serialization.InternalSerializationApi",
+                "kotlinx.serialization.SealedSerializationApi",
+            )
+        )
+        if (overriddenLanguageVersion != null) {
+            languageVersion = KotlinVersion.fromVersion(overriddenLanguageVersion!!)
+            freeCompilerArgs.add("-Xsuppress-version-warnings")
         }
+        freeCompilerArgs.add("-Xexpect-actual-classes")
     }
 
     sourceSets {
@@ -112,6 +124,7 @@ kotlin {
     sourceSets.matching({ it.name.contains("Test") }).configureEach {
         languageSettings {
             optIn("kotlinx.serialization.InternalSerializationApi")
+            optIn("kotlinx.serialization.SealedSerializationApi")
             optIn("kotlinx.serialization.ExperimentalSerializationApi")
         }
     }
@@ -123,10 +136,5 @@ tasks.withType(KotlinCompilationTask::class).configureEach {
         if (isMainTaskName) {
             allWarningsAsErrors = true
         }
-        if (overriddenLanguageVersion != null) {
-            languageVersion = KotlinVersion.fromVersion(overriddenLanguageVersion!!)
-            freeCompilerArgs.add("-Xsuppress-version-warnings")
-        }
-        freeCompilerArgs.add("-Xexpect-actual-classes")
     }
 }
diff --git a/core/api/kotlinx-serialization-core.api b/core/api/kotlinx-serialization-core.api
index 0ac51c85..c8d0d35d 100644
--- a/core/api/kotlinx-serialization-core.api
+++ b/core/api/kotlinx-serialization-core.api
@@ -86,6 +86,9 @@ public final class kotlinx/serialization/SealedClassSerializer : kotlinx/seriali
 	public fun getDescriptor ()Lkotlinx/serialization/descriptors/SerialDescriptor;
 }
 
+public abstract interface annotation class kotlinx/serialization/SealedSerializationApi : java/lang/annotation/Annotation {
+}
+
 public abstract interface class kotlinx/serialization/SerialFormat {
 	public abstract fun getSerializersModule ()Lkotlinx/serialization/modules/SerializersModule;
 }
@@ -278,7 +281,7 @@ public final class kotlinx/serialization/descriptors/PrimitiveKind$STRING : kotl
 }
 
 public abstract interface class kotlinx/serialization/descriptors/SerialDescriptor {
-	public abstract fun getAnnotations ()Ljava/util/List;
+	public fun getAnnotations ()Ljava/util/List;
 	public abstract fun getElementAnnotations (I)Ljava/util/List;
 	public abstract fun getElementDescriptor (I)Lkotlinx/serialization/descriptors/SerialDescriptor;
 	public abstract fun getElementIndex (Ljava/lang/String;)I
@@ -287,8 +290,8 @@ public abstract interface class kotlinx/serialization/descriptors/SerialDescript
 	public abstract fun getKind ()Lkotlinx/serialization/descriptors/SerialKind;
 	public abstract fun getSerialName ()Ljava/lang/String;
 	public abstract fun isElementOptional (I)Z
-	public abstract fun isInline ()Z
-	public abstract fun isNullable ()Z
+	public fun isInline ()Z
+	public fun isNullable ()Z
 }
 
 public final class kotlinx/serialization/descriptors/SerialDescriptor$DefaultImpls {
@@ -358,7 +361,6 @@ public abstract class kotlinx/serialization/encoding/AbstractDecoder : kotlinx/s
 	public final fun decodeByteElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)B
 	public fun decodeChar ()C
 	public final fun decodeCharElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)C
-	public fun decodeCollectionSize (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
 	public fun decodeDouble ()D
 	public final fun decodeDoubleElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)D
 	public fun decodeEnum (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
@@ -373,10 +375,7 @@ public abstract class kotlinx/serialization/encoding/AbstractDecoder : kotlinx/s
 	public fun decodeNotNullMark ()Z
 	public fun decodeNull ()Ljava/lang/Void;
 	public final fun decodeNullableSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
-	public fun decodeNullableSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
-	public fun decodeSequentially ()Z
 	public fun decodeSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
-	public fun decodeSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
 	public fun decodeSerializableValue (Lkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
 	public static synthetic fun decodeSerializableValue$default (Lkotlinx/serialization/encoding/AbstractDecoder;Lkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;ILjava/lang/Object;)Ljava/lang/Object;
 	public fun decodeShort ()S
@@ -389,7 +388,6 @@ public abstract class kotlinx/serialization/encoding/AbstractDecoder : kotlinx/s
 
 public abstract class kotlinx/serialization/encoding/AbstractEncoder : kotlinx/serialization/encoding/CompositeEncoder, kotlinx/serialization/encoding/Encoder {
 	public fun <init> ()V
-	public fun beginCollection (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Lkotlinx/serialization/encoding/CompositeEncoder;
 	public fun beginStructure (Lkotlinx/serialization/descriptors/SerialDescriptor;)Lkotlinx/serialization/encoding/CompositeEncoder;
 	public fun encodeBoolean (Z)V
 	public final fun encodeBooleanElement (Lkotlinx/serialization/descriptors/SerialDescriptor;IZ)V
@@ -409,19 +407,15 @@ public abstract class kotlinx/serialization/encoding/AbstractEncoder : kotlinx/s
 	public final fun encodeIntElement (Lkotlinx/serialization/descriptors/SerialDescriptor;II)V
 	public fun encodeLong (J)V
 	public final fun encodeLongElement (Lkotlinx/serialization/descriptors/SerialDescriptor;IJ)V
-	public fun encodeNotNullMark ()V
 	public fun encodeNull ()V
 	public fun encodeNullableSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
-	public fun encodeNullableSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
 	public fun encodeSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
-	public fun encodeSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
 	public fun encodeShort (S)V
 	public final fun encodeShortElement (Lkotlinx/serialization/descriptors/SerialDescriptor;IS)V
 	public fun encodeString (Ljava/lang/String;)V
 	public final fun encodeStringElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILjava/lang/String;)V
 	public fun encodeValue (Ljava/lang/Object;)V
 	public fun endStructure (Lkotlinx/serialization/descriptors/SerialDescriptor;)V
-	public fun shouldEncodeElementDefault (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z
 }
 
 public abstract interface class kotlinx/serialization/encoding/ChunkedDecoder {
@@ -435,7 +429,7 @@ public abstract interface class kotlinx/serialization/encoding/CompositeDecoder
 	public abstract fun decodeBooleanElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z
 	public abstract fun decodeByteElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)B
 	public abstract fun decodeCharElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)C
-	public abstract fun decodeCollectionSize (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
+	public fun decodeCollectionSize (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
 	public abstract fun decodeDoubleElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)D
 	public abstract fun decodeElementIndex (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
 	public abstract fun decodeFloatElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)F
@@ -443,8 +437,10 @@ public abstract interface class kotlinx/serialization/encoding/CompositeDecoder
 	public abstract fun decodeIntElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)I
 	public abstract fun decodeLongElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)J
 	public abstract fun decodeNullableSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
-	public abstract fun decodeSequentially ()Z
+	public static synthetic fun decodeNullableSerializableElement$default (Lkotlinx/serialization/encoding/CompositeDecoder;Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;ILjava/lang/Object;)Ljava/lang/Object;
+	public fun decodeSequentially ()Z
 	public abstract fun decodeSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
+	public static synthetic fun decodeSerializableElement$default (Lkotlinx/serialization/encoding/CompositeDecoder;Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;ILjava/lang/Object;)Ljava/lang/Object;
 	public abstract fun decodeShortElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)S
 	public abstract fun decodeStringElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Ljava/lang/String;
 	public abstract fun endStructure (Lkotlinx/serialization/descriptors/SerialDescriptor;)V
@@ -478,7 +474,7 @@ public abstract interface class kotlinx/serialization/encoding/CompositeEncoder
 	public abstract fun encodeStringElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILjava/lang/String;)V
 	public abstract fun endStructure (Lkotlinx/serialization/descriptors/SerialDescriptor;)V
 	public abstract fun getSerializersModule ()Lkotlinx/serialization/modules/SerializersModule;
-	public abstract fun shouldEncodeElementDefault (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z
+	public fun shouldEncodeElementDefault (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z
 }
 
 public final class kotlinx/serialization/encoding/CompositeEncoder$DefaultImpls {
@@ -498,8 +494,8 @@ public abstract interface class kotlinx/serialization/encoding/Decoder {
 	public abstract fun decodeLong ()J
 	public abstract fun decodeNotNullMark ()Z
 	public abstract fun decodeNull ()Ljava/lang/Void;
-	public abstract fun decodeNullableSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
-	public abstract fun decodeSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
+	public fun decodeNullableSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
+	public fun decodeSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
 	public abstract fun decodeShort ()S
 	public abstract fun decodeString ()Ljava/lang/String;
 	public abstract fun getSerializersModule ()Lkotlinx/serialization/modules/SerializersModule;
@@ -515,7 +511,7 @@ public final class kotlinx/serialization/encoding/DecodingKt {
 }
 
 public abstract interface class kotlinx/serialization/encoding/Encoder {
-	public abstract fun beginCollection (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Lkotlinx/serialization/encoding/CompositeEncoder;
+	public fun beginCollection (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Lkotlinx/serialization/encoding/CompositeEncoder;
 	public abstract fun beginStructure (Lkotlinx/serialization/descriptors/SerialDescriptor;)Lkotlinx/serialization/encoding/CompositeEncoder;
 	public abstract fun encodeBoolean (Z)V
 	public abstract fun encodeByte (B)V
@@ -526,10 +522,10 @@ public abstract interface class kotlinx/serialization/encoding/Encoder {
 	public abstract fun encodeInline (Lkotlinx/serialization/descriptors/SerialDescriptor;)Lkotlinx/serialization/encoding/Encoder;
 	public abstract fun encodeInt (I)V
 	public abstract fun encodeLong (J)V
-	public abstract fun encodeNotNullMark ()V
+	public fun encodeNotNullMark ()V
 	public abstract fun encodeNull ()V
-	public abstract fun encodeNullableSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
-	public abstract fun encodeSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
+	public fun encodeNullableSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
+	public fun encodeSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
 	public abstract fun encodeShort (S)V
 	public abstract fun encodeString (Ljava/lang/String;)V
 	public abstract fun getSerializersModule ()Lkotlinx/serialization/modules/SerializersModule;
@@ -757,7 +753,7 @@ public final class kotlinx/serialization/internal/FloatSerializer : kotlinx/seri
 
 public abstract interface class kotlinx/serialization/internal/GeneratedSerializer : kotlinx/serialization/KSerializer {
 	public abstract fun childSerializers ()[Lkotlinx/serialization/KSerializer;
-	public abstract fun typeParametersSerializers ()[Lkotlinx/serialization/KSerializer;
+	public fun typeParametersSerializers ()[Lkotlinx/serialization/KSerializer;
 }
 
 public final class kotlinx/serialization/internal/GeneratedSerializer$DefaultImpls {
@@ -989,8 +985,6 @@ public class kotlinx/serialization/internal/PluginGeneratedSerialDescriptor : ko
 	public fun getSerialNames ()Ljava/util/Set;
 	public fun hashCode ()I
 	public fun isElementOptional (I)Z
-	public fun isInline ()Z
-	public fun isNullable ()Z
 	public final fun pushAnnotation (Ljava/lang/annotation/Annotation;)V
 	public final fun pushClassAnnotation (Ljava/lang/annotation/Annotation;)V
 	public fun toString ()Ljava/lang/String;
@@ -1081,7 +1075,6 @@ public abstract class kotlinx/serialization/internal/TaggedDecoder : kotlinx/ser
 	public final fun decodeByteElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)B
 	public final fun decodeChar ()C
 	public final fun decodeCharElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)C
-	public fun decodeCollectionSize (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
 	public final fun decodeDouble ()D
 	public final fun decodeDoubleElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)D
 	public final fun decodeEnum (Lkotlinx/serialization/descriptors/SerialDescriptor;)I
@@ -1096,10 +1089,7 @@ public abstract class kotlinx/serialization/internal/TaggedDecoder : kotlinx/ser
 	public fun decodeNotNullMark ()Z
 	public final fun decodeNull ()Ljava/lang/Void;
 	public final fun decodeNullableSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
-	public fun decodeNullableSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
-	public fun decodeSequentially ()Z
 	public final fun decodeSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
-	public fun decodeSerializableValue (Lkotlinx/serialization/DeserializationStrategy;)Ljava/lang/Object;
 	protected fun decodeSerializableValue (Lkotlinx/serialization/DeserializationStrategy;Ljava/lang/Object;)Ljava/lang/Object;
 	public final fun decodeShort ()S
 	public final fun decodeShortElement (Lkotlinx/serialization/descriptors/SerialDescriptor;I)S
@@ -1130,7 +1120,6 @@ public abstract class kotlinx/serialization/internal/TaggedDecoder : kotlinx/ser
 
 public abstract class kotlinx/serialization/internal/TaggedEncoder : kotlinx/serialization/encoding/CompositeEncoder, kotlinx/serialization/encoding/Encoder {
 	public fun <init> ()V
-	public fun beginCollection (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Lkotlinx/serialization/encoding/CompositeEncoder;
 	public fun beginStructure (Lkotlinx/serialization/descriptors/SerialDescriptor;)Lkotlinx/serialization/encoding/CompositeEncoder;
 	public final fun encodeBoolean (Z)V
 	public final fun encodeBooleanElement (Lkotlinx/serialization/descriptors/SerialDescriptor;IZ)V
@@ -1152,9 +1141,7 @@ public abstract class kotlinx/serialization/internal/TaggedEncoder : kotlinx/ser
 	public fun encodeNotNullMark ()V
 	public fun encodeNull ()V
 	public fun encodeNullableSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
-	public fun encodeNullableSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
 	public fun encodeSerializableElement (Lkotlinx/serialization/descriptors/SerialDescriptor;ILkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
-	public fun encodeSerializableValue (Lkotlinx/serialization/SerializationStrategy;Ljava/lang/Object;)V
 	public final fun encodeShort (S)V
 	public final fun encodeShortElement (Lkotlinx/serialization/descriptors/SerialDescriptor;IS)V
 	public final fun encodeString (Ljava/lang/String;)V
@@ -1181,7 +1168,6 @@ public abstract class kotlinx/serialization/internal/TaggedEncoder : kotlinx/ser
 	protected abstract fun getTag (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Ljava/lang/Object;
 	protected final fun popTag ()Ljava/lang/Object;
 	protected final fun pushTag (Ljava/lang/Object;)V
-	public fun shouldEncodeElementDefault (Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z
 }
 
 public final class kotlinx/serialization/internal/TripleSerializer : kotlinx/serialization/KSerializer {
@@ -1328,7 +1314,6 @@ public final class kotlinx/serialization/modules/SerializersModuleBuilder : kotl
 	public fun contextual (Lkotlin/reflect/KClass;Lkotlinx/serialization/KSerializer;)V
 	public final fun include (Lkotlinx/serialization/modules/SerializersModule;)V
 	public fun polymorphic (Lkotlin/reflect/KClass;Lkotlin/reflect/KClass;Lkotlinx/serialization/KSerializer;)V
-	public fun polymorphicDefault (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
 	public fun polymorphicDefaultDeserializer (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
 	public fun polymorphicDefaultSerializer (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
 }
@@ -1343,9 +1328,9 @@ public final class kotlinx/serialization/modules/SerializersModuleBuildersKt {
 
 public abstract interface class kotlinx/serialization/modules/SerializersModuleCollector {
 	public abstract fun contextual (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
-	public abstract fun contextual (Lkotlin/reflect/KClass;Lkotlinx/serialization/KSerializer;)V
+	public fun contextual (Lkotlin/reflect/KClass;Lkotlinx/serialization/KSerializer;)V
 	public abstract fun polymorphic (Lkotlin/reflect/KClass;Lkotlin/reflect/KClass;Lkotlinx/serialization/KSerializer;)V
-	public abstract fun polymorphicDefault (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
+	public fun polymorphicDefault (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
 	public abstract fun polymorphicDefaultDeserializer (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
 	public abstract fun polymorphicDefaultSerializer (Lkotlin/reflect/KClass;Lkotlin/jvm/functions/Function1;)V
 }
diff --git a/core/api/kotlinx-serialization-core.klib.api b/core/api/kotlinx-serialization-core.klib.api
index c640b605..041c115e 100644
--- a/core/api/kotlinx-serialization-core.klib.api
+++ b/core/api/kotlinx-serialization-core.klib.api
@@ -61,6 +61,10 @@ open annotation class kotlinx.serialization/Required : kotlin/Annotation { // ko
     constructor <init>() // kotlinx.serialization/Required.<init>|<init>(){}[0]
 }
 
+open annotation class kotlinx.serialization/SealedSerializationApi : kotlin/Annotation { // kotlinx.serialization/SealedSerializationApi|null[0]
+    constructor <init>() // kotlinx.serialization/SealedSerializationApi.<init>|<init>(){}[0]
+}
+
 open annotation class kotlinx.serialization/SerialInfo : kotlin/Annotation { // kotlinx.serialization/SerialInfo|null[0]
     constructor <init>() // kotlinx.serialization/SerialInfo.<init>|<init>(){}[0]
 }
diff --git a/core/commonMain/src/kotlinx/serialization/Annotations.kt b/core/commonMain/src/kotlinx/serialization/Annotations.kt
index ec1bf14f..183602f2 100644
--- a/core/commonMain/src/kotlinx/serialization/Annotations.kt
+++ b/core/commonMain/src/kotlinx/serialization/Annotations.kt
@@ -347,33 +347,3 @@ public annotation class Polymorphic
 @Target(AnnotationTarget.CLASS)
 @Retention(AnnotationRetention.RUNTIME)
 public annotation class KeepGeneratedSerializer
-
-/**
- * Marks declarations that are still **experimental** in kotlinx.serialization, which means that the design of the
- * corresponding declarations has open issues which may (or may not) lead to their changes in the future.
- * Roughly speaking, there is a chance that those declarations will be deprecated in the near future or
- * the semantics of their behavior may change in some way that may break some code.
- *
- * By default, the following categories of API are experimental:
- *
- * * Writing 3rd-party serialization formats
- * * Writing non-trivial custom serializers
- * * Implementing [SerialDescriptor] interfaces
- * * Not-yet-stable serialization formats that require additional polishing
- */
-@MustBeDocumented
-@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY, AnnotationTarget.FUNCTION, AnnotationTarget.TYPEALIAS)
-@RequiresOptIn(level = RequiresOptIn.Level.WARNING)
-public annotation class ExperimentalSerializationApi
-
-/**
- * Public API marked with this annotation is effectively **internal**, which means
- * it should not be used outside of `kotlinx.serialization`.
- * Signature, semantics, source and binary compatibilities are not guaranteed for this API
- * and will be changed without any warnings or migration aids.
- * If you cannot avoid using internal API to solve your problem, please report your use-case to serialization's issue tracker.
- */
-@MustBeDocumented
-@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY, AnnotationTarget.FUNCTION, AnnotationTarget.TYPEALIAS)
-@RequiresOptIn(level = RequiresOptIn.Level.ERROR)
-public annotation class InternalSerializationApi
diff --git a/core/commonMain/src/kotlinx/serialization/ApiLevels.kt b/core/commonMain/src/kotlinx/serialization/ApiLevels.kt
new file mode 100644
index 00000000..728ddd12
--- /dev/null
+++ b/core/commonMain/src/kotlinx/serialization/ApiLevels.kt
@@ -0,0 +1,51 @@
+/*
+ * Copyright 2017-2024 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.serialization
+
+import kotlinx.serialization.descriptors.*
+
+/**
+ * Marks declarations that are still **experimental** in kotlinx.serialization, which means that the design of the
+ * corresponding declarations has open issues which may (or may not) lead to their changes in the future.
+ * Roughly speaking, there is a chance that those declarations will be deprecated in the near future or
+ * the semantics of their behavior may change in some way that may break some code.
+ *
+ * By default, the following categories of API are experimental:
+ *
+ * * Writing 3rd-party serialization formats
+ * * Writing non-trivial custom serializers
+ * * Implementing [SerialDescriptor] interfaces
+ * * Not-yet-stable serialization formats that require additional polishing
+ */
+@MustBeDocumented
+@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY, AnnotationTarget.FUNCTION, AnnotationTarget.TYPEALIAS)
+@RequiresOptIn(level = RequiresOptIn.Level.WARNING)
+public annotation class ExperimentalSerializationApi
+
+/**
+ * Public API marked with this annotation is effectively **internal**, which means
+ * it should not be used outside of `kotlinx.serialization`.
+ * Signature, semantics, source and binary compatibilities are not guaranteed for this API
+ * and will be changed without any warnings or migration aids.
+ * If you cannot avoid using internal API to solve your problem, please report your use-case to serialization's issue tracker.
+ */
+@MustBeDocumented
+@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY, AnnotationTarget.FUNCTION, AnnotationTarget.TYPEALIAS)
+@RequiresOptIn(level = RequiresOptIn.Level.ERROR)
+public annotation class InternalSerializationApi
+
+/**
+ * Marks interfaces and non-final classes that can be freely referenced in users' code but should not be
+ * implemented or inherited. Such declarations are effectively `sealed` and do not have this modifier purely for technical reasons.
+ *
+ * kotlinx.serialization library provides compatibility guarantees for existing signatures of such classes;
+ * however, new functions or properties can be added to them in any release.
+ */
+@MustBeDocumented
+@Target() // no direct targets, only argument to @SubclassOptInRequired
+@RequiresOptIn(message = "This class or interface should not be inherited/implemented outside of kotlinx.serialization library. " +
+    "Note it is still permitted to use it directly. Read its documentation about inheritance for details.", level = RequiresOptIn.Level.ERROR)
+public annotation class SealedSerializationApi
+
diff --git a/core/commonMain/src/kotlinx/serialization/builtins/BuiltinSerializers.kt b/core/commonMain/src/kotlinx/serialization/builtins/BuiltinSerializers.kt
index fd9af288..c481e3ad 100644
--- a/core/commonMain/src/kotlinx/serialization/builtins/BuiltinSerializers.kt
+++ b/core/commonMain/src/kotlinx/serialization/builtins/BuiltinSerializers.kt
@@ -61,7 +61,6 @@ public fun Char.Companion.serializer(): KSerializer<Char> = CharSerializer
  * Returns serializer for [CharArray] with [descriptor][SerialDescriptor] of [StructureKind.LIST] kind.
  * Each element of the array is serialized one by one with [Char.Companion.serializer].
  */
-@Suppress("UNCHECKED_CAST")
 public fun CharArraySerializer(): KSerializer<CharArray> = CharArraySerializer
 
 /**
diff --git a/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptor.kt b/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptor.kt
index c84bb96b..207989e9 100644
--- a/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptor.kt
+++ b/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptor.kt
@@ -11,16 +11,16 @@ import kotlinx.serialization.encoding.*
 /**
  * Serial descriptor is an inherent property of [KSerializer] that describes the structure of the serializable type.
  * The structure of the serializable type is not only the characteristic of the type itself, but also of the serializer as well,
- * meaning that one type can have multiple descriptors that have completely different structure.
+ * meaning that one type can have multiple descriptors that have completely different structures.
  *
  * For example, the class `class Color(val rgb: Int)` can have multiple serializable representations,
  * such as `{"rgb": 255}`, `"#0000FF"`, `[0, 0, 255]` and `{"red": 0, "green": 0, "blue": 255}`.
- * Representations are determined by serializers and each such serializer has its own descriptor that identifies
+ * Representations are determined by serializers, and each such serializer has its own descriptor that identifies
  * each structure in a distinguishable and format-agnostic manner.
  *
  * ### Structure
  * Serial descriptor is identified by its [name][serialName] and consists of a kind, potentially empty set of
- * children elements and additional metadata.
+ * children elements, and additional metadata.
  *
  * * [serialName] uniquely identifies the descriptor (and the corresponding serializer) for non-generic types.
  *   For generic types, the actual type substitution is omitted from the string representation, and the name
@@ -29,7 +29,7 @@ import kotlinx.serialization.encoding.*
  *   arguments are not equal to each other.
  *   [serialName] is typically used to specify the type of the target class during serialization of polymorphic and sealed
  *   classes, for observability and diagnostics.
- * * [Kind][SerialKind] defines what this descriptor represents: primitive, enum, object, collection etc.
+ * * [Kind][SerialKind] defines what this descriptor represents: primitive, enum, object, collection, etc.
  * * Children elements are represented as serial descriptors as well and define the structure of the type's elements.
  * * Metadata carries additional information, such as [nullability][nullable], [optionality][isElementOptional]
  *   and [serial annotations][getElementAnnotations].
@@ -40,7 +40,7 @@ import kotlinx.serialization.encoding.*
  * #### Serialization
  * Serial descriptor is used as a bridge between decoders/encoders and serializers.
  * When asking for a next element, the serializer provides an expected descriptor to the decoder, and,
- * based on the descriptor content, decoder decides how to parse its input.
+ * based on the descriptor content, the decoder decides how to parse its input.
  * In JSON, for example, when the encoder is asked to encode the next element and this element
  * is a subtype of [List], the encoder receives a descriptor with [StructureKind.LIST] and, based on that,
  * first writes an opening square bracket before writing the content of the list.
@@ -51,7 +51,7 @@ import kotlinx.serialization.encoding.*
  *
  * #### Introspection
  * Another usage of a serial descriptor is type introspection without its serialization.
- * Introspection can be used to check, whether the given serializable class complies the
+ * Introspection can be used to check whether the given serializable class complies the
  * corresponding scheme and to generate JSON or ProtoBuf schema from the given class.
  *
  * ### Indices
@@ -60,13 +60,13 @@ import kotlinx.serialization.encoding.*
  * the range from zero to [elementsCount] and represent and index of the property in this class.
  * Consequently, primitives do not have children and their element count is zero.
  *
- * For collections and maps indices don't have fixed bound. Regular collections descriptors usually
+ * For collections and maps indices do not have a fixed bound. Regular collections descriptors usually
  * have one element (`T`, maps have two, one for keys and one for values), but potentially unlimited
- * number of actual children values. Valid indices range is not known statically
- * and implementations of such descriptor should provide consistent and unbounded names and indices.
+ * number of actual children values. Valid indices range is not known statically,
+ * and implementations of such a descriptor should provide consistent and unbounded names and indices.
  *
  * In practice, for regular classes it is allowed to invoke `getElement*(index)` methods
- * with an index from `0` to [elementsCount] range and element at the particular index corresponds to the
+ * with an index from `0` to [elementsCount] range and the element at the particular index corresponds to the
  * serializable property at the given position.
  * For collections and maps, index parameter for `getElement*(index)` methods is effectively bounded
  * by the maximal number of collection/map elements.
@@ -80,12 +80,12 @@ import kotlinx.serialization.encoding.*
  *
  * An [equals] implementation should use both [serialName] and elements structure.
  * Comparing [elementDescriptors] directly is discouraged,
- * because it may cause a stack overflow error, e.g. if a serializable class `T` contains elements of type `T`.
+ * because it may cause a stack overflow error, e.g., if a serializable class `T` contains elements of type `T`.
  * To avoid it, a serial descriptor implementation should compare only descriptors
  * of class' type parameters, in a way that `serializer<Box<Int>>().descriptor != serializer<Box<String>>().descriptor`.
- * If type parameters are equal, descriptors structure should be compared by using children elements
+ * If type parameters are equal, descriptor structure should be compared by using children elements
  * descriptors' [serialName]s, which correspond to class names
- * (do not confuse with elements own names, which correspond to properties names); and/or other [SerialDescriptor]
+ * (do not confuse with elements' own names, which correspond to properties' names); and/or other [SerialDescriptor]
  * properties, such as [kind].
  * An example of [equals] implementation:
  * ```
@@ -128,31 +128,44 @@ import kotlinx.serialization.encoding.*
  * }
  * ```
  *
- * For a classes that are represented as a single primitive value, [PrimitiveSerialDescriptor] builder function can be used instead.
+ * For classes that are represented as a single primitive value, [PrimitiveSerialDescriptor] builder function can be used instead.
  *
  * ### Consistency violations
  * An implementation of [SerialDescriptor] should be consistent with the implementation of the corresponding [KSerializer].
- * Yet it is not type-checked statically, thus making it possible to declare a non-consistent implementations of descriptor and serializer.
- * In such cases, the behaviour of an underlying format is unspecified and may lead to both runtime errors and encoding of
+ * Yet it is not type-checked statically, thus making it possible to declare a non-consistent implementation of descriptor and serializer.
+ * In such cases, the behavior of an underlying format is unspecified and may lead to both runtime errors and encoding of
  * corrupted data that is impossible to decode back.
  *
- * ### Not stable for inheritance
+ * ### Not for implementation
  *
- * `SerialDescriptor` interface is not stable for inheritance in 3rd party libraries, as new methods
- * might be added to this interface or contracts of the existing methods can be changed.
- * This interface is safe to build using [buildClassSerialDescriptor] and [PrimitiveSerialDescriptor],
- * and is safe to delegate implementation to existing instances.
+ * `SerialDescriptor` interface should not be implemented in 3rd party libraries, as new methods
+ * might be added to this interface when kotlinx.serialization adds support for new Kotlin features.
+ * This interface is safe to use and construct via [buildClassSerialDescriptor], [PrimitiveSerialDescriptor], and `SerialDescriptor` factory function.
  */
+@SubclassOptInRequired(SealedSerializationApi::class)
 public interface SerialDescriptor {
     /**
      * Serial name of the descriptor that identifies a pair of the associated serializer and target class.
      *
-     * For generated and default serializers, the serial name should be equal to the corresponding class's fully qualified name
+     * For generated and default serializers, the serial name is equal to the corresponding class's fully qualified name
      * or, if overridden, [SerialName].
      * Custom serializers should provide a unique serial name that identifies both the serializable class and
-     * the serializer itself, ignoring type arguments, if they are present, for example: `my.package.LongAsTrimmedString`
+     * the serializer itself, ignoring type arguments if they are present, for example: `my.package.LongAsTrimmedString`.
+     *
+     * Do not confuse with [getElementName], which returns property name:
+     *
+     * ```
+     * package my.app
+     *
+     * @Serializable
+     * class User(val name: String)
+     *
+     * val userDescriptor = User.serializer().descriptor
+     *
+     * userDescriptor.serialName // Returns "my.app.User"
+     * userDescriptor.getElementName(0) // Returns "name"
+     * ```
      */
-    @ExperimentalSerializationApi
     public val serialName: String
 
     /**
@@ -163,21 +176,58 @@ public interface SerialDescriptor {
      * brackets, while ProtoBuf just serialize these types in separate ways.
      *
      * Kind should be consistent with the implementation, for example, if it is a [primitive][PrimitiveKind],
-     * then its elements count should be zero and vice versa.
+     * then its element count should be zero and vice versa.
+     *
+     * Example of introspecting kinds:
+     *
+     * ```
+     * @Serializable
+     * class User(val name: String)
+     *
+     * val userDescriptor = User.serializer().descriptor
+     *
+     * userDescriptor.kind // Returns StructureKind.CLASS
+     * userDescriptor.getElementDescriptor(0).kind // Returns PrimitiveKind.STRING
+     * ```
      */
-    @ExperimentalSerializationApi
     public val kind: SerialKind
 
     /**
-     * Whether the descriptor describes nullable element.
+     * Whether the descriptor describes a nullable type.
      * Returns `true` if associated serializer can serialize/deserialize nullable elements of the described type.
+     *
+     * Example:
+     *
+     * ```
+     * @Serializable
+     * class User(val name: String, val alias: String?)
+     *
+     * val userDescriptor = User.serializer().descriptor
+     *
+     * userDescriptor.isNullable // Returns false
+     * userDescriptor.getElementDescriptor(0).isNullable // Returns false
+     * userDescriptor.getElementDescriptor(1).isNullable // Returns true
+     * ```
      */
-    @ExperimentalSerializationApi
     public val isNullable: Boolean get() = false
 
     /**
      * Returns `true` if this descriptor describes a serializable value class which underlying value
      * is serialized directly.
+     *
+     * This property is true for serializable `@JvmInline value` classes:
+     * ```
+     * @Serializable
+     * class User(val name: Name)
+     *
+     * @Serializable
+     * @JvmInline
+     * value class Name(val value: String)
+     *
+     * User.serializer().descriptor.isInline // false
+     * User.serializer().descriptor.getElementDescriptor(0).isInline // true
+     * Name.serializer().descriptor.isInline // true
+     * ```
      */
     public val isInline: Boolean get() = false
 
@@ -188,19 +238,44 @@ public interface SerialDescriptor {
      *
      * For example, for the following class
      * `class Complex(val real: Long, val imaginary: Long)` the corresponding descriptor
-     * and the serialized form both have two elements, while for `class IntList : ArrayList<Int>()`
+     * and the serialized form both have two elements, while for `List<Int>`
      * the corresponding descriptor has a single element (`IntDescriptor`, the type of list element),
-     * but from zero up to `Int.MAX_VALUE` values in the serialized form.
+     * but from zero up to `Int.MAX_VALUE` values in the serialized form:
+     *
+     * ```
+     * @Serializable
+     * class Complex(val real: Long, val imaginary: Long)
+     *
+     * Complex.serializer().descriptor.elementsCount // Returns 2
+     *
+     * @Serializable
+     * class OuterList(val list: List<Int>)
+     *
+     * OuterList.serializer().descriptor.getElementDescriptor(0).elementsCount // Returns 1
+     * ```
      */
-    @ExperimentalSerializationApi
     public val elementsCount: Int
 
     /**
      * Returns serial annotations of the associated class.
-     * Serial annotations can be used to specify an additional metadata that may be used during serialization.
+     * Serial annotations can be used to specify additional metadata that may be used during serialization.
      * Only annotations marked with [SerialInfo] are added to the resulting list.
+     *
+     * Do not confuse with [getElementAnnotations]:
+     * ```
+     * @Serializable
+     * @OnClassSerialAnnotation
+     * class Nested(...)
+     *
+     * @Serializable
+     * class Outer(@OnPropertySerialAnnotation val nested: Nested)
+     *
+     * val outerDescriptor = Outer.serializer().descriptor
+     *
+     * outerDescriptor.getElementAnnotations(0) // Returns [@OnPropertySerialAnnotation]
+     * outerDescriptor.getElementDescriptor(0).annotations // Returns [@OnClassSerialAnnotation]
+     * ```
      */
-    @ExperimentalSerializationApi
     public val annotations: List<Annotation> get() = emptyList()
 
     /**
@@ -208,41 +283,67 @@ public interface SerialDescriptor {
      * Positional name represents a corresponding property name in the class, associated with
      * the current descriptor.
      *
+     * Do not confuse with [serialName], which returns class name:
+     *
+     * ```
+     * package my.app
+     *
+     * @Serializable
+     * class User(val name: String)
+     *
+     * val userDescriptor = User.serializer().descriptor
+     *
+     * userDescriptor.serialName // Returns "my.app.User"
+     * userDescriptor.getElementName(0) // Returns "name"
+     * ```
+     *
      * @throws IndexOutOfBoundsException for an illegal [index] values.
      * @throws IllegalStateException if the current descriptor does not support children elements (e.g. is a primitive)
      */
-    @ExperimentalSerializationApi
     public fun getElementName(index: Int): String
 
     /**
      * Returns an index in the children list of the given element by its name or [CompositeDecoder.UNKNOWN_NAME]
      * if there is no such element.
      * The resulting index, if it is not [CompositeDecoder.UNKNOWN_NAME], is guaranteed to be usable with [getElementName].
+     *
+     * Example:
+     *
+     * ```
+     * @Serializable
+     * class User(val name: String, val alias: String?)
+     *
+     * val userDescriptor = User.serializer().descriptor
+     *
+     * userDescriptor.getElementIndex("name") // Returns 0
+     * userDescriptor.getElementIndex("alias") // Returns 1
+     * userDescriptor.getElementIndex("lastName") // Returns CompositeDecoder.UNKNOWN_NAME = -3
+     * ```
      */
-    @ExperimentalSerializationApi
     public fun getElementIndex(name: String): Int
 
     /**
      * Returns serial annotations of the child element at the given [index].
      * This method differs from `getElementDescriptor(index).annotations` by reporting only
-     * declaration-specific annotations:
+     * element-specific annotations:
      * ```
      * @Serializable
-     * @SomeSerialAnnotation
+     * @OnClassSerialAnnotation
      * class Nested(...)
      *
      * @Serializable
-     * class Outer(@AnotherSerialAnnotation val nested: Nested)
+     * class Outer(@OnPropertySerialAnnotation val nested: Nested)
      *
-     * outerDescriptor.getElementAnnotations(0) // Returns [@AnotherSerialAnnotation]
-     * outerDescriptor.getElementDescriptor(0).annotations // Returns [@SomeSerialAnnotation]
+     * val outerDescriptor = Outer.serializer().descriptor
+     *
+     * outerDescriptor.getElementAnnotations(0) // Returns [@OnPropertySerialAnnotation]
+     * outerDescriptor.getElementDescriptor(0).annotations // Returns [@OnClassSerialAnnotation]
      * ```
      * Only annotations marked with [SerialInfo] are added to the resulting list.
      *
      * @throws IndexOutOfBoundsException for an illegal [index] values.
      * @throws IllegalStateException if the current descriptor does not support children elements (e.g. is a primitive).
      */
-    @ExperimentalSerializationApi
     public fun getElementAnnotations(index: Int): List<Annotation>
 
     /**
@@ -252,42 +353,63 @@ public interface SerialDescriptor {
      * with `@Serializable(with = ...`)`, [Polymorphic] or [Contextual].
      * This method can be used to completely introspect the type that the current descriptor describes.
      *
+     * Example:
+     * ```
+     * @Serializable
+     * @OnClassSerialAnnotation
+     * class Nested(...)
+     *
+     * @Serializable
+     * class Outer(val nested: Nested)
+     *
+     * val outerDescriptor = Outer.serializer().descriptor
+     *
+     * outerDescriptor.getElementDescriptor(0).serialName // Returns "Nested"
+     * outerDescriptor.getElementDescriptor(0).annotations // Returns [@OnClassSerialAnnotation]
+     * ```
+     *
      * @throws IndexOutOfBoundsException for illegal [index] values.
      * @throws IllegalStateException if the current descriptor does not support children elements (e.g. is a primitive).
      */
-    @ExperimentalSerializationApi
     public fun getElementDescriptor(index: Int): SerialDescriptor
 
     /**
      * Whether the element at the given [index] is optional (can be absent in serialized form).
      * For generated descriptors, all elements that have a corresponding default parameter value are
      * marked as optional. Custom serializers can treat optional values in a serialization-specific manner
-     * without default parameters constraint.
+     * without a default parameters constraint.
      *
      * Example of optionality:
      * ```
      * @Serializable
      * class Holder(
-     *     val a: Int, // Optional == false
-     *     val b: Int?, // Optional == false
-     *     val c: Int? = null, // Optional == true
-     *     val d: List<Int>, // Optional == false
-     *     val e: List<Int> = listOf(1), // Optional == true
+     *     val a: Int, // isElementOptional(0) == false
+     *     val b: Int?, // isElementOptional(1) == false
+     *     val c: Int? = null, // isElementOptional(2) == true
+     *     val d: List<Int>, // isElementOptional(3) == false
+     *     val e: List<Int> = listOf(1), // isElementOptional(4) == true
      * )
      * ```
-     * Returns `false` for valid indices of collections, maps and enums.
+     * Returns `false` for valid indices of collections, maps, and enums.
      *
      * @throws IndexOutOfBoundsException for an illegal [index] values.
      * @throws IllegalStateException if the current descriptor does not support children elements (e.g. is a primitive).
      */
-    @ExperimentalSerializationApi
     public fun isElementOptional(index: Int): Boolean
 }
 
 /**
  * Returns an iterable of all descriptor [elements][SerialDescriptor.getElementDescriptor].
+ *
+ * Example:
+ *
+ * ```
+ * @Serializable
+ * class User(val name: String, val alias: String?)
+ *
+ * User.serializer().descriptor.elementDescriptors.toList() // Returns [PrimitiveDescriptor(kotlin.String), PrimitiveDescriptor(kotlin.String)?]
+ * ```
  */
-@ExperimentalSerializationApi
 public val SerialDescriptor.elementDescriptors: Iterable<SerialDescriptor>
     get() = Iterable {
         object : Iterator<SerialDescriptor> {
@@ -302,8 +424,16 @@ public val SerialDescriptor.elementDescriptors: Iterable<SerialDescriptor>
 
 /**
  * Returns an iterable of all descriptor [element names][SerialDescriptor.getElementName].
+ *
+ * Example:
+ *
+ * ```
+ * @Serializable
+ * class User(val name: String, val alias: String?)
+ *
+ * User.serializer().descriptor.elementNames.toList() // Returns ["name", "alias"]
+ * ```
  */
-@ExperimentalSerializationApi
 public val SerialDescriptor.elementNames: Iterable<String>
     get() = Iterable {
         object : Iterator<String> {
diff --git a/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptors.kt b/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptors.kt
index 89e2cf40..339ac3b7 100644
--- a/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptors.kt
+++ b/core/commonMain/src/kotlinx/serialization/descriptors/SerialDescriptors.kt
@@ -49,8 +49,6 @@ import kotlin.reflect.*
  * }
  * ```
  */
-@Suppress("FunctionName")
-@OptIn(ExperimentalSerializationApi::class)
 public fun buildClassSerialDescriptor(
     serialName: String,
     vararg typeParameters: SerialDescriptor,
@@ -69,7 +67,7 @@ public fun buildClassSerialDescriptor(
 }
 
 /**
- * Factory to create a trivial primitive descriptors.
+ * Factory to create trivial primitive descriptors. [serialName] must be non-blank and unique.
  * Primitive descriptors should be used when the serialized form of the data has a primitive form, for example:
  * ```
  * object LongAsStringSerializer : KSerializer<Long> {
@@ -86,6 +84,7 @@ public fun buildClassSerialDescriptor(
  * }
  * ```
  */
+@Suppress("FunctionName")
 public fun PrimitiveSerialDescriptor(serialName: String, kind: PrimitiveKind): SerialDescriptor {
     require(serialName.isNotBlank()) { "Blank serial names are prohibited" }
     return PrimitiveDescriptorSafe(serialName, kind)
@@ -93,9 +92,8 @@ public fun PrimitiveSerialDescriptor(serialName: String, kind: PrimitiveKind): S
 
 /**
  * Factory to create a new descriptor that is identical to [original] except that the name is equal to [serialName].
- * Should be used when you want to serialize a type as another non-primitive type.
- * Don't use this if you want to serialize a type as a primitive value, use [PrimitiveSerialDescriptor] instead.
- * 
+ * Usually used when you want to serialize a type as another type, delegating implementation of `serialize` and `deserialize`.
+ *
  * Example:
  * ```
  * @Serializable(CustomSerializer::class)
@@ -115,27 +113,24 @@ public fun PrimitiveSerialDescriptor(serialName: String, kind: PrimitiveKind): S
  * }
  * ```
  */
-@ExperimentalSerializationApi
 public fun SerialDescriptor(serialName: String, original: SerialDescriptor): SerialDescriptor {
     require(serialName.isNotBlank()) { "Blank serial names are prohibited" }
-    require(original.kind !is PrimitiveKind) { "For primitive descriptors please use 'PrimitiveSerialDescriptor' instead" }
     require(serialName != original.serialName) { "The name of the wrapped descriptor ($serialName) cannot be the same as the name of the original descriptor (${original.serialName})" }
-    
+    if (original.kind is PrimitiveKind) checkNameIsNotAPrimitive(serialName)
+
     return WrappedSerialDescriptor(serialName, original)
 }
 
-@OptIn(ExperimentalSerializationApi::class)
 internal class WrappedSerialDescriptor(override val serialName: String, original: SerialDescriptor) : SerialDescriptor by original
 
 /**
  * An unsafe alternative to [buildClassSerialDescriptor] that supports an arbitrary [SerialKind].
  * This function is left public only for migration of pre-release users and is not intended to be used
- * as generally-safe and stable mechanism. Beware that it can produce inconsistent or non spec-compliant instances.
+ * as a generally safe and stable mechanism. Beware that it can produce inconsistent or non-spec-compliant instances.
  *
- * If you end up using this builder, please file an issue with your use-case in kotlinx.serialization issue tracker.
+ * If you end up using this builder, please file an issue with your use-case to the kotlinx.serialization issue tracker.
  */
 @InternalSerializationApi
-@OptIn(ExperimentalSerializationApi::class)
 public fun buildSerialDescriptor(
     serialName: String,
     kind: SerialKind,
@@ -152,14 +147,32 @@ public fun buildSerialDescriptor(
 
 /**
  * Retrieves descriptor of type [T] using reified [serializer] function.
+ *
+ * Example:
+ * ```
+ * serialDescriptor<List<String>>() // Returns kotlin.collections.ArrayList(PrimitiveDescriptor(kotlin.String))
+ * ```
  */
 public inline fun <reified T> serialDescriptor(): SerialDescriptor = serializer<T>().descriptor
 
 /**
- * Retrieves descriptor of type associated with the given [KType][type]
+ * Retrieves descriptor of a type associated with the given [KType][type].
+ *
+ * Example:
+ * ```
+ * val type = typeOf<List<String>>()
+ *
+ * serialDescriptor(type) // Returns kotlin.collections.ArrayList(PrimitiveDescriptor(kotlin.String))
+ * ```
  */
 public fun serialDescriptor(type: KType): SerialDescriptor = serializer(type).descriptor
 
+/* The rest of the functions intentionally left experimental for later stabilization
+ It is unclear whether they should be left as-is,
+ or moved to ClassSerialDescriptorBuilder (because this is the main place for them to be used),
+ or simply deprecated in favor of ListSerializer(Element.serializer()).descriptor
+*/
+
 /**
  * Creates a descriptor for the type `List<T>` where `T` is the type associated with [elementDescriptor].
  */
@@ -227,9 +240,10 @@ public val SerialDescriptor.nullable: SerialDescriptor
  * Returns non-nullable serial descriptor for the type if this descriptor has been auto-generated (plugin
  * generated descriptors) or created with `.nullable` extension on a descriptor or serializer.
  *
- * Otherwise, returns this.
+ * Otherwise, returns `this`.
  *
- * It may return nullable descriptor if this descriptor has been created manually as nullable by directly implementing SerialDescriptor interface.
+ * It may return a nullable descriptor
+ * if `this` descriptor has been created manually as nullable by directly implementing SerialDescriptor interface.
  *
  * @see SerialDescriptor.nullable
  * @see KSerializer.nullable
diff --git a/core/commonMain/src/kotlinx/serialization/descriptors/SerialKinds.kt b/core/commonMain/src/kotlinx/serialization/descriptors/SerialKinds.kt
index 5f7881aa..93ce9270 100644
--- a/core/commonMain/src/kotlinx/serialization/descriptors/SerialKinds.kt
+++ b/core/commonMain/src/kotlinx/serialization/descriptors/SerialKinds.kt
@@ -25,7 +25,6 @@ import kotlinx.serialization.modules.*
  * as a single `Long` value, its descriptor should have [PrimitiveKind.LONG] without nested elements even though the class itself
  * represents a structure with two primitive fields.
  */
-@ExperimentalSerializationApi
 public sealed class SerialKind {
 
     /**
@@ -37,7 +36,6 @@ public sealed class SerialKind {
      *
      * Corresponding encoder and decoder methods are [Encoder.encodeEnum] and [Decoder.decodeEnum].
      */
-    @ExperimentalSerializationApi
     public object ENUM : SerialKind()
 
     /**
@@ -50,7 +48,6 @@ public sealed class SerialKind {
      * However, if possible options are known statically (e.g. for sealed classes), they can be
      * enumerated in child descriptors similarly to [ENUM].
      */
-    @ExperimentalSerializationApi
     public object CONTEXTUAL : SerialKind()
 
     override fun toString(): String {
@@ -85,7 +82,6 @@ public sealed class SerialKind {
  * For the `Color` example, represented as single [Int], its descriptor should have [INT] kind, zero elements and serial name **not equals**
  * to `kotlin.Int`: `PrimitiveDescriptor("my.package.ColorAsInt", PrimitiveKind.INT)`
  */
-@OptIn(ExperimentalSerializationApi::class) // May be @Experimental, but break clients + makes impossible to use stable PrimitiveSerialDescriptor
 public sealed class PrimitiveKind : SerialKind() {
     /**
      * Primitive kind that represents a boolean `true`/`false` value.
@@ -188,7 +184,6 @@ public sealed class PrimitiveKind : SerialKind() {
  * For example, provided serializer for [Map.Entry] represents it as [Map] type, so it is serialized
  * as `{"actualKey": "actualValue"}` map directly instead of `{"key": "actualKey", "value": "actualValue"}`
  */
-@ExperimentalSerializationApi
 public sealed class StructureKind : SerialKind() {
 
     /**
@@ -239,7 +234,7 @@ public sealed class StructureKind : SerialKind() {
  * bounded and sealed polymorphism common property: not knowing the actual type statically and requiring
  * formats to additionally encode it.
  */
-@ExperimentalSerializationApi
+@ExperimentalSerializationApi // Intentionally left experimental to sort out things with buildSerialDescriptor(PolymorphicKind.SEALED)
 public sealed class PolymorphicKind : SerialKind() {
     /**
      * Sealed kind represents Kotlin sealed classes, where all subclasses are known statically at the moment of declaration.
diff --git a/core/commonMain/src/kotlinx/serialization/encoding/Decoding.kt b/core/commonMain/src/kotlinx/serialization/encoding/Decoding.kt
index 75bf37f2..dba56244 100644
--- a/core/commonMain/src/kotlinx/serialization/encoding/Decoding.kt
+++ b/core/commonMain/src/kotlinx/serialization/encoding/Decoding.kt
@@ -52,11 +52,17 @@ import kotlinx.serialization.modules.*
  * (`{` or `[`, depending on the descriptor kind), returning the [CompositeDecoder] that is aware of colon separator,
  * that should be read after each key-value pair, whilst [CompositeDecoder.endStructure] will parse a closing bracket.
  *
- * ### Exception guarantees.
- * For the regular exceptions, such as invalid input, missing control symbols or attributes and unknown symbols,
+ * ### Exception guarantees
+ *
+ * For the regular exceptions, such as invalid input, missing control symbols or attributes, and unknown symbols,
  * [SerializationException] can be thrown by any decoder methods. It is recommended to declare a format-specific
  * subclass of [SerializationException] and throw it.
  *
+ * ### Exception safety
+ *
+ * In general, catching [SerializationException] from any of `decode*` methods is not allowed and produces unspecified behavior.
+ * After thrown exception, the current decoder is left in an arbitrary state, no longer suitable for further decoding.
+ *
  * ### Format encapsulation
  *
  * For example, for the following deserializer:
@@ -79,11 +85,6 @@ import kotlinx.serialization.modules.*
  * }
  * ```
  *
- * ### Exception safety
- *
- * In general, catching [SerializationException] from any of `decode*` methods is not allowed and produces unspecified behaviour.
- * After thrown exception, current decoder is left in an arbitrary state, no longer suitable for further decoding.
- *
  * This deserializer does not know anything about the underlying data and will work with any properly-implemented decoder.
  * JSON, for example, parses an opening bracket `{` during the `beginStructure` call, checks that the next key
  * after this bracket is `stringValue` (using the descriptor), returns the value after the colon as string value
@@ -358,7 +359,7 @@ public interface CompositeDecoder {
      * Sequential decoding is a performance optimization for formats with strictly ordered schema,
      * usually binary ones. Regular formats such as JSON or ProtoBuf cannot use this optimization,
      * because e.g. in the latter example, the same data can be represented both as
-     * `{"i": 1, "d": 1.0}`"` and `{"d": 1.0, "i": 1}` (thus, unordered).
+     * `{"i": 1, "d": 1.0}` and `{"d": 1.0, "i": 1}` (thus, unordered).
      */
     @ExperimentalSerializationApi
     public fun decodeSequentially(): Boolean = false
diff --git a/core/commonMain/src/kotlinx/serialization/encoding/Encoding.kt b/core/commonMain/src/kotlinx/serialization/encoding/Encoding.kt
index 76acbf90..ee63bff3 100644
--- a/core/commonMain/src/kotlinx/serialization/encoding/Encoding.kt
+++ b/core/commonMain/src/kotlinx/serialization/encoding/Encoding.kt
@@ -51,11 +51,17 @@ import kotlinx.serialization.modules.*
  * (`{` or `[`, depending on the descriptor kind), returning the [CompositeEncoder] that is aware of colon separator,
  * that should be appended between each key-value pair, whilst [CompositeEncoder.endStructure] will write a closing bracket.
  *
- * ### Exception guarantees.
+ * ### Exception guarantees
+ *
  * For the regular exceptions, such as invalid input, conflicting serial names,
  * [SerializationException] can be thrown by any encoder methods.
  * It is recommended to declare a format-specific subclass of [SerializationException] and throw it.
  *
+ * ### Exception safety
+ *
+ * In general, catching [SerializationException] from any of `encode*` methods is not allowed and produces unspecified behaviour.
+ * After thrown exception, the current encoder is left in an arbitrary state, no longer suitable for further encoding.
+ *
  * ### Format encapsulation
  *
  * For example, for the following serializer:
@@ -83,11 +89,6 @@ import kotlinx.serialization.modules.*
  * machinery could be completely different.
  * In any case, all these parsing details are encapsulated by an encoder.
  *
- * ### Exception safety
- *
- * In general, catching [SerializationException] from any of `encode*` methods is not allowed and produces unspecified behaviour.
- * After thrown exception, current encoder is left in an arbitrary state, no longer suitable for further encoding.
- *
  * ### Encoder implementation.
  *
  * While being strictly typed, an underlying format can transform actual types in the way it wants.
diff --git a/core/commonMain/src/kotlinx/serialization/internal/Primitives.kt b/core/commonMain/src/kotlinx/serialization/internal/Primitives.kt
index 2eaf5b5c..95108de8 100644
--- a/core/commonMain/src/kotlinx/serialization/internal/Primitives.kt
+++ b/core/commonMain/src/kotlinx/serialization/internal/Primitives.kt
@@ -37,15 +37,15 @@ internal class PrimitiveSerialDescriptor(
         return false
     }
     override fun hashCode() = serialName.hashCode() + 31 * kind.hashCode()
-    private fun error(): Nothing = throw IllegalStateException("Primitive descriptor does not have elements")
+    private fun error(): Nothing = throw IllegalStateException("Primitive descriptor $serialName does not have elements")
 }
 
 internal fun PrimitiveDescriptorSafe(serialName: String, kind: PrimitiveKind): SerialDescriptor {
-    checkName(serialName)
+    checkNameIsNotAPrimitive(serialName)
     return PrimitiveSerialDescriptor(serialName, kind)
 }
 
-private fun checkName(serialName: String) {
+internal fun checkNameIsNotAPrimitive(serialName: String) {
     val values = BUILTIN_SERIALIZERS.values
     for (primitive in values) {
         val primitiveName = primitive.descriptor.serialName
diff --git a/core/commonMain/src/kotlinx/serialization/modules/SerializersModuleBuilders.kt b/core/commonMain/src/kotlinx/serialization/modules/SerializersModuleBuilders.kt
index 451e3268..6bb70e38 100644
--- a/core/commonMain/src/kotlinx/serialization/modules/SerializersModuleBuilders.kt
+++ b/core/commonMain/src/kotlinx/serialization/modules/SerializersModuleBuilders.kt
@@ -192,39 +192,30 @@ public class SerializersModuleBuilder @PublishedApi internal constructor() : Ser
         concreteSerializer: KSerializer<Sub>,
         allowOverwrite: Boolean = false
     ) {
-        // Check for overwrite
         val name = concreteSerializer.descriptor.serialName
         val baseClassSerializers = polyBase2Serializers.getOrPut(baseClass, ::hashMapOf)
-        val previousSerializer = baseClassSerializers[concreteClass]
         val names = polyBase2NamedSerializers.getOrPut(baseClass, ::hashMapOf)
-        if (allowOverwrite) {
-            // Remove previous serializers from name mapping
-            if (previousSerializer != null) {
-                names.remove(previousSerializer.descriptor.serialName)
-            }
-            // Update mappings
-            baseClassSerializers[concreteClass] = concreteSerializer
-            names[name] = concreteSerializer
-            return
-        }
-        // Overwrite prohibited
-        if (previousSerializer != null) {
-            if (previousSerializer != concreteSerializer) {
-                throw SerializerAlreadyRegisteredException(baseClass, concreteClass)
-            } else {
-                // Cleanup name mapping
-                names.remove(previousSerializer.descriptor.serialName)
-            }
+
+        // Check KClass conflict
+        val previousSerializer = baseClassSerializers[concreteClass]
+        if (previousSerializer != null && previousSerializer != concreteSerializer) {
+            if (allowOverwrite) names.remove(previousSerializer.descriptor.serialName)
+            else throw SerializerAlreadyRegisteredException(baseClass, concreteClass)
         }
+
+        // Check SerialName conflict
         val previousByName = names[name]
-        if (previousByName != null) {
-            val conflictingClass = polyBase2Serializers[baseClass]!!.asSequence().find { it.value === previousByName }
-            throw IllegalArgumentException(
-                "Multiple polymorphic serializers for base class '$baseClass' " +
-                        "have the same serial name '$name': '$concreteClass' and '$conflictingClass'"
+        if (previousByName != null && previousByName != concreteSerializer) {
+            val previousClass = baseClassSerializers.asSequence().find { it.value === previousByName }?.key
+                ?: error("Name $name is registered in the module but no Kotlin class is associated with it.")
+
+            if (allowOverwrite) baseClassSerializers.remove(previousClass)
+            else throw IllegalArgumentException(
+                "Multiple polymorphic serializers in a scope of '$baseClass' " +
+                        "have the same serial name '$name': $concreteSerializer for '$concreteClass' and $previousByName for '$previousClass'"
             )
         }
-        // Overwrite if no conflicts
+
         baseClassSerializers[concreteClass] = concreteSerializer
         names[name] = concreteSerializer
     }
diff --git a/core/commonTest/src/kotlinx/serialization/BasicTypesSerializationTest.kt b/core/commonTest/src/kotlinx/serialization/BasicTypesSerializationTest.kt
index caa2768f..859818aa 100644
--- a/core/commonTest/src/kotlinx/serialization/BasicTypesSerializationTest.kt
+++ b/core/commonTest/src/kotlinx/serialization/BasicTypesSerializationTest.kt
@@ -198,7 +198,6 @@ class BasicTypesSerializationTest {
         // impossible to deserialize Nothing
         assertFailsWith(SerializationException::class, "'kotlin.Nothing' does not have instances") {
             val inp = KeyValueInput(Parser(StringReader("42")))
-            @Suppress("IMPLICIT_NOTHING_TYPE_ARGUMENT_IN_RETURN_POSITION")
             inp.decodeSerializableValue(NothingSerializer())
         }
 
diff --git a/core/commonTest/src/kotlinx/serialization/WrappedSerialDescriptorTest.kt b/core/commonTest/src/kotlinx/serialization/WrappedSerialDescriptorTest.kt
index d92495b5..31303af1 100644
--- a/core/commonTest/src/kotlinx/serialization/WrappedSerialDescriptorTest.kt
+++ b/core/commonTest/src/kotlinx/serialization/WrappedSerialDescriptorTest.kt
@@ -58,4 +58,21 @@ class WrappedSerialDescriptorTest {
     fun testWrappedComplexClass() {
         checkWrapped(ComplexType.serializer().descriptor, "WrappedComplexType")
     }
-}
\ No newline at end of file
+
+    @Test
+    fun testWrappedPrimitive() {
+        checkWrapped(Int.serializer().descriptor, "MyInt")
+    }
+
+    @Test
+    fun testWrappedPrimitiveContract() {
+        assertFails { SerialDescriptor("   ", ComplexType.serializer().descriptor) }
+        assertFails {
+            SerialDescriptor(
+                SimpleType.serializer().descriptor.serialName,
+                SimpleType.serializer().descriptor
+            )
+        }
+        assertFails { SerialDescriptor("kotlin.Int", Int.serializer().descriptor) }
+    }
+}
diff --git a/core/commonTest/src/kotlinx/serialization/modules/ModuleBuildersTest.kt b/core/commonTest/src/kotlinx/serialization/modules/ModuleBuildersTest.kt
index b4122cfd..f231eb05 100644
--- a/core/commonTest/src/kotlinx/serialization/modules/ModuleBuildersTest.kt
+++ b/core/commonTest/src/kotlinx/serialization/modules/ModuleBuildersTest.kt
@@ -10,6 +10,11 @@ import kotlinx.serialization.*
 import kotlinx.serialization.builtins.*
 import kotlinx.serialization.descriptors.*
 import kotlinx.serialization.encoding.*
+import kotlinx.serialization.test.Platform
+import kotlinx.serialization.test.assertFailsWithMessage
+import kotlinx.serialization.test.currentPlatform
+import kotlinx.serialization.test.isJs
+import kotlinx.serialization.test.isJvm
 import kotlin.reflect.*
 import kotlin.test.*
 
@@ -176,6 +181,10 @@ class ModuleBuildersTest {
     @SerialName("C")
     class C
 
+    @Serializable
+    @SerialName("C")
+    class C2
+
     @Serializer(forClass = C::class)
     object CSerializer : KSerializer<C> {
         override val descriptor: SerialDescriptor = buildSerialDescriptor("AnotherName", StructureKind.OBJECT)
@@ -206,6 +215,27 @@ class ModuleBuildersTest {
         assertNull(result.getPolymorphic(Any::class, serializedClassName = "AnotherName"))
     }
 
+    @Test
+    fun testOverwriteWithDifferentClass() {
+        val c1 = SerializersModule {
+            polymorphic<Any>(Any::class) {
+                subclass(C::class)
+            }
+        }
+        val c2 = SerializersModule {
+            polymorphic<Any>(Any::class) {
+                subclass(C2::class)
+            }
+        }
+        val classNameMsg = if (currentPlatform == Platform.JS || currentPlatform == Platform.WASM) "class Any" else "class kotlin.Any"
+        assertFailsWithMessage<IllegalArgumentException>("Multiple polymorphic serializers in a scope of '$classNameMsg' have the same serial name 'C'") { c1 + c2 }
+        val module = c1 overwriteWith c2
+        // C should not be registered at all, C2 should be registered both under "C" and C2::class
+        assertEquals(C2.serializer(), module.getPolymorphic(Any::class, serializedClassName = "C"))
+        assertNull(module.getPolymorphic(Any::class, C()))
+        assertEquals(C2.serializer(), module.getPolymorphic(Any::class, C2()))
+    }
+
     @Test
     fun testOverwriteWithSameSerialName() {
         val m1 = SerializersModule {
diff --git a/core/commonTest/src/kotlinx/serialization/test/TestHelpers.kt b/core/commonTest/src/kotlinx/serialization/test/TestHelpers.kt
index 86974506..4d572b3e 100644
--- a/core/commonTest/src/kotlinx/serialization/test/TestHelpers.kt
+++ b/core/commonTest/src/kotlinx/serialization/test/TestHelpers.kt
@@ -38,3 +38,7 @@ inline fun jvmOnly(test: () -> Unit) {
     if (isJvm()) test()
 }
 
+inline fun <reified T : Throwable> assertFailsWithMessage(message: String, block: () -> Unit) {
+    val exception = assertFailsWith(T::class, null, block)
+    assertTrue(exception.message!!.contains(message), "Expected message '${exception.message}' to contain substring '$message'")
+}
diff --git a/docs/basic-serialization.md b/docs/basic-serialization.md
index ce98f493..95904adb 100644
--- a/docs/basic-serialization.md
+++ b/docs/basic-serialization.md
@@ -411,8 +411,8 @@ Attempts to explicitly specify its value in the serial format, even if the speci
 value is equal to the default one, produces the following exception.
 
 ```text
-Exception in thread "main" kotlinx.serialization.json.internal.JsonDecodingException: Unexpected JSON token at offset 42: Encountered an unknown key 'language' at path: $.name
-Use 'ignoreUnknownKeys = true' in 'Json {}' builder to ignore unknown keys.
+Exception in thread "main" kotlinx.serialization.json.internal.JsonDecodingException: Encountered an unknown key 'language' at offset 42 at path: $
+Use 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys.
 ```
 
 <!--- TEST LINES_START -->
diff --git a/docs/building.md b/docs/building.md
index 313bf8a1..e49bb7d0 100644
--- a/docs/building.md
+++ b/docs/building.md
@@ -31,7 +31,7 @@ dependencies {
 ```
 
 To use snapshot version of compiler (if you have built and installed it from sources), use flag `-Pbootstrap`.
-If you have built both Kotlin and Kotlin/Native compilers, set `KONAN_LOCAL_DIST` environment property to the path with Kotlin/Native distribution
+If you have built both Kotlin and Kotlin/Native compilers, set `kotlin.native.home` property in `gradle.properties` to the path with Kotlin/Native distribution
 (usually `kotlin-native/dist` folder inside Kotlin project).
 
 The `master` and `dev` branches of the library should be binary compatible with the latest released compiler plugin. In case you want to test some new features from other branches,
diff --git a/docs/json.md b/docs/json.md
index 234d7c92..6e0610cf 100644
--- a/docs/json.md
+++ b/docs/json.md
@@ -13,6 +13,7 @@ In this chapter, we'll walk through features of [JSON](https://www.json.org/json
   * [Pretty printing](#pretty-printing)
   * [Lenient parsing](#lenient-parsing)
   * [Ignoring unknown keys](#ignoring-unknown-keys)
+  * [Ignoring unknown keys per class](#ignoring-unknown-keys-per-class)
   * [Alternative Json names](#alternative-json-names)
   * [Encoding defaults](#encoding-defaults)
   * [Explicit nulls](#explicit-nulls)
@@ -164,6 +165,44 @@ Project(name=kotlinx.serialization)
 
 <!--- TEST -->
 
+### Ignoring unknown keys per class
+
+Sometimes, for cleaner and safer API, it is desirable to ignore unknown properties only for specific classes.
+In that case, you can use [JsonIgnoreUnknownKeys] annotation on such classes while leaving global [ignoreUnknownKeys][JsonBuilder.ignoreUnknownKeys] setting
+turned off:
+
+```kotlin
+@OptIn(ExperimentalSerializationApi::class) // JsonIgnoreUnknownKeys is an experimental annotation for now
+@Serializable
+@JsonIgnoreUnknownKeys
+data class Outer(val a: Int, val inner: Inner)
+
+@Serializable
+data class Inner(val x: String)
+
+fun main() {
+    // 1
+    println(Json.decodeFromString<Outer>("""{"a":1,"inner":{"x":"value"},"unknownKey":42}"""))
+    println()
+    // 2
+    println(Json.decodeFromString<Outer>("""{"a":1,"inner":{"x":"value","unknownKey":"unknownValue"}}"""))
+}
+```
+
+> You can get the full code [here](../guide/example/example-json-04.kt).
+
+Line (1) decodes successfully despite "unknownKey" in `Outer`, because annotation is present on the class. 
+However, line (2) throws `SerializationException` because there is no "unknownKey" property in `Inner`:
+
+```text
+Outer(a=1, inner=Inner(x=value))
+
+Exception in thread "main" kotlinx.serialization.json.internal.JsonDecodingException: Encountered an unknown key 'unknownKey' at offset 29 at path: $.inner
+Use 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys.
+```
+
+<!--- TEST LINES_START-->
+
 ### Alternative Json names
 
 It's not a rare case when JSON fields are renamed due to a schema version change.
@@ -184,7 +223,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-04.kt).
+> You can get the full code [here](../guide/example/example-json-05.kt).
 
 As you can see, both `name` and `title` Json fields correspond to `name` property:
 
@@ -222,7 +261,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-05.kt).
+> You can get the full code [here](../guide/example/example-json-06.kt).
 
 It produces the following output which encodes all the property values including the default ones:
 
@@ -261,7 +300,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-06.kt).
+> You can get the full code [here](../guide/example/example-json-07.kt).
 
 As you can see, `version`, `website` and `description` fields are not present in output JSON on the first line.
 After decoding, the missing nullable property `website` without a default values has received a `null` value,
@@ -319,7 +358,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-07.kt).
+> You can get the full code [here](../guide/example/example-json-08.kt).
 
 The invalid `null` value for the `language` property was coerced into the default value:
 
@@ -348,7 +387,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-08.kt).
+> You can get the full code [here](../guide/example/example-json-09.kt).
 
 Despite that we do not have `Color.pink` and `Color.purple` colors, `decodeFromString` function returns successfully:
 
@@ -384,7 +423,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-09.kt).
+> You can get the full code [here](../guide/example/example-json-10.kt).
 
 The map with structured keys gets represented as JSON array with the following items: `[key1, value1, key2, value2,...]`.
 
@@ -415,7 +454,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-10.kt).
+> You can get the full code [here](../guide/example/example-json-11.kt).
 
 This example produces the following non-stardard JSON output, yet it is a widely used encoding for
 special values in JVM world:
@@ -449,7 +488,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-11.kt).
+> You can get the full code [here](../guide/example/example-json-12.kt).
 
 In combination with an explicitly specified [SerialName] of the class it provides full
 control over the resulting JSON object:
@@ -506,7 +545,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-12.kt).
+> You can get the full code [here](../guide/example/example-json-13.kt).
 
 As you can see, discriminator from the `Base` class is used:
 
@@ -543,7 +582,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-13.kt).
+> You can get the full code [here](../guide/example/example-json-14.kt).
 
 Note that it would be impossible to deserialize this output back with kotlinx.serialization.
 
@@ -579,7 +618,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-14.kt).
+> You can get the full code [here](../guide/example/example-json-15.kt).
 
 It affects serial names as well as alternative names specified with [JsonNames] annotation, so both values are successfully decoded:
 
@@ -612,7 +651,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-15.kt).
+> You can get the full code [here](../guide/example/example-json-16.kt).
 
 As you can see, both serialization and deserialization work as if all serial names are transformed from camel case to snake case:
 
@@ -710,7 +749,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-16.kt)
+> You can get the full code [here](../guide/example/example-json-17.kt)
 
 ```text
 {"base64Input":"Zm9vIHN0cmluZw=="}
@@ -752,7 +791,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-17.kt).
+> You can get the full code [here](../guide/example/example-json-18.kt).
 
 A `JsonElement` prints itself as a valid JSON:
 
@@ -795,7 +834,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-18.kt).
+> You can get the full code [here](../guide/example/example-json-19.kt).
 
 The above example sums `votes` in all objects in the `forks` array, ignoring the objects that have no `votes`:
 
@@ -835,7 +874,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-19.kt).
+> You can get the full code [here](../guide/example/example-json-20.kt).
 
 As a result, you get a proper JSON string:
 
@@ -864,7 +903,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-20.kt).
+> You can get the full code [here](../guide/example/example-json-21.kt).
 
 The result is exactly what you would expect:
 
@@ -910,7 +949,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-21.kt).
+> You can get the full code [here](../guide/example/example-json-22.kt).
 
 Even though `pi` was defined as a number with 30 decimal places, the resulting JSON does not reflect this. 
 The [Double] value is truncated to 15 decimal places, and the String is wrapped in quotes - which is not a JSON number.
@@ -951,7 +990,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-22.kt).
+> You can get the full code [here](../guide/example/example-json-23.kt).
 
 `pi_literal` now accurately matches the value defined.
 
@@ -991,7 +1030,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-23.kt).
+> You can get the full code [here](../guide/example/example-json-24.kt).
 
 The exact value of `pi` is decoded, with all 30 decimal places of precision that were in the source JSON.
 
@@ -1014,7 +1053,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-24.kt).
+> You can get the full code [here](../guide/example/example-json-25.kt).
 
 ```text
 Exception in thread "main" kotlinx.serialization.json.internal.JsonEncodingException: Creating a literal unquoted value of 'null' is forbidden. If you want to create JSON null literal, use JsonNull object, otherwise, use JsonPrimitive
@@ -1090,7 +1129,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-25.kt).
+> You can get the full code [here](../guide/example/example-json-26.kt).
 
 The output shows that both cases are correctly deserialized into a Kotlin [List].
 
@@ -1142,7 +1181,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-26.kt).
+> You can get the full code [here](../guide/example/example-json-27.kt).
 
 You end up with a single JSON object, not an array with one element:
 
@@ -1187,7 +1226,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-27.kt).
+> You can get the full code [here](../guide/example/example-json-28.kt).
 
 See the effect of the custom serializer:
 
@@ -1260,7 +1299,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-28.kt).
+> You can get the full code [here](../guide/example/example-json-29.kt).
 
 No class discriminator is added in the JSON output:
 
@@ -1312,7 +1351,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-29.kt).
+> You can get the full code [here](../guide/example/example-json-30.kt).
 
 `BasicProject` will be printed to the output:
 
@@ -1406,7 +1445,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-30.kt).
+> You can get the full code [here](../guide/example/example-json-31.kt).
 
 This gives you fine-grained control on the representation of the `Response` class in the JSON output:
 
@@ -1471,7 +1510,7 @@ fun main() {
 }
 ```
 
-> You can get the full code [here](../guide/example/example-json-31.kt).
+> You can get the full code [here](../guide/example/example-json-32.kt).
 
 ```text
 UnknownProject(name=example, details={"type":"unknown","maintainer":"Unknown","license":"Apache 2.0"})
@@ -1517,6 +1556,7 @@ The next chapter covers [Alternative and custom formats (experimental)](formats.
 [JsonBuilder.prettyPrint]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-builder/pretty-print.html
 [JsonBuilder.isLenient]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-builder/is-lenient.html
 [JsonBuilder.ignoreUnknownKeys]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-builder/ignore-unknown-keys.html
+[JsonIgnoreUnknownKeys]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-ignore-unknown-keys/index.html
 [JsonNames]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-names/index.html
 [JsonBuilder.useAlternativeNames]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-builder/use-alternative-names.html
 [JsonBuilder.encodeDefaults]: https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/-json-builder/encode-defaults.html
diff --git a/docs/serialization-guide.md b/docs/serialization-guide.md
index 01ada5fa..ce7aeef3 100644
--- a/docs/serialization-guide.md
+++ b/docs/serialization-guide.md
@@ -114,6 +114,7 @@ Once the project is set up, we can start serializing some classes.
   * <a name='pretty-printing'></a>[Pretty printing](json.md#pretty-printing)
   * <a name='lenient-parsing'></a>[Lenient parsing](json.md#lenient-parsing)
   * <a name='ignoring-unknown-keys'></a>[Ignoring unknown keys](json.md#ignoring-unknown-keys)
+  * <a name='ignoring-unknown-keys-per-class'></a>[Ignoring unknown keys per class](json.md#ignoring-unknown-keys-per-class)
   * <a name='alternative-json-names'></a>[Alternative Json names](json.md#alternative-json-names)
   * <a name='encoding-defaults'></a>[Encoding defaults](json.md#encoding-defaults)
   * <a name='explicit-nulls'></a>[Explicit nulls](json.md#explicit-nulls)
diff --git a/docs/serializers.md b/docs/serializers.md
index 19542cc6..8eb6f046 100644
--- a/docs/serializers.md
+++ b/docs/serializers.md
@@ -247,7 +247,8 @@ import kotlinx.serialization.descriptors.*
 
 ```kotlin
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    // Serial names of descriptors should be unique, this is why we advise including app package in the name.
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
@@ -315,7 +316,7 @@ Deserialization is also straightforward because we implemented the `deserialize`
 
 <!--- INCLUDE 
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
@@ -349,7 +350,7 @@ It also works if we serialize or deserialize a different class with `Color` prop
 
 <!--- INCLUDE 
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
@@ -404,8 +405,9 @@ import kotlinx.serialization.builtins.IntArraySerializer
 
 class ColorIntArraySerializer : KSerializer<Color> {
     private val delegateSerializer = IntArraySerializer()
-    @OptIn(ExperimentalSerializationApi::class)
-    override val descriptor = SerialDescriptor("Color", delegateSerializer.descriptor)
+
+    // Serial names of descriptors should be unique, this is why we advise including app package in the name.
+    override val descriptor = SerialDescriptor("my.app.Color", delegateSerializer.descriptor)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val data = intArrayOf(
@@ -487,7 +489,8 @@ generated [SerialDescriptor] for the surrogate because it should be indistinguis
 
 ```kotlin
 object ColorSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = ColorSurrogate.serializer().descriptor
+    // Serial names of descriptors should be unique, so we cannot use ColorSurrogate.serializer().descriptor directly
+    override val descriptor: SerialDescriptor = SerialDescriptor("my.app.Color", ColorSurrogate.serializer().descriptor)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val surrogate = ColorSurrogate((value.rgb shr 16) and 0xff, (value.rgb shr 8) and 0xff, value.rgb and 0xff)
@@ -542,7 +545,7 @@ for the corresponding fields by their type. The order of elements is important.
 
 ```kotlin
     override val descriptor: SerialDescriptor =
-        buildClassSerialDescriptor("Color") {
+        buildClassSerialDescriptor("my.app.Color") {
             element<Int>("r")
             element<Int>("g")
             element<Int>("b")
@@ -633,7 +636,7 @@ The plugin-generated serializers are actually conceptually similar to the code b
 object ColorAsObjectSerializer : KSerializer<Color> {
 
     override val descriptor: SerialDescriptor =
-        buildClassSerialDescriptor("Color") {
+        buildClassSerialDescriptor("my.app.Color") {
             element<Int>("r")
             element<Int>("g")
             element<Int>("b")
@@ -712,7 +715,8 @@ import java.text.SimpleDateFormat
   
 ```kotlin
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    // Serial names of descriptors should be unique, so choose app-specific name in case some library also would declare a serializer for Date.
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
@@ -757,7 +761,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
@@ -798,7 +802,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
@@ -842,7 +846,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
@@ -882,13 +886,13 @@ import java.util.TimeZone
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("DateAsLong", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
 
 object DateAsSimpleTextSerializer: KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("DateAsSimpleText", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsSimpleText", PrimitiveKind.LONG)
     private val format = SimpleDateFormat("yyyy-MM-dd").apply {
         // Here we explicitly set time zone to UTC so output for this sample remains locale-independent.
         // Depending on your needs, you may have to adjust or remove this line.
@@ -946,7 +950,7 @@ serialization, delegating everything to the underlying serializer of its `data`
 
 ```kotlin
 class BoxSerializer<T>(private val dataSerializer: KSerializer<T>) : KSerializer<Box<T>> {
-    override val descriptor: SerialDescriptor = dataSerializer.descriptor
+    override val descriptor: SerialDescriptor = SerialDescriptor("my.app.Box", dataSerializer.descriptor)
     override fun serialize(encoder: Encoder, value: Box<T>) = dataSerializer.serialize(encoder, value.contents)
     override fun deserialize(decoder: Decoder) = Box(dataSerializer.deserialize(decoder))
 }
@@ -1007,7 +1011,7 @@ An example of using two serializers at once:
 
 <!--- INCLUDE
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
@@ -1098,7 +1102,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
diff --git a/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborDecoder.kt b/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborDecoder.kt
index c30c7654..13a773f3 100644
--- a/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborDecoder.kt
+++ b/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborDecoder.kt
@@ -25,9 +25,10 @@ import kotlinx.serialization.encoding.*
  * ```
  */
 @ExperimentalSerializationApi
+@SubclassOptInRequired(SealedSerializationApi::class)
 public interface CborDecoder : Decoder {
     /**
      * Exposes the current [Cbor] instance and all its configuration flags. Useful for low-level custom serializers.
      */
     public val cbor: Cbor
-}
\ No newline at end of file
+}
diff --git a/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborEncoder.kt b/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborEncoder.kt
index 929a753f..7cfead42 100644
--- a/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborEncoder.kt
+++ b/formats/cbor/commonMain/src/kotlinx/serialization/cbor/CborEncoder.kt
@@ -25,9 +25,10 @@ import kotlinx.serialization.encoding.*
  * ```
  */
 @ExperimentalSerializationApi
+@SubclassOptInRequired(SealedSerializationApi::class)
 public interface CborEncoder : Encoder {
     /**
      * Exposes the current [Cbor] instance and all its configuration flags. Useful for low-level custom serializers.
      */
     public val cbor: Cbor
-}
\ No newline at end of file
+}
diff --git a/formats/cbor/commonMain/src/kotlinx/serialization/cbor/internal/Decoder.kt b/formats/cbor/commonMain/src/kotlinx/serialization/cbor/internal/Decoder.kt
index 174f8fc2..88075db2 100644
--- a/formats/cbor/commonMain/src/kotlinx/serialization/cbor/internal/Decoder.kt
+++ b/formats/cbor/commonMain/src/kotlinx/serialization/cbor/internal/Decoder.kt
@@ -426,9 +426,11 @@ internal class CborParser(private val input: ByteArrayInput, private val verifyO
             } else {
                 val header = curByte and 0b111_00000
                 val length = elementLength()
-                if (header == HEADER_ARRAY || header == HEADER_MAP) {
+                if (header == HEADER_TAG) {
+                    readNumber()
+                } else if (header == HEADER_ARRAY || header == HEADER_MAP) {
                     if (length > 0) lengthStack.add(length)
-                    processTags(tags)
+                    else prune(lengthStack) // empty map or array automatically completes
                 } else {
                     input.skip(length)
                     prune(lengthStack)
diff --git a/formats/cbor/commonTest/src/kotlinx/serialization/cbor/CborSkipTagAndEmptyTest.kt b/formats/cbor/commonTest/src/kotlinx/serialization/cbor/CborSkipTagAndEmptyTest.kt
new file mode 100644
index 00000000..842204e0
--- /dev/null
+++ b/formats/cbor/commonTest/src/kotlinx/serialization/cbor/CborSkipTagAndEmptyTest.kt
@@ -0,0 +1,60 @@
+package kotlinx.serialization.cbor
+
+import kotlinx.serialization.*
+import kotlin.test.*
+
+class CborSkipTagAndEmptyTest {
+
+    /**
+     * A3                                      # map(3)
+     *    67                                   # text(7)
+     *       76657273696F6E                    # ""version""
+     *    63                                   # text(3)
+     *       312E30                            # ""1.0""
+     *    69                                   # text(9)
+     *       646F63756D656E7473                # ""documents""
+     *    81                                   # array(1)
+     *       A1                                # map(1)
+     *          6C                             # text(12)
+     *             6465766963655369676E6564    # ""deviceSigned""
+     *          A2                             # map(2)
+     *             6A                          # text(10)
+     *                6E616D65537061636573     # ""nameSpaces""
+     *             D8 18                       # tag(24) <------------------- Testing this skips properly
+     *                41                       # bytes(1)
+     *                   A0                    # ""\xA0""
+     *             6A                          # text(10)
+     *                64657669636541757468     # ""deviceAuth""
+     *             A1                          # map(1)
+     *                69                       # text(9)
+     *                   6465766963654D6163    # ""deviceMac""
+     *                84                       # array(4)
+     *                   43                    # bytes(3)
+     *                      A10105
+     *                   A0                    # map(0) <------------------- Testing this skips properly
+     *                   F6                    # primitive(22)
+     *                   58 20                 # bytes(32)
+     *                      E99521A85AD7891B806A07F8B5388A332D92C189A7BF293EE1F543405AE6824D
+     *    66                                   # text(6)
+     *       737461747573                      # ""status""
+     *    00                                   # unsigned(0)
+     */
+    private val referenceHexString = "A36776657273696F6E63312E3069646F63756D656E747381A16C6465766963655369676E6564A26A6E616D65537061636573D81841A06A64657669636541757468A1696465766963654D61638443A10105A0F65820E99521A85AD7891B806A07F8B5388A332D92C189A7BF293EE1F543405AE6824D6673746174757300"
+
+    @Test
+    fun deserializesCorrectly() {
+        // Specifically, skipping keys with descendants that contain tags and empty maps
+        val cbor = Cbor{
+            ignoreUnknownKeys = true
+        }
+        // Prior exception:
+        // Field 'status' is required for type with serial name 'kotlinx.serialization.cbor.CborSkipTagAndEmptyTest.DataClass', but it was missing
+        val target = cbor.decodeFromHexString(DataClass.serializer(), referenceHexString)
+        assertEquals(0, target.status)
+    }
+
+    @Serializable
+    data class DataClass(
+        val status: Int,
+    )
+}
\ No newline at end of file
diff --git a/formats/hocon/build.gradle.kts b/formats/hocon/build.gradle.kts
index e2670528..66b806f0 100644
--- a/formats/hocon/build.gradle.kts
+++ b/formats/hocon/build.gradle.kts
@@ -21,7 +21,7 @@ kotlin {
             languageVersion = KotlinVersion.fromVersion(overriddenLanguageVersion!!)
             freeCompilerArgs.add("-Xsuppress-version-warnings")
         }
-        freeCompilerArgs.add("-Xjdk-release=1.8")
+        freeCompilerArgs.addAll("-Xjdk-release=1.8", "-Xjvm-default=all-compatibility")
     }
 
     sourceSets.all {
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/SerializersLookupTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/SerializersLookupTest.kt
index f335d0d5..a4c8d356 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/SerializersLookupTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/SerializersLookupTest.kt
@@ -146,8 +146,7 @@ class SerializersLookupTest : JsonTestBase() {
     @OptIn(ExperimentalUuidApi::class)
     fun testLookupUuid() {
         assertSame<KSerializer<*>?>(Uuid.serializer(), serializerOrNull(typeOf<Uuid>()))
-        // TODO: uncomment in 2.1 release
-//        assertSame<KSerializer<*>?>(Uuid.serializer(), serializer<Uuid>())
+        assertSame<KSerializer<*>?>(Uuid.serializer(), serializer<Uuid>())
     }
 
     @Test
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/features/UuidTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/features/UuidTest.kt
index 52f3b13d..a70e110f 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/features/UuidTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/features/UuidTest.kt
@@ -18,19 +18,32 @@ class UuidTest : JsonTestBase() {
         assertJsonFormAndRestored(Uuid.serializer(), uuid, "\"$uuid\"")
     }
 
-    // TODO: write a test without @Contextual after 2.1.0 release
     @Serializable
-    data class Holder(@Contextual val uuid: Uuid)
+    data class Holder(val uuid: Uuid)
+
+    @Serializable
+    data class HolderContextual(@Contextual val uuid: Uuid)
 
     val json = Json { serializersModule = serializersModuleOf(Uuid.serializer()) }
 
     @Test
-    fun testNested() {
+    fun testCompiled() {
         val fixed = Uuid.parse("bc501c76-d806-4578-b45e-97a264e280f1")
         assertJsonFormAndRestored(
             Holder.serializer(),
             Holder(fixed),
             """{"uuid":"bc501c76-d806-4578-b45e-97a264e280f1"}""",
+            Json
+        )
+    }
+
+    @Test
+    fun testContextual() {
+        val fixed = Uuid.parse("bc501c76-d806-4578-b45e-97a264e280f1")
+        assertJsonFormAndRestored(
+            HolderContextual.serializer(),
+            HolderContextual(fixed),
+            """{"uuid":"bc501c76-d806-4578-b45e-97a264e280f1"}""",
             json
         )
     }
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesCompleteTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesCompleteTest.kt
index 96972f92..4a853655 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesCompleteTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesCompleteTest.kt
@@ -1,8 +1,6 @@
 /*
  * Copyright 2017-2021 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
-@file:Suppress("INLINE_CLASSES_NOT_SUPPORTED", "SERIALIZER_NOT_FOUND")
-
 package kotlinx.serialization.features.inline
 
 import kotlinx.serialization.*
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesTest.kt
index f3eb9511..c03183b4 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/features/inline/InlineClassesTest.kt
@@ -2,8 +2,6 @@
  * Copyright 2017-2021 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-@file:Suppress("INLINE_CLASSES_NOT_SUPPORTED", "SERIALIZER_NOT_FOUND")
-
 package kotlinx.serialization.features.inline
 
 import kotlinx.serialization.*
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonElementDecodingTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonElementDecodingTest.kt
index 3cdfa082..efb4d846 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonElementDecodingTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonElementDecodingTest.kt
@@ -3,6 +3,7 @@ package kotlinx.serialization.json
 import kotlinx.serialization.*
 import kotlinx.serialization.descriptors.*
 import kotlinx.serialization.encoding.*
+import kotlinx.serialization.test.*
 import kotlin.test.*
 
 class JsonElementDecodingTest : JsonTestBase() {
@@ -107,4 +108,13 @@ class JsonElementDecodingTest : JsonTestBase() {
         assertJsonFormAndRestored(Wrapper.serializer(), Wrapper(value = JsonNull), """{"value":null}""", noExplicitNullsOrDefaultsJson)
         assertJsonFormAndRestored(Wrapper.serializer(), Wrapper(value = null), """{}""", noExplicitNullsOrDefaultsJson)
     }
+
+    @Test
+    fun testLiteralIncorrectParsing() {
+        val str = """{"a": "3 digit then random string"}"""
+        val obj = Json.decodeFromString<JsonObject>(str)
+        assertFailsWithMessage<NumberFormatException>("Expected input to contain a single valid number") {
+            println(obj.getValue("a").jsonPrimitive.long)
+        }
+    }
 }
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonIgnoreKeysTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonIgnoreKeysTest.kt
new file mode 100644
index 00000000..82f4f239
--- /dev/null
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/json/JsonIgnoreKeysTest.kt
@@ -0,0 +1,53 @@
+/*
+ * Copyright 2017-2024 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
+ */
+
+package kotlinx.serialization.json
+
+import kotlinx.serialization.Serializable
+import kotlinx.serialization.test.checkSerializationException
+import kotlin.test.Test
+import kotlin.test.assertContains
+import kotlin.test.assertContentEquals
+import kotlin.test.assertEquals
+
+class JsonIgnoreKeysTest : JsonTestBase() {
+    val ignoresKeys = Json(default) { ignoreUnknownKeys = true }
+
+    @Serializable
+    class Outer(val a: Int, val inner: Inner)
+
+    @Serializable
+    @JsonIgnoreUnknownKeys
+    class Inner(val x: String)
+
+    @Test
+    fun testIgnoresKeyWhenGlobalSettingNotSet() = parametrizedTest { mode ->
+        val jsonString = """{"a":1,"inner":{"x":"value","unknownKey":"unknownValue"}}"""
+        val result = default.decodeFromString<Outer>(jsonString, mode)
+        assertEquals(1, result.a)
+        assertEquals("value", result.inner.x)
+    }
+
+    @Test
+    fun testThrowsWithoutAnnotationWhenGlobalSettingNotSet() = parametrizedTest { mode ->
+        val jsonString = """{"a":1,"inner":{"x":"value","unknownKey":"unknownValue"}, "b":2}"""
+        checkSerializationException({
+            default.decodeFromString<Outer>(jsonString, mode)
+        }) { msg ->
+            assertContains(
+                msg,
+                if (mode == JsonTestingMode.TREE) "Encountered an unknown key 'b' at element: \$\n"
+                else "Encountered an unknown key 'b' at offset 59 at path: \$\n"
+            )
+        }
+    }
+
+    @Test
+    fun testIgnoresBothKeysWithGlobalSetting() = parametrizedTest { mode ->
+        val jsonString = """{"a":1,"inner":{"x":"value","unknownKey":"unknownValue"}, "b":2}"""
+        val result = ignoresKeys.decodeFromString<Outer>(jsonString, mode)
+        assertEquals(1, result.a)
+        assertEquals("value", result.inner.x)
+    }
+}
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/json/polymorphic/JsonClassDiscriminatorModeTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/json/polymorphic/JsonClassDiscriminatorModeTest.kt
index b2f47137..d55e7559 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/json/polymorphic/JsonClassDiscriminatorModeTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/json/polymorphic/JsonClassDiscriminatorModeTest.kt
@@ -4,7 +4,9 @@
 
 package kotlinx.serialization.json.polymorphic
 
+import kotlinx.serialization.*
 import kotlinx.serialization.json.*
+import kotlinx.serialization.modules.*
 import kotlin.test.*
 
 class ClassDiscriminatorModeAllObjectsTest :
@@ -80,5 +82,44 @@ class ClassDiscriminatorModeNoneTest :
 
     @Test
     fun testNullable() = testNullable("""{"sb":null,"sc":null}""")
+
+    interface CommandType
+
+    @Serializable // For Kotlin/JS
+    enum class Modify : CommandType {
+        CREATE, DELETE
+    }
+
+    @Serializable
+    class Command(val cmd: CommandType)
+
+    @Test
+    fun testNoneModeAllowsPolymorphicEnums() {
+        val module = SerializersModule {
+            polymorphic(CommandType::class) {
+                subclass(Modify::class, Modify.serializer())
+            }
+        }
+        val j = Json(default) { serializersModule = module; classDiscriminatorMode = ClassDiscriminatorMode.NONE }
+        parametrizedTest { mode ->
+            assertEquals("""{"cmd":"CREATE"}""", j.encodeToString(Command(Modify.CREATE), mode))
+        }
+    }
+
+    @Serializable
+    class SomeCommand(val type: String) : CommandType
+
+    @Test
+    fun testNoneModeAllowsDiscriminatorClash() {
+        val module = SerializersModule {
+            polymorphic(CommandType::class) {
+                subclass(SomeCommand::class)
+            }
+        }
+        val j = Json(default) { serializersModule = module; classDiscriminatorMode = ClassDiscriminatorMode.NONE }
+        parametrizedTest { mode ->
+            assertEquals("""{"cmd":{"type":"foo"}}""", j.encodeToString(Command(SomeCommand("foo")), mode))
+        }
+    }
 }
 
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/json/serializers/JsonPrimitiveSerializerTest.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/json/serializers/JsonPrimitiveSerializerTest.kt
index 72f8a4fb..0f084278 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/json/serializers/JsonPrimitiveSerializerTest.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/json/serializers/JsonPrimitiveSerializerTest.kt
@@ -4,6 +4,7 @@
 
 package kotlinx.serialization.json.serializers
 
+import kotlinx.serialization.Serializable
 import kotlinx.serialization.json.*
 import kotlinx.serialization.test.*
 import kotlin.test.*
@@ -201,4 +202,17 @@ class JsonPrimitiveSerializerTest : JsonTestBase() {
             assertUnsignedNumberEncoding(expected, actual, JsonPrimitive(actual))
         }
     }
+
+    @Serializable
+    class OuterLong(val a: Long)
+
+    @Test
+    fun testRejectingIncorrectNumbers() = parametrizedTest { mode ->
+        checkSerializationException({
+            default.decodeFromString(OuterLong.serializer(), """{"a":"12:34:45"}""", mode)
+        }, {
+            if (mode == JsonTestingMode.TREE) assertContains(it, "Failed to parse literal '\"12:34:45\"' as a long value at element: \$.a")
+            else assertContains(it, "Unexpected JSON token at offset 5: Expected closing quotation mark at path: \$.a")
+        })
+    }
 }
diff --git a/formats/json-tests/commonTest/src/kotlinx/serialization/test/TestHelpers.kt b/formats/json-tests/commonTest/src/kotlinx/serialization/test/TestHelpers.kt
index 27ac19f1..76ea07a0 100644
--- a/formats/json-tests/commonTest/src/kotlinx/serialization/test/TestHelpers.kt
+++ b/formats/json-tests/commonTest/src/kotlinx/serialization/test/TestHelpers.kt
@@ -2,8 +2,6 @@
  * Copyright 2017-2022 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-@file:Suppress("INVISIBLE_REFERENCE", "INVISIBLE_MEMBER")
-
 package kotlinx.serialization.test
 
 import kotlinx.serialization.*
diff --git a/formats/json-tests/jvmTest/src/kotlinx/serialization/features/JsonJvmStreamsTest.kt b/formats/json-tests/jvmTest/src/kotlinx/serialization/features/JsonJvmStreamsTest.kt
index 7019edae..40d0cb06 100644
--- a/formats/json-tests/jvmTest/src/kotlinx/serialization/features/JsonJvmStreamsTest.kt
+++ b/formats/json-tests/jvmTest/src/kotlinx/serialization/features/JsonJvmStreamsTest.kt
@@ -2,14 +2,11 @@
  * Copyright 2017-2022 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
  */
 
-@file:Suppress("INVISIBLE_REFERENCE", "INVISIBLE_MEMBER")
-
 package kotlinx.serialization.features
 
 import kotlinx.serialization.*
 import kotlinx.serialization.builtins.serializer
 import kotlinx.serialization.json.*
-import kotlinx.serialization.json.internal.BATCH_SIZE
 import kotlinx.serialization.modules.*
 import kotlinx.serialization.test.*
 import org.junit.Test
@@ -19,6 +16,7 @@ import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
 
 class JsonJvmStreamsTest {
+    val BATCH_SIZE = 16 * 1024 // kotlinx.serialization.json.internal.BATCH_SIZE
     private val strLen = BATCH_SIZE * 2 + 42
 
     @Test
diff --git a/formats/json/api/kotlinx-serialization-json.api b/formats/json/api/kotlinx-serialization-json.api
index 4602ad35..d46439e0 100644
--- a/formats/json/api/kotlinx-serialization-json.api
+++ b/formats/json/api/kotlinx-serialization-json.api
@@ -262,6 +262,13 @@ public final class kotlinx/serialization/json/JsonEncoder$DefaultImpls {
 	public static fun shouldEncodeElementDefault (Lkotlinx/serialization/json/JsonEncoder;Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z
 }
 
+public abstract interface annotation class kotlinx/serialization/json/JsonIgnoreUnknownKeys : java/lang/annotation/Annotation {
+}
+
+public synthetic class kotlinx/serialization/json/JsonIgnoreUnknownKeys$Impl : kotlinx/serialization/json/JsonIgnoreUnknownKeys {
+	public fun <init> ()V
+}
+
 public final class kotlinx/serialization/json/JsonKt {
 	public static final fun Json (Lkotlinx/serialization/json/Json;Lkotlin/jvm/functions/Function1;)Lkotlinx/serialization/json/Json;
 	public static synthetic fun Json$default (Lkotlinx/serialization/json/Json;Lkotlin/jvm/functions/Function1;ILjava/lang/Object;)Lkotlinx/serialization/json/Json;
diff --git a/formats/json/api/kotlinx-serialization-json.klib.api b/formats/json/api/kotlinx-serialization-json.klib.api
index 42628403..b91b9025 100644
--- a/formats/json/api/kotlinx-serialization-json.klib.api
+++ b/formats/json/api/kotlinx-serialization-json.klib.api
@@ -24,6 +24,10 @@ open annotation class kotlinx.serialization.json/JsonClassDiscriminator : kotlin
         final fun <get-discriminator>(): kotlin/String // kotlinx.serialization.json/JsonClassDiscriminator.discriminator.<get-discriminator>|<get-discriminator>(){}[0]
 }
 
+open annotation class kotlinx.serialization.json/JsonIgnoreUnknownKeys : kotlin/Annotation { // kotlinx.serialization.json/JsonIgnoreUnknownKeys|null[0]
+    constructor <init>() // kotlinx.serialization.json/JsonIgnoreUnknownKeys.<init>|<init>(){}[0]
+}
+
 open annotation class kotlinx.serialization.json/JsonNames : kotlin/Annotation { // kotlinx.serialization.json/JsonNames|null[0]
     constructor <init>(kotlin/Array<out kotlin/String>...) // kotlinx.serialization.json/JsonNames.<init>|<init>(kotlin.Array<out|kotlin.String>...){}[0]
 
@@ -308,6 +312,7 @@ sealed class kotlinx.serialization.json/Json : kotlinx.serialization/StringForma
     final fun <#A1: kotlin/Any?> encodeToString(kotlinx.serialization/SerializationStrategy<#A1>, #A1): kotlin/String // kotlinx.serialization.json/Json.encodeToString|encodeToString(kotlinx.serialization.SerializationStrategy<0:0>;0:0){0§<kotlin.Any?>}[0]
     final fun parseToJsonElement(kotlin/String): kotlinx.serialization.json/JsonElement // kotlinx.serialization.json/Json.parseToJsonElement|parseToJsonElement(kotlin.String){}[0]
     final inline fun <#A1: reified kotlin/Any?> decodeFromString(kotlin/String): #A1 // kotlinx.serialization.json/Json.decodeFromString|decodeFromString(kotlin.String){0§<kotlin.Any?>}[0]
+    final inline fun <#A1: reified kotlin/Any?> encodeToString(#A1): kotlin/String // kotlinx.serialization.json/Json.encodeToString|encodeToString(0:0){0§<kotlin.Any?>}[0]
 
     final object Default : kotlinx.serialization.json/Json // kotlinx.serialization.json/Json.Default|null[0]
 }
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/Json.kt b/formats/json/commonMain/src/kotlinx/serialization/json/Json.kt
index fe6b094d..ed63e2ca 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/Json.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/Json.kt
@@ -129,22 +129,6 @@ public sealed class Json(
         }
     }
 
-    /**
-     * Decodes and deserializes the given JSON [string] to the value of type [T] using deserializer
-     * retrieved from the reified type parameter.
-     * Example:
-     * ```
-     * @Serializable
-     * data class Project(val name: String, val language: String)
-     * //  Project(name=kotlinx.serialization, language=Kotlin)
-     * println(Json.decodeFromString<Project>("""{"name":"kotlinx.serialization","language":"Kotlin"}"""))
-     * ```
-     *
-     * @throws SerializationException in case of any decoding-specific error
-     * @throws IllegalArgumentException if the decoded input is not a valid instance of [T]
-     */
-    public inline fun <reified T> decodeFromString(@FormatLanguage("json", "", "") string: String): T =
-            decodeFromString(serializersModule.serializer(), string)
 
     /**
      * Deserializes the given JSON [string] into a value of type [T] using the given [deserializer].
@@ -194,6 +178,48 @@ public sealed class Json(
     public fun parseToJsonElement(@FormatLanguage("json", "", "") string: String): JsonElement {
         return decodeFromString(JsonElementSerializer, string)
     }
+
+    /**
+     * Following functions are copied from extensions on StringFormat
+     * to streamline experience for newcomers, since IDE does not star-import kotlinx.serialization.* automatically
+     */
+
+    /**
+     * Serializes the [value] of type [T] into an equivalent JSON using serializer
+     * retrieved from the reified type parameter.
+     *
+     * Example of usage:
+     * ```
+     * @Serializable
+     * class Project(val name: String, val language: String)
+     *
+     * val data = Project("kotlinx.serialization", "Kotlin")
+     *
+     * // Prints {"name":"kotlinx.serialization","language":"Kotlin"}
+     * println(Json.encodeToString(data))
+     * ```
+     *
+     * @throws [SerializationException] if the given value cannot be serialized to JSON.
+     */
+    public inline fun <reified T> encodeToString(value: T): String =
+        encodeToString(serializersModule.serializer(), value)
+
+    /**
+     * Decodes and deserializes the given JSON [string] to the value of type [T] using deserializer
+     * retrieved from the reified type parameter.
+     * Example:
+     * ```
+     * @Serializable
+     * data class Project(val name: String, val language: String)
+     * //  Project(name=kotlinx.serialization, language=Kotlin)
+     * println(Json.decodeFromString<Project>("""{"name":"kotlinx.serialization","language":"Kotlin"}"""))
+     * ```
+     *
+     * @throws SerializationException in case of any decoding-specific error
+     * @throws IllegalArgumentException if the decoded input is not a valid instance of [T]
+     */
+    public inline fun <reified T> decodeFromString(@FormatLanguage("json", "", "") string: String): T =
+        decodeFromString(serializersModule.serializer(), string)
 }
 
 /**
@@ -411,6 +437,11 @@ public class JsonBuilder internal constructor(json: Json) {
      * // Fails with "Encountered an unknown key 'version'"
      * Json.decodeFromString<Project>("""{"name":"unknown", "version": 2.0}""")
      * ```
+     *
+     * In case you wish to allow unknown properties only for specific class(es),
+     * consider using [JsonIgnoreUnknownKeys] annotation instead of this configuration flag.
+     *
+     * @see JsonIgnoreUnknownKeys
      */
     public var ignoreUnknownKeys: Boolean = json.configuration.ignoreUnknownKeys
 
@@ -495,6 +526,13 @@ public class JsonBuilder internal constructor(json: Json) {
     /**
      * Name of the class descriptor property for polymorphic serialization.
      * `type` by default.
+     *
+     * Note that if your class has any serial names that are equal to [classDiscriminator]
+     * (e.g., `@Serializable class Foo(val type: String)`), an [IllegalArgumentException] will be thrown from `Json {}` builder.
+     * You can disable this check and class discriminator inclusion with [ClassDiscriminatorMode.NONE], but kotlinx.serialization will not be
+     * able to deserialize such data back.
+     *
+     * @see classDiscriminatorMode
      */
     public var classDiscriminator: String = json.configuration.classDiscriminator
 
@@ -504,6 +542,8 @@ public class JsonBuilder internal constructor(json: Json) {
      *
      * Other modes are generally intended to produce JSON for consumption by third-party libraries,
      * therefore, this setting does not affect the deserialization process.
+     *
+     * @see classDiscriminator
      */
     @ExperimentalSerializationApi
     public var classDiscriminatorMode: ClassDiscriminatorMode = json.configuration.classDiscriminatorMode
@@ -669,7 +709,7 @@ private class JsonImpl(configuration: JsonConfiguration, module: SerializersModu
 
     private fun validateConfiguration() {
         if (serializersModule == EmptySerializersModule()) return // Fast-path for in-place JSON allocations
-        val collector = PolymorphismValidator(configuration.useArrayPolymorphism, configuration.classDiscriminator)
+        val collector = JsonSerializersModuleValidator(configuration)
         serializersModule.dumpTo(collector)
     }
 }
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/JsonAnnotations.kt b/formats/json/commonMain/src/kotlinx/serialization/json/JsonAnnotations.kt
index 4ec5a2b5..f126d433 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/JsonAnnotations.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/JsonAnnotations.kt
@@ -74,3 +74,36 @@ public annotation class JsonNames(vararg val names: String)
 @Target(AnnotationTarget.CLASS)
 @ExperimentalSerializationApi
 public annotation class JsonClassDiscriminator(val discriminator: String)
+
+
+/**
+ * Specifies whether encounters of unknown properties (i.e., properties not declared in the class) in the input JSON
+ * should be ignored instead of throwing [SerializationException].
+ *
+ * With this annotation, it is possible to allow unknown properties for annotated classes, while
+ * general decoding methods (such as [Json.decodeFromString] and others) would still reject them for everything else.
+ * If you want [Json.decodeFromString] allow all unknown properties for all classes and inputs, consider using
+ * [JsonBuilder.ignoreUnknownKeys].
+ *
+ * Example:
+ * ```
+ * @Serializable
+ * @JsonIgnoreUnknownKeys
+ * class Outer(val a: Int, val inner: Inner)
+ *
+ * @Serializable
+ * class Inner(val x: String)
+ *
+ * // Throws SerializationException because there is no "unknownKey" property in Inner
+ * Json.decodeFromString<Outer>("""{"a":1,"inner":{"x":"value","unknownKey":"unknownValue"}}""")
+ *
+ * // Decodes successfully despite "unknownKey" property in Outer
+ * Json.decodeFromString<Outer>("""{"a":1,"inner":{"x":"value"}, "unknownKey":42}""")
+ * ```
+ *
+ * @see JsonBuilder.ignoreUnknownKeys
+ */
+@SerialInfo
+@Target(AnnotationTarget.CLASS)
+@ExperimentalSerializationApi
+public annotation class JsonIgnoreUnknownKeys
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/JsonConfiguration.kt b/formats/json/commonMain/src/kotlinx/serialization/json/JsonConfiguration.kt
index ade53a6a..3be703a3 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/JsonConfiguration.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/JsonConfiguration.kt
@@ -81,6 +81,9 @@ public enum class ClassDiscriminatorMode {
      * This mode is generally intended to produce JSON for consumption by third-party libraries.
      * kotlinx.serialization is unable to deserialize [polymorphic classes][POLYMORPHIC] without class discriminators,
      * so it is impossible to deserialize JSON produced in this mode if a data model has polymorphic classes.
+     *
+     * Using this mode relaxes several configuration checks in [Json]. In particular, it is possible to serialize enums and primitives
+     * as polymorphic subclasses in this mode, since it is no longer required for them to have outer `{}` object to include class discriminator.
      */
     NONE,
 
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/JsonDecoder.kt b/formats/json/commonMain/src/kotlinx/serialization/json/JsonDecoder.kt
index 2ccc46a4..5dfd869f 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/JsonDecoder.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/JsonDecoder.kt
@@ -51,6 +51,7 @@ import kotlinx.serialization.descriptors.*
  * Accepting this interface in your API methods, casting [Decoder] to [JsonDecoder] and invoking its
  * methods is considered stable.
  */
+@SubclassOptInRequired(SealedSerializationApi::class)
 public interface JsonDecoder : Decoder, CompositeDecoder {
     /**
      * An instance of the current [Json].
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/JsonElement.kt b/formats/json/commonMain/src/kotlinx/serialization/json/JsonElement.kt
index 47330ebc..202567b7 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/JsonElement.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/JsonElement.kt
@@ -36,7 +36,7 @@ public sealed class JsonPrimitive : JsonElement() {
      * Indicates whether the primitive was explicitly constructed from [String] and
      * whether it should be serialized as one. E.g. `JsonPrimitive("42")` is represented
      * by a string, while `JsonPrimitive(42)` is not.
-     * These primitives will be serialized as `42` and `"42"` respectively.
+     * These primitives will be serialized as `"42"` and `42` respectively.
      */
     public abstract val isString: Boolean
 
@@ -256,7 +256,7 @@ public val JsonElement.jsonNull: JsonNull
  */
 public val JsonPrimitive.int: Int
     get() {
-        val result = mapExceptions { StringJsonLexer(content).consumeNumericLiteral() }
+        val result = exceptionToNumberFormatException { parseLongImpl() }
         if (result !in Int.MIN_VALUE..Int.MAX_VALUE) throw NumberFormatException("$content is not an Int")
         return result.toInt()
     }
@@ -266,7 +266,7 @@ public val JsonPrimitive.int: Int
  */
 public val JsonPrimitive.intOrNull: Int?
     get() {
-        val result = mapExceptionsToNull { StringJsonLexer(content).consumeNumericLiteral() } ?: return null
+        val result = exceptionToNull { parseLongImpl() } ?: return null
         if (result !in Int.MIN_VALUE..Int.MAX_VALUE) return null
         return result.toInt()
     }
@@ -275,14 +275,13 @@ public val JsonPrimitive.intOrNull: Int?
  * Returns content of current element as long
  * @throws NumberFormatException if current element is not a valid representation of number
  */
-public val JsonPrimitive.long: Long get() = mapExceptions { StringJsonLexer(content).consumeNumericLiteral() }
+public val JsonPrimitive.long: Long get() = exceptionToNumberFormatException { parseLongImpl() }
 
 /**
  * Returns content of current element as long or `null` if current element is not a valid representation of number
  */
 public val JsonPrimitive.longOrNull: Long?
-    get() =
-        mapExceptionsToNull { StringJsonLexer(content).consumeNumericLiteral() }
+    get() = exceptionToNull { parseLongImpl() }
 
 /**
  * Returns content of current element as double
@@ -326,7 +325,7 @@ public val JsonPrimitive.contentOrNull: String? get() = if (this is JsonNull) nu
 private fun JsonElement.error(element: String): Nothing =
     throw IllegalArgumentException("Element ${this::class} is not a $element")
 
-private inline fun <T> mapExceptionsToNull(f: () -> T): T? {
+private inline fun <T> exceptionToNull(f: () -> T): T? {
     return try {
         f()
     } catch (e: JsonDecodingException) {
@@ -334,7 +333,7 @@ private inline fun <T> mapExceptionsToNull(f: () -> T): T? {
     }
 }
 
-private inline fun <T> mapExceptions(f: () -> T): T {
+private inline fun <T> exceptionToNumberFormatException(f: () -> T): T {
     return try {
         f()
     } catch (e: JsonDecodingException) {
@@ -345,3 +344,6 @@ private inline fun <T> mapExceptions(f: () -> T): T {
 @PublishedApi
 internal fun unexpectedJson(key: String, expected: String): Nothing =
     throw IllegalArgumentException("Element $key is not a $expected")
+
+// Use this function to avoid re-wrapping exception into NumberFormatException
+internal fun JsonPrimitive.parseLongImpl(): Long = StringJsonLexer(content).consumeNumericLiteralFully()
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/JsonEncoder.kt b/formats/json/commonMain/src/kotlinx/serialization/json/JsonEncoder.kt
index 3dd57b9f..e58042c6 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/JsonEncoder.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/JsonEncoder.kt
@@ -4,6 +4,7 @@
 
 package kotlinx.serialization.json
 
+import kotlinx.serialization.*
 import kotlinx.serialization.encoding.*
 
 /**
@@ -49,6 +50,7 @@ import kotlinx.serialization.encoding.*
  * Accepting this interface in your API methods, casting [Encoder] to [JsonEncoder] and invoking its
  * methods is considered stable.
  */
+@SubclassOptInRequired(SealedSerializationApi::class)
 public interface JsonEncoder : Encoder, CompositeEncoder {
     /**
      * An instance of the current [Json].
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonExceptions.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonExceptions.kt
index c6098dd4..c885c808 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonExceptions.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonExceptions.kt
@@ -49,7 +49,7 @@ internal fun AbstractJsonLexer.throwInvalidFloatingPointDecoded(result: Number):
 internal fun AbstractJsonLexer.invalidTrailingComma(entity: String = "object"): Nothing {
     fail("Trailing comma before the end of JSON $entity",
         position = currentPosition - 1,
-        hint = "Trailing commas are non-complaint JSON and not allowed by default. Use 'allowTrailingCommas = true' in 'Json {}' builder to support them."
+        hint = "Trailing commas are non-complaint JSON and not allowed by default. Use 'allowTrailingComma = true' in 'Json {}' builder to support them."
     )
 }
 
@@ -75,13 +75,6 @@ private fun unexpectedFpErrorMessage(value: Number, key: String, output: String)
             "Current output: ${output.minify()}"
 }
 
-internal fun UnknownKeyException(key: String, input: String) = JsonDecodingException(
-    -1,
-    "Encountered an unknown key '$key'.\n" +
-            "$ignoreUnknownKeysHint\n" +
-            "Current input: ${input.minify()}"
-)
-
 internal fun CharSequence.minify(offset: Int = -1): CharSequence {
     if (length < 200) return this
     if (offset == -1) {
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonNamesMap.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonNamesMap.kt
index 16e6f300..8a4a5865 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonNamesMap.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonNamesMap.kt
@@ -149,3 +149,6 @@ internal inline fun Json.tryCoerceValue(
     }
     return false
 }
+
+internal fun SerialDescriptor.ignoreUnknownKeys(json: Json): Boolean =
+    json.configuration.ignoreUnknownKeys || annotations.any { it is JsonIgnoreUnknownKeys }
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/PolymorphismValidator.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonSerializersModuleValidator.kt
similarity index 86%
rename from formats/json/commonMain/src/kotlinx/serialization/json/internal/PolymorphismValidator.kt
rename to formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonSerializersModuleValidator.kt
index e4606fae..0b00f9da 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/PolymorphismValidator.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/JsonSerializersModuleValidator.kt
@@ -6,15 +6,19 @@ package kotlinx.serialization.json.internal
 
 import kotlinx.serialization.*
 import kotlinx.serialization.descriptors.*
+import kotlinx.serialization.json.*
 import kotlinx.serialization.modules.*
 import kotlin.reflect.*
 
 @OptIn(ExperimentalSerializationApi::class)
-internal class PolymorphismValidator(
-    private val useArrayPolymorphism: Boolean,
-    private val discriminator: String
+internal class JsonSerializersModuleValidator(
+    configuration: JsonConfiguration,
 ) : SerializersModuleCollector {
 
+    private val discriminator: String = configuration.classDiscriminator
+    private val useArrayPolymorphism: Boolean = configuration.useArrayPolymorphism
+    private val isDiscriminatorRequired = configuration.classDiscriminatorMode != ClassDiscriminatorMode.NONE
+
     override fun <T : Any> contextual(
         kClass: KClass<T>,
         provider: (typeArgumentsSerializers: List<KSerializer<*>>) -> KSerializer<*>
@@ -29,7 +33,7 @@ internal class PolymorphismValidator(
     ) {
         val descriptor = actualSerializer.descriptor
         checkKind(descriptor, actualClass)
-        if (!useArrayPolymorphism) {
+        if (!useArrayPolymorphism && isDiscriminatorRequired) {
             // Collisions with "type" can happen only for JSON polymorphism
             checkDiscriminatorCollisions(descriptor, actualClass)
         }
@@ -43,6 +47,7 @@ internal class PolymorphismValidator(
         }
 
         if (useArrayPolymorphism) return
+        if (!isDiscriminatorRequired) return
         /*
          * For this kind we can't intercept the JSON object {} in order to add "type: ...".
          * Except for maps that just can clash and accidentally overwrite the type.
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/Polymorphic.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/Polymorphic.kt
index acc0bf47..26d75266 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/Polymorphic.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/Polymorphic.kt
@@ -37,8 +37,10 @@ internal inline fun <T> JsonEncoder.encodePolymorphically(
         val casted = serializer as AbstractPolymorphicSerializer<Any>
         requireNotNull(value) { "Value for serializer ${serializer.descriptor} should always be non-null. Please report issue to the kotlinx.serialization tracker." }
         val actual = casted.findPolymorphicSerializer(this, value)
-        if (baseClassDiscriminator != null) validateIfSealed(serializer, actual, baseClassDiscriminator)
-        checkKind(actual.descriptor.kind)
+        if (baseClassDiscriminator != null) {
+            validateIfSealed(serializer, actual, baseClassDiscriminator)
+            checkKind(actual.descriptor.kind)
+        }
         actual as SerializationStrategy<T>
     } else serializer
 
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/StreamingJsonDecoder.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/StreamingJsonDecoder.kt
index ee813b31..9477db62 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/StreamingJsonDecoder.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/StreamingJsonDecoder.kt
@@ -122,7 +122,7 @@ internal open class StreamingJsonDecoder(
         // If we're ignoring unknown keys, we have to skip all un-decoded elements,
         // e.g. for object serialization. It can be the case when the descriptor does
         // not have any elements and decodeElementIndex is not invoked at all
-        if (json.configuration.ignoreUnknownKeys && descriptor.elementsCount == 0) {
+        if (descriptor.elementsCount == 0 && descriptor.ignoreUnknownKeys(json)) {
             skipLeftoverElements(descriptor)
         }
         if (lexer.tryConsumeComma() && !json.configuration.allowTrailingComma) lexer.invalidTrailingComma("")
@@ -240,7 +240,7 @@ internal open class StreamingJsonDecoder(
             }
 
             if (isUnknown) { // slow-path for unknown keys handling
-                hasComma = handleUnknown(key)
+                hasComma = handleUnknown(descriptor, key)
             }
         }
         if (hasComma && !json.configuration.allowTrailingComma) lexer.invalidTrailingComma()
@@ -248,12 +248,13 @@ internal open class StreamingJsonDecoder(
         return elementMarker?.nextUnmarkedIndex() ?: CompositeDecoder.DECODE_DONE
     }
 
-    private fun handleUnknown(key: String): Boolean {
-        if (configuration.ignoreUnknownKeys || discriminatorHolder.trySkip(key)) {
+    private fun handleUnknown(descriptor: SerialDescriptor, key: String): Boolean {
+        if (descriptor.ignoreUnknownKeys(json) || discriminatorHolder.trySkip(key)) {
             lexer.skipElement(configuration.isLenient)
         } else {
-            // Here we cannot properly update json path indices
-            // as we do not have a proper SerialDescriptor in our hands
+            // Since path is updated on key decoding, it ends with the key that was successfully decoded last,
+            // and we need to remove it to correctly point to the outer structure.
+            lexer.path.popDescriptor()
             lexer.failOnUnknownKey(key)
         }
         return lexer.tryConsumeComma()
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/StringOps.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/StringOps.kt
index 1f367154..85169a25 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/StringOps.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/StringOps.kt
@@ -12,8 +12,8 @@ private fun toHexChar(i: Int) : Char {
     else (d - 10 + 'a'.code).toChar()
 }
 
-@PublishedApi
-internal val ESCAPE_STRINGS: Array<String?> = arrayOfNulls<String>(93).apply {
+@JsonFriendModuleApi
+public val ESCAPE_STRINGS: Array<String?> = arrayOfNulls<String>(93).apply {
     for (c in 0..0x1f) {
         val c1 = toHexChar(c shr 12)
         val c2 = toHexChar(c shr 8)
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonDecoder.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonDecoder.kt
index ec06db61..2121b27a 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonDecoder.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonDecoder.kt
@@ -8,7 +8,6 @@
 package kotlinx.serialization.json.internal
 
 import kotlinx.serialization.*
-import kotlinx.serialization.builtins.*
 import kotlinx.serialization.descriptors.*
 import kotlinx.serialization.encoding.*
 import kotlinx.serialization.internal.*
@@ -112,19 +111,24 @@ private sealed class AbstractJsonTreeDecoder(
         getPrimitiveValue(tag, "boolean", JsonPrimitive::booleanOrNull)
 
     override fun decodeTaggedByte(tag: String) = getPrimitiveValue(tag, "byte") {
-        val result = int
+        val result = parseLongImpl()
         if (result in Byte.MIN_VALUE..Byte.MAX_VALUE) result.toByte()
         else null
     }
 
     override fun decodeTaggedShort(tag: String) = getPrimitiveValue(tag, "short") {
-        val result = int
+        val result = parseLongImpl()
         if (result in Short.MIN_VALUE..Short.MAX_VALUE) result.toShort()
         else null
     }
 
-    override fun decodeTaggedInt(tag: String) = getPrimitiveValue(tag, "int") { int }
-    override fun decodeTaggedLong(tag: String) = getPrimitiveValue(tag, "long") { long }
+    override fun decodeTaggedInt(tag: String) = getPrimitiveValue(tag, "int") {
+        val result = parseLongImpl()
+        if (result in Int.MIN_VALUE..Int.MAX_VALUE) result.toInt()
+        else null
+    }
+
+    override fun decodeTaggedLong(tag: String) = getPrimitiveValue(tag, "long") { parseLongImpl() }
 
     override fun decodeTaggedFloat(tag: String): Float {
         val result = getPrimitiveValue(tag, "float") { float }
@@ -203,7 +207,6 @@ private open class JsonTreeDecoder(
             { (currentElement(tag) as? JsonPrimitive)?.contentOrNull }
         )
 
-    @Suppress("INVISIBLE_MEMBER")
     override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
         while (position < descriptor.elementsCount) {
             val name = descriptor.getTag(position++)
@@ -267,7 +270,7 @@ private open class JsonTreeDecoder(
     }
 
     override fun endStructure(descriptor: SerialDescriptor) {
-        if (configuration.ignoreUnknownKeys || descriptor.kind is PolymorphicKind) return
+        if (descriptor.ignoreUnknownKeys(json) || descriptor.kind is PolymorphicKind) return
         // Validate keys
         val strategy = descriptor.namingStrategy(json)
 
@@ -280,7 +283,12 @@ private open class JsonTreeDecoder(
 
         for (key in value.keys) {
             if (key !in names && key != polymorphicDiscriminator) {
-                throw UnknownKeyException(key, value.toString())
+                throw JsonDecodingException(
+                    -1,
+                    "Encountered an unknown key '$key' at element: ${renderTagStack()}\n" +
+                        "$ignoreUnknownKeysHint\n" +
+                        "JSON input: ${value.toString().minify()}"
+                )
             }
         }
     }
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonEncoder.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonEncoder.kt
index 74c95b1e..6d2f36c9 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonEncoder.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/TreeJsonEncoder.kt
@@ -22,7 +22,6 @@ public fun <T> writeJson(json: Json, value: T, serializer: SerializationStrategy
     return result
 }
 
-@ExperimentalSerializationApi
 private sealed class AbstractJsonTreeEncoder(
     final override val json: Json,
     protected val nodeConsumer: (JsonElement) -> Unit
diff --git a/formats/json/commonMain/src/kotlinx/serialization/json/internal/lexer/AbstractJsonLexer.kt b/formats/json/commonMain/src/kotlinx/serialization/json/internal/lexer/AbstractJsonLexer.kt
index 7b740089..5f570a95 100644
--- a/formats/json/commonMain/src/kotlinx/serialization/json/internal/lexer/AbstractJsonLexer.kt
+++ b/formats/json/commonMain/src/kotlinx/serialization/json/internal/lexer/AbstractJsonLexer.kt
@@ -14,7 +14,7 @@ internal const val lenientHint = "Use 'isLenient = true' in 'Json {}' builder to
 internal const val coerceInputValuesHint = "Use 'coerceInputValues = true' in 'Json {}' builder to coerce nulls if property has a default value."
 internal const val specialFlowingValuesHint =
     "It is possible to deserialize them using 'JsonBuilder.allowSpecialFloatingPointValues = true'"
-internal const val ignoreUnknownKeysHint = "Use 'ignoreUnknownKeys = true' in 'Json {}' builder to ignore unknown keys."
+internal const val ignoreUnknownKeysHint = "Use 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys."
 internal const val allowStructuredMapKeysHint =
     "Use 'allowStructuredMapKeys = true' in 'Json {}' builder to convert such maps to [key1, value1, key2, value2,...] arrays."
 
@@ -223,12 +223,16 @@ internal abstract class AbstractJsonLexer {
         fail(charToTokenClass(expected))
     }
 
-    internal fun fail(expectedToken: Byte, wasConsumed: Boolean = true): Nothing {
+    internal inline fun fail(
+        expectedToken: Byte,
+        wasConsumed: Boolean = true,
+        message: (expected: String, source: String) -> String = { expected, source -> "Expected $expected, but had '$source' instead" }
+    ): Nothing {
         // Slow path, never called in normal code, can avoid optimizing it
         val expected = tokenDescription(expectedToken)
         val position = if (wasConsumed) currentPosition - 1 else currentPosition
         val s = if (currentPosition == source.length || position < 0) "EOF" else source[position].toString()
-        fail("Expected $expected, but had '$s' instead", position)
+        fail(message(expected, s), position)
     }
 
     open fun peekNextToken(): Byte {
@@ -297,7 +301,7 @@ internal abstract class AbstractJsonLexer {
     }
 
     open fun indexOf(char: Char, startPos: Int) = source.indexOf(char, startPos)
-    open fun substring(startPos: Int, endPos: Int) =  source.substring(startPos, endPos)
+    open fun substring(startPos: Int, endPos: Int) = source.substring(startPos, endPos)
 
     /*
      * This method is a copy of consumeString, but used for key of json objects, so there
@@ -572,7 +576,10 @@ internal abstract class AbstractJsonLexer {
         // but still would like an error to point to the beginning of the key, so we are backtracking it
         val processed = substring(0, currentPosition)
         val lastIndexOf = processed.lastIndexOf(key)
-        fail("Encountered an unknown key '$key'", lastIndexOf, ignoreUnknownKeysHint)
+        throw JsonDecodingException(
+            "Encountered an unknown key '$key' at offset $lastIndexOf at path: ${path.getPath()}\n$ignoreUnknownKeysHint\n" +
+                "JSON input: ${source.minify(lastIndexOf)}"
+        )
     }
 
     fun fail(message: String, position: Int = currentPosition, hint: String = ""): Nothing {
@@ -671,6 +678,15 @@ internal abstract class AbstractJsonLexer {
         }
     }
 
+    fun consumeNumericLiteralFully(): Long {
+        val result = consumeNumericLiteral()
+        val next = consumeNextToken()
+        if (next != TC_EOF) {
+            fail(TC_EOF) { _, source -> "Expected input to contain a single valid number, but got '$source' after it" }
+        }
+        return result
+    }
+
 
     fun consumeBoolean(): Boolean {
         return consumeBoolean(skipWhitespaces())
diff --git a/formats/json/jvmMain/src/kotlinx/serialization/json/internal/ArrayPools.kt b/formats/json/jvmMain/src/kotlinx/serialization/json/internal/ArrayPools.kt
index 0d36c6c0..9484addc 100644
--- a/formats/json/jvmMain/src/kotlinx/serialization/json/internal/ArrayPools.kt
+++ b/formats/json/jvmMain/src/kotlinx/serialization/json/internal/ArrayPools.kt
@@ -8,8 +8,8 @@ package kotlinx.serialization.json.internal
  * (unlikely) problems with memory consumptions.
  */
 private val MAX_CHARS_IN_POOL = runCatching {
-    System.getProperty("kotlinx.serialization.json.pool.size").toIntOrNull()
-}.getOrNull() ?: 2 * 1024 * 1024
+    System.getProperty("kotlinx.serialization.json.pool.size")?.toIntOrNull()
+}.getOrNull() ?: (2 * 1024 * 1024)
 
 internal open class CharArrayPoolBase {
     private val arrays = ArrayDeque<CharArray>()
diff --git a/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/Helpers.kt b/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/Helpers.kt
index ea6d4b68..33e1c78c 100644
--- a/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/Helpers.kt
+++ b/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/Helpers.kt
@@ -22,8 +22,17 @@ internal enum class ProtoWireType(val typeId: Int) {
     ;
 
     companion object {
-        fun from(typeId: Int): ProtoWireType {
-            return ProtoWireType.entries.find { it.typeId == typeId } ?: INVALID
+        private val entryArray = Array(8) { typeId ->
+            ProtoWireType.entries.find { it.typeId == typeId } ?: INVALID
+        }
+
+        /**
+         * Extracts three least significant bits from the [value] and
+         * returns [ProtoWireType] with corresponding type id, or [ProtoWireType.INVALID]
+         * if there are no such a type.
+         */
+        fun fromLeastSignificantBits(value: Int): ProtoWireType {
+            return entryArray[value and 0b111]
         }
     }
 
diff --git a/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/ProtobufReader.kt b/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/ProtobufReader.kt
index 5b8ce1c2..674224a7 100644
--- a/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/ProtobufReader.kt
+++ b/formats/protobuf/commonMain/src/kotlinx/serialization/protobuf/internal/ProtobufReader.kt
@@ -42,7 +42,7 @@ internal class ProtobufReader(private val input: ByteArrayInput) {
             -1
         } else {
             currentId = header ushr 3
-            currentType = ProtoWireType.from(header and 0b111)
+            currentType = ProtoWireType.fromLeastSignificantBits(header)
             currentId
         }
     }
diff --git a/gradle.properties b/gradle.properties
index 460a1cee..084b8484 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -3,14 +3,13 @@
 #
 
 group=org.jetbrains.kotlinx
-version=1.7.4-SNAPSHOT
+version=1.8.0-SNAPSHOT
 jdk_toolchain_version=11
-# This version takes precedence if 'bootstrap' property passed to project
-kotlin.version.snapshot=2.0.255-SNAPSHOT
-# Also set KONAN_LOCAL_DIST environment variable in bootstrap mode to auto-assign konan.home
 
-native.deploy=
-# Only for tests
+# This version takes precedence if 'bootstrap' property passed to project
+kotlin.version.snapshot=2.1.255-SNAPSHOT
+# Also set kotlin.native.home to your $kotlin_project$/kotlin-native/dist if you want to use snapshot Native
+#kotlin.native.home=
 
 kover.enabled=true
 
@@ -23,3 +22,5 @@ org.gradle.caching=true
 kotlin.native.distribution.type=prebuilt
 
 org.gradle.jvmargs="-XX:+HeapDumpOnOutOfMemoryError"
+
+org.jetbrains.dokka.experimental.tryK2=true
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index e4ad3d94..28b64a0a 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -1,7 +1,7 @@
 [versions]
-kotlin = "2.0.20"
+kotlin = "2.1.0"
 kover = "0.8.2"
-dokka = "1.9.20"
+dokka = "2.0.0-Beta"
 knit = "0.5.0"
 bcv = "0.16.2"
 animalsniffer = "1.7.1"
@@ -13,7 +13,7 @@ guava = "31.1-jre"
 guava24 = "24.1.1-jre"
 jackson = "2.13.3"
 okio = "3.9.0"
-kotlinx-io="0.4.0"
+kotlinx-io = "0.4.0"
 gson = "2.8.5"
 moshi = "1.15.1"
 kotlintest = "2.0.7"
@@ -24,33 +24,33 @@ junit4 = "4.12"
 protoc = "3.17.3"
 
 [libraries]
-gradlePlugin-kotlin = { module = "org.jetbrains.kotlin:kotlin-gradle-plugin", version.ref = "kotlin"}
-gradlePlugin-kover = { module = "org.jetbrains.kotlinx:kover-gradle-plugin", version.ref = "kover"}
-gradlePlugin-dokka = { module = "org.jetbrains.dokka:dokka-gradle-plugin", version.ref = "dokka"}
-gradlePlugin-animalsniffer = { module = "ru.vyarus:gradle-animalsniffer-plugin", version.ref = "animalsniffer"}
-gradlePlugin-binaryCompatibilityValidator = { module = "org.jetbrains.kotlinx:binary-compatibility-validator", version.ref = "bcv"}
+gradlePlugin-kotlin = { module = "org.jetbrains.kotlin:kotlin-gradle-plugin", version.ref = "kotlin" }
+gradlePlugin-kover = { module = "org.jetbrains.kotlinx:kover-gradle-plugin", version.ref = "kover" }
+gradlePlugin-dokka = { module = "org.jetbrains.dokka:dokka-gradle-plugin", version.ref = "dokka" }
+gradlePlugin-animalsniffer = { module = "ru.vyarus:gradle-animalsniffer-plugin", version.ref = "animalsniffer" }
+gradlePlugin-binaryCompatibilityValidator = { module = "org.jetbrains.kotlinx:binary-compatibility-validator", version.ref = "bcv" }
 
 kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
 kotlin-test = { module = "org.jetbrains.kotlin:kotlin-test", version.ref = "kotlin" }
 
-dokka-pathsaver = { module = "org.jetbrains.kotlinx:dokka-pathsaver-plugin", version.ref = "knit"}
-knitTest = { module = "org.jetbrains.kotlinx:kotlinx-knit-test", version.ref = "knit"}
-jmhCore = { module = "org.openjdk.jmh:jmh-core", version.ref = "jmh-core"}
-guava = { module = "com.google.guava:guava", version.ref = "guava"}
-guava-24 = { module = "com.google.guava:guava", version.ref = "guava24"}
-jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson"}
-jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson"}
-jackson-module-kotlin = { module = "com.fasterxml.jackson.module:jackson-module-kotlin", version.ref = "jackson"}
-jackson-cbor = { module = "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor", version.ref = "jackson"}
-okio = { module = "com.squareup.okio:okio", version.ref = "okio"}
-kotlinx-io = { module = "org.jetbrains.kotlinx:kotlinx-io-core", version.ref = "kotlinx-io"}
-gson = { module = "com.google.code.gson:gson", version.ref = "gson"}
-kotlintest = { module = "io.kotlintest:kotlintest", version.ref = "kotlintest"}
-coroutines-core = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-core", version.ref = "coroutines"}
-cbor = { module = "com.upokecenter:cbor", version.ref = "cbor"}
-typesafe-config = { module = "com.typesafe:config", version.ref = "typesafe-config"}
-junit-junit4 = { module = "junit:junit", version.ref = "junit4"}
-protoc = { module = "com.google.protobuf:protoc", version.ref = "protoc"}
+dokka-pathsaver = { module = "org.jetbrains.kotlinx:dokka-pathsaver-plugin", version.ref = "knit" }
+knitTest = { module = "org.jetbrains.kotlinx:kotlinx-knit-test", version.ref = "knit" }
+jmhCore = { module = "org.openjdk.jmh:jmh-core", version.ref = "jmh-core" }
+guava = { module = "com.google.guava:guava", version.ref = "guava" }
+guava-24 = { module = "com.google.guava:guava", version.ref = "guava24" }
+jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }
+jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
+jackson-module-kotlin = { module = "com.fasterxml.jackson.module:jackson-module-kotlin", version.ref = "jackson" }
+jackson-cbor = { module = "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor", version.ref = "jackson" }
+okio = { module = "com.squareup.okio:okio", version.ref = "okio" }
+kotlinx-io = { module = "org.jetbrains.kotlinx:kotlinx-io-core", version.ref = "kotlinx-io" }
+gson = { module = "com.google.code.gson:gson", version.ref = "gson" }
+kotlintest = { module = "io.kotlintest:kotlintest", version.ref = "kotlintest" }
+coroutines-core = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-core", version.ref = "coroutines" }
+cbor = { module = "com.upokecenter:cbor", version.ref = "cbor" }
+typesafe-config = { module = "com.typesafe:config", version.ref = "typesafe-config" }
+junit-junit4 = { module = "junit:junit", version.ref = "junit4" }
+protoc = { module = "com.google.protobuf:protoc", version.ref = "protoc" }
 protobuf-java = { module = "com.google.protobuf:protobuf-java", version.ref = "protoc" }
 moshi-kotlin = { module = "com.squareup.moshi:moshi-kotlin", version.ref = "moshi" }
 moshi-codegen = { module = "com.squareup.moshi:moshi-kotlin-codegen", version.ref = "moshi" }
diff --git a/guide/example/example-json-04.kt b/guide/example/example-json-04.kt
index 92d03672..da03eecc 100644
--- a/guide/example/example-json-04.kt
+++ b/guide/example/example-json-04.kt
@@ -4,13 +4,18 @@ package example.exampleJson04
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@OptIn(ExperimentalSerializationApi::class) // JsonNames is an experimental annotation for now
+@OptIn(ExperimentalSerializationApi::class) // JsonIgnoreUnknownKeys is an experimental annotation for now
 @Serializable
-data class Project(@JsonNames("title") val name: String)
+@JsonIgnoreUnknownKeys
+data class Outer(val a: Int, val inner: Inner)
+
+@Serializable
+data class Inner(val x: String)
 
 fun main() {
-  val project = Json.decodeFromString<Project>("""{"name":"kotlinx.serialization"}""")
-  println(project)
-  val oldProject = Json.decodeFromString<Project>("""{"title":"kotlinx.coroutines"}""")
-  println(oldProject)
+    // 1
+    println(Json.decodeFromString<Outer>("""{"a":1,"inner":{"x":"value"},"unknownKey":42}"""))
+    println()
+    // 2
+    println(Json.decodeFromString<Outer>("""{"a":1,"inner":{"x":"value","unknownKey":"unknownValue"}}"""))
 }
diff --git a/guide/example/example-json-05.kt b/guide/example/example-json-05.kt
index 809cc9ed..8d5c1201 100644
--- a/guide/example/example-json-05.kt
+++ b/guide/example/example-json-05.kt
@@ -4,16 +4,13 @@ package example.exampleJson05
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-val format = Json { encodeDefaults = true }
-
+@OptIn(ExperimentalSerializationApi::class) // JsonNames is an experimental annotation for now
 @Serializable
-class Project(
-    val name: String,
-    val language: String = "Kotlin",
-    val website: String? = null
-)
+data class Project(@JsonNames("title") val name: String)
 
 fun main() {
-    val data = Project("kotlinx.serialization")
-    println(format.encodeToString(data))
+  val project = Json.decodeFromString<Project>("""{"name":"kotlinx.serialization"}""")
+  println(project)
+  val oldProject = Json.decodeFromString<Project>("""{"title":"kotlinx.coroutines"}""")
+  println(oldProject)
 }
diff --git a/guide/example/example-json-06.kt b/guide/example/example-json-06.kt
index 776e3ec4..605b4884 100644
--- a/guide/example/example-json-06.kt
+++ b/guide/example/example-json-06.kt
@@ -4,20 +4,16 @@ package example.exampleJson06
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-val format = Json { explicitNulls = false }
+val format = Json { encodeDefaults = true }
 
 @Serializable
-data class Project(
+class Project(
     val name: String,
-    val language: String,
-    val version: String? = "1.2.2",
-    val website: String?,
-    val description: String? = null
+    val language: String = "Kotlin",
+    val website: String? = null
 )
 
 fun main() {
-    val data = Project("kotlinx.serialization", "Kotlin", null, null, null)
-    val json = format.encodeToString(data)
-    println(json)
-    println(format.decodeFromString<Project>(json))
+    val data = Project("kotlinx.serialization")
+    println(format.encodeToString(data))
 }
diff --git a/guide/example/example-json-07.kt b/guide/example/example-json-07.kt
index 4d9ad2c0..60aa2b28 100644
--- a/guide/example/example-json-07.kt
+++ b/guide/example/example-json-07.kt
@@ -4,14 +4,20 @@ package example.exampleJson07
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-val format = Json { coerceInputValues = true }
+val format = Json { explicitNulls = false }
 
 @Serializable
-data class Project(val name: String, val language: String = "Kotlin")
+data class Project(
+    val name: String,
+    val language: String,
+    val version: String? = "1.2.2",
+    val website: String?,
+    val description: String? = null
+)
 
 fun main() {
-    val data = format.decodeFromString<Project>("""
-        {"name":"kotlinx.serialization","language":null}
-    """)
-    println(data)
+    val data = Project("kotlinx.serialization", "Kotlin", null, null, null)
+    val json = format.encodeToString(data)
+    println(json)
+    println(format.decodeFromString<Project>(json))
 }
diff --git a/guide/example/example-json-08.kt b/guide/example/example-json-08.kt
index 501a38eb..0eb68804 100644
--- a/guide/example/example-json-08.kt
+++ b/guide/example/example-json-08.kt
@@ -4,17 +4,14 @@ package example.exampleJson08
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-enum class Color { BLACK, WHITE }
+val format = Json { coerceInputValues = true }
 
 @Serializable
-data class Brush(val foreground: Color = Color.BLACK, val background: Color?)
-
-val json = Json { 
-  coerceInputValues = true
-  explicitNulls = false
-}
+data class Project(val name: String, val language: String = "Kotlin")
 
 fun main() {
-    val brush = json.decodeFromString<Brush>("""{"foreground":"pink", "background":"purple"}""")
-  println(brush)
+    val data = format.decodeFromString<Project>("""
+        {"name":"kotlinx.serialization","language":null}
+    """)
+    println(data)
 }
diff --git a/guide/example/example-json-09.kt b/guide/example/example-json-09.kt
index a0ed6329..ca880e1f 100644
--- a/guide/example/example-json-09.kt
+++ b/guide/example/example-json-09.kt
@@ -4,15 +4,17 @@ package example.exampleJson09
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-val format = Json { allowStructuredMapKeys = true }
+enum class Color { BLACK, WHITE }
 
 @Serializable
-data class Project(val name: String)
+data class Brush(val foreground: Color = Color.BLACK, val background: Color?)
+
+val json = Json { 
+  coerceInputValues = true
+  explicitNulls = false
+}
 
 fun main() {
-    val map = mapOf(
-        Project("kotlinx.serialization") to "Serialization",
-        Project("kotlinx.coroutines") to "Coroutines"
-    )
-    println(format.encodeToString(map))
+    val brush = json.decodeFromString<Brush>("""{"foreground":"pink", "background":"purple"}""")
+  println(brush)
 }
diff --git a/guide/example/example-json-10.kt b/guide/example/example-json-10.kt
index dc528bb6..427d1408 100644
--- a/guide/example/example-json-10.kt
+++ b/guide/example/example-json-10.kt
@@ -4,14 +4,15 @@ package example.exampleJson10
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-val format = Json { allowSpecialFloatingPointValues = true }
+val format = Json { allowStructuredMapKeys = true }
 
 @Serializable
-class Data(
-    val value: Double
-)
+data class Project(val name: String)
 
 fun main() {
-    val data = Data(Double.NaN)
-    println(format.encodeToString(data))
+    val map = mapOf(
+        Project("kotlinx.serialization") to "Serialization",
+        Project("kotlinx.coroutines") to "Coroutines"
+    )
+    println(format.encodeToString(map))
 }
diff --git a/guide/example/example-json-11.kt b/guide/example/example-json-11.kt
index 31f87315..b1d692fe 100644
--- a/guide/example/example-json-11.kt
+++ b/guide/example/example-json-11.kt
@@ -4,18 +4,14 @@ package example.exampleJson11
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-val format = Json { classDiscriminator = "#class" }
+val format = Json { allowSpecialFloatingPointValues = true }
 
 @Serializable
-sealed class Project {
-    abstract val name: String
-}
-
-@Serializable
-@SerialName("owned")
-class OwnedProject(override val name: String, val owner: String) : Project()
+class Data(
+    val value: Double
+)
 
 fun main() {
-    val data: Project = OwnedProject("kotlinx.coroutines", "kotlin")
+    val data = Data(Double.NaN)
     println(format.encodeToString(data))
 }
diff --git a/guide/example/example-json-12.kt b/guide/example/example-json-12.kt
index f3f11a67..15a796cb 100644
--- a/guide/example/example-json-12.kt
+++ b/guide/example/example-json-12.kt
@@ -4,29 +4,18 @@ package example.exampleJson12
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@OptIn(ExperimentalSerializationApi::class) // JsonClassDiscriminator is an experimental annotation for now
-@Serializable
-@JsonClassDiscriminator("message_type")
-sealed class Base
-
-@Serializable // Class discriminator is inherited from Base
-sealed class ErrorClass: Base()
-
-@Serializable
-data class Message(val message: Base, val error: ErrorClass?)
+val format = Json { classDiscriminator = "#class" }
 
 @Serializable
-@SerialName("my.app.BaseMessage")
-data class BaseMessage(val message: String) : Base()
+sealed class Project {
+    abstract val name: String
+}
 
 @Serializable
-@SerialName("my.app.GenericError")
-data class GenericError(@SerialName("error_code") val errorCode: Int) : ErrorClass()
-
-
-val format = Json { classDiscriminator = "#class" }
+@SerialName("owned")
+class OwnedProject(override val name: String, val owner: String) : Project()
 
 fun main() {
-    val data = Message(BaseMessage("not found"), GenericError(404))
+    val data: Project = OwnedProject("kotlinx.coroutines", "kotlin")
     println(format.encodeToString(data))
 }
diff --git a/guide/example/example-json-13.kt b/guide/example/example-json-13.kt
index 9794230c..f4d35057 100644
--- a/guide/example/example-json-13.kt
+++ b/guide/example/example-json-13.kt
@@ -4,18 +4,29 @@ package example.exampleJson13
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@OptIn(ExperimentalSerializationApi::class) // classDiscriminatorMode is an experimental setting for now
-val format = Json { classDiscriminatorMode = ClassDiscriminatorMode.NONE }
+@OptIn(ExperimentalSerializationApi::class) // JsonClassDiscriminator is an experimental annotation for now
+@Serializable
+@JsonClassDiscriminator("message_type")
+sealed class Base
+
+@Serializable // Class discriminator is inherited from Base
+sealed class ErrorClass: Base()
 
 @Serializable
-sealed class Project {
-    abstract val name: String
-}
+data class Message(val message: Base, val error: ErrorClass?)
 
 @Serializable
-class OwnedProject(override val name: String, val owner: String) : Project()
+@SerialName("my.app.BaseMessage")
+data class BaseMessage(val message: String) : Base()
+
+@Serializable
+@SerialName("my.app.GenericError")
+data class GenericError(@SerialName("error_code") val errorCode: Int) : ErrorClass()
+
+
+val format = Json { classDiscriminator = "#class" }
 
 fun main() {
-    val data: Project = OwnedProject("kotlinx.coroutines", "kotlin")
+    val data = Message(BaseMessage("not found"), GenericError(404))
     println(format.encodeToString(data))
 }
diff --git a/guide/example/example-json-14.kt b/guide/example/example-json-14.kt
index f0def0e4..1bc1f67d 100644
--- a/guide/example/example-json-14.kt
+++ b/guide/example/example-json-14.kt
@@ -4,15 +4,18 @@ package example.exampleJson14
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@OptIn(ExperimentalSerializationApi::class) // decodeEnumsCaseInsensitive is an experimental setting for now
-val format = Json { decodeEnumsCaseInsensitive = true }
+@OptIn(ExperimentalSerializationApi::class) // classDiscriminatorMode is an experimental setting for now
+val format = Json { classDiscriminatorMode = ClassDiscriminatorMode.NONE }
 
-@OptIn(ExperimentalSerializationApi::class) // JsonNames is an experimental annotation for now
-enum class Cases { VALUE_A, @JsonNames("Alternative") VALUE_B }
+@Serializable
+sealed class Project {
+    abstract val name: String
+}
 
 @Serializable
-data class CasesList(val cases: List<Cases>)
+class OwnedProject(override val name: String, val owner: String) : Project()
 
 fun main() {
-  println(format.decodeFromString<CasesList>("""{"cases":["value_A", "alternative"]}""")) 
+    val data: Project = OwnedProject("kotlinx.coroutines", "kotlin")
+    println(format.encodeToString(data))
 }
diff --git a/guide/example/example-json-15.kt b/guide/example/example-json-15.kt
index 267d5cc2..69067173 100644
--- a/guide/example/example-json-15.kt
+++ b/guide/example/example-json-15.kt
@@ -4,13 +4,15 @@ package example.exampleJson15
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@Serializable
-data class Project(val projectName: String, val projectOwner: String)
+@OptIn(ExperimentalSerializationApi::class) // decodeEnumsCaseInsensitive is an experimental setting for now
+val format = Json { decodeEnumsCaseInsensitive = true }
+
+@OptIn(ExperimentalSerializationApi::class) // JsonNames is an experimental annotation for now
+enum class Cases { VALUE_A, @JsonNames("Alternative") VALUE_B }
 
-@OptIn(ExperimentalSerializationApi::class) // namingStrategy is an experimental setting for now
-val format = Json { namingStrategy = JsonNamingStrategy.SnakeCase }
+@Serializable
+data class CasesList(val cases: List<Cases>)
 
 fun main() {
-    val project = format.decodeFromString<Project>("""{"project_name":"kotlinx.coroutines", "project_owner":"Kotlin"}""")
-    println(format.encodeToString(project.copy(projectName = "kotlinx.serialization")))
+  println(format.decodeFromString<CasesList>("""{"cases":["value_A", "alternative"]}""")) 
 }
diff --git a/guide/example/example-json-16.kt b/guide/example/example-json-16.kt
index eaa7c90a..c6b78ff5 100644
--- a/guide/example/example-json-16.kt
+++ b/guide/example/example-json-16.kt
@@ -4,54 +4,13 @@ package example.exampleJson16
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-import kotlinx.serialization.encoding.Encoder
-import kotlinx.serialization.encoding.Decoder
-import kotlinx.serialization.descriptors.*
-import kotlin.io.encoding.*
-
-@OptIn(ExperimentalEncodingApi::class)
-object ByteArrayAsBase64Serializer : KSerializer<ByteArray> {
-    private val base64 = Base64.Default
-
-    override val descriptor: SerialDescriptor
-        get() = PrimitiveSerialDescriptor(
-            "ByteArrayAsBase64Serializer",
-            PrimitiveKind.STRING
-        )
-
-    override fun serialize(encoder: Encoder, value: ByteArray) {
-        val base64Encoded = base64.encode(value)
-        encoder.encodeString(base64Encoded)
-    }
-
-    override fun deserialize(decoder: Decoder): ByteArray {
-        val base64Decoded = decoder.decodeString()
-        return base64.decode(base64Decoded)
-    }
-}
-
 @Serializable
-data class Value(
-    @Serializable(with = ByteArrayAsBase64Serializer::class)
-    val base64Input: ByteArray
-) {
-    override fun equals(other: Any?): Boolean {
-        if (this === other) return true
-        if (javaClass != other?.javaClass) return false
-        other as Value
-        return base64Input.contentEquals(other.base64Input)
-    }
+data class Project(val projectName: String, val projectOwner: String)
 
-    override fun hashCode(): Int {
-        return base64Input.contentHashCode()
-    }
-}
+@OptIn(ExperimentalSerializationApi::class) // namingStrategy is an experimental setting for now
+val format = Json { namingStrategy = JsonNamingStrategy.SnakeCase }
 
 fun main() {
-    val string = "foo string"
-    val value = Value(string.toByteArray())
-    val encoded = Json.encodeToString(value)
-    println(encoded)
-    val decoded = Json.decodeFromString<Value>(encoded)
-    println(decoded.base64Input.decodeToString())
+    val project = format.decodeFromString<Project>("""{"project_name":"kotlinx.coroutines", "project_owner":"Kotlin"}""")
+    println(format.encodeToString(project.copy(projectName = "kotlinx.serialization")))
 }
diff --git a/guide/example/example-json-17.kt b/guide/example/example-json-17.kt
index ba7177d6..0c0cbca7 100644
--- a/guide/example/example-json-17.kt
+++ b/guide/example/example-json-17.kt
@@ -4,9 +4,54 @@ package example.exampleJson17
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
+import kotlinx.serialization.encoding.Encoder
+import kotlinx.serialization.encoding.Decoder
+import kotlinx.serialization.descriptors.*
+import kotlin.io.encoding.*
+
+@OptIn(ExperimentalEncodingApi::class)
+object ByteArrayAsBase64Serializer : KSerializer<ByteArray> {
+    private val base64 = Base64.Default
+
+    override val descriptor: SerialDescriptor
+        get() = PrimitiveSerialDescriptor(
+            "ByteArrayAsBase64Serializer",
+            PrimitiveKind.STRING
+        )
+
+    override fun serialize(encoder: Encoder, value: ByteArray) {
+        val base64Encoded = base64.encode(value)
+        encoder.encodeString(base64Encoded)
+    }
+
+    override fun deserialize(decoder: Decoder): ByteArray {
+        val base64Decoded = decoder.decodeString()
+        return base64.decode(base64Decoded)
+    }
+}
+
+@Serializable
+data class Value(
+    @Serializable(with = ByteArrayAsBase64Serializer::class)
+    val base64Input: ByteArray
+) {
+    override fun equals(other: Any?): Boolean {
+        if (this === other) return true
+        if (javaClass != other?.javaClass) return false
+        other as Value
+        return base64Input.contentEquals(other.base64Input)
+    }
+
+    override fun hashCode(): Int {
+        return base64Input.contentHashCode()
+    }
+}
+
 fun main() {
-    val element = Json.parseToJsonElement("""
-        {"name":"kotlinx.serialization","language":"Kotlin"}
-    """)
-    println(element)
+    val string = "foo string"
+    val value = Value(string.toByteArray())
+    val encoded = Json.encodeToString(value)
+    println(encoded)
+    val decoded = Json.decodeFromString<Value>(encoded)
+    println(decoded.base64Input.decodeToString())
 }
diff --git a/guide/example/example-json-18.kt b/guide/example/example-json-18.kt
index f3786155..d2a582d6 100644
--- a/guide/example/example-json-18.kt
+++ b/guide/example/example-json-18.kt
@@ -6,13 +6,7 @@ import kotlinx.serialization.json.*
 
 fun main() {
     val element = Json.parseToJsonElement("""
-        {
-            "name": "kotlinx.serialization",
-            "forks": [{"votes": 42}, {"votes": 9000}, {}]
-        }
+        {"name":"kotlinx.serialization","language":"Kotlin"}
     """)
-    val sum = element
-        .jsonObject["forks"]!!
-        .jsonArray.sumOf { it.jsonObject["votes"]?.jsonPrimitive?.int ?: 0 }
-    println(sum)
+    println(element)
 }
diff --git a/guide/example/example-json-19.kt b/guide/example/example-json-19.kt
index 66ce99b7..6947efec 100644
--- a/guide/example/example-json-19.kt
+++ b/guide/example/example-json-19.kt
@@ -5,19 +5,14 @@ import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
 fun main() {
-    val element = buildJsonObject {
-        put("name", "kotlinx.serialization")
-        putJsonObject("owner") {
-            put("name", "kotlin")
+    val element = Json.parseToJsonElement("""
+        {
+            "name": "kotlinx.serialization",
+            "forks": [{"votes": 42}, {"votes": 9000}, {}]
         }
-        putJsonArray("forks") {
-            addJsonObject {
-                put("votes", 42)
-            }
-            addJsonObject {
-                put("votes", 9000)
-            }
-        }
-    }
-    println(element)
+    """)
+    val sum = element
+        .jsonObject["forks"]!!
+        .jsonArray.sumOf { it.jsonObject["votes"]?.jsonPrimitive?.int ?: 0 }
+    println(sum)
 }
diff --git a/guide/example/example-json-20.kt b/guide/example/example-json-20.kt
index 8f1c786e..81c27e59 100644
--- a/guide/example/example-json-20.kt
+++ b/guide/example/example-json-20.kt
@@ -4,14 +4,20 @@ package example.exampleJson20
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@Serializable
-data class Project(val name: String, val language: String)
-
 fun main() {
     val element = buildJsonObject {
         put("name", "kotlinx.serialization")
-        put("language", "Kotlin")
+        putJsonObject("owner") {
+            put("name", "kotlin")
+        }
+        putJsonArray("forks") {
+            addJsonObject {
+                put("votes", 42)
+            }
+            addJsonObject {
+                put("votes", 9000)
+            }
+        }
     }
-    val data = Json.decodeFromJsonElement<Project>(element)
-    println(data)
+    println(element)
 }
diff --git a/guide/example/example-json-21.kt b/guide/example/example-json-21.kt
index 2b1d1109..f00d50d3 100644
--- a/guide/example/example-json-21.kt
+++ b/guide/example/example-json-21.kt
@@ -4,20 +4,14 @@ package example.exampleJson21
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-import java.math.BigDecimal
-
-val format = Json { prettyPrint = true }
+@Serializable
+data class Project(val name: String, val language: String)
 
 fun main() {
-    val pi = BigDecimal("3.141592653589793238462643383279")
-    
-    val piJsonDouble = JsonPrimitive(pi.toDouble())
-    val piJsonString = JsonPrimitive(pi.toString())
-  
-    val piObject = buildJsonObject {
-        put("pi_double", piJsonDouble)
-        put("pi_string", piJsonString)
+    val element = buildJsonObject {
+        put("name", "kotlinx.serialization")
+        put("language", "Kotlin")
     }
-
-    println(format.encodeToString(piObject))
+    val data = Json.decodeFromJsonElement<Project>(element)
+    println(data)
 }
diff --git a/guide/example/example-json-22.kt b/guide/example/example-json-22.kt
index f334ce5f..180853c0 100644
--- a/guide/example/example-json-22.kt
+++ b/guide/example/example-json-22.kt
@@ -10,16 +10,11 @@ val format = Json { prettyPrint = true }
 
 fun main() {
     val pi = BigDecimal("3.141592653589793238462643383279")
-
-    // use JsonUnquotedLiteral to encode raw JSON content
-    @OptIn(ExperimentalSerializationApi::class)
-    val piJsonLiteral = JsonUnquotedLiteral(pi.toString())
-
+    
     val piJsonDouble = JsonPrimitive(pi.toDouble())
     val piJsonString = JsonPrimitive(pi.toString())
   
     val piObject = buildJsonObject {
-        put("pi_literal", piJsonLiteral)
         put("pi_double", piJsonDouble)
         put("pi_string", piJsonString)
     }
diff --git a/guide/example/example-json-23.kt b/guide/example/example-json-23.kt
index 14f70e23..3e2863ef 100644
--- a/guide/example/example-json-23.kt
+++ b/guide/example/example-json-23.kt
@@ -6,18 +6,23 @@ import kotlinx.serialization.json.*
 
 import java.math.BigDecimal
 
+val format = Json { prettyPrint = true }
+
 fun main() {
-    val piObjectJson = """
-          {
-              "pi_literal": 3.141592653589793238462643383279
-          }
-      """.trimIndent()
-    
-    val piObject: JsonObject = Json.decodeFromString(piObjectJson)
-    
-    val piJsonLiteral = piObject["pi_literal"]!!.jsonPrimitive.content
-    
-    val pi = BigDecimal(piJsonLiteral)
-    
-    println(pi)
+    val pi = BigDecimal("3.141592653589793238462643383279")
+
+    // use JsonUnquotedLiteral to encode raw JSON content
+    @OptIn(ExperimentalSerializationApi::class)
+    val piJsonLiteral = JsonUnquotedLiteral(pi.toString())
+
+    val piJsonDouble = JsonPrimitive(pi.toDouble())
+    val piJsonString = JsonPrimitive(pi.toString())
+  
+    val piObject = buildJsonObject {
+        put("pi_literal", piJsonLiteral)
+        put("pi_double", piJsonDouble)
+        put("pi_string", piJsonString)
+    }
+
+    println(format.encodeToString(piObject))
 }
diff --git a/guide/example/example-json-24.kt b/guide/example/example-json-24.kt
index 3452c6ce..7298ee6b 100644
--- a/guide/example/example-json-24.kt
+++ b/guide/example/example-json-24.kt
@@ -4,8 +4,20 @@ package example.exampleJson24
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-@OptIn(ExperimentalSerializationApi::class)
+import java.math.BigDecimal
+
 fun main() {
-    // caution: creating null with JsonUnquotedLiteral will cause an exception! 
-    JsonUnquotedLiteral("null")
+    val piObjectJson = """
+          {
+              "pi_literal": 3.141592653589793238462643383279
+          }
+      """.trimIndent()
+    
+    val piObject: JsonObject = Json.decodeFromString(piObjectJson)
+    
+    val piJsonLiteral = piObject["pi_literal"]!!.jsonPrimitive.content
+    
+    val pi = BigDecimal(piJsonLiteral)
+    
+    println(pi)
 }
diff --git a/guide/example/example-json-25.kt b/guide/example/example-json-25.kt
index 67c3bf5a..28a27da3 100644
--- a/guide/example/example-json-25.kt
+++ b/guide/example/example-json-25.kt
@@ -4,29 +4,8 @@ package example.exampleJson25
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-import kotlinx.serialization.builtins.*
-
-@Serializable
-data class Project(
-    val name: String,
-    @Serializable(with = UserListSerializer::class)
-    val users: List<User>
-)
-
-@Serializable
-data class User(val name: String)
-
-object UserListSerializer : JsonTransformingSerializer<List<User>>(ListSerializer(User.serializer())) {
-    // If response is not an array, then it is a single object that should be wrapped into the array
-    override fun transformDeserialize(element: JsonElement): JsonElement =
-        if (element !is JsonArray) JsonArray(listOf(element)) else element
-}
-
+@OptIn(ExperimentalSerializationApi::class)
 fun main() {
-    println(Json.decodeFromString<Project>("""
-        {"name":"kotlinx.serialization","users":{"name":"kotlin"}}
-    """))
-    println(Json.decodeFromString<Project>("""
-        {"name":"kotlinx.serialization","users":[{"name":"kotlin"},{"name":"jetbrains"}]}
-    """))
+    // caution: creating null with JsonUnquotedLiteral will cause an exception! 
+    JsonUnquotedLiteral("null")
 }
diff --git a/guide/example/example-json-26.kt b/guide/example/example-json-26.kt
index 812e4967..6ff4a286 100644
--- a/guide/example/example-json-26.kt
+++ b/guide/example/example-json-26.kt
@@ -17,14 +17,16 @@ data class Project(
 data class User(val name: String)
 
 object UserListSerializer : JsonTransformingSerializer<List<User>>(ListSerializer(User.serializer())) {
-
-    override fun transformSerialize(element: JsonElement): JsonElement {
-        require(element is JsonArray) // this serializer is used only with lists
-        return element.singleOrNull() ?: element
-    }
+    // If response is not an array, then it is a single object that should be wrapped into the array
+    override fun transformDeserialize(element: JsonElement): JsonElement =
+        if (element !is JsonArray) JsonArray(listOf(element)) else element
 }
 
 fun main() {
-    val data = Project("kotlinx.serialization", listOf(User("kotlin")))
-    println(Json.encodeToString(data))
+    println(Json.decodeFromString<Project>("""
+        {"name":"kotlinx.serialization","users":{"name":"kotlin"}}
+    """))
+    println(Json.decodeFromString<Project>("""
+        {"name":"kotlinx.serialization","users":[{"name":"kotlin"},{"name":"jetbrains"}]}
+    """))
 }
diff --git a/guide/example/example-json-27.kt b/guide/example/example-json-27.kt
index e28b50ad..111d6a1c 100644
--- a/guide/example/example-json-27.kt
+++ b/guide/example/example-json-27.kt
@@ -4,19 +4,27 @@ package example.exampleJson27
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
+import kotlinx.serialization.builtins.*
+
+@Serializable
+data class Project(
+    val name: String,
+    @Serializable(with = UserListSerializer::class)
+    val users: List<User>
+)
+
 @Serializable
-class Project(val name: String, val language: String)
+data class User(val name: String)
+
+object UserListSerializer : JsonTransformingSerializer<List<User>>(ListSerializer(User.serializer())) {
 
-object ProjectSerializer : JsonTransformingSerializer<Project>(Project.serializer()) {
-    override fun transformSerialize(element: JsonElement): JsonElement =
-        // Filter out top-level key value pair with the key "language" and the value "Kotlin"
-        JsonObject(element.jsonObject.filterNot {
-            (k, v) -> k == "language" && v.jsonPrimitive.content == "Kotlin"
-        })
+    override fun transformSerialize(element: JsonElement): JsonElement {
+        require(element is JsonArray) // this serializer is used only with lists
+        return element.singleOrNull() ?: element
+    }
 }
 
 fun main() {
-    val data = Project("kotlinx.serialization", "Kotlin")
-    println(Json.encodeToString(data)) // using plugin-generated serializer
-    println(Json.encodeToString(ProjectSerializer, data)) // using custom serializer
+    val data = Project("kotlinx.serialization", listOf(User("kotlin")))
+    println(Json.encodeToString(data))
 }
diff --git a/guide/example/example-json-28.kt b/guide/example/example-json-28.kt
index 52ca872c..02553549 100644
--- a/guide/example/example-json-28.kt
+++ b/guide/example/example-json-28.kt
@@ -4,33 +4,19 @@ package example.exampleJson28
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-import kotlinx.serialization.builtins.*
-
-@Serializable
-abstract class Project {
-    abstract val name: String
-}
-
 @Serializable
-data class BasicProject(override val name: String): Project()
-
-
-@Serializable
-data class OwnedProject(override val name: String, val owner: String) : Project()
-
-object ProjectSerializer : JsonContentPolymorphicSerializer<Project>(Project::class) {
-    override fun selectDeserializer(element: JsonElement) = when {
-        "owner" in element.jsonObject -> OwnedProject.serializer()
-        else -> BasicProject.serializer()
-    }
+class Project(val name: String, val language: String)
+
+object ProjectSerializer : JsonTransformingSerializer<Project>(Project.serializer()) {
+    override fun transformSerialize(element: JsonElement): JsonElement =
+        // Filter out top-level key value pair with the key "language" and the value "Kotlin"
+        JsonObject(element.jsonObject.filterNot {
+            (k, v) -> k == "language" && v.jsonPrimitive.content == "Kotlin"
+        })
 }
 
 fun main() {
-    val data = listOf(
-        OwnedProject("kotlinx.serialization", "kotlin"),
-        BasicProject("example")
-    )
-    val string = Json.encodeToString(ListSerializer(ProjectSerializer), data)
-    println(string)
-    println(Json.decodeFromString(ListSerializer(ProjectSerializer), string))
+    val data = Project("kotlinx.serialization", "Kotlin")
+    println(Json.encodeToString(data)) // using plugin-generated serializer
+    println(Json.encodeToString(ProjectSerializer, data)) // using custom serializer
 }
diff --git a/guide/example/example-json-29.kt b/guide/example/example-json-29.kt
index 41245ffb..9c37b126 100644
--- a/guide/example/example-json-29.kt
+++ b/guide/example/example-json-29.kt
@@ -4,31 +4,33 @@ package example.exampleJson29
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
+import kotlinx.serialization.builtins.*
+
 @Serializable
-sealed class Project {
+abstract class Project {
     abstract val name: String
 }
 
-@OptIn(ExperimentalSerializationApi::class)
-@KeepGeneratedSerializer
-@Serializable(with = BasicProjectSerializer::class)
-@SerialName("basic")
+@Serializable
 data class BasicProject(override val name: String): Project()
 
-object BasicProjectSerializer : JsonTransformingSerializer<BasicProject>(BasicProject.generatedSerializer()) {
-    override fun transformDeserialize(element: JsonElement): JsonElement {
-        val jsonObject = element.jsonObject
-        return if ("basic-name" in jsonObject) {
-            val nameElement = jsonObject["basic-name"] ?: throw IllegalStateException()
-            JsonObject(mapOf("name" to nameElement))
-        } else {
-            jsonObject
-        }
+
+@Serializable
+data class OwnedProject(override val name: String, val owner: String) : Project()
+
+object ProjectSerializer : JsonContentPolymorphicSerializer<Project>(Project::class) {
+    override fun selectDeserializer(element: JsonElement) = when {
+        "owner" in element.jsonObject -> OwnedProject.serializer()
+        else -> BasicProject.serializer()
     }
 }
 
-
 fun main() {
-    val project = Json.decodeFromString<Project>("""{"type":"basic","basic-name":"example"}""")
-    println(project)
+    val data = listOf(
+        OwnedProject("kotlinx.serialization", "kotlin"),
+        BasicProject("example")
+    )
+    val string = Json.encodeToString(ListSerializer(ProjectSerializer), data)
+    println(string)
+    println(Json.decodeFromString(ListSerializer(ProjectSerializer), string))
 }
diff --git a/guide/example/example-json-30.kt b/guide/example/example-json-30.kt
index fe379dff..9833fb99 100644
--- a/guide/example/example-json-30.kt
+++ b/guide/example/example-json-30.kt
@@ -4,56 +4,31 @@ package example.exampleJson30
 import kotlinx.serialization.*
 import kotlinx.serialization.json.*
 
-import kotlinx.serialization.descriptors.*
-import kotlinx.serialization.encoding.*
-
-@Serializable(with = ResponseSerializer::class)
-sealed class Response<out T> {
-    data class Ok<out T>(val data: T) : Response<T>()
-    data class Error(val message: String) : Response<Nothing>()
+@Serializable
+sealed class Project {
+    abstract val name: String
 }
 
-class ResponseSerializer<T>(private val dataSerializer: KSerializer<T>) : KSerializer<Response<T>> {
-    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Response") {
-        element("Ok", dataSerializer.descriptor)
-        element("Error", buildClassSerialDescriptor("Error") {
-          element<String>("message")
-        })
-    }
-
-    override fun deserialize(decoder: Decoder): Response<T> {
-        // Decoder -> JsonDecoder
-        require(decoder is JsonDecoder) // this class can be decoded only by Json
-        // JsonDecoder -> JsonElement
-        val element = decoder.decodeJsonElement()
-        // JsonElement -> value
-        if (element is JsonObject && "error" in element)
-            return Response.Error(element["error"]!!.jsonPrimitive.content)
-        return Response.Ok(decoder.json.decodeFromJsonElement(dataSerializer, element))
-    }
-
-    override fun serialize(encoder: Encoder, value: Response<T>) {
-        // Encoder -> JsonEncoder
-        require(encoder is JsonEncoder) // This class can be encoded only by Json
-        // value -> JsonElement
-        val element = when (value) {
-            is Response.Ok -> encoder.json.encodeToJsonElement(dataSerializer, value.data)
-            is Response.Error -> buildJsonObject { put("error", value.message) }
+@OptIn(ExperimentalSerializationApi::class)
+@KeepGeneratedSerializer
+@Serializable(with = BasicProjectSerializer::class)
+@SerialName("basic")
+data class BasicProject(override val name: String): Project()
+
+object BasicProjectSerializer : JsonTransformingSerializer<BasicProject>(BasicProject.generatedSerializer()) {
+    override fun transformDeserialize(element: JsonElement): JsonElement {
+        val jsonObject = element.jsonObject
+        return if ("basic-name" in jsonObject) {
+            val nameElement = jsonObject["basic-name"] ?: throw IllegalStateException()
+            JsonObject(mapOf("name" to nameElement))
+        } else {
+            jsonObject
         }
-        // JsonElement -> JsonEncoder
-        encoder.encodeJsonElement(element)
     }
 }
 
-@Serializable
-data class Project(val name: String)
 
 fun main() {
-    val responses = listOf(
-        Response.Ok(Project("kotlinx.serialization")),
-        Response.Error("Not found")
-    )
-    val string = Json.encodeToString(responses)
-    println(string)
-    println(Json.decodeFromString<List<Response<Project>>>(string))
+    val project = Json.decodeFromString<Project>("""{"type":"basic","basic-name":"example"}""")
+    println(project)
 }
diff --git a/guide/example/example-json-31.kt b/guide/example/example-json-31.kt
index faaa0ff6..1e636ba9 100644
--- a/guide/example/example-json-31.kt
+++ b/guide/example/example-json-31.kt
@@ -7,31 +7,53 @@ import kotlinx.serialization.json.*
 import kotlinx.serialization.descriptors.*
 import kotlinx.serialization.encoding.*
 
-data class UnknownProject(val name: String, val details: JsonObject)
+@Serializable(with = ResponseSerializer::class)
+sealed class Response<out T> {
+    data class Ok<out T>(val data: T) : Response<T>()
+    data class Error(val message: String) : Response<Nothing>()
+}
 
-object UnknownProjectSerializer : KSerializer<UnknownProject> {
-    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("UnknownProject") {
-        element<String>("name")
-        element<JsonElement>("details")
+class ResponseSerializer<T>(private val dataSerializer: KSerializer<T>) : KSerializer<Response<T>> {
+    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Response") {
+        element("Ok", dataSerializer.descriptor)
+        element("Error", buildClassSerialDescriptor("Error") {
+          element<String>("message")
+        })
     }
 
-    override fun deserialize(decoder: Decoder): UnknownProject {
-        // Cast to JSON-specific interface
-        val jsonInput = decoder as? JsonDecoder ?: error("Can be deserialized only by JSON")
-        // Read the whole content as JSON
-        val json = jsonInput.decodeJsonElement().jsonObject
-        // Extract and remove name property
-        val name = json.getValue("name").jsonPrimitive.content
-        val details = json.toMutableMap()
-        details.remove("name")
-        return UnknownProject(name, JsonObject(details))
+    override fun deserialize(decoder: Decoder): Response<T> {
+        // Decoder -> JsonDecoder
+        require(decoder is JsonDecoder) // this class can be decoded only by Json
+        // JsonDecoder -> JsonElement
+        val element = decoder.decodeJsonElement()
+        // JsonElement -> value
+        if (element is JsonObject && "error" in element)
+            return Response.Error(element["error"]!!.jsonPrimitive.content)
+        return Response.Ok(decoder.json.decodeFromJsonElement(dataSerializer, element))
     }
 
-    override fun serialize(encoder: Encoder, value: UnknownProject) {
-        error("Serialization is not supported")
+    override fun serialize(encoder: Encoder, value: Response<T>) {
+        // Encoder -> JsonEncoder
+        require(encoder is JsonEncoder) // This class can be encoded only by Json
+        // value -> JsonElement
+        val element = when (value) {
+            is Response.Ok -> encoder.json.encodeToJsonElement(dataSerializer, value.data)
+            is Response.Error -> buildJsonObject { put("error", value.message) }
+        }
+        // JsonElement -> JsonEncoder
+        encoder.encodeJsonElement(element)
     }
 }
 
+@Serializable
+data class Project(val name: String)
+
 fun main() {
-    println(Json.decodeFromString(UnknownProjectSerializer, """{"type":"unknown","name":"example","maintainer":"Unknown","license":"Apache 2.0"}"""))
+    val responses = listOf(
+        Response.Ok(Project("kotlinx.serialization")),
+        Response.Error("Not found")
+    )
+    val string = Json.encodeToString(responses)
+    println(string)
+    println(Json.decodeFromString<List<Response<Project>>>(string))
 }
diff --git a/guide/example/example-json-32.kt b/guide/example/example-json-32.kt
new file mode 100644
index 00000000..324a08f3
--- /dev/null
+++ b/guide/example/example-json-32.kt
@@ -0,0 +1,37 @@
+// This file was automatically generated from json.md by Knit tool. Do not edit.
+package example.exampleJson32
+
+import kotlinx.serialization.*
+import kotlinx.serialization.json.*
+
+import kotlinx.serialization.descriptors.*
+import kotlinx.serialization.encoding.*
+
+data class UnknownProject(val name: String, val details: JsonObject)
+
+object UnknownProjectSerializer : KSerializer<UnknownProject> {
+    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("UnknownProject") {
+        element<String>("name")
+        element<JsonElement>("details")
+    }
+
+    override fun deserialize(decoder: Decoder): UnknownProject {
+        // Cast to JSON-specific interface
+        val jsonInput = decoder as? JsonDecoder ?: error("Can be deserialized only by JSON")
+        // Read the whole content as JSON
+        val json = jsonInput.decodeJsonElement().jsonObject
+        // Extract and remove name property
+        val name = json.getValue("name").jsonPrimitive.content
+        val details = json.toMutableMap()
+        details.remove("name")
+        return UnknownProject(name, JsonObject(details))
+    }
+
+    override fun serialize(encoder: Encoder, value: UnknownProject) {
+        error("Serialization is not supported")
+    }
+}
+
+fun main() {
+    println(Json.decodeFromString(UnknownProjectSerializer, """{"type":"unknown","name":"example","maintainer":"Unknown","license":"Apache 2.0"}"""))
+}
diff --git a/guide/example/example-serializer-07.kt b/guide/example/example-serializer-07.kt
index 3ebafa21..c1459883 100644
--- a/guide/example/example-serializer-07.kt
+++ b/guide/example/example-serializer-07.kt
@@ -7,7 +7,8 @@ import kotlinx.serialization.encoding.*
 import kotlinx.serialization.descriptors.*
 
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    // Serial names of descriptors should be unique, this is why we advise including app package in the name.
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
diff --git a/guide/example/example-serializer-08.kt b/guide/example/example-serializer-08.kt
index 73c8c810..33b61bca 100644
--- a/guide/example/example-serializer-08.kt
+++ b/guide/example/example-serializer-08.kt
@@ -7,7 +7,7 @@ import kotlinx.serialization.encoding.*
 import kotlinx.serialization.descriptors.*
 
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
diff --git a/guide/example/example-serializer-09.kt b/guide/example/example-serializer-09.kt
index 4fe71119..1192942b 100644
--- a/guide/example/example-serializer-09.kt
+++ b/guide/example/example-serializer-09.kt
@@ -7,7 +7,7 @@ import kotlinx.serialization.encoding.*
 import kotlinx.serialization.descriptors.*
 
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
diff --git a/guide/example/example-serializer-10.kt b/guide/example/example-serializer-10.kt
index a69deceb..74846a4b 100644
--- a/guide/example/example-serializer-10.kt
+++ b/guide/example/example-serializer-10.kt
@@ -10,8 +10,9 @@ import kotlinx.serialization.builtins.IntArraySerializer
 
 class ColorIntArraySerializer : KSerializer<Color> {
     private val delegateSerializer = IntArraySerializer()
-    @OptIn(ExperimentalSerializationApi::class)
-    override val descriptor = SerialDescriptor("Color", delegateSerializer.descriptor)
+
+    // Serial names of descriptors should be unique, this is why we advise including app package in the name.
+    override val descriptor = SerialDescriptor("my.app.Color", delegateSerializer.descriptor)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val data = intArrayOf(
diff --git a/guide/example/example-serializer-11.kt b/guide/example/example-serializer-11.kt
index 3931aa02..477de1a7 100644
--- a/guide/example/example-serializer-11.kt
+++ b/guide/example/example-serializer-11.kt
@@ -15,7 +15,8 @@ private class ColorSurrogate(val r: Int, val g: Int, val b: Int) {
 }
 
 object ColorSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = ColorSurrogate.serializer().descriptor
+    // Serial names of descriptors should be unique, so we cannot use ColorSurrogate.serializer().descriptor directly
+    override val descriptor: SerialDescriptor = SerialDescriptor("my.app.Color", ColorSurrogate.serializer().descriptor)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val surrogate = ColorSurrogate((value.rgb shr 16) and 0xff, (value.rgb shr 8) and 0xff, value.rgb and 0xff)
diff --git a/guide/example/example-serializer-12.kt b/guide/example/example-serializer-12.kt
index e53c7032..1a587e59 100644
--- a/guide/example/example-serializer-12.kt
+++ b/guide/example/example-serializer-12.kt
@@ -9,7 +9,7 @@ import kotlinx.serialization.descriptors.*
 object ColorAsObjectSerializer : KSerializer<Color> {
 
     override val descriptor: SerialDescriptor =
-        buildClassSerialDescriptor("Color") {
+        buildClassSerialDescriptor("my.app.Color") {
             element<Int>("r")
             element<Int>("g")
             element<Int>("b")
diff --git a/guide/example/example-serializer-13.kt b/guide/example/example-serializer-13.kt
index 8de0c8e5..4dbb7e49 100644
--- a/guide/example/example-serializer-13.kt
+++ b/guide/example/example-serializer-13.kt
@@ -9,7 +9,7 @@ import kotlinx.serialization.descriptors.*
 object ColorAsObjectSerializer : KSerializer<Color> {
 
     override val descriptor: SerialDescriptor =
-        buildClassSerialDescriptor("Color") {
+        buildClassSerialDescriptor("my.app.Color") {
             element<Int>("r")
             element<Int>("g")
             element<Int>("b")
diff --git a/guide/example/example-serializer-14.kt b/guide/example/example-serializer-14.kt
index 684290d7..7d8d7e41 100644
--- a/guide/example/example-serializer-14.kt
+++ b/guide/example/example-serializer-14.kt
@@ -10,7 +10,8 @@ import java.util.Date
 import java.text.SimpleDateFormat
 
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    // Serial names of descriptors should be unique, so choose app-specific name in case some library also would declare a serializer for Date.
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
diff --git a/guide/example/example-serializer-15.kt b/guide/example/example-serializer-15.kt
index a508846f..f3c4692b 100644
--- a/guide/example/example-serializer-15.kt
+++ b/guide/example/example-serializer-15.kt
@@ -10,7 +10,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
diff --git a/guide/example/example-serializer-16.kt b/guide/example/example-serializer-16.kt
index 3db0b7ff..afe60f92 100644
--- a/guide/example/example-serializer-16.kt
+++ b/guide/example/example-serializer-16.kt
@@ -10,7 +10,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
diff --git a/guide/example/example-serializer-17.kt b/guide/example/example-serializer-17.kt
index c5624ed3..a637ff07 100644
--- a/guide/example/example-serializer-17.kt
+++ b/guide/example/example-serializer-17.kt
@@ -11,7 +11,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
diff --git a/guide/example/example-serializer-18.kt b/guide/example/example-serializer-18.kt
index b1ce1c9c..70c29f67 100644
--- a/guide/example/example-serializer-18.kt
+++ b/guide/example/example-serializer-18.kt
@@ -11,13 +11,13 @@ import java.util.TimeZone
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("DateAsLong", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
 
 object DateAsSimpleTextSerializer: KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("DateAsSimpleText", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsSimpleText", PrimitiveKind.LONG)
     private val format = SimpleDateFormat("yyyy-MM-dd").apply {
         // Here we explicitly set time zone to UTC so output for this sample remains locale-independent.
         // Depending on your needs, you may have to adjust or remove this line.
diff --git a/guide/example/example-serializer-19.kt b/guide/example/example-serializer-19.kt
index 4622665a..47a0971f 100644
--- a/guide/example/example-serializer-19.kt
+++ b/guide/example/example-serializer-19.kt
@@ -10,7 +10,7 @@ import kotlinx.serialization.descriptors.*
 data class Box<T>(val contents: T) 
 
 class BoxSerializer<T>(private val dataSerializer: KSerializer<T>) : KSerializer<Box<T>> {
-    override val descriptor: SerialDescriptor = dataSerializer.descriptor
+    override val descriptor: SerialDescriptor = SerialDescriptor("my.app.Box", dataSerializer.descriptor)
     override fun serialize(encoder: Encoder, value: Box<T>) = dataSerializer.serialize(encoder, value.contents)
     override fun deserialize(decoder: Decoder) = Box(dataSerializer.deserialize(decoder))
 }
diff --git a/guide/example/example-serializer-20.kt b/guide/example/example-serializer-20.kt
index 812c05b8..053f99df 100644
--- a/guide/example/example-serializer-20.kt
+++ b/guide/example/example-serializer-20.kt
@@ -7,7 +7,7 @@ import kotlinx.serialization.encoding.*
 import kotlinx.serialization.descriptors.*
 
 object ColorAsStringSerializer : KSerializer<Color> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Color", PrimitiveKind.STRING)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.Color", PrimitiveKind.STRING)
 
     override fun serialize(encoder: Encoder, value: Color) {
         val string = value.rgb.toString(16).padStart(6, '0')
diff --git a/guide/example/example-serializer-22.kt b/guide/example/example-serializer-22.kt
index c2360306..326e184e 100644
--- a/guide/example/example-serializer-22.kt
+++ b/guide/example/example-serializer-22.kt
@@ -11,7 +11,7 @@ import java.util.Date
 import java.text.SimpleDateFormat
   
 object DateAsLongSerializer : KSerializer<Date> {
-    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
+    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("my.app.DateAsLong", PrimitiveKind.LONG)
     override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
     override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
 }
diff --git a/guide/test/BasicSerializationTest.kt b/guide/test/BasicSerializationTest.kt
index 11f9e9f2..a4450254 100644
--- a/guide/test/BasicSerializationTest.kt
+++ b/guide/test/BasicSerializationTest.kt
@@ -79,8 +79,8 @@ class BasicSerializationTest {
     @Test
     fun testExampleClasses08() {
         captureOutput("ExampleClasses08") { example.exampleClasses08.main() }.verifyOutputLinesStart(
-            "Exception in thread \"main\" kotlinx.serialization.json.internal.JsonDecodingException: Unexpected JSON token at offset 42: Encountered an unknown key 'language' at path: $.name",
-            "Use 'ignoreUnknownKeys = true' in 'Json {}' builder to ignore unknown keys."
+            "Exception in thread \"main\" kotlinx.serialization.json.internal.JsonDecodingException: Encountered an unknown key 'language' at offset 42 at path: $",
+            "Use 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys."
         )
     }
 
diff --git a/guide/test/JsonTest.kt b/guide/test/JsonTest.kt
index 35de209a..cf46cfb6 100644
--- a/guide/test/JsonTest.kt
+++ b/guide/test/JsonTest.kt
@@ -31,133 +31,133 @@ class JsonTest {
 
     @Test
     fun testExampleJson04() {
-        captureOutput("ExampleJson04") { example.exampleJson04.main() }.verifyOutputLines(
-            "Project(name=kotlinx.serialization)",
-            "Project(name=kotlinx.coroutines)"
+        captureOutput("ExampleJson04") { example.exampleJson04.main() }.verifyOutputLinesStart(
+            "Outer(a=1, inner=Inner(x=value))",
+            "",
+            "Exception in thread \"main\" kotlinx.serialization.json.internal.JsonDecodingException: Encountered an unknown key 'unknownKey' at offset 29 at path: $.inner",
+            "Use 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys."
         )
     }
 
     @Test
     fun testExampleJson05() {
         captureOutput("ExampleJson05") { example.exampleJson05.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\",\"website\":null}"
+            "Project(name=kotlinx.serialization)",
+            "Project(name=kotlinx.coroutines)"
         )
     }
 
     @Test
     fun testExampleJson06() {
         captureOutput("ExampleJson06") { example.exampleJson06.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\"}",
-            "Project(name=kotlinx.serialization, language=Kotlin, version=1.2.2, website=null, description=null)"
+            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\",\"website\":null}"
         )
     }
 
     @Test
     fun testExampleJson07() {
         captureOutput("ExampleJson07") { example.exampleJson07.main() }.verifyOutputLines(
-            "Project(name=kotlinx.serialization, language=Kotlin)"
+            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\"}",
+            "Project(name=kotlinx.serialization, language=Kotlin, version=1.2.2, website=null, description=null)"
         )
     }
 
     @Test
     fun testExampleJson08() {
         captureOutput("ExampleJson08") { example.exampleJson08.main() }.verifyOutputLines(
-            "Brush(foreground=BLACK, background=null)"
+            "Project(name=kotlinx.serialization, language=Kotlin)"
         )
     }
 
     @Test
     fun testExampleJson09() {
         captureOutput("ExampleJson09") { example.exampleJson09.main() }.verifyOutputLines(
-            "[{\"name\":\"kotlinx.serialization\"},\"Serialization\",{\"name\":\"kotlinx.coroutines\"},\"Coroutines\"]"
+            "Brush(foreground=BLACK, background=null)"
         )
     }
 
     @Test
     fun testExampleJson10() {
         captureOutput("ExampleJson10") { example.exampleJson10.main() }.verifyOutputLines(
-            "{\"value\":NaN}"
+            "[{\"name\":\"kotlinx.serialization\"},\"Serialization\",{\"name\":\"kotlinx.coroutines\"},\"Coroutines\"]"
         )
     }
 
     @Test
     fun testExampleJson11() {
         captureOutput("ExampleJson11") { example.exampleJson11.main() }.verifyOutputLines(
-            "{\"#class\":\"owned\",\"name\":\"kotlinx.coroutines\",\"owner\":\"kotlin\"}"
+            "{\"value\":NaN}"
         )
     }
 
     @Test
     fun testExampleJson12() {
         captureOutput("ExampleJson12") { example.exampleJson12.main() }.verifyOutputLines(
-            "{\"message\":{\"message_type\":\"my.app.BaseMessage\",\"message\":\"not found\"},\"error\":{\"message_type\":\"my.app.GenericError\",\"error_code\":404}}"
+            "{\"#class\":\"owned\",\"name\":\"kotlinx.coroutines\",\"owner\":\"kotlin\"}"
         )
     }
 
     @Test
     fun testExampleJson13() {
         captureOutput("ExampleJson13") { example.exampleJson13.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.coroutines\",\"owner\":\"kotlin\"}"
+            "{\"message\":{\"message_type\":\"my.app.BaseMessage\",\"message\":\"not found\"},\"error\":{\"message_type\":\"my.app.GenericError\",\"error_code\":404}}"
         )
     }
 
     @Test
     fun testExampleJson14() {
         captureOutput("ExampleJson14") { example.exampleJson14.main() }.verifyOutputLines(
-            "CasesList(cases=[VALUE_A, VALUE_B])"
+            "{\"name\":\"kotlinx.coroutines\",\"owner\":\"kotlin\"}"
         )
     }
 
     @Test
     fun testExampleJson15() {
         captureOutput("ExampleJson15") { example.exampleJson15.main() }.verifyOutputLines(
-            "{\"project_name\":\"kotlinx.serialization\",\"project_owner\":\"Kotlin\"}"
+            "CasesList(cases=[VALUE_A, VALUE_B])"
         )
     }
 
     @Test
     fun testExampleJson16() {
         captureOutput("ExampleJson16") { example.exampleJson16.main() }.verifyOutputLines(
-            "{\"base64Input\":\"Zm9vIHN0cmluZw==\"}",
-            "foo string"
+            "{\"project_name\":\"kotlinx.serialization\",\"project_owner\":\"Kotlin\"}"
         )
     }
 
     @Test
     fun testExampleJson17() {
         captureOutput("ExampleJson17") { example.exampleJson17.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\"}"
+            "{\"base64Input\":\"Zm9vIHN0cmluZw==\"}",
+            "foo string"
         )
     }
 
     @Test
     fun testExampleJson18() {
         captureOutput("ExampleJson18") { example.exampleJson18.main() }.verifyOutputLines(
-            "9042"
+            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\"}"
         )
     }
 
     @Test
     fun testExampleJson19() {
         captureOutput("ExampleJson19") { example.exampleJson19.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.serialization\",\"owner\":{\"name\":\"kotlin\"},\"forks\":[{\"votes\":42},{\"votes\":9000}]}"
+            "9042"
         )
     }
 
     @Test
     fun testExampleJson20() {
         captureOutput("ExampleJson20") { example.exampleJson20.main() }.verifyOutputLines(
-            "Project(name=kotlinx.serialization, language=Kotlin)"
+            "{\"name\":\"kotlinx.serialization\",\"owner\":{\"name\":\"kotlin\"},\"forks\":[{\"votes\":42},{\"votes\":9000}]}"
         )
     }
 
     @Test
     fun testExampleJson21() {
         captureOutput("ExampleJson21") { example.exampleJson21.main() }.verifyOutputLines(
-            "{",
-            "    \"pi_double\": 3.141592653589793,",
-            "    \"pi_string\": \"3.141592653589793238462643383279\"",
-            "}"
+            "Project(name=kotlinx.serialization, language=Kotlin)"
         )
     }
 
@@ -165,7 +165,6 @@ class JsonTest {
     fun testExampleJson22() {
         captureOutput("ExampleJson22") { example.exampleJson22.main() }.verifyOutputLines(
             "{",
-            "    \"pi_literal\": 3.141592653589793238462643383279,",
             "    \"pi_double\": 3.141592653589793,",
             "    \"pi_string\": \"3.141592653589793238462643383279\"",
             "}"
@@ -175,66 +174,77 @@ class JsonTest {
     @Test
     fun testExampleJson23() {
         captureOutput("ExampleJson23") { example.exampleJson23.main() }.verifyOutputLines(
-            "3.141592653589793238462643383279"
+            "{",
+            "    \"pi_literal\": 3.141592653589793238462643383279,",
+            "    \"pi_double\": 3.141592653589793,",
+            "    \"pi_string\": \"3.141592653589793238462643383279\"",
+            "}"
         )
     }
 
     @Test
     fun testExampleJson24() {
-        captureOutput("ExampleJson24") { example.exampleJson24.main() }.verifyOutputLinesStart(
-            "Exception in thread \"main\" kotlinx.serialization.json.internal.JsonEncodingException: Creating a literal unquoted value of 'null' is forbidden. If you want to create JSON null literal, use JsonNull object, otherwise, use JsonPrimitive"
+        captureOutput("ExampleJson24") { example.exampleJson24.main() }.verifyOutputLines(
+            "3.141592653589793238462643383279"
         )
     }
 
     @Test
     fun testExampleJson25() {
-        captureOutput("ExampleJson25") { example.exampleJson25.main() }.verifyOutputLines(
-            "Project(name=kotlinx.serialization, users=[User(name=kotlin)])",
-            "Project(name=kotlinx.serialization, users=[User(name=kotlin), User(name=jetbrains)])"
+        captureOutput("ExampleJson25") { example.exampleJson25.main() }.verifyOutputLinesStart(
+            "Exception in thread \"main\" kotlinx.serialization.json.internal.JsonEncodingException: Creating a literal unquoted value of 'null' is forbidden. If you want to create JSON null literal, use JsonNull object, otherwise, use JsonPrimitive"
         )
     }
 
     @Test
     fun testExampleJson26() {
         captureOutput("ExampleJson26") { example.exampleJson26.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.serialization\",\"users\":{\"name\":\"kotlin\"}}"
+            "Project(name=kotlinx.serialization, users=[User(name=kotlin)])",
+            "Project(name=kotlinx.serialization, users=[User(name=kotlin), User(name=jetbrains)])"
         )
     }
 
     @Test
     fun testExampleJson27() {
         captureOutput("ExampleJson27") { example.exampleJson27.main() }.verifyOutputLines(
-            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\"}",
-            "{\"name\":\"kotlinx.serialization\"}"
+            "{\"name\":\"kotlinx.serialization\",\"users\":{\"name\":\"kotlin\"}}"
         )
     }
 
     @Test
     fun testExampleJson28() {
         captureOutput("ExampleJson28") { example.exampleJson28.main() }.verifyOutputLines(
-            "[{\"name\":\"kotlinx.serialization\",\"owner\":\"kotlin\"},{\"name\":\"example\"}]",
-            "[OwnedProject(name=kotlinx.serialization, owner=kotlin), BasicProject(name=example)]"
+            "{\"name\":\"kotlinx.serialization\",\"language\":\"Kotlin\"}",
+            "{\"name\":\"kotlinx.serialization\"}"
         )
     }
 
     @Test
     fun testExampleJson29() {
         captureOutput("ExampleJson29") { example.exampleJson29.main() }.verifyOutputLines(
-            "BasicProject(name=example)"
+            "[{\"name\":\"kotlinx.serialization\",\"owner\":\"kotlin\"},{\"name\":\"example\"}]",
+            "[OwnedProject(name=kotlinx.serialization, owner=kotlin), BasicProject(name=example)]"
         )
     }
 
     @Test
     fun testExampleJson30() {
         captureOutput("ExampleJson30") { example.exampleJson30.main() }.verifyOutputLines(
-            "[{\"name\":\"kotlinx.serialization\"},{\"error\":\"Not found\"}]",
-            "[Ok(data=Project(name=kotlinx.serialization)), Error(message=Not found)]"
+            "BasicProject(name=example)"
         )
     }
 
     @Test
     fun testExampleJson31() {
         captureOutput("ExampleJson31") { example.exampleJson31.main() }.verifyOutputLines(
+            "[{\"name\":\"kotlinx.serialization\"},{\"error\":\"Not found\"}]",
+            "[Ok(data=Project(name=kotlinx.serialization)), Error(message=Not found)]"
+        )
+    }
+
+    @Test
+    fun testExampleJson32() {
+        captureOutput("ExampleJson32") { example.exampleJson32.main() }.verifyOutputLines(
             "UnknownProject(name=example, details={\"type\":\"unknown\",\"maintainer\":\"Unknown\",\"license\":\"Apache 2.0\"})"
         )
     }
diff --git a/integration-test/gradle.properties b/integration-test/gradle.properties
index bf55d52a..54375db8 100644
--- a/integration-test/gradle.properties
+++ b/integration-test/gradle.properties
@@ -2,8 +2,8 @@
 # Copyright 2017-2020 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
 #
 
-mainKotlinVersion=2.0.20
-mainLibVersion=1.7.4-SNAPSHOT
+mainKotlinVersion=2.1.0
+mainLibVersion=1.8.0-SNAPSHOT
 
 kotlin.code.style=official
 kotlin.js.compiler=ir
diff --git a/integration-test/gradle/wrapper/gradle-wrapper.jar b/integration-test/gradle/wrapper/gradle-wrapper.jar
index 7454180f..e6441136 100644
Binary files a/integration-test/gradle/wrapper/gradle-wrapper.jar and b/integration-test/gradle/wrapper/gradle-wrapper.jar differ
diff --git a/integration-test/gradle/wrapper/gradle-wrapper.properties b/integration-test/gradle/wrapper/gradle-wrapper.properties
index 31cca491..b82aa23a 100644
--- a/integration-test/gradle/wrapper/gradle-wrapper.properties
+++ b/integration-test/gradle/wrapper/gradle-wrapper.properties
@@ -1,5 +1,7 @@
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-7.6.1-all.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.7-bin.zip
+networkTimeout=10000
+validateDistributionUrl=true
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
diff --git a/integration-test/gradlew b/integration-test/gradlew
index 1b6c7873..1aa94a42 100755
--- a/integration-test/gradlew
+++ b/integration-test/gradlew
@@ -55,7 +55,7 @@
 #       Darwin, MinGW, and NonStop.
 #
 #   (3) This script is generated from the Groovy template
-#       https://github.com/gradle/gradle/blob/master/subprojects/plugins/src/main/resources/org/gradle/api/internal/plugins/unixStartScript.txt
+#       https://github.com/gradle/gradle/blob/HEAD/subprojects/plugins/src/main/resources/org/gradle/api/internal/plugins/unixStartScript.txt
 #       within the Gradle project.
 #
 #       You can find Gradle at https://github.com/gradle/gradle/.
@@ -80,13 +80,11 @@ do
     esac
 done
 
-APP_HOME=$( cd "${APP_HOME:-./}" && pwd -P ) || exit
-
-APP_NAME="Gradle"
+# This is normally unused
+# shellcheck disable=SC2034
 APP_BASE_NAME=${0##*/}
-
-# Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
-DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'
+# Discard cd standard output in case $CDPATH is set (https://github.com/gradle/gradle/issues/25036)
+APP_HOME=$( cd "${APP_HOME:-./}" > /dev/null && pwd -P ) || exit
 
 # Use the maximum available, or set MAX_FD != -1 to use that value.
 MAX_FD=maximum
@@ -133,22 +131,29 @@ location of your Java installation."
     fi
 else
     JAVACMD=java
-    which java >/dev/null 2>&1 || die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
+    if ! command -v java >/dev/null 2>&1
+    then
+        die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
 
 Please set the JAVA_HOME variable in your environment to match the
 location of your Java installation."
+    fi
 fi
 
 # Increase the maximum file descriptors if we can.
 if ! "$cygwin" && ! "$darwin" && ! "$nonstop" ; then
     case $MAX_FD in #(
       max*)
+        # In POSIX sh, ulimit -H is undefined. That's why the result is checked to see if it worked.
+        # shellcheck disable=SC2039,SC3045
         MAX_FD=$( ulimit -H -n ) ||
             warn "Could not query maximum file descriptor limit"
     esac
     case $MAX_FD in  #(
       '' | soft) :;; #(
       *)
+        # In POSIX sh, ulimit -n is undefined. That's why the result is checked to see if it worked.
+        # shellcheck disable=SC2039,SC3045
         ulimit -n "$MAX_FD" ||
             warn "Could not set maximum file descriptor limit to $MAX_FD"
     esac
@@ -193,11 +198,15 @@ if "$cygwin" || "$msys" ; then
     done
 fi
 
-# Collect all arguments for the java command;
-#   * $DEFAULT_JVM_OPTS, $JAVA_OPTS, and $GRADLE_OPTS can contain fragments of
-#     shell script including quotes and variable substitutions, so put them in
-#     double quotes to make sure that they get re-expanded; and
-#   * put everything else in single quotes, so that it's not re-expanded.
+
+# Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
+DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'
+
+# Collect all arguments for the java command:
+#   * DEFAULT_JVM_OPTS, JAVA_OPTS, JAVA_OPTS, and optsEnvironmentVar are not allowed to contain shell fragments,
+#     and any embedded shellness will be escaped.
+#   * For example: A user cannot expect ${Hostname} to be expanded, as it is an environment variable and will be
+#     treated as '${Hostname}' itself on the command line.
 
 set -- \
         "-Dorg.gradle.appname=$APP_BASE_NAME" \
@@ -205,6 +214,12 @@ set -- \
         org.gradle.wrapper.GradleWrapperMain \
         "$@"
 
+# Stop when "xargs" is not available.
+if ! command -v xargs >/dev/null 2>&1
+then
+    die "xargs is not available"
+fi
+
 # Use "xargs" to parse quoted args.
 #
 # With -n1 it outputs one arg per line, with the quotes and backslashes removed.
diff --git a/integration-test/gradlew.bat b/integration-test/gradlew.bat
index ac1b06f9..7101f8e4 100644
--- a/integration-test/gradlew.bat
+++ b/integration-test/gradlew.bat
@@ -14,7 +14,7 @@
 @rem limitations under the License.
 @rem
 
-@if "%DEBUG%" == "" @echo off
+@if "%DEBUG%"=="" @echo off
 @rem ##########################################################################
 @rem
 @rem  Gradle startup script for Windows
@@ -25,7 +25,8 @@
 if "%OS%"=="Windows_NT" setlocal
 
 set DIRNAME=%~dp0
-if "%DIRNAME%" == "" set DIRNAME=.
+if "%DIRNAME%"=="" set DIRNAME=.
+@rem This is normally unused
 set APP_BASE_NAME=%~n0
 set APP_HOME=%DIRNAME%
 
@@ -40,13 +41,13 @@ if defined JAVA_HOME goto findJavaFromJavaHome
 
 set JAVA_EXE=java.exe
 %JAVA_EXE% -version >NUL 2>&1
-if "%ERRORLEVEL%" == "0" goto execute
+if %ERRORLEVEL% equ 0 goto execute
 
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
 
@@ -56,11 +57,11 @@ set JAVA_EXE=%JAVA_HOME%/bin/java.exe
 
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
 
@@ -75,13 +76,15 @@ set CLASSPATH=%APP_HOME%\gradle\wrapper\gradle-wrapper.jar
 
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
diff --git a/integration-test/kotlin-js-store/yarn.lock b/integration-test/kotlin-js-store/yarn.lock
index 70c45d54..c44683df 100644
--- a/integration-test/kotlin-js-store/yarn.lock
+++ b/integration-test/kotlin-js-store/yarn.lock
@@ -274,6 +274,13 @@ js-yaml@^4.1.0:
   dependencies:
     argparse "^2.0.1"
 
+kotlin-web-helpers@2.0.0:
+  version "2.0.0"
+  resolved "https://registry.yarnpkg.com/kotlin-web-helpers/-/kotlin-web-helpers-2.0.0.tgz#b112096b273c1e733e0b86560998235c09a19286"
+  integrity sha512-xkVGl60Ygn/zuLkDPx+oHj7jeLR7hCvoNF99nhwXMn8a3ApB4lLiC9pk4ol4NHPjyoCbvQctBqvzUcp8pkqyWw==
+  dependencies:
+    format-util "^1.0.5"
+
 locate-path@^6.0.0:
   version "6.0.0"
   resolved "https://registry.yarnpkg.com/locate-path/-/locate-path-6.0.0.tgz#55321eb309febbc59c4801d931a72452a681d286"
@@ -296,10 +303,10 @@ minimatch@^5.0.1, minimatch@^5.1.6:
   dependencies:
     brace-expansion "^2.0.1"
 
-mocha@10.7.0:
-  version "10.7.0"
-  resolved "https://registry.yarnpkg.com/mocha/-/mocha-10.7.0.tgz#9e5cbed8fa9b37537a25bd1f7fb4f6fc45458b9a"
-  integrity sha512-v8/rBWr2VO5YkspYINnvu81inSz2y3ODJrhO175/Exzor1RcEZZkizgE2A+w/CAXXoESS8Kys5E62dOHGHzULA==
+mocha@10.7.3:
+  version "10.7.3"
+  resolved "https://registry.yarnpkg.com/mocha/-/mocha-10.7.3.tgz#ae32003cabbd52b59aece17846056a68eb4b0752"
+  integrity sha512-uQWxAu44wwiACGqjbPYmjo7Lg8sFrS3dQe7PP2FQI+woptP4vZXSMcfMyFL/e1yFEeEpV4RtyTpZROOKmxis+A==
   dependencies:
     ansi-colors "^4.1.3"
     browser-stdout "^1.3.1"
diff --git a/kotlin-js-store/yarn.lock b/kotlin-js-store/yarn.lock
index eb19f383..02a30cff 100644
--- a/kotlin-js-store/yarn.lock
+++ b/kotlin-js-store/yarn.lock
@@ -274,6 +274,13 @@ js-yaml@^4.1.0:
   dependencies:
     argparse "^2.0.1"
 
+kotlin-web-helpers@2.0.0:
+  version "2.0.0"
+  resolved "https://registry.yarnpkg.com/kotlin-web-helpers/-/kotlin-web-helpers-2.0.0.tgz#b112096b273c1e733e0b86560998235c09a19286"
+  integrity sha512-xkVGl60Ygn/zuLkDPx+oHj7jeLR7hCvoNF99nhwXMn8a3ApB4lLiC9pk4ol4NHPjyoCbvQctBqvzUcp8pkqyWw==
+  dependencies:
+    format-util "^1.0.5"
+
 locate-path@^6.0.0:
   version "6.0.0"
   resolved "https://registry.yarnpkg.com/locate-path/-/locate-path-6.0.0.tgz#55321eb309febbc59c4801d931a72452a681d286"
@@ -296,10 +303,10 @@ minimatch@^5.0.1, minimatch@^5.1.6:
   dependencies:
     brace-expansion "^2.0.1"
 
-mocha@10.7.0:
-  version "10.7.0"
-  resolved "https://registry.yarnpkg.com/mocha/-/mocha-10.7.0.tgz#9e5cbed8fa9b37537a25bd1f7fb4f6fc45458b9a"
-  integrity sha512-v8/rBWr2VO5YkspYINnvu81inSz2y3ODJrhO175/Exzor1RcEZZkizgE2A+w/CAXXoESS8Kys5E62dOHGHzULA==
+mocha@10.7.3:
+  version "10.7.3"
+  resolved "https://registry.yarnpkg.com/mocha/-/mocha-10.7.3.tgz#ae32003cabbd52b59aece17846056a68eb4b0752"
+  integrity sha512-uQWxAu44wwiACGqjbPYmjo7Lg8sFrS3dQe7PP2FQI+woptP4vZXSMcfMyFL/e1yFEeEpV4RtyTpZROOKmxis+A==
   dependencies:
     ansi-colors "^4.1.3"
     browser-stdout "^1.3.1"
diff --git a/rules/r8.pro b/rules/r8.pro
index ad5dd305..879917c1 100644
--- a/rules/r8.pro
+++ b/rules/r8.pro
@@ -10,3 +10,16 @@
 
  -if @kotlinx.serialization.Serializable class **
  -keep, allowshrinking, allowoptimization, allowobfuscation, allowaccessmodification class <1>
+
+
+# Rule to save INSTANCE field and serializer function for Kotlin serializable objects.
+#
+# R8 full mode works differently if the instance is not explicitly accessed in the code.
+#
+# see https://github.com/Kotlin/kotlinx.serialization/issues/2861
+# see https://issuetracker.google.com/issues/379996140
+
+-keepclassmembers @kotlinx.serialization.Serializable class ** {
+    public static ** INSTANCE;
+    kotlinx.serialization.KSerializer serializer(...);
+}
diff --git a/settings.gradle.kts b/settings.gradle.kts
index 0d7c75ab..628869cd 100644
--- a/settings.gradle.kts
+++ b/settings.gradle.kts
@@ -104,10 +104,12 @@ fun overriddenKotlinVersion(): String? {
     if (kotlinRepoUrl?.isNotEmpty() == true) {
         return repoVersion ?: throw IllegalArgumentException("\"kotlin_version\" Gradle property should be defined")
     } else if (bootstrap != null) {
-        return bootstrapVersion ?: throw IllegalArgumentException("\"kotlin.version.snapshot\" Gradle property should be defined")
+        return bootstrapVersion
+            ?: throw IllegalArgumentException("\"kotlin.version.snapshot\" Gradle property should be defined")
     }
     if (buildSnapshotTrain?.isNotEmpty() == true) {
-        return trainVersion ?: throw IllegalArgumentException("\"kotlin_snapshot_version\" should be defined when building with snapshot compiler")
+        return trainVersion
+            ?: throw IllegalArgumentException("\"kotlin_snapshot_version\" should be defined when building with snapshot compiler")
     }
     return null
 }
```

