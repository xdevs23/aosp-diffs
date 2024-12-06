```diff
diff --git a/.github/pull_request_template.md b/.github/pull_request_template.md
new file mode 100644
index 00000000..64820a0b
--- /dev/null
+++ b/.github/pull_request_template.md
@@ -0,0 +1,3 @@
+
+- [ ] `docs/changelog.md` has been updated if applicable.
+- [ ] [CLA](https://spreadsheets.google.com/spreadsheet/viewform?formkey=dDViT2xzUHAwRkI3X3k5Z0lQM091OGc6MQ&ndplr=1) signed.
diff --git a/.github/workflows/gradle-wrapper.yaml b/.github/workflows/gradle-wrapper.yaml
index d82e2914..53ad51a7 100644
--- a/.github/workflows/gradle-wrapper.yaml
+++ b/.github/workflows/gradle-wrapper.yaml
@@ -12,4 +12,4 @@ jobs:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
-      - uses: gradle/wrapper-validation-action@v1
+      - uses: gradle/gradle-build-action@v3
diff --git a/.github/workflows/mkdocs-requirements.txt b/.github/workflows/mkdocs-requirements.txt
index 5f787ffa..5e42cb7e 100644
--- a/.github/workflows/mkdocs-requirements.txt
+++ b/.github/workflows/mkdocs-requirements.txt
@@ -1,18 +1,18 @@
 click==8.1.7
-future==0.18.3
-Jinja2==3.1.3
-livereload==2.6.3
+future==1.0.0
+Jinja2==3.1.4
+livereload==2.7.0
 lunr==0.7.0.post1
-MarkupSafe==2.1.3
-mkdocs==1.5.3
+MarkupSafe==2.1.5
+mkdocs==1.6.0
 mkdocs-macros-plugin==1.0.5
-mkdocs-material==9.5.4
+mkdocs-material==9.5.29
 mkdocs-material-extensions==1.3.1
-Pygments==2.17.2
-pymdown-extensions==10.7
-python-dateutil==2.8.2
+Pygments==2.18.0
+pymdown-extensions==10.8.1
+python-dateutil==2.9.0.post0
 PyYAML==6.0.1
 repackage==0.7.3
 six==1.16.0
 termcolor==2.4.0
-tornado==6.4
+tornado==6.4.1
diff --git a/.gitignore b/.gitignore
index 9310aea4..748cdf2d 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,5 +1,6 @@
 .classpath
 .gradle
+.kotlin
 .project
 .settings
 eclipsebin
diff --git a/METADATA b/METADATA
index 127fc451..7a6230cf 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/kotlinpoet
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "kotlinpoet"
 description: "A Kotlin API for generating .kt source files"
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 2
+    month: 8
     day: 15
   }
   homepage: "https://square.github.io/kotlinpoet/"
   identifier {
     type: "Git"
     value: "https://github.com/square/kotlinpoet.git"
-    version: "1.16.0"
+    version: "1.18.1"
   }
 }
diff --git a/docs/changelog.md b/docs/changelog.md
index 8f971fe3..4ea3ee32 100644
--- a/docs/changelog.md
+++ b/docs/changelog.md
@@ -3,6 +3,71 @@ Change Log
 
 ## Unreleased
 
+## Version 1.18.1
+
+Thanks to [@mitasov-ra][mitasov-ra] for contributing to this release.
+
+_2024-07-15_
+
+ * Fix: Workaround for [KT-18706][kt-18706]: KotlinPoet now generates import aliases without backticks (#1920).
+
+   ```kotlin
+   // before, doesn't compile due to KT-18706
+   import com.example.one.`$Foo` as `One$Foo`
+   import com.example.two.`$Foo` as `Two$Foo`
+
+   // now, compiles
+   import com.example.one.`$Foo` as One__Foo
+   import com.example.two.`$Foo` as Two__Foo
+   ```
+
+## Version 1.18.0
+
+Thanks to [@DanielGronau][DanielGronau] for contributing to this release.
+
+_2024-07-05_
+
+ * New: Kotlin 2.0.0.
+ * New: KSP 2.0.0-1.0.22.
+ * New: Promote `kotlinpoet-metadata` out of preview to stable.
+ * New: Migrate `kotlinpoet-metadata` to stable `org.jetbrains.kotlin:kotlin-metadata-jvm` artifact for Metadata parsing.
+ * New: Make enum entry references in `KSAnnotation.toAnnotationSpec()` and `KSClassDeclaration.toClassName()` more robust.
+ * Fix: Don't expand typealiases of function types to `LambdaTypeName`s in `KSTypeReference.toTypeName()`.
+ * Fix: Avoid rounding small double and float values in `%L` translation (#1927).
+ * Fix: Fix typealias type argument resolution in KSP2 (#1929).
+
+## Version 1.17.0
+
+Thanks to [@jisungbin][jisungbin], [@hfhbd][hfhbd], [@evant][evant], [@sgjesse][sgjesse], [@sebek64][sebek64] for
+contributing to this release.
+
+_2024-05-24_
+
+* Change: kotlinx-metadata 0.9.0. Note that the `KotlinClassMetadata.read` is deprecated in 0.9.0 and replaced with
+  `readStrict` (#1830).
+  * Note: we now also provide `lenient` parameters to map to the underlying `readStrict()` and `readLenient()` calls
+    (#1766).
+  * We have also removed various `Class`/`TypeElement`/`Metadata`-to-`KmClass` APIs from the public API, as these are
+    trivial to write now with kotlinx-metadata's newer APIs and allows us to focus the API surface area of this artifact
+    better (#1891).
+* New: Supertype list wraps to one-per-line if the primary constructor spans multiple lines (#1866).
+* New: Extract `MemberSpecHolder` interface for constructs that can hold `PropertySpec`s and `FunSpec`s and their
+  builders (#1877).
+* New: `joinToCode` variant which operates on any type, but requires a transform lambda to convert each element into a
+  `CodeBlock` (#1874).
+* New: Support annotation type arguments in `KSAnnotation.toAnnotationSpec()` (#1889).
+* Fix: Prevent name clashes between a function in class and a function call in current scope (#1850).
+* Fix: Fix extension function imports (#1814).
+* Fix: Omit implicit modifiers on `FileSpec.scriptBuilder` (#1813).
+* Fix: Fix trailing newline in `PropertySpec` (#1827).
+* Fix: `KSAnnotation.toAnnotationSpec` writes varargs in place instead of making them an array to work around a Kotlin
+  issue with `OptIn` annotations (#1833).
+* Fix: `MemberName`s without a package are now correctly imported (#1841)
+* Fix: Throw if primary constructor delegates to other constructors (#1859).
+* Fix: Aliased imports with nested class (#1876).
+* Fix: Check for error types in `KSType.toClassName()` (#1890).
+* Fix: Support generating a single import for overloaded `MemberName`s (#1909).
+
 ## Version 1.16.0
 
 Thanks to [@drawers][drawers], [@rickclephas][rickclephas] for contributing to this release.
@@ -751,6 +816,7 @@ _2017-05-16_
  [ksp-interop-docs]: https://square.github.io/kotlinpoet/interop-ksp/
  [javapoet]: https://github.com/square/javapoet
  [javapoet-interop-docs]: https://square.github.io/kotlinpoet/interop-javapoet/
+ [kt-18706]: https://youtrack.jetbrains.com/issue/KT-18706
 
  [martinbonnin]: https://github.com/martinbonnin
  [idanakav]: https://github.com/idanakav
@@ -785,3 +851,9 @@ _2017-05-16_
  [takahirom]: https://github.com/takahirom
  [mcarleio]: https://github.com/mcarleio
  [gabrielittner]: https://github.com/gabrielittner
+ [jisungbin]: https://github.com/jisungbin
+ [hfhbd]: https://github.com/hfhbd
+ [sgjesse]: https://github.com/sgjesse
+ [sebek64]: https://github.com/sebek64
+ [DanielGronau]: https://github.com/DanielGronau
+ [mitasov-ra]: https://github.com/mitasov-ra
diff --git a/docs/contributing.md b/docs/contributing.md
index 74108a8c..5f28817c 100644
--- a/docs/contributing.md
+++ b/docs/contributing.md
@@ -8,8 +8,12 @@ When submitting code, please make every effort to follow existing conventions
 and style in order to keep the code as readable as possible. Please also make
 sure your code compiles by running `./gradlew clean build`.
 
+When creating a pull request, please add a row in the [changelog][2] with the
+patch description and PR # to `Unreleased` section.
+
 Before your code can be accepted into the project you must also sign the
 [Individual Contributor License Agreement (CLA)][1].
 
 
  [1]: https://spreadsheets.google.com/spreadsheet/viewform?formkey=dDViT2xzUHAwRkI3X3k5Z0lQM091OGc6MQ&ndplr=1
+ [2]: https://github.com/square/kotlinpoet/blob/main/docs/changelog.md
diff --git a/docs/interop-javapoet.md b/docs/interop-javapoet.md
index 6b41f0d5..a1567cb1 100644
--- a/docs/interop-javapoet.md
+++ b/docs/interop-javapoet.md
@@ -1,7 +1,7 @@
 JavaPoet Extensions for KotlinPoet
 ==================================
 
-`interop:javapoet` is an interop API for converting [JavaPoet](https://github.com/squareup/javapoet)
+`interop:javapoet` is an interop API for converting [JavaPoet](https://github.com/square/javapoet)
 types to KotlinPoet types. This is particularly useful for projects that support code gen in
 multiple languages and want to easily be able to jump between.
 
diff --git a/gradle.properties b/gradle.properties
index 5ee29f62..9b59502a 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -1,7 +1,7 @@
 org.gradle.jvmargs='-Dfile.encoding=UTF-8'
 
 GROUP=com.squareup
-VERSION_NAME=1.16.0
+VERSION_NAME=1.18.1
 
 POM_URL=https://github.com/square/kotlinpoet
 POM_SCM_URL=https://github.com/square/kotlinpoet
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index 1f39d95b..6baabce7 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -13,38 +13,39 @@
 # limitations under the License.
 
 [versions]
-kotlin = "1.9.22"
-kct = "0.4.0"
-ksp = "1.9.22-1.0.16"
+kotlin = "2.0.0"
+kct = "0.5.1"
+ksp = "2.0.0-1.0.22"
 ktlint = "0.48.2"
 
 [plugins]
 kotlin-multiplatform = { id = "org.jetbrains.kotlin.multiplatform", version.ref = "kotlin" }
 kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
-dokka = { id = "org.jetbrains.dokka", version = "1.9.10" }
+dokka = { id = "org.jetbrains.dokka", version = "1.9.20" }
 ksp = { id = "com.google.devtools.ksp", version.ref = "ksp" }
-spotless = { id = "com.diffplug.spotless", version = "6.24.0" }
-mavenPublish = { id = "com.vanniktech.maven.publish", version = "0.27.0" }
-kotlinBinaryCompatibilityValidator = { id = "org.jetbrains.kotlinx.binary-compatibility-validator", version = "0.13.2" }
+spotless = { id = "com.diffplug.spotless", version = "6.25.0" }
+mavenPublish = { id = "com.vanniktech.maven.publish", version = "0.29.0" }
+kotlinBinaryCompatibilityValidator = { id = "org.jetbrains.kotlinx.binary-compatibility-validator", version = "0.15.1" }
 
 [libraries]
 autoCommon = { module = "com.google.auto:auto-common", version = "1.2.2" }
-guava = { module = "com.google.guava:guava", version = "33.0.0-jre" }
+guava = { module = "com.google.guava:guava", version = "33.2.1-jre" }
 javapoet = "com.squareup:javapoet:1.13.0"
 
 autoService = "com.google.auto.service:auto-service-annotations:1.1.1"
-autoService-ksp = "dev.zacsweers.autoservice:auto-service-ksp:1.1.0"
+autoService-ksp = "dev.zacsweers.autoservice:auto-service-ksp:1.2.0"
 
 kotlin-compilerEmbeddable = { module = "org.jetbrains.kotlin:kotlin-compiler-embeddable", version.ref = "kotlin" }
 kotlin-annotationProcessingEmbeddable = { module = "org.jetbrains.kotlin:kotlin-annotation-processing-embeddable", version.ref = "kotlin" }
 kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlin" }
 kotlin-junit = { module = "org.jetbrains.kotlin:kotlin-test-junit", version.ref = "kotlin" }
-kotlin-metadata = { module = "org.jetbrains.kotlinx:kotlinx-metadata-jvm", version = "0.8.0" }
+kotlin-metadata = { module = "org.jetbrains.kotlin:kotlin-metadata-jvm", version.ref = "kotlin" }
 
 ksp = { module = "com.google.devtools.ksp:symbol-processing", version.ref = "ksp" }
 ksp-api = { module = "com.google.devtools.ksp:symbol-processing-api", version.ref = "ksp" }
+ksp-aaEmbeddable = { module = "com.google.devtools.ksp:symbol-processing-aa-embeddable", version.ref = "ksp" }
 
-truth = { module = "com.google.truth:truth", version = "1.2.0" }
+truth = { module = "com.google.truth:truth", version = "1.4.4" }
 compileTesting = { module = "com.google.testing.compile:compile-testing", version = "0.21.0" }
 jimfs = { module = "com.google.jimfs:jimfs", version = "1.3.0" }
 ecj = { module = "org.eclipse.jdt.core.compiler:ecj", version = "4.6.1" }
diff --git a/gradle/wrapper/gradle-wrapper.jar b/gradle/wrapper/gradle-wrapper.jar
index d64cd491..2c352119 100644
Binary files a/gradle/wrapper/gradle-wrapper.jar and b/gradle/wrapper/gradle-wrapper.jar differ
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index e6aba251..dedd5d1e 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -1,6 +1,6 @@
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-8.5-all.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.9-all.zip
 networkTimeout=10000
 validateDistributionUrl=true
 zipStoreBase=GRADLE_USER_HOME
diff --git a/gradlew b/gradlew
index 1aa94a42..f5feea6d 100755
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
@@ -84,7 +86,8 @@ done
 # shellcheck disable=SC2034
 APP_BASE_NAME=${0##*/}
 # Discard cd standard output in case $CDPATH is set (https://github.com/gradle/gradle/issues/25036)
-APP_HOME=$( cd "${APP_HOME:-./}" > /dev/null && pwd -P ) || exit
+APP_HOME=$( cd -P "${APP_HOME:-./}" > /dev/null && printf '%s
+' "$PWD" ) || exit
 
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
 
diff --git a/interop/kotlinx-metadata/api/kotlinx-metadata.api b/interop/kotlin-metadata/api/kotlin-metadata.api
similarity index 64%
rename from interop/kotlinx-metadata/api/kotlinx-metadata.api
rename to interop/kotlin-metadata/api/kotlin-metadata.api
index 091b3030..ab776573 100644
--- a/interop/kotlinx-metadata/api/kotlinx-metadata.api
+++ b/interop/kotlin-metadata/api/kotlin-metadata.api
@@ -1,63 +1,52 @@
-public final class com/squareup/kotlinpoet/metadata/KotlinPoetMetadata {
-	public static final fun readKotlinClassMetadata (Lkotlin/Metadata;)Lkotlinx/metadata/jvm/KotlinClassMetadata;
-	public static final fun toKmClass (Ljava/lang/Class;)Lkotlinx/metadata/KmClass;
-	public static final fun toKmClass (Ljavax/lang/model/element/TypeElement;)Lkotlinx/metadata/KmClass;
-	public static final fun toKmClass (Lkotlin/Metadata;)Lkotlinx/metadata/KmClass;
-	public static final fun toKmClass (Lkotlin/reflect/KClass;)Lkotlinx/metadata/KmClass;
-}
-
-public abstract interface annotation class com/squareup/kotlinpoet/metadata/KotlinPoetMetadataPreview : java/lang/annotation/Annotation {
-}
-
 public final class com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector : com/squareup/kotlinpoet/metadata/specs/ClassInspector {
 	public static final field Companion Lcom/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector$Companion;
-	public synthetic fun <init> (Ljavax/lang/model/util/Elements;Ljavax/lang/model/util/Types;Lkotlin/jvm/internal/DefaultConstructorMarker;)V
-	public fun containerData (Lkotlinx/metadata/KmDeclarationContainer;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
-	public static final fun create (Ljavax/lang/model/util/Elements;Ljavax/lang/model/util/Types;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
-	public fun declarationContainerFor (Lcom/squareup/kotlinpoet/ClassName;)Lkotlinx/metadata/KmDeclarationContainer;
+	public synthetic fun <init> (ZLjavax/lang/model/util/Elements;Ljavax/lang/model/util/Types;Lkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public fun containerData (Lkotlin/metadata/KmDeclarationContainer;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
+	public static final fun create (ZLjavax/lang/model/util/Elements;Ljavax/lang/model/util/Types;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
+	public fun declarationContainerFor (Lcom/squareup/kotlinpoet/ClassName;)Lkotlin/metadata/KmDeclarationContainer;
 	public fun enumEntry (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
 	public fun getSupportsNonRuntimeRetainedAnnotations ()Z
 	public fun isInterface (Lcom/squareup/kotlinpoet/ClassName;)Z
-	public fun methodExists (Lcom/squareup/kotlinpoet/ClassName;Lkotlinx/metadata/jvm/JvmMethodSignature;)Z
+	public fun methodExists (Lcom/squareup/kotlinpoet/ClassName;Lkotlin/metadata/jvm/JvmMethodSignature;)Z
 }
 
 public final class com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector$Companion {
-	public final fun create (Ljavax/lang/model/util/Elements;Ljavax/lang/model/util/Types;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
+	public final fun create (ZLjavax/lang/model/util/Elements;Ljavax/lang/model/util/Types;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
 }
 
 public final class com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector : com/squareup/kotlinpoet/metadata/specs/ClassInspector {
 	public static final field Companion Lcom/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector$Companion;
-	public synthetic fun <init> (Ljava/lang/ClassLoader;Lkotlin/jvm/internal/DefaultConstructorMarker;)V
-	public fun containerData (Lkotlinx/metadata/KmDeclarationContainer;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
-	public static final fun create (Ljava/lang/ClassLoader;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
-	public fun declarationContainerFor (Lcom/squareup/kotlinpoet/ClassName;)Lkotlinx/metadata/KmDeclarationContainer;
+	public synthetic fun <init> (ZLjava/lang/ClassLoader;Lkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public fun containerData (Lkotlin/metadata/KmDeclarationContainer;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
+	public static final fun create (ZLjava/lang/ClassLoader;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
+	public fun declarationContainerFor (Lcom/squareup/kotlinpoet/ClassName;)Lkotlin/metadata/KmDeclarationContainer;
 	public fun enumEntry (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
 	public fun getSupportsNonRuntimeRetainedAnnotations ()Z
 	public fun isInterface (Lcom/squareup/kotlinpoet/ClassName;)Z
-	public fun methodExists (Lcom/squareup/kotlinpoet/ClassName;Lkotlinx/metadata/jvm/JvmMethodSignature;)Z
+	public fun methodExists (Lcom/squareup/kotlinpoet/ClassName;Lkotlin/metadata/jvm/JvmMethodSignature;)Z
 }
 
 public final class com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector$Companion {
-	public final fun create (Ljava/lang/ClassLoader;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
-	public static synthetic fun create$default (Lcom/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector$Companion;Ljava/lang/ClassLoader;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
+	public final fun create (ZLjava/lang/ClassLoader;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
+	public static synthetic fun create$default (Lcom/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector$Companion;ZLjava/lang/ClassLoader;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/ClassData : com/squareup/kotlinpoet/metadata/specs/ContainerData {
-	public fun <init> (Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/ClassName;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;)V
-	public final fun component1 ()Lkotlinx/metadata/KmClass;
+	public fun <init> (Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/ClassName;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;)V
+	public final fun component1 ()Lkotlin/metadata/KmClass;
 	public final fun component2 ()Lcom/squareup/kotlinpoet/ClassName;
 	public final fun component3 ()Ljava/util/Collection;
 	public final fun component4 ()Ljava/util/Map;
 	public final fun component5 ()Ljava/util/Map;
 	public final fun component6 ()Ljava/util/Map;
-	public final fun copy (Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/ClassName;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;)Lcom/squareup/kotlinpoet/metadata/specs/ClassData;
-	public static synthetic fun copy$default (Lcom/squareup/kotlinpoet/metadata/specs/ClassData;Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/ClassName;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/ClassData;
+	public final fun copy (Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/ClassName;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;)Lcom/squareup/kotlinpoet/metadata/specs/ClassData;
+	public static synthetic fun copy$default (Lcom/squareup/kotlinpoet/metadata/specs/ClassData;Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/ClassName;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/ClassData;
 	public fun equals (Ljava/lang/Object;)Z
 	public fun getAnnotations ()Ljava/util/Collection;
 	public final fun getClassName ()Lcom/squareup/kotlinpoet/ClassName;
 	public final fun getConstructors ()Ljava/util/Map;
-	public fun getDeclarationContainer ()Lkotlinx/metadata/KmClass;
-	public synthetic fun getDeclarationContainer ()Lkotlinx/metadata/KmDeclarationContainer;
+	public fun getDeclarationContainer ()Lkotlin/metadata/KmClass;
+	public synthetic fun getDeclarationContainer ()Lkotlin/metadata/KmDeclarationContainer;
 	public fun getMethods ()Ljava/util/Map;
 	public fun getProperties ()Ljava/util/Map;
 	public fun hashCode ()I
@@ -65,16 +54,16 @@ public final class com/squareup/kotlinpoet/metadata/specs/ClassData : com/square
 }
 
 public abstract interface class com/squareup/kotlinpoet/metadata/specs/ClassInspector {
-	public abstract fun containerData (Lkotlinx/metadata/KmDeclarationContainer;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
-	public abstract fun declarationContainerFor (Lcom/squareup/kotlinpoet/ClassName;)Lkotlinx/metadata/KmDeclarationContainer;
+	public abstract fun containerData (Lkotlin/metadata/KmDeclarationContainer;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
+	public abstract fun declarationContainerFor (Lcom/squareup/kotlinpoet/ClassName;)Lkotlin/metadata/KmDeclarationContainer;
 	public abstract fun enumEntry (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
 	public abstract fun getSupportsNonRuntimeRetainedAnnotations ()Z
 	public abstract fun isInterface (Lcom/squareup/kotlinpoet/ClassName;)Z
-	public abstract fun methodExists (Lcom/squareup/kotlinpoet/ClassName;Lkotlinx/metadata/jvm/JvmMethodSignature;)Z
+	public abstract fun methodExists (Lcom/squareup/kotlinpoet/ClassName;Lkotlin/metadata/jvm/JvmMethodSignature;)Z
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/ClassInspectorKt {
-	public static final fun classFor (Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lkotlinx/metadata/KmClass;
+	public static final fun classFor (Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lkotlin/metadata/KmClass;
 	public static final fun containerData (Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/metadata/specs/ContainerData;
 }
 
@@ -103,20 +92,20 @@ public final class com/squareup/kotlinpoet/metadata/specs/ConstructorData$Compan
 
 public abstract interface class com/squareup/kotlinpoet/metadata/specs/ContainerData {
 	public abstract fun getAnnotations ()Ljava/util/Collection;
-	public abstract fun getDeclarationContainer ()Lkotlinx/metadata/KmDeclarationContainer;
+	public abstract fun getDeclarationContainer ()Lkotlin/metadata/KmDeclarationContainer;
 	public abstract fun getMethods ()Ljava/util/Map;
 	public abstract fun getProperties ()Ljava/util/Map;
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/EnumEntryData {
-	public fun <init> (Lkotlinx/metadata/KmClass;Ljava/util/Collection;)V
-	public final fun component1 ()Lkotlinx/metadata/KmClass;
+	public fun <init> (Lkotlin/metadata/KmClass;Ljava/util/Collection;)V
+	public final fun component1 ()Lkotlin/metadata/KmClass;
 	public final fun component2 ()Ljava/util/Collection;
-	public final fun copy (Lkotlinx/metadata/KmClass;Ljava/util/Collection;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
-	public static synthetic fun copy$default (Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;Lkotlinx/metadata/KmClass;Ljava/util/Collection;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
+	public final fun copy (Lkotlin/metadata/KmClass;Ljava/util/Collection;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
+	public static synthetic fun copy$default (Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;Lkotlin/metadata/KmClass;Ljava/util/Collection;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/EnumEntryData;
 	public fun equals (Ljava/lang/Object;)Z
 	public final fun getAnnotations ()Ljava/util/Collection;
-	public final fun getDeclarationContainer ()Lkotlinx/metadata/KmClass;
+	public final fun getDeclarationContainer ()Lkotlin/metadata/KmClass;
 	public fun hashCode ()I
 	public fun toString ()Ljava/lang/String;
 }
@@ -143,21 +132,21 @@ public final class com/squareup/kotlinpoet/metadata/specs/FieldData$Companion {
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/FileData : com/squareup/kotlinpoet/metadata/specs/ContainerData {
-	public fun <init> (Lkotlinx/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)V
-	public synthetic fun <init> (Lkotlinx/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
-	public final fun component1 ()Lkotlinx/metadata/KmPackage;
+	public fun <init> (Lkotlin/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)V
+	public synthetic fun <init> (Lkotlin/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public final fun component1 ()Lkotlin/metadata/KmPackage;
 	public final fun component2 ()Ljava/util/Collection;
 	public final fun component3 ()Ljava/util/Map;
 	public final fun component4 ()Ljava/util/Map;
 	public final fun component5 ()Lcom/squareup/kotlinpoet/ClassName;
 	public final fun component6 ()Ljava/lang/String;
-	public final fun copy (Lkotlinx/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/metadata/specs/FileData;
-	public static synthetic fun copy$default (Lcom/squareup/kotlinpoet/metadata/specs/FileData;Lkotlinx/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/FileData;
+	public final fun copy (Lkotlin/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/metadata/specs/FileData;
+	public static synthetic fun copy$default (Lcom/squareup/kotlinpoet/metadata/specs/FileData;Lkotlin/metadata/KmPackage;Ljava/util/Collection;Ljava/util/Map;Ljava/util/Map;Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/metadata/specs/FileData;
 	public fun equals (Ljava/lang/Object;)Z
 	public fun getAnnotations ()Ljava/util/Collection;
 	public final fun getClassName ()Lcom/squareup/kotlinpoet/ClassName;
-	public synthetic fun getDeclarationContainer ()Lkotlinx/metadata/KmDeclarationContainer;
-	public fun getDeclarationContainer ()Lkotlinx/metadata/KmPackage;
+	public synthetic fun getDeclarationContainer ()Lkotlin/metadata/KmDeclarationContainer;
+	public fun getDeclarationContainer ()Lkotlin/metadata/KmPackage;
 	public final fun getFileName ()Ljava/lang/String;
 	public final fun getJvmName ()Ljava/lang/String;
 	public fun getMethods ()Ljava/util/Map;
@@ -191,28 +180,28 @@ public abstract interface class com/squareup/kotlinpoet/metadata/specs/JvmModifi
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/KmTypesKt {
-	public static final fun isExtensionType (Lkotlinx/metadata/KmType;)Z
+	public static final fun isExtensionType (Lkotlin/metadata/KmType;)Z
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs {
 	public static final fun getPackageName (Ljavax/lang/model/element/Element;)Ljava/lang/String;
-	public static final fun toFileSpec (Ljava/lang/Class;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static final fun toFileSpec (Ljavax/lang/model/element/TypeElement;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static final fun toFileSpec (Lkotlin/reflect/KClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static final fun toFileSpec (Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static final fun toFileSpec (Lkotlinx/metadata/KmPackage;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static synthetic fun toFileSpec$default (Ljava/lang/Class;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static synthetic fun toFileSpec$default (Ljavax/lang/model/element/TypeElement;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static synthetic fun toFileSpec$default (Lkotlin/reflect/KClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static synthetic fun toFileSpec$default (Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
-	public static final fun toTypeSpec (Ljava/lang/Class;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static final fun toTypeSpec (Ljavax/lang/model/element/TypeElement;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static final fun toTypeSpec (Lkotlin/reflect/KClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static final fun toTypeSpec (Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static synthetic fun toTypeSpec$default (Ljava/lang/Class;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static synthetic fun toTypeSpec$default (Ljavax/lang/model/element/TypeElement;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static synthetic fun toTypeSpec$default (Lkotlin/reflect/KClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
-	public static synthetic fun toTypeSpec$default (Lkotlinx/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static final fun toFileSpec (Ljava/lang/Class;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static final fun toFileSpec (Ljavax/lang/model/element/TypeElement;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static final fun toFileSpec (Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static final fun toFileSpec (Lkotlin/metadata/KmPackage;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static final fun toFileSpec (Lkotlin/reflect/KClass;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static synthetic fun toFileSpec$default (Ljava/lang/Class;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static synthetic fun toFileSpec$default (Ljavax/lang/model/element/TypeElement;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static synthetic fun toFileSpec$default (Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static synthetic fun toFileSpec$default (Lkotlin/reflect/KClass;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec;
+	public static final fun toTypeSpec (Ljava/lang/Class;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static final fun toTypeSpec (Ljavax/lang/model/element/TypeElement;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static final fun toTypeSpec (Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static final fun toTypeSpec (Lkotlin/reflect/KClass;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static synthetic fun toTypeSpec$default (Ljava/lang/Class;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static synthetic fun toTypeSpec$default (Ljavax/lang/model/element/TypeElement;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static synthetic fun toTypeSpec$default (Lkotlin/metadata/KmClass;Lcom/squareup/kotlinpoet/metadata/specs/ClassInspector;Lcom/squareup/kotlinpoet/ClassName;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
+	public static synthetic fun toTypeSpec$default (Lkotlin/reflect/KClass;ZLcom/squareup/kotlinpoet/metadata/specs/ClassInspector;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec;
 }
 
 public final class com/squareup/kotlinpoet/metadata/specs/MethodData {
diff --git a/interop/kotlinx-metadata/build.gradle.kts b/interop/kotlin-metadata/build.gradle.kts
similarity index 84%
rename from interop/kotlinx-metadata/build.gradle.kts
rename to interop/kotlin-metadata/build.gradle.kts
index 6ac626e0..ae703039 100644
--- a/interop/kotlinx-metadata/build.gradle.kts
+++ b/interop/kotlin-metadata/build.gradle.kts
@@ -25,11 +25,8 @@ tasks.jar {
 
 tasks.compileTestKotlin {
   compilerOptions {
-    freeCompilerArgs.addAll(
-      "-Xjvm-default=all",
-      "-opt-in=com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview",
-      "-opt-in=org.jetbrains.kotlin.compiler.plugin.ExperimentalCompilerApi",
-    )
+    freeCompilerArgs.addAll("-Xjvm-default=all")
+    optIn.add("org.jetbrains.kotlin.compiler.plugin.ExperimentalCompilerApi")
   }
 }
 
diff --git a/interop/kotlinx-metadata/gradle.properties b/interop/kotlin-metadata/gradle.properties
similarity index 100%
rename from interop/kotlinx-metadata/gradle.properties
rename to interop/kotlin-metadata/gradle.properties
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/KotlinPoetMetadata.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/KotlinPoetMetadata.kt
similarity index 52%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/KotlinPoetMetadata.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/KotlinPoetMetadata.kt
index bae24747..dc633d12 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/KotlinPoetMetadata.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/KotlinPoetMetadata.kt
@@ -18,45 +18,45 @@
 package com.squareup.kotlinpoet.metadata
 
 import javax.lang.model.element.TypeElement
-import kotlin.annotation.AnnotationTarget.CLASS
-import kotlin.annotation.AnnotationTarget.FUNCTION
-import kotlin.annotation.AnnotationTarget.PROPERTY
+import kotlin.metadata.KmClass
+import kotlin.metadata.jvm.KotlinClassMetadata
+import kotlin.metadata.jvm.Metadata
 import kotlin.reflect.KClass
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.jvm.KotlinClassMetadata
-import kotlinx.metadata.jvm.Metadata
 
 /**
- * Indicates that a given API is part of the experimental KotlinPoet metadata support. This exists
- * because kotlinx-metadata is not a stable API, and will remain in place until it is.
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a new [KmClass] representation of the Kotlin metadata for [this] class.
  */
-@RequiresOptIn
-@Retention(AnnotationRetention.BINARY)
-@Target(CLASS, FUNCTION, PROPERTY)
-public annotation class KotlinPoetMetadataPreview
+internal fun KClass<*>.toKmClass(lenient: Boolean): KmClass = java.toKmClass(lenient)
 
-/** @return a new [KmClass] representation of the Kotlin metadata for [this] class. */
-@KotlinPoetMetadataPreview
-public fun KClass<*>.toKmClass(): KmClass = java.toKmClass()
-
-/** @return a new [KmClass] representation of the Kotlin metadata for [this] class. */
-@KotlinPoetMetadataPreview
-public fun Class<*>.toKmClass(): KmClass = readMetadata(::getAnnotation).toKmClass()
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a new [KmClass] representation of the Kotlin metadata for [this] class.
+ */
+internal fun Class<*>.toKmClass(lenient: Boolean): KmClass = readMetadata(::getAnnotation).toKmClass(lenient)
 
-/** @return a new [KmClass] representation of the Kotlin metadata for [this] type. */
-@KotlinPoetMetadataPreview
-public fun TypeElement.toKmClass(): KmClass = readMetadata(::getAnnotation).toKmClass()
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a new [KmClass] representation of the Kotlin metadata for [this] type.
+ */
+internal fun TypeElement.toKmClass(lenient: Boolean): KmClass = readMetadata(::getAnnotation).toKmClass(lenient)
 
-@KotlinPoetMetadataPreview
-public fun Metadata.toKmClass(): KmClass {
-  return toKotlinClassMetadata<KotlinClassMetadata.Class>()
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ */
+internal fun Metadata.toKmClass(lenient: Boolean): KmClass {
+  return toKotlinClassMetadata<KotlinClassMetadata.Class>(lenient)
     .kmClass
 }
 
-@KotlinPoetMetadataPreview
-public inline fun <reified T : KotlinClassMetadata> Metadata.toKotlinClassMetadata(): T {
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ */
+internal inline fun <reified T : KotlinClassMetadata> Metadata.toKotlinClassMetadata(
+  lenient: Boolean,
+): T {
   val expectedType = T::class
-  val metadata = readKotlinClassMetadata()
+  val metadata = readKotlinClassMetadata(lenient)
   return when (expectedType) {
     KotlinClassMetadata.Class::class -> {
       check(metadata is KotlinClassMetadata.Class)
@@ -82,14 +82,15 @@ public inline fun <reified T : KotlinClassMetadata> Metadata.toKotlinClassMetada
  * Returns the [KotlinClassMetadata] this represents. In general you should only use this function
  * when you don't know what the underlying [KotlinClassMetadata] subtype is, otherwise you should
  * use one of the more direct functions like [toKmClass].
+ *
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
  */
-@KotlinPoetMetadataPreview
-public fun Metadata.readKotlinClassMetadata(): KotlinClassMetadata {
-  val metadata = KotlinClassMetadata.read(asClassHeader())
-  checkNotNull(metadata) {
-    "Could not parse metadata! Try bumping kotlinpoet and/or kotlinx-metadata version."
+internal fun Metadata.readKotlinClassMetadata(lenient: Boolean): KotlinClassMetadata {
+  return if (lenient) {
+    KotlinClassMetadata.readLenient(this)
+  } else {
+    KotlinClassMetadata.readStrict(this)
   }
-  return metadata
 }
 
 private inline fun readMetadata(lookup: ((Class<Metadata>) -> Metadata?)): Metadata {
@@ -97,15 +98,3 @@ private inline fun readMetadata(lookup: ((Class<Metadata>) -> Metadata?)): Metad
     "No Metadata annotation found! Must be Kotlin code built with the standard library on the classpath."
   }
 }
-
-private fun Metadata.asClassHeader(): Metadata {
-  return Metadata(
-    kind = kind,
-    metadataVersion = metadataVersion,
-    data1 = data1,
-    data2 = data2,
-    extraString = extraString,
-    packageName = packageName,
-    extraInt = extraInt,
-  )
-}
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ClassInspectorUtil.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ClassInspectorUtil.kt
similarity index 97%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ClassInspectorUtil.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ClassInspectorUtil.kt
index 1bbf6945..b9690443 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ClassInspectorUtil.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ClassInspectorUtil.kt
@@ -37,17 +37,15 @@ import com.squareup.kotlinpoet.SET
 import com.squareup.kotlinpoet.TypeName
 import com.squareup.kotlinpoet.asClassName
 import com.squareup.kotlinpoet.joinToCode
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.specs.ClassInspector
 import java.util.Collections
 import java.util.TreeSet
-import kotlinx.metadata.KmProperty
-import kotlinx.metadata.isConst
-import kotlinx.metadata.isLocalClassName
+import kotlin.metadata.KmProperty
+import kotlin.metadata.isConst
+import kotlin.metadata.isLocalClassName
 import org.jetbrains.annotations.NotNull
 import org.jetbrains.annotations.Nullable
 
-@KotlinPoetMetadataPreview
 internal object ClassInspectorUtil {
   val JVM_NAME: ClassName = JvmName::class.asClassName()
   private val JVM_FIELD = JvmField::class.asClassName()
@@ -186,7 +184,7 @@ internal object ClassInspectorUtil {
   }
 
   /**
-   * Best guesses a [ClassName] as represented in Metadata's [kotlinx.metadata.ClassName], where
+   * Best guesses a [ClassName] as represented in Metadata's [kotlin.metadata.ClassName], where
    * package names in this name are separated by '/' and class names are separated by '.'.
    *
    * For example: `"org/foo/bar/Baz.Nested"`.
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector.kt
similarity index 95%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector.kt
index 0282913c..9bac779f 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ElementsClassInspector.kt
@@ -28,7 +28,6 @@ import com.squareup.kotlinpoet.DelicateKotlinPoetApi
 import com.squareup.kotlinpoet.TypeName
 import com.squareup.kotlinpoet.asClassName
 import com.squareup.kotlinpoet.asTypeName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.JAVA_DEPRECATED
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.JVM_NAME
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.filterOutNullabilityAnnotations
@@ -67,31 +66,31 @@ import javax.lang.model.util.ElementFilter
 import javax.lang.model.util.Elements
 import javax.lang.model.util.Types
 import kotlin.LazyThreadSafetyMode.NONE
-import kotlinx.metadata.ClassKind
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmDeclarationContainer
-import kotlinx.metadata.KmPackage
-import kotlinx.metadata.hasAnnotations
-import kotlinx.metadata.hasConstant
-import kotlinx.metadata.isConst
-import kotlinx.metadata.isValue
-import kotlinx.metadata.jvm.JvmFieldSignature
-import kotlinx.metadata.jvm.JvmMethodSignature
-import kotlinx.metadata.jvm.KotlinClassMetadata
-import kotlinx.metadata.jvm.fieldSignature
-import kotlinx.metadata.jvm.getterSignature
-import kotlinx.metadata.jvm.setterSignature
-import kotlinx.metadata.jvm.signature
-import kotlinx.metadata.jvm.syntheticMethodForAnnotations
-import kotlinx.metadata.kind
+import kotlin.metadata.ClassKind
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmDeclarationContainer
+import kotlin.metadata.KmPackage
+import kotlin.metadata.hasAnnotations
+import kotlin.metadata.hasConstant
+import kotlin.metadata.isConst
+import kotlin.metadata.isValue
+import kotlin.metadata.jvm.JvmFieldSignature
+import kotlin.metadata.jvm.JvmMethodSignature
+import kotlin.metadata.jvm.KotlinClassMetadata
+import kotlin.metadata.jvm.fieldSignature
+import kotlin.metadata.jvm.getterSignature
+import kotlin.metadata.jvm.setterSignature
+import kotlin.metadata.jvm.signature
+import kotlin.metadata.jvm.syntheticMethodForAnnotations
+import kotlin.metadata.kind
 
 private typealias ElementsModifier = javax.lang.model.element.Modifier
 
 /**
  * An [Elements]-based implementation of [ClassInspector].
  */
-@KotlinPoetMetadataPreview
 public class ElementsClassInspector private constructor(
+  private val lenient: Boolean,
   private val elements: Elements,
   private val types: Types,
 ) : ClassInspector {
@@ -115,7 +114,7 @@ public class ElementsClassInspector private constructor(
       ?: error("No type element found for: $className.")
 
     val metadata = typeElement.getAnnotation(Metadata::class.java)
-    return when (val kotlinClassMetadata = metadata.readKotlinClassMetadata()) {
+    return when (val kotlinClassMetadata = metadata.readKotlinClassMetadata(lenient)) {
       is KotlinClassMetadata.Class -> kotlinClassMetadata.kmClass
       is KotlinClassMetadata.FileFacade -> kotlinClassMetadata.kmPackage
       else -> TODO("Not implemented yet: ${kotlinClassMetadata.javaClass.simpleName}")
@@ -207,7 +206,7 @@ public class ElementsClassInspector private constructor(
         .filter { types.isSubtype(enumTypeAsType, it.superclass) }
         .find { it.simpleName.contentEquals(memberName) }.toOptional()
     }.nullableValue
-    val declarationContainer = member?.getAnnotation(Metadata::class.java)?.toKmClass()
+    val declarationContainer = member?.getAnnotation(Metadata::class.java)?.toKmClass(lenient)
 
     val entry = ElementFilter.fieldsIn(enumType.enclosedElements)
       .find { it.simpleName.contentEquals(memberName) }
@@ -571,11 +570,13 @@ public class ElementsClassInspector private constructor(
   }
 
   public companion object {
-    /** @return an [Elements]-based implementation of [ClassInspector]. */
+    /**
+     * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+     * @return an [Elements]-based implementation of [ClassInspector].
+     */
     @JvmStatic
-    @KotlinPoetMetadataPreview
-    public fun create(elements: Elements, types: Types): ClassInspector {
-      return ElementsClassInspector(elements, types)
+    public fun create(lenient: Boolean, elements: Elements, types: Types): ClassInspector {
+      return ElementsClassInspector(lenient, elements, types)
     }
 
     private val JVM_STATIC = JvmStatic::class.asClassName()
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/JvmDescriptorUtils.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/JvmDescriptorUtils.kt
similarity index 98%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/JvmDescriptorUtils.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/JvmDescriptorUtils.kt
index aea3213b..f67d80e8 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/JvmDescriptorUtils.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/JvmDescriptorUtils.kt
@@ -43,8 +43,8 @@ import javax.lang.model.type.UnionType
 import javax.lang.model.type.WildcardType
 import javax.lang.model.util.AbstractTypeVisitor8
 import javax.lang.model.util.Types
-import kotlinx.metadata.jvm.JvmFieldSignature
-import kotlinx.metadata.jvm.JvmMethodSignature
+import kotlin.metadata.jvm.JvmFieldSignature
+import kotlin.metadata.jvm.JvmMethodSignature
 
 /*
  * Adapted from
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/Optional.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/Optional.kt
similarity index 100%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/Optional.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/Optional.kt
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector.kt
similarity index 95%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector.kt
index d4c74eb3..9930ba11 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/classinspectors/ReflectiveClassInspector.kt
@@ -22,7 +22,6 @@ import com.squareup.kotlinpoet.CodeBlock
 import com.squareup.kotlinpoet.DelicateKotlinPoetApi
 import com.squareup.kotlinpoet.TypeName
 import com.squareup.kotlinpoet.asTypeName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.JAVA_DEPRECATED
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.filterOutNullabilityAnnotations
 import com.squareup.kotlinpoet.metadata.isDeclaration
@@ -55,26 +54,26 @@ import java.lang.reflect.Parameter
 import java.util.TreeMap
 import java.util.concurrent.ConcurrentHashMap
 import kotlin.LazyThreadSafetyMode.NONE
-import kotlinx.metadata.ClassKind
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmDeclarationContainer
-import kotlinx.metadata.KmPackage
-import kotlinx.metadata.hasAnnotations
-import kotlinx.metadata.hasConstant
-import kotlinx.metadata.isConst
-import kotlinx.metadata.isValue
-import kotlinx.metadata.jvm.JvmFieldSignature
-import kotlinx.metadata.jvm.JvmMethodSignature
-import kotlinx.metadata.jvm.KotlinClassMetadata
-import kotlinx.metadata.jvm.fieldSignature
-import kotlinx.metadata.jvm.getterSignature
-import kotlinx.metadata.jvm.setterSignature
-import kotlinx.metadata.jvm.signature
-import kotlinx.metadata.jvm.syntheticMethodForAnnotations
-import kotlinx.metadata.kind
-
-@KotlinPoetMetadataPreview
+import kotlin.metadata.ClassKind
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmDeclarationContainer
+import kotlin.metadata.KmPackage
+import kotlin.metadata.hasAnnotations
+import kotlin.metadata.hasConstant
+import kotlin.metadata.isConst
+import kotlin.metadata.isValue
+import kotlin.metadata.jvm.JvmFieldSignature
+import kotlin.metadata.jvm.JvmMethodSignature
+import kotlin.metadata.jvm.KotlinClassMetadata
+import kotlin.metadata.jvm.fieldSignature
+import kotlin.metadata.jvm.getterSignature
+import kotlin.metadata.jvm.setterSignature
+import kotlin.metadata.jvm.signature
+import kotlin.metadata.jvm.syntheticMethodForAnnotations
+import kotlin.metadata.kind
+
 public class ReflectiveClassInspector private constructor(
+  private val lenient: Boolean,
   private val classLoader: ClassLoader?,
 ) : ClassInspector {
 
@@ -105,7 +104,7 @@ public class ReflectiveClassInspector private constructor(
       ?: error("No type element found for: $className.")
 
     val metadata = clazz.getAnnotation(Metadata::class.java)
-    return when (val kotlinClassMetadata = metadata.readKotlinClassMetadata()) {
+    return when (val kotlinClassMetadata = metadata.readKotlinClassMetadata(lenient)) {
       is KotlinClassMetadata.Class -> kotlinClassMetadata.kmClass
       is KotlinClassMetadata.FileFacade -> kotlinClassMetadata.kmPackage
       else -> TODO("Not implemented yet: ${kotlinClassMetadata.javaClass.simpleName}")
@@ -251,7 +250,7 @@ public class ReflectiveClassInspector private constructor(
         // class.
         null
       } else {
-        enumEntry.javaClass.getAnnotation(Metadata::class.java)?.toKmClass()
+        enumEntry.javaClass.getAnnotation(Metadata::class.java)?.toKmClass(lenient)
       },
       annotations = clazz.getField(enumEntry.name).annotationSpecs(),
     )
@@ -542,10 +541,12 @@ public class ReflectiveClassInspector private constructor(
   }
 
   public companion object {
+    /**
+     * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+     */
     @JvmStatic
-    @KotlinPoetMetadataPreview
-    public fun create(classLoader: ClassLoader? = null): ClassInspector {
-      return ReflectiveClassInspector(classLoader)
+    public fun create(lenient: Boolean, classLoader: ClassLoader? = null): ClassInspector {
+      return ReflectiveClassInspector(lenient, classLoader)
     }
 
     private val Class<*>.descriptor: String
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ClassInspector.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ClassInspector.kt
similarity index 93%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ClassInspector.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ClassInspector.kt
index 14c019fd..dfcc6d22 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ClassInspector.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ClassInspector.kt
@@ -16,13 +16,11 @@
 package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.ClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmDeclarationContainer
-import kotlinx.metadata.jvm.JvmMethodSignature
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmDeclarationContainer
+import kotlin.metadata.jvm.JvmMethodSignature
 
 /** A basic interface for looking up JVM information about a given Class. */
-@KotlinPoetMetadataPreview
 public interface ClassInspector {
 
   /**
@@ -91,7 +89,6 @@ public interface ClassInspector {
  * @param parentClassName the parent [ClassName] name if [className] is nested, inner, or is a
  *        companion object.
  */
-@KotlinPoetMetadataPreview
 public fun ClassInspector.containerData(
   className: ClassName,
   parentClassName: ClassName?,
@@ -107,7 +104,6 @@ public fun ClassInspector.containerData(
  * @return the read [KmClass] from its metadata. If no class was found, this should throw
  *         an exception.
  */
-@KotlinPoetMetadataPreview
 public fun ClassInspector.classFor(className: ClassName): KmClass {
   val container = declarationContainerFor(className)
   check(container is KmClass) {
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ConstructorData.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ConstructorData.kt
similarity index 96%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ConstructorData.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ConstructorData.kt
index 01c98390..3d8305c4 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ConstructorData.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ConstructorData.kt
@@ -17,7 +17,6 @@ package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.TypeName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 
 /**
@@ -30,7 +29,6 @@ import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
  * @property jvmModifiers set of [JvmMethodModifiers][JvmMethodModifier] on this constructor.
  * @property exceptions list of exceptions thrown by this constructor.
  */
-@KotlinPoetMetadataPreview
 public data class ConstructorData(
   private val annotations: List<AnnotationSpec>,
   val parameterAnnotations: Map<Int, Collection<AnnotationSpec>>,
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ContainerData.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ContainerData.kt
similarity index 90%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ContainerData.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ContainerData.kt
index f1006d01..b4931c1c 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ContainerData.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/ContainerData.kt
@@ -17,13 +17,12 @@ package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.ClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmConstructor
-import kotlinx.metadata.KmDeclarationContainer
-import kotlinx.metadata.KmFunction
-import kotlinx.metadata.KmPackage
-import kotlinx.metadata.KmProperty
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmConstructor
+import kotlin.metadata.KmDeclarationContainer
+import kotlin.metadata.KmFunction
+import kotlin.metadata.KmPackage
+import kotlin.metadata.KmProperty
 
 /**
  * Represents relevant information on a declaration container used for [ClassInspector]. Can only
@@ -35,7 +34,6 @@ import kotlinx.metadata.KmProperty
  * @property properties the mapping of [declarationContainer]'s properties to parsed [PropertyData].
  * @property methods the mapping of [declarationContainer]'s methods to parsed [MethodData].
  */
-@KotlinPoetMetadataPreview
 public interface ContainerData {
   public val declarationContainer: KmDeclarationContainer
   public val annotations: Collection<AnnotationSpec>
@@ -53,7 +51,6 @@ public interface ContainerData {
  * @property constructors the mapping of [declarationContainer]'s constructors to parsed
  * [ConstructorData].
  */
-@KotlinPoetMetadataPreview
 public data class ClassData(
   override val declarationContainer: KmClass,
   val className: ClassName,
@@ -72,7 +69,6 @@ public data class ClassData(
  * @property jvmName the `@JvmName` of the class or null if it does not have a custom name.
  *           Default will try to infer from the [className].
  */
-@KotlinPoetMetadataPreview
 public data class FileData(
   override val declarationContainer: KmPackage,
   override val annotations: Collection<AnnotationSpec>,
@@ -97,7 +93,6 @@ public data class FileData(
  * [@Metadata][Metadata] annotation.
  * @property annotations the annotations for the entry
  */
-@KotlinPoetMetadataPreview
 public data class EnumEntryData(
   val declarationContainer: KmClass?,
   val annotations: Collection<AnnotationSpec>,
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/FieldData.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/FieldData.kt
similarity index 95%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/FieldData.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/FieldData.kt
index a000ddef..50c0888e 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/FieldData.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/FieldData.kt
@@ -18,7 +18,6 @@ package com.squareup.kotlinpoet.metadata.specs
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.AnnotationSpec.UseSiteTarget.FIELD
 import com.squareup.kotlinpoet.CodeBlock
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 
 /**
@@ -31,7 +30,6 @@ import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
  * @property constant the constant value of this field, if available. Note that this is does not
  *           strictly imply that the associated property is `const`.
  */
-@KotlinPoetMetadataPreview
 public data class FieldData(
   private val annotations: List<AnnotationSpec>,
   val isSynthetic: Boolean,
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmFieldModifier.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmFieldModifier.kt
similarity index 93%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmFieldModifier.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmFieldModifier.kt
index dc2a55bb..7ef5030c 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmFieldModifier.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmFieldModifier.kt
@@ -17,10 +17,8 @@ package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.asClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 
 /** Modifiers that are annotations in Kotlin but modifier keywords in bytecode. */
-@KotlinPoetMetadataPreview
 public enum class JvmFieldModifier : JvmModifier {
   STATIC {
     override fun annotationSpec(): AnnotationSpec = AnnotationSpec.builder(
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmMethodModifier.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmMethodModifier.kt
similarity index 92%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmMethodModifier.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmMethodModifier.kt
index 5d63738b..e187deb7 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmMethodModifier.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmMethodModifier.kt
@@ -17,10 +17,8 @@ package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.asClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 
 /** Modifiers that are annotations or implicit in Kotlin but modifier keywords in bytecode. */
-@KotlinPoetMetadataPreview
 public enum class JvmMethodModifier : JvmModifier {
   STATIC {
     override fun annotationSpec(): AnnotationSpec = AnnotationSpec.builder(
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmModifier.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmModifier.kt
similarity index 92%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmModifier.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmModifier.kt
index f09e6add..1396a4ae 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmModifier.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmModifier.kt
@@ -16,7 +16,6 @@
 package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.AnnotationSpec
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 
 /**
  * Represents a JVM modifier that is represented as an annotation in Kotlin but as a modifier in
@@ -25,7 +24,6 @@ import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
  *
  * This API is considered read-only and should not be implemented outside of KotlinPoet.
  */
-@KotlinPoetMetadataPreview
 public interface JvmModifier {
   public fun annotationSpec(): AnnotationSpec? {
     return null
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KmTypes.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KmTypes.kt
similarity index 90%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KmTypes.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KmTypes.kt
index 23e793d0..2830452f 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KmTypes.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KmTypes.kt
@@ -24,31 +24,30 @@ import com.squareup.kotlinpoet.STAR
 import com.squareup.kotlinpoet.TypeName
 import com.squareup.kotlinpoet.TypeVariableName
 import com.squareup.kotlinpoet.WildcardTypeName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 import com.squareup.kotlinpoet.metadata.isPrimary
 import com.squareup.kotlinpoet.tags.TypeAliasTag
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmClassifier
-import kotlinx.metadata.KmClassifier.Class
-import kotlinx.metadata.KmClassifier.TypeAlias
-import kotlinx.metadata.KmClassifier.TypeParameter
-import kotlinx.metadata.KmConstructor
-import kotlinx.metadata.KmFlexibleTypeUpperBound
-import kotlinx.metadata.KmFunction
-import kotlinx.metadata.KmProperty
-import kotlinx.metadata.KmType
-import kotlinx.metadata.KmTypeParameter
-import kotlinx.metadata.KmTypeProjection
-import kotlinx.metadata.KmVariance
-import kotlinx.metadata.KmVariance.IN
-import kotlinx.metadata.KmVariance.INVARIANT
-import kotlinx.metadata.KmVariance.OUT
-import kotlinx.metadata.isNullable
-import kotlinx.metadata.isReified
-import kotlinx.metadata.isSuspend
-import kotlinx.metadata.jvm.annotations
-import kotlinx.metadata.jvm.signature
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmClassifier
+import kotlin.metadata.KmClassifier.Class
+import kotlin.metadata.KmClassifier.TypeAlias
+import kotlin.metadata.KmClassifier.TypeParameter
+import kotlin.metadata.KmConstructor
+import kotlin.metadata.KmFlexibleTypeUpperBound
+import kotlin.metadata.KmFunction
+import kotlin.metadata.KmProperty
+import kotlin.metadata.KmType
+import kotlin.metadata.KmTypeParameter
+import kotlin.metadata.KmTypeProjection
+import kotlin.metadata.KmVariance
+import kotlin.metadata.KmVariance.IN
+import kotlin.metadata.KmVariance.INVARIANT
+import kotlin.metadata.KmVariance.OUT
+import kotlin.metadata.isNullable
+import kotlin.metadata.isReified
+import kotlin.metadata.isSuspend
+import kotlin.metadata.jvm.annotations
+import kotlin.metadata.jvm.signature
 
 /**
  * `true` if this is an extension type (i.e. String.() -> Unit vs (String) -> Unit).
@@ -59,7 +58,6 @@ public val KmType.isExtensionType: Boolean get() {
   return annotations.any { it.className == "kotlin/ExtensionFunctionType" }
 }
 
-@KotlinPoetMetadataPreview
 internal val KmClass.primaryConstructor: KmConstructor?
   get() = constructors.find { it.isPrimary }
 
@@ -71,7 +69,6 @@ internal fun KmVariance.toKModifier(): KModifier? {
   }
 }
 
-@KotlinPoetMetadataPreview
 internal fun KmTypeProjection.toTypeName(
   typeParamResolver: TypeParameterResolver,
 ): TypeName {
@@ -89,7 +86,6 @@ internal fun KmTypeProjection.toTypeName(
  * "source" representation. This includes converting [functions][kotlin.Function] and `suspend`
  * types to appropriate [lambda representations][LambdaTypeName].
  */
-@KotlinPoetMetadataPreview
 internal fun KmType.toTypeName(
   typeParamResolver: TypeParameterResolver,
 ): TypeName {
@@ -164,7 +160,6 @@ internal fun KmType.toTypeName(
   } ?: finalType
 }
 
-@KotlinPoetMetadataPreview
 internal fun KmTypeParameter.toTypeVariableName(
   typeParamResolver: TypeParameterResolver,
 ): TypeVariableName {
@@ -186,7 +181,6 @@ internal fun KmTypeParameter.toTypeVariableName(
   )
 }
 
-@KotlinPoetMetadataPreview
 private fun KmFlexibleTypeUpperBound.toTypeName(
   typeParamResolver: TypeParameterResolver,
 ): TypeName {
@@ -207,7 +201,6 @@ internal interface TypeParameterResolver {
   }
 }
 
-@KotlinPoetMetadataPreview
 internal fun List<KmTypeParameter>.toTypeParameterResolver(
   fallback: TypeParameterResolver? = null,
 ): TypeParameterResolver {
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs.kt
similarity index 86%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs.kt
index 88c7b25b..33fdf377 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecs.kt
@@ -33,13 +33,11 @@ import com.squareup.kotlinpoet.KModifier.CROSSINLINE
 import com.squareup.kotlinpoet.KModifier.DATA
 import com.squareup.kotlinpoet.KModifier.EXPECT
 import com.squareup.kotlinpoet.KModifier.EXTERNAL
-import com.squareup.kotlinpoet.KModifier.FINAL
 import com.squareup.kotlinpoet.KModifier.INFIX
 import com.squareup.kotlinpoet.KModifier.INLINE
 import com.squareup.kotlinpoet.KModifier.INNER
 import com.squareup.kotlinpoet.KModifier.LATEINIT
 import com.squareup.kotlinpoet.KModifier.NOINLINE
-import com.squareup.kotlinpoet.KModifier.OPEN
 import com.squareup.kotlinpoet.KModifier.OPERATOR
 import com.squareup.kotlinpoet.KModifier.PRIVATE
 import com.squareup.kotlinpoet.KModifier.PUBLIC
@@ -54,7 +52,6 @@ import com.squareup.kotlinpoet.TypeAliasSpec
 import com.squareup.kotlinpoet.TypeSpec
 import com.squareup.kotlinpoet.UNIT
 import com.squareup.kotlinpoet.asClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.createAnnotations
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.createClassName
@@ -77,94 +74,109 @@ import javax.lang.model.element.Element
 import javax.lang.model.element.ElementKind
 import javax.lang.model.element.PackageElement
 import javax.lang.model.element.TypeElement
+import kotlin.metadata.ClassKind
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmClassifier
+import kotlin.metadata.KmConstructor
+import kotlin.metadata.KmFunction
+import kotlin.metadata.KmPackage
+import kotlin.metadata.KmProperty
+import kotlin.metadata.KmPropertyAccessorAttributes
+import kotlin.metadata.KmType
+import kotlin.metadata.KmTypeAlias
+import kotlin.metadata.KmValueParameter
+import kotlin.metadata.Modality
+import kotlin.metadata.Visibility
+import kotlin.metadata.declaresDefaultValue
+import kotlin.metadata.hasAnnotations
+import kotlin.metadata.isConst
+import kotlin.metadata.isCrossinline
+import kotlin.metadata.isData
+import kotlin.metadata.isDelegated
+import kotlin.metadata.isExpect
+import kotlin.metadata.isExternal
+import kotlin.metadata.isFunInterface
+import kotlin.metadata.isInfix
+import kotlin.metadata.isInline
+import kotlin.metadata.isInner
+import kotlin.metadata.isLateinit
+import kotlin.metadata.isNoinline
+import kotlin.metadata.isOperator
+import kotlin.metadata.isReified
+import kotlin.metadata.isSuspend
+import kotlin.metadata.isTailrec
+import kotlin.metadata.isValue
+import kotlin.metadata.isVar
+import kotlin.metadata.jvm.JvmMethodSignature
+import kotlin.metadata.jvm.getterSignature
+import kotlin.metadata.jvm.setterSignature
+import kotlin.metadata.jvm.signature
+import kotlin.metadata.jvm.toJvmInternalName
+import kotlin.metadata.kind
+import kotlin.metadata.modality
+import kotlin.metadata.visibility
 import kotlin.reflect.KClass
-import kotlinx.metadata.ClassKind
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmClassifier
-import kotlinx.metadata.KmConstructor
-import kotlinx.metadata.KmFunction
-import kotlinx.metadata.KmPackage
-import kotlinx.metadata.KmProperty
-import kotlinx.metadata.KmPropertyAccessorAttributes
-import kotlinx.metadata.KmType
-import kotlinx.metadata.KmTypeAlias
-import kotlinx.metadata.KmValueParameter
-import kotlinx.metadata.Modality
-import kotlinx.metadata.Visibility
-import kotlinx.metadata.declaresDefaultValue
-import kotlinx.metadata.hasAnnotations
-import kotlinx.metadata.hasGetter
-import kotlinx.metadata.hasSetter
-import kotlinx.metadata.isConst
-import kotlinx.metadata.isCrossinline
-import kotlinx.metadata.isData
-import kotlinx.metadata.isDelegated
-import kotlinx.metadata.isExpect
-import kotlinx.metadata.isExternal
-import kotlinx.metadata.isFunInterface
-import kotlinx.metadata.isInfix
-import kotlinx.metadata.isInline
-import kotlinx.metadata.isInner
-import kotlinx.metadata.isLateinit
-import kotlinx.metadata.isNoinline
-import kotlinx.metadata.isOperator
-import kotlinx.metadata.isReified
-import kotlinx.metadata.isSuspend
-import kotlinx.metadata.isTailrec
-import kotlinx.metadata.isValue
-import kotlinx.metadata.isVar
-import kotlinx.metadata.jvm.JvmMethodSignature
-import kotlinx.metadata.jvm.getterSignature
-import kotlinx.metadata.jvm.setterSignature
-import kotlinx.metadata.jvm.signature
-import kotlinx.metadata.jvm.toJvmInternalName
-import kotlinx.metadata.kind
-import kotlinx.metadata.modality
-import kotlinx.metadata.visibility
-
-/** @return a [TypeSpec] ABI representation of this [KClass]. */
-@KotlinPoetMetadataPreview
+
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a [TypeSpec] ABI representation of this [KClass].
+ */
 public fun KClass<*>.toTypeSpec(
+  lenient: Boolean,
   classInspector: ClassInspector? = null,
-): TypeSpec = java.toTypeSpec(classInspector)
+): TypeSpec = java.toTypeSpec(lenient, classInspector)
 
-/** @return a [TypeSpec] ABI representation of this [KClass]. */
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a [TypeSpec] ABI representation of this [KClass].
+ */
 @OptIn(DelicateKotlinPoetApi::class)
-@KotlinPoetMetadataPreview
 public fun Class<*>.toTypeSpec(
+  lenient: Boolean,
   classInspector: ClassInspector? = null,
-): TypeSpec = toKmClass().toTypeSpec(classInspector, asClassName())
+): TypeSpec = toKmClass(lenient).toTypeSpec(classInspector, asClassName())
 
-/** @return a [TypeSpec] ABI representation of this [TypeElement]. */
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a [TypeSpec] ABI representation of this [TypeElement].
+ */
 @OptIn(DelicateKotlinPoetApi::class)
-@KotlinPoetMetadataPreview
 public fun TypeElement.toTypeSpec(
+  lenient: Boolean,
   classInspector: ClassInspector? = null,
-): TypeSpec = toKmClass().toTypeSpec(classInspector, asClassName())
+): TypeSpec = toKmClass(lenient).toTypeSpec(classInspector, asClassName())
 
-/** @return a [FileSpec] ABI representation of this [KClass]. */
-@KotlinPoetMetadataPreview
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a [FileSpec] ABI representation of this [KClass].
+ */
 public fun KClass<*>.toFileSpec(
+  lenient: Boolean,
   classInspector: ClassInspector? = null,
-): FileSpec = java.toFileSpec(classInspector)
+): FileSpec = java.toFileSpec(lenient, classInspector)
 
-/** @return a [FileSpec] ABI representation of this [KClass]. */
-@KotlinPoetMetadataPreview
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a [FileSpec] ABI representation of this [KClass].
+ */
 public fun Class<*>.toFileSpec(
+  lenient: Boolean,
   classInspector: ClassInspector? = null,
-): FileSpec = FileSpec.get(`package`.name, toTypeSpec(classInspector))
+): FileSpec = FileSpec.get(`package`.name, toTypeSpec(lenient, classInspector))
 
-/** @return a [FileSpec] ABI representation of this [TypeElement]. */
-@KotlinPoetMetadataPreview
+/**
+ * @param lenient see docs on [KotlinClassMetadata.readStrict] and [KotlinClassMetadata.readLenient] for more details.
+ * @return a [FileSpec] ABI representation of this [TypeElement].
+ */
 public fun TypeElement.toFileSpec(
+  lenient: Boolean,
   classInspector: ClassInspector? = null,
 ): FileSpec = FileSpec.get(
   packageName = packageName,
-  typeSpec = toTypeSpec(classInspector),
+  typeSpec = toTypeSpec(lenient, classInspector),
 )
 
 /** @return a [TypeSpec] ABI representation of this [KmClass]. */
-@KotlinPoetMetadataPreview
 public fun KmClass.toTypeSpec(
   classInspector: ClassInspector?,
   className: ClassName = createClassName(name),
@@ -173,7 +185,6 @@ public fun KmClass.toTypeSpec(
 }
 
 /** @return a [FileSpec] ABI representation of this [KmClass]. */
-@KotlinPoetMetadataPreview
 public fun KmClass.toFileSpec(
   classInspector: ClassInspector?,
   className: ClassName = createClassName(name),
@@ -185,7 +196,6 @@ public fun KmClass.toFileSpec(
 }
 
 /** @return a [FileSpec] ABI representation of this [KmPackage]. */
-@KotlinPoetMetadataPreview
 public fun KmPackage.toFileSpec(
   classInspector: ClassInspector?,
   className: ClassName,
@@ -243,7 +253,6 @@ public fun KmPackage.toFileSpec(
 
 private const val NOT_IMPLEMENTED = "throw·NotImplementedError(\"Stub!\")"
 
-@KotlinPoetMetadataPreview
 private fun KmClass.toTypeSpec(
   classInspector: ClassInspector?,
   className: ClassName,
@@ -483,7 +492,6 @@ private fun companionObjectName(name: String): String? {
   return if (name == "Companion") null else name
 }
 
-@KotlinPoetMetadataPreview
 private fun KmConstructor.toFunSpec(
   typeParamResolver: TypeParameterResolver,
   constructorData: ConstructorData?,
@@ -511,14 +519,12 @@ private fun KmConstructor.toFunSpec(
     .build()
 }
 
-@KotlinPoetMetadataPreview
 private val ContainerData.isInterface: Boolean get() {
   return declarationContainer.let { container ->
     container is KmClass && container.isInterface
   }
 }
 
-@KotlinPoetMetadataPreview
 private fun KmFunction.toFunSpec(
   classTypeParamsResolver: TypeParameterResolver = TypeParameterResolver.EMPTY,
   classInspector: ClassInspector? = null,
@@ -609,7 +615,6 @@ private fun KmFunction.toFunSpec(
     .build()
 }
 
-@KotlinPoetMetadataPreview
 private fun KmValueParameter.toParameterSpec(
   typeParamResolver: TypeParameterResolver,
   annotations: Collection<AnnotationSpec>,
@@ -635,7 +640,6 @@ private fun KmValueParameter.toParameterSpec(
     .build()
 }
 
-@KotlinPoetMetadataPreview
 private fun KmProperty.toPropertySpec(
   typeParamResolver: TypeParameterResolver = TypeParameterResolver.EMPTY,
   isConstructorParam: Boolean = false,
@@ -648,33 +652,31 @@ private fun KmProperty.toPropertySpec(
   val returnTypeName = returnType.toTypeName(typeParamResolver)
   val mutableAnnotations = mutableListOf<AnnotationSpec>()
   if (containerData != null && propertyData != null) {
-    if (hasGetter) {
-      getterSignature?.let { getterSignature ->
-        if (!containerData.isInterface &&
-          modality != Modality.OPEN && modality != Modality.ABSTRACT
+    getterSignature?.let { getterSignature ->
+      if (!containerData.isInterface &&
+        modality != Modality.OPEN && modality != Modality.ABSTRACT
+      ) {
+        // Infer if JvmName was used
+        // We skip interface types or open/abstract properties because they can't have @JvmName.
+        // For annotation properties, kotlinc puts JvmName annotations by default in
+        // bytecode but they're implicit in source, so we expect the simple name for
+        // annotation types.
+        val expectedMetadataName = if (containerData is ClassData &&
+          containerData.declarationContainer.isAnnotation
         ) {
-          // Infer if JvmName was used
-          // We skip interface types or open/abstract properties because they can't have @JvmName.
-          // For annotation properties, kotlinc puts JvmName annotations by default in
-          // bytecode but they're implicit in source, so we expect the simple name for
-          // annotation types.
-          val expectedMetadataName = if (containerData is ClassData &&
-            containerData.declarationContainer.isAnnotation
-          ) {
-            name
-          } else {
-            "get${name.safeCapitalize(Locale.US)}"
-          }
-          getterSignature.jvmNameAnnotation(
-            metadataName = expectedMetadataName,
-            useSiteTarget = UseSiteTarget.GET,
-          )?.let { jvmNameAnnotation ->
-            mutableAnnotations += jvmNameAnnotation
-          }
+          name
+        } else {
+          "get${name.safeCapitalize(Locale.US)}"
+        }
+        getterSignature.jvmNameAnnotation(
+          metadataName = expectedMetadataName,
+          useSiteTarget = UseSiteTarget.GET,
+        )?.let { jvmNameAnnotation ->
+          mutableAnnotations += jvmNameAnnotation
         }
       }
     }
-    if (hasSetter) {
+    if (setter != null) {
       setterSignature?.let { setterSignature ->
         if (containerData is ClassData &&
           !containerData.declarationContainer.isAnnotation &&
@@ -777,15 +779,15 @@ private fun KmProperty.toPropertySpec(
       // since the delegate handles it
       // vals with initialized constants have a getter in bytecode but not a body in kotlin source
       val modifierSet = modifiers.toSet()
-      if (hasGetter && !isDelegated && modality != Modality.ABSTRACT) {
+      if (!isDelegated && modality != Modality.ABSTRACT) {
         propertyAccessor(
           modifierSet,
-          getter,
+          this@toPropertySpec.getter,
           FunSpec.getterBuilder().addStatement(NOT_IMPLEMENTED),
           isOverride,
         )?.let(::getter)
       }
-      if (hasSetter && !isDelegated && modality != Modality.ABSTRACT) {
+      if (setter != null && !isDelegated && modality != Modality.ABSTRACT) {
         propertyAccessor(modifierSet, setter!!, FunSpec.setterBuilder(), isOverride)?.let(::setter)
       }
     }
@@ -793,7 +795,6 @@ private fun KmProperty.toPropertySpec(
     .build()
 }
 
-@KotlinPoetMetadataPreview
 private fun propertyAccessor(
   propertyModifiers: Set<KModifier>,
   attrs: KmPropertyAccessorAttributes,
@@ -831,7 +832,6 @@ private fun propertyAccessor(
   }
 }
 
-@KotlinPoetMetadataPreview
 private fun KmTypeAlias.toTypeAliasSpec(): TypeAliasSpec {
   val typeParamResolver = typeParameters.toTypeParameterResolver()
   return TypeAliasSpec.builder(name, underlyingType.toTypeName(typeParamResolver))
@@ -868,7 +868,6 @@ private val JAVA_ANNOTATION_ANNOTATIONS = setOf(
   java.lang.annotation.Target::class.asClassName(),
 )
 
-@KotlinPoetMetadataPreview
 private fun visibilityFrom(visibility: Visibility, body: (KModifier) -> Unit) {
   val modifierVisibility = visibility.toKModifier()
   if (modifierVisibility != PUBLIC) {
@@ -880,13 +879,8 @@ private fun String.safeCapitalize(locale: Locale): String {
   return replaceFirstChar { if (it.isLowerCase()) it.titlecase(locale) else it.toString() }
 }
 
-private inline fun <E> setOf(body: MutableSet<E>.() -> Unit): Set<E> {
-  return mutableSetOf<E>().apply(body).toSet()
-}
-
 private val METADATA = Metadata::class.asClassName()
 
-@Suppress("DEPRECATION")
 private val JVM_DEFAULT = ClassName("kotlin.jvm", "JvmDefault")
 private val JVM_STATIC = JvmStatic::class.asClassName()
 
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/MethodData.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/MethodData.kt
similarity index 97%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/MethodData.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/MethodData.kt
index 7319e9d8..ebafce22 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/MethodData.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/MethodData.kt
@@ -18,7 +18,6 @@ package com.squareup.kotlinpoet.metadata.specs
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.AnnotationSpec.UseSiteTarget
 import com.squareup.kotlinpoet.TypeName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 
 /**
@@ -32,7 +31,6 @@ import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
  * @property isOverride indicates if this method overrides one in a supertype.
  * @property exceptions list of exceptions thrown by this method.
  */
-@KotlinPoetMetadataPreview
 public data class MethodData(
   private val annotations: List<AnnotationSpec>,
   val parameterAnnotations: Map<Int, Collection<AnnotationSpec>>,
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/PropertyData.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/PropertyData.kt
similarity index 97%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/PropertyData.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/PropertyData.kt
index 9fc6d3e4..4657c0d2 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/PropertyData.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/PropertyData.kt
@@ -18,7 +18,6 @@ package com.squareup.kotlinpoet.metadata.specs
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.AnnotationSpec.UseSiteTarget.GET
 import com.squareup.kotlinpoet.AnnotationSpec.UseSiteTarget.SET
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 
 /**
@@ -31,7 +30,6 @@ import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
  * @property setterData associated setter (as [MethodData]) with this property, if any.
  * @property isJvmField indicates if this property should be treated as a jvm field.
  */
-@KotlinPoetMetadataPreview
 public data class PropertyData(
   private val annotations: List<AnnotationSpec>,
   val fieldData: FieldData?,
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/kmAnnotations.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/kmAnnotations.kt
similarity index 67%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/kmAnnotations.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/kmAnnotations.kt
index 671147f7..8a3d4438 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/kmAnnotations.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/specs/kmAnnotations.kt
@@ -20,30 +20,28 @@ import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.CodeBlock
 import com.squareup.kotlinpoet.buildCodeBlock
 import com.squareup.kotlinpoet.joinToCode
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil.createClassName
 import com.squareup.kotlinpoet.tag
-import kotlinx.metadata.KmAnnotation
-import kotlinx.metadata.KmAnnotationArgument
-import kotlinx.metadata.KmAnnotationArgument.AnnotationValue
-import kotlinx.metadata.KmAnnotationArgument.ArrayValue
-import kotlinx.metadata.KmAnnotationArgument.BooleanValue
-import kotlinx.metadata.KmAnnotationArgument.ByteValue
-import kotlinx.metadata.KmAnnotationArgument.CharValue
-import kotlinx.metadata.KmAnnotationArgument.DoubleValue
-import kotlinx.metadata.KmAnnotationArgument.EnumValue
-import kotlinx.metadata.KmAnnotationArgument.FloatValue
-import kotlinx.metadata.KmAnnotationArgument.IntValue
-import kotlinx.metadata.KmAnnotationArgument.KClassValue
-import kotlinx.metadata.KmAnnotationArgument.LongValue
-import kotlinx.metadata.KmAnnotationArgument.ShortValue
-import kotlinx.metadata.KmAnnotationArgument.StringValue
-import kotlinx.metadata.KmAnnotationArgument.UByteValue
-import kotlinx.metadata.KmAnnotationArgument.UIntValue
-import kotlinx.metadata.KmAnnotationArgument.ULongValue
-import kotlinx.metadata.KmAnnotationArgument.UShortValue
+import kotlin.metadata.KmAnnotation
+import kotlin.metadata.KmAnnotationArgument
+import kotlin.metadata.KmAnnotationArgument.AnnotationValue
+import kotlin.metadata.KmAnnotationArgument.ArrayValue
+import kotlin.metadata.KmAnnotationArgument.BooleanValue
+import kotlin.metadata.KmAnnotationArgument.ByteValue
+import kotlin.metadata.KmAnnotationArgument.CharValue
+import kotlin.metadata.KmAnnotationArgument.DoubleValue
+import kotlin.metadata.KmAnnotationArgument.EnumValue
+import kotlin.metadata.KmAnnotationArgument.FloatValue
+import kotlin.metadata.KmAnnotationArgument.IntValue
+import kotlin.metadata.KmAnnotationArgument.KClassValue
+import kotlin.metadata.KmAnnotationArgument.LongValue
+import kotlin.metadata.KmAnnotationArgument.ShortValue
+import kotlin.metadata.KmAnnotationArgument.StringValue
+import kotlin.metadata.KmAnnotationArgument.UByteValue
+import kotlin.metadata.KmAnnotationArgument.UIntValue
+import kotlin.metadata.KmAnnotationArgument.ULongValue
+import kotlin.metadata.KmAnnotationArgument.UShortValue
 
-@KotlinPoetMetadataPreview
 internal fun KmAnnotation.toAnnotationSpec(): AnnotationSpec {
   val cn = createClassName(className)
   return AnnotationSpec.builder(cn)
@@ -56,8 +54,6 @@ internal fun KmAnnotation.toAnnotationSpec(): AnnotationSpec {
     .build()
 }
 
-@OptIn(ExperimentalUnsignedTypes::class)
-@KotlinPoetMetadataPreview
 internal fun KmAnnotationArgument.toCodeBlock(): CodeBlock {
   return when (this) {
     is ByteValue -> CodeBlock.of("%L", value)
diff --git a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/util.kt b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/util.kt
similarity index 85%
rename from interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/util.kt
rename to interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/util.kt
index ab30c8ee..91e22824 100644
--- a/interop/kotlinx-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/util.kt
+++ b/interop/kotlin-metadata/src/main/kotlin/com/squareup/kotlinpoet/metadata/util.kt
@@ -16,16 +16,16 @@
 package com.squareup.kotlinpoet.metadata
 
 import com.squareup.kotlinpoet.KModifier
-import kotlinx.metadata.ClassKind
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmConstructor
-import kotlinx.metadata.KmProperty
-import kotlinx.metadata.MemberKind
-import kotlinx.metadata.Modality
-import kotlinx.metadata.Visibility
-import kotlinx.metadata.isSecondary
-import kotlinx.metadata.isVar
-import kotlinx.metadata.kind
+import kotlin.metadata.ClassKind
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmConstructor
+import kotlin.metadata.KmProperty
+import kotlin.metadata.MemberKind
+import kotlin.metadata.Modality
+import kotlin.metadata.Visibility
+import kotlin.metadata.isSecondary
+import kotlin.metadata.isVar
+import kotlin.metadata.kind
 
 internal val KmClass.isObject: Boolean
   get() = kind == ClassKind.OBJECT
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFile.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFile.kt
similarity index 98%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFile.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFile.kt
index 6eb40a88..7417f303 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFile.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFile.kt
@@ -15,6 +15,7 @@
  */
 @file:JvmName("FacadeFile")
 @file:FileAnnotation("file annotations!")
+@file:Suppress("unused", "UNUSED_PARAMETER")
 
 package com.squareup.kotlinpoet.metadata.specs
 
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFileTest.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFileTest.kt
similarity index 99%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFileTest.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFileTest.kt
index e31c0cc6..8180b0b3 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFileTest.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/FacadeFileTest.kt
@@ -17,12 +17,10 @@ package com.squareup.kotlinpoet.metadata.specs
 
 import com.google.common.truth.Truth.assertThat
 import com.squareup.kotlinpoet.FileSpec
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.specs.MultiClassInspectorTest.ClassInspectorType.ELEMENTS
 import com.squareup.kotlinpoet.metadata.specs.MultiClassInspectorTest.ClassInspectorType.REFLECTIVE
 import org.junit.Test
 
-@KotlinPoetMetadataPreview
 class FacadeFileTest : MultiClassInspectorTest() {
 
   @IgnoreForHandlerType(
@@ -60,13 +58,6 @@ class FacadeFileTest : MultiClassInspectorTest() {
       public fun jvmNameFunction() {
       }
 
-      public fun jvmOverloads(
-        param1: String,
-        optionalParam2: String = throw NotImplementedError("Stub!"),
-        nullableParam3: String? = throw NotImplementedError("Stub!"),
-      ) {
-      }
-
       public fun regularFun() {
       }
 
@@ -74,65 +65,72 @@ class FacadeFileTest : MultiClassInspectorTest() {
       public fun synchronizedFun() {
       }
 
-      public val BINARY_PROP: Int = 11
+      public fun jvmOverloads(
+        param1: String,
+        optionalParam2: String = throw NotImplementedError("Stub!"),
+        nullableParam3: String? = throw NotImplementedError("Stub!"),
+      ) {
+      }
 
       public val BOOL_PROP: Boolean = false
 
-      public const val CONST_BINARY_PROP: Int = 11
+      public val BINARY_PROP: Int = 11
 
-      public const val CONST_BOOL_PROP: Boolean = false
+      public val INT_PROP: Int = 1
 
-      public const val CONST_DOUBLE_PROP: Double = 1.0
+      public val UNDERSCORES_PROP: Int = 1_000_000
 
-      public const val CONST_FLOAT_PROP: Float = 1.0F
+      public val HEX_PROP: Int = 15
 
-      public const val CONST_HEX_PROP: Int = 15
+      public val UNDERSCORES_HEX_PROP: Long = 4_293_713_502L
 
-      public const val CONST_INT_PROP: Int = 1
+      public val LONG_PROP: Long = 1L
 
-      public const val CONST_LONG_PROP: Long = 1L
+      public val FLOAT_PROP: Float = 1.0F
 
-      public const val CONST_STRING_PROP: String = "prop"
+      public val DOUBLE_PROP: Double = 1.0
 
-      public const val CONST_UNDERSCORES_HEX_PROP: Long = 4_293_713_502L
+      public val STRING_PROP: String = "prop"
 
-      public const val CONST_UNDERSCORES_PROP: Int = 1_000_000
+      public var VAR_BOOL_PROP: Boolean = throw NotImplementedError("Stub!")
 
-      public val DOUBLE_PROP: Double = 1.0
+      public var VAR_BINARY_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val FLOAT_PROP: Float = 1.0F
+      public var VAR_INT_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val HEX_PROP: Int = 15
+      public var VAR_UNDERSCORES_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val INT_PROP: Int = 1
+      public var VAR_HEX_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val LONG_PROP: Long = 1L
+      public var VAR_UNDERSCORES_HEX_PROP: Long = throw NotImplementedError("Stub!")
 
-      public val STRING_PROP: String = "prop"
+      public var VAR_LONG_PROP: Long = throw NotImplementedError("Stub!")
 
-      public val UNDERSCORES_HEX_PROP: Long = 4_293_713_502L
+      public var VAR_FLOAT_PROP: Float = throw NotImplementedError("Stub!")
 
-      public val UNDERSCORES_PROP: Int = 1_000_000
+      public var VAR_DOUBLE_PROP: Double = throw NotImplementedError("Stub!")
 
-      public var VAR_BINARY_PROP: Int = throw NotImplementedError("Stub!")
+      public var VAR_STRING_PROP: String = throw NotImplementedError("Stub!")
 
-      public var VAR_BOOL_PROP: Boolean = throw NotImplementedError("Stub!")
+      public const val CONST_BOOL_PROP: Boolean = false
 
-      public var VAR_DOUBLE_PROP: Double = throw NotImplementedError("Stub!")
+      public const val CONST_BINARY_PROP: Int = 11
 
-      public var VAR_FLOAT_PROP: Float = throw NotImplementedError("Stub!")
+      public const val CONST_INT_PROP: Int = 1
 
-      public var VAR_HEX_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_UNDERSCORES_PROP: Int = 1_000_000
 
-      public var VAR_INT_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_HEX_PROP: Int = 15
 
-      public var VAR_LONG_PROP: Long = throw NotImplementedError("Stub!")
+      public const val CONST_UNDERSCORES_HEX_PROP: Long = 4_293_713_502L
 
-      public var VAR_STRING_PROP: String = throw NotImplementedError("Stub!")
+      public const val CONST_LONG_PROP: Long = 1L
 
-      public var VAR_UNDERSCORES_HEX_PROP: Long = throw NotImplementedError("Stub!")
+      public const val CONST_FLOAT_PROP: Float = 1.0F
 
-      public var VAR_UNDERSCORES_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_DOUBLE_PROP: Double = 1.0
+
+      public const val CONST_STRING_PROP: String = "prop"
 
       @field:JvmSynthetic
       @JvmField
@@ -151,11 +149,11 @@ class FacadeFileTest : MultiClassInspectorTest() {
       @set:JvmSynthetic
       public var syntheticPropertySet: String? = null
 
+      public typealias FacadeTypeAliasName = String
+
       public typealias FacadeGenericTypeAlias = List<String>
 
       public typealias FacadeNestedTypeAlias = List<GenericTypeAlias>
-
-      public typealias FacadeTypeAliasName = String
       """.trimIndent(),
     )
   }
@@ -195,6 +193,13 @@ class FacadeFileTest : MultiClassInspectorTest() {
       public fun jvmNameFunction() {
       }
 
+      public fun regularFun() {
+      }
+
+      @Synchronized
+      public fun synchronizedFun() {
+      }
+
       @JvmOverloads
       public fun jvmOverloads(
         param1: String,
@@ -203,72 +208,65 @@ class FacadeFileTest : MultiClassInspectorTest() {
       ) {
       }
 
-      public fun regularFun() {
-      }
-
-      @Synchronized
-      public fun synchronizedFun() {
-      }
+      public val BOOL_PROP: Boolean = throw NotImplementedError("Stub!")
 
       public val BINARY_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val BOOL_PROP: Boolean = throw NotImplementedError("Stub!")
-
-      public const val CONST_BINARY_PROP: Int = 11
+      public val INT_PROP: Int = throw NotImplementedError("Stub!")
 
-      public const val CONST_BOOL_PROP: Boolean = false
+      public val UNDERSCORES_PROP: Int = throw NotImplementedError("Stub!")
 
-      public const val CONST_DOUBLE_PROP: Double = 1.0
+      public val HEX_PROP: Int = throw NotImplementedError("Stub!")
 
-      public const val CONST_FLOAT_PROP: Float = 1.0F
+      public val UNDERSCORES_HEX_PROP: Long = throw NotImplementedError("Stub!")
 
-      public const val CONST_HEX_PROP: Int = 15
+      public val LONG_PROP: Long = throw NotImplementedError("Stub!")
 
-      public const val CONST_INT_PROP: Int = 1
+      public val FLOAT_PROP: Float = throw NotImplementedError("Stub!")
 
-      public const val CONST_LONG_PROP: Long = 1L
+      public val DOUBLE_PROP: Double = throw NotImplementedError("Stub!")
 
-      public const val CONST_STRING_PROP: String = "prop"
+      public val STRING_PROP: String = throw NotImplementedError("Stub!")
 
-      public const val CONST_UNDERSCORES_HEX_PROP: Long = 4_293_713_502L
+      public var VAR_BOOL_PROP: Boolean = throw NotImplementedError("Stub!")
 
-      public const val CONST_UNDERSCORES_PROP: Int = 1_000_000
+      public var VAR_BINARY_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val DOUBLE_PROP: Double = throw NotImplementedError("Stub!")
+      public var VAR_INT_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val FLOAT_PROP: Float = throw NotImplementedError("Stub!")
+      public var VAR_UNDERSCORES_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val HEX_PROP: Int = throw NotImplementedError("Stub!")
+      public var VAR_HEX_PROP: Int = throw NotImplementedError("Stub!")
 
-      public val INT_PROP: Int = throw NotImplementedError("Stub!")
+      public var VAR_UNDERSCORES_HEX_PROP: Long = throw NotImplementedError("Stub!")
 
-      public val LONG_PROP: Long = throw NotImplementedError("Stub!")
+      public var VAR_LONG_PROP: Long = throw NotImplementedError("Stub!")
 
-      public val STRING_PROP: String = throw NotImplementedError("Stub!")
+      public var VAR_FLOAT_PROP: Float = throw NotImplementedError("Stub!")
 
-      public val UNDERSCORES_HEX_PROP: Long = throw NotImplementedError("Stub!")
+      public var VAR_DOUBLE_PROP: Double = throw NotImplementedError("Stub!")
 
-      public val UNDERSCORES_PROP: Int = throw NotImplementedError("Stub!")
+      public var VAR_STRING_PROP: String = throw NotImplementedError("Stub!")
 
-      public var VAR_BINARY_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_BOOL_PROP: Boolean = false
 
-      public var VAR_BOOL_PROP: Boolean = throw NotImplementedError("Stub!")
+      public const val CONST_BINARY_PROP: Int = 11
 
-      public var VAR_DOUBLE_PROP: Double = throw NotImplementedError("Stub!")
+      public const val CONST_INT_PROP: Int = 1
 
-      public var VAR_FLOAT_PROP: Float = throw NotImplementedError("Stub!")
+      public const val CONST_UNDERSCORES_PROP: Int = 1_000_000
 
-      public var VAR_HEX_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_HEX_PROP: Int = 15
 
-      public var VAR_INT_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_UNDERSCORES_HEX_PROP: Long = 4_293_713_502L
 
-      public var VAR_LONG_PROP: Long = throw NotImplementedError("Stub!")
+      public const val CONST_LONG_PROP: Long = 1L
 
-      public var VAR_STRING_PROP: String = throw NotImplementedError("Stub!")
+      public const val CONST_FLOAT_PROP: Float = 1.0F
 
-      public var VAR_UNDERSCORES_HEX_PROP: Long = throw NotImplementedError("Stub!")
+      public const val CONST_DOUBLE_PROP: Double = 1.0
 
-      public var VAR_UNDERSCORES_PROP: Int = throw NotImplementedError("Stub!")
+      public const val CONST_STRING_PROP: String = "prop"
 
       @field:JvmSynthetic
       public val syntheticFieldProperty: String? = null
@@ -286,11 +284,11 @@ class FacadeFileTest : MultiClassInspectorTest() {
       @set:JvmSynthetic
       public var syntheticPropertySet: String? = null
 
+      public typealias FacadeTypeAliasName = String
+
       public typealias FacadeGenericTypeAlias = List<String>
 
       public typealias FacadeNestedTypeAlias = List<GenericTypeAlias>
-
-      public typealias FacadeTypeAliasName = String
       """.trimIndent(),
     )
   }
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmNameWithKtFacadeFile.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmNameWithKtFacadeFile.kt
similarity index 100%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmNameWithKtFacadeFile.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/JvmNameWithKtFacadeFile.kt
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KmAnnotationsTest.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KmAnnotationsTest.kt
similarity index 85%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KmAnnotationsTest.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KmAnnotationsTest.kt
index a2ad9d18..77d6f66c 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KmAnnotationsTest.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KmAnnotationsTest.kt
@@ -16,29 +16,26 @@
 package com.squareup.kotlinpoet.metadata.specs
 
 import com.google.common.truth.Truth.assertThat
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
+import kotlin.metadata.KmAnnotation
+import kotlin.metadata.KmAnnotationArgument.AnnotationValue
+import kotlin.metadata.KmAnnotationArgument.ArrayValue
+import kotlin.metadata.KmAnnotationArgument.BooleanValue
+import kotlin.metadata.KmAnnotationArgument.ByteValue
+import kotlin.metadata.KmAnnotationArgument.CharValue
+import kotlin.metadata.KmAnnotationArgument.DoubleValue
+import kotlin.metadata.KmAnnotationArgument.EnumValue
+import kotlin.metadata.KmAnnotationArgument.FloatValue
+import kotlin.metadata.KmAnnotationArgument.IntValue
+import kotlin.metadata.KmAnnotationArgument.KClassValue
+import kotlin.metadata.KmAnnotationArgument.LongValue
+import kotlin.metadata.KmAnnotationArgument.ShortValue
+import kotlin.metadata.KmAnnotationArgument.StringValue
+import kotlin.metadata.KmAnnotationArgument.UByteValue
+import kotlin.metadata.KmAnnotationArgument.UIntValue
+import kotlin.metadata.KmAnnotationArgument.ULongValue
+import kotlin.metadata.KmAnnotationArgument.UShortValue
 import kotlin.test.Test
-import kotlinx.metadata.KmAnnotation
-import kotlinx.metadata.KmAnnotationArgument.AnnotationValue
-import kotlinx.metadata.KmAnnotationArgument.ArrayValue
-import kotlinx.metadata.KmAnnotationArgument.BooleanValue
-import kotlinx.metadata.KmAnnotationArgument.ByteValue
-import kotlinx.metadata.KmAnnotationArgument.CharValue
-import kotlinx.metadata.KmAnnotationArgument.DoubleValue
-import kotlinx.metadata.KmAnnotationArgument.EnumValue
-import kotlinx.metadata.KmAnnotationArgument.FloatValue
-import kotlinx.metadata.KmAnnotationArgument.IntValue
-import kotlinx.metadata.KmAnnotationArgument.KClassValue
-import kotlinx.metadata.KmAnnotationArgument.LongValue
-import kotlinx.metadata.KmAnnotationArgument.ShortValue
-import kotlinx.metadata.KmAnnotationArgument.StringValue
-import kotlinx.metadata.KmAnnotationArgument.UByteValue
-import kotlinx.metadata.KmAnnotationArgument.UIntValue
-import kotlinx.metadata.KmAnnotationArgument.ULongValue
-import kotlinx.metadata.KmAnnotationArgument.UShortValue
 
-@OptIn(ExperimentalUnsignedTypes::class)
-@KotlinPoetMetadataPreview
 class KmAnnotationsTest {
 
   @Test fun noMembers() {
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecsTest.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecsTest.kt
similarity index 99%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecsTest.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecsTest.kt
index 2dd54bbf..a47e080d 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecsTest.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/KotlinPoetMetadataSpecsTest.kt
@@ -13,7 +13,6 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-@file:OptIn(KotlinPoetMetadataPreview::class)
 @file:Suppress(
   "NOTHING_TO_INLINE",
   "RedundantSuspendModifier",
@@ -32,7 +31,6 @@ import com.squareup.kotlinpoet.LIST
 import com.squareup.kotlinpoet.ParameterizedTypeName.Companion.parameterizedBy
 import com.squareup.kotlinpoet.STRING
 import com.squareup.kotlinpoet.TypeSpec
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.specs.MultiClassInspectorTest.ClassInspectorType.ELEMENTS
 import com.squareup.kotlinpoet.metadata.specs.MultiClassInspectorTest.ClassInspectorType.REFLECTIVE
 import com.squareup.kotlinpoet.tag
@@ -40,14 +38,14 @@ import com.squareup.kotlinpoet.tags.TypeAliasTag
 import kotlin.annotation.AnnotationRetention.RUNTIME
 import kotlin.annotation.AnnotationTarget.TYPE
 import kotlin.annotation.AnnotationTarget.TYPE_PARAMETER
+import kotlin.metadata.KmClass
+import kotlin.metadata.KmConstructor
+import kotlin.metadata.KmFunction
+import kotlin.metadata.KmProperty
+import kotlin.metadata.KmTypeParameter
+import kotlin.metadata.KmValueParameter
 import kotlin.properties.Delegates
 import kotlin.test.fail
-import kotlinx.metadata.KmClass
-import kotlinx.metadata.KmConstructor
-import kotlinx.metadata.KmFunction
-import kotlinx.metadata.KmProperty
-import kotlinx.metadata.KmTypeParameter
-import kotlinx.metadata.KmValueParameter
 import org.junit.Ignore
 import org.junit.Test
 
@@ -103,13 +101,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public class Properties() {
-        public var aList: kotlin.collections.List<kotlin.Int> = throw NotImplementedError("Stub!")
+        public val foo: kotlin.String = throw NotImplementedError("Stub!")
 
         public val bar: kotlin.String? = null
 
         public var baz: kotlin.Int = throw NotImplementedError("Stub!")
 
-        public val foo: kotlin.String = throw NotImplementedError("Stub!")
+        public var aList: kotlin.collections.List<kotlin.Int> = throw NotImplementedError("Stub!")
       }
       """.trimIndent(),
     )
@@ -127,13 +125,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public class Properties() {
-        public var aList: kotlin.collections.List<kotlin.Int> = throw NotImplementedError("Stub!")
+        public val foo: kotlin.String = throw NotImplementedError("Stub!")
 
         public val bar: kotlin.String? = null
 
         public var baz: kotlin.Int = throw NotImplementedError("Stub!")
 
-        public val foo: kotlin.String = throw NotImplementedError("Stub!")
+        public var aList: kotlin.collections.List<kotlin.Int> = throw NotImplementedError("Stub!")
       }
       """.trimIndent(),
     )
@@ -263,14 +261,14 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
       public class SuspendTypes() {
         public val testProp: suspend (kotlin.Int, kotlin.Long) -> kotlin.String = throw NotImplementedError("Stub!")
 
-        public suspend fun testComplexSuspendFun(body: suspend (kotlin.Int, suspend (kotlin.Long) -> kotlin.String) -> kotlin.String) {
-        }
-
         public fun testFun(body: suspend (kotlin.Int, kotlin.Long) -> kotlin.String) {
         }
 
         public suspend fun testSuspendFun(param1: kotlin.String) {
         }
+
+        public suspend fun testComplexSuspendFun(body: suspend (kotlin.Int, suspend (kotlin.Long) -> kotlin.String) -> kotlin.String) {
+        }
       }
       """.trimIndent(),
     )
@@ -296,13 +294,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public class Parameters() {
-        public inline fun hasDefault(param1: kotlin.String = throw NotImplementedError("Stub!")) {
-        }
-
         public inline fun `inline`(crossinline param1: () -> kotlin.String) {
         }
 
         public inline fun `noinline`(noinline param1: () -> kotlin.String): kotlin.String = throw NotImplementedError("Stub!")
+
+        public inline fun hasDefault(param1: kotlin.String = throw NotImplementedError("Stub!")) {
+        }
       }
       """.trimIndent(),
     )
@@ -602,7 +600,6 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         FOO {
           override fun toString(): kotlin.String = throw NotImplementedError("Stub!")
         },
-        @com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.FieldAnnotation
         BAR {
           override fun toString(): kotlin.String = throw NotImplementedError("Stub!")
         },
@@ -643,20 +640,20 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(testInterfaceSpec.trimmedToString()).isEqualTo(
       """
       public interface TestInterface {
-        public fun complex(input: kotlin.String, input2: kotlin.String = throw NotImplementedError("Stub!")): kotlin.String = throw NotImplementedError("Stub!")
+        public fun noDefault()
+
+        public fun noDefaultWithInput(input: kotlin.String)
+
+        public fun noDefaultWithInputDefault(input: kotlin.String = throw NotImplementedError("Stub!"))
 
         public fun hasDefault() {
         }
 
-        public fun hasDefaultMultiParam(input: kotlin.String, input2: kotlin.String): kotlin.String = throw NotImplementedError("Stub!")
-
         public fun hasDefaultSingleParam(input: kotlin.String): kotlin.String = throw NotImplementedError("Stub!")
 
-        public fun noDefault()
-
-        public fun noDefaultWithInput(input: kotlin.String)
+        public fun hasDefaultMultiParam(input: kotlin.String, input2: kotlin.String): kotlin.String = throw NotImplementedError("Stub!")
 
-        public fun noDefaultWithInputDefault(input: kotlin.String = throw NotImplementedError("Stub!"))
+        public fun complex(input: kotlin.String, input2: kotlin.String = throw NotImplementedError("Stub!")): kotlin.String = throw NotImplementedError("Stub!")
       }
       """.trimIndent(),
     )
@@ -667,10 +664,10 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(subInterfaceSpec.trimmedToString()).isEqualTo(
       """
       public interface SubInterface : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.TestInterface {
-        override fun hasDefault() {
+        public fun subInterfaceFunction() {
         }
 
-        public fun subInterfaceFunction() {
+        override fun hasDefault() {
         }
       }
       """.trimIndent(),
@@ -805,13 +802,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public class GenericClass<T>() {
-        public fun <T> functionAlsoWithT(`param`: T) {
+        public fun functionWithT(`param`: T) {
         }
 
-        public fun <R> functionWithADifferentType(`param`: R) {
+        public fun <T> functionAlsoWithT(`param`: T) {
         }
 
-        public fun functionWithT(`param`: T) {
+        public fun <R> functionWithADifferentType(`param`: R) {
         }
 
         /**
@@ -881,13 +878,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         @get:com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.GetterAnnotation
         public var getter: kotlin.String? = null
 
+        @set:com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.SetterAnnotation
+        public var setter: kotlin.String? = null
+
         @com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.HolderAnnotation
         @kotlin.jvm.JvmField
         public var holder: kotlin.String? = null
 
-        @set:com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.SetterAnnotation
-        public var setter: kotlin.String? = null
-
         @com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.ConstructorAnnotation
         public constructor(`value`: kotlin.String)
 
@@ -955,76 +952,76 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
       public class Constants(
         public val `param`: kotlin.String = throw NotImplementedError("Stub!"),
       ) {
-        public val binaryProp: kotlin.Int = throw NotImplementedError("Stub!")
-
         public val boolProp: kotlin.Boolean = throw NotImplementedError("Stub!")
 
-        public val doubleProp: kotlin.Double = throw NotImplementedError("Stub!")
-
-        public val floatProp: kotlin.Float = throw NotImplementedError("Stub!")
-
-        public val hexProp: kotlin.Int = throw NotImplementedError("Stub!")
+        public val binaryProp: kotlin.Int = throw NotImplementedError("Stub!")
 
         public val intProp: kotlin.Int = throw NotImplementedError("Stub!")
 
-        public val longProp: kotlin.Long = throw NotImplementedError("Stub!")
-
-        public val stringProp: kotlin.String = throw NotImplementedError("Stub!")
-
-        public val underscoresHexProp: kotlin.Long = throw NotImplementedError("Stub!")
-
         public val underscoresProp: kotlin.Int = throw NotImplementedError("Stub!")
 
-        public companion object {
-          public const val CONST_BINARY_PROP: kotlin.Int = 11
-
-          public const val CONST_BOOL_PROP: kotlin.Boolean = false
-
-          public const val CONST_DOUBLE_PROP: kotlin.Double = 1.0
-
-          public const val CONST_FLOAT_PROP: kotlin.Float = 1.0F
-
-          public const val CONST_HEX_PROP: kotlin.Int = 15
+        public val hexProp: kotlin.Int = throw NotImplementedError("Stub!")
 
-          public const val CONST_INT_PROP: kotlin.Int = 1
+        public val underscoresHexProp: kotlin.Long = throw NotImplementedError("Stub!")
 
-          public const val CONST_LONG_PROP: kotlin.Long = 1L
+        public val longProp: kotlin.Long = throw NotImplementedError("Stub!")
 
-          public const val CONST_STRING_PROP: kotlin.String = "prop"
+        public val floatProp: kotlin.Float = throw NotImplementedError("Stub!")
 
-          public const val CONST_UNDERSCORES_HEX_PROP: kotlin.Long = 4_293_713_502L
+        public val doubleProp: kotlin.Double = throw NotImplementedError("Stub!")
 
-          public const val CONST_UNDERSCORES_PROP: kotlin.Int = 1_000_000
+        public val stringProp: kotlin.String = throw NotImplementedError("Stub!")
 
+        public companion object {
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_BINARY_PROP: kotlin.Int = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_BOOL_PROP: kotlin.Boolean = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_BOOL_PROP: kotlin.Boolean = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_BINARY_PROP: kotlin.Int = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_DOUBLE_PROP: kotlin.Double = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_INT_PROP: kotlin.Int = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_FLOAT_PROP: kotlin.Float = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_UNDERSCORES_PROP: kotlin.Int = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
           public val STATIC_CONST_HEX_PROP: kotlin.Int = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_INT_PROP: kotlin.Int = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_UNDERSCORES_HEX_PROP: kotlin.Long = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
           public val STATIC_CONST_LONG_PROP: kotlin.Long = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_STRING_PROP: kotlin.String = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_FLOAT_PROP: kotlin.Float = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_UNDERSCORES_HEX_PROP: kotlin.Long = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_DOUBLE_PROP: kotlin.Double = throw NotImplementedError("Stub!")
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_UNDERSCORES_PROP: kotlin.Int = throw NotImplementedError("Stub!")
+          public val STATIC_CONST_STRING_PROP: kotlin.String = throw NotImplementedError("Stub!")
+
+          public const val CONST_BOOL_PROP: kotlin.Boolean = false
+
+          public const val CONST_BINARY_PROP: kotlin.Int = 11
+
+          public const val CONST_INT_PROP: kotlin.Int = 1
+
+          public const val CONST_UNDERSCORES_PROP: kotlin.Int = 1_000_000
+
+          public const val CONST_HEX_PROP: kotlin.Int = 15
+
+          public const val CONST_UNDERSCORES_HEX_PROP: kotlin.Long = 4_293_713_502L
+
+          public const val CONST_LONG_PROP: kotlin.Long = 1L
+
+          public const val CONST_FLOAT_PROP: kotlin.Float = 1.0F
+
+          public const val CONST_DOUBLE_PROP: kotlin.Double = 1.0
+
+          public const val CONST_STRING_PROP: kotlin.String = "prop"
         }
       }
       """.trimIndent(),
@@ -1048,76 +1045,76 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
       public class Constants(
         public val `param`: kotlin.String = throw NotImplementedError("Stub!"),
       ) {
-        public val binaryProp: kotlin.Int = throw NotImplementedError("Stub!")
-
         public val boolProp: kotlin.Boolean = throw NotImplementedError("Stub!")
 
-        public val doubleProp: kotlin.Double = throw NotImplementedError("Stub!")
-
-        public val floatProp: kotlin.Float = throw NotImplementedError("Stub!")
-
-        public val hexProp: kotlin.Int = throw NotImplementedError("Stub!")
+        public val binaryProp: kotlin.Int = throw NotImplementedError("Stub!")
 
         public val intProp: kotlin.Int = throw NotImplementedError("Stub!")
 
-        public val longProp: kotlin.Long = throw NotImplementedError("Stub!")
-
-        public val stringProp: kotlin.String = throw NotImplementedError("Stub!")
-
-        public val underscoresHexProp: kotlin.Long = throw NotImplementedError("Stub!")
-
         public val underscoresProp: kotlin.Int = throw NotImplementedError("Stub!")
 
-        public companion object {
-          public const val CONST_BINARY_PROP: kotlin.Int = 11
-
-          public const val CONST_BOOL_PROP: kotlin.Boolean = false
-
-          public const val CONST_DOUBLE_PROP: kotlin.Double = 1.0
-
-          public const val CONST_FLOAT_PROP: kotlin.Float = 1.0F
-
-          public const val CONST_HEX_PROP: kotlin.Int = 15
+        public val hexProp: kotlin.Int = throw NotImplementedError("Stub!")
 
-          public const val CONST_INT_PROP: kotlin.Int = 1
+        public val underscoresHexProp: kotlin.Long = throw NotImplementedError("Stub!")
 
-          public const val CONST_LONG_PROP: kotlin.Long = 1L
+        public val longProp: kotlin.Long = throw NotImplementedError("Stub!")
 
-          public const val CONST_STRING_PROP: kotlin.String = "prop"
+        public val floatProp: kotlin.Float = throw NotImplementedError("Stub!")
 
-          public const val CONST_UNDERSCORES_HEX_PROP: kotlin.Long = 4_293_713_502L
+        public val doubleProp: kotlin.Double = throw NotImplementedError("Stub!")
 
-          public const val CONST_UNDERSCORES_PROP: kotlin.Int = 1_000_000
+        public val stringProp: kotlin.String = throw NotImplementedError("Stub!")
 
+        public companion object {
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_BINARY_PROP: kotlin.Int = 11
+          public val STATIC_CONST_BOOL_PROP: kotlin.Boolean = false
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_BOOL_PROP: kotlin.Boolean = false
+          public val STATIC_CONST_BINARY_PROP: kotlin.Int = 11
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_DOUBLE_PROP: kotlin.Double = 1.0
+          public val STATIC_CONST_INT_PROP: kotlin.Int = 1
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_FLOAT_PROP: kotlin.Float = 1.0F
+          public val STATIC_CONST_UNDERSCORES_PROP: kotlin.Int = 1_000_000
 
           @kotlin.jvm.JvmStatic
           public val STATIC_CONST_HEX_PROP: kotlin.Int = 15
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_INT_PROP: kotlin.Int = 1
+          public val STATIC_CONST_UNDERSCORES_HEX_PROP: kotlin.Long = 4_293_713_502L
 
           @kotlin.jvm.JvmStatic
           public val STATIC_CONST_LONG_PROP: kotlin.Long = 1L
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_STRING_PROP: kotlin.String = "prop"
+          public val STATIC_CONST_FLOAT_PROP: kotlin.Float = 1.0F
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_UNDERSCORES_HEX_PROP: kotlin.Long = 4_293_713_502L
+          public val STATIC_CONST_DOUBLE_PROP: kotlin.Double = 1.0
 
           @kotlin.jvm.JvmStatic
-          public val STATIC_CONST_UNDERSCORES_PROP: kotlin.Int = 1_000_000
+          public val STATIC_CONST_STRING_PROP: kotlin.String = "prop"
+
+          public const val CONST_BOOL_PROP: kotlin.Boolean = false
+
+          public const val CONST_BINARY_PROP: kotlin.Int = 11
+
+          public const val CONST_INT_PROP: kotlin.Int = 1
+
+          public const val CONST_UNDERSCORES_PROP: kotlin.Int = 1_000_000
+
+          public const val CONST_HEX_PROP: kotlin.Int = 15
+
+          public const val CONST_UNDERSCORES_HEX_PROP: kotlin.Long = 4_293_713_502L
+
+          public const val CONST_LONG_PROP: kotlin.Long = 1L
+
+          public const val CONST_FLOAT_PROP: kotlin.Float = 1.0F
+
+          public const val CONST_DOUBLE_PROP: kotlin.Double = 1.0
+
+          public const val CONST_STRING_PROP: kotlin.String = "prop"
         }
       }
       """.trimIndent(),
@@ -1180,18 +1177,18 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public class JvmAnnotations() {
-        @get:kotlin.jvm.Synchronized
-        public val synchronizedGetProp: kotlin.String? = null
-
-        @set:kotlin.jvm.Synchronized
-        public var synchronizedSetProp: kotlin.String? = null
-
         @kotlin.jvm.Transient
         public val transientProp: kotlin.String? = null
 
         @kotlin.jvm.Volatile
         public var volatileProp: kotlin.String? = null
 
+        @get:kotlin.jvm.Synchronized
+        public val synchronizedGetProp: kotlin.String? = null
+
+        @set:kotlin.jvm.Synchronized
+        public var synchronizedSetProp: kotlin.String? = null
+
         @kotlin.jvm.Synchronized
         public fun synchronizedFun() {
         }
@@ -1269,13 +1266,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         @get:kotlin.jvm.JvmName(name = "jvmPropertyGet")
         public val propertyGet: kotlin.String? = null
 
+        @set:kotlin.jvm.JvmName(name = "jvmPropertySet")
+        public var propertySet: kotlin.String? = null
+
         @get:kotlin.jvm.JvmName(name = "jvmPropertyGetAndSet")
         @set:kotlin.jvm.JvmName(name = "jvmPropertyGetAndSet")
         public var propertyGetAndSet: kotlin.String? = null
 
-        @set:kotlin.jvm.JvmName(name = "jvmPropertySet")
-        public var propertySet: kotlin.String? = null
-
         @kotlin.jvm.JvmName(name = "jvmFunction")
         public fun function() {
         }
@@ -1316,13 +1313,13 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         @get:kotlin.jvm.JvmName(name = "jvmPropertyGet")
         public val propertyGet: kotlin.String? = null
 
+        @set:kotlin.jvm.JvmName(name = "jvmPropertySet")
+        public var propertySet: kotlin.String? = null
+
         @get:kotlin.jvm.JvmName(name = "jvmPropertyGetAndSet")
         @set:kotlin.jvm.JvmName(name = "jvmPropertyGetAndSet")
         public var propertyGetAndSet: kotlin.String? = null
 
-        @set:kotlin.jvm.JvmName(name = "jvmPropertySet")
-        public var propertySet: kotlin.String? = null
-
         @kotlin.jvm.JvmName(name = "jvmFunction")
         public fun function() {
         }
@@ -1442,10 +1439,10 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
           @kotlin.jvm.JvmField
           public val companionProp: kotlin.String = ""
 
-          public const val constCompanionProp: kotlin.String = ""
-
           @kotlin.jvm.JvmStatic
           public val staticCompanionProp: kotlin.String = ""
+
+          public const val constCompanionProp: kotlin.String = ""
         }
       }
       """.trimIndent(),
@@ -1474,10 +1471,10 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
           @kotlin.jvm.JvmField
           public val companionProp: kotlin.String = throw NotImplementedError("Stub!")
 
-          public const val constCompanionProp: kotlin.String = ""
-
           @kotlin.jvm.JvmStatic
           public val staticCompanionProp: kotlin.String = throw NotImplementedError("Stub!")
+
+          public const val constCompanionProp: kotlin.String = ""
         }
       }
       """.trimIndent(),
@@ -1514,20 +1511,20 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         public val `param`: kotlin.String,
       ) {
         @field:kotlin.jvm.JvmSynthetic
-        public val fieldProperty: kotlin.String? = null
+        public val `property`: kotlin.String? = null
 
         @field:kotlin.jvm.JvmSynthetic
-        public val `property`: kotlin.String? = null
+        public val fieldProperty: kotlin.String? = null
 
         @get:kotlin.jvm.JvmSynthetic
         public val propertyGet: kotlin.String? = null
 
-        @get:kotlin.jvm.JvmSynthetic
         @set:kotlin.jvm.JvmSynthetic
-        public var propertyGetAndSet: kotlin.String? = null
+        public var propertySet: kotlin.String? = null
 
+        @get:kotlin.jvm.JvmSynthetic
         @set:kotlin.jvm.JvmSynthetic
-        public var propertySet: kotlin.String? = null
+        public var propertyGetAndSet: kotlin.String? = null
 
         /**
          * Note: Since this is a synthetic function, some JVM information (annotations, modifiers) may be missing.
@@ -1579,20 +1576,20 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         public val `param`: kotlin.String,
       ) {
         @field:kotlin.jvm.JvmSynthetic
-        public val fieldProperty: kotlin.String? = null
+        public val `property`: kotlin.String? = null
 
         @field:kotlin.jvm.JvmSynthetic
-        public val `property`: kotlin.String? = null
+        public val fieldProperty: kotlin.String? = null
 
         @get:kotlin.jvm.JvmSynthetic
         public val propertyGet: kotlin.String? = null
 
-        @get:kotlin.jvm.JvmSynthetic
         @set:kotlin.jvm.JvmSynthetic
-        public var propertyGetAndSet: kotlin.String? = null
+        public var propertySet: kotlin.String? = null
 
+        @get:kotlin.jvm.JvmSynthetic
         @set:kotlin.jvm.JvmSynthetic
-        public var propertySet: kotlin.String? = null
+        public var propertyGetAndSet: kotlin.String? = null
 
         /**
          * Note: Since this is a synthetic function, some JVM information (annotations, modifiers) may be missing.
@@ -1677,16 +1674,16 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public class Throwing @kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class]) constructor() {
-        @get:kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
-        @set:kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
-        public var getterAndSetterThrows: kotlin.String? = null
-
         @get:kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
         public val getterThrows: kotlin.String? = null
 
         @set:kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
         public var setterThrows: kotlin.String? = null
 
+        @get:kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
+        @set:kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
+        public var getterAndSetterThrows: kotlin.String? = null
+
         @kotlin.jvm.Throws(exceptionClasses = [java.lang.IllegalStateException::class])
         public fun testFunction() {
         }
@@ -1974,9 +1971,9 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
         public fun <D : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Asset<D>, C : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Asset<A>> function() {
         }
 
-        public class AssetIn<in C : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Asset.AssetIn<C>>()
-
         public class AssetOut<out B : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Asset.AssetOut<B>>()
+
+        public class AssetIn<in C : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Asset.AssetIn<C>>()
       }
       """.trimIndent(),
     )
@@ -1999,10 +1996,10 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public abstract class AbstractClass() {
-        public val baz: kotlin.String? = null
-
         public abstract val foo: kotlin.String
 
+        public val baz: kotlin.String? = null
+
         public abstract fun bar()
 
         public abstract fun barWithReturn(): kotlin.String
@@ -2058,16 +2055,16 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(abstractModalities.trimmedToString()).isEqualTo(
       """
       public abstract class AbstractModalities() : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.ModalitiesInterface {
-        public val implicitFinalProp: kotlin.String? = null
-
         override val interfaceProp: kotlin.String? = null
 
+        public val implicitFinalProp: kotlin.String? = null
+
         public open val openProp: kotlin.String? = null
 
-        public fun implicitFinalFun() {
+        override fun interfaceFun() {
         }
 
-        override fun interfaceFun() {
+        public fun implicitFinalFun() {
         }
 
         public open fun openFun() {
@@ -2166,9 +2163,9 @@ class KotlinPoetMetadataSpecsTest : MultiClassInspectorTest() {
     assertThat(typeSpec.trimmedToString()).isEqualTo(
       """
       public open class Node<T : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Node<T, R>, R : com.squareup.kotlinpoet.metadata.specs.KotlinPoetMetadataSpecsTest.Node<R, T>>() {
-        public var r: R? = null
-
         public var t: T? = null
+
+        public var r: R? = null
       }
       """.trimIndent(),
     )
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/MultiClassInspectorTest.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/MultiClassInspectorTest.kt
similarity index 89%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/MultiClassInspectorTest.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/MultiClassInspectorTest.kt
index 6bb9192a..d08a7b6c 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/MultiClassInspectorTest.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/MultiClassInspectorTest.kt
@@ -19,15 +19,14 @@ import com.google.testing.compile.CompilationRule
 import com.squareup.kotlinpoet.FileSpec
 import com.squareup.kotlinpoet.TypeSpec
 import com.squareup.kotlinpoet.asClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ElementsClassInspector
 import com.squareup.kotlinpoet.metadata.classinspectors.ReflectiveClassInspector
 import com.squareup.kotlinpoet.metadata.specs.MultiClassInspectorTest.ClassInspectorType
 import com.squareup.kotlinpoet.metadata.toKotlinClassMetadata
 import java.lang.annotation.Inherited
 import kotlin.annotation.AnnotationRetention.RUNTIME
+import kotlin.metadata.jvm.KotlinClassMetadata.FileFacade
 import kotlin.reflect.KClass
-import kotlinx.metadata.jvm.KotlinClassMetadata.FileFacade
 import org.junit.Assume
 import org.junit.Rule
 import org.junit.rules.TestRule
@@ -38,7 +37,6 @@ import org.junit.runners.model.Statement
 
 /** Base test class that runs all tests with multiple [ClassInspectorTypes][ClassInspectorType]. */
 @RunWith(Parameterized::class)
-@KotlinPoetMetadataPreview
 abstract class MultiClassInspectorTest {
   companion object {
     @JvmStatic
@@ -59,12 +57,12 @@ abstract class MultiClassInspectorTest {
     },
     REFLECTIVE {
       override fun create(testInstance: MultiClassInspectorTest): ClassInspector {
-        return ReflectiveClassInspector.create()
+        return ReflectiveClassInspector.create(lenient = false)
       }
     },
     ELEMENTS {
       override fun create(testInstance: MultiClassInspectorTest): ClassInspector {
-        return ElementsClassInspector.create(testInstance.compilation.elements, testInstance.compilation.types)
+        return ElementsClassInspector.create(lenient = false, testInstance.compilation.elements, testInstance.compilation.types)
       }
     },
     ;
@@ -107,12 +105,12 @@ abstract class MultiClassInspectorTest {
   }
 
   protected fun KClass<*>.toTypeSpecWithTestHandler(): TypeSpec {
-    return toTypeSpec(classInspectorType.create(this@MultiClassInspectorTest))
+    return toTypeSpec(lenient = false, classInspectorType.create(this@MultiClassInspectorTest))
   }
 
   protected fun KClass<*>.toFileSpecWithTestHandler(): FileSpec {
     val classInspector = classInspectorType.create(this@MultiClassInspectorTest)
-    return java.annotations.filterIsInstance<Metadata>().first().toKotlinClassMetadata<FileFacade>()
+    return java.annotations.filterIsInstance<Metadata>().first().toKotlinClassMetadata<FileFacade>(lenient = false)
       .kmPackage
       .toFileSpec(classInspector, asClassName())
   }
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/NoJvmNameFacadeFile.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/NoJvmNameFacadeFile.kt
similarity index 100%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/NoJvmNameFacadeFile.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/NoJvmNameFacadeFile.kt
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/ReflectiveClassInspectorTest.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/ReflectiveClassInspectorTest.kt
similarity index 92%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/ReflectiveClassInspectorTest.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/ReflectiveClassInspectorTest.kt
index a4ecc3de..7974b7ca 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/ReflectiveClassInspectorTest.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/ReflectiveClassInspectorTest.kt
@@ -17,7 +17,6 @@ package com.squareup.kotlinpoet.metadata.specs
 
 import com.squareup.kotlinpoet.ClassName
 import com.squareup.kotlinpoet.asClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ReflectiveClassInspector
 import com.tschuchort.compiletesting.KotlinCompilation
 import com.tschuchort.compiletesting.SourceFile
@@ -30,7 +29,6 @@ import org.junit.Test
  * @see <a href="https://github.com/square/kotlinpoet/issues/1036">issue</a>
  * @author oberstrike
  */
-@KotlinPoetMetadataPreview
 class ReflectiveClassInspectorTest {
 
   data class Person(val name: String)
@@ -41,7 +39,7 @@ class ReflectiveClassInspectorTest {
    */
   @Test
   fun standardClassLoaderTest() {
-    val classInspector = ReflectiveClassInspector.create()
+    val classInspector = ReflectiveClassInspector.create(lenient = false)
     val className = Person::class.asClassName()
     val declarationContainer = classInspector.declarationContainerFor(className)
     assertNotNull(declarationContainer)
@@ -74,7 +72,7 @@ class ReflectiveClassInspectorTest {
 
     assertEquals(KotlinCompilation.ExitCode.OK, result.exitCode)
     val classLoader = result.classLoader
-    val classInspector = ReflectiveClassInspector.create(classLoader)
+    val classInspector = ReflectiveClassInspector.create(lenient = false, classLoader)
 
     val declarationContainer = classInspector.declarationContainerFor(testClassName)
 
diff --git a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/classinspectors/ClassInspectorUtilTest.kt b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/classinspectors/ClassInspectorUtilTest.kt
similarity index 97%
rename from interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/classinspectors/ClassInspectorUtilTest.kt
rename to interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/classinspectors/ClassInspectorUtilTest.kt
index 4e1c268b..3aa74268 100644
--- a/interop/kotlinx-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/classinspectors/ClassInspectorUtilTest.kt
+++ b/interop/kotlin-metadata/src/test/kotlin/com/squareup/kotlinpoet/metadata/specs/classinspectors/ClassInspectorUtilTest.kt
@@ -19,11 +19,9 @@ import com.google.common.truth.Truth.assertThat
 import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.ClassName
 import com.squareup.kotlinpoet.asClassName
-import com.squareup.kotlinpoet.metadata.KotlinPoetMetadataPreview
 import com.squareup.kotlinpoet.metadata.classinspectors.ClassInspectorUtil
 import kotlin.test.Test
 
-@KotlinPoetMetadataPreview
 class ClassInspectorUtilTest {
 
   @Test fun createClassName_simple() {
diff --git a/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/Annotations.kt b/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/Annotations.kt
index b5dd38c1..00b239e3 100644
--- a/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/Annotations.kt
+++ b/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/Annotations.kt
@@ -26,7 +26,7 @@ import com.squareup.kotlinpoet.AnnotationSpec
 import com.squareup.kotlinpoet.AnnotationSpec.UseSiteTarget
 import com.squareup.kotlinpoet.ClassName
 import com.squareup.kotlinpoet.CodeBlock
-import com.squareup.kotlinpoet.ParameterizedTypeName
+import com.squareup.kotlinpoet.ParameterizedTypeName.Companion.parameterizedBy
 
 /**
  * Returns an [AnnotationSpec] representation of this [KSAnnotation] instance.
@@ -34,24 +34,48 @@ import com.squareup.kotlinpoet.ParameterizedTypeName
  */
 @JvmOverloads
 public fun KSAnnotation.toAnnotationSpec(omitDefaultValues: Boolean = false): AnnotationSpec {
-  val builder = when (val type = annotationType.resolve().unwrapTypeAlias().toTypeName()) {
-    is ClassName -> AnnotationSpec.builder(type)
-    is ParameterizedTypeName -> AnnotationSpec.builder(type)
-    else -> error("This is never possible.")
-  }
+  val builder = annotationType.resolve().unwrapTypeAlias().toClassName()
+    .let { className ->
+      val typeArgs = annotationType.element?.typeArguments.orEmpty()
+        .map { it.toTypeName() }
+      if (typeArgs.isEmpty()) {
+        AnnotationSpec.builder(className)
+      } else {
+        AnnotationSpec.builder(className.parameterizedBy(typeArgs))
+      }
+    }
+
+  val params = (annotationType.resolve().declaration as KSClassDeclaration).primaryConstructor?.parameters.orEmpty()
+    .associateBy { it.name }
   useSiteTarget?.let { builder.useSiteTarget(it.kpAnalog) }
-  // TODO support type params once they're exposed https://github.com/google/ksp/issues/753
+
+  var varargValues: List<*>? = null
   for (argument in arguments) {
     val value = argument.value ?: continue
     val name = argument.name!!.getShortName()
+    val type = params[argument.name]
     if (omitDefaultValues) {
       val defaultValue = this.defaultArguments.firstOrNull { it.name?.asString() == name }?.value
-      if (isDefaultValue(value, defaultValue)) { continue }
+      if (isDefaultValue(value, defaultValue)) {
+        continue
+      }
+    }
+    if (type?.isVararg == true) {
+      // Wait to add varargs to end.
+      varargValues = value as List<*>
+    } else {
+      val member = CodeBlock.builder()
+      member.add("%N = ", name)
+      addValueToBlock(value, member, omitDefaultValues)
+      builder.addMember(member.build())
+    }
+  }
+  if (varargValues != null) {
+    for (item in varargValues) {
+      val member = CodeBlock.builder()
+      addValueToBlock(item!!, member, omitDefaultValues)
+      builder.addMember(member.build())
     }
-    val member = CodeBlock.builder()
-    member.add("%N = ", name)
-    addValueToBlock(value, member, omitDefaultValues)
-    builder.addMember(member.build())
   }
   return builder.build()
 }
@@ -71,17 +95,18 @@ private fun isDefaultValue(value: Any?, defaultValue: Any?): Boolean {
   return value == defaultValue
 }
 
-private val AnnotationUseSiteTarget.kpAnalog: UseSiteTarget get() = when (this) {
-  AnnotationUseSiteTarget.FILE -> UseSiteTarget.FILE
-  AnnotationUseSiteTarget.PROPERTY -> UseSiteTarget.PROPERTY
-  AnnotationUseSiteTarget.FIELD -> UseSiteTarget.FIELD
-  AnnotationUseSiteTarget.GET -> UseSiteTarget.GET
-  AnnotationUseSiteTarget.SET -> UseSiteTarget.SET
-  AnnotationUseSiteTarget.RECEIVER -> UseSiteTarget.RECEIVER
-  AnnotationUseSiteTarget.PARAM -> UseSiteTarget.PARAM
-  AnnotationUseSiteTarget.SETPARAM -> UseSiteTarget.SETPARAM
-  AnnotationUseSiteTarget.DELEGATE -> UseSiteTarget.DELEGATE
-}
+private val AnnotationUseSiteTarget.kpAnalog: UseSiteTarget
+  get() = when (this) {
+    AnnotationUseSiteTarget.FILE -> UseSiteTarget.FILE
+    AnnotationUseSiteTarget.PROPERTY -> UseSiteTarget.PROPERTY
+    AnnotationUseSiteTarget.FIELD -> UseSiteTarget.FIELD
+    AnnotationUseSiteTarget.GET -> UseSiteTarget.GET
+    AnnotationUseSiteTarget.SET -> UseSiteTarget.SET
+    AnnotationUseSiteTarget.RECEIVER -> UseSiteTarget.RECEIVER
+    AnnotationUseSiteTarget.PARAM -> UseSiteTarget.PARAM
+    AnnotationUseSiteTarget.SETPARAM -> UseSiteTarget.SETPARAM
+    AnnotationUseSiteTarget.DELEGATE -> UseSiteTarget.DELEGATE
+  }
 
 internal fun KSType.unwrapTypeAlias(): KSType {
   return if (this.declaration is KSTypeAlias) {
@@ -113,6 +138,7 @@ private fun addValueToBlock(value: Any, member: CodeBlock.Builder, omitDefaultVa
       }
       member.add("⇤⇤)")
     }
+
     is KSType -> {
       val unwrapped = value.unwrapTypeAlias()
       val isEnum = (unwrapped.declaration as KSClassDeclaration).classKind == ClassKind.ENUM_ENTRY
@@ -124,12 +150,22 @@ private fun addValueToBlock(value: Any, member: CodeBlock.Builder, omitDefaultVa
         member.add("%T::class", unwrapped.toClassName())
       }
     }
+
+    is KSClassDeclaration -> {
+      check(value.classKind == ClassKind.ENUM_ENTRY)
+      member.add(
+        "%T",
+        value.toClassName(),
+      )
+    }
+
     is KSName ->
       member.add(
         "%T.%L",
         ClassName.bestGuess(value.getQualifier()),
         value.getShortName(),
       )
+
     is KSAnnotation -> member.add("%L", value.toAnnotationSpec(omitDefaultValues))
     else -> member.add(memberForValue(value))
   }
diff --git a/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/KsTypes.kt b/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/KsTypes.kt
index 3c57aad0..500cb62a 100644
--- a/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/KsTypes.kt
+++ b/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/KsTypes.kt
@@ -36,8 +36,15 @@ import com.squareup.kotlinpoet.TypeVariableName
 import com.squareup.kotlinpoet.WildcardTypeName
 import com.squareup.kotlinpoet.tags.TypeAliasTag
 
+private fun KSType.requireNotErrorType() {
+  require(!isError) {
+    "Error type '$this' is not resolvable in the current round of processing."
+  }
+}
+
 /** Returns the [ClassName] representation of this [KSType] IFF it's a [KSClassDeclaration]. */
 public fun KSType.toClassName(): ClassName {
+  requireNotErrorType()
   val decl = declaration
   check(decl is KSClassDeclaration) {
     "Declaration was not a KSClassDeclaration: $this"
@@ -61,13 +68,12 @@ internal fun KSType.toTypeName(
   typeParamResolver: TypeParameterResolver,
   typeArguments: List<KSTypeArgument>,
 ): TypeName {
-  require(!isError) {
-    "Error type '$this' is not resolvable in the current round of processing."
-  }
+  requireNotErrorType()
   val type = when (val decl = declaration) {
     is KSClassDeclaration -> {
       decl.toClassName().withTypeArguments(arguments.map { it.toTypeName(typeParamResolver) })
     }
+
     is KSTypeParameter -> typeParamResolver[decl.name.getShortName()]
     is KSTypeAlias -> {
       var typeAlias: KSTypeAlias = decl
@@ -105,6 +111,7 @@ internal fun KSType.toTypeName(
         .withTypeArguments(aliasArgs)
         .copy(tags = mapOf(TypeAliasTag::class to TypeAliasTag(abbreviatedType)))
     }
+
     else -> error("Unsupported type: $declaration")
   }
 
@@ -183,14 +190,15 @@ public fun KSTypeReference.toTypeName(
   typeParamResolver: TypeParameterResolver = TypeParameterResolver.EMPTY,
 ): TypeName {
   val type = resolve()
-  return when (val elem = element) {
-    is KSCallableReference -> {
-      LambdaTypeName.get(
-        receiver = elem.receiverType?.toTypeName(typeParamResolver),
-        parameters = elem.functionParameters.map { ParameterSpec.unnamed(it.type.toTypeName(typeParamResolver)) },
-        returnType = elem.returnType.toTypeName(typeParamResolver),
-      ).copy(nullable = type.isMarkedNullable, suspending = type.isSuspendFunctionType)
-    }
-    else -> type.toTypeName(typeParamResolver, element?.typeArguments.orEmpty())
+  val elem = element
+  // Don't wrap in a lambda if this is a typealias, even if the underlying type is a function type.
+  return if (elem is KSCallableReference && type.declaration !is KSTypeAlias) {
+    LambdaTypeName.get(
+      receiver = elem.receiverType?.toTypeName(typeParamResolver),
+      parameters = elem.functionParameters.map { ParameterSpec.unnamed(it.type.toTypeName(typeParamResolver)) },
+      returnType = elem.returnType.toTypeName(typeParamResolver),
+    ).copy(nullable = type.isMarkedNullable, suspending = type.isSuspendFunctionType)
+  } else {
+    type.toTypeName(typeParamResolver, type.arguments)
   }
 }
diff --git a/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/utils.kt b/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/utils.kt
index 7bc8feda..474cd8e9 100644
--- a/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/utils.kt
+++ b/interop/ksp/src/main/kotlin/com/squareup/kotlinpoet/ksp/utils.kt
@@ -16,6 +16,8 @@
 package com.squareup.kotlinpoet.ksp
 
 import com.google.devtools.ksp.isLocal
+import com.google.devtools.ksp.symbol.ClassKind
+import com.google.devtools.ksp.symbol.KSClassDeclaration
 import com.google.devtools.ksp.symbol.KSDeclaration
 import com.squareup.kotlinpoet.ClassName
 import com.squareup.kotlinpoet.LambdaTypeName
@@ -59,7 +61,15 @@ internal fun KSDeclaration.toClassNameInternal(): ClassName {
   require(!isLocal()) {
     "Local/anonymous classes are not supported!"
   }
+
+  if (this is KSClassDeclaration && classKind == ClassKind.ENUM_ENTRY) {
+    val simpleName = this.simpleName.asString()
+    val parent = parentDeclaration!!.toClassNameInternal()
+    return parent.nestedClass(simpleName)
+  }
+
   val pkgName = packageName.asString()
+
   val typesString = checkNotNull(qualifiedName).asString().removePrefix("$pkgName.")
 
   val simpleNames = typesString
diff --git a/interop/ksp/test-processor/build.gradle.kts b/interop/ksp/test-processor/build.gradle.kts
index d2e3fb77..d159f6cc 100644
--- a/interop/ksp/test-processor/build.gradle.kts
+++ b/interop/ksp/test-processor/build.gradle.kts
@@ -20,10 +20,16 @@ plugins {
 
 tasks.compileTestKotlin {
   compilerOptions {
-    freeCompilerArgs.add("-opt-in=org.jetbrains.kotlin.compiler.plugin.ExperimentalCompilerApi")
+    optIn.add("org.jetbrains.kotlin.compiler.plugin.ExperimentalCompilerApi")
   }
 }
 
+tasks.test {
+  // KSP2 needs more memory to run
+  minHeapSize = "1g"
+  maxHeapSize = "4g"
+}
+
 dependencies {
   implementation(projects.kotlinpoet)
   implementation(projects.interop.ksp)
@@ -37,6 +43,7 @@ dependencies {
   testImplementation(libs.ksp)
   testImplementation(libs.kotlinCompileTesting)
   testImplementation(libs.kotlinCompileTesting.ksp)
+  testImplementation(libs.ksp.aaEmbeddable)
   testImplementation(libs.kotlin.junit)
   testImplementation(libs.truth)
 }
diff --git a/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessor.kt b/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessor.kt
index fb0a5f01..d033bc15 100644
--- a/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessor.kt
+++ b/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessor.kt
@@ -26,13 +26,19 @@ import com.google.devtools.ksp.symbol.ClassKind
 import com.google.devtools.ksp.symbol.KSAnnotated
 import com.google.devtools.ksp.symbol.KSClassDeclaration
 import com.google.devtools.ksp.symbol.KSTypeReference
+import com.google.devtools.ksp.symbol.Modifier
 import com.squareup.kotlinpoet.ANY
+import com.squareup.kotlinpoet.ARRAY
+import com.squareup.kotlinpoet.CodeBlock
 import com.squareup.kotlinpoet.FileSpec
 import com.squareup.kotlinpoet.FunSpec
+import com.squareup.kotlinpoet.KModifier
 import com.squareup.kotlinpoet.ParameterSpec
+import com.squareup.kotlinpoet.ParameterizedTypeName
 import com.squareup.kotlinpoet.PropertySpec
 import com.squareup.kotlinpoet.TypeName
 import com.squareup.kotlinpoet.TypeSpec
+import com.squareup.kotlinpoet.WildcardTypeName
 import com.squareup.kotlinpoet.ksp.TypeParameterResolver
 import com.squareup.kotlinpoet.ksp.addOriginatingKSFile
 import com.squareup.kotlinpoet.ksp.kspDependencies
@@ -70,7 +76,7 @@ class TestProcessor(private val env: SymbolProcessorEnvironment) : SymbolProcess
   private fun process(decl: KSAnnotated) {
     check(decl is KSClassDeclaration)
 
-    val classBuilder = TypeSpec.classBuilder(decl.simpleName.getShortName())
+    val classBuilder = TypeSpec.classBuilder("Test${decl.simpleName.getShortName()}")
       .addOriginatingKSFile(decl.containingFile!!)
       .apply {
         decl.getVisibility().toKModifier()?.let { addModifiers(it) }
@@ -143,6 +149,9 @@ class TestProcessor(private val env: SymbolProcessorEnvironment) : SymbolProcess
               property.annotations
                 .map { it.toAnnotationSpec() }.asIterable(),
             )
+            if (Modifier.LATEINIT !in property.modifiers) {
+              initializer(CodeBlock.of("TODO()"))
+            }
           }
           .build(),
       )
@@ -171,12 +180,32 @@ class TestProcessor(private val env: SymbolProcessorEnvironment) : SymbolProcess
           )
           .addParameters(
             function.parameters.map { parameter ->
+              val isVararg = parameter.isVararg
+              val possibleVararg = if (isVararg) {
+                arrayOf(KModifier.VARARG)
+              } else {
+                emptyArray()
+              }
               // Function references can't be obtained from a resolved KSType because it resolves to FunctionN<> which
               // loses the necessary context, skip validation in these cases as we know they won't match.
               val typeName = if (parameter.type.resolve().run { isFunctionType || isSuspendFunctionType }) {
                 parameter.type.toTypeName(functionTypeParams)
               } else {
                 parameter.type.toValidatedTypeName(functionTypeParams)
+              }.let { paramType ->
+                // In KSP1, this just gives us the T type for the param
+                // In KSP2, this gives us an Array<out T> for the param
+                if (paramType is ParameterizedTypeName && paramType.rawType == ARRAY && isVararg) {
+                  paramType.typeArguments.single().let { componentType ->
+                    if (componentType is WildcardTypeName) {
+                      componentType.outTypes.single()
+                    } else {
+                      componentType
+                    }
+                  }
+                } else {
+                  paramType
+                }
               }
               val parameterType = typeName.let {
                 if (unwrapTypeAliases) {
@@ -186,7 +215,7 @@ class TestProcessor(private val env: SymbolProcessorEnvironment) : SymbolProcess
                 }
               }
               parameter.name?.let {
-                ParameterSpec.builder(it.getShortName(), parameterType).build()
+                ParameterSpec.builder(it.getShortName(), parameterType, *possibleVararg).build()
               } ?: ParameterSpec.unnamed(parameterType)
             },
           )
@@ -199,12 +228,13 @@ class TestProcessor(private val env: SymbolProcessorEnvironment) : SymbolProcess
               }
             },
           )
+          .addCode(CodeBlock.of("return TODO()"))
           .build(),
       )
     }
 
     val typeSpec = classBuilder.build()
-    val fileSpec = FileSpec.builder(decl.packageName.asString(), "Test${typeSpec.name}")
+    val fileSpec = FileSpec.builder(decl.packageName.asString(), typeSpec.name!!)
       .addType(typeSpec)
       .build()
 
diff --git a/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/exampleAnnotations.kt b/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/exampleAnnotations.kt
index 1d763464..cabb5cd8 100644
--- a/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/exampleAnnotations.kt
+++ b/interop/ksp/test-processor/src/main/kotlin/com/squareup/kotlinpoet/ksp/test/processor/exampleAnnotations.kt
@@ -79,3 +79,6 @@ annotation class AnotherAnnotation(val input: String)
 enum class AnnotationEnumValue {
   ONE, TWO, THREE
 }
+
+annotation class AnnotationWithVararg(val simpleArg: Int, vararg val args: String)
+annotation class AnnotationWithTypeArgs<T, R>
diff --git a/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/KsTypesTest.kt b/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/KsTypesTest.kt
index 8da749db..14c8841f 100644
--- a/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/KsTypesTest.kt
+++ b/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/KsTypesTest.kt
@@ -21,6 +21,7 @@ import com.google.devtools.ksp.symbol.KSDeclaration
 import com.google.devtools.ksp.symbol.KSType
 import com.google.devtools.ksp.symbol.KSTypeArgument
 import com.google.devtools.ksp.symbol.Nullability
+import com.squareup.kotlinpoet.ksp.toClassName
 import com.squareup.kotlinpoet.ksp.toTypeName
 import kotlin.test.assertFailsWith
 import org.junit.Test
@@ -77,10 +78,16 @@ class KsTypesTest {
       }
     }
 
-    val exception = assertFailsWith<IllegalArgumentException> {
+    val exception1 = assertFailsWith<IllegalArgumentException> {
+      type.toClassName()
+    }
+    assertThat(exception1).hasMessageThat()
+      .contains("is not resolvable in the current round of processing")
+
+    val exception2 = assertFailsWith<IllegalArgumentException> {
       type.toTypeName()
     }
-    assertThat(exception).hasMessageThat()
+    assertThat(exception2).hasMessageThat()
       .contains("is not resolvable in the current round of processing")
   }
 }
diff --git a/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessorTest.kt b/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessorTest.kt
index 06bf588d..966aca09 100644
--- a/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessorTest.kt
+++ b/interop/ksp/test-processor/src/test/kotlin/com/squareup/kotlinpoet/ksp/test/processor/TestProcessorTest.kt
@@ -19,16 +19,29 @@ import com.google.common.truth.Truth.assertThat
 import com.tschuchort.compiletesting.KotlinCompilation
 import com.tschuchort.compiletesting.SourceFile
 import com.tschuchort.compiletesting.SourceFile.Companion.kotlin
-import com.tschuchort.compiletesting.kspArgs
-import com.tschuchort.compiletesting.kspIncremental
+import com.tschuchort.compiletesting.configureKsp
+import com.tschuchort.compiletesting.kspProcessorOptions
 import com.tschuchort.compiletesting.kspSourcesDir
-import com.tschuchort.compiletesting.symbolProcessorProviders
 import java.io.File
 import org.junit.Rule
 import org.junit.Test
 import org.junit.rules.TemporaryFolder
-
-class TestProcessorTest {
+import org.junit.runner.RunWith
+import org.junit.runners.Parameterized
+
+@RunWith(Parameterized::class)
+class TestProcessorTest(private val useKsp2: Boolean) {
+
+  companion object {
+    @JvmStatic
+    @Parameterized.Parameters(name = "useKsp2={0}")
+    fun data(): Collection<Array<Any>> {
+      return listOf(
+        arrayOf(false),
+        arrayOf(true),
+      )
+    }
+  }
 
   @Rule
   @JvmField
@@ -115,15 +128,15 @@ class TestProcessorTest {
              var propF: T? = null
 
              fun functionA(): String {
-               error()
+               TODO()
              }
 
              fun functionB(): R {
-               error()
+               TODO()
              }
 
              fun <F> functionC(param1: String, param2: T, param3: F, param4: F?): R {
-               error()
+               TODO()
              }
 
              suspend fun functionD(
@@ -238,33 +251,30 @@ class TestProcessorTest {
         someClasses = arrayOf(Int::class),
         enumValueArray = arrayOf(AnnotationEnumValue.ONE, AnnotationEnumValue.TWO),
       )
-      public class SmokeTestClass<T, R : Any, E : Enum<E>> {
+      public class TestSmokeTestClass<T, R : Any, E : Enum<E>> {
         @field:AnotherAnnotation(input = "siteTargeting")
-        private val propA: String
+        private val propA: String = TODO()
 
-        internal val propB: String
+        internal val propB: String = TODO()
 
-        public val propC: Int
+        public val propC: Int = TODO()
 
-        public val propD: Int?
+        public val propD: Int? = TODO()
 
         public lateinit var propE: String
 
-        public var propF: T?
+        public var propF: T? = TODO()
 
-        public fun functionA(): String {
-        }
+        public fun functionA(): String = TODO()
 
-        public fun functionB(): R {
-        }
+        public fun functionB(): R = TODO()
 
         public fun <F> functionC(
           param1: String,
           param2: T,
           param3: F,
           param4: F?,
-        ): R {
-        }
+        ): R = TODO()
 
         public suspend fun functionD(
           param1: () -> String,
@@ -300,8 +310,7 @@ class TestProcessorTest {
           ) -> Unit,
           param7: ((String) -> String)?,
           param8: suspend () -> String,
-        ) {
-        }
+        ): Unit = TODO()
 
         public fun wildTypes(
           age: Int,
@@ -327,8 +336,7 @@ class TestProcessorTest {
           genericAlias: GenericTypeAlias,
           parameterizedTypeAlias: ParameterizedTypeAlias<String>,
           nestedArray: Array<Map<String, Any>>?,
-        ) {
-        }
+        ): Unit = TODO()
       }
 
       """.trimIndent(),
@@ -366,7 +374,7 @@ class TestProcessorTest {
            """,
       ),
     )
-    compilation.kspArgs["unwrapTypeAliases"] = "true"
+    compilation.kspProcessorOptions["unwrapTypeAliases"] = "true"
     val result = compilation.compile()
     assertThat(result.exitCode).isEqualTo(KotlinCompilation.ExitCode.OK)
     val generatedFileText = File(compilation.kspSourcesDir, "kotlin/test/TestExample.kt")
@@ -377,18 +385,18 @@ class TestProcessorTest {
 
       import kotlin.Int
       import kotlin.String
+      import kotlin.Unit
       import kotlin.collections.List
       import kotlin.collections.Map
 
-      public class Example {
+      public class TestExample {
         public fun aliases(
           aliasedName: String,
           genericAlias: List<String>,
           genericMapAlias: Map<Int, String>,
           t1Unused: Map<Int, String>,
           a1: Map<String, Int>,
-        ) {
-        }
+        ): Unit = TODO()
       }
 
       """.trimIndent(),
@@ -454,10 +462,10 @@ class TestProcessorTest {
       import com.squareup.kotlinpoet.ksp.test.processor.ExampleAnnotationWithDefaults
 
       @ExampleAnnotationWithDefaults
-      public open class Node<T : Node<T, R>, R : Node<R, T>> {
-        public var t: T?
+      public open class TestNode<T : Node<T, R>, R : Node<R, T>> {
+        public var t: T? = TODO()
 
-        public var r: R?
+        public var r: R? = TODO()
       }
 
       """.trimIndent(),
@@ -491,10 +499,10 @@ class TestProcessorTest {
       """
       package test
 
-      public open class Node<T : Node<T, R>, R : Node<R, T>> {
-        public var t: T?
+      public open class TestNode<T : Node<T, R>, R : Node<R, T>> {
+        public var t: T? = TODO()
 
-        public var r: R?
+        public var r: R? = TODO()
       }
 
       """.trimIndent(),
@@ -514,7 +522,7 @@ class TestProcessorTest {
 
            @ExampleAnnotation
            class EnumWrapper {
-            val enumValue: Enum<*>
+            val enumValue: Enum<*> = TODO()
            }
            """,
       ),
@@ -530,8 +538,8 @@ class TestProcessorTest {
 
       import kotlin.Enum
 
-      public class EnumWrapper {
-        public val enumValue: Enum<*>
+      public class TestEnumWrapper {
+        public val enumValue: Enum<*> = TODO()
       }
 
       """.trimIndent(),
@@ -574,10 +582,10 @@ class TestProcessorTest {
     package test
 
     import kotlin.Int
+    import kotlin.Unit
 
-    public class TransitiveAliases {
-      public fun <T : Alias41<Alias23, out Alias77<Alias73<Int>>>> bar(arg1: T) {
-      }
+    public class TestTransitiveAliases {
+      public fun <T : Alias41<Alias23, out Alias77<Alias73<Int>>>> bar(vararg arg1: T): Unit = TODO()
     }
 
       """.trimIndent(),
@@ -613,17 +621,63 @@ class TestProcessorTest {
       """
     package test
 
+    import kotlin.Unit
     import kotlin.collections.List
 
-    public class AliasAsTypeArgument {
-      public fun bar(arg1: List<Alias997>) {
-      }
+    public class TestAliasAsTypeArgument {
+      public fun bar(arg1: List<Alias997>): Unit = TODO()
     }
 
       """.trimIndent(),
     )
   }
 
+  @Test
+  fun varargArgument() {
+    val compilation = prepareCompilation(
+      kotlin(
+        "Example.kt",
+        """
+           package test
+
+           import com.squareup.kotlinpoet.ksp.test.processor.AnnotationWithVararg
+           import com.squareup.kotlinpoet.ksp.test.processor.ExampleAnnotation
+
+           @RequiresOptIn
+           annotation class MyOptIn
+
+           @ExampleAnnotation
+           @OptIn(MyOptIn::class)
+           @AnnotationWithVararg(0, "one", "two")
+           interface Example
+        """.trimIndent(),
+      ),
+    )
+
+    val result = compilation.compile()
+    assertThat(result.exitCode).isEqualTo(KotlinCompilation.ExitCode.OK)
+    val generatedFileText = File(compilation.kspSourcesDir, "kotlin/test/TestExample.kt")
+      .readText()
+
+    assertThat(generatedFileText).isEqualTo(
+      """
+      package test
+
+      import com.squareup.kotlinpoet.ksp.test.processor.AnnotationWithVararg
+      import kotlin.OptIn
+
+      @OptIn(MyOptIn::class)
+      @AnnotationWithVararg(
+        simpleArg = 0,
+        "one",
+        "two",
+      )
+      public class TestExample
+
+      """.trimIndent(),
+    )
+  }
+
   @Test
   fun regression_1513() {
     val compilation = prepareCompilation(
@@ -634,6 +688,7 @@ class TestProcessorTest {
 
            import com.squareup.kotlinpoet.ksp.test.processor.ExampleAnnotation
 
+           annotation class Inject
            interface Repository<T>
            @ExampleAnnotation
            class RealRepository @Inject constructor() : Repository<String>
@@ -652,7 +707,7 @@ class TestProcessorTest {
 
         import kotlin.String
 
-        public class RealRepository : Repository<String>
+        public class TestRealRepository : Repository<String>
 
       """.trimIndent(),
     )
@@ -689,7 +744,7 @@ class TestProcessorTest {
         import kotlin.String
 
         @GenericAnnotation<String>
-        public class RealRepository
+        public class TestRealRepository
 
       """.trimIndent(),
     )
@@ -726,7 +781,7 @@ class TestProcessorTest {
       """
         package test
 
-        public class RealRepository {
+        public class TestRealRepository {
           public lateinit var prop: LeAlias
 
           public lateinit var complicated: Flow<LeAlias>
@@ -768,7 +823,7 @@ class TestProcessorTest {
 
         import kotlin.String
 
-        public class RealRepository {
+        public class TestRealRepository {
           public lateinit var prop: LeAlias<String>
         }
 
@@ -776,15 +831,146 @@ class TestProcessorTest {
     )
   }
 
+  @Test
+  fun intersectionTypes() {
+    val compilation = prepareCompilation(
+      kotlin(
+        "Example.kt",
+        """
+           package test
+
+           import com.squareup.kotlinpoet.ksp.test.processor.ExampleAnnotation
+
+           @ExampleAnnotation
+           class Example {
+             fun <T> example() where T : Appendable, T : CharSequence {
+
+             }
+           }
+           """,
+      ),
+    )
+
+    val result = compilation.compile()
+    assertThat(result.exitCode).isEqualTo(KotlinCompilation.ExitCode.OK)
+    val generatedFileText = File(compilation.kspSourcesDir, "kotlin/test/TestExample.kt")
+      .readText()
+
+    assertThat(generatedFileText).isEqualTo(
+      """
+        package test
+
+        import kotlin.CharSequence
+        import kotlin.Unit
+        import kotlin.text.Appendable
+
+        public class TestExample {
+          public fun <T> example(): Unit where T : Appendable, T : CharSequence = TODO()
+        }
+
+      """.trimIndent(),
+    )
+  }
+
+  @Test
+  fun typeArgs() {
+    val compilation = prepareCompilation(
+      kotlin(
+        "Example.kt",
+        """
+           package test
+
+           import com.squareup.kotlinpoet.ksp.test.processor.ExampleAnnotation
+           import com.squareup.kotlinpoet.ksp.test.processor.AnnotationWithTypeArgs
+
+           @ExampleAnnotation
+           @AnnotationWithTypeArgs<String, List<Int>>
+           class Example
+           """,
+      ),
+    )
+
+    val result = compilation.compile()
+    assertThat(result.exitCode).isEqualTo(KotlinCompilation.ExitCode.OK)
+    val generatedFileText = File(compilation.kspSourcesDir, "kotlin/test/TestExample.kt")
+      .readText()
+
+    assertThat(generatedFileText).isEqualTo(
+      """
+        package test
+
+        import com.squareup.kotlinpoet.ksp.test.processor.AnnotationWithTypeArgs
+        import kotlin.Int
+        import kotlin.String
+        import kotlin.collections.List
+
+        @AnnotationWithTypeArgs<String, List<Int>>
+        public class TestExample
+
+      """.trimIndent(),
+    )
+  }
+
+  @Test
+  fun complexAliasing() {
+    val compilation = prepareCompilation(
+      kotlin(
+        "Example.kt",
+        """
+           package test
+
+           import javax.inject.Provider
+           import com.squareup.kotlinpoet.ksp.test.processor.ExampleAnnotation
+
+           typealias DaggerProvider<T> = @JvmSuppressWildcards Provider<T>
+           interface SelectOptions
+           interface SelectHandler<T>
+
+           @ExampleAnnotation
+           class Example(
+             private val handlers: Map<Class<out SelectOptions>, DaggerProvider<SelectHandler<*>>>,
+           )
+           """,
+      ),
+    )
+
+    val result = compilation.compile()
+    assertThat(result.exitCode).isEqualTo(KotlinCompilation.ExitCode.OK)
+    val generatedFileText = File(compilation.kspSourcesDir, "kotlin/test/TestExample.kt")
+      .readText()
+
+    assertThat(generatedFileText).isEqualTo(
+      """
+        package test
+
+        import java.lang.Class
+        import kotlin.collections.Map
+
+        public class TestExample {
+          private val handlers: Map<Class<out SelectOptions>, DaggerProvider<SelectHandler<*>>> = TODO()
+        }
+
+      """.trimIndent(),
+    )
+  }
+
   private fun prepareCompilation(vararg sourceFiles: SourceFile): KotlinCompilation {
     return KotlinCompilation()
       .apply {
         workingDir = temporaryFolder.root
         inheritClassPath = true
-        symbolProcessorProviders = listOf(TestProcessorProvider())
         sources = sourceFiles.asList()
         verbose = false
-        kspIncremental = true // The default now
+        configureKsp(useKsp2) {
+          incremental = true // The default now
+          if (!useKsp2) {
+            languageVersion = "1.9"
+            apiVersion = "1.9"
+            // Doesn't exist in KSP 2
+            withCompilation = true
+          }
+          symbolProcessorProviders += TestProcessorProvider()
+        }
       }
   }
 }
diff --git a/kotlinpoet/api/kotlinpoet.api b/kotlinpoet/api/kotlinpoet.api
index 4e92873d..eef2b613 100644
--- a/kotlinpoet/api/kotlinpoet.api
+++ b/kotlinpoet/api/kotlinpoet.api
@@ -148,7 +148,9 @@ public final class com/squareup/kotlinpoet/CodeBlocks {
 	public static final fun joinToCode (Ljava/util/Collection;Ljava/lang/CharSequence;)Lcom/squareup/kotlinpoet/CodeBlock;
 	public static final fun joinToCode (Ljava/util/Collection;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Lcom/squareup/kotlinpoet/CodeBlock;
 	public static final fun joinToCode (Ljava/util/Collection;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Lcom/squareup/kotlinpoet/CodeBlock;
+	public static final fun joinToCode (Ljava/util/Collection;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Lkotlin/jvm/functions/Function1;)Lcom/squareup/kotlinpoet/CodeBlock;
 	public static synthetic fun joinToCode$default (Ljava/util/Collection;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/CodeBlock;
+	public static synthetic fun joinToCode$default (Ljava/util/Collection;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Lkotlin/jvm/functions/Function1;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/CodeBlock;
 	public static final fun withIndent (Lcom/squareup/kotlinpoet/CodeBlock$Builder;Lkotlin/jvm/functions/Function1;)Lcom/squareup/kotlinpoet/CodeBlock$Builder;
 }
 
@@ -181,7 +183,7 @@ public final class com/squareup/kotlinpoet/Dynamic : com/squareup/kotlinpoet/Typ
 public abstract interface annotation class com/squareup/kotlinpoet/ExperimentalKotlinPoetApi : java/lang/annotation/Annotation {
 }
 
-public final class com/squareup/kotlinpoet/FileSpec : com/squareup/kotlinpoet/Annotatable, com/squareup/kotlinpoet/Taggable, com/squareup/kotlinpoet/TypeSpecHolder {
+public final class com/squareup/kotlinpoet/FileSpec : com/squareup/kotlinpoet/Annotatable, com/squareup/kotlinpoet/MemberSpecHolder, com/squareup/kotlinpoet/Taggable, com/squareup/kotlinpoet/TypeSpecHolder {
 	public static final field Companion Lcom/squareup/kotlinpoet/FileSpec$Companion;
 	public static final fun builder (Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public static final fun builder (Lcom/squareup/kotlinpoet/MemberName;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
@@ -192,9 +194,11 @@ public final class com/squareup/kotlinpoet/FileSpec : com/squareup/kotlinpoet/An
 	public final fun getBody ()Lcom/squareup/kotlinpoet/CodeBlock;
 	public final fun getComment ()Lcom/squareup/kotlinpoet/CodeBlock;
 	public final fun getDefaultImports ()Ljava/util/Set;
+	public fun getFunSpecs ()Ljava/util/List;
 	public final fun getMembers ()Ljava/util/List;
 	public final fun getName ()Ljava/lang/String;
 	public final fun getPackageName ()Ljava/lang/String;
+	public fun getPropertySpecs ()Ljava/util/List;
 	public final fun getRelativePath ()Ljava/lang/String;
 	public fun getTags ()Ljava/util/Map;
 	public fun getTypeSpecs ()Ljava/util/List;
@@ -217,7 +221,7 @@ public final class com/squareup/kotlinpoet/FileSpec : com/squareup/kotlinpoet/An
 	public final fun writeTo (Ljavax/annotation/processing/Filer;)V
 }
 
-public final class com/squareup/kotlinpoet/FileSpec$Builder : com/squareup/kotlinpoet/Annotatable$Builder, com/squareup/kotlinpoet/Taggable$Builder, com/squareup/kotlinpoet/TypeSpecHolder$Builder {
+public final class com/squareup/kotlinpoet/FileSpec$Builder : com/squareup/kotlinpoet/Annotatable$Builder, com/squareup/kotlinpoet/MemberSpecHolder$Builder, com/squareup/kotlinpoet/Taggable$Builder, com/squareup/kotlinpoet/TypeSpecHolder$Builder {
 	public final fun addAliasedImport (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addAliasedImport (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;Ljava/lang/String;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addAliasedImport (Lcom/squareup/kotlinpoet/MemberName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
@@ -239,7 +243,8 @@ public final class com/squareup/kotlinpoet/FileSpec$Builder : com/squareup/kotli
 	public final fun addComment (Ljava/lang/String;[Ljava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addDefaultPackageImport (Ljava/lang/String;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addFileComment (Ljava/lang/String;[Ljava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
-	public final fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
+	public fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
+	public synthetic fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
 	public final fun addImport (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addImport (Lcom/squareup/kotlinpoet/ClassName;[Ljava/lang/String;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addImport (Lcom/squareup/kotlinpoet/Import;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
@@ -253,7 +258,8 @@ public final class com/squareup/kotlinpoet/FileSpec$Builder : com/squareup/kotli
 	public final fun addKotlinDefaultImports (ZZ)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public static synthetic fun addKotlinDefaultImports$default (Lcom/squareup/kotlinpoet/FileSpec$Builder;ZZILjava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public final fun addNamedCode (Ljava/lang/String;Ljava/util/Map;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
-	public final fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
+	public fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
+	public synthetic fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
 	public final fun addStatement (Ljava/lang/String;[Ljava/lang/Object;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public fun addType (Lcom/squareup/kotlinpoet/TypeSpec;)Lcom/squareup/kotlinpoet/FileSpec$Builder;
 	public synthetic fun addType (Lcom/squareup/kotlinpoet/TypeSpec;)Lcom/squareup/kotlinpoet/TypeSpecHolder$Builder;
@@ -559,6 +565,24 @@ public final class com/squareup/kotlinpoet/MemberName$Companion {
 	public final synthetic fun member (Lcom/squareup/kotlinpoet/ClassName;Ljava/lang/String;)Lcom/squareup/kotlinpoet/MemberName;
 }
 
+public abstract interface class com/squareup/kotlinpoet/MemberSpecHolder {
+	public abstract fun getFunSpecs ()Ljava/util/List;
+	public abstract fun getPropertySpecs ()Ljava/util/List;
+}
+
+public abstract interface class com/squareup/kotlinpoet/MemberSpecHolder$Builder {
+	public abstract fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addFunctions (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperties (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public abstract fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+}
+
 public final class com/squareup/kotlinpoet/NameAllocator {
 	public fun <init> ()V
 	public fun <init> (Z)V
@@ -933,7 +957,7 @@ public final class com/squareup/kotlinpoet/TypeNames {
 	public static final fun get (Lkotlin/reflect/KClass;)Lcom/squareup/kotlinpoet/ClassName;
 }
 
-public final class com/squareup/kotlinpoet/TypeSpec : com/squareup/kotlinpoet/Annotatable, com/squareup/kotlinpoet/ContextReceivable, com/squareup/kotlinpoet/Documentable, com/squareup/kotlinpoet/OriginatingElementsHolder, com/squareup/kotlinpoet/Taggable, com/squareup/kotlinpoet/TypeSpecHolder {
+public final class com/squareup/kotlinpoet/TypeSpec : com/squareup/kotlinpoet/Annotatable, com/squareup/kotlinpoet/ContextReceivable, com/squareup/kotlinpoet/Documentable, com/squareup/kotlinpoet/MemberSpecHolder, com/squareup/kotlinpoet/OriginatingElementsHolder, com/squareup/kotlinpoet/Taggable, com/squareup/kotlinpoet/TypeSpecHolder {
 	public static final field Companion Lcom/squareup/kotlinpoet/TypeSpec$Companion;
 	public static final fun annotationBuilder (Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public static final fun annotationBuilder (Ljava/lang/String;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
@@ -953,7 +977,7 @@ public final class com/squareup/kotlinpoet/TypeSpec : com/squareup/kotlinpoet/An
 	public fun getAnnotations ()Ljava/util/List;
 	public fun getContextReceiverTypes ()Ljava/util/List;
 	public final fun getEnumConstants ()Ljava/util/Map;
-	public final fun getFunSpecs ()Ljava/util/List;
+	public fun getFunSpecs ()Ljava/util/List;
 	public final fun getInitializerBlock ()Lcom/squareup/kotlinpoet/CodeBlock;
 	public final fun getInitializerIndex ()I
 	public fun getKdoc ()Lcom/squareup/kotlinpoet/CodeBlock;
@@ -962,7 +986,7 @@ public final class com/squareup/kotlinpoet/TypeSpec : com/squareup/kotlinpoet/An
 	public final fun getName ()Ljava/lang/String;
 	public fun getOriginatingElements ()Ljava/util/List;
 	public final fun getPrimaryConstructor ()Lcom/squareup/kotlinpoet/FunSpec;
-	public final fun getPropertySpecs ()Ljava/util/List;
+	public fun getPropertySpecs ()Ljava/util/List;
 	public final fun getSuperclass ()Lcom/squareup/kotlinpoet/TypeName;
 	public final fun getSuperclassConstructorParameters ()Ljava/util/List;
 	public final fun getSuperinterfaces ()Ljava/util/Map;
@@ -989,7 +1013,7 @@ public final class com/squareup/kotlinpoet/TypeSpec : com/squareup/kotlinpoet/An
 	public static final fun valueClassBuilder (Ljava/lang/String;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 }
 
-public final class com/squareup/kotlinpoet/TypeSpec$Builder : com/squareup/kotlinpoet/Annotatable$Builder, com/squareup/kotlinpoet/ContextReceivable$Builder, com/squareup/kotlinpoet/Documentable$Builder, com/squareup/kotlinpoet/OriginatingElementsHolder$Builder, com/squareup/kotlinpoet/Taggable$Builder, com/squareup/kotlinpoet/TypeSpecHolder$Builder {
+public final class com/squareup/kotlinpoet/TypeSpec$Builder : com/squareup/kotlinpoet/Annotatable$Builder, com/squareup/kotlinpoet/ContextReceivable$Builder, com/squareup/kotlinpoet/Documentable$Builder, com/squareup/kotlinpoet/MemberSpecHolder$Builder, com/squareup/kotlinpoet/OriginatingElementsHolder$Builder, com/squareup/kotlinpoet/Taggable$Builder, com/squareup/kotlinpoet/TypeSpecHolder$Builder {
 	public synthetic fun addAnnotation (Lcom/squareup/kotlinpoet/AnnotationSpec;)Lcom/squareup/kotlinpoet/Annotatable$Builder;
 	public fun addAnnotation (Lcom/squareup/kotlinpoet/AnnotationSpec;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public synthetic fun addAnnotation (Lcom/squareup/kotlinpoet/ClassName;)Lcom/squareup/kotlinpoet/Annotatable$Builder;
@@ -1003,8 +1027,10 @@ public final class com/squareup/kotlinpoet/TypeSpec$Builder : com/squareup/kotli
 	public final fun addEnumConstant (Ljava/lang/String;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addEnumConstant (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeSpec;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public static synthetic fun addEnumConstant$default (Lcom/squareup/kotlinpoet/TypeSpec$Builder;Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeSpec;ILjava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addFunctions (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addFunction (Lcom/squareup/kotlinpoet/FunSpec;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addFunctions (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addFunctions (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addInitializerBlock (Lcom/squareup/kotlinpoet/CodeBlock;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public synthetic fun addKdoc (Lcom/squareup/kotlinpoet/CodeBlock;)Lcom/squareup/kotlinpoet/Documentable$Builder;
 	public fun addKdoc (Lcom/squareup/kotlinpoet/CodeBlock;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
@@ -1012,14 +1038,22 @@ public final class com/squareup/kotlinpoet/TypeSpec$Builder : com/squareup/kotli
 	public fun addKdoc (Ljava/lang/String;[Ljava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addModifiers (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addModifiers ([Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperties (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
-	public final fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperties (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperties (Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Lcom/squareup/kotlinpoet/PropertySpec;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lcom/squareup/kotlinpoet/TypeName;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Ljava/lang/reflect/Type;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;Ljava/lang/Iterable;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
+	public synthetic fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/MemberSpecHolder$Builder;
+	public fun addProperty (Ljava/lang/String;Lkotlin/reflect/KClass;[Lcom/squareup/kotlinpoet/KModifier;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addSuperclassConstructorParameter (Lcom/squareup/kotlinpoet/CodeBlock;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addSuperclassConstructorParameter (Ljava/lang/String;[Ljava/lang/Object;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
 	public final fun addSuperinterface (Lcom/squareup/kotlinpoet/TypeName;Lcom/squareup/kotlinpoet/CodeBlock;)Lcom/squareup/kotlinpoet/TypeSpec$Builder;
diff --git a/kotlinpoet/build.gradle.kts b/kotlinpoet/build.gradle.kts
index 48669b33..48ab9c72 100644
--- a/kotlinpoet/build.gradle.kts
+++ b/kotlinpoet/build.gradle.kts
@@ -13,6 +13,8 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
+
 plugins {
   kotlin("multiplatform")
 }
@@ -35,6 +37,12 @@ kotlin {
     withJava()
   }
 
+  @OptIn(ExperimentalKotlinGradlePluginApi::class)
+  compilerOptions {
+    allWarningsAsErrors.set(true)
+    optIn.add("com.squareup.kotlinpoet.DelicateKotlinPoetApi")
+  }
+
   sourceSets {
     val commonMain by getting {
       dependencies {
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeBlock.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeBlock.kt
index 6a99631c..2f628737 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeBlock.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeBlock.kt
@@ -22,6 +22,7 @@ import java.text.DecimalFormat
 import java.text.DecimalFormatSymbols
 import javax.lang.model.element.Element
 import javax.lang.model.type.TypeMirror
+import kotlin.math.max
 import kotlin.reflect.KClass
 
 /**
@@ -374,7 +375,11 @@ public class CodeBlock private constructor(
         minusSign = '-'
       }
 
-      val precision = if (o is Float || o is Double) o.toString().split(".").last().length else 0
+      val precision = when (o) {
+        is Float -> max(o.toBigDecimal().stripTrailingZeros().scale(), 1)
+        is Double -> max(o.toBigDecimal().stripTrailingZeros().scale(), 1)
+        else -> 0
+      }
 
       val pattern = when (o) {
         is Float, is Double -> "###,##0.0" + "#".repeat(precision - 1)
@@ -494,6 +499,10 @@ public class CodeBlock private constructor(
   }
 }
 
+/**
+ * Join each [CodeBlock] in [this] into a single [CodeBlock] using [separator] with an optional
+ * [prefix] and [suffix].
+ */
 @JvmOverloads
 public fun Collection<CodeBlock>.joinToCode(
   separator: CharSequence = ", ",
@@ -505,6 +514,19 @@ public fun Collection<CodeBlock>.joinToCode(
   return CodeBlock.of(placeholders.joinToString(separator, prefix, suffix), *blocks)
 }
 
+/**
+ * Apply [transform] to each element in [this], then join into a single [CodeBlock] using
+ * [separator] with an optional [prefix] and [suffix].
+ */
+public fun <T> Collection<T>.joinToCode(
+  separator: CharSequence = ", ",
+  prefix: CharSequence = "",
+  suffix: CharSequence = "",
+  transform: (T) -> CodeBlock,
+): CodeBlock {
+  return map(transform).joinToCode(separator, prefix, suffix)
+}
+
 /**
  * Builds new [CodeBlock] by populating newly created [CodeBlock.Builder] using provided
  * [builderAction] and then converting it to [CodeBlock].
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeWriter.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeWriter.kt
index d4489f24..584fde50 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeWriter.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/CodeWriter.kt
@@ -54,12 +54,12 @@ internal fun buildCodeString(
  * Converts a [FileSpec] to a string suitable to both human- and kotlinc-consumption. This honors
  * imports, indentation, and deferred variable names.
  */
-internal class CodeWriter constructor(
+internal class CodeWriter(
   out: Appendable,
   private val indent: String = DEFAULT_INDENT,
   imports: Map<String, Import> = emptyMap(),
   private val importedTypes: Map<String, ClassName> = emptyMap(),
-  private val importedMembers: Map<String, MemberName> = emptyMap(),
+  private val importedMembers: Map<String, Set<MemberName>> = emptyMap(),
   columnLimit: Int = 100,
 ) : Closeable {
   private var out = LineWrapper(out, indent, columnLimit)
@@ -238,13 +238,14 @@ internal class CodeWriter constructor(
     codeBlock: CodeBlock,
     isConstantContext: Boolean = false,
     ensureTrailingNewline: Boolean = false,
+    omitImplicitModifiers: Boolean = false,
   ) = apply {
     var a = 0
     var deferredTypeName: ClassName? = null // used by "import static" logic
     val partIterator = codeBlock.formatParts.listIterator()
     while (partIterator.hasNext()) {
       when (val part = partIterator.next()) {
-        "%L" -> emitLiteral(codeBlock.args[a++], isConstantContext)
+        "%L" -> emitLiteral(codeBlock.args[a++], isConstantContext, omitImplicitModifiers)
 
         "%N" -> emit(codeBlock.args[a++] as String)
 
@@ -393,7 +394,7 @@ internal class CodeWriter constructor(
     return false
   }
 
-  private fun emitLiteral(o: Any?, isConstantContext: Boolean) {
+  private fun emitLiteral(o: Any?, isConstantContext: Boolean, omitImplicitModifiers: Boolean) {
     when (o) {
       is TypeSpec -> o.emit(this, null)
       is AnnotationSpec -> o.emit(this, inline = true, asParameter = isConstantContext)
@@ -401,7 +402,7 @@ internal class CodeWriter constructor(
       is FunSpec -> o.emit(
         codeWriter = this,
         enclosingName = null,
-        implicitModifiers = setOf(KModifier.PUBLIC),
+        implicitModifiers = if (omitImplicitModifiers) emptySet() else setOf(KModifier.PUBLIC),
         includeKdocTags = true,
       )
       is TypeAliasSpec -> o.emit(this)
@@ -462,12 +463,15 @@ internal class CodeWriter constructor(
   fun lookupName(memberName: MemberName): String {
     val simpleName = imports[memberName.canonicalName]?.alias ?: memberName.simpleName
     // Match an imported member.
-    val importedMember = importedMembers[simpleName]
-    if (importedMember == memberName) {
+    val importedMembers = importedMembers[simpleName] ?: emptySet()
+    val found = memberName in importedMembers
+    if (found && !isMethodNameUsedInCurrentContext(simpleName)) {
       return simpleName
-    } else if (importedMember != null && memberName.enclosingClassName != null) {
+    } else if (importedMembers.isNotEmpty() && memberName.enclosingClassName != null) {
       val enclosingClassName = lookupName(memberName.enclosingClassName)
       return "$enclosingClassName.$simpleName"
+    } else if (found) {
+      return simpleName
     }
 
     // If the member is in the same package, we're done.
@@ -505,20 +509,25 @@ internal class CodeWriter constructor(
 
   private fun importableType(className: ClassName) {
     val topLevelClassName = className.topLevelClassName()
-    val simpleName = imports[className.canonicalName]?.alias ?: topLevelClassName.simpleName
+    val alias = imports[className.canonicalName]?.alias
+    val simpleName = alias ?: topLevelClassName.simpleName
     // Check for name clashes with members.
     if (simpleName !in importableMembers) {
-      importableTypes[simpleName] = importableTypes.getValue(simpleName) + topLevelClassName
+      // Maintain the inner class name if the alias exists.
+      val newImportTypes = if (alias == null) {
+        topLevelClassName
+      } else {
+        className
+      }
+      importableTypes[simpleName] = importableTypes.getValue(simpleName) + newImportTypes
     }
   }
 
   private fun importableMember(memberName: MemberName) {
-    if (memberName.packageName.isNotEmpty()) {
-      val simpleName = imports[memberName.canonicalName]?.alias ?: memberName.simpleName
-      // Check for name clashes with types.
-      if (simpleName !in importableTypes) {
-        importableMembers[simpleName] = importableMembers.getValue(simpleName) + memberName
-      }
+    val simpleName = imports[memberName.canonicalName]?.alias ?: memberName.simpleName
+    // Check for name clashes with types.
+    if (memberName.isExtension || simpleName !in importableTypes) {
+      importableMembers[simpleName] = importableMembers.getValue(simpleName) + memberName
     }
   }
 
@@ -666,7 +675,7 @@ internal class CodeWriter constructor(
    * collisions, import aliases will be generated.
    */
   private fun suggestedMemberImports(): Map<String, Set<MemberName>> {
-    return importableMembers.filterKeys { it !in referencedNames }.mapValues { it.value.toSet() }
+    return importableMembers.mapValues { it.value.toSet() }
   }
 
   /**
@@ -678,6 +687,7 @@ internal class CodeWriter constructor(
     LineWrapper(out, indent = DEFAULT_INDENT, columnLimit = Int.MAX_VALUE).use { newOut ->
       val oldOut = codeWrapper.out
       codeWrapper.out = newOut
+      @Suppress("UNUSED_EXPRESSION", "unused")
       action()
       codeWrapper.out = oldOut
     }
@@ -707,17 +717,19 @@ internal class CodeWriter constructor(
       )
       emitStep(importsCollector)
       val generatedImports = mutableMapOf<String, Import>()
-      val suggestedTypeImports = importsCollector.suggestedTypeImports()
+      val importedTypes = importsCollector.suggestedTypeImports()
         .generateImports(
           generatedImports,
-          canonicalName = ClassName::canonicalName,
+          computeCanonicalName = ClassName::canonicalName,
           capitalizeAliases = true,
+          referencedNames = importsCollector.referencedNames,
         )
-      val suggestedMemberImports = importsCollector.suggestedMemberImports()
+      val importedMembers = importsCollector.suggestedMemberImports()
         .generateImports(
           generatedImports,
-          canonicalName = MemberName::canonicalName,
+          computeCanonicalName = MemberName::canonicalName,
           capitalizeAliases = false,
+          referencedNames = importsCollector.referencedNames,
         )
       importsCollector.close()
 
@@ -725,40 +737,49 @@ internal class CodeWriter constructor(
         out = out,
         indent = indent,
         imports = memberImports + generatedImports.filterKeys { it !in memberImports },
-        importedTypes = suggestedTypeImports,
-        importedMembers = suggestedMemberImports,
+        importedTypes = importedTypes.mapValues { it.value.single() },
+        importedMembers = importedMembers,
       )
     }
 
     private fun <T> Map<String, Set<T>>.generateImports(
       generatedImports: MutableMap<String, Import>,
-      canonicalName: T.() -> String,
+      computeCanonicalName: T.() -> String,
       capitalizeAliases: Boolean,
-    ): Map<String, T> {
-      return flatMap { (simpleName, qualifiedNames) ->
-        if (qualifiedNames.size == 1) {
-          listOf(simpleName to qualifiedNames.first()).also {
-            val canonicalName = qualifiedNames.first().canonicalName()
-            generatedImports[canonicalName] = Import(canonicalName)
-          }
+      referencedNames: Set<String>,
+    ): Map<String, Set<T>> {
+      val imported = mutableMapOf<String, Set<T>>()
+      forEach { (simpleName, qualifiedNames) ->
+        val canonicalNamesToQualifiedNames = qualifiedNames.associateBy { it.computeCanonicalName() }
+        if (canonicalNamesToQualifiedNames.size == 1 && simpleName !in referencedNames) {
+          val canonicalName = canonicalNamesToQualifiedNames.keys.single()
+          generatedImports[canonicalName] = Import(canonicalName)
+
+          // For types, qualifiedNames should consist of a single name, for which an import will be generated. For
+          // members, there can be more than one qualified name mapping to a single simple name, e.g. overloaded
+          // functions declared in the same package. In these cases, a single import will suffice for all of them.
+          imported[simpleName] = qualifiedNames
         } else {
-          generateImportAliases(simpleName, qualifiedNames, canonicalName, capitalizeAliases)
-            .onEach { (alias, qualifiedName) ->
-              val canonicalName = qualifiedName.canonicalName()
+          generateImportAliases(simpleName, canonicalNamesToQualifiedNames, capitalizeAliases)
+            .onEach { (a, qualifiedName) ->
+              val alias = a.escapeAsAlias()
+              val canonicalName = qualifiedName.computeCanonicalName()
               generatedImports[canonicalName] = Import(canonicalName, alias)
+
+              imported[alias] = setOf(qualifiedName)
             }
         }
-      }.toMap()
+      }
+      return imported
     }
 
     private fun <T> generateImportAliases(
       simpleName: String,
-      qualifiedNames: Set<T>,
-      canonicalName: T.() -> String,
+      canonicalNamesToQualifiedNames: Map<String, T>,
       capitalizeAliases: Boolean,
     ): List<Pair<String, T>> {
-      val canonicalNameSegments = qualifiedNames.associateWith { qualifiedName ->
-        qualifiedName.canonicalName().split('.')
+      val canonicalNameSegmentsToQualifiedNames = canonicalNamesToQualifiedNames.mapKeys { (canonicalName, _) ->
+        canonicalName.split('.')
           .dropLast(1) // Last segment of the canonical name is the simple name, drop it to avoid repetition.
           .filter { it != "Companion" }
           .map { it.replaceFirstChar(Char::uppercaseChar) }
@@ -766,10 +787,10 @@ internal class CodeWriter constructor(
       val aliasNames = mutableMapOf<String, T>()
       var segmentsToUse = 0
       // Iterate until we have unique aliases for all names.
-      while (aliasNames.size != qualifiedNames.size) {
+      while (aliasNames.size != canonicalNamesToQualifiedNames.size) {
         segmentsToUse += 1
         aliasNames.clear()
-        for ((qualifiedName, segments) in canonicalNameSegments) {
+        for ((segments, qualifiedName) in canonicalNameSegmentsToQualifiedNames) {
           val aliasPrefix = segments.takeLast(min(segmentsToUse, segments.size))
             .joinToString(separator = "")
             .replaceFirstChar { if (!capitalizeAliases) it.lowercaseChar() else it }
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/FileSpec.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/FileSpec.kt
index 288848c9..dbe6c65f 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/FileSpec.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/FileSpec.kt
@@ -49,9 +49,11 @@ import kotlin.reflect.KClass
 public class FileSpec private constructor(
   builder: Builder,
   private val tagMap: TagMap = builder.buildTagMap(),
-) : Taggable by tagMap, Annotatable, TypeSpecHolder {
+) : Taggable by tagMap, Annotatable, TypeSpecHolder, MemberSpecHolder {
   override val annotations: List<AnnotationSpec> = builder.annotations.toImmutableList()
   override val typeSpecs: List<TypeSpec> = builder.members.filterIsInstance<TypeSpec>().toImmutableList()
+  override val propertySpecs: List<PropertySpec> = builder.members.filterIsInstance<PropertySpec>().toImmutableList()
+  override val funSpecs: List<FunSpec> = builder.members.filterIsInstance<FunSpec>().toImmutableList()
   public val comment: CodeBlock = builder.comment.build()
   public val packageName: String = builder.packageName
   public val name: String = builder.name
@@ -141,7 +143,7 @@ public class FileSpec private constructor(
     } catch (e: Exception) {
       try {
         filerSourceFile.delete()
-      } catch (ignored: Exception) {
+      } catch (_: Exception) {
       }
       throw e
     }
@@ -191,7 +193,7 @@ public class FileSpec private constructor(
     }
 
     if (isScript) {
-      codeWriter.emitCode(body)
+      codeWriter.emitCode(body, omitImplicitModifiers = true)
     } else {
       members.forEachIndexed { index, member ->
         if (index > 0) codeWriter.emit("\n")
@@ -253,7 +255,11 @@ public class FileSpec private constructor(
     public val packageName: String,
     public val name: String,
     public val isScript: Boolean,
-  ) : Taggable.Builder<Builder>, Annotatable.Builder<Builder>, TypeSpecHolder.Builder<Builder> {
+  ) : Taggable.Builder<Builder>,
+    Annotatable.Builder<Builder>,
+    TypeSpecHolder.Builder<Builder>,
+    MemberSpecHolder.Builder<Builder> {
+
     override val annotations: MutableList<AnnotationSpec> = mutableListOf()
     internal val comment = CodeBlock.builder()
     internal val memberImports = sortedSetOf<Import>()
@@ -311,7 +317,7 @@ public class FileSpec private constructor(
     override fun addTypes(typeSpecs: Iterable<TypeSpec>): Builder = super.addTypes(typeSpecs)
     //endregion
 
-    public fun addFunction(funSpec: FunSpec): Builder = apply {
+    override fun addFunction(funSpec: FunSpec): Builder = apply {
       require(!funSpec.isConstructor && !funSpec.isAccessor) {
         "cannot add ${funSpec.name} to file $name"
       }
@@ -322,7 +328,7 @@ public class FileSpec private constructor(
       }
     }
 
-    public fun addProperty(propertySpec: PropertySpec): Builder = apply {
+    override fun addProperty(propertySpec: PropertySpec): Builder = apply {
       if (isScript) {
         body.add("%L", propertySpec)
       } else {
@@ -339,7 +345,7 @@ public class FileSpec private constructor(
     }
 
     public fun addImport(constant: Enum<*>): Builder = addImport(
-      (constant as java.lang.Enum<*>).declaringClass.asClassName(),
+      constant.declaringJavaClass.asClassName(),
       constant.name,
     )
 
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/MemberSpecHolder.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/MemberSpecHolder.kt
new file mode 100644
index 00000000..e7d6724b
--- /dev/null
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/MemberSpecHolder.kt
@@ -0,0 +1,67 @@
+/*
+ * Copyright (C) 2024 Square, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.squareup.kotlinpoet
+
+import java.lang.reflect.Type
+import kotlin.reflect.KClass
+
+/** A spec which can contain [PropertySpec]s and [FunSpec]s. */
+public interface MemberSpecHolder {
+  public val propertySpecs: List<PropertySpec>
+  public val funSpecs: List<FunSpec>
+
+  public interface Builder<out T : Builder<T>> {
+    @Suppress("UNCHECKED_CAST")
+    public fun addProperties(propertySpecs: Iterable<PropertySpec>): T = apply {
+      propertySpecs.map(::addProperty)
+    } as T
+
+    public fun addProperty(propertySpec: PropertySpec): T
+
+    public fun addProperty(name: String, type: TypeName, vararg modifiers: KModifier): T =
+      addProperty(PropertySpec.builder(name, type, *modifiers).build())
+
+    @DelicateKotlinPoetApi(
+      message = "Java reflection APIs don't give complete information on Kotlin types. Consider " +
+        "using the kotlinpoet-metadata APIs instead.",
+    )
+    public fun addProperty(name: String, type: Type, vararg modifiers: KModifier): T =
+      addProperty(name, type.asTypeName(), *modifiers)
+
+    public fun addProperty(name: String, type: KClass<*>, vararg modifiers: KModifier): T =
+      addProperty(name, type.asTypeName(), *modifiers)
+
+    public fun addProperty(name: String, type: TypeName, modifiers: Iterable<KModifier>): T =
+      addProperty(PropertySpec.builder(name, type, modifiers).build())
+
+    @DelicateKotlinPoetApi(
+      message = "Java reflection APIs don't give complete information on Kotlin types. Consider " +
+        "using the kotlinpoet-metadata APIs instead.",
+    )
+    public fun addProperty(name: String, type: Type, modifiers: Iterable<KModifier>): T =
+      addProperty(name, type.asTypeName(), modifiers)
+
+    public fun addProperty(name: String, type: KClass<*>, modifiers: Iterable<KModifier>): T =
+      addProperty(name, type.asTypeName(), modifiers)
+
+    @Suppress("UNCHECKED_CAST")
+    public fun addFunctions(funSpecs: Iterable<FunSpec>): T = apply {
+      funSpecs.forEach(::addFunction)
+    } as T
+
+    public fun addFunction(funSpec: FunSpec): T
+  }
+}
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/ParameterSpec.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/ParameterSpec.kt
index 91dc8b06..7eaff62a 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/ParameterSpec.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/ParameterSpec.kt
@@ -115,7 +115,7 @@ public class ParameterSpec private constructor(
       ReplaceWith(""),
       level = ERROR,
     )
-    public fun jvmModifiers(modifiers: Iterable<Modifier>): Builder = apply {
+    public fun jvmModifiers(@Suppress("UNUSED_PARAMETER", "unused") modifiers: Iterable<Modifier>): Builder = apply {
       throw IllegalArgumentException("JVM modifiers are not permitted on parameters in Kotlin")
     }
 
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/PropertySpec.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/PropertySpec.kt
index 9ba9409c..be903e6b 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/PropertySpec.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/PropertySpec.kt
@@ -100,7 +100,7 @@ public class PropertySpec private constructor(
       }
       val initializerFormat = if (initializer.hasStatements()) "%L" else "«%L»"
       codeWriter.emitCode(
-        codeBlock = CodeBlock.of(initializerFormat, initializer),
+        codeBlock = CodeBlock.of(initializerFormat, initializer.trimTrailingNewLine()),
         isConstantContext = KModifier.CONST in modifiers,
       )
     }
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/TypeSpec.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/TypeSpec.kt
index af0613b3..677ab740 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/TypeSpec.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/TypeSpec.kt
@@ -48,7 +48,8 @@ public class TypeSpec private constructor(
   ContextReceivable by contextReceivers,
   Annotatable,
   Documentable,
-  TypeSpecHolder {
+  TypeSpecHolder,
+  MemberSpecHolder {
   public val kind: Kind = builder.kind
   public val name: String? = builder.name
   override val kdoc: CodeBlock = builder.kdoc.build()
@@ -73,10 +74,10 @@ public class TypeSpec private constructor(
    */
   public val superinterfaces: Map<TypeName, CodeBlock?> = builder.superinterfaces.toImmutableMap()
   public val enumConstants: Map<String, TypeSpec> = builder.enumConstants.toImmutableMap()
-  public val propertySpecs: List<PropertySpec> = builder.propertySpecs.toImmutableList()
+  override val propertySpecs: List<PropertySpec> = builder.propertySpecs.toImmutableList()
   public val initializerBlock: CodeBlock = builder.initializerBlock.build()
   public val initializerIndex: Int = builder.initializerIndex
-  public val funSpecs: List<FunSpec> = builder.funSpecs.toImmutableList()
+  override val funSpecs: List<FunSpec> = builder.funSpecs.toImmutableList()
   public override val typeSpecs: List<TypeSpec> = builder.typeSpecs.toImmutableList()
   internal val nestedTypesSimpleNames = typeSpecs.map { it.name }.toImmutableSet()
 
@@ -178,6 +179,7 @@ public class TypeSpec private constructor(
         }
         codeWriter.emitTypeVariables(typeVariables)
 
+        var wrapSupertypes = false
         primaryConstructor?.let {
           codeWriter.pushType(this) // avoid name collisions when emitting primary constructor
           val emittedAnnotations = it.annotations.isNotEmpty()
@@ -198,6 +200,8 @@ public class TypeSpec private constructor(
           }
 
           it.parameters.emit(codeWriter, forceNewLines = true) { param ->
+            wrapSupertypes = true
+
             val property = constructorProperties[param.name]
             if (property != null) {
               property.emit(
@@ -232,7 +236,8 @@ public class TypeSpec private constructor(
         }
 
         if (superTypes.isNotEmpty()) {
-          codeWriter.emitCode(superTypes.joinToCode(separator = ", ", prefix = " : "))
+          val separator = if (wrapSupertypes) ",\n    " else ", "
+          codeWriter.emitCode(superTypes.joinToCode(separator = separator, prefix = " : "))
         }
 
         codeWriter.emitWhereBlock(typeVariables)
@@ -471,7 +476,8 @@ public class TypeSpec private constructor(
     ContextReceivable.Builder<Builder>,
     Annotatable.Builder<Builder>,
     Documentable.Builder<Builder>,
-    TypeSpecHolder.Builder<Builder> {
+    TypeSpecHolder.Builder<Builder>,
+    MemberSpecHolder.Builder<Builder> {
     internal var primaryConstructor: FunSpec? = null
     internal var superclass: TypeName = ANY
     internal val initializerBlock = CodeBlock.builder()
@@ -537,6 +543,13 @@ public class TypeSpec private constructor(
             "value/inline classes must have 1 parameter in constructor"
           }
         }
+
+        require(
+          primaryConstructor.delegateConstructor == null &&
+            primaryConstructor.delegateConstructorArguments.isEmpty(),
+        ) {
+          "primary constructor can't delegate to other constructors"
+        }
       }
       this.primaryConstructor = primaryConstructor
     }
@@ -653,11 +666,7 @@ public class TypeSpec private constructor(
       enumConstants[name] = typeSpec
     }
 
-    public fun addProperties(propertySpecs: Iterable<PropertySpec>): Builder = apply {
-      propertySpecs.map(this::addProperty)
-    }
-
-    public fun addProperty(propertySpec: PropertySpec): Builder = apply {
+    override fun addProperty(propertySpec: PropertySpec): Builder = apply {
       if (EXPECT in modifiers) {
         require(propertySpec.initializer == null) {
           "properties in expect classes can't have initializers"
@@ -674,32 +683,6 @@ public class TypeSpec private constructor(
       propertySpecs += propertySpec
     }
 
-    public fun addProperty(name: String, type: TypeName, vararg modifiers: KModifier): Builder =
-      addProperty(PropertySpec.builder(name, type, *modifiers).build())
-
-    @DelicateKotlinPoetApi(
-      message = "Java reflection APIs don't give complete information on Kotlin types. Consider " +
-        "using the kotlinpoet-metadata APIs instead.",
-    )
-    public fun addProperty(name: String, type: Type, vararg modifiers: KModifier): Builder =
-      addProperty(name, type.asTypeName(), *modifiers)
-
-    public fun addProperty(name: String, type: KClass<*>, vararg modifiers: KModifier): Builder =
-      addProperty(name, type.asTypeName(), *modifiers)
-
-    public fun addProperty(name: String, type: TypeName, modifiers: Iterable<KModifier>): Builder =
-      addProperty(PropertySpec.builder(name, type, modifiers).build())
-
-    @DelicateKotlinPoetApi(
-      message = "Java reflection APIs don't give complete information on Kotlin types. Consider " +
-        "using the kotlinpoet-metadata APIs instead.",
-    )
-    public fun addProperty(name: String, type: Type, modifiers: Iterable<KModifier>): Builder =
-      addProperty(name, type.asTypeName(), modifiers)
-
-    public fun addProperty(name: String, type: KClass<*>, modifiers: Iterable<KModifier>): Builder =
-      addProperty(name, type.asTypeName(), modifiers)
-
     public fun addInitializerBlock(block: CodeBlock): Builder = apply {
       checkCanHaveInitializerBlocks()
       // Set index to however many properties we have
@@ -713,11 +696,7 @@ public class TypeSpec private constructor(
         .add("}\n")
     }
 
-    public fun addFunctions(funSpecs: Iterable<FunSpec>): Builder = apply {
-      funSpecs.forEach { addFunction(it) }
-    }
-
-    public fun addFunction(funSpec: FunSpec): Builder = apply {
+    override fun addFunction(funSpec: FunSpec): Builder = apply {
       funSpecs += funSpec
     }
 
@@ -759,6 +738,43 @@ public class TypeSpec private constructor(
 
     @Suppress("RedundantOverride")
     override fun addTypes(typeSpecs: Iterable<TypeSpec>): Builder = super.addTypes(typeSpecs)
+
+    @Suppress("RedundantOverride")
+    override fun addProperties(propertySpecs: Iterable<PropertySpec>): Builder =
+      super.addProperties(propertySpecs)
+
+    @Suppress("RedundantOverride")
+    override fun addProperty(name: String, type: TypeName, vararg modifiers: KModifier): Builder =
+      super.addProperty(name, type, *modifiers)
+
+    @DelicateKotlinPoetApi(
+      message = "Java reflection APIs don't give complete information on Kotlin types. Consider " +
+        "using the kotlinpoet-metadata APIs instead.",
+    )
+    override fun addProperty(name: String, type: Type, vararg modifiers: KModifier): Builder =
+      super.addProperty(name, type, *modifiers)
+
+    @Suppress("RedundantOverride")
+    override fun addProperty(name: String, type: KClass<*>, vararg modifiers: KModifier): Builder =
+      super.addProperty(name, type, *modifiers)
+
+    @Suppress("RedundantOverride")
+    override fun addProperty(name: String, type: TypeName, modifiers: Iterable<KModifier>): Builder =
+      super.addProperty(name, type, modifiers)
+
+    @DelicateKotlinPoetApi(
+      message = "Java reflection APIs don't give complete information on Kotlin types. Consider " +
+        "using the kotlinpoet-metadata APIs instead.",
+    )
+    override fun addProperty(name: String, type: Type, modifiers: Iterable<KModifier>): Builder =
+      super.addProperty(name, type, modifiers)
+
+    @Suppress("RedundantOverride")
+    override fun addProperty(name: String, type: KClass<*>, modifiers: Iterable<KModifier>): Builder =
+      super.addProperty(name, type, modifiers)
+
+    @Suppress("RedundantOverride")
+    override fun addFunctions(funSpecs: Iterable<FunSpec>): Builder = super.addFunctions(funSpecs)
     //endregion
 
     public fun build(): TypeSpec {
diff --git a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/Util.kt b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/Util.kt
index c226f397..d5d28810 100644
--- a/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/Util.kt
+++ b/kotlinpoet/src/commonMain/kotlin/com/squareup/kotlinpoet/Util.kt
@@ -138,7 +138,9 @@ internal fun stringLiteralWithQuotes(
   }
 }
 
-internal fun CodeBlock.ensureEndsWithNewLine() = if (isEmpty()) {
+internal fun CodeBlock.ensureEndsWithNewLine() = trimTrailingNewLine('\n')
+
+internal fun CodeBlock.trimTrailingNewLine(replaceWith: Char? = null) = if (isEmpty()) {
   this
 } else {
   with(toBuilder()) {
@@ -146,11 +148,18 @@ internal fun CodeBlock.ensureEndsWithNewLine() = if (isEmpty()) {
     if (lastFormatPart.isPlaceholder && args.isNotEmpty()) {
       val lastArg = args.last()
       if (lastArg is String) {
-        args[args.size - 1] = lastArg.trimEnd('\n') + '\n'
+        val trimmedArg = lastArg.trimEnd('\n')
+        args[args.size - 1] = if (replaceWith != null) {
+          trimmedArg + replaceWith
+        } else {
+          trimmedArg
+        }
       }
     } else {
       formatParts[formatParts.lastIndexOf(lastFormatPart)] = lastFormatPart.trimEnd('\n')
-      formatParts += "\n"
+      if (replaceWith != null) {
+        formatParts += "$replaceWith"
+      }
     }
     return@with build()
   }
@@ -285,6 +294,50 @@ internal fun String.escapeIfNecessary(validate: Boolean = true): String = escape
   .escapeIfAllCharactersAreUnderscore()
   .apply { if (validate) failIfEscapeInvalid() }
 
+/**
+ * Because of [KT-18706](https://youtrack.jetbrains.com/issue/KT-18706)
+ * bug all aliases escaped with backticks are not resolved.
+ *
+ * So this method is used instead, which uses custom escape rules:
+ * - if all characters are underscores, add `'0'` to the end
+ * - if it's a keyword, prepend it with double underscore `"__"`
+ * - if first character cannot be used as identifier start (e.g. a number), underscore is prepended
+ * - all `'$'` replaced with double underscore `"__"`
+ * - all characters that cannot be used as identifier part (e.g. space or hyphen) are
+ *   replaced with `"_U<code>"` where `code` is 4-digit Unicode character code in hexadecimal form
+ */
+internal fun String.escapeAsAlias(validate: Boolean = true): String {
+  if (allCharactersAreUnderscore) {
+    return "${this}0" // add '0' to make it a valid identifier
+  }
+
+  if (isKeyword) {
+    return "__$this"
+  }
+
+  val newAlias = StringBuilder("")
+
+  if (!Character.isJavaIdentifierStart(first())) {
+    newAlias.append('_')
+  }
+
+  for (ch in this) {
+    if (ch == ALLOWED_CHARACTER) {
+      newAlias.append("__") // all $ replaced with __
+      continue
+    }
+
+    if (!Character.isJavaIdentifierPart(ch)) {
+      newAlias.append("_U").append(Integer.toHexString(ch.code).padStart(4, '0'))
+      continue
+    }
+
+    newAlias.append(ch)
+  }
+
+  return newAlias.toString().apply { if (validate) failIfEscapeInvalid() }
+}
+
 private fun String.alreadyEscaped() = startsWith("`") && endsWith("`")
 
 private fun String.escapeIfKeyword() = if (isKeyword && !alreadyEscaped()) "`$this`" else this
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/CodeBlockTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/CodeBlockTest.kt
index be4e62dd..5d1a3df4 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/CodeBlockTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/CodeBlockTest.kt
@@ -37,6 +37,43 @@ class CodeBlockTest {
     assertThat(a.toString()).isEqualTo("delicious taco")
   }
 
+  @Test fun doublePrecision() {
+    val doubles = listOf(
+      12345678900000.0 to "12_345_678_900_000.0",
+      12345678900000.07 to "12_345_678_900_000.07",
+      123456.0 to "123_456.0",
+      1234.5678 to "1_234.5678",
+      12.345678 to "12.345678",
+      0.12345678 to "0.12345678",
+      0.0001 to "0.0001",
+      0.00001 to "0.00001",
+      0.000001 to "0.000001",
+      0.0000001 to "0.0000001",
+    )
+    for ((d, expected) in doubles) {
+      val a = CodeBlock.of("number %L", d)
+      assertThat(a.toString()).isEqualTo("number $expected")
+    }
+  }
+
+  @Test fun floatPrecision() {
+    val floats = listOf(
+      12345678.0f to "12_345_678.0",
+      123456.0f to "123_456.0",
+      1234.567f to "1_234.567",
+      12.34567f to "12.34567",
+      0.1234567f to "0.1234567",
+      0.0001f to "0.0001",
+      0.00001f to "0.00001",
+      0.000001f to "0.000001",
+      0.0000001f to "0.0000001",
+    )
+    for ((f, expected) in floats) {
+      val a = CodeBlock.of("number %L", f)
+      assertThat(a.toString()).isEqualTo("number $expected")
+    }
+  }
+
   @Test fun percentEscapeCannotBeIndexed() {
     assertThrows<IllegalArgumentException> {
       CodeBlock.builder().add("%1%", "taco").build()
@@ -452,6 +489,12 @@ class CodeBlockTest {
       .isEqualTo(CodeBlock.of("(%L, %L, %L)", "taco1", "taco2", "taco3"))
   }
 
+  @Test fun joinToCodeTransform() {
+    val blocks = listOf("taco1", "taco2", "taco3")
+    assertThat(blocks.joinToCode { CodeBlock.of("%S", it) })
+      .isEqualTo(CodeBlock.of("%S, %S, %S", "taco1", "taco2", "taco3"))
+  }
+
   @Test fun beginControlFlowWithParams() {
     val controlFlow = CodeBlock.builder()
       .beginControlFlow("list.forEach { element ->")
@@ -547,12 +590,12 @@ class CodeBlockTest {
     )
   }
 
-  @Test fun `%N escapes keywords`() {
+  @Test fun `N escapes keywords`() {
     val funSpec = FunSpec.builder("object").build()
     assertThat(CodeBlock.of("%N", funSpec).toString()).isEqualTo("`object`")
   }
 
-  @Test fun `%N escapes spaces`() {
+  @Test fun `N escapes spaces`() {
     val funSpec = FunSpec.builder("create taco").build()
     assertThat(CodeBlock.of("%N", funSpec).toString()).isEqualTo("`create taco`")
   }
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FileSpecTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FileSpecTest.kt
index a855cddc..7eb0f01c 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FileSpecTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FileSpecTest.kt
@@ -373,6 +373,42 @@ class FileSpecTest {
     )
   }
 
+  @Test fun conflictingImportsEscapedWithoutBackticks() {
+    val foo1Type = ClassName("com.example.generated.one", "\$Foo")
+    val foo2Type = ClassName("com.example.generated.another", "\$Foo")
+
+    val testFun = FunSpec.builder("testFun")
+      .addCode(
+        """
+        val foo1 = %T()
+        val foo2 = %T()
+        """.trimIndent(),
+        foo1Type,
+        foo2Type,
+      )
+      .build()
+
+    val testFile = FileSpec.builder("com.squareup.kotlinpoet.test", "TestFile")
+      .addFunction(testFun)
+      .build()
+
+    assertThat(testFile.toString())
+      .isEqualTo(
+        """
+          |package com.squareup.kotlinpoet.test
+          |
+          |import com.example.generated.another.`${'$'}Foo` as Another__Foo
+          |import com.example.generated.one.`${'$'}Foo` as One__Foo
+          |
+          |public fun testFun() {
+          |  val foo1 = One__Foo()
+          |  val foo2 = Another__Foo()
+          |}
+          |
+        """.trimMargin(),
+      )
+  }
+
   @Test fun conflictingImportsEscapeKeywords() {
     val source = FileSpec.builder("com.squareup.tacos", "Taco")
       .addType(
@@ -531,6 +567,54 @@ class FileSpecTest {
     )
   }
 
+  @Test fun aliasedImportClass() {
+    val packageName = "com.mypackage"
+    val className = ClassName(packageName, "Class")
+    val source = FileSpec.builder(packageName, "K")
+      .addAliasedImport(className, "C")
+      .addFunction(
+        FunSpec.builder("main")
+          .returns(className)
+          .addCode("return %T()", className)
+          .build(),
+      )
+      .build()
+    assertThat(source.toString()).isEqualTo(
+      """
+      |package com.mypackage
+      |
+      |import com.mypackage.Class as C
+      |
+      |public fun main(): C = C()
+      |
+      """.trimMargin(),
+    )
+  }
+
+  @Test fun aliasedImportWithNestedClass() {
+    val packageName = "com.mypackage"
+    val className = ClassName(packageName, "Outer").nestedClass("Inner")
+    val source = FileSpec.builder(packageName, "K")
+      .addAliasedImport(className, "INNER")
+      .addFunction(
+        FunSpec.builder("main")
+          .returns(className)
+          .addCode("return %T()", className)
+          .build(),
+      )
+      .build()
+    assertThat(source.toString()).isEqualTo(
+      """
+      |package com.mypackage
+      |
+      |import com.mypackage.Outer.Inner as INNER
+      |
+      |public fun main(): INNER = INNER()
+      |
+      """.trimMargin(),
+    )
+  }
+
   @Test fun conflictingParentName() {
     val source = FileSpec.builder("com.squareup.tacos", "A")
       .addType(
@@ -1126,6 +1210,7 @@ class FileSpecTest {
   class OhNoThisDoesNotCompile
 
   @Test fun longCommentWithTypes() {
+    @Suppress("REDUNDANT_PROJECTION")
     val someLongParameterizedTypeName = typeNameOf<List<Map<in String, Collection<Map<WackyKey, out OhNoThisDoesNotCompile>>>>>()
     val param = ParameterSpec.builder("foo", someLongParameterizedTypeName).build()
     val someLongLambdaTypeName = LambdaTypeName.get(STRING, listOf(param), STRING).copy(suspending = true)
@@ -1187,7 +1272,7 @@ class FileSpecTest {
       |
       |println("hello!")
       |
-      |public fun localFun() {
+      |fun localFun() {
       |}
       |
       |public class Yay
@@ -1242,4 +1327,35 @@ class FileSpecTest {
     assertThat(spec.packageName).isEqualTo(memberName.packageName)
     assertThat(spec.name).isEqualTo(memberName.simpleName)
   }
+
+  @Test fun topLevelPropertyWithControlFlow() {
+    val spec = FileSpec.builder("com.example.foo", "Test")
+      .addProperty(
+        PropertySpec.builder("MyProperty", String::class.java)
+          .initializer(
+            CodeBlock.builder()
+              .beginControlFlow("if (1 + 1 == 2)")
+              .addStatement("Expected")
+              .nextControlFlow("else")
+              .addStatement("Unexpected")
+              .endControlFlow()
+              .build(),
+          ).build(),
+      ).build()
+
+    assertThat(spec.toString()).isEqualTo(
+      """
+      |package com.example.foo
+      |
+      |import java.lang.String
+      |
+      |public val MyProperty: String = if (1 + 1 == 2) {
+      |  Expected
+      |} else {
+      |  Unexpected
+      |}
+      |
+      """.trimMargin(),
+    )
+  }
 }
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FunSpecTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FunSpecTest.kt
index 4fff9fe3..13fb0867 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FunSpecTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/FunSpecTest.kt
@@ -84,7 +84,9 @@ class FunSpecTest {
     }
 
     companion object {
-      @JvmStatic open fun staticMethod() {
+      @Suppress("NON_FINAL_MEMBER_IN_OBJECT")
+      @JvmStatic
+      open fun staticMethod() {
       }
     }
   }
@@ -121,6 +123,8 @@ class FunSpecTest {
     val classType = classElement.asType() as DeclaredType
     val methods = methodsIn(elements.getAllMembers(classElement))
     var exec = findFirst(methods, "call")
+
+    @Suppress("DEPRECATION")
     var funSpec = FunSpec.overriding(exec, classType, types).build()
     assertThat(funSpec.toString()).isEqualTo(
       """
@@ -131,6 +135,7 @@ class FunSpecTest {
       """.trimMargin(),
     )
     exec = findFirst(methods, "compareTo")
+    @Suppress("DEPRECATION")
     funSpec = FunSpec.overriding(exec, classType, types).build()
     assertThat(funSpec.toString()).isEqualTo(
       """
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/KotlinPoetTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/KotlinPoetTest.kt
index 642b65c5..65ebff43 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/KotlinPoetTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/KotlinPoetTest.kt
@@ -1383,6 +1383,60 @@ class KotlinPoetTest {
     )
   }
 
+  @Test fun extensionFunctionIsImportedEvenIfTheSameIsUsedAlsoFromTheCurrentPackage() {
+    val kotlinIsNullOrEmpty = MemberName(packageName = "kotlin.text", simpleName = "isNullOrEmpty", isExtension = true)
+    val samePackageIsNullOrEmpty = MemberName(packageName = "com.example", simpleName = "isNullOrEmpty", isExtension = true)
+    val file = FileSpec.builder("com.example", "Test")
+      .addFunction(
+        FunSpec.builder("main")
+          .addStatement("val isFirstNull = null.%M()", kotlinIsNullOrEmpty)
+          .addStatement("val isSecondNull = null.%M()", samePackageIsNullOrEmpty)
+          .build(),
+      )
+      .build()
+    assertThat(file.toString()).isEqualTo(
+      """
+      |package com.example
+      |
+      |import kotlin.text.isNullOrEmpty as textIsNullOrEmpty
+      |
+      |public fun main() {
+      |  val isFirstNull = null.textIsNullOrEmpty()
+      |  val isSecondNull = null.isNullOrEmpty()
+      |}
+      |
+      """.trimMargin(),
+    )
+  }
+
+  // not a good idea to do that, but still valid syntax
+  @Test fun extensionFunctionIsImportedEvenIfTheSameTypeIsAlreadyImported() {
+    val subpkgIsNullOrEmpty = ClassName(packageName = "com.example.subpkg", simpleNames = listOf("isNullOrEmpty"))
+    val kotlinIsNullOrEmpty = MemberName(packageName = "kotlin.text", simpleName = "isNullOrEmpty", isExtension = true)
+    val file = FileSpec.builder("com.example", "Test")
+      .addFunction(
+        FunSpec.builder("main")
+          .addStatement("val instance = %T()", subpkgIsNullOrEmpty)
+          .addStatement("val extensionFunctionResult = null.%M()", kotlinIsNullOrEmpty)
+          .build(),
+      )
+      .build()
+    assertThat(file.toString()).isEqualTo(
+      """
+      |package com.example
+      |
+      |import com.example.subpkg.isNullOrEmpty
+      |import kotlin.text.isNullOrEmpty
+      |
+      |public fun main() {
+      |  val instance = isNullOrEmpty()
+      |  val extensionFunctionResult = null.isNullOrEmpty()
+      |}
+      |
+      """.trimMargin(),
+    )
+  }
+
   // https://github.com/square/kotlinpoet/issues/1563
   @Test fun nestedClassesWithConflictingAutoGeneratedImports() {
     val source = FileSpec.builder("com.squareup.tacos", "Taco")
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/MemberNameTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/MemberNameTest.kt
index 69271d7d..04eaa536 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/MemberNameTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/MemberNameTest.kt
@@ -322,6 +322,51 @@ class MemberNameTest {
     )
   }
 
+  @Test fun importedMemberClassFunctionNameDontClashForParameterValue() {
+    val tacoName = ClassName("com.squareup.tacos", "Taco")
+    val meatMember = ClassName("com.squareup", "Fridge").member("meat")
+    val buildFun = FunSpec.builder("build")
+      .returns(tacoName)
+      .addStatement("return %T(%M { })", tacoName, meatMember)
+      .build()
+    val spec = FileSpec.builder(tacoName)
+      .addType(
+        TypeSpec.classBuilder("DeliciousTaco")
+          .addFunction(buildFun)
+          .addFunction(FunSpec.builder("deliciousMeat").build())
+          .build(),
+      )
+      .addType(
+        TypeSpec.classBuilder("TastelessTaco")
+          .addFunction(buildFun)
+          .addFunction(FunSpec.builder("meat").build())
+          .build(),
+      )
+      .build()
+    assertThat(spec.toString()).isEqualTo(
+      """
+      |package com.squareup.tacos
+      |
+      |import com.squareup.Fridge.meat
+      |
+      |public class DeliciousTaco {
+      |  public fun build(): Taco = Taco(meat { })
+      |
+      |  public fun deliciousMeat() {
+      |  }
+      |}
+      |
+      |public class TastelessTaco {
+      |  public fun build(): Taco = Taco(com.squareup.Fridge.meat { })
+      |
+      |  public fun meat() {
+      |  }
+      |}
+      |
+      """.trimMargin(),
+    )
+  }
+
   @Test fun memberNameAliases() {
     val createSquareTaco = MemberName("com.squareup.tacos", "createTaco")
     val createTwitterTaco = MemberName("com.twitter.tacos", "createTaco")
@@ -478,7 +523,7 @@ class MemberNameTest {
       .isEqualTo(MemberName(ClassName("kotlin.text", "Regex"), "fromLiteral"))
   }
 
-  @Test fun `%N escapes MemberNames`() {
+  @Test fun `N escapes MemberNames`() {
     val taco = ClassName("com.squareup.tacos", "Taco")
     val packager = ClassName("com.squareup.tacos", "TacoPackager")
     val file = FileSpec.builder("com.example", "Test")
@@ -542,6 +587,29 @@ class MemberNameTest {
     )
   }
 
+  @Test fun importMemberWithoutPackage() {
+    val createTaco = MemberName("", "createTaco")
+    val file = FileSpec.builder("com.example", "Test")
+      .addFunction(
+        FunSpec.builder("makeTacoHealthy")
+          .addStatement("val taco = %M()", createTaco)
+          .build(),
+      )
+      .build()
+    assertThat(file.toString()).isEqualTo(
+      """
+      |package com.example
+      |
+      |import createTaco
+      |
+      |public fun makeTacoHealthy() {
+      |  val taco = createTaco()
+      |}
+      |
+      """.trimMargin(),
+    )
+  }
+
   // https://github.com/square/kotlinpoet/issues/1089
   @Test fun `extension MemberName imported if name clash`() {
     val hashCode = MemberName("kotlin", "hashCode", isExtension = true)
@@ -589,4 +657,29 @@ class MemberNameTest {
       """.trimIndent(),
     )
   }
+
+  // https://github.com/square/kotlinpoet/issues/1907
+  @Test fun `extension and non-extension MemberName clash`() {
+    val file = FileSpec.builder("com.squareup.tacos", "Tacos")
+      .addFunction(
+        FunSpec.builder("main")
+          .addStatement("println(%M(Taco()))", MemberName("com.squareup.wrappers", "wrap"))
+          .addStatement("println(Taco().%M())", MemberName("com.squareup.wrappers", "wrap", isExtension = true))
+          .build(),
+      )
+      .build()
+    assertThat(file.toString()).isEqualTo(
+      """
+      package com.squareup.tacos
+
+      import com.squareup.wrappers.wrap
+
+      public fun main() {
+        println(wrap(Taco()))
+        println(Taco().wrap())
+      }
+
+      """.trimIndent(),
+    )
+  }
 }
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/PropertySpecTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/PropertySpecTest.kt
index af373c25..1ca654db 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/PropertySpecTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/PropertySpecTest.kt
@@ -500,7 +500,6 @@ class PropertySpecTest {
       |  println("arg=${'$'}arg")
       |}
       |
-      |
       """.trimMargin(),
     )
   }
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeSpecTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeSpecTest.kt
index 94732b61..85c0c3b5 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeSpecTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeSpecTest.kt
@@ -596,6 +596,47 @@ class TypeSpecTest {
     )
   }
 
+  @Test fun enumWithPrimaryConstructorAndMultipleInterfaces() {
+    val roshambo = TypeSpec.enumBuilder("Roshambo")
+      .addSuperinterface(Runnable::class)
+      .addSuperinterface(Cloneable::class)
+      .addEnumConstant(
+        "SCISSORS",
+        TypeSpec.anonymousClassBuilder()
+          .addSuperclassConstructorParameter("%S", "peace sign")
+          .build(),
+      )
+      .addProperty(
+        PropertySpec.builder("handPosition", String::class, KModifier.PRIVATE)
+          .initializer("handPosition")
+          .build(),
+      )
+      .primaryConstructor(
+        FunSpec.constructorBuilder()
+          .addParameter("handPosition", String::class)
+          .build(),
+      )
+      .build()
+    assertThat(toString(roshambo)).isEqualTo(
+      """
+        |package com.squareup.tacos
+        |
+        |import java.lang.Runnable
+        |import kotlin.Cloneable
+        |import kotlin.String
+        |
+        |public enum class Roshambo(
+        |  private val handPosition: String,
+        |) : Runnable,
+        |    Cloneable {
+        |  SCISSORS("peace sign"),
+        |  ;
+        |}
+        |
+      """.trimMargin(),
+    )
+  }
+
   /** https://github.com/square/javapoet/issues/193  */
   @Test fun enumsMayDefineAbstractFunctions() {
     val roshambo = TypeSpec.enumBuilder("Tortilla")
@@ -1061,6 +1102,63 @@ class TypeSpecTest {
     )
   }
 
+  @Test fun classImplementsExtendsPrimaryConstructorNoParams() {
+    val taco = ClassName(tacosPackage, "Taco")
+    val food = ClassName("com.squareup.tacos", "Food")
+    val typeSpec = TypeSpec.classBuilder("Taco")
+      .addModifiers(ABSTRACT)
+      .superclass(AbstractSet::class.asClassName().parameterizedBy(food))
+      .addSuperinterface(Serializable::class)
+      .addSuperinterface(Comparable::class.asClassName().parameterizedBy(taco))
+      .primaryConstructor(FunSpec.constructorBuilder().build())
+      .build()
+    assertThat(toString(typeSpec)).isEqualTo(
+      """
+        |package com.squareup.tacos
+        |
+        |import java.io.Serializable
+        |import java.util.AbstractSet
+        |import kotlin.Comparable
+        |
+        |public abstract class Taco() : AbstractSet<Food>(), Serializable, Comparable<Taco>
+        |
+      """.trimMargin(),
+    )
+  }
+
+  @Test fun classImplementsExtendsPrimaryConstructorWithParams() {
+    val taco = ClassName(tacosPackage, "Taco")
+    val food = ClassName("com.squareup.tacos", "Food")
+    val typeSpec = TypeSpec.classBuilder("Taco")
+      .addModifiers(ABSTRACT)
+      .superclass(AbstractSet::class.asClassName().parameterizedBy(food))
+      .addSuperinterface(Serializable::class)
+      .addSuperinterface(Comparable::class.asClassName().parameterizedBy(taco))
+      .primaryConstructor(
+        FunSpec.constructorBuilder()
+          .addParameter("name", String::class)
+          .build(),
+      )
+      .build()
+    assertThat(toString(typeSpec)).isEqualTo(
+      """
+        |package com.squareup.tacos
+        |
+        |import java.io.Serializable
+        |import java.util.AbstractSet
+        |import kotlin.Comparable
+        |import kotlin.String
+        |
+        |public abstract class Taco(
+        |  name: String,
+        |) : AbstractSet<Food>(),
+        |    Serializable,
+        |    Comparable<Taco>
+        |
+      """.trimMargin(),
+    )
+  }
+
   @Test fun classImplementsExtendsSameName() {
     val javapoetTaco = ClassName(tacosPackage, "Taco")
     val tacoBellTaco = ClassName("com.taco.bell", "Taco")
@@ -2638,7 +2736,7 @@ class TypeSpecTest {
         |      |beef
         |      |lettuce
         |      |cheese
-        |      |${"\"\"\""}.trimMargin()
+        |      ${"\"\"\""}.trimMargin()
         |}
         |
       """.trimMargin(),
@@ -5662,6 +5760,24 @@ class TypeSpecTest {
     )
   }
 
+  // https://github.com/square/kotlinpoet/issues/1818
+  @Test fun primaryConstructorCanNotDelegate() {
+    assertThrows<IllegalArgumentException> {
+      TypeSpec.classBuilder("Child")
+        .superclass(ClassName("com.squareup", "Parent"))
+        .primaryConstructor(
+          FunSpec.constructorBuilder()
+            .callSuperConstructor(CodeBlock.of("%L", "param"))
+            .addParameter(
+              name = "param",
+              type = ClassName("com.squareup", "Param"),
+            )
+            .build(),
+        )
+        .build()
+    }.hasMessageThat().isEqualTo("primary constructor can't delegate to other constructors")
+  }
+
   companion object {
     private const val donutsPackage = "com.squareup.donuts"
   }
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeVariableNameTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeVariableNameTest.kt
index 628b569e..ff6c8658 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeVariableNameTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/TypeVariableNameTest.kt
@@ -209,7 +209,7 @@ class TypeVariableNameTest {
   }
 
   @Test fun emptyBoundsShouldDefaultToAnyNullable() {
-    val typeVariable = TypeVariableName("E", bounds = *emptyArray<TypeName>())
+    val typeVariable = TypeVariableName("E", bounds = emptyArray<TypeName>())
     val typeSpec = TypeSpec.classBuilder("Taco")
       .addTypeVariable(typeVariable)
       .build()
diff --git a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/UtilTest.kt b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/UtilTest.kt
index f8bfc0b9..1f12d731 100644
--- a/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/UtilTest.kt
+++ b/kotlinpoet/src/commonTest/kotlin/com/squareup/kotlinpoet/UtilTest.kt
@@ -143,6 +143,52 @@ class UtilTest {
     assertThat("`A`".escapeIfNecessary()).isEqualTo("`A`")
   }
 
+  @Test
+  fun `escapeAsAlias all underscores`() {
+    val input = "____"
+    val expected = "____0"
+    assertThat(input.escapeAsAlias()).isEqualTo(expected)
+  }
+
+  @Test
+  fun `escapeAsAlias keyword`() {
+    val input = "if"
+    val expected = "__if"
+    assertThat(input.escapeAsAlias()).isEqualTo(expected)
+  }
+
+  @Test
+  fun `escapeAsAlias first character cannot be used as identifier start`() {
+    val input = "1abc"
+    val expected = "_1abc"
+    assertThat(input.escapeAsAlias()).isEqualTo(expected)
+  }
+
+  @Test
+  fun `escapeAsAlias dollar sign`() {
+    val input = "\$\$abc"
+    val expected = "____abc"
+    assertThat(input.escapeAsAlias()).isEqualTo(expected)
+  }
+
+  @Test
+  fun `escapeAsAlias characters that cannot be used as identifier part`() {
+    val input = "a b-c"
+    val expected = "a_U0020b_U002dc"
+    assertThat(input.escapeAsAlias()).isEqualTo(expected)
+  }
+
+  @Test
+  fun `escapeAsAlias double escape does nothing`() {
+    val input = "1SampleClass_\$Generated "
+    val expected = "_1SampleClass___Generated_U0020"
+
+    assertThat(input.escapeAsAlias())
+      .isEqualTo(expected)
+    assertThat(input.escapeAsAlias().escapeAsAlias())
+      .isEqualTo(expected)
+  }
+
   private fun stringLiteral(string: String) = stringLiteral(string, string)
 
   private fun stringLiteral(expected: String, value: String) =
diff --git a/mkdocs.yml b/mkdocs.yml
index abd937be..3cbfdc1c 100644
--- a/mkdocs.yml
+++ b/mkdocs.yml
@@ -77,7 +77,7 @@ nav:
     - 'Callable References': callable-references.md
     - 'kotlin-reflect': kotlin-reflect.md
   - 'Interop - JavaPoet': interop-javapoet.md
-  - 'Interop - kotlinx-metadata': interop-kotlinx-metadata.md
+  - 'Interop - kotlin-metadata': interop-kotlin-metadata.md
   - 'Interop - KSP': interop-ksp.md
   - 'API':
     - 'kotlinpoet': 1.x/kotlinpoet/index.html
diff --git a/renovate.json b/renovate.json
index d77f3a63..b4519819 100644
--- a/renovate.json
+++ b/renovate.json
@@ -15,6 +15,13 @@
         "^com\\.google\\.devtools\\.ksp:(?:[\\w-]+)$"
       ],
       "groupName": "Kotlin and KSP"
+    },
+    {
+      "matchManagers": ["pip_requirements"],
+      "matchPackagePrefixes": [
+        "mkdocs"
+      ],
+      "groupName": "MkDocs"
     }
   ]
 }
diff --git a/settings.gradle.kts b/settings.gradle.kts
index c9b262e9..47bc1df4 100644
--- a/settings.gradle.kts
+++ b/settings.gradle.kts
@@ -27,7 +27,7 @@ plugins {
 include(
   ":kotlinpoet",
   ":interop:javapoet",
-  ":interop:kotlinx-metadata",
+  ":interop:kotlin-metadata",
   ":interop:ksp",
   ":interop:ksp:test-processor",
 )
```

