```diff
diff --git a/.github/workflows/MergeToMainWorkflow.yaml b/.github/workflows/MergeToMainWorkflow.yaml
index ad4954e..9aa6590 100644
--- a/.github/workflows/MergeToMainWorkflow.yaml
+++ b/.github/workflows/MergeToMainWorkflow.yaml
@@ -16,30 +16,30 @@ env:
 jobs:
   build:
     name: Build
-    runs-on: ubuntu-latest
+    runs-on: ${{ vars.RUNNER }}
     timeout-minutes: 120
     steps:
       - name: Checkout
-        uses: actions/checkout@v3
+        uses: actions/checkout@v4
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v1
+        uses: gradle/actions/wrapper-validation@v3
 
       - name: Set up JDK
-        uses: actions/setup-java@v3
+        uses: actions/setup-java@v4
         with:
           distribution: ${{ env.DISTRIBUTION }}
           java-version: ${{ env.JDK_VERSION }}
           cache: gradle
 
       - name: Setup Gradle
-        uses: gradle/gradle-build-action@v2
+        uses: gradle/actions/setup-gradle@v3
 
       - name: Build all build type and flavor permutations
         run: ./gradlew assemble --parallel --build-cache
 
       - name: Upload build outputs (APKs)
-        uses: actions/upload-artifact@v3
+        uses: actions/upload-artifact@v4
         with:
           name: build-outputs
           path: app/build/outputs
@@ -47,7 +47,7 @@ jobs:
       - name: Upload build reports
         if: always()
         continue-on-error: true
-        uses: actions/upload-artifact@v3
+        uses: actions/upload-artifact@v4
         with:
           name: build-reports
           path: "*/build/reports"
diff --git a/.github/workflows/PullRequestWorkflow.yaml b/.github/workflows/PullRequestWorkflow.yaml
index 20e1582..ed83887 100644
--- a/.github/workflows/PullRequestWorkflow.yaml
+++ b/.github/workflows/PullRequestWorkflow.yaml
@@ -13,14 +13,14 @@ env:
 jobs:
   build:
     name: Build
-    runs-on: ubuntu-latest
+    runs-on: ${{ vars.RUNNER }}
     timeout-minutes: 120
     steps:
       - name: Checkout
         uses: actions/checkout@v4
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v2
+        uses: gradle/actions/wrapper-validation@v3
 
       - name: Set up JDK
         uses: actions/setup-java@v4
@@ -30,10 +30,10 @@ jobs:
           cache: gradle
 
       - name: Setup Gradle
-        uses: gradle/gradle-build-action@v3
+        uses: gradle/actions/setup-gradle@v3
 
-      - name: Build all build type and flavor permutations
-        run: ./gradlew assemble --parallel --build-cache
+      - name: Build stable debug gradle target
+        run: ./gradlew assembleStableDebug --parallel --build-cache
 
       - name: Upload build outputs (APKs)
         uses: actions/upload-artifact@v4
@@ -51,14 +51,14 @@ jobs:
 
   test:
     name: Unit Tests
-    runs-on: ubuntu-latest
+    runs-on: ${{ vars.RUNNER }}
     timeout-minutes: 120
     steps:
       - name: Checkout
         uses: actions/checkout@v4
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v2
+        uses: gradle/actions/wrapper-validation@v3
 
       - name: Set up JDK
         uses: actions/setup-java@v4
@@ -68,7 +68,7 @@ jobs:
           cache: gradle
 
       - name: Setup Gradle
-        uses: gradle/gradle-build-action@v3
+        uses: gradle/actions/setup-gradle@v3
         continue-on-error: true
 
       - name: Run local tests
@@ -83,7 +83,7 @@ jobs:
 
   android-test:
     name: Instrumentation Tests (${{ matrix.device.name }})
-    runs-on: ubuntu-latest
+    runs-on: ${{ vars.RUNNER }}
     timeout-minutes: 30
     strategy:
       fail-fast: false
@@ -117,9 +117,9 @@ jobs:
         run: yes | "$ANDROID_HOME"/cmdline-tools/latest/bin/sdkmanager --licenses || true
 
       - name: Run instrumentation tests
-        uses: gradle/gradle-build-action@v3
+        uses: gradle/actions/setup-gradle@v3
         with:
-          arguments: ${{ matrix.device.name }}DebugAndroidTest
+          arguments: ${{ matrix.device.name }}StableDebugAndroidTest
 
       - name: Upload instrumentation test reports and logs on failure
         if: failure()
@@ -132,7 +132,7 @@ jobs:
 
   spotless:
     name: Spotless Check
-    runs-on: ubuntu-latest
+    runs-on: ${{ vars.RUNNER }}
     timeout-minutes: 60
     steps:
       - name: Checkout
@@ -141,7 +141,7 @@ jobs:
           fetch-depth: 0
 
       - name: Validate Gradle Wrapper
-        uses: gradle/wrapper-validation-action@v2
+        uses: gradle/actions/wrapper-validation@v3
 
       - name: Set up JDK
         uses: actions/setup-java@v4
@@ -151,7 +151,7 @@ jobs:
           cache: gradle
 
       - name: Setup Gradle
-        uses: gradle/gradle-build-action@v3
+        uses: gradle/actions/setup-gradle@v3
 
       - name: Spotless Check
         run: ./gradlew spotlessCheck --init-script gradle/init.gradle.kts --parallel --build-cache
diff --git a/.gitignore b/.gitignore
index 8b3881d..7b74e6c 100644
--- a/.gitignore
+++ b/.gitignore
@@ -15,3 +15,5 @@
 local.properties
 .idea/deploymentTargetDropDown.xml
 .idea/gradle.xml
+.idea/deploymentTargetSelector.xml
+.idea/androidTestResultsUserPreferences.xml
\ No newline at end of file
diff --git a/.idea/androidTestResultsUserPreferences.xml b/.idea/androidTestResultsUserPreferences.xml
index 24b6073..c64c910 100644
--- a/.idea/androidTestResultsUserPreferences.xml
+++ b/.idea/androidTestResultsUserPreferences.xml
@@ -3,65 +3,14 @@
   <component name="AndroidTestResultsUserPreferences">
     <option name="androidTestResultsTableState">
       <map>
-        <entry key="-1168588695">
+        <entry key="811462001">
           <value>
             <AndroidTestResultsTableState>
               <option name="preferredColumnWidths">
                 <map>
                   <entry key="Duration" value="90" />
                   <entry key="Pixel_7_Pro_API_34" value="120" />
-                  <entry key="Tests" value="360" />
-                </map>
-              </option>
-            </AndroidTestResultsTableState>
-          </value>
-        </entry>
-        <entry key="401594821">
-          <value>
-            <AndroidTestResultsTableState>
-              <option name="preferredColumnWidths">
-                <map>
-                  <entry key="Duration" value="90" />
-                  <entry key="Pixel_6_Pro_API_30" value="120" />
-                  <entry key="Tests" value="360" />
-                </map>
-              </option>
-            </AndroidTestResultsTableState>
-          </value>
-        </entry>
-        <entry key="571770275">
-          <value>
-            <AndroidTestResultsTableState>
-              <option name="preferredColumnWidths">
-                <map>
-                  <entry key="Duration" value="90" />
-                  <entry key="Pixel_7_Pro_API_34" value="120" />
-                  <entry key="Tests" value="360" />
-                </map>
-              </option>
-            </AndroidTestResultsTableState>
-          </value>
-        </entry>
-        <entry key="632950842">
-          <value>
-            <AndroidTestResultsTableState>
-              <option name="preferredColumnWidths">
-                <map>
-                  <entry key="Duration" value="90" />
-                  <entry key="Tests" value="360" />
-                  <entry key="samsung SM-G990U1" value="120" />
-                </map>
-              </option>
-            </AndroidTestResultsTableState>
-          </value>
-        </entry>
-        <entry key="2043991187">
-          <value>
-            <AndroidTestResultsTableState>
-              <option name="preferredColumnWidths">
-                <map>
-                  <entry key="Duration" value="90" />
-                  <entry key="Pixel_6_Pro_API_30" value="120" />
+                  <entry key="Pixel_C_API_34" value="120" />
                   <entry key="Tests" value="360" />
                 </map>
               </option>
diff --git a/.idea/gradle.xml b/.idea/gradle.xml
index 37f7544..ce85930 100644
--- a/.idea/gradle.xml
+++ b/.idea/gradle.xml
@@ -4,25 +4,21 @@
   <component name="GradleSettings">
     <option name="linkedExternalProjectsSettings">
       <GradleProjectSettings>
-        <option name="testRunner" value="GRADLE" />
-        <option name="distributionType" value="DEFAULT_WRAPPED" />
         <option name="externalProjectPath" value="$PROJECT_DIR$" />
-        <option name="gradleJvm" value="Android Studio default JDK" />
+        <option name="gradleJvm" value="jbr-17" />
         <option name="modules">
           <set>
             <option value="$PROJECT_DIR$" />
             <option value="$PROJECT_DIR$/app" />
             <option value="$PROJECT_DIR$/benchmark" />
-            <option value="$PROJECT_DIR$/camera-viewfinder-compose" />
             <option value="$PROJECT_DIR$/core" />
+            <option value="$PROJECT_DIR$/core/camera" />
             <option value="$PROJECT_DIR$/core/common" />
             <option value="$PROJECT_DIR$/data" />
             <option value="$PROJECT_DIR$/data/settings" />
-            <option value="$PROJECT_DIR$/domain" />
-            <option value="$PROJECT_DIR$/domain/camera" />
             <option value="$PROJECT_DIR$/feature" />
+            <option value="$PROJECT_DIR$/feature/permissions" />
             <option value="$PROJECT_DIR$/feature/preview" />
-            <option value="$PROJECT_DIR$/feature/quicksettings" />
             <option value="$PROJECT_DIR$/feature/settings" />
           </set>
         </option>
diff --git a/.idea/kotlinc.xml b/.idea/kotlinc.xml
index 2b8a50f..8d81632 100644
--- a/.idea/kotlinc.xml
+++ b/.idea/kotlinc.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <project version="4">
   <component name="KotlinJpsPluginSettings">
-    <option name="version" value="1.8.0" />
+    <option name="version" value="1.9.22" />
   </component>
 </project>
\ No newline at end of file
diff --git a/.idea/misc.xml b/.idea/misc.xml
index e67ad2b..0ff99b3 100644
--- a/.idea/misc.xml
+++ b/.idea/misc.xml
@@ -1,3 +1,4 @@
+<?xml version="1.0" encoding="UTF-8"?>
 <project version="4">
   <component name="ExternalStorageConfigurationManager" enabled="true" />
   <component name="NullableNotNullManager">
@@ -5,7 +6,7 @@
     <option name="myDefaultNotNull" value="androidx.annotation.NonNull" />
     <option name="myNullables">
       <value>
-        <list size="17">
+        <list size="18">
           <item index="0" class="java.lang.String" itemvalue="com.android.annotations.Nullable" />
           <item index="1" class="java.lang.String" itemvalue="org.jspecify.nullness.Nullable" />
           <item index="2" class="java.lang.String" itemvalue="androidx.annotation.RecentlyNullable" />
@@ -23,12 +24,13 @@
           <item index="14" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NullableDecl" />
           <item index="15" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NullableType" />
           <item index="16" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.Nullable" />
+          <item index="17" class="java.lang.String" itemvalue="jakarta.annotation.Nullable" />
         </list>
       </value>
     </option>
     <option name="myNotNulls">
       <value>
-        <list size="16">
+        <list size="17">
           <item index="0" class="java.lang.String" itemvalue="androidx.annotation.RecentlyNonNull" />
           <item index="1" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.NonNull" />
           <item index="2" class="java.lang.String" itemvalue="org.jspecify.nullness.NonNull" />
@@ -45,11 +47,12 @@
           <item index="13" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NonNullDecl" />
           <item index="14" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NonNullType" />
           <item index="15" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.NonNull" />
+          <item index="16" class="java.lang.String" itemvalue="jakarta.annotation.Nonnull" />
         </list>
       </value>
     </option>
   </component>
-  <component name="ProjectRootManager" version="2" languageLevel="JDK_17" default="true" project-jdk-name="jbr-17" project-jdk-type="JavaSDK">
+  <component name="ProjectRootManager" version="2" languageLevel="JDK_17" default="true" project-jdk-name="Android Studio default JDK" project-jdk-type="JavaSDK">
     <output url="file://$PROJECT_DIR$/build/classes" />
   </component>
   <component name="ProjectType">
diff --git a/app/build.gradle.kts b/app/build.gradle.kts
index 6f57fec..8686bda 100644
--- a/app/build.gradle.kts
+++ b/app/build.gradle.kts
@@ -23,6 +23,8 @@ plugins {
 
 android {
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
+
     namespace = "com.google.jetpackcamera"
 
     defaultConfig {
@@ -48,6 +50,20 @@ android {
             matchingFallbacks += listOf("release")
         }
     }
+
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
+    }
+
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_17
         targetCompatibility = JavaVersion.VERSION_17
@@ -90,6 +106,8 @@ android {
 }
 
 dependencies {
+    implementation(libs.androidx.tracing)
+    implementation(project(":core:common"))
     // Compose
     val composeBom = platform(libs.compose.bom)
     implementation(composeBom)
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt
index 0cf12c1..747650f 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt
@@ -34,6 +34,9 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_1_1_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.runScenarioTest
 import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt
index e33f19e..0e57a00 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt
@@ -27,6 +27,7 @@ import androidx.test.rule.GrantPermissionRule
 import androidx.test.uiautomator.UiDevice
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.TruthJUnit.assume
+import com.google.jetpackcamera.feature.preview.R
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_DROP_DOWN
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
@@ -34,6 +35,13 @@ import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.feature.preview.ui.SCREEN_FLASH_OVERLAY
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.assume
+import com.google.jetpackcamera.utils.getCurrentLensFacing
+import com.google.jetpackcamera.utils.onNodeWithContentDescription
+import com.google.jetpackcamera.utils.runScenarioTest
 import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
@@ -76,7 +84,7 @@ internal class FlashDeviceTest {
         composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
             .assertExists()
         composeTestRule.onNodeWithContentDescription(
-            com.google.jetpackcamera.feature.preview.R.string.quick_settings_flash_on_description
+            R.string.quick_settings_flash_on_description
         )
     }
 
@@ -99,7 +107,7 @@ internal class FlashDeviceTest {
             .performClick()
 
         composeTestRule.onNodeWithContentDescription(
-            com.google.jetpackcamera.feature.preview.R.string.quick_settings_flash_auto_description
+            R.string.quick_settings_flash_auto_description
         )
     }
 
@@ -111,7 +119,7 @@ internal class FlashDeviceTest {
         }
 
         composeTestRule.onNodeWithContentDescription(
-            com.google.jetpackcamera.feature.preview.R.string.quick_settings_flash_off_description
+            R.string.quick_settings_flash_off_description
         )
 
         // Navigate to quick settings
@@ -127,7 +135,7 @@ internal class FlashDeviceTest {
             .performClick()
 
         composeTestRule.onNodeWithContentDescription(
-            com.google.jetpackcamera.feature.preview.R.string.quick_settings_flash_off_description
+            R.string.quick_settings_flash_off_description
         )
     }
 
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
index e9abd40..7edae9a 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
@@ -15,30 +15,36 @@
  */
 package com.google.jetpackcamera
 
-import android.app.Instrumentation
-import android.content.ComponentName
-import android.content.Context
-import android.content.Intent
+import android.app.Activity
 import android.net.Uri
 import android.os.Environment
-import androidx.activity.result.ActivityResultRegistry
-import androidx.activity.result.contract.ActivityResultContract
-import androidx.activity.result.contract.ActivityResultContracts
-import androidx.core.app.ActivityOptionsCompat
-import androidx.test.core.app.ActivityScenario
-import androidx.test.core.app.ApplicationProvider
+import android.provider.MediaStore
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.longClick
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.performTouchInput
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.platform.app.InstrumentationRegistry
 import androidx.test.rule.GrantPermissionRule
-import androidx.test.uiautomator.By
 import androidx.test.uiautomator.UiDevice
-import androidx.test.uiautomator.Until
+import com.google.common.truth.Truth
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
-import kotlinx.coroutines.test.runTest
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.VIDEO_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.deleteFilesInDirAfterTimestamp
+import com.google.jetpackcamera.utils.doesImageFileExist
+import com.google.jetpackcamera.utils.getIntent
+import com.google.jetpackcamera.utils.getTestUri
+import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.runScenarioTestForResult
 import java.io.File
-import java.net.URLConnection
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -51,142 +57,104 @@ internal class ImageCaptureDeviceTest {
     val permissionsRule: GrantPermissionRule =
         GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
 
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
     private val instrumentation = InstrumentationRegistry.getInstrumentation()
-    private var activityScenario: ActivityScenario<MainActivity>? = null
     private val uiDevice = UiDevice.getInstance(instrumentation)
-    private val context = InstrumentationRegistry.getInstrumentation().targetContext
 
     @Test
-    fun image_capture() = runTest {
+    fun image_capture() = runScenarioTest<MainActivity> {
         val timeStamp = System.currentTimeMillis()
-        activityScenario = ActivityScenario.launch(MainActivity::class.java)
-        uiDevice.wait(
-            Until.findObject(By.res(CAPTURE_BUTTON)),
-            5000
-        )
-        uiDevice.findObject(By.res(CAPTURE_BUTTON)).click()
-        uiDevice.wait(
-            Until.findObject(By.res(IMAGE_CAPTURE_SUCCESS_TAG)),
-            5000
-        )
-        assert(deleteFilesInDirAfterTimestamp(timeStamp))
-    }
+        // Wait for the capture button to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+        }
 
-    @Test
-    fun image_capture_external() = runTest {
-        val timeStamp = System.currentTimeMillis()
-        val uri = getTestUri(timeStamp)
-        getTestRegistry {
-            activityScenario = ActivityScenario.launchActivityForResult(it)
-            uiDevice.wait(
-                Until.findObject(By.res(CAPTURE_BUTTON)),
-                5000
-            )
-            uiDevice.findObject(By.res(CAPTURE_BUTTON)).click()
-            uiDevice.wait(
-                Until.findObject(By.res(IMAGE_CAPTURE_SUCCESS_TAG)),
-                5000
-            )
-            activityScenario!!.result
-        }.register("key", TEST_CONTRACT) { result ->
-            assert(result)
-            assert(doesImageFileExist(uri))
-        }.launch(uri)
-        deleteFilesInDirAfterTimestamp(timeStamp)
+        composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+            .assertExists()
+            .performClick()
+        composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(IMAGE_CAPTURE_SUCCESS_TAG).isDisplayed()
+        }
+        Truth.assertThat(File(DIR_PATH).lastModified() > timeStamp).isTrue()
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
     @Test
-    fun image_capture_external_illegal_uri() = run {
+    fun image_capture_external() {
         val timeStamp = System.currentTimeMillis()
-        val inputUri = Uri.parse("asdfasdf")
-        getTestRegistry {
-            activityScenario = ActivityScenario.launchActivityForResult(it)
-            uiDevice.wait(
-                Until.findObject(By.res(CAPTURE_BUTTON)),
-                5000
-            )
-            uiDevice.findObject(By.res(CAPTURE_BUTTON)).click()
-            uiDevice.wait(
-                Until.findObject(By.res(IMAGE_CAPTURE_FAILURE_TAG)),
-                5000
-            )
-            uiDevice.pressBack()
-            activityScenario!!.result
-        }.register("key_illegal_uri", TEST_CONTRACT) { result ->
-            assert(!result)
-        }.launch(inputUri)
-    }
+        val uri = getTestUri(DIR_PATH, timeStamp, "jpg")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
 
-    private fun doesImageFileExist(uri: Uri): Boolean {
-        val file = File(uri.path)
-        if (file.exists()) {
-            val mimeType = URLConnection.guessContentTypeFromName(uri.path)
-            return mimeType != null && mimeType.startsWith("image")
-        }
-        return false
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+                    .assertExists()
+                    .performClick()
+            }
+        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_OK)
+        Truth.assertThat(doesImageFileExist(uri, "image")).isTrue()
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
-    private fun deleteFilesInDirAfterTimestamp(timeStamp: Long): Boolean {
-        var hasDeletedFile = false
-        for (file in File(DIR_PATH).listFiles()) {
-            if (file.lastModified() >= timeStamp) {
-                file.delete()
-                if (file.exists()) {
-                    file.getCanonicalFile().delete()
-                    if (file.exists()) {
-                        instrumentation.targetContext.applicationContext.deleteFile(file.getName())
-                    }
+    @Test
+    fun image_capture_external_illegal_uri() {
+        val uri = Uri.parse("asdfasdf")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
                 }
-                hasDeletedFile = true
+
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+                    .assertExists()
+                    .performClick()
+                composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(IMAGE_CAPTURE_FAILURE_TAG).isDisplayed()
+                }
+                uiDevice.pressBack()
             }
-        }
-        return hasDeletedFile
+        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesImageFileExist(uri, "image")).isFalse()
     }
 
-    private fun getTestRegistry(
-        launch: (Intent) -> Instrumentation.ActivityResult
-    ): ActivityResultRegistry {
-        val testRegistry = object : ActivityResultRegistry() {
-            override fun <I, O> onLaunch(
-                requestCode: Int,
-                contract: ActivityResultContract<I, O>,
-                input: I,
-                options: ActivityOptionsCompat?
+    @Test
+    fun video_capture_during_image_capture_external() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(DIR_PATH, timeStamp, "mp4")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
             ) {
-                // contract.create
-                val launchIntent = contract.createIntent(
-                    ApplicationProvider.getApplicationContext(),
-                    input
-                )
-                val result: Instrumentation.ActivityResult = launch(launchIntent)
-                dispatchResult(requestCode, result.resultCode, result.resultData)
-            }
-        }
-        return testRegistry
-    }
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
 
-    private fun getTestUri(timeStamp: Long): Uri {
-        return Uri.fromFile(
-            File(
-                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
-                "$timeStamp.jpg"
-            )
-        )
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+                    .assertExists()
+                    .performTouchInput { longClick() }
+                composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG)
+                        .isDisplayed()
+                }
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesImageFileExist(uri, "video")).isFalse()
     }
 
     companion object {
         val DIR_PATH: String =
             Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES).path
-
-        val TEST_CONTRACT = object : ActivityResultContracts.TakePicture() {
-            override fun createIntent(context: Context, uri: Uri): Intent {
-                return super.createIntent(context, uri).apply {
-                    component = ComponentName(
-                        ApplicationProvider.getApplicationContext(),
-                        MainActivity::class.java
-                    )
-                }
-            }
-        }
     }
 }
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt
index d06904d..b3e82ab 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt
@@ -30,7 +30,13 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.SETTINGS_BUTTON
+import com.google.jetpackcamera.settings.R
 import com.google.jetpackcamera.settings.ui.BACK_BUTTON
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.assume
+import com.google.jetpackcamera.utils.onNodeWithText
+import com.google.jetpackcamera.utils.runScenarioTest
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -72,7 +78,7 @@ class NavigationTest {
 
         // Assert we do not see the settings screen based on the title
         composeTestRule.onNodeWithText(
-            com.google.jetpackcamera.settings.R.string.settings_title
+            R.string.settings_title
         ).assertDoesNotExist()
     }
 
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt
index 1727db5..5d732a9 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt
@@ -32,6 +32,10 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_
 import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.PREVIEW_DISPLAY
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.assume
+import com.google.jetpackcamera.utils.getCurrentLensFacing
+import com.google.jetpackcamera.utils.runScenarioTest
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt
new file mode 100644
index 0000000..0cfbd73
--- /dev/null
+++ b/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt
@@ -0,0 +1,78 @@
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
+package com.google.jetpackcamera
+
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.longClick
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performTouchInput
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.RequiresDevice
+import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.rule.GrantPermissionRule
+import androidx.test.uiautomator.By
+import androidx.test.uiautomator.UiDevice
+import androidx.test.uiautomator.Until
+import com.google.common.truth.Truth.assertThat
+import com.google.jetpackcamera.feature.preview.ui.AMPLITUDE_HOT_TAG
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.runScenarioTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+@RequiresDevice
+class VideoAudioTest {
+    @get:Rule
+    val permissionsRule: GrantPermissionRule =
+        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
+    private val uiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
+
+    @Before
+    fun setUp() {
+        assertThat(uiDevice.isScreenOn).isTrue()
+    }
+
+    @Test
+    fun audioIncomingWhenEnabled() {
+        runScenarioTest<MainActivity> {
+            // check audio visualizer composable for muted/unmuted icon.
+            // icon will only be unmuted if audio is nonzero
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+            }
+
+            // record video
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+                .assertExists().performTouchInput { longClick(durationMillis = 5000) }
+
+            // assert hot amplitude tag visible
+            uiDevice.wait(
+                Until.findObject(By.res(AMPLITUDE_HOT_TAG)),
+                5000
+            )
+        }
+    }
+}
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
index 437f9a4..545b406 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
@@ -15,26 +15,36 @@
  */
 package com.google.jetpackcamera
 
-import android.app.Instrumentation
-import android.content.ComponentName
-import android.content.Context
-import android.content.Intent
+import android.app.Activity
 import android.net.Uri
 import android.os.Environment
-import androidx.activity.result.ActivityResultRegistry
-import androidx.activity.result.contract.ActivityResultContract
-import androidx.activity.result.contract.ActivityResultContracts
-import androidx.core.app.ActivityOptionsCompat
-import androidx.test.core.app.ActivityScenario
-import androidx.test.core.app.ApplicationProvider
+import android.provider.MediaStore
+import androidx.compose.ui.test.ComposeTimeoutException
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.performTouchInput
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.platform.app.InstrumentationRegistry
 import androidx.test.rule.GrantPermissionRule
-import androidx.test.uiautomator.By
 import androidx.test.uiautomator.UiDevice
-import androidx.test.uiautomator.Until
+import com.google.common.truth.Truth
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
-import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_FAILURE_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.VIDEO_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.VIDEO_DURATION_MILLIS
+import com.google.jetpackcamera.utils.deleteFilesInDirAfterTimestamp
+import com.google.jetpackcamera.utils.doesImageFileExist
+import com.google.jetpackcamera.utils.getIntent
+import com.google.jetpackcamera.utils.getTestUri
+import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.runScenarioTestForResult
 import java.io.File
 import org.junit.Rule
 import org.junit.Test
@@ -46,73 +56,120 @@ internal class VideoRecordingDeviceTest {
     val permissionsRule: GrantPermissionRule =
         GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
 
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
     private val instrumentation = InstrumentationRegistry.getInstrumentation()
-    private var activityScenario: ActivityScenario<MainActivity>? = null
     private val uiDevice = UiDevice.getInstance(instrumentation)
 
     @Test
-    fun video_capture_external_with_image_capture_intent() = run {
+    fun video_capture() = runScenarioTest<MainActivity> {
         val timeStamp = System.currentTimeMillis()
-        val uri = getTestUri(timeStamp)
-        getTestRegistry {
-            activityScenario = ActivityScenario.launchActivityForResult(it)
-            uiDevice.wait(
-                Until.findObject(By.res(CAPTURE_BUTTON)),
-                5000
-            )
-            uiDevice.findObject(By.res(CAPTURE_BUTTON)).longClick()
-            uiDevice.wait(
-                Until.findObject(By.res(VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG)),
-                5000
-            )
-            uiDevice.pressBack()
-            activityScenario!!.result
-        }.register("key", TEST_CONTRACT) { result ->
-            assert(!result)
-        }.launch(uri)
+        // Wait for the capture button to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+        }
+        longClickForVideoRecording()
+        composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(VIDEO_CAPTURE_SUCCESS_TAG).isDisplayed()
+        }
+        Truth.assertThat(File(DIR_PATH).lastModified() > timeStamp).isTrue()
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
-    private fun getTestRegistry(
-        launch: (Intent) -> Instrumentation.ActivityResult
-    ): ActivityResultRegistry {
-        val testRegistry = object : ActivityResultRegistry() {
-            override fun <I, O> onLaunch(
-                requestCode: Int,
-                contract: ActivityResultContract<I, O>,
-                input: I,
-                options: ActivityOptionsCompat?
+    @Test
+    fun video_capture_external_intent() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(DIR_PATH, timeStamp, "mp4")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
             ) {
-                // contract.create
-                val launchIntent = contract.createIntent(
-                    ApplicationProvider.getApplicationContext(),
-                    input
-                )
-                val result: Instrumentation.ActivityResult = launch(launchIntent)
-                dispatchResult(requestCode, result.resultCode, result.resultData)
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+                longClickForVideoRecording()
             }
-        }
-        return testRegistry
+        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_OK)
+        Truth.assertThat(doesImageFileExist(uri, "video")).isTrue()
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
-    private fun getTestUri(timeStamp: Long): Uri {
-        return Uri.fromFile(
-            File(
-                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
-                "$timeStamp.mp4"
-            )
-        )
+    @Test
+    fun video_capture_external_illegal_uri() {
+        val uri = Uri.parse("asdfasdf")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+                longClickForVideoRecording()
+                composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(VIDEO_CAPTURE_FAILURE_TAG).isDisplayed()
+                }
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesImageFileExist(uri, "video")).isFalse()
     }
 
-    companion object {
-        private val TEST_CONTRACT = object : ActivityResultContracts.TakePicture() {
-            override fun createIntent(context: Context, uri: Uri): Intent {
-                return super.createIntent(context, uri).apply {
-                    component = ComponentName(
-                        ApplicationProvider.getApplicationContext(),
-                        MainActivity::class.java
-                    )
+    @Test
+    fun image_capture_during_video_capture_external() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(ImageCaptureDeviceTest.DIR_PATH, timeStamp, "mp4")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+                    .assertExists()
+                    .performClick()
+                composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(
+                        IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+                    ).isDisplayed()
                 }
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesImageFileExist(uri, "image")).isFalse()
+    }
+
+    private fun longClickForVideoRecording() {
+        composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+            .assertExists()
+            .performTouchInput {
+                down(center)
             }
+        idleForVideoDuration()
+        composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+            .assertExists()
+            .performTouchInput {
+                up()
+            }
+    }
+
+    private fun idleForVideoDuration() {
+        // TODO: replace with a check for the timestamp UI of the video duration
+        try {
+            composeTestRule.waitUntil(timeoutMillis = VIDEO_DURATION_MILLIS) {
+                composeTestRule.onNodeWithTag("dummyTagForLongPress").isDisplayed()
+            }
+        } catch (e: ComposeTimeoutException) {
         }
     }
+
+    companion object {
+        val DIR_PATH: String =
+            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MOVIES).path
+    }
 }
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/AppTestUtil.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt
similarity index 95%
rename from app/src/androidTest/java/com/google/jetpackcamera/AppTestUtil.kt
rename to app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt
index b68f8e6..0d1e8d6 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/AppTestUtil.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera
+package com.google.jetpackcamera.utils
 
 import android.os.Build
 
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/ComposeTestRuleExt.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
similarity index 98%
rename from app/src/androidTest/java/com/google/jetpackcamera/ComposeTestRuleExt.kt
rename to app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
index 1e1bca9..e3be80e 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/ComposeTestRuleExt.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera
+package com.google.jetpackcamera.utils
 
 import android.content.Context
 import androidx.annotation.StringRes
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/UiTestUtil.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
similarity index 57%
rename from app/src/androidTest/java/com/google/jetpackcamera/UiTestUtil.kt
rename to app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
index 118bd7b..782ede2 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/UiTestUtil.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,21 +13,31 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera
+package com.google.jetpackcamera.utils
 
 import android.app.Activity
+import android.app.Instrumentation
+import android.content.ComponentName
+import android.content.Intent
+import android.net.Uri
+import android.provider.MediaStore
 import androidx.compose.ui.semantics.SemanticsProperties
 import androidx.compose.ui.test.isDisplayed
 import androidx.compose.ui.test.junit4.ComposeTestRule
 import androidx.compose.ui.test.onNodeWithTag
 import androidx.compose.ui.test.performClick
 import androidx.test.core.app.ActivityScenario
+import com.google.jetpackcamera.MainActivity
 import com.google.jetpackcamera.feature.preview.R
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.settings.model.LensFacing
+import java.io.File
+import java.net.URLConnection
 
 const val APP_START_TIMEOUT_MILLIS = 10_000L
 const val IMAGE_CAPTURE_TIMEOUT_MILLIS = 5_000L
+const val VIDEO_CAPTURE_TIMEOUT_MILLIS = 5_000L
+const val VIDEO_DURATION_MILLIS = 2_000L
 
 inline fun <reified T : Activity> runScenarioTest(
     crossinline block: ActivityScenario<T>.() -> Unit
@@ -37,6 +47,16 @@ inline fun <reified T : Activity> runScenarioTest(
     }
 }
 
+inline fun <reified T : Activity> runScenarioTestForResult(
+    intent: Intent,
+    crossinline block: ActivityScenario<T>.() -> Unit
+): Instrumentation.ActivityResult? {
+    ActivityScenario.launchActivityForResult<T>(intent).use { scenario ->
+        scenario.apply(block)
+        return scenario.result
+    }
+}
+
 context(ActivityScenario<MainActivity>)
 fun ComposeTestRule.getCurrentLensFacing(): LensFacing {
     var needReturnFromQuickSettings = false
@@ -76,3 +96,54 @@ fun ComposeTestRule.getCurrentLensFacing(): LensFacing {
         }
     }
 }
+
+fun getTestUri(directoryPath: String, timeStamp: Long, suffix: String): Uri {
+    return Uri.fromFile(
+        File(
+            directoryPath,
+            "$timeStamp.$suffix"
+        )
+    )
+}
+
+fun deleteFilesInDirAfterTimestamp(
+    directoryPath: String,
+    instrumentation: Instrumentation,
+    timeStamp: Long
+): Boolean {
+    var hasDeletedFile = false
+    for (file in File(directoryPath).listFiles()) {
+        if (file.lastModified() >= timeStamp) {
+            file.delete()
+            if (file.exists()) {
+                file.getCanonicalFile().delete()
+                if (file.exists()) {
+                    instrumentation.targetContext.applicationContext.deleteFile(file.getName())
+                }
+            }
+            hasDeletedFile = true
+        }
+    }
+    return hasDeletedFile
+}
+
+fun doesImageFileExist(uri: Uri, prefix: String): Boolean {
+    val file = File(uri.path)
+    if (file.exists()) {
+        val mimeType = URLConnection.guessContentTypeFromName(uri.path)
+        return mimeType != null && mimeType.startsWith(prefix)
+    }
+    return false
+}
+
+fun getIntent(uri: Uri, action: String): Intent {
+    val intent = Intent(action)
+    intent.setComponent(
+        ComponentName(
+            "com.google.jetpackcamera",
+            "com.google.jetpackcamera.MainActivity"
+        )
+    )
+    intent.putExtra(MediaStore.EXTRA_OUTPUT, uri)
+    return intent
+}
diff --git a/app/src/main/java/com/google/jetpackcamera/MainActivity.kt b/app/src/main/java/com/google/jetpackcamera/MainActivity.kt
index 1ac223c..04dfaf9 100644
--- a/app/src/main/java/com/google/jetpackcamera/MainActivity.kt
+++ b/app/src/main/java/com/google/jetpackcamera/MainActivity.kt
@@ -51,22 +51,27 @@ import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.semantics.testTagsAsResourceId
 import androidx.compose.ui.unit.dp
+import androidx.core.content.IntentCompat
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import androidx.tracing.Trace
 import com.google.jetpackcamera.MainActivityUiState.Loading
 import com.google.jetpackcamera.MainActivityUiState.Success
+import com.google.jetpackcamera.core.common.traceFirstFrameMainActivity
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewViewModel
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.ui.JcaApp
 import com.google.jetpackcamera.ui.theme.JetpackCameraTheme
 import dagger.hilt.android.AndroidEntryPoint
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.flow.collect
 import kotlinx.coroutines.flow.onEach
 import kotlinx.coroutines.launch
 
 private const val TAG = "MainActivity"
+private const val KEY_DEBUG_MODE = "KEY_DEBUG_MODE"
 
 /**
  * Activity for the JetpackCameraApp.
@@ -90,6 +95,18 @@ class MainActivity : Hilt_MainActivity() {
                     .collect()
             }
         }
+
+        var firstFrameComplete: CompletableDeferred<Unit>? = null
+        if (Trace.isEnabled()) {
+            firstFrameComplete = CompletableDeferred()
+            // start trace between app starting and the earliest possible completed capture
+            lifecycleScope.launch {
+                traceFirstFrameMainActivity(cookie = 0) {
+                    firstFrameComplete.await()
+                }
+            }
+        }
+
         setContent {
             when (uiState) {
                 Loading -> {
@@ -121,6 +138,7 @@ class MainActivity : Hilt_MainActivity() {
                         ) {
                             JcaApp(
                                 previewMode = getPreviewMode(),
+                                isDebugMode = isDebugMode,
                                 openAppSettings = ::openAppSettings,
                                 onRequestWindowColorMode = { colorMode ->
                                     // Window color mode APIs require API level 26+
@@ -132,6 +150,9 @@ class MainActivity : Hilt_MainActivity() {
                                         )
                                         window?.colorMode = colorMode
                                     }
+                                },
+                                onFirstFrameCaptureCompleted = {
+                                    firstFrameComplete?.complete(Unit)
                                 }
                             )
                         }
@@ -141,39 +162,60 @@ class MainActivity : Hilt_MainActivity() {
         }
     }
 
-    private fun getPreviewMode(): PreviewMode {
-        if (intent == null || MediaStore.ACTION_IMAGE_CAPTURE != intent.action) {
-            return PreviewMode.StandardMode { event ->
-                if (event is PreviewViewModel.ImageCaptureEvent.ImageSaved) {
-                    val intent = Intent(Camera.ACTION_NEW_PICTURE)
-                    intent.setData(event.savedUri)
-                    sendBroadcast(intent)
-                }
-            }
-        } else {
-            var uri = if (intent.extras == null ||
-                !intent.extras!!.containsKey(MediaStore.EXTRA_OUTPUT)
-            ) {
-                null
-            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
-                intent.extras!!.getParcelable(
-                    MediaStore.EXTRA_OUTPUT,
-                    Uri::class.java
-                )
-            } else {
-                @Suppress("DEPRECATION")
-                intent.extras!!.getParcelable(MediaStore.EXTRA_OUTPUT)
-            }
-            if (uri == null && intent.clipData != null && intent.clipData!!.itemCount != 0) {
-                uri = intent.clipData!!.getItemAt(0).uri
+    private val isDebugMode: Boolean
+        get() = intent?.getBooleanExtra(KEY_DEBUG_MODE, false) ?: false
+
+    private fun getStandardMode(): PreviewMode.StandardMode {
+        return PreviewMode.StandardMode { event ->
+            if (event is PreviewViewModel.ImageCaptureEvent.ImageSaved) {
+                val intent = Intent(Camera.ACTION_NEW_PICTURE)
+                intent.setData(event.savedUri)
+                sendBroadcast(intent)
             }
-            return PreviewMode.ExternalImageCaptureMode(uri) { event ->
-                if (event is PreviewViewModel.ImageCaptureEvent.ImageSaved) {
-                    setResult(RESULT_OK)
-                    finish()
+        }
+    }
+
+    private fun getExternalCaptureUri(): Uri? {
+        return IntentCompat.getParcelableExtra(
+            intent,
+            MediaStore.EXTRA_OUTPUT,
+            Uri::class.java
+        ) ?: intent?.clipData?.getItemAt(0)?.uri
+    }
+
+    private fun getPreviewMode(): PreviewMode {
+        return intent?.action?.let { action ->
+            when (action) {
+                MediaStore.ACTION_IMAGE_CAPTURE ->
+                    PreviewMode.ExternalImageCaptureMode(getExternalCaptureUri()) { event ->
+                        Log.d(TAG, "onImageCapture, event: $event")
+                        if (event is PreviewViewModel.ImageCaptureEvent.ImageSaved) {
+                            val resultIntent = Intent()
+                            resultIntent.putExtra(MediaStore.EXTRA_OUTPUT, event.savedUri)
+                            setResult(RESULT_OK, resultIntent)
+                            Log.d(TAG, "onImageCapture, finish()")
+                            finish()
+                        }
+                    }
+
+                MediaStore.ACTION_VIDEO_CAPTURE ->
+                    PreviewMode.ExternalVideoCaptureMode(getExternalCaptureUri()) { event ->
+                        Log.d(TAG, "onVideoCapture, event: $event")
+                        if (event is PreviewViewModel.VideoCaptureEvent.VideoSaved) {
+                            val resultIntent = Intent()
+                            resultIntent.putExtra(MediaStore.EXTRA_OUTPUT, event.savedUri)
+                            setResult(RESULT_OK, resultIntent)
+                            Log.d(TAG, "onVideoCapture, finish()")
+                            finish()
+                        }
+                    }
+
+                else -> {
+                    Log.w(TAG, "Ignoring external intent with unknown action.")
+                    getStandardMode()
                 }
             }
-        }
+        } ?: getStandardMode()
     }
 }
 
diff --git a/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt b/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
index 1e7add4..1e16d5b 100644
--- a/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
+++ b/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
@@ -36,19 +36,22 @@ import com.google.jetpackcamera.ui.Routes.PERMISSIONS_ROUTE
 import com.google.jetpackcamera.ui.Routes.PREVIEW_ROUTE
 import com.google.jetpackcamera.ui.Routes.SETTINGS_ROUTE
 
-@OptIn(ExperimentalPermissionsApi::class)
 @Composable
 fun JcaApp(
     openAppSettings: () -> Unit,
     /*TODO(b/306236646): remove after still capture*/
     previewMode: PreviewMode,
+    modifier: Modifier = Modifier,
+    isDebugMode: Boolean,
     onRequestWindowColorMode: (Int) -> Unit,
-    modifier: Modifier = Modifier
+    onFirstFrameCaptureCompleted: () -> Unit
 ) {
     JetpackCameraNavHost(
         previewMode = previewMode,
+        isDebugMode = isDebugMode,
         onOpenAppSettings = openAppSettings,
         onRequestWindowColorMode = onRequestWindowColorMode,
+        onFirstFrameCaptureCompleted = onFirstFrameCaptureCompleted,
         modifier = modifier
     )
 }
@@ -58,8 +61,10 @@ fun JcaApp(
 private fun JetpackCameraNavHost(
     modifier: Modifier = Modifier,
     previewMode: PreviewMode,
+    isDebugMode: Boolean,
     onOpenAppSettings: () -> Unit,
     onRequestWindowColorMode: (Int) -> Unit,
+    onFirstFrameCaptureCompleted: () -> Unit,
     navController: NavHostController = rememberNavController()
 ) {
     NavHost(
@@ -69,6 +74,7 @@ private fun JetpackCameraNavHost(
     ) {
         composable(PERMISSIONS_ROUTE) {
             PermissionsScreen(
+                shouldRequestAudioPermission = previewMode is PreviewMode.StandardMode,
                 onNavigateToPreview = {
                     navController.navigate(PREVIEW_ROUTE) {
                         // cannot navigate back to permissions after leaving
@@ -98,7 +104,9 @@ private fun JetpackCameraNavHost(
             PreviewScreen(
                 onNavigateToSettings = { navController.navigate(SETTINGS_ROUTE) },
                 onRequestWindowColorMode = onRequestWindowColorMode,
-                previewMode = previewMode
+                onFirstFrameCaptureCompleted = onFirstFrameCaptureCompleted,
+                previewMode = previewMode,
+                isDebugMode = isDebugMode
             )
         }
         composable(SETTINGS_ROUTE) {
@@ -112,4 +120,3 @@ private fun JetpackCameraNavHost(
         }
     }
 }
-
diff --git a/benchmark/build.gradle.kts b/benchmark/build.gradle.kts
index 72fb9ec..a923cc4 100644
--- a/benchmark/build.gradle.kts
+++ b/benchmark/build.gradle.kts
@@ -22,6 +22,7 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.benchmark"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_1_8
@@ -55,6 +56,18 @@ android {
         }
     }
 
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
+    }
+
     targetProjectPath = ":app"
     // required for benchmark:
     // self instrumentation required for the tests to be able to compile, start, or kill the app
diff --git a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/FirstFrameBenchmark.kt b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/FirstFrameBenchmark.kt
new file mode 100644
index 0000000..3ed5ae4
--- /dev/null
+++ b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/FirstFrameBenchmark.kt
@@ -0,0 +1,118 @@
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
+package com.google.jetpackcamera.benchmark
+
+import android.content.Intent
+import androidx.benchmark.macro.ExperimentalMetricApi
+import androidx.benchmark.macro.MacrobenchmarkScope
+import androidx.benchmark.macro.StartupMode
+import androidx.benchmark.macro.StartupTimingMetric
+import androidx.benchmark.macro.TraceSectionMetric
+import androidx.benchmark.macro.junit4.MacrobenchmarkRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.jetpackcamera.benchmark.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.benchmark.utils.DEFAULT_TEST_ITERATIONS
+import com.google.jetpackcamera.benchmark.utils.FIRST_FRAME_TRACE_MAIN_ACTIVITY
+import com.google.jetpackcamera.benchmark.utils.FIRST_FRAME_TRACE_PREVIEW
+import com.google.jetpackcamera.benchmark.utils.IMAGE_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.benchmark.utils.JCA_PACKAGE_NAME
+import com.google.jetpackcamera.benchmark.utils.allowAllRequiredPerms
+import com.google.jetpackcamera.benchmark.utils.clickCaptureButton
+import com.google.jetpackcamera.benchmark.utils.findObjectByRes
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class FirstFrameBenchmark {
+    @get:Rule
+    val benchmarkRule = MacrobenchmarkRule()
+
+    @Test
+    fun timeToFirstFrameDefaultSettingsColdStartup() {
+        benchmarkFirstFrame(setupBlock = {
+            allowAllRequiredPerms(perms = APP_REQUIRED_PERMISSIONS.toTypedArray())
+        })
+    }
+
+    @Test
+    fun timeToFirstFrameDefaultSettingsHotStartup() {
+        benchmarkFirstFrame(startupMode = StartupMode.HOT, setupBlock = {
+            allowAllRequiredPerms(perms = APP_REQUIRED_PERMISSIONS.toTypedArray())
+        })
+    }
+
+    /**
+     * The benchmark for first frame tracks the amount of time it takes from preview loading on the
+     * screen to when the use case is able to start capturing frames.
+     *
+     * Note that the trace this benchmark tracks is the earliest point in which a frame is captured
+     * and sent to a surface. This does not necessarily mean the frame is visible on screen.
+     *
+     * @param startupMode the designated startup mode, either [StartupMode.COLD] or [StartupMode.HOT]
+     * @param timeout option to change the default timeout length after clicking the Image Capture
+     *  button.
+     *
+     */
+    @OptIn(ExperimentalMetricApi::class)
+    private fun benchmarkFirstFrame(
+        startupMode: StartupMode? = StartupMode.COLD,
+        iterations: Int = DEFAULT_TEST_ITERATIONS,
+        timeout: Long = 15000,
+        intent: Intent? = null,
+        setupBlock: MacrobenchmarkScope.() -> Unit = {}
+    ) {
+        benchmarkRule.measureRepeated(
+            packageName = JCA_PACKAGE_NAME,
+            metrics = buildList {
+                add(StartupTimingMetric())
+                if (startupMode == StartupMode.COLD) {
+                    add(
+                        TraceSectionMetric(
+                            sectionName = FIRST_FRAME_TRACE_MAIN_ACTIVITY,
+                            targetPackageOnly = false,
+                            mode = TraceSectionMetric.Mode.First
+                        )
+                    )
+                }
+                add(
+                    TraceSectionMetric(
+                        sectionName = FIRST_FRAME_TRACE_PREVIEW,
+                        targetPackageOnly = false,
+                        mode = TraceSectionMetric.Mode.First
+                    )
+                )
+            },
+            iterations = iterations,
+            startupMode = startupMode,
+            setupBlock = setupBlock
+        ) {
+            pressHome()
+            if (intent == null) startActivityAndWait() else startActivityAndWait(intent)
+            device.waitForIdle()
+
+            clickCaptureButton(device)
+
+            // ensure trace is closed
+            findObjectByRes(
+                device = device,
+                testTag = IMAGE_CAPTURE_SUCCESS_TAG,
+                timeout = timeout,
+                shouldFailIfNotFound = true
+            )
+        }
+    }
+}
diff --git a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/ImageCaptureLatencyBenchmark.kt b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/ImageCaptureLatencyBenchmark.kt
index 2096265..787e16f 100644
--- a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/ImageCaptureLatencyBenchmark.kt
+++ b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/ImageCaptureLatencyBenchmark.kt
@@ -20,6 +20,17 @@ import androidx.benchmark.macro.ExperimentalMetricApi
 import androidx.benchmark.macro.TraceSectionMetric
 import androidx.benchmark.macro.junit4.MacrobenchmarkRule
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.jetpackcamera.benchmark.utils.DEFAULT_TEST_ITERATIONS
+import com.google.jetpackcamera.benchmark.utils.FlashMode
+import com.google.jetpackcamera.benchmark.utils.IMAGE_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.benchmark.utils.IMAGE_CAPTURE_TRACE
+import com.google.jetpackcamera.benchmark.utils.JCA_PACKAGE_NAME
+import com.google.jetpackcamera.benchmark.utils.allowCamera
+import com.google.jetpackcamera.benchmark.utils.clickCaptureButton
+import com.google.jetpackcamera.benchmark.utils.findObjectByRes
+import com.google.jetpackcamera.benchmark.utils.setQuickFrontFacingCamera
+import com.google.jetpackcamera.benchmark.utils.setQuickSetFlash
+import com.google.jetpackcamera.benchmark.utils.toggleQuickSettings
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -97,7 +108,7 @@ class ImageCaptureLatencyBenchmark {
             // ensure trace is closed
             findObjectByRes(
                 device = device,
-                testTag = IMAGE_CAPTURE_SUCCESS_TOAST,
+                testTag = IMAGE_CAPTURE_SUCCESS_TAG,
                 timeout = timeout,
                 shouldFailIfNotFound = true
             )
diff --git a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/StartupBenchmark.kt b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/StartupBenchmark.kt
index c97a45f..3c1275c 100644
--- a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/StartupBenchmark.kt
+++ b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/StartupBenchmark.kt
@@ -20,6 +20,10 @@ import androidx.benchmark.macro.StartupMode
 import androidx.benchmark.macro.StartupTimingMetric
 import androidx.benchmark.macro.junit4.MacrobenchmarkRule
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.jetpackcamera.benchmark.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.benchmark.utils.DEFAULT_TEST_ITERATIONS
+import com.google.jetpackcamera.benchmark.utils.JCA_PACKAGE_NAME
+import com.google.jetpackcamera.benchmark.utils.allowAllRequiredPerms
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -34,33 +38,33 @@ class StartupBenchmark {
     val benchmarkRule = MacrobenchmarkRule()
 
     @Test
-    fun startupColdWithoutCameraPermission() {
+    fun startupColdWithPermissionRequest() {
         benchmarkStartup()
     }
 
     @Test
-    fun startupCold() {
+    fun startupColdNoPermissionRequest() {
         benchmarkStartup(
             setupBlock =
-            { allowCamera() }
+            { allowAllRequiredPerms(perms = APP_REQUIRED_PERMISSIONS.toTypedArray()) }
         )
     }
 
     @Test
-    fun startupWarm() {
+    fun startupWarmNoPermissionRequest() {
         benchmarkStartup(
             startupMode = StartupMode.WARM,
             setupBlock =
-            { allowCamera() }
+            { allowAllRequiredPerms(perms = APP_REQUIRED_PERMISSIONS.toTypedArray()) }
         )
     }
 
     @Test
-    fun startupHot() {
+    fun startupHotNoPermissionRequest() {
         benchmarkStartup(
             startupMode = StartupMode.HOT,
             setupBlock =
-            { allowCamera() }
+            { allowAllRequiredPerms(perms = APP_REQUIRED_PERMISSIONS.toTypedArray()) }
         )
     }
 
@@ -74,7 +78,6 @@ class StartupBenchmark {
             iterations = DEFAULT_TEST_ITERATIONS,
             startupMode = startupMode,
             setupBlock = setupBlock
-
         ) {
             pressHome()
             startActivityAndWait()
diff --git a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/utils/Permissions.kt b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/utils/Permissions.kt
new file mode 100644
index 0000000..af0455c
--- /dev/null
+++ b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/utils/Permissions.kt
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
+package com.google.jetpackcamera.benchmark.utils
+
+import android.Manifest.permission
+import android.os.Build
+import androidx.benchmark.macro.MacrobenchmarkScope
+
+val APP_REQUIRED_PERMISSIONS: List<String> = buildList {
+    add(permission.CAMERA)
+    add(permission.RECORD_AUDIO)
+    if (Build.VERSION.SDK_INT <= 28) {
+        add(permission.WRITE_EXTERNAL_STORAGE)
+    }
+}
+fun MacrobenchmarkScope.allowCamera() {
+    val command = "pm grant $packageName ${permission.CAMERA}"
+    device.executeShellCommand(command)
+}
+
+fun MacrobenchmarkScope.allowAllRequiredPerms(vararg perms: String) {
+    val command = "pm grant $packageName"
+    perms.forEach { perm -> device.executeShellCommand("$command $perm") }
+}
diff --git a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/Utils.kt b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/utils/Utils.kt
similarity index 94%
rename from benchmark/src/main/java/com/google/jetpackcamera/benchmark/Utils.kt
rename to benchmark/src/main/java/com/google/jetpackcamera/benchmark/utils/Utils.kt
index 1204001..10b030e 100644
--- a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/Utils.kt
+++ b/benchmark/src/main/java/com/google/jetpackcamera/benchmark/utils/Utils.kt
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.benchmark
+package com.google.jetpackcamera.benchmark.utils
 
 import androidx.test.uiautomator.By
 import androidx.test.uiautomator.UiDevice
@@ -29,7 +29,7 @@ const val CAPTURE_BUTTON = "CaptureButton"
 const val QUICK_SETTINGS_DROP_DOWN_BUTTON = "QuickSettingsDropDown"
 const val QUICK_SETTINGS_FLASH_BUTTON = "QuickSettingsFlashButton"
 const val QUICK_SETTINGS_FLIP_CAMERA_BUTTON = "QuickSettingsFlipCameraButton"
-const val IMAGE_CAPTURE_SUCCESS_TOAST = "ImageCaptureSuccessToast"
+const val IMAGE_CAPTURE_SUCCESS_TAG = "ImageCaptureSuccessTag"
 
 // test descriptions
 const val QUICK_SETTINGS_FLASH_OFF = "QUICK SETTINGS FLASH IS OFF"
@@ -40,6 +40,9 @@ const val QUICK_SETTINGS_LENS_FRONT = "QUICK SETTINGS LENS FACING FRONT"
 // trace tags
 const val IMAGE_CAPTURE_TRACE = "JCA Image Capture"
 
+const val FIRST_FRAME_TRACE_PREVIEW = "firstFrameTracePreview"
+const val FIRST_FRAME_TRACE_MAIN_ACTIVITY = "firstFrameTraceMainActivity"
+
 // enums
 enum class FlashMode {
     ON,
diff --git a/domain/camera/.gitignore b/core/camera/.gitignore
similarity index 100%
rename from domain/camera/.gitignore
rename to core/camera/.gitignore
diff --git a/domain/camera/Android.bp b/core/camera/Android.bp
similarity index 80%
rename from domain/camera/Android.bp
rename to core/camera/Android.bp
index 841f3c6..b5a8c62 100644
--- a/domain/camera/Android.bp
+++ b/core/camera/Android.bp
@@ -5,21 +5,23 @@ package {
 }
 
 android_library {
-    name: "jetpack-camera-app_domain_camera",
+    name: "jetpack-camera-app_core_camera",
     srcs: ["src/main/**/*.kt"],
     static_libs: [
         "androidx.concurrent_concurrent-futures-ktx",
         "hilt_android",
         "androidx.camera_camera-core",
-        "androidx.camera_camera-viewfinder",
         "androidx.camera_camera-video",
         "androidx.camera_camera-camera2",
         "androidx.camera_camera-lifecycle",
-        //"androidx.graphics_graphics-core",
+        "androidx.graphics_graphics-core",
         "jetpack-camera-app_data_settings",
         "jetpack-camera-app_core_common",
     ],
     sdk_version: "34",
     min_sdk_version: "21",
     manifest: "src/main/AndroidManifest.xml",
+    kotlincflags: [
+        "-Xcontext-receivers",
+    ],
 }
diff --git a/domain/camera/build.gradle.kts b/core/camera/build.gradle.kts
similarity index 57%
rename from domain/camera/build.gradle.kts
rename to core/camera/build.gradle.kts
index c79cf4b..cc471c3 100644
--- a/domain/camera/build.gradle.kts
+++ b/core/camera/build.gradle.kts
@@ -22,8 +22,9 @@ plugins {
 }
 
 android {
-    namespace = "com.google.jetpackcamera.data.camera"
+    namespace = "com.google.jetpackcamera.core.camera"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -31,6 +32,49 @@ android {
         lint.targetSdk = libs.versions.targetSdk.get().toInt()
 
         testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
+
+        @Suppress("UnstableApiUsage")
+        externalNativeBuild {
+            val versionScript = file("src/main/cpp/jni.lds").absolutePath
+            cmake {
+                cppFlags += listOf(
+                    "-std=c++17",
+                    "-O3",
+                    "-flto",
+                    "-fPIC",
+                    "-fno-exceptions",
+                    "-fno-rtti",
+                    "-fomit-frame-pointer",
+                    "-fdata-sections",
+                    "-ffunction-sections"
+                )
+                arguments += listOf(
+                    "-DCMAKE_VERBOSE_MAKEFILE=ON",
+                    "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,--gc-sections " +
+                        "-Wl,--version-script=${versionScript}"
+                )
+            }
+        }
+    }
+
+    externalNativeBuild {
+        cmake {
+            version = libs.versions.cmake.get()
+            path = file("src/main/cpp/CMakeLists.txt")
+        }
+    }
+
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
     }
 
     compileOptions {
@@ -40,6 +84,10 @@ android {
     kotlin {
         jvmToolchain(17)
     }
+
+    kotlinOptions {
+        freeCompilerArgs += "-Xcontext-receivers"
+    }
 }
 
 dependencies {
@@ -50,10 +98,16 @@ dependencies {
     testImplementation(libs.mockito.core)
     androidTestImplementation(libs.androidx.junit)
     androidTestImplementation(libs.androidx.espresso.core)
+    androidTestImplementation(libs.kotlinx.coroutines.test)
+    androidTestImplementation(libs.rules)
+    androidTestImplementation(libs.truth)
 
     // Futures
     implementation(libs.futures.ktx)
 
+    // LiveData
+    implementation(libs.androidx.lifecycle.livedata)
+
     // CameraX
     implementation(libs.camera.core)
     implementation(libs.camera.camera2)
@@ -66,6 +120,7 @@ dependencies {
 
     // Tracing
     implementation(libs.androidx.tracing)
+    implementation(libs.kotlinx.atomicfu)
 
     // Graphics libraries
     implementation(libs.androidx.graphics.core)
diff --git a/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt b/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt
new file mode 100644
index 0000000..5cd9d75
--- /dev/null
+++ b/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt
@@ -0,0 +1,245 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.app.Application
+import android.content.ContentResolver
+import android.graphics.SurfaceTexture
+import android.net.Uri
+import android.view.Surface
+import androidx.concurrent.futures.DirectExecutor
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.LargeTest
+import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.rule.GrantPermissionRule
+import com.google.jetpackcamera.core.camera.CameraUseCase.OnVideoRecordEvent.OnVideoRecordError
+import com.google.jetpackcamera.core.camera.CameraUseCase.OnVideoRecordEvent.OnVideoRecordStatus
+import com.google.jetpackcamera.core.camera.CameraUseCase.OnVideoRecordEvent.OnVideoRecorded
+import com.google.jetpackcamera.core.camera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.settings.ConstraintsRepository
+import com.google.jetpackcamera.settings.SettableConstraintsRepository
+import com.google.jetpackcamera.settings.SettableConstraintsRepositoryImpl
+import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.LensFacing
+import java.io.File
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.cancel
+import kotlinx.coroutines.channels.ReceiveChannel
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.produceIn
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.withTimeoutOrNull
+import org.junit.After
+import org.junit.Assert.fail
+import org.junit.Assume.assumeTrue
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@LargeTest
+@RunWith(AndroidJUnit4::class)
+class CameraXCameraUseCaseTest {
+
+    companion object {
+        private const val STATUS_VERIFY_COUNT = 5
+        private const val GENERAL_TIMEOUT_MS = 3_000L
+        private const val STATUS_VERIFY_TIMEOUT_MS = 10_000L
+    }
+
+    @get:Rule
+    val permissionsRule: GrantPermissionRule =
+        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+
+    private val instrumentation = InstrumentationRegistry.getInstrumentation()
+    private val context = instrumentation.context
+    private val application = context.applicationContext as Application
+    private val videosToDelete = mutableSetOf<Uri>()
+    private lateinit var useCaseScope: CoroutineScope
+
+    @Before
+    fun setup() {
+        useCaseScope = CoroutineScope(Dispatchers.Default)
+    }
+
+    @After
+    fun tearDown() {
+        useCaseScope.cancel()
+        deleteVideos()
+    }
+
+    @Test
+    fun canRecordVideo(): Unit = runBlocking {
+        // Arrange.
+        val cameraUseCase = createAndInitCameraXUseCase()
+        cameraUseCase.runCameraOnMain()
+
+        // Act.
+        val recordEvent = cameraUseCase.startRecordingAndGetEvents()
+
+        // Assert.
+        recordEvent.onRecordStatus.await(STATUS_VERIFY_TIMEOUT_MS)
+
+        // Act.
+        cameraUseCase.stopVideoRecording()
+
+        // Assert.
+        recordEvent.onRecorded.await()
+    }
+
+    @Test
+    fun recordVideoWithFlashModeOn_shouldEnableTorch(): Unit = runBlocking {
+        // Arrange.
+        val lensFacing = LensFacing.BACK
+        val constraintsRepository = SettableConstraintsRepositoryImpl()
+        val cameraUseCase = createAndInitCameraXUseCase(
+            constraintsRepository = constraintsRepository
+        )
+        assumeTrue("No flash unit, skip the test.", constraintsRepository.hasFlashUnit(lensFacing))
+        cameraUseCase.runCameraOnMain()
+
+        // Arrange: Create a ReceiveChannel to observe the torch enabled state.
+        val torchEnabled: ReceiveChannel<Boolean> = cameraUseCase.getCurrentCameraState()
+            .map { it.torchEnabled }
+            .produceIn(this)
+
+        // Assert: The initial torch enabled should be false.
+        torchEnabled.awaitValue(false)
+
+        // Act: Start recording with FlashMode.ON
+        cameraUseCase.setFlashMode(FlashMode.ON)
+        val recordEvent = cameraUseCase.startRecordingAndGetEvents()
+
+        // Assert: Torch enabled transitions to true.
+        torchEnabled.awaitValue(true)
+
+        // Act: Ensure enough data is received and stop recording.
+        recordEvent.onRecordStatus.await(STATUS_VERIFY_TIMEOUT_MS)
+        cameraUseCase.stopVideoRecording()
+
+        // Assert: Torch enabled transitions to false.
+        torchEnabled.awaitValue(false)
+
+        // Clean-up.
+        torchEnabled.cancel()
+    }
+
+    private suspend fun createAndInitCameraXUseCase(
+        appSettings: CameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
+        constraintsRepository: SettableConstraintsRepository = SettableConstraintsRepositoryImpl()
+    ) = CameraXCameraUseCase(
+        application,
+        useCaseScope,
+        Dispatchers.Default,
+        constraintsRepository
+    ).apply {
+        initialize(appSettings, CameraUseCase.UseCaseMode.STANDARD)
+        providePreviewSurface()
+    }
+
+    private data class RecordEvents(
+        val onRecorded: CompletableDeferred<Unit>,
+        val onRecordStatus: CompletableDeferred<Unit>
+    )
+
+    private suspend fun CompletableDeferred<*>.await(timeoutMs: Long = GENERAL_TIMEOUT_MS) =
+        withTimeoutOrNull(timeoutMs) {
+            await()
+            Unit
+        } ?: fail("Timeout while waiting for the Deferred to complete")
+
+    private suspend fun <T> ReceiveChannel<T>.awaitValue(
+        expectedValue: T,
+        timeoutMs: Long = GENERAL_TIMEOUT_MS
+    ) = withTimeoutOrNull(timeoutMs) {
+        for (value in this@awaitValue) {
+            if (value == expectedValue) return@withTimeoutOrNull
+        }
+    } ?: fail("Timeout while waiting for expected value: $expectedValue")
+
+    private suspend fun CameraXCameraUseCase.startRecordingAndGetEvents(
+        statusVerifyCount: Int = STATUS_VERIFY_COUNT
+    ): RecordEvents {
+        val onRecorded = CompletableDeferred<Unit>()
+        val onRecordStatus = CompletableDeferred<Unit>()
+        var statusCount = 0
+        startVideoRecording(null, false) {
+            when (it) {
+                is OnVideoRecorded -> {
+                    val videoUri = it.savedUri
+                    if (videoUri != Uri.EMPTY) {
+                        videosToDelete.add(videoUri)
+                    }
+                    onRecorded.complete(Unit)
+                }
+                is OnVideoRecordError -> onRecorded.complete(Unit)
+                is OnVideoRecordStatus -> {
+                    statusCount++
+                    if (statusCount == statusVerifyCount) {
+                        onRecordStatus.complete(Unit)
+                    }
+                }
+            }
+        }
+        return RecordEvents(onRecorded, onRecordStatus)
+    }
+
+    private fun CameraXCameraUseCase.providePreviewSurface() {
+        useCaseScope.launch {
+            getSurfaceRequest().filterNotNull().first().let { surfaceRequest ->
+                val surfaceTexture = SurfaceTexture(0)
+                surfaceTexture.setDefaultBufferSize(640, 480)
+                val surface = Surface(surfaceTexture)
+                surfaceRequest.provideSurface(surface, DirectExecutor.INSTANCE) {
+                    surface.release()
+                    surfaceTexture.release()
+                }
+            }
+        }
+    }
+
+    private suspend fun CameraXCameraUseCase.runCameraOnMain() {
+        useCaseScope.launch(Dispatchers.Main) { runCamera() }
+        instrumentation.waitForIdleSync()
+    }
+
+    private suspend fun ConstraintsRepository.hasFlashUnit(lensFacing: LensFacing): Boolean =
+        systemConstraints.first()!!.perLensConstraints[lensFacing]!!.hasFlashUnit
+
+    private fun deleteVideos() {
+        for (uri in videosToDelete) {
+            when (uri.scheme) {
+                ContentResolver.SCHEME_CONTENT -> {
+                    try {
+                        context.contentResolver.delete(uri, null, null)
+                    } catch (e: RuntimeException) {
+                        // Ignore any exception.
+                    }
+                }
+                ContentResolver.SCHEME_FILE -> {
+                    File(uri.path!!).delete()
+                }
+            }
+        }
+    }
+}
diff --git a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/Permissions.kt b/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/utils/AppTestUtil.kt
similarity index 64%
rename from benchmark/src/main/java/com/google/jetpackcamera/benchmark/Permissions.kt
rename to core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/utils/AppTestUtil.kt
index fbe4594..509029e 100644
--- a/benchmark/src/main/java/com/google/jetpackcamera/benchmark/Permissions.kt
+++ b/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/utils/AppTestUtil.kt
@@ -13,14 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.benchmark
+package com.google.jetpackcamera.core.camera.utils
 
-import android.Manifest.permission
-import androidx.benchmark.macro.MacrobenchmarkScope
-import org.junit.Assert
+import android.os.Build
 
-fun MacrobenchmarkScope.allowCamera() {
-    val command = "pm grant $packageName ${permission.CAMERA}"
-    val output = device.executeShellCommand(command)
-    Assert.assertEquals("", output)
+val APP_REQUIRED_PERMISSIONS: List<String> = buildList {
+    add(android.Manifest.permission.CAMERA)
+    add(android.Manifest.permission.RECORD_AUDIO)
+    if (Build.VERSION.SDK_INT <= 28) {
+        add(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
+    }
 }
diff --git a/domain/camera/src/main/AndroidManifest.xml b/core/camera/src/main/AndroidManifest.xml
similarity index 61%
rename from domain/camera/src/main/AndroidManifest.xml
rename to core/camera/src/main/AndroidManifest.xml
index ea4043c..150f8d8 100644
--- a/domain/camera/src/main/AndroidManifest.xml
+++ b/core/camera/src/main/AndroidManifest.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2023 The Android Open Source Project
+  ~ Copyright (C) 2024 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -15,7 +15,11 @@
   ~ limitations under the License.
   -->
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-  package="com.google.jetpackcamera.domain.camera">
-    <uses-permission android:name = "android.permission.RECORD_AUDIO" />
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.google.jetpackcamera.core.camera">
+    <uses-permission android:name="android.permission.CAMERA" />
+    <uses-permission android:name="android.permission.RECORD_AUDIO" />
+    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
+        android:maxSdkVersion="28"
+        tools:ignore="ScopedStorage" />
 </manifest>
-
diff --git a/core/camera/src/main/cpp/CMakeLists.txt b/core/camera/src/main/cpp/CMakeLists.txt
new file mode 100644
index 0000000..008a8a2
--- /dev/null
+++ b/core/camera/src/main/cpp/CMakeLists.txt
@@ -0,0 +1,34 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License"); you may not
+# use this file except in compliance with the License. You may obtain a copy of
+# the License at
+#
+# http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+# License for the specific language governing permissions and limitations under
+# the License.
+#
+cmake_minimum_required(VERSION 3.22.1)
+
+project(core_camera_jni)
+
+add_library(
+        opengl_debug_lib
+        SHARED
+        opengl_debug_jni.cpp
+        jni_hooks.cpp
+)
+
+find_library(log-lib log)
+find_library(opengles3-lib GLESv3)
+target_link_libraries(opengl_debug_lib PRIVATE ${log-lib} ${opengles3-lib})
+target_link_options(
+        opengl_debug_lib
+        PRIVATE
+        "-Wl,-z,max-page-size=16384"
+)
diff --git a/core/camera/src/main/cpp/jni.lds b/core/camera/src/main/cpp/jni.lds
new file mode 100644
index 0000000..c619e88
--- /dev/null
+++ b/core/camera/src/main/cpp/jni.lds
@@ -0,0 +1,10 @@
+VERS_1.0 {
+  # Export JNI symbols.
+  global:
+    Java_*;
+    JNI_OnLoad;
+
+  # Hide everything else.
+  local:
+    *;
+};
diff --git a/core/camera/src/main/cpp/jni_hooks.cpp b/core/camera/src/main/cpp/jni_hooks.cpp
new file mode 100644
index 0000000..ee1cc2c
--- /dev/null
+++ b/core/camera/src/main/cpp/jni_hooks.cpp
@@ -0,0 +1,23 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <jni.h>
+
+extern "C" {
+JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
+    return JNI_VERSION_1_6;
+}
+}
diff --git a/core/camera/src/main/cpp/opengl_debug_jni.cpp b/core/camera/src/main/cpp/opengl_debug_jni.cpp
new file mode 100644
index 0000000..58e5a86
--- /dev/null
+++ b/core/camera/src/main/cpp/opengl_debug_jni.cpp
@@ -0,0 +1,44 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <android/log.h>
+
+#define GL_GLEXT_PROTOTYPES
+#include <GLES2/gl2.h>
+#include <GLES2/gl2ext.h>
+#include <jni.h>
+
+namespace {
+    auto constexpr LOG_TAG = "OpenGLDebugLib";
+
+    void gl_debug_cb(GLenum source, GLenum type, GLuint id, GLenum severity, GLsizei length,
+                     const GLchar* message, const void* userParam) {
+        if (type == GL_DEBUG_TYPE_ERROR_KHR) {
+            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
+                                "GL ERROR:\n %s.",
+                                message);
+        }
+    }
+} // namespace
+
+extern "C" {
+JNIEXPORT void JNICALL
+Java_com_google_jetpackcamera_core_camera_effects_GLDebug_enableES3DebugErrorLogging(
+        JNIEnv *env, jobject clazz) {
+    glDebugMessageCallbackKHR(gl_debug_cb, nullptr);
+    glEnable(GL_DEBUG_OUTPUT_KHR);
+}
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraEvent.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraEvent.kt
new file mode 100644
index 0000000..0fe8cc6
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraEvent.kt
@@ -0,0 +1,27 @@
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
+package com.google.jetpackcamera.core.camera
+
+/**
+ * An event that can be sent to the camera coroutine.
+ */
+sealed interface CameraEvent {
+
+    /**
+     * Represents a focus metering event, that the camera can act on.
+     */
+    data class FocusMeteringEvent(val x: Float, val y: Float) : CameraEvent
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
new file mode 100644
index 0000000..df24af5
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
@@ -0,0 +1,134 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.annotation.SuppressLint
+import android.hardware.camera2.CameraCharacteristics
+import androidx.annotation.OptIn
+import androidx.camera.camera2.interop.Camera2CameraInfo
+import androidx.camera.camera2.interop.ExperimentalCamera2Interop
+import androidx.camera.core.CameraInfo
+import androidx.camera.core.CameraSelector
+import androidx.camera.core.DynamicRange as CXDynamicRange
+import androidx.camera.core.ExperimentalImageCaptureOutputFormat
+import androidx.camera.core.ImageCapture
+import androidx.camera.core.Preview
+import androidx.camera.core.UseCase
+import androidx.camera.core.UseCaseGroup
+import androidx.camera.video.Recorder
+import androidx.camera.video.VideoCapture
+import com.google.jetpackcamera.settings.model.DynamicRange
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.LensFacing
+
+val CameraInfo.appLensFacing: LensFacing
+    get() = when (this.lensFacing) {
+        CameraSelector.LENS_FACING_FRONT -> LensFacing.FRONT
+        CameraSelector.LENS_FACING_BACK -> LensFacing.BACK
+        else -> throw IllegalArgumentException(
+            "Unknown CameraSelector.LensFacing -> LensFacing mapping. " +
+                "[CameraSelector.LensFacing: ${this.lensFacing}]"
+        )
+    }
+
+fun CXDynamicRange.toSupportedAppDynamicRange(): DynamicRange? {
+    return when (this) {
+        CXDynamicRange.SDR -> DynamicRange.SDR
+        CXDynamicRange.HLG_10_BIT -> DynamicRange.HLG10
+        // All other dynamic ranges unsupported. Return null.
+        else -> null
+    }
+}
+
+fun DynamicRange.toCXDynamicRange(): CXDynamicRange {
+    return when (this) {
+        com.google.jetpackcamera.settings.model.DynamicRange.SDR -> CXDynamicRange.SDR
+        com.google.jetpackcamera.settings.model.DynamicRange.HLG10 -> CXDynamicRange.HLG_10_BIT
+    }
+}
+
+fun LensFacing.toCameraSelector(): CameraSelector = when (this) {
+    LensFacing.FRONT -> CameraSelector.DEFAULT_FRONT_CAMERA
+    LensFacing.BACK -> CameraSelector.DEFAULT_BACK_CAMERA
+}
+
+@SuppressLint("RestrictedApi")
+fun CameraSelector.toAppLensFacing(): LensFacing = when (this.lensFacing) {
+    CameraSelector.LENS_FACING_FRONT -> LensFacing.FRONT
+    CameraSelector.LENS_FACING_BACK -> LensFacing.BACK
+    else -> throw IllegalArgumentException(
+        "Unknown CameraSelector -> LensFacing mapping. [CameraSelector: $this]"
+    )
+}
+
+val CameraInfo.sensorLandscapeRatio: Float
+    @OptIn(ExperimentalCamera2Interop::class)
+    get() = Camera2CameraInfo.from(this)
+        .getCameraCharacteristic(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE)
+        ?.let { sensorRect ->
+            if (sensorRect.width() > sensorRect.height()) {
+                sensorRect.width().toFloat() / sensorRect.height()
+            } else {
+                sensorRect.height().toFloat() / sensorRect.width()
+            }
+        } ?: Float.NaN
+
+@OptIn(ExperimentalImageCaptureOutputFormat::class)
+fun Int.toAppImageFormat(): ImageOutputFormat? {
+    return when (this) {
+        ImageCapture.OUTPUT_FORMAT_JPEG -> ImageOutputFormat.JPEG
+        ImageCapture.OUTPUT_FORMAT_JPEG_ULTRA_HDR -> ImageOutputFormat.JPEG_ULTRA_HDR
+        // All other output formats unsupported. Return null.
+        else -> null
+    }
+}
+
+/**
+ * Checks if preview stabilization is supported by the device.
+ *
+ */
+val CameraInfo.isPreviewStabilizationSupported: Boolean
+    get() = Preview.getPreviewCapabilities(this).isStabilizationSupported
+
+/**
+ * Checks if video stabilization is supported by the device.
+ *
+ */
+val CameraInfo.isVideoStabilizationSupported: Boolean
+    get() = Recorder.getVideoCapabilities(this).isStabilizationSupported
+
+fun CameraInfo.filterSupportedFixedFrameRates(desired: Set<Int>): Set<Int> {
+    return buildSet {
+        this@filterSupportedFixedFrameRates.supportedFrameRateRanges.forEach { e ->
+            if (e.upper == e.lower && desired.contains(e.upper)) {
+                add(e.upper)
+            }
+        }
+    }
+}
+
+val CameraInfo.supportedImageFormats: Set<ImageOutputFormat>
+    @OptIn(ExperimentalImageCaptureOutputFormat::class)
+    get() = ImageCapture.getImageCaptureCapabilities(this).supportedOutputFormats
+        .mapNotNull(Int::toAppImageFormat)
+        .toSet()
+
+fun UseCaseGroup.getVideoCapture() = getUseCaseOrNull<VideoCapture<Recorder>>()
+fun UseCaseGroup.getImageCapture() = getUseCaseOrNull<ImageCapture>()
+
+private inline fun <reified T : UseCase> UseCaseGroup.getUseCaseOrNull(): T? {
+    return useCases.filterIsInstance<T>().singleOrNull()
+}
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraModule.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraModule.kt
similarity index 95%
rename from domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraModule.kt
rename to core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraModule.kt
index a2348ac..db2e167 100644
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraModule.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraModule.kt
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.domain.camera
+package com.google.jetpackcamera.core.camera
 
 import dagger.Binds
 import dagger.Module
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
new file mode 100644
index 0000000..fbed566
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
@@ -0,0 +1,728 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.Manifest
+import android.content.ContentValues
+import android.content.Context
+import android.content.pm.PackageManager
+import android.hardware.camera2.CameraCaptureSession
+import android.hardware.camera2.CaptureRequest
+import android.hardware.camera2.CaptureResult
+import android.hardware.camera2.TotalCaptureResult
+import android.net.Uri
+import android.os.Build
+import android.os.SystemClock
+import android.provider.MediaStore
+import android.util.Log
+import android.util.Range
+import androidx.annotation.OptIn
+import androidx.camera.camera2.interop.Camera2CameraInfo
+import androidx.camera.camera2.interop.Camera2Interop
+import androidx.camera.camera2.interop.ExperimentalCamera2Interop
+import androidx.camera.core.Camera
+import androidx.camera.core.CameraControl
+import androidx.camera.core.CameraEffect
+import androidx.camera.core.CameraInfo
+import androidx.camera.core.CameraSelector
+import androidx.camera.core.ExperimentalImageCaptureOutputFormat
+import androidx.camera.core.FocusMeteringAction
+import androidx.camera.core.ImageCapture
+import androidx.camera.core.Preview
+import androidx.camera.core.SurfaceOrientedMeteringPointFactory
+import androidx.camera.core.TorchState
+import androidx.camera.core.UseCaseGroup
+import androidx.camera.core.ViewPort
+import androidx.camera.core.resolutionselector.AspectRatioStrategy
+import androidx.camera.core.resolutionselector.ResolutionSelector
+import androidx.camera.video.FileOutputOptions
+import androidx.camera.video.MediaStoreOutputOptions
+import androidx.camera.video.Recorder
+import androidx.camera.video.Recording
+import androidx.camera.video.VideoCapture
+import androidx.camera.video.VideoRecordEvent
+import androidx.camera.video.VideoRecordEvent.Finalize.ERROR_NONE
+import androidx.concurrent.futures.await
+import androidx.core.content.ContextCompat
+import androidx.core.content.ContextCompat.checkSelfPermission
+import androidx.lifecycle.asFlow
+import com.google.jetpackcamera.core.camera.effects.SingleSurfaceForcingEffect
+import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.DeviceRotation
+import com.google.jetpackcamera.settings.model.DynamicRange
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.Stabilization
+import java.io.File
+import java.util.Date
+import java.util.concurrent.Executor
+import kotlin.coroutines.ContinuationInterceptor
+import kotlin.math.abs
+import kotlinx.atomicfu.atomic
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineStart
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.asExecutor
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.currentCoroutineContext
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onCompletion
+import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.launch
+
+private const val TAG = "CameraSession"
+
+context(CameraSessionContext)
+internal suspend fun runSingleCameraSession(
+    sessionSettings: PerpetualSessionSettings.SingleCamera,
+    useCaseMode: CameraUseCase.UseCaseMode,
+    // TODO(tm): ImageCapture should go through an event channel like VideoCapture
+    onImageCaptureCreated: (ImageCapture) -> Unit = {}
+) = coroutineScope {
+    val lensFacing = sessionSettings.cameraInfo.appLensFacing
+    Log.d(TAG, "Starting new single camera session for $lensFacing")
+
+    val initialTransientSettings = transientSettings
+        .filterNotNull()
+        .first()
+
+    val useCaseGroup = createUseCaseGroup(
+        cameraInfo = sessionSettings.cameraInfo,
+        initialTransientSettings = initialTransientSettings,
+        stabilizePreviewMode = sessionSettings.stabilizePreviewMode,
+        stabilizeVideoMode = sessionSettings.stabilizeVideoMode,
+        aspectRatio = sessionSettings.aspectRatio,
+        targetFrameRate = sessionSettings.targetFrameRate,
+        dynamicRange = sessionSettings.dynamicRange,
+        imageFormat = sessionSettings.imageFormat,
+        useCaseMode = useCaseMode,
+        effect = when (sessionSettings.captureMode) {
+            CaptureMode.SINGLE_STREAM -> SingleSurfaceForcingEffect(this@coroutineScope)
+            CaptureMode.MULTI_STREAM -> null
+        }
+    ).apply {
+        getImageCapture()?.let(onImageCaptureCreated)
+    }
+
+    cameraProvider.runWith(sessionSettings.cameraInfo.cameraSelector, useCaseGroup) { camera ->
+        Log.d(TAG, "Camera session started")
+
+        launch {
+            processFocusMeteringEvents(camera.cameraControl)
+        }
+
+        launch {
+            processVideoControlEvents(
+                camera,
+                useCaseGroup.getVideoCapture(),
+                captureTypeSuffix = when (sessionSettings.captureMode) {
+                    CaptureMode.MULTI_STREAM -> "MultiStream"
+                    CaptureMode.SINGLE_STREAM -> "SingleStream"
+                }
+            )
+        }
+
+        launch {
+            camera.cameraInfo.torchState.asFlow().collectLatest { torchState ->
+                currentCameraState.update { old ->
+                    old.copy(torchEnabled = torchState == TorchState.ON)
+                }
+            }
+        }
+
+        applyDeviceRotation(initialTransientSettings.deviceRotation, useCaseGroup)
+        processTransientSettingEvents(
+            camera,
+            useCaseGroup,
+            initialTransientSettings,
+            transientSettings
+        )
+    }
+}
+
+context(CameraSessionContext)
+internal suspend fun processTransientSettingEvents(
+    camera: Camera,
+    useCaseGroup: UseCaseGroup,
+    initialTransientSettings: TransientSessionSettings,
+    transientSettings: StateFlow<TransientSessionSettings?>
+) {
+    var prevTransientSettings = initialTransientSettings
+    transientSettings.filterNotNull().collectLatest { newTransientSettings ->
+        // Apply camera control settings
+        if (prevTransientSettings.zoomScale != newTransientSettings.zoomScale) {
+            camera.cameraInfo.zoomState.value?.let { zoomState ->
+                val finalScale =
+                    (zoomState.zoomRatio * newTransientSettings.zoomScale).coerceIn(
+                        zoomState.minZoomRatio,
+                        zoomState.maxZoomRatio
+                    )
+                camera.cameraControl.setZoomRatio(finalScale)
+                currentCameraState.update { old ->
+                    old.copy(zoomScale = finalScale)
+                }
+            }
+        }
+
+        useCaseGroup.getImageCapture()?.let { imageCapture ->
+            if (prevTransientSettings.flashMode != newTransientSettings.flashMode) {
+                setFlashModeInternal(
+                    imageCapture = imageCapture,
+                    flashMode = newTransientSettings.flashMode,
+                    isFrontFacing = camera.cameraInfo.appLensFacing == LensFacing.FRONT
+                )
+            }
+        }
+
+        if (prevTransientSettings.deviceRotation
+            != newTransientSettings.deviceRotation
+        ) {
+            Log.d(
+                TAG,
+                "Updating device rotation from " +
+                    "${prevTransientSettings.deviceRotation} -> " +
+                    "${newTransientSettings.deviceRotation}"
+            )
+            applyDeviceRotation(newTransientSettings.deviceRotation, useCaseGroup)
+        }
+
+        prevTransientSettings = newTransientSettings
+    }
+}
+
+internal fun applyDeviceRotation(deviceRotation: DeviceRotation, useCaseGroup: UseCaseGroup) {
+    val targetRotation = deviceRotation.toUiSurfaceRotation()
+    useCaseGroup.useCases.forEach {
+        when (it) {
+            is Preview -> {
+                // Preview's target rotation should not be updated with device rotation.
+                // Instead, preview rotation should match the display rotation.
+                // When Preview is created, it is initialized with the display rotation.
+                // This will need to be updated separately if the display rotation is not
+                // locked. Currently the app is locked to portrait orientation.
+            }
+
+            is ImageCapture -> {
+                it.targetRotation = targetRotation
+            }
+
+            is VideoCapture<*> -> {
+                it.targetRotation = targetRotation
+            }
+        }
+    }
+}
+
+context(CameraSessionContext)
+internal fun createUseCaseGroup(
+    cameraInfo: CameraInfo,
+    initialTransientSettings: TransientSessionSettings,
+    stabilizePreviewMode: Stabilization,
+    stabilizeVideoMode: Stabilization,
+    aspectRatio: AspectRatio,
+    targetFrameRate: Int,
+    dynamicRange: DynamicRange,
+    imageFormat: ImageOutputFormat,
+    useCaseMode: CameraUseCase.UseCaseMode,
+    effect: CameraEffect? = null
+): UseCaseGroup {
+    val previewUseCase =
+        createPreviewUseCase(
+            cameraInfo,
+            aspectRatio,
+            stabilizePreviewMode
+        )
+    val imageCaptureUseCase = if (useCaseMode != CameraUseCase.UseCaseMode.VIDEO_ONLY) {
+        createImageUseCase(cameraInfo, aspectRatio, dynamicRange, imageFormat)
+    } else {
+        null
+    }
+    val videoCaptureUseCase = if (useCaseMode != CameraUseCase.UseCaseMode.IMAGE_ONLY) {
+        createVideoUseCase(
+            cameraInfo,
+            aspectRatio,
+            targetFrameRate,
+            stabilizeVideoMode,
+            dynamicRange,
+            backgroundDispatcher
+        )
+    } else {
+        null
+    }
+
+    imageCaptureUseCase?.let {
+        setFlashModeInternal(
+            imageCapture = imageCaptureUseCase,
+            flashMode = initialTransientSettings.flashMode,
+            isFrontFacing = cameraInfo.appLensFacing == LensFacing.FRONT
+        )
+    }
+
+    return UseCaseGroup.Builder().apply {
+        Log.d(
+            TAG,
+            "Setting initial device rotation to ${initialTransientSettings.deviceRotation}"
+        )
+        setViewPort(
+            ViewPort.Builder(
+                aspectRatio.ratio,
+                // Initialize rotation to Preview's rotation, which comes from Display rotation
+                previewUseCase.targetRotation
+            ).build()
+        )
+        addUseCase(previewUseCase)
+        imageCaptureUseCase?.let {
+            if (dynamicRange == DynamicRange.SDR ||
+                imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+            ) {
+                addUseCase(imageCaptureUseCase)
+            }
+        }
+
+        // Not to bind VideoCapture when Ultra HDR is enabled to keep the app design simple.
+        videoCaptureUseCase?.let {
+            if (imageFormat == ImageOutputFormat.JPEG) {
+                addUseCase(videoCaptureUseCase)
+            }
+        }
+
+        effect?.let { addEffect(it) }
+    }.build()
+}
+
+@OptIn(ExperimentalImageCaptureOutputFormat::class)
+private fun createImageUseCase(
+    cameraInfo: CameraInfo,
+    aspectRatio: AspectRatio,
+    dynamicRange: DynamicRange,
+    imageFormat: ImageOutputFormat
+): ImageCapture {
+    val builder = ImageCapture.Builder()
+    builder.setResolutionSelector(
+        getResolutionSelector(cameraInfo.sensorLandscapeRatio, aspectRatio)
+    )
+    if (dynamicRange != DynamicRange.SDR && imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+    ) {
+        builder.setOutputFormat(ImageCapture.OUTPUT_FORMAT_JPEG_ULTRA_HDR)
+    }
+    return builder.build()
+}
+
+private fun createVideoUseCase(
+    cameraInfo: CameraInfo,
+    aspectRatio: AspectRatio,
+    targetFrameRate: Int,
+    stabilizeVideoMode: Stabilization,
+    dynamicRange: DynamicRange,
+    backgroundDispatcher: CoroutineDispatcher
+): VideoCapture<Recorder> {
+    val sensorLandscapeRatio = cameraInfo.sensorLandscapeRatio
+    val recorder = Recorder.Builder()
+        .setAspectRatio(
+            getAspectRatioForUseCase(sensorLandscapeRatio, aspectRatio)
+        )
+        .setExecutor(backgroundDispatcher.asExecutor()).build()
+    return VideoCapture.Builder(recorder).apply {
+        // set video stabilization
+        if (stabilizeVideoMode == Stabilization.ON) {
+            setVideoStabilizationEnabled(true)
+        }
+        // set target fps
+        if (targetFrameRate != TARGET_FPS_AUTO) {
+            setTargetFrameRate(Range(targetFrameRate, targetFrameRate))
+        }
+
+        setDynamicRange(dynamicRange.toCXDynamicRange())
+    }.build()
+}
+
+private fun getAspectRatioForUseCase(sensorLandscapeRatio: Float, aspectRatio: AspectRatio): Int {
+    return when (aspectRatio) {
+        AspectRatio.THREE_FOUR -> androidx.camera.core.AspectRatio.RATIO_4_3
+        AspectRatio.NINE_SIXTEEN -> androidx.camera.core.AspectRatio.RATIO_16_9
+        else -> {
+            // Choose the aspect ratio which maximizes FOV by being closest to the sensor ratio
+            if (
+                abs(sensorLandscapeRatio - AspectRatio.NINE_SIXTEEN.landscapeRatio.toFloat()) <
+                abs(sensorLandscapeRatio - AspectRatio.THREE_FOUR.landscapeRatio.toFloat())
+            ) {
+                androidx.camera.core.AspectRatio.RATIO_16_9
+            } else {
+                androidx.camera.core.AspectRatio.RATIO_4_3
+            }
+        }
+    }
+}
+
+context(CameraSessionContext)
+private fun createPreviewUseCase(
+    cameraInfo: CameraInfo,
+    aspectRatio: AspectRatio,
+    stabilizePreviewMode: Stabilization
+): Preview = Preview.Builder().apply {
+    updateCameraStateWithCaptureResults(targetCameraInfo = cameraInfo)
+
+    // set preview stabilization
+    if (stabilizePreviewMode == Stabilization.ON) {
+        setPreviewStabilizationEnabled(true)
+    }
+
+    setResolutionSelector(
+        getResolutionSelector(cameraInfo.sensorLandscapeRatio, aspectRatio)
+    )
+}.build()
+    .apply {
+        setSurfaceProvider { surfaceRequest ->
+            surfaceRequests.update { surfaceRequest }
+        }
+    }
+
+private fun getResolutionSelector(
+    sensorLandscapeRatio: Float,
+    aspectRatio: AspectRatio
+): ResolutionSelector {
+    val aspectRatioStrategy = when (aspectRatio) {
+        AspectRatio.THREE_FOUR -> AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
+        AspectRatio.NINE_SIXTEEN -> AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
+        else -> {
+            // Choose the resolution selector strategy which maximizes FOV by being closest
+            // to the sensor aspect ratio
+            if (
+                abs(sensorLandscapeRatio - AspectRatio.NINE_SIXTEEN.landscapeRatio.toFloat()) <
+                abs(sensorLandscapeRatio - AspectRatio.THREE_FOUR.landscapeRatio.toFloat())
+            ) {
+                AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
+            } else {
+                AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
+            }
+        }
+    }
+    return ResolutionSelector.Builder().setAspectRatioStrategy(aspectRatioStrategy).build()
+}
+
+context(CameraSessionContext)
+private fun setFlashModeInternal(
+    imageCapture: ImageCapture,
+    flashMode: FlashMode,
+    isFrontFacing: Boolean
+) {
+    val isScreenFlashRequired =
+        isFrontFacing && (flashMode == FlashMode.ON || flashMode == FlashMode.AUTO)
+
+    if (isScreenFlashRequired) {
+        imageCapture.screenFlash = object : ImageCapture.ScreenFlash {
+            override fun apply(
+                expirationTimeMillis: Long,
+                listener: ImageCapture.ScreenFlashListener
+            ) {
+                Log.d(TAG, "ImageCapture.ScreenFlash: apply")
+                screenFlashEvents.trySend(
+                    CameraUseCase.ScreenFlashEvent(CameraUseCase.ScreenFlashEvent.Type.APPLY_UI) {
+                        listener.onCompleted()
+                    }
+                )
+            }
+
+            override fun clear() {
+                Log.d(TAG, "ImageCapture.ScreenFlash: clear")
+                screenFlashEvents.trySend(
+                    CameraUseCase.ScreenFlashEvent(CameraUseCase.ScreenFlashEvent.Type.CLEAR_UI) {}
+                )
+            }
+        }
+    }
+
+    imageCapture.flashMode = when (flashMode) {
+        FlashMode.OFF -> ImageCapture.FLASH_MODE_OFF // 2
+
+        FlashMode.ON -> if (isScreenFlashRequired) {
+            ImageCapture.FLASH_MODE_SCREEN // 3
+        } else {
+            ImageCapture.FLASH_MODE_ON // 1
+        }
+
+        FlashMode.AUTO -> if (isScreenFlashRequired) {
+            ImageCapture.FLASH_MODE_SCREEN // 3
+        } else {
+            ImageCapture.FLASH_MODE_AUTO // 0
+        }
+    }
+    Log.d(TAG, "Set flash mode to: ${imageCapture.flashMode}")
+}
+
+private suspend fun startVideoRecordingInternal(
+    initialMuted: Boolean,
+    videoCaptureUseCase: VideoCapture<Recorder>,
+    captureTypeSuffix: String,
+    context: Context,
+    videoCaptureUri: Uri?,
+    shouldUseUri: Boolean,
+    onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+): Recording {
+    Log.d(TAG, "recordVideo")
+    // todo(b/336886716): default setting to enable or disable audio when permission is granted
+
+    // ok. there is a difference between MUTING and ENABLING audio
+    // audio must be enabled in order to be muted
+    // if the video recording isnt started with audio enabled, you will not be able to unmute it
+    // the toggle should only affect whether or not the audio is muted.
+    // the permission will determine whether or not the audio is enabled.
+    val audioEnabled = checkSelfPermission(
+        context,
+        Manifest.permission.RECORD_AUDIO
+    ) == PackageManager.PERMISSION_GRANTED
+
+    val pendingRecord = if (shouldUseUri) {
+        val fileOutputOptions = FileOutputOptions.Builder(
+            File(videoCaptureUri!!.path!!)
+        ).build()
+        videoCaptureUseCase.output.prepareRecording(context, fileOutputOptions)
+    } else {
+        val name = "JCA-recording-${Date()}-$captureTypeSuffix.mp4"
+        val contentValues =
+            ContentValues().apply {
+                put(MediaStore.Video.Media.DISPLAY_NAME, name)
+            }
+        val mediaStoreOutput =
+            MediaStoreOutputOptions.Builder(
+                context.contentResolver,
+                MediaStore.Video.Media.EXTERNAL_CONTENT_URI
+            )
+                .setContentValues(contentValues)
+                .build()
+        videoCaptureUseCase.output.prepareRecording(context, mediaStoreOutput)
+    }
+    pendingRecord.apply {
+        if (audioEnabled) {
+            withAudioEnabled()
+        }
+    }
+    val callbackExecutor: Executor =
+        (
+            currentCoroutineContext()[ContinuationInterceptor] as?
+                CoroutineDispatcher
+            )?.asExecutor() ?: ContextCompat.getMainExecutor(context)
+    return pendingRecord.start(callbackExecutor) { onVideoRecordEvent ->
+        Log.d(TAG, onVideoRecordEvent.toString())
+        when (onVideoRecordEvent) {
+            is VideoRecordEvent.Finalize -> {
+                when (onVideoRecordEvent.error) {
+                    ERROR_NONE ->
+                        onVideoRecord(
+                            CameraUseCase.OnVideoRecordEvent.OnVideoRecorded(
+                                onVideoRecordEvent.outputResults.outputUri
+                            )
+                        )
+
+                    else ->
+                        onVideoRecord(
+                            CameraUseCase.OnVideoRecordEvent.OnVideoRecordError(
+                                onVideoRecordEvent.cause
+                            )
+                        )
+                }
+            }
+
+            is VideoRecordEvent.Status -> {
+                onVideoRecord(
+                    CameraUseCase.OnVideoRecordEvent.OnVideoRecordStatus(
+                        onVideoRecordEvent.recordingStats.audioStats
+                            .audioAmplitude
+                    )
+                )
+            }
+        }
+    }.apply {
+        mute(initialMuted)
+    }
+}
+
+private suspend fun runVideoRecording(
+    camera: Camera,
+    videoCapture: VideoCapture<Recorder>,
+    captureTypeSuffix: String,
+    context: Context,
+    transientSettings: StateFlow<TransientSessionSettings?>,
+    videoCaptureUri: Uri?,
+    shouldUseUri: Boolean,
+    onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+) {
+    var currentSettings = transientSettings.filterNotNull().first()
+
+    startVideoRecordingInternal(
+        initialMuted = currentSettings.audioMuted,
+        videoCapture,
+        captureTypeSuffix,
+        context,
+        videoCaptureUri,
+        shouldUseUri,
+        onVideoRecord
+    ).use { recording ->
+
+        fun TransientSessionSettings.isFlashModeOn() = flashMode == FlashMode.ON
+        val isFrontCameraSelector =
+            camera.cameraInfo.cameraSelector == CameraSelector.DEFAULT_FRONT_CAMERA
+
+        if (currentSettings.isFlashModeOn()) {
+            if (!isFrontCameraSelector) {
+                camera.cameraControl.enableTorch(true).await()
+            } else {
+                Log.d(TAG, "Unable to enable torch for front camera.")
+            }
+        }
+
+        transientSettings.filterNotNull()
+            .onCompletion {
+                // Could do some fancier tracking of whether the torch was enabled before
+                // calling this.
+                camera.cameraControl.enableTorch(false)
+            }
+            .collectLatest { newTransientSettings ->
+                if (currentSettings.audioMuted != newTransientSettings.audioMuted) {
+                    recording.mute(newTransientSettings.audioMuted)
+                }
+                if (currentSettings.isFlashModeOn() != newTransientSettings.isFlashModeOn()) {
+                    if (!isFrontCameraSelector) {
+                        camera.cameraControl.enableTorch(newTransientSettings.isFlashModeOn())
+                    } else {
+                        Log.d(TAG, "Unable to update torch for front camera.")
+                    }
+                }
+                currentSettings = newTransientSettings
+            }
+    }
+}
+
+context(CameraSessionContext)
+internal suspend fun processFocusMeteringEvents(cameraControl: CameraControl) {
+    surfaceRequests.map { surfaceRequest ->
+        surfaceRequest?.resolution?.run {
+            Log.d(
+                TAG,
+                "Waiting to process focus points for surface with resolution: " +
+                    "$width x $height"
+            )
+            SurfaceOrientedMeteringPointFactory(width.toFloat(), height.toFloat())
+        }
+    }.collectLatest { meteringPointFactory ->
+        for (event in focusMeteringEvents) {
+            meteringPointFactory?.apply {
+                Log.d(TAG, "tapToFocus, processing event: $event")
+                val meteringPoint = createPoint(event.x, event.y)
+                val action = FocusMeteringAction.Builder(meteringPoint).build()
+                cameraControl.startFocusAndMetering(action)
+            } ?: run {
+                Log.w(TAG, "Ignoring event due to no SurfaceRequest: $event")
+            }
+        }
+    }
+}
+
+context(CameraSessionContext)
+internal suspend fun processVideoControlEvents(
+    camera: Camera,
+    videoCapture: VideoCapture<Recorder>?,
+    captureTypeSuffix: String
+) = coroutineScope {
+    var recordingJob: Job? = null
+
+    for (event in videoCaptureControlEvents) {
+        when (event) {
+            is VideoCaptureControlEvent.StartRecordingEvent -> {
+                if (videoCapture == null) {
+                    throw RuntimeException(
+                        "Attempted video recording with null videoCapture"
+                    )
+                }
+
+                recordingJob = launch(start = CoroutineStart.UNDISPATCHED) {
+                    runVideoRecording(
+                        camera,
+                        videoCapture,
+                        captureTypeSuffix,
+                        context,
+                        transientSettings,
+                        event.videoCaptureUri,
+                        event.shouldUseUri,
+                        event.onVideoRecord
+                    )
+                }
+            }
+
+            VideoCaptureControlEvent.StopRecordingEvent -> {
+                recordingJob?.cancel()
+                recordingJob = null
+            }
+        }
+    }
+}
+
+/**
+ * Applies a CaptureCallback to the provided image capture builder
+ */
+context(CameraSessionContext)
+@OptIn(ExperimentalCamera2Interop::class)
+private fun Preview.Builder.updateCameraStateWithCaptureResults(
+    targetCameraInfo: CameraInfo
+): Preview.Builder {
+    val isFirstFrameTimestampUpdated = atomic(false)
+    val targetCameraLogicalId = Camera2CameraInfo.from(targetCameraInfo).cameraId
+    Camera2Interop.Extender(this).setSessionCaptureCallback(
+        object : CameraCaptureSession.CaptureCallback() {
+            override fun onCaptureCompleted(
+                session: CameraCaptureSession,
+                request: CaptureRequest,
+                result: TotalCaptureResult
+            ) {
+                super.onCaptureCompleted(session, request, result)
+                val logicalCameraId = session.device.id
+                if (logicalCameraId != targetCameraLogicalId) return
+                try {
+                    val physicalCameraId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
+                        result.get(CaptureResult.LOGICAL_MULTI_CAMERA_ACTIVE_PHYSICAL_ID)
+                    } else {
+                        null
+                    }
+                    currentCameraState.update { old ->
+                        if (old.debugInfo.logicalCameraId != logicalCameraId ||
+                            old.debugInfo.physicalCameraId != physicalCameraId
+                        ) {
+                            old.copy(debugInfo = DebugInfo(logicalCameraId, physicalCameraId))
+                        } else {
+                            old
+                        }
+                    }
+                    if (!isFirstFrameTimestampUpdated.value) {
+                        currentCameraState.update { old ->
+                            old.copy(
+                                sessionFirstFrameTimestamp = SystemClock.elapsedRealtimeNanos()
+                            )
+                        }
+                        isFirstFrameTimestampUpdated.value = true
+                    }
+                } catch (_: Exception) {
+                }
+            }
+        }
+    )
+    return this
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
new file mode 100644
index 0000000..1425bbb
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
@@ -0,0 +1,43 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.content.Context
+import androidx.camera.core.SurfaceRequest
+import androidx.camera.lifecycle.ProcessCameraProvider
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.channels.Channel
+import kotlinx.coroutines.channels.SendChannel
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+
+/**
+ * Context that can be shared by all functions in a camera session.
+ *
+ * Can be used to confer context (such as reactive state or session-wide parameters)
+ * on context receivers using [with] in a camera session.
+ */
+internal data class CameraSessionContext(
+    val context: Context,
+    val cameraProvider: ProcessCameraProvider,
+    val backgroundDispatcher: CoroutineDispatcher,
+    val screenFlashEvents: SendChannel<CameraUseCase.ScreenFlashEvent>,
+    val focusMeteringEvents: Channel<CameraEvent.FocusMeteringEvent>,
+    val videoCaptureControlEvents: Channel<VideoCaptureControlEvent>,
+    val currentCameraState: MutableStateFlow<CameraState>,
+    val surfaceRequests: MutableStateFlow<SurfaceRequest?>,
+    val transientSettings: StateFlow<TransientSessionSettings?>
+)
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
new file mode 100644
index 0000000..b96c6a3
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
@@ -0,0 +1,66 @@
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
+package com.google.jetpackcamera.core.camera
+
+import androidx.camera.core.CameraInfo
+import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.DeviceRotation
+import com.google.jetpackcamera.settings.model.DynamicRange
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.Stabilization
+
+/**
+ * Camera settings that persist as long as a camera is running.
+ *
+ * Any change in these settings will require calling [ProcessCameraProvider.runWith] with
+ * updates [CameraSelector] and/or [UseCaseGroup]
+ */
+internal sealed interface PerpetualSessionSettings {
+    val aspectRatio: AspectRatio
+
+    data class SingleCamera(
+        val cameraInfo: CameraInfo,
+        override val aspectRatio: AspectRatio,
+        val captureMode: CaptureMode,
+        val targetFrameRate: Int,
+        val stabilizePreviewMode: Stabilization,
+        val stabilizeVideoMode: Stabilization,
+        val dynamicRange: DynamicRange,
+        val imageFormat: ImageOutputFormat
+    ) : PerpetualSessionSettings
+
+    data class ConcurrentCamera(
+        val primaryCameraInfo: CameraInfo,
+        val secondaryCameraInfo: CameraInfo,
+        override val aspectRatio: AspectRatio
+    ) : PerpetualSessionSettings
+}
+
+/**
+ * Camera settings that can change while the camera is running.
+ *
+ * Any changes in these settings can be applied either directly to use cases via their
+ * setter methods or to [androidx.camera.core.CameraControl].
+ * The use cases typically will not need to be re-bound.
+ */
+internal data class TransientSessionSettings(
+    val audioMuted: Boolean,
+    val deviceRotation: DeviceRotation,
+    val flashMode: FlashMode,
+    val zoomScale: Float
+)
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
similarity index 61%
rename from domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraUseCase.kt
rename to core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
index 9cf1fc4..02477d8 100644
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
@@ -13,20 +13,24 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.domain.camera
+package com.google.jetpackcamera.core.camera
 
 import android.content.ContentResolver
 import android.net.Uri
-import android.view.Display
 import androidx.camera.core.ImageCapture
 import androidx.camera.core.SurfaceRequest
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.settings.model.DeviceRotation
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import kotlinx.coroutines.flow.SharedFlow
+import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.Stabilization
+import kotlinx.coroutines.channels.ReceiveChannel
 import kotlinx.coroutines.flow.StateFlow
 
 /**
@@ -38,7 +42,11 @@ interface CameraUseCase {
      *
      * @return list of available lenses.
      */
-    suspend fun initialize(disableVideoCapture: Boolean)
+    suspend fun initialize(
+        cameraAppSettings: CameraAppSettings,
+        useCaseMode: UseCaseMode,
+        isDebugMode: Boolean = false
+    )
 
     /**
      * Starts the camera.
@@ -64,17 +72,21 @@ interface CameraUseCase {
         ignoreUri: Boolean = false
     ): ImageCapture.OutputFileResults
 
-    suspend fun startVideoRecording(onVideoRecord: (OnVideoRecordEvent) -> Unit)
+    suspend fun startVideoRecording(
+        videoCaptureUri: Uri?,
+        shouldUseUri: Boolean,
+        onVideoRecord: (OnVideoRecordEvent) -> Unit
+    )
 
     fun stopVideoRecording()
 
     fun setZoomScale(scale: Float)
 
-    fun getZoomScale(): StateFlow<Float>
+    fun getCurrentCameraState(): StateFlow<CameraState>
 
     fun getSurfaceRequest(): StateFlow<SurfaceRequest?>
 
-    fun getScreenFlashEvents(): SharedFlow<ScreenFlashEvent>
+    fun getScreenFlashEvents(): ReceiveChannel<ScreenFlashEvent>
 
     fun getCurrentSettings(): StateFlow<CameraAppSettings?>
 
@@ -86,12 +98,28 @@ interface CameraUseCase {
 
     suspend fun setLensFacing(lensFacing: LensFacing)
 
-    fun tapToFocus(display: Display, surfaceWidth: Int, surfaceHeight: Int, x: Float, y: Float)
+    suspend fun tapToFocus(x: Float, y: Float)
 
     suspend fun setCaptureMode(captureMode: CaptureMode)
 
     suspend fun setDynamicRange(dynamicRange: DynamicRange)
 
+    fun setDeviceRotation(deviceRotation: DeviceRotation)
+
+    suspend fun setConcurrentCameraMode(concurrentCameraMode: ConcurrentCameraMode)
+
+    suspend fun setLowLightBoost(lowLightBoost: LowLightBoost)
+
+    suspend fun setImageFormat(imageFormat: ImageOutputFormat)
+
+    suspend fun setAudioMuted(isAudioMuted: Boolean)
+
+    suspend fun setVideoCaptureStabilization(videoCaptureStabilization: Stabilization)
+
+    suspend fun setPreviewStabilization(previewStabilization: Stabilization)
+
+    suspend fun setTargetFrameRate(targetFrameRate: Int)
+
     /**
      * Represents the events required for screen flash.
      */
@@ -106,10 +134,25 @@ interface CameraUseCase {
      * Represents the events for video recording.
      */
     sealed interface OnVideoRecordEvent {
-        object OnVideoRecorded : OnVideoRecordEvent
+        data class OnVideoRecorded(val savedUri: Uri) : OnVideoRecordEvent
 
         data class OnVideoRecordStatus(val audioAmplitude: Double) : OnVideoRecordEvent
 
-        object OnVideoRecordError : OnVideoRecordEvent
+        data class OnVideoRecordError(val error: Throwable?) : OnVideoRecordEvent
+    }
+
+    enum class UseCaseMode {
+        STANDARD,
+        IMAGE_ONLY,
+        VIDEO_ONLY
     }
 }
+
+data class CameraState(
+    val zoomScale: Float = 1f,
+    val sessionFirstFrameTimestamp: Long = 0L,
+    val torchEnabled: Boolean = false,
+    val debugInfo: DebugInfo = DebugInfo(null, null)
+)
+
+data class DebugInfo(val logicalCameraId: String?, val physicalCameraId: String?)
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
new file mode 100644
index 0000000..2f7f99a
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
@@ -0,0 +1,651 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.app.Application
+import android.content.ContentResolver
+import android.content.ContentValues
+import android.net.Uri
+import android.os.Build
+import android.os.Environment
+import android.os.Environment.DIRECTORY_DOCUMENTS
+import android.provider.MediaStore
+import android.util.Log
+import androidx.camera.core.CameraInfo
+import androidx.camera.core.CameraSelector
+import androidx.camera.core.DynamicRange as CXDynamicRange
+import androidx.camera.core.ImageCapture
+import androidx.camera.core.ImageCapture.OutputFileOptions
+import androidx.camera.core.ImageCaptureException
+import androidx.camera.core.SurfaceRequest
+import androidx.camera.core.takePicture
+import androidx.camera.lifecycle.ProcessCameraProvider
+import androidx.camera.lifecycle.awaitInstance
+import androidx.camera.video.Recorder
+import com.google.jetpackcamera.core.camera.DebugCameraInfoUtil.getAllCamerasPropertiesJSONArray
+import com.google.jetpackcamera.core.camera.DebugCameraInfoUtil.writeFileExternalStorage
+import com.google.jetpackcamera.core.common.DefaultDispatcher
+import com.google.jetpackcamera.core.common.IODispatcher
+import com.google.jetpackcamera.settings.SettableConstraintsRepository
+import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.CameraConstraints
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.settings.model.DeviceRotation
+import com.google.jetpackcamera.settings.model.DynamicRange
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.SupportedStabilizationMode
+import com.google.jetpackcamera.settings.model.SystemConstraints
+import dagger.hilt.android.scopes.ViewModelScoped
+import java.io.File
+import java.io.FileNotFoundException
+import java.text.SimpleDateFormat
+import java.util.Calendar
+import java.util.Locale
+import javax.inject.Inject
+import kotlin.properties.Delegates
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.channels.Channel
+import kotlinx.coroutines.channels.trySendBlocking
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.withContext
+
+private const val TAG = "CameraXCameraUseCase"
+const val TARGET_FPS_AUTO = 0
+const val TARGET_FPS_15 = 15
+const val TARGET_FPS_30 = 30
+const val TARGET_FPS_60 = 60
+
+/**
+ * CameraX based implementation for [CameraUseCase]
+ */
+@ViewModelScoped
+class CameraXCameraUseCase
+@Inject
+constructor(
+    private val application: Application,
+    @DefaultDispatcher private val defaultDispatcher: CoroutineDispatcher,
+    @IODispatcher private val iODispatcher: CoroutineDispatcher,
+    private val constraintsRepository: SettableConstraintsRepository
+) : CameraUseCase {
+    private lateinit var cameraProvider: ProcessCameraProvider
+
+    private var imageCaptureUseCase: ImageCapture? = null
+
+    private lateinit var systemConstraints: SystemConstraints
+    private var useCaseMode by Delegates.notNull<CameraUseCase.UseCaseMode>()
+
+    private val screenFlashEvents: Channel<CameraUseCase.ScreenFlashEvent> =
+        Channel(capacity = Channel.UNLIMITED)
+    private val focusMeteringEvents =
+        Channel<CameraEvent.FocusMeteringEvent>(capacity = Channel.CONFLATED)
+    private val videoCaptureControlEvents = Channel<VideoCaptureControlEvent>()
+
+    private val currentSettings = MutableStateFlow<CameraAppSettings?>(null)
+
+    // Could be improved by setting initial value only when camera is initialized
+    private val _currentCameraState = MutableStateFlow(CameraState())
+    override fun getCurrentCameraState(): StateFlow<CameraState> = _currentCameraState.asStateFlow()
+
+    private val _surfaceRequest = MutableStateFlow<SurfaceRequest?>(null)
+    override fun getSurfaceRequest(): StateFlow<SurfaceRequest?> = _surfaceRequest.asStateFlow()
+
+    override suspend fun initialize(
+        cameraAppSettings: CameraAppSettings,
+        useCaseMode: CameraUseCase.UseCaseMode,
+        isDebugMode: Boolean
+    ) {
+        this.useCaseMode = useCaseMode
+        cameraProvider = ProcessCameraProvider.awaitInstance(application)
+
+        // updates values for available cameras
+        val availableCameraLenses =
+            listOf(
+                LensFacing.FRONT,
+                LensFacing.BACK
+            ).filter {
+                cameraProvider.hasCamera(it.toCameraSelector())
+            }
+
+        // Build and update the system constraints
+        systemConstraints = SystemConstraints(
+            availableLenses = availableCameraLenses,
+            concurrentCamerasSupported = cameraProvider.availableConcurrentCameraInfos.any {
+                it.map { cameraInfo -> cameraInfo.cameraSelector.toAppLensFacing() }
+                    .toSet() == setOf(LensFacing.FRONT, LensFacing.BACK)
+            },
+            perLensConstraints = buildMap {
+                val availableCameraInfos = cameraProvider.availableCameraInfos
+                for (lensFacing in availableCameraLenses) {
+                    val selector = lensFacing.toCameraSelector()
+                    selector.filter(availableCameraInfos).firstOrNull()?.let { camInfo ->
+                        val supportedDynamicRanges =
+                            Recorder.getVideoCapabilities(camInfo).supportedDynamicRanges
+                                .mapNotNull(CXDynamicRange::toSupportedAppDynamicRange)
+                                .toSet()
+
+                        val supportedStabilizationModes = buildSet {
+                            if (camInfo.isPreviewStabilizationSupported) {
+                                add(SupportedStabilizationMode.ON)
+                            }
+
+                            if (camInfo.isVideoStabilizationSupported) {
+                                add(SupportedStabilizationMode.HIGH_QUALITY)
+                            }
+                        }
+
+                        val supportedFixedFrameRates =
+                            camInfo.filterSupportedFixedFrameRates(FIXED_FRAME_RATES)
+                        val supportedImageFormats = camInfo.supportedImageFormats
+                        val hasFlashUnit = camInfo.hasFlashUnit()
+
+                        put(
+                            lensFacing,
+                            CameraConstraints(
+                                supportedStabilizationModes = supportedStabilizationModes,
+                                supportedFixedFrameRates = supportedFixedFrameRates,
+                                supportedDynamicRanges = supportedDynamicRanges,
+                                supportedImageFormatsMap = mapOf(
+                                    // Only JPEG is supported in single-stream mode, since
+                                    // single-stream mode uses CameraEffect, which does not support
+                                    // Ultra HDR now.
+                                    Pair(CaptureMode.SINGLE_STREAM, setOf(ImageOutputFormat.JPEG)),
+                                    Pair(CaptureMode.MULTI_STREAM, supportedImageFormats)
+                                ),
+                                hasFlashUnit = hasFlashUnit
+                            )
+                        )
+                    }
+                }
+            }
+        )
+
+        constraintsRepository.updateSystemConstraints(systemConstraints)
+
+        currentSettings.value =
+            cameraAppSettings
+                .tryApplyDynamicRangeConstraints()
+                .tryApplyAspectRatioForExternalCapture(this.useCaseMode)
+                .tryApplyImageFormatConstraints()
+                .tryApplyFrameRateConstraints()
+                .tryApplyStabilizationConstraints()
+                .tryApplyConcurrentCameraModeConstraints()
+        if (isDebugMode && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
+            withContext(iODispatcher) {
+                val cameraProperties =
+                    getAllCamerasPropertiesJSONArray(cameraProvider.availableCameraInfos).toString()
+                val file = File(
+                    Environment.getExternalStoragePublicDirectory(DIRECTORY_DOCUMENTS),
+                    "JCACameraProperties.json"
+                )
+                writeFileExternalStorage(file, cameraProperties)
+                Log.d(TAG, "JCACameraProperties written to ${file.path}. \n$cameraProperties")
+            }
+        }
+    }
+
+    override suspend fun runCamera() = coroutineScope {
+        Log.d(TAG, "runCamera")
+
+        val transientSettings = MutableStateFlow<TransientSessionSettings?>(null)
+        currentSettings
+            .filterNotNull()
+            .map { currentCameraSettings ->
+                transientSettings.value = TransientSessionSettings(
+                    audioMuted = currentCameraSettings.audioMuted,
+                    deviceRotation = currentCameraSettings.deviceRotation,
+                    flashMode = currentCameraSettings.flashMode,
+                    zoomScale = currentCameraSettings.zoomScale
+                )
+
+                when (currentCameraSettings.concurrentCameraMode) {
+                    ConcurrentCameraMode.OFF -> {
+                        val cameraSelector = when (currentCameraSettings.cameraLensFacing) {
+                            LensFacing.FRONT -> CameraSelector.DEFAULT_FRONT_CAMERA
+                            LensFacing.BACK -> CameraSelector.DEFAULT_BACK_CAMERA
+                        }
+
+                        PerpetualSessionSettings.SingleCamera(
+                            cameraInfo = cameraProvider.getCameraInfo(cameraSelector),
+                            aspectRatio = currentCameraSettings.aspectRatio,
+                            captureMode = currentCameraSettings.captureMode,
+                            targetFrameRate = currentCameraSettings.targetFrameRate,
+                            stabilizePreviewMode = currentCameraSettings.previewStabilization,
+                            stabilizeVideoMode = currentCameraSettings.videoCaptureStabilization,
+                            dynamicRange = currentCameraSettings.dynamicRange,
+                            imageFormat = currentCameraSettings.imageFormat
+                        )
+                    }
+                    ConcurrentCameraMode.DUAL -> {
+                        val primaryFacing = currentCameraSettings.cameraLensFacing
+                        val secondaryFacing = primaryFacing.flip()
+                        cameraProvider.availableConcurrentCameraInfos.firstNotNullOf {
+                            var primaryCameraInfo: CameraInfo? = null
+                            var secondaryCameraInfo: CameraInfo? = null
+                            it.forEach { cameraInfo ->
+                                if (cameraInfo.appLensFacing == primaryFacing) {
+                                    primaryCameraInfo = cameraInfo
+                                } else if (cameraInfo.appLensFacing == secondaryFacing) {
+                                    secondaryCameraInfo = cameraInfo
+                                }
+                            }
+
+                            primaryCameraInfo?.let { nonNullPrimary ->
+                                secondaryCameraInfo?.let { nonNullSecondary ->
+                                    PerpetualSessionSettings.ConcurrentCamera(
+                                        primaryCameraInfo = nonNullPrimary,
+                                        secondaryCameraInfo = nonNullSecondary,
+                                        aspectRatio = currentCameraSettings.aspectRatio
+                                    )
+                                }
+                            }
+                        }
+                    }
+                }
+            }.distinctUntilChanged()
+            .collectLatest { sessionSettings ->
+                coroutineScope {
+                    with(
+                        CameraSessionContext(
+                            context = application,
+                            cameraProvider = cameraProvider,
+                            backgroundDispatcher = defaultDispatcher,
+                            screenFlashEvents = screenFlashEvents,
+                            focusMeteringEvents = focusMeteringEvents,
+                            videoCaptureControlEvents = videoCaptureControlEvents,
+                            currentCameraState = _currentCameraState,
+                            surfaceRequests = _surfaceRequest,
+                            transientSettings = transientSettings
+                        )
+                    ) {
+                        try {
+                            when (sessionSettings) {
+                                is PerpetualSessionSettings.SingleCamera -> runSingleCameraSession(
+                                    sessionSettings,
+                                    useCaseMode = useCaseMode
+                                ) { imageCapture ->
+                                    imageCaptureUseCase = imageCapture
+                                }
+
+                                is PerpetualSessionSettings.ConcurrentCamera ->
+                                    runConcurrentCameraSession(
+                                        sessionSettings,
+                                        useCaseMode = CameraUseCase.UseCaseMode.VIDEO_ONLY
+                                    )
+                            }
+                        } finally {
+                            // TODO(tm): This shouldn't be necessary. Cancellation of the
+                            //  coroutineScope by collectLatest should cause this to
+                            //  occur naturally.
+                            cameraProvider.unbindAll()
+                        }
+                    }
+                }
+            }
+    }
+
+    override suspend fun takePicture(onCaptureStarted: (() -> Unit)) {
+        if (imageCaptureUseCase == null) {
+            throw RuntimeException("Attempted take picture with null imageCapture use case")
+        }
+        try {
+            val imageProxy = imageCaptureUseCase!!.takePicture(onCaptureStarted)
+            Log.d(TAG, "onCaptureSuccess")
+            imageProxy.close()
+        } catch (exception: Exception) {
+            Log.d(TAG, "takePicture onError: $exception")
+            throw exception
+        }
+    }
+
+    // TODO(b/319733374): Return bitmap for external mediastore capture without URI
+    override suspend fun takePicture(
+        onCaptureStarted: (() -> Unit),
+        contentResolver: ContentResolver,
+        imageCaptureUri: Uri?,
+        ignoreUri: Boolean
+    ): ImageCapture.OutputFileResults {
+        if (imageCaptureUseCase == null) {
+            throw RuntimeException("Attempted take picture with null imageCapture use case")
+        }
+        val eligibleContentValues = getEligibleContentValues()
+        val outputFileOptions: OutputFileOptions
+        if (ignoreUri) {
+            val formatter = SimpleDateFormat(
+                "yyyy-MM-dd-HH-mm-ss-SSS",
+                Locale.US
+            )
+            val filename = "JCA-${formatter.format(Calendar.getInstance().time)}.jpg"
+            val contentValues = ContentValues()
+            contentValues.put(MediaStore.MediaColumns.DISPLAY_NAME, filename)
+            contentValues.put(MediaStore.MediaColumns.MIME_TYPE, "image/jpeg")
+            outputFileOptions = OutputFileOptions.Builder(
+                contentResolver,
+                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+                contentValues
+            ).build()
+        } else if (imageCaptureUri == null) {
+            val e = RuntimeException("Null Uri is provided.")
+            Log.d(TAG, "takePicture onError: $e")
+            throw e
+        } else {
+            try {
+                val outputStream = contentResolver.openOutputStream(imageCaptureUri)
+                if (outputStream != null) {
+                    outputFileOptions =
+                        OutputFileOptions.Builder(
+                            contentResolver.openOutputStream(imageCaptureUri)!!
+                        ).build()
+                } else {
+                    val e = RuntimeException("Provider recently crashed.")
+                    Log.d(TAG, "takePicture onError: $e")
+                    throw e
+                }
+            } catch (e: FileNotFoundException) {
+                Log.d(TAG, "takePicture onError: $e")
+                throw e
+            }
+        }
+        try {
+            val outputFileResults = imageCaptureUseCase!!.takePicture(
+                outputFileOptions,
+                onCaptureStarted
+            )
+            val relativePath =
+                eligibleContentValues.getAsString(MediaStore.Images.Media.RELATIVE_PATH)
+            val displayName = eligibleContentValues.getAsString(
+                MediaStore.Images.Media.DISPLAY_NAME
+            )
+            Log.d(TAG, "Saved image to $relativePath/$displayName")
+            return outputFileResults
+        } catch (exception: ImageCaptureException) {
+            Log.d(TAG, "takePicture onError: $exception")
+            throw exception
+        }
+    }
+
+    private fun getEligibleContentValues(): ContentValues {
+        val eligibleContentValues = ContentValues()
+        eligibleContentValues.put(
+            MediaStore.Images.Media.DISPLAY_NAME,
+            Calendar.getInstance().time.toString()
+        )
+        eligibleContentValues.put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
+        eligibleContentValues.put(
+            MediaStore.Images.Media.RELATIVE_PATH,
+            Environment.DIRECTORY_PICTURES
+        )
+        return eligibleContentValues
+    }
+
+    override suspend fun startVideoRecording(
+        videoCaptureUri: Uri?,
+        shouldUseUri: Boolean,
+        onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+    ) {
+        if (shouldUseUri && videoCaptureUri == null) {
+            val e = RuntimeException("Null Uri is provided.")
+            Log.d(TAG, "takePicture onError: $e")
+            throw e
+        }
+        videoCaptureControlEvents.send(
+            VideoCaptureControlEvent.StartRecordingEvent(
+                videoCaptureUri,
+                shouldUseUri,
+                onVideoRecord
+            )
+        )
+    }
+
+    override fun stopVideoRecording() {
+        videoCaptureControlEvents.trySendBlocking(VideoCaptureControlEvent.StopRecordingEvent)
+    }
+
+    override fun setZoomScale(scale: Float) {
+        currentSettings.update { old ->
+            old?.copy(zoomScale = scale)
+        }
+    }
+
+    // Sets the camera to the designated lensFacing direction
+    override suspend fun setLensFacing(lensFacing: LensFacing) {
+        currentSettings.update { old ->
+            if (systemConstraints.availableLenses.contains(lensFacing)) {
+                old?.copy(cameraLensFacing = lensFacing)
+                    ?.tryApplyDynamicRangeConstraints()
+                    ?.tryApplyImageFormatConstraints()
+            } else {
+                old
+            }
+        }
+    }
+
+    private fun CameraAppSettings.tryApplyDynamicRangeConstraints(): CameraAppSettings {
+        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedDynamicRanges) {
+                val newDynamicRange = if (contains(dynamicRange)) {
+                    dynamicRange
+                } else {
+                    DynamicRange.SDR
+                }
+
+                this@tryApplyDynamicRangeConstraints.copy(
+                    dynamicRange = newDynamicRange
+                )
+            }
+        } ?: this
+    }
+
+    private fun CameraAppSettings.tryApplyAspectRatioForExternalCapture(
+        useCaseMode: CameraUseCase.UseCaseMode
+    ): CameraAppSettings {
+        return when (useCaseMode) {
+            CameraUseCase.UseCaseMode.STANDARD -> this
+            CameraUseCase.UseCaseMode.IMAGE_ONLY ->
+                this.copy(aspectRatio = AspectRatio.THREE_FOUR)
+
+            CameraUseCase.UseCaseMode.VIDEO_ONLY ->
+                this.copy(aspectRatio = AspectRatio.NINE_SIXTEEN)
+        }
+    }
+
+    private fun CameraAppSettings.tryApplyImageFormatConstraints(): CameraAppSettings {
+        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedImageFormatsMap[captureMode]) {
+                val newImageFormat = if (this != null && contains(imageFormat)) {
+                    imageFormat
+                } else {
+                    ImageOutputFormat.JPEG
+                }
+
+                this@tryApplyImageFormatConstraints.copy(
+                    imageFormat = newImageFormat
+                )
+            }
+        } ?: this
+    }
+
+    private fun CameraAppSettings.tryApplyFrameRateConstraints(): CameraAppSettings {
+        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedFixedFrameRates) {
+                val newTargetFrameRate = if (contains(targetFrameRate)) {
+                    targetFrameRate
+                } else {
+                    TARGET_FPS_AUTO
+                }
+
+                this@tryApplyFrameRateConstraints.copy(
+                    targetFrameRate = newTargetFrameRate
+                )
+            }
+        } ?: this
+    }
+
+    private fun CameraAppSettings.tryApplyStabilizationConstraints(): CameraAppSettings {
+        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedStabilizationModes) {
+                val newVideoStabilization = if (contains(SupportedStabilizationMode.HIGH_QUALITY) &&
+                    (targetFrameRate != TARGET_FPS_60)
+                ) {
+                    // unlike shouldVideoBeStabilized, doesn't check value of previewStabilization
+                    videoCaptureStabilization
+                } else {
+                    Stabilization.UNDEFINED
+                }
+                val newPreviewStabilization = if (contains(SupportedStabilizationMode.ON) &&
+                    (targetFrameRate in setOf(TARGET_FPS_AUTO, TARGET_FPS_30))
+                ) {
+                    previewStabilization
+                } else {
+                    Stabilization.UNDEFINED
+                }
+
+                this@tryApplyStabilizationConstraints.copy(
+                    previewStabilization = newPreviewStabilization,
+                    videoCaptureStabilization = newVideoStabilization
+                )
+            }
+        } ?: this
+    }
+
+    private fun CameraAppSettings.tryApplyConcurrentCameraModeConstraints(): CameraAppSettings =
+        when (concurrentCameraMode) {
+            ConcurrentCameraMode.OFF -> this
+            else ->
+                if (systemConstraints.concurrentCamerasSupported) {
+                    copy(
+                        targetFrameRate = TARGET_FPS_AUTO,
+                        previewStabilization = Stabilization.OFF,
+                        videoCaptureStabilization = Stabilization.OFF,
+                        dynamicRange = DynamicRange.SDR,
+                        captureMode = CaptureMode.MULTI_STREAM
+                    )
+                } else {
+                    copy(concurrentCameraMode = ConcurrentCameraMode.OFF)
+                }
+        }
+
+    override suspend fun tapToFocus(x: Float, y: Float) {
+        focusMeteringEvents.send(CameraEvent.FocusMeteringEvent(x, y))
+    }
+
+    override fun getScreenFlashEvents() = screenFlashEvents
+    override fun getCurrentSettings() = currentSettings.asStateFlow()
+
+    override fun setFlashMode(flashMode: FlashMode) {
+        currentSettings.update { old ->
+            old?.copy(flashMode = flashMode)
+        }
+    }
+
+    override fun isScreenFlashEnabled() =
+        imageCaptureUseCase?.flashMode == ImageCapture.FLASH_MODE_SCREEN &&
+            imageCaptureUseCase?.screenFlash != null
+
+    override suspend fun setAspectRatio(aspectRatio: AspectRatio) {
+        currentSettings.update { old ->
+            old?.copy(aspectRatio = aspectRatio)
+        }
+    }
+
+    override suspend fun setCaptureMode(captureMode: CaptureMode) {
+        currentSettings.update { old ->
+            old?.copy(captureMode = captureMode)
+                ?.tryApplyImageFormatConstraints()
+                ?.tryApplyConcurrentCameraModeConstraints()
+        }
+    }
+
+    override suspend fun setDynamicRange(dynamicRange: DynamicRange) {
+        currentSettings.update { old ->
+            old?.copy(dynamicRange = dynamicRange)
+                ?.tryApplyConcurrentCameraModeConstraints()
+        }
+    }
+
+    override fun setDeviceRotation(deviceRotation: DeviceRotation) {
+        currentSettings.update { old ->
+            old?.copy(deviceRotation = deviceRotation)
+        }
+    }
+
+    override suspend fun setConcurrentCameraMode(concurrentCameraMode: ConcurrentCameraMode) {
+        currentSettings.update { old ->
+            old?.copy(concurrentCameraMode = concurrentCameraMode)
+                ?.tryApplyConcurrentCameraModeConstraints()
+        }
+    }
+
+    override suspend fun setImageFormat(imageFormat: ImageOutputFormat) {
+        currentSettings.update { old ->
+            old?.copy(imageFormat = imageFormat)
+        }
+    }
+
+    override suspend fun setPreviewStabilization(previewStabilization: Stabilization) {
+        currentSettings.update { old ->
+            old?.copy(
+                previewStabilization = previewStabilization
+            )?.tryApplyStabilizationConstraints()
+                ?.tryApplyConcurrentCameraModeConstraints()
+        }
+    }
+
+    override suspend fun setVideoCaptureStabilization(videoCaptureStabilization: Stabilization) {
+        currentSettings.update { old ->
+            old?.copy(
+                videoCaptureStabilization = videoCaptureStabilization
+            )?.tryApplyStabilizationConstraints()
+                ?.tryApplyConcurrentCameraModeConstraints()
+        }
+    }
+
+    override suspend fun setTargetFrameRate(targetFrameRate: Int) {
+        currentSettings.update { old ->
+            old?.copy(targetFrameRate = targetFrameRate)?.tryApplyFrameRateConstraints()
+                ?.tryApplyConcurrentCameraModeConstraints()
+        }
+    }
+
+    override suspend fun setLowLightBoost(lowLightBoost: LowLightBoost) {
+        currentSettings.update { old ->
+            old?.copy(lowLightBoost = lowLightBoost)
+        }
+    }
+
+    override suspend fun setAudioMuted(isAudioMuted: Boolean) {
+        currentSettings.update { old ->
+            old?.copy(audioMuted = isAudioMuted)
+        }
+    }
+
+    companion object {
+        private val FIXED_FRAME_RATES = setOf(TARGET_FPS_15, TARGET_FPS_30, TARGET_FPS_60)
+    }
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
new file mode 100644
index 0000000..1ea84a1
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
@@ -0,0 +1,118 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.annotation.SuppressLint
+import android.util.Log
+import androidx.camera.core.CompositionSettings
+import androidx.camera.core.TorchState
+import androidx.lifecycle.asFlow
+import com.google.jetpackcamera.settings.model.DynamicRange
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.Stabilization
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.launch
+
+private const val TAG = "ConcurrentCameraSession"
+
+context(CameraSessionContext)
+@SuppressLint("RestrictedApi")
+internal suspend fun runConcurrentCameraSession(
+    sessionSettings: PerpetualSessionSettings.ConcurrentCamera,
+    useCaseMode: CameraUseCase.UseCaseMode
+) = coroutineScope {
+    val primaryLensFacing = sessionSettings.primaryCameraInfo.appLensFacing
+    val secondaryLensFacing = sessionSettings.secondaryCameraInfo.appLensFacing
+    Log.d(
+        TAG,
+        "Starting new concurrent camera session " +
+            "[primary: $primaryLensFacing, secondary: $secondaryLensFacing]"
+    )
+
+    val initialTransientSettings = transientSettings
+        .filterNotNull()
+        .first()
+
+    val useCaseGroup = createUseCaseGroup(
+        cameraInfo = sessionSettings.primaryCameraInfo,
+        initialTransientSettings = initialTransientSettings,
+        stabilizePreviewMode = Stabilization.OFF,
+        stabilizeVideoMode = Stabilization.OFF,
+        aspectRatio = sessionSettings.aspectRatio,
+        targetFrameRate = TARGET_FPS_AUTO,
+        dynamicRange = DynamicRange.SDR,
+        imageFormat = ImageOutputFormat.JPEG,
+        useCaseMode = useCaseMode
+    )
+
+    val cameraConfigs = listOf(
+        Pair(
+            sessionSettings.primaryCameraInfo.cameraSelector,
+            CompositionSettings.Builder()
+                .setAlpha(1.0f)
+                .setOffset(0.0f, 0.0f)
+                .setScale(1.0f, 1.0f)
+                .build()
+        ),
+        Pair(
+            sessionSettings.secondaryCameraInfo.cameraSelector,
+            CompositionSettings.Builder()
+                .setAlpha(1.0f)
+                .setOffset(2 / 3f - 0.1f, -2 / 3f + 0.1f)
+                .setScale(1 / 3f, 1 / 3f)
+                .build()
+        )
+    )
+
+    cameraProvider.runWithConcurrent(cameraConfigs, useCaseGroup) { concurrentCamera ->
+        Log.d(TAG, "Concurrent camera session started")
+        val primaryCamera = concurrentCamera.cameras.first {
+            it.cameraInfo.appLensFacing == sessionSettings.primaryCameraInfo.appLensFacing
+        }
+
+        launch {
+            processFocusMeteringEvents(primaryCamera.cameraControl)
+        }
+
+        launch {
+            processVideoControlEvents(
+                primaryCamera,
+                useCaseGroup.getVideoCapture(),
+                captureTypeSuffix = "DualCam"
+            )
+        }
+
+        launch {
+            sessionSettings.primaryCameraInfo.torchState.asFlow().collectLatest { torchState ->
+                currentCameraState.update { old ->
+                    old.copy(torchEnabled = torchState == TorchState.ON)
+                }
+            }
+        }
+
+        applyDeviceRotation(initialTransientSettings.deviceRotation, useCaseGroup)
+        processTransientSettingEvents(
+            primaryCamera,
+            useCaseGroup,
+            initialTransientSettings,
+            transientSettings
+        )
+    }
+}
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CoroutineCameraProvider.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CoroutineCameraProvider.kt
similarity index 75%
rename from domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CoroutineCameraProvider.kt
rename to core/camera/src/main/java/com/google/jetpackcamera/core/camera/CoroutineCameraProvider.kt
index a3c6c33..a6a032f 100644
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CoroutineCameraProvider.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CoroutineCameraProvider.kt
@@ -13,16 +13,21 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.domain.camera
+package com.google.jetpackcamera.core.camera
 
+import android.annotation.SuppressLint
 import androidx.camera.core.Camera
 import androidx.camera.core.CameraSelector
+import androidx.camera.core.CompositionSettings
+import androidx.camera.core.ConcurrentCamera
+import androidx.camera.core.ConcurrentCamera.SingleCameraConfig
 import androidx.camera.core.UseCaseGroup
 import androidx.camera.lifecycle.ProcessCameraProvider
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.LifecycleRegistry
 import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.coroutineScope
 
@@ -36,12 +41,25 @@ import kotlinx.coroutines.coroutineScope
 suspend fun <R> ProcessCameraProvider.runWith(
     cameraSelector: CameraSelector,
     useCases: UseCaseGroup,
-    block: suspend (Camera) -> R
+    block: suspend CoroutineScope.(Camera) -> R
 ): R = coroutineScope {
     val scopedLifecycle = CoroutineLifecycleOwner(coroutineContext)
     block(this@runWith.bindToLifecycle(scopedLifecycle, cameraSelector, useCases))
 }
 
+@SuppressLint("RestrictedApi")
+suspend fun <R> ProcessCameraProvider.runWithConcurrent(
+    cameraConfigs: List<Pair<CameraSelector, CompositionSettings>>,
+    useCaseGroup: UseCaseGroup,
+    block: suspend CoroutineScope.(ConcurrentCamera) -> R
+): R = coroutineScope {
+    val scopedLifecycle = CoroutineLifecycleOwner(coroutineContext)
+    val singleCameraConfigs = cameraConfigs.map {
+        SingleCameraConfig(it.first, useCaseGroup, it.second, scopedLifecycle)
+    }
+    block(this@runWithConcurrent.bindToLifecycle(singleCameraConfigs))
+}
+
 /**
  * A [LifecycleOwner] that follows the lifecycle of a coroutine.
  *
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/DebugCameraInfoUtil.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/DebugCameraInfoUtil.kt
new file mode 100644
index 0000000..cb3645e
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/DebugCameraInfoUtil.kt
@@ -0,0 +1,135 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.hardware.camera2.CameraCharacteristics
+import android.os.Build
+import android.os.Environment
+import androidx.annotation.OptIn
+import androidx.annotation.RequiresApi
+import androidx.camera.camera2.interop.Camera2CameraInfo
+import androidx.camera.camera2.interop.ExperimentalCamera2Interop
+import androidx.camera.core.CameraInfo
+import java.io.File
+import java.io.FileOutputStream
+import org.json.JSONArray
+import org.json.JSONObject
+
+private const val TAG = "DebugCameraInfoUtil"
+object DebugCameraInfoUtil {
+    @OptIn(ExperimentalCamera2Interop::class)
+    @RequiresApi(Build.VERSION_CODES.P)
+    fun getAllCamerasPropertiesJSONArray(cameraInfos: List<CameraInfo>): JSONArray {
+        val result = JSONArray()
+        for (cameraInfo in cameraInfos) {
+            var camera2CameraInfo = Camera2CameraInfo.from(cameraInfo)
+            val logicalCameraId = camera2CameraInfo.cameraId
+            val logicalCameraData = JSONObject()
+            logicalCameraData.put(
+                "logical-$logicalCameraId",
+                getCameraPropertiesJSONObject(camera2CameraInfo)
+            )
+            for (physicalCameraInfo in cameraInfo.physicalCameraInfos) {
+                camera2CameraInfo = Camera2CameraInfo.from(physicalCameraInfo)
+                val physicalCameraId = camera2CameraInfo.cameraId
+                logicalCameraData.put(
+                    "physical-$physicalCameraId",
+                    getCameraPropertiesJSONObject(camera2CameraInfo)
+                )
+            }
+            result.put(logicalCameraData)
+        }
+        return result
+    }
+
+    @OptIn(ExperimentalCamera2Interop::class)
+    private fun getCameraPropertiesJSONObject(cameraInfo: Camera2CameraInfo): JSONObject {
+        val jsonObject = JSONObject()
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
+            cameraInfo.getCameraCharacteristic(CameraCharacteristics.LENS_POSE_ROTATION)
+                ?.let {
+                    jsonObject.put(
+                        CameraCharacteristics.LENS_POSE_ROTATION.name,
+                        it.contentToString()
+                    )
+                }
+            cameraInfo.getCameraCharacteristic(CameraCharacteristics.LENS_POSE_TRANSLATION)
+                ?.let {
+                    jsonObject.put(
+                        CameraCharacteristics.LENS_POSE_TRANSLATION.name,
+                        it.contentToString()
+                    )
+                }
+            cameraInfo.getCameraCharacteristic(CameraCharacteristics.LENS_INTRINSIC_CALIBRATION)
+                ?.let {
+                    jsonObject.put(
+                        CameraCharacteristics.LENS_INTRINSIC_CALIBRATION.name,
+                        it.contentToString()
+                    )
+                }
+        }
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
+            cameraInfo.getCameraCharacteristic(CameraCharacteristics.LENS_DISTORTION)
+                ?.let {
+                    jsonObject.put(
+                        CameraCharacteristics.LENS_DISTORTION.name,
+                        it.contentToString()
+                    )
+                }
+        }
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+            cameraInfo.getCameraCharacteristic(CameraCharacteristics.CONTROL_ZOOM_RATIO_RANGE)
+                ?.let { jsonObject.put(CameraCharacteristics.CONTROL_ZOOM_RATIO_RANGE.name, it) }
+        }
+        cameraInfo.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)
+            ?.let {
+                jsonObject.put(
+                    CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS.name,
+                    it.contentToString()
+                )
+            }
+        cameraInfo.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_MINIMUM_FOCUS_DISTANCE)
+            ?.let {
+                jsonObject.put(
+                    CameraCharacteristics.LENS_INFO_MINIMUM_FOCUS_DISTANCE.name,
+                    it
+                )
+            }
+        cameraInfo.getCameraCharacteristic(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES)
+            ?.let {
+                jsonObject.put(
+                    CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES.name,
+                    it.contentToString()
+                )
+            }
+
+        return jsonObject
+    }
+
+    fun writeFileExternalStorage(file: File, textToWrite: String) {
+        // Checking the availability state of the External Storage.
+        val state = Environment.getExternalStorageState()
+        if (Environment.MEDIA_MOUNTED != state) {
+            // If it isn't mounted - we can't write into it.
+            return
+        }
+
+        file.createNewFile()
+        FileOutputStream(file).use { outputStream ->
+            outputStream.write(textToWrite.toByteArray())
+        }
+    }
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
new file mode 100644
index 0000000..822c5cd
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
@@ -0,0 +1,40 @@
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
+package com.google.jetpackcamera.core.camera
+
+import android.net.Uri
+
+/**
+ * Represents events that control video capture operations.
+ */
+sealed interface VideoCaptureControlEvent {
+
+    /**
+     * Starts video recording.
+     *
+     * @param onVideoRecord Callback to handle video recording events.
+     */
+    class StartRecordingEvent(
+        val videoCaptureUri: Uri?,
+        val shouldUseUri: Boolean,
+        val onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+    ) : VideoCaptureControlEvent
+
+    /**
+     * Stops video recording.
+     */
+    data object StopRecordingEvent : VideoCaptureControlEvent
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/CopyingSurfaceProcessor.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/CopyingSurfaceProcessor.kt
new file mode 100644
index 0000000..8f1fd6c
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/CopyingSurfaceProcessor.kt
@@ -0,0 +1,361 @@
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
+package com.google.jetpackcamera.core.camera.effects
+
+import android.graphics.SurfaceTexture
+import android.opengl.EGL14
+import android.opengl.EGLConfig
+import android.opengl.EGLExt
+import android.opengl.EGLSurface
+import android.util.Size
+import android.view.Surface
+import androidx.camera.core.SurfaceOutput
+import androidx.camera.core.SurfaceProcessor
+import androidx.camera.core.SurfaceRequest
+import androidx.graphics.opengl.GLRenderer
+import androidx.graphics.opengl.egl.EGLManager
+import androidx.graphics.opengl.egl.EGLSpec
+import com.google.jetpackcamera.core.common.RefCounted
+import kotlin.coroutines.coroutineContext
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.Runnable
+import kotlinx.coroutines.SupervisorJob
+import kotlinx.coroutines.async
+import kotlinx.coroutines.cancel
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.ensureActive
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.filterNot
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.onCompletion
+import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.launch
+
+private const val TIMESTAMP_UNINITIALIZED = -1L
+
+/**
+ * This is a [SurfaceProcessor] that passes on the same content from the input
+ * surface to the output surface. Used to make a copies of surfaces.
+ */
+class CopyingSurfaceProcessor(coroutineScope: CoroutineScope) : SurfaceProcessor {
+
+    private val inputSurfaceFlow = MutableStateFlow<SurfaceRequestScope?>(null)
+    private val outputSurfaceFlow = MutableStateFlow<SurfaceOutputScope?>(null)
+
+    init {
+        coroutineScope.launch(start = CoroutineStart.UNDISPATCHED) {
+            inputSurfaceFlow
+                .filterNotNull()
+                .collectLatest { surfaceRequestScope ->
+                    surfaceRequestScope.withSurfaceRequest { surfaceRequest ->
+
+                        val renderCallbacks = ShaderCopy(surfaceRequest.dynamicRange)
+                        renderCallbacks.renderWithSurfaceRequest(surfaceRequest)
+                    }
+                }
+        }
+    }
+
+    private suspend fun RenderCallbacks.renderWithSurfaceRequest(surfaceRequest: SurfaceRequest) =
+        coroutineScope inputScope@{
+            var currentTimestamp = TIMESTAMP_UNINITIALIZED
+            val surfaceTextureRef = RefCounted<SurfaceTexture> {
+                it.release()
+            }
+            val textureTransform = FloatArray(16)
+
+            val frameUpdateFlow = MutableStateFlow(0)
+
+            val initializeCallback = object : GLRenderer.EGLContextCallback {
+
+                override fun onEGLContextCreated(eglManager: EGLManager) {
+                    initRenderer()
+
+                    val surfaceTex = createSurfaceTexture(
+                        surfaceRequest.resolution.width,
+                        surfaceRequest.resolution.height
+                    )
+
+                    // Initialize the reference counted surface texture
+                    surfaceTextureRef.initialize(surfaceTex)
+
+                    surfaceTex.setOnFrameAvailableListener {
+                        // Increment frame counter
+                        frameUpdateFlow.update { it + 1 }
+                    }
+
+                    val inputSurface = Surface(surfaceTex)
+                    surfaceRequest.provideSurface(inputSurface, Runnable::run) { result ->
+                        inputSurface.release()
+                        surfaceTextureRef.release()
+                        this@inputScope.cancel(
+                            "Input surface no longer receiving frames: $result"
+                        )
+                    }
+                }
+
+                override fun onEGLContextDestroyed(eglManager: EGLManager) {
+                    // no-op
+                }
+            }
+
+            val glRenderer = GLRenderer(
+                eglSpecFactory = provideEGLSpec,
+                eglConfigFactory = initConfig
+            )
+            glRenderer.registerEGLContextCallback(initializeCallback)
+            glRenderer.start(glThreadName)
+
+            val inputRenderTarget = glRenderer.createRenderTarget(
+                surfaceRequest.resolution.width,
+                surfaceRequest.resolution.height,
+                object : GLRenderer.RenderCallback {
+
+                    override fun onDrawFrame(eglManager: EGLManager) {
+                        surfaceTextureRef.acquire()?.also {
+                            try {
+                                currentTimestamp =
+                                    if (currentTimestamp == TIMESTAMP_UNINITIALIZED) {
+                                        // Don't perform any updates on first draw,
+                                        // we're only setting up the context.
+                                        0
+                                    } else {
+                                        it.updateTexImage()
+                                        it.getTransformMatrix(textureTransform)
+                                        it.timestamp
+                                    }
+                            } finally {
+                                surfaceTextureRef.release()
+                            }
+                        }
+                    }
+                }
+            )
+
+            // Create the context and initialize the input. This will call RenderTarget.onDrawFrame,
+            // but we won't actually update the frame since this triggers adding the frame callback.
+            // All subsequent updates will then happen through frameUpdateFlow.
+            // This should be updated when https://issuetracker.google.com/331968279 is resolved.
+            inputRenderTarget.requestRender()
+
+            // Connect the onConnectToInput callback with the onDisconnectFromInput
+            // Should only be called on worker thread
+            var connectedToInput = false
+
+            // Should only be called on worker thread
+            val onConnectToInput: () -> Boolean = {
+                connectedToInput = surfaceTextureRef.acquire() != null
+                connectedToInput
+            }
+
+            // Should only be called on worker thread
+            val onDisconnectFromInput: () -> Unit = {
+                if (connectedToInput) {
+                    surfaceTextureRef.release()
+                    connectedToInput = false
+                }
+            }
+
+            // Wait for output surfaces
+            outputSurfaceFlow
+                .onCompletion {
+                    glRenderer.stop(cancelPending = false)
+                    glRenderer.unregisterEGLContextCallback(initializeCallback)
+                }.filterNotNull()
+                .collectLatest { surfaceOutputScope ->
+                    surfaceOutputScope.withSurfaceOutput { refCountedSurface,
+                                                           size,
+                                                           updateTransformMatrix ->
+                        // If we can't acquire the surface, then the surface output is already
+                        // closed, so we'll return and wait for the next output surface.
+                        val outputSurface =
+                            refCountedSurface.acquire() ?: return@withSurfaceOutput
+
+                        val surfaceTransform = FloatArray(16)
+                        val outputRenderTarget = glRenderer.attach(
+                            outputSurface,
+                            size.width,
+                            size.height,
+                            object : GLRenderer.RenderCallback {
+
+                                override fun onSurfaceCreated(
+                                    spec: EGLSpec,
+                                    config: EGLConfig,
+                                    surface: Surface,
+                                    width: Int,
+                                    height: Int
+                                ): EGLSurface? {
+                                    return if (onConnectToInput()) {
+                                        createOutputSurface(spec, config, surface, width, height)
+                                    } else {
+                                        null
+                                    }
+                                }
+
+                                override fun onDrawFrame(eglManager: EGLManager) {
+                                    val currentDrawSurface = eglManager.currentDrawSurface
+                                    if (currentDrawSurface != eglManager.defaultSurface) {
+                                        updateTransformMatrix(
+                                            surfaceTransform,
+                                            textureTransform
+                                        )
+
+                                        drawFrame(
+                                            size.width,
+                                            size.height,
+                                            surfaceTransform
+                                        )
+
+                                        // Set timestamp
+                                        val display =
+                                            EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
+                                        EGLExt.eglPresentationTimeANDROID(
+                                            display,
+                                            eglManager.currentDrawSurface,
+                                            currentTimestamp
+                                        )
+                                    }
+                                }
+                            }
+                        )
+
+                        frameUpdateFlow
+                            .onCompletion {
+                                outputRenderTarget.detach(cancelPending = false) {
+                                    onDisconnectFromInput()
+                                    refCountedSurface.release()
+                                }
+                            }.filterNot { it == 0 } // Don't attempt render on frame count 0
+                            .collectLatest {
+                                inputRenderTarget.requestRender()
+                                outputRenderTarget.requestRender()
+                            }
+                    }
+                }
+        }
+
+    override fun onInputSurface(surfaceRequest: SurfaceRequest) {
+        val newScope = SurfaceRequestScope(surfaceRequest)
+        inputSurfaceFlow.update { old ->
+            old?.cancel("New SurfaceRequest received.")
+            newScope
+        }
+    }
+
+    override fun onOutputSurface(surfaceOutput: SurfaceOutput) {
+        val newScope = SurfaceOutputScope(surfaceOutput)
+        outputSurfaceFlow.update { old ->
+            old?.cancel("New SurfaceOutput received.")
+            newScope
+        }
+    }
+}
+
+interface RenderCallbacks {
+    val glThreadName: String
+    val provideEGLSpec: () -> EGLSpec
+    val initConfig: EGLManager.() -> EGLConfig
+    val initRenderer: () -> Unit
+    val createSurfaceTexture: (width: Int, height: Int) -> SurfaceTexture
+    val createOutputSurface: (
+        eglSpec: EGLSpec,
+        config: EGLConfig,
+        surface: Surface,
+        width: Int,
+        height: Int
+    ) -> EGLSurface
+    val drawFrame: (outputWidth: Int, outputHeight: Int, surfaceTransform: FloatArray) -> Unit
+}
+
+private class SurfaceOutputScope(val surfaceOutput: SurfaceOutput) {
+    private val surfaceLifecycleJob = SupervisorJob()
+    private val refCountedSurface = RefCounted<Surface>(onRelease = {
+        surfaceOutput.close()
+    }).apply {
+        // Ensure we don't release until after `initialize` has completed by deferring
+        // the release.
+        val deferredRelease = CompletableDeferred<Unit>()
+        initialize(
+            surfaceOutput.getSurface(Runnable::run) {
+                deferredRelease.complete(Unit)
+            }
+        )
+        CoroutineScope(Dispatchers.Unconfined).launch {
+            deferredRelease.await()
+            surfaceLifecycleJob.cancel("SurfaceOutput close requested.")
+            this@apply.release()
+        }
+    }
+
+    suspend fun <R> withSurfaceOutput(
+        block: suspend CoroutineScope.(
+            surface: RefCounted<Surface>,
+            surfaceSize: Size,
+            updateTransformMatrix: (updated: FloatArray, original: FloatArray) -> Unit
+        ) -> R
+    ): R {
+        return CoroutineScope(coroutineContext + Job(surfaceLifecycleJob)).async(
+            start = CoroutineStart.UNDISPATCHED
+        ) {
+            ensureActive()
+            block(
+                refCountedSurface,
+                surfaceOutput.size,
+                surfaceOutput::updateTransformMatrix
+            )
+        }.await()
+    }
+
+    fun cancel(message: String? = null) {
+        message?.apply { surfaceLifecycleJob.cancel(message) } ?: surfaceLifecycleJob.cancel()
+    }
+}
+
+private class SurfaceRequestScope(private val surfaceRequest: SurfaceRequest) {
+    private val requestLifecycleJob = SupervisorJob()
+
+    init {
+        surfaceRequest.addRequestCancellationListener(Runnable::run) {
+            requestLifecycleJob.cancel("SurfaceRequest cancelled.")
+        }
+    }
+
+    suspend fun <R> withSurfaceRequest(
+        block: suspend CoroutineScope.(
+            surfaceRequest: SurfaceRequest
+        ) -> R
+    ): R {
+        return CoroutineScope(coroutineContext + Job(requestLifecycleJob)).async(
+            start = CoroutineStart.UNDISPATCHED
+        ) {
+            ensureActive()
+            block(surfaceRequest)
+        }.await()
+    }
+
+    fun cancel(message: String? = null) {
+        message?.apply { requestLifecycleJob.cancel(message) } ?: requestLifecycleJob.cancel()
+        // Attempt to tell frame producer we will not provide a surface. This may fail (silently)
+        // if surface was already provided or the producer has cancelled the request, in which
+        // case we don't have to do anything.
+        surfaceRequest.willNotProvideSurface()
+    }
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/EGLSpecV14ES3.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/EGLSpecV14ES3.kt
new file mode 100644
index 0000000..bf6e3ca
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/EGLSpecV14ES3.kt
@@ -0,0 +1,46 @@
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
+package com.google.jetpackcamera.core.camera.effects
+
+import android.opengl.EGL14
+import android.opengl.EGLConfig
+import android.opengl.EGLContext
+import androidx.graphics.opengl.egl.EGLSpec
+
+val EGLSpec.Companion.V14ES3: EGLSpec
+    get() = object : EGLSpec by V14 {
+
+        private val contextAttributes = intArrayOf(
+            // GLES VERSION 3
+            EGL14.EGL_CONTEXT_CLIENT_VERSION,
+            3,
+            // HWUI provides the ability to configure a context priority as well but that only
+            // seems to be configured on SystemUIApplication. This might be useful for
+            // front buffer rendering situations for performance.
+            EGL14.EGL_NONE
+        )
+
+        override fun eglCreateContext(config: EGLConfig): EGLContext {
+            return EGL14.eglCreateContext(
+                EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY),
+                config,
+                // not creating from a shared context
+                EGL14.EGL_NO_CONTEXT,
+                contextAttributes,
+                0
+            )
+        }
+    }
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/GLDebug.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/GLDebug.kt
new file mode 100644
index 0000000..d9e3fe1
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/GLDebug.kt
@@ -0,0 +1,24 @@
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
+package com.google.jetpackcamera.core.camera.effects
+
+object GLDebug {
+    init {
+        System.loadLibrary("opengl_debug_lib")
+    }
+
+    external fun enableES3DebugErrorLogging()
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/ShaderCopy.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/ShaderCopy.kt
new file mode 100644
index 0000000..0677b23
--- /dev/null
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/ShaderCopy.kt
@@ -0,0 +1,509 @@
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
+package com.google.jetpackcamera.core.camera.effects
+
+import android.graphics.SurfaceTexture
+import android.opengl.EGL14
+import android.opengl.EGLConfig
+import android.opengl.EGLExt
+import android.opengl.GLES11Ext
+import android.opengl.GLES20
+import android.opengl.GLES30
+import android.util.Log
+import android.view.Surface
+import androidx.annotation.WorkerThread
+import androidx.camera.core.DynamicRange
+import androidx.graphics.opengl.egl.EGLConfigAttributes
+import androidx.graphics.opengl.egl.EGLManager
+import androidx.graphics.opengl.egl.EGLSpec
+import java.nio.ByteBuffer
+import java.nio.ByteOrder
+import java.nio.FloatBuffer
+
+class ShaderCopy(private val dynamicRange: DynamicRange) : RenderCallbacks {
+
+    // Called on worker thread only
+    private var externalTextureId: Int = -1
+    private var programHandle = -1
+    private var texMatrixLoc = -1
+    private var samplerLoc = -1
+    private var positionLoc = -1
+    private var texCoordLoc = -1
+    private val glExtensions: Set<String> by lazy {
+        checkGlThread()
+        buildSet {
+            GLES20.glGetString(GLES20.GL_EXTENSIONS)?.split(" ")?.also {
+                addAll(it)
+            }
+        }
+    }
+    private val use10bitPipeline: Boolean
+        get() = dynamicRange.bitDepth == DynamicRange.BIT_DEPTH_10_BIT
+
+    override val glThreadName: String
+        get() = TAG
+
+    override val provideEGLSpec: () -> EGLSpec
+        get() = { if (use10bitPipeline) EGLSpec.V14ES3 else EGLSpec.V14 }
+
+    override val initConfig: EGLManager.() -> EGLConfig
+        get() = {
+            checkNotNull(
+                loadConfig(
+                    EGLConfigAttributes {
+                        if (use10bitPipeline) {
+                            TEN_BIT_REQUIRED_EGL_EXTENSIONS.forEach {
+                                check(isExtensionSupported(it)) {
+                                    "Required extension for 10-bit HDR is not " +
+                                        "supported: $it"
+                                }
+                            }
+                            include(EGLConfigAttributes.RGBA_1010102)
+                            EGL14.EGL_RENDERABLE_TYPE to
+                                EGLExt.EGL_OPENGL_ES3_BIT_KHR
+                            EGL14.EGL_SURFACE_TYPE to
+                                (EGL14.EGL_WINDOW_BIT or EGL14.EGL_PBUFFER_BIT)
+                        } else {
+                            include(EGLConfigAttributes.RGBA_8888)
+                        }
+                    }
+                )
+            ) {
+                "Unable to select EGLConfig"
+            }
+        }
+
+    override val initRenderer: () -> Unit
+        get() = {
+            if (use10bitPipeline && glExtensions.contains("GL_KHR_debug")) {
+                GLDebug.enableES3DebugErrorLogging()
+            }
+
+            createProgram(
+                if (use10bitPipeline) {
+                    TEN_BIT_VERTEX_SHADER
+                } else {
+                    DEFAULT_VERTEX_SHADER
+                },
+                if (use10bitPipeline) {
+                    TEN_BIT_FRAGMENT_SHADER
+                } else {
+                    DEFAULT_FRAGMENT_SHADER
+                }
+            )
+            loadLocations()
+            createTexture()
+            useAndConfigureProgram()
+        }
+
+    override val createSurfaceTexture
+        get() = { width: Int, height: Int ->
+            SurfaceTexture(externalTextureId).apply {
+                setDefaultBufferSize(width, height)
+            }
+        }
+
+    override val createOutputSurface
+        get() = { eglSpec: EGLSpec,
+                config: EGLConfig,
+                surface: Surface,
+                _: Int,
+                _: Int ->
+            eglSpec.eglCreateWindowSurface(
+                config,
+                surface,
+                EGLConfigAttributes {
+                    if (use10bitPipeline) {
+                        EGL_GL_COLORSPACE_KHR to EGL_GL_COLORSPACE_BT2020_HLG_EXT
+                    }
+                }
+            )
+        }
+
+    override val drawFrame
+        get() = { outputWidth: Int,
+                outputHeight: Int,
+                surfaceTransform: FloatArray ->
+            checkGlThread()
+            GLES20.glViewport(
+                0,
+                0,
+                outputWidth,
+                outputHeight
+            )
+            GLES20.glScissor(
+                0,
+                0,
+                outputWidth,
+                outputHeight
+            )
+
+            GLES20.glUniformMatrix4fv(
+                texMatrixLoc,
+                /*count=*/
+                1,
+                /*transpose=*/
+                false,
+                surfaceTransform,
+                /*offset=*/
+                0
+            )
+            checkGlErrorOrThrow("glUniformMatrix4fv")
+
+            // Draw the rect.
+            GLES20.glDrawArrays(
+                GLES20.GL_TRIANGLE_STRIP,
+                /*firstVertex=*/
+                0,
+                /*vertexCount=*/
+                4
+            )
+            checkGlErrorOrThrow("glDrawArrays")
+        }
+
+    @WorkerThread
+    fun createTexture() {
+        checkGlThread()
+        val textures = IntArray(1)
+        GLES20.glGenTextures(1, textures, 0)
+        checkGlErrorOrThrow("glGenTextures")
+        val texId = textures[0]
+        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, texId)
+        checkGlErrorOrThrow("glBindTexture $texId")
+        GLES20.glTexParameterf(
+            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
+            GLES20.GL_TEXTURE_MIN_FILTER,
+            GLES20.GL_NEAREST.toFloat()
+        )
+        GLES20.glTexParameterf(
+            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
+            GLES20.GL_TEXTURE_MAG_FILTER,
+            GLES20.GL_LINEAR.toFloat()
+        )
+        GLES20.glTexParameteri(
+            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
+            GLES20.GL_TEXTURE_WRAP_S,
+            GLES20.GL_CLAMP_TO_EDGE
+        )
+        GLES20.glTexParameteri(
+            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
+            GLES20.GL_TEXTURE_WRAP_T,
+            GLES20.GL_CLAMP_TO_EDGE
+        )
+        checkGlErrorOrThrow("glTexParameter")
+        externalTextureId = texId
+    }
+
+    @WorkerThread
+    fun useAndConfigureProgram() {
+        checkGlThread()
+        // Select the program.
+        GLES20.glUseProgram(programHandle)
+        checkGlErrorOrThrow("glUseProgram")
+
+        // Set the texture.
+        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
+        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, externalTextureId)
+        GLES20.glUniform1i(samplerLoc, 0)
+
+        if (use10bitPipeline) {
+            val vaos = IntArray(1)
+            GLES30.glGenVertexArrays(1, vaos, 0)
+            GLES30.glBindVertexArray(vaos[0])
+            checkGlErrorOrThrow("glBindVertexArray")
+        }
+
+        val vbos = IntArray(2)
+        GLES20.glGenBuffers(2, vbos, 0)
+        checkGlErrorOrThrow("glGenBuffers")
+
+        // Connect vertexBuffer to "aPosition".
+        val coordsPerVertex = 2
+        val vertexStride = 0
+        GLES20.glBindBuffer(GLES20.GL_ARRAY_BUFFER, vbos[0])
+        checkGlErrorOrThrow("glBindBuffer")
+        GLES20.glBufferData(
+            GLES20.GL_ARRAY_BUFFER,
+            VERTEX_BUF.capacity() * SIZEOF_FLOAT,
+            VERTEX_BUF,
+            GLES20.GL_STATIC_DRAW
+        )
+        checkGlErrorOrThrow("glBufferData")
+
+        // Enable the "aPosition" vertex attribute.
+        GLES20.glEnableVertexAttribArray(positionLoc)
+        checkGlErrorOrThrow("glEnableVertexAttribArray")
+
+        GLES20.glVertexAttribPointer(
+            positionLoc,
+            coordsPerVertex,
+            GLES20.GL_FLOAT,
+            /*normalized=*/
+            false,
+            vertexStride,
+            0
+        )
+        checkGlErrorOrThrow("glVertexAttribPointer")
+
+        // Connect texBuffer to "aTextureCoord".
+        val coordsPerTex = 2
+        val texStride = 0
+        GLES20.glBindBuffer(GLES20.GL_ARRAY_BUFFER, vbos[1])
+        checkGlErrorOrThrow("glBindBuffer")
+
+        GLES20.glBufferData(
+            GLES20.GL_ARRAY_BUFFER,
+            TEX_BUF.capacity() * SIZEOF_FLOAT,
+            TEX_BUF,
+            GLES20.GL_STATIC_DRAW
+        )
+        checkGlErrorOrThrow("glBufferData")
+
+        // Enable the "aTextureCoord" vertex attribute.
+        GLES20.glEnableVertexAttribArray(texCoordLoc)
+        checkGlErrorOrThrow("glEnableVertexAttribArray")
+
+        GLES20.glVertexAttribPointer(
+            texCoordLoc,
+            coordsPerTex,
+            GLES20.GL_FLOAT,
+            /*normalized=*/
+            false,
+            texStride,
+            0
+        )
+        checkGlErrorOrThrow("glVertexAttribPointer")
+    }
+
+    @WorkerThread
+    private fun createProgram(vertShader: String, fragShader: String) {
+        checkGlThread()
+        var vertexShader = -1
+        var fragmentShader = -1
+        var program = -1
+        try {
+            fragmentShader = loadShader(
+                GLES20.GL_FRAGMENT_SHADER,
+                fragShader
+            )
+            vertexShader = loadShader(
+                GLES20.GL_VERTEX_SHADER,
+                vertShader
+            )
+            program = GLES20.glCreateProgram()
+            checkGlErrorOrThrow("glCreateProgram")
+            GLES20.glAttachShader(program, vertexShader)
+            checkGlErrorOrThrow("glAttachShader")
+            GLES20.glAttachShader(program, fragmentShader)
+            checkGlErrorOrThrow("glAttachShader")
+            GLES20.glLinkProgram(program)
+            val linkStatus = IntArray(1)
+            GLES20.glGetProgramiv(
+                program,
+                GLES20.GL_LINK_STATUS,
+                linkStatus,
+                /*offset=*/
+                0
+            )
+            check(linkStatus[0] == GLES20.GL_TRUE) {
+                "Could not link program: " + GLES20.glGetProgramInfoLog(
+                    program
+                )
+            }
+            programHandle = program
+        } catch (e: Exception) {
+            if (vertexShader != -1) {
+                GLES20.glDeleteShader(vertexShader)
+            }
+            if (fragmentShader != -1) {
+                GLES20.glDeleteShader(fragmentShader)
+            }
+            if (program != -1) {
+                GLES20.glDeleteProgram(program)
+            }
+            throw e
+        }
+    }
+
+    @WorkerThread
+    private fun loadLocations() {
+        checkGlThread()
+        positionLoc = GLES20.glGetAttribLocation(programHandle, "aPosition")
+        checkLocationOrThrow(positionLoc, "aPosition")
+        texCoordLoc = GLES20.glGetAttribLocation(programHandle, "aTextureCoord")
+        checkLocationOrThrow(texCoordLoc, "aTextureCoord")
+        texMatrixLoc = GLES20.glGetUniformLocation(programHandle, "uTexMatrix")
+        checkLocationOrThrow(texMatrixLoc, "uTexMatrix")
+        samplerLoc = GLES20.glGetUniformLocation(programHandle, VAR_TEXTURE)
+        checkLocationOrThrow(samplerLoc, VAR_TEXTURE)
+    }
+
+    @WorkerThread
+    private fun loadShader(shaderType: Int, source: String): Int {
+        checkGlThread()
+        val shader = GLES20.glCreateShader(shaderType)
+        checkGlErrorOrThrow("glCreateShader type=$shaderType")
+        GLES20.glShaderSource(shader, source)
+        GLES20.glCompileShader(shader)
+        val compiled = IntArray(1)
+        GLES20.glGetShaderiv(
+            shader,
+            GLES20.GL_COMPILE_STATUS,
+            compiled,
+            /*offset=*/
+            0
+        )
+        check(compiled[0] == GLES20.GL_TRUE) {
+            Log.w(TAG, "Could not compile shader: $source")
+            try {
+                return@check "Could not compile shader type " +
+                    "$shaderType: ${GLES20.glGetShaderInfoLog(shader)}"
+            } finally {
+                GLES20.glDeleteShader(shader)
+            }
+        }
+        return shader
+    }
+
+    @WorkerThread
+    private fun checkGlErrorOrThrow(op: String) {
+        val error = GLES20.glGetError()
+        check(error == GLES20.GL_NO_ERROR) { op + ": GL error 0x" + Integer.toHexString(error) }
+    }
+
+    private fun checkLocationOrThrow(location: Int, label: String) {
+        check(location >= 0) { "Unable to locate '$label' in program" }
+    }
+
+    companion object {
+        private const val SIZEOF_FLOAT = 4
+
+        private val VERTEX_BUF = floatArrayOf(
+            // 0 bottom left
+            -1.0f,
+            -1.0f,
+            // 1 bottom right
+            1.0f,
+            -1.0f,
+            // 2 top left
+            -1.0f,
+            1.0f,
+            // 3 top right
+            1.0f,
+            1.0f
+        ).toBuffer()
+
+        private val TEX_BUF = floatArrayOf(
+            // 0 bottom left
+            0.0f,
+            0.0f,
+            // 1 bottom right
+            1.0f,
+            0.0f,
+            // 2 top left
+            0.0f,
+            1.0f,
+            // 3 top right
+            1.0f,
+            1.0f
+        ).toBuffer()
+
+        private const val TAG = "ShaderCopy"
+        private const val GL_THREAD_NAME = TAG
+
+        private const val VAR_TEXTURE_COORD = "vTextureCoord"
+        private val DEFAULT_VERTEX_SHADER =
+            """
+        uniform mat4 uTexMatrix;
+        attribute vec4 aPosition;
+        attribute vec4 aTextureCoord;
+        varying vec2 $VAR_TEXTURE_COORD;
+        void main() {
+            gl_Position = aPosition;
+            $VAR_TEXTURE_COORD = (uTexMatrix * aTextureCoord).xy;
+        }
+            """.trimIndent()
+
+        private val TEN_BIT_VERTEX_SHADER =
+            """
+        #version 300 es
+        in vec4 aPosition;
+        in vec4 aTextureCoord;
+        uniform mat4 uTexMatrix;
+        out vec2 $VAR_TEXTURE_COORD;
+        void main() {
+          gl_Position = aPosition;
+          $VAR_TEXTURE_COORD = (uTexMatrix * aTextureCoord).xy;
+        }
+            """.trimIndent()
+
+        private const val VAR_TEXTURE = "sTexture"
+        private val DEFAULT_FRAGMENT_SHADER =
+            """
+        #extension GL_OES_EGL_image_external : require
+        precision mediump float;
+        varying vec2 $VAR_TEXTURE_COORD;
+        uniform samplerExternalOES $VAR_TEXTURE;
+        void main() {
+            gl_FragColor = texture2D($VAR_TEXTURE, $VAR_TEXTURE_COORD);
+        }
+            """.trimIndent()
+
+        private val TEN_BIT_FRAGMENT_SHADER =
+            """
+        #version 300 es
+        #extension GL_EXT_YUV_target : require
+        precision mediump float;
+        uniform __samplerExternal2DY2YEXT $VAR_TEXTURE;
+        in vec2 $VAR_TEXTURE_COORD;
+        out vec3 outColor;
+        
+        vec3 yuvToRgb(vec3 yuv) {
+          const vec3 yuvOffset = vec3(0.0625, 0.5, 0.5);
+          const mat3 yuvToRgbColorTransform = mat3(
+            1.1689f, 1.1689f, 1.1689f,
+            0.0000f, -0.1881f, 2.1502f,
+            1.6853f, -0.6530f, 0.0000f
+          );
+          return clamp(yuvToRgbColorTransform * (yuv - yuvOffset), 0.0, 1.0);
+        }
+        
+        void main() {
+          outColor = yuvToRgb(texture($VAR_TEXTURE, $VAR_TEXTURE_COORD).xyz);
+        }
+            """.trimIndent()
+
+        private const val EGL_GL_COLORSPACE_KHR = 0x309D
+        private const val EGL_GL_COLORSPACE_BT2020_HLG_EXT = 0x3540
+
+        private val TEN_BIT_REQUIRED_EGL_EXTENSIONS = listOf(
+            "EGL_EXT_gl_colorspace_bt2020_hlg"
+        )
+
+        private fun FloatArray.toBuffer(): FloatBuffer {
+            val bb = ByteBuffer.allocateDirect(size * SIZEOF_FLOAT)
+            bb.order(ByteOrder.nativeOrder())
+            val fb = bb.asFloatBuffer()
+            fb.put(this)
+            fb.position(0)
+            return fb
+        }
+
+        private fun checkGlThread() {
+            check(GL_THREAD_NAME == Thread.currentThread().name)
+        }
+    }
+}
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/SingleSurfaceForcingEffect.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/SingleSurfaceForcingEffect.kt
similarity index 95%
rename from domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/SingleSurfaceForcingEffect.kt
rename to core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/SingleSurfaceForcingEffect.kt
index 6057b89..7748719 100644
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/SingleSurfaceForcingEffect.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/effects/SingleSurfaceForcingEffect.kt
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.domain.camera.effects
+package com.google.jetpackcamera.core.camera.effects
 
 import androidx.camera.core.CameraEffect
 import kotlinx.coroutines.CoroutineScope
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/test/FakeCameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
similarity index 63%
rename from domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/test/FakeCameraUseCase.kt
rename to core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
index 8724bad..f865a63 100644
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/test/FakeCameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
@@ -13,36 +13,36 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.domain.camera.test
+package com.google.jetpackcamera.core.camera.test
 
 import android.annotation.SuppressLint
 import android.content.ContentResolver
 import android.net.Uri
-import android.view.Display
 import androidx.camera.core.ImageCapture
 import androidx.camera.core.SurfaceRequest
-import com.google.jetpackcamera.domain.camera.CameraUseCase
+import com.google.jetpackcamera.core.camera.CameraState
+import com.google.jetpackcamera.core.camera.CameraUseCase
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.settings.model.DeviceRotation
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.SupervisorJob
-import kotlinx.coroutines.flow.MutableSharedFlow
+import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.Stabilization
+import kotlinx.coroutines.channels.Channel
+import kotlinx.coroutines.channels.Channel.Factory.UNLIMITED
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.collectLatest
 import kotlinx.coroutines.flow.onCompletion
 import kotlinx.coroutines.flow.update
-import kotlinx.coroutines.launch
 
 class FakeCameraUseCase(
-    private val coroutineScope: CoroutineScope =
-        CoroutineScope(SupervisorJob() + Dispatchers.Default),
     defaultCameraSettings: CameraAppSettings = CameraAppSettings()
 ) : CameraUseCase {
     private val availableLenses = listOf(LensFacing.FRONT, LensFacing.BACK)
@@ -57,11 +57,15 @@ class FakeCameraUseCase(
     var isLensFacingFront = false
 
     private var isScreenFlash = true
-    private var screenFlashEvents = MutableSharedFlow<CameraUseCase.ScreenFlashEvent>()
+    private var screenFlashEvents = Channel<CameraUseCase.ScreenFlashEvent>(capacity = UNLIMITED)
 
     private val currentSettings = MutableStateFlow(defaultCameraSettings)
 
-    override suspend fun initialize(disableVideoCapture: Boolean) {
+    override suspend fun initialize(
+        cameraAppSettings: CameraAppSettings,
+        useCaseMode: CameraUseCase.UseCaseMode,
+        isDebugMode: Boolean
+    ) {
         initialized = true
     }
 
@@ -89,7 +93,9 @@ class FakeCameraUseCase(
                     isLensFacingFront &&
                     (it.flashMode == FlashMode.AUTO || it.flashMode == FlashMode.ON)
 
-                _zoomScale.value = it.zoomScale
+                _currentCameraState.update { old ->
+                    old.copy(zoomScale = it.zoomScale)
+                }
             }
     }
 
@@ -98,14 +104,12 @@ class FakeCameraUseCase(
             throw IllegalStateException("Usecases not bound")
         }
         if (isScreenFlash) {
-            coroutineScope.launch {
-                screenFlashEvents.emit(
-                    CameraUseCase.ScreenFlashEvent(CameraUseCase.ScreenFlashEvent.Type.APPLY_UI) { }
-                )
-                screenFlashEvents.emit(
-                    CameraUseCase.ScreenFlashEvent(CameraUseCase.ScreenFlashEvent.Type.CLEAR_UI) { }
-                )
-            }
+            screenFlashEvents.trySend(
+                CameraUseCase.ScreenFlashEvent(CameraUseCase.ScreenFlashEvent.Type.APPLY_UI) { }
+            )
+            screenFlashEvents.trySend(
+                CameraUseCase.ScreenFlashEvent(CameraUseCase.ScreenFlashEvent.Type.CLEAR_UI) { }
+            )
         }
         numPicturesTaken += 1
     }
@@ -122,12 +126,12 @@ class FakeCameraUseCase(
     }
 
     fun emitScreenFlashEvent(event: CameraUseCase.ScreenFlashEvent) {
-        coroutineScope.launch {
-            screenFlashEvents.emit(event)
-        }
+        screenFlashEvents.trySend(event)
     }
 
     override suspend fun startVideoRecording(
+        videoCaptureUri: Uri?,
+        shouldUseUri: Boolean,
         onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
     ) {
         if (!useCasesBinded) {
@@ -140,13 +144,13 @@ class FakeCameraUseCase(
         recordingInProgress = false
     }
 
-    private val _zoomScale = MutableStateFlow(1f)
+    private val _currentCameraState = MutableStateFlow(CameraState())
     override fun setZoomScale(scale: Float) {
         currentSettings.update { old ->
             old.copy(zoomScale = scale)
         }
     }
-    override fun getZoomScale(): StateFlow<Float> = _zoomScale.asStateFlow()
+    override fun getCurrentCameraState(): StateFlow<CameraState> = _currentCameraState.asStateFlow()
 
     private val _surfaceRequest = MutableStateFlow<SurfaceRequest?>(null)
     override fun getSurfaceRequest(): StateFlow<SurfaceRequest?> = _surfaceRequest.asStateFlow()
@@ -176,13 +180,7 @@ class FakeCameraUseCase(
         }
     }
 
-    override fun tapToFocus(
-        display: Display,
-        surfaceWidth: Int,
-        surfaceHeight: Int,
-        x: Float,
-        y: Float
-    ) {
+    override suspend fun tapToFocus(x: Float, y: Float) {
         TODO("Not yet implemented")
     }
 
@@ -197,4 +195,52 @@ class FakeCameraUseCase(
             old.copy(dynamicRange = dynamicRange)
         }
     }
+
+    override fun setDeviceRotation(deviceRotation: DeviceRotation) {
+        currentSettings.update { old ->
+            old.copy(deviceRotation = deviceRotation)
+        }
+    }
+
+    override suspend fun setConcurrentCameraMode(concurrentCameraMode: ConcurrentCameraMode) {
+        currentSettings.update { old ->
+            old.copy(concurrentCameraMode = concurrentCameraMode)
+        }
+    }
+
+    override suspend fun setImageFormat(imageFormat: ImageOutputFormat) {
+        currentSettings.update { old ->
+            old.copy(imageFormat = imageFormat)
+        }
+    }
+
+    override suspend fun setLowLightBoost(lowLightBoost: LowLightBoost) {
+        currentSettings.update { old ->
+            old.copy(lowLightBoost = lowLightBoost)
+        }
+    }
+
+    override suspend fun setAudioMuted(isAudioMuted: Boolean) {
+        currentSettings.update { old ->
+            old.copy(audioMuted = isAudioMuted)
+        }
+    }
+
+    override suspend fun setVideoCaptureStabilization(videoCaptureStabilization: Stabilization) {
+        currentSettings.update { old ->
+            old.copy(videoCaptureStabilization = videoCaptureStabilization)
+        }
+    }
+
+    override suspend fun setPreviewStabilization(previewStabilization: Stabilization) {
+        currentSettings.update { old ->
+            old.copy(previewStabilization = previewStabilization)
+        }
+    }
+
+    override suspend fun setTargetFrameRate(targetFrameRate: Int) {
+        currentSettings.update { old ->
+            old.copy(targetFrameRate = targetFrameRate)
+        }
+    }
 }
diff --git a/domain/camera/src/test/Android.bp b/core/camera/src/test/Android.bp
similarity index 78%
rename from domain/camera/src/test/Android.bp
rename to core/camera/src/test/Android.bp
index 2fc04c2..b969779 100644
--- a/domain/camera/src/test/Android.bp
+++ b/core/camera/src/test/Android.bp
@@ -3,7 +3,7 @@ package {
 }
 
 java_test {
-    name: "jetpack-camera-app_domain_camera-tests",
+    name: "jetpack-camera-app_core_camera-tests",
     team: "trendy_team_camerax",
     srcs: ["java/**/*.kt"],
     static_libs: [
@@ -12,8 +12,7 @@ java_test {
         "androidx.test.ext.junit",
         "androidx.test.ext.truth",
         "mockito-core",
-        "jetpack-camera-app_domain_camera",
-
+        "jetpack-camera-app_core_camera",
     ],
     min_sdk_version: "21",
 }
diff --git a/domain/camera/src/test/AndroidManifest.xml b/core/camera/src/test/AndroidManifest.xml
similarity index 77%
rename from domain/camera/src/test/AndroidManifest.xml
rename to core/camera/src/test/AndroidManifest.xml
index e84b7b1..91b7229 100644
--- a/domain/camera/src/test/AndroidManifest.xml
+++ b/core/camera/src/test/AndroidManifest.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2015 The Android Open Source Project
+  ~ Copyright (C) 2024 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -16,15 +16,15 @@
   -->
 
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.jetpackcamera.domain.camera.test" >
+    package="com.google.jetpackcamera.core.camera.test" >
 
     <instrumentation
         android:name="androidx.test.runner.AndroidJUnitRunner"
-        android:label="Domain Camera Unit Tests"
-        android:targetPackage="com.google.jetpackcamera.domain.camera" />
+        android:label="Core Camera Unit Tests"
+        android:targetPackage="com.google.jetpackcamera.core.camera" />
 
     <application>
         <uses-library android:name="android.test.runner" />
     </application>
 
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/domain/camera/src/test/java/com/google/jetpackcamera/domain/camera/test/FakeCameraUseCaseTest.kt b/core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt
similarity index 77%
rename from domain/camera/src/test/java/com/google/jetpackcamera/domain/camera/test/FakeCameraUseCaseTest.kt
rename to core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt
index c6eaf59..00cedf3 100644
--- a/domain/camera/src/test/java/com/google/jetpackcamera/domain/camera/test/FakeCameraUseCaseTest.kt
+++ b/core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt
@@ -13,14 +13,16 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.jetpackcamera.domain.camera.test
+package com.google.jetpackcamera.core.camera.test
 
-import com.google.common.truth.Truth.assertThat
-import com.google.jetpackcamera.domain.camera.CameraUseCase
+import com.google.common.truth.Truth
+import com.google.jetpackcamera.core.camera.CameraUseCase
+import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.consumeAsFlow
 import kotlinx.coroutines.flow.toList
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.test.StandardTestDispatcher
@@ -39,7 +41,7 @@ class FakeCameraUseCaseTest {
     private val testScope = TestScope()
     private val testDispatcher = StandardTestDispatcher(testScope.testScheduler)
 
-    private val cameraUseCase = FakeCameraUseCase(testScope)
+    private val cameraUseCase = FakeCameraUseCase()
 
     @Before
     fun setup() {
@@ -53,13 +55,16 @@ class FakeCameraUseCaseTest {
 
     @Test
     fun canInitialize() = runTest(testDispatcher) {
-        cameraUseCase.initialize(false)
+        cameraUseCase.initialize(
+            cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
+            useCaseMode = CameraUseCase.UseCaseMode.STANDARD
+        )
     }
 
     @Test
     fun canRunCamera() = runTest(testDispatcher) {
         initAndRunCamera()
-        assertThat(cameraUseCase.isPreviewStarted())
+        Truth.assertThat(cameraUseCase.isPreviewStarted())
     }
 
     @Test
@@ -70,7 +75,7 @@ class FakeCameraUseCaseTest {
         cameraUseCase.setFlashMode(flashMode = FlashMode.OFF)
         advanceUntilIdle()
 
-        assertThat(cameraUseCase.isScreenFlashEnabled()).isFalse()
+        Truth.assertThat(cameraUseCase.isScreenFlashEnabled()).isFalse()
     }
 
     @Test
@@ -81,7 +86,7 @@ class FakeCameraUseCaseTest {
         cameraUseCase.setFlashMode(flashMode = FlashMode.ON)
         advanceUntilIdle()
 
-        assertThat(cameraUseCase.isScreenFlashEnabled()).isFalse()
+        Truth.assertThat(cameraUseCase.isScreenFlashEnabled()).isFalse()
     }
 
     @Test
@@ -92,7 +97,7 @@ class FakeCameraUseCaseTest {
         cameraUseCase.setFlashMode(flashMode = FlashMode.AUTO)
         advanceUntilIdle()
 
-        assertThat(cameraUseCase.isScreenFlashEnabled()).isFalse()
+        Truth.assertThat(cameraUseCase.isScreenFlashEnabled()).isFalse()
     }
 
     @Test
@@ -103,7 +108,7 @@ class FakeCameraUseCaseTest {
         cameraUseCase.setFlashMode(flashMode = FlashMode.ON)
         advanceUntilIdle()
 
-        assertThat(cameraUseCase.isScreenFlashEnabled()).isTrue()
+        Truth.assertThat(cameraUseCase.isScreenFlashEnabled()).isTrue()
     }
 
     @Test
@@ -114,7 +119,7 @@ class FakeCameraUseCaseTest {
         cameraUseCase.setFlashMode(flashMode = FlashMode.AUTO)
         advanceUntilIdle()
 
-        assertThat(cameraUseCase.isScreenFlashEnabled()).isTrue()
+        Truth.assertThat(cameraUseCase.isScreenFlashEnabled()).isTrue()
     }
 
     @Test
@@ -124,7 +129,7 @@ class FakeCameraUseCaseTest {
         initAndRunCamera()
         val events = mutableListOf<CameraUseCase.ScreenFlashEvent>()
         backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
-            cameraUseCase.getScreenFlashEvents().toList(events)
+            cameraUseCase.getScreenFlashEvents().consumeAsFlow().toList(events)
         }
 
         // FlashMode.ON in front facing camera automatically enables screen flash
@@ -134,7 +139,7 @@ class FakeCameraUseCaseTest {
         cameraUseCase.takePicture()
 
         advanceUntilIdle()
-        assertThat(events.map { it.type }).containsExactlyElementsIn(
+        Truth.assertThat(events.map { it.type }).containsExactlyElementsIn(
             listOf(
                 CameraUseCase.ScreenFlashEvent.Type.APPLY_UI,
                 CameraUseCase.ScreenFlashEvent.Type.CLEAR_UI
@@ -144,7 +149,10 @@ class FakeCameraUseCaseTest {
 
     private fun TestScope.initAndRunCamera() {
         backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
-            cameraUseCase.initialize(false)
+            cameraUseCase.initialize(
+                cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
+                useCaseMode = CameraUseCase.UseCaseMode.STANDARD
+            )
             cameraUseCase.runCamera()
         }
     }
diff --git a/core/common/Android.bp b/core/common/Android.bp
index 552b888..b5ccf9b 100644
--- a/core/common/Android.bp
+++ b/core/common/Android.bp
@@ -9,11 +9,12 @@ android_library {
     srcs: ["src/main/**/*.kt"],
     static_libs: [
         "androidx.core_core-ktx",
-	"hilt_android",
+        "androidx.tracing_tracing-ktx",
+        "hilt_android",
         "androidx.appcompat_appcompat",
-	"com.google.android.material_material",
+        "com.google.android.material_material",
     ],
     sdk_version: "34",
     min_sdk_version: "21",
-    manifest:"src/main/AndroidManifest.xml"
+    manifest: "src/main/AndroidManifest.xml",
 }
diff --git a/core/common/build.gradle.kts b/core/common/build.gradle.kts
index 1eba073..2a81639 100644
--- a/core/common/build.gradle.kts
+++ b/core/common/build.gradle.kts
@@ -24,6 +24,7 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.core.common"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -41,7 +42,24 @@ android {
                     "proguard-rules.pro"
             )
         }
+        create("benchmark") {
+            initWith(buildTypes.getByName("release"))
+        }
     }
+
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
+    }
+
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_17
         targetCompatibility = JavaVersion.VERSION_17
@@ -57,6 +75,7 @@ dependencies {
     implementation(libs.androidx.appcompat)
     implementation(libs.android.material)
     implementation(libs.kotlinx.atomicfu)
+    implementation(libs.androidx.tracing)
 
     testImplementation(libs.junit)
     testImplementation(libs.truth)
diff --git a/core/common/src/main/java/com/google/jetpackcamera/core/common/CommonModule.kt b/core/common/src/main/java/com/google/jetpackcamera/core/common/CommonModule.kt
index 519f90f..2f93743 100644
--- a/core/common/src/main/java/com/google/jetpackcamera/core/common/CommonModule.kt
+++ b/core/common/src/main/java/com/google/jetpackcamera/core/common/CommonModule.kt
@@ -19,6 +19,7 @@ import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.components.SingletonComponent
+import javax.inject.Qualifier
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
@@ -32,9 +33,22 @@ import kotlinx.coroutines.SupervisorJob
 @InstallIn(SingletonComponent::class)
 class CommonModule {
     @Provides
+    @DefaultDispatcher
     fun provideDefaultDispatcher(): CoroutineDispatcher = Dispatchers.Default
 
+    @Provides
+    @IODispatcher
+    fun provideIODispatcher(): CoroutineDispatcher = Dispatchers.IO
+
     @Singleton
     @Provides
     fun providesCoroutineScope() = CoroutineScope(SupervisorJob() + Dispatchers.Default)
 }
+
+@Qualifier
+@Retention(AnnotationRetention.BINARY)
+annotation class DefaultDispatcher
+
+@Qualifier
+@Retention(AnnotationRetention.BINARY)
+annotation class IODispatcher
diff --git a/core/common/src/main/java/com/google/jetpackcamera/core/common/TraceManager.kt b/core/common/src/main/java/com/google/jetpackcamera/core/common/TraceManager.kt
new file mode 100644
index 0000000..6079362
--- /dev/null
+++ b/core/common/src/main/java/com/google/jetpackcamera/core/common/TraceManager.kt
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
+package com.google.jetpackcamera.core.common
+
+import androidx.tracing.traceAsync
+
+const val FIRST_FRAME_TRACE_PREVIEW = "firstFrameTracePreview"
+const val FIRST_FRAME_TRACE_MAIN_ACTIVITY = "firstFrameTraceMainActivity"
+
+suspend inline fun traceFirstFramePreview(cookie: Int, crossinline block: suspend () -> Unit) {
+    traceAsync(FIRST_FRAME_TRACE_PREVIEW, cookie) {
+        block()
+    }
+}
+suspend inline fun traceFirstFrameMainActivity(cookie: Int, crossinline block: suspend () -> Unit) {
+    traceAsync(FIRST_FRAME_TRACE_MAIN_ACTIVITY, cookie) {
+        block()
+    }
+}
diff --git a/data/settings/build.gradle.kts b/data/settings/build.gradle.kts
index 60c9aa0..e0edd40 100644
--- a/data/settings/build.gradle.kts
+++ b/data/settings/build.gradle.kts
@@ -25,6 +25,7 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.data.settings"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -35,6 +36,19 @@ android {
         consumerProguardFiles("consumer-rules.pro")
     }
 
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
+    }
+
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_17
         targetCompatibility = JavaVersion.VERSION_17
diff --git a/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/LocalSettingsRepositoryInstrumentedTest.kt b/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/LocalSettingsRepositoryInstrumentedTest.kt
index 44846ac..2c67114 100644
--- a/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/LocalSettingsRepositoryInstrumentedTest.kt
+++ b/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/LocalSettingsRepositoryInstrumentedTest.kt
@@ -28,6 +28,7 @@ import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
 import java.io.File
 import kotlinx.coroutines.CoroutineScope
@@ -147,4 +148,18 @@ class LocalSettingsRepositoryInstrumentedTest {
         assertThat(initialDynamicRange).isEqualTo(DynamicRange.SDR)
         assertThat(newDynamicRange).isEqualTo(DynamicRange.HLG10)
     }
+
+    @Test
+    fun can_update_image_format() = runTest {
+        val initialImageFormat = repository.getCurrentDefaultCameraAppSettings().imageFormat
+
+        repository.updateImageFormat(imageFormat = ImageOutputFormat.JPEG_ULTRA_HDR)
+
+        advanceUntilIdle()
+
+        val newImageFormat = repository.getCurrentDefaultCameraAppSettings().imageFormat
+
+        assertThat(initialImageFormat).isEqualTo(ImageOutputFormat.JPEG)
+        assertThat(newImageFormat).isEqualTo(ImageOutputFormat.JPEG_ULTRA_HDR)
+    }
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt
index e0196eb..1a07af2 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt
@@ -32,6 +32,7 @@ object JcaSettingsSerializer : Serializer<JcaSettings> {
         .setStabilizePreview(PreviewStabilization.PREVIEW_STABILIZATION_UNDEFINED)
         .setStabilizeVideo(VideoStabilization.VIDEO_STABILIZATION_UNDEFINED)
         .setDynamicRangeStatus(DynamicRange.DYNAMIC_RANGE_UNSPECIFIED)
+        .setImageFormatStatus(ImageOutputFormat.IMAGE_OUTPUT_FORMAT_JPEG)
         .build()
 
     override suspend fun readFrom(input: InputStream): JcaSettings {
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt
index 80d6e00..fb10dc2 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt
@@ -29,6 +29,8 @@ import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.DynamicRange.Companion.toProto
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.ImageOutputFormat.Companion.toProto
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.LensFacing.Companion.toProto
 import com.google.jetpackcamera.settings.model.Stabilization
@@ -36,9 +38,7 @@ import javax.inject.Inject
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
 
-const val TARGET_FPS_NONE = 0
 const val TARGET_FPS_15 = 15
-const val TARGET_FPS_30 = 30
 const val TARGET_FPS_60 = 60
 
 /**
@@ -73,7 +73,8 @@ class LocalSettingsRepository @Inject constructor(
                     CaptureModeProto.CAPTURE_MODE_MULTI_STREAM -> CaptureMode.MULTI_STREAM
                     else -> CaptureMode.MULTI_STREAM
                 },
-                dynamicRange = DynamicRange.fromProto(it.dynamicRangeStatus)
+                dynamicRange = DynamicRange.fromProto(it.dynamicRangeStatus),
+                imageFormat = ImageOutputFormat.fromProto(it.imageFormatStatus)
             )
         }
 
@@ -180,4 +181,12 @@ class LocalSettingsRepository @Inject constructor(
                 .build()
         }
     }
+
+    override suspend fun updateImageFormat(imageFormat: ImageOutputFormat) {
+        jcaSettings.updateData { currentSettings ->
+            currentSettings.toBuilder()
+                .setImageFormatStatus(imageFormat.toProto())
+                .build()
+        }
+    }
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt
index 6e0fb3d..2631d7f 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt
@@ -21,6 +21,7 @@ import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.Stabilization
 import kotlinx.coroutines.flow.Flow
@@ -51,4 +52,6 @@ interface SettingsRepository {
     suspend fun updateDynamicRange(dynamicRange: DynamicRange)
 
     suspend fun updateTargetFrameRate(targetFrameRate: Int)
+
+    suspend fun updateImageFormat(imageFormat: ImageOutputFormat)
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/AspectRatio.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/AspectRatio.kt
index 8de6ea3..2725bf5 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/AspectRatio.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/AspectRatio.kt
@@ -23,6 +23,10 @@ enum class AspectRatio(val ratio: Rational) {
     NINE_SIXTEEN(Rational(9, 16)),
     ONE_ONE(Rational(1, 1));
 
+    val landscapeRatio: Rational by lazy {
+        Rational(ratio.denominator, ratio.numerator)
+    }
+
     companion object {
 
         /** returns the AspectRatio enum equivalent of a provided AspectRatioProto */
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
index 0bb37c2..1daa078 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
@@ -29,8 +29,14 @@ data class CameraAppSettings(
     val videoCaptureStabilization: Stabilization = Stabilization.UNDEFINED,
     val dynamicRange: DynamicRange = DynamicRange.SDR,
     val defaultHdrDynamicRange: DynamicRange = DynamicRange.HLG10,
+    val defaultHdrImageOutputFormat: ImageOutputFormat = ImageOutputFormat.JPEG_ULTRA_HDR,
+    val lowLightBoost: LowLightBoost = LowLightBoost.DISABLED,
     val zoomScale: Float = 1f,
-    val targetFrameRate: Int = TARGET_FPS_AUTO
+    val targetFrameRate: Int = TARGET_FPS_AUTO,
+    val imageFormat: ImageOutputFormat = ImageOutputFormat.JPEG,
+    val audioMuted: Boolean = false,
+    val deviceRotation: DeviceRotation = DeviceRotation.Natural,
+    val concurrentCameraMode: ConcurrentCameraMode = ConcurrentCameraMode.OFF
 )
 
 fun SystemConstraints.forCurrentLens(cameraAppSettings: CameraAppSettings): CameraConstraints? {
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/ConcurrentCameraMode.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/ConcurrentCameraMode.kt
new file mode 100644
index 0000000..621296a
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/ConcurrentCameraMode.kt
@@ -0,0 +1,21 @@
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
+package com.google.jetpackcamera.settings.model
+
+enum class ConcurrentCameraMode {
+    OFF,
+    DUAL
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
index d4f7364..8b75351 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
@@ -17,13 +17,16 @@ package com.google.jetpackcamera.settings.model
 
 data class SystemConstraints(
     val availableLenses: List<LensFacing>,
+    val concurrentCamerasSupported: Boolean,
     val perLensConstraints: Map<LensFacing, CameraConstraints>
 )
 
 data class CameraConstraints(
     val supportedStabilizationModes: Set<SupportedStabilizationMode>,
     val supportedFixedFrameRates: Set<Int>,
-    val supportedDynamicRanges: Set<DynamicRange>
+    val supportedDynamicRanges: Set<DynamicRange>,
+    val supportedImageFormatsMap: Map<CaptureMode, Set<ImageOutputFormat>>,
+    val hasFlashUnit: Boolean
 )
 
 /**
@@ -32,6 +35,7 @@ data class CameraConstraints(
 val TYPICAL_SYSTEM_CONSTRAINTS =
     SystemConstraints(
         availableLenses = listOf(LensFacing.FRONT, LensFacing.BACK),
+        concurrentCamerasSupported = false,
         perLensConstraints = buildMap {
             for (lensFacing in listOf(LensFacing.FRONT, LensFacing.BACK)) {
                 put(
@@ -39,7 +43,12 @@ val TYPICAL_SYSTEM_CONSTRAINTS =
                     CameraConstraints(
                         supportedFixedFrameRates = setOf(15, 30),
                         supportedStabilizationModes = emptySet(),
-                        supportedDynamicRanges = setOf(DynamicRange.SDR)
+                        supportedDynamicRanges = setOf(DynamicRange.SDR),
+                        supportedImageFormatsMap = mapOf(
+                            Pair(CaptureMode.SINGLE_STREAM, setOf(ImageOutputFormat.JPEG)),
+                            Pair(CaptureMode.MULTI_STREAM, setOf(ImageOutputFormat.JPEG))
+                        ),
+                        hasFlashUnit = lensFacing == LensFacing.BACK
                     )
                 )
             }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/DeviceRotation.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/DeviceRotation.kt
new file mode 100644
index 0000000..95e3c06
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/DeviceRotation.kt
@@ -0,0 +1,70 @@
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
+package com.google.jetpackcamera.settings.model
+
+import android.view.Surface
+
+enum class DeviceRotation {
+    Natural,
+    Rotated90,
+    Rotated180,
+    Rotated270;
+
+    /**
+     * Returns the rotation of the UI, expressed as a [Surface] rotation constant, needed to
+     * compensate for device rotation.
+     *
+     * These values do not match up with the device rotation angle. When the device is rotated,
+     * the UI must rotate in the opposite direction to compensate, so the angles 90 and 270 will
+     * be swapped in UI rotation compared to device rotation.
+     */
+    fun toUiSurfaceRotation(): Int {
+        return when (this) {
+            Natural -> Surface.ROTATION_0
+            Rotated90 -> Surface.ROTATION_270
+            Rotated180 -> Surface.ROTATION_180
+            Rotated270 -> Surface.ROTATION_90
+        }
+    }
+
+    fun toClockwiseRotationDegrees(): Int {
+        return when (this) {
+            Natural -> 0
+            Rotated90 -> 90
+            Rotated180 -> 180
+            Rotated270 -> 270
+        }
+    }
+
+    companion object {
+        fun snapFrom(degrees: Int): DeviceRotation {
+            check(degrees in 0..359) {
+                "Degrees must be in the range [0, 360)"
+            }
+
+            return when (val snappedDegrees = ((degrees + 45) / 90 * 90) % 360) {
+                0 -> Natural
+                90 -> Rotated90
+                180 -> Rotated180
+                270 -> Rotated270
+                else -> throw IllegalStateException(
+                    "Unexpected snapped degrees: $snappedDegrees" +
+                        ". Should be one of 0, 90, 180 or 270."
+                )
+            }
+        }
+    }
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/ImageOutputFormat.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/ImageOutputFormat.kt
new file mode 100644
index 0000000..9f9cf46
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/ImageOutputFormat.kt
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
+package com.google.jetpackcamera.settings.model
+
+import com.google.jetpackcamera.settings.ImageOutputFormat as ImageOutputFormatProto
+
+enum class ImageOutputFormat {
+    JPEG,
+    JPEG_ULTRA_HDR;
+
+    companion object {
+
+        /** returns the DynamicRangeType enum equivalent of a provided DynamicRangeTypeProto */
+        fun fromProto(imageOutputFormatProto: ImageOutputFormatProto): ImageOutputFormat {
+            return when (imageOutputFormatProto) {
+                ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG_ULTRA_HDR -> JPEG_ULTRA_HDR
+
+                // Treat unrecognized as JPEG as a fallback
+                ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG,
+                ImageOutputFormatProto.UNRECOGNIZED -> JPEG
+            }
+        }
+
+        fun ImageOutputFormat.toProto(): ImageOutputFormatProto {
+            return when (this) {
+                JPEG -> ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG
+                JPEG_ULTRA_HDR -> ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG_ULTRA_HDR
+            }
+        }
+    }
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoost.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoost.kt
new file mode 100644
index 0000000..8fd7221
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoost.kt
@@ -0,0 +1,21 @@
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
+package com.google.jetpackcamera.settings.model
+
+enum class LowLightBoost {
+    DISABLED,
+    ENABLED
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt
index c7ed7b7..fce599f 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt
@@ -23,6 +23,7 @@ import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.Stabilization
 import kotlinx.coroutines.flow.Flow
@@ -78,4 +79,8 @@ object FakeSettingsRepository : SettingsRepository {
         currentCameraSettings =
             currentCameraSettings.copy(targetFrameRate = targetFrameRate)
     }
+
+    override suspend fun updateImageFormat(imageFormat: ImageOutputFormat) {
+        currentCameraSettings = currentCameraSettings.copy(imageFormat = imageFormat)
+    }
 }
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/image_output_format.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/image_output_format.proto
new file mode 100644
index 0000000..dedeb4f
--- /dev/null
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/image_output_format.proto
@@ -0,0 +1,25 @@
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
+syntax = "proto3";
+
+option java_package = "com.google.jetpackcamera.settings";
+option java_multiple_files = true;
+
+enum ImageOutputFormat {
+  IMAGE_OUTPUT_FORMAT_JPEG = 0;
+  IMAGE_OUTPUT_FORMAT_JPEG_ULTRA_HDR = 1;
+}
\ No newline at end of file
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto
index cc87e43..03aeb6d 100644
--- a/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto
@@ -21,6 +21,7 @@ import "com/google/jetpackcamera/settings/capture_mode.proto";
 import "com/google/jetpackcamera/settings/dark_mode.proto";
 import "com/google/jetpackcamera/settings/dynamic_range.proto";
 import "com/google/jetpackcamera/settings/flash_mode.proto";
+import "com/google/jetpackcamera/settings/image_output_format.proto";
 import "com/google/jetpackcamera/settings/lens_facing.proto";
 import "com/google/jetpackcamera/settings/preview_stabilization.proto";
 import "com/google/jetpackcamera/settings/video_stabilization.proto";
@@ -39,6 +40,7 @@ message JcaSettings {
   PreviewStabilization stabilize_preview = 6;
   VideoStabilization stabilize_video = 7;
   DynamicRange dynamic_range_status = 8;
+  ImageOutputFormat image_format_status = 10;
 
   // Non-camera app settings
   DarkMode dark_mode_status = 9;
diff --git a/data/settings/src/test/java/com/google/jetpackcamera/settings/ProtoConversionTest.kt b/data/settings/src/test/java/com/google/jetpackcamera/settings/ProtoConversionTest.kt
index a598530..95503bc 100644
--- a/data/settings/src/test/java/com/google/jetpackcamera/settings/ProtoConversionTest.kt
+++ b/data/settings/src/test/java/com/google/jetpackcamera/settings/ProtoConversionTest.kt
@@ -17,8 +17,11 @@ package com.google.jetpackcamera.settings
 
 import com.google.common.truth.Truth.assertThat
 import com.google.jetpackcamera.settings.DynamicRange as DynamicRangeProto
+import com.google.jetpackcamera.settings.ImageOutputFormat as ImageOutputFormatProto
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.DynamicRange.Companion.toProto
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
+import com.google.jetpackcamera.settings.model.ImageOutputFormat.Companion.toProto
 import org.junit.Test
 
 class ProtoConversionTest {
@@ -61,4 +64,44 @@ class ProtoConversionTest {
             assertThat(correctConversions(it)).isEqualTo(DynamicRange.fromProto(it))
         }
     }
+
+    @Test
+    fun imageOutputFormat_convertsToCorrectProto() {
+        val correctConversions = { imageOutputFormat: ImageOutputFormat ->
+            when (imageOutputFormat) {
+                ImageOutputFormat.JPEG -> ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG
+                ImageOutputFormat.JPEG_ULTRA_HDR
+                -> ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG_ULTRA_HDR
+                else -> TODO(
+                    "Test does not yet contain correct conversion for image output format " +
+                        "type: ${imageOutputFormat.name}"
+                )
+            }
+        }
+
+        enumValues<ImageOutputFormat>().forEach {
+            assertThat(correctConversions(it)).isEqualTo(it.toProto())
+        }
+    }
+
+    @Test
+    fun imageOutputFormatProto_convertsToCorrectImageOutputFormat() {
+        val correctConversions = { imageOutputFormatProto: ImageOutputFormatProto ->
+            when (imageOutputFormatProto) {
+                ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG,
+                ImageOutputFormatProto.UNRECOGNIZED
+                -> ImageOutputFormat.JPEG
+                ImageOutputFormatProto.IMAGE_OUTPUT_FORMAT_JPEG_ULTRA_HDR
+                -> ImageOutputFormat.JPEG_ULTRA_HDR
+                else -> TODO(
+                    "Test does not yet contain correct conversion for image output format " +
+                        "proto type: ${imageOutputFormatProto.name}"
+                )
+            }
+        }
+
+        enumValues<ImageOutputFormatProto>().forEach {
+            assertThat(correctConversions(it)).isEqualTo(ImageOutputFormat.fromProto(it))
+        }
+    }
 }
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraXCameraUseCase.kt b/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraXCameraUseCase.kt
deleted file mode 100644
index 97dd767..0000000
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/CameraXCameraUseCase.kt
+++ /dev/null
@@ -1,827 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package com.google.jetpackcamera.domain.camera
-
-import android.Manifest
-import android.app.Application
-import android.content.ContentResolver
-import android.content.ContentValues
-import android.content.pm.PackageManager
-import android.net.Uri
-import android.os.Environment
-import android.provider.MediaStore
-import android.util.Log
-import android.util.Range
-import android.view.Display
-import androidx.camera.core.AspectRatio.RATIO_16_9
-import androidx.camera.core.AspectRatio.RATIO_4_3
-import androidx.camera.core.AspectRatio.RATIO_DEFAULT
-import androidx.camera.core.CameraEffect
-import androidx.camera.core.CameraInfo
-import androidx.camera.core.CameraSelector
-import androidx.camera.core.DynamicRange as CXDynamicRange
-import androidx.camera.core.ImageCapture
-import androidx.camera.core.ImageCapture.OutputFileOptions
-import androidx.camera.core.ImageCapture.ScreenFlash
-import androidx.camera.core.ImageCaptureException
-import androidx.camera.core.Preview
-import androidx.camera.core.SurfaceRequest
-import androidx.camera.core.UseCaseGroup
-import androidx.camera.core.ViewPort
-import androidx.camera.core.resolutionselector.AspectRatioStrategy
-import androidx.camera.core.resolutionselector.ResolutionSelector
-import androidx.camera.core.takePicture
-import androidx.camera.lifecycle.ProcessCameraProvider
-import androidx.camera.lifecycle.awaitInstance
-import androidx.camera.video.MediaStoreOutputOptions
-import androidx.camera.video.Recorder
-import androidx.camera.video.Recording
-import androidx.camera.video.VideoCapture
-import androidx.camera.video.VideoRecordEvent
-import androidx.camera.video.VideoRecordEvent.Finalize.ERROR_NONE
-import androidx.core.content.ContextCompat
-import androidx.core.content.ContextCompat.checkSelfPermission
-import com.google.jetpackcamera.domain.camera.CameraUseCase.ScreenFlashEvent.Type
-import com.google.jetpackcamera.domain.camera.effects.SingleSurfaceForcingEffect
-import com.google.jetpackcamera.settings.SettableConstraintsRepository
-import com.google.jetpackcamera.settings.SettingsRepository
-import com.google.jetpackcamera.settings.model.AspectRatio
-import com.google.jetpackcamera.settings.model.CameraAppSettings
-import com.google.jetpackcamera.settings.model.CameraConstraints
-import com.google.jetpackcamera.settings.model.CaptureMode
-import com.google.jetpackcamera.settings.model.DynamicRange
-import com.google.jetpackcamera.settings.model.FlashMode
-import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
-import com.google.jetpackcamera.settings.model.SupportedStabilizationMode
-import com.google.jetpackcamera.settings.model.SystemConstraints
-import dagger.hilt.android.scopes.ViewModelScoped
-import java.io.FileNotFoundException
-import java.lang.IllegalArgumentException
-import java.text.SimpleDateFormat
-import java.util.Calendar
-import java.util.Date
-import java.util.Locale
-import java.util.concurrent.Executor
-import javax.inject.Inject
-import kotlin.coroutines.ContinuationInterceptor
-import kotlin.properties.Delegates
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.asExecutor
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.currentCoroutineContext
-import kotlinx.coroutines.flow.MutableSharedFlow
-import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.StateFlow
-import kotlinx.coroutines.flow.asSharedFlow
-import kotlinx.coroutines.flow.asStateFlow
-import kotlinx.coroutines.flow.collectLatest
-import kotlinx.coroutines.flow.distinctUntilChanged
-import kotlinx.coroutines.flow.filterNotNull
-import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.flow.map
-import kotlinx.coroutines.flow.update
-import kotlinx.coroutines.launch
-
-private const val TAG = "CameraXCameraUseCase"
-const val TARGET_FPS_AUTO = 0
-const val TARGET_FPS_15 = 15
-const val TARGET_FPS_30 = 30
-const val TARGET_FPS_60 = 60
-
-/**
- * CameraX based implementation for [CameraUseCase]
- */
-@ViewModelScoped
-class CameraXCameraUseCase
-@Inject
-constructor(
-    private val application: Application,
-    private val coroutineScope: CoroutineScope,
-    private val defaultDispatcher: CoroutineDispatcher,
-    private val settingsRepository: SettingsRepository,
-    private val constraintsRepository: SettableConstraintsRepository
-) : CameraUseCase {
-    private lateinit var cameraProvider: ProcessCameraProvider
-
-    private lateinit var imageCaptureUseCase: ImageCapture
-
-    private var videoCaptureUseCase: VideoCapture<Recorder>? = null
-    private var recording: Recording? = null
-    private lateinit var captureMode: CaptureMode
-    private lateinit var systemConstraints: SystemConstraints
-    private var disableVideoCapture by Delegates.notNull<Boolean>()
-
-    private val screenFlashEvents: MutableSharedFlow<CameraUseCase.ScreenFlashEvent> =
-        MutableSharedFlow()
-
-    private val currentSettings = MutableStateFlow<CameraAppSettings?>(null)
-
-    override suspend fun initialize(externalImageCapture: Boolean) {
-        this.disableVideoCapture = externalImageCapture
-        cameraProvider = ProcessCameraProvider.awaitInstance(application)
-
-        // updates values for available cameras
-        val availableCameraLenses =
-            listOf(
-                LensFacing.FRONT,
-                LensFacing.BACK
-            ).filter {
-                cameraProvider.hasCamera(it.toCameraSelector())
-            }
-
-        // Build and update the system constraints
-        systemConstraints = SystemConstraints(
-            availableLenses = availableCameraLenses,
-            perLensConstraints = buildMap {
-                val availableCameraInfos = cameraProvider.availableCameraInfos
-                for (lensFacing in availableCameraLenses) {
-                    val selector = lensFacing.toCameraSelector()
-                    selector.filter(availableCameraInfos).firstOrNull()?.let { camInfo ->
-                        val supportedDynamicRanges =
-                            Recorder.getVideoCapabilities(camInfo).supportedDynamicRanges
-                                .mapNotNull(CXDynamicRange::toSupportedAppDynamicRange)
-                                .toSet()
-
-                        val supportedStabilizationModes = buildSet {
-                            if (isPreviewStabilizationSupported(camInfo)) {
-                                add(SupportedStabilizationMode.ON)
-                            }
-
-                            if (isVideoStabilizationSupported(camInfo)) {
-                                add(SupportedStabilizationMode.HIGH_QUALITY)
-                            }
-                        }
-
-                        val supportedFixedFrameRates = getSupportedFrameRates(camInfo)
-
-                        put(
-                            lensFacing,
-                            CameraConstraints(
-                                supportedStabilizationModes = supportedStabilizationModes,
-                                supportedFixedFrameRates = supportedFixedFrameRates,
-                                supportedDynamicRanges = supportedDynamicRanges
-                            )
-                        )
-                    }
-                }
-            }
-        )
-
-        constraintsRepository.updateSystemConstraints(systemConstraints)
-
-        currentSettings.value =
-            settingsRepository.defaultCameraAppSettings.first()
-                .tryApplyDynamicRangeConstraints()
-                .tryApplyAspectRatioForExternalCapture(externalImageCapture)
-
-        imageCaptureUseCase = ImageCapture.Builder()
-            .setResolutionSelector(
-                getResolutionSelector(
-                    settingsRepository.defaultCameraAppSettings.first().aspectRatio
-                )
-            ).build()
-    }
-
-    /**
-     * Returns the union of supported stabilization modes for a device's cameras
-     */
-    private fun getDeviceSupportedStabilizations(): Set<SupportedStabilizationMode> {
-        val deviceSupportedStabilizationModes = mutableSetOf<SupportedStabilizationMode>()
-
-        cameraProvider.availableCameraInfos.forEach { cameraInfo ->
-            if (isPreviewStabilizationSupported(cameraInfo)) {
-                deviceSupportedStabilizationModes.add(SupportedStabilizationMode.ON)
-            }
-            if (isVideoStabilizationSupported(cameraInfo)) {
-                deviceSupportedStabilizationModes.add(SupportedStabilizationMode.HIGH_QUALITY)
-            }
-        }
-        return deviceSupportedStabilizationModes
-    }
-
-    /**
-     * Camera settings that persist as long as a camera is running.
-     *
-     * Any change in these settings will require calling [ProcessCameraProvider.runWith] with
-     * updates [CameraSelector] and/or [UseCaseGroup]
-     */
-    private data class PerpetualSessionSettings(
-        val cameraSelector: CameraSelector,
-        val aspectRatio: AspectRatio,
-        val captureMode: CaptureMode,
-        val targetFrameRate: Int,
-        val stabilizePreviewMode: Stabilization,
-        val stabilizeVideoMode: Stabilization,
-        val dynamicRange: DynamicRange
-    )
-
-    /**
-     * Camera settings that can change while the camera is running.
-     *
-     * Any changes in these settings can be applied either directly to use cases via their
-     * setter methods or to [androidx.camera.core.CameraControl].
-     * The use cases typically will not need to be re-bound.
-     */
-    private data class TransientSessionSettings(
-        val flashMode: FlashMode,
-        val zoomScale: Float
-    )
-
-    override suspend fun runCamera() = coroutineScope {
-        Log.d(TAG, "runCamera")
-
-        val transientSettings = MutableStateFlow<TransientSessionSettings?>(null)
-        currentSettings
-            .filterNotNull()
-            .map { currentCameraSettings ->
-                transientSettings.value = TransientSessionSettings(
-                    flashMode = currentCameraSettings.flashMode,
-                    zoomScale = currentCameraSettings.zoomScale
-                )
-
-                val cameraSelector = when (currentCameraSettings.cameraLensFacing) {
-                    LensFacing.FRONT -> CameraSelector.DEFAULT_FRONT_CAMERA
-                    LensFacing.BACK -> CameraSelector.DEFAULT_BACK_CAMERA
-                }
-
-                PerpetualSessionSettings(
-                    cameraSelector = cameraSelector,
-                    aspectRatio = currentCameraSettings.aspectRatio,
-                    captureMode = currentCameraSettings.captureMode,
-                    targetFrameRate = currentCameraSettings.targetFrameRate,
-                    stabilizePreviewMode = currentCameraSettings.previewStabilization,
-                    stabilizeVideoMode = currentCameraSettings.videoCaptureStabilization,
-                    dynamicRange = currentCameraSettings.dynamicRange
-                )
-            }.distinctUntilChanged()
-            .collectLatest { sessionSettings ->
-                Log.d(TAG, "Starting new camera session")
-                val cameraInfo = sessionSettings.cameraSelector.filter(
-                    cameraProvider.availableCameraInfos
-                ).first()
-
-                val lensFacing = sessionSettings.cameraSelector.toAppLensFacing()
-                val cameraConstraints = checkNotNull(
-                    systemConstraints.perLensConstraints[lensFacing]
-                ) {
-                    "Unable to retrieve CameraConstraints for $lensFacing. " +
-                        "Was the use case initialized?"
-                }
-
-                val initialTransientSettings = transientSettings
-                    .filterNotNull()
-                    .first()
-
-                val useCaseGroup = createUseCaseGroup(
-                    sessionSettings,
-                    initialTransientSettings,
-                    cameraConstraints.supportedStabilizationModes,
-                    effect = when (sessionSettings.captureMode) {
-                        CaptureMode.SINGLE_STREAM -> SingleSurfaceForcingEffect(coroutineScope)
-                        CaptureMode.MULTI_STREAM -> null
-                    }
-                )
-
-                var prevTransientSettings = initialTransientSettings
-                cameraProvider.runWith(sessionSettings.cameraSelector, useCaseGroup) { camera ->
-                    Log.d(TAG, "Camera session started")
-                    transientSettings.filterNotNull().collectLatest { newTransientSettings ->
-                        // Apply camera control settings
-                        if (prevTransientSettings.zoomScale != newTransientSettings.zoomScale) {
-                            cameraInfo.zoomState.value?.let { zoomState ->
-                                val finalScale =
-                                    (zoomState.zoomRatio * newTransientSettings.zoomScale).coerceIn(
-                                        zoomState.minZoomRatio,
-                                        zoomState.maxZoomRatio
-                                    )
-                                camera.cameraControl.setZoomRatio(finalScale)
-                                _zoomScale.value = finalScale
-                            }
-                        }
-
-                        if (prevTransientSettings.flashMode != newTransientSettings.flashMode) {
-                            setFlashModeInternal(
-                                flashMode = newTransientSettings.flashMode,
-                                isFrontFacing = sessionSettings.cameraSelector
-                                    == CameraSelector.DEFAULT_FRONT_CAMERA
-                            )
-                        }
-
-                        prevTransientSettings = newTransientSettings
-                    }
-                }
-            }
-    }
-
-    override suspend fun takePicture(onCaptureStarted: (() -> Unit)) {
-        try {
-            val imageProxy = imageCaptureUseCase.takePicture(onCaptureStarted)
-            Log.d(TAG, "onCaptureSuccess")
-            imageProxy.close()
-        } catch (exception: Exception) {
-            Log.d(TAG, "takePicture onError: $exception")
-            throw exception
-        }
-    }
-
-    // TODO(b/319733374): Return bitmap for external mediastore capture without URI
-    override suspend fun takePicture(
-        onCaptureStarted: (() -> Unit),
-        contentResolver: ContentResolver,
-        imageCaptureUri: Uri?,
-        ignoreUri: Boolean
-    ): ImageCapture.OutputFileResults {
-        val eligibleContentValues = getEligibleContentValues()
-        val outputFileOptions: OutputFileOptions
-        if (ignoreUri) {
-            val formatter = SimpleDateFormat(
-                "yyyy-MM-dd-HH-mm-ss-SSS",
-                Locale.US
-            )
-            val filename = "JCA-${formatter.format(Calendar.getInstance().time)}.jpg"
-            val contentValues = ContentValues()
-            contentValues.put(MediaStore.MediaColumns.DISPLAY_NAME, filename)
-            contentValues.put(MediaStore.MediaColumns.MIME_TYPE, "image/jpeg")
-            outputFileOptions = OutputFileOptions.Builder(
-                contentResolver,
-                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
-                contentValues
-            ).build()
-        } else if (imageCaptureUri == null) {
-            val e = RuntimeException("Null Uri is provided.")
-            Log.d(TAG, "takePicture onError: $e")
-            throw e
-        } else {
-            try {
-                val outputStream = contentResolver.openOutputStream(imageCaptureUri)
-                if (outputStream != null) {
-                    outputFileOptions =
-                        OutputFileOptions.Builder(
-                            contentResolver.openOutputStream(imageCaptureUri)!!
-                        ).build()
-                } else {
-                    val e = RuntimeException("Provider recently crashed.")
-                    Log.d(TAG, "takePicture onError: $e")
-                    throw e
-                }
-            } catch (e: FileNotFoundException) {
-                Log.d(TAG, "takePicture onError: $e")
-                throw e
-            }
-        }
-        try {
-            val outputFileResults = imageCaptureUseCase.takePicture(
-                outputFileOptions,
-                onCaptureStarted
-            )
-            val relativePath =
-                eligibleContentValues.getAsString(MediaStore.Images.Media.RELATIVE_PATH)
-            val displayName = eligibleContentValues.getAsString(
-                MediaStore.Images.Media.DISPLAY_NAME
-            )
-            Log.d(TAG, "Saved image to $relativePath/$displayName")
-            return outputFileResults
-        } catch (exception: ImageCaptureException) {
-            Log.d(TAG, "takePicture onError: $exception")
-            throw exception
-        }
-    }
-
-    private fun getEligibleContentValues(): ContentValues {
-        val eligibleContentValues = ContentValues()
-        eligibleContentValues.put(
-            MediaStore.Images.Media.DISPLAY_NAME,
-            Calendar.getInstance().time.toString()
-        )
-        eligibleContentValues.put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
-        eligibleContentValues.put(
-            MediaStore.Images.Media.RELATIVE_PATH,
-            Environment.DIRECTORY_PICTURES
-        )
-        return eligibleContentValues
-    }
-
-    override suspend fun startVideoRecording(
-        onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
-    ) {
-        if (videoCaptureUseCase == null) {
-            throw RuntimeException("Attempted video recording with null videoCapture use case")
-        }
-        Log.d(TAG, "recordVideo")
-        // todo(b/336886716): default setting to enable or disable audio when permission is granted
-        // todo(b/336888844): mute/unmute audio while recording is active
-        val audioEnabled = (
-            checkSelfPermission(
-                this.application.baseContext,
-                Manifest.permission.RECORD_AUDIO
-            )
-                == PackageManager.PERMISSION_GRANTED
-            )
-        val captureTypeString =
-            when (captureMode) {
-                CaptureMode.MULTI_STREAM -> "MultiStream"
-                CaptureMode.SINGLE_STREAM -> "SingleStream"
-            }
-        val name = "JCA-recording-${Date()}-$captureTypeString.mp4"
-        val contentValues =
-            ContentValues().apply {
-                put(MediaStore.Video.Media.DISPLAY_NAME, name)
-            }
-
-        val mediaStoreOutput =
-            MediaStoreOutputOptions.Builder(
-                application.contentResolver,
-                MediaStore.Video.Media.EXTERNAL_CONTENT_URI
-            )
-                .setContentValues(contentValues)
-                .build()
-
-        val callbackExecutor: Executor =
-            (
-                currentCoroutineContext()[ContinuationInterceptor] as?
-                    CoroutineDispatcher
-                )?.asExecutor() ?: ContextCompat.getMainExecutor(application)
-        recording =
-            videoCaptureUseCase!!.output
-                .prepareRecording(application, mediaStoreOutput)
-                .apply { if (audioEnabled) withAudioEnabled() }
-                .start(callbackExecutor) { onVideoRecordEvent ->
-                    run {
-                        Log.d(TAG, onVideoRecordEvent.toString())
-                        when (onVideoRecordEvent) {
-                            is VideoRecordEvent.Finalize -> {
-                                when (onVideoRecordEvent.error) {
-                                    ERROR_NONE ->
-                                        onVideoRecord(
-                                            CameraUseCase.OnVideoRecordEvent.OnVideoRecorded
-                                        )
-                                    else ->
-                                        onVideoRecord(
-                                            CameraUseCase.OnVideoRecordEvent.OnVideoRecordError
-                                        )
-                                }
-                            }
-                            is VideoRecordEvent.Status -> {
-                                onVideoRecord(
-                                    CameraUseCase.OnVideoRecordEvent.OnVideoRecordStatus(
-                                        onVideoRecordEvent.recordingStats.audioStats.audioAmplitude
-                                    )
-                                )
-                            }
-                        }
-                    }
-                }
-    }
-
-    override fun stopVideoRecording() {
-        Log.d(TAG, "stopRecording")
-        recording?.stop()
-    }
-
-    override fun setZoomScale(scale: Float) {
-        currentSettings.update { old ->
-            old?.copy(zoomScale = scale)
-        }
-    }
-
-    // Could be improved by setting initial value only when camera is initialized
-    private val _zoomScale = MutableStateFlow(1f)
-    override fun getZoomScale(): StateFlow<Float> = _zoomScale.asStateFlow()
-
-    private val _surfaceRequest = MutableStateFlow<SurfaceRequest?>(null)
-    override fun getSurfaceRequest(): StateFlow<SurfaceRequest?> = _surfaceRequest.asStateFlow()
-
-    // Sets the camera to the designated lensFacing direction
-    override suspend fun setLensFacing(lensFacing: LensFacing) {
-        currentSettings.update { old ->
-            if (systemConstraints.availableLenses.contains(lensFacing)) {
-                old?.copy(cameraLensFacing = lensFacing)
-                    ?.tryApplyDynamicRangeConstraints()
-            } else {
-                old
-            }
-        }
-    }
-
-    private fun CameraAppSettings.tryApplyDynamicRangeConstraints(): CameraAppSettings {
-        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
-            with(constraints.supportedDynamicRanges) {
-                val newDynamicRange = if (contains(dynamicRange)) {
-                    dynamicRange
-                } else {
-                    DynamicRange.SDR
-                }
-
-                this@tryApplyDynamicRangeConstraints.copy(
-                    dynamicRange = newDynamicRange
-                )
-            }
-        } ?: this
-    }
-
-    private fun CameraAppSettings.tryApplyAspectRatioForExternalCapture(
-        externalImageCapture: Boolean
-    ): CameraAppSettings {
-        if (externalImageCapture) {
-            return this.copy(aspectRatio = AspectRatio.THREE_FOUR)
-        }
-        return this
-    }
-
-    override fun tapToFocus(
-        display: Display,
-        surfaceWidth: Int,
-        surfaceHeight: Int,
-        x: Float,
-        y: Float
-    ) {
-        // TODO(tm):Convert API to use SurfaceOrientedMeteringPointFactory and
-        // use a Channel to get result of FocusMeteringAction
-    }
-
-    override fun getScreenFlashEvents() = screenFlashEvents.asSharedFlow()
-    override fun getCurrentSettings() = currentSettings.asStateFlow()
-
-    override fun setFlashMode(flashMode: FlashMode) {
-        currentSettings.update { old ->
-            old?.copy(flashMode = flashMode)
-        }
-    }
-
-    private fun setFlashModeInternal(flashMode: FlashMode, isFrontFacing: Boolean) {
-        val isScreenFlashRequired =
-            isFrontFacing && (flashMode == FlashMode.ON || flashMode == FlashMode.AUTO)
-
-        if (isScreenFlashRequired) {
-            imageCaptureUseCase.screenFlash = object : ScreenFlash {
-                override fun apply(
-                    expirationTimeMillis: Long,
-                    listener: ImageCapture.ScreenFlashListener
-                ) {
-                    Log.d(TAG, "ImageCapture.ScreenFlash: apply")
-                    coroutineScope.launch {
-                        screenFlashEvents.emit(
-                            CameraUseCase.ScreenFlashEvent(Type.APPLY_UI) {
-                                listener.onCompleted()
-                            }
-                        )
-                    }
-                }
-
-                override fun clear() {
-                    Log.d(TAG, "ImageCapture.ScreenFlash: clear")
-                    coroutineScope.launch {
-                        screenFlashEvents.emit(
-                            CameraUseCase.ScreenFlashEvent(Type.CLEAR_UI) {}
-                        )
-                    }
-                }
-            }
-        }
-
-        imageCaptureUseCase.flashMode = when (flashMode) {
-            FlashMode.OFF -> ImageCapture.FLASH_MODE_OFF // 2
-
-            FlashMode.ON -> if (isScreenFlashRequired) {
-                ImageCapture.FLASH_MODE_SCREEN // 3
-            } else {
-                ImageCapture.FLASH_MODE_ON // 1
-            }
-
-            FlashMode.AUTO -> if (isScreenFlashRequired) {
-                ImageCapture.FLASH_MODE_SCREEN // 3
-            } else {
-                ImageCapture.FLASH_MODE_AUTO // 0
-            }
-        }
-        Log.d(TAG, "Set flash mode to: ${imageCaptureUseCase.flashMode}")
-    }
-
-    override fun isScreenFlashEnabled() =
-        imageCaptureUseCase.flashMode == ImageCapture.FLASH_MODE_SCREEN &&
-            imageCaptureUseCase.screenFlash != null
-
-    override suspend fun setAspectRatio(aspectRatio: AspectRatio) {
-        currentSettings.update { old ->
-            old?.copy(aspectRatio = aspectRatio)
-        }
-    }
-
-    override suspend fun setCaptureMode(captureMode: CaptureMode) {
-        currentSettings.update { old ->
-            old?.copy(captureMode = captureMode)
-        }
-    }
-
-    private fun createUseCaseGroup(
-        sessionSettings: PerpetualSessionSettings,
-        initialTransientSettings: TransientSessionSettings,
-        supportedStabilizationModes: Set<SupportedStabilizationMode>,
-        effect: CameraEffect? = null
-    ): UseCaseGroup {
-        val previewUseCase = createPreviewUseCase(sessionSettings, supportedStabilizationModes)
-        if (!disableVideoCapture) {
-            videoCaptureUseCase = createVideoUseCase(sessionSettings, supportedStabilizationModes)
-        }
-
-        setFlashModeInternal(
-            flashMode = initialTransientSettings.flashMode,
-            isFrontFacing = sessionSettings.cameraSelector == CameraSelector.DEFAULT_FRONT_CAMERA
-        )
-        imageCaptureUseCase = ImageCapture.Builder()
-            .setResolutionSelector(getResolutionSelector(sessionSettings.aspectRatio)).build()
-
-        return UseCaseGroup.Builder().apply {
-            setViewPort(
-                ViewPort.Builder(
-                    sessionSettings.aspectRatio.ratio,
-                    previewUseCase.targetRotation
-                ).build()
-            )
-            addUseCase(previewUseCase)
-            if (sessionSettings.dynamicRange == DynamicRange.SDR) {
-                addUseCase(imageCaptureUseCase)
-            }
-            if (videoCaptureUseCase != null) {
-                addUseCase(videoCaptureUseCase!!)
-            }
-
-//            effect?.let { addEffect(it) }
-
-            captureMode = sessionSettings.captureMode
-        }.build()
-    }
-    override suspend fun setDynamicRange(dynamicRange: DynamicRange) {
-        currentSettings.update { old ->
-            old?.copy(dynamicRange = dynamicRange)
-        }
-    }
-
-    private fun createVideoUseCase(
-        sessionSettings: PerpetualSessionSettings,
-        supportedStabilizationMode: Set<SupportedStabilizationMode>
-    ): VideoCapture<Recorder> {
-        val recorder = Recorder.Builder()
-            .setAspectRatio(getAspectRatioForUseCase(sessionSettings.aspectRatio))
-            .setExecutor(defaultDispatcher.asExecutor()).build()
-        return VideoCapture.Builder(recorder).apply {
-            // set video stabilization
-            if (shouldVideoBeStabilized(sessionSettings, supportedStabilizationMode)
-            ) {
-                setVideoStabilizationEnabled(true)
-            }
-            // set target fps
-            if (sessionSettings.targetFrameRate != TARGET_FPS_AUTO) {
-                setTargetFrameRate(
-                    Range(sessionSettings.targetFrameRate, sessionSettings.targetFrameRate)
-                )
-            }
-
-            setDynamicRange(sessionSettings.dynamicRange.toCXDynamicRange())
-        }.build()
-    }
-
-    private fun getAspectRatioForUseCase(aspectRatio: AspectRatio): Int {
-        return when (aspectRatio) {
-            AspectRatio.THREE_FOUR -> RATIO_4_3
-            AspectRatio.NINE_SIXTEEN -> RATIO_16_9
-            else -> RATIO_DEFAULT
-        }
-    }
-
-    private fun shouldVideoBeStabilized(
-        sessionSettings: PerpetualSessionSettings,
-        supportedStabilizationModes: Set<SupportedStabilizationMode>
-    ): Boolean {
-        // video is on and target fps is not 60
-        return (sessionSettings.targetFrameRate != TARGET_FPS_60) &&
-            (supportedStabilizationModes.contains(SupportedStabilizationMode.HIGH_QUALITY)) &&
-            // high quality (video only) selected
-            (
-                sessionSettings.stabilizeVideoMode == Stabilization.ON &&
-                    sessionSettings.stabilizePreviewMode == Stabilization.UNDEFINED
-                )
-    }
-
-    private fun createPreviewUseCase(
-        sessionSettings: PerpetualSessionSettings,
-        supportedStabilizationModes: Set<SupportedStabilizationMode>
-    ): Preview {
-        val previewUseCaseBuilder = Preview.Builder()
-        // set preview stabilization
-        if (shouldPreviewBeStabilized(sessionSettings, supportedStabilizationModes)) {
-            previewUseCaseBuilder.setPreviewStabilizationEnabled(true)
-        }
-
-        previewUseCaseBuilder.setResolutionSelector(
-            getResolutionSelector(sessionSettings.aspectRatio)
-        )
-
-        return previewUseCaseBuilder.build().apply {
-            setSurfaceProvider { surfaceRequest ->
-                _surfaceRequest.value = surfaceRequest
-            }
-        }
-    }
-
-    private fun getResolutionSelector(aspectRatio: AspectRatio): ResolutionSelector {
-        val aspectRatioStrategy = when (aspectRatio) {
-            AspectRatio.THREE_FOUR -> AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
-            AspectRatio.NINE_SIXTEEN -> AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
-            else -> AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
-        }
-        return ResolutionSelector.Builder().setAspectRatioStrategy(aspectRatioStrategy).build()
-    }
-
-    private fun shouldPreviewBeStabilized(
-        sessionSettings: PerpetualSessionSettings,
-        supportedStabilizationModes: Set<SupportedStabilizationMode>
-    ): Boolean {
-        // only supported if target fps is 30 or none
-        return (
-            when (sessionSettings.targetFrameRate) {
-                TARGET_FPS_AUTO, TARGET_FPS_30 -> true
-                else -> false
-            }
-            ) &&
-            (
-                supportedStabilizationModes.contains(SupportedStabilizationMode.ON) &&
-                    sessionSettings.stabilizePreviewMode == Stabilization.ON
-                )
-    }
-
-    companion object {
-        private val FIXED_FRAME_RATES = setOf(TARGET_FPS_15, TARGET_FPS_30, TARGET_FPS_60)
-
-        /**
-         * Checks if preview stabilization is supported by the device.
-         *
-         */
-        private fun isPreviewStabilizationSupported(cameraInfo: CameraInfo): Boolean {
-            return Preview.getPreviewCapabilities(cameraInfo).isStabilizationSupported
-        }
-
-        /**
-         * Checks if video stabilization is supported by the device.
-         *
-         */
-        private fun isVideoStabilizationSupported(cameraInfo: CameraInfo): Boolean {
-            return Recorder.getVideoCapabilities(cameraInfo).isStabilizationSupported
-        }
-
-        private fun getSupportedFrameRates(camInfo: CameraInfo): Set<Int> {
-            return buildSet {
-                camInfo.supportedFrameRateRanges.forEach { e ->
-                    if (e.upper == e.lower && FIXED_FRAME_RATES.contains(e.upper)) {
-                        add(e.upper)
-                    }
-                }
-            }
-        }
-    }
-}
-
-private fun CXDynamicRange.toSupportedAppDynamicRange(): DynamicRange? {
-    return when (this) {
-        CXDynamicRange.SDR -> DynamicRange.SDR
-        CXDynamicRange.HLG_10_BIT -> DynamicRange.HLG10
-        // All other dynamic ranges unsupported. Return null.
-        else -> null
-    }
-}
-
-private fun DynamicRange.toCXDynamicRange(): CXDynamicRange {
-    return when (this) {
-        DynamicRange.SDR -> CXDynamicRange.SDR
-        DynamicRange.HLG10 -> CXDynamicRange.HLG_10_BIT
-    }
-}
-
-private fun LensFacing.toCameraSelector(): CameraSelector = when (this) {
-    LensFacing.FRONT -> CameraSelector.DEFAULT_FRONT_CAMERA
-    LensFacing.BACK -> CameraSelector.DEFAULT_BACK_CAMERA
-}
-
-private fun CameraSelector.toAppLensFacing(): LensFacing = when (this) {
-    CameraSelector.DEFAULT_FRONT_CAMERA -> LensFacing.FRONT
-    CameraSelector.DEFAULT_BACK_CAMERA -> LensFacing.BACK
-    else -> throw IllegalArgumentException(
-        "Unknown CameraSelector -> LensFacing mapping. [CameraSelector: $this]"
-    )
-}
-
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/CopyingSurfaceProcessor.kt b/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/CopyingSurfaceProcessor.kt
deleted file mode 100644
index e5ea5ae..0000000
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/CopyingSurfaceProcessor.kt
+++ /dev/null
@@ -1,361 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.google.jetpackcamera.domain.camera.effects
-
-import android.graphics.SurfaceTexture
-import android.opengl.EGL14
-import android.opengl.EGLConfig
-import android.opengl.EGLExt
-import android.opengl.EGLSurface
-import android.util.Size
-import android.view.Surface
-import androidx.camera.core.SurfaceOutput
-import androidx.camera.core.SurfaceProcessor
-import androidx.camera.core.SurfaceRequest
-//import androidx.graphics.opengl.GLRenderer
-//import androidx.graphics.opengl.egl.EGLManager
-//import androidx.graphics.opengl.egl.EGLSpec
-import com.google.jetpackcamera.core.common.RefCounted
-import kotlin.coroutines.coroutineContext
-import kotlinx.coroutines.CompletableDeferred
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.CoroutineStart
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.Job
-import kotlinx.coroutines.Runnable
-import kotlinx.coroutines.SupervisorJob
-import kotlinx.coroutines.async
-import kotlinx.coroutines.cancel
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.ensureActive
-import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.collectLatest
-import kotlinx.coroutines.flow.filterNot
-import kotlinx.coroutines.flow.filterNotNull
-import kotlinx.coroutines.flow.onCompletion
-import kotlinx.coroutines.flow.update
-import kotlinx.coroutines.launch
-
-private const val TIMESTAMP_UNINITIALIZED = -1L
-
-/**
- * This is a [SurfaceProcessor] that passes on the same content from the input
- * surface to the output surface. Used to make a copies of surfaces.
- */
-class CopyingSurfaceProcessor(coroutineScope: CoroutineScope) : SurfaceProcessor {
-
-//    private val inputSurfaceFlow = MutableStateFlow<SurfaceRequestScope?>(null)
-//    private val outputSurfaceFlow = MutableStateFlow<SurfaceOutputScope?>(null)
-
-    init {
-//        coroutineScope.launch(start = CoroutineStart.UNDISPATCHED) {
-//            inputSurfaceFlow
-//                .filterNotNull()
-//                .collectLatest { surfaceRequestScope ->
-//                    surfaceRequestScope.withSurfaceRequest { surfaceRequest ->
-//
-//                        val renderCallbacks = ShaderCopy(surfaceRequest.dynamicRange)
-//                        renderCallbacks.renderWithSurfaceRequest(surfaceRequest)
-//                    }
-//                }
-//        }
-    }
-
-//    private suspend fun RenderCallbacks.renderWithSurfaceRequest(surfaceRequest: SurfaceRequest) =
-//        coroutineScope inputScope@{
-//            var currentTimestamp = TIMESTAMP_UNINITIALIZED
-//            val surfaceTextureRef = RefCounted<SurfaceTexture> {
-//                it.release()
-//            }
-//            val textureTransform = FloatArray(16)
-//
-//            val frameUpdateFlow = MutableStateFlow(0)
-//
-//            val initializeCallback = object : GLRenderer.EGLContextCallback {
-//
-//                override fun onEGLContextCreated(eglManager: EGLManager) {
-//                    initRenderer()
-//
-//                    val surfaceTex = createSurfaceTexture(
-//                        surfaceRequest.resolution.width,
-//                        surfaceRequest.resolution.height
-//                    )
-//
-//                    // Initialize the reference counted surface texture
-//                    surfaceTextureRef.initialize(surfaceTex)
-//
-//                    surfaceTex.setOnFrameAvailableListener {
-//                        // Increment frame counter
-//                        frameUpdateFlow.update { it + 1 }
-//                    }
-//
-//                    val inputSurface = Surface(surfaceTex)
-//                    surfaceRequest.provideSurface(inputSurface, Runnable::run) { result ->
-//                        inputSurface.release()
-//                        surfaceTextureRef.release()
-//                        this@inputScope.cancel(
-//                            "Input surface no longer receiving frames: $result"
-//                        )
-//                    }
-//                }
-//
-//                override fun onEGLContextDestroyed(eglManager: EGLManager) {
-//                    // no-op
-//                }
-//            }
-//
-//            val glRenderer = GLRenderer(
-//                eglSpecFactory = provideEGLSpec,
-//                eglConfigFactory = initConfig
-//            )
-//            glRenderer.registerEGLContextCallback(initializeCallback)
-//            glRenderer.start(glThreadName)
-//
-//            val inputRenderTarget = glRenderer.createRenderTarget(
-//                surfaceRequest.resolution.width,
-//                surfaceRequest.resolution.height,
-//                object : GLRenderer.RenderCallback {
-//
-//                    override fun onDrawFrame(eglManager: EGLManager) {
-//                        surfaceTextureRef.acquire()?.also {
-//                            try {
-//                                currentTimestamp =
-//                                    if (currentTimestamp == TIMESTAMP_UNINITIALIZED) {
-//                                        // Don't perform any updates on first draw,
-//                                        // we're only setting up the context.
-//                                        0
-//                                    } else {
-//                                        it.updateTexImage()
-//                                        it.getTransformMatrix(textureTransform)
-//                                        it.timestamp
-//                                    }
-//                            } finally {
-//                                surfaceTextureRef.release()
-//                            }
-//                        }
-//                    }
-//                }
-//            )
-//
-//            // Create the context and initialize the input. This will call RenderTarget.onDrawFrame,
-//            // but we won't actually update the frame since this triggers adding the frame callback.
-//            // All subsequent updates will then happen through frameUpdateFlow.
-//            // This should be updated when https://issuetracker.google.com/331968279 is resolved.
-//            inputRenderTarget.requestRender()
-//
-//            // Connect the onConnectToInput callback with the onDisconnectFromInput
-//            // Should only be called on worker thread
-//            var connectedToInput = false
-//
-//            // Should only be called on worker thread
-//            val onConnectToInput: () -> Boolean = {
-//                connectedToInput = surfaceTextureRef.acquire() != null
-//                connectedToInput
-//            }
-//
-//            // Should only be called on worker thread
-//            val onDisconnectFromInput: () -> Unit = {
-//                if (connectedToInput) {
-//                    surfaceTextureRef.release()
-//                    connectedToInput = false
-//                }
-//            }
-//
-//            // Wait for output surfaces
-//            outputSurfaceFlow
-//                .onCompletion {
-//                    glRenderer.stop(cancelPending = false)
-//                    glRenderer.unregisterEGLContextCallback(initializeCallback)
-//                }.filterNotNull()
-//                .collectLatest { surfaceOutputScope ->
-//                    surfaceOutputScope.withSurfaceOutput { refCountedSurface,
-//                                                           size,
-//                                                           updateTransformMatrix ->
-//                        // If we can't acquire the surface, then the surface output is already
-//                        // closed, so we'll return and wait for the next output surface.
-//                        val outputSurface =
-//                            refCountedSurface.acquire() ?: return@withSurfaceOutput
-//
-//                        val surfaceTransform = FloatArray(16)
-//                        val outputRenderTarget = glRenderer.attach(
-//                            outputSurface,
-//                            size.width,
-//                            size.height,
-//                            object : GLRenderer.RenderCallback {
-//
-//                                override fun onSurfaceCreated(
-//                                    spec: EGLSpec,
-//                                    config: EGLConfig,
-//                                    surface: Surface,
-//                                    width: Int,
-//                                    height: Int
-//                                ): EGLSurface? {
-//                                    return if (onConnectToInput()) {
-//                                        createOutputSurface(spec, config, surface, width, height)
-//                                    } else {
-//                                        null
-//                                    }
-//                                }
-//
-//                                override fun onDrawFrame(eglManager: EGLManager) {
-//                                    val currentDrawSurface = eglManager.currentDrawSurface
-//                                    if (currentDrawSurface != eglManager.defaultSurface) {
-//                                        updateTransformMatrix(
-//                                            surfaceTransform,
-//                                            textureTransform
-//                                        )
-//
-//                                        drawFrame(
-//                                            size.width,
-//                                            size.height,
-//                                            surfaceTransform
-//                                        )
-//
-//                                        // Set timestamp
-//                                        val display =
-//                                            EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
-//                                        EGLExt.eglPresentationTimeANDROID(
-//                                            display,
-//                                            eglManager.currentDrawSurface,
-//                                            currentTimestamp
-//                                        )
-//                                    }
-//                                }
-//                            }
-//                        )
-//
-//                        frameUpdateFlow
-//                            .onCompletion {
-//                                outputRenderTarget.detach(cancelPending = false) {
-//                                    onDisconnectFromInput()
-//                                    refCountedSurface.release()
-//                                }
-//                            }.filterNot { it == 0 } // Don't attempt render on frame count 0
-//                            .collectLatest {
-//                                inputRenderTarget.requestRender()
-//                                outputRenderTarget.requestRender()
-//                            }
-//                    }
-//                }
-//        }
-
-    override fun onInputSurface(surfaceRequest: SurfaceRequest) {
-//        val newScope = SurfaceRequestScope(surfaceRequest)
-//        inputSurfaceFlow.update { old ->
-//            old?.cancel("New SurfaceRequest received.")
-//            newScope
-//        }
-    }
-
-    override fun onOutputSurface(surfaceOutput: SurfaceOutput) {
-//        val newScope = SurfaceOutputScope(surfaceOutput)
-//        outputSurfaceFlow.update { old ->
-//            old?.cancel("New SurfaceOutput received.")
-//            newScope
-//        }
-    }
-}
-
-//interface RenderCallbacks {
-//    val glThreadName: String
-//    val provideEGLSpec: () -> EGLSpec
-//    val initConfig: EGLManager.() -> EGLConfig
-//    val initRenderer: () -> Unit
-//    val createSurfaceTexture: (width: Int, height: Int) -> SurfaceTexture
-//    val createOutputSurface: (
-//        eglSpec: EGLSpec,
-//        config: EGLConfig,
-//        surface: Surface,
-//        width: Int,
-//        height: Int
-//    ) -> EGLSurface
-//    val drawFrame: (outputWidth: Int, outputHeight: Int, surfaceTransform: FloatArray) -> Unit
-//}
-//
-//private class SurfaceOutputScope(val surfaceOutput: SurfaceOutput) {
-//    private val surfaceLifecycleJob = SupervisorJob()
-//    private val refCountedSurface = RefCounted<Surface>(onRelease = {
-//        surfaceOutput.close()
-//    }).apply {
-//        // Ensure we don't release until after `initialize` has completed by deferring
-//        // the release.
-//        val deferredRelease = CompletableDeferred<Unit>()
-//        initialize(
-//            surfaceOutput.getSurface(Runnable::run) {
-//                deferredRelease.complete(Unit)
-//            }
-//        )
-//        CoroutineScope(Dispatchers.Unconfined).launch {
-//            deferredRelease.await()
-//            surfaceLifecycleJob.cancel("SurfaceOutput close requested.")
-//            this@apply.release()
-//        }
-//    }
-//
-//    suspend fun <R> withSurfaceOutput(
-//        block: suspend CoroutineScope.(
-//            surface: RefCounted<Surface>,
-//            surfaceSize: Size,
-//            updateTransformMatrix: (updated: FloatArray, original: FloatArray) -> Unit
-//        ) -> R
-//    ): R {
-//        return CoroutineScope(coroutineContext + Job(surfaceLifecycleJob)).async(
-//            start = CoroutineStart.UNDISPATCHED
-//        ) {
-//            ensureActive()
-//            block(
-//                refCountedSurface,
-//                surfaceOutput.size,
-//                surfaceOutput::updateTransformMatrix
-//            )
-//        }.await()
-//    }
-//
-//    fun cancel(message: String? = null) {
-//        message?.apply { surfaceLifecycleJob.cancel(message) } ?: surfaceLifecycleJob.cancel()
-//    }
-//}
-//
-//private class SurfaceRequestScope(private val surfaceRequest: SurfaceRequest) {
-//    private val requestLifecycleJob = SupervisorJob()
-//
-//    init {
-//        surfaceRequest.addRequestCancellationListener(Runnable::run) {
-//            requestLifecycleJob.cancel("SurfaceRequest cancelled.")
-//        }
-//    }
-//
-//    suspend fun <R> withSurfaceRequest(
-//        block: suspend CoroutineScope.(
-//            surfaceRequest: SurfaceRequest
-//        ) -> R
-//    ): R {
-//        return CoroutineScope(coroutineContext + Job(requestLifecycleJob)).async(
-//            start = CoroutineStart.UNDISPATCHED
-//        ) {
-//            ensureActive()
-//            block(surfaceRequest)
-//        }.await()
-//    }
-//
-//    fun cancel(message: String? = null) {
-//        message?.apply { requestLifecycleJob.cancel(message) } ?: requestLifecycleJob.cancel()
-//        // Attempt to tell frame producer we will not provide a surface. This may fail (silently)
-//        // if surface was already provided or the producer has cancelled the request, in which
-//        // case we don't have to do anything.
-//        surfaceRequest.willNotProvideSurface()
-//    }
-//}
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/EGLSpecV14ES3.kt b/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/EGLSpecV14ES3.kt
deleted file mode 100644
index b895883..0000000
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/EGLSpecV14ES3.kt
+++ /dev/null
@@ -1,46 +0,0 @@
-///*
-// * Copyright (C) 2024 The Android Open Source Project
-// *
-// * Licensed under the Apache License, Version 2.0 (the "License");
-// * you may not use this file except in compliance with the License.
-// * You may obtain a copy of the License at
-// *
-// *      http://www.apache.org/licenses/LICENSE-2.0
-// *
-// * Unless required by applicable law or agreed to in writing, software
-// * distributed under the License is distributed on an "AS IS" BASIS,
-// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// * See the License for the specific language governing permissions and
-// * limitations under the License.
-// */
-//package com.google.jetpackcamera.domain.camera.effects
-//
-//import android.opengl.EGL14
-//import android.opengl.EGLConfig
-//import android.opengl.EGLContext
-//import androidx.graphics.opengl.egl.EGLSpec
-//
-//val EGLSpec.Companion.V14ES3: EGLSpec
-//    get() = object : EGLSpec by V14 {
-//
-//        private val contextAttributes = intArrayOf(
-//            // GLES VERSION 3
-//            EGL14.EGL_CONTEXT_CLIENT_VERSION,
-//            3,
-//            // HWUI provides the ability to configure a context priority as well but that only
-//            // seems to be configured on SystemUIApplication. This might be useful for
-//            // front buffer rendering situations for performance.
-//            EGL14.EGL_NONE
-//        )
-//
-//        override fun eglCreateContext(config: EGLConfig): EGLContext {
-//            return EGL14.eglCreateContext(
-//                EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY),
-//                config,
-//                // not creating from a shared context
-//                EGL14.EGL_NO_CONTEXT,
-//                contextAttributes,
-//                0
-//            )
-//        }
-//    }
diff --git a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/ShaderCopy.kt b/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/ShaderCopy.kt
deleted file mode 100644
index 8373561..0000000
--- a/domain/camera/src/main/java/com/google/jetpackcamera/domain/camera/effects/ShaderCopy.kt
+++ /dev/null
@@ -1,450 +0,0 @@
-///*
-// * Copyright (C) 2024 The Android Open Source Project
-// *
-// * Licensed under the Apache License, Version 2.0 (the "License");
-// * you may not use this file except in compliance with the License.
-// * You may obtain a copy of the License at
-// *
-// *      http://www.apache.org/licenses/LICENSE-2.0
-// *
-// * Unless required by applicable law or agreed to in writing, software
-// * distributed under the License is distributed on an "AS IS" BASIS,
-// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// * See the License for the specific language governing permissions and
-// * limitations under the License.
-// */
-//package com.google.jetpackcamera.domain.camera.effects
-//
-//import android.graphics.SurfaceTexture
-//import android.opengl.EGL14
-//import android.opengl.EGLConfig
-//import android.opengl.EGLExt
-//import android.opengl.GLES11Ext
-//import android.opengl.GLES20
-//import android.util.Log
-//import android.view.Surface
-//import androidx.annotation.WorkerThread
-//import androidx.camera.core.DynamicRange
-//import androidx.graphics.opengl.egl.EGLConfigAttributes
-//import androidx.graphics.opengl.egl.EGLManager
-//import androidx.graphics.opengl.egl.EGLSpec
-//import java.nio.ByteBuffer
-//import java.nio.ByteOrder
-//import java.nio.FloatBuffer
-//
-//class ShaderCopy(private val dynamicRange: DynamicRange) : RenderCallbacks {
-//
-//    // Called on worker thread only
-//    private var externalTextureId: Int = -1
-//    private var programHandle = -1
-//    private var texMatrixLoc = -1
-//    private var positionLoc = -1
-//    private var texCoordLoc = -1
-//    private val use10bitPipeline: Boolean
-//        get() = dynamicRange.bitDepth == DynamicRange.BIT_DEPTH_10_BIT
-//
-//    override val glThreadName: String
-//        get() = TAG
-//
-//    override val provideEGLSpec: () -> EGLSpec
-//        get() = { if (use10bitPipeline) EGLSpec.V14ES3 else EGLSpec.V14 }
-//
-//    override val initConfig: EGLManager.() -> EGLConfig
-//        get() = {
-//            checkNotNull(
-//                loadConfig(
-//                    EGLConfigAttributes {
-//                        if (use10bitPipeline) {
-//                            TEN_BIT_REQUIRED_EGL_EXTENSIONS.forEach {
-//                                check(isExtensionSupported(it)) {
-//                                    "Required extension for 10-bit HDR is not " +
-//                                        "supported: $it"
-//                                }
-//                            }
-//                            include(EGLConfigAttributes.RGBA_1010102)
-//                            EGL14.EGL_RENDERABLE_TYPE to
-//                                EGLExt.EGL_OPENGL_ES3_BIT_KHR
-//                            EGL14.EGL_SURFACE_TYPE to
-//                                (EGL14.EGL_WINDOW_BIT or EGL14.EGL_PBUFFER_BIT)
-//                        } else {
-//                            include(EGLConfigAttributes.RGBA_8888)
-//                        }
-//                    }
-//                )
-//            ) {
-//                "Unable to select EGLConfig"
-//            }
-//        }
-//
-//    override val initRenderer: () -> Unit
-//        get() = {
-//            createProgram(
-//                if (use10bitPipeline) {
-//                    TEN_BIT_VERTEX_SHADER
-//                } else {
-//                    DEFAULT_VERTEX_SHADER
-//                },
-//                if (use10bitPipeline) {
-//                    TEN_BIT_FRAGMENT_SHADER
-//                } else {
-//                    DEFAULT_FRAGMENT_SHADER
-//                }
-//            )
-//            loadLocations()
-//            createTexture()
-//            useAndConfigureProgram()
-//        }
-//
-//    override val createSurfaceTexture
-//        get() = { width: Int, height: Int ->
-//            SurfaceTexture(externalTextureId).apply {
-//                setDefaultBufferSize(width, height)
-//            }
-//        }
-//
-//    override val createOutputSurface
-//        get() = { eglSpec: EGLSpec,
-//                config: EGLConfig,
-//                surface: Surface,
-//                _: Int,
-//                _: Int ->
-//            eglSpec.eglCreateWindowSurface(
-//                config,
-//                surface,
-//                EGLConfigAttributes {
-//                    if (use10bitPipeline) {
-//                        EGL_GL_COLORSPACE_KHR to EGL_GL_COLORSPACE_BT2020_HLG_EXT
-//                    }
-//                }
-//            )
-//        }
-//
-//    override val drawFrame
-//        get() = { outputWidth: Int,
-//                outputHeight: Int,
-//                surfaceTransform: FloatArray ->
-//            GLES20.glViewport(
-//                0,
-//                0,
-//                outputWidth,
-//                outputHeight
-//            )
-//            GLES20.glScissor(
-//                0,
-//                0,
-//                outputWidth,
-//                outputHeight
-//            )
-//
-//            GLES20.glUniformMatrix4fv(
-//                texMatrixLoc,
-//                /*count=*/
-//                1,
-//                /*transpose=*/
-//                false,
-//                surfaceTransform,
-//                /*offset=*/
-//                0
-//            )
-//            checkGlErrorOrThrow("glUniformMatrix4fv")
-//
-//            // Draw the rect.
-//            GLES20.glDrawArrays(
-//                GLES20.GL_TRIANGLE_STRIP,
-//                /*firstVertex=*/
-//                0,
-//                /*vertexCount=*/
-//                4
-//            )
-//            checkGlErrorOrThrow("glDrawArrays")
-//        }
-//
-//    @WorkerThread
-//    fun createTexture() {
-//        checkGlThread()
-//        val textures = IntArray(1)
-//        GLES20.glGenTextures(1, textures, 0)
-//        checkGlErrorOrThrow("glGenTextures")
-//        val texId = textures[0]
-//        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, texId)
-//        checkGlErrorOrThrow("glBindTexture $texId")
-//        GLES20.glTexParameterf(
-//            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
-//            GLES20.GL_TEXTURE_MIN_FILTER,
-//            GLES20.GL_NEAREST.toFloat()
-//        )
-//        GLES20.glTexParameterf(
-//            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
-//            GLES20.GL_TEXTURE_MAG_FILTER,
-//            GLES20.GL_LINEAR.toFloat()
-//        )
-//        GLES20.glTexParameteri(
-//            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
-//            GLES20.GL_TEXTURE_WRAP_S,
-//            GLES20.GL_CLAMP_TO_EDGE
-//        )
-//        GLES20.glTexParameteri(
-//            GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
-//            GLES20.GL_TEXTURE_WRAP_T,
-//            GLES20.GL_CLAMP_TO_EDGE
-//        )
-//        checkGlErrorOrThrow("glTexParameter")
-//        externalTextureId = texId
-//    }
-//
-//    @WorkerThread
-//    fun useAndConfigureProgram() {
-//        checkGlThread()
-//        // Select the program.
-//        GLES20.glUseProgram(programHandle)
-//        checkGlErrorOrThrow("glUseProgram")
-//
-//        // Set the texture.
-//        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
-//        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, externalTextureId)
-//
-//        // Enable the "aPosition" vertex attribute.
-//        GLES20.glEnableVertexAttribArray(positionLoc)
-//        checkGlErrorOrThrow("glEnableVertexAttribArray")
-//
-//        // Connect vertexBuffer to "aPosition".
-//        val coordsPerVertex = 2
-//        val vertexStride = 0
-//        GLES20.glVertexAttribPointer(
-//            positionLoc,
-//            coordsPerVertex,
-//            GLES20.GL_FLOAT,
-//            /*normalized=*/
-//            false,
-//            vertexStride,
-//            VERTEX_BUF
-//        )
-//        checkGlErrorOrThrow("glVertexAttribPointer")
-//
-//        // Enable the "aTextureCoord" vertex attribute.
-//        GLES20.glEnableVertexAttribArray(texCoordLoc)
-//        checkGlErrorOrThrow("glEnableVertexAttribArray")
-//
-//        // Connect texBuffer to "aTextureCoord".
-//        val coordsPerTex = 2
-//        val texStride = 0
-//        GLES20.glVertexAttribPointer(
-//            texCoordLoc,
-//            coordsPerTex,
-//            GLES20.GL_FLOAT,
-//            /*normalized=*/
-//            false,
-//            texStride,
-//            TEX_BUF
-//        )
-//        checkGlErrorOrThrow("glVertexAttribPointer")
-//    }
-//
-//    @WorkerThread
-//    private fun createProgram(vertShader: String, fragShader: String) {
-//        checkGlThread()
-//        var vertexShader = -1
-//        var fragmentShader = -1
-//        var program = -1
-//        try {
-//            fragmentShader = loadShader(
-//                GLES20.GL_FRAGMENT_SHADER,
-//                fragShader
-//            )
-//            vertexShader = loadShader(
-//                GLES20.GL_VERTEX_SHADER,
-//                vertShader
-//            )
-//            program = GLES20.glCreateProgram()
-//            checkGlErrorOrThrow("glCreateProgram")
-//            GLES20.glAttachShader(program, vertexShader)
-//            checkGlErrorOrThrow("glAttachShader")
-//            GLES20.glAttachShader(program, fragmentShader)
-//            checkGlErrorOrThrow("glAttachShader")
-//            GLES20.glLinkProgram(program)
-//            val linkStatus = IntArray(1)
-//            GLES20.glGetProgramiv(
-//                program,
-//                GLES20.GL_LINK_STATUS,
-//                linkStatus,
-//                /*offset=*/
-//                0
-//            )
-//            check(linkStatus[0] == GLES20.GL_TRUE) {
-//                "Could not link program: " + GLES20.glGetProgramInfoLog(
-//                    program
-//                )
-//            }
-//            programHandle = program
-//        } catch (e: Exception) {
-//            if (vertexShader != -1) {
-//                GLES20.glDeleteShader(vertexShader)
-//            }
-//            if (fragmentShader != -1) {
-//                GLES20.glDeleteShader(fragmentShader)
-//            }
-//            if (program != -1) {
-//                GLES20.glDeleteProgram(program)
-//            }
-//            throw e
-//        }
-//    }
-//
-//    @WorkerThread
-//    private fun loadLocations() {
-//        checkGlThread()
-//        positionLoc = GLES20.glGetAttribLocation(programHandle, "aPosition")
-//        checkLocationOrThrow(positionLoc, "aPosition")
-//        texCoordLoc = GLES20.glGetAttribLocation(programHandle, "aTextureCoord")
-//        checkLocationOrThrow(texCoordLoc, "aTextureCoord")
-//        texMatrixLoc = GLES20.glGetUniformLocation(programHandle, "uTexMatrix")
-//        checkLocationOrThrow(texMatrixLoc, "uTexMatrix")
-//    }
-//
-//    @WorkerThread
-//    private fun loadShader(shaderType: Int, source: String): Int {
-//        checkGlThread()
-//        val shader = GLES20.glCreateShader(shaderType)
-//        checkGlErrorOrThrow("glCreateShader type=$shaderType")
-//        GLES20.glShaderSource(shader, source)
-//        GLES20.glCompileShader(shader)
-//        val compiled = IntArray(1)
-//        GLES20.glGetShaderiv(
-//            shader,
-//            GLES20.GL_COMPILE_STATUS,
-//            compiled,
-//            /*offset=*/
-//            0
-//        )
-//        check(compiled[0] == GLES20.GL_TRUE) {
-//            Log.w(TAG, "Could not compile shader: $source")
-//            try {
-//                return@check "Could not compile shader type " +
-//                    "$shaderType: ${GLES20.glGetShaderInfoLog(shader)}"
-//            } finally {
-//                GLES20.glDeleteShader(shader)
-//            }
-//        }
-//        return shader
-//    }
-//
-//    @WorkerThread
-//    private fun checkGlErrorOrThrow(op: String) {
-//        val error = GLES20.glGetError()
-//        check(error == GLES20.GL_NO_ERROR) { op + ": GL error 0x" + Integer.toHexString(error) }
-//    }
-//
-//    private fun checkLocationOrThrow(location: Int, label: String) {
-//        check(location >= 0) { "Unable to locate '$label' in program" }
-//    }
-//
-//    companion object {
-//        private const val SIZEOF_FLOAT = 4
-//
-//        private val VERTEX_BUF = floatArrayOf(
-//            // 0 bottom left
-//            -1.0f,
-//            -1.0f,
-//            // 1 bottom right
-//            1.0f,
-//            -1.0f,
-//            // 2 top left
-//            -1.0f,
-//            1.0f,
-//            // 3 top right
-//            1.0f,
-//            1.0f
-//        ).toBuffer()
-//
-//        private val TEX_BUF = floatArrayOf(
-//            // 0 bottom left
-//            0.0f,
-//            0.0f,
-//            // 1 bottom right
-//            1.0f,
-//            0.0f,
-//            // 2 top left
-//            0.0f,
-//            1.0f,
-//            // 3 top right
-//            1.0f,
-//            1.0f
-//        ).toBuffer()
-//
-//        private const val TAG = "ShaderCopy"
-//        private const val GL_THREAD_NAME = TAG
-//
-//        private const val VAR_TEXTURE_COORD = "vTextureCoord"
-//        private val DEFAULT_VERTEX_SHADER =
-//            """
-//        uniform mat4 uTexMatrix;
-//        attribute vec4 aPosition;
-//        attribute vec4 aTextureCoord;
-//        varying vec2 $VAR_TEXTURE_COORD;
-//        void main() {
-//            gl_Position = aPosition;
-//            $VAR_TEXTURE_COORD = (uTexMatrix * aTextureCoord).xy;
-//        }
-//            """.trimIndent()
-//
-//        private val TEN_BIT_VERTEX_SHADER =
-//            """
-//        #version 300 es
-//        in vec4 aPosition;
-//        in vec4 aTextureCoord;
-//        uniform mat4 uTexMatrix;
-//        out vec2 $VAR_TEXTURE_COORD;
-//        void main() {
-//          gl_Position = aPosition;
-//          $VAR_TEXTURE_COORD = (uTexMatrix * aTextureCoord).xy;
-//        }
-//            """.trimIndent()
-//
-//        private const val VAR_TEXTURE = "sTexture"
-//        private val DEFAULT_FRAGMENT_SHADER =
-//            """
-//        #extension GL_OES_EGL_image_external : require
-//        precision mediump float;
-//        varying vec2 $VAR_TEXTURE_COORD;
-//        uniform samplerExternalOES $VAR_TEXTURE;
-//        void main() {
-//            gl_FragColor = texture2D($VAR_TEXTURE, $VAR_TEXTURE_COORD);
-//        }
-//            """.trimIndent()
-//
-//        private val TEN_BIT_FRAGMENT_SHADER =
-//            """
-//        #version 300 es
-//        #extension GL_EXT_YUV_target : require
-//        precision mediump float;
-//        uniform __samplerExternal2DY2YEXT $VAR_TEXTURE;
-//        in vec2 $VAR_TEXTURE_COORD;
-//        layout (yuv) out vec3 outColor;
-//
-//        void main() {
-//          outColor = texture($VAR_TEXTURE, $VAR_TEXTURE_COORD).xyz;
-//        }
-//            """.trimIndent()
-//
-//        private const val EGL_GL_COLORSPACE_KHR = 0x309D
-//        private const val EGL_GL_COLORSPACE_BT2020_HLG_EXT = 0x3540
-//
-//        private val TEN_BIT_REQUIRED_EGL_EXTENSIONS = listOf(
-//            "EGL_EXT_gl_colorspace_bt2020_hlg",
-//            "EGL_EXT_yuv_surface"
-//        )
-//
-//        private fun FloatArray.toBuffer(): FloatBuffer {
-//            val bb = ByteBuffer.allocateDirect(size * SIZEOF_FLOAT)
-//            bb.order(ByteOrder.nativeOrder())
-//            val fb = bb.asFloatBuffer()
-//            fb.put(this)
-//            fb.position(0)
-//            return fb
-//        }
-//
-//        private fun checkGlThread() {
-//            check(GL_THREAD_NAME == Thread.currentThread().name)
-//        }
-//    }
-//}
diff --git a/feature/permissions/build.gradle.kts b/feature/permissions/build.gradle.kts
index a14d8cc..66fadf3 100644
--- a/feature/permissions/build.gradle.kts
+++ b/feature/permissions/build.gradle.kts
@@ -24,6 +24,7 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.permissions"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
diff --git a/feature/permissions/src/main/AndroidManifest.xml b/feature/permissions/src/main/AndroidManifest.xml
index 88a4e8b..926ca9b 100644
--- a/feature/permissions/src/main/AndroidManifest.xml
+++ b/feature/permissions/src/main/AndroidManifest.xml
@@ -17,3 +17,4 @@
 <manifest package="com.google.jetpackcamera.permissions">
 
 </manifest>
+
diff --git a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt
index af17e30..ad67fda 100644
--- a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt
+++ b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt
@@ -34,12 +34,22 @@ private const val TAG = "PermissionsScreen"
 
 @OptIn(ExperimentalPermissionsApi::class)
 @Composable
-fun PermissionsScreen(onNavigateToPreview: () -> Unit, openAppSettings: () -> Unit) {
+fun PermissionsScreen(
+    shouldRequestAudioPermission: Boolean,
+    onNavigateToPreview: () -> Unit,
+    openAppSettings: () -> Unit
+) {
     val permissionStates = rememberMultiplePermissionsState(
-        permissions = listOf(
-            Manifest.permission.CAMERA,
-            Manifest.permission.RECORD_AUDIO
-        )
+        permissions = if (shouldRequestAudioPermission) {
+            listOf(
+                Manifest.permission.CAMERA,
+                Manifest.permission.RECORD_AUDIO
+            )
+        } else {
+            listOf(
+                Manifest.permission.CAMERA
+            )
+        }
     )
     PermissionsScreen(
         permissionStates = permissionStates,
diff --git a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsViewModel.kt b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsViewModel.kt
index 047442f..ac538aa 100644
--- a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsViewModel.kt
+++ b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsViewModel.kt
@@ -25,6 +25,7 @@ import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
 import dagger.hilt.android.lifecycle.HiltViewModel
+import kotlin.collections.removeFirst as ktRemoveFirst // alias must be used now. see https://issuetracker.google.com/348683480
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
@@ -63,7 +64,7 @@ class PermissionsViewModel @AssistedInject constructor(
 
     fun dismissPermission() {
         if (permissionQueue.isNotEmpty()) {
-            permissionQueue.removeFirst()
+            permissionQueue.ktRemoveFirst()
         }
         _permissionsUiState.update {
             (getCurrentPermission())
diff --git a/feature/preview/Android.bp b/feature/preview/Android.bp
index b4920b1..a3d8366 100644
--- a/feature/preview/Android.bp
+++ b/feature/preview/Android.bp
@@ -19,13 +19,15 @@ android_library {
         "hilt_android",
         "androidx.hilt_hilt-navigation-compose",
         "androidx.compose.ui_ui-tooling",
+        "kotlin-reflect",
         "kotlinx_coroutines_guava",
         "androidx.datastore_datastore",
         "libprotobuf-java-lite",
         "androidx.camera_camera-core",
         "androidx.camera_camera-viewfinder",
         "jetpack-camera-app_data_settings",
-        "jetpack-camera-app_domain_camera",
+        "jetpack-camera-app_core_camera",
+        "jetpack-camera-app_core_common",
         "androidx.camera_camera-viewfinder-compose",
         "androidx.compose.ui_ui-tooling",
 
diff --git a/feature/preview/build.gradle.kts b/feature/preview/build.gradle.kts
index a5f0793..5ba5f3a 100644
--- a/feature/preview/build.gradle.kts
+++ b/feature/preview/build.gradle.kts
@@ -24,6 +24,7 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.feature.preview"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -33,6 +34,19 @@ android {
         testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
     }
 
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
+    }
+
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_17
         targetCompatibility = JavaVersion.VERSION_17
@@ -75,6 +89,8 @@ android {
 }
 
 dependencies {
+    // Reflect
+    implementation(libs.kotlin.reflect)
     // Compose
     val composeBom = platform(libs.compose.bom)
     implementation(composeBom)
@@ -131,7 +147,9 @@ dependencies {
 
     // Project dependencies
     implementation(project(":data:settings"))
-    implementation(project(":domain:camera"))
+    implementation(project(":core:camera"))
+    implementation(project(":core:common"))
+    testImplementation(project(":core:common"))
 }
 
 // Allow references to generated code
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeToggleUiState.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeToggleUiState.kt
new file mode 100644
index 0000000..04b7a5e
--- /dev/null
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeToggleUiState.kt
@@ -0,0 +1,87 @@
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
+package com.google.jetpackcamera.feature.preview
+
+import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_DEVICE_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_LENS_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+
+sealed interface CaptureModeToggleUiState {
+
+    data object Invisible : CaptureModeToggleUiState
+
+    sealed interface Visible : CaptureModeToggleUiState {
+        val currentMode: ToggleMode
+    }
+
+    data class Enabled(override val currentMode: ToggleMode) : Visible
+
+    data class Disabled(
+        override val currentMode: ToggleMode,
+        val disabledReason: DisabledReason
+    ) : Visible
+
+    enum class DisabledReason(val testTag: String, val reasonTextResId: Int) {
+        VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED(
+            VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG,
+            R.string.toast_video_capture_external_unsupported
+        ),
+        IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED(
+            IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG,
+            R.string.toast_image_capture_external_unsupported
+
+        ),
+        IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA(
+            IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG,
+            R.string.toast_image_capture_unsupported_concurrent_camera
+        ),
+        HDR_VIDEO_UNSUPPORTED_ON_DEVICE(
+            HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG,
+            R.string.toast_hdr_video_unsupported_on_device
+        ),
+        HDR_VIDEO_UNSUPPORTED_ON_LENS(
+            HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG,
+            R.string.toast_hdr_video_unsupported_on_lens
+        ),
+        HDR_IMAGE_UNSUPPORTED_ON_DEVICE(
+            HDR_IMAGE_UNSUPPORTED_ON_DEVICE_TAG,
+            R.string.toast_hdr_photo_unsupported_on_device
+        ),
+        HDR_IMAGE_UNSUPPORTED_ON_LENS(
+            HDR_IMAGE_UNSUPPORTED_ON_LENS_TAG,
+            R.string.toast_hdr_photo_unsupported_on_lens
+        ),
+        HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM(
+            HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG,
+            R.string.toast_hdr_photo_unsupported_on_lens_single_stream
+        ),
+        HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM(
+            HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG,
+            R.string.toast_hdr_photo_unsupported_on_lens_multi_stream
+        )
+    }
+
+    enum class ToggleMode {
+        CAPTURE_TOGGLE_IMAGE,
+        CAPTURE_TOGGLE_VIDEO
+    }
+}
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt
index de1c7d8..dc3f8e7 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt
@@ -36,4 +36,12 @@ sealed interface PreviewMode {
         val imageCaptureUri: Uri?,
         val onImageCapture: (PreviewViewModel.ImageCaptureEvent) -> Unit
     ) : PreviewMode
+
+    /**
+     * Under this mode, the app is launched by an external intent to capture a video.
+     */
+    data class ExternalVideoCaptureMode(
+        val videoCaptureUri: Uri?,
+        val onVideoCapture: (PreviewViewModel.VideoCaptureEvent) -> Unit
+    ) : PreviewMode
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
index 90eb918..55583a2 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
@@ -19,7 +19,6 @@ import android.annotation.SuppressLint
 import android.content.ContentResolver
 import android.net.Uri
 import android.util.Log
-import android.view.Display
 import androidx.camera.core.SurfaceRequest
 import androidx.compose.foundation.background
 import androidx.compose.foundation.layout.Arrangement
@@ -35,31 +34,40 @@ import androidx.compose.material3.SnackbarHostState
 import androidx.compose.material3.Text
 import androidx.compose.material3.darkColorScheme
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.getValue
 import androidx.compose.runtime.remember
+import androidx.compose.runtime.snapshotFlow
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.dp
 import androidx.hilt.navigation.compose.hiltViewModel
 import androidx.lifecycle.compose.LifecycleStartEffect
+import androidx.tracing.Trace
 import com.google.jetpackcamera.feature.preview.quicksettings.QuickSettingsScreenOverlay
 import com.google.jetpackcamera.feature.preview.ui.CameraControlsOverlay
 import com.google.jetpackcamera.feature.preview.ui.PreviewDisplay
 import com.google.jetpackcamera.feature.preview.ui.ScreenFlashScreen
 import com.google.jetpackcamera.feature.preview.ui.TestableSnackbar
 import com.google.jetpackcamera.feature.preview.ui.TestableToast
+import com.google.jetpackcamera.feature.preview.ui.debouncedOrientationFlow
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.LowLightBoost
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
+import kotlinx.coroutines.flow.transformWhile
 
 private const val TAG = "PreviewScreen"
 
@@ -70,10 +78,12 @@ private const val TAG = "PreviewScreen"
 fun PreviewScreen(
     onNavigateToSettings: () -> Unit,
     previewMode: PreviewMode,
+    isDebugMode: Boolean,
     modifier: Modifier = Modifier,
     onRequestWindowColorMode: (Int) -> Unit = {},
+    onFirstFrameCaptureCompleted: () -> Unit = {},
     viewModel: PreviewViewModel = hiltViewModel<PreviewViewModel, PreviewViewModel.Factory>
-        { factory -> factory.create(previewMode) }
+        { factory -> factory.create(previewMode, isDebugMode) }
 ) {
     Log.d(TAG, "PreviewScreen")
 
@@ -92,31 +102,61 @@ fun PreviewScreen(
         }
     }
 
+    if (Trace.isEnabled()) {
+        LaunchedEffect(onFirstFrameCaptureCompleted) {
+            snapshotFlow { previewUiState }
+                .transformWhile {
+                    var continueCollecting = true
+                    (it as? PreviewUiState.Ready)?.let { ready ->
+                        if (ready.sessionFirstFrameTimestamp > 0) {
+                            emit(Unit)
+                            continueCollecting = false
+                        }
+                    }
+                    continueCollecting
+                }.collect {
+                    onFirstFrameCaptureCompleted()
+                }
+        }
+    }
+
     when (val currentUiState = previewUiState) {
         is PreviewUiState.NotReady -> LoadingScreen()
-        is PreviewUiState.Ready -> ContentScreen(
-            modifier = modifier,
-            previewUiState = currentUiState,
-            screenFlashUiState = screenFlashUiState,
-            surfaceRequest = surfaceRequest,
-            onNavigateToSettings = onNavigateToSettings,
-            onClearUiScreenBrightness = viewModel.screenFlash::setClearUiScreenBrightness,
-            onSetLensFacing = viewModel::setLensFacing,
-            onTapToFocus = viewModel::tapToFocus,
-            onChangeZoomScale = viewModel::setZoomScale,
-            onChangeFlash = viewModel::setFlash,
-            onChangeAspectRatio = viewModel::setAspectRatio,
-            onChangeCaptureMode = viewModel::setCaptureMode,
-            onChangeDynamicRange = viewModel::setDynamicRange,
-            onToggleQuickSettings = viewModel::toggleQuickSettings,
-            onCaptureImage = viewModel::captureImage,
-            onCaptureImageWithUri = viewModel::captureImageWithUri,
-            onStartVideoRecording = viewModel::startVideoRecording,
-            onStopVideoRecording = viewModel::stopVideoRecording,
-            onToastShown = viewModel::onToastShown,
-            onRequestWindowColorMode = onRequestWindowColorMode,
-            onSnackBarResult = viewModel::onSnackBarResult
-        )
+        is PreviewUiState.Ready -> {
+            val context = LocalContext.current
+            LaunchedEffect(Unit) {
+                debouncedOrientationFlow(context).collect(viewModel::setDisplayRotation)
+            }
+
+            ContentScreen(
+                modifier = modifier,
+                previewUiState = currentUiState,
+                screenFlashUiState = screenFlashUiState,
+                surfaceRequest = surfaceRequest,
+                onNavigateToSettings = onNavigateToSettings,
+                onClearUiScreenBrightness = viewModel.screenFlash::setClearUiScreenBrightness,
+                onSetLensFacing = viewModel::setLensFacing,
+                onTapToFocus = viewModel::tapToFocus,
+                onChangeZoomScale = viewModel::setZoomScale,
+                onChangeFlash = viewModel::setFlash,
+                onChangeAspectRatio = viewModel::setAspectRatio,
+                onChangeCaptureMode = viewModel::setCaptureMode,
+                onChangeDynamicRange = viewModel::setDynamicRange,
+                onChangeConcurrentCameraMode = viewModel::setConcurrentCameraMode,
+                onLowLightBoost = viewModel::setLowLightBoost,
+                onChangeImageFormat = viewModel::setImageFormat,
+                onToggleWhenDisabled = viewModel::showSnackBarForDisabledHdrToggle,
+                onToggleQuickSettings = viewModel::toggleQuickSettings,
+                onMuteAudio = viewModel::setAudioMuted,
+                onCaptureImage = viewModel::captureImage,
+                onCaptureImageWithUri = viewModel::captureImageWithUri,
+                onStartVideoRecording = viewModel::startVideoRecording,
+                onStopVideoRecording = viewModel::stopVideoRecording,
+                onToastShown = viewModel::onToastShown,
+                onRequestWindowColorMode = onRequestWindowColorMode,
+                onSnackBarResult = viewModel::onSnackBarResult
+            )
+        }
     }
 }
 
@@ -130,13 +170,18 @@ private fun ContentScreen(
     onNavigateToSettings: () -> Unit = {},
     onClearUiScreenBrightness: (Float) -> Unit = {},
     onSetLensFacing: (newLensFacing: LensFacing) -> Unit = {},
-    onTapToFocus: (Display, Int, Int, Float, Float) -> Unit = { _, _, _, _, _ -> },
+    onTapToFocus: (x: Float, y: Float) -> Unit = { _, _ -> },
     onChangeZoomScale: (Float) -> Unit = {},
     onChangeFlash: (FlashMode) -> Unit = {},
     onChangeAspectRatio: (AspectRatio) -> Unit = {},
     onChangeCaptureMode: (CaptureMode) -> Unit = {},
     onChangeDynamicRange: (DynamicRange) -> Unit = {},
+    onChangeConcurrentCameraMode: (ConcurrentCameraMode) -> Unit = {},
+    onLowLightBoost: (LowLightBoost) -> Unit = {},
+    onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
+    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
     onToggleQuickSettings: () -> Unit = {},
+    onMuteAudio: (Boolean) -> Unit = {},
     onCaptureImage: () -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
@@ -144,7 +189,11 @@ private fun ContentScreen(
         Boolean,
         (PreviewViewModel.ImageCaptureEvent) -> Unit
     ) -> Unit = { _, _, _, _ -> },
-    onStartVideoRecording: () -> Unit = {},
+    onStartVideoRecording: (
+        Uri?,
+        Boolean,
+        (PreviewViewModel.VideoCaptureEvent) -> Unit
+    ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {},
     onToastShown: () -> Unit = {},
     onRequestWindowColorMode: (Int) -> Unit = {},
@@ -164,6 +213,15 @@ private fun ContentScreen(
             }
         }
 
+        val isMuted = remember(previewUiState) {
+            previewUiState.currentCameraSettings.audioMuted
+        }
+        val onToggleMuteAudio = remember(isMuted) {
+            {
+                onMuteAudio(!isMuted)
+            }
+        }
+
         Box(modifier.fillMaxSize()) {
             // display camera feed. this stays behind everything else
             PreviewDisplay(
@@ -182,12 +240,14 @@ private fun ContentScreen(
                 isOpen = previewUiState.quickSettingsIsOpen,
                 toggleIsOpen = onToggleQuickSettings,
                 currentCameraSettings = previewUiState.currentCameraSettings,
-                systemConstraints = previewUiState.systemConstraints,
                 onLensFaceClick = onSetLensFacing,
                 onFlashModeClick = onChangeFlash,
                 onAspectRatioClick = onChangeAspectRatio,
                 onCaptureModeClick = onChangeCaptureMode,
-                onDynamicRangeClick = onChangeDynamicRange // onTimerClick = {}/*TODO*/
+                onDynamicRangeClick = onChangeDynamicRange,
+                onImageOutputFormatClick = onChangeImageFormat,
+                onConcurrentCameraModeClick = onChangeConcurrentCameraMode,
+                onLowLightBoostClick = onLowLightBoost
             )
             // relative-grid style overlay on top of preview display
             CameraControlsOverlay(
@@ -195,7 +255,10 @@ private fun ContentScreen(
                 onNavigateToSettings = onNavigateToSettings,
                 onFlipCamera = onFlipCamera,
                 onChangeFlash = onChangeFlash,
+                onMuteAudio = onToggleMuteAudio,
                 onToggleQuickSettings = onToggleQuickSettings,
+                onChangeImageFormat = onChangeImageFormat,
+                onToggleWhenDisabled = onToggleWhenDisabled,
                 onCaptureImage = onCaptureImage,
                 onCaptureImageWithUri = onCaptureImageWithUri,
                 onStartVideoRecording = onStartVideoRecording,
@@ -274,5 +337,6 @@ private fun ContentScreen_WhileRecording() {
 private val FAKE_PREVIEW_UI_STATE_READY = PreviewUiState.Ready(
     currentCameraSettings = DEFAULT_CAMERA_APP_SETTINGS,
     systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-    previewMode = PreviewMode.StandardMode {}
+    previewMode = PreviewMode.StandardMode {},
+    captureModeToggleUiState = CaptureModeToggleUiState.Invisible
 )
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
index 3bc1750..5152bbe 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
@@ -24,7 +24,7 @@ import com.google.jetpackcamera.settings.model.SystemConstraints
  * Defines the current state of the [PreviewScreen].
  */
 sealed interface PreviewUiState {
-    object NotReady : PreviewUiState
+    data object NotReady : PreviewUiState
 
     data class Ready(
         // "quick" settings
@@ -34,12 +34,18 @@ sealed interface PreviewUiState {
         val videoRecordingState: VideoRecordingState = VideoRecordingState.INACTIVE,
         val quickSettingsIsOpen: Boolean = false,
         val audioAmplitude: Double = 0.0,
+        val audioMuted: Boolean = false,
 
         // todo: remove after implementing post capture screen
         val toastMessageToShow: ToastMessage? = null,
         val snackBarToShow: SnackbarData? = null,
         val lastBlinkTimeStamp: Long = 0,
-        val previewMode: PreviewMode
+        val previewMode: PreviewMode,
+        val captureModeToggleUiState: CaptureModeToggleUiState,
+        val sessionFirstFrameTimestamp: Long = 0L,
+        val currentPhysicalCameraId: String? = null,
+        val currentLogicalCameraId: String? = null,
+        val isDebugMode: Boolean = false
     ) : PreviewUiState
 }
 
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
index ca138a8..fef3aa1 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
@@ -17,29 +17,47 @@ package com.google.jetpackcamera.feature.preview
 
 import android.content.ContentResolver
 import android.net.Uri
+import android.os.SystemClock
 import android.util.Log
-import android.view.Display
 import androidx.camera.core.SurfaceRequest
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import androidx.tracing.Trace
 import androidx.tracing.traceAsync
-import com.google.jetpackcamera.domain.camera.CameraUseCase
+import com.google.jetpackcamera.core.camera.CameraUseCase
+import com.google.jetpackcamera.core.common.traceFirstFramePreview
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.feature.preview.ui.SnackbarData
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_FAILURE_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.settings.ConstraintsRepository
+import com.google.jetpackcamera.settings.SettingsRepository
 import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.CameraConstraints
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.settings.model.DeviceRotation
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.model.forCurrentLens
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
 import dagger.hilt.android.lifecycle.HiltViewModel
+import kotlin.reflect.KProperty
+import kotlin.reflect.full.memberProperties
 import kotlin.time.Duration.Companion.seconds
 import kotlinx.atomicfu.atomic
+import kotlinx.coroutines.CoroutineStart
 import kotlinx.coroutines.Deferred
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.async
@@ -49,6 +67,9 @@ import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.flow.transform
+import kotlinx.coroutines.flow.transformWhile
 import kotlinx.coroutines.flow.update
 import kotlinx.coroutines.launch
 
@@ -60,10 +81,11 @@ private const val IMAGE_CAPTURE_TRACE = "JCA Image Capture"
  */
 @HiltViewModel(assistedFactory = PreviewViewModel.Factory::class)
 class PreviewViewModel @AssistedInject constructor(
-    @Assisted previewMode: PreviewMode,
+    @Assisted val previewMode: PreviewMode,
+    @Assisted val isDebugMode: Boolean,
     private val cameraUseCase: CameraUseCase,
+    private val settingsRepository: SettingsRepository,
     private val constraintsRepository: ConstraintsRepository
-
 ) : ViewModel() {
     private val _previewUiState: MutableStateFlow<PreviewUiState> =
         MutableStateFlow(PreviewUiState.NotReady)
@@ -79,38 +101,69 @@ class PreviewViewModel @AssistedInject constructor(
 
     val screenFlash = ScreenFlash(cameraUseCase, viewModelScope)
 
-    private val imageCaptureCalledCount = atomic(0)
+    private val snackBarCount = atomic(0)
     private val videoCaptureStartedCount = atomic(0)
 
     // Eagerly initialize the CameraUseCase and encapsulate in a Deferred that can be
     // used to ensure we don't start the camera before initialization is complete.
     private var initializationDeferred: Deferred<Unit> = viewModelScope.async {
-        cameraUseCase.initialize(previewMode is PreviewMode.ExternalImageCaptureMode)
+        cameraUseCase.initialize(
+            cameraAppSettings = settingsRepository.defaultCameraAppSettings.first(),
+            previewMode.toUseCaseMode(),
+            isDebugMode
+        )
     }
 
     init {
         viewModelScope.launch {
+            launch {
+                var oldCameraAppSettings: CameraAppSettings? = null
+                settingsRepository.defaultCameraAppSettings.transform { new ->
+                    val old = oldCameraAppSettings
+                    if (old != null) {
+                        emit(getSettingsDiff(old, new))
+                    }
+                    oldCameraAppSettings = new
+                }.collect { diffQueue ->
+                    applySettingsDiff(diffQueue)
+                }
+            }
             combine(
                 cameraUseCase.getCurrentSettings().filterNotNull(),
                 constraintsRepository.systemConstraints.filterNotNull(),
-                cameraUseCase.getZoomScale()
-            ) { cameraAppSettings, systemConstraints, zoomScale ->
+                cameraUseCase.getCurrentCameraState()
+            ) { cameraAppSettings, systemConstraints, cameraState ->
                 _previewUiState.update { old ->
                     when (old) {
                         is PreviewUiState.Ready ->
                             old.copy(
                                 currentCameraSettings = cameraAppSettings,
                                 systemConstraints = systemConstraints,
-                                zoomScale = zoomScale,
-                                previewMode = previewMode
+                                zoomScale = cameraState.zoomScale,
+                                sessionFirstFrameTimestamp = cameraState.sessionFirstFrameTimestamp,
+                                captureModeToggleUiState = getCaptureToggleUiState(
+                                    systemConstraints,
+                                    cameraAppSettings
+                                ),
+                                isDebugMode = isDebugMode,
+                                currentLogicalCameraId = cameraState.debugInfo.logicalCameraId,
+                                currentPhysicalCameraId = cameraState.debugInfo.physicalCameraId
                             )
 
                         is PreviewUiState.NotReady ->
                             PreviewUiState.Ready(
                                 currentCameraSettings = cameraAppSettings,
                                 systemConstraints = systemConstraints,
-                                zoomScale = zoomScale,
-                                previewMode = previewMode
+                                zoomScale = cameraState.zoomScale,
+                                sessionFirstFrameTimestamp = cameraState.sessionFirstFrameTimestamp,
+                                previewMode = previewMode,
+                                captureModeToggleUiState = getCaptureToggleUiState(
+                                    systemConstraints,
+                                    cameraAppSettings
+                                ),
+                                isDebugMode = isDebugMode,
+                                currentLogicalCameraId = cameraState.debugInfo.logicalCameraId,
+                                currentPhysicalCameraId = cameraState.debugInfo.physicalCameraId
                             )
                     }
                 }
@@ -118,10 +171,237 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
+    private fun PreviewMode.toUseCaseMode() = when (this) {
+        is PreviewMode.ExternalImageCaptureMode -> CameraUseCase.UseCaseMode.IMAGE_ONLY
+        is PreviewMode.ExternalVideoCaptureMode -> CameraUseCase.UseCaseMode.VIDEO_ONLY
+        is PreviewMode.StandardMode -> CameraUseCase.UseCaseMode.STANDARD
+    }
+
+    /**
+     * Returns the difference between two [CameraAppSettings] as a mapping of <[KProperty], [Any]>.
+     */
+    private fun getSettingsDiff(
+        oldCameraAppSettings: CameraAppSettings,
+        newCameraAppSettings: CameraAppSettings
+    ): Map<KProperty<Any?>, Any?> = buildMap<KProperty<Any?>, Any?> {
+        CameraAppSettings::class.memberProperties.forEach { property ->
+            if (property.get(oldCameraAppSettings) != property.get(newCameraAppSettings)) {
+                put(property, property.get(newCameraAppSettings))
+            }
+        }
+    }
+
+    /**
+     * Iterates through a queue of [Pair]<[KProperty], [Any]> and attempt to apply them to
+     * [CameraUseCase].
+     */
+    private suspend fun applySettingsDiff(diffSettingsMap: Map<KProperty<Any?>, Any?>) {
+        diffSettingsMap.entries.forEach { entry ->
+            when (entry.key) {
+                CameraAppSettings::cameraLensFacing -> {
+                    cameraUseCase.setLensFacing(entry.value as LensFacing)
+                }
+
+                CameraAppSettings::flashMode -> {
+                    cameraUseCase.setFlashMode(entry.value as FlashMode)
+                }
+
+                CameraAppSettings::captureMode -> {
+                    cameraUseCase.setCaptureMode(entry.value as CaptureMode)
+                }
+
+                CameraAppSettings::aspectRatio -> {
+                    cameraUseCase.setAspectRatio(entry.value as AspectRatio)
+                }
+
+                CameraAppSettings::previewStabilization -> {
+                    cameraUseCase.setPreviewStabilization(entry.value as Stabilization)
+                }
+
+                CameraAppSettings::videoCaptureStabilization -> {
+                    cameraUseCase.setVideoCaptureStabilization(
+                        entry.value as Stabilization
+                    )
+                }
+
+                CameraAppSettings::targetFrameRate -> {
+                    cameraUseCase.setTargetFrameRate(entry.value as Int)
+                }
+
+                CameraAppSettings::darkMode -> {}
+
+                else -> TODO("Unhandled CameraAppSetting $entry")
+            }
+        }
+    }
+
+    private fun getCaptureToggleUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings
+    ): CaptureModeToggleUiState {
+        val cameraConstraints: CameraConstraints? = systemConstraints.forCurrentLens(
+            cameraAppSettings
+        )
+        val hdrDynamicRangeSupported = cameraConstraints?.let {
+            it.supportedDynamicRanges.size > 1
+        } ?: false
+        val hdrImageFormatSupported =
+            cameraConstraints?.supportedImageFormatsMap?.get(cameraAppSettings.captureMode)?.let {
+                it.size > 1
+            } ?: false
+        val isShown = previewMode is PreviewMode.ExternalImageCaptureMode ||
+            previewMode is PreviewMode.ExternalVideoCaptureMode ||
+            cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR ||
+            cameraAppSettings.dynamicRange == DynamicRange.HLG10 ||
+            cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.DUAL
+        val enabled = previewMode !is PreviewMode.ExternalImageCaptureMode &&
+            previewMode !is PreviewMode.ExternalVideoCaptureMode &&
+            hdrDynamicRangeSupported &&
+            hdrImageFormatSupported &&
+            cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.OFF
+        return if (isShown) {
+            val currentMode = if (
+                cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.OFF &&
+                previewMode is PreviewMode.ExternalImageCaptureMode ||
+                cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+            ) {
+                CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE
+            } else {
+                CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO
+            }
+            if (enabled) {
+                CaptureModeToggleUiState.Enabled(currentMode)
+            } else {
+                CaptureModeToggleUiState.Disabled(
+                    currentMode,
+                    getCaptureToggleUiStateDisabledReason(
+                        currentMode,
+                        hdrDynamicRangeSupported,
+                        hdrImageFormatSupported,
+                        systemConstraints,
+                        cameraAppSettings.cameraLensFacing,
+                        cameraAppSettings.captureMode,
+                        cameraAppSettings.concurrentCameraMode
+                    )
+                )
+            }
+        } else {
+            CaptureModeToggleUiState.Invisible
+        }
+    }
+
+    private fun getCaptureToggleUiStateDisabledReason(
+        captureModeToggleUiState: CaptureModeToggleUiState.ToggleMode,
+        hdrDynamicRangeSupported: Boolean,
+        hdrImageFormatSupported: Boolean,
+        systemConstraints: SystemConstraints,
+        currentLensFacing: LensFacing,
+        currentCaptureMode: CaptureMode,
+        concurrentCameraMode: ConcurrentCameraMode
+    ): CaptureModeToggleUiState.DisabledReason {
+        when (captureModeToggleUiState) {
+            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO -> {
+                if (previewMode is PreviewMode.ExternalVideoCaptureMode) {
+                    return CaptureModeToggleUiState.DisabledReason
+                        .IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED
+                }
+
+                if (concurrentCameraMode == ConcurrentCameraMode.DUAL) {
+                    return CaptureModeToggleUiState.DisabledReason
+                        .IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA
+                }
+
+                if (!hdrImageFormatSupported) {
+                    // First check if Ultra HDR image is supported on other capture modes
+                    if (systemConstraints
+                            .perLensConstraints[currentLensFacing]
+                            ?.supportedImageFormatsMap
+                            ?.anySupportsUltraHdr { it != currentCaptureMode } == true
+                    ) {
+                        return when (currentCaptureMode) {
+                            CaptureMode.MULTI_STREAM ->
+                                CaptureModeToggleUiState.DisabledReason
+                                    .HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM
+
+                            CaptureMode.SINGLE_STREAM ->
+                                CaptureModeToggleUiState.DisabledReason
+                                    .HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM
+                        }
+                    }
+
+                    // Check if any other lens supports HDR image
+                    if (systemConstraints.anySupportsUltraHdr { it != currentLensFacing }) {
+                        return CaptureModeToggleUiState.DisabledReason.HDR_IMAGE_UNSUPPORTED_ON_LENS
+                    }
+
+                    // No lenses support HDR image on device
+                    return CaptureModeToggleUiState.DisabledReason.HDR_IMAGE_UNSUPPORTED_ON_DEVICE
+                }
+
+                throw RuntimeException("Unknown DisabledReason for video mode.")
+            }
+
+            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE -> {
+                if (previewMode is PreviewMode.ExternalImageCaptureMode) {
+                    return CaptureModeToggleUiState.DisabledReason
+                        .VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED
+                }
+
+                if (!hdrDynamicRangeSupported) {
+                    if (systemConstraints.anySupportsHdrDynamicRange { it != currentLensFacing }) {
+                        return CaptureModeToggleUiState.DisabledReason.HDR_VIDEO_UNSUPPORTED_ON_LENS
+                    }
+                    return CaptureModeToggleUiState.DisabledReason.HDR_VIDEO_UNSUPPORTED_ON_DEVICE
+                }
+
+                throw RuntimeException("Unknown DisabledReason for image mode.")
+            }
+        }
+    }
+
+    private fun SystemConstraints.anySupportsHdrDynamicRange(
+        lensFilter: (LensFacing) -> Boolean
+    ): Boolean = perLensConstraints.asSequence().firstOrNull {
+        lensFilter(it.key) && it.value.supportedDynamicRanges.size > 1
+    } != null
+
+    private fun Map<CaptureMode, Set<ImageOutputFormat>>.anySupportsUltraHdr(
+        captureModeFilter: (CaptureMode) -> Boolean
+    ): Boolean = asSequence().firstOrNull {
+        captureModeFilter(it.key) && it.value.contains(ImageOutputFormat.JPEG_ULTRA_HDR)
+    } != null
+
+    private fun SystemConstraints.anySupportsUltraHdr(
+        captureModeFilter: (CaptureMode) -> Boolean = { true },
+        lensFilter: (LensFacing) -> Boolean
+    ): Boolean = perLensConstraints.asSequence().firstOrNull { lensConstraints ->
+        lensFilter(lensConstraints.key) &&
+            lensConstraints.value.supportedImageFormatsMap.anySupportsUltraHdr {
+                captureModeFilter(it)
+            }
+    } != null
+
     fun startCamera() {
         Log.d(TAG, "startCamera")
         stopCamera()
         runningCameraJob = viewModelScope.launch {
+            if (Trace.isEnabled()) {
+                launch(start = CoroutineStart.UNDISPATCHED) {
+                    val startTraceTimestamp: Long = SystemClock.elapsedRealtimeNanos()
+                    traceFirstFramePreview(cookie = 1) {
+                        _previewUiState.transformWhile {
+                            var continueCollecting = true
+                            (it as? PreviewUiState.Ready)?.let { uiState ->
+                                if (uiState.sessionFirstFrameTimestamp > startTraceTimestamp) {
+                                    emit(Unit)
+                                    continueCollecting = false
+                                }
+                            }
+                            continueCollecting
+                        }.collect {}
+                    }
+                }
+            }
             // Ensure CameraUseCase is initialized before starting camera
             initializationDeferred.await()
             // TODO(yasith): Handle Exceptions from binding use cases
@@ -153,7 +433,6 @@ class PreviewViewModel @AssistedInject constructor(
 
     fun setCaptureMode(captureMode: CaptureMode) {
         viewModelScope.launch {
-            // apply to cameraUseCase
             cameraUseCase.setCaptureMode(captureMode)
         }
     }
@@ -166,7 +445,43 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
+    fun setAudioMuted(shouldMuteAudio: Boolean) {
+        viewModelScope.launch {
+            cameraUseCase.setAudioMuted(shouldMuteAudio)
+        }
+
+        Log.d(
+            TAG,
+            "Toggle Audio ${
+                (previewUiState.value as PreviewUiState.Ready)
+                    .currentCameraSettings.audioMuted
+            }"
+        )
+    }
+
+    private fun showExternalVideoCaptureUnsupportedToast() {
+        viewModelScope.launch {
+            _previewUiState.update { old ->
+                (old as? PreviewUiState.Ready)?.copy(
+                    snackBarToShow = SnackbarData(
+                        cookie = "Image-ExternalVideoCaptureMode",
+                        stringResource = R.string.toast_image_capture_external_unsupported,
+                        withDismissAction = true,
+                        testTag = IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+                    )
+                ) ?: old
+            }
+        }
+    }
+
     fun captureImage() {
+        if (previewUiState.value is PreviewUiState.Ready &&
+            (previewUiState.value as PreviewUiState.Ready).previewMode is
+                PreviewMode.ExternalVideoCaptureMode
+        ) {
+            showExternalVideoCaptureUnsupportedToast()
+            return
+        }
         Log.d(TAG, "captureImage")
         viewModelScope.launch {
             captureImageInternal(
@@ -189,6 +504,32 @@ class PreviewViewModel @AssistedInject constructor(
         ignoreUri: Boolean = false,
         onImageCapture: (ImageCaptureEvent) -> Unit
     ) {
+        if (previewUiState.value is PreviewUiState.Ready &&
+            (previewUiState.value as PreviewUiState.Ready).previewMode is
+                PreviewMode.ExternalVideoCaptureMode
+        ) {
+            showExternalVideoCaptureUnsupportedToast()
+            return
+        }
+
+        if (previewUiState.value is PreviewUiState.Ready &&
+            (previewUiState.value as PreviewUiState.Ready).previewMode is
+                PreviewMode.ExternalVideoCaptureMode
+        ) {
+            viewModelScope.launch {
+                _previewUiState.update { old ->
+                    (old as? PreviewUiState.Ready)?.copy(
+                        snackBarToShow = SnackbarData(
+                            cookie = "Image-ExternalVideoCaptureMode",
+                            stringResource = R.string.toast_image_capture_external_unsupported,
+                            withDismissAction = true,
+                            testTag = IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+                        )
+                    ) ?: old
+                }
+            }
+            return
+        }
         Log.d(TAG, "captureImageWithUri")
         viewModelScope.launch {
             captureImageInternal(
@@ -214,7 +555,7 @@ class PreviewViewModel @AssistedInject constructor(
         onSuccess: (T) -> Unit = {},
         onFailure: (exception: Exception) -> Unit = {}
     ) {
-        val cookieInt = imageCaptureCalledCount.incrementAndGet()
+        val cookieInt = snackBarCount.incrementAndGet()
         val cookie = "Image-$cookieInt"
         try {
             traceAsync(IMAGE_CAPTURE_TRACE, cookieInt) {
@@ -248,7 +589,28 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun startVideoRecording() {
+    fun showSnackBarForDisabledHdrToggle(disabledReason: CaptureModeToggleUiState.DisabledReason) {
+        val cookieInt = snackBarCount.incrementAndGet()
+        val cookie = "DisabledHdrToggle-$cookieInt"
+        viewModelScope.launch {
+            _previewUiState.update { old ->
+                (old as? PreviewUiState.Ready)?.copy(
+                    snackBarToShow = SnackbarData(
+                        cookie = cookie,
+                        stringResource = disabledReason.reasonTextResId,
+                        withDismissAction = true,
+                        testTag = disabledReason.testTag
+                    )
+                ) ?: old
+            }
+        }
+    }
+
+    fun startVideoRecording(
+        videoCaptureUri: Uri?,
+        shouldUseUri: Boolean,
+        onVideoCapture: (VideoCaptureEvent) -> Unit
+    ) {
         if (previewUiState.value is PreviewUiState.Ready &&
             (previewUiState.value as PreviewUiState.Ready).previewMode is
                 PreviewMode.ExternalImageCaptureMode
@@ -272,23 +634,29 @@ class PreviewViewModel @AssistedInject constructor(
         recordingJob = viewModelScope.launch {
             val cookie = "Video-${videoCaptureStartedCount.incrementAndGet()}"
             try {
-                cameraUseCase.startVideoRecording {
+                cameraUseCase.startVideoRecording(videoCaptureUri, shouldUseUri) {
                     var audioAmplitude = 0.0
                     var snackbarToShow: SnackbarData? = null
                     when (it) {
-                        CameraUseCase.OnVideoRecordEvent.OnVideoRecorded -> {
+                        is CameraUseCase.OnVideoRecordEvent.OnVideoRecorded -> {
+                            Log.d(TAG, "cameraUseCase.startRecording OnVideoRecorded")
+                            onVideoCapture(VideoCaptureEvent.VideoSaved(it.savedUri))
                             snackbarToShow = SnackbarData(
                                 cookie = cookie,
                                 stringResource = R.string.toast_video_capture_success,
-                                withDismissAction = true
+                                withDismissAction = true,
+                                testTag = VIDEO_CAPTURE_SUCCESS_TAG
                             )
                         }
 
-                        CameraUseCase.OnVideoRecordEvent.OnVideoRecordError -> {
+                        is CameraUseCase.OnVideoRecordEvent.OnVideoRecordError -> {
+                            Log.d(TAG, "cameraUseCase.startRecording OnVideoRecordError")
+                            onVideoCapture(VideoCaptureEvent.VideoCaptureError(it.error))
                             snackbarToShow = SnackbarData(
                                 cookie = cookie,
                                 stringResource = R.string.toast_video_capture_failure,
-                                withDismissAction = true
+                                withDismissAction = true,
+                                testTag = VIDEO_CAPTURE_FAILURE_TAG
                             )
                         }
 
@@ -341,6 +709,24 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
+    fun setConcurrentCameraMode(concurrentCameraMode: ConcurrentCameraMode) {
+        viewModelScope.launch {
+            cameraUseCase.setConcurrentCameraMode(concurrentCameraMode)
+        }
+    }
+
+    fun setLowLightBoost(lowLightBoost: LowLightBoost) {
+        viewModelScope.launch {
+            cameraUseCase.setLowLightBoost(lowLightBoost)
+        }
+    }
+
+    fun setImageFormat(imageFormat: ImageOutputFormat) {
+        viewModelScope.launch {
+            cameraUseCase.setImageFormat(imageFormat)
+        }
+    }
+
     // modify ui values
     fun toggleQuickSettings() {
         viewModelScope.launch {
@@ -352,14 +738,11 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun tapToFocus(display: Display, surfaceWidth: Int, surfaceHeight: Int, x: Float, y: Float) {
-        cameraUseCase.tapToFocus(
-            display = display,
-            surfaceWidth = surfaceWidth,
-            surfaceHeight = surfaceHeight,
-            x = x,
-            y = y
-        )
+    fun tapToFocus(x: Float, y: Float) {
+        Log.d(TAG, "tapToFocus")
+        viewModelScope.launch {
+            cameraUseCase.tapToFocus(x, y)
+        }
     }
 
     /**
@@ -392,9 +775,15 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
+    fun setDisplayRotation(deviceRotation: DeviceRotation) {
+        viewModelScope.launch {
+            cameraUseCase.setDeviceRotation(deviceRotation)
+        }
+    }
+
     @AssistedFactory
     interface Factory {
-        fun create(previewMode: PreviewMode): PreviewViewModel
+        fun create(previewMode: PreviewMode, isDebugMode: Boolean): PreviewViewModel
     }
 
     sealed interface ImageCaptureEvent {
@@ -406,4 +795,14 @@ class PreviewViewModel @AssistedInject constructor(
             val exception: Exception
         ) : ImageCaptureEvent
     }
+
+    sealed interface VideoCaptureEvent {
+        data class VideoSaved(
+            val savedUri: Uri
+        ) : VideoCaptureEvent
+
+        data class VideoCaptureError(
+            val error: Throwable?
+        ) : VideoCaptureEvent
+    }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ScreenFlash.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ScreenFlash.kt
index e7ea585..7bd075a 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ScreenFlash.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ScreenFlash.kt
@@ -15,7 +15,7 @@
  */
 package com.google.jetpackcamera.feature.preview
 
-import com.google.jetpackcamera.domain.camera.CameraUseCase
+import com.google.jetpackcamera.core.camera.CameraUseCase
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
@@ -45,7 +45,7 @@ class ScreenFlash(
 
     init {
         scope.launch {
-            cameraUseCase.getScreenFlashEvents().collect { event ->
+            for (event in cameraUseCase.getScreenFlashEvents()) {
                 _screenFlashUiState.emit(
                     when (event.type) {
                         CameraUseCase.ScreenFlashEvent.Type.APPLY_UI ->
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
index a569a8d..2ee1e78 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
@@ -25,6 +25,9 @@ import androidx.compose.material.icons.filled.FlashOff
 import androidx.compose.material.icons.filled.FlashOn
 import androidx.compose.material.icons.filled.HdrOff
 import androidx.compose.material.icons.filled.HdrOn
+import androidx.compose.material.icons.filled.Nightlight
+import androidx.compose.material.icons.filled.PictureInPicture
+import androidx.compose.material.icons.outlined.Nightlight
 import androidx.compose.runtime.Composable
 import androidx.compose.ui.graphics.painter.Painter
 import androidx.compose.ui.graphics.vector.ImageVector
@@ -139,10 +142,46 @@ enum class CameraDynamicRange : QuickSettingsEnum {
         override fun getTextResId() = R.string.quick_settings_dynamic_range_sdr
         override fun getDescriptionResId() = R.string.quick_settings_dynamic_range_sdr_description
     },
-    HLG10 {
+    HDR {
         override fun getDrawableResId() = null
         override fun getImageVector() = Icons.Filled.HdrOn
-        override fun getTextResId() = R.string.quick_settings_dynamic_range_hlg10
-        override fun getDescriptionResId() = R.string.quick_settings_dynamic_range_hlg10_description
+        override fun getTextResId() = R.string.quick_settings_dynamic_range_hdr
+        override fun getDescriptionResId() = R.string.quick_settings_dynamic_range_hdr_description
+    }
+}
+
+enum class CameraLowLightBoost : QuickSettingsEnum {
+
+    ENABLED {
+        override fun getDrawableResId() = null
+        override fun getImageVector() = Icons.Filled.Nightlight
+        override fun getTextResId() = R.string.quick_settings_lowlightboost_enabled
+        override fun getDescriptionResId() =
+            R.string.quick_settings_lowlightboost_enabled_description
+    },
+
+    DISABLED {
+        override fun getDrawableResId() = null
+        override fun getImageVector() = Icons.Outlined.Nightlight
+        override fun getTextResId() = R.string.quick_settings_lowlightboost_disabled
+        override fun getDescriptionResId() =
+            R.string.quick_settings_lowlightboost_disabled_description
+    }
+}
+
+enum class CameraConcurrentCameraMode : QuickSettingsEnum {
+    OFF {
+        override fun getDrawableResId() = R.drawable.picture_in_picture_off_icon
+        override fun getImageVector() = null
+        override fun getTextResId() = R.string.quick_settings_concurrent_camera_off
+        override fun getDescriptionResId() =
+            R.string.quick_settings_concurrent_camera_off_description
+    },
+    DUAL {
+        override fun getDrawableResId() = null
+        override fun getImageVector() = Icons.Filled.PictureInPicture
+        override fun getTextResId() = R.string.quick_settings_concurrent_camera_dual
+        override fun getDescriptionResId() =
+            R.string.quick_settings_concurrent_camera_dual_description
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
index 1eafa89..7dbb474 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2023 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -38,28 +38,34 @@ import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.tooling.preview.Preview
+import com.google.jetpackcamera.feature.preview.CaptureModeToggleUiState
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.R
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.ExpandedQuickSetRatio
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CAPTURE_MODE_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_HDR_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickFlipCamera
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetCaptureMode
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetConcurrentCamera
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetFlash
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetHdr
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetRatio
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSettingsGrid
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.CameraConstraints
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.model.LowLightBoost
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
 import com.google.jetpackcamera.settings.model.forCurrentLens
 
@@ -70,13 +76,15 @@ import com.google.jetpackcamera.settings.model.forCurrentLens
 fun QuickSettingsScreenOverlay(
     previewUiState: PreviewUiState.Ready,
     currentCameraSettings: CameraAppSettings,
-    systemConstraints: SystemConstraints,
     toggleIsOpen: () -> Unit,
     onLensFaceClick: (lensFace: LensFacing) -> Unit,
     onFlashModeClick: (flashMode: FlashMode) -> Unit,
     onAspectRatioClick: (aspectRation: AspectRatio) -> Unit,
     onCaptureModeClick: (captureMode: CaptureMode) -> Unit,
     onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit,
+    onImageOutputFormatClick: (imageOutputFormat: ImageOutputFormat) -> Unit,
+    onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit,
+    onLowLightBoostClick: (lowLightBoost: LowLightBoost) -> Unit,
     modifier: Modifier = Modifier,
     isOpen: Boolean = false
 ) {
@@ -118,7 +126,6 @@ fun QuickSettingsScreenOverlay(
             ExpandedQuickSettingsUi(
                 previewUiState = previewUiState,
                 currentCameraSettings = currentCameraSettings,
-                systemConstraints = systemConstraints,
                 shouldShowQuickSetting = shouldShowQuickSetting,
                 setVisibleQuickSetting = { enum: IsExpandedQuickSetting ->
                     shouldShowQuickSetting = enum
@@ -127,7 +134,10 @@ fun QuickSettingsScreenOverlay(
                 onFlashModeClick = onFlashModeClick,
                 onAspectRatioClick = onAspectRatioClick,
                 onCaptureModeClick = onCaptureModeClick,
-                onDynamicRangeClick = onDynamicRangeClick
+                onDynamicRangeClick = onDynamicRangeClick,
+                onImageOutputFormatClick = onImageOutputFormatClick,
+                onConcurrentCameraModeClick = onConcurrentCameraModeClick,
+                onLowLightBoostClick = onLowLightBoostClick
             )
         }
     } else {
@@ -148,14 +158,16 @@ private enum class IsExpandedQuickSetting {
 private fun ExpandedQuickSettingsUi(
     previewUiState: PreviewUiState.Ready,
     currentCameraSettings: CameraAppSettings,
-    systemConstraints: SystemConstraints,
     onLensFaceClick: (newLensFace: LensFacing) -> Unit,
     onFlashModeClick: (flashMode: FlashMode) -> Unit,
     onAspectRatioClick: (aspectRation: AspectRatio) -> Unit,
     onCaptureModeClick: (captureMode: CaptureMode) -> Unit,
     shouldShowQuickSetting: IsExpandedQuickSetting,
     setVisibleQuickSetting: (IsExpandedQuickSetting) -> Unit,
-    onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit
+    onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit,
+    onImageOutputFormatClick: (imageOutputFormat: ImageOutputFormat) -> Unit,
+    onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit,
+    onLowLightBoostClick: (lowLightBoost: LowLightBoost) -> Unit
 ) {
     Column(
         modifier =
@@ -205,22 +217,64 @@ private fun ExpandedQuickSettingsUi(
                             QuickSetCaptureMode(
                                 modifier = Modifier.testTag(QUICK_SETTINGS_CAPTURE_MODE_BUTTON),
                                 setCaptureMode = { c: CaptureMode -> onCaptureModeClick(c) },
-                                currentCaptureMode = currentCameraSettings.captureMode
+                                currentCaptureMode = currentCameraSettings.captureMode,
+                                enabled = currentCameraSettings.concurrentCameraMode ==
+                                    ConcurrentCameraMode.OFF
                             )
                         }
 
+                        val cameraConstraints = previewUiState.systemConstraints.forCurrentLens(
+                            currentCameraSettings
+                        )
                         add {
+                            fun CameraConstraints.hdrDynamicRangeSupported(): Boolean =
+                                this.supportedDynamicRanges.size > 1
+
+                            fun CameraConstraints.hdrImageFormatSupported(): Boolean =
+                                supportedImageFormatsMap[currentCameraSettings.captureMode]
+                                    ?.let { it.size > 1 } ?: false
+
+                            // TODO(tm): Move this to PreviewUiState
+                            fun shouldEnable(): Boolean = when {
+                                currentCameraSettings.concurrentCameraMode !=
+                                    ConcurrentCameraMode.OFF -> false
+                                else -> (
+                                    cameraConstraints?.hdrDynamicRangeSupported() == true &&
+                                        previewUiState.previewMode is PreviewMode.StandardMode
+                                    ) ||
+                                    cameraConstraints?.hdrImageFormatSupported() == true
+                            }
+
                             QuickSetHdr(
                                 modifier = Modifier.testTag(QUICK_SETTINGS_HDR_BUTTON),
-                                onClick = { d: DynamicRange -> onDynamicRangeClick(d) },
+                                onClick = { d: DynamicRange, i: ImageOutputFormat ->
+                                    onDynamicRangeClick(d)
+                                    onImageOutputFormatClick(i)
+                                },
                                 selectedDynamicRange = currentCameraSettings.dynamicRange,
+                                selectedImageOutputFormat = currentCameraSettings.imageFormat,
                                 hdrDynamicRange = currentCameraSettings.defaultHdrDynamicRange,
-                                enabled = previewUiState.previewMode !is
-                                    PreviewMode.ExternalImageCaptureMode &&
-                                    previewUiState.systemConstraints.forCurrentLens(
-                                        currentCameraSettings
-                                    )
-                                        ?.let { it.supportedDynamicRanges.size > 1 } ?: false
+                                hdrImageFormat = currentCameraSettings.defaultHdrImageOutputFormat,
+                                hdrDynamicRangeSupported =
+                                cameraConstraints?.hdrDynamicRangeSupported() ?: false,
+                                previewMode = previewUiState.previewMode,
+                                enabled = shouldEnable()
+                            )
+                        }
+
+                        add {
+                            QuickSetConcurrentCamera(
+                                modifier =
+                                Modifier.testTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON),
+                                setConcurrentCameraMode = { c: ConcurrentCameraMode ->
+                                    onConcurrentCameraModeClick(c)
+                                },
+                                currentConcurrentCameraMode =
+                                currentCameraSettings.concurrentCameraMode,
+                                enabled =
+                                previewUiState.systemConstraints.concurrentCamerasSupported &&
+                                    previewUiState.previewMode
+                                        !is PreviewMode.ExternalImageCaptureMode
                             )
                         }
                     }
@@ -245,17 +299,20 @@ fun ExpandedQuickSettingsUiPreview() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             currentCameraSettings = CameraAppSettings(),
-            systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
             onLensFaceClick = { },
             onFlashModeClick = { },
             shouldShowQuickSetting = IsExpandedQuickSetting.NONE,
             setVisibleQuickSetting = { },
             onAspectRatioClick = { },
             onCaptureModeClick = { },
-            onDynamicRangeClick = { }
+            onDynamicRangeClick = { },
+            onImageOutputFormatClick = { },
+            onConcurrentCameraModeClick = { },
+            onLowLightBoostClick = { }
         )
     }
 }
@@ -268,17 +325,20 @@ fun ExpandedQuickSettingsUiPreview_WithHdr() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             currentCameraSettings = CameraAppSettings(dynamicRange = DynamicRange.HLG10),
-            systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS_WITH_HDR,
             onLensFaceClick = { },
             onFlashModeClick = { },
             shouldShowQuickSetting = IsExpandedQuickSetting.NONE,
             setVisibleQuickSetting = { },
             onAspectRatioClick = { },
             onCaptureModeClick = { },
-            onDynamicRangeClick = { }
+            onDynamicRangeClick = { },
+            onImageOutputFormatClick = { },
+            onConcurrentCameraModeClick = { },
+            onLowLightBoostClick = { }
         )
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
index f7af6e0..66e2bc7 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
@@ -45,18 +45,24 @@ import androidx.compose.ui.semantics.contentDescription
 import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.text.style.TextAlign
 import androidx.compose.ui.unit.dp
+import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.R
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraAspectRatio
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraCaptureMode
+import com.google.jetpackcamera.feature.preview.quicksettings.CameraConcurrentCameraMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraDynamicRange
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraFlashMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraLensFace
+import com.google.jetpackcamera.feature.preview.quicksettings.CameraLowLightBoost
 import com.google.jetpackcamera.feature.preview.quicksettings.QuickSettingsEnum
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.LowLightBoost
 import kotlin.math.min
 
 // completed components ready to go into preview screen
@@ -103,32 +109,73 @@ fun ExpandedQuickSetRatio(
 @Composable
 fun QuickSetHdr(
     modifier: Modifier = Modifier,
-    onClick: (dynamicRange: DynamicRange) -> Unit,
+    onClick: (dynamicRange: DynamicRange, imageOutputFormat: ImageOutputFormat) -> Unit,
     selectedDynamicRange: DynamicRange,
+    selectedImageOutputFormat: ImageOutputFormat,
     hdrDynamicRange: DynamicRange,
-    enabled: Boolean = true
+    hdrImageFormat: ImageOutputFormat,
+    hdrDynamicRangeSupported: Boolean,
+    previewMode: PreviewMode,
+    enabled: Boolean
 ) {
     val enum =
-        when (selectedDynamicRange) {
-            DynamicRange.SDR -> CameraDynamicRange.SDR
-            DynamicRange.HLG10 -> CameraDynamicRange.HLG10
+        if (selectedDynamicRange == hdrDynamicRange ||
+            selectedImageOutputFormat == hdrImageFormat
+        ) {
+            CameraDynamicRange.HDR
+        } else {
+            CameraDynamicRange.SDR
         }
+
     QuickSettingUiItem(
         modifier = modifier,
         enum = enum,
         onClick = {
-            val newDynamicRange = if (selectedDynamicRange == DynamicRange.SDR) {
-                hdrDynamicRange
-            } else {
-                DynamicRange.SDR
-            }
-            onClick(newDynamicRange)
+            val newDynamicRange =
+                if (selectedDynamicRange == DynamicRange.SDR && hdrDynamicRangeSupported) {
+                    hdrDynamicRange
+                } else {
+                    DynamicRange.SDR
+                }
+            val newImageOutputFormat =
+                if (!hdrDynamicRangeSupported ||
+                    previewMode is PreviewMode.ExternalImageCaptureMode
+                ) {
+                    hdrImageFormat
+                } else {
+                    ImageOutputFormat.JPEG
+                }
+            onClick(newDynamicRange, newImageOutputFormat)
         },
         isHighLighted = (selectedDynamicRange != DynamicRange.SDR),
         enabled = enabled
     )
 }
 
+@Composable
+fun QuickSetLowLightBoost(
+    modifier: Modifier = Modifier,
+    onClick: (lowLightBoost: LowLightBoost) -> Unit,
+    selectedLowLightBoost: LowLightBoost
+) {
+    val enum = when (selectedLowLightBoost) {
+        LowLightBoost.DISABLED -> CameraLowLightBoost.DISABLED
+        LowLightBoost.ENABLED -> CameraLowLightBoost.ENABLED
+    }
+
+    QuickSettingUiItem(
+        modifier = modifier,
+        enum = enum,
+        onClick = {
+            when (selectedLowLightBoost) {
+                LowLightBoost.DISABLED -> onClick(LowLightBoost.ENABLED)
+                LowLightBoost.ENABLED -> onClick(LowLightBoost.DISABLED)
+            }
+        },
+        isHighLighted = false
+    )
+}
+
 @Composable
 fun QuickSetRatio(
     onClick: () -> Unit,
@@ -204,7 +251,8 @@ fun QuickFlipCamera(
 fun QuickSetCaptureMode(
     setCaptureMode: (CaptureMode) -> Unit,
     currentCaptureMode: CaptureMode,
-    modifier: Modifier = Modifier
+    modifier: Modifier = Modifier,
+    enabled: Boolean = true
 ) {
     val enum: CameraCaptureMode =
         when (currentCaptureMode) {
@@ -219,7 +267,33 @@ fun QuickSetCaptureMode(
                 CaptureMode.MULTI_STREAM -> setCaptureMode(CaptureMode.SINGLE_STREAM)
                 CaptureMode.SINGLE_STREAM -> setCaptureMode(CaptureMode.MULTI_STREAM)
             }
+        },
+        enabled = enabled
+    )
+}
+
+@Composable
+fun QuickSetConcurrentCamera(
+    setConcurrentCameraMode: (ConcurrentCameraMode) -> Unit,
+    currentConcurrentCameraMode: ConcurrentCameraMode,
+    modifier: Modifier = Modifier,
+    enabled: Boolean = true
+) {
+    val enum: CameraConcurrentCameraMode =
+        when (currentConcurrentCameraMode) {
+            ConcurrentCameraMode.OFF -> CameraConcurrentCameraMode.OFF
+            ConcurrentCameraMode.DUAL -> CameraConcurrentCameraMode.DUAL
         }
+    QuickSettingUiItem(
+        modifier = modifier,
+        enum = enum,
+        onClick = {
+            when (currentConcurrentCameraMode) {
+                ConcurrentCameraMode.OFF -> setConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+                ConcurrentCameraMode.DUAL -> setConcurrentCameraMode(ConcurrentCameraMode.OFF)
+            }
+        },
+        enabled = enabled
     )
 }
 
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
index f89fb15..5a226e6 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
@@ -16,9 +16,11 @@
 package com.google.jetpackcamera.feature.preview.quicksettings.ui
 
 const val QUICK_SETTINGS_CAPTURE_MODE_BUTTON = "QuickSettingsCaptureModeButton"
+const val QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON = "QuickSettingsConcurrentCameraModeButton"
 const val QUICK_SETTINGS_DROP_DOWN = "QuickSettingsDropDown"
 const val QUICK_SETTINGS_HDR_BUTTON = "QuickSettingsHdrButton"
 const val QUICK_SETTINGS_FLASH_BUTTON = "QuickSettingsFlashButton"
+const val QUICK_SETTINGS_LOW_LIGHT_BOOST_BUTTON = "QuickSettingsLowLightBoostButton"
 const val QUICK_SETTINGS_FLIP_CAMERA_BUTTON = "QuickSettingsFlipCameraButton"
 const val QUICK_SETTINGS_RATIO_3_4_BUTTON = "QuickSettingsRatio3:4Button"
 const val QUICK_SETTINGS_RATIO_9_16_BUTTON = "QuickSettingsRatio9:16Button"
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
index f8e1d54..9563db9 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
@@ -15,6 +15,7 @@
  */
 package com.google.jetpackcamera.feature.preview.ui
 
+import android.annotation.SuppressLint
 import android.content.ContentResolver
 import android.net.Uri
 import androidx.compose.foundation.layout.Arrangement
@@ -26,7 +27,13 @@ import androidx.compose.foundation.layout.fillMaxSize
 import androidx.compose.foundation.layout.fillMaxWidth
 import androidx.compose.foundation.layout.height
 import androidx.compose.foundation.layout.padding
+import androidx.compose.material.icons.Icons
+import androidx.compose.material.icons.filled.CameraAlt
+import androidx.compose.material.icons.filled.Videocam
+import androidx.compose.material.icons.outlined.CameraAlt
+import androidx.compose.material.icons.outlined.Videocam
 import androidx.compose.material3.LocalContentColor
+import androidx.compose.material3.LocalTextStyle
 import androidx.compose.runtime.Composable
 import androidx.compose.runtime.CompositionLocalProvider
 import androidx.compose.runtime.LaunchedEffect
@@ -37,10 +44,14 @@ import androidx.compose.runtime.setValue
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.graphics.vector.rememberVectorPainter
 import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.dp
+import androidx.compose.ui.unit.sp
+import androidx.core.util.Preconditions
+import com.google.jetpackcamera.feature.preview.CaptureModeToggleUiState
 import com.google.jetpackcamera.feature.preview.MultipleEventsCutter
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewUiState
@@ -50,6 +61,7 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSettingsIn
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.ToggleQuickSettingsButton
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.Stabilization
 import com.google.jetpackcamera.settings.model.SystemConstraints
@@ -75,7 +87,10 @@ fun CameraControlsOverlay(
     onNavigateToSettings: () -> Unit = {},
     onFlipCamera: () -> Unit = {},
     onChangeFlash: (FlashMode) -> Unit = {},
+    onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
+    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
     onToggleQuickSettings: () -> Unit = {},
+    onMuteAudio: () -> Unit = {},
     onCaptureImage: () -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
@@ -83,7 +98,11 @@ fun CameraControlsOverlay(
         Boolean,
         (PreviewViewModel.ImageCaptureEvent) -> Unit
     ) -> Unit = { _, _, _, _ -> },
-    onStartVideoRecording: () -> Unit = {},
+    onStartVideoRecording: (
+        Uri?,
+        Boolean,
+        (PreviewViewModel.VideoCaptureEvent) -> Unit
+    ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {}
 ) {
     // Show the current zoom level for a short period of time, only when the level changes.
@@ -118,14 +137,20 @@ fun CameraControlsOverlay(
                 previewUiState = previewUiState,
                 audioAmplitude = previewUiState.audioAmplitude,
                 zoomLevel = previewUiState.zoomScale,
+                physicalCameraId = previewUiState.currentPhysicalCameraId,
+                logicalCameraId = previewUiState.currentLogicalCameraId,
                 showZoomLevel = zoomLevelDisplayState.showZoomLevel,
                 isQuickSettingsOpen = previewUiState.quickSettingsIsOpen,
+                currentCameraSettings = previewUiState.currentCameraSettings,
                 systemConstraints = previewUiState.systemConstraints,
                 videoRecordingState = previewUiState.videoRecordingState,
                 onFlipCamera = onFlipCamera,
                 onCaptureImage = onCaptureImage,
                 onCaptureImageWithUri = onCaptureImageWithUri,
                 onToggleQuickSettings = onToggleQuickSettings,
+                onToggleAudioMuted = onMuteAudio,
+                onChangeImageFormat = onChangeImageFormat,
+                onToggleWhenDisabled = onToggleWhenDisabled,
                 onStartVideoRecording = onStartVideoRecording,
                 onStopVideoRecording = onStopVideoRecording
             )
@@ -171,6 +196,9 @@ private fun ControlsTop(
                 videoStabilization = currentCameraSettings.videoCaptureStabilization,
                 previewStabilization = currentCameraSettings.previewStabilization
             )
+            LowLightBoostIcon(
+                lowLightBoost = currentCameraSettings.lowLightBoost
+            )
         }
     }
 }
@@ -180,9 +208,12 @@ private fun ControlsBottom(
     modifier: Modifier = Modifier,
     audioAmplitude: Double,
     previewUiState: PreviewUiState.Ready,
+    physicalCameraId: String? = null,
+    logicalCameraId: String? = null,
     zoomLevel: Float,
     showZoomLevel: Boolean,
     isQuickSettingsOpen: Boolean,
+    currentCameraSettings: CameraAppSettings,
     systemConstraints: SystemConstraints,
     videoRecordingState: VideoRecordingState,
     onFlipCamera: () -> Unit = {},
@@ -194,12 +225,28 @@ private fun ControlsBottom(
         (PreviewViewModel.ImageCaptureEvent) -> Unit
     ) -> Unit = { _, _, _, _ -> },
     onToggleQuickSettings: () -> Unit = {},
-    onStartVideoRecording: () -> Unit = {},
+    onToggleAudioMuted: () -> Unit = {},
+    onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
+    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
+    onStartVideoRecording: (
+        Uri?,
+        Boolean,
+        (PreviewViewModel.VideoCaptureEvent) -> Unit
+    ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {}
 ) {
     Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
-        if (showZoomLevel) {
-            ZoomScaleText(zoomLevel)
+        CompositionLocalProvider(
+            LocalTextStyle provides LocalTextStyle.current.copy(fontSize = 20.sp)
+        ) {
+            Column(horizontalAlignment = Alignment.CenterHorizontally) {
+                if (showZoomLevel) {
+                    ZoomScaleText(zoomLevel)
+                }
+                if (previewUiState.isDebugMode) {
+                    CurrentCameraIdText(physicalCameraId, logicalCameraId)
+                }
+            }
         }
 
         Row(
@@ -228,15 +275,26 @@ private fun ControlsBottom(
                 onStartVideoRecording = onStartVideoRecording,
                 onStopVideoRecording = onStopVideoRecording
             )
-            Row(Modifier.weight(1f)) {
+            Row(Modifier.weight(1f), horizontalArrangement = Arrangement.SpaceEvenly) {
                 if (videoRecordingState == VideoRecordingState.ACTIVE) {
                     AmplitudeVisualizer(
                         modifier = Modifier
                             .weight(1f)
                             .fillMaxSize(),
+                        onToggleMute = onToggleAudioMuted,
                         size = 75,
                         audioAmplitude = audioAmplitude
                     )
+                } else {
+                    if (!isQuickSettingsOpen &&
+                        previewUiState.captureModeToggleUiState is CaptureModeToggleUiState.Visible
+                    ) {
+                        CaptureModeToggleButton(
+                            uiState = previewUiState.captureModeToggleUiState,
+                            onChangeImageFormat = onChangeImageFormat,
+                            onToggleWhenDisabled = onToggleWhenDisabled
+                        )
+                    }
                 }
             }
         }
@@ -257,7 +315,11 @@ private fun CaptureButton(
         (PreviewViewModel.ImageCaptureEvent) -> Unit
     ) -> Unit = { _, _, _, _ -> },
     onToggleQuickSettings: () -> Unit = {},
-    onStartVideoRecording: () -> Unit = {},
+    onStartVideoRecording: (
+        Uri?,
+        Boolean,
+        (PreviewViewModel.VideoCaptureEvent) -> Unit
+    ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {}
 ) {
     val multipleEventsCutter = remember { MultipleEventsCutter() }
@@ -284,6 +346,14 @@ private fun CaptureButton(
                             previewUiState.previewMode.onImageCapture
                         )
                     }
+
+                    else -> {
+                        onCaptureImageWithUri(
+                            context.contentResolver,
+                            null,
+                            false
+                        ) {}
+                    }
                 }
             }
             if (isQuickSettingsOpen) {
@@ -291,16 +361,78 @@ private fun CaptureButton(
             }
         },
         onLongPress = {
-            onStartVideoRecording()
+            when (previewUiState.previewMode) {
+                is PreviewMode.StandardMode -> {
+                    onStartVideoRecording(null, false) {}
+                }
+
+                is PreviewMode.ExternalVideoCaptureMode -> {
+                    onStartVideoRecording(
+                        previewUiState.previewMode.videoCaptureUri,
+                        true,
+                        previewUiState.previewMode.onVideoCapture
+                    )
+                }
+
+                else -> {
+                    onStartVideoRecording(null, false) {}
+                }
+            }
             if (isQuickSettingsOpen) {
                 onToggleQuickSettings()
             }
         },
-        onRelease = { onStopVideoRecording() },
+        onRelease = {
+            onStopVideoRecording()
+        },
         videoRecordingState = videoRecordingState
     )
 }
 
+@SuppressLint("RestrictedApi")
+@Composable
+private fun CaptureModeToggleButton(
+    uiState: CaptureModeToggleUiState.Visible,
+    onChangeImageFormat: (ImageOutputFormat) -> Unit,
+    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit
+) {
+    // Captures hdr image (left) when output format is UltraHdr, else captures hdr video (right).
+    val initialState =
+        when (uiState.currentMode) {
+            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE -> ToggleState.Left
+            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO -> ToggleState.Right
+        }
+    ToggleButton(
+        leftIcon = if (uiState.currentMode ==
+            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE
+        ) {
+            rememberVectorPainter(image = Icons.Filled.CameraAlt)
+        } else {
+            rememberVectorPainter(image = Icons.Outlined.CameraAlt)
+        },
+        rightIcon = if (uiState.currentMode ==
+            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO
+        ) {
+            rememberVectorPainter(image = Icons.Filled.Videocam)
+        } else {
+            rememberVectorPainter(image = Icons.Outlined.Videocam)
+        },
+        initialState = initialState,
+        onToggleStateChanged = {
+            val imageFormat = when (it) {
+                ToggleState.Left -> ImageOutputFormat.JPEG_ULTRA_HDR
+                ToggleState.Right -> ImageOutputFormat.JPEG
+            }
+            onChangeImageFormat(imageFormat)
+        },
+        onToggleWhenDisabled = {
+            Preconditions.checkArgument(uiState is CaptureModeToggleUiState.Disabled)
+            onToggleWhenDisabled((uiState as CaptureModeToggleUiState.Disabled).disabledReason)
+        },
+        enabled = uiState is CaptureModeToggleUiState.Enabled
+    )
+}
+
 @Preview(backgroundColor = 0xFF000000, showBackground = true)
 @Composable
 private fun Preview_ControlsTop_QuickSettingsOpen() {
@@ -367,11 +499,13 @@ private fun Preview_ControlsBottom() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
+            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
             videoRecordingState = VideoRecordingState.INACTIVE,
             audioAmplitude = 0.0
@@ -387,11 +521,13 @@ private fun Preview_ControlsBottom_NoZoomLevel() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             zoomLevel = 1.3f,
             showZoomLevel = false,
             isQuickSettingsOpen = false,
+            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
             videoRecordingState = VideoRecordingState.INACTIVE,
             audioAmplitude = 0.0
@@ -407,15 +543,16 @@ private fun Preview_ControlsBottom_QuickSettingsOpen() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = true,
+            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
             videoRecordingState = VideoRecordingState.INACTIVE,
             audioAmplitude = 0.0
-
         )
     }
 }
@@ -428,11 +565,13 @@ private fun Preview_ControlsBottom_NoFlippableCamera() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
+            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS.copy(
                 availableLenses = listOf(LensFacing.FRONT),
                 perLensConstraints = mapOf(
@@ -442,7 +581,6 @@ private fun Preview_ControlsBottom_NoFlippableCamera() {
             ),
             videoRecordingState = VideoRecordingState.INACTIVE,
             audioAmplitude = 0.0
-
         )
     }
 }
@@ -455,11 +593,13 @@ private fun Preview_ControlsBottom_Recording() {
             previewUiState = PreviewUiState.Ready(
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-                previewMode = PreviewMode.StandardMode {}
+                previewMode = PreviewMode.StandardMode {},
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
+            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
             videoRecordingState = VideoRecordingState.ACTIVE,
             audioAmplitude = 0.9
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt
index 523efdd..2cf49ad 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt
@@ -17,14 +17,17 @@ package com.google.jetpackcamera.feature.preview.ui
 
 import android.content.pm.ActivityInfo
 import android.os.Build
+import android.util.Log
 import androidx.camera.core.DynamicRange
 import androidx.camera.core.Preview
 import androidx.camera.core.SurfaceRequest
 import androidx.camera.core.SurfaceRequest.TransformationInfo as CXTransformationInfo
+import androidx.camera.viewfinder.compose.MutableCoordinateTransformer
 import androidx.camera.viewfinder.compose.Viewfinder
 import androidx.camera.viewfinder.surface.ImplementationMode
 import androidx.camera.viewfinder.surface.TransformationInfo
 import androidx.camera.viewfinder.surface.ViewfinderSurfaceRequest
+import androidx.compose.foundation.gestures.detectTapGestures
 import androidx.compose.foundation.layout.fillMaxSize
 import androidx.compose.runtime.Composable
 import androidx.compose.runtime.LaunchedEffect
@@ -33,6 +36,7 @@ import androidx.compose.runtime.produceState
 import androidx.compose.runtime.rememberUpdatedState
 import androidx.compose.runtime.snapshotFlow
 import androidx.compose.ui.Modifier
+import androidx.compose.ui.input.pointer.pointerInput
 import kotlinx.coroutines.CoroutineStart
 import kotlinx.coroutines.Runnable
 import kotlinx.coroutines.flow.MutableStateFlow
@@ -47,6 +51,8 @@ import kotlinx.coroutines.flow.onEach
 import kotlinx.coroutines.flow.takeWhile
 import kotlinx.coroutines.launch
 
+private const val TAG = "CameraXViewfinder"
+
 /**
  * A composable viewfinder that adapts CameraX's [Preview.SurfaceProvider] to [Viewfinder]
  *
@@ -63,7 +69,8 @@ fun CameraXViewfinder(
     surfaceRequest: SurfaceRequest,
     modifier: Modifier = Modifier,
     implementationMode: ImplementationMode = ImplementationMode.EXTERNAL,
-    onRequestWindowColorMode: (Int) -> Unit = {}
+    onRequestWindowColorMode: (Int) -> Unit = {},
+    onTap: (x: Float, y: Float) -> Unit = { _, _ -> }
 ) {
     val currentImplementationMode by rememberUpdatedState(implementationMode)
     val currentOnRequestWindowColorMode by rememberUpdatedState(onRequestWindowColorMode)
@@ -151,12 +158,23 @@ fun CameraXViewfinder(
         }
     }
 
+    val coordinateTransformer = MutableCoordinateTransformer()
+
     viewfinderArgs?.let { args ->
         Viewfinder(
             surfaceRequest = args.viewfinderSurfaceRequest,
             implementationMode = args.implementationMode,
             transformationInfo = args.transformationInfo,
-            modifier = modifier.fillMaxSize()
+            modifier = modifier.fillMaxSize().pointerInput(Unit) {
+                detectTapGestures {
+                    with(coordinateTransformer) {
+                        val tapOffset = it.transform()
+                        Log.d(TAG, "onTap: $tapOffset")
+                        onTap(tapOffset.x, tapOffset.y)
+                    }
+                }
+            },
+            coordinateTransformer = coordinateTransformer
         )
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/DebouncedOrientationFlow.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/DebouncedOrientationFlow.kt
new file mode 100644
index 0000000..7add7b2
--- /dev/null
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/DebouncedOrientationFlow.kt
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
+package com.google.jetpackcamera.feature.preview.ui
+
+import android.content.Context
+import android.view.OrientationEventListener
+import android.view.OrientationEventListener.ORIENTATION_UNKNOWN
+import com.google.jetpackcamera.settings.model.DeviceRotation
+import kotlin.math.abs
+import kotlin.math.min
+import kotlinx.coroutines.channels.Channel.Factory.CONFLATED
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.flow.buffer
+import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.runningFold
+
+/** Orientation hysteresis amount used in rounding, in degrees. */
+private const val ORIENTATION_HYSTERESIS = 5
+
+fun debouncedOrientationFlow(context: Context) = callbackFlow {
+    val orientationListener = object : OrientationEventListener(context) {
+        override fun onOrientationChanged(orientation: Int) {
+            trySend(orientation)
+        }
+    }
+
+    orientationListener.enable()
+
+    awaitClose {
+        orientationListener.disable()
+    }
+}.buffer(capacity = CONFLATED)
+    .runningFold(initial = DeviceRotation.Natural) { prevSnap, newDegrees ->
+        if (
+            newDegrees != ORIENTATION_UNKNOWN &&
+            abs(prevSnap.toClockwiseRotationDegrees() - newDegrees).let { min(it, 360 - it) } >=
+            45 + ORIENTATION_HYSTERESIS
+        ) {
+            DeviceRotation.snapFrom(newDegrees)
+        } else {
+            prevSnap
+        }
+    }.distinctUntilChanged()
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
index 688def4..25a0f28 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
@@ -18,7 +18,6 @@ package com.google.jetpackcamera.feature.preview.ui
 import android.content.res.Configuration
 import android.os.Build
 import android.util.Log
-import android.view.Display
 import android.widget.Toast
 import androidx.camera.core.SurfaceRequest
 import androidx.camera.viewfinder.surface.ImplementationMode
@@ -36,6 +35,7 @@ import androidx.compose.foundation.gestures.transformable
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Box
 import androidx.compose.foundation.layout.BoxWithConstraints
+import androidx.compose.foundation.layout.Column
 import androidx.compose.foundation.layout.Row
 import androidx.compose.foundation.layout.aspectRatio
 import androidx.compose.foundation.layout.fillMaxHeight
@@ -51,10 +51,12 @@ import androidx.compose.material.icons.filled.CameraAlt
 import androidx.compose.material.icons.filled.FlipCameraAndroid
 import androidx.compose.material.icons.filled.Mic
 import androidx.compose.material.icons.filled.MicOff
+import androidx.compose.material.icons.filled.Nightlight
 import androidx.compose.material.icons.filled.Settings
 import androidx.compose.material.icons.filled.VideoStable
 import androidx.compose.material.icons.filled.Videocam
 import androidx.compose.material.icons.outlined.CameraAlt
+import androidx.compose.material.icons.outlined.Nightlight
 import androidx.compose.material.icons.outlined.Videocam
 import androidx.compose.material3.Icon
 import androidx.compose.material3.IconButton
@@ -88,12 +90,12 @@ import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.Dp
 import androidx.compose.ui.unit.dp
-import androidx.compose.ui.unit.sp
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.R
 import com.google.jetpackcamera.feature.preview.VideoRecordingState
 import com.google.jetpackcamera.feature.preview.ui.theme.PreviewPreviewTheme
 import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.LowLightBoost
 import com.google.jetpackcamera.settings.model.Stabilization
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.launch
@@ -102,13 +104,18 @@ private const val TAG = "PreviewScreen"
 private const val BLINK_TIME = 100L
 
 @Composable
-fun AmplitudeVisualizer(modifier: Modifier = Modifier, size: Int = 100, audioAmplitude: Double) {
+fun AmplitudeVisualizer(
+    modifier: Modifier = Modifier,
+    size: Int = 100,
+    audioAmplitude: Double,
+    onToggleMute: () -> Unit
+) {
     // Tweak the multiplier to amplitude to adjust the visualizer sensitivity
     val animatedScaling by animateFloatAsState(
         targetValue = EaseOutExpo.transform(1 + (1.75f * audioAmplitude.toFloat())),
         label = "AudioAnimation"
     )
-    Box(modifier = modifier) {
+    Box(modifier = modifier.clickable { onToggleMute() }) {
         // animated circle
         Canvas(
             modifier = Modifier
@@ -138,7 +145,14 @@ fun AmplitudeVisualizer(modifier: Modifier = Modifier, size: Int = 100, audioAmp
         Icon(
             modifier = Modifier
                 .align(Alignment.Center)
-                .size((0.5 * size).dp),
+                .size((0.5 * size).dp)
+                .apply {
+                    if (audioAmplitude != 0.0) {
+                        testTag(AMPLITUDE_HOT_TAG)
+                    } else {
+                        testTag(AMPLITUDE_NONE_TAG)
+                    }
+                },
             tint = Color.Black,
             imageVector = if (audioAmplitude != 0.0) {
                 Icons.Filled.Mic
@@ -236,7 +250,7 @@ fun TestableSnackbar(
 @Composable
 fun PreviewDisplay(
     previewUiState: PreviewUiState.Ready,
-    onTapToFocus: (Display, Int, Int, Float, Float) -> Unit,
+    onTapToFocus: (x: Float, y: Float) -> Unit,
     onFlipCamera: () -> Unit,
     onZoomChange: (Float) -> Unit,
     onRequestWindowColorMode: (Int) -> Unit,
@@ -300,6 +314,7 @@ fun PreviewDisplay(
                     .height(height)
                     .transformable(state = transformableState)
                     .alpha(imageAlpha)
+                    .clip(RoundedCornerShape(16.dp))
             ) {
                 CameraXViewfinder(
                     modifier = Modifier.fillMaxSize(),
@@ -308,7 +323,8 @@ fun PreviewDisplay(
                         Build.VERSION.SDK_INT > 24 -> ImplementationMode.EXTERNAL
                         else -> ImplementationMode.EMBEDDED
                     },
-                    onRequestWindowColorMode = onRequestWindowColorMode
+                    onRequestWindowColorMode = onRequestWindowColorMode,
+                    onTap = { x, y -> onTapToFocus(x, y) }
                 )
             }
         }
@@ -336,6 +352,28 @@ fun StabilizationIcon(
     }
 }
 
+/**
+ * LowLightBoostIcon has 3 states
+ * - disabled: hidden
+ * - enabled and inactive: outline
+ * - enabled and active: filled
+ */
+@Composable
+fun LowLightBoostIcon(lowLightBoost: LowLightBoost, modifier: Modifier = Modifier) {
+    when (lowLightBoost) {
+        LowLightBoost.ENABLED -> {
+            Icon(
+                imageVector = Icons.Outlined.Nightlight,
+                contentDescription =
+                stringResource(id = R.string.quick_settings_lowlightboost_enabled),
+                modifier = modifier.alpha(0.5f)
+            )
+        }
+        LowLightBoost.DISABLED -> {
+        }
+    }
+}
+
 /**
  * A temporary button that can be added to preview for quick testing purposes
  */
@@ -384,19 +422,40 @@ fun SettingsNavButton(onNavigateToSettings: () -> Unit, modifier: Modifier = Mod
 }
 
 @Composable
-fun ZoomScaleText(zoomScale: Float, modifier: Modifier = Modifier) {
+fun ZoomScaleText(zoomScale: Float) {
     val contentAlpha = animateFloatAsState(
         targetValue = 10f,
         label = "zoomScaleAlphaAnimation",
         animationSpec = tween()
     )
     Text(
-        modifier = Modifier.alpha(contentAlpha.value),
-        text = "%.1fx".format(zoomScale),
-        fontSize = 20.sp
+        modifier = Modifier
+            .alpha(contentAlpha.value)
+            .testTag(ZOOM_RATIO_TAG),
+        text = stringResource(id = R.string.zoom_scale_text, zoomScale)
     )
 }
 
+@Composable
+fun CurrentCameraIdText(physicalCameraId: String?, logicalCameraId: String?) {
+    Column(horizontalAlignment = Alignment.CenterHorizontally) {
+        Row {
+            Text(text = stringResource(R.string.debug_text_logical_camera_id_prefix))
+            Text(
+                modifier = Modifier.testTag(LOGICAL_CAMERA_ID_TAG),
+                text = logicalCameraId ?: "---"
+            )
+        }
+        Row {
+            Text(text = stringResource(R.string.debug_text_physical_camera_id_prefix))
+            Text(
+                modifier = Modifier.testTag(PHYSICAL_CAMERA_ID_TAG),
+                text = physicalCameraId ?: "---"
+            )
+        }
+    }
+}
+
 @Composable
 fun CaptureButton(
     onClick: () -> Unit,
@@ -455,9 +514,12 @@ enum class ToggleState {
 fun ToggleButton(
     leftIcon: Painter,
     rightIcon: Painter,
-    modifier: Modifier = Modifier.width(64.dp).height(32.dp),
+    modifier: Modifier = Modifier
+        .width(64.dp)
+        .height(32.dp),
     initialState: ToggleState = ToggleState.Left,
     onToggleStateChanged: (newState: ToggleState) -> Unit = {},
+    onToggleWhenDisabled: () -> Unit = {},
     enabled: Boolean = true,
     leftIconDescription: String = "leftIcon",
     rightIconDescription: String = "rightIcon",
@@ -483,18 +545,18 @@ fun ToggleButton(
         modifier = modifier
             .clip(shape = RoundedCornerShape(50))
             .then(
-                if (enabled) {
-                    Modifier.clickable {
-                        scope.launch {
+                Modifier.clickable {
+                    scope.launch {
+                        if (enabled) {
                             toggleState = when (toggleState) {
                                 ToggleState.Left -> ToggleState.Right
                                 ToggleState.Right -> ToggleState.Left
                             }
                             onToggleStateChanged(toggleState)
+                        } else {
+                            onToggleWhenDisabled()
                         }
                     }
-                } else {
-                    Modifier
                 }
             ),
         color = backgroundColor
@@ -521,9 +583,11 @@ fun ToggleButton(
                 )
             }
             Row(
-                modifier = Modifier.matchParentSize().then(
-                    if (enabled) Modifier else Modifier.alpha(0.38f)
-                ),
+                modifier = Modifier
+                    .matchParentSize()
+                    .then(
+                        if (enabled) Modifier else Modifier.alpha(0.38f)
+                    ),
                 verticalAlignment = Alignment.CenterVertically,
                 horizontalArrangement = Arrangement.SpaceBetween
             ) {
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
index 974619b..077a971 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
@@ -19,7 +19,23 @@ const val CAPTURE_BUTTON = "CaptureButton"
 const val FLIP_CAMERA_BUTTON = "FlipCameraButton"
 const val IMAGE_CAPTURE_SUCCESS_TAG = "ImageCaptureSuccessTag"
 const val IMAGE_CAPTURE_FAILURE_TAG = "ImageCaptureFailureTag"
-const val VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG = "ImageCaptureExternalUnsupportedTag"
+const val IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG = "ImageCaptureExternalUnsupportedTag"
+const val IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG =
+    "ImageCaptureUnsupportedConcurrentCameraTag"
+const val VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG = "VideoCaptureExternalUnsupportedTag"
+const val VIDEO_CAPTURE_SUCCESS_TAG = "VideoCaptureSuccessTag"
+const val VIDEO_CAPTURE_FAILURE_TAG = "VideoCaptureFailureTag"
 const val PREVIEW_DISPLAY = "PreviewDisplay"
 const val SCREEN_FLASH_OVERLAY = "ScreenFlashOverlay"
 const val SETTINGS_BUTTON = "SettingsButton"
+const val AMPLITUDE_NONE_TAG = "AmplitudeNoneTag"
+const val AMPLITUDE_HOT_TAG = "AmplitudeHotTag"
+const val HDR_IMAGE_UNSUPPORTED_ON_DEVICE_TAG = "HdrImageUnsupportedOnDeviceTag"
+const val HDR_IMAGE_UNSUPPORTED_ON_LENS_TAG = "HdrImageUnsupportedOnLensTag"
+const val HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG = "HdrImageUnsupportedOnSingleStreamTag"
+const val HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG = "HdrImageUnsupportedOnMultiStreamTag"
+const val HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG = "HdrVideoUnsupportedOnDeviceTag"
+const val HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG = "HdrVideoUnsupportedOnDeviceTag"
+const val ZOOM_RATIO_TAG = "ZoomRatioTag"
+const val LOGICAL_CAMERA_ID_TAG = "LogicalCameraIdTag"
+const val PHYSICAL_CAMERA_ID_TAG = "PhysicalCameraIdTag"
diff --git a/feature/preview/src/main/res/drawable/picture_in_picture_off_icon.xml b/feature/preview/src/main/res/drawable/picture_in_picture_off_icon.xml
new file mode 100644
index 0000000..3c394b1
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/picture_in_picture_off_icon.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector android:height="72dp" android:tint="#000000"
+    android:viewportHeight="960" android:viewportWidth="960"
+    android:width="72dp" xmlns:android="http://schemas.android.com/apk/res/android">
+    <path android:fillColor="@android:color/white" android:pathData="M700,520Q725,520 742.5,502.5Q760,485 760,460L760,340Q760,315 742.5,297.5Q725,280 700,280L480,280Q463,280 451.5,291.5Q440,303 440,320Q440,337 451.5,348.5Q463,360 480,360L680,360L680,360L680,440L640,440Q623,440 611.5,451.5Q600,463 600,480Q600,497 612,508.5Q624,520 641,520L700,520ZM840,720Q825,720 812.5,709.5Q800,699 800,679L800,240Q800,240 800,240Q800,240 800,240L361,240Q341,240 331,227.5Q321,215 321,200Q321,185 331,172.5Q341,160 361,160L800,160Q833,160 856.5,183.5Q880,207 880,240L880,680Q880,700 867.5,710Q855,720 840,720ZM577,463L577,463L577,463L577,463Q577,463 577,463Q577,463 577,463ZM383,497L383,497Q383,497 383,497Q383,497 383,497L383,497Q383,497 383,497Q383,497 383,497L383,497ZM790,903L686,800L160,800Q127,800 103.5,776.5Q80,753 80,720L80,240Q80,207 103.5,183.5Q127,160 160,160L160,160L240,240L160,240Q160,240 160,240Q160,240 160,240L160,720Q160,720 160,720Q160,720 160,720L606,720L54,168Q42,156 42,139.5Q42,123 54,111Q66,99 82.5,99Q99,99 111,111L847,847Q859,859 859,875Q859,891 847,903Q835,915 818.5,915Q802,915 790,903Z"/>
+</vector>
diff --git a/feature/preview/src/main/res/values/strings.xml b/feature/preview/src/main/res/values/strings.xml
index 3bf1eec..77d80e0 100644
--- a/feature/preview/src/main/res/values/strings.xml
+++ b/feature/preview/src/main/res/values/strings.xml
@@ -20,15 +20,28 @@
     <string name="flip_camera_content_description">Flip Camera</string>
 
     <string name="audio_visualizer_icon">An icon of a microphone</string>
+    <string name="zoom_scale_text">%1$.2fx</string>
+
+    <string name="debug_text_physical_camera_id_prefix">Physical ID: </string>
+    <string name="debug_text_logical_camera_id_prefix">Logical ID: </string>
 
     <string name="toast_image_capture_success">Image Capture Success</string>
     <string name="toast_video_capture_success">Video Capture Success</string>
 
     <string name="toast_capture_failure">Image Capture Failure</string>
     <string name="toast_video_capture_failure">Video Capture Failure</string>
-    <string name="toast_video_capture_external_unsupported">External video capture not supported</string>
+    <string name="toast_video_capture_external_unsupported">Video not supported while app is in image-only capture mode</string>
+    <string name="toast_image_capture_external_unsupported">Image capture not supported while app is in video-only capture mode</string>
+    <string name="toast_image_capture_unsupported_concurrent_camera">Image capture not supported in dual camera mode</string>
     <string name="stabilization_icon_description_preview_and_video">Preview is Stabilized</string>
     <string name="stabilization_icon_description_video_only">Only Video is Stabilized</string>
+    <string name="toast_hdr_photo_unsupported_on_device">Ultra HDR photos not supported on this device</string>
+    <string name="toast_hdr_photo_unsupported_on_lens">Ultra HDR photos not supported by current lens</string>
+    <string name="toast_hdr_photo_unsupported_on_lens_single_stream">Single-stream mode does not support UltraHDR photo capture for current lens</string>
+    <string name="toast_hdr_photo_unsupported_on_lens_multi_stream">Multi-stream mode does not support UltraHDR photo capture for current lens</string>
+    <string name="toast_hdr_video_unsupported_on_device">HDR video not supported on this device</string>
+    <string name="toast_hdr_video_unsupported_on_lens">HDR video not supported by current lens</string>
+
 
     <string name="quick_settings_front_camera_text">FRONT</string>
     <string name="quick_settings_back_camera_text">BACK</string>
@@ -40,9 +53,9 @@
     <string name="quick_settings_aspect_ratio_1_1">1:1</string>
 
     <string name="quick_settings_dynamic_range_sdr">SDR</string>
-    <string name="quick_settings_dynamic_range_hlg10">HLG10</string>
+    <string name="quick_settings_dynamic_range_hdr">HDR</string>
     <string name="quick_settings_dynamic_range_sdr_description">Standard dynamic range</string>
-    <string name="quick_settings_dynamic_range_hlg10_description">10-bit Hybrid Log Gamma dynamic range</string>
+    <string name="quick_settings_dynamic_range_hdr_description">High dynamic range</string>
 
     <string name="quick_settings_aspect_ratio_3_4_description">3 to 4 aspect ratio</string>
     <string name="quick_settings_aspect_ratio_9_16_description">9 to 16 aspect ratio</string>
@@ -62,4 +75,14 @@
 
     <string name="quick_settings_dropdown_open_description">Quick settings open</string>
     <string name="quick_settings_dropdown_closed_description">Quick settings closed</string>
+
+    <string name="quick_settings_lowlightboost_enabled">Low light boost on</string>
+    <string name="quick_settings_lowlightboost_disabled">Low light boost off</string>
+    <string name="quick_settings_lowlightboost_enabled_description">Low light boost on</string>
+    <string name="quick_settings_lowlightboost_disabled_description">Low light boost off</string>
+
+    <string name="quick_settings_concurrent_camera_off">SINGLE</string>
+    <string name="quick_settings_concurrent_camera_dual">DUAL</string>
+    <string name="quick_settings_concurrent_camera_off_description">Concurrent cameras off</string>
+    <string name="quick_settings_concurrent_camera_dual_description">Concurrent dual camera on</string>
 </resources>
diff --git a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
index 1f515c6..2d40334 100644
--- a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
+++ b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
@@ -17,11 +17,12 @@ package com.google.jetpackcamera.feature.preview
 
 import android.content.ContentResolver
 import com.google.common.truth.Truth.assertThat
-import com.google.jetpackcamera.domain.camera.test.FakeCameraUseCase
+import com.google.jetpackcamera.core.camera.test.FakeCameraUseCase
 import com.google.jetpackcamera.settings.SettableConstraintsRepositoryImpl
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
+import com.google.jetpackcamera.settings.test.FakeSettingsRepository
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.test.StandardTestDispatcher
@@ -47,8 +48,10 @@ class PreviewViewModelTest {
         Dispatchers.setMain(StandardTestDispatcher())
         previewViewModel = PreviewViewModel(
             PreviewMode.StandardMode {},
-            cameraUseCase,
-            constraintsRepository
+            false,
+            cameraUseCase = cameraUseCase,
+            constraintsRepository = constraintsRepository,
+            settingsRepository = FakeSettingsRepository
         )
         advanceUntilIdle()
     }
@@ -87,7 +90,7 @@ class PreviewViewModelTest {
     @Test
     fun startVideoRecording() = runTest(StandardTestDispatcher()) {
         previewViewModel.startCameraUntilRunning()
-        previewViewModel.startVideoRecording()
+        previewViewModel.startVideoRecording(null, false) {}
         advanceUntilIdle()
         assertThat(cameraUseCase.recordingInProgress).isTrue()
     }
@@ -95,7 +98,7 @@ class PreviewViewModelTest {
     @Test
     fun stopVideoRecording() = runTest(StandardTestDispatcher()) {
         previewViewModel.startCameraUntilRunning()
-        previewViewModel.startVideoRecording()
+        previewViewModel.startVideoRecording(null, false) {}
         advanceUntilIdle()
         previewViewModel.stopVideoRecording()
         assertThat(cameraUseCase.recordingInProgress).isFalse()
diff --git a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt
index ea8b395..536e90e 100644
--- a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt
+++ b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt
@@ -17,9 +17,10 @@ package com.google.jetpackcamera.feature.preview
 
 import android.content.ContentResolver
 import com.google.common.truth.Truth.assertThat
-import com.google.jetpackcamera.domain.camera.CameraUseCase
-import com.google.jetpackcamera.domain.camera.test.FakeCameraUseCase
+import com.google.jetpackcamera.core.camera.CameraUseCase
+import com.google.jetpackcamera.core.camera.test.FakeCameraUseCase
 import com.google.jetpackcamera.feature.preview.rules.MainDispatcherRule
+import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import kotlinx.coroutines.ExperimentalCoroutinesApi
@@ -43,7 +44,7 @@ class ScreenFlashTest {
     @get:Rule
     val mainDispatcherRule = MainDispatcherRule(testDispatcher)
 
-    private val cameraUseCase = FakeCameraUseCase(testScope)
+    private val cameraUseCase = FakeCameraUseCase()
     private lateinit var screenFlash: ScreenFlash
 
     @Before
@@ -109,7 +110,10 @@ class ScreenFlashTest {
 
     private fun runCameraTest(testBody: suspend TestScope.() -> Unit) = runTest(testDispatcher) {
         backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
-            cameraUseCase.initialize(false)
+            cameraUseCase.initialize(
+                DEFAULT_CAMERA_APP_SETTINGS,
+                CameraUseCase.UseCaseMode.STANDARD
+            )
             cameraUseCase.runCamera()
         }
 
diff --git a/feature/settings/build.gradle.kts b/feature/settings/build.gradle.kts
index 2bb1842..0be4f1b 100644
--- a/feature/settings/build.gradle.kts
+++ b/feature/settings/build.gradle.kts
@@ -24,6 +24,7 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.settings"
     compileSdk = libs.versions.compileSdk.get().toInt()
+    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -33,6 +34,19 @@ android {
         testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
     }
 
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+
+        create("preview") {
+            dimension = "flavor"
+            targetSdkPreview = libs.versions.targetSdkPreview.get()
+        }
+    }
+
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_17
         targetCompatibility = JavaVersion.VERSION_17
diff --git a/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt b/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt
index ae1a0b0..dbbc72b 100644
--- a/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt
+++ b/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt
@@ -22,7 +22,6 @@ import androidx.datastore.dataStoreFile
 import androidx.test.core.app.ApplicationProvider
 import androidx.test.platform.app.InstrumentationRegistry
 import com.google.common.truth.Truth.assertThat
-import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
@@ -85,10 +84,7 @@ internal class CameraAppSettingsViewModelTest {
         }
 
         assertThat(uiState).isEqualTo(
-            SettingsUiState.Enabled(
-                cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
-                systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS
-            )
+            TYPICAL_SETTINGS_UISTATE
         )
     }
 
@@ -99,8 +95,8 @@ internal class CameraAppSettingsViewModelTest {
             it is SettingsUiState.Enabled
         }
 
-        val initialCameraLensFacing = assertIsEnabled(initialState)
-            .cameraAppSettings.cameraLensFacing
+        val initialCameraLensFacing =
+            assertIsEnabled(initialState).lensFlipUiState.currentLensFacing
         val nextCameraLensFacing = if (initialCameraLensFacing == LensFacing.FRONT) {
             LensFacing.BACK
         } else {
@@ -111,7 +107,7 @@ internal class CameraAppSettingsViewModelTest {
         advanceUntilIdle()
 
         assertIsEnabled(settingsViewModel.settingsUiState.value).also {
-            assertThat(it.cameraAppSettings.cameraLensFacing).isEqualTo(nextCameraLensFacing)
+            assertThat(it.lensFlipUiState.currentLensFacing).isEqualTo(nextCameraLensFacing)
         }
     }
 
@@ -122,14 +118,20 @@ internal class CameraAppSettingsViewModelTest {
             it is SettingsUiState.Enabled
         }
 
-        val initialDarkMode = assertIsEnabled(initialState).cameraAppSettings.darkMode
+        val initialDarkMode =
+            (assertIsEnabled(initialState).darkModeUiState as DarkModeUiState.Enabled)
+                .currentDarkMode
 
         settingsViewModel.setDarkMode(DarkMode.DARK)
 
         advanceUntilIdle()
 
-        val newDarkMode = assertIsEnabled(settingsViewModel.settingsUiState.value)
-            .cameraAppSettings.darkMode
+        val newDarkMode =
+            (
+                assertIsEnabled(settingsViewModel.settingsUiState.value)
+                    .darkModeUiState as DarkModeUiState.Enabled
+                )
+                .currentDarkMode
 
         assertEquals(initialDarkMode, DarkMode.SYSTEM)
         assertEquals(DarkMode.DARK, newDarkMode)
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt
index d5ebc0e..a3ab00e 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt
@@ -30,12 +30,10 @@ import androidx.compose.ui.tooling.preview.Preview
 import androidx.hilt.navigation.compose.hiltViewModel
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
-import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.Stabilization
-import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
 import com.google.jetpackcamera.settings.ui.AspectRatioSetting
 import com.google.jetpackcamera.settings.ui.CaptureModeSetting
 import com.google.jetpackcamera.settings.ui.DarkModeSetting
@@ -130,47 +128,32 @@ fun SettingsList(
     SectionHeader(title = stringResource(id = R.string.section_title_camera_settings))
 
     DefaultCameraFacing(
-        settingValue = (uiState.cameraAppSettings.cameraLensFacing == LensFacing.FRONT),
-        enabled = with(uiState.systemConstraints.availableLenses) {
-            size > 1 && contains(LensFacing.FRONT)
-        },
+        lensUiState = uiState.lensFlipUiState,
         setDefaultLensFacing = setDefaultLensFacing
     )
 
     FlashModeSetting(
-        currentFlashMode = uiState.cameraAppSettings.flashMode,
+        flashUiState = uiState.flashUiState,
         setFlashMode = setFlashMode
     )
 
     TargetFpsSetting(
-        currentTargetFps = uiState.cameraAppSettings.targetFrameRate,
-        supportedFps = uiState.systemConstraints.perLensConstraints.values.fold(emptySet()) {
-                union, constraints ->
-            union + constraints.supportedFixedFrameRates
-        },
+        fpsUiState = uiState.fpsUiState,
         setTargetFps = setTargetFrameRate
     )
 
     AspectRatioSetting(
-        currentAspectRatio = uiState.cameraAppSettings.aspectRatio,
+        aspectRatioUiState = uiState.aspectRatioUiState,
         setAspectRatio = setAspectRatio
     )
 
     CaptureModeSetting(
-        currentCaptureMode = uiState.cameraAppSettings.captureMode,
+        captureModeUiState = uiState.captureModeUiState,
         setCaptureMode = setCaptureMode
     )
 
     StabilizationSetting(
-        currentVideoStabilization = uiState.cameraAppSettings.videoCaptureStabilization,
-        currentPreviewStabilization = uiState.cameraAppSettings.previewStabilization,
-        currentTargetFps = uiState.cameraAppSettings.targetFrameRate,
-        supportedStabilizationMode = uiState.systemConstraints.perLensConstraints.values.fold(
-            emptySet()
-        ) {
-                union, constraints ->
-            union + constraints.supportedStabilizationModes
-        },
+        stabilizationUiState = uiState.stabilizationUiState,
         setVideoStabilization = setVideoStabilization,
         setPreviewStabilization = setPreviewStabilization
     )
@@ -178,7 +161,7 @@ fun SettingsList(
     SectionHeader(title = stringResource(id = R.string.section_title_app_settings))
 
     DarkModeSetting(
-        currentDarkMode = uiState.cameraAppSettings.darkMode,
+        darkModeUiState = uiState.darkModeUiState,
         setDarkMode = setDarkMode
     )
 
@@ -190,6 +173,8 @@ fun SettingsList(
     )
 }
 
+// will allow you to open stabilization popup or give disabled rationale
+
 data class VersionInfoHolder(
     val versionName: String,
     val buildType: String
@@ -201,10 +186,7 @@ data class VersionInfoHolder(
 private fun Preview_SettingsScreen() {
     SettingsPreviewTheme {
         SettingsScreen(
-            uiState = SettingsUiState.Enabled(
-                DEFAULT_CAMERA_APP_SETTINGS,
-                TYPICAL_SYSTEM_CONSTRAINTS
-            ),
+            uiState = TYPICAL_SETTINGS_UISTATE,
             versionInfo = VersionInfoHolder(
                 versionName = "1.0.0",
                 buildType = "release"
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt
index 13cf5f0..7f882c3 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt
@@ -15,16 +15,199 @@
  */
 package com.google.jetpackcamera.settings
 
-import com.google.jetpackcamera.settings.model.CameraAppSettings
-import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.DisabledRationale.DeviceUnsupportedRationale
+import com.google.jetpackcamera.settings.DisabledRationale.LensUnsupportedRationale
+import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
+import com.google.jetpackcamera.settings.model.DarkMode
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.ui.DEVICE_UNSUPPORTED_TAG
+import com.google.jetpackcamera.settings.ui.FPS_UNSUPPORTED_TAG
+import com.google.jetpackcamera.settings.ui.LENS_UNSUPPORTED_TAG
+import com.google.jetpackcamera.settings.ui.STABILIZATION_UNSUPPORTED_TAG
 
 /**
  * Defines the current state of the [SettingsScreen].
  */
 sealed interface SettingsUiState {
-    object Disabled : SettingsUiState
+    data object Disabled : SettingsUiState
     data class Enabled(
-        val cameraAppSettings: CameraAppSettings,
-        val systemConstraints: SystemConstraints
+        val aspectRatioUiState: AspectRatioUiState,
+        val captureModeUiState: CaptureModeUiState,
+        val darkModeUiState: DarkModeUiState,
+        val flashUiState: FlashUiState,
+        val fpsUiState: FpsUiState,
+        val lensFlipUiState: FlipLensUiState,
+        val stabilizationUiState: StabilizationUiState
     ) : SettingsUiState
 }
+
+/** State for the individual options on Popup dialog settings */
+sealed interface SingleSelectableState {
+    data object Selectable : SingleSelectableState
+    data class Disabled(val disabledRationale: DisabledRationale) : SingleSelectableState
+}
+
+/** Contains information on why a setting is disabled */
+// TODO(b/360921588): Display information on UI regarding disabled rationale
+sealed interface DisabledRationale {
+    val affectedSettingNameResId: Int
+    val reasonTextResId: Int
+    val testTag: String
+
+    /**
+     * Text will be [affectedSettingNameResId] is [R.string.device_unsupported]
+     */
+    data class DeviceUnsupportedRationale(override val affectedSettingNameResId: Int) :
+        DisabledRationale {
+        override val reasonTextResId: Int = R.string.device_unsupported
+        override val testTag = DEVICE_UNSUPPORTED_TAG
+    }
+
+    data class FpsUnsupportedRationale(
+        override val affectedSettingNameResId: Int,
+        val currentFps: Int
+    ) : DisabledRationale {
+        override val reasonTextResId: Int = R.string.fps_unsupported
+        override val testTag = FPS_UNSUPPORTED_TAG
+    }
+
+    data class StabilizationUnsupportedRationale(override val affectedSettingNameResId: Int) :
+        DisabledRationale {
+        override val reasonTextResId = R.string.stabilization_unsupported
+        override val testTag = STABILIZATION_UNSUPPORTED_TAG
+    }
+
+    sealed interface LensUnsupportedRationale : DisabledRationale {
+        data class FrontLensUnsupportedRationale(override val affectedSettingNameResId: Int) :
+            LensUnsupportedRationale {
+            override val reasonTextResId: Int = R.string.front_lens_unsupported
+            override val testTag = LENS_UNSUPPORTED_TAG
+        }
+
+        data class RearLensUnsupportedRationale(override val affectedSettingNameResId: Int) :
+            LensUnsupportedRationale {
+            override val reasonTextResId: Int = R.string.rear_lens_unsupported
+            override val testTag = LENS_UNSUPPORTED_TAG
+        }
+    }
+}
+
+fun getLensUnsupportedRationale(
+    lensFacing: LensFacing,
+    affectedSettingNameResId: Int
+): LensUnsupportedRationale {
+    return when (lensFacing) {
+        LensFacing.BACK -> LensUnsupportedRationale.RearLensUnsupportedRationale(
+            affectedSettingNameResId
+        )
+
+        LensFacing.FRONT -> LensUnsupportedRationale.FrontLensUnsupportedRationale(
+            affectedSettingNameResId
+        )
+    }
+}
+
+/* Settings that currently have constraints **/
+
+sealed interface FpsUiState {
+    data class Enabled(
+        val currentSelection: Int,
+        val fpsAutoState: SingleSelectableState,
+        val fpsFifteenState: SingleSelectableState,
+        val fpsThirtyState: SingleSelectableState,
+        val fpsSixtyState: SingleSelectableState,
+        // Contains text like "Selected FPS only supported by rear lens"
+        val additionalContext: String = ""
+    ) : FpsUiState
+
+    // FPS selection completely disabled. Cannot open dialog.
+    data class Disabled(val disabledRationale: DisabledRationale) : FpsUiState
+}
+
+sealed interface FlipLensUiState {
+    val currentLensFacing: LensFacing
+
+    data class Enabled(
+        override val currentLensFacing: LensFacing
+    ) : FlipLensUiState
+
+    data class Disabled(
+        override val currentLensFacing: LensFacing,
+        val disabledRationale: DisabledRationale
+    ) : FlipLensUiState
+}
+
+sealed interface StabilizationUiState {
+    data class Enabled(
+        val currentPreviewStabilization: Stabilization,
+        val currentVideoStabilization: Stabilization,
+        val stabilizationOnState: SingleSelectableState,
+        val stabilizationHighQualityState: SingleSelectableState,
+        // Contains text like "Selected stabilization mode only supported by rear lens"
+        val additionalContext: String = ""
+    ) : StabilizationUiState
+
+    // Stabilization selection completely disabled. Cannot open dialog.
+    data class Disabled(val disabledRationale: DisabledRationale) : StabilizationUiState
+}
+
+/* Settings that don't currently depend on constraints */
+
+// this could be constrained w/ a check to see if a torch is available?
+sealed interface FlashUiState {
+    data class Enabled(
+        val currentFlashMode: FlashMode,
+        val additionalContext: String = ""
+    ) : FlashUiState
+}
+
+sealed interface AspectRatioUiState {
+    data class Enabled(
+        val currentAspectRatio: AspectRatio,
+        val additionalContext: String = ""
+    ) : AspectRatioUiState
+}
+
+sealed interface CaptureModeUiState {
+    data class Enabled(
+        val currentCaptureMode: CaptureMode,
+        val additionalContext: String = ""
+    ) : CaptureModeUiState
+}
+
+sealed interface DarkModeUiState {
+    data class Enabled(
+        val currentDarkMode: DarkMode,
+        val additionalContext: String = ""
+    ) : DarkModeUiState
+}
+
+/**
+ * Settings Ui State for testing, based on Typical System Constraints.
+ * @see[com.google.jetpackcamera.settings.model.SystemConstraints]
+ */
+val TYPICAL_SETTINGS_UISTATE = SettingsUiState.Enabled(
+    aspectRatioUiState = AspectRatioUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.aspectRatio),
+    captureModeUiState = CaptureModeUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.captureMode),
+    darkModeUiState = DarkModeUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.darkMode),
+    flashUiState =
+    FlashUiState.Enabled(currentFlashMode = DEFAULT_CAMERA_APP_SETTINGS.flashMode),
+    fpsUiState = FpsUiState.Enabled(
+        currentSelection = DEFAULT_CAMERA_APP_SETTINGS.targetFrameRate,
+        fpsAutoState = SingleSelectableState.Selectable,
+        fpsFifteenState = SingleSelectableState.Selectable,
+        fpsThirtyState = SingleSelectableState.Selectable,
+        fpsSixtyState = SingleSelectableState.Disabled(
+            DeviceUnsupportedRationale(R.string.fps_rationale_prefix)
+        )
+    ),
+    lensFlipUiState = FlipLensUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.cameraLensFacing),
+    stabilizationUiState =
+    StabilizationUiState.Disabled(
+        DeviceUnsupportedRationale(R.string.stabilization_rationale_prefix)
+    )
+)
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
index ea8caf7..43e7a50 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
@@ -18,12 +18,22 @@ package com.google.jetpackcamera.settings
 import android.util.Log
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import com.google.jetpackcamera.settings.DisabledRationale.DeviceUnsupportedRationale
+import com.google.jetpackcamera.settings.DisabledRationale.FpsUnsupportedRationale
+import com.google.jetpackcamera.settings.DisabledRationale.StabilizationUnsupportedRationale
 import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.SupportedStabilizationMode
+import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.ui.FPS_15
+import com.google.jetpackcamera.settings.ui.FPS_30
+import com.google.jetpackcamera.settings.ui.FPS_60
+import com.google.jetpackcamera.settings.ui.FPS_AUTO
 import dagger.hilt.android.lifecycle.HiltViewModel
 import javax.inject.Inject
 import kotlinx.coroutines.flow.SharingStarted
@@ -34,6 +44,7 @@ import kotlinx.coroutines.flow.stateIn
 import kotlinx.coroutines.launch
 
 private const val TAG = "SettingsViewModel"
+private val fpsOptions = setOf(FPS_15, FPS_30, FPS_60)
 
 /**
  * [ViewModel] for [SettingsScreen].
@@ -50,8 +61,14 @@ class SettingsViewModel @Inject constructor(
             constraintsRepository.systemConstraints.filterNotNull()
         ) { updatedSettings, constraints ->
             SettingsUiState.Enabled(
-                cameraAppSettings = updatedSettings,
-                systemConstraints = constraints
+                aspectRatioUiState = AspectRatioUiState.Enabled(updatedSettings.aspectRatio),
+                captureModeUiState = CaptureModeUiState.Enabled(updatedSettings.captureMode),
+                darkModeUiState = DarkModeUiState.Enabled(updatedSettings.darkMode),
+                flashUiState = FlashUiState.Enabled(updatedSettings.flashMode),
+                fpsUiState = getFpsUiState(constraints, updatedSettings),
+                lensFlipUiState = getLensFlipUiState(constraints, updatedSettings),
+                stabilizationUiState = getStabilizationUiState(constraints, updatedSettings)
+
             )
         }.stateIn(
             scope = viewModelScope,
@@ -59,6 +76,317 @@ class SettingsViewModel @Inject constructor(
             initialValue = SettingsUiState.Disabled
         )
 
+    private fun getStabilizationUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings
+    ): StabilizationUiState {
+        val deviceStabilizations: Set<SupportedStabilizationMode> =
+            systemConstraints
+                .perLensConstraints[cameraAppSettings.cameraLensFacing]
+                ?.supportedStabilizationModes
+                ?: emptySet()
+
+        // if no lens supports
+        if (deviceStabilizations.isEmpty()) {
+            return StabilizationUiState.Disabled(
+                DeviceUnsupportedRationale(
+                    R.string.stabilization_rationale_prefix
+                )
+            )
+        }
+
+        // if a lens supports but it isn't the current
+        if (systemConstraints.perLensConstraints[cameraAppSettings.cameraLensFacing]
+                ?.supportedStabilizationModes?.isEmpty() == true
+        ) {
+            return StabilizationUiState.Disabled(
+                getLensUnsupportedRationale(
+                    cameraAppSettings.cameraLensFacing,
+                    R.string.stabilization_rationale_prefix
+                )
+            )
+        }
+
+        // if fps is too high for any stabilization
+        if (cameraAppSettings.targetFrameRate >= TARGET_FPS_60) {
+            return StabilizationUiState.Disabled(
+                FpsUnsupportedRationale(
+                    R.string.stabilization_rationale_prefix,
+                    FPS_60
+                )
+            )
+        }
+
+        return StabilizationUiState.Enabled(
+            currentPreviewStabilization = cameraAppSettings.previewStabilization,
+            currentVideoStabilization = cameraAppSettings.videoCaptureStabilization,
+            stabilizationOnState = getPreviewStabilizationState(
+                currentFrameRate = cameraAppSettings.targetFrameRate,
+                defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                deviceStabilizations = deviceStabilizations,
+                currentLensStabilizations = systemConstraints
+                    .perLensConstraints[cameraAppSettings.cameraLensFacing]
+                    ?.supportedStabilizationModes
+            ),
+            stabilizationHighQualityState =
+            getVideoStabilizationState(
+                currentFrameRate = cameraAppSettings.targetFrameRate,
+                deviceStabilizations = deviceStabilizations,
+                defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                currentLensStabilizations = systemConstraints
+                    .perLensConstraints[cameraAppSettings.cameraLensFacing]
+                    ?.supportedStabilizationModes
+            )
+        )
+    }
+
+    private fun getPreviewStabilizationState(
+        currentFrameRate: Int,
+        defaultLensFacing: LensFacing,
+        deviceStabilizations: Set<SupportedStabilizationMode>,
+        currentLensStabilizations: Set<SupportedStabilizationMode>?
+    ): SingleSelectableState {
+        // if unsupported by device
+        if (!deviceStabilizations.contains(SupportedStabilizationMode.ON)) {
+            return SingleSelectableState.Disabled(
+                disabledRationale =
+                DeviceUnsupportedRationale(R.string.stabilization_rationale_prefix)
+            )
+        }
+
+        // if unsupported by by current lens
+        if (currentLensStabilizations?.contains(SupportedStabilizationMode.ON) == false) {
+            return SingleSelectableState.Disabled(
+                getLensUnsupportedRationale(
+                    defaultLensFacing,
+                    R.string.stabilization_rationale_prefix
+                )
+            )
+        }
+
+        // if fps is unsupported by preview stabilization
+        if (currentFrameRate == TARGET_FPS_60 || currentFrameRate == TARGET_FPS_15) {
+            return SingleSelectableState.Disabled(
+                FpsUnsupportedRationale(
+                    R.string.stabilization_rationale_prefix,
+                    currentFrameRate
+                )
+            )
+        }
+
+        return SingleSelectableState.Selectable
+    }
+
+    private fun getVideoStabilizationState(
+        currentFrameRate: Int,
+        defaultLensFacing: LensFacing,
+        deviceStabilizations: Set<SupportedStabilizationMode>,
+        currentLensStabilizations: Set<SupportedStabilizationMode>?
+    ): SingleSelectableState {
+        // if unsupported by device
+        if (!deviceStabilizations.contains(SupportedStabilizationMode.ON)) {
+            return SingleSelectableState.Disabled(
+                disabledRationale =
+                DeviceUnsupportedRationale(R.string.stabilization_rationale_prefix)
+            )
+        }
+
+        // if unsupported by by current lens
+        if (currentLensStabilizations?.contains(SupportedStabilizationMode.HIGH_QUALITY) == false) {
+            return SingleSelectableState.Disabled(
+                getLensUnsupportedRationale(
+                    defaultLensFacing,
+                    R.string.stabilization_rationale_prefix
+                )
+            )
+        }
+        // if fps is unsupported by preview stabilization
+        if (currentFrameRate == TARGET_FPS_60) {
+            return SingleSelectableState.Disabled(
+                FpsUnsupportedRationale(
+                    R.string.stabilization_rationale_prefix,
+                    currentFrameRate
+                )
+            )
+        }
+
+        return SingleSelectableState.Selectable
+    }
+
+    /**
+     * Enables or disables default camera switch based on:
+     * - number of cameras available
+     * - if there is a front and rear camera, the camera that the setting would switch to must also
+     * support the other settings
+     * */
+    private fun getLensFlipUiState(
+        systemConstraints: SystemConstraints,
+        currentSettings: CameraAppSettings
+    ): FlipLensUiState {
+        // if there is only one lens, stop here
+        if (!with(systemConstraints.availableLenses) {
+                size > 1 && contains(com.google.jetpackcamera.settings.model.LensFacing.FRONT)
+            }
+        ) {
+            return FlipLensUiState.Disabled(
+                currentLensFacing = currentSettings.cameraLensFacing,
+                disabledRationale =
+                DeviceUnsupportedRationale(
+                    // display the lens that isnt supported
+                    when (currentSettings.cameraLensFacing) {
+                        LensFacing.BACK -> R.string.front_lens_rationale_prefix
+                        LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
+                    }
+                )
+            )
+        }
+
+        // If multiple lens available, continue
+        val newLensFacing = if (currentSettings.cameraLensFacing == LensFacing.FRONT) {
+            LensFacing.BACK
+        } else {
+            LensFacing.FRONT
+        }
+        val newLensConstraints = systemConstraints.perLensConstraints[newLensFacing]!!
+        // make sure all current settings wont break constraint when changing new default lens
+
+        // if new lens won't support current fps
+        if (currentSettings.targetFrameRate != FPS_AUTO &&
+            !newLensConstraints.supportedFixedFrameRates
+                .contains(currentSettings.targetFrameRate)
+        ) {
+            return FlipLensUiState.Disabled(
+                currentLensFacing = currentSettings.cameraLensFacing,
+                disabledRationale = FpsUnsupportedRationale(
+                    when (currentSettings.cameraLensFacing) {
+                        LensFacing.BACK -> R.string.front_lens_rationale_prefix
+                        LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
+                    },
+                    currentSettings.targetFrameRate
+                )
+            )
+        }
+
+        // if preview stabilization is currently on and the other lens won't support it
+        if (currentSettings.previewStabilization == Stabilization.ON) {
+            if (!newLensConstraints.supportedStabilizationModes.contains(
+                    SupportedStabilizationMode.ON
+                )
+            ) {
+                return FlipLensUiState.Disabled(
+                    currentLensFacing = currentSettings.cameraLensFacing,
+                    disabledRationale = StabilizationUnsupportedRationale(
+                        when (currentSettings.cameraLensFacing) {
+                            LensFacing.BACK -> R.string.front_lens_rationale_prefix
+                            LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
+                        }
+                    )
+                )
+            }
+        }
+        // if video stabilization is currently on and the other lens won't support it
+        if (currentSettings.videoCaptureStabilization == Stabilization.ON) {
+            if (!newLensConstraints.supportedStabilizationModes
+                    .contains(SupportedStabilizationMode.HIGH_QUALITY)
+            ) {
+                return FlipLensUiState.Disabled(
+                    currentLensFacing = currentSettings.cameraLensFacing,
+                    disabledRationale = StabilizationUnsupportedRationale(
+                        when (currentSettings.cameraLensFacing) {
+                            LensFacing.BACK -> R.string.front_lens_rationale_prefix
+                            LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
+                        }
+                    )
+                )
+            }
+        }
+
+        return FlipLensUiState.Enabled(currentLensFacing = currentSettings.cameraLensFacing)
+    }
+
+    private fun getFpsUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings
+    ): FpsUiState {
+        val optionConstraintRationale: MutableMap<Int, SingleSelectableState> = mutableMapOf()
+
+        val currentLensFrameRates: Set<Int> = systemConstraints
+            .perLensConstraints[cameraAppSettings.cameraLensFacing]
+            ?.supportedFixedFrameRates ?: emptySet()
+
+        // if device supports no fixed frame rates, disable
+        if (currentLensFrameRates.isEmpty()) {
+            return FpsUiState.Disabled(
+                DeviceUnsupportedRationale(R.string.no_fixed_fps_rationale_prefix)
+            )
+        }
+
+        // provide selectable states for each of the fps options
+        fpsOptions.forEach { fpsOption ->
+            val fpsUiState = isFpsOptionEnabled(
+                fpsOption,
+                cameraAppSettings.cameraLensFacing,
+                currentLensFrameRates,
+                systemConstraints.perLensConstraints[cameraAppSettings.cameraLensFacing]
+                    ?.supportedFixedFrameRates ?: emptySet(),
+                cameraAppSettings.previewStabilization,
+                cameraAppSettings.videoCaptureStabilization
+            )
+            if (fpsUiState is SingleSelectableState.Disabled) {
+                Log.d(TAG, "fps option $fpsOption disabled. ${fpsUiState.disabledRationale::class}")
+            }
+            optionConstraintRationale[fpsOption] = fpsUiState
+        }
+        return FpsUiState.Enabled(
+            currentSelection = cameraAppSettings.targetFrameRate,
+            fpsAutoState = SingleSelectableState.Selectable,
+            fpsFifteenState = optionConstraintRationale[FPS_15]!!,
+            fpsThirtyState = optionConstraintRationale[FPS_30]!!,
+            fpsSixtyState = optionConstraintRationale[FPS_60]!!
+        )
+    }
+
+    /**
+     * Auxiliary function to determine if an FPS option should be disabled or not
+     */
+    private fun isFpsOptionEnabled(
+        fpsOption: Int,
+        defaultLensFacing: LensFacing,
+        deviceFrameRates: Set<Int>,
+        lensFrameRates: Set<Int>,
+        previewStabilization: Stabilization,
+        videoStabilization: Stabilization
+    ): SingleSelectableState {
+        // if device doesnt support the fps option, disable
+        if (!deviceFrameRates.contains(fpsOption)) {
+            return SingleSelectableState.Disabled(
+                disabledRationale = DeviceUnsupportedRationale(R.string.fps_rationale_prefix)
+            )
+        }
+        // if the current lens doesnt support the fps, disable
+        if (!lensFrameRates.contains(fpsOption)) {
+            Log.d(TAG, "FPS disabled for current lens")
+
+            return SingleSelectableState.Disabled(
+                getLensUnsupportedRationale(defaultLensFacing, R.string.fps_rationale_prefix)
+            )
+        }
+
+        // if stabilization is on and the option is incompatible, disable
+        if ((
+                previewStabilization == Stabilization.ON &&
+                    (fpsOption == FPS_15 || fpsOption == FPS_60)
+                ) ||
+            (videoStabilization == Stabilization.ON && fpsOption == FPS_60)
+        ) {
+            return SingleSelectableState.Disabled(
+                StabilizationUnsupportedRationale(R.string.fps_rationale_prefix)
+            )
+        }
+
+        return SingleSelectableState.Selectable
+    }
+
     fun setDefaultLensFacing(lensFacing: LensFacing) {
         viewModelScope.launch {
             settingsRepository.updateDefaultLensFacing(lensFacing)
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
index 559f24f..e8c02fb 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
@@ -38,7 +38,7 @@ import androidx.compose.material3.Switch
 import androidx.compose.material3.Text
 import androidx.compose.material3.TopAppBar
 import androidx.compose.runtime.Composable
-import androidx.compose.runtime.LaunchedEffect
+import androidx.compose.runtime.ReadOnlyComposable
 import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.remember
 import androidx.compose.ui.Alignment
@@ -52,14 +52,22 @@ import androidx.compose.ui.text.toUpperCase
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.dp
 import androidx.compose.ui.unit.sp
+import com.google.jetpackcamera.settings.AspectRatioUiState
+import com.google.jetpackcamera.settings.CaptureModeUiState
+import com.google.jetpackcamera.settings.DarkModeUiState
+import com.google.jetpackcamera.settings.DisabledRationale
+import com.google.jetpackcamera.settings.FlashUiState
+import com.google.jetpackcamera.settings.FlipLensUiState
+import com.google.jetpackcamera.settings.FpsUiState
 import com.google.jetpackcamera.settings.R
+import com.google.jetpackcamera.settings.SingleSelectableState
+import com.google.jetpackcamera.settings.StabilizationUiState
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.Stabilization
-import com.google.jetpackcamera.settings.model.SupportedStabilizationMode
 import com.google.jetpackcamera.settings.ui.theme.SettingsPreviewTheme
 
 const val FPS_AUTO = 0
@@ -107,27 +115,38 @@ fun SectionHeader(title: String, modifier: Modifier = Modifier) {
 
 @Composable
 fun DefaultCameraFacing(
-    settingValue: Boolean,
-    enabled: Boolean,
-    setDefaultLensFacing: (LensFacing) -> Unit,
-    modifier: Modifier = Modifier
+    modifier: Modifier = Modifier,
+    lensUiState: FlipLensUiState,
+    setDefaultLensFacing: (LensFacing) -> Unit
 ) {
     SwitchSettingUI(
-        modifier = modifier,
+        modifier = modifier.apply {
+            if (lensUiState is FlipLensUiState.Disabled) {
+                testTag(lensUiState.disabledRationale.testTag)
+            }
+        },
         title = stringResource(id = R.string.default_facing_camera_title),
-        description = null,
+        description = when (lensUiState) {
+            is FlipLensUiState.Disabled -> {
+                disabledRationaleString(disabledRationale = lensUiState.disabledRationale)
+            }
+
+            is FlipLensUiState.Enabled -> {
+                null
+            }
+        },
         leadingIcon = null,
         onSwitchChanged = { on ->
             setDefaultLensFacing(if (on) LensFacing.FRONT else LensFacing.BACK)
         },
-        settingValue = settingValue,
-        enabled = enabled
+        settingValue = lensUiState.currentLensFacing == LensFacing.FRONT,
+        enabled = lensUiState is FlipLensUiState.Enabled
     )
 }
 
 @Composable
 fun DarkModeSetting(
-    currentDarkMode: DarkMode,
+    darkModeUiState: DarkModeUiState,
     setDarkMode: (DarkMode) -> Unit,
     modifier: Modifier = Modifier
 ) {
@@ -135,26 +154,34 @@ fun DarkModeSetting(
         modifier = modifier,
         title = stringResource(id = R.string.dark_mode_title),
         leadingIcon = null,
-        description = when (currentDarkMode) {
-            DarkMode.SYSTEM -> stringResource(id = R.string.dark_mode_description_system)
-            DarkMode.DARK -> stringResource(id = R.string.dark_mode_description_dark)
-            DarkMode.LIGHT -> stringResource(id = R.string.dark_mode_description_light)
+        enabled = true,
+        description = when (darkModeUiState) {
+            is DarkModeUiState.Enabled -> {
+                when (darkModeUiState.currentDarkMode) {
+                    DarkMode.SYSTEM -> stringResource(id = R.string.dark_mode_description_system)
+                    DarkMode.DARK -> stringResource(id = R.string.dark_mode_description_dark)
+                    DarkMode.LIGHT -> stringResource(id = R.string.dark_mode_description_light)
+                }
+            }
         },
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.dark_mode_selector_dark),
-                    selected = currentDarkMode == DarkMode.DARK,
+                    selected = darkModeUiState.currentDarkMode == DarkMode.DARK,
+                    enabled = true,
                     onClick = { setDarkMode(DarkMode.DARK) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.dark_mode_selector_light),
-                    selected = currentDarkMode == DarkMode.LIGHT,
+                    selected = darkModeUiState.currentDarkMode == DarkMode.LIGHT,
+                    enabled = true,
                     onClick = { setDarkMode(DarkMode.LIGHT) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.dark_mode_selector_system),
-                    selected = currentDarkMode == DarkMode.SYSTEM,
+                    selected = darkModeUiState.currentDarkMode == DarkMode.SYSTEM,
+                    enabled = true,
                     onClick = { setDarkMode(DarkMode.SYSTEM) }
                 )
             }
@@ -164,7 +191,7 @@ fun DarkModeSetting(
 
 @Composable
 fun FlashModeSetting(
-    currentFlashMode: FlashMode,
+    flashUiState: FlashUiState,
     setFlashMode: (FlashMode) -> Unit,
     modifier: Modifier = Modifier
 ) {
@@ -172,26 +199,35 @@ fun FlashModeSetting(
         modifier = modifier,
         title = stringResource(id = R.string.flash_mode_title),
         leadingIcon = null,
-        description = when (currentFlashMode) {
-            FlashMode.AUTO -> stringResource(id = R.string.flash_mode_description_auto)
-            FlashMode.ON -> stringResource(id = R.string.flash_mode_description_on)
-            FlashMode.OFF -> stringResource(id = R.string.flash_mode_description_off)
+        enabled = true,
+        description =
+        if (flashUiState is FlashUiState.Enabled) {
+            when (flashUiState.currentFlashMode) {
+                FlashMode.AUTO -> stringResource(id = R.string.flash_mode_description_auto)
+                FlashMode.ON -> stringResource(id = R.string.flash_mode_description_on)
+                FlashMode.OFF -> stringResource(id = R.string.flash_mode_description_off)
+            }
+        } else {
+            TODO("flash mode currently has no disabled criteria")
         },
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.flash_mode_selector_auto),
-                    selected = currentFlashMode == FlashMode.AUTO,
+                    selected = flashUiState.currentFlashMode == FlashMode.AUTO,
+                    enabled = true,
                     onClick = { setFlashMode(FlashMode.AUTO) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.flash_mode_selector_on),
-                    selected = currentFlashMode == FlashMode.ON,
+                    selected = flashUiState.currentFlashMode == FlashMode.ON,
+                    enabled = true,
                     onClick = { setFlashMode(FlashMode.ON) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.flash_mode_selector_off),
-                    selected = currentFlashMode == FlashMode.OFF,
+                    selected = flashUiState.currentFlashMode == FlashMode.OFF,
+                    enabled = true,
                     onClick = { setFlashMode(FlashMode.OFF) }
                 )
             }
@@ -201,7 +237,7 @@ fun FlashModeSetting(
 
 @Composable
 fun AspectRatioSetting(
-    currentAspectRatio: AspectRatio,
+    aspectRatioUiState: AspectRatioUiState,
     setAspectRatio: (AspectRatio) -> Unit,
     modifier: Modifier = Modifier
 ) {
@@ -209,26 +245,38 @@ fun AspectRatioSetting(
         modifier = modifier,
         title = stringResource(id = R.string.aspect_ratio_title),
         leadingIcon = null,
-        description = when (currentAspectRatio) {
-            AspectRatio.NINE_SIXTEEN -> stringResource(id = R.string.aspect_ratio_description_9_16)
-            AspectRatio.THREE_FOUR -> stringResource(id = R.string.aspect_ratio_description_3_4)
-            AspectRatio.ONE_ONE -> stringResource(id = R.string.aspect_ratio_description_1_1)
+        description =
+        if (aspectRatioUiState is AspectRatioUiState.Enabled) {
+            when (aspectRatioUiState.currentAspectRatio) {
+                AspectRatio.NINE_SIXTEEN -> stringResource(
+                    id = R.string.aspect_ratio_description_9_16
+                )
+
+                AspectRatio.THREE_FOUR -> stringResource(id = R.string.aspect_ratio_description_3_4)
+                AspectRatio.ONE_ONE -> stringResource(id = R.string.aspect_ratio_description_1_1)
+            }
+        } else {
+            TODO("aspect ratio currently has no disabled criteria")
         },
+        enabled = true,
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.aspect_ratio_selector_9_16),
-                    selected = currentAspectRatio == AspectRatio.NINE_SIXTEEN,
+                    selected = aspectRatioUiState.currentAspectRatio == AspectRatio.NINE_SIXTEEN,
+                    enabled = true,
                     onClick = { setAspectRatio(AspectRatio.NINE_SIXTEEN) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.aspect_ratio_selector_3_4),
-                    selected = currentAspectRatio == AspectRatio.THREE_FOUR,
+                    selected = aspectRatioUiState.currentAspectRatio == AspectRatio.THREE_FOUR,
+                    enabled = true,
                     onClick = { setAspectRatio(AspectRatio.THREE_FOUR) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.aspect_ratio_selector_1_1),
-                    selected = currentAspectRatio == AspectRatio.ONE_ONE,
+                    selected = aspectRatioUiState.currentAspectRatio == AspectRatio.ONE_ONE,
+                    enabled = true,
                     onClick = { setAspectRatio(AspectRatio.ONE_ONE) }
                 )
             }
@@ -238,7 +286,7 @@ fun AspectRatioSetting(
 
 @Composable
 fun CaptureModeSetting(
-    currentCaptureMode: CaptureMode,
+    captureModeUiState: CaptureModeUiState,
     setCaptureMode: (CaptureMode) -> Unit,
     modifier: Modifier = Modifier
 ) {
@@ -246,25 +294,33 @@ fun CaptureModeSetting(
         modifier = modifier,
         title = stringResource(R.string.capture_mode_title),
         leadingIcon = null,
-        description = when (currentCaptureMode) {
-            CaptureMode.MULTI_STREAM -> stringResource(
-                id = R.string.capture_mode_description_multi_stream
-            )
+        enabled = true,
+        description =
+        if (captureModeUiState is CaptureModeUiState.Enabled) {
+            when (captureModeUiState.currentCaptureMode) {
+                CaptureMode.MULTI_STREAM -> stringResource(
+                    id = R.string.capture_mode_description_multi_stream
+                )
 
-            CaptureMode.SINGLE_STREAM -> stringResource(
-                id = R.string.capture_mode_description_single_stream
-            )
+                CaptureMode.SINGLE_STREAM -> stringResource(
+                    id = R.string.capture_mode_description_single_stream
+                )
+            }
+        } else {
+            TODO("capture mode currently has no disabled criteria")
         },
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.capture_mode_selector_multi_stream),
-                    selected = currentCaptureMode == CaptureMode.MULTI_STREAM,
+                    selected = captureModeUiState.currentCaptureMode == CaptureMode.MULTI_STREAM,
+                    enabled = true,
                     onClick = { setCaptureMode(CaptureMode.MULTI_STREAM) }
                 )
                 SingleChoiceSelector(
                     text = stringResource(id = R.string.capture_mode_description_single_stream),
-                    selected = currentCaptureMode == CaptureMode.SINGLE_STREAM,
+                    selected = captureModeUiState.currentCaptureMode == CaptureMode.SINGLE_STREAM,
+                    enabled = true,
                     onClick = { setCaptureMode(CaptureMode.SINGLE_STREAM) }
                 )
             }
@@ -274,20 +330,21 @@ fun CaptureModeSetting(
 
 @Composable
 fun TargetFpsSetting(
-    currentTargetFps: Int,
-    supportedFps: Set<Int>,
+    fpsUiState: FpsUiState,
     setTargetFps: (Int) -> Unit,
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier,
+        modifier = modifier.apply {
+            if (fpsUiState is FpsUiState.Disabled) {
+                testTag(fpsUiState.disabledRationale.testTag)
+            }
+        },
         title = stringResource(id = R.string.fps_title),
-        enabled = supportedFps.isNotEmpty(),
+        enabled = fpsUiState is FpsUiState.Enabled,
         leadingIcon = null,
-        description = if (supportedFps.isEmpty()) {
-            stringResource(id = R.string.fps_description_unavailable)
-        } else {
-            when (currentTargetFps) {
+        description = if (fpsUiState is FpsUiState.Enabled) {
+            when (fpsUiState.currentSelection) {
                 FPS_15 -> stringResource(id = R.string.fps_description, FPS_15)
                 FPS_30 -> stringResource(id = R.string.fps_description, FPS_30)
                 FPS_60 -> stringResource(id = R.string.fps_description, FPS_60)
@@ -295,27 +352,46 @@ fun TargetFpsSetting(
                     id = R.string.fps_description_auto
                 )
             }
+        } else {
+            disabledRationaleString((fpsUiState as FpsUiState.Disabled).disabledRationale)
         },
         popupContents = {
-            Column(Modifier.selectableGroup()) {
-                Text(
-                    text = stringResource(id = R.string.fps_stabilization_disclaimer),
-                    fontStyle = FontStyle.Italic,
-                    color = MaterialTheme.colorScheme.onPrimaryContainer
-                )
+            if (fpsUiState is FpsUiState.Enabled) {
+                Column(Modifier.selectableGroup()) {
+                    Text(
+                        text = stringResource(id = R.string.fps_stabilization_disclaimer),
+                        fontStyle = FontStyle.Italic,
+                        color = MaterialTheme.colorScheme.onPrimaryContainer
+                    )
 
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.fps_selector_auto),
-                    selected = currentTargetFps == FPS_AUTO,
-                    onClick = { setTargetFps(FPS_AUTO) }
-                )
-                listOf(FPS_15, FPS_30, FPS_60).forEach { fpsOption ->
                     SingleChoiceSelector(
-                        text = "%d".format(fpsOption),
-                        selected = currentTargetFps == fpsOption,
-                        onClick = { setTargetFps(fpsOption) },
-                        enabled = supportedFps.contains(fpsOption)
+                        text = stringResource(id = R.string.fps_selector_auto),
+                        selected = fpsUiState.currentSelection == FPS_AUTO,
+                        onClick = { setTargetFps(FPS_AUTO) },
+                        enabled = fpsUiState.fpsAutoState is SingleSelectableState.Selectable
                     )
+                    listOf(FPS_15, FPS_30, FPS_60).forEach { fpsOption ->
+                        SingleChoiceSelector(
+                            text = "%d".format(fpsOption),
+                            selected = fpsUiState.currentSelection == fpsOption,
+                            onClick = { setTargetFps(fpsOption) },
+                            enabled = when (fpsOption) {
+                                FPS_15 ->
+                                    fpsUiState.fpsFifteenState is
+                                        SingleSelectableState.Selectable
+
+                                FPS_30 ->
+                                    fpsUiState.fpsThirtyState is
+                                        SingleSelectableState.Selectable
+
+                                FPS_60 ->
+                                    fpsUiState.fpsSixtyState is
+                                        SingleSelectableState.Selectable
+
+                                else -> false
+                            }
+                        )
+                    }
                 }
             }
         }
@@ -352,49 +428,44 @@ private fun getStabilizationStringRes(
  * HIGH_QUALITY - Video will be stabilized, preview might be stabilized, depending on the device.
  * OFF - Preview and video stabilization is disabled.
  *
- * @param supportedStabilizationMode the enabled condition for this setting.
+ * @param stabilizationUiState the state for this setting.
  */
 @Composable
 fun StabilizationSetting(
-    currentPreviewStabilization: Stabilization,
-    currentVideoStabilization: Stabilization,
-    currentTargetFps: Int,
-    supportedStabilizationMode: Set<SupportedStabilizationMode>,
+    stabilizationUiState: StabilizationUiState,
     setVideoStabilization: (Stabilization) -> Unit,
     setPreviewStabilization: (Stabilization) -> Unit,
     modifier: Modifier = Modifier
 ) {
-    // if the preview stabilization was left ON and the target frame rate was set to 15,
-    // this setting needs to be reset to OFF
-    LaunchedEffect(key1 = currentTargetFps, key2 = currentPreviewStabilization) {
-        if (currentTargetFps == FPS_15 &&
-            currentPreviewStabilization == Stabilization.ON
-        ) {
-            setPreviewStabilization(Stabilization.UNDEFINED)
-        }
-    }
     // entire setting disabled when no available fps or target fps = 60
     // stabilization is unsupported >30 fps
     BasicPopupSetting(
-        modifier = modifier,
+        modifier = modifier.apply {
+            when (stabilizationUiState) {
+                is StabilizationUiState.Disabled ->
+                    testTag(stabilizationUiState.disabledRationale.testTag)
+
+                else -> {}
+            }
+        },
         title = stringResource(R.string.video_stabilization_title),
         leadingIcon = null,
-        enabled = (
-            supportedStabilizationMode.isNotEmpty() &&
-                currentTargetFps != FPS_60
-            ),
-        description = if (supportedStabilizationMode.isEmpty()) {
-            stringResource(id = R.string.stabilization_description_unsupported_device)
-        } else if (currentTargetFps == FPS_60) {
-            stringResource(id = R.string.stabilization_description_unsupported_fps)
-        } else {
-            stringResource(
-                id = getStabilizationStringRes(
-                    previewStabilization = currentPreviewStabilization,
-                    videoStabilization = currentVideoStabilization
+        enabled = stabilizationUiState is StabilizationUiState.Enabled,
+        description = when (stabilizationUiState) {
+            is StabilizationUiState.Enabled ->
+                stringResource(
+                    id = getStabilizationStringRes(
+                        previewStabilization = stabilizationUiState.currentPreviewStabilization,
+                        videoStabilization = stabilizationUiState.currentVideoStabilization
+                    )
                 )
-            )
+
+            is StabilizationUiState.Disabled -> {
+                // disabled setting description
+                disabledRationaleString(stabilizationUiState.disabledRationale)
+            }
         },
+
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 Text(
@@ -406,55 +477,96 @@ fun StabilizationSetting(
                 // on (preview) selector
                 // disabled if target fps != (30 or off)
                 // TODO(b/328223562): device always resolves to 30fps when using preview stabilization
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.stabilization_selector_on),
-                    secondaryText = stringResource(id = R.string.stabilization_selector_on_info),
-                    enabled =
-                    (
-                        when (currentTargetFps) {
-                            FPS_AUTO, FPS_30 -> true
-                            else -> false
-                        }
-                        ) &&
-                        supportedStabilizationMode.contains(SupportedStabilizationMode.ON),
-                    selected = (currentPreviewStabilization == Stabilization.ON) &&
-                        (currentVideoStabilization != Stabilization.OFF),
-                    onClick = {
-                        setVideoStabilization(Stabilization.UNDEFINED)
-                        setPreviewStabilization(Stabilization.ON)
-                    }
-                )
+                when (stabilizationUiState) {
+                    is StabilizationUiState.Enabled -> {
+                        SingleChoiceSelector(
+                            modifier = Modifier.apply {
+                                if (stabilizationUiState.stabilizationOnState
+                                        is SingleSelectableState.Disabled
+                                ) {
+                                    testTag(
+                                        stabilizationUiState.stabilizationOnState
+                                            .disabledRationale.testTag
+                                    )
+                                }
+                            },
+                            text = stringResource(id = R.string.stabilization_selector_on),
+                            secondaryText = stringResource(
+                                id = R.string.stabilization_selector_on_info
+                            ),
+                            enabled = stabilizationUiState.stabilizationOnState is
+                                SingleSelectableState.Selectable,
+                            selected = (
+                                stabilizationUiState.currentPreviewStabilization
+                                    == Stabilization.ON
+                                ) &&
+                                (
+                                    stabilizationUiState.currentVideoStabilization
+                                        != Stabilization.OFF
+                                    ),
+                            onClick = {
+                                setVideoStabilization(Stabilization.UNDEFINED)
+                                setPreviewStabilization(Stabilization.ON)
+                            }
+                        )
 
-                // high quality selector
-                // disabled if target fps = 60 (see VideoCapabilities.isStabilizationSupported)
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.stabilization_selector_high_quality),
-                    secondaryText = stringResource(
-                        id = R.string.stabilization_selector_high_quality_info
-                    ),
-                    enabled = (currentTargetFps != FPS_60) &&
-                        supportedStabilizationMode.contains(
-                            SupportedStabilizationMode.HIGH_QUALITY
-                        ),
-
-                    selected = (currentPreviewStabilization == Stabilization.UNDEFINED) &&
-                        (currentVideoStabilization == Stabilization.ON),
-                    onClick = {
-                        setVideoStabilization(Stabilization.ON)
-                        setPreviewStabilization(Stabilization.UNDEFINED)
-                    }
-                )
+                        // high quality selector
+                        // disabled if target fps = 60 (see VideoCapabilities.isStabilizationSupported)
+                        SingleChoiceSelector(
+                            modifier = Modifier.apply {
+                                if (stabilizationUiState.stabilizationHighQualityState
+                                        is SingleSelectableState.Disabled
+                                ) {
+                                    testTag(
+                                        stabilizationUiState.stabilizationHighQualityState
+                                            .disabledRationale.testTag
+                                    )
+                                }
+                            },
+                            text = stringResource(
+                                id = R.string.stabilization_selector_high_quality
+                            ),
+                            secondaryText = stringResource(
+                                id = R.string.stabilization_selector_high_quality_info
+                            ),
+                            enabled = stabilizationUiState.stabilizationHighQualityState
+                                == SingleSelectableState.Selectable,
 
-                // off selector
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.stabilization_selector_off),
-                    selected = (currentPreviewStabilization != Stabilization.ON) &&
-                        (currentVideoStabilization != Stabilization.ON),
-                    onClick = {
-                        setVideoStabilization(Stabilization.OFF)
-                        setPreviewStabilization(Stabilization.OFF)
+                            selected = (
+                                stabilizationUiState.currentPreviewStabilization
+                                    == Stabilization.UNDEFINED
+                                ) &&
+                                (
+                                    stabilizationUiState.currentVideoStabilization
+                                        == Stabilization.ON
+                                    ),
+                            onClick = {
+                                setVideoStabilization(Stabilization.ON)
+                                setPreviewStabilization(Stabilization.UNDEFINED)
+                            }
+                        )
+
+                        // off selector
+                        SingleChoiceSelector(
+                            text = stringResource(id = R.string.stabilization_selector_off),
+                            selected = (
+                                stabilizationUiState.currentPreviewStabilization
+                                    != Stabilization.ON
+                                ) &&
+                                (
+                                    stabilizationUiState.currentVideoStabilization
+                                        != Stabilization.ON
+                                    ),
+                            onClick = {
+                                setVideoStabilization(Stabilization.OFF)
+                                setPreviewStabilization(Stabilization.OFF)
+                            },
+                            enabled = true
+                        )
                     }
-                )
+
+                    else -> {}
+                }
             }
         }
     )
@@ -465,7 +577,8 @@ fun VersionInfo(versionName: String, modifier: Modifier = Modifier, buildType: S
     SettingUI(
         modifier = modifier,
         title = stringResource(id = R.string.version_info_title),
-        leadingIcon = null
+        leadingIcon = null,
+        enabled = true
     ) {
         val versionString = versionName +
             if (buildType.isNotEmpty()) {
@@ -492,7 +605,7 @@ fun BasicPopupSetting(
     leadingIcon: @Composable (() -> Unit)?,
     popupContents: @Composable () -> Unit,
     modifier: Modifier = Modifier,
-    enabled: Boolean = true
+    enabled: Boolean
 ) {
     val popupStatus = remember { mutableStateOf(false) }
     SettingUI(
@@ -565,25 +678,25 @@ fun SettingUI(
     title: String,
     leadingIcon: @Composable (() -> Unit)?,
     modifier: Modifier = Modifier,
-    enabled: Boolean = true,
+    enabled: Boolean,
     description: String? = null,
     trailingContent: @Composable (() -> Unit)?
 ) {
     ListItem(
         modifier = modifier,
         headlineContent = {
-            when (enabled) {
-                true -> Text(title)
-                false -> {
-                    Text(text = title, color = LocalContentColor.current.copy(alpha = .7f))
-                }
+            if (enabled) {
+                Text(title)
+            } else {
+                Text(text = title, color = LocalContentColor.current.copy(alpha = .7f))
             }
         },
         supportingContent = {
             if (description != null) {
-                when (enabled) {
-                    true -> Text(description)
-                    false -> Text(
+                if (enabled) {
+                    Text(description)
+                } else {
+                    Text(
                         text = description,
                         color = LocalContentColor.current.copy(alpha = .7f)
                     )
@@ -605,7 +718,7 @@ fun SingleChoiceSelector(
     onClick: () -> Unit,
     modifier: Modifier = Modifier,
     secondaryText: String? = null,
-    enabled: Boolean = true
+    enabled: Boolean
 ) {
     Row(
         modifier
@@ -634,6 +747,34 @@ fun SingleChoiceSelector(
     }
 }
 
+@Composable
+@ReadOnlyComposable
+fun disabledRationaleString(disabledRationale: DisabledRationale): String {
+    return when (disabledRationale) {
+        is DisabledRationale.DeviceUnsupportedRationale -> stringResource(
+
+            disabledRationale.reasonTextResId,
+            stringResource(disabledRationale.affectedSettingNameResId)
+        )
+
+        is DisabledRationale.FpsUnsupportedRationale -> stringResource(
+            disabledRationale.reasonTextResId,
+            stringResource(disabledRationale.affectedSettingNameResId),
+            disabledRationale.currentFps
+        )
+
+        is DisabledRationale.LensUnsupportedRationale -> stringResource(
+            disabledRationale.reasonTextResId,
+            stringResource(disabledRationale.affectedSettingNameResId)
+        )
+
+        is DisabledRationale.StabilizationUnsupportedRationale -> stringResource(
+            disabledRationale.reasonTextResId,
+            stringResource(disabledRationale.affectedSettingNameResId)
+        )
+    }
+}
+
 @Preview(name = "Light Mode")
 @Preview(name = "Dark Mode", uiMode = Configuration.UI_MODE_NIGHT_YES)
 @Composable
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt
index ef11b24..8253fc1 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt
@@ -16,3 +16,9 @@
 package com.google.jetpackcamera.settings.ui
 
 const val BACK_BUTTON = "BackButton"
+
+// unsupported rationale tags
+const val DEVICE_UNSUPPORTED_TAG = "DeviceUnsupportedTag"
+const val STABILIZATION_UNSUPPORTED_TAG = "StabilizationUnsupportedTag"
+const val LENS_UNSUPPORTED_TAG = "LensUnsupportedTag"
+const val FPS_UNSUPPORTED_TAG = "FpsUnsupportedTag"
diff --git a/feature/settings/src/main/res/values/strings.xml b/feature/settings/src/main/res/values/strings.xml
index ad8aff6..e41f4fd 100644
--- a/feature/settings/src/main/res/values/strings.xml
+++ b/feature/settings/src/main/res/values/strings.xml
@@ -101,6 +101,24 @@
     <string name="fps_stabilization_disclaimer">*Available stabilization modes may change due to selected frame rate.</string>
     <string name="lens_stabilization_disclaimer">*Some devices may not support stabilization on both lens.</string>
 
+    <!-- disabled rationale strings-->
+    <string name="device_unsupported">%1$s is unsupported by the device</string>
+    <string name="fps_unsupported"> %1$s is unsupported at %2$d fps</string>
+    <string name="stabilization_unsupported">%$1s is unsupported by the current stabilization</string>
+    <string name="current_lens_unsupported">%$s is unsupported by the current lens</string>
+    <string name="rear_lens_unsupported">%$s is unsupported by the rear lens</string>
+    <string name="front_lens_unsupported">%$s is unsupported by the front lens</string>
+
+
+    <!-- Rationale prefixes -->
+    <string name="stabilization_rationale_prefix">Stabilization</string>
+    <string name="lens_rationale_prefix">Lens flip</string>
+    <string name="fps_rationale_prefix">Fps</string>
+
+    <string name="front_lens_rationale_prefix">Front lens</string>
+    <string name="rear_lens_rationale_prefix">Rear lens</string>
+    <string name="no_fixed_fps_rationale_prefix">Fixed frame rate</string>
+
 
     <!-- Version info strings -->
     <string name="version_info_title">Version</string>
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index a650cf0..36ea132 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -1,8 +1,10 @@
 [versions]
 # Used directly in build.gradle.kts files
 compileSdk = "34"
+compileSdkPreview = "VanillaIceCream"
 minSdk = "21"
 targetSdk = "34"
+targetSdkPreview = "VanillaIceCream"
 composeCompiler = "1.5.10"
 
 # Used below in dependency definitions
@@ -13,7 +15,7 @@ accompanist = "0.34.0"
 # kotlinPlugin and composeCompiler are linked
 # See https://developer.android.com/jetpack/androidx/releases/compose-kotlin
 kotlinPlugin = "1.9.22"
-androidGradlePlugin = "8.4.0-rc01"
+androidGradlePlugin = "8.4.2"
 protobufPlugin = "0.9.4"
 
 androidxActivityCompose = "1.8.2"
@@ -35,6 +37,7 @@ androidxTestMonitor = "1.6.1"
 androidxTestRules = "1.5.0"
 androidxTestUiautomator = "2.3.0"
 androidxTracing = "1.2.0"
+cmake = "3.22.1"
 kotlinxAtomicfu = "0.23.2"
 kotlinxCoroutines = "1.8.0"
 hilt = "2.51"
@@ -44,6 +47,7 @@ mockitoCore = "5.6.0"
 protobuf = "3.25.2"
 robolectric = "4.11.1"
 truth = "1.4.2"
+rules = "1.6.1"
 
 [libraries]
 accompanist-permissions = { module = "com.google.accompanist:accompanist-permissions", version.ref = "accompanist" }
@@ -56,6 +60,7 @@ androidx-datastore = { module = "androidx.datastore:datastore", version.ref = "a
 androidx-espresso-core = { module = "androidx.test.espresso:espresso-core", version.ref = "androidxTestEspresso" }
 androidx-graphics-core = { module = "androidx.graphics:graphics-core", version.ref = "androidxGraphicsCore" }
 androidx-junit = { module = "androidx.test.ext:junit", version.ref = "androidxTestJunit" }
+androidx-lifecycle-livedata = { module = "androidx.lifecycle:lifecycle-livedata-ktx", version.ref = "androidxLifecycle" }
 androidx-lifecycle-viewmodel-compose = { module = "androidx.lifecycle:lifecycle-viewmodel-compose", version.ref = "androidxLifecycle" }
 androidx-lifecycle-runtime-compose = { module = "androidx.lifecycle:lifecycle-runtime-compose", version.ref = "androidxLifecycle" }
 androidx-navigation-compose = { module = "androidx.navigation:navigation-compose", version.ref = "androidxNavigationCompose" }
@@ -81,6 +86,7 @@ dagger-hilt-compiler = { module = "com.google.dagger:hilt-compiler", version.ref
 futures-ktx = { module = "androidx.concurrent:concurrent-futures-ktx", version.ref = "androidxConcurrentFutures" }
 hilt-navigation-compose = { module = "androidx.hilt:hilt-navigation-compose", version.ref = "androidxHiltNavigationCompose" }
 junit = { module = "junit:junit", version.ref = "junit" }
+kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlinPlugin" }
 kotlinx-atomicfu = { module = "org.jetbrains.kotlinx:atomicfu", version.ref = "kotlinxAtomicfu" }
 kotlinx-coroutines-core = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-core", version.ref = "kotlinxCoroutines" }
 kotlinx-coroutines-test = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-test", version.ref = "kotlinxCoroutines" }
@@ -89,6 +95,7 @@ mockito-core = { module = "org.mockito:mockito-core", version.ref = "mockitoCore
 protobuf-kotlin-lite = { module = "com.google.protobuf:protobuf-kotlin-lite", version.ref = "protobuf" }
 robolectric = { module = "org.robolectric:robolectric", version.ref = "robolectric" }
 truth = { module = "com.google.truth:truth", version.ref = "truth" }
+rules = { group = "androidx.test", name = "rules", version.ref = "rules" }
 
 [plugins]
 android-application = { id = "com.android.application", version.ref = "androidGradlePlugin" }
diff --git a/settings.gradle.kts b/settings.gradle.kts
index dd158c4..7c7842f 100644
--- a/settings.gradle.kts
+++ b/settings.gradle.kts
@@ -26,7 +26,7 @@ dependencyResolutionManagement {
     repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
     repositories {
         maven {
-            setUrl("https://androidx.dev/snapshots/builds/11790852/artifacts/repository")
+            setUrl("https://androidx.dev/snapshots/builds/12167802/artifacts/repository")
         }
         google()
         mavenCentral()
@@ -35,7 +35,7 @@ dependencyResolutionManagement {
 rootProject.name = "Jetpack Camera"
 include(":app")
 include(":feature:preview")
-include(":domain:camera")
+include(":core:camera")
 include(":feature:settings")
 include(":data:settings")
 include(":core:common")
```

