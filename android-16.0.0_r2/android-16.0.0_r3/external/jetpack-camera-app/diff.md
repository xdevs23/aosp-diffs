```diff
diff --git a/.github/workflows/ChooseRunner.yaml b/.github/workflows/ChooseRunner.yaml
new file mode 100644
index 0000000..ab7ccde
--- /dev/null
+++ b/.github/workflows/ChooseRunner.yaml
@@ -0,0 +1,29 @@
+name: Choose Runner
+
+on:
+  workflow_call:
+    inputs:
+      forced_runner:
+        required: false
+        type: string
+    outputs:
+      chosen_runner:
+        description: "The runner chosen from inputs and repository variables"
+        value: ${{ jobs.resolve_runner.outputs.resolved_runner }}
+
+jobs:
+  resolve_runner:
+    name: Resolve Runner
+    runs-on: ubuntu-latest
+    outputs:
+        resolved_runner: ${{ steps.resolve_runner.outputs.resolved_runner }}
+    steps:
+      - name: Resolve runner from inputs, repo vars, or default
+        id: resolve_runner
+        run: |
+          FORCED_RUNNER=${{ inputs.forced_runner }}
+          VARS_RUNNER=${{ vars.RUNNER }}
+          BACKUP_RUNNER="ubuntu-latest"
+          RESOLVED_RUNNER="${FORCED_RUNNER:-${VARS_RUNNER:-$BACKUP_RUNNER}}"
+          echo "Resolved runner: $RESOLVED_RUNNER"
+          echo "resolved_runner=$RESOLVED_RUNNER" >> $GITHUB_OUTPUT
diff --git a/.github/workflows/MergeToMainWorkflow.yaml b/.github/workflows/MergeToMainWorkflow.yaml
index 9aa6590..2cde27e 100644
--- a/.github/workflows/MergeToMainWorkflow.yaml
+++ b/.github/workflows/MergeToMainWorkflow.yaml
@@ -14,9 +14,14 @@ env:
   DISTRIBUTION: 'zulu'
 
 jobs:
+  choose_runner:
+    name: Choose Runner
+    uses: ./.github/workflows/ChooseRunner.yaml
+
   build:
     name: Build
-    runs-on: ${{ vars.RUNNER }}
+    needs: choose_runner
+    runs-on: ${{ needs.choose_runner.outputs.chosen_runner }}
     timeout-minutes: 120
     steps:
       - name: Checkout
@@ -34,6 +39,8 @@ jobs:
 
       - name: Setup Gradle
         uses: gradle/actions/setup-gradle@v3
+        with:
+          cache-encryption-key: ${{ secrets.GRADLE_ENCRYPTION_KEY }}
 
       - name: Build all build type and flavor permutations
         run: ./gradlew assemble --parallel --build-cache
diff --git a/.github/workflows/PullRequestWorkflow.yaml b/.github/workflows/PullRequestWorkflow.yaml
index ed83887..da2a6cb 100644
--- a/.github/workflows/PullRequestWorkflow.yaml
+++ b/.github/workflows/PullRequestWorkflow.yaml
@@ -1,6 +1,13 @@
 name: Presubmit
 
-on: [pull_request]
+on:
+  pull_request:
+  workflow_dispatch:
+    inputs:
+      runner:
+        description: "Runner (host machine) to use for all jobs in presubmit"
+        required: false
+        type: string
 
 concurrency:
   group: build-${{ github.ref }}
@@ -11,9 +18,16 @@ env:
   DISTRIBUTION: 'zulu'
 
 jobs:
+  choose_runner:
+    name: Choose Runner
+    uses: ./.github/workflows/ChooseRunner.yaml
+    with:
+      forced_runner: ${{ inputs.runner }}
+
   build:
     name: Build
-    runs-on: ${{ vars.RUNNER }}
+    needs: choose_runner
+    runs-on: ${{ needs.choose_runner.outputs.chosen_runner }}
     timeout-minutes: 120
     steps:
       - name: Checkout
@@ -31,6 +45,8 @@ jobs:
 
       - name: Setup Gradle
         uses: gradle/actions/setup-gradle@v3
+        with:
+          cache-encryption-key: ${{ secrets.GRADLE_ENCRYPTION_KEY }}
 
       - name: Build stable debug gradle target
         run: ./gradlew assembleStableDebug --parallel --build-cache
@@ -51,7 +67,8 @@ jobs:
 
   test:
     name: Unit Tests
-    runs-on: ${{ vars.RUNNER }}
+    needs: choose_runner
+    runs-on: ${{ needs.choose_runner.outputs.chosen_runner }}
     timeout-minutes: 120
     steps:
       - name: Checkout
@@ -69,6 +86,8 @@ jobs:
 
       - name: Setup Gradle
         uses: gradle/actions/setup-gradle@v3
+        with:
+          cache-encryption-key: ${{ secrets.GRADLE_ENCRYPTION_KEY }}
         continue-on-error: true
 
       - name: Run local tests
@@ -83,8 +102,9 @@ jobs:
 
   android-test:
     name: Instrumentation Tests (${{ matrix.device.name }})
-    runs-on: ${{ vars.RUNNER }}
-    timeout-minutes: 30
+    needs: choose_runner
+    runs-on: ${{ needs.choose_runner.outputs.chosen_runner }}
+    timeout-minutes: 120
     strategy:
       fail-fast: false
       matrix:
@@ -120,6 +140,7 @@ jobs:
         uses: gradle/actions/setup-gradle@v3
         with:
           arguments: ${{ matrix.device.name }}StableDebugAndroidTest
+          cache-encryption-key: ${{ secrets.GRADLE_ENCRYPTION_KEY }}
 
       - name: Upload instrumentation test reports and logs on failure
         if: failure()
@@ -132,7 +153,8 @@ jobs:
 
   spotless:
     name: Spotless Check
-    runs-on: ${{ vars.RUNNER }}
+    needs: choose_runner
+    runs-on: ${{ needs.choose_runner.outputs.chosen_runner }}
     timeout-minutes: 60
     steps:
       - name: Checkout
@@ -152,6 +174,8 @@ jobs:
 
       - name: Setup Gradle
         uses: gradle/actions/setup-gradle@v3
+        with:
+          cache-encryption-key: ${{ secrets.GRADLE_ENCRYPTION_KEY }}
 
       - name: Spotless Check
         run: ./gradlew spotlessCheck --init-script gradle/init.gradle.kts --parallel --build-cache
diff --git a/.idea/codeStyles/Project.xml b/.idea/codeStyles/Project.xml
index 7643783..7f70f7e 100644
--- a/.idea/codeStyles/Project.xml
+++ b/.idea/codeStyles/Project.xml
@@ -1,5 +1,40 @@
 <component name="ProjectCodeStyleConfiguration">
   <code_scheme name="Project" version="173">
+    <JavaCodeStyleSettings>
+      <option name="IMPORT_LAYOUT_TABLE">
+        <value>
+          <package name="" withSubpackages="true" static="false" module="true" />
+          <package name="android" withSubpackages="true" static="true" />
+          <package name="androidx" withSubpackages="true" static="true" />
+          <package name="com" withSubpackages="true" static="true" />
+          <package name="junit" withSubpackages="true" static="true" />
+          <package name="net" withSubpackages="true" static="true" />
+          <package name="org" withSubpackages="true" static="true" />
+          <package name="java" withSubpackages="true" static="true" />
+          <package name="javax" withSubpackages="true" static="true" />
+          <package name="" withSubpackages="true" static="true" />
+          <emptyLine />
+          <package name="android" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="androidx" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="com" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="junit" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="net" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="org" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="java" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="javax" withSubpackages="true" static="false" />
+          <emptyLine />
+          <package name="" withSubpackages="true" static="false" />
+          <emptyLine />
+        </value>
+      </option>
+    </JavaCodeStyleSettings>
     <JetCodeStyleSettings>
       <option name="CODE_STYLE_DEFAULTS" value="KOTLIN_OFFICIAL" />
     </JetCodeStyleSettings>
diff --git a/app/build.gradle.kts b/app/build.gradle.kts
index db70317..e77d3d9 100644
--- a/app/build.gradle.kts
+++ b/app/build.gradle.kts
@@ -19,6 +19,7 @@ plugins {
     alias(libs.plugins.kotlin.android)
     alias(libs.plugins.kotlin.kapt)
     alias(libs.plugins.dagger.hilt.android)
+    alias(libs.plugins.compose.compiler)
 }
 
 android {
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/CaptureModeSettingsTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/CaptureModeSettingsTest.kt
new file mode 100644
index 0000000..3859980
--- /dev/null
+++ b/app/src/androidTest/java/com/google/jetpackcamera/CaptureModeSettingsTest.kt
@@ -0,0 +1,343 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+import android.app.Activity
+import android.provider.MediaStore
+import androidx.compose.ui.test.assertIsEnabled
+import androidx.compose.ui.test.assertIsNotEnabled
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.junit4.ComposeTestRule
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.rule.GrantPermissionRule
+import androidx.test.uiautomator.UiDevice
+import com.google.common.truth.Truth
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.TruthJUnit.assume
+import com.google.jetpackcamera.ImageCaptureDeviceTest.Companion.DIR_PATH
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_OPTION_STANDARD
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_MODE_TOGGLE_BUTTON
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.getCurrentCaptureMode
+import com.google.jetpackcamera.utils.getHdrToggleState
+import com.google.jetpackcamera.utils.getSingleImageCaptureIntent
+import com.google.jetpackcamera.utils.getTestUri
+import com.google.jetpackcamera.utils.isHdrToggleEnabled
+import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.runScenarioTestForResult
+import com.google.jetpackcamera.utils.setCaptureMode
+import com.google.jetpackcamera.utils.setConcurrentCameraMode
+import com.google.jetpackcamera.utils.setHdrEnabled
+import com.google.jetpackcamera.utils.unFocusQuickSetting
+import com.google.jetpackcamera.utils.visitQuickSettings
+import com.google.jetpackcamera.utils.waitForNodeWithTag
+import com.google.jetpackcamera.utils.waitForStartup
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+internal class CaptureModeSettingsTest {
+    @get:Rule
+    val permissionsRule: GrantPermissionRule =
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
+
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
+    private val instrumentation = InstrumentationRegistry.getInstrumentation()
+    private val uiDevice = UiDevice.getInstance(instrumentation)
+    private fun ComposeTestRule.checkCaptureMode(captureMode: CaptureMode? = null) =
+        visitQuickSettings {
+            waitUntil(timeoutMillis = 1000) {
+                onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE).isDisplayed()
+            }
+            captureMode?.let {
+                assertThat(getCurrentCaptureMode()).isEqualTo(captureMode)
+            }
+        }
+
+    @Test
+    fun can_set_capture_mode_in_quick_settings() {
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitForStartup()
+            composeTestRule.visitQuickSettings {
+                setCaptureMode(CaptureMode.IMAGE_ONLY)
+                checkCaptureMode(CaptureMode.IMAGE_ONLY)
+
+                setCaptureMode(CaptureMode.VIDEO_ONLY)
+                checkCaptureMode(CaptureMode.VIDEO_ONLY)
+
+                setCaptureMode(CaptureMode.STANDARD)
+                checkCaptureMode(CaptureMode.STANDARD)
+            }
+        }
+    }
+
+    @Test
+    fun concurrent_only_supports_video_capture_mode() {
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitForStartup()
+            composeTestRule.visitQuickSettings {
+                // verify concurrent is supported. if not supported, skip test
+                waitForNodeWithTag(tag = QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                setConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+
+                // capture mode should now be video only
+                checkCaptureMode(CaptureMode.VIDEO_ONLY)
+
+                // should not be able to switch between capture modes
+                onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                    .assertExists()
+                    .assertIsNotEnabled()
+
+                // set concurrent camera mode back to off
+                setConcurrentCameraMode(ConcurrentCameraMode.OFF)
+
+                // capture mode should reset to standard
+                checkCaptureMode(CaptureMode.STANDARD)
+            }
+        }
+    }
+
+    @Test
+    fun image_only_disables_concurrent_camera() {
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitForStartup()
+            composeTestRule.visitQuickSettings {
+                // verify concurrent is supported. if not supported, skip test
+                waitForNodeWithTag(tag = QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                setConcurrentCameraMode(ConcurrentCameraMode.OFF)
+
+                // capture mode should now be image only
+                setCaptureMode(CaptureMode.IMAGE_ONLY)
+                checkCaptureMode(CaptureMode.IMAGE_ONLY)
+
+                // should not be able to enable concurrent
+                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                    .assertExists()
+                    .assertIsNotEnabled()
+
+                // reset caputre mode to standard
+                setCaptureMode(CaptureMode.STANDARD)
+                checkCaptureMode(CaptureMode.STANDARD)
+
+                // concurrent should be enabled again
+                onNodeWithTag(
+                    QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
+                ).assertExists().assertIsEnabled()
+            }
+        }
+    }
+
+    @Test
+    fun hdr_supports_image_only() {
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitForStartup()
+            composeTestRule.setHdrEnabled(true)
+            // check that switch only supports image
+            composeTestRule.waitForNodeWithTag(CAPTURE_MODE_TOGGLE_BUTTON)
+            assume().that(composeTestRule.isHdrToggleEnabled()).isFalse()
+            assume().that(composeTestRule.getHdrToggleState()).isEqualTo(CaptureMode.IMAGE_ONLY)
+
+            composeTestRule.visitQuickSettings {
+                waitForNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                // capture mode should be image only
+                assertThat(getCurrentCaptureMode()).isEqualTo(CaptureMode.IMAGE_ONLY)
+            }
+            // should not be able to change capture mode
+            assertThat(composeTestRule.isHdrToggleEnabled()).isFalse()
+            composeTestRule.setHdrEnabled(false)
+            composeTestRule.checkCaptureMode(CaptureMode.STANDARD)
+        }
+    }
+
+    @Test
+    fun hdr_supports_video_only() {
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitForStartup()
+            composeTestRule.setHdrEnabled(true)
+            // check that switch only supports image
+            composeTestRule.waitForNodeWithTag(CAPTURE_MODE_TOGGLE_BUTTON)
+            // should not be able use capture toggle
+            assume().that(composeTestRule.isHdrToggleEnabled()).isFalse()
+            assume().that(composeTestRule.getHdrToggleState()).isEqualTo(CaptureMode.VIDEO_ONLY)
+
+            composeTestRule.visitQuickSettings {
+                waitForNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                // capture mode should be image only
+                checkCaptureMode(CaptureMode.VIDEO_ONLY)
+            }
+            assertThat(composeTestRule.isHdrToggleEnabled()).isFalse()
+
+            composeTestRule.setHdrEnabled(false)
+            composeTestRule.checkCaptureMode(CaptureMode.STANDARD)
+        }
+    }
+
+    @Test
+    fun hdr_supports_image_and_video() {
+        runScenarioTest<MainActivity> {
+            with(composeTestRule) {
+                composeTestRule.waitForStartup()
+
+                // enable hdr
+                setHdrEnabled(true)
+
+                // check that switch supports both image and video
+                waitForNodeWithTag(CAPTURE_MODE_TOGGLE_BUTTON)
+                assume().that(isHdrToggleEnabled()).isTrue()
+
+                // should default to video when both are available
+                assertThat(getHdrToggleState()).isEqualTo(CaptureMode.VIDEO_ONLY)
+
+                visitQuickSettings {
+                    checkCaptureMode(CaptureMode.VIDEO_ONLY)
+                    setHdrEnabled(false)
+
+                    // capture mode should return to standard when we turn off hdr
+                    checkCaptureMode(CaptureMode.STANDARD)
+
+                    setCaptureMode(CaptureMode.IMAGE_ONLY)
+                    setHdrEnabled(true)
+                    // capture mode should remain as image only, since device supports ultrahdr image
+                    checkCaptureMode(CaptureMode.IMAGE_ONLY)
+                }
+                // if both are supported, should keep the current, non-standard capture mode
+                assertThat(getHdrToggleState()).isEqualTo(CaptureMode.IMAGE_ONLY)
+
+                // turn on video only hdr
+                onNodeWithTag(CAPTURE_MODE_TOGGLE_BUTTON).performClick()
+                assertThat(getHdrToggleState()).isEqualTo(CaptureMode.VIDEO_ONLY)
+
+                visitQuickSettings {
+                    // capture mode should be video only now
+                    checkCaptureMode(CaptureMode.VIDEO_ONLY)
+                    onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE).performClick()
+                    onNodeWithTag(
+                        BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_OPTION_STANDARD
+                    ).assertIsNotEnabled()
+                    unFocusQuickSetting()
+
+                    setHdrEnabled(false)
+                    checkCaptureMode(CaptureMode.STANDARD)
+                }
+            }
+        }
+    }
+
+    @Test
+    fun image_intent_disables_capture_settings() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(DIR_PATH, timeStamp, "jpg")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitForStartup()
+                composeTestRule.visitQuickSettings {
+                    checkCaptureMode(CaptureMode.IMAGE_ONLY)
+
+                    // should not be able to change quick settings
+                    onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                        .assertExists()
+                        .assertIsNotEnabled()
+                }
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+    }
+
+    @Test
+    fun image_intent_disables_hdr_toggle() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(DIR_PATH, timeStamp, "jpg")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitForStartup()
+                composeTestRule.visitQuickSettings {
+                    setHdrEnabled(true)
+                    checkCaptureMode(CaptureMode.IMAGE_ONLY)
+                }
+                assertThat(composeTestRule.isHdrToggleEnabled()).isFalse()
+                assertThat(
+                    composeTestRule.getHdrToggleState()
+                ).isEqualTo(CaptureMode.IMAGE_ONLY)
+
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+    }
+
+    @Test
+    fun video_intent_disables_capture_settings() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(VideoRecordingDeviceTest.Companion.DIR_PATH, timeStamp, "mp4")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitForStartup()
+                composeTestRule.visitQuickSettings {
+                    checkCaptureMode(CaptureMode.VIDEO_ONLY)
+
+                    // should not be able to change quick settings
+                    onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                        .assertExists()
+                        .assertIsNotEnabled()
+                }
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+    }
+
+    @Test
+    fun video_intent_disables_hdr_toggle() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(VideoRecordingDeviceTest.Companion.DIR_PATH, timeStamp, "mp4")
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitForStartup()
+                composeTestRule.visitQuickSettings {
+                    setHdrEnabled(true)
+                    checkCaptureMode(CaptureMode.VIDEO_ONLY)
+                }
+                assertThat(composeTestRule.isHdrToggleEnabled()).isFalse()
+                assertThat(
+                    composeTestRule.getHdrToggleState()
+                ).isEqualTo(CaptureMode.VIDEO_ONLY)
+
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+    }
+}
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt
index b9b2695..cfd45bb 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt
@@ -34,6 +34,7 @@ import androidx.test.rule.GrantPermissionRule
 import com.google.common.truth.Truth.assertThat
 import com.google.jetpackcamera.MainActivity
 import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_DROP_DOWN
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
@@ -42,9 +43,7 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_STREAM_CONFIG_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
-import com.google.jetpackcamera.feature.preview.ui.CAPTURE_MODE_TOGGLE_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
-import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
@@ -56,6 +55,7 @@ import com.google.jetpackcamera.utils.longClickForVideoRecording
 import com.google.jetpackcamera.utils.runMediaStoreAutoDeleteScenarioTest
 import com.google.jetpackcamera.utils.runScenarioTest
 import com.google.jetpackcamera.utils.stateDescriptionMatches
+import kotlinx.coroutines.runBlocking
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -233,39 +233,36 @@ class ConcurrentCameraTest {
     @Test
     fun concurrentCameraMode_whenEnabled_disablesOtherSettings() =
         runConcurrentCameraScenarioTest<MainActivity> {
-            with(composeTestRule) {
-                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
-                    .assertExists()
-                    .assertConcurrentCameraMode(ConcurrentCameraMode.OFF)
-                    // Enable concurrent camera
-                    .performClick()
-                    .assertConcurrentCameraMode(ConcurrentCameraMode.DUAL)
-
-                // Assert the capture mode button is disabled
-                onNodeWithTag(QUICK_SETTINGS_STREAM_CONFIG_BUTTON)
-                    .assertExists()
-                    .assert(isNotEnabled())
-
-                // Assert the HDR button is disabled
-                onNodeWithTag(QUICK_SETTINGS_HDR_BUTTON)
-                    .assertExists()
-                    .assert(isNotEnabled())
-
-                // Exit quick settings
-                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-                    .assertExists()
-                    .performClick()
-
-                onNodeWithTag(CAPTURE_MODE_TOGGLE_BUTTON)
-                    .assertExists()
-                    .assert(
-                        stateDescriptionMatches(
-                            getResString(R.string.capture_mode_video_recording_content_description)
+            runBlocking {
+                with(composeTestRule) {
+                    onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                        .assertExists()
+                        .assertConcurrentCameraMode(ConcurrentCameraMode.OFF)
+                        // Enable concurrent camera
+                        .performClick()
+                        .assertConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+
+                    // Assert the capture mode button is disabled
+                    onNodeWithTag(QUICK_SETTINGS_STREAM_CONFIG_BUTTON)
+                        .assertExists()
+                        .assert(isNotEnabled())
+
+                    // Assert the HDR button is disabled
+                    onNodeWithTag(QUICK_SETTINGS_HDR_BUTTON)
+                        .assertExists()
+                        .assert(isNotEnabled())
+
+                    // Assert the capture mode is disabled and set to video-only
+                    onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                        .assertExists()
+                        .assert(isNotEnabled())
+                        .assert(
+                            stateDescriptionMatches(
+                                getResString(
+                                    R.string.quick_settings_description_capture_mode_video_only
+                                )
+                            )
                         )
-                    ).performClick()
-
-                waitUntil {
-                    onNodeWithTag(IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG).isDisplayed()
                 }
             }
         }
@@ -345,10 +342,10 @@ class ConcurrentCameraTest {
     private fun SemanticsNode.fetchConcurrentCameraMode(): ConcurrentCameraMode {
         config[SemanticsProperties.ContentDescription].any { description ->
             when (description) {
-                getResString(R.string.quick_settings_concurrent_camera_off_description) ->
+                getResString(R.string.quick_settings_description_concurrent_camera_off) ->
                     return ConcurrentCameraMode.OFF
 
-                getResString(R.string.quick_settings_concurrent_camera_dual_description) ->
+                getResString(R.string.quick_settings_description_concurrent_camera_dual) ->
                     return ConcurrentCameraMode.DUAL
 
                 else -> false
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
index d6a4498..11848c4 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
@@ -19,6 +19,7 @@ import android.app.Activity
 import android.net.Uri
 import android.os.Environment
 import android.provider.MediaStore
+import android.view.KeyEvent
 import androidx.compose.ui.test.ComposeTimeoutException
 import androidx.compose.ui.test.isDisplayed
 import androidx.compose.ui.test.isNotDisplayed
@@ -37,6 +38,7 @@ import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.FILE_PREFIX
 import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
 import com.google.jetpackcamera.utils.IMAGE_PREFIX
 import com.google.jetpackcamera.utils.MESSAGE_DISAPPEAR_TIMEOUT_MILLIS
@@ -70,9 +72,9 @@ internal class ImageCaptureDeviceTest {
     private val uiDevice = UiDevice.getInstance(instrumentation)
 
     @Test
-    fun image_capture() = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+    fun image_capture_button() = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
         mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
-        filePrefix = "JCA"
+        filePrefix = FILE_PREFIX
     ) {
         // Wait for the capture button to be displayed
         composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
@@ -87,6 +89,39 @@ internal class ImageCaptureDeviceTest {
         }
     }
 
+    @Test
+    fun image_capture_volumeUp() = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+        mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+        filePrefix = FILE_PREFIX
+    ) {
+        // Wait for the capture button to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+        }
+
+        uiDevice.pressKeyCode(KeyEvent.KEYCODE_VOLUME_UP)
+
+        composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(IMAGE_CAPTURE_SUCCESS_TAG).isDisplayed()
+        }
+    }
+
+    @Test
+    fun image_capture_volumeDown() = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+        mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+        filePrefix = FILE_PREFIX
+    ) {
+        // Wait for the capture button to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+        }
+        uiDevice.pressKeyCode(KeyEvent.KEYCODE_VOLUME_DOWN)
+
+        composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(IMAGE_CAPTURE_SUCCESS_TAG).isDisplayed()
+        }
+    }
+
     @Test
     fun image_capture_external() {
         val timeStamp = System.currentTimeMillis()
@@ -164,8 +199,9 @@ internal class ImageCaptureDeviceTest {
                     throw AssertionError(
                         "$VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG should not be present"
                     )
-                } catch (e: ComposeTimeoutException) { /*do nothing. we want to time out */ }
-
+                } catch (e: ComposeTimeoutException) {
+                    /*do nothing. we want to time out */
+                }
                 uiDevice.pressBack()
             }
         Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/SettingsDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/SettingsDeviceTest.kt
new file mode 100644
index 0000000..68372e2
--- /dev/null
+++ b/app/src/androidTest/java/com/google/jetpackcamera/SettingsDeviceTest.kt
@@ -0,0 +1,136 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+import android.util.Log
+import androidx.compose.ui.test.assertIsEnabled
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.performScrollTo
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.rule.GrantPermissionRule
+import androidx.test.uiautomator.By
+import androidx.test.uiautomator.UiDevice
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.SETTINGS_BUTTON
+import com.google.jetpackcamera.settings.ui.BTN_DIALOG_ASPECT_RATIO_OPTION_9_16_TAG
+import com.google.jetpackcamera.settings.ui.BTN_DIALOG_FLASH_OPTION_AUTO_TAG
+import com.google.jetpackcamera.settings.ui.BTN_DIALOG_FPS_OPTION_AUTO_TAG
+import com.google.jetpackcamera.settings.ui.BTN_DIALOG_STREAM_CONFIG_OPTION_SINGLE_STREAM_TAG
+import com.google.jetpackcamera.settings.ui.BTN_OPEN_DIALOG_SETTING_ASPECT_RATIO_TAG
+import com.google.jetpackcamera.settings.ui.BTN_OPEN_DIALOG_SETTING_FLASH_TAG
+import com.google.jetpackcamera.settings.ui.BTN_OPEN_DIALOG_SETTING_FPS_TAG
+import com.google.jetpackcamera.settings.ui.BTN_OPEN_DIALOG_SETTING_STREAM_CONFIG_TAG
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.runScenarioTest
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+private const val TAG = "SettingsDeviceTest"
+
+@RunWith(AndroidJUnit4::class)
+class SettingsDeviceTest {
+    @get:Rule
+    val permissionsRule: GrantPermissionRule =
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
+
+    private val instrumentation = InstrumentationRegistry.getInstrumentation()
+    private val uiDevice = UiDevice.getInstance(instrumentation)
+
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
+    private fun openSettings_clickSettingComponent_verifyDialog(
+        componentTestTag: String,
+        dialogTestTag: String,
+        componentDisabledMessage: String
+    ) = runScenarioTest<MainActivity> {
+        // Wait for the capture button to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+        }
+
+        // Navigate to the settings screen
+        composeTestRule.onNodeWithTag(SETTINGS_BUTTON)
+            .assertExists()
+            .performClick()
+
+        composeTestRule.onNodeWithTag(componentTestTag)
+            .assertExists()
+            .performScrollTo()
+
+        // Check if the settings dialog is displayed after the component is clicked
+        try {
+            composeTestRule.onNodeWithTag(componentTestTag)
+                .assertIsEnabled()
+            // Verify that UiAutomator object is also enabled
+            assert(uiDevice.findObject(By.res(componentTestTag)).isEnabled)
+
+            composeTestRule.onNodeWithTag(componentTestTag).performClick()
+            composeTestRule.onNodeWithTag(dialogTestTag)
+                .assertExists()
+            uiDevice.pressBack()
+        } catch (_: AssertionError) {
+            // Verify that UiAutomator object is also disabled
+            assert(!uiDevice.findObject(By.res(componentTestTag)).isEnabled)
+            // The settings component is disabled. Display componentDisabledMessage
+            Log.d(TAG, componentDisabledMessage)
+        } finally {
+            uiDevice.pressBack()
+        }
+    }
+
+    @Test
+    fun openSettings_openSetFlashModeDialog() = runScenarioTest<MainActivity> {
+        openSettings_clickSettingComponent_verifyDialog(
+            componentTestTag = BTN_OPEN_DIALOG_SETTING_FLASH_TAG,
+            dialogTestTag = BTN_DIALOG_FLASH_OPTION_AUTO_TAG,
+            componentDisabledMessage = "Flash mode component is disabled"
+        )
+    }
+
+    @Test
+    fun openSettings_openSetFrameRateDialog() = runScenarioTest<MainActivity> {
+        openSettings_clickSettingComponent_verifyDialog(
+            componentTestTag = BTN_OPEN_DIALOG_SETTING_FPS_TAG,
+            dialogTestTag = BTN_DIALOG_FPS_OPTION_AUTO_TAG,
+            componentDisabledMessage = "Frame rate component is disabled"
+        )
+    }
+
+    @Test
+    fun openSettings_openSetAspectRatioDialog() = runScenarioTest<MainActivity> {
+        openSettings_clickSettingComponent_verifyDialog(
+            componentTestTag = BTN_OPEN_DIALOG_SETTING_ASPECT_RATIO_TAG,
+            dialogTestTag = BTN_DIALOG_ASPECT_RATIO_OPTION_9_16_TAG,
+            componentDisabledMessage = "Aspect ratio component is disabled"
+        )
+    }
+
+    @Test
+    fun openSettings_openSetStreamConfigDialog() = runScenarioTest<MainActivity> {
+        openSettings_clickSettingComponent_verifyDialog(
+            componentTestTag = BTN_OPEN_DIALOG_SETTING_STREAM_CONFIG_TAG,
+            dialogTestTag = BTN_DIALOG_STREAM_CONFIG_OPTION_SINGLE_STREAM_TAG,
+            componentDisabledMessage = "Stream configuration component is disabled"
+        )
+    }
+}
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
index c4ff473..39ab778 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
@@ -28,6 +28,7 @@ import androidx.test.platform.app.InstrumentationRegistry
 import androidx.test.rule.GrantPermissionRule
 import androidx.test.uiautomator.UiDevice
 import com.google.common.truth.Truth
+import com.google.common.truth.Truth.assertThat
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
@@ -41,6 +42,7 @@ import com.google.jetpackcamera.utils.doesMediaExist
 import com.google.jetpackcamera.utils.getSingleImageCaptureIntent
 import com.google.jetpackcamera.utils.getTestUri
 import com.google.jetpackcamera.utils.longClickForVideoRecording
+import com.google.jetpackcamera.utils.pressAndDragToLockVideoRecording
 import com.google.jetpackcamera.utils.runMediaStoreAutoDeleteScenarioTest
 import com.google.jetpackcamera.utils.runScenarioTestForResult
 import com.google.jetpackcamera.utils.tapStartLockedVideoRecording
@@ -76,6 +78,30 @@ internal class VideoRecordingDeviceTest {
         deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
+    @Test
+    fun drag_to_lock_pressed_video_capture(): Unit =
+        runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+            mediaUri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
+        ) {
+            val timeStamp = System.currentTimeMillis()
+            // Wait for the capture button to be displayed
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+            }
+            composeTestRule.pressAndDragToLockVideoRecording()
+
+            // stop recording
+            // fixme: this shouldnt need two clicks
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).assertExists().performClick()
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).assertExists().performClick()
+
+            composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(VIDEO_CAPTURE_SUCCESS_TAG).isDisplayed()
+            }
+
+            deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
+        }
+
     @Test
     fun pressed_video_capture_external_intent() {
         val timeStamp = System.currentTimeMillis()
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
index 7561b1e..128e1e3 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
@@ -17,13 +17,16 @@ package com.google.jetpackcamera.utils
 
 import android.content.Context
 import androidx.annotation.StringRes
+import androidx.compose.ui.geometry.Offset
 import androidx.compose.ui.semantics.SemanticsProperties
 import androidx.compose.ui.test.ComposeTimeoutException
 import androidx.compose.ui.test.SemanticsMatcher
 import androidx.compose.ui.test.SemanticsNodeInteraction
 import androidx.compose.ui.test.SemanticsNodeInteractionsProvider
+import androidx.compose.ui.test.assertHasClickAction
 import androidx.compose.ui.test.isDisplayed
 import androidx.compose.ui.test.isEnabled
+import androidx.compose.ui.test.isNotDisplayed
 import androidx.compose.ui.test.junit4.ComposeTestRule
 import androidx.compose.ui.test.onNodeWithContentDescription
 import androidx.compose.ui.test.onNodeWithTag
@@ -32,10 +35,24 @@ import androidx.compose.ui.test.performClick
 import androidx.compose.ui.test.performTouchInput
 import androidx.compose.ui.test.printToString
 import androidx.test.core.app.ApplicationProvider
+import com.google.common.truth.Truth.assertThat
 import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_IMAGE_ONLY
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_OPTION_STANDARD
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_VIDEO_ONLY
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_BACKGROUND_FOCUSED
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_BACKGROUND_MAIN
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_HDR_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_MODE_TOGGLE_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_FAILURE_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import org.junit.AssumptionViolatedException
@@ -97,13 +114,65 @@ fun SemanticsNodeInteraction.assume(
     return this
 }
 
-fun ComposeTestRule.longClickForVideoRecording() {
+// ////////////////////////////
+//
+// idles
+//
+// ////////////////////////////
+fun ComposeTestRule.waitForStartup(timeoutMillis: Long = APP_START_TIMEOUT_MILLIS) {
+    // Wait for the capture button to be displayed
+    waitUntil(timeoutMillis = timeoutMillis) {
+        onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+    }
+}
+fun ComposeTestRule.waitForNodeWithTag(tag: String, timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS) {
+    waitUntil(timeoutMillis = timeoutMillis) { onNodeWithTag(tag).isDisplayed() }
+}
+private fun ComposeTestRule.idleForVideoDuration(
+    durationMillis: Long = VIDEO_DURATION_MILLIS,
+    earlyExitPredicate: () -> Boolean = {
+        // If the video capture fails, there is no point to continue the recording, so stop idling
+        onNodeWithTag(VIDEO_CAPTURE_FAILURE_TAG).isDisplayed()
+    }
+) {
+    // TODO: replace with a check for the timestamp UI of the video duration
+    try {
+        waitUntil(timeoutMillis = durationMillis) {
+            earlyExitPredicate()
+        }
+    } catch (_: ComposeTimeoutException) {
+    }
+}
+
+// ////////////////////////////
+//
+// capture control
+//
+// ////////////////////////////
+
+fun ComposeTestRule.pressAndDragToLockVideoRecording() {
     onNodeWithTag(CAPTURE_BUTTON)
         .assertExists()
         .performTouchInput {
             down(center)
+            moveBy(delta = Offset(-400f, 0f), delayMillis = VIDEO_DURATION_MILLIS)
+            up()
         }
-    idleForVideoDuration()
+    try {
+        waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+            onNodeWithTag(VIDEO_CAPTURE_SUCCESS_TAG).isDisplayed()
+        }
+        throw AssertionError("$VIDEO_CAPTURE_SUCCESS_TAG should not be displayed.")
+    } catch (e: ComposeTimeoutException) { /* do nothing. success tag should not have displayed*/ }
+}
+
+fun ComposeTestRule.longClickForVideoRecording(durationMillis: Long = VIDEO_DURATION_MILLIS) {
+    onNodeWithTag(CAPTURE_BUTTON)
+        .assertExists()
+        .performTouchInput {
+            down(center)
+        }
+    idleForVideoDuration(durationMillis)
     onNodeWithTag(CAPTURE_BUTTON)
         .assertExists()
         .performTouchInput {
@@ -112,22 +181,105 @@ fun ComposeTestRule.longClickForVideoRecording() {
 }
 
 fun ComposeTestRule.tapStartLockedVideoRecording() {
+    assertThat(getCurrentCaptureMode()).isEqualTo(CaptureMode.VIDEO_ONLY)
     onNodeWithTag(CAPTURE_BUTTON)
         .assertExists()
         .performClick()
     idleForVideoDuration()
 }
 
-private fun ComposeTestRule.idleForVideoDuration() {
-    // TODO: replace with a check for the timestamp UI of the video duration
-    try {
-        waitUntil(timeoutMillis = VIDEO_DURATION_MILLIS) {
-            onNodeWithTag("dummyTagForLongPress").isDisplayed()
+// //////////////////////
+//
+// check preview state
+//
+// ///////////////////////
+
+/**
+ * checks if the hdr capture mode toggle is enabled
+ */
+fun ComposeTestRule.isHdrToggleEnabled(): Boolean =
+    checkComponentStateDescriptionState<Boolean>(CAPTURE_MODE_TOGGLE_BUTTON) { description ->
+        when (description) {
+            getResString(R.string.capture_mode_image_capture_content_description),
+            getResString(R.string.capture_mode_video_recording_content_description) ->
+                return@checkComponentStateDescriptionState true
+
+            getResString(
+                R.string.capture_mode_image_capture_content_description_disabled
+            ), getResString(
+                R.string.capture_mode_video_recording_content_description_disabled
+            ) -> return@checkComponentStateDescriptionState false
+
+            else -> false
+        }
+    }
+
+/**
+ * Returns the current state of the capture mode toggle button
+ */
+fun ComposeTestRule.getHdrToggleState(): CaptureMode =
+    checkComponentStateDescriptionState(CAPTURE_MODE_TOGGLE_BUTTON) { description ->
+        when (description) {
+            getResString(R.string.capture_mode_image_capture_content_description),
+            getResString(
+                R.string.capture_mode_image_capture_content_description_disabled
+            ) ->
+                CaptureMode.IMAGE_ONLY
+            getResString(R.string.capture_mode_video_recording_content_description),
+            getResString(
+                R.string.capture_mode_video_recording_content_description_disabled
+            ) ->
+                CaptureMode.VIDEO_ONLY
+            else -> null
         }
-    } catch (e: ComposeTimeoutException) {
     }
+
+// //////////////////////
+//
+// check current quick settings state
+//
+// ///////////////////////
+inline fun <reified T> ComposeTestRule.checkComponentContentDescriptionState(
+    nodeTag: String,
+    crossinline block: (String) -> T?
+): T {
+    waitForNodeWithTag(nodeTag)
+    onNodeWithTag(nodeTag).assume(isEnabled())
+        .fetchSemanticsNode().let { node ->
+            node.config[SemanticsProperties.ContentDescription].any { description ->
+                block(description)?.let { result ->
+                    // Return the T value if block returns non-null.
+                    return@checkComponentContentDescriptionState result
+                } ?: false
+            }
+            throw AssertionError("Unable to determine state from quick settingz")
+        }
 }
 
+inline fun <reified T> ComposeTestRule.checkComponentStateDescriptionState(
+    nodeTag: String,
+    crossinline block: (String) -> T?
+): T {
+    waitForNodeWithTag(nodeTag)
+    onNodeWithTag(nodeTag).assume(isEnabled())
+        .fetchSemanticsNode().let { node ->
+            block(node.config[SemanticsProperties.StateDescription])?.let { result ->
+                // Return the T value if block returns non-null.
+                return@checkComponentStateDescriptionState result
+            } ?: false
+            throw AssertionError("Unable to determine state from component")
+        }
+}
+fun ComposeTestRule.isHdrEnabled(): Boolean =
+    checkComponentContentDescriptionState<Boolean>(QUICK_SETTINGS_HDR_BUTTON) { description ->
+        when (description) {
+            getResString(R.string.quick_settings_dynamic_range_hdr_description) -> {
+                return@checkComponentContentDescriptionState true
+            } getResString(R.string.quick_settings_dynamic_range_sdr_description) -> {
+                return@checkComponentContentDescriptionState false
+            } else -> null
+        }
+    }
 fun ComposeTestRule.getCurrentLensFacing(): LensFacing = visitQuickSettings {
     onNodeWithTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON).fetchSemanticsNode(
         "Flip camera button is not visible when expected."
@@ -165,9 +317,61 @@ fun ComposeTestRule.getCurrentFlashMode(): FlashMode = visitQuickSettings {
         throw AssertionError("Unable to determine flash mode from quick settings")
     }
 }
+fun ComposeTestRule.getConcurrentState(): ConcurrentCameraMode = visitQuickSettings {
+    onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+        .assertExists()
+        .fetchSemanticsNode(
+            "Concurrent camera button is not visible when expected."
+        ).let { node ->
+            node.config[SemanticsProperties.ContentDescription].any { description ->
+                when (description) {
+                    getResString(R.string.quick_settings_description_concurrent_camera_off) -> {
+                        return@let ConcurrentCameraMode.OFF
+                    } getResString(
+                        R.string.quick_settings_description_concurrent_camera_dual
+                    ) ->
+                        return@let ConcurrentCameraMode.DUAL
+                    else -> false
+                }
+            }
+            throw AssertionError(
+                "Unable to determine concurrent camera mode from quick settings"
+            )
+        }
+}
+fun ComposeTestRule.getCurrentCaptureMode(): CaptureMode = visitQuickSettings {
+    waitUntil(timeoutMillis = 1000) {
+        onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE).isDisplayed()
+    }
+    onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE).fetchSemanticsNode(
+        "Capture mode button is not visible when expected."
+    ).let { node ->
+        node.config[SemanticsProperties.ContentDescription].any { description ->
+            // check description is one of the capture modes
+            when (description) {
+                getResString(R.string.quick_settings_description_capture_mode_standard) ->
+                    return@let CaptureMode.STANDARD
+                getResString(R.string.quick_settings_description_capture_mode_image_only) ->
+                    return@let CaptureMode.IMAGE_ONLY
+                getResString(R.string.quick_settings_description_capture_mode_video_only) ->
+                    return@let CaptureMode.VIDEO_ONLY
+                else -> false
+            }
+        }
+        throw (AssertionError("unable to determine capture mode from quick settings"))
+    }
+}
+
+// ////////////////////////////
+//
+// Quick Settings Interaction
+//
+// ////////////////////////////
 
-// Navigates to quick settings if not already there and perform action from provided block.
-// This will return from quick settings if not already there, or remain on quick settings if there.
+/**
+ * Navigates to quick settings if not already there and perform action from provided block.
+ * This will return from quick settings if not already there, or remain on quick settings if there.
+*/
 inline fun <T> ComposeTestRule.visitQuickSettings(crossinline block: ComposeTestRule.() -> T): T {
     var needReturnFromQuickSettings = false
     onNodeWithContentDescription(R.string.quick_settings_dropdown_closed_description).apply {
@@ -188,6 +392,88 @@ inline fun <T> ComposeTestRule.visitQuickSettings(crossinline block: ComposeTest
             onNodeWithContentDescription(R.string.quick_settings_dropdown_open_description)
                 .assertExists()
                 .performClick()
+
+            waitUntil(timeoutMillis = DEFAULT_TIMEOUT_MILLIS) {
+                onNodeWithTag(QUICK_SETTINGS_BACKGROUND_MAIN).isNotDisplayed()
+            }
+        }
+    }
+}
+
+/**
+ * closes expanded quick setting if open to return to main quick settings menu
+ */
+fun ComposeTestRule.unFocusQuickSetting() {
+    // this will click the center of the composable... which may coincide with another composable.
+    // so we offset click input out of the way
+    onNodeWithTag(QUICK_SETTINGS_BACKGROUND_FOCUSED)
+        .assertExists()
+        .assertHasClickAction()
+        .performTouchInput { down(centerLeft) }
+        .performTouchInput { up() }
+
+    this
+        .waitUntil(timeoutMillis = 2_000) {
+            onNodeWithTag(QUICK_SETTINGS_BACKGROUND_MAIN).isDisplayed()
+        }
+}
+
+// ////////////////////////////
+//
+// Apply Quick Settings
+//
+// ////////////////////////////
+fun ComposeTestRule.setHdrEnabled(enabled: Boolean) {
+    visitQuickSettings {
+        if (isHdrEnabled() != enabled) {
+            onNodeWithTag(QUICK_SETTINGS_HDR_BUTTON)
+                .assume(isEnabled()) { "Device does not support HDR." }
+                .performClick()
+        }
+        waitUntil(1000) { isHdrEnabled() == enabled }
+    }
+}
+fun ComposeTestRule.setConcurrentCameraMode(concurrentMode: ConcurrentCameraMode) {
+    visitQuickSettings {
+        waitForNodeWithTag(tag = QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+        onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+            .assume(isEnabled()) { "Device does not support concurrent camera." }
+            .let {
+                if (getConcurrentState() != concurrentMode) {
+                    it.assertExists().performClick()
+                }
+            }
+        waitUntil(1_000) { getConcurrentState() == concurrentMode }
+    }
+}
+fun ComposeTestRule.setCaptureMode(captureMode: CaptureMode) {
+    visitQuickSettings {
+        waitUntil(timeoutMillis = 1000) {
+            onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE).isDisplayed()
+        }
+        // check that current capture mode != given capture mode
+        if (getCurrentCaptureMode() != captureMode) {
+            val optionButtonTag = when (captureMode) {
+                CaptureMode.STANDARD -> BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_OPTION_STANDARD
+                CaptureMode.IMAGE_ONLY -> BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_IMAGE_ONLY
+                CaptureMode.VIDEO_ONLY -> BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_VIDEO_ONLY
+            }
+            // focus setting
+            onNodeWithTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE).assertExists()
+                .assume(isEnabled())
+                .performClick()
+
+            waitUntil(timeoutMillis = 1_000) {
+                onNodeWithTag(optionButtonTag).isDisplayed()
+            }
+
+            // click option button
+            onNodeWithTag(optionButtonTag).assertExists().performClick()
+
+            unFocusQuickSetting()
+        }
+        if (getCurrentCaptureMode() != captureMode) {
+            throw AssertionError("Unable to set capture mode to $captureMode")
         }
     }
 }
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
index c403f2c..af730ca 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
@@ -56,12 +56,15 @@ import org.junit.rules.TestRule
 import org.junit.runner.Description
 import org.junit.runners.model.Statement
 
+const val DEFAULT_TIMEOUT_MILLIS = 1_000L
 const val APP_START_TIMEOUT_MILLIS = 10_000L
+const val SETTINGS_SCREEN_NAVIGATION_TIMEOUT_MILLIS = 5_000L
 const val SCREEN_FLASH_OVERLAY_TIMEOUT_MILLIS = 5_000L
 const val IMAGE_CAPTURE_TIMEOUT_MILLIS = 5_000L
 const val VIDEO_CAPTURE_TIMEOUT_MILLIS = 5_000L
 const val VIDEO_DURATION_MILLIS = 3_000L
 const val MESSAGE_DISAPPEAR_TIMEOUT_MILLIS = 15_000L
+const val FILE_PREFIX = "JCA"
 const val VIDEO_PREFIX = "video"
 const val IMAGE_PREFIX = "image"
 const val COMPONENT_PACKAGE_NAME = "com.google.jetpackcamera"
diff --git a/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt b/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
index e66f510..70f0f75 100644
--- a/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
+++ b/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
@@ -16,7 +16,6 @@
 package com.google.jetpackcamera.ui
 
 import android.Manifest
-import android.net.Uri
 import androidx.compose.animation.AnimatedContentTransitionScope
 import androidx.compose.animation.core.EaseIn
 import androidx.compose.animation.core.EaseOut
@@ -27,11 +26,9 @@ import androidx.compose.runtime.Composable
 import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.ui.Modifier
 import androidx.navigation.NavHostController
-import androidx.navigation.NavType
 import androidx.navigation.compose.NavHost
 import androidx.navigation.compose.composable
 import androidx.navigation.compose.rememberNavController
-import androidx.navigation.navArgument
 import com.google.accompanist.permissions.ExperimentalPermissionsApi
 import com.google.accompanist.permissions.isGranted
 import com.google.accompanist.permissions.rememberMultiplePermissionsState
@@ -118,11 +115,7 @@ private fun JetpackCameraNavHost(
             }
             PreviewScreen(
                 onNavigateToSettings = { navController.navigate(SETTINGS_ROUTE) },
-                onNavigateToPostCapture = { imageUri ->
-                    navController.navigate(
-                        "$POST_CAPTURE_ROUTE?imageUri=${Uri.encode(imageUri.toString())}"
-                    )
-                },
+                onNavigateToPostCapture = { navController.navigate(POST_CAPTURE_ROUTE) },
                 onRequestWindowColorMode = onRequestWindowColorMode,
                 onFirstFrameCaptureCompleted = onFirstFrameCaptureCompleted,
                 previewMode = previewMode,
@@ -156,26 +149,9 @@ private fun JetpackCameraNavHost(
         }
 
         composable(
-            "$POST_CAPTURE_ROUTE?imageUri={imageUri}",
-            arguments = listOf(
-                navArgument("imageUri") {
-                    type = NavType.StringType
-                    defaultValue = ""
-                }
-            )
-        ) { backStackEntry ->
-            val imageUriString = backStackEntry.arguments?.getString("imageUri")
-
-            val imageUri = if (!imageUriString.isNullOrEmpty()) {
-                Uri.parse(
-                    imageUriString
-                )
-            } else {
-                null
-            }
-            PostCaptureScreen(
-                imageUri = imageUri
-            )
+            POST_CAPTURE_ROUTE
+        ) {
+            PostCaptureScreen()
         }
     }
 }
diff --git a/build.gradle.kts b/build.gradle.kts
index 982992f..8a5a2d2 100644
--- a/build.gradle.kts
+++ b/build.gradle.kts
@@ -22,7 +22,7 @@ plugins {
     alias(libs.plugins.kotlin.android) apply false
     alias(libs.plugins.dagger.hilt.android) apply false
     alias(libs.plugins.kotlin.kapt) apply false
-
+        alias(libs.plugins.compose.compiler) apply false
 }
 
 tasks.register<Copy>("installGitHooks") {
diff --git a/core/camera/Android.bp b/core/camera/Android.bp
index ddd01b9..11ee0d8 100644
--- a/core/camera/Android.bp
+++ b/core/camera/Android.bp
@@ -24,4 +24,7 @@ android_library {
     kotlincflags: [
         "-Xcontext-receivers",
     ],
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
index 08103b6..0761d84 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
@@ -102,6 +102,8 @@ import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onCompletion
+import kotlinx.coroutines.flow.transform
 import kotlinx.coroutines.flow.update
 import kotlinx.coroutines.launch
 
@@ -120,10 +122,10 @@ internal suspend fun runSingleCameraSession(
     onImageCaptureCreated: (ImageCapture) -> Unit = {}
 ) = coroutineScope {
     Log.d(TAG, "Starting new single camera session")
-
     val initialCameraSelector = transientSettings.filterNotNull().first()
         .primaryLensFacing.toCameraSelector()
 
+    // only create video use case in standard or video_only
     val videoCaptureUseCase = when (sessionSettings.captureMode) {
         CaptureMode.STANDARD, CaptureMode.VIDEO_ONLY ->
             createVideoUseCase(
@@ -150,80 +152,132 @@ internal suspend fun runSingleCameraSession(
         )
     }
 
-    transientSettings.filterNotNull().distinctUntilChanged { old, new ->
-        old.primaryLensFacing == new.primaryLensFacing
-    }.collectLatest { currentTransientSettings ->
-        cameraProvider.unbindAll()
-        val currentCameraSelector = currentTransientSettings.primaryLensFacing.toCameraSelector()
-        val useCaseGroup = createUseCaseGroup(
-            cameraInfo = cameraProvider.getCameraInfo(currentCameraSelector),
-            videoCaptureUseCase = videoCaptureUseCase,
-            initialTransientSettings = currentTransientSettings,
-            stabilizationMode = sessionSettings.stabilizationMode,
-            aspectRatio = sessionSettings.aspectRatio,
-            dynamicRange = sessionSettings.dynamicRange,
-            imageFormat = sessionSettings.imageFormat,
-            captureMode = sessionSettings.captureMode,
-            effect = when (sessionSettings.streamConfig) {
-                StreamConfig.SINGLE_STREAM -> SingleSurfaceForcingEffect(this@coroutineScope)
-                StreamConfig.MULTI_STREAM -> null
+    transientSettings
+        .filterNotNull()
+        .distinctUntilChanged { old, new -> old.primaryLensFacing == new.primaryLensFacing }
+        .collectLatest { currentTransientSettings ->
+            cameraProvider.unbindAll()
+            val currentCameraSelector = currentTransientSettings.primaryLensFacing
+                .toCameraSelector()
+            val useCaseGroup = createUseCaseGroup(
+                cameraInfo = cameraProvider.getCameraInfo(currentCameraSelector),
+                videoCaptureUseCase = videoCaptureUseCase,
+                initialTransientSettings = currentTransientSettings,
+                stabilizationMode = sessionSettings.stabilizationMode,
+                aspectRatio = sessionSettings.aspectRatio,
+                dynamicRange = sessionSettings.dynamicRange,
+                imageFormat = sessionSettings.imageFormat,
+                captureMode = sessionSettings.captureMode,
+                effect = when (sessionSettings.streamConfig) {
+                    StreamConfig.SINGLE_STREAM -> SingleSurfaceForcingEffect(this@coroutineScope)
+                    StreamConfig.MULTI_STREAM -> null
+                }
+            ).apply {
+                getImageCapture()?.let(onImageCaptureCreated)
             }
-        ).apply {
-            getImageCapture()?.let(onImageCaptureCreated)
-        }
 
-        cameraProvider.runWith(
-            currentCameraSelector,
-            useCaseGroup
-        ) { camera ->
-            Log.d(TAG, "Camera session started")
-
-            launch {
-                processFocusMeteringEvents(camera.cameraControl)
-            }
+            cameraProvider.runWith(
+                currentCameraSelector,
+                useCaseGroup
+            ) { camera ->
+                Log.d(TAG, "Camera session started")
+                launch {
+                    processFocusMeteringEvents(camera.cameraControl)
+                }
 
-            launch {
-                camera.cameraInfo.torchState.asFlow().collectLatest { torchState ->
-                    currentCameraState.update { old ->
-                        old.copy(torchEnabled = torchState == TorchState.ON)
+                launch {
+                    camera.cameraInfo.torchState.asFlow().collectLatest { torchState ->
+                        currentCameraState.update { old ->
+                            old.copy(torchEnabled = torchState == TorchState.ON)
+                        }
                     }
                 }
-            }
 
-            if (videoCaptureUseCase != null) {
-                val videoQuality = getVideoQualityFromResolution(
-                    videoCaptureUseCase.resolutionInfo?.resolution
-                )
-                if (videoQuality != sessionSettings.videoQuality) {
-                    Log.e(
-                        TAG,
-                        "Failed to select video quality: $sessionSettings.videoQuality. " +
-                            "Fallback: $videoQuality"
+                if (videoCaptureUseCase != null) {
+                    val videoQuality = getVideoQualityFromResolution(
+                        videoCaptureUseCase.resolutionInfo?.resolution
                     )
-                }
-                launch {
-                    currentCameraState.update { old ->
-                        old.copy(
-                            videoQualityInfo = VideoQualityInfo(
-                                videoQuality,
-                                getWidthFromCropRect(videoCaptureUseCase.resolutionInfo?.cropRect),
-                                getHeightFromCropRect(videoCaptureUseCase.resolutionInfo?.cropRect)
-                            )
+                    if (videoQuality != sessionSettings.videoQuality) {
+                        Log.e(
+                            TAG,
+                            "Failed to select video quality: $sessionSettings.videoQuality. " +
+                                "Fallback: $videoQuality"
                         )
                     }
+                    launch {
+                        currentCameraState.update { old ->
+                            old.copy(
+                                videoQualityInfo = VideoQualityInfo(
+                                    videoQuality,
+                                    getWidthFromCropRect(
+                                        videoCaptureUseCase.resolutionInfo?.cropRect
+                                    ),
+                                    getHeightFromCropRect(
+                                        videoCaptureUseCase.resolutionInfo?.cropRect
+                                    )
+                                )
+                            )
+                        }
+                    }
                 }
-            }
 
-            applyDeviceRotation(currentTransientSettings.deviceRotation, useCaseGroup)
-            setZoomScale(camera, 1f)
-            processTransientSettingEvents(
-                camera,
-                useCaseGroup,
-                currentTransientSettings,
-                transientSettings
-            )
+                // update camerastate to mirror current zoomstate
+
+                launch {
+                    camera.cameraInfo.zoomState
+                        .asFlow()
+                        .filterNotNull()
+                        .distinctUntilChanged()
+                        .onCompletion {
+                            // reset current camera state when changing cameras.
+                            currentCameraState.update { old ->
+                                old.copy(
+                                    zoomRatios = emptyMap(),
+                                    linearZoomScales = emptyMap()
+                                )
+                            }
+                        }
+                        .collectLatest { zoomState ->
+                            // TODO(b/405987189): remove checks after buggy zoomState is fixed
+                            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
+                                if (zoomState.zoomRatio != 1.0f ||
+                                    zoomState.zoomRatio == currentTransientSettings
+                                        .zoomRatios[currentTransientSettings.primaryLensFacing]
+                                ) {
+                                    currentCameraState.update { old ->
+                                        old.copy(
+                                            zoomRatios = old.zoomRatios
+                                                .toMutableMap()
+                                                .apply {
+                                                    put(
+                                                        camera.cameraInfo.appLensFacing,
+                                                        zoomState.zoomRatio
+                                                    )
+                                                }.toMap(),
+                                            linearZoomScales = old.linearZoomScales
+                                                .toMutableMap()
+                                                .apply {
+                                                    put(
+                                                        camera.cameraInfo.appLensFacing,
+                                                        zoomState.linearZoom
+                                                    )
+                                                }.toMap()
+                                        )
+                                    }
+                                }
+                            }
+                        }
+                }
+
+                applyDeviceRotation(currentTransientSettings.deviceRotation, useCaseGroup)
+                processTransientSettingEvents(
+                    camera,
+                    useCaseGroup,
+                    currentTransientSettings,
+                    transientSettings
+                )
+            }
         }
-    }
 }
 
 context(CameraSessionContext)
@@ -234,6 +288,10 @@ internal suspend fun processTransientSettingEvents(
     initialTransientSettings: TransientSessionSettings,
     transientSettings: StateFlow<TransientSessionSettings?>
 ) {
+    // Immediately Apply camera zoom from current settings when opening a new camera
+    camera.cameraControl.setZoomRatio(
+        initialTransientSettings.zoomRatios[camera.cameraInfo.appLensFacing] ?: 1f
+    )
     var prevTransientSettings = initialTransientSettings
     val isFrontFacing = camera.cameraInfo.appLensFacing == LensFacing.FRONT
     var torchOn = false
@@ -245,22 +303,16 @@ internal suspend fun processTransientSettingEvents(
     }
     combine(
         transientSettings.filterNotNull(),
-        currentCameraState.asStateFlow()
-    ) { newTransientSettings, cameraState ->
-        return@combine Pair(newTransientSettings, cameraState)
-    }.collectLatest {
-        val newTransientSettings = it.first
-        val cameraState = it.second
-
-        // Apply camera zoom
-        if (prevTransientSettings.zoomScale != newTransientSettings.zoomScale
-        ) {
-            setZoomScale(camera, newTransientSettings.zoomScale)
-        }
-
-        // todo(): How should we handle torch on Auto FlashMode?
+        currentCameraState.asStateFlow().transform { emit(it.videoRecordingState) }
+    ) { newTransientSettings, videoRecordingState ->
+        return@combine Pair(newTransientSettings, videoRecordingState)
+    }.collect { transientPair ->
+        val newTransientSettings = transientPair.first
+        val videoRecordingState = transientPair.second
+
+        // todo(): handle torch on Auto FlashMode
         // enable torch only while recording is in progress
-        if ((cameraState.videoRecordingState !is VideoRecordingState.Inactive) &&
+        if ((videoRecordingState !is VideoRecordingState.Inactive) &&
             newTransientSettings.flashMode == FlashMode.ON &&
             !isFrontFacing
         ) {
@@ -314,25 +366,16 @@ internal suspend fun processTransientSettingEvents(
             applyDeviceRotation(newTransientSettings.deviceRotation, useCaseGroup)
         }
 
-        prevTransientSettings = newTransientSettings
-    }
-}
-
-context(CameraSessionContext)
-internal fun setZoomScale(camera: Camera, zoomScaleRelative: Float) {
-    camera.cameraInfo.zoomState.value?.let { zoomState ->
-        transientSettings.value?.let { transientSettings ->
-            val finalScale =
-                (zoomScale.value * zoomScaleRelative).coerceIn(
-                    zoomState.minZoomRatio,
-                    zoomState.maxZoomRatio
-                )
-            camera.cameraControl.setZoomRatio(finalScale)
-            zoomScale.update { finalScale }
-            currentCameraState.update { old ->
-                old.copy(zoomScale = finalScale)
+        // setzoomratio when the primary zoom value changes.
+        if (prevTransientSettings.primaryLensFacing == newTransientSettings.primaryLensFacing &&
+            prevTransientSettings.zoomRatios[prevTransientSettings.primaryLensFacing] !=
+            newTransientSettings.zoomRatios[newTransientSettings.primaryLensFacing]
+        ) {
+            newTransientSettings.primaryLensFacing.let {
+                camera.cameraControl.setZoomRatio(newTransientSettings.zoomRatios[it] ?: 1f)
             }
         }
+        prevTransientSettings = newTransientSettings
     }
 }
 
@@ -377,6 +420,8 @@ internal fun createUseCaseGroup(
             aspectRatio,
             stabilizationMode
         )
+
+    // only create image use case in image or standard
     val imageCaptureUseCase = if (captureMode != CaptureMode.VIDEO_ONLY) {
         createImageUseCase(cameraInfo, aspectRatio, dynamicRange, imageFormat)
     } else {
@@ -404,20 +449,10 @@ internal fun createUseCaseGroup(
             ).build()
         )
         addUseCase(previewUseCase)
-        imageCaptureUseCase?.let {
-            if (dynamicRange == DynamicRange.SDR ||
-                imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
-            ) {
-                addUseCase(imageCaptureUseCase)
-            }
-        }
 
-        // Not to bind VideoCapture when Ultra HDR is enabled to keep the app design simple.
-        videoCaptureUseCase?.let {
-            if (imageFormat == ImageOutputFormat.JPEG) {
-                addUseCase(videoCaptureUseCase)
-            }
-        }
+        // image and video use cases are only created if supported by the configuration
+        imageCaptureUseCase?.let { addUseCase(imageCaptureUseCase) }
+        videoCaptureUseCase?.let { addUseCase(videoCaptureUseCase) }
 
         effect?.let { addEffect(it) }
     }.build()
@@ -708,8 +743,6 @@ private suspend fun startVideoRecordingInternal(
     maxDurationMillis: Long,
     onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
 ): Recording {
-    Log.d(TAG, "recordVideo")
-    // todo(b/336886716): default setting to enable or disable audio when permission is granted
     // set the camerastate to starting
     currentCameraState.update { old ->
         old.copy(videoRecordingState = VideoRecordingState.Starting)
@@ -882,7 +915,8 @@ private suspend fun runVideoRecording(
     videoCaptureUri: Uri?,
     videoControlEvents: Channel<VideoCaptureControlEvent>,
     shouldUseUri: Boolean,
-    onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+    onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit,
+    onRestoreSettings: () -> Unit = {}
 ) = coroutineScope {
     var currentSettings = transientSettings.filterNotNull().first()
 
@@ -933,6 +967,7 @@ private suspend fun runVideoRecording(
                 }
             }
         }
+        onRestoreSettings()
     }
 }
 
@@ -983,7 +1018,8 @@ internal suspend fun processVideoControlEvents(
                     event.videoCaptureUri,
                     videoCaptureControlEvents,
                     event.shouldUseUri,
-                    event.onVideoRecord
+                    event.onVideoRecord,
+                    event.onRestoreSettings
                 )
             }
 
@@ -1026,8 +1062,36 @@ private fun Preview.Builder.updateCameraStateWithCaptureResults(
                         }
                     }
                 }
-
                 val logicalCameraId = session.device.id
+
+                // todo(b/405987189): remove completely after buggy zoomState is fixed
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
+                    logicalCameraId == targetCameraLogicalId
+                ) {
+                    // update camerastate with zoom ratio
+                    val newZoomRatio = result.get(CaptureResult.CONTROL_ZOOM_RATIO)
+                    currentCameraState.update { old ->
+                        if (newZoomRatio != null &&
+                            old.zoomRatios[targetCameraInfo.appLensFacing] != newZoomRatio
+                        ) {
+                            Log.d(
+                                TAG,
+                                "newZoomRatio: $newZoomRatio on lens ${targetCameraInfo.appLensFacing}"
+                            )
+
+                            old.copy(
+                                zoomRatios = old.zoomRatios
+                                    .toMutableMap()
+                                    .apply {
+                                        put(targetCameraInfo.appLensFacing, newZoomRatio)
+                                    }.toMap()
+                            )
+                        } else {
+                            old
+                        }
+                    }
+                }
+
                 if (logicalCameraId != targetCameraLogicalId) return
                 try {
                     val physicalCameraId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
index e28d49a..1425bbb 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
@@ -39,6 +39,5 @@ internal data class CameraSessionContext(
     val videoCaptureControlEvents: Channel<VideoCaptureControlEvent>,
     val currentCameraState: MutableStateFlow<CameraState>,
     val surfaceRequests: MutableStateFlow<SurfaceRequest?>,
-    val transientSettings: StateFlow<TransientSessionSettings?>,
-    var zoomScale: MutableStateFlow<Float>
+    val transientSettings: StateFlow<TransientSessionSettings?>
 )
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
index 2a9fa4d..f104c8a 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
@@ -72,6 +72,6 @@ internal data class TransientSessionSettings(
     val isAudioEnabled: Boolean,
     val deviceRotation: DeviceRotation,
     val flashMode: FlashMode,
-    val zoomScale: Float,
-    val primaryLensFacing: LensFacing
+    val primaryLensFacing: LensFacing,
+    val zoomRatios: Map<LensFacing, Float>
 )
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
index 881953c..027d879 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
@@ -21,6 +21,7 @@ import androidx.camera.core.ImageCapture
 import androidx.camera.core.SurfaceRequest
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DeviceRotation
@@ -86,7 +87,7 @@ interface CameraUseCase {
 
     suspend fun stopVideoRecording()
 
-    fun setZoomScale(scale: Float)
+    fun changeZoomRatio(newZoomState: CameraZoomRatio)
 
     fun getCurrentCameraState(): StateFlow<CameraState>
 
@@ -186,7 +187,8 @@ sealed interface VideoRecordingState {
 
 data class CameraState(
     val videoRecordingState: VideoRecordingState = VideoRecordingState.Inactive(),
-    val zoomScale: Float = 1f,
+    val zoomRatios: Map<LensFacing, Float> = mapOf(),
+    val linearZoomScales: Map<LensFacing, Float> = mapOf(),
     val sessionFirstFrameTimestamp: Long = 0L,
     val torchEnabled: Boolean = false,
     val stabilizationMode: StabilizationMode = StabilizationMode.OFF,
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
index 3bff09c..78e851c 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
@@ -23,6 +23,7 @@ import android.os.Build
 import android.os.Environment
 import android.provider.MediaStore
 import android.util.Log
+import android.util.Range
 import androidx.camera.core.CameraInfo
 import androidx.camera.core.DynamicRange as CXDynamicRange
 import androidx.camera.core.ImageCapture
@@ -43,6 +44,7 @@ import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CameraConstraints
 import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_15
 import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_60
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DeviceRotation
@@ -51,10 +53,12 @@ import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.Illuminant
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.LensToZoom
 import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.SystemConstraints
 import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.ZoomChange
 import com.google.jetpackcamera.settings.model.forCurrentLens
 import dagger.hilt.android.scopes.ViewModelScoped
 import java.io.File
@@ -110,9 +114,11 @@ constructor(
 
     private val currentSettings = MutableStateFlow<CameraAppSettings?>(null)
 
+    private val zoomChanges = MutableStateFlow<CameraZoomRatio?>(null)
+
     // Could be improved by setting initial value only when camera is initialized
-    private var _currentCameraState = MutableStateFlow(CameraState())
-    override fun getCurrentCameraState(): StateFlow<CameraState> = _currentCameraState.asStateFlow()
+    private var currentCameraState = MutableStateFlow(CameraState())
+    override fun getCurrentCameraState(): StateFlow<CameraState> = currentCameraState.asStateFlow()
 
     private val _surfaceRequest = MutableStateFlow<SurfaceRequest?>(null)
 
@@ -161,6 +167,9 @@ constructor(
                                     put(dynamicRange, supportedVideoQualities)
                                 }
                             }
+                        val zoomState = camInfo.zoomState.value
+                        val supportedZoomRange: Range<Float>? =
+                            zoomState?.let { Range(it.minZoomRatio, it.maxZoomRatio) }
 
                         val supportedStabilizationModes = buildSet {
                             if (camInfo.isPreviewStabilizationSupported) {
@@ -242,6 +251,7 @@ constructor(
                                 supportedVideoQualitiesMap = supportedVideoQualitiesMap,
                                 supportedIlluminants = supportedIlluminants,
                                 supportedFlashModes = supportedFlashModes,
+                                supportedZoomRange = supportedZoomRange,
                                 unsupportedStabilizationFpsMap = unsupportedStabilizationFpsMap
                             )
                         )
@@ -261,6 +271,7 @@ constructor(
                 .tryApplyStabilizationConstraints()
                 .tryApplyConcurrentCameraModeConstraints()
                 .tryApplyFlashModeConstraints()
+                .tryApplyCaptureModeConstraints()
                 .tryApplyVideoQualityConstraints()
                 .tryApplyCaptureModeConstraints()
         if (isDebugMode && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
@@ -284,8 +295,6 @@ constructor(
         Log.d(TAG, "runCamera")
 
         val transientSettings = MutableStateFlow<TransientSessionSettings?>(null)
-        val cameraSessionZoomScale = MutableStateFlow(1f)
-        var prevCameraSessionLensFacing: LensFacing? = null
         currentSettings
             .filterNotNull()
             .map { currentCameraSettings ->
@@ -294,7 +303,7 @@ constructor(
                     deviceRotation = currentCameraSettings.deviceRotation,
                     flashMode = currentCameraSettings.flashMode,
                     primaryLensFacing = currentCameraSettings.cameraLensFacing,
-                    zoomScale = currentCameraSettings.zoomScale
+                    zoomRatios = currentCameraSettings.defaultZoomRatios
                 )
 
                 when (currentCameraSettings.concurrentCameraMode) {
@@ -352,10 +361,6 @@ constructor(
                 }
             }.distinctUntilChanged()
             .collectLatest { sessionSettings ->
-                if (transientSettings.value?.primaryLensFacing != prevCameraSessionLensFacing) {
-                    cameraSessionZoomScale.update { 1f }
-                }
-                prevCameraSessionLensFacing = transientSettings.value?.primaryLensFacing
                 coroutineScope {
                     with(
                         CameraSessionContext(
@@ -365,19 +370,19 @@ constructor(
                             screenFlashEvents = screenFlashEvents,
                             focusMeteringEvents = focusMeteringEvents,
                             videoCaptureControlEvents = videoCaptureControlEvents,
-                            currentCameraState = _currentCameraState,
+                            currentCameraState = currentCameraState,
                             surfaceRequests = _surfaceRequest,
-                            transientSettings = transientSettings,
-                            zoomScale = cameraSessionZoomScale
+                            transientSettings = transientSettings
                         )
                     ) {
                         try {
                             when (sessionSettings) {
                                 is PerpetualSessionSettings.SingleCamera -> runSingleCameraSession(
-                                    sessionSettings
-                                ) { imageCapture ->
-                                    imageCaptureUseCase = imageCapture
-                                }
+                                    sessionSettings,
+                                    onImageCaptureCreated = { imageCapture ->
+                                        imageCaptureUseCase = imageCapture
+                                    }
+                                )
 
                                 is PerpetualSessionSettings.ConcurrentCamera ->
                                     runConcurrentCameraSession(
@@ -526,6 +531,7 @@ constructor(
         shouldUseUri: Boolean,
         onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
     ) {
+        val initialRecordSettings = currentSettings.value
         if (shouldUseUri && videoCaptureUri == null) {
             val e = RuntimeException("Null Uri is provided.")
             Log.d(TAG, "takePicture onError: $e")
@@ -537,7 +543,20 @@ constructor(
                 shouldUseUri,
                 currentSettings.value?.maxVideoDurationMillis
                     ?: UNLIMITED_VIDEO_DURATION,
-                onVideoRecord
+                onVideoRecord = onVideoRecord,
+
+                onRestoreSettings = {
+                    // restore settings to be called after video recording completes.
+                    // this resets certain settings to their values pre-recording
+                    initialRecordSettings?.let {
+                        currentSettings.update { old ->
+                            old?.copy(
+                                cameraLensFacing = initialRecordSettings.cameraLensFacing,
+                                defaultZoomRatios = initialRecordSettings.defaultZoomRatios
+                            )
+                        }
+                    }
+                }
             )
         )
     }
@@ -554,9 +573,9 @@ constructor(
         videoCaptureControlEvents.send(VideoCaptureControlEvent.StopRecordingEvent)
     }
 
-    override fun setZoomScale(scale: Float) {
+    override fun changeZoomRatio(newZoomState: CameraZoomRatio) {
         currentSettings.update { old ->
-            old?.copy(zoomScale = scale)
+            old?.tryApplyNewZoomRatio(newZoomState) ?: old
         }
     }
 
@@ -595,44 +614,33 @@ constructor(
                 // concurrent currently only supports VIDEO_ONLY
                 if (concurrentCameraMode == ConcurrentCameraMode.DUAL) {
                     CaptureMode.VIDEO_ONLY
-                } else if (imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR) {
-                    CaptureMode.IMAGE_ONLY
-                } else if (dynamicRange == DynamicRange.HLG10) {
-                    CaptureMode.VIDEO_ONLY
                 }
-                // TODO(kc): the two elif statements above should be DELETED and the block below
-                //  should be used when a dedicated capture mode button is available
 
-                /*
-                 // if hdr is enabled, select an appropriate capture mode
-                 else if (dynamicRange == DynamicRange.HLG10 ||
-                    imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+                // if hdr is enabled...
+                else if (imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR ||
+                    dynamicRange == DynamicRange.HLG10
                 ) {
-                    if (constraints.supportedDynamicRanges.contains(DynamicRange.HLG10)) {
-                        if (constraints.supportedImageFormatsMap[streamConfig]
-                                ?.contains(ImageOutputFormat.JPEG_ULTRA_HDR) == true
-                        ) {
-                            // if both image/video HDR is supported, only change if STANDARD is the current capture mode.
-                            // image and video capture use cases cannot be simultaneously bound while HDR is enabled
-                            if (this.captureMode != CaptureMode.STANDARD) {
-                                this.captureMode
-                            } else {
-                                CaptureMode.VIDEO_ONLY
-                            }
-                        } else {
-                            // if only video is supported, change to video only
+                    // if both hdr video and image capture are supported, default to VIDEO_ONLY
+                    if (constraints.supportedDynamicRanges.contains(DynamicRange.HLG10) &&
+                        constraints.supportedImageFormatsMap[streamConfig]
+                            ?.contains(ImageOutputFormat.JPEG_ULTRA_HDR) == true
+                    ) {
+                        if (captureMode == CaptureMode.STANDARD) {
                             CaptureMode.VIDEO_ONLY
+                        } else {
+                            return this
                         }
-                    } else {
-                        // if only image is supported, change to image only
+                    }
+                    // return appropriate capture mode if only one is supported
+                    else if (imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR) {
                         CaptureMode.IMAGE_ONLY
+                    } else {
+                        CaptureMode.VIDEO_ONLY
                     }
-                }
-                 */
-                else {
-                    // if no dynamic range value is set, its OK to return the current value
+                } else {
                     defaultCaptureMode ?: return this
                 }
+
             Log.d(TAG, "new capture mode $newCaptureMode")
             return this@tryApplyCaptureModeConstraints.copy(
                 captureMode = newCaptureMode
@@ -641,6 +649,44 @@ constructor(
             ?: return this
     }
 
+    private fun CameraAppSettings.tryApplyNewZoomRatio(
+        newZoomState: CameraZoomRatio
+    ): CameraAppSettings {
+        val lensFacing = when (newZoomState.changeType.lensToZoom) {
+            LensToZoom.PRIMARY -> cameraLensFacing
+            LensToZoom.SECONDARY -> {
+                val newLens = cameraLensFacing.flip()
+                check(systemConstraints.perLensConstraints[newLens] != null) {
+                    "Device does not have a secondary camera"
+                }
+                newLens
+            }
+        }
+        return systemConstraints.perLensConstraints[lensFacing]?.let { constraints ->
+            val newZoomRatio = constraints.supportedZoomRange?.let { zoomRatioRange ->
+                when (val change = newZoomState.changeType) {
+                    is ZoomChange.Absolute -> change.value
+                    is ZoomChange.Scale -> (
+                        this.defaultZoomRatios
+                            [lensFacing]
+                            ?: 1.0f
+                        ) *
+                        change.value
+
+                    is ZoomChange.Increment -> {
+                        (this.defaultZoomRatios[lensFacing] ?: 1.0f) + change.value
+                    }
+                }.coerceIn(zoomRatioRange.lower, zoomRatioRange.upper)
+            } ?: 1f
+            this@tryApplyNewZoomRatio
+                .copy(
+                    defaultZoomRatios = this.defaultZoomRatios.toMutableMap().apply {
+                        put(lensFacing, newZoomRatio)
+                    }
+                )
+        } ?: this
+    }
+
     private fun CameraAppSettings.tryApplyDynamicRangeConstraints(): CameraAppSettings =
         systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
             with(constraints.supportedDynamicRanges) {
@@ -718,11 +764,12 @@ constructor(
         when (concurrentCameraMode) {
             ConcurrentCameraMode.OFF -> this
             else ->
-                if (systemConstraints.concurrentCamerasSupported) {
+                if (systemConstraints.concurrentCamerasSupported &&
+                    dynamicRange == DynamicRange.SDR &&
+                    streamConfig == StreamConfig.MULTI_STREAM
+                ) {
                     copy(
-                        targetFrameRate = TARGET_FPS_AUTO,
-                        dynamicRange = DynamicRange.SDR,
-                        streamConfig = StreamConfig.MULTI_STREAM
+                        targetFrameRate = TARGET_FPS_AUTO
                     )
                 } else {
                     copy(concurrentCameraMode = ConcurrentCameraMode.OFF)
@@ -798,6 +845,7 @@ constructor(
             old?.copy(streamConfig = streamConfig)
                 ?.tryApplyImageFormatConstraints()
                 ?.tryApplyConcurrentCameraModeConstraints()
+                ?.tryApplyCaptureModeConstraints()
                 ?.tryApplyVideoQualityConstraints()
         }
     }
@@ -805,6 +853,7 @@ constructor(
     override suspend fun setDynamicRange(dynamicRange: DynamicRange) {
         currentSettings.update { old ->
             old?.copy(dynamicRange = dynamicRange)
+                ?.tryApplyDynamicRangeConstraints()
                 ?.tryApplyConcurrentCameraModeConstraints()
                 ?.tryApplyCaptureModeConstraints(CaptureMode.STANDARD)
         }
@@ -827,6 +876,7 @@ constructor(
     override suspend fun setImageFormat(imageFormat: ImageOutputFormat) {
         currentSettings.update { old ->
             old?.copy(imageFormat = imageFormat)
+                ?.tryApplyImageFormatConstraints()
                 ?.tryApplyCaptureModeConstraints(CaptureMode.STANDARD)
         }
     }
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
index 61b4d11..e1a7812 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
@@ -16,6 +16,7 @@
 package com.google.jetpackcamera.core.camera
 
 import android.annotation.SuppressLint
+import android.os.Build
 import android.util.Log
 import androidx.camera.core.CompositionSettings
 import androidx.camera.core.TorchState
@@ -27,6 +28,7 @@ import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.update
@@ -99,6 +101,7 @@ internal suspend fun runConcurrentCameraSession(
 
     cameraProvider.runWithConcurrent(cameraConfigs, useCaseGroup) { concurrentCamera ->
         Log.d(TAG, "Concurrent camera session started")
+        // todo: concurrent camera only ever lists one camera
         val primaryCamera = concurrentCamera.cameras.first {
             it.cameraInfo.appLensFacing == sessionSettings.primaryCameraInfo.appLensFacing
         }
@@ -122,6 +125,39 @@ internal suspend fun runConcurrentCameraSession(
             }
         }
 
+        // update cameraState to mirror the current zoomState
+        launch {
+            primaryCamera.cameraInfo.zoomState.asFlow().filterNotNull().distinctUntilChanged()
+                .collectLatest { zoomState ->
+                    val settings = transientSettings.value
+                    // TODO(b/405987189): remove checks after buggy zoomState is fixed
+                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
+                        if (zoomState.zoomRatio != 1.0f ||
+                            settings == null ||
+                            zoomState.zoomRatio ==
+                            settings.zoomRatios[primaryCamera.cameraInfo.appLensFacing]
+                        ) {
+                            currentCameraState.update { old ->
+                                old.copy(
+                                    zoomRatios = old.zoomRatios.toMutableMap().apply {
+                                        put(
+                                            primaryCamera.cameraInfo.appLensFacing,
+                                            zoomState.zoomRatio
+                                        )
+                                    }.toMap(),
+                                    linearZoomScales = old.linearZoomScales.toMutableMap().apply {
+                                        put(
+                                            primaryCamera.cameraInfo.appLensFacing,
+                                            zoomState.linearZoom
+                                        )
+                                    }.toMap()
+                                )
+                            }
+                        }
+                    }
+                }
+        }
+
         applyDeviceRotation(initialTransientSettings.deviceRotation, useCaseGroup)
         processTransientSettingEvents(
             primaryCamera,
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
index 1132d8e..cdd35a2 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
@@ -31,6 +31,7 @@ sealed interface VideoCaptureControlEvent {
         val videoCaptureUri: Uri?,
         val shouldUseUri: Boolean,
         val maxVideoDuration: Long,
+        val onRestoreSettings: () -> Unit,
         val onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
     ) : VideoCaptureControlEvent
 
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
index ddd5174..6274100 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
@@ -24,6 +24,7 @@ import com.google.jetpackcamera.core.camera.CameraState
 import com.google.jetpackcamera.core.camera.CameraUseCase
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DeviceRotation
@@ -59,7 +60,7 @@ class FakeCameraUseCase(defaultCameraSettings: CameraAppSettings = CameraAppSett
 
     private var isScreenFlash = true
     private var screenFlashEvents = Channel<CameraUseCase.ScreenFlashEvent>(capacity = UNLIMITED)
-
+    private val zoomChanges = MutableStateFlow<CameraZoomRatio?>(null)
     private val currentSettings = MutableStateFlow(defaultCameraSettings)
 
     override suspend fun initialize(
@@ -150,10 +151,8 @@ class FakeCameraUseCase(defaultCameraSettings: CameraAppSettings = CameraAppSett
     }
 
     private val _currentCameraState = MutableStateFlow(CameraState())
-    override fun setZoomScale(scale: Float) {
-        currentSettings.update { old ->
-            old.copy(zoomScale = scale)
-        }
+    override fun changeZoomRatio(newZoomState: CameraZoomRatio) {
+        zoomChanges.update { newZoomState }
     }
     override fun getCurrentCameraState(): StateFlow<CameraState> = _currentCameraState.asStateFlow()
 
diff --git a/core/common/Android.bp b/core/common/Android.bp
index b5ccf9b..3b0f052 100644
--- a/core/common/Android.bp
+++ b/core/common/Android.bp
@@ -17,4 +17,7 @@ android_library {
     sdk_version: "34",
     min_sdk_version: "21",
     manifest: "src/main/AndroidManifest.xml",
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
diff --git a/core/common/src/main/java/com/google/jetpackcamera/core/common/MediaStoreUtils.kt b/core/common/src/main/java/com/google/jetpackcamera/core/common/MediaStoreUtils.kt
deleted file mode 100644
index f760452..0000000
--- a/core/common/src/main/java/com/google/jetpackcamera/core/common/MediaStoreUtils.kt
+++ /dev/null
@@ -1,100 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
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
-package com.google.jetpackcamera.core.common
-
-import android.content.ContentUris
-import android.content.Context
-import android.graphics.Bitmap
-import android.graphics.ImageDecoder
-import android.graphics.Matrix
-import android.net.Uri
-import android.provider.MediaStore
-import java.io.File
-import java.io.FileNotFoundException
-
-/**
- * Retrieves the URI for the most recently added image whose filename starts with "JCA".
- *
- * @param context The application context.
- * @return The content URI of the matching image, or null if none is found.
- */
-fun getLastImageUri(context: Context): Uri? {
-    val projection = arrayOf(
-        MediaStore.Images.Media._ID,
-        MediaStore.Images.Media.DATE_ADDED
-    )
-
-    // Filter by filenames starting with "JCA"
-    val selection = "${MediaStore.Images.Media.DISPLAY_NAME} LIKE ?"
-    val selectionArgs = arrayOf("JCA%")
-
-    // Sort the results so that the most recently added image appears first.
-    val sortOrder = "${MediaStore.Images.Media.DATE_ADDED} DESC"
-
-    // Perform the query on the MediaStore.
-    context.contentResolver.query(
-        MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
-        projection,
-        selection,
-        selectionArgs,
-        sortOrder
-    )?.use { cursor ->
-        if (cursor.moveToFirst()) {
-            val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
-            val id = cursor.getLong(idColumn)
-
-            return ContentUris.withAppendedId(
-                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
-                id
-            )
-        }
-    }
-    return null
-}
-
-/**
- * Loads a Bitmap from a given URI and rotates it by the specified degrees.
- *
- * @param context The application context.
- * @param uri The URI of the image to load.
- * @param degrees The number of degrees to rotate the image by.
- */
-fun loadAndRotateBitmap(context: Context, uri: Uri?, degrees: Float): Bitmap? {
-    uri ?: return null
-
-    if (uri.scheme == "file") {
-        val file = File(uri.path ?: "")
-        if (!file.exists()) {
-            return null
-        }
-    }
-
-    return try {
-        val bitmap = if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.P) {
-            MediaStore.Images.Media.getBitmap(context.contentResolver, uri)
-        } else {
-            val imageDecoderSource = ImageDecoder.createSource(context.contentResolver, uri)
-            ImageDecoder.decodeBitmap(imageDecoderSource)
-        }
-
-        bitmap?.let {
-            val matrix = Matrix().apply { postRotate(degrees) }
-            Bitmap.createBitmap(it, 0, 0, it.width, it.height, matrix, true)
-        }
-    } catch (e: FileNotFoundException) {
-        null
-    }
-}
diff --git a/data/media/.gitignore b/data/media/.gitignore
new file mode 100644
index 0000000..42afabf
--- /dev/null
+++ b/data/media/.gitignore
@@ -0,0 +1 @@
+/build
\ No newline at end of file
diff --git a/data/media/Android.bp b/data/media/Android.bp
new file mode 100644
index 0000000..767ecba
--- /dev/null
+++ b/data/media/Android.bp
@@ -0,0 +1,23 @@
+package {
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+    ],
+}
+
+android_library {
+    name: "jetpack-camera-app_data_media",
+    srcs: [
+        "src/main/**/*.kt",
+    ],
+    static_libs: [
+        "hilt_android",
+        "kotlinx-coroutines-core",
+        "jetpack-camera-app_core_common",
+    ],
+    sdk_version: "34",
+    min_sdk_version: "21",
+    manifest: "src/main/AndroidManifest.xml",
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
+}
diff --git a/data/media/build.gradle.kts b/data/media/build.gradle.kts
new file mode 100644
index 0000000..2f382a2
--- /dev/null
+++ b/data/media/build.gradle.kts
@@ -0,0 +1,93 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+plugins {
+    alias(libs.plugins.android.library)
+    alias(libs.plugins.kotlin.android)
+    alias(libs.plugins.kotlin.kapt)
+    alias(libs.plugins.dagger.hilt.android)
+}
+
+android {
+    namespace = "com.google.jetpackcamera.data.media"
+    compileSdk = libs.versions.compileSdk.get().toInt()
+
+    defaultConfig {
+        minSdk = libs.versions.minSdk.get().toInt()
+        testOptions.targetSdk = libs.versions.targetSdk.get().toInt()
+        lint.targetSdk = libs.versions.targetSdk.get().toInt()
+
+        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
+        consumerProguardFiles("consumer-rules.pro")
+    }
+
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+    }
+
+    compileOptions {
+        sourceCompatibility = JavaVersion.VERSION_17
+        targetCompatibility = JavaVersion.VERSION_17
+    }
+    kotlin {
+        jvmToolchain(17)
+    }
+
+    @Suppress("UnstableApiUsage")
+    testOptions {
+        managedDevices {
+            localDevices {
+                create("pixel2Api28") {
+                    device = "Pixel 2"
+                    apiLevel = 28
+                }
+                create("pixel8Api34") {
+                    device = "Pixel 8"
+                    apiLevel = 34
+                    systemImageSource = "aosp_atd"
+                }
+            }
+        }
+    }
+}
+
+dependencies {
+    implementation(libs.kotlinx.coroutines.core)
+
+    // Hilt
+    implementation(libs.dagger.hilt.android)
+    kapt(libs.dagger.hilt.compiler)
+
+    // Testing
+    testImplementation(libs.junit)
+    testImplementation(libs.truth)
+    androidTestImplementation(libs.androidx.espresso.core)
+    androidTestImplementation(libs.androidx.junit)
+    androidTestImplementation(libs.truth)
+    androidTestImplementation(libs.kotlinx.coroutines.test)
+
+
+    // Project dependencies
+    implementation(project(":core:common"))
+}
+
+// Allow references to generated code
+kapt {
+    correctErrorTypes = true
+}
diff --git a/data/media/consumer-rules.pro b/data/media/consumer-rules.pro
new file mode 100644
index 0000000..e69de29
diff --git a/data/media/proguard-rules.pro b/data/media/proguard-rules.pro
new file mode 100644
index 0000000..481bb43
--- /dev/null
+++ b/data/media/proguard-rules.pro
@@ -0,0 +1,21 @@
+# Add project specific ProGuard rules here.
+# You can control the set of applied configuration files using the
+# proguardFiles setting in build.gradle.
+#
+# For more details, see
+#   http://developer.android.com/guide/developing/tools/proguard.html
+
+# If your project uses WebView with JS, uncomment the following
+# and specify the fully qualified class name to the JavaScript interface
+# class:
+#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
+#   public *;
+#}
+
+# Uncomment this to preserve the line number information for
+# debugging stack traces.
+#-keepattributes SourceFile,LineNumberTable
+
+# If you keep the line number information, uncomment this to
+# hide the original source file name.
+#-renamesourcefileattribute SourceFile
\ No newline at end of file
diff --git a/data/media/src/main/AndroidManifest.xml b/data/media/src/main/AndroidManifest.xml
new file mode 100644
index 0000000..dca9186
--- /dev/null
+++ b/data/media/src/main/AndroidManifest.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.data.media">
+
+</manifest>
\ No newline at end of file
diff --git a/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/FakeMediaRepository.kt b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/FakeMediaRepository.kt
new file mode 100644
index 0000000..590d10c
--- /dev/null
+++ b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/FakeMediaRepository.kt
@@ -0,0 +1,26 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.data.media
+
+object FakeMediaRepository : MediaRepository {
+    override suspend fun getLastCapturedMedia(): MediaDescriptor {
+        return MediaDescriptor.None
+    }
+
+    override suspend fun load(mediaDescriptor: MediaDescriptor): Media {
+        return Media.None
+    }
+}
diff --git a/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/LocalMediaRepository.kt b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/LocalMediaRepository.kt
new file mode 100644
index 0000000..b38903f
--- /dev/null
+++ b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/LocalMediaRepository.kt
@@ -0,0 +1,167 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.data.media
+
+import android.content.ContentUris
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.BitmapFactory
+import android.graphics.ImageDecoder
+import android.net.Uri
+import android.os.Build
+import android.provider.MediaStore
+import android.util.Size
+import com.google.jetpackcamera.core.common.IODispatcher
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.withContext
+
+class LocalMediaRepository
+@Inject constructor(
+    @ApplicationContext private val context: Context,
+    @IODispatcher private val iODispatcher: CoroutineDispatcher
+) : MediaRepository {
+
+    override suspend fun load(mediaDescriptor: MediaDescriptor): Media {
+        return when (mediaDescriptor) {
+            is MediaDescriptor.Image -> loadImage(mediaDescriptor.uri)
+            MediaDescriptor.None -> Media.None
+            is MediaDescriptor.Video -> Media.Video(mediaDescriptor.uri)
+        }
+    }
+
+    override suspend fun getLastCapturedMedia(): MediaDescriptor {
+        val imagePair =
+            getLastMediaUriWithDate(context, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
+        val videoPair =
+            getLastMediaUriWithDate(context, MediaStore.Video.Media.EXTERNAL_CONTENT_URI)
+
+        return when {
+            imagePair == null && videoPair == null -> MediaDescriptor.None
+            imagePair == null && videoPair != null -> getVideoMediaDescriptor(videoPair.first)
+            videoPair == null && imagePair != null -> getImageMediaDescriptor(imagePair.first)
+            imagePair != null && videoPair != null -> {
+                if (imagePair.second > videoPair.second) {
+                    getImageMediaDescriptor(imagePair.first)
+                } else {
+                    getVideoMediaDescriptor(videoPair.first)
+                }
+            }
+
+            else -> MediaDescriptor.None // Should not happen
+        }
+    }
+
+    private suspend fun loadImage(uri: Uri): Media = withContext(iODispatcher) {
+        try {
+            val loadedBitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
+                // Android 10 (API 29) and above: Use ImageDecoder
+                val source = ImageDecoder.createSource(context.contentResolver, uri)
+                ImageDecoder.decodeBitmap(source)
+            } else {
+                // Android 9 (API 28) and below: Use BitmapFactory
+                context.contentResolver.openInputStream(uri)?.use { inputStream ->
+                    BitmapFactory.decodeStream(inputStream)
+                }
+            }
+
+            return@withContext if (loadedBitmap != null) {
+                Media.Image(loadedBitmap)
+            } else {
+                Media.Error
+            }
+        } catch (e: Exception) {
+            e.printStackTrace()
+            return@withContext Media.Error
+        }
+    }
+
+    private suspend fun getVideoMediaDescriptor(uri: Uri): MediaDescriptor {
+        val thumbnail = getThumbnail(uri, MediaStore.Video.Media.EXTERNAL_CONTENT_URI)
+        return MediaDescriptor.Video(uri, thumbnail)
+    }
+
+    private suspend fun getImageMediaDescriptor(uri: Uri): MediaDescriptor {
+        val thumbnail = getThumbnail(uri, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
+        return MediaDescriptor.Image(uri, thumbnail)
+    }
+
+    private suspend fun getThumbnail(uri: Uri, collectionUri: Uri): Bitmap? =
+        withContext(iODispatcher) {
+            return@withContext try {
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
+                    context.contentResolver.loadThumbnail(uri, Size(640, 480), null)
+                } else {
+                    if (collectionUri == MediaStore.Images.Media.EXTERNAL_CONTENT_URI) {
+                        MediaStore.Images.Thumbnails.getThumbnail(
+                            context.contentResolver,
+                            ContentUris.parseId(uri),
+                            MediaStore.Images.Thumbnails.MINI_KIND,
+                            null
+                        )
+                    } else { // Video
+                        MediaStore.Video.Thumbnails.getThumbnail(
+                            context.contentResolver,
+                            ContentUris.parseId(uri),
+                            MediaStore.Video.Thumbnails.MINI_KIND,
+                            null
+                        )
+                    }
+                }
+            } catch (e: Exception) {
+                e.printStackTrace()
+                null
+            }
+        }
+
+    private fun getLastMediaUriWithDate(context: Context, collectionUri: Uri): Pair<Uri, Long>? {
+        val projection = arrayOf(
+            MediaStore.MediaColumns._ID,
+            MediaStore.MediaColumns.DATE_ADDED
+        )
+
+        // Filter by filenames starting with "JCA"
+        val selection = "${MediaStore.MediaColumns.DISPLAY_NAME} LIKE ?"
+        val selectionArgs = arrayOf("JCA%")
+
+        // Sort the results so that the most recently added media appears first.
+        val sortOrder = "${MediaStore.MediaColumns.DATE_ADDED} DESC"
+
+        // Perform the query on the MediaStore.
+        context.contentResolver.query(
+            collectionUri,
+            projection,
+            selection,
+            selectionArgs,
+            sortOrder
+        )?.use { cursor ->
+            if (cursor.moveToFirst()) {
+                val idColumn = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
+                val dateAddedColumn = cursor.getColumnIndexOrThrow(
+                    MediaStore.MediaColumns.DATE_ADDED
+                )
+
+                val id = cursor.getLong(idColumn)
+                val dateAdded = cursor.getLong(dateAddedColumn)
+
+                val uri = ContentUris.withAppendedId(collectionUri, id)
+                return Pair(uri, dateAdded)
+            }
+        }
+        return null
+    }
+}
diff --git a/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/MediaModule.kt b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/MediaModule.kt
new file mode 100644
index 0000000..a4ec2dd
--- /dev/null
+++ b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/MediaModule.kt
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.data.media
+
+import dagger.Binds
+import dagger.Module
+import dagger.hilt.InstallIn
+import dagger.hilt.components.SingletonComponent
+import javax.inject.Singleton
+
+/**
+ * Dagger [Module] for Media dependencies.
+ */
+@Module
+@InstallIn(SingletonComponent::class)
+interface MediaModule {
+
+    @Binds
+    @Singleton
+    fun bindsMediaRepository(localMediaRepository: LocalMediaRepository): MediaRepository
+}
diff --git a/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/MediaRepository.kt b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/MediaRepository.kt
new file mode 100644
index 0000000..d7705bf
--- /dev/null
+++ b/data/media/src/main/kotlin/com/google/jetpackcamera/data/media/MediaRepository.kt
@@ -0,0 +1,53 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.data.media
+
+import android.graphics.Bitmap
+import android.net.Uri
+
+/**
+ * Data layer for Media.
+ */
+interface MediaRepository {
+    suspend fun getLastCapturedMedia(): MediaDescriptor
+    suspend fun load(mediaDescriptor: MediaDescriptor): Media
+}
+
+/**
+ * Descriptors used for [Media].
+ *
+ * Media descriptors contain a reference to a [Media] item that's not yet loaded.
+ */
+sealed interface MediaDescriptor {
+    data object None : MediaDescriptor
+    class Image(val uri: Uri, val thumbnail: Bitmap?) : MediaDescriptor
+    class Video(val uri: Uri, val thumbnail: Bitmap?) : MediaDescriptor
+}
+
+/**
+ * Media items that are supported by [MediaRepository].
+ *
+ * [Image] will have the bitmap data loaded.
+ * [Video] is still a reference to the video file, will switch to a loaded version later on.
+ *
+ * TODO(yasith): Load the video data to the Video object.
+ */
+sealed interface Media {
+    data object None : Media
+    data object Error : Media
+    class Image(val bitmap: Bitmap) : Media
+    class Video(val uri: Uri) : Media
+}
diff --git a/data/settings/Android.bp b/data/settings/Android.bp
index 2abb0b4..550cb3d 100644
--- a/data/settings/Android.bp
+++ b/data/settings/Android.bp
@@ -9,8 +9,8 @@ java_library {
     installable: false,
     proto: {
         type: "lite",
-	canonical_path_from_root: false,
-	local_include_dirs: ["src/main/proto"],
+        canonical_path_from_root: false,
+        local_include_dirs: ["src/main/proto"],
     },
     srcs: [
         "src/main/proto/**/*.proto",
@@ -20,10 +20,12 @@ java_library {
 
     static_libs: [
         "libprotobuf-java-lite",
-    ]
+    ],
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
 
-
 android_library {
     name: "jetpack-camera-app_data_settings",
     srcs: [
@@ -32,12 +34,14 @@ android_library {
     static_libs: [
         "hilt_android",
         "kotlinx-coroutines-core",
-	"androidx.datastore_datastore",
-	"jetpack-camera-app-protos-java-gen",
-	"libprotobuf-java-lite",
+        "androidx.datastore_datastore",
+        "jetpack-camera-app-protos-java-gen",
+        "libprotobuf-java-lite",
     ],
     sdk_version: "34",
     min_sdk_version: "21",
-    manifest:"src/main/AndroidManifest.xml",
+    manifest: "src/main/AndroidManifest.xml",
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
-
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
index 494ed5b..c8528f8 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
@@ -33,7 +33,7 @@ data class CameraAppSettings(
     val stabilizationMode: StabilizationMode = StabilizationMode.AUTO,
     val dynamicRange: DynamicRange = DynamicRange.SDR,
     val videoQuality: VideoQuality = VideoQuality.UNSPECIFIED,
-    val zoomScale: Float = 1f,
+    val defaultZoomRatios: Map<LensFacing, Float> = mapOf(),
     val targetFrameRate: Int = TARGET_FPS_AUTO,
     val imageFormat: ImageOutputFormat = ImageOutputFormat.JPEG,
     val audioEnabled: Boolean = true,
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraZoomState.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraZoomState.kt
new file mode 100644
index 0000000..ba9155e
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraZoomState.kt
@@ -0,0 +1,77 @@
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
+/**
+ * Represents an action to modify the current zoom Ratio
+ *  * @param changeType the [ZoomChange] to be performed on the current Zoom Ratio
+ *
+ */
+
+data class CameraZoomRatio(val changeType: ZoomChange)
+
+/**
+ * Abstract placeholders
+ */
+enum class LensToZoom {
+
+    /**
+     * An abstract placeholder for the "Current" [LensFacing] in a single camera session,
+     * or the Primary `LensFacing` in a concurrent session.
+     */
+    PRIMARY,
+
+    /**
+     * An abstract placeholder for the "Inactive" [LensFacing] in a single camera session,
+     * or the `Secondary LensFacing` in a concurrent session.
+     *
+     * An "Inactive `LensFacing`" is not guaranteed in a single camera session.
+     * @see[SystemConstraints.availableLenses]
+     */
+    SECONDARY
+}
+
+/**
+ * Represents the different types of actions to modify the current zoom state
+ */
+sealed interface ZoomChange {
+    val value: Float
+    val lensToZoom: LensToZoom
+
+    /**
+     * Use Absolute to set the current zoom ratio or linear state to the value
+     */
+    data class Absolute(
+        override val value: Float,
+        override val lensToZoom: LensToZoom = LensToZoom.PRIMARY
+    ) : ZoomChange
+
+    /**
+     * Use Scale to multiply current zoom ratio or linear state by the value
+     */
+    data class Scale(
+        override val value: Float,
+        override val lensToZoom: LensToZoom = LensToZoom.PRIMARY
+    ) : ZoomChange
+
+    /**
+     * Use Increment to add the value to the current zoom ratio or linear state
+     */
+    data class Increment(
+        override val value: Float,
+        override val lensToZoom: LensToZoom = LensToZoom.PRIMARY
+    ) : ZoomChange
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
index fd23758..4594d14 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
@@ -15,6 +15,8 @@
  */
 package com.google.jetpackcamera.settings.model
 
+import android.util.Range
+
 data class SystemConstraints(
     val availableLenses: List<LensFacing> = emptyList(),
     val concurrentCamerasSupported: Boolean = false,
@@ -33,6 +35,7 @@ data class CameraConstraints(
     val supportedImageFormatsMap: Map<StreamConfig, Set<ImageOutputFormat>>,
     val supportedIlluminants: Set<Illuminant>,
     val supportedFlashModes: Set<FlashMode>,
+    val supportedZoomRange: Range<Float>?,
     val unsupportedStabilizationFpsMap: Map<StabilizationMode, Set<Int>>
 ) {
     val StabilizationMode.unsupportedFpsSet
@@ -68,6 +71,7 @@ val TYPICAL_SYSTEM_CONSTRAINTS =
                         supportedVideoQualitiesMap = emptyMap(),
                         supportedIlluminants = setOf(Illuminant.FLASH_UNIT),
                         supportedFlashModes = setOf(FlashMode.OFF, FlashMode.ON, FlashMode.AUTO),
+                        supportedZoomRange = Range(.5f, 10f),
                         unsupportedStabilizationFpsMap = emptyMap()
                     )
                 )
diff --git a/feature/permissions/Android.bp b/feature/permissions/Android.bp
index 911158d..1e3f969 100644
--- a/feature/permissions/Android.bp
+++ b/feature/permissions/Android.bp
@@ -24,4 +24,7 @@ android_library {
     sdk_version: "34",
     min_sdk_version: "21",
     manifest: "src/main/AndroidManifest.xml",
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
diff --git a/feature/permissions/build.gradle.kts b/feature/permissions/build.gradle.kts
index d935b2c..16f5f14 100644
--- a/feature/permissions/build.gradle.kts
+++ b/feature/permissions/build.gradle.kts
@@ -16,6 +16,7 @@
 plugins {
     alias(libs.plugins.android.library)
     alias(libs.plugins.kotlin.android)
+    alias(libs.plugins.compose.compiler)
 
     alias(libs.plugins.kotlin.kapt)
     alias(libs.plugins.dagger.hilt.android)
diff --git a/feature/postcapture/Android.bp b/feature/postcapture/Android.bp
index 7f49e84..74950f2 100644
--- a/feature/postcapture/Android.bp
+++ b/feature/postcapture/Android.bp
@@ -7,6 +7,9 @@ package {
 android_library {
     name: "jetpack-camera-app_feature_postcapture",
     srcs: ["src/main/**/*.kt"],
+    resource_dirs: [
+        "src/main/res",
+    ],
     static_libs: [
         "androidx.compose.runtime_runtime",
         "androidx.compose.material3_material3",
@@ -14,12 +17,17 @@ android_library {
         "androidx.compose.ui_ui-tooling-preview",
         "androidx.hilt_hilt-navigation-compose",
         "androidx.compose.ui_ui-tooling",
-        "kotlin-reflect",
+        "androidx.media3.media3-common",
+        "androidx.media3.media3-exoplayer",
+        "androidx.media3.media3-ui-compose",
         "kotlinx_coroutines_guava",
         "jetpack-camera-app_core_common",
-
+        "jetpack-camera-app_data_media",
     ],
     sdk_version: "34",
     min_sdk_version: "21",
     manifest: "src/main/AndroidManifest.xml",
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
diff --git a/feature/postcapture/build.gradle.kts b/feature/postcapture/build.gradle.kts
index f421334..cb86c97 100644
--- a/feature/postcapture/build.gradle.kts
+++ b/feature/postcapture/build.gradle.kts
@@ -16,6 +16,9 @@
 plugins {
     alias(libs.plugins.android.library)
     alias(libs.plugins.kotlin.android)
+    alias(libs.plugins.kotlin.kapt)
+    alias(libs.plugins.dagger.hilt.android)
+    alias(libs.plugins.compose.compiler)
 }
 
 android {
@@ -81,9 +84,6 @@ android {
 }
 
 dependencies {
-
-    // Reflect
-    implementation(libs.kotlin.reflect)
     // Compose
     val composeBom = platform(libs.compose.bom)
     implementation(composeBom)
@@ -111,6 +111,14 @@ dependencies {
     testImplementation(libs.compose.test.manifest)
     testImplementation(libs.compose.junit)
 
+    // Hilt
+    implementation(libs.dagger.hilt.android)
+    kapt(libs.dagger.hilt.compiler)
+
+    // Media3
+    implementation(libs.androidx.media3.exoplayer)
+    implementation(libs.androidx.media3.ui.compose)
+
     // Testing
     testImplementation(libs.junit)
     testImplementation(libs.truth)
@@ -129,5 +137,11 @@ dependencies {
 
     // Project dependencies
     implementation(project(":core:common"))
+    implementation(project(":data:media"))
     testImplementation(project(":core:common"))
-}
\ No newline at end of file
+}
+
+// Allow references to generated code
+kapt {
+    correctErrorTypes = true
+}
diff --git a/feature/postcapture/src/main/AndroidManifest.xml b/feature/postcapture/src/main/AndroidManifest.xml
index 664f138..21276cf 100644
--- a/feature/postcapture/src/main/AndroidManifest.xml
+++ b/feature/postcapture/src/main/AndroidManifest.xml
@@ -14,6 +14,6 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.postcapture">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.feature.postcapture">
 
 </manifest>
\ No newline at end of file
diff --git a/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt
index 854f64f..4562ce7 100644
--- a/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt
+++ b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt
@@ -18,6 +18,8 @@ package com.google.jetpackcamera.feature.postcapture
 import android.content.Context
 import android.content.Intent
 import android.net.Uri
+import android.util.Log
+import androidx.annotation.OptIn
 import androidx.compose.foundation.Canvas
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Box
@@ -37,38 +39,40 @@ import androidx.compose.material3.IconButtonDefaults
 import androidx.compose.material3.MaterialTheme
 import androidx.compose.material3.Text
 import androidx.compose.runtime.Composable
-import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.getValue
-import androidx.compose.runtime.remember
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.draw.shadow
 import androidx.compose.ui.geometry.Size
 import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
 import androidx.compose.ui.graphics.nativeCanvas
+import androidx.compose.ui.layout.ContentScale
 import androidx.compose.ui.platform.LocalContext
+import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.unit.dp
 import androidx.hilt.navigation.compose.hiltViewModel
-import com.google.jetpackcamera.core.common.loadAndRotateBitmap
+import androidx.media3.common.util.UnstableApi
+import androidx.media3.ui.compose.PlayerSurface
+import androidx.media3.ui.compose.modifiers.resizeWithContentScale
+import androidx.media3.ui.compose.state.rememberPresentationState
+import com.google.jetpackcamera.data.media.Media
+import com.google.jetpackcamera.data.media.MediaDescriptor
 
+private const val TAG = "PostCaptureScreen"
+
+@OptIn(UnstableApi::class)
 @Composable
-fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel(), imageUri: Uri?) {
+fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel()) {
+    Log.d(TAG, "PostCaptureScreen")
+
     val uiState: PostCaptureUiState by viewModel.uiState.collectAsState()
     val context = LocalContext.current
 
-    LaunchedEffect(imageUri) {
-        viewModel.setLastCapturedImageUri(imageUri)
-    }
-
     Box(modifier = Modifier.fillMaxSize()) {
-        uiState.imageUri?.let { uri ->
-            val bitmap = remember(uri) {
-                // TODO(yasith): Get the image rotation from the image
-                loadAndRotateBitmap(context, uri, 270f)
-            }
-
-            if (bitmap != null) {
+        when (val media = uiState.media) {
+            is Media.Image -> {
+                val bitmap = media.bitmap
                 Canvas(modifier = Modifier.fillMaxSize()) {
                     drawIntoCanvas { canvas ->
                         val scale = maxOf(
@@ -90,10 +94,30 @@ fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel(), imageUr
                     }
                 }
             }
-        } ?: Text(
-            text = "No Image Captured",
-            modifier = Modifier.align(Alignment.Center)
-        )
+            is Media.Video -> {
+                val presentationState = rememberPresentationState(viewModel.player)
+                PlayerSurface(
+                    player = viewModel.player,
+                    modifier = Modifier.resizeWithContentScale(
+                        ContentScale.Fit,
+                        presentationState.videoSizeDp
+                    )
+                )
+                viewModel.playVideo()
+            }
+            Media.None -> {
+                Text(
+                    text = stringResource(R.string.no_media_available),
+                    modifier = Modifier.align(Alignment.Center)
+                )
+            }
+            Media.Error -> {
+                Text(
+                    text = stringResource(R.string.error_loading_media),
+                    modifier = Modifier.align(Alignment.Center)
+                )
+            }
+        }
 
         Row(
             modifier = Modifier
@@ -104,7 +128,7 @@ fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel(), imageUr
         ) {
             // Delete Image Button
             IconButton(
-                onClick = { viewModel.deleteImage(context.contentResolver) },
+                onClick = { viewModel.deleteMedia(context.contentResolver) },
                 modifier = Modifier
                     .size(56.dp)
                     .shadow(10.dp, CircleShape),
@@ -121,11 +145,17 @@ fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel(), imageUr
 
             Spacer(modifier = Modifier.weight(1f))
 
-            // Share Image Button
+            // Share Media Button
             IconButton(
                 onClick = {
-                    imageUri?.let {
-                        shareImage(context, it)
+                    val mediaDescriptor = uiState.mediaDescriptor
+
+                    if (mediaDescriptor is MediaDescriptor.Image) {
+                        shareImage(context, mediaDescriptor.uri, "image/jpeg")
+                    }
+
+                    if (mediaDescriptor is MediaDescriptor.Video) {
+                        shareImage(context, mediaDescriptor.uri, "video/mp4")
                     }
                 },
                 modifier = Modifier
@@ -146,16 +176,13 @@ fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel(), imageUr
 }
 
 /**
- * Starts an intent to share an image
- *
- * @param context The application context
- * @param imagePath The path to the image to share
+ * Starts an intent to share media
  */
-private fun shareImage(context: Context, uri: Uri) {
+private fun shareImage(context: Context, uri: Uri, mimeType: String) {
     val intent = Intent(Intent.ACTION_SEND).apply {
-        type = "image/jpeg"
+        type = mimeType
         putExtra(Intent.EXTRA_STREAM, uri)
     }
     intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
-    context.startActivity(Intent.createChooser(intent, "Share Image"))
+    context.startActivity(Intent.createChooser(intent, "Share Media"))
 }
diff --git a/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt
index a9ed0b8..0a6a95b 100644
--- a/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt
+++ b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt
@@ -16,30 +16,74 @@
 package com.google.jetpackcamera.feature.postcapture
 
 import android.content.ContentResolver
-import android.net.Uri
+import android.content.Context
 import androidx.lifecycle.ViewModel
+import androidx.lifecycle.viewModelScope
+import androidx.media3.common.MediaItem
+import androidx.media3.exoplayer.ExoPlayer
+import com.google.jetpackcamera.data.media.Media
+import com.google.jetpackcamera.data.media.MediaDescriptor
+import com.google.jetpackcamera.data.media.MediaRepository
 import dagger.hilt.android.lifecycle.HiltViewModel
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.launch
 
 @HiltViewModel
-class PostCaptureViewModel : ViewModel() {
+class PostCaptureViewModel @Inject constructor(
+    private val mediaRepository: MediaRepository,
+    @ApplicationContext private val context: Context
+) : ViewModel() {
+
+    init {
+        getLastCapture()
+    }
+
+    private val _uiState = MutableStateFlow(
+        PostCaptureUiState(
+            mediaDescriptor = MediaDescriptor.None,
+            media = Media.None
+        )
+    )
+
+    val player = ExoPlayer.Builder(context).build()
 
-    private val _uiState = MutableStateFlow(PostCaptureUiState())
     val uiState: StateFlow<PostCaptureUiState> = _uiState
 
-    fun setLastCapturedImageUri(imageUri: Uri?) {
-        _uiState.update { it.copy(imageUri = imageUri, isImageDeleted = false) }
+    fun getLastCapture() {
+        viewModelScope.launch {
+            val mediaDescriptor = mediaRepository.getLastCapturedMedia()
+            val media = mediaRepository.load(mediaDescriptor)
+
+            _uiState.update { it.copy(mediaDescriptor = mediaDescriptor, media = media) }
+        }
+    }
+
+    fun deleteMedia(contentResolver: ContentResolver) {
+        when (val mediaDescriptor = uiState.value.mediaDescriptor) {
+            is MediaDescriptor.Image -> contentResolver.delete(mediaDescriptor.uri, null, null)
+            is MediaDescriptor.Video -> contentResolver.delete(mediaDescriptor.uri, null, null)
+            MediaDescriptor.None -> {}
+        }
+        _uiState.update { it.copy(mediaDescriptor = MediaDescriptor.None, media = Media.None) }
     }
 
-    fun deleteImage(contentResolver: ContentResolver) {
-        contentResolver.delete(uiState.value.imageUri!!, null, null)
-        _uiState.update { it.copy(imageUri = null, isImageDeleted = true) }
+    fun playVideo() {
+        val media = uiState.value.media
+        if (media is Media.Video) {
+            val mediaItem = MediaItem.fromUri(media.uri)
+            player.setMediaItem(mediaItem)
+            player.prepare()
+            player.setRepeatMode(ExoPlayer.REPEAT_MODE_ONE)
+            player.play()
+        }
     }
 }
 
 data class PostCaptureUiState(
-    val imageUri: Uri? = null,
-    val isImageDeleted: Boolean = false
+    val mediaDescriptor: MediaDescriptor,
+    val media: Media
 )
diff --git a/feature/postcapture/src/main/res/values/strings.xml b/feature/postcapture/src/main/res/values/strings.xml
new file mode 100644
index 0000000..8248ecc
--- /dev/null
+++ b/feature/postcapture/src/main/res/values/strings.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<resources>
+    <string name="no_media_available">No Media Available</string>
+    <string name="error_loading_media">Error loading media</string>
+</resources>
\ No newline at end of file
diff --git a/feature/preview/Android.bp b/feature/preview/Android.bp
index cbc642a..008b8ed 100644
--- a/feature/preview/Android.bp
+++ b/feature/preview/Android.bp
@@ -19,7 +19,6 @@ android_library {
         "hilt_android",
         "androidx.hilt_hilt-navigation-compose",
         "androidx.compose.ui_ui-tooling",
-        "kotlin-reflect",
         "kotlinx_coroutines_guava",
         "androidx.datastore_datastore",
         "libprotobuf-java-lite",
@@ -29,10 +28,13 @@ android_library {
         "jetpack-camera-app_data_settings",
         "jetpack-camera-app_core_camera",
         "jetpack-camera-app_core_common",
+        "jetpack-camera-app_data_media",
         "androidx.compose.ui_ui-tooling",
-
     ],
     sdk_version: "34",
     min_sdk_version: "21",
     manifest: "src/main/AndroidManifest.xml",
+    apex_available: [
+        "com.android.mediaprovider",
+    ],
 }
diff --git a/feature/preview/build.gradle.kts b/feature/preview/build.gradle.kts
index abe853b..a5bbbce 100644
--- a/feature/preview/build.gradle.kts
+++ b/feature/preview/build.gradle.kts
@@ -19,6 +19,7 @@ plugins {
     alias(libs.plugins.kotlin.android)
     alias(libs.plugins.kotlin.kapt)
     alias(libs.plugins.dagger.hilt.android)
+    alias(libs.plugins.compose.compiler)
 }
 
 android {
@@ -83,8 +84,6 @@ android {
 }
 
 dependencies {
-    // Reflect
-    implementation(libs.kotlin.reflect)
     // Compose
     val composeBom = platform(libs.compose.bom)
     implementation(composeBom)
@@ -140,9 +139,10 @@ dependencies {
     implementation(libs.kotlinx.atomicfu)
 
     // Project dependencies
-    implementation(project(":data:settings"))
     implementation(project(":core:camera"))
     implementation(project(":core:common"))
+    implementation(project(":data:media"))
+    implementation(project(":data:settings"))
     testImplementation(project(":core:common"))
 }
 
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeToggleUiState.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeToggleUiState.kt
deleted file mode 100644
index 04b7a5e..0000000
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeToggleUiState.kt
+++ /dev/null
@@ -1,87 +0,0 @@
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
-package com.google.jetpackcamera.feature.preview
-
-import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_DEVICE_TAG
-import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_LENS_TAG
-import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG
-import com.google.jetpackcamera.feature.preview.ui.HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG
-import com.google.jetpackcamera.feature.preview.ui.HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG
-import com.google.jetpackcamera.feature.preview.ui.HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG
-import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG
-import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-
-sealed interface CaptureModeToggleUiState {
-
-    data object Invisible : CaptureModeToggleUiState
-
-    sealed interface Visible : CaptureModeToggleUiState {
-        val currentMode: ToggleMode
-    }
-
-    data class Enabled(override val currentMode: ToggleMode) : Visible
-
-    data class Disabled(
-        override val currentMode: ToggleMode,
-        val disabledReason: DisabledReason
-    ) : Visible
-
-    enum class DisabledReason(val testTag: String, val reasonTextResId: Int) {
-        VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED(
-            VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG,
-            R.string.toast_video_capture_external_unsupported
-        ),
-        IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED(
-            IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG,
-            R.string.toast_image_capture_external_unsupported
-
-        ),
-        IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA(
-            IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG,
-            R.string.toast_image_capture_unsupported_concurrent_camera
-        ),
-        HDR_VIDEO_UNSUPPORTED_ON_DEVICE(
-            HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG,
-            R.string.toast_hdr_video_unsupported_on_device
-        ),
-        HDR_VIDEO_UNSUPPORTED_ON_LENS(
-            HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG,
-            R.string.toast_hdr_video_unsupported_on_lens
-        ),
-        HDR_IMAGE_UNSUPPORTED_ON_DEVICE(
-            HDR_IMAGE_UNSUPPORTED_ON_DEVICE_TAG,
-            R.string.toast_hdr_photo_unsupported_on_device
-        ),
-        HDR_IMAGE_UNSUPPORTED_ON_LENS(
-            HDR_IMAGE_UNSUPPORTED_ON_LENS_TAG,
-            R.string.toast_hdr_photo_unsupported_on_lens
-        ),
-        HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM(
-            HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG,
-            R.string.toast_hdr_photo_unsupported_on_lens_single_stream
-        ),
-        HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM(
-            HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG,
-            R.string.toast_hdr_photo_unsupported_on_lens_multi_stream
-        )
-    }
-
-    enum class ToggleMode {
-        CAPTURE_TOGGLE_IMAGE,
-        CAPTURE_TOGGLE_VIDEO
-    }
-}
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeUiState.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeUiState.kt
new file mode 100644
index 0000000..b206e62
--- /dev/null
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/CaptureModeUiState.kt
@@ -0,0 +1,88 @@
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
+import com.google.jetpackcamera.feature.preview.ui.HDR_SIMULTANEOUS_IMAGE_VIDEO_UNSUPPORTED_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG
+import com.google.jetpackcamera.feature.preview.ui.HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+import com.google.jetpackcamera.settings.model.CaptureMode
+
+sealed interface CaptureModeUiState {
+    data object Unavailable : CaptureModeUiState
+    data class Enabled(
+        val currentSelection: CaptureMode,
+        val defaultCaptureState: SingleSelectableState = SingleSelectableState.Selectable,
+        val videoOnlyCaptureState: SingleSelectableState = SingleSelectableState.Selectable,
+        val imageOnlyCaptureState: SingleSelectableState = SingleSelectableState.Selectable
+    ) : CaptureModeUiState
+}
+
+enum class DisabledReason(val testTag: String, val reasonTextResId: Int) {
+    VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED(
+        VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG,
+        R.string.toast_video_capture_external_unsupported
+    ),
+    IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED(
+        IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG,
+        R.string.toast_image_capture_external_unsupported
+
+    ),
+    IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA(
+        IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG,
+        R.string.toast_image_capture_unsupported_concurrent_camera
+    ),
+    HDR_VIDEO_UNSUPPORTED_ON_DEVICE(
+        HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG,
+        R.string.toast_hdr_video_unsupported_on_device
+    ),
+    HDR_VIDEO_UNSUPPORTED_ON_LENS(
+        HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG,
+        R.string.toast_hdr_video_unsupported_on_lens
+    ),
+    HDR_IMAGE_UNSUPPORTED_ON_DEVICE(
+        HDR_IMAGE_UNSUPPORTED_ON_DEVICE_TAG,
+        R.string.toast_hdr_photo_unsupported_on_device
+    ),
+    HDR_IMAGE_UNSUPPORTED_ON_LENS(
+        HDR_IMAGE_UNSUPPORTED_ON_LENS_TAG,
+        R.string.toast_hdr_photo_unsupported_on_lens
+    ),
+    HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM(
+        HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG,
+        R.string.toast_hdr_photo_unsupported_on_lens_single_stream
+    ),
+    HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM(
+        HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG,
+        R.string.toast_hdr_photo_unsupported_on_lens_multi_stream
+    ),
+    HDR_SIMULTANEOUS_IMAGE_VIDEO_UNSUPPORTED(
+        HDR_SIMULTANEOUS_IMAGE_VIDEO_UNSUPPORTED_TAG,
+        R.string.toast_hdr_simultaneous_image_video_unsupported
+    )
+}
+
+/** State for the individual options on Popup dialog settings */
+sealed interface SingleSelectableState {
+    data object Selectable : SingleSelectableState
+    data class Disabled(val disabledReason: DisabledReason) : SingleSelectableState
+}
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
index 11140fa..4a46ac0 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
@@ -52,7 +52,6 @@ import androidx.hilt.navigation.compose.hiltViewModel
 import androidx.lifecycle.compose.LifecycleStartEffect
 import androidx.tracing.Trace
 import com.google.jetpackcamera.core.camera.VideoRecordingState
-import com.google.jetpackcamera.core.common.getLastImageUri
 import com.google.jetpackcamera.feature.preview.quicksettings.QuickSettingsScreenOverlay
 import com.google.jetpackcamera.feature.preview.ui.CameraControlsOverlay
 import com.google.jetpackcamera.feature.preview.ui.PreviewDisplay
@@ -63,6 +62,7 @@ import com.google.jetpackcamera.feature.preview.ui.ZoomLevelDisplayState
 import com.google.jetpackcamera.feature.preview.ui.debouncedOrientationFlow
 import com.google.jetpackcamera.feature.preview.ui.debug.DebugOverlayComponent
 import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
@@ -82,7 +82,7 @@ private const val TAG = "PreviewScreen"
 @Composable
 fun PreviewScreen(
     onNavigateToSettings: () -> Unit,
-    onNavigateToPostCapture: (uri: Uri?) -> Unit,
+    onNavigateToPostCapture: () -> Unit,
     previewMode: PreviewMode,
     isDebugMode: Boolean,
     modifier: Modifier = Modifier,
@@ -143,14 +143,15 @@ fun PreviewScreen(
                 onClearUiScreenBrightness = viewModel.screenFlash::setClearUiScreenBrightness,
                 onSetLensFacing = viewModel::setLensFacing,
                 onTapToFocus = viewModel::tapToFocus,
-                onChangeZoomScale = viewModel::setZoomScale,
+                onChangeZoomRatio = viewModel::changeZoomRatio,
+                onSetCaptureMode = viewModel::setCaptureMode,
                 onChangeFlash = viewModel::setFlash,
                 onChangeAspectRatio = viewModel::setAspectRatio,
                 onSetStreamConfig = viewModel::setStreamConfig,
                 onChangeDynamicRange = viewModel::setDynamicRange,
                 onChangeConcurrentCameraMode = viewModel::setConcurrentCameraMode,
                 onChangeImageFormat = viewModel::setImageFormat,
-                onToggleWhenDisabled = viewModel::showSnackBarForDisabledHdrToggle,
+                onDisabledCaptureMode = viewModel::enqueueDisabledHdrToggleSnackBar,
                 onToggleQuickSettings = viewModel::toggleQuickSettings,
                 onToggleDebugOverlay = viewModel::toggleDebugOverlay,
                 onSetPause = viewModel::setPaused,
@@ -163,15 +164,11 @@ fun PreviewScreen(
                 onRequestWindowColorMode = onRequestWindowColorMode,
                 onSnackBarResult = viewModel::onSnackBarResult,
                 isDebugMode = isDebugMode,
-                onImageWellClick = { uri -> onNavigateToPostCapture(uri) }
+                onImageWellClick = onNavigateToPostCapture
             )
 
-            // TODO(yasith): Remove and use ImageRepository after implementing
             LaunchedEffect(Unit) {
-                val lastCapturedImageUri = getLastImageUri(context)
-                lastCapturedImageUri?.let { uri ->
-                    viewModel.updateLastCapturedImageUri(uri)
-                }
+                viewModel.updateLastCapturedMedia()
             }
         }
     }
@@ -186,16 +183,17 @@ private fun ContentScreen(
     modifier: Modifier = Modifier,
     onNavigateToSettings: () -> Unit = {},
     onClearUiScreenBrightness: (Float) -> Unit = {},
+    onSetCaptureMode: (CaptureMode) -> Unit = {},
     onSetLensFacing: (newLensFacing: LensFacing) -> Unit = {},
     onTapToFocus: (x: Float, y: Float) -> Unit = { _, _ -> },
-    onChangeZoomScale: (Float) -> Unit = {},
+    onChangeZoomRatio: (CameraZoomRatio) -> Unit = {},
     onChangeFlash: (FlashMode) -> Unit = {},
     onChangeAspectRatio: (AspectRatio) -> Unit = {},
     onSetStreamConfig: (StreamConfig) -> Unit = {},
     onChangeDynamicRange: (DynamicRange) -> Unit = {},
     onChangeConcurrentCameraMode: (ConcurrentCameraMode) -> Unit = {},
     onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
-    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
+    onDisabledCaptureMode: (DisabledReason) -> Unit = {},
     onToggleQuickSettings: () -> Unit = {},
     onToggleDebugOverlay: () -> Unit = {},
     onSetPause: (Boolean) -> Unit = {},
@@ -217,7 +215,7 @@ private fun ContentScreen(
     onRequestWindowColorMode: (Int) -> Unit = {},
     onSnackBarResult: (String) -> Unit = {},
     isDebugMode: Boolean = false,
-    onImageWellClick: (uri: Uri?) -> Unit = {}
+    onImageWellClick: () -> Unit = {}
 ) {
     val snackbarHostState = remember { SnackbarHostState() }
     Scaffold(
@@ -244,7 +242,7 @@ private fun ContentScreen(
                 previewUiState = previewUiState,
                 onFlipCamera = onFlipCamera,
                 onTapToFocus = onTapToFocus,
-                onZoomChange = onChangeZoomScale,
+                onZoomRatioChange = onChangeZoomRatio,
                 aspectRatio = previewUiState.currentCameraSettings.aspectRatio,
                 surfaceRequest = surfaceRequest,
                 onRequestWindowColorMode = onRequestWindowColorMode
@@ -254,7 +252,7 @@ private fun ContentScreen(
                 modifier = Modifier,
                 previewUiState = previewUiState,
                 isOpen = previewUiState.quickSettingsIsOpen,
-                toggleIsOpen = onToggleQuickSettings,
+                toggleQuickSettings = onToggleQuickSettings,
                 currentCameraSettings = previewUiState.currentCameraSettings,
                 onLensFaceClick = onSetLensFacing,
                 onFlashModeClick = onChangeFlash,
@@ -262,19 +260,22 @@ private fun ContentScreen(
                 onStreamConfigClick = onSetStreamConfig,
                 onDynamicRangeClick = onChangeDynamicRange,
                 onImageOutputFormatClick = onChangeImageFormat,
-                onConcurrentCameraModeClick = onChangeConcurrentCameraMode
+                onConcurrentCameraModeClick = onChangeConcurrentCameraMode,
+                onCaptureModeClick = onSetCaptureMode
             )
             // relative-grid style overlay on top of preview display
             CameraControlsOverlay(
                 previewUiState = previewUiState,
                 onNavigateToSettings = onNavigateToSettings,
+                onSetCaptureMode = onSetCaptureMode,
                 onFlipCamera = onFlipCamera,
                 onChangeFlash = onChangeFlash,
                 onToggleAudio = onToggleAudio,
+                onSetZoom = onChangeZoomRatio,
                 onToggleQuickSettings = onToggleQuickSettings,
                 onToggleDebugOverlay = onToggleDebugOverlay,
                 onChangeImageFormat = onChangeImageFormat,
-                onToggleWhenDisabled = onToggleWhenDisabled,
+                onDisabledCaptureMode = onDisabledCaptureMode,
                 onSetPause = onSetPause,
                 onCaptureImageWithUri = onCaptureImageWithUri,
                 onStartVideoRecording = onStartVideoRecording,
@@ -287,7 +288,7 @@ private fun ContentScreen(
             DebugOverlayComponent(
                 toggleIsOpen = onToggleDebugOverlay,
                 previewUiState = previewUiState,
-                onChangeZoomScale = onChangeZoomScale
+                onChangeZoomRatio = onChangeZoomRatio
             )
 
             // displays toast when there is a message to show
@@ -299,10 +300,11 @@ private fun ContentScreen(
                 )
             }
 
-            if (previewUiState.snackBarToShow != null) {
+            val snackBarData = previewUiState.snackBarQueue.peek()
+            if (snackBarData != null) {
                 TestableSnackbar(
-                    modifier = Modifier.testTag(previewUiState.snackBarToShow.testTag),
-                    snackbarToShow = previewUiState.snackBarToShow,
+                    modifier = Modifier.testTag(snackBarData.testTag),
+                    snackbarToShow = snackBarData,
                     snackbarHostState = snackbarHostState,
                     onSnackbarResult = onSnackBarResult
                 )
@@ -415,7 +417,7 @@ private val FAKE_PREVIEW_UI_STATE_READY = PreviewUiState.Ready(
     videoRecordingState = VideoRecordingState.Inactive(),
     systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
     previewMode = PreviewMode.StandardMode {},
-    captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+    captureModeToggleUiState = CaptureModeUiState.Unavailable
 )
 
 private val FAKE_PREVIEW_UI_STATE_PRESSED_RECORDING = FAKE_PREVIEW_UI_STATE_READY.copy(
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
index 9b097e6..5ffcf64 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
@@ -15,6 +15,7 @@
  */
 package com.google.jetpackcamera.feature.preview
 
+import android.util.Range
 import android.util.Size
 import com.google.jetpackcamera.core.camera.VideoRecordingState
 import com.google.jetpackcamera.feature.preview.ui.ImageWellUiState
@@ -22,10 +23,14 @@ import com.google.jetpackcamera.feature.preview.ui.SnackbarData
 import com.google.jetpackcamera.feature.preview.ui.ToastMessage
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.SystemConstraints
 import com.google.jetpackcamera.settings.model.VideoQuality
+import java.util.LinkedList
+import java.util.Queue
 
 /**
  * Defines the current state of the [PreviewScreen].
@@ -37,16 +42,15 @@ sealed interface PreviewUiState {
         // "quick" settings
         val currentCameraSettings: CameraAppSettings = CameraAppSettings(),
         val systemConstraints: SystemConstraints = SystemConstraints(),
-        val zoomScale: Float = 1f,
         val videoRecordingState: VideoRecordingState = VideoRecordingState.Inactive(),
         val quickSettingsIsOpen: Boolean = false,
 
         // todo: remove after implementing post capture screen
         val toastMessageToShow: ToastMessage? = null,
-        val snackBarToShow: SnackbarData? = null,
+        val snackBarQueue: Queue<SnackbarData> = LinkedList(),
         val lastBlinkTimeStamp: Long = 0,
         val previewMode: PreviewMode = PreviewMode.StandardMode {},
-        val captureModeToggleUiState: CaptureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+        val captureModeToggleUiState: CaptureModeUiState = CaptureModeUiState.Unavailable,
         val sessionFirstFrameTimestamp: Long = 0L,
         val currentPhysicalCameraId: String? = null,
         val currentLogicalCameraId: String? = null,
@@ -57,7 +61,10 @@ sealed interface PreviewUiState {
         val audioUiState: AudioUiState = AudioUiState.Disabled,
         val elapsedTimeUiState: ElapsedTimeUiState = ElapsedTimeUiState.Unavailable,
         val captureButtonUiState: CaptureButtonUiState = CaptureButtonUiState.Unavailable,
-        val imageWellUiState: ImageWellUiState = ImageWellUiState.NoPreviousCapture
+        val imageWellUiState: ImageWellUiState = ImageWellUiState.Unavailable,
+        val captureModeUiState: CaptureModeUiState = CaptureModeUiState.Unavailable,
+        val zoomUiState: ZoomUiState = ZoomUiState.Unavailable,
+        val hdrUiState: HdrUiState = HdrUiState.Unavailable
     ) : PreviewUiState
 }
 
@@ -80,12 +87,26 @@ sealed interface CaptureButtonUiState {
         }
     }
 }
+
 sealed interface ElapsedTimeUiState {
     data object Unavailable : ElapsedTimeUiState
-
     data class Enabled(val elapsedTimeNanos: Long) : ElapsedTimeUiState
 }
-
+sealed interface HdrUiState {
+    data object Unavailable : HdrUiState
+    data class Available(
+        val currentImageOutputFormat: ImageOutputFormat,
+        val currentDynamicRange: DynamicRange
+    ) : HdrUiState
+}
+sealed interface ZoomUiState {
+    data object Unavailable : ZoomUiState
+    data class Enabled(
+        val primaryZoomRange: Range<Float>,
+        val primaryZoomRatio: Float? = null,
+        val primaryLinearZoom: Float? = null
+    ) : ZoomUiState
+}
 sealed interface AudioUiState {
     val amplitude: Double
 
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
index 12deedf..916862a 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
@@ -19,6 +19,7 @@ import android.content.ContentResolver
 import android.net.Uri
 import android.os.SystemClock
 import android.util.Log
+import android.util.Range
 import android.util.Size
 import androidx.camera.core.SurfaceRequest
 import androidx.lifecycle.ViewModel
@@ -29,6 +30,7 @@ import com.google.jetpackcamera.core.camera.CameraState
 import com.google.jetpackcamera.core.camera.CameraUseCase
 import com.google.jetpackcamera.core.camera.VideoRecordingState
 import com.google.jetpackcamera.core.common.traceFirstFramePreview
+import com.google.jetpackcamera.data.media.MediaRepository
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
@@ -42,6 +44,7 @@ import com.google.jetpackcamera.settings.SettingsRepository
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CameraConstraints
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DeviceRotation
@@ -53,14 +56,12 @@ import com.google.jetpackcamera.settings.model.LowLightBoostState
 import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.SystemConstraints
-import com.google.jetpackcamera.settings.model.VideoQuality
 import com.google.jetpackcamera.settings.model.forCurrentLens
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
 import dagger.hilt.android.lifecycle.HiltViewModel
-import kotlin.reflect.KProperty
-import kotlin.reflect.full.memberProperties
+import java.util.LinkedList
 import kotlin.time.Duration.Companion.seconds
 import kotlinx.atomicfu.atomic
 import kotlinx.coroutines.CoroutineStart
@@ -75,7 +76,6 @@ import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.flow.transform
 import kotlinx.coroutines.flow.transformWhile
 import kotlinx.coroutines.flow.update
 import kotlinx.coroutines.launch
@@ -92,7 +92,8 @@ class PreviewViewModel @AssistedInject constructor(
     @Assisted val isDebugMode: Boolean,
     private val cameraUseCase: CameraUseCase,
     private val settingsRepository: SettingsRepository,
-    private val constraintsRepository: ConstraintsRepository
+    private val constraintsRepository: ConstraintsRepository,
+    private val mediaRepository: MediaRepository
 ) : ViewModel() {
     private val _previewUiState: MutableStateFlow<PreviewUiState> =
         MutableStateFlow(PreviewUiState.NotReady)
@@ -142,15 +143,13 @@ class PreviewViewModel @AssistedInject constructor(
         viewModelScope.launch {
             launch {
                 var oldCameraAppSettings: CameraAppSettings? = null
-                settingsRepository.defaultCameraAppSettings.transform { new ->
-                    val old = oldCameraAppSettings
-                    if (old != null) {
-                        emit(getSettingsDiff(old, new))
+                settingsRepository.defaultCameraAppSettings
+                    .collect { new ->
+                        oldCameraAppSettings?.apply {
+                            applyDiffs(new)
+                        }
+                        oldCameraAppSettings = new
                     }
-                    oldCameraAppSettings = new
-                }.collect { diffQueue ->
-                    applySettingsDiff(diffQueue)
-                }
             }
             combine(
                 cameraUseCase.getCurrentSettings().filterNotNull(),
@@ -198,13 +197,8 @@ class PreviewViewModel @AssistedInject constructor(
                         previewMode = previewMode,
                         currentCameraSettings = cameraAppSettings.applyPreviewMode(previewMode),
                         systemConstraints = systemConstraints,
-                        zoomScale = cameraState.zoomScale,
                         videoRecordingState = cameraState.videoRecordingState,
                         sessionFirstFrameTimestamp = cameraState.sessionFirstFrameTimestamp,
-                        captureModeToggleUiState = getCaptureToggleUiState(
-                            systemConstraints,
-                            cameraAppSettings
-                        ),
                         currentLogicalCameraId = cameraState.debugInfo.logicalCameraId,
                         currentPhysicalCameraId = cameraState.debugInfo.physicalCameraId,
                         debugUiState = DebugUiState(
@@ -230,18 +224,37 @@ class PreviewViewModel @AssistedInject constructor(
                             cameraAppSettings,
                             cameraState,
                             lockedState
-                        )
+                        ),
+                        zoomUiState = getZoomUiState(
+                            systemConstraints,
+                            cameraAppSettings.cameraLensFacing,
+                            cameraState
+                        ),
+                        captureModeToggleUiState = getCaptureToggleUiState(
+                            systemConstraints,
+                            cameraAppSettings,
+                            cameraState.videoRecordingState
+                        ),
+                        captureModeUiState = getCaptureModeUiState(
+                            systemConstraints,
+                            cameraAppSettings
+                        ),
+                        hdrUiState = getHdrUiState(systemConstraints, cameraAppSettings)
                     )
                 }
             }.collect {}
         }
     }
 
-    fun updateLastCapturedImageUri(uri: Uri) {
+    fun updateLastCapturedMedia() {
         viewModelScope.launch {
+            val lastCapturedMediaDescriptor = mediaRepository.getLastCapturedMedia()
             _previewUiState.update { old ->
-                (old as PreviewUiState.Ready)
-                    .copy(imageWellUiState = ImageWellUiState.LastCapture(uri))
+                (old as PreviewUiState.Ready).copy(
+                    imageWellUiState = ImageWellUiState.LastCapture(
+                        mediaDescriptor = lastCapturedMediaDescriptor
+                    )
+                ) ?: old
             }
         }
     }
@@ -357,68 +370,41 @@ class PreviewViewModel @AssistedInject constructor(
     }
 
     /**
-     * Returns the difference between two [CameraAppSettings] as a mapping of <[KProperty], [Any]>.
+     * Applies an individual camera app setting with the given [settingExtractor] and
+     * [settingApplicator] if the new setting differs from the old setting.
      */
-    private fun getSettingsDiff(
-        oldCameraAppSettings: CameraAppSettings,
-        newCameraAppSettings: CameraAppSettings
-    ): Map<KProperty<Any?>, Any?> = buildMap<KProperty<Any?>, Any?> {
-        CameraAppSettings::class.memberProperties.forEach { property ->
-            if (property.get(oldCameraAppSettings) != property.get(newCameraAppSettings)) {
-                put(property, property.get(newCameraAppSettings))
-            }
+    private suspend inline fun <R> CameraAppSettings.applyDiff(
+        new: CameraAppSettings,
+        settingExtractor: CameraAppSettings.() -> R,
+        crossinline settingApplicator: suspend (R) -> Unit
+    ) {
+        val oldSetting = settingExtractor.invoke(this)
+        val newSetting = settingExtractor.invoke(new)
+        if (oldSetting != newSetting) {
+            settingApplicator(newSetting)
         }
     }
 
     /**
-     * Iterates through a queue of [Pair]<[KProperty], [Any]> and attempt to apply them to
+     * Checks whether each actionable individual setting has changed and applies them to
      * [CameraUseCase].
      */
-    private suspend fun applySettingsDiff(diffSettingsMap: Map<KProperty<Any?>, Any?>) {
-        diffSettingsMap.entries.forEach { entry ->
-            when (entry.key) {
-                CameraAppSettings::cameraLensFacing -> {
-                    cameraUseCase.setLensFacing(entry.value as LensFacing)
-                }
-
-                CameraAppSettings::flashMode -> {
-                    cameraUseCase.setFlashMode(entry.value as FlashMode)
-                }
-
-                CameraAppSettings::streamConfig -> {
-                    cameraUseCase.setStreamConfig(entry.value as StreamConfig)
-                }
-
-                CameraAppSettings::aspectRatio -> {
-                    cameraUseCase.setAspectRatio(entry.value as AspectRatio)
-                }
-
-                CameraAppSettings::stabilizationMode -> {
-                    cameraUseCase.setStabilizationMode(entry.value as StabilizationMode)
-                }
-
-                CameraAppSettings::targetFrameRate -> {
-                    cameraUseCase.setTargetFrameRate(entry.value as Int)
-                }
-
-                CameraAppSettings::maxVideoDurationMillis -> {
-                    cameraUseCase.setMaxVideoDuration(entry.value as Long)
-                }
-
-                CameraAppSettings::videoQuality -> {
-                    cameraUseCase.setVideoQuality(entry.value as VideoQuality)
-                }
-
-                CameraAppSettings::audioEnabled -> {
-                    cameraUseCase.setAudioEnabled(entry.value as Boolean)
-                }
-
-                CameraAppSettings::darkMode -> {}
-
-                else -> TODO("Unhandled CameraAppSetting $entry")
-            }
-        }
+    private suspend fun CameraAppSettings.applyDiffs(new: CameraAppSettings) {
+        applyDiff(new, CameraAppSettings::cameraLensFacing, cameraUseCase::setLensFacing)
+        applyDiff(new, CameraAppSettings::flashMode, cameraUseCase::setFlashMode)
+        applyDiff(new, CameraAppSettings::streamConfig, cameraUseCase::setStreamConfig)
+        applyDiff(new, CameraAppSettings::aspectRatio, cameraUseCase::setAspectRatio)
+        applyDiff(new, CameraAppSettings::stabilizationMode, cameraUseCase::setStabilizationMode)
+        applyDiff(new, CameraAppSettings::targetFrameRate, cameraUseCase::setTargetFrameRate)
+        applyDiff(
+            new,
+            CameraAppSettings::maxVideoDurationMillis,
+            cameraUseCase::setMaxVideoDuration
+        )
+        applyDiff(new, CameraAppSettings::videoQuality, cameraUseCase::setVideoQuality)
+        applyDiff(new, CameraAppSettings::audioEnabled, cameraUseCase::setAudioEnabled)
     }
+
     fun getCaptureButtonUiState(
         cameraAppSettings: CameraAppSettings,
         cameraState: CameraState,
@@ -442,79 +428,222 @@ class PreviewViewModel @AssistedInject constructor(
                 .Enabled.Idle(captureMode = cameraAppSettings.captureMode)
     }
 
-    private fun getCaptureToggleUiState(
+    private fun getZoomUiState(
+        systemConstraints: SystemConstraints,
+        lensFacing: LensFacing,
+        cameraState: CameraState
+    ): ZoomUiState = ZoomUiState.Enabled(
+        primaryZoomRange =
+        systemConstraints.perLensConstraints[lensFacing]?.supportedZoomRange
+            ?: Range<Float>(1f, 1f),
+        primaryZoomRatio = cameraState.zoomRatios[lensFacing],
+        primaryLinearZoom = cameraState.linearZoomScales[lensFacing]
+    )
+
+    private fun getHdrUiState(
         systemConstraints: SystemConstraints,
         cameraAppSettings: CameraAppSettings
-    ): CaptureModeToggleUiState {
+    ): HdrUiState {
         val cameraConstraints: CameraConstraints? = systemConstraints.forCurrentLens(
             cameraAppSettings
         )
-        val hdrDynamicRangeSupported = cameraConstraints?.let {
-            it.supportedDynamicRanges.size > 1
-        } ?: false
-        val hdrImageFormatSupported =
-            cameraConstraints?.supportedImageFormatsMap?.get(cameraAppSettings.streamConfig)?.let {
-                it.size > 1
-            } ?: false
-        val isShown = previewMode is PreviewMode.ExternalImageCaptureMode ||
-            previewMode is PreviewMode.ExternalVideoCaptureMode ||
-            cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR ||
-            cameraAppSettings.dynamicRange == DynamicRange.HLG10 ||
-            cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.DUAL
-        val enabled = previewMode !is PreviewMode.ExternalImageCaptureMode &&
-            previewMode !is PreviewMode.ExternalVideoCaptureMode &&
-            hdrDynamicRangeSupported &&
-            hdrImageFormatSupported &&
-            cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.OFF
-        return if (isShown) {
-            val currentMode = if (
-                cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.OFF &&
-                previewMode is PreviewMode.ExternalImageCaptureMode ||
-                cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+        return when (previewMode) {
+            is PreviewMode.ExternalImageCaptureMode,
+            is PreviewMode.ExternalMultipleImageCaptureMode -> if (
+                cameraConstraints
+                    ?.supportedImageFormatsMap?.get(cameraAppSettings.streamConfig)
+                    ?.contains(ImageOutputFormat.JPEG_ULTRA_HDR) ?: false
+            ) {
+                HdrUiState.Available(cameraAppSettings.imageFormat, cameraAppSettings.dynamicRange)
+            } else {
+                HdrUiState.Unavailable
+            }
+
+            is PreviewMode.ExternalVideoCaptureMode -> if (
+                cameraConstraints?.supportedDynamicRanges?.contains(DynamicRange.HLG10) == true &&
+                cameraAppSettings.concurrentCameraMode != ConcurrentCameraMode.DUAL
             ) {
-                CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE
+                HdrUiState.Available(
+                    cameraAppSettings.imageFormat,
+                    cameraAppSettings.dynamicRange
+                )
             } else {
-                CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO
+                HdrUiState.Unavailable
             }
-            if (enabled) {
-                CaptureModeToggleUiState.Enabled(currentMode)
+
+            is PreviewMode.StandardMode -> if ((
+                    cameraConstraints?.supportedDynamicRanges?.contains(DynamicRange.HLG10) ==
+                        true ||
+                        cameraConstraints?.supportedImageFormatsMap?.get(
+                            cameraAppSettings.streamConfig
+                        )
+                            ?.contains(ImageOutputFormat.JPEG_ULTRA_HDR) ?: false
+                    ) &&
+                cameraAppSettings.concurrentCameraMode != ConcurrentCameraMode.DUAL
+            ) {
+                HdrUiState.Available(cameraAppSettings.imageFormat, cameraAppSettings.dynamicRange)
             } else {
-                CaptureModeToggleUiState.Disabled(
-                    currentMode,
-                    getCaptureToggleUiStateDisabledReason(
-                        currentMode,
-                        hdrDynamicRangeSupported,
-                        hdrImageFormatSupported,
+                HdrUiState.Unavailable
+            }
+        }
+    }
+
+    private fun getCaptureModeUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings
+    ): CaptureModeUiState {
+        val cameraConstraints: CameraConstraints? = systemConstraints.forCurrentLens(
+            cameraAppSettings
+        )
+        val isHdrOn = cameraAppSettings.dynamicRange == DynamicRange.HLG10 ||
+            cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+        val currentHdrDynamicRangeSupported =
+            if (isHdrOn) {
+                cameraConstraints?.supportedDynamicRanges?.contains(DynamicRange.HLG10) == true
+            } else {
+                true
+            }
+
+        val currentHdrImageFormatSupported =
+            if (isHdrOn) {
+                cameraConstraints?.supportedImageFormatsMap?.get(
+                    cameraAppSettings.streamConfig
+                )?.contains(ImageOutputFormat.JPEG_ULTRA_HDR) == true
+            } else {
+                true
+            }
+        val supportedCaptureModes = getSupportedCaptureModes(
+            cameraAppSettings,
+            isHdrOn,
+            currentHdrDynamicRangeSupported,
+            currentHdrImageFormatSupported
+        )
+        // if all capture modes are supported, return capturemodeuistate
+        if (supportedCaptureModes.containsAll(
+                listOf(
+                    CaptureMode.STANDARD,
+                    CaptureMode.IMAGE_ONLY,
+                    CaptureMode.VIDEO_ONLY
+                )
+            )
+        ) {
+            return CaptureModeUiState.Enabled(currentSelection = cameraAppSettings.captureMode)
+        }
+        // if all capture modes are not supported, give disabledReason
+        // if image or video is not supported, default will also be disabled
+        else {
+            lateinit var defaultCaptureState: SingleSelectableState.Disabled
+            lateinit var imageCaptureState: SingleSelectableState
+            lateinit var videoCaptureState: SingleSelectableState
+            if (!supportedCaptureModes.contains(CaptureMode.VIDEO_ONLY)) {
+                val disabledReason =
+                    getCaptureModeDisabledReason(
+                        disabledCaptureMode = CaptureMode.VIDEO_ONLY,
+                        hdrDynamicRangeSupported = currentHdrDynamicRangeSupported,
+                        hdrImageFormatSupported = currentHdrImageFormatSupported,
+                        systemConstraints = systemConstraints,
+                        cameraAppSettings.cameraLensFacing,
+                        cameraAppSettings.streamConfig,
+                        cameraAppSettings.concurrentCameraMode
+                    )
+
+                imageCaptureState = SingleSelectableState.Selectable
+                videoCaptureState = SingleSelectableState.Disabled(disabledReason = disabledReason)
+                defaultCaptureState =
+                    SingleSelectableState.Disabled(disabledReason = disabledReason)
+            } else if (!supportedCaptureModes.contains(CaptureMode.IMAGE_ONLY)) {
+                val disabledReason =
+                    getCaptureModeDisabledReason(
+                        disabledCaptureMode = CaptureMode.IMAGE_ONLY,
+                        currentHdrDynamicRangeSupported,
+                        currentHdrImageFormatSupported,
                         systemConstraints,
                         cameraAppSettings.cameraLensFacing,
                         cameraAppSettings.streamConfig,
                         cameraAppSettings.concurrentCameraMode
                     )
-                )
+
+                videoCaptureState = SingleSelectableState.Selectable
+                imageCaptureState = SingleSelectableState.Disabled(disabledReason = disabledReason)
+                defaultCaptureState =
+                    SingleSelectableState.Disabled(disabledReason = disabledReason)
+            } else {
+                videoCaptureState = SingleSelectableState.Selectable
+                imageCaptureState = SingleSelectableState.Selectable
+                defaultCaptureState =
+                    SingleSelectableState.Disabled(
+                        disabledReason = DisabledReason.HDR_SIMULTANEOUS_IMAGE_VIDEO_UNSUPPORTED
+                    )
             }
+            return CaptureModeUiState.Enabled(
+                currentSelection = cameraAppSettings.captureMode,
+                videoOnlyCaptureState = videoCaptureState,
+                imageOnlyCaptureState = imageCaptureState,
+                defaultCaptureState = defaultCaptureState
+            )
+        }
+    }
+
+    fun getCaptureToggleUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings,
+        videoRecordingState: VideoRecordingState
+    ): CaptureModeUiState = if (videoRecordingState !is VideoRecordingState.Inactive) {
+        CaptureModeUiState.Unavailable
+    } else if (cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR ||
+        cameraAppSettings.dynamicRange == DynamicRange.HLG10
+    ) {
+        getCaptureModeUiState(systemConstraints, cameraAppSettings)
+    } else {
+        CaptureModeUiState.Unavailable
+    }
+
+    private fun getSupportedCaptureModes(
+        cameraAppSettings: CameraAppSettings,
+        isHdrOn: Boolean,
+        currentHdrDynamicRangeSupported: Boolean,
+        currentHdrImageFormatSupported: Boolean
+    ): List<CaptureMode> = if (
+        previewMode !is PreviewMode.ExternalImageCaptureMode &&
+        previewMode !is PreviewMode.ExternalVideoCaptureMode &&
+        currentHdrDynamicRangeSupported &&
+        currentHdrImageFormatSupported &&
+        cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.OFF
+    ) {
+        // do not allow both use cases to be bound if hdr is on
+        if (isHdrOn) {
+            listOf(CaptureMode.IMAGE_ONLY, CaptureMode.VIDEO_ONLY)
         } else {
-            CaptureModeToggleUiState.Invisible
+            listOf(CaptureMode.STANDARD, CaptureMode.IMAGE_ONLY, CaptureMode.VIDEO_ONLY)
         }
+    } else if (
+        cameraAppSettings.concurrentCameraMode == ConcurrentCameraMode.OFF &&
+        previewMode is PreviewMode.ExternalImageCaptureMode ||
+        cameraAppSettings.imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+    ) {
+        listOf(CaptureMode.IMAGE_ONLY)
+    } else {
+        listOf(CaptureMode.VIDEO_ONLY)
     }
 
-    private fun getCaptureToggleUiStateDisabledReason(
-        captureModeToggleUiState: CaptureModeToggleUiState.ToggleMode,
+    private fun getCaptureModeDisabledReason(
+        disabledCaptureMode: CaptureMode,
         hdrDynamicRangeSupported: Boolean,
         hdrImageFormatSupported: Boolean,
         systemConstraints: SystemConstraints,
         currentLensFacing: LensFacing,
         currentStreamConfig: StreamConfig,
         concurrentCameraMode: ConcurrentCameraMode
-    ): CaptureModeToggleUiState.DisabledReason {
-        when (captureModeToggleUiState) {
-            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO -> {
+    ): DisabledReason {
+        when (disabledCaptureMode) {
+            CaptureMode.IMAGE_ONLY -> {
                 if (previewMode is PreviewMode.ExternalVideoCaptureMode) {
-                    return CaptureModeToggleUiState.DisabledReason
+                    return DisabledReason
                         .IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED
                 }
 
                 if (concurrentCameraMode == ConcurrentCameraMode.DUAL) {
-                    return CaptureModeToggleUiState.DisabledReason
+                    return DisabledReason
                         .IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA
                 }
 
@@ -527,41 +656,47 @@ class PreviewViewModel @AssistedInject constructor(
                     ) {
                         return when (currentStreamConfig) {
                             StreamConfig.MULTI_STREAM ->
-                                CaptureModeToggleUiState.DisabledReason
+                                DisabledReason
                                     .HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM
 
                             StreamConfig.SINGLE_STREAM ->
-                                CaptureModeToggleUiState.DisabledReason
+                                DisabledReason
                                     .HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM
                         }
                     }
 
                     // Check if any other lens supports HDR image
                     if (systemConstraints.anySupportsUltraHdr { it != currentLensFacing }) {
-                        return CaptureModeToggleUiState.DisabledReason.HDR_IMAGE_UNSUPPORTED_ON_LENS
+                        return DisabledReason.HDR_IMAGE_UNSUPPORTED_ON_LENS
                     }
 
                     // No lenses support HDR image on device
-                    return CaptureModeToggleUiState.DisabledReason.HDR_IMAGE_UNSUPPORTED_ON_DEVICE
+                    return DisabledReason.HDR_IMAGE_UNSUPPORTED_ON_DEVICE
                 }
 
-                throw RuntimeException("Unknown DisabledReason for video mode.")
+                throw RuntimeException("Unknown DisabledReason for capture mode.")
             }
 
-            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE -> {
-                if (previewMode is PreviewMode.ExternalImageCaptureMode) {
-                    return CaptureModeToggleUiState.DisabledReason
+            CaptureMode.VIDEO_ONLY -> {
+                if (previewMode is PreviewMode.ExternalImageCaptureMode ||
+                    previewMode is PreviewMode.ExternalMultipleImageCaptureMode
+                ) {
+                    return DisabledReason
                         .VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED
                 }
 
                 if (!hdrDynamicRangeSupported) {
                     if (systemConstraints.anySupportsHdrDynamicRange { it != currentLensFacing }) {
-                        return CaptureModeToggleUiState.DisabledReason.HDR_VIDEO_UNSUPPORTED_ON_LENS
+                        return DisabledReason.HDR_VIDEO_UNSUPPORTED_ON_LENS
                     }
-                    return CaptureModeToggleUiState.DisabledReason.HDR_VIDEO_UNSUPPORTED_ON_DEVICE
+                    return DisabledReason.HDR_VIDEO_UNSUPPORTED_ON_DEVICE
                 }
 
-                throw RuntimeException("Unknown DisabledReason for image mode.")
+                throw RuntimeException("Unknown DisabledReason for video mode.")
+            }
+
+            CaptureMode.STANDARD -> {
+                TODO()
             }
         }
     }
@@ -673,21 +808,30 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    private fun showExternalVideoCaptureUnsupportedToast() {
+    private fun addSnackBarData(snackBarData: SnackbarData) {
         viewModelScope.launch {
             _previewUiState.update { old ->
+                val newQueue = LinkedList((old as? PreviewUiState.Ready)?.snackBarQueue!!)
+                newQueue.add(snackBarData)
+                Log.d(TAG, "SnackBar added. Queue size: ${newQueue.size}")
                 (old as? PreviewUiState.Ready)?.copy(
-                    snackBarToShow = SnackbarData(
-                        cookie = "Image-ExternalVideoCaptureMode",
-                        stringResource = R.string.toast_image_capture_external_unsupported,
-                        withDismissAction = true,
-                        testTag = IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-                    )
+                    snackBarQueue = newQueue
                 ) ?: old
             }
         }
     }
 
+    private fun enqueueExternalImageCaptureUnsupportedSnackBar() {
+        addSnackBarData(
+            SnackbarData(
+                cookie = "Image-ExternalVideoCaptureMode",
+                stringResource = R.string.toast_image_capture_external_unsupported,
+                withDismissAction = true,
+                testTag = IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+            )
+        )
+    }
+
     fun captureImageWithUri(
         contentResolver: ContentResolver,
         imageCaptureUri: Uri?,
@@ -698,7 +842,7 @@ class PreviewViewModel @AssistedInject constructor(
             (previewUiState.value as PreviewUiState.Ready).previewMode is
                 PreviewMode.ExternalVideoCaptureMode
         ) {
-            showExternalVideoCaptureUnsupportedToast()
+            enqueueExternalImageCaptureUnsupportedSnackBar()
             return
         }
 
@@ -706,18 +850,14 @@ class PreviewViewModel @AssistedInject constructor(
             (previewUiState.value as PreviewUiState.Ready).previewMode is
                 PreviewMode.ExternalVideoCaptureMode
         ) {
-            viewModelScope.launch {
-                _previewUiState.update { old ->
-                    (old as? PreviewUiState.Ready)?.copy(
-                        snackBarToShow = SnackbarData(
-                            cookie = "Image-ExternalVideoCaptureMode",
-                            stringResource = R.string.toast_image_capture_external_unsupported,
-                            withDismissAction = true,
-                            testTag = IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-                        )
-                    ) ?: old
-                }
-            }
+            addSnackBarData(
+                SnackbarData(
+                    cookie = "Image-ExternalVideoCaptureMode",
+                    stringResource = R.string.toast_image_capture_external_unsupported,
+                    withDismissAction = true,
+                    testTag = IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+                )
+            )
             return
         }
         Log.d(TAG, "captureImageWithUri")
@@ -745,9 +885,7 @@ class PreviewViewModel @AssistedInject constructor(
                     }, contentResolver, finalImageUri, ignoreUri).savedUri
                 },
                 onSuccess = { savedUri ->
-                    savedUri?.let {
-                        updateLastCapturedImageUri(it)
-                    }
+                    updateLastCapturedMedia()
                     onImageCapture(ImageCaptureEvent.ImageSaved(savedUri), uriIndex)
                 },
                 onFailure = { exception ->
@@ -800,30 +938,21 @@ class PreviewViewModel @AssistedInject constructor(
                 testTag = IMAGE_CAPTURE_FAILURE_TAG
             )
         }.also { snackBarData ->
-            _previewUiState.update { old ->
-                (old as? PreviewUiState.Ready)?.copy(
-                    // todo: remove snackBar after postcapture screen implemented
-                    snackBarToShow = snackBarData
-                ) ?: old
-            }
+            addSnackBarData(snackBarData)
         }
     }
 
-    fun showSnackBarForDisabledHdrToggle(disabledReason: CaptureModeToggleUiState.DisabledReason) {
+    fun enqueueDisabledHdrToggleSnackBar(disabledReason: DisabledReason) {
         val cookieInt = snackBarCount.incrementAndGet()
         val cookie = "DisabledHdrToggle-$cookieInt"
-        viewModelScope.launch {
-            _previewUiState.update { old ->
-                (old as? PreviewUiState.Ready)?.copy(
-                    snackBarToShow = SnackbarData(
-                        cookie = cookie,
-                        stringResource = disabledReason.reasonTextResId,
-                        withDismissAction = true,
-                        testTag = disabledReason.testTag
-                    )
-                ) ?: old
-            }
-        }
+        addSnackBarData(
+            SnackbarData(
+                cookie = cookie,
+                stringResource = disabledReason.reasonTextResId,
+                withDismissAction = true,
+                testTag = disabledReason.testTag
+            )
+        )
     }
 
     fun startVideoRecording(
@@ -836,18 +965,14 @@ class PreviewViewModel @AssistedInject constructor(
                 PreviewMode.ExternalImageCaptureMode
         ) {
             Log.d(TAG, "externalVideoRecording")
-            viewModelScope.launch {
-                _previewUiState.update { old ->
-                    (old as? PreviewUiState.Ready)?.copy(
-                        snackBarToShow = SnackbarData(
-                            cookie = "Video-ExternalImageCaptureMode",
-                            stringResource = R.string.toast_video_capture_external_unsupported,
-                            withDismissAction = true,
-                            testTag = VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-                        )
-                    ) ?: old
-                }
-            }
+            addSnackBarData(
+                SnackbarData(
+                    cookie = "Video-ExternalImageCaptureMode",
+                    stringResource = R.string.toast_video_capture_external_unsupported,
+                    withDismissAction = true,
+                    testTag = VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
+                )
+            )
             return
         }
         Log.d(TAG, "startVideoRecording")
@@ -866,6 +991,7 @@ class PreviewViewModel @AssistedInject constructor(
                                 withDismissAction = true,
                                 testTag = VIDEO_CAPTURE_SUCCESS_TAG
                             )
+                            updateLastCapturedMedia()
                         }
 
                         is CameraUseCase.OnVideoRecordEvent.OnVideoRecordError -> {
@@ -880,13 +1006,7 @@ class PreviewViewModel @AssistedInject constructor(
                         }
                     }
 
-                    viewModelScope.launch {
-                        _previewUiState.update { old ->
-                            (old as? PreviewUiState.Ready)?.copy(
-                                snackBarToShow = snackbarToShow
-                            ) ?: old
-                        }
-                    }
+                    addSnackBarData(snackbarToShow)
                 }
                 Log.d(TAG, "cameraUseCase.startRecording success")
             } catch (exception: IllegalStateException) {
@@ -901,7 +1021,6 @@ class PreviewViewModel @AssistedInject constructor(
             cameraUseCase.stopVideoRecording()
             recordingJob?.cancel()
         }
-        setLockedRecording(false)
     }
 
     /**
@@ -915,13 +1034,17 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun setZoomScale(scale: Float) {
-        cameraUseCase.setZoomScale(scale = scale)
+    fun changeZoomRatio(newZoomState: CameraZoomRatio) {
+        cameraUseCase.changeZoomRatio(newZoomState = newZoomState)
     }
 
     fun setDynamicRange(dynamicRange: DynamicRange) {
-        viewModelScope.launch {
-            cameraUseCase.setDynamicRange(dynamicRange)
+        if (previewMode !is PreviewMode.ExternalImageCaptureMode &&
+            previewMode !is PreviewMode.ExternalMultipleImageCaptureMode
+        ) {
+            viewModelScope.launch {
+                cameraUseCase.setDynamicRange(dynamicRange)
+            }
         }
     }
 
@@ -932,8 +1055,16 @@ class PreviewViewModel @AssistedInject constructor(
     }
 
     fun setImageFormat(imageFormat: ImageOutputFormat) {
+        if (previewMode !is PreviewMode.ExternalVideoCaptureMode) {
+            viewModelScope.launch {
+                cameraUseCase.setImageFormat(imageFormat)
+            }
+        }
+    }
+
+    fun setCaptureMode(captureMode: CaptureMode) {
         viewModelScope.launch {
-            cameraUseCase.setImageFormat(imageFormat)
+            cameraUseCase.setCaptureMode(captureMode)
         }
     }
 
@@ -988,14 +1119,17 @@ class PreviewViewModel @AssistedInject constructor(
     fun onSnackBarResult(cookie: String) {
         viewModelScope.launch {
             _previewUiState.update { old ->
-                (old as? PreviewUiState.Ready)?.snackBarToShow?.let {
-                    if (it.cookie == cookie) {
-                        // If the latest snackbar had a result, then clear snackBarToShow
-                        old.copy(snackBarToShow = null)
+                (old as? PreviewUiState.Ready)?.snackBarQueue!!.let {
+                    val newQueue = LinkedList(it)
+                    val snackBarData = newQueue.remove()
+                    if (snackBarData != null && snackBarData.cookie == cookie) {
+                        // If the latest snackBar had a result, then clear snackBarToShow
+                        Log.d(TAG, "SnackBar removed. Queue size: ${newQueue.size}")
+                        old.copy(snackBarQueue = newQueue)
                     } else {
                         old
                     }
-                } ?: old
+                }
             }
         }
     }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
index 0b8115e..247d2b3 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
@@ -19,6 +19,7 @@ import androidx.annotation.DrawableRes
 import androidx.annotation.StringRes
 import androidx.compose.material.icons.Icons
 import androidx.compose.material.icons.filled.AspectRatio
+import androidx.compose.material.icons.filled.CameraAlt
 import androidx.compose.material.icons.filled.Cameraswitch
 import androidx.compose.material.icons.filled.FlashAuto
 import androidx.compose.material.icons.filled.FlashOff
@@ -26,7 +27,9 @@ import androidx.compose.material.icons.filled.FlashOn
 import androidx.compose.material.icons.filled.HdrOff
 import androidx.compose.material.icons.filled.HdrOn
 import androidx.compose.material.icons.filled.Nightlight
+import androidx.compose.material.icons.filled.PhotoCameraFront
 import androidx.compose.material.icons.filled.PictureInPicture
+import androidx.compose.material.icons.filled.Videocam
 import androidx.compose.material.icons.outlined.Nightlight
 import androidx.compose.runtime.Composable
 import androidx.compose.ui.graphics.painter.Painter
@@ -136,14 +139,15 @@ enum class CameraStreamConfig : QuickSettingsEnum {
     MULTI_STREAM {
         override fun getDrawableResId() = R.drawable.multi_stream_icon
         override fun getImageVector() = null // this icon is not available
-        override fun getTextResId() = R.string.quick_settings_capture_mode_multi
-        override fun getDescriptionResId() = R.string.quick_settings_capture_mode_multi_description
+        override fun getTextResId() = R.string.quick_settings_stream_config_multi
+        override fun getDescriptionResId() = R.string.quick_settings_stream_config_multi_description
     },
     SINGLE_STREAM {
         override fun getDrawableResId() = R.drawable.single_stream_capture_icon
         override fun getImageVector() = null // this icon is not available
-        override fun getTextResId() = R.string.quick_settings_capture_mode_single
-        override fun getDescriptionResId() = R.string.quick_settings_capture_mode_single_description
+        override fun getTextResId() = R.string.quick_settings_stream_config_single
+        override fun getDescriptionResId() =
+            R.string.quick_settings_stream_config_single_description
     }
 }
 
@@ -162,19 +166,51 @@ enum class CameraDynamicRange : QuickSettingsEnum {
     }
 }
 
+enum class CameraCaptureMode : QuickSettingsEnum {
+    STANDARD {
+        override fun getDrawableResId() = null
+
+        override fun getImageVector() = Icons.Default.PhotoCameraFront
+
+        override fun getTextResId() = R.string.quick_settings_text_capture_mode_standard
+
+        override fun getDescriptionResId() =
+            R.string.quick_settings_description_capture_mode_standard
+    },
+    VIDEO_ONLY {
+        override fun getDrawableResId() = null
+
+        override fun getImageVector() = Icons.Default.Videocam
+
+        override fun getTextResId() = R.string.quick_settings_text_capture_mode_video_only
+
+        override fun getDescriptionResId() =
+            R.string.quick_settings_description_capture_mode_video_only
+    },
+    IMAGE_ONLY {
+        override fun getDrawableResId() = null
+
+        override fun getImageVector() = Icons.Default.CameraAlt
+
+        override fun getTextResId() = R.string.quick_settings_text_capture_mode_image_only
+
+        override fun getDescriptionResId() =
+            R.string.quick_settings_description_capture_mode_image_only
+    }
+}
 enum class CameraConcurrentCameraMode : QuickSettingsEnum {
     OFF {
         override fun getDrawableResId() = R.drawable.picture_in_picture_off_icon
         override fun getImageVector() = null
-        override fun getTextResId() = R.string.quick_settings_concurrent_camera_off
+        override fun getTextResId() = R.string.quick_settings_text_concurrent_camera_off
         override fun getDescriptionResId() =
-            R.string.quick_settings_concurrent_camera_off_description
+            R.string.quick_settings_description_concurrent_camera_off
     },
     DUAL {
         override fun getDrawableResId() = null
         override fun getImageVector() = Icons.Filled.PictureInPicture
-        override fun getTextResId() = R.string.quick_settings_concurrent_camera_dual
+        override fun getTextResId() = R.string.quick_settings_text_concurrent_camera_dual
         override fun getDescriptionResId() =
-            R.string.quick_settings_concurrent_camera_dual_description
+            R.string.quick_settings_description_concurrent_camera_dual
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
index 93a55f8..34d306e 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
@@ -23,7 +23,6 @@ import androidx.compose.animation.slideInVertically
 import androidx.compose.animation.slideOutVertically
 import androidx.compose.foundation.background
 import androidx.compose.foundation.clickable
-import androidx.compose.foundation.interaction.MutableInteractionSource
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Column
 import androidx.compose.foundation.layout.fillMaxSize
@@ -37,17 +36,24 @@ import androidx.compose.runtime.setValue
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.dimensionResource
+import androidx.compose.ui.semantics.semantics
+import androidx.compose.ui.semantics.stateDescription
 import androidx.compose.ui.tooling.preview.Preview
 import com.google.jetpackcamera.core.camera.VideoRecordingState
-import com.google.jetpackcamera.feature.preview.CaptureModeToggleUiState
+import com.google.jetpackcamera.feature.preview.CaptureModeUiState
 import com.google.jetpackcamera.feature.preview.DEFAULT_CAPTURE_BUTTON_STATE
 import com.google.jetpackcamera.feature.preview.FlashModeUiState
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.FocusedQuickSetCaptureMode
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.FocusedQuickSetRatio
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_BACKGROUND_FOCUSED
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_BACKGROUND_MAIN
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
@@ -55,6 +61,7 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_STREAM_CONFIG_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickFlipCamera
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetCaptureMode
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetConcurrentCamera
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetFlash
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetHdr
@@ -64,6 +71,7 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSettingsGr
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CameraConstraints
+import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DEFAULT_HDR_DYNAMIC_RANGE
 import com.google.jetpackcamera.settings.model.DEFAULT_HDR_IMAGE_OUTPUT
@@ -80,9 +88,10 @@ import com.google.jetpackcamera.settings.model.forCurrentLens
  */
 @Composable
 fun QuickSettingsScreenOverlay(
+    modifier: Modifier = Modifier,
     previewUiState: PreviewUiState.Ready,
     currentCameraSettings: CameraAppSettings,
-    toggleIsOpen: () -> Unit,
+    toggleQuickSettings: () -> Unit,
     onLensFaceClick: (lensFace: LensFacing) -> Unit,
     onFlashModeClick: (flashMode: FlashMode) -> Unit,
     onAspectRatioClick: (aspectRation: AspectRatio) -> Unit,
@@ -90,7 +99,7 @@ fun QuickSettingsScreenOverlay(
     onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit,
     onImageOutputFormatClick: (imageOutputFormat: ImageOutputFormat) -> Unit,
     onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit,
-    modifier: Modifier = Modifier,
+    onCaptureModeClick: (CaptureMode) -> Unit,
     isOpen: Boolean = false
 ) {
     var focusedQuickSetting by remember {
@@ -104,7 +113,7 @@ fun QuickSettingsScreenOverlay(
     ) {
         val onBack = {
             when (focusedQuickSetting) {
-                FocusedQuickSetting.NONE -> toggleIsOpen()
+                FocusedQuickSetting.NONE -> toggleQuickSettings()
                 else -> focusedQuickSetting = FocusedQuickSetting.NONE
             }
         }
@@ -117,14 +126,18 @@ fun QuickSettingsScreenOverlay(
         Column(
             modifier =
             modifier
+                .testTag(
+                    when (focusedQuickSetting) {
+                        FocusedQuickSetting.NONE -> QUICK_SETTINGS_BACKGROUND_MAIN
+                        else -> QUICK_SETTINGS_BACKGROUND_FOCUSED
+                    }
+                )
                 .fillMaxSize()
                 .background(color = Color.Black.copy(alpha = 0.7f))
                 .clickable(
                     onClick = onBack,
                     indication = null,
-                    interactionSource = remember {
-                        MutableInteractionSource()
-                    }
+                    interactionSource = null
                 ),
             verticalArrangement = Arrangement.Center,
             horizontalAlignment = Alignment.CenterHorizontally
@@ -142,7 +155,8 @@ fun QuickSettingsScreenOverlay(
                 onStreamConfigClick = onStreamConfigClick,
                 onDynamicRangeClick = onDynamicRangeClick,
                 onImageOutputFormatClick = onImageOutputFormatClick,
-                onConcurrentCameraModeClick = onConcurrentCameraModeClick
+                onConcurrentCameraModeClick = onConcurrentCameraModeClick,
+                onCaptureModeClick = onCaptureModeClick
             )
         }
     }
@@ -151,7 +165,8 @@ fun QuickSettingsScreenOverlay(
 // enum representing which individual quick setting is currently focused
 private enum class FocusedQuickSetting {
     NONE,
-    ASPECT_RATIO
+    ASPECT_RATIO,
+    CAPTURE_MODE
 }
 
 // todo: Add UI states for Quick Settings buttons
@@ -172,7 +187,8 @@ private fun ExpandedQuickSettingsUi(
     setFocusedQuickSetting: (FocusedQuickSetting) -> Unit,
     onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit,
     onImageOutputFormatClick: (imageOutputFormat: ImageOutputFormat) -> Unit,
-    onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit
+    onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit,
+    onCaptureModeClick: (CaptureMode) -> Unit
 ) {
     Column(
         modifier =
@@ -248,11 +264,11 @@ private fun ExpandedQuickSettingsUi(
                         fun shouldEnable(): Boolean = when {
                             currentCameraSettings.concurrentCameraMode !=
                                 ConcurrentCameraMode.OFF -> false
+
                             else -> (
-                                cameraConstraints?.hdrDynamicRangeSupported() == true &&
-                                    previewUiState.previewMode is PreviewMode.StandardMode
-                                ) ||
-                                cameraConstraints?.hdrImageFormatSupported() == true
+                                cameraConstraints?.hdrDynamicRangeSupported() == true ||
+                                    cameraConstraints?.hdrImageFormatSupported() == true
+                                )
                         }
 
                         QuickSetHdr(
@@ -261,16 +277,12 @@ private fun ExpandedQuickSettingsUi(
                                 onDynamicRangeClick(d)
                                 onImageOutputFormatClick(i)
                             },
-                            selectedDynamicRange = currentCameraSettings.dynamicRange,
-                            selectedImageOutputFormat = currentCameraSettings.imageFormat,
-                            hdrDynamicRangeSupported =
-                            cameraConstraints?.hdrDynamicRangeSupported() == true,
-                            previewMode = previewUiState.previewMode,
-                            enabled = shouldEnable()
+                            hdrUiState = previewUiState.hdrUiState
                         )
                     }
 
                     add {
+                        // todo(): use a UiState for this
                         QuickSetConcurrentCamera(
                             modifier =
                             Modifier.testTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON),
@@ -283,6 +295,15 @@ private fun ExpandedQuickSettingsUi(
                             previewUiState.systemConstraints.concurrentCamerasSupported &&
                                 previewUiState.previewMode
                                     !is PreviewMode.ExternalImageCaptureMode &&
+                                (
+                                    (
+                                        previewUiState.captureModeUiState as?
+                                            CaptureModeUiState.Enabled
+                                        )
+                                        ?.currentSelection !=
+                                        CaptureMode.IMAGE_ONLY
+                                    ) ==
+                                true &&
                                 (
                                     currentCameraSettings.dynamicRange !=
                                         DEFAULT_HDR_DYNAMIC_RANGE &&
@@ -291,6 +312,26 @@ private fun ExpandedQuickSettingsUi(
                                     )
                         )
                     }
+
+                    add {
+                        val context = LocalContext.current
+                        QuickSetCaptureMode(
+                            modifier = Modifier
+                                .testTag(BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE)
+                                .semantics {
+                                    previewUiState.captureModeUiState.stateDescription()?.let {
+                                        stateDescription = context.getString(it)
+                                    }
+                                },
+                            onClick = {
+                                setFocusedQuickSetting(
+                                    FocusedQuickSetting.CAPTURE_MODE
+                                )
+                            },
+                            captureModeUiState = previewUiState.captureModeUiState,
+                            assignedCaptureMode = null
+                        )
+                    }
                 }
             QuickSettingsGrid(quickSettingsButtons = displayedQuickSettings)
         }
@@ -301,6 +342,21 @@ private fun ExpandedQuickSettingsUi(
                 currentRatio = currentCameraSettings.aspectRatio
             )
         }
+
+        AnimatedVisibility(visible = (focusedQuickSetting == FocusedQuickSetting.CAPTURE_MODE)) {
+            FocusedQuickSetCaptureMode(
+                onSetCaptureMode = onCaptureModeClick,
+                captureModeUiState = previewUiState.captureModeUiState
+            )
+        }
+    }
+}
+
+private fun CaptureModeUiState.stateDescription() = (this as? CaptureModeUiState.Enabled)?.let {
+    when (currentSelection) {
+        CaptureMode.STANDARD -> R.string.quick_settings_description_capture_mode_standard
+        CaptureMode.VIDEO_ONLY -> R.string.quick_settings_description_capture_mode_video_only
+        CaptureMode.IMAGE_ONLY -> R.string.quick_settings_description_capture_mode_image_only
     }
 }
 
@@ -314,7 +370,7 @@ fun ExpandedQuickSettingsUiPreview() {
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
                 videoRecordingState = VideoRecordingState.Inactive(),
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                // captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
                 flashModeUiState = FlashModeUiState.Available(
                     selectedFlashMode = FlashMode.OFF,
                     availableFlashModes = listOf(FlashMode.OFF, FlashMode.ON),
@@ -331,7 +387,8 @@ fun ExpandedQuickSettingsUiPreview() {
             onStreamConfigClick = { },
             onDynamicRangeClick = { },
             onImageOutputFormatClick = { },
-            onConcurrentCameraModeClick = { }
+            onConcurrentCameraModeClick = { },
+            onCaptureModeClick = { }
         )
     }
 }
@@ -344,7 +401,7 @@ fun ExpandedQuickSettingsUiPreview_WithHdr() {
             previewUiState = PreviewUiState.Ready(
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                captureModeToggleUiState = CaptureModeUiState.Unavailable,
                 videoRecordingState = VideoRecordingState.Inactive(),
                 captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
@@ -357,15 +414,16 @@ fun ExpandedQuickSettingsUiPreview_WithHdr() {
             onStreamConfigClick = { },
             onDynamicRangeClick = { },
             onImageOutputFormatClick = { },
-            onConcurrentCameraModeClick = { }
+            onConcurrentCameraModeClick = { },
+            onCaptureModeClick = { }
         )
     }
 }
 
 private val TYPICAL_SYSTEM_CONSTRAINTS_WITH_HDR =
     TYPICAL_SYSTEM_CONSTRAINTS.copy(
-        perLensConstraints = TYPICAL_SYSTEM_CONSTRAINTS
-            .perLensConstraints.entries.associate { (lensFacing, constraints) ->
+        perLensConstraints = TYPICAL_SYSTEM_CONSTRAINTS.perLensConstraints.entries
+            .associate { (lensFacing, constraints) ->
                 lensFacing to constraints.copy(
                     supportedDynamicRanges = setOf(DynamicRange.SDR, DynamicRange.HLG10)
                 )
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
index e991057..b962a27 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
@@ -52,10 +52,13 @@ import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.text.style.TextAlign
 import androidx.compose.ui.unit.dp
+import com.google.jetpackcamera.feature.preview.CaptureModeUiState
 import com.google.jetpackcamera.feature.preview.FlashModeUiState
-import com.google.jetpackcamera.feature.preview.PreviewMode
+import com.google.jetpackcamera.feature.preview.HdrUiState
 import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.SingleSelectableState
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraAspectRatio
+import com.google.jetpackcamera.feature.preview.quicksettings.CameraCaptureMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraConcurrentCameraMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraDynamicRange
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraFlashMode
@@ -63,6 +66,7 @@ import com.google.jetpackcamera.feature.preview.quicksettings.CameraLensFace
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraStreamConfig
 import com.google.jetpackcamera.feature.preview.quicksettings.QuickSettingsEnum
 import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DEFAULT_HDR_DYNAMIC_RANGE
 import com.google.jetpackcamera.settings.model.DEFAULT_HDR_IMAGE_OUTPUT
@@ -114,47 +118,149 @@ fun FocusedQuickSetRatio(
     ExpandedQuickSetting(modifier = modifier, quickSettingButtons = buttons)
 }
 
+@Composable
+fun FocusedQuickSetCaptureMode(
+    modifier: Modifier = Modifier,
+    onSetCaptureMode: (CaptureMode) -> Unit,
+    captureModeUiState: CaptureModeUiState
+) {
+    val buttons: Array<@Composable () -> Unit> =
+        if (captureModeUiState is CaptureModeUiState.Enabled) {
+            arrayOf(
+                {
+                    QuickSetCaptureMode(
+                        modifier = Modifier
+                            .testTag(BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_OPTION_STANDARD),
+                        onClick = { onSetCaptureMode(CaptureMode.STANDARD) },
+                        assignedCaptureMode = CaptureMode.STANDARD,
+                        captureModeUiState = captureModeUiState,
+                        isHighlightEnabled = true
+                    )
+                },
+                {
+                    QuickSetCaptureMode(
+                        modifier = Modifier
+                            .testTag(BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_VIDEO_ONLY),
+                        onClick = { onSetCaptureMode(CaptureMode.VIDEO_ONLY) },
+                        assignedCaptureMode = CaptureMode.VIDEO_ONLY,
+                        captureModeUiState = captureModeUiState,
+                        isHighlightEnabled = true
+                    )
+                },
+                {
+                    QuickSetCaptureMode(
+                        modifier = Modifier
+                            .testTag(BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_IMAGE_ONLY),
+                        onClick = { onSetCaptureMode(CaptureMode.IMAGE_ONLY) },
+                        assignedCaptureMode = CaptureMode.IMAGE_ONLY,
+                        captureModeUiState = captureModeUiState,
+                        isHighlightEnabled = true
+                    )
+                }
+            )
+        } else {
+            emptyArray()
+        }
+    ExpandedQuickSetting(modifier = modifier, quickSettingButtons = buttons)
+}
+
+@Composable
+fun QuickSetCaptureMode(
+    modifier: Modifier = Modifier,
+    onClick: () -> Unit,
+    captureModeUiState: CaptureModeUiState,
+    assignedCaptureMode: CaptureMode?,
+    isHighlightEnabled: Boolean = false
+) {
+    if (captureModeUiState is CaptureModeUiState.Enabled) {
+        val captureToUse = assignedCaptureMode ?: captureModeUiState.currentSelection
+        val enum = when (captureToUse) {
+            CaptureMode.STANDARD -> CameraCaptureMode.STANDARD
+            CaptureMode.VIDEO_ONLY -> CameraCaptureMode.VIDEO_ONLY
+            CaptureMode.IMAGE_ONLY -> CameraCaptureMode.IMAGE_ONLY
+        }
+
+        QuickSettingUiItem(
+            modifier = modifier,
+            enum = enum,
+            onClick = { onClick() },
+            enabled = when (assignedCaptureMode) {
+                null -> {
+                    val list: List<SingleSelectableState> =
+                        listOf(
+                            captureModeUiState.defaultCaptureState,
+                            captureModeUiState.imageOnlyCaptureState,
+                            captureModeUiState.videoOnlyCaptureState
+                        )
+                    // only enabled if there are at least 2 supported capturemodes
+                    list.count { it is SingleSelectableState.Selectable } >= 2
+                }
+
+                CaptureMode.STANDARD ->
+                    captureModeUiState.defaultCaptureState is SingleSelectableState.Selectable
+
+                CaptureMode.VIDEO_ONLY ->
+                    captureModeUiState.videoOnlyCaptureState is SingleSelectableState.Selectable
+
+                CaptureMode.IMAGE_ONLY ->
+                    captureModeUiState.imageOnlyCaptureState is SingleSelectableState.Selectable
+            },
+            isHighLighted =
+            isHighlightEnabled && (assignedCaptureMode == captureModeUiState.currentSelection)
+        )
+    }
+}
+
 @Composable
 fun QuickSetHdr(
     modifier: Modifier = Modifier,
-    onClick: (dynamicRange: DynamicRange, imageOutputFormat: ImageOutputFormat) -> Unit,
-    selectedDynamicRange: DynamicRange,
-    selectedImageOutputFormat: ImageOutputFormat,
-    hdrDynamicRangeSupported: Boolean,
-    previewMode: PreviewMode,
-    enabled: Boolean
+    onClick: (DynamicRange, ImageOutputFormat) -> Unit,
+    hdrUiState: HdrUiState
 ) {
     val enum =
-        if (selectedDynamicRange == DEFAULT_HDR_DYNAMIC_RANGE ||
-            selectedImageOutputFormat == DEFAULT_HDR_IMAGE_OUTPUT
+        if (hdrUiState is HdrUiState.Available &&
+            (
+                hdrUiState.currentDynamicRange == DEFAULT_HDR_DYNAMIC_RANGE ||
+                    hdrUiState.currentImageOutputFormat == DEFAULT_HDR_IMAGE_OUTPUT
+                )
         ) {
             CameraDynamicRange.HDR
         } else {
             CameraDynamicRange.SDR
         }
 
+    val newVideoDynamicRange = if (
+        hdrUiState is HdrUiState.Available &&
+        enum == CameraDynamicRange.SDR
+    ) {
+        DEFAULT_HDR_DYNAMIC_RANGE
+    } else {
+        DynamicRange.SDR
+    }
+
+    val newImageOutputFormat = if (
+        hdrUiState is HdrUiState.Available &&
+        enum == CameraDynamicRange.SDR
+    ) {
+        DEFAULT_HDR_IMAGE_OUTPUT
+    } else {
+        ImageOutputFormat.JPEG
+    }
+
     QuickSettingUiItem(
         modifier = modifier,
         enum = enum,
         onClick = {
-            val newDynamicRange =
-                if (selectedDynamicRange == DynamicRange.SDR && hdrDynamicRangeSupported) {
-                    DEFAULT_HDR_DYNAMIC_RANGE
-                } else {
-                    DynamicRange.SDR
-                }
-            val newImageOutputFormat =
-                if (!hdrDynamicRangeSupported ||
-                    previewMode is PreviewMode.ExternalImageCaptureMode
-                ) {
-                    DEFAULT_HDR_IMAGE_OUTPUT
-                } else {
-                    ImageOutputFormat.JPEG
-                }
-            onClick(newDynamicRange, newImageOutputFormat)
+            onClick(newVideoDynamicRange, newImageOutputFormat)
         },
-        isHighLighted = (selectedDynamicRange != DynamicRange.SDR),
-        enabled = enabled
+        isHighLighted = (
+            hdrUiState is HdrUiState.Available &&
+                (
+                    hdrUiState.currentDynamicRange == DEFAULT_HDR_DYNAMIC_RANGE ||
+                        hdrUiState.currentImageOutputFormat == DEFAULT_HDR_IMAGE_OUTPUT
+                    )
+            ),
+        enabled = hdrUiState is HdrUiState.Available
     )
 }
 
@@ -195,6 +301,7 @@ fun QuickSetFlash(
                 enabled = false,
                 onClick = {}
             )
+
         is FlashModeUiState.Available ->
             QuickSettingUiItem(
                 modifier = modifier,
@@ -342,11 +449,11 @@ fun QuickSettingUiItem(
  */
 @Composable
 fun QuickSettingUiItem(
+    modifier: Modifier = Modifier,
     text: String,
     painter: Painter,
     accessibilityText: String,
     onClick: () -> Unit,
-    modifier: Modifier = Modifier,
     isHighLighted: Boolean = false,
     enabled: Boolean = true
 ) {
@@ -390,7 +497,9 @@ fun QuickSettingUiItem(
             Icon(
                 painter = painter,
                 contentDescription = accessibilityText,
-                modifier = Modifier.size(iconSize).scale(animatedScale)
+                modifier = Modifier
+                    .size(iconSize)
+                    .scale(animatedScale)
             )
 
             Text(text = text, textAlign = TextAlign.Center)
@@ -418,8 +527,15 @@ fun ExpandedQuickSetting(
                         )
                     ) /
                     (
-                        dimensionResource(id = R.dimen.quick_settings_ui_item_icon_size) +
-                            (dimensionResource(id = R.dimen.quick_settings_ui_item_padding) * 2)
+                        dimensionResource(
+                            id = R.dimen.quick_settings_ui_item_icon_size
+                        ) +
+                            (
+                                dimensionResource(
+                                    id = R.dimen.quick_settings_ui_item_padding
+                                ) *
+                                    2
+                                )
                         )
                 ).toInt()
         )
@@ -453,8 +569,15 @@ fun QuickSettingsGrid(
                         )
                     ) /
                     (
-                        dimensionResource(id = R.dimen.quick_settings_ui_item_icon_size) +
-                            (dimensionResource(id = R.dimen.quick_settings_ui_item_padding) * 2)
+                        dimensionResource(
+                            id = R.dimen.quick_settings_ui_item_icon_size
+                        ) +
+                            (
+                                dimensionResource(
+                                    id = R.dimen.quick_settings_ui_item_padding
+                                ) *
+                                    2
+                                )
                         )
                 ).toInt()
         )
@@ -509,6 +632,7 @@ fun FlashModeIndicator(
                 enum = CameraFlashMode.OFF,
                 enabled = false
             )
+
         is FlashModeUiState.Available ->
             TopBarSettingIndicator(
                 enum = flashModeUiState.selectedFlashMode.toCameraFlashMode(
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
index 1c73fa1..886244a 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
@@ -25,9 +25,12 @@ package com.google.jetpackcamera.feature.preview.quicksettings.ui
 //
 // ////////////////////////////////
 
+const val QUICK_SETTINGS_DROP_DOWN = "QuickSettingsDropDown"
+const val QUICK_SETTINGS_BACKGROUND_MAIN = "quick_settings_container"
+const val QUICK_SETTINGS_BACKGROUND_FOCUSED = "quick_settings_container_focused"
+
 const val QUICK_SETTINGS_STREAM_CONFIG_BUTTON = "QuickSettingsStreamConfigButton"
 const val QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON = "QuickSettingsConcurrentCameraModeButton"
-const val QUICK_SETTINGS_DROP_DOWN = "QuickSettingsDropDown"
 const val QUICK_SETTINGS_HDR_BUTTON = "QuickSettingsHdrButton"
 const val QUICK_SETTINGS_FLASH_BUTTON = "QuickSettingsFlashButton"
 const val QUICK_SETTINGS_FLIP_CAMERA_BUTTON = "QuickSettingsFlipCameraButton"
@@ -35,3 +38,12 @@ const val QUICK_SETTINGS_RATIO_3_4_BUTTON = "QuickSettingsRatio3:4Button"
 const val QUICK_SETTINGS_RATIO_9_16_BUTTON = "QuickSettingsRatio9:16Button"
 const val QUICK_SETTINGS_RATIO_1_1_BUTTON = "QuickSettingsRatio1:1Button"
 const val QUICK_SETTINGS_RATIO_BUTTON = "QuickSettingsRatioButton"
+
+// quick settings capture mode
+const val BTN_QUICK_SETTINGS_FOCUS_CAPTURE_MODE = "quick_settings_btn_focus_capture_mode"
+const val BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_OPTION_STANDARD =
+    "quick_settings_focused_capture_mode_btn_option_standard"
+const val BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_VIDEO_ONLY =
+    "quick_settings_focused_capture_mode_btn_option_video_only"
+const val BTN_QUICK_SETTINGS_FOCUSED_CAPTURE_MODE_IMAGE_ONLY =
+    "quick_settings_focused_capture_mode_btn_option_image_only"
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
index 021a25c..ea5e917 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
@@ -17,6 +17,7 @@ package com.google.jetpackcamera.feature.preview.ui
 
 import android.content.ContentResolver
 import android.net.Uri
+import android.util.Range
 import androidx.compose.animation.AnimatedVisibility
 import androidx.compose.animation.core.tween
 import androidx.compose.animation.fadeIn
@@ -31,6 +32,7 @@ import androidx.compose.foundation.layout.fillMaxWidth
 import androidx.compose.foundation.layout.height
 import androidx.compose.foundation.layout.padding
 import androidx.compose.foundation.layout.safeDrawingPadding
+import androidx.compose.foundation.layout.size
 import androidx.compose.material.icons.Icons
 import androidx.compose.material.icons.filled.CameraAlt
 import androidx.compose.material.icons.filled.Videocam
@@ -57,8 +59,9 @@ import androidx.compose.ui.unit.dp
 import androidx.compose.ui.unit.sp
 import com.google.jetpackcamera.core.camera.VideoRecordingState
 import com.google.jetpackcamera.feature.preview.CaptureButtonUiState
-import com.google.jetpackcamera.feature.preview.CaptureModeToggleUiState
+import com.google.jetpackcamera.feature.preview.CaptureModeUiState
 import com.google.jetpackcamera.feature.preview.DEFAULT_CAPTURE_BUTTON_STATE
+import com.google.jetpackcamera.feature.preview.DisabledReason
 import com.google.jetpackcamera.feature.preview.ElapsedTimeUiState
 import com.google.jetpackcamera.feature.preview.FlashModeUiState
 import com.google.jetpackcamera.feature.preview.MultipleEventsCutter
@@ -66,10 +69,14 @@ import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.PreviewViewModel
 import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.SingleSelectableState
 import com.google.jetpackcamera.feature.preview.StabilizationUiState
+import com.google.jetpackcamera.feature.preview.ZoomUiState
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSettingsIndicators
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.ToggleQuickSettingsButton
 import com.google.jetpackcamera.feature.preview.ui.debug.DebugOverlayToggleButton
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
+import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
@@ -98,14 +105,16 @@ fun CameraControlsOverlay(
     modifier: Modifier = Modifier,
     zoomLevelDisplayState: ZoomLevelDisplayState = remember { ZoomLevelDisplayState() },
     onNavigateToSettings: () -> Unit = {},
+    onSetCaptureMode: (CaptureMode) -> Unit = {},
     onFlipCamera: () -> Unit = {},
     onChangeFlash: (FlashMode) -> Unit = {},
     onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
-    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
+    onDisabledCaptureMode: (DisabledReason) -> Unit = {},
     onToggleQuickSettings: () -> Unit = {},
     onToggleDebugOverlay: () -> Unit = {},
     onToggleAudio: () -> Unit = {},
     onSetPause: (Boolean) -> Unit = {},
+    onSetZoom: (CameraZoomRatio) -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
         Uri?,
@@ -118,12 +127,12 @@ fun CameraControlsOverlay(
         (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {},
-    onImageWellClick: (uri: Uri?) -> Unit = {},
+    onImageWellClick: () -> Unit = {},
     onLockVideoRecording: (Boolean) -> Unit
 ) {
     // Show the current zoom level for a short period of time, only when the level changes.
     var firstRun by remember { mutableStateOf(true) }
-    LaunchedEffect(previewUiState.zoomScale) {
+    LaunchedEffect(previewUiState.zoomUiState) {
         if (firstRun) {
             firstRun = false
         } else {
@@ -161,20 +170,21 @@ fun CameraControlsOverlay(
                     .fillMaxWidth()
                     .align(Alignment.BottomCenter),
                 previewUiState = previewUiState,
-                zoomLevel = previewUiState.zoomScale,
+                zoomUiState = previewUiState.zoomUiState,
                 physicalCameraId = previewUiState.currentPhysicalCameraId,
                 logicalCameraId = previewUiState.currentLogicalCameraId,
                 showZoomLevel = zoomLevelDisplayState.showZoomLevel,
                 isQuickSettingsOpen = previewUiState.quickSettingsIsOpen,
                 systemConstraints = previewUiState.systemConstraints,
                 videoRecordingState = previewUiState.videoRecordingState,
+                onSetCaptureMode = onSetCaptureMode,
                 onFlipCamera = onFlipCamera,
+                onSetZoom = onSetZoom,
                 onCaptureImageWithUri = onCaptureImageWithUri,
                 onToggleQuickSettings = onToggleQuickSettings,
                 onToggleAudio = onToggleAudio,
                 onSetPause = onSetPause,
-                onChangeImageFormat = onChangeImageFormat,
-                onToggleWhenDisabled = onToggleWhenDisabled,
+                onDisabledCaptureMode = onDisabledCaptureMode,
                 onStartVideoRecording = onStartVideoRecording,
                 onStopVideoRecording = onStopVideoRecording,
                 onImageWellClick = onImageWellClick,
@@ -261,7 +271,7 @@ private fun ControlsBottom(
     previewUiState: PreviewUiState.Ready,
     physicalCameraId: String? = null,
     logicalCameraId: String? = null,
-    zoomLevel: Float,
+    zoomUiState: ZoomUiState,
     showZoomLevel: Boolean,
     isQuickSettingsOpen: Boolean,
     systemConstraints: SystemConstraints,
@@ -276,27 +286,29 @@ private fun ControlsBottom(
     onToggleQuickSettings: () -> Unit = {},
     onToggleAudio: () -> Unit = {},
     onSetPause: (Boolean) -> Unit = {},
-    onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
-    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
+    onSetCaptureMode: (CaptureMode) -> Unit = {},
+    onDisabledCaptureMode: (DisabledReason) -> Unit = {},
+    onSetZoom: (CameraZoomRatio) -> Unit = {},
     onStartVideoRecording: (
         Uri?,
         Boolean,
         (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {},
-    onImageWellClick: (uri: Uri?) -> Unit = {},
+    onImageWellClick: () -> Unit = {},
     onLockVideoRecording: (Boolean) -> Unit = {}
 ) {
-    Column(
-        modifier = modifier,
-        horizontalAlignment = Alignment.CenterHorizontally
-    ) {
+    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
         CompositionLocalProvider(
             LocalTextStyle provides LocalTextStyle.current.copy(fontSize = 20.sp)
         ) {
             Column(horizontalAlignment = Alignment.CenterHorizontally) {
-                if (showZoomLevel) {
-                    ZoomScaleText(zoomLevel)
+                AnimatedVisibility(
+                    visible = (showZoomLevel && zoomUiState is ZoomUiState.Enabled),
+                    enter = fadeIn(),
+                    exit = fadeOut()
+                ) {
+                    ZoomRatioText(zoomUiState as ZoomUiState.Enabled)
                 }
                 if (previewUiState.debugUiState.isDebugMode) {
                     CurrentCameraIdText(physicalCameraId, logicalCameraId)
@@ -322,7 +334,7 @@ private fun ControlsBottom(
         Column {
             if (!isQuickSettingsOpen &&
                 previewUiState.captureModeToggleUiState
-                    is CaptureModeToggleUiState.Visible
+                    is CaptureModeUiState.Enabled
             ) {
                 // TODO(yasith): Align to end of ImageWell based on alignment lines
                 Box(
@@ -330,8 +342,8 @@ private fun ControlsBottom(
                 ) {
                     CaptureModeToggleButton(
                         uiState = previewUiState.captureModeToggleUiState,
-                        onChangeImageFormat = onChangeImageFormat,
-                        onToggleWhenDisabled = onToggleWhenDisabled,
+                        onChangeCaptureMode = onSetCaptureMode,
+                        onToggleWhenDisabled = onDisabledCaptureMode,
                         modifier = Modifier.testTag(CAPTURE_MODE_TOGGLE_BUTTON)
                     )
                 }
@@ -373,32 +385,30 @@ private fun ControlsBottom(
                     previewMode = previewUiState.previewMode,
                     isQuickSettingsOpen = isQuickSettingsOpen,
                     onCaptureImageWithUri = onCaptureImageWithUri,
+                    onSetZoom = onSetZoom,
                     onToggleQuickSettings = onToggleQuickSettings,
                     onStartVideoRecording = onStartVideoRecording,
                     onStopVideoRecording = onStopVideoRecording,
                     onLockVideoRecording = onLockVideoRecording
                 )
-                Row(Modifier.weight(1f), horizontalArrangement = Arrangement.SpaceEvenly) {
+
+                Box(
+                    modifier = Modifier.weight(1f).size(120.dp),
+                    contentAlignment = Alignment.Center
+                ) {
                     if (videoRecordingState is VideoRecordingState.Active) {
                         AmplitudeVisualizer(
-                            modifier = Modifier
-                                .weight(1f)
-                                .fillMaxSize(),
+                            modifier = Modifier.fillMaxSize(),
                             onToggleAudio = onToggleAudio,
                             audioUiState = previewUiState.audioUiState
                         )
-                    } else {
-                        Column {
-                            if (!isQuickSettingsOpen &&
-                                previewUiState.previewMode is PreviewMode.StandardMode
-                            ) {
-                                ImageWell(
-                                    modifier = Modifier.weight(1f),
-                                    imageWellUiState = previewUiState.imageWellUiState,
-                                    onClick = onImageWellClick
-                                )
-                            }
-                        }
+                    } else if (!isQuickSettingsOpen &&
+                        previewUiState.previewMode is PreviewMode.StandardMode
+                    ) {
+                        ImageWell(
+                            imageWellUiState = previewUiState.imageWellUiState,
+                            onClick = onImageWellClick
+                        )
                     }
                 }
             }
@@ -413,6 +423,7 @@ private fun CaptureButton(
     isQuickSettingsOpen: Boolean,
     previewMode: PreviewMode,
     onToggleQuickSettings: () -> Unit = {},
+    onSetZoom: (CameraZoomRatio) -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
         Uri?,
@@ -432,7 +443,8 @@ private fun CaptureButton(
 
     CaptureButton(
         modifier = modifier.testTag(CAPTURE_BUTTON),
-        onCaptureImage = {
+        onSetZoom = onSetZoom,
+        onImageCapture = {
             if (captureButtonUiState is CaptureButtonUiState.Enabled) {
                 multipleEventsCutter.processEvent {
                     when (previewMode) {
@@ -482,7 +494,7 @@ private fun CaptureButton(
                 onToggleQuickSettings()
             }
         },
-        onStartVideoRecording = {
+        onStartRecording = {
             if (captureButtonUiState is CaptureButtonUiState.Enabled) {
                 when (previewMode) {
                     is PreviewMode.StandardMode -> {
@@ -506,7 +518,7 @@ private fun CaptureButton(
                 }
             }
         },
-        onStopVideoRecording = {
+        onStopRecording = {
             onStopVideoRecording()
         },
         captureButtonUiState = captureButtonUiState,
@@ -516,27 +528,31 @@ private fun CaptureButton(
 
 @Composable
 private fun CaptureModeToggleButton(
-    uiState: CaptureModeToggleUiState.Visible,
-    onChangeImageFormat: (ImageOutputFormat) -> Unit,
-    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit,
+    uiState: CaptureModeUiState.Enabled,
+    onChangeCaptureMode: (CaptureMode) -> Unit,
+    onToggleWhenDisabled: (DisabledReason) -> Unit,
     modifier: Modifier = Modifier
 ) {
     // Captures hdr image (left) when output format is UltraHdr, else captures hdr video (right).
     val initialState =
-        when (uiState.currentMode) {
-            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE -> ToggleState.Left
-            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO -> ToggleState.Right
+        when (uiState.currentSelection) {
+            CaptureMode.IMAGE_ONLY -> ToggleState.Left
+            CaptureMode.VIDEO_ONLY -> ToggleState.Right
+            CaptureMode.STANDARD -> TODO("toggle should not be visible for STANDARD mode")
         }
+    val enabled =
+        uiState.videoOnlyCaptureState == SingleSelectableState.Selectable &&
+            uiState.imageOnlyCaptureState == SingleSelectableState.Selectable
     ToggleButton(
-        leftIcon = if (uiState.currentMode ==
-            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_IMAGE
+        leftIcon = if (uiState.currentSelection ==
+            CaptureMode.IMAGE_ONLY
         ) {
             rememberVectorPainter(image = Icons.Filled.CameraAlt)
         } else {
             rememberVectorPainter(image = Icons.Outlined.CameraAlt)
         },
-        rightIcon = if (uiState.currentMode ==
-            CaptureModeToggleUiState.ToggleMode.CAPTURE_TOGGLE_VIDEO
+        rightIcon = if (uiState.currentSelection ==
+            CaptureMode.VIDEO_ONLY
         ) {
             rememberVectorPainter(image = Icons.Filled.Videocam)
         } else {
@@ -544,21 +560,37 @@ private fun CaptureModeToggleButton(
         },
         initialState = initialState,
         onToggleStateChanged = {
-            val imageFormat = when (it) {
-                ToggleState.Left -> ImageOutputFormat.JPEG_ULTRA_HDR
-                ToggleState.Right -> ImageOutputFormat.JPEG
+            val captureMode = when (it) {
+                ToggleState.Left -> CaptureMode.IMAGE_ONLY
+                ToggleState.Right -> CaptureMode.VIDEO_ONLY
             }
-            onChangeImageFormat(imageFormat)
+            onChangeCaptureMode(captureMode)
         },
         onToggleWhenDisabled = {
-            check(uiState is CaptureModeToggleUiState.Disabled)
-            onToggleWhenDisabled(uiState.disabledReason)
+            val disabledReason: DisabledReason? =
+                (uiState.videoOnlyCaptureState as? SingleSelectableState.Disabled)?.disabledReason
+                    ?: (uiState.imageOnlyCaptureState as? SingleSelectableState.Disabled)
+                        ?.disabledReason
+            disabledReason?.let { onToggleWhenDisabled(it) }
         },
-        enabled = uiState is CaptureModeToggleUiState.Enabled,
+        // toggle only enabled when both capture modes are available
+        enabled = enabled,
         leftIconDescription =
-        stringResource(id = R.string.capture_mode_image_capture_content_description),
+        if (enabled) {
+            stringResource(id = R.string.capture_mode_image_capture_content_description)
+        } else {
+            stringResource(
+                id = R.string.capture_mode_image_capture_content_description_disabled
+            )
+        },
         rightIconDescription =
-        stringResource(id = R.string.capture_mode_video_recording_content_description),
+        if (enabled) {
+            stringResource(id = R.string.capture_mode_video_recording_content_description)
+        } else {
+            stringResource(
+                id = R.string.capture_mode_video_recording_content_description_disabled
+            )
+        },
         modifier = modifier
     )
 }
@@ -647,15 +679,18 @@ private fun Preview_ControlsBottom() {
             previewUiState = PreviewUiState.Ready(
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                captureModeToggleUiState = CaptureModeUiState.Unavailable,
                 videoRecordingState = VideoRecordingState.Inactive(),
                 captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
-            zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-            videoRecordingState = VideoRecordingState.Inactive()
+            videoRecordingState = VideoRecordingState.Inactive(),
+            zoomUiState = ZoomUiState.Enabled(
+                primaryZoomRange = Range(1.0f, 10.0f),
+                primaryZoomRatio = 1.0f
+            )
         )
     }
 }
@@ -668,11 +703,14 @@ private fun Preview_ControlsBottom_NoZoomLevel() {
             previewUiState = PreviewUiState.Ready(
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                captureModeToggleUiState = CaptureModeUiState.Unavailable,
                 videoRecordingState = VideoRecordingState.Inactive(),
                 captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
-            zoomLevel = 1.3f,
+            zoomUiState = ZoomUiState.Enabled(
+                primaryZoomRange = Range(1.0f, 10.0f),
+                primaryZoomRatio = 1.0f
+            ),
             showZoomLevel = false,
             isQuickSettingsOpen = false,
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
@@ -689,11 +727,14 @@ private fun Preview_ControlsBottom_QuickSettingsOpen() {
             previewUiState = PreviewUiState.Ready(
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                captureModeToggleUiState = CaptureModeUiState.Unavailable,
                 videoRecordingState = VideoRecordingState.Inactive(),
                 captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
-            zoomLevel = 1.3f,
+            zoomUiState = ZoomUiState.Enabled(
+                primaryZoomRange = Range(1.0f, 10.0f),
+                primaryZoomRatio = 1.0f
+            ),
             showZoomLevel = true,
             isQuickSettingsOpen = true,
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
@@ -710,11 +751,14 @@ private fun Preview_ControlsBottom_NoFlippableCamera() {
             previewUiState = PreviewUiState.Ready(
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                captureModeToggleUiState = CaptureModeUiState.Unavailable,
                 videoRecordingState = VideoRecordingState.Inactive(),
                 captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
-            zoomLevel = 1.3f,
+            zoomUiState = ZoomUiState.Enabled(
+                primaryZoomRange = Range(1.0f, 10.0f),
+                primaryZoomRatio = 1.0f
+            ),
             showZoomLevel = true,
             isQuickSettingsOpen = false,
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS.copy(
@@ -737,11 +781,14 @@ private fun Preview_ControlsBottom_Recording() {
             previewUiState = PreviewUiState.Ready(
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                captureModeToggleUiState = CaptureModeUiState.Unavailable,
                 videoRecordingState = VideoRecordingState.Active.Recording(0L, .9, 1_000_000_000),
                 captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
-            zoomLevel = 1.3f,
+            zoomUiState = ZoomUiState.Enabled(
+                primaryZoomRange = Range(1.0f, 10.0f),
+                primaryZoomRatio = 1.0f
+            ),
             showZoomLevel = true,
             isQuickSettingsOpen = false,
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CaptureButtonComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CaptureButtonComponents.kt
new file mode 100644
index 0000000..2847098
--- /dev/null
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CaptureButtonComponents.kt
@@ -0,0 +1,764 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+import android.util.Log
+import android.view.KeyEvent
+import androidx.compose.animation.AnimatedVisibility
+import androidx.compose.animation.ExitTransition
+import androidx.compose.animation.animateColorAsState
+import androidx.compose.animation.core.FastOutSlowInEasing
+import androidx.compose.animation.core.animateDpAsState
+import androidx.compose.animation.core.tween
+import androidx.compose.animation.fadeIn
+import androidx.compose.animation.fadeOut
+import androidx.compose.animation.scaleIn
+import androidx.compose.foundation.Canvas
+import androidx.compose.foundation.background
+import androidx.compose.foundation.border
+import androidx.compose.foundation.clickable
+import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
+import androidx.compose.foundation.gestures.detectTapGestures
+import androidx.compose.foundation.layout.Box
+import androidx.compose.foundation.layout.height
+import androidx.compose.foundation.layout.offset
+import androidx.compose.foundation.layout.padding
+import androidx.compose.foundation.layout.size
+import androidx.compose.foundation.layout.width
+import androidx.compose.foundation.shape.CircleShape
+import androidx.compose.material.icons.Icons
+import androidx.compose.material.icons.filled.Lock
+import androidx.compose.material.icons.filled.LockOpen
+import androidx.compose.material3.Icon
+import androidx.compose.material3.LocalContentColor
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.DisposableEffect
+import androidx.compose.runtime.LaunchedEffect
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.rememberCoroutineScope
+import androidx.compose.runtime.rememberUpdatedState
+import androidx.compose.runtime.setValue
+import androidx.compose.ui.Alignment
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.alpha
+import androidx.compose.ui.draw.clip
+import androidx.compose.ui.geometry.CornerRadius
+import androidx.compose.ui.geometry.Offset
+import androidx.compose.ui.geometry.Rect
+import androidx.compose.ui.geometry.Size
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.input.pointer.pointerInput
+import androidx.compose.ui.layout.onSizeChanged
+import androidx.compose.ui.platform.LocalView
+import androidx.compose.ui.platform.LocalViewConfiguration
+import androidx.compose.ui.tooling.preview.Preview
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.dp
+import androidx.core.view.ViewCompat
+import com.google.jetpackcamera.feature.preview.CaptureButtonUiState
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.ZoomChange
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.launch
+
+private const val TAG = "CaptureButton"
+private const val DEFAULT_CAPTURE_BUTTON_SIZE = 80f
+
+// scales against the size of the capture button
+private const val LOCK_SWITCH_PRESSED_NUCLEUS_SCALE = .5f
+
+// scales against the size of the capture button
+private const val LOCK_SWITCH_WIDTH_SCALE = 1.375f
+
+// scales against the size of the pressed nucleus
+private const val LOCK_SWITCH_HEIGHT_SCALE = 1.4f
+
+// 1f = left, 0f = right
+private const val LOCK_SWITCH_POSITION_ON = 1f
+private const val LOCK_SWITCH_POSITION_OFF = 0f
+private const val MINIMUM_LOCK_THRESHOLD = .65F
+
+private const val LOCK_SWITCH_ALPHA = .37f
+
+private enum class CaptureSource {
+    CAPTURE_BUTTON,
+    VOLUME_UP,
+    VOLUME_DOWN
+}
+
+/**
+ * Handler for using certain key events buttons as capture buttons.
+ */
+@Composable
+private fun CaptureKeyHandler(
+    onPress: (CaptureSource) -> Unit,
+    onRelease: (CaptureSource) -> Unit
+) {
+    val view = LocalView.current
+    val currentOnPress by rememberUpdatedState(onPress)
+    val currentOnRelease by rememberUpdatedState(onRelease)
+
+    fun keyCodeToCaptureSource(keyCode: Int): CaptureSource = when (keyCode) {
+        KeyEvent.KEYCODE_VOLUME_UP -> CaptureSource.VOLUME_UP
+        KeyEvent.KEYCODE_VOLUME_DOWN -> CaptureSource.VOLUME_DOWN
+        else -> TODO("Keycode not assigned to CaptureSource")
+    }
+
+    DisposableEffect(view) {
+        // todo call once per keydown
+        var keyActionDown: Int? = null
+        val keyEventDispatcher = ViewCompat.OnUnhandledKeyEventListenerCompat { _, event ->
+            when (event.keyCode) {
+                KeyEvent.KEYCODE_VOLUME_UP, KeyEvent.KEYCODE_VOLUME_DOWN -> {
+                    val captureSource = keyCodeToCaptureSource(event.keyCode)
+                    // pressed down
+                    if (event.action == KeyEvent.ACTION_DOWN && keyActionDown == null) {
+                        keyActionDown = event.keyCode
+                        currentOnPress(captureSource)
+                    }
+                    // released
+                    if (event.action == KeyEvent.ACTION_UP && keyActionDown == event.keyCode) {
+                        keyActionDown = null
+                        currentOnRelease(captureSource)
+                    }
+                    // consume the event
+                    true
+                }
+
+                else -> {
+                    false
+                }
+            }
+        }
+
+        ViewCompat.addOnUnhandledKeyEventListener(view, keyEventDispatcher)
+
+        onDispose {
+            ViewCompat.removeOnUnhandledKeyEventListener(view, keyEventDispatcher)
+        }
+    }
+}
+
+@Composable
+fun CaptureButton(
+    modifier: Modifier = Modifier,
+    onImageCapture: () -> Unit,
+    onStartRecording: () -> Unit,
+    onStopRecording: () -> Unit,
+    onLockVideoRecording: (Boolean) -> Unit,
+    onSetZoom: (CameraZoomRatio) -> Unit,
+    captureButtonUiState: CaptureButtonUiState,
+    captureButtonSize: Float = DEFAULT_CAPTURE_BUTTON_SIZE
+) {
+    var currentUiState = rememberUpdatedState(captureButtonUiState)
+    val firstKeyPressed = remember { mutableStateOf<CaptureSource?>(null) }
+    val isLongPressing = remember { mutableStateOf<Boolean>(false) }
+    var longPressJob by remember { mutableStateOf<Job?>(null) }
+    val scope = rememberCoroutineScope()
+    val longPressTimeout = LocalViewConfiguration.current.longPressTimeoutMillis
+
+    LaunchedEffect(captureButtonUiState) {
+        if (captureButtonUiState is CaptureButtonUiState.Enabled.Idle) {
+            onLockVideoRecording(false)
+        } else if (captureButtonUiState is CaptureButtonUiState.Enabled.Recording.LockedRecording) {
+            longPressJob = null
+            isLongPressing.value = false
+            firstKeyPressed.value = null
+        }
+    }
+    fun onLongPress() {
+        if (isLongPressing.value == false) {
+            when (val current = currentUiState.value) {
+                is CaptureButtonUiState.Enabled.Idle -> when (current.captureMode) {
+                    CaptureMode.STANDARD,
+                    CaptureMode.VIDEO_ONLY -> {
+                        isLongPressing.value = true
+                        Log.d(TAG, "Starting recording")
+                        onStartRecording()
+                    }
+
+                    CaptureMode.IMAGE_ONLY -> {
+                        isLongPressing.value = true
+                    }
+                }
+
+                else -> {}
+            }
+        }
+    }
+
+    fun onPress(captureSource: CaptureSource) {
+        if (firstKeyPressed.value == null) {
+            firstKeyPressed.value = captureSource
+            longPressJob = scope.launch {
+                delay(longPressTimeout)
+                onLongPress()
+            }
+        }
+    }
+
+    fun onKeyUp(captureSource: CaptureSource, isLocked: Boolean = false) {
+        // releasing while pressed recording
+        if (firstKeyPressed.value == captureSource) {
+            if (isLongPressing.value) {
+                if (!isLocked &&
+                    currentUiState.value is
+                        CaptureButtonUiState.Enabled.Recording.PressedRecording
+                ) {
+                    Log.d(TAG, "Stopping recording")
+                    onStopRecording()
+                }
+            }
+            // on click
+            else {
+                when (val current = currentUiState.value) {
+                    is CaptureButtonUiState.Enabled.Idle -> when (current.captureMode) {
+                        CaptureMode.STANDARD,
+                        CaptureMode.IMAGE_ONLY -> onImageCapture()
+
+                        CaptureMode.VIDEO_ONLY -> {
+                            onLockVideoRecording(true)
+                            Log.d(TAG, "Starting recording")
+                            onStartRecording()
+                        }
+                    }
+
+                    CaptureButtonUiState.Enabled.Recording.LockedRecording -> onStopRecording()
+                    CaptureButtonUiState.Enabled.Recording.PressedRecording,
+                    CaptureButtonUiState.Unavailable -> {
+                    }
+                }
+            }
+            longPressJob?.cancel()
+            longPressJob = null
+            isLongPressing.value = false
+            firstKeyPressed.value = null
+        }
+    }
+
+    CaptureKeyHandler(
+        onPress = { captureSource -> onPress(captureSource) },
+        onRelease = { captureSource -> onKeyUp(captureSource) }
+    )
+    CaptureButton(
+        modifier = modifier,
+        onPress = { onPress(CaptureSource.CAPTURE_BUTTON) },
+        onRelease = { onKeyUp(CaptureSource.CAPTURE_BUTTON, it) },
+        onLockVideoRecording = onLockVideoRecording,
+        onSetZoom = onSetZoom,
+        captureButtonUiState = captureButtonUiState,
+        captureButtonSize = captureButtonSize
+    )
+}
+
+@Composable
+private fun CaptureButton(
+    modifier: Modifier = Modifier,
+    onPress: () -> Unit,
+    onRelease: (isLocked: Boolean) -> Unit,
+    onSetZoom: (CameraZoomRatio) -> Unit,
+    onLockVideoRecording: (Boolean) -> Unit,
+    captureButtonUiState: CaptureButtonUiState,
+    useLockSwitch: Boolean = true,
+    captureButtonSize: Float = DEFAULT_CAPTURE_BUTTON_SIZE
+) {
+    // todo: explore MutableInteractionSource
+    var isCaptureButtonPressed by remember {
+        mutableStateOf(false)
+    }
+
+    var switchPosition by remember {
+        mutableFloatStateOf(LOCK_SWITCH_POSITION_OFF)
+    }
+
+    val currentUiState = rememberUpdatedState(captureButtonUiState)
+    val switchWidth = (captureButtonSize * LOCK_SWITCH_WIDTH_SCALE)
+    val currentColor = LocalContentColor.current
+
+    var relativeCaptureButtonBounds by remember { mutableStateOf<Rect?>(null) }
+
+    fun shouldBeLocked(): Boolean = switchPosition > MINIMUM_LOCK_THRESHOLD
+
+    fun setLockSwitchPosition(positionX: Float, offsetX: Float) {
+        relativeCaptureButtonBounds?.let {
+            if (useLockSwitch) {
+                if (positionX > it.center.x) {
+                    switchPosition = LOCK_SWITCH_POSITION_OFF
+                } else {
+                    val newSwitchPosition =
+                        switchPosition - (offsetX / switchWidth)
+                    switchPosition =
+                        newSwitchPosition.coerceIn(
+                            LOCK_SWITCH_POSITION_OFF,
+                            LOCK_SWITCH_POSITION_ON
+                        )
+                }
+            }
+        }
+    }
+
+    fun toggleSwitchPosition() = if (shouldBeLocked()) {
+        switchPosition = LOCK_SWITCH_POSITION_OFF
+    } else {
+        if (!isCaptureButtonPressed) {
+            onLockVideoRecording(true)
+        } else {
+            switchPosition =
+                LOCK_SWITCH_POSITION_ON
+        }
+    }
+    CaptureButtonRing(
+        modifier = modifier
+            .onSizeChanged {
+                relativeCaptureButtonBounds =
+                    Rect(0f, 0f, it.width.toFloat(), it.height.toFloat())
+            }
+            .pointerInput(Unit) {
+                detectTapGestures(
+                    // onLongPress cannot be null, otherwise it won't detect the release if the
+                    // touch is dragged off the component
+                    onLongPress = {},
+                    onPress = {
+                        isCaptureButtonPressed = true
+                        onPress()
+                        awaitRelease()
+                        isCaptureButtonPressed = false
+                        if (shouldBeLocked()) {
+                            onLockVideoRecording(true)
+                            onRelease(true)
+                        }
+
+                        switchPosition = LOCK_SWITCH_POSITION_OFF
+                        onRelease(false)
+                    }
+                )
+            }
+            .pointerInput(Unit) {
+                detectDragGesturesAfterLongPress(
+                    onDragStart = {},
+                    onDragEnd = {},
+                    onDragCancel = {},
+                    onDrag = { change, deltaOffset ->
+                        val newPoint = change.position
+
+                        // update position of lock switch
+                        setLockSwitchPosition(newPoint.x, deltaOffset.x)
+
+                        // update zoom
+                        if (currentUiState.value ==
+                            CaptureButtonUiState.Enabled.Recording.PressedRecording
+                        ) {
+                            val previousPoint = change.position - deltaOffset
+                            val positiveDistance =
+                                if (newPoint.y >= 0 && previousPoint.y >= 0) {
+                                    // 0 if both points are within bounds
+                                    0f
+                                } else if (newPoint.y < 0 && previousPoint.y < 0) {
+                                    deltaOffset.y
+                                } else if (newPoint.y <= 0) {
+                                    newPoint.y
+                                } else {
+                                    previousPoint.y
+                                }
+
+                            if (!positiveDistance.isNaN()) {
+                                // todo(kc): should check the tuning of this.
+                                val zoom = positiveDistance * -0.01f // Adjust sensitivity
+                                onSetZoom(
+                                    CameraZoomRatio(ZoomChange.Increment(zoom))
+                                )
+                            }
+                        }
+                    }
+                )
+            },
+        captureButtonSize = captureButtonSize,
+        color = currentColor
+    ) {
+        if (useLockSwitch) {
+            LockSwitchCaptureButtonNucleus(
+                captureButtonUiState = captureButtonUiState,
+                captureButtonSize = captureButtonSize,
+                switchWidth = switchWidth.dp,
+                switchPosition = switchPosition,
+                onToggleSwitchPosition = { toggleSwitchPosition() },
+                shouldBeLocked = { shouldBeLocked() }
+            )
+        } else {
+            CaptureButtonNucleus(
+                captureButtonUiState = captureButtonUiState,
+                isPressed = isCaptureButtonPressed,
+                captureButtonSize = captureButtonSize
+            )
+        }
+    }
+}
+
+@Composable
+fun CaptureButtonRing(
+    modifier: Modifier = Modifier,
+    captureButtonSize: Float,
+    color: Color,
+    borderWidth: Float = 4f,
+    contents: (@Composable () -> Unit)? = null
+) {
+    Box(modifier = modifier, contentAlignment = Alignment.Center) {
+        contents?.invoke()
+        // todo(): use a canvas instead of a box.
+        //  the sizing gets funny so the scales need to be completely readjusted
+        Box(
+            modifier = Modifier
+                .size(
+                    captureButtonSize.dp
+                )
+                .border(borderWidth.dp, color, CircleShape)
+        )
+    }
+}
+
+/**
+ * A nucleus for the capture button can be dragged to lock the pressed video recording.
+ */
+@Composable
+private fun LockSwitchCaptureButtonNucleus(
+    modifier: Modifier = Modifier,
+    captureButtonUiState: CaptureButtonUiState,
+    captureButtonSize: Float,
+    switchWidth: Dp,
+    switchPosition: Float,
+    onToggleSwitchPosition: () -> Unit,
+    shouldBeLocked: () -> Boolean
+) {
+    val pressedNucleusSize = (captureButtonSize * LOCK_SWITCH_PRESSED_NUCLEUS_SCALE).dp
+    val switchHeight = (pressedNucleusSize * LOCK_SWITCH_HEIGHT_SCALE)
+
+    Box(
+        modifier = modifier
+            .width(switchWidth),
+        contentAlignment = Alignment.Center
+
+    ) {
+        Box(
+            contentAlignment = Alignment.CenterStart,
+            modifier = Modifier
+                .width(switchWidth)
+                .height(switchHeight)
+                .offset(x = -(switchWidth - pressedNucleusSize) / 2)
+        ) {
+            // grey cylinder offset to the left and fades in when pressed recording
+            AnimatedVisibility(
+                visible = captureButtonUiState ==
+                    CaptureButtonUiState.Enabled.Recording.PressedRecording,
+                enter = fadeIn(),
+                exit = ExitTransition.None
+            ) {
+                // grey cylinder
+                Canvas(
+                    modifier = Modifier
+                        .size(switchWidth, switchHeight)
+                        .alpha(LOCK_SWITCH_ALPHA)
+                ) {
+                    drawRoundRect(
+                        color = Color.Black,
+                        cornerRadius = CornerRadius((switchWidth / 2).toPx())
+                    )
+                }
+            }
+        }
+
+        // small moveable Circle remains centered.
+        // is behind lock icon but in front of the switch background
+
+        CaptureButtonNucleus(
+            offsetX = (-(switchWidth - pressedNucleusSize) * switchPosition),
+            captureButtonSize = captureButtonSize,
+            captureButtonUiState = captureButtonUiState,
+            pressedVideoCaptureScale = LOCK_SWITCH_PRESSED_NUCLEUS_SCALE,
+            isPressed = false
+        )
+
+        // locked icon, matches cylinder offset
+        AnimatedVisibility(
+            visible = captureButtonUiState ==
+                CaptureButtonUiState.Enabled.Recording.PressedRecording,
+            enter = fadeIn(),
+            exit = ExitTransition.None
+        ) {
+            Icon(
+                modifier = Modifier
+                    .size(switchHeight * .75f)
+                    .align(Alignment.CenterStart)
+                    .padding(start = 8.dp)
+                    .offset(x = -(switchWidth - pressedNucleusSize))
+                    .clickable(indication = null, interactionSource = null) {
+                        onToggleSwitchPosition()
+                    },
+                tint = Color.White,
+                imageVector = if (shouldBeLocked()) {
+                    Icons.Default.Lock
+                } else {
+                    Icons.Default.LockOpen
+                },
+                contentDescription = null
+            )
+        }
+    }
+}
+
+/**
+ * The animated center of the capture button. It serves as a visual indicator of the current capture and recording states.
+ *
+ * @param captureButtonSize diameter of the capture button ring that this is scaled to
+ * @param isPressed true if the capture button is physically pressed on
+ * @param offsetX the offset of this component. 0 by default
+ * @param idleImageCaptureScale the scale factor for the idle size of the image-only nucleus. Must be between 0 and 1.
+ * @param idleVideoCaptureScale the scale factor for the idle size of the video-only nucleus. Must be between 0 and 1.
+ * @param pressedVideoCaptureScale the scale factor for the pressed size of the video-only nucleus. Must be between 0 and 1.
+ */
+@Composable
+private fun CaptureButtonNucleus(
+    modifier: Modifier = Modifier,
+    captureButtonUiState: CaptureButtonUiState,
+    isPressed: Boolean,
+    captureButtonSize: Float,
+    offsetX: Dp = 0.dp,
+    recordingColor: Color = Color.Red,
+    imageCaptureModeColor: Color = Color.White,
+    idleImageCaptureScale: Float = .7f,
+    idleVideoCaptureScale: Float = .35f,
+    pressedVideoCaptureScale: Float = .7f
+) {
+    require(idleImageCaptureScale in 0f..1f) {
+        "value must be between 0 and 1 to remain within the bounds of the capture button"
+    }
+    require(idleVideoCaptureScale in 0f..1f) {
+        "value must be between 0 and 1 to remain within the bounds of the capture button"
+    }
+    require(pressedVideoCaptureScale in 0f..1f) {
+        "value must be between 0 and 1 to remain within the bounds of the capture button"
+    }
+
+    val currentUiState = rememberUpdatedState(captureButtonUiState)
+
+    // smoothly animate between the size changes of the capture button center
+    val centerShapeSize by animateDpAsState(
+        targetValue = when (val uiState = currentUiState.value) {
+            // inner circle fills white ring when locked
+            CaptureButtonUiState.Enabled.Recording.LockedRecording -> captureButtonSize.dp
+
+            CaptureButtonUiState.Enabled.Recording.PressedRecording ->
+                (captureButtonSize * pressedVideoCaptureScale).dp
+
+            CaptureButtonUiState.Unavailable -> 0.dp
+            is CaptureButtonUiState.Enabled.Idle -> when (uiState.captureMode) {
+                // no inner circle will be visible on STANDARD
+                CaptureMode.STANDARD -> 0.dp
+                // large white circle will be visible on IMAGE_ONLY
+                CaptureMode.IMAGE_ONLY -> (captureButtonSize * idleImageCaptureScale).dp
+                // small red circle will be visible on VIDEO_ONLY
+                CaptureMode.VIDEO_ONLY -> (captureButtonSize * idleVideoCaptureScale).dp
+            }
+        },
+        animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
+    )
+
+    // used to fade between red/white in the center of the capture button
+    val animatedColor by animateColorAsState(
+        targetValue = when (val uiState = currentUiState.value) {
+            is CaptureButtonUiState.Enabled.Idle -> when (uiState.captureMode) {
+                CaptureMode.STANDARD -> imageCaptureModeColor
+                CaptureMode.IMAGE_ONLY -> imageCaptureModeColor
+                CaptureMode.VIDEO_ONLY -> recordingColor
+            }
+
+            is CaptureButtonUiState.Enabled.Recording -> recordingColor
+            is CaptureButtonUiState.Unavailable -> Color.Transparent
+        },
+        animationSpec = tween(durationMillis = 500)
+    )
+
+    // this box contains and centers everything
+    Box(modifier = modifier.offset(x = offsetX), contentAlignment = Alignment.Center) {
+        // this box is the inner circle
+        Box(modifier = Modifier) {
+            Box(
+                contentAlignment = Alignment.Center,
+                modifier = Modifier
+                    .size(centerShapeSize)
+                    .clip(CircleShape)
+                    .alpha(
+                        if (isPressed &&
+                            currentUiState.value ==
+                            CaptureButtonUiState.Enabled.Idle(CaptureMode.IMAGE_ONLY)
+                        ) {
+                            .5f // transparency to indicate click ONLY on IMAGE_ONLY
+                        } else {
+                            1f // solid alpha the rest of the time
+                        }
+                    )
+                    .background(animatedColor)
+            ) {}
+        }
+        // central "square" stop icon
+        AnimatedVisibility(
+            visible = currentUiState.value is
+                CaptureButtonUiState.Enabled.Recording.LockedRecording,
+            enter = scaleIn(initialScale = .5f) + fadeIn(),
+            exit = fadeOut()
+        ) {
+            val smallBoxSize = (captureButtonSize / 5f).dp
+            Canvas(modifier = Modifier) {
+                drawRoundRect(
+                    color = Color.White,
+                    topLeft = Offset(-smallBoxSize.toPx() / 2f, -smallBoxSize.toPx() / 2f),
+                    size = Size(smallBoxSize.toPx(), smallBoxSize.toPx()),
+                    cornerRadius = CornerRadius(smallBoxSize.toPx() * .15f)
+                )
+            }
+        }
+    }
+}
+
+@Preview
+@Composable
+private fun IdleStandardCaptureButtonPreview() {
+    CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+        CaptureButtonNucleus(
+            captureButtonUiState = CaptureButtonUiState.Enabled.Idle(CaptureMode.STANDARD),
+            isPressed = false,
+            captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun IdleImageCaptureButtonPreview() {
+    CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+        CaptureButtonNucleus(
+            captureButtonUiState = CaptureButtonUiState.Enabled.Idle(CaptureMode.IMAGE_ONLY),
+            isPressed = false,
+            captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun PressedImageCaptureButtonPreview() {
+    CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+        CaptureButtonNucleus(
+            captureButtonUiState = CaptureButtonUiState.Enabled.Idle(CaptureMode.IMAGE_ONLY),
+            isPressed = true,
+            captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun IdleRecordingCaptureButtonPreview() {
+    CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+        CaptureButtonNucleus(
+            captureButtonUiState = CaptureButtonUiState.Enabled.Idle(CaptureMode.VIDEO_ONLY),
+            isPressed = false,
+            captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun SimpleNucleusPressedRecordingPreview() {
+    CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+        CaptureButtonNucleus(
+            captureButtonUiState = CaptureButtonUiState.Enabled.Recording.PressedRecording,
+            isPressed = true,
+            captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun LockedRecordingPreview() {
+    CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+        CaptureButtonNucleus(
+            captureButtonUiState = CaptureButtonUiState.Enabled.Recording.LockedRecording,
+            isPressed = false,
+            captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun LockSwitchUnlockedPressedRecordingPreview() {
+    // box is here to account for the offset lock switch
+    Box(modifier = Modifier.width(150.dp), contentAlignment = Alignment.CenterEnd) {
+        CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+            LockSwitchCaptureButtonNucleus(
+                captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE,
+                captureButtonUiState = CaptureButtonUiState.Enabled.Recording.PressedRecording,
+                switchWidth = (DEFAULT_CAPTURE_BUTTON_SIZE * LOCK_SWITCH_WIDTH_SCALE).dp,
+                switchPosition = 0f,
+                onToggleSwitchPosition = {},
+                shouldBeLocked = { false }
+            )
+        }
+    }
+}
+
+@Preview
+@Composable
+private fun LockSwitchLockedAtThresholdPressedRecordingPreview() {
+    // box is here to account for the offset lock switch
+    Box(modifier = Modifier.width(150.dp), contentAlignment = Alignment.CenterEnd) {
+        CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+            LockSwitchCaptureButtonNucleus(
+                captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE,
+                captureButtonUiState = CaptureButtonUiState.Enabled.Recording.PressedRecording,
+                switchWidth = (DEFAULT_CAPTURE_BUTTON_SIZE * LOCK_SWITCH_WIDTH_SCALE).dp,
+                switchPosition = MINIMUM_LOCK_THRESHOLD,
+                onToggleSwitchPosition = {},
+                shouldBeLocked = { true }
+            )
+        }
+    }
+}
+
+@Preview
+@Composable
+private fun LockSwitchLockedPressedRecordingPreview() {
+    // box is here to account for the offset lock switch
+    Box(modifier = Modifier.width(150.dp), contentAlignment = Alignment.CenterEnd) {
+        CaptureButtonRing(captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE, color = Color.White) {
+            LockSwitchCaptureButtonNucleus(
+                captureButtonSize = DEFAULT_CAPTURE_BUTTON_SIZE,
+                captureButtonUiState = CaptureButtonUiState.Enabled.Recording.PressedRecording,
+                switchWidth = (DEFAULT_CAPTURE_BUTTON_SIZE * LOCK_SWITCH_WIDTH_SCALE).dp,
+                switchPosition = 1f,
+                onToggleSwitchPosition = {},
+                shouldBeLocked = { true }
+            )
+        }
+    }
+}
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt
index 504fec2..56995c6 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt
@@ -16,7 +16,6 @@
 package com.google.jetpackcamera.feature.preview.ui
 
 import android.graphics.RectF
-import android.net.Uri
 import androidx.compose.animation.AnimatedContent
 import androidx.compose.foundation.Canvas
 import androidx.compose.foundation.border
@@ -31,22 +30,23 @@ import androidx.compose.ui.draw.clip
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
 import androidx.compose.ui.graphics.nativeCanvas
-import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.unit.dp
-import com.google.jetpackcamera.core.common.loadAndRotateBitmap
+import com.google.jetpackcamera.data.media.MediaDescriptor
 import kotlin.math.min
 
 @Composable
 fun ImageWell(
     modifier: Modifier = Modifier,
-    imageWellUiState: ImageWellUiState = ImageWellUiState.NoPreviousCapture,
-    onClick: (uri: Uri?) -> Unit
+    imageWellUiState: ImageWellUiState = ImageWellUiState.Unavailable,
+    onClick: () -> Unit
 ) {
-    val context = LocalContext.current
-
     when (imageWellUiState) {
         is ImageWellUiState.LastCapture -> {
-            val bitmap = loadAndRotateBitmap(context, imageWellUiState.uri, 270f)
+            val bitmap = when (imageWellUiState.mediaDescriptor) {
+                is MediaDescriptor.Image -> imageWellUiState.mediaDescriptor.thumbnail
+                is MediaDescriptor.Video -> imageWellUiState.mediaDescriptor.thumbnail
+                is MediaDescriptor.None -> null
+            }
 
             bitmap?.let {
                 Box(
@@ -55,7 +55,7 @@ fun ImageWell(
                         .padding(18.dp)
                         .border(2.dp, Color.White, RoundedCornerShape(16.dp))
                         .clip(RoundedCornerShape(16.dp))
-                        .clickable(onClick = { onClick(imageWellUiState.uri) })
+                        .clickable(onClick = onClick)
                 ) {
                     AnimatedContent(
                         targetState = bitmap
@@ -96,14 +96,14 @@ fun ImageWell(
             }
         }
 
-        is ImageWellUiState.NoPreviousCapture -> {
+        is ImageWellUiState.Unavailable -> {
         }
     }
 }
 
 // TODO(yasith): Add support for Video
 sealed interface ImageWellUiState {
-    data object NoPreviousCapture : ImageWellUiState
+    data object Unavailable : ImageWellUiState
 
-    data class LastCapture(val uri: Uri) : ImageWellUiState
+    data class LastCapture(val mediaDescriptor: MediaDescriptor) : ImageWellUiState
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
index 407e3c2..7097a94 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
@@ -26,26 +26,23 @@ import androidx.camera.core.SurfaceRequest
 import androidx.camera.viewfinder.compose.MutableCoordinateTransformer
 import androidx.camera.viewfinder.core.ImplementationMode
 import androidx.compose.animation.AnimatedVisibility
-import androidx.compose.animation.animateColorAsState
 import androidx.compose.animation.core.Animatable
 import androidx.compose.animation.core.EaseOutExpo
-import androidx.compose.animation.core.FastOutSlowInEasing
 import androidx.compose.animation.core.LinearEasing
 import androidx.compose.animation.core.Spring
-import androidx.compose.animation.core.animateDpAsState
 import androidx.compose.animation.core.animateFloatAsState
 import androidx.compose.animation.core.spring
 import androidx.compose.animation.core.tween
+import androidx.compose.animation.expandVertically
 import androidx.compose.animation.fadeIn
-import androidx.compose.animation.fadeOut
-import androidx.compose.animation.scaleIn
+import androidx.compose.animation.shrinkVertically
 import androidx.compose.foundation.Canvas
 import androidx.compose.foundation.background
-import androidx.compose.foundation.border
 import androidx.compose.foundation.clickable
 import androidx.compose.foundation.gestures.detectTapGestures
 import androidx.compose.foundation.gestures.rememberTransformableState
 import androidx.compose.foundation.gestures.transformable
+import androidx.compose.foundation.interaction.MutableInteractionSource
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Box
 import androidx.compose.foundation.layout.BoxWithConstraints
@@ -97,9 +94,6 @@ import androidx.compose.ui.draw.alpha
 import androidx.compose.ui.draw.clip
 import androidx.compose.ui.draw.rotate
 import androidx.compose.ui.draw.scale
-import androidx.compose.ui.geometry.CornerRadius
-import androidx.compose.ui.geometry.Offset
-import androidx.compose.ui.geometry.Size
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.painter.Painter
 import androidx.compose.ui.graphics.vector.rememberVectorPainter
@@ -118,17 +112,22 @@ import androidx.compose.ui.unit.Dp
 import androidx.compose.ui.unit.dp
 import com.google.jetpackcamera.core.camera.VideoRecordingState
 import com.google.jetpackcamera.feature.preview.AudioUiState
-import com.google.jetpackcamera.feature.preview.CaptureButtonUiState
+import com.google.jetpackcamera.feature.preview.CaptureModeUiState
+import com.google.jetpackcamera.feature.preview.DisabledReason
 import com.google.jetpackcamera.feature.preview.ElapsedTimeUiState
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.SingleSelectableState
 import com.google.jetpackcamera.feature.preview.StabilizationUiState
+import com.google.jetpackcamera.feature.preview.ZoomUiState
 import com.google.jetpackcamera.feature.preview.ui.theme.PreviewPreviewTheme
 import com.google.jetpackcamera.settings.model.AspectRatio
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.ZoomChange
 import kotlin.time.Duration.Companion.nanoseconds
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.flow.combine
@@ -421,15 +420,19 @@ fun PreviewDisplay(
     previewUiState: PreviewUiState.Ready,
     onTapToFocus: (x: Float, y: Float) -> Unit,
     onFlipCamera: () -> Unit,
-    onZoomChange: (Float) -> Unit,
+    onZoomRatioChange: (CameraZoomRatio) -> Unit,
     onRequestWindowColorMode: (Int) -> Unit,
     aspectRatio: AspectRatio,
     surfaceRequest: SurfaceRequest?,
     modifier: Modifier = Modifier
 ) {
     val transformableState = rememberTransformableState(
-        onTransformation = { zoomChange, _, _ ->
-            onZoomChange(zoomChange)
+        onTransformation = { pinchZoomChange, _, _ ->
+            onZoomRatioChange(
+                CameraZoomRatio(
+                    ZoomChange.Scale(pinchZoomChange)
+                )
+            )
         }
     )
 
@@ -707,17 +710,11 @@ fun SettingsNavButton(onNavigateToSettings: () -> Unit, modifier: Modifier = Mod
 }
 
 @Composable
-fun ZoomScaleText(zoomScale: Float) {
-    val contentAlpha = animateFloatAsState(
-        targetValue = 10f,
-        label = "zoomScaleAlphaAnimation",
-        animationSpec = tween()
-    )
+fun ZoomRatioText(zoomUiState: ZoomUiState.Enabled) {
     Text(
         modifier = Modifier
-            .alpha(contentAlpha.value)
             .testTag(ZOOM_RATIO_TAG),
-        text = stringResource(id = R.string.zoom_scale_text, zoomScale)
+        text = stringResource(id = R.string.zoom_ratio_text, zoomUiState.primaryZoomRatio ?: 1f)
     )
 }
 
@@ -742,167 +739,118 @@ fun CurrentCameraIdText(physicalCameraId: String?, logicalCameraId: String?) {
 }
 
 @Composable
-fun CaptureButton(
+fun CaptureModeDropDown(
     modifier: Modifier = Modifier,
-    onCaptureImage: () -> Unit,
-    onStartVideoRecording: () -> Unit,
-    onStopVideoRecording: () -> Unit,
-    onLockVideoRecording: (Boolean) -> Unit,
-    captureButtonUiState: CaptureButtonUiState,
-    captureButtonSize: Float = 80f
+    onSetCaptureMode: (CaptureMode) -> Unit,
+    onDisabledCaptureMode: (DisabledReason) -> Unit,
+    captureModeUiState: CaptureModeUiState.Enabled
 ) {
-    val currentUiState = rememberUpdatedState(captureButtonUiState)
-    var isPressedDown by remember {
-        mutableStateOf(false)
-    }
-    var isLongPressing by remember {
-        mutableStateOf(false)
-    }
+    var isExpanded by remember { mutableStateOf(false) }
 
-    val currentColor = LocalContentColor.current
-    Box(
-        contentAlignment = Alignment.Center,
-        modifier = modifier
-            .pointerInput(Unit) {
-                detectTapGestures(
-                    onLongPress = {
-                        isLongPressing = true
-                        val uiState = currentUiState.value
-                        if (uiState is CaptureButtonUiState.Enabled.Idle) {
-                            when (uiState.captureMode) {
-                                CaptureMode.STANDARD,
-                                CaptureMode.VIDEO_ONLY -> {
-                                    onStartVideoRecording()
-                                }
+    Column(modifier = modifier) {
+        AnimatedVisibility(
+            visible = isExpanded,
+            enter =
+            fadeIn() + expandVertically(expandFrom = Alignment.Top),
+            exit = shrinkVertically(shrinkTowards = Alignment.Bottom)
+        ) {
+            fun onDisabledClick(selectableState: SingleSelectableState): () -> Unit =
+                if (selectableState is SingleSelectableState.Disabled) {
+                    { onDisabledCaptureMode(selectableState.disabledReason) }
+                } else {
+                    { TODO("Enabled should not have disabled click") }
+                }
 
-                                CaptureMode.IMAGE_ONLY -> {}
-                            }
-                        }
+            Column {
+                DropDownItem(
+                    text = stringResource(R.string.quick_settings_text_capture_mode_standard),
+                    enabled = captureModeUiState.defaultCaptureState
+                        is SingleSelectableState.Selectable,
+                    onClick = {
+                        onSetCaptureMode(CaptureMode.STANDARD)
+                        isExpanded = false
                     },
-                    onPress = {
-                        isPressedDown = true
-                        awaitRelease()
-                        isPressedDown = false
-                        isLongPressing = false
-                        val uiState = currentUiState.value
-                        when (uiState) {
-                            // stop recording after button is lifted
-                            is CaptureButtonUiState.Enabled.Recording.PressedRecording -> {
-                                onStopVideoRecording()
-                            }
-
-                            is CaptureButtonUiState.Enabled.Idle,
-                            CaptureButtonUiState.Unavailable -> {
-                            }
-
-                            CaptureButtonUiState.Enabled.Recording.LockedRecording -> {}
-                        }
+                    onDisabledClick = onDisabledClick(captureModeUiState.defaultCaptureState)
+                )
+                DropDownItem(
+                    text = stringResource(R.string.quick_settings_text_capture_mode_image_only),
+                    enabled = captureModeUiState.imageOnlyCaptureState
+                        is SingleSelectableState.Selectable,
+                    onClick = {
+                        onSetCaptureMode(CaptureMode.IMAGE_ONLY)
+                        isExpanded = false
                     },
-                    onTap = {
-                        val uiState = currentUiState.value
-                        when (uiState) {
-                            is CaptureButtonUiState.Enabled.Idle -> {
-                                if (!isLongPressing) {
-                                    when (uiState.captureMode) {
-                                        CaptureMode.STANDARD,
-                                        CaptureMode.IMAGE_ONLY -> onCaptureImage()
-
-                                        CaptureMode.VIDEO_ONLY -> {
-                                            onLockVideoRecording(true)
-                                            onStartVideoRecording()
-                                        }
-                                    }
-                                }
-                            }
-                            // stop if locked recording
-                            CaptureButtonUiState.Enabled.Recording.LockedRecording -> {
-                                onStopVideoRecording()
-                            }
+                    onDisabledClick = onDisabledClick(captureModeUiState.imageOnlyCaptureState)
+                )
+                DropDownItem(
+                    text = stringResource(R.string.quick_settings_text_capture_mode_video_only),
+                    enabled = captureModeUiState.videoOnlyCaptureState
+                        is SingleSelectableState.Selectable,
+                    onClick = {
+                        onSetCaptureMode(CaptureMode.VIDEO_ONLY)
+                        isExpanded = false
+                    },
+                    onDisabledClick = onDisabledClick(
+                        captureModeUiState.videoOnlyCaptureState
+                    )
 
-                            CaptureButtonUiState.Unavailable,
-                            CaptureButtonUiState.Enabled.Recording.PressedRecording -> {
-                            }
-                        }
-                    }
                 )
             }
-            .size(captureButtonSize.dp)
-            .border(4.dp, currentColor, CircleShape) // border is the white ring
-    ) {
-        // now we draw center circle
-        val centerShapeSize by animateDpAsState(
-            targetValue = when (val uiState = currentUiState.value) {
-                // inner circle fills white ring when locked
-                CaptureButtonUiState.Enabled.Recording.LockedRecording -> captureButtonSize.dp
-                // larger circle while recording, but not max size
-                CaptureButtonUiState.Enabled.Recording.PressedRecording ->
-                    (captureButtonSize * .7f).dp
-
-                CaptureButtonUiState.Unavailable -> 0.dp
-                is CaptureButtonUiState.Enabled.Idle -> when (uiState.captureMode) {
-                    // no inner circle will be visible on STANDARD
-                    CaptureMode.STANDARD -> 0.dp
-                    // large white circle will be visible on IMAGE_ONLY
-                    CaptureMode.IMAGE_ONLY -> (captureButtonSize * .7f).dp
-                    // small red circle will be visible on VIDEO_ONLY
-                    CaptureMode.VIDEO_ONLY -> (captureButtonSize * .35f).dp
-                }
-            },
-            animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
-        )
-
-        // used to fade between red/white in the center of the capture button
-        val animatedColor by animateColorAsState(
-            targetValue = when (val uiState = currentUiState.value) {
-                is CaptureButtonUiState.Enabled.Idle -> when (uiState.captureMode) {
-                    CaptureMode.STANDARD -> Color.White
-                    CaptureMode.IMAGE_ONLY -> Color.White
-                    CaptureMode.VIDEO_ONLY -> Color.Red
-                }
-
-                is CaptureButtonUiState.Enabled.Recording -> Color.Red
-                is CaptureButtonUiState.Unavailable -> Color.Transparent
-            },
-            animationSpec = tween(durationMillis = 500)
-        )
-        // inner circle
+        }
+        // this text displays the current selection
         Box(
-            contentAlignment = Alignment.Center,
             modifier = Modifier
-                .size(centerShapeSize)
-                .clip(CircleShape)
-                .alpha(
-                    if (isPressedDown &&
-                        currentUiState.value ==
-                        CaptureButtonUiState.Enabled.Idle(CaptureMode.IMAGE_ONLY)
-                    ) {
-                        .5f // transparency to indicate click ONLY on IMAGE_ONLY
-                    } else {
-                        1f // solid alpha the rest of the time
-                    }
+                .clickable(
+                    interactionSource = remember { MutableInteractionSource() },
+                    // removes the greyish background animation that appears when clicking on a clickable
+                    indication = null,
+                    onClick = { isExpanded = !isExpanded }
                 )
-                .background(animatedColor)
-        ) {}
-        // central "square" stop icon
-        AnimatedVisibility(
-            visible = currentUiState.value is
-                CaptureButtonUiState.Enabled.Recording.LockedRecording,
-            enter = scaleIn(initialScale = .5f) + fadeIn(),
-            exit = fadeOut()
+                .padding(8.dp)
         ) {
-            val smallBoxSize = (captureButtonSize / 5f).dp
-            Canvas(modifier = Modifier) {
-                drawRoundRect(
-                    color = Color.White,
-                    topLeft = Offset(-smallBoxSize.toPx() / 2f, -smallBoxSize.toPx() / 2f),
-                    size = Size(smallBoxSize.toPx(), smallBoxSize.toPx()),
-                    cornerRadius = CornerRadius(smallBoxSize.toPx() * .15f)
-                )
-            }
+            Text(
+                text = when (captureModeUiState.currentSelection) {
+                    CaptureMode.STANDARD -> stringResource(
+                        R.string.quick_settings_text_capture_mode_standard
+                    )
+
+                    CaptureMode.VIDEO_ONLY -> stringResource(
+                        R.string.quick_settings_text_capture_mode_image_only
+                    )
+
+                    CaptureMode.IMAGE_ONLY -> stringResource(
+                        R.string.quick_settings_text_capture_mode_video_only
+                    )
+                },
+                modifier = Modifier.padding(16.dp)
+            )
         }
     }
 }
 
+@Composable
+fun DropDownItem(
+    modifier: Modifier = Modifier,
+    text: String,
+    onClick: () -> Unit = {},
+    onDisabledClick: () -> Unit = {},
+    enabled: Boolean = true,
+    isSelected: Boolean = false
+) {
+    Text(
+        text = text,
+        color = if (enabled) Color.Unspecified else Color.DarkGray,
+        modifier = modifier
+            .clickable(enabled = true, onClick = if (enabled) onClick else onDisabledClick)
+            .apply {
+                if (!enabled) {
+                    alpha(.37f)
+                }
+            }
+            .padding(16.dp)
+    )
+}
+
 enum class ToggleState {
     Left,
     Right
@@ -996,7 +944,7 @@ fun ToggleButton(
             ) {
                 Icon(
                     painter = leftIcon,
-                    contentDescription = leftIconDescription,
+                    contentDescription = "leftIcon",
                     modifier = Modifier.padding(iconPadding),
                     tint = if (!enabled) {
                         disableColor
@@ -1008,7 +956,7 @@ fun ToggleButton(
                 )
                 Icon(
                     painter = rightIcon,
-                    contentDescription = rightIconDescription,
+                    contentDescription = "rightIcon",
                     modifier = Modifier.padding(iconPadding),
                     tint = if (!enabled) {
                         disableColor
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
index 58ab943..d482f0c 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
@@ -47,6 +47,7 @@ const val HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM_TAG = "HdrImageUnsupportedOnSin
 const val HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM_TAG = "HdrImageUnsupportedOnMultiStreamTag"
 const val HDR_VIDEO_UNSUPPORTED_ON_DEVICE_TAG = "HdrVideoUnsupportedOnDeviceTag"
 const val HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG = "HdrVideoUnsupportedOnDeviceTag"
+const val HDR_SIMULTANEOUS_IMAGE_VIDEO_UNSUPPORTED_TAG = "HdrSimultaneousImageVideoUnsupportedTag"
 const val ZOOM_RATIO_TAG = "ZoomRatioTag"
 const val LOGICAL_CAMERA_ID_TAG = "LogicalCameraIdTag"
 const val PHYSICAL_CAMERA_ID_TAG = "PhysicalCameraIdTag"
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt
index 47ed19a..9404464 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt
@@ -34,10 +34,8 @@ import androidx.compose.material3.Text
 import androidx.compose.material3.TextButton
 import androidx.compose.material3.TextField
 import androidx.compose.runtime.Composable
-import androidx.compose.runtime.getValue
 import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.remember
-import androidx.compose.runtime.setValue
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.draw.alpha
@@ -53,6 +51,9 @@ import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SET_ZOOM_RATIO_
 import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SET_ZOOM_RATIO_TEXT_FIELD
 import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SHOW_CAMERA_PROPERTIES_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_VIDEO_RESOLUTION_TAG
+import com.google.jetpackcamera.settings.model.CameraZoomRatio
+import com.google.jetpackcamera.settings.model.LensToZoom
+import com.google.jetpackcamera.settings.model.ZoomChange
 import kotlin.math.abs
 
 private const val TAG = "DebugOverlayComponents"
@@ -67,7 +68,7 @@ fun DebugOverlayToggleButton(modifier: Modifier = Modifier, toggleIsOpen: () ->
 @Composable
 fun DebugOverlayComponent(
     modifier: Modifier = Modifier,
-    onChangeZoomScale: (Float) -> Unit,
+    onChangeZoomRatio: (CameraZoomRatio) -> Unit,
     toggleIsOpen: () -> Unit,
     previewUiState: PreviewUiState.Ready
 ) {
@@ -154,7 +155,7 @@ fun DebugOverlayComponent(
 
             // Set zoom ratio
             if (zoomRatioDialog.value) {
-                SetZoomRatioComponent(previewUiState, onChangeZoomScale) {
+                SetZoomRatioComponent(onChangeZoomRatio) {
                     zoomRatioDialog.value = false
                 }
             }
@@ -185,8 +186,7 @@ private fun CameraPropertiesJSONComponent(
 
 @Composable
 private fun SetZoomRatioComponent(
-    previewUiState: PreviewUiState.Ready,
-    onChangeZoomScale: (Float) -> Unit,
+    onChangeZoomRatio: (CameraZoomRatio) -> Unit,
     onClose: () -> Unit
 ) {
     var zoomRatioText = remember { mutableStateOf("") }
@@ -211,14 +211,16 @@ private fun SetZoomRatioComponent(
             ),
             onClick = {
                 try {
-                    val relativeRatio = if (zoomRatioText.value.isEmpty()) {
+                    val newRatio = if (zoomRatioText.value.isEmpty()) {
                         1f
                     } else {
                         zoomRatioText.value.toFloat()
                     }
-                    val currentRatio = previewUiState.zoomScale
-                    val absoluteRatio = relativeRatio / currentRatio
-                    onChangeZoomScale(absoluteRatio)
+                    onChangeZoomRatio(
+                        CameraZoomRatio(
+                            ZoomChange.Absolute(newRatio, LensToZoom.PRIMARY)
+                        )
+                    )
                 } catch (e: NumberFormatException) {
                     Log.d(TAG, "Zoom ratio should be a float")
                 }
diff --git a/feature/preview/src/main/res/values/strings.xml b/feature/preview/src/main/res/values/strings.xml
index d88a2e0..f5c6811 100644
--- a/feature/preview/src/main/res/values/strings.xml
+++ b/feature/preview/src/main/res/values/strings.xml
@@ -15,20 +15,24 @@
   ~ limitations under the License.
   -->
 <resources>
+    <!-- Preview Screen Text -->
     <string name="camera_not_ready">Camera Loading…</string>
 
     <string name="capture_mode_image_capture_content_description">Image capture mode</string>
     <string name="capture_mode_video_recording_content_description">Video recording mode</string>
+<string name="capture_mode_image_capture_content_description_disabled">HDR Image Capture mode only</string>
+    <string name="capture_mode_video_recording_content_description_disabled">HDR Video recording mode only</string>
 
     <string name="settings_content_description">Settings</string>
     <string name="flip_camera_content_description">Flip Camera</string>
 
     <string name="audio_visualizer_icon">An icon of a microphone</string>
-    <string name="zoom_scale_text">%1$.2fx</string>
+    <string name="zoom_ratio_text">%1$.2fx</string>
 
     <string name="debug_text_physical_camera_id_prefix">Physical ID: </string>
     <string name="debug_text_logical_camera_id_prefix">Logical ID: </string>
 
+    <!-- Notification Text -->
     <string name="toast_image_capture_success">Image Capture Success</string>
     <string name="toast_video_capture_success">Video Capture Success</string>
 
@@ -51,50 +55,71 @@
     <string name="toast_hdr_photo_unsupported_on_lens_multi_stream">Multi-stream mode does not support UltraHDR photo capture for current lens</string>
     <string name="toast_hdr_video_unsupported_on_device">HDR video not supported on this device</string>
     <string name="toast_hdr_video_unsupported_on_lens">HDR video not supported by current lens</string>
+    <string name="toast_hdr_simultaneous_image_video_unsupported">HDR video and image capture cannot be bound simultaneously</string>
 
+<!-- Quick Setting Toggle Description   -->
+    <string name="quick_settings_dropdown_open_description">Quick settings open</string>
+    <string name="quick_settings_dropdown_closed_description">Quick settings closed</string>
 
+    <!-- Quick Settings Text and Tags -->
+    <!-- Lens Text -->
     <string name="quick_settings_front_camera_text">FRONT</string>
     <string name="quick_settings_back_camera_text">BACK</string>
     <string name="quick_settings_front_camera_description">Front Camera</string>
     <string name="quick_settings_back_camera_description">Back Camera</string>
 
+    <!-- Aspect Ratio Tags -->
     <string name="quick_settings_aspect_ratio_3_4">3:4</string>
     <string name="quick_settings_aspect_ratio_9_16">9:16</string>
     <string name="quick_settings_aspect_ratio_1_1">1:1</string>
 
+    <string name="quick_settings_aspect_ratio_3_4_description">3 to 4 aspect ratio</string>
+    <string name="quick_settings_aspect_ratio_9_16_description">9 to 16 aspect ratio</string>
+    <string name="quick_settings_aspect_ratio_1_1_description">1 to 1 aspect ratio</string>
+
+    <!-- Dynamic Range Text -->
     <string name="quick_settings_dynamic_range_sdr">SDR</string>
     <string name="quick_settings_dynamic_range_hdr">HDR</string>
     <string name="quick_settings_dynamic_range_sdr_description">Standard dynamic range</string>
     <string name="quick_settings_dynamic_range_hdr_description">High dynamic range</string>
 
-    <string name="quick_settings_aspect_ratio_3_4_description">3 to 4 aspect ratio</string>
-    <string name="quick_settings_aspect_ratio_9_16_description">9 to 16 aspect ratio</string>
-    <string name="quick_settings_aspect_ratio_1_1_description">1 to 1 aspect ratio</string>
-
+    <!-- Flash Text -->
     <string name="quick_settings_flash_off">OFF</string>
     <string name="quick_settings_flash_auto">AUTO</string>
     <string name="quick_settings_flash_on">ON</string>
     <string name="quick_settings_flash_llb">LLB</string>
+
     <string name="quick_settings_flash_off_description">Flash off</string>
     <string name="quick_settings_flash_auto_description">Auto flash</string>
     <string name="quick_settings_flash_on_description">Flash on</string>
     <string name="quick_settings_flash_llb_description">Low Light Boost on</string>
 
-    <string name="quick_settings_capture_mode_single">Single Stream</string>
-    <string name="quick_settings_capture_mode_multi">Multi Stream</string>
-    <string name="quick_settings_capture_mode_single_description">Single-stream capture mode on</string>
-    <string name="quick_settings_capture_mode_multi_description">Multi-stream capture mode on</string>
+    <!-- Stream Config Text -->
+    <string name="quick_settings_stream_config_single">Single Stream</string>
+    <string name="quick_settings_stream_config_multi">Multi Stream</string>
+    <string name="quick_settings_stream_config_single_description">Single-stream capture mode on</string>
+    <string name="quick_settings_stream_config_multi_description">Multi-stream capture mode on</string>
 
-    <string name="quick_settings_dropdown_open_description">Quick settings open</string>
-    <string name="quick_settings_dropdown_closed_description">Quick settings closed</string>
 
+    <!--- Low light boost Text -->
     <string name="quick_settings_lowlightboost_enabled">Low light boost on</string>
     <string name="quick_settings_lowlightboost_disabled">Low light boost off</string>
     <string name="quick_settings_lowlightboost_enabled_description">Low light boost on</string>
     <string name="quick_settings_lowlightboost_disabled_description">Low light boost off</string>
 
-    <string name="quick_settings_concurrent_camera_off">SINGLE</string>
-    <string name="quick_settings_concurrent_camera_dual">DUAL</string>
-    <string name="quick_settings_concurrent_camera_off_description">Concurrent cameras off</string>
-    <string name="quick_settings_concurrent_camera_dual_description">Concurrent dual camera on</string>
+    <!--- Concurrent Camera Text -->
+
+    <string name="quick_settings_text_concurrent_camera_off">Single</string>
+    <string name="quick_settings_text_concurrent_camera_dual">Dual</string>
+    <string name="quick_settings_description_concurrent_camera_off">Single camera mode</string>
+    <string name="quick_settings_description_concurrent_camera_dual">Concurrent dual camera mode</string>
+
+    <!-- Capture Mode Text -->
+    <string name="quick_settings_text_capture_mode_standard">Standard</string>
+    <string name="quick_settings_text_capture_mode_video_only">Video Only</string>
+    <string name="quick_settings_text_capture_mode_image_only">Image Only</string>
+    <string name="quick_settings_description_capture_mode_standard">Standard Capture</string>
+    <string name="quick_settings_description_capture_mode_video_only">Video only capture</string>
+    <string name="quick_settings_description_capture_mode_image_only">Image only capture</string>
+
 </resources>
diff --git a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
index a652896..fa8dc1a 100644
--- a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
+++ b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
@@ -18,6 +18,7 @@ package com.google.jetpackcamera.feature.preview
 import android.content.ContentResolver
 import com.google.common.truth.Truth.assertThat
 import com.google.jetpackcamera.core.camera.test.FakeCameraUseCase
+import com.google.jetpackcamera.data.media.FakeMediaRepository
 import com.google.jetpackcamera.settings.SettableConstraintsRepositoryImpl
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
@@ -54,7 +55,8 @@ class PreviewViewModelTest {
             false,
             cameraUseCase = cameraUseCase,
             constraintsRepository = constraintsRepository,
-            settingsRepository = FakeSettingsRepository
+            settingsRepository = FakeSettingsRepository,
+            mediaRepository = FakeMediaRepository
         )
         advanceUntilIdle()
     }
diff --git a/feature/settings/build.gradle.kts b/feature/settings/build.gradle.kts
index 1d227a3..16fbd37 100644
--- a/feature/settings/build.gradle.kts
+++ b/feature/settings/build.gradle.kts
@@ -19,6 +19,7 @@ plugins {
     alias(libs.plugins.kotlin.android)
     alias(libs.plugins.kotlin.kapt)
     alias(libs.plugins.dagger.hilt.android)
+    alias(libs.plugins.compose.compiler)
 }
 
 android {
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
index 02fbdd8..2a22048 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
@@ -596,6 +596,10 @@ class SettingsViewModel @Inject constructor(
 // ////////////////////////////////////////////////////////////
 //
 // Settings Repository functions
+// ------------------------------------------------------------
+// Note: These do not update the running camera state. Each
+// setting should be applied individually (via diff) in
+// PreviewViewModel.
 //
 // ////////////////////////////////////////////////////////////
 
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
index 3c176de..b0606d5 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
@@ -187,11 +187,7 @@ fun DefaultCameraFacing(
     setDefaultLensFacing: (LensFacing) -> Unit
 ) {
     SwitchSettingUI(
-        modifier = modifier.apply {
-            if (lensUiState is FlipLensUiState.Disabled) {
-                testTag(lensUiState.disabledRationale.testTag)
-            }
-        },
+        modifier = modifier.testTag(BTN_SWITCH_SETTING_LENS_FACING_TAG),
         title = stringResource(id = R.string.default_facing_camera_title),
         description = when (lensUiState) {
             is FlipLensUiState.Disabled -> {
@@ -456,14 +452,7 @@ fun TargetFpsSetting(
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier
-            .apply {
-                if (fpsUiState is FpsUiState.Disabled) {
-                    testTag(fpsUiState.disabledRationale.testTag)
-                } else {
-                    testTag(BTN_OPEN_DIALOG_SETTING_FPS_TAG)
-                }
-            },
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_FPS_TAG),
         title = stringResource(id = R.string.fps_title),
         enabled = fpsUiState is FpsUiState.Enabled,
         leadingIcon = null,
@@ -582,14 +571,7 @@ fun StabilizationSetting(
     // entire setting disabled when no available fps or target fps = 60
     // stabilization is unsupported >30 fps
     BasicPopupSetting(
-        modifier = modifier.apply {
-            when (stabilizationUiState) {
-                is StabilizationUiState.Disabled ->
-                    testTag(stabilizationUiState.disabledRationale.testTag)
-
-                else -> testTag(BTN_OPEN_DIALOG_SETTING_VIDEO_STABILIZATION_TAG)
-            }
-        },
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_VIDEO_STABILIZATION_TAG),
         title = stringResource(R.string.video_stabilization_title),
         leadingIcon = null,
         enabled = stabilizationUiState is StabilizationUiState.Enabled,
@@ -619,18 +601,9 @@ fun StabilizationSetting(
                 when (stabilizationUiState) {
                     is StabilizationUiState.Enabled -> {
                         SingleChoiceSelector(
-                            modifier = Modifier.apply {
-                                if (stabilizationUiState.stabilizationAutoState
-                                        is SingleSelectableState.Disabled
-                                ) {
-                                    testTag(
-                                        stabilizationUiState.stabilizationAutoState
-                                            .disabledRationale.testTag
-                                    )
-                                } else {
-                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_AUTO_TAG)
-                                }
-                            },
+                            modifier = Modifier.testTag(
+                                BTN_DIALOG_VIDEO_STABILIZATION_OPTION_AUTO_TAG
+                            ),
                             text = stringResource(id = R.string.stabilization_selector_auto),
                             secondaryText = stringResource(
                                 id = R.string.stabilization_selector_auto_info
@@ -645,18 +618,9 @@ fun StabilizationSetting(
                         )
 
                         SingleChoiceSelector(
-                            modifier = Modifier.apply {
-                                if (stabilizationUiState.stabilizationOnState
-                                        is SingleSelectableState.Disabled
-                                ) {
-                                    testTag(
-                                        stabilizationUiState.stabilizationOnState
-                                            .disabledRationale.testTag
-                                    )
-                                } else {
-                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_ON_TAG)
-                                }
-                            },
+                            modifier = Modifier.testTag(
+                                BTN_DIALOG_VIDEO_STABILIZATION_OPTION_ON_TAG
+                            ),
                             text = stringResource(id = R.string.stabilization_selector_on),
                             secondaryText = stringResource(
                                 id = R.string.stabilization_selector_on_info
@@ -673,18 +637,9 @@ fun StabilizationSetting(
                         // high quality selector
                         // disabled if target fps = 60 (see VideoCapabilities.isStabilizationSupported)
                         SingleChoiceSelector(
-                            modifier = Modifier.apply {
-                                if (stabilizationUiState.stabilizationHighQualityState
-                                        is SingleSelectableState.Disabled
-                                ) {
-                                    testTag(
-                                        stabilizationUiState.stabilizationHighQualityState
-                                            .disabledRationale.testTag
-                                    )
-                                } else {
-                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_HIGH_QUALITY_TAG)
-                                }
-                            },
+                            modifier = Modifier.testTag(
+                                BTN_DIALOG_VIDEO_STABILIZATION_OPTION_HIGH_QUALITY_TAG
+                            ),
                             text = stringResource(
                                 id = R.string.stabilization_selector_high_quality
                             ),
@@ -703,18 +658,9 @@ fun StabilizationSetting(
 
                         // optical selector
                         SingleChoiceSelector(
-                            modifier = Modifier.apply {
-                                if (stabilizationUiState.stabilizationOpticalState
-                                        is SingleSelectableState.Disabled
-                                ) {
-                                    testTag(
-                                        stabilizationUiState.stabilizationOpticalState
-                                            .disabledRationale.testTag
-                                    )
-                                } else {
-                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_OPTICAL_TAG)
-                                }
-                            },
+                            modifier = Modifier.testTag(
+                                BTN_DIALOG_VIDEO_STABILIZATION_OPTION_OPTICAL_TAG
+                            ),
                             text = stringResource(
                                 id = R.string.stabilization_selector_optical
                             ),
@@ -934,8 +880,7 @@ fun SwitchSettingUI(
                 role = Role.Switch,
                 value = settingValue,
                 onValueChange = { value -> onSwitchChanged(value) }
-            )
-            .testTag(BTN_SWITCH_SETTING_LENS_FACING_TAG),
+            ),
         enabled = enabled,
         title = title,
         description = description,
diff --git a/gradle.properties b/gradle.properties
index 9e52ff1..afa1379 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -6,7 +6,7 @@
 # http://www.gradle.org/docs/current/userguide/build_environment.html
 # Specifies the JVM arguments used for the daemon process.
 # The setting is particularly useful for tweaking memory settings.
-org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
+org.gradle.jvmargs=-Xmx4096m -Dfile.encoding=UTF-8
 # When configured, Gradle will run in incubating parallel mode.
 # This option should only be used with decoupled projects. More details, visit
 # http://www.gradle.org/docs/current/userguide/multi_project_builds.html#sec:decoupled_projects
@@ -20,6 +20,19 @@ android.suppressUnsupportedOptionWarnings=android.suppressUnsupportedOptionWarni
   android.experimental.testOptions.managedDevices.maxConcurrentDevices,\
   android.experimental.testOptions.managedDevices.setupTimeoutMinutes,\
   android.testoptions.manageddevices.emulator.gpu
+
+# When configured, Gradle will run in incubating parallel mode.
+# This option should only be used with decoupled projects. More details, visit
+# http://www.gradle.org/docs/current/userguide/multi_project_builds.html#sec:decoupled_projects
+org.gradle.parallel=true
+
+# Enable caching between builds.
+org.gradle.caching=true
+
+# Enable configuration caching between builds.
+org.gradle.configuration-cache=true
+org.gradle.configuration-cache.parallel=true
+
 # Kotlin code style for this project: "official" or "obsolete":
 kotlin.code.style=official
 # Enables namespacing of each library's R class so that its R class includes only the
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index 97ecfb2..4b20726 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -1,7 +1,7 @@
 [versions]
 # Used directly in build.gradle.kts files
 compileSdk = "35"
-orchestrator = "1.4.2"
+orchestrator = "1.5.1"
 minSdk = "21"
 targetSdk = "35"
 composeCompiler = "1.5.14"
@@ -9,25 +9,26 @@ composeCompiler = "1.5.14"
 # Used below in dependency definitions
 # Compose and Accompanist versions are linked
 # See https://github.com/google/accompanist?tab=readme-ov-file#compose-versions
-composeBom = "2024.11.00"
-accompanist = "0.36.0"
+composeBom = "2025.03.01"
+accompanist = "0.37.2"
 # kotlinPlugin and composeCompiler are linked
 # See https://developer.android.com/jetpack/androidx/releases/compose-kotlin
-kotlinPlugin = "1.9.24"
-androidGradlePlugin = "8.7.3"
-protobufPlugin = "0.9.4"
+kotlinPlugin = "2.1.20"
+androidGradlePlugin = "8.11.0-alpha03"
+protobufPlugin = "0.9.5"
 
-androidxActivityCompose = "1.9.3"
+androidxActivityCompose = "1.10.1"
 androidxAppCompat = "1.7.0"
-androidxBenchmark = "1.3.3"
+androidxBenchmark = "1.3.4"
 androidxCamera = "1.5.0-SNAPSHOT"
 androidxConcurrentFutures = "1.2.0"
 androidxCoreKtx = "1.15.0"
-androidxDatastore = "1.1.1"
-androidxGraphicsCore = "1.0.2"
+androidxDatastore = "1.1.4"
+androidxGraphicsCore = "1.0.3"
 androidxHiltNavigationCompose = "1.2.0"
 androidxLifecycle = "2.8.7"
-androidxNavigationCompose = "2.8.4"
+androidxMedia3 = "1.6.0"
+androidxNavigationCompose = "2.8.9"
 androidxProfileinstaller = "1.4.1"
 androidxTestEspresso = "3.6.1"
 androidxTestJunit = "1.2.1"
@@ -36,14 +37,14 @@ androidxTestRules = "1.6.1"
 androidxTestUiautomator = "2.3.0"
 androidxTracing = "1.2.0"
 cmake = "3.22.1"
-kotlinxAtomicfu = "0.23.2"
-kotlinxCoroutines = "1.9.0"
-hilt = "2.52"
+kotlinxAtomicfu = "0.27.0"
+kotlinxCoroutines = "1.10.2"
+hilt = "2.56.1"
 junit = "4.13.2"
-mockitoCore = "5.6.0"
-protobuf = "3.25.2"
-robolectric = "4.14"
-truth = "1.4.2"
+mockitoCore = "5.17.0"
+protobuf = "4.30.2"
+robolectric = "4.14.1"
+truth = "1.4.4"
 
 [libraries]
 accompanist-permissions = { module = "com.google.accompanist:accompanist-permissions", version.ref = "accompanist" }
@@ -58,6 +59,8 @@ androidx-junit = { module = "androidx.test.ext:junit", version.ref = "androidxTe
 androidx-lifecycle-livedata = { module = "androidx.lifecycle:lifecycle-livedata-ktx", version.ref = "androidxLifecycle" }
 androidx-lifecycle-viewmodel-compose = { module = "androidx.lifecycle:lifecycle-viewmodel-compose", version.ref = "androidxLifecycle" }
 androidx-lifecycle-runtime-compose = { module = "androidx.lifecycle:lifecycle-runtime-compose", version.ref = "androidxLifecycle" }
+androidx-media3-exoplayer = { module = "androidx.media3:media3-exoplayer", version.ref = "androidxMedia3" }
+androidx-media3-ui-compose = { module = "androidx.media3:media3-ui-compose", version.ref = "androidxMedia3" }
 androidx-navigation-compose = { module = "androidx.navigation:navigation-compose", version.ref = "androidxNavigationCompose" }
 androidx-orchestrator = { module = "androidx.test:orchestrator", version.ref = "orchestrator" }
 androidx-profileinstaller = { module = "androidx.profileinstaller:profileinstaller", version.ref = "androidxProfileinstaller" }
@@ -82,7 +85,6 @@ dagger-hilt-compiler = { module = "com.google.dagger:hilt-compiler", version.ref
 futures-ktx = { module = "androidx.concurrent:concurrent-futures-ktx", version.ref = "androidxConcurrentFutures" }
 hilt-navigation-compose = { module = "androidx.hilt:hilt-navigation-compose", version.ref = "androidxHiltNavigationCompose" }
 junit = { module = "junit:junit", version.ref = "junit" }
-kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlinPlugin" }
 kotlinx-atomicfu = { module = "org.jetbrains.kotlinx:atomicfu", version.ref = "kotlinxAtomicfu" }
 kotlinx-coroutines-core = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-core", version.ref = "kotlinxCoroutines" }
 kotlinx-coroutines-test = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-test", version.ref = "kotlinxCoroutines" }
@@ -96,6 +98,7 @@ truth = { module = "com.google.truth:truth", version.ref = "truth" }
 android-application = { id = "com.android.application", version.ref = "androidGradlePlugin" }
 android-library = { id = "com.android.library", version.ref = "androidGradlePlugin" }
 android-test = { id = "com.android.test", version.ref = "androidGradlePlugin" }
+compose-compiler = { id = "org.jetbrains.kotlin.plugin.compose", version.ref = "kotlinPlugin" }
 dagger-hilt-android =  { id = "com.google.dagger.hilt.android", version.ref = "hilt" }
 google-protobuf = { id = "com.google.protobuf", version.ref = "protobufPlugin" }
 kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlinPlugin" }
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 2518d85..b965ecf 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -1,6 +1,6 @@
 #Tue Mar 12 23:44:57 PDT 2024
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-8.9-bin.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.13-bin.zip
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
diff --git a/settings.gradle.kts b/settings.gradle.kts
index 96740cf..cb09553 100644
--- a/settings.gradle.kts
+++ b/settings.gradle.kts
@@ -38,6 +38,7 @@ include(":feature:preview")
 include(":core:camera")
 include(":feature:settings")
 include(":data:settings")
+include(":data:media")
 include(":core:common")
 include(":benchmark")
 include(":feature:permissions")
```

