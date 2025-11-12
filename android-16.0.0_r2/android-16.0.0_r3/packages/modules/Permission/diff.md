```diff
diff --git a/Android.bp b/Android.bp
index f2aab35686..7241eb3e23 100644
--- a/Android.bp
+++ b/Android.bp
@@ -26,6 +26,10 @@ apex {
         "framework-permission-s-compat-config",
     ],
     visibility: ["//packages/modules/common/build"],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 apex_defaults {
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 0bfd581d59..52db985871 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -9,6 +9,3 @@ ktfmt = --kotlinlang-style --include-dirs=SafetyCenter,PermissionController,test
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
 ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES}
-
-[Tool Paths]
-ktfmt = ${REPO_ROOT}/external/ktfmt/ktfmt.sh
diff --git a/PermissionController/Android.bp b/PermissionController/Android.bp
index c1a54619bf..b069a43782 100644
--- a/PermissionController/Android.bp
+++ b/PermissionController/Android.bp
@@ -100,7 +100,6 @@ android_library {
         "android.car-stubs",
         "safety-center-annotations",
     ],
-
     static_libs: [
         "permissioncontroller-protos",
         "iconloader_sc_mainline_prod",
@@ -137,10 +136,12 @@ android_library {
         "SettingsLibCollapsingToolbarBaseActivity",
         "SettingsLibActivityEmbedding",
         "SettingsLibSettingsTheme",
+        "SettingsLibCategory",
         "SettingsLibFooterPreference",
         "SettingsLibSelectorWithWidgetPreference",
         "SettingsLibTwoTargetPreference",
         "SettingsLibIllustrationPreference",
+        "SettingsLibZeroStatePreference",
         "androidx.annotation_annotation",
         "permissioncontroller-statsd",
         "car-ui-lib",
@@ -164,8 +165,13 @@ android_library {
         "android.content.pm.flags-aconfig-java-export",
         "android.os.flags-aconfig-java-export",
         "wear-permission-components",
+        "androidx.appsearch_appsearch",
+        "androidx.appsearch_appsearch-builtin-types",
+        "appfunctions-schema",
     ],
 
+    optional_uses_libs: ["com.android.extensions.appfunctions"],
+
     lint: {
         error_checks: ["Recycle"],
         baseline_filename: "lint-baseline.xml",
@@ -193,6 +199,9 @@ android_app {
     use_resource_processor: true,
     rename_resources_package: false,
     privapp_allowlist: ":privapp_allowlist_com.android.permissioncontroller.xml",
+    flags_packages: [
+        "com.android.permission.flags-aconfig",
+    ],
 
     static_libs: ["PermissionController-lib"],
 
@@ -209,4 +218,8 @@ android_app {
         "//apex_available:platform",
         "com.android.permission",
     ],
+    licenses: [
+        "packages_modules_Permission_PermissionController_license",
+        "opensourcerequest",
+    ],
 }
diff --git a/PermissionController/AndroidManifest.xml b/PermissionController/AndroidManifest.xml
index 9eeef93a2e..3767934fb0 100644
--- a/PermissionController/AndroidManifest.xml
+++ b/PermissionController/AndroidManifest.xml
@@ -332,6 +332,7 @@
                 <action android:name="android.intent.action.MANAGE_UNUSED_APPS" />
                 <action android:name="android.intent.action.REVIEW_APP_DATA_SHARING_UPDATES" />
                 <action android:name="android.permission.action.REVIEW_PERMISSION_DECISIONS"/>
+                <action android:name="com.android.permissioncontroller.action.ADDITIONAL_PERMISSIONS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
         </activity>
@@ -356,6 +357,12 @@
             <intent-filter android:priority="1">
                 <action android:name="com.android.permissioncontroller.settingssearch.action.MANAGE_PERMISSION_APPS" />
                 <action android:name="com.android.permissioncontroller.settingssearch.action.REVIEW_PERMISSION_USAGE" />
+                <action android:name="com.android.permissioncontroller.devicestate.action.MANAGE_PERMISSIONS" />
+                <action android:name="com.android.permissioncontroller.devicestate.action.MANAGE_PERMISSION_APPS" />
+                <action android:name="com.android.permissioncontroller.devicestate.action.MANAGE_APP_PERMISSIONS" />
+                <action android:name="com.android.permissioncontroller.devicestate.action.MANAGE_APP_PERMISSION" />
+                <action android:name="com.android.permissioncontroller.devicestate.action.MANAGE_UNUSED_APPS" />
+                <action android:name="com.android.permissioncontroller.devicestate.action.ADDITIONAL_PERMISSIONS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
         </activity>
@@ -642,6 +649,17 @@
             </intent-filter>
         </activity>
 
+        <service
+            android:name="com.android.permissioncontroller.permission.service.DeviceStateAppFunctionService"
+            android:permission="android.permission.BIND_APP_FUNCTION_SERVICE"
+            android:exported="true"
+            android:featureFlag="com.android.permission.flags.app_function_service_enabled">
+            <property android:name="android.app.appfunctions" android:value="appfunctions.xml"/>
+            <intent-filter>
+                <action android:name="android.app.appfunctions.AppFunctionService"/>
+            </intent-filter>
+        </service>
+
     </application>
 
 </manifest>
diff --git a/PermissionController/TEST_MAPPING b/PermissionController/TEST_MAPPING
index 508105c460..a967c04939 100644
--- a/PermissionController/TEST_MAPPING
+++ b/PermissionController/TEST_MAPPING
@@ -224,7 +224,7 @@
             "name": "CtsPermissionUiTestCases[com.google.android.permission.apex]"
         }
     ],
-    "wear-presubmit": [
+    "wear-cts-presubmit": [
         {
             "name": "CtsPermissionUiTestCases",
             "options": [
diff --git a/PermissionController/appfunctionslib/Android.bp b/PermissionController/appfunctionslib/Android.bp
new file mode 100644
index 0000000000..3c890a3a94
--- /dev/null
+++ b/PermissionController/appfunctionslib/Android.bp
@@ -0,0 +1,42 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package {
+    default_team: "trendy_team_android_permissions",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "appfunctions-schema",
+    sdk_version: "current",
+    min_sdk_version: "30",
+    static_libs: [
+        "androidx.appsearch_appsearch",
+        "androidx.appsearch_appsearch-builtin-types",
+        "androidx.core_core",
+    ],
+
+    srcs: [
+        "src/**/*.kt",
+    ],
+
+    plugins: ["androidx.appsearch_appsearch-compiler-plugin"],
+
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.permission",
+    ],
+}
diff --git a/PermissionController/appfunctionslib/AndroidManifest.xml b/PermissionController/appfunctionslib/AndroidManifest.xml
new file mode 100644
index 0000000000..a6976c52a5
--- /dev/null
+++ b/PermissionController/appfunctionslib/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2025 The Android Open Source Project
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
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.google.android.appfunctions.schema.common.v1.devicestate">
+</manifest>
\ No newline at end of file
diff --git a/PermissionController/appfunctionslib/src/com/google/android/appfunctions/schema/common/v1/devicestate/DeviceState.kt b/PermissionController/appfunctionslib/src/com/google/android/appfunctions/schema/common/v1/devicestate/DeviceState.kt
new file mode 100644
index 0000000000..0d56904f8b
--- /dev/null
+++ b/PermissionController/appfunctionslib/src/com/google/android/appfunctions/schema/common/v1/devicestate/DeviceState.kt
@@ -0,0 +1,269 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.google.android.appfunctions.schema.common.v1.devicestate
+
+import android.content.Context
+import androidx.appsearch.annotation.Document
+import java.util.Objects
+
+private const val DEVICE_STATE_CATEGORY = "device_state"
+
+/** The execution context of app function. */
+public interface AppFunctionContext {
+    /** The Android context. */
+    public val context: Context
+
+    /**
+     * Return the name of the package that invoked this AppFunction. You can use this information to
+     * validate the caller.
+     */
+    public val callingPackageName: String
+}
+
+/** Annotates an interface that defines the app function schema interface. */
+// Binary because it's used to determine the schema name and version from the
+// compiled schema library.
+@Retention(AnnotationRetention.BINARY)
+@Target(AnnotationTarget.CLASS)
+public annotation class AppFunctionSchemaDefinition(
+    val name: String,
+    val version: Int,
+    val category: String,
+)
+
+/** Gets uncategorized device states. */
+@AppFunctionSchemaDefinition(
+    name = "getUncategorizedDeviceState",
+    version = 1,
+    category = DEVICE_STATE_CATEGORY,
+)
+interface GetUncategorizedDeviceState {
+    /**
+     * Gets uncategorized device states.
+     *
+     * @param appFunctionContext The AppFunction execution context.
+     */
+    suspend fun getUncategorizedDeviceState(
+        appFunctionContext: AppFunctionContext
+    ): DeviceStateResponse
+}
+
+/** Gets storage device state. */
+@AppFunctionSchemaDefinition(
+    name = "getStorageDeviceState",
+    version = 1,
+    category = DEVICE_STATE_CATEGORY,
+)
+interface GetStorageDeviceState {
+    /**
+     * Gets storage device states.
+     *
+     * @param appFunctionContext The AppFunction execution context.
+     */
+    suspend fun getStorageDeviceState(appFunctionContext: AppFunctionContext): DeviceStateResponse
+}
+
+/** Gets battery device state. */
+@AppFunctionSchemaDefinition(
+    name = "getBatteryDeviceState",
+    version = 1,
+    category = DEVICE_STATE_CATEGORY,
+)
+interface GetBatteryDeviceState {
+    /**
+     * Gets battery device states.
+     *
+     * @param appFunctionContext The AppFunction execution context.
+     */
+    suspend fun getBatteryDeviceState(appFunctionContext: AppFunctionContext): DeviceStateResponse
+}
+
+/** Gets mobile data usage device state. */
+@AppFunctionSchemaDefinition(
+    name = "getMobileDataUsageDeviceState",
+    version = 1,
+    category = DEVICE_STATE_CATEGORY,
+)
+interface GetMobileDataUsageDeviceState {
+    /**
+     * Gets mobile data suage device states.
+     *
+     * @param appFunctionContext The AppFunction execution context.
+     */
+    suspend fun getMobileDataUsageDeviceState(
+        appFunctionContext: AppFunctionContext
+    ): DeviceStateResponse
+}
+
+/** Gets permissions device state. */
+@AppFunctionSchemaDefinition(
+    name = "getPermissionsDeviceState",
+    version = 1,
+    category = DEVICE_STATE_CATEGORY,
+)
+interface GetPermissionsDeviceState {
+    /**
+     * Gets permissions device states.
+     *
+     * @param appFunctionContext The AppFunction execution context.
+     */
+    suspend fun getPermissionsDeviceState(
+        appFunctionContext: AppFunctionContext
+    ): DeviceStateResponse
+}
+
+/** Gets wellbeing device state. */
+@AppFunctionSchemaDefinition(
+    name = "getWellbeingDeviceState",
+    version = 1,
+    category = DEVICE_STATE_CATEGORY,
+)
+interface GetWellbeingDeviceState {
+    /**
+     * Gets wellbeing device states.
+     *
+     * @param appFunctionContext The AppFunction execution context.
+     */
+    suspend fun getWellbeingDeviceState(appFunctionContext: AppFunctionContext): DeviceStateResponse
+}
+
+/**
+ * Represents the overall state of relevant device settings, structured for consumption by an LLM.
+ * This serves as the top-level response object when querying device state.
+ */
+@Document(name = "com.google.android.appfunctions.schema.common.v1.devicestate.DeviceStateResponse")
+class DeviceStateResponse(
+    @Document.Namespace val namespace: String = "", // unused
+    @Document.Id val id: String = "", // unused
+    /** List of per-screen device states. */
+    @Document.DocumentProperty val perScreenDeviceStates: List<PerScreenDeviceStates> = emptyList(),
+    /**
+     * The device's locale, represented as a BCP 47 language tag.
+     *
+     * Examples: "en-US", "fr-CA", "zh-Hans-CN".
+     */
+    @Document.StringProperty(required = true) val deviceLocale: String,
+) {
+    override fun equals(other: Any?) =
+        other is DeviceStateResponse &&
+            perScreenDeviceStates == other.perScreenDeviceStates &&
+            deviceLocale == other.deviceLocale
+
+    override fun hashCode() = Objects.hash(perScreenDeviceStates, deviceLocale)
+}
+
+/** A list of device states, logically grouped by the Settings screen or area where they appear. */
+@Document(
+    name = "com.google.android.appfunctions.schema.common.v1.devicestate.PerScreenDeviceStates"
+)
+class PerScreenDeviceStates(
+    @Document.Namespace val namespace: String = "", // unused
+    @Document.Id val id: String = "", // unused
+    /**
+     * Optional natural language description providing context about this group of settings. Useful
+     * for the LLM to understand the purpose or scope of this screen/section. Use LLM-interpretable
+     * language. Avoid internal jargon. Can include additional hints that would be interpretable by
+     * the LLM
+     */
+    @Document.StringProperty(required = true) val description: String,
+    /**
+     * The user-visible navigation path within the Settings app to reach this screen, represented as
+     * a list of localized strings. This helps users find the setting manually if needed. Example:
+     * ["Settings", "Network & internet", "Wi-Fi"] For deeper settings, including parent elements
+     * can improve robustness against UI changes. Optional, as `intentUri` is preferred for direct
+     * navigation, but valuable as a fallback or for user guidance. Assumes `LocalizedString`
+     * handles the actual localized text based on `deviceStateLocale`.
+     */
+    @Document.DocumentProperty val paths: List<LocalizedString> = emptyList(),
+    /** Intent uri for the screen, or the nearest parent screen that makes sense. */
+    @Document.StringProperty val intentUri: String? = null,
+    /** List of device state items on the screen. */
+    @Document.DocumentProperty val deviceStateItems: List<DeviceStateItem> = emptyList(),
+) {
+    override fun equals(other: Any?) =
+        other is PerScreenDeviceStates &&
+            description == other.description &&
+            paths == other.paths &&
+            intentUri == other.intentUri &&
+            deviceStateItems == other.deviceStateItems
+
+    override fun hashCode() = Objects.hash(description, paths, intentUri, deviceStateItems)
+}
+
+/** Class for a device state item. */
+@Document(name = "com.google.android.appfunctions.schema.common.v1.devicestate.DeviceStateItem")
+class DeviceStateItem(
+    @Document.Namespace val namespace: String = "", // unused
+    @Document.Id val id: String = "", // unused
+    /** A key identifying this specific setting. MUST be designed to be understood by LLMs */
+    @Document.StringProperty(required = true) val key: String,
+    /** Name from the UI - optional. */
+    @Document.DocumentProperty val name: LocalizedString? = null,
+    /**
+     * The human-readable name or label for this setting as it appears *exactly* in the Settings UI,
+     * localized according to `deviceStateLocale`. Example: "Wi-Fi", "Brightness level", "Show
+     * notifications". Optional: Might not always be available or easily scrapable. Primarily useful
+     * for display verification or showing back to the user, less critical for LLM logic than the
+     * `key`. Assumes `LocalizedString` handles the actual localized text.
+     */
+    @Document.StringProperty val jsonValue: String? = null,
+    /**
+     * This JSON string serves as a direct pass-through to LLM It is intended only for consumption
+     * by the LLM, and developers are not expected to parse it manually. This is optional - we don't
+     * necessarily have the value but we still want to let Gemini know the item exists so it can
+     * point the user towards the relevant screen
+     */
+    @Document.LongProperty val lastUpdatedEpochMillis: Long? = null,
+    /**
+     * Optional natural language hints or instructions for the LLM on how to interpret the `key` and
+     * `jsonValue`. This can clarify units, scales, valid ranges, relationships to other settings,
+     * or constraints. Examples:
+     * - "Value is a percentage (0-100)."
+     * - "Enum values: 'ENABLED', 'DISABLED', 'ASK'."
+     * - "Scale from 0 (off) to 10 (max)."
+     * - "This setting is only effective if 'master.switch.key' is enabled."
+     * - "This setting can be changed by the device care app, package name: com.oem.devicecare" Use
+     *   clear, LLM-interpretable language.
+     */
+    @Document.StringProperty val hintText: String? = null,
+) {
+    override fun equals(other: Any?) =
+        other is DeviceStateItem &&
+            key == other.key &&
+            name == other.name &&
+            jsonValue == other.jsonValue &&
+            lastUpdatedEpochMillis == other.lastUpdatedEpochMillis &&
+            hintText == other.hintText
+
+    override fun hashCode() = Objects.hash(key, name, jsonValue, lastUpdatedEpochMillis, hintText)
+}
+
+/** Class for a localized string. */
+@Document(name = "com.google.android.appfunctions.schema.common.v1.devicestate.LocalizedString")
+class LocalizedString(
+    @Document.Namespace val namespace: String = "", // unused
+    @Document.Id val id: String = "", // unused
+    /** English version of the string. */
+    @Document.StringProperty(required = true) val english: String,
+    /** Localized version of the string. */
+    @Document.StringProperty val localized: String? = null,
+) {
+    override fun equals(other: Any?) =
+        other is LocalizedString && english == other.english && localized == other.localized
+
+    override fun hashCode() = Objects.hash(english, localized)
+}
diff --git a/PermissionController/assets/appfunctions.xml b/PermissionController/assets/appfunctions.xml
new file mode 100644
index 0000000000..36151aef18
--- /dev/null
+++ b/PermissionController/assets/appfunctions.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
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
+
+<appfunctions>
+    <appfunction>
+        <function_id>getPermissionsDeviceState</function_id>
+        <schema_name>getPermissionsDeviceState</schema_name>
+        <schema_category>device_state</schema_category>
+        <schema_version>1</schema_version>
+        <enabled_by_default>true</enabled_by_default>
+    </appfunction>
+</appfunctions>
diff --git a/PermissionController/jarjar-rules.txt b/PermissionController/jarjar-rules.txt
index 7d6e56a707..2042595bfe 100644
--- a/PermissionController/jarjar-rules.txt
+++ b/PermissionController/jarjar-rules.txt
@@ -34,4 +34,8 @@ rule com.android.permission.flags.*FeatureFlags* com.android.permissioncontrolle
 rule com.android.permission.flags.FeatureFlags* com.android.permissioncontroller.jarjar.@0
 rule com.android.permission.flags.FeatureFlags com.android.permissioncontroller.jarjar.@0
 rule com.android.permission.flags.Flags com.android.permissioncontroller.jarjar.@0
+rule com.android.window.flags.*FeatureFlags* com.android.permissioncontroller.jarjar.@0
+rule com.android.window.flags.FeatureFlags* com.android.permissioncontroller.jarjar.@0
+rule com.android.window.flags.FeatureFlags com.android.permissioncontroller.jarjar.@0
+rule com.android.window.flags.Flags com.android.permissioncontroller.jarjar.@0
 # LINT.ThenChange(PermissionController/role-controller/java/com/android/role/controller/model/RoleParser.java:applyJarjarTransform)
diff --git a/PermissionController/res/drawable-v36/permission_history_dash_line_expressive.xml b/PermissionController/res/drawable-v36/permission_history_dash_line_expressive.xml
new file mode 100644
index 0000000000..6df1a05548
--- /dev/null
+++ b/PermissionController/res/drawable-v36/permission_history_dash_line_expressive.xml
@@ -0,0 +1,31 @@
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
+
+<rotate
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:fromDegrees="90"
+    android:toDegrees="90">
+    <shape android:shape="line">
+        <stroke
+            android:color="@color/settingslib_materialColorOutlineVariant"
+            android:dashWidth="2dp"
+            android:dashGap="4dp"
+            android:width="2dp"
+            android:height="26dp"
+            />
+    </shape>
+</rotate>
diff --git a/PermissionController/res/drawable/ic_apps_24dp.xml b/PermissionController/res/drawable/ic_apps_24dp.xml
new file mode 100644
index 0000000000..200471806e
--- /dev/null
+++ b/PermissionController/res/drawable/ic_apps_24dp.xml
@@ -0,0 +1,10 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="?attr/colorControlNormal">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M240,800Q207,800 183.5,776.5Q160,753 160,720Q160,687 183.5,663.5Q207,640 240,640Q273,640 296.5,663.5Q320,687 320,720Q320,753 296.5,776.5Q273,800 240,800ZM480,800Q447,800 423.5,776.5Q400,753 400,720Q400,687 423.5,663.5Q447,640 480,640Q513,640 536.5,663.5Q560,687 560,720Q560,753 536.5,776.5Q513,800 480,800ZM720,800Q687,800 663.5,776.5Q640,753 640,720Q640,687 663.5,663.5Q687,640 720,640Q753,640 776.5,663.5Q800,687 800,720Q800,753 776.5,776.5Q753,800 720,800ZM240,560Q207,560 183.5,536.5Q160,513 160,480Q160,447 183.5,423.5Q207,400 240,400Q273,400 296.5,423.5Q320,447 320,480Q320,513 296.5,536.5Q273,560 240,560ZM480,560Q447,560 423.5,536.5Q400,513 400,480Q400,447 423.5,423.5Q447,400 480,400Q513,400 536.5,423.5Q560,447 560,480Q560,513 536.5,536.5Q513,560 480,560ZM720,560Q687,560 663.5,536.5Q640,513 640,480Q640,447 663.5,423.5Q687,400 720,400Q753,400 776.5,423.5Q800,447 800,480Q800,513 776.5,536.5Q753,560 720,560ZM240,320Q207,320 183.5,296.5Q160,273 160,240Q160,207 183.5,183.5Q207,160 240,160Q273,160 296.5,183.5Q320,207 320,240Q320,273 296.5,296.5Q273,320 240,320ZM480,320Q447,320 423.5,296.5Q400,273 400,240Q400,207 423.5,183.5Q447,160 480,160Q513,160 536.5,183.5Q560,207 560,240Q560,273 536.5,296.5Q513,320 480,320ZM720,320Q687,320 663.5,296.5Q640,273 640,240Q640,207 663.5,183.5Q687,160 720,160Q753,160 776.5,183.5Q800,207 800,240Q800,273 776.5,296.5Q753,320 720,320Z"/>
+</vector>
diff --git a/PermissionController/res/layout-v36/grant_permissions_expressive.xml b/PermissionController/res/layout-v36/grant_permissions_expressive.xml
new file mode 100644
index 0000000000..763b5aa2b7
--- /dev/null
+++ b/PermissionController/res/layout-v36/grant_permissions_expressive.xml
@@ -0,0 +1,201 @@
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
+
+<!--
+  ~ A lot of content in this file is identical to grant_permissions.xml and
+  ~ grant_permissions_material3.xml. Consider updating all the files when making changes.
+  -->
+
+<!-- In (hopefully very rare) case dialog is too high: allow scrolling -->
+<ScrollView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    style="@style/PermissionGrantScrollView">
+
+    <LinearLayout
+        android:id="@+id/grant_singleton"
+        android:importantForAccessibility="no"
+        android:focusable="false"
+        style="@style/PermissionGrantSingleton">
+
+        <!-- The dialog -->
+        <LinearLayout
+            android:id="@+id/grant_dialog"
+            android:theme="@style/Theme.PermissionGrantDialog"
+            android:importantForAccessibility="no"
+            android:focusable="false"
+            style="@style/PermissionGrantDialogMaterial3">
+
+            <LinearLayout
+                android:id="@+id/content_container"
+                style="@style/PermissionGrantContent">
+
+                <LinearLayout
+                    style="@style/PermissionGrantDescription">
+
+                    <ImageView
+                        android:id="@+id/permission_icon"
+                        style="@style/PermissionGrantTitleIconMaterial3" />
+
+                    <TextView
+                        android:id="@+id/permission_message"
+                        android:accessibilityHeading="true"
+                        style="@style/PermissionGrantTitleMessageExpressive" />
+
+                </LinearLayout>
+
+                <TextView
+                    android:id="@+id/detail_message"
+                    style="@style/PermissionGrantDetailMessageExpressive" />
+
+            </LinearLayout>
+
+            <!-- permission rationale  -->
+            <LinearLayout
+                android:id="@+id/permission_rationale_container"
+                style="@style/PermissionGrantPermissionRationaleContent">
+
+                <ImageView
+                    android:id="@+id/permission_rationale_icon"
+                    android:importantForAccessibility="no"
+                    android:src="@drawable/ic_shield_exclamation_outline"
+                    style="@style/PermissionGrantPermissionRationaleIcon" />
+
+                <TextView
+                    android:id="@+id/permission_rationale_message"
+                    style="@style/PermissionGrantPermissionRationaleMessage" />
+
+                <ImageView
+                    android:id="@+id/permission_rationale_more_info_icon"
+                    android:importantForAccessibility="no"
+                    android:src="@drawable/ic_more_info_arrow"
+                    style="@style/PermissionGrantPermissionRationaleMoreInfoIcon" />
+
+            </LinearLayout>
+
+            <!-- location (precise/approximate) animations -->
+            <LinearLayout
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:id="@+id/permission_location_accuracy">
+
+                <RadioGroup
+                    android:id="@+id/permission_location_accuracy_radio_group"
+                    style="@style/PermissionLocationAccuracyRadioGroupMaterial3">
+
+                    <RadioButton
+                        android:id="@+id/permission_location_accuracy_radio_fine"
+                        android:text="@string/permgrouprequest_finelocation_imagetext"
+                        style="@style/PermissionLocationAccuracyRadioFine"/>
+
+                    <RadioButton
+                        android:id="@+id/permission_location_accuracy_radio_coarse"
+                        android:text="@string/permgrouprequest_coarselocation_imagetext"
+                        style="@style/PermissionLocationAccuracyRadioCoarse" />
+                </RadioGroup>
+
+                <ImageView
+                    android:id="@+id/permission_location_accuracy_fine_only"
+                    android:contentDescription="@string/precise_image_description"
+                    style="@style/PermissionLocationAccuracyFineImageViewMaterial3" />
+
+                <ImageView
+                    android:id="@+id/permission_location_accuracy_coarse_only"
+                    android:contentDescription="@string/approximate_image_description"
+                    style="@style/PermissionLocationAccuracyCoarseImageViewMaterial3" />
+
+            </LinearLayout>
+
+            <!-- Buttons on bottom of dialog -->
+            <LinearLayout
+                style="@style/PermissionGrantButtonListExpressive">
+
+                <Space
+                    style="@style/PermissionGrantButtonBarSpace"/>
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_allow_button"
+                    android:text="@string/grant_dialog_button_allow"
+                    style="@style/PermissionGrantButtonAllowExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_allow_foreground_only_button"
+                    android:text="@string/grant_dialog_button_allow_foreground"
+                    style="@style/PermissionGrantButtonAllowForegroundExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_allow_one_time_button"
+                    android:text="@string/grant_dialog_button_allow_one_time"
+                    style="@style/PermissionGrantButtonAllowOneTimeExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_allow_selected_button"
+                    android:text="@string/grant_dialog_button_allow_limited_access"
+                    style="@style/PermissionGrantButtonAllowSelectedExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_allow_all_button"
+                    android:text="@string/grant_dialog_button_allow_all"
+                    style="@style/PermissionGrantButtonAllowAllExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_deny_button"
+                    android:text="@string/grant_dialog_button_deny"
+                    style="@style/PermissionGrantButtonDenyExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_deny_and_dont_ask_again_button"
+                    android:text="@string/grant_dialog_button_deny"
+                    style="@style/PermissionGrantButtonDenyExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_no_upgrade_button"
+                    android:text="@string/grant_dialog_button_no_upgrade"
+                    style="@style/PermissionGrantButtonNoUpgradeExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_no_upgrade_and_dont_ask_again_button"
+                    android:text="@string/grant_dialog_button_no_upgrade"
+                    style="@style/PermissionGrantButtonNoUpgradeExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_no_upgrade_one_time_button"
+                    android:text="@string/grant_dialog_button_no_upgrade_one_time"
+                    style="@style/PermissionGrantButtonNoUpgradeExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_no_upgrade_one_time_and_dont_ask_again_button"
+                    android:text="@string/grant_dialog_button_no_upgrade_one_time"
+                    style="@style/PermissionGrantButtonNoUpgradeExpressive" />
+
+                <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                    android:id="@+id/permission_dont_allow_more_selected_button"
+                    android:text="@string/grant_dialog_button_dont_select_more"
+                    style="@style/PermissionGrantButtonDontAllowMoreExpressive" />
+
+            </LinearLayout>
+
+            <com.android.permissioncontroller.permission.ui.v33.widget.SafetyProtectionSectionView
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginTop="0dp"
+                android:layout_marginBottom="20dp"
+                android:layout_gravity="center" />
+        </LinearLayout>
+    </LinearLayout>
+</ScrollView>
diff --git a/PermissionController/res/layout-v36/permission_rationale_expressive.xml b/PermissionController/res/layout-v36/permission_rationale_expressive.xml
new file mode 100644
index 0000000000..ddff157b7a
--- /dev/null
+++ b/PermissionController/res/layout-v36/permission_rationale_expressive.xml
@@ -0,0 +1,142 @@
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
+
+<!--
+  ~ A lot of content in this file is identical to grant_permissions.xml
+  ~ Be sure to update both files when making changes.
+  -->
+
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+              android:id="@+id/permission_rationale_singleton"
+              android:importantForAccessibility="no"
+              android:focusable="false"
+              style="@style/PermissionRationaleSingleton">
+
+    <!-- The dialog -->
+    <LinearLayout
+        android:id="@+id/permission_rationale_dialog"
+        android:theme="@style/Theme.PermissionRationaleDialog"
+        android:importantForAccessibility="no"
+        style="@style/PermissionRationaleDialog">
+
+        <!-- In (hopefully very rare) case dialog is too high: allow scrolling -->
+        <ScrollView
+            style="@style/PermissionRationaleScrollView">
+
+            <LinearLayout
+                android:id="@+id/content_container"
+                style="@style/PermissionRationaleContentExpressive">
+
+                <LinearLayout
+                    style="@style/PermissionRationaleTitleContainerExpressive">
+
+                    <ImageView
+                        android:id="@+id/permission_icon"
+                        android:importantForAccessibility="no"
+                        android:src="@drawable/ic_shield_exclamation_outline"
+                        style="@style/PermissionRationaleTitleIconExpressive" />
+
+                    <TextView
+                        android:id="@+id/permission_rationale_title"
+                        style="@style/PermissionRationaleTitleMessageExpressive" />
+
+                </LinearLayout>
+
+                <LinearLayout
+                    android:id="@+id/data_sharing_source_section"
+                    style="@style/PermissionRationaleSectionOuterContainerExpressive">
+                    <ImageView
+                        android:id="@+id/data_sharing_source_icon"
+                        android:importantForAccessibility="no"
+                        android:src="@drawable/ic_info_24dp"
+                        style="@style/PermissionRationaleSectionIconExpressive" />
+                    <LinearLayout style="@style/PermissionRationaleSectionInnerContainerExpressive">
+                        <TextView
+                            android:id="@+id/data_sharing_source_title"
+                            android:text="@string/permission_rationale_data_sharing_source_title"
+                            style="@style/PermissionRationaleSectionTitleExpressive" />
+                        <TextView
+                            android:id="@+id/data_sharing_source_message"
+                            style="@style/PermissionRationaleSectionMessageExpressive" />
+                    </LinearLayout>
+                </LinearLayout>
+                <LinearLayout
+                    android:id="@+id/purpose_section"
+                    style="@style/PermissionRationaleSectionOuterContainerExpressive">
+                    <ImageView
+                        android:id="@+id/purpose_icon"
+                        android:importantForAccessibility="no"
+                        android:src="@drawable/ic_help"
+                        style="@style/PermissionRationaleSectionIconExpressive" />
+                    <LinearLayout style="@style/PermissionRationaleSectionInnerContainerExpressive">
+                        <TextView
+                            android:id="@+id/purpose_title"
+                            style="@style/PermissionRationaleSectionTitleExpressive" />
+                        <TextView
+                            android:id="@+id/purpose_message"
+                            style="@style/PermissionRationaleSectionPurposeListExpressive" />
+                    </LinearLayout>
+                </LinearLayout>
+                <LinearLayout
+                    android:id="@+id/learn_more_section"
+                    style="@style/PermissionRationaleSectionOuterContainerExpressive">
+                    <ImageView
+                        android:id="@+id/learn_more_icon"
+                        android:importantForAccessibility="no"
+                        android:src="@drawable/ic_collections_bookmark"
+                        style="@style/PermissionRationaleSectionIconExpressive" />
+                    <LinearLayout style="@style/PermissionRationaleSectionInnerContainerExpressive">
+                        <TextView
+                            android:id="@+id/learn_more_title"
+                            android:text="@string/permission_rationale_permission_data_sharing_varies_title"
+                            style="@style/PermissionRationaleSectionTitleExpressive" />
+                        <TextView
+                            android:id="@+id/learn_more_message"
+                            android:text="@string/permission_rationale_data_sharing_varies_message"
+                            style="@style/PermissionRationaleSectionMessageExpressive" />
+                    </LinearLayout>
+                </LinearLayout>
+                <LinearLayout
+                    android:id="@+id/settings_section"
+                    style="@style/PermissionRationaleSectionOuterContainerExpressive">
+                    <ImageView
+                        android:id="@+id/settings_icon"
+                        android:importantForAccessibility="no"
+                        android:src="@drawable/ic_gear"
+                        style="@style/PermissionRationaleSectionIconExpressive" />
+                    <LinearLayout style="@style/PermissionRationaleSectionInnerContainerExpressive">
+                        <TextView
+                            android:id="@+id/settings_title"
+                            android:text="@string/permission_rationale_location_settings_title"
+                            style="@style/PermissionRationaleSectionTitleExpressive" />
+                        <TextView
+                            android:id="@+id/settings_message"
+                            style="@style/PermissionRationaleSectionMessageExpressive" />
+                    </LinearLayout>
+                </LinearLayout>
+            </LinearLayout>
+        </ScrollView>
+
+        <LinearLayout style="@style/PermissionRationaleButtonContainerExpressive">
+            <com.android.permissioncontroller.permission.ui.widget.SecureButton
+                android:id="@+id/back_button"
+                android:text="@string/back"
+                style="@style/PermissionRationaleBackButtonExpressive" />
+        </LinearLayout>
+
+    </LinearLayout>
+</LinearLayout>
diff --git a/PermissionController/res/layout/enhanced_confirmation_dialog.xml b/PermissionController/res/layout/enhanced_confirmation_dialog.xml
index dde2e3f696..68e8964de9 100644
--- a/PermissionController/res/layout/enhanced_confirmation_dialog.xml
+++ b/PermissionController/res/layout/enhanced_confirmation_dialog.xml
@@ -13,6 +13,12 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
+
+<!--
+  ~ The overall layout is identical to enhanced_confirmation_dialog_expressive.xml. The difference
+  ~ is in the style/theme used. Consider updating all the files when making changes.
+  -->
+
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/enhanced_confirmation_dialog"
diff --git a/PermissionController/res/layout/enhanced_confirmation_dialog_expressive.xml b/PermissionController/res/layout/enhanced_confirmation_dialog_expressive.xml
new file mode 100644
index 0000000000..a37cf0b6b9
--- /dev/null
+++ b/PermissionController/res/layout/enhanced_confirmation_dialog_expressive.xml
@@ -0,0 +1,51 @@
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
+
+<!--
+  ~ The overall layout is identical to enhanced_confirmation_dialog.xml. The difference is in the
+  ~ style/theme used. Consider updating all the files when making changes.
+  -->
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/enhanced_confirmation_dialog"
+    style="@style/EnhancedConfirmationDialogExpressive">
+    <LinearLayout
+        android:id="@+id/enhanced_confirmation_dialog_header"
+        style="@style/EnhancedConfirmationDialogHeaderExpressive">
+        <ImageView
+            android:id="@+id/enhanced_confirmation_dialog_icon"
+            style="@style/EnhancedConfirmationDialogIconExpressive" />
+        <TextView
+            android:id="@+id/enhanced_confirmation_dialog_title"
+            android:text="@string/enhanced_confirmation_dialog_title"
+            style="@style/EnhancedConfirmationDialogTitleExpressive" />
+    </LinearLayout>
+
+    <ScrollView
+        android:id="@+id/enhanced_confirmation_dialog_scrollview"
+        style="@style/EnhancedConfirmationDialogScrollView">
+        <LinearLayout
+            android:id="@+id/enhanced_confirmation_dialog_body"
+            style="@style/EnhancedConfirmationDialogBody">
+            <TextView
+                android:id="@+id/enhanced_confirmation_dialog_desc"
+                android:text="@string/enhanced_confirmation_dialog_desc"
+                style="@style/EnhancedConfirmationDialogDescExpressive" />
+        </LinearLayout>
+    </ScrollView>
+</LinearLayout>
diff --git a/PermissionController/res/values-af-v33/strings.xml b/PermissionController/res/values-af-v33/strings.xml
index 3ad0e7cb4c..b079fdf4ce 100644
--- a/PermissionController/res/values-af-v33/strings.xml
+++ b/PermissionController/res/values-af-v33/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="role_dialer_request_description" msgid="6188305064871543419">"Hierdie app sal toegelaat word om vir jou kennisgewings te stuur, en sal toegang tot jou kamera, kontakte, mikrofoon, foon en SMS\'e kry"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"Hierdie app sal toegelaat word om vir jou kennisgewings te stuur, en sal toegang kry tot jou kamera, kontakte, lêers, mikrofoon, foon en SMS\'e"</string>
-    <string name="permission_description_summary_storage" msgid="1917071243213043858">"Programme met hierdie toestemming het toegang tot alle lêers op hierdie toestel"</string>
+    <string name="permission_description_summary_storage" msgid="1917071243213043858">"Apps met hierdie toestemming het toegang tot alle lêers op hierdie toestel"</string>
     <string name="work_policy_title" msgid="832967780713677409">"Jou werkbeleidinligting"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"Instellings wat deur jou IT-admin bestuur word"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"Vou uit en wys lys"</string>
diff --git a/PermissionController/res/values-af-v36/strings.xml b/PermissionController/res/values-af-v36/strings.xml
new file mode 100644
index 0000000000..5ddecc2f36
--- /dev/null
+++ b/PermissionController/res/values-af-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agentbeheer van ander apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Voer handelinge op jou toestel en in ander apps uit"</string>
+</resources>
diff --git a/PermissionController/res/values-af/strings.xml b/PermissionController/res/values-af/strings.xml
index 79f2b048b5..8d02c607a1 100644
--- a/PermissionController/res/values-af/strings.xml
+++ b/PermissionController/res/values-af/strings.xml
@@ -260,7 +260,7 @@
     <string name="ask_header" msgid="2633816846459944376">"Vra elke keer"</string>
     <string name="denied_header" msgid="903209608358177654">"Nie toegelaat nie"</string>
     <string name="permission_group_name_with_device_name" msgid="8798741850536024820">"<xliff:g id="PERM_GROUP_NAME">%1$s</xliff:g> op <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
-    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Sien meer programme wat toegang tot alle lêers het"</string>
+    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Sien meer apps wat toegang tot alle lêers het"</string>
     <string name="days" msgid="609563020985571393">"{count,plural, =1{1 dag}other{# dae}}"</string>
     <string name="hours" msgid="7302866489666950038">"{count,plural, =1{# uur}other{# uur}}"</string>
     <string name="minutes" msgid="4868414855445375753">"{count,plural, =1{# minuut}other{# minute}}"</string>
@@ -348,7 +348,7 @@
     <string name="no_apps_allowed" msgid="7718822655254468631">"Geen apps toegelaat nie"</string>
     <string name="no_apps_allowed_full" msgid="8011716991498934104">"Geen programme het toestemming vir alle lêers nie"</string>
     <string name="no_apps_allowed_scoped" msgid="4908850477787659501">"Geen programme het toestemming net vir media nie"</string>
-    <string name="no_apps_denied" msgid="7663435886986784743">"Geen programme geweier nie"</string>
+    <string name="no_apps_denied" msgid="7663435886986784743">"Geen apps geweier nie"</string>
     <string name="car_permission_selected" msgid="180837028920791596">"Gekies"</string>
     <string name="settings" msgid="5409109923158713323">"Instellings"</string>
     <string name="accessibility_service_dialog_title_single" msgid="7956432823014102366">"<xliff:g id="SERVICE_NAME">%s</xliff:g> het volle toegang tot jou toestel"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Verstekdigitaleassistentapp"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitaleassistentapp"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Bystandapps kan jou help op grond van inligting vanaf die skerm waarna jy kyk. Sommige apps steun sowel lanseerder- as steminvoerdienste om vir jou geïntegreerde bystand te gee."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Aanbeveel deur <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Verstekblaaier"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Blaaierapp"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps wat jou toegang tot die internet gee en na vertoonskakels waarop jy tik"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Oopmaak van skakels"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Verstek vir werk"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Verstek vir privaat ruimte"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Geoptimeer vir toestel"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Ander"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Geen"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Stelselverstek)"</string>
diff --git a/PermissionController/res/values-am-v36/strings.xml b/PermissionController/res/values-am-v36/strings.xml
new file mode 100644
index 0000000000..dcad3b8696
--- /dev/null
+++ b/PermissionController/res/values-am-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"የሌሎች መተግበሪያዎች ወኪል ቁጥጥር"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"መሣሪያዎ እና ሌሎች መተግበሪያዎች ላይ ተግባሮችን ይፈጽሙ"</string>
+</resources>
diff --git a/PermissionController/res/values-am/strings.xml b/PermissionController/res/values-am/strings.xml
index a683c6bb0c..92bc9ad6d5 100644
--- a/PermissionController/res/values-am/strings.xml
+++ b/PermissionController/res/values-am/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ነባሪ የዲጂታል ረዳት መተግበሪያ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"የዲጂታል ረዳት መተግበሪያ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"ረዳት መተግበሪያዎች በሚያዩት ማያ ገፅ ላይ ባለ መረጃ ላይ ተመስርቶ ሊያግዘዎት ይችላል። አንዳንድ መተግበሪያዎች የተዋሃደ እርዳታ ለእርስዎ ለመስጠት ሁለቱንም ማስጀመሪያ እና የድምፅ ግቤት አገልግሎቶችን ይደግፋሉ።"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"በ<xliff:g id="OEM_NAME">%s</xliff:g> የሚመከር"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ነባሪ አሳሽ መተግበሪያ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"የአሳሽ መተግበሪያ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ወደ በየነ መረብ ለእርስዎ መዳረሻ የሚሰጥዎትን እና እርስዎ መታ የሚያደርጓቸውን አገናኞች የሚያሳዩ መተግበሪያዎች"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"አገናኞችን በመክፈት ላይ"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ለሥራ ነባሪ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ለግል ቦታ ነባሪ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ለመሣሪያ የተባ"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ሌሎች"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ምንም"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(የሥርዓት ነባሪ)"</string>
diff --git a/PermissionController/res/values-ar-v36/strings.xml b/PermissionController/res/values-ar-v36/strings.xml
new file mode 100644
index 0000000000..47bfbfbb5e
--- /dev/null
+++ b/PermissionController/res/values-ar-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"تحكُّم الوكيل في التطبيقات الأخرى"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"يتيح لك هذا الإعداد تنفيذ إجراءات على جهازك وفي تطبيقات أخرى"</string>
+</resources>
diff --git a/PermissionController/res/values-ar/strings.xml b/PermissionController/res/values-ar/strings.xml
index 664fc86233..efac6e31c1 100644
--- a/PermissionController/res/values-ar/strings.xml
+++ b/PermissionController/res/values-ar/strings.xml
@@ -190,7 +190,7 @@
     <string name="app_permission_button_allow_always" msgid="4573292371734011171">"السماح طوال الوقت"</string>
     <string name="app_permission_button_allow_foreground" msgid="1991570451498943207">"السماح عند استخدام التطبيق فقط"</string>
     <string name="app_permission_button_always_allow_all" msgid="4905699259378428855">"السماح بالكل دومًا"</string>
-    <string name="app_permission_button_ask" msgid="3342950658789427">"الطلب في كل مرة"</string>
+    <string name="app_permission_button_ask" msgid="3342950658789427">"السؤال في كل مرة"</string>
     <string name="app_permission_button_deny" msgid="6016454069832050300">"عدم السماح"</string>
     <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"السماح بالوصول المحدود"</string>
     <string name="precise_image_description" msgid="6349638632303619872">"الموقع الجغرافي الدقيق"</string>
@@ -253,8 +253,8 @@
     <string name="app_permission_never_accessed_summary" msgid="401346181461975090">"لم يستخدم الإذن مطلقًا"</string>
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"تم الرفض / لم يسبق الحصول على الإذن"</string>
     <string name="allowed_header" msgid="7769277978004790414">"التطبيقات المسموح لها"</string>
-    <string name="allowed_always_header" msgid="6455903312589013545">"الإذن ممنوحٌ طوال الوقت"</string>
-    <string name="allowed_foreground_header" msgid="6845655788447833353">"تطبيقات يمكنها الوصول عند استخدامها فقط"</string>
+    <string name="allowed_always_header" msgid="6455903312589013545">"تطبيقات لديها الإذن طوال الوقت"</string>
+    <string name="allowed_foreground_header" msgid="6845655788447833353">"تطبيقات لديها الإذن عند استخدامها فقط"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"التطبيقات المسموح لها بالوصول إلى الوسائط فقط"</string>
     <string name="allowed_storage_full" msgid="5356699280625693530">"التطبيقات المسموح لها بإدارة كل الملفات"</string>
     <string name="ask_header" msgid="2633816846459944376">"الطلب في كل مرة"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"تطبيق المساعد الرقمي التلقائي"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"تطبيق المساعد الرقمي"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"بإمكان التطبيقات المساعِدة مساعدتك استنادًا إلى المعلومات التي تظهر على شاشتك. وتعمل بعض التطبيقات مع كل من خدمة المشغّل وخدمة الإدخال الصوتي لتوفير مساعدة متكاملة لك."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"مقترَحة بواسطة \"<xliff:g id="OEM_NAME">%s</xliff:g>\""</string>
     <string name="role_browser_label" msgid="2877796144554070207">"تطبيق المتصفّح التلقائي"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"تطبيق المتصفح"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"التطبيقات التي تتيح إمكانية الوصول إلى الإنترنت وتعرض روابط تنقر عليها"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"فتح الروابط"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"التطبيقات التلقائية للعمل"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"التطبيقات التلقائية في المساحة الخاصّة"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"متوافقة مع الجهاز"</string>
     <string name="default_app_others" msgid="7793029848126079876">"غير ذلك"</string>
     <string name="default_app_none" msgid="9084592086808194457">"غير محدَّد"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(الإعداد التلقائي للنظام)"</string>
@@ -599,7 +599,7 @@
     <string name="active_call_usage_qs" msgid="8559974395932523391">"يتم الاستخدام في المكالمة الهاتفية"</string>
     <string name="recent_call_usage_qs" msgid="743044899599410935">"تم الاستخدام مؤخرًا في مكالمة هاتفية"</string>
     <string name="active_app_usage_qs" msgid="4063912870936464727">"يتم الاستخدام من قِبل <xliff:g id="APP_NAME">%1$s</xliff:g>"</string>
-    <string name="recent_app_usage_qs" msgid="6650259601306212327">"تم الاستخدام مؤخرًا من قِبل \"<xliff:g id="APP_NAME">%1$s</xliff:g>\""</string>
+    <string name="recent_app_usage_qs" msgid="6650259601306212327">"تم الاستخدام مؤخرًا بواسطة \"<xliff:g id="APP_NAME">%1$s</xliff:g>\""</string>
     <string name="active_app_usage_1_qs" msgid="4325136375823357052">"يتم الاستخدام من قِبل <xliff:g id="APP_NAME">%1$s</xliff:g> (<xliff:g id="ATTRIBUTION_LABEL">%2$s</xliff:g>)"</string>
     <string name="recent_app_usage_1_qs" msgid="261450184773310741">"تم الاستخدام مؤخرًا من قِبل <xliff:g id="APP_NAME">%1$s</xliff:g> (<xliff:g id="ATTRIBUTION_LABEL">%2$s</xliff:g>)"</string>
     <string name="active_app_usage_2_qs" msgid="6107866785243565283">"يتم الاستخدام من قِبل <xliff:g id="APP_NAME">%1$s</xliff:g> (<xliff:g id="ATTRIBUTION_LABEL">%2$s</xliff:g> • <xliff:g id="PROXY_LABEL">%3$s</xliff:g>)"</string>
@@ -629,7 +629,7 @@
     <string name="safety_center_background_location_access_revoked" msgid="6972274943343442213">"تم تغيير إذن الوصول."</string>
     <string name="safety_center_view_recent_location_access" msgid="3524391299490678243">"عرض أحدث بيانات استخدام للموقع الجغرافي"</string>
     <string name="privacy_controls_title" msgid="7605929972256835199">"عناصر التحكّم في الخصوصية"</string>
-    <string name="camera_toggle_title" msgid="1251201397431837666">"الوصول إلى الكاميرا"</string>
+    <string name="camera_toggle_title" msgid="1251201397431837666">"الوصول للكاميرا"</string>
     <string name="mic_toggle_title" msgid="2649991093496110162">"الوصول إلى الميكروفون"</string>
     <string name="perm_toggle_description" msgid="7801326363741451379">"للتطبيقات والخدمات"</string>
     <string name="mic_toggle_description" msgid="9163104307990677157">"للتطبيقات والخدمات. إذا كان هذا الخيار غير مفعّل، قد تتم مشاركة بيانات الميكروفون عند الاتصال برقم طوارئ"</string>
@@ -645,7 +645,7 @@
     <string name="permission_rationale_data_sharing_source_message" msgid="8330794595417986883">"‏قدَّم المطوّر معلومات إلى "<annotation id="link"><annotation id="install_source" example="App Store">"%1$s"</annotation></annotation>" عن كيفية مشاركة هذا التطبيق للبيانات. يمكن أنّ يعدّل المطوّر هذه المعلومات بمرور الوقت."</string>
     <string name="permission_rationale_location_purpose_title" msgid="5115877143670012618">"قد يشارك التطبيق بيانات الموقع الجغرافي من أجل:"</string>
     <string name="permission_rationale_permission_data_sharing_varies_title" msgid="9103718980919908316">"اختلاف مشاركة البيانات"</string>
-    <string name="permission_rationale_data_sharing_varies_message" msgid="4224469559084489222">"قد تختلف الممارسات المتعلقة بالبيانات حسب إصدار تطبيقك وآلية استخدامك له ومنطقتك وعمرك. "<annotation id="link">"مزيد من المعلومات عن مشاركة البيانات"</annotation></string>
+    <string name="permission_rationale_data_sharing_varies_message" msgid="4224469559084489222">"قد تختلف الممارسات المتعلقة بالبيانات حسب إصدار تطبيقك وطريقة استخدامك له ومنطقتك وعمرك. "<annotation id="link">"مزيد من المعلومات عن مشاركة البيانات"</annotation></string>
     <string name="permission_rationale_data_sharing_varies_message_without_link" msgid="4912763761399025094">"قد تختلف الممارسات المتعلقة بالبيانات حسب إصدار تطبيقك وآلية استخدامك له ومنطقتك وعمرك."</string>
     <string name="permission_rationale_location_settings_title" msgid="7204145004850190953">"بيانات موقعك الجغرافي"</string>
     <string name="permission_rationale_permission_settings_message" msgid="631286040979660267">"يمكنك تغيير أذونات هذا التطبيق في "<annotation id="link">"إعدادات الخصوصية"</annotation>"."</string>
diff --git a/PermissionController/res/values-as-v36/strings.xml b/PermissionController/res/values-as-v36/strings.xml
new file mode 100644
index 0000000000..32f4821cb1
--- /dev/null
+++ b/PermissionController/res/values-as-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"অন্য এপ্‌সমূহৰ এজেণ্ট নিয়ন্ত্ৰণ"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"আপোনাৰ ডিভাইচত আৰু অন্য এপত কাৰ্য সম্পাদন কৰক"</string>
+</resources>
diff --git a/PermissionController/res/values-as/strings.xml b/PermissionController/res/values-as/strings.xml
index b49b5669bc..690acaedc4 100644
--- a/PermissionController/res/values-as/strings.xml
+++ b/PermissionController/res/values-as/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ডিফ’ল্ট ডিজিটেল সহায়ক এপ্‌"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ডিজিটেল সহায়ক এপ্‌"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"আপুনি চাই থকা স্ক্ৰীনৰ তথ্যৰ ভিত্তিত সহায়ক এপে আপোনাক সহায় কৰিব পাৰে। কিছুমান এপে লঞ্চাৰ আৰু ধ্বনি ইনপুট দুয়োটা সেৱাই আগবঢ়াব পাৰে যাৰ দ্বাৰা আপুনি একীকৃত সহায় লাভ কৰিব পাৰে।"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g>এ চুপাৰিছ কৰা"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ডিফ’ল্ট ব্ৰাউজাৰ এপ্"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ব্ৰাউজাৰ এপ্"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"যিবোৰ এপে আপোনাক ইণ্টাৰনেট আৰু আপুনি টিপা ডিছপ্লে’ লিংকৰ এক্সেছ দিয়ে"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"লিংকসমূহ খুলি থকা হৈছে"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"কৰ্মস্থানৰ বাবে ডিফ’ল্ট"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"প্ৰাইভেট স্পে’চৰ বাবে ডিফ’ল্ট"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ডিভাইচৰ বাবে অপ্টিমাইজ কৰা হৈছে"</string>
     <string name="default_app_others" msgid="7793029848126079876">"অন্য"</string>
     <string name="default_app_none" msgid="9084592086808194457">"নাই"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ছিষ্টেম ডিফ\'ল্ট)"</string>
@@ -679,7 +679,7 @@
     <string name="enhanced_confirmation_dialog_title" msgid="7562437438040966351">"প্ৰতিবন্ধিত ছেটিং"</string>
     <string name="enhanced_confirmation_dialog_desc" msgid="5921240234843839219">"আপোনাৰ সুৰক্ষাৰ বাবে, এই ছেটিংটো বৰ্তমান উপলব্ধ নহয়।"</string>
     <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"কলৰ সময়ত কাৰ্য সম্পূৰ্ণ কৰিব নোৱাৰি"</string>
-    <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"আপোনাৰ ডিভাইচ আৰু ডেটা সুৰক্ষিত কৰিবলৈ এই ছেটিংটো অৱৰোধ কৰা হৈছে।<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
+    <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"আপোনাৰ ডিভাইচ আৰু ডেটা সুৰক্ষিত কৰিবলৈ এই ছেটিং অৱৰোধ কৰা হৈছে।<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
 </xliff:g>স্কেমাৰসকলে আপোনাক এটা নতুন উৎসৰ পৰা অজ্ঞাত এপ্‌সমূহ ইনষ্টল কৰিবলৈ কৈ ক্ষতিকাৰক এপ্‌সমূহ ইনষ্টল কৰিবলৈ চেষ্টা কৰিব পাৰে।"</string>
diff --git a/PermissionController/res/values-az-v36/strings.xml b/PermissionController/res/values-az-v36/strings.xml
new file mode 100644
index 0000000000..54e3721a5c
--- /dev/null
+++ b/PermissionController/res/values-az-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Digər tətbiqlərə nümayəndə nəzarəti"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Cihazınızda və digər tətbiqlərdə əməliyyatlar həyata keçirin"</string>
+</resources>
diff --git a/PermissionController/res/values-az/strings.xml b/PermissionController/res/values-az/strings.xml
index 3276db505c..1e39f6ce88 100644
--- a/PermissionController/res/values-az/strings.xml
+++ b/PermissionController/res/values-az/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Defolt rəq. assistent"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Rəq. assistent tətbiqi"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Köməkçi tətbiqlər ekrandakı məlumatı istifadə edə bilər. Rahat olmaları üçün onlardan bəziləri digər tətbiqlərin işə salınmasını və səsli əmr funksiyasını dəstəkləyir."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> tərəfindən tövsiyə edilir"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Defolt brauzer tətbiqi"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Brauzer tətbiqi"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"İnternet girişini təmin edən və kliklədiyiniz linkləri göstərən tətbiqlər"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Linklərin açılması"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"İş üçün defolt"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Şəxsi sahə üçün defolt"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Cihaz üçün optimallaşdırılıb"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Digərləri"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Yoxdur"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Sistem defoltu)"</string>
diff --git a/PermissionController/res/values-b+sr+Latn-v36/strings.xml b/PermissionController/res/values-b+sr+Latn-v36/strings.xml
new file mode 100644
index 0000000000..6280b85dd4
--- /dev/null
+++ b/PermissionController/res/values-b+sr+Latn-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Kontrolišite druge aplikacije pomoću agenta"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Obavljajte radnje na uređaju i u drugim aplikacijama"</string>
+</resources>
diff --git a/PermissionController/res/values-b+sr+Latn/strings.xml b/PermissionController/res/values-b+sr+Latn/strings.xml
index f65a2ad0ee..df3bed4f97 100644
--- a/PermissionController/res/values-b+sr+Latn/strings.xml
+++ b/PermissionController/res/values-b+sr+Latn/strings.xml
@@ -260,7 +260,7 @@
     <string name="ask_header" msgid="2633816846459944376">"Pitaj svaki put"</string>
     <string name="denied_header" msgid="903209608358177654">"Nije dozvoljeno"</string>
     <string name="permission_group_name_with_device_name" msgid="8798741850536024820">"<xliff:g id="PERM_GROUP_NAME">%1$s</xliff:g> na uređaju <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
-    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Prikaži još aplikacija sa pristupom svim fajlovima"</string>
+    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Pogledajte još aplikacija koje imaju pristup svim fajlovima"</string>
     <string name="days" msgid="609563020985571393">"{count,plural, =1{1 dan}one{# dan}few{# dana}other{# dana}}"</string>
     <string name="hours" msgid="7302866489666950038">"{count,plural, =1{# sat}one{# sat}few{# sata}other{# sati}}"</string>
     <string name="minutes" msgid="4868414855445375753">"{count,plural, =1{# minut}one{# minut}few{# minuta}other{# minuta}}"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Podrazumevani digitalni pomoćnik"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplikacija digitalnog pomoćnika"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikacije za pomoć mogu da vam pomognu na osnovu informacija sa ekrana koji gledate. Neke aplikacije podržavaju usluge pokretača i glasovnog unosa da bi vam pružile integrisanu pomoć."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Preporučuje <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Podrazumevana apl. pregledača"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplikacija pregledača"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikacije koje vam daju pristup internetu i prikazuju linkove koje možete da dodirnete"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Otvaranje linkova"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Podrazumevana za posao"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Podrazumevano za privatan prostor"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizovano za uređaj"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Drugo"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ništa"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Podrazumevana sistemska)"</string>
diff --git a/PermissionController/res/values-be-v36/strings.xml b/PermissionController/res/values-be-v36/strings.xml
new file mode 100644
index 0000000000..7ecd14a8b6
--- /dev/null
+++ b/PermissionController/res/values-be-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Кіраванне іншымі праграмамі ў якасці агента"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Выкананне дзеянняў на прыладзе і ў іншых праграмах"</string>
+</resources>
diff --git a/PermissionController/res/values-be/strings.xml b/PermissionController/res/values-be/strings.xml
index 438da867fb..215fc34350 100644
--- a/PermissionController/res/values-be/strings.xml
+++ b/PermissionController/res/values-be/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Стандартны лічбавы памочнік"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Лічбавы памочнік"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Праграмы-памочнікі кіруюцца інфармацыяй на экране. Для вашай зручнасці некаторыя з іх падтрымліваюць працу з панэллю запуску і галасавы ўвод."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Рэкамендуе <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Стандартны браўзер"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Браўзер"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Праграмы, якія даюць доступ да інтэрнэту і паказваюць спасылкі, на якія вы націскаеце"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Адкрыццё спасылак"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Стандартныя для працы"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Стандартныя праграмы для прыватнай прасторы"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Аптымізаваныя для прылады"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Іншыя"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Няма"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Стандартная сістэмная)"</string>
diff --git a/PermissionController/res/values-bg-v36/strings.xml b/PermissionController/res/values-bg-v36/strings.xml
new file mode 100644
index 0000000000..5449c42bfd
--- /dev/null
+++ b/PermissionController/res/values-bg-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Контролиране на други приложения от агент"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Извършване на действия на устройството ви, както и в други приложения"</string>
+</resources>
diff --git a/PermissionController/res/values-bg/strings.xml b/PermissionController/res/values-bg/strings.xml
index 6713e5dee4..dfbbcf24cb 100644
--- a/PermissionController/res/values-bg/strings.xml
+++ b/PermissionController/res/values-bg/strings.xml
@@ -35,7 +35,7 @@
     <string name="grant_dialog_button_more_info" msgid="213350268561945193">"Още информация"</string>
     <string name="grant_dialog_button_allow_all" msgid="5939066403732409516">"Разрешаване на пълен достъп"</string>
     <string name="grant_dialog_button_always_allow_all" msgid="1719900027660252167">"Винаги да се разрешава пълен достъп"</string>
-    <string name="grant_dialog_button_allow_limited_access" msgid="5713551784422137594">"Разрешаване на ограничения достъп"</string>
+    <string name="grant_dialog_button_allow_limited_access" msgid="5713551784422137594">"Разрешаване на ограничен достъп"</string>
     <string name="grant_dialog_button_allow_selected_photos" msgid="5497042471576153842">"Избиране на снимки и видеоклипове"</string>
     <string name="grant_dialog_button_allow_more_selected_photos" msgid="5145657877588697709">"Избиране на още"</string>
     <string name="grant_dialog_button_dont_select_more" msgid="6643552729129461268">"Без избиране на още"</string>
@@ -192,7 +192,7 @@
     <string name="app_permission_button_always_allow_all" msgid="4905699259378428855">"Винаги да се разрешава пълен достъп"</string>
     <string name="app_permission_button_ask" msgid="3342950658789427">"Извеждане на запитване всеки път"</string>
     <string name="app_permission_button_deny" msgid="6016454069832050300">"Забраняване"</string>
-    <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"Разрешаване на ограничения достъп"</string>
+    <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"Разрешаване на ограничен достъп"</string>
     <string name="precise_image_description" msgid="6349638632303619872">"Точно местоположение"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"Приблизително местоположение"</string>
     <string name="app_permission_location_accuracy" msgid="7166912915040018669">"Използване на точното местоположе­ние"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Дигитален асист.: Станд. прил."</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Прилож. за дигитален асистент"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Помощните приложения могат да ви помагат въз основа на информацията от екрана, който преглеждате. Някои от тях предлагат поддръжка за стартовия панел и услугите за гласово въвеждане, за да ви предоставят интегрирана помощ."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Препоръчани от <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Стандартно прилож. за браузър"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Приложение за браузър"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Приложения, които ви дават достъп до интернет и показват връзки, които можете да докоснете"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Отваряне на връзки"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"По подразбиране за работа"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Стандартни за частното пространство"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Оптимизирано за устройството"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Други"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Няма"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Стандартно за системата)"</string>
diff --git a/PermissionController/res/values-bn-v36/strings.xml b/PermissionController/res/values-bn-v36/strings.xml
new file mode 100644
index 0000000000..77a696b892
--- /dev/null
+++ b/PermissionController/res/values-bn-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"অন্যান্য অ্যাপের এজেন্ট কন্ট্রোল"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"আপনার ডিভাইস ও অন্যান্য অ্যাপে অ্যাকশন পারফর্ম করুন"</string>
+</resources>
diff --git a/PermissionController/res/values-bn/strings.xml b/PermissionController/res/values-bn/strings.xml
index 131a87878e..69b0638534 100644
--- a/PermissionController/res/values-bn/strings.xml
+++ b/PermissionController/res/values-bn/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ডিফল্ট ডিজিটাল অ্যাসিস্ট্যান্ট অ্যাপ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ডিজিটাল অ্যাসিস্ট্যান্ট অ্যাপ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"আপনি যে স্ক্রিন দেখছেন সেটির তথ্যের উপর নির্ভর করে অ্যাসিস্ট অ্যাপ আপনাকে সাহায্য করতে পারে৷ কিছু অ্যাপ আপনাকে ইন্টিগ্রেটেড সহায়তা দিতে, লঞ্চার ও ভয়েস ইনপুট দুটি পরিষেবাই ব্যবহার করতে পারে।"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g>-এর সাজেস্ট করা"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ডিফল্ট ব্রাউজার অ্যাপ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ব্রাউজার অ্যাপ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"এমন অ্যাপ যা ইন্টারনেট অ্যাক্সেস করতে সাহায্য করে ও ট্যাপ করা লিঙ্কগুলি দেখায়"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"লিঙ্ক খোলা"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"অফিসের জন্য ডিফল্ট"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"প্রাইভেট স্পেসের জন্য ডিফল্ট"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ডিভাইসের জন্য অপ্টিমাইজ করা হয়েছে"</string>
     <string name="default_app_others" msgid="7793029848126079876">"অন্যান্য"</string>
     <string name="default_app_none" msgid="9084592086808194457">"কোনওটিই নয়"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(সিস্টেম ডিফল্ট)"</string>
@@ -529,7 +529,7 @@
     <string name="permgroupupgraderequestdetail_camera" msgid="6642747548010962597">"এই অ্যাপ সবসময় এমনকি আপনি যখন অ্যাপ ব্যবহার করছেন না তখনও ছবি তুলতে এবং ভিডিও রেকর্ড করতে চাইবে। "<annotation id="link">"সেটিংস থেকে অনুমতি দিন।"</annotation></string>
     <string name="permgrouprequest_calllog" msgid="2065327180175371397">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;-কে আপনার ফোন কল লগ অ্যাক্সেস করার অনুমতি দেবেন?"</string>
     <string name="permgrouprequest_device_aware_calllog" msgid="8220927190376843309">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; অ্যাপকে &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; ডিভাইসে আপনার ফোনের কল লগ অ্যাক্সেসের অনুমতি দেবেন?"</string>
-    <string name="permgrouprequest_phone" msgid="1829234136997316752">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;-কে কল করতে এবং কল পরিচালনা করতে দেবেন?"</string>
+    <string name="permgrouprequest_phone" msgid="1829234136997316752">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;-কে কল করতে এবং কল ম্যানেজ করতে দেবেন?"</string>
     <string name="permgrouprequest_device_aware_phone" msgid="590399263670349955">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; অ্যাপকে &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; ডিভাইসে ফোন কল করার ও তা ম্যানেজ করার অনুমতি দেবেন?"</string>
     <string name="permgrouprequest_sensors" msgid="4397358316850652235">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;-কে সেন্সর থেকে আপনার ভাইটাল সাইনের ডেটা অ্যাক্সেস করতে দেবেন?"</string>
     <string name="permgrouprequest_device_aware_sensors" msgid="3874451050573615157">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; অ্যাপকে &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; ডিভাইসে আপনার ভাইটাল সাইন সম্পর্কিত সেন্সর ডেটা অ্যাক্সেসের অনুমতি দেবেন?"</string>
@@ -578,7 +578,7 @@
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"এই বিজ্ঞপ্তি বাতিল করবেন?"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"আরও সুরক্ষা যোগ করতে যেকোনও সময় আপনার নিরাপত্তা ও গোপনীয়তা সেটিংস পর্যালোচনা করুন"</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"বাতিল করুন"</string>
-    <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"বাতিল করুন"</string>
+    <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"ক্যানসেল করুন"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"সেটিংস"</string>
     <string name="safety_status_preference_title_and_summary_content_description" msgid="3511373256505058464">"সুরক্ষা ও গোপনীয়তা সংক্রান্ত স্ট্যাটাস। <xliff:g id="OVERALL_SAFETY_STATUS">%1$s</xliff:g>। <xliff:g id="SUMMARY_OF_DEVICE_STATUS">%2$s</xliff:g>"</string>
     <string name="security_settings" msgid="3808106921175271317">"নিরাপত্তা সংক্রান্ত সেটিংস"</string>
diff --git a/PermissionController/res/values-bs-v36/strings.xml b/PermissionController/res/values-bs-v36/strings.xml
new file mode 100644
index 0000000000..7ea893a575
--- /dev/null
+++ b/PermissionController/res/values-bs-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Upravljanje drugim aplikacijama putem agenta"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Izvršavajte radnje na uređaju i u drugim aplikacijama"</string>
+</resources>
diff --git a/PermissionController/res/values-bs/strings.xml b/PermissionController/res/values-bs/strings.xml
index 2b76fd5eb7..b4a2716c3b 100644
--- a/PermissionController/res/values-bs/strings.xml
+++ b/PermissionController/res/values-bs/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Zadani digitalni asistent"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplikacija digitalnog asistenta"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikacije za pomoć vam mogu pomoći na osnovu informacija s ekrana koji pregledate. Neke aplikacije podržavaju i usluge pokretača i glasovnog unosa kako bi vam pružile integriranu pomoć."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Preporučuje <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Zadana aplikacija preglednika"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplikacija preglednika"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikacije koje vam pružaju pristup internetu i prikazuju linkove koje možete dodirnuti"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Otvaranje linkova"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Uobičajeno za rad"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Zadano za privatni prostor"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizirano za uređaj"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Drugo"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nema"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Sistemski zadano)"</string>
diff --git a/PermissionController/res/values-ca-v36/strings.xml b/PermissionController/res/values-ca-v36/strings.xml
new file mode 100644
index 0000000000..42cbc9d305
--- /dev/null
+++ b/PermissionController/res/values-ca-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Control de l\'agent d\'altres aplicacions"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Dur a terme accions al dispositiu i en altres aplicacions"</string>
+</resources>
diff --git a/PermissionController/res/values-ca/strings.xml b/PermissionController/res/values-ca/strings.xml
index f65432f032..15324b4420 100644
--- a/PermissionController/res/values-ca/strings.xml
+++ b/PermissionController/res/values-ca/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Assistent digital predeterminat"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplicació d\'assistent digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Les aplicacions d\'assistència et poden ajudar en funció de la informació que es mostri a la pantalla. Algunes aplicacions admeten tant el menú d\'aplicacions com els serveis d\'entrada de veu per oferir-te una assistència integrada."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomanació de: <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Aplicació de navegador predeterminada"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplicació de navegador"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplicacions que et donen accés a Internet i que mostren els enllaços que toques"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Obertura d\'enllaços"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predeterminada per a la feina"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Predeterminades per a l\'espai privat"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimitzades per al dispositiu"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Altres"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Cap"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Opció predeterminada del sistema)"</string>
@@ -568,7 +568,7 @@
     <string name="automotive_blocked_camera_title" msgid="6142362431548829416">"L\'accés a Càmera està desactivat"</string>
     <string name="automotive_blocked_microphone_title" msgid="3956311098238620220">"L\'accés al micròfon està desactivat"</string>
     <string name="automotive_blocked_location_title" msgid="6047574747593264689">"L\'accés a la ubicació està desactivat"</string>
-    <string name="automotive_blocked_infotainment_app_summary" msgid="8217099645064950860">"Per a les aplicacions d\'informació i entreteniment"</string>
+    <string name="automotive_blocked_infotainment_app_summary" msgid="8217099645064950860">"Per a les aplicacions d\'infoentreteniment"</string>
     <string name="automotive_blocked_required_app_summary" msgid="8591513745681168088">"Per a les aplicacions requerides"</string>
     <string name="automotive_required_app_title" msgid="2992168288249988735">"Es requereix aquesta aplicació"</string>
     <string name="automotive_required_app_summary" msgid="6514902316658090465">"El fabricant del cotxe requereix aquesta aplicació"</string>
diff --git a/PermissionController/res/values-cs-v36/strings.xml b/PermissionController/res/values-cs-v36/strings.xml
new file mode 100644
index 0000000000..ace24e8737
--- /dev/null
+++ b/PermissionController/res/values-cs-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agentní ovládání ostatních aplikací"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Provádějte akce na zařízení a v ostatních aplikacích"</string>
+</resources>
diff --git a/PermissionController/res/values-cs/strings.xml b/PermissionController/res/values-cs/strings.xml
index 242661d917..6c24af699e 100644
--- a/PermissionController/res/values-cs/strings.xml
+++ b/PermissionController/res/values-cs/strings.xml
@@ -79,7 +79,7 @@
     <string name="no_permissions" msgid="3881676756371148563">"Žádná oprávnění"</string>
     <string name="additional_permissions" msgid="5801285469338873430">"Další oprávnění"</string>
     <string name="app_permissions_info_button_label" msgid="7633312050729974623">"Otevřít informace o aplikaci"</string>
-    <string name="additional_permissions_more" msgid="5681220714755304407">"{count,plural, =1{# dalších}few{# další}many{# dalšího}other{# dalších}}"</string>
+    <string name="additional_permissions_more" msgid="5681220714755304407">"{count,plural, =1{a ještě #}few{a ještě # }many{a ještě #}other{a ještě #}}"</string>
     <string name="old_sdk_deny_warning" msgid="2382236998845153919">"Tato aplikace byla vytvořena pro starší verzi platformy Android. Pokud oprávnění neudělíte, může přestat fungovat podle původního záměru."</string>
     <string name="storage_supergroup_warning_allow" msgid="103093462784523190">"Tato aplikace byla vytvořena pro starší verzi platformy Android. Pokud toto oprávnění povolíte, bude povolen přístup k celému úložišti (včetně fotek, videí, hudby, zvuků a dalších souborů)."</string>
     <string name="storage_supergroup_warning_deny" msgid="6420765672683284347">"Tato aplikace byla vytvořena pro starší verzi platformy Android. Pokud toto oprávnění odepřete, bude odepřen přístup k celému úložišti (včetně fotek, videí, hudby, zvuků a dalších souborů)."</string>
@@ -197,8 +197,8 @@
     <string name="approximate_image_description" msgid="938803699637069884">"Přibližná poloha"</string>
     <string name="app_permission_location_accuracy" msgid="7166912915040018669">"Používat přesnou polohu"</string>
     <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"Když je přesná poloha vypnutá, aplikace mají přístup k vaší přibližné poloze"</string>
-    <string name="app_permission_title" msgid="2090897901051370711">"Oprávnění: <xliff:g id="PERM">%1$s</xliff:g>"</string>
-    <string name="app_permission_header" msgid="2951363137032603806">"Přístup této aplikace k oprávnění: <xliff:g id="PERM">%1$s</xliff:g>"</string>
+    <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g>: oprávnění"</string>
+    <string name="app_permission_header" msgid="2951363137032603806">"<xliff:g id="PERM">%1$s</xliff:g>: přístup této aplikace"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"Přístup k <xliff:g id="PERM">%1$s</xliff:g> pro tuto aplikaci v zařízení <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
     <string name="app_permission_footer_app_permissions_link" msgid="4926890342636587393">"Zobrazit všechna oprávnění aplikace <xliff:g id="APP">%1$s</xliff:g>"</string>
     <string name="app_permission_footer_permission_apps_link" msgid="3941988129992794327">"Zobrazit všechny aplikace s tímto oprávněním"</string>
@@ -252,13 +252,13 @@
     <string name="app_permission_most_recent_denied_summary" msgid="7659497197737708112">"Zakázáno / naposledy použito: <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_permission_never_accessed_summary" msgid="401346181461975090">"Žádný přístup"</string>
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"Zakázáno / žádný přístup"</string>
-    <string name="allowed_header" msgid="7769277978004790414">"Povoleno"</string>
+    <string name="allowed_header" msgid="7769277978004790414">"Přístup povolen"</string>
     <string name="allowed_always_header" msgid="6455903312589013545">"Povoleno pořád"</string>
     <string name="allowed_foreground_header" msgid="6845655788447833353">"Povoleno pouze při používání"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"Povolen pouze přístup k médiím"</string>
     <string name="allowed_storage_full" msgid="5356699280625693530">"Povolena správa všech souborů"</string>
     <string name="ask_header" msgid="2633816846459944376">"Pokaždé se zeptat"</string>
-    <string name="denied_header" msgid="903209608358177654">"Nepovoleno"</string>
+    <string name="denied_header" msgid="903209608358177654">"Přístup zakázán"</string>
     <string name="permission_group_name_with_device_name" msgid="8798741850536024820">"<xliff:g id="PERM_GROUP_NAME">%1$s</xliff:g> na <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
     <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Zobrazit další aplikace s přístupem ke všem souborům"</string>
     <string name="days" msgid="609563020985571393">"{count,plural, =1{1 den}few{# dny}many{# dne}other{# dní}}"</string>
@@ -345,10 +345,10 @@
     <string name="app_perms_content_provider_7d_all_files" msgid="7962416229708835558">"Použito během posledních 7 dní • Všechny soubory"</string>
     <string name="no_permissions_allowed" msgid="6081976856354669209">"Nejsou povolena žádná oprávnění"</string>
     <string name="no_permissions_denied" msgid="8159923922804043282">"Nejsou zakázána žádná oprávnění"</string>
-    <string name="no_apps_allowed" msgid="7718822655254468631">"Žádné povolené aplikace"</string>
+    <string name="no_apps_allowed" msgid="7718822655254468631">"Přístup není povolen žádným aplikacím"</string>
     <string name="no_apps_allowed_full" msgid="8011716991498934104">"Žádné aplikace nejsou povolené pro všechny soubory"</string>
     <string name="no_apps_allowed_scoped" msgid="4908850477787659501">"Žádné aplikace nejsou povolené pouze pro média"</string>
-    <string name="no_apps_denied" msgid="7663435886986784743">"Žádné zakázané aplikace"</string>
+    <string name="no_apps_denied" msgid="7663435886986784743">"Přístup není zakázán žádným aplikacím"</string>
     <string name="car_permission_selected" msgid="180837028920791596">"Vybráno"</string>
     <string name="settings" msgid="5409109923158713323">"Nastavení"</string>
     <string name="accessibility_service_dialog_title_single" msgid="7956432823014102366">"Služba <xliff:g id="SERVICE_NAME">%s</xliff:g> má plný přístup k vašemu zařízení"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Výchozí digitální asistent"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplikace digitálního asistenta"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Asistenční aplikace pomáhají na základě informací na zobrazené obrazovce. Některé aplikace podporují spouštěče i hlasový vstup, a nabízejí tak integrovanou asistenci."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Doporučuje: <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Výchozí prohlížeč"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Prohlížeč"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikace, které vám umožňují přístup k internetu a zobrazují odkazy, na které můžete klepnout."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Otevírání odkazů"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Výchozí pracovní"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Výchozí pro soukromý prostor"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimalizováno pro zařízení"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Jiné"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Žádná aplikace"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Výchozí nastavení systému)"</string>
@@ -583,7 +583,7 @@
     <string name="safety_status_preference_title_and_summary_content_description" msgid="3511373256505058464">"Stav ochrany soukromí a zabezpečení. <xliff:g id="OVERALL_SAFETY_STATUS">%1$s</xliff:g>. <xliff:g id="SUMMARY_OF_DEVICE_STATUS">%2$s</xliff:g>"</string>
     <string name="security_settings" msgid="3808106921175271317">"Nastavení zabezpečení"</string>
     <string name="sensor_permissions_qs" msgid="1022267900031317472">"Oprávnění"</string>
-    <string name="safety_privacy_qs_tile_title" msgid="727301867710374052">"Zabezpečení a ochrana soukromí"</string>
+    <string name="safety_privacy_qs_tile_title" msgid="727301867710374052">"Zabezpečení a soukromí"</string>
     <string name="safety_privacy_qs_tile_subtitle" msgid="3621544532041936749">"Zkontrolovat stav"</string>
     <string name="privacy_controls_qs" msgid="5780144882040591169">"Nastavení ochrany soukromí"</string>
     <string name="security_settings_button_label_qs" msgid="8280343822465962330">"Další nastavení"</string>
diff --git a/PermissionController/res/values-da-v36/strings.xml b/PermissionController/res/values-da-v36/strings.xml
new file mode 100644
index 0000000000..85dea721e2
--- /dev/null
+++ b/PermissionController/res/values-da-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agentstyring af andre apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Udfør handlinger på din enhed og i andre apps"</string>
+</resources>
diff --git a/PermissionController/res/values-da/strings.xml b/PermissionController/res/values-da/strings.xml
index aa02618366..4af748ddb3 100644
--- a/PermissionController/res/values-da/strings.xml
+++ b/PermissionController/res/values-da/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Standardapp for digital assistent"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App for digital assistent"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assistanceapps kan hjælpe dig på baggrund af oplysningerne på den aktuelle skærm. Nogle apps understøtter både startertjenester og tjenester til indtaling for at give dig integreret assistance."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Anbefalet af <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Standardapp til browsing"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browserapp"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps, der giver dig adgang til internettet og viser links, som du trykker på"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Åbning af links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Standard til arbejde"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Standard for privat område"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimeret til enheden"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Andre"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ingen"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Systemstandard)"</string>
@@ -587,8 +587,8 @@
     <string name="safety_privacy_qs_tile_subtitle" msgid="3621544532041936749">"Tjek status"</string>
     <string name="privacy_controls_qs" msgid="5780144882040591169">"Dine privatlivsindstillinger"</string>
     <string name="security_settings_button_label_qs" msgid="8280343822465962330">"Flere indstillinger"</string>
-    <string name="camera_toggle_label_qs" msgid="3880261453066157285">"Kameraadgang"</string>
-    <string name="microphone_toggle_label_qs" msgid="8132912469813396552">"Mikrofonadgang"</string>
+    <string name="camera_toggle_label_qs" msgid="3880261453066157285">"Kamera­adgang"</string>
+    <string name="microphone_toggle_label_qs" msgid="8132912469813396552">"Mikrofon­adgang"</string>
     <string name="permissions_removed_qs" msgid="8957319130625294572">"Tilladelsen blev fjernet"</string>
     <string name="camera_usage_qs" msgid="4394233566086665994">"Se seneste kamerabrug"</string>
     <string name="microphone_usage_qs" msgid="8527666682168170417">"Se seneste mikrofonbrug"</string>
@@ -629,8 +629,8 @@
     <string name="safety_center_background_location_access_revoked" msgid="6972274943343442213">"Adgangen er ændret"</string>
     <string name="safety_center_view_recent_location_access" msgid="3524391299490678243">"Se seneste brug af lokation"</string>
     <string name="privacy_controls_title" msgid="7605929972256835199">"Privatlivsindstillinger"</string>
-    <string name="camera_toggle_title" msgid="1251201397431837666">"Kameraadgang"</string>
-    <string name="mic_toggle_title" msgid="2649991093496110162">"Mikrofonadgang"</string>
+    <string name="camera_toggle_title" msgid="1251201397431837666">"Kamera­adgang"</string>
+    <string name="mic_toggle_title" msgid="2649991093496110162">"Mikrofon­adgang"</string>
     <string name="perm_toggle_description" msgid="7801326363741451379">"For apps og tjenester"</string>
     <string name="mic_toggle_description" msgid="9163104307990677157">"For apps og tjenester: Hvis denne indstilling er deaktiveret, deles mikrofondata muligvis stadig, når du ringer til et alarmnummer."</string>
     <string name="location_settings_subtitle" msgid="2328360561197430695">"Se de apps og tjenester, der har adgang til lokation"</string>
diff --git a/PermissionController/res/values-de-v36/strings.xml b/PermissionController/res/values-de-v36/strings.xml
new file mode 100644
index 0000000000..68d657cd40
--- /dev/null
+++ b/PermissionController/res/values-de-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"KI‑Agent-Steuerung anderer Apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Aktionen auf deinem Gerät und in anderen Apps ausführen"</string>
+</resources>
diff --git a/PermissionController/res/values-de/strings.xml b/PermissionController/res/values-de/strings.xml
index e8304f126c..10799ce790 100644
--- a/PermissionController/res/values-de/strings.xml
+++ b/PermissionController/res/values-de/strings.xml
@@ -125,7 +125,7 @@
     <string name="current_permissions_category" msgid="4292990083585728880">"Aktuelle Berechtigungen"</string>
     <string name="message_staging" msgid="9110563899955511866">"App wird vorbereitet…"</string>
     <string name="app_name_unknown" msgid="1319665005754048952">"Unbekannt"</string>
-    <string name="permission_usage_title" msgid="1568233336351734538">"Privatsphäre­dashboard"</string>
+    <string name="permission_usage_title" msgid="1568233336351734538">"Privatsphäre-Dashboard"</string>
     <string name="auto_permission_usage_summary" msgid="7335667266743337075">"Ansehen, welche Apps zuletzt Berechtigungen genutzt haben"</string>
     <string name="permission_group_usage_title" msgid="2595013198075285173">"<xliff:g id="PERMGROUP">%1$s</xliff:g>-Nutzung"</string>
     <string name="perm_usage_adv_info_title" msgid="3357831829538873708">"Andere Berechtigungen ansehen"</string>
@@ -254,7 +254,7 @@
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"Abgelehnt/Kein Zugriff auf diese Berechtigung"</string>
     <string name="allowed_header" msgid="7769277978004790414">"Zugelassen"</string>
     <string name="allowed_always_header" msgid="6455903312589013545">"Immer zugelassen"</string>
-    <string name="allowed_foreground_header" msgid="6845655788447833353">"Nur während Nutzung zugelassen"</string>
+    <string name="allowed_foreground_header" msgid="6845655788447833353">"Nur während der Nutzung zugelassen"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"Zugriff nur auf Mediendateien zugelassen"</string>
     <string name="allowed_storage_full" msgid="5356699280625693530">"Verwalten aller Dateien zugelassen"</string>
     <string name="ask_header" msgid="2633816846459944376">"Jedes Mal fragen"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Standard-App digit. Assistent"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App für digitalen Assistenten"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assistent-Apps können dir bei bestimmten Dingen helfen. Dazu greifen sie auf die Informationen zu, die aktuell auf deinem Bildschirm angezeigt werden. Einige Apps unterstützen sowohl Launcher- als auch Spracheingabedienste."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Empfohlen von <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Standard-Browser-App"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser-App"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps, mit denen du auf das Internet zugreifen kannst und die die entsprechende Seite öffnen, wenn du auf einen Link tippst"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Links öffnen"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Standard-Apps für Arbeit"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Standard-Apps für das vertrauliche Profil"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Für dein Gerät optimiert"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Sonstige"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Keine"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System-Stan­dard­einstellung)"</string>
@@ -531,11 +531,11 @@
     <string name="permgrouprequest_device_aware_calllog" msgid="8220927190376843309">"Darf &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; auf deine Anrufliste zugreifen?"</string>
     <string name="permgrouprequest_phone" msgid="1829234136997316752">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; erlauben, Anrufe zu starten und zu verwalten?"</string>
     <string name="permgrouprequest_device_aware_phone" msgid="590399263670349955">"Darf &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; Anrufe tätigen und verwalten?"</string>
-    <string name="permgrouprequest_sensors" msgid="4397358316850652235">"Darf &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; Sensor­daten zu deinen Vitalfunktionen abrufen?"</string>
-    <string name="permgrouprequest_device_aware_sensors" msgid="3874451050573615157">"Darf &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; auf Sensordaten zu deinen Vitalzeichen zugreifen?"</string>
+    <string name="permgrouprequest_sensors" msgid="4397358316850652235">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; erlauben, Sensor­daten zu deinen Vitalfunktionen abzurufen?"</string>
+    <string name="permgrouprequest_device_aware_sensors" msgid="3874451050573615157">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; erlauben, auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; auf Sensordaten zu deinen Vitalzeichen zuzugreifen?"</string>
     <string name="permgroupupgraderequestdetail_sensors" msgid="6651914048792092835">"Die App möchte jederzeit auf die Sensordaten zu deinen Vitalfunktionen zugreifen, auch wenn du sie nicht verwendest. Du kannst das "<annotation id="link">"in den Einstellungen ändern"</annotation>"."</string>
     <string name="permgroupbackgroundrequest_sensors" msgid="5661924322018503886">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; erlauben, auf Sensordaten zu deinen Vitalfunktionen zuzugreifen?"</string>
-    <string name="permgroupbackgroundrequest_device_aware_sensors" msgid="3687673359121603824">"Darf &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; auf die Sensordaten zu deinen Vitalzeichen zugreifen?"</string>
+    <string name="permgroupbackgroundrequest_device_aware_sensors" msgid="3687673359121603824">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; erlauben, auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; auf die Sensordaten zu deinen Vitalzeichen zuzugreifen?"</string>
     <string name="permgroupbackgroundrequestdetail_sensors" msgid="7726767635834043501">"Damit diese App dauerhaft auf Daten des Körpersensors zugreifen kann, auch dann, wenn sie nicht verwendet wird, "<annotation id="link">"rufe die Einstellungen auf"</annotation>"."</string>
     <string name="permgroupupgraderequest_sensors" msgid="7576527638411370468">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; Zugriff auf Körpersensordaten bei Verwendung weiter erlauben?"</string>
     <string name="permgroupupgraderequest_device_aware_sensors" msgid="5542771499929819675">"Darf die App &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; auf deinem Gerät &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; weiterhin auf deine Körpersensordaten zugreifen, während die App genutzt wird?"</string>
diff --git a/PermissionController/res/values-el-v36/strings.xml b/PermissionController/res/values-el-v36/strings.xml
new file mode 100644
index 0000000000..d1cdc19b22
--- /dev/null
+++ b/PermissionController/res/values-el-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Έλεγχος άλλων εφαρμογών από τον εκπρόσωπο"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Εκτέλεση ενεργειών στη συσκευή σας και σε άλλες εφαρμογές"</string>
+</resources>
diff --git a/PermissionController/res/values-el/strings.xml b/PermissionController/res/values-el/strings.xml
index b066c75cad..8cf9c21162 100644
--- a/PermissionController/res/values-el/strings.xml
+++ b/PermissionController/res/values-el/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Προεπ. εφαρμ. ψηφιακού βοηθού"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Εφαρμογή ψηφιακού βοηθού"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Οι εφαρμογές υποβοήθειας σάς προσφέρουν βοήθεια βάσει των πληροφοριών από την οθόνη που προβάλετε. Ορισμένες εφαρμογές υποστηρίζουν τόσο την εφαρμογή εκκίνησης όσο και τις υπηρεσίες εισόδου φωνής για να λαμβάνετε ολοκληρωμένη βοήθεια."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Προτείνεται από: <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Προεπιλ. πρόγρ. περιήγησης"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Πρόγραμμα περιήγησης"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Εφαρμογές που σας προσφέρουν πρόσβαση στο διαδίκτυο και εμφανίζουν τους συνδέσμους που πατάτε"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Άνοιγμα συνδέσμων"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Προεπιλογή για εργασία"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Προεπιλογή για ιδιωτικό χώρο"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Βελτιστοποιημένες για τη συσκευή"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Άλλες"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Καμία"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Προεπιλογή συστήματος)"</string>
@@ -478,7 +478,7 @@
     <string name="permgrouprequest_location" msgid="6990232580121067883">"Να επιτρέπεται στην εφαρμογή &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; η πρόσβαση στην τοποθεσία αυτής της συσκευής;"</string>
     <string name="permgrouprequest_device_aware_location" msgid="6075412127429878638">"Να επιτρέπεται στην εφαρμογή &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; η πρόσβαση στην τοποθεσία της συσκευής &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>’s&lt;/b&gt;;"</string>
     <string name="permgrouprequestdetail_location" msgid="2635935335778429894">"Η εφαρμογή θα έχει πρόσβαση στην τοποθεσία μόνο κατά τη διάρκεια χρήσης της εφαρμογής"</string>
-    <string name="permgroupbackgroundrequest_location" msgid="1085680897265734809">"Να επιτρέπεται στο &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; να έχει πρόσβαση στην τοποθεσία αυτής της συσκευής;"</string>
+    <string name="permgroupbackgroundrequest_location" msgid="1085680897265734809">"Να επιτρέπεται στην εφαρμογή &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; η πρόσβαση στην τοποθεσία αυτής της συσκευής;"</string>
     <string name="permgroupbackgroundrequest_device_aware_location" msgid="1264484517831380016">"Να επιτρέπεται στην εφαρμογή &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; η πρόσβαση στην τοποθεσία της συσκευής &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>’s&lt;/b&gt;;"</string>
     <string name="permgroupbackgroundrequestdetail_location" msgid="8021219324989662957">"Αυτή η εφαρμογή θέλει να έχει συνεχώς πρόσβαση στην τοποθεσία σας, ακόμη και όταν δεν χρησιμοποιείτε την εφαρμογή. "<annotation id="link">"Εγκρίνετε το αίτημα στις ρυθμίσεις."</annotation></string>
     <string name="permgroupupgraderequest_location" msgid="8328408946822691636">"Αλλαγή πρόσβασης στην τοποθεσία για την εφαρμογή &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;;"</string>
diff --git a/PermissionController/res/values-en-rAU-v36/strings.xml b/PermissionController/res/values-en-rAU-v36/strings.xml
new file mode 100644
index 0000000000..83abd0232e
--- /dev/null
+++ b/PermissionController/res/values-en-rAU-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Perform actions on your device and in other apps"</string>
+</resources>
diff --git a/PermissionController/res/values-en-rAU/strings.xml b/PermissionController/res/values-en-rAU/strings.xml
index 0ec4ed4f23..a759322a93 100644
--- a/PermissionController/res/values-en-rAU/strings.xml
+++ b/PermissionController/res/values-en-rAU/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Default digital assistant app"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistant app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assist apps can help you based on information from the screen that you’re viewing. Some apps support both Launcher and voice input services to give you integrated assistance."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recommended by <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Default browser app"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser app"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps that give you access to the Internet and display links that you tap"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Opening links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Default for work"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Default for private space"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimised for device"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Others"</string>
     <string name="default_app_none" msgid="9084592086808194457">"None"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System default)"</string>
diff --git a/PermissionController/res/values-en-rCA-v36/strings.xml b/PermissionController/res/values-en-rCA-v36/strings.xml
new file mode 100644
index 0000000000..83abd0232e
--- /dev/null
+++ b/PermissionController/res/values-en-rCA-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Perform actions on your device and in other apps"</string>
+</resources>
diff --git a/PermissionController/res/values-en-rCA/strings.xml b/PermissionController/res/values-en-rCA/strings.xml
index c6f8464a36..3cdbd28d9c 100644
--- a/PermissionController/res/values-en-rCA/strings.xml
+++ b/PermissionController/res/values-en-rCA/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Default digital assistant app"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistant app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assist apps can help you based on information from the screen you’re viewing. Some apps support both launcher and voice input services to give you integrated assistance."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recommended by <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Default browser app"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser app"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps that give you access to the internet and display links that you tap"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Opening links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Default for work"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Default for private space"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimized for device"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Others"</string>
     <string name="default_app_none" msgid="9084592086808194457">"None"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System default)"</string>
diff --git a/PermissionController/res/values-en-rGB-v36/strings.xml b/PermissionController/res/values-en-rGB-v36/strings.xml
new file mode 100644
index 0000000000..83abd0232e
--- /dev/null
+++ b/PermissionController/res/values-en-rGB-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Perform actions on your device and in other apps"</string>
+</resources>
diff --git a/PermissionController/res/values-en-rGB/strings.xml b/PermissionController/res/values-en-rGB/strings.xml
index 44a195ef99..55bdb2ff05 100644
--- a/PermissionController/res/values-en-rGB/strings.xml
+++ b/PermissionController/res/values-en-rGB/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Default digital assistant app"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistant app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assist apps can help you based on information from the screen that you’re viewing. Some apps support both Launcher and voice input services to give you integrated assistance."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recommended by <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Default browser app"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser app"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps that give you access to the Internet and display links that you tap"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Opening links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Default for work"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Default for private space"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimised for device"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Others"</string>
     <string name="default_app_none" msgid="9084592086808194457">"None"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System default)"</string>
diff --git a/PermissionController/res/values-en-rIN-v36/strings.xml b/PermissionController/res/values-en-rIN-v36/strings.xml
new file mode 100644
index 0000000000..83abd0232e
--- /dev/null
+++ b/PermissionController/res/values-en-rIN-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Perform actions on your device and in other apps"</string>
+</resources>
diff --git a/PermissionController/res/values-en-rIN/strings.xml b/PermissionController/res/values-en-rIN/strings.xml
index 44a195ef99..55bdb2ff05 100644
--- a/PermissionController/res/values-en-rIN/strings.xml
+++ b/PermissionController/res/values-en-rIN/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Default digital assistant app"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistant app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assist apps can help you based on information from the screen that you’re viewing. Some apps support both Launcher and voice input services to give you integrated assistance."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recommended by <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Default browser app"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser app"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps that give you access to the Internet and display links that you tap"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Opening links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Default for work"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Default for private space"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimised for device"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Others"</string>
     <string name="default_app_none" msgid="9084592086808194457">"None"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System default)"</string>
diff --git a/PermissionController/res/values-es-rUS-v33/strings.xml b/PermissionController/res/values-es-rUS-v33/strings.xml
index 52b8b9497f..ba49e3c3ab 100644
--- a/PermissionController/res/values-es-rUS-v33/strings.xml
+++ b/PermissionController/res/values-es-rUS-v33/strings.xml
@@ -19,7 +19,7 @@
     <string name="role_dialer_request_description" msgid="6188305064871543419">"Esta app podrá enviarte notificaciones y obtendrá acceso tus contactos, cámara, micrófono, teléfono y SMS"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"Esta app podrá enviarte notificaciones y obtendrá acceso tus contactos, cámara, archivos, micrófono, teléfono y SMS"</string>
     <string name="permission_description_summary_storage" msgid="1917071243213043858">"Las apps con este permiso pueden acceder a todos los archivos en este dispositivo"</string>
-    <string name="work_policy_title" msgid="832967780713677409">"Información sobre la política de tu trabajo"</string>
+    <string name="work_policy_title" msgid="832967780713677409">"Información sobre las políticas de trabajo"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"Configuración gestionada por tu administrador de TI"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"Expandir y mostrar lista"</string>
     <string name="safety_center_entry_group_collapse_action" msgid="1525710152244405656">"Contraer lista y ocultar configuración"</string>
diff --git a/PermissionController/res/values-es-rUS-v36/strings.xml b/PermissionController/res/values-es-rUS-v36/strings.xml
new file mode 100644
index 0000000000..c892c57843
--- /dev/null
+++ b/PermissionController/res/values-es-rUS-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Control del agente de otras apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Realiza acciones en tu dispositivo y en otras apps"</string>
+</resources>
diff --git a/PermissionController/res/values-es-rUS/strings.xml b/PermissionController/res/values-es-rUS/strings.xml
index 2ab11d016c..dd3bbaa2cd 100644
--- a/PermissionController/res/values-es-rUS/strings.xml
+++ b/PermissionController/res/values-es-rUS/strings.xml
@@ -348,7 +348,7 @@
     <string name="no_apps_allowed" msgid="7718822655254468631">"No se le otorgó permiso a ninguna app"</string>
     <string name="no_apps_allowed_full" msgid="8011716991498934104">"Ninguna app tiene el permiso para todos los archivos"</string>
     <string name="no_apps_allowed_scoped" msgid="4908850477787659501">"Ninguna app tiene el permiso solo para contenido multimedia"</string>
-    <string name="no_apps_denied" msgid="7663435886986784743">"No hay apps rechazadas"</string>
+    <string name="no_apps_denied" msgid="7663435886986784743">"No se le rechazó el permiso a ninguna app"</string>
     <string name="car_permission_selected" msgid="180837028920791596">"Seleccionado"</string>
     <string name="settings" msgid="5409109923158713323">"Configuración"</string>
     <string name="accessibility_service_dialog_title_single" msgid="7956432823014102366">"<xliff:g id="SERVICE_NAME">%s</xliff:g> tiene acceso completo a tu dispositivo"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"App de asistente digital predeterminada"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App de asistente digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Las aplicaciones de asistencia pueden brindarte ayuda en función de la pantalla que estás viendo. Para ofrecerte asistencia integrada, algunas aplicaciones son compatibles con los servicios de selector y entrada de voz."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomendadas por <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Navegador predeterminado"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"App de navegador"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps que te permiten acceder a Internet y ver los vínculos que presionas"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Abrir vínculos"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predeterminadas de trabajo"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Configuración predeterminada del espacio privado"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizadas para el dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Otras"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ninguna"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Predeterminada del sistema)"</string>
@@ -503,14 +503,14 @@
     <string name="permgrouprequest_storage_pre_q" msgid="168130651144569428">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a &lt;b&gt;fotos, videos, música, audio y otros archivos&lt;/b&gt; del dispositivo?"</string>
     <string name="permgrouprequest_read_media_aural" msgid="2593365397347577812">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a la música y los archivos de audio de este dispositivo?"</string>
     <string name="permgrouprequest_device_aware_read_media_aural" msgid="7927884506238101064">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a la música y al audio en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
-    <string name="permgrouprequest_read_media_visual" msgid="5548780620779729975">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a las fotos y los videos de este dispositivo?"</string>
+    <string name="permgrouprequest_read_media_visual" msgid="5548780620779729975">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a las fotos y los videos de este dispositivo?"</string>
     <string name="permgrouprequest_device_aware_read_media_visual" msgid="3122576538319059333">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a fotos y videos en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequest_more_photos" msgid="128933814654231321">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a más fotos y videos del dispositivo?"</string>
     <string name="permgrouprequest_device_aware_more_photos" msgid="1703469013613723053">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a más fotos y videos en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequest_microphone" msgid="2825208549114811299">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; grabe audio?"</string>
     <string name="permgrouprequest_device_aware_microphone" msgid="8821701550505437951">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; grabe audio en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequestdetail_microphone" msgid="8510456971528228861">"La app solo podrá grabar audio cuando esté en uso"</string>
-    <string name="permgroupbackgroundrequest_microphone" msgid="8874462606796368183">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; grabe audio?"</string>
+    <string name="permgroupbackgroundrequest_microphone" msgid="8874462606796368183">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; grabe audio?"</string>
     <string name="permgroupbackgroundrequest_device_aware_microphone" msgid="3321823187623762958">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; grabe audio en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgroupbackgroundrequestdetail_microphone" msgid="553702902263681838">"Es posible que esta app quiera grabar audio todo el tiempo, incluso cuando no la estés usando. "<annotation id="link">"Permite el acceso en Configuración."</annotation></string>
     <string name="permgroupupgraderequest_microphone" msgid="1362781696161233341">"¿Cambiar el acceso al micrófono de &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;?"</string>
@@ -518,7 +518,7 @@
     <string name="permgroupupgraderequestdetail_microphone" msgid="2870497719571464239">"Esta app quiere grabar audio todo el tiempo, incluso cuando no la uses. "<annotation id="link">"Permite el acceso en Configuración."</annotation></string>
     <string name="permgrouprequest_activityRecognition" msgid="5415121592794230330">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a tu actividad física?"</string>
     <string name="permgrouprequest_device_aware_activityRecognition" msgid="1243869530588745374">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; acceda a tu actividad física en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
-    <string name="permgrouprequest_camera" msgid="5123097035410002594">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; tome fotos y grabe videos?"</string>
+    <string name="permgrouprequest_camera" msgid="5123097035410002594">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; tome fotos y grabe videos?"</string>
     <string name="permgrouprequest_device_aware_camera" msgid="5340173564041615494">"¿Quieres permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; tome fotos y grabe videos en &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequestdetail_camera" msgid="9085323239764667883">"La app solo podrá tomar fotos y grabar videos cuando esté en uso"</string>
     <string name="permgroupbackgroundrequest_camera" msgid="1274286575704213875">"¿Permitir que &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; tome fotos y grabe videos?"</string>
@@ -659,11 +659,11 @@
     <string name="app_permission_rationale_message" msgid="8511466916077100713">"Seguridad de los datos"</string>
     <string name="app_location_permission_rationale_title" msgid="925420340572401350">"Es posible que se compartan los datos de ubicación"</string>
     <string name="app_location_permission_rationale_subtitle" msgid="6986985722752868692">"Esta app indicó que podría compartir tus datos de ubicación con terceros"</string>
-    <string name="data_sharing_updates_title" msgid="7996933386875213859">"Actualizaciones del uso compartido de los datos de ubicación"</string>
+    <string name="data_sharing_updates_title" msgid="7996933386875213859">"Actualizaciones de los datos compartidos de ubicación"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"Revisa las apps que cambiaron la forma en que comparten tus datos de ubicación"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Estas apps cambiaron la forma en que podrían compartir tus datos de ubicación. Es posible que no los hayan compartido antes o que ahora los compartan con fines publicitarios o de marketing."</string>
-    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Los desarrolladores de estas apps brindaron información sobre sus prácticas de uso compartido de datos a una tienda de aplicaciones. Podrían actualizarla con el tiempo.\n\nLas prácticas de uso compartido de datos pueden variar según la versión de la app, el uso, la región y la edad."</string>
-    <string name="learn_about_data_sharing" msgid="4200480587079488045">"Más información sobre el uso compartido de datos"</string>
+    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Los desarrolladores de estas apps brindaron información a una tienda de aplicaciones sobre sus formas de compartir datos. Podrían actualizarla con el tiempo.\n\nLas formas de compartir datos pueden variar según la versión de la app, el uso, la región y la edad."</string>
+    <string name="learn_about_data_sharing" msgid="4200480587079488045">"Más información sobre cómo se comparten los datos"</string>
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"Tus datos de ubicación ahora se comparten con terceros"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"Tus datos de ubicación ahora se comparten con terceros para publicidad o marketing"</string>
     <string name="updated_in_last_days" msgid="8371811947153042322">"{count,plural, =0{Se actualizó en el último día}=1{Se actualizó en el último día}many{Se actualizó hace # de días}other{Se actualizó hace # días}}"</string>
diff --git a/PermissionController/res/values-es-v36/strings.xml b/PermissionController/res/values-es-v36/strings.xml
new file mode 100644
index 0000000000..301c4e9292
--- /dev/null
+++ b/PermissionController/res/values-es-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Control de agentes de otras aplicaciones"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Realiza acciones en el dispositivo y en otras aplicaciones"</string>
+</resources>
diff --git a/PermissionController/res/values-es/strings.xml b/PermissionController/res/values-es/strings.xml
index 6ec8bb7b12..d53183d986 100644
--- a/PermissionController/res/values-es/strings.xml
+++ b/PermissionController/res/values-es/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Aplicación de asistente digital predeterminada"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplicación de asistente digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Las aplicaciones de asistencia te ayudan a partir de la información que aparezca en la pantalla. Algunas aplicaciones admiten tanto el menú de aplicaciones como los servicios de entrada de voz para ofrecerte asistencia integrada."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomendación de <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Aplicación de navegador predeterminada"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplicación de navegador"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Son las aplicaciones que te permiten acceder a Internet y abren los enlaces que tocas"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Abrir enlaces"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predeterminadas para trabajo"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Predeterminadas para el espacio privado"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizadas para el dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Otras"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ninguna"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Predeterminado del sistema)"</string>
diff --git a/PermissionController/res/values-et-v33/strings.xml b/PermissionController/res/values-et-v33/strings.xml
index 56dd683cad..2905a31404 100644
--- a/PermissionController/res/values-et-v33/strings.xml
+++ b/PermissionController/res/values-et-v33/strings.xml
@@ -19,7 +19,7 @@
     <string name="role_dialer_request_description" msgid="6188305064871543419">"Sellel rakendusel lubatakse teile märguandeid saata ja sellele antakse juurdepääs teie kaamerale, kontaktidele, mikrofonile, telefonile ja SMS-idele"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"Sellel rakendusel lubatakse teile märguandeid saata ja sellele antakse juurdepääs teie kaamerale, kontaktidele, failidele, mikrofonile, telefonile ja SMS-idele"</string>
     <string name="permission_description_summary_storage" msgid="1917071243213043858">"Selle loaga rakendused pääsevad selles seadmes juurde kõikidele failidele"</string>
-    <string name="work_policy_title" msgid="832967780713677409">"Teie tööeeskirjade teave"</string>
+    <string name="work_policy_title" msgid="832967780713677409">"Teie tööreeglite teave"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"Seadeid haldab teie IT-administraator"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"Laienda ja kuva loend"</string>
     <string name="safety_center_entry_group_collapse_action" msgid="1525710152244405656">"Ahenda loend ja peida seaded"</string>
diff --git a/PermissionController/res/values-et-v36/strings.xml b/PermissionController/res/values-et-v36/strings.xml
new file mode 100644
index 0000000000..b22fb97210
--- /dev/null
+++ b/PermissionController/res/values-et-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agendi kontroll teiste rakenduste üle"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Tehke toiminguid oma seadmes ja teistes rakendustes"</string>
+</resources>
diff --git a/PermissionController/res/values-et/strings.xml b/PermissionController/res/values-et/strings.xml
index a8f8fb6dde..ab447c8232 100644
--- a/PermissionController/res/values-et/strings.xml
+++ b/PermissionController/res/values-et/strings.xml
@@ -235,15 +235,15 @@
     <string name="special_file_access_dialog" msgid="583804114020740610">"Kas lubada sellel rakendusel selle seadme või ühendatud salvestusseadme ühises salvestusruumis juurde pääseda mis tahes failidele ning neid muuta ja kustutada? See rakendus võib failidele juurde pääseda teilt luba küsimata."</string>
     <string name="permission_description_summary_generic" msgid="5401399408814903391">"Selle loaga rakendused saavad teha järgmist: <xliff:g id="DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="permission_description_summary_activity_recognition" msgid="2652850576497070146">"Selle loaga rakendused pääsevad juurde teie füüsilise tegevuse andmetele (nt kõndimise, ratta- ja autosõidu andmed, sammuloendur ning muud)"</string>
-    <string name="permission_description_summary_calendar" msgid="103329982944411010">"Selle loaga rakendustel on juurdepääs teie kalendrile"</string>
+    <string name="permission_description_summary_calendar" msgid="103329982944411010">"Selle loaga rakendustel on juurdepääs teie kalendrile."</string>
     <string name="permission_description_summary_call_log" msgid="7321437186317577624">"Selle loaga rakendused saavad telefoni kõnelogi lugeda ja sellesse kirjutada"</string>
     <string name="permission_description_summary_camera" msgid="108004375101882069">"Selle loaga rakendused saavad jäädvustada pilte ja videoid"</string>
-    <string name="permission_description_summary_contacts" msgid="2337798886460408996">"Selle loaga rakendustel on juurdepääs teie kontaktidele"</string>
-    <string name="permission_description_summary_location" msgid="2817531799933480694">"Selle loaga rakendustel on juurdepääs seadme asukohateabele"</string>
+    <string name="permission_description_summary_contacts" msgid="2337798886460408996">"Selle loaga rakendustel on juurdepääs teie kontaktidele."</string>
+    <string name="permission_description_summary_location" msgid="2817531799933480694">"Selle loaga rakendustel on juurdepääs seadme asukohateabele."</string>
     <string name="permission_description_summary_nearby_devices" msgid="8269183818275073741">"Selle loaga rakendused saavad leida lähedalasuvaid seadmeid, luua nendega ühenduse ja määrata nende suhtelise asukoha"</string>
     <string name="permission_description_summary_microphone" msgid="630834800308329907">"Selle loaga rakendused võivad heli salvestada"</string>
     <string name="permission_description_summary_phone" msgid="4515277217435233619">"Selle loaga rakendused saavad telefonikõnesid teha ja hallata"</string>
-    <string name="permission_description_summary_sensors" msgid="1836045815643119949">"Selle loaga rakendustel on juurdepääs teie eluliste näitajate andurite andmetele"</string>
+    <string name="permission_description_summary_sensors" msgid="1836045815643119949">"Selle loaga rakendustel on juurdepääs teie eluliste näitajate andurite andmetele."</string>
     <string name="permission_description_summary_sms" msgid="725999468547768517">"Selle loaga rakendused saavad SMS-sõnumeid saata ja vaadata"</string>
     <string name="permission_description_summary_storage" msgid="6575759089065303346">"Selle loaga rakendused pääsevad teie seadmes juurde fotodele, meediale ja failidele"</string>
     <string name="permission_description_summary_read_media_aural" msgid="3354728149930482199">"Selle loaga rakendused pääsevad selles seadmes juurde muusikale ja muudele helifailidele"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Digitaalse assistendi vaikerakendus"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitaalse assistendi rakendus"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Abirakendused saavad aidata teid kuvatud ekraaniteabe alusel. Mõned rakendused toetavad integreeritud abi pakkumisel nii käivitusprogrammi kui ka häälsisendi teenuseid."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> soovitab"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Brauseri vaikerakendus"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Brauserirakendus"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Rakendused, mis võimaldavad juurdepääsu internetile ja kuvavad puudutatavaid linke"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Linkide avamine"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Vaikerakendused töö jaoks"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Privaatse ruumi vaikerakendused"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Seadme jaoks optimeeritud"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Muud"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Puudub"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Süsteemi vaikeseade)"</string>
@@ -489,7 +489,7 @@
     <string name="permgroupupgraderequestdetail_nearby_devices" msgid="6877531270654738614">"Kas lubada rakendusel &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; leida lähedalasuvaid seadmeid, nendega ühendada ja nende suhteline asukoht määrata? "<annotation id="link">"Lubage menüüs Seaded."</annotation></string>
     <string name="permgrouprequest_fineupgrade" msgid="2334242928821697672">"Kas muuta rakenduse <xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g> asukohale juurdepääsemise tase ligikaudsest täpseks?"</string>
     <string name="permgrouprequest_device_aware_fineupgrade" msgid="4453775952305587571">"Kas muuta rakenduse <xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g> juurdepääs asukohateabele seadmes &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; ligikaudsest täpseks?"</string>
-    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"Kas lubada rakendusele &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; juurdepääs selle seadme ligikaudsele asukohale?"</string>
+    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"Kas lubada rakendusel &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; pääseda juurde selle seadme ligikaudsele asukohale?"</string>
     <string name="permgrouprequest_device_aware_coarselocation" msgid="8367540370912066757">"Kas lubada rakendusele &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; juurdepääs seadme &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; ligikaudsele asukohale?"</string>
     <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"Täpne"</string>
     <string name="permgrouprequest_coarselocation_imagetext" msgid="8650605041483025297">"Ligikaudne"</string>
diff --git a/PermissionController/res/values-eu-v36/strings.xml b/PermissionController/res/values-eu-v36/strings.xml
new file mode 100644
index 0000000000..2ea27aa5da
--- /dev/null
+++ b/PermissionController/res/values-eu-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agenteak beste aplikazioak kontrolatzen ditu"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Gauzatu ekintzak gailuan eta beste aplikazio batzuetan"</string>
+</resources>
diff --git a/PermissionController/res/values-eu/strings.xml b/PermissionController/res/values-eu/strings.xml
index e5e3416498..f8bae257cd 100644
--- a/PermissionController/res/values-eu/strings.xml
+++ b/PermissionController/res/values-eu/strings.xml
@@ -196,7 +196,7 @@
     <string name="precise_image_description" msgid="6349638632303619872">"Kokapen zehatza"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"Gutxi gorabeherako kokapena"</string>
     <string name="app_permission_location_accuracy" msgid="7166912915040018669">"Erabili kokapen zehatza"</string>
-    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"Kokapen zehatza desaktibatuta dagoenean, aplikazioek gutxi gorabeherako kokapena atzi dezakete"</string>
+    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"Kokapen zehatza desaktibatuta dagoenean, aplikazioek gutxi gorabeherako kokapena erabil dezakete"</string>
     <string name="app_permission_title" msgid="2090897901051370711">"\"<xliff:g id="PERM">%1$s</xliff:g>\" baimena"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"Aplikazio honek \"<xliff:g id="PERM">%1$s</xliff:g>\" erabiltzeko duen baimena"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"<xliff:g id="PERM">%1$s</xliff:g> erabiltzeko baimena aplikazio honetarako <xliff:g id="DEVICE_NAME">%2$s</xliff:g> gailuan"</string>
@@ -358,8 +358,9 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Laguntzaile digitalaren aplikazio lehenetsia"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Laguntzaile digitalaren aplikazioa"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Ikusten ari zaren pantailako informazioaren araberako laguntza eskain diezazukete laguntza-aplikazioek. Zenbait aplikaziok exekutatzeko tresna eta ahots bidezko zerbitzuak onartzen dituzte laguntza integratua eskaintzeko."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> fabrikatzaileak gomendatua"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Arakatzaile lehenetsia"</string>
-    <string name="role_browser_short_label" msgid="6745009127123292296">"Arakatzaile-apliU+2060kazioa"</string>
+    <string name="role_browser_short_label" msgid="6745009127123292296">"Arakatzaile-apli⁠kazioa⁠⁠⁠⁠"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Interneteko sarbidea ematen dizuten eta sakatzen dituzun estekak bistaratzen dituzten aplikazioak"</string>
     <string name="role_browser_request_title" msgid="2895200507835937192">"<xliff:g id="APP_NAME">%1$s</xliff:g> ezarri nahi duzu arakatzaile lehenetsi gisa?"</string>
     <string name="role_browser_request_description" msgid="5888803407905985941">"Ez du behar baimenik"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Irekiko diren estekak"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Lanerako aplikazio lehenetsiak"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Eremu pribatuko aplikazio lehenetsiak"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Gailurako optimizatuta"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Beste batzuk"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Bat ere ez"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(sistemaren aplikazio lehenetsia)"</string>
diff --git a/PermissionController/res/values-fa-v36/strings.xml b/PermissionController/res/values-fa-v36/strings.xml
new file mode 100644
index 0000000000..02ece0d690
--- /dev/null
+++ b/PermissionController/res/values-fa-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"کنترل نماینده بر برنامه‌های دیگر"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"انجام کنش در دستگاهتان و در برنامه‌های دیگر"</string>
+</resources>
diff --git a/PermissionController/res/values-fa/strings.xml b/PermissionController/res/values-fa/strings.xml
index 40049f4a42..f8d7f29d38 100644
--- a/PermissionController/res/values-fa/strings.xml
+++ b/PermissionController/res/values-fa/strings.xml
@@ -39,7 +39,7 @@
     <string name="grant_dialog_button_allow_selected_photos" msgid="5497042471576153842">"انتخاب عکس و ویدیو"</string>
     <string name="grant_dialog_button_allow_more_selected_photos" msgid="5145657877588697709">"انتخاب موارد بیشتر"</string>
     <string name="grant_dialog_button_dont_select_more" msgid="6643552729129461268">"دیگر چیزی انتخاب نشود"</string>
-    <string name="grant_dialog_button_deny_anyway" msgid="7225905870668915151">"درهرصورت اجازه نیست"</string>
+    <string name="grant_dialog_button_deny_anyway" msgid="7225905870668915151">"به‌هرصورت اجازه ندادن"</string>
     <string name="grant_dialog_button_dismiss" msgid="1930399742250226393">"رد کردن"</string>
     <string name="current_permission_template" msgid="7452035392573329375">"<xliff:g id="CURRENT_PERMISSION_INDEX">%1$s</xliff:g> مجوز از <xliff:g id="PERMISSION_COUNT">%2$s</xliff:g> مجوز"</string>
     <string name="permission_warning_template" msgid="2247087781222679458">"‏به &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; این اجازه داده شود؟ <xliff:g id="ACTION">%2$s</xliff:g>"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"برنامه دستیار دیجیتال پیش‌فرض"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"برنامه دستیار دیجیتال"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"برنامه‌های همیار می‌توانند براساس اطلاعات موجود در صفحه‌ای که در آن هستید، کمکتان کنند. برخی برنامه‌ها از هر دو سرویس راه‌انداز و ورودی صوتی پشتیبانی می‌کنند تا کمک یکپارچه‌ای ارائه دهند."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"توصیه‌شده توسط <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"برنامه مرورگر پیش‌فرض"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"برنامه مرورگر"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"برنامه‌هایی که به شما دسترسی به اینترنت را می‌دهند و پیوندهایی را نشان می‌دهند که روی آن‌ها می‌زنید"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"باز کردن پیوندها"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"پیش‌فرض برای کار"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"برنامه‌های پیش‌فرض برای فضای خصوصی"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"بهینه‌سازی‌شده برای دستگاه"</string>
     <string name="default_app_others" msgid="7793029848126079876">"موارد دیگر"</string>
     <string name="default_app_none" msgid="9084592086808194457">"هیچ‌کدام"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(پیش‌فرض سیستم)"</string>
@@ -576,7 +576,7 @@
     <string name="safety_center_rescan_button" msgid="4517514567809409596">"اسکن کردن دستگاه"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"رد کردن"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"این هشدار رد شود؟"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"هرزمان خواستید تنظیمات ایمنی و حریم خصوصی را بازنگری کنید تا محافظت بیشتری اضافه کنید"</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"هرزمان خواستید تنظیمات ایمنی و حریم خصوصی را بازبینی کنید تا محافظت بیشتری اضافه کنید"</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"رد شدن"</string>
     <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"لغو"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"تنظیمات"</string>
diff --git a/PermissionController/res/values-fi-v36/strings.xml b/PermissionController/res/values-fi-v36/strings.xml
new file mode 100644
index 0000000000..af8cd9eba6
--- /dev/null
+++ b/PermissionController/res/values-fi-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agenttien hallinta muissa sovelluksissa"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Toimintojen suorittaminen laitteella ja muissa sovelluksissa"</string>
+</resources>
diff --git a/PermissionController/res/values-fi/strings.xml b/PermissionController/res/values-fi/strings.xml
index c721e7299a..97495416ae 100644
--- a/PermissionController/res/values-fi/strings.xml
+++ b/PermissionController/res/values-fi/strings.xml
@@ -345,10 +345,10 @@
     <string name="app_perms_content_provider_7d_all_files" msgid="7962416229708835558">"Käytetty 7 viime päivän aikana • Kaikki tiedostot"</string>
     <string name="no_permissions_allowed" msgid="6081976856354669209">"Käyttöoikeuksia ei ole myönnetty"</string>
     <string name="no_permissions_denied" msgid="8159923922804043282">"Ei myöntämättömiä lupia"</string>
-    <string name="no_apps_allowed" msgid="7718822655254468631">"Ei yksikään sovellus"</string>
+    <string name="no_apps_allowed" msgid="7718822655254468631">"Ei sovelluksia"</string>
     <string name="no_apps_allowed_full" msgid="8011716991498934104">"Ei sovelluksia, joilla on käyttöoikeudet kaikille tiedostoille"</string>
     <string name="no_apps_allowed_scoped" msgid="4908850477787659501">"Ei sovelluksia, joilla on käyttöoikeudet vain medialle"</string>
-    <string name="no_apps_denied" msgid="7663435886986784743">"Ei estettyjä sovelluksia"</string>
+    <string name="no_apps_denied" msgid="7663435886986784743">"Ei sovelluksia"</string>
     <string name="car_permission_selected" msgid="180837028920791596">"Valittu"</string>
     <string name="settings" msgid="5409109923158713323">"Asetukset"</string>
     <string name="accessibility_service_dialog_title_single" msgid="7956432823014102366">"<xliff:g id="SERVICE_NAME">%s</xliff:g> on saanut laitteen täydet käyttöoikeudet"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Oletusdigiavustajasovellus"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digiavustajasovellus"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Avustajasovellukset voivat auttaa sinua näytöllä näkyvien tietojen perusteella. Jotkin sovellukset tukevat myös käynnistysohjelma- ja äänisyötepalveluja, joten ne voivat tarjota sinulle integroitua apua."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> suosittelee"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Oletusselainsovellus"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Selainsovellus"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Sovellukset, joiden avulla voit käyttää internetiä ja jotka näyttävät napauttamasi linkit"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Linkkien avaaminen"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Työkäytön oletus"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Oletus yksityiselle tilalle"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimoitu laitteelle"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Muut"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ei mitään"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Järjestelmän oletusarvo)"</string>
diff --git a/PermissionController/res/values-fr-rCA-v36/strings.xml b/PermissionController/res/values-fr-rCA-v36/strings.xml
new file mode 100644
index 0000000000..410cc68e2b
--- /dev/null
+++ b/PermissionController/res/values-fr-rCA-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Contrôle de l\'agent sur d\'autres applis"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Effectuez des actions sur votre appareil et dans d\'autres applis"</string>
+</resources>
diff --git a/PermissionController/res/values-fr-rCA/strings.xml b/PermissionController/res/values-fr-rCA/strings.xml
index 7bde3d4c42..ffad879759 100644
--- a/PermissionController/res/values-fr-rCA/strings.xml
+++ b/PermissionController/res/values-fr-rCA/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Assistant numérique par défaut"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Appli d\'assistant numérique"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Les applis d\'assistance peuvent se servir des informations à l\'écran pour vous aider. Certaines applis sont compatibles à la fois avec le lanceur d\'applis et les services d\'entrée vocale pour vous offrir une assistance intégrée."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recommandées par <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Appli de navigation par défaut"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Appli de navigation"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Applis qui vous donnent accès à Internet et qui affichent des liens que vous pouvez toucher"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Ouverture des liens"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Par défaut pour util. profess."</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Applis par défaut pour l\'Espace privé"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimisée pour l\'appareil"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Autres"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Aucune"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Paramètre(s) système par défaut)"</string>
@@ -659,7 +659,7 @@
     <string name="app_permission_rationale_message" msgid="8511466916077100713">"Sécurité des données"</string>
     <string name="app_location_permission_rationale_title" msgid="925420340572401350">"Les données de localisation peuvent être partagées"</string>
     <string name="app_location_permission_rationale_subtitle" msgid="6986985722752868692">"Cette appli indique qu\'elle peut partager vos données de localisation avec des tiers"</string>
-    <string name="data_sharing_updates_title" msgid="7996933386875213859">"Mises à jour des pratiques de partage des données pour la localisation"</string>
+    <string name="data_sharing_updates_title" msgid="7996933386875213859">"Mises à jour du partage des données pour la localisation"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"Passez en revue les applis qui ont changé la façon dont elles peuvent partager vos données de localisation"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Ces applis ont modifié la façon dont elles peuvent partager vos données de localisation. Elles peuvent ne pas les avoir partagées auparavant, ou peuvent maintenant les partager à des fins d\'annonces ou de marketing."</string>
     <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Les développeurs de ces applis ont fourni des renseignements sur leurs pratiques de partage des données à une boutique d\'applis. Ils peuvent les mettre à jour au fil du temps.\n\nLes pratiques de partage des données peuvent varier en fonction de la version de votre appli, de son utilisation, de votre région et de votre âge."</string>
diff --git a/PermissionController/res/values-fr-v34/strings.xml b/PermissionController/res/values-fr-v34/strings.xml
index bfd957bcb0..5804b72250 100644
--- a/PermissionController/res/values-fr-v34/strings.xml
+++ b/PermissionController/res/values-fr-v34/strings.xml
@@ -20,7 +20,7 @@
     <string name="security_privacy_brand_name" msgid="7303621734258440812">"Sécurité et confidentialité"</string>
     <string name="privacy_subpage_controls_header" msgid="4152396976713749322">"Commandes"</string>
     <string name="health_connect_title" msgid="2132233890867430855">"Santé Connect"</string>
-    <string name="health_connect_summary" msgid="815473513776882296">"Gérer l\'accès de l\'appli aux données de santé"</string>
+    <string name="health_connect_summary" msgid="815473513776882296">"Gérer l\'accès des applis aux données de santé"</string>
     <string name="location_settings" msgid="8863940440881290182">"Accès à la position"</string>
-    <string name="mic_toggle_description" msgid="1504101620086616040">"Pour les applis et services. Si ce paramètre est désactivé, il est possible que les données du micro soient quand même partagées quand vous appelez un numéro d\'urgence"</string>
+    <string name="mic_toggle_description" msgid="1504101620086616040">"Pour les applis et services. Si ce paramètre est désactivé, il est possible que les données du micro soient quand même partagées quand vous appelez un numéro d\'urgence."</string>
 </resources>
diff --git a/PermissionController/res/values-fr-v36/strings.xml b/PermissionController/res/values-fr-v36/strings.xml
new file mode 100644
index 0000000000..acca0511ab
--- /dev/null
+++ b/PermissionController/res/values-fr-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Contrôle de l\'agent d\'autres applications"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Effectuez des actions sur votre appareil et dans d\'autres applis"</string>
+</resources>
diff --git a/PermissionController/res/values-fr/strings.xml b/PermissionController/res/values-fr/strings.xml
index 781f50a3d2..ee484814f4 100644
--- a/PermissionController/res/values-fr/strings.xml
+++ b/PermissionController/res/values-fr/strings.xml
@@ -188,7 +188,7 @@
     <string name="app_permission_button_allow_all_files" msgid="1792232272599018825">"Autoriser la gestion de tous les fichiers"</string>
     <string name="app_permission_button_allow_media_only" msgid="2834282724426046154">"Autoriser l\'accès aux fichiers multimédias uniquement"</string>
     <string name="app_permission_button_allow_always" msgid="4573292371734011171">"Toujours autoriser"</string>
-    <string name="app_permission_button_allow_foreground" msgid="1991570451498943207">"Autoriser seulement si l\'appli est utilisée"</string>
+    <string name="app_permission_button_allow_foreground" msgid="1991570451498943207">"Autoriser seulement lorsque l\'appli est utilisée"</string>
     <string name="app_permission_button_always_allow_all" msgid="4905699259378428855">"Toujours autoriser"</string>
     <string name="app_permission_button_ask" msgid="3342950658789427">"Toujours demander"</string>
     <string name="app_permission_button_deny" msgid="6016454069832050300">"Ne pas autoriser"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Appli d\'assistant numérique par défaut"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Appli d\'assistant numérique"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Les applis d\'assistance peuvent se servir des infos à l\'écran pour vous aider. Certaines sont compatibles à la fois avec le lanceur d\'applications et les services de saisie vocale pour vous fournir une assistance intégrée."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recommandées par <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Appli de navigateur par défaut"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Appli de navigateur"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Applications qui vous permettent d\'accéder à Internet et d\'afficher des liens sur lesquels appuyer"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Ouverture des liens"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Par défaut pour utilisation pro"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Paramètres par défaut d\'Espace privé"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimisées pour l\'appareil"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Autres"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Aucune"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Application système par défaut)"</string>
diff --git a/PermissionController/res/values-gl-v36/strings.xml b/PermissionController/res/values-gl-v36/strings.xml
new file mode 100644
index 0000000000..236dff23e1
--- /dev/null
+++ b/PermissionController/res/values-gl-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Control de axentes doutras aplicacións"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Leva a cabo accións no teu dispositivo e noutras aplicacións"</string>
+</resources>
diff --git a/PermissionController/res/values-gl/strings.xml b/PermissionController/res/values-gl/strings.xml
index 0a46020ff7..7552d37caf 100644
--- a/PermissionController/res/values-gl/strings.xml
+++ b/PermissionController/res/values-gl/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Aplicación de asistente dixital predeterminada"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplicación de asistente dixital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"As aplicacións de asistencia pódente axudar en función da información que apareza na pantalla en cada momento. Algunhas aplicacións son compatibles tanto cos servizos de entrada de voz como co launcher para proporcionarche unha asistencia integrada."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomendadas por <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Aplicación de navegador predeterminada"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplicación de navegador"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplicacións que che permiten acceder a Internet e abrir as ligazóns que tocas."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Apertura de ligazóns"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predeterminadas para o traballo"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Aplicacións predeterminadas do espazo privado"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizadas para o dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Outras"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ningunha"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Opción predeterminada do sistema)"</string>
diff --git a/PermissionController/res/values-gu-v33/strings.xml b/PermissionController/res/values-gu-v33/strings.xml
index 767538cdd2..ce5e9322fe 100644
--- a/PermissionController/res/values-gu-v33/strings.xml
+++ b/PermissionController/res/values-gu-v33/strings.xml
@@ -19,7 +19,7 @@
     <string name="role_dialer_request_description" msgid="6188305064871543419">"આ ઍપને તમને નોટિફિકેશન મોકલવાની મંજૂરી આપવામાં આવશે અને તમારા કૅમેરા, સંપર્કો, માઇક્રોફોન, ફોન અને SMSનો ઍક્સેસ આપવામાં આવશે."</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"આ ઍપને તમને નોટિફિકેશન મોકલવાની મંજૂરી આપવામાં આવશે અને તમારા કૅમેરા, સંપર્કો, ફાઇલો, માઇક્રોફોન, ફોન અને SMSનો ઍક્સેસ આપવામાં આવશે"</string>
     <string name="permission_description_summary_storage" msgid="1917071243213043858">"આ પરવાનગી ધરાવતી ઍપ આ ડિવાઇસ પરની બધી ફાઇલો ઍક્સેસ કરી શકે છે"</string>
-    <string name="work_policy_title" msgid="832967780713677409">"તમારી કાર્ય પૉલિસીની માહિતી"</string>
+    <string name="work_policy_title" msgid="832967780713677409">"તમારી ઑફિસની પૉલિસીની માહિતી"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"તમારા IT ઍડમિન દ્વારા મેનેજ કરવામાં આવતા સેટિંગ"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"સૂચિ મોટી કરીને બતાવો"</string>
     <string name="safety_center_entry_group_collapse_action" msgid="1525710152244405656">"સૂચિ નાની કરો અને સેટિંગ છુપાવો"</string>
diff --git a/PermissionController/res/values-gu-v34/strings.xml b/PermissionController/res/values-gu-v34/strings.xml
index cce1bac6ab..5fd1565925 100644
--- a/PermissionController/res/values-gu-v34/strings.xml
+++ b/PermissionController/res/values-gu-v34/strings.xml
@@ -22,5 +22,5 @@
     <string name="health_connect_title" msgid="2132233890867430855">"Health Connect"</string>
     <string name="health_connect_summary" msgid="815473513776882296">"ઍપનો આરોગ્ય સંબંધિત ડેટાનો ઍક્સેસ મેનેજ કરો"</string>
     <string name="location_settings" msgid="8863940440881290182">"લોકેશન ઍક્સેસ"</string>
-    <string name="mic_toggle_description" msgid="1504101620086616040">"ઍપ અને સેવાઓ માટે. આ સેટિંગ બંધ હોવા છતાં પણ, જ્યારે તમે ઇમર્જન્સી નંબર પર કૉલ કરો ત્યારે હજુ પણ માઇક્રોફોનનો ડેટા શેર કરવામાં આવી શકે"</string>
+    <string name="mic_toggle_description" msgid="1504101620086616040">"ઍપ અને સેવાઓ માટે. આ સેટિંગ બંધ હોવા છતાં પણ, જ્યારે તમે ઇમર્જન્સી નંબર પર કૉલ કરો ત્યારે માઇક્રોફોનનો ડેટા શેર કરવામાં આવી શકે"</string>
 </resources>
diff --git a/PermissionController/res/values-gu-v36/strings.xml b/PermissionController/res/values-gu-v36/strings.xml
new file mode 100644
index 0000000000..3d59da8303
--- /dev/null
+++ b/PermissionController/res/values-gu-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"અન્ય ઍપનું એજન્ટ નિયંત્રણ"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"તમારા ડિવાઇસ અને અન્ય ઍપ પર ઍક્શન પર્ફોર્મ કરો"</string>
+</resources>
diff --git a/PermissionController/res/values-gu/strings.xml b/PermissionController/res/values-gu/strings.xml
index eca8f049af..14d062775f 100644
--- a/PermissionController/res/values-gu/strings.xml
+++ b/PermissionController/res/values-gu/strings.xml
@@ -102,7 +102,7 @@
     <string name="permission_summary_disabled_by_policy_background_only" msgid="221995005556362660">"પૉલિસી દ્વારા બૅકગ્રાઉન્ડ ઍક્સેસને બંધ કરવામાં આવ્યો છે"</string>
     <string name="permission_summary_enabled_by_policy_background_only" msgid="8287675974767104279">"પૉલિસી દ્વારા બૅકગ્રાઉન્ડ ઍક્સેસને ચાલુ કરવામાં આવ્યો છે"</string>
     <string name="permission_summary_enabled_by_policy_foreground_only" msgid="3844582916889767831">"પૉલિસી દ્વારા ફૉરગ્રાઉન્ડ ઍક્સેસને ચાલુ કરવામાં આવ્યો છે"</string>
-    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"વ્યવસ્થાપક દ્વારા નિયંત્રિત"</string>
+    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"ઍડમિન દ્વારા નિયંત્રિત"</string>
     <string name="permission_summary_disabled_by_admin_background_only" msgid="3127091456731845646">"વ્યવસ્થાપકે બૅકગ્રાઉન્ડ ઍક્સેસ બંધ કર્યો છે"</string>
     <string name="permission_summary_enabled_by_admin_background_only" msgid="9132423838440275757">"વ્યવસ્થાપકે બૅકગ્રાઉન્ડ ઍક્સેસ ચાલુ કર્યો છે"</string>
     <string name="permission_summary_enabled_by_admin_foreground_only" msgid="1298432715610745358">"વ્યવસ્થાપકે ફૉરગ્રાઉન્ડ ઍક્સેસ ચાલુ કર્યો છે"</string>
@@ -195,8 +195,8 @@
     <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"મર્યાદિત ઍક્સેસની મંજૂરી આપો"</string>
     <string name="precise_image_description" msgid="6349638632303619872">"ચોક્કસ સ્થાન"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"અંદાજિત સ્થાન"</string>
-    <string name="app_permission_location_accuracy" msgid="7166912915040018669">"ચોક્કસ લોકેશનનો ઉપયોગ કરો"</string>
-    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"જ્યારે ચોક્કસ લોકેશન બંધ હોય, ત્યારે ઍપ તમારા અંદાજિત લોકેશનને ઍક્સેસ કરી શકે છે"</string>
+    <string name="app_permission_location_accuracy" msgid="7166912915040018669">"સચોટ લોકેશનનો ઉપયોગ કરો"</string>
+    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"જ્યારે સચોટ લોકેશન બંધ હોય, ત્યારે ઍપ તમારા અંદાજિત લોકેશનને ઍક્સેસ કરી શકે છે"</string>
     <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g>ની પરવાનગી"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"આ ઍપ માટે <xliff:g id="PERM">%1$s</xliff:g>નો ઍક્સેસ"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"<xliff:g id="DEVICE_NAME">%2$s</xliff:g> પર આ ઍપ માટે <xliff:g id="PERM">%1$s</xliff:g>નો ઍક્સેસ"</string>
@@ -252,7 +252,7 @@
     <string name="app_permission_most_recent_denied_summary" msgid="7659497197737708112">"હાલમાં નકારેલી / છેલ્લો ઍક્સેસ: <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_permission_never_accessed_summary" msgid="401346181461975090">"ક્યારેય ઍક્સેસ કરેલ નથી"</string>
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"નકારી / ક્યારેય ઍક્સેસ કરી નથી"</string>
-    <string name="allowed_header" msgid="7769277978004790414">"મંજૂર"</string>
+    <string name="allowed_header" msgid="7769277978004790414">"મંજૂરી છે"</string>
     <string name="allowed_always_header" msgid="6455903312589013545">"હંમેશાં માટે મંજૂરી આપી છે"</string>
     <string name="allowed_foreground_header" msgid="6845655788447833353">"માત્ર ઉપયોગમાં હોય ત્યારે જ મંજૂરી છે"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"માત્ર મીડિયા ઍક્સેસ કરવાની મંજૂરી છે"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ડિફૉલ્ટ ડિજિટલ આસિસ્ટંટ ઍપ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ડિજિટલ આસિસ્ટંટ ઍપ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"તમે જોઈ રહ્યા હો તે સ્ક્રીન પરની માહિતીના આધારે સહાયક ઍપ તમને સહાય કરી શકે છે. કેટલીક ઍપ તમને એકીકૃત સહાયતા આપવા માટે લૉન્ચર અને વૉઇસ ઇનપુટ સેવાઓ બંનેને સમર્થન આપે છે."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> દ્વારા સુઝાવ આપેલી"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ડિફૉલ્ટ બ્રાઉઝર ઍપ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"બ્રાઉઝર ઍપ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ઍપ કે જે તમને ઇન્ટરનેટનો ઍક્સેસ આપે અને તમે જેના પર ટૅપ કરો તે લિંક દર્શાવે"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"લિંક ખોલવી"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"કાર્ય માટે ડિફૉલ્ટ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ખાનગી સ્પેસ માટે ડિફૉલ્ટ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ડિવાઇસ માટે ઑપ્ટિમાઇઝ કરેલી છે"</string>
     <string name="default_app_others" msgid="7793029848126079876">"અન્ય"</string>
     <string name="default_app_none" msgid="9084592086808194457">"કોઈ નહીં"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(સિસ્ટમ ડિફૉલ્ટ)"</string>
@@ -491,7 +491,7 @@
     <string name="permgrouprequest_device_aware_fineupgrade" msgid="4453775952305587571">"<xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g>નો &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; પરનો લોકેશનનો ઍક્સેસ અંદાજિતમાંથી બદલીને ચોક્કસ કરીએ?"</string>
     <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને આ ડિવાઇસના અંદાજિત લોકેશનને ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_device_aware_coarselocation" msgid="8367540370912066757">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;નું અંદાજિત લોકેશન ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
-    <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"ચોક્કસ"</string>
+    <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"સચોટ"</string>
     <string name="permgrouprequest_coarselocation_imagetext" msgid="8650605041483025297">"અંદાજિત"</string>
     <string name="permgrouprequest_calendar" msgid="1493150855673603806">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને તમારા કૅલેન્ડરને ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_device_aware_calendar" msgid="7161929851377463612">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; પર તમારું કૅલેન્ડર ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
@@ -503,7 +503,7 @@
     <string name="permgrouprequest_storage_pre_q" msgid="168130651144569428">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને આ ડિવાઇસ પર &lt;b&gt;ફોટા, વીડિયો, મ્યુઝિક, ઑડિયો અને અન્ય ફાઇલો&lt;b&gt;ના ઍક્સેસની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_read_media_aural" msgid="2593365397347577812">"શું &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને આ ડિવાઇસ પરની મ્યુઝિક અને ઑડિયો ફાઇલો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_device_aware_read_media_aural" msgid="7927884506238101064">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; પર મ્યુઝિક અને ઑડિયો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
-    <string name="permgrouprequest_read_media_visual" msgid="5548780620779729975">"શું &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને આ ડિવાઇસ પરના ફોટા અને વીડિયો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
+    <string name="permgrouprequest_read_media_visual" msgid="5548780620779729975">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને આ ડિવાઇસ પરના ફોટા અને વીડિયો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_device_aware_read_media_visual" msgid="3122576538319059333">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; પર ફોટા અને વીડિયો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_more_photos" msgid="128933814654231321">"શું &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને આ ડિવાઇસ પરના વધુ ફોટા અને વીડિયો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
     <string name="permgrouprequest_device_aware_more_photos" msgid="1703469013613723053">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ને &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; પર વધુ ફોટા અને વીડિયો ઍક્સેસ કરવાની મંજૂરી આપીએ?"</string>
@@ -633,7 +633,7 @@
     <string name="mic_toggle_title" msgid="2649991093496110162">"માઇક્રોફોનનો ઍક્સેસ"</string>
     <string name="perm_toggle_description" msgid="7801326363741451379">"ઍપ અને સેવાઓ માટે"</string>
     <string name="mic_toggle_description" msgid="9163104307990677157">"ઍપ અને સેવાઓ માટે. આ સેટિંગ બંધ હોવા છતાં પણ, જ્યારે તમે ઇમર્જન્સી નંબર પર કૉલ કરો ત્યારે કદાચ માઇક્રોફોનનો ડેટા શેર કરવામાં આવી શકે."</string>
-    <string name="location_settings_subtitle" msgid="2328360561197430695">"લોકેશનનો ઍક્સેસ ધરાવતી ઍપ અને તેની સેવાઓ જુઓ"</string>
+    <string name="location_settings_subtitle" msgid="2328360561197430695">"લોકેશનનો ઍક્સેસ ધરાવતી ઍપ અને સેવાઓ જુઓ"</string>
     <string name="show_clip_access_notification_title" msgid="5168467637351109096">"ક્લિપબોર્ડનો ઍક્સેસ બતાવો"</string>
     <string name="show_clip_access_notification_summary" msgid="3532020182782112687">"જ્યારે ઍપ તમે કૉપિ કરેલી ટેક્સ્ટ, છબીઓ કે અન્ય કન્ટેન્ટનો ઍક્સેસ કરે, ત્યારે મેસેજ બતાવો"</string>
     <string name="show_password_title" msgid="2877269286984684659">"પાસવર્ડ બતાવો"</string>
@@ -678,7 +678,7 @@
     <string name="allow_restricted_settings" msgid="8073000189478396881">"પ્રતિબંધિત સેટિંગને મંજૂરી આપો"</string>
     <string name="enhanced_confirmation_dialog_title" msgid="7562437438040966351">"પ્રતિબંધિત સેટિંગ"</string>
     <string name="enhanced_confirmation_dialog_desc" msgid="5921240234843839219">"તમારી સુરક્ષા માટે, આ સેટિંગ હાલમાં ઉપલબ્ધ નથી."</string>
-    <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"કૉલ દરમિયાન ક્રિયા પૂર્ણ કરી શકાતી નથી"</string>
+    <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"કૉલ દરમિયાન ઍક્શન પૂર્ણ કરી શકાતી નથી"</string>
     <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"તમારા ડિવાઇસ અને ડેટાને સુરક્ષિત રાખવા માટે આ સેટિંગ બ્લૉક કરવામાં આવ્યું છે.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
diff --git a/PermissionController/res/values-hi-v33/strings.xml b/PermissionController/res/values-hi-v33/strings.xml
index ef727a0607..d1dac6c931 100644
--- a/PermissionController/res/values-hi-v33/strings.xml
+++ b/PermissionController/res/values-hi-v33/strings.xml
@@ -27,7 +27,7 @@
     <string name="safety_center_entry_group_with_actions_needed_content_description" msgid="2708884606775932657">"सूची. <xliff:g id="ENTRY_TITLE">%1$s</xliff:g>. ज़रूरी कार्रवाइयां. <xliff:g id="ENTRY_SUMMARY">%2$s</xliff:g>"</string>
     <string name="safety_center_entry_group_item_content_description" msgid="7348298582877249787">"आइटम की सूची. <xliff:g id="ENTRY_ITEM_TITLE">%1$s</xliff:g>. <xliff:g id="ENTRY_ITEM_SUMMARY">%2$s</xliff:g>"</string>
     <string name="safety_center_entry_content_description" msgid="3639565652938224321">"<xliff:g id="ENTRY_ITEM_TITLE">%1$s</xliff:g>. <xliff:g id="ENTRY_ITEM_SUMMARY">%2$s</xliff:g>"</string>
-    <string name="safety_center_more_issues_card_title" msgid="7425844746197493312">"ज़्यादा चेतावनियां"</string>
+    <string name="safety_center_more_issues_card_title" msgid="7425844746197493312">"ज़्यादा सूचनाएं"</string>
     <string name="safety_center_dismissed_issues_card_title" msgid="2340129842725145733">"खारिज किए गए अलर्ट"</string>
     <string name="safety_center_more_issues_card_expand_action" msgid="7109451851052272946">"{count,plural, =1{कार्ड को बड़ा करके एक और सूचना देखें}one{कार्ड को बड़ा करके # और सूचना देखें}other{कार्ड को बड़ा करके # और सूचनाएं देखें}}"</string>
     <string name="safety_center_more_issues_card_collapse_action" msgid="7485597582198474637">"छोटा करें"</string>
diff --git a/PermissionController/res/values-hi-v36/strings.xml b/PermissionController/res/values-hi-v36/strings.xml
new file mode 100644
index 0000000000..e9a4d8ad40
--- /dev/null
+++ b/PermissionController/res/values-hi-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"अन्य ऐप्लिकेशन के लिए एजेंट कंट्रोल"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"डिवाइस और अन्य ऐप्लिकेशन में कार्रवाइयां करने की अनुमति दें"</string>
+</resources>
diff --git a/PermissionController/res/values-hi-watch/strings.xml b/PermissionController/res/values-hi-watch/strings.xml
index 12d4356d36..017c43f753 100644
--- a/PermissionController/res/values-hi-watch/strings.xml
+++ b/PermissionController/res/values-hi-watch/strings.xml
@@ -22,11 +22,11 @@
     <string name="permission_summary_enforced_by_policy" msgid="2352478756952948019">"बदला नहीं जा सकता"</string>
     <string name="generic_yes" msgid="2489207724988649846">"हां"</string>
     <string name="generic_cancel" msgid="2631708607129269698">"रद्द करें"</string>
-    <string name="permission_access_always" msgid="2107115233573823032">"हर समय"</string>
+    <string name="permission_access_always" msgid="2107115233573823032">"हमेशा"</string>
     <string name="permission_access_only_foreground" msgid="4412115020089923986">"ऐप इस्तेमाल करते समय"</string>
-    <string name="app_permission_button_allow_always" msgid="4920899432212307102">"हर समय"</string>
+    <string name="app_permission_button_allow_always" msgid="4920899432212307102">"हमेशा"</string>
     <string name="app_permission_button_allow_foreground" msgid="7186980598244864830">"ऐप इस्तेमाल करते समय"</string>
-    <string name="grant_dialog_button_allow_always" msgid="7130695257254694576">"हर समय"</string>
+    <string name="grant_dialog_button_allow_always" msgid="7130695257254694576">"हमेशा"</string>
     <string name="grant_dialog_button_allow_foreground" msgid="8917595344037255090">"ऐप इस्तेमाल करते समय"</string>
-    <string name="grant_dialog_button_allow_background" msgid="6104993390936535493">"हर समय"</string>
+    <string name="grant_dialog_button_allow_background" msgid="6104993390936535493">"हमेशा"</string>
 </resources>
diff --git a/PermissionController/res/values-hi/strings.xml b/PermissionController/res/values-hi/strings.xml
index 2931865cd1..bd9b26a6ea 100644
--- a/PermissionController/res/values-hi/strings.xml
+++ b/PermissionController/res/values-hi/strings.xml
@@ -35,7 +35,7 @@
     <string name="grant_dialog_button_more_info" msgid="213350268561945193">"ज़्यादा जानकारी"</string>
     <string name="grant_dialog_button_allow_all" msgid="5939066403732409516">"सभी के लिए अनुमति दें"</string>
     <string name="grant_dialog_button_always_allow_all" msgid="1719900027660252167">"हमेशा के लिए सभी को अनुमति दें"</string>
-    <string name="grant_dialog_button_allow_limited_access" msgid="5713551784422137594">"सीमित ऐक्सेस देने की अनुमति दें"</string>
+    <string name="grant_dialog_button_allow_limited_access" msgid="5713551784422137594">"सीमित ऐक्सेस दें"</string>
     <string name="grant_dialog_button_allow_selected_photos" msgid="5497042471576153842">"चुनिंदा फ़ोटो और वीडियो को अनुमति दें"</string>
     <string name="grant_dialog_button_allow_more_selected_photos" msgid="5145657877588697709">"ज़्यादा फ़ोटो चुनें"</string>
     <string name="grant_dialog_button_dont_select_more" msgid="6643552729129461268">"ज़्यादा फ़ोटो और वीडियो न चुनें"</string>
@@ -164,7 +164,7 @@
     <string name="permission_usage_bar_chart_title_last_minute" msgid="820450867183487607">"पिछले एक मिनट में अनुमति का इस्तेमाल"</string>
     <string name="permission_usage_preference_summary_not_used_in_past_n_days" msgid="4771868094611359651">"{count,plural, =1{पिछले # दिन में इस्तेमाल नहीं की गई}one{पिछले # दिन में इस्तेमाल नहीं की गई}other{पिछले # दिनों में इस्तेमाल नहीं की गई}}"</string>
     <string name="permission_usage_preference_summary_not_used_in_past_n_hours" msgid="3828973177433435742">"{count,plural, =1{पिछले # घंटे में इस्तेमाल नहीं की गई}one{पिछले # घंटे में इस्तेमाल नहीं की गई}other{पिछले # घंटों में इस्तेमाल नहीं की गई}}"</string>
-    <string name="permission_usage_preference_label" msgid="8343167938128676378">"{count,plural, =1{1 ऐप्लिकेशन ने इस्तेमाल किया}one{# ऐप्लिकेशन ने इस्तेमाल किया}other{# ऐप्लिकेशन ने इस्तेमाल किया}}"</string>
+    <string name="permission_usage_preference_label" msgid="8343167938128676378">"{count,plural, =1{1 ऐप ने ऐक्सेस करने की अनुमति का इस्तेमाल किया}one{# ऐप ने ऐक्सेस करने की अनुमति का इस्तेमाल किया}other{# ऐप ने ऐक्सेस करने की अनुमति का इस्तेमाल किया}}"</string>
     <string name="permission_usage_view_details" msgid="6675335735468752787">"डैशबोर्ड में सभी को देखें"</string>
     <string name="app_permission_usage_filter_label" msgid="7182861154638631550">"इससे फ़िल्टर किया गया: <xliff:g id="PERM">%1$s</xliff:g>"</string>
     <string name="app_permission_usage_remove_filter" msgid="2926157607436428207">"फ़िल्टर हटाएं"</string>
@@ -188,15 +188,15 @@
     <string name="app_permission_button_allow_all_files" msgid="1792232272599018825">"सभी फ़ाइलों को मैनेज करने की अनुमति दें"</string>
     <string name="app_permission_button_allow_media_only" msgid="2834282724426046154">"सिर्फ़ मीडिया फ़ाइलें ऐक्सेस करने की अनुमति दें"</string>
     <string name="app_permission_button_allow_always" msgid="4573292371734011171">"हमेशा के लिए अनुमति दें"</string>
-    <string name="app_permission_button_allow_foreground" msgid="1991570451498943207">"सिर्फ़ ऐप्लिकेशन इस्तेमाल करते समय अनुमति दें"</string>
+    <string name="app_permission_button_allow_foreground" msgid="1991570451498943207">"सिर्फ़ इस्तेमाल में होने पर अनुमति दें"</string>
     <string name="app_permission_button_always_allow_all" msgid="4905699259378428855">"हमेशा के लिए सभी को ऐक्सेस की अनुमति दें"</string>
     <string name="app_permission_button_ask" msgid="3342950658789427">"हर बार पूछें"</string>
     <string name="app_permission_button_deny" msgid="6016454069832050300">"अनुमति न दें"</string>
-    <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"सीमित ऐक्सेस देने की अनुमति दें"</string>
+    <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"सीमित ऐक्सेस दें"</string>
     <string name="precise_image_description" msgid="6349638632303619872">"सटीक जगह"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"अनुमानित जगह"</string>
     <string name="app_permission_location_accuracy" msgid="7166912915040018669">"जगह की सटीक जानकारी का इस्तेमाल करें"</string>
-    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"जगह की सटीक जानकारी देने वाली सुविधा बंद होने पर, ऐप्लिकेशन आपकी जगह की अनुमानित जानकारी को ऐक्सेस कर सकते हैं"</string>
+    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"जगह की सटीक जानकारी देने की सुविधा बंद होने पर, ऐप्लिकेशन आपकी जगह की अनुमानित जानकारी को ऐक्सेस कर सकते हैं"</string>
     <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g> की अनुमति"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"इस ऐप्लिकेशन को <xliff:g id="PERM">%1$s</xliff:g> ऐक्सेस करने की अनुमति दें"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"<xliff:g id="DEVICE_NAME">%2$s</xliff:g> पर इस ऐप्लिकेशन के लिए <xliff:g id="PERM">%1$s</xliff:g> का ऐक्सेस"</string>
@@ -239,7 +239,7 @@
     <string name="permission_description_summary_call_log" msgid="7321437186317577624">"ऐसे ऐप्लिकेशन जिनके पास अनुमति है, वे फ़ोन में कॉल लॉग को पढ़ सकते हैं और लिख सकते हैं"</string>
     <string name="permission_description_summary_camera" msgid="108004375101882069">"इस अनुमति वाले ऐप्लिकेशन, फ़ोटो खींच सकते हैं और वीडियो रिकॉर्ड कर सकते हैं"</string>
     <string name="permission_description_summary_contacts" msgid="2337798886460408996">"इस अनुमति वाले ऐप्लिकेशन आपके संपर्कों को ऐक्सेस कर सकते हैं"</string>
-    <string name="permission_description_summary_location" msgid="2817531799933480694">"जिन ऐप्लिकेशन के पास यह अनुमति होगी वे डिवाइस की जगह की जानकारी ऐक्सेस कर सकते हैं"</string>
+    <string name="permission_description_summary_location" msgid="2817531799933480694">"जिन ऐप्लिकेशन के पास अनुमति होगी वे इस डिवाइस की जगह की जानकारी ऐक्सेस कर सकते हैं"</string>
     <string name="permission_description_summary_nearby_devices" msgid="8269183818275073741">"जिन ऐप्लिकेशन के पास यह अनुमति है वे आस-पास मौजूद डिवाइसों को खोज सकते हैं, उनसे कनेक्ट कर सकते हैं, और उनकी जगह की जानकारी का पता लगा सकते हैं"</string>
     <string name="permission_description_summary_microphone" msgid="630834800308329907">"इस अनुमति वाले ऐप्लिकेशन ऑडियो रिकॉर्ड कर सकते हैं"</string>
     <string name="permission_description_summary_phone" msgid="4515277217435233619">"इस अनुमति वाले ऐप्लिकेशन, फ़ोन कॉल कर सकते हैं और कॉल को मैनेज कर सकते हैं"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"डिफ़ॉल्ट डिजिटल असिस्टेंट ऐप"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"डिजिटल असिस्टेंट ऐप्लिकेशन"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"स्क्रीन पर दिख रही जानकारी के आधार पर, सहायक ऐप्लिकेशन आपकी मदद कर सकते हैं. कुछ ऐप्लिकेशन हर तरह से आपकी मदद करने के लिए, लॉन्चर और फ़ोन को बोलकर निर्देश देने वाली सेवाओं, दोनों के साथ काम करते हैं."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> के सुझाए गए ऐप्लिकेशन"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"डिफ़ॉल्ट ब्राउज़र ऐप्लिकेशन"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ब्राउज़र ऐप्लिकेशन"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ऐसे ऐप्लिकेशन जो आपको इंटरनेट तक ऐक्सेस देते हैं और आपके टैप किए गए लिंक को डिसप्ले करते हैं"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"खुलने वाले लिंक"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"काम के लिए डिफ़ॉल्ट"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"प्राइवेट स्पेस के लिए डिफ़ॉल्ट ऐप्लिकेशन"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"डिवाइस के लिए ऑप्टिमाइज़ किया गया"</string>
     <string name="default_app_others" msgid="7793029848126079876">"अन्य"</string>
     <string name="default_app_none" msgid="9084592086808194457">"कोई नहीं"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(सिस्टम डिफ़ॉल्ट)"</string>
@@ -473,9 +473,9 @@
     <string name="assistant_record_audio_user_sensitive_summary" msgid="6482937591816401619">"आवाज़ से डिवाइस का इस्तेमाल करने के लिए, माइक्रोफ़ोन का इस्तेमाल करते समय स्थिति बार में आइकॉन दिखाएं"</string>
     <string name="permgrouprequest_storage_isolated" msgid="4892154224026852295">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को अपने डिवाइस में मौजूद फ़ोटो और मीडिया ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_storage_isolated" msgid="6463062962458809752">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; में मौजूद फ़ोटो और मीडिया का ऐक्सेस देना है?"</string>
-    <string name="permgrouprequest_contacts" msgid="8391550064551053695">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को आपके संपर्कों को ऐक्सेस करने की अनुमति देनी  है?"</string>
+    <string name="permgrouprequest_contacts" msgid="8391550064551053695">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को अपने संपर्कों को ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_contacts" msgid="731025863972535928">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; में मौजूद, संपर्कों को ऐक्सेस करने की अनुमति देनी है?"</string>
-    <string name="permgrouprequest_location" msgid="6990232580121067883">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को इस डिवाइस की जगह की जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
+    <string name="permgrouprequest_location" msgid="6990232580121067883">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को इस डिवाइस की जगह की जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_location" msgid="6075412127429878638">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>’s&lt;/b&gt; की जगह की जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequestdetail_location" msgid="2635935335778429894">"ऐप्लिकेशन, डिवाइस की जगह की जानकारी सिर्फ़ तभी देख पाएगा जब आप इसका इस्तेमाल कर रहे हों"</string>
     <string name="permgroupbackgroundrequest_location" msgid="1085680897265734809">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को इस डिवाइस की जगह की जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
@@ -489,7 +489,7 @@
     <string name="permgroupupgraderequestdetail_nearby_devices" msgid="6877531270654738614">"क्या आप &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को आस-पास मौजूद डिवाइसों को खोजने, उनसे कनेक्ट करने, और उनकी जगह की जानकारी का पता लगाने की अनुमति देना चाहते हैं? "<annotation id="link">"सेटिंग में जाकर अनुमति दें."</annotation></string>
     <string name="permgrouprequest_fineupgrade" msgid="2334242928821697672">"क्या <xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g> आपकी जगह की अनुमानित जानकारी के बजाय सटीक जानकारी ऐक्सेस करे?"</string>
     <string name="permgrouprequest_device_aware_fineupgrade" msgid="4453775952305587571">"क्या &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; के लिए, <xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g> की जगह की जानकारी का ऐक्सेस अनुमानित से सटीक में बदलना है?"</string>
-    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"क्या आपको &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को इस डिवाइस की जगह की अनुमानित जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
+    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को इस डिवाइस की जगह की अनुमानित जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_coarselocation" msgid="8367540370912066757">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;’s की जगह की अनुमानित जानकारी ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"सटीक जगह"</string>
     <string name="permgrouprequest_coarselocation_imagetext" msgid="8650605041483025297">"अनुमानित जगह"</string>
@@ -527,9 +527,9 @@
     <string name="permgroupupgraderequest_camera" msgid="640758449200241582">"क्या आप &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; के लिए, कैमरे के ऐक्सेस की अनुमति बदलना चाहते हैं?"</string>
     <string name="permgroupupgraderequest_device_aware_camera" msgid="3290160912843715236">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; के लिए, &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; के कैमरे का ऐक्सेस बदलना है?"</string>
     <string name="permgroupupgraderequestdetail_camera" msgid="6642747548010962597">"यह ऐप्लिकेशन हर समय तस्वीरें लेना और वीडियो रिकॉर्ड करना चाहता है, तब भी जब आप ऐप्लिकेशन इस्तेमाल न कर रहे हों. "<annotation id="link">"सेटिंग में जाकर अनुमति दें."</annotation></string>
-    <string name="permgrouprequest_calllog" msgid="2065327180175371397">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को आपका कॉल लॉग ऐक्सेस करने की अनुमति देनी है?"</string>
+    <string name="permgrouprequest_calllog" msgid="2065327180175371397">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को अपने फ़ोन में मौजूद कॉल लॉग को ऐक्सेस करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_calllog" msgid="8220927190376843309">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; में मौजूद, कॉल लॉग का ऐक्सेस देना है?"</string>
-    <string name="permgrouprequest_phone" msgid="1829234136997316752">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को फ़ोन कॉल करने और उन्हें मैनेज करने की अनुमति देनी है?"</string>
+    <string name="permgrouprequest_phone" msgid="1829234136997316752">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को फ़ोन कॉल करने और उन्हें मैनेज करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_phone" msgid="590399263670349955">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; से फ़ोन कॉल करने और उन्हें मैनेज करने का ऐक्सेस देना है?"</string>
     <string name="permgrouprequest_sensors" msgid="4397358316850652235">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को बीपी, धड़कन वगैरह की जानकारी इस्तेमाल करने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_sensors" msgid="3874451050573615157">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; में मौजूद, शरीर के बारे में ज़रूरी जानकारी देने वाले सेंसर डेटा का ऐक्सेस देना है?"</string>
@@ -539,7 +539,7 @@
     <string name="permgroupbackgroundrequestdetail_sensors" msgid="7726767635834043501">"इस ऐप्लिकेशन का इस्तेमाल न किए जाने पर भी, इसे बॉडी सेंसर के डेटा को हमेशा ऐक्सेस करने की अनुमति देने के लिए, "<annotation id="link">"सेटिंग पर जाएं."</annotation></string>
     <string name="permgroupupgraderequest_sensors" msgid="7576527638411370468">"क्या इस्तेमाल के दौरान, &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को बॉडी सेंसर के डेटा का ऐक्सेस देते रहना है?"</string>
     <string name="permgroupupgraderequest_device_aware_sensors" msgid="5542771499929819675">"क्या इस्तेमाल के दौरान, &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; पर &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को बॉडी सेंसर के डेटा का ऐक्सेस देते रहना है?"</string>
-    <string name="permgrouprequest_notifications" msgid="6396739062335106181">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को सूचनाएं भेजने की अनुमति देनी है?"</string>
+    <string name="permgrouprequest_notifications" msgid="6396739062335106181">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को सूचनाएं भेजने की अनुमति देनी है?"</string>
     <string name="permgrouprequest_device_aware_notifications" msgid="857671638951040514">"क्या &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; को &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; पर सूचनाएं भेजने की अनुमति देनी है?"</string>
     <string name="auto_granted_permissions" msgid="6009452264824455892">"कंट्रोल की गई अनुमतियां"</string>
     <string name="auto_granted_location_permission_notification_title" msgid="7570818224669050377">"<xliff:g id="APP_NAME">%1$s</xliff:g> के पास, डिवाइस की जगह की जानकारी का ऐक्सेस है"</string>
@@ -576,7 +576,7 @@
     <string name="safety_center_rescan_button" msgid="4517514567809409596">"डिवाइस स्कैन करें"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"खारिज करें"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"क्या इस चेतावनी को खारिज करना है?"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"डिवाइस की सुरक्षा बढ़ाने के लिए, जब चाहें अपनी सुरक्षा और निजता सेटिंग देखें"</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"डिवाइस की सुरक्षा बढ़ाने के लिए, जब चाहें अपनी सुरक्षा और निजता सेटिंग की समीक्षा करें"</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"खारिज करें"</string>
     <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"अभी नहीं"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"सेटिंग"</string>
@@ -662,7 +662,7 @@
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"जगह की जानकारी का डेटा शेयर करने के तरीके के बारे में अपडेट"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"उन ऐप्लिकेशन को देखें जिन्होंने आपकी जगह की जानकारी का डेटा शेयर करने के लिए, अपनी गतिविधियों में बदलाव किया है"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"इन ऐप्लिकेशन ने आपकी जगह की जानकारी के डेटा को शेयर करने का तरीका बदल दिया है. ऐसा हो सकता है कि ये ऐप्लिकेशन पहले जगह की जानकारी का डेटा शेयर न करते हों या फिर अब ये विज्ञापन या मार्केटिंग के लिए यह डेटा शेयर करें."</string>
-    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"इन ऐप्लिकेशन के डेवलपरों ने, डेटा शेयर करने के अपने तरीकों के बारे में ऐप स्टोर पर जानकारी दी है. वे समय-समय पर इस जानकारी को अपडेट कर सकते हैं.\n\nडेटा शेयर करने के तरीके अलग-अलग हो सकते हैं. ये आपकी जगह, उम्र, ऐप्लिकेशन के वर्शन, और उसके इस्तेमाल के हिसाब से तय किए जाते हैं."</string>
+    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"इन ऐप्लिकेशन के डेवलपर ने डेटा शेयर करने के अपने तरीकों के बारे में, ऐप स्टोर पर जानकारी दी है. वे समय-समय पर इस जानकारी को अपडेट कर सकते हैं.\n\nडेटा शेयर करने के तरीके अलग-अलग हो सकते हैं. ये आपकी जगह, उम्र, ऐप्लिकेशन के वर्शन, और उसके इस्तेमाल के हिसाब से तय किए जाते हैं."</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"डेटा शेयर करने की नीतियों के बारे में जानें"</string>
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"आपकी जगह की जानकारी का डेटा अब तीसरे पक्षों के साथ शेयर किया गया है"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"विज्ञापन देने या मार्केटिंग करने के लिए, आपकी जगह की जानकारी को अब तीसरे पक्षों के साथ शेयर किया जा रहा है"</string>
@@ -682,7 +682,7 @@
     <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"आपके डिवाइस और डेटा को सुरक्षित रखने के लिए, यह सेटिंग ब्लॉक की गई है. <xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
-</xliff:g>धोखाधड़ी करने वाले लोग, आपको नए सोर्स से अनजान ऐप्लिकेशन इंस्टॉल करने के लिए कहकर, आपके डिवाइस पर नुकसान पहुंचाने वाले ऐप्लिकेशन इंस्टॉल कराने की कोशिश कर सकते हैं."</string>
+</xliff:g>धोखाधड़ी करने वाले लोग, आपको किसी नए सोर्स से अनजान ऐप्लिकेशन इंस्टॉल करने के लिए कहकर आपके डिवाइस पर नुकसान पहुंचाने वाले ऐप्लिकेशन इंस्टॉल कराने की कोशिश कर सकते हैं."</string>
     <string name="enhanced_confirmation_phone_state_dialog_a11y_desc" msgid="6567523001053288057">"<xliff:g id="EMPTY_LINE">
 
 </xliff:g>धोखाधड़ी करने वाले लोग, आपके डिवाइस में मौजूद किसी ऐप्लिकेशन को ऐक्सेस करने की अनुमति लेकर, आपके डिवाइस को कंट्रोल करने की कोशिश कर सकते हैं."</string>
diff --git a/PermissionController/res/values-hr-v36/strings.xml b/PermissionController/res/values-hr-v36/strings.xml
new file mode 100644
index 0000000000..460b057d21
--- /dev/null
+++ b/PermissionController/res/values-hr-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Pristup aplikacije agenta za druge aplikacije"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Izvršite radnje na uređaju i u drugim aplikacijama"</string>
+</resources>
diff --git a/PermissionController/res/values-hr/strings.xml b/PermissionController/res/values-hr/strings.xml
index d22700aeee..4eaa5eb889 100644
--- a/PermissionController/res/values-hr/strings.xml
+++ b/PermissionController/res/values-hr/strings.xml
@@ -102,7 +102,7 @@
     <string name="permission_summary_disabled_by_policy_background_only" msgid="221995005556362660">"Pristup u pozadini onemogućen je pravilima"</string>
     <string name="permission_summary_enabled_by_policy_background_only" msgid="8287675974767104279">"Pristup u pozadini omogućen je pravilima"</string>
     <string name="permission_summary_enabled_by_policy_foreground_only" msgid="3844582916889767831">"Pristup u prednjem planu omogućen je pravilima"</string>
-    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"Kontrolira administrator"</string>
+    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"Upravlja administrator"</string>
     <string name="permission_summary_disabled_by_admin_background_only" msgid="3127091456731845646">"Pristup iz pozadine onemogućio je administrator"</string>
     <string name="permission_summary_enabled_by_admin_background_only" msgid="9132423838440275757">"Pristup iz pozadine omogućio je administrator"</string>
     <string name="permission_summary_enabled_by_admin_foreground_only" msgid="1298432715610745358">"Pristup iz prednjeg plana omogućio je administrator"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Zadana aplikacija digitalnog asistenta"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Apl. digitalnog asistenta"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikacije za pomoć služe se podacima koji se prikazuju na zaslonu. Neke aplikacije podržavaju pokretač i usluge glasovnog unosa kako bi vam pružile integriranu pomoć."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Preporučuje <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Zadana aplikacija preglednika"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplikacija preglednika"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikacije koje vam omogućuju pristup internetu i prikazuju veze koje dodirnete"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Otvaranje veza"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Zadano za posao"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Zadano za privatni prostor"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizirano za uređaj"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Ostalo"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nijedna"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Zadana postavka sustava)"</string>
diff --git a/PermissionController/res/values-hu-v36/strings.xml b/PermissionController/res/values-hu-v36/strings.xml
new file mode 100644
index 0000000000..05ac7c8cd7
--- /dev/null
+++ b/PermissionController/res/values-hu-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Más alkalmazások ügynöki vezérlése"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Műveletek végrehajtása az eszközön és más alkalmazásokban"</string>
+</resources>
diff --git a/PermissionController/res/values-hu/strings.xml b/PermissionController/res/values-hu/strings.xml
index b09d798738..90a75bd953 100644
--- a/PermissionController/res/values-hu/strings.xml
+++ b/PermissionController/res/values-hu/strings.xml
@@ -102,7 +102,7 @@
     <string name="permission_summary_disabled_by_policy_background_only" msgid="221995005556362660">"A házirend letiltotta a háttérhozzáférést"</string>
     <string name="permission_summary_enabled_by_policy_background_only" msgid="8287675974767104279">"A házirend engedélyezte a háttérhozzáférést"</string>
     <string name="permission_summary_enabled_by_policy_foreground_only" msgid="3844582916889767831">"A házirend engedélyezte az előtérbeli hozzáférést"</string>
-    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"Rendszergazda által irányítva"</string>
+    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"A rendszergazda felügyeli"</string>
     <string name="permission_summary_disabled_by_admin_background_only" msgid="3127091456731845646">"A rendszergazda letiltotta a háttérhozzáférést"</string>
     <string name="permission_summary_enabled_by_admin_background_only" msgid="9132423838440275757">"A rendszergazda engedélyezte a háttérhozzáférést"</string>
     <string name="permission_summary_enabled_by_admin_foreground_only" msgid="1298432715610745358">"A rendszergazda engedélyezte az előtérbeli hozzáférést"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Alapértelmezett digitális asszisztens"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitális asszisztens app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"A segédalkalmazások az aktuális képernyőn lévő információk alapján segíthetnek. Egyes alkalmazások egyaránt támogatják az indítási és a hangbeviteli szolgáltatásokat annak érdekében, hogy integrált segítséget nyújthassanak Önnek."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Javasolta: <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Alapértelmezett böngésző"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Böngészőalkalmazás"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Alkalmazások, amelyek hozzáférést biztosítanak az internethez, valamint koppintható linkeket jelenítenek meg"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Linkek megnyitása"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Munkahelyi alapértelmezett"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Alapértelmezett a magánterületnél"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Az eszközre optimalizálva"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Egyéb"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nincs"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Alapértelmezett)"</string>
diff --git a/PermissionController/res/values-hy-v36/strings.xml b/PermissionController/res/values-hy-v36/strings.xml
new file mode 100644
index 0000000000..ac8521a06d
--- /dev/null
+++ b/PermissionController/res/values-hy-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Այլ հավելվածների կառավարում գործակալի միջոցով"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Կատարեք գործողություններ ձեր սարքում և այլ հավելվածներում"</string>
+</resources>
diff --git a/PermissionController/res/values-hy/strings.xml b/PermissionController/res/values-hy/strings.xml
index 7b686e5fb6..bcb062d825 100644
--- a/PermissionController/res/values-hy/strings.xml
+++ b/PermissionController/res/values-hy/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Կանխադրված թվային օգնական"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Թվային օգնականի հավելված"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Օգնական հավելվածներն աշխատում են էկրանին առկա տեղեկությունների հետ: Որոշ հավելվածներ աջակցում են և՛ գործարկիչի, և՛ ձայնային ներածման ծառայությունները, ինչը ավելի լայն հնարավորություններ է տալիս ձեզ:"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Խորհուրդ է տրվում <xliff:g id="OEM_NAME">%s</xliff:g>-ի կողմից"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Դիտարկիչի կանխադրված հավելված"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Դիտարկիչի հավելված"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Հավելվածներ, որոնց միջոցով կարող եք այցելել կայքեր և բացել հղումներ"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Հղումների բացում"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Կանխադրված՝ աշխատանքի համար"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Կանխադրված հավելվածներ մասնավոր տարածքի համար"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Սարքի համար օպտիմալացված"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Այլ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Չկա"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Համակարգի կանխադրված հավելված)"</string>
diff --git a/PermissionController/res/values-in-v33/strings.xml b/PermissionController/res/values-in-v33/strings.xml
index 32f0c44fe5..736464d21d 100644
--- a/PermissionController/res/values-in-v33/strings.xml
+++ b/PermissionController/res/values-in-v33/strings.xml
@@ -19,7 +19,7 @@
     <string name="role_dialer_request_description" msgid="6188305064871543419">"Aplikasi ini akan diizinkan untuk mengirim Notifikasi, dan akan diberi akses ke Kamera, Kontak, Mikrofon, Telepon, dan SMS Anda"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"Aplikasi ini akan diizinkan untuk mengirim Notifikasi, dan akan diberi akses ke Kamera, Kontak, File, Mikrofon, Telepon, dan SMS Anda"</string>
     <string name="permission_description_summary_storage" msgid="1917071243213043858">"Aplikasi yang memiliki izin ini dapat mengakses semua file di perangkat ini"</string>
-    <string name="work_policy_title" msgid="832967780713677409">"Info kebijakan profil kerja Anda"</string>
+    <string name="work_policy_title" msgid="832967780713677409">"Info kebijakan profil kerja"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"Setelan yang dikelola oleh admin IT"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"Luaskan dan tampilkan daftar"</string>
     <string name="safety_center_entry_group_collapse_action" msgid="1525710152244405656">"Ciutkan daftar dan sembunyikan setelan"</string>
diff --git a/PermissionController/res/values-in-v36/strings.xml b/PermissionController/res/values-in-v36/strings.xml
new file mode 100644
index 0000000000..84cc9a10b1
--- /dev/null
+++ b/PermissionController/res/values-in-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Kontrol agen aplikasi lain"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Melakukan tindakan di perangkat Anda dan di aplikasi lain"</string>
+</resources>
diff --git a/PermissionController/res/values-in/strings.xml b/PermissionController/res/values-in/strings.xml
index 2ab28507dd..323d0eb34c 100644
--- a/PermissionController/res/values-in/strings.xml
+++ b/PermissionController/res/values-in/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Aplikasi asisten digital default"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplikasi asisten digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikasi asisten dapat membantu Anda berdasarkan informasi dari layar yang sedang Anda lihat. Beberapa aplikasi mendukung layanan peluncur dan input suara untuk memberikan bantuan terintegrasi."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Direkomendasikan oleh <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Aplikasi browser default"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplikasi browser"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikasi yang memberi Anda akses ke internet dan menampilkan link yang Anda ketuk"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Membuka link"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Default untuk kerja"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Default untuk ruang privasi"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Dioptimalkan untuk perangkat"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Lainnya"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Tidak ada"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Default sistem)"</string>
@@ -662,7 +662,7 @@
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"Pembaruan berbagi data lokasi"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"Tinjau aplikasi yang mengubah caranya berbagi data lokasi Anda"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Aplikasi ini telah mengubah caranya berbagi data lokasi Anda. Aplikasi mungkin sebelumnya tidak membagikan data, atau mungkin kini membagikan data untuk tujuan iklan atau pemasaran."</string>
-    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Developer aplikasi ini memberikan info tentang praktik berbagi data mereka kepada app store. Developer dapat memperbaruinya dari waktu ke waktu.\n\nPraktik berbagi data mungkin berbeda-beda berdasarkan versi aplikasi, penggunaan, wilayah, dan usia Anda."</string>
+    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Developer aplikasi ini memberikan info tentang praktik berbagi data mereka kepada app store. Developer mungkin memperbaruinya dari waktu ke waktu.\n\nPraktik berbagi data mungkin berbeda-beda berdasarkan versi aplikasi, penggunaan, wilayah, dan usia Anda."</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"Pelajari berbagi data"</string>
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"Data lokasi Anda kini dibagikan kepada pihak ketiga"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"Data lokasi Anda kini dibagikan kepada pihak ketiga untuk tujuan iklan atau pemasaran"</string>
@@ -678,7 +678,7 @@
     <string name="allow_restricted_settings" msgid="8073000189478396881">"Izinkan setelan terbatas"</string>
     <string name="enhanced_confirmation_dialog_title" msgid="7562437438040966351">"Setelan terbatas"</string>
     <string name="enhanced_confirmation_dialog_desc" msgid="5921240234843839219">"Demi keamanan Anda, setelan ini tidak tersedia untuk saat ini."</string>
-    <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"Tidak bisa selesaikan tindakan selama panggilan"</string>
+    <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"Tidak bisa menyelesaikan tindakan selama panggilan"</string>
     <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"Setelan ini diblokir untuk melindungi perangkat dan data Anda.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
diff --git a/PermissionController/res/values-is-v36/strings.xml b/PermissionController/res/values-is-v36/strings.xml
new file mode 100644
index 0000000000..878990e5ab
--- /dev/null
+++ b/PermissionController/res/values-is-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Fulltrúastjórnun á öðrum forritum"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Framkvæmdu aðgerðir í tækinu þínu og öðrum forritum"</string>
+</resources>
diff --git a/PermissionController/res/values-is/strings.xml b/PermissionController/res/values-is/strings.xml
index a4872c6b77..7e668ef16c 100644
--- a/PermissionController/res/values-is/strings.xml
+++ b/PermissionController/res/values-is/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Sjálfgefið hjálparaforrit"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Forrit stafræns hjálpara"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aðstoðarforrit geta notað upplýsingar á skjánum til að hjálpa þér. Sum forrit styðja bæði ræsiforrit og raddinntak til að geta veitt þér heildstæða aðstoð."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> mælti með"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Sjálfgefið vafraforrit"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Vafraforrit"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Forrit sem veita þér aðgang að netinu og birta tengla sem þú ýtir á"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Opnun tengla"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Sjálfgefið fyrir vinnu"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Sjálfgefið fyrir leynirými"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Fínstillt fyrir tæki"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Annað"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ekkert"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Sjálfgildi kerfis)"</string>
diff --git a/PermissionController/res/values-it-v36/strings.xml b/PermissionController/res/values-it-v36/strings.xml
new file mode 100644
index 0000000000..ada00b4e23
--- /dev/null
+++ b/PermissionController/res/values-it-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Controllo dell\'agente su altre app"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Esegui azioni sul dispositivo e in altre app"</string>
+</resources>
diff --git a/PermissionController/res/values-it/strings.xml b/PermissionController/res/values-it/strings.xml
index 91404512fd..b9209b1e2a 100644
--- a/PermissionController/res/values-it/strings.xml
+++ b/PermissionController/res/values-it/strings.xml
@@ -348,7 +348,7 @@
     <string name="no_apps_allowed" msgid="7718822655254468631">"Nessuna app autorizzata"</string>
     <string name="no_apps_allowed_full" msgid="8011716991498934104">"Nessuna app autorizzata per tutti i file"</string>
     <string name="no_apps_allowed_scoped" msgid="4908850477787659501">"Nessuna app autorizzata solo per i contenuti multimediali"</string>
-    <string name="no_apps_denied" msgid="7663435886986784743">"A nessuna app è stata negata l\'autorizzazione"</string>
+    <string name="no_apps_denied" msgid="7663435886986784743">"Nessuna app non autorizzata"</string>
     <string name="car_permission_selected" msgid="180837028920791596">"Selezionato"</string>
     <string name="settings" msgid="5409109923158713323">"Impostazioni"</string>
     <string name="accessibility_service_dialog_title_single" msgid="7956432823014102366">"<xliff:g id="SERVICE_NAME">%s</xliff:g> ha accesso completo al tuo dispositivo"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"App assistente digitale predefinita"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App assistente digitale"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Le app di assistenza possono aiutarti in base alle informazioni visualizzate nella schermata attiva. Alcune app supportano sia Avvio app sia servizi di input vocale per offrirti assistenza integrata."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"App consigliate da <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"App browser predefinita"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"App browser"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"App che ti forniscono accesso a Internet e mostrano i link che tocchi."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Apertura link"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predefinite per il lavoro"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Predefinite per lo spazio privato"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Ottimizzate per il dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Altre"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nessuna"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Predefinita)"</string>
@@ -539,7 +539,7 @@
     <string name="permgroupbackgroundrequestdetail_sensors" msgid="7726767635834043501">"Per consentire a questa app di accedere sempre ai dati dei sensori del corpo, anche quando non la usi, "<annotation id="link">"vai alle impostazioni"</annotation>"."</string>
     <string name="permgroupupgraderequest_sensors" msgid="7576527638411370468">"Continuare a consentire a &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; di accedere ai dati dei sensori del corpo mentre l\'app è in uso?"</string>
     <string name="permgroupupgraderequest_device_aware_sensors" msgid="5542771499929819675">"Continuare a consentire a &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ad accedere ai dati dei sensori del corpo mentre è in uso su &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
-    <string name="permgrouprequest_notifications" msgid="6396739062335106181">"Consentire all\'app &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; di inviarti notifiche?"</string>
+    <string name="permgrouprequest_notifications" msgid="6396739062335106181">"Consentire a &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; di inviarti notifiche?"</string>
     <string name="permgrouprequest_device_aware_notifications" msgid="857671638951040514">"Consentire a &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; di inviarti notifiche su &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="auto_granted_permissions" msgid="6009452264824455892">"Autorizzazioni controllate"</string>
     <string name="auto_granted_location_permission_notification_title" msgid="7570818224669050377">"L\'app <xliff:g id="APP_NAME">%1$s</xliff:g> ha accesso alla posizione"</string>
diff --git a/PermissionController/res/values-iw-v33/strings.xml b/PermissionController/res/values-iw-v33/strings.xml
index b8ded16554..7b47c1507f 100644
--- a/PermissionController/res/values-iw-v33/strings.xml
+++ b/PermissionController/res/values-iw-v33/strings.xml
@@ -20,7 +20,7 @@
     <string name="role_sms_request_description" msgid="1506966389698625395">"‏האפליקציה הזו תקבל הרשאה לשלוח לך התראות, וגם תקבל גישה למצלמה, לאנשי הקשר, לקבצים, למיקרופון, לטלפון ול-SMS"</string>
     <string name="permission_description_summary_storage" msgid="1917071243213043858">"לאפליקציות עם ההרשאה הזו יש גישה לקבצים במכשיר"</string>
     <string name="work_policy_title" msgid="832967780713677409">"פרטי המדיניות של פרופיל העבודה"</string>
-    <string name="work_policy_summary" msgid="3886113358084963931">"‏ההגדרות שמנוהלות על ידי מנהל ה-IT"</string>
+    <string name="work_policy_summary" msgid="3886113358084963931">"‏ההגדרות מנוהלות על ידי אדמין ממחלקת IT"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"הרחבה והצגה של הרשימה"</string>
     <string name="safety_center_entry_group_collapse_action" msgid="1525710152244405656">"כיווץ הרשימה והסתרת ההגדרות"</string>
     <string name="safety_center_entry_group_content_description" msgid="7048420958214443333">"רשימה. <xliff:g id="ENTRY_TITLE">%1$s</xliff:g>. <xliff:g id="ENTRY_SUMMARY">%2$s</xliff:g>"</string>
diff --git a/PermissionController/res/values-iw-v34/strings.xml b/PermissionController/res/values-iw-v34/strings.xml
index 61e486e817..70eb889b30 100644
--- a/PermissionController/res/values-iw-v34/strings.xml
+++ b/PermissionController/res/values-iw-v34/strings.xml
@@ -22,5 +22,5 @@
     <string name="health_connect_title" msgid="2132233890867430855">"Health Connect"</string>
     <string name="health_connect_summary" msgid="815473513776882296">"ניהול הגישה של האפליקציות לנתוני בריאות"</string>
     <string name="location_settings" msgid="8863940440881290182">"גישה למיקום"</string>
-    <string name="mic_toggle_description" msgid="1504101620086616040">"לאפליקציות ולשירותים. אם ההגדרה מושבתת, יכול להיות שנתוני המיקרופון ישותפו בכל זאת כשתתבצע שיחה למספר חירום"</string>
+    <string name="mic_toggle_description" msgid="1504101620086616040">"לאפליקציות ולשירותים. גם כשההגדרה מושבתת, הטלפון עשוי לשתף נתונים מהמיקרופון אם תתקשר למספרי חירום"</string>
 </resources>
diff --git a/PermissionController/res/values-iw-v36/strings.xml b/PermissionController/res/values-iw-v36/strings.xml
new file mode 100644
index 0000000000..63a2664dc7
--- /dev/null
+++ b/PermissionController/res/values-iw-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"שליטה של סוכן באפליקציות אחרות"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ביצוע פעולות במכשיר ובאפליקציות אחרות"</string>
+</resources>
diff --git a/PermissionController/res/values-iw/strings.xml b/PermissionController/res/values-iw/strings.xml
index 2ef72b1912..2344a910e2 100644
--- a/PermissionController/res/values-iw/strings.xml
+++ b/PermissionController/res/values-iw/strings.xml
@@ -28,7 +28,7 @@
     <string name="off" msgid="1438489226422866263">"כבוי"</string>
     <string name="uninstall_or_disable" msgid="4496612999740858933">"הסרה או השבתה"</string>
     <string name="app_not_found_dlg_title" msgid="6029482906093859756">"האפליקציה לא נמצאה"</string>
-    <string name="grant_dialog_button_deny" msgid="88262611492697192">"אין אישור"</string>
+    <string name="grant_dialog_button_deny" msgid="88262611492697192">"לא, אף פעם"</string>
     <string name="grant_dialog_button_deny_and_dont_ask_again" msgid="1748925431574312595">"אין אישור ואין צורך לשאול שוב"</string>
     <string name="grant_dialog_button_no_upgrade" msgid="8344732743633736625">"אני רוצה להשאיר את האפשרות \"כשהאפליקציה נמצאת בשימוש\""</string>
     <string name="grant_dialog_button_no_upgrade_one_time" msgid="5125892775684968694">"אני רוצה לשמור על ההגדרה “רק הפעם”"</string>
@@ -102,7 +102,7 @@
     <string name="permission_summary_disabled_by_policy_background_only" msgid="221995005556362660">"הגישה ברקע מושבתת על ידי מדיניות"</string>
     <string name="permission_summary_enabled_by_policy_background_only" msgid="8287675974767104279">"הגישה ברקע מופעלת על ידי מדיניות"</string>
     <string name="permission_summary_enabled_by_policy_foreground_only" msgid="3844582916889767831">"הגישה במצב פעיל מופעלת על ידי מדיניות"</string>
-    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"בשליטת מנהל מערכת"</string>
+    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"בשליטת אדמין"</string>
     <string name="permission_summary_disabled_by_admin_background_only" msgid="3127091456731845646">"הגישה ברקע מושבתת על ידי מנהל מערכת"</string>
     <string name="permission_summary_enabled_by_admin_background_only" msgid="9132423838440275757">"הגישה ברקע מופעלת על ידי מנהל מערכת"</string>
     <string name="permission_summary_enabled_by_admin_foreground_only" msgid="1298432715610745358">"הגישה במצב פעיל מופעלת על ידי מנהל מערכת"</string>
@@ -112,7 +112,7 @@
     <!-- no translation found for background_access_chooser_dialog_choices:2 (4305536986042401191) -->
     <string name="permission_access_always" msgid="1474641821883823446">"כן, כל הזמן"</string>
     <string name="permission_access_only_foreground" msgid="7801170728159326195">"רק כשהאפליקציה בשימוש"</string>
-    <string name="permission_access_never" msgid="4647014230217936900">"אין אישור"</string>
+    <string name="permission_access_never" msgid="4647014230217936900">"לא, אף פעם"</string>
     <string name="loading" msgid="4789365003890741082">"בטעינה…"</string>
     <string name="all_permissions" msgid="6911125611996872522">"כל ההרשאות"</string>
     <string name="other_permissions" msgid="2901186127193849594">"הרשאות אחרות של האפליקציה"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"עוזר דיגיטלי כברירת המחדל"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"אפליקציית עוזר דיגיטלי"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"אפליקציות של עוזרים אישיים יכולות לסייע לפי המידע שמופיע על במסך. יש אפליקציות שתומכות גם בשירותי מרכז אפליקציות וגם בקלט קולי כדי לספק סיוע משולב."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"בהמלצת <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"אפליקציית ברירת מחדל לדפדפן"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"אפליקציית דפדפן"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"אפליקציות שמספקות לך גישה לאינטרנט ומציגות קישורים ללחיצה"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"פתיחת קישורים"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ברירת מחדל לעבודה"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ברירת מחדל עבור המרחב הפרטי"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"מותאמות למכשיר"</string>
     <string name="default_app_others" msgid="7793029848126079876">"אחרות"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ללא"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ברירת מחדל של המערכת)"</string>
@@ -489,7 +489,7 @@
     <string name="permgroupupgraderequestdetail_nearby_devices" msgid="6877531270654738614">"‏לאשר לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; לאתר מכשירים קרובים, להתחבר אליהם ולזהות את מיקומם היחסי? "<annotation id="link">"יש לתת הרשאה בהגדרות"</annotation></string>
     <string name="permgrouprequest_fineupgrade" msgid="2334242928821697672">"לשנות את הרשאת הגישה של <xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g> ממיקום משוער למיקום מדויק?"</string>
     <string name="permgrouprequest_device_aware_fineupgrade" msgid="4453775952305587571">"‏לשנות את הרשאת הגישה של האפליקציה <xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g> למיקום במכשיר &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>‏&lt;/b&gt; מ\'מיקום משוער\' ל\'מיקום מדויק\'?"</string>
-    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאת גישה למיקום המשוער של המכשיר?"</string>
+    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"‏לאשר לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; לגשת למיקום המשוער של המכשיר?"</string>
     <string name="permgrouprequest_device_aware_coarselocation" msgid="8367540370912066757">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאת גישה למיקום המשוער של &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"מדויק"</string>
     <string name="permgrouprequest_coarselocation_imagetext" msgid="8650605041483025297">"משוער"</string>
@@ -503,7 +503,7 @@
     <string name="permgrouprequest_storage_pre_q" msgid="168130651144569428">"‏לתת לאפליקציה ‎&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‎‏ הרשאת גישה ‎&lt;b&gt;‎‏לתמונות, לסרטונים, למוזיקה, לאודיו ולקבצים אחרים‎&lt;/b&gt;‎‏ במכשיר?"</string>
     <string name="permgrouprequest_read_media_aural" msgid="2593365397347577812">"‏לתת לאפליקציה ‎&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‎‏ הרשאת גישה למוזיקה ולקובצי אודיו במכשיר?"</string>
     <string name="permgrouprequest_device_aware_read_media_aural" msgid="7927884506238101064">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאת גישה למוזיקה ולאודיו במכשיר &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
-    <string name="permgrouprequest_read_media_visual" msgid="5548780620779729975">"‏לתת לאפליקציה ‎&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‎‏ הרשאת גישה לתמונות ולסרטונים במכשיר?"</string>
+    <string name="permgrouprequest_read_media_visual" msgid="5548780620779729975">"‏לאשר לאפליקציה ‎&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‎‏ לגשת לתמונות ולסרטונים במכשיר?"</string>
     <string name="permgrouprequest_device_aware_read_media_visual" msgid="3122576538319059333">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאת גישה לתמונות ולסרטונים במכשיר &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequest_more_photos" msgid="128933814654231321">"‏לתת לאפליקציה ‎&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‎‏ הרשאת גישה לתמונות ולסרטונים נוספים במכשיר?"</string>
     <string name="permgrouprequest_device_aware_more_photos" msgid="1703469013613723053">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאת גישה לעוד תמונות וסרטונים במכשיר &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
@@ -539,7 +539,7 @@
     <string name="permgroupbackgroundrequestdetail_sensors" msgid="7726767635834043501">"כדי לאפשר לאפליקציה הזו לגשת לנתונים של החיישנים הגופניים כל הזמן, גם כשהיא לא בשימוש, "<annotation id="link">"צריך להיכנס להגדרות."</annotation></string>
     <string name="permgroupupgraderequest_sensors" msgid="7576527638411370468">"‏להמשיך לאפשר לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; לגשת לנתונים של חיישני גוף כשהיא נמצאת בשימוש?"</string>
     <string name="permgroupupgraderequest_device_aware_sensors" msgid="5542771499929819675">"‏להמשיך לאפשר לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; לגשת לנתוני החיישנים הגופניים במכשיר &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; כשהאפליקציה בשימוש?"</string>
-    <string name="permgrouprequest_notifications" msgid="6396739062335106181">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאה לשלוח לך התראות?"</string>
+    <string name="permgrouprequest_notifications" msgid="6396739062335106181">"‏לאשר לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; לשלוח לך התראות?"</string>
     <string name="permgrouprequest_device_aware_notifications" msgid="857671638951040514">"‏לתת לאפליקציה &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; הרשאה לשלוח לך התראות במכשיר &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="auto_granted_permissions" msgid="6009452264824455892">"הרשאות בבקרה"</string>
     <string name="auto_granted_location_permission_notification_title" msgid="7570818224669050377">"לאפליקציה <xliff:g id="APP_NAME">%1$s</xliff:g> יש הרשאת גישה למיקום"</string>
@@ -635,9 +635,9 @@
     <string name="mic_toggle_description" msgid="9163104307990677157">"לאפליקציות ולשירותים. אם ההגדרה מושבתת, ייתכן שנתוני המיקרופון ישותפו כשתתבצע שיחה למספר חירום."</string>
     <string name="location_settings_subtitle" msgid="2328360561197430695">"הצגת אפליקציות ושירותים שיש להם גישה למיקום"</string>
     <string name="show_clip_access_notification_title" msgid="5168467637351109096">"הצגת גישה ללוח העריכה"</string>
-    <string name="show_clip_access_notification_summary" msgid="3532020182782112687">"הצגת הודעה בזמן גישה של אפליקציות לטקסט, לתמונות או לכל תוכן אחר שהעתקת"</string>
+    <string name="show_clip_access_notification_summary" msgid="3532020182782112687">"הצגת הודעה כשאפליקציות ניגשות לטקסט, לתמונות או לתכנים אחרים שהעתקת"</string>
     <string name="show_password_title" msgid="2877269286984684659">"הצגת סיסמאות"</string>
-    <string name="show_password_summary" msgid="1110166488865981610">"התווים יופיעו לפרקי זמן קצרים בזמן ההקלדה"</string>
+    <string name="show_password_summary" msgid="1110166488865981610">"התווים יופיעו לכמה רגעים כשאתה מקליד"</string>
     <string name="permission_rationale_message_location" msgid="2153841534298068414">"האפליקציה הזו הצהירה שהיא עשויה לשתף נתוני מיקום עם צדדים שלישיים"</string>
     <string name="permission_rationale_location_title" msgid="2404797182678793506">"שיתוף נתונים ומיקום"</string>
     <string name="permission_rationale_data_sharing_source_title" msgid="6874604543125814316">"מאיפה מגיע המידע לגבי שיתוף הנתונים"</string>
@@ -660,7 +660,7 @@
     <string name="app_location_permission_rationale_title" msgid="925420340572401350">"ייתכן שנתוני המיקום ישותפו"</string>
     <string name="app_location_permission_rationale_subtitle" msgid="6986985722752868692">"מפתחי האפליקציה הזו הצהירו שהאפליקציה עשויה לשתף את נתוני המיקום שלך עם צדדים שלישיים"</string>
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"עדכונים לגבי שיתוף נתוני מיקום"</string>
-    <string name="data_sharing_updates_summary" msgid="764113985772233889">"בדיקת אפליקציות שהדרך שלהן לשתף נתוני מיקום השתנתה"</string>
+    <string name="data_sharing_updates_summary" msgid="764113985772233889">"בדוק את האפליקציות ששינו את שיתוף נתוני המיקום"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"באפליקציות האלה, השתנה האופן שבו הן עשויות לשתף את נתוני המיקום שלך. יכול להיות שהן לא שיתפו את הנתונים האלה בעבר, או שעכשיו הן משתפות את נתוני המיקום לצורכי פרסום ושיווק."</string>
     <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"המפתחים של האפליקציות האלה סיפקו מידע לגבי האופן שבו הנתונים משותפים עם חנות אפליקציות. המידע עשוי להתעדכן עם הזמן.\n\nנוהלי שיתוף הנתונים עשויים להשתנות בהתאם לגרסת האפליקציה, לשימוש בה, לאזור ולגיל המשתמש."</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"מידע נוסף על שיתוף נתונים"</string>
@@ -678,11 +678,11 @@
     <string name="allow_restricted_settings" msgid="8073000189478396881">"הרשאה להגדרות מוגבלות"</string>
     <string name="enhanced_confirmation_dialog_title" msgid="7562437438040966351">"הגדרה מוגבלת"</string>
     <string name="enhanced_confirmation_dialog_desc" msgid="5921240234843839219">"מטעמי אבטחה, ההגדרה הזו לא זמינה כרגע."</string>
-    <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"אי אפשר להשלים את הפעולה במהלך שיחה"</string>
+    <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"זאת פעולה שאי אפשר לעשות בזמן שיחה"</string>
     <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"ההגדרה הזו חסומה כדי להגן על המכשיר ועל הנתונים שלך.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
-</xliff:g>רמאים שינסו לגרום לך להתקין אפליקציות מזיקות יבקשו ממך להתקין אפליקציות לא ידועות ממקור חדש."</string>
+</xliff:g> בקשה להתקין אפליקציה לא מוכרת ממקום חדש יכולה להיות ניסיון של רמאים לגרום לך להתקין תוכנה מזיקה."</string>
     <string name="enhanced_confirmation_phone_state_dialog_a11y_desc" msgid="6567523001053288057">"<xliff:g id="EMPTY_LINE">
 
 </xliff:g>רמאים שירצו להשתלט על המכשיר שלך יבקשו ממך לתת לאפליקציה גישה לשירות הנגישות."</string>
diff --git a/PermissionController/res/values-ja-v36/strings.xml b/PermissionController/res/values-ja-v36/strings.xml
new file mode 100644
index 0000000000..c19ef02fb8
--- /dev/null
+++ b/PermissionController/res/values-ja-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"他のアプリのエージェントのコントロール"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"デバイスと他のアプリで操作を実行します"</string>
+</resources>
diff --git a/PermissionController/res/values-ja/strings.xml b/PermissionController/res/values-ja/strings.xml
index 4b3ad4ac1e..7949a235e9 100644
--- a/PermissionController/res/values-ja/strings.xml
+++ b/PermissionController/res/values-ja/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"デフォルトのデジタル アシスタント アプリ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"デジタル アシスタント アプリ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"アシストアプリは、表示している画面の情報に基づいてサポートを提供します。一部のアプリはランチャーと音声入力サービスの両方に対応しており、統合されたサポートを提供します。"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> がおすすめするアプリ"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"デフォルトのブラウザアプリ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ブラウザアプリ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"インターネットにアクセスするためのアプリです。タップしたリンクは、このアプリで開きます。"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"リンクを開く"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"デフォルトの仕事用アプリ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"プライベート スペースのデフォルト"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"デバイス向けに最適化"</string>
     <string name="default_app_others" msgid="7793029848126079876">"その他"</string>
     <string name="default_app_none" msgid="9084592086808194457">"なし"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"（システムのデフォルト）"</string>
@@ -507,7 +507,7 @@
     <string name="permgrouprequest_device_aware_read_media_visual" msgid="3122576538319059333">"&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;内の写真と動画へのアクセスを &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; に許可しますか？"</string>
     <string name="permgrouprequest_more_photos" msgid="128933814654231321">"このデバイス内の他の写真や動画へのアクセスを &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; に許可しますか？"</string>
     <string name="permgrouprequest_device_aware_more_photos" msgid="1703469013613723053">"&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;内のその他の写真や動画へのアクセスを &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; に許可しますか？"</string>
-    <string name="permgrouprequest_microphone" msgid="2825208549114811299">"音声の録音を「&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;」に許可しますか？"</string>
+    <string name="permgrouprequest_microphone" msgid="2825208549114811299">"音声の録音を &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; に許可しますか？"</string>
     <string name="permgrouprequest_device_aware_microphone" msgid="8821701550505437951">"&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;での録音を &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; に許可しますか？"</string>
     <string name="permgrouprequestdetail_microphone" msgid="8510456971528228861">"アプリは、ユーザーがアプリを使用している場合のみ音声を録音できます"</string>
     <string name="permgroupbackgroundrequest_microphone" msgid="8874462606796368183">"音声の録音を &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; に許可しますか？"</string>
diff --git a/PermissionController/res/values-ka-v36/strings.xml b/PermissionController/res/values-ka-v36/strings.xml
new file mode 100644
index 0000000000..a3e14f4bab
--- /dev/null
+++ b/PermissionController/res/values-ka-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"სხვა აპების აგენტის კონტროლი"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"მოქმედებების შესრულება თქვენს მოწყობილობასა და სხვა აპებში"</string>
+</resources>
diff --git a/PermissionController/res/values-ka/strings.xml b/PermissionController/res/values-ka/strings.xml
index 5023926dd2..b6c4f7689b 100644
--- a/PermissionController/res/values-ka/strings.xml
+++ b/PermissionController/res/values-ka/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ნაგულისხმ. ციფრული ასისტ. აპი"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ციფრული ასისტენტის აპი"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"დახმარების აპებს შეუძლიათ დაგეხმარონ იმ ეკრანიდან მიღებულ ინფორმაციაზე დაყრდნობით, რომელსაც ათვალიერებთ. ზოგიერთი აპის მიერ მხარდაჭერილია როგორც გამშვები, ისე ხმოვანი შეყვანის სერვისები, თქვენთვის კომპლექსური დახმარების გასაწევად."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g>-ის მიერ რეკომენდებული"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ნაგულისხმევი ბრაუზერის აპი"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ბრაუზერის აპი"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"აპები, რომლებიც გაძლევენ წვდომას ინტერნეტზე და გაჩვენებენ ბმულებს, რომლებსაც ეხებით"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ბმულების გახსნა"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ნაგულისხმევი სამსახურისთვის"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"კერძო სივრცისთვის ნაგულისხმევი აპები"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ოპტიმიზებულია მოწყობილობისთვის"</string>
     <string name="default_app_others" msgid="7793029848126079876">"სხვა"</string>
     <string name="default_app_none" msgid="9084592086808194457">"არცერთი"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(სისტემის ნაგულისხმევი)"</string>
diff --git a/PermissionController/res/values-kk-v36/strings.xml b/PermissionController/res/values-kk-v36/strings.xml
new file mode 100644
index 0000000000..2350cdfabe
--- /dev/null
+++ b/PermissionController/res/values-kk-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Басқа қолданбаларға агенттік бақылау жүргізу"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Құрылғыңыздағы және басқа қолданбалардағы әрекеттерді орындаңыз."</string>
+</resources>
diff --git a/PermissionController/res/values-kk/strings.xml b/PermissionController/res/values-kk/strings.xml
index 98e27352df..5231cd2d57 100644
--- a/PermissionController/res/values-kk/strings.xml
+++ b/PermissionController/res/values-kk/strings.xml
@@ -56,7 +56,7 @@
     <string name="grant_dialog_button_change_to_precise_location" msgid="3273115879467236033">"Нақты локацияға ауысу"</string>
     <string name="grant_dialog_button_keey_approximate_location" msgid="438025182769080011">"Болжалды локацияны қалдыру"</string>
     <string name="grant_dialog_button_allow_one_time" msgid="2618088516449706391">"Тек осы жолы"</string>
-    <string name="grant_dialog_button_allow_background" msgid="8236044729434367833">"Біржола рұқсат ету"</string>
+    <string name="grant_dialog_button_allow_background" msgid="8236044729434367833">"Біржола рұқсат беру"</string>
     <string name="grant_dialog_button_allow_all_files" msgid="4955436994954829894">"Барлық файлдарды басқаруға рұқсат беру"</string>
     <string name="grant_dialog_button_allow_media_only" msgid="4832877658422573832">"Медиафайлдарды пайдалануға рұқсат беру"</string>
     <string name="app_permissions_breadcrumb" msgid="5136969550489411650">"Қолданбалар"</string>
@@ -200,8 +200,8 @@
     <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g> рұқсаты"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"<xliff:g id="PERM">%1$s</xliff:g>: осы қолданбаның рұқсаты"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"Құрылғыдағы (<xliff:g id="DEVICE_NAME">%2$s</xliff:g>) осы қолданбаның рұқсаты: <xliff:g id="PERM">%1$s</xliff:g>"</string>
-    <string name="app_permission_footer_app_permissions_link" msgid="4926890342636587393">"Барлық <xliff:g id="APP">%1$s</xliff:g> рұқсаттарын көру"</string>
-    <string name="app_permission_footer_permission_apps_link" msgid="3941988129992794327">"Осы рұқсатқа ие барлық қолданбаларды көру"</string>
+    <string name="app_permission_footer_app_permissions_link" msgid="4926890342636587393">"Барлық <xliff:g id="APP">%1$s</xliff:g> рұқсатын көру"</string>
+    <string name="app_permission_footer_permission_apps_link" msgid="3941988129992794327">"Осы рұқсатқа ие барлық қолданбаны көру"</string>
     <string name="app_permission_info_button" msgid="8973692370208562556">"Ақпарат"</string>
     <string name="app_permission_settings_button" msgid="4582916817451973752">"Параметрлер"</string>
     <string name="assistant_mic_label" msgid="1011432357152323896">"Assistant микрофонының пайдаланылуын көрсету"</string>
@@ -254,7 +254,7 @@
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"Тыйым салынған/Ешқашан пайдаланбаған"</string>
     <string name="allowed_header" msgid="7769277978004790414">"Рұқсат берілгендер"</string>
     <string name="allowed_always_header" msgid="6455903312589013545">"Біржола рұқсат берілген"</string>
-    <string name="allowed_foreground_header" msgid="6845655788447833353">"Пайдаланғанда ғана рұқсат берілгендер"</string>
+    <string name="allowed_foreground_header" msgid="6845655788447833353">"Пайдаланғанда ғана рұқсат берілген"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"Тек мультимедианы пайдалана алатын қолданбалар"</string>
     <string name="allowed_storage_full" msgid="5356699280625693530">"Барлық файлдарды басқара алатын қолданбалар"</string>
     <string name="ask_header" msgid="2633816846459944376">"Әрдайым сұрау"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Әдепкі цифрлық көмекші қолданбасы"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Цифрлық көмекші қолданбасы"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Көмекші қолданбалар ашық тұрған экрандағы ақпарат бойынша көмек бере алады. Кейбір қолданбалар қосымша көмек ретінде іске қосу құралын да, дауыспен енгізу қызметтерін де пайдаланады."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> ұсынған"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Әдепкі браузер қолданбасы"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Браузер қолданбасы"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Интернетке кіруге мүмкіндік беретін және түртілген сілтемелерді көрсететін қолданбалар"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Сілтемелер ашу"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Жұмыс үшін әдепкі қолданба"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Құпия кеңістікке арналған әдепкі қолданбалар"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Құрылғы үшін оңтайландырылған"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Басқа"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Жоқ"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(жүйенің әдепкі қолданбасы)"</string>
@@ -573,7 +573,7 @@
     <string name="automotive_required_app_title" msgid="2992168288249988735">"Осы қолданба қажет"</string>
     <string name="automotive_required_app_summary" msgid="6514902316658090465">"Осы қолданба көлік өндірушісі үшін қажет."</string>
     <string name="safety_center_dashboard_page_title" msgid="2810774008694315854">"Қауіпсіздік және құпиялық"</string>
-    <string name="safety_center_rescan_button" msgid="4517514567809409596">"Құрылғыны тексеру"</string>
+    <string name="safety_center_rescan_button" msgid="4517514567809409596">"Құрылғыны сканерлеу"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"Жабу"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"Осы хабарландыруды жабу керек пе?"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Қорғаныс деңгейін арттыру үшін қауіпсіздік пен құпиялық параметрлерін кез келген уақытта қарап шығыңыз."</string>
@@ -659,7 +659,7 @@
     <string name="app_permission_rationale_message" msgid="8511466916077100713">"Дерек қауіпсіздігі"</string>
     <string name="app_location_permission_rationale_title" msgid="925420340572401350">"Локация деректері жіберілуі мүмкін."</string>
     <string name="app_location_permission_rationale_subtitle" msgid="6986985722752868692">"Бұл қолданба локация деректеріңізді үшінші тараптармен бөлісе алатынын мәлімдеді."</string>
-    <string name="data_sharing_updates_title" msgid="7996933386875213859">"Локация деректерін бөлісу жаңартулары"</string>
+    <string name="data_sharing_updates_title" msgid="7996933386875213859">"Локация деректерін бөлісудегі өзгерістер"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"Локация деректеріңізді бөлісу жолын өзгерткен қолданбаларды тексеру"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Осы қолданбалар локация деректерін бөлісу жолын өзгертті. Олар деректерді бұрын бөліспей, енді жарнамалау не маркетинг үшін бөлісуі мүмкін."</string>
     <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Бұл қолданбалардың әзірлеушілері App Store дүкенінде өздерінің деректерді бөлісу тәртібі туралы ақпарат берді. Олар уақыт өте келе оны жаңарта алады.\n\nДеректерді бөлісу тәртібі қолданбаңыздың нұсқасына, пайдаланылуына, аймағыңыз бен жасыңызға байланысты әртүрлі болуы мүмкін."</string>
@@ -667,7 +667,7 @@
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"Енді локация деректеріңіз үшінші тараптарға жіберіледі."</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"Енді геодерегіңіз жарнамалау не маркетинг мақсатында үшінші тараптарға жіберіледі."</string>
     <string name="updated_in_last_days" msgid="8371811947153042322">"{count,plural, =0{Соңғы күні жаңартылды}=1{Соңғы күні жаңартылды}other{Соңғы # күн ішінде жаңартылды}}"</string>
-    <string name="no_updates_at_this_time" msgid="9031085635689982935">"Әзірге ешқандай жаңарту жоқ."</string>
+    <string name="no_updates_at_this_time" msgid="9031085635689982935">"Әзірге ешқандай өзгеріс жоқ"</string>
     <string name="safety_label_changes_notification_title" msgid="4479955083472203839">"Деректерді бөлісуге қатысты жаңалық"</string>
     <string name="safety_label_changes_notification_desc" msgid="7808764283266234675">"Кейбір қолданбалар локация деректеріңізді бөлісу жолын өзгертті."</string>
     <string name="safety_label_changes_gear_description" msgid="2655887555599138509">"Параметрлер"</string>
diff --git a/PermissionController/res/values-km-v36/strings.xml b/PermissionController/res/values-km-v36/strings.xml
new file mode 100644
index 0000000000..d2b5bcca0e
--- /dev/null
+++ b/PermissionController/res/values-km-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"ការគ្រប់គ្រងភ្នាក់ងាររបស់កម្មវិធីផ្សេងទៀត"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ធ្វើសកម្មភាពនៅលើឧបករណ៍របស់អ្នក និងនៅក្នុងកម្មវិធីផ្សេងទៀត"</string>
+</resources>
diff --git a/PermissionController/res/values-km/strings.xml b/PermissionController/res/values-km/strings.xml
index cf7a5e6d25..abf54862e4 100644
--- a/PermissionController/res/values-km/strings.xml
+++ b/PermissionController/res/values-km/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"កម្មវិធីជំនួយការឌីជីថលលំនាំដើម"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"កម្មវិធីជំនួយការ​ឌីជីថល"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"កម្មវិធីជំនួយអាចជួយអ្នកដោយផ្អែកលើព័ត៌មានពីអេក្រង់ដែលអ្នកកំពុងមើល។ កម្មវិធីមួយចំនួនអាចប្រើបាន​ទាំង​កម្មវិធី​ចាប់ផ្ដើម និងសេវាកម្ម​បញ្ចូលសំឡេង ដើម្បី​ផ្ដល់ជំនួយ​រួមគ្នាដល់អ្នក។"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"បាន​ណែនាំដោយ <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"កម្មវិធីរុករកតាមអ៊ីនធឺណិតលំនាំដើម"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"កម្មវិធីរុករកតាមអ៊ីនធឺណិត"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"កម្មវិធី​ដែលផ្ដល់លទ្ធភាព​ឱ្យអ្នក​ចូលប្រើ​អ៊ីនធឺណិត និងបង្ហាញតំណ​ដែលអ្នកចុច"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ការបើកតំណ"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"លំនាំដើម​សម្រាប់ការងារ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"លំនាំដើមសម្រាប់លំហឯកជន"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"បានបង្កើនប្រសិទ្ធភាពសម្រាប់ឧបករណ៍"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ផ្សេងទៀត"</string>
     <string name="default_app_none" msgid="9084592086808194457">"គ្មាន"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(លំនាំដើមប្រព័ន្ធ)"</string>
diff --git a/PermissionController/res/values-kn-v36/strings.xml b/PermissionController/res/values-kn-v36/strings.xml
new file mode 100644
index 0000000000..fa88683388
--- /dev/null
+++ b/PermissionController/res/values-kn-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"ಇತರ ಆ್ಯಪ್‌ಗಳ ಏಜೆಂಟ್ ನಿಯಂತ್ರಣ"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ನಿಮ್ಮ ಸಾಧನದಲ್ಲಿ ಮತ್ತು ಇತರ ಆ್ಯಪ್‌ಗಳಲ್ಲಿ ಕ್ರಿಯೆಗಳನ್ನು ಮಾಡಿ"</string>
+</resources>
diff --git a/PermissionController/res/values-kn/strings.xml b/PermissionController/res/values-kn/strings.xml
index 7d3c0ebb11..b45d921bf3 100644
--- a/PermissionController/res/values-kn/strings.xml
+++ b/PermissionController/res/values-kn/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ಡೀಫಾಲ್ಟ್ ಡಿಜಿಟಲ್ ಅಸಿಸ್ಟೆಂಟ್ ಆ್ಯಪ್"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ಡಿಜಿಟಲ್ ಅಸಿಸ್ಟೆಂಟ್ ಆ್ಯಪ್"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"ನೀವು ವೀಕ್ಷಿಸುತ್ತಿರುವ ಸ್ಕ್ರೀನ್‌ನ ಮಾಹಿತಿಯನ್ನು ಆಧರಿಸಿ ಅಸಿಸ್ಟೆಂಟ್ ಆ್ಯಪ್‌ಗಳು ನಿಮಗೆ ಸಹಾಯ ಮಾಡಬಹುದು. ಕೆಲವು ಆ್ಯಪ್‌ಗಳು ನಿಮಗೆ ಸಂಪೂರ್ಣ ಸಹಾಯವನ್ನು ಒದಗಿಸಲು ಲಾಂಚರ್ ಮತ್ತು ಧ್ವನಿ ಇನ್‌ಪುಟ್ ಸೇವೆಗಳೆರಡನ್ನೂ ಬೆಂಬಲಿಸುತ್ತವೆ."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> ನಿಂದ ಶಿಫಾರಸು ಮಾಡಲಾಗಿದೆ"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ಡೀಫಾಲ್ಟ್ ಬ್ರೌಸರ್ ಆ್ಯಪ್"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ಬ್ರೌಸರ್ ಆ್ಯಪ್"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ಇಂಟರ್ನೆಟ್‌ಗೆ ಮತ್ತು ನೀವು ಟ್ಯಾಪ್ ಮಾಡುವ ಲಿಂಕ್‌ಗಳನ್ನು ಪ್ರದರ್ಶಿಸಲು ನಿಮಗೆ ಪ್ರವೇಶವನ್ನು ನೀಡುವ ಆ್ಯಪ್‌ಗಳು"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ಲಿಂಕ್‍‍ಗಳನ್ನು ತೆರೆಯುವುದು"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ಕೆಲಸದ ಕುರಿತಾದ ಡೀಫಾಲ್ಟ್ ಆ್ಯಪ್"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ನ ಡೀಫಾಲ್ಟ್"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ಸಾಧನಕ್ಕಾಗಿ ಆಪ್ಟಿಮೈಸ್ ಮಾಡಲಾಗಿದೆ"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ಇತರೆ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ಯಾವುದೂ ಬೇಡ"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ಸಿಸ್ಟಂ ಡಿಫಾಲ್ಟ್)"</string>
diff --git a/PermissionController/res/values-ko-v36/strings.xml b/PermissionController/res/values-ko-v36/strings.xml
new file mode 100644
index 0000000000..16d36dd931
--- /dev/null
+++ b/PermissionController/res/values-ko-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"다른 앱의 에이전트 제어"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"기기 및 다른 앱에서 작업 수행"</string>
+</resources>
diff --git a/PermissionController/res/values-ko/strings.xml b/PermissionController/res/values-ko/strings.xml
index db11b5a4e5..3b75d15d26 100644
--- a/PermissionController/res/values-ko/strings.xml
+++ b/PermissionController/res/values-ko/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"기본 디지털 어시스턴트 앱"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"디지털 어시스턴트 앱"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"지원 앱은 화면에 표시된 정보를 기반으로 도움을 줄 수 있습니다. 일부 앱은 통합된 지원을 제공하기 위해 런처와 음성 입력 서비스를 모두 지원합니다."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> 추천"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"기본 브라우저 앱"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"브라우저 앱"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"인터넷에 액세스하고 탭하는 링크를 표시하는 앱"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"링크 열기"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"직장용 기본 앱"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"비공개 스페이스의 기본값"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"기기에 최적화된 앱"</string>
     <string name="default_app_others" msgid="7793029848126079876">"기타"</string>
     <string name="default_app_none" msgid="9084592086808194457">"없음"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(시스템 기본값)"</string>
diff --git a/PermissionController/res/values-ky-v36/strings.xml b/PermissionController/res/values-ky-v36/strings.xml
new file mode 100644
index 0000000000..00880148e4
--- /dev/null
+++ b/PermissionController/res/values-ky-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Башка колдонмолордун агенттерин көзөмөлдөө"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Түзмөгүңүздө жана башка колдонмолордо аракеттерди аткарыңыз"</string>
+</resources>
diff --git a/PermissionController/res/values-ky/strings.xml b/PermissionController/res/values-ky/strings.xml
index aff6ed8d5a..a14bdfee18 100644
--- a/PermissionController/res/values-ky/strings.xml
+++ b/PermissionController/res/values-ky/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Демейки санариптик жардамчы"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Санариптик жардамчы колдонмосу"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Көмөкчү колдонмолор экранда көргөн маалыматыңыздын негизинде сизге жардам бере алат. Айрым колдонмолор жүргүзгүчтү жана айтып киргизүү функциясын да колдоого алат."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> сунуштаган"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Демейки серепчи"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Серепчи колдонмосу"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Сайттарга кирип, шилтемелер боюнча өткөнгө мүмкүнчүлүк берген колдонмолор."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Шилтемелерди ачуу"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Жумуш үчүн демейки жөндөөлөр"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Жеке мейкиндик үчүн демейки колдонмолор"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Түзмөккө оптималдаштырылды"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Башкалар"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Жок"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Демейки тутум)"</string>
diff --git a/PermissionController/res/values-lo-v33/strings.xml b/PermissionController/res/values-lo-v33/strings.xml
index 16b913cec9..6575b64514 100644
--- a/PermissionController/res/values-lo-v33/strings.xml
+++ b/PermissionController/res/values-lo-v33/strings.xml
@@ -19,7 +19,7 @@
     <string name="role_dialer_request_description" msgid="6188305064871543419">"ແອັບນີ້ຈະໄດ້ຮັບອະນຸຍາດເພື່ອສົ່ງການແຈ້ງເຕືອນຫາທ່ານ ແລະ ຈະໄດ້ຮັບສິດເຂົ້າເຖິງກ້ອງຖ່າຍຮູບ, ລາຍຊື່ຜູ້ຕິດຕໍ່, ໄມໂຄຣໂຟນ, ໂທລະສັບ ແລະ SMS ຂອງທ່ານ"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"ແອັບນີ້ຈະໄດ້ຮັບອະນຸຍາດເພື່ອສົ່ງການແຈ້ງເຕືອນຫາທ່ານ ແລະ ຈະໄດ້ຮັບສິດເຂົ້າເຖິງກ້ອງຖ່າຍຮູບ, ລາຍຊື່ຜູ້ຕິດຕໍ່, ໄຟລ໌, ໄມໂຄຣໂຟນ, ໂທລະສັບ ແລະ SMS ຂອງທ່ານ"</string>
     <string name="permission_description_summary_storage" msgid="1917071243213043858">"ແອັບທີ່ມີການອະນຸຍາດນີ້ຈະສາມາດເຂົ້າເຖິງໄຟລ໌ທັງໝົດຢູ່ອຸປະກອນນີ້ໄດ້"</string>
-    <string name="work_policy_title" msgid="832967780713677409">"ຂໍ້ມູນນະໂຍບາຍວຽກຂອງທ່ານ"</string>
+    <string name="work_policy_title" msgid="832967780713677409">"ຂໍ້ມູນນະໂຍບາຍບ່ອນເຮັດວຽກຂອງທ່ານ"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"ການຕັ້ງຄ່າແມ່ນຈັດການໂດຍຜູ້ເບິ່ງແຍງໄອທີຂອງທ່ານ"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"ຂະຫຍາຍ ແລະ ສະແດງລາຍການ"</string>
     <string name="safety_center_entry_group_collapse_action" msgid="1525710152244405656">"ຫຍໍ້ລາຍການລົງ ແລະ ເຊື່ອງການຕັ້ງຄ່າໄວ້"</string>
diff --git a/PermissionController/res/values-lo-v36/strings.xml b/PermissionController/res/values-lo-v36/strings.xml
new file mode 100644
index 0000000000..6c840a796c
--- /dev/null
+++ b/PermissionController/res/values-lo-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"ຕົວແທນການຄວບຄຸມແອັບອື່ນໆ"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ດຳເນີນຄຳສັ່ງຢູ່ອຸປະກອນຂອງທ່ານ ແລະ ໃນແອັບອື່ນໆ"</string>
+</resources>
diff --git a/PermissionController/res/values-lo/strings.xml b/PermissionController/res/values-lo/strings.xml
index 63a157593d..87cc01c868 100644
--- a/PermissionController/res/values-lo/strings.xml
+++ b/PermissionController/res/values-lo/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ແອັບຜູ້ຊ່ວຍດິຈິຕອນເລີ່ມຕົ້ນ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ແອັບຜູ້ຊ່ວຍດິຈິຕອນ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"ແອັບຜູ້ຊ່ວຍສາມາດຊ່ວຍທ່ານໄດ້ໂດຍອ້າງອີງຕາມຂໍ້ມູນຈາກໜ້າຈໍທີ່ທ່ານກຳລັງເບິ່ງ. ບາງແອັບຮອງຮັບທັງການບໍລິການຕົວເປີດນຳໃຊ້ ແລະ ການປ້ອນສຽງເພື່ອໃຫ້ການຊ່ວຍເຫຼືອທີ່ເຊື່ອມໂຍງໄດ້."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"ແນະນຳໂດຍ <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ແອັບທ່ອງເວັບເລີ່ມຕົ້ນ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ແອັບໂປຣແກຣມທ່ອງເວັບ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ແອັບທີ່ໃຫ້ສິດອະນຸຍາດທ່ານເຂົ້າເຖິງອິນເຕີເນັດ ແລະ ສະແດງລິ້ງທີ່ທ່ານແຕະໃສ່"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ການເປີດລິ້ງ"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ຄ່າເລີ່ມຕົ້ນສຳລັບບ່ອນເຮັດວຽກ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ຄ່າເລີ່ມຕົ້ນສຳລັບພື້ນທີ່ສ່ວນບຸກຄົນ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ໄດ້ຮັບການເພີ່ມປະສິດທິພາບສຳລັບອຸປະກອນ"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ອື່ນໆ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ບໍ່ມີ"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ຄ່າເລີ່ມຕົ້ນຂອງລະບົບ)"</string>
diff --git a/PermissionController/res/values-lt-v36/strings.xml b/PermissionController/res/values-lt-v36/strings.xml
new file mode 100644
index 0000000000..b1a5edc138
--- /dev/null
+++ b/PermissionController/res/values-lt-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Kitų programų valdymas naudojant tarpininką"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Atlikti veiksmus jūsų įrenginyje ir kitose programose"</string>
+</resources>
diff --git a/PermissionController/res/values-lt/strings.xml b/PermissionController/res/values-lt/strings.xml
index 0000f2c116..722b0783e3 100644
--- a/PermissionController/res/values-lt/strings.xml
+++ b/PermissionController/res/values-lt/strings.xml
@@ -200,7 +200,7 @@
     <string name="app_permission_title" msgid="2090897901051370711">"Leidimas: <xliff:g id="PERM">%1$s</xliff:g>"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"<xliff:g id="PERM">%1$s</xliff:g>: šios programos prieiga"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"<xliff:g id="PERM">%1$s</xliff:g> prieiga šiai programai „<xliff:g id="DEVICE_NAME">%2$s</xliff:g>“"</string>
-    <string name="app_permission_footer_app_permissions_link" msgid="4926890342636587393">"Žr. visus „<xliff:g id="APP">%1$s</xliff:g>“ leidimus"</string>
+    <string name="app_permission_footer_app_permissions_link" msgid="4926890342636587393">"Žr. visus leidimus: <xliff:g id="APP">%1$s</xliff:g>"</string>
     <string name="app_permission_footer_permission_apps_link" msgid="3941988129992794327">"Žr. visas programas, kurioms suteiktas šis leidimas"</string>
     <string name="app_permission_info_button" msgid="8973692370208562556">"Informacija"</string>
     <string name="app_permission_settings_button" msgid="4582916817451973752">"Nustatymai"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Numat. skaitm. pagelbiklio pr."</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Skaitmeninio pagelbik. pr."</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Pagalbinė programa gali padėti atsižvelgdama į peržiūrimo ekrano informaciją. Kai kurios programos palaiko tiek paleidimo priemonę, tiek įvesties balsu paslaugas, kad galėtų būti naudingos."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Rekomenduoja „<xliff:g id="OEM_NAME">%s</xliff:g>“"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Numatytoji naršyklės programa"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Naršyklės programa"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Programos, leidžiančios pasiekti internetą ir rodomas nuorodas, kurias paliečiate"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Nuorodų atidarymas"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Numatytosios darbo programos"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Privačios erdvės numatytosios programos"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizuota pagal įrenginį"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Kita"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nėra"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Sistemos numatytoji programa)"</string>
diff --git a/PermissionController/res/values-lv-v36/strings.xml b/PermissionController/res/values-lv-v36/strings.xml
new file mode 100644
index 0000000000..b7e9c6c3d3
--- /dev/null
+++ b/PermissionController/res/values-lv-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Aģenta kontrole pār citām lietotnēm"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Veiciet darbības savā ierīcē un citās lietotnēs"</string>
+</resources>
diff --git a/PermissionController/res/values-lv/strings.xml b/PermissionController/res/values-lv/strings.xml
index 81a68f06f6..8fb5d1fd9b 100644
--- a/PermissionController/res/values-lv/strings.xml
+++ b/PermissionController/res/values-lv/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Noklusēj. digitālais asistents"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitālā asistenta lietotne"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Izmantojot palīga lietotnes, varat iegūt palīdzību, pamatojoties uz ekrānā redzamo informāciju. Dažās lietotnēs tiek atbalstītas gan palaišanas programmas, gan balss ievades pakalpojumi, lai nodrošinātu integrētu palīdzību."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> iesaka"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Noklusējuma pārlūka lietotne"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Pārlūka lietotne"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Lietotnes, kas sniedz jums piekļuvi internetam un atver saites, kam jūs pieskaraties"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Saišu atvēršana"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Noklusējuma iestatījums darbam"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Noklusējums privātajai telpai"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizētas ierīcei"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Citas"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nav"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Sistēmas noklusējums)"</string>
diff --git a/PermissionController/res/values-mk-v33/strings.xml b/PermissionController/res/values-mk-v33/strings.xml
index 6bf33023c3..d2d914afe6 100644
--- a/PermissionController/res/values-mk-v33/strings.xml
+++ b/PermissionController/res/values-mk-v33/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="role_dialer_request_description" msgid="6188305064871543419">"Апликацијава ќе може да ви испраќа известувања и ќе има пристап до камерата, контактите, микрофонот, телефонот и SMS-пораките"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"Апликацијава ќе може да ви испраќа известувања и ќе има пристап до камерата, контактите, датотеките, микрофонот, телефонот и SMS-пораките"</string>
-    <string name="permission_description_summary_storage" msgid="1917071243213043858">"Апликации со оваа дозвола може да пристапуваат до сите датотеки на уредов"</string>
+    <string name="permission_description_summary_storage" msgid="1917071243213043858">"Апликациите со оваа дозвола може да пристапуваат до сите датотеки на уредов"</string>
     <string name="work_policy_title" msgid="832967780713677409">"Информации за работните правила"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"IT-администраторот управува со поставките"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"Проширете го и прикажете го списокот"</string>
diff --git a/PermissionController/res/values-mk-v36/strings.xml b/PermissionController/res/values-mk-v36/strings.xml
new file mode 100644
index 0000000000..899e20901d
--- /dev/null
+++ b/PermissionController/res/values-mk-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Контрола на агенти на други апликации"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Извршувајте дејства на уредот и во други апликации"</string>
+</resources>
diff --git a/PermissionController/res/values-mk/strings.xml b/PermissionController/res/values-mk/strings.xml
index c1c1662a2d..112d2edff0 100644
--- a/PermissionController/res/values-mk/strings.xml
+++ b/PermissionController/res/values-mk/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Стандарден дигитален помошник"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Апл. за дигитален помошник"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Апликациите за помош може да ви помогнат според информациите од прикажаниот екран. Некои апликации поддржуваат услуги и со стартер и со гласовен запис за да ви обезбедат интегрирана помош."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Препорачано од <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Стандардна апл. за прелист."</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Апликација за прелистување"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Апликации што ви даваат пристап до интернет и ги прикажуваат линковите што ги допирате"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"За отворање линкови"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Стандардно за работа"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Стандардно за „Приватен простор“"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Оптимизирано за уредот"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Други"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Нема"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Стандардно за системот)"</string>
@@ -679,7 +679,7 @@
     <string name="enhanced_confirmation_dialog_title" msgid="7562437438040966351">"Ограничена поставка"</string>
     <string name="enhanced_confirmation_dialog_desc" msgid="5921240234843839219">"За ваша безбедност, поставкава е недостапна во моментов."</string>
     <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"Дејството не може да се заврши во тек на повик"</string>
-    <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g> Поставкава е блокирана за да ги заштити вашиот уред и податоци."</string>
+    <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"Поставкава е блокирана за да ги заштити вашиот уред и податоци.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
 </xliff:g>Измамниците може да се обидат да инсталираат штетни апликации барајќи од вас да инсталирате непознати апликации од нов извор."</string>
diff --git a/PermissionController/res/values-ml-v36/strings.xml b/PermissionController/res/values-ml-v36/strings.xml
new file mode 100644
index 0000000000..9c239abf24
--- /dev/null
+++ b/PermissionController/res/values-ml-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"മറ്റ് ആപ്പുകളുടെ ഏജന്റ് നിയന്ത്രണം"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"നിങ്ങളുടെ ഉപകരണത്തിലും മറ്റ് ആപ്പുകളിലും പ്രവർത്തനങ്ങൾ നടത്തുക"</string>
+</resources>
diff --git a/PermissionController/res/values-ml/strings.xml b/PermissionController/res/values-ml/strings.xml
index 86a1ed6801..650acd12e1 100644
--- a/PermissionController/res/values-ml/strings.xml
+++ b/PermissionController/res/values-ml/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ഡിഫോൾട്ട് ഡിജിറ്റൽ അസിസ്‌റ്റന്റ് ആപ്പ്"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ഡിജിറ്റൽ അസിസ്‌റ്റന്റ് ആപ്പ്"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"നിങ്ങൾ കാണുന്ന സ്ക്രീനിൽ നിന്നുള്ള വിവരങ്ങളെ അടിസ്ഥാനമാക്കി സഹായിക്കാൻ സഹായ ആപ്പിന് കഴിയും. നിങ്ങൾക്ക് സമ്പൂർണ്ണമായ സഹായം നൽകാൻ ലോഞ്ചറിനെയും വോയ്‌സ് ഇൻപുട്ട് സേവനങ്ങളെയും ചില ആപ്പുകൾ പിന്തുണയ്‌ക്കുന്നു."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> നിർദ്ദേശിച്ചത്"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ഡിഫോൾട്ട് ബ്രൗസർ ആപ്പ്"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ബ്രൗസർ ആപ്പ്"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"നിങ്ങൾ ടാപ്പ് ചെയ്യുന്ന ലിങ്കുകൾ പ്രദർശിപ്പിക്കുകയും ഇന്റർനെറ്റ് ആക്‌സസ് നൽകുകയും ചെയ്യുന്ന ആപ്പുകൾ"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ലിങ്കുകൾ തുറക്കൽ"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ജോലി ആവശ്യങ്ങൾക്ക് ഡിഫോൾട്ട്"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"സ്വകാര്യ സ്പേസിനായുള്ള ഡിഫോൾട്ട്"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ഉപകരണത്തിനായി ഒപ്റ്റിമൈസ് ചെയ്‌തു"</string>
     <string name="default_app_others" msgid="7793029848126079876">"മറ്റുള്ളവ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ഒന്നുമില്ല"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(സിസ്‌റ്റം ഡിഫോൾട്ട്)"</string>
diff --git a/PermissionController/res/values-mn-v36/strings.xml b/PermissionController/res/values-mn-v36/strings.xml
new file mode 100644
index 0000000000..fc34881165
--- /dev/null
+++ b/PermissionController/res/values-mn-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent аппын бусад аппыг хянах эрх"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Төхөөрөмж дээрээ болон бусад аппад үйлдэл гүйцэтгэнэ үү"</string>
+</resources>
diff --git a/PermissionController/res/values-mn/strings.xml b/PermissionController/res/values-mn/strings.xml
index 55870deb5e..dd390341fe 100644
--- a/PermissionController/res/values-mn/strings.xml
+++ b/PermissionController/res/values-mn/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Өгөгдмөл дижитал туслах апп"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Дижитал туслах апп"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Туслах аппууд нь таны харж байгаа дэлгэцийн мэдээлэлд тулгуурлан танд туслах боломжтой. Зарим апп танд нэгтгэсэн тусламж үзүүлэх зорилгоор эхлүүлэгч болон дуугаар оруулах үйлчилгээг аль алиныг нь дэмждэг."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g>-с санал болгосон"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Хөтчийн өгөгдмөл апп"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Хөтчийн апп"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Танд интернэтийн хандалт өгдөг болон таны товшдог холбоосыг харуулдаг аппууд"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Холбоосыг нээх сонголт"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Ажлын өгөгдмөл апп"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Хаалттай орон зайн өгөгдмөл"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Төхөөрөмжид зориулж оновчилсон"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Бусад"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Тохируулсан апп алга"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Системийн өгөгдмөл)"</string>
diff --git a/PermissionController/res/values-mr-v36/strings.xml b/PermissionController/res/values-mr-v36/strings.xml
new file mode 100644
index 0000000000..8675c797ad
--- /dev/null
+++ b/PermissionController/res/values-mr-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"इतर अ‍ॅप्सचे एजंट नियंत्रण"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"तुमच्या डिव्हाइसवर आणि इतर अ‍ॅप्समध्ये कृती करा"</string>
+</resources>
diff --git a/PermissionController/res/values-mr/strings.xml b/PermissionController/res/values-mr/strings.xml
index 2b5e2947d1..bdc6584c9f 100644
--- a/PermissionController/res/values-mr/strings.xml
+++ b/PermissionController/res/values-mr/strings.xml
@@ -102,7 +102,7 @@
     <string name="permission_summary_disabled_by_policy_background_only" msgid="221995005556362660">"धोरणामुळे बॅकग्राउंड अ‍ॅक्सेस बंद केला आहे"</string>
     <string name="permission_summary_enabled_by_policy_background_only" msgid="8287675974767104279">"धोरणामुळे बॅकग्राउंड अ‍ॅक्सेस सुरू केला आहे"</string>
     <string name="permission_summary_enabled_by_policy_foreground_only" msgid="3844582916889767831">"धोरणामुळे फोरग्राउंड अ‍ॅक्सेस सुरू केला आहे"</string>
-    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"प्रशासकाने नियंत्रित केलेले"</string>
+    <string name="permission_summary_enforced_by_admin" msgid="822702574117248700">"ॲडमिनद्वारे नियंत्रित"</string>
     <string name="permission_summary_disabled_by_admin_background_only" msgid="3127091456731845646">"प्रशासकाने बॅकग्राउंड अ‍ॅक्सेस बंद केला आहे"</string>
     <string name="permission_summary_enabled_by_admin_background_only" msgid="9132423838440275757">"प्रशासकाने बॅकग्राउंड अ‍ॅक्सेस सुरू केला आहे"</string>
     <string name="permission_summary_enabled_by_admin_foreground_only" msgid="1298432715610745358">"प्रशासकाने फोरग्राउंड अ‍ॅक्सेस सुरू केला आहे"</string>
@@ -128,7 +128,7 @@
     <string name="permission_usage_title" msgid="1568233336351734538">"गोपनीयता डॅशबोर्ड"</string>
     <string name="auto_permission_usage_summary" msgid="7335667266743337075">"कोणत्या ॲप्सनी अलीकडे परवानग्या वापरल्या ते पहा"</string>
     <string name="permission_group_usage_title" msgid="2595013198075285173">"<xliff:g id="PERMGROUP">%1$s</xliff:g> वापर"</string>
-    <string name="perm_usage_adv_info_title" msgid="3357831829538873708">"इतर परवानग्या पाहणे"</string>
+    <string name="perm_usage_adv_info_title" msgid="3357831829538873708">"इतर परवानग्या पहा"</string>
     <string name="perm_usage_adv_info_summary_2_items" msgid="3702175198750127822">"<xliff:g id="PERMGROUP_0">%1$s</xliff:g>, <xliff:g id="PERMGROUP_1">%2$s</xliff:g>"</string>
     <string name="perm_usage_adv_info_summary_more_items" msgid="949055326299562218">"<xliff:g id="PERMGROUP_0">%1$s</xliff:g>, <xliff:g id="PERMGROUP_1">%2$s</xliff:g> आणि आणखी <xliff:g id="NUM">%3$s</xliff:g>"</string>
     <string name="permission_group_usage_subtitle_24h" msgid="5120155996322114181">"ॲप्सनी मागील २४ तासांमध्ये तुमचे <xliff:g id="PERMGROUP">%1$s</xliff:g> वापरलेल्याची टाइमलाइन"</string>
@@ -164,7 +164,7 @@
     <string name="permission_usage_bar_chart_title_last_minute" msgid="820450867183487607">"मागील एका मिनिटातील परवानगी वापर"</string>
     <string name="permission_usage_preference_summary_not_used_in_past_n_days" msgid="4771868094611359651">"{count,plural, =1{मागील # दिवसामध्ये न वापरलेली}other{मागील # दिवसांमध्ये न वापरलेली}}"</string>
     <string name="permission_usage_preference_summary_not_used_in_past_n_hours" msgid="3828973177433435742">"{count,plural, =1{मागील # तासामध्ये न वापरलेली}other{मागील # तासांमध्ये न वापरलेली}}"</string>
-    <string name="permission_usage_preference_label" msgid="8343167938128676378">"{count,plural, =1{एका अ‍ॅपने वापरल्या}other{# अ‍ॅप्सनी वापरल्या}}"</string>
+    <string name="permission_usage_preference_label" msgid="8343167938128676378">"{count,plural, =1{एका अ‍ॅपने वापरली}other{# अ‍ॅप्सनी वापरली}}"</string>
     <string name="permission_usage_view_details" msgid="6675335735468752787">"डॅशबोर्डमध्ये सर्व पहा"</string>
     <string name="app_permission_usage_filter_label" msgid="7182861154638631550">"यानुसार फिल्टर केले: <xliff:g id="PERM">%1$s</xliff:g>"</string>
     <string name="app_permission_usage_remove_filter" msgid="2926157607436428207">"फिल्टर काढून टाका"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"डीफॉल्ट डिजिटल साहाय्यक अ‍ॅप"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"डिजिटल असिस्टंट अ‍ॅप"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"साहाय्यक अ‍ॅप्स तुम्ही पाहत असलेल्या स्क्रीनवरील माहितीच्या आधारावर तुम्हाला मदत करू शकतात. काही अ‍ॅप्स तुम्हाला एकत्रित साहाय्य देण्यासाठी लाँचर आणि व्हॉइस इनपुट सेवा दोन्हींना सपोर्ट करतात."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> द्वारे शिफारस केलेले"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"डीफॉल्ट ब्राउझर अ‍ॅप"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ब्राउझर अ‍ॅप"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"तुम्हाला इंटरनेटचा आणि तुम्ही टॅप करत असलेल्या डिस्प्ले लिंकचा अ‍ॅक्सेस देणारी अ‍ॅप्स"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"उघडणार्‍या लिंक"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"कार्यासाठी डीफॉल्ट"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"खाजगी स्पेससाठी डीफॉल्ट"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ऑप्टिमाइझ केलेले डिव्हाइस"</string>
     <string name="default_app_others" msgid="7793029848126079876">"इतर"</string>
     <string name="default_app_none" msgid="9084592086808194457">"काहीही नाही"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(सिस्टीम डीफॉल्ट)"</string>
diff --git a/PermissionController/res/values-ms-v36/strings.xml b/PermissionController/res/values-ms-v36/strings.xml
new file mode 100644
index 0000000000..22a3bf3a1c
--- /dev/null
+++ b/PermissionController/res/values-ms-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Kawalan ejen apl lain"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Lakukan tindakan pada peranti anda dan pada apl lain"</string>
+</resources>
diff --git a/PermissionController/res/values-ms/strings.xml b/PermissionController/res/values-ms/strings.xml
index a013d38770..82412757f9 100644
--- a/PermissionController/res/values-ms/strings.xml
+++ b/PermissionController/res/values-ms/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Apl pembantu digital lalai"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Apl pembantu digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Apl bantu dapat membantu anda berdasarkan maklumat daripada skrin yang sedang dilihat. Sesetengah apl menyokong perkhidmatan pelancar dan input suara untuk memberi anda bantuan bersepadu."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Disyorkan oleh <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Apl penyemak imbas lalai"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Apl penyemak imbas"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apl yang memberi anda akses kepada Internet dan memaparkan pautan yang anda ketik"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Membuka pautan"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Lalai untuk kerja"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Lalai untuk ruang privasi"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Dioptimumkan untuk peranti"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Lain-lain"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Tiada"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Ciri lalai sistem)"</string>
@@ -576,7 +576,7 @@
     <string name="safety_center_rescan_button" msgid="4517514567809409596">"Imbas peranti"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"Ketepikan"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"Ketepikan makluman ini?"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Semak tetapan keselamatan dan privasi anda pada bila-bila masa untuk menambahkan lagi perlindungan"</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Semak tetapan keselamatan dan privasi anda pada bila-bila masa untuk meningkatkan perlindungan"</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"Ketepikan"</string>
     <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"Batal"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"Tetapan"</string>
diff --git a/PermissionController/res/values-my-v36/strings.xml b/PermissionController/res/values-my-v36/strings.xml
new file mode 100644
index 0000000000..17cdc82c98
--- /dev/null
+++ b/PermissionController/res/values-my-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"အခြားအက်ပ်များ၏ အေးဂျင့်ထိန်းချုပ်မှု"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"သင့်စက်နှင့် အခြားအက်ပ်များတွင် လုပ်ဆောင်ချက်များ ဆောင်ရွက်နိုင်သည်"</string>
+</resources>
diff --git a/PermissionController/res/values-my/strings.xml b/PermissionController/res/values-my/strings.xml
index 466552992d..f1e59af58b 100644
--- a/PermissionController/res/values-my/strings.xml
+++ b/PermissionController/res/values-my/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"မူရင်း ဒစ်ဂျစ်တယ်အထောက်အကူ အက်ပ်"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ဒစ်ဂျစ်တယ်အထောက်အကူ အက်ပ်"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"အကူအညီအက်ပ်များသည် သင်ကြည့်နေသည့် မျက်နှာပြင်မှ အချက်အလက်ကို အခြေခံ၍ ပံ့ပိုးပေးနိုင်ပါသည်။ ဘက်စုံ အထောက်အကူပေးနိုင်ရန်အတွက် အချို့အက်ပ်များသည် စဖွင့်စနစ်နှင့် အသံဖြင့်ထည့်သွင်းဝန်ဆောင်မှု နှစ်ခုလုံးကို ပံ့ပိုးပါသည်။"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> က အကြံပြုထားသည်"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"မူရင်း ဘရောင်ဇာအက်ပ်"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ဘရောင်ဇာ အက်ပ်"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"သင့်ကို အင်တာနက်အသုံးပြုခွင့်ပေးပြီး သင်တို့လိုက်သည့် လင့်ခ်များကို ပြသပေးသော အက်ပ်များ"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"လင့်ခ်များကို ဖွင့်ခြင်း"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"အလုပ်အတွက် မူရင်း"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"သီးသန့်နေရာအတွက် မူလအက်ပ်များ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"စက်အတွက် အကောင်းဆုံးပြင်ထားသည်"</string>
     <string name="default_app_others" msgid="7793029848126079876">"အခြား"</string>
     <string name="default_app_none" msgid="9084592086808194457">"မရှိ"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(စနစ်မူရင်း)"</string>
@@ -661,8 +661,8 @@
     <string name="app_location_permission_rationale_subtitle" msgid="6986985722752868692">"ဤအက်ပ်က ၎င်းသည် သင်၏ တည်နေရာဒေတာကို ပြင်ပကုမ္ပဏီများနှင့် မျှဝေနိုင်ကြောင်း ဖော်ပြထားသည်"</string>
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"တည်နေရာအတွက် ဒေတာမျှဝေခြင်း အပ်ဒိတ်"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"သင်၏ တည်နေရာဒေတာ မျှဝေနည်း ပြောင်းထားသော အက်ပ်များကို စိစစ်သည်"</string>
-    <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"ဤအက်ပ်များသည် ၎င်းတို့က သင်၏ တည်နေရာဒေတာ မျှဝေနိုင်သော နည်းလမ်းကို ပြောင်းလိုက်ပါပြီ။ ၎င်းတို့သည် ဒေတာကို ယခင်က မျှဝေထားခြင်း မရှိနိုင်ပါ သို့မဟုတ် ကြော်ငြာခြင်း (သို့) အရောင်းမြှင့်တင်ခြင်းတို့အတွက် ဒေတာကို ယခုမျှဝေနိုင်သည်။"</string>
-    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"ဤအက်ပ်များ၏ ဆော့ဖ်ဝဲရေးသူများသည် ၎င်းတို့၏ ဒေတာမျှဝေခြင်း လုပ်ထုံးလုပ်နည်းများအကြောင်း အချက်အလက်ကို အက်ပ်စတိုးသို့ ပေးထားသည်။ သူတို့သည် ၎င်းကို အချိန်နှင့်အမျှ အပ်ဒိတ်လုပ်နိုင်သည်။\n\nဒေတာမျှဝေခြင်း လုပ်ထုံးလုပ်နည်းများသည် သင်၏ အက်ပ်ဗားရှင်း၊ အသုံးပြုမှု၊ ဒေသနှင့် အသက်အရွယ်ပေါ် အခြေခံ၍ ကွဲပြားနိုင်သည်။"</string>
+    <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"ဤအက်ပ်များက သင်၏ တည်နေရာဒေတာ မျှဝေပုံကို ပြောင်းလိုက်ပါပြီ။ ၎င်းတို့သည် ယခင်က မျှဝေခြင်း မရှိသော်လည်း ယခုအခါ ကြော်ငြာ၊ အရောင်းမြှင့်တင်ခြင်းတို့အတွက် ဒေတာကို မျှဝေနိုင်သည်။"</string>
+    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"ဤအက်ပ်များ၏ ဆော့ဖ်ဝဲရေးသူများသည် ၎င်းတို့၏ ဒေတာမျှဝေခြင်း လုပ်ထုံးလုပ်နည်းများအကြောင်း အချက်အလက်ကို အက်ပ်စတိုးသို့ ပေးထားသည်။ သူတို့သည် ၎င်းကို အပ်ဒိတ်လုပ်ထားနိုင်သည်။\n\nဒေတာမျှဝေခြင်း လုပ်ထုံးလုပ်နည်းများသည် သင်၏ အက်ပ်ဗားရှင်း၊ အသုံးပြုမှု၊ ဒေသနှင့် အသက်အရွယ်ပေါ် အခြေခံ၍ ကွဲပြားနိုင်သည်။"</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"ဒေတာမျှဝေခြင်းအကြောင်း လေ့လာရန်"</string>
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"သင်၏ တည်နေရာဒေတာကို ပြင်ပကုမ္ပဏီများနှင့် ယခု မျှဝေလိုက်ပါပြီ"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"ကြော်ငြာခြင်း (သို့) အရောင်းမြှင့်တင်ခြင်းအတွက် သင်၏ တည်နေရာဒေတာကို ပြင်ပကုမ္ပဏီများနှင့် ယခု မျှဝေလိုက်ပါပြီ"</string>
diff --git a/PermissionController/res/values-nb-v36/strings.xml b/PermissionController/res/values-nb-v36/strings.xml
new file mode 100644
index 0000000000..847d1be581
--- /dev/null
+++ b/PermissionController/res/values-nb-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agentkontroll av andre apper"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Utfør handlinger på enheten og i andre apper"</string>
+</resources>
diff --git a/PermissionController/res/values-nb/strings.xml b/PermissionController/res/values-nb/strings.xml
index 6a4cc55367..bd77b2150a 100644
--- a/PermissionController/res/values-nb/strings.xml
+++ b/PermissionController/res/values-nb/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Standard digital assistentapp"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistent-app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Assistentapper kan hjelpe deg basert på informasjon fra skjermen du bruker. Noen apper støtter tjenester for både appoversikten og taleinndata for å gi deg integrert hjelp."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Anbefalt av <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Standard nettleserapp"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Nettleserapp"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apper som gir deg tilgang til internett og viser linker du trykker på"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Åpning av linker"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Jobbstandard"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Standard for privat område"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimalisert for enheten"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Andre"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ingen"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System-&amp;#173;standard)"</string>
diff --git a/PermissionController/res/values-ne-v36/strings.xml b/PermissionController/res/values-ne-v36/strings.xml
new file mode 100644
index 0000000000..57666b2aeb
--- /dev/null
+++ b/PermissionController/res/values-ne-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"अन्य एपहरूको एजेन्ट कन्ट्रोल"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"आफ्नो डिभाइस र अन्य एपहरूमा कारबाहीहरू गर्नुहोस्"</string>
+</resources>
diff --git a/PermissionController/res/values-ne/strings.xml b/PermissionController/res/values-ne/strings.xml
index fab3fd50a1..2b484a16e6 100644
--- a/PermissionController/res/values-ne/strings.xml
+++ b/PermissionController/res/values-ne/strings.xml
@@ -25,7 +25,7 @@
     <string name="available" msgid="6007778121920339498">"उपलब्ध"</string>
     <string name="blocked" msgid="9195547604866033708">"ब्लक गरिएको"</string>
     <string name="on" msgid="280241003226755921">"अन छ"</string>
-    <string name="off" msgid="1438489226422866263">"निष्क्रिय"</string>
+    <string name="off" msgid="1438489226422866263">"अफ"</string>
     <string name="uninstall_or_disable" msgid="4496612999740858933">"अनइन्स्टल गर्नुहोस् वा असक्षम पार्नुहोस्"</string>
     <string name="app_not_found_dlg_title" msgid="6029482906093859756">"एप फेला परेन"</string>
     <string name="grant_dialog_button_deny" msgid="88262611492697192">"अनुमति नदिनुहोस्"</string>
@@ -234,18 +234,18 @@
     <string name="app_permission_footer_special_file_access" msgid="1884202176147657788">"तपाईंले सबै फाइलहरू व्यवस्थापन गर्ने अनुमति दिनुभयो भने यो एपले यस डिभाइस वा यस डिभाइससँग कनेक्ट गरिएका अन्य डिभाइसको साझा भण्डारणमा भएका सबै फाइलहरू प्रयोग गर्न, परिमार्जन गर्न र मेटाउन सक्छ। यो एपले तपाईंलाई जानकारी नदिइकन ‌फाइलहरू प्रयोग गर्न सक्छ।"</string>
     <string name="special_file_access_dialog" msgid="583804114020740610">"यो एपलाई यस यन्त्र वा यस यन्त्रसँग जोडिएका अन्य भण्डारण डिभाइसमा रहेका फाइलहरू प्रयोग गर्न, परिमार्जन गर्न र मेटाउन दिने हो? यो एपले तपाईंलाई जानकारी नदिइकन ‌फाइलहरू प्रयोग गर्न सक्छ।"</string>
     <string name="permission_description_summary_generic" msgid="5401399408814903391">"यो अनुमति पाएका एपहरूले निम्न कार्य गर्न सक्छन्: <xliff:g id="DESCRIPTION">%1$s</xliff:g>"</string>
-    <string name="permission_description_summary_activity_recognition" msgid="2652850576497070146">"यो अनुमति भएका एपहरूले तपाईंले हिँड्ने, साइकल र गाडी कुदाउने जस्ता क्रियाकलाप गर्दा सृजित हुने डेटा हेर्न तथा प्रयोग गर्न सक्छन्"</string>
+    <string name="permission_description_summary_activity_recognition" msgid="2652850576497070146">"यो अनुमति भएका एपहरूले तपाईंले हिँड्ने, साइकल र गाडी कुदाउने जस्ता क्रियाकलाप गर्दा सृजित हुने डेटा एक्सेस गर्न सक्छन्"</string>
     <string name="permission_description_summary_calendar" msgid="103329982944411010">"यो अनुमति पाएका एपहरूले तपाईंको पात्रो हेर्न तथा चलाउन सक्छन्"</string>
-    <string name="permission_description_summary_call_log" msgid="7321437186317577624">"यो अनुमति भएका एपले फोन कल लग हेर्न तथा प्रयोग गर्न सक्छन्"</string>
+    <string name="permission_description_summary_call_log" msgid="7321437186317577624">"यो अनुमति भएका एपले फोन कल लग एक्सेस गर्न सक्छन्"</string>
     <string name="permission_description_summary_camera" msgid="108004375101882069">"यो अनुमति पाएका एपहरूले फोटो खिच्न र भिडियो रेकर्ड गर्न सक्छन्"</string>
     <string name="permission_description_summary_contacts" msgid="2337798886460408996">"यो अनुमति पाएका एपहरूले तपाईंका कन्ट्याक्टहरू हेर्न सक्छन्"</string>
-    <string name="permission_description_summary_location" msgid="2817531799933480694">"यो अनुमति भएका  एपहरूले यस डिभाइसको लोकेसन हेर्न तथा प्रयोग गर्न सक्छन्"</string>
+    <string name="permission_description_summary_location" msgid="2817531799933480694">"यो अनुमति भएका  एपहरूले यस डिभाइसको लोकेसन एक्सेस गर्न सक्छन्"</string>
     <string name="permission_description_summary_nearby_devices" msgid="8269183818275073741">"यो अनुमति दिइएका एपहरूले नजिकै रहेका डिभाइसहरू भेट्टाउन, ती डिभाइससँग कनेक्ट गर्न र तिनको सापेक्ष स्थिति निर्धारण गर्न सक्छन्"</string>
     <string name="permission_description_summary_microphone" msgid="630834800308329907">"यो अनुमति भएका एपहरूले अडियो रेकर्ड गर्न सक्छन्"</string>
     <string name="permission_description_summary_phone" msgid="4515277217435233619">"यो अनुमति पाएका एपहरूले फोन कल गर्न र तिनको व्यवस्थापन गर्न सक्छन्"</string>
     <string name="permission_description_summary_sensors" msgid="1836045815643119949">"यो अनुमति भएका एपहरूले मुटुको धड्कन जस्ता तपाईं जीवित रहेको संकेत गर्ने शरीरका महत्त्वपूर्ण चालसम्बन्धी डेटा प्रयोग गर्न सक्छन्"</string>
     <string name="permission_description_summary_sms" msgid="725999468547768517">"यो अनुमति पाएका एपहरूले SMS म्यासेज पठाउन र हेर्न सक्छन्"</string>
-    <string name="permission_description_summary_storage" msgid="6575759089065303346">"यो अनुमति भएका एपहरूले तपाईंको डिभाइसमा रहेका फोटो, मिडिया तथा फाइल हेर्न तथा प्रयोग गर्न सक्छन्"</string>
+    <string name="permission_description_summary_storage" msgid="6575759089065303346">"यो अनुमति भएका एपहरूले तपाईंको डिभाइसमा रहेका फोटो, मिडिया तथा फाइल एक्सेस गर्न सक्छन्"</string>
     <string name="permission_description_summary_read_media_aural" msgid="3354728149930482199">"यो अनुमति पाएका एपहरूले यो डिभाइसमा रहेका सङ्गीत र अन्य अडियो फाइलहरू प्रयोग गर्न सक्छन्"</string>
     <string name="permission_description_summary_read_media_visual" msgid="4991801977881732641">"यो अनुमति पाएका एपहरूले यस डिभाइसमा रहेका फोटो र भिडियोहरू प्रयोग गर्न सक्छन्"</string>
     <string name="app_permission_most_recent_summary" msgid="4292074449384040590">"पछिल्लो पटक पहुँच राखिएको समय: <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
@@ -291,8 +291,8 @@
     <string name="background_location_access_reminder_notification_title" msgid="1140797924301941262">"<xliff:g id="APP_NAME">%s</xliff:g> ले पृष्ठभूमिमा तपाईंको स्थानमाथिको पहुँच प्राप्त गर्‍यो"</string>
     <string name="background_location_access_reminder_notification_content" msgid="7787084707336546245">"यो एपले सधैँ तपाईंको स्थान प्रयोग गर्न सक्छ। बदल्न ट्याप गर्नुहोस्‌।"</string>
     <string name="notification_listener_reminder_notification_title" msgid="3747210460187479091">"सूचना हेर्ने अनुमति दिइएको एपको समीक्षा गर्नुहोस्"</string>
-    <string name="notification_listener_reminder_notification_content" msgid="831476101108863427">"<xliff:g id="APP_NAME">%s</xliff:g> ले तपाईंका सूचनामा रहेको सामग्री खारेज गर्न, त्यसमा कारबाही गर्न र उक्त सामग्री हेर्न तथा प्रयोग गर्न सक्छ"</string>
-    <string name="notification_listener_warning_card_content" msgid="7840973324284115893">"यो एपले तपाईंका सूचनामा रहेको सामग्री खारेज गर्न, त्यसमा कारबाही गर्न र उक्त सामग्री हेर्न तथा प्रयोग गर्न सक्छ। केही एपहरूलाई अपेक्षाअनुसार कार्य गर्नका निम्ति यस प्रकारको अनुमति दिनु पर्ने हुन्छ।"</string>
+    <string name="notification_listener_reminder_notification_content" msgid="831476101108863427">"<xliff:g id="APP_NAME">%s</xliff:g> ले तपाईंका सूचनामा रहेको सामग्री खारेज गर्न, त्यसमा कारबाही गर्न र उक्त सामग्री एक्सेस गर्न सक्छ"</string>
+    <string name="notification_listener_warning_card_content" msgid="7840973324284115893">"यो एपले तपाईंका सूचनामा रहेको सामग्री खारेज गर्न, त्यसमा कारबाही गर्न र उक्त सामग्री एक्सेस गर्न सक्छ। केही एपहरूलाई अपेक्षाअनुसार कार्य गर्नका निम्ति यस प्रकारको अनुमति दिनु पर्ने हुन्छ।"</string>
     <string name="notification_listener_remove_access_button_label" msgid="7101898782417817097">"अनुमति हटाउनुहोस्"</string>
     <string name="notification_listener_review_app_button_label" msgid="3433073281029143924">"थप विकल्पहरू हेर्नुहोस्"</string>
     <string name="notification_listener_remove_access_success_label" msgid="2477611529875633107">"अनुमति हटाइएको छ"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"डिफल्ट डिजिटल एसिस्टेन्ट एप"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"डिजिटल एसिस्टेन्ट एप"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"सहायक एपहरूले तपाईंले हेर्दै गर्नुभएको स्क्रिनबाट प्राप्त जानकारीमा आधारित भई तपाईंलाई मद्दत गर्न सक्छन्। केही एपहरूले तपाईंलाई एकीकृत सहायता दिन दुवै लन्चर र आवाज संलग्न इनपुट सेवाहरूलाई समर्थन गर्छन्।"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> ले सिफारिस गरेको"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"डिफल्ट ब्राउजर एप"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ब्राउजर"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"तपाईंलाई इन्टरनेट चलाउने दिने र तपाईंले ट्याप गर्ने लिंकहरू देखाउने एपहरू"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"लिंकहरू खोल्दा"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"कार्यका लागि डिफल्ट"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"निजी स्पेसका लागि डिफल्ट एपहरू"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"यो डिभाइसका लागि अप्टिमाइज गरिएका"</string>
     <string name="default_app_others" msgid="7793029848126079876">"अन्य"</string>
     <string name="default_app_none" msgid="9084592086808194457">"कुनै पनि होइन"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(सिस्टम डिफल्ट)"</string>
@@ -452,7 +452,7 @@
     <string name="special_app_access" msgid="5019319067120213797">"एपसम्बन्धी विशेष पहुँच"</string>
     <string name="no_special_app_access" msgid="6950277571805106247">"एपसम्बन्धी कुनै विशेष पहुँच छैन"</string>
     <string name="special_app_access_no_apps" msgid="4102911722787886970">"कुनै पनि एप छैन"</string>
-    <string name="home_missing_work_profile_support" msgid="1756855847669387977">"कार्य प्रोफाइल समर्थन गर्दैन"</string>
+    <string name="home_missing_work_profile_support" msgid="1756855847669387977">"वर्क प्रोफाइल समर्थन गर्दैन"</string>
     <string name="encryption_unaware_confirmation_message" msgid="8274491794636402484">"टिपोट: तपाईंले आफ्नो यन्त्र पुनः सुरु गर्नुभयो र त्यसमा स्क्रिन लक सेट गरिएको छ भने तपाईंले आफ्नो डिभाइस अनलक नगरेसम्म यो एप सुरु हुन सक्दैन।"</string>
     <string name="assistant_confirmation_message" msgid="7476540402884416212">"सहायकले तपाईंको स्क्रिनमा देखिने वा अनुप्रयोगभित्रबाट पहुँच राख्न सकिने जानकारीलगायत तपाईंको प्रणालीमा प्रयोगमा रहेका एपसम्बन्धी जानकारी पढ्न सक्ने छ।"</string>
     <string name="incident_report_channel_name" msgid="3144954065936288440">"डिबग प्रक्रियासम्बन्धी डेटा सेयर गर्नुहोस्"</string>
diff --git a/PermissionController/res/values-nl-television/strings.xml b/PermissionController/res/values-nl-television/strings.xml
index ae112c6c62..bd2d52de39 100644
--- a/PermissionController/res/values-nl-television/strings.xml
+++ b/PermissionController/res/values-nl-television/strings.xml
@@ -22,7 +22,7 @@
     <string name="preference_show_system_apps" msgid="4262140518693221093">"Systeem-apps tonen"</string>
     <string name="app_permissions_decor_title" msgid="7438716722786036814">"App-rechten"</string>
     <string name="manage_permissions_decor_title" msgid="4138423885439613577">"App-rechten"</string>
-    <string name="permission_apps_decor_title" msgid="2811550489429789828">"<xliff:g id="PERMISSION">%1$s</xliff:g>-rechten"</string>
+    <string name="permission_apps_decor_title" msgid="2811550489429789828">"<xliff:g id="PERMISSION">%1$s</xliff:g>rechten"</string>
     <string name="additional_permissions_decor_title" msgid="5113847982502484225">"Aanvullende rechten"</string>
     <string name="system_apps_decor_title" msgid="4402004958937474803">"<xliff:g id="PERMISSION">%1$s</xliff:g>-rechten"</string>
 </resources>
diff --git a/PermissionController/res/values-nl-v36/strings.xml b/PermissionController/res/values-nl-v36/strings.xml
new file mode 100644
index 0000000000..b20f317df2
--- /dev/null
+++ b/PermissionController/res/values-nl-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent-besturing van andere apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Acties uitvoeren op je apparaat en in andere apps"</string>
+</resources>
diff --git a/PermissionController/res/values-nl/strings.xml b/PermissionController/res/values-nl/strings.xml
index 5bfb2c8844..ff51b992c7 100644
--- a/PermissionController/res/values-nl/strings.xml
+++ b/PermissionController/res/values-nl/strings.xml
@@ -260,7 +260,7 @@
     <string name="ask_header" msgid="2633816846459944376">"Altijd vragen"</string>
     <string name="denied_header" msgid="903209608358177654">"Niet toegestaan"</string>
     <string name="permission_group_name_with_device_name" msgid="8798741850536024820">"<xliff:g id="PERM_GROUP_NAME">%1$s</xliff:g> in <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
-    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Bekijk meer apps die toegang tot alle bestanden hebben."</string>
+    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Bekijk meer apps die toegang tot alle bestanden hebben"</string>
     <string name="days" msgid="609563020985571393">"{count,plural, =1{1 dag}other{# dagen}}"</string>
     <string name="hours" msgid="7302866489666950038">"{count,plural, =1{# uur}other{# uur}}"</string>
     <string name="minutes" msgid="4868414855445375753">"{count,plural, =1{# minuut}other{# minuten}}"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Standaard digitale-assistent-app"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitale-assistent-app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Apps voor assistentie kunnen je helpen op basis van de informatie op het scherm dat je bekijkt. Bepaalde apps ondersteunen launcher- en spraakinvoerservices voor geïntegreerde ondersteuning."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Aanbevolen door <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Standaard browser-app"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser-app"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps die toegang tot internet geven en de links tonen waarop je hebt getikt"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Links openen"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Standaard voor werk"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Standaard voor privégedeelte"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Geoptimaliseerd voor apparaat"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Anders"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Geen"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Systeem­stan­daard)"</string>
@@ -475,7 +475,7 @@
     <string name="permgrouprequest_device_aware_storage_isolated" msgid="6463062962458809752">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang geven tot foto\'s en media op &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequest_contacts" msgid="8391550064551053695">"Toestaan dat &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang heeft tot je contacten?"</string>
     <string name="permgrouprequest_device_aware_contacts" msgid="731025863972535928">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang geven tot je contacten op &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
-    <string name="permgrouprequest_location" msgid="6990232580121067883">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang geven tot de locatie van dit apparaat?"</string>
+    <string name="permgrouprequest_location" msgid="6990232580121067883">"Toestaan dat &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang heeft tot de locatie van dit apparaat?"</string>
     <string name="permgrouprequest_device_aware_location" msgid="6075412127429878638">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang geven tot de locatie van &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;?"</string>
     <string name="permgrouprequestdetail_location" msgid="2635935335778429894">"De app heeft alleen toegang tot de locatie wanneer je de app gebruikt"</string>
     <string name="permgroupbackgroundrequest_location" msgid="1085680897265734809">"Toestaan dat &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; toegang heeft tot de locatie van dit apparaat?"</string>
@@ -660,7 +660,7 @@
     <string name="app_location_permission_rationale_title" msgid="925420340572401350">"Locatiegegevens kunnen worden gedeeld"</string>
     <string name="app_location_permission_rationale_subtitle" msgid="6986985722752868692">"Deze app geeft aan dat je locatiegegevens met derden kunnen worden gedeeld"</string>
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"Updates voor het delen van locatiegegevens"</string>
-    <string name="data_sharing_updates_summary" msgid="764113985772233889">"Ga na welke apps de manier hebben veranderd waarop je locatiegegevens worden gedeeld"</string>
+    <string name="data_sharing_updates_summary" msgid="764113985772233889">"Controleer de apps die de manier hebben veranderd waarop ze je locatiegegevens delen"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Deze apps hebben de manier veranderd waarop ze je locatiegegevens kunnen delen. Misschien deelden ze de gegevens eerder niet, of kunnen ze deze nu delen voor reclame- en marketingdoeleinden."</string>
     <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"De ontwikkelaars van deze apps hebben informatie gegeven aan een appstore over de manier waarop ze gegevens delen. Ze kunnen deze informatie in de loop van de tijd updaten.\n\nProcedures voor gegevens delen kunnen verschillen op basis van je app-versie, gebruik, regio en leeftijd."</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"Meer informatie over gegevens delen"</string>
diff --git a/PermissionController/res/values-or-v36/strings.xml b/PermissionController/res/values-or-v36/strings.xml
new file mode 100644
index 0000000000..af8cfccaee
--- /dev/null
+++ b/PermissionController/res/values-or-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"ଅନ୍ୟ ଆପ୍ସର ଏଜେଣ୍ଟ ନିୟନ୍ତ୍ରଣ"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ଆପଣଙ୍କ ଡିଭାଇସ ଏବଂ ଅନ୍ୟ ଆପ୍ସରେ କାର୍ଯ୍ୟ ପରଫର୍ମ କରନ୍ତୁ"</string>
+</resources>
diff --git a/PermissionController/res/values-or/strings.xml b/PermissionController/res/values-or/strings.xml
index 0c107f51e5..5e60a66a6f 100644
--- a/PermissionController/res/values-or/strings.xml
+++ b/PermissionController/res/values-or/strings.xml
@@ -195,8 +195,8 @@
     <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"ସୀମିତ ଆକ୍ସେସକୁ ଅନୁମତି ଦିଅନ୍ତୁ"</string>
     <string name="precise_image_description" msgid="6349638632303619872">"ସଠିକ୍ ଲୋକେସନ୍"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"ଆନୁମାନିକ ଲୋକେସନ୍"</string>
-    <string name="app_permission_location_accuracy" msgid="7166912915040018669">"ସଠିକ୍ ଲୋକେସନ୍ ବ୍ୟବହାର କରନ୍ତୁ"</string>
-    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"ଯେତେବେଳେ ସଠିକ୍ ଲୋକେସନ୍ ବନ୍ଦ ଥାଏ, ସେତେବେଳେ ଆପଗୁଡ଼ିକ ଆପଣଙ୍କ ଆନୁମାନିକ ଲୋକେସନକୁ ଆକ୍ସେସ୍ କରିପାରିବ"</string>
+    <string name="app_permission_location_accuracy" msgid="7166912915040018669">"ସଠିକ ଲୋକେସନ ବ୍ୟବହାର କରନ୍ତୁ"</string>
+    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"ସଠିକ ଲୋକେସନ ବନ୍ଦ ଥିବା ସମୟରେ ଆପ୍ସ ଆପଣଙ୍କ ଆନୁମାନିକ ଲୋକେସନକୁ ଆକ୍ସେସ କରିପାରିବ"</string>
     <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g> ଅନୁମତି"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"ଏହି ଆପ ପାଇଁ <xliff:g id="PERM">%1$s</xliff:g>ର ଆକ୍ସେସ"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"<xliff:g id="DEVICE_NAME">%2$s</xliff:g>ରେ ଏହି ଆପ ପାଇଁ <xliff:g id="PERM">%1$s</xliff:g> ଆକ୍ସେସ ଅଛି"</string>
@@ -239,7 +239,7 @@
     <string name="permission_description_summary_call_log" msgid="7321437186317577624">"ଏହି ଅନୁମତି ଥିବା ଆପ୍‌ଗୁଡ଼ିକ ଫୋନ୍‌ କଲ୍ ଲଗ୍ ପଢ଼ିପାରିବେ ଏବଂ ଲେଖିପାରିବେ"</string>
     <string name="permission_description_summary_camera" msgid="108004375101882069">"ଏହି ଅନୁମତି ଥିବା ଆପ୍ସ ଛବି ନେଇପାରିବେ ଏବଂ ଭିଡିଓ ରେକର୍ଡ କରିପାରିବେ"</string>
     <string name="permission_description_summary_contacts" msgid="2337798886460408996">"ଏହି ଅନୁମତି ଥିବା ଆପ୍ସ ଆପଣଙ୍କର ଯୋଗାଯୋଗଗୁଡ଼ିକୁ ଆକ୍ସେସ୍ କରିପାରିବ"</string>
-    <string name="permission_description_summary_location" msgid="2817531799933480694">"ଏହି ଅନୁମତି ଥିବା ଆପ୍ସ ଏହି ଡିଭାଇସ୍‌ର ଲୋକେସନ୍‍ ଆକ୍ସେସ୍‍ କରିପାରିବ"</string>
+    <string name="permission_description_summary_location" msgid="2817531799933480694">"ଏହି ଅନୁମତି ଥିବା ଆପ୍ସ ଏହି ଡିଭାଇସର ଲୋକେସନ ଆକ୍ସେସ କରିପାରିବ"</string>
     <string name="permission_description_summary_nearby_devices" msgid="8269183818275073741">"ଏହି ଅନୁମତି ଥିବା ଆପଗୁଡ଼ିକ ଆଖପାଖର ଡିଭାଇସଗୁଡ଼ିକର ଆପେକ୍ଷିକ ଅବସ୍ଥିତିକୁ ଖୋଜିପାରିବ, ସଂଯୋଗ ଏବଂ ନିର୍ଦ୍ଧାରଣ କରିପାରିବ"</string>
     <string name="permission_description_summary_microphone" msgid="630834800308329907">"ଏହି ଅନୁମତି ଥିବା ଆପ୍ସ ଅଡିଓ ରେକର୍ଡ କରିପାରିବ"</string>
     <string name="permission_description_summary_phone" msgid="4515277217435233619">"ଏହି ଅନୁମତି ଥିବା ଆପ୍ସ ଫୋନ୍ କଲ୍ କରିପାରେ ଏବଂ ପରିଚାଳନା କରିପାରେ"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ଡିଫଲ୍ଟ ଡିଜିଟାଲ ସହାୟକ ଆପ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ଡିଜିଟାଲ୍ Assistant ଆପ୍"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"ଆପଣ ଭ୍ୟୁ କରୁଥିବା ସ୍କ୍ରିନ ସୂଚନାକୁ ଆଧାର କରି ସହାୟକ ଆପ ଆପଣଙ୍କୁ ସାହାଯ୍ୟ କରିପାରିବ। କେତେକ ଆପ ଆପଣଙ୍କୁ ସମ୍ପୂର୍ଣ୍ଣ ସହାୟତା ଦେବା ପାଇଁ ଉଭୟ ଲଞ୍ଚର ଓ ଭଏସ ଇନପୁଟ ସେବାକୁ ସମର୍ଥନ କରେ।"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g>ଦ୍ୱାରା ସୁପାରିଶ କରାଯାଇଛି"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ଡିଫଲ୍ଟ ବ୍ରାଉଜର୍‌ ଆପ୍‌"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ବ୍ରାଉଜର୍‌ ଆପ୍‌"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ଆପ୍ସ ଯାହା ଆପଣଙ୍କୁ ଇଣ୍ଟର୍ନେଟ ପାଇଁ ଆକ୍ସେସ ଦିଏ ଏବଂ ଆପଣ ଟାପ କରୁଥିବା ଲିଙ୍କଗୁଡ଼ିକୁ ଡିସପ୍ଲେ କରେ"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ଓପନିଂ ଲିଙ୍କ୍"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"କାର୍ଯ୍ୟ ପାଇଁ ଡିଫଲ୍ଟ ଅଛି"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ପ୍ରାଇଭେଟ ସ୍ପେସ ପାଇଁ ଡିଫଲ୍ଟ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ଡିଭାଇସ ପାଇଁ ଅପ୍ଟିମାଇଜ କରାଯାଇଛି"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ଅନ୍ୟ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"କିଛି ଆପ ସେଟ କରାଯାଇନାହିଁ"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ସିଷ୍ଟମ୍ ଡିଫଲ୍ଟ)"</string>
diff --git a/PermissionController/res/values-pa-v36/strings.xml b/PermissionController/res/values-pa-v36/strings.xml
new file mode 100644
index 0000000000..ec8611f1f0
--- /dev/null
+++ b/PermissionController/res/values-pa-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"ਹੋਰ ਐਪਾਂ ਦਾ ਏਜੰਟ ਕੰਟਰੋਲ"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ਆਪਣੇ ਡੀਵਾਈਸ ਅਤੇ ਹੋਰ ਐਪਾਂ ਵਿੱਚ ਕਾਰਵਾਈਆਂ ਕਰੋ"</string>
+</resources>
diff --git a/PermissionController/res/values-pa/strings.xml b/PermissionController/res/values-pa/strings.xml
index d90bcbfb90..9833cfe228 100644
--- a/PermissionController/res/values-pa/strings.xml
+++ b/PermissionController/res/values-pa/strings.xml
@@ -84,7 +84,7 @@
     <string name="storage_supergroup_warning_allow" msgid="103093462784523190">"ਇਹ ਐਪ Android ਦੇ ਕਿਸੇ ਪੁਰਾਣੇ ਵਰਜਨ ਲਈ ਬਣਾਈ ਗਈ ਸੀ। ਜੇ ਤੁਸੀਂ ਇਸਦੀ ਇਜਾਜ਼ਤ ਦੀ ਆਗਿਆ ਦਿੰਦੇ ਹੋ, ਤਾਂ ਸਾਰੀ ਸਟੋਰੇਜ (ਫ਼ੋਟੋਆਂ, ਵੀਡੀਓ, ਸੰਗੀਤ, ਆਡੀਓ ਅਤੇ ਹੋਰ ਫ਼ਾਈਲਾਂ ਸਮੇਤ) ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਹੋਵੇਗੀ।"</string>
     <string name="storage_supergroup_warning_deny" msgid="6420765672683284347">"ਇਹ ਐਪ Android ਦੇ ਕਿਸੇ ਪੁਰਾਣੇ ਵਰਜਨ ਲਈ ਬਣਾਈ ਗਈ ਸੀ। ਜੇ ਤੁਸੀਂ ਇਸ ਇਜਾਜ਼ਤ ਨੂੰ ਅਸਵੀਕਾਰ ਕਰਦੇ ਹੋ, ਤਾਂ ਸਾਰੀ ਸਟੋਰੇਜ (ਫ਼ੋਟੋਆਂ, ਵੀਡੀਓ, ਸੰਗੀਤ, ਆਡੀਓ ਅਤੇ ਹੋਰ ਫ਼ਾਈਲਾਂ ਸਮੇਤ) ਤੱਕ ਪਹੁੰਚ ਨੂੰ ਅਸਵੀਕਾਰ ਕੀਤਾ ਜਾਵੇਗਾ।"</string>
     <string name="default_permission_description" msgid="4624464917726285203">"ਕੋਈ ਅਗਿਆਤ ਕਾਰਵਾਈ ਕਰੋ"</string>
-    <string name="app_permissions_group_summary" msgid="8788419008958284002">"<xliff:g id="COUNT_1">%2$d</xliff:g> ਵਿੱਚੋਂ <xliff:g id="COUNT_0">%1$d</xliff:g> ਐਪਾਂ ਨੂੰ ਆਗਿਆ ਦਿੱਤੀ"</string>
+    <string name="app_permissions_group_summary" msgid="8788419008958284002">"<xliff:g id="COUNT_1">%2$d</xliff:g> ਵਿੱਚੋਂ <xliff:g id="COUNT_0">%1$d</xliff:g> ਐਪਾਂ ਨੂੰ ਆਗਿਆ ਹੈ"</string>
     <string name="app_permissions_group_summary2" msgid="4329922444840521150">"<xliff:g id="COUNT_0">%1$d</xliff:g>/<xliff:g id="COUNT_1">%2$d</xliff:g> ਐਪਾਂ ਨੂੰ ਇਜਾਜ਼ਤ ਦਿੱਤੀ"</string>
     <string name="menu_show_system" msgid="4254021607027872504">"ਸਿਸਟਮ ਦਿਖਾਓ"</string>
     <string name="menu_hide_system" msgid="3855390843744028465">"ਸਿਸਟਮ ਲੁਕਾਓ"</string>
@@ -196,7 +196,7 @@
     <string name="precise_image_description" msgid="6349638632303619872">"ਸਹੀ ਟਿਕਾਣਾ"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"ਅੰਦਾਜ਼ਨ ਟਿਕਾਣਾ"</string>
     <string name="app_permission_location_accuracy" msgid="7166912915040018669">"ਸਹੀ ਟਿਕਾਣਾ ਵਰਤੋ"</string>
-    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"ਜਦੋਂ ਸਹੀ ਟਿਕਾਣੇ ਦੀ ਜਾਣਕਾਰੀ ਬੰਦ ਹੋਵੇ, ਤਾਂ ਐਪਾਂ ਤੁਹਾਡੀ ਅੰਦਾਜ਼ਨ ਟਿਕਾਣੇ ਦੀ ਜਾਣਕਾਰੀ ਤੱਕ ਪਹੁੰਚ ਕਰ ਸਕਦੀਆਂ ਹਨ"</string>
+    <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"ਸਹੀ ਟਿਕਾਣੇ ਦੀ ਜਾਣਕਾਰੀ ਬੰਦ ਹੋਣ \'ਤੇ, ਐਪਾਂ ਤੁਹਾਡੇ ਅੰਦਾਜ਼ਨ ਟਿਕਾਣੇ ਦੀ ਜਾਣਕਾਰੀ ਤੱਕ ਪਹੁੰਚ ਕਰ ਸਕਦੀਆਂ ਹਨ"</string>
     <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g> ਸੰਬੰਧੀ ਇਜਾਜ਼ਤ"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"ਇਸ ਐਪ ਲਈ <xliff:g id="PERM">%1$s</xliff:g> ਪਹੁੰਚ"</string>
     <string name="app_permission_header_with_device_name" msgid="7193042925656173271">"<xliff:g id="DEVICE_NAME">%2$s</xliff:g> \'ਤੇ ਇਸ ਐਪ ਲਈ <xliff:g id="PERM">%1$s</xliff:g> ਦੀ ਪਹੁੰਚ"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ਪੂਰਵ-ਨਿਰਧਾਰਿਤ ਡਿਜੀਟਲ ਸਹਾਇਕ ਐਪ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ਡਿਜੀਟਲ ਸਹਾਇਕ ਐਪ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"ਸਹਾਇਕ ਐਪਾਂ ਤੁਹਾਡੇ ਵੱਲੋਂ ਦੇਖੀ ਜਾਂਦੀ ਸਕ੍ਰੀਨ ਤੋਂ ਪ੍ਰਾਪਤ ਜਾਣਕਾਰੀ ਦੇ ਆਧਾਰ \'ਤੇ ਤੁਹਾਡੀ ਮਦਦ ਕਰ ਸਕਦੀਆਂ ਹਨ। ਕੁਝ ਐਪਾਂ ਤੁਹਾਨੂੰ ਏਕੀਕ੍ਰਿਤ ਸਹਾਇਤਾ ਦੇਣ ਲਈ ਲਾਂਚਰ ਅਤੇ ਵੌਇਸ ਇਨਪੁੱਟ ਸੇਵਾਵਾਂ ਦੋਵਾਂ ਦਾ ਸਮਰਥਨ ਕਰਦੀਆਂ ਹਨ।"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> ਵੱਲੋਂ ਸਿਫ਼ਾਰਸ਼ੀ"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ਪੂਰਵ-ਨਿਰਧਾਰਿਤ ਬ੍ਰਾਊਜ਼ਰ ਐਪ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"ਬ੍ਰਾਊਜ਼ਰ ਐਪ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"ਐਪਾਂ ਜੋ ਤੁਹਾਨੂੰ ਇੰਟਰਨੈੱਟ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦਿੰਦੀਆਂ ਹਨ ਅਤੇ ਤੁਹਾਡੇ ਵੱਲੋਂ ਟੈਪ ਕੀਤੇ ਲਿੰਕ ਦਿਖਾਉਂਦੀਆਂ ਹਨ"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"ਖੁੱਲ੍ਹਣ ਵਾਲੇ ਲਿੰਕ"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ਕੰਮ ਲਈ ਪੂਰਵ-ਨਿਰਧਾਰਤ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਲਈ ਪੂਰਵ-ਨਿਰਧਾਰਿਤ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ਡੀਵਾਈਸ ਲਈ ਸੁਯੋਗ ਬਣਾਈਆਂ"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ਹੋਰ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ਕੋਈ ਨਹੀਂ"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ਸਿਸਟਮ ਪੂਰਵ-ਨਿਰਧਾਰਿਤ)"</string>
@@ -473,7 +473,7 @@
     <string name="assistant_record_audio_user_sensitive_summary" msgid="6482937591816401619">"ਜਦੋਂ ਅਵਾਜ਼ੀ ਸਹਾਇਕ ਨੂੰ ਕਿਰਿਆਸ਼ੀਲ ਕਰਨ ਲਈ ਮਾਈਕ੍ਰੋਫ਼ੋਨ ਵਰਤਿਆ ਜਾਂਦਾ ਹੈ ਤਾਂ ਸਥਿਤੀ ਪੱਟੀ ਵਿੱਚ ਪ੍ਰਤੀਕ ਦਿਖਾਓ"</string>
     <string name="permgrouprequest_storage_isolated" msgid="4892154224026852295">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਤੁਹਾਡੇ ਡੀਵਾਈਸ \'ਤੇ ਫ਼ੋਟੋਆਂ ਅਤੇ ਮੀਡੀਆ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_device_aware_storage_isolated" msgid="6463062962458809752">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; \'ਤੇ ਫ਼ੋਟੋਆਂ ਅਤੇ ਮੀਡੀਆ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
-    <string name="permgrouprequest_contacts" msgid="8391550064551053695">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਤੁਹਾਡੇ ਸੰਪਰਕਾਂ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੇਣੀ ਹੈ?"</string>
+    <string name="permgrouprequest_contacts" msgid="8391550064551053695">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਤੁਹਾਡੇ ਸੰਪਰਕਾਂ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_device_aware_contacts" msgid="731025863972535928">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; \'ਤੇ ਆਪਣੇ ਸੰਪਰਕਾਂ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_location" msgid="6990232580121067883">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਇਸ ਡੀਵਾਈਸ ਦੇ ਟਿਕਾਣੇ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_device_aware_location" msgid="6075412127429878638">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; ਦੇ ਟਿਕਾਣੇ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
@@ -527,9 +527,9 @@
     <string name="permgroupupgraderequest_camera" msgid="640758449200241582">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਲਈ ਕੈਮਰਾ ਪਹੁੰਚ ਨੂੰ ਬਦਲਣਾ ਹੈ?"</string>
     <string name="permgroupupgraderequest_device_aware_camera" msgid="3290160912843715236">"ਕੀ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; \'ਤੇ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਲਈ ਕੈਮਰਾ ਪਹੁੰਚ ਨੂੰ ਬਦਲਣਾ ਹੈ?"</string>
     <string name="permgroupupgraderequestdetail_camera" msgid="6642747548010962597">"ਇਹ ਐਪ ਹਰ ਵੇਲੇ ਤਸਵੀਰਾਂ ਖਿੱਚਣ ਅਤੇ ਵੀਡੀਓ ਰਿਕਾਰਡ ਕਰਨ ਦੀ ਇਜਾਜ਼ਤ ਮੰਗਦੀ ਹੈ, ਉਦੋਂ ਵੀ ਜਦੋਂ ਤੁਸੀਂ ਐਪ ਦੀ ਵਰਤੋਂ ਨਾ ਕਰ ਰਹੇ ਹੋਵੋ। "<annotation id="link">"ਸੈਟਿੰਗਾਂ ਵਿੱਚ ਇਜਾਜ਼ਤ ਦਿਓ।"</annotation></string>
-    <string name="permgrouprequest_calllog" msgid="2065327180175371397">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਤੁਹਾਡੇ ਫ਼ੋਨ ਦੇ ਕਾਲ ਲੌਗਾਂ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੇਣੀ ਹੈ?"</string>
+    <string name="permgrouprequest_calllog" msgid="2065327180175371397">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਤੁਹਾਡੇ ਫ਼ੋਨ ਦੇ ਕਾਲ ਲੌਗਾਂ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_device_aware_calllog" msgid="8220927190376843309">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; \'ਤੇ ਆਪਣੇ ਫ਼ੋਨ ਕਾਲ ਲੌਗਾਂ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
-    <string name="permgrouprequest_phone" msgid="1829234136997316752">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਫ਼ੋਨ ਕਾਲਾਂ ਕਰਨ ਅਤੇ ਉਨ੍ਹਾਂ ਦਾ ਪ੍ਰਬੰਧਨ ਕਰਨ ਦੇਣਾ ਹੈ?"</string>
+    <string name="permgrouprequest_phone" msgid="1829234136997316752">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਫ਼ੋਨ ਕਾਲਾਂ ਕਰਨ ਅਤੇ ਉਨ੍ਹਾਂ ਦਾ ਪ੍ਰਬੰਧਨ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_device_aware_phone" msgid="590399263670349955">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; \'ਤੇ ਫ਼ੋਨ ਕਾਲਾਂ ਕਰਨ ਅਤੇ ਉਨ੍ਹਾਂ ਦਾ ਪ੍ਰਬੰਧਨ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_sensors" msgid="4397358316850652235">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ ਤੁਹਾਡੇ ਸਰੀਰ ਦੇ ਅਹਿਮ ਲੱਛਣਾਂ ਸੰਬੰਧੀ ਸੈਂਸਰ ਡਾਟੇ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੇਣੀ ਹੈ?"</string>
     <string name="permgrouprequest_device_aware_sensors" msgid="3874451050573615157">"ਕੀ &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; ਨੂੰ &lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; \'ਤੇ ਤੁਹਾਡੇ ਮਹੱਤਵਪੂਰਨ ਲੱਛਣਾਂ ਸੰਬੰਧੀ ਸੈਂਸਰ ਡਾਟਾ ਤੱਕ ਪਹੁੰਚ ਕਰਨ ਦੀ ਆਗਿਆ ਦੇਣੀ ਹੈ?"</string>
diff --git a/PermissionController/res/values-pl-v36/strings.xml b/PermissionController/res/values-pl-v36/strings.xml
new file mode 100644
index 0000000000..c67c98cb59
--- /dev/null
+++ b/PermissionController/res/values-pl-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agent ma kontrolę nad innymi aplikacjami"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Wykonuj działania na urządzeniu i w innych aplikacjach"</string>
+</resources>
diff --git a/PermissionController/res/values-pl/strings.xml b/PermissionController/res/values-pl/strings.xml
index a83db7d35a..329681bbf2 100644
--- a/PermissionController/res/values-pl/strings.xml
+++ b/PermissionController/res/values-pl/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Domyślny asystent cyfrowy"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Asystent cyfrowy"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikacje asystujące mogą Ci pomagać na podstawie informacji wyświetlanych na ekranie, który oglądasz. Niektóre aplikacje obsługują programy uruchamiające i usługi rozpoznawania mowy, by zapewnić Ci zintegrowane wsparcie."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Rekomendowane przez: <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Domyślna przeglądarka"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Przeglądarka"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikacje zapewniające Ci dostęp do internetu i wyświetlające linki, które klikasz"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Otwieranie linków"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Domyślne do pracy"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Domyślne dla przestrzeni prywatnej"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Zoptymalizowane dla danego urządzenia"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Inne"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Brak"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Domyślna aplikacja systemowa)"</string>
diff --git a/PermissionController/res/values-pt-rBR-v34/strings.xml b/PermissionController/res/values-pt-rBR-v34/strings.xml
index 28380d50bb..78bebb7a50 100644
--- a/PermissionController/res/values-pt-rBR-v34/strings.xml
+++ b/PermissionController/res/values-pt-rBR-v34/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="security_privacy_brand_name" msgid="7303621734258440812">"Segurança física e privacidade"</string>
+    <string name="security_privacy_brand_name" msgid="7303621734258440812">"Segurança e privacidade"</string>
     <string name="privacy_subpage_controls_header" msgid="4152396976713749322">"Controles"</string>
     <string name="health_connect_title" msgid="2132233890867430855">"Conexão Saúde"</string>
     <string name="health_connect_summary" msgid="815473513776882296">"Gerenciar o acesso de apps aos dados de saúde"</string>
diff --git a/PermissionController/res/values-pt-rBR-v36/strings.xml b/PermissionController/res/values-pt-rBR-v36/strings.xml
new file mode 100644
index 0000000000..13b31d1ddd
--- /dev/null
+++ b/PermissionController/res/values-pt-rBR-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Outros apps são controlados por um agente"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Realizar ações no dispositivo e em outros apps"</string>
+</resources>
diff --git a/PermissionController/res/values-pt-rBR/strings.xml b/PermissionController/res/values-pt-rBR/strings.xml
index 8950f9e113..7e1e02a1cd 100644
--- a/PermissionController/res/values-pt-rBR/strings.xml
+++ b/PermissionController/res/values-pt-rBR/strings.xml
@@ -24,7 +24,7 @@
     <string name="dialog_close" msgid="6840699812532384661">"Fechar"</string>
     <string name="available" msgid="6007778121920339498">"Disponível"</string>
     <string name="blocked" msgid="9195547604866033708">"Bloqueado"</string>
-    <string name="on" msgid="280241003226755921">"Ativado"</string>
+    <string name="on" msgid="280241003226755921">"Ativada"</string>
     <string name="off" msgid="1438489226422866263">"Desativar"</string>
     <string name="uninstall_or_disable" msgid="4496612999740858933">"Desinstalar ou desativar"</string>
     <string name="app_not_found_dlg_title" msgid="6029482906093859756">"App não encontrado"</string>
@@ -252,7 +252,7 @@
     <string name="app_permission_most_recent_denied_summary" msgid="7659497197737708112">"Negado atualmente/último acesso: <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_permission_never_accessed_summary" msgid="401346181461975090">"Nunca acessou"</string>
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"Negado/nunca acessado"</string>
-    <string name="allowed_header" msgid="7769277978004790414">"Permitido"</string>
+    <string name="allowed_header" msgid="7769277978004790414">"Permitidas"</string>
     <string name="allowed_always_header" msgid="6455903312589013545">"Permitidos sempre"</string>
     <string name="allowed_foreground_header" msgid="6845655788447833353">"Permitidos durante o uso"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"Com permissão para acessar apenas mídia"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"App assistente digital padrão"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App assistente digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Apps assistivos podem ajudar com base nas informações da tela que você vê no momento. Alguns apps são compatíveis com a tela de início e com serviços de entrada de texto por voz para oferecer assistência integrada."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomendados por <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"App de navegação padrão"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"App de navegação"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps que permitem acesso à Internet e links clicáveis."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Abrir links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Padrão para trabalho"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Padrão para o espaço privado"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Otimizados para o dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Outros"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nenhum"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Padrão do sistema)"</string>
diff --git a/PermissionController/res/values-pt-rPT-v36/strings.xml b/PermissionController/res/values-pt-rPT-v36/strings.xml
new file mode 100644
index 0000000000..ca451d118f
--- /dev/null
+++ b/PermissionController/res/values-pt-rPT-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Controlo de agentes de outras apps"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Execute ações no seu dispositivo e noutras apps"</string>
+</resources>
diff --git a/PermissionController/res/values-pt-rPT/strings.xml b/PermissionController/res/values-pt-rPT/strings.xml
index bdf9b2567f..59b02e67fb 100644
--- a/PermissionController/res/values-pt-rPT/strings.xml
+++ b/PermissionController/res/values-pt-rPT/strings.xml
@@ -163,7 +163,7 @@
     <string name="permission_usage_bar_chart_title_last_15_minutes" msgid="2743143675412824819">"Utilização das autorizações nos últimos 15 minutos"</string>
     <string name="permission_usage_bar_chart_title_last_minute" msgid="820450867183487607">"Utilização das autorizações no último minuto"</string>
     <string name="permission_usage_preference_summary_not_used_in_past_n_days" msgid="4771868094611359651">"{count,plural, =1{Não usada há # dia}many{Não usada há # dias}other{Não usada há # dias}}"</string>
-    <string name="permission_usage_preference_summary_not_used_in_past_n_hours" msgid="3828973177433435742">"{count,plural, =1{Não usada há # hora}many{Não usada há # horas}other{Não usada há # horas}}"</string>
+    <string name="permission_usage_preference_summary_not_used_in_past_n_hours" msgid="3828973177433435742">"{count,plural, =1{Não usado há # hora}many{Não usado há # horas}other{Não usado há # horas}}"</string>
     <string name="permission_usage_preference_label" msgid="8343167938128676378">"{count,plural, =1{Utilização: 1 app}many{Utilização: # apps}other{Utilização: # apps}}"</string>
     <string name="permission_usage_view_details" msgid="6675335735468752787">"Ver tudo no painel de controlo"</string>
     <string name="app_permission_usage_filter_label" msgid="7182861154638631550">"Filtrado por: <xliff:g id="PERM">%1$s</xliff:g>"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"App de assistente digital predefinida"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App assistente digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"As apps de assistência podem ser-lhe úteis com base em informações do ecrã que está a ver. Algumas apps são compatíveis com serviços de iniciação e de entrada de texto por voz para oferecer assistência integrada."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomendações da <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"App navegador predefinida"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"App de navegador"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps que lhe dão acesso à Internet e apresentam links em que pode tocar."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Abertura de links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predefinição para o trabalho"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Predefinição para espaço privado"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Otimizadas para o dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Outras"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nenhuma"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Predefinição do sistema)"</string>
@@ -662,7 +662,7 @@
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"Atualizações da partilha de dados para a localização"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"Reveja apps que mudaram a forma de partilhar os seus dados de localização"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Estas apps mudaram a forma de partilhar os seus dados de localização. É possível que não os tenham partilhado antes ou que passem a partilhá-los agora para fins de publicidade ou marketing."</string>
-    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Os programadores destas apps deram informações sobre as respetivas práticas de partilha de dados a uma loja de apps. Podem atualizá-las ao longo do tempo.\n\nAs práticas de partilha de dados podem variar consoante a versão da app, a utilização, a região e a idade."</string>
+    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Os programadores destas apps cederam informações sobre as respetivas práticas de partilha de dados a uma loja de apps. Podem ir atualizando as mesmas.\n\nAs práticas de partilha de dados podem variar consoante a versão da app, a utilização, a região e a idade."</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"Saiba mais sobre a partilha de dados"</string>
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"Os seus dados de localização são agora partilhados com terceiros"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"Os seus dados de localização são agora partilhados com terceiros para fins de publicidade ou marketing"</string>
diff --git a/PermissionController/res/values-pt-v34/strings.xml b/PermissionController/res/values-pt-v34/strings.xml
index 28380d50bb..78bebb7a50 100644
--- a/PermissionController/res/values-pt-v34/strings.xml
+++ b/PermissionController/res/values-pt-v34/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="security_privacy_brand_name" msgid="7303621734258440812">"Segurança física e privacidade"</string>
+    <string name="security_privacy_brand_name" msgid="7303621734258440812">"Segurança e privacidade"</string>
     <string name="privacy_subpage_controls_header" msgid="4152396976713749322">"Controles"</string>
     <string name="health_connect_title" msgid="2132233890867430855">"Conexão Saúde"</string>
     <string name="health_connect_summary" msgid="815473513776882296">"Gerenciar o acesso de apps aos dados de saúde"</string>
diff --git a/PermissionController/res/values-pt-v36/strings.xml b/PermissionController/res/values-pt-v36/strings.xml
new file mode 100644
index 0000000000..13b31d1ddd
--- /dev/null
+++ b/PermissionController/res/values-pt-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Outros apps são controlados por um agente"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Realizar ações no dispositivo e em outros apps"</string>
+</resources>
diff --git a/PermissionController/res/values-pt/strings.xml b/PermissionController/res/values-pt/strings.xml
index 8950f9e113..7e1e02a1cd 100644
--- a/PermissionController/res/values-pt/strings.xml
+++ b/PermissionController/res/values-pt/strings.xml
@@ -24,7 +24,7 @@
     <string name="dialog_close" msgid="6840699812532384661">"Fechar"</string>
     <string name="available" msgid="6007778121920339498">"Disponível"</string>
     <string name="blocked" msgid="9195547604866033708">"Bloqueado"</string>
-    <string name="on" msgid="280241003226755921">"Ativado"</string>
+    <string name="on" msgid="280241003226755921">"Ativada"</string>
     <string name="off" msgid="1438489226422866263">"Desativar"</string>
     <string name="uninstall_or_disable" msgid="4496612999740858933">"Desinstalar ou desativar"</string>
     <string name="app_not_found_dlg_title" msgid="6029482906093859756">"App não encontrado"</string>
@@ -252,7 +252,7 @@
     <string name="app_permission_most_recent_denied_summary" msgid="7659497197737708112">"Negado atualmente/último acesso: <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_permission_never_accessed_summary" msgid="401346181461975090">"Nunca acessou"</string>
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"Negado/nunca acessado"</string>
-    <string name="allowed_header" msgid="7769277978004790414">"Permitido"</string>
+    <string name="allowed_header" msgid="7769277978004790414">"Permitidas"</string>
     <string name="allowed_always_header" msgid="6455903312589013545">"Permitidos sempre"</string>
     <string name="allowed_foreground_header" msgid="6845655788447833353">"Permitidos durante o uso"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"Com permissão para acessar apenas mídia"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"App assistente digital padrão"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"App assistente digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Apps assistivos podem ajudar com base nas informações da tela que você vê no momento. Alguns apps são compatíveis com a tela de início e com serviços de entrada de texto por voz para oferecer assistência integrada."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomendados por <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"App de navegação padrão"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"App de navegação"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Apps que permitem acesso à Internet e links clicáveis."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Abrir links"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Padrão para trabalho"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Padrão para o espaço privado"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Otimizados para o dispositivo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Outros"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Nenhum"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Padrão do sistema)"</string>
diff --git a/PermissionController/res/values-ro-v36/strings.xml b/PermissionController/res/values-ro-v36/strings.xml
new file mode 100644
index 0000000000..9fe78cb000
--- /dev/null
+++ b/PermissionController/res/values-ro-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Controlul agentului asupra altor aplicații"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Realizează acțiuni pe dispozitivul tău și în alte aplicații"</string>
+</resources>
diff --git a/PermissionController/res/values-ro/strings.xml b/PermissionController/res/values-ro/strings.xml
index 570c9ad489..8c18c39bc1 100644
--- a/PermissionController/res/values-ro/strings.xml
+++ b/PermissionController/res/values-ro/strings.xml
@@ -64,7 +64,7 @@
     <string name="unused_apps" msgid="2058057455175955094">"Aplicații nefolosite"</string>
     <string name="edit_photos_description" msgid="5540108003480078892">"Editează fotografiile selectate pentru această aplicație"</string>
     <string name="no_unused_apps" msgid="12809387670415295">"Nu există aplicații nefolosite"</string>
-    <string name="zero_unused_apps" msgid="9024448554157499748">"0 aplicații nefolosite"</string>
+    <string name="zero_unused_apps" msgid="9024448554157499748">"Nicio aplicație nefolosită"</string>
     <string name="review_permission_decisions" msgid="309559429150613632">"Decizii recente privind permisiunile"</string>
     <string name="review_permission_decisions_view_all" msgid="90391040431566130">"Vezi toate deciziile recente privind permisiunile"</string>
     <string name="review_permission_decisions_empty" msgid="8120775336417279806">"Nicio decizie recentă privind permisiunile"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Aplicația asistent digital prestabilită"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplicația asistent digital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplicațiile asistent te pot ajuta pe baza informațiilor din ecranul afișat. Pentru a-ți oferi o asistență integrată, unele aplicații acceptă atât serviciile cu lansatoare, cât și pe cele de intrare vocală."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Recomandate de <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Aplicația browser prestabilită"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplicația browser"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplicații care îți oferă acces la internet și afișează linkurile pe care le atingi"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Deschiderea linkurilor"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Prestabilite pentru serviciu"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Prestabilit pentru spațiul privat"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizate pentru dispozitiv"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Altele"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Niciuna"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Prestabilită de sistem)"</string>
diff --git a/PermissionController/res/values-ru-v33/strings.xml b/PermissionController/res/values-ru-v33/strings.xml
index 5506ccd973..cdab11b25c 100644
--- a/PermissionController/res/values-ru-v33/strings.xml
+++ b/PermissionController/res/values-ru-v33/strings.xml
@@ -34,7 +34,7 @@
     <string name="safety_center_issue_card_prefix_content_description" msgid="1447445289637043544">"Оповещение. <xliff:g id="ISSUE_CARD_TITLE">%1$s</xliff:g>"</string>
     <string name="safety_center_resolved_issue_fallback" msgid="8548932070610766651">"Действие выполнено"</string>
     <string name="safety_center_qs_status_summary" msgid="5193925895830451177">"Изучите настройки, позволяющие усилить защиту устройства"</string>
-    <string name="safety_center_qs_page_landing" msgid="1717368301679228128">"Быстрые настройки безопасности и конфиденциальности"</string>
+    <string name="safety_center_qs_page_landing" msgid="1717368301679228128">"Быстрые настройки защиты и конфиденциальности"</string>
     <string name="safety_center_qs_close_button" msgid="1352313308176244599">"Закрыть"</string>
     <string name="safety_center_qs_expand_action" msgid="2193190557696484169">"Развернуть и показать параметры"</string>
     <string name="safety_center_qs_collapse_action" msgid="5809657430125309183">"Свернуть"</string>
diff --git a/PermissionController/res/values-ru-v36/strings.xml b/PermissionController/res/values-ru-v36/strings.xml
new file mode 100644
index 0000000000..1b0d5bd22a
--- /dev/null
+++ b/PermissionController/res/values-ru-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Агентное управление другими приложениями"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Совершайте действия на своем устройстве и в других приложениях"</string>
+</resources>
diff --git a/PermissionController/res/values-ru/strings.xml b/PermissionController/res/values-ru/strings.xml
index 8f858e7660..2c3ad2736c 100644
--- a/PermissionController/res/values-ru/strings.xml
+++ b/PermissionController/res/values-ru/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Цифровой помощник по умолчанию"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Цифровой помощник"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Приложения-помощники могут использовать информацию на экране. Для большего удобства некоторые из них поддерживают запуск других приложений и голосовой ввод."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Рекомендовано компанией \"<xliff:g id="OEM_NAME">%s</xliff:g>\""</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Браузер по умолчанию"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Браузер"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Приложения, с помощью которых можно просматривать сайты и переходить по ссылкам."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Переход по ссылкам"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Стандартные для работы"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Приложения по умолчанию для личного пространства"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Оптимизированные для устройства"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Прочие"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Нет"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(по умолчанию)"</string>
@@ -576,7 +576,7 @@
     <string name="safety_center_rescan_button" msgid="4517514567809409596">"Сканировать устройство"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"Закрыть"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"Закрыть оповещение?"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Проверить и изменить настройки конфиденциальности и безопасности можно в любое время."</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Проверить и изменить настройки защиты и безопасности можно в любое время."</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"Закрыть"</string>
     <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"Отмена"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"Настройки"</string>
diff --git a/PermissionController/res/values-si-v36/strings.xml b/PermissionController/res/values-si-v36/strings.xml
new file mode 100644
index 0000000000..1a836bc82d
--- /dev/null
+++ b/PermissionController/res/values-si-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"වෙනත් යෙදුම්වල නියෝජිත පාලනය"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ඔබේ උපාංගයේ සහ අනෙකුත් යෙදුම්වල ක්‍රියා සිදු කරන්න"</string>
+</resources>
diff --git a/PermissionController/res/values-si/strings.xml b/PermissionController/res/values-si/strings.xml
index 4319a25bc9..6a6283e437 100644
--- a/PermissionController/res/values-si/strings.xml
+++ b/PermissionController/res/values-si/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"පෙරනිමි ඩිජිටල් සහායක යෙදුම"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ඩිජිටල් සහායක යෙදුම"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"සහායක යෙදුම්වලට ඔබ බලන තිරයෙන් ලැබෙන තොරතුරුවලට අනුව ඔබට උදවු කළ හැක. සමහර යෙදුම් ඔබට ඒකාබද්ධ සහය ලබා දීමට දියක්කරණය සහ හඬ ආදාන සේවා යන දෙකටම සහය දක්වති."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> විසින් නිර්දේශ කර ඇත"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"පෙරනිමි බ්‍රවුසර යෙදුම"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"බ්‍රවුසර යෙදුම"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"අන්තර්ජාලය වෙත ඔබට ප්‍රවේශය දෙන යෙදුම් සහ ඔබ තට්ටු කරන සංදර්ශන සබැඳි"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"සබැඳි විවෘත කිරීම"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"වැඩ සඳහා පෙරනිමි"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"රහසිගත අවකාශය සඳහා පෙරනිමිය"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"උපාංගය සඳහා ප්‍රශස්ත කර ඇත"</string>
     <string name="default_app_others" msgid="7793029848126079876">"වෙනත්"</string>
     <string name="default_app_none" msgid="9084592086808194457">"කිසිවක් නැත"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(පද්ධතිය පෙරනිමි)"</string>
diff --git a/PermissionController/res/values-sk-v36/strings.xml b/PermissionController/res/values-sk-v36/strings.xml
new file mode 100644
index 0000000000..68e65b0d21
--- /dev/null
+++ b/PermissionController/res/values-sk-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Ovládanie iných aplikácií agentom"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Vykonávajte akcie vo svojom zariadení a ďalších aplikáciách"</string>
+</resources>
diff --git a/PermissionController/res/values-sk/strings.xml b/PermissionController/res/values-sk/strings.xml
index 1dc04a5abc..06dafc0659 100644
--- a/PermissionController/res/values-sk/strings.xml
+++ b/PermissionController/res/values-sk/strings.xml
@@ -323,7 +323,7 @@
     <string name="permission_subtitle_media_only" msgid="8917869683764720717">"Médiá"</string>
     <string name="permission_subtitle_all_files" msgid="4982613338298067862">"Všetky súbory"</string>
     <string name="permission_subtitle_background" msgid="8916750995309083180">"Povolené vždy"</string>
-    <string name="app_perms_24h_access" msgid="99069906850627181">"Naposledy použité <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
+    <string name="app_perms_24h_access" msgid="99069906850627181">"Naposledy použité: <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_perms_24h_access_yest" msgid="5411926024794555022">"Naposledy použité včera o <xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_perms_7d_access" msgid="4945055548894683751">"Naposledy použité <xliff:g id="TIME_DATE_0">%1$s</xliff:g> o <xliff:g id="TIME_DATE_1">%2$s</xliff:g>"</string>
     <string name="app_perms_content_provider_24h" msgid="1055526027667508972">"Použité v posledných 24 hodinách"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Predvolený digitálny asistent"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitálny asistent"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Asistenčné aplikácie pomáhajú na základe informácií zo zobrazenej obrazovky. Niektoré aplikácie podporujú spúšťače aj hlasový vstup, a ponúkajú tak integrovanú asistenciu."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> odporúča"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Predvolený prehliadač"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Prehliadač"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikácie, ktoré umožňujú prehliadať internet a otvárať webové odkazy"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Otváranie odkazov"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Predvolené na prácu"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Predvolené pre súkromný priestor"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimalizované pre zariadenie"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Iné"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Žiadna aplikácia"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Predvolené systémom)"</string>
@@ -575,8 +575,8 @@
     <string name="safety_center_dashboard_page_title" msgid="2810774008694315854">"Zabezpečenie, ochrana súkromia"</string>
     <string name="safety_center_rescan_button" msgid="4517514567809409596">"Skontrolovať zariadenie"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"Zavrieť"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"Chcete zavrieť toto upozornenie?"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Kedykoľvek si môžete skontrolovať nastavenia zabezpečenia a ochrany súkromia a ochranu zlepšiť"</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"Chcete varovanie zavrieť?"</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"Nastavenia zabezpečenia a ochrany súkromia môžete kedykoľvek skontrolovať  a stupeň ochrany zvýšiť"</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"Zavrieť"</string>
     <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"Zrušiť"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"Nastavenia"</string>
@@ -667,7 +667,7 @@
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"Údaje o vašej polohe sa teraz zdieľajú s tretími stranami"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"Údaje o vašej polohe sa teraz zdieľajú s tretími stranami na účely reklamy a marketingu"</string>
     <string name="updated_in_last_days" msgid="8371811947153042322">"{count,plural, =0{Aktualizované v priebehu uplynulého dňa}=1{Aktualizované v priebehu uplynulého dňa}few{Aktualizované v priebehu uplynulých # dní}many{Aktualizované v priebehu uplynulej # dňa}other{Aktualizované v priebehu uplynulých # dní}}"</string>
-    <string name="no_updates_at_this_time" msgid="9031085635689982935">"Momentálne neprebehli žiadne aktualizácie"</string>
+    <string name="no_updates_at_this_time" msgid="9031085635689982935">"Momentálne nie sú k dispozícii žiadne aktualizácie"</string>
     <string name="safety_label_changes_notification_title" msgid="4479955083472203839">"Aktualizácie zdieľania údajov"</string>
     <string name="safety_label_changes_notification_desc" msgid="7808764283266234675">"Niektoré aplikácie zmenili spôsob zdieľania údajov o polohe"</string>
     <string name="safety_label_changes_gear_description" msgid="2655887555599138509">"Nastavenia"</string>
diff --git a/PermissionController/res/values-sl-v36/strings.xml b/PermissionController/res/values-sl-v36/strings.xml
new file mode 100644
index 0000000000..b4c12ee6f5
--- /dev/null
+++ b/PermissionController/res/values-sl-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Nadzor agenta nad drugimi aplikacijami"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Izvajanje dejanj v napravi in drugih aplikacijah"</string>
+</resources>
diff --git a/PermissionController/res/values-sl/strings.xml b/PermissionController/res/values-sl/strings.xml
index 0a822baac1..9ec9820a2d 100644
--- a/PermissionController/res/values-sl/strings.xml
+++ b/PermissionController/res/values-sl/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Privzeti digitalni pomočnik"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digitalni pomočnik"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikacije za pomoč vam pomagajo na podlagi podatkov na zaslonu, ki si ga ogledujete. Nekatere aplikacije podpirajo storitve zaganjalnika in glasovnega vnosa pri zagotavljanju integrirane pomoči."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Priporoča <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Privzeti brskalnik"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Brskalnik"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikacije, ki vam omogočajo dostop do interneta in prikaz povezav, ki se jih dotaknete."</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Odpiranje povezav"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Privzeto za delo"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Privzeto za zasebni prostor"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizirano za napravo"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Drugo"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Brez"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(privzeta v sistemu)"</string>
diff --git a/PermissionController/res/values-sq-v33/strings.xml b/PermissionController/res/values-sq-v33/strings.xml
index 038dc8d391..d24e4cf2e3 100644
--- a/PermissionController/res/values-sq-v33/strings.xml
+++ b/PermissionController/res/values-sq-v33/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="role_dialer_request_description" msgid="6188305064871543419">"Ky aplikacion do të lejohet të të dërgojë njoftime dhe do t\'i jepet qasje te kamera, kontaktet, mikrofoni, telefoni dhe mesazhet SMS"</string>
     <string name="role_sms_request_description" msgid="1506966389698625395">"Ky aplikacion do të lejohet të të dërgojë njoftime dhe do t\'i jepet qasje te \"Kamera\", \"Kontaktet\", \"Skedarët\", \"Mikrofoni\", \"Telefoni\" dhe \"SMS-të\""</string>
-    <string name="permission_description_summary_storage" msgid="1917071243213043858">"Aplikacionet me këtë leje mund të kenë qasje tek të gjithë skedarët në këtë pajisje"</string>
+    <string name="permission_description_summary_storage" msgid="1917071243213043858">"Aplikacionet me këtë leje mund të kenë qasje te të gjithë skedarët në këtë pajisje"</string>
     <string name="work_policy_title" msgid="832967780713677409">"Informacioni i politikës së punës"</string>
     <string name="work_policy_summary" msgid="3886113358084963931">"Cilësimet menaxhohen nga administratori i teknologjisë së informacionit"</string>
     <string name="safety_center_entry_group_expand_action" msgid="5358289574941779652">"Zgjero dhe shfaq listën"</string>
diff --git a/PermissionController/res/values-sq-v36/strings.xml b/PermissionController/res/values-sq-v36/strings.xml
new file mode 100644
index 0000000000..41622a8590
--- /dev/null
+++ b/PermissionController/res/values-sq-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Kontrolli i agjentit në aplikacione të tjera"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Kryej veprime në pajisjen tënde dhe në aplikacione të tjera"</string>
+</resources>
diff --git a/PermissionController/res/values-sq/strings.xml b/PermissionController/res/values-sq/strings.xml
index 73d2f27fed..7bbfdede36 100644
--- a/PermissionController/res/values-sq/strings.xml
+++ b/PermissionController/res/values-sq/strings.xml
@@ -260,7 +260,7 @@
     <string name="ask_header" msgid="2633816846459944376">"Pyet çdo herë"</string>
     <string name="denied_header" msgid="903209608358177654">"Nuk lejohet"</string>
     <string name="permission_group_name_with_device_name" msgid="8798741850536024820">"<xliff:g id="PERM_GROUP_NAME">%1$s</xliff:g> në <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
-    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Shiko më shumë aplikacione me qasje tek të gjithë skedarët"</string>
+    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Shiko më shumë aplikacione me qasje te të gjithë skedarët"</string>
     <string name="days" msgid="609563020985571393">"{count,plural, =1{1 ditë}other{# ditë}}"</string>
     <string name="hours" msgid="7302866489666950038">"{count,plural, =1{# orë}other{# orë}}"</string>
     <string name="minutes" msgid="4868414855445375753">"{count,plural, =1{# minutë}other{# minuta}}"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Apl. i parazgjedhur i asistentit dixhital"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Aplikacioni i asistentit dixhital"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Aplikacionet e asistentit të ndihmojnë bazuar në informacionet nga ekrani që je duke shikuar. Disa aplikacione mbështesin shërbimet e nisësit dhe të hyrjes me zë për të të siguruar një ndihmë të integruar."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Rekomanduar nga <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Aplikacioni i parazgjedhur i shfletuesit"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Aplikacioni i shfletuesit"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Aplikacionet që të japin qasje në internet dhe që shfaqin lidhjet që troket ti"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Hapja e lidhjeve"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Të parazgjedhura për punën"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Të parazgjedhurat për hapësirën private"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimizuar për pajisjen"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Të tjera"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Asnjë"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Parazgjedhja e sistemit)"</string>
diff --git a/PermissionController/res/values-sr-v36/strings.xml b/PermissionController/res/values-sr-v36/strings.xml
new file mode 100644
index 0000000000..0015981738
--- /dev/null
+++ b/PermissionController/res/values-sr-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Контролишите друге апликације помоћу агента"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Обављајте радње на уређају и у другим апликацијама"</string>
+</resources>
diff --git a/PermissionController/res/values-sr/strings.xml b/PermissionController/res/values-sr/strings.xml
index aeb17d32a6..fff88c1452 100644
--- a/PermissionController/res/values-sr/strings.xml
+++ b/PermissionController/res/values-sr/strings.xml
@@ -260,7 +260,7 @@
     <string name="ask_header" msgid="2633816846459944376">"Питај сваки пут"</string>
     <string name="denied_header" msgid="903209608358177654">"Није дозвољено"</string>
     <string name="permission_group_name_with_device_name" msgid="8798741850536024820">"<xliff:g id="PERM_GROUP_NAME">%1$s</xliff:g> на уређају <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
-    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Прикажи још апликација са приступом свим фајловима"</string>
+    <string name="storage_footer_hyperlink_text" msgid="8873343987957834810">"Погледајте још апликација које имају приступ свим фајловима"</string>
     <string name="days" msgid="609563020985571393">"{count,plural, =1{1 дан}one{# дан}few{# дана}other{# дана}}"</string>
     <string name="hours" msgid="7302866489666950038">"{count,plural, =1{# сат}one{# сат}few{# сата}other{# сати}}"</string>
     <string name="minutes" msgid="4868414855445375753">"{count,plural, =1{# минут}one{# минут}few{# минута}other{# минута}}"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Подразумевани дигитални помоћник"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Апликација дигиталног помоћника"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Апликације за помоћ могу да вам помогну на основу информација са екрана који гледате. Неке апликације подржавају услуге покретача и гласовног уноса да би вам пружиле интегрисану помоћ."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Препоручује <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Подразумевана апл. прегледача"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Апликација прегледача"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Апликације које вам дају приступ интернету и приказују линкове које можете да додирнете"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Отварање линкова"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Подразумевана за посао"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Подразумевано за приватан простор"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Оптимизовано за уређај"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Друго"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ништа"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Подразумевана системска)"</string>
diff --git a/PermissionController/res/values-sv-v36/strings.xml b/PermissionController/res/values-sv-v36/strings.xml
new file mode 100644
index 0000000000..82176824c4
--- /dev/null
+++ b/PermissionController/res/values-sv-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Agentstyrning av andra appar"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Utför åtgärder på enheten och i andra appar"</string>
+</resources>
diff --git a/PermissionController/res/values-sv/strings.xml b/PermissionController/res/values-sv/strings.xml
index 8f12c1ea33..d11a8fd535 100644
--- a/PermissionController/res/values-sv/strings.xml
+++ b/PermissionController/res/values-sv/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="6098036489833144040">"Behörighetsansvarig"</string>
+    <string name="app_name" msgid="6098036489833144040">"Behörighetsinställning"</string>
     <string name="ok" msgid="1936281769725676272">"OK"</string>
     <string name="permission_search_keyword" msgid="1214451577494730543">"behörigheter"</string>
     <string name="cancel" msgid="8943320028373963831">"Avbryt"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Digital assistentapp, standard"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistentapp"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Med assistentappar kan du få hjälp som baseras på den information som visas på den aktuella skärmen. Vissa appar har stöd för både översikts- och röstinmatningstjänster för att hjälpa dig."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Rekommenderas av <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Standard­webbläsarapp"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Webbläsarapp"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Appar som visar länkar du trycker på och du använder för att ansluta till internet"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Öppna länkar"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Standardinställning för jobbet"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Standard för privat utrymme"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Optimerade för enheten"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Andra"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Ingen"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(System­standard)"</string>
diff --git a/PermissionController/res/values-sw-v36/strings.xml b/PermissionController/res/values-sw-v36/strings.xml
new file mode 100644
index 0000000000..6d4c7e54ca
--- /dev/null
+++ b/PermissionController/res/values-sw-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Usaidizi wa kudhibiti programu nyingine"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Hutekeleza vitendo kwenye kifaa chako na katika programu nyingine"</string>
+</resources>
diff --git a/PermissionController/res/values-sw/strings.xml b/PermissionController/res/values-sw/strings.xml
index 16ce69c026..34f03e682a 100644
--- a/PermissionController/res/values-sw/strings.xml
+++ b/PermissionController/res/values-sw/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Programu msingi ya usaidizi wa kidijitali"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Programu saidizi ya kidijitali"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Programu za usaidizi zinaweza kukusaidia kulingana na maelezo kutoka kwenye skrini unayoangalia. Baadhi ya programu zinaweza kutumia huduma za kifungua programu na kuweka data kwa kutamka ili kukupa usaidizi jumuifu."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Zimependekezwa na <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Programu kuu ya kivinjari"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Programu ya kivinjari"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Programu zinazokupa uwezo wa kufikia intaneti na kuonyesha viungo unavyogusa"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Kufungua viungo"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Programu chaguomsingi kazini"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Programu chaguomsingi za sehemu ya faragha"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Zilizoboreshwa ili kufaa kifaa chako"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Nyingine"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Hakuna"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Programu chaguomsingi ya mfumo)"</string>
@@ -562,7 +562,7 @@
     <string name="blocked_camera_title" msgid="1128510551791284384">"Kamera ya kifaa imezuiwa"</string>
     <string name="blocked_microphone_title" msgid="1631517143648232585">"Maikrofoni ya kifaa imezuiwa"</string>
     <string name="blocked_location_title" msgid="2005608279812892383">"Utambuzi wa mahali kifaa kilipo umezimwa"</string>
-    <string name="blocked_sensor_summary" msgid="4443707628305027375">"Kwa ajili ya programu na huduma"</string>
+    <string name="blocked_sensor_summary" msgid="4443707628305027375">"Kwa programu na huduma"</string>
     <string name="blocked_mic_summary" msgid="8960466941528458347">"Huenda bado data ya maikrofoni ikashirikiwa unapopigia namba ya dharura."</string>
     <string name="blocked_sensor_button_label" msgid="6742092634984289658">"Badilisha"</string>
     <string name="automotive_blocked_camera_title" msgid="6142362431548829416">"Idhini ya kufikia kamera imezimwa"</string>
@@ -662,7 +662,7 @@
     <string name="data_sharing_updates_title" msgid="7996933386875213859">"Masasisho ya kushiriki data ya mahali"</string>
     <string name="data_sharing_updates_summary" msgid="764113985772233889">"Kagua programu zilizobadilisha jinsi zinavyoweza kushiriki data ya mahali ulipo"</string>
     <string name="data_sharing_updates_subtitle" msgid="6311537708950632329">"Programu hizi zimebadilisha jinsi zinavyoweza kushiriki data ya mahali ulipo. Huenda zilikuwa haziishiriki hapo awali au sasa zinaweza kuishiriki kwa madhumuni ya utangazaji au uuzaji."</string>
-    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Wasanidi wa programu hizi wametoa maelezo kuhusu mbinu zao za kushiriki data kwenye duka la programu. Wanaweza kuyasasisha kadiri muda unavyosonga.\n\nMbinu za kushiriki data zinaweza kutofautiana kulingana na toleo la programu, matumizi, eneo na umri wako."</string>
+    <string name="data_sharing_updates_footer_message" msgid="1582711655172892107">"Wasanidi wa programu hizi wametoa maelezo kuhusu mbinu zao za kuruhusu ufikiaji wa data kwenye duka la programu. Wanaweza kuyasasisha kadiri muda unavyosonga.\n\nMbinu za kuruhusu ufikiaji wa data zinaweza kutofautiana kulingana na toleo la programu, matumizi, eneo na umri wako."</string>
     <string name="learn_about_data_sharing" msgid="4200480587079488045">"Pata maelezo kuhusu kushiriki data"</string>
     <string name="shares_location_with_third_parties" msgid="2278051743742057767">"Sasa data ya mahali ulipo inashirikiwa na wengine"</string>
     <string name="shares_location_with_third_parties_for_advertising" msgid="1918588064014480513">"Sasa data ya mahali ulipo inashirikiwa na wengine kwa madhumuni ya utangazaji au uuzaji"</string>
@@ -682,7 +682,7 @@
     <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"Mipangilio hii imezuiwa ili kulinda kifaa na data yako.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
-</xliff:g>Walaghai wanaweza kujaribu kuweka programu hatari kwenye kifaa chako kwa kukuomba uweke programu zisizojulikana kutoka chanzo kigeni."</string>
+</xliff:g>Walaghai wanaweza kujaribu kuweka programu hatari kwenye kifaa chako kwa kukuomba uweke programu zisizojulikana kutoka chanzo geni."</string>
     <string name="enhanced_confirmation_phone_state_dialog_a11y_desc" msgid="6567523001053288057">"<xliff:g id="EMPTY_LINE">
 
 </xliff:g>Walaghai wanaweza kujaribu kudhibiti kifaa chako kwa kukuomba uruhusu programu ifikie vipengele vya ufikivu."</string>
diff --git a/PermissionController/res/values-ta-v36/strings.xml b/PermissionController/res/values-ta-v36/strings.xml
new file mode 100644
index 0000000000..cb74a29ffd
--- /dev/null
+++ b/PermissionController/res/values-ta-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"பிற ஆப்ஸின் ஏஜெண்ட் கட்டுப்பாடு"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"உங்கள் சாதனத்திலும் பிற ஆப்ஸிலும் செயல்களைச் செய்யலாம்"</string>
+</resources>
diff --git a/PermissionController/res/values-ta/strings.xml b/PermissionController/res/values-ta/strings.xml
index 49f81b467a..b3e89dfc4b 100644
--- a/PermissionController/res/values-ta/strings.xml
+++ b/PermissionController/res/values-ta/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"இயல்பான டிஜிட்டல் அசிஸ்டண்ட்"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"டிஜிட்டல் அசிஸ்டண்ட் ஆப்ஸ்"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"நீங்கள் பார்க்கும் திரையில் உள்ள தகவலின் அடிப்படையில் அசிஸ்ட் ஆப்ஸ் உதவும். ஒருங்கிணைந்த உதவியை வழங்குவதற்காக \'தொடக்கியையும்\' \'குரல் உள்ளீட்டுச் சேவைகளையும்\' சில ஆப்ஸ் பயன்படுத்துகின்றன."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> பரிந்துரைப்பவை"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"உலாவிக்கான இயல்பான ஆப்ஸ்"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"பிரவுசர் ஆப்ஸ்"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"இணையத்திற்கும் திரையில் பார்த்துத் தட்டக்கூடிய இணைப்புகளுக்கும் அணுகலை வழங்கும் ஆப்ஸ்"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"இணைப்புகளைத் திறத்தல்"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"பணிக்கான இயல்பு நிலை ஆப்ஸ்"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ரகசிய இடத்திற்கான இயல்பு"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"சாதனத்திற்காக மேம்படுத்தப்பட்டவை"</string>
     <string name="default_app_others" msgid="7793029848126079876">"மற்றவை"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ஏதுமில்லை"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(சிஸ்டத்தின் இயல்புநிலை)"</string>
diff --git a/PermissionController/res/values-te-v36/strings.xml b/PermissionController/res/values-te-v36/strings.xml
new file mode 100644
index 0000000000..9c9562d0a6
--- /dev/null
+++ b/PermissionController/res/values-te-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"ఇతర యాప్‌లకు సంబంధించిన ఏజెంట్ కంట్రోల్"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"మీ డివైజ్‌లో, ఇతర యాప్‌లలో చర్యలను అమలు చేయండి"</string>
+</resources>
diff --git a/PermissionController/res/values-te/strings.xml b/PermissionController/res/values-te/strings.xml
index 0d07bf6c16..363953c30f 100644
--- a/PermissionController/res/values-te/strings.xml
+++ b/PermissionController/res/values-te/strings.xml
@@ -40,7 +40,7 @@
     <string name="grant_dialog_button_allow_more_selected_photos" msgid="5145657877588697709">"మరిన్ని ఫోటోలను ఎంచుకోండి"</string>
     <string name="grant_dialog_button_dont_select_more" msgid="6643552729129461268">"మరిన్ని ఫోటోలను ఎంచుకోవద్దు"</string>
     <string name="grant_dialog_button_deny_anyway" msgid="7225905870668915151">"ఏదేమైనా అనుమతించవద్దు"</string>
-    <string name="grant_dialog_button_dismiss" msgid="1930399742250226393">"విస్మరించు"</string>
+    <string name="grant_dialog_button_dismiss" msgid="1930399742250226393">"విస్మరించండి"</string>
     <string name="current_permission_template" msgid="7452035392573329375">"<xliff:g id="PERMISSION_COUNT">%2$s</xliff:g> యొక్క <xliff:g id="CURRENT_PERMISSION_INDEX">%1$s</xliff:g>"</string>
     <string name="permission_warning_template" msgid="2247087781222679458">"&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‌ను ఈ చర్య చేయడానికి అనుమతించాలా? - <xliff:g id="ACTION">%2$s</xliff:g>"</string>
     <string name="permission_add_background_warning_template" msgid="1812914855915092273">"ఈ చర్యను చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‌ను ఎల్లప్పుడూ అనుమతించాలా? - <xliff:g id="ACTION">%2$s</xliff:g>"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ఆటోమేటిక్ డిజిటల్ అసిస్టెంట్ యాప్"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"డిజిటల్ అసిస్టెంట్ యాప్"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"మీ ముందున్న స్క్రీన్‌లోని సమాచారం ఆధారంగా సహాయక (అసిస్ట్) యాప్‌లు, మీకు హెల్ప్ చేయగలవు. కొన్ని యాప్‌లు, మీకు ఈజీగా సాయం చేయడానికి లాంచర్‌కు, వాయిస్ ఇన్‌పుట్ సర్వీసులకు రెండింటికీ సపోర్ట్‌ ఇస్తాయి."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> ద్వారా సిఫార్సు చేయబడింది"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ఆటోమేటిక్ బ్రౌజర్ యాప్"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"బ్రౌజర్ యాప్"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"మీకు ఇంటర్నెట్‌కు యాక్సెస్‌ ఇచ్చి, ట్యాప్ చేయడానికి లింక్‌ల‌ను డిస్‌ప్లే చేసే యాప్‌లు"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"లింక్‌లను తెరవడం"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"వర్క్‌ ప్లేస్ కోసం ఆటోమేటిక్"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ఆటోమేటిక్‌గా ప్రైవేట్ స్పేస్"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"పరికరం కోసం ఆప్టిమైజ్ చేసినవి"</string>
     <string name="default_app_others" msgid="7793029848126079876">"ఇతర యాప్‌లు"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ఏదీ కాదు"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(సిస్టమ్ ఆటోమేటిక్)"</string>
@@ -460,7 +460,7 @@
     <string name="incident_report_notification_text" msgid="3376480583513587923">"<xliff:g id="APP_NAME">%1$s</xliff:g>డీబగ్గింగ్ సమాచారాన్ని అప్‌లో డ్ చేయదలుచుకుంటున్నారు."</string>
     <string name="incident_report_dialog_title" msgid="669104389325204095">"డీబగ్గింగ్ డేటాను షేర్ చేయమంటారా?"</string>
     <string name="incident_report_dialog_intro" msgid="5897733669850951832">"సిస్టమ్ ఒక సమస్యను గుర్తించింది."</string>
-    <string name="incident_report_dialog_text" msgid="1819244417678973362">"<xliff:g id="APP_NAME_0">%1$s</xliff:g>, <xliff:g id="DATE">%2$s</xliff:g>న <xliff:g id="TIME">%3$s</xliff:g>కు ఈ పరికరంలో తీసిన డీబగ్ రిపోర్ట్‌ను అప్‌లోడ్ చేయమని రిక్వెస్ట్ చేస్తోంది. బగ్ రిపోర్ట్‌లలో మీ పరికరం లేదా లాగిన్ చేసిన యాప్‌లలోని వ్యక్తిగత సమాచారం ఉంటుంది, ఉదాహరణకు యూజర్ నేమ్‌లు, లొకేషన్ డేటా, పరికర ఐడెంటిఫయర్‌లు, ఇంకా నెట్‌వర్క్ సమాచారం వంటివి. మీకు ఈ సమాచారం విషయంలో నమ్మకమైన వ్యక్తులకు, యాప్‌లకు మాత్రమే బగ్ రిపోర్ట్ వివరాలను షేర్ చేయండి.\n\nబగ్ రిపోర్ట్‌ను అప్‌లోడ్ చేయడానికి <xliff:g id="APP_NAME_1">%4$s</xliff:g>‌ను అనుమతించాలా?"</string>
+    <string name="incident_report_dialog_text" msgid="1819244417678973362">"<xliff:g id="APP_NAME_0">%1$s</xliff:g>, <xliff:g id="DATE">%2$s</xliff:g>న <xliff:g id="TIME">%3$s</xliff:g>కు ఈ డివైజ్‌లో తీసిన డీబగ్ రిపోర్ట్‌ను అప్‌లోడ్ చేయమని రిక్వెస్ట్ చేస్తోంది. బగ్ రిపోర్ట్‌లలో మీ డివైజ్ లేదా లాగిన్ చేసిన యాప్‌లలోని వ్యక్తిగత సమాచారం ఉంటుంది, ఉదాహరణకు యూజర్ నేమ్‌లు, లొకేషన్ డేటా, డివైజ్ ఐడెంటిఫయర్‌లు, ఇంకా నెట్‌వర్క్ సమాచారం వంటివి. మీకు ఈ సమాచారం విషయంలో నమ్మకమైన వ్యక్తులకు, యాప్‌లకు మాత్రమే బగ్ రిపోర్ట్ వివరాలను షేర్ చేయండి.\n\nబగ్ రిపోర్ట్‌ను అప్‌లోడ్ చేయడానికి <xliff:g id="APP_NAME_1">%4$s</xliff:g>‌ను అనుమతించాలా?"</string>
     <string name="incident_report_error_dialog_text" msgid="4189647113387092272">"<xliff:g id="APP_NAME">%1$s</xliff:g> కోసం బగ్ రిపోర్ట్‌ ప్రాసెస్ చేయడంలో ఎర్రర్ ఉంది. కాబట్టి వివరణాత్మక డీబగ్గింగ్ డేటాను షేర్ చేయడాన్ని నిరాకరించారు. అంతరాయానికి చింతిస్తున్నాము."</string>
     <string name="incident_report_dialog_allow_label" msgid="2970242967721155239">"అనుమతించండి"</string>
     <string name="incident_report_dialog_deny_label" msgid="3535314290677579383">"తిరస్కరించు"</string>
@@ -475,7 +475,7 @@
     <string name="permgrouprequest_device_aware_storage_isolated" msgid="6463062962458809752">"&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;‌లో ఫోటోలు, మీడియాను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;‌కు అనుమతినివ్వాలా?"</string>
     <string name="permgrouprequest_contacts" msgid="8391550064551053695">"మీ కాంటాక్ట్‌లను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ను అనుమతించాలా?"</string>
     <string name="permgrouprequest_device_aware_contacts" msgid="731025863972535928">"&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;‌లో మీ కాంటాక్ట్‌లను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; యాప్‌ను అనుమతించాలనుకుంటున్నారా?"</string>
-    <string name="permgrouprequest_location" msgid="6990232580121067883">"ఈ పరికర లొకేషన్‌ను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ను అనుమతించాలా?"</string>
+    <string name="permgrouprequest_location" msgid="6990232580121067883">"ఈ డివైజ్‌‌ లొకేషన్‌ను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ను అనుమతించాలా?"</string>
     <string name="permgrouprequest_device_aware_location" msgid="6075412127429878638">"&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt; లొకేషన్‌ను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; యాప్‌ను అనుమతించాలనుకుంటున్నారా?"</string>
     <string name="permgrouprequestdetail_location" msgid="2635935335778429894">"మీరు యాప్‌ను ఉపయోగిస్తున్నప్పుడు మాత్రమే లొకేషన్‌కు యాప్ యాక్సెస్ కలిగి ఉంటుంది"</string>
     <string name="permgroupbackgroundrequest_location" msgid="1085680897265734809">"ఈ పరికర లొకేషన్‌ను యాక్సెస్ చేయడానికి &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;ను అనుమతించాలా?"</string>
@@ -599,7 +599,7 @@
     <string name="active_call_usage_qs" msgid="8559974395932523391">"ఫోన్ కాల్ ద్వారా ఉపయోగించబడుతోంది"</string>
     <string name="recent_call_usage_qs" msgid="743044899599410935">"ఇటీవల ఫోన్ కాల్‌లో ఉపయోగించబడింది"</string>
     <string name="active_app_usage_qs" msgid="4063912870936464727">"<xliff:g id="APP_NAME">%1$s</xliff:g> ద్వారా ఉపయోగించబడుతోంది"</string>
-    <string name="recent_app_usage_qs" msgid="6650259601306212327">"<xliff:g id="APP_NAME">%1$s</xliff:g> ద్వారా ఇటీవల ఉపయోగించబడింది"</string>
+    <string name="recent_app_usage_qs" msgid="6650259601306212327">"ఇటీవల <xliff:g id="APP_NAME">%1$s</xliff:g> వినియోగించింది"</string>
     <string name="active_app_usage_1_qs" msgid="4325136375823357052">"<xliff:g id="APP_NAME">%1$s</xliff:g> (<xliff:g id="ATTRIBUTION_LABEL">%2$s</xliff:g>) ద్వారా ఉపయోగించబడుతోంది"</string>
     <string name="recent_app_usage_1_qs" msgid="261450184773310741">"<xliff:g id="APP_NAME">%1$s</xliff:g> (<xliff:g id="ATTRIBUTION_LABEL">%2$s</xliff:g>) ద్వారా ఇటీవల ఉపయోగించబడింది"</string>
     <string name="active_app_usage_2_qs" msgid="6107866785243565283">"<xliff:g id="APP_NAME">%1$s</xliff:g> (<xliff:g id="ATTRIBUTION_LABEL">%2$s</xliff:g> • <xliff:g id="PROXY_LABEL">%3$s</xliff:g>) ద్వారా ఉపయోగించబడుతోంది"</string>
@@ -679,7 +679,7 @@
     <string name="enhanced_confirmation_dialog_title" msgid="7562437438040966351">"పరిమితం చేయబడిన సెట్టింగ్"</string>
     <string name="enhanced_confirmation_dialog_desc" msgid="5921240234843839219">"మీ సెక్యూరిటీ కోసం, ఈ సెట్టింగ్ ప్రస్తుతం అందుబాటులో లేదు."</string>
     <string name="enhanced_confirmation_phone_state_dialog_title" msgid="5054064107559019689">"కాల్ మాట్లాడే సమయంలో చర్యను పూర్తి చేయడం కుదరదు"</string>
-    <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"మీ పరికరాన్ని, డేటాను సురక్షితంగా ఉంచేందుకు ఈ సెట్టింగ్ బ్లాక్ చేయబడింది.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
+    <string name="enhanced_confirmation_phone_state_dialog_desc" msgid="3803423079498712549">"మీ డివైజ్‌ను, డేటాను సురక్షితంగా ఉంచేందుకు ఈ సెట్టింగ్ బ్లాక్ చేయబడింది.<xliff:g id="SCAM_USE_SETTING_DESCRIPTION">%1$s</xliff:g>"</string>
     <string name="enhanced_confirmation_phone_state_dialog_install_desc" msgid="6400007048943674066">"<xliff:g id="EMPTY_LINE">
 
 </xliff:g>స్కామర్‌లు మిమ్మల్ని కొత్త సోర్స్ నుండి తెలియని యాప్‌లను ఇన్‌స్టాల్ చేయమని అడగడం ద్వారా హానికరమైన యాప్‌లను ఇన్‌స్టాల్ చేయడానికి ట్రై చేయవచ్చు."</string>
diff --git a/PermissionController/res/values-th-v36/strings.xml b/PermissionController/res/values-th-v36/strings.xml
new file mode 100644
index 0000000000..c12cc67a59
--- /dev/null
+++ b/PermissionController/res/values-th-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"การควบคุมแอปอื่นๆ ของตัวแทน"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"ดำเนินการต่างๆ บนอุปกรณ์และในแอปอื่นๆ"</string>
+</resources>
diff --git a/PermissionController/res/values-th/strings.xml b/PermissionController/res/values-th/strings.xml
index 1103e6927d..0589fde8c2 100644
--- a/PermissionController/res/values-th/strings.xml
+++ b/PermissionController/res/values-th/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"แอปผู้ช่วยดิจิทัลเริ่มต้น"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"แอปผู้ช่วยดิจิทัล"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"แอปผู้ช่วยจะช่วยเหลือคุณโดยใช้ข้อมูลจากหน้าจอที่คุณกำลังดูอยู่ แอปบางแอปรองรับทั้ง Launcher และบริการป้อนข้อมูลด้วยเสียงเพื่อให้ความช่วยเหลือแบบบูรณาการแก่คุณ"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"แนะนำโดย <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"แอปเบราว์เซอร์เริ่มต้น"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"แอปเบราว์เซอร์"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"แอปที่ให้คุณเข้าถึงอินเทอร์เน็ตและแสดงลิงก์ที่คุณแตะ"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"การเปิดลิงก์"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"ค่าเริ่มต้นสำหรับงาน"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"ค่าเริ่มต้นสำหรับพื้นที่ส่วนตัว"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"ได้รับการเพิ่มประสิทธิภาพสำหรับอุปกรณ์"</string>
     <string name="default_app_others" msgid="7793029848126079876">"อื่นๆ"</string>
     <string name="default_app_none" msgid="9084592086808194457">"ไม่มี"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(ค่าเริ่มต้นของระบบ)"</string>
@@ -576,7 +576,7 @@
     <string name="safety_center_rescan_button" msgid="4517514567809409596">"สแกนอุปกรณ์"</string>
     <string name="safety_center_issue_card_dismiss_button" msgid="5113965506144222402">"ปิด"</string>
     <string name="safety_center_issue_card_dismiss_confirmation_title" msgid="2734809473425036382">"ปิดการแจ้งเตือนนี้ไหม"</string>
-    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"ตรวจสอบการตั้งค่าความปลอดภัยและความเป็นส่วนตัวได้ทุกเมื่อเพื่อเพิ่มการปกป้อง"</string>
+    <string name="safety_center_issue_card_dismiss_confirmation_message" msgid="3775418736671093563">"ตรวจสอบการตั้งค่าการรักษาความปลอดภัยและความเป็นส่วนตัวได้ทุกเมื่อเพื่อเพิ่มการปกป้อง"</string>
     <string name="safety_center_issue_card_confirm_dismiss_button" msgid="5884137843083634556">"ปิด"</string>
     <string name="safety_center_issue_card_cancel_dismiss_button" msgid="2874578798877712346">"ยกเลิก"</string>
     <string name="safety_center_entries_category_title" msgid="34356964062813115">"การตั้งค่า"</string>
diff --git a/PermissionController/res/values-tl-v36/strings.xml b/PermissionController/res/values-tl-v36/strings.xml
new file mode 100644
index 0000000000..06d8ec73da
--- /dev/null
+++ b/PermissionController/res/values-tl-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Kontrol ng ahente sa iba pang app"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Magsagawa ng mga aksyon sa iyong device at sa iba pang app"</string>
+</resources>
diff --git a/PermissionController/res/values-tl/strings.xml b/PermissionController/res/values-tl/strings.xml
index 604c9cf525..c3697edbfa 100644
--- a/PermissionController/res/values-tl/strings.xml
+++ b/PermissionController/res/values-tl/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Default digital assistant app"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Digital assistant app"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Makakatulong sa iyo ang mga assist app batay sa impormasyon sa screen na tinitingnan mo. Sinusuportahan ng ilang app ang mga serbisyo ng launcher at input ng boses para magbigay sa iyo ng pinagsama-samang tulong."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Inirerekomenda ng <xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Default na browser app"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Browser app"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Mga app na nagbibigay sa iyo ng access sa internet at nagpapakita ng mga link na tina-tap mo"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Pagbubukas ng mga link"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Default para sa trabaho"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Default para sa pribadong space"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Na-optimize para sa device"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Iba pa"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Wala"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Default ng system)"</string>
diff --git a/PermissionController/res/values-tr-v36/strings.xml b/PermissionController/res/values-tr-v36/strings.xml
new file mode 100644
index 0000000000..3b1e12e578
--- /dev/null
+++ b/PermissionController/res/values-tr-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Temsilcinin diğer uygulamaları kontrol etmesi"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Cihazınızda ve diğer uygulamalarda işlem yapma"</string>
+</resources>
diff --git a/PermissionController/res/values-tr/strings.xml b/PermissionController/res/values-tr/strings.xml
index ccf075649e..11a55870bf 100644
--- a/PermissionController/res/values-tr/strings.xml
+++ b/PermissionController/res/values-tr/strings.xml
@@ -348,7 +348,7 @@
     <string name="no_apps_allowed" msgid="7718822655254468631">"Hiçbir uygulamaya izin verilmedi"</string>
     <string name="no_apps_allowed_full" msgid="8011716991498934104">"Tüm dosyalar için hiçbir uygulamaya izin verilmedi"</string>
     <string name="no_apps_allowed_scoped" msgid="4908850477787659501">"Sadece medya için hiçbir uygulamaya izin verilmedi"</string>
-    <string name="no_apps_denied" msgid="7663435886986784743">"Hiçbir uygulama reddedilmedi"</string>
+    <string name="no_apps_denied" msgid="7663435886986784743">"İzin verilmeyen uygulamak yok"</string>
     <string name="car_permission_selected" msgid="180837028920791596">"Seçili"</string>
     <string name="settings" msgid="5409109923158713323">"Ayarlar"</string>
     <string name="accessibility_service_dialog_title_single" msgid="7956432823014102366">"<xliff:g id="SERVICE_NAME">%s</xliff:g> hizmetinin cihazınıza tam erişimi var"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Varsayılan dijital asistan uygulaması"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Dijital asistan uygulaması"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Asistan uygulamaları görüntülemekte olduğunuz ekrandaki bilgilere dayalı olarak size yardım edebilir. Bazı uygulamalar entegre yardım sağlamak için hem başlatıcıyı hem de ses girişi hizmetlerini destekler."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> tarafından öneriliyor"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Varsayılan tarayıcı"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Tarayıcı uygulaması"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"İnternete erişmenizi sağlayan ve dokunduğunuz bağlantıları görüntüleyen uygulamalar"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Bağlantıları açma"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"İş için varsayılan"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Özel alan için varsayılan"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Cihaz için optimize edilenler"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Diğer"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Yok"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Sistem varsayılanı)"</string>
@@ -633,7 +633,7 @@
     <string name="mic_toggle_title" msgid="2649991093496110162">"Mikrofon erişimi"</string>
     <string name="perm_toggle_description" msgid="7801326363741451379">"Uygulamalar ve hizmetler için"</string>
     <string name="mic_toggle_description" msgid="9163104307990677157">"Uygulamalar ve hizmetler için. Bu ayar kapalıyken bir acil durum numarasını aradığınızda mikrofon verileri paylaşılmaya devam edilebilir."</string>
-    <string name="location_settings_subtitle" msgid="2328360561197430695">"Konum erişimi olan uygulama ve hizmetlere göz atın."</string>
+    <string name="location_settings_subtitle" msgid="2328360561197430695">"Konum erişimi olan uygulama ve hizmetlere göz atın"</string>
     <string name="show_clip_access_notification_title" msgid="5168467637351109096">"Panoya erişimi göster"</string>
     <string name="show_clip_access_notification_summary" msgid="3532020182782112687">"Uygulamalar kopyaladığınız metne, resimlere veya diğer içeriklere eriştiğinde mesaj gösterilsin"</string>
     <string name="show_password_title" msgid="2877269286984684659">"Şifreleri göster"</string>
diff --git a/PermissionController/res/values-uk-television/strings.xml b/PermissionController/res/values-uk-television/strings.xml
index e3e61960bd..8cb69df28e 100644
--- a/PermissionController/res/values-uk-television/strings.xml
+++ b/PermissionController/res/values-uk-television/strings.xml
@@ -21,7 +21,7 @@
     <string name="current_permission_template" msgid="6240787325714651204">"<xliff:g id="CURRENT_PERMISSION_INDEX">%1$s</xliff:g> з <xliff:g id="PERMISSION_COUNT">%2$s</xliff:g>"</string>
     <string name="preference_show_system_apps" msgid="4262140518693221093">"Показати системні додатки"</string>
     <string name="app_permissions_decor_title" msgid="7438716722786036814">"Дозволи додатка"</string>
-    <string name="manage_permissions_decor_title" msgid="4138423885439613577">"Дозволи додатка"</string>
+    <string name="manage_permissions_decor_title" msgid="4138423885439613577">"Дозволи для додатків"</string>
     <string name="permission_apps_decor_title" msgid="2811550489429789828">"Дозволи додатка <xliff:g id="PERMISSION">%1$s</xliff:g>"</string>
     <string name="additional_permissions_decor_title" msgid="5113847982502484225">"Додаткові дозволи"</string>
     <string name="system_apps_decor_title" msgid="4402004958937474803">"Дозволи додатка <xliff:g id="PERMISSION">%1$s</xliff:g>"</string>
diff --git a/PermissionController/res/values-uk-v36/strings.xml b/PermissionController/res/values-uk-v36/strings.xml
new file mode 100644
index 0000000000..06c7c409c2
--- /dev/null
+++ b/PermissionController/res/values-uk-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Керування іншими додатками за допомогою агента"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Виконуйте дії на пристрої і в інших додатках"</string>
+</resources>
diff --git a/PermissionController/res/values-uk/strings.xml b/PermissionController/res/values-uk/strings.xml
index 65feb5d2f3..9e549ec6ab 100644
--- a/PermissionController/res/values-uk/strings.xml
+++ b/PermissionController/res/values-uk/strings.xml
@@ -60,7 +60,7 @@
     <string name="grant_dialog_button_allow_all_files" msgid="4955436994954829894">"Дозволити керувати всіма файлами"</string>
     <string name="grant_dialog_button_allow_media_only" msgid="4832877658422573832">"Надати доступ до медіафайлів"</string>
     <string name="app_permissions_breadcrumb" msgid="5136969550489411650">"Додатки"</string>
-    <string name="app_permissions" msgid="3369917736607944781">"Дозволи додатка"</string>
+    <string name="app_permissions" msgid="3369917736607944781">"Дозволи для додатків"</string>
     <string name="unused_apps" msgid="2058057455175955094">"Непотрібні додатки"</string>
     <string name="edit_photos_description" msgid="5540108003480078892">"Змінити вибрані фотографії для цього додатка"</string>
     <string name="no_unused_apps" msgid="12809387670415295">"Усі додатки використовуються"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Цифровий помічник за умовчанням"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Цифровий помічник"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Додатки-помічники можуть допомагати, використовуючи інформацію на екрані. Для зручності деякі з них підтримують панель запуску й голосовий ввід."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Рекомендовано компанією \"<xliff:g id="OEM_NAME">%s</xliff:g>\""</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Вебпереглядач за умовчанням"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Вебпереглядач"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Додатки, за допомогою яких можна переглядати сайти й переходити за посиланнями"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Відкривання посилань"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Для роботи за умовчанням"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"За умовчанням для приватного простору"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Оптимізовано для пристрою"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Інші"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Немає"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(За умовчанням)"</string>
diff --git a/PermissionController/res/values-ur-v36/strings.xml b/PermissionController/res/values-ur-v36/strings.xml
new file mode 100644
index 0000000000..fe6e64def7
--- /dev/null
+++ b/PermissionController/res/values-ur-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"دیگر ایپس کا ایجنٹ کنٹرول"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"اپنے آلے پر اور دیگر ایپس میں کارروائیاں کریں"</string>
+</resources>
diff --git a/PermissionController/res/values-ur/strings.xml b/PermissionController/res/values-ur/strings.xml
index 9f1792afcf..dbace5e6c3 100644
--- a/PermissionController/res/values-ur/strings.xml
+++ b/PermissionController/res/values-ur/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"ڈیفالٹ ڈیجیٹل اسسٹنٹ ایپ"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"ڈیجیٹل اسسٹنٹ ایپ"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"آپ جو اسکرین دیکھ رہے ہیں اس کی معلومات کی بنیاد پر معاون ایپس آپ کی مدد کر سکتی ہیں۔ کچھ ایپس آپ کو مربوط مدد فراہم کرنے کے لیے لانچر اور صوتی ان پُٹ کی سروسز دونوں میں سپورٹ کرتی ہیں۔"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"‫<xliff:g id="OEM_NAME">%s</xliff:g> کی جانب سے تجویز کردہ"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"ڈیفالٹ براؤزر ایپ"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"براؤزر ایپ"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"وہ ایپس جو آپ کو انٹرنیٹ تک رسائی فراہم کرتی ہیں اور ان لنکس کو ڈسپلے کرتی ہیں جن پر آپ تھپتھپاتے ہیں"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"شروعاتی لنکس"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"کام کیلئے ڈیفالٹ"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"پرائیویٹ اسپیس کے لیے ڈیفالٹ"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"آلہ کیلئے بہتر بنایا گیا"</string>
     <string name="default_app_others" msgid="7793029848126079876">"دیگر"</string>
     <string name="default_app_none" msgid="9084592086808194457">"کوئی نہیں"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(سسٹم ڈیفالٹ)"</string>
diff --git a/PermissionController/res/values-uz-v36/strings.xml b/PermissionController/res/values-uz-v36/strings.xml
new file mode 100644
index 0000000000..bc67250a2b
--- /dev/null
+++ b/PermissionController/res/values-uz-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Boshqa ilovalar agent nazorati"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Qurilmangiz va boshqa ilovalarda amallar bajaring"</string>
+</resources>
diff --git a/PermissionController/res/values-uz/strings.xml b/PermissionController/res/values-uz/strings.xml
index c97bd92e8b..5eafe770e3 100644
--- a/PermissionController/res/values-uz/strings.xml
+++ b/PermissionController/res/values-uz/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Asosiy raqamli assistent ilovasi"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Raqamli assistent ilovasi"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Yordamchi ilovalar siz koʻrayotganda ekrandagi maʼlumotlar asosida sizga yordam beradi. Baʼzi ilovalar sizga umumlashgan koʻmak berish maqsadida ham ishga tushirish paneli, ham ovoz bilan yozish xizmatlarini qoʻllab-quvvatlaydi."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> tavsiya etadi"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Birlamchi brauzer ilovasi"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Brauzer ilovasi"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Internetga kirish va havolalarni ochish imkonini beruvchi ilovalar"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Havolalarni ochish"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Ish uchun birlamchi"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Maxfiy makon uchun standart"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Qurilma uchun optimallangan"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Boshqalar"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Hech qanday"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Birlamchi)"</string>
diff --git a/PermissionController/res/values-v35/styles.xml b/PermissionController/res/values-v35/styles.xml
index 513754bb83..c831b4377b 100644
--- a/PermissionController/res/values-v35/styles.xml
+++ b/PermissionController/res/values-v35/styles.xml
@@ -30,6 +30,9 @@
         <item name="android:baselineAligned">false</item>
         <item name="android:layout_marginTop">16dp</item>
         <item name="android:gravity">center_vertical</item>
+        <!-- Workaround for b/412863862 to restore the non-clipping behavior on V. -->
+        <item name="android:clipChildren">false</item>
+        <item name="android:clipToPadding">false</item>
     </style>
 
     <style name="PermissionPreferenceCategoryTextRelativeLayoutStyle">
@@ -38,6 +41,9 @@
         <item name="android:layout_weight">1</item>
         <item name="android:paddingTop">8dp</item>
         <item name="android:paddingBottom">8dp</item>
+        <!-- Workaround for b/412863862 to restore the non-clipping behavior on V. -->
+        <item name="android:clipChildren">false</item>
+        <item name="android:clipToPadding">false</item>
     </style>
 
     <style name="PermissionPreferenceCategoryTitleTextStyle" parent="@style/PreferenceCategoryTitleTextStyle">
diff --git a/PermissionController/res/values-v36/strings.xml b/PermissionController/res/values-v36/strings.xml
new file mode 100644
index 0000000000..c5cd07945c
--- /dev/null
+++ b/PermissionController/res/values-v36/strings.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+
+<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <!-- Title for App Function Access Settings page entry point from Safety Center. Clicking on the
+     entry will navigate to App Function Access Settings page, which displays apps which implement
+     App Function agents. [CHAR LIMIT=70] -->
+    <string name="app_function_access_settings_title" description="The title of the entry for App Function Access Settings">Agent control of other apps</string>
+    <!-- Summary for App Function Access Settings page entry point in Safety Center. Clicking on the
+     entry will navigate to App Function Access Settings page, which displays apps which implement
+     App Function agents. [CHAR LIMIT=130] -->
+    <string name="app_function_access_settings_summary" description="The summary of the entry for App Function Access Settings, which describes the page contents">Perform actions on your device and in other apps</string>
+</resources>
diff --git a/PermissionController/res/values-v36/styles.xml b/PermissionController/res/values-v36/styles.xml
new file mode 100644
index 0000000000..297ae50607
--- /dev/null
+++ b/PermissionController/res/values-v36/styles.xml
@@ -0,0 +1,238 @@
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
+
+<resources>
+    <!-- START EXPRESSIVE PERMISSION GRANT DIALOG -->
+
+    <style name="PermissionGrantTitleMessageExpressive"
+           parent="@style/TextAppearance.SettingsLib.HeadlineSmall">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:gravity">center</item>
+    </style>
+
+    <style name="PermissionGrantDetailMessageExpressive"
+           parent="@style/TextAppearance.SettingsLib.BodyMedium">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:layout_marginTop">18dp</item>
+    </style>
+
+    <style name="PermissionGrantButtonListExpressive">
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:orientation">vertical</item>
+        <item name="android:paddingTop">@dimen/settingslib_expressive_space_none</item>
+        <item name="android:paddingStart">@dimen/settingslib_expressive_space_small4</item>
+        <item name="android:paddingEnd">@dimen/settingslib_expressive_space_small4</item>
+        <item name="android:paddingBottom">14dp</item>
+    </style>
+
+    <style name="PermissionGrantButtonExpressive"
+           parent="@android:style/Widget.DeviceDefault.Button.Borderless.Colored">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">@dimen/settingslib_expressive_space_medium3</item>
+        <item name="android:layout_marginTop">@dimen/settingslib_expressive_space_extrasmall2</item>
+        <item name="android:layout_marginStart">@dimen/settingslib_expressive_space_none</item>
+        <item name="android:layout_marginEnd">@dimen/settingslib_expressive_space_none</item>
+        <item name="android:layout_marginBottom">@dimen/settingslib_expressive_space_extrasmall6</item>
+        <item name="android:paddingLeft">8dp</item>
+        <item name="android:paddingRight">8dp</item>
+        <item name="android:background">@drawable/settingslib_expressive_button_background_filled</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnPrimary</item>
+    </style>
+
+    <!-- END EXPRESSIVE PERMISSION GRANT DIALOG -->
+
+    <!-- START EXPRESSIVE PERMISSION RATIONALE DIALOG -->
+
+    <style name="PermissionRationaleContentExpressive">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:orientation">vertical</item>
+        <item name="android:paddingTop">24dp</item>
+        <item name="android:paddingHorizontal">@dimen/settingslib_expressive_space_small1</item>
+    </style>
+
+    <style name="PermissionRationaleTitleContainerExpressive">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:orientation">vertical</item>
+        <item name="android:gravity">center</item>
+        <item name="android:layout_marginBottom">@dimen/settingslib_expressive_space_extrasmall6</item>
+    </style>
+
+    <style name="PermissionRationaleTitleIconExpressive">
+        <item name="android:layout_width">32dp</item>
+        <item name="android:layout_height">32dp</item>
+        <item name="android:layout_marginBottom">@dimen/settingslib_expressive_space_small1</item>
+        <item name="android:tint">@color/settingslib_materialColorPrimary</item>
+        <item name="android:scaleType">centerInside</item>
+    </style>
+
+    <style name="PermissionRationaleTitleMessageExpressive">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">32dp</item>
+        <item name="android:fontFamily">google-sans</item>
+        <item name="android:fontWeight">400</item>
+        <item name="android:gravity">center</item>
+        <item name="android:lineHeight">32sp</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnSurface</item>
+        <item name="android:textSize">24sp</item>
+    </style>
+
+    <style name="PermissionRationaleSectionOuterContainerExpressive">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:orientation">horizontal</item>
+        <item name="android:paddingVertical">@dimen/settingslib_expressive_space_extrasmall6</item>
+    </style>
+
+    <style name="PermissionRationaleSectionIconExpressive">
+        <item name="android:layout_width">40dp</item>
+        <item name="android:layout_height">40dp</item>
+        <item name="android:padding">@dimen/settingslib_expressive_space_extrasmall4</item>
+        <item name="android:tint">@color/settingslib_materialColorOnSurface</item>
+        <item name="android:scaleType">centerInside</item>
+    </style>
+
+    <style name="PermissionRationaleSectionInnerContainerExpressive">
+        <item name="android:layout_width">wrap_content</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:layout_marginStart">@dimen/settingslib_expressive_space_extrasmall6</item>
+        <item name="android:orientation">vertical</item>
+    </style>
+
+    <style name="PermissionRationaleSectionTitleExpressive"
+           parent="@style/TextAppearance.SettingsLib.TitleMedium">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">24dp</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="android:fontWeight">500</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnSurface</item>
+        <item name="android:textColorLink">@color/settingslib_materialColorOnSurfaceVariant</item>
+    </style>
+
+    <style name="PermissionRationaleSectionMessageExpressive"
+           parent="@style/TextAppearance.SettingsLib.BodyMedium">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="android:fontWeight">400</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnSurfaceVariant</item>
+        <item name="android:textColorLink">@color/settingslib_materialColorPrimary</item>
+    </style>
+
+    <style name="PermissionRationaleSectionPurposeListExpressive"
+           parent="@style/PermissionRationaleSectionMessageExpressive">
+        <item name="android:layout_marginStart">@dimen/permission_rationale_purpose_list_bullet_indent</item>
+    </style>
+
+    <style name="PermissionRationaleButtonContainerExpressive">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:layout_weight">0</item>
+        <item name="android:layout_marginTop">@dimen/settingslib_expressive_space_extrasmall6</item>
+        <item name="android:paddingHorizontal">@dimen/settingslib_expressive_space_small4</item>
+        <item name="android:paddingTop">@dimen/settingslib_expressive_space_extrasmall4</item>
+        <item name="android:paddingBottom">@dimen/settingslib_expressive_space_small4</item>
+        <item name="android:orientation">horizontal</item>
+        <item name="android:gravity">end</item>
+    </style>
+
+    <style name="PermissionRationaleBackButtonExpressive">
+        <item name="android:layout_width">65dp</item>
+        <item name="android:layout_height">@dimen/settingslib_expressive_space_medium3</item>
+        <item name="android:paddingVertical">@dimen/settingslib_expressive_space_extrasmall5</item>
+        <item name="android:paddingHorizontal">@dimen/settingslib_expressive_space_small1</item>
+        <item name="android:background">@drawable/settingslib_expressive_button_background_filled</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="android:fontWeight">500</item>
+        <item name="android:letterSpacing">0.00714286</item>
+        <item name="android:lineHeight">20sp</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnPrimary</item>
+        <item name="android:textSize">14sp</item>
+    </style>
+
+    <!-- END EXPRESSIVE PERMISSION RATIONALE DIALOG -->
+
+    <!-- START EXPRESSIVE ENHANCED CONFIRMATION DIALOG -->
+
+    <style name="EnhancedConfirmationDialogExpressive">
+        <item name="android:layout_width">wrap_content</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:orientation">vertical</item>
+        <item name="android:paddingTop">@dimen/settingslib_expressive_space_small4</item>
+        <item name="android:paddingHorizontal">@dimen/settingslib_expressive_space_small4</item>
+    </style>
+
+    <style name="EnhancedConfirmationDialogHeaderExpressive">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:orientation">vertical</item>
+        <item name="android:gravity">center_horizontal</item>
+        <item name="android:paddingBottom">@dimen/settingslib_expressive_space_small4</item>
+    </style>
+
+    <style name="EnhancedConfirmationDialogIconExpressive">
+        <item name="android:src">@drawable/ic_safety_center_shield</item>
+        <item name="android:layout_width">32dp</item>
+        <item name="android:layout_height">32dp</item>
+        <item name="android:scaleType">fitCenter</item>
+        <item name="android:tint">@color/settingslib_materialColorPrimary</item>
+        <item name="android:contentDescription">@null</item>
+    </style>
+
+    <style name="EnhancedConfirmationDialogTitleExpressive"
+           parent="@style/TextAppearance.SettingsLib.HeadlineSmall">
+        <item name="android:layout_width">wrap_content</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:layout_marginTop">@dimen/settingslib_expressive_space_small1</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="android:fontWeight">400</item>
+        <item name="android:gravity">center_horizontal</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnSurface</item>
+    </style>
+
+    <style name="EnhancedConfirmationDialogDescExpressive"
+           parent="@style/TextAppearance.SettingsLib.BodyMedium">
+        <item name="android:layout_width">match_parent</item>
+        <item name="android:layout_height">wrap_content</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="android:fontWeight">400</item>
+        <item name="android:textColor">@color/settingslib_materialColorOnSurface</item>
+        <item name="android:textColorLink">@color/settingslib_materialColorOnPrimaryContainer</item>
+    </style>
+
+    <!-- END EXPRESSIVE ENHANCED CONFIRMATION DIALOG -->
+
+    <style name="PermissionGrantButtonAllowExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonAllowForegroundExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonAllowOneTimeExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonAllowSelectedExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonAllowAllExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonDenyExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonNoUpgradeExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+    <style name="PermissionGrantButtonDontAllowMoreExpressive"
+           parent="@style/PermissionGrantButtonExpressive"></style>
+</resources>
diff --git a/PermissionController/res/values-v36/themes.xml b/PermissionController/res/values-v36/themes.xml
new file mode 100644
index 0000000000..a084274cea
--- /dev/null
+++ b/PermissionController/res/values-v36/themes.xml
@@ -0,0 +1,47 @@
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
+  ~ limitations under the License
+  -->
+
+<resources>
+    <style name="Settings.Expressive" parent="Theme.SubSettingsBase.Expressive"/>
+
+    <style name="Theme.PermissionController.Settings.Expressive" parent="Settings.Expressive">
+        <!-- These two attributes are required when using Toolbar as ActionBar. -->
+        <item name="android:windowActionBar">false</item>
+        <item name="android:windowNoTitle">true</item>
+        <item name="android:alertDialogTheme">@style/Theme.DeviceDefault.AlertDialog.SettingsLib.Expressive</item>
+    </style>
+
+    <style name="Theme.PermissionController.Settings.Expressive.FilterTouches">
+        <item name="android:filterTouchesWhenObscured">true</item>
+    </style>
+
+    <!-- START EXPRESSIVE ENHANCED CONFIRMATION DIALOG -->
+
+    <!-- This is not overlayable -->
+    <style name="Theme.EnhancedConfirmationDialogActivityExpressive.FilterTouches">
+        <item name="android:filterTouchesWhenObscured">true</item>
+    </style>
+
+    <style name="Theme.EnhancedConfirmationDialogActivityExpressive"
+           parent="@style/Theme.DeviceDefault.Dialog.NoActionBar.DayNight">
+        <item name="android:windowNoTitle">true</item>
+        <item name="android:alertDialogTheme">@style/Theme.DeviceDefault.AlertDialog.SettingsLib.Expressive</item>
+    </style>
+
+    <!-- END EXPRESSIVE ENHANCED CONFIRMATION DIALOG -->
+
+</resources>
diff --git a/PermissionController/res/values-vi-v36/strings.xml b/PermissionController/res/values-vi-v36/strings.xml
new file mode 100644
index 0000000000..c2cf86515e
--- /dev/null
+++ b/PermissionController/res/values-vi-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Tác nhân kiểm soát các ứng dụng khác"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Thao tác trên thiết bị và trong các ứng dụng khác"</string>
+</resources>
diff --git a/PermissionController/res/values-vi/strings.xml b/PermissionController/res/values-vi/strings.xml
index ce5e6dca37..1196cab273 100644
--- a/PermissionController/res/values-vi/strings.xml
+++ b/PermissionController/res/values-vi/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"Ứng dụng trợ lý kỹ thuật số mặc định"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"Ứng dụng trợ lý kỹ thuật số"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Các ứng dụng trợ lý có thể giúp bạn dựa trên thông tin từ màn hình bạn đang xem. Một số ứng dụng hỗ trợ cả dịch vụ nhập bằng giọng nói và trình chạy để hỗ trợ bạn toàn diện hơn."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Do <xliff:g id="OEM_NAME">%s</xliff:g> đề xuất"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Ứng dụng trình duyệt mặc định"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"Ứng dụng trình duyệt"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Các ứng dụng giúp bạn truy cập vào Internet và hiển thị đường liên kết để bạn nhấn vào"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Mở đường liên kết"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Ứng dụng mặc định cho công việc"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Ứng dụng mặc định cho không gian riêng tư"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Tối ưu hoá cho thiết bị"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Ứng dụng khác"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Không có"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Ứng dụng mặc định của hệ thống)"</string>
diff --git a/PermissionController/res/values-zh-rCN-v34/strings.xml b/PermissionController/res/values-zh-rCN-v34/strings.xml
index fbb8bc6dbb..ea1b803c1c 100644
--- a/PermissionController/res/values-zh-rCN-v34/strings.xml
+++ b/PermissionController/res/values-zh-rCN-v34/strings.xml
@@ -21,6 +21,6 @@
     <string name="privacy_subpage_controls_header" msgid="4152396976713749322">"控件"</string>
     <string name="health_connect_title" msgid="2132233890867430855">"健康数据共享"</string>
     <string name="health_connect_summary" msgid="815473513776882296">"管理应用对健康数据的访问权限"</string>
-    <string name="location_settings" msgid="8863940440881290182">"位置信息访问权限"</string>
+    <string name="location_settings" msgid="8863940440881290182">"位置信息权限"</string>
     <string name="mic_toggle_description" msgid="1504101620086616040">"针对应用和服务。关闭此设置后，系统仍可能在您拨打紧急电话号码时分享麦克风数据"</string>
 </resources>
diff --git a/PermissionController/res/values-zh-rCN-v36/strings.xml b/PermissionController/res/values-zh-rCN-v36/strings.xml
new file mode 100644
index 0000000000..d07b2ce985
--- /dev/null
+++ b/PermissionController/res/values-zh-rCN-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"其他应用的代理控制"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"在您的设备和其他应用中执行操作"</string>
+</resources>
diff --git a/PermissionController/res/values-zh-rCN/strings.xml b/PermissionController/res/values-zh-rCN/strings.xml
index 6e1a2d1a32..feb37b9bef 100644
--- a/PermissionController/res/values-zh-rCN/strings.xml
+++ b/PermissionController/res/values-zh-rCN/strings.xml
@@ -56,7 +56,7 @@
     <string name="grant_dialog_button_change_to_precise_location" msgid="3273115879467236033">"更改为确切位置"</string>
     <string name="grant_dialog_button_keey_approximate_location" msgid="438025182769080011">"继续使用大致位置"</string>
     <string name="grant_dialog_button_allow_one_time" msgid="2618088516449706391">"仅限这一次"</string>
-    <string name="grant_dialog_button_allow_background" msgid="8236044729434367833">"一律允许"</string>
+    <string name="grant_dialog_button_allow_background" msgid="8236044729434367833">"始终允许"</string>
     <string name="grant_dialog_button_allow_all_files" msgid="4955436994954829894">"允许管理所有文件"</string>
     <string name="grant_dialog_button_allow_media_only" msgid="4832877658422573832">"允许访问媒体文件"</string>
     <string name="app_permissions_breadcrumb" msgid="5136969550489411650">"应用"</string>
@@ -84,8 +84,8 @@
     <string name="storage_supergroup_warning_allow" msgid="103093462784523190">"此应用专为旧版 Android 系统打造。如果您同意授予这项权限，即会允许访问所有存储空间（包括照片、视频、音乐、音频和其他文件）。"</string>
     <string name="storage_supergroup_warning_deny" msgid="6420765672683284347">"此应用专为旧版 Android 系统打造。如果您拒绝授予这项权限，则会禁止访问所有存储空间（包括照片、视频、音乐、音频和其他文件）。"</string>
     <string name="default_permission_description" msgid="4624464917726285203">"执行未知操作"</string>
-    <string name="app_permissions_group_summary" msgid="8788419008958284002">"已授权 <xliff:g id="COUNT_0">%1$d</xliff:g> 个应用（共 <xliff:g id="COUNT_1">%2$d</xliff:g> 个）"</string>
-    <string name="app_permissions_group_summary2" msgid="4329922444840521150">"已授权 <xliff:g id="COUNT_0">%1$d</xliff:g> 个应用/共 <xliff:g id="COUNT_1">%2$d</xliff:g> 个"</string>
+    <string name="app_permissions_group_summary" msgid="8788419008958284002">"已授权给 <xliff:g id="COUNT_0">%1$d</xliff:g> 个应用（共 <xliff:g id="COUNT_1">%2$d</xliff:g> 个）"</string>
+    <string name="app_permissions_group_summary2" msgid="4329922444840521150">"已授权给 <xliff:g id="COUNT_0">%1$d</xliff:g> 个应用/共 <xliff:g id="COUNT_1">%2$d</xliff:g> 个"</string>
     <string name="menu_show_system" msgid="4254021607027872504">"显示系统应用"</string>
     <string name="menu_hide_system" msgid="3855390843744028465">"隐藏系统应用"</string>
     <string name="menu_show_7_days_data" msgid="8979611198508523706">"显示过去 7 天内的权限使用情况"</string>
@@ -110,7 +110,7 @@
     <!-- no translation found for background_access_chooser_dialog_choices:0 (1351721623256561996) -->
     <!-- no translation found for background_access_chooser_dialog_choices:1 (9127301153688725448) -->
     <!-- no translation found for background_access_chooser_dialog_choices:2 (4305536986042401191) -->
-    <string name="permission_access_always" msgid="1474641821883823446">"一律允许"</string>
+    <string name="permission_access_always" msgid="1474641821883823446">"始终允许"</string>
     <string name="permission_access_only_foreground" msgid="7801170728159326195">"仅在使用该应用时允许"</string>
     <string name="permission_access_never" msgid="4647014230217936900">"不允许"</string>
     <string name="loading" msgid="4789365003890741082">"正在加载…"</string>
@@ -195,7 +195,7 @@
     <string name="app_permission_button_allow_limited_access" msgid="8824410215149764113">"允许有限访问"</string>
     <string name="precise_image_description" msgid="6349638632303619872">"确切位置"</string>
     <string name="approximate_image_description" msgid="938803699637069884">"大致位置"</string>
-    <string name="app_permission_location_accuracy" msgid="7166912915040018669">"使用确切位置"</string>
+    <string name="app_permission_location_accuracy" msgid="7166912915040018669">"使用精确位置"</string>
     <string name="app_permission_location_accuracy_subtitle" msgid="2654077606404987210">"精确位置关闭时，应用可以获取您的大致位置"</string>
     <string name="app_permission_title" msgid="2090897901051370711">"<xliff:g id="PERM">%1$s</xliff:g>权限"</string>
     <string name="app_permission_header" msgid="2951363137032603806">"是否允许此应用获得“<xliff:g id="PERM">%1$s</xliff:g>”权限"</string>
@@ -253,7 +253,7 @@
     <string name="app_permission_never_accessed_summary" msgid="401346181461975090">"从未访问"</string>
     <string name="app_permission_never_accessed_denied_summary" msgid="6596000497490905146">"已拒绝授权/从未访问"</string>
     <string name="allowed_header" msgid="7769277978004790414">"已允许"</string>
-    <string name="allowed_always_header" msgid="6455903312589013545">"一律允许"</string>
+    <string name="allowed_always_header" msgid="6455903312589013545">"始终允许"</string>
     <string name="allowed_foreground_header" msgid="6845655788447833353">"仅在使用时允许"</string>
     <string name="allowed_storage_scoped" msgid="5383645873719086975">"仅获准访问媒体文件"</string>
     <string name="allowed_storage_full" msgid="5356699280625693530">"获准管理所有文件"</string>
@@ -322,7 +322,7 @@
     <string name="permission_subtitle_only_in_foreground" msgid="9068389431267377564">"仅在使用该应用期间允许"</string>
     <string name="permission_subtitle_media_only" msgid="8917869683764720717">"媒体文件"</string>
     <string name="permission_subtitle_all_files" msgid="4982613338298067862">"所有文件"</string>
-    <string name="permission_subtitle_background" msgid="8916750995309083180">"一律允许"</string>
+    <string name="permission_subtitle_background" msgid="8916750995309083180">"始终允许"</string>
     <string name="app_perms_24h_access" msgid="99069906850627181">"上次访问时间：<xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_perms_24h_access_yest" msgid="5411926024794555022">"上次访问时间：昨天<xliff:g id="TIME_DATE">%1$s</xliff:g>"</string>
     <string name="app_perms_7d_access" msgid="4945055548894683751">"上次访问时间：<xliff:g id="TIME_DATE_0">%1$s</xliff:g><xliff:g id="TIME_DATE_1">%2$s</xliff:g>"</string>
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"默认数字助理应用"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"数字助理应用"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"辅助应用可根据您当前浏览的屏幕内容为您提供帮助。部分应用同时支持启动器和语音输入服务，可为您提供更全面的协助。"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g>推荐"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"默认浏览器应用"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"浏览器应用"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"这类应用可让您访问互联网以及显示您点按的链接"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"打开链接"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"默认工作应用"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"私密空间的默认应用"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"针对设备进行了优化"</string>
     <string name="default_app_others" msgid="7793029848126079876">"其他"</string>
     <string name="default_app_none" msgid="9084592086808194457">"无"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"（系统默认）"</string>
@@ -489,9 +489,9 @@
     <string name="permgroupupgraderequestdetail_nearby_devices" msgid="6877531270654738614">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;查找、连接附近设备以及确定附近设备的相对位置吗？"<annotation id="link">"您可以在“设置”中允许。"</annotation></string>
     <string name="permgrouprequest_fineupgrade" msgid="2334242928821697672">"要将“<xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g>”可以使用的位置信息从大致位置改为精确位置吗？"</string>
     <string name="permgrouprequest_device_aware_fineupgrade" msgid="4453775952305587571">"要将<xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g>在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上的位置信息访问权限从大致位置信息改为精确位置信息吗？"</string>
-    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”获取此设备的大致位置信息吗？"</string>
+    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"要允许 &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; 获取此设备的大致位置信息吗？"</string>
     <string name="permgrouprequest_device_aware_coarselocation" msgid="8367540370912066757">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;获取&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;的大致位置信息吗？"</string>
-    <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"确切位置"</string>
+    <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"精确位置"</string>
     <string name="permgrouprequest_coarselocation_imagetext" msgid="8650605041483025297">"大致位置"</string>
     <string name="permgrouprequest_calendar" msgid="1493150855673603806">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”访问您的日历吗？"</string>
     <string name="permgrouprequest_device_aware_calendar" msgid="7161929851377463612">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上访问您的日历吗？"</string>
@@ -507,10 +507,10 @@
     <string name="permgrouprequest_device_aware_read_media_visual" msgid="3122576538319059333">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上访问照片和视频吗？"</string>
     <string name="permgrouprequest_more_photos" msgid="128933814654231321">"允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;访问此设备上的更多照片和视频？"</string>
     <string name="permgrouprequest_device_aware_more_photos" msgid="1703469013613723053">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上访问更多照片和视频吗？"</string>
-    <string name="permgrouprequest_microphone" msgid="2825208549114811299">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”录音吗？"</string>
+    <string name="permgrouprequest_microphone" msgid="2825208549114811299">"要允许 &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; 录音吗？"</string>
     <string name="permgrouprequest_device_aware_microphone" msgid="8821701550505437951">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上录音吗？"</string>
     <string name="permgrouprequestdetail_microphone" msgid="8510456971528228861">"此应用将只能在您使用它时录音"</string>
-    <string name="permgroupbackgroundrequest_microphone" msgid="8874462606796368183">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”录音吗？"</string>
+    <string name="permgroupbackgroundrequest_microphone" msgid="8874462606796368183">"要允许 &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; 录音吗？"</string>
     <string name="permgroupbackgroundrequest_device_aware_microphone" msgid="3321823187623762958">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上录音吗？"</string>
     <string name="permgroupbackgroundrequestdetail_microphone" msgid="553702902263681838">"此应用可能想要随时录音，即使在您未使用它的时候。"<annotation id="link">"您可以在“设置”中授权"</annotation>"。"</string>
     <string name="permgroupupgraderequest_microphone" msgid="1362781696161233341">"要更改&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;的麦克风使用权限吗？"</string>
@@ -518,14 +518,14 @@
     <string name="permgroupupgraderequestdetail_microphone" msgid="2870497719571464239">"此应用想要随时录音，即使在您未使用它的时候。"<annotation id="link">"您可以在“设置”中授权"</annotation>"。"</string>
     <string name="permgrouprequest_activityRecognition" msgid="5415121592794230330">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”获取您的身体活动数据吗？"</string>
     <string name="permgrouprequest_device_aware_activityRecognition" msgid="1243869530588745374">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上访问您的身体活动记录吗？"</string>
-    <string name="permgrouprequest_camera" msgid="5123097035410002594">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”拍摄照片和录制视频吗？"</string>
+    <string name="permgrouprequest_camera" msgid="5123097035410002594">"要允许 &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; 拍摄照片和录制视频吗？"</string>
     <string name="permgrouprequest_device_aware_camera" msgid="5340173564041615494">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上拍照片和录视频吗？"</string>
     <string name="permgrouprequestdetail_camera" msgid="9085323239764667883">"此应用将只能在您使用它时拍摄照片和录制视频"</string>
-    <string name="permgroupbackgroundrequest_camera" msgid="1274286575704213875">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”拍摄照片和录制视频吗？"</string>
+    <string name="permgroupbackgroundrequest_camera" msgid="1274286575704213875">"要允许 &lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt; 拍摄照片和录制视频吗？"</string>
     <string name="permgroupbackgroundrequest_device_aware_camera" msgid="8533353179594971475">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上拍照片和录视频吗？"</string>
     <string name="permgroupbackgroundrequestdetail_camera" msgid="4458783509089859078">"此应用可能想要随时拍摄照片和录制视频，即使在您未使用它的时候。"<annotation id="link">"您可以在“设置”中授权"</annotation>"。"</string>
-    <string name="permgroupupgraderequest_camera" msgid="640758449200241582">"要更改&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;的相机使用权限吗？"</string>
-    <string name="permgroupupgraderequest_device_aware_camera" msgid="3290160912843715236">"要更改&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上的相机使用权限吗？"</string>
+    <string name="permgroupupgraderequest_camera" msgid="640758449200241582">"要更改&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;的相机权限吗？"</string>
+    <string name="permgroupupgraderequest_device_aware_camera" msgid="3290160912843715236">"要更改&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上的相机权限吗？"</string>
     <string name="permgroupupgraderequestdetail_camera" msgid="6642747548010962597">"此应用想要随时拍摄照片和录制视频，即使在您未使用它的时候。"<annotation id="link">"您可以在“设置”中授权"</annotation>"。"</string>
     <string name="permgrouprequest_calllog" msgid="2065327180175371397">"要允许“&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;”访问您的手机通话记录吗？"</string>
     <string name="permgrouprequest_device_aware_calllog" msgid="8220927190376843309">"要允许&lt;b&gt;<xliff:g id="APP_NAME">%1$s</xliff:g>&lt;/b&gt;在&lt;b&gt;<xliff:g id="DEVICE_NAME">%2$s</xliff:g>&lt;/b&gt;上访问您的手机通话记录吗？"</string>
@@ -565,7 +565,7 @@
     <string name="blocked_sensor_summary" msgid="4443707628305027375">"会影响应用和服务"</string>
     <string name="blocked_mic_summary" msgid="8960466941528458347">"当您拨打紧急电话号码时，系统可能仍会分享麦克风数据。"</string>
     <string name="blocked_sensor_button_label" msgid="6742092634984289658">"更改"</string>
-    <string name="automotive_blocked_camera_title" msgid="6142362431548829416">"摄像头访问权限已关闭"</string>
+    <string name="automotive_blocked_camera_title" msgid="6142362431548829416">"已关闭相机权限"</string>
     <string name="automotive_blocked_microphone_title" msgid="3956311098238620220">"麦克风使用权限已关闭"</string>
     <string name="automotive_blocked_location_title" msgid="6047574747593264689">"位置信息获取权限已关闭"</string>
     <string name="automotive_blocked_infotainment_app_summary" msgid="8217099645064950860">"信息娱乐应用"</string>
@@ -587,8 +587,8 @@
     <string name="safety_privacy_qs_tile_subtitle" msgid="3621544532041936749">"查看状态"</string>
     <string name="privacy_controls_qs" msgid="5780144882040591169">"您的隐私控制项"</string>
     <string name="security_settings_button_label_qs" msgid="8280343822465962330">"更多设置"</string>
-    <string name="camera_toggle_label_qs" msgid="3880261453066157285">"摄像头使用权限"</string>
-    <string name="microphone_toggle_label_qs" msgid="8132912469813396552">"麦克风使用权限"</string>
+    <string name="camera_toggle_label_qs" msgid="3880261453066157285">"相机权限"</string>
+    <string name="microphone_toggle_label_qs" msgid="8132912469813396552">"麦克风权限"</string>
     <string name="permissions_removed_qs" msgid="8957319130625294572">"已移除权限"</string>
     <string name="camera_usage_qs" msgid="4394233566086665994">"查看近期相机使用情况"</string>
     <string name="microphone_usage_qs" msgid="8527666682168170417">"查看近期麦克风使用情况"</string>
@@ -629,13 +629,13 @@
     <string name="safety_center_background_location_access_revoked" msgid="6972274943343442213">"访问权限已更改"</string>
     <string name="safety_center_view_recent_location_access" msgid="3524391299490678243">"查看近期位置信息使用情况"</string>
     <string name="privacy_controls_title" msgid="7605929972256835199">"隐私控制"</string>
-    <string name="camera_toggle_title" msgid="1251201397431837666">"摄像头使用权限"</string>
-    <string name="mic_toggle_title" msgid="2649991093496110162">"麦克风使用权限"</string>
+    <string name="camera_toggle_title" msgid="1251201397431837666">"相机权限"</string>
+    <string name="mic_toggle_title" msgid="2649991093496110162">"麦克风权限"</string>
     <string name="perm_toggle_description" msgid="7801326363741451379">"针对应用和服务"</string>
     <string name="mic_toggle_description" msgid="9163104307990677157">"会影响应用和服务。如果您关闭此设置，那么当您拨打紧急电话号码时，系统可能仍会分享麦克风数据。"</string>
     <string name="location_settings_subtitle" msgid="2328360561197430695">"查看能够访问位置信息的应用和服务"</string>
     <string name="show_clip_access_notification_title" msgid="5168467637351109096">"显示剪贴板访问通知"</string>
-    <string name="show_clip_access_notification_summary" msgid="3532020182782112687">"系统会在应用访问您复制的文字、图片或其他内容时显示一条消息"</string>
+    <string name="show_clip_access_notification_summary" msgid="3532020182782112687">"若有应用访问您复制的文字、图片或其他内容，系统会显示通知"</string>
     <string name="show_password_title" msgid="2877269286984684659">"显示密码"</string>
     <string name="show_password_summary" msgid="1110166488865981610">"输入时短暂显示字符"</string>
     <string name="permission_rationale_message_location" msgid="2153841534298068414">"此应用已声明它可能会与第三方分享位置数据"</string>
diff --git a/PermissionController/res/values-zh-rHK-v36/strings.xml b/PermissionController/res/values-zh-rHK-v36/strings.xml
new file mode 100644
index 0000000000..630849ad2c
--- /dev/null
+++ b/PermissionController/res/values-zh-rHK-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"其他應用程式的代理控制項"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"在裝置和其他應用程式中執行操作"</string>
+</resources>
diff --git a/PermissionController/res/values-zh-rHK/strings.xml b/PermissionController/res/values-zh-rHK/strings.xml
index 782912088d..f16c519b92 100644
--- a/PermissionController/res/values-zh-rHK/strings.xml
+++ b/PermissionController/res/values-zh-rHK/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"預設數碼助理應用程式"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"數碼助理應用程式"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"小幫手應用程式能根據你正在查看的螢幕資訊提供協助。部分應用程式可同時支援啟動器及語音輸入服務，以提供更全面的協助。"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"<xliff:g id="OEM_NAME">%s</xliff:g> 的建議"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"預設瀏覽器應用程式"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"瀏覽器應用程式"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"此類應用程式可讓你存取互聯網，並會顯示你輕按的連結"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"開啟連結"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"預設用於工作"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"私人空間的預設應用程式"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"已針對你的裝置優化"</string>
     <string name="default_app_others" msgid="7793029848126079876">"其他"</string>
     <string name="default_app_none" msgid="9084592086808194457">"無"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(系統預設)"</string>
diff --git a/PermissionController/res/values-zh-rTW-v36/strings.xml b/PermissionController/res/values-zh-rTW-v36/strings.xml
new file mode 100644
index 0000000000..710db24f4b
--- /dev/null
+++ b/PermissionController/res/values-zh-rTW-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"其他應用程式的代理控制選項"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"在裝置和其他應用程式中執行操作"</string>
+</resources>
diff --git a/PermissionController/res/values-zh-rTW/strings.xml b/PermissionController/res/values-zh-rTW/strings.xml
index d745840ad3..a92527f06b 100644
--- a/PermissionController/res/values-zh-rTW/strings.xml
+++ b/PermissionController/res/values-zh-rTW/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"預設數位助理應用程式"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"數位助理應用程式"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"小幫手應用程式可根據當下的螢幕內容提供協助。某些應用程式同時支援啟動器和語音輸入服務，服務更完善。"</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"「<xliff:g id="OEM_NAME">%s</xliff:g>」推薦"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"預設瀏覽器應用程式"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"瀏覽器應用程式"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"透過這類應用程式你可以連上網際網路和顯示你輕觸的連結"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"開啟連結"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"預設的工作應用程式"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"私人空間的預設應用程式"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"已針對裝置最佳化"</string>
     <string name="default_app_others" msgid="7793029848126079876">"其他"</string>
     <string name="default_app_none" msgid="9084592086808194457">"無"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(系統預設)"</string>
@@ -489,7 +489,7 @@
     <string name="permgroupupgraderequestdetail_nearby_devices" msgid="6877531270654738614">"要允許「<xliff:g id="APP_NAME">%1$s</xliff:g>」&lt;b&gt;&lt;/b&gt;尋找、連結及判斷附近裝置的相對位置嗎？"<annotation id="link">"請前往「設定」授予權限。"</annotation></string>
     <string name="permgrouprequest_fineupgrade" msgid="2334242928821697672">"要將「<xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g>」可以存取的定位資訊從「大概位置」改為「精確位置」嗎？"</string>
     <string name="permgrouprequest_device_aware_fineupgrade" msgid="4453775952305587571">"要將「<xliff:g id="APP_NAME">&lt;b&gt;%1$s&lt;/b&gt;</xliff:g>」在「<xliff:g id="DEVICE_NAME">%2$s</xliff:g>」&lt;b&gt;&lt;/b&gt;的位置資訊存取權從大概變更為精確嗎？"</string>
-    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"要允許「<xliff:g id="APP_NAME">%1$s</xliff:g>」&lt;b&gt;&lt;/b&gt;存取這部裝置的大概位置資訊嗎？"</string>
+    <string name="permgrouprequest_coarselocation" msgid="7244605063736425232">"要允許「<xliff:g id="APP_NAME">%1$s</xliff:g>」&lt;b&gt;&lt;/b&gt;存取這部裝置的大概位置嗎？"</string>
     <string name="permgrouprequest_device_aware_coarselocation" msgid="8367540370912066757">"要允許「<xliff:g id="APP_NAME">%1$s</xliff:g>」&lt;b&gt;&lt;/b&gt;存取「<xliff:g id="DEVICE_NAME">%2$s</xliff:g>」&lt;b&gt;&lt;/b&gt;的大概位置資訊嗎？"</string>
     <string name="permgrouprequest_finelocation_imagetext" msgid="1313062433398914334">"精確"</string>
     <string name="permgrouprequest_coarselocation_imagetext" msgid="8650605041483025297">"大概"</string>
diff --git a/PermissionController/res/values-zu-v36/strings.xml b/PermissionController/res/values-zu-v36/strings.xml
new file mode 100644
index 0000000000..276b81545a
--- /dev/null
+++ b/PermissionController/res/values-zu-v36/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="6493844150240131544">"Isilawuli somenzeli samanye ama-app"</string>
+    <string name="app_function_access_settings_summary" msgid="4981985766883304913">"Yenza okuthile kudivayisi yakho nakwamanye ama-app"</string>
+</resources>
diff --git a/PermissionController/res/values-zu/strings.xml b/PermissionController/res/values-zu/strings.xml
index 92bbe3d8c8..d62be254ba 100644
--- a/PermissionController/res/values-zu/strings.xml
+++ b/PermissionController/res/values-zu/strings.xml
@@ -358,6 +358,7 @@
     <string name="role_assistant_label" msgid="4727586018198208128">"I-app yomsizi wedijithali ezenzekelayo"</string>
     <string name="role_assistant_short_label" msgid="3369003713187703399">"I-app yomsizi wedijithali"</string>
     <string name="role_assistant_description" msgid="6622458130459922952">"Izinhlelo zokusebenza zokusiza zingakusiza kusukela kulwazi olusuka kusikrini osibukayo. Ezinye izinhlelo zokusebenza ezingasekela womabili amasevisi esiqalisi nawokokufaka kwezwi azokunikeza ukusiza okuhlanganisiwe."</string>
+    <string name="role_assistant_recommended_title" msgid="2093873159106905257">"Kunconywe ngu-<xliff:g id="OEM_NAME">%s</xliff:g>"</string>
     <string name="role_browser_label" msgid="2877796144554070207">"Uhlelo lokusebenza lwesiphequluli oluzenzakalelayo"</string>
     <string name="role_browser_short_label" msgid="6745009127123292296">"I-app yesiphequluli"</string>
     <string name="role_browser_description" msgid="3465253637499842671">"Izinhlelo zokusebenza ezikunikeza ukufinyelela ku-inthanethi nezibonisa izixhumanisi ozithephayo"</string>
@@ -440,7 +441,6 @@
     <string name="default_apps_manage_domain_urls" msgid="6775566451561036069">"Ivula amalinki"</string>
     <string name="default_apps_for_work" msgid="4970308943596201811">"Okuzenzakalelayo kokusebenza"</string>
     <string name="default_apps_for_private_profile" msgid="2022024112144880785">"Okuzenzakalelayo kwendawo engasese"</string>
-    <string name="default_app_recommended" msgid="5669584821778942909">"Ilungiselelwe idivayisi"</string>
     <string name="default_app_others" msgid="7793029848126079876">"Amanye"</string>
     <string name="default_app_none" msgid="9084592086808194457">"Lutho"</string>
     <string name="default_app_system_default" msgid="6218386768175513760">"(Okuzenzakalelayo kwesistimu)"</string>
diff --git a/PermissionController/res/values/bools.xml b/PermissionController/res/values/bools.xml
index 4483fc48f5..22abdd6e29 100644
--- a/PermissionController/res/values/bools.xml
+++ b/PermissionController/res/values/bools.xml
@@ -22,4 +22,12 @@
     <bool name="is_at_least_v">false</bool>
     <bool name="config_usePreferenceForAppPermissionSettings">false</bool>
     <bool name="config_appPermissionFooterLinkPreferenceSummaryUnderlined">false</bool>
+    <bool name="config_enableExpressiveDesignInPermissionSettings">true</bool>
+    <!-- config for opting out of expressive permission dialogs -->
+    <bool name="config_enableExpressiveDesignInRequestPermissionDialog">true</bool>
+    <!-- config for opting out of expressive enhanced confirmation dialogs -->
+    <bool name="config_enableExpressiveDesignInEnhancedConfirmationDialog">true</bool>
+    <!-- config for opting out of expressive Safety Center. This has no effect currently
+    but may be enabled in a subsequent release -->
+    <bool name="config_enableExpressiveDesignInSafetyCenter">false</bool>
 </resources>
diff --git a/PermissionController/res/values/config.xml b/PermissionController/res/values/config.xml
index 657dc07dda..88fb1d1097 100644
--- a/PermissionController/res/values/config.xml
+++ b/PermissionController/res/values/config.xml
@@ -20,13 +20,34 @@
     <bool name="config_showDialerRole">true</bool>
     <bool name="config_showSmsRole">true</bool>
     <!--
-      ~ Semicolon separated list of packages that are recommended for the assistant role.
+      ~ The "OEM_NAME" part of the "Recommended by OEM_NAME" title for the recommended section in
+      ~ the default assistant setting.
+      ~ <p>
+      ~ Recommendation is only enabled if {@code config_recommendedAssistantsBy},
+      ~ {@code config_recommendedAssistantsDescription} and {@code config_recommendedAssistants}
+      ~ are all set.
+      -->
+    <string name="config_recommendedAssistantsBy"></string>
+    <!--
+      ~ Description for the recommended section in the default assistant setting.
+      ~ <p>
+      ~ Recommendation is only enabled if {@code config_recommendedAssistantsBy},
+      ~ {@code config_recommendedAssistantsDescription} and {@code config_recommendedAssistants}
+      ~ are all set.
+      -->
+    <string name="config_recommendedAssistantsDescription"></string>
+    <!--
+      ~ Semicolon separated list of packages that are recommended in the default assistant setting.
       ~ <p>
       ~ This follows the same format as config_defaultAssistant and also requires a signing
       ~ certificate digest (separated by a colon from the package name) if the app is not a system
       ~ app.
+      ~ <p>
+      ~ Recommendation is only enabled if {@code config_recommendedAssistantsBy},
+      ~ {@code config_recommendedAssistantsDescription} and {@code config_recommendedAssistants}
+      ~ are all set.
       -->
-    <string name="config_recommendedAssistants"></string>
+    <string name="config_recommendedAssistants" translatable="false"></string>
 
     <bool name="config_useAlternativePermGroupSummary">false</bool>
     <bool name="config_useWindowBlur">false</bool>
diff --git a/PermissionController/res/values/overlayable.xml b/PermissionController/res/values/overlayable.xml
index 72896fcdb1..a0bcf9ad5a 100644
--- a/PermissionController/res/values/overlayable.xml
+++ b/PermissionController/res/values/overlayable.xml
@@ -154,6 +154,44 @@
 
             <!-- END Used in V30 only -->
 
+            <!-- START EXPRESSIVE PERMISSION DIALOG -->
+
+            <item type="style" name="PermissionGrantTitleMessageExpressive" />
+            <item type="style" name="PermissionGrantDetailMessageExpressive" />
+            <item type="style" name="PermissionGrantButtonListExpressive" />
+            <item type="style" name="PermissionGrantButtonExpressive" />
+
+            <item type="style" name="PermissionGrantButtonAllowExpressive" />
+            <item type="style" name="PermissionGrantButtonAllowForegroundExpressive" />
+            <item type="style" name="PermissionGrantButtonAllowOneTimeExpressive" />
+            <item type="style" name="PermissionGrantButtonAllowSelectedExpressive" />
+            <item type="style" name="PermissionGrantButtonAllowAllExpressive" />
+            <item type="style" name="PermissionGrantButtonDenyExpressive" />
+            <item type="style" name="PermissionGrantButtonNoUpgradeExpressive" />
+            <item type="style" name="PermissionGrantButtonDontAllowMoreExpressive" />
+
+            <item type="style" name="PermissionRationaleContentExpressive" />
+            <item type="style" name="PermissionRationaleTitleContainerExpressive" />
+            <item type="style" name="PermissionRationaleTitleIconExpressive" />
+            <item type="style" name="PermissionRationaleTitleMessageExpressive" />
+            <item type="style" name="PermissionRationaleSectionOuterContainerExpressive" />
+            <item type="style" name="PermissionRationaleSectionIconExpressive" />
+            <item type="style" name="PermissionRationaleSectionInnerContainerExpressive" />
+            <item type="style" name="PermissionRationaleSectionTitleExpressive" />
+            <item type="style" name="PermissionRationaleSectionMessageExpressive" />
+            <item type="style" name="PermissionRationaleSectionPurposeListExpressive" />
+            <item type="style" name="PermissionRationaleButtonContainerExpressive" />
+            <item type="style" name="PermissionRationaleBackButtonExpressive" />
+
+            <item type="style" name="EnhancedConfirmationDialogExpressive" />
+            <item type="style" name="EnhancedConfirmationDialogHeaderExpressive" />
+            <item type="style" name="EnhancedConfirmationDialogIconExpressive" />
+            <item type="style" name="EnhancedConfirmationDialogTitleExpressive" />
+            <item type="style" name="EnhancedConfirmationDialogDescExpressive" />
+            <item type="style" name="Theme.EnhancedConfirmationDialogActivityExpressive" />
+
+            <!-- END EXPRESSIVE PERMISSION DIALOG -->
+
             <!-- END PERMISSION GRANT DIALOG -->
 
             <!-- START PERMISSION RATIONALE DIALOG -->
@@ -378,6 +416,8 @@
             <item type="bool" name="config_showBrowserRole" />
             <item type="bool" name="config_showDialerRole" />
             <item type="bool" name="config_showSmsRole" />
+            <item type="string" name="config_recommendedAssistantsBy" />
+            <item type="string" name="config_recommendedAssistantsDescription" />
             <item type="string" name="config_recommendedAssistants" />
             <!-- END ROLE CONFIGS -->
 
@@ -476,7 +516,7 @@
             <item type="style" name="EnhancedConfirmationDialogButton" />
             <!-- END ENHANCED CONFIRMATION DIALOG -->
 
-            <!-- START STETINGS LIB HEADER -->
+            <!-- START SETTINGS LIB HEADER -->
             <item type="style" name="SettingsLibEntityHeader" />
             <item type="style" name="SettingsLibEntityHeaderContent" />
             <item type="style" name="SettingsLibEntityHeaderIcon" />
@@ -485,7 +525,67 @@
             <item type="bool" name="config_useCollapsingToolbarInPermissionSettings"/>
             <!-- END SETTINGS LIB HEADER -->
 
-        </policy>
+            <!-- START EXPRESSIVE DESIGN CONFIGS -->
+            <item type="bool" name="config_enableExpressiveDesignInPermissionSettings"/>
+            <!-- config for opting out of expressive permission dialogs -->
+            <item type="bool" name="config_enableExpressiveDesignInRequestPermissionDialog"/>
+            <!-- config for opting out of expressive enhanced confirmation dialogs -->
+            <item type="bool" name="config_enableExpressiveDesignInEnhancedConfirmationDialog"/>
+            <!-- END EXPRESSIVE DESIGN CONFIGS -->
+
+            <!-- START EXPRESSIVE DESIGN ATTRIBUTES -->
+
+            <!-- Start: SwitchCompat -->
+            <!-- Tint to apply to the thumb drawable. -->
+            <item type="attr" name="thumbTint" />
+            <!-- Blending mode used to apply the thumb tint. -->
+            <item type="attr" name="thumbTintMode" />
+            <!-- Drawable to use as the "track" that the switch thumb slides within. -->
+            <item type="attr" name="track" />
+            <!-- Tint to apply to the track. -->
+            <item type="attr" name="trackTint" />
+            <!-- Blending mode used to apply the track tint. -->
+            <item type="attr" name="trackTintMode" />
+            <!-- Amount of padding on either side of text within the switch thumb. -->
+            <item type="attr" name="thumbTextPadding" />
+            <!-- TextAppearance style for text displayed on the switch thumb. -->
+            <item type="attr" name="switchTextAppearance" />
+            <!-- Minimum width for the switch component -->
+            <item type="attr" name="switchMinWidth" />
+            <!-- Minimum space between the switch and caption text -->
+            <item type="attr" name="switchPadding" />
+            <!-- Whether to split the track and leave a gap for the thumb drawable. -->
+            <item type="attr" name="splitTrack" />
+            <!-- Whether to draw on/off text. -->
+            <item type="attr" name="showText" />
+            <!-- END: SwitchCompat -->
+
+            <!-- Start: MaterialSwitch -->
+            <!-- MaterialSwitch-specific state to represent presence of a thumb icon. -->
+            <item type="attr"  name="state_with_icon" />
+            <!-- Drawable used for the thumb icon that will be drawn upon the thumb. -->
+            <item type="attr" name="thumbIcon" />
+            <!-- Tint that will be applied to the thumb icon drawable. -->
+            <item type="attr" name="thumbIconTint" />
+            <!-- The blending mode used to apply the tint specified by thumbIconTint
+            to thumbIcon. The default mode is SRC_IN if not specified. -->
+            <item type="attr" name="thumbIconTintMode" />
+            <!-- Size of the thumb icon. -->
+            <item type="attr" name="thumbIconSize" />
+            <!-- Drawable used for the track decoration that will be drawn upon the track.
+            By default it will draw an outline on the track in the unchecked state. -->
+            <item type="attr" name="trackDecoration" />
+            <!-- Tint that will be applied to the track decoration drawable.. -->
+            <item type="attr" name="trackDecorationTint" />
+            <!-- The blending mode used to apply the tint specified by trackDecorationTint
+            to trackDecoration. The default mode is SRC_IN if not specified. -->
+            <item type="attr" name="trackDecorationTintMode" />
+            <!-- END: MaterialSwitch -->
+
+            <!-- Expressive switch style attribute -->
+            <item type="attr" name="expressiveSwitchStyle" />
+            <!-- END EXPRESSIVE DESIGN ATTRIBUTES -->
+         </policy>
 
     </overlayable>
 
@@ -646,6 +746,8 @@
             <item type="style" name="TextAppearance.SafetyCenter.ActionButton" />
             <item type="style" name="TextAppearance.SafetyCenter.ActionButton.Secondary" />
             <item type="style" name="TextAppearance.SafetyCenter.BrandChip" />
+
+            <item type="bool" name="config_enableExpressiveDesignInSafetyCenter"/>
         </policy>
     </overlayable>
 
diff --git a/PermissionController/res/values/strings.xml b/PermissionController/res/values/strings.xml
index f5a997674f..8a1b9d1d3f 100644
--- a/PermissionController/res/values/strings.xml
+++ b/PermissionController/res/values/strings.xml
@@ -1125,6 +1125,8 @@
     <string name="role_assistant_short_label">Digital assistant app</string>
     <!-- Description for the assistant role. [CHAR LIMIT=NONE] -->
     <string name="role_assistant_description">Assist apps can help you based on information from the screen you\u2019re viewing. Some apps support both launcher and voice input services to give you integrated assistance.</string>
+    <!-- Title for category of recommended assistant apps. [CHAR LIMIT=50] [SCREENSHOT=screen/89mSADZQmkrZeNq] -->
+    <string name="role_assistant_recommended_title">Recommended by <xliff:g id="OEM_NAME" example="FictionalOEM">%s</xliff:g></string>
 
     <!-- Label for the browser role. [CHAR LIMIT=30] -->
     <string name="role_browser_label">Default browser app</string>
@@ -1337,9 +1339,6 @@
     <!-- Title for category of default apps for private profile [CHAR LIMIT=50] -->
     <string name="default_apps_for_private_profile">Default for private space</string>
 
-    <!-- Title for category of apps that are optimized for the device [CHAR LIMIT=50] -->
-    <string name="default_app_recommended">Optimized for device</string>
-
     <!-- Title for category of other apps [CHAR LIMIT=50] -->
     <string name="default_app_others">Others</string>
 
diff --git a/PermissionController/res/values/styles.xml b/PermissionController/res/values/styles.xml
index 9d280c38a8..66b42d1d58 100644
--- a/PermissionController/res/values/styles.xml
+++ b/PermissionController/res/values/styles.xml
@@ -1467,7 +1467,8 @@
         <item name="android:contentDescription">@null</item>
     </style>
 
-    <style name="EnhancedConfirmationDialogTitle" parent="@android:style/TextAppearance.Material.Headline">
+    <style name="EnhancedConfirmationDialogTitle"
+           parent="@android:style/TextAppearance.Material.Headline">
         <item name="android:layout_width">wrap_content</item>
         <item name="android:layout_height">wrap_content</item>
         <item name="android:layout_marginTop">16dp</item>
@@ -1485,7 +1486,8 @@
         <item name="android:layout_height">wrap_content</item>
         <item name="android:orientation">vertical</item>
     </style>
-    <style name="EnhancedConfirmationDialogDesc" parent="@android:style/TextAppearance.Material.Body1">
+    <style name="EnhancedConfirmationDialogDesc"
+           parent="@android:style/TextAppearance.Material.Body1">
         <item name="android:layout_width">match_parent</item>
         <item name="android:layout_height">wrap_content</item>
         <item name="android:gravity">start</item>
diff --git a/PermissionController/res/xml-v34/privacy_subpage.xml b/PermissionController/res/xml-v34/privacy_subpage.xml
index 0aec164ced..ea6b38044a 100644
--- a/PermissionController/res/xml-v34/privacy_subpage.xml
+++ b/PermissionController/res/xml-v34/privacy_subpage.xml
@@ -21,12 +21,11 @@
         android:key="subpage_brand_chip"
         app:selectable="false"/>
 
-    <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
+    <com.android.settingslib.widget.UntitledPreferenceCategory
         android:key="subpage_issue_group"
-        android:layout="@layout/preference_category_no_label"
         app:selectable="false" />
 
-    <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
+    <com.android.settingslib.widget.UntitledPreferenceCategory
         android:key="subpage_generic_entry_group"
         app:selectable="false" />
 
@@ -59,9 +58,8 @@
             android:title="@string/location_settings"
           android:summary="@string/location_settings_subtitle"/>
 
-        <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
+        <com.android.settingslib.widget.UntitledPreferenceCategory
             android:key="subpage_controls_extra_entry_group"
-            android:layout="@layout/preference_category_no_label"
             app:selectable="false" />
     </com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory>
 </PreferenceScreen>
diff --git a/PermissionController/res/xml-v34/safety_center_subpage.xml b/PermissionController/res/xml-v34/safety_center_subpage.xml
index 81e2467730..c25f861879 100644
--- a/PermissionController/res/xml-v34/safety_center_subpage.xml
+++ b/PermissionController/res/xml-v34/safety_center_subpage.xml
@@ -26,9 +26,8 @@
         android:key="subpage_illustration"
         app:selectable="false"/>
 
-    <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
+    <com.android.settingslib.widget.UntitledPreferenceCategory
         android:key="subpage_issue_group"
-        android:layout="@layout/preference_category_no_label"
         app:selectable="false" />
 
     <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
diff --git a/PermissionController/res/xml-v35/app_permission.xml b/PermissionController/res/xml-v35/app_permission.xml
index 87315815dd..3084540859 100644
--- a/PermissionController/res/xml-v35/app_permission.xml
+++ b/PermissionController/res/xml-v35/app_permission.xml
@@ -71,6 +71,12 @@
         android:title="@string/app_permission_location_accuracy"
         app:isPreferenceVisible="false" />
 
+    <androidx.preference.SwitchPreferenceCompat
+        android:key="app_permission_location_accuracy_switch_compat"
+        android:summary="@string/app_permission_location_accuracy_subtitle"
+        android:title="@string/app_permission_location_accuracy"
+        app:isPreferenceVisible="false" />
+
     <com.android.permissioncontroller.permission.ui.handheld.v36.PermissionTwoTargetPreference
         android:key="app_permission_details"
         android:selectable="false"
diff --git a/PermissionController/res/xml/adjust_user_sensitive.xml b/PermissionController/res/xml/adjust_user_sensitive.xml
deleted file mode 100644
index ba7d80050f..0000000000
--- a/PermissionController/res/xml/adjust_user_sensitive.xml
+++ /dev/null
@@ -1,34 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2019 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-
-<PreferenceScreen
-    xmlns:android="http://schemas.android.com/apk/res/android">
-
-    <SwitchPreference
-        android:key="assistantrecordaudio"
-        android:title="@string/assistant_record_audio_user_sensitive_title"
-        android:summary="@string/assistant_record_audio_user_sensitive_summary"/>
-
-    <SwitchPreference
-        android:key="global"
-        android:title="@string/adjust_user_sensitive_globally_title"
-        android:summary="@string/adjust_user_sensitive_globally_summary"/>
-
-    <PreferenceCategory
-        android:key="perapp"
-        android:title="@string/adjust_user_sensitive_per_app_header" />
-
-</PreferenceScreen>
diff --git a/PermissionController/res/xml/roles.xml b/PermissionController/res/xml/roles.xml
index 78017c32e4..33732b9613 100644
--- a/PermissionController/res/xml/roles.xml
+++ b/PermissionController/res/xml/roles.xml
@@ -202,6 +202,8 @@
           -->
         <permissions>
             <permission name="android.permission.PROVIDE_OWN_AUTOFILL_SUGGESTIONS" minSdkVersion="34" />
+            <permission name="android.permission.REPOSITION_SELF_WINDOWS"
+                featureFlag="com.android.window.flags.Flags.enableWindowRepositioningApi" />
         </permissions>
     </role>
 
@@ -1378,9 +1380,34 @@
                 featureFlag="android.permission.flags.Flags.supervisionRolePermissionUpdateEnabled"/>
             <permission name="android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS"
                 featureFlag="android.permission.flags.Flags.supervisionRolePermissionUpdateEnabled"/>
+            <permission name="android.permission.MANAGE_DEVICE_POLICY_CAMERA"
+                featureFlag="android.app.admin.flags.Flags.setApplicationRestrictionsCoexistence"/>
+            <permission name="android.permission.MANAGE_DEVICE_POLICY_PROFILES"
+                featureFlag="android.app.admin.flags.Flags.setApplicationRestrictionsCoexistence"/>
         </permissions>
     </role>
 
+    <role
+        name="android.app.role.SUPERVISION"
+        behavior="v36r1.SupervisionRoleBehavior"
+        exclusive="false"
+        exclusivity="none"
+        featureFlag="android.permission.flags.Flags.supervisionRoleEnabled"
+        minSdkVersion="36"
+        systemOnly="true"
+        visible="false" >
+        <required-components>
+            <service permission="android.permission.BIND_SUPERVISION_APP_SERVICE">
+                <intent-filter>
+                    <action name="android.app.action.SUPERVISION_APP_SERVICE" />
+                </intent-filter>
+            </service>
+        </required-components>
+        <permissions>
+        </permissions>
+    </role>
+
+
     <!---
       ~ A role for the package responsible for constructing managed device experiences,
       ~ including during provisioning.
diff --git a/PermissionController/res/xml/safety_center_dashboard.xml b/PermissionController/res/xml/safety_center_dashboard.xml
index e3951ca83b..b47454f8ef 100644
--- a/PermissionController/res/xml/safety_center_dashboard.xml
+++ b/PermissionController/res/xml/safety_center_dashboard.xml
@@ -24,9 +24,8 @@
         android:order="-3"
         app:selectable="false" />
 
-    <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
+    <com.android.settingslib.widget.UntitledPreferenceCategory
         android:key="issues_group"
-        android:layout="@layout/preference_category_no_label"
         app:selectable="false" />
 
     <!-- TODO: b/291574390 - Move this to the issue drawer or status card view instead of having a
@@ -39,9 +38,8 @@
         android:title="@string/safety_center_entries_category_title"
         app:selectable="false" />
 
-    <com.android.permissioncontroller.safetycenter.ui.ComparablePreferenceCategory
+    <com.android.settingslib.widget.UntitledPreferenceCategory
         android:key="static_entries_group"
-        android:layout="@layout/preference_category_no_label"
         app:selectable="false" />
 
     <com.android.permissioncontroller.safetycenter.ui.SpacerPreference
diff --git a/PermissionController/res/xml/unused_app_categories.xml b/PermissionController/res/xml/unused_app_categories.xml
index 69cbfd1439..dcb1e4eaf3 100644
--- a/PermissionController/res/xml/unused_app_categories.xml
+++ b/PermissionController/res/xml/unused_app_categories.xml
@@ -15,9 +15,16 @@
   -->
 
 <PreferenceScreen
-    xmlns:android="http://schemas.android.com/apk/res/android">
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto">>
 
     <PreferenceCategory
         android:key="info_msg_category"/>
 
+    <com.android.settingslib.widget.ZeroStatePreference
+        android:key="zero_state_preference"
+        android:title="@string/no_unused_apps"
+        android:icon="@drawable/ic_apps_24dp"
+        app:isPreferenceVisible="false"/>
+
 </PreferenceScreen>
diff --git a/PermissionController/role-controller/Android.bp b/PermissionController/role-controller/Android.bp
index 9f217660a0..4b18c6cd00 100644
--- a/PermissionController/role-controller/Android.bp
+++ b/PermissionController/role-controller/Android.bp
@@ -37,6 +37,7 @@ java_library {
         "android.content.pm.flags-aconfig-java-export",
         "android.permission.flags-aconfig-java-export",
         "android.os.flags-aconfig-java-export",
+        "com.android.window.flags.window-aconfig-java-export",
         "device_policy_aconfig_flags_java_export",
     ],
     apex_available: [
diff --git a/PermissionController/role-controller/java/com/android/role/controller/behavior/v36r1/SupervisionRoleBehavior.java b/PermissionController/role-controller/java/com/android/role/controller/behavior/v36r1/SupervisionRoleBehavior.java
new file mode 100644
index 0000000000..d86ef849e1
--- /dev/null
+++ b/PermissionController/role-controller/java/com/android/role/controller/behavior/v36r1/SupervisionRoleBehavior.java
@@ -0,0 +1,111 @@
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
+
+package com.android.role.controller.behavior.v36r1;
+
+import android.app.supervision.SupervisionManager;
+import android.content.Context;
+import android.content.pm.ApplicationInfo;
+import android.content.res.Resources;
+import android.os.UserHandle;
+import android.permission.flags.Flags;
+import android.util.Log;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.role.controller.model.Role;
+import com.android.role.controller.model.RoleBehavior;
+import com.android.role.controller.util.PackageUtils;
+import com.android.role.controller.util.SignedPackage;
+import com.android.role.controller.util.SignedPackageUtils;
+
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * Class for behavior of the supervision role.
+ *
+ * <p>For a package to qualify as the role holder, it must be specified as an allowed package in
+ * config_allowedSupervisionRolePackages or the config_systemSupervision package.
+ */
+public class SupervisionRoleBehavior implements RoleBehavior {
+
+    private static final String LOG_TAG = SupervisionRoleBehavior.class.getSimpleName();
+
+    /*
+     * This config is temporary and intentionally not exposed as a system API and must be
+     * accessed by name.
+     */
+    private static final String CONFIG_ALLOWED_SUPERVISION_ROLE_PACKAGES =
+            "config_allowedSupervisionRolePackages";
+
+    @Nullable
+    @Override
+    public Boolean isPackageQualifiedAsUser(@NonNull Role role, @NonNull String packageName,
+            @NonNull UserHandle user, @NonNull Context context) {
+        if (!Flags.supervisionRoleEnabled()) {
+            return false;
+        }
+
+        return isSystemSupervisionPackage(packageName, context)
+                || isAllowedPackage(packageName, user, context);
+    }
+
+    @Override
+    @Nullable
+    public Boolean shouldAllowBypassingQualification(@NonNull Role role, @NonNull Context context) {
+        if (!Flags.supervisionRoleEnabled()) {
+            return false;
+        }
+
+        SupervisionManager supervisionManager = context.getSystemService(SupervisionManager.class);
+        return supervisionManager.shouldAllowBypassingSupervisionRoleQualification();
+    }
+
+    private boolean isSystemSupervisionPackage(@NonNull String packageName,
+            @NonNull Context context) {
+        return Objects.equals(context.getString(android.R.string.config_systemSupervision),
+                packageName);
+    }
+
+    private boolean isAllowedPackage(
+            @NonNull String packageName, @NonNull UserHandle user, @NonNull Context context) {
+        ApplicationInfo applicationInfo =
+                PackageUtils.getApplicationInfoAsUser(packageName, user, context);
+        if (applicationInfo == null) {
+            return false;
+        }
+
+        int resourceId = context.getResources().getIdentifier(
+                CONFIG_ALLOWED_SUPERVISION_ROLE_PACKAGES, "string", "android");
+        if (resourceId == 0) {
+            Log.w(LOG_TAG, "Cannot find resource for: " + CONFIG_ALLOWED_SUPERVISION_ROLE_PACKAGES);
+            return false;
+        }
+
+        String config;
+        try {
+            config = context.getString(resourceId);
+        } catch (Resources.NotFoundException e) {
+            Log.w(LOG_TAG, "Cannot get resource: " + CONFIG_ALLOWED_SUPERVISION_ROLE_PACKAGES, e);
+            return false;
+        }
+
+        List<SignedPackage> signedPackages = SignedPackage.parseList(config);
+        return SignedPackageUtils.matchesAny(applicationInfo, signedPackages, context);
+    }
+}
diff --git a/PermissionController/role-controller/java/com/android/role/controller/behavior/v36r1/package-info.java b/PermissionController/role-controller/java/com/android/role/controller/behavior/v36r1/package-info.java
new file mode 100644
index 0000000000..b2cf10e30e
--- /dev/null
+++ b/PermissionController/role-controller/java/com/android/role/controller/behavior/v36r1/package-info.java
@@ -0,0 +1,18 @@
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
+
+@androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.BAKLAVA)
+package com.android.role.controller.behavior.v36r1;
diff --git a/PermissionController/src/com/android/permissioncontroller/Constants.java b/PermissionController/src/com/android/permissioncontroller/Constants.java
index 47ec9cabb9..88a4978838 100644
--- a/PermissionController/src/com/android/permissioncontroller/Constants.java
+++ b/PermissionController/src/com/android/permissioncontroller/Constants.java
@@ -156,6 +156,12 @@ public class Constants {
      */
     public static final String ACTION_MANAGE_AUTO_REVOKE = "manageAutoRevoke";
 
+    /**
+     * String action for navigating to the additional permissions screen.
+     */
+    public static final String ACTION_ADDITIONAL_PERMISSIONS =
+            "com.android.permissioncontroller.action.ADDITIONAL_PERMISSIONS";
+
     /**
      * Key for Notification.Builder.setGroup() for the incident report approval notification.
      */
diff --git a/PermissionController/src/com/android/permissioncontroller/appfunctions/AppFunctionsUtil.kt b/PermissionController/src/com/android/permissioncontroller/appfunctions/AppFunctionsUtil.kt
new file mode 100644
index 0000000000..cccf5cfd74
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/appfunctions/AppFunctionsUtil.kt
@@ -0,0 +1,71 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.permissioncontroller.appfunctions
+
+import android.content.Context
+import android.content.Intent
+import android.util.Log
+import com.android.permissioncontroller.permission.utils.Utils
+import java.util.UUID
+
+object AppFunctionsUtil {
+    const val ACTION_MANAGE_PERMISSIONS =
+        "com.android.permissioncontroller.devicestate.action.MANAGE_PERMISSIONS"
+
+    const val ACTION_MANAGE_PERMISSION_APPS =
+        "com.android.permissioncontroller.devicestate.action.MANAGE_PERMISSION_APPS"
+
+    const val ACTION_MANAGE_APP_PERMISSIONS =
+        "com.android.permissioncontroller.devicestate.action.MANAGE_APP_PERMISSIONS"
+
+    const val ACTION_MANAGE_APP_PERMISSION =
+        "com.android.permissioncontroller.devicestate.action.MANAGE_APP_PERMISSION"
+
+    const val ACTION_MANAGE_UNUSED_APPS =
+        "com.android.permissioncontroller.devicestate.action.MANAGE_UNUSED_APPS"
+
+    const val ACTION_ADDITIONAL_PERMISSIONS =
+        "com.android.permissioncontroller.devicestate.action.ADDITIONAL_PERMISSIONS"
+
+    const val LOG_TAG = "AppFunctionsUtil"
+    const val EXTRA_DEVICE_STATE_KEY = "com.android.permissioncontroller.devicestate.key"
+    const val DEVICE_STATE_PASSWORD_KEY = "device_state_password"
+    private val sPasswordLock: Any = Any()
+
+    @JvmStatic
+    fun isIntentValid(intent: Intent, context: Context): Boolean {
+        val passwordFromIntent = intent.getStringExtra(EXTRA_DEVICE_STATE_KEY) ?: return false
+        val password = getPasswordForIntent(context)
+        val valid = passwordFromIntent == password
+        if (!valid) {
+            Log.w(LOG_TAG, "Invalid password: $passwordFromIntent")
+        }
+        return valid
+    }
+
+    fun getPasswordForIntent(context: Context): String {
+        synchronized(sPasswordLock) {
+            val sharedPreferences = Utils.getDeviceProtectedSharedPreferences(context)
+            var password = sharedPreferences.getString(DEVICE_STATE_PASSWORD_KEY, null)
+            if (password == null) {
+                password = UUID.randomUUID().toString()
+                sharedPreferences.edit().putString(DEVICE_STATE_PASSWORD_KEY, password).apply()
+            }
+            return password
+        }
+    }
+}
diff --git a/PermissionController/src/com/android/permissioncontroller/appfunctions/DeviceStateScreens.kt b/PermissionController/src/com/android/permissioncontroller/appfunctions/DeviceStateScreens.kt
new file mode 100644
index 0000000000..d950c7f9b4
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/appfunctions/DeviceStateScreens.kt
@@ -0,0 +1,395 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.permissioncontroller.appfunctions
+
+import android.content.Context
+import android.content.Intent
+import android.content.pm.PackageManager
+import android.content.res.Resources
+import android.net.Uri
+import android.os.UserHandle
+import android.provider.Settings
+import com.android.permissioncontroller.R
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.ACTION_ADDITIONAL_PERMISSIONS
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.ACTION_MANAGE_APP_PERMISSION
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.ACTION_MANAGE_APP_PERMISSIONS
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.ACTION_MANAGE_PERMISSIONS
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.ACTION_MANAGE_PERMISSION_APPS
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.ACTION_MANAGE_UNUSED_APPS
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil.EXTRA_DEVICE_STATE_KEY
+import com.android.permissioncontroller.permission.model.livedatatypes.AppPermGroupUiInfo.PermGrantState
+import com.android.permissioncontroller.permission.ui.model.UnusedAppsViewModel.UnusedPeriod
+import com.android.permissioncontroller.permission.utils.KotlinUtils.getPermGroupLabel
+import com.android.permissioncontroller.permission.utils.Utils
+import com.google.android.appfunctions.schema.common.v1.devicestate.DeviceStateItem
+import com.google.android.appfunctions.schema.common.v1.devicestate.LocalizedString
+import com.google.android.appfunctions.schema.common.v1.devicestate.PerScreenDeviceStates
+
+abstract class PerScreenDeviceState(val context: Context) {
+    /** A unique key that identifies a screen. Used only internally */
+    abstract val key: String
+
+    /** Description of the screen. */
+    abstract val description: String
+
+    /** Path to the screen from Settings page, represented by a list of each page along the way */
+    abstract val paths: List<String>
+
+    /** Intent of the screen to be used by deeplinking */
+    abstract val intent: Intent
+
+    /** Intent Uri of the screen */
+    val intentUri: String
+        get() =
+            intent
+                .putExtra(EXTRA_DEVICE_STATE_KEY, AppFunctionsUtil.getPasswordForIntent(context))
+                .toUri(Intent.URI_INTENT_SCHEME)
+
+    open fun getDeviceStateItems(): List<DeviceStateItem> {
+        return emptyList()
+    }
+
+    fun toPerScreenDeviceStates(): PerScreenDeviceStates {
+        val localizedPaths = paths.map { LocalizedString(english = it) }
+
+        return PerScreenDeviceStates(
+            description = description,
+            paths = localizedPaths,
+            intentUri = intentUri,
+            deviceStateItems = getDeviceStateItems(),
+        )
+    }
+
+    companion object {
+        const val DEFAULT_PACKAGE_LABEL = "Unknown"
+    }
+}
+
+class PermissionManagerScreen(context: Context) : PerScreenDeviceState(context) {
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = DESCRIPTION
+
+    // TODO b/411229443 - Make paths customizable for OEMs
+    override val paths: List<String>
+        get() = listOf("Security & privacy", "Privacy controls", "Permission manager")
+
+    override val intent: Intent
+        get() = Intent(ACTION_MANAGE_PERMISSIONS)
+
+    companion object {
+        const val KEY = "permission_manager"
+        const val DESCRIPTION = "Permission Manager"
+    }
+}
+
+class PermissionAppsScreen(context: Context, val permissionGroup: String) :
+    PerScreenDeviceState(context) {
+    private val permissionGroupLabel: String =
+        getPermGroupLabel(context, permissionGroup).toString()
+
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = "Permission Manager: $permissionGroupLabel"
+
+    override val paths: List<String>
+        get() =
+            listOf(
+                "Security & privacy",
+                "Privacy controls",
+                "Permission manager",
+                permissionGroupLabel,
+            )
+
+    override val intent: Intent
+        get() =
+            Intent(ACTION_MANAGE_PERMISSION_APPS).apply {
+                putExtra(Intent.EXTRA_PERMISSION_GROUP_NAME, permissionGroup)
+            }
+
+    companion object {
+        const val KEY = "permission_apps"
+    }
+}
+
+class AppPermissionsScreen(context: Context, val packageName: String) :
+    PerScreenDeviceState(context) {
+
+    private var packageLabel: String
+
+    init {
+        val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
+        packageLabel = Utils.getFullAppLabel(appInfo, context)
+    }
+
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = "App Permissions: $packageLabel"
+
+    override val paths: List<String>
+        get() = listOf("Apps", packageLabel, "Permissions")
+
+    override val intent: Intent
+        get() =
+            Intent(ACTION_MANAGE_APP_PERMISSIONS).apply {
+                putExtra(Intent.EXTRA_PACKAGE_NAME, packageName)
+            }
+
+    companion object {
+        const val KEY = "app_permissions"
+    }
+}
+
+class AppPermissionScreen(
+    context: Context,
+    val permissionGroup: String,
+    val packageName: String,
+    val userHandle: UserHandle,
+    val permissionGrantState: PermGrantState,
+    val lastAccessTime: Long,
+    val usePreciseLocation: Boolean?,
+) : PerScreenDeviceState(context) {
+    private val permissionGroupLabel: String =
+        getPermGroupLabel(context, permissionGroup).toString()
+
+    private var packageLabel: String
+
+    init {
+        try {
+            val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
+            packageLabel = Utils.getFullAppLabel(appInfo, context)
+        } catch (e: PackageManager.NameNotFoundException) {
+            packageLabel = DEFAULT_PACKAGE_LABEL
+        }
+    }
+
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = "$permissionGroupLabel Permission: $packageLabel"
+
+    override val paths: List<String>
+        get() =
+            listOf(
+                "Security & privacy",
+                "Privacy controls",
+                "Permission manager",
+                permissionGroupLabel,
+                packageLabel,
+            )
+
+    override val intent: Intent
+        get() =
+            Intent(ACTION_MANAGE_APP_PERMISSION).apply {
+                putExtra(Intent.EXTRA_PERMISSION_GROUP_NAME, permissionGroup)
+                putExtra(Intent.EXTRA_PACKAGE_NAME, packageName)
+                putExtra(Intent.EXTRA_USER, userHandle)
+            }
+
+    override fun getDeviceStateItems(): List<DeviceStateItem> {
+        val result: MutableList<DeviceStateItem> = mutableListOf()
+        val permissionGroupLabel: String = getPermGroupLabel(context, permissionGroup).toString()
+        val permissionStateItem =
+            DeviceStateItem(
+                key = "${permissionGroupLabel.lowercase()}_permission_state",
+                name = LocalizedString(english = "$permissionGroupLabel access for this app"),
+                jsonValue = translatePermissionGrantState(),
+            )
+        result.add(permissionStateItem)
+
+        if (lastAccessTime > 0) {
+            val summaryTimestamp =
+                Utils.getPermissionLastAccessSummaryTimestamp(
+                    lastAccessTime,
+                    context,
+                    permissionGroup,
+                )
+            val recentAccessItem =
+                DeviceStateItem(
+                    key = "recent_access",
+                    name = LocalizedString(english = "Recent access"),
+                    jsonValue = getRecentAccessSummary(summaryTimestamp),
+                )
+            result.add(recentAccessItem)
+        }
+
+        if (usePreciseLocation != null) {
+            val usePreciseLocation =
+                DeviceStateItem(
+                    key = "use_precise_location",
+                    name = LocalizedString(english = "Use precise location"),
+                    jsonValue = usePreciseLocation.toString(),
+                )
+            result.add(usePreciseLocation)
+        }
+
+        return result
+    }
+
+    private fun translatePermissionGrantState(): String {
+        return when (permissionGrantState) {
+            PermGrantState.PERMS_DENIED -> "Not Allowed"
+            PermGrantState.PERMS_ALLOWED -> "Allowed"
+            PermGrantState.PERMS_ALLOWED_FOREGROUND_ONLY -> "Allowed while using the app"
+            PermGrantState.PERMS_ALLOWED_ALWAYS -> "Always Allowed"
+            PermGrantState.PERMS_ASK -> "Ask every time"
+        }
+    }
+
+    private fun getRecentAccessSummary(summaryTimestamp: Triple<String, Int, String>): String {
+        val res: Resources = context.resources
+
+        return when (summaryTimestamp.second) {
+            Utils.LAST_24H_CONTENT_PROVIDER ->
+                res.getString(R.string.app_perms_content_provider_24h)
+            Utils.LAST_7D_CONTENT_PROVIDER -> res.getString(R.string.app_perms_content_provider_7d)
+            Utils.LAST_24H_SENSOR_TODAY ->
+                res.getString(R.string.app_perms_24h_access, summaryTimestamp.first)
+            Utils.LAST_24H_SENSOR_YESTERDAY ->
+                res.getString(R.string.app_perms_24h_access_yest, summaryTimestamp.first)
+            Utils.LAST_7D_SENSOR ->
+                res.getString(
+                    R.string.app_perms_7d_access,
+                    summaryTimestamp.third,
+                    summaryTimestamp.first,
+                )
+            else -> ""
+        }
+    }
+
+    companion object {
+        const val KEY = "app_permission"
+    }
+}
+
+class UnusedAppsScreen(context: Context) : PerScreenDeviceState(context) {
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = DESCRIPTION
+
+    override val paths: List<String>
+        get() = listOf("Apps", "Unused apps")
+
+    override val intent: Intent
+        get() = Intent(ACTION_MANAGE_UNUSED_APPS)
+
+    companion object {
+        const val KEY = "unused_apps"
+        const val DESCRIPTION = "Unused apps"
+    }
+}
+
+class UnusedAppLastUsageScreen(
+    context: Context,
+    val packageName: String,
+    private val lastUsageTime: Long,
+) : PerScreenDeviceState(context) {
+    private var packageLabel: String
+
+    init {
+        try {
+            val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
+            packageLabel = Utils.getFullAppLabel(appInfo, context)
+        } catch (e: PackageManager.NameNotFoundException) {
+            packageLabel = DEFAULT_PACKAGE_LABEL
+        }
+    }
+
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = "Unused app details: $packageLabel"
+
+    override val paths: List<String>
+        get() = listOf("Apps", "Unused apps", packageLabel)
+
+    override val intent: Intent
+        get() =
+            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
+                setData(Uri.fromParts("package", packageName, null))
+            }
+
+    override fun getDeviceStateItems(): List<DeviceStateItem> {
+        val usagePeriod = UnusedPeriod.findLongestValidPeriod(lastUsageTime)
+
+        val lastUsed =
+            DeviceStateItem(
+                key = "last_used",
+                name = LocalizedString(english = "Last used"),
+                jsonValue = translateUnusedPeriod(usagePeriod),
+            )
+        return listOf(lastUsed)
+    }
+
+    private fun translateUnusedPeriod(usagePeriod: UnusedPeriod): String {
+        return when (usagePeriod) {
+            UnusedPeriod.ONE_MONTH -> "1 month ago"
+            UnusedPeriod.THREE_MONTHS -> "3 months ago"
+            UnusedPeriod.SIX_MONTHS -> "6 months ago"
+        }
+    }
+
+    companion object {
+        const val KEY = "unused_app_last_usage"
+    }
+}
+
+class AdditionalPermissionsScreen(context: Context) : PerScreenDeviceState(context) {
+    override val key: String
+        get() = KEY
+
+    override val description: String
+        get() = DESCRIPTION
+
+    override val paths: List<String>
+        get() =
+            listOf(
+                "Security & privacy",
+                "Privacy controls",
+                "Permission manager",
+                "Additional permissions",
+            )
+
+    override val intent: Intent
+        get() = Intent(ACTION_ADDITIONAL_PERMISSIONS)
+
+    companion object {
+        const val KEY = "additional_permissions"
+        const val DESCRIPTION = "Additional Permissions"
+    }
+}
+
+val deviceStateScreenKeys: List<String> =
+    listOf(
+        PermissionManagerScreen.KEY,
+        PermissionAppsScreen.KEY,
+        AppPermissionsScreen.KEY,
+        AppPermissionScreen.KEY,
+        UnusedAppsScreen.KEY,
+        UnusedAppLastUsageScreen.KEY,
+        AdditionalPermissionsScreen.KEY,
+    )
diff --git a/PermissionController/src/com/android/permissioncontroller/appfunctions/GenericDocumentToPlatformConverter.kt b/PermissionController/src/com/android/permissioncontroller/appfunctions/GenericDocumentToPlatformConverter.kt
new file mode 100644
index 0000000000..2feee96546
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/appfunctions/GenericDocumentToPlatformConverter.kt
@@ -0,0 +1,103 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.permissioncontroller.appfunctions
+
+import android.os.Build
+import androidx.appsearch.app.EmbeddingVector
+import androidx.appsearch.app.Features
+import androidx.appsearch.app.GenericDocument
+import java.util.Objects
+
+object GenericDocumentToPlatformConverter {
+    /** Translates a jetpack [androidx.appsearch.app.GenericDocument] into a platform [ ]. */
+    @Suppress("UNCHECKED_CAST")
+    fun toPlatformGenericDocument(
+        jetpackDocument: GenericDocument
+    ): android.app.appsearch.GenericDocument {
+        Objects.requireNonNull(jetpackDocument)
+        val platformBuilder =
+            android.app.appsearch.GenericDocument.Builder<
+                android.app.appsearch.GenericDocument.Builder<*>
+            >(
+                jetpackDocument.namespace,
+                jetpackDocument.id,
+                jetpackDocument.schemaType,
+            )
+        platformBuilder
+            .setScore(jetpackDocument.score)
+            .setTtlMillis(jetpackDocument.ttlMillis)
+            .setCreationTimestampMillis(jetpackDocument.creationTimestampMillis)
+        for (propertyName in jetpackDocument.propertyNames) {
+            val property = jetpackDocument.getProperty(propertyName!!)
+            if (property is Array<*> && property.isArrayOf<String>()) {
+                platformBuilder.setPropertyString(propertyName, *property as Array<String?>)
+            } else if (property is LongArray) {
+                platformBuilder.setPropertyLong(propertyName, *property)
+            } else if (property is DoubleArray) {
+                platformBuilder.setPropertyDouble(propertyName, *property)
+            } else if (property is BooleanArray) {
+                platformBuilder.setPropertyBoolean(propertyName, *property)
+            } else if (property is Array<*> && property.isArrayOf<ByteArray>()) {
+                val byteValues = property
+                // This is a patch for b/204677124, framework-appsearch in Android S and S_V2 will
+                // crash if the user put a document with empty byte[][] or document[].
+                if (
+                    (Build.VERSION.SDK_INT == Build.VERSION_CODES.S ||
+                        Build.VERSION.SDK_INT == Build.VERSION_CODES.S_V2) && byteValues.size == 0
+                ) {
+                    continue
+                }
+                platformBuilder.setPropertyBytes(propertyName, *byteValues as Array<out ByteArray>)
+            } else if (property is Array<*> && property.isArrayOf<GenericDocument>()) {
+                val documentValues = property
+                // This is a patch for b/204677124, framework-appsearch in Android S and S_V2 will
+                // crash if the user put a document with empty byte[][] or document[].
+                if (
+                    (Build.VERSION.SDK_INT == Build.VERSION_CODES.S ||
+                        Build.VERSION.SDK_INT == Build.VERSION_CODES.S_V2) &&
+                        documentValues.size == 0
+                ) {
+                    continue
+                }
+                val platformSubDocuments =
+                    arrayOfNulls<android.app.appsearch.GenericDocument>(documentValues.size)
+                for (j in documentValues.indices) {
+                    platformSubDocuments[j] =
+                        GenericDocumentToPlatformConverter.toPlatformGenericDocument(
+                            documentValues[j] as GenericDocument
+                        )
+                }
+                platformBuilder.setPropertyDocument(propertyName, *platformSubDocuments)
+            } else if (property is Array<*> && property.isArrayOf<EmbeddingVector>()) {
+                // TODO(b/326656531): Remove this once embedding search APIs are available.
+                throw UnsupportedOperationException(
+                    Features.SCHEMA_EMBEDDING_PROPERTY_CONFIG +
+                        " is not available on this AppSearch implementation."
+                )
+            } else {
+                throw IllegalStateException(
+                    String.format(
+                        "Property \"%s\" has unsupported value type %s",
+                        propertyName,
+                        property!!.javaClass.toString(),
+                    )
+                )
+            }
+        }
+        return platformBuilder.build()
+    }
+}
diff --git a/PermissionController/src/com/android/permissioncontroller/ecm/EnhancedConfirmationDialogActivity.kt b/PermissionController/src/com/android/permissioncontroller/ecm/EnhancedConfirmationDialogActivity.kt
index c5191938ed..145dc5563d 100644
--- a/PermissionController/src/com/android/permissioncontroller/ecm/EnhancedConfirmationDialogActivity.kt
+++ b/PermissionController/src/com/android/permissioncontroller/ecm/EnhancedConfirmationDialogActivity.kt
@@ -49,10 +49,13 @@ import com.android.permissioncontroller.permission.utils.KotlinUtils
 import com.android.permissioncontroller.permission.utils.PermissionMapping
 import com.android.permissioncontroller.permission.utils.Utils
 import com.android.role.controller.model.Roles
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider
+import com.android.settingslib.widget.SettingsThemeHelper
+import com.android.settingslib.widget.theme.flags.Flags as SettingsLibFlags
 
 @Keep
 @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
-class EnhancedConfirmationDialogActivity : FragmentActivity() {
+class EnhancedConfirmationDialogActivity : FragmentActivity(), ExpressiveDesignEnabledProvider {
     companion object {
         private const val KEY_WAS_CLEAR_RESTRICTION_ALLOWED = "KEY_WAS_CLEAR_RESTRICTION_ALLOWED"
         private const val REASON_PHONE_STATE = "phone_state"
@@ -96,6 +99,12 @@ class EnhancedConfirmationDialogActivity : FragmentActivity() {
             return
         }
 
+        if (SettingsThemeHelper.isExpressiveTheme(this)) {
+            setTheme(R.style.Theme_EnhancedConfirmationDialogActivityExpressive_FilterTouches)
+        } else {
+            setTheme(R.style.Theme_EnhancedConfirmationDialog_FilterTouches)
+        }
+
         if (DeviceUtils.isWear(this)) {
             WearEnhancedConfirmationDialogFragment.newInstance(setting.title, setting.message)
                 .show(supportFragmentManager, WearEnhancedConfirmationDialogFragment.TAG)
@@ -248,6 +257,14 @@ class EnhancedConfirmationDialogActivity : FragmentActivity() {
         }
     }
 
+    override fun isExpressiveDesignEnabled(): Boolean {
+        return SdkLevel.isAtLeastB() &&
+            DeviceUtils.isHandheld() &&
+            SettingsLibFlags.isExpressiveDesignEnabled() &&
+            getResources()
+                .getBoolean(R.bool.config_enableExpressiveDesignInEnhancedConfirmationDialog)
+    }
+
     class EnhancedConfirmationDialogFragment() : DialogFragment() {
         companion object {
             val TAG = EnhancedConfirmationDialogFragment::class.simpleName
@@ -295,7 +312,14 @@ class EnhancedConfirmationDialogActivity : FragmentActivity() {
             message: CharSequence?,
         ): View =
             LayoutInflater.from(context)
-                .inflate(R.layout.enhanced_confirmation_dialog, null)
+                .inflate(
+                    if (SettingsThemeHelper.isExpressiveTheme(dialogActivity)) {
+                        R.layout.enhanced_confirmation_dialog_expressive
+                    } else {
+                        R.layout.enhanced_confirmation_dialog
+                    },
+                    null,
+                )
                 .apply {
                     title?.let {
                         requireViewById<TextView>(R.id.enhanced_confirmation_dialog_title).text = it
diff --git a/PermissionController/src/com/android/permissioncontroller/hibernation/HibernationPolicy.kt b/PermissionController/src/com/android/permissioncontroller/hibernation/HibernationPolicy.kt
index 8b11036e89..21e21140ab 100644
--- a/PermissionController/src/com/android/permissioncontroller/hibernation/HibernationPolicy.kt
+++ b/PermissionController/src/com/android/permissioncontroller/hibernation/HibernationPolicy.kt
@@ -38,7 +38,6 @@ import android.app.job.JobScheduler
 import android.app.job.JobService
 import android.app.role.RoleManager
 import android.app.usage.UsageStats
-import android.app.usage.UsageStatsManager.INTERVAL_DAILY
 import android.app.usage.UsageStatsManager.INTERVAL_MONTHLY
 import android.content.BroadcastReceiver
 import android.content.ComponentName
@@ -62,6 +61,7 @@ import android.printservice.PrintService
 import android.provider.DeviceConfig
 import android.provider.DeviceConfig.NAMESPACE_APP_HIBERNATION
 import android.provider.Settings
+import android.provider.Settings.Global.DEVICE_DEMO_MODE
 import android.provider.Settings.Secure.USER_SETUP_COMPLETE
 import android.safetycenter.SafetyCenterManager
 import android.safetycenter.SafetyEvent
@@ -119,23 +119,17 @@ import java.util.Random
 import java.util.concurrent.TimeUnit
 
 private const val LOG_TAG = "HibernationPolicy"
-const val DEBUG_OVERRIDE_THRESHOLDS = false
-const val DEBUG_HIBERNATION_POLICY = false
 
 private var SKIP_NEXT_RUN = false
 
 private val DEFAULT_UNUSED_THRESHOLD_MS = TimeUnit.DAYS.toMillis(90)
 
 fun getUnusedThresholdMs() =
-    when {
-        DEBUG_OVERRIDE_THRESHOLDS -> TimeUnit.SECONDS.toMillis(1)
-        else ->
-            DeviceConfig.getLong(
-                DeviceConfig.NAMESPACE_PERMISSIONS,
-                Utils.PROPERTY_HIBERNATION_UNUSED_THRESHOLD_MILLIS,
-                DEFAULT_UNUSED_THRESHOLD_MS
-            )
-    }
+    DeviceConfig.getLong(
+        DeviceConfig.NAMESPACE_PERMISSIONS,
+        Utils.PROPERTY_HIBERNATION_UNUSED_THRESHOLD_MILLIS,
+        DEFAULT_UNUSED_THRESHOLD_MS
+    )
 
 private val DEFAULT_CHECK_FREQUENCY_MS = TimeUnit.DAYS.toMillis(15)
 
@@ -281,6 +275,10 @@ class HibernationBroadcastReceiver : BroadcastReceiver() {
         val action = intent.action
         val contentResolver = context.contentResolver
         if (action == Intent.ACTION_BOOT_COMPLETED || action == ACTION_SET_UP_HIBERNATION) {
+            if (Settings.Global.getInt(contentResolver, DEVICE_DEMO_MODE, 0) != 0) {
+                DumpableLog.i(LOG_TAG, "Not scheduling hibernation job. Device is retail mode")
+                return
+            }
             if (isUserSetupComplete(contentResolver)) {
                 maybeInitStartTimeUnusedAppTracking(context.sharedPreferences)
             } else {
@@ -297,12 +295,20 @@ class HibernationBroadcastReceiver : BroadcastReceiver() {
                                 && isUserSetupComplete(contentResolver)) {
                                 contentResolver.unregisterContentObserver(this)
                                 maybeInitStartTimeUnusedAppTracking(context.sharedPreferences)
+
+                                // Retail mode is set during set-up wizard so we need to check
+                                // after if the job should actually be scheduled
+                                if (Settings.Global.getInt(contentResolver, DEVICE_DEMO_MODE, 0)
+                                    != 0) {
+                                    context.getSystemService(JobScheduler::class.java)!!.cancel(
+                                        Constants.HIBERNATION_JOB_ID)
+                                }
                             }
                         }
                     }
                 )
             }
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(
                     LOG_TAG,
                     "scheduleHibernationJob " +
@@ -316,7 +322,7 @@ class HibernationBroadcastReceiver : BroadcastReceiver() {
             // If this user is a profile, then its hibernation/auto-revoke will be handled by the
             // primary user
             if (isProfile(context)) {
-                if (DEBUG_HIBERNATION_POLICY) {
+                if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                     DumpableLog.i(
                         LOG_TAG,
                         "user ${Process.myUserHandle().identifier} is a profile." +
@@ -324,7 +330,7 @@ class HibernationBroadcastReceiver : BroadcastReceiver() {
                     )
                 }
                 return
-            } else if (DEBUG_HIBERNATION_POLICY) {
+            } else if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(
                     LOG_TAG,
                     "user ${Process.myUserHandle().identifier} is a profile" +
@@ -381,17 +387,17 @@ class HibernationBroadcastReceiver : BroadcastReceiver() {
                 .getSystemService(JobScheduler::class.java)!!
                 .getPendingJob(Constants.HIBERNATION_JOB_ID)
         if (existingJob == null) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "No existing job, scheduling a new one")
             }
             scheduleNewJob = true
         } else if (existingJob.intervalMillis != getCheckFrequencyMs()) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Interval frequency has changed, updating job")
             }
             scheduleNewJob = true
         } else {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Job already scheduled.")
             }
         }
@@ -419,10 +425,10 @@ private suspend fun getAppsToHibernate(
     val userStats =
         UsageStatsLiveData[
                 getUnusedThresholdMs(),
-                if (DEBUG_OVERRIDE_THRESHOLDS) INTERVAL_DAILY else INTERVAL_MONTHLY]
+                INTERVAL_MONTHLY]
             .getInitializedValue()
             ?: emptyMap()
-    if (DEBUG_HIBERNATION_POLICY) {
+    if (Log.isLoggable(LOG_TAG, Log.INFO)) {
         for ((user, stats) in userStats) {
             DumpableLog.i(
                 LOG_TAG,
@@ -435,7 +441,7 @@ private suspend fun getAppsToHibernate(
     }
     for (user in unusedApps.keys.toList()) {
         if (user !in userStats.keys) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Ignoring user ${user.identifier}")
             }
             unusedApps.remove(user)
@@ -485,7 +491,7 @@ private suspend fun getAppsToHibernate(
             }
 
         unusedApps[user] = unusedUserApps
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(
                 LOG_TAG,
                 "Unused apps for user ${user.identifier}: " +
@@ -526,7 +532,7 @@ private suspend fun getAppsToHibernate(
                 return@forEachInParallel
             }
 
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(
                     LOG_TAG,
                     "unused app $packageName - last used on " +
@@ -576,17 +582,24 @@ suspend fun isPackageHibernationExemptBySystem(
 ): Boolean {
     val launcherPkgs = LauncherPackagesLiveData.getInitializedValue() ?: emptyList()
     if (!launcherPkgs.contains(pkg.packageName)) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - Package is not on launcher")
         }
         return true
     }
     val exemptServicePkgs = ExemptServicesLiveData[user].getInitializedValue() ?: emptyMap()
     if (!exemptServicePkgs[pkg.packageName].isNullOrEmpty()) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
+            DumpableLog.i(
+                LOG_TAG,
+                "Exempted ${pkg.packageName} - Has exempt components:" +
+                        "${exemptServicePkgs[pkg.packageName]?.joinToString()}",
+            )
+        }
         return true
     }
     if (Utils.isUserDisabledOrWorkProfile(user)) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(
                 LOG_TAG,
                 "Exempted ${pkg.packageName} - $user is disabled or a work profile"
@@ -596,7 +609,7 @@ suspend fun isPackageHibernationExemptBySystem(
     }
 
     if (pkg.uid == Process.SYSTEM_UID) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - Package shares system uid")
         }
         return true
@@ -608,7 +621,7 @@ suspend fun isPackageHibernationExemptBySystem(
         val isFinancedDevice =
             Settings.Global.getInt(context.contentResolver, "device_owner_type", 0) == 1
         if (!isFinancedDevice) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - device is managed")
             }
             return true
@@ -627,7 +640,7 @@ suspend fun isPackageHibernationExemptBySystem(
         )
     }
     if (carrierPrivilegedStatus == CARRIER_PRIVILEGE_STATUS_HAS_ACCESS) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - carrier privileged")
         }
         return true
@@ -639,7 +652,7 @@ suspend fun isPackageHibernationExemptBySystem(
             .checkPermission(Manifest.permission.READ_PRIVILEGED_PHONE_STATE, pkg.packageName) ==
             PERMISSION_GRANTED
     ) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(
                 LOG_TAG,
                 "Exempted ${pkg.packageName} " + "- holder of READ_PRIVILEGED_PHONE_STATE"
@@ -653,7 +666,7 @@ suspend fun isPackageHibernationExemptBySystem(
             .getSystemService(android.app.role.RoleManager::class.java)!!
             .getRoleHolders(RoleManager.ROLE_EMERGENCY)
     if (emergencyRoleHolders.contains(pkg.packageName)) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - emergency app")
         }
         return true
@@ -679,7 +692,7 @@ suspend fun isPackageHibernationExemptBySystem(
             }
         }
         if (hasRegisteredPhoneAccount) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(
                         LOG_TAG,
                         "Exempted ${pkg.packageName} - caller app"
@@ -708,7 +721,7 @@ suspend fun isPackageHibernationExemptBySystem(
         // Grant if app w/ privileged install/update permissions or app is an installer app that
         // updates packages without user action.
         if (hasInstallOrUpdatePermissions || isInstallerOfRecord) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - installer app")
             }
             return true
@@ -719,7 +732,7 @@ suspend fun isPackageHibernationExemptBySystem(
                 .getSystemService(android.app.role.RoleManager::class.java)!!
                 .getRoleHolders(RoleManager.ROLE_SYSTEM_WELLBEING)
         if (roleHolders.contains(pkg.packageName)) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - wellbeing app")
             }
             return true
@@ -732,7 +745,7 @@ suspend fun isPackageHibernationExemptBySystem(
                 .getSystemService(android.app.role.RoleManager::class.java)!!
                 .getRoleHolders(RoleManager.ROLE_DEVICE_POLICY_MANAGEMENT)
         if (roleHolders.contains(pkg.packageName)) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Exempted ${pkg.packageName} - device policy manager app")
             }
             return true
@@ -745,7 +758,7 @@ suspend fun isPackageHibernationExemptBySystem(
                     pkg.packageName, AppOpsManager.OPSTR_SYSTEM_EXEMPT_FROM_HIBERNATION, pkg.uid]
                 .getInitializedValue() == AppOpsManager.MODE_ALLOWED
     ) {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(
                 LOG_TAG,
                 "Exempted ${pkg.packageName} - has OP_SYSTEM_EXEMPT_FROM_HIBERNATION"
@@ -774,10 +787,6 @@ suspend fun isPackageHibernationExemptByUser(
             .getInitializedValue()
     if (allowlistAppOpMode == AppOpsManager.MODE_DEFAULT) {
         // Initial state - allowlist not explicitly overridden by either user or installer
-        if (DEBUG_OVERRIDE_THRESHOLDS) {
-            // Suppress exemptions to allow debugging
-            return false
-        }
 
         if (hibernationTargetsPreSApps()) {
             // Default on if overridden
@@ -967,12 +976,12 @@ class HibernationJobService : JobService() {
     var jobStartTime: Long = -1L
 
     override fun onStartJob(params: JobParameters?): Boolean {
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(LOG_TAG, "onStartJob")
         }
 
         if (!isUserSetupComplete(contentResolver)) {
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Skipping hibernation job because set-up is not complete")
             }
             jobFinished(params, /* wantsReschedule= */ true)
@@ -983,7 +992,7 @@ class HibernationJobService : JobService() {
 
         if (SKIP_NEXT_RUN) {
             SKIP_NEXT_RUN = false
-            if (DEBUG_HIBERNATION_POLICY) {
+            if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                 DumpableLog.i(LOG_TAG, "Skipping auto revoke first run when scheduled by system")
             }
             jobFinished(params, false)
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/data/BroadcastReceiverLiveData.kt b/PermissionController/src/com/android/permissioncontroller/permission/data/BroadcastReceiverLiveData.kt
index e14a02115e..06779ba4af 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/data/BroadcastReceiverLiveData.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/data/BroadcastReceiverLiveData.kt
@@ -22,9 +22,9 @@ import android.app.admin.DeviceAdminReceiver
 import android.content.Intent
 import android.content.pm.PackageManager
 import android.os.UserHandle
+import android.util.Log
 import com.android.permissioncontroller.DumpableLog
 import com.android.permissioncontroller.PermissionControllerApplication
-import com.android.permissioncontroller.hibernation.DEBUG_HIBERNATION_POLICY
 import com.android.permissioncontroller.permission.utils.Utils.getUserContext
 import kotlinx.coroutines.Job
 
@@ -84,7 +84,7 @@ class BroadcastReceiverLiveData(
                     }
                     val packageName = resolveInfo.activityInfo?.packageName
                     if (!isReceiverEnabled(packageName)) {
-                        if (DEBUG_HIBERNATION_POLICY) {
+                        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                             DumpableLog.i(
                                 LOG_TAG,
                                 "Not exempting $packageName - not an active $name " +
@@ -96,7 +96,7 @@ class BroadcastReceiverLiveData(
                     packageName
                 }
                 .toSet()
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(
                 LOG_TAG,
                 "Detected ${intentAction.substringAfterLast(".")}s: $packageNames"
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/data/ServiceLiveData.kt b/PermissionController/src/com/android/permissioncontroller/permission/data/ServiceLiveData.kt
index 2deae79cc5..971b6fe6f4 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/data/ServiceLiveData.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/data/ServiceLiveData.kt
@@ -29,10 +29,10 @@ import android.service.dreams.DreamService
 import android.service.notification.NotificationListenerService
 import android.service.voice.VoiceInteractionService
 import android.service.wallpaper.WallpaperService
+import android.util.Log
 import android.view.inputmethod.InputMethod
 import com.android.permissioncontroller.DumpableLog
 import com.android.permissioncontroller.PermissionControllerApplication
-import com.android.permissioncontroller.hibernation.DEBUG_HIBERNATION_POLICY
 import com.android.permissioncontroller.permission.utils.Utils.getUserContext
 import kotlinx.coroutines.Job
 
@@ -174,7 +174,7 @@ class ServiceLiveData(
                     }
                     val packageName = resolveInfo.serviceInfo?.packageName
                     if (!isServiceEnabled(packageName)) {
-                        if (DEBUG_HIBERNATION_POLICY) {
+                        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
                             DumpableLog.i(
                                 LOG_TAG,
                                 "Not exempting $packageName - not an active $name " +
@@ -186,7 +186,7 @@ class ServiceLiveData(
                     packageName
                 }
                 .toSet()
-        if (DEBUG_HIBERNATION_POLICY) {
+        if (Log.isLoggable(LOG_TAG, Log.INFO)) {
             DumpableLog.i(LOG_TAG, "Detected ${name}s: $packageNames")
         }
 
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/model/AppPermissionGroup.java b/PermissionController/src/com/android/permissioncontroller/permission/model/AppPermissionGroup.java
index 3b2cc7ee0d..f6c98da9ef 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/model/AppPermissionGroup.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/model/AppPermissionGroup.java
@@ -23,12 +23,15 @@ import static android.app.AppOpsManager.MODE_ALLOWED;
 import static android.app.AppOpsManager.MODE_FOREGROUND;
 import static android.app.AppOpsManager.MODE_IGNORED;
 import static android.app.AppOpsManager.OPSTR_LEGACY_STORAGE;
+import static android.content.pm.PackageManager.FLAG_PERMISSION_ONE_TIME;
+import static android.content.pm.PackageManager.FLAG_PERMISSION_REVOKED_COMPAT;
 import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 import static android.health.connect.HealthPermissions.HEALTH_PERMISSION_GROUP;
 
 import static com.android.permissioncontroller.permission.utils.Utils.isHealthPermissionUiEnabled;
 
 import android.Manifest;
+import android.annotation.SuppressLint;
 import android.app.ActivityManager;
 import android.app.AppOpsManager;
 import android.app.Application;
@@ -1662,12 +1665,36 @@ public final class AppPermissionGroup implements Comparable<AppPermissionGroup>
             } finally {
                 Binder.restoreCallingIdentity(token);
             }
-        } else {
+        } else if (!anyPermsOfPackageOneTimeGranted(getApp())) {
+            // Stop the session only when no permission in the package is granted as one time.
             mContext.getSystemService(PermissionManager.class)
                     .stopOneTimePermissionSession(packageName);
         }
     }
 
+    @SuppressLint("MissingPermission")
+    private boolean anyPermsOfPackageOneTimeGranted(PackageInfo packageInfo) {
+        if (packageInfo.requestedPermissions == null
+                || packageInfo.requestedPermissionsFlags == null) {
+            return false;
+        }
+
+        for (int i = 0; i < packageInfo.requestedPermissions.length; i++) {
+            if ((packageInfo.requestedPermissionsFlags[i] &
+                    PackageInfo.REQUESTED_PERMISSION_GRANTED) == 0) {
+                continue;
+            }
+            int flags = mPackageManager.getPermissionFlags(
+                    packageInfo.requestedPermissions[i], packageInfo.packageName, getUser());
+            boolean isGrantedOneTime = (flags & FLAG_PERMISSION_REVOKED_COMPAT) == 0 &&
+                    (flags & FLAG_PERMISSION_ONE_TIME) != 0;
+            if (isGrantedOneTime) {
+                return true;
+            }
+        }
+        return false;
+    }
+
     /**
      * Check if permission group contains a runtime permission that split from an installed
      * permission and the split happened in an Android version higher than app's targetSdk.
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/model/v31/AppPermissionUsage.java b/PermissionController/src/com/android/permissioncontroller/permission/model/v31/AppPermissionUsage.java
index b7cddace26..c883c6fa50 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/model/v31/AppPermissionUsage.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/model/v31/AppPermissionUsage.java
@@ -45,6 +45,8 @@ import com.android.permissioncontroller.permission.model.AppPermissionGroup;
 import com.android.permissioncontroller.permission.model.Permission;
 import com.android.permissioncontroller.permission.model.legacy.PermissionApps.PermissionApp;
 
+import kotlin.Triple;
+
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -54,8 +56,6 @@ import java.util.Set;
 import java.util.function.Function;
 import java.util.stream.Collectors;
 
-import kotlin.Triple;
-
 /**
  * Stats for permission usage of an app. This data is for a given time period,
  * i.e. does not contain the full history.
@@ -115,16 +115,6 @@ public final class AppPermissionUsage {
         return mPermissionApp.getUid();
     }
 
-    public long getLastAccessTime() {
-        long lastAccessTime = 0;
-        final int permissionCount = mGroupUsages.size();
-        for (int i = 0; i < permissionCount; i++) {
-            final GroupUsage groupUsage = mGroupUsages.get(i);
-            lastAccessTime = Math.max(lastAccessTime, groupUsage.getLastAccessTime());
-        }
-        return lastAccessTime;
-    }
-
     public @NonNull List<GroupUsage> getGroupUsages() {
         return mGroupUsages;
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/model/v31/PermissionUsages.java b/PermissionController/src/com/android/permissioncontroller/permission/model/v31/PermissionUsages.java
index 03c9ce584e..cedc7305fc 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/model/v31/PermissionUsages.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/model/v31/PermissionUsages.java
@@ -64,6 +64,7 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
+import java.util.Objects;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicReference;
@@ -114,11 +115,11 @@ public final class PermissionUsages implements LoaderCallbacks<List<AppPermissio
 
     /**
      * Start the {@link Loader} to load the permission usages in the background. Loads without a uid
-     * filter.
+     * filter. A loaderManager is required when loading asynchronously
      */
     public void load(@Nullable String filterPackageName,
             @Nullable String[] filterPermissionGroups, long filterBeginTimeMillis,
-            long filterEndTimeMillis, int usageFlags, @NonNull LoaderManager loaderManager,
+            long filterEndTimeMillis, int usageFlags, @Nullable LoaderManager loaderManager,
             boolean getUiInfo, boolean getNonPlatformPermissions,
             @NonNull PermissionsUsagesChangeCallback callback, boolean sync) {
         load(Process.INVALID_UID, filterPackageName, filterPermissionGroups, filterBeginTimeMillis,
@@ -128,11 +129,12 @@ public final class PermissionUsages implements LoaderCallbacks<List<AppPermissio
 
     /**
      * Start the {@link Loader} to load the permission usages in the background. Loads only
-     * permissions for the specified {@code filterUid}.
+     * permissions for the specified {@code filterUid}. A loaderManager is required when loading
+     * asynchronously.
      */
     public void load(int filterUid, @Nullable String filterPackageName,
             @Nullable String[] filterPermissionGroups, long filterBeginTimeMillis,
-            long filterEndTimeMillis, int usageFlags, @NonNull LoaderManager loaderManager,
+            long filterEndTimeMillis, int usageFlags, @Nullable LoaderManager loaderManager,
             boolean getUiInfo, boolean getNonPlatformPermissions,
             @NonNull PermissionsUsagesChangeCallback callback, boolean sync) {
         mCallback = callback;
@@ -150,6 +152,7 @@ public final class PermissionUsages implements LoaderCallbacks<List<AppPermissio
             final List<AppPermissionUsage> usages = loader.loadInBackground();
             onLoadFinished(loader, usages);
         } else {
+            Objects.requireNonNull(loaderManager);
             loaderManager.restartLoader(1, args, this);
         }
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/service/BackupHelper.java b/PermissionController/src/com/android/permissioncontroller/permission/service/BackupHelper.java
index 2fa809c6d9..41f8554f75 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/service/BackupHelper.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/service/BackupHelper.java
@@ -68,6 +68,7 @@ import java.security.NoSuchAlgorithmException;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
+import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Set;
 
@@ -738,8 +739,8 @@ public class BackupHelper {
         @NonNull
         static BackupSigningInfoState parseFromXml(@NonNull XmlPullParser parser)
                 throws IOException, XmlPullParserException {
-            Set<byte[]> currentCertDigests = new HashSet<>();
-            Set<byte[]> pastCertDigests = new HashSet<>();
+            Set<byte[]> currentCertDigests = new LinkedHashSet<>();
+            Set<byte[]> pastCertDigests = new LinkedHashSet<>();
 
             while (true) {
                 switch (parser.next()) {
@@ -794,8 +795,8 @@ public class BackupHelper {
          */
         @NonNull
         static BackupSigningInfoState fromSigningInfo(@NonNull SigningInfo signingInfo) {
-            Set<byte[]> currentCertDigests = new HashSet<>();
-            Set<byte[]> pastCertDigests = new HashSet<>();
+            Set<byte[]> currentCertDigests = new LinkedHashSet<>();
+            Set<byte[]> pastCertDigests = new LinkedHashSet<>();
 
             Signature[] apkContentsSigners = signingInfo.getApkContentsSigners();
             for (int i = 0; i < apkContentsSigners.length; i++) {
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/service/DeviceStateAppFunctionService.kt b/PermissionController/src/com/android/permissioncontroller/permission/service/DeviceStateAppFunctionService.kt
new file mode 100644
index 0000000000..6a6bb34904
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/permission/service/DeviceStateAppFunctionService.kt
@@ -0,0 +1,407 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.permissioncontroller.permission.service
+
+import android.Manifest
+import android.Manifest.permission.ACCESS_COARSE_LOCATION
+import android.Manifest.permission.ACCESS_FINE_LOCATION
+import android.app.appfunctions.AppFunctionException
+import android.app.appfunctions.AppFunctionException.ERROR_FUNCTION_NOT_FOUND
+import android.app.appfunctions.AppFunctionService
+import android.app.appfunctions.ExecuteAppFunctionRequest
+import android.app.appfunctions.ExecuteAppFunctionResponse
+import android.app.appsearch.GenericDocument
+import android.app.usage.UsageStats
+import android.content.Context
+import android.content.pm.SigningInfo
+import android.content.res.Configuration
+import android.os.Build
+import android.os.CancellationSignal
+import android.os.OutcomeReceiver
+import android.os.UserHandle
+import androidx.annotation.RequiresApi
+import com.android.permissioncontroller.appfunctions.AdditionalPermissionsScreen
+import com.android.permissioncontroller.appfunctions.AppPermissionScreen
+import com.android.permissioncontroller.appfunctions.AppPermissionsScreen
+import com.android.permissioncontroller.appfunctions.GenericDocumentToPlatformConverter
+import com.android.permissioncontroller.appfunctions.PermissionAppsScreen
+import com.android.permissioncontroller.appfunctions.PermissionManagerScreen
+import com.android.permissioncontroller.appfunctions.UnusedAppLastUsageScreen
+import com.android.permissioncontroller.appfunctions.UnusedAppsScreen
+import com.android.permissioncontroller.appfunctions.deviceStateScreenKeys
+import com.android.permissioncontroller.hibernation.lastTimePackageUsed
+import com.android.permissioncontroller.permission.data.AllPackageInfosLiveData
+import com.android.permissioncontroller.permission.data.SinglePermGroupPackagesUiInfoLiveData
+import com.android.permissioncontroller.permission.data.UsageStatsLiveData
+import com.android.permissioncontroller.permission.data.getUnusedPackages
+import com.android.permissioncontroller.permission.model.livedatatypes.LightPackageInfo
+import com.android.permissioncontroller.permission.model.v31.AppPermissionUsage
+import com.android.permissioncontroller.permission.model.v31.PermissionUsages
+import com.android.permissioncontroller.permission.model.v31.PermissionUsages.PermissionsUsagesChangeCallback
+import com.google.android.appfunctions.schema.common.v1.devicestate.DeviceStateResponse
+import com.google.android.appfunctions.schema.common.v1.devicestate.PerScreenDeviceStates
+import java.time.Instant
+import java.util.Locale
+import java.util.concurrent.TimeUnit
+import kotlin.math.max
+import kotlin.time.Duration.Companion.days
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.SupervisorJob
+import kotlinx.coroutines.async
+import kotlinx.coroutines.awaitAll
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.launch
+
+// TODO b/411150350: Add CTS test for this service
+@RequiresApi(Build.VERSION_CODES.BAKLAVA)
+class DeviceStateAppFunctionService : AppFunctionService(), PermissionsUsagesChangeCallback {
+    private lateinit var englishContext: Context
+    private lateinit var permissionUsages: PermissionUsages
+    private val serviceJob = SupervisorJob()
+    private val serviceScope: CoroutineScope = CoroutineScope(serviceJob + Dispatchers.Main)
+
+    override fun onCreate() {
+        super.onCreate()
+        englishContext = createEnglishContext()
+        permissionUsages = PermissionUsages(applicationContext)
+    }
+
+    override fun onDestroy() {
+        super.onDestroy()
+        serviceJob.cancel()
+    }
+
+    override fun onExecuteFunction(
+        request: ExecuteAppFunctionRequest,
+        callingPackage: String,
+        callingPackageSigningInfo: SigningInfo,
+        cancellationSignal: CancellationSignal,
+        callback: OutcomeReceiver<ExecuteAppFunctionResponse, AppFunctionException>,
+    ) {
+        if (request.functionIdentifier != APP_FUNCTION_IDENTIFIER) {
+            callback.onError(
+                AppFunctionException(
+                    ERROR_FUNCTION_NOT_FOUND,
+                    "${request.functionIdentifier} not supported.",
+                )
+            )
+            return
+        }
+
+        serviceScope.launch {
+            val jetpackDocument =
+                androidx.appsearch.app.GenericDocument.fromDocumentClass(buildDeviceStateResponse())
+
+            val platformDocument =
+                GenericDocumentToPlatformConverter.toPlatformGenericDocument(jetpackDocument)
+
+            val resultDocument =
+                GenericDocument.Builder<GenericDocument.Builder<*>>("", "", "")
+                    .setPropertyDocument(
+                        ExecuteAppFunctionResponse.PROPERTY_RETURN_VALUE,
+                        platformDocument,
+                    )
+                    .build()
+            val response = ExecuteAppFunctionResponse(resultDocument)
+            callback.onResult(response)
+        }
+    }
+
+    private fun createEnglishContext(): Context {
+        val configuration = Configuration(applicationContext.resources.configuration)
+        configuration.setLocale(Locale.US)
+        return applicationContext.createConfigurationContext(configuration)
+    }
+
+    private suspend fun buildDeviceStateResponse(): DeviceStateResponse {
+        val perScreenDeviceStatesList = deviceStateScreenKeys.map { buildPerScreenDeviceStates(it) }
+        val locale = applicationContext.resources.configuration.locales[0]
+
+        return DeviceStateResponse(
+            perScreenDeviceStates = perScreenDeviceStatesList.flatten(),
+            deviceLocale = locale.toString(),
+        )
+    }
+
+    private suspend fun buildPerScreenDeviceStates(screenKey: String): List<PerScreenDeviceStates> {
+        when (screenKey) {
+            PermissionManagerScreen.KEY -> {
+                return listOf(PermissionManagerScreen(applicationContext).toPerScreenDeviceStates())
+            }
+            PermissionAppsScreen.KEY -> {
+                return coroutineScope {
+                    SUPPORTED_PERMISSION_GROUPS.map {
+                            async {
+                                PermissionAppsScreen(applicationContext, it)
+                                    .toPerScreenDeviceStates()
+                            }
+                        }
+                        .awaitAll()
+                }
+            }
+            AppPermissionsScreen.KEY -> {
+                val allPackages =
+                    applicationContext.packageManager
+                        .getInstalledPackagesAsUser(0, UserHandle.myUserId())
+                        .map { packageInfo -> packageInfo.packageName }
+                        .toList()
+
+                return coroutineScope {
+                        allPackages.map {
+                            async {
+                                AppPermissionsScreen(applicationContext, it)
+                                    .toPerScreenDeviceStates()
+                            }
+                        }
+                    }
+                    .awaitAll()
+            }
+            AppPermissionScreen.KEY -> {
+                val filterBeginTimeMillis =
+                    System.currentTimeMillis() -
+                        TimeUnit.DAYS.toMillis(PERMISSION_USAGE_START_DAY_FROM_NOW)
+
+                permissionUsages.load(
+                    null,
+                    SUPPORTED_PERMISSION_GROUPS.toTypedArray(),
+                    filterBeginTimeMillis,
+                    Long.MAX_VALUE,
+                    PermissionUsages.USAGE_FLAG_LAST,
+                    null,
+                    false,
+                    false,
+                    this,
+                    true,
+                )
+
+                val appPermissionUsages = permissionUsages.usages
+
+                return coroutineScope {
+                    SUPPORTED_PERMISSION_GROUPS.map { permissionGroup ->
+                            async {
+                                val packagePermissionInfoMap =
+                                    SinglePermGroupPackagesUiInfoLiveData[permissionGroup]
+                                        .getInitializedValue(staleOk = false, forceUpdate = true)!!
+
+                                val deviceStateScreens = mutableListOf<PerScreenDeviceStates>()
+                                packagePermissionInfoMap.forEach { (packageInfo, permissionInfo) ->
+                                    deviceStateScreens.add(
+                                        AppPermissionScreen(
+                                                context = applicationContext,
+                                                permissionGroup = permissionGroup,
+                                                packageName = packageInfo.first,
+                                                userHandle = packageInfo.second,
+                                                permissionGrantState =
+                                                    permissionInfo.permGrantState,
+                                                lastAccessTime =
+                                                    extractLastAccessTime(
+                                                        appPermissionUsages,
+                                                        permissionGroup,
+                                                        packageInfo.first,
+                                                        packageInfo.second,
+                                                    ),
+                                                usePreciseLocation =
+                                                    checkUsePreciseLocation(
+                                                        appPermissionUsages,
+                                                        packageInfo.first,
+                                                        permissionGroup,
+                                                    ),
+                                            )
+                                            .toPerScreenDeviceStates()
+                                    )
+                                }
+                                deviceStateScreens
+                            }
+                        }
+                        .awaitAll()
+                        .flatten()
+                }
+            }
+            UnusedAppsScreen.KEY -> {
+                return listOf(UnusedAppsScreen(applicationContext).toPerScreenDeviceStates())
+            }
+            UnusedAppLastUsageScreen.KEY -> {
+                val unusedApps = getUnusedPackages().getInitializedValue()!!
+                val usageStats =
+                    UsageStatsLiveData[MAX_UNUSED_PERIOD_MILLIS].getInitializedValue() ?: emptyMap()
+                val allPackageInfos = AllPackageInfosLiveData.getInitializedValue()!!
+                val lastUsedDataUnusedApps =
+                    extractUnusedAppsUsageData(usageStats, unusedApps) { it: UsageStats ->
+                        PackageLastUsageTime(it.packageName, it.lastTimePackageUsed())
+                    }
+                val firstInstallDataUnusedApps =
+                    extractUnusedAppsUsageData(allPackageInfos, unusedApps) { it: LightPackageInfo
+                        ->
+                        PackageLastUsageTime(it.packageName, it.firstInstallTime)
+                    }
+
+                val deviceStateScreens = mutableListOf<PerScreenDeviceStates>()
+                unusedApps.keys.forEach { (packageName, user) ->
+                    val userPackage = packageName to user
+                    val lastUsageTime =
+                        lastUsedDataUnusedApps[userPackage]
+                            ?: firstInstallDataUnusedApps[userPackage]
+                            ?: 0L
+
+                    deviceStateScreens.add(
+                        UnusedAppLastUsageScreen(
+                                context = applicationContext,
+                                packageName = packageName,
+                                lastUsageTime = lastUsageTime,
+                            )
+                            .toPerScreenDeviceStates()
+                    )
+                }
+
+                return deviceStateScreens
+            }
+            AdditionalPermissionsScreen.KEY -> {
+                return listOf(
+                    AdditionalPermissionsScreen(applicationContext).toPerScreenDeviceStates()
+                )
+            }
+        }
+        throw Exception("$screenKey is not supported")
+    }
+
+    override fun onPermissionUsagesChanged() {}
+
+    /**
+     * Extract PackageLastUsageTime for unused apps from userPackages map. This method may be used
+     * for extracting different usage time (such as installation time or last opened time) from
+     * different Package structures
+     */
+    private fun <PackageData> extractUnusedAppsUsageData(
+        usageStats: Map<UserHandle, List<PackageData>>,
+        unusedApps: Map<Pair<String, UserHandle>, Set<String>>,
+        extractUsageData: (fullData: PackageData) -> PackageLastUsageTime,
+    ): Map<Pair<String, UserHandle>, Long> {
+        return usageStats
+            .flatMap { (userHandle, fullData) ->
+                fullData.map { userHandle to extractUsageData(it) }
+            }
+            .associate { (handle, appData) -> (appData.packageName to handle) to appData.usageTime }
+            .filterKeys { unusedApps.contains(it) }
+    }
+
+    private fun extractLastAccessTime(
+        appPermissionUsages: List<AppPermissionUsage>,
+        permissionGroup: String,
+        packageName: String,
+        userHandle: UserHandle,
+    ): Long {
+        val filterTimeBeginMillis =
+            max(
+                System.currentTimeMillis() -
+                    TimeUnit.DAYS.toMillis(PERMISSION_USAGE_START_DAY_FROM_NOW),
+                Instant.EPOCH.toEpochMilli(),
+            )
+        for (appUsage in appPermissionUsages) {
+            if (packageName != appUsage.packageName) {
+                continue
+            }
+            for (groupUsage in appUsage.groupUsages) {
+                if (
+                    permissionGroup != groupUsage.group.name || userHandle != groupUsage.group.user
+                ) {
+                    continue
+                }
+                if (groupUsage.lastAccessTime >= filterTimeBeginMillis) {
+                    return groupUsage.lastAccessTime
+                }
+            }
+        }
+        return -1
+    }
+
+    /**
+     * The returned value corresponds to the Use precise location UI on the app permission page
+     * - null: Use precise location doesn't apply to the current permission group due to it is not a
+     *   location permission or the permission is not granted.
+     * - true: Use precise location is enabled
+     * - false: Use precise location is disabled
+     */
+    private fun checkUsePreciseLocation(
+        appPermissionUsages: List<AppPermissionUsage>,
+        packageName: String,
+        permissionGroup: String,
+    ): Boolean? {
+        if (permissionGroup != Manifest.permission_group.LOCATION) {
+            return null
+        }
+
+        for (appUsage in appPermissionUsages) {
+            if (packageName != appUsage.packageName) {
+                continue
+            }
+            for (groupUsage in appUsage.groupUsages) {
+                val group = groupUsage.group
+                if (group.name != Manifest.permission_group.LOCATION) {
+                    continue
+                }
+                val coarseLocation = group.getPermission(ACCESS_COARSE_LOCATION)
+                val fineLocation = group.getPermission(ACCESS_FINE_LOCATION)
+
+                if (
+                    coarseLocation == null ||
+                        fineLocation == null ||
+                        !group.areRuntimePermissionsGranted() ||
+                        group.isOneTime
+                ) {
+                    return null
+                }
+
+                // Steps to decide location accuracy toggle state
+                // 1. If FINE or COARSE are granted, then return true if FINE is granted.
+                // 2. Else if FINE or COARSE have the isSelectedLocationAccuracy flag set, then
+                // return
+                //    true if FINE isSelectedLocationAccuracy is set.
+                // 3. Else, return default precision from device config.
+                return if (fineLocation.isGranted || coarseLocation.isGranted) {
+                    fineLocation.isGranted
+                } else if (
+                    fineLocation.isSelectedLocationAccuracy ||
+                        coarseLocation.isSelectedLocationAccuracy
+                ) {
+                    fineLocation.isSelectedLocationAccuracy
+                } else {
+                    // default location precision is true, indicates FINE
+                    true
+                }
+            }
+        }
+        return false
+    }
+
+    private data class PackageLastUsageTime(val packageName: String, val usageTime: Long)
+
+    companion object {
+        private const val TAG = "DeviceStateAppFunctionService"
+        private const val APP_FUNCTION_IDENTIFIER = "getPermissionsDeviceState"
+        private val SUPPORTED_PERMISSION_GROUPS =
+            listOf(
+                Manifest.permission_group.LOCATION,
+                Manifest.permission_group.CONTACTS,
+                Manifest.permission_group.CALL_LOG,
+            )
+        // These two constants are copied from PermissionUsages and UnusedAppsViewModel respectively
+        // TODO: b/415813567 - use the same view model to reduce code duplicate
+        private const val PERMISSION_USAGE_START_DAY_FROM_NOW: Long = 7
+        private val MAX_UNUSED_PERIOD_MILLIS = 180.days.inWholeMilliseconds
+    }
+}
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/GrantPermissionsActivity.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/GrantPermissionsActivity.java
index 0dd07ffd06..40a2a413cd 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/GrantPermissionsActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/GrantPermissionsActivity.java
@@ -95,6 +95,7 @@ import com.android.permissioncontroller.permission.utils.KotlinUtils;
 import com.android.permissioncontroller.permission.utils.PermissionMapping;
 import com.android.permissioncontroller.permission.utils.Utils;
 import com.android.permissioncontroller.permission.utils.v35.MultiDeviceUtils;
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider;
 
 import java.util.ArrayList;
 import java.util.Arrays;
@@ -109,7 +110,7 @@ import java.util.Set;
  * An activity which displays runtime permission prompts on behalf of an app.
  */
 public class GrantPermissionsActivity extends SettingsActivity
-        implements GrantPermissionsViewHandler.ResultListener {
+        implements GrantPermissionsViewHandler.ResultListener, ExpressiveDesignEnabledProvider {
 
     private static final String LOG_TAG = "GrantPermissionsActivity";
 
@@ -384,9 +385,15 @@ public class GrantPermissionsActivity extends SettingsActivity
                     finishAfterTransition();
                     return;
                 }
-                // Merge the old dialogs into the new
-                onNewFollowerActivity(current, current.mRequestedPermissions, true);
-                sCurrentGrantRequests.put(mKey, this);
+                if (icicle != null) {
+                    // This dialog is being recreated, so it should be considered a follower
+                    mDelegated = true;
+                    current.onNewFollowerActivity(this, mRequestedPermissions, true);
+                } else {
+                    // Merge the old dialogs into the new
+                    onNewFollowerActivity(current, current.mRequestedPermissions, true);
+                    sCurrentGrantRequests.put(mKey, this);
+                }
             }
         }
 
@@ -1041,6 +1048,14 @@ public class GrantPermissionsActivity extends SettingsActivity
         }
     }
 
+    @Override
+    public boolean isExpressiveDesignEnabled() {
+        return SdkLevel.isAtLeastB() && DeviceUtils.isHandheld()
+                && com.android.settingslib.widget.theme.flags.Flags.isExpressiveDesignEnabled()
+                && getResources().getBoolean(
+                R.bool.config_enableExpressiveDesignInRequestPermissionDialog);
+    }
+
     /**
      * Remove this activity from the map of activities
      */
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivity.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivity.java
index 0af7cf2ec3..c14f7c33ab 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivity.java
@@ -27,6 +27,8 @@ import static com.android.permissioncontroller.PermissionControllerStatsLog.APP_
 import static com.android.permissioncontroller.PermissionControllerStatsLog.APP_PERMISSION_GROUPS_FRAGMENT_AUTO_REVOKE_ACTION__ACTION__OPENED_FOR_AUTO_REVOKE;
 import static com.android.permissioncontroller.PermissionControllerStatsLog.APP_PERMISSION_GROUPS_FRAGMENT_AUTO_REVOKE_ACTION__ACTION__OPENED_FROM_INTENT;
 import static com.android.permissioncontroller.PermissionControllerStatsLog.AUTO_REVOKE_NOTIFICATION_CLICKED;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__PERMISSION_MANAGER_OPENED;
 import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_USAGE_FRAGMENT_INTERACTION;
 import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_USAGE_FRAGMENT_INTERACTION__ACTION__OPEN;
 
@@ -72,6 +74,7 @@ import com.android.permissioncontroller.permission.ui.auto.AutoUnusedAppsFragmen
 import com.android.permissioncontroller.permission.ui.auto.dashboard.AutoPermissionUsageDetailsFragment;
 import com.android.permissioncontroller.permission.ui.auto.dashboard.AutoPermissionUsageFragment;
 import com.android.permissioncontroller.permission.ui.handheld.AppPermissionGroupsFragment;
+import com.android.permissioncontroller.permission.ui.handheld.ManageCustomPermissionsFragment;
 import com.android.permissioncontroller.permission.ui.handheld.PermissionAppsFragment;
 import com.android.permissioncontroller.permission.ui.handheld.v31.PermissionDetailsWrapperFragment;
 import com.android.permissioncontroller.permission.ui.handheld.v31.PermissionUsageWrapperFragment;
@@ -85,6 +88,7 @@ import com.android.permissioncontroller.permission.ui.wear.WearUnusedAppsFragmen
 import com.android.permissioncontroller.permission.utils.KotlinUtils;
 import com.android.permissioncontroller.permission.utils.PermissionMapping;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import java.util.Objects;
 import java.util.Random;
@@ -154,6 +158,8 @@ public final class ManagePermissionsActivity extends SettingsActivity {
             // Automotive relies on a different theme. Apply before calling super so that
             // fragments are restored properly on configuration changes.
             setTheme(R.style.CarSettings);
+        } else if (SettingsThemeHelper.isExpressiveTheme(this)) {
+            setTheme(R.style.Theme_PermissionController_Settings_Expressive_FilterTouches);
         }
         if (SdkLevel.isAtLeastV() && DeviceUtils.isHandheld(this)) {
             switch (getIntent().getAction()) {
@@ -218,6 +224,12 @@ public final class ManagePermissionsActivity extends SettingsActivity {
         String permissionName;
         switch (action) {
             case Intent.ACTION_MANAGE_PERMISSIONS:
+                PermissionControllerStatsLog.write(
+                        PERMISSION_MANAGER_PAGE_INTERACTION,
+                        sessionId,
+                        PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__PERMISSION_MANAGER_OPENED,
+                        null
+                );
                 Bundle arguments = new Bundle();
                 arguments.putLong(EXTRA_SESSION_ID, sessionId);
                 if (DeviceUtils.isAuto(this)) {
@@ -546,6 +558,14 @@ public final class ManagePermissionsActivity extends SettingsActivity {
                 }
             } break;
 
+            case Constants.ACTION_ADDITIONAL_PERMISSIONS: {
+                if (!DeviceUtils.isAuto(this) && !DeviceUtils.isTelevision(this)) {
+                    Bundle args = ManageCustomPermissionsFragment.createArgs(sessionId);
+                    setNavGraph(args, R.id.manage_custom);
+                    return;
+                }
+            } break;
+
             default: {
                 Log.w(LOG_TAG, "Unrecognized action " + action);
                 finishAfterTransition();
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivityTrampoline.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivityTrampoline.java
index af93400dde..bf4bad6dda 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivityTrampoline.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/ManagePermissionsActivityTrampoline.java
@@ -19,7 +19,11 @@ package com.android.permissioncontroller.permission.ui;
 import android.app.Activity;
 import android.content.Intent;
 import android.os.Bundle;
+import android.os.UserHandle;
+import android.provider.Settings;
 
+import com.android.permissioncontroller.Constants;
+import com.android.permissioncontroller.appfunctions.AppFunctionsUtil;
 import com.android.permissioncontroller.permission.service.PermissionSearchIndexablesProvider;
 
 /**
@@ -32,7 +36,8 @@ public class ManagePermissionsActivityTrampoline extends Activity {
         super.onCreate(savedInstanceState);
 
         Intent intent = getIntent();
-        if (!PermissionSearchIndexablesProvider.isIntentValid(intent, this)) {
+        if (!PermissionSearchIndexablesProvider.isIntentValid(intent, this)
+                && !AppFunctionsUtil.isIntentValid(intent, this)) {
             finish();
             return;
         }
@@ -45,14 +50,44 @@ public class ManagePermissionsActivityTrampoline extends Activity {
 
         Intent newIntent = new Intent(this, ManagePermissionsActivity.class)
                 .addFlags(Intent.FLAG_ACTIVITY_FORWARD_RESULT);
-        if (action.equals(PermissionSearchIndexablesProvider.ACTION_MANAGE_PERMISSION_APPS)) {
-            newIntent
-                    .setAction(Intent.ACTION_MANAGE_PERMISSION_APPS)
-                    .putExtra(Intent.EXTRA_PERMISSION_GROUP_NAME,
-                            PermissionSearchIndexablesProvider.getOriginalKey(intent));
-        } else {
-            finish();
-            return;
+
+        switch (action) {
+            case PermissionSearchIndexablesProvider.ACTION_MANAGE_PERMISSION_APPS:
+                newIntent.setAction(Intent.ACTION_MANAGE_PERMISSION_APPS).putExtra(
+                        Intent.EXTRA_PERMISSION_GROUP_NAME,
+                        PermissionSearchIndexablesProvider.getOriginalKey(intent));
+                break;
+            case AppFunctionsUtil.ACTION_MANAGE_PERMISSIONS:
+                newIntent.setAction(Intent.ACTION_MANAGE_PERMISSIONS);
+                break;
+            case AppFunctionsUtil.ACTION_MANAGE_PERMISSION_APPS:
+                newIntent.setAction(Intent.ACTION_MANAGE_PERMISSION_APPS).putExtra(
+                        Intent.EXTRA_PERMISSION_GROUP_NAME,
+                        intent.getStringExtra(Intent.EXTRA_PERMISSION_GROUP_NAME));
+                break;
+            case AppFunctionsUtil.ACTION_MANAGE_APP_PERMISSIONS:
+                newIntent.setAction(Settings.ACTION_APP_PERMISSIONS_SETTINGS).putExtra(
+                        Intent.EXTRA_PACKAGE_NAME,
+                        intent.getStringExtra(Intent.EXTRA_PACKAGE_NAME));
+                break;
+            case AppFunctionsUtil.ACTION_MANAGE_APP_PERMISSION:
+                newIntent.setAction(Intent.ACTION_MANAGE_APP_PERMISSION).putExtra(
+                                Intent.EXTRA_PERMISSION_GROUP_NAME,
+                                intent.getStringExtra(Intent.EXTRA_PERMISSION_GROUP_NAME))
+                        .putExtra(Intent.EXTRA_PACKAGE_NAME,
+                                intent.getStringExtra(Intent.EXTRA_PACKAGE_NAME))
+                        .putExtra(Intent.EXTRA_USER,
+                                intent.getParcelableExtra(Intent.EXTRA_USER, UserHandle.class));
+                break;
+            case AppFunctionsUtil.ACTION_MANAGE_UNUSED_APPS:
+                newIntent.setAction(Intent.ACTION_MANAGE_UNUSED_APPS);
+                break;
+            case AppFunctionsUtil.ACTION_ADDITIONAL_PERMISSIONS:
+                newIntent.setAction(Constants.ACTION_ADDITIONAL_PERMISSIONS);
+                break;
+            default:
+                finish();
+                return;
         }
 
         startActivity(newIntent);
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/SettingsActivity.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/SettingsActivity.java
index f8667bc285..d5b709ebcc 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/SettingsActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/SettingsActivity.java
@@ -16,17 +16,28 @@
 
 package com.android.permissioncontroller.permission.ui;
 
+import com.android.modules.utils.build.SdkLevel;
 import com.android.permissioncontroller.DeviceUtils;
+import com.android.permissioncontroller.R;
 import com.android.settingslib.collapsingtoolbar.SettingsTransitionActivity;
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider;
+import com.android.settingslib.widget.theme.flags.Flags;
 
 /**
  * Parent activity that supports transitions
  */
-public class SettingsActivity extends SettingsTransitionActivity {
+public class SettingsActivity extends SettingsTransitionActivity implements
+        ExpressiveDesignEnabledProvider {
     @Override
     protected boolean isSettingsTransitionEnabled() {
         return super.isSettingsTransitionEnabled() && !(DeviceUtils.isAuto(this)
                 || DeviceUtils.isTelevision(this) || DeviceUtils.isWear(this));
     }
 
+    @Override
+    public boolean isExpressiveDesignEnabled() {
+        return SdkLevel.isAtLeastB() && DeviceUtils.isHandheld()
+                && Flags.isExpressiveDesignEnabled() && getResources().getBoolean(
+                R.bool.config_enableExpressiveDesignInPermissionSettings);
+    }
 }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AllAppPermissionsFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AllAppPermissionsFragment.java
index 81de139e48..1b9c96f1e6 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AllAppPermissionsFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AllAppPermissionsFragment.java
@@ -24,16 +24,19 @@ import android.content.Context;
 import android.content.Intent;
 import android.graphics.drawable.Drawable;
 import android.net.Uri;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.UserHandle;
 import android.provider.Settings;
 import android.util.Log;
 import android.view.MenuItem;
-import android.widget.Switch;
+import android.view.View;
+import android.widget.CompoundButton;
 import android.widget.Toast;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
 import androidx.lifecycle.ViewModelProvider;
 import androidx.preference.Preference;
 import androidx.preference.PreferenceGroup;
@@ -42,12 +45,14 @@ import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.permission.data.PackagePermissionsLiveData;
 import com.android.permissioncontroller.permission.model.AppPermissionGroup;
 import com.android.permissioncontroller.permission.model.Permission;
+import com.android.permissioncontroller.permission.ui.handheld.v36.MultiTargetSwitchPreferenceCompat;
 import com.android.permissioncontroller.permission.ui.model.AllAppPermissionsViewModel;
 import com.android.permissioncontroller.permission.ui.model.AllAppPermissionsViewModelFactory;
 import com.android.permissioncontroller.permission.utils.ArrayUtils;
 import com.android.permissioncontroller.permission.utils.KotlinUtils;
 import com.android.permissioncontroller.permission.utils.PermissionMapping;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import java.text.Collator;
 import java.util.List;
@@ -248,7 +253,12 @@ public final class AllAppPermissionsFragment extends SettingsWithLargeHeader {
         if (mutable) {
             AppPermissionGroup appPermGroup = AppPermissionGroup.create(
                     getActivity().getApplication(), mPackageName, groupName, mUser, false);
-            pref = new MyMultiTargetSwitchPreference(context, permName, appPermGroup);
+            boolean isChecked = appPermGroup.areRuntimePermissionsGranted(new String[]{permName});
+            MyMultiTargetSwitchOnClickListener listener =
+                    new MyMultiTargetSwitchOnClickListener(permName, appPermGroup);
+            pref = SettingsThemeHelper.isExpressiveTheme(context)
+                    ? new MyMultiTargetSwitchPreferenceCompat(context, isChecked, listener)
+                    : new MyMultiTargetSwitchPreference(context, isChecked, listener);
         } else {
             pref = new PermissionPreference(context);
         }
@@ -269,61 +279,84 @@ public final class AllAppPermissionsFragment extends SettingsWithLargeHeader {
         return pref;
     }
 
-    private static final class MyMultiTargetSwitchPreference extends MultiTargetSwitchPreference {
-        MyMultiTargetSwitchPreference(Context context, String permission,
+    private static final class MyMultiTargetSwitchOnClickListener implements View.OnClickListener {
+
+        private final String mPermission;
+        private final AppPermissionGroup mAppPermissionGroup;
+
+        MyMultiTargetSwitchOnClickListener(String permission,
                 AppPermissionGroup appPermissionGroup) {
-            super(context);
+            mPermission = permission;
+            mAppPermissionGroup = appPermissionGroup;
+        }
 
-            setChecked(appPermissionGroup.areRuntimePermissionsGranted(
-                    new String[]{permission}));
-
-            setSwitchOnClickListener(v -> {
-                Switch switchView = (Switch) v;
-                if (switchView.isChecked()) {
-                    appPermissionGroup.grantRuntimePermissions(true, false,
-                            new String[]{permission});
-                    // We are granting a permission from a group but since this is an
-                    // individual permission control other permissions in the group may
-                    // be revoked, hence we need to mark them user fixed to prevent the
-                    // app from requesting a non-granted permission and it being granted
-                    // because another permission in the group is granted. This applies
-                    // only to apps that support runtime permissions.
-                    if (appPermissionGroup.doesSupportRuntimePermissions()) {
-                        int grantedCount = 0;
-                        String[] revokedPermissionsToFix = null;
-                        final int permissionCount = appPermissionGroup.getPermissions().size();
-                        for (int i = 0; i < permissionCount; i++) {
-                            Permission current = appPermissionGroup.getPermissions().get(i);
-                            if (!current.isGrantedIncludingAppOp()) {
-                                if (!current.isUserFixed()) {
-                                    revokedPermissionsToFix = ArrayUtils.appendString(
-                                            revokedPermissionsToFix, current.getName());
-                                }
-                            } else {
-                                grantedCount++;
+        @Override
+        public void onClick(View v) {
+            CompoundButton switchView = (CompoundButton) v;
+            if (switchView.isChecked()) {
+                mAppPermissionGroup.grantRuntimePermissions(true, false,
+                        new String[]{mPermission});
+                // We are granting a permission from a group but since this is an
+                // individual permission control other permissions in the group may
+                // be revoked, hence we need to mark them user fixed to prevent the
+                // app from requesting a non-granted permission and it being granted
+                // because another permission in the group is granted. This applies
+                // only to apps that support runtime permissions.
+                if (mAppPermissionGroup.doesSupportRuntimePermissions()) {
+                    int grantedCount = 0;
+                    String[] revokedPermissionsToFix = null;
+                    final int permissionCount = mAppPermissionGroup.getPermissions().size();
+                    for (int i = 0; i < permissionCount; i++) {
+                        Permission current = mAppPermissionGroup.getPermissions().get(i);
+                        if (!current.isGrantedIncludingAppOp()) {
+                            if (!current.isUserFixed()) {
+                                revokedPermissionsToFix = ArrayUtils.appendString(
+                                        revokedPermissionsToFix, current.getName());
                             }
-                        }
-                        if (revokedPermissionsToFix != null) {
-                            // If some permissions were not granted then they should be fixed.
-                            appPermissionGroup.revokeRuntimePermissions(true,
-                                    revokedPermissionsToFix);
-                        } else if (appPermissionGroup.getPermissions().size() == grantedCount) {
-                            // If all permissions are granted then they should not be fixed.
-                            appPermissionGroup.grantRuntimePermissions(true, false);
+                        } else {
+                            grantedCount++;
                         }
                     }
-                } else {
-                    appPermissionGroup.revokeRuntimePermissions(true,
-                            new String[]{permission});
-                    // If we just revoked the last permission we need to clear
-                    // the user fixed state as now the app should be able to
-                    // request them at runtime if supported.
-                    if (appPermissionGroup.doesSupportRuntimePermissions()
-                            && !appPermissionGroup.areRuntimePermissionsGranted()) {
-                        appPermissionGroup.revokeRuntimePermissions(false);
+                    if (revokedPermissionsToFix != null) {
+                        // If some permissions were not granted then they should be fixed.
+                        mAppPermissionGroup.revokeRuntimePermissions(true,
+                                revokedPermissionsToFix);
+                    } else if (mAppPermissionGroup.getPermissions().size() == grantedCount) {
+                        // If all permissions are granted then they should not be fixed.
+                        mAppPermissionGroup.grantRuntimePermissions(true, false);
                     }
                 }
-            });
+            } else {
+                mAppPermissionGroup.revokeRuntimePermissions(true,
+                        new String[]{mPermission});
+                // If we just revoked the last permission we need to clear
+                // the user fixed state as now the app should be able to
+                // request them at runtime if supported.
+                if (mAppPermissionGroup.doesSupportRuntimePermissions()
+                        && !mAppPermissionGroup.areRuntimePermissionsGranted()) {
+                    mAppPermissionGroup.revokeRuntimePermissions(false);
+                }
+            }
+        }
+    }
+
+    private static final class MyMultiTargetSwitchPreference extends MultiTargetSwitchPreference {
+        MyMultiTargetSwitchPreference(Context context, Boolean isChecked,
+                View.OnClickListener listener) {
+            super(context);
+            setChecked(isChecked);
+            setSwitchOnClickListener(listener);
+        }
+    }
+
+    @RequiresApi(Build.VERSION_CODES.BAKLAVA)
+    private static final class MyMultiTargetSwitchPreferenceCompat
+            extends MultiTargetSwitchPreferenceCompat {
+        MyMultiTargetSwitchPreferenceCompat(Context context, Boolean isChecked,
+                View.OnClickListener listener) {
+            super(context);
+            setChecked(isChecked);
+            setSwitchOnClickListener(listener);
         }
     }
 }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AppPermissionGroupsFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AppPermissionGroupsFragment.java
index e995588b2d..cd929f38a5 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AppPermissionGroupsFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/AppPermissionGroupsFragment.java
@@ -61,7 +61,8 @@ import androidx.lifecycle.ViewModelProvider;
 import androidx.preference.Preference;
 import androidx.preference.PreferenceCategory;
 import androidx.preference.PreferenceScreen;
-import androidx.preference.SwitchPreference;
+import androidx.preference.SwitchPreferenceCompat;
+import androidx.preference.TwoStatePreference;
 
 import com.android.modules.utils.build.SdkLevel;
 import com.android.permission.flags.Flags;
@@ -79,6 +80,7 @@ import com.android.permissioncontroller.permission.utils.StringUtils;
 import com.android.permissioncontroller.permission.utils.Utils;
 import com.android.permissioncontroller.permission.utils.v35.MultiDeviceUtils;
 import com.android.settingslib.HelpUtils;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import java.text.Collator;
 import java.time.Instant;
@@ -454,7 +456,9 @@ public final class AppPermissionGroupsFragment extends SettingsWithLargeHeader i
         autoRevokeCategory.setKey(AUTO_REVOKE_CATEGORY_KEY);
         screen.addPreference(autoRevokeCategory);
 
-        SwitchPreference autoRevokeSwitch = new PermissionSwitchPreference(context);
+        TwoStatePreference autoRevokeSwitch = SettingsThemeHelper.isExpressiveTheme(getContext())
+                ? new SwitchPreferenceCompat(context)
+                : new PermissionSwitchPreference(context);
         autoRevokeSwitch.setOnPreferenceClickListener((preference) -> {
             mViewModel.setAutoRevoke(autoRevokeSwitch.isChecked());
             return true;
@@ -503,7 +507,7 @@ public final class AppPermissionGroupsFragment extends SettingsWithLargeHeader i
 
         PreferenceCategory autoRevokeCategory = getPreferenceScreen()
                 .findPreference(AUTO_REVOKE_CATEGORY_KEY);
-        SwitchPreference autoRevokeSwitch = autoRevokeCategory.findPreference(
+        TwoStatePreference autoRevokeSwitch = autoRevokeCategory.findPreference(
                 AUTO_REVOKE_SWITCH_KEY);
         Preference autoRevokeSummary = autoRevokeCategory.findPreference(
                 AUTO_REVOKE_SUMMARY_KEY);
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/GrantPermissionsViewHandlerImpl.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/GrantPermissionsViewHandlerImpl.kt
index bb698b49ae..33e7f4e7b6 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/GrantPermissionsViewHandlerImpl.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/GrantPermissionsViewHandlerImpl.kt
@@ -77,17 +77,18 @@ import com.android.permissioncontroller.permission.ui.GrantPermissionsViewHandle
 import com.android.permissioncontroller.permission.ui.GrantPermissionsViewHandler.GRANTED_ONE_TIME
 import com.android.permissioncontroller.permission.ui.GrantPermissionsViewHandler.GRANTED_USER_SELECTED
 import com.android.permissioncontroller.permission.ui.GrantPermissionsViewHandler.ResultListener
+import com.android.settingslib.widget.SettingsThemeHelper
 
 class GrantPermissionsViewHandlerImpl(
     private val mActivity: Activity,
-    private val resultListener: ResultListener
+    private val resultListener: ResultListener,
 ) : GrantPermissionsViewHandler, OnClickListener {
 
     private val LOCATION_ACCURACY_DIALOGS =
         listOf(
             DIALOG_WITH_BOTH_LOCATIONS,
             DIALOG_WITH_FINE_LOCATION_ONLY,
-            DIALOG_WITH_COARSE_LOCATION_ONLY
+            DIALOG_WITH_COARSE_LOCATION_ONLY,
         )
     private val LOCATION_ACCURACY_IMAGE_DIAMETER =
         mActivity.resources.getDimension(R.dimen.location_accuracy_image_size)
@@ -130,7 +131,7 @@ class GrantPermissionsViewHandlerImpl(
         arguments.putCharSequence(ARG_GROUP_DETAIL_MESSAGE, detailMessage)
         arguments.putCharSequence(
             ARG_GROUP_PERMISSION_RATIONALE_MESSAGE,
-            permissionRationaleMessage
+            permissionRationaleMessage,
         )
         arguments.putBooleanArray(ARG_DIALOG_BUTTON_VISIBILITIES, buttonVisibilities)
         arguments.putBooleanArray(ARG_DIALOG_LOCATION_VISIBILITIES, locationVisibilities)
@@ -164,7 +165,7 @@ class GrantPermissionsViewHandlerImpl(
         detailMessage: CharSequence?,
         permissionRationaleMessage: CharSequence?,
         buttonVisibilities: BooleanArray?,
-        locationVisibilities: BooleanArray?
+        locationVisibilities: BooleanArray?,
     ) {
         this.groupName = groupName
         this.groupCount = groupCount
@@ -201,14 +202,15 @@ class GrantPermissionsViewHandlerImpl(
     override fun createView(): View {
         val useMaterial3PermissionGrantDialog =
             mActivity.resources.getBoolean(R.bool.config_useMaterial3PermissionGrantDialog)
-        val rootView =
-            if (useMaterial3PermissionGrantDialog || SdkLevel.isAtLeastT()) {
-                LayoutInflater.from(mActivity).inflate(R.layout.grant_permissions_material3, null)
-                    as ViewGroup
+        val layoutResource =
+            if (SettingsThemeHelper.isExpressiveTheme(mActivity)) {
+                R.layout.grant_permissions_expressive
+            } else if (useMaterial3PermissionGrantDialog || SdkLevel.isAtLeastT()) {
+                R.layout.grant_permissions_material3
             } else {
-                LayoutInflater.from(mActivity).inflate(R.layout.grant_permissions, null)
-                    as ViewGroup
+                R.layout.grant_permissions
             }
+        val rootView = LayoutInflater.from(mActivity).inflate(layoutResource, null) as ViewGroup
         this.rootView = rootView
 
         // Uses the vertical gravity of the PermissionGrantSingleton style to position the window
@@ -269,6 +271,7 @@ class GrantPermissionsViewHandlerImpl(
                 override fun getIntrinsicHeight(): Int {
                     return (super.getIntrinsicHeight() * scale).toInt()
                 }
+
                 override fun getIntrinsicWidth(): Int {
                     return (super.getIntrinsicWidth() * scale).toInt()
                 }
@@ -434,13 +437,13 @@ class GrantPermissionsViewHandlerImpl(
                 null,
                 coarseOffDrawable,
                 null,
-                null
+                null,
             )
             fineRadioButton?.setCompoundDrawablesWithIntrinsicBounds(
                 null,
                 fineOnDrawable,
                 null,
-                null
+                null,
             )
             coarseOffDrawable?.start()
             fineOnDrawable?.start()
@@ -453,13 +456,13 @@ class GrantPermissionsViewHandlerImpl(
                 null,
                 coarseOnDrawable,
                 null,
-                null
+                null,
             )
             fineRadioButton?.setCompoundDrawablesWithIntrinsicBounds(
                 null,
                 fineOffDrawable,
                 null,
-                null
+                null,
             )
             fineOffDrawable?.start()
             coarseOnDrawable?.start()
@@ -523,63 +526,63 @@ class GrantPermissionsViewHandlerImpl(
             ALLOW_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    GRANTED_ALWAYS
+                    GRANTED_ALWAYS,
                 )
             }
             ALLOW_FOREGROUND_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    GRANTED_FOREGROUND_ONLY
+                    GRANTED_FOREGROUND_ONLY,
                 )
             }
             ALLOW_ALWAYS_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    GRANTED_ALWAYS
+                    GRANTED_ALWAYS,
                 )
             }
             ALLOW_ONE_TIME_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    GRANTED_ONE_TIME
+                    GRANTED_ONE_TIME,
                 )
             }
             ALLOW_SELECTED_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    GRANTED_USER_SELECTED
+                    GRANTED_USER_SELECTED,
                 )
             }
             DONT_ALLOW_MORE_SELECTED_BUTTON -> {
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    DENIED_MORE
+                    DENIED_MORE,
                 )
             }
             DENY_BUTTON,
@@ -587,12 +590,12 @@ class GrantPermissionsViewHandlerImpl(
             NO_UPGRADE_OT_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    DENIED
+                    DENIED,
                 )
             }
             DENY_AND_DONT_ASK_AGAIN_BUTTON,
@@ -600,12 +603,12 @@ class GrantPermissionsViewHandlerImpl(
             NO_UPGRADE_OT_AND_DONT_ASK_AGAIN_BUTTON -> {
                 view.performAccessibilityAction(
                     AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS,
-                    null
+                    null,
                 )
                 resultListener.onPermissionGrantResult(
                     groupName,
                     affectedForegroundPermissions,
-                    DENIED_DO_NOT_ASK_AGAIN
+                    DENIED_DO_NOT_ASK_AGAIN,
                 )
             }
         }
@@ -649,54 +652,54 @@ class GrantPermissionsViewHandlerImpl(
             BUTTON_RES_ID_TO_NUM.put(R.id.permission_allow_button, ALLOW_BUTTON)
             BUTTON_RES_ID_TO_NUM.put(
                 R.id.permission_allow_foreground_only_button,
-                ALLOW_FOREGROUND_BUTTON
+                ALLOW_FOREGROUND_BUTTON,
             )
             BUTTON_RES_ID_TO_NUM.put(R.id.permission_deny_button, DENY_BUTTON)
             BUTTON_RES_ID_TO_NUM.put(
                 R.id.permission_deny_and_dont_ask_again_button,
-                DENY_AND_DONT_ASK_AGAIN_BUTTON
+                DENY_AND_DONT_ASK_AGAIN_BUTTON,
             )
             BUTTON_RES_ID_TO_NUM.put(R.id.permission_allow_one_time_button, ALLOW_ONE_TIME_BUTTON)
             BUTTON_RES_ID_TO_NUM.put(R.id.permission_no_upgrade_button, NO_UPGRADE_BUTTON)
             BUTTON_RES_ID_TO_NUM.put(
                 R.id.permission_no_upgrade_and_dont_ask_again_button,
-                NO_UPGRADE_AND_DONT_ASK_AGAIN_BUTTON
+                NO_UPGRADE_AND_DONT_ASK_AGAIN_BUTTON,
             )
             BUTTON_RES_ID_TO_NUM.put(
                 R.id.permission_no_upgrade_one_time_button,
-                NO_UPGRADE_OT_BUTTON
+                NO_UPGRADE_OT_BUTTON,
             )
             BUTTON_RES_ID_TO_NUM.put(
                 R.id.permission_no_upgrade_one_time_and_dont_ask_again_button,
-                NO_UPGRADE_OT_AND_DONT_ASK_AGAIN_BUTTON
+                NO_UPGRADE_OT_AND_DONT_ASK_AGAIN_BUTTON,
             )
             BUTTON_RES_ID_TO_NUM.put(R.id.permission_allow_all_button, ALLOW_ALL_BUTTON)
             BUTTON_RES_ID_TO_NUM.put(R.id.permission_allow_selected_button, ALLOW_SELECTED_BUTTON)
             BUTTON_RES_ID_TO_NUM.put(
                 R.id.permission_dont_allow_more_selected_button,
-                DONT_ALLOW_MORE_SELECTED_BUTTON
+                DONT_ALLOW_MORE_SELECTED_BUTTON,
             )
 
             LOCATION_RES_ID_TO_NUM.put(R.id.permission_location_accuracy, LOCATION_ACCURACY_LAYOUT)
             LOCATION_RES_ID_TO_NUM.put(
                 R.id.permission_location_accuracy_radio_fine,
-                FINE_RADIO_BUTTON
+                FINE_RADIO_BUTTON,
             )
             LOCATION_RES_ID_TO_NUM.put(
                 R.id.permission_location_accuracy_radio_coarse,
-                COARSE_RADIO_BUTTON
+                COARSE_RADIO_BUTTON,
             )
             LOCATION_RES_ID_TO_NUM.put(
                 R.id.permission_location_accuracy_radio_group,
-                DIALOG_WITH_BOTH_LOCATIONS
+                DIALOG_WITH_BOTH_LOCATIONS,
             )
             LOCATION_RES_ID_TO_NUM.put(
                 R.id.permission_location_accuracy_fine_only,
-                DIALOG_WITH_FINE_LOCATION_ONLY
+                DIALOG_WITH_FINE_LOCATION_ONLY,
             )
             LOCATION_RES_ID_TO_NUM.put(
                 R.id.permission_location_accuracy_coarse_only,
-                DIALOG_WITH_COARSE_LOCATION_ONLY
+                DIALOG_WITH_COARSE_LOCATION_ONLY,
             )
         }
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/HandheldUnusedAppsFragment.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/HandheldUnusedAppsFragment.kt
index 030b12c666..b3d131cd89 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/HandheldUnusedAppsFragment.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/HandheldUnusedAppsFragment.kt
@@ -27,12 +27,15 @@ import com.android.permissioncontroller.R
 import com.android.permissioncontroller.hibernation.isHibernationEnabled
 import com.android.permissioncontroller.permission.ui.UnusedAppsFragment
 import com.android.permissioncontroller.permission.ui.UnusedAppsFragment.Companion.INFO_MSG_CATEGORY
+import com.android.settingslib.widget.SettingsThemeHelper
 
 /** Handheld wrapper, with customizations, around [UnusedAppsFragment]. */
 class HandheldUnusedAppsFragment :
     PermissionsFrameFragment(), UnusedAppsFragment.Parent<UnusedAppPreference> {
 
     companion object {
+        private const val ZERO_STATE_KEY = "zero_state_preference"
+
         /** Create a new instance of this fragment. */
         @JvmStatic
         fun newInstance(): HandheldUnusedAppsFragment {
@@ -97,7 +100,7 @@ class HandheldUnusedAppsFragment :
     override fun createUnusedAppPref(
         app: Application,
         packageName: String,
-        user: UserHandle
+        user: UserHandle,
     ): UnusedAppPreference {
         return UnusedAppPreference(app, packageName, user, requireContext())
     }
@@ -110,5 +113,9 @@ class HandheldUnusedAppsFragment :
         val infoMsgCategory =
             preferenceScreen.findPreference<PreferenceCategory>(INFO_MSG_CATEGORY)!!
         infoMsgCategory.isVisible = !empty
+        if (SettingsThemeHelper.isExpressiveTheme(requireContext())) {
+            val zeroStatePref = preferenceScreen.findPreference<Preference>(ZERO_STATE_KEY)!!
+            zeroStatePref.isVisible = empty
+        }
     }
 }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageCustomPermissionsFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageCustomPermissionsFragment.java
index dd460aa2fb..321cfef4e3 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageCustomPermissionsFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageCustomPermissionsFragment.java
@@ -17,6 +17,9 @@
 package com.android.permissioncontroller.permission.ui.handheld;
 
 import static com.android.permissioncontroller.Constants.EXTRA_SESSION_ID;
+import static com.android.permissioncontroller.Constants.INVALID_SESSION_ID;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__ADDITIONAL_PERMISSION_GROUP_CLICKED;
 import static com.android.permissioncontroller.permission.ui.handheld.UtilsKt.pressBack;
 
 import android.os.Bundle;
@@ -25,6 +28,7 @@ import android.view.MenuItem;
 import androidx.lifecycle.ViewModelProvider;
 
 import com.android.permission.flags.Flags;
+import com.android.permissioncontroller.PermissionControllerStatsLog;
 import com.android.permissioncontroller.permission.data.PermGroupsPackagesUiInfoLiveData;
 import com.android.permissioncontroller.permission.ui.model.ManageCustomPermissionsViewModel;
 import com.android.permissioncontroller.permission.ui.model.ManageCustomPermissionsViewModelFactory;
@@ -37,7 +41,7 @@ import java.util.HashMap;
 public class ManageCustomPermissionsFragment extends ManagePermissionsFragment {
 
     private ManageCustomPermissionsViewModel mViewModel;
-
+    private long mSessionId;
     /**
      * Create a bundle with the arguments needed by this fragment
      *
@@ -61,7 +65,7 @@ public class ManageCustomPermissionsFragment extends ManagePermissionsFragment {
     @Override
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
-
+        mSessionId = getArguments().getLong(EXTRA_SESSION_ID, INVALID_SESSION_ID);
         ManageCustomPermissionsViewModelFactory factory =
                 new ManageCustomPermissionsViewModelFactory(getActivity().getApplication());
         mViewModel = new ViewModelProvider(this, factory)
@@ -80,6 +84,12 @@ public class ManageCustomPermissionsFragment extends ManagePermissionsFragment {
 
     @Override
     public void showPermissionApps(String permissionGroupName) {
+        PermissionControllerStatsLog.write(
+                PERMISSION_MANAGER_PAGE_INTERACTION,
+                mSessionId,
+                PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__ADDITIONAL_PERMISSION_GROUP_CLICKED,
+                permissionGroupName
+        );
         mViewModel.showPermissionApps(this, PermissionAppsFragment.createArgs(
                 permissionGroupName, getArguments().getLong(EXTRA_SESSION_ID)));
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageStandardPermissionsFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageStandardPermissionsFragment.java
index 51c0906a20..3094249263 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageStandardPermissionsFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ManageStandardPermissionsFragment.java
@@ -19,6 +19,10 @@ import static androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory;
 
 import static com.android.permissioncontroller.Constants.EXTRA_SESSION_ID;
 import static com.android.permissioncontroller.Constants.INVALID_SESSION_ID;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__ADDITIONAL_PERMISSIONS_CLICKED;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__STANDARD_PERMISSION_GROUP_CLICKED;
+import static com.android.permissioncontroller.PermissionControllerStatsLog.PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__UNUSED_APPS_LEARN_MORE_CLICKED;
 import static com.android.permissioncontroller.permission.ui.handheld.UtilsKt.pressBack;
 
 import android.app.Application;
@@ -32,6 +36,7 @@ import androidx.preference.PreferenceScreen;
 
 import com.android.modules.utils.build.SdkLevel;
 import com.android.permission.flags.Flags;
+import com.android.permissioncontroller.PermissionControllerStatsLog;
 import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.permission.data.PermGroupsPackagesUiInfoLiveData;
 import com.android.permissioncontroller.permission.ui.UnusedAppsFragment;
@@ -47,6 +52,7 @@ public final class ManageStandardPermissionsFragment extends ManagePermissionsFr
     private static final String AUTO_REVOKE_KEY = "auto_revoke_key";
     private static final String LOG_TAG = ManageStandardPermissionsFragment.class.getSimpleName();
     private ManageStandardPermissionsViewModel mViewModel;
+    private long mSessionId;
 
     /**
      * Create a bundle with the arguments needed by this fragment
@@ -71,7 +77,7 @@ public final class ManageStandardPermissionsFragment extends ManagePermissionsFr
     @Override
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
-
+        mSessionId = getArguments().getLong(EXTRA_SESSION_ID, INVALID_SESSION_ID);
         final Application application = getActivity().getApplication();
         mViewModel = new ViewModelProvider(this, AndroidViewModelFactory.getInstance(application))
                 .get(ManageStandardPermissionsViewModel.class);
@@ -157,6 +163,12 @@ public final class ManageStandardPermissionsFragment extends ManagePermissionsFr
                         android.R.attr.colorControlNormal));
                 additionalPermissionsPreference.setTitle(R.string.additional_permissions);
                 additionalPermissionsPreference.setOnPreferenceClickListener(preference -> {
+                    PermissionControllerStatsLog.write(
+                            PERMISSION_MANAGER_PAGE_INTERACTION,
+                            mSessionId,
+                            PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__ADDITIONAL_PERMISSIONS_CLICKED,
+                            null
+                    );
                     mViewModel.showCustomPermissions(this,
                             ManageCustomPermissionsFragment.createArgs(
                                     getArguments().getLong(EXTRA_SESSION_ID)));
@@ -195,6 +207,12 @@ public final class ManageStandardPermissionsFragment extends ManagePermissionsFr
                 new PermissionFooterPreference(getContext());
         autoRevokePreference.setSummary(R.string.auto_revoked_apps_page_summary);
         autoRevokePreference.setLearnMoreAction(view -> {
+            PermissionControllerStatsLog.write(
+                    PERMISSION_MANAGER_PAGE_INTERACTION,
+                    mSessionId,
+                    PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__UNUSED_APPS_LEARN_MORE_CLICKED,
+                    null
+            );
             mViewModel.showAutoRevoke(this, UnusedAppsFragment.createArgs(
                             getArguments().getLong(EXTRA_SESSION_ID, INVALID_SESSION_ID)));
             });
@@ -210,6 +228,12 @@ public final class ManageStandardPermissionsFragment extends ManagePermissionsFr
         autoRevokePreference.setTitle(R.string.auto_revoke_permission_notification_title);
         autoRevokePreference.setSummary(R.string.auto_revoke_setting_subtitle);
         autoRevokePreference.setOnPreferenceClickListener(preference -> {
+            PermissionControllerStatsLog.write(
+                    PERMISSION_MANAGER_PAGE_INTERACTION,
+                    mSessionId,
+                    PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__UNUSED_APPS_LEARN_MORE_CLICKED,
+                    null
+            );
             mViewModel.showAutoRevoke(this, UnusedAppsFragment.createArgs(
                     getArguments().getLong(EXTRA_SESSION_ID, INVALID_SESSION_ID)));
             return true;
@@ -219,6 +243,12 @@ public final class ManageStandardPermissionsFragment extends ManagePermissionsFr
 
     @Override
     public void showPermissionApps(String permissionGroupName) {
+        PermissionControllerStatsLog.write(
+                PERMISSION_MANAGER_PAGE_INTERACTION,
+                mSessionId,
+                PERMISSION_MANAGER_PAGE_INTERACTION__ACTION__STANDARD_PERMISSION_GROUP_CLICKED,
+                permissionGroupName
+        );
         // If we return to this page within a reasonable time, prioritize loading data from the
         // permission group whose page we are going to, as that is group most likely to have changed
         getPermGroupsLiveData().setFirstLoadGroup(permissionGroupName);
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/MultiTargetSwitchPreference.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/MultiTargetSwitchPreference.java
index 955428a657..f72c084f64 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/MultiTargetSwitchPreference.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/MultiTargetSwitchPreference.java
@@ -14,6 +14,8 @@
 * limitations under the License.
 */
 
+// LINT.IfChange
+
 package com.android.permissioncontroller.permission.ui.handheld;
 
 import android.content.Context;
@@ -61,3 +63,4 @@ class MultiTargetSwitchPreference extends SwitchPreference {
         }
     }
 }
+// LINT.ThenChange(../v36/MultiTargetSwitchPreferenceCompat.java)
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionFooterPreference.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionFooterPreference.kt
index e7749d827c..6c2fa2fb5d 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionFooterPreference.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionFooterPreference.kt
@@ -22,6 +22,7 @@ import android.view.View
 import com.android.modules.utils.build.SdkLevel
 import com.android.permissioncontroller.R
 import com.android.settingslib.widget.FooterPreference
+import com.android.settingslib.widget.SettingsThemeHelper
 
 class PermissionFooterPreference : FooterPreference {
     constructor(context: Context) : super(context)
@@ -30,7 +31,9 @@ class PermissionFooterPreference : FooterPreference {
 
     init {
         if (SdkLevel.isAtLeastV()) {
-            layoutResource = R.layout.permission_footer_preference
+            if (!SettingsThemeHelper.isExpressiveTheme(context)) {
+                layoutResource = R.layout.permission_footer_preference
+            }
             if (context.resources.getBoolean(R.bool.config_permissionFooterPreferenceIconVisible)) {
                 setIconVisibility(View.VISIBLE)
             } else {
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionPreference.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionPreference.kt
index 010ca28a73..258af2db48 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionPreference.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionPreference.kt
@@ -24,6 +24,7 @@ import androidx.preference.Preference
 import com.android.modules.utils.build.SdkLevel
 import com.android.permissioncontroller.DeviceUtils
 import com.android.permissioncontroller.R
+import com.android.settingslib.widget.SettingsThemeHelper
 
 open class PermissionPreference : Preference {
     constructor(context: Context) : super(context)
@@ -44,7 +45,11 @@ open class PermissionPreference : Preference {
     ) : super(context, attrs, defStyleAttr, defStyleRes)
 
     init {
-        if (SdkLevel.isAtLeastV() && DeviceUtils.isHandheld(context)) {
+        if (
+            SdkLevel.isAtLeastV() &&
+                DeviceUtils.isHandheld(context) &&
+                !SettingsThemeHelper.isExpressiveTheme(context)
+        ) {
             layoutResource = R.layout.permission_preference
         }
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionsFrameFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionsFrameFragment.java
index af204d7d45..c07720610b 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionsFrameFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/PermissionsFrameFragment.java
@@ -29,7 +29,6 @@ import android.view.animation.AnimationUtils;
 import android.widget.TextView;
 
 import androidx.annotation.NonNull;
-import androidx.preference.PreferenceFragmentCompat;
 import androidx.preference.PreferenceScreen;
 import androidx.recyclerview.widget.RecyclerView;
 
@@ -39,8 +38,13 @@ import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.permission.ui.handheld.v35.SectionPreferenceGroupAdapter;
 import com.android.permissioncontroller.permission.utils.Utils;
 import com.android.settingslib.widget.ActionBarShadowController;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
-public abstract class PermissionsFrameFragment extends PreferenceFragmentCompat {
+// TODO: b/375480009 - After using SettingsBasePreferenceFragment as the base class for our
+//  fragments, we must ensure that we migrate to SettingsPreferenceGroupAdapter, and that doing so
+//  does not break UI customization.
+public abstract class PermissionsFrameFragment extends SettingsBasePreferenceFragment {
     private static final String LOG_TAG = PermissionsFrameFragment.class.getSimpleName();
 
     static final int MENU_ALL_PERMS = Menu.FIRST + 1;
@@ -124,7 +128,8 @@ public abstract class PermissionsFrameFragment extends PreferenceFragmentCompat
 
     @Override
     public RecyclerView.Adapter onCreateAdapter(@NonNull PreferenceScreen preferenceScreen) {
-        if (SdkLevel.isAtLeastV() && DeviceUtils.isHandheld(requireContext())) {
+        if (SdkLevel.isAtLeastV() && DeviceUtils.isHandheld(requireContext())
+                && !SettingsThemeHelper.isExpressiveTheme(requireContext())) {
             return new SectionPreferenceGroupAdapter(preferenceScreen);
         } else {
             return super.onCreateAdapter(preferenceScreen);
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ReviewPermissionsFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ReviewPermissionsFragment.java
index 73366f4cde..e3df0895e9 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ReviewPermissionsFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/ReviewPermissionsFragment.java
@@ -66,6 +66,7 @@ import com.android.permissioncontroller.permission.ui.model.ReviewPermissionsVie
 import com.android.permissioncontroller.permission.ui.model.ReviewPermissionsViewModel.PermissionTarget;
 import com.android.permissioncontroller.permission.utils.KotlinUtils;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
 
 import java.util.ArrayList;
 import java.util.List;
@@ -76,7 +77,7 @@ import java.util.Random;
  * If an app does not support runtime permissions the user is prompted via this fragment to select
  * which permissions to grant to the app before first use and if an update changed the permissions.
  */
-public final class ReviewPermissionsFragment extends PreferenceFragmentCompat
+public final class ReviewPermissionsFragment extends SettingsBasePreferenceFragment
         implements View.OnClickListener,
         BasePermissionReviewPreference.PermissionPreferenceChangeListener,
         BasePermissionReviewPreference.PermissionPreferenceOwnerFragment {
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/PermissionHistoryPreference.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/PermissionHistoryPreference.java
index 3be9434b25..21a03a7479 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/PermissionHistoryPreference.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/PermissionHistoryPreference.java
@@ -49,6 +49,7 @@ import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.permission.compat.IntentCompat;
 import com.android.permissioncontroller.permission.ui.model.v31.PermissionUsageDetailsViewModel;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import java.util.Objects;
 import java.util.Set;
@@ -138,6 +139,9 @@ public class PermissionHistoryPreference extends Preference {
         setInfoIcon(holder, widgetView, dividerVerticalBar);
 
         View dashLine = widget.findViewById(R.id.permission_history_dash_line);
+        if (SettingsThemeHelper.isExpressiveTheme(mContext)) {
+            dashLine.setBackgroundResource(R.drawable.permission_history_dash_line_expressive);
+        }
         dashLine.setVisibility(mIsLastUsage ? View.GONE : View.VISIBLE);
 
         // This Intent should ideally be part of the constructor, passed in from the ViewModel.
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/ReviewOngoingUsageFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/ReviewOngoingUsageFragment.java
index 216d208774..aa96f91d09 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/ReviewOngoingUsageFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v31/ReviewOngoingUsageFragment.java
@@ -40,7 +40,6 @@ import android.widget.TextView;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.lifecycle.ViewModelProvider;
-import androidx.preference.PreferenceFragmentCompat;
 
 import com.android.permissioncontroller.PermissionControllerStatsLog;
 import com.android.permissioncontroller.R;
@@ -49,6 +48,7 @@ import com.android.permissioncontroller.permission.ui.model.v31.ReviewOngoingUsa
 import com.android.permissioncontroller.permission.ui.model.v31.ReviewOngoingUsageViewModelFactory;
 import com.android.permissioncontroller.permission.utils.KotlinUtils;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
 
 import java.text.Collator;
 import java.util.ArrayList;
@@ -60,7 +60,7 @@ import java.util.Set;
 /**
  * A dialog listing the currently uses of camera, microphone, and location.
  */
-public class ReviewOngoingUsageFragment extends PreferenceFragmentCompat {
+public class ReviewOngoingUsageFragment extends SettingsBasePreferenceFragment {
     private static final String LOG_TAG = ReviewOngoingUsageFragment.class.getSimpleName();
 
     // TODO: Replace with OPSTR... APIs
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v34/PermissionRationaleViewHandlerImpl.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v34/PermissionRationaleViewHandlerImpl.kt
index 9eb7a0fa4f..c59dc85219 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v34/PermissionRationaleViewHandlerImpl.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v34/PermissionRationaleViewHandlerImpl.kt
@@ -37,6 +37,7 @@ import androidx.core.text.method.LinkMovementMethodCompat
 import com.android.permissioncontroller.R
 import com.android.permissioncontroller.permission.ui.v34.PermissionRationaleViewHandler
 import com.android.permissioncontroller.permission.ui.v34.PermissionRationaleViewHandler.Result.Companion.CANCELLED
+import com.android.settingslib.widget.SettingsThemeHelper
 
 /**
  * Handheld implementation of [PermissionRationaleViewHandler]. Used for managing the presentation
@@ -46,7 +47,7 @@ import com.android.permissioncontroller.permission.ui.v34.PermissionRationaleVie
 class PermissionRationaleViewHandlerImpl(
     private val mActivity: Activity,
     private val resultListener: PermissionRationaleViewHandler.ResultListener,
-    private val shouldShowSettingsSection: Boolean
+    private val shouldShowSettingsSection: Boolean,
 ) : PermissionRationaleViewHandler, OnClickListener {
 
     private var groupName: String? = null
@@ -94,7 +95,7 @@ class PermissionRationaleViewHandlerImpl(
         purposeTitle: CharSequence,
         purposeMessage: CharSequence,
         learnMoreMessage: CharSequence,
-        settingsMessage: CharSequence
+        settingsMessage: CharSequence,
     ) {
         this.groupName = groupName
         this.title = title
@@ -128,8 +129,13 @@ class PermissionRationaleViewHandlerImpl(
     }
 
     override fun createView(): View {
-        val rootView =
-            LayoutInflater.from(mActivity).inflate(R.layout.permission_rationale, null) as ViewGroup
+        val layoutResource =
+            if (SettingsThemeHelper.isExpressiveTheme(mActivity)) {
+                R.layout.permission_rationale_expressive
+            } else {
+                R.layout.permission_rationale
+            }
+        val rootView = LayoutInflater.from(mActivity).inflate(layoutResource, null) as ViewGroup
 
         // Uses the vertical gravity of the PermissionGrantSingleton style to position the window
         val gravity =
@@ -164,10 +170,13 @@ class PermissionRationaleViewHandlerImpl(
             rootView.findViewById<Button>(R.id.back_button)!!.apply {
                 setOnClickListener(this@PermissionRationaleViewHandlerImpl)
 
-                // Load the text color from the activity theme rather than the Material Design theme
-                val textColor =
-                    getColorStateListForAttr(mActivity, android.R.attr.textColorPrimary)!!
-                setTextColor(textColor)
+                if (!SettingsThemeHelper.isExpressiveTheme(mActivity)) {
+                    // Load the text color from the activity theme rather than the Material Design
+                    // theme
+                    val textColor =
+                        getColorStateListForAttr(mActivity, android.R.attr.textColorPrimary)!!
+                    setTextColor(textColor)
+                }
             }
 
         this.rootView = rootView
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFooterLinkPreference.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFooterLinkPreference.kt
index 01554880a7..a2eac967b6 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFooterLinkPreference.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFooterLinkPreference.kt
@@ -26,9 +26,10 @@ import androidx.annotation.StyleRes
 import androidx.preference.PreferenceViewHolder
 import com.android.permissioncontroller.R
 import com.android.permissioncontroller.permission.ui.handheld.PermissionPreference
+import com.android.settingslib.widget.GroupSectionDividerMixin
 
 @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
-class AppPermissionFooterLinkPreference : PermissionPreference {
+class AppPermissionFooterLinkPreference : PermissionPreference, GroupSectionDividerMixin {
     constructor(context: Context) : super(context)
 
     constructor(context: Context, attrs: AttributeSet?) : super(context, attrs)
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFragment.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFragment.java
index 768b00e395..d534fdf170 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/AppPermissionFragment.java
@@ -82,7 +82,6 @@ import com.android.permissioncontroller.permission.ui.handheld.PermissionAppsFra
 import com.android.permissioncontroller.permission.ui.handheld.PermissionFooterPreference;
 import com.android.permissioncontroller.permission.ui.handheld.PermissionPreference;
 import com.android.permissioncontroller.permission.ui.handheld.PermissionPreferenceCategory;
-import com.android.permissioncontroller.permission.ui.handheld.PermissionSwitchPreference;
 import com.android.permissioncontroller.permission.ui.handheld.SettingsWithLargeHeader;
 import com.android.permissioncontroller.permission.ui.model.AppPermissionViewModel;
 import com.android.permissioncontroller.permission.ui.model.AppPermissionViewModel.ButtonState;
@@ -96,6 +95,7 @@ import com.android.permissioncontroller.permission.utils.v35.MultiDeviceUtils;
 import com.android.settingslib.RestrictedLockUtils;
 import com.android.settingslib.RestrictedLockUtils.EnforcedAdmin;
 import com.android.settingslib.widget.SelectorWithWidgetPreference;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import kotlin.Pair;
 
@@ -130,7 +130,7 @@ public class AppPermissionFragment extends SettingsWithLargeHeader
     private @NonNull SelectorWithWidgetPreference mAskButton;
     private @NonNull SelectorWithWidgetPreference mDenyButton;
     private @NonNull SelectorWithWidgetPreference mDenyForegroundButton;
-    private @NonNull PermissionSwitchPreference mLocationAccuracySwitch;
+    private @NonNull TwoStatePreference mLocationAccuracySwitch;
     private @NonNull PermissionTwoTargetPreference mDetails;
     private @NonNull AppPermissionFooterLinkPreference mFooterLink1;
     private @NonNull AppPermissionFooterLinkPreference mFooterLink2;
@@ -222,7 +222,12 @@ public class AppPermissionFragment extends SettingsWithLargeHeader
         mAskButton = requirePreference("app_permission_ask_radio_button");
         mDenyButton = requirePreference("app_permission_deny_radio_button");
         mDenyForegroundButton = requirePreference("app_permission_deny_foreground_radio_button");
-        mLocationAccuracySwitch = requirePreference("app_permission_location_accuracy_switch");
+        if (SettingsThemeHelper.isExpressiveTheme(getContext())) {
+            mLocationAccuracySwitch =
+                    requirePreference("app_permission_location_accuracy_switch_compat");
+        } else {
+            mLocationAccuracySwitch = requirePreference("app_permission_location_accuracy_switch");
+        }
         mDetails = requirePreference("app_permission_details");
         mFooterLink1 = requirePreference("app_permission_footer_link_1");
         mFooterLink2 = requirePreference("app_permission_footer_link_2");
@@ -311,7 +316,7 @@ public class AppPermissionFragment extends SettingsWithLargeHeader
     }
 
     private void showPermissionRationaleDialog(Boolean showPermissionRationale) {
-        showPermissionRationaleDialog(showPermissionRationale == Boolean.TRUE);
+        showPermissionRationaleDialog(Objects.equals(showPermissionRationale, Boolean.TRUE));
     }
 
     private void showPermissionRationaleDialog(boolean showPermissionRationale) {
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/MultiTargetSwitchPreferenceCompat.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/MultiTargetSwitchPreferenceCompat.java
new file mode 100644
index 0000000000..baccd7df45
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/MultiTargetSwitchPreferenceCompat.java
@@ -0,0 +1,76 @@
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
+
+// LINT.IfChange
+
+package com.android.permissioncontroller.permission.ui.handheld.v36;
+
+import android.content.Context;
+import android.os.Build;
+import android.view.View;
+
+import androidx.annotation.RequiresApi;
+import androidx.preference.PreferenceViewHolder;
+import androidx.preference.SwitchPreferenceCompat;
+
+/**
+ * {@link com.android.permissioncontroller.permission.ui.handheld.MultiTargetSwitchPreference} that
+ * extends {@link SwitchPreferenceCompat}
+ */
+@RequiresApi(Build.VERSION_CODES.BAKLAVA)
+public class MultiTargetSwitchPreferenceCompat extends SwitchPreferenceCompat {
+    private View.OnClickListener mSwitchOnClickLister;
+
+    public MultiTargetSwitchPreferenceCompat(Context context) {
+        super(context);
+    }
+
+    /**
+     * Calls {@link SwitchPreferenceCompat#setCheckedOverride} without checking for
+     * SwitchOnClickListener
+     */
+    public void setCheckedOverride(boolean checked) {
+        super.setChecked(checked);
+    }
+
+    @Override
+    public void setChecked(boolean checked) {
+        // If double target behavior is enabled do nothing
+        if (mSwitchOnClickLister == null) {
+            super.setChecked(checked);
+        }
+    }
+
+    public void setSwitchOnClickListener(View.OnClickListener listener) {
+        mSwitchOnClickLister = listener;
+    }
+
+    @Override
+    public void onBindViewHolder(PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        View switchView = holder.itemView.findViewById(androidx.preference.R.id.switchWidget);
+        if (switchView != null) {
+            switchView.setOnClickListener(mSwitchOnClickLister);
+
+            if (mSwitchOnClickLister != null) {
+                final int padding = (int) ((holder.itemView.getMeasuredHeight()
+                        - switchView.getMeasuredHeight()) / 2 + 0.5f);
+                switchView.setPaddingRelative(padding, padding, 0, padding);
+            }
+        }
+    }
+}
+// LINT.ThenChange(../MultiTargetSwitchPreference.java)
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionSelectorWithWidgetPreference.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionSelectorWithWidgetPreference.kt
index 1574eaba39..ee44e5e632 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionSelectorWithWidgetPreference.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionSelectorWithWidgetPreference.kt
@@ -28,6 +28,7 @@ import androidx.preference.PreferenceViewHolder
 import com.android.permissioncontroller.R
 import com.android.permissioncontroller.permission.utils.ResourceUtils
 import com.android.settingslib.widget.SelectorWithWidgetPreference
+import com.android.settingslib.widget.SettingsThemeHelper
 
 /**
  * A `SelectorWithWidgetPreference` with additional features:
@@ -59,8 +60,10 @@ class PermissionSelectorWithWidgetPreference : SelectorWithWidgetPreference {
     }
 
     private fun init(context: Context, attrs: AttributeSet?) {
-        layoutResource = R.layout.permission_preference_selector_with_widget
-        widgetLayoutResource = R.layout.permission_preference_widget_radiobutton
+        if (!SettingsThemeHelper.isExpressiveTheme(context)) {
+            layoutResource = R.layout.permission_preference_selector_with_widget
+            widgetLayoutResource = R.layout.permission_preference_widget_radiobutton
+        }
         extraWidgetIconRes =
             ResourceUtils.getResourceIdByAttr(context, attrs, R.attr.extraWidgetIcon)
         extraWidgetIdRes = ResourceUtils.getResourceIdByAttr(context, attrs, R.attr.extraWidgetId)
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionTwoTargetPreference.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionTwoTargetPreference.kt
index a3a3172e83..230f7a1bee 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionTwoTargetPreference.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/handheld/v36/PermissionTwoTargetPreference.kt
@@ -27,6 +27,7 @@ import androidx.annotation.StyleRes
 import androidx.preference.PreferenceViewHolder
 import com.android.permissioncontroller.R
 import com.android.permissioncontroller.permission.utils.ResourceUtils
+import com.android.settingslib.widget.SettingsThemeHelper
 import com.android.settingslib.widget.TwoTargetPreference
 
 /**
@@ -62,7 +63,9 @@ class PermissionTwoTargetPreference : TwoTargetPreference {
     }
 
     private fun init(context: Context, attrs: AttributeSet?) {
-        layoutResource = R.layout.permission_preference_two_target
+        if (!SettingsThemeHelper.isExpressiveTheme(context)) {
+            layoutResource = R.layout.permission_preference_two_target
+        }
         extraWidgetIconRes =
             ResourceUtils.getResourceIdByAttr(context, attrs, R.attr.extraWidgetIcon)
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/model/AppPermissionViewModel.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/model/AppPermissionViewModel.kt
index 8a9408517c..2da7daf764 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/model/AppPermissionViewModel.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/model/AppPermissionViewModel.kt
@@ -1533,7 +1533,11 @@ class AppPermissionViewModel(
      * READ_MEDIA_VISUAL_USER_SELECTED and/or ACCESS_MEDIA_LOCATION granted
      */
     private fun isPartialStorageGrant(group: LightAppPermGroup): Boolean {
-        if (!isPhotoPickerPromptEnabled() || group.permGroupName != READ_MEDIA_VISUAL) {
+        if (
+            !isPhotoPickerPromptEnabled() ||
+            group.permGroupName != READ_MEDIA_VISUAL ||
+            group.specialFixedStorageGrant
+        ) {
             return false
         }
 
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/model/GrantPermissionsViewModel.kt b/PermissionController/src/com/android/permissioncontroller/permission/ui/model/GrantPermissionsViewModel.kt
index 1e5b96c2e9..0c6ea82dd2 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/model/GrantPermissionsViewModel.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/model/GrantPermissionsViewModel.kt
@@ -1116,8 +1116,8 @@ class GrantPermissionsViewModel(
         if (currCallback == null || requestCode != currCallback.requestCode) {
             return
         }
-        currCallback.consumer.accept(data)
         activityResultCallback = null
+        currCallback.consumer.accept(data)
     }
 
     fun handleHealthConnectPermissions(activity: Activity) {
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/ui/v34/PermissionRationaleActivity.java b/PermissionController/src/com/android/permissioncontroller/permission/ui/v34/PermissionRationaleActivity.java
index 606ce8157c..5a07bda68e 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/ui/v34/PermissionRationaleActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/ui/v34/PermissionRationaleActivity.java
@@ -57,6 +57,7 @@ import androidx.annotation.RequiresApi;
 import androidx.annotation.StringRes;
 import androidx.core.util.Preconditions;
 
+import com.android.modules.utils.build.SdkLevel;
 import com.android.permission.safetylabel.DataPurposeConstants.Purpose;
 import com.android.permissioncontroller.Constants;
 import com.android.permissioncontroller.DeviceUtils;
@@ -70,6 +71,8 @@ import com.android.permissioncontroller.permission.ui.model.v34.PermissionRation
 import com.android.permissioncontroller.permission.ui.model.v34.PermissionRationaleViewModelFactory;
 import com.android.permissioncontroller.permission.utils.KotlinUtils;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider;
+import com.android.settingslib.widget.theme.flags.Flags;
 
 import org.jetbrains.annotations.Nullable;
 
@@ -87,7 +90,7 @@ import java.util.stream.Collectors;
  */
 @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
 public class PermissionRationaleActivity extends SettingsActivity implements
-        PermissionRationaleViewHandler.ResultListener {
+        PermissionRationaleViewHandler.ResultListener, ExpressiveDesignEnabledProvider {
 
     private static final String LOG_TAG = PermissionRationaleActivity.class.getSimpleName();
 
@@ -335,6 +338,13 @@ public class PermissionRationaleActivity extends SettingsActivity implements
         }
     }
 
+    @Override
+    public boolean isExpressiveDesignEnabled() {
+        return SdkLevel.isAtLeastB() && DeviceUtils.isHandheld()
+                && Flags.isExpressiveDesignEnabled() && getResources().getBoolean(
+                R.bool.config_enableExpressiveDesignInRequestPermissionDialog);
+    }
+
     private void onPermissionRationaleInfoLoad(PermissionRationaleInfo permissionRationaleInfo) {
         if (!mViewModel.getPermissionRationaleInfoLiveData().isInitialized()) {
             return;
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/utils/KotlinUtils.kt b/PermissionController/src/com/android/permissioncontroller/permission/utils/KotlinUtils.kt
index 51f098371f..072ef433b3 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/utils/KotlinUtils.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/utils/KotlinUtils.kt
@@ -40,6 +40,7 @@ import android.content.Intent
 import android.content.Intent.ACTION_MAIN
 import android.content.Intent.CATEGORY_INFO
 import android.content.Intent.CATEGORY_LAUNCHER
+import android.content.pm.PackageInfo
 import android.content.pm.PackageManager
 import android.content.pm.PackageManager.FLAG_PERMISSION_AUTO_REVOKED
 import android.content.pm.PackageManager.FLAG_PERMISSION_ONE_TIME
@@ -1144,7 +1145,7 @@ object KotlinUtils {
                 group.specialFixedStorageGrant,
             )
 
-        if (wasOneTime && !anyPermsOfPackageOneTimeGranted(app, newGroup.packageInfo, newGroup)) {
+        if (wasOneTime && !anyPermsOfPackageOneTimeGranted(app, newGroup.packageInfo)) {
             // Create a new context with the given deviceId so that permission updates will be bound
             // to the device
             val context = ContextCompat.createDeviceContext(app.applicationContext, deviceId)
@@ -1189,30 +1190,24 @@ object KotlinUtils {
      *
      * @param app The current application
      * @param packageInfo The packageInfo we wish to examine
-     * @param group Optional, the current app permission group we are examining
      * @return true if any permission in the package is granted for one time, false otherwise
      */
     @Suppress("MissingPermission")
     private fun anyPermsOfPackageOneTimeGranted(
         app: Application,
         packageInfo: LightPackageInfo,
-        group: LightAppPermGroup? = null,
     ): Boolean {
-        val user = group?.userHandle ?: UserHandle.getUserHandleForUid(packageInfo.uid)
-        if (group?.isOneTime == true) {
-            return true
-        }
-        for ((idx, permName) in packageInfo.requestedPermissions.withIndex()) {
-            if (permName in group?.permissions ?: emptyMap()) {
+        val user = UserHandle.getUserHandleForUid(packageInfo.uid)
+        for ((index, permName) in packageInfo.requestedPermissions.withIndex()) {
+            if ((packageInfo.requestedPermissionsFlags[index] and
+                        PackageInfo.REQUESTED_PERMISSION_GRANTED) == 0) {
                 continue
             }
             val flags =
-                app.packageManager.getPermissionFlags(permName, packageInfo.packageName, user) and
-                    FLAG_PERMISSION_ONE_TIME
-            val granted =
-                packageInfo.requestedPermissionsFlags[idx] == PackageManager.PERMISSION_GRANTED &&
-                    (flags and FLAG_PERMISSION_REVOKED_COMPAT) == 0
-            if (granted && (flags and FLAG_PERMISSION_ONE_TIME) != 0) {
+                app.packageManager.getPermissionFlags(permName, packageInfo.packageName, user)
+            val isGrantedOneTime = (flags and FLAG_PERMISSION_REVOKED_COMPAT) == 0 &&
+                    (flags and FLAG_PERMISSION_ONE_TIME) != 0
+            if (isGrantedOneTime) {
                 return true
             }
         }
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/utils/PermissionMapping.kt b/PermissionController/src/com/android/permissioncontroller/permission/utils/PermissionMapping.kt
index 1693b32d1e..0638439639 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/utils/PermissionMapping.kt
+++ b/PermissionController/src/com/android/permissioncontroller/permission/utils/PermissionMapping.kt
@@ -158,7 +158,8 @@ object PermissionMapping {
                 Manifest.permission_group.XR_TRACKING
 
             PLATFORM_PERMISSIONS[Manifest.permission.EYE_TRACKING_FINE] =
-                Manifest.permission_group.XR_TRACKING_SENSITIVE
+                Manifest.permission_group.XR_EYE_SENSITIVE
+
             PLATFORM_PERMISSIONS[Manifest.permission.HEAD_TRACKING] =
                 Manifest.permission_group.XR_TRACKING_SENSITIVE
             PLATFORM_PERMISSIONS[Manifest.permission.SCENE_UNDERSTANDING_FINE] =
diff --git a/PermissionController/src/com/android/permissioncontroller/permission/utils/Utils.java b/PermissionController/src/com/android/permissioncontroller/permission/utils/Utils.java
index 149bc4efc9..ae5dc702f4 100644
--- a/PermissionController/src/com/android/permissioncontroller/permission/utils/Utils.java
+++ b/PermissionController/src/com/android/permissioncontroller/permission/utils/Utils.java
@@ -115,7 +115,6 @@ import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.permission.model.AppPermissionGroup;
 import com.android.permissioncontroller.permission.model.livedatatypes.LightAppPermGroup;
 import com.android.permissioncontroller.permission.model.livedatatypes.LightPackageInfo;
-import com.android.settingslib.widget.SettingsThemeHelper;
 
 import kotlin.Triple;
 
@@ -900,7 +899,7 @@ public final class Utils {
      * when the platform is T+, and the package has legacy storage access (i.e., either the package
      * has a targetSdk less than Q, or has a targetSdk equal to Q and has OPSTR_LEGACY_STORAGE).
      *
-     * TODO jaysullivan: This is always calling AppOpsManager; not taking advantage of LiveData
+     * NOTE: This is always calling AppOpsManager; not taking advantage of LiveData
      *
      * @param pkg The package to check
      */
@@ -1069,14 +1068,6 @@ public final class Utils {
         }
     }
 
-    /**
-     * Whether Expressive Design is enabled on this device.
-     */
-    public static boolean isExpressiveDesignEnabled(@NonNull Context context) {
-        return SdkLevel.isAtLeastB() && DeviceUtils.isHandheld()
-                && SettingsThemeHelper.isExpressiveTheme(context);
-    }
-
     /**
      * Returns true if the group name passed is that of the Platform health group.
      * @param permGroupName name of the group that needs to be checked.
diff --git a/PermissionController/src/com/android/permissioncontroller/privacysources/SafetyCenterReceiver.kt b/PermissionController/src/com/android/permissioncontroller/privacysources/SafetyCenterReceiver.kt
index 885b8ea869..2b9c1cb6dc 100644
--- a/PermissionController/src/com/android/permissioncontroller/privacysources/SafetyCenterReceiver.kt
+++ b/PermissionController/src/com/android/permissioncontroller/privacysources/SafetyCenterReceiver.kt
@@ -23,6 +23,7 @@ import android.content.Intent
 import android.content.Intent.ACTION_BOOT_COMPLETED
 import android.content.pm.PackageManager
 import android.os.Build
+import android.permission.flags.Flags
 import android.provider.DeviceConfig
 import android.safetycenter.SafetyCenterManager
 import android.safetycenter.SafetyCenterManager.ACTION_REFRESH_SAFETY_SOURCES
@@ -39,6 +40,8 @@ import com.android.permissioncontroller.permission.utils.Utils
 import com.android.permissioncontroller.privacysources.WorkPolicyInfo.Companion.WORK_POLICY_INFO_SOURCE_ID
 import com.android.permissioncontroller.privacysources.v34.AppDataSharingUpdatesPrivacySource
 import com.android.permissioncontroller.privacysources.v34.AppDataSharingUpdatesPrivacySource.Companion.APP_DATA_SHARING_UPDATES_SOURCE_ID
+import com.android.permissioncontroller.privacysources.v36r1.AppFunctionAccessPrivacySource
+import com.android.permissioncontroller.privacysources.v36r1.AppFunctionAccessPrivacySource.Companion.APP_FUNCTION_ACCESS_SOURCE_ID
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers.Default
@@ -59,6 +62,10 @@ private fun createMapOfSourceIdsToSources(context: Context): Map<String, Privacy
         sourceMap[APP_DATA_SHARING_UPDATES_SOURCE_ID] = AppDataSharingUpdatesPrivacySource()
     }
 
+    if (SdkLevel.isAtLeastB() && Flags.appFunctionAccessUiEnabled()) {
+        sourceMap[APP_FUNCTION_ACCESS_SOURCE_ID] = AppFunctionAccessPrivacySource()
+    }
+
     return sourceMap
 }
 
@@ -66,13 +73,13 @@ private fun createMapOfSourceIdsToSources(context: Context): Map<String, Privacy
 class SafetyCenterReceiver(
     private val getMapOfSourceIdsToSources: (Context) -> Map<String, PrivacySource> =
         ::createMapOfSourceIdsToSources,
-    private val dispatcher: CoroutineDispatcher = Default
+    private val dispatcher: CoroutineDispatcher = Default,
 ) : BroadcastReceiver() {
 
     enum class RefreshEvent {
         UNKNOWN,
         EVENT_DEVICE_REBOOTED,
-        EVENT_REFRESH_REQUESTED
+        EVENT_REFRESH_REQUESTED,
     }
 
     override fun onReceive(context: Context, intent: Intent) {
@@ -82,7 +89,7 @@ class SafetyCenterReceiver(
         val safetyCenterManager: SafetyCenterManager =
             Utils.getSystemServiceSafe(
                 PermissionControllerApplication.get().applicationContext,
-                SafetyCenterManager::class.java
+                SafetyCenterManager::class.java,
             )
 
         val mapOfSourceIdsToSources = getMapOfSourceIdsToSources(context)
@@ -92,7 +99,7 @@ class SafetyCenterReceiver(
                 safetyCenterEnabledChanged(
                     context,
                     safetyCenterManager.isSafetyCenterEnabled,
-                    mapOfSourceIdsToSources.values
+                    mapOfSourceIdsToSources.values,
                 )
             }
             ACTION_REFRESH_SAFETY_SOURCES -> {
@@ -104,7 +111,7 @@ class SafetyCenterReceiver(
                             intent,
                             RefreshEvent.EVENT_REFRESH_REQUESTED,
                             mapOfSourceIdsToSources,
-                            sourceIdsExtra.toList()
+                            sourceIdsExtra.toList(),
                         )
                     }
                 }
@@ -117,7 +124,7 @@ class SafetyCenterReceiver(
                         intent,
                         RefreshEvent.EVENT_DEVICE_REBOOTED,
                         mapOfSourceIdsToSources,
-                        mapOfSourceIdsToSources.keys.toList()
+                        mapOfSourceIdsToSources.keys.toList(),
                     )
                 }
             }
@@ -127,7 +134,7 @@ class SafetyCenterReceiver(
     private fun safetyCenterEnabledChanged(
         context: Context,
         enabled: Boolean,
-        privacySources: Collection<PrivacySource>
+        privacySources: Collection<PrivacySource>,
     ) {
         privacySources.forEach { source ->
             CoroutineScope(dispatcher).launch {
@@ -148,19 +155,19 @@ class SafetyCenterReceiver(
             DeviceConfig.getInt(
                 DeviceConfig.NAMESPACE_PRIVACY,
                 QS_TILE_COMPONENT_SETTING_FLAGS,
-                PackageManager.DONT_KILL_APP
+                PackageManager.DONT_KILL_APP,
             )
         if (enabled && !wasEnabled) {
             context.packageManager.setComponentEnabledSetting(
                 tileComponent,
                 PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
-                qsTileComponentSettingFlags
+                qsTileComponentSettingFlags,
             )
         } else if (!enabled && wasEnabled) {
             context.packageManager.setComponentEnabledSetting(
                 tileComponent,
                 PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
-                qsTileComponentSettingFlags
+                qsTileComponentSettingFlags,
             )
         }
     }
@@ -170,7 +177,7 @@ class SafetyCenterReceiver(
         intent: Intent,
         refreshEvent: RefreshEvent,
         mapOfSourceIdsToSources: Map<String, PrivacySource>,
-        sourceIdsToRefresh: List<String>
+        sourceIdsToRefresh: List<String>,
     ) {
         for (sourceId in sourceIdsToRefresh) {
             CoroutineScope(dispatcher).launch {
diff --git a/PermissionController/src/com/android/permissioncontroller/privacysources/v36r1/AppFunctionAccessPrivacySource.kt b/PermissionController/src/com/android/permissioncontroller/privacysources/v36r1/AppFunctionAccessPrivacySource.kt
new file mode 100644
index 0000000000..7f08836e6f
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/privacysources/v36r1/AppFunctionAccessPrivacySource.kt
@@ -0,0 +1,115 @@
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
+package com.android.permissioncontroller.privacysources.v36r1
+
+import android.app.PendingIntent
+import android.app.PendingIntent.FLAG_IMMUTABLE
+import android.app.PendingIntent.FLAG_UPDATE_CURRENT
+import android.app.appfunctions.AppFunctionManager
+import android.content.Context
+import android.content.Intent
+import android.permission.flags.Flags
+import android.safetycenter.SafetyCenterManager
+import android.safetycenter.SafetyEvent
+import android.safetycenter.SafetySourceData
+import android.safetycenter.SafetySourceStatus
+import com.android.permissioncontroller.R
+import com.android.permissioncontroller.permission.utils.Utils
+import com.android.permissioncontroller.privacysources.PrivacySource
+import com.android.permissioncontroller.privacysources.SafetyCenterReceiver
+import com.android.permissioncontroller.privacysources.SafetyCenterReceiver.RefreshEvent
+
+/**
+ * Privacy source providing the App Functions Access page entry to Safety Center.
+ *
+ * The content of the App Functions Access page is static, however the entry should only be
+ * displayed if the App Functions Access feature is enabled.
+ */
+class AppFunctionAccessPrivacySource : PrivacySource {
+    override val shouldProcessProfileRequest: Boolean = false
+
+    override fun safetyCenterEnabledChanged(context: Context, enabled: Boolean) {
+        // Do nothing
+    }
+
+    override fun rescanAndPushSafetyCenterData(
+        context: Context,
+        intent: Intent,
+        refreshEvent: SafetyCenterReceiver.RefreshEvent,
+    ) {
+        val safetyCenterManager: SafetyCenterManager =
+            Utils.getSystemServiceSafe(context, SafetyCenterManager::class.java)
+
+        // TODO(b/414805948): Add app function access API flag here once exported
+        val safetySourceData =
+            if (Flags.appFunctionAccessUiEnabled()) {
+                val pendingIntent = getPendingIntentForAppFunctionAgentList(context)
+                val status =
+                    SafetySourceStatus.Builder(
+                            context.getString(R.string.app_function_access_settings_title),
+                            context.getString(R.string.app_function_access_settings_summary),
+                            SafetySourceData.SEVERITY_LEVEL_UNSPECIFIED,
+                        )
+                        .setPendingIntent(pendingIntent)
+                        .build()
+                SafetySourceData.Builder().setStatus(status).build()
+            } else {
+                null
+            }
+
+        safetyCenterManager.setSafetySourceData(
+            APP_FUNCTION_ACCESS_SOURCE_ID,
+            safetySourceData,
+            createSafetyEvent(refreshEvent, intent),
+        )
+    }
+
+    /** Companion object for [AppFunctionAccessPrivacySource]. */
+    companion object {
+        /** Source id for safety center source for app data sharing updates. */
+        const val APP_FUNCTION_ACCESS_SOURCE_ID = "AndroidAppFunctionAccess"
+
+        private fun getPendingIntentForAppFunctionAgentList(context: Context): PendingIntent {
+            val intent = Intent(AppFunctionManager.ACTION_MANAGE_APP_FUNCTION_ACCESS)
+            return PendingIntent.getActivity(
+                context,
+                /* requestCode= */ 0,
+                intent,
+                FLAG_UPDATE_CURRENT or FLAG_IMMUTABLE,
+            )
+        }
+
+        private fun createSafetyEvent(refreshEvent: RefreshEvent, intent: Intent): SafetyEvent {
+            return when (refreshEvent) {
+                RefreshEvent.EVENT_REFRESH_REQUESTED -> {
+                    val refreshBroadcastId =
+                        intent.getStringExtra(
+                            SafetyCenterManager.EXTRA_REFRESH_SAFETY_SOURCES_BROADCAST_ID
+                        )
+                    SafetyEvent.Builder(SafetyEvent.SAFETY_EVENT_TYPE_REFRESH_REQUESTED)
+                        .setRefreshBroadcastId(refreshBroadcastId)
+                        .build()
+                }
+                RefreshEvent.EVENT_DEVICE_REBOOTED -> {
+                    SafetyEvent.Builder(SafetyEvent.SAFETY_EVENT_TYPE_DEVICE_REBOOTED).build()
+                }
+                RefreshEvent.UNKNOWN -> {
+                    SafetyEvent.Builder(SafetyEvent.SAFETY_EVENT_TYPE_SOURCE_STATE_CHANGED).build()
+                }
+            }
+        }
+    }
+}
diff --git a/PermissionController/src/com/android/permissioncontroller/privacysources/v36r1/package-info.java b/PermissionController/src/com/android/permissioncontroller/privacysources/v36r1/package-info.java
new file mode 100644
index 0000000000..442056e148
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/privacysources/v36r1/package-info.java
@@ -0,0 +1,18 @@
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
+
+@androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.BAKLAVA)
+package com.android.permissioncontroller.privacysources.v36r1;
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppActivity.java b/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppActivity.java
index 41f1a06a96..5f8a2b6846 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppActivity.java
@@ -28,7 +28,6 @@ import androidx.annotation.Nullable;
 import androidx.fragment.app.Fragment;
 
 import com.android.permissioncontroller.DeviceUtils;
-import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.role.ui.auto.AutoDefaultAppFragment;
 import com.android.permissioncontroller.role.ui.handheld.HandheldDefaultAppFragment;
 import com.android.permissioncontroller.role.ui.wear.WearDefaultAppFragment;
@@ -61,11 +60,6 @@ public class DefaultAppActivity extends SettingsActivity {
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
-        if (DeviceUtils.isAuto(this)) {
-            // Automotive relies on a different theme. Apply before calling super so that
-            // fragments are restored properly on configuration changes.
-            setTheme(R.style.CarSettings);
-        }
         super.onCreate(savedInstanceState);
 
         Intent intent = getIntent();
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppChildFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppChildFragment.java
index 36d9cc3a06..9380133d87 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppChildFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppChildFragment.java
@@ -72,6 +72,8 @@ public class DefaultAppChildFragment<PF extends PreferenceFragmentCompat
 
     private static final String PREFERENCE_KEY_RECOMMENDED_CATEGORY =
             DefaultAppChildFragment.class.getName() + ".preference.RECOMMENDED_CATEGORY";
+    private static final String PREFERENCE_KEY_RECOMMENDED_DESCRIPTION =
+            DefaultAppChildFragment.class.getName() + ".preference.RECOMMENDED_DESCRIPTION";
     private static final String PREFERENCE_KEY_OTHERS_CATEGORY =
             DefaultAppChildFragment.class.getName() + ".preference.OTHERS_CATEGORY";
     private static final String PREFERENCE_KEY_NONE = DefaultAppChildFragment.class.getName()
@@ -178,16 +180,13 @@ public class DefaultAppChildFragment<PF extends PreferenceFragmentCompat
         }
 
         if (Flags.defaultAppsRecommendationEnabled() && !recommendedApplicationItems.isEmpty()) {
-            addApplicationPreferenceCategory(oldRecommendedPreferenceCategory,
-                    PREFERENCE_KEY_RECOMMENDED_CATEGORY,
-                    getString(R.string.default_app_recommended), preferenceScreen, false, false,
-                    recommendedApplicationItems, oldPreferences, context);
+            addApplicationPreferenceCategory(oldRecommendedPreferenceCategory, true,
+                    preferenceScreen, false, recommendedApplicationItems, oldPreferences, context);
             if (mRole.shouldShowNone() || !otherApplicationItems.isEmpty()) {
                 boolean noneChecked = !(hasHolderApplication(recommendedApplicationItems)
                         || hasHolderApplication(otherApplicationItems));
-                addApplicationPreferenceCategory(oldOthersPreferenceCategory,
-                        PREFERENCE_KEY_OTHERS_CATEGORY, getString(R.string.default_app_others),
-                        preferenceScreen, true, noneChecked, otherApplicationItems, oldPreferences,
+                addApplicationPreferenceCategory(oldOthersPreferenceCategory, false,
+                        preferenceScreen, noneChecked, otherApplicationItems, oldPreferences,
                         context);
             }
         } else {
@@ -225,24 +224,41 @@ public class DefaultAppChildFragment<PF extends PreferenceFragmentCompat
     }
 
     private void addApplicationPreferenceCategory(
-            @Nullable PreferenceCategory oldPreferenceCategory, @NonNull String key,
-            @Nullable String title, @NonNull PreferenceScreen preferenceScreen,
-            boolean addNonePreferenceIfNeeded, boolean noneChecked,
+            @Nullable PreferenceCategory oldPreferenceCategory, boolean isRecommended,
+            @NonNull PreferenceScreen preferenceScreen, boolean noneChecked,
             @NonNull List<RoleApplicationItem> applicationItems,
             @NonNull ArrayMap<String, Preference> oldPreferences, @NonNull Context context) {
         PreferenceCategory preferenceCategory = oldPreferenceCategory;
         if (preferenceCategory == null) {
             preferenceCategory = new PreferenceCategory(context);
-            preferenceCategory.setKey(key);
-            preferenceCategory.setTitle(title);
+            preferenceCategory.setKey(isRecommended ? PREFERENCE_KEY_RECOMMENDED_CATEGORY
+                    : PREFERENCE_KEY_OTHERS_CATEGORY);
+            preferenceCategory.setTitle(isRecommended
+                    ? RoleUiBehaviorUtils.getRecommendedApplicationsTitle(mRole, context)
+                    : getString(R.string.default_app_others));
         }
         preferenceScreen.addPreference(preferenceCategory);
-        if (addNonePreferenceIfNeeded) {
+        if (isRecommended) {
+            addRecommendedDescriptionPreference(preferenceCategory, oldPreferences, context);
+        } else {
             addNonePreferenceIfNeeded(preferenceCategory, noneChecked, oldPreferences, context);
         }
         addApplicationPreferences(preferenceCategory, applicationItems, oldPreferences, context);
     }
 
+    private void addRecommendedDescriptionPreference(@NonNull PreferenceGroup preferenceGroup,
+            @NonNull ArrayMap<String, Preference> oldPreferences, @NonNull Context context) {
+        Preference preference = oldPreferences.get(PREFERENCE_KEY_RECOMMENDED_DESCRIPTION);
+        if (preference == null) {
+            preference = requirePreferenceFragment().createDescriptionPreference(false);
+            preference.setKey(PREFERENCE_KEY_RECOMMENDED_DESCRIPTION);
+            preference.setSummary(
+                    RoleUiBehaviorUtils.getRecommendedApplicationsDescription(mRole, context));
+        }
+
+        preferenceGroup.addPreference(preference);
+    }
+
     private static boolean hasHolderApplication(
             @NonNull List<RoleApplicationItem> applicationItems) {
         int applicationItemsSize = applicationItems.size();
@@ -411,7 +427,7 @@ public class DefaultAppChildFragment<PF extends PreferenceFragmentCompat
             @NonNull ArrayMap<String, Preference> oldPreferences) {
         Preference preference = oldPreferences.get(PREFERENCE_KEY_DESCRIPTION);
         if (preference == null) {
-            preference = requirePreferenceFragment().createFooterPreference();
+            preference = requirePreferenceFragment().createDescriptionPreference(true);
             preference.setKey(PREFERENCE_KEY_DESCRIPTION);
             preference.setSummary(mRole.getDescriptionResource());
         }
@@ -446,12 +462,13 @@ public class DefaultAppChildFragment<PF extends PreferenceFragmentCompat
         RoleApplicationPreference createApplicationPreference();
 
         /**
-         * Create a new preference for the footer.
+         * Create a new preference for a description.
          *
-         * @return a new preference for the footer
+         * @param isFooter whether the description is a footer
+         * @return a new preference for the description
          */
         @NonNull
-        Preference createFooterPreference();
+        Preference createDescriptionPreference(boolean isFooter);
 
         /**
          * Callback when changes have been made to the {@link PreferenceScreen} of the parent
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppListActivity.java b/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppListActivity.java
index 58f35705cd..031aa1e139 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppListActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppListActivity.java
@@ -22,7 +22,6 @@ import androidx.annotation.Nullable;
 import androidx.fragment.app.Fragment;
 
 import com.android.permissioncontroller.DeviceUtils;
-import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.role.ui.auto.AutoDefaultAppListFragment;
 import com.android.permissioncontroller.role.ui.handheld.HandheldDefaultAppListFragment;
 import com.android.permissioncontroller.role.ui.wear.WearDefaultAppListFragment;
@@ -34,12 +33,6 @@ public class DefaultAppListActivity extends SettingsActivity {
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
-        if (DeviceUtils.isAuto(this)) {
-            // Automotive relies on a different theme. Apply before calling super so that
-            // fragments are restored properly on configuration changes.
-            setTheme(R.style.CarSettings);
-        }
-
         super.onCreate(savedInstanceState);
 
         if (savedInstanceState == null) {
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/SettingsActivity.java b/PermissionController/src/com/android/permissioncontroller/role/ui/SettingsActivity.java
index ee5f9a801c..446cc1d6ae 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/SettingsActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/SettingsActivity.java
@@ -21,18 +21,30 @@ import android.view.WindowManager;
 
 import androidx.annotation.Nullable;
 
+import com.android.modules.utils.build.SdkLevel;
 import com.android.permissioncontroller.DeviceUtils;
+import com.android.permissioncontroller.R;
 import com.android.settingslib.collapsingtoolbar.EdgeToEdgeUtils;
 import com.android.settingslib.collapsingtoolbar.SettingsTransitionActivity;
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider;
+import com.android.settingslib.widget.SettingsThemeHelper;
+import com.android.settingslib.widget.theme.flags.Flags;
 
 /**
  * Base class for settings activities.
  */
 // Made public for com.android.permissioncontroller.role.ui.specialappaccess
-public class SettingsActivity extends SettingsTransitionActivity {
+public class SettingsActivity extends SettingsTransitionActivity implements
+        ExpressiveDesignEnabledProvider {
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
+        if (DeviceUtils.isAuto(this)) {
+            // Automotive relies on a different theme.
+            setTheme(R.style.CarSettings);
+        } else if (SettingsThemeHelper.isExpressiveTheme(this)) {
+            setTheme(R.style.Theme_PermissionController_Settings_Expressive_FilterTouches);
+        }
         EdgeToEdgeUtils.enable(this);
 
         super.onCreate(savedInstanceState);
@@ -46,4 +58,10 @@ public class SettingsActivity extends SettingsTransitionActivity {
         return super.isSettingsTransitionEnabled() && !(DeviceUtils.isAuto(this)
                 || DeviceUtils.isTelevision(this) || DeviceUtils.isWear(this));
     }
+
+    @Override
+    public boolean isExpressiveDesignEnabled() {
+        return SdkLevel.isAtLeastB() && DeviceUtils.isHandheld()
+                && Flags.isExpressiveDesignEnabled();
+    }
 }
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoDefaultAppFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoDefaultAppFragment.java
index dc6c03d090..c8938ab409 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoDefaultAppFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoDefaultAppFragment.java
@@ -96,9 +96,11 @@ public class AutoDefaultAppFragment extends AutoSettingsFrameFragment implements
 
     @NonNull
     @Override
-    public Preference createFooterPreference() {
+    public Preference createDescriptionPreference(boolean isFooter) {
         Preference preference = new Preference(requireContext());
-        preference.setIcon(R.drawable.ic_info_outline);
+        if (isFooter) {
+            preference.setIcon(R.drawable.ic_info_outline);
+        }
         preference.setSelectable(false);
         return preference;
     }
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoSpecialAppAccessFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoSpecialAppAccessFragment.java
index c377354277..42c5bd1d74 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoSpecialAppAccessFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/auto/AutoSpecialAppAccessFragment.java
@@ -86,7 +86,7 @@ public class AutoSpecialAppAccessFragment extends AutoSettingsFrameFragment impl
 
     @NonNull
     @Override
-    public Preference createFooterPreference() {
+    public Preference createDescriptionPreference() {
         Preference preference = new Preference(requireContext());
         preference.setIcon(R.drawable.ic_info_outline);
         preference.setSelectable(false);
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/AssistantRoleUiBehavior.java b/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/AssistantRoleUiBehavior.java
index c74c3d5192..02a1fd8dcb 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/AssistantRoleUiBehavior.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/AssistantRoleUiBehavior.java
@@ -52,18 +52,45 @@ public class AssistantRoleUiBehavior implements RoleUiBehavior {
         return new Intent(Settings.ACTION_VOICE_INPUT_SETTINGS);
     }
 
+    @Nullable
+    @Override
+    public String getRecommendedApplicationsTitle(@NonNull Role role, @NonNull Context context) {
+        if (Flags.defaultAppsRecommendationEnabled()) {
+            String by = context.getString(R.string.config_recommendedAssistantsBy);
+            if (!by.isEmpty()) {
+                return context.getString(R.string.role_assistant_recommended_title, by);
+            }
+        }
+        return RoleUiBehavior.super.getRecommendedApplicationsTitle(role, context);
+    }
+
+    @Nullable
+    @Override
+    public String getRecommendedApplicationsDescription(@NonNull Role role,
+            @NonNull Context context) {
+        if (Flags.defaultAppsRecommendationEnabled()) {
+            String description =
+                    context.getString(R.string.config_recommendedAssistantsDescription);
+            if (!description.isEmpty()) {
+                return description;
+            }
+        }
+        return RoleUiBehavior.super.getRecommendedApplicationsDescription(role, context);
+    }
+
     @NonNull
     @Override
     public Predicate<RoleApplicationItem> getRecommendedApplicationFilter(
             @NonNull Role role, @NonNull Context context) {
-        if (Flags.defaultAppsRecommendationEnabled()) {
+        if (Flags.defaultAppsRecommendationEnabled()
+                && getRecommendedApplicationsTitle(role, context) != null
+                && getRecommendedApplicationsDescription(role, context) != null) {
             List<SignedPackage> signedPackages = SignedPackage.parseList(
                     context.getResources().getString(R.string.config_recommendedAssistants));
             return applicationItem -> SignedPackageUtils.matchesAny(
                     applicationItem.getApplicationInfo(), signedPackages, context);
-        } else {
-            return RoleUiBehavior.super.getRecommendedApplicationFilter(role, context);
         }
+        return RoleUiBehavior.super.getRecommendedApplicationFilter(role, context);
     }
 
     @Nullable
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/RoleUiBehavior.java b/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/RoleUiBehavior.java
index e1bf213a04..047c32f0a6 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/RoleUiBehavior.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/behavior/RoleUiBehavior.java
@@ -93,6 +93,35 @@ public interface RoleUiBehavior {
             @NonNull Preference preference, @NonNull ApplicationInfo applicationInfo,
             @NonNull UserHandle user, @NonNull Context context) {}
 
+    /**
+     * Get the title for recommended applications of this role.
+     *
+     * @param role the role to get the recommended applications title for
+     * @param context the {@code Context} to retrieve system services
+     *
+     * @return the title for recommended applications, or {@code null} when recommendation isn't
+     *         enabled
+     */
+    @Nullable
+    default String getRecommendedApplicationsTitle(@NonNull Role role, @NonNull Context context) {
+        return null;
+    }
+
+    /**
+     * Get the description for recommended applications of this role.
+     *
+     * @param role the role to get the recommended applications description for
+     * @param context the {@code Context} to retrieve system services
+     *
+     * @return the description for recommended applications, or {@code null} when recommendation
+     *         isn't enabled
+     */
+    @Nullable
+    default String getRecommendedApplicationsDescription(@NonNull Role role,
+            @NonNull Context context) {
+        return null;
+    }
+
     /**
      * Get the filter for recommended applications of this role.
      *
@@ -102,8 +131,8 @@ public interface RoleUiBehavior {
      * @return the filter for recommended applications
      */
     @NonNull
-    default Predicate<RoleApplicationItem> getRecommendedApplicationFilter(
-            @NonNull Role role, @NonNull Context context) {
+    default Predicate<RoleApplicationItem> getRecommendedApplicationFilter(@NonNull Role role,
+            @NonNull Context context) {
         return applicationItem -> false;
     }
 
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppListPreferenceFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppListPreferenceFragment.java
index da920ea7f8..e0625c8db2 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppListPreferenceFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppListPreferenceFragment.java
@@ -20,17 +20,17 @@ import android.os.Bundle;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
-import androidx.preference.PreferenceFragmentCompat;
 
 import com.android.permissioncontroller.role.ui.DefaultAppListChildFragment;
 import com.android.permissioncontroller.role.ui.RolePreference;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
 
 /**
  * Handheld preference fragment for the list of default apps.
  * <p>
  * Must be added as a child fragment and its parent fragment must implement {@link Parent}.
  */
-public class HandheldDefaultAppListPreferenceFragment extends PreferenceFragmentCompat
+public class HandheldDefaultAppListPreferenceFragment extends SettingsBasePreferenceFragment
         implements DefaultAppListChildFragment.Parent {
 
     /**
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppPreferenceFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppPreferenceFragment.java
index b8156590a4..5359f3c9a2 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppPreferenceFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDefaultAppPreferenceFragment.java
@@ -23,18 +23,17 @@ import android.os.UserHandle;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.preference.Preference;
-import androidx.preference.PreferenceFragmentCompat;
 
 import com.android.permissioncontroller.role.ui.DefaultAppChildFragment;
 import com.android.permissioncontroller.role.ui.RoleApplicationPreference;
-import com.android.settingslib.widget.FooterPreference;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
 
 /**
  * Handheld preference fragment for a default app.
  * <p>
  * Must be added as a child fragment and its parent fragment must implement {@link Parent}.
  */
-public class HandheldDefaultAppPreferenceFragment extends PreferenceFragmentCompat
+public class HandheldDefaultAppPreferenceFragment extends SettingsBasePreferenceFragment
         implements DefaultAppChildFragment.Parent {
 
     @NonNull
@@ -101,8 +100,8 @@ public class HandheldDefaultAppPreferenceFragment extends PreferenceFragmentComp
 
     @NonNull
     @Override
-    public Preference createFooterPreference() {
-        return new FooterPreference(requireContext());
+    public Preference createDescriptionPreference(boolean isFooter) {
+        return new HandheldDescriptionPreference(requireContext(), isFooter);
     }
 
     @Override
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDescriptionPreference.java b/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDescriptionPreference.java
new file mode 100644
index 0000000000..f896791752
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/handheld/HandheldDescriptionPreference.java
@@ -0,0 +1,40 @@
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
+
+package com.android.permissioncontroller.role.ui.handheld;
+
+import android.content.Context;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+
+import com.android.settingslib.widget.FooterPreference;
+
+/**
+ * Preference used as a description.
+ * <p>
+ * This preference does not set an {@link androidx.preference.Preference#setOrder(int) order} for
+ * itself like {@link FooterPreference} does, and uses the default (insertion) order instead.
+ */
+public class HandheldDescriptionPreference extends FooterPreference {
+
+    public HandheldDescriptionPreference(@NonNull Context context, boolean isFooter) {
+        super(context);
+
+        setOrder(DEFAULT_ORDER);
+        setIconVisibility(isFooter ? View.VISIBLE : View.GONE);
+    }
+}
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessActivity.java b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessActivity.java
index 472464061e..654b5b251e 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessActivity.java
@@ -27,7 +27,6 @@ import androidx.annotation.Nullable;
 import androidx.fragment.app.Fragment;
 
 import com.android.permissioncontroller.DeviceUtils;
-import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.role.ui.SettingsActivity;
 import com.android.permissioncontroller.role.ui.auto.AutoSpecialAppAccessFragment;
 import com.android.permissioncontroller.role.ui.specialappaccess.handheld.HandheldSpecialAppAccessFragment;
@@ -56,11 +55,6 @@ public class SpecialAppAccessActivity extends SettingsActivity {
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
-        if (DeviceUtils.isAuto(this)) {
-            // Automotive relies on a different theme. Apply before calling super so that
-            // fragments are restored properly on configuration changes.
-            setTheme(R.style.CarSettings);
-        }
         super.onCreate(savedInstanceState);
 
         String roleName = getIntent().getStringExtra(Intent.EXTRA_ROLE_NAME);
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessChildFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessChildFragment.java
index 7a13eb2b51..4992a4e513 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessChildFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessChildFragment.java
@@ -173,7 +173,7 @@ public class SpecialAppAccessChildFragment<PF extends PreferenceFragmentCompat
 
         Preference descriptionPreference = oldDescriptionPreference;
         if (descriptionPreference == null) {
-            descriptionPreference = preferenceFragment.createFooterPreference();
+            descriptionPreference = preferenceFragment.createDescriptionPreference();
             descriptionPreference.setKey(PREFERENCE_KEY_DESCRIPTION);
             descriptionPreference.setSummary(mRole.getDescriptionResource());
         }
@@ -239,12 +239,12 @@ public class SpecialAppAccessChildFragment<PF extends PreferenceFragmentCompat
         RoleApplicationPreference createApplicationPreference();
 
         /**
-         * Create a new preference for the footer.
+         * Create a new preference for a description.
          *
-         * @return a new preference for the footer
+         * @return a new preference for the description
          */
         @NonNull
-        Preference createFooterPreference();
+        Preference createDescriptionPreference();
 
         /**
          * Callback when changes have been made to the {@link PreferenceScreen} of the parent
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessListActivity.java b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessListActivity.java
index bb9020a745..0f6a9b1c81 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessListActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/SpecialAppAccessListActivity.java
@@ -22,7 +22,6 @@ import androidx.annotation.Nullable;
 import androidx.fragment.app.Fragment;
 
 import com.android.permissioncontroller.DeviceUtils;
-import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.role.ui.SettingsActivity;
 import com.android.permissioncontroller.role.ui.auto.AutoSpecialAppAccessListFragment;
 import com.android.permissioncontroller.role.ui.specialappaccess.handheld.HandheldSpecialAppAccessListFragment;
@@ -34,11 +33,6 @@ public class SpecialAppAccessListActivity extends SettingsActivity {
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
-        if (DeviceUtils.isAuto(this)) {
-            // Automotive relies on a different theme. Apply before calling super so that
-            // fragments are restored properly on configuration changes.
-            setTheme(R.style.CarSettings);
-        }
         super.onCreate(savedInstanceState);
 
         if (savedInstanceState == null) {
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessListPreferenceFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessListPreferenceFragment.java
index 26d858d725..7b755fed22 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessListPreferenceFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessListPreferenceFragment.java
@@ -21,18 +21,18 @@ import android.os.Bundle;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
-import androidx.preference.PreferenceFragmentCompat;
 
 import com.android.permissioncontroller.role.ui.RolePreference;
 import com.android.permissioncontroller.role.ui.handheld.HandheldRolePreference;
 import com.android.permissioncontroller.role.ui.specialappaccess.SpecialAppAccessListChildFragment;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
 
 /**
  * Handheld fragment for the list of special app accesses.
  * <p>
  * Must be added as a child fragment and its parent fragment must implement {@link Parent}.
  */
-public class HandheldSpecialAppAccessListPreferenceFragment extends PreferenceFragmentCompat
+public class HandheldSpecialAppAccessListPreferenceFragment extends SettingsBasePreferenceFragment
         implements SpecialAppAccessListChildFragment.Parent {
 
     /**
diff --git a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessPreferenceFragment.java b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessPreferenceFragment.java
index bfcbefdca9..d0027e656e 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessPreferenceFragment.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/ui/specialappaccess/handheld/HandheldSpecialAppAccessPreferenceFragment.java
@@ -25,8 +25,8 @@ import androidx.preference.Preference;
 import androidx.preference.PreferenceFragmentCompat;
 
 import com.android.permissioncontroller.role.ui.RoleApplicationPreference;
+import com.android.permissioncontroller.role.ui.handheld.HandheldDescriptionPreference;
 import com.android.permissioncontroller.role.ui.specialappaccess.SpecialAppAccessChildFragment;
-import com.android.settingslib.widget.FooterPreference;
 
 /**
  * Handheld fragment for a special app access.
@@ -95,8 +95,8 @@ public class HandheldSpecialAppAccessPreferenceFragment extends PreferenceFragme
 
     @NonNull
     @Override
-    public Preference createFooterPreference() {
-        return new FooterPreference(requireContext());
+    public Preference createDescriptionPreference() {
+        return new HandheldDescriptionPreference(requireContext(), true);
     }
 
     @Override
diff --git a/PermissionController/src/com/android/permissioncontroller/role/utils/RoleUiBehaviorUtils.java b/PermissionController/src/com/android/permissioncontroller/role/utils/RoleUiBehaviorUtils.java
index 255d88ff01..fed1b28da1 100644
--- a/PermissionController/src/com/android/permissioncontroller/role/utils/RoleUiBehaviorUtils.java
+++ b/PermissionController/src/com/android/permissioncontroller/role/utils/RoleUiBehaviorUtils.java
@@ -118,6 +118,32 @@ public final class RoleUiBehaviorUtils {
                 context);
     }
 
+    /**
+     * @see RoleUiBehavior#getRecommendedApplicationsTitle
+     */
+    @Nullable
+    public static String getRecommendedApplicationsTitle(@NonNull Role role,
+            @NonNull Context context) {
+        RoleUiBehavior uiBehavior = getUiBehavior(role);
+        if (uiBehavior == null) {
+            return null;
+        }
+        return uiBehavior.getRecommendedApplicationsTitle(role, context);
+    }
+
+    /**
+     * @see RoleUiBehavior#getRecommendedApplicationsDescription
+     */
+    @Nullable
+    public static String getRecommendedApplicationsDescription(@NonNull Role role,
+            @NonNull Context context) {
+        RoleUiBehavior uiBehavior = getUiBehavior(role);
+        if (uiBehavior == null) {
+            return null;
+        }
+        return uiBehavior.getRecommendedApplicationsDescription(role, context);
+    }
+
     /**
      * @see RoleUiBehavior#getRecommendedApplicationFilter
      */
diff --git a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterActivity.java b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterActivity.java
index 04206479f5..ba69a0d0fe 100644
--- a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterActivity.java
@@ -62,6 +62,7 @@ import com.android.permissioncontroller.permission.utils.Utils;
 import com.android.permissioncontroller.safetycenter.ui.model.PrivacyControlsViewModel.Pref;
 import com.android.settingslib.activityembedding.ActivityEmbeddingUtils;
 import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity;
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider;
 import com.android.settingslib.widget.SettingsThemeHelper;
 
 import java.util.List;
@@ -69,7 +70,8 @@ import java.util.Objects;
 
 /** Entry-point activity for SafetyCenter. */
 @RequiresApi(TIRAMISU)
-public final class SafetyCenterActivity extends CollapsingToolbarBaseActivity {
+public final class SafetyCenterActivity extends CollapsingToolbarBaseActivity
+        implements ExpressiveDesignEnabledProvider {
 
     private static final String TAG = SafetyCenterActivity.class.getSimpleName();
     private static final String PRIVACY_CONTROLS_ACTION = "android.settings.PRIVACY_CONTROLS";
@@ -362,4 +364,11 @@ public final class SafetyCenterActivity extends CollapsingToolbarBaseActivity {
         }
         return null;
     }
+
+    @Override
+    public boolean isExpressiveDesignEnabled() {
+        // Expressive design is pre-emptively disabled for Safety Center until implementation is
+        // complete.
+        return false;
+    }
 }
diff --git a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterQsActivity.java b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterQsActivity.java
index d9f45cc087..ac7734932d 100644
--- a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterQsActivity.java
+++ b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyCenterQsActivity.java
@@ -26,10 +26,12 @@ import androidx.fragment.app.FragmentActivity;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.permissioncontroller.R;
 import com.android.permissioncontroller.permission.utils.Utils;
+import com.android.settingslib.widget.ExpressiveDesignEnabledProvider;
 import com.android.settingslib.widget.SettingsThemeHelper;
 
 /** Activity for the Safety Center Quick Settings Activity */
-public class SafetyCenterQsActivity extends FragmentActivity {
+public class SafetyCenterQsActivity extends FragmentActivity
+        implements ExpressiveDesignEnabledProvider {
 
     @Override
     @SuppressWarnings("NewApi")
@@ -71,4 +73,11 @@ public class SafetyCenterQsActivity extends FragmentActivity {
                                                 PermissionGroupUsage.class)))
                 .commit();
     }
+
+    @Override
+    public boolean isExpressiveDesignEnabled() {
+        // Expressive design is pre-emptively disabled for Safety Center until implementation is
+        // complete.
+        return false;
+    }
 }
diff --git a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyPreferenceComparisonCallback.java b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyPreferenceComparisonCallback.java
deleted file mode 100644
index 2daf1e06db..0000000000
--- a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyPreferenceComparisonCallback.java
+++ /dev/null
@@ -1,45 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
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
-package com.android.permissioncontroller.safetycenter.ui;
-
-import static android.os.Build.VERSION_CODES.TIRAMISU;
-
-import androidx.annotation.RequiresApi;
-import androidx.preference.Preference;
-import androidx.preference.PreferenceManager.SimplePreferenceComparisonCallback;
-
-/** A {@link PreferenceComparisonCallback} to identify changed preferences of Safety Center. */
-@RequiresApi(TIRAMISU)
-class SafetyPreferenceComparisonCallback extends SimplePreferenceComparisonCallback {
-
-    @Override
-    public boolean arePreferenceItemsTheSame(Preference oldPreference, Preference newPreference) {
-        if (oldPreference instanceof ComparablePreference) {
-            return ((ComparablePreference) oldPreference).isSameItem(newPreference);
-        }
-        return super.arePreferenceItemsTheSame(oldPreference, newPreference);
-    }
-
-    @Override
-    public boolean arePreferenceContentsTheSame(
-            Preference oldPreference, Preference newPreference) {
-        if (oldPreference instanceof ComparablePreference) {
-            return ((ComparablePreference) oldPreference).hasSameContents(newPreference);
-        }
-        return super.arePreferenceContentsTheSame(oldPreference, newPreference);
-    }
-}
diff --git a/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyPreferenceComparisonCallback.kt b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyPreferenceComparisonCallback.kt
new file mode 100644
index 0000000000..79cb453277
--- /dev/null
+++ b/PermissionController/src/com/android/permissioncontroller/safetycenter/ui/SafetyPreferenceComparisonCallback.kt
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+package com.android.permissioncontroller.safetycenter.ui
+
+import android.os.Build
+import androidx.annotation.RequiresApi
+import androidx.preference.Preference
+import androidx.preference.PreferenceCategory
+import androidx.preference.PreferenceManager
+
+/** A [PreferenceComparisonCallback] to identify changed preferences of Safety Center. */
+@RequiresApi(Build.VERSION_CODES.TIRAMISU)
+internal class SafetyPreferenceComparisonCallback :
+    PreferenceManager.SimplePreferenceComparisonCallback() {
+    override fun arePreferenceItemsTheSame(
+        oldPreference: Preference,
+        newPreference: Preference,
+    ): Boolean {
+        if (oldPreference is ComparablePreference) {
+            return oldPreference.isSameItem(newPreference)
+        }
+        if (oldPreference is PreferenceCategory && newPreference is PreferenceCategory) {
+            return oldPreference::class == newPreference::class &&
+                oldPreference.key == newPreference.key
+        }
+        return super.arePreferenceItemsTheSame(oldPreference, newPreference)
+    }
+
+    override fun arePreferenceContentsTheSame(
+        oldPreference: Preference,
+        newPreference: Preference,
+    ): Boolean {
+        if (oldPreference is ComparablePreference) {
+            return oldPreference.hasSameContents(newPreference)
+        }
+        if (oldPreference is PreferenceCategory && newPreference is PreferenceCategory) {
+            return oldPreference.title == newPreference.title
+        }
+        return super.arePreferenceContentsTheSame(oldPreference, newPreference)
+    }
+}
diff --git a/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/hibernation/HibernationPolicyTest.kt b/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/hibernation/HibernationPolicyTest.kt
index 15a37532f2..0fa6941397 100644
--- a/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/hibernation/HibernationPolicyTest.kt
+++ b/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/hibernation/HibernationPolicyTest.kt
@@ -69,6 +69,7 @@ import org.mockito.ArgumentMatchers.eq
 import org.mockito.Mock
 import org.mockito.Mockito
 import org.mockito.Mockito.verify
+import org.mockito.Mockito.verifyNoInteractions
 import org.mockito.Mockito.`when`
 import org.mockito.MockitoAnnotations
 import org.mockito.MockitoSession
@@ -84,6 +85,7 @@ class HibernationPolicyTest {
         private val application = Mockito.mock(PermissionControllerApplication::class.java)
         private const val USER_SETUP_INCOMPLETE = 0
         private const val USER_SETUP_COMPLETE = 1
+        private const val IS_DEMO_MODE = 1
         private const val TEST_PKG_NAME = "test.package"
     }
 
@@ -109,6 +111,7 @@ class HibernationPolicyTest {
                 .mockStatic(PermissionControllerApplication::class.java)
                 .mockStatic(DeviceConfig::class.java)
                 .mockStatic(Settings.Secure::class.java)
+                .mockStatic(Settings.Global::class.java)
                 .strictness(Strictness.LENIENT)
                 .startMocking()
         `when`(PermissionControllerApplication.get()).thenReturn(application)
@@ -213,6 +216,48 @@ class HibernationPolicyTest {
         assertAdjustedTime(systemTimeSnapshot, realtimeSnapshot)
     }
 
+    @Test
+    fun onReceive_schedulesJob() {
+        receiver.onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
+
+        verify(jobScheduler).schedule(any())
+    }
+
+    @Test
+    fun onReceive_demoMode_doesNotScheduleJob() {
+        `when`(Settings.Global.getInt(any(), eq(Settings.Global.DEVICE_DEMO_MODE), anyInt()))
+            .thenReturn(IS_DEMO_MODE)
+
+        receiver.onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
+
+        verifyNoInteractions(jobScheduler)
+    }
+
+    @Test
+    fun onReceive_userSetupCompletesAndDemoMode_cancelsJob() {
+        `when`(Settings.Secure.getInt(any(), eq(Settings.Secure.USER_SETUP_COMPLETE), anyInt()))
+            .thenReturn(USER_SETUP_INCOMPLETE)
+
+        receiver.onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
+
+        val contentObserverCaptor = ArgumentCaptor.forClass(ContentObserver::class.java)
+        val uri = Settings.Secure.getUriFor(Settings.Secure.USER_SETUP_COMPLETE)
+        verify(contentResolver).registerContentObserver(
+            eq(uri),
+            anyBoolean(),
+            contentObserverCaptor.capture())
+        val contentObserver = contentObserverCaptor.value
+        `when`(Settings.Secure.getInt(any(), eq(Settings.Secure.USER_SETUP_COMPLETE), anyInt()))
+            .thenReturn(USER_SETUP_COMPLETE)
+
+        `when`(Settings.Global.getInt(any(), eq(Settings.Global.DEVICE_DEMO_MODE), anyInt()))
+            .thenReturn(IS_DEMO_MODE)
+
+        contentObserver.onChange(/* selfChange= */ false, uri)
+
+        verify(jobScheduler).cancel(Constants.HIBERNATION_JOB_ID)
+    }
+
     @Test
     fun getStartTimeOfUnusedAppTracking_shouldReturnExpectedValue() {
         assertThat(getStartTimeOfUnusedAppTracking(sharedPreferences))
diff --git a/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/privacysources/AppFunctionAccessPrivacySourceTest.kt b/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/privacysources/AppFunctionAccessPrivacySourceTest.kt
new file mode 100644
index 0000000000..7df99dae86
--- /dev/null
+++ b/PermissionController/tests/mocking/src/com/android/permissioncontroller/tests/mocking/privacysources/AppFunctionAccessPrivacySourceTest.kt
@@ -0,0 +1,249 @@
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
+package com.android.permissioncontroller.tests.mocking.privacysources
+
+import android.app.PendingIntent
+import android.app.PendingIntent.FLAG_IMMUTABLE
+import android.app.PendingIntent.FLAG_UPDATE_CURRENT
+import android.app.appfunctions.AppFunctionManager
+import android.content.Context
+import android.content.ContextWrapper
+import android.content.Intent
+import android.content.Intent.ACTION_BOOT_COMPLETED
+import android.os.Build
+import android.platform.test.annotations.RequiresFlagsDisabled
+import android.platform.test.annotations.RequiresFlagsEnabled
+import android.platform.test.flag.junit.CheckFlagsRule
+import android.platform.test.flag.junit.DeviceFlagsValueProvider
+import android.provider.DeviceConfig
+import android.safetycenter.SafetyCenterManager
+import android.safetycenter.SafetyCenterManager.ACTION_REFRESH_SAFETY_SOURCES
+import android.safetycenter.SafetyCenterManager.EXTRA_REFRESH_SAFETY_SOURCES_BROADCAST_ID
+import android.safetycenter.SafetyEvent
+import android.safetycenter.SafetyEvent.SAFETY_EVENT_TYPE_DEVICE_REBOOTED
+import android.safetycenter.SafetyEvent.SAFETY_EVENT_TYPE_REFRESH_REQUESTED
+import android.safetycenter.SafetySourceData
+import android.safetycenter.SafetySourceStatus
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SdkSuppress
+import com.android.dx.mockito.inline.extended.ExtendedMockito
+import com.android.permissioncontroller.PermissionControllerApplication
+import com.android.permissioncontroller.permission.utils.Utils
+import com.android.permissioncontroller.privacysources.SafetyCenterReceiver.RefreshEvent.EVENT_DEVICE_REBOOTED
+import com.android.permissioncontroller.privacysources.SafetyCenterReceiver.RefreshEvent.EVENT_REFRESH_REQUESTED
+import com.android.permissioncontroller.privacysources.v36r1.AppFunctionAccessPrivacySource
+import com.android.permissioncontroller.privacysources.v36r1.AppFunctionAccessPrivacySource.Companion.APP_FUNCTION_ACCESS_SOURCE_ID
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentMatchers.any
+import org.mockito.ArgumentMatchers.eq
+import org.mockito.Mock
+import org.mockito.Mockito.verify
+import org.mockito.Mockito.verifyNoMoreInteractions
+import org.mockito.Mockito.`when`
+import org.mockito.MockitoAnnotations
+import org.mockito.MockitoSession
+import org.mockito.quality.Strictness
+
+/** Tests for [AppFunctionAccessPrivacySource]. */
+@RunWith(AndroidJUnit4::class)
+@SdkSuppress(minSdkVersion = Build.VERSION_CODES.BAKLAVA)
+class AppFunctionAccessPrivacySourceTest {
+    @get:Rule val checkFlagsRule: CheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule()
+
+    private lateinit var mockitoSession: MockitoSession
+    private lateinit var appFunctionAccessPrivacySource: AppFunctionAccessPrivacySource
+    @Mock lateinit var mockSafetyCenterManager: SafetyCenterManager
+
+    @Before
+    fun setup() {
+        MockitoAnnotations.initMocks(this)
+        mockitoSession =
+            ExtendedMockito.mockitoSession()
+                .mockStatic(DeviceConfig::class.java)
+                .mockStatic(PermissionControllerApplication::class.java)
+                .mockStatic(Utils::class.java)
+                .strictness(Strictness.LENIENT)
+                .startMocking()
+        `when`(
+                Utils.getSystemServiceSafe(
+                    any(ContextWrapper::class.java),
+                    eq(SafetyCenterManager::class.java),
+                )
+            )
+            .thenReturn(mockSafetyCenterManager)
+
+        appFunctionAccessPrivacySource = AppFunctionAccessPrivacySource()
+    }
+
+    @After
+    fun cleanup() {
+        mockitoSession.finishMocking()
+    }
+
+    @Test
+    fun safetyCenterEnabledChanged_enabled_doesNothing() {
+        appFunctionAccessPrivacySource.safetyCenterEnabledChanged(context, true)
+
+        verifyNoMoreInteractions(mockSafetyCenterManager)
+    }
+
+    @Test
+    fun safetyCenterEnabledChanged_disabled_doesNothing() {
+        appFunctionAccessPrivacySource.safetyCenterEnabledChanged(context, false)
+
+        verifyNoMoreInteractions(mockSafetyCenterManager)
+    }
+
+    @RequiresFlagsEnabled(FLAG_APP_FUNCTION_ACCESS_UI_ENABLED)
+    @Test
+    fun rescanAndPushSafetyCenterData_refreshRequested_appFunctionsEnabled_setsDataWithStatus() {
+        val refreshIntent =
+            Intent(ACTION_REFRESH_SAFETY_SOURCES)
+                .putExtra(EXTRA_REFRESH_SAFETY_SOURCES_BROADCAST_ID, REFRESH_ID)
+
+        appFunctionAccessPrivacySource.rescanAndPushSafetyCenterData(
+            context,
+            refreshIntent,
+            EVENT_REFRESH_REQUESTED,
+        )
+
+        val expectedSafetySourceData: SafetySourceData =
+            SafetySourceData.Builder()
+                .setStatus(
+                    SafetySourceStatus.Builder(
+                            APP_FUNCTION_ACCESS_TITLE,
+                            APP_FUNCTION_ACCESS_SUMMARY,
+                            SafetySourceData.SEVERITY_LEVEL_UNSPECIFIED,
+                        )
+                        .setPendingIntent(
+                            PendingIntent.getActivity(
+                                context,
+                                /* requestCode= */ 0,
+                                Intent(AppFunctionManager.ACTION_MANAGE_APP_FUNCTION_ACCESS),
+                                FLAG_UPDATE_CURRENT or FLAG_IMMUTABLE,
+                            )
+                        )
+                        .build()
+                )
+                .build()
+        val expectedSafetyEvent =
+            SafetyEvent.Builder(SAFETY_EVENT_TYPE_REFRESH_REQUESTED)
+                .setRefreshBroadcastId(AppDataSharingUpdatesPrivacySourceTest.REFRESH_ID)
+                .build()
+        verify(mockSafetyCenterManager)
+            .setSafetySourceData(
+                APP_FUNCTION_ACCESS_SOURCE_ID,
+                expectedSafetySourceData,
+                expectedSafetyEvent,
+            )
+    }
+
+    @RequiresFlagsEnabled(FLAG_APP_FUNCTION_ACCESS_UI_ENABLED)
+    @Test
+    fun rescanAndPushSafetyCenterData_deviceRebooted_appFunctionsEnabled_setsDataWithStatus() {
+        val bootCompleteIntent = Intent(ACTION_BOOT_COMPLETED)
+
+        appFunctionAccessPrivacySource.rescanAndPushSafetyCenterData(
+            AppDataSharingUpdatesPrivacySourceTest.context,
+            bootCompleteIntent,
+            EVENT_DEVICE_REBOOTED,
+        )
+
+        val expectedSafetySourceData: SafetySourceData =
+            SafetySourceData.Builder()
+                .setStatus(
+                    SafetySourceStatus.Builder(
+                            APP_FUNCTION_ACCESS_TITLE,
+                            APP_FUNCTION_ACCESS_SUMMARY,
+                            SafetySourceData.SEVERITY_LEVEL_UNSPECIFIED,
+                        )
+                        .setPendingIntent(
+                            PendingIntent.getActivity(
+                                context,
+                                /* requestCode= */ 0,
+                                Intent(AppFunctionManager.ACTION_MANAGE_APP_FUNCTION_ACCESS),
+                                FLAG_UPDATE_CURRENT or FLAG_IMMUTABLE,
+                            )
+                        )
+                        .build()
+                )
+                .build()
+        val expectedSafetyEvent = SafetyEvent.Builder(SAFETY_EVENT_TYPE_DEVICE_REBOOTED).build()
+        verify(mockSafetyCenterManager)
+            .setSafetySourceData(
+                APP_FUNCTION_ACCESS_SOURCE_ID,
+                expectedSafetySourceData,
+                expectedSafetyEvent,
+            )
+    }
+
+    @RequiresFlagsDisabled(FLAG_APP_FUNCTION_ACCESS_UI_ENABLED)
+    @Test
+    fun rescanAndPushSafetyCenterData_refreshRequested_appFunctionsDisabled_setsNullData() {
+        val refreshIntent =
+            Intent(ACTION_REFRESH_SAFETY_SOURCES)
+                .putExtra(EXTRA_REFRESH_SAFETY_SOURCES_BROADCAST_ID, REFRESH_ID)
+
+        appFunctionAccessPrivacySource.rescanAndPushSafetyCenterData(
+            context,
+            refreshIntent,
+            EVENT_REFRESH_REQUESTED,
+        )
+
+        val expectedSafetyEvent =
+            SafetyEvent.Builder(SAFETY_EVENT_TYPE_REFRESH_REQUESTED)
+                .setRefreshBroadcastId(REFRESH_ID)
+                .build()
+        verify(mockSafetyCenterManager)
+            .setSafetySourceData(APP_FUNCTION_ACCESS_SOURCE_ID, null, expectedSafetyEvent)
+    }
+
+    @RequiresFlagsDisabled(FLAG_APP_FUNCTION_ACCESS_UI_ENABLED)
+    @Test
+    fun rescanAndPushSafetyCenterData_deviceRebooted_appFunctionsDisabled_setsNullData() {
+        val bootCompleteIntent = Intent(ACTION_BOOT_COMPLETED)
+
+        appFunctionAccessPrivacySource.rescanAndPushSafetyCenterData(
+            AppDataSharingUpdatesPrivacySourceTest.context,
+            bootCompleteIntent,
+            EVENT_DEVICE_REBOOTED,
+        )
+
+        val expectedSafetyEvent = SafetyEvent.Builder(SAFETY_EVENT_TYPE_DEVICE_REBOOTED).build()
+        verify(mockSafetyCenterManager)
+            .setSafetySourceData(APP_FUNCTION_ACCESS_SOURCE_ID, null, expectedSafetyEvent)
+    }
+
+    /** Companion object for [AppFunctionAccessPrivacySourceTest]. */
+    companion object {
+        // Flag lib changes has caused issues with jarjar and now annotations require the jarjar
+        // package prepended to the flag string
+        const val FLAG_APP_FUNCTION_ACCESS_UI_ENABLED =
+            "com.android.permissioncontroller.jarjar.android.permission.flags.app_function_access_ui_enabled"
+
+        // Real context, used in order to avoid mocking resources.
+        var context: Context = ApplicationProvider.getApplicationContext()
+        const val APP_FUNCTION_ACCESS_TITLE: String = "Agent control of other apps"
+        const val APP_FUNCTION_ACCESS_SUMMARY: String =
+            "Perform actions on your device and in other apps"
+        const val REFRESH_ID: String = "refresh_id"
+    }
+}
diff --git a/PermissionController/wear-permission-components/src/wear.permission.components/material2/ListHeader.kt b/PermissionController/wear-permission-components/src/wear.permission.components/material2/ListHeader.kt
index 6ed81353ae..ab4e5059cc 100644
--- a/PermissionController/wear-permission-components/src/wear.permission.components/material2/ListHeader.kt
+++ b/PermissionController/wear-permission-components/src/wear.permission.components/material2/ListHeader.kt
@@ -36,6 +36,7 @@ import androidx.compose.ui.semantics.heading
 import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.text.style.Hyphens
 import androidx.compose.ui.unit.dp
+import androidx.compose.ui.unit.em
 import androidx.wear.compose.material.LocalContentColor
 import androidx.wear.compose.material.LocalTextStyle
 import androidx.wear.compose.material.MaterialTheme
@@ -71,7 +72,8 @@ fun ListHeader(
     ) {
         CompositionLocalProvider(
             LocalContentColor provides contentColor,
-            LocalTextStyle provides MaterialTheme.typography.title3.copy(hyphens = Hyphens.Auto),
+            LocalTextStyle provides
+                MaterialTheme.typography.title3.copy(hyphens = Hyphens.Auto, lineHeight = 1.1.em),
         ) {
             content()
         }
diff --git a/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionButtonStyle.kt b/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionButtonStyle.kt
index f48d47b2c5..3991f8a957 100644
--- a/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionButtonStyle.kt
+++ b/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionButtonStyle.kt
@@ -75,11 +75,11 @@ internal fun WearPermissionButtonStyle.material3ButtonColors(): ButtonColors {
 private fun ButtonDefaults.disabledLikeColors() =
     filledTonalButtonColors().run {
         ButtonColors(
-            containerPainter = disabledContainerPainter,
+            containerColor = disabledContainerColor,
             contentColor = disabledContentColor,
             secondaryContentColor = disabledSecondaryContentColor,
             iconColor = disabledIconColor,
-            disabledContainerPainter = disabledContainerPainter,
+            disabledContainerColor = disabledContainerColor,
             disabledContentColor = disabledContentColor,
             disabledSecondaryContentColor = disabledSecondaryContentColor,
             disabledIconColor = disabledIconColor,
diff --git a/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionScaffold.kt b/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionScaffold.kt
index 87ca048bc0..3401a105df 100644
--- a/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionScaffold.kt
+++ b/PermissionController/wear-permission-components/src/wear.permission.components/material3/WearPermissionScaffold.kt
@@ -36,6 +36,7 @@ import androidx.compose.ui.res.painterResource
 import androidx.compose.ui.text.style.Hyphens
 import androidx.compose.ui.text.style.TextAlign
 import androidx.compose.ui.unit.dp
+import androidx.compose.ui.unit.em
 import androidx.wear.compose.foundation.ExpandableState
 import androidx.wear.compose.foundation.ScrollInfoProvider
 import androidx.wear.compose.foundation.expandableButton
@@ -377,7 +378,7 @@ private fun ListScopeWrapper.titleItem(
                     text = it,
                     textAlign = TextAlign.Center,
                     modifier = Modifier.optionalTestTag(testTag),
-                    style = style.copy(hyphens = Hyphens.Auto),
+                    style = style.copy(hyphens = Hyphens.Auto, lineHeight = 1.1.em),
                 )
             }
         }
diff --git a/SafetyCenter/Resources/res/raw-v36/safety_center_config.xml b/SafetyCenter/Resources/res/raw-v36/safety_center_config.xml
index 730edf812e..6f94110a85 100644
--- a/SafetyCenter/Resources/res/raw-v36/safety_center_config.xml
+++ b/SafetyCenter/Resources/res/raw-v36/safety_center_config.xml
@@ -101,6 +101,13 @@
                 refreshOnPageOpenAllowed="false"
                 title="@com.android.safetycenter.resources:string/health_connect_title"
                 searchTerms="@com.android.safetycenter.resources:string/health_connect_search_terms"/>
+            <dynamic-safety-source
+                id="AndroidAppFunctionAccess"
+                packageName="com.android.permissioncontroller"
+                profile="primary_profile_only"
+                initialDisplayState="hidden"
+                refreshOnPageOpenAllowed="false"
+                title="@com.android.safetycenter.resources:string/app_function_access_settings_title"/>
             <dynamic-safety-source
                 id="AndroidPrivacyAppDataSharingUpdates"
                 packageName="com.android.permissioncontroller"
diff --git a/SafetyCenter/Resources/res/values-af-v36/strings.xml b/SafetyCenter/Resources/res/values-af-v36/strings.xml
index 304c3ec835..5030e7a45e 100644
--- a/SafetyCenter/Resources/res/values-af-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-af-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agentbeheer van ander apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Voer handelinge op jou toestel en in ander apps uit"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Gesig"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Gesig vir werk"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-am-v36/strings.xml b/SafetyCenter/Resources/res/values-am-v36/strings.xml
index 5733311934..2d80638128 100644
--- a/SafetyCenter/Resources/res/values-am-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-am-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"የሌሎች መተግበሪያዎች ወኪል ቁጥጥር"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"መሣሪያዎ እና ሌሎች መተግበሪያዎች ላይ ተግባሮችን ይፈጽሙ"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"መልክ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"መልክ ለሥራ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ar-v36/strings.xml b/SafetyCenter/Resources/res/values-ar-v36/strings.xml
index 0012b1548f..79fa568874 100644
--- a/SafetyCenter/Resources/res/values-ar-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ar-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"تحكُّم الوكيل في التطبيقات الأخرى"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"يتيح لك هذا الإعداد تنفيذ إجراءات على جهازك وفي تطبيقات أخرى"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"الوجه"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"بصمة الوجه للعمل"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-as-v36/strings.xml b/SafetyCenter/Resources/res/values-as-v36/strings.xml
index dff88f101c..adef84ef88 100644
--- a/SafetyCenter/Resources/res/values-as-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-as-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"অন্য এপ্‌সমূহৰ এজেণ্ট নিয়ন্ত্ৰণ"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"আপোনাৰ ডিভাইচত আৰু অন্য এপত কাৰ্য সম্পাদন কৰক"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"মুখাৱয়ব"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"কৰ্মস্থানৰ বাবে মুখাৱয়ব"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-az-v36/strings.xml b/SafetyCenter/Resources/res/values-az-v36/strings.xml
index 26a77a7d73..909761d6ae 100644
--- a/SafetyCenter/Resources/res/values-az-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-az-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Digər tətbiqlərə nümayəndə nəzarəti"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Cihazınızda və digər tətbiqlərdə əməliyyatlar həyata keçirin"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Üz"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"İş üçün üz"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-b+sr+Latn-v36/strings.xml b/SafetyCenter/Resources/res/values-b+sr+Latn-v36/strings.xml
index 3613b2c027..bf583f0a2e 100644
--- a/SafetyCenter/Resources/res/values-b+sr+Latn-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-b+sr+Latn-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Kontrolišite druge aplikacije pomoću agenta"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Obavljajte radnje na uređaju i u drugim aplikacijama"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Lice"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Otključavanje licem za posao"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-be-v36/strings.xml b/SafetyCenter/Resources/res/values-be-v36/strings.xml
index 7fdab64d0b..a39cbbf496 100644
--- a/SafetyCenter/Resources/res/values-be-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-be-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Кіраванне іншымі праграмамі ў якасці агента"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Выкананне дзеянняў на прыладзе і ў іншых праграмах"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Твар"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Твар (для выкарыстання)"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-bg-v36/strings.xml b/SafetyCenter/Resources/res/values-bg-v36/strings.xml
index d3f2112361..0a4c26af1c 100644
--- a/SafetyCenter/Resources/res/values-bg-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-bg-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Контролиране на други приложения от агент"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Извършване на действия на устройството ви, както и в други приложения"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Лице"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Лице за служебни цели"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-bn-v36/strings.xml b/SafetyCenter/Resources/res/values-bn-v36/strings.xml
index d06b0617c6..7b602f3cd4 100644
--- a/SafetyCenter/Resources/res/values-bn-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-bn-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"অন্যান্য অ্যাপের এজেন্ট কন্ট্রোল"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"আপনার ডিভাইস ও অন্যান্য অ্যাপে অ্যাকশন পারফর্ম করুন"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ফেস"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ডিভাইসে কাজ করার জন্য ফেস আনলক"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-bs-v36/strings.xml b/SafetyCenter/Resources/res/values-bs-v36/strings.xml
index 21ef83688b..e9d5fe4c27 100644
--- a/SafetyCenter/Resources/res/values-bs-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-bs-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Upravljanje drugim aplikacijama putem agenta"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Izvršavajte radnje na uređaju i u drugim aplikacijama"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Lice"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Otključavanje licem za radni profil"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ca-v36/strings.xml b/SafetyCenter/Resources/res/values-ca-v36/strings.xml
index 7921f0a931..f49432083c 100644
--- a/SafetyCenter/Resources/res/values-ca-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ca-v36/strings.xml
@@ -17,12 +17,14 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Control de l\'agent d\'altres aplicacions"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Dur a terme accions al dispositiu i en altres aplicacions"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Cara"</string>
-    <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Cara de la feina"</string>
+    <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Cara per al treball"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
     <string name="face_unlock_search_terms" msgid="2708195853333028283">"Desbloqueig facial, cara"</string>
     <string name="fingerprint_unlock_title" msgid="5579868242026550596">"Empremta digital"</string>
-    <string name="fingerprint_unlock_title_for_work" msgid="6343690273672384918">"Empremta digital de la feina"</string>
+    <string name="fingerprint_unlock_title_for_work" msgid="6343690273672384918">"Empremta digital per al treball"</string>
     <string name="fingerprint_unlock_title_for_private_profile" msgid="9004513575240235691"></string>
     <string name="fingerprint_unlock_search_terms" msgid="688405183240088603">"Empremta digital, dit, afegir una empremta digital"</string>
     <string name="wear_unlock_title" msgid="1613730442896319515">"Rellotge"</string>
diff --git a/SafetyCenter/Resources/res/values-cs-v36/strings.xml b/SafetyCenter/Resources/res/values-cs-v36/strings.xml
index e14e7f8eec..4b0d979137 100644
--- a/SafetyCenter/Resources/res/values-cs-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-cs-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agentní ovládání ostatních aplikací"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Provádějte akce na zařízení a v ostatních aplikacích"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Obličej"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Obličej pro práci"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-da-v36/strings.xml b/SafetyCenter/Resources/res/values-da-v36/strings.xml
index be7c510168..d9ef2bf0f4 100644
--- a/SafetyCenter/Resources/res/values-da-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-da-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agentstyring af andre apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Udfør handlinger på din enhed og i andre apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Ansigt"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Ansigt til arbejdsprofil"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-de-v36/strings.xml b/SafetyCenter/Resources/res/values-de-v36/strings.xml
index 693573d890..273c565168 100644
--- a/SafetyCenter/Resources/res/values-de-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-de-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"KI‑Agent-Steuerung anderer Apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Aktionen auf deinem Gerät und in anderen Apps ausführen"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Gesicht"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Einstellungen der Entsperrung per Gesichtserkennung für die Arbeit"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-de/strings.xml b/SafetyCenter/Resources/res/values-de/strings.xml
index 8491f5adc7..e3433ddf04 100644
--- a/SafetyCenter/Resources/res/values-de/strings.xml
+++ b/SafetyCenter/Resources/res/values-de/strings.xml
@@ -27,7 +27,7 @@
     <string name="biometrics_search_terms" msgid="6040319118762671981">"Fingerabdruck, Finger, Fingerabdruck hinzufügen, Entsperrung per Gesichtserkennung, Gesicht"</string>
     <string name="privacy_sources_title" msgid="4061110826457365957">"Datenschutz"</string>
     <string name="privacy_sources_summary" msgid="4089719981155120864">"Dashboard, Berechtigungen, Einstellungen"</string>
-    <string name="permission_usage_title" msgid="3633779688945350407">"Privatsphäre­dashboard"</string>
+    <string name="permission_usage_title" msgid="3633779688945350407">"Privatsphäre-Dashboard"</string>
     <string name="permission_usage_summary" msgid="5323079206029964468">"Anzeigen, welche Apps zuletzt Berechtigungen genutzt haben"</string>
     <string name="permission_usage_search_terms" msgid="3852343592870257104">"Privatsphäre, Privatsphäredashboard"</string>
     <string name="permission_manager_title" msgid="5277347862821255015">"Berechtigungsmanager"</string>
diff --git a/SafetyCenter/Resources/res/values-el-v36/strings.xml b/SafetyCenter/Resources/res/values-el-v36/strings.xml
index 9a57115d4f..550f87f5a7 100644
--- a/SafetyCenter/Resources/res/values-el-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-el-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Έλεγχος άλλων εφαρμογών από τον εκπρόσωπο"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Εκτέλεση ενεργειών στη συσκευή σας και σε άλλες εφαρμογές"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Πρόσωπο"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Πρόσωπο για επαγγελματική χρήση"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-en-rAU-v36/strings.xml b/SafetyCenter/Resources/res/values-en-rAU-v36/strings.xml
index 327a15b5df..ab67a5299c 100644
--- a/SafetyCenter/Resources/res/values-en-rAU-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-en-rAU-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Perform actions on your device and in other apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Face"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Face for work"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-en-rCA-v36/strings.xml b/SafetyCenter/Resources/res/values-en-rCA-v36/strings.xml
index 6a70e3a9b6..d4d88a2cc0 100644
--- a/SafetyCenter/Resources/res/values-en-rCA-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-en-rCA-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Perform actions on your device and in other apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Face"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Face for work"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-en-rGB-v36/strings.xml b/SafetyCenter/Resources/res/values-en-rGB-v36/strings.xml
index 327a15b5df..ab67a5299c 100644
--- a/SafetyCenter/Resources/res/values-en-rGB-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-en-rGB-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Perform actions on your device and in other apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Face"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Face for work"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-en-rIN-v36/strings.xml b/SafetyCenter/Resources/res/values-en-rIN-v36/strings.xml
index 327a15b5df..ab67a5299c 100644
--- a/SafetyCenter/Resources/res/values-en-rIN-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-en-rIN-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent control of other apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Perform actions on your device and in other apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Face"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Face for work"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-es-rUS-v34/strings.xml b/SafetyCenter/Resources/res/values-es-rUS-v34/strings.xml
index 4158efa920..3d7c5ebefa 100644
--- a/SafetyCenter/Resources/res/values-es-rUS-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-es-rUS-v34/strings.xml
@@ -22,8 +22,8 @@
     <string name="privacy_sources_summary" msgid="4083646673569677049">"Permisos, panel, controles"</string>
     <string name="health_connect_title" msgid="8318152190040327804">"Health Connect"</string>
     <string name="health_connect_search_terms" msgid="4998970586245680829">"Health, Health Connect"</string>
-    <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"Actualizaciones del uso compartido de los datos de ubicación"</string>
-    <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"datos, uso compartido de los datos, actualizaciones del uso compartido de los datos, actualizaciones del uso compartido de los datos de ubicación, uso compartido"</string>
+    <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"Actualizaciones de los datos compartidos de ubicación"</string>
+    <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"datos, datos compartidos, actualizaciones de los datos compartidos, actualizaciones de los datos compartidos de ubicación, uso compartido"</string>
     <string name="advanced_title" msgid="6259362998269627310">"Otras opciones"</string>
     <string name="more_settings_title" msgid="9033454654010697185">"Mayor seguridad y privacidad"</string>
     <string name="more_settings_summary" msgid="7086620830002515710">"Autocompletar, notificaciones y más"</string>
diff --git a/SafetyCenter/Resources/res/values-es-rUS-v35/strings.xml b/SafetyCenter/Resources/res/values-es-rUS-v35/strings.xml
index 9b17255b5a..641b823228 100644
--- a/SafetyCenter/Resources/res/values-es-rUS-v35/strings.xml
+++ b/SafetyCenter/Resources/res/values-es-rUS-v35/strings.xml
@@ -22,7 +22,7 @@
     <string name="biometrics_title_for_private_profile" msgid="542819107383037820"></string>
     <string name="privacy_title" msgid="7047524783080782769">"Privacidad"</string>
     <string name="privacy_sources_title" msgid="309304028326660956">"Controles de privacidad"</string>
-    <string name="privacy_sources_summary" msgid="2165270848857537278">"Permisos y controles"</string>
+    <string name="privacy_sources_summary" msgid="2165270848857537278">"Permisos, controles"</string>
     <string name="privacy_additional_title" msgid="4239060639056083649"></string>
     <string name="private_space_title" msgid="6158245041481535879">"Espacio privado"</string>
     <string name="private_space_summary" msgid="529869826714610294">"Configura el Espacio privado y mucho más"</string>
diff --git a/SafetyCenter/Resources/res/values-es-rUS-v36/strings.xml b/SafetyCenter/Resources/res/values-es-rUS-v36/strings.xml
index 02e0214fde..eff58d537a 100644
--- a/SafetyCenter/Resources/res/values-es-rUS-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-es-rUS-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Control del agente de otras apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Realiza acciones en tu dispositivo y en otras apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Rostro"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Rostro para el trabajo"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-es-v36/strings.xml b/SafetyCenter/Resources/res/values-es-v36/strings.xml
index 8dd8a23c48..52b033060e 100644
--- a/SafetyCenter/Resources/res/values-es-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-es-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Control de agentes de otras aplicaciones"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Realiza acciones en el dispositivo y en otras aplicaciones"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Cara"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Cara para el trabajo"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-et-v36/strings.xml b/SafetyCenter/Resources/res/values-et-v36/strings.xml
index c5828aebf5..212fa5415f 100644
--- a/SafetyCenter/Resources/res/values-et-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-et-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agendi kontroll teiste rakenduste üle"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Tehke toiminguid oma seadmes ja teistes rakendustes"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Nägu"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Näoga avamine töö jaoks"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-eu-v36/strings.xml b/SafetyCenter/Resources/res/values-eu-v36/strings.xml
index 6187881b19..10e6d50802 100644
--- a/SafetyCenter/Resources/res/values-eu-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-eu-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agenteak beste aplikazioak kontrolatzen ditu"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Gauzatu ekintzak gailuan eta beste aplikazio batzuetan"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Aurpegia"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Aurpegia lanerako"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
@@ -25,7 +27,7 @@
     <string name="fingerprint_unlock_title_for_work" msgid="6343690273672384918">"Hatz-marka lanerako"</string>
     <string name="fingerprint_unlock_title_for_private_profile" msgid="9004513575240235691"></string>
     <string name="fingerprint_unlock_search_terms" msgid="688405183240088603">"Hatz-marka, hatza, hatz-marka gehitu"</string>
-    <string name="wear_unlock_title" msgid="1613730442896319515">"Ikusi"</string>
+    <string name="wear_unlock_title" msgid="1613730442896319515">"Erlojua"</string>
     <string name="wear_unlock_title_for_work" msgid="3103157953371670280">"Erlojua lanerako"</string>
     <string name="wear_unlock_title_for_private_profile" msgid="927318621331822758"></string>
     <string name="wear_unlock_search_terms" msgid="3769797118448924263">"Erlojua, Erloju bidez desblokeatzea"</string>
diff --git a/SafetyCenter/Resources/res/values-fa-v34/strings.xml b/SafetyCenter/Resources/res/values-fa-v34/strings.xml
index 92a2168dee..a9256006e7 100644
--- a/SafetyCenter/Resources/res/values-fa-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-fa-v34/strings.xml
@@ -24,7 +24,7 @@
     <string name="health_connect_search_terms" msgid="4998970586245680829">"‏سلامت، Health Connect"</string>
     <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"به‌روزرسانی‌های هم‌رسانی داده برای مکان"</string>
     <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"داده، هم‌رسانی داده، به‌روزرسانی‌های هم‌رسانی داده، به‌روزرسانی‌های هم‌رسانی داده مکان، هم‌رسانی"</string>
-    <string name="advanced_title" msgid="6259362998269627310">"تنظیمات دیگر"</string>
+    <string name="advanced_title" msgid="6259362998269627310">"سایر تنظیمات"</string>
     <string name="more_settings_title" msgid="9033454654010697185">"امنیت و حریم خصوصی بیشتر"</string>
     <string name="more_settings_summary" msgid="7086620830002515710">"تکمیل خودکار، اعلان‌ها، و موارد دیگر"</string>
     <string name="more_settings_search_terms" msgid="1371913937610933955"></string>
diff --git a/SafetyCenter/Resources/res/values-fa-v36/strings.xml b/SafetyCenter/Resources/res/values-fa-v36/strings.xml
index 5a2885223b..05a888d21f 100644
--- a/SafetyCenter/Resources/res/values-fa-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-fa-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"کنترل نماینده بر برنامه‌های دیگر"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"انجام کنش در دستگاهتان و در برنامه‌های دیگر"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"چهره"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"چهره برای نمایه کاری"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-fi-v36/strings.xml b/SafetyCenter/Resources/res/values-fi-v36/strings.xml
index 42ab153096..a0f03b0772 100644
--- a/SafetyCenter/Resources/res/values-fi-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-fi-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agenttien hallinta muissa sovelluksissa"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Toimintojen suorittaminen laitteella ja muissa sovelluksissa"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Kasvot"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Kasvot (työ)"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-fr-rCA-v34/strings.xml b/SafetyCenter/Resources/res/values-fr-rCA-v34/strings.xml
index f4d710dfd5..956fd42aa2 100644
--- a/SafetyCenter/Resources/res/values-fr-rCA-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-fr-rCA-v34/strings.xml
@@ -22,7 +22,7 @@
     <string name="privacy_sources_summary" msgid="4083646673569677049">"Autorisations, tableau de bord, commandes"</string>
     <string name="health_connect_title" msgid="8318152190040327804">"Connexion santé"</string>
     <string name="health_connect_search_terms" msgid="4998970586245680829">"Santé, Connexion Santé"</string>
-    <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"Mises à jour des pratiques de partage des données pour la localisation"</string>
+    <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"Mises à jour du partage des données pour la localisation"</string>
     <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"Données, Partage des données, Mises à jour du partage des données, Mises à jour du partage des données pour la localisation, partage"</string>
     <string name="advanced_title" msgid="6259362998269627310">"Autres paramètres"</string>
     <string name="more_settings_title" msgid="9033454654010697185">"Plus de sécurité et de confidentialité"</string>
diff --git a/SafetyCenter/Resources/res/values-fr-rCA-v36/strings.xml b/SafetyCenter/Resources/res/values-fr-rCA-v36/strings.xml
index cc3a3dba61..8765b30397 100644
--- a/SafetyCenter/Resources/res/values-fr-rCA-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-fr-rCA-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Contrôle de l\'agent sur d\'autres applis"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Effectuez des actions sur votre appareil et dans d\'autres applis"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Reconnaissance faciale"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Reconnaissance faciale pour le travail"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-fr-v36/strings.xml b/SafetyCenter/Resources/res/values-fr-v36/strings.xml
index d5b3b68eca..2e72ee158f 100644
--- a/SafetyCenter/Resources/res/values-fr-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-fr-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Contrôle de l\'agent d\'autres applications"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Effectuez des actions sur votre appareil et dans d\'autres applis"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Visage"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Déverrouillage par reconnaissance faciale pour le travail"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-gl-v36/strings.xml b/SafetyCenter/Resources/res/values-gl-v36/strings.xml
index d0eed4528e..b31c035ce4 100644
--- a/SafetyCenter/Resources/res/values-gl-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-gl-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Control de axentes doutras aplicacións"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Leva a cabo accións no teu dispositivo e noutras aplicacións"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Cara"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Cara para o traballo"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-gu-v36/strings.xml b/SafetyCenter/Resources/res/values-gu-v36/strings.xml
index 709be02b9e..e1b6f1e2be 100644
--- a/SafetyCenter/Resources/res/values-gu-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-gu-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"અન્ય ઍપનું એજન્ટ નિયંત્રણ"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"તમારા ડિવાઇસ અને અન્ય ઍપ પર ઍક્શન પર્ફોર્મ કરો"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ફેસ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ડિવાઇસ પર કામ કરવા માટે ફેસ અનલૉક"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-hi-v34/strings.xml b/SafetyCenter/Resources/res/values-hi-v34/strings.xml
index c608d0f9ed..5efcab8163 100644
--- a/SafetyCenter/Resources/res/values-hi-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-hi-v34/strings.xml
@@ -25,7 +25,7 @@
     <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"जगह की जानकारी शेयर करने के तरीके के बारे में अपडेट"</string>
     <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"डेटा, डेटा शेयर करना, डेटा शेयर करने के अपडेट, जगह की जानकारी शेयर करने के बारे में अपडेट, शेयर करना"</string>
     <string name="advanced_title" msgid="6259362998269627310">"बेहतर सेटिंग"</string>
-    <string name="more_settings_title" msgid="9033454654010697185">"सुरक्षा और निजता की ज़्यादा सेटिंग"</string>
+    <string name="more_settings_title" msgid="9033454654010697185">"सुरक्षा और निजता से जुड़ी अन्य सेटिंग"</string>
     <string name="more_settings_summary" msgid="7086620830002515710">"जानकारी अपने-आप भरने की सुविधा, सूचनाएं वगैरह"</string>
     <string name="more_settings_search_terms" msgid="1371913937610933955"></string>
     <string name="work_policy_title" msgid="915692932391542104">"आपके ऑफ़िस की नीति के बारे में जानकारी"</string>
diff --git a/SafetyCenter/Resources/res/values-hi-v36/strings.xml b/SafetyCenter/Resources/res/values-hi-v36/strings.xml
index 3edfcabaa8..abbfc72af6 100644
--- a/SafetyCenter/Resources/res/values-hi-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-hi-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"अन्य ऐप्लिकेशन के लिए एजेंट कंट्रोल"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"डिवाइस और अन्य ऐप्लिकेशन में कार्रवाइयां करने की अनुमति दें"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"फ़ेस अनलॉक"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"डिवाइस पर काम करने के लिए फ़ेस अनलॉक"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-hr-v36/strings.xml b/SafetyCenter/Resources/res/values-hr-v36/strings.xml
index 8e8c0c2883..e670b80198 100644
--- a/SafetyCenter/Resources/res/values-hr-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-hr-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Pristup aplikacije agenta za druge aplikacije"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Izvršite radnje na uređaju i u drugim aplikacijama"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Lice"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Lice za poslovni profil"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-hu-v36/strings.xml b/SafetyCenter/Resources/res/values-hu-v36/strings.xml
index 065af914cc..079d448735 100644
--- a/SafetyCenter/Resources/res/values-hu-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-hu-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Más alkalmazások ügynöki vezérlése"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Műveletek végrehajtása az eszközön és más alkalmazásokban"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Arc"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Arc munkához"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-hy-v36/strings.xml b/SafetyCenter/Resources/res/values-hy-v36/strings.xml
index 97da4e698c..05b9028521 100644
--- a/SafetyCenter/Resources/res/values-hy-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-hy-v36/strings.xml
@@ -17,12 +17,14 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Այլ հավելվածների կառավարում գործակալի միջոցով"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Կատարեք գործողություններ ձեր սարքում և այլ հավելվածներում"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Դեմք"</string>
-    <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Դեմք (աշխատանք)"</string>
+    <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Դեմք աշխատանքի համար"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
     <string name="face_unlock_search_terms" msgid="2708195853333028283">"Դեմքով ապակողպում, դեմք"</string>
     <string name="fingerprint_unlock_title" msgid="5579868242026550596">"Մատնահետք"</string>
-    <string name="fingerprint_unlock_title_for_work" msgid="6343690273672384918">"Մատնահետք (աշխատանք)"</string>
+    <string name="fingerprint_unlock_title_for_work" msgid="6343690273672384918">"Մատնահետք աշխատանքի համար"</string>
     <string name="fingerprint_unlock_title_for_private_profile" msgid="9004513575240235691"></string>
     <string name="fingerprint_unlock_search_terms" msgid="688405183240088603">"Մատնահետք, մատ, ավելացնել մատնահետք"</string>
     <string name="wear_unlock_title" msgid="1613730442896319515">"Ժամացույց"</string>
diff --git a/SafetyCenter/Resources/res/values-in-v34/strings.xml b/SafetyCenter/Resources/res/values-in-v34/strings.xml
index 37061ad805..15f65a45ba 100644
--- a/SafetyCenter/Resources/res/values-in-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-in-v34/strings.xml
@@ -28,5 +28,5 @@
     <string name="more_settings_title" msgid="9033454654010697185">"Keamanan &amp; privasi lain"</string>
     <string name="more_settings_summary" msgid="7086620830002515710">"Isi otomatis, notifikasi, dan lain-lain"</string>
     <string name="more_settings_search_terms" msgid="1371913937610933955"></string>
-    <string name="work_policy_title" msgid="915692932391542104">"Info kebijakan profil kerja Anda"</string>
+    <string name="work_policy_title" msgid="915692932391542104">"Info kebijakan profil kerja"</string>
 </resources>
diff --git a/SafetyCenter/Resources/res/values-in-v36/strings.xml b/SafetyCenter/Resources/res/values-in-v36/strings.xml
index ed52e15576..e1760e46da 100644
--- a/SafetyCenter/Resources/res/values-in-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-in-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Kontrol agen aplikasi lain"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Melakukan tindakan di perangkat Anda dan di aplikasi lain"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Wajah"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Wajah untuk kerja"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-is-v36/strings.xml b/SafetyCenter/Resources/res/values-is-v36/strings.xml
index c1284b2a14..b7126d200e 100644
--- a/SafetyCenter/Resources/res/values-is-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-is-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Fulltrúastjórnun á öðrum forritum"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Framkvæmdu aðgerðir í tækinu þínu og öðrum forritum"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Andlit"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Andlit fyrir vinnu"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-it-v36/strings.xml b/SafetyCenter/Resources/res/values-it-v36/strings.xml
index 267daef8f5..61804087ef 100644
--- a/SafetyCenter/Resources/res/values-it-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-it-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Controllo dell\'agente su altre app"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Esegui azioni sul dispositivo e in altre app"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Volto"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Volto per lavoro"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-iw-v36/strings.xml b/SafetyCenter/Resources/res/values-iw-v36/strings.xml
index e17879fc31..5a45dbb402 100644
--- a/SafetyCenter/Resources/res/values-iw-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-iw-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"שליטה של סוכן באפליקציות אחרות"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ביצוע פעולות במכשיר ובאפליקציות אחרות"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"זיהוי הפנים"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"זיהוי הפנים לפרופיל העבודה"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ja-v36/strings.xml b/SafetyCenter/Resources/res/values-ja-v36/strings.xml
index 7fc642fe86..9e43b62c51 100644
--- a/SafetyCenter/Resources/res/values-ja-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ja-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"他のアプリのエージェントのコントロール"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"デバイスと他のアプリで操作を実行します"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"顔認証"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"顔認証（仕事用）"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ka-v36/strings.xml b/SafetyCenter/Resources/res/values-ka-v36/strings.xml
index 7234024373..0b66485ae1 100644
--- a/SafetyCenter/Resources/res/values-ka-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ka-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"სხვა აპების აგენტის კონტროლი"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"მოქმედებების შესრულება თქვენს მოწყობილობასა და სხვა აპებში"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"სახე"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"სახე სამუშაოსთვის"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-kk-v34/strings.xml b/SafetyCenter/Resources/res/values-kk-v34/strings.xml
index 362a4f700f..7a53985af7 100644
--- a/SafetyCenter/Resources/res/values-kk-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-kk-v34/strings.xml
@@ -22,8 +22,8 @@
     <string name="privacy_sources_summary" msgid="4083646673569677049">"Рұқсаттар, бақылау тақтасы, басқару элементтері"</string>
     <string name="health_connect_title" msgid="8318152190040327804">"Health Connect"</string>
     <string name="health_connect_search_terms" msgid="4998970586245680829">"Денсаулық, Health Connect"</string>
-    <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"Локация деректерін бөлісу жаңартулары"</string>
-    <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"Деректер, Деректерді бөлісу, Деректерді бөлісу жаңартулары, Локация деректерін бөлісу жаңартулары"</string>
+    <string name="app_data_sharing_updates_title" msgid="7428862330643262588">"Локация деректерін бөлісудегі өзгерістер"</string>
+    <string name="app_data_sharing_updates_search_terms" msgid="8414777373734245398">"Деректер, Деректерді бөлісу, Деректерді бөлісудегі өзгерістер, Локация деректерін бөлісудегі өзгерістер"</string>
     <string name="advanced_title" msgid="6259362998269627310">"Басқа параметрлер"</string>
     <string name="more_settings_title" msgid="9033454654010697185">"Күшейтілген қауіпсіздік пен құпиялық"</string>
     <string name="more_settings_summary" msgid="7086620830002515710">"Автотолтыру, хабарландырулар және тағы басқалар"</string>
diff --git a/SafetyCenter/Resources/res/values-kk-v36/strings.xml b/SafetyCenter/Resources/res/values-kk-v36/strings.xml
index c61a052579..cdc6cb7bb5 100644
--- a/SafetyCenter/Resources/res/values-kk-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-kk-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Басқа қолданбаларға агенттік бақылау жүргізу"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Құрылғыңыздағы және басқа қолданбалардағы әрекеттерді орындаңыз."</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Бет"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Жұмысқа арналған бет тану функциясы"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-km-v36/strings.xml b/SafetyCenter/Resources/res/values-km-v36/strings.xml
index cefd48bec8..7101e427ae 100644
--- a/SafetyCenter/Resources/res/values-km-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-km-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"ការគ្រប់គ្រងភ្នាក់ងាររបស់កម្មវិធីផ្សេងទៀត"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ធ្វើសកម្មភាពនៅលើឧបករណ៍របស់អ្នក និងនៅក្នុងកម្មវិធីផ្សេងទៀត"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"មុខ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"មុខ​សម្រាប់​ការងារ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-kn-v36/strings.xml b/SafetyCenter/Resources/res/values-kn-v36/strings.xml
index 222c4f1abb..a5b089accb 100644
--- a/SafetyCenter/Resources/res/values-kn-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-kn-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"ಇತರ ಆ್ಯಪ್‌ಗಳ ಏಜೆಂಟ್ ನಿಯಂತ್ರಣ"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ನಿಮ್ಮ ಸಾಧನದಲ್ಲಿ ಮತ್ತು ಇತರ ಆ್ಯಪ್‌ಗಳಲ್ಲಿ ಕ್ರಿಯೆಗಳನ್ನು ಮಾಡಿ"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ಫೇಸ್"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ಕೆಲಸದ ಸ್ಥಳದ ಫೇಸ್"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ko-v36/strings.xml b/SafetyCenter/Resources/res/values-ko-v36/strings.xml
index 619c47d665..a1d228407d 100644
--- a/SafetyCenter/Resources/res/values-ko-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ko-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"다른 앱의 에이전트 제어"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"기기 및 다른 앱에서 작업 수행"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"얼굴"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"직장용 얼굴"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ky-v36/strings.xml b/SafetyCenter/Resources/res/values-ky-v36/strings.xml
index 3e2823a053..f0e194694c 100644
--- a/SafetyCenter/Resources/res/values-ky-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ky-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Башка колдонмолордун агенттерин көзөмөлдөө"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Түзмөгүңүздө жана башка колдонмолордо аракеттерди аткарыңыз"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Жүз"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Жумуш колдонмолорун жүзүнөн таанып ачуу"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-lo-v36/strings.xml b/SafetyCenter/Resources/res/values-lo-v36/strings.xml
index e96e6c1a97..0add4875ee 100644
--- a/SafetyCenter/Resources/res/values-lo-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-lo-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"ຕົວແທນການຄວບຄຸມແອັບອື່ນໆ"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ດຳເນີນຄຳສັ່ງຢູ່ອຸປະກອນຂອງທ່ານ ແລະ ໃນແອັບອື່ນໆ"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ໃບໜ້າ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ໃບໜ້າສຳລັບວຽກ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-lt-v36/strings.xml b/SafetyCenter/Resources/res/values-lt-v36/strings.xml
index 5376e77547..510ea51bec 100644
--- a/SafetyCenter/Resources/res/values-lt-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-lt-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Kitų programų valdymas naudojant tarpininką"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Atlikti veiksmus jūsų įrenginyje ir kitose programose"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Veidas"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Atrakinimas pagal veidą, skirtas darbo profiliui"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-lv-v36/strings.xml b/SafetyCenter/Resources/res/values-lv-v36/strings.xml
index 57861575e5..5a6dd3acf7 100644
--- a/SafetyCenter/Resources/res/values-lv-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-lv-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Aģenta kontrole pār citām lietotnēm"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Veiciet darbības savā ierīcē un citās lietotnēs"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Seja"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Seja darba profilam"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-mk-v36/strings.xml b/SafetyCenter/Resources/res/values-mk-v36/strings.xml
index 7f29863938..3ccbe03513 100644
--- a/SafetyCenter/Resources/res/values-mk-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-mk-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Контрола на агенти на други апликации"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Извршувајте дејства на уредот и во други апликации"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Лик"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Лик за работен профил"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ml-v36/strings.xml b/SafetyCenter/Resources/res/values-ml-v36/strings.xml
index 902c676391..6b68c52bed 100644
--- a/SafetyCenter/Resources/res/values-ml-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ml-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"മറ്റ് ആപ്പുകളുടെ ഏജന്റ് നിയന്ത്രണം"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"നിങ്ങളുടെ ഉപകരണത്തിലും മറ്റ് ആപ്പുകളിലും പ്രവർത്തനങ്ങൾ നടത്തുക"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ഫെയ്‌സ്"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ഔദ്യോഗിക പ്രൊഫെെലിനുള്ള ഫെയ്‌സ്"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-mn-v36/strings.xml b/SafetyCenter/Resources/res/values-mn-v36/strings.xml
index 868fe1e63f..67216b2f76 100644
--- a/SafetyCenter/Resources/res/values-mn-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-mn-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent аппын бусад аппыг хянах эрх"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Төхөөрөмж дээрээ болон бусад аппад үйлдэл гүйцэтгэнэ үү"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Царай"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Ажлын зориулалтаар ашиглах царай"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-mr-v36/strings.xml b/SafetyCenter/Resources/res/values-mr-v36/strings.xml
index 6eef98db93..d93628e2d7 100644
--- a/SafetyCenter/Resources/res/values-mr-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-mr-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"इतर अ‍ॅप्सचे एजंट नियंत्रण"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"तुमच्या डिव्हाइसवर आणि इतर अ‍ॅप्समध्ये कृती करा"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"फेस"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"कार्य प्रोफाइलसाठी फेस अनलॉक"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ms-v36/strings.xml b/SafetyCenter/Resources/res/values-ms-v36/strings.xml
index e867d56297..0fc20d1457 100644
--- a/SafetyCenter/Resources/res/values-ms-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ms-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Kawalan ejen apl lain"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Lakukan tindakan pada peranti anda dan pada apl lain"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Wajah"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Wajah untuk profil kerja"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-my-v36/strings.xml b/SafetyCenter/Resources/res/values-my-v36/strings.xml
index 60475a70b3..f87ab1f352 100644
--- a/SafetyCenter/Resources/res/values-my-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-my-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"အခြားအက်ပ်များ၏ အေးဂျင့်ထိန်းချုပ်မှု"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"သင့်စက်နှင့် အခြားအက်ပ်များတွင် လုပ်ဆောင်ချက်များ ဆောင်ရွက်နိုင်သည်"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"မျက်နှာ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"အလုပ်အတွက် မျက်နှာ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-nb-v36/strings.xml b/SafetyCenter/Resources/res/values-nb-v36/strings.xml
index 7ad44d31f8..346536324d 100644
--- a/SafetyCenter/Resources/res/values-nb-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-nb-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agentkontroll av andre apper"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Utfør handlinger på enheten og i andre apper"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Ansikt"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Ansikt for jobb"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ne-v36/strings.xml b/SafetyCenter/Resources/res/values-ne-v36/strings.xml
index 5b7e161929..f01fdc021b 100644
--- a/SafetyCenter/Resources/res/values-ne-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ne-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"अन्य एपहरूको एजेन्ट कन्ट्रोल"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"आफ्नो डिभाइस र अन्य एपहरूमा कारबाहीहरू गर्नुहोस्"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"फेस अनलक"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"कामसम्बन्धी प्रयोजनका लागि फेस अनलक"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-nl-v36/strings.xml b/SafetyCenter/Resources/res/values-nl-v36/strings.xml
index 69db973387..15b07d969b 100644
--- a/SafetyCenter/Resources/res/values-nl-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-nl-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent-besturing van andere apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Acties uitvoeren op je apparaat en in andere apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Gezicht"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Gezicht voor werk"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-or-v36/strings.xml b/SafetyCenter/Resources/res/values-or-v36/strings.xml
index 6ca5d6efaa..ceb0c2f848 100644
--- a/SafetyCenter/Resources/res/values-or-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-or-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"ଅନ୍ୟ ଆପ୍ସର ଏଜେଣ୍ଟ ନିୟନ୍ତ୍ରଣ"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ଆପଣଙ୍କ ଡିଭାଇସ ଏବଂ ଅନ୍ୟ ଆପ୍ସରେ କାର୍ଯ୍ୟ ପରଫର୍ମ କରନ୍ତୁ"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ଫେସ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ୱାର୍କ ପାଇଁ ଫେସ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-or/strings.xml b/SafetyCenter/Resources/res/values-or/strings.xml
index d4d8d1a4a7..5dff0e8b2e 100644
--- a/SafetyCenter/Resources/res/values-or/strings.xml
+++ b/SafetyCenter/Resources/res/values-or/strings.xml
@@ -30,7 +30,7 @@
     <string name="permission_usage_title" msgid="3633779688945350407">"ଗୋପନୀୟତା ଡେସବୋର୍ଡ"</string>
     <string name="permission_usage_summary" msgid="5323079206029964468">"କେଉଁ ଆପ୍ସ ଏବେ ଅନୁମତିଗୁଡ଼ିକ ବ୍ୟବହାର କରିଛି ତାହା ଦେଖାନ୍ତୁ"</string>
     <string name="permission_usage_search_terms" msgid="3852343592870257104">"ଗୋପନୀୟତା, ଗୋପନୀୟତା ଡେସବୋର୍ଡ"</string>
-    <string name="permission_manager_title" msgid="5277347862821255015">"ପର୍ମିସନ ମେନେଜର"</string>
+    <string name="permission_manager_title" msgid="5277347862821255015">"ଅନୁମତି ପରିଚାଳକ"</string>
     <string name="permission_manager_summary" msgid="8099852107340970790">"ଆପଣଙ୍କ ଡାଟାକୁ ଆପର ଆକ୍ସେସ ନିୟନ୍ତ୍ରଣ କରନ୍ତୁ"</string>
     <string name="permission_manager_search_terms" msgid="2895147613099694722">"ଅନୁମତି, ଅନୁମତି ପରିଚାଳକ"</string>
     <string name="privacy_controls_title" msgid="5322875777945432395">"ଗୋପନୀୟତା ନିୟନ୍ତ୍ରଣଗୁଡ଼ିକ"</string>
diff --git a/SafetyCenter/Resources/res/values-pa-v36/strings.xml b/SafetyCenter/Resources/res/values-pa-v36/strings.xml
index 2dc9bb8c9e..805ac03eef 100644
--- a/SafetyCenter/Resources/res/values-pa-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-pa-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"ਹੋਰ ਐਪਾਂ ਦਾ ਏਜੰਟ ਕੰਟਰੋਲ"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ਆਪਣੇ ਡੀਵਾਈਸ ਅਤੇ ਹੋਰ ਐਪਾਂ ਵਿੱਚ ਕਾਰਵਾਈਆਂ ਕਰੋ"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ਫ਼ੇਸ ਅਣਲਾਕ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ਕੰਮ ਲਈ ਫ਼ੇਸ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-pl-v36/strings.xml b/SafetyCenter/Resources/res/values-pl-v36/strings.xml
index 8705e008c9..778af93bed 100644
--- a/SafetyCenter/Resources/res/values-pl-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-pl-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agent ma kontrolę nad innymi aplikacjami"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Wykonuj działania na urządzeniu i w innych aplikacjach"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Twarz"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Twarz – profil służbowy"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-pt-rBR-v36/strings.xml b/SafetyCenter/Resources/res/values-pt-rBR-v36/strings.xml
index 144078c11d..70b6028cbe 100644
--- a/SafetyCenter/Resources/res/values-pt-rBR-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-pt-rBR-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Outros apps são controlados por um agente"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Realizar ações no dispositivo e em outros apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Rosto"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Reconhecimento facial para o trabalho"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-pt-rBR/strings.xml b/SafetyCenter/Resources/res/values-pt-rBR/strings.xml
index ea356263a3..342b1e6a0f 100644
--- a/SafetyCenter/Resources/res/values-pt-rBR/strings.xml
+++ b/SafetyCenter/Resources/res/values-pt-rBR/strings.xml
@@ -24,7 +24,7 @@
     <string name="lock_screen_summary_disabled" msgid="354071230916616692">"Ainda não há informações"</string>
     <string name="lock_screen_search_terms" msgid="2678486357779794826">"Bloqueio do dispositivo, Bloqueio de tela, Tela de bloqueio, Senha, PIN, Padrão"</string>
     <string name="biometrics_title" msgid="5859504610285212938">"Biometria"</string>
-    <string name="biometrics_search_terms" msgid="6040319118762671981">"Impressão digital, Dedo, Adicionar impressão digital, Desbloqueio facial, Rosto"</string>
+    <string name="biometrics_search_terms" msgid="6040319118762671981">"Impressão digital, dedo, adicionar impressão digital, desbloqueio facial, rosto"</string>
     <string name="privacy_sources_title" msgid="4061110826457365957">"Privacidade"</string>
     <string name="privacy_sources_summary" msgid="4089719981155120864">"Painel, permissões, controles"</string>
     <string name="permission_usage_title" msgid="3633779688945350407">"Painel de privacidade"</string>
diff --git a/SafetyCenter/Resources/res/values-pt-rPT-v36/strings.xml b/SafetyCenter/Resources/res/values-pt-rPT-v36/strings.xml
index 10a613c26d..1c27a33d3d 100644
--- a/SafetyCenter/Resources/res/values-pt-rPT-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-pt-rPT-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Controlo de agentes de outras apps"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Execute ações no seu dispositivo e noutras apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Rosto"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Rosto para trabalho"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-pt-v36/strings.xml b/SafetyCenter/Resources/res/values-pt-v36/strings.xml
index 144078c11d..70b6028cbe 100644
--- a/SafetyCenter/Resources/res/values-pt-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-pt-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Outros apps são controlados por um agente"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Realizar ações no dispositivo e em outros apps"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Rosto"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Reconhecimento facial para o trabalho"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-pt/strings.xml b/SafetyCenter/Resources/res/values-pt/strings.xml
index ea356263a3..342b1e6a0f 100644
--- a/SafetyCenter/Resources/res/values-pt/strings.xml
+++ b/SafetyCenter/Resources/res/values-pt/strings.xml
@@ -24,7 +24,7 @@
     <string name="lock_screen_summary_disabled" msgid="354071230916616692">"Ainda não há informações"</string>
     <string name="lock_screen_search_terms" msgid="2678486357779794826">"Bloqueio do dispositivo, Bloqueio de tela, Tela de bloqueio, Senha, PIN, Padrão"</string>
     <string name="biometrics_title" msgid="5859504610285212938">"Biometria"</string>
-    <string name="biometrics_search_terms" msgid="6040319118762671981">"Impressão digital, Dedo, Adicionar impressão digital, Desbloqueio facial, Rosto"</string>
+    <string name="biometrics_search_terms" msgid="6040319118762671981">"Impressão digital, dedo, adicionar impressão digital, desbloqueio facial, rosto"</string>
     <string name="privacy_sources_title" msgid="4061110826457365957">"Privacidade"</string>
     <string name="privacy_sources_summary" msgid="4089719981155120864">"Painel, permissões, controles"</string>
     <string name="permission_usage_title" msgid="3633779688945350407">"Painel de privacidade"</string>
diff --git a/SafetyCenter/Resources/res/values-ro-v36/strings.xml b/SafetyCenter/Resources/res/values-ro-v36/strings.xml
index edc1a5ad9c..04c6e9591e 100644
--- a/SafetyCenter/Resources/res/values-ro-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ro-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Controlul agentului asupra altor aplicații"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Realizează acțiuni pe dispozitivul tău și în alte aplicații"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Chip"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Chip pentru serviciu"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ru-v36/strings.xml b/SafetyCenter/Resources/res/values-ru-v36/strings.xml
index cdaea134f1..d03828b3da 100644
--- a/SafetyCenter/Resources/res/values-ru-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ru-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Агентное управление другими приложениями"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Совершайте действия на своем устройстве и в других приложениях"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Лицо"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Лицо для работы"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-si-v36/strings.xml b/SafetyCenter/Resources/res/values-si-v36/strings.xml
index 4bf8b1c89f..f1b44141f7 100644
--- a/SafetyCenter/Resources/res/values-si-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-si-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"වෙනත් යෙදුම්වල නියෝජිත පාලනය"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ඔබේ උපාංගයේ සහ අනෙකුත් යෙදුම්වල ක්‍රියා සිදු කරන්න"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"මුහුණ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"රැකියාව සඳහා මුහුණ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-sk-v36/strings.xml b/SafetyCenter/Resources/res/values-sk-v36/strings.xml
index ffbc3391eb..e04498259f 100644
--- a/SafetyCenter/Resources/res/values-sk-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-sk-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Ovládanie iných aplikácií agentom"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Vykonávajte akcie vo svojom zariadení a ďalších aplikáciách"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Tvár"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Tvár pre prácu"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-sl-v36/strings.xml b/SafetyCenter/Resources/res/values-sl-v36/strings.xml
index 9f0a32d41c..a5b6a61d84 100644
--- a/SafetyCenter/Resources/res/values-sl-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-sl-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Nadzor agenta nad drugimi aplikacijami"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Izvajanje dejanj v napravi in drugih aplikacijah"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Obraz"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Obraz za službo"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-sq-v36/strings.xml b/SafetyCenter/Resources/res/values-sq-v36/strings.xml
index ee8d02923a..77bd5e7300 100644
--- a/SafetyCenter/Resources/res/values-sq-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-sq-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Kontrolli i agjentit në aplikacione të tjera"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Kryej veprime në pajisjen tënde dhe në aplikacione të tjera"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Fytyra"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Fytyra për punën"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-sr-v36/strings.xml b/SafetyCenter/Resources/res/values-sr-v36/strings.xml
index 9a73a07075..306ee5e190 100644
--- a/SafetyCenter/Resources/res/values-sr-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-sr-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Контролишите друге апликације помоћу агента"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Обављајте радње на уређају и у другим апликацијама"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Лице"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Откључавање лицем за посао"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-sv-v36/strings.xml b/SafetyCenter/Resources/res/values-sv-v36/strings.xml
index c79423a8fc..4194011645 100644
--- a/SafetyCenter/Resources/res/values-sv-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-sv-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Agentstyrning av andra appar"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Utför åtgärder på enheten och i andra appar"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Ansikte"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Ansikte för jobbet"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-sw-v36/strings.xml b/SafetyCenter/Resources/res/values-sw-v36/strings.xml
index 61d141ab99..010116dc3e 100644
--- a/SafetyCenter/Resources/res/values-sw-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-sw-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Usaidizi wa kudhibiti programu nyingine"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Hutekeleza vitendo kwenye kifaa chako na katika programu nyingine"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Uso"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Uso kwenye wasifu wa kazini"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ta-v36/strings.xml b/SafetyCenter/Resources/res/values-ta-v36/strings.xml
index 2d81dcc9f6..8823ec484a 100644
--- a/SafetyCenter/Resources/res/values-ta-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ta-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"பிற ஆப்ஸின் ஏஜெண்ட் கட்டுப்பாடு"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"உங்கள் சாதனத்திலும் பிற ஆப்ஸிலும் செயல்களைச் செய்யலாம்"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"முகம்"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"பணிக்கான முகம்"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-te-v34/strings.xml b/SafetyCenter/Resources/res/values-te-v34/strings.xml
index 9ca7bea5f7..e7064c464c 100644
--- a/SafetyCenter/Resources/res/values-te-v34/strings.xml
+++ b/SafetyCenter/Resources/res/values-te-v34/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="lock_screen_sources_title" msgid="5493678510117489865">"పరికర అన్‌లాక్"</string>
+    <string name="lock_screen_sources_title" msgid="5493678510117489865">"డివైజ్ అన్‌లాక్"</string>
     <string name="biometrics_title_for_work" msgid="1842284049407771568">"వర్క్ యాప్‌ల కోసం బయోమెట్రిక్స్"</string>
     <string name="privacy_sources_summary" msgid="4083646673569677049">"అనుమతులు, డ్యాష్‌బోర్డ్, కంట్రోల్స్"</string>
     <string name="health_connect_title" msgid="8318152190040327804">"Health Connect"</string>
diff --git a/SafetyCenter/Resources/res/values-te-v36/strings.xml b/SafetyCenter/Resources/res/values-te-v36/strings.xml
index ff5785cff0..95270f0b85 100644
--- a/SafetyCenter/Resources/res/values-te-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-te-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"ఇతర యాప్‌లకు సంబంధించిన ఏజెంట్ కంట్రోల్"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"మీ డివైజ్‌లో, ఇతర యాప్‌లలో చర్యలను అమలు చేయండి"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ముఖం"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ఆఫీస్ కోసం ఫేస్ అన్‌లాక్"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-th-v36/strings.xml b/SafetyCenter/Resources/res/values-th-v36/strings.xml
index ca675dee0a..bd3f0a262a 100644
--- a/SafetyCenter/Resources/res/values-th-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-th-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"การควบคุมแอปอื่นๆ ของตัวแทน"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"ดำเนินการต่างๆ บนอุปกรณ์และในแอปอื่นๆ"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"ใบหน้า"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"ใช้ใบหน้าสำหรับการทำงาน"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-tl-v36/strings.xml b/SafetyCenter/Resources/res/values-tl-v36/strings.xml
index ab3854f748..2f7151fc0c 100644
--- a/SafetyCenter/Resources/res/values-tl-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-tl-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Kontrol ng ahente sa iba pang app"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Magsagawa ng mga aksyon sa iyong device at sa iba pang app"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Mukha"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Mukha sa trabaho"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-tr-v36/strings.xml b/SafetyCenter/Resources/res/values-tr-v36/strings.xml
index 9bc9110c42..728ab33f68 100644
--- a/SafetyCenter/Resources/res/values-tr-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-tr-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Temsilcinin diğer uygulamaları kontrol etmesi"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Cihazınızda ve diğer uygulamalarda işlem yapma"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Yüz"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Çalışma için yüz"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-uk-v36/strings.xml b/SafetyCenter/Resources/res/values-uk-v36/strings.xml
index 22cc885e6b..7654352203 100644
--- a/SafetyCenter/Resources/res/values-uk-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-uk-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Керування іншими додатками за допомогою агента"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Виконуйте дії на пристрої і в інших додатках"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Обличчя"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Фейс-контроль для роботи"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-ur-v36/strings.xml b/SafetyCenter/Resources/res/values-ur-v36/strings.xml
index 0d1b90f129..46c2616df6 100644
--- a/SafetyCenter/Resources/res/values-ur-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-ur-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"دیگر ایپس کا ایجنٹ کنٹرول"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"اپنے آلے پر اور دیگر ایپس میں کارروائیاں کریں"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"چہرہ"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"کام کے لیے چہرہ"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-uz-v36/strings.xml b/SafetyCenter/Resources/res/values-uz-v36/strings.xml
index 06aea14bbf..47954be1b5 100644
--- a/SafetyCenter/Resources/res/values-uz-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-uz-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Boshqa ilovalar agent nazorati"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Qurilmangiz va boshqa ilovalarda amallar bajaring"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Yuz"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Ish uchun yuz"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-v36/config.xml b/SafetyCenter/Resources/res/values-v36/config.xml
index 6fa28a3403..6624b6a32d 100644
--- a/SafetyCenter/Resources/res/values-v36/config.xml
+++ b/SafetyCenter/Resources/res/values-v36/config.xml
@@ -17,5 +17,5 @@
 
 <resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <!-- Comma separated list of safety source IDs to show in the same task as the safety center -->
-    <string name="config_same_task_safety_source_ids" translatable="false">AndroidAccessibility,AndroidBackgroundLocation,AndroidBiometrics,AndroidFaceUnlock,AndroidFingerprintUnlock,AndroidHealthConnect,AndroidLockScreen,AndroidPrivateSpace,AndroidMoreSettings,AndroidNotificationListener,AndroidPermissionAutoRevoke,AndroidPermissionManager,AndroidPermissionUsage,AndroidPrivacyAppDataSharingUpdates,AndroidPrivacyControls,AndroidWearUnlock,AndroidWorkPolicyInfo</string>
+    <string name="config_same_task_safety_source_ids" translatable="false">AndroidAccessibility,AndroidAppFunctionAccess,AndroidBackgroundLocation,AndroidBiometrics,AndroidFaceUnlock,AndroidFingerprintUnlock,AndroidHealthConnect,AndroidLockScreen,AndroidPrivateSpace,AndroidMoreSettings,AndroidNotificationListener,AndroidPermissionAutoRevoke,AndroidPermissionManager,AndroidPermissionUsage,AndroidPrivacyAppDataSharingUpdates,AndroidPrivacyControls,AndroidWearUnlock,AndroidWorkPolicyInfo</string>
 </resources>
diff --git a/SafetyCenter/Resources/res/values-v36/strings.xml b/SafetyCenter/Resources/res/values-v36/strings.xml
index f452e045a8..1e1f031bfc 100644
--- a/SafetyCenter/Resources/res/values-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-v36/strings.xml
@@ -16,6 +16,9 @@
   -->
 
 <resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string name="app_function_access_settings_title" description="The title of the entry for App Function Access Settings">Agent control of other apps</string>
+  <string name="app_function_access_settings_summary" description="The summary of the entry for App Function Access Settings, which describes the page contents">Perform actions on your device and in other apps</string>
+
   <string name="face_unlock_title" description="The default title of the setting for managing face unlock options on the device">Face</string>
   <string name="face_unlock_title_for_work" description="The default title of the setting for managing face unlock options for work on the device">Face for work</string>
   <string name="face_unlock_title_for_private_profile" description="The default title of the setting for managing face unlock options for private profile on the device"><!-- Empty placeholder--></string>
diff --git a/SafetyCenter/Resources/res/values-vi-v36/strings.xml b/SafetyCenter/Resources/res/values-vi-v36/strings.xml
index 3665f3bcfe..0a985b5eb8 100644
--- a/SafetyCenter/Resources/res/values-vi-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-vi-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Tác nhân kiểm soát các ứng dụng khác"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Thao tác trên thiết bị và trong các ứng dụng khác"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Khuôn mặt"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Khuôn mặt cho ứng dụng công việc"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-zh-rCN-v36/strings.xml b/SafetyCenter/Resources/res/values-zh-rCN-v36/strings.xml
index e60d81f96f..6f37d7b7d1 100644
--- a/SafetyCenter/Resources/res/values-zh-rCN-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-zh-rCN-v36/strings.xml
@@ -17,7 +17,9 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="face_unlock_title" msgid="3991635517593572926">"人脸"</string>
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"其他应用的代理控制"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"在您的设备和其他应用中执行操作"</string>
+    <string name="face_unlock_title" msgid="3991635517593572926">"面孔"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"工作专用人脸"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
     <string name="face_unlock_search_terms" msgid="2708195853333028283">"人脸解锁, 人脸, Face unlock, Face"</string>
diff --git a/SafetyCenter/Resources/res/values-zh-rCN/strings.xml b/SafetyCenter/Resources/res/values-zh-rCN/strings.xml
index 4348fb7082..56b03d46a5 100644
--- a/SafetyCenter/Resources/res/values-zh-rCN/strings.xml
+++ b/SafetyCenter/Resources/res/values-zh-rCN/strings.xml
@@ -41,6 +41,6 @@
     <string name="advanced_security_summary" msgid="6172253327022425123">"加密、凭据等"</string>
     <string name="advanced_security_search_terms" msgid="3350609555814362075"></string>
     <string name="advanced_privacy_title" msgid="1117725225706176643">"更多隐私设置"</string>
-    <string name="advanced_privacy_summary" msgid="2281203390575069543">"自动填充、活动控件等"</string>
+    <string name="advanced_privacy_summary" msgid="2281203390575069543">"自动填充、活动记录控制选项等"</string>
     <string name="advanced_privacy_search_terms" msgid="5044404599789175222"></string>
 </resources>
diff --git a/SafetyCenter/Resources/res/values-zh-rHK-v36/strings.xml b/SafetyCenter/Resources/res/values-zh-rHK-v36/strings.xml
index 55c92891de..31b1ccdcc3 100644
--- a/SafetyCenter/Resources/res/values-zh-rHK-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-zh-rHK-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"其他應用程式的代理控制項"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"在裝置和其他應用程式中執行操作"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"面孔"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"工作設定檔的面孔"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-zh-rTW-v36/strings.xml b/SafetyCenter/Resources/res/values-zh-rTW-v36/strings.xml
index 9adfdca6f1..9cd5eef24d 100644
--- a/SafetyCenter/Resources/res/values-zh-rTW-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-zh-rTW-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"其他應用程式的代理控制選項"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"在裝置和其他應用程式中執行操作"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"人臉"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"使用人臉解鎖工作資料夾"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/res/values-zu-v36/strings.xml b/SafetyCenter/Resources/res/values-zu-v36/strings.xml
index bba0ffe789..34909f75c4 100644
--- a/SafetyCenter/Resources/res/values-zu-v36/strings.xml
+++ b/SafetyCenter/Resources/res/values-zu-v36/strings.xml
@@ -17,6 +17,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_function_access_settings_title" msgid="3894819108224606683">"Isilawuli somenzeli samanye ama-app"</string>
+    <string name="app_function_access_settings_summary" msgid="2719347800336419237">"Yenza okuthile kudivayisi yakho nakwamanye ama-app"</string>
     <string name="face_unlock_title" msgid="3991635517593572926">"Ubuso"</string>
     <string name="face_unlock_title_for_work" msgid="1451170625947022012">"Ubuso bomsebenzi"</string>
     <string name="face_unlock_title_for_private_profile" msgid="2758692637409168420"></string>
diff --git a/SafetyCenter/Resources/shared_res/values-ne/strings.xml b/SafetyCenter/Resources/shared_res/values-ne/strings.xml
index e7c392a3b7..a7f9c73e34 100644
--- a/SafetyCenter/Resources/shared_res/values-ne/strings.xml
+++ b/SafetyCenter/Resources/shared_res/values-ne/strings.xml
@@ -41,7 +41,7 @@
     <string name="redirecting_error" msgid="8146983632878233202">"पेज खोल्न सकिएन"</string>
     <string name="resolving_action_error" msgid="371968886143262375">"अलर्ट समाधान गर्न सकिएन"</string>
     <string name="refresh_error" msgid="656062128422446177">"{count,plural, =1{सेटिङ जाँच गर्न सकिएन}other{सेटिङहरू जाँच गर्न सकिएन}}"</string>
-    <string name="work_profile_paused" msgid="7037400224040869079">"कार्य प्रोफाइल पज गरिएको छ"</string>
+    <string name="work_profile_paused" msgid="7037400224040869079">"वर्क प्रोफाइल पज गरिएको छ"</string>
     <string name="group_unknown_summary" msgid="6951386960814105641">"कुनै जानकारी उपलब्ध छैन"</string>
     <string name="notification_channel_group_name" msgid="7155072032524876859">"सुरक्षा तथा गोपनीयता"</string>
     <string name="notification_channel_name_information" msgid="2966444432152990166">"सिफारिसहरू"</string>
diff --git a/SafetyCenter/Resources/shared_res/values-zh-rHK/strings.xml b/SafetyCenter/Resources/shared_res/values-zh-rHK/strings.xml
index 071d4bad11..296fd6a22f 100644
--- a/SafetyCenter/Resources/shared_res/values-zh-rHK/strings.xml
+++ b/SafetyCenter/Resources/shared_res/values-zh-rHK/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="scanning_title" msgid="5424849039854311398">"正在掃瞄"</string>
     <string name="loading_summary" msgid="3740846439782713910">"正在檢查裝置設定…"</string>
-    <string name="overall_severity_level_ok_title" msgid="2041250138727564565">"沒有問題"</string>
+    <string name="overall_severity_level_ok_title" msgid="2041250138727564565">"一切正常"</string>
     <string name="overall_severity_level_ok_summary" msgid="383626536912856690">"未發現任何問題"</string>
     <string name="overall_severity_level_tip_summary" msgid="1935765582243024999">"{count,plural, =1{查看建議}other{查看建議}}"</string>
     <string name="overall_severity_level_action_taken_summary" msgid="8064091657855656545">"{count,plural, =1{已採取行動}other{已採取行動}}"</string>
diff --git a/SafetyCenter/Resources/shared_res/values-zh-rTW/strings.xml b/SafetyCenter/Resources/shared_res/values-zh-rTW/strings.xml
index beb5af4a29..98c26cfac8 100644
--- a/SafetyCenter/Resources/shared_res/values-zh-rTW/strings.xml
+++ b/SafetyCenter/Resources/shared_res/values-zh-rTW/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="scanning_title" msgid="5424849039854311398">"掃描"</string>
     <string name="loading_summary" msgid="3740846439782713910">"正在檢查裝置設定…"</string>
-    <string name="overall_severity_level_ok_title" msgid="2041250138727564565">"沒有問題"</string>
+    <string name="overall_severity_level_ok_title" msgid="2041250138727564565">"一切正常"</string>
     <string name="overall_severity_level_ok_summary" msgid="383626536912856690">"未發現任何問題"</string>
     <string name="overall_severity_level_tip_summary" msgid="1935765582243024999">"{count,plural, =1{查看建議}other{查看建議}}"</string>
     <string name="overall_severity_level_action_taken_summary" msgid="8064091657855656545">"{count,plural, =1{已採取行動}other{已採取行動}}"</string>
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
index 99a50ab7d3..743355ffa2 100644
--- a/flags/flags.aconfig
+++ b/flags/flags.aconfig
@@ -174,3 +174,20 @@ flag {
     bug: "399872661"
     is_fixed_read_only: true
 }
+
+flag {
+    name: "system_financed_device_controller"
+    is_exported: true
+    namespace: "growth_dlc"
+    description: "Flag to expose SYSTEM_FINANCED_DEVICE_CONTROLLER as a SystemApi"
+    bug: "402301589"
+    is_fixed_read_only: true
+ }
+
+flag {
+    name: "app_function_service_enabled"
+    namespace: "permissions"
+    description: "This flag is used to enable device state app functions service"
+    bug: "409105506"
+    is_fixed_read_only: true
+}
diff --git a/framework-s/api/system-current.txt b/framework-s/api/system-current.txt
index c5d971435c..07772ba875 100644
--- a/framework-s/api/system-current.txt
+++ b/framework-s/api/system-current.txt
@@ -62,9 +62,11 @@ package android.app.role {
     field public static final String ROLE_DEVICE_POLICY_MANAGEMENT = "android.app.role.DEVICE_POLICY_MANAGEMENT";
     field public static final String ROLE_FINANCED_DEVICE_KIOSK = "android.app.role.FINANCED_DEVICE_KIOSK";
     field @FlaggedApi("com.android.permission.flags.cross_user_role_enabled") public static final String ROLE_RESERVED_FOR_TESTING_PROFILE_GROUP_EXCLUSIVITY = "android.app.role.RESERVED_FOR_TESTING_PROFILE_GROUP_EXCLUSIVITY";
+    field @FlaggedApi("android.permission.flags.supervision_role_enabled") public static final String ROLE_SUPERVISION = "android.app.role.SUPERVISION";
     field public static final String ROLE_SYSTEM_ACTIVITY_RECOGNIZER = "android.app.role.SYSTEM_ACTIVITY_RECOGNIZER";
     field public static final String ROLE_SYSTEM_CALL_STREAMING = "android.app.role.SYSTEM_CALL_STREAMING";
     field @FlaggedApi("android.content.pm.sdk_dependency_installer") public static final String ROLE_SYSTEM_DEPENDENCY_INSTALLER = "android.app.role.SYSTEM_DEPENDENCY_INSTALLER";
+    field @FlaggedApi("com.android.permission.flags.system_financed_device_controller") public static final String ROLE_SYSTEM_FINANCED_DEVICE_CONTROLLER = "android.app.role.SYSTEM_FINANCED_DEVICE_CONTROLLER";
     field public static final String ROLE_SYSTEM_SUPERVISION = "android.app.role.SYSTEM_SUPERVISION";
     field public static final String ROLE_SYSTEM_WELLBEING = "android.app.role.SYSTEM_WELLBEING";
   }
diff --git a/framework-s/java/android/app/role/RoleManager.java b/framework-s/java/android/app/role/RoleManager.java
index 9f28b7f192..6c5d60e6bf 100644
--- a/framework-s/java/android/app/role/RoleManager.java
+++ b/framework-s/java/android/app/role/RoleManager.java
@@ -171,6 +171,15 @@ public final class RoleManager {
     @SystemApi
     public static final String ROLE_SYSTEM_SUPERVISION = "android.app.role.SYSTEM_SUPERVISION";
 
+    /**
+     * The name of the supervision role.
+     *
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_SUPERVISION_ROLE_ENABLED)
+    @SystemApi
+    public static final String ROLE_SUPERVISION = "android.app.role.SUPERVISION";
+
     /**
      * The name of the system activity recognizer role.
      *
@@ -202,6 +211,22 @@ public final class RoleManager {
     public static final String ROLE_FINANCED_DEVICE_KIOSK =
             "android.app.role.FINANCED_DEVICE_KIOSK";
 
+    /**
+     * The name of the system financed device controller role.
+     *
+     * This role grants the device lock controller a set of permissions that allows it
+     * to manage the device state for financed devices. When a creditor app that holds the
+     * {@link #ROLE_FINANCED_DEVICE_KIOSK} role invokes the lock or unlock command on a
+     * financed device, it is through the device lock controller that the accompanying policies
+     * are enforced.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(com.android.permission.flags.Flags.FLAG_SYSTEM_FINANCED_DEVICE_CONTROLLER)
+    public static final String ROLE_SYSTEM_FINANCED_DEVICE_CONTROLLER =
+            "android.app.role.SYSTEM_FINANCED_DEVICE_CONTROLLER";
+
     /**
      * The name of the system call streaming role.
      *
diff --git a/service/Android.bp b/service/Android.bp
index b6e85b0fc9..d3a9bbd7be 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -21,7 +21,6 @@ filegroup {
     name: "service-permission-java-sources",
     srcs: [
         "java/**/*.java",
-        "java/**/*.kt",
     ],
     path: "java",
     visibility: ["//visibility:private"],
@@ -90,14 +89,9 @@ java_sdk_library {
         "framework-permission-s-shared",
         "framework-statsd.stubs.module_lib",
         "jsr305",
-
-        // Soong fails to automatically add this dependency because all the
-        // *.kt sources are inside a filegroup.
-        "kotlin-annotations",
         "safety-center-annotations",
     ],
     static_libs: [
-        "kotlin-stdlib",
         "modules-utils-backgroundthread",
         "modules-utils-build",
         "modules-utils-os",
@@ -119,13 +113,6 @@ java_sdk_library {
     },
     exclude_kotlinc_generated_files: true,
     jarjar_rules: "jarjar-rules.txt",
-    kotlincflags: [
-        "-Werror",
-        "-Xjvm-default=all",
-        "-Xno-call-assertions",
-        "-Xno-param-assertions",
-        "-Xno-receiver-assertions",
-    ],
     lint: {
         baseline_filename: "lint-baseline.xml",
     },
diff --git a/service/jarjar-rules.txt b/service/jarjar-rules.txt
index d9833ca56c..786e7f8201 100644
--- a/service/jarjar-rules.txt
+++ b/service/jarjar-rules.txt
@@ -43,6 +43,9 @@ rule com.android.safetycenter.internaldata.** com.android.permission.jarjar.@0
 rule com.android.safetycenter.pendingintents.** com.android.permission.jarjar.@0
 rule com.android.safetycenter.resources.** com.android.permission.jarjar.@0
 rule com.google.protobuf.** com.android.permission.jarjar.@0
-rule kotlin.** com.android.permission.jarjar.@0
 rule com.android.permissioncontroller.PermissionControllerStatsLog com.android.permission.jarjar.@0
+rule com.android.window.flags.*FeatureFlags* com.android.permission.jarjar.@0
+rule com.android.window.flags.FeatureFlags* com.android.permission.jarjar.@0
+rule com.android.window.flags.FeatureFlags com.android.permission.jarjar.@0
+rule com.android.window.flags.Flags com.android.permission.jarjar.@0
 # LINT.ThenChange(PermissionController/role-controller/java/com/android/role/controller/model/RoleParser.java:applyJarjarTransform)
diff --git a/service/java/com/android/ecm/EnhancedConfirmationService.java b/service/java/com/android/ecm/EnhancedConfirmationService.java
index 64b5724a22..eaa8bb098b 100644
--- a/service/java/com/android/ecm/EnhancedConfirmationService.java
+++ b/service/java/com/android/ecm/EnhancedConfirmationService.java
@@ -43,6 +43,7 @@ import android.content.pm.PackageInstaller;
 import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.NameNotFoundException;
 import android.content.pm.SignedPackage;
+import android.content.res.Resources;
 import android.database.Cursor;
 import android.net.Uri;
 import android.os.Binder;
@@ -65,6 +66,7 @@ import android.view.accessibility.AccessibilityManager;
 
 import androidx.annotation.Keep;
 import androidx.annotation.RequiresApi;
+import androidx.annotation.VisibleForTesting;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.util.Preconditions;
@@ -76,6 +78,7 @@ import com.android.server.SystemService;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
@@ -110,41 +113,15 @@ public class EnhancedConfirmationService extends SystemService {
         int ECM_STATE_IMPLICIT = AppOpsManager.MODE_DEFAULT;
     }
 
-    private static final ArraySet<String> PER_PACKAGE_PROTECTED_SETTINGS = new ArraySet<>();
+    private static final String EXEMPT_ALL_SETTINGS = "*";
+
+    @VisibleForTesting
+    final ArraySet<String> mPerPackageProtectedSettings = new ArraySet<>();
 
     // Settings restricted when an untrusted call is ongoing. These must also be added to
     // PROTECTED_SETTINGS
-    private static final ArraySet<String> UNTRUSTED_CALL_RESTRICTED_SETTINGS = new ArraySet<>();
-
-    static {
-        // Runtime permissions
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.SEND_SMS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.RECEIVE_SMS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.READ_SMS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.RECEIVE_MMS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.RECEIVE_WAP_PUSH);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.READ_CELL_BROADCASTS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission_group.SMS);
-
-        PER_PACKAGE_PROTECTED_SETTINGS.add(Manifest.permission.BIND_DEVICE_ADMIN);
-        // App ops
-        PER_PACKAGE_PROTECTED_SETTINGS.add(AppOpsManager.OPSTR_BIND_ACCESSIBILITY_SERVICE);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(AppOpsManager.OPSTR_ACCESS_NOTIFICATIONS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(AppOpsManager.OPSTR_GET_USAGE_STATS);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(AppOpsManager.OPSTR_LOADER_USAGE_STATS);
-        // Default application roles.
-        PER_PACKAGE_PROTECTED_SETTINGS.add(RoleManager.ROLE_DIALER);
-        PER_PACKAGE_PROTECTED_SETTINGS.add(RoleManager.ROLE_SMS);
-
-        if (Flags.unknownCallPackageInstallBlockingEnabled()) {
-            // Requesting package installs, limited during phone calls
-            UNTRUSTED_CALL_RESTRICTED_SETTINGS.add(
-                    AppOpsManager.OPSTR_REQUEST_INSTALL_PACKAGES);
-            UNTRUSTED_CALL_RESTRICTED_SETTINGS.add(
-                    AppOpsManager.OPSTR_BIND_ACCESSIBILITY_SERVICE);
-        }
-    }
+    @VisibleForTesting
+    final ArraySet<String> mUntrustedCallRestrictedSettings = new ArraySet<>();
 
     private Map<String, List<byte[]>> mTrustedPackageCertDigests;
     private Map<String, List<byte[]>> mTrustedInstallerCertDigests;
@@ -183,6 +160,7 @@ public class EnhancedConfirmationService extends SystemService {
                 systemConfigManager.getEnhancedConfirmationTrustedPackages());
         mTrustedInstallerCertDigests = toTrustedPackageMap(
                 systemConfigManager.getEnhancedConfirmationTrustedInstallers());
+        initSettings(context);
 
         publishBinderService(Context.ECM_ENHANCED_CONFIRMATION_SERVICE, new Stub());
 
@@ -202,6 +180,64 @@ public class EnhancedConfirmationService extends SystemService {
         return trustedPackageMap;
     }
 
+    private static final String EXEMPT_SETTINGS_RESOURCE_NAME =
+            "config_enhancedConfirmationModeExemptSettings";
+
+    @VisibleForTesting
+    void initSettings(@NonNull Context context) {
+        // Runtime permissions
+        mPerPackageProtectedSettings.add(Manifest.permission.SEND_SMS);
+        mPerPackageProtectedSettings.add(Manifest.permission.RECEIVE_SMS);
+        mPerPackageProtectedSettings.add(Manifest.permission.READ_SMS);
+        mPerPackageProtectedSettings.add(Manifest.permission.RECEIVE_MMS);
+        mPerPackageProtectedSettings.add(Manifest.permission.RECEIVE_WAP_PUSH);
+        mPerPackageProtectedSettings.add(Manifest.permission.READ_CELL_BROADCASTS);
+        mPerPackageProtectedSettings.add(Manifest.permission_group.SMS);
+
+        mPerPackageProtectedSettings.add(Manifest.permission.BIND_DEVICE_ADMIN);
+        // App ops
+        mPerPackageProtectedSettings.add(AppOpsManager.OPSTR_BIND_ACCESSIBILITY_SERVICE);
+        mPerPackageProtectedSettings.add(AppOpsManager.OPSTR_ACCESS_NOTIFICATIONS);
+        mPerPackageProtectedSettings.add(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW);
+        mPerPackageProtectedSettings.add(AppOpsManager.OPSTR_GET_USAGE_STATS);
+        mPerPackageProtectedSettings.add(AppOpsManager.OPSTR_LOADER_USAGE_STATS);
+        // Default application roles.
+        mPerPackageProtectedSettings.add(RoleManager.ROLE_DIALER);
+        mPerPackageProtectedSettings.add(RoleManager.ROLE_SMS);
+
+        if (Flags.unknownCallPackageInstallBlockingEnabled()) {
+            // Requesting package installs, limited during phone calls
+            mUntrustedCallRestrictedSettings.add(
+                    AppOpsManager.OPSTR_REQUEST_INSTALL_PACKAGES);
+            mUntrustedCallRestrictedSettings.add(
+                    AppOpsManager.OPSTR_BIND_ACCESSIBILITY_SERVICE);
+        }
+        loadPackageExemptSettings(context);
+    }
+
+
+    @VisibleForTesting
+    void loadPackageExemptSettings(@NonNull Context context) {
+        int resourceId = context.getResources().getIdentifier(EXEMPT_SETTINGS_RESOURCE_NAME,
+                "array", "android");
+        if (resourceId == 0) {
+            return;
+        }
+        try {
+            List<String> exemptSettings =
+                    Arrays.asList(context.getResources().getStringArray(resourceId));
+            for (String exemptSetting: exemptSettings) {
+                if (EXEMPT_ALL_SETTINGS.equals(exemptSetting)) {
+                    mPerPackageProtectedSettings.clear();
+                    return;
+                }
+                mPerPackageProtectedSettings.remove(exemptSetting);
+            }
+        } catch (Resources.NotFoundException e) {
+            Log.e(LOG_TAG, "Cannot get resource: " + EXEMPT_SETTINGS_RESOURCE_NAME, e);
+        }
+    }
+
     void addOngoingCall(Call call) {
         assertNotMainThread();
         if (mCallTracker != null) {
@@ -301,7 +337,7 @@ public class EnhancedConfirmationService extends SystemService {
                     throw new IllegalStateException("Clear restriction attempted but not allowed");
                 }
                 setAppEcmState(packageName, EcmState.ECM_STATE_NOT_GUARDED, userId);
-                EnhancedConfirmationStatsLogUtils.INSTANCE.logRestrictionCleared(
+                EnhancedConfirmationStatsLogUtils.logRestrictionCleared(
                         getPackageUid(mPackageManager, packageName, userId));
             } catch (NameNotFoundException e) {
                 throw new IllegalArgumentException(e);
@@ -402,7 +438,7 @@ public class EnhancedConfirmationService extends SystemService {
 
         private boolean isSettingEcmGuardedForPackage(@NonNull String settingIdentifier,
                 @NonNull String packageName, @UserIdInt int userId) throws NameNotFoundException {
-            if (!PER_PACKAGE_PROTECTED_SETTINGS.contains(settingIdentifier)) {
+            if (!mPerPackageProtectedSettings.contains(settingIdentifier)) {
                 return false;
             }
             return isPackageEcmGuarded(packageName, userId);
@@ -478,10 +514,10 @@ public class EnhancedConfirmationService extends SystemService {
                 return false;
             }
 
-            if (PER_PACKAGE_PROTECTED_SETTINGS.contains(settingIdentifier)) {
+            if (mPerPackageProtectedSettings.contains(settingIdentifier)) {
                 return true;
             }
-            if (UNTRUSTED_CALL_RESTRICTED_SETTINGS.contains(settingIdentifier)) {
+            if (mUntrustedCallRestrictedSettings.contains(settingIdentifier)) {
                 return true;
             }
             // TODO(b/310218979): Add role selections as protected settings
@@ -492,7 +528,7 @@ public class EnhancedConfirmationService extends SystemService {
         // method will result in a metric being logged, representing a blocked/allowed setting
         private String getGlobalProtectionReason(@NonNull String settingIdentifier,
                 @NonNull String packageName, @UserIdInt int userId) {
-            if (!UNTRUSTED_CALL_RESTRICTED_SETTINGS.contains(settingIdentifier)) {
+            if (!mUntrustedCallRestrictedSettings.contains(settingIdentifier)) {
                 return null;
             }
             if (mCallTracker == null) {
@@ -554,7 +590,7 @@ public class EnhancedConfirmationService extends SystemService {
         }
     }
 
-    private static class CallTracker {
+    private class CallTracker {
         // The time we will remember an untrusted call
         private static final long UNTRUSTED_CALL_STORAGE_TIME_MS = TimeUnit.HOURS.toMillis(1);
         // The minimum time that must pass between individual logs of the same call, uid, trusted
@@ -797,7 +833,7 @@ public class EnhancedConfirmationService extends SystemService {
                 return;
             }
 
-            if (!UNTRUSTED_CALL_RESTRICTED_SETTINGS.contains(settingIdentifier)) {
+            if (!mUntrustedCallRestrictedSettings.contains(settingIdentifier)) {
                 return;
             }
 
diff --git a/service/java/com/android/ecm/EnhancedConfirmationStatsLogUtils.kt b/service/java/com/android/ecm/EnhancedConfirmationStatsLogUtils.java
similarity index 63%
rename from service/java/com/android/ecm/EnhancedConfirmationStatsLogUtils.kt
rename to service/java/com/android/ecm/EnhancedConfirmationStatsLogUtils.java
index 5bf925fc7c..28f109955c 100644
--- a/service/java/com/android/ecm/EnhancedConfirmationStatsLogUtils.kt
+++ b/service/java/com/android/ecm/EnhancedConfirmationStatsLogUtils.java
@@ -14,13 +14,14 @@
  * limitations under the License.
  */
 
-package com.android.ecm
+package com.android.ecm;
 
-import android.permission.flags.Flags
-import android.util.Log
-import com.android.internal.annotations.Keep
-import com.android.modules.utils.build.SdkLevel
-import com.android.permissioncontroller.PermissionControllerStatsLog
+import android.permission.flags.Flags;
+import android.util.Log;
+
+import com.android.internal.annotations.Keep;
+import com.android.modules.utils.build.SdkLevel;
+import com.android.permissioncontroller.PermissionControllerStatsLog;
 
 /**
  * Provides ECM-related metrics logging for Permission APEX services.
@@ -28,18 +29,19 @@ import com.android.permissioncontroller.PermissionControllerStatsLog
  * @hide
  */
 @Keep
-object EnhancedConfirmationStatsLogUtils {
-    private val LOG_TAG = EnhancedConfirmationStatsLogUtils::class.java.simpleName
+public class EnhancedConfirmationStatsLogUtils {
+    private static final String LOG_TAG = EnhancedConfirmationStatsLogUtils.class.getSimpleName();
 
-    fun logRestrictionCleared(uid: Int) {
+    /** @hide */
+    public static void logRestrictionCleared(int uid) {
         if (!SdkLevel.isAtLeastV() || !Flags.enhancedConfirmationModeApisEnabled()) {
-            return
+            return;
         }
-        Log.v(LOG_TAG, "ENHANCED_CONFIRMATION_RESTRICTION_CLEARED: uid='$uid'")
+        Log.v(LOG_TAG, "ENHANCED_CONFIRMATION_RESTRICTION_CLEARED: uid=" + uid);
 
         PermissionControllerStatsLog.write(
-            PermissionControllerStatsLog.ENHANCED_CONFIRMATION_RESTRICTION_CLEARED,
-            uid
-        )
+                PermissionControllerStatsLog.ENHANCED_CONFIRMATION_RESTRICTION_CLEARED,
+                uid
+        );
     }
 }
diff --git a/tests/apex/java/com/android/ecm/EnhancedConfirmationServiceTest.kt b/tests/apex/java/com/android/ecm/EnhancedConfirmationServiceTest.kt
new file mode 100644
index 0000000000..26b1cc4e61
--- /dev/null
+++ b/tests/apex/java/com/android/ecm/EnhancedConfirmationServiceTest.kt
@@ -0,0 +1,150 @@
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
+
+package com.android.ecm
+
+import android.Manifest.permission.RECEIVE_SMS
+import android.Manifest.permission.SEND_SMS
+import android.app.role.RoleManager.ROLE_DIALER
+import android.app.role.RoleManager.ROLE_SMS
+import android.content.Context
+import android.content.res.Resources
+import android.os.Build
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SdkSuppress
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession
+import com.android.server.LocalManagerRegistry
+import com.google.common.truth.Truth.assertThat
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.Mock
+import org.mockito.Mockito
+import org.mockito.Mockito.`when`
+import org.mockito.MockitoAnnotations.initMocks
+import org.mockito.MockitoSession
+import org.mockito.quality.Strictness
+
+@RunWith(AndroidJUnit4::class)
+@SdkSuppress(minSdkVersion = Build.VERSION_CODES.VANILLA_ICE_CREAM, codeName = "VanillaIceCream")
+class EnhancedConfirmationServiceTest {
+    private val context = InstrumentationRegistry.getInstrumentation().context
+    private lateinit var mockitoSession: MockitoSession
+    private lateinit var enhancedConfirmationService: EnhancedConfirmationService
+
+    private lateinit var defaultCallRestrictedSettings: Set<String>
+
+    @Mock private lateinit var mockContext: Context
+
+    @Mock private lateinit var mockResources: Resources
+
+    @Before
+    fun setUp() {
+        initMocks(this)
+        mockitoSession =
+            mockitoSession()
+                .mockStatic(LocalManagerRegistry::class.java)
+                .strictness(Strictness.LENIENT)
+                .startMocking()
+        enhancedConfirmationService = EnhancedConfirmationService(context)
+        overrideStringArrayResource(EXEMPT_SETTINGS_RESOURCE_NAME, null)
+        enhancedConfirmationService.initSettings(mockContext)
+        defaultCallRestrictedSettings =
+            enhancedConfirmationService.mUntrustedCallRestrictedSettings.toSet()
+    }
+
+    @After
+    fun finishMockingApexEnvironment() {
+        mockitoSession.finishMocking()
+        overrideStringArrayResource(EXEMPT_SETTINGS_RESOURCE_NAME, null)
+        enhancedConfirmationService.initSettings(mockContext)
+    }
+
+    @Test
+    fun exemptSettingsAreExempt() {
+        overrideStringArrayResource(EXEMPT_SETTINGS_RESOURCE_NAME, EXEMPT_SETTINGS)
+        enhancedConfirmationService.loadPackageExemptSettings(mockContext)
+
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(SEND_SMS))
+            .isFalse()
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(RECEIVE_SMS))
+            .isFalse()
+    }
+
+    @Test
+    fun nonExemptSettingsAreNotExempt() {
+        overrideStringArrayResource(EXEMPT_SETTINGS_RESOURCE_NAME, EXEMPT_SETTINGS)
+        enhancedConfirmationService.loadPackageExemptSettings(mockContext)
+
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(ROLE_DIALER))
+            .isTrue()
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(ROLE_SMS))
+            .isTrue()
+    }
+
+    @Test
+    fun givenNoExemptSettingsThenNoneExempt() {
+        overrideStringArrayResource(EXEMPT_SETTINGS_RESOURCE_NAME, null)
+        enhancedConfirmationService.loadPackageExemptSettings(mockContext)
+
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(SEND_SMS))
+            .isTrue()
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(RECEIVE_SMS))
+            .isTrue()
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(ROLE_DIALER))
+            .isTrue()
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings.contains(ROLE_SMS))
+            .isTrue()
+    }
+
+    @Test
+    fun wildcardExemptsAllSettings() {
+        overrideStringArrayResource(EXEMPT_SETTINGS_RESOURCE_NAME, EXEMPT_ALL_SETTINGS)
+        enhancedConfirmationService.loadPackageExemptSettings(mockContext)
+        assertThat(enhancedConfirmationService.mPerPackageProtectedSettings).isEmpty()
+    }
+
+    @Test
+    fun exemptionDoesntAffectCallSettings() {
+        overrideStringArrayResource(
+            EXEMPT_SETTINGS_RESOURCE_NAME,
+            defaultCallRestrictedSettings.toTypedArray(),
+        )
+        enhancedConfirmationService.loadPackageExemptSettings(mockContext)
+        assertThat(enhancedConfirmationService.mUntrustedCallRestrictedSettings)
+            .isEqualTo(defaultCallRestrictedSettings)
+    }
+
+    private fun overrideStringArrayResource(name: String, newValue: Array<String>?) {
+        `when`(mockContext.getResources()).thenReturn(mockResources)
+        `when`(mockResources.getIdentifier(Mockito.eq(name), Mockito.any(), Mockito.any()))
+            .thenReturn(if (newValue == null) 0 else EXEMPT_SETTINGS_RESOURCE)
+        `when`(mockResources.getStringArray(Mockito.eq(EXEMPT_SETTINGS_RESOURCE)))
+            .thenReturn(newValue)
+    }
+
+    companion object {
+        private const val EXEMPT_SETTINGS_RESOURCE = 1 // Fake resource id
+        private const val EXEMPT_SETTINGS_RESOURCE_NAME =
+            "config_enhancedConfirmationModeExemptSettings"
+
+        private val EXEMPT_SETTINGS = arrayOf<String>(SEND_SMS, RECEIVE_SMS)
+
+        private val EXEMPT_ALL_SETTINGS = arrayOf<String>("*")
+    }
+}
diff --git a/tests/cts/permission/permissionTestUtilLib/Android.bp b/tests/cts/permission/permissionTestUtilLib/Android.bp
index 2f7004d5f8..5d235b87b6 100644
--- a/tests/cts/permission/permissionTestUtilLib/Android.bp
+++ b/tests/cts/permission/permissionTestUtilLib/Android.bp
@@ -31,6 +31,7 @@ java_library {
         "androidx.test.uiautomator_uiautomator",
         "compatibility-device-util-axt",
         "androidx.test.ext.junit-nodeps",
+        "notification_flags_lib",
     ],
 
     sdk_version: "test_current",
diff --git a/tests/cts/permission/permissionTestUtilLib/src/android/permission/cts/CtsNotificationListenerServiceUtils.kt b/tests/cts/permission/permissionTestUtilLib/src/android/permission/cts/CtsNotificationListenerServiceUtils.kt
index 15d091f72c..15f691c24e 100644
--- a/tests/cts/permission/permissionTestUtilLib/src/android/permission/cts/CtsNotificationListenerServiceUtils.kt
+++ b/tests/cts/permission/permissionTestUtilLib/src/android/permission/cts/CtsNotificationListenerServiceUtils.kt
@@ -16,9 +16,12 @@
 
 package android.permission.cts
 
+import android.content.Context
 import android.permission.cts.TestUtils.ensure
 import android.permission.cts.TestUtils.eventually
 import android.service.notification.StatusBarNotification
+import com.android.compatibility.common.util.UserHelper
+import com.android.server.notification.Flags.managedServicesConcurrentMultiuser
 import org.junit.Assert
 
 object CtsNotificationListenerServiceUtils {
@@ -124,4 +127,18 @@ object CtsNotificationListenerServiceUtils {
         }
         return null
     }
+
+    /**
+     * Returns a boolean value indicating whether the device supports NotificationListener.
+     *
+     * @param context the {@link Context}
+     * @return A boolean value indicating whether the device supports NotificationListener.
+     *         It's true if not a visible background user.
+     *         For a visible background user, It's true when the flag is true.
+     */
+    @JvmStatic
+    fun isNotificationListenerSupported(context: Context): Boolean {
+        return !UserHelper(context).isVisibleBackgroundUser() ||
+                managedServicesConcurrentMultiuser()
+    }
 }
diff --git a/tests/cts/permission/src/android/permission/cts/AccessibilityPrivacySourceTest.kt b/tests/cts/permission/src/android/permission/cts/AccessibilityPrivacySourceTest.kt
index 41c0afa075..6283004da7 100644
--- a/tests/cts/permission/src/android/permission/cts/AccessibilityPrivacySourceTest.kt
+++ b/tests/cts/permission/src/android/permission/cts/AccessibilityPrivacySourceTest.kt
@@ -29,6 +29,7 @@ import android.permission.cts.CtsNotificationListenerServiceUtils.assertNotifica
 import android.permission.cts.CtsNotificationListenerServiceUtils.cancelNotification
 import android.permission.cts.CtsNotificationListenerServiceUtils.cancelNotifications
 import android.permission.cts.CtsNotificationListenerServiceUtils.getNotification
+import android.permission.cts.CtsNotificationListenerServiceUtils.isNotificationListenerSupported
 import android.permission.cts.SafetyCenterUtils.assertSafetyCenterIssueDoesNotExist
 import android.permission.cts.SafetyCenterUtils.assertSafetyCenterIssueExist
 import android.permission.cts.SafetyCenterUtils.assertSafetyCenterStarted
@@ -50,8 +51,8 @@ import com.android.compatibility.common.util.SystemUtil.runWithShellPermissionId
 import com.android.modules.utils.build.SdkLevel
 import org.junit.After
 import org.junit.Assert
-import org.junit.Assume
 import org.junit.Assume.assumeFalse
+import org.junit.Assume.assumeTrue
 import org.junit.Before
 import org.junit.ClassRule
 import org.junit.Rule
@@ -76,6 +77,7 @@ class AccessibilityPrivacySourceTest {
         ComponentName(context, AccessibilityTestService::class.java).flattenToString()
     private val safetyCenterIssueId = "accessibility_$accessibilityTestService"
     private val safetyCenterManager = context.getSystemService(SafetyCenterManager::class.java)
+    private val isNotificationListenerSupported = isNotificationListenerSupported(context)
 
     @get:Rule val screenRecordRule = ScreenRecordRule(false, false)
 
@@ -103,7 +105,9 @@ class AccessibilityPrivacySourceTest {
 
     @Before
     fun setup() {
-        Assume.assumeTrue(deviceSupportsSafetyCenter(context))
+        assumeTrue(deviceSupportsSafetyCenter(context))
+        // Skip tests if NotificationListener not available
+        assumeTrue("Test requires using NotificationListener", isNotificationListenerSupported)
         InstrumentedAccessibilityService.disableAllServices()
         runShellCommand("input keyevent KEYCODE_WAKEUP")
         resetPermissionController()
@@ -119,7 +123,9 @@ class AccessibilityPrivacySourceTest {
 
     @After
     fun cleanup() {
-        cancelNotifications(permissionControllerPackage)
+        if (isNotificationListenerSupported) {
+            cancelNotifications(permissionControllerPackage)
+        }
         runWithShellPermissionIdentity { safetyCenterManager?.clearAllSafetySourceDataForTests() }
     }
 
diff --git a/tests/cts/permission/src/android/permission/cts/LocationAccessCheckTest.java b/tests/cts/permission/src/android/permission/cts/LocationAccessCheckTest.java
index 024a89f2ee..b5bad4121a 100644
--- a/tests/cts/permission/src/android/permission/cts/LocationAccessCheckTest.java
+++ b/tests/cts/permission/src/android/permission/cts/LocationAccessCheckTest.java
@@ -24,6 +24,8 @@ import static android.content.Context.BIND_AUTO_CREATE;
 import static android.content.Context.BIND_NOT_FOREGROUND;
 import static android.location.Criteria.ACCURACY_FINE;
 import static android.os.Process.myUserHandle;
+import static android.permission.cts.CtsNotificationListenerServiceUtils
+        .isNotificationListenerSupported;
 import static android.provider.Settings.Secure.LOCATION_ACCESS_CHECK_DELAY_MILLIS;
 import static android.provider.Settings.Secure.LOCATION_ACCESS_CHECK_INTERVAL_MILLIS;
 
@@ -77,7 +79,6 @@ import androidx.test.filters.SdkSuppress;
 import androidx.test.runner.AndroidJUnit4;
 
 import com.android.compatibility.common.util.DeviceConfigStateChangerRule;
-import com.android.compatibility.common.util.UserHelper;
 import com.android.compatibility.common.util.mainline.MainlineModule;
 import com.android.compatibility.common.util.mainline.ModuleDetector;
 import com.android.modules.utils.build.SdkLevel;
@@ -200,7 +201,7 @@ public class LocationAccessCheckTest {
 
     private static boolean sWasLocationEnabled = true;
 
-    private UserHelper mUserHelper = new UserHelper(sContext);
+    private boolean mNotificationListenerSupported = isNotificationListenerSupported(sContext);
 
     @BeforeClass
     public static void beforeClassSetup() throws Exception {
@@ -468,13 +469,8 @@ public class LocationAccessCheckTest {
     @Before
     public void beforeEachTestSetup() throws Throwable {
         assumeIsNotLowRamDevice();
-
-        // TODO(b/380297485): Remove this assumption once NotificationListeners are supported on
-        // visible background users.
-        // Skipping each test for visible background users as all test cases depend on
-        // NotificationListeners.
-        assumeFalse("NotificationListeners are not yet supported on visible background users",
-                mUserHelper.isVisibleBackgroundUser());
+        // Skip tests if NotificationListener not available
+        assumeTrue("Test requires using NotificationListener", mNotificationListenerSupported);
 
         wakeUpAndDismissKeyguard();
         bindService();
diff --git a/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckTest.java b/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckTest.java
index 19fc20de6b..7d061f2420 100644
--- a/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckTest.java
+++ b/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckTest.java
@@ -16,6 +16,8 @@
 
 package android.permission.cts;
 
+import static android.permission.cts.CtsNotificationListenerServiceUtils
+        .isNotificationListenerSupported;
 import static android.permission.cts.PermissionUtils.clearAppState;
 import static android.permission.cts.PermissionUtils.install;
 import static android.permission.cts.PermissionUtils.uninstallApp;
@@ -24,6 +26,7 @@ import static android.permission.cts.TestUtils.eventually;
 
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assume.assumeTrue;
 
 import android.app.ActivityOptions;
 import android.app.PendingIntent;
@@ -34,6 +37,7 @@ import android.service.notification.StatusBarNotification;
 
 import androidx.test.filters.FlakyTest;
 import androidx.test.filters.SdkSuppress;
+import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.runner.AndroidJUnit4;
 
 import com.android.modules.utils.build.SdkLevel;
@@ -53,13 +57,17 @@ import org.junit.runner.RunWith;
 @ScreenRecordRule.ScreenRecord
 @FlakyTest
 public class NotificationListenerCheckTest extends BaseNotificationListenerCheckTest {
-
     public final ScreenRecordRule mScreenRecordRule = new ScreenRecordRule(false, false);
 
+    private boolean mNotificationListenerSupported = isNotificationListenerSupported(
+            InstrumentationRegistry.getInstrumentation().getTargetContext());
+
     @Before
     public void setup() throws Throwable {
         // Skip tests if safety center not allowed
         assumeDeviceSupportsSafetyCenter();
+        // Skip tests if NotificationListener not available
+        assumeTrue("Test requires using NotificationListener" , mNotificationListenerSupported);
 
         wakeUpAndDismissKeyguard();
         resetPermissionControllerBeforeEachTest();
@@ -80,8 +88,9 @@ public class NotificationListenerCheckTest extends BaseNotificationListenerCheck
         // Disallow and uninstall the app with NLS for testing
         disallowTestAppNotificationListenerService();
         uninstallApp(TEST_APP_PKG);
-
-        clearNotifications();
+        if (mNotificationListenerSupported) {
+            clearNotifications();
+        }
     }
 
     @Test
diff --git a/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckWithSafetyCenterUnsupportedTest.java b/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckWithSafetyCenterUnsupportedTest.java
index a346de6fdd..aec9e094bf 100644
--- a/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckWithSafetyCenterUnsupportedTest.java
+++ b/tests/cts/permission/src/android/permission/cts/NotificationListenerCheckWithSafetyCenterUnsupportedTest.java
@@ -16,16 +16,20 @@
 
 package android.permission.cts;
 
+import static android.permission.cts.CtsNotificationListenerServiceUtils
+        .isNotificationListenerSupported;
 import static android.permission.cts.PermissionUtils.install;
 import static android.permission.cts.PermissionUtils.uninstallApp;
 import static android.permission.cts.TestUtils.ensure;
 
 import static org.junit.Assert.assertNull;
+import static org.junit.Assume.assumeTrue;
 
 import android.os.Build;
 import android.platform.test.annotations.AppModeFull;
 
 import androidx.test.filters.SdkSuppress;
+import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.runner.AndroidJUnit4;
 
 import org.junit.After;
@@ -43,10 +47,15 @@ import org.junit.runner.RunWith;
 public class NotificationListenerCheckWithSafetyCenterUnsupportedTest
         extends BaseNotificationListenerCheckTest  {
 
+    private boolean mNotificationListenerSupported = isNotificationListenerSupported(
+            InstrumentationRegistry.getInstrumentation().getTargetContext());
+
     @Before
     public void setup() throws Throwable {
         // Skip tests if safety center is supported
         assumeDeviceDoesNotSupportSafetyCenter();
+        // Skip tests if NotificationListener not available
+        assumeTrue("Test requires using NotificationListener" , mNotificationListenerSupported);
 
         wakeUpAndDismissKeyguard();
         resetPermissionControllerBeforeEachTest();
@@ -64,7 +73,9 @@ public class NotificationListenerCheckWithSafetyCenterUnsupportedTest
         disallowTestAppNotificationListenerService();
         uninstallApp(TEST_APP_PKG);
 
-        clearNotifications();
+        if (mNotificationListenerSupported) {
+            clearNotifications();
+        }
     }
 
     @Test
diff --git a/tests/cts/permission/src/android/permission/cts/PermissionUpdateListenerTest.java b/tests/cts/permission/src/android/permission/cts/PermissionUpdateListenerTest.java
index 86b8fa8951..fe3360b417 100644
--- a/tests/cts/permission/src/android/permission/cts/PermissionUpdateListenerTest.java
+++ b/tests/cts/permission/src/android/permission/cts/PermissionUpdateListenerTest.java
@@ -32,6 +32,7 @@ import android.platform.test.annotations.AppModeFull;
 import android.platform.test.annotations.RequiresFlagsEnabled;
 import android.virtualdevice.cts.common.VirtualDeviceRule;
 
+import androidx.annotation.NonNull;
 import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner;
 import androidx.test.platform.app.InstrumentationRegistry;
 
@@ -44,6 +45,7 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 
 import java.util.Map;
+import java.util.Objects;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
@@ -219,9 +221,11 @@ public class PermissionUpdateListenerTest {
         }
 
         @Override
-        public void onPermissionsChanged(int uid, String deviceId) {
+        public void onPermissionsChanged(int uid, @NonNull String deviceId) {
             if (uid == mTestAppUid) {
                 mCountDownLatch.countDown();
+
+                Objects.requireNonNull(deviceId, "deviceId cannot be null");
                 mUidDeviceIdsMap.put(uid, deviceId);
             }
         }
diff --git a/tests/cts/permission/src/android/permission/cts/SmsManagerPermissionTest.java b/tests/cts/permission/src/android/permission/cts/SmsManagerPermissionTest.java
index dd0d9f2349..c7111e26f0 100644
--- a/tests/cts/permission/src/android/permission/cts/SmsManagerPermissionTest.java
+++ b/tests/cts/permission/src/android/permission/cts/SmsManagerPermissionTest.java
@@ -57,8 +57,8 @@ public class SmsManagerPermissionTest {
         mTelephonyManager = mContext.getSystemService(TelephonyManager.class);
         int subId = SubscriptionManager.getDefaultSmsSubscriptionId();
         mHasTelephony = mContext.getPackageManager().hasSystemFeature(
-                PackageManager.FEATURE_TELEPHONY);
-        assumeTrue(mHasTelephony); // Don't run these tests if FEATURE_TELEPHONY is not available.
+                PackageManager.FEATURE_TELEPHONY_MESSAGING);
+        assumeTrue(mHasTelephony); // Don't run these tests if messaging is not available.
 
         Log.d("SmsManagerPermissionTest", "mSubId=" + subId);
 
diff --git a/tests/cts/permissionpolicy/Android.bp b/tests/cts/permissionpolicy/Android.bp
index 07fde8bff5..1019c961b9 100644
--- a/tests/cts/permissionpolicy/Android.bp
+++ b/tests/cts/permissionpolicy/Android.bp
@@ -39,6 +39,8 @@ android_test {
         "flag-junit",
         "android.app.flags-aconfig",
         "android.permission.flags-aconfig-java-export",
+        "update_engine_exported_flags_java_lib",
+        "appsearch_flags_java_exported_lib",
     ],
     srcs: [
         "src/**/*.java",
diff --git a/tests/cts/permissionpolicy/res/raw/android_manifest.xml b/tests/cts/permissionpolicy/res/raw/android_manifest.xml
index 200e3cf424..e55cebb708 100644
--- a/tests/cts/permissionpolicy/res/raw/android_manifest.xml
+++ b/tests/cts/permissionpolicy/res/raw/android_manifest.xml
@@ -914,6 +914,12 @@
                 android:protectionLevel="signature|privileged"
                 android:featureFlag="android.provider.user_keys" />
 
+    <!-- This permission protects a content provider within home/launcher applications, enabling management of home screen metadata such as shortcut placement, launch intents, and labels. -->
+    <!-- @FlaggedApi(android.provider.Flags.FLAG_LAUNCHER_DATA_ACCESS) -->
+    <permission android:name="android.permission.LAUNCHER_DATA_ACCESS"
+      android:protectionLevel="signatureOrSystem"
+      android:featureFlag="android.provider.launcher_data_access" />
+
     <!-- Allows an application to set default account for new contacts.
         <p>This permission is only granted to system applications fulfilling the Contacts app role.
         <p>Protection level: internal|role
@@ -1879,6 +1885,15 @@
         android:protectionLevel="dangerous"
         android:permissionFlags="hardRestricted" />
 
+   <!-- Allows an app to access moisture intrusion sensor data
+        <p>Protection level: normal
+         @hide
+    -->
+    <permission android:name="android.permission.READ_MOISTURE_INTRUSION"
+                android:permissionGroup="android.permission-group.SENSORS"
+                android:protectionLevel="normal"
+                android:featureFlag="com.android.tradeinmode.flags.trade_in_mode_2025q4"/>
+
     <!-- Allows an app to use fingerprint hardware.
          <p>Protection level: normal
          @deprecated Applications should request {@link
@@ -4343,6 +4358,13 @@
     <permission android:name="android.permission.EMBED_ANY_APP_IN_UNTRUSTED_MODE"
                 android:protectionLevel="internal|role" />
 
+    <!-- Allows an application to make requests to WM Shell for actions or
+         configurations related to select multitasking features like Bubbles.
+         @hide -->
+    <permission android:name="android.permission.REQUEST_SYSTEM_MULTITASKING_CONTROLS"
+                android:protectionLevel="signature|privileged"
+                android:featureFlag="com.android.window.flags.enable_experimental_bubbles_controller" />
+
     <!-- Allows an application to start any activity, regardless of permission
          protection or exported state.
          @hide -->
@@ -4463,7 +4485,22 @@
 
          <p>Not for use by third-party applications. -->
     <permission android:name="android.permission.SYSTEM_APPLICATION_OVERLAY"
-                android:protectionLevel="signature|recents|role|installer"/>
+        android:protectionLevel="signature|recents|role|installer|appop"
+        android:featureFlag="com.android.media.projection.flags.recording_overlay" />
+
+    <!-- @SystemApi @hide Allows an application to create windows using the type
+         {@link android.view.WindowManager.LayoutParams#TYPE_APPLICATION_OVERLAY},
+         shown on top of all other apps.
+
+         Allows an application to use
+         {@link android.view.WindowManager.LayoutsParams#setSystemApplicationOverlay(boolean)}
+         to create overlays that will stay visible, even if another window is requesting overlays to
+         be hidden through {@link android.view.Window#setHideOverlayWindows(boolean)}.
+
+         <p>Not for use by third-party applications. -->
+    <permission android:name="android.permission.SYSTEM_APPLICATION_OVERLAY"
+        android:protectionLevel="signature|recents|role|installer"
+        android:featureFlag="!com.android.media.projection.flags.recording_overlay" />
 
     <!-- @deprecated Use {@link android.Manifest.permission#REQUEST_COMPANION_RUN_IN_BACKGROUND}
          @hide
@@ -5180,6 +5217,14 @@
     <permission android:name="android.permission.READ_LOGS"
         android:protectionLevel="signature|privileged|development" />
 
+    <!-- @FlaggedApi("com.android.update_engine.minor_changes_2025q4")
+    Allows an application to read the low-level update engine log files.
+    <p>Not for use by third-party applications, because
+    Log entries can contain the user's private information. -->
+    <permission android:name="android.permission.READ_UPDATE_ENGINE_LOGS"
+        android:protectionLevel="signature|privileged|development"
+        android:featureFlag="com.android.update_engine.minor_changes_2025q4" />
+
     <!-- Configure an application for debugging.
     <p>Not for use by third-party applications. -->
     <permission android:name="android.permission.SET_DEBUG_APP"
@@ -6513,6 +6558,16 @@
     <permission android:name="android.permission.REQUEST_OBSERVE_DEVICE_UUID_PRESENCE"
                 android:protectionLevel="signature|privileged" />
 
+    <!-- Allow applications to access other companion apps' association and device presence info.
+         <p>Not for use by third-party applications.
+         @FlaggedApi(android.companion.Flags.FLAG_ASSOCIATION_VERIFICATION)
+         @SystemApi
+         @hide
+    -->
+    <permission android:name="android.permission.ACCESS_COMPANION_INFO"
+        android:featureFlag="android.companion.association_verification"
+        android:protectionLevel="signature|privileged" />
+
     <!-- Allows an application to deliver companion messages to system
          -->
     <permission android:name="android.permission.DELIVER_COMPANION_MESSAGES"
@@ -7387,6 +7442,14 @@
     <permission android:name="android.permission.ACCESS_KEYGUARD_SECURE_STORAGE"
         android:protectionLevel="signature|setup" />
 
+    <!-- @hide @SystemApi Allows an application running a foreground service to hide the
+   notification icon from the status bar.
+   <p>Not for use by third-party applications.
+   @FlaggedApi(android.app.Flags.FLAG_HIDE_STATUS_BAR_NOTIFICATION)-->
+    <permission android:name="android.permission.HIDE_STATUS_BAR_NOTIFICATION"
+        android:protectionLevel="signature|privileged"
+        android:featureFlag="android.app.hide_status_bar_notification"/>
+
     <!-- Allows applications to set the initial lockscreen state.
          <p>Not for use by third-party applications. @hide -->
     <permission android:name="android.permission.SET_INITIAL_LOCK"
@@ -8163,6 +8226,18 @@
                 android:description="@string/permdesc_fullScreenIntent"
                 android:protectionLevel="normal|appop" />
 
+    <!-- Required for apps to post promoted notifications.
+         <p>This is required in addition to (not instead of)
+         {@link android.app.Manifest.permission#POST_NOTIFICATIONS}.
+         <p>Protection level: normal|appops
+         @FlaggedApi(android.app.Flags.FLAG_API_RICH_ONGOING_PERMISSION)
+         -->
+    <permission android:name="android.permission.POST_PROMOTED_NOTIFICATIONS"
+        android:label="@string/permlab_postPromotedNotifications"
+        android:description="@string/permdesc_postPromotedNotifications"
+        android:protectionLevel="normal|appop"
+        android:featureFlag="android.app.ui_rich_ongoing"/>
+
     <!-- @SystemApi Required for the privileged assistant apps targeting
          {@link android.os.Build.VERSION_CODES#VANILLA_ICE_CREAM}
          that receive voice trigger from a sandboxed {@link HotwordDetectionService}.
@@ -8477,6 +8552,15 @@
     <permission android:name="android.permission.READ_HOME_APP_SEARCH_DATA"
         android:protectionLevel="internal|role" />
 
+    <!-- Must be required by an {@link com.android.server.appsearch.isolated_storage_service.IsolatedStorageService}
+         to ensure that only the system can bind to it.
+         <p>Protection level: signature
+         @hide
+    -->
+    <permission android:name="android.permission.BIND_APP_SEARCH_ISOLATED_STORAGE_SERVICE"
+        android:protectionLevel="signature"
+        android:featureFlag= "com.android.appsearch.flags.enable_isolated_storage" />
+
     <!-- Allows an assistive application to perform actions on behalf of users inside of
          applications.
          <p>For now, this permission is only granted to the Assistant application selected by
@@ -8497,12 +8581,22 @@
     <!-- Allows an application to perform actions on behalf of users inside of
          applications.
          <p>This permission is currently only granted to privileged system apps.
-         <p>Protection level: internal|privileged
-         @FlaggedApi(android.app.appfunctions.flags.Flags.FLAG_ENABLE_APP_FUNCTION_MANAGER)  -->
+         <p>Protection level: internal|privileged -->
     <permission android:name="android.permission.EXECUTE_APP_FUNCTIONS"
-        android:featureFlag="android.app.appfunctions.flags.enable_app_function_manager"
+        android:featureFlag="!android.permission.flags.app_function_access_api_enabled"
         android:protectionLevel="internal|privileged" />
 
+    <!-- Allows an application to perform actions on behalf of users inside of
+     applications.
+     <p>To execute a function in another app, an application must first hold the
+        android.permission.EXECUTE_APP_FUNCTIONS permission. In addition, the application must be
+        on a device allowlist, and its ability to execute functions is subject to user approval or
+        disapproval.
+     <p>Protection level: normal -->
+    <permission android:name="android.permission.EXECUTE_APP_FUNCTIONS"
+        android:featureFlag="android.permission.flags.app_function_access_api_enabled"
+        android:protectionLevel="normal" />
+
     <!-- Allows an application to display its suggestions using the autofill framework.
          <p>For now, this permission is only granted to the Browser application.
          <p>Protection level: internal|role
@@ -8515,6 +8609,13 @@
     <permission android:name="android.permission.CREATE_VIRTUAL_DEVICE"
                 android:protectionLevel="internal|role" />
 
+    <!-- Allows an application access to computer control features.
+     @hide -->
+    <permission android:name="android.permission.ACCESS_COMPUTER_CONTROL"
+        android:protectionLevel="internal|knownSigner"
+        android:knownCerts="@array/config_accessComputerControlKnownSigners"
+        android:featureFlag="android.companion.virtualdevice.flags.computer_control_access"/>
+
     <!-- @SystemApi Must be required by a safety source to send an update using the
              {@link android.safetycenter.SafetyCenterManager}.
              <p>Protection level: internal|privileged
@@ -8630,7 +8731,15 @@
          @hide -->
     <permission android:name="android.permission.MANAGE_KEY_GESTURES"
                 android:protectionLevel="signature"
-                android:featureFlag="com.android.hardware.input.manage_key_gestures" />
+                android:featureFlag="!com.android.window.flags.grant_manage_key_gestures_to_recents" />
+
+    <!-- Allows low-level access to manage key gestures.
+         <p>Not for use by third-party applications.
+         @hide -->
+    <permission android:name="android.permission.MANAGE_KEY_GESTURES"
+                android:protectionLevel="signature|recents"
+                android:featureFlag="com.android.window.flags.grant_manage_key_gestures_to_recents" />
+
 
     <!-- Allows applications to register listeners for key activeness through
          InputManagerService.
@@ -8649,6 +8758,17 @@
     <permission android:name="android.permission.MANAGE_DEVICE_LOCK_STATE"
                 android:protectionLevel="internal|role" />
 
+    <!-- Allows an app to get the device lock enrollment type.
+        <p>This permission is only granted to system applications.
+        <p>Protection level: signature|privileged
+        @SystemApi
+        @FlaggedApi(com.android.devicelock.flags.Flags.FLAG_GET_ENROLLMENT_TYPE)
+        @hide
+    -->
+    <permission android:name="android.permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE"
+        android:protectionLevel="signature|privileged"
+        android:featureFlag="com.android.devicelock.flags.get_enrollment_type" />
+
     <!-- @SystemApi Required by a WearableSensingService to
           ensure that only the caller with this permission can bind to it.
           <p> Protection level: signature
@@ -9004,6 +9124,38 @@
         android:protectionLevel="signature|role|privileged"
         android:featureFlag="android.permission.flags.text_classifier_choice_api_enabled"/>
 
+    <!--
+        @SystemApi
+        @FlaggedApi(android.permission.flags.Flags.FLAG_SUPERVISION_ROLE_ENABLED)
+        Must be required by a {@link android.app.supervision.SupervisionAppService},
+        to ensure that only the system can bind to it.
+        <p>Protection level: signature
+        @hide
+    -->
+    <permission android:name="android.permission.BIND_SUPERVISION_APP_SERVICE"
+        android:protectionLevel="signature"
+        android:featureFlag="android.permission.flags.supervision_role_enabled" />
+
+    <!-- @SystemApi
+        @FlaggedApi(android.permission.flags.Flags.FLAG_APP_FUNCTION_ACCESS_API_ENABLED)
+        This permission is required to set the access state flags on an agent, to access
+        AppFunctions of other apps.
+        <p> Protection level: signature|installer
+        @hide
+    -->
+    <permission android:name="android.permission.MANAGE_APP_FUNCTION_ACCESS"
+        android:protectionLevel="signature|installer"
+        android:featureFlag="android.permission.flags.app_function_access_api_enabled"/>
+
+    <!-- Allows an application to programmatically move and resize its tasks when the system is in
+        a state that allows such operations, e.g. in a desktop-like environment. It is only
+        extended to the {@link android.app.role.RoleManager#ROLE_BROWSER default browser}.
+        <p>Protection level: internal|role
+        @FlaggedApi(com.android.window.flags.Flags.FLAG_ENABLE_WINDOW_REPOSITIONING_API) -->
+    <permission android:name="android.permission.REPOSITION_SELF_WINDOWS"
+        android:protectionLevel="internal|role"
+        android:featureFlag="com.android.window.flags.enable_window_repositioning_api" />
+
     <!-- Attribution for Geofencing service. -->
     <attribution android:tag="GeofencingService" android:label="@string/geofencing_service"/>
     <!-- Attribution for Country Detector. -->
diff --git a/tests/cts/permissionpolicy/res/raw/automotive_android_manifest.xml b/tests/cts/permissionpolicy/res/raw/automotive_android_manifest.xml
index 2b40d3ed74..dc0c0f0e07 100644
--- a/tests/cts/permissionpolicy/res/raw/automotive_android_manifest.xml
+++ b/tests/cts/permissionpolicy/res/raw/automotive_android_manifest.xml
@@ -703,4 +703,10 @@
         android:label="@string/car_permission_label_inject_vehicle_properties"
         android:description="@string/car_permission_desc_inject_vehicle_properties"
         android:featureFlag="android.car.feature.car_property_simulation" />
+    <permission
+        android:name="android.car.permission.READ_PROPERTY_VENDOR_STATUS"
+        android:protectionLevel="signature|privileged"
+        android:label="@string/car_permission_label_read_property_vendor_status"
+        android:description="@string/car_permission_desc_read_property_vendor_status"
+        android:featureFlag="android.car.feature.car_property_status_detailed_not_available" />
 </manifest>
diff --git a/tests/cts/permissionui/src/android/permissionui/cts/BaseUsePermissionTest.kt b/tests/cts/permissionui/src/android/permissionui/cts/BaseUsePermissionTest.kt
index 2cb93e903d..182a5f946c 100644
--- a/tests/cts/permissionui/src/android/permissionui/cts/BaseUsePermissionTest.kt
+++ b/tests/cts/permissionui/src/android/permissionui/cts/BaseUsePermissionTest.kt
@@ -155,7 +155,7 @@ abstract class BaseUsePermissionTest : BasePermissionTest() {
             "app_location_permission_rationale_subtitle"
         const val HEALTH_PERMISSION_SELECT_HEART_RATE_PLAIN_TEXT = "Heart rate"
         const val HEALTH_PERMISSION_ALLOW_ALL_PLAIN_TEXT = "Allow all"
-        const val HEALTH_PERMISSION_ALLOW_ALWAYS_PLAIN_TEXT = "Allow all the time"
+        const val HEALTH_PERMISSION_ALLOW_ALWAYS_PLAIN_TEXT = "All the time"
         const val GRANT_DIALOG_PERMISSION_RATIONALE_CONTAINER_VIEW =
             "com.android.permissioncontroller:id/permission_rationale_container"
         const val PERMISSION_RATIONALE_ACTIVITY_TITLE_VIEW =
@@ -1194,6 +1194,7 @@ abstract class BaseUsePermissionTest : BasePermissionTest() {
             }
         }
     }
+
     protected fun navigateToIndividualPermissionSetting(
         permission: String,
         manuallyNavigate: Boolean = false,
@@ -1213,7 +1214,7 @@ abstract class BaseUsePermissionTest : BasePermissionTest() {
             if (isWatch) {
                 clickAndWaitForWindowTransition(
                     By.text(permissionLabel).displayId(displayId),
-                    40_000,
+                    120_000,
                 )
             } else {
                 clickPermissionControllerUi(By.text(permissionLabel).displayId(displayId))
@@ -1284,7 +1285,7 @@ abstract class BaseUsePermissionTest : BasePermissionTest() {
             navigatedGroupLabels.add(permissionLabel)
             if (useLegacyNavigation) {
                 if (isWatch) {
-                    click(By.text(permissionLabel).displayId(displayId), 40_000)
+                    click(By.text(permissionLabel).displayId(displayId), 120_000)
                 } else if (isAutomotive) {
                     clickPermissionControllerUi(permissionLabel)
                 } else {
```

