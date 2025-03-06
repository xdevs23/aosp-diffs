```diff
diff --git a/Android.bp b/Android.bp
index c4b9ad3f1..cd0b9c99c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,6 +27,28 @@ license {
     license_text: [],
 }
 
+aconfig_declarations {
+    name: "docsui-flags-aconfig",
+    package: "com.android.documentsui.flags",
+    container: "system",
+    srcs: ["flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "docsui-flags-aconfig-java-lib",
+    aconfig_declarations: "docsui-flags-aconfig",
+    min_sdk_version: "29",
+    sdk_version: "system_current",
+}
+
+java_library {
+    name: "docsui-change-ids",
+    srcs: ["src/com/android/documentsui/ChangeIds.java"],
+    libs: ["app-compat-annotations"],
+    min_sdk_version: "29",
+    sdk_version: "system_current",
+}
+
 java_defaults {
     name: "documentsui_defaults",
 
@@ -40,14 +62,11 @@ java_defaults {
         "androidx.transition_transition",
         "apache-commons-compress",
         "com.google.android.material_material",
+        "docsui-change-ids",
         "guava",
         "modules-utils-build_system",
     ],
 
-    libs: [
-        "app-compat-annotations",
-    ],
-
     privileged: true,
 
     certificate: "platform",
@@ -63,7 +82,7 @@ java_defaults {
 
 platform_compat_config {
     name: "documents-ui-compat-config",
-    src: ":DocumentsUI",
+    src: ":docsui-change-ids",
 }
 
 java_library {
@@ -90,6 +109,8 @@ genrule {
 android_library {
     name: "DocumentsUI-lib",
     defaults: ["documentsui_defaults"],
+    static_libs: ["docsui-flags-aconfig-java-lib"],
+    flags_packages: ["docsui-flags-aconfig"],
 
     manifest: "AndroidManifestLib.xml",
 
@@ -101,8 +122,12 @@ android_library {
         "--auto-add-overlay",
     ],
 
+    // This is included in `documentsui_defaults`.
+    exclude_srcs: ["src/com/android/documentsui/ChangeIds.java"],
+
     srcs: [
         "src/**/*.java",
+        "src/**/*.kt",
         ":statslog-docsui-java-gen",
     ],
 
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index be98d1d08..d948b605c 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -210,15 +210,5 @@
             android:process=":com.android.documentsui.services">
         </service>
 
-        <activity
-            android:name=".selection.demo.SelectionDemoActivity"
-            android:label="Selection Demo"
-            android:exported="true"
-            android:theme="@style/DocumentsTheme">
-            <intent-filter>
-                <action android:name="android.intent.action.MAIN" />
-            </intent-filter>
-        </activity>
-
     </application>
 </manifest>
diff --git a/OWNERS b/OWNERS
index c293a16ca..5b8cd52bf 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,5 @@
 # Bug component: 46626
 
-include platform/frameworks/base:/core/java/android/os/storage/OWNERS
\ No newline at end of file
+include platform/frameworks/base:/core/java/android/os/storage/OWNERS
+
+benreich@google.com
diff --git a/compose/Android.bp b/compose/Android.bp
new file mode 100644
index 000000000..f00bf4c20
--- /dev/null
+++ b/compose/Android.bp
@@ -0,0 +1,62 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "DocumentsUIComposelib",
+    manifest: "AndroidManifest.xml",
+
+    resource_dirs: [
+        "res",
+    ],
+    srcs: [
+        "src/**/*.kt",
+    ],
+
+    static_libs: [
+        "androidx.activity_activity-compose",
+        "androidx.appcompat_appcompat",
+        "androidx.compose.foundation_foundation",
+        "androidx.compose.material3_material3",
+        "androidx.compose.material3_material3-window-size-class",
+        "androidx.compose.material_material-icons-extended",
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.ui_ui",
+        "androidx.core_core-ktx",
+        "androidx.hilt_hilt-navigation-compose",
+        "androidx.lifecycle_lifecycle-runtime-compose",
+        "androidx.lifecycle_lifecycle-runtime-ktx",
+        "hilt_android",
+        "modules-utils-build_system",
+    ],
+
+    sdk_version: "system_current",
+    target_sdk_version: "33",
+    min_sdk_version: "29",
+}
+
+android_app {
+    name: "DocumentsUICompose",
+    manifest: "AndroidManifest.xml",
+    static_libs: ["DocumentsUIComposelib"],
+
+    privileged: true,
+    certificate: "platform",
+
+    sdk_version: "system_current",
+    min_sdk_version: "29",
+}
diff --git a/compose/AndroidManifest.xml b/compose/AndroidManifest.xml
new file mode 100644
index 000000000..dbed77310
--- /dev/null
+++ b/compose/AndroidManifest.xml
@@ -0,0 +1,60 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+-->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+        package="com.android.documentsui.compose">
+
+    <uses-sdk android:minSdkVersion="29"/>
+
+    <!-- Permissions copied from com.android.documentsui AndroidManifest.xml -->
+    <uses-permission android:name="android.permission.MANAGE_DOCUMENTS" />
+    <uses-permission android:name="android.permission.REMOVE_TASKS" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC"/>
+    <uses-permission android:name="android.permission.WAKE_LOCK" />
+    <uses-permission android:name="android.permission.CACHE_CONTENT" />
+    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
+    <uses-permission android:name="android.permission.CHANGE_OVERLAY_PACKAGES" />
+    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS" />
+    <uses-permission android:name="android.permission.MODIFY_QUIET_MODE" />
+    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
+    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
+    <uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>
+    <uses-permission android:name="android.permission.LOG_COMPAT_CHANGE"/>
+    <uses-permission android:name="android.permission.READ_COMPAT_CHANGE_CONFIG"/>
+    <uses-permission android:name="android.permission.START_FOREGROUND_SERVICES_FROM_BACKGROUND"/>
+    <uses-permission android:name="android.permission.READ_DEVICE_CONFIG"/>
+
+    <application
+        android:name=".DocumentsUIApplication"
+        android:label="@string/app_label"
+        android:supportsRtl="true"
+        android:allowBackup="true"
+        android:theme="@style/Theme.DocumentsUINoTitleBar">
+
+        <activity
+            android:name=".MainActivity"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN" />
+                <category android:name="android.intent.category.LAUNCHER" />
+            </intent-filter>
+        </activity>
+
+    </application>
+</manifest>
diff --git a/compose/OWNERS b/compose/OWNERS
new file mode 100644
index 000000000..ee4568b02
--- /dev/null
+++ b/compose/OWNERS
@@ -0,0 +1,6 @@
+# Bug component: 374224390
+
+wenbojie@google.com
+benreich@google.com
+lucmult@google.com
+tylersaunders@google.com
diff --git a/compose/README b/compose/README
new file mode 100644
index 000000000..5ccfbeda3
--- /dev/null
+++ b/compose/README
@@ -0,0 +1,12 @@
+This folder is intended for Sydney Files team to experiment constructing Jetpack Compose components
+for DocumentsUI.
+
+## Build and Install
+
+Use `brya` target as an example.
+
+```bash
+lunch brya-trunk_staging-eng
+m DocumentsUICompose
+adb install out/target/product/brya/system/priv-app/DocumentsUICompose/DocumentsUICompose.apk
+```
\ No newline at end of file
diff --git a/res/menu/selection_demo_actions.xml b/compose/res/values/strings.xml
similarity index 60%
rename from res/menu/selection_demo_actions.xml
rename to compose/res/values/strings.xml
index e07c06b12..a7acb0e66 100644
--- a/res/menu/selection_demo_actions.xml
+++ b/compose/res/values/strings.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2017 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -14,13 +14,6 @@
      limitations under the License.
 -->
 
-<menu xmlns:android="http://schemas.android.com/apk/res/android">
-   <item
-       android:id="@+id/option_menu_add_column"
-       android:title="Add column"
-       android:showAsAction="always" />
-   <item
-       android:id="@+id/option_menu_remove_column"
-       android:title="Remove column"
-       android:showAsAction="always" />
-</menu>
+<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_label">DocsUI Compose</string>
+</resources>
\ No newline at end of file
diff --git a/compose/res/values/themes.xml b/compose/res/values/themes.xml
new file mode 100644
index 000000000..95442b050
--- /dev/null
+++ b/compose/res/values/themes.xml
@@ -0,0 +1,4 @@
+<?xml version="1.0" encoding="utf-8"?>
+<resources>
+    <style name="Theme.DocumentsUINoTitleBar" parent="android:Theme.Material.Light.NoActionBar" />
+</resources>
\ No newline at end of file
diff --git a/compose/src/com/android/documentsui/compose/DocumentsUIApplication.kt b/compose/src/com/android/documentsui/compose/DocumentsUIApplication.kt
new file mode 100644
index 000000000..f6e0e811e
--- /dev/null
+++ b/compose/src/com/android/documentsui/compose/DocumentsUIApplication.kt
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
+package com.android.documentsui.compose
+
+import android.app.Application
+import dagger.hilt.android.HiltAndroidApp
+
+@HiltAndroidApp(Application::class)
+class DocumentsUIApplication : Hilt_DocumentsUIApplication()
diff --git a/compose/src/com/android/documentsui/compose/MainActivity.kt b/compose/src/com/android/documentsui/compose/MainActivity.kt
new file mode 100644
index 000000000..8db5140f2
--- /dev/null
+++ b/compose/src/com/android/documentsui/compose/MainActivity.kt
@@ -0,0 +1,47 @@
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
+package com.android.documentsui.compose
+
+import android.os.Bundle
+import androidx.activity.ComponentActivity
+import androidx.activity.compose.setContent
+import androidx.activity.enableEdgeToEdge
+import androidx.compose.foundation.layout.fillMaxSize
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.Surface
+import androidx.compose.material3.Text
+import androidx.compose.ui.Modifier
+import dagger.hilt.android.AndroidEntryPoint
+
+@AndroidEntryPoint(ComponentActivity::class)
+class MainActivity : Hilt_MainActivity() {
+    override fun onCreate(savedInstanceState: Bundle?) {
+        enableEdgeToEdge()
+        super.onCreate(savedInstanceState)
+
+        setContent {
+            DocumentsUITheme {
+                Surface(
+                    modifier = Modifier.fillMaxSize(),
+                    color = MaterialTheme.colorScheme.background
+                ) {
+                    Text(text = "DocumentsUI Compose")
+                }
+            }
+        }
+    }
+}
diff --git a/compose/src/com/android/documentsui/compose/Theme.kt b/compose/src/com/android/documentsui/compose/Theme.kt
new file mode 100644
index 000000000..de6f7f34f
--- /dev/null
+++ b/compose/src/com/android/documentsui/compose/Theme.kt
@@ -0,0 +1,48 @@
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
+package com.android.documentsui.compose
+
+import androidx.compose.foundation.isSystemInDarkTheme
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.darkColorScheme
+import androidx.compose.material3.dynamicDarkColorScheme
+import androidx.compose.material3.dynamicLightColorScheme
+import androidx.compose.material3.lightColorScheme
+import androidx.compose.runtime.Composable
+import androidx.compose.ui.platform.LocalContext
+import com.android.modules.utils.build.SdkLevel
+
+@Composable
+fun DocumentsUITheme(
+    darkTheme: Boolean = isSystemInDarkTheme(),
+    dynamicColor: Boolean = true,
+    content: @Composable () -> Unit
+) {
+    val colorScheme = when {
+        dynamicColor && SdkLevel.isAtLeastS() -> {
+            val context = LocalContext.current
+            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
+        }
+        darkTheme -> darkColorScheme()
+        else -> lightColorScheme()
+    }
+
+    MaterialTheme(
+        colorScheme = colorScheme,
+        content = content
+    )
+}
diff --git a/flags.aconfig b/flags.aconfig
new file mode 100644
index 000000000..6646e196b
--- /dev/null
+++ b/flags.aconfig
@@ -0,0 +1,19 @@
+package: "com.android.documentsui.flags"
+container: "system"
+
+flag {
+    name: "use_material3"
+    namespace: "documentsui"
+    description: "Use Material 3 theme and styles."
+    bug: "373720657"
+    is_fixed_read_only: true
+}
+
+flag {
+    name: "use_search_v2"
+    namespace: "documentsui"
+    description: "Enables the next generation search functionality."
+    bug: "378590312"
+    is_fixed_read_only: true
+}
+
diff --git a/res/color/doc_list_item_subtitle_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/doc_list_item_subtitle_color.xml
similarity index 100%
rename from res/color/doc_list_item_subtitle_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/doc_list_item_subtitle_color.xml
diff --git a/res/color/fragment_pick_button_background_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/fragment_pick_button_background_color.xml
similarity index 100%
rename from res/color/fragment_pick_button_background_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/fragment_pick_button_background_color.xml
diff --git a/res/color/fragment_pick_button_text_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/fragment_pick_button_text_color.xml
similarity index 100%
rename from res/color/fragment_pick_button_text_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/fragment_pick_button_text_color.xml
diff --git a/res/color/horizontal_breadcrumb_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/horizontal_breadcrumb_color.xml
similarity index 100%
rename from res/color/horizontal_breadcrumb_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/horizontal_breadcrumb_color.xml
diff --git a/res/color/item_action_icon.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_action_icon.xml
similarity index 100%
rename from res/color/item_action_icon.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_action_icon.xml
diff --git a/res/color/item_details.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_details.xml
similarity index 100%
rename from res/color/item_details.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_details.xml
diff --git a/res/color/item_doc_grid_border.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_doc_grid_border.xml
similarity index 100%
rename from res/color/item_doc_grid_border.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_doc_grid_border.xml
diff --git a/res/color/item_doc_grid_tint.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_doc_grid_tint.xml
similarity index 100%
rename from res/color/item_doc_grid_tint.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_doc_grid_tint.xml
diff --git a/res/color/item_root_icon.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_root_icon.xml
similarity index 100%
rename from res/color/item_root_icon.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_root_icon.xml
diff --git a/res/color/item_root_primary_text.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_root_primary_text.xml
similarity index 100%
rename from res/color/item_root_primary_text.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_root_primary_text.xml
diff --git a/res/color/item_root_secondary_text.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/item_root_secondary_text.xml
similarity index 100%
rename from res/color/item_root_secondary_text.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/item_root_secondary_text.xml
diff --git a/res/color/profile_tab_selector.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/profile_tab_selector.xml
similarity index 100%
rename from res/color/profile_tab_selector.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/profile_tab_selector.xml
diff --git a/res/color/search_chip_background_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_background_color.xml
similarity index 100%
rename from res/color/search_chip_background_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_background_color.xml
diff --git a/res/color/search_chip_ripple_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_ripple_color.xml
similarity index 100%
rename from res/color/search_chip_ripple_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_ripple_color.xml
diff --git a/res/color/search_chip_stroke_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_stroke_color.xml
similarity index 100%
rename from res/color/search_chip_stroke_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_stroke_color.xml
diff --git a/res/color/search_chip_text_color.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_text_color.xml
similarity index 100%
rename from res/color/search_chip_text_color.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/search_chip_text_color.xml
diff --git a/res/color/sort_list_text.xml b/res/flag(!com.android.documentsui.flags.use_material3)/color/sort_list_text.xml
similarity index 100%
rename from res/color/sort_list_text.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/color/sort_list_text.xml
diff --git a/res/drawable-ldrtl/roots_list_border.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable-ldrtl/roots_list_border.xml
similarity index 100%
rename from res/drawable-ldrtl/roots_list_border.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable-ldrtl/roots_list_border.xml
diff --git a/res/drawable/band_select_overlay.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/band_select_overlay.xml
similarity index 100%
rename from res/drawable/band_select_overlay.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/band_select_overlay.xml
diff --git a/res/drawable/bottom_sheet_dialog_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/bottom_sheet_dialog_background.xml
similarity index 100%
rename from res/drawable/bottom_sheet_dialog_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/bottom_sheet_dialog_background.xml
diff --git a/res/drawable/breadcrumb_item_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/breadcrumb_item_background.xml
similarity index 100%
rename from res/drawable/breadcrumb_item_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/breadcrumb_item_background.xml
diff --git a/res/drawable/circle_button_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/circle_button_background.xml
similarity index 100%
rename from res/drawable/circle_button_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/circle_button_background.xml
diff --git a/res/drawable/debug_msg_1.png b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/debug_msg_1.png
similarity index 100%
rename from res/drawable/debug_msg_1.png
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/debug_msg_1.png
diff --git a/res/drawable/debug_msg_2.png b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/debug_msg_2.png
similarity index 100%
rename from res/drawable/debug_msg_2.png
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/debug_msg_2.png
diff --git a/res/drawable/drag_shadow_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/drag_shadow_background.xml
similarity index 100%
rename from res/drawable/drag_shadow_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/drag_shadow_background.xml
diff --git a/res/drawable/drop_badge_states.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/drop_badge_states.xml
similarity index 100%
rename from res/drawable/drop_badge_states.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/drop_badge_states.xml
diff --git a/res/drawable/dropdown_sort_widget_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/dropdown_sort_widget_background.xml
similarity index 100%
rename from res/drawable/dropdown_sort_widget_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/dropdown_sort_widget_background.xml
diff --git a/res/drawable/empty.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/empty.xml
similarity index 100%
rename from res/drawable/empty.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/empty.xml
diff --git a/res/drawable/fast_scroll_thumb_drawable.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/fast_scroll_thumb_drawable.xml
similarity index 100%
rename from res/drawable/fast_scroll_thumb_drawable.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/fast_scroll_thumb_drawable.xml
diff --git a/res/drawable/fast_scroll_track_drawable.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/fast_scroll_track_drawable.xml
similarity index 100%
rename from res/drawable/fast_scroll_track_drawable.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/fast_scroll_track_drawable.xml
diff --git a/res/drawable/generic_ripple_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/generic_ripple_background.xml
similarity index 100%
rename from res/drawable/generic_ripple_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/generic_ripple_background.xml
diff --git a/res/drawable/gradient_actionbar_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/gradient_actionbar_background.xml
similarity index 100%
rename from res/drawable/gradient_actionbar_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/gradient_actionbar_background.xml
diff --git a/res/drawable/grid_item_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/grid_item_background.xml
similarity index 100%
rename from res/drawable/grid_item_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/grid_item_background.xml
diff --git a/res/drawable/hourglass.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/hourglass.xml
similarity index 100%
rename from res/drawable/hourglass.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/hourglass.xml
diff --git a/res/drawable/ic_action_clear.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_action_clear.xml
similarity index 100%
rename from res/drawable/ic_action_clear.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_action_clear.xml
diff --git a/res/drawable/ic_action_open.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_action_open.xml
similarity index 100%
rename from res/drawable/ic_action_open.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_action_open.xml
diff --git a/res/drawable/ic_advanced_shortcut.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_advanced_shortcut.xml
similarity index 100%
rename from res/drawable/ic_advanced_shortcut.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_advanced_shortcut.xml
diff --git a/res/drawable/ic_arrow_back.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_arrow_back.xml
similarity index 100%
rename from res/drawable/ic_arrow_back.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_arrow_back.xml
diff --git a/res/drawable/ic_arrow_upward.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_arrow_upward.xml
similarity index 100%
rename from res/drawable/ic_arrow_upward.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_arrow_upward.xml
diff --git a/res/drawable/ic_breadcrumb_arrow.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_breadcrumb_arrow.xml
similarity index 100%
rename from res/drawable/ic_breadcrumb_arrow.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_breadcrumb_arrow.xml
diff --git a/res/drawable/ic_briefcase.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_briefcase.xml
similarity index 100%
rename from res/drawable/ic_briefcase.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_briefcase.xml
diff --git a/res/drawable/ic_briefcase_white.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_briefcase_white.xml
similarity index 100%
rename from res/drawable/ic_briefcase_white.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_briefcase_white.xml
diff --git a/res/drawable/ic_cab_cancel.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_cab_cancel.xml
similarity index 100%
rename from res/drawable/ic_cab_cancel.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_cab_cancel.xml
diff --git a/res/drawable/ic_check.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_check.xml
similarity index 100%
rename from res/drawable/ic_check.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_check.xml
diff --git a/res/drawable/ic_check_circle.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_check_circle.xml
similarity index 100%
rename from res/drawable/ic_check_circle.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_check_circle.xml
diff --git a/res/drawable/ic_chip_from_this_week.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_chip_from_this_week.xml
similarity index 100%
rename from res/drawable/ic_chip_from_this_week.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_chip_from_this_week.xml
diff --git a/res/drawable/ic_chip_large_files.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_chip_large_files.xml
similarity index 100%
rename from res/drawable/ic_chip_large_files.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_chip_large_files.xml
diff --git a/res/drawable/ic_create_new_folder.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_create_new_folder.xml
similarity index 100%
rename from res/drawable/ic_create_new_folder.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_create_new_folder.xml
diff --git a/res/drawable/ic_debug_menu.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_debug_menu.xml
similarity index 100%
rename from res/drawable/ic_debug_menu.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_debug_menu.xml
diff --git a/res/drawable/ic_dialog_alert.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_dialog_alert.xml
similarity index 100%
rename from res/drawable/ic_dialog_alert.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_dialog_alert.xml
diff --git a/res/drawable/ic_dialog_info.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_dialog_info.xml
similarity index 100%
rename from res/drawable/ic_dialog_info.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_dialog_info.xml
diff --git a/res/drawable/ic_done.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_done.xml
similarity index 100%
rename from res/drawable/ic_done.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_done.xml
diff --git a/res/drawable/ic_drop_copy_badge.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_drop_copy_badge.xml
similarity index 100%
rename from res/drawable/ic_drop_copy_badge.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_drop_copy_badge.xml
diff --git a/res/drawable/ic_eject.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_eject.xml
similarity index 100%
rename from res/drawable/ic_eject.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_eject.xml
diff --git a/res/drawable/ic_exit_to_app.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_exit_to_app.xml
similarity index 100%
rename from res/drawable/ic_exit_to_app.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_exit_to_app.xml
diff --git a/res/drawable/ic_folder_shortcut.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_folder_shortcut.xml
similarity index 100%
rename from res/drawable/ic_folder_shortcut.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_folder_shortcut.xml
diff --git a/res/drawable/ic_hamburger.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_hamburger.xml
similarity index 100%
rename from res/drawable/ic_hamburger.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_hamburger.xml
diff --git a/res/drawable/ic_history.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_history.xml
similarity index 100%
rename from res/drawable/ic_history.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_history.xml
diff --git a/res/drawable/ic_images_shortcut.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_images_shortcut.xml
similarity index 100%
rename from res/drawable/ic_images_shortcut.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_images_shortcut.xml
diff --git a/res/drawable/ic_menu_compress.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_compress.xml
similarity index 100%
rename from res/drawable/ic_menu_compress.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_compress.xml
diff --git a/res/drawable/ic_menu_copy.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_copy.xml
similarity index 100%
rename from res/drawable/ic_menu_copy.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_copy.xml
diff --git a/res/drawable/ic_menu_delete.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_delete.xml
similarity index 100%
rename from res/drawable/ic_menu_delete.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_delete.xml
diff --git a/res/drawable/ic_menu_extract.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_extract.xml
similarity index 100%
rename from res/drawable/ic_menu_extract.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_extract.xml
diff --git a/res/drawable/ic_menu_search.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_search.xml
similarity index 100%
rename from res/drawable/ic_menu_search.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_search.xml
diff --git a/res/drawable/ic_menu_share.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_share.xml
similarity index 100%
rename from res/drawable/ic_menu_share.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_share.xml
diff --git a/res/drawable/ic_menu_view_grid.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_grid.xml
similarity index 100%
rename from res/drawable/ic_menu_view_grid.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_grid.xml
diff --git a/res/drawable/ic_menu_view_list.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_list.xml
similarity index 100%
rename from res/drawable/ic_menu_view_list.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_list.xml
diff --git a/res/drawable/ic_reject_drop_badge.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_reject_drop_badge.xml
similarity index 100%
rename from res/drawable/ic_reject_drop_badge.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_reject_drop_badge.xml
diff --git a/res/drawable/ic_root_bugreport.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_bugreport.xml
similarity index 100%
rename from res/drawable/ic_root_bugreport.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_bugreport.xml
diff --git a/res/drawable/ic_root_download.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_download.xml
similarity index 100%
rename from res/drawable/ic_root_download.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_download.xml
diff --git a/res/drawable/ic_root_recent.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_recent.xml
similarity index 100%
rename from res/drawable/ic_root_recent.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_recent.xml
diff --git a/res/drawable/ic_root_smartphone.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_smartphone.xml
similarity index 100%
rename from res/drawable/ic_root_smartphone.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_root_smartphone.xml
diff --git a/res/drawable/ic_sd_storage.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_sd_storage.xml
similarity index 100%
rename from res/drawable/ic_sd_storage.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_sd_storage.xml
diff --git a/res/drawable/ic_sort.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_sort.xml
similarity index 100%
rename from res/drawable/ic_sort.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_sort.xml
diff --git a/res/drawable/ic_sort_arrow.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_sort_arrow.xml
similarity index 100%
rename from res/drawable/ic_sort_arrow.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_sort_arrow.xml
diff --git a/res/drawable/ic_subdirectory_arrow.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_subdirectory_arrow.xml
similarity index 100%
rename from res/drawable/ic_subdirectory_arrow.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_subdirectory_arrow.xml
diff --git a/res/drawable/ic_usb_shortcut.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_usb_shortcut.xml
similarity index 100%
rename from res/drawable/ic_usb_shortcut.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_usb_shortcut.xml
diff --git a/res/drawable/ic_usb_storage.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_usb_storage.xml
similarity index 100%
rename from res/drawable/ic_usb_storage.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_usb_storage.xml
diff --git a/res/drawable/ic_user_profile.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_user_profile.xml
similarity index 100%
rename from res/drawable/ic_user_profile.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_user_profile.xml
diff --git a/res/drawable/ic_zoom_out.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_zoom_out.xml
similarity index 100%
rename from res/drawable/ic_zoom_out.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/ic_zoom_out.xml
diff --git a/res/drawable/inspector_separator.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/inspector_separator.xml
similarity index 100%
rename from res/drawable/inspector_separator.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/inspector_separator.xml
diff --git a/res/drawable/item_doc_grid_border.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border.xml
similarity index 100%
rename from res/drawable/item_doc_grid_border.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border.xml
diff --git a/res/drawable/item_doc_grid_border_rounded.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border_rounded.xml
similarity index 100%
rename from res/drawable/item_doc_grid_border_rounded.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border_rounded.xml
diff --git a/res/drawable/launcher_screen.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/launcher_screen.xml
similarity index 100%
rename from res/drawable/launcher_screen.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/launcher_screen.xml
diff --git a/res/drawable/launcher_screen_night.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/launcher_screen_night.xml
similarity index 100%
rename from res/drawable/launcher_screen_night.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/launcher_screen_night.xml
diff --git a/res/drawable/list_checker.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/list_checker.xml
similarity index 100%
rename from res/drawable/list_checker.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/list_checker.xml
diff --git a/res/drawable/list_divider.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/list_divider.xml
similarity index 100%
rename from res/drawable/list_divider.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/list_divider.xml
diff --git a/res/drawable/list_item_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/list_item_background.xml
similarity index 100%
rename from res/drawable/list_item_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/list_item_background.xml
diff --git a/res/drawable/menu_dropdown_panel.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/menu_dropdown_panel.xml
similarity index 100%
rename from res/drawable/menu_dropdown_panel.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/menu_dropdown_panel.xml
diff --git a/res/drawable/progress_indeterminate_horizontal_material_trimmed.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/progress_indeterminate_horizontal_material_trimmed.xml
similarity index 100%
rename from res/drawable/progress_indeterminate_horizontal_material_trimmed.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/progress_indeterminate_horizontal_material_trimmed.xml
diff --git a/res/drawable/root_item_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/root_item_background.xml
similarity index 100%
rename from res/drawable/root_item_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/root_item_background.xml
diff --git a/res/drawable/root_list_selector.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/root_list_selector.xml
similarity index 100%
rename from res/drawable/root_list_selector.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/root_list_selector.xml
diff --git a/res/drawable/search_bar_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/search_bar_background.xml
similarity index 100%
rename from res/drawable/search_bar_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/search_bar_background.xml
diff --git a/res/drawable/share_off.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/share_off.xml
similarity index 100%
rename from res/drawable/share_off.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/share_off.xml
diff --git a/res/drawable/sort_widget_background.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/sort_widget_background.xml
similarity index 100%
rename from res/drawable/sort_widget_background.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/sort_widget_background.xml
diff --git a/res/drawable/splash_screen.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/splash_screen.xml
similarity index 100%
rename from res/drawable/splash_screen.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/splash_screen.xml
diff --git a/res/drawable/tab_border_rounded.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/tab_border_rounded.xml
similarity index 100%
rename from res/drawable/tab_border_rounded.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/tab_border_rounded.xml
diff --git a/res/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml
similarity index 100%
rename from res/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml
diff --git a/res/drawable/work_off.xml b/res/flag(!com.android.documentsui.flags.use_material3)/drawable/work_off.xml
similarity index 100%
rename from res/drawable/work_off.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/drawable/work_off.xml
diff --git a/res/layout-sw720dp/column_headers.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/column_headers.xml
similarity index 100%
rename from res/layout-sw720dp/column_headers.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/column_headers.xml
diff --git a/res/layout-sw720dp/directory_app_bar.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/directory_app_bar.xml
similarity index 100%
rename from res/layout-sw720dp/directory_app_bar.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/directory_app_bar.xml
diff --git a/res/layout-sw720dp/item_doc_list.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/item_doc_list.xml
similarity index 100%
rename from res/layout-sw720dp/item_doc_list.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/item_doc_list.xml
diff --git a/res/layout-sw720dp/shared_cell_content.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/shared_cell_content.xml
similarity index 100%
rename from res/layout-sw720dp/shared_cell_content.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout-sw720dp/shared_cell_content.xml
diff --git a/res/layout/apps_item.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/apps_item.xml
similarity index 100%
rename from res/layout/apps_item.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/apps_item.xml
diff --git a/res/layout/apps_row.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/apps_row.xml
similarity index 100%
rename from res/layout/apps_row.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/apps_row.xml
diff --git a/res/layout/column_headers.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/column_headers.xml
similarity index 100%
rename from res/layout/column_headers.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/column_headers.xml
diff --git a/res/layout/dialog_delete_confirmation.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/dialog_delete_confirmation.xml
similarity index 100%
rename from res/layout/dialog_delete_confirmation.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/dialog_delete_confirmation.xml
diff --git a/res/layout/dialog_file_name.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/dialog_file_name.xml
similarity index 100%
rename from res/layout/dialog_file_name.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/dialog_file_name.xml
diff --git a/res/layout/dialog_sorting.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/dialog_sorting.xml
similarity index 100%
rename from res/layout/dialog_sorting.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/dialog_sorting.xml
diff --git a/res/layout/directory_app_bar.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/directory_app_bar.xml
similarity index 100%
rename from res/layout/directory_app_bar.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/directory_app_bar.xml
diff --git a/res/layout/directory_header.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/directory_header.xml
similarity index 100%
rename from res/layout/directory_header.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/directory_header.xml
diff --git a/res/layout/drag_shadow_layout.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/drag_shadow_layout.xml
similarity index 100%
rename from res/layout/drag_shadow_layout.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/drag_shadow_layout.xml
diff --git a/res/layout/drawer_layout.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/drawer_layout.xml
similarity index 100%
rename from res/layout/drawer_layout.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/drawer_layout.xml
diff --git a/res/layout/drop_badge.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/drop_badge.xml
similarity index 100%
rename from res/layout/drop_badge.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/drop_badge.xml
diff --git a/res/layout/fixed_layout.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/fixed_layout.xml
similarity index 100%
rename from res/layout/fixed_layout.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/fixed_layout.xml
diff --git a/res/layout/fragment_directory.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_directory.xml
similarity index 100%
rename from res/layout/fragment_directory.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_directory.xml
diff --git a/res/layout/fragment_pick.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_pick.xml
similarity index 100%
rename from res/layout/fragment_pick.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_pick.xml
diff --git a/res/layout/fragment_roots.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_roots.xml
similarity index 100%
rename from res/layout/fragment_roots.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_roots.xml
diff --git a/res/layout/fragment_save.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_save.xml
similarity index 100%
rename from res/layout/fragment_save.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_save.xml
diff --git a/res/layout/fragment_search.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_search.xml
similarity index 100%
rename from res/layout/fragment_search.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/fragment_search.xml
diff --git a/res/layout/inspector_action_view.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_action_view.xml
similarity index 100%
rename from res/layout/inspector_action_view.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_action_view.xml
diff --git a/res/layout/inspector_activity.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_activity.xml
similarity index 100%
rename from res/layout/inspector_activity.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_activity.xml
diff --git a/res/layout/inspector_header.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_header.xml
similarity index 100%
rename from res/layout/inspector_header.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_header.xml
diff --git a/res/layout/inspector_section_title.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_section_title.xml
similarity index 100%
rename from res/layout/inspector_section_title.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/inspector_section_title.xml
diff --git a/res/layout/item_dir_grid.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_dir_grid.xml
similarity index 100%
rename from res/layout/item_dir_grid.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_dir_grid.xml
diff --git a/res/layout/item_doc_grid.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_grid.xml
similarity index 100%
rename from res/layout/item_doc_grid.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_grid.xml
diff --git a/res/layout/item_doc_header_message.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_header_message.xml
similarity index 100%
rename from res/layout/item_doc_header_message.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_header_message.xml
diff --git a/res/layout/item_doc_inflated_message.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message.xml
similarity index 100%
rename from res/layout/item_doc_inflated_message.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message.xml
diff --git a/res/layout/item_doc_inflated_message_content.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_content.xml
similarity index 100%
rename from res/layout/item_doc_inflated_message_content.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_content.xml
diff --git a/res/layout/item_doc_inflated_message_cross_profile.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_cross_profile.xml
similarity index 100%
rename from res/layout/item_doc_inflated_message_cross_profile.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_cross_profile.xml
diff --git a/res/layout/item_doc_list.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_list.xml
similarity index 100%
rename from res/layout/item_doc_list.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_doc_list.xml
diff --git a/res/layout/item_history.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_history.xml
similarity index 100%
rename from res/layout/item_history.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_history.xml
diff --git a/res/layout/item_photo_grid.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_photo_grid.xml
similarity index 100%
rename from res/layout/item_photo_grid.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_photo_grid.xml
diff --git a/res/layout/item_root.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_root.xml
similarity index 100%
rename from res/layout/item_root.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_root.xml
diff --git a/res/layout/item_root_header.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_root_header.xml
similarity index 100%
rename from res/layout/item_root_header.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_root_header.xml
diff --git a/res/layout/item_root_spacer.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/item_root_spacer.xml
similarity index 100%
rename from res/layout/item_root_spacer.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/item_root_spacer.xml
diff --git a/res/layout/navigation_breadcrumb_item.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/navigation_breadcrumb_item.xml
similarity index 100%
rename from res/layout/navigation_breadcrumb_item.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/navigation_breadcrumb_item.xml
diff --git a/res/layout/root_vertical_divider.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/root_vertical_divider.xml
similarity index 100%
rename from res/layout/root_vertical_divider.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/root_vertical_divider.xml
diff --git a/res/layout/search_chip_item.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/search_chip_item.xml
similarity index 100%
rename from res/layout/search_chip_item.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/search_chip_item.xml
diff --git a/res/layout/search_chip_row.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/search_chip_row.xml
similarity index 100%
rename from res/layout/search_chip_row.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/search_chip_row.xml
diff --git a/res/layout/sort_list_item.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/sort_list_item.xml
similarity index 100%
rename from res/layout/sort_list_item.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/sort_list_item.xml
diff --git a/res/layout/table_key_value_row.xml b/res/flag(!com.android.documentsui.flags.use_material3)/layout/table_key_value_row.xml
similarity index 100%
rename from res/layout/table_key_value_row.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/layout/table_key_value_row.xml
diff --git a/res/values-h600dp-v31/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-h600dp-v31/dimens.xml
similarity index 100%
rename from res/values-h600dp-v31/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-h600dp-v31/dimens.xml
diff --git a/res/values-h600dp/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-h600dp/dimens.xml
similarity index 100%
rename from res/values-h600dp/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-h600dp/dimens.xml
diff --git a/res/values-night-v31/colors.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-night-v31/colors.xml
similarity index 100%
rename from res/values-night-v31/colors.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-night-v31/colors.xml
diff --git a/res/values-night-v31/styles.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-night-v31/styles.xml
similarity index 100%
rename from res/values-night-v31/styles.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-night-v31/styles.xml
diff --git a/res/values-night/colors.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-night/colors.xml
similarity index 100%
rename from res/values-night/colors.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-night/colors.xml
diff --git a/res/values-night/themes.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-night/themes.xml
similarity index 100%
rename from res/values-night/themes.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-night/themes.xml
diff --git a/res/values-sw600dp/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-sw600dp/dimens.xml
similarity index 100%
rename from res/values-sw600dp/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-sw600dp/dimens.xml
diff --git a/res/values-sw720dp-land/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp-land/dimens.xml
similarity index 100%
rename from res/values-sw720dp-land/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp-land/dimens.xml
diff --git a/res/values-sw720dp-land/layouts.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp-land/layouts.xml
similarity index 100%
rename from res/values-sw720dp-land/layouts.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp-land/layouts.xml
diff --git a/res/values-sw720dp/colors.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp/colors.xml
similarity index 100%
rename from res/values-sw720dp/colors.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp/colors.xml
diff --git a/res/values-sw720dp/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp/dimens.xml
similarity index 100%
rename from res/values-sw720dp/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-sw720dp/dimens.xml
diff --git a/res/values-v31/colors.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-v31/colors.xml
similarity index 100%
rename from res/values-v31/colors.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-v31/colors.xml
diff --git a/res/values-v31/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-v31/dimens.xml
similarity index 100%
rename from res/values-v31/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-v31/dimens.xml
diff --git a/res/values-v31/styles.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-v31/styles.xml
similarity index 100%
rename from res/values-v31/styles.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-v31/styles.xml
diff --git a/res/values-v31/styles_text.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values-v31/styles_text.xml
similarity index 100%
rename from res/values-v31/styles_text.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values-v31/styles_text.xml
diff --git a/res/values/colors.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values/colors.xml
similarity index 100%
rename from res/values/colors.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values/colors.xml
diff --git a/res/values/dimens.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values/dimens.xml
similarity index 100%
rename from res/values/dimens.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values/dimens.xml
diff --git a/res/values/layouts.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values/layouts.xml
similarity index 100%
rename from res/values/layouts.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values/layouts.xml
diff --git a/res/values/styles.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values/styles.xml
similarity index 100%
rename from res/values/styles.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values/styles.xml
diff --git a/res/values/styles_text.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values/styles_text.xml
similarity index 100%
rename from res/values/styles_text.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values/styles_text.xml
diff --git a/res/values/themes.xml b/res/flag(!com.android.documentsui.flags.use_material3)/values/themes.xml
similarity index 100%
rename from res/values/themes.xml
rename to res/flag(!com.android.documentsui.flags.use_material3)/values/themes.xml
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/doc_list_item_subtitle_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/doc_list_item_subtitle_color.xml
new file mode 100644
index 000000000..d9f27e60a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/doc_list_item_subtitle_color.xml
@@ -0,0 +1,22 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_enabled="false"
+        android:color="@color/doc_list_item_subtitle_disabled" />
+    <item android:color="@color/doc_list_item_subtitle_enabled" />
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/fragment_pick_button_background_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/fragment_pick_button_background_color.xml
new file mode 100644
index 000000000..cf6d480ea
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/fragment_pick_button_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+  Copyright 2018 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      https://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:color="@color/fragment_pick_active_button_color" android:state_enabled="true" />
+  <item android:color="@color/fragment_pick_inactive_button_color" android:state_enabled="false" />
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/fragment_pick_button_text_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/fragment_pick_button_text_color.xml
new file mode 100644
index 000000000..e4e1edc48
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/fragment_pick_button_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+  Copyright 2018 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      https://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:color="@color/fragment_pick_active_text_color" android:state_enabled="true" />
+  <item android:color="@color/fragment_pick_inactive_text_color" android:state_enabled="false" />
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/horizontal_breadcrumb_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/horizontal_breadcrumb_color.xml
new file mode 100644
index 000000000..ab511326d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/horizontal_breadcrumb_color.xml
@@ -0,0 +1,21 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_enabled="true"
+        android:color="?android:colorAccent" />
+    <item android:color="?android:attr/colorControlNormal" />
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/item_action_icon.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_action_icon.xml
new file mode 100644
index 000000000..4487795c1
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_action_icon.xml
@@ -0,0 +1,22 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_enabled="false"
+        android:alpha="@dimen/root_icon_disabled_alpha"
+        android:color="?android:colorControlNormal" />
+    <item android:color="?android:colorControlNormal" />
+</selector>
diff --git a/res/drawable/selection_demo_item_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_details.xml
similarity index 78%
rename from res/drawable/selection_demo_item_background.xml
rename to res/flag(com.android.documentsui.flags.use_material3)/color/item_details.xml
index de5c14236..321ec9cb1 100644
--- a/res/drawable/selection_demo_item_background.xml
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_details.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2017 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -15,7 +15,7 @@
 -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_activated="true">
-        <color android:color="?android:attr/colorControlHighlight"></color>
-    </item>
+    <item
+        android:state_enabled="true"
+        android:color="?android:textColorSecondary" />
 </selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/item_doc_grid_border.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_doc_grid_border.xml
new file mode 100644
index 000000000..36ea36f93
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_doc_grid_border.xml
@@ -0,0 +1,27 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:state_focused="true"
+        android:state_selected="false"
+        android:color="?android:attr/colorAccent"/>
+    <item
+        android:state_selected="true"
+        android:color="?android:attr/colorAccent"/>
+    <item
+        android:color="@android:color/transparent"/>
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/item_doc_grid_tint.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_doc_grid_tint.xml
new file mode 100644
index 000000000..c20b7d032
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_doc_grid_tint.xml
@@ -0,0 +1,24 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:state_activated="true"
+        android:color="?android:colorAccent"
+        android:alpha=".15" />
+    <item
+        android:color="@android:color/transparent" />
+</selector>
diff --git a/res/color/selection_demo_item_selector.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_icon.xml
similarity index 78%
rename from res/color/selection_demo_item_selector.xml
rename to res/flag(com.android.documentsui.flags.use_material3)/color/item_root_icon.xml
index bd87b4c6b..142d85e6f 100644
--- a/res/color/selection_demo_item_selector.xml
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_icon.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2017 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -15,13 +15,10 @@
 -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item
-        android:state_activated="true"
-        android:color="?android:attr/colorForeground"
-        />
     <item
         android:state_activated="false"
-        android:color="?android:attr/colorForeground"
-        android:alpha=".3"
-        />
+        android:color="?android:colorControlNormal" />
+    <item
+        android:state_activated="true"
+        android:color="?android:colorControlActivated" />
 </selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_primary_text.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_primary_text.xml
new file mode 100644
index 000000000..337c1a2c1
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_primary_text.xml
@@ -0,0 +1,22 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true" android:state_activated="true" android:color="?android:colorControlActivated" />
+    <item android:state_focused="false" android:state_activated="true" android:color="?android:colorControlActivated" />
+    <item android:state_enabled="false" android:alpha="0.5" android:color="?android:textColorPrimary" />
+    <item android:color="?android:textColorPrimary" />
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_secondary_text.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_secondary_text.xml
new file mode 100644
index 000000000..b6149ff13
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/item_root_secondary_text.xml
@@ -0,0 +1,25 @@
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
+  ~ limitations under the License
+  -->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true" android:state_activated="true"
+        android:color="?android:colorControlActivated" />
+    <item android:state_focused="false" android:state_activated="true"
+        android:color="?android:colorControlActivated" />
+    <item android:state_enabled="false" android:alpha="0.5" android:color="?android:textColorSecondary" />
+    <item android:color="?android:textColorSecondary" />
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/profile_tab_selector.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/profile_tab_selector.xml
new file mode 100644
index 000000000..a163185af
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/profile_tab_selector.xml
@@ -0,0 +1,23 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:state_selected="true"
+        android:color="@color/profile_tab_selected_color"/>
+    <item
+        android:color="@color/profile_tab_default_color"/>
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_background_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_background_color.xml
new file mode 100644
index 000000000..08c0ac3ca
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_background_color.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2018 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      https://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <!-- Disabled -->
+    <item android:color="@android:color/transparent" android:state_enabled="false"/>
+
+    <!-- Selected -->
+    <item android:color="?attr/colorSecondaryContainer" android:state_selected="true"/>
+
+    <!-- Not selected: different from default value -->
+    <item android:color="@android:color/transparent" />
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_ripple_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_ripple_color.xml
new file mode 100644
index 000000000..b4aa0b8a7
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_ripple_color.xml
@@ -0,0 +1,39 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2018 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      https://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<!-- TODO(b/379776735): remove this file after M3 uplift -->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <!-- Selected. -->
+    <item android:state_pressed="true" android:state_selected="true"
+          android:alpha="0.16" android:color="?android:colorSecondary"/>
+    <item android:state_focused="true" android:state_hovered="true" android:state_selected="true"
+          android:alpha="0.16" android:color="?android:colorSecondary"/>
+    <item android:state_focused="true" android:state_selected="true"
+          android:alpha="0.12" android:color="?android:colorSecondary"/>
+    <item android:state_hovered="true" android:state_selected="true"
+          android:alpha="0.04" android:color="?android:colorSecondary"/>
+    <item android:state_selected="true"
+          android:alpha="0.00" android:color="?android:colorSecondary"/>
+
+    <!-- Unselected. -->
+    <item android:state_pressed="true" android:alpha="0.16" android:color="?android:textColorSecondary"/>
+    <item android:state_focused="true" android:state_hovered="true"
+          android:alpha="0.16" android:color="?android:textColorSecondary"/>
+    <item android:state_focused="true" android:alpha="0.12" android:color="?android:textColorSecondary"/>
+    <item android:state_hovered="true" android:alpha="0.04" android:color="?android:textColorSecondary"/>
+    <item android:alpha="0.00" android:color="?android:textColorSecondary"/>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_stroke_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_stroke_color.xml
new file mode 100644
index 000000000..518352c0d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_stroke_color.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2018 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      https://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <!-- Disabled -->
+    <item android:alpha="0.12" android:color="?attr/colorOnSurface" android:state_enabled="false"/>
+
+    <!-- Focused: different from default value -->
+    <item android:color="?attr/colorSecondary" android:state_focused="true"/>
+
+    <!-- Selected -->
+    <item android:color="@android:color/transparent" android:state_selected="true"/>
+
+    <!-- Other states -->
+    <item android:color="?attr/colorOutline"/>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_text_color.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_text_color.xml
new file mode 100644
index 000000000..be0cc404b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/search_chip_text_color.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2018 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      https://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<!-- TODO(b/379776735): remove this file after M3 uplift -->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true" android:color="@color/search_chip_text_selected_color"/>
+    <item android:state_enabled="true" android:color="?android:textColorSecondary"/>
+    <item android:state_enabled="false" android:color="?android:textColorSecondary" android:alpha="0.3"/>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/color/sort_list_text.xml b/res/flag(com.android.documentsui.flags.use_material3)/color/sort_list_text.xml
new file mode 100644
index 000000000..a1e93630b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/color/sort_list_text.xml
@@ -0,0 +1,22 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:state_checked="true"
+        android:color="?android:attr/colorAccent"/>
+    <item
+        android:color="?android:attr/textColorPrimary"/>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable-ldrtl/roots_list_border.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable-ldrtl/roots_list_border.xml
new file mode 100644
index 000000000..6c2b50857
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable-ldrtl/roots_list_border.xml
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
+
+<inset xmlns:android="http://schemas.android.com/apk/res/android"
+       android:insetTop="-1dp"
+       android:insetBottom="-1dp"
+       android:insetRight="-1dp">
+    <shape android:shape="rectangle">
+        <stroke
+            android:width="1dp"
+            android:color="?android:strokeColor"/>
+    </shape>
+</inset>
\ No newline at end of file
diff --git a/res/drawable/selection_demo_band_overlay.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/band_select_overlay.xml
similarity index 79%
rename from res/drawable/selection_demo_band_overlay.xml
rename to res/flag(com.android.documentsui.flags.use_material3)/drawable/band_select_overlay.xml
index adf2b27f8..53f969284 100644
--- a/res/drawable/selection_demo_band_overlay.xml
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/band_select_overlay.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2015 The Android Open Source Project
+  ~ Copyright (C) 2024 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -17,6 +17,6 @@
 
 <shape xmlns:android="http://schemas.android.com/apk/res/android"
         android:shape="rectangle">
-    <solid android:color="#339999ff" />
-    <stroke android:width="1dp" android:color="#44000000" />
+    <solid android:color="@color/band_select_background" />
+    <stroke android:width="1dp" android:color="@color/band_select_border" />
 </shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/bottom_sheet_dialog_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/bottom_sheet_dialog_background.xml
new file mode 100644
index 000000000..eba36783f
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/bottom_sheet_dialog_background.xml
@@ -0,0 +1,25 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+
+    <solid android:color="?android:attr/colorBackground" />
+
+    <corners android:topLeftRadius="@dimen/grid_item_radius"
+             android:topRightRadius="@dimen/grid_item_radius"
+             android:bottomLeftRadius="0dp"
+             android:bottomRightRadius="0dp"/>
+
+</shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/breadcrumb_item_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/breadcrumb_item_background.xml
new file mode 100644
index 000000000..8e6282199
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/breadcrumb_item_background.xml
@@ -0,0 +1,42 @@
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
+
+<ripple
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:color="?attr/colorControlHighlight">
+    <item
+        android:id="@android:id/mask"
+        android:drawable="@android:color/white"/>
+
+    <item>
+        <selector>
+            <item
+                app:state_highlighted="true"
+                android:drawable="@color/item_breadcrumb_background_hovered"/>
+            <item
+                app:state_highlighted="false"
+                android:drawable="@android:color/transparent">
+                <corners
+                    android:topLeftRadius="2dp"
+                    android:topRightRadius="2dp"
+                    android:bottomLeftRadius="2dp"
+                    android:bottomRightRadius="2dp"
+                />
+            </item>
+        </selector>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/circle_button_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/circle_button_background.xml
new file mode 100644
index 000000000..be2874119
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/circle_button_background.xml
@@ -0,0 +1,21 @@
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
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:shape="oval">
+    <solid
+        android:color="#66000000"/>
+</shape>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/debug_msg_1.png b/res/flag(com.android.documentsui.flags.use_material3)/drawable/debug_msg_1.png
new file mode 100644
index 000000000..862769a39
Binary files /dev/null and b/res/flag(com.android.documentsui.flags.use_material3)/drawable/debug_msg_1.png differ
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/debug_msg_2.png b/res/flag(com.android.documentsui.flags.use_material3)/drawable/debug_msg_2.png
new file mode 100644
index 000000000..e4c62591c
Binary files /dev/null and b/res/flag(com.android.documentsui.flags.use_material3)/drawable/debug_msg_2.png differ
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/drag_shadow_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/drag_shadow_background.xml
new file mode 100644
index 000000000..eed005eca
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/drag_shadow_background.xml
@@ -0,0 +1,25 @@
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
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:shape="rectangle">
+  <solid android:color="@color/item_drag_shadow_background" />
+  <corners
+      android:bottomRightRadius="2dp"
+      android:bottomLeftRadius="2dp"
+      android:topLeftRadius="2dp"
+      android:topRightRadius="2dp"/>
+</shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/drop_badge_states.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/drop_badge_states.xml
new file mode 100644
index 000000000..7b78a7b69
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/drop_badge_states.xml
@@ -0,0 +1,36 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto">
+
+    <!-- state when we can't drop -->
+    <item
+        app:state_reject_drop="true"
+        android:drawable="@drawable/ic_reject_drop_badge"/>
+
+    <!-- state when we can drop, and it will be a copy -->
+    <item
+        app:state_reject_drop="false"
+        app:state_copy="true"
+        android:drawable="@drawable/ic_drop_copy_badge"/>
+
+    <!-- default state. Also used to show state when we can drop, and it will be a move -->
+    <item
+        app:state_reject_drop="false"
+        app:state_copy="false"
+        android:drawable="@android:color/transparent" />
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/dropdown_sort_widget_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/dropdown_sort_widget_background.xml
new file mode 100644
index 000000000..20179035e
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/dropdown_sort_widget_background.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+  -->
+
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+        android:color="?attr/colorControlHighlight" >
+    <item
+        android:id="@android:id/mask"
+        android:drawable="@android:color/white"/>
+</ripple>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/empty.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/empty.xml
new file mode 100644
index 000000000..cddd96821
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/empty.xml
@@ -0,0 +1,51 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="210dp"
+        android:height="210dp"
+        android:viewportWidth="210"
+        android:viewportHeight="210">
+
+    <path
+        android:fillColor="#DADCE0"
+        android:pathData="M115,109.44H95c-1.1,0-2-0.9-2-2s0.9-2,2-2h20c1.1,0,2,0.9,2,2S116.1,109.44,115,109.44z" />
+    <path
+        android:fillColor="#DADCE0"
+        android:pathData="M62.67,85.14l3-0.11L62.67,85.14c-0.04-0.74-0.06-1.48-0.06-2.22c0-0.69,0.02-1.37,0.05-2.05l5.99,0.29 c-0.03,0.58-0.04,1.17-0.04,1.76c0,0.64,0.02,1.28,0.05,1.92l-2.99,0.2L62.67,85.14z" />
+    <path
+        android:fillColor="#DADCE0"
+        android:pathData="M147.35,84.94l-5.99-0.28c0.03-0.56,0.04-1.12,0.04-1.69c0-0.64-0.02-1.28-0.05-1.92l-0.01-0.13l5.99-0.3 l0,0.08c0.04,0.77,0.06,1.52,0.06,2.26C147.39,83.64,147.38,84.29,147.35,84.94z" />
+    <path
+        android:fillColor="#EA4335"
+        android:pathData="M72.56,66.45l-5.35-2.72c0.65-1.28,1.38-2.54,2.16-3.75l5.04,3.25C73.74,64.27,73.12,65.35,72.56,66.45z" />
+    <path
+        android:fillColor="#EA4335"
+        android:pathData="M137.35,66.27c-0.56-1.09-1.19-2.17-1.87-3.21l5.02-3.28c0.79,1.21,1.52,2.46,2.18,3.74L137.35,66.27z" />
+    <path
+        android:fillColor="#DADCE0"
+        android:pathData="M85.15,52.44l-3.28-5.03c1.2-0.79,2.46-1.52,3.74-2.18l2.75,5.33C87.26,51.14,86.18,51.77,85.15,52.44z" />
+    <path
+        android:fillColor="#DADCE0"
+        android:pathData="M124.69,52.34c-1.04-0.67-2.12-1.29-3.22-1.85l2.72-5.35c1.28,0.65,2.54,1.38,3.75,2.15L124.69,52.34z" />
+    <path
+        android:fillColor="#EA4335"
+        android:pathData="M103.12,46.61l-0.4-5.99l0.08,0c1.45-0.07,2.85-0.08,4.25-0.01l-0.28,5.99 C105.56,46.54,104.34,46.54,103.12,46.61z" />
+    <path
+        android:fillColor="#DADCE0"
+        android:pathData="M154,95.44v70H56v-70H154 M154,91.44H56c-2.21,0-4,1.79-4,4v70c0,2.21,1.79,4,4,4h98c2.21,0,4-1.79,4-4 v-70C158,93.24,156.21,91.44,154,91.44L154,91.44z" />
+    <path
+        android:pathData="M 0 0 H 210 V 210 H 0 V 0 Z" />
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/fast_scroll_thumb_drawable.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/fast_scroll_thumb_drawable.xml
new file mode 100644
index 000000000..540a3877e
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/fast_scroll_thumb_drawable.xml
@@ -0,0 +1,30 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_pressed="true">
+        <shape  android:shape="rectangle">
+            <solid android:color="?android:attr/colorControlNormal" />
+            <size android:width="8dp" android:height="48dp" />
+        </shape>
+    </item>
+    <item>
+        <shape android:shape="rectangle">
+            <solid android:color="?android:attr/colorControlNormal" />
+            <size android:width="8dp" android:height="48dp" />
+        </shape>
+    </item>
+</selector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/fast_scroll_track_drawable.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/fast_scroll_track_drawable.xml
new file mode 100644
index 000000000..8daf5e69a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/fast_scroll_track_drawable.xml
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+  android:shape="rectangle">
+    <solid android:color="@android:color/transparent" />
+    <size android:width="8dp" />
+</shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/generic_ripple_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/generic_ripple_background.xml
new file mode 100644
index 000000000..74e1f9395
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/generic_ripple_background.xml
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
+
+<ripple
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="?android:attr/colorControlHighlight">
+    <item
+        android:id="@android:id/mask">
+        <shape android:shape="rectangle">
+            <solid android:color="@android:color/white"/>
+        </shape>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/gradient_actionbar_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/gradient_actionbar_background.xml
new file mode 100644
index 000000000..e3ace24a6
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/gradient_actionbar_background.xml
@@ -0,0 +1,23 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <gradient
+        android:startColor="@color/tool_bar_gradient_max"
+        android:endColor="@android:color/transparent"
+        android:angle="270"
+        android:type="linear" >
+    </gradient>
+</shape>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/grid_item_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/grid_item_background.xml
new file mode 100644
index 000000000..8ad58f3c9
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/grid_item_background.xml
@@ -0,0 +1,27 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true">
+        <color android:color="?android:colorSecondary"/>
+    </item>
+    <item android:state_drag_hovered="true">
+        <color android:color="?android:strokeColor"/>
+    </item>
+    <item android:state_selected="false">
+        <color android:color="?android:colorBackground"/>
+    </item>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/hourglass.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/hourglass.xml
new file mode 100644
index 000000000..e4c803da9
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/hourglass.xml
@@ -0,0 +1,168 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="421dp"
+        android:height="909dp"
+        android:viewportWidth="421.0"
+        android:viewportHeight="909.0">
+    <path
+        android:pathData="M36,122.9c-2.8,-2.6,-5.7,-5.1,-8.3,-7.8c-5.6,-6,-9.2,-12.9,-8.8,-21.5c0.3,-7.5,0.6,-15,-0.1,-22.5   c-1.2,-14.1,5.5,-23.9,16,-31.9c16.7,-12.8,36.1,-19.6,56.1,-25.1c23.8,-6.5,48,-10.2,72.5,-12.3C168.6,1.3,174,2.2,179,0   c19.3,0,38.7,0,58,0c6,2.1,12.4,1.3,18.6,1.8c30.2,2.7,59.9,7.6,88.5,17.5c16.5,5.7,32.6,12.6,45.2,25.4c6.5,6.6,10.3,14,9.8,23.6   c-0.4,7.8,-0.5,15.7,0,23.4c0.6,10.3,-3.4,18.4,-10.6,25.2c-2.2,2,-4.4,4,-6.6,6c-3,2,-6.1,4,-9.1,5.9c-9.2,4.5,-18.5,9,-28.2,12.3   c-42.4,14.5,-86.3,18.8,-130.8,19.6c-10.9,0.2,-21.9,-0.4,-32.9,-0.7c-4.6,-0.4,-9.2,-0.8,-13.9,-1.1c-18.9,-1.1,-37.5,-3.9,-56,-7.6   c-15.3,-3.1,-30.2,-7.6,-44.9,-12.6c-7.6,-3.7,-15.3,-7.4,-22.9,-11.1C41.1,125.8,38.6,124.3,36,122.9z M41,72c2.9,6.9,7.1,12.6,13.1,17.2   c13,10,27.9,15.8,43.4,20.6c28.2,8.8,57.2,12.8,86.5,14c31.8,1.2,63.7,0.8,95.3,-4.6c25.3,-4.4,50.1,-10,72.9,-22.2   c10.8,-5.8,20,-13.1,24.7,-24.9c2.3,-11,-2.3,-19.5,-10.2,-26.4c-10.5,-9.2,-23.1,-14.9,-36.2,-19.6C295.2,13.4,258.4,9.7,221.2,8.1   c-11.1,-0.5,-22.2,0,-33.4,0.6c-21.4,1,-42.6,3.1,-63.6,7.3c-22.2,4.5,-44.1,10.3,-63.4,22.6C48.9,46.3,38.4,55.4,41,72z"
+        android:fillColor="#9F9F9F"/>
+    <path
+        android:pathData="M0,829c3.7,-2.8,4.7,-7.6,7.8,-10.9c2.6,-2.8,4.9,-5.7,9.2,-7.6c0,3.4,-0.1,6.5,0,9.5c0,1.5,-0.7,3.5,1.7,4   c0.4,3.3,1.4,6.4,2.9,9.4c3.8,7.7,10,13,16.8,17.9c9.2,6.7,19.7,10.8,29.8,15.5c-0.7,2.4,1.3,0.7,1.8,1.1l0,0c1.5,2.1,3.7,2.2,6,2   l0,0c0.8,0.6,1.5,1.4,2.4,1.7c9.5,2.7,18.9,5.8,28.7,7.4c3.6,0.6,7,3.5,10.9,1.1c2.4,0.4,4.8,0.8,7.1,1.2c0.2,1.5,1.3,1.6,2.5,1.8   c6.6,0.9,13.3,2.4,19.9,2.8c5.1,0.3,10.3,2.9,15.4,0.3c0.4,0,0.8,0.1,1.1,0.1c0.3,2.2,2.1,1.8,3.5,1.8c3.8,0,7.6,0,11.5,0   c1.1,1.4,2.7,1,4.1,1c17.2,0,34.5,0,51.7,0c1.4,0,3,0.4,4.1,-1c3.8,0,7.6,0,11.5,0c1.4,0,3.2,0.4,3.5,-1.8c9.4,-1,18.7,-2.1,28.1,-3.1   c6,1.3,11.6,0.4,16.9,-2.8c21.2,-4.2,42.1,-9.3,61.8,-18.4c15.8,-7.3,30.8,-15.8,38,-33.1c2.4,-2,1.9,-4.8,2.2,-7.4c0.3,-3,0,-6,0.1,-9   c0,-1,-0.3,-2.1,0.7,-2.7c1.1,-0.7,1.7,0.5,2.5,1c7.2,5,12.1,11.7,14.8,20c0.4,1.2,0.6,2.2,2.1,2.3c0,3.3,0,6.7,0,10   c-1.5,0,-1.8,1.1,-2.2,2.2c-3.8,10.2,-11.2,17.5,-20.1,23.3c-20.8,13.6,-44.1,21.2,-68.1,26.7c-29.2,6.7,-58.7,11,-88.7,11.7   c-1.6,0,-3.5,-0.5,-3.9,2c-18.7,0,-37.3,0,-56,0c-0.3,-2.5,-2.3,-1.9,-3.9,-2c-5.6,-0.1,-11.2,-0.5,-16.9,-0.8c-18.5,-1.2,-36.8,-3.8,-55,-7.3   C79.9,893.9,54,887,30.2,874C19,867.9,8.5,860.9,2.5,849C2,848,1.4,847,0,847C0,841,0,835,0,829z"
+        android:fillColor="#E6E4E4"/>
+    <path
+        android:pathData="M372.9,128.9c3,-2,6.1,-4,9.1,-5.9c-0.2,2.7,0.2,5.4,1,8c-1.5,1.6,-0.3,1.8,1,2c0.3,1,0.7,2,1,3   c-1.5,1.6,-0.3,1.8,1,2c0.7,2,1.3,4,2,6c-1.5,1.6,-0.3,1.8,1,2c0.3,1.7,0.7,3.3,1,5c-1,2.3,-0.6,4.1,2,5c4.9,23.8,9,47.6,8,72   c-3.5,1.5,-2.1,3.8,-1,6c-1,6,-2,12,-3,18c-1.3,1,-1.3,2,0,3c0,0.7,0,1.3,0,2c-2.1,0.4,-2.6,1.3,-1,3c0,0.3,0,0.7,0,1   c-1.3,0.2,-2.5,0.4,-1,2c0.4,2.1,-0.7,4,-1,6c-1.3,0.2,-2.5,0.4,-1,2c-3.7,9.3,-7.3,18.7,-11,28c-2.7,1.2,-4.2,2.9,-3,6   c-3.4,6.9,-7.8,13.3,-12.2,19.5c-6.1,8.6,-12.4,17.3,-19.4,25.2c-7.3,8.3,-15.5,15.8,-23.9,23c-11.9,10.3,-24.9,19.3,-38.1,27.7   c-12.2,7.8,-25.4,14.1,-38.4,20.5c-12.1,6,-18.5,15.8,-21,28.6c-1.5,7.8,-0.5,15.4,2,22.8c1.2,3.5,3.7,6.1,5.6,9.2   c5.4,8.6,14.8,10.5,22.6,15c15.3,9,30.8,17.7,45.3,28.1c14.4,10.4,28.2,21.5,40.5,34.1c10.1,10.4,18.5,22.2,26.8,34.3   c6.5,9.5,11.3,19.6,16.1,29.8c-1.5,1.6,-0.3,1.8,1,2c0.7,2,1.3,4,2,6c-1,2.3,-0.6,4.1,2,5c0.7,1.2,1.2,2.5,1,4c-1,2.3,-0.6,4.1,2,5   c1.2,12.3,4.6,24.1,5.7,36.5c0.8,8.4,1.4,16.8,1,25.1c-0.3,5.9,-1.1,12,-1.9,18c-1.2,8.7,-2.3,17.4,-4.2,25.9   c-1.5,6.6,-3.7,13.1,-5.6,19.6c-1.8,3.1,-2.9,6.5,-3.9,9.9c-3.4,6.4,-5.6,13.6,-11.9,18.2c-0.1,-3.8,1.6,-7.1,3,-10.4   c8.7,-20.9,13,-42.8,14.7,-65.1c1,-12.9,0.2,-25.8,-1.7,-38.7c-2.7,-18.5,-7.8,-36.2,-15.8,-53.1c-7.3,-15.4,-16.8,-29.3,-27.7,-42.4   c-2.7,-3.2,-6.3,-5.7,-9.6,-8.6c0.4,0.8,0.7,1.4,1,1.9c0.7,1.1,1.5,2.2,2.3,3.3c16.5,21.5,28.5,45.2,34.2,71.7c0.7,3.3,3.1,6.9,0.3,10.4   c-1,-1.9,-2.1,-3.7,-3.1,-5.6c-3.3,-6.3,-6.1,-12.9,-11.7,-17.6c-0.4,-0.9,-0.8,-1.8,-1.3,-2.6c-4,-6.3,-10.4,-10.4,-14.8,-16.2c0,-5.4,-2.7,-9.9,-4.8,-14.5   c-8.4,-18.6,-20.4,-34.9,-32.9,-50.8c-8.4,-10.8,-15.5,-22.8,-28.7,-28.8c-5.3,-2.4,-10,-6,-15.1,-8.6c-5.1,-2.6,-9.9,-6.4,-16.3,-5.2   c-5.2,1,-10.4,2.1,-15.3,4.1c-29.3,11.9,-48.4,34.1,-61.8,61.9c-0.3,0.3,-0.7,0.6,-1,1c-7.1,0.8,-13.9,2.9,-20.7,5.1   c-32.6,10.6,-61,27.4,-82.3,54.9c-9.2,11.6,-15.4,24.7,-18.9,39c-1.5,-1.1,-1.1,-2.7,-1.1,-4.1c-0.1,-9.6,0.3,-19.2,1.8,-28.7   c3.7,-22.6,11.8,-43.5,24,-62.8c12.6,-20,28.6,-36.9,47,-51.7c21.3,-17.3,44.6,-31.3,69.3,-42.9c14.5,-6.8,20,-18.8,21.8,-33.1   c1.8,-13.3,-4.9,-24.1,-12.2,-34.4c-3.6,-5,-7.4,-9.8,-13.2,-12.5c-5.8,-2.8,-11.6,-5.7,-17.4,-8.7c-22,-11.6,-42.6,-25.1,-61.1,-41.7   c-20.7,-18.6,-37.9,-40,-48.8,-65.9c-6.7,-15.7,-10.9,-32.1,-12,-49c-1.8,-27.1,2.1,-53.6,11.7,-79.1c3.8,-10.1,7.1,-20.4,13.3,-29.4   c14.7,5,29.6,9.5,44.9,12.6c18.5,3.7,37.2,6.5,56,7.6c4.6,0.3,9.3,0.7,13.9,1.1c0.2,3.6,-1.5,6.8,-2.6,10   c-11.9,33.6,-17.8,68.2,-17.2,103.8c0.2,9.7,1.3,19.4,2.7,29.1c3.8,24.6,11.4,47.7,26,68.1c12.2,17.1,28.4,28.6,49,33.4   c4.7,1.1,9.5,2.2,14.5,-0.5c18.7,-10.2,36.8,-21.2,53.7,-34.2c15.4,-11.9,29.4,-25.3,41.5,-40.5c12.9,-16.2,23.4,-33.8,30.4,-53.4   c6.4,-17.6,10.3,-35.6,10.9,-54.3c0.5,-15.9,0.2,-31.9,-3,-47.6C383.8,158.7,380.1,143.3,372.9,128.9z"
+        android:fillColor="#EDECEC"/>
+    <path
+        android:pathData="M383,780c1.1,-3.4,2.1,-6.8,3.9,-9.9c7.8,7.1,12.8,15.2,12.2,26.4c-0.6,10.7,-0.3,21.5,-0.5,32.3   c-7.2,17.3,-22.2,25.8,-38,33.1c-19.7,9.1,-40.6,14.1,-61.8,18.4c-5.6,0.9,-11.3,1.9,-16.9,2.8c-9.4,1,-18.7,2.1,-28.1,3.1   c-5,0.3,-9.9,0.7,-14.9,1c-20,1.2,-40,0.9,-60,0c-5,-0.3,-9.9,-0.7,-14.9,-1c-0.4,0,-0.8,-0.1,-1.1,-0.1c-12.6,-1.6,-25.2,-3.2,-37.9,-4.8   c-2.4,-0.4,-4.8,-0.8,-7.1,-1.2c-2.6,-0.6,-5.1,-1.3,-7.7,-1.8c-11.6,-2,-22.6,-6.3,-34.2,-8.4c0,0,0,0,0,0c-1.7,-1.6,-3.7,-2.2,-6,-2c0,0,0,0,0,0   c-0.2,-1,-1.1,-0.9,-1.8,-1.1c-10.2,-4.7,-20.6,-8.8,-29.8,-15.5c-6.8,-4.9,-13,-10.2,-16.8,-17.9c-1.5,-3,-2.4,-6.1,-2.9,-9.4   c0.1,-10.3,0,-20.6,0.2,-30.9c0.1,-8.3,3.5,-15,10,-20.2c2,3.5,3.4,7.1,4.1,11c-1.1,0.8,-1,2,-1.1,3.1c-0.6,8.2,2.9,14.9,8.3,20.6   c8.9,9.6,20.4,15.4,32.3,20.2c17.9,7.2,36.5,11.9,55.4,15.4c20.1,3.7,40.3,5.7,60.6,6.5c21.4,0.8,42.8,0.4,64.2,-1.6   c19.8,-1.9,39.4,-4.6,58.7,-9.3c19.9,-4.8,39.3,-11.2,56.4,-22.9c7.8,-5.3,15.2,-11.3,17.4,-21C386.4,790.1,388.3,784.3,383,780z"
+        android:fillColor="#9F9F9F"/>
+    <path
+        android:pathData="M378,305c-1.2,-3.1,0.3,-4.8,3,-6C380.6,301.3,379.7,303.3,378,305z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M399,234c-1.1,-2.2,-2.5,-4.5,1,-6C399.7,230,400.8,232.2,399,234z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M392,156c-2.6,-0.9,-3,-2.7,-2,-5C391.4,152.4,391.6,154.2,392,156z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M389,636c-2.6,-0.9,-3,-2.7,-2,-5C388.4,632.4,388.6,634.2,389,636z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M392,645c-2.6,-0.9,-3,-2.7,-2,-5C391.4,641.4,391.6,643.2,392,645z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M396,255c-1.3,-1,-1.3,-2,0,-3C397.3,253,397.3,254,396,255z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M395,260c-1.6,-1.7,-1.1,-2.6,1,-3C395.7,258,395.3,259,395,260z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M384,133c-1.3,-0.2,-2.5,-0.4,-1,-2C383.8,131.4,384,132.2,384,133z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M385,625c-1.3,-0.2,-2.5,-0.4,-1,-2C384.8,623.4,385,624.2,385,625z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M392,271c-1.5,-1.6,-0.3,-1.8,1,-2C393,269.8,392.8,270.6,392,271z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M394,263c-1.5,-1.6,-0.3,-1.8,1,-2C395,261.8,394.8,262.6,394,263z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M386,138c-1.3,-0.2,-2.5,-0.4,-1,-2C385.8,136.4,386,137.2,386,138z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M389,146c-1.3,-0.2,-2.5,-0.4,-1,-2C388.8,144.4,389,145.2,389,146z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M33.1,783.9c-0.8,-3.9,-2.2,-7.6,-4.1,-11c-3.7,-11.7,-7.2,-23.5,-9.2,-35.5c-1.3,-7.6,-1.9,-15.4,-2.7,-23.2   c-0.6,-6.2,-0.9,-12.4,-1,-18.5c-0.2,-7.9,1.9,-15.7,2.3,-23.4c0.5,-10.1,2.9,-19.5,5.5,-29c6.3,-23.1,17.3,-43.9,31.5,-62.8   c23.4,-31.1,53.3,-54.7,86.9,-74.1c10.1,-5.8,20.3,-11.6,30.9,-16.2c11.7,-5.2,16.3,-14.9,18.8,-26.3c3.2,-14.9,-2.8,-26.6,-12.7,-37.1   c-1.8,-1.9,-3.9,-3.1,-6.2,-4.2c-23.7,-11.4,-46.4,-24.4,-67.2,-40.7c-16.2,-12.6,-31.3,-26.5,-44.2,-42.6c-16.2,-20.3,-28.8,-42.5,-36.2,-67.5   c-3.1,-10.6,-5.4,-21.3,-6.2,-32.4c-0.7,-9.6,-3.2,-19.3,-2,-28.8c0.8,-6.6,1.5,-13.4,1.9,-20c1,-15.2,4.9,-29.6,9.2,-44c1.7,-5.7,4,-11.3,6.4,-16.8   c0.9,-2.2,1.3,-4.4,1.3,-6.8c2.6,1.4,5.1,2.9,7.2,4.9c-0.6,0.8,-1.4,1.4,-1.8,2.3c-11.2,26.2,-16.2,53.8,-17.4,82.2   c-0.4,8.8,1,17.5,1.9,26.2c2,19.7,7.4,38.4,15.6,56.3c17.9,39.2,46.6,69.1,81.3,93.6c18.5,13.1,38.1,24.3,58.5,34.1   c3.3,1.6,6,3.7,8.1,6.5c8,10.6,12.6,22.1,9.6,35.7c-2.1,9.4,-6.5,17.9,-14.8,22.7c-8.2,4.7,-16.9,8.5,-25.3,12.9   c-22.5,12,-43.8,25.8,-62.6,43c-21.9,19.9,-40.8,42.1,-53.7,69.2C26.3,646.5,20.6,682,24.1,719c1.8,18.7,7,36.7,12.7,54.6   c5.9,18.7,18.2,30.9,35.3,38.9c15.4,7.2,31.5,12.2,48.1,15.8c1.6,0.4,4.3,-0.3,4.8,2.6c-18,-2.8,-35.4,-7.5,-52.3,-14.5   c-12.2,-5.1,-23.4,-11.4,-32.4,-21.4C37.2,791.7,36.5,787,33.1,783.9z"
+        android:fillColor="#EDECEC"/>
+    <path
+        android:pathData="M372.9,128.9c7.2,14.3,10.9,29.8,14.1,45.4c3.2,15.7,3.5,31.6,3,47.6c-0.6,18.7,-4.6,36.7,-10.9,54.3   c-7.1,19.6,-17.6,37.2,-30.4,53.4c-12.1,15.2,-26.1,28.6,-41.5,40.5c-16.9,13,-35,24,-53.7,34.2c-5,2.7,-9.8,1.6,-14.5,0.5   c-20.6,-4.8,-36.8,-16.3,-49,-33.4c-14.6,-20.4,-22.3,-43.5,-26,-68.1c-1.5,-9.7,-2.6,-19.4,-2.7,-29.1c-0.6,-35.6,5.4,-70.2,17.2,-103.8   c1.2,-3.3,2.8,-6.4,2.6,-10c11,0.2,21.9,0.9,32.9,0.7c44.4,-0.8,88.4,-5.2,130.8,-19.6C354.4,137.9,363.7,133.5,372.9,128.9z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M377,72c-4.6,11.9,-13.9,19.1,-24.7,24.9c-22.9,12.2,-47.6,17.9,-72.9,22.2c-31.6,5.4,-63.5,5.9,-95.3,4.6   c-29.3,-1.1,-58.3,-5.1,-86.5,-14C82.1,105,67.2,99.1,54.2,89.2C48.2,84.6,43.9,78.8,41,72c3.9,-1.8,4.6,-6.2,7.3,-9   c10.3,-10.5,22.9,-16.9,36.5,-21.8c19.7,-7.1,40,-11.5,60.7,-14.5c19.4,-2.8,38.9,-3.9,58.4,-4.5c17.9,-0.6,35.8,0.8,53.6,2.8   c15,1.6,29.9,3.5,44.5,7.1c20,4.9,39.7,10.7,57.2,22.1C366.5,58.8,371.5,65.5,377,72z"
+        android:fillColor="#8D8E8E"/>
+    <path
+        android:pathData="M125,831c-0.4,-2.9,-3.2,-2.3,-4.8,-2.6c-16.6,-3.7,-32.7,-8.7,-48.1,-15.8c-17.1,-8,-29.4,-20.2,-35.3,-38.9   c-5.7,-17.9,-10.9,-35.9,-12.7,-54.6c-3.6,-37.1,2.1,-72.5,18.4,-106.4c13,-27.1,31.9,-49.3,53.7,-69.2c18.8,-17.1,40.2,-30.9,62.6,-43   c8.4,-4.5,17.1,-8.2,25.3,-12.9c8.4,-4.8,12.7,-13.3,14.8,-22.7c3.1,-13.6,-1.6,-25.1,-9.6,-35.7c-2.1,-2.8,-4.8,-4.9,-8.1,-6.5   c-20.4,-9.9,-40,-21.1,-58.5,-34.1c-34.7,-24.6,-63.4,-54.5,-81.3,-93.6c-8.2,-17.9,-13.6,-36.6,-15.6,-56.3c-0.9,-8.7,-2.3,-17.5,-1.9,-26.2   c1.2,-28.3,6.2,-55.9,17.4,-82.2c0.4,-0.9,1.2,-1.5,1.8,-2.3c7.6,3.7,15.3,7.4,22.9,11.1c-6.2,9,-9.5,19.3,-13.3,29.4   c-9.6,25.5,-13.5,52,-11.7,79.1c1.1,16.9,5.4,33.3,12,49c11,25.9,28.1,47.4,48.8,65.9c18.5,16.6,39.1,30.2,61.1,41.7   c5.7,3,11.5,5.9,17.4,8.7c5.8,2.8,9.7,7.6,13.2,12.5c7.3,10.3,14,21.1,12.2,34.4c-1.9,14.3,-7.4,26.3,-21.8,33.1   c-24.7,11.6,-48,25.7,-69.3,42.9c-18.3,14.9,-34.3,31.7,-47,51.7c-12.2,19.3,-20.3,40.2,-24,62.8c-1.6,9.6,-2,19.1,-1.8,28.7   c0,1.4,-0.4,3.1,1.1,4.1c-0.6,14.9,0.1,29.8,3,44.5c4.2,21.4,9.1,42.6,26,58.4c-0.2,2.3,0.9,4.1,2.2,5.9c8.8,12.3,22,18.6,35.3,24.1   c26.4,10.9,54.2,16.1,82.4,19.1c1.7,0.2,3,0.4,3,2.4c-4.5,0.7,-9,0.9,-13.4,0.5c-13.2,-1,-26.5,-1.9,-39.6,-4.1c-0.6,-2.4,-1.7,-2.3,-3.1,-0.6   c-1.3,-0.1,-2.6,-0.3,-3.9,-0.4c-0.6,-2.3,-1.6,-2.4,-3.1,-0.7c-0.6,-0.1,-1.3,-0.2,-1.9,-0.3c-0.6,-2.4,-1.7,-2.4,-3.1,-0.6   C126.2,831.2,125.6,831.1,125,831z"
+        android:fillColor="#E8E8E7"/>
+    <path
+        android:pathData="M377,72c-5.4,-6.4,-10.5,-13.2,-17.7,-17.9C341.7,42.7,322.1,36.9,302,32c-14.6,-3.6,-29.5,-5.5,-44.5,-7.1   c-17.8,-1.9,-35.7,-3.3,-53.6,-2.8c-19.5,0.6,-39,1.7,-58.4,4.5c-20.7,3,-41,7.4,-60.7,14.5C71.3,46.1,58.7,52.4,48.4,63   c-2.7,2.8,-3.5,7.2,-7.3,9c-2.6,-16.6,7.9,-25.6,19.8,-33.3c19.3,-12.3,41.2,-18.2,63.4,-22.6c21,-4.2,42.2,-6.3,63.6,-7.3   c11.1,-0.5,22.3,-1,33.4,-0.6c37.2,1.5,74,5.3,109.4,17.9c13.1,4.6,25.6,10.4,36.2,19.6C374.7,52.5,379.3,61,377,72z"
+        android:fillColor="#808080"/>
+    <path
+        android:pathData="M179,887.2c20,0.9,40,1.2,60,0c0,0.3,0,0.5,0,0.8c-1.1,1.4,-2.7,1,-4.1,1c-17.2,0,-34.5,0,-51.7,0   c-1.4,0,-3,0.4,-4.1,-1C179,887.7,179,887.5,179,887.2z"
+        android:fillColor="#F4F3F2"/>
+    <path
+        android:pathData="M76,869.9c11.6,2.2,22.6,6.5,34.2,8.4c2.6,0.4,5.2,1.2,7.7,1.8c-3.9,2.3,-7.3,-0.6,-10.9,-1.1   c-9.8,-1.6,-19.2,-4.7,-28.7,-7.4C77.5,871.3,76.8,870.5,76,869.9z"
+        android:fillColor="#F4F3F2"/>
+    <path
+        android:pathData="M125.1,881.3c12.6,1.6,25.2,3.2,37.9,4.8c-5.2,2.6,-10.3,0,-15.4,-0.3c-6.7,-0.4,-13.3,-1.9,-19.9,-2.8   C126.3,882.9,125.2,882.8,125.1,881.3z"
+        android:fillColor="#F4F3F2"/>
+    <path
+        android:pathData="M282,883.1c5.6,-0.9,11.3,-1.9,16.9,-2.8C293.7,883.4,288.1,884.4,282,883.1z"
+        android:fillColor="#F4F3F2"/>
+    <path
+        android:pathData="M179,887.2c0,0.3,0,0.5,0,0.8c-3.8,0,-7.6,0,-11.5,0c-1.4,0,-3.2,0.4,-3.5,-1.8C169,886.5,174,886.9,179,887.2z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M239,888c0,-0.3,0,-0.5,0,-0.8c5,-0.3,9.9,-0.7,14.9,-1c-0.3,2.2,-2.1,1.8,-3.5,1.8C246.6,888,242.8,888,239,888z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M70,867.9c2.3,-0.2,4.3,0.4,6,2C73.8,870.1,71.6,870,70,867.9z"
+        android:fillColor="#F4F3F2"/>
+    <path
+        android:pathData="M68.2,866.8c0.7,0.2,1.6,0.2,1.8,1.1C69.5,867.4,67.6,869.2,68.2,866.8z"
+        android:fillColor="#F4F3F2"/>
+    <path
+        android:pathData="M165,584c0.3,-0.3,0.7,-0.6,1,-1c10.5,-1.3,21,-3.3,31.5,-3.8c20.8,-1.1,41.4,0.7,61.7,5.4   c30.5,7,57.8,20.3,81.8,40.5c4.4,5.9,10.8,10,14.8,16.2c0.5,0.8,0.9,1.7,1.3,2.6c-2.4,4.1,-4.7,8.1,-7.1,12.2c-4,3.7,-6.3,8.9,-11,12   c-1.6,-0.1,-2.8,0.5,-4.1,1.5c-12.6,9.3,-26.7,15.6,-41.5,20.1c-31,9.4,-62.6,13.3,-95.1,11.6c-12.3,-0.6,-24.5,-1.5,-36.5,-3.4   c-4.5,-0.7,-5.3,0.5,-4.8,4.2c-0.5,0,-1,0.1,-1.5,0c-17.8,-3.9,-34.7,-10.3,-50.9,-18.7c-1,-0.5,-1.6,-1.1,-1.6,-2.3c2.3,-0.3,4.1,1.1,6.1,2   c14.2,6.2,28.9,10.6,44.1,13.3c2.5,0.4,3,0.2,2.4,-2.3c-2.5,-9.3,-3.7,-18.7,-4.8,-28.3c-1.5,-13.7,-0.3,-27.1,1.7,-40.5   C154.6,610.8,159.7,597.4,165,584z"
+        android:fillColor="#E57474"/>
+    <path
+        android:pathData="M103,681c0.1,1.1,0.7,1.8,1.6,2.3c16.2,8.4,33.1,14.8,50.9,18.7c0.5,0.1,1,0,1.5,0c0.6,0.4,1.3,0.7,1.9,1.1   c-0.1,2.7,1,5.2,1.9,7.6c6.5,17.8,16.5,33.6,27.5,48.8c12.5,17.1,27.1,32.1,45.1,43.6c6.6,4.2,13.7,7.3,20.5,11   c-15.6,2.8,-31.4,2.5,-47.1,2.4c-9.9,0,-19.9,-0.2,-29.8,-1.1c-18.2,-1.6,-36.2,-3.9,-54,-8.3c-18.1,-4.4,-35.9,-9.5,-51,-21.1   c-16.9,-15.8,-21.8,-37,-26,-58.4c-2.9,-14.7,-3.6,-29.6,-3,-44.5c3.5,-14.4,9.7,-27.4,18.9,-39c3.4,4.8,6.2,10.1,10.3,14.2   c6,6.1,11.6,13,19.7,16.8c0.5,0.8,1.2,1,2.1,1c0,0,0,0,0,0c0.3,0.3,0.7,0.7,1,1c0,0,0,0,0,0c0.3,0.3,0.7,0.7,1,1l0,0   c1,1.3,2.4,1.8,4,2l0,0C100.7,681.2,101.9,681,103,681L103,681z"
+        android:fillColor="#E6A3A3"/>
+    <path
+        android:pathData="M341,625c-24,-20.1,-51.3,-33.5,-81.8,-40.5c-20.3,-4.7,-41,-6.5,-61.7,-5.4c-10.5,0.6,-21,2.5,-31.5,3.8   c13.4,-27.8,32.5,-49.9,61.8,-61.9c4.9,-2,10.1,-3.1,15.3,-4.1c6.3,-1.2,11.2,2.6,16.3,5.2c5.2,2.6,9.9,6.2,15.1,8.6   c13.3,6,20.3,18,28.7,28.8c12.5,16,24.6,32.2,32.9,50.8C338.3,615.2,341,619.7,341,625z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M91.9,675c-8,-3.8,-13.6,-10.7,-19.7,-16.8c-4.1,-4.1,-6.9,-9.4,-10.3,-14.2c21.3,-27.5,49.8,-44.3,82.3,-54.9   c6.8,-2.2,13.6,-4.3,20.7,-5.1c-5.3,13.4,-10.4,26.9,-12.5,41.2c-2,13.4,-3.2,26.8,-1.7,40.5c1.1,9.6,2.3,19,4.8,28.3   c0.7,2.5,0.1,2.7,-2.4,2.3c-15.2,-2.6,-29.9,-7.1,-44.1,-13.3c-2,-0.9,-3.7,-2.3,-6.1,-2c0,0,0,0,0,0c-0.7,-1.2,-1.9,-1,-3,-1c0,0,0,0,0,0   c-0.3,-2.7,-2.4,-1.8,-4,-2c0,0,0,0,0,0c-0.3,-0.3,-0.7,-0.7,-1,-1c0,0,0,0,0,0c-0.3,-0.3,-0.7,-0.7,-1,-1c0,0,0,0,0,0   C93.6,675.2,92.8,675,91.9,675z"
+        android:fillColor="#D86868"/>
+    <path
+        android:pathData="M135,832.8c1.3,0.1,2.6,0.3,3.9,0.4c0.9,0.8,2,0.7,3.1,0.6c13.1,2.2,26.4,3,39.6,4.1   c4.5,0.3,9,0.2,13.4,-0.5c3.1,0.3,6.3,0.7,9.4,0.8c22.6,0.4,45.2,-0.9,67.6,-4.1c23.9,-3.3,47.4,-8.2,69.8,-17.6   c10.7,-4.5,21.4,-9.3,29.3,-18.3l0,0.1c6.2,-4.6,8.5,-11.8,11.9,-18.2c5.2,4.3,3.3,10.1,2.2,15c-2.2,9.7,-9.6,15.7,-17.4,21   c-17.1,11.7,-36.5,18.1,-56.4,22.9c-19.3,4.7,-38.9,7.4,-58.7,9.3c-21.4,2,-42.8,2.5,-64.2,1.6c-20.3,-0.8,-40.5,-2.8,-60.6,-6.5   c-19,-3.5,-37.6,-8.2,-55.4,-15.4c-11.9,-4.8,-23.4,-10.6,-32.3,-20.2c-5.3,-5.8,-8.9,-12.4,-8.3,-20.6c0.1,-1.2,0,-2.4,1.1,-3.1   c3.3,3.1,4.1,7.8,7.2,11.1c9,9.9,20.2,16.3,32.4,21.4c16.8,7,34.3,11.7,52.3,14.5c0.6,0.1,1.2,0.2,1.9,0.3c0.9,0.8,2,0.7,3.1,0.6   c0.6,0.1,1.3,0.2,1.9,0.3C132.8,833,133.9,833,135,832.8z"
+        android:fillColor="#999899"/>
+    <path
+        android:pathData="M371.9,667c2.8,-3.5,0.4,-7.1,-0.3,-10.4c-5.7,-26.6,-17.7,-50.3,-34.2,-71.7c-0.8,-1,-1.5,-2.2,-2.3,-3.3   c-0.3,-0.5,-0.6,-1.1,-1,-1.9c3.4,3,6.9,5.4,9.6,8.6c10.8,13.1,20.4,27,27.7,42.4c8,16.9,13.1,34.6,15.8,53.1   c1.9,12.9,2.6,25.8,1.7,38.7c-1.7,22.4,-6,44.3,-14.7,65.1c-1.4,3.3,-3.1,6.6,-3,10.4c0,0,0,-0.1,0,-0.1c-1.8,-0.3,-3.3,0.4,-4.7,1.2   c-6.3,3.7,-12.6,7.3,-19.4,10.2c-24,10.3,-48.8,14.5,-74.7,9.2c-4.2,-0.9,-9.4,-0.2,-12.4,-4.8c13.8,-2,27.6,-4.4,41.1,-8   c10,-2.7,20,-5.4,29,-10.8c1.5,-0.5,3.2,-0.9,4.6,-1.6c10.6,-5.1,19.5,-12.1,25.3,-22.6c4.7,-3.1,8.2,-10.7,6.9,-15c0.3,-1.4,0.6,-2.9,1,-4.3   c5.4,-16.2,7.5,-33.1,9,-50C378,689.7,375.5,678.3,371.9,667z"
+        android:fillColor="#F1F0F0"/>
+    <path
+        android:pathData="M371.9,667c3.6,11.3,6.1,22.7,5.1,34.6c-1.5,16.9,-3.6,33.8,-9,50c-0.5,1.4,-0.7,2.9,-1,4.3   c-2.3,5,-4.6,10,-6.9,15c-5.8,10.5,-14.7,17.5,-25.3,22.6c-1.5,0.7,-3.1,1.1,-4.6,1.6c-0.3,-2.1,0.3,-3.9,1.1,-5.7   c3.4,-7.4,6.4,-14.9,8.9,-22.6c6,-18.1,10,-36.5,12,-55.6c1.2,-11.6,0.9,-23.2,0.6,-34.8c-0.2,-6.8,-0.7,-13.8,-2.8,-20.5   c2.4,-4.1,4.7,-8.1,7.1,-12.2c5.6,4.7,8.4,11.3,11.7,17.6C369.8,663.3,370.8,665.2,371.9,667z"
+        android:fillColor="#E6A3A3"/>
+    <path
+        android:pathData="M260,814c2.9,4.6,8.1,3.9,12.4,4.8c25.9,5.3,50.7,1.1,74.7,-9.2c6.7,-2.9,13.1,-6.4,19.4,-10.2   c1.4,-0.9,2.9,-1.6,4.7,-1.2c-7.9,9.1,-18.6,13.8,-29.3,18.3c-22.3,9.4,-45.9,14.3,-69.8,17.6c-22.4,3.1,-45,4.4,-67.6,4.1   c-3.1,-0.1,-6.3,-0.5,-9.4,-0.8c-0.1,-2,-1.4,-2.2,-3,-2.4c-28.3,-3,-56,-8.2,-82.4,-19.1c-13.4,-5.5,-26.5,-11.8,-35.3,-24.1c-1.3,-1.8,-2.4,-3.6,-2.2,-5.9   c15.1,11.6,32.9,16.7,51,21.1c17.7,4.4,35.8,6.6,54,8.3c10,0.9,20,1.1,29.8,1.1c15.7,0.1,31.5,0.4,47.1,-2.4   C256,814,258,814,260,814z"
+        android:fillColor="#EDECEC"/>
+    <path
+        android:pathData="M130,831.9c-1.1,0.1,-2.2,0.2,-3.1,-0.6C128.3,829.5,129.4,829.5,130,831.9z"
+        android:fillColor="#EDECEC"/>
+    <path
+        android:pathData="M135,832.8c-1.1,0.1,-2.2,0.2,-3.1,-0.7C133.4,830.5,134.4,830.6,135,832.8z"
+        android:fillColor="#EDECEC"/>
+    <path
+        android:pathData="M142,833.8c-1.1,0.1,-2.2,0.2,-3.1,-0.6C140.3,831.5,141.4,831.5,142,833.8z"
+        android:fillColor="#EDECEC"/>
+    <path
+        android:pathData="M260,814c-2,0,-4,0,-6,0c-6.8,-3.7,-13.9,-6.8,-20.5,-11c-18,-11.5,-32.7,-26.4,-45.1,-43.6c-11,-15.2,-21,-31,-27.5,-48.8   c-0.9,-2.5,-2,-4.9,-1.9,-7.7c0.7,0,1.4,-0.1,2,0.1c16.2,4.6,33.1,5.3,49.6,5.3c10,0,20.1,-0.2,30.2,-1.3c19.5,-2,38.7,-5.3,57,-12.4   c15.6,-6,30.1,-13.9,41.3,-26.9c4.7,-3.1,7,-8.3,11,-12c2.1,6.7,2.6,13.7,2.8,20.5c0.3,11.6,0.6,23.1,-0.6,34.8c-2,19,-6,37.5,-12,55.6   c-2.6,7.7,-5.5,15.3,-8.9,22.6c-0.9,1.9,-1.5,3.7,-1.1,5.7c-9,5.4,-19,8.1,-29,10.8C287.6,809.6,273.8,811.9,260,814z"
+        android:fillColor="#E6A3A3"/>
+    <path
+        android:pathData="M339,668c-11.1,13,-25.7,20.8,-41.3,26.9c-18.3,7.1,-37.5,10.4,-57,12.4c-10.1,1,-20.3,1.3,-30.2,1.3   c-16.6,0,-33.4,-0.7,-49.6,-5.3c-0.6,-0.2,-1.3,-0.1,-2,-0.1c-0.6,-0.4,-1.3,-0.7,-1.9,-1.1c-0.4,-3.8,0.3,-5,4.8,-4.2c12.1,2,24.3,2.8,36.5,3.4   c32.4,1.7,64.1,-2.3,95.1,-11.6c14.8,-4.5,29,-10.8,41.5,-20.1C336.3,668.5,337.5,667.9,339,668z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M96,678c1.6,0.2,3.7,-0.7,4,2C98.4,679.8,97,679.3,96,678z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M100,680c1.1,0,2.3,-0.2,3,1C101.9,681,100.7,681.2,100,680z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M91.9,675c0.8,0,1.6,0.2,2.1,1C93.2,676,92.4,675.8,91.9,675z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M94,676c0.3,0.3,0.7,0.7,1,1C94.7,676.7,94.3,676.3,94,676z"
+        android:fillColor="#FFFFFF"/>
+    <path
+        android:pathData="M95,677c0.3,0.3,0.7,0.7,1,1C95.7,677.7,95.3,677.3,95,677z"
+        android:fillColor="#C5C5C5"/>
+    <path
+        android:pathData="M360,771c2.3,-5,4.6,-10,6.9,-15C368.2,760.3,364.7,767.8,360,771z"
+        android:fillColor="#EDECEC"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_action_clear.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_action_clear.xml
new file mode 100644
index 000000000..6b12b0d61
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_action_clear.xml
@@ -0,0 +1,25 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24.0"
+    android:viewportHeight="24.0"
+    android:tint="?android:attr/colorControlNormal" >
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_action_open.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_action_open.xml
new file mode 100644
index 000000000..96d4ce250
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_action_open.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24.0"
+    android:viewportHeight="24.0">
+  <path
+      android:fillColor="#FF737373"
+      android:pathData="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_advanced_shortcut.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_advanced_shortcut.xml
new file mode 100644
index 000000000..23b1be846
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_advanced_shortcut.xml
@@ -0,0 +1,33 @@
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
+
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+    <background android:drawable="@color/shortcut_background" />
+    <foreground>
+        <inset android:inset="33%">
+            <vector
+                android:width="24dp"
+                android:height="24dp"
+                android:viewportWidth="24.0"
+                android:viewportHeight="24.0">
+                <path
+                    android:fillColor="@color/shortcut_foreground"
+                    android:pathData="M17 1.01L7 1c-1.1 0,-2 .9,-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2,-.9 2,-2V3c0,-1.1,-.9,-1.99,-2,-1.99zM17 19H7V5h10v14z"/>
+            </vector>
+        </inset>
+    </foreground>
+</adaptive-icon>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_arrow_back.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_arrow_back.xml
new file mode 100644
index 000000000..1a9993033
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_arrow_back.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2019, The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="?android:colorControlNormal"
+        android:pathData="M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_arrow_upward.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_arrow_upward.xml
new file mode 100644
index 000000000..96fa93ade
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_arrow_upward.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+
+    <path
+        android:pathData="M0 0h24v24H0V0z" />
+    <path
+        android:fillColor="?android:textColorSecondary"
+        android:pathData="M4 12l1.41 1.41L11 7.83V20h2V7.83l5.58 5.59L20 12l-8-8-8 8z" />
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_breadcrumb_arrow.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_breadcrumb_arrow.xml
new file mode 100644
index 000000000..5305b4ae3
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_breadcrumb_arrow.xml
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:autoMirrored="true"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M10,6L8.59,7.41 13.17,12l-4.58,4.59L10,18l6,-6 -6,-6z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_briefcase.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_briefcase.xml
new file mode 100644
index 000000000..8fc7d4a44
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_briefcase.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+  <path
+      android:fillColor="?android:attr/colorAccent"
+      android:pathData="M20,6h-4L16,4c0,-1.11 -0.89,-2 -2,-2h-4c-1.11,0 -2,0.89 -2,2v2L4,6c-1.11,0 -1.99,0.89 -1.99,2L2,19c0,1.11 0.89,2 2,2h16c1.11,0 2,-0.89 2,-2L22,8c0,-1.11 -0.89,-2 -2,-2zM12,15c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2zM14,6h-4L10,4h4v2z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_briefcase_white.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_briefcase_white.xml
new file mode 100644
index 000000000..7fb9b3c8a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_briefcase_white.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M20,6h-4L16,4c0,-1.11 -0.89,-2 -2,-2h-4c-1.11,0 -2,0.89 -2,2v2L4,6c-1.11,0 -1.99,0.89 -1.99,2L2,19c0,1.11 0.89,2 2,2h16c1.11,0 2,-0.89 2,-2L22,8c0,-1.11 -0.89,-2 -2,-2zM12,15c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2zM14,6h-4L10,4h4v2z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_cab_cancel.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_cab_cancel.xml
new file mode 100644
index 000000000..ded7fd678
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_cab_cancel.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="#FF000000"
+        android:pathData="M19,6.41L17.59,5 12,10.59 6.41,5 5,6.41 10.59,12 5,17.59 6.41,19 12,13.41 17.59,19 19,17.59 13.41,12 19,6.41z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_check.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_check.xml
new file mode 100644
index 000000000..445d9969d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_check.xml
@@ -0,0 +1,25 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0"
+        android:tint="@color/search_chip_text_selected_color">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="vM9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_check_circle.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_check_circle.xml
new file mode 100644
index 000000000..88b784183
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_check_circle.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="?android:attr/colorAccent"
+        android:pathData="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10,-4.48 10,-10S17.52 2 12 2zm-2 15l-5,-5 1.41,-1.41L10 14.17l7.59,-7.59L19 8l-9 9z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_chip_from_this_week.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_chip_from_this_week.xml
new file mode 100644
index 000000000..dca3b19a0
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_chip_from_this_week.xml
@@ -0,0 +1,25 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M13,3c-4.97,0 -9,4.03 -9,9L1,12l4,3.99L9,12L6,12c0,-3.87 3.13,-7 7,-7s7,3.13 7,7 -3.13,7 -7,7c-1.93,0 -3.68,-0.79 -4.94,-2.06l-1.42,1.42C8.27,19.99 10.51,21 13,21c4.97,0 9,-4.03 9,-9s-4.03,-9 -9,-9zM12,8v5l4.25,2.52 0.77,-1.28 -3.52,-2.09L13.5,8z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_chip_large_files.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_chip_large_files.xml
new file mode 100644
index 000000000..d0fe55090
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_chip_large_files.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M21.41,11.58l-9,-9C12.05,2.22 11.55,2 11,2H4c-1.1,0 -2,0.9 -2,2v7c0,0.55 0.22,1.05 0.59,1.42l9,9c0.36,0.36 0.86,0.58 1.41,0.58s1.05,-0.22 1.41,-0.59l7,-7c0.37,-0.36 0.59,-0.86 0.59,-1.41s-0.23,-1.06 -0.59,-1.42zM13,20.01L4,11V4h7v-0.01l9,9 -7,7.02zM8,6.5C8,7.33 7.33,8 6.5,8S5,7.33 5,6.5 5.67,5 6.5,5 8,5.67 8,6.5z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_create_new_folder.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_create_new_folder.xml
new file mode 100644
index 000000000..cdd126a4a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_create_new_folder.xml
@@ -0,0 +1,28 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24.0"
+    android:viewportHeight="24.0"
+    android:tint="?attr/colorControlNormal">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M12 12h2v-2h2v2h2v2h-2v2h-2v-2h-2v-2zm10-4v10c0 1.1-0.9 2-2 2H4c-1.1 0-2-0.9-2-2l0.01-12c0-1.1 0.89 -2 1.99-2h6l2 2h8c1.1 0 2 0.9 2 2zm-2 0H4v10h16V8z" />
+    <path
+        android:pathData="M0 0h24v24H0V0z" />
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_debug_menu.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_debug_menu.xml
new file mode 100644
index 000000000..c0e884b47
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_debug_menu.xml
@@ -0,0 +1,24 @@
+<!--
+ Copyright 2024 The Android Open Source Project
+
+ Licensed under the Apache License, Version 2.0 (the "License");
+ you may not use this file except in compliance with the License.
+ You may obtain a copy of the License at
+
+      http://www.apache.org/licenses/LICENSE-2.0
+
+ Unless required by applicable law or agreed to in writing, software
+ distributed under the License is distributed on an "AS IS" BASIS,
+ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ See the License for the specific language governing permissions and
+ limitations under the License.
+-->
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="960"
+        android:viewportHeight="960">
+    <path android:fillColor="?android:attr/colorControlNormal"
+          android:pathData="M 180 460 C 152 460 128.334 450.333 109 431 C 89.667 411.667 80 388 80 360 C 80 332 89.667 308.333 109 289 C 128.334 269.667 152 260 180 260 C 208 260 231.667 269.667 251 289 C 270.334 308.333 280 332 280 360 C 280 388 270.334 411.667 251 431 C 231.667 450.333 208 460 180 460 Z M 360 300 C 332 300 308.334 290.333 289 271 C 269.667 251.667 260 228 260 200 C 260 172 269.667 148.333 289 129 C 308.334 109.667 332 100 360 100 C 388 100 411.667 109.667 431 129 C 450.334 148.333 460 172 460 200 C 460 228 450.334 251.667 431 271 C 411.667 290.333 388 300 360 300 Z M 600 300 C 572 300 548.334 290.333 529 271 C 509.667 251.667 500 228 500 200 C 500 172 509.667 148.333 529 129 C 548.334 109.667 572 100 600 100 C 628 100 651.667 109.667 671 129 C 690.334 148.333 700 172 700 200 C 700 228 690.334 251.667 671 271 C 651.667 290.333 628 300 600 300 Z M 780 460 C 752 460 728.334 450.333 709 431 C 689.667 411.667 680 388 680 360 C 680 332 689.667 308.333 709 289 C 728.334 269.667 752 260 780 260 C 808 260 831.667 269.667 851 289 C 870.334 308.333 880 332 880 360 C 880 388 870.334 411.667 851 431 C 831.667 450.333 808 460 780 460 Z M 266 860 C 236 860 210.834 848.5 190.5 825.5 C 170.167 802.5 160 775.333 160 744 C 160 709.333 171.834 679 195.5 653 C 219.167 627 242.667 601.333 266 576 C 285.334 555.333 302 532.833 316 508.5 C 330 484.167 346.667 461.333 366 440 C 380.667 422.667 397.667 408.333 417 397 C 436.334 385.667 457.334 380 480 380 C 502.667 380 523.667 385.333 543 396 C 562.334 406.667 579.334 420.667 594 438 C 612.667 459.333 629.167 482.333 643.5 507 C 657.834 531.667 674.667 554.667 694 576 C 717.334 601.333 740.834 627 764.5 653 C 788.167 679 800 709.333 800 744 C 800 775.333 789.834 802.5 769.5 825.5 C 749.167 848.5 724 860 694 860 C 658 860 622.334 857 587 851 C 551.667 845 516 842 480 842 C 444 842 408.334 845 373 851 C 337.667 857 302 860 266 860 Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_dialog_alert.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_dialog_alert.xml
new file mode 100644
index 000000000..e31cff30a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_dialog_alert.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M1,21h22L12,2 1,21zM13,18h-2v-2h2v2zM13,14h-2v-4h2v4z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_dialog_info.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_dialog_info.xml
new file mode 100644
index 000000000..dface66f6
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_dialog_info.xml
@@ -0,0 +1,28 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0"
+        android:tint="?android:attr/colorAccent">
+    <path
+        android:fillColor="?android:attr/colorBackground"
+        android:pathData="M11 15h2v2h-2v-2zm0-8h2v6h-2V7zm0.99-5C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z" />
+    <path
+        android:pathData="M0 0h24v24H0V0z" />
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_done.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_done.xml
new file mode 100644
index 000000000..8439cb2a5
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_done.xml
@@ -0,0 +1,24 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="?android:colorAccent"
+        android:pathData="M9,16.2L4.8,12l-1.4,1.4L9,19 21,7l-1.4,-1.4L9,16.2z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_drop_copy_badge.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_drop_copy_badge.xml
new file mode 100644
index 000000000..370c4fe70
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_drop_copy_badge.xml
@@ -0,0 +1,37 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="14dp"
+        android:height="14dp"
+        android:viewportWidth="28.0"
+        android:viewportHeight="28.0">
+
+    <group
+         android:name="whiteBg">
+    <path
+        android:fillColor="#FFFFFFFF"
+        android:pathData="M0,15a15,15 0 1,0 30,0a15,15 0 1,0 -30,0" />
+    </group>
+
+    <group
+         android:name="badge"
+         android:translateX="2"
+         android:translateY="2">
+    <path
+        android:fillColor="#FF0B8043"
+        android:pathData="M13,0 C5.824,0 0,5.824 0,13 C0,20.176 5.824,26 13,26 C20.176,26 26,20.176 26,13 C26,5.824 20.176,0 13,0 L13,0 Z M19,14 L14,14 L14,19 L12,19 L12,14 L7,14 L7,12 L12,12 L12,7 L14,7 L14,12 L19,12 L19,14 Z" />
+    </group>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_eject.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_eject.xml
new file mode 100644
index 000000000..11c8af06f
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_eject.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M5 17h14v2H5zm7-12L5.33 15h13.34z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_exit_to_app.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_exit_to_app.xml
new file mode 100644
index 000000000..e0ebf7319
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_exit_to_app.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_folder_shortcut.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_folder_shortcut.xml
new file mode 100644
index 000000000..fb2427a38
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_folder_shortcut.xml
@@ -0,0 +1,33 @@
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
+
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+    <background android:drawable="@color/shortcut_background" />
+    <foreground>
+        <inset android:inset="33%">
+            <vector
+                android:width="24dp"
+                android:height="24dp"
+                android:viewportWidth="24.0"
+                android:viewportHeight="24.0">
+                <path
+                    android:fillColor="@color/shortcut_foreground"
+                    android:pathData="M10 4H4c-1.1 0,-1.99.9,-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2,-.9 2,-2V8c0,-1.1,-.9,-2,-2,-2h-8l-2,-2z"/>
+            </vector>
+        </inset>
+    </foreground>
+</adaptive-icon>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_hamburger.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_hamburger.xml
new file mode 100644
index 000000000..1d3990887
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_hamburger.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M3,18h18v-2H3V18zM3,13h18v-2H3V13zM3,6v2h18V6H3z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_history.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_history.xml
new file mode 100644
index 000000000..516b76daa
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_history.xml
@@ -0,0 +1,24 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:textColorSecondary"
+        android:pathData="M13,3c-4.97,0 -9,4.03 -9,9L1,12l4,3.99L9,12L6,12c0,-3.87 3.13,-7 7,-7s7,3.13 7,7 -3.13,7 -7,7c-1.93,0 -3.68,-0.79 -4.94,-2.06l-1.42,1.42C8.27,19.99 10.51,21 13,21c4.97,0 9,-4.03 9,-9s-4.03,-9 -9,-9zM12,8v5l4.25,2.52 0.77,-1.28 -3.52,-2.09L13.5,8z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_images_shortcut.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_images_shortcut.xml
new file mode 100644
index 000000000..66de1938c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_images_shortcut.xml
@@ -0,0 +1,33 @@
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
+
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+    <background android:drawable="@color/shortcut_background" />
+    <foreground>
+      <inset android:inset="33%">
+        <vector xmlns:android="http://schemas.android.com/apk/res/android"
+          android:width="24dp"
+          android:height="24dp"
+          android:viewportHeight="24"
+          android:viewportWidth="24">
+        <path
+          android:fillColor="@color/shortcut_foreground"
+          android:pathData="M21 19V5c0,-1.1,-.9,-2,-2,-2H5c-1.1 0,-2 .9,-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2,-.9 2,-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5,-4.5z" />
+        </vector>
+      </inset>
+    </foreground>
+</adaptive-icon>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_compress.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_compress.xml
new file mode 100644
index 000000000..e88245ec0
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_compress.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+<path
+    android:fillColor="?android:attr/colorControlNormal"
+    android:pathData="M20.54,5.23l-1.39,-1.68C18.88,3.21 18.47,3 18,3H6c-0.47,0 -0.88,0.21 -1.16,0.55L3.46,5.23C3.17,5.57 3,6.02 3,6.5V19c0,1.1 0.9,2 2,2h14c1.1,0 2,-0.9 2,-2V6.5c0,-0.48 -0.17,-0.93 -0.46,-1.27zM12,17.5L6.5,12H10v-2h4v2h3.5L12,17.5zM5.12,5l0.81,-1h12l0.94,1H5.12z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_copy.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_copy.xml
new file mode 100644
index 000000000..ea45ba341
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_copy.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M16,1L4,1c-1.1,0 -2,0.9 -2,2v14h2L4,3h12L16,1zM15,5L8,5c-1.1,0 -1.99,0.9 -1.99,2L6,21c0,1.1 0.89,2 1.99,2L19,23c1.1,0 2,-0.9 2,-2L21,11l-6,-6zM8,21L8,7h6v5h5v9L8,21z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_delete.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_delete.xml
new file mode 100644
index 000000000..677fbd25c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_delete.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M6,19c0,1.1 0.9,2 2,2h8c1.1,0 2,-0.9 2,-2V7H6v12zM19,4h-3.5l-1,-1h-5l-1,1H5v2h14V4z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_extract.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_extract.xml
new file mode 100644
index 000000000..6a48e697c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_extract.xml
@@ -0,0 +1,28 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <group>
+        <clip-path android:pathData="M0,0h24v24H0V0z M 0,0"/>
+        <path
+            android:fillColor="?android:attr/colorControlNormal"
+            android:pathData="M20.55 5.22l-1.39,-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0,-.88.21,-1.15.55L3.46 5.22C3.17 5.57 3 6.01 3 6.5V19c0 1.1.89 2 2 2h14c1.1 0 2,-.9 2,-2V6.5c0,-.49,-.17,-.93,-.45,-1.28zM12 9.5l5.5 5.5H14v2h-4v-2H6.5L12 9.5zM5.12 5l.82,-1h12l.93 1H5.12z"/>
+    </group>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_search.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_search.xml
new file mode 100644
index 000000000..6d896b75d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_search.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M15.5,14h-0.79l-0.28,-0.27C15.41,12.59 16,11.11 16,9.5 16,5.91 13.09,3 9.5,3S3,5.91 3,9.5 5.91,16 9.5,16c1.61,0 3.09,-0.59 4.23,-1.57l0.27,0.28v0.79l5,4.99L20.49,19l-4.99,-5zM9.5,14C7.01,14 5,11.99 5,9.5S7.01,5 9.5,5 14,7.01 14,9.5 11.99,14 9.5,14z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_share.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_share.xml
new file mode 100644
index 000000000..78fae8ed1
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_share.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M18,16.08c-0.76,0 -1.44,0.3 -1.96,0.77L8.91,12.7c0.05,-0.23 0.09,-0.46 0.09,-0.7s-0.04,-0.47 -0.09,-0.7l7.05,-4.11c0.54,0.5 1.25,0.81 2.04,0.81 1.66,0 3,-1.34 3,-3s-1.34,-3 -3,-3 -3,1.34 -3,3c0,0.24 0.04,0.47 0.09,0.7L8.04,9.81C7.5,9.31 6.79,9 6,9c-1.66,0 -3,1.34 -3,3s1.34,3 3,3c0.79,0 1.5,-0.31 2.04,-0.81l7.12,4.16c-0.05,0.21 -0.08,0.43 -0.08,0.65 0,1.61 1.31,2.92 2.92,2.92 1.61,0 2.92,-1.31 2.92,-2.92s-1.31,-2.92 -2.92,-2.92z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_grid.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_grid.xml
new file mode 100644
index 000000000..9818c4c4a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_grid.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M4,5v13h17L21,5L4,5zM14,7v3.5h-3L11,7h3zM6,7h3v3.5L6,10.5L6,7zM6,16v-3.5h3L9,16L6,16zM11,16v-3.5h3L14,16h-3zM19,16h-3v-3.5h3L19,16zM16,10.5L16,7h3v3.5h-3z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_list.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_list.xml
new file mode 100644
index 000000000..81bdd5e85
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_menu_view_list.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="?android:attr/colorControlNormal"
+        android:pathData="M3,5v14h17L20,5L3,5zM7,7v2L5,9L5,7h2zM5,13v-2h2v2L5,13zM5,15h2v2L5,17v-2zM18,17L9,17v-2h9v2zM18,13L9,13v-2h9v2zM18,9L9,9L9,7h9v2z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_reject_drop_badge.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_reject_drop_badge.xml
new file mode 100644
index 000000000..06db34617
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_reject_drop_badge.xml
@@ -0,0 +1,38 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="14dp"
+        android:height="14dp"
+        android:viewportWidth="28.0"
+        android:viewportHeight="28.0">
+
+    <group
+         android:name="whiteBg">
+        <path
+            android:fillColor="#FFFFFFFF"
+            android:pathData="M0,15a15,15 0 1,0 30,0a15,15 0 1,0 -30,0" />
+    </group>
+
+    <group
+         android:name="badge"
+         android:translateX="2"
+         android:translateY="2">
+        <path
+            android:fillColor="#FFC53929"
+            android:pathData="M3.8056487,3.8056487 C-1.26854957,8.87984696 -1.26854957,17.1162267 3.8056487,22.190425 C8.87984696,27.2646233 17.1162267,27.2646233 22.190425,22.190425 C27.2646233,17.1162267 27.2646233,8.87984696 22.190425,3.8056487 C17.1162267,-1.26854957 8.87984696,-1.26854957 3.8056487,3.8056487 L3.8056487,3.8056487 Z M16.5335708,17.9477843 L12.9980369,14.4122504 L9.46250295,17.9477843 L8.04828938,16.5335708 L11.5838233,12.9980369 L8.04828938,9.46250295 L9.46250295,8.04828938 L12.9980369,11.5838233 L16.5335708,8.04828938 L17.9477843,9.46250295 L14.4122504,12.9980369 L17.9477843,16.5335708 L16.5335708,17.9477843 L16.5335708,17.9477843 Z" />
+    </group>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_bugreport.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_bugreport.xml
new file mode 100644
index 000000000..20517f951
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_bugreport.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M20 10V8h-2.81c-.45-.78-1.07-1.46-1.82-1.96L17 4.41 15.59 3l-2.17 2.17c-.03-.01-.05-.01-.08-.01-.16-.04-.32-.06-.49-.09l-.17-.03C12.46 5.02 12.23 5 12 5c-.49 0-.97.07-1.42.18l.02-.01L8.41 3 7 4.41l1.62 1.63h.01c-.75.5-1.37 1.18-1.82 1.96H4v2h2.09c-.06.33-.09.66-.09 1v1H4v2h2v1c0 .34.04.67.09 1H4v2h2.81c1.04 1.79 2.97 3 5.19 3s4.15-1.21 5.19-3H20v-2h-2.09c.05-.33.09-.66.09-1v-1h2v-2h-2v-1c0-.34-.04-.67-.09-1H20zm-4 5c0 2.21-1.79 4-4 4s-4-1.79-4-4v-4c0-2.21 1.79-4 4-4s4 1.79 4 4v4zm-6-1h4v2h-4zm0-4h4v2h-4z" />
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_download.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_download.xml
new file mode 100644
index 000000000..caea0922f
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_download.xml
@@ -0,0 +1,25 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportHeight="24"
+        android:viewportWidth="24">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z" />
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_recent.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_recent.xml
new file mode 100644
index 000000000..fc26692c7
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_recent.xml
@@ -0,0 +1,31 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2
+11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z" />
+
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M12.5 7H11v6l5.25 3.15 .75 -1.23-4.5-2.67z" />
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_smartphone.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_smartphone.xml
new file mode 100644
index 000000000..01af619a0
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_root_smartphone.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M17 1.01L7 1c-1.1 0,-2 .9,-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2,-.9 2,-2V3c0,-1.1,-.9,-1.99,-2,-1.99zM17 19H7V5h10v14z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sd_storage.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sd_storage.xml
new file mode 100644
index 000000000..bd54eb31b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sd_storage.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="#5F6368"
+        android:pathData="M18 2h-8L4.02 8 4 20c0 1.1.9 2 2 2h12c1.1 0 2,-.9 2,-2V4c0,-1.1,-.9,-2,-2,-2zm-6 6h-2V4h2v4zm3 0h-2V4h2v4zm3 0h-2V4h2v4z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sort.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sort.xml
new file mode 100644
index 000000000..a64bb9ef1
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sort.xml
@@ -0,0 +1,26 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0"
+        android:tint="?attr/colorControlNormal">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M3,18h6v-2L3,16v2zM3,6v2h18L21,6L3,6zM3,13h12v-2L3,11v2z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sort_arrow.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sort_arrow.xml
new file mode 100644
index 000000000..e54ee3158
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_sort_arrow.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+  -->
+
+<rotate xmlns:android="http://schemas.android.com/apk/res/android"
+        android:drawable="@drawable/ic_arrow_upward"
+        android:fromDegrees="0"
+        android:toDegrees="180"
+        android:pivotX="50%"
+        android:pivotY="50%"/>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_subdirectory_arrow.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_subdirectory_arrow.xml
new file mode 100644
index 000000000..684565bf0
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_subdirectory_arrow.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="?android:textColorSecondary"
+        android:pathData="M19 15l-6 6,-1.42,-1.42L15.17 16H4V4h2v10h9.17l-3.59,-3.58L13 9l6 6z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_usb_shortcut.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_usb_shortcut.xml
new file mode 100644
index 000000000..6e53700f9
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_usb_shortcut.xml
@@ -0,0 +1,33 @@
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
+
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+    <background android:drawable="@color/shortcut_background" />
+    <foreground>
+        <inset android:inset="33%">
+            <vector xmlns:android="http://schemas.android.com/apk/res/android"
+                android:width="24dp"
+                android:height="24dp"
+                android:viewportHeight="24"
+                android:viewportWidth="24">
+                <path
+                    android:fillColor="@color/shortcut_foreground"
+                    android:pathData="M15 7v4h1v2h-3V5h2l-3,-4,-3 4h2v8H8v-2.07c.7,-.37 1.2,-1.08 1.2,-1.93 0,-1.21,-.99,-2.2,-2.2,-2.2,-1.21 0,-2.2.99,-2.2 2.2 0 .85.5 1.56 1.2 1.93V13c0 1.11.89 2 2 2h3v3.05c-.71.37,-1.2 1.1,-1.2 1.95 0 1.22.99 2.2 2.2 2.2 1.21 0 2.2,-.98 2.2,-2.2 0,-.85,-.49,-1.58,-1.2,-1.95V15h3c1.11 0 2,-.89 2,-2v-2h1V7h-4z"/>
+            </vector>
+        </inset>
+    </foreground>
+</adaptive-icon>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_usb_storage.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_usb_storage.xml
new file mode 100644
index 000000000..6dde75108
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_usb_storage.xml
@@ -0,0 +1,24 @@
+<!--
+Copyright (C) 2024 The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="?android:textColorSecondary"
+        android:pathData="M15 7v4h1v2h-3V5h2l-3,-4,-3 4h2v8H8v-2.07c.7,-.37 1.2,-1.08 1.2,-1.93 0,-1.21,-.99,-2.2,-2.2,-2.2,-1.21 0,-2.2.99,-2.2 2.2 0 .85.5 1.56 1.2 1.93V13c0 1.11.89 2 2 2h3v3.05c-.71.37,-1.2 1.1,-1.2 1.95 0 1.22.99 2.2 2.2 2.2 1.21 0 2.2,-.98 2.2,-2.2 0,-.85,-.49,-1.58,-1.2,-1.95V15h3c1.11 0 2,-.89 2,-2v-2h1V7h-4z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_user_profile.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_user_profile.xml
new file mode 100644
index 000000000..42e06a59e
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_user_profile.xml
@@ -0,0 +1,9 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:pathData="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm6.36 14.83c-1.43-1.74-4.9-2.33-6.36-2.33s-4.93.59-6.36 2.33C4.62 15.49 4 13.82 4 12c0-4.41 3.59-8 8-8s8 3.59 8 8c0 1.82-.62 3.49-1.64 4.83zM12 6c-1.94 0-3.5 1.56-3.5 3.5S10.06 13 12 13s3.5-1.56 3.5-3.5S13.94 6 12 6z"
+        android:fillColor="#4285F4"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_zoom_out.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_zoom_out.xml
new file mode 100644
index 000000000..c986d6579
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/ic_zoom_out.xml
@@ -0,0 +1,24 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24.0"
+        android:viewportHeight="24.0">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M15,3l2.3,2.3 -2.89,2.87 1.42,1.42L18.7,6.7 21,9L21,3zM3,9l2.3,-2.3 2.87,2.89 1.42,-1.42L6.7,5.3 9,3L3,3zM9,21l-2.3,-2.3 2.89,-2.87 -1.42,-1.42L5.3,17.3 3,15v6zM21,15l-2.3,2.3 -2.87,-2.89 -1.42,1.42 2.89,2.87L15,21h6z"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/inspector_separator.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/inspector_separator.xml
new file mode 100644
index 000000000..fcfd61f1d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/inspector_separator.xml
@@ -0,0 +1,24 @@
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
+<inset xmlns:android="http://schemas.android.com/apk/res/android"
+    android:insetTop="10dp"
+    android:insetBottom="10dp" >
+    <shape xmlns:android="http://schemas.android.com/apk/res/android"
+           android:tint="?android:attr/colorForeground">
+        <size android:height="1dp"/>
+        <solid android:color="#1f000000"/>
+    </shape>
+</inset>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border.xml
new file mode 100644
index 000000000..411085500
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="UTF-8"?>
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
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:shape="rectangle">
+    <stroke
+        android:width="2dp"
+        android:color="@color/item_doc_grid_border"/>
+</shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border_rounded.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border_rounded.xml
new file mode 100644
index 000000000..249bda702
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/item_doc_grid_border_rounded.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="UTF-8"?>
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
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:shape="rectangle">
+    <stroke
+        android:width="2dp"
+        android:color="@color/item_doc_grid_border"/>
+    <corners android:radius="@dimen/grid_item_radius"/>
+</shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/launcher_screen.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/launcher_screen.xml
new file mode 100644
index 000000000..c0d814632
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/launcher_screen.xml
@@ -0,0 +1,11 @@
+<?xml version="1.0" encoding="utf-8"?>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android" >
+  <item android:drawable="@android:color/white"/>
+
+  <item
+      android:drawable="@drawable/splash_screen"
+      android:height="150dp"
+      android:width="150dp"
+      android:gravity="center"/>
+
+</layer-list>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/launcher_screen_night.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/launcher_screen_night.xml
new file mode 100644
index 000000000..983c4977d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/launcher_screen_night.xml
@@ -0,0 +1,11 @@
+<?xml version="1.0" encoding="utf-8"?>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android" >
+  <item android:drawable="@color/app_background_color"/>
+
+  <item
+      android:drawable="@drawable/splash_screen"
+      android:height="150dp"
+      android:width="150dp"
+      android:gravity="center"/>
+
+</layer-list>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_checker.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_checker.xml
new file mode 100644
index 000000000..c3371b71a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_checker.xml
@@ -0,0 +1,22 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:state_checked="true"
+        android:drawable="@drawable/ic_done"/>
+    <item
+        android:drawable="@android:color/transparent"/>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_divider.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_divider.xml
new file mode 100644
index 000000000..ea48565c1
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_divider.xml
@@ -0,0 +1,23 @@
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
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:tint="?android:attr/colorForeground">
+    <solid android:color="@color/list_divider_color" />
+    <size
+        android:height="1dp"
+        android:width="1dp" />
+</shape>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_item_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_item_background.xml
new file mode 100644
index 000000000..126788c6d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/list_item_background.xml
@@ -0,0 +1,31 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true" >
+        <color android:color="@color/list_item_selected_background_color"/>
+    </item>
+    <item android:state_selected="true">
+        <color android:color="@color/list_item_selected_background_color"/>
+    </item>
+    <item android:state_drag_hovered="true">
+        <color android:color="?android:strokeColor"/>
+    </item>
+    <item android:state_selected="false"
+          android:state_focused="false">
+        <color android:color="?android:attr/colorBackground"/>
+    </item>
+</selector>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/main_container_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/main_container_background.xml
new file mode 100644
index 000000000..151a7ba77
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/main_container_background.xml
@@ -0,0 +1,20 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <solid android:color="?attr/colorSurfaceBright" />
+    <corners android:radius="16dp" />
+</shape>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/menu_dropdown_panel.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/menu_dropdown_panel.xml
new file mode 100644
index 000000000..43dd62e2c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/menu_dropdown_panel.xml
@@ -0,0 +1,46 @@
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
+
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android" >
+    <!-- Panel shadow -->
+    <item>
+        <shape
+            xmlns:android="http://schemas.android.com/apk/res/android"
+            android:shape="rectangle"
+            android:tint="?android:attr/colorBackgroundFloating">
+            <stroke android:width="2dp" android:color="#3C4043" />
+            <solid android:color="#5F6368" />
+            <corners
+                android:topRightRadius="@dimen/material_round_radius"
+                android:topLeftRadius="@dimen/material_round_radius"
+                android:bottomRightRadius="@dimen/material_round_radius"
+                android:bottomLeftRadius="@dimen/material_round_radius"/>
+        </shape>
+    </item>
+    <!-- Panel surface -->
+    <item android:bottom="2dp">
+        <shape
+            xmlns:android="http://schemas.android.com/apk/res/android"
+            android:shape="rectangle"
+            android:tint="?android:attr/colorBackgroundFloating">
+            <corners
+                android:topRightRadius="@dimen/material_round_radius"
+                android:topLeftRadius="@dimen/material_round_radius"
+                android:bottomRightRadius="@dimen/material_round_radius"
+                android:bottomLeftRadius="@dimen/material_round_radius"/>
+        </shape>
+    </item>
+</layer-list>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/progress_indeterminate_horizontal_material_trimmed.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/progress_indeterminate_horizontal_material_trimmed.xml
new file mode 100644
index 000000000..1200ab00b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/progress_indeterminate_horizontal_material_trimmed.xml
@@ -0,0 +1,28 @@
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
+
+<!-- Variant of progress_indeterminate_horizontal_material in frameworks/base/core/res, which
+     draws the whole height of the progress bar instead having blank space above and below the
+     bar. -->
+<animated-vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:drawable="@drawable/vector_drawable_progress_indeterminate_horizontal_trimmed" >
+    <target
+        android:name="rect2_grp"
+        android:animation="@anim/progress_indeterminate_horizontal_rect2" />
+    <target
+        android:name="rect1_grp"
+        android:animation="@anim/progress_indeterminate_horizontal_rect1" />
+</animated-vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/root_item_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/root_item_background.xml
new file mode 100644
index 000000000..544d23beb
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/root_item_background.xml
@@ -0,0 +1,43 @@
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
+
+<ripple
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:color="?android:attr/colorControlHighlight">
+    <item
+        android:id="@android:id/mask"
+        android:drawable="@drawable/root_list_selector"/>
+
+    <item>
+        <selector>
+            <item app:state_highlighted="true">
+                <color android:color="?android:attr/colorControlHighlight"/>
+            </item>
+            <item
+                app:state_highlighted="false"
+                android:drawable="@android:color/transparent"/>
+        </selector>
+    </item>
+
+    <item>
+        <selector>
+            <item
+                android:state_activated="true"
+                android:drawable="@drawable/root_list_selector"/>
+        </selector>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/root_list_selector.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/root_list_selector.xml
new file mode 100644
index 000000000..11d28a70f
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/root_list_selector.xml
@@ -0,0 +1,30 @@
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
+
+<inset xmlns:android="http://schemas.android.com/apk/res/android"
+       android:inset="8dp">
+    <shape
+        xmlns:android="http://schemas.android.com/apk/res/android"
+        android:shape="rectangle">
+        <corners
+            android:topLeftRadius="2dp"
+            android:topRightRadius="2dp"
+            android:bottomLeftRadius="2dp"
+            android:bottomRightRadius="2dp"/>
+        <solid
+            android:color="?android:attr/colorSecondary"/>
+    </shape>
+</inset>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/search_bar_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/search_bar_background.xml
new file mode 100644
index 000000000..8ad306c06
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/search_bar_background.xml
@@ -0,0 +1,30 @@
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
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item>
+        <shape android:shape="rectangle">
+            <solid android:color="@android:color/transparent"/>
+        </shape>
+    </item>
+    <item
+        android:start="@dimen/search_bar_background_margin_start"
+        android:end="@dimen/search_bar_background_margin_end">
+        <shape android:shape="rectangle">
+            <solid android:color="?android:attr/colorBackgroundFloating"/>
+            <corners android:radius="@dimen/search_bar_radius"/>
+        </shape>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/share_off.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/share_off.xml
new file mode 100644
index 000000000..e5c0f95ae
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/share_off.xml
@@ -0,0 +1,26 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:pathData="M19.7225,20.9245L21.2011,22.4031L22.4032,21.201L2.8022,1.6L1.6001,2.8021L8.1265,9.3284L7.64,9.612C7.1,9.112 6.39,8.802 5.6,8.802C3.94,8.802 2.6,10.142 2.6,11.802C2.6,13.462 3.94,14.802 5.6,14.802C6.39,14.802 7.1,14.492 7.64,13.992L14.69,18.112C14.64,18.332 14.6,18.562 14.6,18.802C14.6,20.462 15.94,21.802 17.6,21.802C18.43,21.802 19.18,21.467 19.7225,20.9245ZM16.8938,18.0958L18.3063,19.5083C18.125,19.6895 17.875,19.802 17.6,19.802C17.05,19.802 16.6,19.352 16.6,18.802C16.6,18.527 16.7125,18.277 16.8938,18.0958ZM15.1871,16.3891L9.3881,10.5901L8.51,11.102C8.56,11.332 8.6,11.562 8.6,11.802C8.6,12.042 8.56,12.272 8.51,12.502L15.1871,16.3891ZM15.56,6.992L12.4382,8.8119L11.1766,7.5503L14.69,5.502C14.64,5.282 14.6,5.042 14.6,4.802C14.6,3.142 15.94,1.802 17.6,1.802C19.26,1.802 20.6,3.142 20.6,4.802C20.6,6.462 19.26,7.802 17.6,7.802C16.81,7.802 16.09,7.492 15.56,6.992ZM18.6,4.802C18.6,4.252 18.15,3.802 17.6,3.802C17.05,3.802 16.6,4.252 16.6,4.802C16.6,5.352 17.05,5.802 17.6,5.802C18.15,5.802 18.6,5.352 18.6,4.802ZM5.6,12.802C5.05,12.802 4.6,12.352 4.6,11.802C4.6,11.252 5.05,10.802 5.6,10.802C6.15,10.802 6.6,11.252 6.6,11.802C6.6,12.352 6.15,12.802 5.6,12.802Z"
+        android:fillType="evenOdd"
+        android:fillColor="@color/error_image_color"/>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/sort_widget_background.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/sort_widget_background.xml
new file mode 100644
index 000000000..212dab765
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/sort_widget_background.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+  -->
+
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:top="-1dp"
+        android:left="-1dp"
+        android:right="-1dp"
+        android:bottom="0dp">
+        <shape android:shape="rectangle">
+            <stroke
+                android:width="1dp"
+                android:color="#1f000000" />
+        </shape>
+    </item>
+</layer-list>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/splash_screen.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/splash_screen.xml
new file mode 100644
index 000000000..3f0c48b6b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/splash_screen.xml
@@ -0,0 +1,64 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:aapt="http://schemas.android.com/aapt"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+  <path
+      android:pathData="M12,12m-11,0a11,11 0,1 1,22 0a11,11 0,1 1,-22 0"
+      android:fillColor="#4285F4"/>
+  <path
+      android:pathData="M23,12c0,6.1 -4.9,11 -11,11S1,18.1 1,12c0,0 0,0 0,-0.1c0,6 4.9,10.9 11,10.9S23,18 23,12C23,12 23,12 23,12z"
+      android:strokeAlpha="0.2"
+      android:fillColor="#263238"
+      android:fillAlpha="0.2"/>
+  <path
+      android:pathData="M23,12C23,12 23,12 23,12c0,-6 -4.9,-10.9 -11,-10.9S1,6 1,12.1c0,0 0,0 0,-0.1C1,5.9 5.9,1 12,1S23,5.9 23,12z"
+      android:strokeAlpha="0.2"
+      android:fillColor="#FFFFFF"
+      android:fillAlpha="0.2"/>
+  <path
+      android:pathData="M22.8,14.2c-1,4.8 -5,8.4 -9.9,8.8l-6.4,-6.4L17.6,9C17.6,9 22.8,14.2 22.8,14.2z"
+      android:fillColor="#4285F4"/>
+  <path
+      android:pathData="M22.8,14.2c-1,4.8 -5,8.4 -9.9,8.8l-6.4,-6.4L17.6,9C17.6,9 22.8,14.2 22.8,14.2z">
+    <aapt:attr name="android:fillColor">
+      <gradient
+          android:startY="12.203438"
+          android:startX="11.452812"
+          android:endY="20.219812"
+          android:endX="19.469187"
+          android:type="linear">
+        <item android:offset="0" android:color="#33263238"/>
+        <item android:offset="1" android:color="#05263238"/>
+      </gradient>
+    </aapt:attr>
+  </path>
+  <path
+      android:pathData="M16.5,8.5H12L10.8,7H7.5C6.7,7 6,7.7 6,8.5v7C6,16.3 6.7,17 7.5,17h9c0.8,0 1.5,-0.7 1.5,-1.5V10C18,9.2 17.3,8.5 16.5,8.5z"
+      android:fillColor="#F5F5F5"/>
+  <path
+      android:pathData="M18,10v0.1c0,-0.8 -0.7,-1.5 -1.5,-1.5H12l-1.2,-1.5H7.5C6.7,7.1 6,7.8 6,8.6V8.5C6,7.7 6.7,7 7.5,7h3.2L12,8.5h4.5C17.3,8.5 18,9.2 18,10z"
+      android:strokeAlpha="0.4"
+      android:fillColor="#FFFFFF"
+      android:fillAlpha="0.4"/>
+  <path
+      android:pathData="M18,15.5v0.1c0,0.8 -0.7,1.5 -1.5,1.5h-9c-0.8,0 -1.5,-0.7 -1.5,-1.5v-0.1C6,16.3 6.7,17 7.5,17h9C17.3,17 18,16.3 18,15.5z"
+      android:strokeAlpha="0.2"
+      android:fillColor="#263238"
+      android:fillAlpha="0.2"/>
+  <path
+      android:pathData="M12,12m-11,0a11,11 0,1 1,22 0a11,11 0,1 1,-22 0"
+      android:fillAlpha="0.1">
+    <aapt:attr name="android:fillColor">
+      <gradient
+          android:gradientRadius="22.333876"
+          android:centerX="3.238875"
+          android:centerY="5.0445"
+          android:type="radial">
+        <item android:offset="0" android:color="#FFFFFFFF"/>
+        <item android:offset="1" android:color="#00FFFFFF"/>
+      </gradient>
+    </aapt:attr>
+  </path>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/tab_border_rounded.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/tab_border_rounded.xml
new file mode 100644
index 000000000..96b7e6d49
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/tab_border_rounded.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="UTF-8"?>
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
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+
+   <solid
+       android:color="@color/profile_tab_selector"/>
+   <corners android:radius="12dp"/>
+</shape>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml
new file mode 100644
index 000000000..c8d899ff7
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/vector_drawable_progress_indeterminate_horizontal_trimmed.xml
@@ -0,0 +1,53 @@
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
+
+<!-- Variant of vector_drawable_progress_indeterminate_horizontal in frameworks/base/core/res, which
+     draws the whole height of the progress bar instead having blank space above and below the
+     bar. -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:height="10dp"
+    android:width="360dp"
+    android:viewportHeight="10"
+    android:viewportWidth="360" >
+    <group
+        android:name="progress_group"
+        android:translateX="180"
+        android:translateY="5" >
+        <path
+            android:name="background_track"
+            android:pathData="M -180.0,-5.0 l 360.0,0 l 0,10.0 l -360.0,0 Z"
+            android:fillColor="?android:attr/colorControlActivated"
+            android:fillAlpha="?android:attr/disabledAlpha"/>
+        <group
+            android:name="rect2_grp"
+            android:translateX="-197.60001"
+            android:scaleX="0.1" >
+            <path
+                android:name="rect2"
+                android:pathData="M -144.0,-5.0 l 288.0,0 l 0,10.0 l -288.0,0 Z"
+                android:fillColor="?android:attr/colorControlActivated" />
+        </group>
+        <group
+            android:name="rect1_grp"
+            android:translateX="-522.59998"
+            android:scaleX="0.1" >
+            <path
+                android:name="rect1"
+                android:pathData="M -144.0,-5.0 l 288.0,0 l 0,10.0 l -288.0,0 Z"
+                android:fillColor="?android:attr/colorControlActivated" />
+        </group>
+    </group>
+</vector>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/drawable/work_off.xml b/res/flag(com.android.documentsui.flags.use_material3)/drawable/work_off.xml
new file mode 100644
index 000000000..500a62fbd
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/drawable/work_off.xml
@@ -0,0 +1,26 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24">
+    <path
+        android:fillColor="@color/error_image_color"
+        android:pathData="M20,6h-4L16,4c0,-1.11 -0.89,-2 -2,-2h-4c-1.11,0 -2,0.89 -2,2v1.17L10.83,8L20,8v9.17l1.98,1.98c0,-0.05 0.02,-0.1 0.02,-0.16L22,8c0,-1.11 -0.89,-2 -2,-2zM14,6h-4L10,4h4v2zM19,19L8,8 6,6 2.81,2.81 1.39,4.22 3.3,6.13C2.54,6.41 2.01,7.14 2.01,8L2,19c0,1.11 0.89,2 2,2h14.17l1.61,1.61 1.41,-1.41 -0.37,-0.37L19,19zM4,19L4,8h1.17l11,11L4,19z"/>
+</vector>
+
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/column_headers.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/column_headers.xml
new file mode 100644
index 000000000..f24a28241
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/column_headers.xml
@@ -0,0 +1,122 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/table_header"
+    android:orientation="horizontal"
+    android:layout_width="match_parent"
+    android:layout_height="@dimen/doc_header_height"
+    android:background="@drawable/sort_widget_background"
+    android:visibility="gone">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:baselineAligned="false"
+        android:gravity="center_vertical"
+        android:minHeight="@dimen/list_item_height"
+        android:paddingStart="@dimen/list_item_padding"
+        android:paddingEnd="@dimen/list_item_width"
+        android:orientation="horizontal">
+        <!-- Placeholder for icon -->
+        <View
+            android:layout_width="@dimen/list_item_thumbnail_size"
+            android:layout_height="@dimen/list_item_thumbnail_size"
+            android:layout_gravity="center_vertical"
+            android:layout_marginEnd="16dp"
+            android:layout_marginStart="0dp"/>
+
+        <!-- Column headers -->
+        <LinearLayout
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="1"
+            android:orientation="horizontal">
+
+            <com.android.documentsui.sorting.HeaderCell
+                android:id="@android:id/title"
+                android:layout_width="0dp"
+                android:layout_height="match_parent"
+                android:layout_weight="0.4"
+                android:layout_marginEnd="12dp"
+                android:focusable="true"
+                android:gravity="center_vertical"
+                android:orientation="horizontal"
+                android:animateLayoutChanges="true">
+
+                <include layout="@layout/shared_cell_content" />
+            </com.android.documentsui.sorting.HeaderCell>
+
+            <com.android.documentsui.sorting.HeaderCell
+                android:id="@android:id/summary"
+                android:layout_width="0dp"
+                android:layout_height="match_parent"
+                android:layout_weight="0"
+                android:layout_marginEnd="0dp"
+                android:focusable="true"
+                android:gravity="center_vertical"
+                android:orientation="horizontal"
+                android:animateLayoutChanges="true">
+
+                <include layout="@layout/shared_cell_content" />
+            </com.android.documentsui.sorting.HeaderCell>
+
+            <com.android.documentsui.sorting.HeaderCell
+                android:id="@+id/file_type"
+                android:layout_width="0dp"
+                android:layout_height="match_parent"
+                android:layout_weight="0.2"
+                android:layout_marginEnd="12dp"
+                android:focusable="true"
+                android:gravity="center_vertical"
+                android:orientation="horizontal"
+                android:animateLayoutChanges="true">
+
+                <include layout="@layout/shared_cell_content" />
+            </com.android.documentsui.sorting.HeaderCell>
+
+            <com.android.documentsui.sorting.HeaderCell
+                android:id="@+id/size"
+                android:layout_width="0dp"
+                android:layout_height="match_parent"
+                android:layout_weight="0.2"
+                android:layout_marginEnd="12dp"
+                android:focusable="true"
+                android:gravity="center_vertical"
+                android:orientation="horizontal"
+                android:animateLayoutChanges="true">
+
+                <include layout="@layout/shared_cell_content" />
+            </com.android.documentsui.sorting.HeaderCell>
+
+            <com.android.documentsui.sorting.HeaderCell
+                android:id="@+id/date"
+                android:layout_width="0dp"
+                android:layout_height="match_parent"
+                android:layout_weight="0.2"
+                android:layout_marginEnd="12dp"
+                android:focusable="true"
+                android:gravity="center_vertical"
+                android:orientation="horizontal"
+                android:animateLayoutChanges="true">
+
+                <include layout="@layout/shared_cell_content" />
+            </com.android.documentsui.sorting.HeaderCell>
+        </LinearLayout>
+    </LinearLayout>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/directory_app_bar.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/directory_app_bar.xml
new file mode 100644
index 000000000..177aeba4f
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/directory_app_bar.xml
@@ -0,0 +1,55 @@
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
+
+<com.google.android.material.appbar.AppBarLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/app_bar"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:background="?android:attr/colorBackground">
+
+    <androidx.appcompat.widget.Toolbar
+        android:id="@+id/toolbar"
+        android:layout_width="match_parent"
+        android:layout_height="?android:attr/actionBarSize"
+        android:layout_margin="@dimen/search_bar_margin"
+        android:background="?android:attr/colorBackground"
+        android:theme="?actionBarTheme"
+        android:popupTheme="?actionBarPopupTheme"
+        android:elevation="3dp"
+        app:collapseContentDescription="@string/button_back"
+        app:titleTextAppearance="@style/ToolbarTitle"
+        app:layout_collapseMode="pin">
+
+        <TextView
+            android:id="@+id/searchbar_title"
+            android:layout_width="match_parent"
+            android:layout_height="?android:attr/actionBarSize"
+            android:layout_marginStart="@dimen/search_bar_text_margin_start"
+            android:layout_marginEnd="@dimen/search_bar_text_margin_end"
+            android:paddingStart="@dimen/search_bar_icon_padding"
+            android:gravity="center_vertical"
+            android:text="@string/search_bar_hint"
+            android:textAppearance="@style/SearchBarTitle"
+            android:drawableStart="@drawable/ic_menu_search"
+            android:drawablePadding="@dimen/search_bar_icon_padding"/>
+
+    </androidx.appcompat.widget.Toolbar>
+
+    <include layout="@layout/directory_header"/>
+
+</com.google.android.material.appbar.AppBarLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/item_doc_list.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/item_doc_list.xml
new file mode 100644
index 000000000..d9b0ab6f4
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/item_doc_list.xml
@@ -0,0 +1,186 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:background="@drawable/list_item_background"
+    android:foreground="?android:attr/selectableItemBackground"
+    android:clickable="true"
+    android:focusable="true"
+    android:orientation="horizontal" >
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:baselineAligned="false"
+        android:gravity="center_vertical"
+        android:minHeight="@dimen/list_item_height"
+        android:orientation="horizontal" >
+
+        <FrameLayout
+            android:id="@+id/icon"
+            android:pointerIcon="hand"
+            android:layout_width="@dimen/list_item_width"
+            android:layout_height="@dimen/list_item_height"
+            android:paddingBottom="@dimen/list_item_icon_padding"
+            android:paddingTop="@dimen/list_item_icon_padding"
+            android:paddingEnd="16dp"
+            android:paddingStart="@dimen/list_item_padding" >
+
+            <com.google.android.material.card.MaterialCardView
+                app:cardElevation="0dp"
+                app:cardBackgroundColor="@android:color/transparent"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent">
+
+                <ImageView
+                    android:id="@+id/icon_mime"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:contentDescription="@null"
+                    android:scaleType="centerInside" />
+
+                <ImageView
+                    android:id="@+id/icon_thumb"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:layout_gravity="center"
+                    android:contentDescription="@null"
+                    android:scaleType="centerCrop" />
+
+                <ImageView
+                    android:id="@+id/icon_check"
+                    android:layout_width="@dimen/check_icon_size"
+                    android:layout_height="@dimen/check_icon_size"
+                    android:layout_gravity="center"
+                    android:alpha="0"
+                    android:contentDescription="@null"
+                    android:scaleType="fitCenter"
+                    android:src="@drawable/ic_check_circle" />
+
+            </com.google.android.material.card.MaterialCardView>
+
+        </FrameLayout>
+
+        <!-- This is the one special case where we want baseline alignment! -->
+
+        <LinearLayout
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_weight="1"
+            android:orientation="horizontal" >
+
+            <LinearLayout
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_weight="0.4"
+                android:layout_marginEnd="12dp"
+                android:orientation="horizontal">
+
+                <ImageView
+                    android:id="@+id/icon_profile_badge"
+                    android:layout_height="@dimen/briefcase_icon_size"
+                    android:layout_width="@dimen/briefcase_icon_size"
+                    android:layout_marginEnd="@dimen/briefcase_icon_margin"
+                    android:layout_gravity="center_vertical"
+                    android:src="@drawable/ic_briefcase"
+                    android:tint="?android:attr/colorAccent"
+                    android:contentDescription="@string/a11y_work"/>
+
+                <TextView
+                    android:id="@android:id/title"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:ellipsize="middle"
+                    android:singleLine="true"
+                    android:textAlignment="viewStart"
+                    android:textAppearance="@style/Subhead"
+                    android:textColor="?android:attr/textColorPrimary"/>
+            </LinearLayout>
+
+            <TextView
+                android:id="@+id/file_type"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_marginEnd="12dp"
+                android:layout_weight="0.2"
+                android:ellipsize="end"
+                android:singleLine="true"
+                android:textAlignment="viewStart"
+                android:textAppearance="@style/Body1"
+                android:textColor="?android:attr/textColorSecondary" />
+
+            <TextView
+                android:id="@+id/size"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_marginEnd="12dp"
+                android:layout_weight="0.2"
+                android:ellipsize="end"
+                android:minWidth="70dp"
+                android:singleLine="true"
+                android:textAlignment="viewEnd"
+                android:textAppearance="@style/Body1"
+                android:textColor="?android:attr/textColorSecondary" />
+
+            <TextView
+                android:id="@+id/date"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_marginEnd="12dp"
+                android:layout_weight="0.2"
+                android:ellipsize="end"
+                android:minWidth="70dp"
+                android:singleLine="true"
+                android:textAlignment="viewEnd"
+                android:textAppearance="@style/Body1"
+                android:textColor="?android:attr/textColorSecondary" />
+        </LinearLayout>
+
+        <FrameLayout
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content">
+
+            <FrameLayout
+                android:id="@+id/preview_icon"
+                android:layout_width="@dimen/list_item_width"
+                android:layout_height="@dimen/list_item_height"
+                android:padding="@dimen/list_item_icon_padding"
+                android:focusable="true">
+
+                <ImageView
+                    android:layout_width="@dimen/check_icon_size"
+                    android:layout_height="@dimen/check_icon_size"
+                    android:layout_gravity="center"
+                    android:scaleType="fitCenter"
+                    android:tint="?android:attr/textColorPrimary"
+                    android:src="@drawable/ic_zoom_out"/>
+
+            </FrameLayout>
+
+            <android.widget.Space
+                android:layout_width="@dimen/list_item_width"
+                android:layout_height="@dimen/list_item_height"/>
+
+        </FrameLayout>
+
+    </LinearLayout>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/shared_cell_content.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/shared_cell_content.xml
new file mode 100644
index 000000000..4702eada3
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout-w720dp/shared_cell_content.xml
@@ -0,0 +1,37 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+  -->
+
+<merge xmlns:android="http://schemas.android.com/apk/res/android">
+    <TextView
+        android:id="@+id/label"
+        android:layout_height="wrap_content"
+        android:layout_width="wrap_content"
+        android:ellipsize="end"
+        android:singleLine="true"
+        android:textAlignment="viewStart"
+        android:textAppearance="@style/Subhead"
+        android:textColor="?android:attr/textColorSecondary"/>
+
+    <ImageView
+        android:id="@+id/sort_arrow"
+        android:layout_height="@dimen/doc_header_sort_icon_size"
+        android:layout_width="@dimen/doc_header_sort_icon_size"
+        android:layout_marginStart="3dp"
+        android:visibility="gone"
+        android:src="@drawable/ic_sort_arrow"
+        android:contentDescription="@null"/>
+</merge>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/apps_item.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/apps_item.xml
new file mode 100644
index 000000000..6477adedd
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/apps_item.xml
@@ -0,0 +1,59 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="0dp"
+    android:layout_height="wrap_content"
+    android:layout_weight="1"
+    android:minWidth="@dimen/apps_row_item_width"
+    android:paddingBottom="@dimen/apps_row_exit_icon_margin_bottom"
+    android:orientation="vertical"
+    android:background="@drawable/generic_ripple_background"
+    android:gravity="center_horizontal">
+
+    <ImageView
+        android:id="@+id/app_icon"
+        android:layout_width="@dimen/apps_row_app_icon_size"
+        android:layout_height="@dimen/apps_row_app_icon_size"
+        android:layout_marginTop="@dimen/apps_row_app_icon_margin_top"
+        android:layout_marginBottom="@dimen/apps_row_app_icon_margin_bottom"
+        android:layout_marginStart="@dimen/apps_row_app_icon_margin_horizontal"
+        android:layout_marginEnd="@dimen/apps_row_app_icon_margin_horizontal"/>
+
+    <TextView
+        android:id="@android:id/title"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginStart="@dimen/apps_row_item_text_margin_horizontal"
+        android:layout_marginEnd="@dimen/apps_row_item_text_margin_horizontal"
+        android:textAppearance="@style/AppsItemText"
+        android:maxLines="1"
+        android:ellipsize="end"
+        android:gravity="center"/>
+
+    <TextView
+        android:id="@+id/summary"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginStart="@dimen/apps_row_item_text_margin_horizontal"
+        android:layout_marginEnd="@dimen/apps_row_item_text_margin_horizontal"
+        android:textAppearance="@style/AppsItemSubText"
+        android:maxLines="1"
+        android:ellipsize="end"
+        android:gravity="center"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/apps_row.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/apps_row.xml
new file mode 100644
index 000000000..8b6471265
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/apps_row.xml
@@ -0,0 +1,46 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/apps_row"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical">
+
+    <TextView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:minHeight="@dimen/apps_row_title_height"
+        android:paddingStart="@dimen/apps_row_title_padding_start"
+        android:textAppearance="@style/SortTitle"
+        android:text="@string/apps_row_title"
+        android:textAllCaps="true"
+        android:gravity="center"/>
+
+    <HorizontalScrollView
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:fillViewport="true"
+        android:scrollbars="none">
+        <LinearLayout
+            android:id="@+id/apps_group"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:orientation="horizontal"/>
+    </HorizontalScrollView>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/column_headers.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/column_headers.xml
new file mode 100644
index 000000000..fde349b88
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/column_headers.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<!-- A placeholder of table header on small screens. This won't inflate any view when it's included
+     into other layouts. -->
+<merge />
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_delete_confirmation.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_delete_confirmation.xml
new file mode 100644
index 000000000..fb3ff29cf
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_delete_confirmation.xml
@@ -0,0 +1,25 @@
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
+
+<TextView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:paddingTop="24dp"
+    android:paddingStart="24dp"
+    android:paddingEnd="24dp"
+    android:textAppearance="@style/Subhead">
+</TextView>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_file_name.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_file_name.xml
new file mode 100644
index 000000000..8cae6ac03
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_file_name.xml
@@ -0,0 +1,40 @@
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
+
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:fitsSystemWindows="true">
+
+    <com.google.android.material.textfield.TextInputLayout
+        android:id="@+id/input_wrapper"
+        android:orientation="vertical"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginStart="?android:attr/listPreferredItemPaddingStart"
+        android:layout_marginEnd="?android:attr/listPreferredItemPaddingEnd"
+        android:layout_marginTop="@dimen/dialog_content_padding_top"
+        android:layout_marginBottom="@dimen/dialog_content_padding_bottom">
+
+        <com.google.android.material.textfield.TextInputEditText
+            android:id="@android:id/text1"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:maxLength="255"
+            android:inputType="textCapSentences"/>
+
+    </com.google.android.material.textfield.TextInputLayout>
+</FrameLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_sorting.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_sorting.xml
new file mode 100644
index 000000000..9ddbfaee4
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/dialog_sorting.xml
@@ -0,0 +1,38 @@
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
+
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical">
+
+    <TextView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:paddingStart="?android:attr/listPreferredItemPaddingStart"
+        android:paddingEnd="?android:attr/listPreferredItemPaddingEnd"
+        android:paddingTop="?android:attr/listPreferredItemPaddingStart"
+        android:paddingBottom="?android:attr/listPreferredItemPaddingStart"
+        android:textAllCaps="true"
+        android:text="@string/sort_dimension_dialog_title"
+        android:textAppearance="@style/SortTitle"/>
+
+    <ListView
+        android:id="@+id/sorting_dialog_list"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"/>
+
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/directory_app_bar.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/directory_app_bar.xml
new file mode 100644
index 000000000..1f8aa7b3c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/directory_app_bar.xml
@@ -0,0 +1,65 @@
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
+
+<com.google.android.material.appbar.AppBarLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/app_bar"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:background="?android:attr/colorBackground">
+
+    <com.google.android.material.appbar.CollapsingToolbarLayout
+        android:id="@+id/collapsing_toolbar"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        app:titleEnabled="false"
+        app:layout_scrollFlags="scroll|enterAlways|enterAlwaysCollapsed">
+
+        <androidx.core.widget.NestedScrollView
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content">
+
+            <include layout="@layout/directory_header" />
+
+        </androidx.core.widget.NestedScrollView>
+
+        <androidx.appcompat.widget.Toolbar
+            android:id="@+id/toolbar"
+            android:layout_width="match_parent"
+            android:layout_height="?android:attr/actionBarSize"
+            android:layout_margin="@dimen/search_bar_margin"
+            android:background="?android:attr/colorBackground"
+            android:theme="?actionBarTheme"
+            android:popupTheme="?actionBarPopupTheme"
+            android:elevation="@dimen/search_bar_elevation"
+            app:collapseContentDescription="@string/button_back"
+            app:titleTextAppearance="@style/ToolbarTitle"
+            app:layout_collapseMode="pin">
+
+            <TextView
+                android:id="@+id/searchbar_title"
+                android:layout_width="match_parent"
+                android:layout_height="?android:attr/actionBarSize"
+                android:gravity="center_vertical"
+                android:text="@string/search_bar_hint"
+                android:textAppearance="@style/SearchBarTitle" />
+
+        </androidx.appcompat.widget.Toolbar>
+
+    </com.google.android.material.appbar.CollapsingToolbarLayout>
+
+</com.google.android.material.appbar.AppBarLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/directory_header.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/directory_header.xml
new file mode 100644
index 000000000..8d8bd7f8a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/directory_header.xml
@@ -0,0 +1,95 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+              xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/directory_header"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical">
+
+    <com.android.documentsui.HorizontalBreadcrumb
+        android:id="@+id/horizontal_breadcrumb"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+    <!-- used for search chip. -->
+    <include layout="@layout/search_chip_row"/>
+
+    <LinearLayout
+        android:id="@+id/tabs_container"
+        android:theme="@style/TabTheme"
+        android:clipToPadding="true"
+        android:clipChildren="true"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:paddingLeft="@dimen/profile_tab_padding"
+        android:paddingRight="@dimen/profile_tab_padding"
+        android:orientation="vertical">
+
+        <com.google.android.material.tabs.TabLayout
+            android:id="@+id/tabs"
+            android:background="@android:color/transparent"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            app:tabMaxWidth="0dp"
+            app:tabGravity="fill"
+            app:tabMode="fixed"
+            app:tabIndicatorColor="?android:attr/colorAccent"
+            app:tabIndicatorHeight="@dimen/tab_selector_indicator_height"
+            app:tabSelectedTextColor="@color/tab_selected_text_color"
+            app:tabTextAppearance="@style/TabTextAppearance"
+            app:tabTextColor="@color/tab_unselected_text_color"/>
+        <View
+            android:id="@+id/tab_separator"
+            android:layout_width="match_parent"
+            android:layout_height="1dp"
+            android:background="?android:attr/listDivider"/>
+    </LinearLayout>
+
+    <!-- used for apps row. -->
+    <include layout="@layout/apps_row"/>
+
+    <LinearLayout
+        android:id="@+id/header_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginStart="@dimen/root_info_header_horizontal_padding"
+        android:layout_marginEnd="@dimen/root_info_header_horizontal_padding"
+        android:minHeight="@dimen/root_info_header_height"
+        android:accessibilityHeading="true">
+
+        <TextView
+            android:id="@+id/header_title"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:layout_weight="1"
+            android:textAppearance="@style/SectionHeader"
+            android:maxLines="1"
+            android:ellipsize="end"
+            android:gravity="start|center_vertical"/>
+
+        <androidx.appcompat.widget.ActionMenuView
+            android:id="@+id/sub_menu"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="end|center_vertical"/>
+
+    </LinearLayout>
+
+    <!-- column headers are empty on small screens, in portrait or in grid mode. -->
+    <include layout="@layout/column_headers"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/drag_shadow_layout.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/drag_shadow_layout.xml
new file mode 100644
index 000000000..c3de2399c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/drag_shadow_layout.xml
@@ -0,0 +1,48 @@
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
+
+<!-- Transparent container so shadow layer can be drawn -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:padding="8dp"
+    android:background="@color/item_drag_shadow_container_background">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:paddingStart="12dp"
+        android:paddingEnd="12dp"
+        android:orientation="horizontal"
+        android:gravity="center_vertical"
+        android:background="@drawable/drag_shadow_background">
+
+        <include layout="@layout/drop_badge"/>
+
+        <TextView
+            android:id="@android:id/title"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:maxLines="1"
+            android:ellipsize="end"
+            android:textAlignment="viewStart"
+            android:textAppearance="@style/Subhead"
+            android:paddingStart="6dp"
+            android:paddingBottom="1dp"/>
+
+    </LinearLayout>
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/drawer_layout.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/drawer_layout.xml
new file mode 100644
index 000000000..58ef57f58
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/drawer_layout.xml
@@ -0,0 +1,102 @@
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
+
+<!-- CoordinatorLayout is necessary for various components (e.g. Snackbars, and
+     floating action buttons) to operate correctly. -->
+<androidx.coordinatorlayout.widget.CoordinatorLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:id="@+id/coordinator_layout">
+
+    <androidx.drawerlayout.widget.DrawerLayout
+        android:id="@+id/drawer_layout"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent">
+
+        <androidx.coordinatorlayout.widget.CoordinatorLayout
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:orientation="vertical">
+
+            <FrameLayout
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                app:layout_behavior="@string/scrolling_behavior">
+
+                <FrameLayout
+                    android:id="@+id/container_directory"
+                    android:clipToPadding="false"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:layout_weight="1" />
+
+                <FrameLayout
+                    android:id="@+id/container_search_fragment"
+                    android:clipToPadding="false"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent" />
+
+                <!-- Drawer edge is a placeholder view used to capture hovering
+                     event on view edge to open the drawer. (b/28345294) -->
+                <View
+                    android:id="@+id/drawer_edge"
+                    android:background="@android:color/transparent"
+                    android:layout_width="@dimen/drawer_edge_width"
+                    android:layout_height="match_parent"/>
+            </FrameLayout>
+
+            <androidx.coordinatorlayout.widget.CoordinatorLayout
+                android:id="@+id/container_save"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_gravity="bottom|center_horizontal"
+                android:background="?android:attr/colorBackgroundFloating"
+                android:elevation="8dp" />
+
+            <include layout="@layout/directory_app_bar"/>
+
+        </androidx.coordinatorlayout.widget.CoordinatorLayout>
+
+        <LinearLayout
+            android:id="@+id/drawer_roots"
+            android:layout_width="256dp"
+            android:layout_height="match_parent"
+            android:layout_gravity="start"
+            android:orientation="vertical"
+            android:elevation="0dp"
+            android:background="?android:attr/colorBackground">
+
+            <androidx.appcompat.widget.Toolbar
+                android:id="@+id/roots_toolbar"
+                android:layout_width="match_parent"
+                android:layout_height="?android:attr/actionBarSize"
+                android:background="?android:attr/colorBackground"
+                android:elevation="0dp"
+                app:titleTextAppearance="@style/DrawerMenuTitle"
+                app:titleTextColor="?android:colorAccent"/>
+
+            <FrameLayout
+                android:id="@+id/container_roots"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_weight="1" />
+
+        </LinearLayout>
+
+    </androidx.drawerlayout.widget.DrawerLayout>
+</androidx.coordinatorlayout.widget.CoordinatorLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/drop_badge.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/drop_badge.xml
new file mode 100644
index 000000000..e2f0d35cd
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/drop_badge.xml
@@ -0,0 +1,24 @@
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
+
+<com.android.documentsui.DropBadgeView
+        xmlns:android="http://schemas.android.com/apk/res/android"
+        android:id="@android:id/icon"
+        android:layout_width="26dp"
+        android:layout_height="26dp"
+        android:scaleType="centerInside"
+        android:contentDescription="@null"
+        android:duplicateParentState="true"/>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/fixed_layout.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/fixed_layout.xml
new file mode 100644
index 000000000..682edcb7d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/fixed_layout.xml
@@ -0,0 +1,115 @@
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
+
+<!-- CoordinatorLayout is necessary for various components (e.g. Snackbars, and
+     floating action buttons) to operate correctly. -->
+<androidx.coordinatorlayout.widget.CoordinatorLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:id="@+id/coordinator_layout"
+    android:focusable="true">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:background="?attr/colorSurfaceContainer"
+        android:orientation="vertical">
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="0dp"
+            android:layout_weight="1"
+            android:orientation="horizontal"
+            android:baselineAligned="false">
+
+            <FrameLayout
+                android:id="@+id/container_roots"
+                android:layout_width="256dp"
+                android:layout_height="match_parent"
+                android:layout_marginTop="@dimen/space_medium_1"
+                />
+
+            <LinearLayout
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:orientation="vertical"
+                android:background="@drawable/main_container_background"
+                android:layout_margin="@dimen/space_small_1"
+                android:layout_marginStart="0dp">
+
+                <androidx.appcompat.widget.Toolbar
+                    android:id="@+id/toolbar"
+                    android:layout_width="match_parent"
+                    android:layout_height="?android:attr/actionBarSize"
+                    android:layout_margin="@dimen/search_bar_margin"
+                    android:elevation="3dp"
+                    android:popupTheme="?actionBarPopupTheme"
+                    android:theme="?actionBarTheme"
+                    app:collapseContentDescription="@string/button_back"
+                    app:titleTextAppearance="@style/ToolbarTitle">
+
+                    <TextView
+                        android:id="@+id/searchbar_title"
+                        android:layout_width="match_parent"
+                        android:layout_height="?android:attr/actionBarSize"
+                        android:layout_marginEnd="@dimen/search_bar_text_margin_end"
+                        android:layout_marginStart="@dimen/search_bar_text_margin_start"
+                        android:drawablePadding="@dimen/search_bar_icon_padding"
+                        android:drawableStart="@drawable/ic_menu_search"
+                        android:gravity="center_vertical"
+                        android:paddingStart="@dimen/search_bar_icon_padding"
+                        android:text="@string/search_bar_hint"
+                        android:textAppearance="@style/SearchBarTitle" />
+
+                </androidx.appcompat.widget.Toolbar>
+
+                <include layout="@layout/directory_header" />
+
+                <FrameLayout
+                    android:layout_width="match_parent"
+                    android:layout_height="0dp"
+                    android:layout_weight="1">
+
+                    <FrameLayout
+                        android:id="@+id/container_directory"
+                        android:clipToPadding="false"
+                        android:layout_width="match_parent"
+                        android:layout_height="match_parent" />
+
+                    <FrameLayout
+                        android:id="@+id/container_search_fragment"
+                        android:clipToPadding="false"
+                        android:layout_width="match_parent"
+                        android:layout_height="match_parent" />
+
+                </FrameLayout>
+
+                <androidx.coordinatorlayout.widget.CoordinatorLayout
+                    android:id="@+id/container_save"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:background="?android:attr/colorBackgroundFloating"
+                    android:elevation="8dp" />
+
+            </LinearLayout>
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+</androidx.coordinatorlayout.widget.CoordinatorLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_directory.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_directory.xml
new file mode 100644
index 000000000..f424e407d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_directory.xml
@@ -0,0 +1,53 @@
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
+
+<com.android.documentsui.dirlist.AnimationView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical">
+
+    <ProgressBar
+        android:id="@+id/progressbar"
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/progress_bar_height"
+        android:indeterminate="true"
+        style="@style/TrimmedHorizontalProgressBar"
+        android:visibility="gone"/>
+
+    <com.android.documentsui.dirlist.DocumentsSwipeRefreshLayout
+        android:id="@+id/refresh_layout"
+        android:background="@android:color/transparent"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent">
+
+        <androidx.recyclerview.widget.RecyclerView
+            android:id="@+id/dir_list"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:paddingStart="0dp"
+            android:paddingEnd="0dp"
+            android:paddingTop="0dp"
+            android:paddingBottom="0dp"
+            android:clipToPadding="false"
+            android:scrollbars="none"
+            android:drawSelectorOnTop="true"
+            app:fastScrollEnabled="false"/>
+
+    </com.android.documentsui.dirlist.DocumentsSwipeRefreshLayout>
+
+</com.android.documentsui.dirlist.AnimationView>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_pick.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_pick.xml
new file mode 100644
index 000000000..742861a3e
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_pick.xml
@@ -0,0 +1,60 @@
+<?xml version="1.0" encoding="utf-8"?><!-- Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="horizontal"
+    android:baselineAligned="false"
+    android:gravity="center_vertical|end"
+    android:paddingStart="@dimen/bottom_bar_padding"
+    android:paddingEnd="@dimen/bottom_bar_padding">
+
+    <com.google.android.material.button.MaterialButton
+        android:id="@android:id/button2"
+        style="?attr/materialButtonOutlinedStyle"
+        app:cornerRadius="@dimen/button_corner_radius"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginStart="4dp"
+        android:layout_marginEnd="4dp"
+        android:text="@android:string/cancel" />
+
+    <FrameLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent">
+
+        <com.google.android.material.button.MaterialButton
+            android:id="@android:id/button1"
+            style="?attr/materialButtonStyle"
+            app:cornerRadius="@dimen/button_corner_radius"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="4dp"
+            android:backgroundTint="@color/fragment_pick_button_background_color"
+            android:textColor="@color/fragment_pick_button_text_color"
+            android:layout_marginEnd="4dp" />
+
+        <!-- Handles touch events when button1 is disabled. -->
+        <FrameLayout
+            android:id="@+id/pick_button_overlay"
+            android:importantForAccessibility="no"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent" />
+
+    </FrameLayout>
+
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_roots.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_roots.xml
new file mode 100644
index 000000000..97363208b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_roots.xml
@@ -0,0 +1,23 @@
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
+
+<com.android.documentsui.sidebar.RootsList xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/roots_list"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:paddingTop="8dp"
+    android:keyboardNavigationCluster="true"
+    android:divider="@null"/>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_save.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_save.xml
new file mode 100644
index 000000000..401eaec88
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_save.xml
@@ -0,0 +1,76 @@
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
+
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingStart="@dimen/list_item_padding"
+    android:paddingEnd="@dimen/bottom_bar_padding"
+    android:orientation="horizontal"
+    android:baselineAligned="false"
+    android:gravity="center_vertical"
+    android:minHeight="?android:attr/listPreferredItemHeightSmall">
+
+    <FrameLayout
+        android:layout_width="@dimen/icon_size"
+        android:layout_height="@dimen/icon_size"
+        android:layout_marginEnd="16dp">
+
+        <ImageView
+            android:id="@android:id/icon"
+            android:layout_width="@dimen/root_icon_size"
+            android:layout_height="match_parent"
+            android:scaleType="centerInside"
+            android:contentDescription="@null" />
+
+    </FrameLayout>
+
+    <EditText
+        android:id="@android:id/title"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:singleLine="true"
+        android:selectAllOnFocus="true" />
+
+    <FrameLayout
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent">
+
+        <com.google.android.material.button.MaterialButton
+            android:id="@android:id/button1"
+            style="@style/Widget.Material3.Button.UnelevatedButton"
+            app:cornerRadius="@dimen/button_corner_radius"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="4dp"
+            android:layout_marginEnd="4dp"
+            android:text="@string/menu_save"/>
+
+        <ProgressBar
+            android:id="@android:id/progress"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center"
+            android:visibility="gone"
+            android:indeterminate="true"
+            android:padding="8dp"
+            style="?android:attr/progressBarStyle" />
+
+    </FrameLayout>
+
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_search.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_search.xml
new file mode 100644
index 000000000..75608a888
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/fragment_search.xml
@@ -0,0 +1,34 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:orientation="vertical"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:background="?android:attr/colorBackground">
+
+    <!-- used for search chip. -->
+    <include layout="@layout/search_chip_row"/>
+
+    <ListView
+        android:id="@+id/history_list"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:divider="@null"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_action_view.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_action_view.xml
new file mode 100644
index 000000000..c67233e1f
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_action_view.xml
@@ -0,0 +1,58 @@
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
+<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent">
+
+    <include
+        layout="@layout/inspector_section_title"
+        android:id="@+id/action_header" />
+
+    <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+        android:id="@+id/default_app_info"
+        android:paddingLeft="16dp"
+        android:paddingRight="16dp"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:paddingBottom="10dp"
+        android:layout_below="@id/action_header">
+
+        <ImageView
+            android:id="@+id/app_icon"
+            android:paddingLeft="5dp"
+            android:layout_width="50dp"
+            android:layout_height="50dp" />
+
+        <TextView
+            android:id="@+id/app_name"
+            android:paddingLeft="16dp"
+            android:paddingBottom="10dp"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_toRightOf="@id/app_icon"
+            android:layout_centerVertical="true"/>
+
+        <ImageButton
+            android:id="@+id/inspector_action_button"
+            android:layout_width="50dp"
+            android:layout_height="50dp"
+            android:layout_alignParentRight="true"
+            android:layout_centerVertical="true"
+            android:background="@null"/>
+
+        </RelativeLayout>
+
+</RelativeLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_activity.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_activity.xml
new file mode 100644
index 000000000..c7a34a1e6
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_activity.xml
@@ -0,0 +1,119 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<androidx.coordinatorlayout.widget.CoordinatorLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/inspector_root"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent">
+
+    <com.google.android.material.appbar.AppBarLayout
+        android:id="@+id/app_bar"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:background="?android:colorBackground">
+
+        <com.google.android.material.appbar.CollapsingToolbarLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:minHeight="?android:attr/actionBarSize"
+            app:titleEnabled="false"
+            app:statusBarScrim="@android:color/transparent"
+            app:layout_scrollFlags="scroll|exitUntilCollapsed">
+
+            <LinearLayout
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:orientation="vertical">
+
+                <android.widget.Space
+                    android:layout_width="match_parent"
+                    android:layout_height="?android:attr/actionBarSize"/>
+
+                <com.android.documentsui.inspector.HeaderView
+                    android:id="@+id/inspector_header_view"
+                    android:layout_width="match_parent"
+                    android:layout_height="@dimen/inspector_header_height"
+                    app:layout_collapseMode="parallax"/>
+            </LinearLayout>
+
+            <androidx.appcompat.widget.Toolbar
+                android:id="@+id/toolbar"
+                android:layout_width="match_parent"
+                android:layout_height="?android:attr/actionBarSize"
+                android:background="?android:attr/colorBackground"
+                android:theme="?actionBarTheme"
+                app:title="@string/inspector_title"
+                app:titleTextAppearance="@style/ToolbarTitle"
+                app:layout_collapseMode="pin">
+            </androidx.appcompat.widget.Toolbar>
+        </com.google.android.material.appbar.CollapsingToolbarLayout>
+    </com.google.android.material.appbar.AppBarLayout>
+
+    <androidx.core.widget.NestedScrollView
+        android:orientation="vertical"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        app:behavior_overlapTop="10dp"
+        app:layout_behavior="@string/appbar_scrolling_view_behavior">
+
+        <LinearLayout
+            android:id="@+id/inspector_container"
+            android:orientation="vertical"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@drawable/bottom_sheet_dialog_background"
+            android:paddingBottom="5dp">
+
+            <com.android.documentsui.inspector.DetailsView
+                android:id="@+id/inspector_details_view"
+                android:orientation="vertical"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"/>
+
+            <com.android.documentsui.inspector.MediaView
+                android:id="@+id/inspector_media_view"
+                android:orientation="vertical"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"/>
+
+            <com.android.documentsui.inspector.actions.ActionView
+                android:id="@+id/inspector_show_in_provider_view"
+                android:orientation="vertical"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:visibility="gone"/>
+
+            <com.android.documentsui.inspector.actions.ActionView
+                android:id="@+id/inspector_app_defaults_view"
+                android:orientation="vertical"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:visibility="gone"/>
+
+            <com.android.documentsui.inspector.DebugView
+                android:id="@+id/inspector_debug_view"
+                android:orientation="vertical"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:paddingTop="20dp"
+                android:visibility="gone" />
+
+        </LinearLayout>
+    </androidx.core.widget.NestedScrollView>
+
+</androidx.coordinatorlayout.widget.CoordinatorLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_header.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_header.xml
new file mode 100644
index 000000000..a44ed0b76
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_header.xml
@@ -0,0 +1,29 @@
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
+
+<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent">
+
+    <ImageView
+        android:id="@+id/inspector_thumbnail"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:scaleType="fitCenter"
+        android:alpha="0.0"
+        android:background="?android:colorBackgroundFloating" />
+
+</RelativeLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_section_title.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_section_title.xml
new file mode 100644
index 000000000..d98fa143a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/inspector_section_title.xml
@@ -0,0 +1,45 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_height="wrap_content"
+    android:layout_width="match_parent"
+    android:orientation="vertical"
+    android:divider="@drawable/inspector_separator"
+    android:showDividers="beginning"
+    android:paddingStart="10dp"
+    android:paddingEnd="10dp">
+
+    <!--Empty view for keeping divider when title is gone-->
+    <android.widget.Space
+        android:layout_height="wrap_content"
+        android:layout_width="wrap_content">
+    </android.widget.Space >
+
+    <TextView
+        android:layout_height="match_parent"
+        android:layout_width="match_parent"
+        android:id="@+id/inspector_header_title"
+        android:paddingStart="16dp"
+        android:paddingEnd="16dp"
+        android:paddingTop="25dp"
+        android:paddingBottom="25dp"
+        android:layout_gravity="center_vertical"
+        android:clickable="false"
+        android:textAppearance="@style/ToolbarTitle"
+        android:textAlignment="viewStart"
+        android:textIsSelectable="true"/>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_dir_grid.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_dir_grid.xml
new file mode 100644
index 000000000..44a53325d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_dir_grid.xml
@@ -0,0 +1,116 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
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
+<!-- FYI: This layout has an extra top level container view that was previously used
+     to allow for the insertion of debug info. The debug info is now gone, but the
+     container remains because there is a high likelihood of UI regression relating
+     to focus and selection states, some of which are specific to keyboard
+     when touch mode is not enable. So, if you, heroic engineer of the future,
+     decide to rip these out, please be sure to check out focus and keyboards. -->
+<com.google.android.material.card.MaterialCardView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/item_root"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layout_margin="4dp"
+    android:foreground="?android:attr/selectableItemBackground"
+    android:clickable="true"
+    android:focusable="true"
+    app:cardElevation="0dp">
+
+    <com.google.android.material.card.MaterialCardView
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:elevation="0dp"
+        android:duplicateParentState="true"
+        app:cardElevation="0dp"
+        app:strokeWidth="1dp"
+        app:strokeColor="?android:strokeColor">
+
+        <!-- The height is 48px.
+             paddingTop (9dp) + @dimen/check_icon_size (30dp) + paddingBottom (9dp) -->
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:orientation="horizontal"
+            android:background="?android:attr/colorBackground"
+            android:gravity="center_vertical">
+
+            <FrameLayout
+                android:id="@+id/icon"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:pointerIcon="hand"
+                android:paddingBottom="9dp"
+                android:paddingStart="9dp"
+                android:paddingEnd="8dp"
+                android:paddingTop="9dp">
+
+                <ImageView
+                    android:id="@+id/icon_mime_sm"
+                    android:layout_width="@dimen/grid_item_icon_size"
+                    android:layout_height="@dimen/grid_item_icon_size"
+                    android:layout_gravity="center"
+                    android:contentDescription="@null"
+                    android:scaleType="centerInside"/>
+
+                <ImageView
+                    android:id="@+id/icon_check"
+                    android:layout_width="@dimen/check_icon_size"
+                    android:layout_height="@dimen/check_icon_size"
+                    android:alpha="0"
+                    android:contentDescription="@null"
+                    android:scaleType="fitCenter"
+                    android:src="@drawable/ic_check_circle"/>
+
+            </FrameLayout>
+
+            <ImageView
+                android:id="@+id/icon_profile_badge"
+                android:layout_height="@dimen/briefcase_icon_size"
+                android:layout_width="@dimen/briefcase_icon_size"
+                android:layout_marginEnd="@dimen/briefcase_icon_margin"
+                android:src="@drawable/ic_briefcase"
+                android:tint="?android:attr/colorAccent"
+                android:contentDescription="@string/a11y_work"/>
+
+            <TextView
+                android:id="@android:id/title"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:ellipsize="end"
+                android:singleLine="true"
+                android:textAlignment="viewStart"
+                android:textAppearance="@style/CardPrimaryText"
+                android:layout_marginBottom="9dp"
+                android:layout_marginEnd="12dp"
+                android:layout_marginTop="9dp"/>
+
+        </LinearLayout>
+
+    </com.google.android.material.card.MaterialCardView>
+
+    <!-- An overlay that draws the item border when it is focused. -->
+    <View
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:background="@drawable/item_doc_grid_border_rounded"
+        android:contentDescription="@null"
+        android:duplicateParentState="true"/>
+
+</com.google.android.material.card.MaterialCardView>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_grid.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_grid.xml
new file mode 100644
index 000000000..32596f2f4
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_grid.xml
@@ -0,0 +1,209 @@
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
+
+<!-- FYI: This layout has an extra top level container view that was previously used
+     to allow for the insertion of debug info. The debug info is now gone, but the
+     container remains because there is a high likelihood of UI regression relating
+     to focus and selection states, some of which are specific to keyboard
+     when touch mode is not enable. So, if you, heroic engineer of the future,
+     decide to rip these out, please be sure to check out focus and keyboards. -->
+<com.google.android.material.card.MaterialCardView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/item_root"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layout_margin="4dp"
+    android:foreground="?android:attr/selectableItemBackground"
+    android:clickable="true"
+    android:focusable="true"
+    app:cardElevation="0dp">
+
+    <com.google.android.material.card.MaterialCardView
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:elevation="0dp"
+        android:duplicateParentState="true"
+        app:cardElevation="0dp"
+        app:strokeWidth="1dp"
+        app:strokeColor="?android:strokeColor">
+
+        <RelativeLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:duplicateParentState="true">
+
+            <!-- Main item thumbnail.  Comprised of two overlapping images, the
+                 visibility of which is controlled by code in
+                 DirectoryFragment.java. -->
+
+            <FrameLayout
+                android:id="@+id/thumbnail"
+                android:background="?attr/gridItemTint"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content">
+
+                <com.android.documentsui.GridItemThumbnail
+                    android:id="@+id/icon_thumb"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:scaleType="centerCrop"
+                    android:contentDescription="@null"
+                    android:tint="?attr/gridItemTint"
+                    android:tintMode="src_over"/>
+
+                <com.android.documentsui.GridItemThumbnail
+                    android:id="@+id/icon_mime_lg"
+                    android:layout_width="@dimen/icon_size"
+                    android:layout_height="@dimen/icon_size"
+                    android:layout_gravity="center"
+                    android:scaleType="fitCenter"
+                    android:contentDescription="@null"/>
+
+            </FrameLayout>
+
+            <FrameLayout
+                android:id="@+id/preview_icon"
+                android:layout_width="@dimen/button_touch_size"
+                android:layout_height="@dimen/button_touch_size"
+                android:layout_alignParentTop="true"
+                android:layout_alignParentEnd="true"
+                android:pointerIcon="hand"
+                android:focusable="true"
+                android:clickable="true">
+
+                <ImageView
+                    android:layout_width="@dimen/zoom_icon_size"
+                    android:layout_height="@dimen/zoom_icon_size"
+                    android:padding="2dp"
+                    android:layout_gravity="center"
+                    android:background="@drawable/circle_button_background"
+                    android:scaleType="fitCenter"
+                    android:src="@drawable/ic_zoom_out"/>
+
+            </FrameLayout>
+
+            <!-- Item nameplate.  Has a mime-type icon and some text fields (title,
+                 size, mod-time, etc). -->
+
+            <LinearLayout
+                android:id="@+id/nameplate"
+                android:background="?android:attr/colorBackground"
+                android:orientation="horizontal"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_below="@id/thumbnail">
+
+                <FrameLayout
+                    android:id="@+id/icon"
+                    android:layout_width="wrap_content"
+                    android:layout_height="match_parent"
+                    android:layout_centerVertical="true"
+                    android:pointerIcon="hand"
+                    android:paddingTop="8dp"
+                    android:paddingBottom="8dp"
+                    android:paddingStart="12dp"
+                    android:paddingEnd="8dp">
+
+                    <ImageView
+                        android:id="@+id/icon_mime_sm"
+                        android:layout_width="@dimen/grid_item_icon_size"
+                        android:layout_height="@dimen/grid_item_icon_size"
+                        android:layout_gravity="center"
+                        android:scaleType="center"
+                        android:contentDescription="@null"/>
+
+                    <ImageView
+                        android:id="@+id/icon_check"
+                        android:src="@drawable/ic_check_circle"
+                        android:alpha="0"
+                        android:layout_width="@dimen/check_icon_size"
+                        android:layout_height="@dimen/check_icon_size"
+                        android:layout_gravity="center"
+                        android:scaleType="fitCenter"
+                        android:contentDescription="@null"/>
+
+                </FrameLayout>
+
+                <RelativeLayout
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:paddingBottom="8dp"
+                    android:paddingTop="8dp"
+                    android:paddingEnd="12dp">
+
+                    <ImageView
+                        android:id="@+id/icon_profile_badge"
+                        android:layout_height="@dimen/briefcase_icon_size"
+                        android:layout_width="@dimen/briefcase_icon_size"
+                        android:layout_marginEnd="@dimen/briefcase_icon_margin"
+                        android:layout_alignTop="@android:id/title"
+                        android:layout_alignBottom="@android:id/title"
+                        android:gravity="center_vertical"
+                        android:src="@drawable/ic_briefcase"
+                        android:tint="?android:attr/colorAccent"
+                        android:contentDescription="@string/a11y_work"/>
+
+                    <TextView
+                        android:id="@android:id/title"
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:layout_alignParentTop="true"
+                        android:layout_toEndOf="@+id/icon_profile_badge"
+                        android:singleLine="true"
+                        android:ellipsize="end"
+                        android:textAlignment="viewStart"
+                        android:textAppearance="@style/CardPrimaryText"/>
+
+                    <TextView
+                        android:id="@+id/details"
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:layout_below="@android:id/title"
+                        android:layout_marginEnd="4dp"
+                        android:singleLine="true"
+                        android:ellipsize="end"
+                        android:textAlignment="viewStart"
+                        android:textAppearance="@style/ItemCaptionText" />
+
+                    <TextView
+                        android:id="@+id/date"
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:layout_below="@android:id/title"
+                        android:layout_toEndOf="@id/details"
+                        android:singleLine="true"
+                        android:ellipsize="end"
+                        android:textAlignment="viewStart"
+                        android:textAppearance="@style/ItemCaptionText" />
+
+                </RelativeLayout>
+
+            </LinearLayout>
+
+        </RelativeLayout>
+
+    </com.google.android.material.card.MaterialCardView>
+
+    <!-- An overlay that draws the item border when it is focused. -->
+    <View
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:background="@drawable/item_doc_grid_border_rounded"
+        android:contentDescription="@null"
+        android:duplicateParentState="true"/>
+
+</com.google.android.material.card.MaterialCardView>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_header_message.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_header_message.xml
new file mode 100644
index 000000000..86fa60ccc
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_header_message.xml
@@ -0,0 +1,116 @@
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
+
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/item_root"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content">
+
+    <com.google.android.material.card.MaterialCardView
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_margin="4dp"
+        android:elevation="0dp"
+        android:duplicateParentState="true"
+        app:cardElevation="0dp"
+        app:strokeWidth="1dp"
+        app:strokeColor="?android:strokeColor">
+
+        <LinearLayout
+            android:layout_height="wrap_content"
+            android:layout_width="match_parent"
+            android:background="?android:attr/colorBackground"
+            android:orientation="vertical">
+
+            <LinearLayout
+                android:animateLayoutChanges="true"
+                android:id="@+id/message_container"
+                android:layout_height="wrap_content"
+                android:layout_width="match_parent"
+                android:minHeight="60dp"
+                android:orientation="horizontal">
+
+                <ImageView
+                    android:contentDescription="@null"
+                    android:id="@+id/message_icon"
+                    android:layout_height="@dimen/icon_size"
+                    android:layout_width="@dimen/icon_size"
+                    android:layout_margin="8dp"
+                    android:layout_gravity="center"
+                    android:scaleType="centerInside"/>
+
+                <LinearLayout
+                    android:layout_height="wrap_content"
+                    android:layout_width="match_parent"
+                    android:minHeight="48dp"
+                    android:paddingTop="12dp"
+                    android:paddingEnd="12dp"
+                    android:gravity="center_vertical"
+                    android:orientation="vertical">
+
+                    <TextView
+                        android:id="@+id/message_title"
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:textSize="16sp"
+                        android:textAppearance="@style/DrawerMenuPrimary"/>
+
+                    <TextView
+                        android:id="@+id/message_subtitle"
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:selectAllOnFocus="true"
+                        android:textSize="12sp"/>
+
+                    <TextView
+                        android:id="@+id/message_textview"
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:selectAllOnFocus="true"/>
+
+                    <Button
+                        android:id="@+id/dismiss_button"
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:layout_gravity="end"
+                        android:text="@android:string/ok"
+                        style="@style/DialogTextButton"/>
+
+                </LinearLayout>
+            </LinearLayout>
+
+            <LinearLayout
+                android:id="@+id/action_view"
+                android:layout_height="wrap_content"
+                android:layout_width="match_parent"
+                android:orientation="vertical">
+
+                <Button
+                    android:id="@+id/action_button"
+                    android:layout_height="wrap_content"
+                    android:layout_width="wrap_content"
+                    android:layout_marginEnd="16dp"
+                    android:layout_gravity="end"
+                    style="@style/DialogTextButton"/>
+
+            </LinearLayout>
+
+        </LinearLayout>
+
+    </com.google.android.material.card.MaterialCardView>
+</FrameLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message.xml
new file mode 100644
index 000000000..26f5a8ee7
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message.xml
@@ -0,0 +1,28 @@
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
+
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@android:id/empty"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:background="?android:attr/colorBackground"
+    android:focusable="true">
+
+    <include android:id="@+id/content" layout="@layout/item_doc_inflated_message_content"/>
+    <include android:id="@+id/cross_profile"
+             layout="@layout/item_doc_inflated_message_cross_profile"/>
+</FrameLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_content.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_content.xml
new file mode 100644
index 000000000..7645b6cd5
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_content.xml
@@ -0,0 +1,45 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/content"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical">
+
+    <ImageView
+        android:id="@+id/artwork"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="25dp"
+        android:layout_marginBottom="25dp"
+        android:scaleType="fitCenter"
+        android:maxHeight="250dp"
+        android:adjustViewBounds="true"
+        android:gravity="bottom|center_horizontal"
+        android:contentDescription="@null"/>
+
+    <TextView
+        android:id="@+id/message"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginBottom="25dp"
+        android:gravity="center_horizontal"
+        style="?android:attr/textAppearanceListItem"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_cross_profile.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_cross_profile.xml
new file mode 100644
index 000000000..4a77c702e
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_inflated_message_cross_profile.xml
@@ -0,0 +1,73 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:gravity="center_horizontal"
+    android:paddingTop="@dimen/item_doc_inflated_message_padding_top"
+    android:paddingStart="72dp"
+    android:paddingEnd="72dp">
+
+    <ProgressBar
+        android:id="@+id/cross_profile_progress"
+        style="@android:style/Widget.Material.Light.ProgressBar"
+        android:visibility="gone"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:indeterminate="true"
+        android:indeterminateTint="?attr/colorAccent"/>
+
+    <LinearLayout
+        android:id="@+id/cross_profile_content"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="vertical"
+        android:gravity="center_horizontal">
+
+        <ImageView
+            android:id="@+id/artwork"
+            android:layout_width="24dp"
+            android:layout_height="24dp"/>
+        <TextView
+            android:id="@+id/title"
+            android:layout_marginTop="8dp"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:gravity="center_horizontal"
+            android:textAppearance="@style/EmptyStateTitleText"/>
+        <TextView
+            android:id="@+id/message"
+            android:layout_marginTop="@dimen/cross_profile_button_message_margin_top"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:gravity="center_horizontal"
+            android:textAppearance="@style/EmptyStateMessageText"/>
+        <Button
+            android:id="@+id/button"
+            android:layout_marginTop="16dp"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:cornerRadius="@dimen/cross_profile_button_corner_radius"
+            app:strokeWidth="@dimen/cross_profile_button_stroke_width"
+            app:strokeColor="@color/work_profile_button_stroke_color"
+            style="@style/EmptyStateButton"/>
+    </LinearLayout>
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_list.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_list.xml
new file mode 100644
index 000000000..055c1b203
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_doc_list.xml
@@ -0,0 +1,163 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+     Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/item_root"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:background="@drawable/list_item_background"
+    android:foreground="?android:attr/selectableItemBackground"
+    android:clickable="true"
+    android:focusable="true"
+    android:orientation="vertical">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:baselineAligned="false"
+        android:gravity="center_vertical"
+        android:minHeight="@dimen/list_item_height"
+        android:orientation="horizontal">
+
+      <FrameLayout
+          android:id="@+id/icon"
+          android:pointerIcon="hand"
+          android:layout_width="@dimen/list_item_width"
+          android:layout_height="@dimen/list_item_height"
+          android:paddingBottom="@dimen/list_item_icon_padding"
+          android:paddingTop="@dimen/list_item_icon_padding"
+          android:paddingEnd="16dp"
+          android:paddingStart="@dimen/list_item_padding">
+
+        <com.google.android.material.card.MaterialCardView
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            app:cardBackgroundColor="@android:color/transparent"
+            app:cardElevation="0dp">
+
+          <ImageView
+              android:id="@+id/icon_mime"
+              android:layout_width="wrap_content"
+              android:layout_height="wrap_content"
+              android:layout_gravity="center"
+              android:contentDescription="@null"
+              android:scaleType="centerInside" />
+
+          <ImageView
+              android:id="@+id/icon_thumb"
+              android:layout_width="match_parent"
+              android:layout_height="match_parent"
+              android:contentDescription="@null"
+              android:scaleType="centerCrop" />
+
+          <ImageView
+              android:id="@+id/icon_check"
+              android:layout_width="@dimen/check_icon_size"
+              android:layout_height="@dimen/check_icon_size"
+              android:layout_gravity="center"
+              android:alpha="0"
+              android:contentDescription="@null"
+              android:scaleType="fitCenter"
+              android:src="@drawable/ic_check_circle" />
+
+        </com.google.android.material.card.MaterialCardView>
+
+      </FrameLayout>
+
+      <LinearLayout
+          android:layout_width="0dp"
+          android:layout_height="wrap_content"
+          android:layout_weight="1"
+          android:orientation="vertical"
+          android:layout_gravity="center_vertical"
+          android:layout_marginEnd="@dimen/list_item_padding">
+
+        <LinearLayout
+            android:layout_width="wrap_content"
+            android:layout_height="0dp"
+            android:layout_weight="1">
+
+          <ImageView
+              android:id="@+id/icon_profile_badge"
+              android:layout_height="@dimen/briefcase_icon_size"
+              android:layout_width="@dimen/briefcase_icon_size"
+              android:layout_marginEnd="@dimen/briefcase_icon_margin"
+              android:layout_gravity="center_vertical"
+              android:src="@drawable/ic_briefcase"
+              android:tint="?android:attr/colorAccent"
+              android:contentDescription="@string/a11y_work" />
+
+          <TextView
+              android:id="@android:id/title"
+              android:layout_width="wrap_content"
+              android:layout_height="wrap_content"
+              android:ellipsize="end"
+              android:singleLine="true"
+              android:textAlignment="viewStart"
+              android:textAppearance="?android:attr/textAppearanceListItem" />
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/line2"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:baselineAligned="false"
+            android:layout_marginTop="4dp"
+            android:gravity="center_vertical"
+            android:orientation="horizontal">
+
+          <TextView
+              android:id="@+id/metadata"
+              android:layout_width="wrap_content"
+              android:layout_height="wrap_content"
+              android:ellipsize="end"
+              android:singleLine="true"
+              android:textAppearance="@style/ItemCaptionText" />
+
+        </LinearLayout>
+
+      </LinearLayout>
+
+      <FrameLayout
+          android:id="@+id/preview_icon"
+          android:layout_width="@dimen/list_item_width"
+          android:layout_height="@dimen/list_item_height"
+          android:padding="@dimen/list_item_icon_padding"
+          android:focusable="true"
+          android:clickable="true">
+
+        <ImageView
+            android:layout_width="@dimen/check_icon_size"
+            android:layout_height="@dimen/check_icon_size"
+            android:layout_gravity="center"
+            android:scaleType="fitCenter"
+            android:tint="?android:attr/colorControlNormal"
+            android:src="@drawable/ic_zoom_out" />
+
+      </FrameLayout>
+
+    </LinearLayout>
+
+  <View
+      android:layout_width="match_parent"
+      android:layout_height="1dp"
+      android:layout_marginStart="72dp"
+      android:layout_marginEnd="8dp"
+      android:background="?android:strokeColor" />
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_history.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_history.xml
new file mode 100644
index 000000000..2936741e5
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_history.xml
@@ -0,0 +1,50 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:orientation="horizontal"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:minHeight="?android:attr/listPreferredItemHeight"
+    android:paddingStart="?android:attr/listPreferredItemPaddingStart"
+    android:paddingEnd="?android:attr/listPreferredItemPaddingEnd"
+    android:gravity="center_vertical">
+
+    <ImageView
+        android:layout_width="@dimen/button_touch_size"
+        android:layout_height="@dimen/button_touch_size"
+        android:src="@drawable/ic_history"
+        android:scaleType="centerInside"/>
+
+    <TextView
+        android:id="@android:id/title"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:paddingStart="?android:attr/listPreferredItemPaddingStart"
+        android:textAppearance="?android:attr/textAppearanceListItem"
+        android:ellipsize="end"
+        android:singleLine="true"
+        android:gravity="center_vertical"/>
+
+    <ImageView
+        android:id="@android:id/icon"
+        android:layout_width="@dimen/button_touch_size"
+        android:layout_height="@dimen/button_touch_size"
+        android:background="@drawable/generic_ripple_background"
+        android:src="@drawable/ic_action_clear"
+        android:scaleType="centerInside"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_photo_grid.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_photo_grid.xml
new file mode 100644
index 000000000..cd7e8f945
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_photo_grid.xml
@@ -0,0 +1,141 @@
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
+
+<!-- FYI: This layout has an extra top level container view that was previously used
+     to allow for the insertion of debug info. The debug info is now gone, but the
+     container remains because there is a high likelihood of UI regression relating
+     to focus and selection states, some of which are specific to keyboard
+     when touch mode is not enable. So, if you, heroic engineer of the future,
+     decide to rip these out, please be sure to check out focus and keyboards. -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:layout_margin="4dp"
+    android:background="@drawable/grid_item_background"
+    android:elevation="@dimen/grid_item_elevation"
+    android:focusable="true">
+
+    <RelativeLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:duplicateParentState="true">
+
+        <!-- Main item thumbnail. Comprised of two overlapping images, the
+             visibility of which is controlled by code in
+             DirectoryFragment.java. -->
+
+        <FrameLayout
+            android:id="@+id/thumbnail"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content">
+
+            <com.android.documentsui.GridItemThumbnail
+                android:id="@+id/icon_thumb"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:scaleType="centerCrop"
+                android:contentDescription="@null"
+                android:tint="?attr/gridItemTint"
+                android:tintMode="src_over"/>
+
+            <com.android.documentsui.GridItemThumbnail
+                android:id="@+id/icon_mime_lg"
+                android:layout_width="@dimen/icon_size"
+                android:layout_height="@dimen/icon_size"
+                android:layout_gravity="center"
+                android:scaleType="fitCenter"
+                android:contentDescription="@null"/>
+
+        </FrameLayout>
+
+        <FrameLayout
+            android:layout_width="@dimen/button_touch_size"
+            android:layout_height="@dimen/button_touch_size"
+            android:layout_alignParentTop="true"
+            android:layout_alignParentStart="true"
+            android:pointerIcon="hand">
+
+            <ImageView
+                android:id="@+id/icon_check"
+                android:src="@drawable/ic_check_circle"
+                android:alpha="0"
+                android:layout_width="@dimen/check_icon_size"
+                android:layout_height="@dimen/check_icon_size"
+                android:layout_gravity="center"
+                android:scaleType="fitCenter"
+                android:contentDescription="@null"/>
+
+        </FrameLayout>
+
+        <FrameLayout
+            android:id="@+id/preview_icon"
+            android:layout_width="@dimen/button_touch_size"
+            android:layout_height="@dimen/button_touch_size"
+            android:layout_alignParentTop="true"
+            android:layout_alignParentEnd="true"
+            android:pointerIcon="hand"
+            android:focusable="true"
+            android:clickable="true">
+
+            <ImageView
+                android:layout_width="@dimen/zoom_icon_size"
+                android:layout_height="@dimen/zoom_icon_size"
+                android:padding="2dp"
+                android:layout_gravity="center"
+                android:background="@drawable/circle_button_background"
+                android:scaleType="fitCenter"
+                android:src="@drawable/ic_zoom_out"/>
+
+        </FrameLayout>
+
+        <FrameLayout
+            android:id="@+id/icon_profile_badge"
+            android:layout_width="@dimen/button_touch_size"
+            android:layout_height="@dimen/button_touch_size"
+            android:layout_alignParentBottom="true"
+            android:layout_alignParentEnd="true"
+            android:pointerIcon="hand">
+
+            <ImageView
+                android:id="@+id/icon_id"
+                android:layout_height="@dimen/briefcase_icon_size_photo"
+                android:layout_width="@dimen/briefcase_icon_size_photo"
+                android:src="@drawable/ic_briefcase_white"
+                android:tint="?android:attr/colorAccent"
+                android:padding="5dp"
+                android:background="@drawable/circle_button_background"
+                android:layout_gravity="center"
+                android:scaleType="fitCenter"
+                android:contentDescription="@string/a11y_work"/>
+        </FrameLayout>
+
+        <!-- An overlay that draws the item border when it is focused. -->
+        <View
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_alignBottom="@id/thumbnail"
+            android:layout_alignTop="@id/thumbnail"
+            android:layout_alignLeft="@id/thumbnail"
+            android:layout_alignRight="@id/thumbnail"
+            android:contentDescription="@null"
+            android:background="@drawable/item_doc_grid_border"
+            android:duplicateParentState="true"/>
+
+    </RelativeLayout>
+
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root.xml
new file mode 100644
index 000000000..14751c014
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root.xml
@@ -0,0 +1,92 @@
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
+
+<com.android.documentsui.sidebar.RootItemView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:minHeight="52dp"
+    android:paddingStart="24dp"
+    android:gravity="center_vertical"
+    android:orientation="horizontal"
+    android:baselineAligned="false"
+    android:background="@drawable/root_item_background">
+
+    <FrameLayout
+        android:layout_width="wrap_content"
+        android:layout_height="@dimen/icon_size"
+        android:duplicateParentState="true">
+
+        <ImageView
+            android:id="@android:id/icon"
+            android:layout_width="@dimen/root_icon_size"
+            android:layout_height="match_parent"
+            android:scaleType="centerInside"
+            android:contentDescription="@null"
+            android:duplicateParentState="true" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:paddingStart="16dp"
+        android:paddingTop="8dp"
+        android:paddingBottom="8dp"
+        android:orientation="vertical"
+        android:layout_weight="1">
+
+        <TextView
+            android:id="@android:id/title"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:singleLine="true"
+            android:ellipsize="end"
+            android:textAlignment="viewStart"
+            android:textAppearance="@style/DrawerMenuPrimary" />
+
+        <TextView
+            android:id="@android:id/summary"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:singleLine="true"
+            android:ellipsize="end"
+            android:textAlignment="viewStart"
+            android:textAppearance="@style/DrawerMenuSecondary" />
+
+    </LinearLayout>
+
+    <include layout="@layout/root_vertical_divider" />
+
+    <FrameLayout
+        android:id="@+id/action_icon_area"
+        android:layout_width="@dimen/button_touch_size"
+        android:layout_height="@dimen/button_touch_size"
+        android:paddingEnd="@dimen/grid_padding_horiz"
+        android:duplicateParentState="true"
+        android:visibility="gone">
+
+        <ImageView
+            android:id="@+id/action_icon"
+            android:focusable="false"
+            android:layout_width="@dimen/root_action_icon_size"
+            android:layout_height="match_parent"
+            android:layout_gravity="center"
+            android:scaleType="centerInside"/>
+
+    </FrameLayout>
+
+</com.android.documentsui.sidebar.RootItemView>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root_header.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root_header.xml
new file mode 100644
index 000000000..041164ae6
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root_header.xml
@@ -0,0 +1,33 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingTop="8dp"
+    android:paddingBottom="8dp"
+    android:gravity="center_vertical">
+
+    <TextView
+        android:id="@android:id/title"
+        android:paddingStart="64dp"
+        android:layout_width="wrap_content"
+        android:layout_height="44dp"
+        android:gravity="center_vertical"
+        style="@style/DrawerMenuHeader"/>
+
+</LinearLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root_spacer.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root_spacer.xml
new file mode 100644
index 000000000..83dcd818c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/item_root_spacer.xml
@@ -0,0 +1,29 @@
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
+
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingStart="@dimen/root_spacer_padding"
+    android:paddingTop="12dp"
+    android:paddingBottom="12dp">
+
+    <View
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:background="?android:attr/listDivider" />
+
+</FrameLayout>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/navigation_breadcrumb_item.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/navigation_breadcrumb_item.xml
new file mode 100644
index 000000000..672343795
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/navigation_breadcrumb_item.xml
@@ -0,0 +1,54 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
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
+
+<!--
+     CoordinatorLayout is necessary for various components (e.g. Snackbars, and
+     floating action buttons) to operate correctly.
+-->
+<!--
+     focusableInTouchMode is set in order to force key events to go to the activity's global key
+     callback, which is necessary for proper event routing. See BaseActivity.onKeyDown.
+-->
+
+<LinearLayout
+  xmlns:android="http://schemas.android.com/apk/res/android"
+  android:layout_width="wrap_content"
+  android:layout_height="wrap_content"
+  android:minHeight="48dp"
+  android:focusable="true"
+  android:gravity="center_vertical"
+  android:orientation="horizontal">
+
+    <TextView
+        android:id="@+id/breadcrumb_text"
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent"
+        android:maxWidth="275dp"
+        android:gravity="center_vertical"
+        android:maxLines="1"
+        android:ellipsize="end"
+        android:textAppearance="@style/BreadcrumbText"
+        android:background="@drawable/breadcrumb_item_background" />
+
+    <ImageView
+        android:id="@+id/breadcrumb_arrow"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:src="@drawable/ic_breadcrumb_arrow"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/root_vertical_divider.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/root_vertical_divider.xml
new file mode 100644
index 000000000..74316598d
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/root_vertical_divider.xml
@@ -0,0 +1,34 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/vertical_divider"
+    android:layout_width="wrap_content"
+    android:layout_height="match_parent"
+    android:gravity="start|center_vertical"
+    android:orientation="horizontal"
+    android:paddingTop="@dimen/drawer_edge_width"
+    android:paddingBottom="@dimen/drawer_edge_width"
+    android:paddingStart="@dimen/grid_padding_horiz"
+    android:paddingEnd="@dimen/grid_padding_horiz"
+    android:visibility="gone">
+    <View
+        android:layout_width="1dp"
+        android:layout_height="match_parent"
+        android:background="?android:attr/listDivider"/>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/search_chip_item.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/search_chip_item.xml
new file mode 100644
index 000000000..28f69981c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/search_chip_item.xml
@@ -0,0 +1,24 @@
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
+
+<com.google.android.material.chip.Chip
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    style="@style/SearchChipItemStyle"
+    app:chipIconVisible="true"
+/>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/search_chip_row.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/search_chip_row.xml
new file mode 100644
index 000000000..ef14bcdb2
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/search_chip_row.xml
@@ -0,0 +1,29 @@
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
+
+<HorizontalScrollView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:scrollbars="none">
+
+    <com.google.android.material.chip.ChipGroup
+        android:id="@+id/search_chip_group"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:paddingHorizontal="@dimen/search_chip_group_margin_horizontal"
+        android:paddingVertical="@dimen/search_chip_group_margin_vertical"/>
+</HorizontalScrollView>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/sort_list_item.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/sort_list_item.xml
new file mode 100644
index 000000000..ed25bf809
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/sort_list_item.xml
@@ -0,0 +1,25 @@
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
+
+<CheckedTextView xmlns:android="http://schemas.android.com/apk/res/android"
+                 android:id="@android:id/text1"
+                 android:layout_width="match_parent"
+                 android:layout_height="?android:attr/listPreferredItemHeightSmall"
+                 android:textAppearance="@style/SortList"
+                 android:gravity="center_vertical"
+                 android:checkMark="@drawable/list_checker"
+                 android:paddingStart="?android:attr/listPreferredItemPaddingStart"
+                 android:paddingEnd="?android:attr/listPreferredItemPaddingEnd" />
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/layout/table_key_value_row.xml b/res/flag(com.android.documentsui.flags.use_material3)/layout/table_key_value_row.xml
new file mode 100644
index 000000000..5214133dd
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/layout/table_key_value_row.xml
@@ -0,0 +1,50 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<com.android.documentsui.inspector.KeyValueRow
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:orientation="horizontal"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:paddingStart="30dp"
+    android:paddingEnd="30dp">
+
+    <TextView
+        android:id="@+id/table_row_key"
+        android:layout_height="wrap_content"
+        android:layout_width="0dp"
+        android:layout_weight="1"
+        android:paddingTop="13dp"
+        android:paddingBottom="13dp"
+        android:paddingEnd="5dp"
+        android:textAlignment="viewStart"
+        android:textAppearance="?attr/textAppearanceSubtitle1">
+    </TextView>
+
+    <TextView
+        android:id="@+id/table_row_value"
+        android:layout_height="wrap_content"
+        android:layout_width="0dp"
+        android:layout_weight="1"
+        android:paddingTop="13dp"
+        android:paddingBottom="13dp"
+        android:clickable="false"
+        android:textIsSelectable="true"
+        android:textAlignment="viewStart"
+        android:textAppearance="@style/InspectorKeySubTitle">
+    </TextView>
+
+</com.android.documentsui.inspector.KeyValueRow>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-night-v31/colors.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-night-v31/colors.xml
new file mode 100644
index 000000000..ab154150b
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-night-v31/colors.xml
@@ -0,0 +1,50 @@
+<?xml version="1.0" encoding="utf-8"?><!-- Copyright (C) 2024 The Android Open Source Project
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
+<resources>
+  <color name="tab_selected_text_color">@android:color/black</color>
+  <color name="work_profile_button_stroke_color">
+    @*android:color/system_accent1_200
+  </color> <!-- accent 200 -->
+  <color name="empty_state_text_color">@*android:color/system_neutral1_100
+  </color>
+  <!-- neutral 100 -->
+  <color name="empty_state_message_text_color">
+    @*android:color/system_neutral2_200
+  </color>
+  <!-- neutral variant 200 -->
+  <color name="tab_unselected_text_color">@*android:color/system_neutral2_200
+  </color>
+  <!-- neutral variant 200 -->
+  <color name="profile_tab_default_color">@*android:color/system_neutral1_800
+  </color>
+  <!-- neutral 800 -->
+  <color name="profile_tab_selected_color">@*android:color/system_neutral2_100
+  </color>
+  <!-- neutral variant 100 -->
+  <color name="fragment_pick_inactive_button_color">
+    @*android:color/system_neutral1_800
+  </color>
+  <!-- neutral 100 -->
+  <color name="fragment_pick_inactive_text_color">
+    @*android:color/system_neutral1_600
+  </color>
+  <!-- neutral 600 -->
+  <color name="fragment_pick_active_button_color">
+    @*android:color/system_neutral2_100
+  </color>
+  <!-- neutral variant 100 -->
+  <color name="fragment_pick_active_text_color">@android:color/black</color>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-night-v31/styles.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-night-v31/styles.xml
new file mode 100644
index 000000000..23fcdfaf0
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-night-v31/styles.xml
@@ -0,0 +1,31 @@
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
+
+<resources>
+    <style name="TabTextAppearance" parent="@style/TextAppearance.Material3.TitleMedium">
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+        <item name="android:textColor">?android:attr/colorAccent</item>
+    </style>
+
+    <style name="EmptyStateButton" parent="@style/Widget.Material3.Button.OutlinedButton">
+        <item name="android:backgroundTint">@android:color/transparent</item>
+        <item name="android:textColor">@*android:color/system_neutral1_100</item>
+        <item name="android:textAllCaps">false</item>
+        <item name="android:textAppearance">@style/EmptyStateButtonTextAppearance</item>
+    </style>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-night/colors.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-night/colors.xml
new file mode 100644
index 000000000..f9c58172a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-night/colors.xml
@@ -0,0 +1,41 @@
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
+<resources>
+    <color name="app_background_color">#202124</color>
+    <color name="background_floating">#3C4043</color>
+    <color name="nav_bar_translucent">#52000000</color>
+
+    <color name="primary">#8AB4F8</color>
+    <color name="secondary">#3D8AB4F8</color>
+    <color name="hairline">#5F6368</color>
+
+    <color name="empty_state_text_color">@android:color/white</color>
+    <color name="error_image_color">@android:color/white</color>
+
+    <color name="edge_effect">@android:color/white</color>
+
+    <!-- AppCompat.textColorSecondary -->
+    <color name="doc_list_item_subtitle_enabled">#b3ffffff</color>
+    <color name="doc_list_item_subtitle_disabled">#36ffffff</color>
+
+    <color name="list_divider_color">#9aa0a6</color>
+    <color name="list_item_selected_background_color">?android:colorSecondary</color>
+
+    <color name="fragment_pick_active_text_color">#202124</color> <!-- Grey 900 -->
+
+    <!-- TODO(b/379776735): remove this after M3 uplift -->
+    <color name="search_chip_text_selected_color">@android:color/black</color>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-night/themes.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-night/themes.xml
new file mode 100644
index 000000000..12b9577c6
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-night/themes.xml
@@ -0,0 +1,47 @@
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
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+    <style name="LauncherTheme" parent="DocumentsTheme">
+        <item name="android:windowBackground">@drawable/launcher_screen_night</item>
+    </style>
+    <style name="DocumentsTheme" parent="@android:style/Theme.DeviceDefault.DocumentsUI">
+
+        <!-- Toolbar -->
+        <item name="android:actionModeBackground">?android:attr/colorBackground</item>
+        <item name="android:actionBarSize">@dimen/action_bar_size</item>
+
+        <!-- Color section -->
+        <item name="android:colorAccent">@color/primary</item>
+        <item name="android:colorBackground">@color/app_background_color</item>
+        <item name="android:colorBackgroundFloating">@color/background_floating</item>
+        <item name="android:colorControlHighlight">@color/ripple_material_dark</item>
+        <item name="android:colorControlActivated">@color/primary</item>
+        <item name="android:colorPrimary">@color/primary</item>
+        <item name="android:colorSecondary">@color/secondary</item>
+        <item name="android:strokeColor">@color/hairline</item>
+
+        <!-- System | Widget section -->
+        <item name="android:listDivider">@drawable/list_divider</item>
+        <item name="android:statusBarColor">?android:attr/colorBackground</item>
+        <item name="android:windowBackground">?android:attr/colorBackground</item>
+        <item name="android:windowLightStatusBar">false</item>
+        <item name="android:windowLightNavigationBar">false</item>
+        <item name="android:windowNoTitle">true</item>
+        <item name="android:windowSoftInputMode">stateUnspecified|adjustUnspecified</item>
+
+    </style>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-v31/colors.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/colors.xml
new file mode 100644
index 000000000..44feff32a
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/colors.xml
@@ -0,0 +1,51 @@
+<?xml version="1.0" encoding="utf-8"?><!-- Copyright (C) 2024 The Android Open Source Project
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
+<resources>
+  <color name="tab_selected_text_color">@*android:color/system_neutral1_900
+  </color>
+  <!-- neutral 900 -->
+  <color name="tab_unselected_text_color">@*android:color/system_neutral2_700
+  </color>
+  <!-- neutral variant 700-->
+  <color name="work_profile_button_stroke_color">
+    @*android:color/system_accent1_600
+  </color> <!-- primary 600 -->
+  <color name="empty_state_text_color">@*android:color/system_neutral1_900
+  </color>
+  <!-- neutral 900 -->
+  <color name="empty_state_message_text_color">
+    @*android:color/system_neutral2_700
+  </color>
+  <!-- neutral variant 700 -->
+  <color name="profile_tab_selected_color">@*android:color/system_accent1_100
+  </color>
+  <!-- accent 100 -->
+  <color name="profile_tab_default_color">@*android:color/system_neutral1_10
+  </color>
+  <!-- neutral 10 -->
+  <color name="fragment_pick_inactive_button_color">
+    @*android:color/system_neutral1_100
+  </color>
+  <!-- neutral 100 -->
+  <color name="fragment_pick_inactive_text_color">
+    @*android:color/system_neutral1_400
+  </color>
+  <!-- neutral 400 -->
+  <color name="fragment_pick_active_button_color">@*android:color/system_accent1_600
+  </color>
+  <!-- accent 600 -->
+  <color name="fragment_pick_active_text_color">@android:color/white</color>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-v31/dimens.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/dimens.xml
new file mode 100644
index 000000000..006b99173
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/dimens.xml
@@ -0,0 +1,29 @@
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
+<resources>
+    <dimen name="action_bar_elevation">0dp</dimen>
+    <dimen name="action_bar_margin">0dp</dimen>
+    <dimen name="button_corner_radius">20dp</dimen>
+    <dimen name="tab_selector_indicator_height">0dp</dimen>
+    <dimen name="tab_height">48dp</dimen>
+    <dimen name="tab_container_height">48dp</dimen>
+    <dimen name="profile_tab_padding">20dp</dimen>
+    <dimen name="profile_tab_margin_top">16dp</dimen>
+    <dimen name="profile_tab_margin_side">4dp</dimen>
+    <dimen name="cross_profile_button_corner_radius">30dp</dimen>
+    <dimen name="cross_profile_button_stroke_width">1dp</dimen>
+    <dimen name="cross_profile_button_message_margin_top">16dp</dimen>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-v31/styles.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/styles.xml
new file mode 100644
index 000000000..5be3cd9dc
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/styles.xml
@@ -0,0 +1,52 @@
+<?xml version="1.0" encoding="utf-8"?><!--
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
+
+<resources>
+
+  <style name="SectionHeader" parent="@style/TextAppearance.Material3.TitleMedium">
+    <item name="android:textColor">?android:attr/textColorPrimary</item>
+    <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    <item name="android:textSize">12sp</item>
+  </style>
+
+  <style name="MaterialButton" parent="@style/Widget.Material3.Button.UnelevatedButton">
+    <item name="android:textAppearance">@style/MaterialButtonTextAppearance
+    </item>
+    <item name="android:backgroundTint">?android:colorAccent</item>
+  </style>
+
+  <style name="MaterialOutlinedButton" parent="@style/Widget.Material3.Button.OutlinedButton">
+    <item name="android:textAppearance">@style/MaterialButtonTextAppearance
+    </item>
+    <item name="android:backgroundTint">@android:color/white</item>
+    <item name="android:textColor">?android:colorAccent</item>
+  </style>
+
+  <style name="EmptyStateButton" parent="@style/Widget.Material3.Button.OutlinedButton">
+    <item name="android:backgroundTint">@android:color/transparent</item>
+    <item name="android:textColor">@*android:color/system_neutral1_900</item>
+    <item name="android:textAllCaps">false</item>
+    <item name="android:textAppearance">@style/EmptyStateButtonTextAppearance
+    </item>
+  </style>
+
+  <style name="DialogTextButton" parent="@style/Widget.Material3.Button.TextButton.Dialog">
+    <item name="android:textAppearance">@style/MaterialButtonTextAppearance
+    </item>
+    <item name="android:textColor">?android:attr/colorAccent</item>
+    <item name="android:backgroundTint">@android:color/transparent</item>
+  </style>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-v31/styles_text.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/styles_text.xml
new file mode 100644
index 000000000..d69d83c93
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-v31/styles_text.xml
@@ -0,0 +1,28 @@
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
+<resources>
+    <style name="EmptyStateTitleText">
+        <item name="android:textColor">@color/empty_state_text_color</item>
+        <item name="android:textSize">18sp</item>
+        <item name="fontFamily">@string/config_headerFontFamily</item>
+    </style>
+
+    <style name="EmptyStateMessageText">
+        <item name="android:textColor">@color/empty_state_message_text_color</item>
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+</resources>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-w600dp/dimens.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-w600dp/dimens.xml
new file mode 100644
index 000000000..9884577cf
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-w600dp/dimens.xml
@@ -0,0 +1,20 @@
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
+
+<resources>
+    <dimen name="search_chip_group_margin_horizontal">@dimen/space_medium_1</dimen>
+    <dimen name="search_chip_group_margin_vertical">@dimen/space_small_1</dimen>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/colors.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/colors.xml
new file mode 100644
index 000000000..ec2e1ff1c
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/colors.xml
@@ -0,0 +1,19 @@
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
+
+<resources>
+    <color name="menu_search_background">#ff2852ab</color>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/dimens.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/dimens.xml
new file mode 100644
index 000000000..a3232c9c2
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/dimens.xml
@@ -0,0 +1,31 @@
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
+
+<resources>
+    <dimen name="grid_padding_horiz">16dp</dimen>
+    <dimen name="grid_padding_vert">16dp</dimen>
+
+    <dimen name="list_item_padding">24dp</dimen>
+    <dimen name="list_item_width">80dp</dimen>
+
+    <dimen name="max_drawer_width">320dp</dimen>
+
+    <dimen name="search_bar_background_margin_start">120dp</dimen>
+    <dimen name="search_bar_background_margin_end">120dp</dimen>
+    <dimen name="search_bar_text_margin_start">55dp</dimen>
+    <dimen name="search_bar_text_margin_end">24dp</dimen>
+    <dimen name="search_bar_icon_padding">16dp</dimen>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/layouts.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/layouts.xml
new file mode 100644
index 000000000..9e4109a45
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-w720dp/layouts.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2015 The Android Open Source Project
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
+<resources>
+    <item name="documents_activity" type="layout">@layout/fixed_layout</item>
+    <item name="files_activity" type="layout">@layout/fixed_layout</item>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values-w900dp/dimens.xml b/res/flag(com.android.documentsui.flags.use_material3)/values-w900dp/dimens.xml
new file mode 100644
index 000000000..30c551c21
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values-w900dp/dimens.xml
@@ -0,0 +1,20 @@
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
+
+<resources>
+    <dimen name="search_chip_group_margin_horizontal">@dimen/space_medium_5</dimen>
+    <dimen name="search_chip_group_margin_vertical">@dimen/space_small_1</dimen>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/colors.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/colors.xml
new file mode 100644
index 000000000..76bd5dc18
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/colors.xml
@@ -0,0 +1,74 @@
+<?xml version="1.0" encoding="utf-8"?><!-- Copyright (C) 2024 The Android Open Source Project
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
+<resources>
+  <!-- This is the window background, but also the background for anything
+       else that needs to manually declare a background matching the "default"
+       app background (e.g. the drawer overlay). -->
+
+  <color name="app_background_color">@android:color/white</color>
+  <color name="background_floating">@android:color/white</color>
+  <color name="nav_bar_translucent">#99FFFFFF</color>
+
+  <color name="primary">#1E88E5</color> <!-- Blue 600 -->
+  <color name="secondary">#E3F2FD</color> <!-- Blue 50 -->
+  <color name="hairline">#E0E0E0</color> <!-- Gray 300 -->
+
+  <!-- TODO(b/379776735): remove this after M3 uplift -->
+  <color name="chip_background_disable_color">#fff1f3f4</color>
+  <color name="menu_search_background">@android:color/transparent</color>
+  <color name="item_breadcrumb_background_hovered">#1affffff</color>
+  <color name="item_drag_shadow_background">@android:color/white</color>
+  <color name="item_drag_shadow_container_background">
+    @android:color/transparent
+  </color>
+  <color name="tool_bar_gradient_max">#7f000000</color>
+
+  <color name="band_select_background">#88ffffff</color>
+  <color name="band_select_border">#44000000</color>
+
+  <color name="downloads_icon_background">#ff4688f2</color>
+  <color name="app_icon_background">#ff4688f2</color>
+  <color name="shortcut_foreground">#ff3367d6</color>
+  <color name="shortcut_background">#fff5f5f5</color>
+
+  <color name="empty_state_text_color">#202124</color>
+  <color name="error_image_color">#757575</color>
+
+  <color name="edge_effect">@android:color/black</color>
+
+  <color name="doc_list_item_subtitle_enabled">#5F6368</color> <!-- Gray 700 -->
+  <color name="doc_list_item_subtitle_disabled">#613c4043
+  </color> <!-- 38% Grey800 -->
+
+  <color name="list_divider_color">#1f000000</color>
+  <color name="list_item_selected_background_color">?android:colorSecondary
+  </color>
+  <color name="color_surface_header">@color/app_background_color</color>
+
+  <color name="tab_selected_text_color">@color/primary</color>
+  <color name="work_profile_button_stroke_color">@color/primary</color>
+  <color name="profile_tab_selected_color">?android:attr/colorAccent</color>
+  <color name="profile_tab_default_color">#E0E0E0</color>
+  <color name="tab_unselected_text_color">#5F6368</color> <!-- Gray 700 -->
+
+  <color name="fragment_pick_inactive_button_color">#E0E0E0</color>
+  <color name="fragment_pick_inactive_text_color">#5F6368</color>
+  <color name="fragment_pick_active_button_color">@color/primary</color>
+  <color name="fragment_pick_active_text_color">@android:color/white</color>
+
+  <!-- TODO(b/379776735): remove this after M3 uplift -->
+  <color name="search_chip_text_selected_color">@android:color/white</color>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/dimens.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/dimens.xml
new file mode 100644
index 000000000..681de06f4
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/dimens.xml
@@ -0,0 +1,141 @@
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
+
+<resources>
+    <!-- Material design rounded radius -->
+    <dimen name="material_round_radius">2dp</dimen>
+
+    <dimen name="tab_selector_indicator_height">2dp</dimen>
+    <dimen name="profile_tab_padding">0dp</dimen>
+    <dimen name="grid_container_padding">20dp</dimen>
+    <dimen name="list_container_padding">20dp</dimen>
+    <dimen name="icon_size">40dp</dimen>
+    <dimen name="button_touch_size">48dp</dimen>
+    <dimen name="root_icon_size">24dp</dimen>
+    <dimen name="root_icon_margin">0dp</dimen>
+    <dimen name="root_spacer_padding">0dp</dimen>
+    <dimen name="root_action_icon_size">18dp</dimen>
+    <dimen name="root_icon_disabled_alpha">?android:attr/disabledAlpha</dimen>
+    <dimen name="check_icon_size">30dp</dimen>
+    <dimen name="zoom_icon_size">24dp</dimen>
+    <dimen name="list_item_thumbnail_size">40dp</dimen>
+    <dimen name="grid_item_icon_size">30dp</dimen>
+    <dimen name="progress_bar_height">4dp</dimen>
+    <fraction name="grid_scale_min">85%</fraction>
+    <fraction name="grid_scale_max">200%</fraction>
+    <dimen name="grid_width">152dp</dimen>
+    <dimen name="grid_section_separator_height">0dp</dimen>
+    <dimen name="grid_item_margin">6dp</dimen>
+    <dimen name="grid_padding_horiz">4dp</dimen>
+    <dimen name="grid_padding_vert">4dp</dimen>
+    <dimen name="list_item_width">72dp</dimen>
+    <dimen name="list_item_height">72dp</dimen>
+    <dimen name="list_item_padding">16dp</dimen>
+    <dimen name="list_item_icon_padding">16dp</dimen>
+    <dimen name="breadcrumb_item_padding">8dp</dimen>
+    <dimen name="breadcrumb_item_height">36dp</dimen>
+    <dimen name="list_divider_inset">72dp</dimen>
+    <dimen name="dir_elevation">8dp</dimen>
+    <dimen name="drag_shadow_size">120dp</dimen>
+    <dimen name="grid_item_elevation">2dp</dimen>
+    <dimen name="grid_item_radius">2dp</dimen>
+    <dimen name="max_drawer_width">280dp</dimen>
+    <dimen name="briefcase_icon_margin">8dp</dimen>
+    <dimen name="briefcase_icon_size">14dp</dimen>
+    <dimen name="briefcase_icon_size_photo">24dp</dimen>
+    <dimen name="button_corner_radius">2dp</dimen>
+
+    <dimen name="drawer_edge_width">12dp</dimen>
+
+    <dimen name="drag_shadow_width">176dp</dimen>
+    <dimen name="drag_shadow_height">64dp</dimen>
+    <dimen name="drag_shadow_radius">4dp</dimen>
+    <dimen name="drag_shadow_padding">8dp</dimen>
+
+    <dimen name="doc_header_sort_icon_size">16dp</dimen>
+    <dimen name="doc_header_height">60dp</dimen>
+
+    <dimen name="dropdown_sort_widget_margin">12dp</dimen>
+    <dimen name="dropdown_sort_widget_size">54dp</dimen>
+    <dimen name="dropdown_sort_text_size">18sp</dimen>
+
+    <dimen name="drop_icon_height">14dp</dimen>
+    <dimen name="drop_icon_width">14dp</dimen>
+
+    <dimen name="header_message_horizontal_padding">8dp</dimen>
+
+    <dimen name="fastscroll_default_thickness">8dp</dimen>
+    <dimen name="fastscroll_minimum_range">50dp</dimen>
+    <dimen name="fastscroll_margin">0dp</dimen>
+
+    <dimen name="bottom_bar_height">56dp</dimen>
+    <dimen name="bottom_bar_padding">10dp</dimen>
+    <dimen name="bottom_bar_button_height">36dip</dimen>
+    <dimen name="bottom_bar_button_horizontal_padding">24dp</dimen>
+    <dimen name="bottom_bar_button_corner_radius">4dp</dimen>
+
+    <dimen name="inspector_header_height">280dp</dimen>
+
+    <dimen name="root_info_header_height">60dp</dimen>
+    <dimen name="root_info_header_horizontal_padding">24dp</dimen>
+
+    <!-- TODO(b/379776735): remove this block after M3 uplift -->
+    <dimen name="search_chip_group_margin">20dp</dimen>
+    <dimen name="search_chip_spacing">8dp</dimen>
+    <dimen name="search_chip_half_spacing">4dp</dimen>
+    <dimen name="search_chip_icon_padding">4dp</dimen>
+    <!-- block end -->
+    <dimen name="search_chip_radius">8dp</dimen>
+    <dimen name="search_chip_group_margin_horizontal">@dimen/space_small_4</dimen>
+    <dimen name="search_chip_group_margin_vertical">@dimen/space_small_1</dimen>
+
+    <dimen name="dialog_content_padding_top">18dp</dimen>
+    <dimen name="dialog_content_padding_bottom">24dp</dimen>
+
+    <dimen name="apps_row_title_height">48dp</dimen>
+    <dimen name="apps_row_title_padding_start">24dp</dimen>
+    <dimen name="apps_row_item_width">92dp</dimen>
+    <dimen name="apps_row_item_height">82dp</dimen>
+    <dimen name="apps_row_app_icon_size">32dp</dimen>
+    <dimen name="apps_row_app_icon_margin_horizontal">30dp</dimen>
+    <dimen name="apps_row_app_icon_margin_top">6dp</dimen>
+    <dimen name="apps_row_app_icon_margin_bottom">10dp</dimen>
+    <dimen name="apps_row_exit_icon_size">12dp</dimen>
+    <dimen name="apps_row_exit_icon_margin_top">2dp</dimen>
+    <dimen name="apps_row_exit_icon_margin_bottom">6dp</dimen>
+    <dimen name="apps_row_item_text_margin_horizontal">8dp</dimen>
+
+    <dimen name="search_bar_elevation">3dp</dimen>
+    <dimen name="search_bar_radius">8dp</dimen>
+    <dimen name="search_bar_background_margin_start">0dp</dimen>
+    <dimen name="search_bar_background_margin_end">0dp</dimen>
+    <dimen name="search_bar_margin">@dimen/space_extra_small_6</dimen>
+    <dimen name="search_bar_text_size">16dp</dimen>
+
+    <dimen name="action_bar_elevation">3dp</dimen>
+    <dimen name="action_bar_margin">1dp</dimen>
+    <dimen name="action_bar_size">48dp</dimen>
+    <dimen name="action_mode_text_size">18sp</dimen>
+
+    <dimen name="refresh_icon_range">64dp</dimen>
+
+    <dimen name="item_doc_inflated_message_padding_top">0dp</dimen>
+    <dimen name="cross_profile_button_corner_radius">0dp</dimen>
+    <dimen name="cross_profile_button_stroke_width">0dp</dimen>
+    <dimen name="cross_profile_button_message_margin_top">4dp</dimen>
+
+    <dimen name="focus_ring_width">3dp</dimen>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/layouts.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/layouts.xml
new file mode 100644
index 000000000..d5b4f9da8
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/layouts.xml
@@ -0,0 +1,20 @@
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
+
+<resources>
+    <item name="documents_activity" type="layout">@layout/drawer_layout</item>
+    <item name="files_activity" type="layout">@layout/drawer_layout</item>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/spaces.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/spaces.xml
new file mode 100644
index 000000000..595c8ddda
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/spaces.xml
@@ -0,0 +1,76 @@
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
+
+<!-- Measurement System Tokens, Version: 20241119-dbv3 -->
+<resources>
+    <!--  Space tokens  -->
+    <dimen name="space_none">0</dimen>
+    <dimen name="space_extra_small_1">2dp</dimen>
+    <dimen name="space_extra_small_2">4dp</dimen>
+    <dimen name="space_extra_small_3">6dp</dimen>
+    <dimen name="space_extra_small_4">8dp</dimen>
+    <dimen name="space_extra_small_5">10dp</dimen>
+    <dimen name="space_extra_small_6">12dp</dimen>
+    <dimen name="space_extra_small_7">14dp</dimen>
+    <dimen name="space_small_1">16dp</dimen>
+    <dimen name="space_small_2">18dp</dimen>
+    <dimen name="space_small_3">20dp</dimen>
+    <dimen name="space_small_4">24dp</dimen>
+    <dimen name="space_medium_1">32dp</dimen>
+    <dimen name="space_medium_2">36dp</dimen>
+    <dimen name="space_medium_3">40dp</dimen>
+    <dimen name="space_medium_4">44dp</dimen>
+    <dimen name="space_medium_5">48dp</dimen>
+    <dimen name="space_medium_6">52dp</dimen>
+    <dimen name="space_large_1">60dp</dimen>
+    <dimen name="space_large_2">64dp</dimen>
+    <dimen name="space_large_3">72dp</dimen>
+    <dimen name="space_large_4">80dp</dimen>
+    <dimen name="space_large_5">96dp</dimen>
+
+    <!--  Icon size tokens  -->
+    <dimen name="icon_size_title_small">16dp</dimen>
+    <dimen name="icon_size_title_medium">20dp</dimen>
+    <dimen name="icon_size_title_large">24dp</dimen>
+    <dimen name="icon_size_headline_small">28dp</dimen>
+    <dimen name="icon_size_headline_medium">32dp</dimen>
+    <dimen name="icon_size_headline_large">48dp</dimen>
+    <dimen name="icon_size_display_small">72dp</dimen>
+    <dimen name="icon_size_display_medium">96dp</dimen>
+    <dimen name="icon_size_display_large">120dp</dimen>
+    <dimen name="icon_size_display_extra_large">280dp</dimen>
+
+    <!--  Size tokens  -->
+    <dimen name="size_extra_small_1">2dp</dimen>
+    <dimen name="size_extra_small_2">4dp</dimen>
+    <dimen name="size_extra_small_3">8dp</dimen>
+    <dimen name="size_small_1">16dp</dimen>
+    <dimen name="size_small_2">20dp</dimen>
+    <dimen name="size_small_3">24dp</dimen>
+    <dimen name="size_small_4">28dp</dimen>
+    <dimen name="size_medium_1">32dp</dimen>
+    <dimen name="size_medium_2">36dp</dimen>
+    <dimen name="size_medium_3">40dp</dimen>
+    <dimen name="size_medium_4">48dp</dimen>
+    <dimen name="size_medium_5">52dp</dimen>
+    <dimen name="size_medium_6">56dp</dimen>
+    <dimen name="size_large_1">60dp</dimen>
+    <dimen name="size_large_2">64dp</dimen>
+    <dimen name="size_large_3">72dp</dimen>
+    <dimen name="size_large_4">80dp</dimen>
+    <dimen name="size_large_5">96dp</dimen>
+    <dimen name="size_large_6">108dp</dimen>
+</resources>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/styles.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/styles.xml
new file mode 100644
index 000000000..8aba2dfa3
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/styles.xml
@@ -0,0 +1,129 @@
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
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+    <style name="ActionBarThemeCommon" parent="@style/ThemeOverlay.AppCompat.ActionBar">
+        <item name="colorControlNormal">?android:textColorSecondary</item>
+        <!-- Modern platform themes set actionMenuTextColor to textColorPrimary. For example,
+             see Theme.Material in frameworks/base/core/res/res/values/themes_material.xml.
+             However, if the platform theme does not set actionMenuTextColor we are going to
+             crash, so let's set it here. Additionally, most of our ActionBarTheme themes
+             override this -->
+        <item name="android:actionMenuTextColor">?android:textColorPrimary</item>
+        <item name="android:textAllCaps">false</item>
+    </style>
+
+    <!-- This gets overridden for specific platform versions and/or configs -->
+    <style name="ActionBarTheme" parent="@style/ActionBarThemeCommon"/>
+
+    <style name="ActionModeStyle" parent="Widget.AppCompat.ActionMode">
+        <!-- attr "height" was used by support lib should not in overlay scope -->
+        <item name="height">@dimen/action_bar_size</item>
+        <item name="titleTextStyle">@style/ActionModeTitle</item>
+        <item name="android:layout_margin">@dimen/search_bar_margin</item>
+    </style>
+
+    <style name="CardViewStyle" parent="@style/Widget.Material3.CardView.Outlined">
+        <item name="cardBackgroundColor">@color/app_background_color</item>
+        <item name="cardPreventCornerOverlap">false</item>
+        <item name="cardCornerRadius">@dimen/grid_item_radius</item>
+        <item name="cardElevation">@dimen/grid_item_elevation</item>
+    </style>
+
+    <style name="TrimmedHorizontalProgressBar" parent="android:Widget.Material.ProgressBar.Horizontal">
+        <item name="android:indeterminateDrawable">@drawable/progress_indeterminate_horizontal_material_trimmed</item>
+        <item name="android:minHeight">3dp</item>
+        <item name="android:maxHeight">3dp</item>
+    </style>
+
+    <style name="SnackbarButtonStyle" parent="@style/Widget.AppCompat.Button.Borderless">
+        <item name="android:textColor">?android:colorPrimary</item>
+    </style>
+
+    <style name="AutoCompleteTextViewStyle" parent="@style/Widget.AppCompat.AutoCompleteTextView">
+        <item name="android:textColorHint">?android:attr/textColorSecondary</item>
+        <item name="android:textAppearance">@style/AutoCompleteText</item>
+    </style>
+
+    <style name="BottomSheetDialogStyle" parent="@style/ThemeOverlay.Material3.BottomSheetDialog">
+        <item name="android:windowIsFloating">false</item>
+        <item name="bottomSheetStyle">@style/BottomSheet</item>
+        <item name="colorControlHighlight">@color/ripple_material_light</item>
+    </style>
+
+    <style name="BottomSheet" parent="@style/Widget.Design.BottomSheet.Modal">
+        <item name="android:background">@drawable/bottom_sheet_dialog_background</item>
+    </style>
+
+    <style name="OverflowButtonStyle" parent="@style/Widget.AppCompat.ActionButton.Overflow">
+        <item name="android:tint">?android:colorControlNormal</item>
+        <item name="android:minWidth">@dimen/button_touch_size</item>
+    </style>
+
+    <style name="OverflowMenuStyle" parent="@style/Widget.AppCompat.PopupMenu.Overflow">
+        <item name="android:popupBackground">@drawable/menu_dropdown_panel</item>
+        <item name="android:dropDownWidth">wrap_content</item>
+        <item name="android:overlapAnchor">false</item>
+    </style>
+
+    <style name="MaterialAlertDialogTitleStyle" parent="@style/MaterialAlertDialog.Material3.Title.Text.CenterStacked">
+        <item name="android:textColor">?attr/colorOnSurface</item>
+        <item name="android:textSize">20sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="MaterialButton" parent="@style/Widget.Material3.Button.UnelevatedButton">
+        <item name="android:textAppearance">@style/MaterialButtonTextAppearance</item>
+    </style>
+
+    <style name="MaterialOutlinedButton" parent="@style/Widget.Material3.Button.OutlinedButton">
+        <item name="android:textAppearance">@style/MaterialButtonTextAppearance</item>
+    </style>
+
+    <style name="DialogTextButton" parent="@style/Widget.Material3.Button.TextButton.Dialog">
+        <item name="android:textAppearance">@style/MaterialButtonTextAppearance</item>
+        <item name="android:textColor">?android:attr/colorAccent</item>
+    </style>
+
+    <style name="EmptyStateButton" parent="@style/Widget.Material3.Button.TextButton">
+        <item name="android:textAppearance">@style/EmptyStateButtonTextAppearance</item>
+    </style>
+
+    <style name="AlertDialogTheme" parent="@style/ThemeOverlay.AppCompat.Dialog.Alert">
+        <item name="buttonBarPositiveButtonStyle">@style/DialogTextButton</item>
+        <item name="buttonBarNegativeButtonStyle">@style/DialogTextButton</item>
+    </style>
+
+    <style name="MaterialAlertDialogStyle" parent="@style/MaterialAlertDialog.Material3">
+        <item name="backgroundInsetTop">12dp</item>
+        <item name="backgroundInsetBottom">12dp</item>
+    </style>
+
+    <style name="MaterialAlertDialogTheme" parent="@style/ThemeOverlay.Material3.MaterialAlertDialog.Centered">
+        <item name="android:dialogCornerRadius">@dimen/grid_item_radius</item>
+        <item name="alertDialogStyle">@style/MaterialAlertDialogStyle</item>
+        <item name="buttonBarPositiveButtonStyle">@style/DialogTextButton</item>
+        <item name="buttonBarNegativeButtonStyle">@style/DialogTextButton</item>
+        <item name="materialAlertDialogTitleTextStyle">@style/MaterialAlertDialogTitleStyle</item>
+    </style>
+
+    <style name="SearchChipItemStyle" parent="@style/Widget.Material3.Chip.Filter">
+        <item name="android:textAppearance">@style/SearchChipText</item>
+        <item name="chipBackgroundColor">@color/search_chip_background_color</item>
+        <item name="chipStrokeColor">@color/search_chip_stroke_color</item>
+        <item name="chipCornerRadius">@dimen/search_chip_radius</item>
+    </style>
+</resources>
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/styles_text.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/styles_text.xml
new file mode 100644
index 000000000..c8cf16cbf
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/styles_text.xml
@@ -0,0 +1,152 @@
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
+<resources>
+    <style name="SortTitle" parent="@style/TextAppearance.Material3.TitleLarge">
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+        <item name="android:textSize">11sp</item>
+    </style>
+
+    <style name="SectionHeader" parent="@style/TextAppearance.Material3.TitleMedium">
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+        <item name="android:textAllCaps">true</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+        <item name="android:textSize">12sp</item>
+    </style>
+
+    <style name="SortList" parent="@style/TextAppearance.AppCompat.Subhead">
+        <item name="android:textColor">@color/sort_list_text</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="SearchBarTitle" parent="@style/TextAppearance.Widget.AppCompat.Toolbar.Subtitle">
+        <item name="android:textColor">?android:attr/textColorSecondary</item>
+        <item name="android:textSize">@dimen/search_bar_text_size</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="SearchChipText" parent="@style/TextAppearance.Material3.LabelLarge">
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="AppsItemText">
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+        <item name="android:textSize">12sp</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="AppsItemSubText">
+        <item name="android:textColor">?android:attr/textColorSecondary</item>
+        <item name="android:textSize">11sp</item>
+    </style>
+
+    <style name="AutoCompleteText" parent="@style/TextAppearance.AppCompat.Medium">
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="CardPrimaryText" parent="@style/TextAppearance.AppCompat.Subhead">
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="ActionModeTitle" parent="@style/ToolbarTitle">
+        <item name="android:textSize">@dimen/action_mode_text_size</item>
+    </style>
+
+    <style name="ToolbarTitle" parent="@style/TextAppearance.Material3.TitleLarge">
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="DrawerMenuTitle" parent="@style/TextAppearance.Material3.TitleLarge">
+        <item name="android:textSize">24sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="DrawerMenuHeader" parent="@style/TextAppearance.Material3.BodyLarge">
+        <item name="android:textColor">?android:attr/textColorSecondary</item>
+        <item name="android:textAllCaps">true</item>
+        <item name="android:textSize">11sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="DrawerMenuPrimary" parent="@style/TextAppearance.Material3.BodyMedium">
+        <item name="android:textSize">14sp</item>
+        <item name="android:textColor">@color/item_root_primary_text</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="DrawerMenuSecondary" parent="@style/TextAppearance.Material3.BodyMedium">
+        <item name="android:textSize">12sp</item>
+        <item name="android:textColor">@color/item_root_secondary_text</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="InspectorKeySubTitle" parent="@style/TextAppearance.Material3.TitleMedium">
+        <item name="android:textColor">?android:attr/textColorSecondary</item>
+    </style>
+
+    <style name="MaterialButtonTextAppearance" parent="@style/TextAppearance.Material3.LabelLarge">
+        <item name="android:textAllCaps">@bool/config_button_all_caps</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="BreadcrumbText" parent="@style/TextAppearance.Widget.AppCompat.Toolbar.Subtitle">
+        <item name="android:textColor">@color/horizontal_breadcrumb_color</item>
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="EmptyStateTitleText">
+        <item name="android:textColor">@color/empty_state_text_color</item>
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="EmptyStateMessageText">
+        <item name="android:textColor">@color/empty_state_text_color</item>
+        <item name="android:textSize">12sp</item>
+    </style>
+
+    <style name="EmptyStateButtonTextAppearance">
+        <item name="android:textColor">?android:attr/colorAccent</item>
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="TabTextAppearance" parent="@style/TextAppearance.Material3.TitleMedium">
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamilyMedium</item>
+    </style>
+
+    <style name="ItemCaptionText" parent="@style/TextAppearance.Material3.BodySmall">
+        <item name="android:textColor">@color/doc_list_item_subtitle_color</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="MenuItemTextAppearance" parent="@style/TextAppearance.Material3.BodyMedium">
+        <item name="android:textSize">14sp</item>
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="Subhead" parent="@style/TextAppearance.Material3.BodyLarge">
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+    <style name="Body1" parent="@style/TextAppearance.Material3.BodyMedium">
+        <item name="fontFamily">@string/config_fontFamily</item>
+    </style>
+
+</resources>
\ No newline at end of file
diff --git a/res/flag(com.android.documentsui.flags.use_material3)/values/themes.xml b/res/flag(com.android.documentsui.flags.use_material3)/values/themes.xml
new file mode 100644
index 000000000..8f145fd38
--- /dev/null
+++ b/res/flag(com.android.documentsui.flags.use_material3)/values/themes.xml
@@ -0,0 +1,83 @@
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
+
+<resources>
+    <style name="LauncherTheme" parent="DocumentsTheme">
+        <item name="android:windowBackground">@drawable/launcher_screen</item>
+    </style>
+    <!-- DocumentsTheme is allow customize by run time overlay -->
+    <style name="DocumentsTheme" parent="@android:style/Theme.DeviceDefault.DocumentsUI">
+
+        <item name="android:actionBarSize">@dimen/action_bar_size</item>
+        <item name="android:actionModeBackground">?android:attr/colorBackground</item>
+
+        <!-- Color section -->
+        <item name="android:colorAccent">@color/primary</item>
+        <item name="android:colorBackground">@android:color/white</item>
+        <item name="android:colorBackgroundFloating">@color/background_floating</item>
+        <item name="android:colorControlHighlight">@color/ripple_material_light</item>
+        <item name="android:colorControlActivated">@color/primary</item>
+        <item name="android:colorPrimary">@color/primary</item>
+        <item name="android:colorSecondary">@color/secondary</item>
+        <item name="android:strokeColor">@color/hairline</item>
+
+        <!-- System | Widget section -->
+        <item name="android:listDivider">@drawable/list_divider</item>
+        <item name="android:statusBarColor">?android:colorBackground</item>
+        <item name="android:navigationBarColor">?android:colorBackground</item>
+        <item name="android:windowBackground">?android:colorBackground</item>
+        <item name="android:windowLightStatusBar">true</item>
+        <item name="android:windowLightNavigationBar">true</item>
+        <item name="android:windowSoftInputMode">stateUnspecified|adjustUnspecified</item>
+
+        <!-- OEM should not overlay this attr -->
+        <item name="android:windowNoTitle">true</item>
+
+    </style>
+
+    <style name="DocumentsDefaultTheme" parent="@style/Theme.Material3.DayNight.NoActionBar">
+
+        <!-- This only used by support lib, not allow to overlay -->
+        <item name="windowActionBar">false</item>
+        <item name="windowActionModeOverlay">true</item>
+
+        <!-- For material design widget, chips, buttons, not support attr-->
+        <item name="colorPrimary">@color/primary</item>
+        <item name="colorAccent">@color/primary</item>
+
+        <!-- TODO need to solve the error handle in GridItemThumbnail -->
+        <item name="gridItemTint">@color/item_doc_grid_tint</item>
+
+        <item name="actionBarTheme">@style/ActionBarTheme</item>
+        <item name="actionModeStyle">@style/ActionModeStyle</item>
+        <item name="actionOverflowButtonStyle">@style/OverflowButtonStyle</item>
+        <item name="actionOverflowMenuStyle">@style/OverflowMenuStyle</item>
+        <item name="alertDialogTheme">@style/AlertDialogTheme</item>
+        <item name="autoCompleteTextViewStyle">@style/AutoCompleteTextViewStyle</item>
+        <item name="bottomSheetDialogTheme">@style/BottomSheetDialogStyle</item>
+        <item name="materialButtonStyle">@style/MaterialButton</item>
+        <item name="materialButtonOutlinedStyle">@style/MaterialOutlinedButton</item>
+        <item name="materialCardViewStyle">@style/CardViewStyle</item>
+        <item name="materialAlertDialogTheme">@style/MaterialAlertDialogTheme</item>
+        <item name="queryBackground">@color/menu_search_background</item>
+        <item name="snackbarButtonStyle">@style/SnackbarButtonStyle</item>
+        <item name="android:itemTextAppearance">@style/MenuItemTextAppearance</item>
+    </style>
+
+    <style name="TabTheme" parent="@android:style/Theme.DeviceDefault.DayNight">
+        <item name="colorPrimary">@color/edge_effect</item>
+    </style>
+</resources>
diff --git a/res/layout/selection_demo_list_item.xml b/res/layout/selection_demo_list_item.xml
deleted file mode 100644
index 0d4b71826..000000000
--- a/res/layout/selection_demo_list_item.xml
+++ /dev/null
@@ -1,53 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2017 The Android Open Source Project
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
-<LinearLayout
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="match_parent"
-    android:paddingStart="10dp"
-    android:paddingEnd="10dp"
-    android:paddingTop="5dp"
-    android:paddingBottom="5dp"
-    android:layout_height="50dp">
-  <LinearLayout
-      android:id="@+id/container"
-      xmlns:android="http://schemas.android.com/apk/res/android"
-      android:layout_height="match_parent"
-      android:layout_width="match_parent"
-      android:background="@drawable/selection_demo_item_background">
-      <TextView
-          android:id="@+id/selector"
-          android:textSize="20sp"
-          android:textStyle="bold"
-          android:gravity="center"
-          android:layout_height="match_parent"
-          android:layout_width="40dp"
-          android:textColor="@color/selection_demo_item_selector"
-          android:pointerIcon="hand"
-          android:text="✕">
-      </TextView>
-      <TextView
-          android:id="@+id/label"
-          android:textSize="20sp"
-          android:textStyle="bold"
-          android:gravity="center_vertical"
-          android:paddingStart="10dp"
-          android:paddingEnd="10dp"
-          android:layout_height="match_parent"
-          android:layout_width="match_parent">
-      </TextView>
-  </LinearLayout>
-</LinearLayout>
diff --git a/res/menu/dir_context_menu.xml b/res/menu/dir_context_menu.xml
index 383841ae3..232753b9d 100644
--- a/res/menu/dir_context_menu.xml
+++ b/res/menu/dir_context_menu.xml
@@ -33,6 +33,9 @@
         <item
             android:id="@+id/dir_menu_copy_to_clipboard"
             android:title="@string/menu_copy_to_clipboard" />
+        <item
+            android:id="@+id/dir_menu_compress"
+            android:title="@string/menu_compress" />
         <item
             android:id="@+id/dir_menu_paste_into_folder"
             android:title="@string/menu_paste_into_folder" />
@@ -47,6 +50,7 @@
             android:id="@+id/dir_menu_delete"
             android:title="@string/menu_delete" />
     </group>
+
     <group
         android:id="@+id/menu_extras_group">
         <item
diff --git a/res/menu/file_context_menu.xml b/res/menu/file_context_menu.xml
index 9e786f173..02b0e87e1 100644
--- a/res/menu/file_context_menu.xml
+++ b/res/menu/file_context_menu.xml
@@ -38,6 +38,9 @@
         <item
             android:id="@+id/dir_menu_copy_to_clipboard"
             android:title="@string/menu_copy_to_clipboard" />
+        <item
+            android:id="@+id/dir_menu_compress"
+            android:title="@string/menu_compress" />
     </group>
 
     <group
@@ -49,6 +52,7 @@
             android:id="@+id/dir_menu_delete"
             android:title="@string/menu_delete" />
     </group>
+
     <group
         android:id="@+id/menu_extras_group">
         <item
diff --git a/res/menu/mixed_context_menu.xml b/res/menu/mixed_context_menu.xml
index cb6b4fdaf..128b130d5 100644
--- a/res/menu/mixed_context_menu.xml
+++ b/res/menu/mixed_context_menu.xml
@@ -26,6 +26,9 @@
         <item
             android:id="@+id/dir_menu_copy_to_clipboard"
             android:title="@string/menu_copy_to_clipboard" />
+        <item
+            android:id="@+id/dir_menu_compress"
+            android:title="@string/menu_compress" />
     </group>
 
     <group
@@ -34,6 +37,7 @@
             android:id="@+id/dir_menu_delete"
             android:title="@string/menu_delete" />
     </group>
+
     <group
         android:id="@+id/menu_extras_group">
         <item
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 7c2e20c50..74f2c90eb 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -97,7 +97,7 @@
     <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"<xliff:g id="PROFILE">%1$s</xliff:g> apps word gepouseer"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Skakel <xliff:g id="PROFILE">%1$s</xliff:g> apps aan"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Kan nie werklêers kies nie"</string>
-    <string name="cant_select_work_files_error_message" msgid="683480676150690641">"Jou IT-administrateur laat jou nie toe om van \'n persoonlike program af by werklêers in te gaan nie"</string>
+    <string name="cant_select_work_files_error_message" msgid="683480676150690641">"Jou IT-administrateur laat jou nie toe om van \'n persoonlike app af by werklêers in te gaan nie"</string>
     <string name="cant_select_personal_files_error_title" msgid="3200697170148617742">"Kan nie persoonlike lêers kies nie"</string>
     <string name="cant_select_personal_files_error_message" msgid="4105905035459118209">"Jou IT-administrateur laat jou nie toe om van \'n werkprogram af by persoonlike lêers in te gaan nie"</string>
     <string name="cant_select_cross_profile_files_error_title" msgid="17010948874969413">"Kan nie <xliff:g id="PROFILE">%1$s</xliff:g> lêers kies nie"</string>
@@ -286,7 +286,7 @@
     <string name="personal_tab" msgid="3878576287868528503">"Persoonlik"</string>
     <string name="work_tab" msgid="7265359366883747413">"Werk"</string>
     <string name="a11y_work" msgid="7504431382825242153">"Werk"</string>
-    <string name="drag_from_another_app" msgid="8310249276199969905">"Jy kan nie lêers uit \'n ander program skuif nie."</string>
+    <string name="drag_from_another_app" msgid="8310249276199969905">"Jy kan nie lêers uit \'n ander app skuif nie."</string>
     <string name="grid_mode_showing" msgid="2803166871485028508">"Wys tans in roostermodus."</string>
     <string name="list_mode_showing" msgid="1225413902295895166">"Wys tans in lysmodus."</string>
 </resources>
diff --git a/res/values-bs/inspector_strings.xml b/res/values-bs/inspector_strings.xml
index 1044ceb35..74b6dcc8a 100644
--- a/res/values-bs/inspector_strings.xml
+++ b/res/values-bs/inspector_strings.xml
@@ -32,7 +32,7 @@
     <string name="metadata_altitude" msgid="8063792127436794294">"Visina"</string>
     <string name="metadata_camera" msgid="2363009732801281319">"Kamera"</string>
     <string name="metadata_camera_format" msgid="1494489751904311612">"<xliff:g id="MAKE">%1$s</xliff:g> <xliff:g id="MODEL">%2$s</xliff:g>"</string>
-    <string name="metadata_aperture" msgid="6538741952698935357">"Blenda"</string>
+    <string name="metadata_aperture" msgid="6538741952698935357">"Otvor blende"</string>
     <string name="metadata_shutter_speed" msgid="8204739885103326131">"Brzina zatvarača"</string>
     <string name="metadata_duration" msgid="3115494422055472715">"Trajanje"</string>
     <string name="metadata_date_time" msgid="1090351199248114406">"Vrijeme snimanja"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 7a3b08358..76d717243 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -220,7 +220,7 @@
       <item quantity="one">S\'ha copiat <xliff:g id="COUNT_0">%1$d</xliff:g> element al porta-retalls.</item>
     </plurals>
     <string name="file_operation_rejected" msgid="4301554203329008794">"L\'operació del fitxer no s\'admet."</string>
-    <string name="file_operation_error" msgid="2234357335716533795">"S\'ha produït un error en l\'operació del fitxer."</string>
+    <string name="file_operation_error" msgid="2234357335716533795">"Hi ha hagut un error en l\'operació del fitxer."</string>
     <string name="rename_error" msgid="6700093173508118635">"No s\'ha pogut canviar el nom del document"</string>
     <string name="menu_eject_root" msgid="9215040039374893613">"Expulsa"</string>
     <string name="notification_copy_files_converted_title" msgid="6916768494891833365">"S\'han convertit alguns fitxers"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 1aaacb0a7..822177a1e 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -182,7 +182,7 @@
       <item quantity="two">לא ניתן היה למחוק <xliff:g id="COUNT_1">%1$d</xliff:g> פריטים</item>
       <item quantity="other">לא ניתן היה למחוק <xliff:g id="COUNT_1">%1$d</xliff:g> פריטים</item>
     </plurals>
-    <string name="notification_touch_for_details" msgid="2385563502445129570">"יש להקיש להצגת הפרטים"</string>
+    <string name="notification_touch_for_details" msgid="2385563502445129570">"יש ללחוץ להצגת הפרטים"</string>
     <string name="close" msgid="905969391788869975">"סגירה"</string>
     <plurals name="copy_failure_alert_content" formatted="false" msgid="5570549471912990536">
       <item quantity="one">הקבצים הבאים לא הועתקו: <xliff:g id="LIST_1">%1$s</xliff:g></item>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 3c6765192..92d58f55a 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -240,7 +240,7 @@
     <string name="name_conflict" msgid="28407269328862986">"Датотека со истото име веќе постои."</string>
     <string name="authentication_required" msgid="8030880723643436099">"За да го прегледате адресаров, најавете се на <xliff:g id="NAME">%1$s</xliff:g>"</string>
     <string name="cant_display_content" msgid="8633226333229417237">"Не може да се прикаже содржината"</string>
-    <string name="sign_in" msgid="6253762676723505592">"Најави се"</string>
+    <string name="sign_in" msgid="6253762676723505592">"Најавете се"</string>
     <string name="new_archive_file_name" msgid="1604650338077249838">"архива<xliff:g id="EXTENSION">%s</xliff:g>"</string>
     <string name="overwrite_file_confirmation_message" msgid="2496109652768222716">"Да се презапише <xliff:g id="NAME">%1$s</xliff:g>?"</string>
     <string name="continue_in_background" msgid="1974214559047793331">"Продолжи во заднина"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index d7f8d61be..8dd6249e8 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Não é possível carregar o conteúdo no momento"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Os apps de trabalho foram pausados"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Ativar apps de trabalho"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g> estão pausados"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Os apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g> estão pausados"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Ativar apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g>"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Não é possível selecionar arquivos de trabalho"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"Seu administrador de TI não permite que você acesse arquivos de trabalho em um app pessoal"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index d7f8d61be..8dd6249e8 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Não é possível carregar o conteúdo no momento"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Os apps de trabalho foram pausados"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Ativar apps de trabalho"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g> estão pausados"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Os apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g> estão pausados"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Ativar apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g>"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Não é possível selecionar arquivos de trabalho"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"Seu administrador de TI não permite que você acesse arquivos de trabalho em um app pessoal"</string>
diff --git a/src/com/android/documentsui/BaseActivity.java b/src/com/android/documentsui/BaseActivity.java
index 31c287393..b3439d585 100644
--- a/src/com/android/documentsui/BaseActivity.java
+++ b/src/com/android/documentsui/BaseActivity.java
@@ -19,6 +19,7 @@ package com.android.documentsui;
 import static com.android.documentsui.base.Shared.EXTRA_BENCHMARK;
 import static com.android.documentsui.base.SharedMinimal.DEBUG;
 import static com.android.documentsui.base.State.MODE_GRID;
+import static com.android.documentsui.flags.Flags.useMaterial3;
 
 import android.content.Context;
 import android.content.Intent;
@@ -78,6 +79,7 @@ import com.android.documentsui.sorting.SortModel;
 import com.android.modules.utils.build.SdkLevel;
 
 import com.google.android.material.appbar.AppBarLayout;
+import com.google.android.material.color.DynamicColors;
 
 import java.util.ArrayList;
 import java.util.Date;
@@ -178,9 +180,13 @@ public abstract class BaseActivity
 
         // ToDo Create tool to check resource version before applyStyle for the theme
         // If version code is not match, we should reset overlay package to default,
-        // in case Activity continueusly encounter resource not found exception
+        // in case Activity continuously encounter resource not found exception.
         getTheme().applyStyle(R.style.DocumentsDefaultTheme, false);
 
+        if (useMaterial3() && SdkLevel.isAtLeastS()) {
+            DynamicColors.applyToActivityIfAvailable(this);
+        }
+
         super.onCreate(savedInstanceState);
 
         final Intent intent = getIntent();
diff --git a/src/com/android/documentsui/ChangeIds.java b/src/com/android/documentsui/ChangeIds.java
new file mode 100644
index 000000000..5ddf40f8e
--- /dev/null
+++ b/src/com/android/documentsui/ChangeIds.java
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
+package com.android.documentsui;
+
+import android.compat.annotation.ChangeId;
+import android.compat.annotation.EnabledAfter;
+import android.os.Build;
+
+public final class ChangeIds {
+    /**
+     * We support restrict Storage Access Framework from {@link Build.VERSION_CODES#R}.
+     * App Compatibility flag that indicates whether the app should be restricted or not.
+     * This flag is turned on by default for all apps targeting >
+     * {@link Build.VERSION_CODES#Q}.
+     */
+    @ChangeId
+    @EnabledAfter(targetSdkVersion = Build.VERSION_CODES.Q)
+    public static final long RESTRICT_STORAGE_ACCESS_FRAMEWORK = 141600225L;
+}
diff --git a/src/com/android/documentsui/MenuManager.java b/src/com/android/documentsui/MenuManager.java
index 405533a00..f46ffe482 100644
--- a/src/com/android/documentsui/MenuManager.java
+++ b/src/com/android/documentsui/MenuManager.java
@@ -213,6 +213,11 @@ public abstract class MenuManager {
         Menus.setEnabledAndVisible(delete, canDelete);
 
         Menus.setEnabledAndVisible(inspect, selectionDetails.size() == 1);
+
+        final MenuItem compress = menu.findItem(R.id.dir_menu_compress);
+        if (compress != null) {
+            updateCompress(compress, selectionDetails);
+        }
     }
 
     /**
diff --git a/src/com/android/documentsui/PreBootReceiver.java b/src/com/android/documentsui/PreBootReceiver.java
index 2bdbee555..afb32dd54 100644
--- a/src/com/android/documentsui/PreBootReceiver.java
+++ b/src/com/android/documentsui/PreBootReceiver.java
@@ -95,8 +95,11 @@ public class PreBootReceiver extends BroadcastReceiver {
         if (resId != 0) {
             final ComponentName component = new ComponentName(packageName, className);
             boolean enabled = overlayRes.getBoolean(resId);
-            if (VersionUtils.isAtLeastS() && CONFIG_IS_LAUNCHER_ENABLED.equals(config)) {
-                enabled = false; // Do not allow LauncherActivity to be enabled for S+.
+            if (VersionUtils.isAtLeastS() && !pm.hasSystemFeature(PackageManager.FEATURE_PC)
+                    && CONFIG_IS_LAUNCHER_ENABLED.equals(config)) {
+                // Devices using S+ that don't support the `FEATURE_PC` system feature should not
+                // show Files in the launcher.
+                enabled = false;
             }
             if (DEBUG) {
                 Log.i(TAG,
diff --git a/src/com/android/documentsui/base/Shared.java b/src/com/android/documentsui/base/Shared.java
index 5ac9de4d7..ac089999f 100644
--- a/src/com/android/documentsui/base/Shared.java
+++ b/src/com/android/documentsui/base/Shared.java
@@ -17,11 +17,10 @@
 package com.android.documentsui.base;
 
 import static com.android.documentsui.base.SharedMinimal.TAG;
+import static com.android.documentsui.ChangeIds.RESTRICT_STORAGE_ACCESS_FRAMEWORK;
 
 import android.app.Activity;
 import android.app.compat.CompatChanges;
-import android.compat.annotation.ChangeId;
-import android.compat.annotation.EnabledAfter;
 import android.content.ComponentName;
 import android.content.ContentResolver;
 import android.content.Context;
@@ -143,16 +142,6 @@ public final class Shared {
 
     private static final Collator sCollator;
 
-    /**
-     * We support restrict Storage Access Framework from {@link android.os.Build.VERSION_CODES#R}.
-     * App Compatibility flag that indicates whether the app should be restricted or not.
-     * This flag is turned on by default for all apps targeting >
-     * {@link android.os.Build.VERSION_CODES#Q}.
-     */
-    @ChangeId
-    @EnabledAfter(targetSdkVersion = android.os.Build.VERSION_CODES.Q)
-    private static final long RESTRICT_STORAGE_ACCESS_FRAMEWORK = 141600225L;
-
     static {
         sCollator = Collator.getInstance();
         sCollator.setStrength(Collator.SECONDARY);
diff --git a/src/com/android/documentsui/dirlist/DirectoryFragment.java b/src/com/android/documentsui/dirlist/DirectoryFragment.java
index 04589552b..e099ca734 100644
--- a/src/com/android/documentsui/dirlist/DirectoryFragment.java
+++ b/src/com/android/documentsui/dirlist/DirectoryFragment.java
@@ -321,8 +321,6 @@ public class DirectoryFragment extends Fragment implements SwipeRefreshLayout.On
                 }
                 mActivity.refreshCurrentRootAndDirectory(AnimationView.ANIM_NONE);
             }
-        } else {
-            checkUriAndScheduleCheckIfNeeded(userId);
         }
     }
 
@@ -950,7 +948,7 @@ public class DirectoryFragment extends Fragment implements SwipeRefreshLayout.On
             // Need to plum down into handling the way we do with deleteDocuments.
             mActionModeController.finishActionMode();
             return true;
-        } else if (id == R.id.action_menu_compress) {
+        } else if (id == R.id.action_menu_compress || id == R.id.dir_menu_compress) {
             transferDocuments(selection, mState.stack,
                     FileOperationService.OPERATION_COMPRESS);
             // TODO: Only finish selection mode if compress is not canceled.
@@ -1387,11 +1385,16 @@ public class DirectoryFragment extends Fragment implements SwipeRefreshLayout.On
         // Remove thumbnail cache. We do this not because we're worried about stale thumbnails as it
         // should be covered by last modified value we store in thumbnail cache, but rather to give
         // the user a greater sense that contents are being reloaded.
-        ThumbnailCache cache = DocumentsApplication.getThumbnailCache(getContext());
-        String[] ids = mModel.getModelIds();
-        int numOfEvicts = Math.min(ids.length, CACHE_EVICT_LIMIT);
-        for (int i = 0; i < numOfEvicts; ++i) {
-            cache.removeUri(mModel.getItemUri(ids[i]), mModel.getItemUserId(ids[i]));
+        Context context = getContext();
+        if (context == null) {
+            Log.w(TAG, "Fragment is not attached to an activity.");
+        } else {
+            ThumbnailCache cache = DocumentsApplication.getThumbnailCache(context);
+            String[] ids = mModel.getModelIds();
+            int numOfEvicts = Math.min(ids.length, CACHE_EVICT_LIMIT);
+            for (int i = 0; i < numOfEvicts; ++i) {
+                cache.removeUri(mModel.getItemUri(ids[i]), mModel.getItemUserId(ids[i]));
+            }
         }
 
         final DocumentInfo doc = mActivity.getCurrentDirectory();
diff --git a/src/com/android/documentsui/files/FilesActivity.java b/src/com/android/documentsui/files/FilesActivity.java
index 7a53e5361..1ebe2374f 100644
--- a/src/com/android/documentsui/files/FilesActivity.java
+++ b/src/com/android/documentsui/files/FilesActivity.java
@@ -321,7 +321,6 @@ public class FilesActivity extends BaseActivity implements AbstractActionHandler
 
     @Override
     public boolean onOptionsItemSelected(MenuItem item) {
-        DirectoryFragment dir;
         final int id = item.getItemId();
         if (id == R.id.option_menu_create_dir) {
             assert (canCreateDirectory());
diff --git a/src/com/android/documentsui/queries/SearchChipViewManager.java b/src/com/android/documentsui/queries/SearchChipViewManager.java
index f80a3a7fa..3dbc6ff74 100644
--- a/src/com/android/documentsui/queries/SearchChipViewManager.java
+++ b/src/com/android/documentsui/queries/SearchChipViewManager.java
@@ -16,6 +16,8 @@
 
 package com.android.documentsui.queries;
 
+import static com.android.documentsui.flags.Flags.useMaterial3;
+
 import android.animation.ObjectAnimator;
 import android.content.Context;
 import android.graphics.drawable.Drawable;
@@ -39,6 +41,7 @@ import com.android.documentsui.base.Shared;
 import com.android.documentsui.util.VersionUtils;
 
 import com.google.android.material.chip.Chip;
+import com.google.android.material.chip.ChipGroup;
 import com.google.common.primitives.Ints;
 
 import java.time.LocalDate;
@@ -372,6 +375,21 @@ public class SearchChipViewManager {
         }
     }
 
+    /**
+     * When the chip is focused, adding a focus ring indicator using Stroke.
+     */
+    private void onChipFocusChange(View v, boolean hasFocus) {
+        Chip chip = (Chip) v;
+        if (hasFocus) {
+            final int focusRingWidth = mChipGroup
+                    .getResources()
+                    .getDimensionPixelSize(R.dimen.focus_ring_width);
+            chip.setChipStrokeWidth(focusRingWidth);
+        } else {
+            chip.setChipStrokeWidth(1f);
+        }
+    }
+
     private void bindChip(Chip chip, SearchChipData chipData) {
         final Context context = mChipGroup.getContext();
         chip.setTag(chipData);
@@ -390,6 +408,10 @@ public class SearchChipViewManager {
         chip.setChipIcon(chipIcon);
         chip.setOnClickListener(this::onChipClick);
 
+        if (useMaterial3()) {
+            chip.setOnFocusChangeListener(this::onChipFocusChange);
+        }
+
         if (mCheckedChipItems.contains(chipData)) {
             setChipChecked(chip, true);
         }
@@ -425,10 +447,20 @@ public class SearchChipViewManager {
             return;
         }
 
-        final int chipSpacing = mChipGroup.getResources().getDimensionPixelSize(
-                R.dimen.search_chip_spacing);
+        final int chipSpacing =
+                useMaterial3()
+                        ? ((ChipGroup) mChipGroup).getChipSpacingHorizontal()
+                        : mChipGroup
+                                .getResources()
+                                .getDimensionPixelSize(R.dimen.search_chip_spacing);
         final boolean isRtl = mChipGroup.getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
-        float lastX = isRtl ? mChipGroup.getWidth() - chipSpacing / 2 : chipSpacing / 2;
+        final float chipMarginStartEnd =
+                useMaterial3()
+                        ? 0
+                        : mChipGroup
+                                .getResources()
+                                .getDimensionPixelSize(R.dimen.search_chip_half_spacing);
+        float lastX = isRtl ? mChipGroup.getWidth() - chipMarginStartEnd : chipMarginStartEnd;
 
         // remove all chips except current clicked chip to avoid losing
         // accessibility focus.
diff --git a/tests/common/com/android/documentsui/testing/TestMenu.java b/tests/common/com/android/documentsui/testing/TestMenu.java
index 5181c730b..10e0ea493 100644
--- a/tests/common/com/android/documentsui/testing/TestMenu.java
+++ b/tests/common/com/android/documentsui/testing/TestMenu.java
@@ -44,6 +44,7 @@ public abstract class TestMenu implements Menu {
                 R.id.dir_menu_open_with,
                 R.id.dir_menu_cut_to_clipboard,
                 R.id.dir_menu_copy_to_clipboard,
+                R.id.dir_menu_compress,
                 R.id.dir_menu_paste_from_clipboard,
                 R.id.dir_menu_create_dir,
                 R.id.dir_menu_select_all,
diff --git a/tests/functional/com/android/documentsui/overlay/OverlayableTest.java b/tests/functional/com/android/documentsui/overlay/OverlayableTest.java
index d56470a61..092f4a15d 100644
--- a/tests/functional/com/android/documentsui/overlay/OverlayableTest.java
+++ b/tests/functional/com/android/documentsui/overlay/OverlayableTest.java
@@ -43,12 +43,6 @@ public class OverlayableTest extends ThemeUiTestBase {
         super.setUp();
     }
 
-    @Test
-    public void testConfig_isLauncherEnable_isNotNull() {
-        assertThat(
-                mTargetContext.getResources().getBoolean(R.bool.is_launcher_enabled)).isNotNull();
-    }
-
     @Test
     public void testConfig_defaultRootUri_isNotEmpty() {
         assertThat(
diff --git a/tests/unit/com/android/documentsui/dirlist/MessageTest.java b/tests/unit/com/android/documentsui/dirlist/MessageTest.java
index efc25f56e..f7f8fe0e6 100644
--- a/tests/unit/com/android/documentsui/dirlist/MessageTest.java
+++ b/tests/unit/com/android/documentsui/dirlist/MessageTest.java
@@ -37,6 +37,7 @@ import android.content.pm.UserProperties;
 import android.graphics.drawable.Drawable;
 import android.os.UserHandle;
 import android.os.UserManager;
+import android.util.Log;
 
 import androidx.core.util.Preconditions;
 import androidx.test.filters.SmallTest;
@@ -65,6 +66,7 @@ import org.junit.runners.Parameterized.Parameter;
 import org.junit.runners.Parameterized.Parameters;
 
 import java.util.HashMap;
+import java.util.Locale;
 import java.util.Map;
 
 @SmallTest
@@ -157,10 +159,25 @@ public final class MessageTest {
 
         assertThat(mInflateMessage.getLayout())
                 .isEqualTo(InflateMessageDocumentHolder.LAYOUT_CROSS_PROFILE_ERROR);
-        assertThat(mInflateMessage.getTitleString())
-                .isEqualTo(mContext.getString(R.string.cant_select_work_files_error_title));
-        assertThat(mInflateMessage.getMessageString())
-                .isEqualTo(mContext.getString(R.string.cant_select_work_files_error_message));
+        Log.d("DocsUiAdi", "title string in test = " + mInflateMessage.getTitleString());
+        if (isPrivateSpaceEnabled) {
+            String workLabel = mContext.getString(R.string.work_tab);
+            String personalLabel = mContext.getString(R.string.personal_tab);
+            assertThat(mInflateMessage.getTitleString())
+                    .isEqualTo(
+                            mContext.getString(R.string.cant_select_cross_profile_files_error_title,
+                                    workLabel.toLowerCase(Locale.getDefault())));
+            assertThat(mInflateMessage.getMessageString())
+                    .isEqualTo(mContext.getString(
+                            R.string.cant_select_cross_profile_files_error_message,
+                            workLabel.toLowerCase(Locale.getDefault()),
+                            personalLabel.toLowerCase(Locale.getDefault())));
+        } else {
+            assertThat(mInflateMessage.getTitleString())
+                    .isEqualTo(mContext.getString(R.string.cant_select_work_files_error_title));
+            assertThat(mInflateMessage.getMessageString())
+                    .isEqualTo(mContext.getString(R.string.cant_select_work_files_error_message));
+        }
         // No button for this error
         assertThat(mInflateMessage.getButtonString()).isNull();
     }
diff --git a/tests/unit/com/android/documentsui/files/MenuManagerTest.java b/tests/unit/com/android/documentsui/files/MenuManagerTest.java
index fe1d02209..02988d62f 100644
--- a/tests/unit/com/android/documentsui/files/MenuManagerTest.java
+++ b/tests/unit/com/android/documentsui/files/MenuManagerTest.java
@@ -60,6 +60,7 @@ public final class MenuManagerTest {
     private TestMenuItem dirOpenWith;
     private TestMenuItem dirCutToClipboard;
     private TestMenuItem dirCopyToClipboard;
+    private TestMenuItem mDirCompress;
     private TestMenuItem dirPasteFromClipboard;
     private TestMenuItem dirCreateDir;
     private TestMenuItem dirSelectAll;
@@ -132,6 +133,7 @@ public final class MenuManagerTest {
         dirOpenWith = testMenu.findItem(R.id.dir_menu_open_with);
         dirCutToClipboard = testMenu.findItem(R.id.dir_menu_cut_to_clipboard);
         dirCopyToClipboard = testMenu.findItem(R.id.dir_menu_copy_to_clipboard);
+        mDirCompress = testMenu.findItem(R.id.dir_menu_compress);
         dirPasteFromClipboard = testMenu.findItem(R.id.dir_menu_paste_from_clipboard);
         dirCreateDir = testMenu.findItem(R.id.dir_menu_create_dir);
         dirSelectAll = testMenu.findItem(R.id.dir_menu_select_all);
@@ -581,6 +583,7 @@ public final class MenuManagerTest {
         dirOpen.assertDisabledAndInvisible();
         dirCutToClipboard.assertDisabledAndInvisible();
         dirCopyToClipboard.assertEnabledAndVisible();
+        mDirCompress.assertDisabledAndInvisible();
         dirRename.assertDisabledAndInvisible();
         dirCreateDir.assertEnabledAndVisible();
         dirDelete.assertDisabledAndInvisible();
@@ -605,6 +608,7 @@ public final class MenuManagerTest {
         selectionDetails.size = 3;
         mgr.updateContextMenuForFiles(testMenu, selectionDetails);
         dirOpen.assertDisabledAndInvisible();
+        mDirCompress.assertDisabledAndInvisible();
     }
 
     @Test
@@ -616,6 +620,7 @@ public final class MenuManagerTest {
         dirOpenInNewWindow.assertEnabledAndVisible();
         dirCutToClipboard.assertDisabledAndInvisible();
         dirCopyToClipboard.assertEnabledAndVisible();
+        mDirCompress.assertDisabledAndInvisible();
         dirPasteIntoFolder.assertEnabledAndVisible();
         dirRename.assertDisabledAndInvisible();
         dirDelete.assertDisabledAndInvisible();
@@ -629,6 +634,7 @@ public final class MenuManagerTest {
         dirOpenInNewWindow.assertEnabledAndVisible();
         dirCutToClipboard.assertDisabledAndInvisible();
         dirCopyToClipboard.assertEnabledAndVisible();
+        mDirCompress.assertDisabledAndInvisible();
         dirPasteIntoFolder.assertDisabledAndInvisible();
         dirRename.assertDisabledAndInvisible();
         dirDelete.assertDisabledAndInvisible();
@@ -656,6 +662,7 @@ public final class MenuManagerTest {
         selectionDetails.size = 3;
         mgr.updateContextMenuForDirs(testMenu, selectionDetails);
         dirOpenInNewWindow.assertDisabledAndInvisible();
+        mDirCompress.assertDisabledAndInvisible();
     }
 
     @Test
@@ -667,6 +674,7 @@ public final class MenuManagerTest {
         mgr.updateContextMenu(testMenu, selectionDetails);
         dirCutToClipboard.assertEnabledAndVisible();
         dirCopyToClipboard.assertEnabledAndVisible();
+        mDirCompress.assertDisabledAndInvisible();
         dirDelete.assertEnabledAndVisible();
     }
 
@@ -680,6 +688,7 @@ public final class MenuManagerTest {
         mgr.updateContextMenu(testMenu, selectionDetails);
         dirCutToClipboard.assertDisabledAndInvisible();
         dirCopyToClipboard.assertDisabledAndInvisible();
+        mDirCompress.assertDisabledAndInvisible();
         dirDelete.assertEnabledAndVisible();
     }
 
@@ -692,6 +701,7 @@ public final class MenuManagerTest {
         mgr.updateContextMenu(testMenu, selectionDetails);
         dirCutToClipboard.assertDisabledAndInvisible();
         dirCopyToClipboard.assertEnabledAndVisible();
+        mDirCompress.assertDisabledAndInvisible();
         dirDelete.assertDisabledAndInvisible();
     }
 
```

