```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 90dcf3e..f6b8db3 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -26,7 +26,7 @@
          android:supportsRtl="true">
         <activity android:name="HTMLViewerActivity"
              android:label="@string/app_label"
-             android:theme="@style/Theme.HTMLViewer"
+             android:theme="@android:style/Theme.DeviceDefault.Settings"
              android:exported="true">
             <intent-filter>
                 <category android:name="android.intent.category.DEFAULT"/>
diff --git a/res/values/themes.xml b/res/values/themes.xml
deleted file mode 100644
index d1ce102..0000000
--- a/res/values/themes.xml
+++ /dev/null
@@ -1,22 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-    Copyright (C) 2024 The Android Open Source Project
-
-    Licensed under the Apache License, Version 2.0 (the "License");
-    you may not use this file except in compliance with the License.
-    You may obtain a copy of the License at
-
-         http://www.apache.org/licenses/LICENSE-2.0
-
-    Unless required by applicable law or agreed to in writing, software
-    distributed under the License is distributed on an "AS IS" BASIS,
-    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-    See the License for the specific language governing permissions and
-    limitations under the License.
-  -->
-
-<resources>
-    <style name="Theme.HTMLViewer" parent="@android:style/Theme.DeviceDefault.Settings">
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
-    </style>
-</resources>
\ No newline at end of file
```

