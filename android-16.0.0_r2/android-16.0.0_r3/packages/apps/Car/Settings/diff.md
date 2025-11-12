```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 30e5d1a1e..49e54aec4 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -47,7 +47,6 @@
     <uses-permission android:name="android.permission.GET_PACKAGE_SIZE"/>
     <uses-permission android:name="android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS"/>
     <uses-permission android:name="android.permission.INJECT_EVENTS"/>
-    <uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
     <uses-permission android:name="android.permission.INTERNET"/>
     <uses-permission android:name="android.permission.MANAGE_ACCOUNTS"/>
     <uses-permission android:name="android.permission.MANAGE_SENSOR_PRIVACY"/>
@@ -827,6 +826,9 @@
                 <action android:name="android.settings.MANAGE_DOMAIN_URLS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.APP_OPEN_BY_DEFAULT_SETTINGS" />
+            </intent-filter>
             <meta-data android:name="com.android.car.settings.SINGLE_PANE" android:value="true"/>
             <meta-data android:name="distractionOptimized" android:value="true"/>
         </activity>
@@ -1107,13 +1109,21 @@
                   android:theme="@style/AlertDialogTheme"
                   android:excludeFromRecents="true"
                   android:exported="true"
-                  android:launchMode="singleTask">
+                  android:launchMode="singleTop">
             <meta-data android:name="distractionOptimized" android:value="true"/>
             <!-- Common Settings Intents -->
+            <intent-filter>
+                <action android:name="android.settings.ADVANCED_MEMORY_PROTECTION_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
             <intent-filter>
                 <action android:name="android.settings.AIRPLANE_MODE_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.APP_LOCALE_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
             <intent-filter>
                 <action android:name="android.settings.APP_NOTIFICATION_PROMOTION_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
@@ -1138,6 +1148,26 @@
                 <action android:name="android.settings.IGNORE_BATTERY_OPTIMIZATION_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.MANAGE_DEFAULT_APPS_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.MANAGE_UNKNOWN_APP_SOURCES" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
             <intent-filter>
                 <action android:name="android.settings.MEMORY_CARD_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
@@ -1178,6 +1208,14 @@
                 <action android:name="android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.REQUEST_MANAGE_MEDIA" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.REQUEST_MEDIA_ROUTING_CONTROL" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
             <intent-filter>
                 <action android:name="android.settings.VOICE_CONTROL_AIRPLANE_MODE" />
                 <category android:name="android.intent.category.DEFAULT" />
@@ -1230,6 +1268,10 @@
                 <action android:name="android.settings.NOTIFICATION_ASSISTANT_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.panel.action.NFC" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
             <intent-filter>
                 <action android:name="android.settings.QUICK_ACCESS_WALLET_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
@@ -1253,11 +1295,33 @@
             <intent-filter>
                 <action android:name="android.settings.STORAGE_VOLUME_ACCESS_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+                <intent-filter>
+                    <action android:name="android.settings.USER_DICTIONARY_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
             <intent-filter>
                 <action android:name="android.settings.VPN_SETTINGS" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.WEBVIEW_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter>
+                <action android:name="android.settings.SHOW_REGULATORY_INFO" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <!-- To remove after they are supported by injected settings apps -->
+            <intent-filter android:priority="-1">
+                <action android:name="android.settings.CAST_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <intent-filter android:priority="-1">
+                <action android:name="android.settings.CREDENTIAL_PROVIDER" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+
         </activity>
 
         <service android:name=".bluetooth.BluetoothPairingService"
diff --git a/OWNERS b/OWNERS
index d9b52a88b..3d0b130cc 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,7 +3,7 @@
 # Primary
 danzz@google.com
 eschiang@google.com
-cassieyw@google.com
+alanschen@google.com
 
 # Secondary (only if people in Primary are unreachable)
 dnek@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/aconfig/carsettings.aconfig b/aconfig/carsettings.aconfig
index b408f4769..bc25fa2ea 100644
--- a/aconfig/carsettings.aconfig
+++ b/aconfig/carsettings.aconfig
@@ -49,3 +49,10 @@ flag {
     description: "Flag to display several new fragments added to host necessary intents."
     bug: "376744576"
 }
+
+flag {
+    name: "car_settings_multi_casting"
+    namespace: "car_sys_exp"
+    description: "Flag to display the multi-casting feature in Car Settings."
+    bug: "406359269"
+}
diff --git a/res/drawable/ic_audio_sharing.xml b/res/drawable/ic_audio_sharing.xml
new file mode 100644
index 000000000..d909cc06b
--- /dev/null
+++ b/res/drawable/ic_audio_sharing.xml
@@ -0,0 +1,26 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="@dimen/icon_size"
+        android:height="@dimen/icon_size"
+        android:viewportWidth="960"
+        android:viewportHeight="960">
+    <path
+        android:fillColor="@color/icon_color_default"
+        android:pathData="M320,880L480,596L640,880L320,880ZM480,560Q447,560 423.5,536.5Q400,513 400,480Q400,447 423.5,423.5Q447,400 480,400Q513,400 536.5,423.5Q560,447 560,480Q560,513 536.5,536.5Q513,560 480,560ZM339,661Q322,661 310.5,649.5Q299,638 299,621Q299,604 310.5,592.5Q322,581 339,581Q356,581 367.5,592.5Q379,604 379,621Q379,638 367.5,649.5Q356,661 339,661ZM280,520Q263,520 251.5,508.5Q240,497 240,480Q240,463 251.5,451.5Q263,440 280,440Q297,440 308.5,451.5Q320,463 320,480Q320,497 308.5,508.5Q297,520 280,520ZM339,379Q322,379 310.5,367.5Q299,356 299,339Q299,322 310.5,310.5Q322,299 339,299Q356,299 367.5,310.5Q379,322 379,339Q379,356 367.5,367.5Q356,379 339,379ZM480,320Q463,320 451.5,308.5Q440,297 440,280Q440,263 451.5,251.5Q463,240 480,240Q497,240 508.5,251.5Q520,263 520,280Q520,297 508.5,308.5Q497,320 480,320ZM621,379Q604,379 592.5,367.5Q581,356 581,339Q581,322 592.5,310.5Q604,299 621,299Q638,299 649.5,310.5Q661,322 661,339Q661,356 649.5,367.5Q638,379 621,379ZM680,520Q663,520 651.5,508.5Q640,497 640,480Q640,463 651.5,451.5Q663,440 680,440Q697,440 708.5,451.5Q720,463 720,480Q720,497 708.5,508.5Q697,520 680,520ZM621,661Q604,661 592.5,649.5Q581,638 581,621Q581,604 592.5,592.5Q604,581 621,581Q638,581 649.5,592.5Q661,604 661,621Q661,638 649.5,649.5Q638,661 621,661ZM255,801Q238,801 226,788.5Q214,776 214,759Q214,742 226,730Q238,718 255,718Q272,718 284.5,730Q297,742 297,759Q297,776 284.5,788.5Q272,801 255,801ZM156,676Q139,676 127.5,664Q116,652 116,635Q116,618 127.5,606.5Q139,595 156,595Q173,595 185,606.5Q197,618 197,635Q197,652 185,664Q173,676 156,676ZM120,520Q103,520 91.5,508.5Q80,497 80,480Q80,463 91.5,451.5Q103,440 120,440Q137,440 148.5,451.5Q160,463 160,480Q160,497 148.5,508.5Q137,520 120,520ZM156,363Q139,363 127.5,351.5Q116,340 116,323Q116,306 127.5,294.5Q139,283 156,283Q173,283 184.5,294.5Q196,306 196,323Q196,340 184.5,351.5Q173,363 156,363ZM256,239Q239,239 227.5,227.5Q216,216 216,199Q216,182 227.5,170.5Q239,159 256,159Q273,159 284.5,170.5Q296,182 296,199Q296,216 284.5,227.5Q273,239 256,239ZM400,169Q383,169 371.5,157.5Q360,146 360,129Q360,112 371.5,100.5Q383,89 400,89Q417,89 428.5,100.5Q440,112 440,129Q440,146 428.5,157.5Q417,169 400,169ZM560,169Q543,169 531.5,157.5Q520,146 520,129Q520,112 531.5,100.5Q543,89 560,89Q577,89 588.5,100.5Q600,112 600,129Q600,146 588.5,157.5Q577,169 560,169ZM705,239Q688,239 676.5,227.5Q665,216 665,199Q665,182 676.5,170.5Q688,159 705,159Q722,159 733.5,170.5Q745,182 745,199Q745,216 733.5,227.5Q722,239 705,239ZM805,364Q788,364 776.5,352.5Q765,341 765,324Q765,307 776.5,295.5Q788,284 805,284Q822,284 833.5,295.5Q845,307 845,324Q845,341 833.5,352.5Q822,364 805,364ZM840,520Q823,520 811.5,508.5Q800,497 800,480Q800,463 811.5,451.5Q823,440 840,440Q857,440 868.5,451.5Q880,463 880,480Q880,497 868.5,508.5Q857,520 840,520ZM805,676Q788,676 776.5,664.5Q765,653 765,636Q765,619 776.5,607.5Q788,596 805,596Q822,596 833.5,607.5Q845,619 845,636Q845,653 833.5,664.5Q822,676 805,676ZM705,801Q688,801 676.5,789.5Q665,778 665,761Q665,744 676.5,732.5Q688,721 705,721Q722,721 733.5,732.5Q745,744 745,761Q745,778 733.5,789.5Q722,801 705,801Z"/>
+</vector>
diff --git a/res/drawable/ic_music_cast.xml b/res/drawable/ic_music_cast.xml
new file mode 100644
index 000000000..397d5b551
--- /dev/null
+++ b/res/drawable/ic_music_cast.xml
@@ -0,0 +1,26 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="@dimen/icon_size"
+        android:height="@dimen/icon_size"
+        android:viewportWidth="960"
+        android:viewportHeight="960">
+    <path
+        android:fillColor="@color/icon_color_default"
+        android:pathData="M560,800Q494,800 447,753Q400,706 400,640Q400,574 447,527Q494,480 560,480Q583,480 602.5,485.5Q622,491 640,502L640,160L880,160L880,280L720,280L720,640Q720,706 673,753Q626,800 560,800ZM80,640Q80,541 118,453.5Q156,366 221,301Q286,236 373.5,198Q461,160 560,160L560,240Q478,240 405,271.5Q332,303 277.5,357.5Q223,412 191.5,484.5Q160,557 160,640L80,640ZM240,640Q240,574 265.5,515.5Q291,457 334.5,413.5Q378,370 436,345Q494,320 560,320L560,400Q460,400 390,470Q320,540 320,640L240,640Z"/>
+</vector>
diff --git a/res/drawable/ic_volume_up.xml b/res/drawable/ic_volume_up.xml
new file mode 100644
index 000000000..0cc5d66c4
--- /dev/null
+++ b/res/drawable/ic_volume_up.xml
@@ -0,0 +1,26 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="@dimen/icon_size"
+        android:height="@dimen/icon_size"
+        android:viewportWidth="960"
+        android:viewportHeight="960">
+    <path
+        android:fillColor="@color/icon_color_default"
+        android:pathData="M560,829L560,747Q650,721 705,647Q760,573 760,479Q760,385 705,311Q650,237 560,211L560,129Q684,157 762,254.5Q840,352 840,479Q840,606 762,703.5Q684,801 560,829ZM120,600L120,360L280,360L480,160L480,800L280,600L120,600ZM560,640L560,318Q607,340 633.5,384Q660,428 660,480Q660,531 633.5,574.5Q607,618 560,640ZM400,354L314,440L200,440L200,520L314,520L400,606L400,354ZM300,480L300,480L300,480L300,480L300,480L300,480Z"/>
+</vector>
diff --git a/res/drawable/top_level_preference_background.xml b/res/drawable/top_level_preference_background.xml
deleted file mode 100644
index 597a36c7f..000000000
--- a/res/drawable/top_level_preference_background.xml
+++ /dev/null
@@ -1,45 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-  ~ Copyright (C) 2021 The Android Open Source Project
-  ~
-  ~ Licensed under the Apache License, Version 2.0 (the "License");
-  ~ you may not use this file except in compliance with the License.
-  ~ You may obtain a copy of the License at
-  ~
-  ~      http://www.apache.org/licenses/LICENSE-2.0
-  ~
-  ~ Unless required by applicable law or agreed to in writing, software
-  ~ distributed under the License is distributed on an "AS IS" BASIS,
-  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  ~ See the License for the specific language governing permissions and
-  ~ limitations under the License.
-  -->
-
-<selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_focused="true" android:state_pressed="true">
-        <shape android:shape="rectangle">
-            <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
-            <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
-                    android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-            <corners android:radius="?topLevelPreferenceCornerRadius"/>
-        </shape>
-    </item>
-    <item android:state_focused="true">
-        <shape android:shape="rectangle">
-            <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
-            <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
-                    android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="?topLevelPreferenceCornerRadius"/>
-        </shape>
-    </item>
-    <item>
-        <ripple android:color="?android:attr/colorControlHighlight">
-            <item>
-                <shape android:shape="rectangle">
-                    <solid android:color="@color/car_card_ripple_background" />
-                    <corners android:radius="?topLevelPreferenceCornerRadius"/>
-                </shape>
-            </item>
-        </ripple>
-    </item>
-</selector>
diff --git a/res/drawable/top_level_preference_highlight.xml b/res/drawable/top_level_preference_highlight.xml
deleted file mode 100644
index f97ae21f6..000000000
--- a/res/drawable/top_level_preference_highlight.xml
+++ /dev/null
@@ -1,40 +0,0 @@
-<!--
-  ~ Copyright (C) 2021 The Android Open Source Project
-  ~
-  ~ Licensed under the Apache License, Version 2.0 (the "License");
-  ~ you may not use this file except in compliance with the License.
-  ~ You may obtain a copy of the License at
-  ~
-  ~      http://www.apache.org/licenses/LICENSE-2.0
-  ~
-  ~ Unless required by applicable law or agreed to in writing, software
-  ~ distributed under the License is distributed on an "AS IS" BASIS,
-  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  ~ See the License for the specific language governing permissions and
-  ~ limitations under the License.
-  -->
-
-<selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_focused="true" android:state_pressed="true">
-        <shape android:shape="rectangle">
-            <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
-            <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
-                    android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-            <corners android:radius="?topLevelPreferenceCornerRadius"/>
-        </shape>
-    </item>
-    <item android:state_focused="true">
-        <shape android:shape="rectangle">
-            <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
-            <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
-                    android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="?topLevelPreferenceCornerRadius"/>
-        </shape>
-    </item>
-    <item>
-        <shape android:shape="rectangle">
-            <solid android:color="@*android:color/car_card_ripple_background"/>
-            <corners android:radius="?topLevelPreferenceCornerRadius"/>
-        </shape>
-    </item>
-</selector>
diff --git a/res/layout/audio_sharing_device_selector_preference_group.xml b/res/layout/audio_sharing_device_selector_preference_group.xml
new file mode 100644
index 000000000..7698a2a3e
--- /dev/null
+++ b/res/layout/audio_sharing_device_selector_preference_group.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright 2025 The Android Open Source Project
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"/>
diff --git a/res/layout/audio_stream_qr_preference.xml b/res/layout/audio_stream_qr_preference.xml
new file mode 100644
index 000000000..0d5dd4863
--- /dev/null
+++ b/res/layout/audio_stream_qr_preference.xml
@@ -0,0 +1,44 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright 2025 The Android Open Source Project
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
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingEnd="?android:attr/listPreferredItemPaddingEnd"
+    android:paddingStart="?android:attr/listPreferredItemPaddingStart"
+    android:layout_marginTop="@dimen/qc_code_preference_margin"
+    android:layout_marginBottom="@dimen/qc_code_preference_margin"
+    android:layout_centerHorizontal="true"
+    android:gravity="center_horizontal"
+    android:orientation="vertical">
+    <androidx.cardview.widget.CardView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:scaleType="fitCenter"
+        android:antialias="true"
+        android:layout_marginTop="@dimen/qc_code_preference_margin"
+        android:layout_marginBottom="@dimen/qc_code_preference_margin"
+        app:cardElevation="@dimen/card_view_elevation"
+        app:cardCornerRadius="?audioSharingQrCodeRoundedCornerRadius">
+        <ImageView
+            android:id="@+id/audio_sharing_qr_code"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"/>
+    </androidx.cardview.widget.CardView>
+</LinearLayout>
diff --git a/res/layout/top_level_preference.xml b/res/layout/top_level_preference.xml
index 6a0593485..c7968f571 100644
--- a/res/layout/top_level_preference.xml
+++ b/res/layout/top_level_preference.xml
@@ -19,7 +19,7 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
-    android:background="@drawable/top_level_preference_background"
+    android:background="?android:attr/selectableItemBackground"
     android:clipToPadding="false"
     android:minHeight="@dimen/top_level_preference_min_height"
     android:paddingEnd="?android:attr/listPreferredItemPaddingEnd"
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 4fa43de2c..2f289f1ac 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Toestelverbindings met jou motor"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultrawyeband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Help jou motor om die posisie van UWB-toestelle te identifiseer"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Oudiodeling"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Deel oudio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Luisteraars moet hul eie LE-oudio-oorfone hê"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Speel ’n toetsklank"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Almal wat luister behoort dit te hoor"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktiewe mediatoestelle"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Instellings van oudiostroom"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-kode van oudiostroom"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skandeer QR-kode om te koppel"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Ander mense kan versoenbare oorfone aan hul Android-toestel koppel om na oudiostroom te luister. Hulle kan dan hierdie QR-kode skandeer."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth-saambindversoek"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Bind saam en koppel"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-saambindkode"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Ander programme"</string>
     <string name="storage_files" msgid="6382081694781340364">"Lêers"</string>
     <string name="storage_system" msgid="1271345630248014010">"Stelsel"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s in totaal"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Stelsel sluit lêers in wat gebruik word om Android-weergawe <xliff:g id="VERSION">%s</xliff:g> te laat werk"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Oudiolêers"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Bereken tans …"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 6dac5069f..720bb7879 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ከመኪናዎ ጋር ያሉ የመሣሪያ ግንኙነቶች"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"ልዕለ-ሰፊ ባንድ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"መኪናዎ የUWB መሣሪያዎችን አቀማመጥ እንዲለይ ያግዛል"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"የድምፅ ማጋራት"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ኦዲዮ ያጋሩ"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"አድማጮች የራሳቸው LE ኦዲዮ የራስ ላይ ማዳመጫዎች ያስፈልጋቸዋል"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"የሙከራ ድምፅ ያጫውቱ"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"የሚያዳምጥ ሁሉም ሰው ሊሰማው ይገባል"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ገቢር የማህደረ መረጃ መሣሪያዎች"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"የኦዲዮ ዥረት ቅንብሮች"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"የኦዲዮ ዥረት QR ኮድ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"ለመገናኘት QR ኮድ ይቃኙ"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ኦዲዮ ዥረት ለማዳመጥ ሌሎች ሰዎች ተኳኳኝ የራስ ላይ ማዳመጫዎችን ከandroid መሣሪያቸው ጋር ማገናኘት ይችላሉ። ከዚያ ይህን QR ኮድ መቃኘት ይችላሉ።"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"የብሉቱዝ ማጣመር ጥያቄ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"አጣምር እና ተገናኝ"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"የብሉቱዝ ማጣመሪያ ኮድ"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"ሌሎች መተግበሪያዎች"</string>
     <string name="storage_files" msgid="6382081694781340364">"ፋይሎች"</string>
     <string name="storage_system" msgid="1271345630248014010">"ሥርዓት"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s አጠቃላይ"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"ስርዓት የAndroid ስሪት <xliff:g id="VERSION">%s</xliff:g>ን ለማሄድ ሥራ ላይ የዋሉ ፋይሎችን ያካትታል"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"የኦዲዮ ፋይሎች"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"በማስላት ላይ…"</string>
@@ -925,7 +936,7 @@
     <string name="screen_reader_settings_title" msgid="4012734340987826872">"ማያ ገፅ አንባቢ"</string>
     <string name="show_captions_toggle_title" msgid="710582308974826311">"መግለጫ ጽሑፎችን አሳይ"</string>
     <string name="captions_text_size_title" msgid="1960814652560877963">"የጽሑፍ መጠን"</string>
-    <string name="captions_settings_style_header" msgid="944591388386054372">"የመግለጫ ጽሁፍ መጠን እና ቅጥ"</string>
+    <string name="captions_settings_style_header" msgid="944591388386054372">"የመግለጫ ጽሑፍ መጠን እና ቅጥ"</string>
     <string name="captions_settings_text_size_very_small" msgid="7476485317028306502">"በጣም ትንሽ"</string>
     <string name="captions_settings_text_size_small" msgid="1481895299805450566">"ትንሽ"</string>
     <string name="captions_settings_text_size_default" msgid="2227802573224038267">"ነባሪ"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 6b15d92c7..e1d9628d4 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"اتصالات الأجهزة بسيارتك"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"النطاق الفائق العرض (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"يساعد هذا الخيار سيارتك في التعرّف على موقع أجهزة النطاق الفائق العرض (UWB)"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"مشاركة الصوت"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"مشاركة الصوت"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"يجب على المستمعين استخدام سماعات الرأس المتوافقة مع LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"تشغيل صوت تجريبي"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"من المفترض أن يسمع جميع المستخدمين هذا الصوت"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"أجهزة الوسائط المشغَّلة"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"إعدادات البث الصوتي"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"رمز الاستجابة السريعة للبث الصوتي"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"مسح رمز الاستجابة السريعة ضوئيًا للربط"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"بإمكان المستخدمين الآخرين الاستماع إلى البث الصوتي عن طريق ربط سماعات الرأس المتوافقة بأجهزة Android. ويمكنهم بعد ذلك مسح رمز الاستجابة السريعة هذا ضوئيًا."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"طلب إقران البلوتوث"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"الإقران والاتصال"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"رمز إقران البلوتوث"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"تطبيقات أخرى"</string>
     <string name="storage_files" msgid="6382081694781340364">"الملفات"</string>
     <string name="storage_system" msgid="1271345630248014010">"النظام"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"مساحة التخزين الإجمالية: ‎%s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"يتضمّن النظام الملفات المستخدمة لتشغيل إصدار Android‏ <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"الملفات الصوتية"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"جارٍ الحساب…"</string>
@@ -949,7 +960,7 @@
     <string name="screen_reader_settings_title" msgid="4012734340987826872">"قارئ الشاشة"</string>
     <string name="show_captions_toggle_title" msgid="710582308974826311">"عرض الشرح"</string>
     <string name="captions_text_size_title" msgid="1960814652560877963">"حجم النص"</string>
-    <string name="captions_settings_style_header" msgid="944591388386054372">"حجم نصوص الشرح ونمطها"</string>
+    <string name="captions_settings_style_header" msgid="944591388386054372">"حجم نص الترجمة والشرح ونمطه"</string>
     <string name="captions_settings_text_size_very_small" msgid="7476485317028306502">"صغير جدًا"</string>
     <string name="captions_settings_text_size_small" msgid="1481895299805450566">"صغير"</string>
     <string name="captions_settings_text_size_default" msgid="2227802573224038267">"تلقائي"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index afb5fdd60..6b6d8f1a7 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"আপোনাৰ গাড়ীৰ সৈতে ডিভাইচৰ সংযোগ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"আল্ট্ৰা-ৱাইডবেণ্ড (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"আপোনাক গাড়ীখনক UWB ডিভাইচৰ স্থান চিনাক্ত কৰাত সহায় কৰে"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"অডিঅ’ শ্বেয়াৰিং"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"অডিঅ’ শ্বেয়াৰ কৰক"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"শ্ৰোতাসকলক নিজৰ LE অডিঅ’ হেডফ’নৰ আৱশ্যক"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"এটা পৰীক্ষামূলক ধ্বনি প্লে’ কৰক"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"শুনি থকা সকলোৱে এইটো শুনা পাব লাগে"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"সক্ৰিয় মিডিয়া ডিভাইচ"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"অডিঅ’ ষ্ট্ৰীমৰ ছেটিং"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"অডিঅ’ ষ্ট্ৰীমৰ কিউআৰ ক’ড"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"সংযোগ কৰিবলৈ কিউআৰ ক’ডটো স্কেন কৰক"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"অডিঅ’ ষ্ট্ৰীম শুনিবলৈ, অন্য লোকসকলে নিজৰ Android ডিভাইচৰ সৈতে সুসংগত হেডফ’ন সংযোগ কৰিব পাৰে। তেওঁলোকে তাৰ পাছত এই কিউআৰ ক’ডটো স্কেন কৰিব পাৰে।"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ব্লুটুথ যোৰা লগোৱাৰ অনুৰোধ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"পেয়াৰ আৰু সংযোগ কৰক"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ব্লুটুথ যোৰ লগোৱা ক’ড"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"অন্যান্য এপ্‌"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"ছিষ্টেম"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"মুঠ %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"ছিষ্টেমত Android সংস্কৰণ <xliff:g id="VERSION">%s</xliff:g> চলাবলৈ ব্যৱহাৰ কৰা ফাইল অন্তৰ্ভুক্ত হৈ আছে"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"অডিঅ’ ফাইলসমূহ"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"গণনা কৰি থকা হৈছে…"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 3c1a428a8..e3dbce560 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Avtomobil ilə cihaz bağlantıları"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra genişzolaqlı (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Avtomobilə UWB cihazlarının yerini tapmaqda kömək edir"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio paylaşma"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Audio paylaşın"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Dinləyicilərin öz LE Audio qulaqlıqları olmalıdır"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Test səsini oxudun"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Dinləyən hər kəs bunu eşitməlidir"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktiv media cihazları"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio yayımı ayarları"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio yayımı QR kodu"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Qoşulmaq üçün QR kodunu skan edin"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Audio yayımı dinləmək üçün digərləri uyğun qulaqlıqları Android cihazlarına qoşa bilərlər. Sonra bu QR kodunu skan edə bilərlər."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth birləşdirmə sorğusu"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"birləşdirin və əlaqə yaradın"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth birləşdirmə kodu"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Digər tətbiqlər"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fayllar"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Ümumi %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistemə Android <xliff:g id="VERSION">%s</xliff:g> versiyasını işə salmaq üçün istifadə olunan fayllar daxildir"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio fayllar"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Hesablanır…"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 267ce02e3..a0b71bc81 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Povezivanje uređaja sa automobilom"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra-široki pojas (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Pomaže automobilu da identifikuje poziciju UWB uređaja"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Deljenje zvuka"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Deli zvuk"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Slušaoci treba da koriste svoje LE Audio slušalice"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Pustite probni zvuk"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Svi slušaoci bi trebalo da čuju"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktivni medijski uređaji"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Podešavanja audio strima"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR kôd audio strima"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skenirajte QR kôd da biste se povezali"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Da bi slušali audio strim, drugi ljudi mogu da povežu kompatibilne slušalice sa Android uređajem. Zatim mogu da skeniraju ovaj QR kôd."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Zahtev za Bluetooth uparivanje"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Upari i poveži"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kôd za uparivanje sa Bluetooth uređajem"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Druge aplikacije"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fajlovi"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Ukupno: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistem obuhvata datoteke koje se koriste za pokretanje verzije Android-a <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio datoteke"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Izračunava se…"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index b7fd6ef93..548230242 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Падключэнні прылад да аўтамабіля"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Звышшырокапалосная сувязь (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Дапамагае аўтамабілю вызначаць месцазнаходжанне прылад UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Абагульванне аўдыя"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Абагуліць аўдыя"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Для гэтага патрэбныя ўласныя навушнікі з падтрымкай LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Прайграванне тэставага гуку"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Гэты гук павінны чуць усе падключаныя карыстальнікі"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Медыяпрылады, якія выкарыстоўваюцца"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Налады аўдыяплыні"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-код аўдыяплыні"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Сканіраваць QR-код, каб падключыцца"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Каб слухаць аўдыяплынь, іншыя карыстальнікі могуць падключыць сумяшчальныя навушнікі да сваіх прылад Android. Пасля ім трэба будзе адсканіраваць гэты QR-код."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Запыт спалучэння па Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Спалучэнне i падключэнне"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Код спалучэння па Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Іншыя праграмы"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файлы"</string>
     <string name="storage_system" msgid="1271345630248014010">"Сістэма"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Усяго %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Сістэма ўключае ў сябе файлы, неабходныя для працы версіі Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аўдыяфайлы"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Ідзе падлік…"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 22975c4a7..74e1c8bfc 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Връзки на устройството с автомобила ви"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ултрашироколентов сигнал (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Помага на автомобила ви да идентифицира позицията на устройствата с UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Споделяне на звука"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Споделяне на звука"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"На хората ще им трябват слушалки, които поддържат LE Audio."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Възпроизвеждане на тестов звук"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Всички, които слушат, би трябвало да чуват"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Активни носители"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Настройки за аудиопотока"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR код за аудиопоток"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Сканирайте QR кода, за да се свържете"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"За да слушат аудиопоток, другите хора могат да свържат съвместими слушалки към устройството си с Android, след което да сканират този QR код."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Заявка за сдвояване чрез Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Сдвояване и свързване"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Код за сдвояване с Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Други приложения"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файлове"</string>
     <string name="storage_system" msgid="1271345630248014010">"Система"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Общо %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Системата включва файлове, използвани за изпълняването на версия <xliff:g id="VERSION">%s</xliff:g> на Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудиофайлове"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Изчислява се…"</string>
@@ -812,7 +823,7 @@
     <string name="profiles_and_accounts_settings_title" msgid="2672643892127659812">"Потребители и профили"</string>
     <string name="manage_other_profiles_button_text" msgid="2262188413455510828">"Управление на други потр. профили"</string>
     <string name="add_a_profile_button_text" msgid="8027395095117925114">"Добавяне на потребителски профил"</string>
-    <string name="delete_this_profile_text" msgid="6035404714526922665">"Изтриване на този потр. профил"</string>
+    <string name="delete_this_profile_text" msgid="6035404714526922665">"Изтриване на този потребителски профил"</string>
     <string name="add_profile_text" msgid="9118410102199116969">"Добавяне на потребителски профил"</string>
     <string name="cannot_remove_driver_profile" msgid="4109363161608717969">"Понастоящем този потребителски профил се използва от шофьор. Опитайте отново, когато не се използва така."</string>
     <string name="qc_display_brightness" msgid="2939655289816201170">"Яркост на екрана"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 57683433b..9dffcb662 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"আপনার গাড়িতে থাকা ডিভাইস কানেকশন"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"আলট্রা-ওয়াইডব্যান্ড (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"এটি আপনার গাড়িকে UWB ডিভাইসের পজিশন শনাক্ত করতে সাহায্য করে"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"অডিও শেয়ারিং"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"অডিও শেয়ার করুন"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"শ্রোতাদের নিজস্ব LE অডিও হেডফোন থাকতে হবে"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"টেস্ট সাউন্ড চালান"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"অডিও শেয়ার করা হয়েছে, এমন প্রত্যেকের শুনতে পাওয়ার কথা"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"চালু থাকা মিডিয়া ডিভাইস"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"অডিও স্ট্রিমের সেটিংস"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"অডিও স্ট্রিম QR কোড"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"কানেক্ট করার জন্য QR কোড স্ক্যান করুন"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"অডিও স্ট্রিম শুনতে, অন্য লোকজন তাদের Android ডিভাইসে মানানসই হেডফোন কানেক্ট করতে পারবেন। তারপরে তারা এই QR কোড স্ক্যান করতে পারবে।"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ব্লুটুথ পেয়ার করার অনুরোধ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"পেয়ার এবং কানেক্ট করুন"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ব্লুটুথের মাধ্যমে পেয়ার করার কোড"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"অন্যান্য অ্যাপ"</string>
     <string name="storage_files" msgid="6382081694781340364">"ফাইল"</string>
     <string name="storage_system" msgid="1271345630248014010">"সিস্টেম"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"মোট %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Android ভার্সন <xliff:g id="VERSION">%s</xliff:g> চালানোর জন্য সিস্টেমের মধ্যে ফাইল থাকে"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"অডিও ফাইলগুলি"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"হিসেব করা হচ্ছে…"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 3932da38c..ba2d68830 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -36,7 +36,7 @@
     <string name="mobile_network_toggle_title" msgid="3515647310810280063">"Mobilni podaci"</string>
     <string name="mobile_network_toggle_summary" msgid="8698267487987697148">"Pristupi podacima putem mobilne mreže"</string>
     <string name="mobile_network_mobile_network_toggle_title" msgid="3087288149339116597">"Mobilna mreža"</string>
-    <string name="mobile_network_mobile_network_toggle_summary" msgid="1679917666306941420">"Koristi prijenos podataka na mobilnoj mreži"</string>
+    <string name="mobile_network_mobile_network_toggle_summary" msgid="1679917666306941420">"Koristi prenos podataka na mobilnoj mreži"</string>
     <string name="mobile_network_state_off" msgid="471795861420831748">"Isključeno"</string>
     <string name="confirm_mobile_data_disable" msgid="826493998804496639">"Isključiti prijenos podataka na mobilnoj mreži?"</string>
     <string name="sim_selection_required_pref" msgid="6599562910262785784">"Potrebno je odabrati"</string>
@@ -61,7 +61,7 @@
     <string name="carrier_and_update_now_text" msgid="9058821833613481573">"Upravo ažurirao mob. operater <xliff:g id="ID_1">^1</xliff:g>"</string>
     <string name="no_carrier_update_now_text" msgid="5953142546373783189">"Upravo ažurirano"</string>
     <string name="launch_manage_plan_text" msgid="906657488611815787">"Prikaži plan"</string>
-    <string name="app_data_usage" msgid="3878609885080232877">"Prijenos podataka u aplikaciji"</string>
+    <string name="app_data_usage" msgid="3878609885080232877">"Prenos podataka aplikacija"</string>
     <string name="data_usage_app_restricted" msgid="4570970078120010951">"ograničeno"</string>
     <string name="cycle_reset_day_of_month_picker_title" msgid="1374568502823735361">"Datum poništavanja ciklusa korištenja"</string>
     <string name="cycle_reset_day_of_month_picker_subtitle" msgid="5361061448258189846">"Datum svakog mjeseca:"</string>
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Veze uređaja s automobilom"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra široki opseg"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Pomaže automobilu da identificira položaj uređaja ultra širokog opsega"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Dijeljenje zvuka"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Dijeli zvuk"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Slušaoci trebaju slušalice s LE Audijem"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reproduciraj testni zvuk"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Svako ko sluša treba ovo čuti"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktivni medijski uređaji"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Postavke prenosa zvuka"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR kôd prenosa zvuka"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skenirajte QR kôd da se povežete"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Da druge osobe slušaju prenos, mogu povezati kompatibilne slušalice s Android uređajem. Zatim mogu skenirati ovaj QR kôd."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Zahtjev za uparivanje putem Bluetootha"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Upari i poveži"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kôd za uparivanje putem Bluetootha"</string>
@@ -361,7 +371,7 @@
     <string name="app_open_by_default_title" msgid="7275063779631935446">"Zadano otvaranje"</string>
     <string name="app_open_by_default_summary" msgid="3261520150951464121">"Dozvolite aplikaciji da otvara podržane linkove"</string>
     <string name="data_usage_summary_title" msgid="4368024763485916986">"Prijenos podataka"</string>
-    <string name="data_usage_app_summary_title" msgid="5012851696585421420">"Prijenos podataka za apl."</string>
+    <string name="data_usage_app_summary_title" msgid="5012851696585421420">"Prenos podataka aplikacija"</string>
     <string name="data_usage_usage_history_title" msgid="2386346082501471648">"Historija korištenja"</string>
     <string name="data_usage_all_apps_title" msgid="5956991037518761599">"Sve aplikacije"</string>
     <string name="app_data_usage_title" msgid="6991057296054761322">"Korištenje: podaci i WiFi"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Druge aplikacije"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fajlovi"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Ukupno %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistem obuhvata fajlove koji se koriste za pokretanje verzije Androida <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio fajlovi"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Računanje…"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 5d3456612..b11441e4c 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Connexions del dispositiu amb el cotxe"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultraampla (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Ajuda el cotxe a identificar la posició dels dispositius UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Compartició d\'àudio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Comparteix l\'àudio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Els oients han de tenir els seus propis auriculars LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reprodueix un so de prova"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Tothom qui està escoltant l\'hauria de sentir"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispositius multimèdia actius"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Configuració del flux d\'àudio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Codi QR del flux d\'àudio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Escaneja el codi QR per connectar-te"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Per escoltar un flux d\'àudio, altres persones poden connectar auriculars compatibles al seu dispositiu Android. A continuació, poden escanejar aquest codi QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Sol·licitud de vinculació de Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Vincula i connecta"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Codi de vinculació per Bluetooth"</string>
@@ -444,7 +454,7 @@
     <string name="location_settings_title" msgid="901334356682423679">"Ubicació"</string>
     <string name="location_toggle_title" msgid="836779750812064601">"Utilitza la ubicació"</string>
     <string name="location_toggle_summary" msgid="5651728747635881194">"Utilitza la ubicació del cotxe amb qualsevol aplicació que hagis especificat."</string>
-    <string name="location_infotainment_apps_toggle_title" msgid="2083924249183557387">"Aplicacions d\'informació i entreteniment"</string>
+    <string name="location_infotainment_apps_toggle_title" msgid="2083924249183557387">"Aplicacions d\'infoentreteniment"</string>
     <string name="location_infotainment_apps_toggle_summary" msgid="6657657826985915806">"Permet que les aplicacions tinguin accés a la teva ubicació"</string>
     <string name="location_toggle_off_warning" msgid="5959449346865136081">"Si desactives aquesta opció, se suprimirà l\'accés a la ubicació per a totes les aplicacions excepte les que es necessitin per a l\'assistència al conductor"</string>
     <string name="adas_location_toggle_off_warning" msgid="2269555998731648820">"Si desactives aquesta opció, les aplicacions d\'assistència al conductor que depenen de la informació d\'ubicació es desactivaran"</string>
@@ -482,8 +492,8 @@
     <string name="system_update_settings_title" msgid="8448588267784138855">"Actualitzacions del sistema"</string>
     <string name="system_advanced_title" msgid="6303355131691523362">"Configuració avançada"</string>
     <string name="system_advanced_summary" msgid="5833643795981791953">"Informació sobre el dispositiu, informació legal, restabliment de les dades de fàbrica i més"</string>
-    <string name="restart_infotainment_system_title" msgid="5174129167446756511">"Reinicia el sistema d\'informació i entreteniment"</string>
-    <string name="restart_infotainment_system_dialog_text" msgid="6395281407323116808">"Reiniciar el sistema d\'informació i entreteniment del cotxe pot tardar uns quants minuts. Vols continuar?"</string>
+    <string name="restart_infotainment_system_title" msgid="5174129167446756511">"Reinicia el sistema d\'infoentreteniment"</string>
+    <string name="restart_infotainment_system_dialog_text" msgid="6395281407323116808">"Reiniciar el sistema d\'infoentreteniment del cotxe pot tardar uns quants minuts. Vols continuar?"</string>
     <string name="continue_confirmation" msgid="1598892163951467191">"Continua"</string>
     <string name="firmware_version" msgid="8491753744549309333">"Versió d\'Android"</string>
     <string name="security_patch" msgid="4794276590178386903">"Nivell de pedaç de seguretat d\'Android"</string>
@@ -545,7 +555,7 @@
     <string name="reset_app_pref_complete_toast" msgid="8709072932243594166">"S\'han restablert les preferències d\'aplicacions"</string>
     <string name="factory_reset_title" msgid="4019066569214122052">"Esborra totes les dades (restabliment de les dades de fàbrica)"</string>
     <string name="factory_reset_summary" msgid="854815182943504327">"Esborra tots els perfils i les dades del sistema d\'informació i entreteniment"</string>
-    <string name="factory_reset_desc" msgid="2774024747279286354">"Aquesta acció esborrarà totes les dades del sistema d\'informació i entreteniment del vehicle, com ara:\n\n"<li>"Els teus comptes i perfils"</li>\n<li>"Les dades i la configuració del sistema i de les aplicacions"</li>\n<li>"Les aplicacions baixades"</li></string>
+    <string name="factory_reset_desc" msgid="2774024747279286354">"Aquesta acció esborrarà totes les dades del sistema d\'infoentreteniment del vehicle, com ara:\n\n"<li>"Els teus comptes i perfils"</li>\n<li>"Les dades i la configuració del sistema i de les aplicacions"</li>\n<li>"Les aplicacions baixades"</li></string>
     <string name="factory_reset_accounts" msgid="5523956654938834209">"Actualment tens la sessió iniciada als comptes següents:"</string>
     <string name="factory_reset_other_users_present" msgid="3852324375352090570">"S\'han configurat altres perfils per a aquest vehicle."</string>
     <string name="factory_reset_button_text" msgid="2626666247051368256">"Esborra totes les dades"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Altres aplicacions"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fitxers"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s en total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"El sistema inclou fitxers que s\'utilitzen per executar la versió d\'Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Fitxers d\'àudio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"S\'està calculant…"</string>
@@ -681,16 +692,16 @@
     <string name="action_unavailable" msgid="7087119418684417249">"Aquesta acció no està disponible per al teu perfil"</string>
     <string name="microphone_access_settings_title" msgid="6748613084403267254">"Accés al micròfon"</string>
     <string name="microphone_access_settings_summary" msgid="3531690421673836538">"Tria si les aplicacions poden accedir als micròfons del cotxe"</string>
-    <string name="microphone_infotainment_apps_toggle_title" msgid="6625559365680936672">"Aplicacions d\'informació i entreteniment"</string>
-    <string name="microphone_infotainment_apps_toggle_summary" msgid="5967713909533492475">"Permet que les aplicacions d\'informació i entreteniment gravin àudio"</string>
+    <string name="microphone_infotainment_apps_toggle_title" msgid="6625559365680936672">"Aplicacions d\'infoentreteniment"</string>
+    <string name="microphone_infotainment_apps_toggle_summary" msgid="5967713909533492475">"Permet que les aplicacions d\'infoentreteniment gravin àudio"</string>
     <string name="camera_access_settings_title" msgid="1841809323727456945">"Accés a la càmera"</string>
     <string name="camera_access_settings_summary" msgid="8820488359585532496">"Tria si les aplicacions poden accedir a les càmeres del cotxe"</string>
     <string name="required_apps_group_title" msgid="8607608579973985786">"Aplicacions requerides"</string>
     <string name="required_apps_group_summary" msgid="5026442309718220831">"Aplicacions requerides pel fabricant del cotxe per ajudar-te a conduir"</string>
     <string name="required_apps_privacy_policy_button_text" msgid="960364076891996263">"Política"</string>
     <string name="camera_access_disclaimer_summary" msgid="442467418242962647">"És possible que el fabricant del cotxe encara tingui accés a la càmera del cotxe"</string>
-    <string name="camera_infotainment_apps_toggle_title" msgid="6628966732265022536">"Aplicacions d\'informació i entreteniment"</string>
-    <string name="camera_infotainment_apps_toggle_summary" msgid="2422476957183039039">"Permet que les aplicacions d\'informació i entreteniment facin fotos i gravin vídeos"</string>
+    <string name="camera_infotainment_apps_toggle_title" msgid="6628966732265022536">"Aplicacions d\'infoentreteniment"</string>
+    <string name="camera_infotainment_apps_toggle_summary" msgid="2422476957183039039">"Permet que les aplicacions d\'infoentreteniment facin fotos i gravin vídeos"</string>
     <string name="permission_grant_allowed" msgid="4844649705788049638">"Amb permís"</string>
     <string name="permission_grant_always" msgid="8851460274973784076">"En tot moment"</string>
     <string name="permission_grant_never" msgid="1357441946890127898">"Sense permís"</string>
@@ -720,7 +731,7 @@
     <string name="lockpattern_pattern_confirmed" msgid="5984306638250515385">"El teu nou patró de desbloqueig"</string>
     <string name="lockpattern_recording_intro_header" msgid="7864149726033694408">"Dibuixa un patró de desbloqueig"</string>
     <string name="lockpattern_recording_inprogress" msgid="1575019990484725964">"Deixa anar el dit quan acabis"</string>
-    <string name="lockpattern_pattern_entered" msgid="6103071005285320575">"Patró enregistrat"</string>
+    <string name="lockpattern_pattern_entered" msgid="6103071005285320575">"Patró gravat"</string>
     <string name="lockpattern_need_to_confirm" msgid="4648070076022940382">"Dibuixa el patró de nou per confirmar-lo"</string>
     <string name="lockpattern_recording_incorrect_too_short" msgid="2417932185815083082">"Connecta 4 punts com a mínim. Torna-ho a provar."</string>
     <string name="lockpattern_pattern_wrong" msgid="929223969555399363">"El patró no és correcte"</string>
@@ -823,21 +834,21 @@
     <string name="show_layout_bounds_title" msgid="8590148405645027755">"Mostra els límits de la disposició"</string>
     <string name="show_force_rtl_title" msgid="8240732919603115320">"Força la direcció dreta-esquerra"</string>
     <string name="show_customization_overlay_title" msgid="2543804846629965883">"Superposició de personalització"</string>
-    <string name="device_admin_add_title" msgid="1294399588284546811">"Administrador del sistema d\'informació i entreteniment"</string>
+    <string name="device_admin_add_title" msgid="1294399588284546811">"Administrador del sistema d\'infoentreteniment"</string>
     <string name="device_admin_activated_apps" msgid="568075063362271751">"Aplicacions activades"</string>
     <string name="device_admin_deactivated_apps" msgid="3797263682500122872">"Aplicacions desactivades"</string>
     <string name="device_admin_apps_description" msgid="1371935499168453457">"Les aplicacions amb aquest permís tenen accés a les dades d\'aquest vehicle"</string>
     <string name="device_admin_apps_list_empty" msgid="7634804595645191123">"No hi ha cap aplicació d\'administració de vehicles"</string>
-    <string name="device_admin_status" msgid="4041772636856135168">"Aquesta aplicació d\'administració del sistema d\'informació i entreteniment està activa i permet a l\'aplicació <xliff:g id="APP_NAME">%1$s</xliff:g> dur a terme les operacions següents:"</string>
-    <string name="device_admin_warning" msgid="8997805999333600901">"L\'activació d\'aquesta aplicació del sistema d\'informació i entreteniment permetrà que l\'aplicació <xliff:g id="APP_NAME">%1$s</xliff:g> faci les operacions següents:"</string>
-    <string name="add_device_admin_msg" msgid="8188888666879499482">"Vols activar aquesta aplicació?"</string>
-    <string name="add_device_admin" msgid="7674707256074840333">"Activa aquesta aplicació del sistema d\'informació i entreteniment"</string>
+    <string name="device_admin_status" msgid="4041772636856135168">"Aquesta aplicació d\'administració del sistema d\'infoentreteniment està activa i permet a l\'aplicació <xliff:g id="APP_NAME">%1$s</xliff:g> dur a terme les operacions següents:"</string>
+    <string name="device_admin_warning" msgid="8997805999333600901">"L\'activació d\'aquesta aplicació del sistema d\'infoentreteniment permetrà que l\'aplicació <xliff:g id="APP_NAME">%1$s</xliff:g> faci les operacions següents:"</string>
+    <string name="add_device_admin_msg" msgid="8188888666879499482">"Vols activar aquesta aplicacióde sistema d\'infoentreteniment?"</string>
+    <string name="add_device_admin" msgid="7674707256074840333">"Activa aquesta aplicació del sistema d\'infoentreteniment"</string>
     <string name="deactivate_and_uninstall_device_admin" msgid="596399938769951696">"Desactiva i desinstal·la"</string>
-    <string name="remove_device_admin" msgid="3595343390502030723">"Desactiva aquesta aplicació del sistema d\'informació i entreteniment"</string>
+    <string name="remove_device_admin" msgid="3595343390502030723">"Desactiva aquesta aplicació del sistema d\'infoentreteniment"</string>
     <string name="admin_profile_owner_message" msgid="8361351256802954556">"El gestor de l\'organització pot supervisar i gestionar les aplicacions i les dades associades a aquest perfil, inclosos els permisos, la configuració, l\'accés corporatiu, l\'activitat de xarxa i la informació d\'ubicació del vehicle."</string>
     <string name="admin_profile_owner_user_message" msgid="366072696508275753">"El gestor de l\'organització pot supervisar i gestionar les aplicacions i les dades associades a aquest perfil, inclosos els permisos, la configuració, l\'accés corporatiu, l\'activitat de xarxa i la informació d\'ubicació del dispositiu."</string>
-    <string name="admin_device_owner_message" msgid="896530502350904835">"El gestor de l\'organització pot supervisar i gestionar les aplicacions i les dades associades a aquest sistema d\'informació i entreteniment, inclosos els permisos, la configuració, l\'accés corporatiu, l\'activitat de xarxa i la informació d\'ubicació del vehicle."</string>
-    <string name="admin_financed_message" msgid="7357397436233684082">"És possible que el gestor de l\'organització pugui accedir a les dades associades a aquest sistema d\'informació i entreteniment, gestionar les aplicacions i canviar la configuració d\'aquest vehicle."</string>
+    <string name="admin_device_owner_message" msgid="896530502350904835">"El gestor de l\'organització pot supervisar i gestionar les aplicacions i les dades associades a aquest sistema d\'infoentreteniment, inclosos els permisos, la configuració, l\'accés corporatiu, l\'activitat de xarxa i la informació d\'ubicació del vehicle."</string>
+    <string name="admin_financed_message" msgid="7357397436233684082">"És possible que el gestor de l\'organització pugui accedir a les dades associades a aquest sistema d\'infoentreteniment, gestionar les aplicacions i canviar la configuració d\'aquest vehicle."</string>
     <string name="disabled_by_policy_title" msgid="1121694702115232518">"No està disponible"</string>
     <string name="disabled_by_policy_title_adjust_volume" msgid="7002865820552702232">"No es pot canviar el volum d\'aquest vehicle gestionat"</string>
     <string name="disabled_by_policy_title_outgoing_calls" msgid="158752542663419500">"No es poden fer trucades en aquest vehicle gestionat"</string>
@@ -857,11 +868,11 @@
     <string name="footer_learn_more_content_description" msgid="7749452309729272078">"Més informació sobre <xliff:g id="SERVICE">%1$s</xliff:g>"</string>
     <string name="enterprise_privacy_settings" msgid="6496900796150572727">"Informació del vehicle gestionat"</string>
     <string name="enterprise_privacy_settings_summary_generic" msgid="5850991363779957797">"Configuració gestionada per l\'administrador de la flota"</string>
-    <string name="enterprise_privacy_header" msgid="4652489109303330306">"Per donar accés a les dades d\'aquest vehicle gestionat, l\'administrador de la flota pot canviar la configuració del sistema d\'informació i entreteniment i també instal·lar-hi programari.\n\nPer obtenir més informació, contacta amb l\'administrador de la flota."</string>
+    <string name="enterprise_privacy_header" msgid="4652489109303330306">"Per donar accés a les dades d\'aquest vehicle gestionat, l\'administrador de la flota pot canviar la configuració del sistema d\'infoentreteniment i també instal·lar-hi programari.\n\nPer obtenir més informació, contacta amb l\'administrador de la flota."</string>
     <string name="enterprise_privacy_exposure_category" msgid="4870494030035008520">"Informació que l\'administrador de la flota pot veure"</string>
     <string name="enterprise_privacy_exposure_changes_category" msgid="8837106430193547177">"Canvis fets per l\'administrador de la flota"</string>
     <string name="enterprise_privacy_exposure_desc" msgid="7962571201715956427">" "<li>"Dades associades al compte del vehicle gestionat"</li>\n" "<li>"Llista d\'aplicacions del vehicle gestionat"</li>\n" "<li>"Temps dedicat i dades utilitzades en cada aplicació"</li></string>
-    <string name="enterprise_privacy_device_access_category" msgid="5820180227429886857">"El teu accés al sistema d\'informació i entreteniment"</string>
+    <string name="enterprise_privacy_device_access_category" msgid="5820180227429886857">"El teu accés al sistema d\'infoentreteniment"</string>
     <string name="enterprise_privacy_installed_packages" msgid="1069862734971848156">"Llista de les aplicacions que hi ha al vehicle"</string>
     <string name="enterprise_privacy_apps_count_estimation_info" msgid="2684195229249659340">"El nombre d\'aplicacions és aproximat. És possible que no inclogui les aplicacions instal·lades que no provenen de Play Store."</string>
     <plurals name="enterprise_privacy_number_packages_lower_bound" formatted="false" msgid="1628398874478431488">
@@ -885,8 +896,8 @@
     <string name="enterprise_privacy_input_method_name" msgid="2027313786295077607">"Mètode definit: <xliff:g id="APP_LABEL">%s</xliff:g>"</string>
     <string name="enterprise_privacy_global_http_proxy" msgid="1366593928008294049">"S\'ha definit el servidor intermediari HTTP global"</string>
     <string name="enterprise_privacy_ca_certs_personal" msgid="5677098981429650665">"Certificats de confiança al teu perfil personal"</string>
-    <string name="enterprise_privacy_device_access_desc" msgid="3442555102576036038">" "<li>"L\'administrador pot bloquejar el sistema d\'informació i entreteniment i també restablir la contrasenya"</li>\n" "<li>"L\'administrador pot suprimir dades del sistema d\'informació i entreteniment"</li></string>
-    <string name="enterprise_privacy_failed_password_wipe_device" msgid="4768743631260876559">"Intents fallits d\'introduir la contrasenya abans que se suprimeixin totes les dades del sistema d\'informació i entreteniment"</string>
+    <string name="enterprise_privacy_device_access_desc" msgid="3442555102576036038">" "<li>"L\'administrador pot bloquejar el sistema d\'infoentreteniment i també restablir la contrasenya"</li>\n" "<li>"L\'administrador pot suprimir dades del sistema d\'informació i entreteniment"</li></string>
+    <string name="enterprise_privacy_failed_password_wipe_device" msgid="4768743631260876559">"Intents fallits d\'introduir la contrasenya abans que se suprimeixin totes les dades del sistema d\'infoentreteniment"</string>
     <string name="enterprise_privacy_failed_password_wipe_current_user" msgid="786246192213446835">"Intents fallits d\'introduir la contrasenya abans que se suprimeixin les dades del perfil"</string>
     <plurals name="enterprise_privacy_number_failed_password_wipe" formatted="false" msgid="445847844239023816">
       <item quantity="other"><xliff:g id="COUNT_1">%d</xliff:g> intents</item>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index a32fc9d3c..e2600a2cf 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Připojení zařízení k autu"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra-wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Pomáhá autu rozpoznat umístění zařízení UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Sdílení zvuku"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Sdílet zvuk"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Posluchači potřebují vlastní sluchátka LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Přehrát zkušební zvuk"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Měl by ho slyšet každý, kdo poslouchá"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktivní mediální zařízení"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Nastavení zvukového streamu"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR kód zvukového streamu"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Připojte se naskenováním QR kódu"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Další lidé mohou zvukový stream poslouchat tak, že ke svému zařízení Android připojí kompatibilní sluchátka a poté naskenují tento QR kód."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Požadavek na párování zařízení Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Párovat a připojit"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Párovací kód Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Další aplikace"</string>
     <string name="storage_files" msgid="6382081694781340364">"Soubory"</string>
     <string name="storage_system" msgid="1271345630248014010">"Systém"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s celkem"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Systém obsahuje soubory používané ke spuštění systému Android verze <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Zvukové soubory"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Výpočet…"</string>
@@ -820,7 +831,7 @@
     <string name="qc_bluetooth_on_no_devices_info" msgid="7573736950041887300">"Zařízení spárujete v nastavení Bluetooth"</string>
     <string name="qc_ui_mode_title" msgid="2425571805732530923">"Motiv"</string>
     <string name="driving_mode_title" msgid="8103270030335833998">"Nastavit režim jízdy autem"</string>
-    <string name="show_layout_bounds_title" msgid="8590148405645027755">"Zobrazit ohraničení"</string>
+    <string name="show_layout_bounds_title" msgid="8590148405645027755">"Zobrazovat ohraničení"</string>
     <string name="show_force_rtl_title" msgid="8240732919603115320">"Vynutit rozvržení zprava doleva"</string>
     <string name="show_customization_overlay_title" msgid="2543804846629965883">"Vrstva přizpůsobení"</string>
     <string name="device_admin_add_title" msgid="1294399588284546811">"Administrátor informačního a zábavního systému"</string>
@@ -945,7 +956,7 @@
     <string name="captions_settings_text_size_very_large" msgid="949511539689307969">"Velmi velké"</string>
     <string name="captions_text_style_title" msgid="8547777957403577760">"Styl titulků"</string>
     <string name="captions_settings_text_style_by_app" msgid="7014882290456996444">"Nastaveno aplikací"</string>
-    <string name="captions_settings_text_style_white_on_black" msgid="5758084000323596070">"Bílé na černém"</string>
+    <string name="captions_settings_text_style_white_on_black" msgid="5758084000323596070">"Bílá na černém"</string>
     <string name="captions_settings_text_style_black_on_white" msgid="3906140601916221220">"Černé na bílém"</string>
     <string name="captions_settings_text_style_yellow_on_black" msgid="4681565950104511943">"Žluté na černém"</string>
     <string name="captions_settings_text_style_yellow_on_blue" msgid="5072521958156112239">"Žluté na modrém"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 74dd73456..afe4d1958 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Enheder forbundet til din bil"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultrabredbånd (UWB, Ultra-Wideband)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Hjælper din bil med at lokalisere UWB-enheder"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Lyddeling"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Del lyd"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Lyttere skal have deres egne høretelefoner med LE-lyd."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Afspil en testlyd"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Alle, der lytter, bør kunne høre den"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktive medieenheder"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Indstillinger for lydstream"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-kode til lydstream"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scan QR-koden for at oprette forbindelse"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Andre, som vil lytte til lydstreamen, kan forbinde kompatible høretelefoner til deres Android-enhed og derefter scanne denne QR-kode."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Anmodning om Bluetooth-parring"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Tilknyt og forbind"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-parringskode"</string>
@@ -505,7 +515,7 @@
     <string name="contributors_title" msgid="7698463793409916113">"Bidragydere"</string>
     <string name="manual" msgid="4819839169843240804">"Manuel"</string>
     <string name="regulatory_labels" msgid="3165587388499646779">"Regulatorisk mærkning"</string>
-    <string name="safety_and_regulatory_info" msgid="1204127697132067734">"Brugervejledning i sikkerhed og regler"</string>
+    <string name="safety_and_regulatory_info" msgid="1204127697132067734">"Brugervejledning i sikkerhed og reguleringer"</string>
     <string name="copyright_title" msgid="4220237202917417876">"Ophavsret"</string>
     <string name="license_title" msgid="936705938435249965">"Licens"</string>
     <string name="terms_title" msgid="5201471373602628765">"Vilkår og betingelser"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Andre apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Filer"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s i alt"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Systemet omfatter filer, der anvendes til at køre Android-versionen <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Lydfiler"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Beregner…"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index b164036ac..d7e77f214 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Geräteverbindungen mit deinem Auto"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultrabreitband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Unterstützt dein Auto beim Erkennen der Position von UWB-Geräten"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audiofreigabe"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Audioinhalte freigeben"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Alle Zuhörer benötigen dazu eigene LE Audio-Kopfhörer"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Testton abspielen"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Alle Zuhörer sollten ihn hören können"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktive Mediengeräte"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Einstellungen des Audiostreams"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-Code des Audiostreams"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Zum Verbinden den QR-Code scannen"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Wenn andere Personen den Audiostream anhören möchten, können sie kompatible Kopfhörer mit ihrem Android-Gerät verbinden und dann diesen QR-Code scannen."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Anfrage zur Bluetooth-Kopplung"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Koppeln &amp; verbinden"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-Kopplungscode"</string>
@@ -245,7 +255,7 @@
     <string name="text_to_speech_settings" msgid="811985746199507343">"Sprachausgabe"</string>
     <string name="text_to_speech_preferred_engine_settings" msgid="2766782925699132256">"Bevorzugtes Modul"</string>
     <string name="text_to_speech_current_engine" msgid="8133107484909612597">"Aktuelles Modul"</string>
-    <string name="tts_speech_rate" msgid="4512944877291943133">"Sprechgeschwindigkeit"</string>
+    <string name="tts_speech_rate" msgid="4512944877291943133">"Sprech­geschwindigkeit"</string>
     <string name="tts_pitch" msgid="2389171233852604923">"Stimmlage"</string>
     <string name="tts_reset" msgid="6289481549801844709">"Zurücksetzen"</string>
     <string name="sound_settings" msgid="3072423952331872246">"Ton"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Weitere Apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s insgesamt"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"System enthält Dateien für die Ausführung der Android-Version <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audiodateien"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Wird berechnet…"</string>
@@ -641,7 +652,7 @@
     <string name="no_accounts_added" msgid="5148163140691096055">"Keine Konten hinzugefügt"</string>
     <string name="account_list_title" msgid="7631588514613843065">"Konten für <xliff:g id="CURRENT_USER_NAME">%1$s</xliff:g>"</string>
     <string name="account_auto_sync_title" msgid="3238816995364191432">"Daten automatisch synchronisieren"</string>
-    <string name="account_auto_sync_summary" msgid="6963837893148304128">"Apps die automatische Aktualisierung von Daten erlauben"</string>
+    <string name="account_auto_sync_summary" msgid="6963837893148304128">"Zulassen, dass Apps Daten automatisch aktualisieren"</string>
     <string name="data_usage_auto_sync_on_dialog_title" msgid="8068513213445588532">"Automatische Datensynchronisierung zulassen?"</string>
     <string name="data_usage_auto_sync_on_dialog" msgid="8683935973719807821">"Änderungen, die du im Web an deinen Konten vornimmst, werden automatisch für dein Fahrzeug kopiert.\n\nIm Gegenzug werden bei manchen Konten auch automatisch alle Änderungen, die für das Fahrzeug vorgenommen werden, ins Web kopiert."</string>
     <string name="data_usage_auto_sync_off_dialog_title" msgid="6683011954002351091">"Automatische Datensynchronisierung verbieten?"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index e457057df..19797cc36 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Συνδέσεις συσκευών με το αυτοκίνητό σας"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Υπερευρεία ζώνη (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Βοηθάει το αυτοκίνητό σας να προσδιορίσει τη θέση των συσκευών UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Κοινή χρήση ήχου"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Κοινή χρήση ήχου"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Οι ακροατές πρέπει να έχουν τα δικά τους ακουστικά LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Αναπαραγωγή δοκιμαστικού ήχου"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Όλοι οι ακροατές θα μπορέσουν να τον ακούσουν"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Ενεργές συσκευές μέσων"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Ρυθμίσεις ροής ήχου"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Κωδικός QR ροής ήχου"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Σαρώστε τον κωδικό QR για σύνδεση"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Για να ακούσουν τη ροή ήχου, τα άλλα άτομα μπορούν να συνδέσουν συμβατά ακουστικά στη συσκευή Android που διαθέτουν. Στη συνέχεια, θα μπορούν να σαρώσουν αυτόν τον κωδικό QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Αίτημα σύζευξης Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Σύζευξη και σύνδεση"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Κωδικός σύζευξης Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Άλλες εφαρμογές"</string>
     <string name="storage_files" msgid="6382081694781340364">"Αρχεία"</string>
     <string name="storage_system" msgid="1271345630248014010">"Σύστημα"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s σύνολο"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Το σύστημα περιλαμβάνει αρχεία που χρησιμοποιούνται για την εκτέλεση του Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Αρχεία ήχου"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Υπολογισμός…"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 839eb83cc..c79c71f50 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Device connections with your car"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Helps your car identify the position of UWB devices"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio sharing"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Share audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Listeners need their own LE Audio headphones"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Play a test sound"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Everyone listening should hear it"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Active media devices"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio stream settings"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio stream QR code"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scan QR code to connect"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"To listen to the audio stream, other people can connect compatible headphones to their Android device. They can then scan this QR code."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth pairing request"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Pair &amp; connect"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth pairing code"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Other apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"System includes files used to run Android version <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio files"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculating…"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index da10ff5dd..870015ea7 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Device connections with your car"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Helps your car identify the position of UWB devices"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio Sharing"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Share audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Listeners need their own LE Audio headphones"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Play a test sound"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Everyone listening should hear it"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Active media devices"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio stream settings"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio stream QR Code"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scan QR code to connect"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"To listen to audio stream, other people can connect compatible headphones to their android device. They can then scan this QR code."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth pairing request"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Pair &amp; connect"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth pairing code"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Other apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"System includes files used to run Android version <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio files"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculating…"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 14ef663fc..7f0b1a141 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Device connections with your car"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Helps your car identify the position of UWB devices"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio sharing"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Share audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Listeners need their own LE Audio headphones"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Play a test sound"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Everyone listening should hear it"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Active media devices"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio stream settings"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio stream QR code"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scan QR code to connect"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"To listen to the audio stream, other people can connect compatible headphones to their Android device. They can then scan this QR code."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth pairing request"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Pair &amp; connect"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth pairing code"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Other apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"System includes files used to run Android version <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio files"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculating…"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index df1f6d4e8..07d3e7cf1 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Device connections with your car"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Helps your car identify the position of UWB devices"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio sharing"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Share audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Listeners need their own LE Audio headphones"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Play a test sound"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Everyone listening should hear it"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Active media devices"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio stream settings"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio stream QR code"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scan QR code to connect"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"To listen to the audio stream, other people can connect compatible headphones to their Android device. They can then scan this QR code."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth pairing request"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Pair &amp; connect"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth pairing code"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Other apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"System includes files used to run Android version <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio files"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculating…"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index ccc8b8922..1299e3e27 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Conexiones de dispositivos a tu vehículo"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultraancha (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Permite que el vehículo identifique la posición de los dispositivos UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Uso compartido de audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Compartir audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Deberán tener sus propios auriculares con LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reproducir un sonido de prueba"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Todos los que escuchan deberían oírlo"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispositivos de medios activos"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Configuración de la transmisión de audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Código QR de la transmisión de audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Escanea el código QR para conectarte"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Para escuchar la transmisión de audio, otras personas pueden conectar auriculares compatibles a su dispositivo Android. Luego, pueden escanear este código QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Solicitud de vinculación mediante Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Vincular y conectar"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Código de vinculación mediante Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Otras apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Archivos"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Total: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"El sistema incluye archivos que se usan para ejecutar la versión <xliff:g id="VERSION">%s</xliff:g> de Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Archivos de audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculando…"</string>
@@ -819,7 +830,7 @@
     <string name="qc_bluetooth_off_devices_info" msgid="8420985279976892700">"Para ver tus dispositivos, activa Bluetooth"</string>
     <string name="qc_bluetooth_on_no_devices_info" msgid="7573736950041887300">"Vincula un dispositivo desde la config. de Bluetooth"</string>
     <string name="qc_ui_mode_title" msgid="2425571805732530923">"Tema"</string>
-    <string name="driving_mode_title" msgid="8103270030335833998">"Establecer en automóvil"</string>
+    <string name="driving_mode_title" msgid="8103270030335833998">"Establecer modo Conducción"</string>
     <string name="show_layout_bounds_title" msgid="8590148405645027755">"Mostrar límites de diseño"</string>
     <string name="show_force_rtl_title" msgid="8240732919603115320">"Forzar diseño de derecha a izquierda"</string>
     <string name="show_customization_overlay_title" msgid="2543804846629965883">"Personalización de la superposición"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index b6a18cb41..2099995a8 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Conexiones de dispositivos a tu coche"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultraancha (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Ayuda a tu coche a identificar la posición de dispositivos UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Compartir audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Compartir audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Deberán tener sus propios auriculares con LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reproducir un sonido de prueba"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Todas las personas conectadas deberían escucharlo"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispositivos multimedia activos"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Ajustes del stream de audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Código QR del stream de audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Escanea el código QR para conectarte"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Para escuchar el stream de audio, otras personas pueden conectar auriculares compatibles a sus dispositivos Android. Después, podrán escanear este código QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Solicitud de emparejamiento por Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Sincronizar y conectar"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Código de emparejamiento por Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Otras aplicaciones"</string>
     <string name="storage_files" msgid="6382081694781340364">"Archivos"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Total: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"El sistema incluye los archivos necesarios para que la versión <xliff:g id="VERSION">%s</xliff:g> de Android funcione"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Archivos de audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculando…"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 5e880b5a1..44ff7244a 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Seadme ühendused teie autoga"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ülilairibatehnoloogia (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Aitab teie autol tuvastada UWB-seadmete asukoha"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Heli jagamine"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Jaga heli"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Kuulajatel on vaja enda LE Audio kõrvaklappe"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Testheli esitamine"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Kõik kuulajad peaksid seda kuulma"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktiivsed meediaseadmed"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Helivoo seaded"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Helivoo QR-kood"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Ühendamiseks skannige QR-kood"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Helivoo kuulamiseks saavad teised inimesed ühendada oma Androidi seadmega ühilduvad kõrvaklapid. Seejärel saavad nad skannida selle QR-koodi."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetoothi sidumistaotlus"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Seo ja ühenda"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetoothi sidumiskood"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Muud rakendused"</string>
     <string name="storage_files" msgid="6382081694781340364">"Failid"</string>
     <string name="storage_system" msgid="1271345630248014010">"Süsteem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Kokku %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Süsteem hõlmab Androidi versiooni <xliff:g id="VERSION">%s</xliff:g> käitamiseks vajalikke faile"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Helifailid"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Arvutamine …"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 52ca0d51f..1d9cd011a 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Autora konektatutako konexioak"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultrazabala"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Autoari banda ultrazabaleko gailuen posizioa identifikatzen laguntzen dio"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audioa partekatzea"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Partekatu audioa"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Entzuleek kontsumo txikiko audioko entzungailuak behar dituzte"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Erreproduzitu probako soinu bat"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Entzuten ari diren guztiek entzun beharko lukete"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Multimedia-gailu aktiboak"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Zuzeneko audio-erreprodukzioaren ezarpenak"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Zuzeneko audio-erreprodukzioaren QR kodea"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Konektatzeko, eskaneatu QR kodea"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Zuzeneko audio-erreprodukzioa entzuteko, beste pertsonek entzungailu bateragarriak konektatu behar dituzte Android-eko gailuetara. Ondoren, QR kode hau eskaneatu behar dute."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth bidez parekatzeko eskaera"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Parekatu eta konektatu"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth bidez konektatzeko parekatze-kodea"</string>
@@ -455,7 +465,7 @@
     <string name="location_recently_accessed" msgid="522888989582110975">"Azkenaldian kokapena atzitu dutenak"</string>
     <string name="location_settings_recently_accessed_title" msgid="6016264778609426382">"Azkenaldian kokapena atzitu dutenak"</string>
     <string name="location_settings_recently_accessed_view_all_title" msgid="6344830628885781448">"Ikusi guztiak"</string>
-    <string name="location_no_recent_access" msgid="2859914321242257931">"Ez dago azkenaldian kokapena atzitu duen aplikaziorik"</string>
+    <string name="location_no_recent_access" msgid="2859914321242257931">"Ez dago azkenaldian kokapena erabili duen aplikaziorik"</string>
     <string name="driver_assistance_label" msgid="5330316311913399041">"<xliff:g id="TIME">%1$s</xliff:g> • Gidatzeko laguntza • Erabiltzeko baimena behar du"</string>
     <string name="location_adas_apps_list_title" msgid="482882078448695177">"Gidatzen laguntzen dizuten eginbideak"</string>
     <string name="location_driver_assistance_privacy_policy_button_text" msgid="1092702462617222722">"Gidalerroak"</string>
@@ -472,7 +482,7 @@
     <string name="microphone_toggle_summary" msgid="2682653449849128626">"Eman mikrofonoa erabiltzeko baimena aplikazio guztiei"</string>
     <string name="microphone_manage_permissions" msgid="7280905792151988183">"Kudeatu mikrofonoaren baimenak"</string>
     <string name="microphone_recently_accessed" msgid="2084292372486026607">"Berriki mikrofonoa atzitu dutenak"</string>
-    <string name="microphone_no_recent_access" msgid="6412908936060990649">"Ez dago azkenaldian atzitutako aplikaziorik"</string>
+    <string name="microphone_no_recent_access" msgid="6412908936060990649">"Ez dago azkenaldian erabilitako aplikaziorik"</string>
     <string name="microphone_app_permission_summary_microphone_off" msgid="6139321726246115550">"Ez dago sarbidea duen aplikaziorik"</string>
     <string name="microphone_app_permission_summary_microphone_on" msgid="7870834777359783838">"{count,plural, =1{#/{total_count} aplikaziok du sarbidea}other{#/{total_count} aplikaziok dute sarbidea}}"</string>
     <string name="microphone_settings_recent_requests_title" msgid="8154796551134761329">"Berriki mikrofonoa atzitu dutenak"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Beste aplikazio batzuk"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fitxategiak"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s guztira"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Android-en <xliff:g id="VERSION">%s</xliff:g> bertsioa exekutatzeko erabiltzen diren fitxategiak daude sisteman"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio-fitxategiak"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Kalkulatzen…"</string>
@@ -863,7 +874,7 @@
     <string name="enterprise_privacy_exposure_desc" msgid="7962571201715956427">" "<li>"Ibilgailu kudeatuaren kontuarekin erlazionatutako datuak."</li>\n" "<li>"Ibilgailu kudeatuaren aplikazioen zerrenda."</li>\n" "<li>"Aplikazio bakoitzean emandako denbora eta erabilitako datuak."</li></string>
     <string name="enterprise_privacy_device_access_category" msgid="5820180227429886857">"Informazio- eta aisia-sistemarako duzun sarbidea"</string>
     <string name="enterprise_privacy_installed_packages" msgid="1069862734971848156">"Ibilgailuko aplikazioen zerrenda"</string>
-    <string name="enterprise_privacy_apps_count_estimation_info" msgid="2684195229249659340">"Estimazio da aplikazio kopurua. Baliteke Play Store-tik instalatu ez diren aplikazioak kontuan ez izatea."</string>
+    <string name="enterprise_privacy_apps_count_estimation_info" msgid="2684195229249659340">"Estimazio da aplikazio kopurua. Baliteke Google Play Store-tik instalatu ez diren aplikazioak kontuan ez izatea."</string>
     <plurals name="enterprise_privacy_number_packages_lower_bound" formatted="false" msgid="1628398874478431488">
       <item quantity="other">Gutxienez <xliff:g id="COUNT_1">%d</xliff:g> aplikazio</item>
       <item quantity="one">Gutxienez <xliff:g id="COUNT_0">%d</xliff:g> aplikazio</item>
@@ -948,7 +959,7 @@
     <string name="camera_toggle_summary" msgid="5751159996822627567">"Eman kamera erabiltzeko baimena aplikazio guztiei"</string>
     <string name="camera_manage_permissions" msgid="9005596413781984368">"Kudeatu kamera erabiltzeko baimenak"</string>
     <string name="camera_recently_accessed" msgid="8084100710444691977">"Azkenaldian atzitu dutenak"</string>
-    <string name="camera_no_recent_access" msgid="965105023454777859">"Ez dago azkenaldian atzitu duen aplikaziorik"</string>
+    <string name="camera_no_recent_access" msgid="965105023454777859">"Ez dago azkenaldian erabili duen aplikaziorik"</string>
     <string name="camera_app_permission_summary_camera_off" msgid="1437200903113016549">"Ez dago sarbidea duen aplikaziorik"</string>
     <string name="camera_app_permission_summary_camera_on" msgid="7260565911222013361">"{count,plural, =1{#/{total_count} aplikaziok du sarbidea}other{#/{total_count} aplikaziok dute sarbidea}}"</string>
     <string name="camera_settings_recent_requests_title" msgid="2433698239374365206">"Azkenaldian atzitu dutenak"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 8af2b2faa..b26cdcb74 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -94,7 +94,7 @@
     <string name="loading_wifi_list" msgid="8584901433195876465">"درحال بارگیری فهرست Wi‑Fi"</string>
     <string name="wifi_disabled" msgid="5013262438128749950">"Wi‑Fi غیرفعال شد"</string>
     <string name="wifi_failed_forget_message" msgid="121732682699377206">"شبکه فراموش نشد"</string>
-    <string name="wifi_failed_connect_message" msgid="4447498225022147324">"اتصال به شبکه برقرار نشد"</string>
+    <string name="wifi_failed_connect_message" msgid="4447498225022147324">"به شبکه متصل نشد"</string>
     <string name="wifi_setup_add_network" msgid="3660498520389954620">"افزودن شبکه"</string>
     <string name="wifi_setup_connect" msgid="3512399573397979101">"اتصال"</string>
     <string name="wifi_connecting" msgid="1930665730621677960">"درحال اتصال…"</string>
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"اتصال‌های دستگاه با خودرو"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"«فراپهن‌باند» (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"به خودروتان کمک می‌کند موقعیت دستگاه‌های مجهز به «فراپهن‌باند» را شناسایی کند"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"اشتراک صدا"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"هم‌رسانی صدا"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"شنوندگان باید هدفون مجهز به «صدای کم‌مصرف» خود را داشته باشند"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"پخش صدای آزمایشی"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"همه افرادی که گوش می‌دهند باید این صدا را بشنوند"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"دستگاه‌های رسانه‌ای فعال"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"تنظیمات جاری‌سازی صوتی"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"رمزینه پاسخ‌سریع جاری‌سازی صوتی"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"متصل شدن با اسکن رمزینه پاسخ‌سریع"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"برای گوش دادن به جاری‌سازی صوتی، دیگران می‌توانند هدفون سازگاری را به دستگاه Android خود وصل کنند. سپس می‌توانند این رمزینه پاسخ‌سریع را اسکن کنند."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"درخواست مرتبط‌سازی بلوتوث"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"مرتبط‌ کردن و اتصال"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"کد مرتبط‌سازی بلوتوث"</string>
@@ -516,7 +526,7 @@
     <string name="status_serial_number" msgid="9158889113131907656">"شماره سریال"</string>
     <string name="hardware_revision" msgid="5713759927934872874">"نسخه سخت‌افزار"</string>
     <string name="regulatory_info_text" msgid="8890339124198005428"></string>
-    <string name="settings_license_activity_title" msgid="8499293744313077709">"مجوزهای شخص ثالث"</string>
+    <string name="settings_license_activity_title" msgid="8499293744313077709">"پروانه‌های طرف سوم"</string>
     <string name="settings_license_activity_unavailable" msgid="6104592821991010350">"مشکلی در بارگیری مجوزها وجود دارد."</string>
     <string name="settings_license_activity_loading" msgid="6163263123009681841">"درحال بار کردن…"</string>
     <string name="show_dev_countdown" msgid="7416958516942072383">"{count,plural, =1{اکنون # گام تا توسعه‌دهنده شدن فاصله دارید.}one{اکنون # گام تا توسعه‌دهنده شدن فاصله دارید.}other{اکنون # گام تا توسعه‌دهنده شدن فاصله دارید.}}"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"سایر برنامه‌ها"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"سیستم"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"مجموع %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"سیستم حاوی فایل‌هایی است که برای اجرای Android نسخه <xliff:g id="VERSION">%s</xliff:g> استفاده می‌شود"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"فایل‌های صوتی"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"در حال محاسبه…"</string>
@@ -933,7 +944,7 @@
     <string name="captions_settings_text_size_very_large" msgid="949511539689307969">"بسیار بزرگ"</string>
     <string name="captions_text_style_title" msgid="8547777957403577760">"زیرنویس ناشنوایان"</string>
     <string name="captions_settings_text_style_by_app" msgid="7014882290456996444">"تنظیم‌شده توسط برنامه"</string>
-    <string name="captions_settings_text_style_white_on_black" msgid="5758084000323596070">"سفید در سیاه"</string>
+    <string name="captions_settings_text_style_white_on_black" msgid="5758084000323596070">"سفید روی سیاه"</string>
     <string name="captions_settings_text_style_black_on_white" msgid="3906140601916221220">"سیاه در سفید"</string>
     <string name="captions_settings_text_style_yellow_on_black" msgid="4681565950104511943">"زرد در سیاه"</string>
     <string name="captions_settings_text_style_yellow_on_blue" msgid="5072521958156112239">"زرد در آبی"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 288c72f0a..66e861734 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Laitteiden yhteydet autoosi"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra-Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Auttaa autoa tunnistamaan UWB-laitteiden sijainnin"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audionjako"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Jaa audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Kuuntelijat tarvitsevat omat LE Audio ‑kuulokkeet"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Toista testiääni"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Kaikkien pitäisi kuulla se"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktiiviset medialaitteet"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audiostriimin asetukset"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audiostriimin QR-koodi"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Yhdistä skannaamalla QR-koodi"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Jos muut haluavat kuunnella audiostriimiä, he voivat yhdistää yhteensopivat kuulokkeet Android-laitteeseen. Sen jälkeen he voivat skannata QR-koodin."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth-laiteparipyyntö"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Muodosta laitepari ja yhdistä"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-laiteparikoodi"</string>
@@ -504,7 +514,7 @@
     <string name="legal_information" msgid="1838443759229784762">"Lakitiedot"</string>
     <string name="contributors_title" msgid="7698463793409916113">"Tekijät"</string>
     <string name="manual" msgid="4819839169843240804">"Manuaalinen"</string>
-    <string name="regulatory_labels" msgid="3165587388499646779">"Viranomaismerkinnät"</string>
+    <string name="regulatory_labels" msgid="3165587388499646779">"Viranomaistietoa sisältävät tunnisteet"</string>
     <string name="safety_and_regulatory_info" msgid="1204127697132067734">"Turvallisuus- ja säädöstenmukaisuusopas"</string>
     <string name="copyright_title" msgid="4220237202917417876">"Tekijänoikeudet"</string>
     <string name="license_title" msgid="936705938435249965">"Käyttölupa"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Muut sovellukset"</string>
     <string name="storage_files" msgid="6382081694781340364">"Tiedostot"</string>
     <string name="storage_system" msgid="1271345630248014010">"Järjestelmä"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Yhteensä %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Järjestelmä sisältää tiedostoja, joita tarvitaan Android-version <xliff:g id="VERSION">%s</xliff:g> toimintaan."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Äänitiedostot"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Lasketaan…"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index b251935bd..8d465a872 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Connexions d\'appareils à votre voiture"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Bande ultralarge (BUL)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Aide votre voiture à identifier la position des appareils BUL"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Partage audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Partager l\'audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Les auditeurs doivent avoir leurs propres écouteurs LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Tester l\'audio"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Tous les auditeurs devraient l\'entendre"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Appareils de stockage multimédia actifs"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Paramètres du flux audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Code QR du flux audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Balayer le code QR pour vous connecter"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Pour écouter un flux audio, d\'autres personnes peuvent connecter des écouteurs compatibles à leur appareil Android. Elles pourront ensuite balayer ce code QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Demande d\'association Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Associer et connecter"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Code d\'association Bluetooth"</string>
@@ -543,7 +553,7 @@
     <string name="reset_app_pref_desc" msgid="579392665146962149">"Cette opération réinitialise toutes les préférences relatives aux éléments suivants :\n\n"<li>"Applications désactivées"</li>\n<li>"Notifications associées aux applications désactivées"</li>\n<li>"Applications par défaut pour les actions"</li>\n<li>"Restrictions de données en arrière-plan pour les applications"</li>\n<li>"Toutes les restrictions d\'autorisations"</li>\n\n"Vous ne perdrez aucune donnée liée aux applications."</string>
     <string name="reset_app_pref_button_text" msgid="6270820447321231609">"Réinitialiser les applications"</string>
     <string name="reset_app_pref_complete_toast" msgid="8709072932243594166">"Les préférences des applications ont été réinitialisées"</string>
-    <string name="factory_reset_title" msgid="4019066569214122052">"Effacer toutes les données"</string>
+    <string name="factory_reset_title" msgid="4019066569214122052">"Effacer les données (réinitialisation)"</string>
     <string name="factory_reset_summary" msgid="854815182943504327">"Effacer toutes les données et tous les profils du système d\'infodivertissement"</string>
     <string name="factory_reset_desc" msgid="2774024747279286354">"Cette action effacera toutes les données du système d\'infodivertissement de votre véhicule, y compris :\n\n"<li>"Vos comptes et profils"</li>\n<li>"Les données et les paramètres du système et de l\'application"</li>\n<li>"Les applications téléchargées"</li></string>
     <string name="factory_reset_accounts" msgid="5523956654938834209">"Vous êtes actuellement connecté aux comptes suivants :"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Autres applications"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fichiers"</string>
     <string name="storage_system" msgid="1271345630248014010">"Système"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s au total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Le répertoire Système comprend des fichiers utilisés pour faire fonctionner Android version <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Fichiers audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calcul en cours…"</string>
@@ -939,7 +950,7 @@
     <string name="captions_settings_text_style_yellow_on_blue" msgid="5072521958156112239">"Texte jaune sur fond bleu"</string>
     <string name="accessibility_settings_screen_reader_title" msgid="5113265553157624836">"Lecteur d\'écran"</string>
     <string name="screen_reader_settings_off" msgid="6081562047935689764">"Désactivé"</string>
-    <string name="screen_reader_settings_on" msgid="2168217218643349459">"Énoncer les éléments à l\'écran"</string>
+    <string name="screen_reader_settings_on" msgid="2168217218643349459">"énoncer les éléments à l\'écran"</string>
     <string name="enable_screen_reader_toggle_title" msgid="7641307781194619254">"Utiliser <xliff:g id="ACCESSIBILITY_APP_NAME">%1$s</xliff:g>"</string>
     <string name="screen_reader_options_title" msgid="1073640098442831819">"Options"</string>
     <string name="screen_reader_description_title" msgid="8766666406552388012">"Paramètres"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 1a2d54145..e97893192 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Connexions des appareils à votre voiture"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Bande ultralarge (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Aide votre voiture à identifier la position des appareils UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Partage audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Partager le contenu audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Chaque personne a besoin de son propre casque LE Audio."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Lire un son de test"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Tous ceux qui écoutent devraient l\'entendre"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Périphériques multimédias actifs"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Paramètres du flux audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR code du flux audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scannez le QR code pour vous connecter"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Si d\'autres personnes veulent écouter le flux audio, elles peuvent connecter un casque compatible à leur appareil Android, puis scanner ce QR code."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Demande d\'association Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Associer et connecter"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Code d\'association Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Autres applications"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"Système"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s au total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Le système contient des fichiers servant à l\'exécution d\'Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Fichiers audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calcul…"</string>
@@ -713,7 +724,7 @@
     <string name="set_screen_lock" msgid="5239317292691332780">"Configurer le verrouillage de l\'écran"</string>
     <string name="lockscreen_choose_your_pin" msgid="1645229555410061526">"Choisissez votre code"</string>
     <string name="lockscreen_choose_your_password" msgid="4487577710136014069">"Sélectionner un mot de passe"</string>
-    <string name="current_screen_lock" msgid="637651611145979587">"Verrouillage actuel de l\'écran"</string>
+    <string name="current_screen_lock" msgid="637651611145979587">"Méthode utilisée actuellement"</string>
     <string name="choose_lock_pattern_message" msgid="6242765203541309524">"Pour la sécurité, définissez un schéma"</string>
     <string name="lockpattern_retry_button_text" msgid="4655398824001857843">"Effacer"</string>
     <string name="lockpattern_cancel_button_text" msgid="4068764595622381766">"Annuler"</string>
@@ -925,7 +936,7 @@
     <string name="screen_reader_settings_title" msgid="4012734340987826872">"Lecteur d\'écran"</string>
     <string name="show_captions_toggle_title" msgid="710582308974826311">"Afficher les sous-titres"</string>
     <string name="captions_text_size_title" msgid="1960814652560877963">"Taille du texte"</string>
-    <string name="captions_settings_style_header" msgid="944591388386054372">"Style et taille des sous-titres"</string>
+    <string name="captions_settings_style_header" msgid="944591388386054372">"Taille et style des sous-titres"</string>
     <string name="captions_settings_text_size_very_small" msgid="7476485317028306502">"Très petite"</string>
     <string name="captions_settings_text_size_small" msgid="1481895299805450566">"Petite"</string>
     <string name="captions_settings_text_size_default" msgid="2227802573224038267">"Par défaut"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 8c101a28e..177f33afd 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Conexións do dispositivo co coche"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultralarga"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Permite que o coche poida identificar a posición dos dispositivos de banda ultralarga"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio compartido"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Compartir audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"A audiencia necesita auriculares de audio de baixo consumo"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reproducir un son de proba"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Todas as persoas conectadas deberían oílo"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Activar os dispositivos multimedia"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Configuración da emisión de audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Código QR da emisión de audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Escanear o código QR para conectarse"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Para escoitar unha emisión de audio, as demais persoas poden conectar auriculares compatibles ao seu dispositivo Android. Despois poden escanear este código QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Solicitude de sincronización por Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Sincronizar e conectar"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Código de vinculación por Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Outras aplicacións"</string>
     <string name="storage_files" msgid="6382081694781340364">"Ficheiros"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s (total)"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"O sistema inclúe arquivos usados para executar a versión <xliff:g id="VERSION">%s</xliff:g> de Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Ficheiros de audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculando…"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 9c06e1b97..ef2f67f1c 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"તમારી કાર સાથેના ડિવાઇસ કનેક્શન"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"અલ્ટ્રા-વાઇડબૅન્ડ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"તમારી કારને UWB ડિવાઇસની સ્થિતિ ઓળખવામાં સહાય કરે છે"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ઑડિયો શેરિંગ"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ઑડિયો શેર કરો"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"સાંભળનારા શ્રોતાઓ પાસે તેમના પોતાના LE ઑડિયો હૅડફોન હોવા આવશ્યક છે"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"કોઈ પરીક્ષણ સાઉન્ડ વગાડો"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"સાંભળનાર પ્રત્યેક વ્યક્તિએ તેને સાંભળવું જોઈએ"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ઍક્ટિવ મીડિયા ડિવાઇસ"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ઑડિયો સ્ટ્રીમના સેટિંગ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ઑડિયો સ્ટ્રીમનો QR કોડ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"કનેક્ટ કરવા માટે QR કોડ સ્કૅન કરો"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ઑડિયો સ્ટ્રીમ સાંભળવા માટે, અન્ય લોકો તેમના Android ડિવાઇસ સાથે સુસંગત હૅડફોન કનેક્ટ કરી શકે છે. ત્યારબાદ તેઓ આ QR કોડ સ્કૅન કરી શકે છે."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"બ્લૂટૂથ જોડાણ બનાવવાની વિનંતી"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"જોડી બનાવો અને કનેક્ટ કરો"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"બ્લૂટૂથનો જોડાણ કરવાનો કોડ"</string>
@@ -511,7 +521,7 @@
     <string name="terms_title" msgid="5201471373602628765">"નિયમો અને શરતો"</string>
     <string name="webview_license_title" msgid="6442372337052056463">"સિસ્ટમ WebView લાઇસન્સ"</string>
     <string name="wallpaper_attributions" msgid="9201272150014500697">"વૉલપેપર"</string>
-    <string name="wallpaper_attributions_values" msgid="4292446851583307603">"ઉપગ્રહ છબી પ્રદાતાઓ:\n©2014 CNES / Astrium, DigitalGlobe, Bluesky"</string>
+    <string name="wallpaper_attributions_values" msgid="4292446851583307603">"સૅટલાઇટથી લીધેલી છબીઓના પ્રદાતાઓ:\n©2014 CNES / Astrium, DigitalGlobe, Bluesky"</string>
     <string name="model_info" msgid="4966408071657934452">"મૉડલ"</string>
     <string name="status_serial_number" msgid="9158889113131907656">"અનુક્રમ નંબર"</string>
     <string name="hardware_revision" msgid="5713759927934872874">"હાર્ડવેરનું વર્ઝન"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"અન્ય ઍપ"</string>
     <string name="storage_files" msgid="6382081694781340364">"ફાઇલો"</string>
     <string name="storage_system" msgid="1271345630248014010">"સિસ્ટમ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"કુલ %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"સિસ્ટમમાં Androidનું <xliff:g id="VERSION">%s</xliff:g> વર્ઝન ચલાવવા માટે ઉપયોગી ફાઇલોનો સમાવેશ છે"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ઑડિયોની ફાઇલો"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"ગણતરી કરી રહ્યાં છીએ…"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index fc2272be9..7c73c7944 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -149,7 +149,7 @@
     <string name="wifi_hotspot_password_title" msgid="4103948315849351988">"हॉटस्पॉट का पासवर्ड"</string>
     <string name="wifi_hotspot_security_title" msgid="2299925790743587725">"सुरक्षा"</string>
     <string name="wifi_hotspot_wpa3_sae" msgid="4752416911592950174">"WPA3-निजी"</string>
-    <string name="wifi_security_psk_sae" msgid="8738371461215752280">"WPA2/WPA3-निजी"</string>
+    <string name="wifi_security_psk_sae" msgid="8738371461215752280">"WPA2/WPA3-Personal"</string>
     <string name="wifi_hotspot_wpa2_personal" msgid="7135181212837798318">"WPA2 व्यक्तिगत"</string>
     <string name="wifi_hotspot_security_none" msgid="2514844105085054386">"कोई नहीं"</string>
     <string name="wifi_hotspot_ap_band_title" msgid="7685279281668988593">"एपी बैंड"</string>
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"आपकी कार से कनेक्ट डिवाइस"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"अल्ट्रा-वाइडबैंड (यूडब्ल्यूबी)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"इससे आपकी कार को यूडब्ल्यूबी डिवाइसों की जगह की जानकारी पता लगाने में मदद मिलती है"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ऑडियो शेयर करने की सुविधा"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ऑडियो शेयर करें"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"लिसनर के पास LE Audio वाले हेडफ़ोन होने चाहिए"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"कोई टेस्ट साउंड चलाएं"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"यह उन सभी को सुनाई देना चाहिए जिन्हें ऑडियो शेयर किया गया है"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"चालू मीडिया डिवाइस"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ऑडियो स्ट्रीम की सेटिंग"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ऑडियो स्ट्रीम का क्यूआर कोड"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"कनेक्ट करने के लिए क्यूआर कोड स्कैन करें"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ऑडियो स्ट्रीम सुनने के लिए, अन्य लोग अपने Android डिवाइस के साथ काम करने वाले हेडफ़ोन कनेक्ट कर सकते हैं. इसके बाद, वे इस क्यूआर कोड को स्कैन कर सकते हैं."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ब्लूटूथ के ज़रिए जोड़ने का अनुरोध किया गया"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"दूसरे डिवाइस से जोड़ें और कनेक्‍ट करें"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ब्‍लूटूथ के ज़रिए जोड़ने के लिए कोड"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"दूसरे ऐप्लिकेशन"</string>
     <string name="storage_files" msgid="6382081694781340364">"फ़ाइलें"</string>
     <string name="storage_system" msgid="1271345630248014010">"सिस्टम"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"कुल %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"सिस्टम में ऐसी फ़ाइलें शामिल हैं जिनका इस्तेमाल Android वर्शन <xliff:g id="VERSION">%s</xliff:g> को चलाने के लिए किया जाता है"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ऑडियो फ़ाइलें"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"गिनती की जा रही है…"</string>
@@ -713,7 +724,7 @@
     <string name="set_screen_lock" msgid="5239317292691332780">"स्क्रीन लॉक सेट करें"</string>
     <string name="lockscreen_choose_your_pin" msgid="1645229555410061526">"अनलॉक करने के लिए पिन चुनें"</string>
     <string name="lockscreen_choose_your_password" msgid="4487577710136014069">"अनलॉक करने के लिए पासवर्ड चुनें"</string>
-    <string name="current_screen_lock" msgid="637651611145979587">"मौजूदा स्क्रीन लॉक"</string>
+    <string name="current_screen_lock" msgid="637651611145979587">"मौजूदा स्क्रीन लॉक टाइप"</string>
     <string name="choose_lock_pattern_message" msgid="6242765203541309524">"सुरक्षा के लिए पैटर्न सेट करें"</string>
     <string name="lockpattern_retry_button_text" msgid="4655398824001857843">"हटाएं"</string>
     <string name="lockpattern_cancel_button_text" msgid="4068764595622381766">"अभी नहीं"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 9e2339d77..17292be5f 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Veze uređaja s automobilom"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultraširokopojasno povezivanje (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Pomaže automobilu da otkrije položaj UWB uređaja"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Zajedničko slušanje"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Dijeli zvuk"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Slušatelji trebaju imati svoje LE Audio slušalice"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reprodukcija testnog zvuka"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Svi koji slušaju trebali bi čuti zvuk"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktivni multimedijski uređaji"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Postavke audiostreama"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR kôd audiostreama"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skenirajte QR kôd za povezivanje"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Da bi slušali audiostream, drugi korisnici mogu povezati kompatibilne slušalice sa svojim Android uređajem. Zatim mogu skenirati ovaj QR kôd."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Zahtjev za Bluetooth uparivanje"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Upari i poveži"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetoothov kôd za uparivanje"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Ostale aplikacije"</string>
     <string name="storage_files" msgid="6382081694781340364">"Datoteke"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sustav"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Ukupno: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sustav uključuje datoteke koje se upotrebljavaju za pokretanje Androida verzije <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audiodatoteke"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Izračun u tijeku…"</string>
@@ -776,7 +787,7 @@
     <string name="lockpassword_pin_no_sequential_digits" msgid="6511579896796310956">"Rastući, padajući ili ponavljajući slijed brojeva nije dopušten"</string>
     <string name="setup_lock_settings_options_button_label" msgid="3337845811029780896">"Opcije zaključavanja zaslona"</string>
     <string name="credentials_reset" msgid="873900550885788639">"Izbriši vjerodajnice"</string>
-    <string name="credentials_reset_summary" msgid="6067911547500459637">"Ukloni sve certifikate"</string>
+    <string name="credentials_reset_summary" msgid="6067911547500459637">"Uklonite sve certifikate"</string>
     <string name="credentials_reset_hint" msgid="3459271621754137661">"Ukloniti sve sadržaje?"</string>
     <string name="credentials_erased" msgid="2515915439705550379">"Izbrisan je spremnik vjerodajnica."</string>
     <string name="credentials_not_erased" msgid="6118567459076742720">"Spremnik vjerodajnica nije izbrisan."</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index e3198e8a2..0f7c68bfe 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Az autó eszközkapcsolatai"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultraszélessáv (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Segít az autónak meghatározni az UWB-eszközök helyzetét"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Hang megosztása"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Hang megosztása"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"A hallgatóknak saját LE Audio-fejhallgatóra van szükségük."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Teszthang lejátszása"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Minden társhallgató hallani fogja"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktív médiaeszközök"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audiostream beállításai"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audiostream QR-kódja"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Csatlakozás a QR-kód beolvasásával"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Az audiostreamek hallgatásához más személyek kompatibilis fejhallgatójukkal saját Android-eszközükhöz csatlakozhatnak. Ha ez megtörtént, beolvashatják ezt a QR-kódot."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth párosítási kérelem"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Párosítás és csatlakozás"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-párosítókód"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Egyéb alkalmazások"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fájlok"</string>
     <string name="storage_system" msgid="1271345630248014010">"Rendszer"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Összesen: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"A rendszer az Android <xliff:g id="VERSION">%s</xliff:g> verziójának futtatásához használt fájlokat tartalmaz"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Hangfájlok"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Számítás…"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 48140f3fd..b2ded5fa3 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Սարքերի միացումները ձեր մեքենայի հետ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Գերլայնաշերտ տեխնոլոգիա (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Օգնում է ձեր մեքենային պարզել UWB սարքերի դիրքը"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Աուդիոյի փոխանցում"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Փոխանցել աուդիոն"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Լսողները պետք է իրենց LE Audio ականջակալն ունենան"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Միացնել փորձնական ձայն"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Բոլոր լսողները կլսեն այն"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Ակտիվ մեդիա սարքեր"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Աուդիո հոսքի կարգավորումներ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Աուդիո հոսքի QR կոդ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Սկանավորեք QR կոդը՝ միանալու համար"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Աուդիո հոսքը լսելու համար մյուս մարդիկ կարող են համատեղելի ականջակալ միացնել իրենց Android սարքին։ Այնուհետև կարող են սկանավորել այս QR կոդը։"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth-ով զուգակցման հարցում"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Զուգակցել և միանալ"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-ով զուգակցման կոդ"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Այլ հավելվածներ"</string>
     <string name="storage_files" msgid="6382081694781340364">"Ֆայլեր"</string>
     <string name="storage_system" msgid="1271345630248014010">"Համակարգ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Ընդամենը՝ %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Համակարգը ներառում է ֆայլեր, որոնք անհրաժեշտ են Android-ի <xliff:g id="VERSION">%s</xliff:g> տարբերակի աշխատանքի համար"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Աուդիո ֆայլեր"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Հաշվարկում…"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 4426f270e..b465917ff 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Koneksi perangkat dengan mobil Anda"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra-Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Bantu mobil Anda mengidentifikasi posisi perangkat UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Berbagi Audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Bagikan audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Pendengar harus menggunakan headphone LE Audio milik sendiri"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Putar suara uji coba"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Semua orang yang diajak berbagi audio harus dapat mendengar"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Perangkat media yang aktif"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Setelan streaming audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Kode QR streaming audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Pindai kode QR untuk terhubung"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Jika ada orang lain yang ingin mendengarkan streaming audio, mereka dapat menghubungkan headphone yang kompatibel ke perangkat Android mereka, lalu memindai kode QR ini."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Permintaan penyambungan Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Sambungkan &amp; hubungkan"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kode penyambungan Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Aplikasi lainnya"</string>
     <string name="storage_files" msgid="6382081694781340364">"File"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Total %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistem mencakup file yang digunakan untuk menjalankan Android versi <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"File audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Menghitung…"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 94ea0542b..0e427366d 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Tengingar tækis við bílinn þinn"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ofurbreiðband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Hjálpar bílnum þínum að bera kennsl á afstöðu UWB-tækja"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Hljóðdeiling"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Deila hljóði"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Hlustendur þurfa að vera með sín eigin heyrnartól sem geta spilað LE-hljóð"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Spila prufuhljóð"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Allir sem hlusta ættu að heyra það"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Virk margmiðlunartæki"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Stillingar hljóðstreymis"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-kóði hljóðstreymis"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skannaðu QR-kóðann til að hlusta"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Aðrir geta tengt samhæf heyrnartól við Android-tækin sín og skannað þennan QR-kóða til að hlusta á hljóðstreymið."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Beiðni um Bluetooth-pörun"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Pörun og tenging"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-pörunarkóði"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Önnur forrit"</string>
     <string name="storage_files" msgid="6382081694781340364">"Skrár"</string>
     <string name="storage_system" msgid="1271345630248014010">"Kerfi"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s samtals"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Kerfi inniheldur skrár notaðar til að keyra Android útgáfu <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Hljóðskrár"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Reiknar út…"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index ef0029f3b..f2c01c93f 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Connessioni del dispositivo all\'auto"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultralarga (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Consente all\'auto di identificare la posizione dei dispositivi UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Condivisione audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Condividi audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Chi ascolta i contenuti deve avere le sue cuffie LE audio."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Riproduci un suono di prova"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Chiunque stia ascoltando dovrebbe sentirlo"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispositivi multimediali attivi"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Impostazioni stream audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Codice QR stream audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scansiona il codice QR per connetterti"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Per ascoltare lo stream audio, altre persone possono connettere delle cuffie compatibili al loro dispositivo Android e scansionare questo codice QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Richiesta accoppiamento Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Accoppia e connetti"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Codice di accoppiamento Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Altre app"</string>
     <string name="storage_files" msgid="6382081694781340364">"File"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s in totale"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Il sistema include i file utilizzati per eseguire Android versione <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"File audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calcolo…"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 399ff54e5..1bbd29bdc 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"חיבורי המכשיר לרכב"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"‫Ultra Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"כך הרכב יכול לזהות את המיקומים של מכשירי UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"שיתוף האודיו"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"שיתוף האודיו"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"אנשים שרוצים להאזין צריכים אוזניות LE Audio משלהם"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"השמעת צליל בדיקה"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"כל המאזינים ישמעו את זה"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"מכשירים פעילים לאחסון מדיה"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"הגדרות שידור האודיו"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"קוד ה-QR של שידור האודיו"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"כדי להתחבר, צריך לסרוק את קוד ה-QR"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"כדי להאזין לשידור האודיו, אנשים אחרים יכולים לחבר אוזניות תואמות למכשיר ה-Android שלהם. אחר כך הם יכולים לסרוק את קוד ה-QR הזה."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"בקשה להתאמת Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"התאמה וחיבור"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"קוד ההתאמה ל-Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"אפליקציות אחרות"</string>
     <string name="storage_files" msgid="6382081694781340364">"קבצים"</string>
     <string name="storage_system" msgid="1271345630248014010">"מערכת"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"סה\"כ %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"המערכת כוללת קבצים המשמשים להרצה של גרסת Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"קובצי אודיו"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"מתבצע חישוב…"</string>
@@ -710,19 +721,19 @@
     <string name="continue_button_text" msgid="5129979170426836641">"המשך"</string>
     <string name="lockscreen_retry_button_text" msgid="5314212350698701242">"ניסיון חוזר"</string>
     <string name="lockscreen_skip_button_text" msgid="3755748786396198091">"דילוג"</string>
-    <string name="set_screen_lock" msgid="5239317292691332780">"הגדרת מסך נעילה"</string>
+    <string name="set_screen_lock" msgid="5239317292691332780">"הגדרת שיטה לפתיחת הנעילה"</string>
     <string name="lockscreen_choose_your_pin" msgid="1645229555410061526">"בחירת קוד גישה"</string>
     <string name="lockscreen_choose_your_password" msgid="4487577710136014069">"בחירת סיסמה"</string>
-    <string name="current_screen_lock" msgid="637651611145979587">"השיטה הנוכחית לביטול הנעילה"</string>
+    <string name="current_screen_lock" msgid="637651611145979587">"השיטה הנוכחית לפתיחת הנעילה"</string>
     <string name="choose_lock_pattern_message" msgid="6242765203541309524">"מטעמי אבטחה, יש להגדיר קו ביטול נעילה"</string>
     <string name="lockpattern_retry_button_text" msgid="4655398824001857843">"ניקוי"</string>
     <string name="lockpattern_cancel_button_text" msgid="4068764595622381766">"ביטול"</string>
     <string name="lockpattern_pattern_confirmed" msgid="5984306638250515385">"קו ביטול הנעילה החדש שלך"</string>
     <string name="lockpattern_recording_intro_header" msgid="7864149726033694408">"מהו קו ביטול הנעילה שלך?"</string>
     <string name="lockpattern_recording_inprogress" msgid="1575019990484725964">"לסיום הפעולה פשוט צריך להרים את האצבע"</string>
-    <string name="lockpattern_pattern_entered" msgid="6103071005285320575">"קו ביטול הנעילה נשמר"</string>
+    <string name="lockpattern_pattern_entered" msgid="6103071005285320575">"קו פתיחת הנעילה נשמר"</string>
     <string name="lockpattern_need_to_confirm" msgid="4648070076022940382">"יש לצייר שוב את קו ביטול הנעילה כדי לאשר"</string>
-    <string name="lockpattern_recording_incorrect_too_short" msgid="2417932185815083082">"יש לחבר 4 נקודות לפחות. עליך לנסות שוב."</string>
+    <string name="lockpattern_recording_incorrect_too_short" msgid="2417932185815083082">"צריך לחבר 4 נקודות לפחות. אפשר לנסות שוב."</string>
     <string name="lockpattern_pattern_wrong" msgid="929223969555399363">"קו ביטול נעילה שגוי"</string>
     <string name="lockpattern_settings_help_how_to_record" msgid="4436556875843192284">"כיצד לשרטט קו ביטול נעילה"</string>
     <string name="error_saving_lockpattern" msgid="2933512812768570130">"שגיאה בשמירה של קו ביטול הנעילה"</string>
@@ -801,7 +812,7 @@
     <string name="restricted_for_driver" msgid="3364388937671526800">"לא ניתן לבצע את הפעולה הזו"</string>
     <string name="add_user_restricted_while_driving" msgid="1037301074725362944">"לא ניתן להוסיף פרופיל בזמן הנהיגה"</string>
     <string name="default_search_query" msgid="3137420627428857068">"חיפוש"</string>
-    <string name="assistant_and_voice_setting_title" msgid="737733881661819853">"Assistant והקול"</string>
+    <string name="assistant_and_voice_setting_title" msgid="737733881661819853">"‫Assistant והקול"</string>
     <string name="assistant_and_voice_assistant_app_title" msgid="5981647244625171285">"אפליקציית עוזר דיגיטלי"</string>
     <string name="assistant_and_voice_use_text_from_screen_title" msgid="5851460943413795599">"שימוש בטקסט המופיע במסך"</string>
     <string name="assistant_and_voice_use_text_from_screen_summary" msgid="4161751708121301541">"מתן הרשאה ל-Assistant לגשת לתוכן המסך"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 0bd64843d..760c803fd 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"デバイスと車との接続"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"超広帯域無線（UWB）"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB デバイスの位置を車が特定できるようにします"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"音声の共有"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"音声を共有"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"聴くには LE Audio 対応ヘッドフォンが必要です。"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"テスト音声の再生"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"聴いている人全員に聞こえます"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"有効なメディア デバイス"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"音声ストリームの設定"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"音声ストリームの QR コード"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"QR コードをスキャンして接続"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"対応するヘッドフォンを Android デバイスに接続して、この QR コードをスキャンした人は、誰でも音声ストリームを聴くことができます。"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth のペア設定リクエスト"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ペア設定して接続"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth ペア設定コード"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"その他のアプリ"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"システム"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"合計 %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"システムには、Android バージョン <xliff:g id="VERSION">%s</xliff:g> の実行に使用されるファイルが含まれています"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"音声ファイル"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"計算しています…"</string>
@@ -736,7 +747,7 @@
     <string name="lock_settings_enter_pin" msgid="1669172111244633904">"PIN の入力"</string>
     <string name="lock_settings_enter_password" msgid="2636669926649496367">"パスワードの入力"</string>
     <string name="choose_lock_pin_message" msgid="2963792070267774417">"セキュリティ強化のために PIN を設定"</string>
-    <string name="confirm_your_pin_header" msgid="9096581288537156102">"PIN の再入力"</string>
+    <string name="confirm_your_pin_header" msgid="9096581288537156102">"PIN を再入力"</string>
     <string name="choose_lock_pin_hints" msgid="7362906249992020844">"PIN は 4 桁以上で設定してください"</string>
     <string name="lockpin_invalid_pin" msgid="2149191577096327424">"PIN が無効です。4 桁以上にしてください。"</string>
     <string name="confirm_pins_dont_match" msgid="4607110139373520720">"PIN が一致しません"</string>
@@ -744,7 +755,7 @@
     <string name="lockscreen_wrong_pin" msgid="4922465731473805306">"PIN が間違っています"</string>
     <string name="lockscreen_wrong_password" msgid="5757087577162231825">"パスワードが正しくありません"</string>
     <string name="choose_lock_password_message" msgid="6124341145027370784">"セキュリティ強化のためにパスワードを設定"</string>
-    <string name="confirm_your_password_header" msgid="7052891840366724938">"パスワードの再入力"</string>
+    <string name="confirm_your_password_header" msgid="7052891840366724938">"パスワードを再入力"</string>
     <string name="confirm_passwords_dont_match" msgid="7300229965206501753">"パスワードが一致しません"</string>
     <string name="lockpassword_clear_label" msgid="6363680971025188064">"消去"</string>
     <string name="lockpassword_cancel_label" msgid="5791237697404166450">"キャンセル"</string>
@@ -775,7 +786,7 @@
     <string name="lockpassword_pin_too_long" msgid="8315542764465856288">"{count,plural, =1{# 桁未満にしてください}other{# 桁未満にしてください}}"</string>
     <string name="lockpassword_pin_no_sequential_digits" msgid="6511579896796310956">"一連の数字を昇順や降順にしたり、繰り返したりすることはできません"</string>
     <string name="setup_lock_settings_options_button_label" msgid="3337845811029780896">"画面ロックの方法"</string>
-    <string name="credentials_reset" msgid="873900550885788639">"認証情報の消去"</string>
+    <string name="credentials_reset" msgid="873900550885788639">"認証情報を消去"</string>
     <string name="credentials_reset_summary" msgid="6067911547500459637">"証明書をすべて削除する"</string>
     <string name="credentials_reset_hint" msgid="3459271621754137661">"コンテンツをすべて削除しますか？"</string>
     <string name="credentials_erased" msgid="2515915439705550379">"認証情報ストレージを消去しました。"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 4558ced53..a33352b40 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"მოწყობილობის კავშირი თქვენს ავტომობილთან"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"ულტრაფართოზოლიანი კავშირი (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"თქვენს ავტომობილს UWB მოწყობილობების პოზიციის იდენტიფიცირებაში ეხმარება"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"აუდიოს გაზიარება"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"აუდიოს გაზიარება"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"მსმენელებს თავიანთი LE-აუდიო ყურსასმენები დასჭირდებათ"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"აუდიოს სატესტო დაკვრა"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ვინც უსმენს, ყველას უნდა ესმოდეს"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"აქტიური მედიამოწყობილობები"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"აუდიონაკადის პარამეტრები"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"აუდიონაკადის QR კოდი"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"QR კოდის სკანირება დასაკავშირებლად"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"აუდიონაკადის მოსმენის მიზნით სხვა პირებს შეუძლიათ, თავიანთ Android მოწყობილობებს დაუკავშირონ თავსებადი ყურსასმენები. შემდეგ, შეუძლიათ, დაასკანირონ ეს QR კოდი."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth დაწყვილების მოთხოვნა"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"დაწყვილება და შეერთება"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-ის დაკავშირების კოდი"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"სხვა აპები"</string>
     <string name="storage_files" msgid="6382081694781340364">"ფაილები"</string>
     <string name="storage_system" msgid="1271345630248014010">"სისტემა"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"სულ: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"სისტემა მოიცავს ფაილებს, რომლებიც Android <xliff:g id="VERSION">%s</xliff:g> ვერსიის გასაშვებად გამოიყენება"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"აუდიოფაილები"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"მიმდინარეობს გამოთვლა…"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 8b9717892..b8be2a3a4 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Көлігіңізге құрылғыларды қосу"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Кеңжолақты байланыс (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Көлігіңіздің UWB құрылғыларының орнын анықтауға көмектеседі."</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Аудио бөлісу"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Аудионы бөлісу"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Тыңдаушыларға өз LE Audio құлақаспаптарын пайдалану қажет."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Дыбысты тексеріп көріңіз"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Барлық тыңдаушы оны естуі керек."</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Белсенді медиа құрылғылар"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Аудио трансляция параметрлері"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Аудио трансляцияның QR коды"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Қосылу үшін QR кодын сканерлеу"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Аудио трансляцияны тыңдау үшін басқа адамдар өз Android құрылғыларына үйлесімді құлақаспаптарды жалғай алады. Содан кейін осы QR кодын сканерлейді."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth жұптау сұрауы"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Жұптау және жалғау"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth жұптау коды"</string>
@@ -246,7 +256,7 @@
     <string name="text_to_speech_preferred_engine_settings" msgid="2766782925699132256">"Таңдалған жүйе"</string>
     <string name="text_to_speech_current_engine" msgid="8133107484909612597">"Ағымдағы жүйе"</string>
     <string name="tts_speech_rate" msgid="4512944877291943133">"Сөйлеу жылдамдығы"</string>
-    <string name="tts_pitch" msgid="2389171233852604923">"Дауыс тембрі"</string>
+    <string name="tts_pitch" msgid="2389171233852604923">"Тон"</string>
     <string name="tts_reset" msgid="6289481549801844709">"Қалпына келтіру"</string>
     <string name="sound_settings" msgid="3072423952331872246">"Дыбыс"</string>
     <string name="ring_volume_title" msgid="3135241004980719442">"Қоңыраудың дыбыс деңгейі"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Басқа қолданбалар"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файлдар"</string>
     <string name="storage_system" msgid="1271345630248014010">"Жүйе"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Барлығы %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"\"Жүйе\" қалтасында Android <xliff:g id="VERSION">%s</xliff:g> жұмысына қажетті файлдар орналасқан."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудио файлдар"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Есептелуде…"</string>
@@ -721,7 +732,7 @@
     <string name="lockpattern_recording_intro_header" msgid="7864149726033694408">"Құлыпты ашу өрнегін сызыңыз"</string>
     <string name="lockpattern_recording_inprogress" msgid="1575019990484725964">"Салып болғанда саусағыңызды жіберіңіз"</string>
     <string name="lockpattern_pattern_entered" msgid="6103071005285320575">"Өрнек сақталды"</string>
-    <string name="lockpattern_need_to_confirm" msgid="4648070076022940382">"Растау үшін өрнекті қайта сызыңыз"</string>
+    <string name="lockpattern_need_to_confirm" msgid="4648070076022940382">"Растау үшін өрнекті қайта сызыңыз."</string>
     <string name="lockpattern_recording_incorrect_too_short" msgid="2417932185815083082">"Кемі 4 нүктені қосу қажет. Қайта салып көріңіз."</string>
     <string name="lockpattern_pattern_wrong" msgid="929223969555399363">"Қате өрнек"</string>
     <string name="lockpattern_settings_help_how_to_record" msgid="4436556875843192284">"Құлыпты ашу өрнегін сызу"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 90b56348a..5775ac21f 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ការតភ្ជាប់ឧបករណ៍ជាមួយរថយន្តរបស់អ្នក"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"កម្រិតបញ្ជូនខ្ពស់ខ្លាំង (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"ជួយរថយន្តរបស់អ្នកកំណត់ទីតាំងឧបករណ៍ UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ការស្ដាប់សំឡេងរួមគ្នា"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ស្ដាប់សំឡេងរួមគ្នា"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"អ្នកស្ដាប់ត្រូវមានកាស LE Audio ផ្ទាល់ខ្លួនរបស់ពួកគេ"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ចាក់សំឡេងសាកល្បង"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"អ្នកគ្រប់គ្នាដែលកំពុងស្ដាប់គួរតែស្ដាប់ឮវា"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ឧបករណ៍មេឌៀសកម្ម"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ការកំណត់ការចាក់សំឡេងលើអ៊ីនធឺណិត"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"កូដ QR ការចាក់សំឡេងលើអ៊ីនធឺណិត"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"ស្កេនកូដ QR ដើម្បីភ្ជាប់"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ដើម្បីស្ដាប់ការចាក់សំឡេងលើអ៊ីនធឺណិត អ្នកផ្សេងទៀតអាចភ្ជាប់កាសដែលត្រូវគ្នាទៅនឹងឧបករណ៍ Android របស់ពួកគេ។ បន្ទាប់មកពួកគេអាចស្កេនកូដ QR នេះបាន។"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"សំណើ​ផ្គូផ្គង​តាម​ប៊្លូធូស"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ផ្គូផ្គង និងភ្ជាប់"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"លេខកូដផ្គូផ្គងប៊្លូធូស"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"កម្មវិធី​ផ្សេង​ទៀត"</string>
     <string name="storage_files" msgid="6382081694781340364">"ឯកសារ"</string>
     <string name="storage_system" msgid="1271345630248014010">"ប្រព័ន្ធ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"សរុប %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"ប្រព័ន្ធរួមបញ្ចូលទាំងឯកសារ​ដែលប្រើ​សម្រាប់​ដំណើរការ​កំណែ Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ឯកសារ​សំឡេង"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"កំពុង​គណនា…"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 2ad94571d..7db396112 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ನಿಮ್ಮ ಕಾರ್‌ ಜೊತೆಗಿರುವ ಸಾಧನದ ಕನೆಕ್ಷನ್‌ಗಳು"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"ಅಲ್ಟ್ರಾ-ವೈಡ್‌ಬ್ಯಾಂಡ್ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB ಸಾಧನಗಳ ಸ್ಥಾನವನ್ನು ಗುರುತಿಸಲು ನಿಮ್ಮ ಕಾರಿಗೆ ಸಹಾಯ ಮಾಡುತ್ತದೆ"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ಆಡಿಯೋ ಹಂಚಿಕೊಳ್ಳುವಿಕೆ"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ಆಡಿಯೋ ಹಂಚಿಕೊಳ್ಳಿ"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ಕೇಳುಗರಿಗೆ ತಮ್ಮದೇ ಆದ LE ಆಡಿಯೋ ಹೆಡ್‌ಫೋನ್‌ಗಳ ಅಗತ್ಯವಿದೆ"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ಟೆಸ್ಟ್ ಸೌಂಡ್ ಅನ್ನು ಪ್ಲೇ ಮಾಡಿ"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ಆಲಿಸುತ್ತಿರುವ ಪ್ರತಿಯೊಬ್ಬರೂ ಅದನ್ನು ಕೇಳಬೇಕು"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ಸಕ್ರಿಯ ಮಾಧ್ಯಮ ಸಾಧನಗಳು"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ಆಡಿಯೋ ಸ್ಟ್ರೀಮ್ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ಆಡಿಯೋ ಸ್ಟ್ರೀಮ್ QR ಕೋಡ್‌"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"ಕನೆಕ್ಟ್ ಮಾಡಲು QR ಕೋಡ್ ಸ್ಕ್ಯಾನ್ ಮಾಡಿ"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ಆಡಿಯೋ ಸ್ಟ್ರೀಮ್ ಅನ್ನು ಆಲಿಸಲು, ಇತರ ಜನರು ತಮ್ಮ Android ಸಾಧನದಲ್ಲಿ ಹೊಂದಾಣಿಕೆಯ ಹೆಡ್‌ಫೋನ್‌ಗಳನ್ನು ಕನೆಕ್ಟ್‌ ಮಾಡಬಹುದು. ನಂತರ ಅವರು ಈ QR ಕೋಡ್ ಅನ್ನು ಸ್ಕ್ಯಾನ್ ಮಾಡಬಹುದು."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ಬ್ಲೂಟೂತ್‌‌ ಜೋಡಣೆ ವಿನಂತಿ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ಜೋಡಿಸಿ ಮತ್ತು ಸಂಪರ್ಕಪಡಿಸಿ"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ಬ್ಲೂಟೂತ್ ಜೋಡಣೆ ಕೋಡ್"</string>
@@ -325,7 +335,7 @@
     <string name="force_stop_dialog_title" msgid="4481858344628934971">"ಆ್ಯಪ್ ಅನ್ನು ನಿಲ್ಲಿಸಬೇಕೆ?"</string>
     <string name="force_stop_dialog_text" msgid="4354954014318432599">"ಆ್ಯಪ್‍ ಅನ್ನು ಬಲವಂತವಾಗಿ ಸ್ಥಗಿತಗೊಳಿಸಿದರೆ, ಅದು ಸರಿಯಾಗಿ ಕಾರ್ಯನಿರ್ವಹಿಸದಿರಬಹುದು."</string>
     <string name="force_stop_success_toast_text" msgid="2986272849275894254">"<xliff:g id="APP_NAME">%1$s</xliff:g> ಅನ್ನು ನಿಲ್ಲಿಸಲಾಗಿದೆ."</string>
-    <string name="prioritize_app_performance_dialog_title" msgid="3205297520523665568">"ಆ್ಯಪ್‌ನ ಕಾರ್ಯಕ್ಷಮತೆ ಆದ್ಯತೆಗೊಳಿಸಬೇಕೇ?"</string>
+    <string name="prioritize_app_performance_dialog_title" msgid="3205297520523665568">"ಆ್ಯಪ್‌ನ ಪರ್ಫಾರ್ಮೆನ್ಸ್ ಆದ್ಯತೆಗೊಳಿಸಬೇಕೇ?"</string>
     <string name="prioritize_app_performance_dialog_text" msgid="4321564728229192878">"ಸಂಭಾವ್ಯ ಸಿಸ್ಟಂ ಅಸ್ಥಿರತೆ ಅಥವಾ ದೀರ್ಘಾವಧಿಯ ಹಾರ್ಡ್‌ವೇರ್ ಪರಿಣಾಮವನ್ನು ಇದು ಉಂಟಾಗಬಹುದು. ನೀವು ಮುಂದುವರಿಸಲು ಬಯಸುತ್ತೀರಾ?"</string>
     <string name="prioritize_app_performance_dialog_action_on" msgid="3556735049873419163">"ಹೌದು"</string>
     <string name="prioritize_app_performance_dialog_action_off" msgid="2813324718753199319">"ಬೇಡ"</string>
@@ -422,7 +432,7 @@
     <string name="special_access" msgid="5730278220917123811">"ಆ್ಯಪ್‌ಗೆ ವಿಶೇಷ ಆ್ಯಕ್ಸೆಸ್"</string>
     <string name="show_system" msgid="4401355756969485287">"ಸಿಸ್ಟಂ ತೋರಿಸಿ"</string>
     <string name="hide_system" msgid="8845453295584638040">"ಸಿಸ್ಟಂ ಮರೆಮಾಡಿ"</string>
-    <string name="hide_system_apps" msgid="6583947381056154020">"ಸಿಸ್ಟಂ ಆ್ಯಪ್‌ಗಳನ್ನು ನಕಲಿಸಿ"</string>
+    <string name="hide_system_apps" msgid="6583947381056154020">"ಸಿಸ್ಟಂ ಆ್ಯಪ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಿ"</string>
     <string name="alarms_and_reminders_title" msgid="5201073616071479075">"ಅಲಾರಂಗಳು ಮತ್ತು ರಿಮೈಂಡರ್‌ಗಳು"</string>
     <string name="modify_system_settings_title" msgid="4596320571562433972">"ಸಿಸ್ಟಂ ಸೆಟ್ಟಿಂಗ್‍ ಮಾರ್ಪಡಿಸಿ"</string>
     <string name="modify_system_settings_description" msgid="5295023124419592452">"ಈ ಅನುಮತಿಯು ಸಿಸ್ಟಂ ಸೆಟ್ಟಿಂಗ್‌ಗಳನ್ನು ಮಾರ್ಪಡಿಸಲು ಆ್ಯಪ್‌ಗೆ ಅನುಮತಿಸುತ್ತದೆ."</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"ಇತರ ಆ್ಯಪ್‌ಗಳು"</string>
     <string name="storage_files" msgid="6382081694781340364">"ಫೈಲ್‌ಗಳು"</string>
     <string name="storage_system" msgid="1271345630248014010">"ಸಿಸ್ಟಂ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"ಒಟ್ಟು %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Android ಆವೃತ್ತಿ <xliff:g id="VERSION">%s</xliff:g> ರನ್ ಮಾಡಲು ಬಳಸುವ ಫೈಲ್‌ಗಳು ಈ ಸಿಸ್ಟಂನಲ್ಲಿವೆ"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ಆಡಿಯೋ ಫೈಲ್‌ಗಳು"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"ಲೆಕ್ಕ ಮಾಡಲಾಗುತ್ತಿದೆ…"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index d645cf1d2..32ca2d2e4 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"자동차와 기기 연결"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"초광대역(UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"자동차에서 초광대역 기기의 위치를 파악하도록 돕습니다."</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"오디오 공유"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"오디오 공유"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"오디오를 들으려면 각자 LE 오디오 헤드폰이 있어야 합니다."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"테스트 소리 재생"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"청취 중인 모든 사용자가 들을 수 있어야 합니다."</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"사용 중인 미디어 기기"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"오디오 스트림 설정"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"오디오 스트림 QR 코드"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"QR 코드를 스캔하여 연결"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"자신의 Android 기기에 호환되는 헤드폰을 연결하고 이 QR 코드를 스캔하면 누구나 오디오 스트림을 들을 수 있습니다."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"블루투스 페어링 요청"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"페어링 및 연결"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"블루투스 페어링 코드"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"기타 앱"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"시스템"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"총 %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"시스템에는 Android 버전 <xliff:g id="VERSION">%s</xliff:g> 실행에 사용되는 파일이 포함되어 있습니다."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"오디오 파일"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"계산 중..."</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 0ecca67f6..37c323faa 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Түзмөктүн унааңыз менен туташуулары"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Өтө кең тилке (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Унааңызга UWB түзмөктөрүн аныктоого жардам берет"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Чогуу угуу"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Аудиону бөлүшүү"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Угуу үчүн алардын LE Audio гарнитурасы болушу керек"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Добушту угуп көрүү"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Ал туташып турган колдонуучулардын баарына угулушу керек"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Активдүү медиа түзмөктөр"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Аудио агымдын параметрлери"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Аудио агымдын QR коду"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Туташуу үчүн QR кодун скандоо"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Аудио агымды угуу үчүн башкалар шайкеш гарнитурасын Android түзмөгүнө туташтыра алышат. Андан соң, алар бул QR кодун скандашы керек."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth жупташтыруу өтүнүчү"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Байланыштыруу жана туташтыруу"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth аркылуу байланыштыруу коду"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Башка колдонмолор"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файлдар"</string>
     <string name="storage_system" msgid="1271345630248014010">"Система"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Бардыгы %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Системада Android <xliff:g id="VERSION">%s</xliff:g> версиясында иштеген файлдар бар"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудио файлдар"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Эсептелүүдө…"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index ad6f95fe7..8a48999e7 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ການເຊື່ອມຕໍ່ອຸປະກອນກັບລົດຂອງທ່ານ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"ultra-wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"ຊ່ວຍລົດຂອງທ່ານລະບຸຕຳແໜ່ງຂອງອຸປະກອນ UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ການແບ່ງປັນສຽງ"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ແບ່ງປັນສຽງ"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ຜູ້ຟັງຈຳເປັນຕ້ອງມີຫູຟັງສຽງ LE ຂອງຕົນເອງ"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ຫຼິ້ນສຽງທົດສອບ"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ທຸກຄົນທີ່ຟັງຄວນໄດ້ຍິນ"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ອຸປະກອນມີເດຍທີ່ໃຊ້ຢູ່"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ການຕັ້ງຄ່າການສະຕຣີມສຽງ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ລະຫັດ QR ການສະຕຣີມສຽງ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"ສະແກນລະຫັດ QR ເພື່ອເຊື່ອມຕໍ່"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ເພື່ອຟັງການສະຕຣີມສຽງ, ຄົນອື່ນສາມາດເຊື່ອມຕໍ່ຫູຟັງທີ່ເຂົ້າກັນໄດ້ກັບອຸປະກອນ Android ຂອງເຂົາເຈົ້າໄດ້. ເຂົາເຈົ້າສາມາດສະແກນລະຫັດ QR ນີ້."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ຄຳຂໍຈັບຄູ່ Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ຈັບຄູ່ ແລະ ເຊື່ອມຕໍ່"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ລະຫັດຈັບຄູ່ Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"ແອັບອື່ນໆ"</string>
     <string name="storage_files" msgid="6382081694781340364">"ໄຟລ໌"</string>
     <string name="storage_system" msgid="1271345630248014010">"ລະບົບ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"ຮວມ %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"ລະບົບຮວມມີໄຟລ໌ທີ່ໃຊ້ເພື່ອເປີດໃຊ້ Android ເວີຊັນ <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ໄຟລ໌ສຽງ"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"ກຳລັງຄິດໄລ່…"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 7e1eacb4a..0fbf87f28 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Įrenginio prisijungimai prie automobilio"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultraplačiajuostė ryšio techn. (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Padeda automobiliui nustatyti UWB įrenginių padėtį"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Garso įrašų bendrinimas"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Bendrinti garsą"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Klausytojams reikia atskirų „LE Audio“ ausinių"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Bandomojo garso leidimas"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Visi klausantieji turėtų girdėti"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktyvūs medijos įrenginiai"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Garso srauto nustatymai"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Garso srauto QR kodas"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Nusk. QR kodą, kad gal. prisijungti"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Norėdami klausyti garso srautą, kiti žmonės gali prijungti suderinamas ausines prie „Android“ įrenginio. Tada jie gali nuskaityti šį QR kodą."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"„Bluetooth“ susiejimo užklausa"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Susieti ir jungti"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"„Bluetooth“ susiejimo kodas"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Kitos programos"</string>
     <string name="storage_files" msgid="6382081694781340364">"Failai"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Iš viso: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistema apima failus, naudojamus vykdant <xliff:g id="VERSION">%s</xliff:g> versijos „Android“"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Garso failai"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Skaičiuojama…"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 3f5991fcc..bf23b3d35 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Ar jūsu automašīnu savienotās ierīces"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra platjosla (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Palīdz jūsu automašīnai identificēt UWB ierīču pozīciju."</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio kopīgošana"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Kopīgot audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Klausītājiem vajadzēs savas LE Audio austiņas"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Testa signāla atskaņošana"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Audio jābūt dzirdamam visiem klausītājiem"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktīvās multivides ierīces"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio straumes iestatījumi"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio straumes kvadrātkods"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skenējiet kvadrātkodu, lai savienotu"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Lai klausītos audio straumi, citi lietotāji savās Android ierīcēs var izveidot savienojumu ar saderīgām austiņām. Pēc tam viņi var skenēt šo kvadrātkodu."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth pieprasījums savienošanai pārī"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Savienot pārī un izveidot savienojumu"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth kods savienošanai pārī"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Citas lietotnes"</string>
     <string name="storage_files" msgid="6382081694781340364">"Faili"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistēma"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Kopā: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistēmā ir ietverti faili, kas tiek izmantoti Android versijai <xliff:g id="VERSION">%s</xliff:g>."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio faili"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Notiek aprēķināšana…"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 4ba056bf0..2a4504af4 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -44,7 +44,7 @@
     <string name="sim_change_data_message" msgid="4669775284395549069">"Користите <xliff:g id="CARRIER2_0">%2$s</xliff:g> за мобилен интернет. Ако се префрлите на <xliff:g id="CARRIER1">%1$s</xliff:g>, <xliff:g id="CARRIER2_1">%2$s</xliff:g> веќе нема да се користи за мобилен интернет."</string>
     <string name="sim_change_data_ok" msgid="2348804996223271081">"Користи <xliff:g id="CARRIER">%1$s</xliff:g>"</string>
     <string name="roaming_title" msgid="6218635014519017734">"Роаминг"</string>
-    <string name="roaming_summary" msgid="7476127740259728901">"Поврзувај се со интернет-услуги во роаминг"</string>
+    <string name="roaming_summary" msgid="7476127740259728901">"Поврзувај се на мобилен интернет во роаминг"</string>
     <string name="roaming_alert_title" msgid="4433901635766775763">"Да се дозволи ли интернет-роаминг?"</string>
     <string name="roaming_warning" msgid="4908184914868720704">"Може да ви се наплати за роаминг."</string>
     <string name="data_usage_settings" msgid="7877132994777987848">"Потрошен интернет"</string>
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Поврзувања на уредот со вашиот автомобил"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ултраширок појас (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Му помага на вашиот автомобил да ја идентификува положбата на уредите со UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Споделување аудио"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Споделувајте аудио"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Слушателите треба да имаат сопствени слушалки со LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Пуштете пробен звук"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Секој што слуша би требало да го слушне"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Активни преносливи уреди"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Поставки за аудиостримот"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-код на аудиостримот"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Скенирајте го QR-кодот за да се поврзете"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"За слушање на аудиостримот, други луѓе може да поврзат компатибилни слушалки на нивниот уред со Android. Потоа може да го скенираат QR-кодов."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Барање за спарување преку Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Спари и поврзи"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Код за спарување преку Bluetooth"</string>
@@ -359,7 +369,7 @@
     <string name="storage_type_internal" msgid="8918688427078709570">"%s во внатрешен капацитет"</string>
     <string name="prioritize_app_performance_summary" msgid="1081874788185691418">"Се користат ресурси на системот за да се стави приоритет на изведбата на апликацијата"</string>
     <string name="app_open_by_default_title" msgid="7275063779631935446">"Отворај стандардно"</string>
-    <string name="app_open_by_default_summary" msgid="3261520150951464121">"Дозволете апликацијата да отвора поддржани линкови"</string>
+    <string name="app_open_by_default_summary" msgid="3261520150951464121">"Дозволете ѝ на апликацијата да отвора поддржани линкови"</string>
     <string name="data_usage_summary_title" msgid="4368024763485916986">"Потрошен интернет"</string>
     <string name="data_usage_app_summary_title" msgid="5012851696585421420">"Потрошен интернет од апл."</string>
     <string name="data_usage_usage_history_title" msgid="2386346082501471648">"Историја на сообраќај"</string>
@@ -436,7 +446,7 @@
     <string name="performance_impacting_apps_button_label" msgid="8277507326717608783">"Дајте предност на апликацијата"</string>
     <string name="premium_sms_access_title" msgid="4290463862145052004">"Премиум SMS"</string>
     <string name="premium_sms_access_description" msgid="7119026067677052169">"Премиум SMS може да ве чини пари, а сумата ќе се додаде на сметките од операторот. Ако овозможите дозвола за апликацијата, ќе може да испраќате премиум SMS со неа."</string>
-    <string name="usage_access_title" msgid="2306113730908698218">"Податоци за користење апликација"</string>
+    <string name="usage_access_title" msgid="2306113730908698218">"Податоци за користење апликации"</string>
     <string name="usage_access_description" msgid="7889884409739123407">"Пристапот до сите податоци за користењето апликација овозможуваат апликацијата да следи кои други апликации ги користите и колку често, како и вашиот оператор, поставки за јазик и други детали."</string>
     <string name="wifi_control_title" msgid="5660436566907731929">"Контрола на Wi-Fi"</string>
     <string name="wifi_control_description" msgid="6021926850423169261">"Контролата на Wi-Fi дозволува апликацијава да вклучува или исклучува Wi-Fi, да скенира и да се поврзува на Wi-Fi мрежи, да додава или отстранува мрежи или да стартува локална точка на пристап."</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Други апликации"</string>
     <string name="storage_files" msgid="6382081694781340364">"Датотеки"</string>
     <string name="storage_system" msgid="1271345630248014010">"Систем"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Вкупно: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Системот опфаќа датотеки што се користат за извршување на верзијата <xliff:g id="VERSION">%s</xliff:g> на Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудиодатотеки"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Се пресметува…"</string>
@@ -776,7 +787,7 @@
     <string name="lockpassword_pin_no_sequential_digits" msgid="6511579896796310956">"Не е дозволена нагорна, надолна или повторлива секвенца на цифри"</string>
     <string name="setup_lock_settings_options_button_label" msgid="3337845811029780896">"Опции за заклучување на екранот"</string>
     <string name="credentials_reset" msgid="873900550885788639">"Бришење акредитиви"</string>
-    <string name="credentials_reset_summary" msgid="6067911547500459637">"Отстрани ги сите сертификати"</string>
+    <string name="credentials_reset_summary" msgid="6067911547500459637">"Отстранете ги сите сертификати"</string>
     <string name="credentials_reset_hint" msgid="3459271621754137661">"Дали да се отстранат сите содржини?"</string>
     <string name="credentials_erased" msgid="2515915439705550379">"Меморијата на акредитиви е избришана."</string>
     <string name="credentials_not_erased" msgid="6118567459076742720">"Меморијата на акредитиви не може да се избрише."</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 2f0ad7634..7b9c42286 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"കാറിലേക്ക് കണക്‌റ്റ് ചെയ്ത ഉപകരണങ്ങൾ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"അൾട്രാ-വൈഡ്ബാൻഡ് (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB ഉപകരണങ്ങളുടെ സ്ഥാനം തിരിച്ചറിയാൻ നിങ്ങളുടെ കാറിനെ സഹായിക്കുന്നു"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ഓഡിയോ പങ്കിടൽ"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ഓഡിയോ പങ്കിടുക"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"കേൾക്കുന്നവർക്ക് അവരുടേതായ LE ഓഡിയോ ഹെഡ്‌ഫോണുകൾ ആവശ്യമാണ്"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ശബ്ദ പരിശോധന പ്ലേ ചെയ്യുക"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ശ്രദ്ധിക്കുന്ന എല്ലാവരും ഇത് കേൾക്കണം"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"സജീവമായ മീഡിയ ഉപകരണങ്ങൾ"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ഓഡിയോ സ്ട്രീം ക്രമീകരണം"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ഓഡിയോ സ്ട്രീം QR കോഡ്"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"കണക്‌റ്റ് ചെയ്യാൻ QR കോഡ് സ്‌കാൻ ചെയ്യുക"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ഓഡിയോ സ്ട്രീം കേൾക്കാൻ, മറ്റുള്ളവർക്ക് അവരുടെ Android ഉപകരണത്തിലേക്ക് അനുയോജ്യമായ ഹെഡ്‌ഫോണുകൾ കണക്റ്റ് ചെയ്യാം. തുടർന്ന്, അവർക്ക് ഈ QR കോഡ് സ്കാൻ ചെയ്യാം."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth ജോടിയാക്കൽ അഭ്യർത്ഥന"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ജോടിയാക്കി കണ‌ക്‌റ്റ് ചെയ്യുക"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth ജോടിയാക്കൽ കോഡ്"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"മറ്റ് ആപ്പുകൾ"</string>
     <string name="storage_files" msgid="6382081694781340364">"ഫയലുകൾ"</string>
     <string name="storage_system" msgid="1271345630248014010">"സിസ്‌റ്റം"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"മൊത്തം %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"സിസ്‌റ്റത്തിൽ Android <xliff:g id="VERSION">%s</xliff:g> പതിപ്പ് റൺ ചെയ്യാൻ ഉപയോഗിച്ച ഫയലുകളും ഉൾപ്പെടുന്നു"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ഓഡിയോ ഫയലുകൾ"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"കണക്കാക്കുന്നു…"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 942e959ad..9599599e8 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Таны машины төхөөрөмжийн холболтууд"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Хэт өргөн зурвас (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Таны машинд UWB төхөөрөмжүүдийн байрлалыг танихад тусалдаг"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Аудио хуваалцах"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Аудио хуваалцах"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Сонсогч өөрийн гэсэн LE Аудио чихэвчтэй байх шаардлагатай"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Туршилтын дуу чимээ тоглуулах"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Сонсож буй хүн бүр үүнийг сонсох ёстой"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Идэвхтэй медиа төхөөрөмж"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Аудио дамжуулалтын тохиргоо"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Аудио дамжуулалтын QR код"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Холбохын тулд QR кодыг скан хийх"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Аудио дамжуулалт сонсохын тулд бусад хүн Android төхөөрөмждөө тохирох чихэвч холбож болно. Тэд дараа нь энэ QR кодыг скан хийх боломжтой."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth-г хослуулах хүсэлт"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Хослуулах ба холбох"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-н хослуулах код"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Бусад апп"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файл"</string>
     <string name="storage_system" msgid="1271345630248014010">"Систем"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Нийт %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Систем Андройдын <xliff:g id="VERSION">%s</xliff:g> хувилбарыг ажиллуулахад ашигладаг файлуудыг агуулдаг"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудио файл"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Тооцоолж байна…"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index f291e9c38..2c3becb46 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"तुमच्या कारसोबतची डिव्हाइस कनेक्शन"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"अल्ट्रा-वाइडबँड (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"तुमच्या कारला UWB डिव्हाइसचे स्थान ओळखण्यात मदत करते"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ऑडिओ शेअरिंग"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ऑडिओ शेअर करा"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ऐकणाऱ्यांकडे त्यांचे स्वत:चे LE ऑडिओ हेडफोन असणे आवश्यक आहे"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"चाचणी आवाज प्ले करा"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ऐकणाऱ्या प्रत्येकाला ते ऐकू यायला हवे"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ॲक्टिव्ह मीडिया डिव्हाइस"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ऑडिओ स्ट्रीमची सेटिंग्ज"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ऑडिओ स्ट्रीमचा QR कोड"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"कनेक्ट करण्यासाठी QR कोड स्कॅन करा"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ऑडिओ स्ट्रीम ऐकण्यासाठी, इतर लोक त्यांच्या Android डिव्हाइसशी कंपॅटिबल हेडफोन कनेक्ट करू शकतात. त्यानंतर ते हा QR कोड स्कॅन करू शकतात."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ब्लूटूथ पेअरिंग विनंती"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"पेअर करा आणि कनेक्ट करा"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ब्लूटूथ पेअरिंग कोड"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"इतर अ‍ॅप्स"</string>
     <string name="storage_files" msgid="6382081694781340364">"फाइल"</string>
     <string name="storage_system" msgid="1271345630248014010">"सिस्टीम"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"एकूण %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"सिस्टममध्ये अशा फायलींचा समावेश आहे ज्यांचा वापर Android आवृत्ती <xliff:g id="VERSION">%s</xliff:g> रन करण्यासाठी केला जातो"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ऑडिओ फाइल"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"मोजत आहे…"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 0266e137f..b820ba70d 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Sambungan peranti dengan kereta anda"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Jalur Ultralebar (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Bantu kereta anda mengenal pasti kedudukan peranti UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Perkongsian Audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Kongsi audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Pendengar memerlukan fon kepala LE Audio mereka sendiri"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Mainkan bunyi ujian"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Orang yang mendengar seharusnya dapat mendengar bunyi itu"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Peranti media aktif"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Tetapan strim audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Kod QR strim audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Imbas kod QR untuk membuat sambungan"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Untuk mendengar strim audio, orang lain boleh menyambungkan fon kepala serasi kepada peranti Android mereka. Kemudian mereka boleh mengimbas kod QR ini."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Permintaan penggandingan Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Gandingkan &amp; sambung"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kod gandingan Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Apl lain"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fail"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s kesemuanya"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistem termasuk fail yang digunakan untuk menjalankan Android versi <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Fail audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Mengira…"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 7c200b6ee..60121d55e 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ကားနှင့် စက်ပစ္စည်း ချိတ်ဆက်မှုများ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"သင့်ကားကို UWB စက်ပစ္စည်းများ၏ တည်နေရာ ရှာဖွေသတ်မှတ်ရာတွင် ကူညီပေးသည်"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"အော်ဒီယို မျှဝေခြင်း"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"အသံမျှဝေရန်"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"နားဆင်သူများသည် .သူတို့ကိုယ်ပိုင် LE Audio နားကြပ် လိုအပ်သည်"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"စမ်းသပ်အသံ ဖွင့်ခြင်း"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"၎င်းကို လူတိုင်း ကြားရမည်"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"လက်ရှိ မီဒီယာ စက်ပစ္စည်းများ"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"အသံထုတ်လွှင့်ခြင်း ဆက်တင်များ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"အသံထုတ်လွှင့်ခြင်း QR ကုဒ်"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"ချိတ်ဆက်ရန် QR ကုဒ်ကို စကင်ဖတ်ပါ"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"အသံထုတ်လွှင့်ခြင်းကို နားထောင်ရန် အခြားသူများသည် သူတို့၏ Android စက်တွင် တွဲသုံးနိုင်သော နားကြပ်ကို ချိတ်ဆက်နိုင်သည်။ ထို့နောက် ဤ QR ကုဒ်ကို စကင်ဖတ်နိုင်သည်။"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ဘလူးတုသ်တွဲချိတ်ရန် တောင်းဆိုချက်"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"တွဲချိတ်ပြီးနောက် ချိတ်ဆက်ရန်"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ဘလူးတုသ် တွဲချိတ်ကုဒ်"</string>
@@ -489,7 +499,7 @@
     <string name="firmware_version" msgid="8491753744549309333">"Android ဗားရှင်း"</string>
     <string name="security_patch" msgid="4794276590178386903">"Android လုံခြုံရေးပက်ချ်အဆင့်"</string>
     <string name="hardware_info" msgid="3973165746261507658">"မော်ဒယ်နှင့် စက်ပစ္စည်းဆိုင်ရာ"</string>
-    <string name="hardware_info_summary" msgid="8262576443254075921">"မော်ဒယ်- <xliff:g id="MODEL">%1$s</xliff:g>"</string>
+    <string name="hardware_info_summary" msgid="8262576443254075921">"မိုဒယ်- <xliff:g id="MODEL">%1$s</xliff:g>"</string>
     <string name="baseband_version" msgid="2370088062235041897">"baseband ဗားရှင်း"</string>
     <string name="kernel_version" msgid="7327212934187011508">"Kernel ဗားရှင်း"</string>
     <string name="build_number" msgid="3997326631001009102">"တည်ဆောက်မှုနံပါတ်"</string>
@@ -513,7 +523,7 @@
     <string name="webview_license_title" msgid="6442372337052056463">"စနစ်၏ ဝဘ်မြင်ကွင်း လိုင်စင်များ"</string>
     <string name="wallpaper_attributions" msgid="9201272150014500697">"နောက်ခံပုံများ"</string>
     <string name="wallpaper_attributions_values" msgid="4292446851583307603">"ဂြိုဟ်တုဓာတ်ပုံ ဝန်ဆောင်မှုပေးသူများ−\n©2014 CNES / Astrium၊ DigitalGlobe၊ Bluesky"</string>
-    <string name="model_info" msgid="4966408071657934452">"မော်ဒယ်"</string>
+    <string name="model_info" msgid="4966408071657934452">"မိုဒယ်"</string>
     <string name="status_serial_number" msgid="9158889113131907656">"အမှတ်စဉ်"</string>
     <string name="hardware_revision" msgid="5713759927934872874">"ဟာ့ဒ်ဝဲ ဗားရှင်း"</string>
     <string name="regulatory_info_text" msgid="8890339124198005428"></string>
@@ -623,6 +633,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"အခြားအက်ပ်များ"</string>
     <string name="storage_files" msgid="6382081694781340364">"ဖိုင်များ"</string>
     <string name="storage_system" msgid="1271345630248014010">"စနစ်"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"စုစုပေါင်း %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"စနစ်တွင် Android ဗားရှင်း <xliff:g id="VERSION">%s</xliff:g> ဖြင့် ဖွင့်ခဲ့သည့်ဖိုင်များ ပါဝင်သည်"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"အသံဖိုင်များ"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"တွက်ချက်နေသည်…"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 186382996..3f83ca35a 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Enhetstilkoblinger til bilen din"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultrabredbånd (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Gjør det lettere for bilen å identifisere hvor UWB-enheter er plassert"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Lyddeling"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Del lyd"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"De må ha sine egne hodetelefoner med støtte for LE-lyd"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Spill av en testlyd"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Alle som lytter, skal høre den"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktive medieenheter"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Innstillinger for lydstrømmen"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-kode for lydstrømmen"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skann QR-koden for å koble til"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"For å lytte til lydstrømmer kan folk koble kompatible hodetelefoner til Android-enheten sin. Deretter kan de skanne denne QR-koden."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Forespørsel om Bluetooth-tilkobling"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Koble sammen"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-tilkoblingskode"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Andre apper"</string>
     <string name="storage_files" msgid="6382081694781340364">"Filer"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s totalt"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Systemet inkluderer filer som brukes for å kjøre Android versjon <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Lydfiler"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Beregner …"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index fbea2797e..735b94067 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"तपाईंको कारमा उपलब्ध डिभाइस कनेक्सनहरू"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"अल्ट्रा-वाइडब्यान्ड (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"तपाईंको कारलाई UWB डिभाइसहरूको स्थान पत्ता लगाउन मद्दत गर्छ"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"अडियो सेयर गर्ने सुविधा"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"अडियो सेयर गर्नुहोस्"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"यसका लागि श्रोतासँग आफ्नै LE अडियो हेडफोन हुनु पर्छ"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"परीक्षण गर्न कुनै साउन्ड प्ले गर्नुहोस्"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"अडियो सुनिरहेका सबै मान्छेले यो साउन्ड सुन्नु पर्छ"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"सक्रिय मिडिया डिभाइसहरू"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"अडियो स्ट्रिमसम्बन्धी सेटिङ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"अडियो स्ट्रिमको QR कोड"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"कनेक्ट गर्न QR कोड स्क्यान गर्नुहोस्"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"अडियो स्ट्रिम सुन्न अन्य मान्छेहरूले आफ्नो Android डिभाइसमा कम्प्याटिबल हेडफोन कनेक्ट गर्नु पर्छ। त्यसपछि उनीहरूले यो QR कोड स्क्यान गर्नु पर्छ।"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ब्लुटुथसँग कनेक्ट गर्ने अनुरोध"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"जोडा बनाउनुहोस् र कनेक्ट गर्नुहोस्"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ब्लुटुथसँग कनेक्ट गर्ने कोड"</string>
@@ -522,7 +532,7 @@
     <string name="show_dev_countdown" msgid="7416958516942072383">"{count,plural, =1{तपाईं अब # चरण पूरा गरेपछि विकासकर्ता बन्नु हुने छ।}other{तपाईं अब # वटा चरण पूरा गरेपछि विकासकर्ता बन्नु हुने छ।}}"</string>
     <string name="show_dev_on" msgid="5339077400040834808">"तपाईं अब एउटा विकासकर्ता हुनुभएको छ!"</string>
     <string name="show_dev_already" msgid="1678087328973865736">"आवश्यक छैन, तपाईं आफैँ नै एउटा विकासकर्ता हुनुहुन्छ।"</string>
-    <string name="developer_options_settings" msgid="1530739225109118480">"विकासकर्ताका विकल्पहरू"</string>
+    <string name="developer_options_settings" msgid="1530739225109118480">"विकासकर्ता मोड"</string>
     <string name="reset_options_title" msgid="4388902952861833420">"रिसेटका विकल्पहरू"</string>
     <string name="reset_options_summary" msgid="5508201367420359293">"नेटवर्क, एप वा यन्त्रको रिसेटसम्बन्धी विकल्प"</string>
     <string name="reset_network_title" msgid="3077846909739832734">"Wi‑Fi तथा ब्लुटुथ रिसेट गर्नुहोस्"</string>
@@ -559,7 +569,7 @@
     <string name="date_time_auto" msgid="6018635902717385962">"समय स्वतः सेट गर्नुहोस्"</string>
     <string name="zone_auto" msgid="4174874778459184605">"प्रामाणिक समय स्वतः सेट गर्नुहोस्"</string>
     <string name="date_time_24hour_title" msgid="3025576547136168692">"२४ घन्टे ढाँचा"</string>
-    <string name="date_time_24hour" msgid="1137618702556486913">"२४-घन्टे ढाँचा प्रयोग गर्नुहोस्"</string>
+    <string name="date_time_24hour" msgid="1137618702556486913">"२४-घन्टे घडी प्रयोग गर्नुहोस्"</string>
     <string name="date_time_set_time_title" msgid="5884883050656937853">"समय"</string>
     <string name="date_time_set_time" msgid="3684135432529445165">"घडी मिलाउनुहोस्"</string>
     <string name="date_time_set_timezone_title" msgid="3001779256157093425">"प्रामाणिक समय"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"अन्य एपहरू"</string>
     <string name="storage_files" msgid="6382081694781340364">"फाइलहरू"</string>
     <string name="storage_system" msgid="1271345630248014010">"प्रणाली"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"कुल %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"सिस्टममा Android को संस्करण <xliff:g id="VERSION">%s</xliff:g> चलाउन प्रयोग भएका फाइलहरू समावेश छन्"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"अडियो फाइलहरू"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"गणना गर्दै…"</string>
@@ -837,7 +848,7 @@
     <string name="admin_profile_owner_message" msgid="8361351256802954556">"सङ्गठनका प्रबन्धक सम्बन्धित सेटिङ, अनुमति, संस्थागत पहुँच, नेटवर्कसम्बन्धी क्रियाकलाप र सवारी साधनको लोकेसनसम्बन्धी जानकारीसहित यो प्रोफाइलसँग सम्बन्धित एप र डेटाको निरीक्षण तथा व्यवस्थापन गर्न सक्छन्।"</string>
     <string name="admin_profile_owner_user_message" msgid="366072696508275753">"सङ्गठनका प्रबन्धक सम्बन्धित सेटिङ, अनुमति, संस्थागत पहुँच, नेटवर्कसम्बन्धी क्रियाकलाप र यो डिभाइसको लोकेसनसम्बन्धी जानकारीसहित यो प्रोफाइलसँग सम्बन्धित एप र डेटाको निरीक्षण तथा व्यवस्थापन गर्न सक्छन्।"</string>
     <string name="admin_device_owner_message" msgid="896530502350904835">"सङ्गठनका प्रबन्धक सम्बन्धित सेटिङ, अनुमति, संस्थागत पहुँच, नेटवर्कसम्बन्धी क्रियाकलाप र सवारी साधनको लोकेसनसम्बन्धी जानकारीसहित यो इन्फोटेनमेन्ट प्रणालीसँग सम्बन्धित एप र डेटाको निरीक्षण तथा व्यवस्थापन गर्न सक्छन्।"</string>
-    <string name="admin_financed_message" msgid="7357397436233684082">"सङ्गठनका प्रबन्धक यो इन्फोटेनमेन्ट प्रणालीसँग सम्बन्धित डेटा हेर्न तथा प्रयोग गर्न, एपहरू व्यवस्थापन गर्न र यो सवारी साधनका सेटिङ परिवर्तन गर्न सक्छन्।"</string>
+    <string name="admin_financed_message" msgid="7357397436233684082">"सङ्गठनका प्रबन्धक यो इन्फोटेनमेन्ट प्रणालीसँग सम्बन्धित डेटा एक्सेस गर्न, एपहरू व्यवस्थापन गर्न र यो सवारी साधनका सेटिङ परिवर्तन गर्न सक्छन्।"</string>
     <string name="disabled_by_policy_title" msgid="1121694702115232518">"तपाईं यो सेटिङ खोल्न सक्नुहुन्न"</string>
     <string name="disabled_by_policy_title_adjust_volume" msgid="7002865820552702232">"व्यवस्थापन गरिएको यो सवारी साधनमा भोल्युम घटबढ गर्न सकिँदैन"</string>
     <string name="disabled_by_policy_title_outgoing_calls" msgid="158752542663419500">"व्यवस्थापन गरिएको यो सवारी साधनबाट कल गर्न मिल्दैन"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 8c49a526f..0f82d41a9 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Apparaatverbindingen met je auto"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra-wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Helpt je auto om de positie van UWB-apparaten te bepalen"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio delen"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Audio delen"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Luisteraars hebben een eigen koptelefoon met LE Audio nodig"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Een testgeluid afspelen"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Iedereen die luistert, zou het moeten horen"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Actieve media-apparaten"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Instellingen voor audiostream"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-code van audiostream"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scan de QR-code om verbinding te maken"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Andere mensen kunnen een geschikte koptelefoon met hun Android-apparaat verbinden als ze naar een audiostream willen luisteren. Daarna moeten ze deze QR-code scannen."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth-koppelingsverzoek"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Koppelen en verbinden"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth-koppelingscode"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Andere apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Bestanden"</string>
     <string name="storage_system" msgid="1271345630248014010">"Systeem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Totaal %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Systeem omvat bestanden die worden gebruikt om Android-versie <xliff:g id="VERSION">%s</xliff:g> uit te voeren"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audiobestanden"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Berekenen…"</string>
@@ -821,7 +832,7 @@
     <string name="qc_ui_mode_title" msgid="2425571805732530923">"Thema"</string>
     <string name="driving_mode_title" msgid="8103270030335833998">"Rijstand instellen"</string>
     <string name="show_layout_bounds_title" msgid="8590148405645027755">"Indelingsgrenzen tonen"</string>
-    <string name="show_force_rtl_title" msgid="8240732919603115320">"V.r.n.l.-indelingsrichting afdwingen"</string>
+    <string name="show_force_rtl_title" msgid="8240732919603115320">"RTL-indelingsrichting afdwingen"</string>
     <string name="show_customization_overlay_title" msgid="2543804846629965883">"Overlay voor aanpassing"</string>
     <string name="device_admin_add_title" msgid="1294399588284546811">"Beheer van infotainmentsysteem"</string>
     <string name="device_admin_activated_apps" msgid="568075063362271751">"Geactiveerde apps"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 84fc422c6..eb134a7c1 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ଆପଣଙ୍କ କାର ସହ ଡିଭାଇସ କନେକ୍ସନଗୁଡ଼ିକ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"ଅଲ୍ଟ୍ରା-ୱାଇଡବେଣ୍ଡ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"ଏହା ଆପଣଙ୍କ କାରକୁ UWB ଡିଭାଇସଗୁଡ଼ିକର ଅବସ୍ଥିତି ଚିହ୍ନଟ କରିବାରେ ସାହାଯ୍ୟ କରେ"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ଅଡିଓ ସେୟାରିଂ"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ଅଡିଓ ସେୟାର କରନ୍ତୁ"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ଶ୍ରୋତାମାନେ ସେମାନଙ୍କର ନିଜର LE ଅଡିଓ ହେଡଫୋନଗୁଡ଼ିକୁ ଆବଶ୍ୟକ କରନ୍ତି"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ଏକ ଟେଷ୍ଟ ସାଉଣ୍ଡ ଚଲାନ୍ତୁ"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ଶୁଣୁଥିବା ସମସ୍ତ ବ୍ୟକ୍ତି ଏହା ଶୁଣିବା ଉଚିତ"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ସକ୍ରିୟ ମିଡିଆ ଡିଭାଇସ"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ଅଡିଓ ଷ୍ଟ୍ରିମ ସେଟିଂସ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ଅଡିଓ ଷ୍ଟ୍ରିମ QR କୋଡ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"କନେକ୍ଟ କରିବା ପାଇଁ QR କୋଡକୁ ସ୍କାନ କରନ୍ତୁ"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ଅଡିଓ ଷ୍ଟ୍ରିମକୁ ଶୁଣିବା ପାଇଁ, ଅନ୍ୟ ଲୋକ କମ୍ପାଟିବଲ ହେଡଫୋନଗୁଡ଼ିକୁ ସେମାନଙ୍କ Android ଡିଭାଇସ ସହିତ କନେକ୍ଟ କରିପାରିବେ। ତା\'ପରେ ସେମାନେ ଏହି QR କୋଡକୁ ସ୍କାନ କରିପାରିବେ।"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ବ୍ଲୁଟୂଥ୍‍ ପେୟାର୍ କରିବା ପାଇଁ ଅନୁରୋଧ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ପେୟାର୍‌ ଓ ସଂଯୋଗ"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ବ୍ଲୁଟୁଥ ପେୟାରିଂ କୋଡ୍"</string>
@@ -509,7 +519,7 @@
     <string name="copyright_title" msgid="4220237202917417876">"କପୀରାଇଟ୍‌"</string>
     <string name="license_title" msgid="936705938435249965">"ଲାଇସେନ୍ସ"</string>
     <string name="terms_title" msgid="5201471373602628765">"ନିୟମ ଓ ସର୍ତ୍ତାବଳୀ"</string>
-    <string name="webview_license_title" msgid="6442372337052056463">"ସିଷ୍ଟମ୍‍ WebView ଲାଇସେନ୍ସ"</string>
+    <string name="webview_license_title" msgid="6442372337052056463">"ସିଷ୍ଟମ WebView ଲାଇସେନ୍ସ"</string>
     <string name="wallpaper_attributions" msgid="9201272150014500697">"ୱାଲପେପର୍‌"</string>
     <string name="wallpaper_attributions_values" msgid="4292446851583307603">"ସେଟେଲାଇଟ ଇମେଜେରୀ ପ୍ରଦାତା:\n©2014 CNES / Astrium, DigitalGlobe, Bluesky"</string>
     <string name="model_info" msgid="4966408071657934452">"ମଡେଲ୍‌"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"ଅନ୍ୟ ଆପ୍‍"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"ସିଷ୍ଟମ୍"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s ମୋଟ"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Android ସଂସ୍କରଣ <xliff:g id="VERSION">%s</xliff:g>କୁ ଚଲାଇବା ପାଇଁ ସିଷ୍ଟମ୍, ଫାଇଲ୍‍ଗୁଡ଼ିକୁ ଅନ୍ତର୍ଭୁକ୍ତ କରିଥାଏ"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ଅଡିଓ ଫାଇଲ୍‌ଗୁଡ଼ିକ"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"ଗଣନା କରାଯାଉଛି…"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 839573705..4ed86e64e 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ਤੁਹਾਡੀ ਕਾਰ ਦੇ ਡੀਵਾਈਸ ਕਨੈਕਸ਼ਨ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"ਅਲਟ੍ਰਾ-ਵਾਈਡਬੈਂਡ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"ਇਸ ਨਾਲ ਤੁਹਾਡੀ ਕਾਰ ਨੂੰ UWB ਡੀਵਾਈਸਾਂ ਦੀ ਸਥਿਤੀ ਦੀ ਪਛਾਣ ਕਰਨ ਵਿੱਚ ਮਦਦ ਮਿਲਦੀ ਹੈ"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ਆਡੀਓ ਸਾਂਝਾਕਰਨ"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ਆਡੀਓ ਨੂੰ ਸਾਂਝਾ ਕਰੋ"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ਸਰੋਤਿਆਂ ਨੂੰ ਆਪਣੇ ਖੁਦ ਦੇ LE ਆਡੀਓ ਹੈੱਡਫ਼ੋਨਾਂ ਦੀ ਲੋੜ ਹੁੰਦੀ ਹੈ।"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ਕੋਈ ਜਾਂਚ ਧੁਨੀ ਚਲਾਓ"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ਸੁਣਨ ਵਾਲੇ ਹਰੇਕ ਵਿਅਕਤੀ ਨੂੰ ਇਹ ਸੁਣਨੀ ਚਾਹੀਦੀ ਹੈ"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"ਕਿਰਿਆਸ਼ੀਲ ਮੀਡੀਆ ਡੀਵਾਈਸ"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ਆਡੀਓ ਸਟ੍ਰੀਮ ਦੀਆਂ ਸੈਟਿੰਗਾਂ"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ਆਡੀਓ ਸਟ੍ਰੀਮ ਦਾ QR ਕੋਡ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"ਕਨੈਕਟ ਕਰਨ ਲਈ QR ਕੋਡ ਸਕੈਨ ਕਰੋ"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ਆਡੀਓ ਸਟ੍ਰੀਮ ਨੂੰ ਸੁਣਨ ਲਈ, ਹੋਰ ਲੋਕ ਅਨੁਰੂਪ ਹੈੱਡਫ਼ੋਨਾਂ ਨੂੰ ਆਪਣੇ Android ਡੀਵਾਈਸ ਨਾਲ ਕਨੈਕਟ ਕਰ ਸਕਦੇ ਹਨ। ਉਹ ਫਿਰ ਇਸ QR ਕੋਡ ਨੂੰ ਸਕੈਨ ਕਰ ਸਕਦੇ ਹਨ।"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"ਬਲੂਟੁੱਥ ਜੋੜਾਬੱਧ ਕਰਨ ਦੀ ਬੇਨਤੀ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ਜੋੜਾਬੱਧ ਕਰੋ ਅਤੇ ਕਨੈਕਟ ਕਰੋ"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"ਬਲੂਟੁੱਥ ਜੋੜਾਬੱਧਕਰਨ ਕੋਡ"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"ਹੋਰ ਐਪਾਂ"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"ਸਿਸਟਮ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"ਕੁੱਲ %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"ਸਿਸਟਮ ਵਿੱਚ ਅਜਿਹੀਆਂ ਫ਼ਾਈਲਾਂ ਸ਼ਾਮਲ ਹਨ ਜੋ Android ਵਰਜਨ <xliff:g id="VERSION">%s</xliff:g> ਨੂੰ ਚਲਾਉਣ ਲਈ ਵਰਤੀਆਂ ਜਾਂਦੀਆਂ ਹਨ"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ਆਡੀਓ ਫ਼ਾਈਲਾਂ"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"ਗਣਨਾ ਕੀਤੀ ਜਾ ਰਹੀ ਹੈ…"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 18c114336..54013898e 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Połączenia samochodu z urządzeniami"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Łącze ultraszerokopasmowe (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Pomaga samochodowi wykrywać położenie urządzeń UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Udostępnianie dźwięku"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Udostępnij dźwięk"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Osoby słuchające muszą mieć własne słuchawki LE Audio."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Odtwórz dźwięk testowy"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Każda słuchająca osoba powinna to usłyszeć"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktywne urządzenia multimedialne"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Ustawienia strumienia audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Kod QR strumienia audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Aby się połączyć, zeskanuj kod QR"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Osoby, które także chcą posłuchać strumienia audio, muszą połączyć zgodne słuchawki ze swoim urządzeniem z Androidem, a potem zeskanować ten kod QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Prośba o sparowanie Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Sparuj i połącz"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kod parowania Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Inne aplikacje"</string>
     <string name="storage_files" msgid="6382081694781340364">"Pliki"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Łącznie %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"System uwzględnia pliki używane do uruchomienia Androida w wersji <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Pliki audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Obliczam…"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 793a88554..c756b2ad3 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Ligações do dispositivo com o carro"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultralarga (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Ajuda o carro a identificar a posição dos dispositivos de UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Partilha de áudio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Partilhar áudio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Os ouvintes precisam dos próprios auscultadores com LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Ouça um som de teste"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Todas as pessoas por perto podem ouvir"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispositivos multimédia ativos"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Definições da stream de áudio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Código QR da stream de áudio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Leia o código QR para fazer a ligação"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Para ouvir a stream de áudio, as outras pessoas podem ligar auscultadores compatíveis ao respetivo dispositivo Android. Em seguida, podem ler este código QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Pedido de sincronização de Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Sincronizar e ligar"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Código de sincronização Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Outras aplicações"</string>
     <string name="storage_files" msgid="6382081694781340364">"Ficheiros"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s no total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"O sistema inclui ficheiros utilizados para executar a versão <xliff:g id="VERSION">%s</xliff:g> do Android."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Ficheiros de áudio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"A calcular…"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index b6e2e66e2..530f569ab 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Conexões do dispositivo com seu carro"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Banda ultralarga (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Ajuda seu carro a identificar a posição de dispositivos UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Compartilhamento de áudio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Compartilhar áudio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"As pessoas precisam de fones de ouvido próprios com LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Reproduzir um teste de som"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Todas as pessoas conectadas devem ouvir"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispositivos portáteis de mídia ativos"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Configurações do stream de áudio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR code do stream de áudio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Faça a leitura do QR code para conectar"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Para ouvir o stream de áudio é preciso conectar fones compatíveis ao próprio dispositivo Android e ler o QR code abaixo."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Solicitação de pareamento Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Parear e conectar"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Código de pareamento Bluetooth"</string>
@@ -428,8 +438,8 @@
     <string name="modify_system_settings_description" msgid="5295023124419592452">"Permite que um app modifique configurações do sistema."</string>
     <string name="notification_access_title" msgid="1467340098885813473">"Acesso a notificações"</string>
     <string name="notification_listener_security_warning_title" msgid="2893273335175140895">"Permitir que <xliff:g id="SERVICE">%1$s</xliff:g> acesse as notificações?"</string>
-    <string name="notification_listener_security_warning_summary" msgid="7280197998063498125">"<xliff:g id="NOTIFICATION_LISTENER_NAME">%1$s</xliff:g> poderá ler todas as notificações, incluindo informações pessoais, como nomes de contato e o texto das mensagens que você recebe. Ele também poderá dispensar notificações ou ativar botões de ação que elas contenham.\n\nIsso também autoriza o app a ativar ou desativar o modo \"Não perturbe\" e alterar as configurações relacionadas."</string>
-    <string name="notification_listener_revoke_warning_summary" msgid="5960149609163649424">"Se você desativar o acesso a notificações para <xliff:g id="NOTIFICATION_LISTENER_NAME">%1$s</xliff:g>, é possível que o controle do Não perturbe também seja desativado."</string>
+    <string name="notification_listener_security_warning_summary" msgid="7280197998063498125">"<xliff:g id="NOTIFICATION_LISTENER_NAME">%1$s</xliff:g> poderá ler todas as notificações, incluindo informações pessoais, como nomes de contato e o texto das mensagens que você recebe. Ele também poderá dispensar notificações ou ativar botões de ação que elas contenham.\n\nIsso também autoriza o app a ativar ou desativar o modo não perturbe e alterar as configurações relacionadas."</string>
+    <string name="notification_listener_revoke_warning_summary" msgid="5960149609163649424">"Se você desativar o acesso a notificações para <xliff:g id="NOTIFICATION_LISTENER_NAME">%1$s</xliff:g>, é possível que o controle do não perturbe também seja desativado."</string>
     <string name="notification_listener_revoke_warning_confirm" msgid="2759583507454984812">"Desativar"</string>
     <string name="notification_listener_revoke_warning_cancel" msgid="4399941651358241154">"Cancelar"</string>
     <string name="performance_impacting_apps_description" msgid="7361464904617808444">"Esses apps prejudicam o desempenho do sistema e tiveram a execução em segundo plano impedida.\nPriorize o app para permitir o uso em segundo plano e o remover desta lista."</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Outros apps"</string>
     <string name="storage_files" msgid="6382081694781340364">"Arquivos"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistema"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Total: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"O sistema inclui arquivos usados para executar a versão <xliff:g id="VERSION">%s</xliff:g> do Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Arquivos de áudio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Calculando…"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 407c3625b..d8d93dc7f 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Conexiuni între dispozitive și mașină"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Bandă ultralargă (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Ajută mașina să identifice poziția dispozitivelor UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Permiterea accesului la audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Trimite audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Ascultătorii au nevoie de propriul set de căști LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Redă un sunet de test"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Toți cei care ascultă ar trebui să-l audă"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Dispozitive media active"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Setările streamului audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Codul QR al streamului audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Scanează codul QR pentru a te conecta"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Pentru a asculta streamul audio, alte persoane pot să conecteze căști compatibile la dispozitivul lor Android. Apoi pot să scaneze acest cod QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Solicitare de conectare prin Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Asociază și conectează"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Cod de conectare prin Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Alte aplicații"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fișiere"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s în total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistemul include fișiere folosite pentru a rula versiunea de Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Fișiere audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Se calculează…"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index d2907b426..c3bc804c3 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Устройства, подключенные к автомобилю"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Сверхширокая полоса (СШП)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Параметр помогает автомобилю определять, где находятся устройства, использующие СШП"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Передача аудио"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Передавать аудио"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Каждому пользователю нужны наушники с поддержкой LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Воспроизведение аудиообразца"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Звук должен быть слышен всем подключенным пользователям"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Активные медиаустройства"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Настройки аудиопотока"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-код аудиопотока"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Сканировать QR-код для подключения"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Чтобы слушать аудиопоток, другие пользователи могут подключить совместимые наушники к своему устройству Android, а затем отсканировать этот QR-код"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Запрос на подключение через Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Установить соединение и подключить"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Код подключения через Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Другие приложения"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файлы"</string>
     <string name="storage_system" msgid="1271345630248014010">"Система"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s всего"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"В разделе \"Система\" находятся файлы, используемые Android <xliff:g id="VERSION">%s</xliff:g>."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудиофайлы"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Подождите…"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 8a600f221..7f1a20cd3 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"ඔබේ මෝටර් රථය සමග උපාංග සම්බන්ධතා"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"අති-පුළුල් කලාප (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB උපාංගවල පිහිටීම හඳුනා ගැනීමට ඔබේ මෝටර් රථයට උදවු කරයි"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ශ්‍රව්‍ය බෙදා ගැනීම"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ශ්‍රව්‍ය බෙදා ගන්න"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"සවන්දෙන්නන්ට ඔවුන්ගේම LE ශ්‍රව්‍ය හෙඩ්ෆෝන් අවශ්‍යයි"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"පරීක්ෂණ ශබ්දයක් වාදනය කරන්න"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"සවන් දෙන සෑම කෙනෙකුටම එය ඇසිය යුතු ය"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"සක්‍රිය මාධ්‍ය උපාංග"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ශ්‍රව්‍ය ප්‍රවාහ සැකසීම්"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ශ්‍රව්‍ය ප්‍රවාහ QR කේතය"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"සම්බන්ධ වීමට QR කේතය ස්කෑන් කරන්න"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ශ්‍රව්‍ය ප්‍රවාහය වෙත සවන් දීමට, වෙනත් පුද්ගලයින්ට ඔවුන්ගේ Android උපාංගයට ගැළපෙන හෙඩ්ෆෝන් සම්බන්ධ කළ හැක. එවිට ඔවුන්ට මෙම QR කේතය ස්කෑන් කළ හැක."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"බ්ලූටූත් යුගලන ඉල්ලීම"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"යුගලනය සහ සබැඳීම"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"බ්ලූටූත් යුගල කේතය"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"වෙනත් යෙදුම්"</string>
     <string name="storage_files" msgid="6382081694781340364">"ගොනු"</string>
     <string name="storage_system" msgid="1271345630248014010">"පද්ධතිය"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s එකතුව"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Android අනුවාදය <xliff:g id="VERSION">%s</xliff:g> ධාවනයට භාවිත ගොනු පද්ධතියේ අඩංගුයි"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ශ්‍රව්‍ය ගොනු"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"ගණනය කරමින්…"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index ebae4d4fb..8020d2b67 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Pripojenia zariadenia k autu"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Pomáha autu rozpoznať umiestnenie zariadení UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Zdieľanie zvuku"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Zdieľať zvuk"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Poslucháči potrebujú vlastné slúchadlá podporujúce LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Prehranie testovacieho zvuku"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Počuť by ho mal každý poslucháč"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktívne mediálne zariadenia"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Nastavenia zvukového streamu"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR kód zvukového streamu"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Pripojte sa naskenovaním QR kódu"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Ak chcú ďalší ľudia počúvať zvukový stream, môžu k svojmu zariadeniu s Androidom pripojiť kompatibilné slúchadlá. Potom môžu naskenovať tento QR kód."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Žiadosť o párovanie zariadenia Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Párovať a pripojiť"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Párovací kód Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Ďalšie aplikácie"</string>
     <string name="storage_files" msgid="6382081694781340364">"Súbory"</string>
     <string name="storage_system" msgid="1271345630248014010">"Systém"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Celkove %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Systém obsahuje súbory používané na fungovanie Androidu verzie <xliff:g id="VERSION">%s</xliff:g>."</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Zvukové súbory"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Prebieha výpočet…"</string>
@@ -721,7 +732,7 @@
     <string name="lockpattern_recording_intro_header" msgid="7864149726033694408">"Nakreslite bezpečnostný vzor"</string>
     <string name="lockpattern_recording_inprogress" msgid="1575019990484725964">"Na záver zdvihnite prst z obrazovky"</string>
     <string name="lockpattern_pattern_entered" msgid="6103071005285320575">"Vzor bol zaznamenaný"</string>
-    <string name="lockpattern_need_to_confirm" msgid="4648070076022940382">"Znova nakreslite vzor pre potvrdenie"</string>
+    <string name="lockpattern_need_to_confirm" msgid="4648070076022940382">"Na potvrdenie nakreslite vzor ešte raz"</string>
     <string name="lockpattern_recording_incorrect_too_short" msgid="2417932185815083082">"Musíte spojiť aspoň 4 body. Skúste to znova."</string>
     <string name="lockpattern_pattern_wrong" msgid="929223969555399363">"Nesprávny vzor"</string>
     <string name="lockpattern_settings_help_how_to_record" msgid="4436556875843192284">"Ako kresliť bezpečnostný vzor obrazovky"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index eca727083..ef4b13a54 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Povezave naprav z avtomobilom"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Izjemno širok pas (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Avtomobilu pomaga določiti položaj naprav z izjemno širokim pasom (UWB)"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Deljenje zvoka"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Deli zvok"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Poslušalci potrebujejo svoje slušalke s funkcijo LE zvok"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Predvajanje preizkusnega zvoka"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Vsi poslušalci bi morali slišati zvok"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktivne predstavnostne naprave"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Nastavitve pretočnega predvajanja zvoka"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Koda QR za pretočno predvajanje zvoka"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Optično preberite kodo QR za povezovanje"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Za poslušanje pretočnega predvajanja zvoka lahko druge osebe povežejo združljive slušalke s svojo napravo Android. Nato lahko optično preberejo to kodo QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Zahteva za seznanitev naprave Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Seznanitev in povezava"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Koda za seznanitev naprave Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Druge aplikacije"</string>
     <string name="storage_files" msgid="6382081694781340364">"Datoteke"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s skupno"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistem vključuje datoteke, ki se uporabljajo za izvajanje Androida različice <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Zvočne datoteke"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Izračunavanje …"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 56d18aa99..3c26905b5 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Lidhjet e pajisjes me makinën tënde"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Brezi ultra i gjerë (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"E ndihmon makinën tënde të identifikojë pozicionin e pajisjeve UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Ndarja e audios"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Ndaj audion"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Dëgjuesit duhet të kenë kufjet e tyre me LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Luaj një tingull testimi"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Të gjithë dëgjuesit do ta dëgjojnë"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Pajisjet aktive të medias"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Cilësimet e transmetimit audio"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Kodi QR i transmetimit audio"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skano kodin QR për t\'u lidhur"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Për të dëgjuar transmetimin audio, të tjerët mund të lidhin kufje të përputhshme me pajisjen e tyre Android. Më pas ata mund të skanojnë këtë kod QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Kërkesë çiftimi me Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Ҫifto dhe lidh"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kodi i çiftimit të Bluetooth-it"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Aplikacionet e tjera"</string>
     <string name="storage_files" msgid="6382081694781340364">"Skedarët"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistemi"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s në total"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistemi përfshin skedarët që përdoren për ekzekutimin e versionit <xliff:g id="VERSION">%s</xliff:g> të Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Skedarët audio"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Po llogaritet…"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 402a9236f..c9e2e6cf5 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Повезивање уређаја са аутомобилом"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ултра-широки појас (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Помаже аутомобилу да идентификује позицију UWB уређаја"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Дељење звука"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Дели звук"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Слушаоци треба да користе своје LE Audio слушалице"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Пустите пробни звук"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Сви слушаоци би требало да чују"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Активни медијски уређаји"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Подешавања аудио стрима"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR кôд аудио стрима"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Скенирајте QR кôд да бисте се повезали"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Да би слушали аудио стрим, други људи могу да повежу компатибилне слушалице са Android уређајем. Затим могу да скенирају овај QR кôд."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Захтев за Bluetooth упаривање"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Упари и повежи"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Кôд за упаривање са Bluetooth уређајем"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Друге апликације"</string>
     <string name="storage_files" msgid="6382081694781340364">"Фајлови"</string>
     <string name="storage_system" msgid="1271345630248014010">"Систем"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Укупно: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Систем обухвата датотеке које се користе за покретање верзије Android-а <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудио датотеке"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Израчунава се…"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 0d1f3c6a0..4d4125274 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Enhetsanslutningar till bilen"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultrabredband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Hjälper bilen att identifiera UWB-enheters position"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Ljuddelning"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Dela ljud"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Lyssnare behöver sina egna LE Audio-hörlurar"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Spela upp ett testljud"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Alla som lyssnar bör höra det"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Aktiva medieenheter"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Inställningar för ljudstream"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-kod för ljudstream"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skanna QR-koden för att ansluta"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Andra som vill lyssna på ljudstreamen kan ansluta kompatibla hörlurar till sin Android-enhet. Sedan kan de skanna den här QR-koden."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Begäran om Bluetooth-koppling"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Parkoppla och anslut"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Kopplingskod för Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Andra appar"</string>
     <string name="storage_files" msgid="6382081694781340364">"Filer"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s totalt"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Systemet innehåller filer som används för att köra Android-versionen <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Ljudfiler"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Beräknas …"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index b2bb4b5f9..aabc441c7 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Miunganisho ya vifaa kwenye gari lako"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Bendi Pana Zaidi (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Husaidia gari lako litambue mahali vifaa vya Bendi Pana Zaidi (UWB) vilipo"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Kusikiliza Pamoja"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Sikiliza pamoja na wengine"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Wasikilizaji wanahitaji vipokea sauti vyao vya kichwani vinavyotumia LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Cheza sauti ya jaribio"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Kila mtu anayesikiliza anapaswa kuisikia"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Vifaa vinavyotumika"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Mipangilio ya mtiririko wa maudhui ya sauti"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Msimbo wa QR wa mtiririko wa maudhui ya sauti"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Changanua msimbo wa QR ili uunganishe"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Ili kusikiliza mtiririko wa maudhui ya sauti, watu wengine wanaweza kuunganisha vipokea sauti vya kichwani vinavyooana na vifaa vyao vya Android. Kisha wanaweza kuchanganua msimbo huu wa QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Ombi la kuoanisha Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Oanisha kisha uunganishe"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Msimbo wa kuoanisha Bluetooth"</string>
@@ -401,7 +411,7 @@
     <string name="auto_launch_reset_text" msgid="590439611312092392">"Futa chaguomsingi"</string>
     <string name="app_launch_open_domain_urls_title" msgid="4705344946367759393">"Fungua viungo vinavyoweza kutumika"</string>
     <string name="app_link_open_always" msgid="5783167184335545230">"Fungua katika programu hii"</string>
-    <string name="app_link_open_ask" msgid="7242075065136237456">"Uliza kila wakati"</string>
+    <string name="app_link_open_ask" msgid="7242075065136237456">"Omba kila wakati"</string>
     <string name="app_link_open_never" msgid="2173174327831792316">"Usifungue katika programu hii"</string>
     <string name="app_launch_supported_domain_urls_title" msgid="7345116365785981158">"Viungo vinavyoweza kutumika"</string>
     <string name="opening_links_verified_links_title" msgid="6781351697264180708">"Viungo vilivyothibitishwa"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Programu zingine"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"Mfumo"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Jumla ya %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Mfumo unajumuisha faili zinazotumika katika toleo la Android la <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Faili za sauti"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Inahesabu…"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 08b2caf50..5a0476bba 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"உங்கள் காருடனான சாதன இணைப்புகள்"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"அல்ட்ரா-வைடுபேண்ட் (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB சாதனங்களின் நிலையைக் கண்டறிய உங்கள் காருக்கு உதவும்"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ஆடியோ பகிர்வு"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ஆடியோவைப் பகிர்தல்"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ஆடியோ கேட்பவர்களிடம் LE ஆடியோ ஹெட்ஃபோன்கள் இருக்க வேண்டும்"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"பரிசோதனை ஒலியைப் பிளே செய்தல்"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ஆடியோவைக் கேட்கும் அனைவருக்கும் இந்த ஒலி கேட்க வேண்டும்"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"செயலிலுள்ள மீடியா சாதனங்கள்"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ஆடியோ ஸ்ட்ரீம் அமைப்புகள்"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ஆடியோ ஸ்ட்ரீம் QR குறியீடு"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"இணைக்க QR குறியீட்டை ஸ்கேன் செய்யுங்கள்"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ஆடியோ ஸ்ட்ரீமைக் கேட்க, பிறர் இணக்கமான ஹெட்ஃபோன்களைத் தங்கள் Android சாதனத்துடன் இணைக்கலாம். அதன்பிறகு அவர்கள் இந்த QR குறியீட்டை ஸ்கேன் செய்யலாம்."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"புளூடூத் இணைப்பிற்கான கோரிக்கை"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"ஜோடி சேர்த்து, இணை"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"புளூடூத் இணைத்தல் குறியீடு"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"பிற ஆப்ஸ்"</string>
     <string name="storage_files" msgid="6382081694781340364">"ஃபைல்கள்"</string>
     <string name="storage_system" msgid="1271345630248014010">"சிஸ்டம்"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"மொத்தம் %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Android <xliff:g id="VERSION">%s</xliff:g> பதிப்பை இயக்குவதற்குப் பயன்படுத்தப்படும் ஃபைல்களும் சிஸ்டத்தில் அடங்கும்"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ஆடியோ ஃபைல்கள்"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"கணக்கிடுகிறது…"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index be3089059..af478d019 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"మీ కారుతో పరికర కనెక్షన్‌లు"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"అల్ట్రా-వైడ్ బ్యాండ్ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB పరికరాల స్థానాలను గుర్తించడంలో మీ కారుకు సహాయపడుతుంది"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"ఆడియో షేరింగ్"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"ఆడియోను షేర్ చేయండి"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"లిజనర్స్‌కు వారి సొంత LE ఆడియో హెడ్‌ఫోన్స్ కావాలి"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"టెస్ట్ సౌండ్‌ను ప్లే చేయండి"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ఆడియో వింటున్న అందరూ దీనిని వింటారు"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"యాక్టివ్‌గా ఉన్న మీడియా డివైజ్‌లు"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"ఆడియో స్ట్రీమ్ సెట్టింగ్‌లు"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"ఆడియో స్ట్రీమ్ QR కోడ్"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"QR కోడ్‌ను స్కాన్ చేసి కనెక్ట్ చేయండి"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"ఆడియో స్ట్రీమ్‌ను వినడానికి, ఇతర యూజర్‌లు తమ Android డివైజ్‌కు అనుకూలమైన హెడ్‌ఫోన్స్‌ను కనెక్ట్ చేయవచ్చు. తర్వాత ఈ QR కోడ్‌ను స్కాన్ చేయవచ్చు."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"బ్లూటూత్ జత చేయడానికి రిక్వెస్ట్‌"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"జత చేసి, కనెక్ట్ చేయి"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"బ్లూటూత్ పెయిరింగ్ కోడ్"</string>
@@ -347,7 +357,7 @@
     <string name="unused_apps_summary" msgid="8257304516038923072">"{count,plural, =1{# ఉపయోగించని యాప్}other{# ఉపయోగించని యాప్‌లు}}"</string>
     <string name="unused_apps_switch" msgid="4433958286200341563">"అనుమతులను తీసివేసి స్పేస్‌ను ఖాళీ చేయండి"</string>
     <string name="aspect_ratio_label" msgid="5484863076085548807">"ఆకార నిష్పత్తి (ప్రయోగాత్మకం)"</string>
-    <string name="aspect_ratio_action_button" msgid="5581373962239508271">"తెరువు"</string>
+    <string name="aspect_ratio_action_button" msgid="5581373962239508271">"తెరవండి"</string>
     <string name="user_aspect_ratio_app_default" msgid="283669241296845522">"యాప్ ఆటోమేటిక్ సెట్టింగ్"</string>
     <string name="user_aspect_ratio_fullscreen" msgid="7558176135316113">"ఫుల్-స్క్రీన్"</string>
     <string name="user_aspect_ratio_half_screen" msgid="6294133158286722632">"సగం స్క్రీన్"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"ఇతర యాప్‌లు"</string>
     <string name="storage_files" msgid="6382081694781340364">"ఫైళ్లు"</string>
     <string name="storage_system" msgid="1271345630248014010">"సిస్టమ్"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"మొత్తం %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"సిస్టమ్‌లో Android వెర్షన్ <xliff:g id="VERSION">%s</xliff:g>ను రన్ చేయడానికి అవసరమైన ఫైళ్లు ఉంటాయి"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ఆడియో ఫైళ్లు"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"గణిస్తోంది…"</string>
@@ -925,7 +936,7 @@
     <string name="screen_reader_settings_title" msgid="4012734340987826872">"స్క్రీన్ రీడర్"</string>
     <string name="show_captions_toggle_title" msgid="710582308974826311">"క్యాప్షన్‌లను చూడండి"</string>
     <string name="captions_text_size_title" msgid="1960814652560877963">"టెక్స్ట్ సైజ్"</string>
-    <string name="captions_settings_style_header" msgid="944591388386054372">"క్యాప్షన్ సైజ్, స్టయిల్"</string>
+    <string name="captions_settings_style_header" msgid="944591388386054372">"క్యాప్షన్ సైజ్ &amp; స్టయిల్"</string>
     <string name="captions_settings_text_size_very_small" msgid="7476485317028306502">"చాలా చిన్నది"</string>
     <string name="captions_settings_text_size_small" msgid="1481895299805450566">"చిన్నది"</string>
     <string name="captions_settings_text_size_default" msgid="2227802573224038267">"ఆటోమేటిక్ సెట్టింగ్"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 8e8885579..84cf9a4b3 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -77,7 +77,7 @@
     <string name="data_usage_limit_dialog_mobile" msgid="3633960011913085089">"ระบบเครื่องเสียงของรถยนต์จะปิดอินเทอร์เน็ตมือถือเมื่อมีการใช้งานถึงขีดจำกัดที่คุณกำหนดไว้\n\nเนื่องจากนี่เป็นปริมาณการใช้อินเทอร์เน็ตที่วัดโดยระบบเครื่องเสียง ปริมาณการใช้งานที่ผู้ให้บริการวัดได้จึงอาจไม่เท่ากัน โปรดกำหนดขีดจำกัดอย่างระมัดระวัง"</string>
     <string name="data_usage_warning_editor_title" msgid="2041517150169038813">"ตั้งค่าคำเตือนปริมาณการใช้อินเทอร์เน็ต"</string>
     <string name="data_usage_limit_editor_title" msgid="133468242379286689">"ตั้งค่าขีดจำกัดปริมาณการใช้อินเทอร์เน็ต"</string>
-    <string name="data_usage_settings_footer" msgid="681881387909678237">"ปริมาณการใช้อินเทอร์เน็ตจะวัดโดยอุปกรณ์ ซึ่งอาจแตกต่างจากปริมาณอินเทอร์เน็ตของผู้ให้บริการเครือข่ายมือถือ"</string>
+    <string name="data_usage_settings_footer" msgid="681881387909678237">"ปริมาณการใช้อินเทอร์เน็ตจะวัดโดยอุปกรณ์ ซึ่งอาจแตกต่างจากปริมาณอินเทอร์เน็ตของผู้ให้บริการมือถือ"</string>
     <string name="usage_bytes_threshold_picker_positive_button" msgid="4625479840977965519">"ตั้งค่า"</string>
     <string name="data_usage_warning_save_title" msgid="2900544287239037695">"บันทึก"</string>
     <string name="network_and_internet_oem_network_title" msgid="6436902713696212250">"เครือข่าย OEM"</string>
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"การเชื่อมต่ออุปกรณ์กับรถของคุณ"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"แถบความถี่กว้างยิ่งยวด (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"ช่วยรถของคุณระบุตำแหน่งของอุปกรณ์ UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"การแชร์เสียง"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"แชร์เสียง"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"ผู้ฟังจำเป็นต้องมีหูฟังที่รองรับ LE Audio ของตนเอง"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"เล่นเสียงทดสอบ"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ทุกคนที่กำลังฟังอยู่ควรจะได้ยิน"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"อุปกรณ์สื่อที่ใช้งานอยู่"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"การตั้งค่าสตรีมเสียง"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"คิวอาร์โค้ดของสตรีมเสียง"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"สแกนคิวอาร์โค้ดเพื่อเชื่อมต่อ"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"บุคคลอื่นที่ต้องการฟังสตรีมเสียงสามารถเชื่อมต่อหูฟังที่รองรับการใช้งานเข้ากับอุปกรณ์ Android ของตน จากนั้นจึงสแกนคิวอาร์โค้ดนี้ได้"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"คำขอจับคู่อุปกรณ์บลูทูธ"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"จับคู่อุปกรณ์และเชื่อมต่อ"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"รหัสการจับคู่บลูทูธ"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"แอปอื่นๆ"</string>
     <string name="storage_files" msgid="6382081694781340364">"ไฟล์"</string>
     <string name="storage_system" msgid="1271345630248014010">"ระบบ"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"รวม %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"ระบบรวมไฟล์สำหรับเรียกใช้ Android เวอร์ชัน <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"ไฟล์เสียง"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"กำลังคำนวณ…"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 78b8ad633..1708bb918 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Mga koneksyon sa device sa kotse mo"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra‑Wideband (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Tumutulong sa kotse mo na matukoy ang posisyon ng mga UWB device"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Pag-share ng Audio"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"I-share ang audio"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Kailangan ng listener ng sarili nilang LE Audio headphones."</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Mag-play ng pansubok na tunog"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Dapat marinig ito ng lahat ng nakikinig"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Mga aktibong media device"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Mga setting ng audio stream"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR Code ng audio stream"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"I-scan ang QR code para kumonekta"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Para makinig sa audio stream, puwedeng magkonekta ang ibang tao ng compatible na headphones sa kanilang android device. Puwede nilang i-scan ang QR code na ito."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Kahilingan sa pagpapares ng Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Ipares at kumonekta"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Code ng pagpapares ng Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Iba pang app"</string>
     <string name="storage_files" msgid="6382081694781340364">"Mga File"</string>
     <string name="storage_system" msgid="1271345630248014010">"System"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"%s sa kabuuan"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"May mga file ang system na ginagamit para patakbuhin ang bersyon <xliff:g id="VERSION">%s</xliff:g> ng Android"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Mga audio file"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Kinakalkula…"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 735af42cb..e5d905e05 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Arabanıza bağlı cihazlar"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra geniş bant (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Arabanızın ultra geniş banda sahip cihazların konumlarını belirlemesine yardımcı olur"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Ses Paylaşımı"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Sesi paylaş"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Dinleyen kullanıcıların da LE Audio kulaklığı olması gerekir"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Test sesi çal"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Dinleyen herkes duyabilir"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Etkin medya cihazları"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Ses yayını ayarları"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Ses yayını QR kodu"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Bağlanmak için QR kodunu tarayın"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Diğer kullanıcılar, ses yayınını dinlemek için uyumlu kulaklıkları Android cihazlarına bağlayabilir ve bu QR kodunu tarayabilir."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth eşleme isteği"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Eşleştir ve bağlan"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth eşleme kodu"</string>
@@ -505,7 +515,7 @@
     <string name="contributors_title" msgid="7698463793409916113">"Katkıda bulunanlar"</string>
     <string name="manual" msgid="4819839169843240804">"Manuel"</string>
     <string name="regulatory_labels" msgid="3165587388499646779">"Yönetmelik etiketleri"</string>
-    <string name="safety_and_regulatory_info" msgid="1204127697132067734">"Güvenlik ve yönetmelik kılavuzu"</string>
+    <string name="safety_and_regulatory_info" msgid="1204127697132067734">"Güvenlik ve yasal düzenleme kılavuzu"</string>
     <string name="copyright_title" msgid="4220237202917417876">"Telif hakkı"</string>
     <string name="license_title" msgid="936705938435249965">"Lisans"</string>
     <string name="terms_title" msgid="5201471373602628765">"Şartlar ve koşullar"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Diğer uygulamalar"</string>
     <string name="storage_files" msgid="6382081694781340364">"Dosyalar"</string>
     <string name="storage_system" msgid="1271345630248014010">"Sistem"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Toplam %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Sistem, Android <xliff:g id="VERSION">%s</xliff:g> sürümünü çalıştırmak için kullanılan dosyaları içeriyor"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Ses dosyaları"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Hesaplanıyor…"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 2bb4ad70d..4184c3214 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"З’єднання пристроїв з автомобілем"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Надширокосмуговий зв’язок (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Допомагає автомобілю визначати розташування пристроїв із підтримкою UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Надсилання аудіо"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Поділитись аудіо"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Слухачам потрібно мати власні навушники LE Audio"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Перевірте звук"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Усі, хто слухає, зможуть чути його"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Активні носії"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Налаштування аудіопотоку"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"QR-код аудіопотоку"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Сканувати QR-код, щоб підключитися"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Щоб слухати аудіопотік, інші користувачі можуть підключити сумісні навушники до свого пристрою Android, а тоді відсканувати цей QR-код."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Запит Bluetooth на створення пари"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Створити пару та підключитися"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Код підключення Bluetooth"</string>
@@ -504,7 +514,7 @@
     <string name="legal_information" msgid="1838443759229784762">"Правова інформація"</string>
     <string name="contributors_title" msgid="7698463793409916113">"Співавтори"</string>
     <string name="manual" msgid="4819839169843240804">"Посібник"</string>
-    <string name="regulatory_labels" msgid="3165587388499646779">"Сертифікації"</string>
+    <string name="regulatory_labels" msgid="3165587388499646779">"Нормативні етикетки"</string>
     <string name="safety_and_regulatory_info" msgid="1204127697132067734">"Посібник із безпеки й нормативних вимог"</string>
     <string name="copyright_title" msgid="4220237202917417876">"Авторські права"</string>
     <string name="license_title" msgid="936705938435249965">"Ліцензія"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Інші додатки"</string>
     <string name="storage_files" msgid="6382081694781340364">"Файли"</string>
     <string name="storage_system" msgid="1271345630248014010">"Система"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Усього: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"У розділі \"Система\" містяться файли, потрібні для роботи Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Аудіофайли"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Обчислення…"</string>
@@ -834,8 +845,8 @@
     <string name="add_device_admin" msgid="7674707256074840333">"Активувати цей додаток інформаційно-розважальної системи"</string>
     <string name="deactivate_and_uninstall_device_admin" msgid="596399938769951696">"Вимкнути й видалити"</string>
     <string name="remove_device_admin" msgid="3595343390502030723">"Деактивувати цей додаток інформаційно-розважальної системи"</string>
-    <string name="admin_profile_owner_message" msgid="8361351256802954556">"Адміністратор організації може відстежувати додатки й дані, пов’язані з цим профілем, зокрема налаштування, дозволи, корпоративний доступ, дії в мережі й дані про місцезнаходження транспортного засобу, а також керувати ними."</string>
-    <string name="admin_profile_owner_user_message" msgid="366072696508275753">"Адміністратор організації може відстежувати додатки й дані, пов’язані з цим профілем, зокрема налаштування, дозволи, корпоративний доступ, дії в мережі й дані про місцезнаходження пристрою, а також керувати ними."</string>
+    <string name="admin_profile_owner_message" msgid="8361351256802954556">"Адміністратор організації може відстежувати додатки й дані, пов’язані із цим профілем, зокрема налаштування, дозволи, корпоративний доступ, дії в мережі й дані про місцезнаходження транспортного засобу, а також керувати ними."</string>
+    <string name="admin_profile_owner_user_message" msgid="366072696508275753">"Адміністратор організації може відстежувати додатки й дані, пов’язані із цим профілем, зокрема налаштування, дозволи, корпоративний доступ, дії в мережі й дані про місцезнаходження пристрою, а також керувати ними."</string>
     <string name="admin_device_owner_message" msgid="896530502350904835">"Адміністратор організації може відстежувати додатки й дані, пов’язані з цією інформаційно-розважальною системою, зокрема налаштування, дозволи, корпоративний доступ, дії в мережі й дані про місцезнаходження транспортного засобу, а також керувати ними."</string>
     <string name="admin_financed_message" msgid="7357397436233684082">"Адміністратор організації може мати доступ до даних, пов’язаних з цією інформаційно-розважальною системою, керувати додатками й змінювати налаштування цього транспортного засобу."</string>
     <string name="disabled_by_policy_title" msgid="1121694702115232518">"Немає доступу"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 9ed5ddd4c..f4c8905b4 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"آپ کی کار کے ساتھ آلے کے کنکشنز"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"الٹرا وائڈ بینڈ (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"UWB آلات کی پوزیشن کی شناخت میں آپ کی کار کی مدد کرتا ہے"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"آڈیو کا اشتراک"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"آڈیو کا اشتراک کریں"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"سامعین کو ان کے اپنے LE آڈیو ہیڈ فونز کی ضرورت ہے"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"ٹیسٹ ساؤنڈ چلائیں"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"ہر سننے والے کو یہ سنائی دینا چاہیے"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"فعال میڈیا آلات"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"آڈیو سلسلہ کی ترتیبات"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"آڈیو سلسلے کا QR کوڈ"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"منسلک کرنے کیلئے QR کوڈ اسکین کریں"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"آڈیو سلسلہ سننے کے لئے دوسرے لوگ موافق ہیڈ فونز کو اپنے Android آلہ سے منسلک کر سکتے ہیں۔ پھر وہ اس QR کوڈ کو اسکین کر سکتے ہیں۔"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"بلوٹوتھ جوڑا بنانے کی درخواست"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"جوڑا بنائیں اور منسلک کریں"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"بلوٹوتھ جوڑا بنانے کا کوڈ"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"دیگر ایپس"</string>
     <string name="storage_files" msgid="6382081694781340364">"فائلیں"</string>
     <string name="storage_system" msgid="1271345630248014010">"سسٹم"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"کل ‎%s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"سسٹم میں Android ورژن <xliff:g id="VERSION">%s</xliff:g> چلانے کے لیے استعمال کی جانے والی فائلیں شامل ہیں"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"آڈیو فائلز"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"حساب لگایا جا رہا ہے…"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 7a8804d0c..17484587d 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Avtomobil bilan qurilma ulanishi"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Ultra keng polosali aloqa (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Avtomobilga UWB qurilmalari joylashishini aniqlashga yordam beradi"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Audio ulashuvi"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Audioni ulashish"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Har bir tinglovchida LE Audio xususiyatli quloqliklar boʻlishi kerak"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Tovushni tekshirish"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Ulangan barcha foydalanuvchilar eshitadi"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Faol media qurilmalar"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Audio oqim sozlamalari"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Audio oqim QR kodi"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Ulanish uchun QR kodni skanerlang"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Audio oqimni tinglash uchun boshqa foydalanuvchilar shaxsiy Android qurilmalariga mos quloqliklarni ulashi mumkin. Keyin bu QR kodni skanerlash kifoya."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Bluetooth orqali ulanish so‘rovi"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Juftlash va ulash"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Bluetooth orqali ulanish kodi"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Boshqa ilovalar"</string>
     <string name="storage_files" msgid="6382081694781340364">"Fayllar"</string>
     <string name="storage_system" msgid="1271345630248014010">"Tizim"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"jami: %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Tizim rukniga Android <xliff:g id="VERSION">%s</xliff:g> uchun zarur fayllar kiradi"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Audio fayllar"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Hisoblanmoqda…"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 4d1d2460a..5cf4d4496 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Kết nối giữa các thiết bị với ô tô"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"Băng tần siêu rộng (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Giúp ô tô xác định được vị trí của các thiết bị UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Chia sẻ âm thanh"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Chia sẻ âm thanh"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Người nghe cần có tai nghe Âm thanh năng lượng thấp riêng"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Phát thử âm thanh"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Tất cả những ai đang nghe đều sẽ nghe thấy"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Thiết bị đa phương tiện đang hoạt động"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Cài đặt luồng âm thanh"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Mã QR của luồng âm thanh"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Quét mã QR để kết nối"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Để nghe luồng âm thanh, những người khác có thể kết nối tai nghe tương thích với thiết bị Android của họ, rồi quét mã QR này."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Yêu cầu ghép nối Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Ghép nối và kết nối"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Mã ghép nối Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Ứng dụng khác"</string>
     <string name="storage_files" msgid="6382081694781340364">"Tệp"</string>
     <string name="storage_system" msgid="1271345630248014010">"Hệ thống"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Tổng cộng %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Hệ thống bao gồm các tệp được dùng để chạy phiên bản Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Tệp âm thanh"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Đang tính toán..."</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 7b60b8b34..8c13cc993 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -21,7 +21,7 @@
     <string name="more_settings_label" msgid="3867559443480110616">"更多"</string>
     <string name="display_settings" msgid="5325515247739279185">"显示"</string>
     <string name="brightness" msgid="2919605130898772866">"亮度"</string>
-    <string name="auto_brightness_title" msgid="9124647862844666581">"自适应亮度"</string>
+    <string name="auto_brightness_title" msgid="9124647862844666581">"自动调节亮度"</string>
     <string name="auto_brightness_summary" msgid="2002570577219479702">"根据环境调节屏幕亮度"</string>
     <string name="theme_toggle_title" msgid="7091393596274709558">"主题"</string>
     <string name="condition_night_display_title" msgid="3777509730126972675">"夜间光效已开启"</string>
@@ -164,7 +164,7 @@
     <string name="wifi_ap_band_select_one" msgid="615578175244067396">"请为 WLAN 热点至少选择一个频段："</string>
     <string name="tether_settings_title_all" msgid="6076625733772210734">"WLAN 热点"</string>
     <string name="hotspot_settings_title" msgid="8220814387592756713">"热点"</string>
-    <string name="wifi_hotspot_switch_title" msgid="5011183846278097937">"使用 WLAN 热点"</string>
+    <string name="wifi_hotspot_switch_title" msgid="5011183846278097937">"启用 WLAN 热点"</string>
     <string name="wifi_hotspot_state_off" msgid="6096709579204322798">"已关闭"</string>
     <string name="wifi_hotspot_keep_on_title" msgid="2920327805105370804">"在每次驾车时使用热点"</string>
     <string name="wifi_hotspot_keep_on_summary" msgid="7701814310702163462">"让热点在每次驾车时都可供使用"</string>
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"设备与您汽车间的连接"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"超宽带 (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"帮助您的汽车识别 UWB 设备的位置"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"音频分享"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"分享音频"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"收听者需要自备 LE 音频耳机"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"播放测试音"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"所有收听者应该都能听到"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"使用中的媒体设备"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"音频流设置"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"音频流二维码"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"扫描二维码即可连接"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"若要收听音频流内容，其他人可以将兼容耳机连接到自己的 Android 设备，然后扫描此二维码。"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"蓝牙配对请求"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"配对和连接"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"蓝牙配对码"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"其他应用"</string>
     <string name="storage_files" msgid="6382081694781340364">"文件"</string>
     <string name="storage_system" msgid="1271345630248014010">"系统"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"总共 %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"“系统”中包含用于运行 Android 版本 <xliff:g id="VERSION">%s</xliff:g> 的文件"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"音频文件"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"正在计算…"</string>
@@ -774,7 +785,7 @@
     <string name="lockpassword_password_too_long" msgid="1709616257350671045">"{count,plural, =1{必须少于 # 个字符}other{必须少于 # 个字符}}"</string>
     <string name="lockpassword_pin_too_long" msgid="8315542764465856288">"{count,plural, =1{必须少于 # 位数}other{必须少于 # 位数}}"</string>
     <string name="lockpassword_pin_no_sequential_digits" msgid="6511579896796310956">"禁止使用以升序、降序或重复序列排列的一串数字"</string>
-    <string name="setup_lock_settings_options_button_label" msgid="3337845811029780896">"屏幕解锁方式"</string>
+    <string name="setup_lock_settings_options_button_label" msgid="3337845811029780896">"屏锁方式"</string>
     <string name="credentials_reset" msgid="873900550885788639">"清除凭据"</string>
     <string name="credentials_reset_summary" msgid="6067911547500459637">"移除所有证书"</string>
     <string name="credentials_reset_hint" msgid="3459271621754137661">"要移除所有内容吗？"</string>
@@ -925,7 +936,7 @@
     <string name="screen_reader_settings_title" msgid="4012734340987826872">"屏幕阅读器"</string>
     <string name="show_captions_toggle_title" msgid="710582308974826311">"显示字幕"</string>
     <string name="captions_text_size_title" msgid="1960814652560877963">"文字大小"</string>
-    <string name="captions_settings_style_header" msgid="944591388386054372">"字幕文字大小和样式"</string>
+    <string name="captions_settings_style_header" msgid="944591388386054372">"字幕大小和样式"</string>
     <string name="captions_settings_text_size_very_small" msgid="7476485317028306502">"超小"</string>
     <string name="captions_settings_text_size_small" msgid="1481895299805450566">"小"</string>
     <string name="captions_settings_text_size_default" msgid="2227802573224038267">"默认"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 72dda9748..c00a6ee7d 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"汽車的裝置連接"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"超寬頻 (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"協助你的汽車識別 UWB 裝置位置"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"音訊分享功能"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"分享音訊"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"收聽者需要使用自己的 LE Audio 耳機"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"播放測試音效"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"所有收聽者均聽到此音效"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"有效的媒體裝置"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"音訊串流設定"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"音訊串流 QR 碼"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"掃瞄 QR 碼以連接"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"如要收聽音訊串流，其他人只需將兼容耳機連接至 Android 裝置，然後掃瞄此 QR 碼便可。"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"藍牙配對要求"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"配對並連線"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"藍牙配對碼"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"其他應用程式"</string>
     <string name="storage_files" msgid="6382081694781340364">"Files"</string>
     <string name="storage_system" msgid="1271345630248014010">"系統"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"總 %s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"「系統」包含用來執行 Android <xliff:g id="VERSION">%s</xliff:g> 版本的檔案"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"音訊檔案"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"正在計算…"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 83cead9dd..89c5fca71 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"車輛與裝置間的連結"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"超寬頻 (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"協助車輛判斷 UWB 裝置的位置"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"音訊分享"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"分享音訊"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"聆聽者需要使用自己的 LE Audio 耳機"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"播放測試音效"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"所有聆聽者應該都聽得到"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"有效的媒體裝置"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"音訊串流設定"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"音訊串流 QR code"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"掃描 QR code 即可連線"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"如要聆聽音訊串流，其他使用者只要將相容耳機連線到 Android 裝置，再掃描這個 QR code 即可。"</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"藍牙配對要求"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"配對並連線"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"藍牙配對碼"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"其他應用程式"</string>
     <string name="storage_files" msgid="6382081694781340364">"檔案"</string>
     <string name="storage_system" msgid="1271345630248014010">"系統"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"總空間：%s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"「系統」中包含用來執行 Android <xliff:g id="VERSION">%s</xliff:g> 版的檔案"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"音訊檔案"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"計算中…"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 616332e27..747cc244d 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -219,6 +219,16 @@
     <string name="device_connections_category_title" msgid="1753729363581927505">"Uxhumano lwedivayisi nemoto yakho"</string>
     <string name="uwb_toggle_title" msgid="8831695790040626922">"I-Ultra‑WideBand (UWB)"</string>
     <string name="uwb_toggle_summary" msgid="2206513296288659105">"Isiza imoto yakho ibone indawo yamadivayisi e-UWB"</string>
+    <string name="bluetooth_audio_sharing" msgid="5886869395645761760">"Ukwabelana Ngokuqoshiwe"</string>
+    <string name="share_audio_switch_title" msgid="8798673733841544186">"Yabelana ngomsindo"</string>
+    <string name="share_audio_switch_summary" msgid="5123598607194828495">"Abalaleli badinga ama-headphone abo omsindo we-LE"</string>
+    <string name="share_audio_test_sound_title" msgid="7570329148373530884">"Dlala umsindo wokuhlola"</string>
+    <string name="share_audio_test_sound_summary" msgid="7071332264787908147">"Wonke umuntu olalele kumele ayizwe"</string>
+    <string name="audio_sharing_active_media_devices" msgid="3845107517790253262">"Amadivayisi asebenzayo abezindaba"</string>
+    <string name="audio_stream_settings_category_title" msgid="4274632745953092854">"Amasethingi okusakaza komsindo"</string>
+    <string name="audio_streaming_title" msgid="174897810502966132">"Ikhodi ye-QR yokusakaza komsindo"</string>
+    <string name="scan_qr_code_to_connect" msgid="734470733189688139">"Skena ikhodi ye-QR ukuze uxhumeke"</string>
+    <string name="audio_stream_qr_code_description" msgid="7809312868707708527">"Ukuze balalele ukusakaza komsindo, abanye abantu bangaxhuma ama-headphone ahambisanayo edivayisini yabo ye-Android. Bese bangaskena le khodi ye-QR."</string>
     <string name="bluetooth_notif_ticker" msgid="7192577740198156792">"Isicelo sokubhanqa i-Bluetooth"</string>
     <string name="bluetooth_device_context_pair_connect" msgid="3138105800372470422">"Pheya futhi uxhume"</string>
     <string name="bluetooth_pairing_key_msg" msgid="5066825929751599037">"Ikhodi yokumatanisa ye-Bluetooth"</string>
@@ -622,6 +632,7 @@
     <string name="storage_other_apps" msgid="945509804756782640">"Ezinye izinhlelo zokusebenza"</string>
     <string name="storage_files" msgid="6382081694781340364">"Amafayela"</string>
     <string name="storage_system" msgid="1271345630248014010">"Isistimu"</string>
+    <string name="storage_total_label" msgid="5055933048275837265">"Isamba sika-%s"</string>
     <string name="storage_detail_dialog_system" msgid="796365720531622361">"Isistimu ibandakanya amafayela asetshenziswe ukusebenzisa inguqulo ye-Android <xliff:g id="VERSION">%s</xliff:g>"</string>
     <string name="storage_audio_files_title" msgid="5183170457027181700">"Amafayela omsindo"</string>
     <string name="memory_calculating_size" msgid="1672238502950390033">"Iyabala…"</string>
diff --git a/res/values/attrs.xml b/res/values/attrs.xml
index f3ffe7edc..63b6c7ff2 100644
--- a/res/values/attrs.xml
+++ b/res/values/attrs.xml
@@ -145,4 +145,5 @@
     <attr name="topLevelPreferenceCornerRadius" format="dimension"/>
     <attr name="wifiTetherQrCodeRoundedCornerRadius" format="dimension"/>
     <attr name="wifiDetailsShareRoundedCornerRadius" format="dimension"/>
+    <attr name="audioSharingQrCodeRoundedCornerRadius" format="dimension"/>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 29102fcda..11c1dc37e 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -72,6 +72,7 @@
     <dimen name="bluetooth_bonded_device_border_width">2dp</dimen>
     <dimen name="bluetooth_device_icon_size">44dp</dimen>
     <dimen name="bluetooth_device_foreground_icon_inset">8dp</dimen>
+    <dimen name="bluetooth_audio_streaming_qr_code_size">256dp</dimen>
 
     <!-- Display -->
     <dimen name="theme_toggle_button_size">72dp</dimen>
diff --git a/res/values/ids.xml b/res/values/ids.xml
index e8e5a8677..41d1465a4 100644
--- a/res/values/ids.xml
+++ b/res/values/ids.xml
@@ -22,6 +22,4 @@
 
     <!-- ID for the selected item in the ringtone picker -->
     <item type="id" name="ringtone_picker_selected_id"/>
-    <!-- ID key for tagging whether a preference is highlighted or not -->
-    <item type="id" name="preference_highlighted" />
 </resources>
diff --git a/res/values/overlayable.xml b/res/values/overlayable.xml
index d0aa91bc1..f4c6c9985 100644
--- a/res/values/overlayable.xml
+++ b/res/values/overlayable.xml
@@ -51,6 +51,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="attr" name="action_item_two"/>
       <item type="attr" name="action_item_two_enabled"/>
       <item type="attr" name="action_item_two_shown"/>
+      <item type="attr" name="audioSharingQrCodeRoundedCornerRadius"/>
       <item type="attr" name="bluetoothBondedDeviceButtonRadius"/>
       <item type="attr" name="bluetoothBondedDevicePreferenceToggleButtonRadius"/>
       <item type="attr" name="controller"/>
@@ -192,6 +193,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="aspect_ratio_icon_height"/>
       <item type="dimen" name="aspect_ratio_icon_width"/>
       <item type="dimen" name="block_by_admin_icon_padding"/>
+      <item type="dimen" name="bluetooth_audio_streaming_qr_code_size"/>
       <item type="dimen" name="bluetooth_bonded_device_border_width"/>
       <item type="dimen" name="bluetooth_bonded_device_button_size"/>
       <item type="dimen" name="bluetooth_bonded_device_foreground_icon_inset"/>
@@ -335,6 +337,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="drawable" name="ic_arrow_drop_down"/>
       <item type="drawable" name="ic_arrow_forward"/>
       <item type="drawable" name="ic_audio_navi"/>
+      <item type="drawable" name="ic_audio_sharing"/>
       <item type="drawable" name="ic_backspace"/>
       <item type="drawable" name="ic_block"/>
       <item type="drawable" name="ic_blocked_by_admin"/>
@@ -369,6 +372,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="drawable" name="ic_launcher_settings_foreground"/>
       <item type="drawable" name="ic_lock"/>
       <item type="drawable" name="ic_media_stream"/>
+      <item type="drawable" name="ic_music_cast"/>
       <item type="drawable" name="ic_open"/>
       <item type="drawable" name="ic_ota_update_current"/>
       <item type="drawable" name="ic_ota_update_none"/>
@@ -453,6 +457,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="drawable" name="ic_units"/>
       <item type="drawable" name="ic_uwb"/>
       <item type="drawable" name="ic_video_settings"/>
+      <item type="drawable" name="ic_volume_up"/>
       <item type="drawable" name="ic_warning"/>
       <item type="drawable" name="ic_wifi_signal_0"/>
       <item type="drawable" name="ic_wifi_signal_1"/>
@@ -471,12 +476,11 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="drawable" name="profile_avatar_bg_circle"/>
       <item type="drawable" name="restricted_wifi_signal"/>
       <item type="drawable" name="theme_toggle_button_rotary_background"/>
-      <item type="drawable" name="top_level_preference_background"/>
-      <item type="drawable" name="top_level_preference_highlight"/>
       <item type="drawable" name="user_disclaimer_action_button_background"/>
       <item type="drawable" name="wifi_signal"/>
       <item type="id" name="action_text"/>
       <item type="id" name="alphanumeric_pin"/>
+      <item type="id" name="audio_sharing_qr_code"/>
       <item type="id" name="bottomDivider"/>
       <item type="id" name="button1"/>
       <item type="id" name="button1Icon"/>
@@ -558,7 +562,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="id" name="phonebook_sharing_message_entry_pin"/>
       <item type="id" name="pin_pad"/>
       <item type="id" name="pin_values_hint"/>
-      <item type="id" name="preference_highlighted"/>
       <item type="id" name="profile_avatar"/>
       <item type="id" name="profile_grid"/>
       <item type="id" name="profile_name"/>
@@ -619,6 +622,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="integer" name="recent_notifications_days_threshold"/>
       <item type="integer" name="user_switcher_num_col"/>
       <item type="layout" name="action_buttons_preference"/>
+      <item type="layout" name="audio_sharing_device_selector_preference_group"/>
+      <item type="layout" name="audio_stream_qr_preference"/>
       <item type="layout" name="bluetooth_pin_confirm"/>
       <item type="layout" name="bluetooth_pin_entry"/>
       <item type="layout" name="car_setting_activity"/>
@@ -772,6 +777,10 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="audio_route_dialog_neutral_button_text"/>
       <item type="string" name="audio_route_selector_title"/>
       <item type="string" name="audio_route_selector_toast"/>
+      <item type="string" name="audio_sharing_active_media_devices"/>
+      <item type="string" name="audio_stream_qr_code_description"/>
+      <item type="string" name="audio_stream_settings_category_title"/>
+      <item type="string" name="audio_streaming_title"/>
       <item type="string" name="auto_brightness_summary"/>
       <item type="string" name="auto_brightness_title"/>
       <item type="string" name="auto_launch_disable_text"/>
@@ -798,6 +807,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="bluetooth_ask_enablement_and_discovery"/>
       <item type="string" name="bluetooth_ask_enablement_and_discovery_no_name"/>
       <item type="string" name="bluetooth_ask_enablement_no_name"/>
+      <item type="string" name="bluetooth_audio_sharing"/>
       <item type="string" name="bluetooth_available_devices"/>
       <item type="string" name="bluetooth_bonded_bluetooth_toggle_content_description"/>
       <item type="string" name="bluetooth_bonded_media_toggle_content_description"/>
@@ -1403,6 +1413,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="runtime_permissions_summary_no_permissions_granted"/>
       <item type="string" name="runtime_permissions_summary_no_permissions_requested"/>
       <item type="string" name="safety_and_regulatory_info"/>
+      <item type="string" name="scan_qr_code_to_connect"/>
       <item type="string" name="screen_lock_options"/>
       <item type="string" name="screen_reader_description_title"/>
       <item type="string" name="screen_reader_options_title"/>
@@ -1427,6 +1438,10 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="settings_license_activity_unavailable"/>
       <item type="string" name="setup_lock_settings_options_button_label"/>
       <item type="string" name="seven"/>
+      <item type="string" name="share_audio_switch_summary"/>
+      <item type="string" name="share_audio_switch_title"/>
+      <item type="string" name="share_audio_test_sound_summary"/>
+      <item type="string" name="share_audio_test_sound_title"/>
       <item type="string" name="share_remote_bugreport_action"/>
       <item type="string" name="share_remote_bugreport_dialog_message"/>
       <item type="string" name="share_remote_bugreport_dialog_message_finished"/>
@@ -1473,6 +1488,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="storage_type_internal"/>
       <item type="string" name="storage_unmount_failure"/>
       <item type="string" name="storage_unmount_success"/>
+      <item type="string" name="storage_total_label"/>
       <item type="string" name="suggestion_dismiss_button"/>
       <item type="string" name="sync_button_sync_cancel"/>
       <item type="string" name="sync_button_sync_now"/>
@@ -1740,6 +1756,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="xml" name="applications_settings_fragment"/>
       <item type="xml" name="apps_fragment"/>
       <item type="xml" name="assistant_and_voice_fragment"/>
+      <item type="xml" name="audio_sharing_fragment"/>
+      <item type="xml" name="audio_stream_fragment"/>
       <item type="xml" name="bluetooth_device_details_fragment"/>
       <item type="xml" name="bluetooth_device_picker_fragment"/>
       <item type="xml" name="bluetooth_pairing_selection_fragment"/>
diff --git a/res/values/preference_keys.xml b/res/values/preference_keys.xml
index ab54ed6e3..65f44cf40 100644
--- a/res/values/preference_keys.xml
+++ b/res/values/preference_keys.xml
@@ -33,6 +33,15 @@
     <string name="pk_bluetooth_extra_settings" translatable="false">bluetooth_extra_settings
     </string>
     <string name="pk_uwb_key" translatable="false">uwb_setting</string>
+    <string name="pk_bluetooth_audio_sharing" translatable="false">bluetooth_audio_sharing</string>
+    <string name="pk_share_audio_switch" translatable="false">share_audio_switch</string>
+    <string name="pk_share_audio_test_sound" translatable="false">share_audio_test_sound</string>
+    <string name="pk_audio_sharing_active_media_devices" translatable="false">audio_sharing_active_media_devices</string>
+    <string name="pk_audio_stream_settings" translatable="false">audio_stream_settings</string>
+    <string name="pk_audio_stream_device_selector" translatable="false">audio_stream_device_selector</string>
+    <string name="pk_audio_sharing_audio_stream" translatable="false">pk_audio_sharing_audio_stream</string>
+    <string name="pk_audio_stream_qr_code_description" translatable="false">pk_audio_stream_qr_code_description</string>
+    <string name="pk_audio_stream_qr_code" translatable="false">pk_audio_stream_qr_code</string>
     <string name="pk_location_settings_entry" translatable="false">location_settings_entry</string>
     <string name="pk_notifications_settings_entry" translatable="false">
         notifications_settings_entry
@@ -470,6 +479,7 @@
 
     <!-- Sound Settings -->
     <string name="pk_audio_destination" translatable="false">audio_destination</string>
+    <string name="pk_audio_destination_new" translatable="false">audio_destination_new</string>
     <string name="pk_volume_settings" translatable="false">volume_settings</string>
     <string name="pk_default_ringtone" translatable="false">default_ringtone</string>
     <string name="pk_default_notification" translatable="false">default_notification</string>
diff --git a/res/values/preference_screen_keys.xml b/res/values/preference_screen_keys.xml
index 33509f330..a98085c8f 100644
--- a/res/values/preference_screen_keys.xml
+++ b/res/values/preference_screen_keys.xml
@@ -37,6 +37,9 @@
     <string name="psk_bluetooth_device_picker" translatable="false">bluetooth_device_picker_screen</string>
     <string name="psk_bluetooth_pairing_selection" translatable="false">bluetooth_pairing_selection_screen</string>
     <string name="psk_bluetooth_settings" translatable="false">bluetooth_settings_screen</string>
+    <string name="psk_audio_sharing" translatable="false">audio_sharing_screen</string>
+    <string name="psk_audio_streaming" translatable="false">audio_streaming_screen</string>
+    <string name="psk_audio_route_selecting" translatable="false">audio_route_selecting_screen</string>
     <string name="psk_camera_settings" translatable="false">camera_settings_screen</string>
     <string name="psk_camera_recent_requests" translatable="false">camera_recent_requests_screen</string>
     <string name="psk_child_locale_picker" translatable="false">child_locale_picker_screen</string>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index b27adc747..05612ec52 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -458,7 +458,26 @@
     <string name="uwb_toggle_title">Ultra\u2011Wideband &#40;UWB&#41;</string>
     <!-- Summary of the UWB toggle [CHAR LIMIT=NONE]-->
     <string name="uwb_toggle_summary">Helps your car identify the position of UWB devices</string>
-
+    <!-- Title of the Audio sharing preference [CHAR LIMIT=40] -->
+    <string name="bluetooth_audio_sharing">Audio Sharing</string>
+    <!-- Title of the Share audio switch [CHAR LIMIT=40] -->
+    <string name="share_audio_switch_title">Share audio</string>
+    <!-- Summary of the Share audio switch [CHAR LIMIT=60] -->
+    <string name="share_audio_switch_summary">Listeners need their own LE Audio headphones</string>
+    <!-- Title for playing a test sound on the Share audio page [CHAR LIMIT=40] -->
+    <string name="share_audio_test_sound_title">Play a test sound</string>
+    <!-- Summary for playing a test sound on the Share audio page [CHAR LIMIT=60] -->
+    <string name="share_audio_test_sound_summary">Everyone listening should hear it</string>
+    <!-- Title for category of the Audio streaming settings on the Share audio page [CHAR LIMIT=40] -->
+    <string name="audio_sharing_active_media_devices">Active media devices</string>
+    <!-- Title for category of the Audio streaming settings on the Share audio page [CHAR LIMIT=40] -->
+    <string name="audio_stream_settings_category_title">Audio stream settings</string>
+    <!-- Title for the audio stream Qr code sharing page [CHAR LIMIT=40] -->
+    <string name="audio_streaming_title">Audio stream QR Code</string>
+    <!-- Title for the preference to launch audio stream QR code page [CHAR LIMIT=40] -->
+    <string name="scan_qr_code_to_connect">Scan QR code to connect</string>
+    <!-- Description for how to use Qr code to join audio stream [CHAR LIMIT=NONE] -->
+    <string name="audio_stream_qr_code_description">To listen to audio stream, other people can connect compatible headphones to their android device. They can then scan this QR code.</string>
     <!-- Bluetooth pairing --><skip/>
     <!-- Notification ticker text (shown in the status bar) when a Bluetooth device wants to pair with us -->
     <string name="bluetooth_notif_ticker">Bluetooth pairing request</string>
@@ -1460,6 +1479,8 @@
     <string name="storage_files">Files</string>
     <!-- Preference label for the System storage section. [CHAR LIMIT=50] -->
     <string name="storage_system">System</string>
+    <!-- Max unit label of system storage framgment -->
+    <string name="storage_total_label">%s total</string>
     <!-- Body of dialog informing user about the storage used by the Android System [CHAR LIMIT=NONE]-->
     <string name="storage_detail_dialog_system">System includes files used to run Android version <xliff:g id="version" example="8.0">%s</xliff:g></string>
     <!-- Car storage settings summary. Displayed when the total memory usage is being calculated. Will be replaced with a number like "12.3 GB" when finished calculating. [CHAR LIMIT=30] -->
diff --git a/res/values/themes.xml b/res/values/themes.xml
index adc3dc004..3bd38636f 100644
--- a/res/values/themes.xml
+++ b/res/values/themes.xml
@@ -43,6 +43,7 @@
         <item name="themeTogglePreferenceToggleButtonRadius">?oemShapeCornerExtraSmall</item>
         <item name="suggestionsCornerRadius">?oemShapeCornerSmall</item>
         <item name="wifiTetherQrCodeRoundedCornerRadius">?oemShapeCornerSmall</item>
+        <item name="audioSharingQrCodeRoundedCornerRadius">?oemShapeCornerSmall</item>
     </style>
 
     <style name="FallbackHome" parent="@android:style/Theme.DeviceDefault.NoActionBar">
diff --git a/res/xml/audio_sharing_fragment.xml b/res/xml/audio_sharing_fragment.xml
new file mode 100644
index 000000000..2bc40c2f1
--- /dev/null
+++ b/res/xml/audio_sharing_fragment.xml
@@ -0,0 +1,53 @@
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
+<PreferenceScreen
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:settings="http://schemas.android.com/apk/res-auto"
+    android:title="@string/bluetooth_audio_sharing"
+    android:key="@string/psk_audio_sharing">
+    <com.android.car.settings.common.ColoredSwitchPreference
+        android:key="@string/pk_share_audio_switch"
+        android:title="@string/share_audio_switch_title"
+        android:summary="@string/share_audio_switch_summary"
+        style="@style/ColoredSwitchPreferenceStyle"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.AudioSharingStateSwitchPreferenceController"/>
+    <PreferenceCategory
+        android:key="@string/pk_audio_sharing_active_media_devices"
+        android:title="@string/audio_sharing_active_media_devices"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.BroadcastDescriptionPreferenceController"/>
+    <com.android.car.ui.preference.CarUiPreference
+        android:icon="@drawable/ic_music_cast"
+        android:key="@string/pk_share_audio_test_sound"
+        android:title="@string/share_audio_test_sound_title"
+        android:summary="@string/share_audio_test_sound_summary"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.PlaySoundPreferenceController"
+        settings:showChevron="false"/>
+    <com.android.car.settings.bluetooth.audiosharing.DeviceSelectorPreferenceGroup
+        android:key="@string/pk_audio_stream_device_selector"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.DeviceSelectorPreferenceGroupController"/>
+    <PreferenceCategory
+        android:key="@string/pk_audio_stream_settings"
+        android:title="@string/audio_stream_settings_category_title"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.BroadcastDescriptionPreferenceController"/>
+    <com.android.car.ui.preference.CarUiTwoActionIconPreference
+        android:key="@string/pk_audio_sharing_audio_stream"
+        android:title="@string/scan_qr_code_to_connect"
+        android:fragment="com.android.car.settings.bluetooth.audiosharing.audiostreaming.AudioStreamFragment"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.audiostreaming.AudioStreamController"
+        settings:secondaryActionIcon="@drawable/ic_qr"/>
+</PreferenceScreen>
diff --git a/res/xml/audio_stream_fragment.xml b/res/xml/audio_stream_fragment.xml
new file mode 100644
index 000000000..c96c42622
--- /dev/null
+++ b/res/xml/audio_stream_fragment.xml
@@ -0,0 +1,32 @@
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
+<PreferenceScreen
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:settings="http://schemas.android.com/apk/res-auto"
+    android:title="@string/audio_streaming_title"
+    android:key="@string/psk_audio_streaming">
+    <com.android.car.ui.preference.CarUiPreference
+        android:key="@string/pk_audio_stream_qr_code_description"
+        android:selectable="false"
+        android:summary="@string/audio_stream_qr_code_description"
+        settings:showChevron="false"/>
+    <com.android.car.settings.bluetooth.audiosharing.audiostreaming.AudioStreamQrPreference
+        android:key="@string/pk_audio_stream_qr_code"
+        android:selectable="false"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.audiostreaming.AudioStreamQrPreferenceController"/>
+</PreferenceScreen>
diff --git a/res/xml/bluetooth_settings_fragment.xml b/res/xml/bluetooth_settings_fragment.xml
index 040ae2300..9abda19b3 100644
--- a/res/xml/bluetooth_settings_fragment.xml
+++ b/res/xml/bluetooth_settings_fragment.xml
@@ -62,4 +62,12 @@
         settings:occupant_front_passenger="read"
         settings:occupant_rear_passenger="read"
         settings:controller="com.android.car.settings.bluetooth.UwbTogglePreferenceController"/>
+    <com.android.car.ui.preference.CarUiPreference
+        android:fragment="com.android.car.settings.bluetooth.audiosharing.AudioSharingFragment"
+        android:icon="@drawable/ic_audio_sharing"
+        android:key="@string/pk_bluetooth_audio_sharing"
+        android:title="@string/bluetooth_audio_sharing"
+        settings:controller="com.android.car.settings.bluetooth.audiosharing.AudioSharingPreferenceController"
+        settings:showChevron="false">
+    </com.android.car.ui.preference.CarUiPreference>
 </PreferenceScreen>
diff --git a/src/com/android/car/settings/applications/appinfo/AppAspectRatioPreferenceController.java b/src/com/android/car/settings/applications/appinfo/AppAspectRatioPreferenceController.java
index 28aff77ab..f91227c0d 100644
--- a/src/com/android/car/settings/applications/appinfo/AppAspectRatioPreferenceController.java
+++ b/src/com/android/car/settings/applications/appinfo/AppAspectRatioPreferenceController.java
@@ -16,9 +16,12 @@
 
 package com.android.car.settings.applications.appinfo;
 
+import android.car.Car;
+import android.car.content.pm.CarPackageManager;
 import android.car.drivingstate.CarUxRestrictions;
 import android.content.Context;
 import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
 
 import com.android.car.settings.common.FragmentController;
 import com.android.car.settings.common.Logger;
@@ -35,12 +38,18 @@ public final class AppAspectRatioPreferenceController extends
     private ApplicationInfo mApplicationInfo;
     private AspectRatioManager mAspectRatioManager;
     private String mPackageName;
+    private CarPackageManager mCarPackageManager;
 
     public AppAspectRatioPreferenceController(Context context, String preferenceKey,
             FragmentController fragmentController,
             CarUxRestrictions uxRestrictions) {
         super(context, preferenceKey, fragmentController, uxRestrictions);
         mAspectRatioManager = new AspectRatioManager(context);
+
+        Car car = Car.createCar(getContext());
+        if (car != null) {
+            mCarPackageManager = car.getCarManager(CarPackageManager.class);
+        }
     }
 
     @Override
@@ -50,6 +59,16 @@ public final class AppAspectRatioPreferenceController extends
 
     @Override
     public int getDefaultAvailabilityStatus() {
+        if (mCarPackageManager != null) {
+            try {
+                if (!mCarPackageManager.requiresDisplayCompat(mApplicationInfo.packageName)) {
+                    return UNSUPPORTED_ON_DEVICE;
+                }
+            } catch (PackageManager.NameNotFoundException e) {
+                LOG.e("App " + mApplicationInfo + " not found");
+            }
+        }
+
         return mAspectRatioManager.shouldShowAspectRatioSettingsForApp(mApplicationInfo)
                 ? AVAILABLE : UNSUPPORTED_ON_DEVICE;
     }
diff --git a/src/com/android/car/settings/applications/appinfo/AppAspectRatiosGroupPreferenceController.java b/src/com/android/car/settings/applications/appinfo/AppAspectRatiosGroupPreferenceController.java
index 337056b24..0b4d19c06 100644
--- a/src/com/android/car/settings/applications/appinfo/AppAspectRatiosGroupPreferenceController.java
+++ b/src/com/android/car/settings/applications/appinfo/AppAspectRatiosGroupPreferenceController.java
@@ -51,7 +51,6 @@ public class AppAspectRatiosGroupPreferenceController extends
     private static final String KEY_PREF_16_9 = "16_9_pref";
     private static final String KEY_PREF_4_3 = "4_3_pref";
     private static final String KEY_PREF_3_2 = "3_2_pref";
-    private static final String KEY_ASPECT_RATIO_UNSET = "aspect_ratio_unset";
     private static final BiMap<String, Integer> KEY_TO_ASPECT_RATIO_MAP = ImmutableBiMap.of(
             KEY_PREF_DEFAULT, PackageManager.USER_MIN_ASPECT_RATIO_APP_DEFAULT,
             KEY_PREF_FULLSCREEN, PackageManager.USER_MIN_ASPECT_RATIO_FULLSCREEN,
@@ -59,8 +58,7 @@ public class AppAspectRatiosGroupPreferenceController extends
             KEY_PREF_DISPLAY_SIZE, PackageManager.USER_MIN_ASPECT_RATIO_DISPLAY_SIZE,
             KEY_PREF_4_3, PackageManager.USER_MIN_ASPECT_RATIO_4_3,
             KEY_PREF_16_9, PackageManager.USER_MIN_ASPECT_RATIO_16_9,
-            KEY_PREF_3_2, PackageManager.USER_MIN_ASPECT_RATIO_3_2,
-            KEY_ASPECT_RATIO_UNSET, PackageManager.USER_MIN_ASPECT_RATIO_UNSET
+            KEY_PREF_3_2, PackageManager.USER_MIN_ASPECT_RATIO_3_2
     );
     private List<RadioWithImagePreference> mPreferenceList;
     private String mSelectedKey = KEY_PREF_DEFAULT;
@@ -99,7 +97,7 @@ public class AppAspectRatiosGroupPreferenceController extends
             LOG.d("There is an exception when trying to get the current aspect ratio: " + e);
         }
         mSelectedKey = KEY_TO_ASPECT_RATIO_MAP.inverse()
-                .getOrDefault(currentAspectRatio, KEY_ASPECT_RATIO_UNSET);
+                .getOrDefault(currentAspectRatio, KEY_PREF_DEFAULT);
         for (int i = 0; i < getPreference().getPreferenceCount(); i++) {
             RadioWithImagePreference child =
                     (RadioWithImagePreference) getPreference().getPreference(i);
diff --git a/src/com/android/car/settings/bluetooth/BluetoothDeviceProfilesPreferenceController.java b/src/com/android/car/settings/bluetooth/BluetoothDeviceProfilesPreferenceController.java
index adefe8146..398594dec 100644
--- a/src/com/android/car/settings/bluetooth/BluetoothDeviceProfilesPreferenceController.java
+++ b/src/com/android/car/settings/bluetooth/BluetoothDeviceProfilesPreferenceController.java
@@ -73,6 +73,11 @@ public class BluetoothDeviceProfilesPreferenceController extends
     @Override
     protected void updateState(PreferenceGroup preferenceGroup) {
         for (LocalBluetoothProfile profile : getCachedDevice().getProfiles()) {
+            // Do not show if the user should not be able to access this profile from the UI
+            if (!profile.accessProfileEnabled()) {
+                continue;
+            }
+
             Preference profilePref = preferenceGroup.findPreference(profile.toString());
             if (profilePref == null) {
                 profilePref = new BluetoothDeviceProfilePreference(getContext(), profile,
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingFragment.java b/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingFragment.java
new file mode 100644
index 000000000..05ae2f4e0
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingFragment.java
@@ -0,0 +1,33 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import androidx.annotation.XmlRes;
+
+import com.android.car.settings.R;
+import com.android.car.settings.common.SettingsFragment;
+
+/**
+ * A fragment for updating the audio sharing settings via LE bluetooth.
+ */
+public class AudioSharingFragment extends SettingsFragment {
+    @Override
+    @XmlRes
+    protected int getPreferenceScreenResId() {
+        return R.xml.audio_sharing_fragment;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingPreferenceController.java b/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingPreferenceController.java
new file mode 100644
index 000000000..deafceb09
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingPreferenceController.java
@@ -0,0 +1,50 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+
+import com.android.car.settings.Flags;
+import com.android.car.settings.common.FragmentController;
+import com.android.car.ui.preference.CarUiPreference;
+
+/**
+ * The controller for the launching {@link AudioSharingFragment};
+ */
+public class AudioSharingPreferenceController extends BaseAudioSharingPreferenceController
+        <CarUiPreference> {
+
+    public AudioSharingPreferenceController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+    }
+
+    @Override
+    protected Class<CarUiPreference> getPreferenceType() {
+        return CarUiPreference.class;
+    }
+
+    @Override
+    protected int getDefaultAvailabilityStatus() {
+        if (!Flags.carSettingsMultiCasting()) return CONDITIONALLY_UNAVAILABLE;
+        if (isBluetoothStateOn() && isBroadcastAvailable()) {
+            return AVAILABLE;
+        }
+        return CONDITIONALLY_UNAVAILABLE;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingStateSwitchPreferenceController.java b/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingStateSwitchPreferenceController.java
new file mode 100644
index 000000000..788297bfc
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/AudioSharingStateSwitchPreferenceController.java
@@ -0,0 +1,77 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+import android.content.SharedPreferences;
+
+import com.android.car.settings.Flags;
+import com.android.car.settings.common.ColoredSwitchPreference;
+import com.android.car.settings.common.FragmentController;
+
+/**
+ * Enables/disables audio sharing state via SwitchPreference.
+ */
+public class AudioSharingStateSwitchPreferenceController extends
+        BaseAudioSharingPreferenceController<ColoredSwitchPreference> {
+
+    public AudioSharingStateSwitchPreferenceController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+    }
+
+    @Override
+    protected void updateState(ColoredSwitchPreference preference) {
+        setAudioSharingState(isUserEnabled());
+    }
+
+    @Override
+    protected boolean handlePreferenceChanged(ColoredSwitchPreference preference, Object newValue) {
+        setAudioSharingState((boolean) newValue);
+        return true;
+    }
+
+    private void setAudioSharingState(boolean userEnabled) {
+        if (userEnabled != isUserEnabled()) {
+            SharedPreferences.Editor editor = getContext().getSharedPreferences(
+                    USER_ENABLE_AUDIO_SHARING_KEY, Context.MODE_PRIVATE).edit();
+            editor.putBoolean(USER_ENABLE_AUDIO_SHARING_KEY, userEnabled);
+            editor.apply();
+        }
+        if (getPreference().isChecked() != userEnabled) {
+            getPreference().setChecked(userEnabled);
+        }
+        if (!userEnabled) {
+            mLeBroadcastProfile.stopLatestBroadcast();
+        }
+    }
+
+    @Override
+    protected Class<ColoredSwitchPreference> getPreferenceType() {
+        return ColoredSwitchPreference.class;
+    }
+
+    @Override
+    protected int getDefaultAvailabilityStatus() {
+        if (!Flags.carSettingsMultiCasting()) return CONDITIONALLY_UNAVAILABLE;
+        if (isBluetoothStateOn() && isBroadcastAvailable()) {
+            return AVAILABLE;
+        }
+        return AVAILABLE_FOR_VIEWING;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/BaseAudioSharingPreferenceController.java b/src/com/android/car/settings/bluetooth/audiosharing/BaseAudioSharingPreferenceController.java
new file mode 100644
index 000000000..35919a16e
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/BaseAudioSharingPreferenceController.java
@@ -0,0 +1,173 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import static android.bluetooth.BluetoothAdapter.ERROR;
+import static android.bluetooth.BluetoothAdapter.EXTRA_STATE;
+import static android.bluetooth.BluetoothAdapter.STATE_OFF;
+import static android.bluetooth.BluetoothAdapter.STATE_ON;
+
+import android.bluetooth.BluetoothAdapter;
+import android.bluetooth.BluetoothLeBroadcastMetadata;
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.SharedPreferences;
+
+import androidx.preference.Preference;
+
+import com.android.car.settings.Flags;
+import com.android.car.settings.common.FragmentController;
+import com.android.car.settings.common.PreferenceController;
+import com.android.settingslib.bluetooth.LeAudioProfile;
+import com.android.settingslib.bluetooth.LocalBluetoothLeBroadcast;
+import com.android.settingslib.bluetooth.LocalBluetoothLeBroadcastAssistant;
+import com.android.settingslib.bluetooth.LocalBluetoothManager;
+
+import java.util.List;
+
+/**
+ * Base controller for all audio sharing preferences, which will only have its
+ * {@link #getDefaultAvailabilityStatus()} set to return {@code true} if the feature is available on
+ * this device and is currently broadcasting.
+ *
+ * <p>This controller and its subclasses will automatically call {@link #refreshUi} when
+ * either bluetooth states or LE broadcast state changes.</p>
+ * @param <T> should match the typing of the preference controller.
+ */
+public abstract class BaseAudioSharingPreferenceController<T extends Preference> extends
+        PreferenceController<T> {
+    public static final String USER_ENABLE_AUDIO_SHARING_KEY =
+            "com.android.car.settings.bluetooth.audiosharing.USER_ENABLE_AUDIO_SHARING";
+    protected final LocalBluetoothManager mBtManager;
+    protected LeAudioProfile mLeAudioProfile;
+    protected LocalBluetoothLeBroadcast mLeBroadcastProfile;
+    protected LocalBluetoothLeBroadcastAssistant mLeBroadcastAssistantProfile;
+    private boolean mUserAudioSharingEnabled;
+
+    public BaseAudioSharingPreferenceController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+        // required available profiles for LE bluetooth audio
+        mBtManager = LocalBluetoothManager.getInstance(context, null);
+        if (mBtManager != null && mBtManager.getProfileManager() != null) {
+            mLeAudioProfile = mBtManager.getProfileManager().getLeAudioProfile();
+            mLeBroadcastProfile = mBtManager.getProfileManager().getLeAudioBroadcastProfile();
+            mLeBroadcastAssistantProfile = mBtManager.getProfileManager()
+                    .getLeAudioBroadcastAssistantProfile();
+        }
+        // listener to update availability state bluetooth state is turned on and off
+        context.registerReceiver(new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent intent) {
+                final int state = intent.getIntExtra(EXTRA_STATE, ERROR);
+                if (state == STATE_ON || state == STATE_OFF) {
+                    refreshUi();
+                }
+            }
+        }, new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED));
+        // listener to update availability state when broadcast updates
+        if (isBroadcastAvailable()) {
+            mLeBroadcastProfile.registerServiceCallBack(getContext().getMainExecutor(),
+                    new BaseLeBroadcastCallback() {
+                        @Override
+                        public void onBroadcastStarted(int reason, int broadcastId) {
+                            refreshUi();
+                            BaseAudioSharingPreferenceController.this
+                                    .onBroadcastStartedInternal(broadcastId);
+                        }
+                        @Override
+                        public void onBroadcastStopped(int reason, int broadcastId) {
+                            refreshUi();
+                            BaseAudioSharingPreferenceController.this
+                                    .onBroadcastStoppedInternal(broadcastId);
+                        }
+                    });
+        }
+        // listener to update availability state when user toggles audio sharing
+        SharedPreferences sharedPrefs =
+                context.getSharedPreferences(USER_ENABLE_AUDIO_SHARING_KEY, Context.MODE_PRIVATE);
+        mUserAudioSharingEnabled = sharedPrefs.getBoolean(USER_ENABLE_AUDIO_SHARING_KEY,
+                /* defaultValue= */ false);
+        sharedPrefs.registerOnSharedPreferenceChangeListener(
+                (sharedPreferences, key) -> {
+                    if (key != null && key.equals(USER_ENABLE_AUDIO_SHARING_KEY)) {
+                        mUserAudioSharingEnabled = sharedPrefs.getBoolean(
+                                USER_ENABLE_AUDIO_SHARING_KEY, false);
+                        refreshUi();
+                    }
+                });
+    }
+
+    /**
+     * @return {@link BluetoothLeBroadcastMetadata} representing the current broadcast, or
+     * {@code null} if there is no currently active session.
+     */
+    public BluetoothLeBroadcastMetadata getCurrentBroadcast() {
+        List<BluetoothLeBroadcastMetadata> metadata = mLeBroadcastProfile.getAllBroadcastMetadata();
+        if (metadata.isEmpty()) {
+            return null;
+        }
+        return metadata.getFirst();
+    }
+
+    /**
+     * @return {@code true} if bluetooth is turned on.
+     */
+    public boolean isBluetoothStateOn() {
+        return mBtManager != null && mBtManager.getBluetoothAdapter() != null
+                && mBtManager.getBluetoothAdapter().getBluetoothState() == STATE_ON;
+    }
+
+    /**
+     * @return {@code true} if all bluetooth profiles necessary for LE bluetooth broadcast state
+     * management in Settings is available, {@code false} otherwise.
+     */
+    public boolean isBroadcastAvailable() {
+        return isBluetoothStateOn() && mBtManager != null && mLeAudioProfile != null
+                && mLeBroadcastProfile != null && mLeBroadcastAssistantProfile != null;
+    }
+
+    /**
+     * @return {@code true} if there is an active broadcast session, {@code false} otherwise.
+     */
+    public boolean isBroadcasting() {
+        return isBroadcastAvailable() && !mLeBroadcastProfile.getAllBroadcastMetadata().isEmpty();
+    }
+
+    /**
+     * @return {@code true} if user has opted-in to audio sharing.
+     */
+    public boolean isUserEnabled() {
+        return mUserAudioSharingEnabled;
+    }
+
+    protected void onBroadcastStartedInternal(int broadcastId) {}
+
+    protected void onBroadcastStoppedInternal(int broadcastId) {}
+
+    @Override
+    protected int getDefaultAvailabilityStatus() {
+        if (!Flags.carSettingsMultiCasting()) return CONDITIONALLY_UNAVAILABLE;
+        if (isUserEnabled() && isBroadcasting()) {
+            return AVAILABLE;
+        }
+        return CONDITIONALLY_UNAVAILABLE;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/BaseLeBroadcastAssistantCallback.java b/src/com/android/car/settings/bluetooth/audiosharing/BaseLeBroadcastAssistantCallback.java
new file mode 100644
index 000000000..05485a133
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/BaseLeBroadcastAssistantCallback.java
@@ -0,0 +1,68 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.bluetooth.BluetoothDevice;
+import android.bluetooth.BluetoothLeBroadcastAssistant;
+import android.bluetooth.BluetoothLeBroadcastMetadata;
+import android.bluetooth.BluetoothLeBroadcastReceiveState;
+
+import androidx.annotation.NonNull;
+
+/**
+ * Base class that implements all methods of the callbacks API. This allows the creation of listener
+ * classes that only implement some of the methods, and leave the rest as no-op.
+ */
+public class BaseLeBroadcastAssistantCallback implements BluetoothLeBroadcastAssistant.Callback {
+    @Override
+    public void onSearchStarted(int reason) {}
+
+    @Override
+    public void onSearchStartFailed(int reason) {}
+
+    @Override
+    public void onSearchStopped(int reason) {}
+
+    @Override
+    public void onSearchStopFailed(int reason) {}
+
+    @Override
+    public void onSourceFound(@NonNull BluetoothLeBroadcastMetadata source) {}
+
+    @Override
+    public void onSourceAdded(@NonNull BluetoothDevice sink, int sourceId, int reason) {}
+
+    @Override
+    public void onSourceAddFailed(@NonNull BluetoothDevice sink,
+            @NonNull BluetoothLeBroadcastMetadata source, int reason) {}
+
+    @Override
+    public void onSourceModified(@NonNull BluetoothDevice sink, int sourceId, int reason) {}
+
+    @Override
+    public void onSourceModifyFailed(@NonNull BluetoothDevice sink, int sourceId, int reason) {}
+
+    @Override
+    public void onSourceRemoved(@NonNull BluetoothDevice sink, int sourceId, int reason) {}
+
+    @Override
+    public void onSourceRemoveFailed(@NonNull BluetoothDevice sink, int sourceId, int reason) {}
+
+    @Override
+    public void onReceiveStateChanged(@NonNull BluetoothDevice sink, int sourceId,
+            @NonNull BluetoothLeBroadcastReceiveState state) {}
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/BaseLeBroadcastCallback.java b/src/com/android/car/settings/bluetooth/audiosharing/BaseLeBroadcastCallback.java
new file mode 100644
index 000000000..4e7aa7de9
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/BaseLeBroadcastCallback.java
@@ -0,0 +1,56 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.bluetooth.BluetoothLeBroadcast;
+import android.bluetooth.BluetoothLeBroadcastMetadata;
+
+import androidx.annotation.NonNull;
+
+/**
+ * Base class that implements all methods of the callbacks API. This allows the creation of listener
+ * classes that only implement some of the methods, and leave the rest as no-op.
+ */
+public abstract class BaseLeBroadcastCallback implements BluetoothLeBroadcast.Callback {
+    @Override
+    public void onBroadcastStarted(int reason, int broadcastId) {}
+
+    @Override
+    public void onBroadcastStartFailed(int reason) {}
+
+    @Override
+    public void onBroadcastStopped(int reason, int broadcastId) {}
+
+    @Override
+    public void onBroadcastStopFailed(int reason) {}
+
+    @Override
+    public void onPlaybackStarted(int reason, int broadcastId) {}
+
+    @Override
+    public void onPlaybackStopped(int reason, int broadcastId) {}
+
+    @Override
+    public void onBroadcastUpdated(int reason, int broadcastId) {}
+
+    @Override
+    public void onBroadcastUpdateFailed(int reason, int broadcastId) {}
+
+    @Override
+    public void onBroadcastMetadataChanged(int broadcastId,
+            @NonNull BluetoothLeBroadcastMetadata metadata) {}
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/BroadcastDescriptionPreferenceController.java b/src/com/android/car/settings/bluetooth/audiosharing/BroadcastDescriptionPreferenceController.java
new file mode 100644
index 000000000..8cae043a6
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/BroadcastDescriptionPreferenceController.java
@@ -0,0 +1,48 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+
+import androidx.preference.PreferenceCategory;
+
+import com.android.car.settings.common.FragmentController;
+
+/**
+ * Simple audio sharing bluetooth preference controller for static {@link PreferenceCategory} texts.
+ */
+public class BroadcastDescriptionPreferenceController extends
+        BaseAudioSharingPreferenceController<PreferenceCategory> {
+    public BroadcastDescriptionPreferenceController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+    }
+
+    @Override
+    protected Class<PreferenceCategory> getPreferenceType() {
+        return PreferenceCategory.class;
+    }
+
+    @Override
+    protected int getDefaultAvailabilityStatus() {
+        if (isUserEnabled() && isBroadcastAvailable()) {
+            return AVAILABLE;
+        }
+        return CONDITIONALLY_UNAVAILABLE;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/DeviceSelectorPreferenceGroup.java b/src/com/android/car/settings/bluetooth/audiosharing/DeviceSelectorPreferenceGroup.java
new file mode 100644
index 000000000..37732630e
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/DeviceSelectorPreferenceGroup.java
@@ -0,0 +1,49 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.content.Context;
+import android.util.AttributeSet;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceGroup;
+
+import com.android.car.ui.R;
+
+/**
+ * Preference group for holding preferences that connect or disconnect audio shared devices.
+ */
+public class DeviceSelectorPreferenceGroup extends PreferenceGroup {
+    public DeviceSelectorPreferenceGroup(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr, int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+        setLayoutResource(R.layout.audio_sharing_device_selector_preference_group);
+    }
+
+    public DeviceSelectorPreferenceGroup(Context context, AttributeSet attrs, int defStyleAttr) {
+        this(context, attrs, defStyleAttr, 0);
+    }
+
+    public DeviceSelectorPreferenceGroup(Context context, AttributeSet attrs) {
+        this(context, attrs, 0);
+    }
+
+    public DeviceSelectorPreferenceGroup(Context context) {
+        this(context, null);
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/DeviceSelectorPreferenceGroupController.java b/src/com/android/car/settings/bluetooth/audiosharing/DeviceSelectorPreferenceGroupController.java
new file mode 100644
index 000000000..29284ba01
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/DeviceSelectorPreferenceGroupController.java
@@ -0,0 +1,215 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import android.bluetooth.BluetoothDevice;
+import android.bluetooth.BluetoothLeBroadcastMetadata;
+import android.bluetooth.BluetoothLeBroadcastReceiveState;
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.Preference;
+
+import com.android.car.settings.CarSettingsApplication;
+import com.android.car.settings.Flags;
+import com.android.car.settings.R;
+import com.android.car.settings.common.FragmentController;
+import com.android.car.ui.preference.CarUiTwoActionIconPreference;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * Class for selecting device to join the broadcast.
+ */
+public class DeviceSelectorPreferenceGroupController extends
+        BaseAudioSharingPreferenceController<DeviceSelectorPreferenceGroup> {
+    private final List<BluetoothDevice> mPendingDeviceAdds = new ArrayList<>();
+
+    public DeviceSelectorPreferenceGroupController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+        if (isBroadcastAvailable()) {
+            mLeBroadcastProfile.registerServiceCallBack(getContext().getMainExecutor(),
+                    new BaseLeBroadcastCallback() {
+                        @Override
+                        public void onBroadcastStarted(int reason, int broadcastId) {
+                            addPendingDevices(getCurrentBroadcast());
+                        }
+                        @Override
+                        public void onBroadcastMetadataChanged(int broadcastId,
+                                @NonNull BluetoothLeBroadcastMetadata metadata) {
+                            addPendingDevices(metadata);
+                        }
+                    });
+            mLeBroadcastAssistantProfile.registerServiceCallBack(getContext().getMainExecutor(),
+                    new BaseLeBroadcastAssistantCallback() {
+                        @Override
+                        public void onSourceAdded(@NonNull BluetoothDevice sink, int sourceId,
+                                int reason) {
+                            updatePreferenceList();
+                        }
+
+                        @Override
+                        public void onSourceRemoved(@NonNull BluetoothDevice sink, int sourceId,
+                                int reason) {
+                            updatePreferenceList();
+                            if (hasNoActiveSinkDevice(sourceId)) {
+                                stopBroadcast();
+                            }
+                        }
+                    });
+        }
+    }
+
+    private void addPendingDevices(@Nullable BluetoothLeBroadcastMetadata metadata) {
+        if (metadata == null || mPendingDeviceAdds.isEmpty()) {
+            return;
+        }
+        for (BluetoothDevice device : mPendingDeviceAdds) {
+            mLeBroadcastAssistantProfile.addSource(device, /* metadata= */ getCurrentBroadcast(),
+                    /* isGroupOp= */ false);
+        }
+        mPendingDeviceAdds.clear();
+    }
+
+    private boolean hasNoActiveSinkDevice(int sourceId) {
+        BluetoothLeBroadcastMetadata metadata = getCurrentBroadcast();
+        for (BluetoothDevice device : mBtManager.getBluetoothAdapter().getBondedDevices()) {
+            if (device != null && device.isConnected()) {
+                BluetoothLeBroadcastMetadata srcMetadata =
+                        mLeBroadcastAssistantProfile.getSourceMetadata(device, sourceId);
+                if (metadata != null && srcMetadata != null
+                        && srcMetadata.getSourceDevice().equals(metadata.getSourceDevice())) {
+                    return false;
+                }
+            }
+        }
+        return true;
+    }
+
+    @Override
+    protected void updateState(DeviceSelectorPreferenceGroup preference) {
+        super.updateState(preference);
+        updatePreferenceList();
+    }
+
+    @Override
+    protected void onBroadcastStartedInternal(int broadcastId) {
+        updatePreferenceList();
+    }
+
+    @Override
+    protected void onBroadcastStoppedInternal(int broadcastId) {
+        updatePreferenceList();
+    }
+
+    private void updatePreferenceList() {
+        getPreference().removeAll();
+        if (!isBroadcastAvailable()) return;
+        for (BluetoothDevice device : mBtManager.getBluetoothAdapter().getBondedDevices()) {
+            if (device != null && device.isConnected() && mLeAudioProfile.isEnabled(device)) {
+                getPreference().addPreference(createLeAudioDevicePreference(device));
+            }
+        }
+    }
+
+    private boolean isReceivingBroadcast(BluetoothDevice device) {
+        BluetoothLeBroadcastMetadata metadata = getCurrentBroadcast();
+        List<BluetoothLeBroadcastReceiveState> broadcastSources =
+                mLeBroadcastAssistantProfile.getAllSources(device);
+        if (metadata != null && !broadcastSources.isEmpty()) {
+            for (BluetoothLeBroadcastReceiveState state : broadcastSources) {
+                if (state.getSourceDevice().equals(metadata.getSourceDevice())) {
+                    return true;
+                }
+            }
+        }
+        return false;
+    }
+
+    private Preference createLeAudioDevicePreference(BluetoothDevice device) {
+        CarUiTwoActionIconPreference preference = new CarUiTwoActionIconPreference(getContext());
+        preference.setTitle(device.getName());
+        preference.setOnPreferenceClickListener(pref -> {
+            if (!isBroadcasting()) {
+                mPendingDeviceAdds.add(device);
+                startBroadcast();
+            } else {
+                mLeBroadcastAssistantProfile.addSource(device,
+                        /* metadata= */ getCurrentBroadcast(), /* isGroupOp= */ false);
+            }
+            return true;
+        });
+        preference.setSecondaryActionIcon(R.drawable.ic_remove_circle);
+        preference.setOnSecondaryActionClickListener(() -> {
+            removeSourceIfDeviceListening(device);
+        });
+
+        if (isReceivingBroadcast(device)) {
+            preference.setIcon(R.drawable.ic_audio_sharing);
+            preference.setSecondaryActionVisible(true);
+        } else {
+            preference.setIcon(R.drawable.ic_headset);
+            preference.setSecondaryActionVisible(false);
+        }
+        return preference;
+    }
+
+    private void removeSourceIfDeviceListening(BluetoothDevice device) {
+        BluetoothLeBroadcastMetadata currentSource = getCurrentBroadcast();
+        List<BluetoothLeBroadcastReceiveState> deviceSources =
+                mLeBroadcastAssistantProfile.getAllSources(device);
+        if (currentSource == null || deviceSources.isEmpty()) {
+            return;
+        }
+        for (BluetoothLeBroadcastReceiveState source : deviceSources) {
+            if (currentSource.getBroadcastId() == source.getBroadcastId()) {
+                mLeBroadcastAssistantProfile.removeSource(device,
+                        /* sourceId */ source.getSourceId());
+            }
+        }
+    }
+
+    private void startBroadcast() {
+        mLeBroadcastProfile.stopLatestBroadcast();
+        mLeBroadcastProfile.startBroadcast(CarSettingsApplication.CAR_SETTINGS_PACKAGE_NAME,
+                /* language= */ null);
+        // set the broadcast code to byte[0] to start a public broadcast
+        mLeBroadcastProfile.setBroadcastCode(new byte[0]);
+    }
+
+    private void stopBroadcast() {
+        mLeBroadcastProfile.stopLatestBroadcast();
+    }
+
+    @Override
+    protected Class<DeviceSelectorPreferenceGroup> getPreferenceType() {
+        return DeviceSelectorPreferenceGroup.class;
+    }
+
+    @Override
+    protected int getDefaultAvailabilityStatus() {
+        if (!Flags.carSettingsMultiCasting()) return CONDITIONALLY_UNAVAILABLE;
+        if (isUserEnabled() && isBroadcastAvailable()) {
+            return AVAILABLE;
+        }
+        return CONDITIONALLY_UNAVAILABLE;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/PlaySoundPreferenceController.java b/src/com/android/car/settings/bluetooth/audiosharing/PlaySoundPreferenceController.java
new file mode 100644
index 000000000..a126f9051
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/PlaySoundPreferenceController.java
@@ -0,0 +1,78 @@
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
+package com.android.car.settings.bluetooth.audiosharing;
+
+import static android.provider.Settings.System.DEFAULT_NOTIFICATION_URI;
+
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+import android.media.AudioAttributes;
+import android.media.Ringtone;
+import android.media.RingtoneManager;
+
+import com.android.car.settings.common.FragmentController;
+import com.android.car.ui.preference.CarUiPreference;
+
+/**
+ * Preference controller that plays the default notification chime on the media channel.
+ */
+public class PlaySoundPreferenceController extends
+        BaseAudioSharingPreferenceController<CarUiPreference> {
+    private final Ringtone mRingtone;
+
+    public PlaySoundPreferenceController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+        mRingtone = RingtoneManager.getRingtone(context, DEFAULT_NOTIFICATION_URI);
+        mRingtone.setAudioAttributes(new AudioAttributes.Builder()
+                .setUsage(AudioAttributes.USAGE_MEDIA)
+                .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
+                .build());
+    }
+
+    @Override
+    protected void onStartInternal() {
+        super.onStartInternal();
+        getPreference().setOnPreferenceClickListener(pref -> {
+            if (mRingtone != null) {
+                mRingtone.stop();
+                mRingtone.play();
+            }
+            return true;
+        });
+    }
+
+    @Override
+    protected void onPauseInternal() {
+        super.onResumeInternal();
+        if (mRingtone != null) {
+            mRingtone.stop();
+        }
+    }
+
+    @Override
+    protected Class<CarUiPreference> getPreferenceType() {
+        return CarUiPreference.class;
+    }
+
+    @Override
+    protected int getDefaultAvailabilityStatus() {
+        if (isUserEnabled() && isBroadcasting()) {
+            return AVAILABLE;
+        }
+        return CONDITIONALLY_UNAVAILABLE;
+    }}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamController.java b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamController.java
new file mode 100644
index 000000000..9ea97f099
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamController.java
@@ -0,0 +1,50 @@
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
+package com.android.car.settings.bluetooth.audiosharing.audiostreaming;
+
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+
+import com.android.car.settings.bluetooth.audiosharing.BaseAudioSharingPreferenceController;
+import com.android.car.settings.common.FragmentController;
+import com.android.car.ui.preference.CarUiTwoActionIconPreference;
+
+/**
+ * Controller for launching {@link AudioStreamFragment}.
+ */
+public class AudioStreamController extends
+        BaseAudioSharingPreferenceController<CarUiTwoActionIconPreference> {
+
+    public AudioStreamController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+    }
+
+    @Override
+    protected void updateState(CarUiTwoActionIconPreference preference) {
+        super.updateState(preference);
+        preference.setOnSecondaryActionClickListener(() -> {
+            getFragmentController().launchFragment(new AudioStreamFragment());
+        });
+        preference.setSecondaryActionVisible(true);
+    }
+
+    @Override
+    protected Class<CarUiTwoActionIconPreference> getPreferenceType() {
+        return CarUiTwoActionIconPreference.class;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamFragment.java b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamFragment.java
new file mode 100644
index 000000000..fc27a5e83
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamFragment.java
@@ -0,0 +1,33 @@
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
+package com.android.car.settings.bluetooth.audiosharing.audiostreaming;
+
+import androidx.annotation.XmlRes;
+
+import com.android.car.settings.R;
+import com.android.car.settings.common.SettingsFragment;
+
+/**
+ * Fragment for displaying information about the shared audio stream.
+ */
+public class AudioStreamFragment extends SettingsFragment {
+    @Override
+    @XmlRes
+    protected int getPreferenceScreenResId() {
+        return R.xml.audio_stream_fragment;
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamQrPreference.java b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamQrPreference.java
new file mode 100644
index 000000000..2e388cca1
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamQrPreference.java
@@ -0,0 +1,74 @@
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
+package com.android.car.settings.bluetooth.audiosharing.audiostreaming;
+
+import android.content.Context;
+import android.graphics.Bitmap;
+import android.util.AttributeSet;
+import android.widget.ImageView;
+
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.car.settings.R;
+import com.android.car.ui.preference.CarUiPreference;
+
+/**
+ * A Preference used to show the QR code for joining the broadcast stream.
+ */
+public class AudioStreamQrPreference extends CarUiPreference {
+
+    private Bitmap mImage;
+
+    public AudioStreamQrPreference(
+            Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+        init();
+    }
+
+    public AudioStreamQrPreference(Context context, AttributeSet attrs, int defStyleAttr) {
+        this(context, attrs, defStyleAttr, 0);
+    }
+
+    public AudioStreamQrPreference(Context context, AttributeSet attrs) {
+        this(context, attrs, 0);
+    }
+
+    public AudioStreamQrPreference(Context context) {
+        this(context, null);
+    }
+
+    private void init() {
+        setLayoutResource(R.layout.audio_stream_qr_preference);
+    }
+
+    @Override
+    public void onBindViewHolder(PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        ImageView qrCode = (ImageView) holder.findViewById(R.id.audio_sharing_qr_code);
+        if (qrCode != null && mImage != null) {
+            qrCode.setImageBitmap(mImage);
+        }
+    }
+
+    /**
+     * Sets information for this preference.
+     */
+    public void setPreferenceInfo(Bitmap bmp) {
+        mImage = bmp;
+        notifyChanged();
+    }
+}
diff --git a/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamQrPreferenceController.java b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamQrPreferenceController.java
new file mode 100644
index 000000000..8afe13465
--- /dev/null
+++ b/src/com/android/car/settings/bluetooth/audiosharing/audiostreaming/AudioStreamQrPreferenceController.java
@@ -0,0 +1,68 @@
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
+package com.android.car.settings.bluetooth.audiosharing.audiostreaming;
+
+import android.bluetooth.BluetoothLeBroadcastMetadata;
+import android.car.drivingstate.CarUxRestrictions;
+import android.content.Context;
+
+import com.android.car.settings.R;
+import com.android.car.settings.bluetooth.audiosharing.BaseAudioSharingPreferenceController;
+import com.android.car.settings.common.FragmentController;
+import com.android.car.settings.common.Logger;
+import com.android.settingslib.bluetooth.BluetoothLeBroadcastMetadataExt;
+import com.android.settingslib.qrcode.QrCodeGenerator;
+
+/**
+ * Controller for updating the Qr code for {@link AudioStreamQrPreference}.
+ */
+public class AudioStreamQrPreferenceController extends
+        BaseAudioSharingPreferenceController<AudioStreamQrPreference> {
+    private static final Logger LOG = new Logger(AudioStreamQrPreferenceController.class);
+
+    public AudioStreamQrPreferenceController(Context context, String preferenceKey,
+            FragmentController fragmentController, CarUxRestrictions uxRestrictions) {
+        super(context, preferenceKey, fragmentController, uxRestrictions);
+    }
+
+    @Override
+    protected void updateState(AudioStreamQrPreference preference) {
+        super.updateState(preference);
+        updateBroadcastQrCodeInfo();
+    }
+
+    private void updateBroadcastQrCodeInfo() {
+        BluetoothLeBroadcastMetadata metadata = getCurrentBroadcast();
+        if (metadata != null) {
+            try {
+                String uri = BluetoothLeBroadcastMetadataExt.INSTANCE.toQrCodeString(metadata);
+                int size = getContext().getResources().getDimensionPixelSize(
+                        R.dimen.bluetooth_audio_streaming_qr_code_size);
+                int margin = getContext().getResources().getDimensionPixelSize(
+                        R.dimen.qr_code_margin);
+                getPreference().setPreferenceInfo(QrCodeGenerator.encodeQrCode(uri, size, margin));
+            } catch (Exception e) {
+                LOG.e("Couldn't generate audio sharing QR code", e);
+            }
+        }
+    }
+
+    @Override
+    protected Class<AudioStreamQrPreference> getPreferenceType() {
+        return AudioStreamQrPreference.class;
+    }
+}
diff --git a/src/com/android/car/settings/common/HighlightablePreferenceGroupAdapter.java b/src/com/android/car/settings/common/HighlightablePreferenceGroupAdapter.java
index 1ab21eb9b..9352eee09 100644
--- a/src/com/android/car/settings/common/HighlightablePreferenceGroupAdapter.java
+++ b/src/com/android/car/settings/common/HighlightablePreferenceGroupAdapter.java
@@ -16,42 +16,20 @@
 
 package com.android.car.settings.common;
 
-import android.content.Context;
-import android.util.TypedValue;
 import android.view.View;
 
-import androidx.annotation.DrawableRes;
 import androidx.preference.PreferenceGroup;
 import androidx.preference.PreferenceGroupAdapter;
 import androidx.preference.PreferenceViewHolder;
 import androidx.recyclerview.widget.RecyclerView;
 
-import com.android.car.settings.R;
-
 /** RecyclerView adapter that supports single-preference highlighting. */
 public class HighlightablePreferenceGroupAdapter extends PreferenceGroupAdapter {
 
-    @DrawableRes
-    private final int mNormalBackgroundRes;
-    @DrawableRes
-    private final int mHighlightBackgroundRes;
     private int mHighlightPosition = RecyclerView.NO_POSITION;
 
     public HighlightablePreferenceGroupAdapter(PreferenceGroup preferenceGroup) {
         super(preferenceGroup);
-        Context context = preferenceGroup.getContext();
-        TypedValue outValue = new TypedValue();
-        context.getTheme().resolveAttribute(android.R.attr.selectableItemBackground,
-                outValue, /* resolveRefs= */ true);
-        mNormalBackgroundRes = outValue.resourceId;
-        mHighlightBackgroundRes = R.drawable.preference_highlight_default;
-    }
-
-    public HighlightablePreferenceGroupAdapter(PreferenceGroup preferenceGroup,
-            @DrawableRes int normalBackgroundRes, @DrawableRes int highlightBackgroundRes) {
-        super(preferenceGroup);
-        mNormalBackgroundRes = normalBackgroundRes;
-        mHighlightBackgroundRes = highlightBackgroundRes;
     }
 
     @Override
@@ -112,16 +90,14 @@ public class HighlightablePreferenceGroupAdapter extends PreferenceGroupAdapter
     }
 
     private void addHighlightBackground(View v) {
-        v.setTag(R.id.preference_highlighted, true);
-        v.setBackgroundResource(mHighlightBackgroundRes);
+        v.setActivated(true);
     }
 
     private void removeHighlightBackground(View v) {
-        v.setTag(R.id.preference_highlighted, false);
-        v.setBackgroundResource(mNormalBackgroundRes);
+        v.setActivated(false);
     }
 
     private boolean hasHighlightBackground(View v) {
-        return Boolean.TRUE.equals(v.getTag(R.id.preference_highlighted));
+        return v.isActivated();
     }
 }
diff --git a/src/com/android/car/settings/common/TopLevelMenuFragment.java b/src/com/android/car/settings/common/TopLevelMenuFragment.java
index 0e99fdacc..e819535a1 100644
--- a/src/com/android/car/settings/common/TopLevelMenuFragment.java
+++ b/src/com/android/car/settings/common/TopLevelMenuFragment.java
@@ -178,9 +178,7 @@ public class TopLevelMenuFragment extends SettingsFragment {
     @Override
     protected HighlightablePreferenceGroupAdapter createHighlightableAdapter(
             PreferenceScreen preferenceScreen) {
-        return new HighlightablePreferenceGroupAdapter(preferenceScreen,
-                R.drawable.top_level_preference_background,
-                R.drawable.top_level_preference_highlight);
+        return new HighlightablePreferenceGroupAdapter(preferenceScreen);
     }
 
     private void updatePreferenceHighlight(String key) {
diff --git a/src/com/android/car/settings/datausage/AppDataUsageFragment.java b/src/com/android/car/settings/datausage/AppDataUsageFragment.java
index 0d9efcc80..97708f3bc 100644
--- a/src/com/android/car/settings/datausage/AppDataUsageFragment.java
+++ b/src/com/android/car/settings/datausage/AppDataUsageFragment.java
@@ -136,7 +136,7 @@ public class AppDataUsageFragment extends SettingsFragment implements
     @VisibleForTesting
     NetworkTemplate getNetworkTemplate(Context context, int subId) {
         TelephonyManager telephonyManager = context.getSystemService(TelephonyManager.class);
-        return DataUsageUtils.getMobileNetworkTemplate(telephonyManager, subId);
+        return DataUsageUtils.getMobileNetworkTemplate(context, telephonyManager, subId);
     }
 
     @VisibleForTesting
diff --git a/src/com/android/car/settings/datausage/AppSpecificDataUsageFragment.java b/src/com/android/car/settings/datausage/AppSpecificDataUsageFragment.java
index c0e97feca..4e5101275 100644
--- a/src/com/android/car/settings/datausage/AppSpecificDataUsageFragment.java
+++ b/src/com/android/car/settings/datausage/AppSpecificDataUsageFragment.java
@@ -79,7 +79,7 @@ public class AppSpecificDataUsageFragment extends SettingsFragment implements
             TelephonyManager telephonyManager = context.getSystemService(TelephonyManager.class);
             SubscriptionManager subscriptionManager =
                     context.getSystemService(SubscriptionManager.class);
-            networkTemplate = DataUsageUtils.getMobileNetworkTemplate(telephonyManager,
+            networkTemplate = DataUsageUtils.getMobileNetworkTemplate(context, telephonyManager,
                     DataUsageUtils.getDefaultSubscriptionId(subscriptionManager));
         }
 
diff --git a/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragment.java b/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragment.java
index 69e4cc91f..8dc5e04df 100644
--- a/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragment.java
+++ b/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragment.java
@@ -86,7 +86,7 @@ public abstract class DataUsageSetThresholdBaseFragment extends SettingsFragment
         if (mNetworkTemplate == null) {
             mTelephonyManager = context.getSystemService(TelephonyManager.class);
             mSubscriptionManager = context.getSystemService(SubscriptionManager.class);
-            mNetworkTemplate = DataUsageUtils.getMobileNetworkTemplate(mTelephonyManager,
+            mNetworkTemplate = DataUsageUtils.getMobileNetworkTemplate(context, mTelephonyManager,
                     DataUsageUtils.getDefaultSubscriptionId(mSubscriptionManager));
         }
 
diff --git a/src/com/android/car/settings/datausage/DataUsageUtils.java b/src/com/android/car/settings/datausage/DataUsageUtils.java
index 8bd823037..0003d8d77 100644
--- a/src/com/android/car/settings/datausage/DataUsageUtils.java
+++ b/src/com/android/car/settings/datausage/DataUsageUtils.java
@@ -16,6 +16,8 @@
 
 package com.android.car.settings.datausage;
 
+import static android.content.pm.PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION;
+
 import android.content.Context;
 import android.net.NetworkStats;
 import android.net.NetworkTemplate;
@@ -50,8 +52,11 @@ public final class DataUsageUtils {
     /**
      * Returns the mobile network template given the subscription id.
      */
-    public static NetworkTemplate getMobileNetworkTemplate(TelephonyManager telephonyManager,
-            int subscriptionId) {
+    public static NetworkTemplate getMobileNetworkTemplate(Context context,
+            TelephonyManager telephonyManager, int subscriptionId) {
+        if (!context.getPackageManager().hasSystemFeature(FEATURE_TELEPHONY_SUBSCRIPTION)) {
+            return null;
+        }
         String subscriberId = telephonyManager.getSubscriberId(subscriptionId);
         NetworkTemplate.Builder builder =
                 new NetworkTemplate.Builder(NetworkTemplate.MATCH_MOBILE)
diff --git a/src/com/android/car/settings/datausage/DataWarningAndLimitFragment.java b/src/com/android/car/settings/datausage/DataWarningAndLimitFragment.java
index f7dd534f2..a7891c2a1 100644
--- a/src/com/android/car/settings/datausage/DataWarningAndLimitFragment.java
+++ b/src/com/android/car/settings/datausage/DataWarningAndLimitFragment.java
@@ -74,7 +74,7 @@ public class DataWarningAndLimitFragment extends SettingsFragment {
         if (mNetworkTemplate == null) {
             mTelephonyManager = context.getSystemService(TelephonyManager.class);
             mSubscriptionManager = context.getSystemService(SubscriptionManager.class);
-            mNetworkTemplate = DataUsageUtils.getMobileNetworkTemplate(mTelephonyManager,
+            mNetworkTemplate = DataUsageUtils.getMobileNetworkTemplate(context, mTelephonyManager,
                     DataUsageUtils.getDefaultSubscriptionId(mSubscriptionManager));
         }
 
diff --git a/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImpl.java b/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImpl.java
index 06f806e54..7fe0a0c24 100644
--- a/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImpl.java
+++ b/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImpl.java
@@ -87,6 +87,12 @@ final class DeviceAdminStringProviderImpl implements DeviceAdminStringProvider {
                 "disabled_by_policy_title_biometric_parental_consent not used on automotive");
     }
 
+    @Override
+    public String getDisabledByParentalControlsTitle() {
+        throw new UnsupportedOperationException(
+                "disabled_by_policy_title_parental_controls not used on automotive");
+    }
+
     @Override
     public String getDisabledByParentContent() {
         throw new UnsupportedOperationException(
diff --git a/src/com/android/car/settings/network/MobileNetworkEntryPreferenceController.java b/src/com/android/car/settings/network/MobileNetworkEntryPreferenceController.java
index 9d6ba3a56..f0220f900 100644
--- a/src/com/android/car/settings/network/MobileNetworkEntryPreferenceController.java
+++ b/src/com/android/car/settings/network/MobileNetworkEntryPreferenceController.java
@@ -247,7 +247,7 @@ public class MobileNetworkEntryPreferenceController extends
     }
 
     @Override
-    public void onChange(int value) {
+    public void onStatusChanged(int value) {
         refreshUi();
     }
 }
diff --git a/src/com/android/car/settings/network/NetworkBasePreferenceController.java b/src/com/android/car/settings/network/NetworkBasePreferenceController.java
index c17117f47..c3aad500a 100644
--- a/src/com/android/car/settings/network/NetworkBasePreferenceController.java
+++ b/src/com/android/car/settings/network/NetworkBasePreferenceController.java
@@ -65,6 +65,7 @@ public abstract class NetworkBasePreferenceController<V extends Preference> exte
     public void setFields(int subId) {
         mSubId = subId;
         mTelephonyManager = TelephonyManager.from(getContext()).createForSubscriptionId(mSubId);
-        mNetworkTemplate = DataUsageUtils.getMobileNetworkTemplate(mTelephonyManager, subId);
+        mNetworkTemplate = DataUsageUtils.getMobileNetworkTemplate(
+                getContext(), mTelephonyManager, subId);
     }
 }
diff --git a/src/com/android/car/settings/network/RoamingPreferenceController.java b/src/com/android/car/settings/network/RoamingPreferenceController.java
index 4aefaafba..df2b94030 100644
--- a/src/com/android/car/settings/network/RoamingPreferenceController.java
+++ b/src/com/android/car/settings/network/RoamingPreferenceController.java
@@ -16,6 +16,8 @@
 
 package com.android.car.settings.network;
 
+import static android.content.pm.PackageManager.FEATURE_TELEPHONY_DATA;
+
 import android.car.drivingstate.CarUxRestrictions;
 import android.content.Context;
 import android.database.ContentObserver;
@@ -78,9 +80,14 @@ public class RoamingPreferenceController extends
 
     @Override
     protected void updateState(TwoStatePreference preference) {
-        preference.setEnabled(getSubId() != SubscriptionManager.INVALID_SUBSCRIPTION_ID);
-        preference.setChecked(getTelephonyManager() != null
-                ? getTelephonyManager().isDataRoamingEnabled() : false);
+        if (getContext().getPackageManager().hasSystemFeature(FEATURE_TELEPHONY_DATA)) {
+            preference.setEnabled(getSubId() != SubscriptionManager.INVALID_SUBSCRIPTION_ID);
+            preference.setChecked(getTelephonyManager() != null
+                    ? getTelephonyManager().isDataRoamingEnabled() : false);
+            return;
+        }
+        preference.setEnabled(false);
+        preference.setChecked(false);
     }
 
     @Override
diff --git a/src/com/android/car/settings/profiles/AddProfileHandler.java b/src/com/android/car/settings/profiles/AddProfileHandler.java
index 11d0203ef..9948beefb 100644
--- a/src/com/android/car/settings/profiles/AddProfileHandler.java
+++ b/src/com/android/car/settings/profiles/AddProfileHandler.java
@@ -17,6 +17,7 @@
 package com.android.car.settings.profiles;
 
 import static android.os.UserManager.DISALLOW_ADD_USER;
+import static android.os.UserManager.USER_TYPE_FULL_SECONDARY;
 
 import static com.android.car.settings.common.PreferenceController.AVAILABLE;
 import static com.android.car.settings.common.PreferenceController.AVAILABLE_FOR_VIEWING;
@@ -196,7 +197,7 @@ public class AddProfileHandler implements AddNewProfileTask.AddNewProfileListene
             // Shows a dialog if this PreferenceController is disabled because there is
             // restriction set from DevicePolicyManager
             showActionDisabledByAdminDialog();
-        } else if (!getUserManager(mContext).canAddMoreUsers()) {
+        } else if (!canAddMoreUsers()) {
             // Shows a dialog if no more profiles can be added because the maximum allowed number
             // is reached
             ConfirmationDialogFragment dialogFragment =
@@ -219,6 +220,14 @@ public class AddProfileHandler implements AddNewProfileTask.AddNewProfileListene
         return context.getSystemService(UserManager.class);
     }
 
+    private boolean canAddMoreUsers() {
+        if (android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+            return getUserManager(mContext).canAddMoreUsers(USER_TYPE_FULL_SECONDARY);
+        } else {
+            return getUserManager(mContext).canAddMoreUsersLegacy();
+        }
+    }
+
     @VisibleForTesting
     void setCarUserManager(CarUserManager carUserManager) {
         mCarUserManager = carUserManager;
diff --git a/src/com/android/car/settings/profiles/AddProfilePreferenceController.java b/src/com/android/car/settings/profiles/AddProfilePreferenceController.java
index 23dc82c54..620764f15 100644
--- a/src/com/android/car/settings/profiles/AddProfilePreferenceController.java
+++ b/src/com/android/car/settings/profiles/AddProfilePreferenceController.java
@@ -16,6 +16,8 @@
 
 package com.android.car.settings.profiles;
 
+import static android.os.UserManager.USER_TYPE_FULL_SECONDARY;
+
 import static com.android.car.settings.enterprise.EnterpriseUtils.hasUserRestrictionByDpm;
 
 import android.car.drivingstate.CarUxRestrictions;
@@ -95,7 +97,7 @@ public class AddProfilePreferenceController extends PreferenceController<Prefere
             return true;
         }
 
-        if (!mUserManager.canAddMoreUsers()
+        if (!canAddMoreUsers()
                 || hasUserRestrictionByDpm(getContext(), UserManager.DISALLOW_ADD_USER)) {
             mAddProfileHandler.runClickableWhileDisabled();
             return true;
@@ -116,6 +118,14 @@ public class AddProfilePreferenceController extends PreferenceController<Prefere
                 .getAddProfilePreferenceAvailabilityStatus(getContext());
     }
 
+    private boolean canAddMoreUsers() {
+        if (android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+            return mUserManager.canAddMoreUsers(USER_TYPE_FULL_SECONDARY);
+        } else {
+            return mUserManager.canAddMoreUsersLegacy();
+        }
+    }
+
     @VisibleForTesting
     void setUserManager(UserManager userManager) {
         mUserManager = userManager;
diff --git a/src/com/android/car/settings/profiles/ProfileGridRecyclerView.java b/src/com/android/car/settings/profiles/ProfileGridRecyclerView.java
index 54d1e71f2..7ac3d422c 100644
--- a/src/com/android/car/settings/profiles/ProfileGridRecyclerView.java
+++ b/src/com/android/car/settings/profiles/ProfileGridRecyclerView.java
@@ -18,6 +18,7 @@ package com.android.car.settings.profiles;
 
 import static android.os.UserManager.DISALLOW_ADD_USER;
 import static android.os.UserManager.SWITCHABILITY_STATUS_OK;
+import static android.os.UserManager.USER_TYPE_FULL_SECONDARY;
 
 import android.annotation.IntDef;
 import android.app.Activity;
@@ -414,7 +415,7 @@ public class ProfileGridRecyclerView extends RecyclerView {
         }
 
         private void handleAddProfileClicked(View addProfileView) {
-            if (!mUserManager.canAddMoreUsers()) {
+            if (!canAddMoreUsers()) {
                 showMaxProfilesLimitReachedDialog();
             } else {
                 mAddProfileView = addProfileView;
@@ -424,6 +425,14 @@ public class ProfileGridRecyclerView extends RecyclerView {
             }
         }
 
+        private boolean canAddMoreUsers() {
+            if (android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+                return mUserManager.canAddMoreUsers(USER_TYPE_FULL_SECONDARY);
+            } else {
+                return mUserManager.canAddMoreUsersLegacy();
+            }
+        }
+
         private void showMaxProfilesLimitReachedDialog() {
             ConfirmationDialogFragment dialogFragment =
                     ProfilesDialogProvider.getMaxProfilesLimitReachedDialogFragment(getContext(),
diff --git a/src/com/android/car/settings/profiles/ProfileHelper.java b/src/com/android/car/settings/profiles/ProfileHelper.java
index 931901dbf..e2b83cb55 100644
--- a/src/com/android/car/settings/profiles/ProfileHelper.java
+++ b/src/com/android/car/settings/profiles/ProfileHelper.java
@@ -457,6 +457,11 @@ public class ProfileHelper {
         return mUserManager.getUserInfo(UserHandle.myUserId());
     }
 
+    private static boolean areMaxUsersMethodFlagsEnabled() {
+        return android.multiuser.Flags.consistentMaxUsers()
+                && android.multiuser.Flags.maxUsersInCarIsForSecondary();
+    }
+
     /**
      * Maximum number of profiles allowed on the device. This includes real profiles, managed
      * profiles and restricted profiles, but excludes guests.
@@ -464,8 +469,15 @@ public class ProfileHelper {
      * <p> It excludes system profile in headless system profile model.
      *
      * @return Maximum number of profiles that can be present on the device.
+     * @deprecated Use {@link #getMaxSupportedRealProfiles()} instead.
      */
+    @Deprecated
     private int getMaxSupportedProfiles() {
+        if (areMaxUsersMethodFlagsEnabled()) {
+            // TODO(b/394178333): When the flags are permanent, delete this method entirely.
+            throw new UnsupportedOperationException("This method is no longer supported");
+        }
+
         int maxSupportedUsers = UserManager.getMaxSupportedUsers();
         if (UserManager.isHeadlessSystemUserMode()) {
             maxSupportedUsers -= 1;
@@ -474,6 +486,11 @@ public class ProfileHelper {
     }
 
     private int getManagedProfilesCount() {
+        if (areMaxUsersMethodFlagsEnabled()) {
+            // TODO(b/394178333): When the flags are permanent, delete this method entirely.
+            throw new UnsupportedOperationException("This method is no longer supported");
+        }
+
         List<UserInfo> users = getAllProfiles();
 
         // Count all users that are managed profiles of another user.
@@ -496,7 +513,12 @@ public class ProfileHelper {
      * @return Maximum number of real profiles that can be created.
      */
     public int getMaxSupportedRealProfiles() {
-        return getMaxSupportedProfiles() - getManagedProfilesCount();
+        if (!areMaxUsersMethodFlagsEnabled()) {
+            return getMaxSupportedProfiles() - getManagedProfilesCount();
+        }
+        // "Real" users means secondary users and - for non-HSUM devices - the full system user.
+        return mUserManager.getCurrentAllowedNumberOfUsers(UserManager.USER_TYPE_FULL_SECONDARY)
+                + (UserManager.isHeadlessSystemUserMode() ? 0 : 1);
     }
 
     /**
diff --git a/src/com/android/car/settings/qc/MobileDataBaseWorker.java b/src/com/android/car/settings/qc/MobileDataBaseWorker.java
index 34e1ce462..44df9bf30 100644
--- a/src/com/android/car/settings/qc/MobileDataBaseWorker.java
+++ b/src/com/android/car/settings/qc/MobileDataBaseWorker.java
@@ -131,7 +131,7 @@ public abstract class MobileDataBaseWorker<E extends SettingsQCItem>
     }
 
     @Override
-    public void onChange(int value) {
+    public void onStatusChanged(int value) {
         if (getQCItem() != null) {
             notifyQCItemChange();
         }
diff --git a/src/com/android/car/settings/storage/StorageSystemCategoryPreferenceController.java b/src/com/android/car/settings/storage/StorageSystemCategoryPreferenceController.java
index 4c18d2253..9ca04fef8 100644
--- a/src/com/android/car/settings/storage/StorageSystemCategoryPreferenceController.java
+++ b/src/com/android/car/settings/storage/StorageSystemCategoryPreferenceController.java
@@ -21,6 +21,7 @@ import android.content.Context;
 import android.os.Build;
 import android.util.DataUnit;
 import android.util.SparseArray;
+import android.icu.util.MeasureUnit;
 
 import com.android.car.settings.R;
 import com.android.car.settings.common.ConfirmationDialogFragment;
@@ -58,6 +59,17 @@ public class StorageSystemCategoryPreferenceController extends
         return Math.max(DataUnit.GIBIBYTES.toBytes(1), usedSizeBytes - attributedSize);
     }
 
+    @Override
+    protected void setStorageSize(long size, long total) {
+        super.setStorageSize(size, total);
+        getPreference().setMaxLabel(getContext().getString(R.string.storage_total_label,
+                FileSizeFormatter.formatFileSize(
+                getContext(),
+                total,
+                MeasureUnit.GIGABYTE,
+                FileSizeFormatter.GIGABYTE_IN_BYTES)));
+    }
+
     @Override
     protected boolean handlePreferenceClicked(ProgressBarPreference preference) {
         getFragmentController().showDialog(
diff --git a/src/com/android/car/settings/storage/StorageUsageBasePreferenceController.java b/src/com/android/car/settings/storage/StorageUsageBasePreferenceController.java
index 8d33963f4..1cf01dde4 100644
--- a/src/com/android/car/settings/storage/StorageUsageBasePreferenceController.java
+++ b/src/com/android/car/settings/storage/StorageUsageBasePreferenceController.java
@@ -82,8 +82,11 @@ public abstract class StorageUsageBasePreferenceController extends
     /**
      * Sets the storage size for this preference that will be displayed as a summary. It will also
      * update the progress bar accordingly.
+     *
+     * <p>Subclass may extend this method to update the preference with category specific
+     * information, such as setMaxLabel or summary.
      */
-    private void setStorageSize(long size, long total) {
+    protected void setStorageSize(long size, long total) {
         getPreference().setSummary(
                 FileSizeFormatter.formatFileSize(
                         getContext(),
diff --git a/src/com/android/car/settings/units/CarUnitsManager.java b/src/com/android/car/settings/units/CarUnitsManager.java
index c89eb6895..44f9df4e9 100644
--- a/src/com/android/car/settings/units/CarUnitsManager.java
+++ b/src/com/android/car/settings/units/CarUnitsManager.java
@@ -20,7 +20,6 @@ import android.car.Car;
 import android.car.CarNotConnectedException;
 import android.car.VehiclePropertyIds;
 import android.car.VehicleUnit;
-import android.car.feature.Flags;
 import android.car.hardware.CarPropertyConfig;
 import android.car.hardware.property.CarPropertyManager;
 import android.content.Context;
@@ -97,8 +96,7 @@ public class CarUnitsManager {
 
         // Checks if the property is read-write property. Checking only one area Id because _UNITS
         // properties are global properties.
-        if ((Flags.areaIdConfigAccess() ? configs.get(0).getAreaIdConfig(0).getAccess()
-                : configs.get(0).getAccess())
+        if (configs.get(0).getAreaIdConfig(0).getAccess()
                 != CarPropertyConfig.VEHICLE_PROPERTY_ACCESS_READ_WRITE) {
             return null;
         }
diff --git a/src/com/android/car/settings/wifi/WifiTetherPersistentOnPreferenceController.java b/src/com/android/car/settings/wifi/WifiTetherPersistentOnPreferenceController.java
index 733ff8484..381daaf64 100644
--- a/src/com/android/car/settings/wifi/WifiTetherPersistentOnPreferenceController.java
+++ b/src/com/android/car/settings/wifi/WifiTetherPersistentOnPreferenceController.java
@@ -19,7 +19,6 @@ package com.android.car.settings.wifi;
 import static android.car.settings.CarSettings.Global.ENABLE_PERSISTENT_TETHERING;
 
 import android.car.drivingstate.CarUxRestrictions;
-import android.car.feature.Flags;
 import android.car.wifi.CarWifiManager;
 import android.content.Context;
 import android.provider.Settings;
@@ -55,9 +54,6 @@ public class WifiTetherPersistentOnPreferenceController extends
 
     @Override
     protected int getDefaultAvailabilityStatus() {
-        if (!Flags.persistApSettings()) {
-            return UNSUPPORTED_ON_DEVICE;
-        }
         CarWifiManager carWifiManager = getCarWifiManager();
         if (carWifiManager != null && carWifiManager.canControlPersistTetheringSettings()) {
             return AVAILABLE;
diff --git a/tests/deviceless/src/com/android/car/settings/profiles/ProfileHelperTest.java b/tests/deviceless/src/com/android/car/settings/profiles/ProfileHelperTest.java
index a7638c2f0..de01c721c 100644
--- a/tests/deviceless/src/com/android/car/settings/profiles/ProfileHelperTest.java
+++ b/tests/deviceless/src/com/android/car/settings/profiles/ProfileHelperTest.java
@@ -23,6 +23,7 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
@@ -426,6 +427,15 @@ public class ProfileHelperTest {
     @Test
     public void testGetMaxSupportedRealUsers_isHeadless() {
         ShadowUserManager.setIsHeadlessSystemUserMode(true);
+
+        if (android.multiuser.Flags.consistentMaxUsers()
+                && android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+            when(mMockUserManager.getCurrentAllowedNumberOfUsers(
+                    eq(UserManager.USER_TYPE_FULL_SECONDARY))).thenReturn(4);
+            assertThat(mProfileHelper.getMaxSupportedRealProfiles()).isEqualTo(4);
+            return;
+        }
+
         ShadowUserManager.setMaxSupportedUsersCount(7);
 
         // Create System user, two managed profiles, and two normal users.
@@ -444,6 +454,16 @@ public class ProfileHelperTest {
     @Test
     public void testGetMaxSupportedRealUsers_isNotHeadless() {
         ShadowUserManager.setIsHeadlessSystemUserMode(false);
+
+        if (android.multiuser.Flags.consistentMaxUsers()
+                && android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+            when(mMockUserManager.getCurrentAllowedNumberOfUsers(
+                    eq(UserManager.USER_TYPE_FULL_SECONDARY))).thenReturn(4);
+            // The system user counts as a real user, so add it as well.
+            assertThat(mProfileHelper.getMaxSupportedRealProfiles()).isEqualTo(5);
+            return;
+        }
+
         ShadowUserManager.setMaxSupportedUsersCount(7);
 
         // Create System user, two managed profiles, and two normal users.
diff --git a/tests/helpers/src/com/android/car/settings/testutils/ShadowLocalBroadcastManager.java b/tests/helpers/src/com/android/car/settings/testutils/ShadowLocalBroadcastManager.java
index 54bbe71c2..df21eecbb 100644
--- a/tests/helpers/src/com/android/car/settings/testutils/ShadowLocalBroadcastManager.java
+++ b/tests/helpers/src/com/android/car/settings/testutils/ShadowLocalBroadcastManager.java
@@ -28,7 +28,6 @@ import org.robolectric.RuntimeEnvironment;
 import org.robolectric.annotation.Implementation;
 import org.robolectric.annotation.Implements;
 import org.robolectric.annotation.Resetter;
-import org.robolectric.shadows.ShadowApplication;
 import org.robolectric.util.ReflectionHelpers;
 import org.robolectric.util.ReflectionHelpers.ClassParameter;
 
@@ -43,9 +42,8 @@ public class ShadowLocalBroadcastManager {
 
     @Implementation
     public static LocalBroadcastManager getInstance(final Context context) {
-        return ShadowApplication.getInstance().getSingleton(LocalBroadcastManager.class,
-                () -> ReflectionHelpers.callConstructor(LocalBroadcastManager.class,
-                        ClassParameter.from(Context.class, context)));
+        return ReflectionHelpers.callConstructor(LocalBroadcastManager.class,
+                        ClassParameter.from(Context.class, context));
     }
 
     @Implementation
diff --git a/tests/helpers/src/com/android/car/settings/testutils/ShadowUserManager.java b/tests/helpers/src/com/android/car/settings/testutils/ShadowUserManager.java
index df43df736..99c21d051 100644
--- a/tests/helpers/src/com/android/car/settings/testutils/ShadowUserManager.java
+++ b/tests/helpers/src/com/android/car/settings/testutils/ShadowUserManager.java
@@ -88,6 +88,11 @@ public class ShadowUserManager extends org.robolectric.shadows.ShadowUserManager
         return sCanAddMoreUsers;
     }
 
+    @Implementation
+    protected static boolean canAddMoreUsers(String userType) {
+        return sCanAddMoreUsers;
+    }
+
     public static void setCanAddMoreUsers(boolean isEnabled) {
         sCanAddMoreUsers = isEnabled;
     }
diff --git a/tests/multivalent/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragmentTest.java b/tests/multivalent/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragmentTest.java
index 26e725622..bf9c6622e 100644
--- a/tests/multivalent/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragmentTest.java
+++ b/tests/multivalent/src/com/android/car/settings/datausage/DataUsageSetThresholdBaseFragmentTest.java
@@ -97,7 +97,7 @@ public class DataUsageSetThresholdBaseFragmentTest {
     @UiThreadTest
     public void onActivityCreated_noTemplateSet_getsDefaultTemplate() throws Throwable {
         when(DataUsageUtils.getDefaultSubscriptionId(any())).thenReturn(SUB_ID);
-        when(DataUsageUtils.getMobileNetworkTemplate(any(), eq(SUB_ID)))
+        when(DataUsageUtils.getMobileNetworkTemplate(mContext, any(), eq(SUB_ID)))
                 .thenReturn(mMockNetworkTemplate);
         setUpFragment(/* useTemplate= */ false, /* initialBytes= */ MIB_IN_BYTES);
 
diff --git a/tests/multivalent/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImplTest.java b/tests/multivalent/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImplTest.java
index c18fde2c8..491573fe0 100644
--- a/tests/multivalent/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImplTest.java
+++ b/tests/multivalent/src/com/android/car/settings/enterprise/DeviceAdminStringProviderImplTest.java
@@ -111,4 +111,13 @@ public class DeviceAdminStringProviderImplTest {
         assertThat(e.getMessage())
                 .contains("disabled_by_policy_content_biometric_parental_consent");
     }
+
+    @Test
+    public void testDisabledByParentalControlsTitle() {
+        UnsupportedOperationException e =
+                expectThrows(
+                        UnsupportedOperationException.class,
+                        () -> mDeviceAdminStringProvider.getDisabledByParentalControlsTitle());
+        assertThat(e.getMessage()).contains("disabled_by_policy_title_parental_controls");
+    }
 }
diff --git a/tests/multivalent/src/com/android/car/settings/network/NetworkBasePreferenceControllerTest.java b/tests/multivalent/src/com/android/car/settings/network/NetworkBasePreferenceControllerTest.java
index 08fe8d386..6c3e5510c 100644
--- a/tests/multivalent/src/com/android/car/settings/network/NetworkBasePreferenceControllerTest.java
+++ b/tests/multivalent/src/com/android/car/settings/network/NetworkBasePreferenceControllerTest.java
@@ -72,7 +72,8 @@ public class NetworkBasePreferenceControllerTest {
         ExtendedMockito.when(TelephonyManager.from(mContext)).thenReturn(mMockTelephonyManager);
         when(mMockTelephonyManager.createForSubscriptionId(SUB_ID))
                 .thenReturn(mMockTelephonyManager);
-        ExtendedMockito.when(DataUsageUtils.getMobileNetworkTemplate(mMockTelephonyManager, SUB_ID))
+        ExtendedMockito.when(DataUsageUtils.getMobileNetworkTemplate(mContext,
+                        mMockTelephonyManager, SUB_ID))
                 .thenReturn(mMockNetworkTemplate);
 
         mCarUxRestrictions = new CarUxRestrictions.Builder(/* reqOpt= */ true,
diff --git a/tests/multivalent/src/com/android/car/settings/profiles/AddProfilePreferenceControllerTest.java b/tests/multivalent/src/com/android/car/settings/profiles/AddProfilePreferenceControllerTest.java
index 7ae3ebc16..ab9c5e44f 100644
--- a/tests/multivalent/src/com/android/car/settings/profiles/AddProfilePreferenceControllerTest.java
+++ b/tests/multivalent/src/com/android/car/settings/profiles/AddProfilePreferenceControllerTest.java
@@ -26,6 +26,7 @@ import static com.android.car.settings.profiles.AddProfilePreferenceController.M
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
@@ -159,7 +160,8 @@ public class AddProfilePreferenceControllerTest {
     @Test
     public void onCreate_userRestrictedByDpmFromAddingNewProfileAndNotInDemo_availableForViewing() {
         when(mUserManager.isDemoUser()).thenReturn(false);
-        when(mUserManager.canAddMoreUsers()).thenReturn(true);
+        when(mUserManager.canAddMoreUsersLegacy()).thenReturn(true);
+        when(mUserManager.canAddMoreUsers(anyString())).thenReturn(true);
         EnterpriseTestUtils
                 .mockUserRestrictionSetByDpm(mUserManager, TEST_RESTRICTION, true);
 
@@ -171,7 +173,8 @@ public class AddProfilePreferenceControllerTest {
     @Test
     public void onCreate_addingNewProfileAndNotInDemo_availableForViewing_zoneWrite() {
         when(mUserManager.isDemoUser()).thenReturn(false);
-        when(mUserManager.canAddMoreUsers()).thenReturn(true);
+        when(mUserManager.canAddMoreUsersLegacy()).thenReturn(true);
+        when(mUserManager.canAddMoreUsers(anyString())).thenReturn(true);
         EnterpriseTestUtils
                 .mockUserRestrictionSetByDpm(mUserManager, TEST_RESTRICTION, true);
 
@@ -185,7 +188,8 @@ public class AddProfilePreferenceControllerTest {
     @Test
     public void onCreate_addingNewProfileAndNotInDemo_availableForViewing_zoneRead() {
         when(mUserManager.isDemoUser()).thenReturn(false);
-        when(mUserManager.canAddMoreUsers()).thenReturn(true);
+        when(mUserManager.canAddMoreUsersLegacy()).thenReturn(true);
+        when(mUserManager.canAddMoreUsers(anyString())).thenReturn(true);
         EnterpriseTestUtils
                 .mockUserRestrictionSetByDpm(mUserManager, TEST_RESTRICTION, true);
 
@@ -199,7 +203,8 @@ public class AddProfilePreferenceControllerTest {
     @Test
     public void onCreate_addingNewProfileAndNotInDemo_availableForViewing_zoneHidden() {
         when(mUserManager.isDemoUser()).thenReturn(false);
-        when(mUserManager.canAddMoreUsers()).thenReturn(true);
+        when(mUserManager.canAddMoreUsersLegacy()).thenReturn(true);
+        when(mUserManager.canAddMoreUsers(anyString())).thenReturn(true);
         EnterpriseTestUtils
                 .mockUserRestrictionSetByDpm(mUserManager, TEST_RESTRICTION, true);
 
@@ -275,7 +280,8 @@ public class AddProfilePreferenceControllerTest {
         when(mUserManager.isDemoUser()).thenReturn(false);
         EnterpriseTestUtils
                 .mockUserRestrictionSetByUm(mUserManager, TEST_RESTRICTION, false);
-        when(mUserManager.canAddMoreUsers()).thenReturn(false);
+        when(mUserManager.canAddMoreUsersLegacy()).thenReturn(true);
+        when(mUserManager.canAddMoreUsers(anyString())).thenReturn(false);
 
         mPreferenceController.onCreate(mLifecycleOwner);
         mPreference.performClick();
@@ -288,7 +294,8 @@ public class AddProfilePreferenceControllerTest {
     @UiThreadTest
     public void disabledClick_restrictedByDpm_dialog() {
         when(mUserManager.isDemoUser()).thenReturn(false);
-        when(mUserManager.canAddMoreUsers()).thenReturn(true);
+        when(mUserManager.canAddMoreUsersLegacy()).thenReturn(true);
+        when(mUserManager.canAddMoreUsers(anyString())).thenReturn(true);
         EnterpriseTestUtils
                 .mockUserRestrictionSetByDpm(mUserManager, TEST_RESTRICTION, true);
 
diff --git a/tests/multivalent/src/com/android/car/settings/sound/AudioRouteSelectorControllerTest.java b/tests/multivalent/src/com/android/car/settings/sound/AudioRouteSelectorControllerTest.java
index a9c588808..c0d07a908 100644
--- a/tests/multivalent/src/com/android/car/settings/sound/AudioRouteSelectorControllerTest.java
+++ b/tests/multivalent/src/com/android/car/settings/sound/AudioRouteSelectorControllerTest.java
@@ -27,10 +27,8 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.car.drivingstate.CarUxRestrictions;
-import android.car.feature.Flags;
 import android.car.media.CarAudioManager;
 import android.content.Context;
-import android.platform.test.flag.junit.SetFlagsRule;
 import android.widget.Toast;
 
 import androidx.lifecycle.LifecycleOwner;
@@ -46,7 +44,6 @@ import com.android.dx.mockito.inline.extended.ExtendedMockito;
 
 import org.junit.After;
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
@@ -82,12 +79,8 @@ public class AudioRouteSelectorControllerTest {
     @Mock
     private Toast mMockToast;
 
-    @Rule
-    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
-
     @Before
     public void setUp() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CAR_AUDIO_DYNAMIC_DEVICES);
         mLifecycleOwner = new TestLifecycleOwner();
 
         mSession = ExtendedMockito.mockitoSession()
```

