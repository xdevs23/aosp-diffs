```diff
diff --git a/Android.bp b/Android.bp
index 552a69a..74a7f36 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,23 +14,47 @@ license {
     ],
 }
 
-android_app {
-    name: "PrivateSpace",
-    certificate: "platform",
-    platform_apis: true,
-    privileged: true,
-    optimize: {
-        enabled: true,
-    },
+android_library {
+    name: "PrivateSpaceLibrary",
+    manifest: "AndroidManifest.xml",
     srcs: [
         "src/**/*.kt",
+        ":statslog-privatespace-java-gen",
     ],
-    resource_dirs: ["res"],
     static_libs: [
         "androidx.appcompat_appcompat",
         "androidx.compose.foundation_foundation",
         "androidx.compose.ui_ui",
         "androidx.compose.material3_material3",
         "androidx.compose.runtime_runtime",
+        "androidx.datastore_datastore-preferences",
+    ],
+    resource_dirs: ["res"],
+    platform_apis: true,
+    flags_packages: [
+        "android.multiuser.flags-aconfig",
+    ],
+}
+
+android_app {
+    name: "PrivateSpace",
+    certificate: "platform",
+    privileged: true,
+    platform_apis: true,
+    optimize: {
+        enabled: true,
+        optimize: true,
+        shrink_resources: true,
+    },
+    static_libs: [
+        "PrivateSpaceLibrary",
     ],
 }
+
+genrule {
+    name: "statslog-privatespace-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module privatespace" +
+        " --javaPackage com.android.privatespace --javaClass PrivateSpaceStatsLog",
+    out: ["com/android/privatespace/logging/PrivateSpaceStatsLog.java"],
+}
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index dbc72a8..2a74741 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -20,14 +20,17 @@
     package="com.android.privatespace">
 
     <application
-        android:label="@string/private_space_app_label">
+        android:label="@string/private_space_app_label"
+        android:icon="@mipmap/ic_app_icon">
         <activity android:name=".PrivateSpaceActivity"
             android:exported="true"
             android:theme="@style/Theme.TransparentActivity"
-            android:excludeFromRecents="true">
+            android:excludeFromRecents="true"
+            android:featureFlag="android.multiuser.enable_moving_content_into_private_space">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN" />
                 <category android:name="android.intent.category.LAUNCHER" />
+                <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
             <meta-data android:name="android.app.shortcuts"
                 android:resource="@xml/shortcuts" />
@@ -35,13 +38,24 @@
         <service
             android:name=".filetransfer.FileTransferService"
             android:exported="false"
-            android:foregroundServiceType="mediaProcessing" />
+            android:foregroundServiceType="mediaProcessing"
+            android:featureFlag="android.multiuser.enable_moving_content_into_private_space"/>
+
+        <receiver android:name=".BootCompletedBroadcastReceiver"
+            android:exported="false"
+            android:featureFlag="android.multiuser.enable_moving_content_into_private_space">
+            <intent-filter>
+                <action android:name="android.intent.action.BOOT_COMPLETED" />
+            </intent-filter>
+        </receiver>
 
     </application>
 
+    <uses-permission android:name="android.permission.ACCESS_HIDDEN_PROFILES_FULL" />
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING" />
     <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
+    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
 
     <uses-sdk android:minSdkVersion="36" android:targetSdkVersion="36" />
 </manifest>
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..bb00ada
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,12 @@
+{
+  "presubmit": [
+    {
+      "name": "PrivateSpaceTests"
+    }
+  ],
+  "postsubmit": [
+    {
+      "name": "PrivateSpaceIntegrationTests"
+    }
+  ]
+}
diff --git a/res/mipmap-anydpi-v26/ic_app_icon.xml b/res/mipmap-anydpi-v26/ic_app_icon.xml
new file mode 100644
index 0000000..5183ca0
--- /dev/null
+++ b/res/mipmap-anydpi-v26/ic_app_icon.xml
@@ -0,0 +1,39 @@
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
+<!-- TODO(b/406986798): check if we need to add the monochrome version of the icon. -->
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+    <background android:drawable="@android:color/white"/>
+    <foreground>
+        <vector
+            android:width="24dp"
+            android:height="24dp"
+            android:viewportWidth="24"
+            android:viewportHeight="24">
+            <group android:scaleX="0.6"
+                android:scaleY="0.6"
+                android:translateY="5"
+                android:translateX="5">
+                <path
+                    android:pathData="M12,2L4,5V11.09C4,16.14 7.41,20.85 12,22C16.59,20.85 20,16.14 20,11.09V5L12,2ZM15,15V17H13V18H11V12.84C9.56,12.41 8.5,11.09 8.5,9.5C8.5,7.57 10.07,6 12,6C13.93,6 15.5,7.57 15.5,9.5C15.5,11.08 14.44,12.41 13,12.84V15H15Z"
+                    android:fillColor="#3C4043"/>
+                <path
+                    android:pathData="M12,11C12.828,11 13.5,10.328 13.5,9.5C13.5,8.672 12.828,8 12,8C11.172,8 10.5,8.672 10.5,9.5C10.5,10.328 11.172,11 12,11Z"
+                    android:fillColor="#3C4043"/>
+            </group>
+        </vector>
+    </foreground>
+</adaptive-icon>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index bfd7414..ed86413 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Skuif"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopieer"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Kanselleer"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopieer tans <xliff:g id="FILES">%1$d</xliff:g> lêer(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Skuif tans <xliff:g id="FILES">%1$d</xliff:g> lêer(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> lêer(s) gekopieer"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> lêer(s) is geskuif"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Jou gekose lêers word tans na jou privaat ruimte gekopieer"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Jou gekose lêers word tans na jou privaat ruimte geskuif"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Jou gekose lêers is na jou privaat ruimte gekopieer"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Jou gekose lêers is na jou privaat ruimte geskuif"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopieer tans # lêer}other{Kopieer tans # lêers}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Skuif tans # lêer}other{Skuif tans # lêers}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# lêer is gekopieer}other{# lêers is gekopieer}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# lêer is geskuif}other{# lêers is geskuif}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Jou gekose lêers word tans na jou privaat ruimte gekopieer}other{Jou gekose lêers word tans na jou privaat ruimte gekopieer}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Jou gekose lêer word tans na jou privaat ruimte geskuif}other{Jou gekose lêers word tans na jou privaat ruimte geskuif}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Jou gekose lêer is na jou privaat ruimte gekopieer}other{Jou gekose lêers is na jou privaat ruimte gekopieer}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Jou gekose lêer is na jou privaat ruimte geskuif}other{Jou gekose lêers is na jou privaat ruimte geskuif}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Wys lêers"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Kennisgewings oor lêeroordrag"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Wanneer jy lêers na jou privaat ruimte kopieer of skuif, kan jy kennisgewings ontvang om jou op te dateer oor hoe dit vorder"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Kan sommige lêers nie kopieer nie"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Kan sommige lêers nie skuif nie"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Jy kan weer probeer om jou lêers te kopieer"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Jy kan weer probeer om jou lêers te skuif"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Koppel steeds lêers"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Skuif steeds lêers"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Jy kan nog lêers kopieer of skuif wanneer dit klaar is"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Kon nie lêers kopieer nie"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Kon nie lêers skuif nie"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Totale lêergrootte is te groot"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Jy kan net tot 2 GB op ’n slag kopieer of skuif"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Te veel lêers is gekies"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Jy kan net tot 100 lêers op ’n slag kopieer of skuif"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Kan nie lêers byvoeg nie"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Jy het nie genoeg toestelberging nie"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Maak spasie beskikbaar"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Kan nie lêers van privaat ruimte af kopieer of skuif nie"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Kon sommige lêers nie kopieer nie"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Kon sommige lêers nie skuif nie"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Jou privaat ruimte is toegemaak tydens kopiëring"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Jou privaat ruimte is toegemaak tydens skuiwing"</string>
 </resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index c637bcb..0f0a426 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"አንቀሳቅስ"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"ቅዳ"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ይቅር"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ፋይል(ሎች)ን በመቅዳት ላይ"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ፋይል(ሎች)ን በማንቀሳቀስ ላይ"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ፋይል(ሎች) ተቀድተዋል"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ፋይል(ሎች) ተንቀሳቅሰዋል"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"የተመረጡ ፋይሎችዎ ወደ የእርስዎ የግል ቦታ እየተቀዱ ነው"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"የተመረጡ ፋይሎችዎ ወደ የእርስዎ የግል ቦታ እየተንቀሳቀሱ ነው"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"የተመረጡ ፋይሎችዎ ወደ የግል ቦታዎ ተቀድተዋል"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"የተመረጡ ፋይሎችዎ ወደ የግል ቦታዎ ተንቀሳቅሰዋል"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ፋይል በመቅዳት ላይ}one{# ፋይል በመቅዳት ላይ}other{# ፋይሎችን በመቅዳት ላይ}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ፋይል በማንቀሳቀስ ላይ}one{# ፋይል በማንቀሳቀስ ላይ}other{# ፋይሎች በማንቀሳቀስ ላይ}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ፋይል ተቀድቷል}one{# ፋይል ተቀድቷል}other{# ፋይሎች ተቀድተዋል}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ፋይል ተንቀሳቅሷል}one{# ፋይል ተንቀሳቅሷል}other{# ፋይሎች ተንቀሳቅሰዋል}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ እየተቀዳ ነው}one{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ እየተቀዳ ነው}other{የተመረጡ ፋይሎችዎ ወደ የእርስዎ የግል ቦታ እየተቀዱ ነው}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ እየተንቀሳቀሰ ነው}one{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ እየተንቀሳቀሰ ነው}other{የተመረጡ ፋይሎችዎ ወደ የእርስዎ የግል ቦታ እየተንቀሳቀሱ ነው}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ ተቀድቷል}one{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ ተቀድቷል}other{የተመረጡ ፋይሎችዎ ወደ የእርስዎ የግል ቦታ ተቀድተዋል}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ ተንቀሳቅሷል}one{የተመረጠ ፋይልዎ ወደ የእርስዎ የግል ቦታ ተንቀሳቅሷል}other{የተመረጡ ፋይሎችዎ ወደ የእርስዎ የግል ቦታ ተንቀሳቅሰዋል}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ፋይሎችን አሳይ"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"የፋይል ማስተላለፍ ማሳወቂያዎች"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ወደ የግል ቦታዎ ፋይሎችን ሲቀዱ ወይም ሲያንቀሳቅሱ በሂደቱ ላይ ለእርስዎ ዝማኔ ለመስጠት ማሳወቂያዎች ይደርሱዎታል"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"አንዳንድ ፋይሎችን መቅዳት አልተቻለም"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"አንዳንድ ፋይሎችን ማንቀሳቀስ አልተቻለም"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ፋይሎችዎን እንደገና ለመቅዳት መሞከር ይችላሉ"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ፋይሎችዎን እንደገና ለማንቀሳቀስ መሞከር ይችላሉ"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"አሁንም ፋይሎችን በመቅዳት ላይ"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"አሁንም ፋይሎችን በማንቀሳቀስ ላይ"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"አንዴ ይህ ከተጠናቀቀ በኋላ ተጨማሪ ፋይሎችን መቅዳት ወይም ማንቀሳቀስ ይችላሉ"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ፋይሎችን መቅዳት አልተቻለም"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ፋይሎችን ማንቀሳቀስ አልተቻለም"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ጠቅላላ የፋይል መጠን በጣም ትልቅ ነው"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"በአንድ ጊዜ እስከ 2 ጊባ ድረስ ብቻ መቅዳት እና ማንቀሳቀስ ይችላሉ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"በጣም ብዙ ፋይሎች ተመርጠዋል"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"በአንድ ጊዜ እስከ 100 ፋይሎች ድረስ ብቻ መቅዳት እና ማንቀሳቀስ ይችላሉ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ፋይሎችን ማከል አልተቻለም"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"በቂ የመሣሪያ ማከማቻ የለዎትም"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"እሺ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ቦታ ያስለቅቁ"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ፋይሎችን ከግል ቦታ መቅዳት ወይም ማንቀሳቀስ አልተቻለም"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"አንዳንድ ፋይሎችን መቅዳት አልተቻለም"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"አንዳንድ ፋይሎችን ማንቀሳቀስ አልተቻለም"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"በመቅዳት ላይ ሳለ የግል ቦታዎ ተዘግቷል"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"በመንቀሳቀስ ላይ ሳለ የግል ቦታዎ ተዘግቷል"</string>
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index d1ef68a..60b2c5d 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -18,21 +18,43 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="private_space_app_label" msgid="4816454052314284927">"المساحة الخاصّة"</string>
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"إضافة ملفات"</string>
-    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"تثبيت التطبيقات"</string>
+    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"تثبيت تطبيقات"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"هل المطلوب نقل الملفات أو نسخها؟"</string>
     <string name="move_files_dialog_summary" msgid="5669539681627056766">"في حال نقل هذه الملفات إلى مساحتك الخاصّة، ستتم إزالتها من مجلّداتها الأصلية"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"نقل الملفات"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"نسخ"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"إلغاء"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"جارٍ نسخ <xliff:g id="FILES">%1$d</xliff:g> من الملفات"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"جارٍ نقل <xliff:g id="FILES">%1$d</xliff:g> من الملفات"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"تم نسخ <xliff:g id="FILES">%1$d</xliff:g> من الملفات"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"تم نقل <xliff:g id="FILES">%1$d</xliff:g> من الملفات"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"جارٍ نسخ الملفات المحدَّدة إلى مساحتك الخاصّة"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"جارٍ نقل الملفات المحدَّدة إلى مساحتك الخاصّة"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"تم نسخ الملفات المحدَّدة إلى مساحتك الخاصّة"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"تم نقل الملفات المحدَّدة إلى مساحتك الخاصّة"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{جارٍ نسخ ملف واحد}zero{جارٍ نسخ # ملف}two{جارٍ نسخ ملفَين}few{جارٍ نسخ # ملفات}many{جارٍ نسخ # ملفًا}other{جارٍ نسخ # ملف}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{جارٍ نقل ملف واحد}zero{جارٍ نقل # ملف}two{جارٍ نقل ملفَين}few{جارٍ نقل # ملفات}many{جارٍ نقل # ملفًا}other{جارٍ نقل # ملف}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{تم نسخ ملف واحد}zero{تم نسخ # ملف}two{تم نسخ ملفَين}few{تم نسخ # ملفات}many{تم نسخ # ملفًا}other{تم نسخ # ملف}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{تم نقل ملف واحد}zero{تم نقل # ملف}two{تم نقل ملفًين}few{تم نقل # ملفات}many{تم نقل # ملفًا}other{تم نقل # ملف}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{جارٍ نسخ الملف المحدَّد إلى مساحتك الخاصّة}zero{جارٍ نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}two{جارٍ نسخ الملفَين المحدَّدَين إلى مساحتك الخاصّة}few{جارٍ نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}many{جارٍ نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}other{جارٍ نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{جارٍ نقل الملف المحدَّد إلى مساحتك الخاصّة}zero{جارٍ نقل الملفات المحدَّدة إلى مساحتك الخاصّة}two{جارٍ نقل الملفَين المحدَّدَين إلى مساحتك الخاصّة}few{جارٍ نقل الملفات المحدَّدة إلى مساحتك الخاصّة}many{جارٍ نقل الملفات المحدَّدة إلى مساحتك الخاصّة}other{جارٍ نقل الملفات المحدَّدة إلى مساحتك الخاصّة}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{تم نسخ الملف المحدَّد إلى مساحتك الخاصّة}zero{تم نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}two{تم نسخ الملفَين المحدَّدَين إلى مساحتك الخاصّة}few{تم نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}many{تم نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}other{تم نسخ الملفات المحدَّدة إلى مساحتك الخاصّة}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{تم نقل الملف المحدَّد إلى مساحتك الخاصّة}zero{تم نقل الملفات المحدَّدة إلى مساحتك الخاصّة}two{تم نقل الملفَين المحدَّدَين إلى مساحتك الخاصّة}few{تم نقل الملفات المحدَّدة إلى مساحتك الخاصّة}many{تم نقل الملفات المحدَّدة إلى مساحتك الخاصّة}other{تم نقل الملفات المحدَّدة إلى مساحتك الخاصّة}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"عرض الملفات"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"إشعارات نقل الملفات"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"عند نسخ الملفات أو نقلها إلى مساحتك الخاصّة، يمكنك تلقّي إشعارات لإطلاعك على مستوى التقدّم"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"يتعذَّر نسخ بعض الملفات"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"يتعذَّر نقل بعض الملفات"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"يمكنك محاولة نسخ ملفاتك مرة أخرى"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"يمكنك محاولة نقل ملفاتك مرة أخرى"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"لا تزال عملية نسخ الملفات جارية"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"لا تزال عملية نقل الملفات جارية"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"يمكنك نسخ أو نقل المزيد من الملفات بعد اكتمال هذه العملية"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"تعذَّر نسخ الملفات"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"تعذَّر نقل الملفات"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"حجم الملف الإجمالي كبير جدًا"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"يمكنك نسخ أو نقل ما يصل إلى 2 غيغابايت فقط في كل مرة"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"عدد الملفات المحدَّدة كبير جدًا"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"يمكنك نسخ أو نقل ما يصل إلى 100 ملف في آنٍ واحد"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"تتعذَّر إضافة الملفات"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"لا تتوفّر مساحة تخزين كافية على الجهاز"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"حسنًا"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"إخلاء بعض المساحة"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"يتعذّر نسخ الملفات أو نقلها من \"المساحة الخاصّة\""</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"تعذَّر نسخ بعض الملفات"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"تعذَّر نقل بعض الملفات"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"تم إغلاق المساحة الخاصّة أثناء عملية النسخ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"تم إغلاق المساحة الخاصّة أثناء عملية النقل"</string>
 </resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index e593f3d..b25bebd 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"স্থানান্তৰ কৰক"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"প্ৰতিলিপি কৰক"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"বাতিল কৰক"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> টা ফাইল প্ৰতিলিপি কৰি থকা হৈছে"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> টা ফাইল স্থানান্তৰ কৰি থকা হৈছে"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> টা ফাইল প্ৰতিলিপি কৰা হৈছে"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> টা ফাইল স্থানান্তৰ কৰা হৈছে"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰি থকা হৈছে"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰি থকা হৈছে"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰা হৈছে"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰা হৈছে"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# টা ফাইল প্ৰতিলিপি কৰি থকা হৈছে}one{# টা ফাইল প্ৰতিলিপি কৰি থকা হৈছে}other{# টা ফাইল প্ৰতিলিপি কৰি থকা হৈছে}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# টা ফাইল স্থানান্তৰ কৰি থকা হৈছে}one{# টা ফাইল স্থানান্তৰ কৰি থকা হৈছে}other{# টা ফাইল স্থানান্তৰ কৰি থকা হৈছে}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# টা ফাইল প্ৰতিলিপি কৰা হৈছে}one{# টা ফাইল প্ৰতিলিপি কৰা হৈছে}other{# টা ফাইল প্ৰতিলিপি কৰা হৈছে}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# টা ফাইল স্থানান্তৰ কৰা হৈছে}one{# টা ফাইল স্থানান্তৰ কৰা হৈছে}other{# টা ফাইল স্থানান্তৰ কৰা হৈছে}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{আপোনাৰ বাছনি কৰা ফাইলটো আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰি থকা হৈছে}one{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰি থকা হৈছে}other{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰি থকা হৈছে}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{আপোনাৰ বাছনি কৰা ফাইলটো আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰি থকা হৈছে}one{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰি থকা হৈছে}other{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰি থকা হৈছে}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{আপোনাৰ বাছনি কৰা ফাইলটো আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰা হৈছে}one{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰা হৈছে}other{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ প্ৰতিলিপি কৰা হৈছে}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{আপোনাৰ বাছনি কৰা ফাইলটো আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰা হৈছে}one{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰা হৈছে}other{আপোনাৰ বাছনি কৰা ফাইলসমূহ আপোনাৰ প্ৰাইভেট স্পে’চলৈ স্থানান্তৰ কৰা হৈছে}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ফাইল দেখুৱাওক"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ফাইল স্থানান্তৰণৰ জাননী"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"আপুনি নিজৰ প্ৰাইভেট স্পে’চলৈ ফাইল প্ৰতিলিপি বা স্থানান্তৰ কৰিবলৈ, আপুনি প্ৰগতিৰ বিষয়ে আপডে’ট কৰিবলৈ জাননীসমূহ পাব পাৰে"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"কিছুমান ফাইল প্ৰতিলিপি কৰিব নোৱাৰি"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"কিছুমান ফাইল স্থানান্তৰ কৰিব নোৱাৰি"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"আপুনি নিজৰ ফাইলসমূহ পুনৰ প্ৰতিলিপি কৰিবলৈ চেষ্টা কৰিব পাৰে"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"আপুনি নিজৰ ফাইলসমূহ পুনৰ স্থানান্তৰ কৰিবলৈ চেষ্টা কৰিব পাৰে"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"এতিয়াও ফাইলসমূহ প্ৰতিলিপি কৰি থকা হৈছে"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"এতিয়াও ফাইলসমূহ স্থানান্তৰ কৰি থকা হৈছে"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"এইটো কৰা হ’লে আপুনি অধিক ফাইল প্ৰতিলিপি বা স্থানান্তৰ কৰিব পাৰিব"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ফাইলসমূহ প্ৰতিলিপি কৰিব পৰা নগ’ল"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ফাইলসমূহ স্থানান্তৰ কৰিব পৰা নগ’ল"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ফাইলৰ মুঠ আকাৰ অতি বেছি ডাঙৰ"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"আপুনি এবাৰত কেৱল ২ জিবিলৈকেহে প্ৰতিলিপি বা স্থানান্তৰ কৰিব পাৰিব"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"অতি বেছি সংখ্যক ফাইল বাছনি কৰা হৈছে"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"আপুনি এবাৰত কেৱল ১০০ টালৈকেহে ফাইল প্ৰতিলিপি বা স্থানান্তৰ কৰিব পাৰিব"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ফাইলসমূহ যোগ দিব নোৱাৰি"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"আপোনাৰ ওচৰত পৰ্যাপ্ত ডিভাইচৰ ষ্ট’ৰেজ নাই"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ঠিক আছে"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ঠাই খালী কৰক"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"প্ৰাইভেট স্পে’চৰ পৰা ফাইলসমূহ প্ৰতিলিপি বা স্থানান্তৰ কৰিব নোৱাৰি"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"কিছুমান ফাইল প্ৰতিলিপি কৰিব পৰা নগ’ল"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"কিছুমান ফাইল স্থানান্তৰ কৰিব পৰা নগ’ল"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"প্ৰতিলিপি কৰোঁতে আপোনাৰ প্ৰাইভেট স্পে’চ বন্ধ কৰা হৈছে"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"স্থানান্তৰ কৰোঁতে আপোনাৰ প্ৰাইভেট স্পে’চ বন্ধ কৰা হৈছে"</string>
 </resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 1ec1586..3d3cc0d 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Köçürün"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiyalayın"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Ləğv edin"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> fayl kopiyalanır"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> fayl köçürülür"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fayl kopiyalandı"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fayl köçürüldü"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Seçilmiş fayllarınız şəxsi sahənizə kopiyalanır"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Seçilmiş fayllarınız şəxsi sahənizə köçürülür"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Seçilmiş fayllarınız şəxsi sahənizə kopiyalandı"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Seçilmiş fayllarınız şəxsi sahənizə köçürüldü"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# fayl kopiyalanır}other{# fayl kopiyalanır}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# fayl köçürülür}other{# fayl köçürülür}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fayl kopiyalandı}other{# fayl kopiyalandı}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fayl köçürüldü}other{# fayl köçürüldü}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Seçilmiş faylınız şəxsi sahənizə kopiyalanır}other{Seçilmiş faylınız şəxsi sahənizə kopiyalanır}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Seçilmiş faylınız şəxsi sahənizə köçürülür}other{Seçilmiş faylınız şəxsi sahənizə köçürülür}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Seçilmiş faylınız şəxsi sahənizə kopiyalanıb}other{Seçilmiş faylınız şəxsi sahənizə kopiyalanıb}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Seçilmiş faylınız şəxsi sahənizə köçürülüb}other{Seçilmiş faylınız şəxsi sahənizə köçürülüb}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Faylları göstərin"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Fayl ötürmə bildirişləri"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Faylları şəxsi sahənizə kopiyaladıqda və ya köçürdükdə gedişat barədə məlumat almaq üçün bildirişlər qəbul edə bilərsiniz"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Bəzi faylları kopiyalamaq mümkün deyil"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Bəzi faylları köçürmək mümkün deyil"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Fayllarınızı yenidən kopiyalamağa cəhd edə bilərsiniz"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Fayllarınızı yenidən köçürməyə cəhd edə bilərsiniz"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Hələ fayllar kopiyalanır"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Hələ fayllar köçürülür"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Tamamlandıqdan sonra daha çox faylı kopiyalaya və ya köçürə bilərsiniz"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Fayllar kopiyalanmadı"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Faylları köçürmək mümkün olmadı"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Ümumi fayl ölçüsü çox böyükdür"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Eyni anda maksimum 2 GB kopiyalaya və ya köçürə bilərsiniz"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Həddən çox fayl seçilib"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Eyni anda maksimum 100 fayl kopiyalaya və ya köçürə bilərsiniz"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Fayllar əlavə etmək mümkün deyil"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Kifayət qədər cihaz yaddaşınız yoxdur"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Yer boşaldın"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Şəxsi Sahədən faylları kopiyalamaq və ya köçürmək mümkün deyil"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Bəzi faylları kopiyalamaq olmadı"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Bəzi faylları köçürmək olmadı"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Kopiyalayan zaman şəxsi sahəniz bağlandı"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Köçürən zaman şəxsi sahəniz bağlandı"</string>
 </resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 7d1d896..e3cd006 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -17,22 +17,44 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="private_space_app_label" msgid="4816454052314284927">"Privatan prostor"</string>
-    <string name="shortcut_label_add_files" msgid="5537029952988156354">"Dodajte fajlove"</string>
-    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Instalirajte aplikacije"</string>
+    <string name="shortcut_label_add_files" msgid="5537029952988156354">"Dodaj fajlove"</string>
+    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Instaliraj aplikacije"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Želite da premestite ili kopirate fajlove?"</string>
     <string name="move_files_dialog_summary" msgid="5669539681627056766">"Ako premestite ove fajlove u privatan prostor, uklonićete ih iz prvobitnih foldera"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Premesti"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiraj"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Otkaži"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopiraju se fajlovi: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Premeštaju se fajlovi: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Kopirano fajlova: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Premešteni fajlovi: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Odabrani fajlovi se kopiraju u privatan prostor"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Odabrani fajlovi se premeštaju u privatan prostor"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Izabrani fajlovi su kopirani u privatan prostor"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Izabrani fajlovi su premešteni u privatan prostor"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopira se # fajl}one{Kopira se # fajl}few{Kopiraju se # fajla}other{Kopira se # fajlova}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Premešta se # fajl}one{Premešta se # fajl}few{Premeštaju se # fajla}other{Premešta se # fajlova}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fajl je kopiran}one{# fajl je kopiran}few{# fajla su kopirana}other{# fajlova je kopirano}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fajl je premešten}one{# fajl je premešten}few{# fajla su premeštena}other{# fajlova je premešteno}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Odabrani fajl se kopira u privatan prostor}one{Odabrani fajlovi se kopiraju u privatan prostor}few{Odabrani fajlovi se kopiraju u privatan prostor}other{Odabrani fajlovi se kopiraju u privatan prostor}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Odabrani fajl se premešta u privatan prostor}one{Odabrani fajlovi se premeštaju u privatan prostor}few{Odabrani fajlovi se premeštaju u privatan prostor}other{Odabrani fajlovi se premeštaju u privatan prostor}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Odabrani fajl je kopiran u privatan prostor}one{Odabrani fajlovi su kopirani u privatan prostor}few{Odabrani fajlovi su kopirani u privatan prostor}other{Odabrani fajlovi su kopirani u privatan prostor}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Odabrani fajl je premešten u privatan prostor}one{Odabrani fajlovi su premešteni u privatan prostor}few{Odabrani fajlovi su premešteni u privatan prostor}other{Odabrani fajlovi su premešteni u privatan prostor}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Prikaži fajlove"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Obaveštenja o prenosu fajlova"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kada kopirate ili premeštate fajlove u privatan prostor, možete da dobijate obaveštenja o napretku"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Kopiranje nekih fajlova nije uspelo"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Premeštanje nekih fajlova nije uspelo"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Možete ponovo da probate da kopirate fajlove"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Možete ponovo da probate da premestite fajlove"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Fajlovi se i dalje kopiraju"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Fajlovi se i dalje premeštaju"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Kada se to završi, možete da kopirate ili premestite još fajlova"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Kopiranje fajlova nije uspelo"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Premeštanje fajlova nije uspelo"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Ukupna veličina fajlova je prevelika"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Možete da kopirate ili premestite najviše 2 GB odjednom"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Izabrano je previše fajlova"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Možete da kopirate ili premestite najviše 100 fajlova odjednom"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Dodavanje fajlova nije uspelo"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Nemate dovoljno memorijskog prostora uređaja"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Potvrdi"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Oslobodite prostor"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Ne možete da kopirate ni premeštate fajlove iz privatnog prostora"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Kopiranje nekih fajlova nije uspelo"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Premeštanje nekih fajlova nije uspelo"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Privatan prostor je bio zatvoren tokom kopiranja"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Privatan prostor je bio zatvoren tokom premeštanja"</string>
 </resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index b64dd1d..4460d42 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Перамясціць"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Капіраваць"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Скасаваць"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Капіраванне файлаў (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Перамяшчэнне файлаў (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Файлы (<xliff:g id="FILES">%1$d</xliff:g>) скапіраваны"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Файлы (<xliff:g id="FILES">%1$d</xliff:g>) перамешчаны"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Выбраныя файлы капіруюцца ў прыватную прастору"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Выбраныя файлы перамяшчаюцца ў прыватную прастору"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Выбраныя файлы былі скапіраваны ў прыватную прастору"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Выбраныя файлы былі перамешчаны ў прыватную прастору"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Капіруецца # файл}one{Капіруецца # файл}few{Капіруюцца # файлы}many{Капіруюцца # файлаў}other{Капіруюцца # файла}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Перамяшчаецца # файл}one{Перамяшчаецца # файл}few{Перамяшчаюцца # файлы}many{Перамяшчаюцца # файлаў}other{Перамяшчаюцца # файла}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Скапіраваны # файл}one{Скапіраваны # файл}few{Скапіраваны # файлы}many{Скапіраваны # файлаў}other{Скапіраваны # файла}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Перамешчаны # файл}one{Перамешчаны # файл}few{Перамешчаны # файлы}many{Перамешчаны # файлаў}other{Перамешчаны # файла}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Выбраны файл капіруецца ў прыватную прастору}one{Выбраныя файлы капіруюцца ў прыватную прастору}few{Выбраныя файлы капіруюцца ў прыватную прастору}many{Выбраныя файлы капіруюцца ў прыватную прастору}other{Выбраныя файлы капіруюцца ў прыватную прастору}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Выбраны файл перамяшчаецца ў прыватную прастору}one{Выбраныя файлы перамяшчаюцца ў прыватную прастору}few{Выбраныя файлы перамяшчаюцца ў прыватную прастору}many{Выбраныя файлы перамяшчаюцца ў прыватную прастору}other{Выбраныя файлы перамяшчаюцца ў прыватную прастору}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Выбраны файл быў скапіраваны ў прыватную прастору}one{Выбраныя файлы былі скапіраваны ў прыватную прастору}few{Выбраныя файлы былі скапіраваны ў прыватную прастору}many{Выбраныя файлы былі скапіраваны ў прыватную прастору}other{Выбраныя файлы былі скапіраваны ў прыватную прастору}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Выбраны файл быў перамешчаны ў прыватную прастору}one{Выбраныя файлы былі перамешчаны ў прыватную прастору}few{Выбраныя файлы былі перамешчаны ў прыватную прастору}many{Выбраныя файлы былі перамешчаны ў прыватную прастору}other{Выбраныя файлы былі перамешчаны ў прыватную прастору}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Паказаць файлы"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Апавяшчэнні аб пераносе файлаў"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Калі вы капіруеце ці перамяшчаеце файлы ў прыватную прастору, то можаце атрымліваць апавяшчэнні аб ходзе выканання"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Не ўдаецца скапіраваць некаторыя файлы"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Не ўдаецца перамясціць некаторыя файлы"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Можаце зноў паспрабаваць скапіраваць файлы"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Можаце зноў паспрабаваць перамясціць файлы"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Файлы яшчэ капіруюцца"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Файлы яшчэ перамяшчаюцца"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Пасля завяршэння можна будзе скапіраваць ці перамясціць іншыя файлы"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Не ўдалося скапіраваць файлы"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Не ўдалося перамясціць файлы"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Агульны памер файлаў занадта вялікі"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"За раз можна скапіраваць ці перамясціць не больш за 2 ГБ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Выбрана зашмат файлаў"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"За раз можна скапіраваць ці перамясціць не больш за 100 файлаў"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Не ўдаецца дадаць файлы"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"У сховішчы прылады недастаткова месца"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ОК"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Вызваліце месца"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Не ўдаецца скапіраваць ці перамясціць файлы з прыватнай прасторы"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Не ўдалося скапіраваць некаторыя файлы"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Не ўдалося перамясціць некаторыя файлы"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Падчас капіравання прыватная прастора была закрыта"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Падчас перамяшчэння прыватная прастора была закрыта"</string>
 </resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 8f1465e..9097254 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Преместване"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Копиране"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Отказ"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Копира(т) се <xliff:g id="FILES">%1$d</xliff:g> файл(а)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Премества(т) се <xliff:g id="FILES">%1$d</xliff:g> файл(а)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Копирани файлове: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Преместени файлове: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Избраните от вас файлове се копират в частното ви пространство"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Избраните от вас файлове се преместват в частното ви пространство"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Избраните от вас файлове бяха копирани в частното ви пространство"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Избраните от вас файлове бяха преместени в частното ви пространство"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# файл се копира}other{# файла се копират}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# файл се премества}other{# файла се преместват}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# копиран файл}other{# копирани файла}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# преместен файл}other{# преместени файла}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Избраният от вас файл се копира в частното ви пространство}other{Избраните от вас файлове се копират в частното ви пространство}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Избраният от вас файл се премества в частното ви пространство}other{Избраните от вас файлове се преместват в частното ви пространство}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Избраният от вас файл бе копиран в частното ви пространство}other{Избраните от вас файлове бяха копирани в частното ви пространство}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Избраният от вас файл бе преместен в частното ви пространство}other{Избраните от вас файлове бяха преместени в частното ви пространство}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Показване на файловете"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Известия за прехвърлянето на файлове"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Когато копирате или премествате файлове в частното си пространство, можете да получавате известия с актуална информация за напредъка"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Някои файлове не бяха копирани"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Някои файлове не бяха преместени"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Можете отново да опитате да копирате файловете си"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Можете отново да опитате да преместите файловете си"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Още се копират файлове"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Още се преместват файлове"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Можете да копирате или преместите още файлове, след като този процес приключи"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Файловете не бяха копирани"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Файловете не бяха преместени"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Общият размер на файловете е твърде голям"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Можете да копирате или премествате само до 2 GB наведнъж"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Избрани са твърде много файлове"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Можете да копирате или премествате само до 100 файла наведнъж"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Файловете не бяха добавени"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Няма достатъчно място в хранилището на устройството"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Освобождаване на място"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Файловете не могат да бъдат копирани, нито преместени от частното пространство"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Някои файлове не бяха копирани"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Някои файлове не бяха преместени"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Частното ви пространство бе затворено по време на копирането"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Частното ви пространство бе затворено по време на преместването"</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index f402add..d007724 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"সরান"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"কপি করুন"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"বাতিল করুন"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g>টি ফাইল কপি করা হচ্ছে"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g>টি ফাইল সরানো হচ্ছে"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g>টি ফাইল কপি করা হয়েছে"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g>টি ফাইল সরানো হয়েছে"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"আপনার বেছে নেওয়া ফাইল প্রাইভেট স্পেসে কপি করা হচ্ছে"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"আপনার বেছে নেওয়া ফাইল প্রাইভেট স্পেসে সরানো হয়েছে"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"আপনার বেছে নেওয়া ফাইল প্রাইভেট স্পেসে কপি করা হয়েছে"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"আপনার বেছে নেওয়া ফাইল প্রাইভেট স্পেসে সরানো হয়েছে"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{#টি ফাইল কপি করা হচ্ছে}one{#টি ফাইল কপি করা হচ্ছে}other{#টি ফাইল কপি করা হচ্ছে}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{#টি ফাইল সরানো হচ্ছে}one{#টি ফাইল সরানো হচ্ছে}other{#টি ফাইল সরানো হচ্ছে}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{#টি ফাইল কপি করা হয়েছে}one{#টি ফাইল কপি করা হয়েছে}other{#টি ফাইল কপি করা হয়েছে}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{#টি ফাইল সরানো হয়েছে}one{#টি ফাইল সরানো হয়েছে}other{#টি ফাইল সরানো হয়েছে}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{আপনার বেছে নেওয়া ফাইল আপনার প্রাইভেট স্পেসে কপি করা হচ্ছে}one{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে কপি করা হচ্ছে}other{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে কপি করা হচ্ছে}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{আপনার বেছে নেওয়া ফাইল আপনার প্রাইভেট স্পেসে সরানো হচ্ছে}one{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে সরানো হচ্ছে}other{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে সরানো হচ্ছে}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{আপনার বেছে নেওয়া ফাইল আপনার প্রাইভেট স্পেসে কপি করা হয়েছে}one{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে কপি করা হয়েছে}other{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে কপি করা হয়েছে}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{আপনার বেছে নেওয়া ফাইল আপনার প্রাইভেট স্পেসে সরানো হয়েছে}one{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে সরানো হয়েছে}other{আপনার বেছে নেওয়া ফাইলগুলি আপনার প্রাইভেট স্পেসে সরানো হয়েছে}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ফাইল দেখুন"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ফাইল ট্রান্সফার সংক্রান্ত বিজ্ঞপ্তি"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"আপনার প্রাইভেট স্পেসে ফাইল কপি করলে বা সরালে, প্রোগ্রেস সম্পর্কে আপনাকে আপডেট দিতে বিজ্ঞপ্তি পাঠানো হবে"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"কিছু ফাইল কপি করা যাচ্ছে না"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"কিছু ফাইল সরানো যাচ্ছে না"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"আপনি আবার আপনার ফাইল কপি করার চেষ্টা করতে পারেন"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"আপনি আবার আপনার ফাইল সরানোর চেষ্টা করতে পারেন"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ফাইল এখনও কপি করা হচ্ছে"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ফাইল এখনও সরানো হচ্ছে"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"এটি হয়ে গেলে আপনি আরও ফাইল কপি করতে বা সরাতে পারবেন"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ফাইল কপি করা যায়নি"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ফাইল সরানো যায়নি"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ফাইলের মোট সাইজ খুবই বড়"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"আপনি একবারে কেবল ২ জিবি পর্যন্ত কপি বা ট্রান্সফার করতে পারবেন"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"অনেক বেশি ফাইল বেছে নেওয়া হয়েছে"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"আপনি একবারে কেবল ১০০টি ফাইল পর্যন্ত কপি বা ট্রান্সফার করতে পারবেন"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ফাইল যোগ করা যাচ্ছে না"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"আপনার পর্যাপ্ত ডিভাইস স্টোরেজ নেই"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ঠিক আছে"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"জায়গা খালি করুন"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"প্রাইভেট স্পেস থেকে ফাইল কপি করা বা সরানো যাচ্ছে না"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"কিছু ফাইল কপি করা যায়নি"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"কিছু ফাইল সরানো যায়নি"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"কপি করা সময় আপনার প্রাইভেট স্পেস বন্ধ করে দেওয়া হয়েছে"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"সরানোর সময় আপনার প্রাইভেট স্পেস বন্ধ করে দেওয়া হয়েছে"</string>
 </resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 42c75e0..650cfb9 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Premjesti"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiraj"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Otkaži"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopiranje <xliff:g id="FILES">%1$d</xliff:g> fajl(ov)a"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Premještanje <xliff:g id="FILES">%1$d</xliff:g> fajl(ov)a"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Kopirani fajlovi: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Premješteni fajlovi: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Odabrani fajlovi se kopiraju u privatni prostor"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Odabrani fajlovi se premještaju u privatni prostor"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Odabrani fajlovi su kopirani u privatni prostor"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Odabrani fajlovi su premješteni u privatni prostor"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# fajl se kopira}one{# fajl se kopira}few{# fajla se kopiraju}other{# fajlova se kopira}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# fajl se premješta}one{# fajl se premješta}few{# fajla se premještaju}other{# fajlova se premješta}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Kopiran je # fajl}one{Kopiran je # fajl}few{Kopirana su # fajla}other{Kopirano je # fajlova}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Premješten je # fajl}one{Premješten je # fajl}few{Premještena su # fajla}other{Premješteno je # fajlova}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Odabrani fajl se kopira u privatni prostor}one{Odabrani fajlovi se kopiraju u privatni prostor}few{Odabrani fajlovi se kopiraju u privatni prostor}other{Odabrani fajlovi se kopiraju u privatni prostor}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Odabrani fajl se premješta u privatni prostor}one{Odabrani fajlovi se premještaju u privatni prostor}few{Odabrani fajlovi se premještaju u privatni prostor}other{Odabrani fajlovi se premještaju u privatni prostor}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Odabrani fajl je kopiran u privatni prostor}one{Odabrani fajlovi su kopirani u privatni prostor}few{Odabrani fajlovi su kopirani u privatni prostor}other{Odabrani fajlovi su kopirani u privatni prostor}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Odabrani fajl je premješten u privatni prostor}one{Odabrani fajlovi su premješteni u privatni prostor}few{Odabrani fajlovi su premješteni u privatni prostor}other{Odabrani fajlovi su premješteni u privatni prostor}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Prikaži fajlove"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Obavještenja o prenosu fajlova"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kada kopirate ili premještate fajlove u privatni prostor, možete primati obavještenja o napretku"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nije moguće kopirati određene fajlove"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nije moguće premjestiti određene fajlove"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Možete ponovo pokušati kopirati fajlove"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Možete ponovo pokušati premjestiti fajlove"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Fajlovi se i dalje kopiraju"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Fajlovi se i dalje premještaju"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Možete kopirati ili premjestiti više fajlova čim se ovo završi"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Kopiranje fajlova nije uspjelo"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Premještanje fajlova nije uspjelo"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Ukupna veličina fajlova je prevelika"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Možete kopirati ili premjestiti samo do 2 GB odjednom"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Odabrano je previše fajlova"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Možete kopirati ili premjestiti samo do 100 fajlova odjednom"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nije moguće dodati fajlove"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Nemate dovoljno pohrane na uređaju"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Uredu"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Oslobodite prostor"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Nije moguće kopirati niti premjestiti fajlove iz privatnog prostora"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Kopiranje određenih fajlova nije uspjelo"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Premještanje određenih fajlova nije uspjelo"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Privatni prostor je zatvoren prilikom kopiranja"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Privatni prostor je zatvoren prilikom premještanja"</string>
 </resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 9ae820f..8fda4f7 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mou"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copia"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancel·la"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"S\'estan copiant <xliff:g id="FILES">%1$d</xliff:g> fitxers"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"S\'estan movent <xliff:g id="FILES">%1$d</xliff:g> fitxers"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"S\'han copiat <xliff:g id="FILES">%1$d</xliff:g> fitxers"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"S\'han mogut <xliff:g id="FILES">%1$d</xliff:g> fitxers"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Els fitxers que has triat s\'estan copiant al teu espai privat"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Els fitxers que has triat s\'estan movent al teu espai privat"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Els fitxers que has triat s\'han copiat al teu espai privat"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Els fitxers que has triat s\'han mogut al teu espai privat"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{S\'està copiant # fitxer}many{S\'estan copiant # de fitxers}other{S\'estan copiant # fitxers}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{S\'està movent # fitxer}many{S\'estan movent # de fitxers}other{S\'estan movent # fitxers}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{S\'ha copiat # fitxer}many{S\'han copiat # de fitxers}other{S\'han copiat # fitxers}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{S\'ha mogut # fitxer}many{S\'han mogut # de fitxers}other{S\'han mogut # fitxers}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{El fitxer que has triat s\'està copiant al teu espai privat}many{Els fitxers que has triat s\'estan copiant al teu espai privat}other{Els fitxers que has triat s\'estan copiant al teu espai privat}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{El fitxer que has triat s\'està movent al teu espai privat}many{Els fitxers que has triat s\'estan movent al teu espai privat}other{Els fitxers que has triat s\'estan movent al teu espai privat}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{El fitxer que has triat s\'ha copiat al teu espai privat}many{Els fitxers que has triat s\'han copiat al teu espai privat}other{Els fitxers que has triat s\'han copiat al teu espai privat}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{El fitxer que has triat s\'ha mogut al teu espai privat}many{Els fitxers que has triat s\'han mogut al teu espai privat}other{Els fitxers que has triat s\'han mogut al teu espai privat}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostra els fitxers"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notificacions transferència de fitxers"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Quan copies o mous fitxers al teu espai privat, pots rebre notificacions perquè t\'informin del progrés"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"No es poden copiar alguns fitxers"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"No es poden moure alguns fitxers"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Pots provar de tornar a copiar els fitxers"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Pots provar de tornar a moure els fitxers"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Encara s\'estan copiant els fitxers"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Encara s\'estan movent fitxers"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Un cop fet això, podràs copiar o moure més fitxers"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"No s\'han pogut copiar els fitxers"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"No s\'han pogut moure els fitxers"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"La mida total del fitxer és massa gran"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Només pots copiar o moure fins a 2 GB alhora"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"S\'han seleccionat massa fitxers"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Només pots copiar o moure fins a 100 fitxers alhora"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"No es poden afegir fitxers"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"No tens prou emmagatzematge al dispositiu"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"D\'acord"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Allibera espai"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"No es poden copiar ni moure fitxers de l\'espai privat"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"No s\'han pogut copiar alguns fitxers"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"No s\'han pogut moure alguns fitxers"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"L\'espai privat s\'ha tancat durant la còpia"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"L\'espai privat s\'ha tancat durant la migració"</string>
 </resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index bcae372..bef1eeb 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Přesunout"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopírovat"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Zrušit"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopírování souborů (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Přesouvání souborů (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> zkopírované soubory"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Soubory (<xliff:g id="FILES">%1$d</xliff:g>) byly přesunuty"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Vybrané soubory se kopírují do vašeho soukromého prostoru"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Vybrané soubory se přesouvají do vašeho soukromého prostoru"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Vybrané soubory byly zkopírovány do vašeho soukromého prostoru"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Vybrané soubory byly přesunuty do vašeho soukromého prostoru"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopírování # souboru}few{Kopírování # souborů}many{Kopírování # souboru}other{Kopírování # souborů}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Přesouvání # souboru}few{Přesouvání # souborů}many{Přesouvání # souboru}other{Přesouvání # souborů}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Byl zkopírován # soubor}few{Byly zkopírovány # soubory}many{Bylo zkopírováno # souboru}other{Bylo zkopírováno # souborů}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Byl přesunut # soubor}few{Byly přesunuty # soubory}many{Bylo přesunuto # souboru}other{Bylo přesunuto # souborů}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Vybraný soubor se kopíruje do vašeho soukromého prostoru}few{Vybrané soubory se kopírují do vašeho soukromého prostoru}many{Vybrané soubory se kopírují do vašeho soukromého prostoru}other{Vybrané soubory se kopírují do vašeho soukromého prostoru}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Vybraný soubor se přesouvá do vašeho soukromého prostoru}few{Vybrané soubory se přesouvají do vašeho soukromého prostoru}many{Vybrané soubory se přesouvají do vašeho soukromého prostoru}other{Vybrané soubory se přesouvají do vašeho soukromého prostoru}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Vybraný soubor byl zkopírován do vašeho soukromého prostoru}few{Vybrané soubory byly zkopírovány do vašeho soukromého prostoru}many{Vybrané soubory byly zkopírovány do vašeho soukromého prostoru}other{Vybrané soubory byly zkopírovány do vašeho soukromého prostoru}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Vybraný soubor byl přesunut do vašeho soukromého prostoru}few{Vybrané soubory byly přesunuty do vašeho soukromého prostoru}many{Vybrané soubory byly přesunuty do vašeho soukromého prostoru}other{Vybrané soubory byly přesunuty do vašeho soukromého prostoru}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Zobrazit soubory"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Oznámení o přenosu souborů"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Při kopírování nebo přesouvání souborů do soukromého prostoru můžete dostávat oznámení s informacemi o průběhu"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Některé soubory zkopírovat nelze"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Některé soubory přesunout nelze"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Můžete soubory zkusit zkopírovat znovu"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Můžete soubory zkusit přesunout znovu"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Probíhá kopírování souborů"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Stále probíhá přesouvání souborů"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Další soubory budete moct zkopírovat nebo přesunout po dokončení"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Soubory se zkopírovat nepodařilo"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Soubory se přesunout nepodařilo"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Soubory jsou dohromady příliš velké"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Najednou můžete zkopírovat nebo přesunout maximálně 2 GB"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Vybrali jste příliš mnoho souborů"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Najednou můžete zkopírovat nebo přesunout maximálně 100 souborů"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Soubory nelze přidat"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Na zařízení nemáte dostatek úložiště"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Uvolněte místo"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Nelze kopírovat ani přesouvat soubory ze soukromého prostoru"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Některé soubory nebylo možné zkopírovat"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Některé soubory nebylo možné přesunout"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Soukromý prostor byl při kopírování uzavřen"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Soukromý prostor byl při přesouvání uzavřen"</string>
 </resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index b4849f8..fc2bcf7 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Flyt"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiér"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Annuller"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopierer filer: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Flytter filer: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Kopierede filer: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Flyttede filer: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Dine valgte filer kopieres til dit private område"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Dine valgte filer flyttes til dit private område"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Dine valgte filer blev kopieret til dit private område"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Dine valgte filer blev flyttet til dit private område"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopierer # fil}one{Kopierer # fil}other{Kopierer # filer}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Flytter # fil}one{Flytter # fil}other{Flytter # filer}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fil blev kopieret}one{# fil blev kopieret}other{# filer blev kopieret}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fil blev flyttet}one{# fil blev flyttet}other{# filer blev flyttet}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Din valgte fil kopieres til dit private område}one{Din valgte fil kopieres til dit private område}other{Dine valgte filer kopieres til dit private område}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Din valgte fil flyttes til dit private område}one{Din valgte fil flyttes til dit private område}other{Dine valgte filer flyttes til dit private område}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Din valgte fil blev kopieret til dit private område}one{Din valgte fil blev kopieret til dit private område}other{Dine valgte filer blev kopieret til dit private område}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Din valgte fil blev flyttet til dit private område}one{Din valgte fil blev flyttet til dit private område}other{Dine valgte filer blev flyttet til dit private område}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Vis filer"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notifikationer om filoverførsel"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Når du kopierer filer eller flytter dem til dit private område, kan du få notifikationer med statusopdateringer"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nogle filer kan ikke kopieres"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nogle filer kan ikke flyttes"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Du kan prøve at kopiere dine filer igen"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Du kan prøve at flytte dine filer igen"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Filerne kopieres stadig"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Filerne flyttes stadig"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Du kan kopiere eller flytte flere filer, når dette er fuldført"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Filerne kunne ikke kopieres"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Filerne kunne ikke flyttes"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Den samlede filstørrelse er for stor"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Du kan kun kopiere eller flytte op til 2 GB ad gangen"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Der er valgt for mange filer"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Du kan kun kopiere eller flytte op til 100 filer ad gangen"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Filerne kan ikke tilføjes"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Du har ikke nok lagerplads på enheden"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Frigør plads"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Filer kan ikke kopieres eller flyttes fra det private område"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Visse filer kunne ikke kopieres"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Visse filer kunne ikke flyttes"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Dit private område blev lukket under kopieringen"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Dit private område blev lukket under flytningen"</string>
 </resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 10723c9..d999deb 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Verschieben"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopieren"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Abbrechen"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> Datei(en) werden kopiert"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> Datei(en) werden verschoben"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> Datei(en) kopiert"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> Datei(en) verschoben"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Die ausgewählten Dateien werden in das vertrauliche Profil kopiert"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Die ausgewählten Dateien werden in das vertrauliche Profil verschoben"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Die ausgewählten Dateien wurden in das vertrauliche Profil kopiert"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Die ausgewählten Dateien wurden in das vertrauliche Profil verschoben"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# Datei wird kopiert}other{# Dateien werden kopiert}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# Datei wird verschoben}other{# Dateien werden verschoben}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# Datei kopiert}other{# Dateien kopiert}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# Datei verschoben}other{# Dateien verschoben}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Die ausgewählte Datei wird in das vertrauliche Profil kopiert}other{Die ausgewählten Dateien werden in das vertrauliche Profil kopiert}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Die ausgewählte Datei wird in das vertrauliche Profil verschoben}other{Die ausgewählten Dateien werden in das vertrauliche Profil verschoben}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Die ausgewählte Datei wurde in das vertrauliche Profil kopiert}other{Die ausgewählten Dateien wurden in das vertrauliche Profil kopiert}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Die ausgewählte Datei wurde in das vertrauliche Profil verschoben}other{Die ausgewählten Dateien wurden in das vertrauliche Profil verschoben}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Dateien anzeigen"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Benachrichtigungen zu Dateiübertragungen"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Wenn du Dateien in dein vertrauliches Profil kopierst oder verschiebst, kannst du Benachrichtigungen zum Fortschrittsstatus erhalten"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Einige Dateien können nicht kopiert werden"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Einige Dateien können nicht verschoben werden"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Du kannst noch einmal versuchen, deine Dateien zu kopieren"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Du kannst noch einmal versuchen, deine Dateien zu verschieben"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Dateien werden noch kopiert"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Dateien werden noch verschoben"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Sobald dies abgeschlossen ist, kannst du weitere Dateien kopieren oder verschieben"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Dateien konnten nicht kopiert werden"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Dateien konnten nicht verschoben werden"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Summe der Dateigrößen zu hoch"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Du kannst maximal 2 GB gleichzeitig kopieren oder verschieben"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Zu viele Dateien ausgewählt"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Du kannst maximal 100 Dateien gleichzeitig kopieren oder verschieben"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Dateien können nicht hinzugefügt werden"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Du hast nicht genug Gerätespeicher"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Ok"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Speicherplatz freigeben"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Es ist nicht möglich, Dateien aus einem vertraulichen Profil zu kopieren oder zu verschieben"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Einige Dateien konnten nicht kopiert werden"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Einige Dateien konnten nicht verschoben werden"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Dein vertrauliches Profil wurde während des Kopierens geschlossen"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Dein vertrauliches Profil wurde während des Verschiebens geschlossen"</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 8521c9d..8dd6500 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Μετακίνηση"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Αντιγραφή"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Ακύρωση"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Γίνεται αντιγραφή <xliff:g id="FILES">%1$d</xliff:g> αρχείων"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Γίνεται μεταφορά <xliff:g id="FILES">%1$d</xliff:g> αρχείων"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Έγινε αντιγραφή <xliff:g id="FILES">%1$d</xliff:g> αρχείων"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Έγινε μεταφορά <xliff:g id="FILES">%1$d</xliff:g> αρχείων"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Γίνεται αντιγραφή των επιλεγμένων αρχείων στον ιδιωτικό χώρο"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Γίνεται μεταφορά των επιλεγμένων αρχείων στον ιδιωτικό χώρο"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Έγινε αντιγραφή των επιλεγμένων αρχείων στον ιδιωτικό χώρο"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Έγινε μεταφορά των επιλεγμένων αρχείων στον ιδιωτικό χώρο"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Γίνεται αντιγραφή # αρχείου}other{Γίνεται αντιγραφή # αρχείων}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Γίνεται μεταφορά # αρχείου}other{Γίνεται μεταφορά # αρχείων}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Αντιγράφηκε # αρχείο}other{Αντιγράφηκαν # αρχεία}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Μεταφέρθηκε # αρχείο}other{Μεταφέρθηκαν # αρχεία}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Γίνεται αντιγραφή του επιλεγμένου αρχείου στον ιδιωτικό χώρο}other{Γίνεται αντιγραφή των επιλεγμένων αρχείων στον ιδιωτικό χώρο}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Γίνεται μεταφορά του επιλεγμένου αρχείου στον ιδιωτικό χώρο}other{Γίνεται μεταφορά των επιλεγμένων αρχείων στον ιδιωτικό χώρο}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Το επιλεγμένο αρχείο αντιγράφηκε στον ιδιωτικό χώρο}other{Τα επιλεγμένα αρχεία αντιγράφηκαν στον ιδιωτικό χώρο}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Το επιλεγμένο αρχείο μεταφέρθηκε στον ιδιωτικό χώρο}other{Τα επιλεγμένα αρχεία μεταφέρθηκαν στον ιδιωτικό χώρο}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Εμφάνιση αρχείων"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Ειδοποιήσεις μεταφοράς αρχείων"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Όταν αντιγράφετε ή μετακινείτε αρχεία στον ιδιωτικό χώρο, μπορείτε να λαμβάνετε ειδοποιήσεις για την πρόοδο"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Δεν είναι δυνατή η αντιγραφή ορισμένων αρχείων"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Δεν είναι δυνατή η μετακίνηση ορισμένων αρχείων"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Μπορείτε να δοκιμάσετε να αντιγράψετε ξανά τα αρχεία σας"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Μπορείτε να δοκιμάσετε να μετακινήσετε ξανά τα αρχεία σας"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Η αντιγραφή αρχείων είναι ακόμα σε εξέλιξη"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Η μετακίνηση αρχείων είναι ακόμα σε εξέλιξη"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Μπορείτε να αντιγράψετε ή να μετακινήσετε περισσότερα αρχεία μόλις γίνει αυτό"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Δεν ήταν δυνατή η αντιγραφή αρχείων"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Δεν ήταν δυνατή η μετακίνηση αρχείων"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Το συνολικό μέγεθος αρχείων είναι πολύ μεγάλο"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Μπορείτε να αντιγράψετε ή να μετακινήσετε μόνο έως 2 GB κάθε φορά"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Επιλέχθηκαν πάρα πολλά αρχεία"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Μπορείτε να αντιγράψετε ή να μετακινήσετε μόνο έως 100 αρχεία κάθε φορά"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Δεν είναι δυνατή η προσθήκη αρχείων"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Δεν έχετε επαρκή αποθηκευτικό χώρο συσκευής"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ΟΚ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Αποδεσμεύστε χώρο"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Δεν είναι δυνατή η αντιγραφή ή η μετακίνηση αρχείων από τον Ιδιωτικό χώρο"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Δεν ήταν δυνατή η αντιγραφή ορισμένων αρχείων"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Δεν ήταν δυνατή η μετακίνηση ορισμένων αρχείων"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Ο ιδιωτικός σας χώρος έκλεισε κατά την αντιγραφή"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Ο ιδιωτικός σας χώρος έκλεισε κατά τη μετακίνηση"</string>
 </resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 2236c6d..7fb9bee 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Move"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copy"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancel"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copying <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Moving <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> file(s) copied"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> file(s) moved"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Your chosen files are being copied to your private space"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Your chosen files are being moved to your private space"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Your chosen files were copied to your private space"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Your chosen files were moved to your private space"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copying # file}other{Copying # files}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Moving # file}other{Moving # files}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# file copied}other{# files copied}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# file moved}other{# files moved}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Your chosen file is being copied to your private space}other{Your chosen files are being copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Your chosen file is being moved to your private space}other{Your chosen files are being moved to your private space}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Your chosen file was copied to your private space}other{Your chosen files were copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Your chosen file was moved to your private space}other{Your chosen files were moved to your private space}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Show files"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"File transfer notifications"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"When you copy or move files to your private space, you can receive notifications to update you on the progress"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Can\'t copy some files"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Can\'t move some files"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"You can try to copy your files again"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"You can try to move your files again"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Still copying files"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Still moving files"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"You can copy or move more files once this is finished"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Couldn\'t copy files"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Couldn\'t move files"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Total file size is too large"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"You can only copy or move up to 2 GB at once"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Too many files selected"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"You can only copy or move up to 100 files at once"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Can\'t add files"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"You don\'t have enough device storage"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Free up space"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Can\'t copy or move files from private space"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Couldn\'t copy some files"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Couldn\'t move some files"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Your private space was closed while copying"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Your private space was closed while moving"</string>
 </resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 550cc1b..23eb358 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Move"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copy"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancel"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copying <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Moving <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> file(s) copied"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> file(s) moved"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Your chosen files are being copied to your private space"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Your chosen files are being moved to your private space"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Your chosen files were copied to your private space"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Your chosen files were moved to your private space"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copying # file}other{Copying # files}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Moving # file}other{Moving # files}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# file copied}other{# files copied}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# file moved}other{# files moved}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Your chosen file is being copied to your private space}other{Your chosen files are being copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Your chosen file is being moved to your private space}other{Your chosen files are being moved to your private space}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Your chosen file was copied to your private space}other{Your chosen files were copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Your chosen file was moved to your private space}other{Your chosen files were moved to your private space}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Show files"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"File transfer notifications"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"When you copy or move files to your private space, you can receive notifications to update you on the progress"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Can\'t copy some files"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Can\'t move some files"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"You can try to copy your files again"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"You can try to move your files again"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Still copying files"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Still moving files"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"You can copy or move more files once this is done"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Couldn\'t copy files"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Couldn\'t move files"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Total file size is too large"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"You can only copy or move up to 2 GB at once"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Too many files selected"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"You can only copy or move up to 100 files at once"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Can\'t add files"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"You don’t have enough device storage"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Free up space"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Can\'t copy or move files from Private Space"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Couldn\'t copy some files"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Couldn\'t move some files"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Your private space was closed while copying"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Your private space was closed while moving"</string>
 </resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 2236c6d..7fb9bee 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Move"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copy"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancel"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copying <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Moving <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> file(s) copied"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> file(s) moved"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Your chosen files are being copied to your private space"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Your chosen files are being moved to your private space"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Your chosen files were copied to your private space"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Your chosen files were moved to your private space"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copying # file}other{Copying # files}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Moving # file}other{Moving # files}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# file copied}other{# files copied}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# file moved}other{# files moved}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Your chosen file is being copied to your private space}other{Your chosen files are being copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Your chosen file is being moved to your private space}other{Your chosen files are being moved to your private space}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Your chosen file was copied to your private space}other{Your chosen files were copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Your chosen file was moved to your private space}other{Your chosen files were moved to your private space}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Show files"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"File transfer notifications"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"When you copy or move files to your private space, you can receive notifications to update you on the progress"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Can\'t copy some files"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Can\'t move some files"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"You can try to copy your files again"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"You can try to move your files again"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Still copying files"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Still moving files"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"You can copy or move more files once this is finished"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Couldn\'t copy files"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Couldn\'t move files"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Total file size is too large"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"You can only copy or move up to 2 GB at once"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Too many files selected"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"You can only copy or move up to 100 files at once"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Can\'t add files"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"You don\'t have enough device storage"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Free up space"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Can\'t copy or move files from private space"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Couldn\'t copy some files"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Couldn\'t move some files"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Your private space was closed while copying"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Your private space was closed while moving"</string>
 </resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 2236c6d..7fb9bee 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Move"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copy"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancel"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copying <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Moving <xliff:g id="FILES">%1$d</xliff:g> file(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> file(s) copied"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> file(s) moved"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Your chosen files are being copied to your private space"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Your chosen files are being moved to your private space"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Your chosen files were copied to your private space"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Your chosen files were moved to your private space"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copying # file}other{Copying # files}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Moving # file}other{Moving # files}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# file copied}other{# files copied}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# file moved}other{# files moved}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Your chosen file is being copied to your private space}other{Your chosen files are being copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Your chosen file is being moved to your private space}other{Your chosen files are being moved to your private space}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Your chosen file was copied to your private space}other{Your chosen files were copied to your private space}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Your chosen file was moved to your private space}other{Your chosen files were moved to your private space}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Show files"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"File transfer notifications"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"When you copy or move files to your private space, you can receive notifications to update you on the progress"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Can\'t copy some files"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Can\'t move some files"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"You can try to copy your files again"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"You can try to move your files again"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Still copying files"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Still moving files"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"You can copy or move more files once this is finished"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Couldn\'t copy files"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Couldn\'t move files"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Total file size is too large"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"You can only copy or move up to 2 GB at once"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Too many files selected"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"You can only copy or move up to 100 files at once"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Can\'t add files"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"You don\'t have enough device storage"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Free up space"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Can\'t copy or move files from private space"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Couldn\'t copy some files"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Couldn\'t move some files"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Your private space was closed while copying"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Your private space was closed while moving"</string>
 </resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 55d67c2..5e504ff 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Agrega archivos"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Instala apps"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"¿Quieres mover o copiar los archivos?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Si mueves estos archivos a tu espacio privado, se quitarán de sus carpetas originales"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Si mueves estos archivos a tu espacio privado, se quitarán de las carpetas originales"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mover"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiar"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancelar"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copiando <xliff:g id="FILES">%1$d</xliff:g> archivo(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Moviendo <xliff:g id="FILES">%1$d</xliff:g> archivo(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Archivos copiados: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Archivos movidos: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Se están copiando los archivos que elegiste en tu espacio privado"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Se están moviendo los archivos que elegiste en tu espacio privado"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Se copiaron los archivos que elegiste en tu espacio privado"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Se movieron los archivos que elegiste en tu espacio privado"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copiando # archivo}many{Copiando # de archivos}other{Copiando # archivos}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Moviendo # archivo}many{Moviendo # archivos}other{Moviendo # archivos}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# archivo copiado}many{# de archivos copiados}other{# archivos copiados}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# archivo movido}many{# de archivos movidos}other{# archivos movidos}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Se está copiando en tu espacio privado el archivo que elegiste}many{Se están copiando en tu espacio privado los archivos que elegiste}other{Se están copiando en tu espacio privado los archivos que elegiste}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Se está moviendo el archivo que elegiste a tu espacio privado}many{Se están moviendo los archivos que elegiste a tu espacio privado}other{Se están moviendo los archivos que elegiste a tu espacio privado}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Se copió en tu espacio privado el archivo que elegiste}many{Se copiaron en tu espacio privado los archivos que elegiste}other{Se copiaron en tu espacio privado los archivos que elegiste}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Se movió el archivo que elegiste a tu espacio privado}many{Se movieron los archivos que elegiste en tu espacio privado}other{Se movieron los archivos que elegiste en tu espacio privado}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostrar archivos"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notificaciones de transferencia de archivos"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Cuando copias o mueves archivos a tu espacio privado, puedes recibir notificaciones para conocer el progreso"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"No se pueden copiar algunos archivos"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"No se pueden transferir algunos archivos"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Puedes intentar volver a copiar tus archivos"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Puedes intentar transferir tus archivos de nuevo"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Aún se están copiando los archivos"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Aún se están transfiriendo los archivos"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Podrás copiar o mover más archivos cuando se complete"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"No se pudieron copiar los archivos"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"No se pudieron transferir los archivos"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"El archivo es demasiado grande"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Solo puedes copiar o transferir hasta 2 GB a la vez"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Se seleccionaron demasiados archivos"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Solo puedes copiar o transferir hasta 100 archivos a la vez"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"No se pueden agregar archivos"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"No tienes suficiente espacio de almacenamiento en el dispositivo"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Aceptar"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Liberar espacio"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"No se pueden copiar ni mover archivos del espacio privado"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"No se pudieron copiar algunos archivos"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"No se pudieron transferir algunos archivos"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Se cerró tu espacio privado mientras se realizaba la copia"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Se cerró tu espacio privado mientras se realizaba la transferencia"</string>
 </resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 40000ed..5a4e1a9 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mover"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiar"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancelar"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copiando <xliff:g id="FILES">%1$d</xliff:g> archivo(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Moviendo <xliff:g id="FILES">%1$d</xliff:g> archivo(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Archivos copiados: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Archivos movidos: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Los archivos seleccionados se están copiando en tu espacio privado"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Los archivos seleccionados se están moviendo a tu espacio privado"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Los archivos seleccionados se han copiado en tu espacio privado"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Los archivos seleccionados se han movido a tu espacio privado"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copiando # archivo}many{Copiando # archivos}other{Copiando # archivos}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Moviendo # archivo}many{Moviendo # archivos}other{Moviendo # archivos}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# archivo copiado}many{# archivos copiados}other{# archivos copiados}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# archivo movido}many{# archivos movidos}other{# archivos movidos}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{El archivo seleccionado se está copiando en tu espacio privado}many{Los archivos seleccionados se están copiando en tu espacio privado}other{Los archivos seleccionados se están copiando en tu espacio privado}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{El archivo seleccionado se está moviendo a tu espacio privado}many{Los archivos seleccionados se están moviendo a tu espacio privado}other{Los archivos seleccionados se están moviendo a tu espacio privado}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{El archivo seleccionado se ha copiado en tu espacio privado}many{Los archivos seleccionados se han copiado en tu espacio privado}other{Los archivos seleccionados se han copiado en tu espacio privado}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{El archivo seleccionado se ha movido a tu espacio privado}many{Los archivos seleccionados se han movido a tu espacio privado}other{Los archivos seleccionados se han movido a tu espacio privado}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostrar archivos"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notificaciones de transferencia de archivos"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Cuando copias o mueves archivos a tu espacio privado, puedes recibir notificaciones para estar al tanto del progreso"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"No se pueden copiar algunos archivos"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"No se pueden mover algunos archivos"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Puedes intentar copiar tus archivos de nuevo"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Puedes intentar mover tus archivos de nuevo"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Aún se están copiando archivos"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Aún se están moviendo archivos"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Podrás copiar o mover más archivos cuando se complete"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"No se han podido copiar los archivos"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"No se han podido mover los archivos"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"El tamaño total del archivo es demasiado grande"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Solo puedes copiar o mover hasta 2 GB por vez"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Has seleccionado demasiados archivos"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Solo puedes copiar o mover hasta 100 archivos por vez"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"No se pueden añadir archivos"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"No hay suficiente espacio de almacenamiento en el dispositivo"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Aceptar"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Liberar espacio"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"No se pueden copiar ni mover archivos del espacio privado"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"No se han podido copiar algunos archivos"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"No se han podido mover algunos archivos"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Tu espacio privado se ha cerrado durante la copia de archivos"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Tu espacio privado se ha cerrado mientras se movían archivos"</string>
 </resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 82c151a..0ff24bd 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Failide lisamine"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Rakenduste installimine"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Kas soovite failid teisaldada või kopeerida?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Kui teisaldate need failid privaatsesse ruumi, eemaldatakse need algsetest kaustadest"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Kui teisaldate need failid privaatsesse ruumi, eemaldatakse need algsetest kaustadest."</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Teisalda"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopeeri"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Tühista"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopeeritakse <xliff:g id="FILES">%1$d</xliff:g> faili"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Teisaldatakse <xliff:g id="FILES">%1$d</xliff:g> faili"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fail(i) on kopeeritud"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fail(i) on teisaldatud"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Teie valitud failid kopeeritakse teie privaatsesse ruumi"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Teie valitud faile teisaldatakse teie privaatsesse ruumi"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Teie valitud failid kopeeriti teie privaatsesse ruumi"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Teie valitud failid teisaldati teie privaatsesse ruumi"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# faili kopeerimine}other{# faili kopeerimine}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# faili teisaldamine}other{# faili teisaldamine}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fail on kopeeritud}other{# faili on kopeeritud}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fail on teisaldatud}other{# faili on teisaldatud}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Teie valitud fail kopeeritakse teie privaatsesse ruumi.}other{Teie valitud failid kopeeritakse teie privaatsesse ruumi.}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Teie valitud fail teisaldatakse teie privaatsesse ruumi.}other{Teie valitud failid teisaldatakse teie privaatsesse ruumi.}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Teie valitud fail kopeeriti teie privaatsesse ruumi}other{Teie valitud failid kopeeriti teie privaatsesse ruumi}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Teie valitud fail teisaldati teie privaatsesse ruumi.}other{Teie valitud failid teisaldati teie privaatsesse ruumi.}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Kuva failid"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Failiedastuse märguanded"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kui kopeerite või teisaldate failid oma privaatsesse ruumi, on teil võimalik saada märguandeid, mis annavad teavet edenemise kohta"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Mõnda faili ei saa kopeerida"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Mõnda faili ei saa teisaldada"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Võite proovida faile uuesti kopeerida"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Võite proovida faile uuesti teisaldada"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Kopeerimine endiselt käib"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Teisaldamine endiselt käib"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Kui see on tehtud, saate rohkem faile kopeerida või teisaldada."</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Faile ei saanud kopeerida"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Faile ei saanud teisaldada"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Faili kogumaht on liiga suur"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Korraga saate kopeerida või teisaldada ainult kuni 2 GB."</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Valitud on liiga palju faile"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Korraga saate kopeerida või teisaldada ainult kuni 100 faili."</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Faile ei saa lisada"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Teil ei ole piisavalt seadme salvestusruumi"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Ruumi vabastamine"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Faile ei saa privaatsest ruumist kopeerida ega teisaldada"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Osa faile jäi kopeerimata"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Osa faile jäi teisaldamata"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Teie privaatne ruum suleti kopeerimise ajal"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Teie privaatne ruum suleti teisaldamise ajal"</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index af097fd..6a813b0 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mugitu"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiatu"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Utzi"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> fitxategi kopiatzen"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> fitxategi mugitzen"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fitxategi kopiatu dira"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fitxategi mugitu dira"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Aukeratu dituzun fitxategiak eremu pribatuan kopiatzen"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Aukeratu dituzun fitxategiak eremu pribatura eramaten"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Kopiatu dira aukeratu dituzun fitxategiak eremu pribatuan"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Eraman dira aukeratu dituzun fitxategiak eremu pribatura"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# fitxategi kopiatzen}other{# fitxategi kopiatzen}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# fitxategi eramaten}other{# fitxategi eramaten}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fitxategi kopiatu da}other{# fitxategi kopiatu dira}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fitxategi eraman da}other{# fitxategi eraman dira}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Aukeratu duzun fitxategia eremu pribatuan kopiatzen ari gara}other{Aukeratu dituzun fitxategiak eremu pribatuan kopiatzen ari gara}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Aukeratu duzun fitxategia eremu pribatura eramaten ari gara}other{Aukeratu dituzun fitxategiak eremu pribatura eramaten ari gara}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Kopiatu da aukeratu duzun fitxategia eremu pribatuan}other{Kopiatu dira aukeratu dituzun fitxategiak eremu pribatuan}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Eraman da aukeratu duzun fitxategia eremu pribatura}other{Eraman dira aukeratu dituzun fitxategiak eremu pribatura}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Erakutsi fitxategiak"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Fitxategi-transferentziei buruzko jakinarazpenak"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Fitxategiak zure eremu pribatuan kopiatzen edo hartara eramaten dituzunean, garapenari buruzko jakinarazpenak jasoko dituzu"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Ezin dira kopiatu fitxategi batzuk"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Ezin dira mugitu fitxategi batzuk"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Berriro saia zaitezke fitxategiak kopiatzen"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Berriro saia zaitezke fitxategiak mugitzen"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Fitxategiak kopiatzen oraindik ere"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Fitxategiak mugitzen oraindik ere"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Hau amaitzean kopiatu edo mugitu ahal izango dituzu fitxategi gehiago"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Ezin izan dira kopiatu fitxategiak"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Ezin izan dira mugitu fitxategiak"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Fitxategien guztizko tamaina handiegia da"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Gehienez 2 GB kopiatu edo mugi ditzakezu aldi berean"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Fitxategi gehiegi hautatu dituzu"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Gehienez 100 fitxategi kopiatu edo mugi ditzakezu aldi berean"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Ezin dira gehitu fitxategiak"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Ez duzu behar adina biltegiratze gailuan"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Ados"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Egin tokia"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Eremu pribatuko fitxategiak ezin dira kopiatu, ezta mugitu ere"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Ezin izan dira kopiatu fitxategi batzuk"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Ezin izan dira mugitu fitxategi batzuk"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Zure eremu pribatua itxi egin da kopiatu bitartean"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Zure eremu pribatua itxi egin da mugitu bitartean"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 9cca521..fa138ba 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"انتقال"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"کپی"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"لغو"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"درحال کپی کردن <xliff:g id="FILES">%1$d</xliff:g> فایل"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"درحال انتقال <xliff:g id="FILES">%1$d</xliff:g> فایل"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"‫<xliff:g id="FILES">%1$d</xliff:g> فایل کپی شد"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"‫<xliff:g id="FILES">%1$d</xliff:g> فایل منتقل شد"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"فایل‌هایی که انتخاب کرده‌اید درحال کپی شدن در فضای خصوصی‌تان هستند"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"فایل‌هایی که انتخاب کرده‌اید درحال انتقال به فضای خصوصی‌تان هستند"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"فایل‌هایی که انتخاب کرده‌اید در فضای خصوصی‌تان کپی می‌شوند"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"فایل‌هایی که انتخاب کرده‌اید به فضای خصوصی‌تان منتقل شدند"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{درحال کپی کردن # فایل}one{درحال کپی کردن # فایل}other{درحال کپی کردن # فایل}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{درحال انتقال # فایل}one{درحال انتقال # فایل}other{درحال انتقال # فایل}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{‫# فایل کپی شد}one{‫# فایل کپی شد}other{‫# فایل کپی شد}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{‫# فایل منتقل شد}one{‫# فایل منتقل شد}other{‫# فایل منتقل شد}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{فایلی که انتخاب کردید درحال کپی شدن در فضای خصوصی‌تان است}one{فایل‌هایی که انتخاب کردید درحال کپی شدن در فضای خصوصی‌تان هستند}other{فایل‌هایی که انتخاب کردید درحال کپی شدن در فضای خصوصی‌تان هستند}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{فایلی که انتخاب کردید درحال انتقال به فضای خصوصی‌تان است}one{فایل‌هایی که انتخاب کردید درحال انتقال به فضای خصوصی‌تان هستند}other{فایل‌هایی که انتخاب کردید درحال انتقال به فضای خصوصی‌تان هستند}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{فایلی که انتخاب کردید در فضای خصوصی‌تان کپی شد}one{فایل‌هایی که انتخاب کردید در فضای خصوصی‌تان کپی شدند}other{فایل‌هایی که انتخاب کردید در فضای خصوصی‌تان کپی شدند}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{فایلی که انتخاب کردید به فضای خصوصی‌تان منتقل شد}one{فایل‌هایی که انتخاب کردید به فضای خصوصی‌تان منتقل شدند}other{فایل‌هایی که انتخاب کردید به فضای خصوصی‌تان منتقل شدند}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"نشان دادن فایل‌ها"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"اعلان‌های انتقال فایل"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"وقتی فایل‌ها را به فضای خصوصی‌تان منتقل یا در آن کپی می‌کنید، می‌توانید اعلان‌هایی دریافت کنید که پیشرفت را به شما اطلاع می‌دهند"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"برخی فایل‌ها کپی نشد"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"برخی فایل‌ها منتقل نشد"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"می‌توانید فایل‌ها را دوباره کپی کنید"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"می‌توانید فایل‌ها را دوباره انتقال دهید"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"هنوز درحال کپی کردن فایل‌ها هستیم"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"هنوز درحال انتقال فایل‌ها هستیم"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"پس‌از اتمام این کار، می‌توانید فایل‌های بیشتری را کپی کنید یا انتقال دهید"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"فایل‌ها کپی نشد"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"فایل‌ها منتقل نشد"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"حجم کل فایل خیلی بزرگ است"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"فقط می‌توانید تا ۲ گیگابایت را هم‌زمان کپی کنید یا انتقال دهید"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"تعداد فایل‌های انتخاب‌شده خیلی زیاد است"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"فقط می‌توانید تا ۱۰۰ فایل را هم‌زمان کپی کنید یا انتقال دهید"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"فایل‌ها اضافه نشد"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"فضای ذخیره‌سازی کافی در دستگاه ندارید"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"بسیارخوب"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"آزاد کردن فضا"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"کپی یا منتقل کردن فایل‌ها از «فضای خصوصی» ممکن نیست"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"برخی‌از فایل‌ها کپی نشدند"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"برخی‌از فایل‌ها منتقل نشدند"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"فضای خصوصی شما هنگام کپی کردن بسته شد"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"فضای خصوصی شما هنگام انتقال دادن بسته شد"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 0b57a0e..e954c39 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Siirrä"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopioi"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Peru"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopioidaan <xliff:g id="FILES">%1$d</xliff:g> tiedostoa"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Siirretään <xliff:g id="FILES">%1$d</xliff:g> tiedostoa"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Kopioidut tiedostot: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Siirretyt tiedostot: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Valittuja tiedostoja kopioidaan yksityiseen tilaan"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Valittuja tiedostoja siirretään yksityiseen tilaan"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Valitut tiedostot on kopioitu yksityiseen tilaan"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Valitut tiedostot on siirretty yksityiseen tilaan"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopioidaan # tiedosto}other{Kopioidaan # tiedostoa}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Siirretään # tiedostoa}other{Siirretään # tiedostoa}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# tiedosto kopioitu}other{# tiedostoa kopioitu}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# tiedosto siirretty}other{# tiedostoa siirretty}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Valittua tiedostoa kopioidaan yksityiseen tilaan}other{Valittuja tiedostoja kopioidaan yksityiseen tilaan}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Valittua tiedostoa siirretään yksityiseen tilaan}other{Valittuja tiedostoja siirretään yksityiseen tilaan}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Valittu tiedosto on kopioitu yksityiseen tilaan}other{Valitut tiedostot on kopioitu yksityiseen tilaan}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Valittu tiedosto on siirretty yksityiseen tilaan}other{Valitut tiedostot on siirretty yksityiseen tilaan}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Näytä tiedostot"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Tiedostonsiirtoilmoitukset"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kun kopioit tai siirrät tiedostoja yksityiseen tilaan, saat ilmoituksia edistymisestä"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Joitakin tiedostoja ei voi kopioida"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Joitakin tiedostoja ei voi siirtää"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Voit yrittää kopioida tiedostot uudelleen"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Voit yrittää siirtää tiedostot uudelleen"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Tiedostojen kopiointi on kesken"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Tiedostojen siirtäminen on kesken"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Voit kopioida tai siirtää lisää tiedostoja, kun tämä on valmis"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Tiedostoja ei voitu kopioida"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Tiedostoja ei voitu siirtää"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Tiedostojen yhteenlaskettu koko on liian suuri"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Voit kopioida tai siirtää enintään 2 Gt kerrallaan"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Liian monta tiedostoa valittuna"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Voit kopioida tai siirtää enintään 100 tiedostoa kerrallaan"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Tiedostoja ei voi lisätä"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Laitteen tallennustila ei riitä"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Vapauta tilaa"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Tiedostoja ei voi kopioida tai siirtää yksityisestä tilasta"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Joitakin tiedostoja ei voitu kopioida"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Joitakin tiedostoja ei voitu siirtää"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Yksityinen tila suljettiin kopioinnin aikana"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Yksityinen tila suljettiin siirtämisen aikana"</string>
 </resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 0dbec26..c048c62 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Déplacer"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copier"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Annuler"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copie de <xliff:g id="FILES">%1$d</xliff:g> fichier(s) en cours…"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Déplacement de <xliff:g id="FILES">%1$d</xliff:g> fichier(s) en cours…"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fichier(s) copié(s)"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fichier(s) déplacé(s)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Vos fichiers choisis sont copiés dans votre espace privé"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Vos fichiers choisis sont déplacés vers votre espace privé"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Vos fichiers choisis ont été copiés dans votre espace privé"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Vos fichiers choisis ont été déplacés vers votre espace privé"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copie de # fichier en cours…}one{Copie de # fichier en cours…}many{Copie de # de fichiers en cours…}other{Copie de # fichiers en cours…}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Déplacement de # fichier en cours…}one{Déplacement de # fichier en cours…}many{Déplacement de # de fichiers en cours…}other{Déplacement de # fichiers en cours…}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fichier copié}one{# fichier copié}many{# de fichiers copiés}other{# fichiers copiés}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fichier déplacé}one{# fichier déplacé}many{# de fichiers déplacés}other{# fichiers déplacés}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Le fichier que vous avez choisi est copié dans votre espace privé}one{Le fichier que vous avez choisi est copié dans votre espace privé}many{Les fichiers que vous avez choisis sont copiés dans votre espace privé}other{Les fichiers que vous avez choisis sont copiés dans votre espace privé}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Le fichier que vous avez choisi est déplacé vers votre espace privé}one{Le fichier que vous avez choisi est déplacé vers votre espace privé}many{Les fichiers que vous avez choisis sont déplacés vers votre espace privé}other{Les fichiers que vous avez choisis sont déplacés vers votre espace privé}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Le fichier que vous avez choisi a été copié dans votre espace privé}one{Le fichier que vous avez choisi a été copié dans votre espace privé}many{Les fichiers que vous avez choisis ont été copiés dans votre espace privé}other{Les fichiers que vous avez choisis ont été copiés dans votre espace privé}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Le fichier que vous avez choisi a été déplacé vers votre espace privé}one{Le fichier que vous avez choisi a été déplacé vers votre espace privé}many{Les fichiers que vous avez choisis ont été déplacés vers votre espace privé}other{Les fichiers que vous avez choisis ont été déplacés vers votre espace privé}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Afficher les fichiers"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notifications de transfert de fichiers"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Lorsque vous copiez ou déplacez des fichiers vers votre espace privé, vous pouvez recevoir des notifications vous informant de la progression de l\'opération"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Impossible de copier certains fichiers"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Impossible de déplacer certains fichiers"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Vous pouvez essayer de copier à nouveau vos fichiers"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Vous pouvez essayer de déplacer à nouveau vos fichiers"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"La copie de fichiers est toujours en cours…"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Le déplacement de fichiers est toujours en cours…"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Vous pouvez copier ou déplacer d\'autres fichiers lorsque cette action est terminée"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Impossible de copier les fichiers"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Impossible de déplacer les fichiers"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"La taille totale du fichier est trop grande"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Vous ne pouvez copier ou déplacer que 2 Go à la fois"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Trop de fichiers sélectionnés"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Vous pouvez uniquement copier ou déplacer jusqu\'à 100 fichiers à la fois"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Impossible d\'ajouter des fichiers"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Vous n\'avez pas assez d\'espace de stockage sur l\'appareil"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Libérer de l\'espace"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Impossible de copier ou de déplacer des fichiers de l\'espace privé"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Impossible de copier certains fichiers"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Impossible de déplacer certains fichiers"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Votre espace privé a été fermé pendant la copie"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Votre espace privé a été fermé durant le déplacement"</string>
 </resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 105f98c..dc5e220 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -18,21 +18,43 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="private_space_app_label" msgid="4816454052314284927">"Espace privé"</string>
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Ajouter des fichiers"</string>
-    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Installer des applications"</string>
+    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Installer des applis"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Déplacer ou copier les fichiers ?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Si vous déplacez ces fichiers dans votre espace privé, ils seront supprimés de leur dossier d\'origine"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Si vous déplacez ces fichiers vers votre espace privé, ils seront supprimés de leur dossier d\'origine"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Déplacer"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copier"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Annuler"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copie de <xliff:g id="FILES">%1$d</xliff:g> fichier(s)…"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Déplacement de <xliff:g id="FILES">%1$d</xliff:g> fichier(s)…"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fichier(s) copié(s)"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fichier(s) déplacé(s)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Les fichiers sélectionnés sont en cours de copie dans votre espace privé"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Les fichiers que vous avez sélectionnés sont en cours de déplacement vers votre espace privé"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Les fichiers que vous avez choisis ont été copiés dans votre espace privé"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Les fichiers que vous avez choisis ont été déplacés dans votre espace privé"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copie de # fichier}one{Copie de # fichier}many{Copie de # de fichiers}other{Copie de # fichiers}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Déplacement de # fichier}one{Déplacement de # fichier}many{Déplacement de # de fichiers}other{Déplacement de # fichiers}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fichier copié}one{# fichier copié}many{# de fichiers copiés}other{# fichiers copiés}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fichier déplacé}one{# fichier déplacé}many{# de fichiers déplacés}other{# fichiers déplacés}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Le fichier que vous avez choisi est en train d\'être copié dans votre espace privé}one{Le fichier que vous avez choisi est en train d\'être copié dans votre espace privé}many{Les fichiers que vous avez choisis sont en train d\'être copiés dans votre espace privé}other{Les fichiers que vous avez choisis sont en train d\'être copiés dans votre espace privé}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Le fichier que vous avez choisi est en train d\'être déplacé vers votre espace privé}one{Le fichier que vous avez choisi est en train d\'être déplacé vers votre espace privé}many{Les fichiers que vous avez choisis sont en train d\'être déplacés vers votre espace privé}other{Les fichiers que vous avez choisis sont en train d\'être déplacés vers votre espace privé}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Le fichier que vous avez choisi a été copié dans votre espace privé}one{Le fichier que vous avez choisi a été copié dans votre espace privé}many{Les fichiers que vous avez choisis ont été copiés dans votre espace privé}other{Les fichiers que vous avez choisis ont été copiés dans votre espace privé}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Le fichier que vous avez choisi a été déplacé dans votre espace privé}one{Le fichier que vous avez choisi a été déplacé dans votre espace privé}many{Les fichiers que vous avez choisis ont été déplacés dans votre espace privé}other{Les fichiers que vous avez choisis ont été déplacés dans votre espace privé}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Afficher les fichiers"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notifications de transfert de fichiers"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Lorsque vous copiez ou déplacez des fichiers dans votre espace privé, vous pouvez recevoir des notifications pour suivre leur progression"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Impossible de copier certains fichiers"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Impossible de déplacer certains fichiers"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Vous pouvez réessayer de copier vos fichiers"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Vous pouvez réessayer de déplacer vos fichiers"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Copie de fichiers toujours en cours"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Déplacement de fichiers toujours en cours"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Vous pourrez copier ou déplacer d\'autres fichiers une fois cette opération terminée"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Impossible de copier les fichiers"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Impossible de déplacer les fichiers"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"La taille totale des fichiers est trop importante"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Vous ne pouvez copier ou déplacer que 2 Go à la fois"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Trop de fichiers sélectionnés"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Vous ne pouvez copier ou déplacer que 100 fichiers à la fois"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Impossible d\'ajouter des fichiers"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Espace de stockage insuffisant sur l\'appareil"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Libérer de l\'espace"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Impossible de copier ou de déplacer des fichiers depuis l\'espace privé"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Impossible de copier certains fichiers"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Impossible de déplacer certains fichiers"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Votre espace privé a été fermé lors de la copie"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Votre espace privé a été fermé lors du déplacement"</string>
 </resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 7f72c70..5e0b8ae 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mover"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiar"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancelar"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copiando ficheiros (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Movendo ficheiros (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Ficheiros copiados: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Ficheiros movidos: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Os ficheiros seleccionados estanse copiando no teu espazo privado"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Os ficheiros seleccionados estanse movendo ao teu espazo privado"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Os ficheiros seleccionados copiáronse no teu espazo privado"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Os ficheiros seleccionados movéronse ao teu espazo privado"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copiando # ficheiro}other{Copiando # ficheiros}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Movendo # ficheiro}other{Movendo # ficheiros}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ficheiro copiado}other{# ficheiros copiados}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ficheiro movido}other{# ficheiros movidos}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{O ficheiro seleccionado estase copiando no teu espazo privado}other{Os ficheiros seleccionados estanse copiando no teu espazo privado}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{O ficheiro seleccionado está movéndose ao teu espazo privado}other{Os ficheiros seleccionados estanse movendo ao teu espazo privado}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{O ficheiro seleccionado copiouse no teu espazo privado}other{Os ficheiros seleccionados copiáronse no teu espazo privado}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{O ficheiro seleccionado moveuse ao teu espazo privado}other{Os ficheiros seleccionados movéronse ao teu espazo privado}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostrar ficheiros"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notific. de transferencia de ficheiros"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Cando copias ou moves ficheiros ao teu espazo privado, podes recibir notificacións con actualizacións sobre o progreso"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Non se puideron copiar algúns ficheiros"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Non se puideron mover algúns ficheiros"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Podes tentar copiar os ficheiros de novo"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Podes tentar mover os ficheiros de novo"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Aínda están copiándose os ficheiros"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Aínda están movéndose os ficheiros"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Poderás copiar ou mover máis ficheiros cando finalice este proceso"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Non se puideron copiar os ficheiros"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Non se puideron mover os ficheiros"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"O tamaño total do ficheiro é excesivo"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Só podes copiar ou mover un máximo de 2 GB á vez"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Seleccionáronse demasiados ficheiros"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Só podes copiar ou mover un máximo de 100 ficheiros á vez"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Non se puideron engadir os ficheiros"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Non tes almacenamento suficiente no dispositivo"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Aceptar"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Liberar espazo"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Non se poden copiar nin mover os ficheiros do espazo privado"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Non se puideron copiar algúns ficheiros"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Non se puideron mover algúns ficheiros"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"O teu espazo privado estaba pechado mentres se copiaban os ficheiros"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"O teu espazo privado estaba pechado mentres se movían os ficheiros"</string>
 </resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index ab4d865..338daf4 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ખસેડો"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"કૉપિ કરો"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"રદ કરો"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ફાઇલ કૉપિ કરવામાં આવી રહી છે"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ફાઇલ ખસેડવામાં આવી રહી છે"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ફાઇલ કૉપિ કરી"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ફાઇલ ખસેડી"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી રહી છે"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી રહી છે"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી હતી"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી છે"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ફાઇલ કૉપિ કરી રહ્યાં છીએ}one{# ફાઇલ કૉપિ કરી રહ્યાં છીએ}other{# ફાઇલ કૉપિ કરી રહ્યાં છીએ}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ફાઇલ ખસેડી રહ્યાં છીએ}one{# ફાઇલ ખસેડી રહ્યાં છીએ}other{# ફાઇલ ખસેડી રહ્યાં છીએ}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ફાઇલ કૉપિ કરી}one{# ફાઇલ કૉપિ કરી}other{# ફાઇલ કૉપિ કરી}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ફાઇલ ખસેડી}one{# ફાઇલ ખસેડી}other{# ફાઇલ ખસેડી}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી રહી છે}one{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી રહી છે}other{તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી રહી છે}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી રહી છે}one{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી રહી છે}other{તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી રહી છે}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી હતી}one{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી હતી}other{તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં કૉપિ કરવામાં આવી હતી}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી હતી}one{તમારી પસંદ કરેલી ફાઇલ તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી હતી}other{તમારી પસંદ કરેલી ફાઇલો તમારી ખાનગી સ્પેસમાં ખસેડવામાં આવી હતી}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ફાઇલો બતાવો"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ફાઇલ ટ્રાન્સફરના નોટિફિકેશન"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"જ્યારે તમે ફાઇલોને તમારી ખાનગી સ્પેસમાં કૉપિ કરો છો અથવા ખસેડો છો, ત્યારે તમને પ્રગતિ વિશે અપડેટ કરવા માટે નોટિફિકેશન પ્રાપ્ત થઈ શકે છે"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"કેટલીક ફાઇલો કૉપિ કરી શકાતી નથી"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"કેટલીક ફાઇલો ખસેડી શકાતી નથી"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"તમે તમારી ફાઇલોને ફરીથી કૉપિ કરવાનો પ્રયાસ કરી શકો છો"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"તમે તમારી ફાઇલોને ફરીથી ખસેડવાનો પ્રયાસ કરી શકો છો"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ફાઇલો હજુ પણ કૉપિ કરી રહ્યા છીએ"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ફાઇલો હજુ પણ ખસેડી રહ્યા છીએ"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"એકવાર આ થઈ જાય પછી તમે વધુ ફાઇલોને કૉપિ કરી શકો છો અથવા ખસેડી શકો છો"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ફાઇલો કૉપિ કરી શક્યાં નહીં"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ફાઇલો ખસેડી શકાઈ નથી"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ફાઇલનું કુલ કદ ખૂબ મોટું છે"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"તમે એકવારમાં ફક્ત 2 GB સુધીની ફાઇલો કૉપિ અથવા ખસેડી શકો છો"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ઘણી બધી ફાઇલો પસંદ કરી"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"તમે એકસાથે ફક્ત 100 ફાઇલો કૉપિ અથવા ખસેડી શકો છો"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ફાઇલો ઉમેરી શકાતી નથી"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"તમારી પાસે પૂરતો ડિવાઇસ સ્ટોરેજ નથી"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ઓકે"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"સ્પેસ ખાલી કરો"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ખાનગી સ્પેસમાંથી ફાઇલ કૉપિ કરી શકાતી કે ખસેડી શકાતી નથી"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"કેટલીક ફાઇલો કૉપિ કરી શક્યા નથી"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"કેટલીક ફાઇલો કૉપિ ખસેડી શક્યા નથી"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"કૉપિ કરતી વખતે તમારી ખાનગી સ્પેસ બંધ હતી"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ખસેડતી વખતે તમારી ખાનગી સ્પેસ બંધ હતી"</string>
 </resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 4af588d..369d26d 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -19,20 +19,42 @@
     <string name="private_space_app_label" msgid="4816454052314284927">"प्राइवेट स्पेस"</string>
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"फ़ाइलें जोड़ें"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"ऐप्लिकेशन इंस्टॉल करें"</string>
-    <string name="move_files_dialog_title" msgid="4288920082565374705">"क्या आपको फ़ाइलें ट्रांसफ़र या कॉपी करनी हैं?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"अगर इन फ़ाइलों को प्राइवेट स्पेस में ट्रांसफ़र किया जाता है, तो ये ओरिजनल फ़ोल्डर से हट जाएंगी"</string>
+    <string name="move_files_dialog_title" msgid="4288920082565374705">"फ़ाइलों को ट्रांसफ़र करना हैं या कॉपी करना है?"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"प्राइवेट स्पेस में ट्रांसफ़र करने का विकल्प चुनने पर, फ़ाइलें ओरिजनल फ़ोल्डर से हट जाएंगी"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ट्रांसफ़र करें"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"कॉपी करें"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"रद्द करें"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> फ़ाइलें कॉपी हो रही हैं"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> फ़ाइलें ट्रांसफ़र की जा रही हैं"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> फ़ाइलों को कॉपी किया गया"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> फ़ाइलों को ट्रांसफ़र किया गया"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में कॉपी कर दिया गया है"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में ट्रांसफ़र किया जा रहा है"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में कॉपी कर दिया गया है"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में ट्रांसफ़र कर दिया गया है"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# फ़ाइल कॉपी की जा रही है}one{# फ़ाइल कॉपी की जा रही है}other{# फ़ाइलें कॉपी की जा रही हैं}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# फ़ाइल मूव की जा रही है}one{# फ़ाइल मूव की जा रही है}other{# फ़ाइलें मूव की जा रही हैं}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# फ़ाइल कॉपी की गई}one{# फ़ाइल कॉपी की गई}other{# फ़ाइलें कॉपी की गईं}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# फ़ाइल मूव कर दी गई}one{# फ़ाइल मूव कर दी गई}other{# फ़ाइलें मूव कर दी गईं}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में कॉपी किया जा रहा है}one{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में कॉपी किया जा रहा है}other{चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में कॉपी किया जा रहा है}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में मूव किया जा रहा है}one{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में मूव किया जा रहा है}other{चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में मूव किया जा रहा है}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में कॉपी कर दिया गया}one{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में कॉपी कर दिया गया}other{चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में कॉपी कर दिया गया}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में मूव कर दिया गया}one{चुनी गई फ़ाइल को आपके प्राइवेट स्पेस में मूव कर दिया गया}other{चुनी गई फ़ाइलों को आपके प्राइवेट स्पेस में मूव कर दिया गया}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"फ़ाइलें दिखाएं"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"फ़ाइल ट्रांसफ़र करने से जुड़ी सूचनाएं"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"फ़ाइलों को प्राइवेट स्पेस में ले जाने या कॉपी करने पर, इसकी जानकारी देने के लिए आपको सूचनाएं मिल सकती हैं."</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"कुछ फ़ाइलों को कॉपी नहीं किया जा सकता"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"कुछ फ़ाइलों को मूव नहीं किया जा सकता"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"अपनी फ़ाइलों को फिर से कॉपी करें"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"अपनी फ़ाइलों को फिर से मूव करने की कोशिश करें"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"फ़ाइलें अब भी कॉपी की जा रही हैं"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"फ़ाइलें अब भी ट्रांसफ़र की जा रही हैं"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"प्रोसेस पूरा होने के बाद, और फ़ाइलों को कॉपी या ट्रांसफ़र किया जा सकेगा"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"फ़ाइलों को कॉपी नहीं किया जा सकता"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"फ़ाइलों को ट्रांसफ़र नहीं किया जा सकता"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"फ़ाइल का साइज़ बहुत ज़्यादा बड़ा है"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"एक बार में सिर्फ़ 2 जीबी तक की फ़ाइलें कॉपी या मूव की जा सकती हैं"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"बहुत ज़्यादा फाइलें चुन ली गई हैं"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"एक बार में ज़्यादा से ज़्यादा 100 फाइलों को कॉपी या मूव किया जा सकता है"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"फ़ाइलें नहीं जोड़ी जा सकतीं"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"आपके डिवाइस में ज़रूरत के मुताबिक स्टोरेज नहीं है"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ठीक है"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"स्टोरेज खाली करें"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"प्राइवेट स्पेस से फ़ाइलें कॉपी या मूव नहीं की जा सकतीं"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"कुछ फ़ाइलें कॉपी नहीं की जा सकीं"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"कुछ फ़ाइलें मूव नहीं की जा सकीं"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"फ़ाइलें कॉपी करने के दौरान, आपका प्राइवेट स्पेस बंद हो गया था"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"फ़ाइलें मूव करने के दौरान, आपका प्राइवेट स्पेस बंद हो गया था"</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 5779a98..2ed4491 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Premjesti"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiraj"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Odustani"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopiranje datoteka (njih <xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Premještanje datoteka (njih <xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Broj kopiranih datoteka: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Datoteke su premještene (njih <xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Odabrane datoteke kopiraju se u vaš privatni prostor"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Odabrane datoteke premještaju se u vaš privatni prostor"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Odabrane datoteke kopirane su u vaš privatni prostor"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Odabrane datoteke premještene su u vaš privatni prostor"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopira se # datoteka}one{Kopira se # datoteka}few{Kopiraju se # datoteke}other{Kopira se # datoteka}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Premješta se # datoteka}one{Premješta se # datoteka}few{Premještaju se # datoteke}other{Premješta se # datoteka}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Broj kopiranih datoteka: #}one{Broj kopiranih datoteka: #}few{Broj kopiranih datoteka: #}other{Broj kopiranih datoteka: #}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Premještena je # datoteka}one{Premještena je # datoteka}few{Premještene su # datoteke}other{Premješteno je # datoteka}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Odabrana datoteka kopira se u vaš privatni prostor}one{Odabrana datoteka kopira se u vaš privatni prostor}few{Odabrane datoteke kopiraju se u vaš privatni prostor}other{Odabranih datoteka kopira se u vaš privatni prostor}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Odabrana datoteka premješta se u vaš privatni prostor}one{Odabrana datoteka premješta se u vaš privatni prostor}few{Odabrane datoteke premještaju se u vaš privatni prostor}other{Odabrane datoteke premještaju se u vaš privatni prostor}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Odabrana datoteka kopirana je u vaš privatni prostor}one{Odabrana datoteka kopirana je u vaš privatni prostor}few{Odabrane datoteke kopirane su u vaš privatni prostor}other{Odabranih datoteka kopirano je u vaš privatni prostor}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Odabrana datoteka premještena je u vaš privatni prostor}one{Odabrana datoteka premještena je u vaš privatni prostor}few{Odabrane datoteke premještene su u vaš privatni prostor}other{Odabranih datoteka premješteno je u vaš privatni prostor}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Prikaži datoteke"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Obavijesti o prijenosu datoteka"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kad kopirate ili premjestite datoteke u privatni prostor, možete primati obavijesti o napretku"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Neke se datoteke ne mogu kopirati"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Neke se datoteke ne mogu premjestiti"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Možete pokušati ponovo kopirati datoteke"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Možete pokušati ponovo premjestiti datoteke"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Datoteke se i dalje kopiraju"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Datoteke se i dalje premještaju"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Kad kopiranje završi, možete kopirati ili premjestiti druge datoteke"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Kopiranje datoteka nije uspjelo"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Premještanje datoteka nije uspjelo"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Ukupna veličina datoteka je prevelika"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Možete kopirati ili premjestiti najviše 2 GB odjednom"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Odabrano je previše datoteka"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Možete kopirati ili premjestiti najviše 100 datoteka odjednom"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nije moguće dodati datoteke"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Nemate dovoljno pohrane na uređaju"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"U redu"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Oslobađanje prostora"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Datoteke se ne mogu kopirati ili premjestiti iz privatnog prostora"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Kopiranje nekih datoteka nije uspjelo"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Premještanje nekih datoteka nije uspjelo"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Vaš je privatni prostor zatvoren tijekom kopiranja"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Vaš je privatni prostor zatvoren tijekom premještanja"</string>
 </resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 99e9f14..abdef47 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Áthelyezés"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Másolás"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Mégse"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> fájl másolása…"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> fájl áthelyezése…"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fájl átmásolva"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fájl áthelyezve"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Folyamatban van a kiválasztott fájlok átmásolása a privát területre"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"A kiválasztott fájlok áthelyezése a privát területre…"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"A kiválasztott fájlok át lettek másolva a privát területre"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"A kiválasztott fájlok át lettek helyezve a privát területre"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# fájl másolása…}other{# fájl másolása…}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# fájl áthelyezése…}other{# fájl áthelyezése…}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fájl átmásolva}other{# fájl átmásolva}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fájl áthelyezve}other{# fájl áthelyezve}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Folyamatban van a kiválasztott fájl átmásolása a privát területre}other{Folyamatban van a kiválasztott fájlok átmásolása a privát területre}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Folyamatban van a kiválasztott fájl áthelyezése a privát területre}other{Folyamatban van a kiválasztott fájlok áthelyezése a privát területre}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{A kiválasztott fájl át lett másolva a privát területre}other{A kiválasztott fájlok át lettek másolva a privát területre}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{A kiválasztott fájl át lett helyezve a privát területre}other{A kiválasztott fájlok át lettek helyezve a privát területre}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Fájlok megjelenítése"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Fájlátviteli értesítések"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Amikor fájlokat másol vagy helyez át a privát területére, tájékoztató értesítéseket kaphat az előrehaladásról"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Néhány fájl másolása nem sikerült"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nem sikerült áthelyezni néhány fájlt"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Megpróbálkozhat ismét a fájlok másolásával"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Megpróbálkozhat ismét a fájlok áthelyezésével"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"A fájlok másolása még folyamatban van"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"A fájlok áthelyezése még folyamatban van"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Ha befejeződött, további fájlokat is másolhat és áthelyezhet"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Nem sikerült átmásolni a fájlokat"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Nem sikerült áthelyezni a fájlokat"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"A fájlok összmérete túl nagy"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Egyszerre legfeljebb 2 GB-ot másolhat vagy helyezhet át"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Túl sok fájl van kiválasztva"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Egyszerre legfeljebb 100 fájlt másolhat vagy helyezhet át"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nem lehet fájlokat hozzáadni"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Nincs elég tárhely az eszközön"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Tárhely felszabadítása"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Privát területről nem lehet fájlokat másolni vagy áthelyezni"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Nem sikerült átmásolni néhány fájlt"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Nem sikerült áthelyezni néhány fájlt"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"A másolás közben bezárult a privát terület"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Az áthelyezés közben bezárult a privát terület"</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index c1ef46a..16f2ebf 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Ավելացնել ֆայլեր"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Տեղադրել հավելվածներ"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Պատճենե՞լ, թե՞ տեղափոխել ֆայլերը"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Եթե այս ֆայլերը տեղափոխեք մասնավոր տարածք, դրանք կհեռացվեն այն պանակներից, որոնցում ներկայումս գտնվում են"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Եթե այս ֆայլերը տեղափոխեք մասնավոր տարածք, դրանք կհեռացվեն պանակներից, որոնցում ներկայումս գտնվում են"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Տեղափոխել"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Պատճենել"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Չեղարկել"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ֆայլ պատճենվում է"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ֆայլ տեղափոխվում է"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ֆայլ պատճենվեց"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ֆայլ տեղափոխվեց"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Ընտրված ֆայլերը պատճենվում են ձեր մասնավոր տարածքում"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Ընտրված ֆայլերը տեղափոխվում են ձեր մասնավոր տարածք"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Ընտրված ֆայլերը պատճենվեցին ձեր մասնավոր տարածքում"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Ընտրված ֆայլերը տեղափոխվեցին ձեր մասնավոր տարածք"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ֆայլ պատճենվում է}one{# ֆայլ պատճենվում է}other{# ֆայլ պատճենվում է}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ֆայլ տեղափոխվում է}one{# ֆայլ տեղափոխվում է}other{# ֆայլ տեղափոխվում է}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ֆայլ պատճենվեց}one{# ֆայլ պատճենվեց}other{# ֆայլ պատճենվեց}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ֆայլ տեղափոխվեց}one{# ֆայլ տեղափոխվեց}other{# ֆայլ տեղափոխվեց}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Ընտրված ֆայլը պատճենվում է ձեր մասնավոր տարածքում}one{Ընտրված ֆայլը պատճենվում է ձեր մասնավոր տարածքում}other{Ընտրված ֆայլերը պատճենվում են ձեր մասնավոր տարածքում}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Ընտրված ֆայլը տեղափոխվում է ձեր մասնավոր տարածք}one{Ընտրված ֆայլը տեղափոխվում է ձեր մասնավոր տարածք}other{Ընտրված ֆայլերը տեղափոխվում են ձեր մասնավոր տարածք}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Ընտրված ֆայլը պատճենվեց ձեր մասնավոր տարածքում}one{Ընտրված ֆայլը պատճենվեց ձեր մասնավոր տարածքում}other{Ընտրված ֆայլերը պատճենվեցին ձեր մասնավոր տարածքում}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Ընտրված ֆայլը տեղափոխվեց ձեր մասնավոր տարածք}one{Ընտրված ֆայլը տեղափոխվեց ձեր մասնավոր տարածք}other{Ընտրված ֆայլերը տեղափոխվեցին ձեր մասնավոր տարածք}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Ցույց տալ ֆայլերը"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Ֆայլերի տեղափոխման մասին ծանուցումներ"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Երբ դուք ֆայլեր եք պատճենում ձեր մասնավոր տարածքում կամ տեղափոխում այնտեղ, ձեզ կարող են ուղարկվել գործընթացի կարգավիճակի մասին ծանուցումներ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Որոշ ֆայլեր չհաջողվեց պատճենել"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Որոշ ֆայլեր չհաջողվեց տեղափոխել"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Կարող եք նորից փորձել պատճենել ձեր ֆայլերը"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Կարող եք նորից փորձել տեղափոխել ձեր ֆայլերը"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Ֆայլերի պատճենումը դեռ չի ավարտվել"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Ֆայլերի տեղափոխումը դեռ չի ավարտվել"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Նոր ֆայլեր պատճենելու կամ տեղափոխելու համար սպասեք, մինչև ընթացիկ գործողությունն ավարտվի"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Չհաջողվեց պատճենել ֆայլերը"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Չհաջողվեց տեղափոխել ֆայլերը"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Ֆայլի ընդհանուր ծավալը չափազանց մեծ է"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Դուք կարող եք միանգամից պատճենել կամ տեղափոխել մինչև 2 ԳԲ ծավալով ֆայլեր"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Չափազանց շատ ֆայլեր են ընտրվել"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Դուք կարող եք միանգամից պատճենել կամ տեղափոխել մինչև 100 ֆայլ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Չհաջողվեց ավելացնել ֆայլերը"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Դուք ձեր սարքում բավարար տարածք չունեք"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Եղավ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Տարածք ազատել"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Հնարավոր չէ պատճենել կամ տեղափոխել ֆայլերը մասնավոր տարածքից"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Որոշ ֆայլեր չհաջողվեց պատճենել"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Որոշ ֆայլեր չհաջողվեց տեղափոխել"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Ձեր մասնավոր տարածքը փակվել է ֆայլերի պատճենման ընթացքում"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Ձեր մասնավոր տարածքը փակվել է ֆայլերի տեղափոխման ընթացքում"</string>
 </resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 51d481c..2ce6e25 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Pindahkan"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Salin"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Batal"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Menyalin <xliff:g id="FILES">%1$d</xliff:g> file"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Memindahkan <xliff:g id="FILES">%1$d</xliff:g> file"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> file disalin"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> file dipindahkan"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"File yang Anda pilih sedang disalin ke ruang privasi Anda"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"File yang Anda pilih sedang dipindahkan ke ruang privasi Anda"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"File yang Anda pilih telah disalin ke ruang privasi Anda"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"File yang Anda pilih telah dipindahkan ke ruang privasi Anda"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Menyalin # file}other{Menyalin # file}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Memindahkan # file}other{Memindahkan # file}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# file disalin}other{# file disalin}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# file dipindahkan}other{# file dipindahkan}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{File yang Anda pilih sedang disalin ke ruang privasi Anda}other{File yang Anda pilih sedang disalin ke ruang privasi Anda}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{File yang Anda pilih sedang dipindahkan ke ruang privasi Anda}other{File yang Anda pilih sedang dipindahkan ke ruang privasi Anda}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{File yang Anda pilih telah disalin ke ruang privasi Anda}other{File yang Anda pilih telah disalin ke ruang privasi Anda}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{File yang Anda pilih telah dipindahkan ke ruang privasi Anda}other{File yang Anda pilih telah dipindahkan ke ruang privasi Anda}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Tampilkan file"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notifikasi transfer file"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Saat menyalin atau memindahkan file ke ruang privasi, Anda dapat menerima notifikasi untuk mengetahui progresnya"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Tidak dapat menyalin beberapa file"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Tidak dapat memindahkan beberapa file"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Anda dapat mencoba menyalin file lagi"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Anda dapat mencoba memindahkan file lagi"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Masih menyalin file"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Masih memindahkan file"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Anda dapat menyalin atau memindahkan file lainnya setelah proses ini selesai"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Tidak dapat menyalin file"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Tidak dapat memindahkan file"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Total ukuran file terlalu besar"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Anda hanya dapat menyalin atau memindahkan maksimal 2 GB sekaligus"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Terlalu banyak file yang dipilih"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Anda hanya dapat menyalin atau memindahkan maksimal 100 file sekaligus"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Tidak dapat menambahkan file"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Anda tidak memiliki penyimpanan perangkat yang cukup"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Oke"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Kosongkan ruang penyimpanan"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Tidak dapat menyalin atau memindahkan file dari Ruang Privasi"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Tidak dapat menyalin beberapa file"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Tidak dapat memindahkan beberapa file"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Ruang privasi Anda ditutup saat menyalin"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Ruang privasi Anda ditutup saat memindahkan"</string>
 </resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 4724447..bcb4d29 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Bæta skrám við"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Setja upp forrit"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Færa eða afrita skrár?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Ef þú færir skrárnar yfir í leynirýmið þitt verða þær fjarlægðar úr upprunalegu möppum sínum"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Ef þú færir skrárnar yfir í leynirýmið þitt verða þær fjarlægðar úr upprunalegu möppunum"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Færa"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Afrita"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Hætta við"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Afritar <xliff:g id="FILES">%1$d</xliff:g> skrá(r)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Flytur <xliff:g id="FILES">%1$d</xliff:g> skrá(r)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> skrá(r) afrituð/afritaðar"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> skrá(r) flutt(ar)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Verið er að afrita völdu skrárnar yfir í leynirýmið þitt"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Verið er að flytja völdu skrárnar yfir í leynirýmið þitt"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Völdu skrárnar voru afritaðar yfir í leynirýmið þitt"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Völdu skrárnar voru fluttar yfir í leynirýmið þitt"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Afritar # skrá.}one{Afritar # skrá}other{Afritar # skrár}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Flytur # skrá}one{Flytur # skrá}other{Flytur # skrár}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# skrá afrituð}one{# skrá afrituð}other{# skrár afritaðar}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# skrá flutt}one{# skrá flutt}other{# skrár fluttar}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Verið er að afrita völdu skrána yfir í leynirýmið þitt}one{Verið er að afrita völdu skrárnar yfir í leynirýmið þitt}other{Verið er að afrita völdu skrárnar yfir í leynirýmið þitt}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Verið er að flytja völdu skrána yfir í leynirýmið þitt}one{Verið er að flytja völdu skrárnar yfir í leynirýmið þitt}other{Verið er að flytja völdu skrárnar yfir í leynirýmið þitt}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Valda skráin var afrituð yfir í leynirýmið þitt}one{Völdu skrárnar voru afritaðar yfir í leynirýmið þitt}other{Völdu skrárnar voru afritaðar yfir í leynirýmið þitt}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Valda skráin var færð yfir í leynirýmið þitt}one{Völdu skrárnar voru fluttar yfir í leynirýmið þitt}other{Völdu skrárnar voru fluttar yfir í leynirýmið þitt}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Sýna skrár"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Tilkynningar um skráarflutning"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Þegar þú afritar að flytur skrár yfir í leynirýmið geturðu fengið tilkynningar sem uppfæra þig um framvinduna"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Ekki tókst að afrita sumar skrárnar"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Ekki tókst að flytja sumar skrárnar"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Þú getur prófað að afrita skrárnar þínar aftur"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Þú getur prófað að flytja skrárnar þínar aftur"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Afritun skráa er enn í gangi"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Flutningur skráa er enn í gangi"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Þú getur afritað eða flutt fleiri skrár þegar því er lokið"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Ekki tókst að afrita skrár"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Ekki tókst að flytja skrár"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Heildarstærð skráa fer umfram hámarkið"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Þú getur afritað eða flutt að hámarki 2 GB í einu"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Of margar skrár valdar"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Þú getur afritað eða flutt að hámarki 100 skrár í einu"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Ekki tókst að bæta skrám við"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Þú ert ekki með nægt geymslurými í tækinu"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Í lagi"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Losa geymslupláss"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Ekki er hægt að afrita eða flytja skrár úr leynirými"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Ekki tókst að afrita allar skrár"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Ekki tókst að flytja allar skrár"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Leynirýmið þitt var lokað á meðan á afritun stóð"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Leynirýmið þitt var lokað meðan á flutningi stóð"</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index fed404a..3608cc3 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Sposta"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copia"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Annulla"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copia di file (<xliff:g id="FILES">%1$d</xliff:g>) in corso…"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Spostamento dei file (<xliff:g id="FILES">%1$d</xliff:g>) in corso…"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"File copiati: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"File spostati: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"È in corso la copia dei file che hai scelto nel tuo spazio privato"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"I file che hai scelto verranno spostati nel tuo spazio privato"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"I file che hai scelto sono stati copiati nel tuo spazio privato"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"I file che hai scelto sono stati spostati nel tuo spazio privato"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copia di # file in corso…}many{Copia di # di file in corso…}other{Copia di # file in corso…}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Spostamento di # file in corso…}many{Spostamento di # di file in corso…}other{Spostamento di # file in corso…}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# file copiato}many{# di file copiati}other{# file copiati}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# file spostato}many{# di file spostati}other{# file spostati}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{È in corso la copia del file che hai scelto nel tuo spazio privato}many{È in corso la copia dei file che hai scelto nel tuo spazio privato}other{È in corso la copia dei file che hai scelto nel tuo spazio privato}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{È in corso lo spostamento del file che hai scelto nel tuo spazio privato}many{È in corso lo spostamento dei file che hai scelto nel tuo spazio privato}other{È in corso lo spostamento dei file che hai scelto nel tuo spazio privato}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Il file che hai scelto è stato copiato nel tuo spazio privato}many{I file che hai scelto sono stati copiati nel tuo spazio privato}other{I file che hai scelto sono stati copiati nel tuo spazio privato}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Il file che hai scelto è stato spostato nel tuo spazio privato}many{I file che hai scelto sono stati spostati nel tuo spazio privato}other{I file che hai scelto sono stati spostati nel tuo spazio privato}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostra file"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notifiche di trasferimento file"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Quando copi o sposti file nel tuo spazio privato, puoi ricevere notifiche sull\'avanzamento"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Impossibile copiare alcuni file"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Impossibile spostare alcuni file"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Puoi provare a copiare di nuovo i file"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Puoi provare a spostare di nuovo i file"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Copia dei file ancora in corso…"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Spostamento dei file ancora in corso…"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Al termine, potrai copiare o spostare altri file"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Impossibile copiare i file"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Impossibile spostare i file"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Le dimensioni totali del file sono troppo grandi"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Puoi copiare o spostare solo fino a un massimo di 2 GB alla volta"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Troppi file selezionati"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Puoi copiare o spostare solo fino a un massimo di 100 file alla volta"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Impossibile aggiungere i file"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Lo spazio sul dispositivo non è sufficiente"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Ok"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Libera spazio"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Impossibile copiare o spostare file dallo spazio privato"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Impossibile copiare alcuni file"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Impossibile spostare alcuni file"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Il tuo spazio privato è stato chiuso durante la copia"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Il tuo spazio privato è stato chiuso durante lo spostamento"</string>
 </resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 0ab5774..4e50ac4 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"העברה"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"העתקה"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ביטול"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"מספר הקבצים שהמערכת מעתיקה: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"מספר הקבצים שהמערכת מעבירה: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"מספר הקבצים שהועתקו: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"מספר הקבצים שהועברו: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"הקבצים שבחרת מועתקים למרחב הפרטי שלך"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"הקבצים שבחרת מועברים למרחב הפרטי שלך"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"הקבצים שבחרת הועתקו למרחב הפרטי שלך"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"הקבצים שבחרת הועברו למרחב הפרטי שלך"</string>
-    <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"הצגת הקבצים"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{מועתק קובץ אחד}one{מועתקים # קבצים}two{מועתקים # קבצים}other{מועתקים # קבצים}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{מועבר קובץ אחד}one{מועברים # קבצים}two{מועברים # קבצים}other{מועברים # קבצים}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{הועתק קובץ אחד}one{הועתקו # קבצים}two{הועתקו # קבצים}other{הועתקו # קבצים}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{הועבר קובץ אחד}one{הועברו # קבצים}two{הועברו # קבצים}other{הועברו # קבצים}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{הקובץ שבחרת מועתק למרחב הפרטי שלך}one{הקבצים שבחרת מועתקים למרחב הפרטי שלך}two{הקבצים שבחרת מועתקים למרחב הפרטי שלך}other{הקבצים שבחרת מועתקים למרחב הפרטי שלך}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{הקובץ שבחרת מועבר למרחב הפרטי שלך}one{הקבצים שבחרת מועברים למרחב הפרטי שלך}two{הקבצים שבחרת מועברים למרחב הפרטי שלך}other{הקבצים שבחרת מועברים למרחב הפרטי שלך}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{הקובץ שבחרת הועתק למרחב הפרטי שלך}one{הקבצים שבחרת הועתקו למרחב הפרטי שלך}two{הקבצים שבחרת הועתקו למרחב הפרטי שלך}other{הקבצים שבחרת הועתקו למרחב הפרטי שלך}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{הקובץ שבחרת הועבר למרחב הפרטי שלך}one{הקבצים שבחרת הועברו למרחב הפרטי שלך}two{הקבצים שבחרת הועברו למרחב הפרטי שלך}other{הקבצים שבחרת הועברו למרחב הפרטי שלך}}"</string>
+    <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"לצפייה בקבצים"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"התראות לגבי העברת קבצים"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"כשמעתיקים או מעבירים קבצים למרחב הפרטי, אפשר לקבל התראות עם עדכונים על ההתקדמות"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"לא ניתן להעתיק חלק מהקבצים"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"לא ניתן להעביר חלק מהקבצים"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"אפשר לנסות להעתיק את הקבצים שוב"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"אפשר לנסות להעביר את הקבצים שוב"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"המערכת עדיין מעתיקה קבצים"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"העברת הקבצים עדיין לא הסתיימה"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"כשהיא תסתיים אפשר יהיה להעתיק או להעביר עוד קבצים"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"לא הייתה אפשרות להעתיק את הקבצים"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"לא הייתה אפשרות להעביר את הקבצים"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"הגודל של כל הקבצים ביחד חורג מהמכסה"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"‏אפשר להעתיק או להעביר רק עד 2GB בכל פעם"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"בחרת יותר מדי קבצים"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"אפשר להעתיק או להעביר רק עד 100 קבצים בכל פעם"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"לא ניתן להוסיף קבצים"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"אין מספיק נפח אחסון פנוי במכשיר"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"אישור"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"פינוי נפח אחסון"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"אי אפשר להעתיק או להעביר קבצים מהמרחב הפרטי"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"לא ניתן היה להעתיק חלק מהקבצים"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"לא ניתן היה להעביר חלק מהקבצים"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"המרחב הפרטי נסגר בזמן ההעתקה"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"המרחב הפרטי נסגר במהלך ההעברה"</string>
 </resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index c6edc99..471f76b 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"移動"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"コピー"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"キャンセル"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> 個のファイルをコピーしています"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> 個のファイルを移動しています"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> 個のファイルをコピーしました"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> 個のファイルを移動しました"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"選択したファイルをプライベート スペースにコピーしています"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"選択したファイルをプライベート スペースに移動しています"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"選択したファイルがプライベート スペースにコピーされました"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"選択したファイルをプライベート スペースに移動しました"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# 個のファイルをコピーしています}other{# 個のファイルをコピーしています}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# 個のファイルを移動しています}other{# 個のファイルを移動しています}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# 個のファイルをコピーしました}other{# 個のファイルをコピーしました}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# 個のファイルを移動しました}other{# 個のファイルを移動しました}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{選択したファイルをプライベート スペースにコピーしています}other{選択したファイルをプライベート スペースにコピーしています}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{選択したファイルをプライベート スペースに移動しています}other{選択したファイルをプライベート スペースに移動しています}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{選択したファイルがプライベート スペースにコピーされました}other{選択したファイルがプライベート スペースにコピーされました}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{選択したファイルをプライベート スペースに移動しました}other{選択したファイルをプライベート スペースに移動しました}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ファイルを表示"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ファイルの転送通知"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ファイルをプライベート スペースにコピーまたは移動すると通知が届き、現在の進行状況を確認できます"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"一部のファイルをコピーできません"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"一部のファイルを移動できません"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ファイルをもう一度コピーしてみてください"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ファイルをもう一度移動してみてください"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ファイルのコピー中です"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ファイルの移動中です"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"完了したら、他のファイルをコピーまたは移動できます"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ファイルをコピーできませんでした"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ファイルを移動できませんでした"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ファイルの合計サイズが大きすぎます"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"一度にコピーまたは移動できるデータのサイズは 2 GB までです"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"選択したファイルが多すぎます"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"一度にコピーまたは移動できるファイルは 100 個までです"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ファイルを追加できません"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"デバイスの空き容量が不足しています"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"空き容量を増やす"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"プライベート スペースからファイルをコピー、移動することはできません"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"一部のファイルをコピーできませんでした"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"一部のファイルを移動できませんでした"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"コピー中にプライベート スペースが終了しました"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"移動中にプライベート スペースが終了しました"</string>
 </resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index d63db91..1c2d385 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"გადატანა"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"კოპირება"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"გაუქმება"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"მიმდინარეობს <xliff:g id="FILES">%1$d</xliff:g> ფაილის კოპირება"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"მიმდინარეობს <xliff:g id="FILES">%1$d</xliff:g> ფაილის გადატანა"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"დაკოპირდა <xliff:g id="FILES">%1$d</xliff:g> ფაილი"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"გადატანილია <xliff:g id="FILES">%1$d</xliff:g> ფაილი"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"მიმდინარეობს თქვენ მიერ არჩეული ფაილების თქვენს კერძო სივრცეში კოპირება"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"მიმდინარეობს თქვენ მიერ არჩეული ფაილების თქვენს კერძო სივრცეში გადატანა"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"თქვენ მიერ არჩეული ფაილები დაკოპირდა თქვენს კერძო სივრცეში"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"თქვენ მიერ არჩეული ფაილები გადატანილია თქვენს კერძო სივრცეში"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{მიმდინარეობს # ფაილის კოპირება}other{მიმდინარეობს # ფაილის კოპირება}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{მიმდინარეობს # ფაილის გადატანა.}other{მიმდინარეობს # ფაილის გადატანა}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{დაკოპირდა # ფაილი}other{დაკოპირდა # ფაილი}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{გადატანილია # ფაილი}other{გადატანილია # ფაილი}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{მიმდინარეობს თქვენ მიერ არჩეული ფაილის კოპირება თქვენს კერძო სივრცეში}other{მიმდინარეობს თქვენ მიერ არჩეული ფაილების კოპირება თქვენს კერძო სივრცეში}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{მიმდინარეობს თქვენ მიერ არჩეული ფაილის გადატანა თქვენს კერძო სივრცეში}other{მიმდინარეობს თქვენ მიერ არჩეული ფაილების გადატანა თქვენს კერძო სივრცეში}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{თქვენ მიერ არჩეული ფაილი დაკოპირდა თქვენს კერძო სივრცეში}other{თქვენ მიერ არჩეული ფაილები დაკოპირდა თქვენს კერძო სივრცეში}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{თქვენ მიერ არჩეული ფაილი გადატანილია თქვენს კერძო სივრცეში}other{თქვენ მიერ არჩეული ფაილი გადატანილია თქვენს კერძო სივრცეში}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ფაილების ჩვენება"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ფაილის გადატანის შეტყობინებები"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"თქვენს კერძო სივრცეში ფაილების კოპირების ან გადაადგილებისას შეგიძლიათ, პროგრესის შესახებ განახლებების თაობაზე შეტყობინებები მიიღოთ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"ზოგიერთი ფაილის კოპირება ვერ ხერხდება"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ზოგიერთი ფაილის გადატანა ვერ ხერხდება"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"შეგიძლიათ, ხელახლა ცადოთ თქვენი ფაილების კოპირება"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"შეგიძლიათ, ხელახლა ცადოთ თქვენი ფაილების გადატანა"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ფაილების კოპირება ჯერ არ დასრულებულა"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ფაილების გადატანა ჯერ არ დასრულებულა"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ფაილების კოპირება და გადატანა შეგეძლებათ ამის დასრულებისთანავე"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ფაილების კოპირება ვერ მოხერხდა"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ფაილების გადატანა ვერ მოხერხდა"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ფაილის სრული ზომა ძალიან დიდია"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ერთდროულად შეგიძლიათ არაუმეტეს 2 გბაიტის კოპირება ან გადატანა"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"არჩეულია ძალიან ბევრი ფაილი"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ერთდროულად შეგიძლიათ არაუმეტეს 100 ფაილის კოპირება ან გადატანა"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ფაილების დამატება ვერ ხერხდება"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"თქვენი მოწყობილობის მეხსიერება არასაკმარისია"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"კარგი"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"მეხსიერების გათავისუფლება"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"კერძო სივრციდან ფაილების კოპირება ან გადატანა შეუძლებელია"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"ზოგიერთი ფაილის კოპირება ვერ მოხერხდა"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ზოგიერთი ფაილის გადატანა ვერ მოხერხდა"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"თქვენი კერძო სივრცე დაიხურა კოპირების დროს"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"თქვენი კერძო სივრცე დაიხურა გადატანის დროს"</string>
 </resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index ec21812..527b8cb 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -19,20 +19,42 @@
     <string name="private_space_app_label" msgid="4816454052314284927">"Құпия кеңістік"</string>
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Файлдарды қосу"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Қолданбаларды орнату"</string>
-    <string name="move_files_dialog_title" msgid="4288920082565374705">"Файлдарды жылжыту керек пе немесе көшіру керек пе?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Бұл файлдарды құпия кеңістікке жылжытсаңыз, олар бастапқы қалталарынан жойылады."</string>
-    <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Жылжыту"</string>
+    <string name="move_files_dialog_title" msgid="4288920082565374705">"Файлдарды тасымалдау керек пе немесе көшіру керек пе?"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Бұл файлдарды құпия кеңістікке тасымалдасаңыз, олар бастапқы қалталарынан жойылады."</string>
+    <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Тасымалдау"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Көшіру"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Бас тарту"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> файл көшіріліп жатыр"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> файл жіберіліп жатыр"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> файл көшірілді"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> файл жіберілді"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Таңдаған файлдарыңыз құпия кеңістігіңізге көшіріліп жатыр."</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Таңдаған файлдарыңыз құпия кеңістігіңізге жіберіліп жатыр."</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Таңдаған файлдарыңыз құпия кеңістігіңізге көшірілді."</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Таңдаған файлдарыңыз құпия кеңістігіңізге жіберілді."</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# файл көшіріліп жатыр}other{# файл көшіріліп жатыр}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# файл тасымалданып жатыр}other{# файл тасымалданып жатыр}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# файл көшірілді}other{# файл көшірілді}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# файл тасымалданды}other{# файл тасымалданды}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Таңдалған файл құпия кеңістігіңізге көшіріліп жатыр.}other{Таңдалған файлдар құпия кеңістігіңізге көшіріліп жатыр.}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Таңдалған файл құпия кеңістігіңізге тасымалданып жатыр.}other{Таңдалған файлдар құпия кеңістігіңізге тасымалданып жатыр.}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Таңдалған файл құпия кеңістігіңізге көшірілді.}other{Таңдалған файлдар құпия кеңістігіңізге көшірілді.}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Таңдалған файл құпия кеңістігіңізге тасымалданды.}other{Таңдалған файлдар құпия кеңістігіңізге тасымалданды.}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Файлдарды көрсету"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Файлды тасымалдау туралы хабарландырулар"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Файлдарды құпия кеңістікке көшірген немесе жылжытқан кезде, орындалу барысын жаңарту туралы хабарландырулар шығуы мүмкін."</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Кейбір файлдар көшірілмейді"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Кейбір файлдар тасымалданбайды"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Файлдарды қайта көшіріп көрсеңіз болады."</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Файлдарды қайта тасымалдап көрсеңіз болады."</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Файлдар әлі көшіріліп жатыр"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Файлдар әлі тасымалданып жатыр"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Аяқталған кезде, тағы файл көшіруге не тасымалдауға болады."</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Файлдар көшірілмеді"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Файлдар тасымалданбады"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Файлдардың жалпы өлшемі тым үлкен"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Бір уақытта тек 2 ГБ-қа дейін көшіруге не тасымалдауға болады."</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Тым көп файл таңдалды"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Бір уақытта тек 100 файлға дейін көшіруге не тасымалдауға болады."</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Файлдар қосылмайды"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Құрылғы жады жеткіліксіз"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Жарайды"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Жадты босатыңыз"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Файлдарды құпия кеңістіктен көшіру немесе тасымалдау мүмкін емес."</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Кейбір файлдар көшірілмеді"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Кейбір файлдар тасымалданбады"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Көшіру кезінде құпия кеңістік жабылды."</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Тасымалдау кезінде құпия кеңістік жабылды."</string>
 </resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 4616cec..0d7f405 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"បញ្ចូល​ឯកសារ"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"ដំឡើង​កម្មវិធី"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"ផ្លាស់ទី ឬចម្លងឯកសារឬ?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"ប្រសិនបើអ្នកផ្លាស់ទីឯកសារទាំងនេះទៅកាន់លំហឯកជនរបស់អ្នក ឯកសារទាំងនេះនឹងត្រូវបានដកចេញពីថតដើមរបស់ឯកសារទាំងនោះ"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"ប្រសិនបើអ្នកផ្លាស់ទីឯកសារទាំងនេះទៅកាន់លំហឯកជនរបស់អ្នក ឯកសារទាំងនេះនឹងត្រូវបានដកចេញពីថតដើមរបស់ឯកសារទាំងនេះ"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ផ្លាស់ទី"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"ចម្លង"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"បោះបង់"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"កំពុងចម្លងឯកសារ <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"កំពុងផ្លាស់ទីឯកសារ <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"បានចម្លងឯកសារ <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"បាន​ផ្លាស់ទី​ឯកសារ <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ឯកសារដែលអ្នកបានជ្រើសរើសកំពុងត្រូវបានចម្លងទៅលំហឯកជនរបស់អ្នក"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ឯកសារដែលអ្នកបានជ្រើសរើសកំពុងត្រូវបានផ្លាស់ទីទៅលំហឯកជនរបស់អ្នក"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ឯកសារដែលអ្នកបានជ្រើសរើសត្រូវបានចម្លងទៅលំហឯកជនរបស់អ្នក"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ឯកសារដែលអ្នកបានជ្រើសរើសត្រូវបានផ្លាស់ទីទៅលំហឯកជនរបស់អ្នក"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{កំពុងចម្លងឯកសារ #}other{កំពុងចម្លងឯកសារ #}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{កំពុងផ្លាស់ទីឯកសារ #}other{កំពុងផ្លាស់ទីឯកសារ #}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{បាន​ចម្លង​ឯកសារ #}other{បាន​ចម្លង​ឯកសារ #}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{បាន​ផ្លាស់ទី​ឯកសារ #}other{បាន​ផ្លាស់ទី​ឯកសារ #}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ឯកសារដែលអ្នកបានជ្រើសរើសកំពុងត្រូវបានចម្លងទៅលំហឯកជនរបស់អ្នក}other{ឯកសារដែលអ្នកបានជ្រើសរើសកំពុងត្រូវបានចម្លងទៅលំហឯកជនរបស់អ្នក}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ឯកសារដែលអ្នកបានជ្រើសរើសកំពុងត្រូវបានផ្លាស់ទីទៅលំហឯកជនរបស់អ្នក}other{ឯកសារដែលអ្នកបានជ្រើសរើសកំពុងត្រូវបានផ្លាស់ទីទៅលំហឯកជនរបស់អ្នក}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ឯកសារដែលអ្នកបានជ្រើសរើសត្រូវបានចម្លងទៅលំហឯកជនរបស់អ្នក}other{ឯកសារដែលអ្នកបានជ្រើសរើសត្រូវបានចម្លងទៅលំហឯកជនរបស់អ្នក}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ឯកសារដែលអ្នកបានជ្រើសរើសត្រូវបានផ្លាស់ទីទៅលំហឯកជនរបស់អ្នក}other{ឯកសារដែលអ្នកបានជ្រើសរើសត្រូវបានផ្លាស់ទីទៅលំហឯកជនរបស់អ្នក}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"បង្ហាញឯកសារ"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ការ​ជូនដំណឹងអំពីការផ្ទេរឯកសារ"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"នៅពេលអ្នកចម្លង ឬផ្លាស់ទីឯកសារទៅលំហឯកជនរបស់អ្នក អ្នកអាចទទួលបានការ​ជូនដំណឹង ដើម្បីផ្ដល់ព័ត៌មាន​ថ្មីៗ​ដល់​អ្នក​អំពីដំណើរការ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"មិនអាចចម្លងឯកសារមួយចំនួនបានទេ"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"មិនអាចផ្លាស់ទីឯកសារមួយចំនួនបានទេ"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"អ្នកអាចព្យាយាមចម្លងឯកសាររបស់អ្នកម្ដងទៀត"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"អ្នកអាចព្យាយាមផ្លាស់ទីឯកសាររបស់អ្នកម្ដងទៀត"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"កំពុងចម្លងឯកសារនៅឡើយ"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"កំពុងផ្លាស់ទីឯកសារនៅឡើយ"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"អ្នកអាចចម្លង ឬផ្លាស់ទីឯកសារច្រើនទៀត ពេលដំណើរការនេះចប់"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"មិនអាចចម្លងឯកសារបានទេ"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"មិនអាចផ្លាស់ទីឯកសារបានទេ"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ទំហំឯកសារសរុបធំពេក"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"អ្នកអាចចម្លង ឬផ្លាស់ទីបានដល់ 2 GB ក្នុងមួយលើកតែប៉ុណ្ណោះ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"បាន​ជ្រើសរើស​ឯកសារ​ច្រើន​ពេក"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"អ្នកអាចចម្លង ឬផ្លាស់ទីបានដល់ 100 ឯកសារក្នុងមួយលើកតែប៉ុណ្ណោះ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"មិនអាចបញ្ចូលឯកសារបានទេ"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"អ្នកមិនមានទំហំ​ផ្ទុកឧបករណ៍គ្រប់គ្រាន់ទេ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"យល់ព្រម"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"សម្អាតឱ្យសល់​ទំហំផ្ទុក​ទំនេរ"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"មិនអាចចម្លង ឬផ្លាស់ទីឯកសារពីលំហឯកជនបានទេ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"មិនអាចចម្លងឯកសារមួយចំនួនបានទេ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"មិនអាចផ្លាស់ទីឯកសារមួយចំនួនបានទេ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"លំហឯកជនរបស់អ្នកត្រូវបានបិទ ពេលកំពុងចម្លង"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"លំហឯកជនរបស់អ្នកត្រូវបានបិទ ពេលកំពុងផ្លាស់ទី"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 86027cb..530b1b0 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -19,20 +19,42 @@
     <string name="private_space_app_label" msgid="4816454052314284927">"ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್"</string>
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"ಫೈಲ್‌ಗಳನ್ನು ಸೇರಿಸಿ"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ"</string>
-    <string name="move_files_dialog_title" msgid="4288920082565374705">"ಫೈಲ್‌ಗಳನ್ನು ಸರಿಸಬೇಕೆ ಅಥವಾ ಕಾಪಿ ಮಾಡಬೇಕೆ?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"ನೀವು ಈ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಸರಿಸಿದರೆ, ಅವುಗಳನ್ನು ಅವುಗಳ ಮೂಲ ಫೋಲ್ಡರ್‌ಗಳಿಂದ ತೆಗೆದುಹಾಕಲಾಗುತ್ತದೆ"</string>
-    <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ಸರಿಸಿ"</string>
+    <string name="move_files_dialog_title" msgid="4288920082565374705">"ಫೈಲ್‌ಗಳನ್ನು ಮೂವ್ ಮಾಡಬೇಕೆ ಅಥವಾ ಕಾಪಿ ಮಾಡಬೇಕೆ?"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"ನೀವು ಈ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಮೂವ್ ಮಾಡಿದರೆ, ಅವುಗಳನ್ನು ಅವುಗಳ ಮೂಲ ಫೋಲ್ಡರ್‌ಗಳಿಂದ ತೆಗೆದುಹಾಕಲಾಗುತ್ತದೆ"</string>
+    <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ಮೂವ್"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"ಕಾಪಿ ಮಾಡಿ"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ರದ್ದುಮಾಡಿ"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ಫೈಲ್(ಗಳನ್ನು) ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ಫೈಲ್(ಗಳನ್ನು) ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ಫೈಲ್(ಗಳನ್ನು) ಕಾಪಿ ಮಾಡಲಾಗಿದೆ"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ಫೈಲ್(ಗಳನ್ನು) ಮೂವ್ ಮಾಡಲಾಗಿದೆ"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ನಿಮ್ಮ ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ನಿಮ್ಮ ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ನಿಮ್ಮ ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗಿದೆ"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ನಿಮ್ಮ ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಮೂವ್ ಮಾಡಲಾಗಿದೆ"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ಫೈಲ್ ಅನ್ನು ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ}one{# ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ}other{# ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ಫೈಲ್ ಅನ್ನು ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ}one{# ಫೈಲ್‌ಗಳನ್ನು ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ}other{# ಫೈಲ್‌ಗಳನ್ನು ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ಫೈಲ್ ಅನ್ನು ಕಾಪಿ ಮಾಡಲಾಗಿದೆ}one{# ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲಾಗಿದೆ}other{# ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲಾಗಿದೆ}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ಫೈಲ್ ಅನ್ನು ಸರಿಸಲಾಗಿದೆ}one{# ಫೈಲ್‌ಗಳನ್ನು ಸರಿಸಲಾಗಿದೆ}other{# ಫೈಲ್‌ಗಳನ್ನು ಸರಿಸಲಾಗಿದೆ}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್ ಅನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ}one{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ}other{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್ ಅನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ}one{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ}other{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಮೂವ್ ಮಾಡಲಾಗುತ್ತಿದೆ}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್ ಅನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗಿದೆ}one{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗಿದೆ}other{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಲಾಗಿದೆ}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್ ಅನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಸರಿಸಲಾಗಿದೆ}one{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಸರಿಸಲಾಗಿದೆ}other{ನೀವು ಆಯ್ಕೆಮಾಡಿದ ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಸರಿಸಲಾಗಿದೆ}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ಫೈಲ್‌ಗಳನ್ನು ತೋರಿಸಿ"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ಫೈಲ್ ವರ್ಗಾವಣೆ ನೋಟಿಫಿಕೇಶನ್‌ಗಳು"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ನೀವು ಫೈಲ್‌ಗಳನ್ನು ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಿದಾಗ ಅಥವಾ ಸರಿಸಿದಾಗ, ಪ್ರಗತಿಯ ಕುರಿತು ನಿಮಗೆ ತಿಳಿಸಲು ನೀವು ನೋಟಿಫಿಕೇಶನ್‌ಗಳನ್ನು ಸ್ವೀಕರಿಸಬಹುದು"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"ಕೆಲವು ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ಕೆಲವು ಫೈಲ್‌ಗಳನ್ನು ಸರಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ನಿಮ್ಮ ಫೈಲ್‌ಗಳನ್ನು ಮತ್ತೊಮ್ಮೆ ಕಾಪಿ ಮಾಡಲು ನೀವು ಪ್ರಯತ್ನಿಸಬಹುದು"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ನಿಮ್ಮ ಫೈಲ್‌ಗಳನ್ನು ಮತ್ತೆ ಸರಿಸಲು ನೀವು ಪ್ರಯತ್ನಿಸಬಹುದು"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ಇನ್ನೂ ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ಇನ್ನೂ ಫೈಲ್‌ಗಳು ಮೂವ್ ಆಗುತ್ತಿವೆ"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ಇದು ಮುಗಿದ ನಂತರ ನೀವು ಇನ್ನಷ್ಟು ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಬಹುದು ಅಥವಾ ಮೂವ್ ಮಾಡಬಹುದು"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡುಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ಫೈಲ್‌ಗಳನ್ನು ಸರಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ಒಟ್ಟು ಫೈಲ್ ಗಾತ್ರವು ತುಂಬಾ ದೊಡ್ಡದಾಗಿದೆ."</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ನೀವು ಒಂದು ಬಾರಿಗೆ 2 GB ವರೆಗೆ ಮಾತ್ರ ಕಾಪಿ ಮಾಡಬಹುದು ಅಥವಾ ಮೂವ್ ಮಾಡಬಹುದು"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ಹಲವಾರು ಫೈಲ್‌ಗಳನ್ನು ಆಯ್ಕೆ ಮಾಡಲಾಗಿದೆ"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ನೀವು ಒಂದು ಬಾರಿಗೆ 100 ಫೈಲ್‌ಗಳನ್ನು ಮಾತ್ರ ಕಾಪಿ ಮಾಡಬಹುದು ಅಥವಾ ಮೂವ್ ಮಾಡಬಹುದು"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ಫೈಲ್‌ಗಳನ್ನು ಸೇರಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"ನೀವು ಸಾಕಾಗುವಷ್ಟು ಸಾಧನದ ಸ್ಟೋರೇಜ್ ಅನ್ನು ಹೊಂದಿಲ್ಲ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ಸರಿ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ಸ್ಥಳಾವಕಾಶವನ್ನು ತೆರವುಗೊಳಿಸಿ"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್‌ನಿಂದ ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲು ಅಥವಾ ಸರಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"ಕೆಲವು ಫೈಲ್‌ಗಳನ್ನು ಕಾಪಿ ಮಾಡಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ಕೆಲವು ಫೈಲ್‌ಗಳನ್ನು ಮೂವ್ ಮಾಡಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"ಕಾಪಿ ಮಾಡುವಾಗ ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್ ಅನ್ನು ಮುಚ್ಚಲಾಗಿತ್ತು"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ಮೂವ್ ಆಗುವಾಗ ನಿಮ್ಮ ಪ್ರೈವೆಟ್ ಸ್ಪೇಸ್ ಅನ್ನು ಮುಚ್ಚಲಾಗಿತ್ತು"</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 9111016..d37d649 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"이동"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"복사"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"취소"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"파일 <xliff:g id="FILES">%1$d</xliff:g>개 복사 중"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"파일 <xliff:g id="FILES">%1$d</xliff:g>개 이동 중"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"파일 <xliff:g id="FILES">%1$d</xliff:g>개 복사됨"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"파일 <xliff:g id="FILES">%1$d</xliff:g>개 이동됨"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"선택한 파일을 비공개 스페이스로 복사하는 중입니다."</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"선택한 파일을 비공개 스페이스로 이동 중입니다."</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"선택한 파일이 비공개 스페이스로 복사되었습니다."</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"선택한 파일이 비공개 스페이스로 이동되었습니다."</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{파일 #개 복사 중…}other{파일 #개 복사 중}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{파일 #개 이동 중}other{파일 #개 이동 중}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{파일 #개 복사됨}other{파일 #개 복사됨}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{파일 #개 이동됨}other{파일 #개 이동됨}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{선택한 파일을 비공개 스페이스로 복사하는 중입니다.}other{선택한 파일을 비공개 스페이스로 복사하는 중입니다.}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{선택한 파일을 비공개 스페이스로 이동 중입니다.}other{선택한 파일을 비공개 스페이스로 이동 중입니다.}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{선택한 파일이 비공개 스페이스로 복사되었습니다.}other{선택한 파일이 비공개 스페이스로 복사되었습니다.}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{선택한 파일이 비공개 스페이스로 이동되었습니다.}other{선택한 파일이 비공개 스페이스로 이동되었습니다.}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"파일 표시"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"파일 전송 알림"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"파일을 비공개 스페이스로 복사하거나 이동할 때 알림을 받아 진행 상황을 확인할 수 있습니다."</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"일부 파일을 복사할 수 없습니다"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"일부 파일을 이동할 수 없습니다"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"파일을 다시 복사해 보세요."</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"파일을 다시 이동해 보세요."</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"아직 파일 복사 중"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"아직 파일 이동 중"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"이 작업이 완료되면 더 많은 파일을 복사하거나 이동할 수 있습니다."</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"파일을 복사할 수 없습니다"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"파일을 이동할 수 없습니다"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"총 파일 크기가 너무 큽니다"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"한 번에 최대 2GB까지만 복사하거나 이동할 수 있습니다."</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"선택된 파일이 너무 많습니다"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"한 번에 최대 100개의 파일만 복사하거나 이동할 수 있습니다."</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"파일을 추가할 수 없습니다"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"기기 저장용량이 충분하지 않습니다."</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"확인"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"여유 공간 확보"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"비공개 스페이스에서 파일을 복사하거나 이동할 수 없음"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"일부 파일을 복사할 수 없음"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"일부 파일을 이동할 수 없음"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"복사하는 동안 비공개 스페이스가 닫혔습니다"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"이동하는 동안 비공개 스페이스가 닫혔습니다"</string>
 </resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index c515df6..58cda59 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Жылдыруу"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Көчүрүү"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Жокко чыгаруу"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> файл көчүрүлүүдө"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> файл жылдырылууда"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> файл көчүрүлдү"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> файл жылдырылды"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Тандалган файлдар жеке мейкиндигиңизге көчүрүлүүдө"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Тандалган файлдар жеке мейкиндигиңизге жылдырылууда"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Тандалган файлдар жеке мейкиндигиңизге көчүрүлдү"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Тандалган файлдар жеке мейкиндигиңизге жылдырылды"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# файл көчүрүлүүдө}other{# файл көчүрүлүүдө}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# файл жылдырылууда}other{# файл жылдырылууда}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# файл көчүрүлдү}other{# файл көчүрүлдү}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# файл жылдырылды}other{# файл жылдырылды}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Тандалган файл жеке мейкиндигиңизге көчүрүлүүдө}other{Тандалган файлдар жеке мейкиндигиңизге көчүрүлүүдө}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Тандалган файл жеке мейкиндигиңизге жылдырылууда}other{Тандалган файл жеке мейкиндигиңизге жылдырылууда}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Тандалган файл жеке мейкиндигиңизге көчүрүлдү}other{Тандалган файлдар жеке мейкиндигиңизге көчүрүлдү}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Тандалган файл жеке мейкиндигиңизге жылдырылды}other{Тандалган файлдар жеке мейкиндигиңизге жылдырылды}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Файлдарды көрсөтүү"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Файлдын өткөрүлүшү жөнүндө билдирмелер"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Файлдарды жеке мейкиндикке көчүргөндө алардын көчүрүлүшү жөнүндө билдирмелерди алсаңыз болот"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Айрым файлдарды көчүрүү мүмкүн эмес"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Айрым файлдарды жылдыруу мүмкүн эмес"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Файлдарыңызды кайрадан көчүрүп көрсөңүз болот"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Файлдарыңызды кайрадан жылдырып көрсөңүз болот"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Файлдар дагы эле көчүрүлүүдө"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Файлдар дагы эле жылдырылууда"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Башка файлдарды бул процесс бүткөндөн кийин көчүрүп же жылдыра аласыз"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Файлдар көчүрүлбөй койду"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Файлдар жылдырылган жок"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Файлдардын жалпы өлчөмү өтө чоң"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Бир убакта 2 Гб чейин гана көчүрүп же жылдыра аласыз"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Өтө көп файл тандалды"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Бир убакта 100 файлга чейин гана көчүрүп же жылдыра аласыз"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Файлдарды кошуу мүмкүн эмес"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Түзмөгүңүздүн сактагычында орун жетишсиз"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Жарайт"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Орун бошотуу"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Жеке мейкиндиктен файлдарды көчүрүү же жылдырууга болбойт"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Кээ бир файлдар көчүрүлгөн жок"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Кээ бир файлдар жылдырылган жок"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Көчүрүп жатканда жеке мейкиндигиңиз жабылды"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Жылдырып жатканда жеке мейкиндигиңиз жабылды"</string>
 </resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 7eed439..cea2a41 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ຍ້າຍ"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"ສຳເນົາ"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ຍົກເລີກ"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"ກຳລົງສຳເນົາ <xliff:g id="FILES">%1$d</xliff:g> ໄຟລ໌"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"ກຳລັງຍ້າຍ <xliff:g id="FILES">%1$d</xliff:g> ໄຟລ໌"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"ສຳເນົາ <xliff:g id="FILES">%1$d</xliff:g> ໄຟລ໌ແລ້ວ"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"ຍ້າຍ <xliff:g id="FILES">%1$d</xliff:g> ໄຟລ໌ແລ້ວ"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ໄຟລ໌ທີ່ທ່ານເລືອກກຳລັງຖືກສຳເນົາໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ໄຟລ໌ທີ່ທ່ານເລືອກກຳລັງຖືກຍ້າຍໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ໄຟລ໌ທີ່ທ່ານເລືອກໄດ້ຖືກສຳເນົາໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານແລ້ວ"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ໄດ້ຍ້າຍໄຟລ໌ທີ່ທ່ານເລືອກໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານແລ້ວ"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{ກຳລັງສຳເນົາ # ໄຟລ໌}other{ກຳລັງສຳເນົາ # ໄຟລ໌}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{ກຳລັງຍ້າຍ # ໄຟລ໌}other{ກຳລັງຍ້າຍ # ໄຟລ໌}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{ສຳເນົາ # ໄຟລ໌ແລ້ວ}other{ສຳເນົາ # ໄຟລ໌ແລ້ວ}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{ຍ້າຍແລ້ວ # ໄຟລ໌}other{ຍ້າຍແລ້ວ # ໄຟລ໌}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ກຳລັງສຳເນົາໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ}other{ກຳລັງສຳເນົາໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ກຳລັງຍ້າຍໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ}other{ກຳລັງຍ້າຍໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ສຳເນົາໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານແລ້ວ}other{ສຳເນົາໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານແລ້ວ}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ຍ້າຍໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານແລ້ວ}other{ຍ້າຍໄຟລ໌ທີ່ທ່ານເລືອກໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານແລ້ວ}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ສະແດງໄຟລ໌"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ການແຈ້ງເຕືອນການໂອນໄຟລ໌"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ເມື່ອທ່ານສຳເນົາ ຫຼື ຍ້າຍໄຟລ໌ໄປໃສ່ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານ, ທ່ານສາມາດໄດ້ຮັບການແຈ້ງເຕືອນເພື່ອອັບເດດໃຫ້ທ່ານຮູ້ເຖິງຄວາມຄືບໜ້າ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"ບໍ່ສາມາດສຳເນົາບາງໄຟລ໌ໄດ້"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ບໍ່ສາມາດຍ້າຍບາງໄຟລ໌ໄດ້"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ທ່ານສາມາດລອງສຳເນົາໄຟລ໌ຂອງທ່ານອີກຄັ້ງໄດ້"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ທ່ານສາມາດລອງຍ້າຍໄຟລ໌ຂອງທ່ານອີກຄັ້ງໄດ້"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ກຳລັງສຳເນົາໄຟລ໌ຢູ່"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ກຳລັງຍ້າຍໄຟລ໌ຢູ່"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ທ່ານສາມາດສຳເນົາ ຫຼື ຍ້າຍໄຟລ໌ເພີ່ມເຕີມໄດ້ເມື່ອດຳເນີນການນີ້ສຳເລັດ"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ບໍ່ສາມາດສຳເນົາໄດ້"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ບໍ່ສາມາດຍ້າຍໄຟລ໌ໄດ້"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ຂະໜາດໄຟລ໌ທັງໝົດໃຫຍ່ເກີນໄປ"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ທ່ານສາມາດສຳເນົາ ຫຼື ຍ້າຍໄດ້ສູງເຖິງ 2 GB ຕໍ່ຄັ້ງເທົ່ານັ້ນ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ເລືອກຫຼາຍໄຟລ໌ເກີນໄປ"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ທ່ານສາມາດສຳເນົາ ຫຼື ຍ້າຍໄດ້ສູງສຸດ 100 ໄຟລ໌ຕໍ່ຄັ້ງເທົ່ານັ້ນ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ບໍ່ສາມາດເພີ່ມໄຟລ໌ໄດ້"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"ທ່ານບໍ່ມີບ່ອນຈັດເກັບຂໍ້ມູນອຸປະກອນພຽງພໍ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ຕົກລົງ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ເພີ່ມພື້ນທີ່ຫວ່າງ"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ບໍ່ສາມາດສຳເນົາ ຫຼື ຍ້າຍໄຟລ໌ຈາກພື້ນທີ່ສ່ວນບຸກຄົນໄດ້"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"ບໍ່ສາມາດສຳເນົາບາງໄຟລ໌ໄດ້"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ບໍ່ສາມາດຍ້າຍບາງໄຟລ໌ໄດ້"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານຖືກປິດໄວ້ໃນລະຫວ່າງທີ່ສຳເນົາ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ພື້ນທີ່ສ່ວນບຸກຄົນຂອງທ່ານຖືກປິດໄວ້ໃນລະຫວ່າງທີ່ຍ້າຍ"</string>
 </resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 8c26fe4..d165bb0 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Perkelti"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopijuoti"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Atšaukti"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopijuojami failai: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Perkeliami failai: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Nukopijuota failų: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Perkelta failų: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Pasirinkti failai kopijuojami į privačią erdvę"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Pasirinkti failai perkeliami į privačią erdvę"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Pasirinkti failai nukopijuoti į privačią erdvę"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Pasirinkti failai perkelti į privačią erdvę"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopijuojamas # failas}one{Kopijuojamas # failas}few{Kopijuojami # failai}many{Kopijuojama # failo}other{Kopijuojama # failų}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Perkeliamas # failas}one{Perkeliamas # failas}few{Perkeliami # failai}many{Perkeliama # failo}other{Perkeliama # failų}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Nukopijuotas # failas}one{Nukopijuotas # failas}few{Nukopijuoti # failai}many{Nukopijuota # failo}other{Nukopijuota # failų}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Perkeltas # failas}one{Perkeltas # failas}few{Perkelti # failai}many{Perkelta # failo}other{Perkelta # failų}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Pasirinktas failas kopijuojamas į privačią erdvę}one{Pasirinkti failai kopijuojami į privačią erdvę}few{Pasirinkti failai kopijuojami į privačią erdvę}many{Pasirinkti failai kopijuojami į privačią erdvę}other{Pasirinkti failai kopijuojami į privačią erdvę}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Pasirinktas failas perkeliamas į privačią erdvę}one{Pasirinkti failai perkeliami į privačią erdvę}few{Pasirinkti failai perkeliami į privačią erdvę}many{Pasirinkti failai perkeliami į privačią erdvę}other{Pasirinkti failai perkeliami į privačią erdvę}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Pasirinktas failas nukopijuotas į privačią erdvę}one{Pasirinkti failai nukopijuoti į privačią erdvę}few{Pasirinkti failai nukopijuoti į privačią erdvę}many{Pasirinkti failai nukopijuoti į privačią erdvę}other{Pasirinkti failai nukopijuoti į privačią erdvę}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Pasirinktas failas perkeltas į privačią erdvę}one{Pasirinkti failai perkelti į privačią erdvę}few{Pasirinkti failai perkelti į privačią erdvę}many{Pasirinkti failai perkelti į privačią erdvę}other{Pasirinkti failai perkelti į privačią erdvę}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Rodyti failus"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Failų perkėlimo pranešimai"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kai kopijuojate arba perkeliate failus į privačią erdvę, galite gauti pranešimus, kuriais informuojama apie eigą"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nepavyko nukopijuoti kai kurių failų"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nepavyko perkelti kai kurių failų"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Galite pabandyti dar kartą nukopijuoti failus"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Galite pabandyti dar kartą perkelti failus"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Vis dar kopijuojami failai"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Vis dar perkeliami failai"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Kai tai bus atlikta, galėsite kopijuoti arba perkelti daugiau failų"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Nepavyko nukopijuoti failų"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Nepavyko perkelti failų"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Bendras failo dydis per didelis"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Vienu metu galite kopijuoti arba perkelti ne daugiau kaip 2 GB"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Pasirinkta per daug failų"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Vienu metu galite kopijuoti arba perkelti tik iki 100 failų"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nepavyko pridėti failų"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Įrenginio saugykloje neturite pakankamai vietos"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Gerai"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Atlaisvinkite vietos"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Nepavyko nukopijuoti arba perkelti failų iš privačios erdvės"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Nepavyko nukopijuoti kai kurių failų"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Nepavyko perkelti kai kurių failų"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Jūsų privati erdvė buvo uždaryta kopijuojant"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Jūsų privati erdvė buvo uždaryta perkeliant"</string>
 </resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index d5dbef8..998dbd4 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Pārvietot"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopēt"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Atcelt"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Notiek <xliff:g id="FILES">%1$d</xliff:g> faila(-u) kopēšana…"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Notiek <xliff:g id="FILES">%1$d</xliff:g> faila(-u) pārvietošana…"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Pārkopēts(-i) <xliff:g id="FILES">%1$d</xliff:g> fails(-i)"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Pārvietots(-i) <xliff:g id="FILES">%1$d</xliff:g> fails(-i)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Jūsu izvēlētie faili tiek kopēti uz jūsu privāto telpu."</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Jūsu izvēlētie faili tiek pārvietoti uz jūsu privāto telpu."</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Jūsu izvēlētie faili tika pārkopēti uz jūsu privāto telpu."</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Jūsu izvēlētie faili tika pārvietoti uz jūsu privāto telpu."</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Notiek # faila kopēšana}zero{Notiek # failu kopēšana}one{Notiek # faila kopēšana}other{Notiek # failu kopēšana}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Notiek # faila pārvietošana}zero{Notiek # failu pārvietošana}one{Notiek # faila pārvietošana}other{Notiek # failu pārvietošana}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fails ir pārkopēts}zero{# faili ir pārkopēti}one{# fails ir pārkopēts}other{# faili ir pārkopēti}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fails ir pārvietots}zero{# faili ir pārvietoti}one{# fails ir pārvietots}other{# faili ir pārvietoti}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Jūsu izvēlētais fails tiek kopēts uz jūsu privāto telpu.}zero{Jūsu izvēlētie faili tiek kopēti uz jūsu privāto telpu.}one{Jūsu izvēlētie faili tiek kopēti uz jūsu privāto telpu.}other{Jūsu izvēlētie faili tiek kopēti uz jūsu privāto telpu.}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Jūsu izvēlētais fails tiek pārvietots uz jūsu privāto telpu}zero{Jūsu izvēlētie faili tiek pārvietoti uz jūsu privāto telpu}one{Jūsu izvēlētie faili tiek pārvietoti uz jūsu privāto telpu}other{Jūsu izvēlētie faili tiek pārvietoti uz jūsu privāto telpu}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Jūsu izvēlētais fails tika pārkopēts uz jūsu privāto telpu.}zero{Jūsu izvēlētie faili tika pārkopēti uz jūsu privāto telpu.}one{Jūsu izvēlētie faili tika pārkopēti uz jūsu privāto telpu.}other{Jūsu izvēlētie faili tika pārkopēti uz jūsu privāto telpu.}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Jūsu izvēlētais fails tika pārvietots uz jūsu privāto telpu.}zero{Jūsu izvēlētie faili tika pārvietoti uz jūsu privāto telpu.}one{Jūsu izvēlētie faili tika pārvietoti uz jūsu privāto telpu.}other{Jūsu izvēlētie faili tika pārvietoti uz jūsu privāto telpu.}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Rādīt failus"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Paziņojumi par failu pārsūtīšanu"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kad kopējat vai pārvietojat failus uz savu privāto telpu, varat saņemt paziņojumus par failu kopēšanas vai pārvietošanas norisi."</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nevar kopēt dažus failus"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nevar pārvietot dažus failus"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Varat mēģināt vēlreiz kopēt failus."</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Varat mēģināt vēlreiz pārvietot failus."</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Joprojām notiek failu kopēšana…"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Joprojām notiek failu pārvietošana…"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Kad pārsūtīšana būs pabeigta, varēsiet kopēt vai pārvietot citus failus."</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Nevarēja nokopēt failus"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Nevarēja pārvietot failus"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Kopējais failu lielums ir pārāk liels"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Vienlaikus var kopēt vai pārvietot ne vairāk kā 2 GB lielu failu kopu."</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Atlasīts pārāk daudz failu"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Vienlaikus var kopēt vai pārvietot ne vairāk kā 100 failus."</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nevar pievienot failus"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Ierīces krātuvē nav pietiekami daudz vietas."</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Labi"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Atbrīvot vietu"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Nevar kopēt vai pārvietot failus no privātās telpas"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Nevarēja nokopēt dažus failus"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Nevarēja pārvietot dažus failus"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Jūsu privātā telpa tika aizvērta kopēšanas laikā."</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Jūsu privātā telpa tika aizvērta pārvietošanas laikā."</string>
 </resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 5f5d279..4b55926 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Премести"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Копирај"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Откажи"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Се копираат <xliff:g id="FILES">%1$d</xliff:g> датотеки"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Се преместуваат <xliff:g id="FILES">%1$d</xliff:g> датотеки"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Копирани се <xliff:g id="FILES">%1$d</xliff:g> датотеки"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Преместени се <xliff:g id="FILES">%1$d</xliff:g> датотеки"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Избраните датотеки се копираат во вашиот „Приватен простор“"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Избраните датотеки се преместуваат во вашиот „Приватен простор“"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Избраните датотеки се копирани во вашиот „Приватен простор“"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Избраните датотеки се преместени во вашиот „Приватен простор“"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Се копира # датотека}one{Се копираат # датотека}other{Се копираат # датотеки}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Се преместува # датотека}one{Се преместуваат # датотека}other{Се преместуваат # датотеки}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Копирана е # датотека}one{Копирани се # датотека}other{Копирани се # датотеки}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Преместена е # датотека}one{Преместени се # датотека}other{Преместени се # датотеки}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Избраната датотека се копира во вашиот „Приватен простор“}one{Избраните датотеки се копираат во вашиот „Приватен простор“}other{Избраните датотеки се копираат во вашиот „Приватен простор“}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Избраната датотека се преместува во вашиот „Приватен простор“}one{Избраните датотеки се преместуваат во вашиот „Приватен простор“}other{Избраните датотеки се преместуваат во вашиот „Приватен простор“}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Избраната датотека е копирана во вашиот „Приватен простор“}one{Избраните датотеки се копирани во вашиот „Приватен простор“}other{Избраните датотеки се копирани во вашиот „Приватен простор“}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Избраната датотека е преместена во вашиот „Приватен простор“}one{Избраните датотеки се преместени во вашиот „Приватен простор“}other{Избраните датотеки се преместени во вашиот „Приватен простор“}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Прикажи датотеки"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Известувања за префрлање датотеки"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Кога копирате или префрлате датотеки во вашиот „Приватен простор“, може да добивате известувања за напредокот"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Не може да се копираат некои датотеки"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Не може да се префрлат некои датотеки"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Може да се обидете да ги копирате датотеките повторно"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Може да се обидете да ги префрлите датотеките повторно"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Сѐ уште се копираат датотеките"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Сѐ уште се префрлаат датотеките"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Може да копирате или префрлите други датотеки откако ќе заврши ова"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Не можеше да се копираат датотеките"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Не можеше да се префрлат датотеките"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Вкупната големина на датотеката е преголема"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Може да копирате или префрлите најмногу 2 GB истовремено"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Избрани се премногу датотеки"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Може да копирате или префрлите најмногу 100 датотеки истовремено"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Не може да се додадат датотеки"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Немате доволно простор на уредот"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Во ред"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Ослободете простор"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Не може да копирате или преместувате датотеки од „Приватниот простор“"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Некои датотеки не можеше да се копираат"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Некои датотеки не можеше да се преместат"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Вашиот „Приватен простор“ се затвори при копирањето"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Вашиот „Приватен простор“ се затвори при префрлањето"</string>
 </resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 591432e..594813f 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"നീക്കുക"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"പകർത്തുക"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"റദ്ദാക്കുക"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ഫയൽ(കൾ) പകർത്തുന്നു"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ഫയൽ(കൾ) നീക്കുന്നു"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ഫയൽ(കൾ) പകർത്തി"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ഫയൽ(കൾ) നീക്കി"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേ‌സിലേക്ക് പകർത്തുകയാണ്"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേ‌സിലേക്ക് നീക്കുകയാണ്"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേ‌സിലേക്ക് പകർത്തി"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേ‌സിലേക്ക് നീക്കി"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ഫയൽ പകർത്തുന്നു}other{# ഫയലുകൾ പകർത്തുന്നു}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ഫയൽ നീക്കുന്നു}other{# ഫയലുകൾ നീക്കുന്നു}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ഫയൽ പകർത്തി}other{# ഫയലുകൾ പകർത്തി}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ഫയൽ നീക്കി}other{# ഫയലുകൾ നീക്കി}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{തിരഞ്ഞെടുത്ത ഫയൽ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് പകർത്തുകയാണ്}other{തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് പകർത്തുകയാണ്}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{തിരഞ്ഞെടുത്ത ഫയൽ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് നീക്കുകയാണ്}other{തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് നീക്കുകയാണ്}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{തിരഞ്ഞെടുത്ത ഫയൽ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് പകർത്തി}other{തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് പകർത്തി}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{തിരഞ്ഞെടുത്ത ഫയൽ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് നീക്കി}other{തിരഞ്ഞെടുത്ത ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് നീക്കി}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ഫയലുകൾ കാണിക്കുക"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ഫയൽ കൈമാറ്റം സംബന്ധിച്ച അറിയിപ്പുകൾ"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ഈ ഫയലുകൾ നിങ്ങളുടെ സ്വകാര്യ സ്പേസിലേക്ക് പകർത്തുകയോ നീക്കുകയോ ചെയ്‌താൽ, പുരോഗതി അറിയിച്ചുകൊണ്ടുള്ള അറിയിപ്പുകൾ നിങ്ങൾക്ക് സ്വീകരിക്കാം"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"ചില ഫയലുകൾ പകർത്താനാകുന്നില്ല"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ചില ഫയലുകൾ നീക്കാനാകുന്നില്ല"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"നിങ്ങളുടെ ഫയലുകൾ വീണ്ടും പകർത്താൻ ശ്രമിക്കാം"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"നിങ്ങളുടെ ഫയലുകൾ വീണ്ടും നീക്കാൻ ശ്രമിക്കാം"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ഇപ്പോഴും ഫയലുകൾ പകർത്തുന്നു"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ഇപ്പോഴും ഫയലുകൾ നീക്കുന്നു"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ഇത് ചെയ്തുകഴിഞ്ഞാൽ, നിങ്ങൾക്ക് കൂടുതൽ ഫയലുകൾ പകർത്താനോ നീക്കാനോ കഴിയും"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ഫയലുകൾ പകർത്താനായില്ല"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ഫയലുകൾ നീക്കാനായില്ല"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"മൊത്തം ഫയലിന്റെ വലുപ്പം വളരെ കൂടുതലാണ്"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ഒരേസമയം 2 GB വരെ മാത്രമേ നിങ്ങൾക്ക് പകർത്താനോ നീക്കാനോ കഴിയൂ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"നിരവധി ഫയലുകൾ തിരഞ്ഞെടുത്തു"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ഒരേസമയം 100 ഫയലുകൾ വരെ മാത്രമേ നിങ്ങൾക്ക് പകർത്താനോ നീക്കാനോ കഴിയൂ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ഫയലുകൾ ചേർക്കാനാകുന്നില്ല"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"നിങ്ങൾക്ക് മതിയായ ഉപകരണ സ്റ്റോറേജ് ഇല്ല"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ശരി"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ഇടം സൃഷ്ടിക്കുക"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"സ്വകാര്യ സ്‌പേസിൽ നിന്ന് ഫയലുകൾ പകർത്താനോ നീക്കാനോ കഴിയില്ല"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"ചില ഫയലുകൾ പകർത്താനായില്ല"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ചില ഫയലുകൾ നീക്കാനായില്ല"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"പകർത്തുന്നതിനിടെ, നിങ്ങളുടെ സ്വകാര്യ സ്പേസ് അടച്ചു"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"നീക്കുന്നതിനിടെ, നിങ്ങളുടെ സ്വകാര്യ സ്പേസ് അടച്ചു"</string>
 </resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 4b63f2e..a459aaf 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Зөөх"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Хуулах"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Цуцлах"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> файл хуулж байна"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> файл зөөж байна"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> файл хуулсан"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> файл зөөсөн"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Таны сонгосон файлыг хаалттай орон зай руу тань хуулж байна"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Таны сонгосон файлыг хаалттай орон зай руу тань зөөж байна"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Таны сонгосон файлыг хаалттай орон зай руу тань хуулсан"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Таны сонгосон файлыг хаалттай орон зай руу тань зөөсөн"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# файлыг хуулж байна}other{# файлыг хуулж байна}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# файлыг зөөж байна}other{# файлыг зөөж байна}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# файлыг хуулсан}other{# файлыг хуулсан}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# файлыг зөөсөн}other{# файлыг зөөсөн}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Таны сонгосон файлыг хаалттай орон зай руу тань хуулж байна}other{Таны сонгосон файлуудыг хаалттай орон зай руу тань хуулж байна}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Таны сонгосон файлыг хаалттай орон зай руу тань зөөж байна}other{Таны сонгосон файлуудыг хаалттай орон зай руу тань зөөж байна}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Таны сонгосон файлыг хаалттай орон зай руу тань хуулсан}other{Таны сонгосон файлуудыг хаалттай орон зай руу тань хуулсан}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Таны сонгосон файлыг хаалттай орон зай руу тань зөөсөн}other{Таны сонгосон файлуудыг хаалттай орон зай руу тань зөөсөн}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Файлыг харуулах"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Файл шилжүүлэх талаарх мэдэгдэл"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Та хаалттай орон зай руугаа файл хуулах, зөөхдөө танд явцын талаар шинэ мэдээлэл өгөх мэдэгдэл хүлээн авах боломжтой"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Зарим файлыг хуулах боломжгүй"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Зарим файлыг зөөх боломжгүй"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Та файлаа хуулахаар дахин оролдох боломжтой"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Та файлаа зөөхөөр дахин оролдох боломжтой"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Файлыг хуулсаар байна"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Файлыг зөөсөөр байна"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Та үүнийг дууссаны дараа илүү олон файл хуулах, зөөх боломжтой"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Файлыг хуулж чадсангүй"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Файлыг зөөж чадсангүй"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Файлын нийт хэмжээ хэт том байна"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Та нэг дор 2 ГБ хүртэлх файлыг л хуулах, зөөх боломжтой"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Хэт олон файл сонгосон"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Та нэг дор 100 хүртэлх файлыг л хуулах, зөөх боломжтой"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Файл нэмэх боломжгүй"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Танд хангалттай төхөөрөмжийн хадгалах сан байхгүй байна"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Сул зай гаргах"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Хаалттай орон зайнаас файл хуулах, зөөх боломжгүй"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Зарим файлыг хуулж чадсангүй"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Зарим файлыг зөөж чадсангүй"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Хуулж байхад таны хаалттай орон зайг хаасан"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Зөөж байхад таны хаалттай орон зайг хаасан"</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 2ecdcd7..2f6c445 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"हलवा"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"कॉपी करा"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"रद्द करा"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> फाइल कॉपी करत आहे"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> फाइल हलवत आहे"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> फाइल कॉपी केल्या आहेत"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> फाइल हलवल्या आहेत"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये कॉपी केल्या जात आहेत"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये हलवल्या जात आहेत"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये कॉपी केल्या आहेत"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये हलवल्या आहेत"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# फाइल कॉपी करत आहे}other{# फाइल कॉपी करत आहे}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# फाइल हलवत आहे}other{# फाइल हलवत आहे}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# फाइल कॉपी केली आहे}other{# फाइल कॉपी केल्या आहेत}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# फाइल हलवली आहे}other{# फाइल हलवल्या आहेत}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{तुमची निवडलेली फाइल तुमच्या खाजगी स्पेसमध्ये कॉपी केली जात आहे}other{तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये कॉपी केल्या जात आहेत}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{तुमची निवडलेली फाइल तुमच्या खाजगी स्पेसमध्ये हलवली जात आहे}other{तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये हलवल्या जात आहेत}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{तुमची निवडलेली फाइल तुमच्या खाजगी स्पेसमध्ये कॉपी केली आहे}other{तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये कॉपी केल्या आहेत}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{तुमची निवडलेली फाइल तुमच्या खाजगी स्पेसमध्ये हलवली आहे}other{तुमच्या निवडलेल्या फाइल तुमच्या खाजगी स्पेसमध्ये हलवल्या आहेत}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"फाइल दाखवा"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"फाइल ट्रान्सफरसंबंधित नोटिफिकेशन"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"तुम्ही तुमच्या खाजगी स्पेसमध्ये फाइल कॉपी केल्यास किंवा हलवल्यास, प्रगतीबाबत अपडेट मिळवण्यासाठी तुम्ही नोटिफिकेशन मिळवू शकता"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"काही फाइल कॉपी करू शकत नाही"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"काही फाइल हलवू शकत नाही"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"तुम्ही तुमच्या फाइल कॉपी करण्याचा पुन्हा प्रयत्न करू शकता"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"तुम्ही तुमच्या फाइल हलवण्याचा पुन्हा प्रयत्न करू शकता"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"फाइल अजूनही कॉपी करत आहे"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"फाइल अजूनही हलवत आहे"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"हे पूर्ण झाल्यानंतर तुम्ही आणखी फाइल कॉपी करू शकता किंवा हलवू शकता"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"फाइल कॉपी करता आली नाही"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"फाइल हलवता आल्या नाहीत"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"फाइलचा एकूण आकार खूप मोठा आहे"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"तुम्ही एकावेळी फक्त कमाल २ GB कॉपी करू शकता किंवा हलवू शकता"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"बऱ्याच फाइल निवडल्या आहेत"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"तुम्ही एकावेळी फक्त १०० फाइल कॉपी करू शकता किंवा हलवू शकता"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"फाइल जोडू शकत नाही"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"तुमच्याकडे पुरेसे डिव्हाइस स्टोरेज नाही"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ओके"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"जागा मोकळी करा"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"खाजगी स्पेसमधून फाइल कॉपी करू किंवा हलवू शकत नाही"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"काही फाइल कॉपी करता आल्या नाहीत"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"काही फाइल हलवता आल्या नाहीत"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"कॉपी करताना तुमची खाजगी स्पेस बंद केली गेली होती"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"हलवताना तुमची खाजगी स्पेस बंद केली गेली होती"</string>
 </resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 7534c65..b948297 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Alih"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Salin"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Batal"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Menyalin <xliff:g id="FILES">%1$d</xliff:g> fail"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Mengalihkan <xliff:g id="FILES">%1$d</xliff:g> fail"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fail disalin"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fail dialihkan"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Fail pilihan anda sedang disalin kepada ruang persendirian anda"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Fail pilihan anda sedang disalin kepada ruang persendirian anda"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Fail pilihan anda telah disalin kepada ruang persendirian anda"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Fail pilihan anda telah dialihkan kepada ruang persendirian anda"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Menyalin # fail}other{Menyalin # fail}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Mengalihkan # fail}other{Mengalihkan # fail}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fail disalin}other{# fail disalin}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fail dialihkan}other{# fail dialihkan}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Fail pilihan anda sedang disalin kepada ruang persendirian anda}other{Fail pilihan anda sedang disalin kepada ruang persendirian anda}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Fail pilihan anda sedang dialihkan kepada ruang persendirian anda}other{Fail pilihan anda sedang dialihkan kepada ruang persendirian anda}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Fail pilihan anda telah disalin kepada ruang persendirian anda}other{Fail pilihan anda telah disalin kepada ruang persendirian anda}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Fail pilihan anda telah dialih kepada ruang persendirian anda}other{Fail pilihan anda telah dialihkan kepada ruang persendirian anda}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Tunjukkan fail"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Pemberitahuan pemindahan fail"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Apabila anda menyalin atau mengalihkan fail kepada ruang persendirian anda, anda boleh menerima pemberitahuan untuk memaklumi anda tentang kemajuan proses itu"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Tidak dapat menyalin beberapa fail"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Tidak dapat mengalihkan beberapa fail"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Anda boleh cuba menyalin fail anda sekali lagi"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Anda boleh cuba mengalihkan fail anda sekali lagi"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Masih menyalin fail"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Masih mengalihkan fail"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Anda boleh menyalin atau mengalihkan fail lagi sebaik sahaja proses ini selesai"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Tidak dapat menyalin fail"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Tidak dapat mengalihkan fail"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Saiz jumlah fail terlalu besar"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Anda hanya boleh menyalin atau mengalihkan maksimum 2 GB sekali gus"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Terlalu banyak fail dipilih"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Anda hanya boleh menyalin atau mengalihkan maksimum 100 fail sekali gus"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Tidak dapat menambahkan fail"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Anda tidak mempunyai storan peranti yang mencukupi"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Kosongkan ruang"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Tidak dapat menyalin atau mengalihkan fail daripada Ruang Persendirian"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Tidak dapat menyalinkan beberapa fail"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Tidak dapat menggerakkan beberapa fail"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Ruang persendirian anda telah ditutup semasa menyalin fail"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Ruang persendirian anda telah ditutup semasa mengalihkan fail"</string>
 </resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 5111f0f..c55eb8e 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ရွှေ့ရန်"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"မိတ္တူကူးရန်"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"မလုပ်တော့"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"ဖိုင် <xliff:g id="FILES">%1$d</xliff:g> ခုကို မိတ္တူကူးနေသည်"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"ဖိုင် <xliff:g id="FILES">%1$d</xliff:g> ခုကို ရွှေ့နေသည်"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"ဖိုင် <xliff:g id="FILES">%1$d</xliff:g> ခုကို မိတ္တူကူးပြီးပါပြီ"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"ဖိုင် <xliff:g id="FILES">%1$d</xliff:g> ခုကို ရွှေ့ပြီးပါပြီ"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ မိတ္တူကူးနေသည်"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ ရွှေ့နေသည်"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ မိတ္တူကူးထားသည်"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ ရွှေ့ထားသည်"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{ဖိုင် # ခုကို မိတ္တူကူးနေသည်}other{ဖိုင် # ခုကို မိတ္တူကူးနေသည်}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{ဖိုင် # ခုကို ရွှေ့နေသည်}other{ဖိုင် # ခုကို ရွှေ့နေသည်}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{ဖိုင် # ခုကို မိတ္တူကူးလိုက်သည်}other{ဖိုင် # ခုကို မိတ္တူကူးလိုက်သည်}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{ဖိုင် # ခုကို ရွှေ့လိုက်သည်}other{ဖိုင် # ခုကို ရွှေ့လိုက်သည်}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ရွေးထားသောဖိုင်ကို သင်၏သီးသန့်နေရာသို့ မိတ္တူကူးနေသည်}other{ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ မိတ္တူကူးနေသည်}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ရွေးထားသောဖိုင်ကို သင်၏သီးသန့်နေရာသို့ ရွှေ့နေသည်}other{ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ ရွှေ့နေသည်}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ရွေးထားသောဖိုင်ကို သင်၏သီးသန့်နေရာသို့ မိတ္တူကူးလိုက်သည်}other{ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ မိတ္တူကူးလိုက်သည်}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ရွေးထားသောဖိုင်ကို သင်၏သီးသန့်နေရာသို့ ရွှေ့လိုက်သည်}other{ရွေးထားသောဖိုင်များကို သင်၏သီးသန့်နေရာသို့ ရွှေ့လိုက်သည်}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ဖိုင်များပြပါ"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ဖိုင်လွှဲပြောင်းခြင်း အကြောင်းကြားချက်"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ဖိုင်များကို သီးသန့်နေရာသို့ မိတ္တူကူး (သို့) ရွှေ့ပါက လုပ်ဆောင်ချက်အတွက် သင့်အားအပ်ဒိတ်လုပ်ရန် အကြောင်းကြားချက်များ ပို့မည်"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"ဖိုင်အချို့ကို မိတ္တူကူး၍မရပါ"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ဖိုင်အချို့ကို ရွှေ့၍မရလိုက်ပါ"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"သင့်ဖိုင်များကို ထပ်မံ မိတ္တူကူးကြည့်နိုင်သည်"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"သင့်ဖိုင်များကို ထပ်မံ ရွှေ့ကြည့်နိုင်သည်"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ဖိုင်များ မိတ္တူကူးနေဆဲ"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ဖိုင်များ ရွှေ့နေဆဲ"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ပြီးဆုံးသည်နှင့် နောက်ထပ်ဖိုင်များကို မိတ္တူကူးနိုင် (သို့) ရွှေ့နိုင်သည်"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ဖိုင်များကို မိတ္တူကူး၍မရလိုက်ပါ"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ဖိုင်များကို ရွှေ့၍မရလိုက်ပါ"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"စုစုပေါင်း ဖိုင်အရွယ်အစားသည် ကြီးလွန်းသည်"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"တစ်ကြိမ်လျှင် ၂ GB အထိ မိတ္တူကူးနိုင် (သို့) ရွှေ့နိုင်သည်"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ရွေးထားသောဖိုင် များလွန်းသည်"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"တစ်ကြိမ်လျှင် ဖိုင် ၁၀၀ အထိ မိတ္တူကူးနိုင် (သို့) ရွှေ့နိုင်သည်"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ဖိုင်များ ထည့်၍မရပါ"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"စက်သိုလှောင်ခန်း လုံလုံလောက်လောက် မရှိပါ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"နေရာလွတ် ပြုလုပ်ရန်"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"‘သီးသန့်နေရာ’ မှ ဖိုင်များကို မိတ္တူကူး၍ (သို့) ရွှေ့၍ မရပါ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"ဖိုင်အချို့ကို မိတ္တူကူး၍မရလိုက်ပါ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ဖိုင်အချို့ကို ရွှေ့၍မရလိုက်ပါ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"မိတ္တူကူးနေစဉ် သင့်သီးသန့်နေရာကို ပိတ်ထားသည်"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ရွှေ့နေစဉ် သင့်သီးသန့်နေရာကို ပိတ်ထားသည်"</string>
 </resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index cf5526f..b0c9931 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Flytt"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiér"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Avbryt"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopierer <xliff:g id="FILES">%1$d</xliff:g> fil(er)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Flytter <xliff:g id="FILES">%1$d</xliff:g> fil(er)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> fil(er) er kopiert"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> fil(er) er flyttet"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Filene du har valgt, kopieres til det private området"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"De valgte filene flyttes til det private området"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"De valgte filene er kopiert til det private området ditt"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"De valgte filene er flyttet til det private området"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopierer # fil}other{Kopierer # filer}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Flytter # fil}other{Flytter # filer}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fil er kopiert}other{# filer er kopiert}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fil er flyttet}other{# filer er flyttet}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Den valgte filen kopieres til det private området ditt}other{De valgte filene kopieres til det private området ditt}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Den valgte filen flyttes til det private området ditt}other{De valgte filene flyttes til det private området ditt}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Den valgte filen er kopiert til det private området ditt}other{De valgte filene er kopiert til det private området ditt}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Den valgte filen er flyttet til det private området ditt}other{De valgte filene er flyttet til det private området ditt}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Vis filene"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Varsler om filoverføring"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Når du kopierer eller flytter filer til det private området ditt, kan du motta varsler som oppdaterer deg om fremdriften"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Kan ikke kopiere enkelte filer"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Kan ikke flytte enkelte filer"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Du kan prøve å kopiere filene på nytt"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Du kan prøve å flytte filene på nytt"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Kopierer fortsatt filer"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Flytter fortsatt filer"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Du kan kopiere eller flytte flere filer når dette er gjort"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Kunne ikke kopiere filene"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Kunne ikke flytte filene"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Filen(e) er for stor(e)"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Du kan bare kopiere eller flytte opptil 2 GB om gangen"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Du har valgt for mange filer"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Du kan bare kopiere eller flytte opptil 100 filer om gangen"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Kan ikke legge til filer"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Du har ikke nok lagringsplass på enheten"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Frigjør plass"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Kan ikke kopiere eller flytte filer fra det private området"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Kunne ikke kopiere visse filer"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Kunne ikke flytte visse filer"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Det private området ble lukket under kopieringen"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Det private området ble lukket under flyttingen"</string>
 </resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 72677f7..2ad390c 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"सार्नुहोस्"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"कपी गर्नुहोस्"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"रद्द गर्नुहोस्"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> वटा फाइल कपी गरिँदै छ"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> वटा फाइल सारिँदै छ"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> वटा फाइल कपी गरिए"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> वटा फाइल सारिए"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"तपाईंले छानेका फाइलहरू कपी गरेर तपाईंको निजी स्पेसमा पेस्ट गरिँदै छ"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"तपाईंले छानेका फाइलहरू सारेर तपाईंको निजी स्पेसमा लगिँदै छ"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"तपाईंले छानेका फाइलहरू कपी गरेर तपाईंको निजी स्पेसमा पेस्ट गरिए"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"तपाईंले छानेका फाइलहरू सारेर तपाईंको निजी स्पेसमा लगिए"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# फाइल कपी गरिँदै छ}other{# वटा फाइल कपी गरिँदै छन्}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# फाइल सारिँदै छ}other{# वटा फाइल सारिँदै छन्}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# फाइल कपी गरिएको छ}other{# वटा फाइल कपी गरिएका छन्}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# फाइल सारिएको छ}other{# वटा फाइल सारिएका छन्}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{तपाईंले छनौट गरेको फाइल तपाईंको निजी स्पेसमा कपी गरिँदै छ}other{तपाईंले छनौट गरेका फाइलहरू तपाईंको निजी स्पेसमा कपी गरिँदै छन्}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{तपाईंले छनौट गरेको फाइल सारेर तपाईंको निजी स्पेसमा लगिँदै छ}other{तपाईंले छनौट गरेका फाइलहरू सारेर तपाईंको निजी स्पेसमा लगिँदै छन्}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{तपाईंले छनौट गरेको फाइल तपाईंको निजी स्पेसमा कपी गरिएको छ}other{तपाईंले छनौट गरेका फाइलहरू तपाईंको निजी स्पेसमा कपी गरिएका छन्}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{तपाईंले छनौट गरेको फाइल सारेर तपाईंको निजी स्पेसमा लगिएको गरिएको छ}other{तपाईंले छनौट गरेका फाइलहरू सारेर तपाईंको निजी स्पेसमा लगिएका छन्}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"फाइलहरू देखाउनुहोस्"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"फाइल ट्रान्स्फर गर्ने कार्यसम्बन्धी नोटिफिकेसन"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"तपाईंले फाइलहरू कपी गरेर आफ्नो निजी स्पेस पेस्ट गर्दा वा फाइलहरू सारेर आफ्नो निजी स्पेसमा लैजाँदा तपाईं सो कार्य कति पूरा भयो भन्ने बारेमा नोटिफिकेसनहरू प्राप्त गर्न सक्नुहुन्छ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"केही फाइलहरू कपी गर्न सकिएन"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"केही फाइलहरू सार्न सकिएन"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"तपाईं फाइलहरू फेरि कपी गरी हेर्न सक्नुहुन्छ"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"तपाईं फाइलहरू फेरि सारी हेर्न सक्नुहुन्छ"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"फाइलहरू अझै पनि कपी गरिँदै छन्"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"फाइलहरू अझै पनि सारिँदै छन्"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"यो कार्य पूरा भएपछि तपाईं थप फाइल कपी गर्न वा सार्न सक्नुहुन्छ"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"फाइलहरू कपी गर्न सकिएन"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"फाइलहरू सार्न सकिएन"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"फाइलहरूको कुल आकार अत्यन्तै बढी छ"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"तपाईं एक पटकमा बढीमा कुल २ जि.बि. का फाइलहरू मात्र कपी गर्न वा सार्न सक्नुहुन्छ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"अत्यधिक धेरै फाइलहरू चयन गरिएका छन्"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"तपाईं एक पटकमा बढीमा १०० वटा फाइल मात्र कपी गर्न वा सार्न सक्नुहुन्छ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"फाइलहरू हाल्न सकिएन"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"तपाईंको डिभाइसमा पर्याप्त खाली ठाउँ छैन"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ठिक छ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ठाउँ खाली गर्नुहोस्"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"निजी स्पेसमा भएका फाइलहरू कपी गर्न वा सारेर अन्यत्र लैजान मिल्दैन"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"केही फाइल कपी गर्न सकिएन"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"केही फाइल सार्न सकिएन"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"फाइलहरू कपी गर्दै गर्दा तपाईंको निजी स्पेस बन्द गरिएको थियो"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"फाइलहरू सार्दै गर्दा तपाईंको निजी स्पेस बन्द गरिएको थियो"</string>
 </resources>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index d4d3b1b..6a03c95 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Verplaatsen"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiëren"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Annuleren"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> bestand(en) kopiëren"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> bestand(en) verplaatsen"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> bestand(en) gekopieerd"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> bestand(en) verplaatst"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"De gekozen bestanden worden gekopieerd naar je privégedeelte"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"De gekozen bestanden worden verplaatst naar je privégedeelte"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"De gekozen bestanden zijn gekopieerd naar je privégedeelte"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"De gekozen bestanden zijn verplaatst naar je privégedeelte"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# bestand kopiëren}other{# bestanden kopiëren}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# bestand verplaatsen}other{# bestanden verplaatsen}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# bestand gekopieerd}other{# bestanden gekopieerd}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# bestand verplaatst}other{# bestanden verplaatst}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Het gekozen bestand wordt gekopieerd naar je privégedeelte}other{De gekozen bestanden worden gekopieerd naar je privégedeelte}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Het gekozen bestand wordt verplaatst naar je privégedeelte}other{De gekozen bestanden worden verplaatst naar je privégedeelte}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Het gekozen bestand is gekopieerd naar je privégedeelte}other{De gekozen bestanden zijn gekopieerd naar je privégedeelte}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Het gekozen bestand is verplaatst naar je privégedeelte}other{De gekozen bestanden zijn verplaatst naar je privégedeelte}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Bestanden tonen"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Meldingen over bestandsoverdracht"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Als je bestanden naar je privégedeelte kopieert of verplaatst, kun je meldingen krijgen over de voortgang"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Kan sommige bestanden niet kopiëren"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Kan sommige bestanden niet verplaatsen"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Je kunt proberen je bestanden opnieuw te kopiëren"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Je kunt proberen je bestanden opnieuw te verplaatsen"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Bestanden worden nog gekopieerd"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Bestanden worden nog verplaatst"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Je kunt meer bestanden kopiëren of verplaatsen als dit is afgerond"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Kan de bestanden niet kopiëren."</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Kan de bestanden niet verplaatsen"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Totale bestandsgrootte is te groot"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Je kunt maximaal 2 GB tegelijk kopiëren of verplaatsen"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Te veel bestanden geselecteerd"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Je kunt maximaal 100 bestanden tegelijk kopiëren of verplaatsen"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Kan de bestanden niet toevoegen"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Je hebt niet genoeg apparaatopslag"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Ruimte vrijmaken"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Kan geen bestanden kopiëren of verplaatsen vanuit het privégedeelte"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Kan sommige bestanden niet kopiëren"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Sommige bestanden kunnen niet worden verplaatst"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Je privégedeelte is gesloten tijdens het kopiëren"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Je privégedeelte is gesloten tijdens het verplaatsen"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index cfbf561..774779b 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ମୁଭ କରନ୍ତୁ"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"କପି କରନ୍ତୁ"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ବାତିଲ କରନ୍ତୁ"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ଫାଇଲ କପି କରାଯାଉଛି"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ଫାଇଲ ମୁଭ କରାଯାଉଛି"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ଫାଇଲ କପି କରାଯାଇଛି"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ଫାଇଲ ମୁଭ କରାଯାଇଛି"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସରେ କପି କରାଯାଉଛି"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସକୁ ମୁଭ କରାଯାଉଛି"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସରେ କପି କରାଯାଇଛି"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସକୁ ମୁଭ କରାଯାଉଛି"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ଫାଇଲକୁ କପି କରାଯାଉଛି}other{# ଫାଇଲକୁ କପି କରାଯାଉଛି}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ଫାଇଲକୁ ମୁଭ କରାଯାଉଛି}other{# ଫାଇଲକୁ ମୁଭ କରାଯାଉଛି}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ଫାଇଲ କପି କରାଯାଇଛି}other{# ଫାଇଲ କପି କରାଯାଇଛି}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ଫାଇଲକୁ ମୁଭ କରାଯାଇଛି}other{# ଫାଇଲକୁ ମୁଭ କରାଯାଇଛି}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ଆପଣ ବାଛିଥିବା ଫାଇଲକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସରେ କପି କରାଯାଉଛି}other{ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସରେ କପି କରାଯାଉଛି}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ଆପଣ ବାଛିଥିବା ଫାଇଲକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସକୁ ମୁଭ କରାଯାଉଛି}other{ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସକୁ ମୁଭ କରାଯାଉଛି}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ଆପଣ ବାଛିଥିବା ଫାଇଲକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସରେ କପି କରାଯାଇଛି}other{ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସରେ କପି କରାଯାଇଛି}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ଆପଣ ବାଛିଥିବା ଫାଇଲକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସକୁ ମୁଭ କରାଯାଇଛି}other{ଆପଣ ବାଛିଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସକୁ ମୁଭ କରାଯାଇଛି}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ଫାଇଲଗୁଡ଼ିକ ଦେଖାନ୍ତୁ"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ଫାଇଲ ଟ୍ରାନ୍ସଫର ବିଜ୍ଞପ୍ତି"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ଆପଣ ଫାଇଲଗୁଡ଼ିକୁ ଆପଣଙ୍କର ପ୍ରାଇଭେଟ ସ୍ପେସକୁ କପି କିମ୍ବା ମୁଭ କଲେ, ଆପଣଙ୍କୁ ପ୍ରୋଗ୍ରେସ ବିଷୟରେ ଅପଡେଟ କରିବା ପାଇଁ ଆପଣ ବିଜ୍ଞପ୍ତିଗୁଡ଼ିକ ପାଇପାରିବେ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"କିଛି ଫାଇଲକୁ କପି କରାଯାଇପାରିବ ନାହିଁ"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"କିଛି ଫାଇଲକୁ ମୁଭ କରାଯାଇପାରିବ ନାହିଁ"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ଆପଣ ଆପଣଙ୍କ ଫାଇଲଗୁଡ଼ିକୁ ପୁଣି କପି କରିବାକୁ ଚେଷ୍ଟା କରିପାରିବେ"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ଆପଣ ଆପଣଙ୍କ ଫାଇଲଗୁଡ଼ିକୁ ପୁଣି ମୁଭ କରିବାକୁ ଚେଷ୍ଟା କରିପାରିବେ"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ଫାଇଲଗୁଡ଼ିକୁ ଏବେ ବି କପି କରାଯାଉଛି"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ଫାଇଲଗୁଡ଼ିକୁ ଏବେ ବି ମୁଭ କରାଯାଉଛି"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ଏହା ହୋଇଗଲା ପରେ ଆପଣ ଅଧିକ ଫାଇଲ କପି କିମ୍ବା ମୁଭ କରିପାରିବେ"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ଫାଇଲକୁ କପି କରାଯାଇପାରିଲା ନାହିଁ"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ଫାଇଲଗୁଡ଼ିକୁ ମୁଭ କରାଯାଇପାରିଲା ନାହିଁ"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ମୋଟ ଫାଇଲ ସାଇଜ ବହୁତ ବଡ଼ ଅଟେ"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ଆପଣ ଥରକେ କେବଳ 2 GB ପର୍ଯ୍ୟନ୍ତ କପି କିମ୍ବା ମୁଭ କରିପାରିବେ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ବହୁତ ଅଧିକ ଫାଇଲ ଚୟନ କରାଯାଇଛି"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ଆପଣ ଥରକେ କେବଳ 100 ପର୍ଯ୍ୟନ୍ତ ଫାଇଲ କପି କିମ୍ବା ମୁଭ କରିପାରିବେ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ଫାଇଲଗୁଡ଼ିକୁ ଯୋଗ କରାଯାଇପାରିବ ନାହିଁ"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"ଆପଣଙ୍କର ପର୍ଯ୍ୟାପ୍ତ ଡିଭାଇସ ଷ୍ଟୋରେଜ ନାହିଁ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ଠିକ ଅଛି"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ସ୍ପେସ ଖାଲି କରନ୍ତୁ"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ପ୍ରାଇଭେଟ ସ୍ପେସରୁ ଫାଇଲଗୁଡ଼ିକୁ କପି କିମ୍ବା ମୁଭ କରାଯାଇପାରିବ ନାହିଁ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"କିଛି ଫାଇଲକୁ କପି କରାଯାଇପାରିଲା ନାହିଁ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"କିଛି ଫାଇଲକୁ ମୁଭ କରାଯାଇପାରିଲା ନାହିଁ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"କପି କରିବା ସମୟରେ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସ ବନ୍ଦ ହୋଇଯାଇଥିଲା"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ମୁଭ କରିବା ସମୟରେ ଆପଣଙ୍କ ପ୍ରାଇଭେଟ ସ୍ପେସ ବନ୍ଦ ହୋଇଯାଇଥିଲା"</string>
 </resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 32065c9..16b3c7e 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ਲਿਜਾਓ"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"ਕਾਪੀ ਕਰੋ"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ਰੱਦ ਕਰੋ"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ਫ਼ਾਈਲਾਂ ਕਾਪੀ ਕੀਤੀਆਂ ਜਾ ਰਹੀਆਂ ਹਨ"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ਫ਼ਾਈਲਾਂ ਲਿਜਾਈਆਂ ਜਾ ਰਹੀਆਂ ਹਨ"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ਫ਼ਾਈਲਾਂ ਕਾਪੀ ਕੀਤੀਆਂ ਗਈਆਂ"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ਲਿਜਾਈਆਂ ਗਈਆਂ"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਕਾਪੀ ਕੀਤੀਆਂ ਜਾ ਰਹੀਆਂ ਹਨ"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਵਿੱਚ ਲਿਜਾਈਆਂ ਜਾ ਰਹੀਆਂ ਹਨ"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਕਾਪੀ ਕਰ ਦਿੱਤੀਆਂ ਗਈਆਂ ਹਨ"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਵਿੱਚ ਲਿਜਾਈਆਂ ਗਈਆਂ ਹਨ"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ਫ਼ਾਈਲ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{# ਫ਼ਾਈਲ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{# ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ਫ਼ਾਈਲ ਨੂੰ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ}one{# ਫ਼ਾਈਲ ਨੂੰ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ}other{# ਫ਼ਾਈਲਾਂ ਨੂੰ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ਫ਼ਾਈਲ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਗਿਆ}one{# ਫ਼ਾਈਲ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਗਿਆ}other{# ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਗਿਆ}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ਫ਼ਾਈਲ ਨੂੰ ਲਿਜਾਇਆ ਗਿਆ}one{# ਫ਼ਾਈਲ ਨੂੰ ਲਿਜਾਇਆ ਗਿਆ}other{# ਫ਼ਾਈਲਾਂ ਨੂੰ ਲਿਜਾਇਆ ਗਿਆ}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਵਿੱਚ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਵਿੱਚ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਵਿੱਚ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ}one{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ}other{ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਕਾਪੀ ਕਰ ਦਿੱਤਾ ਗਿਆ ਹੈ}one{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਕਾਪੀ ਕਰ ਦਿੱਤਾ ਗਿਆ ਹੈ}other{ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਕਾਪੀ ਕਰ ਦਿੱਤਾ ਗਿਆ ਹੈ}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਲਿਜਾਇਆ ਗਿਆ}one{ਤੁਹਾਡੀ ਚੁਣੀ ਗਈ ਫ਼ਾਈਲ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਲਿਜਾਇਆ ਗਿਆ}other{ਤੁਹਾਡੀਆਂ ਚੁਣੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਤੁਹਾਡੀ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਲਿਜਾਇਆ ਗਿਆ}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ਫ਼ਾਈਲਾਂ ਦਿਖਾਓ"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ਫ਼ਾਈਲ ਟ੍ਰਾਂਸਫ਼ਰ ਸੰਬੰਧੀ ਸੂਚਨਾਵਾਂ"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ਜਦੋਂ ਤੁਸੀਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਆਪਣੇ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ \'ਤੇ ਕਾਪੀ ਕਰਦੇ ਜਾਂ ਲਿਜਾਉਂਦੇ ਹੋ, ਤਾਂ ਤੁਸੀਂ ਸੂਚਨਾਵਾਂ ਪ੍ਰਾਪਤ ਕਰ ਸਕਦੇ ਹੋ, ਤਾਂ ਜੋ ਤੁਹਾਨੂੰ ਪ੍ਰਗਤੀ ਸੰਬੰਧੀ ਅੱਪਡੇਟ ਮਿਲ ਸਕੇ"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"ਕੁਝ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ਕੁਝ ਫ਼ਾਈਲਾਂ ਨੂੰ ਲਿਜਾਇਆ ਨਹੀਂ ਜਾ ਸਕਦਾ"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ਤੁਸੀਂ ਆਪਣੀਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਕਰਨ ਦੀ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰ ਸਕਦੇ ਹੋ"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ਤੁਸੀਂ ਆਪਣੀਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਲਿਜਾਉਣ ਦੀ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰ ਸਕਦੇ ਹੋ"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ਹਾਲੇ ਵੀ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ਹਾਲੇ ਵੀ ਫ਼ਾਈਲਾਂ ਨੂੰ ਲਿਜਾਇਆ ਜਾ ਰਿਹਾ ਹੈ"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ਇਸਦੇ ਪੂਰਾ ਹੋਣ \'ਤੇ, ਤੁਸੀਂ ਹੋਰ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਕਰ ਜਾਂ ਲਿਜਾ ਸਕਦੇ ਹੋ"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਿਆ"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ਫ਼ਾਈਲਾਂ ਨੂੰ ਲਿਜਾਇਆ ਨਹੀਂ ਜਾ ਸਕਿਆ"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ਫ਼ਾਈਲ ਦਾ ਕੁੱਲ ਆਕਾਰ ਬਹੁਤ ਜ਼ਿਆਦਾ ਵੱਡਾ ਹੈ"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ਤੁਸੀਂ ਇੱਕ ਵਾਰ ਵਿੱਚ ਸਿਰਫ਼ 2 GB ਤੱਕ ਕਾਪੀ ਕਰ ਸਕਦੇ ਹੋ ਜਾਂ ਇੱਕ ਤੋਂ ਦੂਜੀ ਥਾਂ \'ਤੇ ਲਿਜਾ ਸਕਦੇ ਹੋ"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ਬਹੁਤ ਸਾਰੀਆਂ ਫ਼ਾਈਲਾਂ ਚੁਣੀਆਂ ਗਈਆਂ"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ਤੁਸੀਂ ਇੱਕ ਵਾਰ ਵਿੱਚ ਸਿਰਫ਼ 100 ਫ਼ਾਈਲਾਂ ਤੱਕ ਕਾਪੀ ਕਰ ਜਾਂ ਲਿਜਾ ਸਕਦੇ ਹੋ"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ਫ਼ਾਈਲਾਂ ਨੂੰ ਸ਼ਾਮਲ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"ਤੁਹਾਡੇ ਕੋਲ ਲੋੜੀਂਦੀ ਡੀਵਾਈਸ ਸਟੋਰੇਜ ਨਹੀਂ ਹੈ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ਠੀਕ ਹੈ"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ਜਗ੍ਹਾ ਖਾਲੀ ਕਰੋ"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਤੋਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਾਪੀ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ ਜਾਂ ਉਨ੍ਹਾਂ ਨੂੰ ਕਿਸੇ ਹੋਰ ਥਾਂ \'ਤੇ ਨਹੀਂ ਲਿਜਾਇਆ ਜਾ ਸਕਦਾ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"ਕੁਝ ਫ਼ਾਈਲਾਂ ਕਾਪੀ ਨਹੀਂ ਕੀਤੀਆਂ ਜਾ ਸਕੀਆਂ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ਕੁਝ ਫ਼ਾਈਲਾਂ ਦਾ ਟਿਕਾਣਾ ਨਹੀਂ ਬਦਲਿਆ ਜਾ ਸਕਿਆ"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"ਕਾਪੀ ਕਰਨ ਵੇਲੇ ਤੁਹਾਡਾ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਬੰਦ ਸੀ"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ਟਿਕਾਣਾ ਬਦਲਣ ਵੇਲੇ ਤੁਹਾਡਾ ਪ੍ਰਾਈਵੇਟ ਸਪੇਸ ਬੰਦ ਸੀ"</string>
 </resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index e7326b6..ceec61d 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Przenieś"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiuj"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Anuluj"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopiuję pliki (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Przenoszę pliki (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Skopiowano pliki (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Przeniesiono pliki (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Trwa kopiowanie wybranych plików do przestrzeni prywatnej"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Trwa przenoszenie wybranych plików do przestrzeni prywatnej"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Wybrane pliki zostały skopiowane do przestrzeni prywatnej"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Wybrane pliki zostały przeniesione do przestrzeni prywatnej"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopiuję # plik}few{Kopiuję # pliki}many{Kopiuję # plików}other{Kopiuję # pliku}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Przenoszę # plik}few{Przenoszę # pliki}many{Przenoszę # plików}other{Przenoszę # pliku}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Skopiowano # plik}few{Skopiowano # pliki}many{Skopiowano # plików}other{Skopiowano # pliku}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Przeniesiono # plik}few{Przeniesiono # pliki}many{Przeniesiono # plików}other{Przeniesiono # pliku}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Trwa kopiowanie wybranego pliku do przestrzeni prywatnej}few{Trwa kopiowanie wybranych plików do przestrzeni prywatnej}many{Trwa kopiowanie wybranych plików do przestrzeni prywatnej}other{Trwa kopiowanie wybranych plików do przestrzeni prywatnej}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Trwa przenoszenie wybranego pliku do przestrzeni prywatnej}few{Trwa przenoszenie wybranych plików do przestrzeni prywatnej}many{Trwa przenoszenie wybranych plików do przestrzeni prywatnej}other{Trwa przenoszenie wybranych plików do przestrzeni prywatnej}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Wybrany plik został skopiowany do przestrzeni prywatnej}few{Wybrane pliki zostały skopiowane do przestrzeni prywatnej}many{Wybrane pliki zostały skopiowane do przestrzeni prywatnej}other{Wybrane pliki zostały skopiowane do przestrzeni prywatnej}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Wybrany plik został przeniesiony do przestrzeni prywatnej}few{Wybrane pliki zostały przeniesione do przestrzeni prywatnej}many{Wybrane pliki zostały przeniesione do przestrzeni prywatnej}other{Wybrane pliki zostały przeniesione do przestrzeni prywatnej}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Zobacz pliki"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Powiadomienia o przesyłaniu plików"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Gdy kopiujesz lub przenosisz pliki do przestrzeni prywatnej, możesz otrzymywać powiadomienia o postępach"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nie można skopiować niektórych plików"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nie można przenieść niektórych plików"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Możesz spróbować ponownie skopiować pliki"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Możesz spróbować ponownie przenieść pliki"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Nadal kopiuję pliki"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Nadal przenoszę pliki"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Po zakończeniu możesz skopiować lub przenieść więcej plików"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Nie udało się skopiować plików"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Nie udało się przenieść plików"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Łączny rozmiar plików jest za duży"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Możesz skopiować lub przenieść maksymalnie 2 GB naraz"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Wybrano zbyt wiele plików"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Możesz skopiować lub przenieść maksymalnie 100 plików naraz"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nie można dodać plików"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Masz za mało pamięci na urządzeniu"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Zwolnij miejsce"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Nie można skopiować lub przenieść plików z przestrzeni prywatnej"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Nie udało się skopiować niektórych plików"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Nie udało się przenieść niektórych plików"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Podczas kopiowania Twoja przestrzeń prywatna została zamknięta"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Podczas przenoszenia Twoja przestrzeń prywatna została zamknięta"</string>
 </resources>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index b09bb94..14784f2 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Adicionar arquivos"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Instalar apps"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Mover ou copiar arquivos?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Se você mover esses arquivos para seu Espaço Privado, eles serão removidos das pastas originais"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Se você mover esses arquivos para seu espaço privado, eles serão removidos das pastas originais"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mover"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiar"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancelar"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copiando <xliff:g id="FILES">%1$d</xliff:g> arquivo(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Movendo <xliff:g id="FILES">%1$d</xliff:g> arquivo(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Arquivos copiados: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Arquivos movidos: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Os arquivos escolhidos estão sendo copiados para seu espaço privado"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Os arquivos escolhidos estão sendo movidos para seu espaço privado"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Os arquivos escolhidos foram copiados para seu espaço privado"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Os arquivos escolhidos foram movidos para seu espaço privado"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copiando # arquivo}one{Copiando # arquivo}many{Copiando # de arquivos}other{Copiando # arquivos}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Movendo # arquivo}one{Movendo # arquivo}many{Movendo # de arquivos}other{Movendo # arquivos}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# arquivo copiado}one{# arquivo copiado}many{# de arquivos copiados}other{# arquivos copiados}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# arquivo movido}one{# arquivo movido}many{# de arquivos movidos}other{# arquivos movidos}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{O arquivo escolhido está sendo copiado para seu espaço privado}one{O arquivo escolhido está sendo copiado para seu espaço privado}many{Os arquivos escolhidos estão sendo copiados para seu espaço privado}other{Os arquivos escolhidos estão sendo copiados para seu espaço privado}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{O arquivo escolhido está sendo movido para seu espaço privado}one{O arquivo escolhido está sendo movido para seu espaço privado}many{Os arquivos escolhidos estão sendo movidos para seu espaço privado}other{Os arquivos escolhidos estão sendo movidos para seu espaço privado}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{O arquivo escolhido foi copiado para seu espaço privado}one{O arquivo escolhido foi copiado para seu espaço privado}many{Os arquivos escolhidos foram copiados para seu espaço privado}other{Os arquivos escolhidos foram copiados para seu espaço privado}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{O arquivo escolhido foi movido para seu espaço privado}one{O arquivo escolhido foi movido para seu espaço privado}many{Os arquivos escolhidos foram movidos para seu espaço privado}other{Os arquivos escolhidos foram movidos para seu espaço privado}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostrar arquivos"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notificações de transferência de arquivo"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Quando você copia ou move arquivos para o espaço privado, pode receber notificações com atualizações sobre o progresso"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Não é possível copiar alguns arquivos"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Não é possível mover alguns arquivos"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Tente copiar os arquivos de novo"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Tente mover os arquivos de novo"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Ainda copiando arquivos"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Ainda movendo arquivos"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Você poderá copiar ou mover mais arquivos depois que o processo for concluído"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Não foi possível copiar os arquivos"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Não foi possível mover os arquivos"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Tamanho total muito grande"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Só é possível copiar ou mover até 2 GB por vez"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Muitos arquivos selecionados"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Só é possível copiar ou mover até 100 arquivos por vez"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Não é possível adicionar arquivos"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Não há armazenamento suficiente no dispositivo"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Liberar espaço"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Não é possível copiar ou mover arquivos do espaço privado"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Não foi possível copiar alguns arquivos"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Não foi possível mover alguns arquivos"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Seu Espaço Privado foi fechado durante a cópia"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Seu Espaço Privado foi fechado durante a transferência"</string>
 </resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 01df8d4..a1fce08 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mover"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiar"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancelar"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"A copiar <xliff:g id="FILES">%1$d</xliff:g> ficheiro(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"A mover <xliff:g id="FILES">%1$d</xliff:g> ficheiro(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ficheiro(s) copiado(s)"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ficheiro(s) movido(s)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Os ficheiros escolhidos estão a ser copiados para o seu espaço privado"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Os ficheiros escolhidos estão a ser movidos para o seu espaço privado"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Os ficheiros escolhidos foram copiados para o seu espaço privado"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Os ficheiros escolhidos foram movidos para o seu espaço privado"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{A copiar # ficheiro}many{A copiar # ficheiros}other{A copiar # ficheiros}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{A mover # ficheiro}many{A mover # ficheiros}other{A mover # ficheiros}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ficheiro copiado}many{# ficheiros copiados}other{# ficheiros copiados}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ficheiro movido}many{# ficheiros movidos}other{# ficheiros movidos}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{O ficheiro escolhido está a ser copiado para o seu espaço privado}many{Os ficheiros escolhidos estão a ser copiados para o seu espaço privado}other{Os ficheiros escolhidos estão a ser copiados para o seu espaço privado}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{O ficheiro escolhido está a ser movido para o seu espaço privado}many{Os ficheiros escolhidos estão a ser movidos para o seu espaço privado}other{Os ficheiros escolhidos estão a ser movidos para o seu espaço privado}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{O ficheiro escolhido foi copiado para o seu espaço privado}many{Os ficheiros escolhidos foram copiados para o seu espaço privado}other{Os ficheiros escolhidos foram copiados para o seu espaço privado}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{O ficheiro escolhido foi movido para o seu espaço privado}many{Os ficheiros escolhidos foram movidos para o seu espaço privado}other{Os ficheiros escolhidos foram movidos para o seu espaço privado}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostrar ficheiros"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notific. de transferência de ficheiros"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Quando copia ou move ficheiros para o seu espaço privado, pode receber notificações com atualizações sobre o progresso"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Não é possível copiar alguns ficheiros"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Não é possível mover alguns ficheiros"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Pode tentar copiar os ficheiros novamente"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Pode tentar mover os ficheiros novamente"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Ainda a copiar ficheiros"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Ainda a mover ficheiros"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Pode copiar ou mover mais ficheiros assim que esta ação estiver concluída"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Não foi possível copiar os ficheiros"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Não foi possível mover os ficheiros"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"O tamanho total do ficheiro é demasiado grande"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Só pode copiar ou mover até 2 GB de cada vez"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Demasiados ficheiros selecionados"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Só pode copiar ou mover até 100 ficheiros de uma vez"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Não é possível adicionar ficheiros"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Não tem armazenamento do dispositivo suficiente"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Libertar espaço"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Não é possível copiar ou mover ficheiros do espaço privado"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Não foi possível copiar alguns ficheiros"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Não foi possível mover alguns ficheiros"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"O seu espaço privado foi fechado durante a cópia"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"O seu espaço privado foi fechado durante a mudança"</string>
 </resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index b09bb94..14784f2 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"Adicionar arquivos"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Instalar apps"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Mover ou copiar arquivos?"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Se você mover esses arquivos para seu Espaço Privado, eles serão removidos das pastas originais"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"Se você mover esses arquivos para seu espaço privado, eles serão removidos das pastas originais"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mover"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiar"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Cancelar"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Copiando <xliff:g id="FILES">%1$d</xliff:g> arquivo(s)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Movendo <xliff:g id="FILES">%1$d</xliff:g> arquivo(s)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Arquivos copiados: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Arquivos movidos: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Os arquivos escolhidos estão sendo copiados para seu espaço privado"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Os arquivos escolhidos estão sendo movidos para seu espaço privado"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Os arquivos escolhidos foram copiados para seu espaço privado"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Os arquivos escolhidos foram movidos para seu espaço privado"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Copiando # arquivo}one{Copiando # arquivo}many{Copiando # de arquivos}other{Copiando # arquivos}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Movendo # arquivo}one{Movendo # arquivo}many{Movendo # de arquivos}other{Movendo # arquivos}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# arquivo copiado}one{# arquivo copiado}many{# de arquivos copiados}other{# arquivos copiados}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# arquivo movido}one{# arquivo movido}many{# de arquivos movidos}other{# arquivos movidos}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{O arquivo escolhido está sendo copiado para seu espaço privado}one{O arquivo escolhido está sendo copiado para seu espaço privado}many{Os arquivos escolhidos estão sendo copiados para seu espaço privado}other{Os arquivos escolhidos estão sendo copiados para seu espaço privado}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{O arquivo escolhido está sendo movido para seu espaço privado}one{O arquivo escolhido está sendo movido para seu espaço privado}many{Os arquivos escolhidos estão sendo movidos para seu espaço privado}other{Os arquivos escolhidos estão sendo movidos para seu espaço privado}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{O arquivo escolhido foi copiado para seu espaço privado}one{O arquivo escolhido foi copiado para seu espaço privado}many{Os arquivos escolhidos foram copiados para seu espaço privado}other{Os arquivos escolhidos foram copiados para seu espaço privado}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{O arquivo escolhido foi movido para seu espaço privado}one{O arquivo escolhido foi movido para seu espaço privado}many{Os arquivos escolhidos foram movidos para seu espaço privado}other{Os arquivos escolhidos foram movidos para seu espaço privado}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Mostrar arquivos"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notificações de transferência de arquivo"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Quando você copia ou move arquivos para o espaço privado, pode receber notificações com atualizações sobre o progresso"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Não é possível copiar alguns arquivos"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Não é possível mover alguns arquivos"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Tente copiar os arquivos de novo"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Tente mover os arquivos de novo"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Ainda copiando arquivos"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Ainda movendo arquivos"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Você poderá copiar ou mover mais arquivos depois que o processo for concluído"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Não foi possível copiar os arquivos"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Não foi possível mover os arquivos"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Tamanho total muito grande"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Só é possível copiar ou mover até 2 GB por vez"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Muitos arquivos selecionados"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Só é possível copiar ou mover até 100 arquivos por vez"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Não é possível adicionar arquivos"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Não há armazenamento suficiente no dispositivo"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Liberar espaço"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Não é possível copiar ou mover arquivos do espaço privado"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Não foi possível copiar alguns arquivos"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Não foi possível mover alguns arquivos"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Seu Espaço Privado foi fechado durante a cópia"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Seu Espaço Privado foi fechado durante a transferência"</string>
 </resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index b73ea7f..c98cc3a 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Mută"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Copiază"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Anulează"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Se copiază <xliff:g id="FILES">%1$d</xliff:g> fișier"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Se mută <xliff:g id="FILES">%1$d</xliff:g> fișier"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Fișiere copiate: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Fișiere mutate: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Fișierele alese se copiază în spațiul privat"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Fișierele alese sunt mutate în spațiul privat"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Fișierele alese au fost copiate în spațiul privat"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Fișierele alese au fost mutate în spațiul privat"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Se copiază # fișier}few{Se copiază # fișiere}other{Se copiază # de fișiere}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Se mută # fișier}few{Se mută # fișiere}other{Se mută # de fișiere}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fișier copiat}few{# fișiere copiate}other{# de fișiere copiate}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fișier mutat}few{# fișiere mutate}other{# de fișiere mutate}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Fișierul ales se copiază în spațiul privat}few{Fișierele alese se copiază în spațiul privat}other{Fișierele alese se copiază în spațiul privat}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Fișierul ales este mutat în spațiul privat}few{Fișierele alese sunt mutate în spațiul privat}other{Fișierele alese sunt mutate în spațiul privat}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Fișierul ales a fost copiat în spațiul privat}few{Fișierele alese au fost copiate în spațiul privat}other{Fișierele alese au fost copiate în spațiul privat}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Fișierul ales a fost mutat în spațiul privat}few{Fișierele alese au fost mutate în spațiul privat}other{Fișierele alese au fost mutate în spațiul privat}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Afișează fișierele"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Notificări privind transferul de fișiere"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Când copiezi sau muți fișiere în spațiul privat, poți primi notificări pentru a fi la curent cu progresul"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nu se pot copia unele fișiere"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nu se pot muta unele fișiere"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Poți încerca să copiezi din nou fișierele"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Încearcă să muți din nou fișierele"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Încă se copiază fișiere"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Încă se mută fișiere"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Poți să copiezi sau să muți mai multe fișiere după ce ai terminat"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Nu s-au putut copia fișiere"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Nu s-au putut muta fișierele"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Dimensiunea totală a fișierului este prea mare"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Poți să copiezi sau să muți maximum 2 GB odată"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Ai selectat prea multe fișiere"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Poți să copiezi sau să muți maximum 100 de fișiere simultan"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Nu se pot adăuga fișiere"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Nu ai suficient spațiu de stocare pe dispozitiv"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Eliberează spațiu"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Nu poți copia sau muta fișiere din Spațiul privat"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Nu s-au putut copia anumite fișiere"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Unele fișiere nu au putut fi mutate"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Spațiul privat a fost închis în timpul copierii"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Spațiul privat a fost închis în timpul mutării"</string>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 84e2821..2f6c9ef 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Переместить"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Копировать"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Отмена"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Копирование файлов (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Перемещение файлов (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Скопировано файлов: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Перемещено файлов: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Выбранные файлы копируются в частное пространство."</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Выбранные файлы перемещаются в частное пространство."</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Выбранные файлы скопированы в частное пространство."</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Выбранные файлы перемещены в частное пространство."</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Копирование # файла…}one{Копирование # файла…}few{Копирование # файлов…}many{Копирование # файлов…}other{Копирование # файла…}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Перемещение # файла…}one{Перемещение # файла…}few{Перемещение # файлов…}many{Перемещение # файлов…}other{Перемещение # файла…}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Скопирован # файл}one{Скопирован # файл}few{Скопировано # файла}many{Скопировано # файлов}other{Скопировано # файла}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Перемещен # файл}one{Перемещен # файл}few{Перемещено # файла}many{Перемещено # файлов}other{Перемещено # файла}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Выбранный файл копируется в частное пространство.}one{Выбранные файлы копируются в частное пространство.}few{Выбранные файлы копируются в частное пространство.}many{Выбранные файлы копируются в частное пространство.}other{Выбранные файлы копируются в частное пространство.}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Выбранный файл перемещается в частное пространство.}one{Выбранные файлы перемещаются в частное пространство.}few{Выбранные файлы перемещаются в частное пространство.}many{Выбранные файлы перемещаются в частное пространство.}other{Выбранные файлы перемещаются в частное пространство.}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Выбранный файл скопирован в частное пространство.}one{Выбранные файлы скопированы в частное пространство.}few{Выбранные файлы скопированы в частное пространство.}many{Выбранные файлы скопированы в частное пространство.}other{Выбранные файлы скопированы в частное пространство.}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Выбранный файл перемещен в частное пространство.}one{Выбранные файлы перемещены в частное пространство.}few{Выбранные файлы перемещены в частное пространство.}many{Выбранные файлы перемещены в частное пространство.}other{Выбранные файлы перемещены в частное пространство.}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Показать файлы"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Уведомления о переносе файлов"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Когда вы копируете или перемещаете файлы в частное пространство, вам могут приходить уведомления о статусе этого процесса"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Не удалось скопировать некоторые файлы"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Не удалось переместить некоторые файлы"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Попробуйте скопировать файлы ещё раз."</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Попробуйте переместить файлы ещё раз."</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Копирование ещё не завершено"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Перемещение ещё не завершено"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Подождите, прежде чем копировать или перемещать другие файлы."</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Не удалось скопировать файлы"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Не удалось переместить файлы"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Общий размер файлов слишком большой"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Одновременно можно копировать или перемещать не более 2 ГБ."</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Выбрано слишком много файлов"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Одновременно можно копировать или перемещать не более 100 файлов."</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Не удалось добавить файлы"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"На устройстве недостаточно места."</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ОК"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Освободить место"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Файлы из частного пространства нельзя перемещать или копировать."</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Не удалось скопировать некоторые файлы"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Не удалось переместить некоторые файлы"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Во время копирования частное пространство было закрыто."</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Во время перемещения частное пространство было закрыто."</string>
 </resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index bf14da4..4ec0a47 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ගෙන යන්න"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"පිටපත් කරන්න"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"අවලංගු කරන්න"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"ගොනු(ගොනුව) <xliff:g id="FILES">%1$d</xliff:g> පිටපත් කරමින්"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"ගොනු(ගොනුව) <xliff:g id="FILES">%1$d</xliff:g>ක් ගෙන යාම"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"ගොනු(ගොනුව) <xliff:g id="FILES">%1$d</xliff:g>ක් පිටපත් කරන ලදී"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"ගොනු(ගොනුව) <xliff:g id="FILES">%1$d</xliff:g>ක් චලනය කරන ලදී"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"ඔබ තෝරාගත් ගොනු ඔබගේ රහසිගත අවකාශයට පිටපත් කරමින් පවතී."</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"ඔබ තෝරාගත් ගොනු ඔබගේ රහසිගත අවකාශයට චලනය කරමින් පවතී"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට පිටපත් කරන ලදී."</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට චලනය කරන ලදී"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ගොනුවක් පිටපත් කරමින්}one{ගොනු #ක් පිටපත් කරමින්}other{ගොනු #ක් පිටපත් කරමින්}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ගොනුවක් ගෙන යමින්}one{ගොනු #ක් ගෙන යමින්}other{ගොනු #ක් ගෙන යමින්}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ගොනුවක් පිටපත් කර ඇත}one{ගොනු #ක් පිටපත් කර ඇත}other{ගොනු #ක් පිටපත් කර ඇත}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ගොනුවක් ගෙන යන ලදි}one{ගොනු #ක් ගෙන යන ලදි}other{ගොනු #ක් ගෙන යන ලදි}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{ඔබ තෝරාගත් ගොනුව ඔබේ රහසිගත අවකාශයට පිටපත් කරමින් පවතී}one{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට පිටපත් කරමින් පවතී}other{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට පිටපත් කරමින් පවතී}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{ඔබ තෝරාගත් ගොනුව ඔබේ රහසිගත අවකාශයට ගෙන යමින් පවතී}one{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට ගෙන යමින් පවතී}other{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට ගෙන යමින් පවතී}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{ඔබ තෝරාගත් ගොනුව ඔබේ රහසිගත අවකාශයට පිටපත් කරන ලදි}one{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට පිටපත් කරන ලදි}other{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට පිටපත් කරන ලදි}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ඔබ තෝරාගත් ගොනුව ඔබේ රහසිගත අවකාශයට ගෙන යන ලදි}one{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට ගෙන යන ලදි}other{ඔබ තෝරාගත් ගොනු ඔබේ රහසිගත අවකාශයට ගෙන යන ලදි}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ගොනු පෙන්වන්න"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ගොනු මාරු කිරීමේ දැනුම්දීම්"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ඔබ ඔබේ රහසිගත අවකාශයට ගොනු පිටපත් කරන විට හෝ ගෙන යන විට, ප්‍රගතිය පිළිබඳව ඔබව යාවත්කාලීන කිරීමට ඔබට දැනුම්දීම් ලැබිය හැක"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"සමහර ගොනු පිටපත් කළ නොහැක"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"සමහර ගොනු ගෙන යා නොහැක"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"ඔබට නැවත ඔබේ ගොනු පිටපත් කිරීමට උත්සාහ කළ හැක"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"ඔබට ඔබේ ගොනු නැවත ගෙන යාමට උත්සාහ කළ හැක"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"තවමත් ගොනු පිටපත් කරමින්"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"තවමත් ගොනු ගෙන යමින්"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"මෙය නිම කළ පසු ඔබට තවත් ගොනු පිටපත් කිරීමට හෝ ගෙන යාමට හැක"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ගොනු පිටපත් කළ නොහැකි විය"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ගොනු ගෙන යාමට නොහැකි විය"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"මුළු ගොනු ප්‍රමාණය ඉතා විශාලයි"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ඔබට එකවර 2 GB දක්වා පමණක් පිටපත් කිරීමට හෝ ගෙන යාමට හැක"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"ගොනු බොහෝමයක් තේරිණි"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ඔබට එකවර ගොනු 100ක් දක්වා පිටපත් කිරීමට හෝ ගෙන යාමට පමණක් හැක"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ගොනු එක් කළ නොහැක"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"ඔබට ප්‍රමාණවත් උපාංග ගබඩාවක් නොමැත"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"හරි"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"ඉඩ නිදහස් කර ගන්න"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"රහසිගත අවකාශය වෙතින් ගොනු පිටපත් කිරීමට හෝ ගෙන යාමට නොහැක"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"සමහර ගොනු පිටපත් කිරීමට නොහැකි විය"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"සමහර ගොනු ගෙන යාමට නොහැකි විය"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"පිටපත් කරන අතරේ ඔබේ පෞද්ගලික ඉඩ වසා දමන ලදි"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"ගෙන යන අතරේ ඔබේ පෞද්ගලික ඉඩ වසා දමන ලදි"</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 3fe7fc0..8dfe3cb 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Presunúť"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Skopírovať"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Zrušiť"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopírujú sa súbory (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Presúvajú sa súbory (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Boli skopírované súbory (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Boli presunuté súbory (<xliff:g id="FILES">%1$d</xliff:g>)"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Vybrané súbory sa kopírujú do vášho súkromného priestoru"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Vybrané súbory sa presúvajú do vášho súkromného priestoru"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Vybrané súbory boli skopírované do vášho súkromného priestoru"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Vybrané súbory boli presunuté do vášho súkromného priestoru"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopíruje sa # súbor}few{Kopírujú sa # súbory}many{Copying # files}other{Kopíruje sa # súborov}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Presúva sa # súbor}few{Presúvajú sa # súbory}many{Moving # files}other{Presúva sa # súborov}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Bol skopírovaný # súbor}few{Boli skopírované # súbory}many{# files copied}other{Bolo skopírovaných # súborov}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Bol presunutý # súbor}few{Boli presunuté # súbory}many{# files moved}other{Bolo presunutých # súborov}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Vybraný súbor sa kopíruje do vášho súkromného priestoru}few{Vybrané súbory sa kopírujú do vášho súkromného priestoru}many{Vybrané súbory sa kopírujú do vášho súkromného priestoru}other{Vybrané súbory sa kopírujú do vášho súkromného priestoru}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Vybraný súbor sa presúva do vášho súkromného priestoru}few{Vybrané súbory sa presúvajú do vášho súkromného priestoru}many{Vybrané súbory sa presúvajú do vášho súkromného priestoru}other{Vybrané súbory sa presúvajú do vášho súkromného priestoru}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Vybraný súbor bol skopírovaný do vášho súkromného priestoru}few{Vybrané súbory boli skopírované do vášho súkromného priestoru}many{Vybrané súbory boli skopírované do vášho súkromného priestoru}other{Vybrané súbory boli skopírované do vášho súkromného priestoru}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Vybraný súbor bol presunutý do vášho súkromného priestoru}few{Vybrané súbory boli presunuté do vášho súkromného priestoru}many{Vybrané súbory boli presunuté do vášho súkromného priestoru}other{Vybrané súbory boli presunuté do vášho súkromného priestoru}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Zobraziť súbory"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Upozornenia na prenos súborov"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Keď kopírujete alebo presúvate súbory do svojho súkromného priestoru, môžete dostávať upozornenia s informáciami o priebehu"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Niektoré súbory sa nedajú skopírovať"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Niektoré súbory sa nedajú presunúť"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Súbory môžete skúsiť znova skopírovať"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Súbory môžete skúsiť znova presunúť"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Prebieha kopírovanie súborov"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Súbory sa stále presúvajú"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Ďalšie súbory môžete kopírovať alebo presúvať po dokončení"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Súbory sa nepodarilo skopírovať"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Súbory sa nepodarilo presunúť"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Súbory sú spolu príliš veľké"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Naraz môžete skopírovať alebo presunúť maximálne 2 GB"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Príliš veľa vybraných súborov"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Naraz môžete skopírovať alebo presunúť maximálne 100 súborov"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Súbory sa nedajú pridať"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"V zariadení nemáte dostatok priestoru"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Uvoľniť priestor"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Súbory zo súkromného priestoru sa nedajú kopírovať ani presúvať"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Niektoré súbory sa nepodarilo skopírovať"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Niektoré súbory sa nepodarilo presunúť"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Váš súkromný priestor bol počas kopírovania zavretý"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Váš súkromný priestor bol počas presunu zavretý"</string>
 </resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 30bc738..9c0d36f 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Premakni"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiraj"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Prekliči"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopiranje toliko datotek: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Premikanje toliko datotek: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Št. kopiranih datotek: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Št. premaknjenih datotek: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Poteka kopiranje izbranih datotek v zasebni prostor"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Poteka premikanje izbranih datotek v zasebni prostor"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Izbrane datoteke so bile kopirane v zasebni prostor"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Izbrane datoteke so bile premaknjene v zasebni prostor"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kopiranje # datoteke}one{Kopiranje # datoteke}two{Kopiranje # datotek}few{Kopiranje # datotek}other{Kopiranje # datotek}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Premikanje # datoteke}one{Premikanje # datoteke}two{Premikanje # datotek}few{Premikanje # datotek}other{Premikanje # datotek}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# datoteka je bila kopirana}one{# datoteka je bila kopirana}two{# datoteki sta bili kopirani}few{# datoteke so bile kopirane}other{# datotek je bilo kopiranih}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# datoteka je bila premaknjena}one{# datoteka je bila premaknjena}two{# datoteki sta bili premaknjeni}few{# datoteke so bile premaknjene}other{# datotek je bilo premaknjenih}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Poteka kopiranje izbrane datoteke v zasebni prostor}one{Poteka kopiranje izbranih datotek v zasebni prostor}two{Poteka kopiranje izbranih datotek v zasebni prostor}few{Poteka kopiranje izbranih datotek v zasebni prostor}other{Poteka kopiranje izbranih datotek v zasebni prostor}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Poteka premikanje izbrane datoteke v zasebni prostor}one{Poteka premikanje izbranih datotek v zasebni prostor}two{Poteka premikanje izbranih datotek v zasebni prostor}few{Poteka premikanje izbranih datotek v zasebni prostor}other{Poteka premikanje izbranih datotek v zasebni prostor}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Izbrana datoteka je bila kopirana v zasebni prostor}one{Izbrane datoteke so bile kopirane v zasebni prostor}two{Izbrane datoteke so bile kopirane v zasebni prostor}few{Izbrane datoteke so bile kopirane v zasebni prostor}other{Izbrane datoteke so bile kopirane v zasebni prostor}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Izbrana datoteka je bila premaknjena v zasebni prostor}one{Izbrane datoteke so bile premaknjene v zasebni prostor}two{Izbrane datoteke so bile premaknjene v zasebni prostor}few{Izbrane datoteke so bile premaknjene v zasebni prostor}other{Izbrane datoteke so bile premaknjene v zasebni prostor}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Pokaži datoteke"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Obvestila o prenosu datotek"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Ko kopirate ali premaknete datoteke v zasebni prostor, lahko prejmete obvestila o napredku"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Nekaterih datotek ni mogoče kopirati"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Nekaterih datotek ni mogoče premakniti"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Znova lahko poskusite kopirati datoteke"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Znova lahko poskusite premakniti datoteke"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Kopiranje datotek še vedno poteka"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Premikanje datotek še vedno poteka"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Ko bo to končano, boste lahko kopirali ali premaknili še več datotek"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Datotek ni bilo mogoče kopirati"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Datotek ni bilo mogoče premakniti"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Skupna velikost datotek je prevelika"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Hkrati lahko kopirate ali premaknete največ 2 GB"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Izbranih je preveč datotek"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Hkrati lahko kopirate ali premaknete največ 100 datotek"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Datotek ni mogoče dodati"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"V napravi ni dovolj prostora za shranjevanje"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"V redu"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Sprostite prostor"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Datotek ni mogoče kopirati ali premakniti iz zasebnega prostora"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Nekaterih datotek ni bilo mogoče kopirati"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Nekaterih datotek ni bilo mogoče premakniti"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Zasebni prostor je bil zaprt med kopiranjem"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Zasebni prostor je bil zaprt med premikanjem"</string>
 </resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 88c570f..bf7a542 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Zhvendos"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopjo"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Anulo"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Skedarët që po kopjohen: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Skedarët që po zhvendosen: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Skedarët e kopjuar: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Skedarët e zhvendosur: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Skedarët që ke zgjedhur po kopjohen te hapësira jote private"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Skedarët që ke zgjedhur po zhvendosen te hapësira jote private"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Skedarët që ke zgjedhur u kopjuan te hapësira jote private"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Skedarët që ke zgjedhur u zhvendosën te hapësira jote private"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Po kopjohet # skedar}other{Po kopjohen # skedarë}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Po zhvendoset # skedar}other{Po zhvendosen # skedarë}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# skedar u kopjua}other{# skedarë u kopjuan}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# skedar u zhvendos}other{# skedarë u zhvendosën}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Skedari që ke zgjedhur po kopjohet te hapësira jote private}other{Skedarët që ke zgjedhur po kopjohen te hapësira jote private}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Skedari që ke zgjedhur po zhvendoset te hapësira jote private}other{Skedarët që ke zgjedhur po zhvendosen te hapësira jote private}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Skedari që ke zgjedhur u kopjua te hapësira jote private}other{Skedarët që ke zgjedhur u kopjuan te hapësira jote private}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Skedari që ke zgjedhur u zhvendos te hapësira jote private}other{Skedarët që ke zgjedhur u zhvendosën te hapësira jote private}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Shfaq skedarët"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Njoftimet për transferimin e skedarëve"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kur kopjon ose zhvendos skedarët te hapësira jote private, mund të marrësh njoftime për të të përditësuar për progresin"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Disa skedarë nuk mund të kopjoheshin"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Disa skedarë nuk mund të zhvendoseshin"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Mund të provosh t\'i kopjosh përsëri skedarët e tu"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Mund të provosh t\'i zhvendosësh përsëri skedarët e tu"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Skedarët po kopjohen akoma"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Skedarët po zhvendosen akoma"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Mund të kopjosh ose të zhvendosësh më shumë skedarë kur të përfundojë kjo"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Skedarët nuk mund të kopjoheshin"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Skedarët nuk mund të zhvendoseshin"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Madhësia totale e skedarëve është shumë e madhe"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Mund të kopjosh ose të zhvendosësh deri në 2 GB njëkohësisht"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Janë zgjedhur shumë skedarë"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Mund të kopjosh ose të zhvendosësh deri në 100 skedarë njëkohësisht"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Skedarët nuk mund të shtohen"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Nuk ke hapësirë ruajtëse të mjaftueshme të pajisjes"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Në rregull"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Liro hapësirë"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Skedarët nuk mund të kopjohen ose të zhvendosen nga \"Hapësira private\""</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Disa skedarë nuk mund të kopjoheshin"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Disa skedarë nuk mund të zhvendoseshin"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Hapësira jote private u mbyll gjatë kopjimit"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Hapësira jote private u mbyll gjatë zhvendosjes"</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 7b6df3f..bd03ae3 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -17,22 +17,44 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="private_space_app_label" msgid="4816454052314284927">"Приватан простор"</string>
-    <string name="shortcut_label_add_files" msgid="5537029952988156354">"Додајте фајлове"</string>
-    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Инсталирајте апликације"</string>
+    <string name="shortcut_label_add_files" msgid="5537029952988156354">"Додај фајлове"</string>
+    <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"Инсталирај апликације"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"Желите да преместите или копирате фајлове?"</string>
     <string name="move_files_dialog_summary" msgid="5669539681627056766">"Ако преместите ове фајлове у приватан простор, уклонићете их из првобитних фолдера"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Премести"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Копирај"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Откажи"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Копирају се фајлови: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Премештају се фајлови: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Копирано фајлова: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Премештени фајлови: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Одабрани фајлови се копирају у приватан простор"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Одабрани фајлови се премештају у приватан простор"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Изабрани фајлови су копирани у приватан простор"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Изабрани фајлови су премештени у приватан простор"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Копира се # фајл}one{Копира се # фајл}few{Копирају се # фајла}other{Копира се # фајлова}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Премешта се # фајл}one{Премешта се # фајл}few{Премештају се # фајла}other{Премешта се # фајлова}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# фајл је копиран}one{# фајл је копиран}few{# фајла су копирана}other{# фајлова је копирано}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# фајл је премештен}one{# фајл је премештен}few{# фајла су премештена}other{# фајлова је премештено}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Одабрани фајл се копира у приватан простор}one{Одабрани фајлови се копирају у приватан простор}few{Одабрани фајлови се копирају у приватан простор}other{Одабрани фајлови се копирају у приватан простор}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Одабрани фајл се премешта у приватан простор}one{Одабрани фајлови се премештају у приватан простор}few{Одабрани фајлови се премештају у приватан простор}other{Одабрани фајлови се премештају у приватан простор}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Одабрани фајл је копиран у приватан простор}one{Одабрани фајлови су копирани у приватан простор}few{Одабрани фајлови су копирани у приватан простор}other{Одабрани фајлови су копирани у приватан простор}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Одабрани фајл је премештен у приватан простор}one{Одабрани фајлови су премештени у приватан простор}few{Одабрани фајлови су премештени у приватан простор}other{Одабрани фајлови су премештени у приватан простор}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Прикажи фајлове"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Обавештења о преносу фајлова"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Када копирате или премештате фајлове у приватан простор, можете да добијате обавештења о напретку"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Копирање неких фајлова није успело"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Премештање неких фајлова није успело"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Можете поново да пробате да копирате фајлове"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Можете поново да пробате да преместите фајлове"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Фајлови се и даље копирају"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Фајлови се и даље премештају"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Када се то заврши, можете да копирате или преместите још фајлова"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Копирање фајлова није успело"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Премештање фајлова није успело"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Укупна величина фајлова је превелика"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Можете да копирате или преместите највише 2 GB одједном"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Изабрано је превише фајлова"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Можете да копирате или преместите највише 100 фајлова одједном"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Додавање фајлова није успело"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Немате довољно меморијског простора уређаја"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Потврди"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Ослободите простор"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Не можете да копирате ни премештате фајлове из приватног простора"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Копирање неких фајлова није успело"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Премештање неких фајлова није успело"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Приватан простор је био затворен током копирања"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Приватан простор је био затворен током премештања"</string>
 </resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 74a6421..6e0f623 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Flytta"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopiera"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Avbryt"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kopierar <xliff:g id="FILES">%1$d</xliff:g> filer"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Flyttar <xliff:g id="FILES">%1$d</xliff:g> filer"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> filer har kopierats"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> filer har flyttats"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"De valda filerna kopieras till ditt privata utrymme"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"De valda filerna flyttas till ditt privata utrymme"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"De valda filerna har kopierats till ditt privata utrymme"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"De valda filerna har flyttats till ditt privata utrymme"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# fil kopieras}other{# filer kopieras}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# fil flyttas}other{# filer flyttas}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# fil har kopierats}other{# filer har kopierats}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# fil har flyttats}other{# filer har flyttats}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Den valda filen kopieras till ditt privata utrymme}other{De valda filerna kopieras till ditt privata utrymme}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Den valda filen flyttas till ditt privata utrymme}other{De valda filerna flyttas till ditt privata utrymme}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Den valda filen har kopierats till ditt privata utrymme}other{De valda filerna har kopierats till ditt privata utrymme}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Den valda filen har flyttats till ditt privata utrymme}other{De valda filerna har flyttats till ditt privata utrymme}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Visa filer"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Aviseringar om filöverföring"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"När du kopierar eller flyttar filer till ditt privata utrymme kan du få aviseringar om förloppet"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Det går inte att kopiera vissa filer"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Det går inte att flytta vissa filer"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Du kan testa att kopiera filerna igen"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Du kan testa att flytta filerna igen"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Kopierar fortfarande filer"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Flyttar fortfarande filer"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Du kan kopiera eller flytta fler filer när detta är klart"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Det gick inte att kopiera filerna"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Det gick inte att flytta filerna"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Den totala filstorleken är för stor"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Du kan bara kopiera eller flytta upp till 2 GB åt gången"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"För många filer valda"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Du kan bara kopiera eller flytta upp till 100 filer åt gången"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Det går inte att lägga till filer"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Det finns inte tillräckligt med lagringsutrymme på enheten"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Frigör utrymme"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Det går inte att kopiera eller flytta filer från det privata utrymmet"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Det gick inte att kopiera vissa filer"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Det gick inte att flytta vissa filer"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Ditt privata utrymme stängdes medan filerna kopierades"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Ditt privata utrymme stängdes medan filerna flyttades"</string>
 </resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 30eb806..4695439 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Hamisha"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Nakili"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Acha"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Inanakili faili <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Inahamisha faili <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Imenakili faili <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Faili <xliff:g id="FILES">%1$d</xliff:g> zimehamishwa"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Faili ulizochagua zinanakiliwa kwenye sehemu yako ya faragha"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Faili ulizochagua zinahamishiwa kwenye nafasi yako ya faragha"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Faili ulizochagua zimenakiliwa kwenye sehemu yako ya faragha"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Faili ulizochagua zimehamishiwa kwenye sehemu yako ya faragha"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Inanakili faili #}other{Inanakili faili #}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Inahamisha faili #}other{Inahamisha faili #}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Imenakili faili #}other{Imenakili faili #}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Imehamisha faili #}other{Imehamisha faili #}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Inanakili faili uliyochagua kwenye sehemu yako ya faragha}other{Inanakili faili ulizochagua kwenye sehemu yako ya faragha}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Inahamishia faili uliyochagua kwenye sehemu yako ya faragha}other{Inahamishia faili ulizochagua kwenye nafasi yako ya faragha}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Imenakili faili uliyochagua kwenye sehemu yako ya faragha}other{Imenakili faili ulizochagua kwenye sehemu yako ya faragha}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Imehamishia faili uliyochagua kwenye sehemu yako ya faragha}other{Imehamishia faili ulizochagua kwenye sehemu yako ya faragha}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Onyesha faili"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Arifa kuhusu mchakato wa kuhamisha faili"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Unaweza kupokea arifa za kukuarifu kuhusu maendeleo unaponakili au kuhamisha faili kwenye sehemu yako ya faragha"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Imeshindwa kunakili baadhi ya faili"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Imeshindwa kuhamisha baadhi ya faili"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Unaweza kujaribu kunakili faili zako tena"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Unaweza kujaribu kuhamisha faili zako tena"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Bado inanakili faili"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Bado inahamisha faili"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Unaweza kunakili au kuhamisha faili zaidi baada ya kukamilisha hii"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Imeshindwa kunakili faili"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Imeshindwa kuhamisha faili"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Faili ni kubwa mno"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Unaweza tu kuhamisha au kunakili faili zenye ukubwa wa hadi GB 2 kwa wakati moja"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Umechagua faili nyingi mno"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Unaweza tu kuhamisha au kunakili hadi faili 100 kwa wakati moja"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Imeshindwa kuweka faili"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Kifaa chako hakina nafasi ya hifadhi ya kutosha"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Sawa"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Futa ili upate nafasi"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Huwezi kunakili au kusogeza faili kutoka Sehemu ya Faragha"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Imeshindwa kunakili baadhi ya faili"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Imeshindwa kuhamisha baadhi ya faili"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Sehemu yako ya faragha ilifungwa wakati unanakili"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Sehemu yako ya faragha ilifungwa wakati unahamisha"</string>
 </resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index bc5f06c..fe302e6 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"நகர்த்து"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"நகலெடு"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ரத்துசெய்"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ஃபைல்கள் நகலெடுக்கப்படுகின்றன"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ஃபைல்கள் நகர்த்தப்படுகின்றன"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ஃபைல்கள் நகலெடுக்கப்பட்டன"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ஃபைல்கள் நகர்த்தப்பட்டன"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகலெடுக்கப்படுகின்றன"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகர்த்தப்படுகின்றன"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகலெடுக்கப்பட்டன"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகர்த்தப்பட்டன"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ஃபைலை நகலெடுக்கிறது}other{# ஃபைல்களை நகலெடுக்கிறது}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ஃபைலை நகர்த்துகிறது}other{# ஃபைல்களை நகர்த்துகிறது}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ஃபைல் நகலெடுக்கப்பட்டது}other{# ஃபைல்கள் நகலெடுக்கப்பட்டன}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ஃபைல் நகர்த்தப்பட்டது}other{# ஃபைல்கள் நகர்த்தப்பட்டன}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{நீங்கள் தேர்வுசெய்த ஃபைல் உங்கள் ரகசிய இடத்திற்கு நகலெடுக்கப்படுகிறது}other{நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகலெடுக்கப்படுகின்றன}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{நீங்கள் தேர்வுசெய்த ஃபைல் உங்கள் ரகசிய இடத்திற்கு நகர்த்தப்படுகிறது}other{நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகர்த்தப்படுகின்றன}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{நீங்கள் தேர்வுசெய்த ஃபைல் உங்கள் ரகசிய இடத்திற்கு நகலெடுக்கப்பட்டது}other{நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகலெடுக்கப்பட்டன}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{நீங்கள் தேர்வுசெய்த ஃபைல் உங்கள் ரகசிய இடத்திற்கு நகர்த்தப்பட்டது}other{நீங்கள் தேர்வுசெய்த ஃபைல்கள் உங்கள் ரகசிய இடத்திற்கு நகர்த்தப்பட்டன}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ஃபைல்களைக் காட்டு"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ஃபைல் பரிமாற்ற அறிவிப்புகள்"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"ரகசிய இடத்திற்கு ஃபைல்களை நகலெடுக்கும்போது அல்லது நகர்த்தும்போது, செயல்நிலை குறித்து உங்களுக்குத் தெரிவிக்க அறிவிப்புகளைப் பெறலாம்"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"சில ஃபைல்களை நகலெடுக்க முடியவில்லை"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"சில ஃபைல்களை நகர்த்த முடியவில்லை"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"உங்கள் ஃபைல்களை மீண்டும் நகலெடுத்துப் பாருங்கள்"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"உங்கள் ஃபைல்களை மீண்டும் நகர்த்திப் பாருங்கள்"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"இன்னமும் ஃபைல்களைப் நகலெடுக்கிறது"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"இன்னமும் ஃபைல்களை நகர்த்துகிறது"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"இது முடிந்ததும் அதிகமான ஃபைல்களை நகலெடுக்கலாம்/நகர்த்தலாம்"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ஃபைல்களை நகலெடுக்க முடியவில்லை"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ஃபைல்களை நகர்த்த முடியவில்லை"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"மொத்த ஃபைல் அளவு மிகவும் அதிகமாக உள்ளது"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ஒரே நேரத்தில் 2 GB வரை மட்டுமே உங்களால் நகலெடுக்கவோ நகர்த்தவோ முடியும்"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"நிறைய ஃபைல்கள் தேர்ந்தெடுக்கப்பட்டுள்ளன"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ஒரே நேரத்தில் 100 ஃபைல்கள் வரை மட்டுமே உங்களால் நகலெடுக்கவோ நகர்த்தவோ முடியும்"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ஃபைல்களைச் சேர்க்க முடியவில்லை"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"உங்களிடம் போதுமான சாதனச் சேமிப்பகம் இல்லை"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"சரி"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"இடத்தைக் காலியாக்குங்கள்"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ரகசிய இடத்தில் இருந்து ஃபைல்களை நகலெடுக்கவோ நகர்த்தவோ முடியாது"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"சில ஃபைல்களை நகலெடுக்க முடியவில்லை"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"சில ஃபைல்களை நகர்த்த முடியவில்லை"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"நகலெடுக்கும்போது ரகசிய இடம் மூடியிருந்தது"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"நகர்த்தும்போது ரகசிய இடம் மூடியிருந்தது"</string>
 </resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 712183c..53afd7e 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"తరలించండి"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"కాపీ చేయండి"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"రద్దు చేయండి"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ఫైల్(ల)ను కాపీ చేస్తోంది"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ఫైల్(ల)ను తరలిస్తోంది"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ఫైల్(లు) కాపీ అయ్యాయి"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ఫైల్(లు) తరలించబడ్డాయి"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"మీరు ఎంచుకున్న ఫైల్‌లు మీ ప్రైవేట్ స్పేస్‌కు కాపీ అయ్యాయి"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"మీరు ఎంచుకున్న ఫైల్స్‌ను మీ ప్రైవేట్ స్పేస్‌కు తరలించారు"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"మీరు ఎంచుకున్న ఫైల్స్ మీ ప్రైవేట్ స్పేస్‌కు కాపీ అయ్యాయి"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"మీరు ఎంచుకున్న ఫైల్స్‌ను మీ ప్రైవేట్ స్పేస్‌కు తరలించారు"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ఫైల్ కాపీ అవుతోంది}other{# ఫైల్స్ కాపీ అవుతున్నాయి}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ఫైల్‌ను తరలిస్తున్నారు}other{# ఫైల్స్‌ను తరలిస్తున్నారు}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ఫైల్ కాపీ అయింది}other{# ఫైల్స్ కాపీ అయ్యాయి}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ఫైల్‌ను తరలించారు}other{# ఫైల్స్‌ను తరలించారు}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{మీరు ఎంచుకున్న ఫైల్, మీ ప్రైవేట్ స్పేస్‌కు కాపీ అవుతోంది}other{మీరు ఎంచుకున్న ఫైల్స్, మీ ప్రైవేట్ స్పేస్‌కు కాపీ అవుతున్నాయి}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{మీరు ఎంచుకున్న ఫైల్‌ను, మీ ప్రైవేట్ స్పేస్‌కు తరలిస్తున్నారు}other{మీరు ఎంచుకున్న ఫైల్స్‌ను, మీ ప్రైవేట్ స్పేస్‌కు తరలిస్తున్నారు}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{మీరు ఎంచుకున్న ఫైల్ మీ ప్రైవేట్ స్పేస్‌కు కాపీ అయింది}other{మీరు ఎంచుకున్న ఫైల్స్ మీ ప్రైవేట్ స్పేస్‌కు కాపీ అయ్యాయి}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{మీరు ఎంచుకున్న ఫైల్‌ను, మీ ప్రైవేట్ స్పేస్‌కు తరలించారు}other{మీరు ఎంచుకున్న ఫైల్స్‌ను, మీ ప్రైవేట్ స్పేస్‌కు తరలించారు}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"ఫైళ్లను చూపండి"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"ఫైల్ బదిలీ నోటిఫికేషన్‌లు"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"మీరు ఫైళ్లను మీ ప్రైవేట్ స్పేస్‌కు తరలించినప్పుడు, ప్రోగ్రెస్ గురించి మీకు అప్‌డేట్ చేయడానికి మీరు నోటిఫికేషన్‌లను పొందవచ్చు"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"కొన్ని ఫైల్స్‌ను కాపీ చేయడం సాధ్యం కాదు"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"కొన్ని ఫైల్స్‌ను తరలించడం సాధ్యం కాదు"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"మీ ఫైల్స్‌ను కాపీ చేయడానికి మీరు మళ్లీ ట్రై చేయవచ్చు"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"మీ ఫైల్స్‌ను తరలించడానికి మీరు మళ్లీ ట్రై చేయవచ్చు"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"ఫైల్స్ ఇంకా కాపీ అవుతున్నాయి"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"ఫైల్స్ ఇంకా తరలించబడుతున్నాయి"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"ఇది పూర్తయిన తర్వాత మీరు మరిన్ని ఫైల్స్‌ను కాపీ చేయవచ్చు లేదా తరలించవచ్చు"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"ఫైల్స్‌ను కాపీ చేయడం సాధ్యం కాలేదు"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ఫైల్స్‌ను తరలించడం సాధ్యం కాలేదు"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"మొత్తం ఫైల్ సైజ్ మరీ పెద్దగా ఉంది"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"ఒకేసారి మీరు గరిష్ఠంగా 2 GBని మాత్రమే కాపీ చేయగలరు"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"చాలా ఫైల్స్‌ను ఎంచుకున్నారు"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"ఒకేసారి మీరు గరిష్ఠంగా 100 ఫైల్స్‌ను మాత్రమే కాపీ చేయగలరు లేదా తరలించగలరు"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"ఫైల్స్‌ను జోడించడం సాధ్యం కాదు"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"మీ వద్ద తగినంత పరికర స్టోరేజీ లేదు"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"సరే"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"స్పేస్‌ను ఖాళీ చేయండి"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"ప్రైవేట్ స్పేస్ నుండి ఫైళ్లను కాపీ చేయడం లేదా తరలించడం సాధ్యం కాదు"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"కొన్ని ఫైళ్లను కాపీ చేయడం సాధ్యపడలేదు"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"కొన్ని ఫైళ్లను తరలించడం సాధ్యపడలేదు"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"కాపీ చేస్తున్నప్పుడు మీ ప్రైవేట్ స్పేస్ మూసివేయబడింది"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"తరలిస్తున్నప్పుడు మీ ప్రైవేట్ స్పేస్ మూసివేయబడింది"</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index a1dc858..9522045 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"ย้าย"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"คัดลอก"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"ยกเลิก"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"กำลังคัดลอก <xliff:g id="FILES">%1$d</xliff:g> ไฟล์"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"กำลังย้าย <xliff:g id="FILES">%1$d</xliff:g> ไฟล์"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"คัดลอกแล้ว <xliff:g id="FILES">%1$d</xliff:g> ไฟล์"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"ย้ายแล้ว <xliff:g id="FILES">%1$d</xliff:g> ไฟล์"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"กำลังคัดลอกไฟล์ที่เลือกไปยังพื้นที่ส่วนตัว"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"กำลังย้ายไฟล์ที่เลือกไปยังพื้นที่ส่วนตัว"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"คัดลอกไฟล์ที่เลือกไปยังพื้นที่ส่วนตัวแล้ว"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"ย้ายไฟล์ที่เลือกไปยังพื้นที่ส่วนตัวแล้ว"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{กำลังคัดลอกไฟล์ # ไฟล์}other{กำลังคัดลอกไฟล์ # ไฟล์}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{กำลังย้าย # ไฟล์}other{กำลังย้าย # ไฟล์}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{คัดลอกแล้ว # ไฟล์}other{คัดลอกแล้ว # ไฟล์}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{ย้ายแล้ว # ไฟล์}other{ย้ายแล้ว # ไฟล์}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{กำลังคัดลอกไฟล์ที่เลือกไปยังพื้นที่ส่วนตัว}other{กำลังคัดลอกไฟล์ที่เลือกไปยังพื้นที่ส่วนตัว}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{กำลังย้ายไฟล์ที่เลือกไปยังพื้นที่ส่วนตัว}other{กำลังย้ายไฟล์ที่เลือกไปยังพื้นที่ส่วนตัว}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{คัดลอกไฟล์ที่เลือกไปยังพื้นที่ส่วนตัวแล้ว}other{คัดลอกไฟล์ที่เลือกไปยังพื้นที่ส่วนตัวแล้ว}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{ย้ายไฟล์ที่เลือกไปยังพื้นที่ส่วนตัวแล้ว}other{ย้ายไฟล์ที่เลือกไปยังพื้นที่ส่วนตัวแล้ว}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"แสดงไฟล์"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"การแจ้งเตือนการโอนไฟล์"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"เมื่อคัดลอกหรือย้ายไฟล์ไปยังพื้นที่ส่วนตัว คุณจะได้รับการแจ้งเตือนเพื่ออัปเดตความคืบหน้า"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"คัดลอกบางไฟล์ไม่ได้"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"ย้ายบางไฟล์ไม่ได้"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"คุณลองคัดลอกไฟล์อีกครั้งได้"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"คุณลองย้ายไฟล์อีกครั้งได้"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"กำลังคัดลอกไฟล์"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"กำลังย้ายไฟล์"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"คุณคัดลอกหรือย้ายไฟล์เพิ่มเติมได้เมื่อการดำเนินการนี้เสร็จสิ้น"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"คัดลอกไฟล์ไม่ได้"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"ย้ายไฟล์ไม่ได้"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"ขนาดไฟล์รวมใหญ่เกินไป"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"คุณคัดลอกหรือย้ายได้ครั้งละไม่เกิน 2 GB เท่านั้น"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"เลือกไฟล์มากเกินไป"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"คุณคัดลอกหรือย้ายได้ครั้งละไม่เกิน 100 ไฟล์"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"เพิ่มไฟล์ไม่ได้"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"คุณมีพื้นที่เก็บข้อมูลของอุปกรณ์ไม่เพียงพอ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ตกลง"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"เพิ่มพื้นที่ว่าง"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"คัดลอกหรือย้ายไฟล์จากพื้นที่ส่วนตัวไม่ได้"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"คัดลอกบางไฟล์ไม่ได้"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"ย้ายบางไฟล์ไม่ได้"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"พื้นที่ส่วนตัวของคุณจะปิดขณะที่คัดลอก"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"พื้นที่ส่วนตัวของคุณจะปิดขณะที่ย้าย"</string>
 </resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index f2e233a..a400183 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Ilipat"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopyahin"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Kanselahin"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Kinokopya ang <xliff:g id="FILES">%1$d</xliff:g> (na) file"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Inililipat ang <xliff:g id="FILES">%1$d</xliff:g> (na) file"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> (na) file ang nakopya"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Inilipat ang <xliff:g id="FILES">%1$d</xliff:g> (na) file"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Kinokopya sa iyong pribadong space ang iyong mga napiling file"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Inililipat sa iyong pribadong space ang iyong mga napiling file"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Nakopya sa iyong pribadong space ang iyong mga napiling file"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Inilipat sa iyong pribadong space ang iyong mga napiling file"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Kinokopya ang # file}one{Kinokopya ang # file}other{Kinokopya ang # na file}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Inililipat ang # file}one{Inililipat ang # file}other{Inililipat ang # na file}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{May # file na nakopya}one{May # file na nakopya}other{May # na file na nakopya}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{May # file na nailipat}one{May # file na nailipat}other{May # na file na nailipat}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Kinokopya sa iyong pribadong space ang napili mong file}one{Kinokopya sa iyong pribadong space ang mga napili mong file}other{Kinokopya sa iyong pribadong space ang mga napili mong file}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Inililipat sa iyong pribadong space ang napili mong file}one{Inililipat sa iyong pribadong space ang mga napili mong file}other{Inililipat sa iyong pribadong space ang mga napili mong file}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Nakopya sa iyong pribadong space ang napili mong file}one{Nakopya sa iyong pribadong space ang mga napili mong file}other{Nakopya sa iyong pribadong space ang mga napili mong file}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Nailipat sa iyong pribadong space ang napili mong file}one{Nailipat sa iyong pribadong space ang mga napili mong file}other{Nailipat sa iyong pribadong space ang mga napili mong file}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Ipakita ang mga file"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Mga notification sa paglilipat ng file"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Kapag kumopya o naglipat ka ng mga file sa iyong pribadong space, puwede kang makatanggap ng mga notification para i-update ka sa pag-usad"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Hindi makopya ang ilang file"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Hindi mailipat ang ilang file"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Puwede mong subukang kopyahin ulit ang iyong mga file"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Puwede mong subukang ilipat ulit ang iyong mga file"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Kumukopya pa ng mga file"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Naglilipat pa ng mga file"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Puwede kang kumopya o maglipat ng higit pang file kapag tapos na ito"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Hindi makopya ang mga file"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Hindi mailipat ang mga file"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Masyadong malaki ang kabuuang laki ng file"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Puwede ka lang kumopya o maglipat ng hanggang 2 GB nang sabay-sabay"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Napakaraming file ang napili"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Puwede ka lang kumopya o maglipat ng hanggang 100 file nang sabay-sabay"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Hindi makapagdagdag ng mga file"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Wala kang sapat na storage ng device"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Magbakante ng espasyo"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Hindi makopya o mailipat ang mga file mula sa Pibadong Space"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"May ilang file na hindi nakopya"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"May ilang file na hindi nailipat"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Isinara ang iyong pribadong space habang kumukopya"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Isinara ang iyong pribadong space habang naglilipat"</string>
 </resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index a1f92e8..2dac82d 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Taşı"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopyala"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"İptal"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> dosya kopyalanıyor"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> dosya taşınıyor"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> dosya kopyalandı"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> dosya taşındı"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Seçtiğiniz dosyalar özel alanınıza kopyalanıyor"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Seçtiğiniz dosyalar özel alanınıza taşınıyor"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Seçtiğiniz dosyalar özel alanınıza kopyalandı"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Seçtiğiniz dosyalar özel alanınıza taşındı"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# dosya kopyalanıyor…}other{# dosya kopyalanıyor}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# dosya taşınıyor}other{# dosya taşınıyor}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# dosya kopyalandı}other{# dosya kopyalandı}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# dosya taşındı}other{# dosya taşındı}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Seçtiğiniz dosya özel alanınıza kopyalanıyor}other{Seçtiğiniz dosyalar özel alanınıza kopyalanıyor}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Seçtiğiniz dosya özel alanınıza taşınıyor}other{Seçtiğiniz dosyalar özel alanınıza taşınıyor}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Seçtiğiniz dosya özel alanınıza kopyalandı}other{Seçtiğiniz dosyalar özel alanınıza kopyalandı}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Seçtiğiniz dosya özel alanınıza taşındı}other{Seçtiğiniz dosyalar özel alanınıza taşındı}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Dosyaları göster"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Dosya aktarımı bildirimleri"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Dosyaları özel alanınıza kopyaladığınızda veya taşıdığınızda ilerleme durumuyla ilgili güncelleme bildirimleri alabilirsiniz"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Bazı dosyalar kopyalanamıyor"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Bazı dosyalar taşınamıyor"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Dosyalarınızı tekrar kopyalamayı deneyebilirsiniz"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Dosyalarınızı tekrar taşımayı deneyebilirsiniz"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Dosya kopyalama işlemi devam ediyor"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Dosya taşıma işlemi devam ediyor"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Bu işlem tamamlandıktan sonra daha fazla dosya kopyalayabilir veya taşıyabilirsiniz"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Dosyalar kopyalanamadı"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Dosyalar taşınamadı"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Toplam dosya boyutu çok büyük"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Tek seferde en fazla 2 GB kopyalayabilir veya taşıyabilirsiniz"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Çok fazla dosya seçildi"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Tek seferde en fazla 100 dosya kopyalayabilir veya taşıyabilirsiniz"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Dosya eklenemiyor"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Cihazınızda yeterli depolama alanı yok"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"Tamam"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Yer açın"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Özel alandaki dosyalar kopyalanamıyor veya taşınamıyor"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Bazı dosyalar kopyalanamadı"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Bazı dosyalar taşınamadı"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Kopyalama işlemi sırasında özel alanınız kapatıldı"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Taşıma işlemi sırasında özel alanınız kapatıldı"</string>
 </resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 755f57f..d7f601a 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Перемістити"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Копіювати"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Скасувати"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Копіювання файлів: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Перенесення файлів: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Скопійовано файлів: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Перенесено файлів: <xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Вибрані файли копіюються в приватний простір"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Вибрані файли переносяться в приватний простір"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Вибрані файли скопійовано в приватний простір"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Вибрані файли перенесено в приватний простір"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Копіювання # файлу}one{Копіювання # файлу}few{Копіювання # файлів}many{Копіювання # файлів}other{Копіювання # файлу}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Переміщення # файлу}one{Переміщення # файлу}few{Переміщення # файлів}many{Переміщення # файлів}other{Переміщення # файлу}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Скопійовано # файл}one{Скопійовано # файл}few{Скопійовано # файли}many{Скопійовано # файлів}other{Скопійовано # файлу}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Переміщено # файл}one{Переміщено # файл}few{Переміщено # файли}many{Переміщено # файлів}other{Переміщено # файлу}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Вибраний файл копіюється в приватний простір}one{Вибрані файли копіюються в приватний простір}few{Вибрані файли копіюються в приватний простір}many{Вибрані файли копіюються в приватний простір}other{Вибрані файли копіюються в приватний простір}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Вибраний файл переміщується в приватний простір}one{Вибрані файли переміщуються в приватний простір}few{Вибрані файли переміщуються в приватний простір}many{Вибрані файли переміщуються в приватний простір}other{Вибрані файли переміщуються в приватний простір}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Вибраний файл скопійовано в приватний простір}one{Вибрані файли скопійовано в приватний простір}few{Вибрані файли скопійовано в приватний простір}many{Вибрані файли скопійовано в приватний простір}other{Вибрані файли скопійовано в приватний простір}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Вибраний файл переміщено в приватний простір}one{Вибрані файли переміщено в приватний простір}few{Вибрані файли переміщено в приватний простір}many{Вибрані файли переміщено в приватний простір}other{Вибрані файли переміщено в приватний простір}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Показати файли"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Сповіщення про перенесення файлів"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Коли ви копіюєте або переміщуєте файли в приватний простір, то можете отримувати сповіщення про перебіг процесу"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Не вдалося скопіювати деякі файли"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Не вдалося перемістити деякі файли"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Ви можете спробувати скопіювати файли ще раз"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Ви можете спробувати перемістити файли ще раз"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Триває копіювання файлів"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Триває переміщення файлів"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Коли цей процес завершиться, ви зможете скопіювати або перемістити інші файли"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Не вдалося скопіювати файли"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Не вдалося перемістити файли"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Загальний розмір файлів завеликий"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Одночасно можна копіювати або переміщувати не більше ніж 2 ГБ даних"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Вибрано забагато файлів"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Одночасно можна скопіювати або перемістити не більше ніж 100 файлів"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Не вдалося додати файли"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"На пристрої недостатньо вільної пам’яті"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Звільнити місце"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Не можна скопіювати або перемістити файли з приватного простору"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Не вдалося скопіювати деякі файли"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Не вдалося перемістити деякі файли"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Ваш приватний простір було закрито під час копіювання"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Ваш приватний простір було закрито під час переміщення"</string>
 </resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 664f954..d1499fa 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"منتقل کریں"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"کاپی کریں"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"منسوخ کریں"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"‫<xliff:g id="FILES">%1$d</xliff:g> فائل (فائلز) کاپی ہو رہی ہے"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"‫<xliff:g id="FILES">%1$d</xliff:g> فائل (فائلز) منتقل ہو رہی ہے"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"‫<xliff:g id="FILES">%1$d</xliff:g> فائل (فائلز) کاپی کی گئی"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"‫<xliff:g id="FILES">%1$d</xliff:g> فائل (فائلز) منتقل کر دی گئی"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں کاپی کیا جا رہا ہے"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں منتقل کیا جا رہا ہے"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں کاپی کیا گیا تھا"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں منتقل کر دیا گیا تھا"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{‫# فائل کاپی ہو رہی ہے}other{‫# فائلز کاپی ہو رہی ہیں}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{‫# فائل منتقل ہو رہی ہے}other{‫# فائلز منتقل ہو رہی ہیں}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{‫# فائل کاپی ہو گئی}other{‫# فائلز کاپی ہو گئیں}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{‫# فائل منتقل ہو گئی}other{‫# فائلز منتقل ہو گئیں}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{آپ کی منتخب فائل کو آپ کی پرائیویٹ اسپیس میں کاپی کیا جا رہا ہے}other{آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں کاپی کیا جا رہا ہے}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{آپ کی منتخب فائل کو آپ کی پرائیویٹ اسپیس میں منتقل کیا جا رہا ہے}other{آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں منتقل کیا جا رہا ہے}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{آپ کی منتخب کردہ فائل کو آپ کی پرائیویٹ اسپیس میں کاپی کیا گیا}other{آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں کاپی کیا گیا تھا}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{آپ کی منتخب کردہ فائل کو آپ کی پرائیویٹ اسپیس میں منتقل کیا گیا}other{آپ کی منتخب فائلز کو آپ کی پرائیویٹ اسپیس میں منتقل کیا گیا}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"فائلیں دکھائیں"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"فائل منتقلی کی اطلاعات"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"جب آپ فائلوں کو اپنی پرائیویٹ اسپیس میں کاپی یا منتقل کرتے ہیں تو آپ کو پیش رفت کے بارے میں اپ ڈیٹ کرنے کے لیے اطلاعات موصول ہو سکتی ہیں"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"کچھ فائلز کو کاپی نہیں کیا جا سکتا"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"کچھ فائلز کو منتقل نہیں کیا جا سکتا"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"آپ اپنی فائلز کو دوبارہ کاپی کرنے کی کوشش کر سکتے ہیں"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"آپ اپنی فائلز کو دوبارہ منتقل کرنے کی کوشش کر سکتے ہیں"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"فائلز اب بھی کاپی ہو رہی ہیں"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"فائلز اب بھی منتقل ہو رہی ہیں"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"اس کے مکمل ہونے کے بعد آپ مزید فائلز کو کاپی یا منتقل کر سکتے ہیں"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"فائلز کو کاپی نہیں کیا جا سکا"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"فائلز کو منتقل نہیں کیا جا سکا"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"فائل کا کل سائز بہت بڑا ہے"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"‏‫آپ ایک بار میں صرف ‎2 GB تک کاپی یا منتقل کر سکتے ہیں"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"بہت زیادہ فائلز منتخب کی گئی ہیں"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"آپ ایک بار میں صرف 100 فائلز تک کاپی یا منتقل کر سکتے ہیں"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"فائلز کو شامل نہیں کیا جا سکتا"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"آپ کے پاس کافی آلے کی اسٹوریج نہیں ہے"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"ٹھیک ہے"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"جگہ خالی کریں"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"پرائیویٹ اسپیس سے فائلز کو کاپی یا منتقل نہیں کیا جا سکتا"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"کچھ فائلز کو کاپی نہیں کیا جا سکا"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"کچھ فائلز کو منتقل نہیں کیا جا سکا"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"کاپی کرتے وقت آپ کی پرائیویٹ اسپیس بند تھی"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"منتقل کرتے وقت آپ کی پرائیویٹ اسپیس بند تھی"</string>
 </resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index d7ada2b..06328a5 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Boshqa joyga olish"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Nusxalash"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Bekor qilish"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"<xliff:g id="FILES">%1$d</xliff:g> ta fayl nusxalanmoqda"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"<xliff:g id="FILES">%1$d</xliff:g> ta fayl boshqa joyga olinmoqda"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"<xliff:g id="FILES">%1$d</xliff:g> ta fayl nusxalandi"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"<xliff:g id="FILES">%1$d</xliff:g> ta fayl boshqa joyga olindi"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Tanlangan fayllar maxfiy makonga nusxalanmoqda"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Tanlangan fayllar maxfiy makonga olinmoqda"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Tanlangan fayllar maxfiy makonga nusxalandi"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Tanlangan fayllar maxfiy makonga olindi"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{# ta fayldan nusxa olinmoqda}other{# ta fayldan nusxa olinmoqda}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{# ta fayl koʻchirilmoqda}other{# ta fayl koʻchirilmoqda}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{# ta fayldan nusxa olindi}other{# ta fayldan nusxa olindi}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{# ta fayl koʻchirildi}other{# ta fayl koʻchirildi}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Tanlangan fayl maxfiy makonga nusxalanmoqda}other{Tanlangan fayllar maxfiy makonga nusxalanmoqda}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Tanlangan fayl maxfiy makonga koʻchirilmoqda}other{Tanlangan fayllar maxfiy makonga koʻchirilmoqda}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Tanlangan fayl maxfiy makoningizga nusxalandi}other{Tanlangan fayllar maxfiy makoningizga nusxalandi}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Tanlangan fayl maxfiy makonga olindi}other{Tanlangan fayllar maxfiy makonga olindi}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Fayllarni chiqarish"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Fayl uzatish bildirishnomalari"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Fayllarni yopiq maydonga nusxalasangiz yoki koʻchirsangiz, sizni rivoj haqida xabardor qilish uchun bildirishnomalar olasiz"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Ayrim fayllardan nusxa olinmadi"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Ayrim fayllar koʻchirilmadi"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Fayllarni qaytadan nusxalashingiz mumkin"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Fayllarni qaytadan koʻchirishingiz mumkin"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Fayllar hali ham nusxalanmoqda"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Fayllar hali ham koʻchirilmoqda"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Bu bajarilgach, yana boshqa fayllarni nusxalash yoki koʻchirish mumkin"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Fayllardan nusxa olinmadi"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Fayllar koʻchirilmadi"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Faylning umumiy hajmi juda katta"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Bir vaqtda faqat 2 GB gacha nusxalash yoki koʻchirish mumkin"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Nihoyatda koʻp fayl tanlandi"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Bir vaqtda faqat 100 GB gacha nusxalash yoki koʻchirish mumkin"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Fayllar qoʻshilmadi"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Qurilma xotirasida joy yetarli emas"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Xotiradan joy ochish"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Maxfiy makondan fayllarni nusxalash yoki koʻchirish imkonsiz"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Ayrim fayllar nusxalanmaydi"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Ayrim fayllar koʻchirilmaydi"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Nusxalash paytida maxfiy makoningiz yopildi"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Koʻchirish paytida maxfiy makoningiz yopildi"</string>
 </resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 3d42723..3e255d4 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Di chuyển"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Sao chép"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Huỷ"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Đang sao chép <xliff:g id="FILES">%1$d</xliff:g> tệp"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Đang chuyển <xliff:g id="FILES">%1$d</xliff:g> tệp"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Đã sao chép <xliff:g id="FILES">%1$d</xliff:g> tệp"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Đã chuyển <xliff:g id="FILES">%1$d</xliff:g> tệp"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Các tệp bạn chọn đang được sao chép vào không gian riêng tư"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Các tệp bạn chọn đang được chuyển vào không gian riêng tư"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Các tệp bạn chọn đã được sao chép vào không gian riêng tư"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Các tệp bạn chọn đã được chuyển vào không gian riêng tư"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Đang sao chép # tệp}other{Đang sao chép # tệp}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Đang chuyển # tệp}other{Đang chuyển # tệp}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Đã sao chép # tệp}other{Đã sao chép # tệp}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Đã chuyển # tệp}other{Đã chuyển # tệp}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Tệp bạn chọn đang được sao chép vào không gian riêng tư}other{Các tệp bạn chọn đang được sao chép vào không gian riêng tư}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Tệp bạn chọn đang được chuyển vào không gian riêng tư}other{Các tệp bạn chọn đang được chuyển vào không gian riêng tư}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Tệp bạn chọn đã được sao chép vào không gian riêng tư}other{Các tệp bạn chọn đã được sao chép vào không gian riêng tư}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Tệp bạn chọn đã được chuyển vào không gian riêng tư}other{Các tệp bạn chọn đã được chuyển vào không gian riêng tư}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Hiện tệp"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Thông báo về việc chuyển tệp"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Khi sao chép hoặc chuyển tệp vào không gian riêng tư, bạn có thể nhận được thông báo để cập nhật về tiến trình"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Không sao chép được một số tệp"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Không chuyển được một số tệp"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Bạn có thể cố sao chép các tệp của mình một lần nữa"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Bạn có thể thử chuyển các tệp của mình một lần nữa"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Vẫn đang sao chép tệp"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Vẫn đang chuyển tệp"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Bạn có thể sao chép hoặc chuyển thêm tệp sau khi quá trình này hoàn tất"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Không sao chép được tệp"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Không chuyển được tệp"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Tổng kích thước tệp quá lớn"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Bạn chỉ có thể sao chép hoặc chuyển tối đa 2 GB cùng một lúc"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Đã chọn quá nhiều tệp"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Bạn chỉ có thể sao chép hoặc chuyển tối đa 100 tệp cùng một lúc"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Không thêm được tệp"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Bộ nhớ trên thiết bị của bạn không đủ"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"OK"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Giải phóng dung lượng"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Không thể sao chép hoặc chuyển tệp từ Không gian riêng tư"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Không sao chép được một số tệp"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Không chuyển được một số tệp"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Không gian riêng tư của bạn đã bị đóng trong quá trình sao chép tệp"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Không gian riêng tư của bạn đã bị đóng trong quá trình chuyển tệp"</string>
 </resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 40c8099..a351e44 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -20,19 +20,41 @@
     <string name="shortcut_label_add_files" msgid="5537029952988156354">"添加文件"</string>
     <string name="shortcut_label_open_market_app" msgid="4433521224840755768">"安装应用"</string>
     <string name="move_files_dialog_title" msgid="4288920082565374705">"要移动或复制文件吗？"</string>
-    <string name="move_files_dialog_summary" msgid="5669539681627056766">"如果您将这些文件移至私密空间，系统会将它们从原始文件夹中移除"</string>
+    <string name="move_files_dialog_summary" msgid="5669539681627056766">"如果您选择移动至私密空间，系统将从原始文件夹中移除这些文件。"</string>
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"移动"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"复制"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"取消"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"正在复制 <xliff:g id="FILES">%1$d</xliff:g> 个文件"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"正在移动 <xliff:g id="FILES">%1$d</xliff:g> 个文件"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"已复制 <xliff:g id="FILES">%1$d</xliff:g> 个文件"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"已移动 <xliff:g id="FILES">%1$d</xliff:g> 个文件"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"您选定的文件正在复制到您的私密空间"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"您选定的文件正在移至您的私密空间"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"您选定的文件已复制到您的私密空间"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"您选定的文件已移至您的私密空间"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{正在复制 # 个文件}other{正在复制 # 个文件}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{正在移动 # 个文件。}other{正在移动 # 个文件}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{已复制 # 个文件}other{已复制 # 个文件}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{已移动 # 个文件}other{已移动 # 个文件}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{您选定的文件正在复制到您的私密空间}other{您选定的文件正在复制到您的私密空间}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{您选定的文件正在移至您的私密空间}other{您选定的文件正在移至您的私密空间}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{您选定的文件已复制到您的私密空间}other{您选定的文件已复制到您的私密空间}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{您选定的文件已移至您的私密空间}other{您选定的文件已移至您的私密空间}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"显示文件"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"文件传输通知"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"当您将文件复制或移至私密空间时，您可以收到通知，了解进度"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"无法复制部分文件"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"无法移动部分文件"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"您可以尝试重新复制文件"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"您可以尝试重新移动文件"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"仍在复制文件"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"仍在移动文件"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"复制完成后，您可以继续复制或移动文件"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"无法复制文件"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"无法移动文件"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"文件总大小超过上限"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"您一次最多只能复制或移动 2 GB 的文件"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"选择的文件过多"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"您一次最多只能复制或移动 100 个文件"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"无法添加文件"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"设备存储空间不足"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"确定"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"释放空间"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"无法复制或移动私密空间中的文件"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"无法复制某些文件"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"无法移动某些文件"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"复制文件时，您的私密空间处于关闭状态"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"移动文件时，您的私密空间处于关闭状态"</string>
 </resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index b276ae9..eb51138 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"移動"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"複製"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"取消"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"正在複製 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"正在移動 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"已複製 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"已移動 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"正在將所選檔案複製至私人空間"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"正在將所選檔案移至私人空間"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"所選檔案已複製至私人空間"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"所選檔案已移至私人空間"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{正在複製 # 個檔案}other{正在複製 # 個檔案}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{正在移動 # 個檔案}other{正在移動 # 個檔案}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{已複製 # 個檔案}other{已複製 # 個檔案}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{已移動 # 個檔案}other{已移動 # 個檔案}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{正在將所選檔案複製至私人空間}other{正在將所選檔案複製至私人空間}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{正在將所選檔案移至私人空間}other{正在將所選檔案移至私人空間}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{所選檔案已複製至私人空間}other{所選檔案已複製至私人空間}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{所選檔案已移至私人空間}other{所選檔案已移至私人空間}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"顯示檔案"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"檔案傳輸通知"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"當你將檔案複製或移動至私人空間時，系統會傳送進度更新通知"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"無法複製部分檔案"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"無法移動部分檔案"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"你可以嘗試再次複製檔案"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"你可以嘗試再次移動檔案"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"檔案複製進行中"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"仍在移動檔案"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"完成後，你可以複製或移動更多檔案"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"無法複製檔案"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"無法移動檔案"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"檔案總大小超過上限"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"你每次最多只可複製或移動 2GB 檔案"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"選取的檔案數量過多"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"你每次最多只可複製或移動 100 個檔案"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"無法新增檔案"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"你沒有足夠的裝置儲存空間"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"好"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"騰出空間"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"無法從「私人空間」複製或移動檔案"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"無法複製部分檔案"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"無法移動部分檔案"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"私人空間在複製期間已關閉"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"私人空間在移動期間已關閉"</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 09d32c9..ecd7b22 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"移動"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"複製"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"取消"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"正在複製 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"正在移動 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"已複製 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"已移動 <xliff:g id="FILES">%1$d</xliff:g> 個檔案"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"正在將所選檔案複製到私人空間"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"正在將所選檔案移到私人空間"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"所選檔案已複製到私人空間"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"所選檔案已移到私人空間"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{正在複製 # 個檔案}other{正在複製 # 個檔案}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{正在移動 # 個檔案}other{正在移動 # 個檔案}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{已複製 # 個檔案}other{已複製 # 個檔案}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{已移動 # 個檔案}other{已移動 # 個檔案}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{正在將所選檔案複製到私人空間}other{正在將所選檔案複製到私人空間}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{正在將所選檔案移到私人空間}other{正在將所選檔案移到私人空間}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{所選檔案已複製到私人空間}other{所選檔案已複製到私人空間}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{所選檔案已移到私人空間}other{所選檔案已移到私人空間}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"顯示檔案"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"檔案傳輸通知"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"你將檔案複製或移到私人空間時，系統可顯示通知，方便你掌握進度"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"無法複製部分檔案"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"無法移動部分檔案"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"你可以再試著複製檔案"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"你可以再試著移動檔案"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"仍在複製檔案"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"仍在移動檔案"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"完成後，你可以複製或移動更多檔案"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"無法複製檔案"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"無法移動檔案"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"檔案總大小過大"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"一次只能複製或移動最多 2 GB 的檔案"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"選取的檔案數量過多"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"一次最多只能複製或移動 100 個檔案"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"無法新增檔案"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"裝置儲存空間不足"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"確定"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"釋出空間"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"無法複製或移動私人空間中的檔案"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"無法複製部分檔案"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"無法移動部分檔案"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"私人空間已在複製時關閉"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"私人空間已在移動時關閉"</string>
 </resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 15ac80a..442f698 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -24,15 +24,37 @@
     <string name="move_files_dialog_button_label_move" msgid="1751064793113192183">"Hambisa"</string>
     <string name="move_files_dialog_button_label_copy" msgid="7432216057718935377">"Kopisha"</string>
     <string name="move_files_dialog_button_label_cancel" msgid="1323427446951554831">"Khansela"</string>
-    <string name="filetransfer_notification_copy_progress_title" msgid="2461931256956245376">"Ikopisha ifayela elingu-<xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_move_progress_title" msgid="5822981195498127235">"Ihambisa ifayela elingu-<xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_complete_title" msgid="667008084900445279">"Ifayela elingu-<xliff:g id="FILES">%1$d</xliff:g> likopishiwe"</string>
-    <string name="filetransfer_notification_move_complete_title" msgid="2912472815860378028">"Kuhanjiswe ifayela elingu-<xliff:g id="FILES">%1$d</xliff:g>"</string>
-    <string name="filetransfer_notification_copy_progress_text" msgid="3335832577999712410">"Amafayela owakhethile akopishelwa endaweni yakho engasese"</string>
-    <string name="filetransfer_notification_move_progress_text" msgid="7414106168630442326">"Amafayela owakhethile ahanjiswa endaweni yakho engasese"</string>
-    <string name="filetransfer_notification_copy_complete_text" msgid="1851705090163843207">"Amafayela owakhethile akopishelwe endaweni yakho engasese"</string>
-    <string name="filetransfer_notification_move_complete_text" msgid="3869201560583963976">"Amafayela owakhethile ahanjiswe endaweni yakho engasese"</string>
+    <string name="filetransfer_notification_copy_progress_title" msgid="1273317697415657776">"{count,plural, =1{Ikopisha ifayela elingu-#}one{Ikopisha amafayela angu-#}other{Ikopisha amafayela angu-#}}"</string>
+    <string name="filetransfer_notification_move_progress_title" msgid="6257049184801798568">"{count,plural, =1{Ihambisa ifayela elingu-#}one{Ihambisa amafayela angu-#}other{Ihambisa amafayela angu-#}}"</string>
+    <string name="filetransfer_notification_copy_complete_title" msgid="5723966267168662496">"{count,plural, =1{Ifayela elingu-# likopishiwe}one{Amafayela angu-# akopishiwe}other{Amafayela angu-# akopishiwe}}"</string>
+    <string name="filetransfer_notification_move_complete_title" msgid="6984589616628431425">"{count,plural, =1{Ifayela elingu-# lihanjisiwe}one{Amafayela angu-# ahanjisiwe}other{Amafayela angu-# ahanjisiwe}}"</string>
+    <string name="filetransfer_notification_copy_progress_text" msgid="7826033004395460524">"{count,plural, =1{Ifayela lakho olikhethile likopishelwa endaweni yakho engasese}one{Amafayela akho owakhethile akopishelwa endaweni yakho engasese}other{Amafayela akho owakhethile akopishelwa endaweni yakho engasese}}"</string>
+    <string name="filetransfer_notification_move_progress_text" msgid="7520839052374095824">"{count,plural, =1{Ifayela lakho olikhethile lihanjiswa endaweni yakho engasese}one{Amafayela akho owakhethile ahanjiswa endaweni yakho engasese}other{Amafayela akho owakhethile ahanjiswa endaweni yakho engasese}}"</string>
+    <string name="filetransfer_notification_copy_complete_text" msgid="7118479336695406242">"{count,plural, =1{Ifayela olikhethile likopishelwe endaweni yakho engasese}one{Amafayela akho owakhethile akopishelwe endaweni yakho engasese}other{Amafayela akho owakhethile akopishelwe endaweni yakho engasese}}"</string>
+    <string name="filetransfer_notification_move_complete_text" msgid="7466128588012981125">"{count,plural, =1{Ifayela lakho olikhethile liyiswe endaweni yakho engasese}one{Amafayela akho owakhethile ayiswe endaweni yakho engasese}other{Amafayela akho owakhethile ayiswe endaweni yakho engasese}}"</string>
     <string name="filetransfer_notification_action_label" msgid="3580418408308393674">"Bonisa amafayela"</string>
     <string name="filetransfer_notification_channel_name" msgid="5904517724807973216">"Izaziso zalapho udlulisela amafayela"</string>
     <string name="filetransfer_notification_channel_description" msgid="6731093270622225619">"Lapho ukopisha noma uthuthela amafayela endaweni engasese, ungathola izaziso ukuze zikutshele ukuthi sekukuliphi izinga lokhu okwenzayo"</string>
+    <string name="filetransfer_notification_partial_copy_error_title" msgid="1677347860559329792">"Ayikwazi ukukopisha amanye amafayela"</string>
+    <string name="filetransfer_notification_partial_move_error_title" msgid="876116969364070849">"Ayikwazi ukuhambisa amanye amafayela"</string>
+    <string name="filetransfer_generic_copy_error_message" msgid="5632773012035808586">"Ungazama ukukopisha amafayela akho futhi"</string>
+    <string name="filetransfer_generic_move_error_message" msgid="6148258308893327201">"Ungazama ukuhambisa amafayela akho futhi"</string>
+    <string name="filetransfer_dialog_still_copying_error_title" msgid="5641360898141140186">"Isakopisha amafayela"</string>
+    <string name="filetransfer_dialog_still_moving_error_title" msgid="5943530378894921491">"Isahambisa amafayela"</string>
+    <string name="filetransfer_dialog_still_transferring_error_message" msgid="6497954259225540223">"Ungakopisha noma uhambise amafayela amaningi uma lokhu sekwenziwe"</string>
+    <string name="filetransfer_notification_copy_error_title" msgid="3389760086373476260">"Ayikwazi ukukopisha amafayela"</string>
+    <string name="filetransfer_notification_move_error_title" msgid="8076458375024121497">"Ayikwazanga ukuhambisa amafayela"</string>
+    <string name="filetransfer_large_files_size_error_title" msgid="6423154416185732854">"Isamba sosayizi wefayela sikhulu kakhulu"</string>
+    <string name="filetransfer_large_files_size_error_message" msgid="2003755260732056369">"Ungakopisha kuphela noma uhambise phezulu kufikela ku-2 GB ngaleso sikhathi"</string>
+    <string name="filetransfer_too_many_files_error_title" msgid="6511377405439734732">"Kukhethwe amafayela amaningi kakhulu"</string>
+    <string name="filetransfer_too_many_files_error_message" msgid="7423256743455308539">"Ungakopisha kuphela noma uhambise phezulu kufikela kumafayela angu-100 ngesikhathi"</string>
+    <string name="filetransfer_notification_transfer_error_title" msgid="8560198738417942070">"Ayikwazi ukungeza amafayela"</string>
+    <string name="filetransfer_notification_insufficient_storage_error_message" msgid="1077849452734339820">"Awunasitoreji esanele sedivayisi"</string>
+    <string name="filetransfer_error_dialog_button" msgid="5066514769596768979">"KULUNGILE"</string>
+    <string name="filetransfer_notification_not_enough_storage_error_action" msgid="4568585891334469685">"Khulula isikhala"</string>
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user" msgid="5123007665712006029">"Ayikwazi ukukopisha noma ukuhambisa amafayela Asendaweni Engasese"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_title" msgid="1761733378089621286">"Amanye amafayela akakopishekanga"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_title" msgid="8689393501629819076">"Amanye amafayela akahambanga"</string>
+    <string name="filetransfer_notification_incomplete_copy_transfer_message" msgid="6664772162662622245">"Indawo yakho yangasese ibivaliwe ngesikhathi kukopishwa"</string>
+    <string name="filetransfer_notification_incomplete_move_transfer_message" msgid="8930132651559792918">"Indawo yakho yangasese ibivaliwe ngesikhathi kuhanjiswa izinto"</string>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 6883ee8..a906da0 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -15,8 +15,9 @@
 -->
 
 <resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <!-- TODO(b/398234821): update the description to note that the label under the app icon is different once it is implemented -->
-    <!-- The name of the application as it appears under the main Launcher icon and in Settings apps stats -->
+    <!-- The name of the application as it appears in Settings apps stats. Note that this is not the
+          the label displayed under the plus button in the Private Space container, where it is
+          the "Add" label. -->
     <string name="private_space_app_label">Private Space</string>
     <!-- Label for the app shortcut to start the workflow for moving files into Private Space. [CHAR LIMIT=25] -->
     <string name="shortcut_label_add_files">Add files</string>
@@ -33,25 +34,97 @@
     <!-- Label for the move content dialog button to choose to cancel the operation. -->
     <string name="move_files_dialog_button_label_cancel">Cancel</string>
     <!-- Copy in progress notification title with the total number of files-->
-    <string name="filetransfer_notification_copy_progress_title">Copying <xliff:g example="4" id="files">%1$d</xliff:g> file(s)</string>
+    <string name="filetransfer_notification_copy_progress_title">
+        {count, plural, =1 {Copying # file} other {Copying # files}}
+    </string>
     <!-- Move in progress notification title with the total number of files-->
-    <string name="filetransfer_notification_move_progress_title">Moving <xliff:g example="4" id="files">%1$d</xliff:g> file(s)</string>
+    <string name="filetransfer_notification_move_progress_title">
+        {count, plural, =1 {Moving # file} other {Moving # files}}
+    </string>
     <!-- Copy complete notification title with the total number of files-->
-    <string name="filetransfer_notification_copy_complete_title"><xliff:g example="4" id="files">%1$d</xliff:g> file(s) copied</string>
+    <string name="filetransfer_notification_copy_complete_title">
+        {count, plural, =1 {# file copied} other {# files copied}}
+    </string>
     <!-- Move complete notification title with the total number of files-->
-    <string name="filetransfer_notification_move_complete_title"><xliff:g example="4" id="files">%1$d</xliff:g> file(s) moved</string>
+    <string name="filetransfer_notification_move_complete_title">
+        {count, plural, =1 {# file moved} other {# files moved}}
+    </string>
     <!-- Copy files progress notification description-->
-    <string name="filetransfer_notification_copy_progress_text">Your chosen files are being copied to your private space</string>
+    <string name="filetransfer_notification_copy_progress_text">
+        {count, plural,
+        =1 {Your chosen file is being copied to your private space}
+        other {Your chosen files are being copied to your private space}
+        }
+    </string>
     <!-- Move files progress notification description-->
-    <string name="filetransfer_notification_move_progress_text">Your chosen files are being moved to your private space</string>
+    <string name="filetransfer_notification_move_progress_text">
+        {count, plural,
+        =1 {Your chosen file is being moved to your private space}
+        other {Your chosen files are being moved to your private space}
+        }
+    </string>
     <!-- Copy files completion notification description-->
-    <string name="filetransfer_notification_copy_complete_text">Your chosen files were copied to your private space</string>
+    <string name="filetransfer_notification_copy_complete_text">
+        {count, plural,
+        =1 {Your chosen file was copied to your private space}
+        other {Your chosen files were copied to your private space}
+        }
+    </string>
     <!-- Move files completion notification description-->
-    <string name="filetransfer_notification_move_complete_text">Your chosen files were moved to your private space</string>
+    <string name="filetransfer_notification_move_complete_text">
+        {count, plural,
+        =1 {Your chosen file was moved to your private space}
+        other {Your chosen files were moved to your private space}
+        }
+    </string>
     <!-- Label for the copy/move files notification action button-->
     <string name="filetransfer_notification_action_label">Show files</string>
     <!-- Move content notification channel name as it appears in the notification settings of the Private space app. [CHAR LIMIT=40]-->
     <string name="filetransfer_notification_channel_name">File transfer notifications</string>
     <!-- Move content notification channel description as it appears in the notification settings of the Private space app. [CHAR LIMIT=300]-->
-    <string name="filetransfer_notification_channel_description">"When you copy or move files to your private space, you can receive notifications to update you on the progress"</string>
+    <string name="filetransfer_notification_channel_description">When you copy or move files to your private space, you can receive notifications to update you on the progress</string>
+    <!-- Unable to copy some files notification title-->
+    <string name="filetransfer_notification_partial_copy_error_title">"Can't copy some files"</string>
+    <!-- Unable to move some files notification title-->
+    <string name="filetransfer_notification_partial_move_error_title">"Can't move some files"</string>
+    <!-- Unable to copy some files error dialog/notification message -->
+    <string name="filetransfer_generic_copy_error_message">You can try to copy your files again</string>
+    <!-- Unable to move some files error dialog/notification message -->
+    <string name="filetransfer_generic_move_error_message">You can try to move your files again</string>
+    <!-- Another copy operation still in progress dialog error title-->
+    <string name="filetransfer_dialog_still_copying_error_title">Still copying files</string>
+    <!-- Another move operation still in progress dialog error title-->
+    <string name="filetransfer_dialog_still_moving_error_title">Still moving files</string>
+    <!-- Transfer still in progress dialog error message-->
+    <string name="filetransfer_dialog_still_transferring_error_message">You can copy or move more files once this is done</string>
+    <!-- Unable to copy all the files notification title-->
+    <string name="filetransfer_notification_copy_error_title">"Couldn't copy files"</string>
+    <!-- Unable to move all the files notification title-->
+    <string name="filetransfer_notification_move_error_title">"Couldn't move files"</string>
+    <!-- Total files size of the selected more that the 2GB copy/move limit dialog error title -->
+    <string name="filetransfer_large_files_size_error_title">Total file size is too large</string>
+    <!-- Total files size of the selected more that the 2GB copy/move limit dialog error message -->
+    <string name="filetransfer_large_files_size_error_message">You can only copy or move up to 2 GB at once</string>
+    <!-- Total files selected more that 100 copy/move limit dialog error title -->
+    <string name="filetransfer_too_many_files_error_title">Too many files selected</string>
+    <!-- Total files selected more that 100 copy/move limit dialog error message -->
+    <string name="filetransfer_too_many_files_error_message">You can only copy or move up to 100 files at once</string>
+    <!-- Unable to copy or move all the files notification title-->
+    <string name="filetransfer_notification_transfer_error_title">"Can't add files"</string>
+    <!-- Not enough storage available on device to complete the copy -->
+    <string name="filetransfer_notification_insufficient_storage_error_message">"You don’t have enough device storage"</string>
+    <!-- Dialog button shown in case fo a move content error -->
+    <string name="filetransfer_error_dialog_button">OK</string>
+    <!-- Free up space notification action -->
+    <string name="filetransfer_notification_not_enough_storage_error_action">Free up space</string>
+    <!-- String used to power the error toast when the user tries to copy or move files from the private space itself -->
+    <string name="filetransfer_error_toast_cannot_transfer_from_same_user">"Can't copy or move files from Private Space"</string>
+    <!-- Title of the notification diplayed after private space is unlocked, if the transfer was interrupted, for example private space locked or device rebooted while copying files -->
+    <string name="filetransfer_notification_incomplete_copy_transfer_title">"Couldn't copy some files"</string>
+    <!-- Title of the notification diplayed after private space is unlocked, if the transfer was interrupted, for example private space locked or device rebooted while moving files -->
+    <string name="filetransfer_notification_incomplete_move_transfer_title">"Couldn't move some files"</string>
+    <!-- The description of the notification diplayed after private space is unlocked, if the transfer was interrupted, for example private space locked or device rebooted while copying files -->
+    <string name="filetransfer_notification_incomplete_copy_transfer_message">Your private space was closed while copying</string>
+    <!-- The description of the notification diplayed after private space is unlocked, if the transfer was interrupted, for example private space locked or device rebooted while moving files -->
+    <string name="filetransfer_notification_incomplete_move_transfer_message">Your private space was closed while moving</string>
 </resources>
diff --git a/src/com/android/privatespace/BootCompletedBroadcastReceiver.kt b/src/com/android/privatespace/BootCompletedBroadcastReceiver.kt
new file mode 100644
index 0000000..2db699b
--- /dev/null
+++ b/src/com/android/privatespace/BootCompletedBroadcastReceiver.kt
@@ -0,0 +1,47 @@
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
+package com.android.privatespace
+
+import android.content.BroadcastReceiver
+import android.content.Context
+import android.content.Intent
+import com.android.privatespace.filetransfer.FileTransferStateChecker
+import com.android.privatespace.filetransfer.FileTransferStateRepository
+import com.android.privatespace.filetransfer.NotificationsHelper
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.launch
+
+/**
+ * A BroadcastReceiver that handles the {@link Intent.ACTION_BOOT_COMPLETED} broadcast after private
+ * space unlock.
+ */
+class BootCompletedBroadcastReceiver : BroadcastReceiver() {
+    private val coroutineScope = CoroutineScope(Dispatchers.IO)
+
+    override fun onReceive(context: Context, intent: Intent) {
+        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
+            val pendingResult = goAsync()
+            coroutineScope.launch {
+                //  Check and handle the last known file transfer state
+                FileTransferStateChecker(FileTransferStateRepository, NotificationsHelper(context))
+                    .postBootTransferStateCheck(context)
+                pendingResult.finish()
+            }
+        }
+    }
+}
diff --git a/src/com/android/privatespace/PrivateSpaceActivity.kt b/src/com/android/privatespace/PrivateSpaceActivity.kt
index 3b1365f..2d3a981 100644
--- a/src/com/android/privatespace/PrivateSpaceActivity.kt
+++ b/src/com/android/privatespace/PrivateSpaceActivity.kt
@@ -18,22 +18,20 @@ package com.android.privatespace
 import android.app.ActivityOptions
 import android.content.ActivityNotFoundException
 import android.content.Intent
+import android.content.IntentSender
 import android.content.IntentSender.SendIntentException
 import android.content.pm.LauncherApps
 import android.net.Uri
 import android.os.Bundle
 import android.util.Log
+import android.widget.Toast
 import androidx.activity.ComponentActivity
 import androidx.activity.compose.setContent
 import androidx.activity.result.ActivityResultLauncher
 import androidx.activity.result.contract.ActivityResultContracts
 import androidx.activity.viewModels
-import androidx.compose.material3.Button
-import androidx.compose.material3.OutlinedButton
-import androidx.compose.material3.Text
-import androidx.compose.material3.TextButton
-import androidx.compose.runtime.Composable
-import androidx.compose.ui.res.stringResource
+import androidx.annotation.VisibleForTesting
+import java.util.function.Supplier
 
 /**
  * The main activity for the Private Space system app.
@@ -53,8 +51,11 @@ class PrivateSpaceActivity : ComponentActivity() {
 
     companion object {
         private const val TAG = "PrivateSpaceActivity"
-        private const val ACTION_ADD_FILES = "com.android.privatespace.action.ADD_FILES"
-        private const val ACTION_OPEN_MARKET_APP = "com.android.privatespace.action.OPEN_MARKET_APP"
+        @VisibleForTesting
+        internal const val ACTION_ADD_FILES = "com.android.privatespace.action.ADD_FILES"
+        @VisibleForTesting
+        internal const val ACTION_OPEN_MARKET_APP =
+            "com.android.privatespace.action.OPEN_MARKET_APP"
     }
 
     override fun onCreate(savedInstanceState: Bundle?) {
@@ -73,7 +74,16 @@ class PrivateSpaceActivity : ComponentActivity() {
                 }
             }
 
-        setContent { PrivateSpaceAppTheme { PrivateSpaceActivityScreen(viewModel = viewModel) } }
+        setContent {
+            PrivateSpaceAppTheme {
+                PrivateSpaceActivityScreen(
+                    viewModel = viewModel,
+                    context = applicationContext,
+                    onOpenDocumentsPicker = this::openDocumentPicker,
+                    onFinished = this::finish,
+                )
+            }
+        }
         handleIntent(intent)
     }
 
@@ -81,13 +91,11 @@ class PrivateSpaceActivity : ComponentActivity() {
         Log.d(TAG, "handleIntent action: ${intent.action}")
 
         when (intent.action) {
-            ACTION_ADD_FILES -> openDocumentPicker()
-            ACTION_OPEN_MARKET_APP -> openMarketApp()
-            else -> {
-                Log.d(TAG, "No known action specified")
-                // TODO(b/397383858): default to the Private Space settings screen
-                viewModel.finishFlow()
+            ACTION_ADD_FILES -> {
+                viewModel.checkIfNewTransferCanStart(applicationContext)
             }
+            ACTION_OPEN_MARKET_APP -> openMarketApp()
+            else -> openPrivateSpaceSettings()
         }
     }
 
@@ -97,108 +105,113 @@ class PrivateSpaceActivity : ComponentActivity() {
                 type = "*/*"
                 addCategory(Intent.CATEGORY_OPENABLE)
                 putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
+                putExtra(Intent.EXTRA_LOCAL_ONLY, true)
             }
         documentPickerLauncher.launch(intent)
     }
 
     private fun openMarketApp() {
-        val launcherApps =
-            applicationContext.getSystemService(LauncherApps::class.java)
-                ?: run {
-                    Log.e(TAG, "Failed to get LauncherApps service")
-                    viewModel.finishFlow()
-                    return
-                }
-
-        try {
-            val intentSender =
-                launcherApps.getAppMarketActivityIntent(
+        handleLauncherAppsIntentSender {
+            getLauncherApps()
+                ?.getAppMarketActivityIntent(
                     applicationContext.packageName,
                     applicationContext.user,
                 )
-            intentSender?.let {
-                // Satisfy BAL restrictions.
-                val fillInIntent = Intent()
-                val options =
-                    ActivityOptions.makeBasic()
-                        .setPendingIntentBackgroundActivityStartMode(
-                            ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE
-                        )
-                        .toBundle()
-                startIntentSender(it, fillInIntent, 0, 0, 0, options)
-            } ?: run { Log.e(TAG, "Failed to open market app.") }
-        } catch (e: Exception) {
-            when (e) {
-                is NullPointerException,
-                is ActivityNotFoundException,
-                is SecurityException,
-                is SendIntentException -> {
-                    Log.e(TAG, "Private Space could not start the market app", e)
-                }
-                else -> throw e
-            }
-        } finally {
-            viewModel.finishFlow()
         }
     }
 
-    private fun handleDocumentSelection(data: Intent) {
-        val uris = buildList {
-            // Single URI is passed in data, multiple URIs are passed in clipData
-            data.data?.let {
-                persistUriPermissions(it)
-                add(it)
-            }
-            data.clipData?.let { clipData ->
-                for (i in 0 until clipData.itemCount) {
-                    val uri: Uri = clipData.getItemAt(i).uri
-                    persistUriPermissions(uri)
-                    add(uri)
+    private fun openPrivateSpaceSettings() {
+        handleLauncherAppsIntentSender { getLauncherApps()?.privateSpaceSettingsIntent }
+        viewModel.finishFlow()
+    }
+
+    private fun getLauncherApps(): LauncherApps? {
+        return (applicationContext.getSystemService(LauncherApps::class.java)
+            ?: run {
+                Log.e(TAG, "Failed to get LauncherApps service")
+                viewModel.finishFlow()
+                null
+            })
+    }
+
+    private fun launchIntentSenderWithBal(intentSender: IntentSender) {
+        val fillInIntent = Intent()
+        val options =
+            ActivityOptions.makeBasic()
+                .setPendingIntentBackgroundActivityStartMode(
+                    ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE
+                )
+                .toBundle()
+        startIntentSender(intentSender, fillInIntent, 0, 0, 0, options)
+    }
+
+    private fun handleLauncherAppsIntentSender(intentSenderSupplier: Supplier<IntentSender?>) {
+        val intentSender = intentSenderSupplier.get()
+        intentSender?.let {
+            try {
+                launchIntentSenderWithBal(it)
+            } catch (e: Exception) {
+                when (e) {
+                    is NullPointerException,
+                    is ActivityNotFoundException,
+                    is SecurityException,
+                    is SendIntentException -> {
+                        Log.e(TAG, "Private Space could not start the intended activity", e)
+                    }
+                    else -> throw e
                 }
+            } finally {
+                viewModel.finishFlow()
             }
-        }
+        } ?: run { Log.e(TAG, "Failed to get IntentSender") }
+    }
 
-        viewModel.showMoveFilesDialog(uris)
+    private fun handleDocumentSelection(data: Intent) {
+        val uris = getValidatedUriList(data)
+        if (viewModel.validateSelectedFileLimits(applicationContext, uris)) {
+            viewModel.showMoveFilesDialog(uris)
+        }
     }
 
-    @Composable
-    fun PrivateSpaceActivityScreen(viewModel: PrivateSpaceViewModel) {
-        when (viewModel.uiState) {
-            PrivateSpaceUiState.STARTED -> {
-                // Show nothing, wait for the results of the document picker.
-            }
-            PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG -> {
-                ThreeButtonAlertDialog(
-                    onDismissRequest = viewModel::finishFlow,
-                    title = stringResource(R.string.move_files_dialog_title),
-                    message = stringResource(R.string.move_files_dialog_summary),
-                    primaryButton = {
-                        Button(onClick = { viewModel.moveFiles(applicationContext) }) {
-                            Text(stringResource(R.string.move_files_dialog_button_label_move))
-                        }
-                    },
-                    secondaryButton = {
-                        OutlinedButton(onClick = { viewModel.copyFiles(applicationContext) }) {
-                            Text(stringResource(R.string.move_files_dialog_button_label_copy))
-                        }
-                    },
-                    dismissButton = {
-                        TextButton(onClick = viewModel::finishFlow) {
-                            Text(stringResource(R.string.move_files_dialog_button_label_cancel))
-                        }
-                    },
-                )
+    private fun getValidatedUriList(data: Intent): ArrayList<Uri> {
+        // Single Uri is passed in intent's data, multiple uris in clip data
+        data.data?.let {
+            if (isUriFromSameUser(it)) {
+                showCannotTransferFromSameUserToast()
+                return arrayListOf()
             }
-            PrivateSpaceUiState.FINISHED -> {
-                finish()
+            return arrayListOf(it)
+        }
+        data.clipData?.let { clipData ->
+            val uriList = ArrayList<Uri>()
+            for (i in 0 until clipData.itemCount) {
+                val uri = clipData.getItemAt(i).uri
+                if (isUriFromSameUser(uri)) {
+                    showCannotTransferFromSameUserToast()
+                    return arrayListOf()
+                }
+                uriList.add(uri)
             }
+            return uriList
         }
+        return arrayListOf()
+    }
+
+    private fun isUriFromSameUser(uri: Uri): Boolean {
+        // DocumentsUI uris contain a user id as part of the authority if the file is from a
+        // different user than the current user. If the user is null, the file is from the current
+        // user.
+        return uri.userInfo == null
     }
 
-    private fun persistUriPermissions(uri: Uri) {
-        applicationContext.contentResolver.takePersistableUriPermission(
-            uri,
-            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
-        )
+    private fun showCannotTransferFromSameUserToast() {
+        Toast.makeText(
+                applicationContext,
+                applicationContext.resources.getString(
+                    R.string.filetransfer_error_toast_cannot_transfer_from_same_user
+                ),
+                Toast.LENGTH_SHORT,
+            )
+            .show()
     }
 }
diff --git a/src/com/android/privatespace/PrivateSpaceActivityScreen.kt b/src/com/android/privatespace/PrivateSpaceActivityScreen.kt
new file mode 100644
index 0000000..75f0ffb
--- /dev/null
+++ b/src/com/android/privatespace/PrivateSpaceActivityScreen.kt
@@ -0,0 +1,142 @@
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
+package com.android.privatespace
+
+import android.content.Context
+import androidx.compose.foundation.layout.Box
+import androidx.compose.foundation.layout.fillMaxSize
+import androidx.compose.foundation.layout.fillMaxWidth
+import androidx.compose.foundation.layout.padding
+import androidx.compose.material3.AlertDialog
+import androidx.compose.material3.Button
+import androidx.compose.material3.CircularProgressIndicator
+import androidx.compose.material3.OutlinedButton
+import androidx.compose.material3.Text
+import androidx.compose.material3.TextButton
+import androidx.compose.runtime.Composable
+import androidx.compose.ui.Alignment
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.platform.testTag
+import androidx.compose.ui.res.stringResource
+import androidx.compose.ui.text.style.TextAlign
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.window.DialogProperties
+
+internal const val CIRCULAR_PROGRESS_INDICATOR_TEST_TAG = "CIRCULAR_PROGRESS_INDICATOR"
+
+@Composable
+fun PrivateSpaceActivityScreen(
+    viewModel: PrivateSpaceViewModel,
+    context: Context,
+    onOpenDocumentsPicker: () -> Unit,
+    onFinished: () -> Unit,
+) {
+    when (viewModel.uiState) {
+        PrivateSpaceUiState.STARTED -> {
+            // Show nothing, wait for the results of the document picker.
+        }
+        PrivateSpaceUiState.CHECKING_PROGRESS_INDICATOR ->
+            Box(modifier = Modifier.fillMaxSize()) {
+                CircularProgressIndicator(
+                    modifier =
+                        Modifier.align(Alignment.Center)
+                            .testTag(CIRCULAR_PROGRESS_INDICATOR_TEST_TAG)
+                )
+            }
+        PrivateSpaceUiState.SHOW_DOCUMENT_PICKER -> onOpenDocumentsPicker()
+        PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG -> {
+            ThreeButtonAlertDialog(
+                onDismissRequest = viewModel::finishFlow,
+                title = stringResource(R.string.move_files_dialog_title),
+                message = stringResource(R.string.move_files_dialog_summary),
+                primaryButton = {
+                    Button(onClick = { viewModel.moveFiles(context) }) {
+                        Text(stringResource(R.string.move_files_dialog_button_label_move))
+                    }
+                },
+                secondaryButton = {
+                    OutlinedButton(onClick = { viewModel.copyFiles(context) }) {
+                        Text(stringResource(R.string.move_files_dialog_button_label_copy))
+                    }
+                },
+                dismissButton = {
+                    TextButton(onClick = viewModel::finishFlow) {
+                        Text(stringResource(R.string.move_files_dialog_button_label_cancel))
+                    }
+                },
+            )
+        }
+        PrivateSpaceUiState.SHOW_NOT_ENOUGH_SPACE_DIALOG -> {
+            buildErrorDialog(
+                viewModel,
+                stringResource(R.string.filetransfer_notification_transfer_error_title),
+                stringResource(
+                    R.string.filetransfer_notification_insufficient_storage_error_message
+                ),
+            )
+        }
+        PrivateSpaceUiState.SHOW_ABOVE_FILE_SIZE_LIMITS_DIALOG -> {
+            buildErrorDialog(
+                viewModel,
+                stringResource(R.string.filetransfer_large_files_size_error_title),
+                stringResource(R.string.filetransfer_large_files_size_error_message),
+            )
+        }
+        PrivateSpaceUiState.SHOW_TOO_MANY_FILES_SELECTED_DIALOG -> {
+            buildErrorDialog(
+                viewModel,
+                stringResource(R.string.filetransfer_too_many_files_error_title),
+                stringResource(R.string.filetransfer_too_many_files_error_message),
+            )
+        }
+        PrivateSpaceUiState.SHOW_TRANSFER_IN_PROGRESS_DIALOG -> {
+            buildErrorDialog(
+                viewModel,
+                stringResource(
+                    if (viewModel.isCopyOperationForErrorDialog())
+                        R.string.filetransfer_dialog_still_copying_error_title
+                    else R.string.filetransfer_dialog_still_moving_error_title
+                ),
+                stringResource(R.string.filetransfer_dialog_still_transferring_error_message),
+            )
+        }
+        PrivateSpaceUiState.FINISHED -> {
+            onFinished()
+        }
+    }
+}
+
+@Composable
+private fun buildErrorDialog(viewModel: PrivateSpaceViewModel, title: String, message: String) {
+    AlertDialog(
+        onDismissRequest = { viewModel.finishFlow() },
+        title = {
+            Text(text = title, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
+        },
+        text = {
+            Text(text = message, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
+        },
+        confirmButton = {},
+        dismissButton = {
+            Button(onClick = { viewModel.finishFlow() }) {
+                Text(stringResource(R.string.filetransfer_error_dialog_button))
+            }
+        },
+        properties = DialogProperties(usePlatformDefaultWidth = false),
+        modifier = Modifier.padding(horizontal = 24.dp),
+    )
+}
diff --git a/src/com/android/privatespace/PrivateSpaceUiState.kt b/src/com/android/privatespace/PrivateSpaceUiState.kt
index f0ff7d4..c277bc3 100644
--- a/src/com/android/privatespace/PrivateSpaceUiState.kt
+++ b/src/com/android/privatespace/PrivateSpaceUiState.kt
@@ -18,6 +18,12 @@ package com.android.privatespace
 /** Enum for PrivateSpaceActivity state. */
 enum class PrivateSpaceUiState {
     STARTED,
+    CHECKING_PROGRESS_INDICATOR,
+    SHOW_DOCUMENT_PICKER,
     SHOW_MOVE_FILES_DIALOG,
+    SHOW_NOT_ENOUGH_SPACE_DIALOG,
+    SHOW_ABOVE_FILE_SIZE_LIMITS_DIALOG,
+    SHOW_TOO_MANY_FILES_SELECTED_DIALOG,
+    SHOW_TRANSFER_IN_PROGRESS_DIALOG,
     FINISHED,
 }
diff --git a/src/com/android/privatespace/PrivateSpaceViewModel.kt b/src/com/android/privatespace/PrivateSpaceViewModel.kt
index bad77c9..50313b9 100644
--- a/src/com/android/privatespace/PrivateSpaceViewModel.kt
+++ b/src/com/android/privatespace/PrivateSpaceViewModel.kt
@@ -19,24 +19,47 @@ import android.content.Context
 import android.content.Intent
 import android.net.Uri
 import android.os.Environment
+import android.util.Log
+import androidx.annotation.OpenForTesting
+import androidx.annotation.VisibleForTesting
 import androidx.compose.runtime.getValue
 import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.setValue
 import androidx.lifecycle.ViewModel
+import androidx.lifecycle.viewModelScope
 import com.android.privatespace.filetransfer.FileTransferService
 import com.android.privatespace.filetransfer.FileTransferService.Companion.DESTINATION_PATH_EXTRA
 import com.android.privatespace.filetransfer.FileTransferService.Companion.KEEP_ORIGINAL_EXTRA
 import com.android.privatespace.filetransfer.FileTransferService.Companion.SOURCE_URIS_EXTRA
+import com.android.privatespace.filetransfer.FileTransferStateRepository
+import com.android.privatespace.filetransfer.IFileTransferStateRepository
 import java.util.ArrayList
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.withTimeoutOrNull
 
 /** A ViewModel for the PrivateSpaceActivity move files feature and its dialog. */
-class PrivateSpaceViewModel : ViewModel() {
-    var uiState by mutableStateOf(PrivateSpaceUiState.STARTED)
+@OpenForTesting
+open class PrivateSpaceViewModel(
+    private val storageHelper: StorageHelper = StorageHelperImpl,
+    private val fileTransferStateRepository: IFileTransferStateRepository =
+        FileTransferStateRepository,
+) : ViewModel() {
+    companion object {
+        private const val TAG = "PrivateSpaceViewModel"
+        private const val MAXIMUM_TRANSFER_BYTES_ALLOWED: Long = 2_000_000_000L
+        private const val MAXIMUM_NUMBER_OF_FILES_ALLOWED: Int = 100
+        internal const val TRANSFER_STATUS_TIMEOUT_MS = 3_000L // 3 seconds
+    }
+
+    open var uiState by mutableStateOf(PrivateSpaceUiState.STARTED)
         private set
 
-    private var fileUris: List<Uri> = emptyList()
+    var isPreviousTransferCopy: Boolean = true
+        private set
 
-    fun showMoveFilesDialog(uris: List<Uri>) {
+    @VisibleForTesting internal var fileUris: ArrayList<Uri> = ArrayList()
+
+    fun showMoveFilesDialog(uris: ArrayList<Uri>) {
         fileUris = uris
         if (uris.isNotEmpty()) {
             uiState = PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG
@@ -46,28 +69,115 @@ class PrivateSpaceViewModel : ViewModel() {
         }
     }
 
-    fun moveFiles(context: Context) {
+    fun checkIfNewTransferCanStart(context: Context) {
+        uiState = PrivateSpaceUiState.CHECKING_PROGRESS_INDICATOR
+        viewModelScope.launch {
+            val transferState =
+                withTimeoutOrNull(TRANSFER_STATUS_TIMEOUT_MS) {
+                    fileTransferStateRepository.getTransferState(context)
+                }
+            if (transferState != null && transferState.transferInProgress) {
+                Log.e(TAG, "New transfer invoked while another transfer already in progress")
+                uiState = PrivateSpaceUiState.SHOW_TRANSFER_IN_PROGRESS_DIALOG
+                isPreviousTransferCopy = transferState.keepOriginal
+            } else {
+                if (transferState == null) {
+                    Log.w(
+                        TAG,
+                        "getTransferState timed out after $TRANSFER_STATUS_TIMEOUT_MS ms. Falling back to SHOW_DOCUMENT_PICKER.",
+                    )
+                } else {
+                    Log.d(TAG, "No transfer in progress, showing document picker.")
+                }
+                uiState = PrivateSpaceUiState.SHOW_DOCUMENT_PICKER
+            }
+        }
+    }
+
+    @OpenForTesting
+    open fun isCopyOperationForErrorDialog(): Boolean {
+        return isPreviousTransferCopy
+    }
+
+    @OpenForTesting
+    open fun moveFiles(context: Context) {
         val serviceIntent = getServiceIntent(context)
         serviceIntent.putExtra(KEEP_ORIGINAL_EXTRA, false)
+        persistUriPermissions(context)
         context.startForegroundService(serviceIntent)
         finishFlow()
     }
 
-    fun copyFiles(context: Context) {
+    @OpenForTesting
+    open fun copyFiles(context: Context) {
         val serviceIntent = getServiceIntent(context)
         serviceIntent.putExtra(KEEP_ORIGINAL_EXTRA, true)
+        persistUriPermissions(context)
         context.startForegroundService(serviceIntent)
         finishFlow()
     }
 
-    fun finishFlow() {
+    @OpenForTesting
+    open fun finishFlow() {
         uiState = PrivateSpaceUiState.FINISHED
     }
 
+    fun validateSelectedFileLimits(context: Context, uris: List<Uri>): Boolean {
+        val numberOfFiles = uris.size
+        val totalBytes =
+            storageHelper.calculateTotalSize(
+                context,
+                uris,
+                { uri, e ->
+                    Log.e(
+                        TAG,
+                        "calculateTotalSize: Unable to get the file size for the uri $uri",
+                        e,
+                    )
+                },
+            )
+
+        val availableDeviceStorage = storageHelper.getAvailableDeviceStorage()
+        if (totalBytes > MAXIMUM_TRANSFER_BYTES_ALLOWED) {
+            uiState = PrivateSpaceUiState.SHOW_ABOVE_FILE_SIZE_LIMITS_DIALOG
+            Log.w(
+                TAG,
+                "Total files size is above the $MAXIMUM_TRANSFER_BYTES_ALLOWED maximum transfer bytes",
+            )
+            return false
+        }
+        if (totalBytes > availableDeviceStorage) {
+            uiState = PrivateSpaceUiState.SHOW_NOT_ENOUGH_SPACE_DIALOG
+            Log.w(
+                TAG,
+                "Total files size is above the $availableDeviceStorage available device storage",
+            )
+            return false
+        }
+        if (numberOfFiles > MAXIMUM_NUMBER_OF_FILES_ALLOWED) {
+            uiState = PrivateSpaceUiState.SHOW_TOO_MANY_FILES_SELECTED_DIALOG
+            Log.w(
+                TAG,
+                "$numberOfFiles files selected which is above $MAXIMUM_NUMBER_OF_FILES_ALLOWED allowed number of files to transfer at once.",
+            )
+            return false
+        }
+        return true
+    }
+
     private fun getServiceIntent(context: Context): Intent {
         val intent = Intent(context, FileTransferService::class.java)
-        intent.putParcelableArrayListExtra(SOURCE_URIS_EXTRA, ArrayList(fileUris))
+        intent.putParcelableArrayListExtra(SOURCE_URIS_EXTRA, fileUris)
         intent.putExtra(DESTINATION_PATH_EXTRA, Environment.DIRECTORY_DOWNLOADS)
         return intent
     }
+
+    private fun persistUriPermissions(context: Context) {
+        fileUris.forEach { uri ->
+            context.contentResolver.takePersistableUriPermission(
+                uri,
+                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
+            )
+        }
+    }
 }
diff --git a/src/com/android/privatespace/StorageHelper.kt b/src/com/android/privatespace/StorageHelper.kt
new file mode 100644
index 0000000..dfee05b
--- /dev/null
+++ b/src/com/android/privatespace/StorageHelper.kt
@@ -0,0 +1,73 @@
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
+package com.android.privatespace
+
+import android.content.Context
+import android.net.Uri
+import android.os.Environment
+import android.os.StatFs
+import java.io.File
+import java.io.FileNotFoundException
+
+/** An interface declaring storage operations helper methods */
+interface StorageHelper {
+    fun getAvailableDeviceStorage(): Long
+
+    fun calculateTotalSize(
+        context: Context,
+        uris: List<Uri>,
+        onError: (Uri, Exception) -> Unit,
+    ): Long
+}
+
+/** Singleton implementation of {@link StorageHelper} */
+object StorageHelperImpl : StorageHelper {
+    private const val AVAILABLE_DEVICE_STORAGE_BUFFER: Long = 256_000_000L
+
+    override fun getAvailableDeviceStorage(): Long {
+        val file = File(Environment.getExternalStorageDirectory().absolutePath)
+        val stat = StatFs(file.path)
+        val availableBytes = stat.availableBlocksLong * stat.blockSizeLong
+        return availableBytes - AVAILABLE_DEVICE_STORAGE_BUFFER
+    }
+
+    override fun calculateTotalSize(
+        context: Context,
+        uris: List<Uri>,
+        onError: (Uri, Exception) -> Unit,
+    ): Long {
+        var totalBytes: Long = 0
+        for (fileUri in uris) {
+            try {
+                context.contentResolver.openFileDescriptor(fileUri, "r")?.use { fileDescriptor ->
+                    totalBytes += fileDescriptor.statSize
+                }
+                    ?: {
+                        onError(
+                            fileUri,
+                            IllegalStateException(
+                                "A null ParcelFileDescriptor was returned from ContentResolver"
+                            ),
+                        )
+                    }
+            } catch (e: FileNotFoundException) {
+                onError(fileUri, e)
+            }
+        }
+        return totalBytes
+    }
+}
diff --git a/src/com/android/privatespace/ThreeButtonAlertDialog.kt b/src/com/android/privatespace/ThreeButtonAlertDialog.kt
index 3186e8f..d65f0af 100644
--- a/src/com/android/privatespace/ThreeButtonAlertDialog.kt
+++ b/src/com/android/privatespace/ThreeButtonAlertDialog.kt
@@ -51,12 +51,7 @@ fun ThreeButtonAlertDialog(
 ) {
     BasicAlertDialog(
         onDismissRequest = { onDismissRequest() },
-        properties =
-            DialogProperties(
-                dismissOnBackPress = true,
-                dismissOnClickOutside = true,
-                usePlatformDefaultWidth = false,
-            ),
+        properties = DialogProperties(usePlatformDefaultWidth = false),
     ) {
         Surface(
             shape = MaterialTheme.shapes.extraLarge,
@@ -80,8 +75,8 @@ fun ThreeButtonAlertDialog(
 
                 FlowRow(
                     modifier = Modifier.fillMaxWidth(),
-                    verticalArrangement = Arrangement.spacedBy(10.dp),
-                    horizontalArrangement = Arrangement.End,
+                    verticalArrangement = Arrangement.spacedBy(8.dp),
+                    horizontalArrangement = Arrangement.spacedBy(8.dp, alignment = Alignment.End),
                 ) {
                     dismissButton()
                     Spacer(modifier = Modifier.weight(1.0f))
diff --git a/src/com/android/privatespace/filetransfer/FileTransferManagerImpl.kt b/src/com/android/privatespace/filetransfer/FileTransferManagerImpl.kt
index 1dc18e1..1fda6c3 100644
--- a/src/com/android/privatespace/filetransfer/FileTransferManagerImpl.kt
+++ b/src/com/android/privatespace/filetransfer/FileTransferManagerImpl.kt
@@ -23,8 +23,12 @@ import android.os.SystemClock
 import android.provider.DocumentsContract
 import android.provider.MediaStore
 import android.util.Log
+import com.android.privatespace.StorageHelper
+import com.android.privatespace.StorageHelperImpl
 import java.io.FileNotFoundException
 import java.io.IOException
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.launch
 
 /**
  * An object responsible for transferring selected files to the current and removing the original
@@ -34,12 +38,18 @@ import java.io.IOException
  */
 class FileTransferManagerImpl(
     private var notificationsHelper: NotificationsHelper,
-    context: Context,
+    private var context: Context,
+    private var fileTransferStateRepository: IFileTransferStateRepository,
+    private val scope: CoroutineScope,
+    private var storageHelper: StorageHelper = StorageHelperImpl,
 ) : IFileTransferManager {
     private val contentResolver = context.contentResolver
+    private var lastUpdatedTime: Long = 0L
+    private var totalCopiedBytes: Long = 0L
+    var failedToTransferSomeFiles = false
 
     companion object {
-        private const val TAG: String = "FileTransferImpl"
+        private const val TAG: String = "FileTransferManagerImpl"
         private const val DEFAULT_MIMETYPE = "application/octet-stream"
         private const val PROGRESS_NOTIFICATION_UPDATE_INTERVAL_MS: Long = 1000L
         private const val BUFFER_SIZE = 1024
@@ -50,27 +60,41 @@ class FileTransferManagerImpl(
         keepOriginal: Boolean,
         destinationPath: String,
     ) {
+        updateTransferState(keepOriginal, transferInProgress = true)
         val numberOfFiles: Int = uris.size
         var progress: Int = 0
-        var copiedBytes: Long = 0L
 
         val totalBytes =
-            try {
-                calculateTotalSize(uris)
-            } catch (e: FileNotFoundException) {
-                // TODO(b/394024024) Notify user that the transfer could not be completed
-                Log.e(TAG, "transferFiles: Unable to get the total size of the files. ", e)
-                return
-            }
+            storageHelper.calculateTotalSize(
+                context,
+                uris,
+                { uri, e ->
+                    logAndMarkError(
+                        logMessage =
+                            "calculateTotalSize: Unable to get the file size for the uri $uri",
+                        exception = e,
+                    )
+                    scope.launch { updateTransferState(keepOriginal, transferInProgress = false) }
+                },
+            )
 
-        // TODO(b/394024024) Files size and available storage checks
+        lastUpdatedTime = SystemClock.elapsedRealtime()
+
+        val availableDeviceStorage = storageHelper.getAvailableDeviceStorage()
+        if (totalBytes > availableDeviceStorage) {
+            notificationsHelper.postNotEnoughStorageNotification(keepOriginal)
+            logAllFilesFailedTransfer(
+                logMessage =
+                    "Total files size is above the $availableDeviceStorage available device storage"
+            )
+            return
+        }
 
         // Copy/Move each individual file
         for (sourceUri in uris) {
             val metadata = getFileMetadata(sourceUri)
             if (metadata == null) {
-                // TODO(b/401000421): Deliver a notification to the user about this failed file
-                Log.e(TAG, "Unable to get metadata for uri: $sourceUri")
+                logAndMarkError(logMessage = "Unable to get metadata for uri: $sourceUri")
                 continue
             }
 
@@ -79,13 +103,12 @@ class FileTransferManagerImpl(
 
             val newUri = createNewMediaEntry(displayName, mimeType, destinationPath)
             if (newUri == null) {
-                // TODO(b/401000421): Deliver a notification to the user about this failed file
-                Log.e(TAG, "Failed to create new media entry for: $displayName")
+                logAndMarkError(logMessage = "Failed to create new media entry for: $displayName")
                 continue
             }
 
             // TODO(b/403206691): We should probably do this operation in parallel
-            copiedBytes +=
+            totalCopiedBytes +=
                 copySingleFile(sourceUri, newUri, totalBytes) { newProgress ->
                     if (newProgress - progress >= 1) {
                         progress = newProgress
@@ -99,7 +122,19 @@ class FileTransferManagerImpl(
 
             removeFileIfRequired(sourceUri, keepOriginal)
         }
-        notificationsHelper.displayCompletionNotification(numberOfFiles, keepOriginal)
+    }
+
+    /**
+     * Display the end of transfer notification. If there are some files that failed to transfer, a
+     * partial transfer notification will be displayed. Otherwise a successful transfer completion
+     * notification will be shown.
+     */
+    suspend fun postEndOfTransferNotification(numberOfFiles: Int, keepOriginal: Boolean) {
+        if (failedToTransferSomeFiles) {
+            notificationsHelper.displayPartialTransferErrorNotification(keepOriginal)
+            return
+        }
+        notificationsHelper.displaySuccessfulCompletionNotification(numberOfFiles, keepOriginal)
     }
 
     /** Retrieves file metadata such as display name and MIME type. */
@@ -122,10 +157,13 @@ class FileTransferManagerImpl(
                     val mimeType: String = contentResolver.getType(uri) ?: DEFAULT_MIMETYPE
                     return FileMetadata(displayName, mimeType)
                 } catch (e: IllegalArgumentException) {
-                    Log.e(TAG, "getFileMetadata: Could not retrieve the file name ", e)
+                    logAndMarkError(
+                        logMessage = "getFileMetadata: Could not retrieve the file name ",
+                        e,
+                    )
                 }
             }
-        } ?: Log.e(TAG, "Failed to query URI: $uri")
+        } ?: { logAndMarkError(logMessage = "Failed to query URI: $uri") }
         return null
     }
 
@@ -156,59 +194,45 @@ class FileTransferManagerImpl(
         totalBytes: Long,
         onProgressUpdate: (Int) -> Unit,
     ): Long {
-        var copiedBytes = 0L
+        var currentFileCopiedBytes = 0L
 
         try {
             contentResolver.openInputStream(sourceUri)?.use { inputStream ->
                 contentResolver.openOutputStream(destinationUri)?.use { outputStream ->
                     val buffer = ByteArray(BUFFER_SIZE)
                     var length: Int
-                    var lastUpdated = SystemClock.elapsedRealtime()
 
                     while (inputStream.read(buffer).also { length = it } > 0) {
                         outputStream.write(buffer, 0, length)
-                        copiedBytes += length
+                        currentFileCopiedBytes += length
 
                         val newProgress =
                             if (totalBytes == 0L) {
                                 100
                             } else {
-                                ((copiedBytes * 100) / totalBytes).toInt()
+                                (((totalCopiedBytes + currentFileCopiedBytes) * 100) / totalBytes)
+                                    .toInt()
                             }
                         val currentTime = SystemClock.elapsedRealtime()
 
-                        if (currentTime - lastUpdated > PROGRESS_NOTIFICATION_UPDATE_INTERVAL_MS) {
+                        if (
+                            currentTime - lastUpdatedTime > PROGRESS_NOTIFICATION_UPDATE_INTERVAL_MS
+                        ) {
                             onProgressUpdate(newProgress)
-                            lastUpdated = currentTime
+                            lastUpdatedTime = currentTime
                         }
                     }
                 }
                     ?: {
-                        // TODO(b/401000421): Maybe deliver a notification to the user about this
-                        // failed file
-                        Log.e(TAG, "Failed to open output stream for URI: $destinationUri")
+                        logAndMarkError(
+                            logMessage = "Failed to open output stream for URI: $destinationUri"
+                        )
                     }
-            }
-                ?: {
-                    // TODO(b/401000421): Maybe deliver a notification to the user about this failed
-                    // file
-                    Log.e(TAG, "Failed to open input stream for URI: $sourceUri")
-                }
+            } ?: { logAndMarkError(logMessage = "Failed to open input stream for URI: $sourceUri") }
         } catch (e: IOException) {
-            // TODO(b/401000421): Maybe deliver a notification to the user about this failed file
-            Log.e(TAG, "Error copying file: ${e.message}")
+            logAndMarkError(logMessage = "Error copying file: ${e.message}")
         }
-
-        return copiedBytes
-    }
-
-    @Throws(FileNotFoundException::class)
-    private fun calculateTotalSize(uris: List<Uri>): Long {
-        var totalBytes: Long = 0
-        for (fileUri in uris) {
-            totalBytes += contentResolver.openFileDescriptor(fileUri, "r")?.statSize ?: 0L
-        }
-        return totalBytes
+        return currentFileCopiedBytes
     }
 
     private fun removeFileIfRequired(sourceUri: Uri, keepOriginal: Boolean) {
@@ -216,9 +240,26 @@ class FileTransferManagerImpl(
             try {
                 DocumentsContract.deleteDocument(contentResolver, sourceUri)
             } catch (e: FileNotFoundException) {
-                // TODO(b/394024024) Handle this gracefully
-                Log.e(TAG, "Unable to remove the original file: ${e.message}")
+                logAndMarkError(logMessage = "Unable to remove the original file:", e)
             }
         }
     }
+
+    private fun logAndMarkError(logMessage: String) {
+        failedToTransferSomeFiles = true
+        Log.e(TAG, logMessage)
+    }
+
+    private fun logAndMarkError(logMessage: String, exception: Exception) {
+        failedToTransferSomeFiles = true
+        Log.e(TAG, logMessage, exception)
+    }
+
+    private fun logAllFilesFailedTransfer(logMessage: String) {
+        Log.e(TAG, logMessage)
+    }
+
+    private suspend fun updateTransferState(keepOriginal: Boolean, transferInProgress: Boolean) {
+        fileTransferStateRepository.saveState(context, keepOriginal, transferInProgress)
+    }
 }
diff --git a/src/com/android/privatespace/filetransfer/FileTransferService.kt b/src/com/android/privatespace/filetransfer/FileTransferService.kt
index c20e690..48d3289 100644
--- a/src/com/android/privatespace/filetransfer/FileTransferService.kt
+++ b/src/com/android/privatespace/filetransfer/FileTransferService.kt
@@ -22,7 +22,6 @@ import android.net.Uri
 import android.os.Environment
 import android.os.IBinder
 import android.util.Log
-import java.util.ArrayList
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.launch
@@ -46,17 +45,20 @@ class FileTransferService(
          * with guidelines for {@link MediaStore.MediaColumns.RELATIVE_PATH}
          */
         const val DESTINATION_PATH_EXTRA: String = "destination_path"
-
+        private var keepOriginal: Boolean = true
         private const val TAG: String = "FileTransferService"
     }
 
+    var uris: List<Uri>? = null
+
     override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
         val uris: ArrayList<Uri>? =
             intent.getParcelableArrayListExtra(SOURCE_URIS_EXTRA, Uri::class.java)
-        val keepOriginal = intent.getBooleanExtra(KEEP_ORIGINAL_EXTRA, true)
+        keepOriginal = intent.getBooleanExtra(KEEP_ORIGINAL_EXTRA, true)
         val destinationPath =
             intent.getStringExtra(DESTINATION_PATH_EXTRA) ?: Environment.DIRECTORY_DOWNLOADS
 
+        this.uris = uris
         uris?.let {
             val numberOfFiles = it.size
             if (numberOfFiles == 0) {
@@ -67,7 +69,13 @@ class FileTransferService(
             val notificationsHelper = NotificationsHelper(applicationContext)
             notificationsHelper.createNotificationChannel()
 
-            val fileTransferImpl = FileTransferManagerImpl(notificationsHelper, applicationContext)
+            val fileTransferImpl =
+                FileTransferManagerImpl(
+                    notificationsHelper,
+                    applicationContext,
+                    FileTransferStateRepository,
+                    serviceScope,
+                )
 
             serviceScope.launch {
                 startForeground(
@@ -75,8 +83,14 @@ class FileTransferService(
                     notificationsHelper.buildProgressNotification(0, numberOfFiles, keepOriginal),
                 )
                 fileTransferImpl.transferFiles(it, keepOriginal, destinationPath)
-                stopForeground(STOP_FOREGROUND_DETACH)
+                stopForeground(STOP_FOREGROUND_REMOVE)
                 stopSelf()
+                fileTransferImpl.postEndOfTransferNotification(numberOfFiles, keepOriginal)
+                FileTransferStateRepository.saveState(
+                    applicationContext,
+                    keepOriginal,
+                    transferInProgress = false,
+                )
             }
         }
             ?:
@@ -89,4 +103,14 @@ class FileTransferService(
     override fun onBind(intent: Intent?): IBinder? {
         return null
     }
+
+    override fun onDestroy() {
+        // TODO (b/400701740): Add tests for releasing the permissions
+        uris?.forEach { uri ->
+            applicationContext.contentResolver.releasePersistableUriPermission(
+                uri,
+                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
+            )
+        }
+    }
 }
diff --git a/src/com/android/privatespace/filetransfer/FileTransferStateChecker.kt b/src/com/android/privatespace/filetransfer/FileTransferStateChecker.kt
new file mode 100644
index 0000000..a22dd4a
--- /dev/null
+++ b/src/com/android/privatespace/filetransfer/FileTransferStateChecker.kt
@@ -0,0 +1,42 @@
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
+package com.android.privatespace.filetransfer
+
+import android.content.Context
+
+/**
+ * Checks the file transfer state and triggers a notification if the transfer was still in progress
+ *
+ * @property fileTransferStateRepository The state repository for the file transfer.
+ * @property notificationsHelper The helper for displaying notifications.
+ */
+class FileTransferStateChecker(
+    private val fileTransferStateRepository: IFileTransferStateRepository,
+    private val notificationsHelper: NotificationsHelper,
+) {
+    suspend fun postBootTransferStateCheck(context: Context) {
+        val transferState = fileTransferStateRepository.getTransferState(context)
+        if (transferState.transferInProgress) {
+            notificationsHelper.displayInterruptedTransferNotification(transferState.keepOriginal)
+            fileTransferStateRepository.saveState(
+                context,
+                transferState.keepOriginal,
+                transferInProgress = false,
+            )
+        }
+    }
+}
diff --git a/src/com/android/privatespace/filetransfer/FileTransferStateRepository.kt b/src/com/android/privatespace/filetransfer/FileTransferStateRepository.kt
new file mode 100644
index 0000000..e2b5210
--- /dev/null
+++ b/src/com/android/privatespace/filetransfer/FileTransferStateRepository.kt
@@ -0,0 +1,69 @@
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
+package com.android.privatespace.filetransfer
+
+import android.content.Context
+import androidx.datastore.preferences.core.booleanPreferencesKey
+import androidx.datastore.preferences.core.edit
+import androidx.datastore.preferences.preferencesDataStore
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.flow.map
+
+/** Interface for managing the writes and reads of the state of file transfer. */
+interface IFileTransferStateRepository {
+    /** Saves the state of the file transfer. */
+    suspend fun saveState(context: Context, keepOriginal: Boolean, transferInProgress: Boolean)
+
+    /** Returns the current state of the file transfer. */
+    suspend fun getTransferState(context: Context): TransferState
+}
+
+/** Manages the writes and reads of the state of file transfer */
+object FileTransferStateRepository : IFileTransferStateRepository {
+    private val Context.dataStore by preferencesDataStore(name = FILE_TRANSFER_PREFS_KEY)
+
+    private const val FILE_TRANSFER_PREFS_KEY = "file_transfer_prefs"
+    private val KEEP_ORIGINAL_KEY = booleanPreferencesKey("keep_original")
+    private val TRANSFER_IN_PROGRESS_KEY = booleanPreferencesKey("transfer_in_progress")
+
+    override suspend fun saveState(
+        context: Context,
+        keepOriginal: Boolean,
+        transferInProgress: Boolean,
+    ) {
+        context.dataStore.edit { prefs ->
+            prefs[KEEP_ORIGINAL_KEY] = keepOriginal
+            prefs[TRANSFER_IN_PROGRESS_KEY] = transferInProgress
+        }
+    }
+
+    /**
+     * Returns the current {@link TransferState}.
+     *
+     * If there is no state saved, it means that no file transfer is in progress. The default value
+     * for keepOriginal file is true, while the default for transferInProgress is false
+     */
+    override suspend fun getTransferState(context: Context): TransferState {
+        return context.dataStore.data
+            .map { prefs ->
+                val keepOriginal = prefs[KEEP_ORIGINAL_KEY] ?: true
+                val transferInProgress = prefs[TRANSFER_IN_PROGRESS_KEY] ?: false
+                TransferState(keepOriginal, transferInProgress)
+            }
+            .first()
+    }
+}
diff --git a/src/com/android/privatespace/filetransfer/NotificationsHelper.kt b/src/com/android/privatespace/filetransfer/NotificationsHelper.kt
index 4d59a42..e697346 100644
--- a/src/com/android/privatespace/filetransfer/NotificationsHelper.kt
+++ b/src/com/android/privatespace/filetransfer/NotificationsHelper.kt
@@ -23,14 +23,22 @@ import android.app.NotificationManager
 import android.app.PendingIntent
 import android.content.Context
 import android.content.Intent
+import android.graphics.drawable.Icon
+import android.icu.text.MessageFormat
+import android.provider.Settings
+import androidx.annotation.OpenForTesting
 import com.android.privatespace.R
+import java.util.HashMap
+import java.util.Locale
 import java.util.concurrent.atomic.AtomicBoolean
 
 /** A helper class to send file transfer progress and completion notifications to the user */
-class NotificationsHelper(private val context: Context) {
+@OpenForTesting
+open class NotificationsHelper(val context: Context) {
 
     companion object {
         private val NOTIFICATION_CHANNEL_ID: String = "FileTransferProgress"
+        private const val COUNT_NOTIFICATION_ARGUMENT_KEY: String = "count"
         const val NOTIFICATION_ID: Int = 1
     }
 
@@ -39,7 +47,8 @@ class NotificationsHelper(private val context: Context) {
     private var notificationManager: NotificationManager =
         context.getSystemService(NotificationManager::class.java)
 
-    fun createNotificationChannel() {
+    @OpenForTesting
+    open fun createNotificationChannel() {
         val channel =
             NotificationChannel(
                 NOTIFICATION_CHANNEL_ID,
@@ -51,7 +60,7 @@ class NotificationsHelper(private val context: Context) {
         notificationManager.createNotificationChannel(channel)
     }
 
-    fun displayCompletionNotification(numberOfFiles: Int, keepOriginal: Boolean) {
+    fun displaySuccessfulCompletionNotification(numberOfFiles: Int, keepOriginal: Boolean) {
         canUpdateProgressNotification.getAndSet(false)
         val notification = buildCompletionNotification(numberOfFiles, keepOriginal)
         notificationManager.notify(NOTIFICATION_ID, notification)
@@ -64,6 +73,81 @@ class NotificationsHelper(private val context: Context) {
         }
     }
 
+    @OpenForTesting
+    open fun displayInterruptedTransferNotification(keepOriginal: Boolean) {
+        val notification =
+            baseNotificationBuilder(
+                    context.resources.getString(
+                        if (keepOriginal)
+                            R.string.filetransfer_notification_incomplete_copy_transfer_title
+                        else R.string.filetransfer_notification_incomplete_move_transfer_title
+                    ),
+                    context.resources.getString(
+                        if (keepOriginal)
+                            R.string.filetransfer_notification_incomplete_copy_transfer_message
+                        else R.string.filetransfer_notification_incomplete_move_transfer_message
+                    ),
+                    context,
+                )
+                .build()
+        notificationManager.notify(NOTIFICATION_ID, notification)
+    }
+
+    fun displayPartialTransferErrorNotification(keepOriginal: Boolean) {
+        val notification =
+            baseNotificationBuilder(
+                    context.resources.getString(
+                        if (keepOriginal)
+                            R.string.filetransfer_notification_partial_copy_error_title
+                        else R.string.filetransfer_notification_partial_move_error_title
+                    ),
+                    context.resources.getString(
+                        if (keepOriginal) R.string.filetransfer_generic_copy_error_message
+                        else R.string.filetransfer_generic_move_error_message
+                    ),
+                    context,
+                )
+                .setOngoing(false)
+                .build()
+        notificationManager.notify(NOTIFICATION_ID, notification)
+    }
+
+    fun postNotEnoughStorageNotification(keepOriginal: Boolean) {
+        val openFileIntent = Intent(Settings.ACTION_INTERNAL_STORAGE_SETTINGS)
+        val pendingIntent =
+            PendingIntent.getActivity(
+                context,
+                0,
+                openFileIntent,
+                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
+            )
+        val notification: Notification =
+            baseNotificationBuilder(
+                    context.resources.getString(
+                        if (keepOriginal) R.string.filetransfer_notification_copy_error_title
+                        else R.string.filetransfer_notification_move_error_title
+                    ),
+                    context.resources.getString(
+                        R.string.filetransfer_notification_insufficient_storage_error_message
+                    ),
+                    context,
+                )
+                .setOngoing(false)
+                .addAction(
+                    Notification.Action.Builder(
+                            Icon.createWithResource(context, R.drawable.ic_private_profile_badge),
+                            context.resources.getString(
+                                R.string.filetransfer_notification_not_enough_storage_error_action
+                            ),
+                            pendingIntent,
+                        )
+                        .build()
+                )
+                .build()
+
+        notificationManager.notify(NOTIFICATION_ID, notification)
+    }
+
     fun buildProgressNotification(
         progress: Int,
         numberOfFiles: Int,
@@ -73,18 +157,22 @@ class NotificationsHelper(private val context: Context) {
         openFileIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
 
         val notificationTitle =
-            context.resources.getString(
-                if (keepOriginal) R.string.filetransfer_notification_copy_progress_title
-                else R.string.filetransfer_notification_move_progress_title,
+            applyFilesCount(
+                context.resources.getString(
+                    if (keepOriginal) R.string.filetransfer_notification_copy_progress_title
+                    else R.string.filetransfer_notification_move_progress_title
+                ),
                 numberOfFiles,
             )
+
         val notificationText =
-            context
-                .getResources()
-                .getString(
+            applyFilesCount(
+                context.resources.getString(
                     if (keepOriginal) R.string.filetransfer_notification_copy_progress_text
                     else R.string.filetransfer_notification_move_progress_text
-                )
+                ),
+                numberOfFiles,
+            )
 
         val pendingIntent =
             PendingIntent.getActivity(
@@ -100,7 +188,7 @@ class NotificationsHelper(private val context: Context) {
             .setContentIntent(pendingIntent)
             .addAction(
                 Notification.Action.Builder(
-                        R.drawable.ic_private_profile_badge,
+                        Icon.createWithResource(context, R.drawable.ic_private_profile_badge),
                         context.resources.getString(
                             R.string.filetransfer_notification_action_label
                         ),
@@ -119,15 +207,21 @@ class NotificationsHelper(private val context: Context) {
         openFileIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
 
         val notificationTitle =
-            context.resources.getString(
-                if (keepOriginal) R.string.filetransfer_notification_copy_complete_title
-                else R.string.filetransfer_notification_move_complete_title,
+            applyFilesCount(
+                context.resources.getString(
+                    if (keepOriginal) R.string.filetransfer_notification_copy_complete_title
+                    else R.string.filetransfer_notification_move_complete_title
+                ),
                 numberOfFiles,
             )
+
         val notificationText =
-            context.resources.getString(
-                if (keepOriginal) R.string.filetransfer_notification_copy_complete_text
-                else R.string.filetransfer_notification_move_complete_text
+            applyFilesCount(
+                context.resources.getString(
+                    if (keepOriginal) R.string.filetransfer_notification_copy_complete_text
+                    else R.string.filetransfer_notification_move_complete_text
+                ),
+                numberOfFiles,
             )
 
         val pendingIntent =
@@ -141,10 +235,9 @@ class NotificationsHelper(private val context: Context) {
         return baseNotificationBuilder(notificationTitle, notificationText, context)
             .setOngoing(false)
             .setContentIntent(pendingIntent)
-            .setAutoCancel(true)
             .addAction(
                 Notification.Action.Builder(
-                        R.drawable.ic_private_profile_badge,
+                        Icon.createWithResource(context, R.drawable.ic_private_profile_badge),
                         context.resources.getString(
                             R.string.filetransfer_notification_action_label
                         ),
@@ -165,5 +258,13 @@ class NotificationsHelper(private val context: Context) {
             .setContentText(contentText)
             .setSmallIcon(R.drawable.ic_private_profile_badge)
             .setOnlyAlertOnce(true)
+            .setAutoCancel(true)
+    }
+
+    private fun applyFilesCount(msg: String, count: Int): String {
+        val msgFormat = MessageFormat(msg, Locale.getDefault())
+        val arguments = HashMap<String, Any>()
+        arguments.put(COUNT_NOTIFICATION_ARGUMENT_KEY, count)
+        return msgFormat.format(arguments)
     }
 }
diff --git a/src/com/android/privatespace/filetransfer/TransferState.kt b/src/com/android/privatespace/filetransfer/TransferState.kt
new file mode 100644
index 0000000..06c11d6
--- /dev/null
+++ b/src/com/android/privatespace/filetransfer/TransferState.kt
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
+
+package com.android.privatespace.filetransfer
+
+/**
+ * Data class to hold the state of a file transfer.
+ *
+ * @property keepOriginal Whether to keep the original file after the transfer.
+ * @property transferInProgress a boolean indicating whether the transfer is still in progress or
+ *   not.
+ */
+data class TransferState(val keepOriginal: Boolean, val transferInProgress: Boolean)
diff --git a/tests/Android.bp b/tests/Android.bp
deleted file mode 100644
index 1c4f3ad..0000000
--- a/tests/Android.bp
+++ /dev/null
@@ -1,19 +0,0 @@
-package {
-    // See: http://go/android-license-faq
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-android_test {
-    name: "PrivateSpaceTests",
-    certificate: "platform",
-    srcs: [
-        "src/**/*.kt",
-    ],
-    static_libs: [
-        "androidx.test.runner",
-        "androidx.test.ext.junit",
-    ],
-    test_suites: [
-        "general-tests",
-    ],
-}
diff --git a/tests/integration/Android.bp b/tests/integration/Android.bp
new file mode 100644
index 0000000..8f6f1a6
--- /dev/null
+++ b/tests/integration/Android.bp
@@ -0,0 +1,29 @@
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "PrivateSpaceIntegrationTests",
+    certificate: "platform",
+    sdk_version: "system_current",
+    srcs: [
+        "src/**/*.kt",
+    ],
+    static_libs: [
+        "androidx.test.runner",
+        "androidx.test.ext.junit",
+        "androidx.test.ext.truth",
+        "androidx.test.uiautomator_uiautomator",
+        "PrivateSpaceLibrary",
+        "bedstead-multiuser",
+        "flag-junit",
+        "android.multiuser.flags-aconfig-java",
+    ],
+    associates: [
+        "PrivateSpaceLibrary",
+    ],
+    test_suites: [
+        "general-tests",
+    ],
+}
diff --git a/tests/integration/AndroidManifest.xml b/tests/integration/AndroidManifest.xml
new file mode 100644
index 0000000..bdf9929
--- /dev/null
+++ b/tests/integration/AndroidManifest.xml
@@ -0,0 +1,29 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.privatespace.integration">
+
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation
+        android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:label="Private Space Integration Tests"
+        android:targetPackage="com.android.privatespace.integration" />
+
+    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS"/>
+</manifest>
diff --git a/tests/integration/AndroidTest.xml b/tests/integration/AndroidTest.xml
new file mode 100644
index 0000000..2c53fe7
--- /dev/null
+++ b/tests/integration/AndroidTest.xml
@@ -0,0 +1,29 @@
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
+<configuration description="Integration Tests for PrivateSpace">
+    <option name="test-suite-tag" value="device-tests" />
+    <option name="config-descriptor:metadata" key="parameter" value="multiuser" />
+    <target_preparer class="com.android.tradefed.targetprep.TestAppInstallSetup">
+        <option name="test-file-name" value="PrivateSpaceIntegrationTests.apk" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest">
+        <option name="package" value="com.android.privatespace.integration" />
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+        <option name="exclude-annotation" value="com.android.bedstead.harrier.annotations.RequireRunOnWorkProfile" />
+        <option name="exclude-annotation" value="com.android.bedstead.harrier.annotations.RequireRunOnSecondaryUser" />
+    </test>
+</configuration>
diff --git a/tests/integration/res/drawable/android.png b/tests/integration/res/drawable/android.png
new file mode 100644
index 0000000..8a9e698
Binary files /dev/null and b/tests/integration/res/drawable/android.png differ
diff --git a/tests/integration/src/MoveContentEndToEndTest.kt b/tests/integration/src/MoveContentEndToEndTest.kt
new file mode 100644
index 0000000..a4ca1fe
--- /dev/null
+++ b/tests/integration/src/MoveContentEndToEndTest.kt
@@ -0,0 +1,254 @@
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
+package com.android.privatespace.integration
+
+import android.content.ComponentName
+import android.content.ContentValues
+import android.content.Context
+import android.content.Intent
+import android.graphics.Bitmap
+import android.graphics.BitmapFactory
+import android.multiuser.Flags
+import android.net.Uri
+import android.os.Bundle
+import android.os.Environment
+import android.os.UserHandle
+import android.platform.test.annotations.RequiresFlagsEnabled
+import android.provider.MediaStore
+import android.util.Log
+import android.widget.TextView
+import androidx.test.InstrumentationRegistry
+import androidx.test.uiautomator.UiDevice
+import androidx.test.uiautomator.UiSelector
+import com.android.bedstead.harrier.BedsteadJUnit4
+import com.android.bedstead.harrier.annotations.NotificationsTest
+import com.android.bedstead.multiuser.annotations.RequireRunOnPrivateProfile
+import com.android.bedstead.nene.TestApis
+import com.android.bedstead.nene.notifications.NotificationListener
+import com.android.privatespace.PrivateSpaceActivity
+import com.android.privatespace.PrivateSpaceActivity.Companion.ACTION_ADD_FILES
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.Truth.assertWithMessage
+import java.io.File
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.runBlocking
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+@RunWith(BedsteadJUnit4::class)
+@RequireRunOnPrivateProfile
+class MoveContentEndToEndTest {
+    private lateinit var context: Context
+    private lateinit var parentContext: Context
+    private lateinit var device: UiDevice
+    private lateinit var imageTestFile: FileInfo
+    private lateinit var primaryUser: UserHandle
+
+    companion object {
+        private const val TAG: String = "MoveContentEndToEndTest"
+        private const val PRIVATE_SPACE_PACKAGE_NAME: String = "com.android.privatespace"
+        private const val PERSONAL_TAB_LABEL: String = "Personal"
+        private const val TEST_IMAGE_NAME_PREFIX: String = "test_image_"
+        private const val CHANNEL_ID: String = "FileTransferProgress"
+        private const val WAIT_TIMEOUT_MILLIS: Long = 5_000L
+        private const val DEFAULT_POLL_INTERVAL_MILLIS: Long = 100L
+        private val DOWNLOADS_FOLDER =
+            File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "")
+    }
+
+    @Before
+    fun setUp() {
+        context = InstrumentationRegistry.getInstrumentation().targetContext
+        primaryUser = TestApis.users().initial().userHandle()
+        parentContext = context.createPackageContextAsUser("android", 0, primaryUser)
+        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
+        createTestImageFile(parentContext)
+    }
+
+    @After
+    fun tearDown() {
+        removeOriginalFile(parentContext, imageTestFile.uri)
+    }
+
+    @Test
+    @NotificationsTest
+    fun testTransferOneFile_copyOperation() {
+        startActivityAndSelectFile()
+
+        TestApis.notifications().createListener().use { notifications ->
+            waitForVisibilityAndClick(
+                context.resources.getString(
+                    com.android.privatespace.R.string.move_files_dialog_button_label_copy
+                )
+            )
+            assertNotificationPosted(notifications)
+        }
+
+        verifyFileExistInPrivateSpace(
+            imageTestFile.name
+        ) // Tests run in the context of the private space user
+        assertThat(originalFileExist(parentContext, imageTestFile.uri)).isTrue()
+    }
+
+    @Test
+    @NotificationsTest
+    fun testTransferOneFile_moveOperation() {
+        startActivityAndSelectFile()
+
+        TestApis.notifications().createListener().use { notifications ->
+            waitForVisibilityAndClick(
+                context.resources.getString(
+                    com.android.privatespace.R.string.move_files_dialog_button_label_move
+                )
+            )
+            assertNotificationPosted(notifications)
+        }
+
+        verifyFileExistInPrivateSpace(
+            imageTestFile.name
+        ) // Tests run in the context of the private space user
+        assertThat(originalFileExist(parentContext, imageTestFile.uri)).isFalse()
+    }
+
+    private fun startActivityAndSelectFile() {
+        context.startActivity(
+            Intent(ACTION_ADD_FILES)
+                .setComponent(
+                    ComponentName(
+                        PRIVATE_SPACE_PACKAGE_NAME,
+                        PrivateSpaceActivity::class.qualifiedName.toString(),
+                    )
+                )
+                .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
+        )
+
+        waitForVisibilityAndClick(PERSONAL_TAB_LABEL)
+
+        waitForVisibilityAndClick(imageTestFile.name)
+    }
+
+    private fun createTestImageFile(context: Context) {
+        var originalFileInfo: FileInfo? =
+            savePngDrawableToMediaStore(
+                context,
+                R.drawable.android,
+                TEST_IMAGE_NAME_PREFIX + System.currentTimeMillis(),
+            )
+        assertWithMessage("Unable to create a test file").that(originalFileInfo).isNotNull()
+        imageTestFile = originalFileInfo!!
+    }
+
+    private fun savePngDrawableToMediaStore(
+        context: Context,
+        drawableResId: Int,
+        displayName: String,
+    ): FileInfo? {
+        val bitmap = BitmapFactory.decodeResource(context.resources, drawableResId)
+        val resolver = context.contentResolver
+
+        val contentValues =
+            ContentValues().apply {
+                put(MediaStore.Images.Media.DISPLAY_NAME, "$displayName.png")
+                put(MediaStore.Images.Media.MIME_TYPE, "image/png")
+                put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES)
+                put(MediaStore.Images.Media.IS_PENDING, 1)
+            }
+
+        val imageUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues)
+
+        imageUri?.let { uri ->
+            resolver.openOutputStream(uri)?.use { outputStream ->
+                bitmap.compress(Bitmap.CompressFormat.PNG, 100, outputStream)
+            }
+            contentValues.clear()
+            contentValues.put(MediaStore.Images.Media.IS_PENDING, 0)
+            resolver.update(uri, contentValues, null, null)
+        }
+        if (imageUri == null) {
+            return null
+        }
+
+        return FileInfo(uriWithUserId(imageUri, primaryUser.identifier), "$displayName.png")
+    }
+
+    private fun waitForVisibilityAndClick(label: String) {
+        val uiObject = device.findObject(UiSelector().text(label).className(TextView::class.java))
+        uiObject.waitForExists(WAIT_TIMEOUT_MILLIS)
+        uiObject.click()
+    }
+
+    private fun assertNotificationPosted(notifications: NotificationListener) {
+        com.android.bedstead.nene.notifications.NotificationListenerQuerySubject.assertThat(
+                notifications
+                    .query()
+                    .wherePackageName()
+                    .isEqualTo(PRIVATE_SPACE_PACKAGE_NAME)
+                    .whereNotification()
+                    .channelId()
+                    .isEqualTo(CHANNEL_ID)
+            )
+            .wasPosted()
+    }
+
+    private fun removeOriginalFile(context: Context, uri: Uri?) {
+        if (uri == null) {
+            return
+        }
+        try {
+            context.contentResolver.delete(uri, Bundle())
+        } catch (e: Exception) {
+            Log.e(TAG, "File already removed or unavailable: $uri", e)
+        }
+    }
+
+    private fun verifyFileExistInPrivateSpace(expectedFileName: String) {
+        val destinationFile = File(DOWNLOADS_FOLDER, expectedFileName)
+        runBlocking { assertThat(waitForCondition({ destinationFile.exists() })).isTrue() }
+    }
+
+    private suspend fun waitForCondition(
+        condition: () -> Boolean,
+        timeout: Long = WAIT_TIMEOUT_MILLIS,
+        pollInterval: Long = DEFAULT_POLL_INTERVAL_MILLIS,
+    ): Boolean {
+        val endTime = System.currentTimeMillis() + timeout
+        while (System.currentTimeMillis() < endTime) {
+            if (condition()) return true
+            delay(timeMillis = pollInterval)
+        }
+        return false
+    }
+
+    private fun originalFileExist(context: Context, uri: Uri): Boolean {
+        return try {
+            context.contentResolver.openFileDescriptor(uri, "r")?.use { true } ?: false
+        } catch (e: Exception) {
+            Log.e(TAG, "Unable to open uri: $uri", e)
+            false
+        }
+    }
+
+    private fun uriWithUserId(uri: Uri, userId: Int): Uri {
+        val builder = uri.buildUpon()
+        builder.encodedAuthority("" + userId + "@" + uri.getEncodedAuthority())
+        return builder.build()
+    }
+
+    data class FileInfo(val uri: Uri, val name: String)
+}
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
new file mode 100644
index 0000000..30f68d3
--- /dev/null
+++ b/tests/unit/Android.bp
@@ -0,0 +1,36 @@
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "PrivateSpaceTests",
+    certificate: "platform",
+    srcs: [
+        "src/**/*.kt",
+    ],
+    static_libs: [
+        "androidx.compose.ui_ui-test-junit4",
+        "androidx.compose.ui_ui-test-manifest",
+        "androidx.compose.runtime_runtime",
+        "androidx.test.core",
+        "androidx.test.espresso.intents",
+        "androidx.test.ext.junit",
+        "androidx.test.ext.truth",
+        "androidx.test.rules",
+        "androidx.test.runner",
+        "Harrier",
+        "flag-junit",
+        "kotlinx_coroutines_test",
+        "mockito-target-minus-junit4",
+        "mockito-kotlin2",
+        "platform-test-annotations",
+        "PrivateSpaceLibrary",
+    ],
+    associates: [
+        "PrivateSpaceLibrary",
+    ],
+    test_suites: [
+        "general-tests",
+    ],
+}
diff --git a/tests/AndroidManifest.xml b/tests/unit/AndroidManifest.xml
similarity index 93%
rename from tests/AndroidManifest.xml
rename to tests/unit/AndroidManifest.xml
index ab27f88..604ee54 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/unit/AndroidManifest.xml
@@ -25,4 +25,5 @@
         android:label="Private Space Tests"
         android:targetPackage="com.android.privatespace.tests" />
 
+    <uses-sdk android:minSdkVersion="36" android:targetSdkVersion="36" />
 </manifest>
diff --git a/tests/AndroidTest.xml b/tests/unit/AndroidTest.xml
similarity index 100%
rename from tests/AndroidTest.xml
rename to tests/unit/AndroidTest.xml
diff --git a/tests/unit/src/com/android/privatespace/PrivateSpaceActivityScreenTest.kt b/tests/unit/src/com/android/privatespace/PrivateSpaceActivityScreenTest.kt
new file mode 100644
index 0000000..be42ea5
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/PrivateSpaceActivityScreenTest.kt
@@ -0,0 +1,283 @@
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
+package com.android.privatespace
+
+import android.content.Context
+import android.multiuser.Flags
+import android.platform.test.annotations.RequiresFlagsEnabled
+import androidx.compose.ui.test.assertIsDisplayed
+import androidx.compose.ui.test.junit4.createComposeRule
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.onNodeWithText
+import androidx.compose.ui.test.performClick
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.kotlin.mock
+import org.mockito.kotlin.verify
+import org.mockito.kotlin.whenever
+
+@RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+@RunWith(AndroidJUnit4::class)
+class PrivateSpaceActivityScreenTest {
+
+    @get:Rule val composeTestRule = createComposeRule()
+
+    private lateinit var mockViewModel: PrivateSpaceViewModel
+    private lateinit var mockOnOpenDocumentsPicker: () -> Unit
+    private lateinit var mockOnFinished: () -> Unit
+    private lateinit var context: Context
+
+    @Before
+    fun setUp() {
+        context = ApplicationProvider.getApplicationContext()
+        mockViewModel = mock()
+        mockOnOpenDocumentsPicker = mock()
+        mockOnFinished = mock()
+    }
+
+    @Test
+    fun uiStateStarted_showsNothing() {
+        setScreenContent(PrivateSpaceUiState.STARTED)
+        // Check that known text from dialogs does NOT exist.
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_title))
+            .assertDoesNotExist()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .assertDoesNotExist()
+    }
+
+    @Test
+    fun uiStateCheckingTransferStatus_showsCircularProgressIndicator() {
+        setScreenContent(PrivateSpaceUiState.CHECKING_PROGRESS_INDICATOR)
+
+        composeTestRule
+            .onNodeWithTag(testTag = CIRCULAR_PROGRESS_INDICATOR_TEST_TAG)
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun uiShowDocumentPicker_callsOnOpenDocumentPicker() {
+        setScreenContent(PrivateSpaceUiState.SHOW_DOCUMENT_PICKER)
+
+        verify(mockOnOpenDocumentsPicker).invoke()
+    }
+
+    @Test
+    fun uiStateShowMoveFilesDialog_displaysDialogAndButtons() {
+        setScreenContent(PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_title))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_summary))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_button_label_move))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_button_label_copy))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_button_label_cancel))
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun showMoveFilesDialog_clickMoveButton_callsViewModelMoveFiles() {
+        setScreenContent(PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_button_label_move))
+            .performClick()
+
+        verify(mockViewModel).moveFiles(context)
+    }
+
+    @Test
+    fun showMoveFilesDialog_clickCopyButton_callsViewModelCopyFiles() {
+        setScreenContent(PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_button_label_copy))
+            .performClick()
+
+        verify(mockViewModel).copyFiles(context)
+    }
+
+    @Test
+    fun showMoveFilesDialog_clickCancelButton_callsViewModelFinishFlow() {
+        setScreenContent(PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.move_files_dialog_button_label_cancel))
+            .performClick()
+
+        verify(mockViewModel).finishFlow()
+    }
+
+    @Test
+    fun uiStateShowNotEnoughSpaceDialog_displaysErrorDialog() {
+        setScreenContent(PrivateSpaceUiState.SHOW_NOT_ENOUGH_SPACE_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(
+                context.getString(R.string.filetransfer_notification_transfer_error_title)
+            )
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(
+                context.getString(
+                    R.string.filetransfer_notification_insufficient_storage_error_message
+                )
+            )
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun uiStateShowNotEnoughSpaceDialog_clickDismissButton_callsViewModelFinishFlow() {
+        setScreenContent(PrivateSpaceUiState.SHOW_NOT_ENOUGH_SPACE_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .performClick()
+        verify(mockViewModel).finishFlow()
+    }
+
+    @Test
+    fun uiStateShowAboveFileSizeLimitsDialog_displaysErrorDialog() {
+        setScreenContent(PrivateSpaceUiState.SHOW_ABOVE_FILE_SIZE_LIMITS_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_large_files_size_error_title))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_large_files_size_error_message))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun uiStateShowAboveFileSizeLimitsDialog_clickDismissButton_callsViewModelFinishFlow() {
+        setScreenContent(PrivateSpaceUiState.SHOW_ABOVE_FILE_SIZE_LIMITS_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .performClick()
+        verify(mockViewModel).finishFlow()
+    }
+
+    @Test
+    fun uiStateShowTooManyFilesSelectedDialog_displaysErrorDialog() {
+        setScreenContent(PrivateSpaceUiState.SHOW_TOO_MANY_FILES_SELECTED_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_too_many_files_error_title))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_too_many_files_error_message))
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun uiStateShowTooManyFilesSelectedDialog_clickDismissButton_callsViewModelFinishFlow() {
+        setScreenContent(PrivateSpaceUiState.SHOW_TOO_MANY_FILES_SELECTED_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .performClick()
+        verify(mockViewModel).finishFlow()
+    }
+
+    @Test
+    fun uiStateShowTransferInProgressDialog_displaysCorrectTitle_whenMoving() {
+        whenever(mockViewModel.isCopyOperationForErrorDialog()).thenReturn(false)
+
+        setScreenContent(PrivateSpaceUiState.SHOW_TRANSFER_IN_PROGRESS_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(
+                context.getString(R.string.filetransfer_dialog_still_moving_error_title)
+            )
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(
+                context.getString(R.string.filetransfer_dialog_still_transferring_error_message)
+            )
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun uiStateShowTransferInProgressDialog_displaysCorrectTitle_whenCopying() {
+        whenever(mockViewModel.isCopyOperationForErrorDialog()).thenReturn(true)
+
+        setScreenContent(PrivateSpaceUiState.SHOW_TRANSFER_IN_PROGRESS_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(
+                context.getString(R.string.filetransfer_dialog_still_copying_error_title)
+            )
+            .assertIsDisplayed()
+        composeTestRule
+            .onNodeWithText(
+                context.getString(R.string.filetransfer_dialog_still_transferring_error_message)
+            )
+            .assertIsDisplayed()
+    }
+
+    @Test
+    fun uiStateShowTransferInProgressDialog_clickDismissButton_callsViewModelFinishFlow() {
+        setScreenContent(PrivateSpaceUiState.SHOW_TOO_MANY_FILES_SELECTED_DIALOG)
+
+        composeTestRule
+            .onNodeWithText(context.getString(R.string.filetransfer_error_dialog_button))
+            .performClick()
+        verify(mockViewModel).finishFlow()
+    }
+
+    @Test
+    fun uiStateFinished_callsOnFinishedLambda() {
+        setScreenContent(PrivateSpaceUiState.FINISHED)
+        verify(mockOnFinished).invoke()
+    }
+
+    private fun setScreenContent(uiState: PrivateSpaceUiState) {
+        whenever(mockViewModel.uiState).thenReturn(uiState)
+
+        composeTestRule.setContent {
+            PrivateSpaceActivityScreen(
+                viewModel = mockViewModel,
+                context = context,
+                onOpenDocumentsPicker = mockOnOpenDocumentsPicker,
+                onFinished = mockOnFinished,
+            )
+        }
+    }
+}
diff --git a/tests/unit/src/com/android/privatespace/PrivateSpaceActivityTest.kt b/tests/unit/src/com/android/privatespace/PrivateSpaceActivityTest.kt
new file mode 100644
index 0000000..68bd146
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/PrivateSpaceActivityTest.kt
@@ -0,0 +1,139 @@
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
+package com.android.privatespace
+
+import android.app.Activity
+import android.app.Instrumentation
+import android.content.Context
+import android.content.Intent
+import android.multiuser.Flags
+import android.platform.test.annotations.RequiresFlagsDisabled
+import android.platform.test.annotations.RequiresFlagsEnabled
+import android.platform.test.flag.junit.CheckFlagsRule
+import android.platform.test.flag.junit.DeviceFlagsValueProvider
+import androidx.lifecycle.Lifecycle
+import androidx.test.core.app.ActivityScenario
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.espresso.intent.Intents
+import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
+import androidx.test.espresso.intent.matcher.IntentMatchers.hasCategories
+import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
+import androidx.test.espresso.intent.matcher.IntentMatchers.hasType
+import androidx.test.espresso.intent.rule.IntentsRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.common.truth.Truth.assertThat
+import org.hamcrest.core.AllOf.allOf
+import org.junit.Assert.assertThrows
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class PrivateSpaceActivityTest {
+
+    @get:Rule val intentsTestRule = IntentsRule()
+
+    @get:Rule val checkFlagsRule: CheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule()
+
+    private lateinit var context: Context
+
+    @Before
+    fun setUp() {
+        context = ApplicationProvider.getApplicationContext()
+    }
+
+    @Test
+    @RequiresFlagsDisabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+    fun intentActionMain_movingContentFlagDisabled_throws() {
+        val intent =
+            Intent(context, PrivateSpaceActivity::class.java).apply { action = Intent.ACTION_MAIN }
+        assertThrows(RuntimeException::class.java) {
+            ActivityScenario.launch<PrivateSpaceActivity>(intent)
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+    fun intentActionAddFiles_triggersDocumentPickerIntent() {
+        val intent =
+            Intent(context, PrivateSpaceActivity::class.java).apply {
+                action = PrivateSpaceActivity.ACTION_ADD_FILES
+            }
+        ActivityScenario.launch<PrivateSpaceActivity>(intent).use { scenario ->
+            Intents.intended(
+                allOf(
+                    hasAction(Intent.ACTION_OPEN_DOCUMENT),
+                    hasCategories(setOf(Intent.CATEGORY_OPENABLE)),
+                    hasType("*/*"),
+                    hasExtra(Intent.EXTRA_ALLOW_MULTIPLE, true),
+                    hasExtra(Intent.EXTRA_LOCAL_ONLY, true),
+                )
+            )
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+    fun intentActionOpenMarketApp_finishesActivity() {
+        val intent =
+            Intent(context, PrivateSpaceActivity::class.java).apply {
+                action = PrivateSpaceActivity.ACTION_OPEN_MARKET_APP
+            }
+        ActivityScenario.launch<PrivateSpaceActivity>(intent).use { scenario ->
+            assertThat(scenario.state).isEqualTo(Lifecycle.State.DESTROYED)
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+    fun intentActionUnknown_finishesActivity() {
+        val intent =
+            Intent(context, PrivateSpaceActivity::class.java).apply {
+                action = "com.example.UNKNOWN_ACTION"
+            }
+
+        ActivityScenario.launch<PrivateSpaceActivity>(intent).use { scenario ->
+            assertThat(scenario.state).isEqualTo(Lifecycle.State.DESTROYED)
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+    fun intentActionNull_finishesActivity() {
+        val intent = Intent(context, PrivateSpaceActivity::class.java) // action is null by default
+
+        ActivityScenario.launch<PrivateSpaceActivity>(intent).use { scenario ->
+            assertThat(scenario.state).isEqualTo(Lifecycle.State.DESTROYED)
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+    fun intentActionAddFiles_activityResultNotOk_finishesActivity() {
+        val launchIntent =
+            Intent(context, PrivateSpaceActivity::class.java).apply {
+                action = PrivateSpaceActivity.ACTION_ADD_FILES
+            }
+        val resultData = Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
+        Intents.intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(resultData)
+
+        ActivityScenario.launch<PrivateSpaceActivity>(launchIntent).use { scenario ->
+            assertThat(scenario.state).isEqualTo(Lifecycle.State.DESTROYED)
+        }
+    }
+}
diff --git a/tests/unit/src/com/android/privatespace/PrivateSpaceViewModelTest.kt b/tests/unit/src/com/android/privatespace/PrivateSpaceViewModelTest.kt
new file mode 100644
index 0000000..9faa7b3
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/PrivateSpaceViewModelTest.kt
@@ -0,0 +1,308 @@
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
+package com.android.privatespace
+
+import android.content.ContentResolver
+import android.content.Context
+import android.content.Intent
+import android.multiuser.Flags
+import android.net.Uri
+import android.os.Environment
+import android.platform.test.annotations.RequiresFlagsEnabled
+import android.privatespace.TestUtils.Companion.getTestUris
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.privatespace.filetransfer.FileTransferService
+import com.android.privatespace.filetransfer.IFileTransferStateRepository
+import com.android.privatespace.filetransfer.TransferState
+import com.google.common.truth.Truth.assertThat
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.StandardTestDispatcher
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.advanceUntilIdle
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.rules.TestWatcher
+import org.junit.runner.Description
+import org.junit.runner.RunWith
+import org.mockito.Mock
+import org.mockito.Mockito.`when` as whenever
+import org.mockito.MockitoAnnotations
+import org.mockito.kotlin.any
+import org.mockito.kotlin.argumentCaptor
+import org.mockito.kotlin.verify
+
+@OptIn(ExperimentalCoroutinesApi::class)
+@RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+@RunWith(AndroidJUnit4::class)
+class PrivateSpaceViewModelTest {
+
+    @get:Rule val mainDispatcherRule = MainDispatcherRule()
+    private lateinit var privateSpaceViewModel: PrivateSpaceViewModel
+    @Mock private lateinit var mockContext: Context
+    @Mock private lateinit var mockContentResolver: ContentResolver
+    @Mock private lateinit var mockStorageHelper: StorageHelper
+    @Mock private lateinit var mockFileTransferStateRepository: IFileTransferStateRepository
+
+    private var closeable: AutoCloseable? = null
+
+    @Before
+    fun setUp() {
+        closeable = MockitoAnnotations.openMocks(this)
+        whenever(mockStorageHelper.getAvailableDeviceStorage()).thenReturn(Long.MAX_VALUE)
+        whenever(mockStorageHelper.calculateTotalSize(any(), any(), any())).thenReturn(1)
+        whenever(mockContext.contentResolver).thenReturn(mockContentResolver)
+        privateSpaceViewModel =
+            PrivateSpaceViewModel(
+                storageHelper = mockStorageHelper,
+                fileTransferStateRepository = mockFileTransferStateRepository,
+            )
+    }
+
+    @After
+    fun tearDown() {
+        closeable?.close()
+    }
+
+    @Test
+    fun initialUiState() {
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.STARTED)
+    }
+
+    @Test
+    fun validateSelectedFileLimits_moreThanAvailableDeviceStorage() {
+        val mockAvailableDeviceStorage = 500_000_000L
+        val mockTotalFilesSizeToBeTransferred =
+            1_500_000_000L // More than the mockAvailableDeviceStorage value
+        whenever(mockStorageHelper.calculateTotalSize(any(), any(), any()))
+            .thenReturn(mockTotalFilesSizeToBeTransferred)
+        whenever(mockStorageHelper.getAvailableDeviceStorage())
+            .thenReturn(mockAvailableDeviceStorage)
+        assertThat(privateSpaceViewModel.validateSelectedFileLimits(mockContext, getTestUris()))
+            .isFalse()
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.SHOW_NOT_ENOUGH_SPACE_DIALOG)
+    }
+
+    @Test
+    fun validateSelectedFileLimits_moreThanTotalFileSizeLimits() {
+        val aboveTotalLimitMockValue = 3_000_000_000L // Limit size is 2GB
+        whenever(mockStorageHelper.calculateTotalSize(any(), any(), any()))
+            .thenReturn(aboveTotalLimitMockValue)
+        assertThat(privateSpaceViewModel.validateSelectedFileLimits(mockContext, getTestUris()))
+            .isFalse()
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.SHOW_ABOVE_FILE_SIZE_LIMITS_DIALOG)
+    }
+
+    @Test
+    fun validateSelectedFileLimits_moreThanFilesCountLimit() {
+        val selectedUris: List<Uri> = (1..101).map { i -> Uri.parse("content://authority/item/$i") }
+        assertThat(privateSpaceViewModel.validateSelectedFileLimits(mockContext, selectedUris))
+            .isFalse()
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.SHOW_TOO_MANY_FILES_SELECTED_DIALOG)
+    }
+
+    @Test
+    fun validateSelectedFileLimits() {
+        val uri = Uri.parse("content://authority/item/1")
+        assertThat(privateSpaceViewModel.validateSelectedFileLimits(mockContext, listOf(uri)))
+            .isTrue()
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.STARTED)
+    }
+
+    @Test
+    fun validateSelectedFileLimits_multipleUris() {
+        val selectedUris: List<Uri> = (1..10).map { i -> Uri.parse("content://authority/item/$i") }
+        assertThat(privateSpaceViewModel.validateSelectedFileLimits(mockContext, selectedUris))
+            .isTrue()
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.STARTED)
+    }
+
+    @Test
+    fun canStartNewTransfer_serviceRunning() = runTest {
+        whenever(mockFileTransferStateRepository.getTransferState(mockContext))
+            .thenReturn(TransferState(keepOriginal = true, transferInProgress = true))
+
+        privateSpaceViewModel.checkIfNewTransferCanStart(mockContext)
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.CHECKING_PROGRESS_INDICATOR)
+
+        advanceUntilIdle()
+
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.SHOW_TRANSFER_IN_PROGRESS_DIALOG)
+        assertThat(privateSpaceViewModel.isPreviousTransferCopy).isTrue()
+    }
+
+    @Test
+    fun canStartNewTransfer() = runTest {
+        whenever(mockFileTransferStateRepository.getTransferState(mockContext))
+            .thenReturn(TransferState(keepOriginal = true, transferInProgress = false))
+        privateSpaceViewModel.checkIfNewTransferCanStart(mockContext)
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.CHECKING_PROGRESS_INDICATOR)
+
+        advanceUntilIdle()
+
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.SHOW_DOCUMENT_PICKER)
+    }
+
+    @Test
+    fun showMoveFilesDialog() {
+        val uriList = arrayListOf(Uri.parse("content://authority/item/1"))
+        privateSpaceViewModel.showMoveFilesDialog(uriList)
+
+        assertThat(privateSpaceViewModel.fileUris).isEqualTo(uriList)
+        assertThat(privateSpaceViewModel.uiState)
+            .isEqualTo(PrivateSpaceUiState.SHOW_MOVE_FILES_DIALOG)
+    }
+
+    @Test
+    fun showMoveFilesDialog_emptyUriList() {
+        privateSpaceViewModel.showMoveFilesDialog(arrayListOf())
+
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.FINISHED)
+    }
+
+    @Test
+    fun finishFlow() {
+        privateSpaceViewModel.finishFlow()
+
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.FINISHED)
+    }
+
+    @Test
+    fun moveFiles_singleUri() {
+        val uri = Uri.parse("content://authority/item/1")
+        privateSpaceViewModel.fileUris = arrayListOf(uri)
+        val intentCaptor = argumentCaptor<Intent>()
+
+        privateSpaceViewModel.moveFiles(mockContext)
+
+        verify(mockContext).startForegroundService(intentCaptor.capture())
+        assertServiceIntent(
+            intent = intentCaptor.firstValue,
+            keepOriginal = false,
+            uris = arrayListOf(uri),
+        )
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.FINISHED)
+        verify(mockContentResolver)
+            .takePersistableUriPermission(
+                uri,
+                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
+            )
+    }
+
+    @Test
+    fun moveFiles_multipleUris() {
+        val uris: ArrayList<Uri> =
+            (1..10).mapTo(ArrayList()) { i -> Uri.parse("content://authority/item/$i") }
+        privateSpaceViewModel.fileUris = uris
+        val intentCaptor = argumentCaptor<Intent>()
+
+        privateSpaceViewModel.moveFiles(mockContext)
+
+        verify(mockContext).startForegroundService(intentCaptor.capture())
+        assertServiceIntent(intent = intentCaptor.firstValue, keepOriginal = false, uris = uris)
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.FINISHED)
+        uris.forEach { uri ->
+            verify(mockContentResolver)
+                .takePersistableUriPermission(
+                    uri,
+                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
+                )
+        }
+    }
+
+    @Test
+    fun copyFiles_singleUri() {
+        val uri = Uri.parse("content://authority/item/1")
+        privateSpaceViewModel.fileUris = arrayListOf(uri)
+        val intentCaptor = argumentCaptor<Intent>()
+
+        privateSpaceViewModel.copyFiles(mockContext)
+        verify(mockContext).startForegroundService(intentCaptor.capture())
+        assertServiceIntent(
+            intent = intentCaptor.firstValue,
+            keepOriginal = true,
+            uris = arrayListOf(uri),
+        )
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.FINISHED)
+        verify(mockContentResolver)
+            .takePersistableUriPermission(
+                uri,
+                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
+            )
+    }
+
+    @Test
+    fun copyFiles_multipleUris() {
+        val uris: ArrayList<Uri> =
+            (1..10).mapTo(ArrayList()) { i -> Uri.parse("content://authority/item/$i") }
+        privateSpaceViewModel.fileUris = uris
+        val intentCaptor = argumentCaptor<Intent>()
+
+        privateSpaceViewModel.copyFiles(mockContext)
+
+        verify(mockContext).startForegroundService(intentCaptor.capture())
+        assertServiceIntent(intent = intentCaptor.firstValue, keepOriginal = true, uris = uris)
+        assertThat(privateSpaceViewModel.uiState).isEqualTo(PrivateSpaceUiState.FINISHED)
+        uris.forEach { uri ->
+            verify(mockContentResolver)
+                .takePersistableUriPermission(
+                    uri,
+                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
+                )
+        }
+    }
+
+    private fun assertServiceIntent(intent: Intent, keepOriginal: Boolean, uris: ArrayList<Uri>) {
+        assertThat(intent.component).isNotNull()
+        assertThat(intent.component!!.className).isEqualTo(FileTransferService::class.java.name)
+        assertThat(
+                intent.getParcelableArrayListExtra(
+                    FileTransferService.SOURCE_URIS_EXTRA,
+                    Uri::class.java,
+                )
+            )
+            .isEqualTo(uris)
+        assertThat(intent.getStringExtra(FileTransferService.DESTINATION_PATH_EXTRA))
+            .isEqualTo(Environment.DIRECTORY_DOWNLOADS)
+        assertThat(intent.getBooleanExtra(FileTransferService.KEEP_ORIGINAL_EXTRA, !keepOriginal))
+            .isEqualTo(keepOriginal)
+    }
+
+    @ExperimentalCoroutinesApi
+    class MainDispatcherRule(val testDispatcher: TestDispatcher = StandardTestDispatcher()) :
+        TestWatcher() {
+        override fun starting(description: Description) {
+            Dispatchers.setMain(testDispatcher)
+        }
+
+        override fun finished(description: Description) {
+            Dispatchers.resetMain()
+        }
+    }
+}
diff --git a/tests/src/com/android/privatespace/PrivateSpaceActivityTest.kt b/tests/unit/src/com/android/privatespace/TestUtils.kt
similarity index 67%
rename from tests/src/com/android/privatespace/PrivateSpaceActivityTest.kt
rename to tests/unit/src/com/android/privatespace/TestUtils.kt
index e723f4c..72bfb42 100644
--- a/tests/src/com/android/privatespace/PrivateSpaceActivityTest.kt
+++ b/tests/unit/src/com/android/privatespace/TestUtils.kt
@@ -14,9 +14,17 @@
  * limitations under the License.
  */
 
-package com.android.privatespace
+package android.privatespace
 
-import androidx.test.ext.junit.runners.AndroidJUnit4
-import org.junit.runner.RunWith
+import android.net.Uri
 
-@RunWith(AndroidJUnit4::class) class PrivateSpaceActivityTest
+class TestUtils {
+    companion object {
+        fun getTestUris(): List<Uri> {
+            return arrayListOf(
+                Uri.parse("content://example/file1"),
+                Uri.parse("content://example/file2"),
+            )
+        }
+    }
+}
diff --git a/tests/unit/src/com/android/privatespace/filetransfer/FakeFileTransferStateRepository.kt b/tests/unit/src/com/android/privatespace/filetransfer/FakeFileTransferStateRepository.kt
new file mode 100644
index 0000000..b78bfdc
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/filetransfer/FakeFileTransferStateRepository.kt
@@ -0,0 +1,36 @@
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
+package com.android.privatespace.filetransfer
+
+import android.content.Context
+import androidx.annotation.OpenForTesting
+
+@OpenForTesting
+open class FakeFileTransferStateRepository : IFileTransferStateRepository {
+    override suspend fun saveState(
+        context: Context,
+        keepOriginal: Boolean,
+        transferInProgress: Boolean,
+    ) {
+        // This is left to the caller to mock
+    }
+
+    override suspend fun getTransferState(context: Context): TransferState {
+        // Returns the default state. It is left to the caller to mock the return value
+        return TransferState(keepOriginal = true, transferInProgress = false)
+    }
+}
diff --git a/tests/src/com/android/privatespace/filetransfer/FileTransferServiceTest.kt b/tests/unit/src/com/android/privatespace/filetransfer/FileTransferManagerImplTest.kt
similarity index 81%
rename from tests/src/com/android/privatespace/filetransfer/FileTransferServiceTest.kt
rename to tests/unit/src/com/android/privatespace/filetransfer/FileTransferManagerImplTest.kt
index 40c45cc..37fec2e 100644
--- a/tests/src/com/android/privatespace/filetransfer/FileTransferServiceTest.kt
+++ b/tests/unit/src/com/android/privatespace/filetransfer/FileTransferManagerImplTest.kt
@@ -16,7 +16,4 @@
 
 package com.android.privatespace.filetransfer
 
-import androidx.test.ext.junit.runners.AndroidJUnit4
-import org.junit.runner.RunWith
-
-@RunWith(AndroidJUnit4::class) class FileTransferServiceTest
+class FileTransferManagerImplTest
diff --git a/tests/unit/src/com/android/privatespace/filetransfer/FileTransferServiceTest.kt b/tests/unit/src/com/android/privatespace/filetransfer/FileTransferServiceTest.kt
new file mode 100644
index 0000000..5416cdd
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/filetransfer/FileTransferServiceTest.kt
@@ -0,0 +1,81 @@
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
+package com.android.privatespace.filetransfer
+
+import android.app.Service
+import android.content.Intent
+import android.multiuser.Flags
+import android.net.Uri
+import android.os.Environment
+import android.platform.test.annotations.RequiresFlagsEnabled
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.privatespace.filetransfer.FileTransferService.Companion.DESTINATION_PATH_EXTRA
+import com.android.privatespace.filetransfer.FileTransferService.Companion.KEEP_ORIGINAL_EXTRA
+import com.android.privatespace.filetransfer.FileTransferService.Companion.SOURCE_URIS_EXTRA
+import kotlinx.coroutines.test.runTest
+import org.junit.After
+import org.junit.Assert.assertEquals
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentMatchers.anyBoolean
+import org.mockito.ArgumentMatchers.anyList
+import org.mockito.ArgumentMatchers.anyString
+import org.mockito.Mock
+import org.mockito.Mockito.never
+import org.mockito.Mockito.verify
+import org.mockito.Mockito.`when` as whenever
+import org.mockito.MockitoAnnotations
+
+@RunWith(AndroidJUnit4::class)
+@RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+class FileTransferServiceTest {
+    private lateinit var fileTransferService: FileTransferService
+    @Mock private lateinit var mockFileTransferManager: IFileTransferManager
+    @Mock private lateinit var mockIntent: Intent
+
+    private var closeable: AutoCloseable? = null
+
+    @Before
+    fun setUp() {
+        closeable = MockitoAnnotations.openMocks(this)
+        fileTransferService = FileTransferService()
+    }
+
+    @After
+    fun tearDown() {
+        closeable?.close()
+    }
+
+    @Test
+    fun testOnStartCommand_nullUris() = runTest {
+        prepareMockIntent()
+        whenever(mockIntent.getParcelableArrayListExtra<Uri>(SOURCE_URIS_EXTRA, Uri::class.java))
+            .thenReturn(null)
+        val result = fileTransferService.onStartCommand(mockIntent, flags = 0, startId = 1)
+        assertEquals(result, Service.START_NOT_STICKY)
+        verify(mockFileTransferManager, never()).transferFiles(anyList(), anyBoolean(), anyString())
+    }
+
+    // TODO(b/400701740): Add more tests with valid uris
+
+    private fun prepareMockIntent() {
+        whenever(mockIntent.getBooleanExtra(KEEP_ORIGINAL_EXTRA, true)).thenReturn(true)
+        whenever(mockIntent.getStringExtra(DESTINATION_PATH_EXTRA))
+            .thenReturn(Environment.DIRECTORY_DOWNLOADS)
+    }
+}
diff --git a/tests/unit/src/com/android/privatespace/filetransfer/FileTransferStateCheckerTest.kt b/tests/unit/src/com/android/privatespace/filetransfer/FileTransferStateCheckerTest.kt
new file mode 100644
index 0000000..81e1917
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/filetransfer/FileTransferStateCheckerTest.kt
@@ -0,0 +1,84 @@
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
+package com.android.privatespace.filetransfer
+
+import android.content.Context
+import android.multiuser.Flags
+import android.platform.test.annotations.RequiresFlagsEnabled
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import kotlinx.coroutines.test.runTest
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.Mock
+import org.mockito.Mockito.never
+import org.mockito.Mockito.verify
+import org.mockito.MockitoAnnotations
+import org.mockito.kotlin.whenever
+
+@RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+@RunWith(AndroidJUnit4::class)
+class FileTransferStateCheckerTest {
+    private lateinit var fileTransferStateChecker: FileTransferStateChecker
+
+    @Mock private lateinit var notificationsHelper: NotificationsHelper
+
+    @Mock private lateinit var fileTransferStateRepository: FakeFileTransferStateRepository
+
+    @Mock private lateinit var context: Context
+
+    private var closeable: AutoCloseable? = null
+
+    @Before
+    fun setUp() {
+        closeable = MockitoAnnotations.openMocks(this)
+        fileTransferStateChecker =
+            FileTransferStateChecker(fileTransferStateRepository, notificationsHelper)
+    }
+
+    @After
+    fun tearDown() {
+        closeable?.close()
+    }
+
+    @Test
+    fun testCheckTransferState_shouldNotifyUser() = runTest {
+        val testState = TransferState(keepOriginal = true, transferInProgress = true)
+        whenever(fileTransferStateRepository.getTransferState(context)).thenReturn(testState)
+
+        fileTransferStateChecker.postBootTransferStateCheck(context)
+
+        verify(notificationsHelper).displayInterruptedTransferNotification(testState.keepOriginal)
+        verify(fileTransferStateRepository)
+            .saveState(context, testState.keepOriginal, transferInProgress = false)
+    }
+
+    @Test
+    fun testCheckTransferState_shouldNotNotifyUser() = runTest {
+        val testState = TransferState(keepOriginal = true, transferInProgress = false)
+        whenever(fileTransferStateRepository.getTransferState(context)).thenReturn(testState)
+
+        fileTransferStateChecker.postBootTransferStateCheck(context)
+
+        verify(notificationsHelper, never()).createNotificationChannel()
+        verify(notificationsHelper, never())
+            .displayInterruptedTransferNotification(testState.keepOriginal)
+        verify(fileTransferStateRepository, never())
+            .saveState(context, testState.keepOriginal, transferInProgress = false)
+    }
+}
diff --git a/tests/unit/src/com/android/privatespace/filetransfer/NotificationsHelperTest.kt b/tests/unit/src/com/android/privatespace/filetransfer/NotificationsHelperTest.kt
new file mode 100644
index 0000000..cebb25b
--- /dev/null
+++ b/tests/unit/src/com/android/privatespace/filetransfer/NotificationsHelperTest.kt
@@ -0,0 +1,326 @@
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
+package com.android.privatespace.filetransfer
+
+import android.app.Notification
+import android.app.NotificationChannel
+import android.app.NotificationManager
+import android.content.Context
+import android.content.pm.ApplicationInfo
+import android.icu.text.MessageFormat
+import android.multiuser.Flags
+import android.os.Build
+import android.platform.test.annotations.RequiresFlagsEnabled
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.bedstead.harrier.BedsteadJUnit4
+import com.android.bedstead.harrier.annotations.EnumTestParameter
+import com.android.bedstead.harrier.annotations.IntTestParameter
+import com.android.privatespace.R
+import com.google.common.truth.Truth.assertThat
+import java.util.HashMap
+import java.util.Locale
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentCaptor
+import org.mockito.ArgumentMatchers.any
+import org.mockito.ArgumentMatchers.eq
+import org.mockito.Mock
+import org.mockito.Mockito.atMostOnce
+import org.mockito.Mockito.verify
+import org.mockito.Mockito.`when` as whenever
+import org.mockito.MockitoAnnotations
+
+@RequiresFlagsEnabled(Flags.FLAG_ENABLE_MOVING_CONTENT_INTO_PRIVATE_SPACE)
+@RunWith(BedsteadJUnit4::class)
+class NotificationsHelperTest {
+    private lateinit var notificationsHelper: NotificationsHelper
+
+    @Mock private lateinit var mockContext: Context
+    private var realContext: Context =
+        InstrumentationRegistry.getInstrumentation().getTargetContext()
+
+    @Mock private lateinit var notificationManager: NotificationManager
+
+    private var applicationInfo = ApplicationInfo()
+    private var closeable: AutoCloseable? = null
+
+    companion object {
+        private const val PACKAGE_NAME = "com.android.privatespace.tests"
+        private const val CHANNEL_ID: String = "FileTransferProgress"
+        private const val COUNT_NOTIFICATION_ARGUMENT_KEY: String = "count"
+        private const val NOTIFICATION_ID: Int = 1
+    }
+
+    @Before
+    fun setUp() {
+        closeable = MockitoAnnotations.openMocks(this)
+        whenever(mockContext.getSystemService(eq(Context.NOTIFICATION_SERVICE)))
+            .thenReturn(notificationManager)
+        whenever(mockContext.getSystemServiceName(eq(NotificationManager::class.java)))
+            .thenReturn(Context.NOTIFICATION_SERVICE)
+        whenever(mockContext.resources).thenReturn(realContext.resources)
+        whenever(mockContext.user).thenReturn(realContext.user)
+        whenever(mockContext.userId).thenReturn(realContext.userId)
+        notificationsHelper = NotificationsHelper(mockContext)
+        mockContextProperties()
+    }
+
+    @After
+    fun tearDown() {
+        closeable?.close()
+    }
+
+    @Test
+    fun testCreateNotificationChannel() {
+        val notificationChannelCaptor = ArgumentCaptor.forClass(NotificationChannel::class.java)
+        notificationsHelper.createNotificationChannel()
+        verify(notificationManager).createNotificationChannel(notificationChannelCaptor.capture())
+        val notificationChannel: NotificationChannel = notificationChannelCaptor.value
+        assertThat(notificationChannel.id).isEqualTo(CHANNEL_ID)
+        assertThat(notificationChannel.importance).isEqualTo(NotificationManager.IMPORTANCE_HIGH)
+        assertThat(notificationChannel.name).isNotNull()
+        assertThat(notificationChannel.description).isNotNull()
+    }
+
+    @Test
+    fun testUpdateProgressNotification(
+        @NumberOfFilesTestParameter numberOfFiles: Int,
+        @TransferTypeTestParameter transferTypeEnum: TransferType,
+    ) {
+        val keepOriginal = transferTypeEnum == TransferType.COPY
+        notificationsHelper.updateProgressNotification(progress = 23, numberOfFiles, keepOriginal)
+        val notificationCaptor = ArgumentCaptor.forClass(Notification::class.java)
+        verify(notificationManager).notify(eq(NOTIFICATION_ID), notificationCaptor.capture())
+        verifyProgressNotification(notificationCaptor.value, keepOriginal, numberOfFiles)
+    }
+
+    @Test
+    fun testNoProgressNotificationAfterCompletion() {
+        notificationsHelper.displaySuccessfulCompletionNotification(
+            numberOfFiles = 10,
+            keepOriginal = true,
+        )
+        notificationsHelper.updateProgressNotification(
+            progress = 90,
+            numberOfFiles = 10,
+            keepOriginal = true,
+        )
+        verify(notificationManager, atMostOnce()).notify(eq(NOTIFICATION_ID), any())
+    }
+
+    @Test
+    fun testDisplayCompletionNotification(
+        @NumberOfFilesTestParameter numberOfFiles: Int,
+        @TransferTypeTestParameter transferType: TransferType,
+    ) {
+        val keepOriginal = transferType == TransferType.COPY
+        notificationsHelper.displaySuccessfulCompletionNotification(numberOfFiles, keepOriginal)
+        val notificationCaptor = ArgumentCaptor.forClass(Notification::class.java)
+        verify(notificationManager).notify(eq(NOTIFICATION_ID), notificationCaptor.capture())
+        verifySuccessfulCompletionNotification(
+            notificationCaptor.value,
+            keepOriginal,
+            numberOfFiles,
+        )
+    }
+
+    @Test
+    fun testBuildProgressNotification(
+        @NumberOfFilesTestParameter numberOfFiles: Int,
+        @TransferTypeTestParameter transferTypeEnum: TransferType,
+    ) {
+        val keepOriginal = transferTypeEnum == TransferType.COPY
+        val notification =
+            notificationsHelper.buildProgressNotification(
+                progress = 10,
+                numberOfFiles,
+                keepOriginal,
+            )
+        verifyProgressNotification(notification, keepOriginal, numberOfFiles)
+    }
+
+    @Test
+    fun testDisplayPartialTransferErrorNotification(
+        @TransferTypeTestParameter transferTypeEnum: TransferType
+    ) {
+        val keepOriginal = transferTypeEnum == TransferType.COPY
+        notificationsHelper.displayPartialTransferErrorNotification(keepOriginal)
+        val notificationCaptor = ArgumentCaptor.forClass(Notification::class.java)
+        verify(notificationManager).notify(eq(NOTIFICATION_ID), notificationCaptor.capture())
+        verifyPartialTransferErrorNotification(notificationCaptor.value, keepOriginal)
+    }
+
+    @Test
+    fun testPostNotEnoughStorageNotification(
+        @TransferTypeTestParameter transferTypeEnum: TransferType
+    ) {
+        val keepOriginal = transferTypeEnum == TransferType.COPY
+        notificationsHelper.postNotEnoughStorageNotification(keepOriginal)
+        val notificationCaptor = ArgumentCaptor.forClass(Notification::class.java)
+        verify(notificationManager).notify(eq(NOTIFICATION_ID), notificationCaptor.capture())
+        verifyNotEnoughStorageNotification(notificationCaptor.value, keepOriginal)
+    }
+
+    @Test
+    fun testDisplayInterruptedTransferNotification(
+        @TransferTypeTestParameter transferTypeEnum: TransferType
+    ) {
+        val keepOriginal = transferTypeEnum == TransferType.COPY
+        notificationsHelper.displayInterruptedTransferNotification(keepOriginal)
+        val notificationCaptor = ArgumentCaptor.forClass(Notification::class.java)
+        verify(notificationManager).notify(eq(NOTIFICATION_ID), notificationCaptor.capture())
+        verifyInterruptedTransferNotification(notificationCaptor.value, keepOriginal)
+    }
+
+    private fun verifySuccessfulCompletionNotification(
+        notification: Notification,
+        keepOriginal: Boolean,
+        numberOfFiles: Int,
+    ) {
+        assertThat(notification.channelId).isEqualTo(CHANNEL_ID)
+        comparePluralizedStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TITLE),
+            if (keepOriginal) R.string.filetransfer_notification_copy_complete_title
+            else R.string.filetransfer_notification_move_complete_title,
+            quantity = numberOfFiles,
+        )
+        comparePluralizedStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TEXT),
+            if (keepOriginal) R.string.filetransfer_notification_copy_complete_text
+            else R.string.filetransfer_notification_move_complete_text,
+            quantity = numberOfFiles,
+        )
+        assertThat(notification.actions.size).isEqualTo(1)
+        assertThat(notification.actions.get(0).actionIntent).isNotNull()
+    }
+
+    private fun verifyProgressNotification(
+        notification: Notification,
+        keepOriginal: Boolean,
+        numberOfFiles: Int,
+    ) {
+        assertThat(notification.channelId).isEqualTo(CHANNEL_ID)
+        comparePluralizedStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TITLE),
+            if (keepOriginal) R.string.filetransfer_notification_copy_progress_title
+            else R.string.filetransfer_notification_move_progress_title,
+            quantity = numberOfFiles,
+        )
+        comparePluralizedStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TEXT),
+            if (keepOriginal) R.string.filetransfer_notification_copy_progress_text
+            else R.string.filetransfer_notification_move_progress_text,
+            quantity = numberOfFiles,
+        )
+        assertThat(notification.actions.size).isEqualTo(1)
+        assertThat(notification.actions.get(0).actionIntent).isNotNull()
+    }
+
+    private fun verifyNotEnoughStorageNotification(
+        notification: Notification,
+        keepOriginal: Boolean,
+    ) {
+        assertThat(notification.channelId).isEqualTo(CHANNEL_ID)
+        compareStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TITLE),
+            if (keepOriginal) R.string.filetransfer_notification_copy_error_title
+            else R.string.filetransfer_notification_move_error_title,
+        )
+        compareStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TEXT),
+            R.string.filetransfer_notification_insufficient_storage_error_message,
+        )
+        assertThat(notification.actions.size).isEqualTo(1)
+        assertThat(notification.actions.get(0).actionIntent).isNotNull()
+    }
+
+    private fun verifyInterruptedTransferNotification(
+        notification: Notification,
+        keepOriginal: Boolean,
+    ) {
+        assertThat(notification.channelId).isEqualTo(CHANNEL_ID)
+        compareStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TITLE),
+            if (keepOriginal) R.string.filetransfer_notification_incomplete_copy_transfer_title
+            else R.string.filetransfer_notification_incomplete_move_transfer_title,
+        )
+        compareStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TEXT),
+            if (keepOriginal) R.string.filetransfer_notification_incomplete_copy_transfer_message
+            else R.string.filetransfer_notification_incomplete_move_transfer_message,
+        )
+    }
+
+    private fun verifyPartialTransferErrorNotification(
+        notification: Notification,
+        keepOriginal: Boolean,
+    ) {
+        assertThat(notification.channelId).isEqualTo(CHANNEL_ID)
+        compareStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TITLE),
+            if (keepOriginal) R.string.filetransfer_notification_partial_copy_error_title
+            else R.string.filetransfer_notification_partial_move_error_title,
+        )
+        compareStringWithResources(
+            notification.extras.getString(Notification.EXTRA_TEXT),
+            if (keepOriginal) R.string.filetransfer_generic_copy_error_message
+            else R.string.filetransfer_generic_move_error_message,
+        )
+        assertThat(notification.actions).isNull()
+    }
+
+    private fun compareStringWithResources(actual: String?, expectedResId: Int) {
+        assertThat(actual).isEqualTo(realContext.resources.getString(expectedResId))
+    }
+
+    private fun comparePluralizedStringWithResources(
+        actual: String?,
+        expectedResId: Int,
+        quantity: Int = 1,
+    ) {
+        assertThat(actual)
+            .isEqualTo(applyFilesCount(quantity, realContext.resources.getString(expectedResId)))
+    }
+
+    private fun applyFilesCount(count: Int, msg: String): String {
+        val msgFormat = MessageFormat(msg, Locale.getDefault())
+        val arguments = HashMap<String, Any>()
+        arguments.put(COUNT_NOTIFICATION_ARGUMENT_KEY, count)
+        return msgFormat.format(arguments)
+    }
+
+    private fun mockContextProperties() {
+        whenever(mockContext.packageName).thenReturn(PACKAGE_NAME)
+        applicationInfo.targetSdkVersion = Build.VERSION_CODES.BAKLAVA
+        whenever(mockContext.applicationInfo).thenReturn(applicationInfo)
+    }
+
+    @IntTestParameter(1, 10)
+    @kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
+    private annotation class NumberOfFilesTestParameter
+
+    @EnumTestParameter(TransferType::class)
+    @kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
+    private annotation class TransferTypeTestParameter
+
+    enum class TransferType {
+        COPY,
+        MOVE,
+    }
+}
```

