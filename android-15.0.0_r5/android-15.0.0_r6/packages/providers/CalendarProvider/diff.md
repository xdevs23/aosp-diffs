```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 0f68870..e1b7075 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -63,7 +63,9 @@
             </intent-filter>
         </receiver>
 
-        <activity android:name="CalendarDebug" android:label="@string/calendar_info"
+        <activity android:name="CalendarDebug"
+            android:theme="@style/OptOutEdgeToEdgeEnforcement"
+            android:label="@string/calendar_info"
             android:exported="true">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN" />
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 4676713..a41cd5f 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="calendar_storage" msgid="8317143729823142952">"Calendar storage"</string>
+    <string name="calendar_storage" msgid="8317143729823142952">"Calendar Storage"</string>
     <string name="calendar_default_name" msgid="5010385424907560782">"Default"</string>
     <string name="calendar_info" msgid="3080204956905796668">"Calendar info"</string>
     <string name="calendar_info_error" msgid="8686794108585408379">"Error"</string>
@@ -29,5 +29,5 @@
     <string name="debug_tool_message" msgid="2315979068524074618">"You are about to 1) make a copy of your calendar database to the SD card/USB storage, which is readable by any app, and 2) email it. Remember to delete the copy as soon as you have successfully copied it off the device or the email is received."</string>
     <string name="debug_tool_email_sender_picker" msgid="2527150861906694072">"Choose a program to send your file"</string>
     <string name="debug_tool_email_subject" msgid="1450453531950410260">"Calendar Db attached"</string>
-    <string name="debug_tool_email_body" msgid="1271714905048793618">"Attached is my calendar database with all my appointments and personal information. Handle with care."</string>
+    <string name="debug_tool_email_body" msgid="1271714905048793618">"Attached is my Calendar database with all my appointments and personal information. Handle with care."</string>
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
new file mode 100644
index 0000000..a088894
--- /dev/null
+++ b/res/values/styles.xml
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
+  ~ limitations under the License
+  -->
+
+<resources>
+    <style name="OptOutEdgeToEdgeEnforcement">
+        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
+    </style>
+</resources>
diff --git a/tests/Android.bp b/tests/Android.bp
index 44070fc..55a859f 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -17,9 +17,9 @@ android_test {
     ],
     libs: [
         "ext",
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     instrumentation_for: "CalendarProvider",
 }
```

