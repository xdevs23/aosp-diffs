```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index e1b7075..cb14ef5 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -64,7 +64,6 @@
         </receiver>
 
         <activity android:name="CalendarDebug"
-            android:theme="@style/OptOutEdgeToEdgeEnforcement"
             android:label="@string/calendar_info"
             android:exported="true">
             <intent-filter>
diff --git a/OWNERS b/OWNERS
index dc2d0b3..6c54e85 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,4 @@
-omakoto@google.com
-yamasani@google.com
+# Bug component: 197771
+
+varunshah@google.com
+yamasani@google.com
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index ff5bc58..82a19ce 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -26,8 +26,8 @@
     <string name="provider_label" msgid="1910026788169486138">"Kalender"</string>
     <string name="debug_tool_delete_button" msgid="2843837310185088850">"Vee nou uit"</string>
     <string name="debug_tool_start_button" msgid="2827965939935983665">"Begin"</string>
-    <string name="debug_tool_message" msgid="2315979068524074618">"Jy is op die punt om 1) \'n kopie van jou kalenderdatabasis na die SD-kaart of USB-berging te maak wat deur enige program gelees kan word en 2) dit te e-pos. Onthou om die kopie uit te vee sodra jy dit suksesvol van die toestel af gekopieer het of die e-pos ontvang is."</string>
-    <string name="debug_tool_email_sender_picker" msgid="2527150861906694072">"Kies \'n program om jou lêer te stuur"</string>
+    <string name="debug_tool_message" msgid="2315979068524074618">"Jy is op die punt om 1) \'n kopie van jou kalenderdatabasis na die SD-kaart of USB-berging te maak wat deur enige app gelees kan word en 2) dit te e-pos. Onthou om die kopie uit te vee sodra jy dit suksesvol van die toestel af gekopieer het of die e-pos ontvang is."</string>
+    <string name="debug_tool_email_sender_picker" msgid="2527150861906694072">"Kies \'n app om jou lêer te stuur"</string>
     <string name="debug_tool_email_subject" msgid="1450453531950410260">"Kalenderdatabasis aangeheg"</string>
     <string name="debug_tool_email_body" msgid="1271714905048793618">"Aangeheg is my Kalender-databasis met al my afsprake en persoonlike inligting. Hanteer versigtig."</string>
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
deleted file mode 100644
index a088894..0000000
--- a/res/values/styles.xml
+++ /dev/null
@@ -1,22 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-  ~ Copyright (C) 2024 The Android Open Source Project
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
-  ~ limitations under the License
-  -->
-
-<resources>
-    <style name="OptOutEdgeToEdgeEnforcement">
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
-    </style>
-</resources>
diff --git a/src/com/android/providers/calendar/CalendarConfidenceChecker.java b/src/com/android/providers/calendar/CalendarConfidenceChecker.java
index ae340b3..88490b6 100644
--- a/src/com/android/providers/calendar/CalendarConfidenceChecker.java
+++ b/src/com/android/providers/calendar/CalendarConfidenceChecker.java
@@ -86,9 +86,9 @@ public class CalendarConfidenceChecker {
     @VisibleForTesting
     protected long getUserUnlockTime() {
         final UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
-        final long startTime = um.getUserStartRealtime();
         final long unlockTime = um.getUserUnlockRealtime();
         if (DEBUG) {
+            final long startTime = um.getUserStartRealtime();
             Log.d(TAG, String.format("User start/unlock time=%d/%d", startTime, unlockTime));
         }
         return unlockTime;
@@ -127,16 +127,16 @@ public class CalendarConfidenceChecker {
             final long nowBootCount = getBootCount();
             final long nowRealtime = getRealtimeMillis();
 
-            final long unlockTime = getUserUnlockTime();
 
             if (DEBUG) {
                 Log.d(TAG, String.format("isStateValid: %d/%d %d/%d unlocked=%d lastWtf=%d",
-                        lastBootCount, nowBootCount, lastCheckTime, nowRealtime, unlockTime,
-                        lastWtfTime));
+                        lastBootCount, nowBootCount, lastCheckTime, nowRealtime,
+                        getUserUnlockTime(), lastWtfTime));
             }
 
             if (lastBootCount != nowBootCount) {
                 // This branch means updateLastCheckTime() hasn't been called since boot.
+                final long unlockTime = getUserUnlockTime();
 
                 debug("checkLastCheckTime: Last check time not set.");
 
diff --git a/src/com/android/providers/calendar/EventLogTags.logtags b/src/com/android/providers/calendar/EventLogTags.logtags
index 621b3c7..35f585b 100644
--- a/src/com/android/providers/calendar/EventLogTags.logtags
+++ b/src/com/android/providers/calendar/EventLogTags.logtags
@@ -1,4 +1,4 @@
-# See system/core/logcat/event.logtags for a description of the format of this file.
+# See system/logging/logcat/event.logtags for a description of the format of this file.
 
 option java_package com.android.providers.calendar;
 
```

