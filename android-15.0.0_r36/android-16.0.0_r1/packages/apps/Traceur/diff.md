```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index b02b5c27..19619601 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -21,7 +21,7 @@
      android:versionCode="2"
      android:versionName="1.0">
     <uses-sdk android:minSdkVersion="26"
-         android:targetSdkVersion="34"/>
+         android:targetSdkVersion="35"/>
 
     <!--- Used to query for Betterbug. -->
     <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 776359d8..1c25f5d3 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,10 +1,11 @@
 // for packages/apps/Traceur
 {
-    "presubmit": [
-        {
-            "name": "TraceurUiTests"
-        }
-    ],
+// TODO(b/397511281)
+//    "presubmit": [
+//        {
+//            "name": "TraceurUiTests"
+//        }
+//    ],
     "hwasan-postsubmit": [
         {
             "name": "TraceurUiTests"
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 0c0658d5..b2f7078f 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -32,8 +32,8 @@
     <string name="applications" msgid="521776761270770549">"אפליקציות"</string>
     <string name="no_debuggable_apps" msgid="4386209254520471208">"אין אפליקציות שניתן לנפות בהן באגים"</string>
     <string name="buffer_size" msgid="3944311026715111454">"‏שטח אחסון זמני לכל יחידת עיבוד מרכזית (CPU)"</string>
-    <string name="show_quick_settings_tile" msgid="3827556161191376500">"הצגת לחצן המעקב ב\'הגדרות מהירות\'"</string>
-    <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"‏הצגת לחצן פרופיילינג של המעבד (CPU) ב\'הגדרות מהירות\'"</string>
+    <string name="show_quick_settings_tile" msgid="3827556161191376500">"הצגת כפתור המעקב ב\"הגדרות מהירות\""</string>
+    <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"‏הצגת כפתור פרופיילינג של המעבד (CPU) ב\"הגדרות מהירות\""</string>
     <string name="saving_trace" msgid="1468692734770800541">"שמירת מעקב מתבצעת"</string>
     <string name="trace_saved" msgid="5869970594780992309">"המעקב נשמר"</string>
     <string name="saving_stack_samples" msgid="8174915522390525221">"שמירת מקבץ של דגימות"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 5ab11853..140a8aeb 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -55,10 +55,10 @@
     <string name="clear_saved_files_question" msgid="8586686617760838834">"सेव्ह केलेल्या फाइल साफ करायच्या का?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces मधून सर्व रेकॉर्डिंग हटवली जातील"</string>
     <string name="clear" msgid="5484761795406948056">"साफ करा"</string>
-    <string name="system_traces_storage_title" msgid="8294090839883366871">"सिस्टम माग"</string>
+    <string name="system_traces_storage_title" msgid="8294090839883366871">"सिस्टीम ट्रेस"</string>
     <string name="keywords" msgid="736547007949049535">"systrace, माग काढणे, कामगिरी"</string>
     <string name="share_file" msgid="1982029143280382271">"फाइल शेअर करायची का?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"सिस्टमचा माग काढणे फायलींमध्ये संवेदनशील सिस्टम आणि अ‍ॅप डेटा (जसे की अ‍ॅप वापर) यांचा समावेश असू शकतो. ज्या लोकांवर आणि अ‍ॅपवर तुमचा विश्वास आहे केवळ त्यांच्यासह हा सिस्टमचा माग शेअर करा."</string>
+    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"सिस्टीम ट्रेसिंग फाइलमध्ये संवेदनशील सिस्टीम आणि अ‍ॅप डेटा (जसे की अ‍ॅप वापर) यांचा समावेश असू शकतो. ज्या लोकांवर आणि अ‍ॅपवर तुमचा विश्वास आहे केवळ त्यांच्यासह हा सिस्टीमचे ट्रेस शेअर करा."</string>
     <string name="share" msgid="8443979083706282338">"शेअर करा"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"पुन्हा दाखवू नका"</string>
     <string name="long_traces" msgid="5110949471775966329">"मोठे ट्रेस"</string>
diff --git a/res/values/preference_keys.xml b/res/values/preference_keys.xml
index cdfdf11c..6816f2e8 100644
--- a/res/values/preference_keys.xml
+++ b/res/values/preference_keys.xml
@@ -6,7 +6,7 @@
     <string name="pref_key_heap_dump_on">heap_dump_on</string>
     <string name="pref_key_recording_was_trace">recording_was_trace</string>
     <string name="pref_key_recording_was_stack_samples">recording_was_stack_samples</string>
-    <string name="pref_key_tags">current_tags_10</string>
+    <string name="pref_key_tags">current_tags_11</string>
     <string name="pref_key_apps">all_apps</string>
     <string name="pref_key_winscope">winscope</string>
     <string name="pref_key_buffer_size">buffer_size</string>
diff --git a/src_common/com/android/traceur/PresetTraceConfigs.java b/src_common/com/android/traceur/PresetTraceConfigs.java
index b38b66a4..686c268b 100644
--- a/src_common/com/android/traceur/PresetTraceConfigs.java
+++ b/src_common/com/android/traceur/PresetTraceConfigs.java
@@ -27,7 +27,7 @@ import java.util.Set;
 public class PresetTraceConfigs {
 
     private static final List<String> DEFAULT_TRACE_TAGS = Arrays.asList(
-            "aidl", "am", "binder_driver", "camera", "dalvik", "disk", "freq",
+            "aidl", "am", "binder_driver", "camera", "cpm", "dalvik", "disk", "freq",
             "gfx", "hal", "idle", "input", "memory", "memreclaim", "network", "power",
             "res", "sched", "ss", "sync", "thermal", "view", "webview", "wm", "workq");
 
diff --git a/uitests/Android.bp b/uitests/Android.bp
index 8bf29b70..319e5d17 100644
--- a/uitests/Android.bp
+++ b/uitests/Android.bp
@@ -22,6 +22,7 @@ android_test {
         "androidx.test.rules",
         "platform-test-annotations",
         "androidx.test.uiautomator_uiautomator",
+        "collector-device-lib",
     ],
     sdk_version: "current",
     test_suites: ["device-tests"],
diff --git a/uitests/AndroidTest.xml b/uitests/AndroidTest.xml
index fe185f20..dbbaffb1 100644
--- a/uitests/AndroidTest.xml
+++ b/uitests/AndroidTest.xml
@@ -29,5 +29,13 @@
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
         <option name="package" value="com.android.traceur.uitest" />
         <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+        <option name="device-listeners" value="android.device.collectors.ScreenRecordCollector,android.device.collectors.ScreenshotOnFailureCollector"/>
     </test>
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
+        <option name="pull-pattern-keys"
+                value="android.device.collectors.ScreenRecordCollector.*\.mp4"/>
+        <option name="pull-pattern-keys" value="android.device.collectors.ScreenshotOnFailureCollector.*\.png"/>
+        <option name="directory-keys" value="/data/user/0/com.android.traceur.uitest/files" />
+        <option name="collect-on-run-ended-only" value="false" />
+    </metrics_collector>
 </configuration>
```

