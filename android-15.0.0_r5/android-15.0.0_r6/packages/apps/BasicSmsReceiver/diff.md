```diff
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 610c35d..713dbc3 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="sms_app_name" msgid="3641211328012514267">"સરળ સંદેશ રીસીવર"</string>
-    <string name="sms_message_from_format" msgid="7163240046237558485">"<xliff:g id="USERNAME">%1$s</xliff:g> દ્વારા સંદેશ"</string>
+    <string name="sms_app_name" msgid="3641211328012514267">"સરળ મેસેજ રિસીવર"</string>
+    <string name="sms_message_from_format" msgid="7163240046237558485">"<xliff:g id="USERNAME">%1$s</xliff:g> તરફથી મેસેજ"</string>
     <string name="sms_done_button" msgid="4063239029747798890">"થઈ ગયું"</string>
 </resources>
diff --git a/tests/Android.bp b/tests/Android.bp
index 95f3946..31f3781 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -22,9 +22,9 @@ android_test {
     name: "BasicSmsReceiverTests",
 
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
         "junit",
```

