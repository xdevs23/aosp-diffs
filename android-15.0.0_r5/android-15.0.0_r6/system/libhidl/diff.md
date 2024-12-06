```diff
diff --git a/fuzzer/Android.bp b/fuzzer/Android.bp
index 3de7b74..c353960 100644
--- a/fuzzer/Android.bp
+++ b/fuzzer/Android.bp
@@ -29,8 +29,6 @@ cc_defaults {
         "libutils",
         "libprocessgroup",
         "libjsoncpp",
-        "libcgrouprc",
-        "libcgrouprc_format",
         "libfmq",
     ],
     target: {
diff --git a/vintfdata/frozen/202404.xml b/vintfdata/frozen/202404.xml
index fa5e3ac..91d537a 100644
--- a/vintfdata/frozen/202404.xml
+++ b/vintfdata/frozen/202404.xml
@@ -1,5 +1,9 @@
 <compatibility-matrix version="8.0" type="device">
-    <hal format="aidl" optional="false">
+    <!--
+         cameraserver is installed for all phones and tablets, but not
+         auto, TV, or Wear.
+    -->
+    <hal format="aidl" optional="true">
         <name>android.frameworks.cameraservice.service</name>
         <version>2</version>
         <interface>
@@ -30,7 +34,10 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <!--
+          vibrator is installed for all form factors except TV
+    -->
+    <hal format="aidl" optional="true">
         <name>android.frameworks.vibrator</name>
         <interface>
             <name>IVibratorControlService</name>
```

