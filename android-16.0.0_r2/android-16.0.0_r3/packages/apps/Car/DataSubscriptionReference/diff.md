```diff
diff --git a/Android.bp b/Android.bp
index 3226821..a020bfc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -29,8 +29,8 @@ android_app {
         "car-ui-lib",
     ],
 
-    resource_dirs: ["res"],
+    platform_apis: true,
 
-    sdk_version: "current",
+    resource_dirs: ["res"],
 
 }
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index d1f7e0c..2eba6e0 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -28,7 +28,7 @@
         <category android:name="android.intent.category.LAUNCHER"/>
       </intent-filter>
       <intent-filter>
-        <action android:name="android.intent.action.DATA_SUBSCRIPTION"/>
+        <action android:name="com.android.car.datasubscription.action.DATA_SUBSCRIPTION"/>
         <category android:name="android.intent.category.DEFAULT" />
       </intent-filter>
     </activity>
```

