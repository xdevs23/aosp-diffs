```diff
diff --git a/Android.bp b/Android.bp
index 147ff0c..3226821 100644
--- a/Android.bp
+++ b/Android.bp
@@ -26,6 +26,7 @@ android_app {
     static_libs: [
         "car-resource-common",
         "car-data-subscription-lib",
+        "car-ui-lib",
     ],
 
     resource_dirs: ["res"],
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 5263240..d1f7e0c 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -16,11 +16,12 @@
   -->
 
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.android.car.datasubscription">
+    package="com.android.car.datasubscription"
+    android:versionName="1.0">
   <application
       android:label="Data Subscription Reference">
     <activity android:name=".MainActivity"
-        android:theme="@android:style/Theme.NoTitleBar"
+        android:theme="@style/Theme.CarUi.NoToolbar"
         android:exported="true">
       <intent-filter>
         <action android:name="android.intent.action.MAIN"/>
```

