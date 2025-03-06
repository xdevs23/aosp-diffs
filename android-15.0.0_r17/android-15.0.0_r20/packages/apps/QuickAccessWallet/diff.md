```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 9d8a58d..0468ee5 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -19,6 +19,6 @@
       package="com.android.systemui.plugin.globalactions.wallet">
     <uses-sdk
         android:minSdkVersion="33"
-        android:targetSdkVersion="33" />
+        android:targetSdkVersion="35" />
     <application/>
 </manifest>
diff --git a/AndroidManifest_App.xml b/AndroidManifest_App.xml
index d999b6f..de8b25e 100644
--- a/AndroidManifest_App.xml
+++ b/AndroidManifest_App.xml
@@ -22,7 +22,7 @@
 
     <uses-sdk
         android:minSdkVersion="33"
-        android:targetSdkVersion="33"/>
+        android:targetSdkVersion="35"/>
 
     <!-- For using plugins -->
     <uses-permission android:name="com.android.systemui.permission.PLUGIN" />
diff --git a/README b/README
new file mode 100644
index 0000000..1372f28
--- /dev/null
+++ b/README
@@ -0,0 +1,4 @@
+This app is not actively supported and the source is only available as a
+reference. This project will be removed from the source manifest sometime in the
+future.
+
```

