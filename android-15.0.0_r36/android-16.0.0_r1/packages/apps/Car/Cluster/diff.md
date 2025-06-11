```diff
diff --git a/ClusterHomeSample/AndroidManifest.xml b/ClusterHomeSample/AndroidManifest.xml
index 526280a..a68a86f 100644
--- a/ClusterHomeSample/AndroidManifest.xml
+++ b/ClusterHomeSample/AndroidManifest.xml
@@ -39,6 +39,8 @@
         <activity android:name=".ClusterHomeActivity"
                 android:exported="true"
                 android:showForAllUsers="true"
+                android:showWhenLocked="true"
+                android:turnScreenOn="true"
                 android:excludeFromRecents="true"
                 android:screenOrientation="nosensor"
                 android:launchMode="singleTask"
@@ -53,6 +55,8 @@
         <activity android:name=".ClusterHomeActivityLightMode"
                   android:exported="true"
                   android:showForAllUsers="true"
+                  android:showWhenLocked="true"
+                  android:turnScreenOn="true"
                   android:excludeFromRecents="true"
                   android:screenOrientation="nosensor"
                   android:launchMode="singleTask"
diff --git a/ClusterHomeSample/README.md b/ClusterHomeSample/README.md
index ab29659..4bf3f2b 100644
--- a/ClusterHomeSample/README.md
+++ b/ClusterHomeSample/README.md
@@ -67,6 +67,30 @@ attribute must be set to `true` in the `AndroidManifest.xml` file.
 ```
 See https://developer.android.com/guide/topics/manifest/activity-element#showForAllUsers
 for more information on `showForAllUsers`.
+### `showWhenLocked`
+If your cluster activity needs to be shown even when the screen is locked,
+set `showWhenLocked` to `true` in the `AndroidManifest.xml` file.
+```
+<activity android:name=".ClusterHomeActivity"
+    ...
+    android:showWhenLocked="true">
+```
+See https://developer.android.com/reference/android/R.attr#showWhenLocked
+for more information on `showWhenLocked`.
+### `turnScreenOn`
+The `turnScreenOn` is set to specify whether the screen needs to be
+turned on when the activity is resumed. Usually `turnScreenOn` is specified
+with `showWhenLocked` to turn on the screen and show the activity
+when the lockscreen is up.
+```
+<activity android:name=".ClusterHomeActivity"
+    ...
+    android:turnScreenOn="true">
+```
+See https://developer.android.com/reference/android/R.attr#turnScreenOn
+for more information on `turnScreenOn`.
+
+``
 ## FULL mode
 
 The cluster application makes full use of the `ClusterHomeManager` APIs in the FULL mode.
diff --git a/DirectRenderingCluster/tests/robotests/Android.bp b/DirectRenderingCluster/tests/robotests/Android.bp
index 220c1d6..8e356e2 100644
--- a/DirectRenderingCluster/tests/robotests/Android.bp
+++ b/DirectRenderingCluster/tests/robotests/Android.bp
@@ -20,6 +20,5 @@ android_robolectric_test {
     ],
 
     instrumentation_for: "DirectRenderingCluster",
-    upstream: true,
     strict_mode: false,
 }
```

