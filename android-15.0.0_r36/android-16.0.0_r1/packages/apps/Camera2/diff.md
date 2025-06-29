```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 4d7e17144..303819285 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -46,6 +46,7 @@
         android:restoreAnyVersion="true"
         android:supportsRtl="true"
         android:theme="@style/Theme.Camera"
+        android:enableOnBackInvokedCallback="false"
         android:usesCleartextTraffic="false" >
         <activity
             android:name="com.android.camera.CameraActivity"
diff --git a/OWNERS b/OWNERS
index 304ffc68d..3b85e2cfd 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
-rtenneti@google.com
 
 include platform/frameworks/av:/camera/OWNERS
diff --git a/src/com/android/camera/CameraActivity.java b/src/com/android/camera/CameraActivity.java
index 3093b2584..5ccc9b2f8 100644
--- a/src/com/android/camera/CameraActivity.java
+++ b/src/com/android/camera/CameraActivity.java
@@ -32,6 +32,7 @@ import android.content.IntentFilter;
 import android.content.pm.ActivityInfo;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
+import android.content.pm.ProviderInfo;
 import android.content.res.Configuration;
 import android.graphics.Bitmap;
 import android.graphics.Matrix;
@@ -1403,7 +1404,6 @@ public class CameraActivity extends QuickActivity
         mOnCreateTime = System.currentTimeMillis();
         mAppContext = getApplicationContext();
         mMainHandler = new MainHandler(this, getMainLooper());
-        mLocationManager = new LocationManager(mAppContext, shouldUseNoOpLocation());
         mOrientationManager = new OrientationManagerImpl(this, mMainHandler);
         mSettingsManager = getServices().getSettingsManager();
         mSoundPlayer = new SoundPlayer(mAppContext);
@@ -1539,6 +1539,8 @@ public class CameraActivity extends QuickActivity
             mSecureCamera = intent.getBooleanExtra(SECURE_CAMERA_EXTRA, false);
         }
 
+        mLocationManager = new LocationManager(mAppContext, shouldUseNoOpLocation(intent));
+
         if (mSecureCamera) {
             // Change the window flags so that secure camera can show when
             // locked
@@ -1702,7 +1704,27 @@ public class CameraActivity extends QuickActivity
      * Incase the calling package doesn't have ACCESS_FINE_LOCATION permissions, we should not pass
      * it valid location information in exif.
      */
-    private boolean shouldUseNoOpLocation () {
+    private boolean shouldUseNoOpLocation (Intent intent) {
+        final PackageManager pm = getPackageManager();
+
+        // Check who implements the ContentProvider behind a URI, and check its
+        // FINE_LOCATION permission.
+        final Bundle myExtras = intent.getExtras();
+        if (myExtras != null) {
+            Uri saveUri = myExtras.getParcelable(MediaStore.EXTRA_OUTPUT);
+            if (saveUri != null) {
+                ProviderInfo info = pm.resolveContentProvider(saveUri.getAuthority(), 0);
+                if (info == null) {
+                    // The URI cannot be resolved to a valid ProviderInfo. In this case,
+                    // we should use no-op location
+                    return true;
+                }
+                return (pm.checkPermission(Manifest.permission.ACCESS_FINE_LOCATION,
+                      info.packageName) != PackageManager.PERMISSION_GRANTED);
+            }
+        }
+
+        // If no save Uri is provided, fall back to inspect calling package.
         String callingPackage = getCallingPackage();
         if (callingPackage == null) {
             if (isCaptureIntent()) {
@@ -1712,28 +1734,8 @@ public class CameraActivity extends QuickActivity
                 callingPackage = mAppContext.getPackageName();
             }
         }
-        PackageInfo packageInfo = null;
-        try {
-            packageInfo = getPackageManager().getPackageInfo(callingPackage,
-                    PackageManager.GET_PERMISSIONS);
-        } catch (Exception e) {
-            Log.w(TAG, "Unable to get PackageInfo for callingPackage " + callingPackage);
-        }
-        if (packageInfo != null) {
-            if (packageInfo.requestedPermissions == null) {
-                // No-permissions at all, were requested by the calling app.
-                return true;
-            }
-            for (int i = 0; i < packageInfo.requestedPermissions.length; i++) {
-                if (packageInfo.requestedPermissions[i].equals(
-                        Manifest.permission.ACCESS_FINE_LOCATION) &&
-                        (packageInfo.requestedPermissionsFlags[i] &
-                        PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
-                  return false;
-                }
-            }
-        }
-        return true;
+        return (pm.checkPermission(Manifest.permission.ACCESS_FINE_LOCATION,
+              callingPackage) != PackageManager.PERMISSION_GRANTED);
     }
     /**
      * Call this whenever the mode drawer or filmstrip change the visibility
diff --git a/src/com/android/camera/util/ApiHelper.java b/src/com/android/camera/util/ApiHelper.java
index d04e52c66..aaabaa31e 100644
--- a/src/com/android/camera/util/ApiHelper.java
+++ b/src/com/android/camera/util/ApiHelper.java
@@ -26,6 +26,8 @@ public class ApiHelper {
 
     public static final boolean AT_LEAST_16 = Build.VERSION.SDK_INT >= 16;
 
+    public static final boolean AT_LEAST_34 = Build.VERSION.SDK_INT >= 34;
+
     public static final boolean HAS_APP_GALLERY =
             Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1;
 
```

