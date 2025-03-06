```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 534f05c..d32bc3b 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -19,10 +19,7 @@
         xmlns:android="http://schemas.android.com/apk/res/android"
         package="com.android.car.systemupdater">
 
-    <uses-permission android:name="android.permission.WRITE_MEDIA_STORAGE" />
     <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
-    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
-    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
     <uses-permission android:name="android.permission.REBOOT" />
     <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
     <uses-feature android:name="android.hardware.usb.host" />
diff --git a/src/com/android/car/systemupdater/SystemUpdaterActivity.java b/src/com/android/car/systemupdater/SystemUpdaterActivity.java
index 25b8cf4..853cc2d 100644
--- a/src/com/android/car/systemupdater/SystemUpdaterActivity.java
+++ b/src/com/android/car/systemupdater/SystemUpdaterActivity.java
@@ -17,14 +17,10 @@ package com.android.car.systemupdater;
 
 import static com.android.car.systemupdater.UpdateLayoutFragment.EXTRA_RESUME_UPDATE;
 
-import android.Manifest;
-import android.content.pm.PackageManager;
 import android.os.Bundle;
 import android.view.MenuItem;
 
 import androidx.appcompat.app.AppCompatActivity;
-import androidx.core.app.ActivityCompat;
-import androidx.core.content.ContextCompat;
 
 import com.android.car.ui.core.CarUi;
 import com.android.car.ui.toolbar.Toolbar;
@@ -39,23 +35,11 @@ public class SystemUpdaterActivity extends AppCompatActivity
         implements DeviceListFragment.SystemUpdater {
 
     private static final String FRAGMENT_TAG = "FRAGMENT_TAG";
-    private static final int STORAGE_PERMISSIONS_REQUEST_CODE = 0;
-    private static final String[] REQUIRED_STORAGE_PERMISSIONS = new String[]{
-            Manifest.permission.READ_EXTERNAL_STORAGE,
-            Manifest.permission.WRITE_EXTERNAL_STORAGE,
-            Manifest.permission.WRITE_MEDIA_STORAGE
-    };
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
 
-        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
-                != PackageManager.PERMISSION_GRANTED) {
-            ActivityCompat.requestPermissions(this, REQUIRED_STORAGE_PERMISSIONS,
-                    STORAGE_PERMISSIONS_REQUEST_CODE);
-        }
-
         setContentView(R.layout.activity_main);
 
         ToolbarController toolbar = CarUi.requireToolbar(this);
@@ -91,22 +75,6 @@ public class SystemUpdaterActivity extends AppCompatActivity
         return super.onOptionsItemSelected(item);
     }
 
-    @Override
-    public void onRequestPermissionsResult(int requestCode, String permissions[],
-            int[] grantResults) {
-        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
-        if (STORAGE_PERMISSIONS_REQUEST_CODE == requestCode) {
-            if (grantResults.length == 0) {
-                finish();
-            }
-            for (int grantResult : grantResults) {
-                if (grantResult != PackageManager.PERMISSION_GRANTED) {
-                    finish();
-                }
-            }
-        }
-    }
-
     @Override
     public void applyUpdate(File file) {
         UpdateLayoutFragment fragment = UpdateLayoutFragment.getInstance(file);
```

