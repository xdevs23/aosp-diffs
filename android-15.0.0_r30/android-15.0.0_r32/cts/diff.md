```diff
diff --git a/tests/tests/appop/src/android/app/appops/cts/AppOpsTest.kt b/tests/tests/appop/src/android/app/appops/cts/AppOpsTest.kt
index 16b584ea877..a6a0539e6f3 100644
--- a/tests/tests/appop/src/android/app/appops/cts/AppOpsTest.kt
+++ b/tests/tests/appop/src/android/app/appops/cts/AppOpsTest.kt
@@ -22,11 +22,11 @@ import android.app.AppOpsManager.MODE_ALLOWED
 import android.app.AppOpsManager.MODE_DEFAULT
 import android.app.AppOpsManager.MODE_ERRORED
 import android.app.AppOpsManager.MODE_IGNORED
-import android.app.AppOpsManager.OPSTR_RESERVED_FOR_TESTING
 import android.app.AppOpsManager.OPSTR_ACCESS_RESTRICTED_SETTINGS
 import android.app.AppOpsManager.OPSTR_PHONE_CALL_CAMERA
 import android.app.AppOpsManager.OPSTR_PHONE_CALL_MICROPHONE
 import android.app.AppOpsManager.OPSTR_PICTURE_IN_PICTURE
+import android.app.AppOpsManager.OPSTR_RESERVED_FOR_TESTING
 import android.app.AppOpsManager.OPSTR_VIBRATE
 import android.app.AppOpsManager.OPSTR_WIFI_SCAN
 import android.app.AppOpsManager.OP_FLAG_SELF
@@ -35,6 +35,7 @@ import android.app.AppOpsManager.OnOpNotedListener
 import android.companion.virtual.VirtualDeviceManager
 import android.content.Context
 import android.content.pm.PackageManager
+import android.content.pm.PackageManager.NameNotFoundException
 import android.os.Process
 import android.os.UserHandle
 import android.permission.flags.Flags
@@ -46,15 +47,11 @@ import android.util.Log
 import androidx.test.InstrumentationRegistry
 import androidx.test.filters.FlakyTest
 import androidx.test.runner.AndroidJUnit4
+import com.android.internal.R
 import com.google.common.base.Objects
 import java.util.concurrent.LinkedBlockingQueue
-import com.android.compatibility.common.util.PollingCheck
-import com.google.common.truth.Truth.assertThat
-import org.junit.After
-import java.util.concurrent.CompletableFuture
-import java.util.concurrent.Executor
-import java.util.concurrent.LinkedBlockingDeque
 import java.util.concurrent.TimeUnit
+import org.junit.After
 import org.junit.Assert
 import org.junit.Assert.assertEquals
 import org.junit.Assert.assertFalse
@@ -65,7 +62,6 @@ import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
 import org.junit.Assume.assumeTrue
 import org.junit.Before
-import org.junit.Ignore
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -167,6 +163,25 @@ class AppOpsTest {
         reset(mOpPackageName)
     }
 
+    @Test
+    fun testModeSettingRestrictedToShellForDeviceProvisioningApp() {
+        val adbUid = runCommand("id -u").trim()
+        assumeTrue("Test is skipped when adb is root", "0" != adbUid)
+
+        val deviceProvisioningPackage =
+            mContext.getResources().getString(R.string.config_deviceProvisioningPackage)
+
+        try {
+            mContext.packageManager.getPackageInfo(deviceProvisioningPackage, 0)
+        } catch (e: NameNotFoundException) {
+            assumeTrue("Test is skipped when device provisioning package does not exist", false)
+        }
+
+        assertEquals(MODE_ALLOWED, getOpMode(deviceProvisioningPackage, OPSTR_RESERVED_FOR_TESTING))
+        setOpMode(deviceProvisioningPackage, OPSTR_RESERVED_FOR_TESTING, MODE_IGNORED)
+        assertEquals(MODE_ALLOWED, getOpMode(deviceProvisioningPackage, OPSTR_RESERVED_FOR_TESTING))
+    }
+
     @Test
     fun testNoteOpAndCheckOp() {
         setOpMode(mOpPackageName, OPSTR_RESERVED_FOR_TESTING, MODE_ALLOWED)
```

