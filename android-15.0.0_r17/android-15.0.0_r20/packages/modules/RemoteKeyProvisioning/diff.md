```diff
diff --git a/app/Android.bp b/app/Android.bp
index 7293709..40f7f75 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -61,7 +61,7 @@ android_app {
     sdk_version: "module_current",
     target_sdk_version: "34",
     min_sdk_version: "33",
-    updatable: false,
+    updatable: true,
     privileged: true,
     libs: [
         "framework-annotations-lib",
diff --git a/app/src/com/android/rkpdapp/provisioner/PeriodicProvisioner.java b/app/src/com/android/rkpdapp/provisioner/PeriodicProvisioner.java
index cb1a979..09939e3 100644
--- a/app/src/com/android/rkpdapp/provisioner/PeriodicProvisioner.java
+++ b/app/src/com/android/rkpdapp/provisioner/PeriodicProvisioner.java
@@ -18,6 +18,7 @@ package com.android.rkpdapp.provisioner;
 
 import android.annotation.NonNull;
 import android.content.Context;
+import android.os.Trace;
 import android.util.Log;
 
 import androidx.work.WorkManager;
@@ -83,8 +84,10 @@ public class PeriodicProvisioner extends Worker {
     public Result doWork() {
         sLock.lock();
         try {
+            Trace.beginSection("Periodic.Provisioner");
             return doSynchronizedWork();
         } finally {
+            Trace.endSection();
             sLock.unlock();
         }
     }
diff --git a/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java b/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java
index 59a16b9..7adfd4d 100644
--- a/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java
+++ b/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java
@@ -70,13 +70,12 @@ public class WidevineProvisioner extends Worker {
 
     private static String buildUserAgentString() {
         ArrayList<String> parts = new ArrayList<>();
-        parts.add("AndroidRemoteProvisioner");
-        parts.add(Build.BRAND);
+        parts.add("Linux");
+        parts.add("Android " + Build.VERSION.RELEASE);
         parts.add(Build.MODEL);
-        parts.add(Build.TYPE);
-        parts.add(Build.VERSION.INCREMENTAL);
         parts.add(Build.ID);
-        return String.join("/", parts);
+        parts.add(Build.TYPE);
+        return "AndroidRemoteProvisioner (" + String.join("; ", parts) + ")";
     }
 
     private Result retryOrFail() {
diff --git a/app/src/com/android/rkpdapp/service/RegistrationBinder.java b/app/src/com/android/rkpdapp/service/RegistrationBinder.java
index 4631c57..be21de1 100644
--- a/app/src/com/android/rkpdapp/service/RegistrationBinder.java
+++ b/app/src/com/android/rkpdapp/service/RegistrationBinder.java
@@ -19,6 +19,7 @@ package com.android.rkpdapp.service;
 import android.content.Context;
 import android.os.IBinder;
 import android.os.RemoteException;
+import android.os.Trace;
 import android.util.Log;
 
 import androidx.annotation.GuardedBy;
@@ -114,7 +115,12 @@ public final class RegistrationBinder extends IRegistration.Stub {
             checkedCallback(callback::onProvisioningNeeded);
             try (ProvisioningAttempt metrics = ProvisioningAttempt.createOutOfKeysAttemptMetrics(
                     mContext, mSystemInterface.getServiceName())) {
-                fetchGeekAndProvisionKeys(metrics);
+                Trace.beginSection("Registration.Binder.fetchGeekAndProvisionKeys");
+                try {
+                    fetchGeekAndProvisionKeys(metrics);
+                } finally {
+                    Trace.endSection();
+                }
             }
             assignedKey = tryToAssignKey(minExpiry, keyId);
         }
@@ -213,8 +219,10 @@ public final class RegistrationBinder extends IRegistration.Stub {
 
     @Override
     public void getKey(int keyId, IGetKeyCallback callback) {
+        Trace.beginSection("Registration.Binder.getKey");
         synchronized (mTasksLock) {
             if (mTasks.containsKey(callback.asBinder())) {
+                Trace.endSection();
                 throw new IllegalArgumentException("Callback " + callback.asBinder().hashCode()
                         + " is already associated with a getKey operation that is in-progress");
             }
@@ -222,6 +230,7 @@ public final class RegistrationBinder extends IRegistration.Stub {
             mTasks.put(callback.asBinder(),
                     mThreadPool.submit(() -> getKeyThreadWorker(keyId, callback)));
         }
+        Trace.endSection();
     }
 
     private void getKeyThreadWorker(int keyId, IGetKeyCallback callback) {
diff --git a/app/tests/e2e/src/com/android/rkpdapp/wvtest/WidevineHostTestHelperTests.java b/app/tests/e2e/src/com/android/rkpdapp/wvtest/WidevineHostTestHelperTests.java
index 16aa78a..0c4f469 100644
--- a/app/tests/e2e/src/com/android/rkpdapp/wvtest/WidevineHostTestHelperTests.java
+++ b/app/tests/e2e/src/com/android/rkpdapp/wvtest/WidevineHostTestHelperTests.java
@@ -28,6 +28,7 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.work.ListenableWorker;
 import androidx.work.testing.TestWorkerBuilder;
 
+import com.android.compatibility.common.util.PropertyUtil;
 import com.android.rkpdapp.provisioner.WidevineProvisioner;
 
 import org.junit.BeforeClass;
@@ -54,6 +55,15 @@ public class WidevineHostTestHelperTests {
     }
 
     private boolean isProvisioning4() {
+        if (PropertyUtil.getFirstApiLevel() < android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
+            Log.i(TAG, "First API level less than U: " + PropertyUtil.getFirstApiLevel());
+            return false;
+        }
+        // Check SoC API level
+        if (PropertyUtil.getVsrApiLevel() < android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
+            Log.i(TAG, "VSR API level less than U: " + PropertyUtil.getFirstApiLevel());
+            return false;
+        }
         return sDrm.getPropertyString("provisioningModel").equals("BootCertificateChain");
     }
 
diff --git a/app/tests/hosttest/Android.bp b/app/tests/hosttest/Android.bp
index c0bfd87..68d06af 100644
--- a/app/tests/hosttest/Android.bp
+++ b/app/tests/hosttest/Android.bp
@@ -34,7 +34,7 @@ java_test_host {
     static_libs: [
         "cts-statsd-atom-host-test-utils",
     ],
-    data: [
+    device_common_data: [
         ":RkpdAppIntegrationTests",
         ":RkpdAppUnitTests",
     ],
diff --git a/system-server/src/android/security/rkp/service/RegistrationProxy.java b/system-server/src/android/security/rkp/service/RegistrationProxy.java
index 7663741..7385baf 100644
--- a/system-server/src/android/security/rkp/service/RegistrationProxy.java
+++ b/system-server/src/android/security/rkp/service/RegistrationProxy.java
@@ -100,6 +100,7 @@ public class RegistrationProxy {
                     new ComponentName(serviceInfo.applicationInfo.packageName, serviceInfo.name));
             if (!context.bindServiceAsUser(intent, this, Context.BIND_AUTO_CREATE,
                     UserHandle.SYSTEM)) {
+                context.unbindService(this);
                 throw new RemoteException("Failed to bind to IRemoteProvisioning service");
             }
         }
```

