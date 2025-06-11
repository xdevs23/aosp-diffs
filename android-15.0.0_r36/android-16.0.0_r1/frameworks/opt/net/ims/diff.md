```diff
diff --git a/Android.bp b/Android.bp
index 82bf369..e5f7666 100644
--- a/Android.bp
+++ b/Android.bp
@@ -31,10 +31,6 @@ java_library {
     name: "ims-common",
     installable: true,
 
-    static_libs: [
-        "ucepresencelib",
-    ],
-
     aidl: {
         local_include_dirs: ["src/java"],
     },
diff --git a/src/java/com/android/ims/ImsManager.java b/src/java/com/android/ims/ImsManager.java
index 696fc87..37c0832 100644
--- a/src/java/com/android/ims/ImsManager.java
+++ b/src/java/com/android/ims/ImsManager.java
@@ -524,9 +524,7 @@ public class ImsManager implements FeatureUpdates {
         // Check SDK version of the vendor partition.
         final int vendorApiLevel = SystemProperties.getInt(
                 "ro.vendor.api_level", Build.VERSION.DEVICE_INITIAL_SDK_INT);
-        if (vendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) return false;
-
-        return Flags.minimalTelephonyCdmCheck();
+        return vendorApiLevel >= Build.VERSION_CODES.VANILLA_ICE_CREAM;
     }
 
     /**
@@ -3746,10 +3744,6 @@ public class ImsManager implements FeatureUpdates {
      * {@code false} otherwise.
      */
     private boolean overrideWfcRoamingModeWhileUsingNTN() {
-        if (!Flags.carrierEnabledSatelliteFlag()) {
-            return false;
-        }
-
         if (mTelephonyManager == null) {
             return false;
         }
diff --git a/src/java/com/android/ims/RcsFeatureConnection.java b/src/java/com/android/ims/RcsFeatureConnection.java
index c19c36c..11c7344 100644
--- a/src/java/com/android/ims/RcsFeatureConnection.java
+++ b/src/java/com/android/ims/RcsFeatureConnection.java
@@ -16,7 +16,6 @@
 
 package com.android.ims;
 
-import android.annotation.NonNull;
 import android.content.Context;
 import android.net.Uri;
 import android.os.IBinder;
@@ -113,17 +112,15 @@ public class RcsFeatureConnection extends FeatureConnection {
         }
     }
 
-    @VisibleForTesting
-    public AvailabilityCallbackManager mAvailabilityCallbackManager;
-    @VisibleForTesting
-    public RegistrationCallbackManager mRegistrationCallbackManager;
+    private final AvailabilityCallbackManager mAvailabilityCallbackManager;
+    private final RegistrationCallbackManager mRegistrationCallbackManager;
 
     public RcsFeatureConnection(Context context, int slotId, int subId, IImsRcsFeature feature,
             IImsConfig c, IImsRegistration r, ISipTransport s) {
         super(context, slotId, subId, c, r, s);
-        setBinder(feature != null ? feature.asBinder() : null);
         mAvailabilityCallbackManager = new AvailabilityCallbackManager(mContext);
         mRegistrationCallbackManager = new RegistrationCallbackManager(mContext);
+        setBinder(feature != null ? feature.asBinder() : null);
     }
 
     public void close() {
diff --git a/src/java/com/android/ims/rcs/uce/eab/EabBulkCapabilityUpdater.java b/src/java/com/android/ims/rcs/uce/eab/EabBulkCapabilityUpdater.java
index 738a4fc..c407a90 100644
--- a/src/java/com/android/ims/rcs/uce/eab/EabBulkCapabilityUpdater.java
+++ b/src/java/com/android/ims/rcs/uce/eab/EabBulkCapabilityUpdater.java
@@ -397,6 +397,7 @@ public final class EabBulkCapabilityUpdater {
         cancelTimeAlert(mContext);
         unRegisterContactProviderListener();
         unRegisterEabUserSettings();
+        mIsCarrierConfigEnabled = false;
     }
 
     private void registerContactProviderListener() {
diff --git a/tests/src/com/android/ims/FeatureConnectorTest.java b/tests/src/com/android/ims/FeatureConnectorTest.java
index c2b0a10..0f9a33a 100644
--- a/tests/src/com/android/ims/FeatureConnectorTest.java
+++ b/tests/src/com/android/ims/FeatureConnectorTest.java
@@ -24,7 +24,7 @@ import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
diff --git a/tests/src/com/android/ims/ImsConfigTest.java b/tests/src/com/android/ims/ImsConfigTest.java
index 7ce26dd..519557f 100644
--- a/tests/src/com/android/ims/ImsConfigTest.java
+++ b/tests/src/com/android/ims/ImsConfigTest.java
@@ -16,7 +16,7 @@
 
 package com.android.ims;
 
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.verify;
 
 import android.telephony.ims.aidl.IImsConfig;
diff --git a/tests/src/com/android/ims/ImsFeatureBinderRepositoryTest.java b/tests/src/com/android/ims/ImsFeatureBinderRepositoryTest.java
index 6f35e38..bc7c758 100644
--- a/tests/src/com/android/ims/ImsFeatureBinderRepositoryTest.java
+++ b/tests/src/com/android/ims/ImsFeatureBinderRepositoryTest.java
@@ -21,7 +21,7 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
diff --git a/tests/src/com/android/ims/ImsManagerTest.java b/tests/src/com/android/ims/ImsManagerTest.java
index b31ee51..b48f4ae 100644
--- a/tests/src/com/android/ims/ImsManagerTest.java
+++ b/tests/src/com/android/ims/ImsManagerTest.java
@@ -935,8 +935,6 @@ public class ImsManagerTest extends ImsTestBase {
 
     @Test @SmallTest
     public void getWfcMode_overrideWfcRoamingModeWhileUsingNTN() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
         // Phone connected to non-terrestrial network
         NetworkRegistrationInfo nri = new NetworkRegistrationInfo.Builder()
                 .setIsNonTerrestrialNetwork(true)
```

