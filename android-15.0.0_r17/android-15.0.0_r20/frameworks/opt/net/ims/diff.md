```diff
diff --git a/src/java/com/android/ims/FeatureConnector.java b/src/java/com/android/ims/FeatureConnector.java
index 32674d9..c6094ac 100644
--- a/src/java/com/android/ims/FeatureConnector.java
+++ b/src/java/com/android/ims/FeatureConnector.java
@@ -260,7 +260,9 @@ public class FeatureConnector<U extends FeatureUpdates> {
 
     // Check if this ImsFeature is supported or not.
     private boolean isSupported() {
-        return mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS);
+        PackageManager pm = mContext.getPackageManager();
+        if (pm == null) return false;
+        return pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS);
     }
 
     /**
diff --git a/src/java/com/android/ims/ImsManager.java b/src/java/com/android/ims/ImsManager.java
index 217a26f..696fc87 100644
--- a/src/java/com/android/ims/ImsManager.java
+++ b/src/java/com/android/ims/ImsManager.java
@@ -517,6 +517,26 @@ public class ImsManager implements FeatureUpdates {
         return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS);
     }
 
+    /**
+     * Returns true if Calling/Data/Messaging features should be checked on this device.
+     */
+    private static boolean minimalTelephonyCdmCheck() {
+        // Check SDK version of the vendor partition.
+        final int vendorApiLevel = SystemProperties.getInt(
+                "ro.vendor.api_level", Build.VERSION.DEVICE_INITIAL_SDK_INT);
+        if (vendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) return false;
+
+        return Flags.minimalTelephonyCdmCheck();
+    }
+
+    /**
+     * @return true if this device supports telephony calling, false if it does not.
+     */
+    private static boolean isTelephonyCallingSupportedOnDevice(Context context) {
+        return minimalTelephonyCdmCheck() && context.getPackageManager().hasSystemFeature(
+                        PackageManager.FEATURE_TELEPHONY_CALLING);
+    }
+
     /**
      * Sets the callback that will be called when events related to IMS metric collection occur.
      * <p>
@@ -1018,6 +1038,11 @@ public class ImsManager implements FeatureUpdates {
             loge("isCallComposerEnabledByUser: TelephonyManager is null, returning false");
             return false;
         }
+        if (!isTelephonyCallingSupportedOnDevice(mContext)) {
+            loge("isCallComposerEnabledByUser: FEATURE_TELEPHONY_CALLING not supported,"
+                    + " returning false");
+            return false;
+        }
         return mTelephonyManager.getCallComposerStatus()
                 == TelephonyManager.CALL_COMPOSER_STATUS_ON;
     }
@@ -1031,6 +1056,11 @@ public class ImsManager implements FeatureUpdates {
             loge("isBusinessOnlyCallComposerEnabledByUser: TelephonyManager is null");
             return false;
         }
+        if (!isTelephonyCallingSupportedOnDevice(mContext)) {
+            loge("isBusinessOnlyCallComposerEnabledByUser: FEATURE_TELEPHONY_CALLING not"
+                    + " supported, returning false");
+            return false;
+        }
         return tm.getCallComposerStatus() == TelephonyManager.CALL_COMPOSER_STATUS_BUSINESS_ONLY;
     }
 
diff --git a/src/java/com/android/ims/rcs/uce/request/UceRequestManager.java b/src/java/com/android/ims/rcs/uce/request/UceRequestManager.java
index 8955ec4..56a9ae7 100644
--- a/src/java/com/android/ims/rcs/uce/request/UceRequestManager.java
+++ b/src/java/com/android/ims/rcs/uce/request/UceRequestManager.java
@@ -952,7 +952,7 @@ public class UceRequestManager {
             SomeArgs args = (SomeArgs) msg.obj;
             final Long coordinatorId = (Long) args.arg1;
             final Long taskId = (Long) Optional.ofNullable(args.arg2).orElse(-1L);
-            final Integer requestEvent = Optional.ofNullable(args.argi1).orElse(-1);
+            final int requestEvent = args.argi1;
             args.recycle();
 
             requestManager.logd("handleMessage: " + EVENT_DESCRIPTION.get(msg.what)
```

