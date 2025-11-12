```diff
diff --git a/src/java/com/android/ims/ImsManager.java b/src/java/com/android/ims/ImsManager.java
index 37c0832..97564a3 100644
--- a/src/java/com/android/ims/ImsManager.java
+++ b/src/java/com/android/ims/ImsManager.java
@@ -531,8 +531,9 @@ public class ImsManager implements FeatureUpdates {
      * @return true if this device supports telephony calling, false if it does not.
      */
     private static boolean isTelephonyCallingSupportedOnDevice(Context context) {
-        return minimalTelephonyCdmCheck() && context.getPackageManager().hasSystemFeature(
-                        PackageManager.FEATURE_TELEPHONY_CALLING);
+        if (!minimalTelephonyCdmCheck()) return true;
+        return context.getPackageManager().hasSystemFeature(
+                 PackageManager.FEATURE_TELEPHONY_CALLING);
     }
 
     /**
```

