```diff
diff --git a/OWNERS b/OWNERS
index 30b4824..32224e8 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
-alisher@google.com
 jackcwyu@google.com
 georgekgchang@google.com
diff --git a/src/com/android/se/SecureElementService.java b/src/com/android/se/SecureElementService.java
index 3f78ebd..43065a7 100644
--- a/src/com/android/se/SecureElementService.java
+++ b/src/com/android/se/SecureElementService.java
@@ -212,10 +212,12 @@ public final class SecureElementService extends Service {
         initialize();
         createTerminals();
 
-        // Add vendor stable service only if it is configured
-        if (getResources().getBoolean(R.bool.secure_element_vintf_enabled)) {
-            ServiceManager.addService(VSTABLE_SECURE_ELEMENT_SERVICE,
-                    mSecureElementServiceBinderVntf);
+        // Add vendor stable service only if it is configured for the system user.
+        if (UserHandle.myUserId() == UserHandle.USER_SYSTEM) {
+            if (getResources().getBoolean(R.bool.secure_element_vintf_enabled)) {
+                ServiceManager.addService(VSTABLE_SECURE_ELEMENT_SERVICE,
+                        mSecureElementServiceBinderVntf);
+            }
         }
 
         // Since ISecureElementService is marked with VINTF stability
diff --git a/src/com/android/se/Terminal.java b/src/com/android/se/Terminal.java
index 8ef86b9..c90ff53 100644
--- a/src/com/android/se/Terminal.java
+++ b/src/com/android/se/Terminal.java
@@ -901,12 +901,12 @@ public class Terminal {
      */
     public boolean reset() {
         synchronized (mLock) {
-            if (mSEHal12 == null && mAidlHal == null) {
-                return false;
-            }
             mContext.enforceCallingOrSelfPermission(
                 android.Manifest.permission.SECURE_ELEMENT_PRIVILEGED_OPERATION,
                 "Need SECURE_ELEMENT_PRIVILEGED_OPERATION permission");
+            if (mSEHal12 == null && mAidlHal == null) {
+                return false;
+            }
 
             try {
                 if (mAidlHal != null) {
```

