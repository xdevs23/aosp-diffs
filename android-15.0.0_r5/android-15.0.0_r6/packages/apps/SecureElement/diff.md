```diff
diff --git a/Android.bp b/Android.bp
index 05820b1..f35ff78 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,7 +38,4 @@ android_app {
                   "android.hardware.secure_element-V1.1-java",
                   "android.hardware.secure_element-V1.2-java",
                   "android.hardware.secure_element-V1-java"],
-    optimize: {
-        enabled: false,
-    },
 }
diff --git a/src/com/android/se/Terminal.java b/src/com/android/se/Terminal.java
index aba77bb..e9b0e6c 100644
--- a/src/com/android/se/Terminal.java
+++ b/src/com/android/se/Terminal.java
@@ -748,8 +748,9 @@ public class Terminal {
                     return false;
                 }
                 return true;
+            } else if (mSEHal == null) {
+                return false;
             }
-
             LogicalChannelResponse[] responseArray = new LogicalChannelResponse[1];
             byte[] status = new byte[1];
             try {
@@ -876,8 +877,10 @@ public class Terminal {
         try {
             if (mAidlHal != null) {
                 return mAidlHal.isCardPresent();
-            } else {
+            } else if (mSEHal != null) {
                 return mSEHal.isCardPresent();
+            } else {
+                return false;
             }
         } catch (ServiceSpecificException e) {
             Log.e(mTag, "Error in isSecureElementPresent() " + e);
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 0e59ece..4e2d7b9 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -9,9 +9,9 @@ android_test {
     certificate: "platform",
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     static_libs: [
```

