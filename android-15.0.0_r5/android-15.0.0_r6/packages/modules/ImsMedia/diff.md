```diff
diff --git a/service/Android.bp b/service/Android.bp
index a37dd316..9e29ce84 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -32,6 +32,7 @@ android_library {
     libs: [
         "android-support-annotations",
         "androidx.annotation_annotation",
+        "keepanno-annotations",
     ],
     static_libs: [
         "android.hardware.radio.ims.media-V1-java",
@@ -51,9 +52,6 @@ android_app {
     required: [
         "libimsmedia",
     ],
-    optimize: {
-        enabled: false,
-    },
     dex_preopt: {
         enabled: false,
     },
diff --git a/service/src/com/android/telephony/imsmedia/JNIImsMediaService.java b/service/src/com/android/telephony/imsmedia/JNIImsMediaService.java
index e5c442ce..ee6eb9d4 100644
--- a/service/src/com/android/telephony/imsmedia/JNIImsMediaService.java
+++ b/service/src/com/android/telephony/imsmedia/JNIImsMediaService.java
@@ -25,8 +25,14 @@ import android.view.Surface;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.telephony.imsmedia.util.Log;
+import com.android.tools.r8.keepanno.annotations.KeepItemKind;
+import com.android.tools.r8.keepanno.annotations.UsedByNative;
 
 /** JNI interface class to send message to libimsmediajni */
+@UsedByNative(
+        description = "Called from JNI in jni/libimsmediajni.cpp",
+        kind = KeepItemKind.CLASS_AND_MEMBERS
+)
 public class JNIImsMediaService {
     private static final String TAG = "JNIImsMediaService";
     private static final int THREAD_PRIORITY_REALTIME = -20;
@@ -163,6 +169,7 @@ public class JNIImsMediaService {
      * @param baData byte array form of data to send
      * @return 1 if it is success to send data, -1 when it fails
      */
+    @UsedByNative
     public static int sendData2Java(final int sessionId, final byte[] baData) {
         Log.dc(TAG, "sendData2Java() - sessionId=" + sessionId);
         JNIImsMediaListener listener = getListener(sessionId);
@@ -188,6 +195,7 @@ public class JNIImsMediaService {
      *
      * @param threadId is the id of the thread whose priority should to be increased.
      */
+    @UsedByNative
     public static void setAudioThreadPriority(int threadId) {
         Log.d(TAG, "setAudioThreadPriority. tid:" + threadId);
         Process.setThreadPriority(threadId, THREAD_PRIORITY_REALTIME);
```

