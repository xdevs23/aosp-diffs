```diff
diff --git a/src/com/android/imsserviceentitlement/fcm/FcmUtils.java b/src/com/android/imsserviceentitlement/fcm/FcmUtils.java
index 70ec276..e4ab0af 100644
--- a/src/com/android/imsserviceentitlement/fcm/FcmUtils.java
+++ b/src/com/android/imsserviceentitlement/fcm/FcmUtils.java
@@ -24,6 +24,8 @@ import android.util.Log;
 
 import androidx.annotation.WorkerThread;
 
+import com.android.imsserviceentitlement.utils.TelephonyUtils;
+
 import java.util.concurrent.CountDownLatch;
 
 /** Convenience methods for FCM. */
@@ -37,6 +39,10 @@ public final class FcmUtils {
     /** Fetches FCM token, if it's not available via {@link FcmTokenStore#getToken}. */
     @WorkerThread
     public static void fetchFcmToken(Context context, int subId) {
+        if (TelephonyUtils.getFcmSenderId(context, subId).isEmpty()) {
+            return;
+        }
+
         if (FcmTokenStore.hasToken(context, subId)) {
             Log.d(LOG_TAG, "FCM token available.");
             return;
```

