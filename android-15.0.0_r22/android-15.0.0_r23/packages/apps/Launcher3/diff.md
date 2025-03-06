```diff
diff --git a/quickstep/src/com/android/quickstep/TouchInteractionService.java b/quickstep/src/com/android/quickstep/TouchInteractionService.java
index c8e53ab7af..6c7fb2aa7b 100644
--- a/quickstep/src/com/android/quickstep/TouchInteractionService.java
+++ b/quickstep/src/com/android/quickstep/TouchInteractionService.java
@@ -48,7 +48,9 @@ import android.graphics.Region;
 import android.hardware.input.InputManager;
 import android.os.Bundle;
 import android.os.IBinder;
+import android.os.IRemoteCallback;
 import android.os.Looper;
+import android.os.RemoteException;
 import android.os.SystemClock;
 import android.os.Trace;
 import android.util.ArraySet;
@@ -400,6 +402,20 @@ public class TouchInteractionService extends Service {
                     taskbarManager.onNavigationBarLumaSamplingEnabled(displayId, enable));
         }
 
+        @Override
+        public void onUnbind(IRemoteCallback reply) {
+            // Run everything in the same main thread block to ensure the cleanup happens before
+            // sending the reply.
+            MAIN_EXECUTOR.execute(() -> {
+                executeForTaskbarManager(TaskbarManager::destroy);
+                try {
+                    reply.sendResult(null);
+                } catch (RemoteException e) {
+                    Log.w(TAG, "onUnbind: Failed to reply to OverviewProxyService", e);
+                }
+            });
+        }
+
         private void executeForTouchInteractionService(
                 @NonNull Consumer<TouchInteractionService> tisConsumer) {
             TouchInteractionService tis = mTis.get();
```

