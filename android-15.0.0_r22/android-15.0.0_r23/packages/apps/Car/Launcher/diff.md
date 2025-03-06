```diff
diff --git a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
index 4e5224cf..3634641b 100644
--- a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
+++ b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
@@ -25,7 +25,9 @@ import android.content.Intent;
 import android.graphics.Region;
 import android.os.Bundle;
 import android.os.IBinder;
+import android.os.IRemoteCallback;
 import android.os.RemoteException;
+import android.util.Log;
 
 import androidx.annotation.Nullable;
 
@@ -37,6 +39,9 @@ import com.android.wm.shell.recents.IRecentTasks;
 import java.util.List;
 
 public class CarQuickStepService extends Service {
+
+    private static final String TAG = "CarQuickStepService";
+
     private RecentTasksProvider mRecentTasksProvider;
     private ActivityManager mActivityManager;
     private ComponentName mRecentsComponent;
@@ -215,5 +220,15 @@ public class CarQuickStepService extends Service {
         public void appTransitionPending(boolean pending) {
             // no-op
         }
+
+        @Override
+        public void onUnbind(IRemoteCallback reply) {
+            // no-op but immediately call the reply to unblock OveriewProxyService.
+            try {
+                reply.sendResult(null);
+            } catch (RemoteException e) {
+                Log.w(TAG, "onUnbind: Failed to reply to OverviewProxyService", e);
+            }
+        }
     }
 }
```

