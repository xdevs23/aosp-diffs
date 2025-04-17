```diff
diff --git a/src/com/android/server/telecom/ConnectionServiceWrapper.java b/src/com/android/server/telecom/ConnectionServiceWrapper.java
index 260c2383f..915d3ea71 100644
--- a/src/com/android/server/telecom/ConnectionServiceWrapper.java
+++ b/src/com/android/server/telecom/ConnectionServiceWrapper.java
@@ -79,6 +79,7 @@ import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
+import java.util.concurrent.RejectedExecutionException;
 import java.util.concurrent.ScheduledExecutorService;
 import java.util.concurrent.ScheduledFuture;
 import java.util.concurrent.TimeUnit;
@@ -1655,11 +1656,21 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                         }
                     }
                 };
-                // Post cleanup to the executor service and cache the future, so we can cancel it if
-                // needed.
-                ScheduledFuture<?> future = mScheduledExecutor.schedule(r.getRunnableToCancel(),
-                        SERVICE_BINDING_TIMEOUT, TimeUnit.MILLISECONDS);
-                mScheduledFutureMap.put(call, future);
+                if (mScheduledExecutor != null && !mScheduledExecutor.isShutdown()) {
+                    try {
+                        // Post cleanup to the executor service and cache the future,
+                        // so we can cancel it if needed.
+                        ScheduledFuture<?> future = mScheduledExecutor.schedule(
+                                r.getRunnableToCancel(),SERVICE_BINDING_TIMEOUT,
+                                TimeUnit.MILLISECONDS);
+                        mScheduledFutureMap.put(call, future);
+                    } catch (RejectedExecutionException e) {
+                        Log.e(this, e, "createConference: mScheduledExecutor was "
+                                + "already shutdown");
+                    }
+                } else {
+                    Log.w(this, "createConference: Scheduled executor is null or shutdown");
+                }
                 try {
                     mServiceInterface.createConference(
                             call.getConnectionManagerPhoneAccount(),
@@ -1784,11 +1795,21 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                         }
                     }
                 };
-                // Post cleanup to the executor service and cache the future, so we can cancel it if
-                // needed.
-                ScheduledFuture<?> future = mScheduledExecutor.schedule(r.getRunnableToCancel(),
-                        SERVICE_BINDING_TIMEOUT, TimeUnit.MILLISECONDS);
-                mScheduledFutureMap.put(call, future);
+                if (mScheduledExecutor != null && !mScheduledExecutor.isShutdown()) {
+                    try {
+                        // Post cleanup to the executor service and cache the future,
+                        // so we can cancel it if needed.
+                        ScheduledFuture<?> future = mScheduledExecutor.schedule(
+                                r.getRunnableToCancel(),SERVICE_BINDING_TIMEOUT,
+                                TimeUnit.MILLISECONDS);
+                        mScheduledFutureMap.put(call, future);
+                    } catch (RejectedExecutionException e) {
+                        Log.e(this, e, "createConnection: mScheduledExecutor was "
+                                + "already shutdown");
+                    }
+                } else {
+                    Log.w(this, "createConnection: Scheduled executor is null or shutdown");
+                }
                 try {
                     if (mFlags.cswServiceInterfaceIsNull() && mServiceInterface == null) {
                         if (mFlags.dontTimeoutDestroyedCalls()) {
diff --git a/src/com/android/server/telecom/callredirection/CallRedirectionProcessor.java b/src/com/android/server/telecom/callredirection/CallRedirectionProcessor.java
index 05e73d544..15b8aa942 100644
--- a/src/com/android/server/telecom/callredirection/CallRedirectionProcessor.java
+++ b/src/com/android/server/telecom/callredirection/CallRedirectionProcessor.java
@@ -133,6 +133,14 @@ public class CallRedirectionProcessor implements CallRedirectionCallback {
                             + mServiceType + " call redirection service");
                 }
             }
+            Log.i(this, "notifyTimeout: call redirection has timed out so "
+                    + "unbinding the connection");
+            if (mConnection != null) {
+                // We still need to call unbind even if the service disconnected.
+                mContext.unbindService(mConnection);
+                mConnection = null;
+            }
+            mService = null;
         }
 
         private class CallRedirectionServiceConnection implements ServiceConnection {
diff --git a/tests/src/com/android/server/telecom/tests/CallRedirectionProcessorTest.java b/tests/src/com/android/server/telecom/tests/CallRedirectionProcessorTest.java
index 241216aa2..185c08f42 100644
--- a/tests/src/com/android/server/telecom/tests/CallRedirectionProcessorTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallRedirectionProcessorTest.java
@@ -221,6 +221,9 @@ public class CallRedirectionProcessorTest extends TelecomTestCase {
         verify(mCallsManager, times(1)).onCallRedirectionComplete(eq(mCall), any(),
                 eq(mPhoneAccountHandle), eq(null), eq(SPEAKER_PHONE_ON), eq(VIDEO_STATE),
                 eq(false), eq(CallRedirectionProcessor.UI_TYPE_NO_ACTION));
+        // Verify service was unbound
+        verify(mContext, times(1)).
+                unbindService(any(ServiceConnection.class));
     }
 
     @Test
@@ -249,6 +252,9 @@ public class CallRedirectionProcessorTest extends TelecomTestCase {
         verify(mCallsManager, times(1)).onCallRedirectionComplete(eq(mCall), any(),
                 eq(mPhoneAccountHandle), eq(null), eq(SPEAKER_PHONE_ON), eq(VIDEO_STATE),
                 eq(true), eq(CallRedirectionProcessor.UI_TYPE_USER_DEFINED_TIMEOUT));
+        // Verify service was unbound
+        verify(mContext, times(1)).
+                unbindService(any(ServiceConnection.class));
     }
 
     @Test
@@ -280,6 +286,9 @@ public class CallRedirectionProcessorTest extends TelecomTestCase {
         verify(mCallsManager, times(1)).onCallRedirectionComplete(eq(mCall), any(),
                 eq(mPhoneAccountHandle), eq(null), eq(SPEAKER_PHONE_ON), eq(VIDEO_STATE),
                 eq(true), eq(CallRedirectionProcessor.UI_TYPE_USER_DEFINED_TIMEOUT));
+        // Verify service was unbound
+        verify(mContext, times(1)).
+                unbindService(any(ServiceConnection.class));
 
         // Wait for another carrier timeout time, but should not expect any carrier service request
         // is triggered.
@@ -289,6 +298,9 @@ public class CallRedirectionProcessorTest extends TelecomTestCase {
         verify(mCallsManager, times(1)).onCallRedirectionComplete(eq(mCall), any(),
                 eq(mPhoneAccountHandle), eq(null), eq(SPEAKER_PHONE_ON), eq(VIDEO_STATE),
                 eq(true), eq(CallRedirectionProcessor.UI_TYPE_USER_DEFINED_TIMEOUT));
+        // Verify service was unbound
+        verify(mContext, times(1)).
+                unbindService(any(ServiceConnection.class));
     }
 
     @Test
```

