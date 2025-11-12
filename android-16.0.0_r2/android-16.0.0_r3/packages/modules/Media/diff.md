```diff
diff --git a/apex/framework/java/android/media/MediaCommunicationManager.java b/apex/framework/java/android/media/MediaCommunicationManager.java
index 852c548..8c2bf28 100644
--- a/apex/framework/java/android/media/MediaCommunicationManager.java
+++ b/apex/framework/java/android/media/MediaCommunicationManager.java
@@ -178,8 +178,8 @@ public class MediaCommunicationManager {
         Objects.requireNonNull(executor, "executor must not be null");
         Objects.requireNonNull(callback, "callback must not be null");
 
-        if (!mTokenCallbackRecords.addIfAbsent(
-                new SessionCallbackRecord(executor, callback))) {
+        SessionCallbackRecord sessionCallbackRecord = new SessionCallbackRecord(executor, callback);
+        if (!mTokenCallbackRecords.addIfAbsent(sessionCallbackRecord)){
             Log.w(TAG, "registerSession2TokenCallback: Ignoring the same callback");
             return;
         }
@@ -192,6 +192,11 @@ public class MediaCommunicationManager {
                     mCallbackStub = callbackStub;
                 } catch (RemoteException ex) {
                     ex.rethrowFromSystemServer();
+                } finally {
+                    // When the service call failed, revert the changes made to mCallbackStub.
+                    if (mCallbackStub == null) {
+                        mTokenCallbackRecords.remove(sessionCallbackRecord);
+                    }
                 }
             }
         }
```

