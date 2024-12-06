```diff
diff --git a/src/java/com/android/server/sip/SipService.java b/src/java/com/android/server/sip/SipService.java
index c68508b..5922575 100644
--- a/src/java/com/android/server/sip/SipService.java
+++ b/src/java/com/android/server/sip/SipService.java
@@ -44,6 +44,7 @@ import android.os.Process;
 import android.os.RemoteException;
 import android.os.ServiceManager;
 import android.os.SystemClock;
+import android.os.UserHandle;
 import android.telephony.Rlog;
 
 import java.io.IOException;
@@ -197,7 +198,7 @@ public final class SipService extends ISipService.Stub {
     }
 
     private boolean isCallerRadio() {
-        return (Binder.getCallingUid() == Process.PHONE_UID);
+        return UserHandle.isSameApp(Binder.getCallingUid(), Process.PHONE_UID);
     }
 
     @Override
```

