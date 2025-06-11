```diff
diff --git a/OWNERS b/OWNERS
index c43d4d6..30b4824 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,4 +3,3 @@
 alisher@google.com
 jackcwyu@google.com
 georgekgchang@google.com
-zachoverflow@google.com
diff --git a/src/com/android/se/SecureElementService.java b/src/com/android/se/SecureElementService.java
index 47d3103..3f78ebd 100644
--- a/src/com/android/se/SecureElementService.java
+++ b/src/com/android/se/SecureElementService.java
@@ -308,13 +308,8 @@ public final class SecureElementService extends Service {
     }
 
     private byte[] getUUIDFromCallingUid(int uid) {
-        byte[] uuid = HalRefDoParser.getInstance().findUUID(Binder.getCallingUid());
-
-        if (uuid != null) {
-            return uuid;
-        }
-
-        return null;
+        byte[] uuid = HalRefDoParser.getInstance().findUUID(uid);
+        return uuid;
     }
 
     final class SecureElementSession extends ISecureElementSession.Stub {
```

