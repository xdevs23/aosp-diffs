```diff
diff --git a/java/src/com/android/intentresolver/IntentForwarderActivity.java b/java/src/com/android/intentresolver/IntentForwarderActivity.java
index db94c918..30e518fa 100644
--- a/java/src/com/android/intentresolver/IntentForwarderActivity.java
+++ b/java/src/com/android/intentresolver/IntentForwarderActivity.java
@@ -312,30 +312,44 @@ public class IntentForwarderActivity extends Activity  {
      * forwarding if it can be forwarded, {@code null} otherwise.
      */
     public static Intent canForward(Intent incomingIntent, int sourceUserId, int targetUserId,
-            IPackageManager packageManager, ContentResolver contentResolver)  {
+            IPackageManager packageManager, ContentResolver contentResolver) {
         Intent forwardIntent = new Intent(incomingIntent);
         forwardIntent.addFlags(
                 Intent.FLAG_ACTIVITY_FORWARD_RESULT | Intent.FLAG_ACTIVITY_PREVIOUS_IS_TOP);
         sanitizeIntent(forwardIntent);
 
-        Intent intentToCheck = forwardIntent;
-        if (Intent.ACTION_CHOOSER.equals(forwardIntent.getAction())) {
+        if (!canForwardInner(forwardIntent, sourceUserId, targetUserId, packageManager,
+                contentResolver)) {
             return null;
         }
+
         if (forwardIntent.getSelector() != null) {
-            intentToCheck = forwardIntent.getSelector();
+            sanitizeIntent(forwardIntent.getSelector());
+
+            if (!canForwardInner(forwardIntent.getSelector(), sourceUserId, targetUserId,
+                    packageManager, contentResolver)) {
+                return null;
+            }
+        }
+        return forwardIntent;
+    }
+
+    private static boolean canForwardInner(Intent intent, int sourceUserId, int targetUserId,
+            IPackageManager packageManager, ContentResolver contentResolver) {
+        if (Intent.ACTION_CHOOSER.equals(intent.getAction())) {
+            return false;
         }
-        String resolvedType = intentToCheck.resolveTypeIfNeeded(contentResolver);
-        sanitizeIntent(intentToCheck);
+
+        String resolvedType = intent.resolveTypeIfNeeded(contentResolver);
         try {
             if (packageManager.canForwardTo(
-                    intentToCheck, resolvedType, sourceUserId, targetUserId)) {
-                return forwardIntent;
+                    intent, resolvedType, sourceUserId, targetUserId)) {
+                return true;
             }
         } catch (RemoteException e) {
             Slog.e(TAG, "PackageManagerService is dead?");
         }
-        return null;
+        return false;
     }
 
     /**
```

