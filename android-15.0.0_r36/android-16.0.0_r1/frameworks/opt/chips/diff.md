```diff
diff --git a/README b/README
new file mode 100644
index 0000000..3c2ea4a
--- /dev/null
+++ b/README
@@ -0,0 +1,6 @@
+This library is not actively supported and the source is only available
+as a reference for use with `packages/apps/Calendar` and
+`packages/apps/Messaging`.
+
+This project will be removed from the source manifest sometime in the
+future along with these two apps.
diff --git a/src/com/android/ex/chips/RecipientAlternatesAdapter.java b/src/com/android/ex/chips/RecipientAlternatesAdapter.java
index cc19700..992055c 100644
--- a/src/com/android/ex/chips/RecipientAlternatesAdapter.java
+++ b/src/com/android/ex/chips/RecipientAlternatesAdapter.java
@@ -415,7 +415,7 @@ public class RecipientAlternatesAdapter extends CursorAdapter {
         } else {
             projection = Queries.PHONE.getProjection();
 
-            if (lookupKey == null) {
+            if (directoryId == null || lookupKey == null) {
                 uri = Queries.PHONE.getContentUri();
                 desiredMimeType = null;
             } else {
@@ -441,10 +441,14 @@ public class RecipientAlternatesAdapter extends CursorAdapter {
             cursor = new MatrixCursor(projection);
         }
 
-        final Cursor resultCursor = removeUndesiredDestinations(cursor, desiredMimeType, lookupKey);
-        cursor.close();
+        if (cursor != null) {
+            final Cursor resultCursor = removeUndesiredDestinations(cursor,
+                    desiredMimeType, lookupKey);
+            cursor.close();
+            return resultCursor;
+        }
 
-        return resultCursor;
+        return cursor;
     }
 
     /**
```

