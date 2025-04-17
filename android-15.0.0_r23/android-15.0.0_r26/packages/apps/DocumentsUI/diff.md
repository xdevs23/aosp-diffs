```diff
diff --git a/src/com/android/documentsui/picker/ActionHandler.java b/src/com/android/documentsui/picker/ActionHandler.java
index 4ea7bbc2d..553fa6986 100644
--- a/src/com/android/documentsui/picker/ActionHandler.java
+++ b/src/com/android/documentsui/picker/ActionHandler.java
@@ -272,6 +272,9 @@ class ActionHandler<T extends FragmentActivity & Addons> extends AbstractActionH
     private void onLastAccessedStackLoaded(@Nullable DocumentStack stack) {
         if (stack == null) {
             loadDefaultLocation();
+        } else if (shouldPreemptivelyRestrictRequestedInitialUri(stack.peek().getDocumentUri())) {
+            // If the last accessed stack has restricted uri, load default location
+            loadDefaultLocation();
         } else {
             mState.stack.reset(stack);
             mActivity.refreshCurrentRootAndDirectory(AnimationView.ANIM_NONE);
```

