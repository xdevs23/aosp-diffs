```diff
diff --git a/default.xml b/default.xml
index f87f67797..452f0f69c 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r12"
+  <default revision="refs/tags/android-15.0.0_r17"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r12"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r17"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

