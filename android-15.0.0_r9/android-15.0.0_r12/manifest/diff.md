```diff
diff --git a/default.xml b/default.xml
index ee3d87b..f87f677 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r9"
+  <default revision="refs/tags/android-15.0.0_r12"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r9"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r12"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

