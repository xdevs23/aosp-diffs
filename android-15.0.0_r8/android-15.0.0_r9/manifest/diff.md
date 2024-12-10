```diff
diff --git a/default.xml b/default.xml
index 230869106..ee3d87bca 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r8"
+  <default revision="refs/tags/android-15.0.0_r9"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r8"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r9"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

