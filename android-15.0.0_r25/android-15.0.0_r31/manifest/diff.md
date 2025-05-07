```diff
diff --git a/default.xml b/default.xml
index 63f2b23e4..1d3a2d254 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r25"
+  <default revision="refs/tags/android-15.0.0_r31"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r25"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r31"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

