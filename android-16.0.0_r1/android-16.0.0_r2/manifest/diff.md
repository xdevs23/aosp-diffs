```diff
diff --git a/default.xml b/default.xml
index da4b29897..a04f29de2 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-16.0.0_r1"
+  <default revision="refs/tags/android-16.0.0_r2"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-16.0.0_r1"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-16.0.0_r2"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

