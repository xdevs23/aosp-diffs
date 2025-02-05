```diff
diff --git a/default.xml b/default.xml
index 140666e7e..b5fc196c9 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r14"
+  <default revision="refs/tags/android-15.0.0_r15"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r14"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r15"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

