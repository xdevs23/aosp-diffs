```diff
diff --git a/default.xml b/default.xml
index 2534a1f45..140666e7e 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r13"
+  <default revision="refs/tags/android-15.0.0_r14"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r13"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r14"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

