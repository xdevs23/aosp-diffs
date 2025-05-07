```diff
diff --git a/default.xml b/default.xml
index 0fcdea10d..554a5b3a3 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r32"
+  <default revision="refs/tags/android-15.0.0_r33"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r32"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r33"/>
   <contactinfo bugurl="go/repo-bug" />
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
```

