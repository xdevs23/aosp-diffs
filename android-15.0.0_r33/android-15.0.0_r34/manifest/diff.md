```diff
diff --git a/default.xml b/default.xml
index 554a5b3a3..0f5dd2641 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r33"
+  <default revision="refs/tags/android-15.0.0_r34"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r33"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r34"/>
   <contactinfo bugurl="go/repo-bug" />
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
```

