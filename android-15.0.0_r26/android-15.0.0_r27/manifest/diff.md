```diff
diff --git a/default.xml b/default.xml
index cdfe3b0..520d7b8 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r26"
+  <default revision="refs/tags/android-15.0.0_r27"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r26"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r27"/>
   <contactinfo bugurl="go/repo-bug" />
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
```

