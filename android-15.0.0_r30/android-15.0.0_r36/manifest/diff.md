```diff
diff --git a/default.xml b/default.xml
index 30387dc68..a7c482a23 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r30"
+  <default revision="refs/tags/android-15.0.0_r36"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r30"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r36"/>
   <contactinfo bugurl="go/repo-bug" />
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
```

