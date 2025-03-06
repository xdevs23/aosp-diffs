```diff
diff --git a/default.xml b/default.xml
index 37a935c..dbadb9a 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r20"
+  <default revision="refs/tags/android-15.0.0_r21"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r20"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r21"/>
   <contactinfo bugurl="go/repo-bug" />
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
```

