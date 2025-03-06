```diff
diff --git a/default.xml b/default.xml
index dbadb9a..f9d9338 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r21"
+  <default revision="refs/tags/android-15.0.0_r22"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r21"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r22"/>
   <contactinfo bugurl="go/repo-bug" />
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
```

