```diff
diff --git a/Android.bp b/Android.bp
index 874e9aa0..d8028f0d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -2,7 +2,7 @@ package {
     default_applicable_licenses: [
         "Android-Apache-2.0",
     ],
-    default_team: "trendy_team_camerax",
+    default_team: "trendy_team_android_camera_innovation_team",
 }
 
 subdirs = [
diff --git a/OWNERS b/OWNERS
index 2e8f086e..a2a42685 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

