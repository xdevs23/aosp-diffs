```diff
diff --git a/Android.bp b/Android.bp
index 50ed06f8..5e813f80 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,7 +32,8 @@ license {
 }
 
 version_name = "1.24-asop"
-version_code = "417000452"
+// Allow LiveTv app to be available for kids mode without being impacted by OEM's configuration
+version_code = "999999999"
 
 java_defaults {
     name: "LiveTv_defaults",
```

