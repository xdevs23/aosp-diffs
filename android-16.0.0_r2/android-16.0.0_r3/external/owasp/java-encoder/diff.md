```diff
diff --git a/Android.bp b/Android.bp
index 96b16e2..757ef4b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -59,7 +59,6 @@ android_test {
     sdk_version: "test_current",
     test_suites: [
         "general-tests",
-        "mts-ondevicepersonalization",
     ],
     visibility: ["//visibility:private"],
 }
```

