```diff
diff --git a/libs/WifiTrackerLib/Android.bp b/libs/WifiTrackerLib/Android.bp
index ac9bc731d..5f67f28ad 100644
--- a/libs/WifiTrackerLib/Android.bp
+++ b/libs/WifiTrackerLib/Android.bp
@@ -21,9 +21,11 @@ java_defaults {
 android_library {
     name: "WifiTrackerLib",
     defaults: ["WifiTrackerLibDefaults"],
+    libs: [
+        "android.net.wifi.flags-aconfig-java",
+    ],
     static_libs: [
         "wifi_aconfig_flags_lib",
-        "android.net.wifi.flags-aconfig-java",
     ],
     srcs: ["src/**/*.java"],
 }
```

