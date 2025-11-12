```diff
diff --git a/mts/Android.bp b/mts/Android.bp
index be0378fd..65db99f3 100644
--- a/mts/Android.bp
+++ b/mts/Android.bp
@@ -39,6 +39,6 @@ android_test {
         "general-tests",
         "mts-art",
     ],
-    host_required: ["cts-dalvik-host-test-runner"],
+    host_common_data: [":cts-dalvik-host-test-runner"],
     test_config: "MtsLibcoreBouncyCastleTestCases.xml",
 }
```

