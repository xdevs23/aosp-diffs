```diff
diff --git a/Android.bp b/Android.bp
index 0625012e..14b9cfb4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -160,7 +160,6 @@ cc_test {
         "test/base-test.cc",
         "test/chrono-test.cc",
         "test/color-test.cc",
-        "test/enforce-checks-test.cc",
         "test/format-test.cc",
         "test/noexception-test.cc",
         // Some of the os-test tests deliberately try to do bad things with
@@ -187,6 +186,8 @@ cc_test {
     ],
 }
 
+// This one needs to be seprate because multiple definition of
+// function format_as(test_enum) with printf-test.cc
 cc_test {
     name: "fmtlib_test_3",
     defaults: ["fmtlib-test-defaults"],
@@ -194,3 +195,12 @@ cc_test {
         "test/ranges-test.cc",
     ],
 }
+
+// enforce-checks-test.cc is a test with a main() function
+cc_test {
+    name: "fmtlib_test_4",
+    defaults: ["fmtlib-test-defaults"],
+    srcs: [
+        "test/enforce-checks-test.cc",
+    ],
+}
```

