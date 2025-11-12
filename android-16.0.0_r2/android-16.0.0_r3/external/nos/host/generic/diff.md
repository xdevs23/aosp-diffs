```diff
diff --git a/OWNERS b/OWNERS
index 0e826e7..3980b2b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,6 @@
 # Default owners are top 3 or more active developers of the past 1 or 2 years
 # or people with more than 10 commits last year.
 # Please update this list if you find better owner candidates.
-wfrichar@google.com
 tommychiu@google.com
+wfrichar@google.com
 zhakevin@google.com
-kroot@google.com
-include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/libnos/generator/Android.bp b/libnos/generator/Android.bp
index 9e5a688..fba982d 100644
--- a/libnos/generator/Android.bp
+++ b/libnos/generator/Android.bp
@@ -31,7 +31,7 @@ cc_binary_host {
         "nos_cc_defaults",
     ],
     static_libs: [
-        "libabsl_host",
+        "absl_strings",
         "libnosprotos",
     ],
     shared_libs: ["libprotoc"],
diff --git a/nugget/include/hals/weaver.h b/nugget/include/hals/weaver.h
index 29bd67c..0081985 100644
--- a/nugget/include/hals/weaver.h
+++ b/nugget/include/hals/weaver.h
@@ -99,8 +99,8 @@ enum nos2_weaver_read_status {
 struct nos2_weaver_read_response {
   struct nos2_cmd_hal hal;
 
-  uint32_t timeout;
   uint32_t status;  /* enum nos2_weaver_read_status, but of specified size */
+  uint64_t timeout64; /* in milliseconds for some reason */
   /* Put potentially variable-length members at the end. It's NOT, though */
   nos2_weaver_value_t value;
 };
diff --git a/nugget/proto/nugget/app/weaver/weaver.proto b/nugget/proto/nugget/app/weaver/weaver.proto
index cfc6c2e..8ff4ce5 100644
--- a/nugget/proto/nugget/app/weaver/weaver.proto
+++ b/nugget/proto/nugget/app/weaver/weaver.proto
@@ -70,8 +70,9 @@ message ReadResponse {
   }
 
   Error error = 1;
-  uint32 throttle_msec = 2;
+  uint32 throttle32 = 2;  // deprecated
   bytes value = 3;
+  uint64 throttle64 = 4;  // preferred
 }
 
 // EraseValue
```

