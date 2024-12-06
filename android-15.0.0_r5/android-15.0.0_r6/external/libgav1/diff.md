```diff
diff --git a/Android.bp b/Android.bp
index 5059d5b..93deae4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -260,6 +260,14 @@ cc_defaults {
     fuzz_config: {
         cc: fuzz_email_cc,
         componentid: bug_component_id,
+        hotlists: [
+            "2100854",
+        ],
+        description: "The fuzzer targets the APIs of libgav1",
+        vector: "remote",
+        service_privilege: "constrained",
+        users: "multi_user",
+        fuzzed_code_usage: "shipped",
     },
 }
 
```

