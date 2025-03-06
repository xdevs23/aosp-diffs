```diff
diff --git a/Android.bp b/Android.bp
index 9741ae2..e8b565e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -115,20 +115,15 @@ sdk {
         },
         android: {
             native_shared_libs: [
-                "heapprofd_client_api",
                 "libbinder_ndk",
                 "liblog",
             ],
-            native_static_libs: [
-                "libperfetto_client_experimental",
-                "perfetto_trace_protos",
-            ],
         },
         not_windows: {
             native_libs: [
                 "liblog",
             ],
-        }
+        },
     },
 }
 
```

