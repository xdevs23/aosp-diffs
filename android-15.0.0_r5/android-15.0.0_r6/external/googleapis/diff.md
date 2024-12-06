```diff
diff --git a/google/rpc/Android.bp b/google/rpc/Android.bp
index f6809c88d..aeb5ba60e 100644
--- a/google/rpc/Android.bp
+++ b/google/rpc/Android.bp
@@ -34,3 +34,21 @@ java_library_host {
     // TODO(b/339514031): Unpin tradefed dependencies to Java 11.
     java_version: "11",
 }
+
+java_library {
+    name: "googleapis-status-java-proto-lite",
+    srcs: [
+        "status.proto",
+        ":libprotobuf-internal-any-proto",
+    ],
+    libs: [
+        "libprotobuf-java-lite",
+    ],
+    proto: {
+        include_dirs: [
+            "external/googleapis",
+            "external/protobuf/src",
+        ],
+        type: "lite",
+    },
+}
```

