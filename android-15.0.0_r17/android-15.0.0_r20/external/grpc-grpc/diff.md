```diff
diff --git a/third_party/opentelemetry-cpp b/third_party/opentelemetry-cpp
deleted file mode 160000
index 4bd64c9a33..0000000000
--- a/third_party/opentelemetry-cpp
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 4bd64c9a336fd438d6c4c9dad2e6b61b0585311f
diff --git a/third_party/protoc-gen-validate b/third_party/protoc-gen-validate
deleted file mode 160000
index fab737efbb..0000000000
--- a/third_party/protoc-gen-validate
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit fab737efbb4b4d03e7c771393708f75594b121e4
diff --git a/third_party/upb/Android.bp b/third_party/upb/Android.bp
index 01eab1b2ee..6569899ca6 100644
--- a/third_party/upb/Android.bp
+++ b/third_party/upb/Android.bp
@@ -86,6 +86,8 @@ cc_library_static {
     cflags: [
         "-Wno-unused-parameter",
     ],
+    // Pin this project to C17 until we have upstream's NULL/false confusion fixes.
+    c_std: "gnu17",
     static_libs: [
         "libgrpc_third_party_utf8_range",
         "libgrpc_upb_protos",
```

