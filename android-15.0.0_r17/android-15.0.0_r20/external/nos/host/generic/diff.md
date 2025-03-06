```diff
diff --git a/nugget/proto/BUILD b/nugget/proto/BUILD
index 70952ea..fefc9b3 100644
--- a/nugget/proto/BUILD
+++ b/nugget/proto/BUILD
@@ -1,6 +1,7 @@
 package(default_visibility = ["//visibility:public"])
 
-exports_files(glob(["*.proto"]))
+exports_files(glob(["nugget/app/**/*.options"]))
+
 
 ################################################################################
 # proto cc libraries
```

