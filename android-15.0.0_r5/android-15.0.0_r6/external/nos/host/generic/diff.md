```diff
diff --git a/libnos/feature.cpp b/libnos/feature.cpp
index 6651319..50c9d31 100644
--- a/libnos/feature.cpp
+++ b/libnos/feature.cpp
@@ -16,6 +16,8 @@
 
 #include <nos/feature.h>
 
+#include <cstring>
+
 namespace nos {
 
 bool has_feature(NuggetClientInterface& nug, enum feature_support_app_id app_id,
diff --git a/libnos/generator/main.cpp b/libnos/generator/main.cpp
index 51acfa2..32e4e1b 100644
--- a/libnos/generator/main.cpp
+++ b/libnos/generator/main.cpp
@@ -79,7 +79,7 @@ std::string FullyQualifiedIdentifier(const Descriptor& descriptor) {
 template <typename Descriptor>
 std::string FullyQualifiedHeader(const Descriptor& descriptor) {
     const std::vector<std::string> packages = Packages(descriptor);
-    const std::vector<std::string_view> path_components =
+    const std::vector<std::string> path_components =
         absl::StrSplit(descriptor.file()->name(), '/');
     const std::string file(path_components.back());
     const std::string header = absl::StrCat(absl::StripSuffix(file, ".proto"), ".pb.h");
diff --git a/libnos/include/nos/NuggetClientDebuggable.h b/libnos/include/nos/NuggetClientDebuggable.h
index ff1f080..dd1d7f4 100644
--- a/libnos/include/nos/NuggetClientDebuggable.h
+++ b/libnos/include/nos/NuggetClientDebuggable.h
@@ -17,13 +17,14 @@
 #ifndef NOS_NUGGET_CLIENT_DEBUGGABLE_H
 #define NOS_NUGGET_CLIENT_DEBUGGABLE_H
 
+#include <nos/NuggetClient.h>
+#include <nos/device.h>
+
 #include <cstdint>
+#include <functional>
 #include <string>
 #include <vector>
 
-#include <nos/device.h>
-#include <nos/NuggetClient.h>
-
 namespace nos {
 
 /**
diff --git a/nugget/include/application.h b/nugget/include/application.h
index 053d016..ddbd497 100644
--- a/nugget/include/application.h
+++ b/nugget/include/application.h
@@ -82,7 +82,7 @@ typedef const void * const __private;
 #define APP_ID_TEST              0x7f
 
 /* OR this with the APP_ID to request no-protobuf messages */
-#define APP_ID_NO_PROTO_FLAG     0x80
+#define APP_ID_NO_PROTO_FLAG     0x80u
 
 /* No-protobuf app, experimental for now */
 #define APP_ID_WEAVER2           (APP_ID_WEAVER | APP_ID_NO_PROTO_FLAG)
diff --git a/nugget/proto/BUILD b/nugget/proto/BUILD
index fc1df57..70952ea 100644
--- a/nugget/proto/BUILD
+++ b/nugget/proto/BUILD
@@ -1,3 +1,7 @@
+package(default_visibility = ["//visibility:public"])
+
+exports_files(glob(["*.proto"]))
+
 ################################################################################
 # proto cc libraries
 ################################################################################
```

