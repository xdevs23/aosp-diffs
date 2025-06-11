```diff
diff --git a/Android.bp b/Android.bp
index 68260b6..83247cc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -35,6 +35,10 @@ cc_binary {
     srcs: [
         "gsi_tool.cpp",
     ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
 }
 
 cc_library {
@@ -49,6 +53,10 @@ cc_library {
     shared_libs: [
         "libbase",
     ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
     export_include_dirs: ["include"],
 }
 
@@ -63,6 +71,10 @@ cc_library_static {
         "libbinder",
         "libutils",
     ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
     export_include_dirs: ["include"],
 }
 
@@ -110,10 +122,13 @@ cc_defaults {
     header_libs: [
         "libstorage_literals_headers",
     ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
     target: {
         android: {
             shared_libs: [
-                "libprocessgroup",
                 "libvndksupport",
             ],
         },
diff --git a/gsi_service.h b/gsi_service.h
index 0dce269..9883b8b 100644
--- a/gsi_service.h
+++ b/gsi_service.h
@@ -108,8 +108,6 @@ class GsiService : public BinderService<GsiService>, public BnGsiService {
 
     bool SetBootMode(bool one_shot);
 
-    static android::wp<GsiService> sInstance;
-
     std::string install_dir_ = {};
     std::unique_ptr<PartitionInstaller> installer_;
     std::mutex lock_;
diff --git a/gsi_tool.cpp b/gsi_tool.cpp
index 6aa0fb5..6f78163 100644
--- a/gsi_tool.cpp
+++ b/gsi_tool.cpp
@@ -237,13 +237,11 @@ static int Install(sp<IGsiService> gsid, int argc, char** argv) {
             {"no-reboot", no_argument, nullptr, 'n'},
             {"userdata-size", required_argument, nullptr, 'u'},
             {"partition-name", required_argument, nullptr, 'p'},
-            {"wipe", no_argument, nullptr, 'w'},
             {nullptr, 0, nullptr, 0},
     };
 
     int64_t gsiSize = 0;
     int64_t userdataSize = 0;
-    bool wipeUserdata = false;
     bool reboot = true;
     std::string installDir = "";
     std::string partition = kDefaultPartition;
@@ -273,9 +271,6 @@ static int Install(sp<IGsiService> gsid, int argc, char** argv) {
             case 'i':
                 installDir = optarg;
                 break;
-            case 'w':
-                wipeUserdata = true;
-                break;
             case 'n':
                 reboot = false;
                 break;
diff --git a/libgsid.cpp b/libgsid.cpp
index fc75c90..73ef9bd 100644
--- a/libgsid.cpp
+++ b/libgsid.cpp
@@ -27,8 +27,7 @@ using android::sp;
 sp<IGsiService> GetGsiService() {
     auto sm = android::defaultServiceManager();
     auto name = android::String16(kGsiServiceName);
-    static android::sp<android::IBinder> res = sm->waitForService(name);
-    if (res) {
+    if (android::sp<android::IBinder> res = sm->waitForService(name)) {
         return android::interface_cast<IGsiService>(res);
     }
     LOG(ERROR) << "Unable to GetGsiService";
```

