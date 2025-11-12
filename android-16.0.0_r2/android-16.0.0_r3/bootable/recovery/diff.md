```diff
diff --git a/recovery_main.cpp b/recovery_main.cpp
index 903a3173..b65b4a82 100644
--- a/recovery_main.cpp
+++ b/recovery_main.cpp
@@ -76,11 +76,10 @@ static bool IsDeviceUnlocked() {
 static void UiLogger(android::base::LogId log_buffer_id, android::base::LogSeverity severity,
                      const char* tag, const char* file, unsigned int line, const char* message) {
   android::base::KernelLogger(log_buffer_id, severity, tag, file, line, message);
-  static constexpr auto&& log_characters = "VDIWEF";
   if (severity >= android::base::ERROR && ui != nullptr) {
     ui->Print("ERROR: %10s: %s\n", tag, message);
   } else {
-    fprintf(stdout, "%c:%s\n", log_characters[severity], message);
+    fprintf(stdout, "%c:%s\n", android::base::kSeverityChars[severity], message);
   }
 }
 
diff --git a/tools/recovery_l10n/Android.bp b/tools/recovery_l10n/Android.bp
index ac08e1a5..0040539b 100644
--- a/tools/recovery_l10n/Android.bp
+++ b/tools/recovery_l10n/Android.bp
@@ -30,3 +30,9 @@ android_app {
         "src/**/*.java",
     ],
 }
+
+filegroup {
+    name: "bootable_recovery_resources",
+    srcs: ["res/**/*.xml"],
+    path: "res",
+}
diff --git a/update_verifier/include/update_verifier/update_verifier.h b/update_verifier/include/update_verifier/update_verifier.h
index 0cccc907..f125508d 100644
--- a/update_verifier/include/update_verifier/update_verifier.h
+++ b/update_verifier/include/update_verifier/update_verifier.h
@@ -19,7 +19,6 @@
 #include <functional>
 #include <map>
 #include <string>
-#include <vector>
 
 #include <snapuserd/snapuserd_client.h>
 #include "otautil/rangeset.h"
@@ -28,10 +27,6 @@
 // During the verification, it reads all the blocks in the care_map. And if a failure happens,
 // it rejects the current boot and triggers a fallback.
 
-// Note that update_verifier should be backward compatible to not reject care_map.txt from old
-// releases, which could otherwise fail to boot into the new release. For example, we've changed
-// the care_map format between N and O. An O update_verifier would fail to work with N care_map.txt.
-// This could be a result of sideloading an O OTA while the device having a pending N update.
 int update_verifier(int argc, char** argv);
 
 // The UpdateVerifier parses the content in the care map, and continues to verify the
@@ -41,9 +36,8 @@ class UpdateVerifier {
  public:
   UpdateVerifier();
 
-  // This function tries to process the care_map.pb as protobuf message; and falls back to use
-  // care_map.txt if the pb format file doesn't exist. If the parsing succeeds, put the result
-  // of the pair <partition_name, ranges> into the |partition_map_|.
+  // This function tries to process the care_map.pb as protobuf message. If the parsing succeeds,
+  // put the result of the pair <partition_name, ranges> into the |partition_map_|.
   bool ParseCareMap();
 
   // Verifies the new boot by reading all the cared blocks for partitions in |partition_map_|.
diff --git a/update_verifier/update_verifier.cpp b/update_verifier/update_verifier.cpp
index a0160e2f..03b3741e 100644
--- a/update_verifier/update_verifier.cpp
+++ b/update_verifier/update_verifier.cpp
@@ -369,7 +369,7 @@ int update_verifier(int argc, char** argv) {
 
     bool supports_checkpoint = false;
     auto sm = android::defaultServiceManager();
-    android::sp<android::IBinder> binder = sm->getService(android::String16("vold"));
+    android::sp<android::IBinder> binder = sm->waitForService(android::String16("vold"));
     if (binder) {
       auto vold = android::interface_cast<android::os::IVold>(binder);
       android::binder::Status status = vold->supportsCheckpoint(&supports_checkpoint);
```

