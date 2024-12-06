```diff
diff --git a/Android.bp b/Android.bp
index 67ece850..20a2098e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -111,7 +111,6 @@ cc_defaults {
     ],
 
     static_libs: [
-        "libc++fs",
         "libinstall",
         "librecovery_fastboot",
         "libminui",
diff --git a/Android.mk b/Android.mk
index 3d1ee39c..85c3a901 100644
--- a/Android.mk
+++ b/Android.mk
@@ -46,6 +46,7 @@ LOCAL_WHOLE_STATIC_LIBRARIES := \
 
 LOCAL_SHARED_LIBRARIES := \
     libbase.recovery \
+    libboot_control_client.recovery \
     liblog.recovery \
     librecovery_ui.recovery
 
diff --git a/install/adb_install.cpp b/install/adb_install.cpp
index b12e5294..79426ff2 100644
--- a/install/adb_install.cpp
+++ b/install/adb_install.cpp
@@ -167,7 +167,7 @@ static bool HandleMessageFromMinadbd(int socket_fd,
   if (command_type == MinadbdCommand::kError) {
     return false;
   }
-  if (command_map.find(command_type) == command_map.end()) {
+  if (!command_map.contains(command_type)) {
     LOG(ERROR) << "Unsupported command: "
                << android::base::get_unaligned<unsigned int>(
                       message.substr(strlen(kMinadbdCommandPrefix)).c_str());
diff --git a/minadbd/minadbd_services.cpp b/minadbd/minadbd_services.cpp
index 16bcb5ed..df562537 100644
--- a/minadbd/minadbd_services.cpp
+++ b/minadbd/minadbd_services.cpp
@@ -233,7 +233,7 @@ static void RescueGetpropHostService(unique_fd sfd, const std::string& prop) {
       }
       result += "[" + key + "]: [" + value + "]\n";
     }
-  } else if (kGetpropAllowedProps.find(prop) != kGetpropAllowedProps.end()) {
+  } else if (kGetpropAllowedProps.contains(prop)) {
     result = query_prop(prop) + "\n";
   }
   if (result.empty()) {
diff --git a/minui/Android.bp b/minui/Android.bp
index 02fb3638..c731dd42 100644
--- a/minui/Android.bp
+++ b/minui/Android.bp
@@ -50,7 +50,6 @@ cc_library {
     shared_libs: [
         "libbase",
         "libpng",
-        "libz",
     ],
 
     target: {
diff --git a/recovery_utils/roots.cpp b/recovery_utils/roots.cpp
index e7a7d652..2825bdae 100644
--- a/recovery_utils/roots.cpp
+++ b/recovery_utils/roots.cpp
@@ -37,6 +37,7 @@
 #include <ext4_utils/wipe.h>
 #include <fs_mgr.h>
 #include <fs_mgr/roots.h>
+#include <fstab/fstab.h>
 
 #include "otautil/sysutil.h"
 
@@ -130,13 +131,68 @@ static int64_t get_file_size(int fd, uint64_t reserve_len) {
   return computed_size;
 }
 
+static FstabEntry* LocateFormattableEntry(const std::vector<FstabEntry*>& entries) {
+  if (entries.empty()) {
+    return nullptr;
+  }
+  FstabEntry* f2fs_entry = nullptr;
+  for (auto&& entry : entries) {
+    if (getpagesize() != 4096 && entry->fs_type == "f2fs") {
+      f2fs_entry = entry;
+      continue;
+    }
+    if (f2fs_entry) {
+      LOG(INFO) << "Skipping F2FS format for block device " << entry->blk_device << " @ "
+                << entry->mount_point
+                << " in non-4K mode for dev option enabled devices, "
+                   "as these devices need to toggle between 4K/16K mode, and F2FS does "
+                   "not support page_size != block_size configuration.";
+    }
+    return entry;
+  }
+  if (f2fs_entry) {
+    LOG(INFO) << "Using F2FS for " << f2fs_entry->blk_device << " @ " << f2fs_entry->mount_point
+              << " even though we are in non-4K mode. Device might require a data wipe after "
+                 "going back to 4K mode, as F2FS does not support page_size != block_size";
+  }
+  return f2fs_entry;
+}
+
+bool WipeBlockDevice(const char* path) {
+  android::base::unique_fd fd(open(path, O_RDWR));
+  if (fd == -1) {
+    PLOG(ERROR) << "WipeBlockDevice: failed to open " << path;
+    return false;
+  }
+  int64_t device_size = get_file_size(fd.get(), 0);
+  if (device_size < 0) {
+    PLOG(ERROR) << "WipeBlockDevice: failed to determine size of " << device_size;
+    return false;
+  }
+  if (device_size == 0) {
+    PLOG(ERROR) << "WipeBlockDevice: block device " << device_size << " has 0 length, skip wiping";
+    return false;
+  }
+  if (!wipe_block_device(fd.get(), device_size)) {
+    return true;
+  }
+  PLOG(ERROR) << "Failed to wipe " << path;
+  return false;
+}
+
 int format_volume(const std::string& volume, const std::string& directory,
                   std::string_view new_fstype) {
-  const FstabEntry* v = android::fs_mgr::GetEntryForPath(&fstab, volume);
-  if (v == nullptr) {
+  const auto entries = android::fs_mgr::GetEntriesForPath(&fstab, volume);
+  if (entries.empty()) {
     LOG(ERROR) << "unknown volume \"" << volume << "\"";
     return -1;
   }
+
+  const FstabEntry* v = LocateFormattableEntry(entries);
+  if (v == nullptr) {
+    LOG(ERROR) << "Unable to find formattable entry for \"" << volume << "\"";
+    return -1;
+  }
   if (v->fs_type == "ramdisk") {
     LOG(ERROR) << "can't format_volume \"" << volume << "\"";
     return -1;
@@ -273,13 +329,17 @@ int format_volume(const std::string& volume, const std::string& directory,
     make_f2fs_cmd.push_back("-O");
     make_f2fs_cmd.push_back("extra_attr");
   }
+  make_f2fs_cmd.push_back("-b");
+  make_f2fs_cmd.push_back(std::to_string(getpagesize()));
   make_f2fs_cmd.push_back(v->blk_device);
   if (length >= kSectorSize) {
     make_f2fs_cmd.push_back(std::to_string(length / kSectorSize));
   }
 
   if (exec_cmd(make_f2fs_cmd) != 0) {
-    PLOG(ERROR) << "format_volume: Failed to make_f2fs on " << v->blk_device;
+    PLOG(ERROR) << "format_volume: Failed to make_f2fs on " << v->blk_device
+                << " wiping the block device to avoid leaving partially formatted data.";
+    WipeBlockDevice(v->blk_device.c_str());
     return -1;
   }
   if (!directory.empty()) {
diff --git a/tests/Android.bp b/tests/Android.bp
index 55d3dbf3..99f6a8de 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -83,7 +83,6 @@ librecovery_static_libs = [
     "libhidlbase",
     "liblp",
     "libtinyxml2",
-    "libc++fs",
 ]
 
 // recovery image for unittests.
diff --git a/tools/recovery_l10n/res/values-gu/strings.xml b/tools/recovery_l10n/res/values-gu/strings.xml
index bd83447d..cf1aefc7 100644
--- a/tools/recovery_l10n/res/values-gu/strings.xml
+++ b/tools/recovery_l10n/res/values-gu/strings.xml
@@ -6,7 +6,7 @@
     <string name="recovery_no_command" msgid="4465476568623024327">"કોઈ આદેશ નથી"</string>
     <string name="recovery_error" msgid="5748178989622716736">"ભૂલ!"</string>
     <string name="recovery_installing_security" msgid="9184031299717114342">"સુરક્ષા અપડેટ ઇન્સ્ટૉલ કરી રહ્યાં છે"</string>
-    <string name="recovery_wipe_data_menu_header" msgid="550255032058254478">"Android સિસ્ટમ લોડ કરી શકાતી નથી. તમારો ડેટા કદાચ દૂષિત થયો હોઈ શકે છે. જો તમને આ સંદેશ મળવાનું ચાલુ રહે, તો કદાચ તમારે આ ડિવાઇસ માટે ફેક્ટરી ડેટા રીસેટ કરવાની પ્રક્રિયા કરવી અને આના પર સ્ટોર કરેલો વપરાશકર્તાનો બધો ડેટા કાઢી નાખવો જરૂરી રહેશે."</string>
+    <string name="recovery_wipe_data_menu_header" msgid="550255032058254478">"Android સિસ્ટમ લોડ કરી શકાતી નથી. તમારો ડેટા કદાચ દૂષિત થયો હોઈ શકે છે. જો તમને આ મેસેજ મળવાનું ચાલુ રહે, તો કદાચ તમારે આ ડિવાઇસ માટે ફેક્ટરી ડેટા રીસેટ કરવાની પ્રક્રિયા કરવી અને આના પર સ્ટોર કરેલો વપરાશકર્તાનો બધો ડેટા કાઢી નાખવો જરૂરી રહેશે."</string>
     <string name="recovery_try_again" msgid="7168248750158873496">"ફરી પ્રયાસ કરો"</string>
     <string name="recovery_factory_data_reset" msgid="7321351565602894783">"ફેક્ટરી ડેટા રીસેટ કરો"</string>
     <string name="recovery_wipe_data_confirmation" msgid="5439823343348043954">"શું વપરાશકર્તાનો બધો ડેટા વાઇપ કરીએ?\n\n આ ક્રિયામાં કરેલો ફેરફાર રદ કરી શકાતો નથી!"</string>
```

