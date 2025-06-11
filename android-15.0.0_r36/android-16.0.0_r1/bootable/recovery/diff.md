```diff
diff --git a/Android.bp b/Android.bp
index 0b4fefb8..e94a2c1b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -310,3 +310,58 @@ cc_library_shared {
         default: ["librecovery_ui_default"],
     }),
 }
+
+prebuilt_res {
+    name: "recovery-resources-common-mdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "res-mdpi/images/*.png",
+    ],
+    no_full_install: true,
+}
+
+prebuilt_res {
+    name: "recovery-resources-common-hdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "res-hdpi/images/*.png",
+    ],
+    no_full_install: true,
+}
+
+prebuilt_res {
+    name: "recovery-resources-common-xhdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "res-xhdpi/images/*.png",
+    ],
+    no_full_install: true,
+}
+
+prebuilt_res {
+    name: "recovery-resources-common-xxhdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "res-xxhdpi/images/*.png",
+    ],
+    no_full_install: true,
+}
+
+prebuilt_res {
+    name: "recovery-resources-common-xxxhdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "res-xxxhdpi/images/*.png",
+    ],
+    no_full_install: true,
+}
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975ca..00000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/OWNERS b/OWNERS
index 45c72e38..59235e0c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 elsk@google.com
 nhdo@google.com
-xunchang@google.com
 zhangkelvin@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 023d48b9..28aa06f4 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -6,6 +6,5 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
                   --file_whitelist tools/ updater_sample/
diff --git a/res-xxhdpi/Android.bp b/fonts/Android.bp
similarity index 72%
rename from res-xxhdpi/Android.bp
rename to fonts/Android.bp
index f1608b3f..8fefbe46 100644
--- a/res-xxhdpi/Android.bp
+++ b/fonts/Android.bp
@@ -15,12 +15,21 @@
 //
 
 prebuilt_res {
-    name: "recovery-resources-common-xxhdpi",
+    name: "recovery-fonts-12",
     recovery: true,
     install_in_root: true,
     relative_install_path: "images",
-    srcs: [
-        "images/*.png",
-    ],
+    src: "12x22.png",
     no_full_install: true,
+    filename: "font.png",
+}
+
+prebuilt_res {
+    name: "recovery-fonts-18",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    src: "18x32.png",
+    no_full_install: true,
+    filename: "font.png",
 }
diff --git a/install/include/install/snapshot_utils.h b/install/include/install/snapshot_utils.h
index f4b978d2..2f3f0214 100644
--- a/install/include/install/snapshot_utils.h
+++ b/install/include/install/snapshot_utils.h
@@ -28,3 +28,6 @@ bool FinishPendingSnapshotMerges(Device* device);
  * devices were created or there was no need to.
  */
 bool CreateSnapshotPartitions();
+
+// Check whether it's okay to cancel any in-progress OTAs for sideload.
+bool IsCancelUpdateSafe(Device* device);
diff --git a/install/install.cpp b/install/install.cpp
index 6294a3dc..ea9535cc 100644
--- a/install/install.cpp
+++ b/install/install.cpp
@@ -744,6 +744,23 @@ bool verify_package(Package* package, RecoveryUI* ui) {
   return true;
 }
 
+bool CheckPathCanonical(const std::string& path) {
+  // Reject the package if the input path doesn't equal the canonicalized path.
+  // e.g. /cache/../sdcard/update_package.
+  std::error_code ec;
+  auto canonical_path = std::filesystem::canonical(path, ec);
+  if (ec) {
+    LOG(ERROR) << "Failed to get canonical of " << path << ", " << ec.message();
+    return false;
+  }
+  if (canonical_path.string() != path) {
+    LOG(ERROR) << "Installation aborts. The canonical path " << canonical_path.string()
+               << " doesn't equal the original path " << path;
+    return false;
+  }
+  return true;
+}
+
 bool SetupPackageMount(const std::string& package_path, bool* should_use_fuse) {
   CHECK(should_use_fuse != nullptr);
 
@@ -754,10 +771,28 @@ bool SetupPackageMount(const std::string& package_path, bool* should_use_fuse) {
   *should_use_fuse = true;
   if (package_path[0] == '@') {
     auto block_map_path = package_path.substr(1);
+    if (!CheckPathCanonical(block_map_path)) {
+      LOG(ERROR) << "Block map path " << package_path << " not canonical, abort installation.";
+      return false;
+    }
+
     if (ensure_path_mounted(block_map_path) != 0) {
       LOG(ERROR) << "Failed to mount " << block_map_path;
       return false;
     }
+    auto block_map_data = BlockMapData::ParseBlockMapFile(block_map_path);
+    if (!CheckPathCanonical(block_map_data.path())) {
+      LOG(ERROR) << "Block map " << package_path << " contains non-canonical path "
+                 << block_map_data.path() << " abort installation.";
+      return false;
+    }
+    if (!BlockDevHasFstab(block_map_data.path())) {
+      LOG(ERROR) << "Block device " << block_map_path
+                 << " does not have corresponding fstab. This might be an external device, "
+                    "aborting installation.";
+      return false;
+    }
+
     // uncrypt only produces block map only if the package stays on /data.
     *should_use_fuse = false;
     return true;
@@ -769,17 +804,8 @@ bool SetupPackageMount(const std::string& package_path, bool* should_use_fuse) {
     return false;
   }
 
-  // Reject the package if the input path doesn't equal the canonicalized path.
-  // e.g. /cache/../sdcard/update_package.
-  std::error_code ec;
-  auto canonical_path = std::filesystem::canonical(package_path, ec);
-  if (ec) {
-    LOG(ERROR) << "Failed to get canonical of " << package_path << ", " << ec.message();
-    return false;
-  }
-  if (canonical_path.string() != package_path) {
-    LOG(ERROR) << "Installation aborts. The canonical path " << canonical_path.string()
-               << " doesn't equal the original path " << package_path;
+  if (!CheckPathCanonical(package_path)) {
+    LOG(ERROR) << "Block map path " << package_path << " not canonical, abort installation.";
     return false;
   }
 
diff --git a/install/snapshot_utils.cpp b/install/snapshot_utils.cpp
index 336e50f8..17ee00cd 100644
--- a/install/snapshot_utils.cpp
+++ b/install/snapshot_utils.cpp
@@ -23,9 +23,20 @@
 #include "recovery_ui/ui.h"
 #include "recovery_utils/roots.h"
 
+using android::snapshot::CancelResult;
 using android::snapshot::CreateResult;
 using android::snapshot::SnapshotManager;
 
+bool IsCancelUpdateSafe(Device* device) {
+  auto sm = SnapshotManager::New();
+  if (!sm) {
+    RecoveryUI* ui = device->GetUI();
+    ui->Print("Could not create SnapshotManager.\n");
+    return false;
+  }
+  return sm->IsCancelUpdateSafe();
+}
+
 bool FinishPendingSnapshotMerges(Device* device) {
   if (!android::base::GetBoolProperty("ro.virtual_ab.enabled", false)) {
     return true;
diff --git a/recovery.cpp b/recovery.cpp
index 7dd005f7..b7bf629c 100644
--- a/recovery.cpp
+++ b/recovery.cpp
@@ -175,6 +175,25 @@ static bool ask_to_wipe_data(Device* device) {
   return (chosen_item == 1);
 }
 
+static bool ask_to_cancel_ota(Device* device) {
+  // clang-format off
+  std::vector<std::string> headers{
+    "Overwrite in-progress update?",
+    "An update may already be in progress. If you proceed, "
+    "the existing OS may not longer boot, and completing "
+    "an update via ADB will be required."
+  };
+  std::vector<std::string> items{
+    "Cancel",
+    "Continue",
+  };
+  // clang-format on
+  size_t chosen_item = device->GetUI()->ShowMenu(
+      headers, items, 0, true,
+      std::bind(&Device::HandleMenuKey, device, std::placeholders::_1, std::placeholders::_2));
+  return (chosen_item == 1);
+}
+
 static InstallResult prompt_and_wipe_data(Device* device) {
   // Reset to normal system boot so recovery won't cycle indefinitely.
   std::string err;
@@ -461,6 +480,12 @@ static Device::BuiltinAction PromptAndWait(Device* device, InstallResult status)
       case Device::ENTER_RESCUE: {
         save_current_log = true;
 
+        if (!IsCancelUpdateSafe(device)) {
+          if (!ask_to_cancel_ota(device)) {
+            break;
+          }
+        }
+
         update_in_progress = true;
         WriteUpdateInProgress();
 
diff --git a/recovery_utils/include/recovery_utils/roots.h b/recovery_utils/include/recovery_utils/roots.h
index 6afefb81..103a3b23 100644
--- a/recovery_utils/include/recovery_utils/roots.h
+++ b/recovery_utils/include/recovery_utils/roots.h
@@ -32,6 +32,10 @@ Volume* volume_for_mount_point(const std::string& mount_point);
 // success (volume is mounted).
 int ensure_path_mounted(const std::string& path);
 
+// Return true if the block device has a corresponding entry
+// in fstab
+bool BlockDevHasFstab(const std::string& path);
+
 // Similar to ensure_path_mounted, but allows one to specify the mount_point.
 int ensure_path_mounted_at(const std::string& path, const std::string& mount_point);
 
diff --git a/recovery_utils/roots.cpp b/recovery_utils/roots.cpp
index 2825bdae..36b7c388 100644
--- a/recovery_utils/roots.cpp
+++ b/recovery_utils/roots.cpp
@@ -29,6 +29,7 @@
 #include <string>
 #include <vector>
 
+#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
@@ -90,6 +91,25 @@ int ensure_path_unmounted(const std::string& path) {
   return android::fs_mgr::EnsurePathUnmounted(&fstab, path) ? 0 : -1;
 }
 
+bool BlockDevHasFstab(const std::string& path) {
+  std::string bdev_path;
+  if (!android::base::Realpath(path, &bdev_path)) {
+    PLOG(ERROR) << "Failed to get realpath for " << path;
+    return false;
+  }
+  for (const auto& entry : fstab) {
+    std::string fstab_bdev_path;
+    if (!android::base::Realpath(entry.blk_device, &fstab_bdev_path)) {
+      PLOG(ERROR) << "Failed to get realpath for " << entry.blk_device;
+      return false;
+    }
+    if (fstab_bdev_path == bdev_path) {
+      return true;
+    }
+  }
+  return false;
+}
+
 static int exec_cmd(const std::vector<std::string>& args) {
   CHECK(!args.empty());
   auto argv = StringVectorToNullTerminatedArray(args);
diff --git a/res-hdpi/Android.bp b/res-hdpi/Android.bp
deleted file mode 100644
index 0cf3a5ba..00000000
--- a/res-hdpi/Android.bp
+++ /dev/null
@@ -1,26 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-prebuilt_res {
-    name: "recovery-resources-common-hdpi",
-    recovery: true,
-    install_in_root: true,
-    relative_install_path: "images",
-    srcs: [
-        "images/*.png",
-    ],
-    no_full_install: true,
-}
diff --git a/res-mdpi/Android.bp b/res-mdpi/Android.bp
deleted file mode 100644
index efdbbe1c..00000000
--- a/res-mdpi/Android.bp
+++ /dev/null
@@ -1,26 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-prebuilt_res {
-    name: "recovery-resources-common-mdpi",
-    recovery: true,
-    install_in_root: true,
-    relative_install_path: "images",
-    srcs: [
-        "images/*.png",
-    ],
-    no_full_install: true,
-}
diff --git a/res-xhdpi/Android.bp b/res-xhdpi/Android.bp
deleted file mode 100644
index cdddc5d1..00000000
--- a/res-xhdpi/Android.bp
+++ /dev/null
@@ -1,26 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-prebuilt_res {
-    name: "recovery-resources-common-xhdpi",
-    recovery: true,
-    install_in_root: true,
-    relative_install_path: "images",
-    srcs: [
-        "images/*.png",
-    ],
-    no_full_install: true,
-}
diff --git a/res-xxxhdpi/Android.bp b/res-xxxhdpi/Android.bp
deleted file mode 100644
index 6e062692..00000000
--- a/res-xxxhdpi/Android.bp
+++ /dev/null
@@ -1,26 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-prebuilt_res {
-    name: "recovery-resources-common-xxxhdpi",
-    recovery: true,
-    install_in_root: true,
-    relative_install_path: "images",
-    srcs: [
-        "images/*.png",
-    ],
-    no_full_install: true,
-}
diff --git a/tests/Android.bp b/tests/Android.bp
index b8991b01..ac1d717d 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -39,7 +39,6 @@ cc_defaults {
         "libcutils",
         "liblog",
         "libpng",
-        "libprocessgroup",
         "libselinux",
         "libziparchive",
     ],
diff --git a/tools/recovery_l10n/res/values-kn/strings.xml b/tools/recovery_l10n/res/values-kn/strings.xml
index eafd831e..c1e677ea 100644
--- a/tools/recovery_l10n/res/values-kn/strings.xml
+++ b/tools/recovery_l10n/res/values-kn/strings.xml
@@ -9,6 +9,6 @@
     <string name="recovery_wipe_data_menu_header" msgid="550255032058254478">"Android ಸಿಸ್ಟಂ ಅನ್ನು ಲೋಡ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ. ನಿಮ್ಮ ಡೇಟಾ ದೋಷಪೂರಿತವಾಗಿರಬಹುದು. ನೀವು ಈ ಸಂದೇಶ ಪಡೆಯುವುದು ಮುಂದುವರಿದರೆ, ನೀವು ಫ್ಯಾಕ್ಟರಿ ಡೇಟಾ ರಿಸೆಟ್ ಮಾಡುವ ಅಗತ್ಯವಿದೆ ಮತ್ತು ಈ ಸಾಧನದಲ್ಲಿ ಸಂಗ್ರಹಿಸಲಾದ ಎಲ್ಲಾ ಬಳಕೆದಾರರ ಡೇಟಾವನ್ನು ಅಳಿಸಬೇಕಾಗುತ್ತದೆ."</string>
     <string name="recovery_try_again" msgid="7168248750158873496">"ಮತ್ತೆ ಪ್ರಯತ್ನಿಸಿ"</string>
     <string name="recovery_factory_data_reset" msgid="7321351565602894783">"ಫ್ಯಾಕ್ಟರಿ ಡೇಟಾ ರೀಸೆಟ್"</string>
-    <string name="recovery_wipe_data_confirmation" msgid="5439823343348043954">"ಎಲ್ಲಾ ಬಳಕೆದಾರರ ಡೇಟಾವನ್ನು ಅಳಿಸುವುದೇ?\n\n ಇದನ್ನು ರದ್ದುಗೊಳಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ!"</string>
+    <string name="recovery_wipe_data_confirmation" msgid="5439823343348043954">"ಎಲ್ಲಾ ಬಳಕೆದಾರರ ಡೇಟಾವನ್ನು ಅಳಿಸಬೇಕೆ?\n\n ಇದನ್ನು ರದ್ದುಗೊಳಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ!"</string>
     <string name="recovery_cancel_wipe_data" msgid="66987687653647384">"ರದ್ದುಮಾಡಿ"</string>
 </resources>
diff --git a/tools/recovery_l10n/res/values-mr/strings.xml b/tools/recovery_l10n/res/values-mr/strings.xml
index 9b137079..68c1525e 100644
--- a/tools/recovery_l10n/res/values-mr/strings.xml
+++ b/tools/recovery_l10n/res/values-mr/strings.xml
@@ -1,12 +1,12 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recovery_installing" msgid="2013591905463558223">"सिस्टम अपडेट इंस्टॉल करत आहे"</string>
+    <string name="recovery_installing" msgid="2013591905463558223">"सिस्टीम अपडेट इंस्टॉल करत आहे"</string>
     <string name="recovery_erasing" msgid="7334826894904037088">"मिटवत आहे"</string>
     <string name="recovery_no_command" msgid="4465476568623024327">"कोणतीही कमांड नाही"</string>
     <string name="recovery_error" msgid="5748178989622716736">"एरर!"</string>
     <string name="recovery_installing_security" msgid="9184031299717114342">"सुरक्षा अपडेट इंस्टॉल करत आहे"</string>
-    <string name="recovery_wipe_data_menu_header" msgid="550255032058254478">"Android सिस्टम लोड करू शकत नाही. तुमचा डेटा धोक्यात असू शकतो.तुम्हाला हा मेसेज मिळत राहिल्यास, फॅक्टरी डेटा रीसेट करणे आणि या डिव्हाइसवर स्टोअर केलेला सर्व वापरकर्ता डेटा मिटवणे आवश्यक आहे."</string>
+    <string name="recovery_wipe_data_menu_header" msgid="550255032058254478">"Android सिस्टीम लोड करता आली नाही. तुमचा डेटा धोक्यात असू शकतो. तुम्हाला हा मेसेज मिळत राहिल्यास, फॅक्टरी डेटा रीसेट करणे आणि या डिव्हाइसवर स्टोअर केलेला सर्व वापरकर्ता डेटा मिटवणे आवश्यक आहे."</string>
     <string name="recovery_try_again" msgid="7168248750158873496">"पुन्हा प्रयत्न करा"</string>
     <string name="recovery_factory_data_reset" msgid="7321351565602894783">"फॅक्‍टरी डेटा रीसेट"</string>
     <string name="recovery_wipe_data_confirmation" msgid="5439823343348043954">"सर्व वापरकर्ता डेटा पुसून टाकायचा का?\n\n हे पहिल्‍यासारखे करू शकत नाही!"</string>
diff --git a/update_verifier/Android.bp b/update_verifier/Android.bp
index aff91471..a9c6a8be 100644
--- a/update_verifier/Android.bp
+++ b/update_verifier/Android.bp
@@ -38,7 +38,10 @@ python_library_host {
     srcs: [
         "care_map.proto",
     ],
-    proto: {type: "lite", canonical_path_from_root: false},
+    proto: {
+        type: "lite",
+        canonical_path_from_root: false,
+    },
     visibility: [
         "//build/make/tools/releasetools:__subpackages__",
     ],
@@ -136,9 +139,4 @@ python_binary_host {
         canonical_path_from_root: false,
     },
 
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
```

