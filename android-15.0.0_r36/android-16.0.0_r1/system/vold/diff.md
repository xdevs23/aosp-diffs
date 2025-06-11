```diff
diff --git a/Android.bp b/Android.bp
index ba3267ca..bef64710 100644
--- a/Android.bp
+++ b/Android.bp
@@ -43,6 +43,7 @@ cc_defaults {
         "libfs_mgr",
         "libsquashfs_utils",
         "libvold_binder",
+        "android.system.vold-V1-cpp",
     ],
     shared_libs: [
         "android.hardware.boot@1.0",
@@ -103,6 +104,11 @@ cc_library_headers {
     export_include_dirs: ["."],
 }
 
+vintf_fragment {
+    name: "android.system.vold-service.xml",
+    src: "android.system.vold-service.xml",
+}
+
 // Static library factored out to support testing
 cc_library_static {
     name: "libvold",
@@ -132,10 +138,12 @@ cc_library_static {
         "NetlinkManager.cpp",
         "Process.cpp",
         "Utils.cpp",
+        "VendorVoldNativeService.cpp",
         "VoldNativeService.cpp",
         "VoldNativeServiceValidation.cpp",
         "VoldUtil.cpp",
         "VolumeManager.cpp",
+        "WriteBooster.cpp",
         "cryptfs.cpp",
         "fs/Exfat.cpp",
         "fs/Ext4.cpp",
@@ -150,6 +158,12 @@ cc_library_static {
         "model/VolumeBase.cpp",
         "model/VolumeEncryption.cpp",
     ],
+    shared_libs: [
+        "server_configurable_flags",
+    ],
+    static_libs: [
+        "vold_flags_c_lib",
+    ],
     product_variables: {
         arc: {
             exclude_srcs: [
@@ -198,6 +212,7 @@ cc_binary {
             ],
         },
     },
+    vintf_fragment_modules: ["android.system.vold-service.xml"],
 }
 
 cc_binary {
@@ -262,3 +277,15 @@ filegroup {
     ],
     path: "binder",
 }
+
+aconfig_declarations {
+    name: "vold_flags",
+    package: "android.vold.flags",
+    srcs: ["aconfig/flags.aconfig"],
+    container: "system",
+}
+
+cc_aconfig_library {
+    name: "vold_flags_c_lib",
+    aconfig_declarations: "vold_flags",
+}
\ No newline at end of file
diff --git a/Checkpoint.cpp b/Checkpoint.cpp
index 598a87bc..195a1372 100644
--- a/Checkpoint.cpp
+++ b/Checkpoint.cpp
@@ -136,13 +136,16 @@ Status cp_startCheckpoint(int retry) {
         return error(ENOTSUP, "Checkpoints not supported");
 
     if (retry < -1) return error(EINVAL, "Retry count must be more than -1");
-    std::string content = std::to_string(retry + 1);
+    std::string content;
     if (retry == -1) {
+        content = std::to_string(-1);
         auto module = BootControlClient::WaitForService();
         if (module) {
             std::string suffix = module->GetSuffix(module->GetCurrentSlot());
             if (!suffix.empty()) content += " " + suffix;
         }
+    } else {
+        content = std::to_string(retry + 1);
     }
     if (!android::base::WriteStringToFile(content, kMetadataCPFile))
         return error("Failed to write checkpoint file");
@@ -159,6 +162,21 @@ volatile bool needsCheckpointWasCalled = false;
 // Protects isCheckpointing, needsCheckpointWasCalled and code that makes decisions based on status
 // of isCheckpointing
 std::mutex isCheckpointingLock;
+
+std::mutex listenersLock;
+std::vector<android::sp<android::system::vold::IVoldCheckpointListener>> listeners;
+}  // namespace
+
+void notifyCheckpointListeners() {
+    std::lock_guard<std::mutex> lock(listenersLock);
+
+    for (auto& listener : listeners) {
+        listener->onCheckpointingComplete();
+        listener = nullptr;
+    }
+
+    // Reclaim vector memory; we likely won't need it again.
+    listeners = std::vector<android::sp<android::system::vold::IVoldCheckpointListener>>();
 }
 
 Status cp_commitChanges() {
@@ -221,6 +239,8 @@ Status cp_commitChanges() {
     if (!android::base::RemoveFileIfExists(kMetadataCPFile, &err_str))
         return error(err_str.c_str());
 
+    notifyCheckpointListeners();
+
     std::thread(DoCheckpointCommittedWork).detach();
     return Status::ok();
 }
@@ -290,18 +310,21 @@ bool cp_needsCheckpoint() {
     std::string content;
     auto module = BootControlClient::WaitForService();
 
-    if (isCheckpointing) return isCheckpointing;
+    if (isCheckpointing) return true;
+
     // In case of INVALID slot or other failures, we do not perform checkpoint.
     if (module && !module->IsSlotMarkedSuccessful(module->GetCurrentSlot()).value_or(true)) {
         isCheckpointing = true;
         return true;
     }
     ret = android::base::ReadFileToString(kMetadataCPFile, &content);
-    if (ret) {
-        ret = content != "0";
-        isCheckpointing = ret;
-        return ret;
+    if (ret && content != "0") {
+        isCheckpointing = true;
+        return true;
     }
+
+    // Leave isCheckpointing false and notify listeners now that we know we don't need one
+    notifyCheckpointListeners();
     return false;
 }
 
@@ -801,5 +824,20 @@ void cp_resetCheckpoint() {
     needsCheckpointWasCalled = false;
 }
 
+bool cp_registerCheckpointListener(
+        android::sp<android::system::vold::IVoldCheckpointListener> listener) {
+    std::lock_guard<std::mutex> checkpointGuard(isCheckpointingLock);
+    if (needsCheckpointWasCalled && !isCheckpointing) {
+        // Either checkpoint already committed or we didn't need one
+        return false;
+    }
+
+    // Either we don't know whether we need a checkpoint or we're already checkpointing,
+    // so we need to save this listener to notify later.
+    std::lock_guard<std::mutex> listenersGuard(listenersLock);
+    listeners.push_back(std::move(listener));
+    return true;
+}
+
 }  // namespace vold
 }  // namespace android
diff --git a/Checkpoint.h b/Checkpoint.h
index 6f3acacf..76253106 100644
--- a/Checkpoint.h
+++ b/Checkpoint.h
@@ -17,6 +17,7 @@
 #ifndef _CHECKPOINT_H
 #define _CHECKPOINT_H
 
+#include <android/system/vold/IVold.h>
 #include <binder/Status.h>
 #include <string>
 
@@ -48,6 +49,9 @@ android::binder::Status cp_restoreCheckpoint(const std::string& mountPoint, int
 android::binder::Status cp_markBootAttempt();
 
 void cp_resetCheckpoint();
+
+bool cp_registerCheckpointListener(
+        android::sp<android::system::vold::IVoldCheckpointListener> listener);
 }  // namespace vold
 }  // namespace android
 
diff --git a/OWNERS b/OWNERS
index 6d8d89fa..81da3291 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
-alanstokes@google.com
 drosen@google.com
 ebiggers@google.com
 jeffv@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be1..c8dbf77f 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -3,6 +3,3 @@ clang_format = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
-
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/Process.cpp b/Process.cpp
index 426a4252..0115fb16 100644
--- a/Process.cpp
+++ b/Process.cpp
@@ -46,7 +46,7 @@ using android::base::StringPrintf;
 namespace android {
 namespace vold {
 
-static bool checkMaps(const std::string& path, const std::string& prefix) {
+static bool checkMaps(const std::string& path, const std::vector<std::string>& prefixes) {
     bool found = false;
     auto file = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
     if (!file) {
@@ -60,9 +60,14 @@ static bool checkMaps(const std::string& path, const std::string& prefix) {
         std::string::size_type pos = line.find('/');
         if (pos != std::string::npos) {
             line = line.substr(pos);
-            if (android::base::StartsWith(line, prefix)) {
-                LOG(WARNING) << "Found map " << path << " referencing " << line;
-                found = true;
+            for (const auto& prefix : prefixes) {
+                if (android::base::StartsWith(line, prefix)) {
+                    LOG(WARNING) << "Found map " << path << " referencing " << line;
+                    found = true;
+                    break;
+                }
+            }
+            if (found) {
                 break;
             }
         }
@@ -72,12 +77,14 @@ static bool checkMaps(const std::string& path, const std::string& prefix) {
     return found;
 }
 
-static bool checkSymlink(const std::string& path, const std::string& prefix) {
+static bool checkSymlink(const std::string& path, const std::vector<std::string>& prefixes) {
     std::string res;
     if (android::base::Readlink(path, &res)) {
-        if (android::base::StartsWith(res, prefix)) {
-            LOG(WARNING) << "Found symlink " << path << " referencing " << res;
-            return true;
+        for (const auto& prefix : prefixes) {
+            if (android::base::StartsWith(res, prefix)) {
+                LOG(WARNING) << "Found symlink " << path << " referencing " << res;
+                return true;
+            }
         }
     }
     return false;
@@ -129,7 +136,8 @@ int KillProcessesWithTmpfsMounts(const std::string& prefix, int signal) {
     return pids.size();
 }
 
-int KillProcessesWithOpenFiles(const std::string& prefix, int signal, bool killFuseDaemon) {
+int KillProcessesWithOpenFiles(const std::vector<std::string>& prefixes, int signal,
+                               bool killFuseDaemon) {
     std::unordered_set<pid_t> pids;
 
     auto proc_d = std::unique_ptr<DIR, int (*)(DIR*)>(opendir("/proc"), closedir);
@@ -148,10 +156,10 @@ int KillProcessesWithOpenFiles(const std::string& prefix, int signal, bool killF
         // Look for references to prefix
         bool found = false;
         auto path = StringPrintf("/proc/%d", pid);
-        found |= checkMaps(path + "/maps", prefix);
-        found |= checkSymlink(path + "/cwd", prefix);
-        found |= checkSymlink(path + "/root", prefix);
-        found |= checkSymlink(path + "/exe", prefix);
+        found |= checkMaps(path + "/maps", prefixes);
+        found |= checkSymlink(path + "/cwd", prefixes);
+        found |= checkSymlink(path + "/root", prefixes);
+        found |= checkSymlink(path + "/exe", prefixes);
 
         auto fd_path = path + "/fd";
         auto fd_d = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(fd_path.c_str()), closedir);
@@ -161,7 +169,7 @@ int KillProcessesWithOpenFiles(const std::string& prefix, int signal, bool killF
             struct dirent* fd_de;
             while ((fd_de = readdir(fd_d.get())) != nullptr) {
                 if (fd_de->d_type != DT_LNK) continue;
-                found |= checkSymlink(fd_path + "/" + fd_de->d_name, prefix);
+                found |= checkSymlink(fd_path + "/" + fd_de->d_name, prefixes);
             }
         }
 
@@ -198,5 +206,10 @@ int KillProcessesWithOpenFiles(const std::string& prefix, int signal, bool killF
     return totalKilledPids;
 }
 
+int KillProcessesWithOpenFiles(const std::string& prefix, int signal, bool killFuseDaemon) {
+    return KillProcessesWithOpenFiles(std::vector<std::string>(1, prefix), signal,
+                                      killFuseDaemon);
+}
+
 }  // namespace vold
 }  // namespace android
diff --git a/Process.h b/Process.h
index f3728b5d..8a20d1c2 100644
--- a/Process.h
+++ b/Process.h
@@ -20,6 +20,8 @@
 namespace android {
 namespace vold {
 
+int KillProcessesWithOpenFiles(const std::vector<std::string>& paths, int signal,
+                               bool killFuseDaemon = true);
 int KillProcessesWithOpenFiles(const std::string& path, int signal, bool killFuseDaemon = true);
 int KillProcessesWithTmpfsMounts(const std::string& path, int signal);
 
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 93938b6d..50bd3dad 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -17,9 +17,6 @@
     },
     {
       "name": "CtsScopedStorageRedactUriTest"
-    },
-    {
-      "name": "AdoptableHostTest"
     }
   ],
   "hwasan-postsubmit": [
@@ -40,9 +37,6 @@
     },
     {
       "name": "CtsScopedStorageRedactUriTest"
-    },
-    {
-      "name": "AdoptableHostTest"
     }
   ]
 }
diff --git a/Utils.cpp b/Utils.cpp
index c4070d13..9ad828ca 100644
--- a/Utils.cpp
+++ b/Utils.cpp
@@ -1724,6 +1724,139 @@ status_t UnmountUserFuse(userid_t user_id, const std::string& absolute_lower_pat
     return result;
 }
 
+/* returns list of non unmounted paths */
+std::vector<std::string> UnmountFusePaths(const std::vector<std::string>& paths_to_unmount) {
+    std::vector<std::string> non_unmounted_paths;
+    for (const auto& path : paths_to_unmount) {
+        LOG(INFO) << "Unmounting fuse path " << path;
+        const char* cpath = path.c_str();
+        if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
+            rmdir(cpath);
+            continue;
+        }
+        non_unmounted_paths.push_back(path);
+    }
+    return non_unmounted_paths;
+}
+
+/* returns list of non unmounted paths */
+std::vector<std::string> UnmountFusePathsWithSleepAndPolling(
+        const std::vector<std::string>& paths_to_unmount) {
+    std::vector<std::string> non_unmounted_paths = paths_to_unmount;
+
+    int count = 10;
+    while (count-- > 0) {
+        usleep(500 * 1000);
+        non_unmounted_paths = UnmountFusePaths(non_unmounted_paths);
+        if (non_unmounted_paths.empty()) {
+            return non_unmounted_paths;
+        }
+    }
+    return non_unmounted_paths;
+}
+
+/* returns list of non unmounted paths */
+std::vector<std::string> KillProcessesWithFuseOpenFilesAndUnmount(
+        const std::vector<std::string>& paths_to_unmount, const std::string& absolute_upper_path,
+        int signal, bool kill_fuse_daemon, bool force_sleep_if_no_processes_killed) {
+
+    // In addition to killing apps using paths to unmount, we need to kill aps using
+    // the upper path (e.g storage/emulated) As they would prevent unmounting fuse
+    std::vector<std::string> paths_to_kill(paths_to_unmount);
+    paths_to_kill.push_back(absolute_upper_path);
+
+    int total_killed_pids = KillProcessesWithOpenFiles(paths_to_kill, signal, kill_fuse_daemon);
+
+    if (sSleepOnUnmount && (force_sleep_if_no_processes_killed || total_killed_pids)) {
+        return UnmountFusePathsWithSleepAndPolling(paths_to_unmount);
+    }
+    return UnmountFusePaths(paths_to_unmount);
+}
+
+status_t UnmountUserFuseEnhanced(userid_t user_id, const std::string& absolute_lower_path,
+                                 const std::string& relative_upper_path,
+                                 const std::string& absolute_upper_path,
+                                 const std::vector<std::string>& bind_mount_paths) {
+    std::vector<std::string> paths_to_unmount(bind_mount_paths);
+
+    std::string fuse_path(StringPrintf("/mnt/user/%d/%s", user_id, relative_upper_path.c_str()));
+    paths_to_unmount.push_back(fuse_path);
+
+    std::string pass_through_path(
+            StringPrintf("/mnt/pass_through/%d/%s", user_id, relative_upper_path.c_str()));
+    paths_to_unmount.push_back(pass_through_path);
+
+    auto start_time = std::chrono::steady_clock::now();
+    LOG(INFO) << "Unmounting fuse paths";
+
+    // Try unmounting without killing any processes
+    paths_to_unmount = UnmountFusePaths(paths_to_unmount);
+    if (paths_to_unmount.empty()) {
+        return android::OK;
+    }
+
+    // Kill processes except for FuseDaemon holding references to fuse paths with SIGINT
+    // And try to unmount afterwards with sleep and polling mechanism
+    paths_to_unmount = KillProcessesWithFuseOpenFilesAndUnmount(
+            paths_to_unmount, absolute_upper_path, SIGINT, /*kill_fuse_daemon*/ false,
+            /*force_sleep_if_no_processes_killed*/false);
+    if (paths_to_unmount.empty()) {
+        return android::OK;
+    }
+
+    // Kill processes except for FuseDaemon holding references to fuse paths with SIGTERM
+    // And try to unmount afterwards with sleep and polling mechanism
+    paths_to_unmount = KillProcessesWithFuseOpenFilesAndUnmount(
+            paths_to_unmount, absolute_upper_path, SIGTERM, /*kill_fuse_daemon*/ false,
+            /*force_sleep_if_no_processes_killed*/false);
+
+    if (paths_to_unmount.empty()) {
+        return android::OK;
+    }
+
+    auto now = std::chrono::steady_clock::now();
+    auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
+    bool force_sleep_if_no_process_killed = time_elapsed < std::chrono::milliseconds(5000);
+    // Kill processes except for FuseDaemon holding references to fuse paths with SIGKILL
+    // And try to unmount afterwards with sleep and polling mechanism
+    // intentionally force sleep if sSleepOnUnmount isn't set to false
+    // and if we haven't slept in previous retries so that we give MediaProvider time
+    // to release FDs prior to try killing it in the next step
+    paths_to_unmount = KillProcessesWithFuseOpenFilesAndUnmount(
+            paths_to_unmount, absolute_upper_path, SIGKILL, /*kill_fuse_daemon*/ false,
+            force_sleep_if_no_process_killed);
+
+    if (paths_to_unmount.empty()) {
+        return android::OK;
+    }
+
+    // Kill processes including FuseDaemon holding references to fuse paths with SIGKILL
+    // And try to unmount afterwards with sleep and polling mechanism
+    paths_to_unmount = KillProcessesWithFuseOpenFilesAndUnmount(
+            paths_to_unmount, absolute_upper_path, SIGKILL, /*kill_fuse_daemon*/ true,
+            /*force_sleep_if_no_processes_killed*/false);
+    if (paths_to_unmount.empty()) {
+        return android::OK;
+    }
+
+    // If we reached here, then it means that previous kill and unmount retries didn't succeed
+    // Try to unmount with MNT_DETACH so we try lazily unmount
+    android::status_t result = android::OK;
+    for (const auto& path : paths_to_unmount) {
+        LOG(ERROR) << "Failed to unmount. Trying MNT_DETACH " << path;
+        const char* cpath = path.c_str();
+        if (!umount2(cpath, UMOUNT_NOFOLLOW | MNT_DETACH) || errno == EINVAL || errno == ENOENT) {
+            rmdir(cpath);
+            continue;
+        }
+        PLOG(ERROR) << "Failed to unmount with MNT_DETACH " << path;
+        if (path == fuse_path) {
+            result = -errno;
+        }
+    }
+    return result;
+}
+
 status_t PrepareAndroidDirs(const std::string& volumeRoot) {
     std::string androidDir = volumeRoot + kAndroidDir;
     std::string androidDataDir = volumeRoot + kAppDataDir;
diff --git a/Utils.h b/Utils.h
index 0eca9020..8296ef85 100644
--- a/Utils.h
+++ b/Utils.h
@@ -205,6 +205,10 @@ status_t MountUserFuse(userid_t user_id, const std::string& absolute_lower_path,
 
 status_t UnmountUserFuse(userid_t userId, const std::string& absolute_lower_path,
                          const std::string& relative_upper_path);
+status_t UnmountUserFuseEnhanced(userid_t userId, const std::string& absolute_lower_path,
+                                 const std::string& relative_upper_path,
+                                 const std::string& absolute_upper_path,
+                                 const std::vector<std::string>& bind_mount_paths = {});
 
 status_t PrepareAndroidDirs(const std::string& volumeRoot);
 
diff --git a/VendorVoldNativeService.cpp b/VendorVoldNativeService.cpp
new file mode 100644
index 00000000..6d13a140
--- /dev/null
+++ b/VendorVoldNativeService.cpp
@@ -0,0 +1,67 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "VendorVoldNativeService.h"
+
+#include <mutex>
+
+#include <android-base/logging.h>
+#include <binder/IServiceManager.h>
+#include <private/android_filesystem_config.h>
+#include <utils/Trace.h>
+
+#include "Checkpoint.h"
+#include "VoldNativeServiceValidation.h"
+#include "VolumeManager.h"
+
+#define ENFORCE_SYSTEM_OR_ROOT                              \
+    {                                                       \
+        binder::Status status = CheckUidOrRoot(AID_SYSTEM); \
+        if (!status.isOk()) {                               \
+            return status;                                  \
+        }                                                   \
+    }
+
+#define ACQUIRE_LOCK                                                        \
+    std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock()); \
+    ATRACE_CALL();
+
+namespace android::vold {
+
+status_t VendorVoldNativeService::try_start() {
+    auto service_name = String16("android.system.vold.IVold/default");
+    if (!defaultServiceManager()->isDeclared(service_name)) {
+        LOG(DEBUG) << "Service for VendorVoldNativeService (" << service_name << ") not declared.";
+        return OK;
+    }
+    return defaultServiceManager()->addService(std::move(service_name),
+                                               new VendorVoldNativeService());
+}
+
+binder::Status VendorVoldNativeService::registerCheckpointListener(
+        const sp<android::system::vold::IVoldCheckpointListener>& listener,
+        android::system::vold::CheckpointingState* _aidl_return) {
+    ENFORCE_SYSTEM_OR_ROOT;
+    ACQUIRE_LOCK;
+
+    bool possible_checkpointing = cp_registerCheckpointListener(listener);
+    *_aidl_return = possible_checkpointing
+                            ? android::system::vold::CheckpointingState::POSSIBLE_CHECKPOINTING
+                            : android::system::vold::CheckpointingState::CHECKPOINTING_COMPLETE;
+    return binder::Status::ok();
+}
+
+}  // namespace android::vold
diff --git a/VendorVoldNativeService.h b/VendorVoldNativeService.h
new file mode 100644
index 00000000..884ccb0e
--- /dev/null
+++ b/VendorVoldNativeService.h
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef _VENDOR_VOLD_NATIVE_SERVICE_H_
+#define _VENDOR_VOLD_NATIVE_SERVICE_H_
+
+#include <android/system/vold/BnVold.h>
+#include <android/system/vold/CheckpointingState.h>
+#include <android/system/vold/IVoldCheckpointListener.h>
+
+namespace android::vold {
+
+class VendorVoldNativeService : public android::system::vold::BnVold {
+  public:
+    /** Start the service, but if it's not declared, give up and return OK. */
+    static status_t try_start();
+
+    binder::Status registerCheckpointListener(
+            const sp<android::system::vold::IVoldCheckpointListener>& listener,
+            android::system::vold::CheckpointingState* _aidl_return) final;
+};
+
+}  // namespace android::vold
+
+#endif  // _VENDOR_VOLD_NATIVE_SERVICE_H_
\ No newline at end of file
diff --git a/VoldNativeService.cpp b/VoldNativeService.cpp
index 3784487f..aa9d842d 100644
--- a/VoldNativeService.cpp
+++ b/VoldNativeService.cpp
@@ -40,6 +40,7 @@
 #include "VoldNativeServiceValidation.h"
 #include "VoldUtil.h"
 #include "VolumeManager.h"
+#include "WriteBooster.h"
 #include "cryptfs.h"
 #include "incfs.h"
 
@@ -512,6 +513,45 @@ binder::Status VoldNativeService::getStorageRemainingLifetime(int32_t* _aidl_ret
     return Ok();
 }
 
+binder::Status VoldNativeService::getWriteBoosterBufferSize(int32_t* _aidl_return) {
+    ENFORCE_SYSTEM_OR_ROOT;
+
+    *_aidl_return = GetWriteBoosterBufferSize();
+    return Ok();
+}
+
+binder::Status VoldNativeService::getWriteBoosterBufferAvailablePercent(int32_t* _aidl_return) {
+    ENFORCE_SYSTEM_OR_ROOT;
+    ACQUIRE_LOCK;
+
+    *_aidl_return = GetWriteBoosterBufferAvailablePercent();
+    return Ok();
+}
+
+binder::Status VoldNativeService::setWriteBoosterBufferFlush(bool enable, bool* _aidl_return) {
+    ENFORCE_SYSTEM_OR_ROOT;
+    ACQUIRE_LOCK;
+
+    *_aidl_return = SetWriteBoosterBufferFlush(enable);
+    return Ok();
+}
+
+binder::Status VoldNativeService::setWriteBoosterBufferOn(bool enable, bool* _aidl_return) {
+    ENFORCE_SYSTEM_OR_ROOT;
+    ACQUIRE_LOCK;
+
+    *_aidl_return = SetWriteBoosterBufferOn(enable);
+    return Ok();
+}
+
+binder::Status VoldNativeService::getWriteBoosterLifeTimeEstimate(int32_t* _aidl_return) {
+    ENFORCE_SYSTEM_OR_ROOT;
+    ACQUIRE_LOCK;
+
+    *_aidl_return = GetWriteBoosterLifeTimeEstimate();
+    return Ok();
+}
+
 binder::Status VoldNativeService::setGCUrgentPace(int32_t neededSegments,
                                                   int32_t minSegmentThreshold,
                                                   float dirtyReclaimRate, float reclaimWeight,
diff --git a/VoldNativeService.h b/VoldNativeService.h
index a5253c0c..2d0613c0 100644
--- a/VoldNativeService.h
+++ b/VoldNativeService.h
@@ -165,6 +165,12 @@ class VoldNativeService : public BinderService<VoldNativeService>, public os::Bn
     binder::Status destroyDsuMetadataKey(const std::string& dsuSlot) override;
 
     binder::Status getStorageSize(int64_t* storageSize) override;
+
+    binder::Status getWriteBoosterBufferSize(int32_t* _aidl_return);
+    binder::Status getWriteBoosterBufferAvailablePercent(int32_t* _aidl_return);
+    binder::Status setWriteBoosterBufferFlush(bool enable, bool* _aidl_return);
+    binder::Status setWriteBoosterBufferOn(bool enable, bool* _aidl_return);
+    binder::Status getWriteBoosterLifeTimeEstimate(int32_t* _aidl_return);
 };
 
 }  // namespace vold
diff --git a/VoldUtil.cpp b/VoldUtil.cpp
index 082f7434..c87b41d7 100644
--- a/VoldUtil.cpp
+++ b/VoldUtil.cpp
@@ -15,5 +15,73 @@
  */
 
 #include "VoldUtil.h"
+#include "Utils.h"
+
+#include <libdm/dm.h>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+
+using android::base::Basename;
+using android::base::Realpath;
+using namespace android::dm;
 
 android::fs_mgr::Fstab fstab_default;
+
+static std::string GetUfsHostControllerSysfsPathOnce() {
+    android::fs_mgr::FstabEntry* entry =
+            android::fs_mgr::GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT);
+    if (entry == nullptr) {
+        LOG(ERROR) << "No mount point entry for " << DATA_MNT_POINT;
+        return "";
+    }
+
+    // Handle symlinks.
+    std::string real_path;
+    if (!Realpath(entry->blk_device, &real_path)) {
+        real_path = entry->blk_device;
+    }
+
+    // Handle logical volumes.
+    android::dm::DeviceMapper& dm = android::dm::DeviceMapper::Instance();
+    for (;;) {
+        std::optional<std::string> parent = dm.GetParentBlockDeviceByPath(real_path);
+        if (!parent.has_value()) break;
+        real_path = *parent;
+    }
+
+    std::string path = "/sys/class/block/" + Basename(real_path);
+
+    // Walk up the sysfs directory tree from the partition (e.g, /sys/class/block/sda34)
+    // or from the disk (e.g., /sys/class/block/sda) to reach the UFS host controller's directory
+    // (e.g., /sys/class/block/sda34/../device/../../.. --> /sys/devices/platform/00000000.ufs).
+    if (android::vold::pathExists(path + "/../device")) {
+        path += "/../device/../../..";
+    } else if (android::vold::pathExists(path + "/device")) {
+        path += "/device/../../..";
+    } else {
+        LOG(WARNING) << "Failed to get sysfs_path for user data partition";
+        return "";
+    }
+
+    // Verify the block device is UFS by checking for the presence of "uic_link_state",
+    // which is UFS interconnect layer link state.
+    // If not UFS, return an empty path.
+    if (!android::vold::pathExists(path + "/uic_link_state")) {
+        LOG(ERROR) << "The block device (" << Basename(real_path) << ") of " << DATA_MNT_POINT
+                   << " is not UFS.";
+        return "";
+    }
+
+    LOG(DEBUG) << "The sysfs directory for the ufs host controller is found at " << path;
+    return path;
+}
+
+// get sysfs directory for the ufs host controller containing userdata
+// returns an empty string on failures.
+std::string GetUfsHostControllerSysfsPath() {
+    static std::string ufshc_sysfs_path = GetUfsHostControllerSysfsPathOnce();
+    return ufshc_sysfs_path;
+}
diff --git a/VoldUtil.h b/VoldUtil.h
index ce6b411f..9fb9e966 100644
--- a/VoldUtil.h
+++ b/VoldUtil.h
@@ -21,3 +21,5 @@
 extern android::fs_mgr::Fstab fstab_default;
 
 #define DATA_MNT_POINT "/data"
+
+std::string GetUfsHostControllerSysfsPath();
diff --git a/VolumeManager.cpp b/VolumeManager.cpp
index d932ec88..49a8b2b8 100644
--- a/VolumeManager.cpp
+++ b/VolumeManager.cpp
@@ -452,36 +452,41 @@ int VolumeManager::onUserStarted(userid_t userId) {
 
     if (mStartedUsers.find(userId) == mStartedUsers.end()) {
         createEmulatedVolumesForUser(userId);
-        std::list<std::string> public_vols;
-        listVolumes(VolumeBase::Type::kPublic, public_vols);
-        for (const std::string& id : public_vols) {
-            PublicVolume* pvol = static_cast<PublicVolume*>(findVolume(id).get());
-            if (pvol->getState() != VolumeBase::State::kMounted) {
-                continue;
-            }
-            if (pvol->isVisible() == 0) {
-                continue;
-            }
-            userid_t mountUserId = pvol->getMountUserId();
-            if (userId == mountUserId) {
-                // No need to bind mount for the user that owns the mount
-                continue;
-            }
-            if (mountUserId != VolumeManager::Instance()->getSharedStorageUser(userId)) {
-                // No need to bind if the user does not share storage with the mount owner
-                continue;
-            }
-            // Create mount directory for the user as there is a chance that no other Volume is
-            // mounted for the user (ex: if the user is just started), so /mnt/user/user_id  does
-            // not exist yet.
-            auto mountDirStatus = android::vold::PrepareMountDirForUser(userId);
-            if (mountDirStatus != OK) {
-                LOG(ERROR) << "Failed to create Mount Directory for user " << userId;
-            }
-            auto bindMountStatus = pvol->bindMountForUser(userId);
-            if (bindMountStatus != OK) {
-                LOG(ERROR) << "Bind Mounting Public Volume: " << pvol << " for user: " << userId
-                           << "Failed. Error: " << bindMountStatus;
+
+        userid_t sharedStorageUserId = VolumeManager::Instance()->getSharedStorageUser(userId);
+        if (sharedStorageUserId != USER_UNKNOWN) {
+            std::list<std::string> public_vols;
+            listVolumes(VolumeBase::Type::kPublic, public_vols);
+            for (const std::string& id : public_vols) {
+                PublicVolume *pvol = static_cast<PublicVolume *>(findVolume(id).get());
+                if (pvol->getState() != VolumeBase::State::kMounted) {
+                    continue;
+                }
+                if (pvol->isVisible() == 0) {
+                    continue;
+                }
+                userid_t mountUserId = pvol->getMountUserId();
+                if (userId == mountUserId) {
+                    // No need to bind mount for the user that owns the mount
+                    continue;
+                }
+
+                if (mountUserId != sharedStorageUserId) {
+                    // No need to bind if the user does not share storage with the mount owner
+                    continue;
+                }
+                // Create mount directory for the user as there is a chance that no other Volume is
+                // mounted for the user (ex: if the user is just started),
+                // so /mnt/user/user_id  does not exist yet.
+                auto mountDirStatus = android::vold::PrepareMountDirForUser(userId);
+                if (mountDirStatus != OK) {
+                    LOG(ERROR) << "Failed to create Mount Directory for user " << userId;
+                }
+                auto bindMountStatus = pvol->bindMountForUser(userId);
+                if (bindMountStatus != OK) {
+                    LOG(ERROR) << "Bind Mounting Public Volume: " << pvol << " for user: " << userId
+                               << "Failed. Error: " << bindMountStatus;
+                }
             }
         }
     }
@@ -497,6 +502,36 @@ int VolumeManager::onUserStopped(userid_t userId) {
 
     if (mStartedUsers.find(userId) != mStartedUsers.end()) {
         destroyEmulatedVolumesForUser(userId);
+
+        userid_t sharedStorageUserId = VolumeManager::Instance()->getSharedStorageUser(userId);
+        if (sharedStorageUserId != USER_UNKNOWN) {
+            std::list<std::string> public_vols;
+            listVolumes(VolumeBase::Type::kPublic, public_vols);
+            for (const std::string &id: public_vols) {
+                PublicVolume *pvol = static_cast<PublicVolume *>(findVolume(id).get());
+                if (pvol->getState() != VolumeBase::State::kMounted) {
+                    continue;
+                }
+                if (pvol->isVisible() == 0) {
+                    continue;
+                }
+                userid_t mountUserId = pvol->getMountUserId();
+                if (userId == mountUserId) {
+                    // No need to remove bind mount for the user that owns the mount
+                    continue;
+                }
+                if (mountUserId != sharedStorageUserId) {
+                    // No need to remove bind mount
+                    // if the user does not share storage with the mount owner
+                    continue;
+                }
+                LOG(INFO) << "Removing Public Volume Bind Mount for: " << userId;
+                auto mountPath = GetFuseMountPathForUser(userId, pvol->getStableName());
+                android::vold::ForceUnmount(mountPath);
+                rmdir(mountPath.c_str());
+            }
+        }
+
     }
 
     mStartedUsers.erase(userId);
@@ -1247,7 +1282,8 @@ int VolumeManager::openAppFuseFile(uid_t uid, int mountId, int fileId, int flags
     return android::vold::OpenAppFuseFile(uid, mountId, fileId, flags);
 }
 
-static android::status_t getDeviceSize(std::string& device, int64_t* storageSize) {
+static android::status_t getDeviceSize(std::string& device, int64_t* storageSize,
+                                       bool isF2fsPrimary) {
     // Follow any symbolic links
     std::string dataDevice;
     if (!android::base::Realpath(device, &dataDevice)) {
@@ -1256,14 +1292,35 @@ static android::status_t getDeviceSize(std::string& device, int64_t* storageSize
 
     // Handle mapped volumes.
     auto& dm = android::dm::DeviceMapper::Instance();
-    for (;;) {
-        auto parent = dm.GetParentBlockDeviceByPath(dataDevice);
-        if (!parent.has_value()) break;
-        dataDevice = *parent;
+    std::string dmPath = dataDevice;
+    if (dm.IsDmBlockDevice(dataDevice)) {
+        for (;;) {
+            auto parent = dm.GetParentBlockDeviceByPath(dataDevice);
+            if (!parent.has_value()) break;
+            dataDevice = *parent;
+        }
+    } else if (isF2fsPrimary) {
+        if (!dm.GetDmDevicePathByName(android::base::Basename(device), &dmPath)) {
+            LOG(WARNING) << "No proper dm device for " << device;
+            isF2fsPrimary = false;
+        }
+    }
+
+    // Find a device name for F2FS primary partition
+    std::string f2fsReservedBlocksSysfs;
+    std::size_t leaf;
+    if (isF2fsPrimary) {
+        leaf = dmPath.rfind('/');
+        if (leaf == std::string::npos) {
+            LOG(WARNING) << "dm device " << dmPath << " is not a path";
+            isF2fsPrimary = false;
+        }
+        f2fsReservedBlocksSysfs =
+                std::string() + "/sys/fs/f2fs/" + dmPath.substr(leaf + 1) + "/reserved_blocks";
     }
 
     // Get the potential /sys/block entry
-    std::size_t leaf = dataDevice.rfind('/');
+    leaf = dataDevice.rfind('/');
     if (leaf == std::string::npos) {
         LOG(ERROR) << "data device " << dataDevice << " is not a path";
         return EINVAL;
@@ -1293,14 +1350,32 @@ static android::status_t getDeviceSize(std::string& device, int64_t* storageSize
     }
 
     // Read the size file and be done
+    int64_t sizeNum;
     std::stringstream ssSize(size);
-    ssSize >> *storageSize;
+    ssSize >> sizeNum;
     if (ssSize.fail()) {
         LOG(ERROR) << sizeFile << " cannot be read as an integer";
         return EINVAL;
     }
 
-    *storageSize *= 512;
+    sizeNum *= 512;
+    if (isF2fsPrimary) {
+        int64_t reservedBlocksNum = 0;
+        if (!android::base::ReadFileToString(f2fsReservedBlocksSysfs, &size, true)) {
+            LOG(WARNING) << "Could not find valid entry from " << f2fsReservedBlocksSysfs;
+        } else {
+            std::stringstream reservedBlocks(size);
+            reservedBlocks >> reservedBlocksNum;
+            if (reservedBlocks.fail()) {
+                LOG(WARNING) << f2fsReservedBlocksSysfs << " cannot be read as an integer";
+                reservedBlocksNum = 0;
+            }
+        }
+        int64_t blockSize = android::base::GetIntProperty("ro.boot.hardware.cpu.pagesize", 0);
+        sizeNum -= reservedBlocksNum * blockSize;
+    }
+
+    *storageSize = sizeNum;
     return OK;
 }
 
@@ -1313,14 +1388,14 @@ android::status_t android::vold::GetStorageSize(int64_t* storageSize) {
         return EINVAL;
     }
 
-    status = getDeviceSize(entry->blk_device, storageSize);
+    status = getDeviceSize(entry->blk_device, storageSize, entry->fs_type == "f2fs");
     if (status != OK) {
         return status;
     }
 
     for (auto device : entry->user_devices) {
         int64_t deviceStorageSize;
-        status = getDeviceSize(device, &deviceStorageSize);
+        status = getDeviceSize(device, &deviceStorageSize, false);
         if (status != OK) {
             return status;
         }
diff --git a/WriteBooster.cpp b/WriteBooster.cpp
new file mode 100644
index 00000000..1d5c1bc1
--- /dev/null
+++ b/WriteBooster.cpp
@@ -0,0 +1,214 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "WriteBooster.h"
+#include "Utils.h"
+#include "VoldUtil.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/parseint.h>
+#include <android-base/result.h>
+#include <android-base/strings.h>
+
+using android::base::ReadFileToString;
+using android::base::WriteStringToFile;
+
+namespace android {
+namespace vold {
+
+template <typename T>
+static android::base::Result<T> readHexValue(const std::string_view path) {
+    std::string sysfs_path = GetUfsHostControllerSysfsPath();
+    if (sysfs_path.empty()) {
+        return android::base::Error();
+    }
+
+    std::string fullpath = sysfs_path + "/" + std::string(path);
+    std::string s;
+
+    if (!ReadFileToString(fullpath, &s)) {
+        PLOG(WARNING) << "Reading failed for " << fullpath;
+        return android::base::Error();
+    }
+
+    s = android::base::Trim(s);
+    T out;
+    if (!android::base::ParseUint(s, &out)) {
+        PLOG(WARNING) << "Parsing of " << fullpath << " failed. Content: " << s;
+        return android::base::Error();
+    }
+
+    return out;
+}
+
+int32_t GetWriteBoosterBufferSize() {
+    /* wb_cur_buf: in unit of allocation_unit_size (field width is 4 bytes)
+     * allocation_unit_size: in unit of segments (field width is 1 bytes)
+     * segment_size: in unit of 512 bytes (field width is 4 bytes)
+     * raw_device_capacity: in unit of 512 bytes (field width is 8 bytes)
+     */
+    auto allocation_unit_size = readHexValue<uint8_t>("geometry_descriptor/allocation_unit_size");
+    if (!allocation_unit_size.ok()) {
+        return -1;
+    }
+
+    auto segment_size = readHexValue<uint32_t>("geometry_descriptor/segment_size");
+    if (!segment_size.ok()) {
+        return -1;
+    }
+
+    auto wb_cur_buf = readHexValue<uint32_t>("attributes/wb_cur_buf");
+    if (!wb_cur_buf.ok()) {
+        return -1;
+    }
+
+    auto raw_device_capacity = readHexValue<uint64_t>("geometry_descriptor/raw_device_capacity");
+    if (!raw_device_capacity.ok()) {
+        return -1;
+    }
+
+    if (allocation_unit_size.value() == 0) {
+        LOG(DEBUG) << "Zero allocation_unit_size is invalid.";
+        return -1;
+    }
+
+    if (segment_size.value() == 0) {
+        LOG(DEBUG) << "Zero segment_size is invalid.";
+        return -1;
+    }
+
+    uint64_t wb_cur_buf_allocation_units =
+            static_cast<uint64_t>(wb_cur_buf.value()) * segment_size.value();
+
+    if (wb_cur_buf_allocation_units >
+        (raw_device_capacity.value() / allocation_unit_size.value())) {
+        LOG(DEBUG) << "invalid wb_cur_buff > raw_device_capacity ";
+        return -1;
+    }
+
+    /* The allocation_unit_size is represented in the number of sectors.
+     * Since the sector size is 512 bytes, the allocation_unit_size in MiB can be calculated as
+     * follows: allocation_unit_size in MiB = (allocation_unit_size * 512) / 1024 / 1024 =
+     * allocation_unit_size / 2048
+     */
+    uint64_t wb_cur_buf_mib = wb_cur_buf_allocation_units * allocation_unit_size.value() / 2048ULL;
+
+    if (wb_cur_buf_mib > INT32_MAX) {
+        LOG(DEBUG) << "wb_cur_buff overflow";
+        return -1;
+    }
+
+    /* return in unit of MiB */
+    return static_cast<int32_t>(wb_cur_buf_mib);
+}
+
+/*
+ * Returns the WriteBooster buffer's remaining capacity as a percentage (0-100).
+ */
+int32_t GetWriteBoosterBufferAvailablePercent() {
+    /*
+     * wb_avail_buf is in unit of 10% granularity.
+     * 00h: 0% buffer remains.
+     * 01h~09h: 10%~90% buffer remains
+     * 0Ah: 100% buffer remains
+     * Others : Reserved
+     */
+    auto out = readHexValue<uint8_t>("attributes/wb_avail_buf");
+    if (!out.ok()) {
+        return -1;
+    }
+
+    if (out.value() > 10) {
+        PLOG(WARNING) << "Invalid wb_avail_buf (" << out.value() << ")";
+        return -1;
+    }
+
+    return static_cast<int32_t>(out.value() * 10);
+}
+
+bool SetWriteBoosterBufferFlush(bool enable) {
+    std::string path = GetUfsHostControllerSysfsPath();
+    if (path.empty()) {
+        return false;
+    }
+
+    path += "/enable_wb_buf_flush";
+
+    std::string s = enable ? "1" : "0";
+
+    LOG(DEBUG) << "Toggle WriteBoosterBufferFlush to " << s;
+    if (!WriteStringToFile(s, std::string(path))) {
+        PLOG(WARNING) << "Failed to set WriteBoosterBufferFlush to " << s << " on " << path;
+        return false;
+    }
+    return true;
+}
+
+bool SetWriteBoosterBufferOn(bool enable) {
+    std::string path = GetUfsHostControllerSysfsPath();
+    if (path.empty()) {
+        return false;
+    }
+
+    path += "/wb_on";
+
+    std::string s = enable ? "1" : "0";
+
+    LOG(DEBUG) << "Toggle WriteBoosterBufferOn to " << s;
+    if (!WriteStringToFile(s, std::string(path))) {
+        PLOG(WARNING) << "Failed to set WriteBoosterBufferOn to " << s << " on " << path;
+        return false;
+    }
+    return true;
+}
+
+/**
+ * Returns WriteBooster buffer lifetime as a percentage (0-100).
+ *
+ */
+int32_t GetWriteBoosterLifeTimeEstimate() {
+    /*
+     * wb_life_time_est returns as follows:
+     * 00h: Information not available (WriteBooster Buffer is disabled)
+     * 01h: 0% - 10% WriteBooster Buffer life time used
+     * 02h-09h: 10% - 90% WriteBooster Buffer life time used
+     * 0Ah: 90% - 100% WriteBooster Buffer life time used
+     * 0Bh: Exceeded its maximum estimated WriteBooster Buffer life time
+     *      (write commands are processed as if WriteBooster feature was
+     *       disabled)
+     * Others: Reserved
+     */
+    auto out = readHexValue<uint8_t>("attributes/wb_life_time_est");
+    if (!out.ok()) {
+        return -1;
+    }
+
+    if (out.value() == 0) {
+        PLOG(WARNING) << "WriteBooster is disabled.";
+        return -1;
+    }
+
+    if (out.value() > 11) {
+        PLOG(WARNING) << "Invalid wb_life_time_est (" << out.value() << ")";
+        return -1;
+    }
+
+    return static_cast<int32_t>(10 * (out.value() - 1));
+}
+
+}  // namespace vold
+}  // namespace android
diff --git a/WriteBooster.h b/WriteBooster.h
new file mode 100644
index 00000000..6aa97998
--- /dev/null
+++ b/WriteBooster.h
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef ANDROID_VOLD_WRITE_BOOSTER_H
+#define ANDROID_VOLD_WRITE_BOOSTER_H
+
+#include <cstdint>
+
+namespace android {
+namespace vold {
+
+int32_t GetWriteBoosterBufferSize();
+int32_t GetWriteBoosterBufferAvailablePercent();
+bool SetWriteBoosterBufferFlush(bool enable);
+bool SetWriteBoosterBufferOn(bool enable);
+int32_t GetWriteBoosterLifeTimeEstimate();
+
+}  // namespace vold
+}  // namespace android
+
+#endif
diff --git a/aconfig/flags.aconfig b/aconfig/flags.aconfig
new file mode 100644
index 00000000..d9c8fe2e
--- /dev/null
+++ b/aconfig/flags.aconfig
@@ -0,0 +1,10 @@
+package: "android.vold.flags"
+container: "system"
+
+flag {
+  name: "enhance_fuse_unmount"
+  namespace: "mediaprovider"
+  description: "This flag controls whether enhancements to unmounting is enabled"
+  bug: "402367661"
+  is_fixed_read_only: true
+}
diff --git a/android.system.vold-service.xml b/android.system.vold-service.xml
new file mode 100644
index 00000000..ea084b79
--- /dev/null
+++ b/android.system.vold-service.xml
@@ -0,0 +1,10 @@
+<manifest version="1.0" type="framework">
+    <hal format="aidl">
+        <name>android.system.vold</name>
+        <version>1</version>
+        <interface>
+            <name>IVold</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</manifest>
\ No newline at end of file
diff --git a/binder/android/os/IVold.aidl b/binder/android/os/IVold.aidl
index 810fdadb..15213ea9 100644
--- a/binder/android/os/IVold.aidl
+++ b/binder/android/os/IVold.aidl
@@ -143,6 +143,12 @@ interface IVold {
     // on failure.
     int getStorageRemainingLifetime();
 
+    int getWriteBoosterBufferSize();
+    int getWriteBoosterBufferAvailablePercent();
+    boolean setWriteBoosterBufferFlush(boolean enable);
+    boolean setWriteBoosterBufferOn(boolean enable);
+    int getWriteBoosterLifeTimeEstimate();
+
     const int FSTRIM_FLAG_DEEP_TRIM = 1;
 
     const int MOUNT_FLAG_PRIMARY = 1;
diff --git a/main.cpp b/main.cpp
index 078ee14b..bdce76ed 100644
--- a/main.cpp
+++ b/main.cpp
@@ -19,6 +19,7 @@
 #include "FsCrypt.h"
 #include "MetadataCrypt.h"
 #include "NetlinkManager.h"
+#include "VendorVoldNativeService.h"
 #include "VoldNativeService.h"
 #include "VoldUtil.h"
 #include "VolumeManager.h"
@@ -126,9 +127,16 @@ int main(int argc, char** argv) {
         exit(1);
     }
     ATRACE_END();
-
     LOG(DEBUG) << "VoldNativeService::start() completed OK";
 
+    ATRACE_BEGIN("VendorVoldNativeService::try_start");
+    if (android::vold::VendorVoldNativeService::try_start() != android::OK) {
+        LOG(ERROR) << "Unable to start VendorVoldNativeService";
+        exit(1);
+    }
+    ATRACE_END();
+    LOG(DEBUG) << "VendorVoldNativeService::try_start() completed OK";
+
     ATRACE_BEGIN("NetlinkManager::start");
     if (nm->start()) {
         PLOG(ERROR) << "Unable to start NetlinkManager";
diff --git a/model/EmulatedVolume.cpp b/model/EmulatedVolume.cpp
index 270dcd48..2df35cb3 100644
--- a/model/EmulatedVolume.cpp
+++ b/model/EmulatedVolume.cpp
@@ -36,8 +36,11 @@
 #include <sys/sysmacros.h>
 #include <sys/types.h>
 #include <sys/wait.h>
+#include <android_vold_flags.h>
 
 using android::base::StringPrintf;
+namespace flags = android::vold::flags;
+
 
 namespace android {
 namespace vold {
@@ -113,6 +116,32 @@ status_t EmulatedVolume::bindMountVolume(const EmulatedVolume& volume,
     return status;
 }
 
+std::shared_ptr<android::vold::VolumeBase> getSharedStorageVolume(int userId) {
+    userid_t sharedStorageUserId = VolumeManager::Instance()->getSharedStorageUser(userId);
+    if (sharedStorageUserId != USER_UNKNOWN) {
+        auto filter_fn = [&](const VolumeBase &vol) {
+            if (vol.getState() != VolumeBase::State::kMounted) {
+                // The volume must be mounted
+                return false;
+            }
+            if (vol.getType() != VolumeBase::Type::kEmulated) {
+                return false;
+            }
+            if (vol.getMountUserId() != sharedStorageUserId) {
+                return false;
+            }
+            if ((vol.getMountFlags() & EmulatedVolume::MountFlags::kPrimary) == 0) {
+                // We only care about the primary emulated volume, so not a private
+                // volume with an emulated volume stacked on top.
+                return false;
+            }
+            return true;
+        };
+        return VolumeManager::Instance()->findVolumeWithFilter(filter_fn);
+    }
+    return nullptr;
+}
+
 status_t EmulatedVolume::mountFuseBindMounts() {
     std::string androidSource;
     std::string label = getLabel();
@@ -192,49 +221,26 @@ status_t EmulatedVolume::mountFuseBindMounts() {
     //
     // This will ensure that any access to the volume for a specific user always
     // goes through a single FUSE daemon.
-    userid_t sharedStorageUserId = VolumeManager::Instance()->getSharedStorageUser(userId);
-    if (sharedStorageUserId != USER_UNKNOWN) {
-        auto filter_fn = [&](const VolumeBase& vol) {
-            if (vol.getState() != VolumeBase::State::kMounted) {
-                // The volume must be mounted
-                return false;
-            }
-            if (vol.getType() != VolumeBase::Type::kEmulated) {
-                return false;
-            }
-            if (vol.getMountUserId() != sharedStorageUserId) {
-                return false;
-            }
-            if ((vol.getMountFlags() & MountFlags::kPrimary) == 0) {
-                // We only care about the primary emulated volume, so not a private
-                // volume with an emulated volume stacked on top.
-                return false;
-            }
-            return true;
-        };
-        auto vol = VolumeManager::Instance()->findVolumeWithFilter(filter_fn);
-        if (vol != nullptr) {
-            auto sharedVol = static_cast<EmulatedVolume*>(vol.get());
-            // Bind mount this volume in the other user's primary volume
-            status = sharedVol->bindMountVolume(*this, pathsToUnmount);
-            if (status != OK) {
-                return status;
-            }
-            // And vice-versa
-            status = bindMountVolume(*sharedVol, pathsToUnmount);
-            if (status != OK) {
-                return status;
-            }
+    auto vol = getSharedStorageVolume(userId);
+    if (vol != nullptr) {
+        auto sharedVol = static_cast<EmulatedVolume*>(vol.get());
+        // Bind mount this volume in the other user's primary volume
+        status = sharedVol->bindMountVolume(*this, pathsToUnmount);
+        if (status != OK) {
+            return status;
+        }
+        // And vice-versa
+        status = bindMountVolume(*sharedVol, pathsToUnmount);
+        if (status != OK) {
+            return status;
         }
     }
+
     unmount_guard.Disable();
     return OK;
 }
 
-status_t EmulatedVolume::unmountFuseBindMounts() {
-    std::string label = getLabel();
-    int userId = getMountUserId();
-
+status_t EmulatedVolume::unbindSharedStorageMountPath() {
     if (!mSharedStorageMountPath.empty()) {
         LOG(INFO) << "Unmounting " << mSharedStorageMountPath;
         auto status = UnmountTree(mSharedStorageMountPath);
@@ -242,7 +248,25 @@ status_t EmulatedVolume::unmountFuseBindMounts() {
             LOG(ERROR) << "Failed to unmount " << mSharedStorageMountPath;
         }
         mSharedStorageMountPath = "";
+        return status;
     }
+    return OK;
+}
+
+
+status_t EmulatedVolume::unmountFuseBindMounts() {
+    std::string label = getLabel();
+    int userId = getMountUserId();
+
+    if (!mSharedStorageMountPath.empty()) {
+        unbindSharedStorageMountPath();
+        auto vol = getSharedStorageVolume(userId);
+        if (vol != nullptr) {
+            auto sharedVol = static_cast<EmulatedVolume*>(vol.get());
+            sharedVol->unbindSharedStorageMountPath();
+        }
+    }
+
     if (mUseSdcardFs || mAppDataIsolationEnabled) {
         std::string installerTarget(
                 StringPrintf("/mnt/installer/%d/%s/%d/Android/obb", userId, label.c_str(), userId));
@@ -428,9 +452,17 @@ status_t EmulatedVolume::doMount() {
         auto fuse_unmounter = [&]() {
             LOG(INFO) << "fuse_unmounter scope_guard running";
             fd.reset();
-            if (UnmountUserFuse(user_id, getInternalPath(), label) != OK) {
-                PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
+            if (flags::enhance_fuse_unmount()) {
+                std::string user_path(StringPrintf("%s/%d", getPath().c_str(), getMountUserId()));
+                if (UnmountUserFuseEnhanced(user_id, getInternalPath(), label, user_path) != OK) {
+                    PLOG(INFO) << "UnmountUserFuseEnhanced failed on emulated fuse volume";
+                }
+            } else {
+                if (UnmountUserFuse(user_id, getInternalPath(), label) != OK) {
+                    PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
+                }
             }
+
             mFuseMounted = false;
         };
         auto fuse_guard = android::base::make_scope_guard(fuse_unmounter);
@@ -486,21 +518,22 @@ status_t EmulatedVolume::doMount() {
 status_t EmulatedVolume::doUnmount() {
     int userId = getMountUserId();
 
-    // Kill all processes using the filesystem before we unmount it. If we
-    // unmount the filesystem first, most file system operations will return
-    // ENOTCONN until the unmount completes. This is an exotic and unusual
-    // error code and might cause broken behaviour in applications.
     if (mFuseMounted) {
-        // For FUSE specifically, we have an emulated volume per user, so only kill
-        // processes using files from this particular user.
         std::string user_path(StringPrintf("%s/%d", getPath().c_str(), getMountUserId()));
-        LOG(INFO) << "Killing all processes referencing " << user_path;
-        KillProcessesUsingPath(user_path);
-    } else {
-        KillProcessesUsingPath(getPath());
-    }
 
-    if (mFuseMounted) {
+        // We don't kill processes before trying to unmount in case enhance_fuse_unmount enabled
+        // As we make sure to kill processes if needed if unmounting failed
+        if (!flags::enhance_fuse_unmount()) {
+            // Kill all processes using the filesystem before we unmount it. If we
+            // unmount the filesystem first, most file system operations will return
+            // ENOTCONN until the unmount completes. This is an exotic and unusual
+            // error code and might cause broken behaviour in applications.
+            // For FUSE specifically, we have an emulated volume per user, so only kill
+            // processes using files from this particular user.
+            LOG(INFO) << "Killing all processes referencing " << user_path;
+            KillProcessesUsingPath(user_path);
+        }
+
         std::string label = getLabel();
 
         if (!IsFuseBpfEnabled()) {
@@ -509,12 +542,24 @@ status_t EmulatedVolume::doUnmount() {
             unmountFuseBindMounts();
         }
 
-        if (UnmountUserFuse(userId, getInternalPath(), label) != OK) {
-            PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
-            return -errno;
+        if (flags::enhance_fuse_unmount()) {
+            status_t result = UnmountUserFuseEnhanced(userId, getInternalPath(), label, user_path);
+            if (result != OK) {
+                PLOG(INFO) << "UnmountUserFuseEnhanced failed on emulated fuse volume";
+                return result;
+            }
+        } else {
+            if (UnmountUserFuse(userId, getInternalPath(), label) != OK) {
+                PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
+                return -errno;
+            }
         }
 
         mFuseMounted = false;
+    } else {
+        // This branch is needed to help with unmounting private volumes that aren't set to primary
+        // and don't have fuse mounted but have stacked emulated volumes
+        KillProcessesUsingPath(getPath());
     }
 
     return unmountSdcardFs();
diff --git a/model/EmulatedVolume.h b/model/EmulatedVolume.h
index 0389ea7f..322dd385 100644
--- a/model/EmulatedVolume.h
+++ b/model/EmulatedVolume.h
@@ -51,6 +51,7 @@ class EmulatedVolume : public VolumeBase {
     status_t unmountSdcardFs();
     status_t mountFuseBindMounts();
     status_t unmountFuseBindMounts();
+    status_t unbindSharedStorageMountPath();
 
     status_t bindMountVolume(const EmulatedVolume& vol, std::list<std::string>& pathsToUnmount);
 
diff --git a/model/PublicVolume.cpp b/model/PublicVolume.cpp
index 91b1ca23..5a30fca8 100644
--- a/model/PublicVolume.cpp
+++ b/model/PublicVolume.cpp
@@ -36,9 +36,11 @@
 #include <sys/sysmacros.h>
 #include <sys/types.h>
 #include <sys/wait.h>
+#include <android_vold_flags.h>
 
 using android::base::GetBoolProperty;
 using android::base::StringPrintf;
+namespace flags = android::vold::flags;
 
 namespace android {
 namespace vold {
@@ -88,6 +90,15 @@ status_t PublicVolume::initAsecStage() {
     return OK;
 }
 
+std::string PublicVolume::getStableName() {
+    // Use UUID as stable name, if available
+    std::string stableName = getId();
+    if (!mFsUuid.empty()) {
+        stableName = mFsUuid;
+    }
+    return stableName;
+}
+
 status_t PublicVolume::doCreate() {
     return CreateDeviceNode(mDevPath, mDevice);
 }
@@ -115,11 +126,7 @@ status_t PublicVolume::doMount() {
         return -EIO;
     }
 
-    // Use UUID as stable name, if available
-    std::string stableName = getId();
-    if (!mFsUuid.empty()) {
-        stableName = mFsUuid;
-    }
+    std::string stableName = getStableName();
 
     mRawPath = StringPrintf("/mnt/media_rw/%s", stableName.c_str());
 
@@ -286,10 +293,7 @@ status_t PublicVolume::doMount() {
 
 status_t PublicVolume::bindMountForUser(userid_t user_id) {
     userid_t mountUserId = getMountUserId();
-    std::string stableName = getId();
-    if (!mFsUuid.empty()) {
-        stableName = mFsUuid;
-    }
+    std::string stableName = getStableName();
 
     LOG(INFO) << "Bind Mounting Public Volume for user: " << user_id
               << ".Mount owner: " << mountUserId;
@@ -307,34 +311,57 @@ status_t PublicVolume::doUnmount() {
     // the FUSE process first, most file system operations will return
     // ENOTCONN until the unmount completes. This is an exotic and unusual
     // error code and might cause broken behaviour in applications.
-    KillProcessesUsingPath(getPath());
+
+    // We don't kill processes here if enhance_fuse_unmount as we make sure that we kill processes
+    // only if unmounting failed
+    if (!mFuseMounted || !flags::enhance_fuse_unmount()) {
+        KillProcessesUsingPath(getPath());
+    }
 
     if (mFuseMounted) {
-        // Use UUID as stable name, if available
-        std::string stableName = getId();
-        if (!mFsUuid.empty()) {
-            stableName = mFsUuid;
-        }
+        std::string stableName = getStableName();
 
         // Unmount bind mounts for running users
         auto vol_manager = VolumeManager::Instance();
-        int user_id = getMountUserId();
-        for (int started_user : vol_manager->getStartedUsers()) {
+        userid_t user_id = getMountUserId();
+        std::vector<std::string> bind_mount_paths;
+        for (userid_t started_user : vol_manager->getStartedUsers()) {
             if (started_user == user_id) {
                 // No need to remove bind mount for the user that owns the mount
                 continue;
             }
-            LOG(INFO) << "Removing Public Volume Bind Mount for: " << started_user;
+            if (user_id != VolumeManager::Instance()->getSharedStorageUser(started_user)) {
+                // No need to remove bind mount
+                // if the user does not share storage with the mount owner
+                continue;
+            }
+
             auto mountPath = GetFuseMountPathForUser(started_user, stableName);
-            ForceUnmount(mountPath);
-            rmdir(mountPath.c_str());
+            if (flags::enhance_fuse_unmount()) {
+                // Add it to list so that we unmount it as part of UnmountUserFuseEnhanced
+                bind_mount_paths.push_back(mountPath);
+            } else {
+                LOG(INFO) << "Removing Public Volume Bind Mount for: " << started_user;
+                ForceUnmount(mountPath);
+                rmdir(mountPath.c_str());
+            }
         }
 
-        if (UnmountUserFuse(getMountUserId(), getInternalPath(), stableName) != OK) {
-            PLOG(INFO) << "UnmountUserFuse failed on public fuse volume";
-            return -errno;
+        if (flags::enhance_fuse_unmount()) {
+            status_t result = UnmountUserFuseEnhanced(getMountUserId(), getInternalPath(),
+                                                      stableName, getPath(), bind_mount_paths);
+            if (result != OK) {
+                PLOG(INFO) << "UnmountUserFuseEnhanced failed on public fuse volume";
+                return result;
+            }
+        } else {
+            if (UnmountUserFuse(getMountUserId(), getInternalPath(), stableName) != OK) {
+                PLOG(INFO) << "UnmountUserFuse failed on public fuse volume";
+                return -errno;
+            }
         }
 
+
         mFuseMounted = false;
     }
 
diff --git a/model/PublicVolume.h b/model/PublicVolume.h
index ca553b06..5eff35e4 100644
--- a/model/PublicVolume.h
+++ b/model/PublicVolume.h
@@ -43,6 +43,7 @@ class PublicVolume : public VolumeBase {
     virtual ~PublicVolume();
 
     status_t bindMountForUser(userid_t user_id);
+    std::string getStableName();
 
   protected:
     status_t doCreate() override;
diff --git a/tests/VoldFuzzer.cpp b/tests/VoldFuzzer.cpp
index 630a785e..173c7654 100644
--- a/tests/VoldFuzzer.cpp
+++ b/tests/VoldFuzzer.cpp
@@ -17,6 +17,7 @@
 #include <android-base/logging.h>
 #include <fuzzbinder/libbinder_driver.h>
 
+#include "VendorVoldNativeService.h"
 #include "VoldNativeService.h"
 #include "sehandle.h"
 
@@ -36,7 +37,10 @@ extern "C" int LLVMFuzzerInitialize(int argc, char argv) {
 }
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+    // TODO(b/183141167): need to rewrite 'dump' to avoid SIGPIPE.
+    signal(SIGPIPE, SIG_IGN);
     auto voldService = sp<android::vold::VoldNativeService>::make();
-    fuzzService(voldService, FuzzedDataProvider(data, size));
+    auto voldVendorService = sp<android::vold::VendorVoldNativeService>::make();
+    fuzzService({voldService, voldVendorService}, FuzzedDataProvider(data, size));
     return 0;
 }
\ No newline at end of file
```

