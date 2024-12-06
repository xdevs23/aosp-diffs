```diff
diff --git a/MetadataCrypt.cpp b/MetadataCrypt.cpp
index a1106fdd..8d835410 100644
--- a/MetadataCrypt.cpp
+++ b/MetadataCrypt.cpp
@@ -17,6 +17,7 @@
 #include "MetadataCrypt.h"
 #include "KeyBuffer.h"
 
+#include <fstream>
 #include <string>
 
 #include <fcntl.h>
@@ -244,13 +245,57 @@ static bool parse_options(const std::string& options_string, CryptoOptions* opti
     return true;
 }
 
+class EncryptionInProgress {
+  private:
+    std::string file_path_;
+    bool need_cleanup_ = false;
+
+  public:
+    EncryptionInProgress(const FstabEntry& entry) {
+        file_path_ = fs_mgr_metadata_encryption_in_progress_file_name(entry);
+    }
+
+    [[nodiscard]] bool Mark() {
+        {
+            std::ofstream touch(file_path_);
+            if (!touch.is_open()) {
+                PLOG(ERROR) << "Failed to mark metadata encryption in progress " << file_path_;
+                return false;
+            }
+            need_cleanup_ = true;
+        }
+        if (!android::vold::FsyncParentDirectory(file_path_)) return false;
+
+        LOG(INFO) << "Marked metadata encryption in progress (" << file_path_ << ")";
+        return true;
+    }
+
+    [[nodiscard]] bool Remove() {
+        need_cleanup_ = false;
+        if (unlink(file_path_.c_str()) != 0) {
+            PLOG(ERROR) << "Failed to clear metadata encryption in progress (" << file_path_ << ")";
+            return false;
+        }
+        if (!android::vold::FsyncParentDirectory(file_path_)) return false;
+
+        LOG(INFO) << "Cleared metadata encryption in progress (" << file_path_ << ")";
+        return true;
+    }
+
+    ~EncryptionInProgress() {
+        if (need_cleanup_) (void)Remove();
+    }
+};
+
 bool fscrypt_mount_metadata_encrypted(const std::string& blk_device, const std::string& mount_point,
                                       bool needs_encrypt, bool should_format,
                                       const std::string& fs_type, bool is_zoned,
-                                      const std::vector<std::string>& user_devices) {
+                                      const std::vector<std::string>& user_devices,
+                                      int64_t length) {
     LOG(DEBUG) << "fscrypt_mount_metadata_encrypted: " << mount_point
                << " encrypt: " << needs_encrypt << " format: " << should_format << " with "
-               << fs_type << " block device: " << blk_device << " with zoned " << is_zoned;
+               << fs_type << " block device: " << blk_device << " with zoned " << is_zoned
+               << " length: " << length;
 
     for (auto& device : user_devices) {
         LOG(DEBUG) << " - user devices: " << device;
@@ -332,13 +377,15 @@ bool fscrypt_mount_metadata_encrypted(const std::string& blk_device, const std::
     }
 
     if (needs_encrypt) {
+        EncryptionInProgress marker(*data_rec);
+        if (!marker.Mark()) return false;
         if (should_format) {
             status_t error;
 
             if (fs_type == "ext4") {
                 error = ext4::Format(crypto_blkdev, 0, mount_point);
             } else if (fs_type == "f2fs") {
-                error = f2fs::Format(crypto_blkdev, is_zoned, crypto_user_blkdev);
+                error = f2fs::Format(crypto_blkdev, is_zoned, crypto_user_blkdev, length);
             } else {
                 LOG(ERROR) << "Unknown filesystem type: " << fs_type;
                 return false;
@@ -360,6 +407,7 @@ bool fscrypt_mount_metadata_encrypted(const std::string& blk_device, const std::
                 return false;
             }
         }
+        if (!marker.Remove()) return false;
     }
 
     LOG(DEBUG) << "Mounting metadata-encrypted filesystem:" << mount_point;
diff --git a/MetadataCrypt.h b/MetadataCrypt.h
index 2c07a143..a0914433 100644
--- a/MetadataCrypt.h
+++ b/MetadataCrypt.h
@@ -29,7 +29,7 @@ void defaultkey_precreate_dm_device();
 bool fscrypt_mount_metadata_encrypted(const std::string& block_device,
                                       const std::string& mount_point, bool needs_encrypt,
                                       bool should_format, const std::string& fs_type, bool is_zoned,
-                                      const std::vector<std::string>& user_devices);
+                                      const std::vector<std::string>& user_devices, int64_t length);
 
 bool defaultkey_volume_keygen(KeyGeneration* gen);
 
diff --git a/NetlinkManager.cpp b/NetlinkManager.cpp
index 56d9df6a..ee0c2f83 100644
--- a/NetlinkManager.cpp
+++ b/NetlinkManager.cpp
@@ -46,7 +46,7 @@ NetlinkManager::~NetlinkManager() {}
 
 int NetlinkManager::start() {
     struct sockaddr_nl nladdr;
-    int sz = 64 * 1024;
+    int sz = 256 * 1024;
     int on = 1;
 
     memset(&nladdr, 0, sizeof(nladdr));
diff --git a/Utils.cpp b/Utils.cpp
index 696b0b48..c4070d13 100644
--- a/Utils.cpp
+++ b/Utils.cpp
@@ -754,6 +754,57 @@ status_t ForkExecvp(const std::vector<std::string>& args, std::vector<std::strin
     return OK;
 }
 
+status_t ForkTimeout(int (*func)(void*), void* args, std::chrono::seconds timeout) {
+    int status;
+
+    // We're waiting on either the timeout or workload process to finish, so we're
+    // initially forking to get away from any other vold children
+    pid_t wait_timeout_pid = fork();
+    if (wait_timeout_pid == 0) {
+        pid_t pid = fork();
+        if (pid == 0) {
+            _exit(func(args));
+        }
+        if (pid == -1) {
+            _exit(EXIT_FAILURE);
+        }
+        pid_t timer_pid = fork();
+        if (timer_pid == 0) {
+            std::this_thread::sleep_for(timeout);
+            _exit(ETIMEDOUT);
+        }
+        if (timer_pid == -1) {
+            PLOG(ERROR) << "fork in ForkTimeout failed";
+            kill(pid, SIGTERM);
+            _exit(EXIT_FAILURE);
+        }
+        // Preserve the exit code of the first process to finish, and end the other
+        pid_t finished = wait(&status);
+        if (finished == pid) {
+            kill(timer_pid, SIGTERM);
+        } else {
+            kill(pid, SIGTERM);
+        }
+        if (!WIFEXITED(status)) {
+            _exit(ECHILD);
+        }
+        _exit(WEXITSTATUS(status));
+    }
+    if (waitpid(wait_timeout_pid, &status, 0) == -1) {
+        PLOG(ERROR) << "waitpid in ForkTimeout failed";
+        return -errno;
+    }
+    if (!WIFEXITED(status)) {
+        LOG(ERROR) << "Process did not exit normally, status: " << status;
+        return -ECHILD;
+    }
+    if (WEXITSTATUS(status)) {
+        LOG(ERROR) << "Process exited with code: " << WEXITSTATUS(status);
+        return WEXITSTATUS(status);
+    }
+    return OK;
+}
+
 status_t ForkExecvpTimeout(const std::vector<std::string>& args, std::chrono::seconds timeout,
                            char* context) {
     int status;
@@ -1562,15 +1613,9 @@ status_t MountUserFuse(userid_t user_id, const std::string& absolute_lower_path,
         return -1;
     }
 
-    // Shell is neither AID_ROOT nor AID_EVERYBODY. Since it equally needs 'execute' access to
-    // /mnt/user/0 to 'adb shell ls /sdcard' for instance, we set the uid bit of /mnt/user/0 to
-    // AID_SHELL. This gives shell access along with apps running as group everybody (user 0 apps)
-    // These bits should be consistent with what is set in zygote in
-    // com_android_internal_os_Zygote#MountEmulatedStorage on volume bind mount during app fork
-    result = PrepareDir(pre_fuse_path, 0710, user_id ? AID_ROOT : AID_SHELL,
-                             multiuser_get_uid(user_id, AID_EVERYBODY));
+    result = PrepareMountDirForUser(user_id);
     if (result != android::OK) {
-        PLOG(ERROR) << "Failed to prepare directory " << pre_fuse_path;
+        PLOG(ERROR) << "Failed to create Mount Directory for user " << user_id;
         return -1;
     }
 
@@ -1808,5 +1853,22 @@ bool IsFuseBpfEnabled() {
     return enabled;
 }
 
+status_t PrepareMountDirForUser(userid_t user_id) {
+    std::string pre_fuse_path(StringPrintf("/mnt/user/%d", user_id));
+    LOG(INFO) << "Creating mount directory " << pre_fuse_path;
+    // Shell is neither AID_ROOT nor AID_EVERYBODY. Since it equally needs 'execute' access to
+    // /mnt/user/0 to 'adb shell ls /sdcard' for instance, we set the uid bit of /mnt/user/0 to
+    // AID_SHELL. This gives shell access along with apps running as group everybody (user 0 apps)
+    // These bits should be consistent with what is set in zygote in
+    // com_android_internal_os_Zygote#MountEmulatedStorage on volume bind mount during app fork
+    auto result = PrepareDir(pre_fuse_path, 0710, user_id ? AID_ROOT : AID_SHELL,
+                             multiuser_get_uid(user_id, AID_EVERYBODY));
+    if (result != android::OK) {
+        PLOG(ERROR) << "Failed to prepare directory " << pre_fuse_path;
+        return -1;
+    }
+    return result;
+}
+
 }  // namespace vold
 }  // namespace android
diff --git a/Utils.h b/Utils.h
index 690f79e5..0eca9020 100644
--- a/Utils.h
+++ b/Utils.h
@@ -39,6 +39,7 @@ static const char* kVoldAppDataIsolationEnabled = "persist.sys.vold_app_data_iso
 static const char* kExternalStorageSdcardfs = "external_storage.sdcardfs.enabled";
 
 static constexpr std::chrono::seconds kUntrustedFsckSleepTime(45);
+static constexpr std::chrono::seconds kUntrustedMountSleepTime(20);
 
 /* SELinux contexts used depending on the block device type */
 extern char* sBlkidContext;
@@ -107,6 +108,7 @@ status_t ReadMetadataUntrusted(const std::string& path, std::string* fsType, std
                                std::string* fsLabel);
 
 /* Returns either WEXITSTATUS() status, or a negative errno */
+status_t ForkTimeout(int (*func)(void*), void* args, std::chrono::seconds timeout);
 status_t ForkExecvp(const std::vector<std::string>& args,
                     std::vector<std::string>* output = nullptr, char* context = nullptr);
 status_t ForkExecvpTimeout(const std::vector<std::string>& args, std::chrono::seconds timeout,
@@ -219,6 +221,8 @@ bool IsFuseBpfEnabled();
 // referenced inside the current process via the virtual procfs symlink returned here.
 std::pair<android::base::unique_fd, std::string> OpenDirInProcfs(std::string_view path);
 
+status_t PrepareMountDirForUser(userid_t user_id);
+
 }  // namespace vold
 }  // namespace android
 
diff --git a/VoldNativeService.cpp b/VoldNativeService.cpp
index a70639c6..98dec667 100644
--- a/VoldNativeService.cpp
+++ b/VoldNativeService.cpp
@@ -594,18 +594,19 @@ binder::Status VoldNativeService::mountFstab(const std::string& blkDevice,
     ACQUIRE_LOCK;
 
     return translateBool(fscrypt_mount_metadata_encrypted(blkDevice, mountPoint, false, false,
-                                                          "null", isZoned, userDevices));
+                                                          "null", isZoned, userDevices, 0));
 }
 
 binder::Status VoldNativeService::encryptFstab(const std::string& blkDevice,
                                                const std::string& mountPoint, bool shouldFormat,
                                                const std::string& fsType, bool isZoned,
-                                               const std::vector<std::string>& userDevices) {
+                                               const std::vector<std::string>& userDevices,
+                                               int64_t length) {
     ENFORCE_SYSTEM_OR_ROOT;
     ACQUIRE_LOCK;
 
     return translateBool(fscrypt_mount_metadata_encrypted(blkDevice, mountPoint, true, shouldFormat,
-                                                          fsType, isZoned, userDevices));
+                                                          fsType, isZoned, userDevices, length));
 }
 
 binder::Status VoldNativeService::setStorageBindingSeed(const std::vector<uint8_t>& seed) {
diff --git a/VoldNativeService.h b/VoldNativeService.h
index 619c7202..bd37ac76 100644
--- a/VoldNativeService.h
+++ b/VoldNativeService.h
@@ -107,9 +107,10 @@ class VoldNativeService : public BinderService<VoldNativeService>, public os::Bn
     binder::Status initUser0();
     binder::Status mountFstab(const std::string& blkDevice, const std::string& mountPoint,
                               bool isZoned, const std::vector<std::string>& userDevices);
+
     binder::Status encryptFstab(const std::string& blkDevice, const std::string& mountPoint,
                                 bool shouldFormat, const std::string& fsType, bool isZoned,
-                                const std::vector<std::string>& userDevices);
+                                const std::vector<std::string>& userDevices, int64_t length);
 
     binder::Status setStorageBindingSeed(const std::vector<uint8_t>& seed);
 
diff --git a/VolumeManager.cpp b/VolumeManager.cpp
index a1ac20d4..a7c87a3a 100644
--- a/VolumeManager.cpp
+++ b/VolumeManager.cpp
@@ -101,8 +101,6 @@ static const char* kPathVirtualDisk = "/data/misc/vold/virtual_disk";
 
 static const char* kPropVirtualDisk = "persist.sys.virtual_disk";
 
-static const std::string kEmptyString("");
-
 /* 512MiB is large enough for testing purposes */
 static const unsigned int kSizeVirtualDisk = 536870912;
 
@@ -473,6 +471,13 @@ int VolumeManager::onUserStarted(userid_t userId) {
                 // No need to bind if the user does not share storage with the mount owner
                 continue;
             }
+            // Create mount directory for the user as there is a chance that no other Volume is
+            // mounted for the user (ex: if the user is just started), so /mnt/user/user_id  does
+            // not exist yet.
+            auto mountDirStatus = android::vold::PrepareMountDirForUser(userId);
+            if (mountDirStatus != OK) {
+                LOG(ERROR) << "Failed to create Mount Directory for user " << userId;
+            }
             auto bindMountStatus = pvol->bindMountForUser(userId);
             if (bindMountStatus != OK) {
                 LOG(ERROR) << "Bind Mounting Public Volume: " << pvol << " for user: " << userId
@@ -1031,7 +1036,8 @@ int VolumeManager::unmountAll() {
              !StartsWith(test, "/mnt/scratch") &&
 #endif
              !StartsWith(test, "/mnt/vendor") && !StartsWith(test, "/mnt/product") &&
-             !StartsWith(test, "/mnt/installer") && !StartsWith(test, "/mnt/androidwritable")) ||
+             !StartsWith(test, "/mnt/installer") && !StartsWith(test, "/mnt/androidwritable") &&
+             !StartsWith(test, "/mnt/vm")) ||
             StartsWith(test, "/storage/")) {
             toUnmount.push_front(test);
         }
@@ -1304,4 +1310,4 @@ android::status_t android::vold::GetStorageSize(int64_t* storageSize) {
 
     *storageSize *= 512;
     return OK;
-}
\ No newline at end of file
+}
diff --git a/binder/android/os/IVold.aidl b/binder/android/os/IVold.aidl
index 919369b6..a8cce94a 100644
--- a/binder/android/os/IVold.aidl
+++ b/binder/android/os/IVold.aidl
@@ -84,7 +84,7 @@ interface IVold {
 
     void initUser0();
     void mountFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean isZoned, in @utf8InCpp String[] userDevices);
-    void encryptFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean shouldFormat, @utf8InCpp String fsType, boolean isZoned, in @utf8InCpp String[] userDevices);
+    void encryptFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean shouldFormat, @utf8InCpp String fsType, boolean isZoned, in @utf8InCpp String[] userDevices, long length);
 
     void setStorageBindingSeed(in byte[] seed);
 
diff --git a/fs/Exfat.cpp b/fs/Exfat.cpp
index ed539216..48fa6a37 100644
--- a/fs/Exfat.cpp
+++ b/fs/Exfat.cpp
@@ -58,8 +58,8 @@ status_t Check(const std::string& source) {
     }
 }
 
-status_t Mount(const std::string& source, const std::string& target, int ownerUid, int ownerGid,
-               int permMask) {
+status_t DoMount(const std::string& source, const std::string& target, int ownerUid, int ownerGid,
+                 int permMask) {
     int mountFlags = MS_NODEV | MS_NOSUID | MS_DIRSYNC | MS_NOATIME | MS_NOEXEC;
     auto mountData = android::base::StringPrintf("uid=%d,gid=%d,fmask=%o,dmask=%o", ownerUid,
                                                  ownerGid, permMask, permMask);
@@ -77,6 +77,27 @@ status_t Mount(const std::string& source, const std::string& target, int ownerUi
     return -1;
 }
 
+struct mount_args {
+    const std::string& source;
+    const std::string& target;
+    int ownerUid;
+    int ownerGid;
+    int permMask;
+};
+
+int DoMountWrapper(void* args) {
+    struct mount_args* m_args = (struct mount_args*)args;
+
+    return DoMount(m_args->source, m_args->target, m_args->ownerUid, m_args->ownerGid,
+                   m_args->permMask);
+}
+
+status_t Mount(const std::string& source, const std::string& target, int ownerUid, int ownerGid,
+               int permMask) {
+    struct mount_args args = {source, target, ownerUid, ownerGid, permMask};
+    return ForkTimeout(DoMountWrapper, &args, kUntrustedMountSleepTime);
+}
+
 status_t Format(const std::string& source) {
     std::vector<std::string> cmd;
     cmd.push_back(kMkfsPath);
diff --git a/fs/Ext4.cpp b/fs/Ext4.cpp
index 293efc43..800f9034 100644
--- a/fs/Ext4.cpp
+++ b/fs/Ext4.cpp
@@ -68,7 +68,7 @@ status_t Check(const std::string& source, const std::string& target) {
     const char* c_target = target.c_str();
     int ret;
     long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
-    char* tmpmnt_opts = (char*)"nomblk_io_submit,errors=remount-ro";
+    char* tmpmnt_opts = (char*)"errors=remount-ro";
 
     /*
      * First try to mount and unmount the filesystem.  We do this because
diff --git a/fs/F2fs.cpp b/fs/F2fs.cpp
index 99afc32a..3cdf5740 100644
--- a/fs/F2fs.cpp
+++ b/fs/F2fs.cpp
@@ -72,8 +72,10 @@ status_t Mount(const std::string& source, const std::string& target) {
 }
 
 status_t Format(const std::string& source, bool is_zoned,
-                const std::vector<std::string>& user_devices) {
+                const std::vector<std::string>& user_devices, int64_t length) {
     std::vector<char const*> cmd;
+    /* '-g android' parameter passed here which defaults the sector size to 4096 */
+    static constexpr int kSectorSize = 4096;
     cmd.emplace_back(kMkfsPath);
 
     cmd.emplace_back("-f");
@@ -110,6 +112,9 @@ status_t Format(const std::string& source, bool is_zoned,
 
     cmd.emplace_back(source.c_str());
 
+    if (length) {
+        cmd.emplace_back(std::to_string(length / kSectorSize).c_str());
+    }
     return logwrap_fork_execvp(cmd.size(), cmd.data(), nullptr, false, LOG_KLOG,
                              false, nullptr);
 }
diff --git a/fs/F2fs.h b/fs/F2fs.h
index a0218f26..73913102 100644
--- a/fs/F2fs.h
+++ b/fs/F2fs.h
@@ -31,7 +31,7 @@ bool IsSupported();
 status_t Check(const std::string& source);
 status_t Mount(const std::string& source, const std::string& target);
 status_t Format(const std::string& source, const bool is_zoned,
-                const std::vector<std::string>& user_devices);
+                const std::vector<std::string>& user_devices, int64_t length = 0);
 
 }  // namespace f2fs
 }  // namespace vold
diff --git a/fs/Vfat.cpp b/fs/Vfat.cpp
index d9e2713f..3bab02f9 100644
--- a/fs/Vfat.cpp
+++ b/fs/Vfat.cpp
@@ -129,8 +129,8 @@ int16_t currentUtcOffsetMinutes() {
     return (int16_t)(utcOffsetSeconds / 60);
 }
 
-status_t Mount(const std::string& source, const std::string& target, bool ro, bool remount,
-               bool executable, int ownerUid, int ownerGid, int permMask, bool createLost) {
+status_t DoMount(const std::string& source, const std::string& target, bool ro, bool remount,
+                 bool executable, int ownerUid, int ownerGid, int permMask, bool createLost) {
     int rc;
     unsigned long flags;
 
@@ -198,6 +198,32 @@ status_t Mount(const std::string& source, const std::string& target, bool ro, bo
     return rc;
 }
 
+struct mount_args {
+    const std::string& source;
+    const std::string& target;
+    bool ro;
+    bool remount;
+    bool executable;
+    int ownerUid;
+    int ownerGid;
+    int permMask;
+    bool createLost;
+};
+
+int DoMountWrapper(void* args) {
+    struct mount_args* m_args = (struct mount_args*)args;
+
+    return DoMount(m_args->source, m_args->target, m_args->ro, m_args->remount, m_args->executable,
+                   m_args->ownerUid, m_args->ownerGid, m_args->permMask, m_args->createLost);
+}
+
+status_t Mount(const std::string& source, const std::string& target, bool ro, bool remount,
+               bool executable, int ownerUid, int ownerGid, int permMask, bool createLost) {
+    struct mount_args args = {source,   target,   ro,       remount,   executable,
+                              ownerUid, ownerGid, permMask, createLost};
+    return ForkTimeout(DoMountWrapper, &args, kUntrustedMountSleepTime);
+}
+
 status_t Format(const std::string& source, unsigned long numSectors) {
     std::vector<std::string> cmd;
     cmd.push_back(kMkfsPath);
diff --git a/model/PublicVolume.cpp b/model/PublicVolume.cpp
index e86d0026..91b1ca23 100644
--- a/model/PublicVolume.cpp
+++ b/model/PublicVolume.cpp
@@ -269,6 +269,12 @@ status_t PublicVolume::doMount() {
             // No need to bind if the user does not share storage with the mount owner
             continue;
         }
+        // Create mount directory for the user as there is a chance that no other Volume is mounted
+        // for the user (ex: if the user is just started), so /mnt/user/user_id  does not exist yet.
+        auto mountDirStatus = PrepareMountDirForUser(started_user);
+        if (mountDirStatus != OK) {
+            LOG(ERROR) << "Failed to create Mount Directory for user " << started_user;
+        }
         auto bindMountStatus = bindMountForUser(started_user);
         if (bindMountStatus != OK) {
             LOG(ERROR) << "Bind Mounting Public Volume: " << stableName
diff --git a/tests/corpus/seed-2024-08-29-0 b/tests/corpus/seed-2024-08-29-0
new file mode 100644
index 00000000..3ee0dc41
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-0 differ
diff --git a/tests/corpus/seed-2024-08-29-1 b/tests/corpus/seed-2024-08-29-1
new file mode 100644
index 00000000..612a60c5
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-1 differ
diff --git a/tests/corpus/seed-2024-08-29-10 b/tests/corpus/seed-2024-08-29-10
new file mode 100644
index 00000000..f5a5c0f3
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-10 differ
diff --git a/tests/corpus/seed-2024-08-29-11 b/tests/corpus/seed-2024-08-29-11
new file mode 100644
index 00000000..c497a4b5
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-11 differ
diff --git a/tests/corpus/seed-2024-08-29-12 b/tests/corpus/seed-2024-08-29-12
new file mode 100644
index 00000000..3a20bc55
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-12 differ
diff --git a/tests/corpus/seed-2024-08-29-13 b/tests/corpus/seed-2024-08-29-13
new file mode 100644
index 00000000..4bce6edd
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-13 differ
diff --git a/tests/corpus/seed-2024-08-29-14 b/tests/corpus/seed-2024-08-29-14
new file mode 100644
index 00000000..1680af07
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-14 differ
diff --git a/tests/corpus/seed-2024-08-29-15 b/tests/corpus/seed-2024-08-29-15
new file mode 100644
index 00000000..21b99f0a
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-15 differ
diff --git a/tests/corpus/seed-2024-08-29-2 b/tests/corpus/seed-2024-08-29-2
new file mode 100644
index 00000000..9ea7969e
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-2 differ
diff --git a/tests/corpus/seed-2024-08-29-3 b/tests/corpus/seed-2024-08-29-3
new file mode 100644
index 00000000..d679dd48
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-3 differ
diff --git a/tests/corpus/seed-2024-08-29-4 b/tests/corpus/seed-2024-08-29-4
new file mode 100644
index 00000000..3734101c
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-4 differ
diff --git a/tests/corpus/seed-2024-08-29-5 b/tests/corpus/seed-2024-08-29-5
new file mode 100644
index 00000000..f6ddcd8a
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-5 differ
diff --git a/tests/corpus/seed-2024-08-29-6 b/tests/corpus/seed-2024-08-29-6
new file mode 100644
index 00000000..bdd6fb5c
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-6 differ
diff --git a/tests/corpus/seed-2024-08-29-7 b/tests/corpus/seed-2024-08-29-7
new file mode 100644
index 00000000..2e1d6cb2
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-7 differ
diff --git a/tests/corpus/seed-2024-08-29-8 b/tests/corpus/seed-2024-08-29-8
new file mode 100644
index 00000000..9491bf04
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-8 differ
diff --git a/tests/corpus/seed-2024-08-29-9 b/tests/corpus/seed-2024-08-29-9
new file mode 100644
index 00000000..7366c8c3
Binary files /dev/null and b/tests/corpus/seed-2024-08-29-9 differ
diff --git a/vdc.cpp b/vdc.cpp
index ee8cf9ee..9764b1af 100644
--- a/vdc.cpp
+++ b/vdc.cpp
@@ -109,13 +109,15 @@ static void encryptFstab(std::vector<std::string>& args,
     if (isZoned == android::base::ParseBoolResult::kError) exit(EINVAL);
 
     std::vector<std::string> userDevices = {};
-    if (args[7] != "") {
-        userDevices = android::base::Split(args[7], " ");
+    int64_t length;
+    if (!android::base::ParseInt(args[7], &length)) exit(EINVAL);
+    if (args[8] != "") {
+        userDevices = android::base::Split(args[8], " ");
     }
-    checkStatus(args,
-                vold->encryptFstab(args[2], args[3],
-                                   shouldFormat == android::base::ParseBoolResult::kTrue, args[5],
-                                   isZoned == android::base::ParseBoolResult::kTrue, userDevices));
+    checkStatus(args, vold->encryptFstab(args[2], args[3],
+                                         shouldFormat == android::base::ParseBoolResult::kTrue,
+                                         args[5], isZoned == android::base::ParseBoolResult::kTrue,
+                                         userDevices, length));
 }
 
 int main(int argc, char** argv) {
@@ -162,7 +164,7 @@ int main(int argc, char** argv) {
         bindkeys(args, vold);
     } else if (args[0] == "cryptfs" && args[1] == "mountFstab" && args.size() == 6) {
         mountFstab(args, vold);
-    } else if (args[0] == "cryptfs" && args[1] == "encryptFstab" && args.size() == 8) {
+    } else if (args[0] == "cryptfs" && args[1] == "encryptFstab" && args.size() == 9) {
         encryptFstab(args, vold);
     } else if (args[0] == "checkpoint" && args[1] == "supportsCheckpoint" && args.size() == 2) {
         bool supported = false;
```

