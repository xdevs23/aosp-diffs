```diff
diff --git a/FsCrypt.cpp b/FsCrypt.cpp
index 3eb4599..563dd4f 100644
--- a/FsCrypt.cpp
+++ b/FsCrypt.cpp
@@ -37,6 +37,7 @@
 #include <sys/mount.h>
 #include <sys/stat.h>
 #include <sys/types.h>
+#include <sys/utsname.h>
 #include <unistd.h>
 
 #include <private/android_filesystem_config.h>
@@ -233,7 +234,20 @@ static bool read_and_fixate_user_ce_key(userid_t user_id,
     return false;
 }
 
-static bool MightBeEmmcStorage(const std::string& blk_device) {
+// Checks whether the kernel definitely supports the sysfs files that describe the storage
+// hardware's inline encryption capabilities.  They are supported in upstream 5.18 and later, and in
+// android14-5.15 and later (but not android13-5.15).  For simplicity we just check for 5.18.
+static bool DoesKernelSupportBlkCryptoSysfsFiles() {
+    struct utsname uts;
+    unsigned int major = 0, minor = 0;
+    if (uname(&uts) != 0 || sscanf(uts.release, "%u.%u", &major, &minor) != 2) {
+        return true;  // This should never happen; assume new rather than old.
+    }
+    return major > 5 || (major == 5 && minor >= 18);
+}
+
+// Checks whether the storage hardware might support only 32-bit data unit numbers.
+static bool DoesHardwareSupportOnly32DunBits(const std::string& blk_device) {
     // Handle symlinks.
     std::string real_path;
     if (!Realpath(blk_device, &real_path)) {
@@ -249,15 +263,53 @@ static bool MightBeEmmcStorage(const std::string& blk_device) {
     }
 
     // Now we should have the "real" block device.
-    LOG(DEBUG) << "MightBeEmmcStorage(): blk_device = " << blk_device
-               << ", real_path=" << real_path;
     std::string name = Basename(real_path);
-    return StartsWith(name, "mmcblk") ||
-           // virtio devices may provide inline encryption support that is
-           // backed by eMMC inline encryption on the host, thus inheriting the
-           // DUN size limitation.  So virtio devices must be allowed here too.
-           // TODO(b/207390665): check the maximum DUN size directly instead.
-           StartsWith(name, "vd");
+
+    // If possible, do the check precisely via sysfs.
+    // Exclude older devices, just in case they are broken by doing the check correctly...
+    if (GetFirstApiLevel() >= __ANDROID_API_V__) {
+        std::string sysfs_path = "/sys/class/block/" + name + "/queue/crypto/max_dun_bits";
+        if (!android::vold::pathExists(sysfs_path)) {
+            // For a partition, "queue" is in the parent directory which represents the disk.
+            sysfs_path = "/sys/class/block/" + name + "/../queue/crypto/max_dun_bits";
+        }
+        if (android::vold::pathExists(sysfs_path)) {
+            std::string max_dun_bits;
+            if (!android::base::ReadFileToString(sysfs_path, &max_dun_bits)) {
+                PLOG(ERROR) << "Error reading " << sysfs_path;
+                return false;
+            }
+            max_dun_bits = android::base::Trim(max_dun_bits);
+            if (max_dun_bits != "32") {
+                LOG(ERROR) << sysfs_path << " = " << max_dun_bits;
+                // In this case, using emmc_optimized is not appropriate because the hardware
+                // supports inline encryption but does not have the 32-bit DUN limit.
+                return false;
+            }
+            LOG(DEBUG) << sysfs_path << " = " << max_dun_bits;
+            return true;
+        }
+        if (DoesKernelSupportBlkCryptoSysfsFiles()) {
+            // In this case, using emmc_optimized is not appropriate because the hardware does not
+            // support inline encryption.
+            LOG(ERROR) << sysfs_path << " does not exist";
+            return false;
+        }
+        // In this case, the kernel might be too old to support the sysfs files.
+    }
+
+    // Fallback method for older kernels that don't have the crypto capabilities in sysfs.  The
+    // 32-bit DUN limit is only known to exist on eMMC storage, and also on virtio storage that
+    // inherits the limit from eMMC on the host.  So allow either of those storage types.  Note that
+    // this can be overly lenient compared to actually checking max_dun_bits.
+    if (StartsWith(name, "mmcblk") || StartsWith(name, "vd")) {
+        LOG(DEBUG) << __func__ << "(): << blk_device = " << blk_device
+                   << ", real_path = " << real_path;
+        return true;
+    }
+    // Log at ERROR level here so that it shows up in the kernel log.
+    LOG(ERROR) << __func__ << "(): << blk_device = " << blk_device << ", real_path = " << real_path;
+    return false;
 }
 
 // Sets s_data_options to the file encryption options for the /data filesystem.
@@ -273,9 +325,10 @@ static bool init_data_file_encryption_options() {
         return false;
     }
     if ((s_data_options.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32) &&
-        !MightBeEmmcStorage(entry->blk_device)) {
-        LOG(ERROR) << "The emmc_optimized encryption flag is only allowed on eMMC storage.  Remove "
-                      "this flag from the device's fstab";
+        !DoesHardwareSupportOnly32DunBits(entry->blk_device)) {
+        // This would unnecessarily reduce security and not be compliant with the CDD.
+        LOG(ERROR) << "The emmc_optimized encryption flag is only allowed on hardware limited to "
+                      "32-bit DUNs.  Remove this flag from the device's fstab";
         return false;
     }
     return true;
@@ -757,15 +810,14 @@ bool fscrypt_set_ce_key_protection(userid_t user_id, const std::vector<uint8_t>&
         // kEmptyAuthentication are encrypted by the user's synthetic password.
         LOG(DEBUG) << "CE key already exists on-disk; re-protecting it with the given secret";
         if (!read_and_fixate_user_ce_key(user_id, kEmptyAuthentication, &ce_key)) {
-            LOG(ERROR) << "Failed to retrieve CE key for user " << user_id << " using empty auth";
             // Before failing, also check whether the key is already protected
-            // with the given secret.  This isn't expected, but in theory it
-            // could happen if an upgrade is requested for a user more than once
-            // due to a power-off or other interruption.
+            // with the given secret.
             if (read_and_fixate_user_ce_key(user_id, auth, &ce_key)) {
-                LOG(WARNING) << "CE key is already protected by given secret";
+                LOG(INFO) << "CE key is already protected by given secret.  Nothing to do.";
+                LOG(INFO) << "Errors above are for the attempt with empty auth and can be ignored.";
                 return true;
             }
+            LOG(ERROR) << "Failed to retrieve CE key for user " << user_id;
             // The key isn't protected by either kEmptyAuthentication or by
             // |auth|.  This should never happen, and there's nothing we can do
             // besides return an error.
diff --git a/Keystore.cpp b/Keystore.cpp
index 6040f2d..fd8a887 100644
--- a/Keystore.cpp
+++ b/Keystore.cpp
@@ -130,8 +130,8 @@ Keystore::Keystore() {
 bool Keystore::generateKey(const km::AuthorizationSet& inParams, std::string* key) {
     ks2::KeyDescriptor in_key = {
             .domain = ks2::Domain::BLOB,
-            .alias = std::nullopt,
             .nspace = VOLD_NAMESPACE,
+            .alias = std::nullopt,
             .blob = std::nullopt,
     };
     ks2::KeyMetadata keyMetadata;
@@ -154,8 +154,8 @@ bool Keystore::exportKey(const KeyBuffer& ksKey, std::string* key) {
     bool ret = false;
     ks2::KeyDescriptor storageKey = {
             .domain = ks2::Domain::BLOB,
-            .alias = std::nullopt,
             .nspace = VOLD_NAMESPACE,
+            .alias = std::nullopt,
     };
     storageKey.blob = std::make_optional<std::vector<uint8_t>>(ksKey.begin(), ksKey.end());
     ks2::EphemeralStorageKeyResponse ephemeral_key_response;
@@ -184,8 +184,8 @@ out:
 bool Keystore::deleteKey(const std::string& key) {
     ks2::KeyDescriptor keyDesc = {
             .domain = ks2::Domain::BLOB,
-            .alias = std::nullopt,
             .nspace = VOLD_NAMESPACE,
+            .alias = std::nullopt,
     };
     keyDesc.blob =
             std::optional<std::vector<uint8_t>>(std::vector<uint8_t>(key.begin(), key.end()));
@@ -198,8 +198,8 @@ KeystoreOperation Keystore::begin(const std::string& key, const km::Authorizatio
                                   km::AuthorizationSet* outParams) {
     ks2::KeyDescriptor keyDesc = {
             .domain = ks2::Domain::BLOB,
-            .alias = std::nullopt,
             .nspace = VOLD_NAMESPACE,
+            .alias = std::nullopt,
     };
     keyDesc.blob =
             std::optional<std::vector<uint8_t>>(std::vector<uint8_t>(key.begin(), key.end()));
@@ -224,7 +224,7 @@ KeystoreOperation Keystore::begin(const std::string& key, const km::Authorizatio
 }
 
 void Keystore::earlyBootEnded() {
-    ::ndk::SpAIBinder binder(AServiceManager_getService(maintenance_service_name));
+    ::ndk::SpAIBinder binder(AServiceManager_waitForService(maintenance_service_name));
     auto maint_service = ks2_maint::IKeystoreMaintenance::fromBinder(binder);
 
     if (!maint_service) {
@@ -237,7 +237,7 @@ void Keystore::earlyBootEnded() {
 }
 
 void Keystore::deleteAllKeys() {
-    ::ndk::SpAIBinder binder(AServiceManager_getService(maintenance_service_name));
+    ::ndk::SpAIBinder binder(AServiceManager_waitForService(maintenance_service_name));
     auto maint_service = ks2_maint::IKeystoreMaintenance::fromBinder(binder);
 
     if (!maint_service) {
diff --git a/MetadataCrypt.cpp b/MetadataCrypt.cpp
index 8d83541..2fa0cff 100644
--- a/MetadataCrypt.cpp
+++ b/MetadataCrypt.cpp
@@ -291,7 +291,7 @@ bool fscrypt_mount_metadata_encrypted(const std::string& blk_device, const std::
                                       bool needs_encrypt, bool should_format,
                                       const std::string& fs_type, bool is_zoned,
                                       const std::vector<std::string>& user_devices,
-                                      int64_t length) {
+                                      const std::vector<bool>& device_aliased, int64_t length) {
     LOG(DEBUG) << "fscrypt_mount_metadata_encrypted: " << mount_point
                << " encrypt: " << needs_encrypt << " format: " << should_format << " with "
                << fs_type << " block device: " << blk_device << " with zoned " << is_zoned
@@ -385,7 +385,8 @@ bool fscrypt_mount_metadata_encrypted(const std::string& blk_device, const std::
             if (fs_type == "ext4") {
                 error = ext4::Format(crypto_blkdev, 0, mount_point);
             } else if (fs_type == "f2fs") {
-                error = f2fs::Format(crypto_blkdev, is_zoned, crypto_user_blkdev, length);
+                error = f2fs::Format(crypto_blkdev, is_zoned, crypto_user_blkdev, device_aliased,
+                                     length);
             } else {
                 LOG(ERROR) << "Unknown filesystem type: " << fs_type;
                 return false;
diff --git a/MetadataCrypt.h b/MetadataCrypt.h
index a091443..6c46237 100644
--- a/MetadataCrypt.h
+++ b/MetadataCrypt.h
@@ -29,7 +29,8 @@ void defaultkey_precreate_dm_device();
 bool fscrypt_mount_metadata_encrypted(const std::string& block_device,
                                       const std::string& mount_point, bool needs_encrypt,
                                       bool should_format, const std::string& fs_type, bool is_zoned,
-                                      const std::vector<std::string>& user_devices, int64_t length);
+                                      const std::vector<std::string>& user_devices,
+                                      const std::vector<bool>& device_aliased, int64_t length);
 
 bool defaultkey_volume_keygen(KeyGeneration* gen);
 
diff --git a/VoldNativeService.cpp b/VoldNativeService.cpp
index 98dec66..3784487 100644
--- a/VoldNativeService.cpp
+++ b/VoldNativeService.cpp
@@ -594,19 +594,21 @@ binder::Status VoldNativeService::mountFstab(const std::string& blkDevice,
     ACQUIRE_LOCK;
 
     return translateBool(fscrypt_mount_metadata_encrypted(blkDevice, mountPoint, false, false,
-                                                          "null", isZoned, userDevices, 0));
+                                                          "null", isZoned, userDevices, {}, 0));
 }
 
 binder::Status VoldNativeService::encryptFstab(const std::string& blkDevice,
                                                const std::string& mountPoint, bool shouldFormat,
                                                const std::string& fsType, bool isZoned,
                                                const std::vector<std::string>& userDevices,
+                                               const std::vector<bool>& deviceAliased,
                                                int64_t length) {
     ENFORCE_SYSTEM_OR_ROOT;
     ACQUIRE_LOCK;
 
     return translateBool(fscrypt_mount_metadata_encrypted(blkDevice, mountPoint, true, shouldFormat,
-                                                          fsType, isZoned, userDevices, length));
+                                                          fsType, isZoned, userDevices,
+                                                          deviceAliased, length));
 }
 
 binder::Status VoldNativeService::setStorageBindingSeed(const std::vector<uint8_t>& seed) {
diff --git a/VoldNativeService.h b/VoldNativeService.h
index bd37ac7..a5253c0 100644
--- a/VoldNativeService.h
+++ b/VoldNativeService.h
@@ -110,7 +110,8 @@ class VoldNativeService : public BinderService<VoldNativeService>, public os::Bn
 
     binder::Status encryptFstab(const std::string& blkDevice, const std::string& mountPoint,
                                 bool shouldFormat, const std::string& fsType, bool isZoned,
-                                const std::vector<std::string>& userDevices, int64_t length);
+                                const std::vector<std::string>& userDevices,
+                                const std::vector<bool>& deviceAliased, int64_t length);
 
     binder::Status setStorageBindingSeed(const std::vector<uint8_t>& seed);
 
diff --git a/VolumeManager.cpp b/VolumeManager.cpp
index a7c87a3..d932ec8 100644
--- a/VolumeManager.cpp
+++ b/VolumeManager.cpp
@@ -1247,19 +1247,11 @@ int VolumeManager::openAppFuseFile(uid_t uid, int mountId, int fileId, int flags
     return android::vold::OpenAppFuseFile(uid, mountId, fileId, flags);
 }
 
-android::status_t android::vold::GetStorageSize(int64_t* storageSize) {
-    // Start with the /data mount point from fs_mgr
-    auto entry = android::fs_mgr::GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT);
-    if (entry == nullptr) {
-        LOG(ERROR) << "No mount point entry for " << DATA_MNT_POINT;
-        return EINVAL;
-    }
-
+static android::status_t getDeviceSize(std::string& device, int64_t* storageSize) {
     // Follow any symbolic links
-    std::string blkDevice = entry->blk_device;
     std::string dataDevice;
-    if (!android::base::Realpath(blkDevice, &dataDevice)) {
-        dataDevice = blkDevice;
+    if (!android::base::Realpath(device, &dataDevice)) {
+        dataDevice = device;
     }
 
     // Handle mapped volumes.
@@ -1311,3 +1303,29 @@ android::status_t android::vold::GetStorageSize(int64_t* storageSize) {
     *storageSize *= 512;
     return OK;
 }
+
+android::status_t android::vold::GetStorageSize(int64_t* storageSize) {
+    android::status_t status;
+    // Start with the /data mount point from fs_mgr
+    auto entry = android::fs_mgr::GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT);
+    if (entry == nullptr) {
+        LOG(ERROR) << "No mount point entry for " << DATA_MNT_POINT;
+        return EINVAL;
+    }
+
+    status = getDeviceSize(entry->blk_device, storageSize);
+    if (status != OK) {
+        return status;
+    }
+
+    for (auto device : entry->user_devices) {
+        int64_t deviceStorageSize;
+        status = getDeviceSize(device, &deviceStorageSize);
+        if (status != OK) {
+            return status;
+        }
+        *storageSize += deviceStorageSize;
+    }
+
+    return OK;
+}
diff --git a/binder/android/os/IVold.aidl b/binder/android/os/IVold.aidl
index a8cce94..810fdad 100644
--- a/binder/android/os/IVold.aidl
+++ b/binder/android/os/IVold.aidl
@@ -84,7 +84,7 @@ interface IVold {
 
     void initUser0();
     void mountFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean isZoned, in @utf8InCpp String[] userDevices);
-    void encryptFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean shouldFormat, @utf8InCpp String fsType, boolean isZoned, in @utf8InCpp String[] userDevices, long length);
+    void encryptFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean shouldFormat, @utf8InCpp String fsType, boolean isZoned, in @utf8InCpp String[] userDevices, in boolean[] deviceAliased, long length);
 
     void setStorageBindingSeed(in byte[] seed);
 
diff --git a/fs/Exfat.cpp b/fs/Exfat.cpp
index 48fa6a3..6444178 100644
--- a/fs/Exfat.cpp
+++ b/fs/Exfat.cpp
@@ -102,7 +102,7 @@ status_t Format(const std::string& source) {
     std::vector<std::string> cmd;
     cmd.push_back(kMkfsPath);
     cmd.push_back("-n");
-    cmd.push_back("android");
+    cmd.push_back("External");
     cmd.push_back(source);
 
     int rc = ForkExecvp(cmd);
diff --git a/fs/F2fs.cpp b/fs/F2fs.cpp
index 3cdf574..c52e80e 100644
--- a/fs/F2fs.cpp
+++ b/fs/F2fs.cpp
@@ -27,6 +27,7 @@
 #include <vector>
 
 #include <sys/mount.h>
+#include <filesystem>
 
 using android::base::StringPrintf;
 
@@ -72,8 +73,9 @@ status_t Mount(const std::string& source, const std::string& target) {
 }
 
 status_t Format(const std::string& source, bool is_zoned,
-                const std::vector<std::string>& user_devices, int64_t length) {
-    std::vector<char const*> cmd;
+                const std::vector<std::string>& user_devices,
+                const std::vector<bool>& device_aliased, int64_t length) {
+    std::vector<std::string> cmd;
     /* '-g android' parameter passed here which defaults the sector size to 4096 */
     static constexpr int kSectorSize = 4096;
     cmd.emplace_back(kMkfsPath);
@@ -102,21 +104,31 @@ status_t Format(const std::string& source, bool is_zoned,
     if (is_zoned) {
         cmd.emplace_back("-m");
     }
-    for (auto& device : user_devices) {
+    for (size_t i = 0; i < user_devices.size(); i++) {
+        std::string device_name = user_devices[i];
+
         cmd.emplace_back("-c");
-        cmd.emplace_back(device.c_str());
+        if (device_aliased[i]) {
+            std::filesystem::path path = device_name;
+            device_name += "@" + path.filename().string();
+        }
+        cmd.emplace_back(device_name);
     }
-    std::string block_size = std::to_string(getpagesize());
     cmd.emplace_back("-b");
-    cmd.emplace_back(block_size.c_str());
+    cmd.emplace_back(std::to_string(getpagesize()));
 
     cmd.emplace_back(source.c_str());
 
     if (length) {
-        cmd.emplace_back(std::to_string(length / kSectorSize).c_str());
+        cmd.emplace_back(std::to_string(length / kSectorSize));
+    }
+
+    std::vector<char const*> cmd_cstrs;
+    for (auto& arg : cmd) {
+        cmd_cstrs.emplace_back(arg.c_str());
     }
-    return logwrap_fork_execvp(cmd.size(), cmd.data(), nullptr, false, LOG_KLOG,
-                             false, nullptr);
+    return logwrap_fork_execvp(cmd_cstrs.size(), cmd_cstrs.data(), nullptr, false, LOG_KLOG, false,
+                               nullptr);
 }
 
 }  // namespace f2fs
diff --git a/fs/F2fs.h b/fs/F2fs.h
index 7391310..4193c87 100644
--- a/fs/F2fs.h
+++ b/fs/F2fs.h
@@ -31,7 +31,8 @@ bool IsSupported();
 status_t Check(const std::string& source);
 status_t Mount(const std::string& source, const std::string& target);
 status_t Format(const std::string& source, const bool is_zoned,
-                const std::vector<std::string>& user_devices, int64_t length = 0);
+                const std::vector<std::string>& user_devices,
+                const std::vector<bool>& device_aliased, int64_t length = 0);
 
 }  // namespace f2fs
 }  // namespace vold
diff --git a/model/PrivateVolume.cpp b/model/PrivateVolume.cpp
index bb52647..0f06c1f 100644
--- a/model/PrivateVolume.cpp
+++ b/model/PrivateVolume.cpp
@@ -45,6 +45,7 @@ namespace android {
 namespace vold {
 
 static const unsigned int kMajorBlockLoop = 7;
+static const unsigned int kMajorBlockHdd = 8;
 static const unsigned int kMajorBlockMmc = 179;
 
 PrivateVolume::PrivateVolume(dev_t device, const KeyBuffer& keyRaw)
@@ -218,6 +219,7 @@ status_t PrivateVolume::doFormat(const std::string& fsType) {
         // give everyone else ext4 because sysfs rotational isn't reliable.
         // Additionally, prefer f2fs for loop-based devices
         if ((major(mRawDevice) == kMajorBlockMmc ||
+             major(mRawDevice) == kMajorBlockHdd ||
              major(mRawDevice) == kMajorBlockLoop ||
              IsVirtioBlkDevice(major(mRawDevice))) && f2fs::IsSupported()) {
             resolvedFsType = "f2fs";
@@ -234,7 +236,7 @@ status_t PrivateVolume::doFormat(const std::string& fsType) {
             return -EIO;
         }
     } else if (resolvedFsType == "f2fs") {
-        if (f2fs::Format(mDmDevPath, false, {})) {
+        if (f2fs::Format(mDmDevPath, false, {}, {})) {
             PLOG(ERROR) << getId() << " failed to format";
             return -EIO;
         }
diff --git a/vdc.cpp b/vdc.cpp
index 9764b1a..400bc5d 100644
--- a/vdc.cpp
+++ b/vdc.cpp
@@ -114,10 +114,22 @@ static void encryptFstab(std::vector<std::string>& args,
     if (args[8] != "") {
         userDevices = android::base::Split(args[8], " ");
     }
+    std::vector<std::string> deviceAliasedStr = {};
+    std::vector<bool> deviceAliased = {};
+    if (args[9] != "") {
+        deviceAliasedStr = android::base::Split(args[9], " ");
+        for (auto aliased : deviceAliasedStr) {
+            if (aliased == "0") {
+                deviceAliased.push_back(false);
+            } else {
+                deviceAliased.push_back(true);
+            }
+        }
+    }
     checkStatus(args, vold->encryptFstab(args[2], args[3],
                                          shouldFormat == android::base::ParseBoolResult::kTrue,
                                          args[5], isZoned == android::base::ParseBoolResult::kTrue,
-                                         userDevices, length));
+                                         userDevices, deviceAliased, length));
 }
 
 int main(int argc, char** argv) {
@@ -164,7 +176,7 @@ int main(int argc, char** argv) {
         bindkeys(args, vold);
     } else if (args[0] == "cryptfs" && args[1] == "mountFstab" && args.size() == 6) {
         mountFstab(args, vold);
-    } else if (args[0] == "cryptfs" && args[1] == "encryptFstab" && args.size() == 9) {
+    } else if (args[0] == "cryptfs" && args[1] == "encryptFstab" && args.size() == 10) {
         encryptFstab(args, vold);
     } else if (args[0] == "checkpoint" && args[1] == "supportsCheckpoint" && args.size() == 2) {
         bool supported = false;
```

