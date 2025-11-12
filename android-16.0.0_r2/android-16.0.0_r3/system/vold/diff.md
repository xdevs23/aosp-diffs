```diff
diff --git a/Android.bp b/Android.bp
index bef6471..d4eb18c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -29,8 +29,6 @@ cc_defaults {
     name: "vold_default_libs",
 
     static_libs: [
-        "android.hardware.health.storage@1.0",
-        "android.hardware.health.storage-V1-ndk",
         "android.security.maintenance-ndk",
         "libasync_safe",
         "libavb",
@@ -288,4 +286,4 @@ aconfig_declarations {
 cc_aconfig_library {
     name: "vold_flags_c_lib",
     aconfig_declarations: "vold_flags",
-}
\ No newline at end of file
+}
diff --git a/FileDeviceUtils.h b/FileDeviceUtils.h
index 4428cef..d167d2d 100644
--- a/FileDeviceUtils.h
+++ b/FileDeviceUtils.h
@@ -18,6 +18,7 @@
 #define ANDROID_VOLD_FILEDEVICEUTILS_H
 
 #include <linux/fiemap.h>
+#include <memory>
 #include <string>
 
 namespace android {
diff --git a/IdleMaint.cpp b/IdleMaint.cpp
index fafa280..acd5755 100644
--- a/IdleMaint.cpp
+++ b/IdleMaint.cpp
@@ -24,15 +24,12 @@
 #include <thread>
 #include <utility>
 
-#include <aidl/android/hardware/health/storage/BnGarbageCollectCallback.h>
-#include <aidl/android/hardware/health/storage/IStorage.h>
 #include <android-base/chrono_utils.h>
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android/binder_manager.h>
-#include <android/hardware/health/storage/1.0/IStorage.h>
 #include <fs_mgr.h>
 #include <private/android_filesystem_config.h>
 #include <wakelock/wakelock.h>
@@ -50,15 +47,6 @@ using android::base::Realpath;
 using android::base::StringPrintf;
 using android::base::Timer;
 using android::base::WriteStringToFile;
-using android::hardware::Return;
-using android::hardware::Void;
-using AStorage = aidl::android::hardware::health::storage::IStorage;
-using ABnGarbageCollectCallback =
-        aidl::android::hardware::health::storage::BnGarbageCollectCallback;
-using AResult = aidl::android::hardware::health::storage::Result;
-using HStorage = android::hardware::health::storage::V1_0::IStorage;
-using HGarbageCollectCallback = android::hardware::health::storage::V1_0::IGarbageCollectCallback;
-using HResult = android::hardware::health::storage::V1_0::Result;
 using std::string_literals::operator""s;
 
 namespace android {
@@ -325,70 +313,6 @@ static void runDevGcFstab(void) {
     return;
 }
 
-enum class IDL { HIDL, AIDL };
-std::ostream& operator<<(std::ostream& os, IDL idl) {
-    return os << (idl == IDL::HIDL ? "HIDL" : "AIDL");
-}
-
-template <IDL idl, typename Result>
-class GcCallbackImpl {
-  protected:
-    void onFinishInternal(Result result) {
-        std::unique_lock<std::mutex> lock(mMutex);
-        mFinished = true;
-        mResult = result;
-        lock.unlock();
-        mCv.notify_all();
-    }
-
-  public:
-    void wait(uint64_t seconds) {
-        std::unique_lock<std::mutex> lock(mMutex);
-        mCv.wait_for(lock, std::chrono::seconds(seconds), [this] { return mFinished; });
-
-        if (!mFinished) {
-            LOG(WARNING) << "Dev GC on " << idl << " HAL timeout";
-        } else if (mResult != Result::SUCCESS) {
-            LOG(WARNING) << "Dev GC on " << idl << " HAL failed with " << toString(mResult);
-        } else {
-            LOG(INFO) << "Dev GC on " << idl << " HAL successful";
-        }
-    }
-
-  private:
-    std::mutex mMutex;
-    std::condition_variable mCv;
-    bool mFinished{false};
-    Result mResult{Result::UNKNOWN_ERROR};
-};
-
-class AGcCallbackImpl : public ABnGarbageCollectCallback,
-                        public GcCallbackImpl<IDL::AIDL, AResult> {
-    ndk::ScopedAStatus onFinish(AResult result) override {
-        onFinishInternal(result);
-        return ndk::ScopedAStatus::ok();
-    }
-};
-
-class HGcCallbackImpl : public HGarbageCollectCallback, public GcCallbackImpl<IDL::HIDL, HResult> {
-    Return<void> onFinish(HResult result) override {
-        onFinishInternal(result);
-        return Void();
-    }
-};
-
-template <IDL idl, typename Service, typename GcCallbackImpl, typename GetDescription>
-static void runDevGcOnHal(Service service, GcCallbackImpl cb, GetDescription get_description) {
-    LOG(DEBUG) << "Start Dev GC on " << idl << " HAL";
-    auto ret = service->garbageCollect(DEVGC_TIMEOUT_SEC, cb);
-    if (!ret.isOk()) {
-        LOG(WARNING) << "Cannot start Dev GC on " << idl
-                     << " HAL: " << std::invoke(get_description, ret);
-        return;
-    }
-    cb->wait(DEVGC_TIMEOUT_SEC);
-}
-
 static void runDevGc(void) {
     runDevGcFstab();
 }
diff --git a/KeyUtil.h b/KeyUtil.h
index cc1a1f9..eb1aa55 100644
--- a/KeyUtil.h
+++ b/KeyUtil.h
@@ -23,6 +23,7 @@
 #include <fscrypt/fscrypt.h>
 
 #include <memory>
+#include <mutex>
 #include <string>
 
 namespace android {
diff --git a/OWNERS b/OWNERS
index 81da329..36d5d07 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,6 +3,5 @@ ebiggers@google.com
 jeffv@google.com
 jsharkey@android.com
 maco@google.com
-paulcrowley@google.com
 paullawrence@google.com
 zezeozue@google.com
diff --git a/vold_prepare_subdirs.cpp b/vold_prepare_subdirs.cpp
index e82a7c2..ca8e3f6 100644
--- a/vold_prepare_subdirs.cpp
+++ b/vold_prepare_subdirs.cpp
@@ -235,15 +235,7 @@ static bool prepare_subdirs(const std::string& volume_uuid, int user_id, int fla
             // the user id to set the correct selinux mls_level.
             if (!prepare_dir_for_user(sehandle, 0770, AID_SYSTEM, AID_CACHE,
                                       misc_ce_path + "/checkin", user_id)) {
-                // TODO(b/203742483) the checkin directory was created with the wrong permission &
-                // context. Delete the directory to get these devices out of the bad state. Revert
-                // the change once the droidfood population is on newer build.
-                LOG(INFO) << "Failed to prepare the checkin directory, deleting for recreation";
-                android::vold::DeleteDirContentsAndDir(misc_ce_path + "/checkin");
-                if (!prepare_dir_for_user(sehandle, 0770, AID_SYSTEM, AID_CACHE,
-                                          misc_ce_path + "/checkin", user_id)) {
-                    return false;
-                }
+                return false;
             }
 
             auto system_ce_path = android::vold::BuildDataSystemCePath(user_id);
@@ -254,6 +246,10 @@ static bool prepare_subdirs(const std::string& volume_uuid, int user_id, int fla
                              system_ce_path + "/backup_stage")) {
                 return false;
             }
+            if (!prepare_dir(sehandle, 0700, AID_SYSTEM, AID_SYSTEM,
+                             system_ce_path + "/appsearch")) {
+                return false;
+            }
             auto vendor_ce_path = android::vold::BuildDataVendorCePath(user_id);
             auto facedata_path = vendor_ce_path + "/facedata";
             if (!prepare_dir(sehandle, 0700, AID_SYSTEM, AID_SYSTEM, facedata_path)) {
```

