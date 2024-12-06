```diff
diff --git a/common/hal/aidl_service/Android.bp b/common/hal/aidl_service/Android.bp
index b11b89a..3827f20 100644
--- a/common/hal/aidl_service/Android.bp
+++ b/common/hal/aidl_service/Android.bp
@@ -58,14 +58,15 @@ python_binary_host {
 }
 
 cc_genrule {
-   name: "aidl_camera_build_version",
-   tool_files: ["version_script.py"],
-   cmd: "python3 $(location version_script.py) $(in) $(out)",
-   vendor: true,
-   srcs: [
-       "aidl_camera_build_version.inl",
-   ],
-   out: ["aidl_camera_build_version.h"],
+    name: "aidl_camera_build_version",
+    tools: ["camera_hal_version_script"],
+    cmd: "$(location camera_hal_version_script) $(in) $(out)",
+    uses_order_only_build_number_file: true,
+    vendor: true,
+    srcs: [
+        "aidl_camera_build_version.inl",
+    ],
+    out: ["aidl_camera_build_version.h"],
 }
 
 cc_defaults {
diff --git a/common/hal/aidl_service/aidl_camera_device_session.cc b/common/hal/aidl_service/aidl_camera_device_session.cc
index 8bf2cee..90c9254 100644
--- a/common/hal/aidl_service/aidl_camera_device_session.cc
+++ b/common/hal/aidl_service/aidl_camera_device_session.cc
@@ -129,6 +129,9 @@ void AidlCameraDeviceSession::ProcessCaptureResult(
         ATRACE_INT64("preview_timestamp_diff", timestamp_diff);
         ATRACE_INT("preview_frame_number", hal_result->frame_number);
       }
+      if (first_request_frame_number_ == hal_result->frame_number) {
+        ATRACE_ASYNC_END("first_preview_frame", 0);
+      }
       preview_timestamp_last_ = timestamp_now;
     }
   }
@@ -142,6 +145,8 @@ void AidlCameraDeviceSession::ProcessCaptureResult(
     return;
   }
   if (aidl_results[0].inputBuffer.streamId != -1) {
+    ALOGI("%s: reprocess_frame %d image complete", __FUNCTION__,
+          aidl_results[0].frameNumber);
     ATRACE_ASYNC_END("reprocess_frame", aidl_results[0].frameNumber);
     aidl_profiler_->ReprocessingResultEnd(aidl_results[0].frameNumber);
   }
@@ -183,6 +188,8 @@ void AidlCameraDeviceSession::ProcessBatchCaptureResult(
     }
 
     if (aidl_result.inputBuffer.streamId != -1) {
+      ALOGI("%s: reprocess_frame %d image complete", __FUNCTION__,
+            aidl_result.frameNumber);
       ATRACE_ASYNC_END("reprocess_frame", aidl_result.frameNumber);
       aidl_profiler_->ReprocessingResultEnd(aidl_result.frameNumber);
     }
@@ -721,10 +728,15 @@ ndk::ScopedAStatus AidlCameraDeviceSession::processCaptureRequest(
     first_request_frame_number_ = requests[0].frameNumber;
     aidl_profiler_->FirstFrameStart();
     ATRACE_ASYNC_BEGIN("first_frame", 0);
+    if (preview_stream_id_ != -1) {
+      ATRACE_ASYNC_BEGIN("first_preview_frame", 0);
+    }
   }
 
   for (const auto& request : requests) {
     if (request.inputBuffer.streamId != -1) {
+      ALOGI("%s: reprocess_frame %d request received", __FUNCTION__,
+            request.frameNumber);
       ATRACE_ASYNC_BEGIN("reprocess_frame", request.frameNumber);
       aidl_profiler_->ReprocessingRequestStart(
           device_session_->GetProfiler(
@@ -825,6 +837,15 @@ ndk::ScopedAStatus AidlCameraDeviceSession::flush() {
   return ndk::ScopedAStatus::ok();
 }
 
+ndk::ScopedAStatus AidlCameraDeviceSession::repeatingRequestEnd(
+    int32_t in_frameNumber, const std::vector<int32_t>& in_streamIds) {
+  ATRACE_NAME("AidlCameraDeviceSession::repeatingRequestEnd");
+  if (device_session_ != nullptr) {
+    device_session_->RepeatingRequestEnd(in_frameNumber, in_streamIds);
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
 ndk::ScopedAStatus AidlCameraDeviceSession::close() {
   ATRACE_NAME("AidlCameraDeviceSession::close");
   if (device_session_ != nullptr) {
diff --git a/common/hal/aidl_service/aidl_camera_device_session.h b/common/hal/aidl_service/aidl_camera_device_session.h
index 1cec9f3..8d6539a 100644
--- a/common/hal/aidl_service/aidl_camera_device_session.h
+++ b/common/hal/aidl_service/aidl_camera_device_session.h
@@ -108,10 +108,7 @@ class AidlCameraDeviceSession
           aidl_return) override;
 
   ndk::ScopedAStatus repeatingRequestEnd(
-      int32_t /*in_frameNumber*/,
-      const std::vector<int32_t>& /*in_streamIds*/) override {
-    return ndk::ScopedAStatus::ok();
-  };
+      int32_t in_frameNumber, const std::vector<int32_t>& in_streamIds) override;
 
   ndk::ScopedAStatus configureStreamsV2(
       const aidl::android::hardware::camera::device::StreamConfiguration&,
diff --git a/common/hal/google_camera_hal/Android.bp b/common/hal/google_camera_hal/Android.bp
index 7910d90..7ef7f3e 100644
--- a/common/hal/google_camera_hal/Android.bp
+++ b/common/hal/google_camera_hal/Android.bp
@@ -38,6 +38,22 @@ gch_hal_cc_defaults {
     },
 }
 
+aconfig_declarations {
+    name: "libgooglecamerahal_flags",
+    package: "libgooglecamerahal.flags",
+    container: "vendor",
+    srcs: ["libgooglecamerahal_flags.aconfig"],
+}
+
+cc_aconfig_library {
+    name: "libgooglecamerahal_flags_cc_lib",
+    aconfig_declarations: "libgooglecamerahal_flags",
+    defaults: ["google_camera_hal_defaults"],
+    host_supported: true,
+    owner: "google",
+    vendor: true,
+}
+
 cc_library_shared {
     name: "libgooglecamerahal",
     defaults: [
@@ -60,20 +76,10 @@ cc_library_shared {
         "camera_provider.cc",
         "capture_session_utils.cc",
         "capture_session_wrapper_process_block.cc",
-        "depth_process_block.cc",
-        "dual_ir_capture_session.cc",
-        "dual_ir_depth_result_processor.cc",
-        "dual_ir_request_processor.cc",
-        "dual_ir_result_request_processor.cc",
-        "hdrplus_capture_session.cc",
         "pending_requests_tracker.cc",
         "realtime_zsl_request_processor.cc",
         "realtime_zsl_result_processor.cc",
         "realtime_zsl_result_request_processor.cc",
-        "rgbird_capture_session.cc",
-        "rgbird_depth_result_processor.cc",
-        "rgbird_result_request_processor.cc",
-        "rgbird_rt_request_processor.cc",
         "snapshot_request_processor.cc",
         "snapshot_result_processor.cc",
         "vendor_tags.cc",
@@ -84,6 +90,7 @@ cc_library_shared {
         "libbase",
         "libcamera_metadata",
         "libcutils",
+        "libgooglecamerahal_flags_cc_lib",
         "libgooglecamerahalutils",
         "libhidlbase",
         "liblog",
@@ -93,7 +100,6 @@ cc_library_shared {
         "libsync",
     ],
     header_libs: [
-        "lib_depth_generator_headers",
         "libgooglecamerahal_headers",
     ],
     // b/129863492, clang-tidy nondeterministic seg fault
diff --git a/common/hal/google_camera_hal/basic_capture_session.cc b/common/hal/google_camera_hal/basic_capture_session.cc
index 58bbdce..f77c6fb 100644
--- a/common/hal/google_camera_hal/basic_capture_session.cc
+++ b/common/hal/google_camera_hal/basic_capture_session.cc
@@ -300,6 +300,14 @@ status_t BasicCaptureSession::Flush() {
   return request_processor_->Flush();
 }
 
+void BasicCaptureSession::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  if (request_processor_ != nullptr) {
+    return request_processor_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 void BasicCaptureSession::ProcessCaptureResult(
     std::unique_ptr<CaptureResult> result) {
   result_dispatcher_->AddResult(std::move(result));
diff --git a/common/hal/google_camera_hal/basic_capture_session.h b/common/hal/google_camera_hal/basic_capture_session.h
index 64e98f1..3f58a9f 100644
--- a/common/hal/google_camera_hal/basic_capture_session.h
+++ b/common/hal/google_camera_hal/basic_capture_session.h
@@ -17,6 +17,8 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_BASIC_CAPTURE_SESSION_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_BASIC_CAPTURE_SESSION_H_
 
+#include <vector>
+
 #include "camera_buffer_allocator_hwl.h"
 #include "camera_device_session_hwl.h"
 #include "capture_session.h"
@@ -71,6 +73,9 @@ class BasicCaptureSession : public CaptureSession {
   status_t Flush() override;
   // Override functions in CaptureSession end.
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
  protected:
   BasicCaptureSession() = default;
 
diff --git a/common/hal/google_camera_hal/basic_request_processor.cc b/common/hal/google_camera_hal/basic_request_processor.cc
index 06beb5d..56f4ab6 100644
--- a/common/hal/google_camera_hal/basic_request_processor.cc
+++ b/common/hal/google_camera_hal/basic_request_processor.cc
@@ -14,14 +14,14 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_BasicRequestProcessor"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
+#include "basic_request_processor.h"
+
 #include <log/log.h>
 #include <utils/Trace.h>
 
-#include "basic_request_processor.h"
-
 namespace android {
 namespace google_camera_hal {
 
@@ -126,5 +126,14 @@ status_t BasicRequestProcessor::Flush() {
   return process_block_->Flush();
 }
 
+void BasicRequestProcessor::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(process_block_shared_lock_);
+  if (process_block_ != nullptr) {
+    process_block_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 }  // namespace google_camera_hal
 }  // namespace android
diff --git a/common/hal/google_camera_hal/basic_request_processor.h b/common/hal/google_camera_hal/basic_request_processor.h
index 0b46421..cce5199 100644
--- a/common/hal/google_camera_hal/basic_request_processor.h
+++ b/common/hal/google_camera_hal/basic_request_processor.h
@@ -18,6 +18,7 @@
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_BASIC_REQUEST_PROCESSOR_H_
 
 #include <shared_mutex>
+#include <vector>
 
 #include "process_block.h"
 #include "request_processor.h"
@@ -48,6 +49,9 @@ class BasicRequestProcessor : public RequestProcessor {
   status_t ProcessRequest(const CaptureRequest& request) override;
 
   status_t Flush() override;
+
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
   // Override functions of RequestProcessor end.
 
  protected:
diff --git a/common/hal/google_camera_hal/camera_device.cc b/common/hal/google_camera_hal/camera_device.cc
index 8eb3ec2..067d344 100644
--- a/common/hal/google_camera_hal/camera_device.cc
+++ b/common/hal/google_camera_hal/camera_device.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_CameraDevice"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
 #include "camera_device.h"
@@ -30,6 +30,8 @@
 
 #include <thread>
 
+#include "hwl_types.h"
+#include "log/log_main.h"
 #include "utils.h"
 #include "vendor_tags.h"
 
@@ -37,10 +39,17 @@ using android::meminfo::ProcMemInfo;
 using namespace android::meminfo;
 
 namespace android {
+namespace {
+enum class PreloadMode {
+  kMadvise = 0,
+  kMlockMadvise = 1,
+};
+}  // namespace
 
 void MadviseFileForRange(size_t madvise_size_limit_bytes, size_t map_size_bytes,
                          const uint8_t* map_begin, const uint8_t* map_end,
-                         const std::string& file_name) {
+                         const std::string& file_name,
+                         PreloadMode preload_mode) {
   // Ideal blockTransferSize for madvising files (128KiB)
   static const size_t kIdealIoTransferSizeBytes = 128 * 1024;
   size_t target_size_bytes =
@@ -49,7 +58,15 @@ void MadviseFileForRange(size_t madvise_size_limit_bytes, size_t map_size_bytes,
     return;
   }
   std::string trace_tag =
-      "madvising " + file_name + " size=" + std::to_string(target_size_bytes);
+      file_name + " size=" + std::to_string(target_size_bytes);
+  if (preload_mode == PreloadMode::kMadvise) {
+    trace_tag = "madvising " + trace_tag;
+  } else if (preload_mode == PreloadMode::kMlockMadvise) {
+    trace_tag = "madvising and mlocking " + trace_tag;
+  } else {
+    trace_tag = "Unknown preload mode " + trace_tag;
+    ALOGE("%s: Unknown preload mode %d", __FUNCTION__, preload_mode);
+  }
   ATRACE_NAME(trace_tag.c_str());
   // Based on requested size (target_size_bytes)
   const uint8_t* target_pos = map_begin + target_size_bytes;
@@ -72,36 +89,75 @@ void MadviseFileForRange(size_t madvise_size_limit_bytes, size_t map_size_bytes,
     size_t madvise_length =
         std::min(kIdealIoTransferSizeBytes,
                  static_cast<size_t>(target_pos - madvise_start));
-    int status = madvise(madvise_addr, madvise_length, MADV_WILLNEED);
+    if (preload_mode == PreloadMode::kMlockMadvise) {
+      int status_mlock = mlock(madvise_addr, madvise_length);
+      // In case of error we stop mlocking rest of the file
+      if (status_mlock < 0) {
+        ALOGW(
+            "%s: Pinning memory by mlock failed! status=%i, errno=%i, "
+            "trace_tag=%s",
+            __FUNCTION__, status_mlock, errno, trace_tag.c_str());
+        break;
+      }
+    }
+    int status_madvise = madvise(madvise_addr, madvise_length, MADV_WILLNEED);
     // In case of error we stop madvising rest of the file
-    if (status < 0) {
+    if (status_madvise < 0) {
       break;
     }
   }
 }
 
-static void ReadAheadVma(const Vma& vma, const size_t madvise_size_limit_bytes) {
+static void ReadAheadVma(const Vma& vma, const size_t madvise_size_limit_bytes,
+                         PreloadMode preload_mode) {
   const uint8_t* map_begin = reinterpret_cast<uint8_t*>(vma.start);
   const uint8_t* map_end = reinterpret_cast<uint8_t*>(vma.end);
   MadviseFileForRange(madvise_size_limit_bytes,
                       static_cast<size_t>(map_end - map_begin), map_begin,
-                      map_end, vma.name);
+                      map_end, vma.name, preload_mode);
+}
+
+static void UnpinVma(const Vma& vma) {
+  std::string trace_tag =
+      "munlocking " + vma.name + " size=" + std::to_string(vma.end - vma.start);
+  ATRACE_NAME(trace_tag.c_str());
+  int status_munlock =
+      munlock(reinterpret_cast<uint8_t*>(vma.start), vma.end - vma.start);
+  if (status_munlock < 0) {
+    ALOGW(
+        "%s: Unlocking memory failed! status=%i, errno=%i, "
+        "trace_tag=%s",
+        __FUNCTION__, status_munlock, errno, trace_tag.c_str());
+  }
 }
 
-static void LoadLibraries(const std::vector<std::string>* libs) {
-  auto vmaCollectorCb = [&libs](const Vma& vma) {
-    const static size_t kMadviseSizeLimitBytes =
-        std::numeric_limits<size_t>::max();
+// Update memory configuration to match the new configuration. This includes
+// pinning new libraries, unpinning libraries that were pinned in the old
+// config but aren't any longer, and madvising anonymous VMAs.
+static void LoadLibraries(google_camera_hal::HwlMemoryConfig memory_config,
+                          google_camera_hal::HwlMemoryConfig old_memory_config) {
+  auto vmaCollectorCb = [&memory_config, &old_memory_config](const Vma& vma) {
     // Read ahead for anonymous VMAs and for specific files.
     // vma.flags represents a VMAs rwx bits.
     if (vma.inode == 0 && !vma.is_shared && vma.flags) {
-      ReadAheadVma(vma, kMadviseSizeLimitBytes);
-    } else if (vma.inode != 0 && libs != nullptr &&
-               std::any_of(libs->begin(), libs->end(),
-                           [&vma](std::string lib_name) {
-                             return lib_name.compare(vma.name) == 0;
-                           })) {
-      ReadAheadVma(vma, kMadviseSizeLimitBytes);
+      if (memory_config.madvise_map_size_limit_bytes == 0) {
+        return true;
+      }
+      // Madvise anonymous memory, do not pin.
+      ReadAheadVma(vma, memory_config.madvise_map_size_limit_bytes,
+                   PreloadMode::kMadvise);
+      return true;
+    }
+    if (memory_config.pinned_libraries.contains(vma.name) &&
+        !old_memory_config.pinned_libraries.contains(vma.name)) {
+      // File-backed VMAs do not have a madvise limit
+      ReadAheadVma(vma, std::numeric_limits<size_t>::max(),
+                   PreloadMode::kMlockMadvise);
+    } else if (!memory_config.pinned_libraries.contains(vma.name) &&
+               old_memory_config.pinned_libraries.contains(vma.name)) {
+      // Unpin libraries that were previously pinned but are no longer needed.
+      ALOGI("%s: Unpinning %s", __FUNCTION__, vma.name.c_str());
+      UnpinVma(vma);
     }
     return true;
   };
@@ -122,10 +178,12 @@ constexpr char kExternalCaptureSessionDir[] =
 #endif
 #endif
 
+HwlMemoryConfig CameraDevice::applied_memory_config_;
+std::mutex CameraDevice::applied_memory_config_mutex_;
+
 std::unique_ptr<CameraDevice> CameraDevice::Create(
     std::unique_ptr<CameraDeviceHwl> camera_device_hwl,
-    CameraBufferAllocatorHwl* camera_allocator_hwl,
-    const std::vector<std::string>* configure_streams_libs) {
+    CameraBufferAllocatorHwl* camera_allocator_hwl) {
   ATRACE_CALL();
   auto device = std::unique_ptr<CameraDevice>(new CameraDevice());
 
@@ -144,7 +202,17 @@ std::unique_ptr<CameraDevice> CameraDevice::Create(
 
   ALOGI("%s: Created a camera device for public(%u)", __FUNCTION__,
         device->GetPublicCameraId());
-  device->configure_streams_libs_ = configure_streams_libs;
+
+  android::google_camera_hal::HwlMemoryConfig memory_config =
+      device->camera_device_hwl_->GetMemoryConfig();
+  memory_config.madvise_map_size_limit_bytes = 0;
+  ALOGI("Pinning memory for %zu shared libraries.",
+        memory_config.pinned_libraries.size());
+
+  std::lock_guard<std::mutex> lock(applied_memory_config_mutex_);
+  std::thread t(LoadLibraries, memory_config, device->GetAppliedMemoryConfig());
+  t.detach();
+  device->SetAppliedMemoryConfig(memory_config);
 
   return device;
 }
@@ -360,7 +428,10 @@ status_t CameraDevice::CreateCameraDeviceSession(
     return UNKNOWN_ERROR;
   }
 
-  std::thread t(LoadLibraries, configure_streams_libs_);
+  std::lock_guard<std::mutex> lock(applied_memory_config_mutex_);
+  HwlMemoryConfig memory_config = camera_device_hwl_->GetMemoryConfig();
+  std::thread t(LoadLibraries, memory_config, GetAppliedMemoryConfig());
+  SetAppliedMemoryConfig(memory_config);
   t.detach();
 
   return OK;
diff --git a/common/hal/google_camera_hal/camera_device.h b/common/hal/google_camera_hal/camera_device.h
index 359893e..cfbd04d 100644
--- a/common/hal/google_camera_hal/camera_device.h
+++ b/common/hal/google_camera_hal/camera_device.h
@@ -23,6 +23,7 @@
 #include "camera_device_hwl.h"
 #include "camera_device_session.h"
 #include "hal_camera_metadata.h"
+#include "hwl_types.h"
 #include "profiler.h"
 
 namespace android {
@@ -39,8 +40,7 @@ class CameraDevice {
   // lifetime of CameraDevice
   static std::unique_ptr<CameraDevice> Create(
       std::unique_ptr<CameraDeviceHwl> camera_device_hwl,
-      CameraBufferAllocatorHwl* camera_allocator_hwl = nullptr,
-      const std::vector<std::string>* configure_streams_libs = nullptr);
+      CameraBufferAllocatorHwl* camera_allocator_hwl = nullptr);
 
   virtual ~CameraDevice();
 
@@ -106,6 +106,17 @@ class CameraDevice {
     return public_camera_id_;
   };
 
+  // Get the applied memory config for this camera device.
+  HwlMemoryConfig GetAppliedMemoryConfig() {
+    HwlMemoryConfig memory_config = applied_memory_config_;
+    return memory_config;
+  }
+
+  // Set the applied memory config for this camera device.
+  void SetAppliedMemoryConfig(HwlMemoryConfig memory_config) {
+    applied_memory_config_ = memory_config;
+  }
+
   // Query whether a particular streams configuration is supported.
   // stream_config: It contains the stream info and a set of features, which are
   // described in the form of session settings.
@@ -128,6 +139,9 @@ class CameraDevice {
   status_t Initialize(std::unique_ptr<CameraDeviceHwl> camera_device_hwl,
                       CameraBufferAllocatorHwl* camera_allocator_hwl);
 
+  static HwlMemoryConfig applied_memory_config_;
+  static std::mutex applied_memory_config_mutex_;
+
   uint32_t public_camera_id_ = 0;
 
   std::unique_ptr<CameraDeviceHwl> camera_device_hwl_;
@@ -140,8 +154,6 @@ class CameraDevice {
   std::vector<void*> external_capture_session_lib_handles_;
   // Stream use cases supported by this camera device
   std::map<uint32_t, std::set<int64_t>> camera_id_to_stream_use_cases_;
-
-  const std::vector<std::string>* configure_streams_libs_ = nullptr;
 };
 
 }  // namespace google_camera_hal
diff --git a/common/hal/google_camera_hal/camera_device_session.cc b/common/hal/google_camera_hal/camera_device_session.cc
index 7784567..22e0a3d 100644
--- a/common/hal/google_camera_hal/camera_device_session.cc
+++ b/common/hal/google_camera_hal/camera_device_session.cc
@@ -21,15 +21,13 @@
 
 #include <inttypes.h>
 #include <log/log.h>
+#include <system/graphics-base-v1.0.h>
 #include <utils/Trace.h>
 
 #include "basic_capture_session.h"
 #include "capture_session_utils.h"
-#include "dual_ir_capture_session.h"
 #include "hal_types.h"
 #include "hal_utils.h"
-#include "hdrplus_capture_session.h"
-#include "rgbird_capture_session.h"
 #include "system/camera_metadata.h"
 #include "ui/GraphicBufferMapper.h"
 #include "vendor_tag_defs.h"
@@ -48,16 +46,6 @@ static constexpr int64_t kAllocationThreshold = 33000000;  // 33ms
 
 std::vector<CaptureSessionEntryFuncs>
     CameraDeviceSession::kCaptureSessionEntries = {
-        {.IsStreamConfigurationSupported =
-             HdrplusCaptureSession::IsStreamConfigurationSupported,
-         .CreateSession = HdrplusCaptureSession::Create},
-        {.IsStreamConfigurationSupported =
-             RgbirdCaptureSession::IsStreamConfigurationSupported,
-         .CreateSession = RgbirdCaptureSession::Create},
-        {.IsStreamConfigurationSupported =
-             DualIrCaptureSession::IsStreamConfigurationSupported,
-         .CreateSession = DualIrCaptureSession::Create},
-        // BasicCaptureSession is supposed to be the last resort.
         {.IsStreamConfigurationSupported =
              BasicCaptureSession::IsStreamConfigurationSupported,
          .CreateSession = BasicCaptureSession::Create}};
@@ -1564,6 +1552,15 @@ status_t CameraDeviceSession::Flush() {
   return res;
 }
 
+void CameraDeviceSession::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(capture_session_lock_);
+  if (capture_session_ != nullptr) {
+    capture_session_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 void CameraDeviceSession::AppendOutputIntentToSettingsLocked(
     const CaptureRequest& request, CaptureRequest* updated_request) {
   if (updated_request == nullptr || updated_request->settings == nullptr) {
@@ -1687,11 +1684,15 @@ status_t CameraDeviceSession::RegisterStreamsIntoCacheManagerLocked(
     uint64_t producer_usage = 0;
     uint64_t consumer_usage = 0;
     int32_t stream_id = -1;
+    android_pixel_format_t stream_format = stream.format;
     for (auto& hal_stream : hal_streams) {
       if (hal_stream.id == stream.id) {
         producer_usage = hal_stream.producer_usage;
         consumer_usage = hal_stream.consumer_usage;
         stream_id = hal_stream.id;
+        if (stream_format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) {
+          stream_format = hal_stream.override_format;
+        }
       }
     }
     if (stream_id == -1) {
@@ -1751,7 +1752,7 @@ status_t CameraDeviceSession::RegisterStreamsIntoCacheManagerLocked(
                                          .stream_id = stream_id,
                                          .width = stream.width,
                                          .height = stream.height,
-                                         .format = stream.format,
+                                         .format = stream_format,
                                          .producer_flags = producer_usage,
                                          .consumer_flags = consumer_usage,
                                          .num_buffers_to_cache = 1};
diff --git a/common/hal/google_camera_hal/camera_device_session.h b/common/hal/google_camera_hal/camera_device_session.h
index f7fdf3d..8dccacb 100644
--- a/common/hal/google_camera_hal/camera_device_session.h
+++ b/common/hal/google_camera_hal/camera_device_session.h
@@ -17,11 +17,11 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_CAMERA_DEVICE__SESSION_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_CAMERA_DEVICE__SESSION_H_
 
+#include <map>
 #include <memory>
 #include <set>
 #include <shared_mutex>
 #include <vector>
-#include <map>
 
 #include "camera_buffer_allocator_hwl.h"
 #include "camera_device_session_hwl.h"
@@ -118,6 +118,9 @@ class CameraDeviceSession {
   // Flush all pending requests.
   status_t Flush();
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids);
+
   // Check reconfiguration is required or not
   // old_session is old session parameter
   // new_session is new session parameter
diff --git a/common/hal/google_camera_hal/camera_provider.cc b/common/hal/google_camera_hal/camera_provider.cc
index 30e184d..9d5dba8 100644
--- a/common/hal/google_camera_hal/camera_provider.cc
+++ b/common/hal/google_camera_hal/camera_provider.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_CameraProvider"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
 #include "camera_provider.h"
@@ -23,9 +23,6 @@
 #include <log/log.h>
 #include <utils/Trace.h>
 
-#if !GCH_HWL_USE_DLOPEN
-#include "lyric_hwl/madvise_library_list.h"
-#endif
 #include "vendor_tag_defs.h"
 #include "vendor_tag_utils.h"
 
@@ -280,17 +277,8 @@ status_t CameraProvider::CreateCameraDevice(
     return res;
   }
 
-  const std::vector<std::string>* configure_streams_libs = nullptr;
-
-#if GCH_HWL_USE_DLOPEN
-  configure_streams_libs = reinterpret_cast<decltype(configure_streams_libs)>(
-      dlsym(hwl_lib_handle_, "configure_streams_libraries"));
-#else
-  configure_streams_libs = &configure_streams_libraries;
-#endif
-  *device =
-      CameraDevice::Create(std::move(camera_device_hwl),
-                           camera_allocator_hwl_.get(), configure_streams_libs);
+  *device = CameraDevice::Create(
+      std::move(camera_device_hwl), camera_allocator_hwl_.get());
   if (*device == nullptr) {
     return NO_INIT;
   }
diff --git a/common/hal/google_camera_hal/capture_session_wrapper_process_block.cc b/common/hal/google_camera_hal/capture_session_wrapper_process_block.cc
index 74e1eda..7805ed3 100644
--- a/common/hal/google_camera_hal/capture_session_wrapper_process_block.cc
+++ b/common/hal/google_camera_hal/capture_session_wrapper_process_block.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #include <cstddef>
 #include <memory>
 
@@ -202,5 +202,14 @@ status_t CaptureSessionWrapperProcessBlock::Flush() {
   return camera_device_session_hwl_->Flush();
 }
 
+void CaptureSessionWrapperProcessBlock::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(configure_shared_mutex_);
+  if (is_configured_) {
+    camera_device_session_hwl_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 }  // namespace google_camera_hal
 }  // namespace android
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/capture_session_wrapper_process_block.h b/common/hal/google_camera_hal/capture_session_wrapper_process_block.h
index ea870a3..275e3e1 100644
--- a/common/hal/google_camera_hal/capture_session_wrapper_process_block.h
+++ b/common/hal/google_camera_hal/capture_session_wrapper_process_block.h
@@ -18,6 +18,7 @@
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_CAPTURE_SESSION_WRAPPER_PROCESS_BLOCK_H_
 
 #include <shared_mutex>
+#include <vector>
 
 #include "camera_device_session.h"
 #include "capture_session.h"
@@ -63,6 +64,9 @@ class CaptureSessionWrapperProcessBlock : public ProcessBlock {
   status_t Flush() override;
   // Override functions of ProcessBlock end.
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
  protected:
   CaptureSessionWrapperProcessBlock(
       const std::vector<ExternalCaptureSessionFactory*>&
diff --git a/common/hal/google_camera_hal/depth_process_block.cc b/common/hal/google_camera_hal/depth_process_block.cc
deleted file mode 100644
index 11f61bd..0000000
--- a/common/hal/google_camera_hal/depth_process_block.cc
+++ /dev/null
@@ -1,900 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//#define LOG_NDEBUG 0
-#define LOG_TAG "GCH_DepthProcessBlock"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include <cutils/properties.h>
-#include <hardware/gralloc1.h>
-#include <log/log.h>
-#include <sys/mman.h>
-#include <utils/Trace.h>
-
-#include <dlfcn.h>
-
-#include "depth_process_block.h"
-#include "hal_types.h"
-#include "hal_utils.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-#if GCH_HWL_USE_DLOPEN
-static std::string kDepthGeneratorLib = "/vendor/lib64/libdepthgenerator.so";
-using android::depth_generator::CreateDepthGenerator_t;
-#endif
-const float kSmallOffset = 0.01f;
-
-std::unique_ptr<DepthProcessBlock> DepthProcessBlock::Create(
-    CameraDeviceSessionHwl* device_session_hwl,
-    HwlRequestBuffersFunc request_stream_buffers,
-    const DepthProcessBlockCreateData& create_data) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return nullptr;
-  }
-
-  auto block = std::unique_ptr<DepthProcessBlock>(
-      new DepthProcessBlock(request_stream_buffers, create_data));
-  if (block == nullptr) {
-    ALOGE("%s: Creating DepthProcessBlock failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  status_t res = block->InitializeBufferManagementStatus(device_session_hwl);
-  if (res != OK) {
-    ALOGE("%s: Failed to initialize HAL Buffer Management status.",
-          __FUNCTION__);
-    return nullptr;
-  }
-
-  res = block->CalculateActiveArraySizeRatio(device_session_hwl);
-  if (res != OK) {
-    ALOGE("%s: Calculating active array size ratio failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  block->force_internal_stream_ =
-      property_get_bool("persist.vendor.camera.rgbird.forceinternal", false);
-  if (block->force_internal_stream_) {
-    ALOGI("%s: Force creating internal streams for IR pipelines", __FUNCTION__);
-  }
-
-  block->pipelined_depth_engine_enabled_ = property_get_bool(
-      "persist.vendor.camera.frontdepth.enablepipeline", true);
-
-  // TODO(b/129910835): Change the controlling prop into some deterministic
-  // logic that controls when the front depth autocal will be triggered.
-  // depth_process_block does not control autocal in current implementation.
-  // Whenever there is a YUV buffer in the process block request, it will
-  // trigger the AutoCal. So the condition is completely controlled by
-  // rt_request_processor and result_request_processor.
-  block->rgb_ir_auto_cal_enabled_ =
-      property_get_bool("vendor.camera.frontdepth.enableautocal", true);
-  block->device_session_hwl_ = device_session_hwl;
-  return block;
-}
-
-status_t DepthProcessBlock::InitializeBufferManagementStatus(
-    CameraDeviceSessionHwl* device_session_hwl) {
-  // Query characteristics to check if buffer management supported
-  std::unique_ptr<google_camera_hal::HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: Get camera characteristics failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  camera_metadata_ro_entry entry = {};
-  res = characteristics->Get(ANDROID_INFO_SUPPORTED_BUFFER_MANAGEMENT_VERSION,
-                             &entry);
-  if (res == OK && entry.count > 0) {
-    buffer_management_used_ =
-        (entry.data.u8[0] ==
-         ANDROID_INFO_SUPPORTED_BUFFER_MANAGEMENT_VERSION_HIDL_DEVICE_3_5);
-    session_buffer_management_supported_ =
-        (entry.data.u8[0] ==
-         ANDROID_INFO_SUPPORTED_BUFFER_MANAGEMENT_VERSION_SESSION_CONFIGURABLE);
-  }
-
-  return OK;
-}
-
-DepthProcessBlock::DepthProcessBlock(
-    HwlRequestBuffersFunc request_stream_buffers,
-    const DepthProcessBlockCreateData& create_data)
-    : request_stream_buffers_(request_stream_buffers),
-      rgb_internal_yuv_stream_id_(create_data.rgb_internal_yuv_stream_id),
-      ir1_internal_raw_stream_id_(create_data.ir1_internal_raw_stream_id),
-      ir2_internal_raw_stream_id_(create_data.ir2_internal_raw_stream_id) {
-}
-
-DepthProcessBlock::~DepthProcessBlock() {
-  ATRACE_CALL();
-  depth_generator_ = nullptr;
-
-  if (depth_generator_lib_handle_ != nullptr) {
-    dlclose(depth_generator_lib_handle_);
-    depth_generator_lib_handle_ = nullptr;
-  }
-}
-
-status_t DepthProcessBlock::SetResultProcessor(
-    std::unique_ptr<ResultProcessor> result_processor) {
-  ATRACE_CALL();
-  if (result_processor == nullptr) {
-    ALOGE("%s: result_processor is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(result_processor_lock_);
-  if (result_processor_ != nullptr) {
-    ALOGE("%s: result_processor_ was already set.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  result_processor_ = std::move(result_processor);
-  return OK;
-}
-
-status_t DepthProcessBlock::GetStreamBufferSize(const Stream& stream,
-                                                int32_t* buffer_size) {
-  ATRACE_CALL();
-  // TODO(b/130764929): Use actual gralloc buffer stride instead of stream dim
-  switch (stream.format) {
-    case HAL_PIXEL_FORMAT_Y8:
-      *buffer_size = stream.width * stream.height;
-      break;
-    case HAL_PIXEL_FORMAT_Y16:
-      *buffer_size = stream.width * stream.height * 2;
-      break;
-    case HAL_PIXEL_FORMAT_YCBCR_420_888:
-      *buffer_size = static_cast<int32_t>(stream.width * stream.height * 1.5);
-      break;
-    default:
-      ALOGW("%s: Unsupported format:%d", __FUNCTION__, stream.format);
-      *buffer_size = 0;
-      break;
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::ConfigureStreams(
-    const StreamConfiguration& stream_config,
-    const StreamConfiguration& /*overall_config*/) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (is_configured_) {
-    ALOGE("%s: Already configured.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  if (force_internal_stream_) {
-    // Nothing to configure if this is force internal mode
-    ALOGV("%s: Force internal enabled, skip depth block config.", __FUNCTION__);
-    is_configured_ = true;
-    return OK;
-  }
-
-  uint32_t num_depth_stream = 0;
-  for (auto& stream : stream_config.streams) {
-    if (utils::IsDepthStream(stream)) {
-      num_depth_stream++;
-      // Save depth stream as HAL configured stream
-      depth_stream_.id = stream.id;
-      depth_stream_.override_format = stream.format;
-      depth_stream_.producer_usage = GRALLOC1_PRODUCER_USAGE_CAMERA;
-      depth_stream_.consumer_usage = 0;
-      depth_stream_.max_buffers = kDepthStreamMaxBuffers;
-      depth_stream_.override_data_space = stream.data_space;
-      depth_stream_.is_physical_camera_stream = false;
-      depth_stream_.physical_camera_id = 0;
-    }
-
-    // Save stream information for mapping purposes
-    depth_io_streams_[stream.id] = stream;
-    int32_t buffer_size = 0;
-    status_t res = GetStreamBufferSize(stream, &buffer_size);
-    if (res != OK) {
-      ALOGE("%s: Failed to get stream buffer size.", __FUNCTION__);
-      return res;
-    }
-    stream_buffer_sizes_[stream.id] = buffer_size;
-  }
-
-  if (num_depth_stream != 1) {
-    ALOGE(
-        "%s: Depth Process Block can only config 1 depth stream. There are "
-        "%zu streams, including %u depth stream.",
-        __FUNCTION__, stream_config.streams.size(), num_depth_stream);
-    return BAD_VALUE;
-  }
-
-  if (depth_generator_ == nullptr) {
-    status_t res = LoadDepthGenerator(&depth_generator_);
-    if (res != OK) {
-      ALOGE("%s: Creating DepthGenerator failed.", __FUNCTION__);
-      return NO_INIT;
-    }
-
-    if (pipelined_depth_engine_enabled_ == true) {
-      auto depth_result_callback =
-          android::depth_generator::DepthResultCallbackFunction(
-              [this](DepthResultStatus result_status, uint32_t frame_number) {
-                status_t res = ProcessDepthResult(result_status, frame_number);
-                if (res != OK) {
-                  ALOGE("%s: Failed to process the depth result for frame %d.",
-                        __FUNCTION__, frame_number);
-                }
-              });
-      ALOGI("%s: Async depth api is used. Callback func is set.", __FUNCTION__);
-      depth_generator_->SetResultCallback(depth_result_callback);
-    } else {
-      ALOGI("%s: Blocking depth api is used.", __FUNCTION__);
-      depth_generator_->SetResultCallback(nullptr);
-    }
-  }
-  if (session_buffer_management_supported_ &&
-      device_session_hwl_->configure_streams_v2()) {
-    hal_buffer_managed_streams_ =
-        device_session_hwl_->GetHalBufferManagedStreams(stream_config);
-  }
-  is_configured_ = true;
-  return OK;
-}
-
-status_t DepthProcessBlock::GetConfiguredHalStreams(
-    std::vector<HalStream>* hal_streams) const {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (hal_streams == nullptr) {
-    ALOGE("%s: hal_streams is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  if (!is_configured_) {
-    ALOGE("%s: Not configured yet.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  hal_streams->push_back(depth_stream_);
-
-  return OK;
-}
-
-status_t DepthProcessBlock::SubmitBlockingDepthRequest(
-    const DepthRequestInfo& request_info) {
-  ALOGV("%s: [ud] ExecuteProcessRequest for frame %d", __FUNCTION__,
-        request_info.frame_number);
-
-  status_t res = depth_generator_->ExecuteProcessRequest(request_info);
-  if (res != OK) {
-    ALOGE("%s: Depth generator fails to process frame %d.", __FUNCTION__,
-          request_info.frame_number);
-    return res;
-  }
-
-  res = ProcessDepthResult(DepthResultStatus::kOk, request_info.frame_number);
-  if (res != OK) {
-    ALOGE("%s: Failed to process depth result.", __FUNCTION__);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::SubmitAsyncDepthRequest(
-    const DepthRequestInfo& request_info) {
-  std::unique_lock<std::mutex> lock(depth_generator_api_lock_);
-  ALOGV("%s: [ud] ExecuteProcessRequest for frame %d", __FUNCTION__,
-        request_info.frame_number);
-  status_t res = depth_generator_->EnqueueProcessRequest(request_info);
-  if (res != OK) {
-    ALOGE("%s: Failed to enqueue depth request.", __FUNCTION__);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::ProcessDepthResult(DepthResultStatus result_status,
-                                               uint32_t frame_number) {
-  std::unique_lock<std::mutex> lock(depth_generator_api_lock_);
-  ALOGV("%s: [ud] Depth result for frame %u notified.", __FUNCTION__,
-        frame_number);
-
-  status_t res = UnmapDepthRequestBuffers(frame_number);
-  if (res != OK) {
-    ALOGE("%s: Failed to clean up the depth request info.", __FUNCTION__);
-    return res;
-  }
-
-  auto capture_result = std::make_unique<CaptureResult>();
-  if (capture_result == nullptr) {
-    ALOGE("%s: Creating capture_result failed.", __FUNCTION__);
-    return NO_MEMORY;
-  }
-
-  CaptureRequest request;
-  {
-    std::lock_guard<std::mutex> pending_request_lock(pending_requests_mutex_);
-    if (pending_depth_requests_.find(frame_number) ==
-        pending_depth_requests_.end()) {
-      ALOGE("%s: Frame %u does not exist in pending requests list.",
-            __FUNCTION__, frame_number);
-    } else {
-      auto& request = pending_depth_requests_[frame_number].request;
-      capture_result->frame_number = frame_number;
-      capture_result->output_buffers = request.output_buffers;
-
-      // In case the depth engine fails to process a depth request, mark the
-      // buffer as in error state.
-      if (result_status != DepthResultStatus::kOk) {
-        for (auto& stream_buffer : capture_result->output_buffers) {
-          if (stream_buffer.stream_id == depth_stream_.id) {
-            stream_buffer.status = BufferStatus::kError;
-          }
-        }
-      }
-
-      capture_result->input_buffers = request.input_buffers;
-      pending_depth_requests_.erase(frame_number);
-    }
-  }
-
-  ProcessBlockResult block_result = {.request_id = 0,
-                                     .result = std::move(capture_result)};
-  {
-    std::lock_guard<std::mutex> lock(result_processor_lock_);
-    result_processor_->ProcessResult(std::move(block_result));
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::ProcessRequests(
-    const std::vector<ProcessBlockRequest>& process_block_requests,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  if (force_internal_stream_) {
-    // Nothing to configure if this is force internal mode
-    ALOGE("%s: Force internal ON, Depth PB should not process request.",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (!is_configured_) {
-    ALOGE("%s: block is not configured.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  if (process_block_requests.size() != 1) {
-    ALOGE("%s: Only a single request is supported but there are %zu",
-          __FUNCTION__, process_block_requests.size());
-    return BAD_VALUE;
-  }
-
-  {
-    std::lock_guard<std::mutex> lock(result_processor_lock_);
-    if (result_processor_ == nullptr) {
-      ALOGE("%s: result processor was not set.", __FUNCTION__);
-      return NO_INIT;
-    }
-
-    status_t res = result_processor_->AddPendingRequests(
-        process_block_requests, remaining_session_request);
-    if (res != OK) {
-      ALOGE("%s: Adding a pending request to result processor failed: %s(%d)",
-            __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-  }
-
-  auto& request = process_block_requests[0].request;
-  DepthRequestInfo request_info;
-  request_info.frame_number = request.frame_number;
-  std::unique_ptr<HalCameraMetadata> metadata = nullptr;
-  if (request.settings != nullptr) {
-    metadata = HalCameraMetadata::Clone(request.settings.get());
-  }
-
-  std::unique_ptr<HalCameraMetadata> color_metadata = nullptr;
-  for (auto& metadata : request.input_buffer_metadata) {
-    if (metadata != nullptr) {
-      color_metadata = HalCameraMetadata::Clone(metadata.get());
-    }
-  }
-
-  ALOGV("%s: [ud] Prepare depth request info for frame %u .", __FUNCTION__,
-        request.frame_number);
-
-  status_t res = PrepareDepthRequestInfo(request, &request_info, metadata.get(),
-                                         color_metadata.get());
-  if (res != OK) {
-    ALOGE("%s: Failed to perpare the depth request info.", __FUNCTION__);
-    return res;
-  }
-
-  if (pipelined_depth_engine_enabled_ == true) {
-    res = SubmitAsyncDepthRequest(request_info);
-    if (res != OK) {
-      ALOGE("%s: Failed to submit asynchronized depth request.", __FUNCTION__);
-    }
-  } else {
-    res = SubmitBlockingDepthRequest(request_info);
-    if (res != OK) {
-      ALOGE("%s: Failed to submit blocking depth request.", __FUNCTION__);
-    }
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::Flush() {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (!is_configured_) {
-    return OK;
-  }
-
-  // TODO(b/127322570): Implement this method.
-  return OK;
-}
-
-status_t DepthProcessBlock::LoadDepthGenerator(
-    std::unique_ptr<DepthGenerator>* depth_generator) {
-  ATRACE_CALL();
-#if GCH_HWL_USE_DLOPEN
-  CreateDepthGenerator_t create_depth_generator;
-
-  ALOGI("%s: Loading library: %s", __FUNCTION__, kDepthGeneratorLib.c_str());
-  depth_generator_lib_handle_ =
-      dlopen(kDepthGeneratorLib.c_str(), RTLD_NOW | RTLD_NODELETE);
-  if (depth_generator_lib_handle_ == nullptr) {
-    ALOGE("Depth generator loading %s failed.", kDepthGeneratorLib.c_str());
-    return NO_INIT;
-  }
-
-  create_depth_generator = (CreateDepthGenerator_t)dlsym(
-      depth_generator_lib_handle_, "CreateDepthGenerator");
-  if (create_depth_generator == nullptr) {
-    ALOGE("%s: dlsym failed (%s).", __FUNCTION__, kDepthGeneratorLib.c_str());
-    dlclose(depth_generator_lib_handle_);
-    depth_generator_lib_handle_ = nullptr;
-    return NO_INIT;
-  }
-
-  *depth_generator = std::unique_ptr<DepthGenerator>(create_depth_generator());
-  if (*depth_generator == nullptr) {
-    return NO_INIT;
-  }
-#else
-  if (CreateDepthGenerator == nullptr) {
-    return NO_INIT;
-  }
-  *depth_generator = std::unique_ptr<DepthGenerator>(CreateDepthGenerator());
-#endif
-
-  return OK;
-}
-
-status_t DepthProcessBlock::MapBuffersForDepthGenerator(
-    const StreamBuffer& stream_buffer, depth_generator::Buffer* buffer) {
-  ATRACE_CALL();
-  buffer_handle_t buffer_handle = stream_buffer.buffer;
-  ALOGV("%s: Mapping FD=%d to CPU addr.", __FUNCTION__, buffer_handle->data[0]);
-
-  int32_t stream_id = stream_buffer.stream_id;
-  if (stream_buffer_sizes_.find(stream_id) == stream_buffer_sizes_.end() ||
-      depth_io_streams_.find(stream_id) == depth_io_streams_.end()) {
-    ALOGE("%s: Stream buffer stream id:%d not found.", __FUNCTION__, stream_id);
-    return UNKNOWN_ERROR;
-  }
-
-  void* virtual_addr =
-      mmap(NULL, stream_buffer_sizes_[stream_id], (PROT_READ | PROT_WRITE),
-           MAP_SHARED, buffer_handle->data[0], 0);
-
-  if (virtual_addr == nullptr || virtual_addr == reinterpret_cast<void*>(-1)) {
-    ALOGE("%s: Failed to map the stream buffer to virtual addr.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  auto& stream = depth_io_streams_[stream_id];
-  buffer->format = stream.format;
-  buffer->width = stream.width;
-  buffer->height = stream.height;
-  depth_generator::BufferPlane buffer_plane = {};
-  buffer_plane.addr = reinterpret_cast<uint8_t*>(virtual_addr);
-  // TODO(b/130764929): Use actual gralloc buffer stride instead of stream dim
-  buffer_plane.stride = stream.width;
-  buffer_plane.scanline = stream.height;
-  buffer->planes.push_back(buffer_plane);
-
-  return OK;
-}
-
-status_t DepthProcessBlock::UnmapBuffersForDepthGenerator(
-    const StreamBuffer& stream_buffer, uint8_t* addr) {
-  ATRACE_CALL();
-  if (addr == nullptr) {
-    ALOGE("%s: Addr is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  int32_t stream_id = stream_buffer.stream_id;
-  if (stream_buffer_sizes_.find(stream_id) == stream_buffer_sizes_.end() ||
-      depth_io_streams_.find(stream_id) == depth_io_streams_.end()) {
-    ALOGE("%s: Stream buffer stream id:%d not found.", __FUNCTION__, stream_id);
-    return UNKNOWN_ERROR;
-  }
-
-  munmap(addr, stream_buffer_sizes_[stream_id]);
-  return OK;
-}
-
-status_t DepthProcessBlock::RequestDepthStreamBuffer(
-    StreamBuffer* incomplete_buffer, uint32_t frame_number) {
-  if (request_stream_buffers_ == nullptr) {
-    ALOGE("%s: request_stream_buffers_ is nullptr", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  std::vector<StreamBuffer> buffers;
-  {
-    status_t res = request_stream_buffers_(
-        incomplete_buffer->stream_id,
-        /* request one depth buffer each time */ 1, &buffers, frame_number);
-    if (res != OK) {
-      ALOGE("%s: Failed to request stream buffers from camera device session.",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  *incomplete_buffer = buffers[0];
-  return OK;
-}
-
-status_t DepthProcessBlock::UpdateCropRegion(const CaptureRequest& request,
-                                             DepthRequestInfo* depth_request_info,
-                                             HalCameraMetadata* metadata) {
-  if (request.settings != nullptr && metadata != nullptr) {
-    camera_metadata_ro_entry_t entry_crop_region_user = {};
-    if (request.settings->Get(ANDROID_SCALER_CROP_REGION,
-                              &entry_crop_region_user) == OK) {
-      const int32_t* crop_region = entry_crop_region_user.data.i32;
-      ALOGV("%s: Depth PB crop region[%d %d %d %d]", __FUNCTION__,
-            crop_region[0], crop_region[1], crop_region[2], crop_region[3]);
-
-      int32_t resized_crop_region[4] = {};
-      // top
-      resized_crop_region[0] = crop_region[1] / logical_to_ir_ratio_;
-      if (resized_crop_region[0] < 0) {
-        resized_crop_region[0] = 0;
-      }
-      // left
-      resized_crop_region[1] = crop_region[0] / logical_to_ir_ratio_;
-      if (resized_crop_region[1] < 0) {
-        resized_crop_region[1] = 0;
-      }
-      // bottom
-      resized_crop_region[2] =
-          (crop_region[3] / logical_to_ir_ratio_) + resized_crop_region[0];
-      if (resized_crop_region[2] > ir_active_array_height_) {
-        resized_crop_region[2] = ir_active_array_height_;
-      }
-      // right
-      resized_crop_region[3] =
-          (crop_region[2] / logical_to_ir_ratio_) + resized_crop_region[1];
-      if (resized_crop_region[3] > ir_active_array_width_) {
-        resized_crop_region[3] = ir_active_array_width_;
-      }
-      metadata->Set(ANDROID_SCALER_CROP_REGION, resized_crop_region,
-                    sizeof(resized_crop_region) / sizeof(int32_t));
-
-      depth_request_info->settings = metadata->GetRawCameraMetadata();
-    }
-  }
-  return OK;
-}
-
-status_t DepthProcessBlock::MapDepthRequestBuffers(
-    const CaptureRequest& request, DepthRequestInfo* depth_request_info) {
-  status_t res = OK;
-  depth_request_info->ir_buffer.resize(2);
-  for (auto& input_buffer : request.input_buffers) {
-    // If the stream id is invalid. The input buffer is only a place holder
-    // corresponding to the input buffer metadata for the rgb pipeline.
-    if (input_buffer.stream_id == kInvalidStreamId) {
-      ALOGV("%s: Skipping input buffer place holder for frame %u.",
-            __FUNCTION__, depth_request_info->frame_number);
-      continue;
-    }
-
-    depth_generator::Buffer buffer = {};
-    res = MapBuffersForDepthGenerator(input_buffer, &buffer);
-    if (res != OK) {
-      ALOGE("%s: Mapping buffer for depth generator failed.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-    const int32_t stream_id = input_buffer.stream_id;
-    if (stream_id == rgb_internal_yuv_stream_id_) {
-      // TODO(b/129910835): Triggering Condition
-      // Adjust the condition according to how rt_request_processor and
-      // result_request_processor handles the triggering condition. If they have
-      // full control of the logic and decide to pass yuv buffer only when
-      // autocal should be triggered, then the logic here can be as simple as
-      // this.
-      depth_request_info->color_buffer.push_back(buffer);
-    } else if (stream_id == ir1_internal_raw_stream_id_) {
-      depth_request_info->ir_buffer[0].push_back(buffer);
-    } else if (stream_id == ir2_internal_raw_stream_id_) {
-      depth_request_info->ir_buffer[1].push_back(buffer);
-    }
-  }
-
-  res = MapBuffersForDepthGenerator(request.output_buffers[0],
-                                    &depth_request_info->depth_buffer);
-  if (res != OK) {
-    ALOGE("%s: Mapping depth buffer for depth generator failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::PrepareDepthRequestInfo(
-    const CaptureRequest& request, DepthRequestInfo* depth_request_info,
-    HalCameraMetadata* metadata, const HalCameraMetadata* color_metadata) {
-  ATRACE_CALL();
-
-  if (depth_request_info == nullptr) {
-    ALOGE("%s: depth_request_info is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  status_t res = UpdateCropRegion(request, depth_request_info, metadata);
-  if (res != OK) {
-    ALOGE("%s: Failed to update crop region.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  if (color_metadata != nullptr) {
-    depth_request_info->color_buffer_metadata =
-        color_metadata->GetRawCameraMetadata();
-  }
-
-  if (request.input_buffers.size() < 2 || request.input_buffers.size() > 3 ||
-      request.output_buffers.size() != 1) {
-    ALOGE(
-        "%s: Cannot prepare request info, input buffer size is not 2 or 3(is"
-        " %zu) or output buffer size is not 1(is %zu).",
-        __FUNCTION__, request.input_buffers.size(),
-        request.output_buffers.size());
-    return BAD_VALUE;
-  }
-  int32_t stream_id = request.output_buffers[0].stream_id;
-  if (buffer_management_used_ || (hal_buffer_managed_streams_.find(stream_id) !=
-                                  hal_buffer_managed_streams_.end())) {
-    res = RequestDepthStreamBuffer(
-        &(const_cast<CaptureRequest&>(request).output_buffers[0]),
-        request.frame_number);
-    if (res != OK) {
-      ALOGE("%s: Failed to request depth stream buffer.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  res = MapDepthRequestBuffers(request, depth_request_info);
-  if (res != OK) {
-    ALOGE("%s: Failed to map buffers for depth request.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  {
-    uint32_t frame_number = request.frame_number;
-    std::lock_guard<std::mutex> lock(pending_requests_mutex_);
-    if (pending_depth_requests_.find(frame_number) !=
-        pending_depth_requests_.end()) {
-      ALOGE("%s: Frame %u already exists in pending requests.", __FUNCTION__,
-            request.frame_number);
-      return UNKNOWN_ERROR;
-    } else {
-      pending_depth_requests_[frame_number] = {};
-      auto& pending_request = pending_depth_requests_[frame_number].request;
-      pending_request.frame_number = frame_number;
-      pending_request.input_buffers = request.input_buffers;
-      pending_request.output_buffers = request.output_buffers;
-      auto& pending_depth_request =
-          pending_depth_requests_[frame_number].depth_request;
-      pending_depth_request = *depth_request_info;
-    }
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::UnmapDepthRequestBuffers(uint32_t frame_number) {
-  std::lock_guard<std::mutex> lock(pending_requests_mutex_);
-  if (pending_depth_requests_.find(frame_number) ==
-      pending_depth_requests_.end()) {
-    ALOGE("%s: Can not find frame %u in pending requests list.", __FUNCTION__,
-          frame_number);
-    return BAD_VALUE;
-  }
-
-  auto& request = pending_depth_requests_[frame_number].request;
-  auto& depth_request_info = pending_depth_requests_[frame_number].depth_request;
-
-  ATRACE_CALL();
-  if (request.input_buffers.size() < 2 || request.input_buffers.size() > 3 ||
-      request.output_buffers.size() != 1) {
-    ALOGE(
-        "%s: Cannot prepare request info, input buffer size is not 2 or 3(is "
-        "%zu) or output buffer size is not 1(is %zu).",
-        __FUNCTION__, request.input_buffers.size(),
-        request.output_buffers.size());
-    return BAD_VALUE;
-  }
-
-  status_t res = OK;
-  for (auto& input_buffer : request.input_buffers) {
-    uint8_t* addr = nullptr;
-    int32_t stream_id = input_buffer.stream_id;
-    if (stream_id == kInvalidStreamId) {
-      ALOGV("%s: input buffer place holder found for frame %u", __FUNCTION__,
-            frame_number);
-      continue;
-    }
-
-    if (stream_id == rgb_internal_yuv_stream_id_) {
-      addr = depth_request_info.color_buffer[0].planes[0].addr;
-    } else if (stream_id == ir1_internal_raw_stream_id_) {
-      addr = depth_request_info.ir_buffer[0][0].planes[0].addr;
-    } else if (stream_id == ir2_internal_raw_stream_id_) {
-      addr = depth_request_info.ir_buffer[1][0].planes[0].addr;
-    }
-
-    res = UnmapBuffersForDepthGenerator(input_buffer, addr);
-    if (res != OK) {
-      ALOGE("%s: Unmapping input buffer for depth generator failed.",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  res = UnmapBuffersForDepthGenerator(
-      request.output_buffers[0], depth_request_info.depth_buffer.planes[0].addr);
-  if (res != OK) {
-    ALOGE("%s: Unmapping depth buffer for depth generator failed.",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  return OK;
-}
-
-status_t DepthProcessBlock::CalculateActiveArraySizeRatio(
-    CameraDeviceSessionHwl* device_session_hwl) {
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  uint32_t active_array_width = 0;
-  uint32_t active_array_height = 0;
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(
-      ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE, &entry);
-  if (res == OK) {
-    active_array_width = entry.data.i32[2];
-    active_array_height = entry.data.i32[3];
-    ALOGI("%s Active size (%d x %d).", __FUNCTION__, active_array_width,
-          active_array_height);
-  } else {
-    ALOGE("%s Get active size failed: %s (%d).", __FUNCTION__, strerror(-res),
-          res);
-    return UNKNOWN_ERROR;
-  }
-
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl->GetPhysicalCameraIds();
-  if (physical_camera_ids.size() != 3) {
-    ALOGE("%s: Only support 3 cameras", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  uint32_t ir_active_array_width = 0;
-  uint32_t ir_active_array_height = 0;
-  std::unique_ptr<HalCameraMetadata> ir_characteristics;
-  for (auto camera_id : physical_camera_ids) {
-    res = device_session_hwl->GetPhysicalCameraCharacteristics(
-        camera_id, &ir_characteristics);
-    if (res != OK) {
-      ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-
-    // assuming both IR camera are of the same size
-    if (hal_utils::IsIrCamera(ir_characteristics.get())) {
-      camera_metadata_ro_entry entry;
-      res = ir_characteristics->Get(
-          ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE, &entry);
-      if (res == OK) {
-        ir_active_array_width = entry.data.i32[2];
-        ir_active_array_height = entry.data.i32[3];
-        ALOGI("%s IR active size (%dx%d).", __FUNCTION__, ir_active_array_width,
-              ir_active_array_height);
-      } else {
-        ALOGE("%s Get ir active size failed: %s (%d).", __FUNCTION__,
-              strerror(-res), res);
-        return UNKNOWN_ERROR;
-      }
-      break;
-    }
-  }
-
-  if (active_array_width == 0 || active_array_height == 0 ||
-      ir_active_array_width == 0 || ir_active_array_height == 0) {
-    ALOGE(
-        "%s: One dimension of the logical camera active array size or the "
-        "IR camera active array size is 0.",
-        __FUNCTION__);
-    return INVALID_OPERATION;
-  }
-
-  float logical_aspect_ratio = 1.0;
-  float ir_aspect_ratio = 1.0;
-  if (active_array_width > active_array_height) {
-    logical_aspect_ratio = active_array_width / active_array_height;
-    ir_aspect_ratio = ir_active_array_width / ir_active_array_height;
-  } else {
-    logical_aspect_ratio = active_array_height / active_array_width;
-    ir_aspect_ratio = ir_active_array_height / ir_active_array_width;
-  }
-
-  ir_active_array_height_ = ir_active_array_height;
-  ir_active_array_width_ = ir_active_array_width;
-
-  float aspect_ratio_diff = logical_aspect_ratio - ir_aspect_ratio;
-  if (aspect_ratio_diff > kSmallOffset || aspect_ratio_diff < -kSmallOffset) {
-    ALOGE(
-        "%s: Logical camera aspect ratio and IR camera aspect ratio are "
-        "different from each other.",
-        __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  logical_to_ir_ratio_ = float(active_array_height) / ir_active_array_height;
-
-  ALOGI("%s: logical_to_ir_ratio_ = %f", __FUNCTION__, logical_to_ir_ratio_);
-
-  return OK;
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/google_camera_hal/depth_process_block.h b/common/hal/google_camera_hal/depth_process_block.h
deleted file mode 100644
index 2c1cfa4..0000000
--- a/common/hal/google_camera_hal/depth_process_block.h
+++ /dev/null
@@ -1,219 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DEPTH_PROCESS_BLOCK_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DEPTH_PROCESS_BLOCK_H_
-
-#include <map>
-
-#include "depth_generator.h"
-#include "hwl_types.h"
-#include "process_block.h"
-
-using android::depth_generator::DepthGenerator;
-using android::depth_generator::DepthRequestInfo;
-using android::depth_generator::DepthResultStatus;
-
-namespace android {
-namespace google_camera_hal {
-
-// DepthProcessBlock implements a ProcessBlock to generate a depth stream
-// for a logical camera consisting of one RGB and two IR camera sensors.
-class DepthProcessBlock : public ProcessBlock {
- public:
-  struct DepthProcessBlockCreateData {
-    // stream id of the internal yuv stream from RGB sensor
-    int32_t rgb_internal_yuv_stream_id = -1;
-    // stream id of the internal raw stream from IR 1
-    int32_t ir1_internal_raw_stream_id = -1;
-    // stream id of the internal raw stream from IR 2
-    int32_t ir2_internal_raw_stream_id = -1;
-  };
-  // Create a DepthProcessBlock.
-  static std::unique_ptr<DepthProcessBlock> Create(
-      CameraDeviceSessionHwl* device_session_hwl,
-      HwlRequestBuffersFunc request_stream_buffers,
-      const DepthProcessBlockCreateData& create_data);
-
-  virtual ~DepthProcessBlock();
-
-  // Override functions of ProcessBlock start.
-  status_t ConfigureStreams(const StreamConfiguration& stream_config,
-                            const StreamConfiguration& overall_config) override;
-
-  status_t SetResultProcessor(
-      std::unique_ptr<ResultProcessor> result_processor) override;
-
-  status_t GetConfiguredHalStreams(
-      std::vector<HalStream>* hal_streams) const override;
-
-  status_t ProcessRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  status_t Flush() override;
-  // Override functions of ProcessBlock end.
-
- protected:
-  DepthProcessBlock(HwlRequestBuffersFunc request_stream_buffers_,
-                    const DepthProcessBlockCreateData& create_data);
-
- private:
-  struct PendingDepthRequestInfo {
-    CaptureRequest request;
-    DepthRequestInfo depth_request;
-  };
-
-  static constexpr int32_t kInvalidStreamId = -1;
-  const uint32_t kDepthStreamMaxBuffers = 8;
-
-  // Callback function to request stream buffer from camera device session
-  const HwlRequestBuffersFunc request_stream_buffers_;
-
-  // Load the depth generator dynamically
-  status_t LoadDepthGenerator(std::unique_ptr<DepthGenerator>* depth_generator);
-
-  // Map the input and output buffers from buffer_handle_t to UMD virtual addr
-  status_t MapBuffersForDepthGenerator(const StreamBuffer& stream_buffer,
-                                       depth_generator::Buffer* depth_buffer);
-
-  // Get the gralloc buffer size of a stream
-  status_t GetStreamBufferSize(const Stream& stream, int32_t* buffer_size);
-
-  // Ummap the input and output buffers
-  status_t UnmapBuffersForDepthGenerator(const StreamBuffer& stream_buffer,
-                                         uint8_t* addr);
-
-  // Prepare a depth request info for the depth generator
-  status_t PrepareDepthRequestInfo(const CaptureRequest& request,
-                                   DepthRequestInfo* depth_request_info,
-                                   HalCameraMetadata* metadata,
-                                   const HalCameraMetadata* color_metadata);
-
-  // Clean up a depth request info by unmapping the buffers
-  status_t UnmapDepthRequestBuffers(uint32_t frame_number);
-
-  // Caclculate the ratio of logical camera active array size comparing to the
-  // IR camera active array size
-  status_t CalculateActiveArraySizeRatio(
-      CameraDeviceSessionHwl* device_session_hwl);
-
-  // Calculate the crop region info from the RGB sensor framework to the IR
-  // sensor framework. Update the depth_request_info with the updated result.
-  status_t UpdateCropRegion(const CaptureRequest& request,
-                            DepthRequestInfo* depth_request_info,
-                            HalCameraMetadata* metadata);
-
-  // Request the stream buffer for depth stream. incomplete_buffer is the
-  // StreamBuffer that does not have a valid buffer handle and needs to be
-  // replaced by the newly requested buffer.
-  status_t RequestDepthStreamBuffer(StreamBuffer* incomplete_buffer,
-                                    uint32_t frame_number);
-
-  // Initialize the HAL Buffer Management status.
-  status_t InitializeBufferManagementStatus(
-      CameraDeviceSessionHwl* device_session_hwl);
-
-  // Submit a depth request through the blocking depth generator API
-  status_t SubmitBlockingDepthRequest(const DepthRequestInfo& request_info);
-
-  // Submit a detph request through the asynchronized depth generator API
-  status_t SubmitAsyncDepthRequest(const DepthRequestInfo& request_info);
-
-  // Process the depth result of frame frame_number
-  status_t ProcessDepthResult(DepthResultStatus result_status,
-                              uint32_t frame_number);
-
-  // Map all buffers needed by a depth request from request
-  status_t MapDepthRequestBuffers(const CaptureRequest& request,
-                                  DepthRequestInfo* depth_request_info);
-
-  mutable std::mutex configure_lock_;
-
-  // If streams are configured. Must be protected by configure_lock_.
-  bool is_configured_ = false;
-
-  std::mutex result_processor_lock_;
-
-  // Result processor. Must be protected by result_processor_lock_.
-  std::unique_ptr<ResultProcessor> result_processor_ = nullptr;
-
-  // Depth stream configured in the depth process block
-  HalStream depth_stream_;
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  bool force_internal_stream_ = false;
-
-  // Provider library handle.
-  void* depth_generator_lib_handle_ = nullptr;
-
-  // Depth Generator
-  std::unique_ptr<DepthGenerator> depth_generator_ = nullptr;
-
-  // Map from stream id to their buffer size
-  std::map<int32_t, uint32_t> stream_buffer_sizes_;
-
-  // Map from stream id to the stream
-  std::map<int32_t, Stream> depth_io_streams_;
-
-  // Ratio of logical camera active array size comparing to IR camera active
-  // array size.
-  float logical_to_ir_ratio_ = 1.0;
-
-  // IR sensor active array sizes
-  int32_t ir_active_array_width_ = 640;
-  int32_t ir_active_array_height_ = 480;
-
-  // Whether the HAL Buffer Management is supported for the session
-  // configured
-  bool buffer_management_used_ = false;
-  bool session_buffer_management_supported_ = false;
-  std::set<int32_t> hal_buffer_managed_streams_;
-
-  // Owned by the client calling Create()
-  CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
-
-  // Whether the pipelined depth engine is enabled
-  bool pipelined_depth_engine_enabled_ = false;
-
-  std::mutex pending_requests_mutex_;
-  // Pending depth request indexed by the frame_number
-  // Must be protected by pending_requests_mutex_
-  std::unordered_map<uint32_t, PendingDepthRequestInfo> pending_depth_requests_;
-
-  // Whether RGB-IR auto-calibration is enabled. This affects how the internal
-  // YUV stream results are handled.
-  bool rgb_ir_auto_cal_enabled_ = false;
-
-  // stream id of the internal yuv stream from RGB sensor
-  int32_t rgb_internal_yuv_stream_id_ = kInvalidStreamId;
-  // stream id of the internal raw stream from IR 1
-  int32_t ir1_internal_raw_stream_id_ = kInvalidStreamId;
-  // stream id of the internal raw stream from IR 2
-  int32_t ir2_internal_raw_stream_id_ = kInvalidStreamId;
-
-  // Guarding async depth generator API calls and the result processing calls
-  std::mutex depth_generator_api_lock_;
-};
-
-#if !GCH_HWL_USE_DLOPEN
-extern "C" __attribute__((weak)) DepthGenerator* CreateDepthGenerator();
-#endif
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DEPTH_PROCESS_BLOCK_H_
diff --git a/common/hal/google_camera_hal/dual_ir_capture_session.cc b/common/hal/google_camera_hal/dual_ir_capture_session.cc
deleted file mode 100644
index 4b52476..0000000
--- a/common/hal/google_camera_hal/dual_ir_capture_session.cc
+++ /dev/null
@@ -1,555 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_DualIrCaptureSession"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "dual_ir_capture_session.h"
-
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <set>
-#include <vector>
-
-#include "dual_ir_request_processor.h"
-#include "dual_ir_result_request_processor.h"
-#include "hal_utils.h"
-#include "multicam_realtime_process_block.h"
-
-namespace android {
-namespace google_camera_hal {
-
-bool DualIrCaptureSession::IsStreamConfigurationSupported(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return false;
-  }
-
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl->GetPhysicalCameraIds();
-  if (physical_camera_ids.size() != 2) {
-    ALOGD("%s: Only support two IR cameras but there are %zu cameras.",
-          __FUNCTION__, physical_camera_ids.size());
-    return false;
-  }
-
-  // Check the two physical cameras are IR cameras.
-  for (auto id : physical_camera_ids) {
-    std::unique_ptr<HalCameraMetadata> characteristics;
-    status_t res = device_session_hwl->GetPhysicalCameraCharacteristics(
-        id, &characteristics);
-    if (res != OK) {
-      ALOGE("%s: Cannot get physical camera characteristics for camera %u",
-            __FUNCTION__, id);
-      return false;
-    }
-
-    // TODO(b/129088371): Work around b/129088371 because current IR camera's
-    // CFA is MONO instead of NIR.
-    if (!hal_utils::IsIrCamera(characteristics.get()) &&
-        !hal_utils::IsMonoCamera(characteristics.get())) {
-      ALOGD("%s: camera %u is not an IR or MONO camera", __FUNCTION__, id);
-      return false;
-    }
-  }
-
-  uint32_t physical_stream_number = 0;
-  uint32_t logical_stream_number = 0;
-  for (auto& stream : stream_config.streams) {
-    if (stream.is_physical_camera_stream) {
-      physical_stream_number++;
-    } else {
-      logical_stream_number++;
-    }
-  }
-  if (logical_stream_number > 0 && physical_stream_number > 0) {
-    ALOGD("%s: can't support mixed logical and physical stream", __FUNCTION__);
-    return false;
-  }
-
-  ALOGD("%s: DualIrCaptureSession supports the stream config", __FUNCTION__);
-  return true;
-}
-
-std::unique_ptr<CaptureSession> DualIrCaptureSession::Create(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/,
-    NotifyFunc notify, HwlSessionCallback /*session_callback*/,
-    std::vector<HalStream>* hal_configured_streams,
-    CameraBufferAllocatorHwl* /*camera_allocator_hwl*/) {
-  ATRACE_CALL();
-  if (!IsStreamConfigurationSupported(device_session_hwl, stream_config)) {
-    ALOGE("%s: stream configuration is not supported.", __FUNCTION__);
-    return nullptr;
-  }
-
-  // TODO(b/129707250): Assume the first physical camera is the lead until
-  // it's available in the static metadata.
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl->GetPhysicalCameraIds();
-  uint32_t lead_camera_id = physical_camera_ids[0];
-
-  // If stream configuration only contains follower physical streams, set
-  // follower as lead.
-  bool has_lead_camera_config = false;
-  for (auto& stream : stream_config.streams) {
-    if (!stream.is_physical_camera_stream ||
-        (stream.is_physical_camera_stream &&
-         stream.physical_camera_id == physical_camera_ids[0])) {
-      has_lead_camera_config = true;
-      break;
-    }
-  }
-  if (!has_lead_camera_config) {
-    lead_camera_id = physical_camera_ids[1];
-  }
-
-  auto session = std::unique_ptr<DualIrCaptureSession>(
-      new DualIrCaptureSession(lead_camera_id));
-  if (session == nullptr) {
-    ALOGE("%s: Creating DualIrCaptureSession failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  status_t res = session->Initialize(device_session_hwl, stream_config,
-                                     process_capture_result, notify,
-                                     hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Initializing DualIrCaptureSession failed: %s (%d).",
-          __FUNCTION__, strerror(-res), res);
-    return nullptr;
-  }
-
-  ALOGI("%s: Created a DualIrCaptureSession", __FUNCTION__);
-  return session;
-}
-
-DualIrCaptureSession::DualIrCaptureSession(uint32_t lead_camera_id)
-    : kLeadCameraId(lead_camera_id) {
-}
-
-DualIrCaptureSession::~DualIrCaptureSession() {
-  ATRACE_CALL();
-  if (device_session_hwl_ != nullptr) {
-    device_session_hwl_->DestroyPipelines();
-  }
-}
-
-bool DualIrCaptureSession::AreAllStreamsConfigured(
-    const StreamConfiguration& stream_config,
-    const StreamConfiguration& process_block_stream_config) const {
-  ATRACE_CALL();
-  // Check all streams are configured.
-  if (stream_config.streams.size() !=
-      process_block_stream_config.streams.size()) {
-    ALOGE("%s: stream_config has %zu streams but only configured %zu streams",
-          __FUNCTION__, stream_config.streams.size(),
-          process_block_stream_config.streams.size());
-    return false;
-  }
-
-  for (auto& stream : stream_config.streams) {
-    bool found = false;
-    for (auto& configured_stream : process_block_stream_config.streams) {
-      if (stream.id == configured_stream.id) {
-        found = true;
-        break;
-      }
-    }
-
-    if (!found) {
-      ALOGE("%s: Cannot find stream %u in configured streams.", __FUNCTION__,
-            stream.id);
-      return false;
-    }
-  }
-
-  return true;
-}
-
-status_t DualIrCaptureSession::ConfigureStreams(
-    RequestProcessor* request_processor, ProcessBlock* process_block,
-    const StreamConfiguration& overall_config,
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (request_processor == nullptr || process_block == nullptr) {
-    ALOGE("%s: request_processor(%p) or process_block(%p) is nullptr",
-          __FUNCTION__, request_processor, process_block);
-    return BAD_VALUE;
-  }
-
-  status_t res = request_processor->ConfigureStreams(
-      internal_stream_manager_.get(), stream_config,
-      process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream for RequestProcessor failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  res = process_block->ConfigureStreams(*process_block_stream_config,
-                                        overall_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring streams for ProcessBlock failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::ConnectProcessChain(
-    RequestProcessor* request_processor,
-    std::unique_ptr<ProcessBlock> process_block,
-    std::unique_ptr<ResultProcessor> result_processor) {
-  ATRACE_CALL();
-  if (request_processor == nullptr) {
-    ALOGE("%s: request_processor is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  status_t res = process_block->SetResultProcessor(std::move(result_processor));
-  if (res != OK) {
-    ALOGE("%s: Setting result process in process block failed.", __FUNCTION__);
-    return res;
-  }
-
-  res = request_processor->SetProcessBlock(std::move(process_block));
-  if (res != OK) {
-    ALOGE("%s: Setting process block for request processor failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::PurgeHalConfiguredStream(
-    const StreamConfiguration& stream_config,
-    std::vector<HalStream>* hal_configured_streams) {
-  if (hal_configured_streams == nullptr) {
-    ALOGE("%s: HAL configured stream list is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::set<int32_t> framework_stream_id_set;
-  for (auto& stream : stream_config.streams) {
-    framework_stream_id_set.insert(stream.id);
-  }
-
-  std::vector<HalStream> configured_streams;
-  for (auto& hal_stream : *hal_configured_streams) {
-    if (framework_stream_id_set.find(hal_stream.id) !=
-        framework_stream_id_set.end()) {
-      configured_streams.push_back(hal_stream);
-    }
-  }
-  *hal_configured_streams = configured_streams;
-  return OK;
-}
-
-status_t DualIrCaptureSession::MakeDepthChainSegmentStreamConfig(
-    const StreamConfiguration& /*stream_config*/,
-    StreamConfiguration* rt_process_block_stream_config,
-    StreamConfiguration* depth_chain_segment_stream_config) {
-  if (depth_chain_segment_stream_config == nullptr ||
-      rt_process_block_stream_config == nullptr) {
-    ALOGE(
-        "%s: depth_chain_segment_stream_config is nullptr or "
-        "rt_process_block_stream_config is nullptr.",
-        __FUNCTION__);
-    return BAD_VALUE;
-  }
-  // TODO(b/131618554):
-  // Actually implement this function to form a depth chain segment stream
-  // config from the overall stream config and the streams mutli-camera realtime
-  // process block configured.
-  // This function signature may need to be changed.
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::SetupRealtimeSegment(
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config,
-    std::unique_ptr<MultiCameraRtProcessBlock>* rt_process_block,
-    std::unique_ptr<DualIrResultRequestProcessor>* rt_result_request_processor) {
-  request_processor_ =
-      DualIrRequestProcessor::Create(device_session_hwl_, kLeadCameraId);
-  if (request_processor_ == nullptr) {
-    ALOGE("%s: Creating DualIrRtRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  auto process_block = MultiCameraRtProcessBlock::Create(device_session_hwl_);
-  if (process_block == nullptr) {
-    ALOGE("%s: Creating MultiCameraRtProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  auto result_request_processor = DualIrResultRequestProcessor::Create(
-      device_session_hwl_, stream_config, kLeadCameraId);
-  if (result_request_processor == nullptr) {
-    ALOGE("%s: Creating DualIrResultRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  status_t res = ConfigureStreams(request_processor_.get(), process_block.get(),
-                                  stream_config, stream_config,
-                                  process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring streams failed: %s(%d).", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  *rt_process_block = std::move(process_block);
-  *rt_result_request_processor = std::move(result_request_processor);
-  return OK;
-}
-
-status_t DualIrCaptureSession::SetupDepthSegment(
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config,
-    DualIrResultRequestProcessor* rt_result_request_processor,
-    std::unique_ptr<DepthProcessBlock>* depth_process_block,
-    std::unique_ptr<DualIrDepthResultProcessor>* depth_result_processor) {
-  DepthProcessBlock::DepthProcessBlockCreateData data = {};
-  auto process_block =
-      DepthProcessBlock::Create(device_session_hwl_, nullptr, data);
-  if (process_block == nullptr) {
-    ALOGE("%s: Creating DepthProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  auto result_processor =
-      DualIrDepthResultProcessor::Create(internal_stream_manager_.get());
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating DualIrDepthResultProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  StreamConfiguration depth_pb_stream_config;
-  StreamConfiguration depth_chain_segment_stream_config;
-  status_t res = MakeDepthChainSegmentStreamConfig(
-      stream_config, process_block_stream_config,
-      &depth_chain_segment_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Failed to make depth chain segment stream configuration: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  res = ConfigureStreams(rt_result_request_processor, process_block.get(),
-                         stream_config, depth_chain_segment_stream_config,
-                         &depth_pb_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Failed to configure streams for the depth segment.",
-          __FUNCTION__);
-    return res;
-  }
-
-  // Append the streams configured by depth process block. So
-  // process_block_stream_config contains all streams configured by both
-  // realtime and depth process blocks
-  process_block_stream_config->streams.insert(
-      process_block_stream_config->streams.end(),
-      depth_pb_stream_config.streams.begin(),
-      depth_pb_stream_config.streams.end());
-
-  *depth_process_block = std::move(process_block);
-  *depth_result_processor = std::move(result_processor);
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::BuildPipelines(
-    const StreamConfiguration& stream_config,
-    std::vector<HalStream>* hal_configured_streams,
-    MultiCameraRtProcessBlock* rt_process_block,
-    DepthProcessBlock* depth_process_block) {
-  status_t res = device_session_hwl_->BuildPipelines();
-  if (res != OK) {
-    ALOGE("%s: Building pipelines failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  res = rt_process_block->GetConfiguredHalStreams(hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Getting HAL streams failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  if (has_depth_stream_) {
-    std::vector<HalStream> depth_pb_configured_streams;
-    res = depth_process_block->GetConfiguredHalStreams(
-        &depth_pb_configured_streams);
-    if (res != OK) {
-      ALOGE("%s: Failed to get configured hal streams from DepthProcessBlock",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-    // Depth Process Block can only configure one depth stream so far
-    if (depth_pb_configured_streams.size() != 1) {
-      ALOGE("%s: DepthProcessBlock configured more than one stream.",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-    hal_configured_streams->push_back(depth_pb_configured_streams[0]);
-  }
-
-  res = PurgeHalConfiguredStream(stream_config, hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Removing internal streams from configured stream failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::CreateProcessChain(
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-
-  // process_block_stream_config is used to collect all streams configured by
-  // both realtime and the depth process blocks. This is used to verify if all
-  // framework streams have been configured.
-  StreamConfiguration process_block_stream_config;
-
-  std::unique_ptr<MultiCameraRtProcessBlock> rt_process_block;
-  std::unique_ptr<DualIrResultRequestProcessor> rt_result_request_processor;
-  status_t res =
-      SetupRealtimeSegment(stream_config, &process_block_stream_config,
-                           &rt_process_block, &rt_result_request_processor);
-  if (res != OK) {
-    ALOGE("%s: Failed to setup the realtime segment of the process chain.",
-          __FUNCTION__);
-    return res;
-  }
-
-  // Create process block and result processor for Depth Process Chain Segment
-  std::unique_ptr<DepthProcessBlock> depth_process_block;
-  std::unique_ptr<DualIrDepthResultProcessor> depth_result_processor;
-  if (has_depth_stream_) {
-    status_t res =
-        SetupDepthSegment(stream_config, &process_block_stream_config,
-                          rt_result_request_processor.get(),
-                          &depth_process_block, &depth_result_processor);
-    if (res != OK) {
-      ALOGE("%s: Failed to setup the depth segment of the process chain.",
-            __FUNCTION__);
-      return res;
-    }
-  }
-
-  if (!AreAllStreamsConfigured(stream_config, process_block_stream_config)) {
-    ALOGE("%s: Not all streams are configured!", __FUNCTION__);
-    return INVALID_OPERATION;
-  }
-
-  res = BuildPipelines(stream_config, hal_configured_streams,
-                       rt_process_block.get(), depth_process_block.get());
-  if (res != OK) {
-    ALOGE("%s: Failed to build pipelines.", __FUNCTION__);
-    return res;
-  }
-
-  // Only connect the depth segment of the realtime process chain when depth
-  // stream is configured
-  if (has_depth_stream_) {
-    depth_result_processor->SetResultCallback(
-        process_capture_result, notify,
-        /*process_batch_capture_result=*/nullptr);
-    res = ConnectProcessChain(rt_result_request_processor.get(),
-                              std::move(depth_process_block),
-                              std::move(depth_result_processor));
-    if (res != OK) {
-      ALOGE("%s: Connecting depth segment of realtime chain failed: %s(%d)",
-            __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-  }
-
-  rt_result_request_processor->SetResultCallback(
-      process_capture_result, notify, /*process_batch_capture_result=*/nullptr);
-  res =
-      ConnectProcessChain(request_processor_.get(), std::move(rt_process_block),
-                          std::move(rt_result_request_processor));
-  if (res != OK) {
-    ALOGE("%s: Connecting process chain failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::Initialize(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-  device_session_hwl_ = device_session_hwl;
-
-  internal_stream_manager_ = InternalStreamManager::Create();
-  if (internal_stream_manager_ == nullptr) {
-    ALOGE("%s: Cannot create internal stream manager.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  for (auto& stream : stream_config.streams) {
-    if (utils::IsDepthStream(stream)) {
-      ALOGI("%s: Depth stream found in the stream config.", __FUNCTION__);
-      has_depth_stream_ = true;
-    }
-  }
-
-  status_t res = CreateProcessChain(stream_config, process_capture_result,
-                                    notify, hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Creating the process  chain failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t DualIrCaptureSession::ProcessRequest(const CaptureRequest& request) {
-  ATRACE_CALL();
-  return request_processor_->ProcessRequest(request);
-}
-
-status_t DualIrCaptureSession::Flush() {
-  ATRACE_CALL();
-  return request_processor_->Flush();
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/google_camera_hal/dual_ir_capture_session.h b/common/hal/google_camera_hal/dual_ir_capture_session.h
deleted file mode 100644
index b28820b..0000000
--- a/common/hal/google_camera_hal/dual_ir_capture_session.h
+++ /dev/null
@@ -1,167 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_CAPTURE_SESSION_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_CAPTURE_SESSION_H_
-
-#include "camera_device_session_hwl.h"
-#include "capture_session.h"
-#include "depth_process_block.h"
-#include "dual_ir_depth_result_processor.h"
-#include "dual_ir_request_processor.h"
-#include "dual_ir_result_request_processor.h"
-#include "hwl_types.h"
-#include "multicam_realtime_process_block.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// DualIrCaptureSession implements a CaptureSession that contains a single
-// process chain that consists of
-//
-//   DualIrRequestProcessor -> MultiCameraRtProcessBlock ->
-//     DualIrResultRequestProcessor -> DepthProcessBlock ->
-//     DualIrDepthResultProcessor
-//
-// It only supports a camera device session that consists of two IR cameras.
-class DualIrCaptureSession : public CaptureSession {
- public:
-  // Return if the device session HWL and stream configuration are supported.
-  static bool IsStreamConfigurationSupported(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config);
-
-  // Create a DualIrCaptureSession.
-  //
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of DualIrCaptureSession.
-  // stream_config is the stream configuration.
-  // process_capture_result is the callback function to notify results.
-  // process_batch_capture_result is the callback function to notify batched
-  // results.
-  // notify is the callback function to notify messages.
-  // hal_configured_streams will be filled with HAL configured streams.
-  // camera_allocator_hwl is owned by the caller and must be valid during the
-  // lifetime of DualIrCaptureSession
-  static std::unique_ptr<CaptureSession> Create(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result,
-      ProcessBatchCaptureResultFunc process_batch_capture_result,
-      NotifyFunc notify, HwlSessionCallback session_callback,
-      std::vector<HalStream>* hal_configured_streams,
-      CameraBufferAllocatorHwl* camera_allocator_hwl);
-
-  virtual ~DualIrCaptureSession();
-
-  // Override functions in CaptureSession start.
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions in CaptureSession end.
-
- protected:
-  DualIrCaptureSession(uint32_t lead_camera_id);
-
- private:
-  const uint32_t kLeadCameraId;
-
-  status_t Initialize(CameraDeviceSessionHwl* device_session_hwl,
-                      const StreamConfiguration& stream_config,
-                      ProcessCaptureResultFunc process_capture_result,
-                      NotifyFunc notify,
-                      std::vector<HalStream>* hal_configured_streams);
-
-  status_t CreateProcessChain(const StreamConfiguration& stream_config,
-                              ProcessCaptureResultFunc process_capture_result,
-                              NotifyFunc notify,
-                              std::vector<HalStream>* hal_configured_streams);
-
-  // Connect ProcessBlock and Request/Result processors to form a process chain
-  status_t ConnectProcessChain(RequestProcessor* request_processor,
-                               std::unique_ptr<ProcessBlock> process_block,
-                               std::unique_ptr<ResultProcessor> result_processor);
-
-  // Check if all streams in stream_config are also in
-  // process_block_stream_config.
-  bool AreAllStreamsConfigured(
-      const StreamConfiguration& stream_config,
-      const StreamConfiguration& process_block_stream_config) const;
-
-  // Configure streams for the process chain.
-  status_t ConfigureStreams(RequestProcessor* request_processor,
-                            ProcessBlock* process_block,
-                            const StreamConfiguration& overall_config,
-                            const StreamConfiguration& stream_config,
-                            StreamConfiguration* process_block_stream_config);
-
-  // Make a stream configuration for the depth chaing segment in case a depth
-  // stream is configured by the framework.
-  status_t MakeDepthChainSegmentStreamConfig(
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* rt_process_block_stream_config,
-      StreamConfiguration* depth_chain_segment_stream_config);
-
-  // Purge the hal_configured_streams such that only framework streams are left
-  status_t PurgeHalConfiguredStream(
-      const StreamConfiguration& stream_config,
-      std::vector<HalStream>* hal_configured_streams);
-
-  // Setup the realtime segment of the DualIr process chain. This creates the
-  // related process block and request/result processors. It also calls the
-  // ConfigureStreams for the request processor and the process block.
-  status_t SetupRealtimeSegment(
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config,
-      std::unique_ptr<MultiCameraRtProcessBlock>* rt_process_block,
-      std::unique_ptr<DualIrResultRequestProcessor>* rt_result_request_processor);
-
-  // Setup the depth segment of the DualIr process chain. This creates the
-  // related process block and request/result processors. It also calls the
-  // ConfigureStreams for the request processor and the process block.
-  // It generates the stream_config for the depth chain segment internally.
-  // This function should only be invoked when has_depth_stream_ is true
-  status_t SetupDepthSegment(
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config,
-      DualIrResultRequestProcessor* rt_result_request_processor,
-      std::unique_ptr<DepthProcessBlock>* depth_process_block,
-      std::unique_ptr<DualIrDepthResultProcessor>* depth_result_processor);
-
-  // This build pipelines for all process blocks. It also collects those
-  // framework streams which are configured by the HAL(i.e. process blocks)
-  status_t BuildPipelines(const StreamConfiguration& stream_config,
-                          std::vector<HalStream>* hal_configured_streams,
-                          MultiCameraRtProcessBlock* rt_process_block,
-                          DepthProcessBlock* depth_process_block);
-
-  // device_session_hwl_ is owned by the client.
-  CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
-
-  std::unique_ptr<DualIrRequestProcessor> request_processor_;
-
-  // Internal stream manager
-  std::unique_ptr<InternalStreamManager> internal_stream_manager_;
-
-  // Whether there is a depth stream configured in the current session
-  bool has_depth_stream_ = false;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_CAPTURE_SESSION_H_
diff --git a/common/hal/google_camera_hal/dual_ir_depth_result_processor.cc b/common/hal/google_camera_hal/dual_ir_depth_result_processor.cc
deleted file mode 100644
index a81a448..0000000
--- a/common/hal/google_camera_hal/dual_ir_depth_result_processor.cc
+++ /dev/null
@@ -1,143 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "DualIrDepthResultProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "dual_ir_depth_result_processor.h"
-
-#include <inttypes.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-
-namespace android {
-namespace google_camera_hal {
-std::unique_ptr<DualIrDepthResultProcessor> DualIrDepthResultProcessor::Create(
-    InternalStreamManager* internal_stream_manager) {
-  if (internal_stream_manager == nullptr) {
-    ALOGE("%s: internal_stream_manager is null.", __FUNCTION__);
-    return nullptr;
-  }
-
-  auto result_processor = std::unique_ptr<DualIrDepthResultProcessor>(
-      new DualIrDepthResultProcessor(internal_stream_manager));
-  if (result_processor == nullptr) {
-    ALOGE("%s: Failed to create DualIrDepthResultProcessor.", __FUNCTION__);
-    return nullptr;
-  }
-
-  return result_processor;
-}
-
-DualIrDepthResultProcessor::DualIrDepthResultProcessor(
-    InternalStreamManager* internal_stream_manager)
-    : internal_stream_manager_(internal_stream_manager) {
-}
-
-void DualIrDepthResultProcessor::SetResultCallback(
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  process_capture_result_ = process_capture_result;
-  notify_ = notify;
-}
-
-status_t DualIrDepthResultProcessor::AddPendingRequests(
-    const std::vector<ProcessBlockRequest>& process_block_requests,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  // This is the last result processor. Sanity check if requests contains
-  // all remaining output buffers.
-  if (!hal_utils::AreAllRemainingBuffersRequested(process_block_requests,
-                                                  remaining_session_request)) {
-    ALOGE("%s: Some output buffers will not be completed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  return OK;
-}
-
-void DualIrDepthResultProcessor::ProcessResult(ProcessBlockResult block_result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  std::unique_ptr<CaptureResult> result = std::move(block_result.result);
-  if (result == nullptr) {
-    ALOGW("%s: block_result has a null result.", __FUNCTION__);
-    return;
-  }
-
-  if (process_capture_result_ == nullptr) {
-    ALOGE("%s: process_capture_result_ is null, dropping a result.",
-          __FUNCTION__);
-    return;
-  }
-
-  // Depth Process Block should not return result metadata
-  if (result->result_metadata != nullptr) {
-    ALOGE("%s: non-null result metadata received from the depth process block",
-          __FUNCTION__);
-    return;
-  }
-
-  // Depth Process Block only returns depth stream buffer, so recycle any input
-  // buffers to internal stream manager and forward the depth buffer to the
-  // framework right away.
-  for (auto& buffer : result->input_buffers) {
-    status_t res = internal_stream_manager_->ReturnStreamBuffer(buffer);
-    if (res != OK) {
-      ALOGE(
-          "%s: Failed to returned internal buffer[buffer_handle:%p, "
-          "stream_id:%d, buffer_id%" PRIu64 "].",
-          __FUNCTION__, buffer.buffer, buffer.stream_id, buffer.buffer_id);
-    } else {
-      ALOGV(
-          "%s: Successfully returned internal buffer[buffer_handle:%p, "
-          "stream_id:%d, buffer_id%" PRIu64 "].",
-          __FUNCTION__, buffer.buffer, buffer.stream_id, buffer.buffer_id);
-    }
-  }
-}
-
-void DualIrDepthResultProcessor::Notify(
-    const ProcessBlockNotifyMessage& block_message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  const NotifyMessage& message = block_message.message;
-  if (notify_ == nullptr) {
-    ALOGE("%s: notify_ is null, dropping a message", __FUNCTION__);
-    return;
-  }
-
-  if (message.type != MessageType::kError) {
-    ALOGE(
-        "%s: depth result processor is not supposed to return shutter, "
-        "dropping a message.",
-        __FUNCTION__);
-    return;
-  }
-
-  notify_(message);
-}
-
-status_t DualIrDepthResultProcessor::FlushPendingRequests() {
-  ATRACE_CALL();
-  return INVALID_OPERATION;
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/google_camera_hal/dual_ir_depth_result_processor.h b/common/hal/google_camera_hal/dual_ir_depth_result_processor.h
deleted file mode 100644
index 6641e11..0000000
--- a/common/hal/google_camera_hal/dual_ir_depth_result_processor.h
+++ /dev/null
@@ -1,65 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_DEPTH_RESULT_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_DEPTH_RESULT_PROCESSOR_H_
-
-#include "internal_stream_manager.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-class DualIrDepthResultProcessor : public ResultProcessor {
- public:
-  static std::unique_ptr<DualIrDepthResultProcessor> Create(
-      InternalStreamManager* internal_stream_manager);
-
-  virtual ~DualIrDepthResultProcessor() = default;
-
-  // Override functions of ResultProcessor start.
-  void SetResultCallback(
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
-
-  status_t AddPendingRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  void ProcessResult(ProcessBlockResult block_result) override;
-
-  void Notify(const ProcessBlockNotifyMessage& block_message) override;
-
-  status_t FlushPendingRequests() override;
-  // Override functions of ResultProcessor end.
-
- protected:
-  DualIrDepthResultProcessor(InternalStreamManager* internal_stream_manager);
-
- private:
-  InternalStreamManager* internal_stream_manager_ = nullptr;
-
-  std::mutex callback_lock_;
-
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_DEPTH_RESULT_PROCESSOR_H_
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/dual_ir_request_processor.cc b/common/hal/google_camera_hal/dual_ir_request_processor.cc
deleted file mode 100644
index b8aa769..0000000
--- a/common/hal/google_camera_hal/dual_ir_request_processor.cc
+++ /dev/null
@@ -1,165 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//#define LOG_NDEBUG 0
-#define LOG_TAG "GCH_DualIrRequestProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "dual_ir_request_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<DualIrRequestProcessor> DualIrRequestProcessor::Create(
-    CameraDeviceSessionHwl* device_session_hwl, uint32_t lead_ir_camera_id) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return nullptr;
-  }
-
-  // Check there are two physical cameras.
-  std::vector<uint32_t> camera_ids = device_session_hwl->GetPhysicalCameraIds();
-  if (camera_ids.size() != 2) {
-    ALOGE("%s: Only support two IR cameras but there are %zu cameras.",
-          __FUNCTION__, camera_ids.size());
-    return nullptr;
-  }
-
-  // TODO(b/129017376): Figure out default IR camera ID from static metadata.
-  // Assume the first physical camera is the default for now.
-  auto request_processor = std::unique_ptr<DualIrRequestProcessor>(
-      new DualIrRequestProcessor(lead_ir_camera_id));
-  if (request_processor == nullptr) {
-    ALOGE("%s: Creating DualIrRequestProcessor failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  return request_processor;
-}
-
-DualIrRequestProcessor::DualIrRequestProcessor(uint32_t lead_camera_id)
-    : kLeadCameraId(lead_camera_id) {
-}
-
-status_t DualIrRequestProcessor::ConfigureStreams(
-    InternalStreamManager* /*internal_stream_manager*/,
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (process_block_stream_config == nullptr) {
-    ALOGE("%s: process_block_stream_config is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  process_block_stream_config->streams = stream_config.streams;
-  process_block_stream_config->operation_mode = stream_config.operation_mode;
-  process_block_stream_config->session_params =
-      HalCameraMetadata::Clone(stream_config.session_params.get());
-  process_block_stream_config->stream_config_counter =
-      stream_config.stream_config_counter;
-  process_block_stream_config->log_id = stream_config.log_id;
-
-  for (auto& stream : process_block_stream_config->streams) {
-    // Assign all logical streams to the lead camera.
-    if (!stream.is_physical_camera_stream) {
-      stream.is_physical_camera_stream = true;
-      stream.physical_camera_id = kLeadCameraId;
-    }
-
-    stream_physical_camera_ids_[stream.id] = stream.physical_camera_id;
-  }
-
-  return OK;
-}
-
-status_t DualIrRequestProcessor::SetProcessBlock(
-    std::unique_ptr<ProcessBlock> process_block) {
-  ATRACE_CALL();
-  if (process_block == nullptr) {
-    ALOGE("%s: process_block is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ != nullptr) {
-    ALOGE("%s: Already configured.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  process_block_ = std::move(process_block);
-  return OK;
-}
-
-status_t DualIrRequestProcessor::ProcessRequest(const CaptureRequest& request) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ == nullptr) {
-    ALOGE("%s: Not configured yet.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  uint32_t frame_number = request.frame_number;
-
-  // Create one physical request for each physical camera.
-  // Map from camera_id to the camera's request.
-  std::map<uint32_t, CaptureRequest> requests;
-
-  for (auto& buffer : request.output_buffers) {
-    uint32_t camera_id = stream_physical_camera_ids_[buffer.stream_id];
-    CaptureRequest* physical_request = nullptr;
-
-    auto request_iter = requests.find(camera_id);
-    if (request_iter == requests.end()) {
-      physical_request = &requests[camera_id];
-      physical_request->frame_number = frame_number;
-      // TODO: Combine physical camera settings?
-      physical_request->settings =
-          HalCameraMetadata::Clone(request.settings.get());
-    } else {
-      physical_request = &request_iter->second;
-    }
-    physical_request->output_buffers.push_back(buffer);
-  }
-
-  // Construct block requests.
-  std::vector<ProcessBlockRequest> block_requests;
-  for (auto& [camera_id, physical_request] : requests) {
-    ProcessBlockRequest block_request = {
-        .request_id = camera_id,
-        .request = std::move(physical_request),
-    };
-
-    block_requests.push_back(std::move(block_request));
-  }
-
-  return process_block_->ProcessRequests(block_requests, request);
-}
-
-status_t DualIrRequestProcessor::Flush() {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ == nullptr) {
-    return OK;
-  }
-
-  return process_block_->Flush();
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/dual_ir_request_processor.h b/common/hal/google_camera_hal/dual_ir_request_processor.h
deleted file mode 100644
index 45ab617..0000000
--- a/common/hal/google_camera_hal/dual_ir_request_processor.h
+++ /dev/null
@@ -1,73 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_REQUEST_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_REQUEST_PROCESSOR_H_
-
-#include "process_block.h"
-#include "request_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// DualIrRequestProcessor implements a RequestProcessor handling realtime
-// requests for a logical camera consisting of two IR camera sensors.
-class DualIrRequestProcessor : public RequestProcessor {
- public:
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of this DualIrRequestProcessor.
-  // lead_camera_id is the lead IR camera ID. Logical streams will be
-  // assigned to the lead IR camera.
-  static std::unique_ptr<DualIrRequestProcessor> Create(
-      CameraDeviceSessionHwl* device_session_hwl, uint32_t lead_camera_id);
-
-  virtual ~DualIrRequestProcessor() = default;
-
-  // Override functions of RequestProcessor start.
-  status_t ConfigureStreams(
-      InternalStreamManager* internal_stream_manager,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config) override;
-
-  status_t SetProcessBlock(std::unique_ptr<ProcessBlock> process_block) override;
-
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions of RequestProcessor end.
-
- protected:
-  DualIrRequestProcessor(uint32_t lead_camera_id);
-
- private:
-  // ID of the lead IR camera. All logical streams will be assigned to the
-  // lead camera.
-  const uint32_t kLeadCameraId;
-
-  std::mutex process_block_lock_;
-
-  // Protected by process_block_lock_.
-  std::unique_ptr<ProcessBlock> process_block_;
-
-  // Map from a stream ID to the physical camera ID the stream belongs to.
-  // Protected by process_block_lock_.
-  std::map<int32_t, uint32_t> stream_physical_camera_ids_;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_REQUEST_PROCESSOR_H_
diff --git a/common/hal/google_camera_hal/dual_ir_result_request_processor.cc b/common/hal/google_camera_hal/dual_ir_result_request_processor.cc
deleted file mode 100644
index 0e3819d..0000000
--- a/common/hal/google_camera_hal/dual_ir_result_request_processor.cc
+++ /dev/null
@@ -1,356 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_DualIrResultRequestProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "dual_ir_result_request_processor.h"
-
-#include <inttypes.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<DualIrResultRequestProcessor>
-DualIrResultRequestProcessor::Create(CameraDeviceSessionHwl* device_session_hwl,
-                                     const StreamConfiguration& stream_config,
-                                     uint32_t lead_camera_id) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr.", __FUNCTION__);
-    return nullptr;
-  }
-
-  uint32_t camera_id = device_session_hwl->GetCameraId();
-  auto result_processor = std::unique_ptr<DualIrResultRequestProcessor>(
-      new DualIrResultRequestProcessor(stream_config, camera_id,
-                                       lead_camera_id));
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating DualIrResultRequestProcessor failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  return result_processor;
-}
-
-DualIrResultRequestProcessor::DualIrResultRequestProcessor(
-    const StreamConfiguration& stream_config, uint32_t logical_camera_id,
-    uint32_t lead_camera_id)
-    : kLogicalCameraId(logical_camera_id), kLeadCameraId(lead_camera_id) {
-  ATRACE_CALL();
-  // Initialize stream ID -> camera ID map based on framework's stream
-  // configuration.
-  for (auto& stream : stream_config.streams) {
-    if (stream.is_physical_camera_stream) {
-      stream_camera_ids_[stream.id] = stream.physical_camera_id;
-    } else {
-      stream_camera_ids_[stream.id] = kLogicalCameraId;
-    }
-  }
-}
-
-void DualIrResultRequestProcessor::SetResultCallback(
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  process_capture_result_ = process_capture_result;
-  notify_ = notify;
-}
-
-bool DualIrResultRequestProcessor::IsFrameworkPhyiscalStream(
-    int32_t stream_id, uint32_t* physical_camera_id) const {
-  ATRACE_CALL();
-  auto camera_id_iter = stream_camera_ids_.find(stream_id);
-  if (camera_id_iter == stream_camera_ids_.end()) {
-    ALOGE("%s: Cannot find camera ID for stream %u", __FUNCTION__, stream_id);
-    return false;
-  }
-
-  uint32_t camera_id = camera_id_iter->second;
-  if (camera_id == kLogicalCameraId) {
-    return false;
-  }
-
-  if (physical_camera_id != nullptr) {
-    *physical_camera_id = camera_id;
-  }
-
-  return true;
-}
-
-status_t DualIrResultRequestProcessor::AddPendingPhysicalCameraMetadata(
-    const ProcessBlockRequest& block_request,
-    std::map<uint32_t, std::unique_ptr<HalCameraMetadata>>* physical_metadata) {
-  ATRACE_CALL();
-  if (physical_metadata == nullptr) {
-    ALOGE("%s: physical_metadata is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  for (auto& buffer : block_request.request.output_buffers) {
-    uint32_t physical_camera_id;
-    if (IsFrameworkPhyiscalStream(buffer.stream_id, &physical_camera_id)) {
-      // Add physical_camera_id to physical_metadata.
-      (*physical_metadata)[physical_camera_id] = nullptr;
-    }
-  }
-
-  return OK;
-}
-
-status_t DualIrResultRequestProcessor::AddPendingRequests(
-    const std::vector<ProcessBlockRequest>& process_block_requests,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  // This is the last result processor. Sanity check if requests contains
-  // all remaining output buffers.
-  if (!hal_utils::AreAllRemainingBuffersRequested(process_block_requests,
-                                                  remaining_session_request)) {
-    ALOGE("%s: Some output buffers will not be completed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  // Create new pending result metadata.
-  PendingResultMetadata pending_result_metadata;
-  for (auto& block_request : process_block_requests) {
-    status_t res = AddPendingPhysicalCameraMetadata(
-        block_request, &pending_result_metadata.physical_metadata);
-    if (res != OK) {
-      ALOGE("%s: Failed to fill pending physical camera metadata: %s(%d)",
-            __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-  }
-
-  uint32_t frame_number = process_block_requests[0].request.frame_number;
-
-  std::lock_guard<std::mutex> lock(pending_result_metadata_mutex_);
-  pending_result_metadata_[frame_number] = std::move(pending_result_metadata);
-
-  return OK;
-}
-
-void DualIrResultRequestProcessor::TrySendingResultMetadataLocked(
-    uint32_t frame_number) {
-  ATRACE_CALL();
-  auto pending_result_metadata_iter =
-      pending_result_metadata_.find(frame_number);
-  if (pending_result_metadata_iter == pending_result_metadata_.end()) {
-    ALOGE("%s: Can't find pending result for frame number %u", __FUNCTION__,
-          frame_number);
-    return;
-  }
-
-  // Check if we got result metadata from all cameras for this frame.
-  auto& pending_result_metadata = pending_result_metadata_iter->second;
-  if (pending_result_metadata.metadata == nullptr) {
-    // No metadata for logical camera yet.
-    return;
-  }
-
-  for (auto& [camera_id, metadata] : pending_result_metadata.physical_metadata) {
-    if (metadata == nullptr) {
-      // No metadata for this physical camera yet.
-      return;
-    }
-  }
-
-  // Prepare the result.
-  auto result = std::make_unique<CaptureResult>();
-  result->frame_number = frame_number;
-  result->partial_result = 1;
-  result->result_metadata = std::move(pending_result_metadata.metadata);
-
-  for (auto& [camera_id, metadata] : pending_result_metadata.physical_metadata) {
-    PhysicalCameraMetadata physical_metadata = {
-        .physical_camera_id = camera_id,
-        .metadata = std::move(metadata),
-    };
-
-    result->physical_metadata.push_back(std::move(physical_metadata));
-  }
-
-  process_capture_result_(std::move(result));
-  pending_result_metadata_.erase(pending_result_metadata_iter);
-}
-
-status_t DualIrResultRequestProcessor::ProcessResultMetadata(
-    uint32_t frame_number, uint32_t physical_camera_id,
-    std::unique_ptr<HalCameraMetadata> result_metadata) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(pending_result_metadata_mutex_);
-  auto pending_result_metadata_iter =
-      pending_result_metadata_.find(frame_number);
-  if (pending_result_metadata_iter == pending_result_metadata_.end()) {
-    ALOGE("%s: frame number %u is not expected.", __FUNCTION__, frame_number);
-    return BAD_VALUE;
-  }
-
-  auto& pending_result_metadata = pending_result_metadata_iter->second;
-
-  if (physical_camera_id == kLeadCameraId) {
-    if (pending_result_metadata.metadata != nullptr) {
-      ALOGE("%s: Already received metadata from camera %u for frame %u",
-            __FUNCTION__, physical_camera_id, frame_number);
-      return UNKNOWN_ERROR;
-    }
-
-    // Set lead camera id to multi camera metadata
-    std::string activePhysicalId = std::to_string(kLeadCameraId);
-    if (OK != result_metadata->Set(
-                  ANDROID_LOGICAL_MULTI_CAMERA_ACTIVE_PHYSICAL_ID,
-                  reinterpret_cast<const uint8_t*>(activePhysicalId.c_str()),
-                  static_cast<uint32_t>(activePhysicalId.size() + 1))) {
-      ALOGE("Failure in setting active physical camera");
-    }
-
-    // Logical camera's result metadata is a clone of the lead camera's
-    // result metadata.
-    pending_result_metadata.metadata = std::move(result_metadata);
-  }
-
-  // Add the physical result metadata to pending result metadata if needed.
-  auto physical_metadata_iter =
-      pending_result_metadata.physical_metadata.find(physical_camera_id);
-  if (physical_metadata_iter != pending_result_metadata.physical_metadata.end()) {
-    // If the pending result metadata have physical metadata for a physical
-    // camera ID, the physical result metadata is needed.
-    if (physical_metadata_iter->second != nullptr) {
-      ALOGE("%s: Already received result metadata for camera %u for frame %u",
-            __FUNCTION__, physical_camera_id, frame_number);
-      return UNKNOWN_ERROR;
-    }
-
-    if (physical_camera_id == kLeadCameraId) {
-      // If this physical camera is the lead camera, clone the result metadata
-      // from the logical camera's result metadata.
-      physical_metadata_iter->second =
-          HalCameraMetadata::Clone(pending_result_metadata.metadata.get());
-    } else {
-      physical_metadata_iter->second = std::move(result_metadata);
-    }
-  }
-
-  TrySendingResultMetadataLocked(frame_number);
-  return OK;
-}
-
-void DualIrResultRequestProcessor::ProcessResult(ProcessBlockResult block_result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (block_result.result == nullptr) {
-    ALOGW("%s: Received a nullptr result.", __FUNCTION__);
-    return;
-  }
-
-  if (process_capture_result_ == nullptr) {
-    ALOGE("%s: process_capture_result_ is nullptr. Dropping a result.",
-          __FUNCTION__);
-    return;
-  }
-
-  // Request ID is set to camera ID by DualIrRequestProcessor.
-  uint32_t camera_id = block_result.request_id;
-
-  // Process result metadata separately because there could be two result
-  // metadata (one from each camera).
-  auto result = std::move(block_result.result);
-  if (result->result_metadata != nullptr) {
-    status_t res = ProcessResultMetadata(result->frame_number, camera_id,
-                                         std::move(result->result_metadata));
-    if (res != OK) {
-      ALOGE("%s: Processing result metadata failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      // Continue processing rest of the result.
-    }
-  }
-
-  if (result->output_buffers.size() == 0) {
-    // No buffer to send out.
-    return;
-  }
-
-  process_capture_result_(std::move(result));
-}
-
-void DualIrResultRequestProcessor::Notify(
-    const ProcessBlockNotifyMessage& block_message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (notify_ == nullptr) {
-    ALOGE("%s: notify_ is nullptr. Dropping a message.", __FUNCTION__);
-    return;
-  }
-
-  const NotifyMessage& message = block_message.message;
-
-  // Request ID is set to camera ID by DualIrRequestProcessor.
-  uint32_t camera_id = block_message.request_id;
-  if (message.type == MessageType::kShutter && camera_id != kLeadCameraId) {
-    // Only send out shutters from the lead camera.
-    return;
-  }
-
-  // TODO(b/129017376): if there are multiple requests for this frame, wait for
-  // all notification to arrive before calling process_capture_result_().
-  notify_(block_message.message);
-}
-
-status_t DualIrResultRequestProcessor::ConfigureStreams(
-    InternalStreamManager* /*internal_stream_manager*/,
-    const StreamConfiguration& /*stream_config*/,
-    StreamConfiguration* /*process_block_stream_config*/) {
-  ATRACE_CALL();
-  // TODO(b/131618554): Implement this function.
-
-  return INVALID_OPERATION;
-}
-
-status_t DualIrResultRequestProcessor::SetProcessBlock(
-    std::unique_ptr<ProcessBlock> /*process_block*/) {
-  ATRACE_CALL();
-  // TODO(b/131618554): Implement this function.
-
-  return INVALID_OPERATION;
-}
-
-status_t DualIrResultRequestProcessor::ProcessRequest(
-    const CaptureRequest& /*request*/) {
-  ATRACE_CALL();
-  // TODO(b/131618554): Implement this function.
-
-  return INVALID_OPERATION;
-}
-
-status_t DualIrResultRequestProcessor::Flush() {
-  ATRACE_CALL();
-  // TODO(b/131618554): Implement this function.
-
-  return INVALID_OPERATION;
-}
-
-status_t DualIrResultRequestProcessor::FlushPendingRequests() {
-  ATRACE_CALL();
-  return OK;
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/dual_ir_result_request_processor.h b/common/hal/google_camera_hal/dual_ir_result_request_processor.h
deleted file mode 100644
index 534fa71..0000000
--- a/common/hal/google_camera_hal/dual_ir_result_request_processor.h
+++ /dev/null
@@ -1,135 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_RESULT_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_RESULT_PROCESSOR_H_
-
-#include <map>
-
-#include "request_processor.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// DualIrResultRequestProcessor implements a ResultProcessor for a logical
-// camera that consists of two IR cameras. It also implements a RequestProcessor
-// for the logical camera to generate depth.
-class DualIrResultRequestProcessor : public ResultProcessor,
-                                     public RequestProcessor {
- public:
-  // Create a DualIrResultRequestProcessor.
-  // device_session_hwl is owned by the client and must be valid during the life
-  // cycle of this DualIrResultRequestProcessor.
-  // stream_config is the stream configuration set by the framework. It's not
-  // the process block's stream configuration.
-  // lead_camera_id is the ID of the lead IR camera.
-  static std::unique_ptr<DualIrResultRequestProcessor> Create(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config, uint32_t lead_camera_id);
-
-  virtual ~DualIrResultRequestProcessor() = default;
-
-  // Override functions of ResultProcessor start.
-  void SetResultCallback(
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
-
-  status_t AddPendingRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  void ProcessResult(ProcessBlockResult block_result) override;
-
-  void Notify(const ProcessBlockNotifyMessage& block_message) override;
-
-  status_t FlushPendingRequests() override;
-  // Override functions of ResultProcessor end.
-
-  // Override functions of RequestProcessor start.
-  status_t ConfigureStreams(
-      InternalStreamManager* internal_stream_manager,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config) override;
-
-  status_t SetProcessBlock(std::unique_ptr<ProcessBlock> process_block) override;
-
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions of RequestProcessor end.
-
- protected:
-  DualIrResultRequestProcessor(const StreamConfiguration& stream_config,
-                               uint32_t logical_camera_id,
-                               uint32_t lead_camera_id);
-
- private:
-  const uint32_t kLogicalCameraId;
-  const uint32_t kLeadCameraId;
-
-  // Define a pending result metadata
-  struct PendingResultMetadata {
-    // Result metadata for the logical camera.
-    std::unique_ptr<HalCameraMetadata> metadata;
-    // Map from a physical camera ID to the physical camera's result metadata.
-    std::map<uint32_t, std::unique_ptr<HalCameraMetadata>> physical_metadata;
-  };
-
-  // If a stream is a physical stream configured by the framework.
-  // stream_id is the ID of the stream.
-  // physical_camera_id will be filled with the physical camera ID if this
-  // method return true.
-  bool IsFrameworkPhyiscalStream(int32_t stream_id,
-                                 uint32_t* physical_camera_id) const;
-
-  // Add pending physical camera's result metadata to the map.
-  // block_request is a block request used figure out pending results.
-  // physical_metadata is the map to add the pending physical camera's result
-  // metadata to.
-  status_t AddPendingPhysicalCameraMetadata(
-      const ProcessBlockRequest& block_request,
-      std::map<uint32_t, std::unique_ptr<HalCameraMetadata>>* physical_metadata);
-
-  // Try to send result metadata for a frame number if all of it's result
-  // metadata are ready. Must have pending_result_metadata_mutex_ locked.
-  void TrySendingResultMetadataLocked(uint32_t frame_number);
-
-  // Process a result metadata and update the pending result metadata map.
-  status_t ProcessResultMetadata(
-      uint32_t frame_number, uint32_t physical_camera_id,
-      std::unique_ptr<HalCameraMetadata> result_metadata);
-
-  // Map from a stream ID to a camera ID based on framework stream configuration.
-  std::map<int32_t, uint32_t> stream_camera_ids_;
-
-  std::mutex pending_result_metadata_mutex_;
-
-  // Map from a frame number to the pending result metadata. Must be protected
-  // by pending_result_metadata_mutex_.
-  std::map<uint32_t, PendingResultMetadata> pending_result_metadata_;
-
-  std::mutex callback_lock_;
-
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_DUAL_IR_RESULT_PROCESSOR_H_
diff --git a/common/hal/google_camera_hal/hdrplus_capture_session.cc b/common/hal/google_camera_hal/hdrplus_capture_session.cc
deleted file mode 100644
index 456e8c9..0000000
--- a/common/hal/google_camera_hal/hdrplus_capture_session.cc
+++ /dev/null
@@ -1,683 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_HdrplusCaptureSession"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "hdrplus_capture_session.h"
-
-#include <cutils/properties.h>
-#include <inttypes.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <set>
-
-#include "hal_utils.h"
-#include "hdrplus_process_block.h"
-#include "hdrplus_request_processor.h"
-#include "hdrplus_result_processor.h"
-#include "realtime_process_block.h"
-#include "realtime_zsl_request_processor.h"
-#include "realtime_zsl_result_processor.h"
-#include "vendor_tag_defs.h"
-
-namespace android {
-namespace google_camera_hal {
-bool HdrplusCaptureSession::IsStreamConfigurationSupported(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return false;
-  }
-
-  uint32_t num_physical_cameras =
-      device_session_hwl->GetPhysicalCameraIds().size();
-  if (num_physical_cameras > 1) {
-    ALOGD("%s: HdrplusCaptureSession doesn't support %u physical cameras",
-          __FUNCTION__, num_physical_cameras);
-    return false;
-  }
-
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  if (hal_utils::IsStreamHdrplusCompatible(stream_config,
-                                           characteristics.get()) == false) {
-    return false;
-  }
-
-  if (!hal_utils::IsBayerCamera(characteristics.get())) {
-    ALOGD("%s: camera %d is not a bayer camera", __FUNCTION__,
-          device_session_hwl->GetCameraId());
-    return false;
-  }
-
-  ALOGI("%s: HDR+ is enabled", __FUNCTION__);
-  ALOGD("%s: HdrplusCaptureSession supports the stream config", __FUNCTION__);
-  return true;
-}
-
-std::unique_ptr<HdrplusCaptureSession> HdrplusCaptureSession::Create(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/,
-    NotifyFunc notify, HwlSessionCallback /*session_callback*/,
-    std::vector<HalStream>* hal_configured_streams,
-    CameraBufferAllocatorHwl* /*camera_allocator_hwl*/) {
-  ATRACE_CALL();
-  auto session =
-      std::unique_ptr<HdrplusCaptureSession>(new HdrplusCaptureSession());
-  if (session == nullptr) {
-    ALOGE("%s: Creating HdrplusCaptureSession failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  status_t res = session->Initialize(device_session_hwl, stream_config,
-                                     process_capture_result, notify,
-                                     hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Initializing HdrplusCaptureSession failed: %s (%d).",
-          __FUNCTION__, strerror(-res), res);
-    return nullptr;
-  }
-
-  return session;
-}
-
-HdrplusCaptureSession::~HdrplusCaptureSession() {
-  ATRACE_CALL();
-  if (device_session_hwl_ != nullptr) {
-    device_session_hwl_->DestroyPipelines();
-  }
-}
-
-status_t HdrplusCaptureSession::ConfigureStreams(
-    const StreamConfiguration& stream_config,
-    RequestProcessor* request_processor, ProcessBlock* process_block,
-    int32_t* raw_stream_id) {
-  ATRACE_CALL();
-  if (request_processor == nullptr || process_block == nullptr ||
-      raw_stream_id == nullptr) {
-    ALOGE(
-        "%s: request_processor (%p) or process_block (%p) is nullptr or "
-        "raw_stream_id (%p) is nullptr",
-        __FUNCTION__, request_processor, process_block, raw_stream_id);
-    return BAD_VALUE;
-  }
-
-  StreamConfiguration process_block_stream_config;
-  // Configure streams for request processor
-  status_t res = request_processor->ConfigureStreams(
-      internal_stream_manager_.get(), stream_config,
-      &process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream for request processor failed.", __FUNCTION__);
-    return res;
-  }
-
-  // Check all streams are configured.
-  if (stream_config.streams.size() > process_block_stream_config.streams.size()) {
-    ALOGE("%s: stream_config has %zu streams but only configured %zu streams",
-          __FUNCTION__, stream_config.streams.size(),
-          process_block_stream_config.streams.size());
-    return UNKNOWN_ERROR;
-  }
-
-  for (auto& stream : stream_config.streams) {
-    bool found = false;
-    for (auto& configured_stream : process_block_stream_config.streams) {
-      if (stream.id == configured_stream.id) {
-        found = true;
-        break;
-      }
-    }
-
-    if (!found) {
-      ALOGE("%s: Cannot find stream %u in configured streams.", __FUNCTION__,
-            stream.id);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  for (auto& configured_stream : process_block_stream_config.streams) {
-    if (configured_stream.format == kHdrplusRawFormat) {
-      *raw_stream_id = configured_stream.id;
-      break;
-    }
-  }
-
-  if (*raw_stream_id == -1) {
-    ALOGE("%s: Configuring stream fail due to wrong raw_stream_id",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Configure streams for process block.
-  res = process_block->ConfigureStreams(process_block_stream_config,
-                                        stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream for process block failed.", __FUNCTION__);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::ConfigureHdrplusStreams(
-    const StreamConfiguration& stream_config,
-    RequestProcessor* hdrplus_request_processor,
-    ProcessBlock* hdrplus_process_block) {
-  ATRACE_CALL();
-  if (hdrplus_process_block == nullptr || hdrplus_request_processor == nullptr) {
-    ALOGE("%s: hdrplus_process_block or hdrplus_request_processor is nullptr",
-          __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  StreamConfiguration process_block_stream_config;
-  // Configure streams for request processor
-  status_t res = hdrplus_request_processor->ConfigureStreams(
-      internal_stream_manager_.get(), stream_config,
-      &process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream for request processor failed.", __FUNCTION__);
-    return res;
-  }
-
-  // Check all streams are configured.
-  if (stream_config.streams.size() > process_block_stream_config.streams.size()) {
-    ALOGE("%s: stream_config has %zu streams but only configured %zu streams",
-          __FUNCTION__, stream_config.streams.size(),
-          process_block_stream_config.streams.size());
-    return UNKNOWN_ERROR;
-  }
-
-  for (auto& stream : stream_config.streams) {
-    bool found = false;
-    for (auto& configured_stream : process_block_stream_config.streams) {
-      if (stream.id == configured_stream.id) {
-        found = true;
-        break;
-      }
-    }
-
-    if (!found) {
-      ALOGE("%s: Cannot find stream %u in configured streams.", __FUNCTION__,
-            stream.id);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  // Configure streams for HDR+ process block.
-  res = hdrplus_process_block->ConfigureStreams(process_block_stream_config,
-                                                stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring hdrplus stream for process block failed.",
-          __FUNCTION__);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::BuildPipelines(
-    ProcessBlock* process_block, ProcessBlock* hdrplus_process_block,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-  if (process_block == nullptr || hal_configured_streams == nullptr) {
-    ALOGE("%s: process_block (%p) or hal_configured_streams (%p) is nullptr",
-          __FUNCTION__, process_block, hal_configured_streams);
-    return BAD_VALUE;
-  }
-
-  status_t res = device_session_hwl_->BuildPipelines();
-  if (res != OK) {
-    ALOGE("%s: Building pipelines failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  res = process_block->GetConfiguredHalStreams(hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Getting HAL streams failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  std::vector<HalStream> hdrplus_hal_configured_streams;
-  res = hdrplus_process_block->GetConfiguredHalStreams(
-      &hdrplus_hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Getting HDR+ HAL streams failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  // Combine realtime and HDR+ hal stream.
-  // Only usage of internal raw stream is different, so combine usage directly
-  uint64_t consumer_usage = 0;
-  for (uint32_t i = 0; i < hdrplus_hal_configured_streams.size(); i++) {
-    if (hdrplus_hal_configured_streams[i].override_format == kHdrplusRawFormat) {
-      consumer_usage = hdrplus_hal_configured_streams[i].consumer_usage;
-      break;
-    }
-  }
-
-  for (uint32_t i = 0; i < hal_configured_streams->size(); i++) {
-    if (hal_configured_streams->at(i).override_format == kHdrplusRawFormat) {
-      hal_configured_streams->at(i).consumer_usage = consumer_usage;
-      if (hal_configured_streams->at(i).max_buffers < kRawMinBufferCount) {
-        hal_configured_streams->at(i).max_buffers = kRawMinBufferCount;
-      }
-      // Allocate internal raw stream buffers
-      uint32_t additional_num_buffers =
-          (hal_configured_streams->at(i).max_buffers >= kRawBufferCount)
-              ? 0
-              : (kRawBufferCount - hal_configured_streams->at(i).max_buffers);
-      res = internal_stream_manager_->AllocateBuffers(
-          hal_configured_streams->at(i), additional_num_buffers);
-      if (res != OK) {
-        ALOGE("%s: AllocateBuffers failed.", __FUNCTION__);
-        return UNKNOWN_ERROR;
-      }
-      break;
-    }
-  }
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::ConnectProcessChain(
-    RequestProcessor* request_processor,
-    std::unique_ptr<ProcessBlock> process_block,
-    std::unique_ptr<ResultProcessor> result_processor) {
-  ATRACE_CALL();
-  if (request_processor == nullptr) {
-    ALOGE("%s: request_processor is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  status_t res = process_block->SetResultProcessor(std::move(result_processor));
-  if (res != OK) {
-    ALOGE("%s: Setting result process in process block failed.", __FUNCTION__);
-    return res;
-  }
-
-  res = request_processor->SetProcessBlock(std::move(process_block));
-  if (res != OK) {
-    ALOGE(
-        "%s: Setting process block for HdrplusRequestProcessor failed: %s(%d)",
-        __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::SetupRealtimeProcessChain(
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::unique_ptr<ProcessBlock>* realtime_process_block,
-    std::unique_ptr<ResultProcessor>* realtime_result_processor,
-    int32_t* raw_stream_id) {
-  ATRACE_CALL();
-  if (realtime_process_block == nullptr ||
-      realtime_result_processor == nullptr || raw_stream_id == nullptr) {
-    ALOGE(
-        "%s: realtime_process_block(%p) or realtime_result_processor(%p) or "
-        "raw_stream_id(%p) is nullptr",
-        __FUNCTION__, realtime_process_block, realtime_result_processor,
-        raw_stream_id);
-    return BAD_VALUE;
-  }
-  // Create realtime process block.
-  auto process_block = RealtimeProcessBlock::Create(device_session_hwl_);
-  if (process_block == nullptr) {
-    ALOGE("%s: Creating RealtimeProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Create realtime request processor.
-  request_processor_ = RealtimeZslRequestProcessor::Create(
-      device_session_hwl_, HAL_PIXEL_FORMAT_RAW10);
-  if (request_processor_ == nullptr) {
-    ALOGE("%s: Creating RealtimeZslsRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  status_t res = ConfigureStreams(stream_config, request_processor_.get(),
-                                  process_block.get(), raw_stream_id);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  // Create realtime result processor.
-  auto result_processor = RealtimeZslResultProcessor::Create(
-      internal_stream_manager_.get(), *raw_stream_id, HAL_PIXEL_FORMAT_RAW10);
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating RealtimeZslResultProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  result_processor->SetResultCallback(process_capture_result, notify,
-                                      /*process_batch_capture_result=*/nullptr);
-
-  *realtime_process_block = std::move(process_block);
-  *realtime_result_processor = std::move(result_processor);
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::SetupHdrplusProcessChain(
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::unique_ptr<ProcessBlock>* hdrplus_process_block,
-    std::unique_ptr<ResultProcessor>* hdrplus_result_processor,
-    int32_t raw_stream_id) {
-  ATRACE_CALL();
-  if (hdrplus_process_block == nullptr || hdrplus_result_processor == nullptr) {
-    ALOGE(
-        "%s: hdrplus_process_block(%p) or hdrplus_result_processor(%p) is "
-        "nullptr",
-        __FUNCTION__, hdrplus_process_block, hdrplus_result_processor);
-    return BAD_VALUE;
-  }
-
-  // Create hdrplus process block.
-  auto process_block = HdrplusProcessBlock::Create(
-      device_session_hwl_, device_session_hwl_->GetCameraId());
-  if (process_block == nullptr) {
-    ALOGE("%s: Creating HdrplusProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Create hdrplus request processor.
-  hdrplus_request_processor_ = HdrplusRequestProcessor::Create(
-      device_session_hwl_, raw_stream_id, device_session_hwl_->GetCameraId());
-  if (hdrplus_request_processor_ == nullptr) {
-    ALOGE("%s: Creating HdrplusRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Create hdrplus result processor.
-  auto result_processor = HdrplusResultProcessor::Create(
-      internal_stream_manager_.get(), raw_stream_id);
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating HdrplusResultProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  result_processor->SetResultCallback(process_capture_result, notify,
-                                      /*process_batch_capture_result=*/nullptr);
-
-  status_t res = ConfigureHdrplusStreams(
-      stream_config, hdrplus_request_processor_.get(), process_block.get());
-  if (res != OK) {
-    ALOGE("%s: Configuring hdrplus stream failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  *hdrplus_process_block = std::move(process_block);
-  *hdrplus_result_processor = std::move(result_processor);
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::Initialize(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-  if (!IsStreamConfigurationSupported(device_session_hwl, stream_config)) {
-    ALOGE("%s: stream configuration is not supported.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(VendorTagIds::kHdrUsageMode, &entry);
-  if (res == OK) {
-    hdr_mode_ = static_cast<HdrMode>(entry.data.u8[0]);
-  }
-
-  for (auto stream : stream_config.streams) {
-    if (utils::IsPreviewStream(stream)) {
-      hal_preview_stream_id_ = stream.id;
-      break;
-    }
-  }
-  device_session_hwl_ = device_session_hwl;
-  internal_stream_manager_ = InternalStreamManager::Create();
-  if (internal_stream_manager_ == nullptr) {
-    ALOGE("%s: Cannot create internal stream manager.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Create result dispatcher
-  result_dispatcher_ =
-      ResultDispatcher::Create(kPartialResult, process_capture_result,
-                               /*process_batch_capture_result=*/nullptr, notify,
-                               stream_config, "HdrplusDispatcher");
-  if (result_dispatcher_ == nullptr) {
-    ALOGE("%s: Cannot create result dispatcher.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  device_session_notify_ = notify;
-  process_capture_result_ =
-      ProcessCaptureResultFunc([this](std::unique_ptr<CaptureResult> result) {
-        ProcessCaptureResult(std::move(result));
-      });
-  notify_ = NotifyFunc(
-      [this](const NotifyMessage& message) { NotifyHalMessage(message); });
-
-  // Setup realtime process chain
-  int32_t raw_stream_id = -1;
-  std::unique_ptr<ProcessBlock> realtime_process_block;
-  std::unique_ptr<ResultProcessor> realtime_result_processor;
-
-  res = SetupRealtimeProcessChain(stream_config, process_capture_result_,
-                                  notify_, &realtime_process_block,
-                                  &realtime_result_processor, &raw_stream_id);
-  if (res != OK) {
-    ALOGE("%s: SetupRealtimeProcessChain fail: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  // Setup hdrplus process chain
-  std::unique_ptr<ProcessBlock> hdrplus_process_block;
-  std::unique_ptr<ResultProcessor> hdrplus_result_processor;
-
-  res = SetupHdrplusProcessChain(stream_config, process_capture_result_,
-                                 notify_, &hdrplus_process_block,
-                                 &hdrplus_result_processor, raw_stream_id);
-  if (res != OK) {
-    ALOGE("%s: SetupHdrplusProcessChain fail: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  // Realtime and HDR+ streams are configured
-  // Start to build pipleline
-  res = BuildPipelines(realtime_process_block.get(),
-                       hdrplus_process_block.get(), hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Building pipelines failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  res = PurgeHalConfiguredStream(stream_config, hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Removing internal streams from configured stream failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  // Connect realtime process chain
-  res = ConnectProcessChain(request_processor_.get(),
-                            std::move(realtime_process_block),
-                            std::move(realtime_result_processor));
-  if (res != OK) {
-    ALOGE("%s: Connecting process chain failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  // Connect HDR+ process chain
-  res = ConnectProcessChain(hdrplus_request_processor_.get(),
-                            std::move(hdrplus_process_block),
-                            std::move(hdrplus_result_processor));
-  if (res != OK) {
-    ALOGE("%s: Connecting HDR+ process chain failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t HdrplusCaptureSession::ProcessRequest(const CaptureRequest& request) {
-  ATRACE_CALL();
-  bool is_hdrplus_request =
-      hal_utils::IsRequestHdrplusCompatible(request, hal_preview_stream_id_);
-
-  status_t res = result_dispatcher_->AddPendingRequest(request);
-  if (res != OK) {
-    ALOGE("%s: frame(%d) fail to AddPendingRequest", __FUNCTION__,
-          request.frame_number);
-    return BAD_VALUE;
-  }
-
-  if (is_hdrplus_request) {
-    ALOGI("%s: hdrplus snapshot (%d), output stream size:%zu", __FUNCTION__,
-          request.frame_number, request.output_buffers.size());
-    res = hdrplus_request_processor_->ProcessRequest(request);
-    if (res != OK) {
-      ALOGI("%s: hdrplus snapshot frame(%d) request to realtime process",
-            __FUNCTION__, request.frame_number);
-      res = request_processor_->ProcessRequest(request);
-    }
-  } else {
-    res = request_processor_->ProcessRequest(request);
-  }
-
-  if (res != OK) {
-    ALOGE("%s: ProcessRequest (%d) fail and remove pending request",
-          __FUNCTION__, request.frame_number);
-    result_dispatcher_->RemovePendingRequest(request.frame_number);
-  }
-  return res;
-}
-
-status_t HdrplusCaptureSession::Flush() {
-  ATRACE_CALL();
-  return request_processor_->Flush();
-}
-
-void HdrplusCaptureSession::ProcessCaptureResult(
-    std::unique_ptr<CaptureResult> result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (result == nullptr) {
-    return;
-  }
-
-  if (result->result_metadata && hdr_mode_ != HdrMode::kHdrplusMode) {
-    device_session_hwl_->FilterResultMetadata(result->result_metadata.get());
-  }
-
-  status_t res = result_dispatcher_->AddResult(std::move(result));
-  if (res != OK) {
-    ALOGE("%s: fail to AddResult", __FUNCTION__);
-    return;
-  }
-}
-
-status_t HdrplusCaptureSession::PurgeHalConfiguredStream(
-    const StreamConfiguration& stream_config,
-    std::vector<HalStream>* hal_configured_streams) {
-  if (hal_configured_streams == nullptr) {
-    ALOGE("%s: HAL configured stream list is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::set<int32_t> framework_stream_id_set;
-  for (auto& stream : stream_config.streams) {
-    framework_stream_id_set.insert(stream.id);
-  }
-
-  std::vector<HalStream> configured_streams;
-  for (auto& hal_stream : *hal_configured_streams) {
-    if (framework_stream_id_set.find(hal_stream.id) !=
-        framework_stream_id_set.end()) {
-      configured_streams.push_back(hal_stream);
-    }
-  }
-  *hal_configured_streams = configured_streams;
-  return OK;
-}
-
-void HdrplusCaptureSession::NotifyHalMessage(const NotifyMessage& message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (device_session_notify_ == nullptr) {
-    ALOGE("%s: device_session_notify_ is nullptr. Dropping a message.",
-          __FUNCTION__);
-    return;
-  }
-
-  if (message.type == MessageType::kShutter) {
-    status_t res = result_dispatcher_->AddShutter(
-        message.message.shutter.frame_number,
-        message.message.shutter.timestamp_ns,
-        message.message.shutter.readout_timestamp_ns);
-    if (res != OK) {
-      ALOGE("%s: AddShutter for frame %u failed: %s (%d).", __FUNCTION__,
-            message.message.shutter.frame_number, strerror(-res), res);
-      return;
-    }
-  } else if (message.type == MessageType::kError) {
-    status_t res = result_dispatcher_->AddError(message.message.error);
-    if (res != OK) {
-      ALOGE("%s: AddError for frame %u failed: %s (%d).", __FUNCTION__,
-            message.message.error.frame_number, strerror(-res), res);
-      return;
-    }
-  } else {
-    ALOGW("%s: Unsupported message type: %u", __FUNCTION__, message.type);
-    device_session_notify_(message);
-  }
-}
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/google_camera_hal/hdrplus_capture_session.h b/common/hal/google_camera_hal/hdrplus_capture_session.h
deleted file mode 100644
index 29d8993..0000000
--- a/common/hal/google_camera_hal/hdrplus_capture_session.h
+++ /dev/null
@@ -1,163 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_CAPTURE_SESSION_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_CAPTURE_SESSION_H_
-
-#include "camera_buffer_allocator_hwl.h"
-#include "camera_device_session_hwl.h"
-#include "capture_session.h"
-#include "hwl_types.h"
-#include "request_processor.h"
-#include "result_dispatcher.h"
-#include "result_processor.h"
-#include "vendor_tag_types.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// HdrplusCaptureSession implements a CaptureSession that contains two
-// process chains (realtime and HDR+)
-//
-// 1. RealtimeZslRequestProcessor -> RealtimeProcessBlock ->
-//    RealtimeZslResultRequestProcessor
-// 2. HdrplusRequestProcessor -> HdrplusProcessBlock -> HdrplusResultProcessor
-//
-// It only supports a single physical camera device session.
-class HdrplusCaptureSession : public CaptureSession {
- public:
-  // Return if the device session HWL and stream configuration are supported.
-  static bool IsStreamConfigurationSupported(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config);
-
-  // Create a HdrplusCaptureSession.
-  //
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of HdrplusCaptureSession.
-  // stream_config is the stream configuration.
-  // process_capture_result is the callback function to notify results.
-  // process_batch_capture_result is the callback function to notify batched
-  // results.
-  // notify is the callback function to notify messages.
-  // hal_configured_streams will be filled with HAL configured streams.
-  // camera_allocator_hwl is owned by the caller and must be valid during the
-  // lifetime of HdrplusCaptureSession
-  static std::unique_ptr<HdrplusCaptureSession> Create(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result,
-      ProcessBatchCaptureResultFunc process_batch_capture_result,
-      NotifyFunc notify, HwlSessionCallback session_callback,
-      std::vector<HalStream>* hal_configured_streams,
-      CameraBufferAllocatorHwl* camera_allocator_hwl = nullptr);
-
-  virtual ~HdrplusCaptureSession();
-
-  // Override functions in CaptureSession start.
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions in CaptureSession end.
-
- protected:
-  HdrplusCaptureSession() = default;
-
- private:
-  static const uint32_t kRawBufferCount = 16;
-  static const uint32_t kRawMinBufferCount = 12;
-  static constexpr uint32_t kPartialResult = 1;
-  static const android_pixel_format_t kHdrplusRawFormat = HAL_PIXEL_FORMAT_RAW10;
-  status_t Initialize(CameraDeviceSessionHwl* device_session_hwl,
-                      const StreamConfiguration& stream_config,
-                      ProcessCaptureResultFunc process_capture_result,
-                      NotifyFunc notify,
-                      std::vector<HalStream>* hal_configured_streams);
-
-  // Setup realtime process chain
-  status_t SetupRealtimeProcessChain(
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      std::unique_ptr<ProcessBlock>* realtime_process_block,
-      std::unique_ptr<ResultProcessor>* realtime_result_processor,
-      int32_t* raw_stream_id);
-
-  // Setup hdrplus process chain
-  status_t SetupHdrplusProcessChain(
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      std::unique_ptr<ProcessBlock>* hdrplus_process_block,
-      std::unique_ptr<ResultProcessor>* hdrplus_result_processor,
-      int32_t raw_stream_id);
-
-  // Configure streams for request processor and process block.
-  status_t ConfigureStreams(const StreamConfiguration& stream_config,
-                            RequestProcessor* request_processor,
-                            ProcessBlock* process_block, int32_t* raw_stream_id);
-
-  // Configure hdrplus streams for request processor and process block.
-  status_t ConfigureHdrplusStreams(const StreamConfiguration& stream_config,
-                                   RequestProcessor* hdrplus_request_processor,
-                                   ProcessBlock* hdrplus_process_block);
-
-  // Build pipelines and return HAL configured streams.
-  // Allocate internal raw buffer
-  status_t BuildPipelines(ProcessBlock* process_block,
-                          ProcessBlock* hdrplus_process_block,
-                          std::vector<HalStream>* hal_configured_streams);
-
-  // Connect the process chain.
-  status_t ConnectProcessChain(RequestProcessor* request_processor,
-                               std::unique_ptr<ProcessBlock> process_block,
-                               std::unique_ptr<ResultProcessor> result_processor);
-
-  // Purge the hal_configured_streams such that only framework streams are left
-  status_t PurgeHalConfiguredStream(
-      const StreamConfiguration& stream_config,
-      std::vector<HalStream>* hal_configured_streams);
-
-  // Invoked when receiving a result from result processor.
-  void ProcessCaptureResult(std::unique_ptr<CaptureResult> result);
-
-  // Invoked when reciving a message from result processor.
-  void NotifyHalMessage(const NotifyMessage& message);
-
-  std::unique_ptr<RequestProcessor> request_processor_;
-
-  std::unique_ptr<RequestProcessor> hdrplus_request_processor_;
-  // device_session_hwl_ is owned by the client.
-  CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
-
-  std::unique_ptr<InternalStreamManager> internal_stream_manager_;
-
-  std::unique_ptr<ResultDispatcher> result_dispatcher_;
-
-  std::mutex callback_lock_;
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-  // For error notify to framework directly
-  NotifyFunc device_session_notify_;
-  // Use this stream id to check the request is HDR+ compatible
-  int32_t hal_preview_stream_id_ = -1;
-
-  HdrMode hdr_mode_ = HdrMode::kHdrplusMode;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_CAPTURE_SESSION_H_
diff --git a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
new file mode 100644
index 0000000..d349bf2
--- /dev/null
+++ b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
@@ -0,0 +1,9 @@
+package: "libgooglecamerahal.flags"
+container: "vendor"
+
+flag {
+  name: "zsl_video_denoise_in_hwl"
+  namespace: "camera_hal"
+  description: "Enable HWL ZSL video processing and disable GCH processing"
+  bug: "341748497"
+}
diff --git a/common/hal/google_camera_hal/realtime_zsl_request_processor.cc b/common/hal/google_camera_hal/realtime_zsl_request_processor.cc
index 8232456..6ddc47c 100644
--- a/common/hal/google_camera_hal/realtime_zsl_request_processor.cc
+++ b/common/hal/google_camera_hal/realtime_zsl_request_processor.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_RealtimeZslRequestProcessor"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
 #include "realtime_zsl_request_processor.h"
@@ -126,9 +126,13 @@ std::unique_ptr<RealtimeZslRequestProcessor> RealtimeZslRequestProcessor::Create
     ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
     return nullptr;
   }
+  if (pixel_format != android_pixel_format_t::HAL_PIXEL_FORMAT_YCBCR_420_888) {
+    ALOGE("%s: only YCBCR_420_888 is supported for YUV ZSL", __FUNCTION__);
+    return nullptr;
+  }
 
   auto request_processor = std::unique_ptr<RealtimeZslRequestProcessor>(
-      new RealtimeZslRequestProcessor(pixel_format, device_session_hwl));
+      new RealtimeZslRequestProcessor(device_session_hwl));
   if (request_processor == nullptr) {
     ALOGE("%s: Creating RealtimeZslRequestProcessor failed.", __FUNCTION__);
     return nullptr;
@@ -167,12 +171,6 @@ status_t RealtimeZslRequestProcessor::Initialize(
           res);
     return res;
   }
-  if (pixel_format_ == android_pixel_format_t::HAL_PIXEL_FORMAT_RAW10) {
-    res = characteristics->Get(VendorTagIds::kHdrUsageMode, &entry);
-    if (res == OK) {
-      hdr_mode_ = static_cast<HdrMode>(entry.data.u8[0]);
-    }
-  }
 
   return OK;
 }
@@ -193,21 +191,19 @@ status_t RealtimeZslRequestProcessor::ConfigureStreams(
 
   // For YUV ZSL, we will use the JPEG size for ZSL buffer size. We already
   // checked the size is supported in capture session.
-  if (pixel_format_ == android_pixel_format_t::HAL_PIXEL_FORMAT_YCBCR_420_888) {
-    for (const auto& stream : stream_config.streams) {
-      if (utils::IsSoftwareDenoiseEligibleSnapshotStream(stream)) {
-        if (SelectWidthAndHeight(stream.width, stream.height,
-                                 *device_session_hwl_, active_array_width_,
-                                 active_array_height_) != OK) {
-          ALOGE("%s: failed to select ZSL YUV buffer width and height",
-                __FUNCTION__);
-          return BAD_VALUE;
-        }
-        ALOGI("%s, Snapshot size is (%d x %d), selected size is (%d x %d)",
-              __FUNCTION__, stream.width, stream.height, active_array_width_,
-              active_array_height_);
-        break;
+  for (const auto& stream : stream_config.streams) {
+    if (utils::IsSoftwareDenoiseEligibleSnapshotStream(stream)) {
+      if (SelectWidthAndHeight(stream.width, stream.height,
+                               *device_session_hwl_, active_array_width_,
+                               active_array_height_) != OK) {
+        ALOGE("%s: failed to select ZSL YUV buffer width and height",
+              __FUNCTION__);
+        return BAD_VALUE;
       }
+      ALOGI("%s, Snapshot size is (%d x %d), selected size is (%d x %d)",
+            __FUNCTION__, stream.width, stream.height, active_array_width_,
+            active_array_height_);
+      break;
     }
   }
 
@@ -216,7 +212,7 @@ status_t RealtimeZslRequestProcessor::ConfigureStreams(
   stream_to_add.stream_type = StreamType::kOutput;
   stream_to_add.width = active_array_width_;
   stream_to_add.height = active_array_height_;
-  stream_to_add.format = pixel_format_;
+  stream_to_add.format = HAL_PIXEL_FORMAT_YCBCR_420_888;
   stream_to_add.usage = 0;
   stream_to_add.rotation = StreamRotation::kRotation0;
   stream_to_add.data_space = HAL_DATASPACE_ARBITRARY;
@@ -224,8 +220,7 @@ status_t RealtimeZslRequestProcessor::ConfigureStreams(
   // we will add the new stream as physical stream. As we support physical
   // streams only or logical streams only combination. We can check the stream
   // type of the first stream in the list.
-  if (pixel_format_ == android_pixel_format_t::HAL_PIXEL_FORMAT_YCBCR_420_888 &&
-      stream_config.streams[0].is_physical_camera_stream) {
+  if (stream_config.streams[0].is_physical_camera_stream) {
     stream_to_add.is_physical_camera_stream = true;
     stream_to_add.physical_camera_id =
         stream_config.streams[0].physical_camera_id;
@@ -282,20 +277,6 @@ status_t RealtimeZslRequestProcessor::ProcessRequest(
     return NO_INIT;
   }
 
-  if (is_hdrplus_zsl_enabled_ && request.settings != nullptr) {
-    camera_metadata_ro_entry entry = {};
-    status_t res =
-        request.settings->Get(VendorTagIds::kThermalThrottling, &entry);
-    if (res != OK || entry.count != 1) {
-      ALOGW("%s: Getting thermal throttling entry failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-    } else if (entry.data.u8[0] == true) {
-      // Disable HDR+ ZSL once thermal throttles.
-      is_hdrplus_zsl_enabled_ = false;
-      ALOGI("%s: HDR+ ZSL disabled due to thermal throttling", __FUNCTION__);
-    }
-  }
-
   // Update if preview intent has been requested.
   camera_metadata_ro_entry entry;
   if (!preview_intent_seen_ && request.settings != nullptr &&
@@ -324,44 +305,21 @@ status_t RealtimeZslRequestProcessor::ProcessRequest(
         HalCameraMetadata::Clone(physical_metadata.get());
   }
 
-  if (is_hdrplus_zsl_enabled_ ||
-      pixel_format_ == android_pixel_format_t::HAL_PIXEL_FORMAT_YCBCR_420_888) {
-    // Get one bffer from internal stream manager
-    StreamBuffer buffer = {};
-    status_t result;
-    if (preview_intent_seen_) {
-      result = internal_stream_manager_->GetStreamBuffer(stream_id_, &buffer);
-      if (result != OK) {
-        ALOGE("%s: frame:%d GetStreamBuffer failed.", __FUNCTION__,
-              request.frame_number);
-        return UNKNOWN_ERROR;
-      }
+  // Get one buffer from internal stream manager
+  StreamBuffer buffer = {};
+  status_t result;
+  if (preview_intent_seen_) {
+    result = internal_stream_manager_->GetStreamBuffer(stream_id_, &buffer);
+    if (result != OK) {
+      ALOGE("%s: frame:%d GetStreamBuffer failed.", __FUNCTION__,
+            request.frame_number);
+      return UNKNOWN_ERROR;
     }
+  }
 
-    // Add output to capture request
-    if (preview_intent_seen_) {
-      block_request.output_buffers.push_back(buffer);
-    }
-
-    if (block_request.settings != nullptr && is_hdrplus_zsl_enabled_) {
-      bool enable_hybrid_ae =
-          (hdr_mode_ == HdrMode::kNonHdrplusMode ? false : true);
-      result = hal_utils::ModifyRealtimeRequestForHdrplus(
-          block_request.settings.get(), enable_hybrid_ae);
-      if (result != OK) {
-        ALOGE("%s: ModifyRealtimeRequestForHdrplus (%d) fail", __FUNCTION__,
-              request.frame_number);
-        return UNKNOWN_ERROR;
-      }
-
-      if (hdr_mode_ != HdrMode::kHdrplusMode) {
-        uint8_t processing_mode =
-            static_cast<uint8_t>(ProcessingMode::kIntermediateProcessing);
-        block_request.settings->Set(VendorTagIds::kProcessingMode,
-                                    &processing_mode,
-                                    /*data_count=*/1);
-      }
-    }
+  // Add output to capture request
+  if (preview_intent_seen_) {
+    block_request.output_buffers.push_back(buffer);
   }
 
   std::vector<ProcessBlockRequest> block_requests(1);
@@ -379,5 +337,14 @@ status_t RealtimeZslRequestProcessor::Flush() {
   return process_block_->Flush();
 }
 
+void RealtimeZslRequestProcessor::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(process_block_lock_);
+  if (process_block_ != nullptr) {
+    process_block_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 }  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/common/hal/google_camera_hal/realtime_zsl_request_processor.h b/common/hal/google_camera_hal/realtime_zsl_request_processor.h
index b8be026..63a60d4 100644
--- a/common/hal/google_camera_hal/realtime_zsl_request_processor.h
+++ b/common/hal/google_camera_hal/realtime_zsl_request_processor.h
@@ -18,6 +18,8 @@
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_REALTIME_ZSL_REQUEST_PROCESSOR_H_
 
 #include <shared_mutex>
+#include <vector>
+
 #include "process_block.h"
 #include "request_processor.h"
 #include "vendor_tag_types.h"
@@ -26,7 +28,7 @@ namespace android {
 namespace google_camera_hal {
 
 // RealtimeZslRequestProcessor implements a RequestProcessor that adds
-// internal raw stream to request and forwards the request to its ProcessBlock.
+// internal stream to request and forwards the request to its ProcessBlock.
 class RealtimeZslRequestProcessor : public RequestProcessor {
  public:
   // device_session_hwl is owned by the caller and must be valid during the
@@ -39,7 +41,7 @@ class RealtimeZslRequestProcessor : public RequestProcessor {
 
   // Override functions of RequestProcessor start.
   // RealtimeZslRequestProcessor will configure all streams in stream_config.
-  // And register one internal raw stream
+  // And register one internal stream
   status_t ConfigureStreams(
       InternalStreamManager* internal_stream_manager,
       const StreamConfiguration& stream_config,
@@ -48,19 +50,19 @@ class RealtimeZslRequestProcessor : public RequestProcessor {
   // Set the realtime process block for sending requests later.
   status_t SetProcessBlock(std::unique_ptr<ProcessBlock> process_block) override;
 
-  // Add one additional RAW output to capture request
+  // Add one additional output to capture request
   // And forwards the capture request to realtime process
   status_t ProcessRequest(const CaptureRequest& request) override;
 
   status_t Flush() override;
+
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
   // Override functions of RequestProcessor end.
 
  protected:
-  RealtimeZslRequestProcessor(android_pixel_format_t pixel_format,
-                              CameraDeviceSessionHwl* device_session_hwl)
-      : pixel_format_(pixel_format),
-        device_session_hwl_(device_session_hwl),
-        is_hdrplus_zsl_enabled_(pixel_format == HAL_PIXEL_FORMAT_RAW10){};
+  RealtimeZslRequestProcessor(CameraDeviceSessionHwl* device_session_hwl)
+      : device_session_hwl_(device_session_hwl) {};
 
  private:
   status_t Initialize(CameraDeviceSessionHwl* device_session_hwl);
@@ -70,17 +72,11 @@ class RealtimeZslRequestProcessor : public RequestProcessor {
   std::unique_ptr<ProcessBlock> process_block_;
 
   InternalStreamManager* internal_stream_manager_ = nullptr;
-  android_pixel_format_t pixel_format_;
   CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
   bool preview_intent_seen_ = false;
   int32_t stream_id_ = -1;
   uint32_t active_array_width_ = 0;
   uint32_t active_array_height_ = 0;
-
-  HdrMode hdr_mode_ = HdrMode::kHdrplusMode;
-
-  // If HDR+ ZSL is enabled.
-  bool is_hdrplus_zsl_enabled_ = false;
 };
 
 }  // namespace google_camera_hal
diff --git a/common/hal/google_camera_hal/realtime_zsl_result_processor.cc b/common/hal/google_camera_hal/realtime_zsl_result_processor.cc
index 2735920..9534b05 100644
--- a/common/hal/google_camera_hal/realtime_zsl_result_processor.cc
+++ b/common/hal/google_camera_hal/realtime_zsl_result_processor.cc
@@ -37,10 +37,14 @@ std::unique_ptr<RealtimeZslResultProcessor> RealtimeZslResultProcessor::Create(
     ALOGE("%s: internal_stream_manager is nullptr.", __FUNCTION__);
     return nullptr;
   }
+  if (pixel_format != android_pixel_format_t::HAL_PIXEL_FORMAT_YCBCR_420_888) {
+    ALOGE("%s: only YCBCR_420_888 is supported for YUV ZSL", __FUNCTION__);
+    return nullptr;
+  }
 
-  auto result_processor = std::unique_ptr<RealtimeZslResultProcessor>(
-      new RealtimeZslResultProcessor(internal_stream_manager, stream_id,
-                                     pixel_format, partial_result_count));
+  auto result_processor =
+      std::unique_ptr<RealtimeZslResultProcessor>(new RealtimeZslResultProcessor(
+          internal_stream_manager, stream_id, partial_result_count));
   if (result_processor == nullptr) {
     ALOGE("%s: Creating RealtimeZslResultProcessor failed.", __FUNCTION__);
     return nullptr;
@@ -51,10 +55,9 @@ std::unique_ptr<RealtimeZslResultProcessor> RealtimeZslResultProcessor::Create(
 
 RealtimeZslResultProcessor::RealtimeZslResultProcessor(
     InternalStreamManager* internal_stream_manager, int32_t stream_id,
-    android_pixel_format_t pixel_format, uint32_t partial_result_count) {
+    uint32_t partial_result_count) {
   internal_stream_manager_ = internal_stream_manager;
   stream_id_ = stream_id;
-  pixel_format_ = pixel_format;
   partial_result_count_ = partial_result_count;
 }
 
@@ -66,88 +69,6 @@ void RealtimeZslResultProcessor::SetResultCallback(
   notify_ = notify;
 }
 
-void RealtimeZslResultProcessor::SaveLsForHdrplus(const CaptureRequest& request) {
-  if (request.settings != nullptr) {
-    uint8_t lens_shading_map_mode;
-    status_t res =
-        hal_utils::GetLensShadingMapMode(request, &lens_shading_map_mode);
-    if (res == OK) {
-      current_lens_shading_map_mode_ = lens_shading_map_mode;
-    }
-  }
-
-  {
-    std::lock_guard<std::mutex> lock(lens_shading_lock_);
-    requested_lens_shading_map_modes_.emplace(request.frame_number,
-                                              current_lens_shading_map_mode_);
-  }
-}
-
-status_t RealtimeZslResultProcessor::HandleLsResultForHdrplus(
-    uint32_t frameNumber, HalCameraMetadata* metadata) {
-  if (metadata == nullptr) {
-    ALOGE("%s: metadata is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-  std::lock_guard<std::mutex> lock(lens_shading_lock_);
-  auto iter = requested_lens_shading_map_modes_.find(frameNumber);
-  if (iter == requested_lens_shading_map_modes_.end()) {
-    ALOGW("%s: can't find frame (%d)", __FUNCTION__, frameNumber);
-    return OK;
-  }
-
-  if (iter->second == ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF) {
-    status_t res = hal_utils::RemoveLsInfoFromResult(metadata);
-    if (res != OK) {
-      ALOGW("%s: RemoveLsInfoFromResult fail", __FUNCTION__);
-    }
-  }
-  requested_lens_shading_map_modes_.erase(iter);
-
-  return OK;
-}
-
-void RealtimeZslResultProcessor::SaveFdForHdrplus(const CaptureRequest& request) {
-  // Enable face detect mode for internal use
-  if (request.settings != nullptr) {
-    uint8_t fd_mode;
-    status_t res = hal_utils::GetFdMode(request, &fd_mode);
-    if (res == OK) {
-      current_face_detect_mode_ = fd_mode;
-    }
-  }
-
-  {
-    std::lock_guard<std::mutex> lock(face_detect_lock_);
-    requested_face_detect_modes_.emplace(request.frame_number,
-                                         current_face_detect_mode_);
-  }
-}
-
-status_t RealtimeZslResultProcessor::HandleFdResultForHdrplus(
-    uint32_t frameNumber, HalCameraMetadata* metadata) {
-  if (metadata == nullptr) {
-    ALOGE("%s: metadata is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-  std::lock_guard<std::mutex> lock(face_detect_lock_);
-  auto iter = requested_face_detect_modes_.find(frameNumber);
-  if (iter == requested_face_detect_modes_.end()) {
-    ALOGW("%s: can't find frame (%d)", __FUNCTION__, frameNumber);
-    return OK;
-  }
-
-  if (iter->second == ANDROID_STATISTICS_FACE_DETECT_MODE_OFF) {
-    status_t res = hal_utils::RemoveFdInfoFromResult(metadata);
-    if (res != OK) {
-      ALOGW("%s: RestoreFdMetadataForHdrplus fail", __FUNCTION__);
-    }
-  }
-  requested_face_detect_modes_.erase(iter);
-
-  return OK;
-}
-
 status_t RealtimeZslResultProcessor::AddPendingRequests(
     const std::vector<ProcessBlockRequest>& process_block_requests,
     const CaptureRequest& remaining_session_request) {
@@ -160,11 +81,6 @@ status_t RealtimeZslResultProcessor::AddPendingRequests(
     return BAD_VALUE;
   }
 
-  if (pixel_format_ == HAL_PIXEL_FORMAT_RAW10) {
-    SaveFdForHdrplus(remaining_session_request);
-    SaveLsForHdrplus(remaining_session_request);
-  }
-
   return OK;
 }
 
@@ -183,8 +99,8 @@ void RealtimeZslResultProcessor::ProcessResult(ProcessBlockResult block_result)
     return;
   }
 
-  // Return filled raw buffer to internal stream manager
-  // And remove raw buffer from result
+  // Return filled buffer to internal stream manager
+  // And remove buffer from result
   bool returned_output = false;
   status_t res;
   std::vector<StreamBuffer> modified_output_buffers;
@@ -224,28 +140,10 @@ void RealtimeZslResultProcessor::ProcessResult(ProcessBlockResult block_result)
         ALOGW("%s: SetEnableZslMetadata (%d) fail", __FUNCTION__,
               result->frame_number);
       }
-
-      if (pixel_format_ == HAL_PIXEL_FORMAT_RAW10) {
-        res = HandleFdResultForHdrplus(result->frame_number,
-                                       result->result_metadata.get());
-        if (res != OK) {
-          ALOGE("%s: HandleFdResultForHdrplus(%d) fail", __FUNCTION__,
-                result->frame_number);
-          return;
-        }
-
-        res = HandleLsResultForHdrplus(result->frame_number,
-                                       result->result_metadata.get());
-        if (res != OK) {
-          ALOGE("%s: HandleLsResultForHdrplus(%d) fail", __FUNCTION__,
-                result->frame_number);
-          return;
-        }
-      }
     }
   }
 
-  // Don't send result to framework if only internal raw callback
+  // Don't send result to framework if only internal callback
   if (returned_output && result->result_metadata == nullptr &&
       result->output_buffers.size() == 0) {
     return;
@@ -279,4 +177,4 @@ status_t RealtimeZslResultProcessor::FlushPendingRequests() {
 }
 
 }  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/common/hal/google_camera_hal/realtime_zsl_result_processor.h b/common/hal/google_camera_hal/realtime_zsl_result_processor.h
index 7ab5490..fd63ec9 100644
--- a/common/hal/google_camera_hal/realtime_zsl_result_processor.h
+++ b/common/hal/google_camera_hal/realtime_zsl_result_processor.h
@@ -26,7 +26,7 @@ namespace android {
 namespace google_camera_hal {
 
 // RealtimeZslResultProcessor implements a ResultProcessor that return
-// filled raw buffer and metadata to internal stream manager.
+// filled buffer and metadata to internal stream manager.
 class RealtimeZslResultProcessor : public ResultProcessor {
  public:
   static std::unique_ptr<RealtimeZslResultProcessor> Create(
@@ -44,8 +44,8 @@ class RealtimeZslResultProcessor : public ResultProcessor {
       const std::vector<ProcessBlockRequest>& process_block_requests,
       const CaptureRequest& remaining_session_request) override;
 
-  // Return filled raw buffer and metadata to internal stream manager
-  // and forwards the results without raw buffer to its callback functions.
+  // Return filled buffer and metadata to internal stream manager
+  // and forwards the results without buffer to its callback functions.
   void ProcessResult(ProcessBlockResult block_result) override;
 
   void Notify(const ProcessBlockNotifyMessage& block_message) override;
@@ -55,9 +55,7 @@ class RealtimeZslResultProcessor : public ResultProcessor {
 
  protected:
   RealtimeZslResultProcessor(InternalStreamManager* internal_stream_manager,
-                             int32_t stream_id,
-                             android_pixel_format_t pixel_format,
-                             uint32_t partial_result_count);
+                             int32_t stream_id, uint32_t partial_result_count);
 
   InternalStreamManager* internal_stream_manager_;
   int32_t stream_id_ = -1;
@@ -71,38 +69,6 @@ class RealtimeZslResultProcessor : public ResultProcessor {
   NotifyFunc notify_;
 
  private:
-  // Save face detect mode for HDR+
-  void SaveFdForHdrplus(const CaptureRequest& request);
-  // Handle face detect metadata from result for HDR+
-  status_t HandleFdResultForHdrplus(uint32_t frameNumber,
-                                    HalCameraMetadata* metadata);
-  // Save lens shading map mode for HDR+
-  void SaveLsForHdrplus(const CaptureRequest& request);
-  // Handle Lens shading metadata from result for HDR+
-  status_t HandleLsResultForHdrplus(uint32_t frameNumber,
-                                    HalCameraMetadata* metadata);
-
-  android_pixel_format_t pixel_format_;
-
-  // Current face detect mode set by framework.
-  uint8_t current_face_detect_mode_ = ANDROID_STATISTICS_FACE_DETECT_MODE_OFF;
-
-  std::mutex face_detect_lock_;
-  // Map from frame number to face detect mode requested for that frame by
-  // framework. And requested_face_detect_modes_ is protected by
-  // face_detect_lock_
-  std::unordered_map<uint32_t, uint8_t> requested_face_detect_modes_;
-
-  // Current lens shading map mode set by framework.
-  uint8_t current_lens_shading_map_mode_ =
-      ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF;
-
-  std::mutex lens_shading_lock_;
-  // Map from frame number to lens shading map mode requested for that frame
-  // by framework. And requested_lens_shading_map_modes_ is protected by
-  // lens_shading_lock_
-  std::unordered_map<uint32_t, uint8_t> requested_lens_shading_map_modes_;
-
   std::shared_mutex process_block_shared_lock_;
 };
 
diff --git a/common/hal/google_camera_hal/realtime_zsl_result_request_processor.cc b/common/hal/google_camera_hal/realtime_zsl_result_request_processor.cc
index 93e5844..e6dc92b 100644
--- a/common/hal/google_camera_hal/realtime_zsl_result_request_processor.cc
+++ b/common/hal/google_camera_hal/realtime_zsl_result_request_processor.cc
@@ -51,10 +51,14 @@ RealtimeZslResultRequestProcessor::Create(
     ALOGE("%s: internal_stream_manager is nullptr.", __FUNCTION__);
     return nullptr;
   }
+  if (pixel_format != android_pixel_format_t::HAL_PIXEL_FORMAT_YCBCR_420_888) {
+    ALOGE("%s: only YCBCR_420_888 is supported for YUV ZSL", __FUNCTION__);
+    return nullptr;
+  }
 
   auto result_processor = std::unique_ptr<RealtimeZslResultRequestProcessor>(
       new RealtimeZslResultRequestProcessor(internal_stream_manager, stream_id,
-                                            pixel_format, partial_result_count));
+                                            partial_result_count));
   if (result_processor == nullptr) {
     ALOGE("%s: Creating RealtimeZslResultRequestProcessor failed.",
           __FUNCTION__);
@@ -66,9 +70,9 @@ RealtimeZslResultRequestProcessor::Create(
 
 RealtimeZslResultRequestProcessor::RealtimeZslResultRequestProcessor(
     InternalStreamManager* internal_stream_manager, int32_t stream_id,
-    android_pixel_format_t pixel_format, uint32_t partial_result_count)
+    uint32_t partial_result_count)
     : RealtimeZslResultProcessor(internal_stream_manager, stream_id,
-                                 pixel_format, partial_result_count) {
+                                 partial_result_count) {
 }
 
 void RealtimeZslResultRequestProcessor::UpdateOutputBufferCount(
@@ -117,8 +121,8 @@ void RealtimeZslResultRequestProcessor::ProcessResult(
     pending_request.capture_request->frame_number = result->frame_number;
   }
 
-  // Return filled raw buffer to internal stream manager
-  // And remove raw buffer from result
+  // Return filled buffer to internal stream manager
+  // And remove buffer from result
   status_t res;
   std::vector<StreamBuffer> modified_output_buffers;
   for (uint32_t i = 0; i < result->output_buffers.size(); i++) {
@@ -299,6 +303,15 @@ status_t RealtimeZslResultRequestProcessor::Flush() {
   return process_block_->Flush();
 }
 
+void RealtimeZslResultRequestProcessor::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(process_block_shared_lock_);
+  if (process_block_ != nullptr) {
+    process_block_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 void RealtimeZslResultRequestProcessor::Notify(
     const ProcessBlockNotifyMessage& block_message) {
   ATRACE_CALL();
@@ -415,7 +428,7 @@ void RealtimeZslResultRequestProcessor::ReturnResultDirectlyForFramesWithErrorsL
     pending_frame_number_to_requests_.erase(result->frame_number);
   }
 
-  // Don't send result to framework if only internal raw callback
+  // Don't send result to framework if only internal callback
   if (has_returned_output_to_internal_stream_manager &&
       result->result_metadata == nullptr && result->output_buffers.size() == 0) {
     return;
diff --git a/common/hal/google_camera_hal/realtime_zsl_result_request_processor.h b/common/hal/google_camera_hal/realtime_zsl_result_request_processor.h
index 5454916..33436b9 100644
--- a/common/hal/google_camera_hal/realtime_zsl_result_request_processor.h
+++ b/common/hal/google_camera_hal/realtime_zsl_result_request_processor.h
@@ -19,6 +19,7 @@
 
 #include <cstdint>
 #include <shared_mutex>
+#include <vector>
 
 #include "hal_types.h"
 #include "internal_stream_manager.h"
@@ -30,7 +31,7 @@ namespace android {
 namespace google_camera_hal {
 
 // RealtimeZslResultRequestProcessor implements a RealtimeZslResultProcessor
-// that return filled raw buffer and metadata to internal stream manager. It
+// that return filled buffer and metadata to internal stream manager. It
 // also implements a RequestProcess to forward the results.
 class RealtimeZslResultRequestProcessor : public RealtimeZslResultProcessor,
                                           RequestProcessor {
@@ -58,6 +59,9 @@ class RealtimeZslResultRequestProcessor : public RealtimeZslResultProcessor,
   status_t ProcessRequest(const CaptureRequest& request) override;
 
   status_t Flush() override;
+
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
   // Override functions of RequestProcessor end.
 
   void UpdateOutputBufferCount(int32_t frame_number, int output_buffer_count,
@@ -66,7 +70,7 @@ class RealtimeZslResultRequestProcessor : public RealtimeZslResultProcessor,
  protected:
   RealtimeZslResultRequestProcessor(
       InternalStreamManager* internal_stream_manager, int32_t stream_id,
-      android_pixel_format_t pixel_format, uint32_t partial_result_count);
+      uint32_t partial_result_count);
 
  private:
   std::shared_mutex process_block_shared_lock_;
@@ -80,7 +84,7 @@ class RealtimeZslResultRequestProcessor : public RealtimeZslResultProcessor,
     uint32_t partial_results_received = 0;
     bool zsl_buffer_received = false;
     int framework_buffer_count = INT_MAX;
-    // Whether there were filled raw buffers that have been returned to internal
+    // Whether there were filled buffers that have been returned to internal
     // stream manager.
     bool has_returned_output_to_internal_stream_manager = false;
   };
diff --git a/common/hal/google_camera_hal/rgbird_capture_session.cc b/common/hal/google_camera_hal/rgbird_capture_session.cc
deleted file mode 100644
index 35370f8..0000000
--- a/common/hal/google_camera_hal/rgbird_capture_session.cc
+++ /dev/null
@@ -1,1137 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_RgbirdCaptureSession"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "rgbird_capture_session.h"
-
-#include <cutils/properties.h>
-#include <inttypes.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <set>
-
-#include "basic_result_processor.h"
-#include "depth_process_block.h"
-#include "hal_utils.h"
-#include "hdrplus_process_block.h"
-#include "hdrplus_request_processor.h"
-#include "hdrplus_result_processor.h"
-#include "multicam_realtime_process_block.h"
-#include "rgbird_depth_result_processor.h"
-#include "rgbird_result_request_processor.h"
-#include "rgbird_rt_request_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-bool RgbirdCaptureSession::IsStreamConfigurationSupported(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& /*stream_config*/) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return false;
-  }
-
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl->GetPhysicalCameraIds();
-  if (physical_camera_ids.size() != 3) {
-    ALOGD("%s: RgbirdCaptureSession doesn't support %zu physical cameras",
-          __FUNCTION__, physical_camera_ids.size());
-    return false;
-  }
-
-  // Check if this is a logical camera containing two IR cameras.
-  uint32_t num_ir_camera = 0;
-  for (auto id : physical_camera_ids) {
-    std::unique_ptr<HalCameraMetadata> characteristics;
-    status_t res = device_session_hwl->GetPhysicalCameraCharacteristics(
-        id, &characteristics);
-
-    if (res != OK) {
-      ALOGE("%s: Cannot get physical camera characteristics for camera %u",
-            __FUNCTION__, id);
-      return false;
-    }
-
-    // TODO(b/129088371): Work around b/129088371 because current IR camera's
-    // CFA is MONO instead of NIR.
-    if (hal_utils::IsIrCamera(characteristics.get()) ||
-        hal_utils::IsMonoCamera(characteristics.get())) {
-      num_ir_camera++;
-    }
-  }
-
-  if (num_ir_camera != 2) {
-    ALOGD("%s: RgbirdCaptureSession only supports 2 ir cameras", __FUNCTION__);
-    return false;
-  }
-
-  ALOGD("%s: RgbirdCaptureSession supports the stream config", __FUNCTION__);
-  return true;
-}
-
-std::unique_ptr<CaptureSession> RgbirdCaptureSession::Create(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/,
-    NotifyFunc notify, HwlSessionCallback session_callback,
-    std::vector<HalStream>* hal_configured_streams,
-    CameraBufferAllocatorHwl* /*camera_allocator_hwl*/) {
-  ATRACE_CALL();
-  auto session =
-      std::unique_ptr<RgbirdCaptureSession>(new RgbirdCaptureSession());
-  if (session == nullptr) {
-    ALOGE("%s: Creating RgbirdCaptureSession failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  status_t res = session->Initialize(
-      device_session_hwl, stream_config, process_capture_result, notify,
-      session_callback.request_stream_buffers, hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Initializing RgbirdCaptureSession failed: %s (%d).",
-          __FUNCTION__, strerror(-res), res);
-    return nullptr;
-  }
-
-  return session;
-}
-
-RgbirdCaptureSession::~RgbirdCaptureSession() {
-  if (device_session_hwl_ != nullptr) {
-    device_session_hwl_->DestroyPipelines();
-  }
-
-  rt_request_processor_ = nullptr;
-  hdrplus_request_processor_ = nullptr;
-  result_dispatcher_ = nullptr;
-}
-
-bool RgbirdCaptureSession::AreAllStreamsConfigured(
-    const StreamConfiguration& stream_config,
-    const StreamConfiguration& process_block_stream_config) const {
-  ATRACE_CALL();
-  // Check all streams are configured.
-  if (stream_config.streams.size() > process_block_stream_config.streams.size()) {
-    ALOGE("%s: stream_config has %zu streams but only configured %zu streams",
-          __FUNCTION__, stream_config.streams.size(),
-          process_block_stream_config.streams.size());
-    return false;
-  }
-
-  for (auto& stream : stream_config.streams) {
-    bool found = false;
-    for (auto& configured_stream : process_block_stream_config.streams) {
-      if (stream.id == configured_stream.id) {
-        found = true;
-        break;
-      }
-    }
-
-    if (!found) {
-      ALOGE("%s: Cannot find stream %u in configured streams.", __FUNCTION__,
-            stream.id);
-      return false;
-    }
-  }
-
-  return true;
-}
-
-status_t RgbirdCaptureSession::ConfigureStreams(
-    const StreamConfiguration& stream_config,
-    RequestProcessor* request_processor, ProcessBlock* process_block,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (request_processor == nullptr || process_block == nullptr ||
-      process_block_stream_config == nullptr) {
-    ALOGE(
-        "%s: request_processor(%p) or process_block(%p) or "
-        "process_block_stream_config(%p) is nullptr",
-        __FUNCTION__, request_processor, process_block,
-        process_block_stream_config);
-    return BAD_VALUE;
-  }
-
-  status_t res = request_processor->ConfigureStreams(
-      internal_stream_manager_.get(), stream_config,
-      process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream for RequestProcessor failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  res = process_block->ConfigureStreams(*process_block_stream_config,
-                                        stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring streams for ProcessBlock failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::SetDepthInternalStreamId(
-    const StreamConfiguration& process_block_stream_config,
-    const StreamConfiguration& stream_config) {
-  // Assuming there is at most one internal YUV stream configured when this
-  // function is called(i.e. when depth stream is configured).
-  for (auto& configured_stream : process_block_stream_config.streams) {
-    if (configured_stream.format == HAL_PIXEL_FORMAT_YCBCR_420_888) {
-      bool matching_found = false;
-      for (auto& framework_stream : stream_config.streams) {
-        if (configured_stream.id == framework_stream.id) {
-          matching_found = true;
-          break;
-        }
-      }
-      if (!matching_found) {
-        rgb_internal_yuv_stream_id_ = configured_stream.id;
-      }
-    } else if (configured_stream.format == HAL_PIXEL_FORMAT_Y8) {
-      if (configured_stream.physical_camera_id == ir1_camera_id_) {
-        ir1_internal_raw_stream_id_ = configured_stream.id;
-      } else if (configured_stream.physical_camera_id == ir2_camera_id_) {
-        ir2_internal_raw_stream_id_ = configured_stream.id;
-      } else {
-        ALOGV("%s: Y8 stream found from non-IR sensors.", __FUNCTION__);
-      }
-    }
-  }
-
-  if (rgb_internal_yuv_stream_id_ == kInvalidStreamId ||
-      ir1_internal_raw_stream_id_ == kInvalidStreamId ||
-      ir2_internal_raw_stream_id_ == kInvalidStreamId) {
-    ALOGE(
-        "%s: Internal YUV or IR stream not found in "
-        "process_block_stream_config.",
-        __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::ConfigureHdrplusRawStreamId(
-    const StreamConfiguration& process_block_stream_config) {
-  ATRACE_CALL();
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl_->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  uint32_t active_array_width, active_array_height;
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(
-      ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE, &entry);
-  if (res == OK) {
-    active_array_width = entry.data.i32[2];
-    active_array_height = entry.data.i32[3];
-    ALOGI("%s Active size (%d x %d).", __FUNCTION__, active_array_width,
-          active_array_height);
-  } else {
-    ALOGE("%s Get active size failed: %s (%d).", __FUNCTION__, strerror(-res),
-          res);
-    return UNKNOWN_ERROR;
-  }
-
-  for (auto& configured_stream : process_block_stream_config.streams) {
-    if (configured_stream.format == kHdrplusRawFormat &&
-        configured_stream.width == active_array_width &&
-        configured_stream.height == active_array_height) {
-      rgb_raw_stream_id_ = configured_stream.id;
-      break;
-    }
-  }
-
-  if (rgb_raw_stream_id_ == -1) {
-    ALOGE("%s: Configuring stream fail due to wrong raw_stream_id",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::AllocateInternalBuffers(
-    const StreamConfiguration& framework_stream_config,
-    std::vector<HalStream>* hal_configured_streams,
-    ProcessBlock* hdrplus_process_block) {
-  ATRACE_CALL();
-  status_t res = OK;
-
-  std::set<int32_t> framework_stream_id_set;
-  for (auto& stream : framework_stream_config.streams) {
-    framework_stream_id_set.insert(stream.id);
-  }
-
-  for (uint32_t i = 0; i < hal_configured_streams->size(); i++) {
-    HalStream& hal_stream = hal_configured_streams->at(i);
-
-    if (framework_stream_id_set.find(hal_stream.id) ==
-        framework_stream_id_set.end()) {
-      // hdrplus rgb raw stream buffers is allocated separately
-      if (hal_stream.id == rgb_raw_stream_id_) {
-        continue;
-      }
-
-      uint32_t additional_num_buffers =
-          (hal_stream.max_buffers >= kDefaultInternalBufferCount)
-              ? 0
-              : (kDefaultInternalBufferCount - hal_stream.max_buffers);
-      res = internal_stream_manager_->AllocateBuffers(
-          hal_stream, hal_stream.max_buffers + additional_num_buffers);
-      if (res != OK) {
-        ALOGE("%s: Failed to allocate buffer for internal stream %d: %s(%d)",
-              __FUNCTION__, hal_stream.id, strerror(-res), res);
-        return res;
-      } else {
-        ALOGI("%s: Allocating %d internal buffers for stream %d", __FUNCTION__,
-              additional_num_buffers + hal_stream.max_buffers, hal_stream.id);
-      }
-    }
-  }
-
-  if (is_hdrplus_supported_) {
-    std::vector<HalStream> hdrplus_hal_configured_streams;
-    res = hdrplus_process_block->GetConfiguredHalStreams(
-        &hdrplus_hal_configured_streams);
-    if (res != OK) {
-      ALOGE("%s: Getting HDR+ HAL streams failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-
-    res = ConfigureHdrplusUsageAndBuffers(hal_configured_streams,
-                                          &hdrplus_hal_configured_streams);
-    if (res != OK) {
-      ALOGE("%s: ConfigureHdrplusUsageAndBuffer failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-  }
-  return res;
-}
-
-status_t RgbirdCaptureSession::PurgeHalConfiguredStream(
-    const StreamConfiguration& stream_config,
-    std::vector<HalStream>* hal_configured_streams) {
-  if (hal_configured_streams == nullptr) {
-    ALOGE("%s: HAL configured stream list is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::set<int32_t> framework_stream_id_set;
-  for (auto& stream : stream_config.streams) {
-    framework_stream_id_set.insert(stream.id);
-  }
-
-  std::vector<HalStream> configured_streams;
-  for (auto& hal_stream : *hal_configured_streams) {
-    if (framework_stream_id_set.find(hal_stream.id) !=
-        framework_stream_id_set.end()) {
-      configured_streams.push_back(hal_stream);
-    }
-  }
-  *hal_configured_streams = configured_streams;
-  return OK;
-}
-
-bool RgbirdCaptureSession::NeedDepthProcessBlock() const {
-  // TODO(b/128633958): remove force flag after FLL syncing is verified
-  return force_internal_stream_ || has_depth_stream_;
-}
-
-status_t RgbirdCaptureSession::CreateDepthChainSegment(
-    std::unique_ptr<DepthProcessBlock>* depth_process_block,
-    std::unique_ptr<RgbirdDepthResultProcessor>* depth_result_processor,
-    RgbirdResultRequestProcessor* rt_result_processor,
-    const StreamConfiguration& stream_config,
-    const StreamConfiguration& overall_config,
-    StreamConfiguration* depth_block_stream_config) {
-  ATRACE_CALL();
-  DepthProcessBlock::DepthProcessBlockCreateData data = {
-      .rgb_internal_yuv_stream_id = rgb_internal_yuv_stream_id_,
-      .ir1_internal_raw_stream_id = ir1_internal_raw_stream_id_,
-      .ir2_internal_raw_stream_id = ir2_internal_raw_stream_id_};
-  auto process_block = DepthProcessBlock::Create(device_session_hwl_,
-                                                 request_stream_buffers_, data);
-  if (process_block == nullptr) {
-    ALOGE("%s: Creating DepthProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  auto result_processor =
-      RgbirdDepthResultProcessor::Create(internal_stream_manager_.get());
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating RgbirdDepthResultProcessor", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  status_t res = rt_result_processor->ConfigureStreams(
-      internal_stream_manager_.get(), stream_config, depth_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring streams for ResultRequestProcessor failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  res = process_block->ConfigureStreams(*depth_block_stream_config,
-                                        overall_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring streams for DepthProcessBlock failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  *depth_process_block = std::move(process_block);
-  *depth_result_processor = std::move(result_processor);
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::SetupDepthChainSegment(
-    const StreamConfiguration& stream_config,
-    RgbirdResultRequestProcessor* realtime_result_processor,
-    std::unique_ptr<ProcessBlock>* depth_process_block,
-    std::unique_ptr<ResultProcessor>* depth_result_processor,
-    StreamConfiguration* rt_process_block_stream_config) {
-  ATRACE_CALL();
-  // Create the depth segment of realtime process chain if need depth processing
-  std::unique_ptr<DepthProcessBlock> d_process_block;
-  std::unique_ptr<RgbirdDepthResultProcessor> d_result_processor;
-  if (NeedDepthProcessBlock()) {
-    StreamConfiguration depth_chain_segment_stream_config;
-    status_t res =
-        MakeDepthStreamConfig(*rt_process_block_stream_config, stream_config,
-                              &depth_chain_segment_stream_config);
-    if (res != OK) {
-      ALOGE(
-          "%s: Making depth chain segment stream configuration failed: "
-          "%s(%d).",
-          __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-
-    StreamConfiguration depth_block_stream_config;
-    res = CreateDepthChainSegment(&d_process_block, &d_result_processor,
-                                  realtime_result_processor,
-                                  depth_chain_segment_stream_config,
-                                  stream_config, &depth_block_stream_config);
-    if (res != OK) {
-      ALOGE("%s: Creating depth chain segment failed: %s(%d).", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-
-    // process_block_stream_config may contain internal streams(some may be
-    // duplicated as both input and output for bridging the rt and depth
-    // segments of the realtime process chain.)
-    rt_process_block_stream_config->streams.insert(
-        rt_process_block_stream_config->streams.end(),
-        depth_block_stream_config.streams.begin(),
-        depth_block_stream_config.streams.end());
-
-    *depth_process_block = std::move(d_process_block);
-    *depth_result_processor = std::move(d_result_processor);
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::MakeDepthStreamConfig(
-    const StreamConfiguration& rt_process_block_stream_config,
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* depth_stream_config) {
-  ATRACE_CALL();
-  if (depth_stream_config == nullptr) {
-    ALOGE("%s: depth_stream_config is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  if (!NeedDepthProcessBlock()) {
-    ALOGE("%s: No need to create depth process chain segment stream config.",
-          __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  // Assuming all internal streams must be for depth process block as input,
-  // if depth stream is configured by framework.
-  depth_stream_config->operation_mode = stream_config.operation_mode;
-  depth_stream_config->session_params =
-      HalCameraMetadata::Clone(stream_config.session_params.get());
-  depth_stream_config->stream_config_counter =
-      stream_config.stream_config_counter;
-  depth_stream_config->streams = stream_config.streams;
-  for (auto& stream : rt_process_block_stream_config.streams) {
-    bool is_internal_stream = true;
-    for (auto& framework_stream : stream_config.streams) {
-      if (stream.id == framework_stream.id) {
-        is_internal_stream = false;
-        break;
-      }
-    }
-
-    // Change all internal streams to input streams and keep others untouched
-    if (is_internal_stream) {
-      Stream input_stream = stream;
-      input_stream.stream_type = StreamType::kInput;
-      depth_stream_config->streams.push_back(input_stream);
-    }
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::SetupRealtimeProcessChain(
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::unique_ptr<ProcessBlock>* realtime_process_block,
-    std::unique_ptr<RgbirdResultRequestProcessor>* realtime_result_processor,
-    std::unique_ptr<ProcessBlock>* depth_process_block,
-    std::unique_ptr<ResultProcessor>* depth_result_processor) {
-  ATRACE_CALL();
-  if (realtime_process_block == nullptr ||
-      realtime_result_processor == nullptr) {
-    ALOGE("%s: realtime_process_block(%p) or realtime_result_processor(%p) or ",
-          __FUNCTION__, realtime_process_block, realtime_result_processor);
-    return BAD_VALUE;
-  }
-
-  auto rt_process_block = MultiCameraRtProcessBlock::Create(device_session_hwl_);
-  if (rt_process_block == nullptr) {
-    ALOGE("%s: Creating RealtimeProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // TODO(b/128632740): Create and connect depth process block.
-  rt_request_processor_ = RgbirdRtRequestProcessor::Create(
-      device_session_hwl_, is_hdrplus_supported_);
-  if (rt_request_processor_ == nullptr) {
-    ALOGE("%s: Creating RealtimeZslsRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  StreamConfiguration process_block_stream_config;
-  status_t res =
-      ConfigureStreams(stream_config, rt_request_processor_.get(),
-                       rt_process_block.get(), &process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring stream failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  if (is_hdrplus_supported_) {
-    res = ConfigureHdrplusRawStreamId(process_block_stream_config);
-    if (res != OK) {
-      ALOGE("%s: ConfigureHdrplusRawStreamId failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-  }
-
-  if (has_depth_stream_) {
-    res = SetDepthInternalStreamId(process_block_stream_config, stream_config);
-    if (res != OK) {
-      ALOGE("%s: ConfigureDepthOnlyRawStreamId failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-  }
-
-  // Create realtime result processor.
-  RgbirdResultRequestProcessor::RgbirdResultRequestProcessorCreateData data = {
-      .rgb_camera_id = rgb_camera_id_,
-      .ir1_camera_id = ir1_camera_id_,
-      .ir2_camera_id = ir2_camera_id_,
-      .rgb_raw_stream_id = rgb_raw_stream_id_,
-      .is_hdrplus_supported = is_hdrplus_supported_,
-      .rgb_internal_yuv_stream_id = rgb_internal_yuv_stream_id_};
-  auto rt_result_processor = RgbirdResultRequestProcessor::Create(data);
-  if (rt_result_processor == nullptr) {
-    ALOGE("%s: Creating RgbirdResultRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  rt_result_processor->SetResultCallback(
-      process_capture_result, notify, /*process_batch_capture_result=*/nullptr);
-
-  if (is_hdrplus_supported_) {
-    res = rt_result_processor->ConfigureStreams(internal_stream_manager_.get(),
-                                                stream_config,
-                                                &process_block_stream_config);
-    if (res != OK) {
-      ALOGE("%s: Configuring streams for ResultRequestProcessor failed: %s(%d)",
-            __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-  }
-
-  res = SetupDepthChainSegment(stream_config, rt_result_processor.get(),
-                               depth_process_block, depth_result_processor,
-                               &process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Failed to setup depth chain segment.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // TODO(b/128632740): Remove force internal flag after depth block is in place
-  //                    and the FLL sync is verified.
-  //                    This should be done after depth process block stream
-  //                    configuration.
-  if (!AreAllStreamsConfigured(stream_config, process_block_stream_config) &&
-      !force_internal_stream_) {
-    // TODO(b/127322570): Handle the case where RT request processor configures
-    // internal streams for depth.
-    ALOGE("%s: Not all streams are configured.", __FUNCTION__);
-    return INVALID_OPERATION;
-  }
-
-  *realtime_process_block = std::move(rt_process_block);
-  *realtime_result_processor = std::move(rt_result_processor);
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::SetupHdrplusProcessChain(
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::unique_ptr<ProcessBlock>* hdrplus_process_block,
-    std::unique_ptr<ResultProcessor>* hdrplus_result_processor) {
-  ATRACE_CALL();
-  if (hdrplus_process_block == nullptr || hdrplus_result_processor == nullptr) {
-    ALOGE(
-        "%s: hdrplus_process_block(%p) or hdrplus_result_processor(%p) is "
-        "nullptr",
-        __FUNCTION__, hdrplus_process_block, hdrplus_result_processor);
-    return BAD_VALUE;
-  }
-
-  // Create hdrplus process block.
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl_->GetPhysicalCameraIds();
-  // TODO: Check the static metadata and determine which one is rgb camera
-  auto process_block =
-      HdrplusProcessBlock::Create(device_session_hwl_, physical_camera_ids[0]);
-  if (process_block == nullptr) {
-    ALOGE("%s: Creating HdrplusProcessBlock failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Create hdrplus request processor.
-  hdrplus_request_processor_ = HdrplusRequestProcessor::Create(
-      device_session_hwl_, rgb_raw_stream_id_, physical_camera_ids[0]);
-  if (hdrplus_request_processor_ == nullptr) {
-    ALOGE("%s: Creating HdrplusRequestProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Create hdrplus result processor.
-  auto result_processor = HdrplusResultProcessor::Create(
-      internal_stream_manager_.get(), rgb_raw_stream_id_);
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating HdrplusResultProcessor failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  result_processor->SetResultCallback(process_capture_result, notify,
-                                      /*process_batch_capture_result=*/nullptr);
-
-  StreamConfiguration process_block_stream_config;
-  status_t res =
-      ConfigureStreams(stream_config, hdrplus_request_processor_.get(),
-                       process_block.get(), &process_block_stream_config);
-  if (res != OK) {
-    ALOGE("%s: Configuring hdrplus stream failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  *hdrplus_process_block = std::move(process_block);
-  *hdrplus_result_processor = std::move(result_processor);
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::CreateProcessChain(
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-  // Setup realtime process chain
-  std::unique_ptr<ProcessBlock> realtime_process_block;
-  std::unique_ptr<RgbirdResultRequestProcessor> realtime_result_processor;
-  std::unique_ptr<ProcessBlock> depth_process_block;
-  std::unique_ptr<ResultProcessor> depth_result_processor;
-
-  status_t res = SetupRealtimeProcessChain(
-      stream_config, process_capture_result, notify, &realtime_process_block,
-      &realtime_result_processor, &depth_process_block, &depth_result_processor);
-  if (res != OK) {
-    ALOGE("%s: SetupRealtimeProcessChain fail: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  // Setup hdrplus process chain
-  std::unique_ptr<ProcessBlock> hdrplus_process_block;
-  std::unique_ptr<ResultProcessor> hdrplus_result_processor;
-  if (is_hdrplus_supported_) {
-    res = SetupHdrplusProcessChain(stream_config, process_capture_result,
-                                   notify, &hdrplus_process_block,
-                                   &hdrplus_result_processor);
-    if (res != OK) {
-      ALOGE("%s: SetupHdrplusProcessChain fail: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-  }
-  // Realtime and HDR+ streams are configured
-  // Start to build pipleline
-  res = BuildPipelines(stream_config, realtime_process_block.get(),
-                       depth_process_block.get(), hdrplus_process_block.get(),
-                       hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Building pipelines failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  // Connecting the depth segment of the realtime process chain.
-  if (NeedDepthProcessBlock()) {
-    depth_result_processor->SetResultCallback(
-        process_capture_result, notify,
-        /*process_batch_capture_result=*/nullptr);
-
-    res = ConnectProcessChain(realtime_result_processor.get(),
-                              std::move(depth_process_block),
-                              std::move(depth_result_processor));
-    if (res != OK) {
-      ALOGE("%s: Connecting depth segment of realtime chain failed: %s(%d)",
-            __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-  }
-
-  // Connect realtime process chain
-  res = ConnectProcessChain(rt_request_processor_.get(),
-                            std::move(realtime_process_block),
-                            std::move(realtime_result_processor));
-  if (res != OK) {
-    ALOGE("%s: Connecting process chain failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  if (is_hdrplus_supported_) {
-    // Connect HDR+ process chain
-    res = ConnectProcessChain(hdrplus_request_processor_.get(),
-                              std::move(hdrplus_process_block),
-                              std::move(hdrplus_result_processor));
-    if (res != OK) {
-      ALOGE("%s: Connecting HDR+ process chain failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-      return res;
-    }
-  }
-  return OK;
-}
-
-status_t RgbirdCaptureSession::ConnectProcessChain(
-    RequestProcessor* request_processor,
-    std::unique_ptr<ProcessBlock> process_block,
-    std::unique_ptr<ResultProcessor> result_processor) {
-  ATRACE_CALL();
-  if (request_processor == nullptr) {
-    ALOGE("%s: request_processor is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  status_t res = process_block->SetResultProcessor(std::move(result_processor));
-  if (res != OK) {
-    ALOGE("%s: Setting result process in process block failed.", __FUNCTION__);
-    return res;
-  }
-
-  res = request_processor->SetProcessBlock(std::move(process_block));
-  if (res != OK) {
-    ALOGE("%s: Setting process block for request processor failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::ConfigureHdrplusUsageAndBuffers(
-    std::vector<HalStream>* hal_configured_streams,
-    std::vector<HalStream>* hdrplus_hal_configured_streams) {
-  ATRACE_CALL();
-  if (hal_configured_streams == nullptr ||
-      hdrplus_hal_configured_streams == nullptr) {
-    ALOGE(
-        "%s: hal_configured_streams (%p) or hdrplus_hal_configured_streams "
-        "(%p) is nullptr",
-        __FUNCTION__, hal_configured_streams, hdrplus_hal_configured_streams);
-    return BAD_VALUE;
-  }
-  // Combine realtime and HDR+ hal stream.
-  // Only usage of internal raw stream is different, so combine usage directly
-  uint64_t consumer_usage = 0;
-  for (uint32_t i = 0; i < (*hdrplus_hal_configured_streams).size(); i++) {
-    if (hdrplus_hal_configured_streams->at(i).override_format ==
-            kHdrplusRawFormat &&
-        hdrplus_hal_configured_streams->at(i).id == rgb_raw_stream_id_) {
-      consumer_usage = hdrplus_hal_configured_streams->at(i).consumer_usage;
-      break;
-    }
-  }
-
-  for (uint32_t i = 0; i < hal_configured_streams->size(); i++) {
-    if (hal_configured_streams->at(i).override_format == kHdrplusRawFormat &&
-        hal_configured_streams->at(i).id == rgb_raw_stream_id_) {
-      hal_configured_streams->at(i).consumer_usage = consumer_usage;
-      // Allocate internal raw stream buffers
-      if (hal_configured_streams->at(i).max_buffers < kRgbMinRawBufferCount) {
-        hal_configured_streams->at(i).max_buffers = kRgbMinRawBufferCount;
-      }
-
-      uint32_t additional_num_buffers =
-          (hal_configured_streams->at(i).max_buffers >= kRgbRawBufferCount)
-              ? 0
-              : (kRgbRawBufferCount - hal_configured_streams->at(i).max_buffers);
-      status_t res = internal_stream_manager_->AllocateBuffers(
-          hal_configured_streams->at(i), additional_num_buffers);
-      if (res != OK) {
-        ALOGE("%s: AllocateBuffers failed.", __FUNCTION__);
-        return UNKNOWN_ERROR;
-      }
-      break;
-    }
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::BuildPipelines(
-    const StreamConfiguration& stream_config,
-    ProcessBlock* realtime_process_block, ProcessBlock* depth_process_block,
-    ProcessBlock* hdrplus_process_block,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-  if (realtime_process_block == nullptr) {
-    ALOGE("%s: realtime_process_block (%p) is nullptr", __FUNCTION__,
-          realtime_process_block);
-    return BAD_VALUE;
-  }
-
-  if (depth_process_block == nullptr && has_depth_stream_) {
-    ALOGE("%s: depth_process_block (%p) is nullptr", __FUNCTION__,
-          depth_process_block);
-    return BAD_VALUE;
-  }
-
-  if (hal_configured_streams == nullptr) {
-    ALOGE("%s: hal_configured_streams (%p) is nullptr", __FUNCTION__,
-          hal_configured_streams);
-    return BAD_VALUE;
-  }
-
-  if (is_hdrplus_supported_ && hdrplus_process_block == nullptr) {
-    ALOGE("%s: hdrplus_process_block is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  status_t res = device_session_hwl_->BuildPipelines();
-  if (res != OK) {
-    ALOGE("%s: Building pipelines failed: %s(%d)", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  res = realtime_process_block->GetConfiguredHalStreams(hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Getting HAL streams failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  res = AllocateInternalBuffers(stream_config, hal_configured_streams,
-                                hdrplus_process_block);
-
-  // Need to update hal_configured_streams if there is a depth stream
-  std::vector<HalStream> depth_streams;
-  if (has_depth_stream_) {
-    res = depth_process_block->GetConfiguredHalStreams(&depth_streams);
-    if (res != OK) {
-      ALOGE("%s: Failed to get configured hal streams from DepthProcessBlock",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-
-    // Depth Process Block can only configure one depth stream so far
-    if (depth_streams.size() != 1) {
-      ALOGE("%s: DepthProcessBlock configured more than one stream.",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-
-    hal_configured_streams->push_back(depth_streams[0]);
-  }
-
-  if (res != OK) {
-    ALOGE("%s: Allocating buffer for internal stream managers failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  hal_utils::DumpHalConfiguredStreams(*hal_configured_streams,
-                                      "hal_configured_streams BEFORE purge");
-
-  // TODO(b/128633958): cover the streams Depth PB processes
-  res = PurgeHalConfiguredStream(stream_config, hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Removing internal streams from configured stream failed: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return res;
-  }
-
-  hal_utils::DumpHalConfiguredStreams(*hal_configured_streams,
-                                      "hal_configured_streams AFTER purge");
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::InitializeCameraIds(
-    CameraDeviceSessionHwl* device_session_hwl) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: Device session hwl is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl->GetPhysicalCameraIds();
-  if (physical_camera_ids.size() != 3) {
-    ALOGE("%s: Failed to initialize camera ids. Only support 3 cameras",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // TODO(b/127322570): Figure out physical camera IDs from static metadata.
-  rgb_camera_id_ = physical_camera_ids[0];
-  ir1_camera_id_ = physical_camera_ids[1];
-  ir2_camera_id_ = physical_camera_ids[2];
-  return OK;
-}
-
-status_t RgbirdCaptureSession::Initialize(
-    CameraDeviceSessionHwl* device_session_hwl,
-    const StreamConfiguration& stream_config,
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    HwlRequestBuffersFunc request_stream_buffers,
-    std::vector<HalStream>* hal_configured_streams) {
-  ATRACE_CALL();
-  if (!IsStreamConfigurationSupported(device_session_hwl, stream_config)) {
-    ALOGE("%s: stream configuration is not supported.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  force_internal_stream_ =
-      property_get_bool("persist.vendor.camera.rgbird.forceinternal", false);
-  if (force_internal_stream_) {
-    ALOGI("%s: Force creating internal streams for IR pipelines", __FUNCTION__);
-  }
-
-  device_session_hwl_ = device_session_hwl;
-  internal_stream_manager_ = InternalStreamManager::Create();
-  if (internal_stream_manager_ == nullptr) {
-    ALOGE("%s: Cannot create internal stream manager.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  is_hdrplus_supported_ = hal_utils::IsStreamHdrplusCompatible(
-      stream_config, characteristics.get());
-
-  if (is_hdrplus_supported_) {
-    for (auto stream : stream_config.streams) {
-      if (utils::IsPreviewStream(stream)) {
-        hal_preview_stream_id_ = stream.id;
-        break;
-      }
-    }
-  }
-
-  // Create result dispatcher
-  result_dispatcher_ =
-      ResultDispatcher::Create(kPartialResult, process_capture_result,
-                               /*process_batch_capture_result=*/nullptr, notify,
-                               stream_config, "RgbirdDispatcher");
-  if (result_dispatcher_ == nullptr) {
-    ALOGE("%s: Cannot create result dispatcher.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Reroute callback functions
-  device_session_notify_ = notify;
-  process_capture_result_ =
-      ProcessCaptureResultFunc([this](std::unique_ptr<CaptureResult> result) {
-        ProcessCaptureResult(std::move(result));
-      });
-  notify_ = NotifyFunc(
-      [this](const NotifyMessage& message) { NotifyHalMessage(message); });
-  request_stream_buffers_ = request_stream_buffers;
-
-  // Initialize physical camera ids
-  res = InitializeCameraIds(device_session_hwl_);
-  if (res != OK) {
-    ALOGE("%s: Initializing camera ids failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  for (auto& stream : stream_config.streams) {
-    if (utils::IsDepthStream(stream)) {
-      ALOGI("%s: Depth stream exists in the stream config.", __FUNCTION__);
-      has_depth_stream_ = true;
-    }
-  }
-
-  // Finally create the process chains
-  res = CreateProcessChain(stream_config, process_capture_result_, notify_,
-                           hal_configured_streams);
-  if (res != OK) {
-    ALOGE("%s: Creating the process  chain failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  return OK;
-}
-
-status_t RgbirdCaptureSession::ProcessRequest(const CaptureRequest& request) {
-  ATRACE_CALL();
-  bool is_hdrplus_request = false;
-  if (is_hdrplus_supported_) {
-    is_hdrplus_request =
-        hal_utils::IsRequestHdrplusCompatible(request, hal_preview_stream_id_);
-    // TODO: Check if request is HDR+ request when contains a depth buffer
-  }
-
-  status_t res = result_dispatcher_->AddPendingRequest(request);
-  if (res != OK) {
-    ALOGE("%s: frame(%d) fail to AddPendingRequest", __FUNCTION__,
-          request.frame_number);
-    return BAD_VALUE;
-  }
-
-  if (is_hdrplus_request) {
-    ALOGI("%s: hdrplus snapshot (%d), output stream size:%zu", __FUNCTION__,
-          request.frame_number, request.output_buffers.size());
-    res = hdrplus_request_processor_->ProcessRequest(request);
-    if (res != OK) {
-      ALOGI("%s: hdrplus snapshot frame(%d) request to realtime process",
-            __FUNCTION__, request.frame_number);
-      res = rt_request_processor_->ProcessRequest(request);
-    }
-  } else {
-    res = rt_request_processor_->ProcessRequest(request);
-  }
-
-  if (res != OK) {
-    ALOGE("%s: ProcessRequest (%d) fail and remove pending request",
-          __FUNCTION__, request.frame_number);
-    result_dispatcher_->RemovePendingRequest(request.frame_number);
-  }
-  return res;
-}
-
-status_t RgbirdCaptureSession::Flush() {
-  ATRACE_CALL();
-  return rt_request_processor_->Flush();
-}
-
-void RgbirdCaptureSession::ProcessCaptureResult(
-    std::unique_ptr<CaptureResult> result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  status_t res = result_dispatcher_->AddResult(std::move(result));
-  if (res != OK) {
-    ALOGE("%s: fail to AddResult", __FUNCTION__);
-    return;
-  }
-}
-
-void RgbirdCaptureSession::NotifyHalMessage(const NotifyMessage& message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (device_session_notify_ == nullptr) {
-    ALOGE("%s: device_session_notify_ is nullptr. Dropping a message.",
-          __FUNCTION__);
-    return;
-  }
-
-  if (message.type == MessageType::kShutter) {
-    status_t res = result_dispatcher_->AddShutter(
-        message.message.shutter.frame_number,
-        message.message.shutter.timestamp_ns,
-        message.message.shutter.readout_timestamp_ns);
-    if (res != OK) {
-      ALOGE("%s: frame(%d) fail to AddShutter", __FUNCTION__,
-            message.message.shutter.frame_number);
-      return;
-    }
-  } else if (message.type == MessageType::kError) {
-    // drop the error notifications for the internal streams
-    auto error_stream_id = message.message.error.error_stream_id;
-    if (has_depth_stream_ &&
-        message.message.error.error_code == ErrorCode::kErrorBuffer &&
-        error_stream_id != kInvalidStreamId &&
-        (error_stream_id == rgb_internal_yuv_stream_id_ ||
-         error_stream_id == ir1_internal_raw_stream_id_ ||
-         error_stream_id == ir2_internal_raw_stream_id_)) {
-      return;
-    }
-
-    status_t res = result_dispatcher_->AddError(message.message.error);
-    if (res != OK) {
-      ALOGE("%s: AddError for frame %u failed: %s (%d).", __FUNCTION__,
-            message.message.error.frame_number, strerror(-res), res);
-      return;
-    }
-  } else {
-    ALOGW("%s: Unsupported message type: %u", __FUNCTION__, message.type);
-    device_session_notify_(message);
-  }
-}
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/google_camera_hal/rgbird_capture_session.h b/common/hal/google_camera_hal/rgbird_capture_session.h
deleted file mode 100644
index a9da992..0000000
--- a/common/hal/google_camera_hal/rgbird_capture_session.h
+++ /dev/null
@@ -1,257 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_CAPTURE_SESSION_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_CAPTURE_SESSION_H_
-
-#include "camera_buffer_allocator_hwl.h"
-#include "camera_device_session_hwl.h"
-#include "capture_session.h"
-#include "depth_process_block.h"
-#include "hwl_types.h"
-#include "result_dispatcher.h"
-#include "result_processor.h"
-#include "rgbird_depth_result_processor.h"
-#include "rgbird_result_request_processor.h"
-#include "rgbird_rt_request_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// RgbirdCaptureSession implements a CaptureSession that contains a single
-// process chain that consists of
-//
-//   RgbirdRtRequestProcessor -> MultiCameraRtProcessBlock ->
-//     RgbirdResultRequestProcessor -> DepthProcessBlock ->
-//     BasicResultProcessor
-//
-// It only supports a camera device session that consists of one RGB and two
-// IR cameras.
-class RgbirdCaptureSession : public CaptureSession {
- public:
-  // Return if the device session HWL and stream configuration are supported.
-  static bool IsStreamConfigurationSupported(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config);
-
-  // Create a RgbirdCaptureSession.
-  //
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of RgbirdCaptureSession.
-  // stream_config is the stream configuration.
-  // process_capture_result is the callback function to notify results.
-  // notify is the callback function to notify messages.
-  // process_batch_capture_result is the callback function to notify batched
-  // results.
-  // notify is the callback function to notify messages.
-  // hal_configured_streams will be filled with HAL configured streams.
-  // camera_allocator_hwl is owned by the caller and must be valid during the
-  // lifetime of RgbirdCaptureSession
-  static std::unique_ptr<CaptureSession> Create(
-      CameraDeviceSessionHwl* device_session_hwl,
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result,
-      ProcessBatchCaptureResultFunc process_batch_capture_result,
-      NotifyFunc notify, HwlSessionCallback session_callback,
-      std::vector<HalStream>* hal_configured_streams,
-      CameraBufferAllocatorHwl* camera_allocator_hwl = nullptr);
-
-  virtual ~RgbirdCaptureSession();
-
-  // Override functions in CaptureSession start.
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions in CaptureSession end.
-
- protected:
-  RgbirdCaptureSession() = default;
-
- private:
-  static constexpr int32_t kInvalidStreamId = -1;
-  static const uint32_t kRgbRawBufferCount = 16;
-  // Min required buffer count of internal raw stream.
-  static const uint32_t kRgbMinRawBufferCount = 12;
-  static constexpr uint32_t kPartialResult = 1;
-  static const android_pixel_format_t kHdrplusRawFormat = HAL_PIXEL_FORMAT_RAW10;
-  static const uint32_t kDefaultInternalBufferCount = 8;
-
-  status_t Initialize(CameraDeviceSessionHwl* device_session_hwl,
-                      const StreamConfiguration& stream_config,
-                      ProcessCaptureResultFunc process_capture_result,
-                      NotifyFunc notify,
-                      HwlRequestBuffersFunc request_stream_buffers,
-                      std::vector<HalStream>* hal_configured_streams);
-
-  // Create a process chain that contains a realtime process block and a
-  // depth process block.
-  status_t CreateProcessChain(const StreamConfiguration& stream_config,
-                              ProcessCaptureResultFunc process_capture_result,
-                              NotifyFunc notify,
-                              std::vector<HalStream>* hal_configured_streams);
-
-  // Check if all streams in stream_config are also in
-  // process_block_stream_config.
-  bool AreAllStreamsConfigured(
-      const StreamConfiguration& stream_config,
-      const StreamConfiguration& process_block_stream_config) const;
-
-  // Setup realtime process chain
-  status_t SetupRealtimeProcessChain(
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      std::unique_ptr<ProcessBlock>* realtime_process_block,
-      std::unique_ptr<RgbirdResultRequestProcessor>* realtime_result_processor,
-      std::unique_ptr<ProcessBlock>* depth_process_block,
-      std::unique_ptr<ResultProcessor>* depth_result_processor);
-
-  // Setup hdrplus process chain
-  status_t SetupHdrplusProcessChain(
-      const StreamConfiguration& stream_config,
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      std::unique_ptr<ProcessBlock>* hdrplus_process_block,
-      std::unique_ptr<ResultProcessor>* hdrplus_result_processor);
-
-  // Configure streams for the process chain.
-  status_t ConfigureStreams(const StreamConfiguration& stream_config,
-                            RequestProcessor* request_processor,
-                            ProcessBlock* process_block,
-                            StreamConfiguration* process_block_stream_config);
-
-  // Build pipelines and return HAL configured streams.
-  // Allocate internal raw buffer
-  status_t BuildPipelines(const StreamConfiguration& stream_config,
-                          ProcessBlock* realtime_process_block,
-                          ProcessBlock* depth_process_block,
-                          ProcessBlock* hdrplus_process_block,
-                          std::vector<HalStream>* hal_configured_streams);
-
-  // Connect the process chain.
-  status_t ConnectProcessChain(RequestProcessor* request_processor,
-                               std::unique_ptr<ProcessBlock> process_block,
-                               std::unique_ptr<ResultProcessor> result_processor);
-
-  // Invoked when receiving a result from result processor.
-  void ProcessCaptureResult(std::unique_ptr<CaptureResult> result);
-
-  // Invoked when reciving a message from result processor.
-  void NotifyHalMessage(const NotifyMessage& message);
-
-  // Get internal rgb raw stream id from request processor.
-  status_t ConfigureHdrplusRawStreamId(
-      const StreamConfiguration& process_block_stream_config);
-
-  // Get internal RGB YUV stream id and IR RAW streams from request processor in
-  // case depth is configured.
-  status_t SetDepthInternalStreamId(
-      const StreamConfiguration& process_block_stream_config,
-      const StreamConfiguration& stream_config);
-
-  // Combine usage of realtime and HDR+ hal stream
-  // And allocate internal rgb raw stream buffers
-  status_t ConfigureHdrplusUsageAndBuffers(
-      std::vector<HalStream>* hal_configured_streams,
-      std::vector<HalStream>* hdrplus_hal_configured_streams);
-
-  // Allocate buffers for internal stream buffer managers
-  status_t AllocateInternalBuffers(
-      const StreamConfiguration& framework_stream_config,
-      std::vector<HalStream>* hal_configured_streams,
-      ProcessBlock* hdrplus_process_block);
-
-  // Initialize physical camera ids from the camera characteristics
-  status_t InitializeCameraIds(CameraDeviceSessionHwl* device_session_hwl);
-
-  // Remove internal streams from the hal configured stream list
-  status_t PurgeHalConfiguredStream(
-      const StreamConfiguration& stream_config,
-      std::vector<HalStream>* hal_configured_streams);
-
-  // Determine if a depth process block is needed the capture session
-  bool NeedDepthProcessBlock() const;
-
-  // Create stream config for the Depth process chain segment
-  // Keep all output stream from stream_config, change rt internal streams added
-  // for depth processing as input streams.
-  status_t MakeDepthStreamConfig(
-      const StreamConfiguration& rt_process_block_stream_config,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* depth_stream_config);
-
-  // Create the segment of chain that contains a depth process block
-  status_t CreateDepthChainSegment(
-      std::unique_ptr<DepthProcessBlock>* depth_process_block,
-      std::unique_ptr<RgbirdDepthResultProcessor>* depth_result_processor,
-      RgbirdResultRequestProcessor* rt_result_processor,
-      const StreamConfiguration& overall_config,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* depth_block_stream_config);
-
-  // Setup the offline segment connecting to the realtime process chain
-  status_t SetupDepthChainSegment(
-      const StreamConfiguration& stream_config,
-      RgbirdResultRequestProcessor* realtime_result_processor,
-      std::unique_ptr<ProcessBlock>* depth_process_block,
-      std::unique_ptr<ResultProcessor>* depth_result_processor,
-      StreamConfiguration* rt_process_block_stream_config);
-
-  // device_session_hwl_ is owned by the client.
-  CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
-  std::unique_ptr<InternalStreamManager> internal_stream_manager_;
-
-  std::unique_ptr<RgbirdRtRequestProcessor> rt_request_processor_;
-
-  std::unique_ptr<RequestProcessor> hdrplus_request_processor_;
-
-  std::unique_ptr<ResultDispatcher> result_dispatcher_;
-
-  std::mutex callback_lock_;
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-  HwlRequestBuffersFunc request_stream_buffers_;
-
-  // For error notify to framework directly
-  NotifyFunc device_session_notify_;
-  int32_t rgb_raw_stream_id_ = kInvalidStreamId;
-  bool is_hdrplus_supported_ = false;
-
-  // Whether the stream configuration has depth stream
-  bool has_depth_stream_ = false;
-  // Internal YUV stream id if there is a depth stream configured
-  int32_t rgb_internal_yuv_stream_id_ = kInvalidStreamId;
-  // Internal IR source stream id
-  int32_t ir1_internal_raw_stream_id_ = kInvalidStreamId;
-  // Internal IR target stream id
-  int32_t ir2_internal_raw_stream_id_ = kInvalidStreamId;
-
-  // Camera ids parsed from the characteristics
-  uint32_t rgb_camera_id_ = 0;
-  // Ir1 generates the src buffer for depth
-  uint32_t ir1_camera_id_ = 0;
-  // Ir2 generates the tar buffer for depth
-  uint32_t ir2_camera_id_ = 0;
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  bool force_internal_stream_ = false;
-  // Use this stream id to check the request is HDR+ compatible
-  int32_t hal_preview_stream_id_ = -1;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_CAPTURE_SESSION_H_
diff --git a/common/hal/google_camera_hal/rgbird_depth_result_processor.cc b/common/hal/google_camera_hal/rgbird_depth_result_processor.cc
deleted file mode 100644
index 591a6a6..0000000
--- a/common/hal/google_camera_hal/rgbird_depth_result_processor.cc
+++ /dev/null
@@ -1,152 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_RgbirdDepthResultProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "rgbird_depth_result_processor.h"
-
-#include <inttypes.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-
-namespace android {
-namespace google_camera_hal {
-std::unique_ptr<RgbirdDepthResultProcessor> RgbirdDepthResultProcessor::Create(
-    InternalStreamManager* internal_stream_manager) {
-  if (internal_stream_manager == nullptr) {
-    ALOGE("%s: internal_stream_manager is null.", __FUNCTION__);
-    return nullptr;
-  }
-
-  auto result_processor = std::unique_ptr<RgbirdDepthResultProcessor>(
-      new RgbirdDepthResultProcessor(internal_stream_manager));
-  if (result_processor == nullptr) {
-    ALOGE("%s: Failed to create RgbirdDepthResultProcessor.", __FUNCTION__);
-    return nullptr;
-  }
-
-  return result_processor;
-}
-
-RgbirdDepthResultProcessor::RgbirdDepthResultProcessor(
-    InternalStreamManager* internal_stream_manager)
-    : internal_stream_manager_(internal_stream_manager) {
-}
-
-void RgbirdDepthResultProcessor::SetResultCallback(
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  process_capture_result_ = process_capture_result;
-  notify_ = notify;
-}
-
-status_t RgbirdDepthResultProcessor::AddPendingRequests(
-    const std::vector<ProcessBlockRequest>& process_block_requests,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  // This is the last result processor. Sanity check if requests contains
-  // all remaining output buffers.
-  if (!hal_utils::AreAllRemainingBuffersRequested(process_block_requests,
-                                                  remaining_session_request)) {
-    ALOGE("%s: Some output buffers will not be completed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  return OK;
-}
-
-void RgbirdDepthResultProcessor::ProcessResult(ProcessBlockResult block_result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  std::unique_ptr<CaptureResult> result = std::move(block_result.result);
-  if (result == nullptr) {
-    ALOGW("%s: block_result has a null result.", __FUNCTION__);
-    return;
-  }
-
-  if (process_capture_result_ == nullptr) {
-    ALOGE("%s: process_capture_result_ is null, dropping a result.",
-          __FUNCTION__);
-    return;
-  }
-
-  // Depth Process Block should not return result metadata
-  if (result->result_metadata != nullptr) {
-    ALOGE("%s: non-null result metadata received from the depth process block",
-          __FUNCTION__);
-    return;
-  }
-
-  // Depth Process Block only returns depth stream buffer, so recycle any input
-  // buffers to internal stream manager and forward the depth buffer to the
-  // framework right away.
-  for (auto& buffer : result->input_buffers) {
-    // If the stream id is invalid. The input buffer is only a place holder
-    // corresponding to the input buffer metadata for the rgb pipeline.
-    if (buffer.stream_id == kInvalidStreamId) {
-      continue;
-    }
-
-    status_t res = internal_stream_manager_->ReturnStreamBuffer(buffer);
-    if (res != OK) {
-      ALOGE(
-          "%s: Failed to returned internal buffer[buffer_handle:%p, "
-          "stream_id:%d, buffer_id%" PRIu64 "].",
-          __FUNCTION__, buffer.buffer, buffer.stream_id, buffer.buffer_id);
-    } else {
-      ALOGV(
-          "%s: Successfully returned internal buffer[buffer_handle:%p, "
-          "stream_id:%d, buffer_id%" PRIu64 "].",
-          __FUNCTION__, buffer.buffer, buffer.stream_id, buffer.buffer_id);
-    }
-  }
-  result->input_buffers.clear();
-
-  process_capture_result_(std::move(result));
-}
-
-void RgbirdDepthResultProcessor::Notify(
-    const ProcessBlockNotifyMessage& block_message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  const NotifyMessage& message = block_message.message;
-  if (notify_ == nullptr) {
-    ALOGE("%s: notify_ is null, dropping a message", __FUNCTION__);
-    return;
-  }
-
-  if (message.type != MessageType::kError) {
-    ALOGE(
-        "%s: depth result processor is not supposed to return shutter, "
-        "dropping a message.",
-        __FUNCTION__);
-    return;
-  }
-
-  notify_(message);
-}
-
-status_t RgbirdDepthResultProcessor::FlushPendingRequests() {
-  ATRACE_CALL();
-  return INVALID_OPERATION;
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/rgbird_depth_result_processor.h b/common/hal/google_camera_hal/rgbird_depth_result_processor.h
deleted file mode 100644
index e4f201c..0000000
--- a/common/hal/google_camera_hal/rgbird_depth_result_processor.h
+++ /dev/null
@@ -1,74 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_DEPTH_RESULT_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_DEPTH_RESULT_PROCESSOR_H_
-
-#include "internal_stream_manager.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// RgbirdDepthResultProcessor implements a ResultProcessor that returns depth
-// stream to the framework, and the internal NIR raw streams(and optionally
-// internal YUV stream) to the capture session internal stream manager.
-// It is assumed that the result metadata and shutter has been reported to the
-// framework by the request_result_processor before depth process block. So
-// RgbirdDepthResultProcessor is not responsible for metadata or shutter
-// notification. It only needs to return/recycle buffers unless there is an
-// error returned from the depth process block.
-class RgbirdDepthResultProcessor : public ResultProcessor {
- public:
-  static std::unique_ptr<RgbirdDepthResultProcessor> Create(
-      InternalStreamManager* internal_stream_manager);
-
-  virtual ~RgbirdDepthResultProcessor() = default;
-
-  // Override functions of ResultProcessor start.
-  void SetResultCallback(
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
-
-  status_t AddPendingRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  void ProcessResult(ProcessBlockResult block_result) override;
-
-  void Notify(const ProcessBlockNotifyMessage& block_message) override;
-
-  status_t FlushPendingRequests() override;
-  // Override functions of ResultProcessor end.
-
- protected:
-  RgbirdDepthResultProcessor(InternalStreamManager* internal_stream_manager);
-
- private:
-  static constexpr int32_t kInvalidStreamId = -1;
-  InternalStreamManager* internal_stream_manager_ = nullptr;
-
-  std::mutex callback_lock_;
-
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_DEPTH_RESULT_PROCESSOR_H_
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/rgbird_result_request_processor.cc b/common/hal/google_camera_hal/rgbird_result_request_processor.cc
deleted file mode 100644
index a05384c..0000000
--- a/common/hal/google_camera_hal/rgbird_result_request_processor.cc
+++ /dev/null
@@ -1,877 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_RgbirdResultRequestProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "rgbird_result_request_processor.h"
-
-#include <cutils/native_handle.h>
-#include <cutils/properties.h>
-#include <inttypes.h>
-#include <log/log.h>
-#include <sync/sync.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<RgbirdResultRequestProcessor> RgbirdResultRequestProcessor::Create(
-    const RgbirdResultRequestProcessorCreateData& create_data) {
-  ATRACE_CALL();
-  auto result_processor = std::unique_ptr<RgbirdResultRequestProcessor>(
-      new RgbirdResultRequestProcessor(create_data));
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating RgbirdResultRequestProcessor failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  result_processor->force_internal_stream_ =
-      property_get_bool("persist.vendor.camera.rgbird.forceinternal", false);
-  if (result_processor->force_internal_stream_) {
-    ALOGI("%s: Force creating internal streams for IR pipelines", __FUNCTION__);
-  }
-
-  // TODO(b/129910835): Change the controlling prop into some deterministic
-  // logic that controls when the front depth autocal will be triggered.
-  result_processor->rgb_ir_auto_cal_enabled_ =
-      property_get_bool("vendor.camera.frontdepth.enableautocal", true);
-  if (result_processor->rgb_ir_auto_cal_enabled_) {
-    ALOGI("%s: autocal is enabled.", __FUNCTION__);
-  }
-
-  return result_processor;
-}
-
-RgbirdResultRequestProcessor::RgbirdResultRequestProcessor(
-    const RgbirdResultRequestProcessorCreateData& create_data)
-    : kRgbCameraId(create_data.rgb_camera_id),
-      kIr1CameraId(create_data.ir1_camera_id),
-      kIr2CameraId(create_data.ir2_camera_id),
-      rgb_raw_stream_id_(create_data.rgb_raw_stream_id),
-      is_hdrplus_supported_(create_data.is_hdrplus_supported),
-      rgb_internal_yuv_stream_id_(create_data.rgb_internal_yuv_stream_id) {
-}
-
-void RgbirdResultRequestProcessor::SetResultCallback(
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  process_capture_result_ = process_capture_result;
-  notify_ = notify;
-}
-
-void RgbirdResultRequestProcessor::SaveFdForHdrplus(
-    const CaptureRequest& request) {
-  // Enable face detect mode for internal use
-  if (request.settings != nullptr) {
-    uint8_t fd_mode;
-    status_t res = hal_utils::GetFdMode(request, &fd_mode);
-    if (res == OK) {
-      current_face_detect_mode_ = fd_mode;
-    }
-  }
-
-  {
-    std::lock_guard<std::mutex> lock(face_detect_lock_);
-    requested_face_detect_modes_.emplace(request.frame_number,
-                                         current_face_detect_mode_);
-  }
-}
-
-void RgbirdResultRequestProcessor::SaveLsForHdrplus(
-    const CaptureRequest& request) {
-  if (request.settings != nullptr) {
-    uint8_t lens_shading_map_mode;
-    status_t res =
-        hal_utils::GetLensShadingMapMode(request, &lens_shading_map_mode);
-    if (res == OK) {
-      current_lens_shading_map_mode_ = lens_shading_map_mode;
-    }
-  }
-
-  {
-    std::lock_guard<std::mutex> lock(lens_shading_lock_);
-    requested_lens_shading_map_modes_.emplace(request.frame_number,
-                                              current_lens_shading_map_mode_);
-  }
-}
-
-status_t RgbirdResultRequestProcessor::HandleLsResultForHdrplus(
-    uint32_t frameNumber, HalCameraMetadata* metadata) {
-  if (metadata == nullptr) {
-    ALOGE("%s: metadata is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-  std::lock_guard<std::mutex> lock(lens_shading_lock_);
-  auto iter = requested_lens_shading_map_modes_.find(frameNumber);
-  if (iter == requested_lens_shading_map_modes_.end()) {
-    ALOGW("%s: can't find frame (%d)", __FUNCTION__, frameNumber);
-    return OK;
-  }
-
-  if (iter->second == ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF) {
-    status_t res = hal_utils::RemoveLsInfoFromResult(metadata);
-    if (res != OK) {
-      ALOGW("%s: RemoveLsInfoFromResult fail", __FUNCTION__);
-    }
-  }
-  requested_lens_shading_map_modes_.erase(iter);
-
-  return OK;
-}
-
-bool RgbirdResultRequestProcessor::IsAutocalRequest(uint32_t frame_number) const {
-  // TODO(b/129910835): Use the proper logic to control when internal yuv buffer
-  // needs to be passed to the depth process block. Even if the auto cal is
-  // enabled, there is no need to pass the internal yuv buffer for every
-  // request, not even every device session. This is also related to how the
-  // buffer is added into the request. Similar logic exists in realtime request
-  // processor. However, this logic can further filter and determine which
-  // requests contain the internal yuv stream buffers and send them to the depth
-  // process block. Current implementation only treat the kAutocalFrameNumber
-  // request as autocal request. This must be consistent with that of the
-  // rt_request_processor.
-  if (!rgb_ir_auto_cal_enabled_) {
-    return false;
-  }
-
-  return frame_number == kAutocalFrameNumber;
-}
-
-void RgbirdResultRequestProcessor::TryReturnInternalBufferForDepth(
-    CaptureResult* result, bool* has_internal) {
-  ATRACE_CALL();
-  if (result == nullptr || has_internal == nullptr) {
-    ALOGE("%s: result or has_rgb_raw_output is nullptr", __FUNCTION__);
-    return;
-  }
-
-  if (internal_stream_manager_ == nullptr) {
-    ALOGE("%s: internal_stream_manager_ nullptr", __FUNCTION__);
-    return;
-  }
-
-  std::vector<StreamBuffer> modified_output_buffers;
-  for (uint32_t i = 0; i < result->output_buffers.size(); i++) {
-    if (rgb_internal_yuv_stream_id_ == result->output_buffers[i].stream_id &&
-        !IsAutocalRequest(result->frame_number)) {
-      *has_internal = true;
-      status_t res = internal_stream_manager_->ReturnStreamBuffer(
-          result->output_buffers[i]);
-      if (res != OK) {
-        ALOGW("%s: Failed to return RGB internal raw buffer for frame %d",
-              __FUNCTION__, result->frame_number);
-      }
-    } else {
-      modified_output_buffers.push_back(result->output_buffers[i]);
-    }
-  }
-
-  if (!result->output_buffers.empty()) {
-    result->output_buffers = modified_output_buffers;
-  }
-}
-
-status_t RgbirdResultRequestProcessor::HandleFdResultForHdrplus(
-    uint32_t frameNumber, HalCameraMetadata* metadata) {
-  if (metadata == nullptr) {
-    ALOGE("%s: metadata is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-  std::lock_guard<std::mutex> lock(face_detect_lock_);
-  auto iter = requested_face_detect_modes_.find(frameNumber);
-  if (iter == requested_face_detect_modes_.end()) {
-    ALOGW("%s: can't find frame (%d)", __FUNCTION__, frameNumber);
-    return OK;
-  }
-
-  if (iter->second == ANDROID_STATISTICS_FACE_DETECT_MODE_OFF) {
-    status_t res = hal_utils::RemoveFdInfoFromResult(metadata);
-    if (res != OK) {
-      ALOGW("%s: RestoreFdMetadataForHdrplus fail", __FUNCTION__);
-    }
-  }
-  requested_face_detect_modes_.erase(iter);
-
-  return OK;
-}
-
-status_t RgbirdResultRequestProcessor::AddPendingRequests(
-    const std::vector<ProcessBlockRequest>& /*process_block_requests*/,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(depth_requests_mutex_);
-  for (auto stream_buffer : remaining_session_request.output_buffers) {
-    if (stream_buffer.acquire_fence != nullptr) {
-      stream_buffer.acquire_fence =
-          native_handle_clone(stream_buffer.acquire_fence);
-      if (stream_buffer.acquire_fence == nullptr) {
-        ALOGE("%s: Cloning acquire_fence of buffer failed", __FUNCTION__);
-        return UNKNOWN_ERROR;
-      }
-    }
-    if (depth_stream_id_ == stream_buffer.stream_id) {
-      ALOGV("%s: request %d has a depth buffer", __FUNCTION__,
-            remaining_session_request.frame_number);
-      auto capture_request = std::make_unique<CaptureRequest>();
-      capture_request->frame_number = remaining_session_request.frame_number;
-      if (remaining_session_request.settings != nullptr) {
-        capture_request->settings =
-            HalCameraMetadata::Clone(remaining_session_request.settings.get());
-      }
-      capture_request->input_buffers.clear();
-      capture_request->output_buffers.push_back(stream_buffer);
-      depth_requests_.emplace(remaining_session_request.frame_number,
-                              std::move(capture_request));
-      break;
-    }
-  }
-
-  if (is_hdrplus_supported_) {
-    SaveFdForHdrplus(remaining_session_request);
-    SaveLsForHdrplus(remaining_session_request);
-  }
-  return OK;
-}
-
-void RgbirdResultRequestProcessor::ProcessResultForHdrplus(CaptureResult* result,
-                                                           bool* rgb_raw_output) {
-  ATRACE_CALL();
-  if (result == nullptr || rgb_raw_output == nullptr) {
-    ALOGE("%s: result or rgb_raw_output is nullptr", __FUNCTION__);
-    return;
-  }
-
-  if (internal_stream_manager_ == nullptr) {
-    ALOGE("%s: internal_stream_manager_ nullptr", __FUNCTION__);
-    return;
-  }
-
-  // Return filled raw buffer to internal stream manager
-  // And remove raw buffer from result
-  status_t res;
-  std::vector<StreamBuffer> modified_output_buffers;
-  for (uint32_t i = 0; i < result->output_buffers.size(); i++) {
-    if (rgb_raw_stream_id_ == result->output_buffers[i].stream_id) {
-      *rgb_raw_output = true;
-      res = internal_stream_manager_->ReturnFilledBuffer(
-          result->frame_number, result->output_buffers[i]);
-      if (res != OK) {
-        ALOGW("%s: (%d)ReturnStreamBuffer fail", __FUNCTION__,
-              result->frame_number);
-      }
-    } else {
-      modified_output_buffers.push_back(result->output_buffers[i]);
-    }
-  }
-
-  if (result->output_buffers.size() > 0) {
-    result->output_buffers = modified_output_buffers;
-  }
-
-  if (result->result_metadata) {
-    res = internal_stream_manager_->ReturnMetadata(
-        rgb_raw_stream_id_, result->frame_number, result->result_metadata.get());
-    if (res != OK) {
-      ALOGW("%s: (%d)ReturnMetadata fail", __FUNCTION__, result->frame_number);
-    }
-
-    res = HandleFdResultForHdrplus(result->frame_number,
-                                   result->result_metadata.get());
-    if (res != OK) {
-      ALOGE("%s: HandleFdResultForHdrplus(%d) fail", __FUNCTION__,
-            result->frame_number);
-      return;
-    }
-
-    res = HandleLsResultForHdrplus(result->frame_number,
-                                   result->result_metadata.get());
-    if (res != OK) {
-      ALOGE("%s: HandleLsResultForHdrplus(%d) fail", __FUNCTION__,
-            result->frame_number);
-      return;
-    }
-  }
-}
-
-status_t RgbirdResultRequestProcessor::ReturnInternalStreams(
-    CaptureResult* result) {
-  ATRACE_CALL();
-  if (result == nullptr) {
-    ALOGE("%s: block_result is null.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  std::vector<StreamBuffer> modified_output_buffers;
-  for (auto& stream_buffer : result->output_buffers) {
-    if (framework_stream_id_set_.find(stream_buffer.stream_id) ==
-        framework_stream_id_set_.end()) {
-      status_t res = internal_stream_manager_->ReturnStreamBuffer(stream_buffer);
-      if (res != OK) {
-        ALOGE("%s: Failed to return stream buffer.", __FUNCTION__);
-        return UNKNOWN_ERROR;
-      }
-    } else {
-      modified_output_buffers.push_back(stream_buffer);
-    }
-  }
-  result->output_buffers = modified_output_buffers;
-  return OK;
-}
-
-status_t RgbirdResultRequestProcessor::CheckFenceStatus(CaptureRequest* request) {
-  int fence_status = 0;
-
-  if (request == nullptr) {
-    ALOGE("%s: request is null.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  for (uint32_t i = 0; i < request->output_buffers.size(); i++) {
-    if (request->output_buffers[i].acquire_fence != nullptr) {
-      auto fence =
-          const_cast<native_handle_t*>(request->output_buffers[i].acquire_fence);
-      if (fence->numFds == 1) {
-        fence_status = sync_wait(fence->data[0], kSyncWaitTime);
-      }
-      if (0 != fence_status) {
-        ALOGE("%s: Fence check failed.", __FUNCTION__);
-        return UNKNOWN_ERROR;
-      }
-      native_handle_close(fence);
-      native_handle_delete(fence);
-      request->output_buffers[i].acquire_fence = nullptr;
-    }
-  }
-
-  return OK;
-}
-
-bool RgbirdResultRequestProcessor::IsAutocalMetadataReadyLocked(
-    const HalCameraMetadata& metadata) {
-  camera_metadata_ro_entry entry = {};
-  if (metadata.Get(VendorTagIds::kNonWarpedCropRegion, &entry) != OK) {
-    ALOGV("%s Get kNonWarpedCropRegion, tag fail.", __FUNCTION__);
-    return false;
-  }
-
-  uint8_t fd_mode = ANDROID_STATISTICS_FACE_DETECT_MODE_OFF;
-  if (metadata.Get(ANDROID_STATISTICS_FACE_DETECT_MODE, &entry) != OK) {
-    ALOGV("%s Get ANDROID_STATISTICS_FACE_DETECT_MODE tag fail.", __FUNCTION__);
-    return false;
-  } else {
-    fd_mode = *entry.data.u8;
-  }
-
-  // If FD mode is off, don't need to check FD related metadata.
-  if (fd_mode != ANDROID_STATISTICS_FACE_DETECT_MODE_OFF) {
-    if (metadata.Get(ANDROID_STATISTICS_FACE_RECTANGLES, &entry) != OK) {
-      ALOGV("%s Get ANDROID_STATISTICS_FACE_RECTANGLES tag fail.", __FUNCTION__);
-      return false;
-    }
-    if (metadata.Get(ANDROID_STATISTICS_FACE_SCORES, &entry) != OK) {
-      ALOGV("%s Get ANDROID_STATISTICS_FACE_SCORES tag fail.", __FUNCTION__);
-      return false;
-    }
-  }
-
-  return true;
-}
-
-status_t RgbirdResultRequestProcessor::VerifyAndSubmitDepthRequest(
-    uint32_t frame_number) {
-  std::lock_guard<std::mutex> lock(depth_requests_mutex_);
-  if (depth_requests_.find(frame_number) == depth_requests_.end()) {
-    ALOGW("%s: Can not find depth request with frame number %u", __FUNCTION__,
-          frame_number);
-    return NAME_NOT_FOUND;
-  }
-
-  uint32_t valid_input_buffer_num = 0;
-  auto& depth_request = depth_requests_[frame_number];
-  for (auto& input_buffer : depth_request->input_buffers) {
-    if (input_buffer.stream_id != kInvalidStreamId) {
-      valid_input_buffer_num++;
-    }
-  }
-
-  if (IsAutocalRequest(frame_number)) {
-    if (valid_input_buffer_num != /*rgb+ir1+ir2*/ 3) {
-      // not all input buffers are ready, early return properly
-      ALOGV("%s: Not all input buffers are ready for frame %u", __FUNCTION__,
-            frame_number);
-      return OK;
-    }
-  } else {
-    // The input buffer for RGB pipeline could be a place holder to be
-    // consistent with the input buffer metadata.
-    if (valid_input_buffer_num != /*ir1+ir2*/ 2) {
-      // not all input buffers are ready, early return properly
-      ALOGV("%s: Not all input buffers are ready for frame %u", __FUNCTION__,
-            frame_number);
-      return OK;
-    }
-  }
-
-  if (depth_request->input_buffer_metadata.empty()) {
-    // input buffer metadata is not ready(cloned) yet, early return properly
-    ALOGV("%s: Input buffer metadata is not ready for frame %u", __FUNCTION__,
-          frame_number);
-    return OK;
-  }
-
-  // Check against all metadata needed before move on e.g. check against
-  // cropping info, FD result for internal YUV stream
-  status_t res = OK;
-  if (IsAutocalRequest(frame_number)) {
-    bool is_ready = false;
-    for (auto& metadata : depth_request->input_buffer_metadata) {
-      if (metadata != nullptr) {
-        is_ready = IsAutocalMetadataReadyLocked(*(metadata.get()));
-      }
-    }
-    if (!is_ready) {
-      ALOGV("%s: Not all AutoCal Metadata is ready for frame %u.", __FUNCTION__,
-            frame_number);
-      return OK;
-    }
-  }
-
-  res = CheckFenceStatus(depth_request.get());
-  if (res != OK) {
-    ALOGE("%s:Fence status wait failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  res = ProcessRequest(*depth_request.get());
-  if (res != OK) {
-    ALOGE("%s: Failed to submit process request to depth process block.",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  depth_requests_.erase(frame_number);
-  return OK;
-}
-
-status_t RgbirdResultRequestProcessor::TrySubmitDepthProcessBlockRequest(
-    const ProcessBlockResult& block_result) {
-  ATRACE_CALL();
-  uint32_t request_id = block_result.request_id;
-  CaptureResult* result = block_result.result.get();
-  uint32_t frame_number = result->frame_number;
-
-  bool pending_request_updated = false;
-  for (auto& output_buffer : result->output_buffers) {
-    if (request_id == kIr1CameraId || request_id == kIr2CameraId ||
-        (request_id == kRgbCameraId &&
-         rgb_internal_yuv_stream_id_ == output_buffer.stream_id &&
-         IsAutocalRequest(frame_number))) {
-      std::lock_guard<std::mutex> lock(depth_requests_mutex_);
-
-      // In case depth request is flushed
-      if (depth_requests_.find(frame_number) == depth_requests_.end()) {
-        ALOGV("%s: Can not find depth request with frame number %u",
-              __FUNCTION__, frame_number);
-        status_t res =
-            internal_stream_manager_->ReturnStreamBuffer(output_buffer);
-        if (res != OK) {
-          ALOGW(
-              "%s: Failed to return internal buffer for flushed depth request"
-              " %u",
-              __FUNCTION__, frame_number);
-        }
-        continue;
-      }
-
-      // If input_buffer_metadata is not empty, the RGB pipeline result metadata
-      // must have been cloned(other entries for IRs set to nullptr). The
-      // yuv_internal_stream buffer has to be inserted into the corresponding
-      // entry in input_buffers. Or if this is not a AutoCal request, the stream
-      // id for the place holder of the RGB input buffer must be invalid. Refer
-      // the logic below for result metadata handling.
-      const auto& metadata_list =
-          depth_requests_[frame_number]->input_buffer_metadata;
-      auto& input_buffers = depth_requests_[frame_number]->input_buffers;
-      if (!metadata_list.empty()) {
-        uint32_t rgb_metadata_index = 0;
-        for (; rgb_metadata_index < metadata_list.size(); rgb_metadata_index++) {
-          // Only the RGB pipeline result metadata is needed and cloned
-          if (metadata_list[rgb_metadata_index] != nullptr) {
-            break;
-          }
-        }
-
-        if (rgb_metadata_index == metadata_list.size()) {
-          ALOGE("%s: RGB result metadata not found. rgb_metadata_index %u",
-                __FUNCTION__, rgb_metadata_index);
-          return UNKNOWN_ERROR;
-        }
-
-        if (input_buffers.size() < kNumOfAutoCalInputBuffers) {
-          input_buffers.resize(kNumOfAutoCalInputBuffers);
-        }
-
-        if (request_id == kRgbCameraId) {
-          if (input_buffers[rgb_metadata_index].stream_id != kInvalidStreamId) {
-            ALOGE("%s: YUV buffer already exists.", __FUNCTION__);
-            return UNKNOWN_ERROR;
-          }
-          input_buffers[rgb_metadata_index] = output_buffer;
-        } else {
-          for (uint32_t i_buffer = 0; i_buffer < input_buffers.size();
-               i_buffer++) {
-            if (input_buffers[i_buffer].stream_id == kInvalidStreamId &&
-                rgb_metadata_index != i_buffer) {
-              input_buffers[i_buffer] = output_buffer;
-              break;
-            }
-          }
-        }
-      } else {
-        input_buffers.push_back(output_buffer);
-      }
-      pending_request_updated = true;
-    }
-  }
-
-  if (result->result_metadata != nullptr && request_id == kRgbCameraId) {
-    std::lock_guard<std::mutex> lock(depth_requests_mutex_);
-
-    // In case a depth request is flushed
-    if (depth_requests_.find(frame_number) == depth_requests_.end()) {
-      ALOGV("%s No depth request for Autocal", __FUNCTION__);
-      return OK;
-    }
-
-    // If YUV buffer exists in the input_buffers, the RGB pipeline metadata
-    // needs to be inserted into the corresponding entry in
-    // input_buffer_metadata. Otherwise, insert the RGB pipeline metadata into
-    // the entry that is not reserved for any existing IR input buffer. Refer
-    // above logic for input buffer preparation.
-    auto& input_buffers = depth_requests_[frame_number]->input_buffers;
-    auto& metadata_list = depth_requests_[frame_number]->input_buffer_metadata;
-    metadata_list.resize(kNumOfAutoCalInputBuffers);
-    uint32_t yuv_buffer_index = 0;
-    for (; yuv_buffer_index < input_buffers.size(); yuv_buffer_index++) {
-      if (input_buffers[yuv_buffer_index].stream_id ==
-          rgb_internal_yuv_stream_id_) {
-        break;
-      }
-    }
-
-    if (yuv_buffer_index >= kNumOfAutoCalInputBuffers) {
-      ALOGE("%s: input_buffers is full and YUV buffer not found.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-
-    metadata_list[yuv_buffer_index] =
-        HalCameraMetadata::Clone(result->result_metadata.get());
-    if (metadata_list[yuv_buffer_index] == nullptr) {
-      ALOGE("%s: clone RGB pipeline result metadata failed.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-    pending_request_updated = true;
-
-    // If metadata arrives after all IR buffers and there is not RGB buffer
-    if (input_buffers.size() < kNumOfAutoCalInputBuffers) {
-      input_buffers.resize(kNumOfAutoCalInputBuffers);
-    }
-  }
-
-  if (pending_request_updated) {
-    status_t res = VerifyAndSubmitDepthRequest(frame_number);
-    if (res != OK) {
-      ALOGE("%s: Failed to verify and submit depth request.", __FUNCTION__);
-      return res;
-    }
-  }
-
-  return OK;
-}
-
-void RgbirdResultRequestProcessor::ProcessResult(ProcessBlockResult block_result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (block_result.result == nullptr) {
-    ALOGW("%s: Received a nullptr result.", __FUNCTION__);
-    return;
-  }
-
-  if (process_capture_result_ == nullptr) {
-    ALOGE("%s: process_capture_result_ is nullptr. Dropping a result.",
-          __FUNCTION__);
-    return;
-  }
-
-  CaptureResult* result = block_result.result.get();
-
-  bool has_internal_stream_buffer = false;
-  if (is_hdrplus_supported_) {
-    ProcessResultForHdrplus(result, &has_internal_stream_buffer);
-  } else if (depth_stream_id_ != -1) {
-    TryReturnInternalBufferForDepth(result, &has_internal_stream_buffer);
-  }
-
-  status_t res = OK;
-  if (result->result_metadata) {
-    res = hal_utils::SetEnableZslMetadata(result->result_metadata.get(), false);
-    if (res != OK) {
-      ALOGW("%s: SetEnableZslMetadata (%d) fail", __FUNCTION__,
-            result->frame_number);
-    }
-  }
-
-  // Don't send result to framework if only internal raw callback
-  if (has_internal_stream_buffer && result->result_metadata == nullptr &&
-      result->output_buffers.size() == 0 && result->input_buffers.size() == 0) {
-    return;
-  }
-
-  // TODO(b/128633958): remove the following once FLL syncing is verified
-  {
-    std::lock_guard<std::mutex> lock(depth_requests_mutex_);
-    if (((force_internal_stream_) ||
-         (depth_requests_.find(result->frame_number) == depth_requests_.end())) &&
-        (depth_stream_id_ != -1)) {
-      res = ReturnInternalStreams(result);
-      if (res != OK) {
-        ALOGE("%s: Failed to return internal buffers.", __FUNCTION__);
-        return;
-      }
-    }
-  }
-
-  // Save necessary data for depth process block request
-  res = TrySubmitDepthProcessBlockRequest(block_result);
-  if (res != OK) {
-    ALOGE("%s: Failed to submit depth process block request.", __FUNCTION__);
-    return;
-  }
-
-  if (block_result.request_id != kRgbCameraId) {
-    return;
-  }
-
-  // If internal yuv stream remains in the result output buffer list, it must
-  // be used by some other purposes and will be returned separately. It should
-  // not be returned through the process_capture_result_. So we remove them here.
-  if (!result->output_buffers.empty()) {
-    auto iter = result->output_buffers.begin();
-    while (iter != result->output_buffers.end()) {
-      if (iter->stream_id == rgb_internal_yuv_stream_id_) {
-        result->output_buffers.erase(iter);
-        break;
-      }
-      iter++;
-    }
-  }
-
-  process_capture_result_(std::move(block_result.result));
-}
-
-void RgbirdResultRequestProcessor::Notify(
-    const ProcessBlockNotifyMessage& block_message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (notify_ == nullptr) {
-    ALOGE("%s: notify_ is nullptr. Dropping a message.", __FUNCTION__);
-    return;
-  }
-
-  const NotifyMessage& message = block_message.message;
-  // Request ID is set to camera ID by RgbirdRtRequestProcessor.
-  uint32_t camera_id = block_message.request_id;
-  if (message.type == MessageType::kShutter && camera_id != kRgbCameraId) {
-    // Only send out shutters from the lead camera.
-    return;
-  }
-
-  notify_(block_message.message);
-}
-
-status_t RgbirdResultRequestProcessor::ConfigureStreams(
-    InternalStreamManager* internal_stream_manager,
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (process_block_stream_config == nullptr) {
-    ALOGE("%s: process_block_stream_config is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  if (internal_stream_manager == nullptr) {
-    ALOGE("%s: internal_stream_manager is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-  internal_stream_manager_ = internal_stream_manager;
-
-  if (is_hdrplus_supported_) {
-    return OK;
-  }
-
-  process_block_stream_config->streams.clear();
-  Stream depth_stream = {};
-  for (auto& stream : stream_config.streams) {
-    // stream_config passed to this ConfigureStreams must contain only framework
-    // output and internal input streams
-    if (stream.stream_type == StreamType::kOutput) {
-      if (utils::IsDepthStream(stream)) {
-        ALOGI("%s: Depth stream id: %u observed by RgbirdResReqProcessor.",
-              __FUNCTION__, stream.id);
-        depth_stream_id_ = stream.id;
-        depth_stream = stream;
-      }
-      // record all framework output, save depth only for depth process block
-      framework_stream_id_set_.insert(stream.id);
-    } else if (stream.stream_type == StreamType::kInput) {
-      process_block_stream_config->streams.push_back(stream);
-    }
-  }
-
-  // TODO(b/128633958): remove force flag after FLL syncing is verified
-  if (force_internal_stream_ || depth_stream_id_ != -1) {
-    process_block_stream_config->streams.push_back(depth_stream);
-    process_block_stream_config->operation_mode = stream_config.operation_mode;
-    process_block_stream_config->session_params =
-        HalCameraMetadata::Clone(stream_config.session_params.get());
-    process_block_stream_config->stream_config_counter =
-        stream_config.stream_config_counter;
-  }
-  process_block_stream_config->log_id = stream_config.log_id;
-
-  return OK;
-}
-
-status_t RgbirdResultRequestProcessor::SetProcessBlock(
-    std::unique_ptr<ProcessBlock> process_block) {
-  ATRACE_CALL();
-  if (process_block == nullptr) {
-    ALOGE("%s: process_block is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(depth_process_block_lock_);
-  if (depth_process_block_ != nullptr) {
-    ALOGE("%s: Already configured.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  depth_process_block_ = std::move(process_block);
-  return OK;
-}
-
-status_t RgbirdResultRequestProcessor::ProcessRequest(
-    const CaptureRequest& request) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(depth_process_block_lock_);
-  if (depth_process_block_ == nullptr) {
-    ALOGE("%s: depth_process_block_ is null.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  // Depth Process Block only handles one process block request each time
-  std::vector<ProcessBlockRequest> process_block_requests(1);
-  auto& block_request = process_block_requests[0];
-  block_request.request_id = 0;
-  CaptureRequest& physical_request = block_request.request;
-  physical_request.frame_number = request.frame_number;
-  physical_request.settings = HalCameraMetadata::Clone(request.settings.get());
-  for (auto& metadata : request.input_buffer_metadata) {
-    physical_request.input_buffer_metadata.emplace_back(
-        HalCameraMetadata::Clone(metadata.get()));
-  }
-  physical_request.input_buffers = request.input_buffers;
-  physical_request.output_buffers = request.output_buffers;
-
-  return depth_process_block_->ProcessRequests(process_block_requests, request);
-}
-
-status_t RgbirdResultRequestProcessor::Flush() {
-  ATRACE_CALL();
-
-  std::lock_guard<std::mutex> lock(depth_process_block_lock_);
-  if (depth_process_block_ == nullptr) {
-    ALOGW("%s: depth_process_block_ is null.", __FUNCTION__);
-    return OK;
-  }
-
-  return depth_process_block_->Flush();
-}
-
-status_t RgbirdResultRequestProcessor::FlushPendingRequests() {
-  ATRACE_CALL();
-
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (notify_ == nullptr) {
-    ALOGE("%s: notify_ is nullptr. Dropping a message.", __FUNCTION__);
-    return OK;
-  }
-
-  if (process_capture_result_ == nullptr) {
-    ALOGE("%s: process_capture_result_ is nullptr. Dropping a result.",
-          __FUNCTION__);
-    return OK;
-  }
-
-  std::lock_guard<std::mutex> requests_lock(depth_requests_mutex_);
-  for (auto& [frame_number, capture_request] : depth_requests_) {
-    // Returns all internal stream buffers
-    for (auto& input_buffer : capture_request->input_buffers) {
-      if (input_buffer.stream_id != kInvalidStreamId) {
-        status_t res =
-            internal_stream_manager_->ReturnStreamBuffer(input_buffer);
-        if (res != OK) {
-          ALOGW("%s: Failed to return internal buffer for depth request %d",
-                __FUNCTION__, frame_number);
-        }
-      }
-    }
-
-    // Notify buffer error for the depth stream output buffer
-    const NotifyMessage message = {
-        .type = MessageType::kError,
-        .message.error = {.frame_number = frame_number,
-                          .error_stream_id = depth_stream_id_,
-                          .error_code = ErrorCode::kErrorBuffer}};
-    notify_(message);
-
-    // Return output buffer for the depth stream
-    auto result = std::make_unique<CaptureResult>();
-    result->frame_number = frame_number;
-    for (auto& output_buffer : capture_request->output_buffers) {
-      if (output_buffer.stream_id == depth_stream_id_) {
-        result->output_buffers.push_back(output_buffer);
-        auto& buffer = result->output_buffers.back();
-        buffer.status = BufferStatus::kError;
-        buffer.acquire_fence = nullptr;
-        buffer.release_fence = nullptr;
-        break;
-      }
-    }
-    process_capture_result_(std::move(result));
-  }
-  depth_requests_.clear();
-  ALOGI("%s: Flushing depth requests done. ", __FUNCTION__);
-  return OK;
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/google_camera_hal/rgbird_result_request_processor.h b/common/hal/google_camera_hal/rgbird_result_request_processor.h
deleted file mode 100644
index 84ee2c1..0000000
--- a/common/hal/google_camera_hal/rgbird_result_request_processor.h
+++ /dev/null
@@ -1,201 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_RESULT_REQUEST_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_RESULT_REQUEST_PROCESSOR_H_
-
-#include <set>
-
-#include "request_processor.h"
-#include "result_processor.h"
-#include "vendor_tag_defs.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// RgbirdResultRequestProcessor implements a ResultProcessor handling realtime
-// capture results for a logical camera consisting of one RGB and two IR camera
-// sensors.
-class RgbirdResultRequestProcessor : public ResultProcessor,
-                                     public RequestProcessor {
- public:
-  struct RgbirdResultRequestProcessorCreateData {
-    // camera id of the color sensor
-    uint32_t rgb_camera_id = 0;
-    // camera id of the NIR sensor used as source
-    uint32_t ir1_camera_id = 0;
-    // camera id of the NIR sensor used as target
-    uint32_t ir2_camera_id = 0;
-    // stream id of the internal raw stream for hdr+
-    int32_t rgb_raw_stream_id = -1;
-    // whether hdr+ is supported
-    bool is_hdrplus_supported = false;
-    // stream id of the internal yuv stream in case depth is configured
-    int32_t rgb_internal_yuv_stream_id = -1;
-  };
-
-  static std::unique_ptr<RgbirdResultRequestProcessor> Create(
-      const RgbirdResultRequestProcessorCreateData& create_data);
-
-  virtual ~RgbirdResultRequestProcessor() = default;
-
-  // Override functions of ResultProcessor start.
-  void SetResultCallback(
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
-
-  status_t AddPendingRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  void ProcessResult(ProcessBlockResult block_result) override;
-
-  void Notify(const ProcessBlockNotifyMessage& block_message) override;
-
-  status_t FlushPendingRequests() override;
-  // Override functions of ResultProcessor end.
-
-  // Override functions of RequestProcessor start.
-  status_t ConfigureStreams(
-      InternalStreamManager* internal_stream_manager,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config) override;
-
-  status_t SetProcessBlock(std::unique_ptr<ProcessBlock> process_block) override;
-
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions of RequestProcessor end.
-
- protected:
-  RgbirdResultRequestProcessor(
-      const RgbirdResultRequestProcessorCreateData& create_data);
-
- private:
-  static constexpr int32_t kInvalidStreamId = -1;
-  static constexpr uint32_t kAutocalFrameNumber = 5;
-  static constexpr uint32_t kNumOfAutoCalInputBuffers = /*YUV+IR+IR*/ 3;
-  const uint32_t kRgbCameraId;
-  const uint32_t kIr1CameraId;
-  const uint32_t kIr2CameraId;
-  const int32_t kSyncWaitTime = 5000;  // milliseconds
-
-  void ProcessResultForHdrplus(CaptureResult* result, bool* rgb_raw_output);
-  // Return the RGB internal YUV stream buffer if there is any and depth is
-  // configured
-  void TryReturnInternalBufferForDepth(CaptureResult* result,
-                                       bool* has_internal);
-
-  // Save face detect mode for HDR+
-  void SaveFdForHdrplus(const CaptureRequest& request);
-  // Handle face detect metadata from result for HDR+
-  status_t HandleFdResultForHdrplus(uint32_t frameNumber,
-                                    HalCameraMetadata* metadata);
-  // Save lens shading map mode for HDR+
-  void SaveLsForHdrplus(const CaptureRequest& request);
-  // Handle Lens shading metadata from result for HDR+
-  status_t HandleLsResultForHdrplus(uint32_t frameNumber,
-                                    HalCameraMetadata* metadata);
-  // TODO(b/127322570): update the following function after FLL sync verified
-  // Remove internal streams for depth lock
-  status_t ReturnInternalStreams(CaptureResult* result);
-
-  // Check fence status if need
-  status_t CheckFenceStatus(CaptureRequest* request);
-
-  // Check all metadata exist for Autocal
-  // Protected by depth_requests_mutex_
-  bool IsAutocalMetadataReadyLocked(const HalCameraMetadata& metadata);
-
-  // Prepare Depth Process Block request and try to submit that
-  status_t TrySubmitDepthProcessBlockRequest(
-      const ProcessBlockResult& block_result);
-
-  // Whether the internal yuv stream buffer needs to be passed to the depth
-  // process block.
-  bool IsAutocalRequest(uint32_t frame_number) const;
-
-  // Verify if all information is ready for a depth request for frame_number and
-  // submit the request to the process block if so.
-  status_t VerifyAndSubmitDepthRequest(uint32_t frame_number);
-
-  std::mutex callback_lock_;
-
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-
-  std::mutex depth_process_block_lock_;
-  // Protected by depth_process_block_lock_.
-  std::unique_ptr<ProcessBlock> depth_process_block_;
-
-  // rgb_raw_stream_id_ is the stream ID of internal raw from RGB camera for HDR+
-  int32_t rgb_raw_stream_id_ = -1;
-  bool is_hdrplus_supported_ = false;
-
-  // Current face detect mode set by framework.
-  uint8_t current_face_detect_mode_ = ANDROID_STATISTICS_FACE_DETECT_MODE_OFF;
-
-  std::mutex face_detect_lock_;
-  // Map from frame number to face detect mode requested for that frame by
-  // framework. And requested_face_detect_modes_ is protected by
-  // face_detect_lock_
-  std::unordered_map<uint32_t, uint8_t> requested_face_detect_modes_;
-
-  // Current lens shading map mode set by framework.
-  uint8_t current_lens_shading_map_mode_ =
-      ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF;
-
-  std::mutex lens_shading_lock_;
-  // Map from frame number to lens shading map mode requested for that frame
-  // by framework. And requested_lens_shading_map_modes_ is protected by
-  // lens_shading_lock_
-  std::unordered_map<uint32_t, uint8_t> requested_lens_shading_map_modes_;
-
-  // Internal stream manager
-  InternalStreamManager* internal_stream_manager_ = nullptr;
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  bool force_internal_stream_ = false;
-
-  // Set of framework stream id
-  std::set<int32_t> framework_stream_id_set_;
-
-  std::mutex depth_requests_mutex_;
-
-  // Map from framework number to capture request for depth process block. If a
-  // request does not contain any depth buffer, it is not recorded in the map.
-  // Protected by depth_requests_mutex_
-  std::unordered_map<uint32_t, std::unique_ptr<CaptureRequest>> depth_requests_;
-
-  // Depth stream id if it is configured for the current session
-  int32_t depth_stream_id_ = -1;
-
-  // If a depth stream is configured, always configure an extra internal YUV
-  // stream to cover the case when there is no request for any stream from the
-  // RGB sensor.
-  int32_t rgb_internal_yuv_stream_id_ = -1;
-
-  // Whether RGB-IR auto-calibration is enabled. This affects how the internal
-  // YUV stream results are handled.
-  bool rgb_ir_auto_cal_enabled_ = false;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_RESULT_REQUEST_PROCESSOR_H_
diff --git a/common/hal/google_camera_hal/rgbird_rt_request_processor.cc b/common/hal/google_camera_hal/rgbird_rt_request_processor.cc
deleted file mode 100644
index 1e752c4..0000000
--- a/common/hal/google_camera_hal/rgbird_rt_request_processor.cc
+++ /dev/null
@@ -1,743 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//#define LOG_NDEBUG 0
-#define LOG_TAG "GCH_RgbirdRtRequestProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include <cutils/properties.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-#include "rgbird_rt_request_processor.h"
-#include "vendor_tag_defs.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<RgbirdRtRequestProcessor> RgbirdRtRequestProcessor::Create(
-    CameraDeviceSessionHwl* device_session_hwl, bool is_hdrplus_supported) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return nullptr;
-  }
-
-  std::vector<uint32_t> physical_camera_ids =
-      device_session_hwl->GetPhysicalCameraIds();
-  if (physical_camera_ids.size() != 3) {
-    ALOGE("%s: Only support 3 cameras", __FUNCTION__);
-    return nullptr;
-  }
-
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  uint32_t active_array_width, active_array_height;
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(
-      ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE, &entry);
-  if (res == OK) {
-    active_array_width = entry.data.i32[2];
-    active_array_height = entry.data.i32[3];
-    ALOGI("%s Active size (%d x %d).", __FUNCTION__, active_array_width,
-          active_array_height);
-  } else {
-    ALOGE("%s Get active size failed: %s (%d).", __FUNCTION__, strerror(-res),
-          res);
-    return nullptr;
-  }
-
-  auto request_processor =
-      std::unique_ptr<RgbirdRtRequestProcessor>(new RgbirdRtRequestProcessor(
-          physical_camera_ids[0], physical_camera_ids[1],
-          physical_camera_ids[2], active_array_width, active_array_height,
-          is_hdrplus_supported, device_session_hwl));
-  if (request_processor == nullptr) {
-    ALOGE("%s: Creating RgbirdRtRequestProcessor failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  request_processor->force_internal_stream_ =
-      property_get_bool("persist.vendor.camera.rgbird.forceinternal", false);
-  if (request_processor->force_internal_stream_) {
-    ALOGI("%s: Force creating internal streams for IR pipelines", __FUNCTION__);
-  }
-
-  // TODO(b/129910835): This prop should be removed once that logic is in place.
-  request_processor->rgb_ir_auto_cal_enabled_ =
-      property_get_bool("vendor.camera.frontdepth.enableautocal", true);
-  if (request_processor->rgb_ir_auto_cal_enabled_) {
-    ALOGI("%s: ", __FUNCTION__);
-  }
-  request_processor->is_auto_cal_session_ =
-      request_processor->IsAutocalSession();
-
-  return request_processor;
-}
-
-bool RgbirdRtRequestProcessor::IsAutocalSession() const {
-  // TODO(b/129910835): Use more specific logic to determine if a session needs
-  // to run autocal or not. Even if rgb_ir_auto_cal_enabled_ is true, it is
-  // more reasonable to only run auto cal for some sessions(e.g. 1st session
-  // after device boot that has a depth stream configured).
-  // To allow more tests, every session having a depth stream is an autocal
-  // session now.
-  return rgb_ir_auto_cal_enabled_;
-}
-
-bool RgbirdRtRequestProcessor::IsAutocalRequest(uint32_t frame_number) {
-  // TODO(b/129910835): Refine the logic here to only trigger auto cal for
-  // specific request. The result/request processor and depth process block has
-  // final right to determine if an internal yuv stream buffer will be used for
-  // autocal.
-  // The current logic is to trigger the autocal in the kAutocalFrameNumber
-  // frame. This must be consistent with that of result_request_processor.
-  if (!is_auto_cal_session_ || auto_cal_triggered_ ||
-      frame_number != kAutocalFrameNumber ||
-      depth_stream_id_ == kStreamIdInvalid) {
-    return false;
-  }
-
-  auto_cal_triggered_ = true;
-  return true;
-}
-
-RgbirdRtRequestProcessor::RgbirdRtRequestProcessor(
-    uint32_t rgb_camera_id, uint32_t ir1_camera_id, uint32_t ir2_camera_id,
-    uint32_t active_array_width, uint32_t active_array_height,
-    bool is_hdrplus_supported, CameraDeviceSessionHwl* device_session_hwl)
-    : kRgbCameraId(rgb_camera_id),
-      kIr1CameraId(ir1_camera_id),
-      kIr2CameraId(ir2_camera_id),
-      rgb_active_array_width_(active_array_width),
-      rgb_active_array_height_(active_array_height),
-      is_hdrplus_supported_(is_hdrplus_supported),
-      is_hdrplus_zsl_enabled_(is_hdrplus_supported),
-      device_session_hwl_(device_session_hwl) {
-  ALOGI(
-      "%s: Created a RGBIRD RT request processor for RGB %u, IR1 %u, IR2 %u, "
-      "is_hdrplus_supported_ :%d",
-      __FUNCTION__, kRgbCameraId, kIr1CameraId, kIr2CameraId,
-      is_hdrplus_supported_);
-}
-
-status_t RgbirdRtRequestProcessor::FindSmallestNonWarpedYuvStreamResolution(
-    uint32_t* yuv_w_adjusted, uint32_t* yuv_h_adjusted) {
-  if (yuv_w_adjusted == nullptr || yuv_h_adjusted == nullptr) {
-    ALOGE("%s: yuv_w_adjusted or yuv_h_adjusted is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl_->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(VendorTagIds::kAvailableNonWarpedYuvSizes, &entry);
-  if (res != OK) {
-    ALOGE("%s Get stream size failed: %s (%d).", __FUNCTION__, strerror(-res),
-          res);
-    return UNKNOWN_ERROR;
-  }
-
-  uint32_t min_area = std::numeric_limits<uint32_t>::max();
-  uint32_t current_area = 0;
-  for (size_t i = 0; i < entry.count; i += 2) {
-    current_area = entry.data.i32[i] * entry.data.i32[i + 1];
-    if (current_area < min_area) {
-      *yuv_w_adjusted = entry.data.i32[i];
-      *yuv_h_adjusted = entry.data.i32[i + 1];
-      min_area = current_area;
-    }
-  }
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::FindSmallestResolutionForInternalYuvStream(
-    const StreamConfiguration& process_block_stream_config,
-    uint32_t* yuv_w_adjusted, uint32_t* yuv_h_adjusted) {
-  if (yuv_w_adjusted == nullptr || yuv_h_adjusted == nullptr) {
-    ALOGE("%s: yuv_w_adjusted or yuv_h_adjusted is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  *yuv_w_adjusted = kDefaultYuvStreamWidth;
-  *yuv_h_adjusted = kDefaultYuvStreamHeight;
-  uint32_t framework_non_raw_w = 0;
-  uint32_t framework_non_raw_h = 0;
-  bool non_raw_non_depth_stream_configured = false;
-  for (auto& stream : process_block_stream_config.streams) {
-    if (!utils::IsRawStream(stream) && !utils::IsDepthStream(stream)) {
-      non_raw_non_depth_stream_configured = true;
-      framework_non_raw_w = stream.width;
-      framework_non_raw_h = stream.height;
-      break;
-    }
-  }
-
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = device_session_hwl_->GetCameraCharacteristics(&characteristics);
-  if (res != OK) {
-    ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
-                             &entry);
-  if (res != OK) {
-    ALOGE("%s Get stream size failed: %s (%d).", __FUNCTION__, strerror(-res),
-          res);
-    return UNKNOWN_ERROR;
-  }
-
-  uint32_t min_area = std::numeric_limits<uint32_t>::max();
-  uint32_t current_area = 0;
-  if (non_raw_non_depth_stream_configured) {
-    bool found_matching_aspect_ratio = false;
-    for (size_t i = 0; i < entry.count; i += 4) {
-      uint8_t format = entry.data.i32[i];
-      if ((format == HAL_PIXEL_FORMAT_YCbCr_420_888) &&
-          (entry.data.i32[i + 3] ==
-           ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)) {
-        current_area = entry.data.i32[i + 1] * entry.data.i32[i + 2];
-        if ((entry.data.i32[i + 1] * framework_non_raw_h ==
-             entry.data.i32[i + 2] * framework_non_raw_w) &&
-            (current_area < min_area)) {
-          *yuv_w_adjusted = entry.data.i32[i + 1];
-          *yuv_h_adjusted = entry.data.i32[i + 2];
-          min_area = current_area;
-          found_matching_aspect_ratio = true;
-        }
-      }
-    }
-    if (!found_matching_aspect_ratio) {
-      ALOGE(
-          "%s: No matching aspect ratio can be found in the available stream"
-          "config resolution list.",
-          __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  } else {
-    ALOGI(
-        "No YUV stream configured, ues smallest resolution for internal "
-        "stream.");
-    for (size_t i = 0; i < entry.count; i += 4) {
-      if ((entry.data.i32[i] == HAL_PIXEL_FORMAT_YCbCr_420_888) &&
-          (entry.data.i32[i + 3] ==
-           ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)) {
-        current_area = entry.data.i32[i + 1] * entry.data.i32[i + 2];
-        if (current_area < min_area) {
-          *yuv_w_adjusted = entry.data.i32[i + 1];
-          *yuv_h_adjusted = entry.data.i32[i + 2];
-          min_area = current_area;
-        }
-      }
-    }
-  }
-
-  if ((*yuv_w_adjusted == 0) || (*yuv_h_adjusted == 0)) {
-    ALOGE("%s Get internal YUV stream size failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::SetNonWarpedYuvStreamId(
-    int32_t non_warped_yuv_stream_id,
-    StreamConfiguration* process_block_stream_config) {
-  if (process_block_stream_config == nullptr) {
-    ALOGE("%s: process_block_stream_config is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  if (process_block_stream_config->session_params == nullptr) {
-    uint32_t num_entries = 128;
-    uint32_t data_bytes = 512;
-
-    process_block_stream_config->session_params =
-        HalCameraMetadata::Create(num_entries, data_bytes);
-    if (process_block_stream_config->session_params == nullptr) {
-      ALOGE("%s: Failed to create session parameter.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  auto logical_metadata = process_block_stream_config->session_params.get();
-
-  status_t res = logical_metadata->Set(VendorTagIds::kNonWarpedYuvStreamId,
-                                       &non_warped_yuv_stream_id, 1);
-  if (res != OK) {
-    ALOGE("%s: Failed to update VendorTagIds::kNonWarpedYuvStreamId: %s(%d)",
-          __FUNCTION__, strerror(-res), res);
-    return UNKNOWN_ERROR;
-  }
-
-  return res;
-}
-
-status_t RgbirdRtRequestProcessor::CreateDepthInternalStreams(
-    InternalStreamManager* internal_stream_manager,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-
-  uint32_t yuv_w_adjusted = 0;
-  uint32_t yuv_h_adjusted = 0;
-  status_t result = OK;
-
-  if (IsAutocalSession()) {
-    result = FindSmallestNonWarpedYuvStreamResolution(&yuv_w_adjusted,
-                                                      &yuv_h_adjusted);
-    if (result != OK) {
-      ALOGE("%s: Could not find non-warped YUV resolution for internal YUV.",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  } else {
-    result = FindSmallestResolutionForInternalYuvStream(
-        *process_block_stream_config, &yuv_w_adjusted, &yuv_h_adjusted);
-    if (result != OK) {
-      ALOGE("%s: Could not find compatible resolution for internal YUV.",
-            __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  ALOGI("Depth internal YUV stream (%d x %d)", yuv_w_adjusted, yuv_h_adjusted);
-  // create internal streams:
-  // 1 YUV(must have for autocal and 3-sensor syncing)
-  // 2 RAW(must have to generate depth)
-  Stream yuv_stream;
-  yuv_stream.stream_type = StreamType::kOutput;
-  yuv_stream.width = yuv_w_adjusted;
-  yuv_stream.height = yuv_h_adjusted;
-  yuv_stream.format = HAL_PIXEL_FORMAT_YCBCR_420_888;
-  yuv_stream.usage = 0;
-  yuv_stream.rotation = StreamRotation::kRotation0;
-  yuv_stream.data_space = HAL_DATASPACE_ARBITRARY;
-  yuv_stream.is_physical_camera_stream = true;
-  yuv_stream.physical_camera_id = kRgbCameraId;
-
-  result = internal_stream_manager->RegisterNewInternalStream(
-      yuv_stream, &rgb_yuv_stream_id_);
-  if (result != OK) {
-   ALOGE("%s: RegisterNewInternalStream failed.", __FUNCTION__);
-   return UNKNOWN_ERROR;
-  }
-  yuv_stream.id = rgb_yuv_stream_id_;
-
-  if (IsAutocalSession()) {
-    result = SetNonWarpedYuvStreamId(rgb_yuv_stream_id_,
-                                     process_block_stream_config);
-  }
-
-  if (result != OK) {
-    ALOGE("%s: Failed to set no post processing yuv stream id.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  Stream raw_stream[2];
-  for (uint32_t i = 0; i < 2; i++) {
-    raw_stream[i].stream_type = StreamType::kOutput;
-    raw_stream[i].width = 640;
-    raw_stream[i].height = 480;
-    raw_stream[i].format = HAL_PIXEL_FORMAT_Y8;
-    raw_stream[i].usage = 0;
-    raw_stream[i].rotation = StreamRotation::kRotation0;
-    raw_stream[i].data_space = HAL_DATASPACE_ARBITRARY;
-    raw_stream[i].is_physical_camera_stream = true;
-
-    status_t result = internal_stream_manager->RegisterNewInternalStream(
-        raw_stream[i], &ir_raw_stream_id_[i]);
-    if (result != OK) {
-     ALOGE("%s: RegisterNewInternalStream failed.", __FUNCTION__);
-     return UNKNOWN_ERROR;
-    }
-    raw_stream[i].id = ir_raw_stream_id_[i];
-  }
-
-  raw_stream[0].physical_camera_id = kIr1CameraId;
-  raw_stream[1].physical_camera_id = kIr2CameraId;
-
-  process_block_stream_config->streams.push_back(yuv_stream);
-  process_block_stream_config->streams.push_back(raw_stream[0]);
-  process_block_stream_config->streams.push_back(raw_stream[1]);
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::RegisterHdrplusInternalRaw(
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (process_block_stream_config == nullptr) {
-    ALOGE("%s: process_block_stream_config is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  // Register internal raw stream
-  Stream raw_stream;
-  raw_stream.stream_type = StreamType::kOutput;
-  raw_stream.width = rgb_active_array_width_;
-  raw_stream.height = rgb_active_array_height_;
-  raw_stream.format = HAL_PIXEL_FORMAT_RAW10;
-  raw_stream.usage = 0;
-  raw_stream.rotation = StreamRotation::kRotation0;
-  raw_stream.data_space = HAL_DATASPACE_ARBITRARY;
-
-  status_t result = internal_stream_manager_->RegisterNewInternalStream(
-      raw_stream, &rgb_raw_stream_id_);
-  if (result != OK) {
-    ALOGE("%s: RegisterNewInternalStream failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  // Set id back to raw_stream and then HWL can get correct HAL stream ID
-  raw_stream.id = rgb_raw_stream_id_;
-
-  raw_stream.is_physical_camera_stream = true;
-  raw_stream.physical_camera_id = kRgbCameraId;
-
-  // Add internal RAW stream
-  process_block_stream_config->streams.push_back(raw_stream);
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::ConfigureStreams(
-    InternalStreamManager* internal_stream_manager,
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (process_block_stream_config == nullptr) {
-    ALOGE("%s: process_block_stream_config is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  internal_stream_manager_ = internal_stream_manager;
-  if (is_hdrplus_supported_) {
-    status_t result = RegisterHdrplusInternalRaw(process_block_stream_config);
-    if (result != OK) {
-      ALOGE("%s: RegisterHdrplusInternalRaw failed.", __FUNCTION__);
-      return UNKNOWN_ERROR;
-    }
-  }
-
-  process_block_stream_config->operation_mode = stream_config.operation_mode;
-  process_block_stream_config->session_params =
-      HalCameraMetadata::Clone(stream_config.session_params.get());
-  process_block_stream_config->stream_config_counter =
-      stream_config.stream_config_counter;
-  process_block_stream_config->log_id = stream_config.log_id;
-
-  bool has_depth_stream = false;
-  for (auto& stream : stream_config.streams) {
-    if (utils::IsDepthStream(stream)) {
-      has_depth_stream = true;
-      depth_stream_id_ = stream.id;
-      continue;
-    }
-
-    auto pb_stream = stream;
-    // Assign all logical streams to RGB camera.
-    if (!pb_stream.is_physical_camera_stream) {
-      pb_stream.is_physical_camera_stream = true;
-      pb_stream.physical_camera_id = kRgbCameraId;
-    }
-
-    process_block_stream_config->streams.push_back(pb_stream);
-  }
-
-  // TODO(b/128633958): remove the force flag after FLL syncing is verified
-  if (force_internal_stream_ || has_depth_stream) {
-    CreateDepthInternalStreams(internal_stream_manager,
-                               process_block_stream_config);
-  }
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::SetProcessBlock(
-    std::unique_ptr<ProcessBlock> process_block) {
-  ATRACE_CALL();
-  if (process_block == nullptr) {
-    ALOGE("%s: process_block is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ != nullptr) {
-    ALOGE("%s: Already configured.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  process_block_ = std::move(process_block);
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::AddIrRawProcessBlockRequestLocked(
-    std::vector<ProcessBlockRequest>* block_requests,
-    const CaptureRequest& request, uint32_t camera_id) {
-  ATRACE_CALL();
-  uint32_t stream_id_index = 0;
-
-  if (camera_id == kIr1CameraId) {
-    stream_id_index = 0;
-  } else if (camera_id == kIr2CameraId) {
-    stream_id_index = 1;
-  } else {
-    ALOGE("%s: Unknown IR camera id %d", __FUNCTION__, camera_id);
-    return INVALID_OPERATION;
-  }
-
-  ProcessBlockRequest block_request = {.request_id = camera_id};
-  CaptureRequest& physical_request = block_request.request;
-  physical_request.frame_number = request.frame_number;
-  physical_request.settings = HalCameraMetadata::Clone(request.settings.get());
-
-  // TODO(b/128633958): Remap the crop region for IR sensors properly.
-  // The crop region cloned from logical camera control settings causes mass log
-  // spew from the IR pipelines. Force the crop region for now as a WAR.
-  if (physical_request.settings != nullptr) {
-    camera_metadata_ro_entry_t entry_crop_region_user = {};
-    if (physical_request.settings->Get(ANDROID_SCALER_CROP_REGION,
-                                       &entry_crop_region_user) == OK) {
-      const uint32_t ir_crop_region[4] = {0, 0, 640, 480};
-      physical_request.settings->Set(
-          ANDROID_SCALER_CROP_REGION,
-          reinterpret_cast<const int32_t*>(&ir_crop_region),
-          sizeof(ir_crop_region) / sizeof(int32_t));
-    }
-  }
-  // Requests for IR pipelines should not include any input buffer or metadata
-  // physical_request.input_buffers
-  // physical_request.input_buffer_metadata
-
-  StreamBuffer internal_buffer = {};
-  status_t res = internal_stream_manager_->GetStreamBuffer(
-      ir_raw_stream_id_[stream_id_index], &internal_buffer);
-  if (res != OK) {
-    ALOGE(
-        "%s: Failed to get internal stream buffer for frame %d, stream id"
-        " %d: %s(%d)",
-        __FUNCTION__, request.frame_number, ir_raw_stream_id_[0],
-        strerror(-res), res);
-    return UNKNOWN_ERROR;
-  }
-  physical_request.output_buffers.push_back(internal_buffer);
-
-  physical_request.physical_camera_settings[camera_id] =
-      HalCameraMetadata::Clone(request.settings.get());
-
-  block_requests->push_back(std::move(block_request));
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::TryAddRgbProcessBlockRequestLocked(
-    std::vector<ProcessBlockRequest>* block_requests,
-    const CaptureRequest& request) {
-  ATRACE_CALL();
-  if (block_requests == nullptr) {
-    ALOGE("%s: block_requests is nullptr.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  ProcessBlockRequest block_request = {.request_id = kRgbCameraId};
-  CaptureRequest& physical_request = block_request.request;
-
-  for (auto& output_buffer : request.output_buffers) {
-    if (output_buffer.stream_id != depth_stream_id_) {
-      physical_request.output_buffers.push_back(output_buffer);
-    }
-  }
-
-  if (is_hdrplus_zsl_enabled_ && request.settings != nullptr) {
-    camera_metadata_ro_entry entry = {};
-    status_t res =
-        request.settings->Get(VendorTagIds::kThermalThrottling, &entry);
-    if (res != OK || entry.count != 1) {
-      ALOGW("%s: Getting thermal throttling entry failed: %s(%d)", __FUNCTION__,
-            strerror(-res), res);
-    } else if (entry.data.u8[0] == true) {
-      // Disable HDR+ once thermal throttles.
-      is_hdrplus_zsl_enabled_ = false;
-      ALOGI("%s: HDR+ ZSL disabled due to thermal throttling", __FUNCTION__);
-    }
-  }
-
-  // Disable HDR+ for thermal throttling.
-  if (is_hdrplus_zsl_enabled_) {
-    status_t res = TryAddHdrplusRawOutputLocked(&physical_request, request);
-    if (res != OK) {
-      ALOGE("%s: AddHdrplusRawOutput fail", __FUNCTION__);
-      return res;
-    }
-  } else if (physical_request.output_buffers.empty() ||
-             IsAutocalRequest(request.frame_number)) {
-    status_t res = TryAddDepthInternalYuvOutputLocked(&physical_request);
-    if (res != OK) {
-      ALOGE("%s: AddDepthOnlyRawOutput failed.", __FUNCTION__);
-      return res;
-    }
-  }
-
-  // In case there is only one depth stream
-  if (!physical_request.output_buffers.empty()) {
-    physical_request.frame_number = request.frame_number;
-    physical_request.settings = HalCameraMetadata::Clone(request.settings.get());
-
-    if (is_hdrplus_zsl_enabled_ && physical_request.settings != nullptr) {
-      status_t res = hal_utils::ModifyRealtimeRequestForHdrplus(
-          physical_request.settings.get());
-      if (res != OK) {
-        ALOGE("%s: ModifyRealtimeRequestForHdrplus (%d) fail", __FUNCTION__,
-              request.frame_number);
-        return UNKNOWN_ERROR;
-      }
-    }
-
-    physical_request.input_buffers = request.input_buffers;
-
-    for (auto& metadata : request.input_buffer_metadata) {
-      physical_request.input_buffer_metadata.push_back(
-          HalCameraMetadata::Clone(metadata.get()));
-    }
-
-    block_requests->push_back(std::move(block_request));
-  }
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::TryAddDepthInternalYuvOutputLocked(
-    CaptureRequest* block_request) {
-  if (block_request == nullptr) {
-    ALOGE("%s: block_request is nullptr.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  StreamBuffer buffer = {};
-  status_t result =
-      internal_stream_manager_->GetStreamBuffer(rgb_yuv_stream_id_, &buffer);
-  if (result != OK) {
-    ALOGE("%s: GetStreamBuffer failed.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-  block_request->output_buffers.push_back(buffer);
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::TryAddHdrplusRawOutputLocked(
-    CaptureRequest* block_request, const CaptureRequest& request) {
-  ATRACE_CALL();
-  if (block_request == nullptr) {
-    ALOGE("%s: block_request is nullptr.", __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  // Update if preview intent has been requested.
-  camera_metadata_ro_entry entry;
-  if (!preview_intent_seen_ && request.settings != nullptr &&
-      request.settings->Get(ANDROID_CONTROL_CAPTURE_INTENT, &entry) == OK) {
-    if (entry.count == 1 &&
-        *entry.data.u8 == ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW) {
-      preview_intent_seen_ = true;
-      ALOGI("%s: First request with preview intent. ZSL starts.", __FUNCTION__);
-    }
-  }
-
-  // Get one RAW bffer from internal stream manager
-  // Add RAW output to capture request
-  if (preview_intent_seen_) {
-    StreamBuffer buffer = {};
-    status_t result =
-        internal_stream_manager_->GetStreamBuffer(rgb_raw_stream_id_, &buffer);
-    if (result != OK) {
-      ALOGE("%s: frame:%d GetStreamBuffer failed.", __FUNCTION__,
-            request.frame_number);
-      return UNKNOWN_ERROR;
-    }
-    block_request->output_buffers.push_back(buffer);
-  }
-
-  return OK;
-}
-
-status_t RgbirdRtRequestProcessor::ProcessRequest(const CaptureRequest& request) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ == nullptr) {
-    ALOGE("%s: Not configured yet.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  // Rgbird should not have phys settings
-  if (!request.physical_camera_settings.empty()) {
-    ALOGE("%s: Rgbird capture session does not support physical settings.",
-          __FUNCTION__);
-    return UNKNOWN_ERROR;
-  }
-
-  {
-    std::vector<ProcessBlockRequest> block_requests;
-    status_t res = TryAddRgbProcessBlockRequestLocked(&block_requests, request);
-    if (res != OK) {
-      ALOGE("%s: Failed to add process block request for rgb pipeline.",
-            __FUNCTION__);
-      return res;
-    }
-
-    // TODO(b/128633958): Remove the force flag after FLL sync is verified
-    if (force_internal_stream_ || depth_stream_id_ != kStreamIdInvalid) {
-      res = AddIrRawProcessBlockRequestLocked(&block_requests, request,
-                                              kIr1CameraId);
-      if (res != OK) {
-        ALOGE("%s: Failed to add process block request for ir1 pipeline.",
-              __FUNCTION__);
-        return res;
-      }
-      res = AddIrRawProcessBlockRequestLocked(&block_requests, request,
-                                              kIr2CameraId);
-      if (res != OK) {
-        ALOGE("%s: Failed to add process block request for ir2 pipeline.",
-              __FUNCTION__);
-        return res;
-      }
-    }
-
-    return process_block_->ProcessRequests(block_requests, request);
-  }
-}
-
-status_t RgbirdRtRequestProcessor::Flush() {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ == nullptr) {
-    return OK;
-  }
-
-  return process_block_->Flush();
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/rgbird_rt_request_processor.h b/common/hal/google_camera_hal/rgbird_rt_request_processor.h
deleted file mode 100644
index af17a35..0000000
--- a/common/hal/google_camera_hal/rgbird_rt_request_processor.h
+++ /dev/null
@@ -1,147 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_RT_REQUEST_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_RT_REQUEST_PROCESSOR_H_
-
-#include <limits>
-
-#include "process_block.h"
-#include "request_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// RgbirdRtRequestProcessor implements a RequestProcessor handling realtime
-// requests for a logical camera consisting of one RGB camera sensor and two IR
-// camera sensors.
-class RgbirdRtRequestProcessor : public RequestProcessor {
- public:
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of this RgbirdRtRequestProcessor.
-  static std::unique_ptr<RgbirdRtRequestProcessor> Create(
-      CameraDeviceSessionHwl* device_session_hwl, bool is_hdrplus_supported);
-
-  virtual ~RgbirdRtRequestProcessor() = default;
-
-  // Override functions of RequestProcessor start.
-  status_t ConfigureStreams(
-      InternalStreamManager* internal_stream_manager,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config) override;
-
-  status_t SetProcessBlock(std::unique_ptr<ProcessBlock> process_block) override;
-
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions of RequestProcessor end.
-
-  // Whether the current session is a session in which auto cal should happen.
-  bool IsAutocalSession() const;
-
- protected:
-  RgbirdRtRequestProcessor(uint32_t rgb_camera_id, uint32_t ir1_camera_id,
-                           uint32_t ir2_camera_id, uint32_t active_array_width,
-                           uint32_t active_array_height,
-                           bool is_hdrplus_supported,
-                           CameraDeviceSessionHwl* device_session_hwl);
-
- private:
-  static const int32_t kStreamIdInvalid = -1;
-  static constexpr uint32_t kAutocalFrameNumber = 5;
-  const uint32_t kDefaultYuvStreamWidth = 640;
-  const uint32_t kDefaultYuvStreamHeight = 480;
-  const uint32_t kRgbCameraId;
-  const uint32_t kIr1CameraId;
-  const uint32_t kIr2CameraId;
-
-  status_t CreateDepthInternalStreams(
-      InternalStreamManager* internal_stream_manager,
-      StreamConfiguration* process_block_stream_config);
-
-  status_t RegisterHdrplusInternalRaw(
-      StreamConfiguration* process_block_stream_config);
-  status_t TryAddHdrplusRawOutputLocked(CaptureRequest* block_request,
-                                        const CaptureRequest& request);
-  // Try to add RGB internal YUV buffer if there is no request on any stream
-  // from the RGB sensor.
-  // Must lock process_block_lock_ before calling this function.
-  status_t TryAddDepthInternalYuvOutputLocked(CaptureRequest* block_request);
-  status_t AddIrRawProcessBlockRequestLocked(
-      std::vector<ProcessBlockRequest>* block_requests,
-      const CaptureRequest& request, uint32_t camera_id);
-
-  status_t TryAddRgbProcessBlockRequestLocked(
-      std::vector<ProcessBlockRequest>* block_requests,
-      const CaptureRequest& request);
-
-  // Find a resolution from the available stream configuration that has the same
-  // aspect ratio with one of the non-raw and non-depth stream in the framework
-  // stream config.
-  // If there is no non-raw and non-depth stream from framework, use the
-  // resolution with the smallest area in the available stream config.
-  status_t FindSmallestResolutionForInternalYuvStream(
-      const StreamConfiguration& process_block_stream_config,
-      uint32_t* yuv_w_adjusted, uint32_t* yuv_h_adjusted);
-
-  /// Find smallest non-warped YUV stream resolution supported by HWL
-  status_t FindSmallestNonWarpedYuvStreamResolution(uint32_t* yuv_w_adjusted,
-                                                    uint32_t* yuv_h_adjusted);
-
-  // Set the stream id of the yuv stream that does not need warping in
-  // the session parameter of the process block stream configuration.
-  status_t SetNonWarpedYuvStreamId(
-      int32_t non_warped_yuv_stream_id,
-      StreamConfiguration* process_block_stream_config);
-
-  // Whether the internal YUV stream result should be used for auto cal.
-  bool IsAutocalRequest(uint32_t frame_number);
-
-  std::mutex process_block_lock_;
-
-  // Protected by process_block_lock_.
-  std::unique_ptr<ProcessBlock> process_block_;
-  // [0]: IR1 stream; [1]: IR2 stream
-  int32_t ir_raw_stream_id_[2] = {kStreamIdInvalid, kStreamIdInvalid};
-  int32_t rgb_yuv_stream_id_ = kStreamIdInvalid;
-
-  bool preview_intent_seen_ = false;
-  // rgb_raw_stream_id_ is the stream ID of internal raw from RGB camera for HDR+
-  int32_t rgb_raw_stream_id_ = -1;
-  uint32_t rgb_active_array_width_ = 0;
-  uint32_t rgb_active_array_height_ = 0;
-  bool is_hdrplus_supported_ = false;
-  bool is_hdrplus_zsl_enabled_ = false;
-
-  // TODO(b/128633958): remove this after FLL syncing is verified
-  bool force_internal_stream_ = false;
-  int32_t depth_stream_id_ = kStreamIdInvalid;
-  InternalStreamManager* internal_stream_manager_ = nullptr;
-  CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
-
-  // Whether RGB-IR auto cal is needed
-  bool rgb_ir_auto_cal_enabled_ = false;
-  // Indicates whether a session needs auto cal(not every session needs even if
-  // rgb_ir_auto_cal_enabled_ is true).
-  bool is_auto_cal_session_ = false;
-  bool auto_cal_triggered_ = false;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_RGBIRD_RT_REQUEST_PROCESSOR_H_
diff --git a/common/hal/google_camera_hal/snapshot_request_processor.cc b/common/hal/google_camera_hal/snapshot_request_processor.cc
index 3c66860..0d865a9 100644
--- a/common/hal/google_camera_hal/snapshot_request_processor.cc
+++ b/common/hal/google_camera_hal/snapshot_request_processor.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #include "system/graphics-base-v1.0.h"
 #define LOG_TAG "GCH_SnapshotRequestProcessor"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
@@ -217,5 +217,14 @@ status_t SnapshotRequestProcessor::Flush() {
   return process_block_->Flush();
 }
 
+void SnapshotRequestProcessor::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::lock_guard<std::mutex> lock(process_block_lock_);
+  if (process_block_ != nullptr) {
+    process_block_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 }  // namespace google_camera_hal
 }  // namespace android
\ No newline at end of file
diff --git a/common/hal/google_camera_hal/snapshot_request_processor.h b/common/hal/google_camera_hal/snapshot_request_processor.h
index a17191a..34fba59 100644
--- a/common/hal/google_camera_hal/snapshot_request_processor.h
+++ b/common/hal/google_camera_hal/snapshot_request_processor.h
@@ -17,6 +17,8 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_SNAPSHOT_REQUEST_PROCESSOR_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_SNAPSHOT_REQUEST_PROCESSOR_H_
 
+#include <vector>
+
 #include "process_block.h"
 #include "request_processor.h"
 
@@ -51,6 +53,9 @@ class SnapshotRequestProcessor : public RequestProcessor {
   status_t Flush() override;
   // Override functions of RequestProcessor end.
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
  protected:
   explicit SnapshotRequestProcessor(HwlSessionCallback session_callback)
       : session_callback_(session_callback) {
diff --git a/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc b/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
index d42a9e2..9bfbc2c 100644
--- a/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
+++ b/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
@@ -27,6 +27,7 @@
 #include <utils/Trace.h>
 
 #include "hal_utils.h"
+#include "libgooglecamerahal_flags.h"
 #include "realtime_zsl_result_request_processor.h"
 #include "snapshot_request_processor.h"
 #include "snapshot_result_processor.h"
@@ -733,8 +734,12 @@ status_t ZslSnapshotCaptureSession::Initialize(
   res = characteristics->Get(VendorTagIds::kVideoSwDenoiseEnabled,
                              &video_sw_denoise_entry);
   if (res == OK && video_sw_denoise_entry.data.u8[0] == 1) {
-    video_sw_denoise_enabled_ = true;
-    ALOGI("%s: video sw denoise is enabled.", __FUNCTION__);
+    if (libgooglecamerahal::flags::zsl_video_denoise_in_hwl()) {
+      ALOGI("%s: video sw denoise is enabled in HWL", __FUNCTION__);
+    } else {
+      video_sw_denoise_enabled_ = true;
+      ALOGI("%s: video sw denoise is enabled in GCH", __FUNCTION__);
+    }
   } else {
     ALOGI("%s: video sw denoise is disabled.", __FUNCTION__);
   }
@@ -879,6 +884,15 @@ status_t ZslSnapshotCaptureSession::Flush() {
   return realtime_request_processor_->Flush();
 }
 
+void ZslSnapshotCaptureSession::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  if (realtime_request_processor_ != nullptr) {
+    return realtime_request_processor_->RepeatingRequestEnd(frame_number,
+                                                            stream_ids);
+  }
+}
+
 void ZslSnapshotCaptureSession::ProcessCaptureResult(
     std::unique_ptr<CaptureResult> result) {
   ATRACE_CALL();
diff --git a/common/hal/google_camera_hal/zsl_snapshot_capture_session.h b/common/hal/google_camera_hal/zsl_snapshot_capture_session.h
index a376030..0934a5c 100644
--- a/common/hal/google_camera_hal/zsl_snapshot_capture_session.h
+++ b/common/hal/google_camera_hal/zsl_snapshot_capture_session.h
@@ -17,6 +17,8 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_ZSL_SNAPSHOT_CAPTURE_SESSION_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_ZSL_SNAPSHOT_CAPTURE_SESSION_H_
 
+#include <vector>
+
 #include "basic_result_processor.h"
 #include "camera_buffer_allocator_hwl.h"
 #include "camera_device_session_hwl.h"
@@ -84,6 +86,9 @@ class ZslSnapshotCaptureSession : public CaptureSession {
   status_t Flush() override;
   // Override functions in CaptureSession end.
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
  protected:
   ZslSnapshotCaptureSession(
       const std::vector<ExternalCaptureSessionFactory*>&
diff --git a/common/hal/hwl_interface/camera_device_hwl.h b/common/hal/hwl_interface/camera_device_hwl.h
index 7a5855c..b646513 100644
--- a/common/hal/hwl_interface/camera_device_hwl.h
+++ b/common/hal/hwl_interface/camera_device_hwl.h
@@ -23,6 +23,7 @@
 #include "camera_device_session_hwl.h"
 #include "hal_camera_metadata.h"
 #include "hal_types.h"
+#include "hwl_types.h"
 #include "physical_camera_info_hwl.h"
 #include "profiler.h"
 
@@ -70,6 +71,9 @@ class CameraDeviceHwl : public PhysicalCameraInfoHwl {
       uint32_t physical_camera_id,
       std::unique_ptr<HalCameraMetadata>* characteristics) const = 0;
 
+  // Get the memory config of this camera device.
+  virtual HwlMemoryConfig GetMemoryConfig() const = 0;
+
   // Set the torch mode of the camera device. The torch mode status remains
   // unchanged after this CameraDevice instance is destroyed.
   virtual status_t SetTorchMode(TorchMode mode) = 0;
diff --git a/common/hal/hwl_interface/camera_device_session_hwl.h b/common/hal/hwl_interface/camera_device_session_hwl.h
index 7984287..5cc6165 100644
--- a/common/hal/hwl_interface/camera_device_session_hwl.h
+++ b/common/hal/hwl_interface/camera_device_session_hwl.h
@@ -20,6 +20,7 @@
 #include <utils/Errors.h>
 
 #include <set>
+#include <vector>
 
 #include "hal_camera_metadata.h"
 #include "hwl_types.h"
@@ -130,6 +131,9 @@ class CameraDeviceSessionHwl : public PhysicalCameraInfoHwl {
   // Flush all pending requests.
   virtual status_t Flush() = 0;
 
+  virtual void RepeatingRequestEnd(int32_t frame_number,
+                                   const std::vector<int32_t>& stream_ids) = 0;
+
   // Return the camera ID that this camera device session is associated with.
   virtual uint32_t GetCameraId() const = 0;
 
diff --git a/common/hal/hwl_interface/capture_session.h b/common/hal/hwl_interface/capture_session.h
index 6cfe7a1..65bb1ae 100644
--- a/common/hal/hwl_interface/capture_session.h
+++ b/common/hal/hwl_interface/capture_session.h
@@ -19,6 +19,8 @@
 
 #include <utils/Errors.h>
 
+#include <vector>
+
 #include "camera_buffer_allocator_hwl.h"
 #include "camera_device_session_hwl.h"
 #include "hal_types.h"
@@ -58,6 +60,9 @@ class CaptureSession {
 
   // Flush all pending capture requests.
   virtual status_t Flush() = 0;
+
+  virtual void RepeatingRequestEnd(int32_t frame_number,
+                                   const std::vector<int32_t>& stream_ids) = 0;
 };
 
 // ExternalCaptureSessionFactory defines the interface of an external capture
diff --git a/common/hal/hwl_interface/hwl_types.h b/common/hal/hwl_interface/hwl_types.h
index 8017fef..fb92510 100644
--- a/common/hal/hwl_interface/hwl_types.h
+++ b/common/hal/hwl_interface/hwl_types.h
@@ -17,6 +17,10 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_HWL_INTERFACE_HWL_TYPES_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_HWL_INTERFACE_HWL_TYPES_H_
 
+#include <cstdint>
+#include <limits>
+#include <string>
+#include <unordered_set>
 #include <vector>
 
 #include "hal_types.h"
@@ -24,6 +28,15 @@
 namespace android {
 namespace google_camera_hal {
 
+// Controls what memory is pinned and madvised
+struct HwlMemoryConfig {
+  // Defines which libraries to pin in memory.
+  std::unordered_set<std::string> pinned_libraries;
+
+  // Sets the maximum size of a map to be madvised.
+  size_t madvise_map_size_limit_bytes = std::numeric_limits<size_t>::max();
+};
+
 // Enumerates pipeline roles that are used to communicate with HWL.
 enum class HwlOfflinePipelineRole {
   kOfflineInvalidRole = 0,
diff --git a/common/hal/hwl_interface/process_block.h b/common/hal/hwl_interface/process_block.h
index 455dadd..236e80f 100644
--- a/common/hal/hwl_interface/process_block.h
+++ b/common/hal/hwl_interface/process_block.h
@@ -19,6 +19,8 @@
 
 #include <utils/Errors.h>
 
+#include <vector>
+
 #include "camera_device_session_hwl.h"
 #include "hal_types.h"
 
@@ -94,6 +96,9 @@ class ProcessBlock {
 
   // Flush pending requests.
   virtual status_t Flush() = 0;
+
+  virtual void RepeatingRequestEnd(int32_t frame_number,
+                                   const std::vector<int32_t>& stream_ids) = 0;
 };
 
 // ExternalProcessBlockFactory defines the interface of an external process
diff --git a/common/hal/hwl_interface/request_processor.h b/common/hal/hwl_interface/request_processor.h
index c08df95..0f78fcc 100644
--- a/common/hal/hwl_interface/request_processor.h
+++ b/common/hal/hwl_interface/request_processor.h
@@ -19,6 +19,8 @@
 
 #include <utils/Errors.h>
 
+#include <vector>
+
 #include "hal_types.h"
 #include "internal_stream_manager.h"
 #include "process_block.h"
@@ -66,6 +68,9 @@ class RequestProcessor {
 
   // Flush all pending requests.
   virtual status_t Flush() = 0;
+
+  virtual void RepeatingRequestEnd(int32_t frame_number,
+                                   const std::vector<int32_t>& stream_ids) = 0;
 };
 
 }  // namespace google_camera_hal
diff --git a/common/hal/tests/Android.bp b/common/hal/tests/Android.bp
index b02cbac..364f83a 100644
--- a/common/hal/tests/Android.bp
+++ b/common/hal/tests/Android.bp
@@ -55,7 +55,6 @@ cc_library {
         "zsl_buffer_manager_tests.cc",
     ],
     shared_libs: [
-        "android.hardware.camera.provider@2.4",
         "lib_profiler",
         "libcamera_metadata",
         "libcutils",
@@ -67,6 +66,7 @@ cc_library {
         "libutils",
     ],
     static_libs: [
+        "android.hardware.camera.provider@2.4",
         "libgmock",
         "libgtest",
     ],
@@ -92,7 +92,6 @@ cc_test {
         "lib_profiler",
         "libgooglecamerahal",
         "libgooglecamerahalutils",
-        "android.hardware.camera.provider@2.4",
         "libcamera_metadata",
         "libcutils",
         "libhardware",
@@ -104,6 +103,7 @@ cc_test {
         "libgoogle_camera_hal_tests",
     ],
     static_libs: [
+        "android.hardware.camera.provider@2.4",
         "libgmock",
         "libgtest",
     ],
diff --git a/common/hal/tests/mock_device_hwl.h b/common/hal/tests/mock_device_hwl.h
index bde4a81..5464b68 100644
--- a/common/hal/tests/mock_device_hwl.h
+++ b/common/hal/tests/mock_device_hwl.h
@@ -89,6 +89,10 @@ class MockDeviceHwl : public CameraDeviceHwl {
     return OK;
   }
 
+  HwlMemoryConfig GetMemoryConfig() const {
+    return HwlMemoryConfig();
+  }
+
   status_t SetTorchMode(TorchMode /*mode*/) {
     return OK;
   }
diff --git a/common/hal/tests/mock_device_session_hwl.cc b/common/hal/tests/mock_device_session_hwl.cc
index 5a8af01..91eed13 100644
--- a/common/hal/tests/mock_device_session_hwl.cc
+++ b/common/hal/tests/mock_device_session_hwl.cc
@@ -206,6 +206,10 @@ status_t FakeCameraDeviceSessionHwl::Flush() {
   return OK;
 }
 
+void FakeCameraDeviceSessionHwl::RepeatingRequestEnd(
+    int32_t /*frame_number*/, const std::vector<int32_t>& /*stream_ids*/) {
+}
+
 uint32_t FakeCameraDeviceSessionHwl::GetCameraId() const {
   return kCameraId;
 }
@@ -340,6 +344,10 @@ void MockDeviceSessionHwl::DelegateCallsToFakeSession() {
       .WillByDefault(
           Invoke(&fake_session_hwl_, &FakeCameraDeviceSessionHwl::Flush));
 
+  ON_CALL(*this, RepeatingRequestEnd(_, _))
+      .WillByDefault(Invoke(&fake_session_hwl_,
+                            &FakeCameraDeviceSessionHwl::RepeatingRequestEnd));
+
   ON_CALL(*this, GetCameraId())
       .WillByDefault(
           Invoke(&fake_session_hwl_, &FakeCameraDeviceSessionHwl::GetCameraId));
diff --git a/common/hal/tests/mock_device_session_hwl.h b/common/hal/tests/mock_device_session_hwl.h
index 76b512b..7ee4826 100644
--- a/common/hal/tests/mock_device_session_hwl.h
+++ b/common/hal/tests/mock_device_session_hwl.h
@@ -20,6 +20,8 @@
 #include <camera_device_session.h>
 #include <gmock/gmock.h>
 
+#include <vector>
+
 #include "profiler.h"
 #include "session_data_defs.h"
 
@@ -72,6 +74,9 @@ class FakeCameraDeviceSessionHwl : public CameraDeviceSessionHwl {
 
   status_t Flush() override;
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
   uint32_t GetCameraId() const override;
 
   std::vector<uint32_t> GetPhysicalCameraIds() const override;
@@ -162,6 +167,10 @@ class MockDeviceSessionHwl : public CameraDeviceSessionHwl {
 
   MOCK_METHOD0(Flush, status_t());
 
+  MOCK_METHOD(void, RepeatingRequestEnd,
+              (int32_t frame_number, const std::vector<int32_t>& stream_ids),
+              (override));
+
   MOCK_CONST_METHOD0(GetCameraId, uint32_t());
 
   MOCK_CONST_METHOD0(GetPhysicalCameraIds, std::vector<uint32_t>());
diff --git a/common/hal/tests/mock_process_block.h b/common/hal/tests/mock_process_block.h
index 56a993c..48c0809 100644
--- a/common/hal/tests/mock_process_block.h
+++ b/common/hal/tests/mock_process_block.h
@@ -42,6 +42,10 @@ class MockProcessBlock : public ProcessBlock {
                const CaptureRequest& remaining_session_request));
 
   MOCK_METHOD0(Flush, status_t());
+
+  MOCK_METHOD(void, RepeatingRequestEnd,
+              (int32_t frame_number, const std::vector<int32_t>& stream_ids),
+              (override));
 };
 
 }  // namespace google_camera_hal
diff --git a/common/hal/utils/Android.bp b/common/hal/utils/Android.bp
index 98fffef..6d29907 100644
--- a/common/hal/utils/Android.bp
+++ b/common/hal/utils/Android.bp
@@ -29,9 +29,6 @@ cc_library_shared {
         "gralloc_buffer_allocator.cc",
         "hal_camera_metadata.cc",
         "hal_utils.cc",
-        "hdrplus_process_block.cc",
-        "hdrplus_request_processor.cc",
-        "hdrplus_result_processor.cc",
         "hwl_buffer_allocator.cc",
         "internal_stream_manager.cc",
         "multicam_realtime_process_block.cc",
@@ -61,6 +58,6 @@ cc_library_shared {
     ],
     export_include_dirs: ["."],
     include_dirs: [
-        "system/media/private/camera/include"
+        "system/media/private/camera/include",
     ],
 }
diff --git a/common/hal/utils/hdrplus_process_block.cc b/common/hal/utils/hdrplus_process_block.cc
deleted file mode 100644
index 6811189..0000000
--- a/common/hal/utils/hdrplus_process_block.cc
+++ /dev/null
@@ -1,219 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//#define LOG_NDEBUG 0
-#define LOG_TAG "GCH_HdrplusProcessBlock"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-#include "hdrplus_process_block.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<HdrplusProcessBlock> HdrplusProcessBlock::Create(
-    CameraDeviceSessionHwl* device_session_hwl, uint32_t cameraId) {
-  ATRACE_CALL();
-  if (!IsSupported(device_session_hwl)) {
-    ALOGE("%s: Not supported.", __FUNCTION__);
-    return nullptr;
-  }
-  ALOGI("%s: cameraId: %d", __FUNCTION__, cameraId);
-  auto block = std::unique_ptr<HdrplusProcessBlock>(
-      new HdrplusProcessBlock(cameraId, device_session_hwl));
-  if (block == nullptr) {
-    ALOGE("%s: Creating HdrplusProcessBlock failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  return block;
-}
-
-bool HdrplusProcessBlock::IsSupported(CameraDeviceSessionHwl* device_session_hwl) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl is nullptr", __FUNCTION__);
-    return false;
-  }
-
-  return true;
-}
-
-HdrplusProcessBlock::HdrplusProcessBlock(
-    uint32_t cameraId, CameraDeviceSessionHwl* device_session_hwl)
-    : kCameraId(cameraId), device_session_hwl_(device_session_hwl) {
-  ATRACE_CALL();
-  hwl_pipeline_callback_.process_pipeline_result = HwlProcessPipelineResultFunc(
-      [this](std::unique_ptr<HwlPipelineResult> result) {
-        NotifyHwlPipelineResult(std::move(result));
-      });
-
-  hwl_pipeline_callback_.notify = NotifyHwlPipelineMessageFunc(
-      [this](uint32_t pipeline_id, const NotifyMessage& message) {
-        NotifyHwlPipelineMessage(pipeline_id, message);
-      });
-}
-
-status_t HdrplusProcessBlock::SetResultProcessor(
-    std::unique_ptr<ResultProcessor> result_processor) {
-  ATRACE_CALL();
-  if (result_processor == nullptr) {
-    ALOGE("%s: result_processor is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(result_processor_lock_);
-  if (result_processor_ != nullptr) {
-    ALOGE("%s: result_processor_ was already set.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  result_processor_ = std::move(result_processor);
-  return OK;
-}
-
-status_t HdrplusProcessBlock::ConfigureStreams(
-    const StreamConfiguration& stream_config,
-    const StreamConfiguration& overall_config) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (is_configured_) {
-    ALOGE("%s: Already configured.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  status_t res = device_session_hwl_->ConfigurePipeline(
-      kCameraId, hwl_pipeline_callback_, stream_config, overall_config,
-      &pipeline_id_);
-  if (res != OK) {
-    ALOGE("%s: Configuring a pipeline failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  is_configured_ = true;
-  return OK;
-}
-
-status_t HdrplusProcessBlock::GetConfiguredHalStreams(
-    std::vector<HalStream>* hal_streams) const {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (hal_streams == nullptr) {
-    ALOGE("%s: hal_streams is nullptr.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  if (!is_configured_) {
-    ALOGE("%s: Not configured yet.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  return device_session_hwl_->GetConfiguredHalStream(pipeline_id_, hal_streams);
-}
-
-status_t HdrplusProcessBlock::ProcessRequests(
-    const std::vector<ProcessBlockRequest>& process_block_requests,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  if (process_block_requests.size() != 1) {
-    ALOGE("%s: Only a single request is supported but there are %zu",
-          __FUNCTION__, process_block_requests.size());
-    return BAD_VALUE;
-  }
-
-  {
-    std::lock_guard<std::mutex> lock(result_processor_lock_);
-    if (result_processor_ == nullptr) {
-      ALOGE("%s: result processor was not set.", __FUNCTION__);
-      return NO_INIT;
-    }
-
-    status_t res = result_processor_->AddPendingRequests(
-        process_block_requests, remaining_session_request);
-    if (res != OK) {
-      ALOGE("%s: Adding a pending request to result processor failed: %s(%d)",
-            __FUNCTION__, strerror(-res), res);
-      return res;
-    }
-  }
-
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (!is_configured_) {
-    ALOGE("%s: block is not configured.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  std::vector<HwlPipelineRequest> hwl_requests(1);
-  status_t res = hal_utils::CreateHwlPipelineRequest(
-      &hwl_requests[0], pipeline_id_, process_block_requests[0].request);
-  if (res != OK) {
-    ALOGE("%s: Creating HWL pipeline request failed: %s(%d)", __FUNCTION__,
-          strerror(-res), res);
-    return res;
-  }
-
-  return device_session_hwl_->SubmitRequests(
-      process_block_requests[0].request.frame_number, hwl_requests);
-}
-
-status_t HdrplusProcessBlock::Flush() {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(configure_lock_);
-  if (!is_configured_) {
-    return OK;
-  }
-
-  return device_session_hwl_->Flush();
-}
-
-void HdrplusProcessBlock::NotifyHwlPipelineResult(
-    std::unique_ptr<HwlPipelineResult> hwl_result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(result_processor_lock_);
-  if (result_processor_ == nullptr) {
-    ALOGE("%s: result processor is nullptr. Dropping a result", __FUNCTION__);
-    return;
-  }
-
-  auto capture_result = hal_utils::ConvertToCaptureResult(std::move(hwl_result));
-  if (capture_result == nullptr) {
-    ALOGE("%s: Converting to capture result failed.", __FUNCTION__);
-    return;
-  }
-
-  ProcessBlockResult result = {.result = std::move(capture_result)};
-  result_processor_->ProcessResult(std::move(result));
-}
-
-void HdrplusProcessBlock::NotifyHwlPipelineMessage(uint32_t /*pipeline_id*/,
-                                                   const NotifyMessage& message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(result_processor_lock_);
-  if (result_processor_ == nullptr) {
-    ALOGE("%s: result processor is nullptr. Dropping a message", __FUNCTION__);
-    return;
-  }
-
-  ProcessBlockNotifyMessage block_message = {.message = message};
-  result_processor_->Notify(block_message);
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
diff --git a/common/hal/utils/hdrplus_process_block.h b/common/hal/utils/hdrplus_process_block.h
deleted file mode 100644
index 1218fba..0000000
--- a/common/hal/utils/hdrplus_process_block.h
+++ /dev/null
@@ -1,94 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_PROCESS_BLOCK_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_PROCESS_BLOCK_H_
-
-#include "process_block.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// HdrplusProcessBlock implements a offline ProcessBlock.
-// It can process offline capture requests for a single physical camera.
-class HdrplusProcessBlock : public ProcessBlock {
- public:
-  // Create a HdrplusProcessBlock.
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of this HdrplusProcessBlock.
-  static std::unique_ptr<HdrplusProcessBlock> Create(
-      CameraDeviceSessionHwl* device_session_hwl, uint32_t cameraId);
-
-  virtual ~HdrplusProcessBlock() = default;
-
-  // Override functions of ProcessBlock start.
-  // All output streams must be physical streams. HdrplusProcessBlock does not
-  // support logical output streams.
-  status_t ConfigureStreams(const StreamConfiguration& stream_config,
-                            const StreamConfiguration& overall_config) override;
-
-  status_t SetResultProcessor(
-      std::unique_ptr<ResultProcessor> result_processor) override;
-
-  status_t GetConfiguredHalStreams(
-      std::vector<HalStream>* hal_streams) const override;
-
-  status_t ProcessRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  status_t Flush() override;
-  // Override functions of ProcessBlock end.
-
- protected:
-  HdrplusProcessBlock(uint32_t cameraId,
-                      CameraDeviceSessionHwl* device_session_hwl);
-
- private:
-  // Camera ID of this process block.
-  const uint32_t kCameraId;
-
-  // If the process block supports the device session.
-  static bool IsSupported(CameraDeviceSessionHwl* device_session_hwl);
-
-  // Invoked when the HWL pipeline sends a result.
-  void NotifyHwlPipelineResult(std::unique_ptr<HwlPipelineResult> hwl_result);
-
-  // Invoked when the HWL pipeline sends a message.
-  void NotifyHwlPipelineMessage(uint32_t pipeline_id,
-                                const NotifyMessage& message);
-
-  HwlPipelineCallback hwl_pipeline_callback_;
-  CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
-
-  mutable std::mutex configure_lock_;
-
-  // If streams are configured. Must be protected by configure_lock_.
-  bool is_configured_ = false;
-
-  // HWL pipeline ID. Must be protected by configure_lock_.
-  uint32_t pipeline_id_ = 0;
-
-  std::mutex result_processor_lock_;
-
-  // Result processor. Must be protected by result_processor_lock_.
-  std::unique_ptr<ResultProcessor> result_processor_ = nullptr;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_PROCESS_BLOCK_H_
diff --git a/common/hal/utils/hdrplus_request_processor.cc b/common/hal/utils/hdrplus_request_processor.cc
deleted file mode 100644
index 9ca39fb..0000000
--- a/common/hal/utils/hdrplus_request_processor.cc
+++ /dev/null
@@ -1,254 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//#define LOG_NDEBUG 0
-#define LOG_TAG "GCH_HdrplusRequestProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hdrplus_request_processor.h"
-#include "vendor_tag_defs.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<HdrplusRequestProcessor> HdrplusRequestProcessor::Create(
-    CameraDeviceSessionHwl* device_session_hwl, int32_t raw_stream_id,
-    uint32_t physical_camera_id) {
-  ATRACE_CALL();
-  if (device_session_hwl == nullptr) {
-    ALOGE("%s: device_session_hwl (%p) is nullptr", __FUNCTION__,
-          device_session_hwl);
-    return nullptr;
-  }
-
-  auto request_processor = std::unique_ptr<HdrplusRequestProcessor>(
-      new HdrplusRequestProcessor(physical_camera_id));
-  if (request_processor == nullptr) {
-    ALOGE("%s: Creating HdrplusRequestProcessor failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  status_t res =
-      request_processor->Initialize(device_session_hwl, raw_stream_id);
-  if (res != OK) {
-    ALOGE("%s: Initializing HdrplusRequestProcessor failed: %s (%d).",
-          __FUNCTION__, strerror(-res), res);
-    return nullptr;
-  }
-
-  return request_processor;
-}
-
-status_t HdrplusRequestProcessor::Initialize(
-    CameraDeviceSessionHwl* device_session_hwl, int32_t raw_stream_id) {
-  ATRACE_CALL();
-  std::unique_ptr<HalCameraMetadata> characteristics;
-  status_t res = NO_INIT;
-  uint32_t num_physical_cameras =
-      device_session_hwl->GetPhysicalCameraIds().size();
-  if (num_physical_cameras > 0) {
-    res = device_session_hwl->GetPhysicalCameraCharacteristics(
-        kCameraId, &characteristics);
-    if (res != OK) {
-      ALOGE("%s: GetPhysicalCameraCharacteristics failed.", __FUNCTION__);
-      return BAD_VALUE;
-    }
-  } else {
-    res = device_session_hwl->GetCameraCharacteristics(&characteristics);
-    if (res != OK) {
-      ALOGE("%s: GetCameraCharacteristics failed.", __FUNCTION__);
-      return BAD_VALUE;
-    }
-  }
-
-  camera_metadata_ro_entry entry;
-  res = characteristics->Get(
-      ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE, &entry);
-  if (res == OK) {
-    active_array_width_ = entry.data.i32[2];
-    active_array_height_ = entry.data.i32[3];
-    ALOGI("%s Active size (%d x %d).", __FUNCTION__, active_array_width_,
-          active_array_height_);
-  } else {
-    ALOGE("%s Get active size failed: %s (%d).", __FUNCTION__, strerror(-res),
-          res);
-    return res;
-  }
-
-  res = characteristics->Get(VendorTagIds::kHdrplusPayloadFrames, &entry);
-  if (res != OK || entry.data.i32[0] <= 0) {
-    ALOGE("%s: Getting kHdrplusPayloadFrames failed or number <= 0",
-          __FUNCTION__);
-    return BAD_VALUE;
-  }
-  payload_frames_ = entry.data.i32[0];
-  ALOGI("%s: HDR+ payload_frames_: %d", __FUNCTION__, payload_frames_);
-  raw_stream_id_ = raw_stream_id;
-
-  return OK;
-}
-
-status_t HdrplusRequestProcessor::ConfigureStreams(
-    InternalStreamManager* internal_stream_manager,
-    const StreamConfiguration& stream_config,
-    StreamConfiguration* process_block_stream_config) {
-  ATRACE_CALL();
-  if (process_block_stream_config == nullptr ||
-      internal_stream_manager == nullptr) {
-    ALOGE(
-        "%s: process_block_stream_config (%p) is nullptr or "
-        "internal_stream_manager (%p) is nullptr",
-        __FUNCTION__, process_block_stream_config, internal_stream_manager);
-    return BAD_VALUE;
-  }
-
-  internal_stream_manager_ = internal_stream_manager;
-
-  Stream raw_stream;
-  raw_stream.stream_type = StreamType::kInput;
-  raw_stream.width = active_array_width_;
-  raw_stream.height = active_array_height_;
-  raw_stream.format = HAL_PIXEL_FORMAT_RAW10;
-  raw_stream.usage = 0;
-  raw_stream.rotation = StreamRotation::kRotation0;
-  raw_stream.data_space = HAL_DATASPACE_ARBITRARY;
-  // Set id back to raw_stream and then HWL can get correct HAL stream ID
-  raw_stream.id = raw_stream_id_;
-
-  process_block_stream_config->streams = stream_config.streams;
-  // Add internal RAW stream
-  process_block_stream_config->streams.push_back(raw_stream);
-  process_block_stream_config->operation_mode = stream_config.operation_mode;
-  process_block_stream_config->session_params =
-      HalCameraMetadata::Clone(stream_config.session_params.get());
-  process_block_stream_config->stream_config_counter =
-      stream_config.stream_config_counter;
-  process_block_stream_config->log_id = stream_config.log_id;
-
-  return OK;
-}
-
-status_t HdrplusRequestProcessor::SetProcessBlock(
-    std::unique_ptr<ProcessBlock> process_block) {
-  ATRACE_CALL();
-  if (process_block == nullptr) {
-    ALOGE("%s: process_block is nullptr", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ != nullptr) {
-    ALOGE("%s: Already configured.", __FUNCTION__);
-    return ALREADY_EXISTS;
-  }
-
-  process_block_ = std::move(process_block);
-  return OK;
-}
-
-bool HdrplusRequestProcessor::IsReadyForNextRequest() {
-  ATRACE_CALL();
-  if (internal_stream_manager_ == nullptr) {
-    ALOGW("%s: internal_stream_manager_ nullptr", __FUNCTION__);
-    return false;
-  }
-  if (internal_stream_manager_->IsPendingBufferEmpty(raw_stream_id_) == false) {
-    return false;
-  }
-  return true;
-}
-
-void HdrplusRequestProcessor::RemoveJpegMetadata(
-    std::vector<std::unique_ptr<HalCameraMetadata>>* metadata) {
-  const uint32_t tags[] = {
-      ANDROID_JPEG_THUMBNAIL_SIZE,  ANDROID_JPEG_ORIENTATION,
-      ANDROID_JPEG_QUALITY,         ANDROID_JPEG_THUMBNAIL_QUALITY,
-      ANDROID_JPEG_GPS_COORDINATES, ANDROID_JPEG_GPS_PROCESSING_METHOD,
-      ANDROID_JPEG_GPS_TIMESTAMP};
-  if (metadata == nullptr) {
-    ALOGW("%s: metadata is nullptr", __FUNCTION__);
-    return;
-  }
-
-  for (uint32_t i = 0; i < metadata->size(); i++) {
-    for (uint32_t tag_index = 0; tag_index < sizeof(tags) / sizeof(uint32_t);
-         tag_index++) {
-      if (metadata->at(i) == nullptr) {
-        continue;
-      }
-      status_t res = metadata->at(i)->Erase(tags[tag_index]);
-      if (res != OK) {
-        ALOGW("%s: (%d)erase index(%d) failed: %s(%d)", __FUNCTION__, i,
-              tag_index, strerror(-res), res);
-      }
-    }
-  }
-}
-
-status_t HdrplusRequestProcessor::ProcessRequest(const CaptureRequest& request) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ == nullptr) {
-    ALOGE("%s: Not configured yet.", __FUNCTION__);
-    return NO_INIT;
-  }
-
-  if (IsReadyForNextRequest() == false) {
-    return BAD_VALUE;
-  }
-
-  CaptureRequest block_request;
-  block_request.frame_number = request.frame_number;
-  block_request.settings = HalCameraMetadata::Clone(request.settings.get());
-  block_request.output_buffers = request.output_buffers;
-  for (auto& [camera_id, physical_metadata] : request.physical_camera_settings) {
-    block_request.physical_camera_settings[camera_id] =
-        HalCameraMetadata::Clone(physical_metadata.get());
-  }
-
-  // Get multiple raw buffer and metadata from internal stream as input
-  status_t result = internal_stream_manager_->GetMostRecentStreamBuffer(
-      raw_stream_id_, &(block_request.input_buffers),
-      &(block_request.input_buffer_metadata), payload_frames_);
-  if (result != OK) {
-    ALOGE("%s: frame:%d GetStreamBuffer failed.", __FUNCTION__,
-          request.frame_number);
-    return UNKNOWN_ERROR;
-  }
-
-  RemoveJpegMetadata(&(block_request.input_buffer_metadata));
-  std::vector<ProcessBlockRequest> block_requests(1);
-  block_requests[0].request = std::move(block_request);
-  ALOGD("%s: frame number %u is an HDR+ request.", __FUNCTION__,
-        request.frame_number);
-
-  return process_block_->ProcessRequests(block_requests, request);
-}
-
-status_t HdrplusRequestProcessor::Flush() {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(process_block_lock_);
-  if (process_block_ == nullptr) {
-    return OK;
-  }
-
-  return process_block_->Flush();
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
diff --git a/common/hal/utils/hdrplus_request_processor.h b/common/hal/utils/hdrplus_request_processor.h
deleted file mode 100644
index e6cf9af..0000000
--- a/common/hal/utils/hdrplus_request_processor.h
+++ /dev/null
@@ -1,86 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_REQUEST_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_REQUEST_PROCESSOR_H_
-
-#include "process_block.h"
-#include "request_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// HdrplusRequestProcessor implements a RequestProcessor that adds
-// internal raw stream as input stream to request and forwards the request to
-// its ProcessBlock.
-class HdrplusRequestProcessor : public RequestProcessor {
- public:
-  // device_session_hwl is owned by the caller and must be valid during the
-  // lifetime of this HdrplusRequestProcessor.
-  static std::unique_ptr<HdrplusRequestProcessor> Create(
-      CameraDeviceSessionHwl* device_session_hwl, int32_t raw_stream_id,
-      uint32_t physical_camera_id);
-
-  virtual ~HdrplusRequestProcessor() = default;
-
-  // Override functions of RequestProcessor start.
-  status_t ConfigureStreams(
-      InternalStreamManager* internal_stream_manager,
-      const StreamConfiguration& stream_config,
-      StreamConfiguration* process_block_stream_config) override;
-
-  status_t SetProcessBlock(std::unique_ptr<ProcessBlock> process_block) override;
-
-  // Adds internal raw stream as input stream to request and forwards the
-  // request to its ProcessBlock.
-  status_t ProcessRequest(const CaptureRequest& request) override;
-
-  status_t Flush() override;
-  // Override functions of RequestProcessor end.
-
- protected:
-  HdrplusRequestProcessor(uint32_t physical_camera_id)
-      : kCameraId(physical_camera_id){};
-
- private:
-  // Physical camera ID of request processor.
-  const uint32_t kCameraId;
-
-  status_t Initialize(CameraDeviceSessionHwl* device_session_hwl,
-                      int32_t raw_stream_id);
-  bool IsReadyForNextRequest();
-  // For CTS (android.hardware.camera2.cts.StillCaptureTest#testJpegExif)
-  // Remove JPEG metadata (THUMBNAIL_SIZE, ORIENTATION...) from internal raw
-  // buffer in order to get these metadata from HDR+ capture request directly
-  void RemoveJpegMetadata(
-      std::vector<std::unique_ptr<HalCameraMetadata>>* metadata);
-  std::mutex process_block_lock_;
-
-  // Protected by process_block_lock_.
-  std::unique_ptr<ProcessBlock> process_block_;
-
-  InternalStreamManager* internal_stream_manager_;
-  int32_t raw_stream_id_ = -1;
-  uint32_t active_array_width_ = 0;
-  uint32_t active_array_height_ = 0;
-  // The number of HDR+ input buffers
-  uint32_t payload_frames_ = 0;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_REQUEST_PROCESSOR_H_
diff --git a/common/hal/utils/hdrplus_result_processor.cc b/common/hal/utils/hdrplus_result_processor.cc
deleted file mode 100644
index ba08bb4..0000000
--- a/common/hal/utils/hdrplus_result_processor.cc
+++ /dev/null
@@ -1,140 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// #define LOG_NDEBUG 0
-#define LOG_TAG "GCH_HdrplusResultProcessor"
-#define ATRACE_TAG ATRACE_TAG_CAMERA
-#include "hdrplus_result_processor.h"
-
-#include <inttypes.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include "hal_utils.h"
-
-namespace android {
-namespace google_camera_hal {
-
-std::unique_ptr<HdrplusResultProcessor> HdrplusResultProcessor::Create(
-    InternalStreamManager* internal_stream_manager, int32_t raw_stream_id) {
-  ATRACE_CALL();
-  if (internal_stream_manager == nullptr) {
-    ALOGE("%s: internal_stream_manager nullptr.", __FUNCTION__);
-    return nullptr;
-  }
-
-  auto result_processor = std::unique_ptr<HdrplusResultProcessor>(
-      new HdrplusResultProcessor(internal_stream_manager, raw_stream_id));
-  if (result_processor == nullptr) {
-    ALOGE("%s: Creating HdrplusResultProcessor failed.", __FUNCTION__);
-    return nullptr;
-  }
-
-  return result_processor;
-}
-
-HdrplusResultProcessor::HdrplusResultProcessor(
-    InternalStreamManager* internal_stream_manager, int32_t raw_stream_id) {
-  internal_stream_manager_ = internal_stream_manager;
-  raw_stream_id_ = raw_stream_id;
-}
-void HdrplusResultProcessor::SetResultCallback(
-    ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  process_capture_result_ = process_capture_result;
-  notify_ = notify;
-}
-
-status_t HdrplusResultProcessor::AddPendingRequests(
-    const std::vector<ProcessBlockRequest>& process_block_requests,
-    const CaptureRequest& remaining_session_request) {
-  ATRACE_CALL();
-  // This is the last result processor. Sanity check if requests contains
-  // all remaining output buffers.
-  if (!hal_utils::AreAllRemainingBuffersRequested(process_block_requests,
-                                                  remaining_session_request)) {
-    ALOGE("%s: Some output buffers will not be completed.", __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  return OK;
-}
-
-void HdrplusResultProcessor::ProcessResult(ProcessBlockResult block_result) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-
-  std::unique_ptr<CaptureResult> result = std::move(block_result.result);
-  if (result == nullptr) {
-    ALOGW("%s: Received a nullptr result.", __FUNCTION__);
-    return;
-  }
-
-  if (process_capture_result_ == nullptr) {
-    ALOGE("%s: process_capture_result_ is nullptr. Dropping a result.",
-          __FUNCTION__);
-    return;
-  }
-
-  // Return raw buffer to internal stream manager and remove it from result
-  status_t res;
-  if (result->output_buffers.size() != 0 &&
-      internal_stream_manager_->IsPendingBufferEmpty(raw_stream_id_) == false) {
-    res = internal_stream_manager_->ReturnZslStreamBuffers(result->frame_number,
-                                                           raw_stream_id_);
-    if (res != OK) {
-      ALOGE("%s: (%d)ReturnZslStreamBuffers fail", __FUNCTION__,
-            result->frame_number);
-      return;
-    } else {
-      ALOGI("%s: (%d)ReturnZslStreamBuffers ok", __FUNCTION__,
-            result->frame_number);
-    }
-    result->input_buffers.clear();
-  }
-
-  if (result->result_metadata) {
-    res = hal_utils::SetEnableZslMetadata(result->result_metadata.get(), true);
-    if (res != OK) {
-      ALOGW("%s: SetEnableZslMetadata (%d) fail", __FUNCTION__,
-            result->frame_number);
-    }
-  }
-
-  process_capture_result_(std::move(result));
-}
-
-void HdrplusResultProcessor::Notify(
-    const ProcessBlockNotifyMessage& block_message) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(callback_lock_);
-  if (notify_ == nullptr) {
-    ALOGE("%s: notify_ is nullptr. Dropping a message.", __FUNCTION__);
-    return;
-  }
-
-  notify_(block_message.message);
-}
-
-status_t HdrplusResultProcessor::FlushPendingRequests() {
-  ATRACE_CALL();
-  return INVALID_OPERATION;
-}
-
-}  // namespace google_camera_hal
-}  // namespace android
\ No newline at end of file
diff --git a/common/hal/utils/hdrplus_result_processor.h b/common/hal/utils/hdrplus_result_processor.h
deleted file mode 100644
index 6719eb9..0000000
--- a/common/hal/utils/hdrplus_result_processor.h
+++ /dev/null
@@ -1,72 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_RESULT_PROCESSOR_H_
-#define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_RESULT_PROCESSOR_H_
-
-#include "internal_stream_manager.h"
-#include "result_processor.h"
-
-namespace android {
-namespace google_camera_hal {
-
-// HdrplusResultProcessor implements a ResultProcessor that return
-// raw buffer to internal stream manager and forwards the results without
-// raw buffer to its callback functions.
-class HdrplusResultProcessor : public ResultProcessor {
- public:
-  static std::unique_ptr<HdrplusResultProcessor> Create(
-      InternalStreamManager* internal_stream_manager, int32_t raw_stream_id);
-
-  virtual ~HdrplusResultProcessor() = default;
-
-  // Override functions of ResultProcessor start.
-  void SetResultCallback(
-      ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
-
-  status_t AddPendingRequests(
-      const std::vector<ProcessBlockRequest>& process_block_requests,
-      const CaptureRequest& remaining_session_request) override;
-
-  // Return raw buffer to internal stream manager and forwards the results
-  // without raw buffer to its callback functions.
-  void ProcessResult(ProcessBlockResult block_result) override;
-
-  void Notify(const ProcessBlockNotifyMessage& block_message) override;
-
-  status_t FlushPendingRequests() override;
-  // Override functions of ResultProcessor end.
-
- protected:
-  HdrplusResultProcessor(InternalStreamManager* internal_stream_manager,
-                         int32_t raw_stream_id);
-
- private:
-  std::mutex callback_lock_;
-
-  // The following callbacks must be protected by callback_lock_.
-  ProcessCaptureResultFunc process_capture_result_;
-  NotifyFunc notify_;
-
-  InternalStreamManager* internal_stream_manager_;
-  int32_t raw_stream_id_ = -1;
-};
-
-}  // namespace google_camera_hal
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_HDRPLUS_RESULT_PROCESSOR_H_
diff --git a/common/hal/utils/multicam_realtime_process_block.cc b/common/hal/utils/multicam_realtime_process_block.cc
index da624d4..66383d2 100644
--- a/common/hal/utils/multicam_realtime_process_block.cc
+++ b/common/hal/utils/multicam_realtime_process_block.cc
@@ -14,16 +14,17 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_MultiCameraRtProcessBlock"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
+#include "multicam_realtime_process_block.h"
+
 #include <log/log.h>
 #include <utils/Trace.h>
 
 #include <unordered_set>
 
 #include "hal_utils.h"
-#include "multicam_realtime_process_block.h"
 #include "result_processor.h"
 
 namespace android {
@@ -422,6 +423,15 @@ status_t MultiCameraRtProcessBlock::Flush() {
   return result_processor_->FlushPendingRequests();
 }
 
+void MultiCameraRtProcessBlock::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(configure_shared_mutex_);
+  if (!configured_streams_.empty()) {
+    device_session_hwl_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 void MultiCameraRtProcessBlock::NotifyHwlPipelineResult(
     std::unique_ptr<HwlPipelineResult> hwl_result) {
   ATRACE_CALL();
diff --git a/common/hal/utils/multicam_realtime_process_block.h b/common/hal/utils/multicam_realtime_process_block.h
index c44e84d..b715a50 100644
--- a/common/hal/utils/multicam_realtime_process_block.h
+++ b/common/hal/utils/multicam_realtime_process_block.h
@@ -19,6 +19,7 @@
 
 #include <map>
 #include <shared_mutex>
+#include <vector>
 
 #include "pipeline_request_id_manager.h"
 #include "process_block.h"
@@ -57,6 +58,9 @@ class MultiCameraRtProcessBlock : public ProcessBlock {
       const CaptureRequest& remaining_session_request) override;
 
   status_t Flush() override;
+
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
   // Override functions of ProcessBlock end.
 
   // Prepare pipeline by camera id
diff --git a/common/hal/utils/profiling/aidl_profiler.cc b/common/hal/utils/profiling/aidl_profiler.cc
index 77c9650..a58cc17 100644
--- a/common/hal/utils/profiling/aidl_profiler.cc
+++ b/common/hal/utils/profiling/aidl_profiler.cc
@@ -92,7 +92,7 @@ class AidlProfilerImpl : public AidlProfiler {
     }
 
     if (int size = latency_profilers_.size(); size > 2) {
-      ALOGE("%s: Too many overlapping operations (have: %d). Will not profile.",
+      ALOGW("%s: Too many overlapping operations (have: %d). Will not profile.",
             __FUNCTION__, size);
       return nullptr;
     }
@@ -105,7 +105,7 @@ class AidlProfilerImpl : public AidlProfiler {
         return nullptr;
       }
     }
-    ALOGE("%s: Could not find an operation for incoming event: %s",
+    ALOGW("%s: Could not find an operation for incoming event: %s",
           __FUNCTION__, EventTypeToString(type).c_str());
     return nullptr;
   }
@@ -118,7 +118,7 @@ class AidlProfilerImpl : public AidlProfiler {
         return;
       }
     }
-    ALOGE("%s: Error: no profiler accepted First Frame Start", __FUNCTION__);
+    ALOGW("%s: Error: no profiler accepted First Frame Start", __FUNCTION__);
   }
 
   void FirstFrameEnd() override {
@@ -130,7 +130,7 @@ class AidlProfilerImpl : public AidlProfiler {
         return;
       }
     }
-    ALOGE("%s: Error: no profiler accepted First Frame End", __FUNCTION__);
+    ALOGW("%s: Error: no profiler accepted First Frame End", __FUNCTION__);
   }
 
   void ReprocessingRequestStart(
@@ -176,7 +176,7 @@ class AidlProfilerImpl : public AidlProfiler {
     }
     std::shared_ptr<Profiler> profiler = Profiler::Create(latency_flag_);
     if (profiler == nullptr) {
-      ALOGE("%s: Failed to create profiler", __FUNCTION__);
+      ALOGW("%s: Failed to create profiler", __FUNCTION__);
       return nullptr;
     }
     profiler->SetDumpFilePrefix(
@@ -210,7 +210,7 @@ class AidlProfilerImpl : public AidlProfiler {
     }
     std::shared_ptr<Profiler> profiler = Profiler::Create(fps_flag_);
     if (profiler == nullptr) {
-      ALOGE("%s: Failed to create profiler", __FUNCTION__);
+      ALOGW("%s: Failed to create profiler", __FUNCTION__);
       return nullptr;
     }
     profiler->SetDumpFilePrefix("/data/vendor/camera/profiler/aidl_fps_");
@@ -223,7 +223,7 @@ class AidlProfilerImpl : public AidlProfiler {
     }
     std::shared_ptr<Profiler> profiler = Profiler::Create(latency_flag_);
     if (profiler == nullptr) {
-      ALOGE("%s: Failed to create profiler", __FUNCTION__);
+      ALOGW("%s: Failed to create profiler", __FUNCTION__);
       return nullptr;
     }
     profiler->SetDumpFilePrefix("/data/vendor/camera/profiler/aidl_reprocess_");
diff --git a/common/hal/utils/realtime_process_block.cc b/common/hal/utils/realtime_process_block.cc
index d5679be..5358704 100644
--- a/common/hal/utils/realtime_process_block.cc
+++ b/common/hal/utils/realtime_process_block.cc
@@ -190,6 +190,15 @@ status_t RealtimeProcessBlock::Flush() {
   return device_session_hwl_->Flush();
 }
 
+void RealtimeProcessBlock::RepeatingRequestEnd(
+    int32_t frame_number, const std::vector<int32_t>& stream_ids) {
+  ATRACE_CALL();
+  std::shared_lock lock(configure_shared_mutex_);
+  if (is_configured_) {
+    device_session_hwl_->RepeatingRequestEnd(frame_number, stream_ids);
+  }
+}
+
 void RealtimeProcessBlock::NotifyHwlPipelineResult(
     std::unique_ptr<HwlPipelineResult> hwl_result) {
   ATRACE_CALL();
diff --git a/common/hal/utils/realtime_process_block.h b/common/hal/utils/realtime_process_block.h
index e2eb90f..9aeadb6 100644
--- a/common/hal/utils/realtime_process_block.h
+++ b/common/hal/utils/realtime_process_block.h
@@ -56,6 +56,9 @@ class RealtimeProcessBlock : public ProcessBlock {
   status_t Flush() override;
   // Override functions of ProcessBlock end.
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
  protected:
   RealtimeProcessBlock(CameraDeviceSessionHwl* device_session_hwl);
 
diff --git a/common/hal/utils/result_dispatcher.cc b/common/hal/utils/result_dispatcher.cc
index f4225e5..8ea872b 100644
--- a/common/hal/utils/result_dispatcher.cc
+++ b/common/hal/utils/result_dispatcher.cc
@@ -17,6 +17,7 @@
 // #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_ResultDispatcher"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
+
 #include "result_dispatcher.h"
 
 #include <inttypes.h>
@@ -64,6 +65,12 @@ ResultDispatcher::ResultDispatcher(
       process_batch_capture_result_(process_batch_capture_result),
       notify_(notify) {
   ATRACE_CALL();
+  pending_shutters_ = DispatchQueue<PendingShutter>(name_, "shutter");
+  pending_early_metadata_ =
+      DispatchQueue<PendingResultMetadata>(name_, "early result metadata");
+  pending_final_metadata_ =
+      DispatchQueue<PendingResultMetadata>(name_, "final result metadata");
+
   notify_callback_thread_ =
       std::thread([this] { this->NotifyCallbackThreadLoop(); });
 
@@ -118,23 +125,33 @@ status_t ResultDispatcher::AddPendingRequestLocked(
     const CaptureRequest& pending_request) {
   ATRACE_CALL();
   uint32_t frame_number = pending_request.frame_number;
+  const RequestType request_type = pending_request.input_buffers.empty()
+                                       ? RequestType::kNormal
+                                       : RequestType::kReprocess;
 
-  status_t res = AddPendingShutterLocked(frame_number);
+  status_t res = pending_shutters_.AddRequest(frame_number, request_type);
   if (res != OK) {
     ALOGE("[%s] %s: Adding pending shutter for frame %u failed: %s(%d)",
           name_.c_str(), __FUNCTION__, frame_number, strerror(-res), res);
     return res;
   }
 
-  res = AddPendingFinalResultMetadataLocked(frame_number);
+  res = pending_early_metadata_.AddRequest(frame_number, request_type);
   if (res != OK) {
-    ALOGE("[%s] %s: Adding pending result metadata for frame %u failed: %s(%d)",
+    ALOGE("[%s] %s: Adding pending early metadata for frame %u failed: %s(%d)",
+          name_.c_str(), __FUNCTION__, frame_number, strerror(-res), res);
+    return res;
+  }
+
+  res = pending_final_metadata_.AddRequest(frame_number, request_type);
+  if (res != OK) {
+    ALOGE("[%s] %s: Adding pending final metadata for frame %u failed: %s(%d)",
           name_.c_str(), __FUNCTION__, frame_number, strerror(-res), res);
     return res;
   }
 
   for (auto& buffer : pending_request.input_buffers) {
-    res = AddPendingBufferLocked(frame_number, buffer, /*is_input=*/true);
+    res = AddPendingBufferLocked(frame_number, buffer, request_type);
     if (res != OK) {
       ALOGE("[%s] %s: Adding pending input buffer for frame %u failed: %s(%d)",
             name_.c_str(), __FUNCTION__, frame_number, strerror(-res), res);
@@ -143,7 +160,7 @@ status_t ResultDispatcher::AddPendingRequestLocked(
   }
 
   for (auto& buffer : pending_request.output_buffers) {
-    res = AddPendingBufferLocked(frame_number, buffer, /*is_input=*/false);
+    res = AddPendingBufferLocked(frame_number, buffer, request_type);
     if (res != OK) {
       ALOGE("[%s] %s: Adding pending output buffer for frame %u failed: %s(%d)",
             name_.c_str(), __FUNCTION__, frame_number, strerror(-res), res);
@@ -154,63 +171,28 @@ status_t ResultDispatcher::AddPendingRequestLocked(
   return OK;
 }
 
-status_t ResultDispatcher::AddPendingShutterLocked(uint32_t frame_number) {
-  ATRACE_CALL();
-  if (pending_shutters_.find(frame_number) != pending_shutters_.end()) {
-    ALOGE("[%s] %s: Pending shutter for frame %u already exists.",
-          name_.c_str(), __FUNCTION__, frame_number);
-    return ALREADY_EXISTS;
-  }
-
-  pending_shutters_[frame_number] = PendingShutter();
-  return OK;
-}
-
-status_t ResultDispatcher::AddPendingFinalResultMetadataLocked(
-    uint32_t frame_number) {
-  ATRACE_CALL();
-  if (pending_final_metadata_.find(frame_number) !=
-      pending_final_metadata_.end()) {
-    ALOGE("[%s] %s: Pending final result metadata for frame %u already exists.",
-          name_.c_str(), __FUNCTION__, frame_number);
-    return ALREADY_EXISTS;
-  }
-
-  pending_final_metadata_[frame_number] = PendingFinalResultMetadata();
-  return OK;
-}
-
 status_t ResultDispatcher::AddPendingBufferLocked(uint32_t frame_number,
                                                   const StreamBuffer& buffer,
-                                                  bool is_input) {
+                                                  RequestType request_type) {
   ATRACE_CALL();
   StreamKey stream_key = CreateStreamKey(buffer.stream_id);
-  if (stream_pending_buffers_map_.find(stream_key) ==
-      stream_pending_buffers_map_.end()) {
-    stream_pending_buffers_map_[stream_key] =
-        std::map<uint32_t, PendingBuffer>();
+  if (!stream_pending_buffers_map_.contains(stream_key)) {
+    stream_pending_buffers_map_[stream_key] = DispatchQueue<PendingBuffer>(
+        name_, "buffer of stream " + DumpStreamKey(stream_key));
   }
 
-  if (stream_pending_buffers_map_[stream_key].find(frame_number) !=
-      stream_pending_buffers_map_[stream_key].end()) {
-    ALOGE("[%s] %s: Pending buffer of stream %s for frame %u already exists.",
-          name_.c_str(), __FUNCTION__, DumpStreamKey(stream_key).c_str(),
-          frame_number);
-    return ALREADY_EXISTS;
-  }
-
-  PendingBuffer pending_buffer = {.is_input = is_input};
-  stream_pending_buffers_map_[stream_key][frame_number] = pending_buffer;
-  return OK;
+  return stream_pending_buffers_map_[stream_key].AddRequest(frame_number,
+                                                            request_type);
 }
 
 void ResultDispatcher::RemovePendingRequestLocked(uint32_t frame_number) {
   ATRACE_CALL();
-  pending_shutters_.erase(frame_number);
-  pending_final_metadata_.erase(frame_number);
+  pending_shutters_.RemoveRequest(frame_number);
+  pending_early_metadata_.RemoveRequest(frame_number);
+  pending_final_metadata_.RemoveRequest(frame_number);
 
   for (auto& pending_buffers : stream_pending_buffers_map_) {
-    pending_buffers.second.erase(frame_number);
+    pending_buffers.second.RemoveRequest(frame_number);
   }
 }
 
@@ -231,7 +213,7 @@ status_t ResultDispatcher::AddResultImpl(std::unique_ptr<CaptureResult> result)
   }
 
   for (auto& buffer : result->output_buffers) {
-    res = AddBuffer(frame_number, buffer);
+    res = AddBuffer(frame_number, buffer, /*is_input=*/false);
     if (res != OK) {
       ALOGE("[%s] %s: Adding an output buffer failed: %s (%d)", name_.c_str(),
             __FUNCTION__, strerror(-res), res);
@@ -240,7 +222,7 @@ status_t ResultDispatcher::AddResultImpl(std::unique_ptr<CaptureResult> result)
   }
 
   for (auto& buffer : result->input_buffers) {
-    res = AddBuffer(frame_number, buffer);
+    res = AddBuffer(frame_number, buffer, /*is_input=*/true);
     if (res != OK) {
       ALOGE("[%s] %s: Adding an input buffer failed: %s (%d)", name_.c_str(),
             __FUNCTION__, strerror(-res), res);
@@ -264,9 +246,6 @@ status_t ResultDispatcher::AddResult(std::unique_ptr<CaptureResult> result) {
 
 status_t ResultDispatcher::AddBatchResult(
     std::vector<std::unique_ptr<CaptureResult>> results) {
-  // Send out the partial results immediately.
-  NotifyBatchPartialResultMetadata(results);
-
   std::optional<status_t> last_error;
   for (auto& result : results) {
     const status_t res = AddResultImpl(std::move(result));
@@ -286,27 +265,22 @@ status_t ResultDispatcher::AddShutter(uint32_t frame_number,
                                       int64_t timestamp_ns,
                                       int64_t readout_timestamp_ns) {
   ATRACE_CALL();
+
   {
     std::lock_guard<std::mutex> lock(result_lock_);
-
-    auto shutter_it = pending_shutters_.find(frame_number);
-    if (shutter_it == pending_shutters_.end()) {
-      ALOGE("[%s] %s: Cannot find the pending shutter for frame %u",
-            name_.c_str(), __FUNCTION__, frame_number);
-      return NAME_NOT_FOUND;
-    }
-
-    if (shutter_it->second.ready) {
-      ALOGE("[%s] %s: Already received shutter (%" PRId64
-            ") for frame %u. New timestamp %" PRId64,
-            name_.c_str(), __FUNCTION__, shutter_it->second.timestamp_ns,
-            frame_number, timestamp_ns);
-      return ALREADY_EXISTS;
+    status_t res = pending_shutters_.AddResult(
+        frame_number, PendingShutter{
+                          .timestamp_ns = timestamp_ns,
+                          .readout_timestamp_ns = readout_timestamp_ns,
+                          .ready = true,
+                      });
+    if (res != OK) {
+      ALOGE(
+          "[%s] %s: Failed to add shutter for frame %u , New timestamp "
+          "%" PRId64,
+          name_.c_str(), __FUNCTION__, frame_number, timestamp_ns);
+      return res;
     }
-
-    shutter_it->second.timestamp_ns = timestamp_ns;
-    shutter_it->second.readout_timestamp_ns = readout_timestamp_ns;
-    shutter_it->second.ready = true;
   }
   {
     std::unique_lock<std::mutex> lock(notify_callback_lock_);
@@ -324,12 +298,13 @@ status_t ResultDispatcher::AddError(const ErrorMessage& error) {
   if (error.error_code == ErrorCode::kErrorDevice ||
       error.error_code == ErrorCode::kErrorResult ||
       error.error_code == ErrorCode::kErrorRequest) {
-    pending_shutters_.erase(frame_number);
+    pending_shutters_.RemoveRequest(frame_number);
   }
   // No need to deliver the result metadata on a result metadata error
   if (error.error_code == ErrorCode::kErrorResult ||
       error.error_code == ErrorCode::kErrorRequest) {
-    pending_final_metadata_.erase(frame_number);
+    pending_early_metadata_.RemoveRequest(frame_number);
+    pending_final_metadata_.RemoveRequest(frame_number);
   }
 
   NotifyMessage message = {.type = MessageType::kError, .message.error = error};
@@ -353,31 +328,6 @@ std::unique_ptr<CaptureResult> ResultDispatcher::MakeResultMetadata(
   return result;
 }
 
-status_t ResultDispatcher::AddFinalResultMetadata(
-    uint32_t frame_number, std::unique_ptr<HalCameraMetadata> final_metadata,
-    std::vector<PhysicalCameraMetadata> physical_metadata) {
-  ATRACE_CALL();
-  std::lock_guard<std::mutex> lock(result_lock_);
-
-  auto metadata_it = pending_final_metadata_.find(frame_number);
-  if (metadata_it == pending_final_metadata_.end()) {
-    ALOGE("[%s] %s: Cannot find the pending result metadata for frame %u",
-          name_.c_str(), __FUNCTION__, frame_number);
-    return NAME_NOT_FOUND;
-  }
-
-  if (metadata_it->second.ready) {
-    ALOGE("[%s] %s: Already received final result metadata for frame %u.",
-          name_.c_str(), __FUNCTION__, frame_number);
-    return ALREADY_EXISTS;
-  }
-
-  metadata_it->second.metadata = std::move(final_metadata);
-  metadata_it->second.physical_metadata = std::move(physical_metadata);
-  metadata_it->second.ready = true;
-  return OK;
-}
-
 status_t ResultDispatcher::AddResultMetadata(
     uint32_t frame_number, std::unique_ptr<HalCameraMetadata> metadata,
     std::vector<PhysicalCameraMetadata> physical_metadata,
@@ -396,22 +346,21 @@ status_t ResultDispatcher::AddResultMetadata(
     return BAD_VALUE;
   }
 
-  if (partial_result < kPartialResultCount) {
-    // Send out partial results immediately.
-    std::vector<std::unique_ptr<CaptureResult>> results;
-    results.push_back(MakeResultMetadata(frame_number, std::move(metadata),
-                                         std::move(physical_metadata),
-                                         partial_result));
-    NotifyCaptureResults(std::move(results));
-    return OK;
-  }
-
-  return AddFinalResultMetadata(frame_number, std::move(metadata),
-                                std::move(physical_metadata));
-}
-
-status_t ResultDispatcher::AddBuffer(uint32_t frame_number,
-                                     StreamBuffer buffer) {
+  std::lock_guard<std::mutex> lock(result_lock_);
+  DispatchQueue<PendingResultMetadata>& queue =
+      partial_result < kPartialResultCount ? pending_early_metadata_
+                                           : pending_final_metadata_;
+  return queue.AddResult(frame_number,
+                         PendingResultMetadata{
+                             .metadata = std::move(metadata),
+                             .physical_metadata = std::move(physical_metadata),
+                             .partial_result_count = partial_result,
+                             .ready = true,
+                         });
+}
+
+status_t ResultDispatcher::AddBuffer(uint32_t frame_number, StreamBuffer buffer,
+                                     bool is_input) {
   ATRACE_CALL();
   std::lock_guard<std::mutex> lock(result_lock_);
 
@@ -423,25 +372,12 @@ status_t ResultDispatcher::AddBuffer(uint32_t frame_number,
     return NAME_NOT_FOUND;
   }
 
-  auto pending_buffer_it = pending_buffers_it->second.find(frame_number);
-  if (pending_buffer_it == pending_buffers_it->second.end()) {
-    ALOGE("[%s] %s: Cannot find the pending buffer for stream %s for frame %u",
-          name_.c_str(), __FUNCTION__, DumpStreamKey(stream_key).c_str(),
-          frame_number);
-    return NAME_NOT_FOUND;
-  }
-
-  if (pending_buffer_it->second.ready) {
-    ALOGE("[%s] %s: Already received a buffer for stream %s for frame %u",
-          name_.c_str(), __FUNCTION__, DumpStreamKey(stream_key).c_str(),
-          frame_number);
-    return ALREADY_EXISTS;
-  }
-
-  pending_buffer_it->second.buffer = std::move(buffer);
-  pending_buffer_it->second.ready = true;
-
-  return OK;
+  return pending_buffers_it->second.AddResult(frame_number,
+                                              PendingBuffer{
+                                                  .buffer = buffer,
+                                                  .is_input = is_input,
+                                                  .ready = true,
+                                              });
 }
 
 void ResultDispatcher::NotifyCallbackThreadLoop() {
@@ -453,7 +389,7 @@ void ResultDispatcher::NotifyCallbackThreadLoop() {
 
   while (1) {
     NotifyShutters();
-    NotifyFinalResultMetadata();
+    NotifyResultMetadata();
     NotifyBuffers();
 
     std::unique_lock<std::mutex> lock(notify_callback_lock_);
@@ -475,22 +411,12 @@ void ResultDispatcher::NotifyCallbackThreadLoop() {
 
 void ResultDispatcher::PrintTimeoutMessages() {
   std::lock_guard<std::mutex> lock(result_lock_);
-  for (auto& [frame_number, shutter] : pending_shutters_) {
-    ALOGW("[%s] %s: pending shutter for frame %u ready %d", name_.c_str(),
-          __FUNCTION__, frame_number, shutter.ready);
-  }
-
-  for (auto& [frame_number, final_metadata] : pending_final_metadata_) {
-    ALOGW("[%s] %s: pending final result metadaata for frame %u ready %d",
-          name_.c_str(), __FUNCTION__, frame_number, final_metadata.ready);
-  }
+  pending_shutters_.PrintTimeoutMessages();
+  pending_early_metadata_.PrintTimeoutMessages();
+  pending_final_metadata_.PrintTimeoutMessages();
 
   for (auto& [stream_key, pending_buffers] : stream_pending_buffers_map_) {
-    for (auto& [frame_number, pending_buffer] : pending_buffers) {
-      ALOGW("[%s] %s: pending buffer of stream %s for frame %u ready %d",
-            name_.c_str(), __FUNCTION__, DumpStreamKey(stream_key).c_str(),
-            frame_number, pending_buffer.ready);
-    }
+    pending_buffers.PrintTimeoutMessages();
   }
 }
 
@@ -525,37 +451,23 @@ std::string ResultDispatcher::DumpStreamKey(const StreamKey& stream_key) const {
   }
 }
 
-status_t ResultDispatcher::GetReadyShutterMessage(NotifyMessage* message) {
-  ATRACE_CALL();
-  if (message == nullptr) {
-    ALOGE("[%s] %s: message is nullptr", name_.c_str(), __FUNCTION__);
-    return BAD_VALUE;
-  }
-
-  auto shutter_it = pending_shutters_.begin();
-  if (shutter_it == pending_shutters_.end() || !shutter_it->second.ready) {
-    // The first pending shutter is not ready.
-    return NAME_NOT_FOUND;
-  }
-
-  message->type = MessageType::kShutter;
-  message->message.shutter.frame_number = shutter_it->first;
-  message->message.shutter.timestamp_ns = shutter_it->second.timestamp_ns;
-  message->message.shutter.readout_timestamp_ns =
-      shutter_it->second.readout_timestamp_ns;
-  pending_shutters_.erase(shutter_it);
-
-  return OK;
-}
-
 void ResultDispatcher::NotifyShutters() {
   ATRACE_CALL();
   NotifyMessage message = {};
+  // TODO: b/347771898 - Update to not depend on running faster than data is
+  // ready
   while (true) {
+    uint32_t frame_number = 0;
+    PendingShutter pending_shutter;
     std::lock_guard<std::mutex> lock(result_lock_);
-    if (GetReadyShutterMessage(&message) != OK) {
+    if (pending_shutters_.GetReadyData(frame_number, pending_shutter) != OK) {
       break;
     }
+    message.type = MessageType::kShutter;
+    message.message.shutter.frame_number = frame_number;
+    message.message.shutter.timestamp_ns = pending_shutter.timestamp_ns;
+    message.message.shutter.readout_timestamp_ns =
+        pending_shutter.readout_timestamp_ns;
     ALOGV("[%s] %s: Notify shutter for frame %u timestamp %" PRIu64
           " readout_timestamp %" PRIu64,
           name_.c_str(), __FUNCTION__, message.message.shutter.frame_number,
@@ -578,70 +490,45 @@ void ResultDispatcher::NotifyCaptureResults(
   }
 }
 
-status_t ResultDispatcher::GetReadyFinalMetadata(
-    uint32_t* frame_number, std::unique_ptr<HalCameraMetadata>* final_metadata,
-    std::vector<PhysicalCameraMetadata>* physical_metadata) {
+void ResultDispatcher::NotifyResultMetadata() {
   ATRACE_CALL();
-  if (final_metadata == nullptr || frame_number == nullptr) {
-    ALOGE("[%s] %s: final_metadata (%p) or frame_number (%p) is nullptr",
-          name_.c_str(), __FUNCTION__, final_metadata, frame_number);
-    return BAD_VALUE;
-  }
-
-  std::lock_guard<std::mutex> lock(result_lock_);
-
-  auto final_metadata_it = pending_final_metadata_.begin();
-  if (final_metadata_it == pending_final_metadata_.end() ||
-      !final_metadata_it->second.ready) {
-    // The first pending final metadata is not ready.
-    return NAME_NOT_FOUND;
-  }
-
-  *frame_number = final_metadata_it->first;
-  *final_metadata = std::move(final_metadata_it->second.metadata);
-  *physical_metadata = std::move(final_metadata_it->second.physical_metadata);
-  pending_final_metadata_.erase(final_metadata_it);
-
-  return OK;
-}
+  uint32_t frame_number = 0;
+  std::vector<std::unique_ptr<CaptureResult>> early_results;
+  std::vector<std::unique_ptr<CaptureResult>> final_results;
+  PendingResultMetadata early_result_metadata;
+  PendingResultMetadata final_result_metadata;
+  // TODO: b/347771898 - Assess if notify can hold the lock for less time
+  {
+    std::lock_guard<std::mutex> lock(result_lock_);
+    while (pending_early_metadata_.GetReadyData(frame_number,
+                                                early_result_metadata) == OK) {
+      ALOGV("[%s] %s: Notify early metadata for frame %u", name_.c_str(),
+            __FUNCTION__, frame_number);
+      early_results.push_back(MakeResultMetadata(
+          frame_number, std::move(early_result_metadata.metadata),
+          std::move(early_result_metadata.physical_metadata),
+          early_result_metadata.partial_result_count));
+    }
 
-void ResultDispatcher::NotifyBatchPartialResultMetadata(
-    std::vector<std::unique_ptr<CaptureResult>>& results) {
-  ATRACE_CALL();
-  std::vector<std::unique_ptr<CaptureResult>> metadata_results;
-  for (auto& result : results) {
-    if (result->result_metadata != nullptr &&
-        result->partial_result < kPartialResultCount) {
-      ALOGV("[%s] %s: Notify partial metadata for frame %u, result count %u",
-            name_.c_str(), __FUNCTION__, result->frame_number,
-            result->partial_result);
-      metadata_results.push_back(MakeResultMetadata(
-          result->frame_number, std::move(result->result_metadata),
-          std::move(result->physical_metadata), result->partial_result));
+    while (pending_final_metadata_.GetReadyData(frame_number,
+                                                final_result_metadata) == OK) {
+      ALOGV("[%s] %s: Notify final metadata for frame %u", name_.c_str(),
+            __FUNCTION__, frame_number);
+      // Removes the pending early metadata if it exists, in case the HAL only
+      // sent the final metadata
+      pending_early_metadata_.RemoveRequest(frame_number);
+
+      final_results.push_back(MakeResultMetadata(
+          frame_number, std::move(final_result_metadata.metadata),
+          std::move(final_result_metadata.physical_metadata),
+          final_result_metadata.partial_result_count));
     }
   }
-  if (!metadata_results.empty()) {
-    NotifyCaptureResults(std::move(metadata_results));
+  if (!early_results.empty()) {
+    NotifyCaptureResults(std::move(early_results));
   }
-}
-
-void ResultDispatcher::NotifyFinalResultMetadata() {
-  ATRACE_CALL();
-  uint32_t frame_number;
-  std::unique_ptr<HalCameraMetadata> final_metadata;
-  std::vector<PhysicalCameraMetadata> physical_metadata;
-  std::vector<std::unique_ptr<CaptureResult>> results;
-
-  while (GetReadyFinalMetadata(&frame_number, &final_metadata,
-                               &physical_metadata) == OK) {
-    ALOGV("[%s] %s: Notify final metadata for frame %u", name_.c_str(),
-          __FUNCTION__, frame_number);
-    results.push_back(
-        MakeResultMetadata(frame_number, std::move(final_metadata),
-                           std::move(physical_metadata), kPartialResultCount));
-  }
-  if (!results.empty()) {
-    NotifyCaptureResults(std::move(results));
+  if (!final_results.empty()) {
+    NotifyCaptureResults(std::move(final_results));
   }
 }
 
@@ -657,23 +544,18 @@ status_t ResultDispatcher::GetReadyBufferResult(
   *result = nullptr;
 
   for (auto& pending_buffers : stream_pending_buffers_map_) {
-    auto buffer_it = pending_buffers.second.begin();
-    while (buffer_it != pending_buffers.second.end()) {
-      if (!buffer_it->second.ready) {
-        // No more buffer ready.
-        break;
-      }
-
-      auto buffer_result = std::make_unique<CaptureResult>(CaptureResult({}));
-
-      buffer_result->frame_number = buffer_it->first;
-      if (buffer_it->second.is_input) {
-        buffer_result->input_buffers.push_back(buffer_it->second.buffer);
+    uint32_t frame_number = 0;
+    PendingBuffer buffer_data;
+    if (pending_buffers.second.GetReadyData(frame_number, buffer_data) == OK) {
+      std::unique_ptr<CaptureResult> buffer_result =
+          std::make_unique<CaptureResult>(CaptureResult({}));
+
+      buffer_result->frame_number = frame_number;
+      if (buffer_data.is_input) {
+        buffer_result->input_buffers.push_back(buffer_data.buffer);
       } else {
-        buffer_result->output_buffers.push_back(buffer_it->second.buffer);
+        buffer_result->output_buffers.push_back(buffer_data.buffer);
       }
-
-      pending_buffers.second.erase(buffer_it);
       *result = std::move(buffer_result);
       return OK;
     }
@@ -687,6 +569,8 @@ void ResultDispatcher::NotifyBuffers() {
   std::vector<std::unique_ptr<CaptureResult>> results;
   std::unique_ptr<CaptureResult> result;
 
+  // TODO: b/347771898 - Update to not depend on running faster than data is
+  // ready
   while (GetReadyBufferResult(&result) == OK) {
     if (result == nullptr) {
       ALOGE("[%s] %s: result is nullptr", name_.c_str(), __FUNCTION__);
@@ -701,5 +585,101 @@ void ResultDispatcher::NotifyBuffers() {
   }
 }
 
+template <typename FrameData>
+ResultDispatcher::DispatchQueue<FrameData>::DispatchQueue(
+    std::string_view dispatcher_name, std::string_view data_name)
+    : dispatcher_name_(dispatcher_name), data_name_(data_name) {
+}
+
+template <typename FrameData>
+status_t ResultDispatcher::DispatchQueue<FrameData>::AddRequest(
+    uint32_t frame_number, RequestType request_type) {
+  if (normal_request_map_.contains(frame_number) ||
+      reprocess_request_map_.contains(frame_number)) {
+    ALOGE("[%s] %s: Pending %s for frame %u already exists.",
+          std::string(dispatcher_name_).c_str(), __FUNCTION__,
+          data_name_.c_str(), frame_number);
+    return ALREADY_EXISTS;
+  }
+  if (request_type == RequestType::kNormal) {
+    normal_request_map_[frame_number] = FrameData();
+  } else {
+    reprocess_request_map_[frame_number] = FrameData();
+  }
+  return OK;
+}
+
+template <typename FrameData>
+void ResultDispatcher::DispatchQueue<FrameData>::RemoveRequest(
+    uint32_t frame_number) {
+  normal_request_map_.erase(frame_number);
+  reprocess_request_map_.erase(frame_number);
+}
+
+template <typename FrameData>
+status_t ResultDispatcher::DispatchQueue<FrameData>::AddResult(
+    uint32_t frame_number, FrameData result) {
+  auto it = normal_request_map_.find(frame_number);
+  if (it == normal_request_map_.end()) {
+    it = reprocess_request_map_.find(frame_number);
+    if (it == reprocess_request_map_.end()) {
+      ALOGE("[%s] %s: Cannot find the pending %s for frame %u",
+            std::string(dispatcher_name_).c_str(), __FUNCTION__,
+            data_name_.c_str(), frame_number);
+      return NAME_NOT_FOUND;
+    }
+  }
+
+  if (it->second.ready) {
+    ALOGE("[%s] %s: Already received %s for frame %u",
+          std::string(dispatcher_name_).c_str(), __FUNCTION__,
+          data_name_.c_str(), frame_number);
+    return ALREADY_EXISTS;
+  }
+
+  it->second = std::move(result);
+  return OK;
+}
+
+template <typename FrameData>
+status_t ResultDispatcher::DispatchQueue<FrameData>::GetReadyData(
+    uint32_t& frame_number, FrameData& ready_data) {
+  auto it = normal_request_map_.begin();
+  if (it != normal_request_map_.end() && it->second.ready) {
+    frame_number = it->first;
+    ready_data = std::move(it->second);
+    normal_request_map_.erase(it);
+    return OK;
+  }
+
+  it = reprocess_request_map_.begin();
+  if (it != reprocess_request_map_.end() && it->second.ready) {
+    frame_number = it->first;
+    ready_data = std::move(it->second);
+    reprocess_request_map_.erase(it);
+    return OK;
+  }
+  // The first pending data is not ready
+  return NAME_NOT_FOUND;
+}
+
+template <typename FrameData>
+void ResultDispatcher::DispatchQueue<FrameData>::PrintTimeoutMessages() {
+  for (auto& [frame_number, pending_data] : normal_request_map_) {
+    ALOGW("[%s] %s: pending %s for frame %u ready %d",
+          std::string(dispatcher_name_).c_str(), __FUNCTION__,
+          data_name_.c_str(), frame_number, pending_data.ready);
+  }
+  for (auto& [frame_number, pending_data] : reprocess_request_map_) {
+    ALOGW("[%s] %s: pending %s for frame %u ready %d",
+          std::string(dispatcher_name_).c_str(), __FUNCTION__,
+          data_name_.c_str(), frame_number, pending_data.ready);
+  }
+}
+template class ResultDispatcher::DispatchQueue<ResultDispatcher::PendingShutter>;
+template class ResultDispatcher::DispatchQueue<ResultDispatcher::PendingBuffer>;
+template class ResultDispatcher::DispatchQueue<
+    ResultDispatcher::PendingResultMetadata>;
+
 }  // namespace google_camera_hal
 }  // namespace android
diff --git a/common/hal/utils/result_dispatcher.h b/common/hal/utils/result_dispatcher.h
index 2f76ad3..33db7a7 100644
--- a/common/hal/utils/result_dispatcher.h
+++ b/common/hal/utils/result_dispatcher.h
@@ -17,6 +17,8 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_UTILS_RESULT_DISPATCHER_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_UTILS_RESULT_DISPATCHER_H_
 
+#include <android-base/thread_annotations.h>
+
 #include <map>
 #include <string>
 #include <string_view>
@@ -58,7 +60,8 @@ class ResultDispatcher {
   // Add a pending request. This tells ResultDispatcher to watch for
   // the shutter, result metadata, and stream buffers for this request,
   // that will be added later via AddResult() and AddShutter().
-  status_t AddPendingRequest(const CaptureRequest& pending_request);
+  status_t AddPendingRequest(const CaptureRequest& pending_request)
+      EXCLUDES(result_lock_);
 
   // Add a ready result. If the result doesn't belong to a pending request that
   // was previously added via AddPendingRequest(), an error will be returned.
@@ -71,14 +74,14 @@ class ResultDispatcher {
   // pending request that was previously added via AddPendingRequest(), an error
   // will be returned.
   status_t AddShutter(uint32_t frame_number, int64_t timestamp_ns,
-                      int64_t readout_timestamp_ns);
+                      int64_t readout_timestamp_ns) EXCLUDES(result_lock_);
 
   // Add an error notification for a frame number. When this is called, we no
   // longer wait for a shutter message or result metadata for the given frame.
-  status_t AddError(const ErrorMessage& error);
+  status_t AddError(const ErrorMessage& error) EXCLUDES(result_lock_);
 
   // Remove a pending request.
-  void RemovePendingRequest(uint32_t frame_number);
+  void RemovePendingRequest(uint32_t frame_number) EXCLUDES(result_lock_);
 
   ResultDispatcher(uint32_t partial_result_count,
                    ProcessCaptureResultFunc process_capture_result,
@@ -90,6 +93,13 @@ class ResultDispatcher {
   static constexpr uint32_t kCallbackThreadTimeoutMs = 500;
   const uint32_t kPartialResultCount;
 
+  // Define the request types. Normal is for general application.
+  // Reprocess is for reprocessing requests.
+  enum class RequestType : uint32_t {
+    kNormal = 0,
+    kReprocess,
+  };
+
   // Define the stream key types. Single stream type is for normal streams.
   // Group stream type is for the group streams of multi-resolution streams.
   enum class StreamKeyType : uint32_t {
@@ -114,37 +124,75 @@ class ResultDispatcher {
     bool ready = false;
   };
 
-  // Define a pending buffer that will be ready later when AddResult() is called.
+  // Define a pending buffer that will be ready later when AddResult() is
+  // called.
   struct PendingBuffer {
     StreamBuffer buffer = {};
     bool is_input = false;
     bool ready = false;
   };
 
-  // Define a pending final result metadata that will be ready later when
-  // AddResult() is called.
-  struct PendingFinalResultMetadata {
+  // Define a pending result metadata that will be ready later when AddResult()
+  // is called.
+  struct PendingResultMetadata {
     std::unique_ptr<HalCameraMetadata> metadata;
     std::vector<PhysicalCameraMetadata> physical_metadata;
+    uint32_t partial_result_count = 0;
     bool ready = false;
   };
 
-  // Add a pending request for a frame. Must be protected with result_lock_.
-  status_t AddPendingRequestLocked(const CaptureRequest& pending_request);
-
-  // Add a pending shutter for a frame. Must be protected with result_lock_.
-  status_t AddPendingShutterLocked(uint32_t frame_number);
+  // Template class for pending data queues.
+  // Pending data can be shutter, early/final result metadata, buffer, and each
+  // type of data has its own queue. Handles having multiple queues per request
+  // type, adds to the appropriate queue and checks all queues for ready data.
+  template <typename FrameData>
+  class DispatchQueue {
+   public:
+    DispatchQueue(std::string_view dispatcher_name = "DefaultDispatcher",
+                  std::string_view data_name = "DefaultData");
+
+    // Add a request to the dispatch queue that will later be populated with
+    // results.
+    status_t AddRequest(uint32_t frame_number, RequestType request_type);
+
+    // Remove request for frame number from data queue
+    void RemoveRequest(uint32_t frame_number);
+
+    // Add results for the request in the queue of the same frame number
+    status_t AddResult(uint32_t frame_number, FrameData result);
+
+    // Move ready data to caller, returns failure status if no data is ready
+    // Data is ready if its result has been added and is the first in its queue
+    status_t GetReadyData(uint32_t& frame_number, FrameData& ready_data);
+
+    void PrintTimeoutMessages();
+
+   private:
+    // Name of the dispatcher for debug messages
+    std::string_view dispatcher_name_;
+    // Name of the data (shutter, metadata, buffer + stream key) for debug
+    // messages
+    std::string data_name_;
+
+    // Queue for data of reprocess request types
+    std::map<uint32_t, FrameData> reprocess_request_map_;
+    // Queue for data of normal request types
+    std::map<uint32_t, FrameData> normal_request_map_;
+  };
 
-  // Add a pending final metadata for a frame. Must be protected with
-  // result_lock_.
-  status_t AddPendingFinalResultMetadataLocked(uint32_t frame_number);
+  // Add a pending shutter, result metadata, and buffers for a frame number.
+  status_t AddPendingRequestLocked(const CaptureRequest& pending_request)
+      EXCLUSIVE_LOCKS_REQUIRED(result_lock_);
 
-  // Add a pending buffer for a frame. Must be protected with result_lock_.
+  // Add a pending buffer for the associated stream
   status_t AddPendingBufferLocked(uint32_t frame_number,
-                                  const StreamBuffer& buffer, bool is_input);
+                                  const StreamBuffer& buffer,
+                                  RequestType request_type)
+      EXCLUSIVE_LOCKS_REQUIRED(result_lock_);
 
   // Remove pending shutter, result metadata, and buffers for a frame number.
-  void RemovePendingRequestLocked(uint32_t frame_number);
+  void RemovePendingRequestLocked(uint32_t frame_number)
+      EXCLUSIVE_LOCKS_REQUIRED(result_lock_);
 
   // Add result metadata and buffers to the storage to send them from the notify
   // callback thread.
@@ -159,39 +207,26 @@ class ResultDispatcher {
   // Invoke the capture result callback to notify capture results.
   void NotifyCaptureResults(std::vector<std::unique_ptr<CaptureResult>> results);
 
-  status_t AddFinalResultMetadata(
-      uint32_t frame_number, std::unique_ptr<HalCameraMetadata> final_metadata,
-      std::vector<PhysicalCameraMetadata> physical_metadata);
-
   status_t AddResultMetadata(
       uint32_t frame_number, std::unique_ptr<HalCameraMetadata> metadata,
       std::vector<PhysicalCameraMetadata> physical_metadata,
-      uint32_t partial_result);
+      uint32_t partial_result) EXCLUDES(result_lock_);
+  ;
 
-  status_t AddBuffer(uint32_t frame_number, StreamBuffer buffer);
+  status_t AddBuffer(uint32_t frame_number, StreamBuffer buffer, bool is_input)
+      EXCLUDES(result_lock_);
 
-  // Get a shutter message that is ready to be notified via notify_.
-  status_t GetReadyShutterMessage(NotifyMessage* message);
+  // Check all pending shutters and invoke notify_ with shutters that are ready.
+  void NotifyShutters() EXCLUDES(result_lock_);
 
-  // Get a final metadata that is ready to be notified via the capture result callback.
-  status_t GetReadyFinalMetadata(
-      uint32_t* frame_number, std::unique_ptr<HalCameraMetadata>* final_metadata,
-      std::vector<PhysicalCameraMetadata>* physical_metadata);
+  // Check all pending result metadata and invoke the capture result callback
+  // with the result metadata that are ready.
+  void NotifyResultMetadata() EXCLUDES(result_lock_);
 
   // Get a result with a buffer that is ready to be notified via the capture
   // result callback.
-  status_t GetReadyBufferResult(std::unique_ptr<CaptureResult>* result);
-
-  // Check all pending shutters and invoke notify_ with shutters that are ready.
-  void NotifyShutters();
-
-  // Send partial result callbacks if `results` contains partial result metadata.
-  void NotifyBatchPartialResultMetadata(
-      std::vector<std::unique_ptr<CaptureResult>>& results);
-
-  // Check all pending final result metadata and invoke the capture result
-  // callback with final result metadata that are ready.
-  void NotifyFinalResultMetadata();
+  status_t GetReadyBufferResult(std::unique_ptr<CaptureResult>* result)
+      EXCLUDES(result_lock_);
 
   // Check all pending buffers and invoke notify_ with buffers that are ready.
   void NotifyBuffers();
@@ -200,19 +235,36 @@ class ResultDispatcher {
   // notifies the client when one is ready.
   void NotifyCallbackThreadLoop();
 
-  void PrintTimeoutMessages();
+  void PrintTimeoutMessages() EXCLUDES(result_lock_);
 
-  // Initialize the group stream ids map if needed. Must be protected with result_lock_.
-  void InitializeGroupStreamIdsMap(const StreamConfiguration& stream_config);
+  // Initialize the group stream ids map if needed. Must be protected with
+  // result_lock_.
+  void InitializeGroupStreamIdsMap(const StreamConfiguration& stream_config)
+      EXCLUDES(result_lock_);
 
   // Name used for debugging purpose to disambiguate multiple ResultDispatchers.
   std::string name_;
 
   std::mutex result_lock_;
 
-  // Maps from frame numbers to pending shutters.
+  // Queue for shutter data.
+  DispatchQueue<PendingShutter> pending_shutters_ GUARDED_BY(result_lock_);
+  // Queue for early result metadata.
+  DispatchQueue<PendingResultMetadata> pending_early_metadata_
+      GUARDED_BY(result_lock_);
+  // Queue for final result metadata.
+  DispatchQueue<PendingResultMetadata> pending_final_metadata_
+      GUARDED_BY(result_lock_);
+
+  // Maps from a stream or stream group to a queue for buffer data.
   // Protected by result_lock_.
-  std::map<uint32_t, PendingShutter> pending_shutters_;
+  // For single streams, pending buffers would be tracked by streams.
+  // For multi-resolution streams, camera HAL can return only one stream buffer
+  // within the same stream group each request. So all of the buffers of certain
+  // stream group will be tracked together via a single map.
+  // TODO: b/347771069 - Update to use unordered_map
+  std::map<StreamKey, DispatchQueue<PendingBuffer>> stream_pending_buffers_map_
+      GUARDED_BY(result_lock_);
 
   // Create a StreamKey for a stream
   inline StreamKey CreateStreamKey(int32_t stream_id) const;
@@ -220,19 +272,6 @@ class ResultDispatcher {
   // Dump a StreamKey to a debug string
   inline std::string DumpStreamKey(const StreamKey& stream_key) const;
 
-  // Maps from a stream or a stream group to "a map from a frame number to a
-  // pending buffer". Protected by result_lock_.
-  // For single streams, pending buffers would be tracked by streams.
-  // For multi-resolution streams, camera HAL can return only one stream buffer
-  // within the same stream group each request. So all of the buffers of certain
-  // stream group will be tracked together via a single map.
-  std::map<StreamKey, std::map<uint32_t, PendingBuffer>>
-      stream_pending_buffers_map_;
-
-  // Maps from a stream ID to pending result metadata.
-  // Protected by result_lock_.
-  std::map<uint32_t, PendingFinalResultMetadata> pending_final_metadata_;
-
   std::mutex process_capture_result_lock_;
   ProcessCaptureResultFunc process_capture_result_;
   ProcessBatchCaptureResultFunc process_batch_capture_result_;
@@ -243,7 +282,8 @@ class ResultDispatcher {
 
   std::mutex notify_callback_lock_;
 
-  // Condition to wake up notify_callback_thread_. Used with notify_callback_lock.
+  // Condition to wake up notify_callback_thread_. Used with
+  // notify_callback_lock.
   std::condition_variable notify_callback_condition_;
 
   // Protected by notify_callback_lock.
diff --git a/devices/EmulatedCamera/hwl/Android.bp b/devices/EmulatedCamera/hwl/Android.bp
index 62edc35..5269daf 100644
--- a/devices/EmulatedCamera/hwl/Android.bp
+++ b/devices/EmulatedCamera/hwl/Android.bp
@@ -50,6 +50,7 @@ cc_defaults {
         "libui",
         "libutils",
         "libyuv",
+        "libultrahdr",
     ],
     static_libs: [
         "android.hardware.camera.common@1.0-helper",
@@ -82,6 +83,7 @@ cc_library_static {
     owner: "google",
     proprietary: true,
     host_supported: true,
+    defaults: ["android.hardware.graphics.common-ndk_shared"],
 
     srcs: [
         "EmulatedScene.cpp",
@@ -103,6 +105,7 @@ cc_library_static {
         "libjpeg",
         "liblog",
         "libyuv",
+        "libultrahdr",
     ],
 
     static_libs: [
diff --git a/devices/EmulatedCamera/hwl/Base.h b/devices/EmulatedCamera/hwl/Base.h
index bb7fb81..cca525e 100644
--- a/devices/EmulatedCamera/hwl/Base.h
+++ b/devices/EmulatedCamera/hwl/Base.h
@@ -21,6 +21,7 @@
 
 #include <memory>
 
+#include "aidl/android/hardware/graphics/common/Dataspace.h"
 #include "android/hardware/graphics/common/1.1/types.h"
 #include "hwl_types.h"
 
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.cpp b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.cpp
index 6fd880c..bc99bbf 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.cpp
@@ -182,6 +182,10 @@ status_t EmulatedCameraDeviceHwlImpl::GetPhysicalCameraCharacteristics(
   return OK;
 }
 
+google_camera_hal::HwlMemoryConfig EmulatedCameraDeviceHwlImpl::GetMemoryConfig() const {
+  return HwlMemoryConfig();
+}
+
 status_t EmulatedCameraDeviceHwlImpl::SetTorchMode(TorchMode mode) {
   if (torch_state_.get() == nullptr) {
     return INVALID_OPERATION;
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.h b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.h
index e52da22..cddf9a5 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.h
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceHWLImpl.h
@@ -35,6 +35,7 @@ using google_camera_hal::CameraDeviceHwl;
 using google_camera_hal::CameraDeviceSessionHwl;
 using google_camera_hal::CameraResourceCost;
 using google_camera_hal::HalCameraMetadata;
+using google_camera_hal::HwlMemoryConfig;
 using google_camera_hal::kTemplateCount;
 using google_camera_hal::RequestTemplate;
 using google_camera_hal::StreamConfiguration;
@@ -67,6 +68,8 @@ class EmulatedCameraDeviceHwlImpl : public CameraDeviceHwl {
       uint32_t physical_camera_id,
       std::unique_ptr<HalCameraMetadata>* characteristics) const override;
 
+  HwlMemoryConfig GetMemoryConfig() const override;
+
   status_t SetTorchMode(TorchMode mode) override;
 
   status_t TurnOnTorchWithStrengthLevel(int32_t torch_strength) override;
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.cpp b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.cpp
index ead2ea1..4ac0350 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.cpp
@@ -183,7 +183,8 @@ status_t EmulatedCameraDeviceSessionHwlImpl::Initialize(
   logical_chars_.emplace(camera_id_, sensor_chars_);
   for (const auto& it : *physical_device_map_) {
     SensorCharacteristics physical_chars;
-    auto stat = GetSensorCharacteristics(it.second.second.get(), &physical_chars);
+    auto stat =
+        GetSensorCharacteristics(it.second.second.get(), &physical_chars);
     if (stat == OK) {
       logical_chars_.emplace(it.first, physical_chars);
     } else {
@@ -277,9 +278,11 @@ status_t EmulatedCameraDeviceSessionHwlImpl::ConfigurePipeline(
   }
 
   *pipeline_id = pipelines_.size();
-  EmulatedPipeline emulated_pipeline{.cb = hwl_pipeline_callback,
-                                     .physical_camera_id = physical_camera_id,
-                                     .pipeline_id = *pipeline_id,};
+  EmulatedPipeline emulated_pipeline{
+      .cb = hwl_pipeline_callback,
+      .physical_camera_id = physical_camera_id,
+      .pipeline_id = *pipeline_id,
+  };
 
   emulated_pipeline.streams.reserve(request_config.streams.size());
   for (const auto& stream : request_config.streams) {
@@ -476,6 +479,10 @@ status_t EmulatedCameraDeviceSessionHwlImpl::Flush() {
   return request_processor_->Flush();
 }
 
+void EmulatedCameraDeviceSessionHwlImpl::RepeatingRequestEnd(
+    int32_t /*frame_number*/, const std::vector<int32_t>& /*stream_ids*/) {
+}
+
 uint32_t EmulatedCameraDeviceSessionHwlImpl::GetCameraId() const {
   return camera_id_;
 }
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.h b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.h
index 00b5daa..60f8ea1 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.h
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceSessionHWLImpl.h
@@ -21,6 +21,7 @@
 
 #include <memory>
 #include <set>
+#include <vector>
 
 #include "EmulatedCameraDeviceHWLImpl.h"
 #include "EmulatedRequestProcessor.h"
@@ -128,6 +129,9 @@ class EmulatedCameraDeviceSessionHwlImpl : public CameraDeviceSessionHwl {
 
   status_t Flush() override;
 
+  void RepeatingRequestEnd(int32_t frame_number,
+                           const std::vector<int32_t>& stream_ids) override;
+
   uint32_t GetCameraId() const override;
 
   std::vector<uint32_t> GetPhysicalCameraIds() const override;
@@ -139,9 +143,7 @@ class EmulatedCameraDeviceSessionHwlImpl : public CameraDeviceSessionHwl {
       uint32_t physical_camera_id,
       std::unique_ptr<HalCameraMetadata>* characteristics) const override;
 
-  status_t SetSessionData(SessionDataKey /*key*/
-                                    ,
-                                    void* /*value*/) override {
+  status_t SetSessionData(SessionDataKey /*key*/, void* /*value*/) override {
     return OK;
   }  // Noop for now
 
diff --git a/devices/EmulatedCamera/hwl/EmulatedRequestProcessor.cpp b/devices/EmulatedCamera/hwl/EmulatedRequestProcessor.cpp
index 570b840..f3454f2 100644
--- a/devices/EmulatedCamera/hwl/EmulatedRequestProcessor.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedRequestProcessor.cpp
@@ -266,7 +266,10 @@ status_t EmulatedRequestProcessor::GetBufferSizeAndStride(
       }
       break;
     case HAL_PIXEL_FORMAT_BLOB:
-      if (stream.override_data_space == HAL_DATASPACE_V0_JFIF) {
+      if (stream.override_data_space == HAL_DATASPACE_V0_JFIF ||
+          stream.override_data_space ==
+              static_cast<android_dataspace_t>(
+                  aidl::android::hardware::graphics::common::Dataspace::JPEG_R)) {
         *size = stream.buffer_size;
         *stride = *size;
       } else {
diff --git a/devices/EmulatedCamera/hwl/EmulatedSensor.cpp b/devices/EmulatedCamera/hwl/EmulatedSensor.cpp
index f39799a..35b19c1 100644
--- a/devices/EmulatedCamera/hwl/EmulatedSensor.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedSensor.cpp
@@ -475,6 +475,9 @@ bool EmulatedSensor::IsStreamCombinationSupported(
       switch (stream.format) {
         case HAL_PIXEL_FORMAT_BLOB:
           if ((stream.data_space != HAL_DATASPACE_V0_JFIF) &&
+              (stream.data_space !=
+               static_cast<android_dataspace_t>(
+                   aidl::android::hardware::graphics::common::Dataspace::JPEG_R)) &&
               (stream.data_space != HAL_DATASPACE_UNKNOWN)) {
             ALOGE("%s: Unsupported Blob dataspace 0x%x", __FUNCTION__,
                   stream.data_space);
@@ -528,10 +531,10 @@ bool EmulatedSensor::IsStreamCombinationSupported(
           is_dynamic_output
               ? physical_map.at(stream.physical_camera_id)
                     ->GetDynamicPhysicalStreamOutputSizes(stream.format)
-              : stream.is_physical_camera_stream
-                    ? physical_map.at(stream.physical_camera_id)
-                          ->GetOutputSizes(stream.format)
-                    : config_map.GetOutputSizes(stream.format);
+          : stream.is_physical_camera_stream
+              ? physical_map.at(stream.physical_camera_id)
+                    ->GetOutputSizes(stream.format, stream.data_space)
+              : config_map.GetOutputSizes(stream.format, stream.data_space);
 
       auto stream_size = std::make_pair(stream.width, stream.height);
       if (output_sizes.find(stream_size) == output_sizes.end()) {
@@ -1108,6 +1111,60 @@ bool EmulatedSensor::threadLoop() {
 
             Mutex::Autolock lock(control_mutex_);
             jpeg_compressor_->QueueYUV420(std::move(jpeg_job));
+          } else if ((*b)->dataSpace == static_cast<android_dataspace_t>(
+                                            aidl::android::hardware::graphics::
+                                                common::Dataspace::JPEG_R)) {
+            if (!reprocess_request) {
+              YUV420Frame yuv_input{};
+              auto jpeg_input = std::make_unique<JpegYUV420Input>();
+              jpeg_input->width = (*b)->width;
+              jpeg_input->height = (*b)->height;
+              jpeg_input->color_space = (*b)->color_space;
+              auto img = new uint8_t[(*b)->width * (*b)->height * 3];
+              jpeg_input->yuv_planes = {
+                  .img_y = img,
+                  .img_cb = img + (*b)->width * (*b)->height * 2,
+                  .img_cr = img + (*b)->width * (*b)->height * 2 + 2,
+                  .y_stride = (*b)->width * 2,
+                  .cbcr_stride = (*b)->width * 2,
+                  .cbcr_step = 2,
+                  .bytesPerPixel = 2};
+              jpeg_input->buffer_owner = true;
+              YUV420Frame yuv_output{.width = jpeg_input->width,
+                                     .height = jpeg_input->height,
+                                     .planes = jpeg_input->yuv_planes};
+
+              bool rotate = device_settings->second.rotate_and_crop ==
+                            ANDROID_SCALER_ROTATE_AND_CROP_90;
+              auto ret = ProcessYUV420(
+                  yuv_input, yuv_output, device_settings->second.gain,
+                  process_type, device_settings->second.zoom_ratio, rotate,
+                  (*b)->color_space, device_chars->second);
+              if (ret != 0) {
+                (*b)->stream_buffer.status = BufferStatus::kError;
+                break;
+              }
+
+              auto jpeg_job = std::make_unique<JpegYUV420Job>();
+              jpeg_job->exif_utils = std::unique_ptr<ExifUtils>(
+                  ExifUtils::Create(device_chars->second));
+              jpeg_job->input = std::move(jpeg_input);
+              // If jpeg compression is successful, then the jpeg compressor
+              // must set the corresponding status.
+              (*b)->stream_buffer.status = BufferStatus::kError;
+              std::swap(jpeg_job->output, *b);
+              jpeg_job->result_metadata =
+                  HalCameraMetadata::Clone(next_result->result_metadata.get());
+
+              Mutex::Autolock lock(control_mutex_);
+              jpeg_compressor_->QueueYUV420(std::move(jpeg_job));
+            } else {
+              ALOGE(
+                  "%s: Reprocess requests with output format JPEG_R are not "
+                  "supported!",
+                  __FUNCTION__);
+              (*b)->stream_buffer.status = BufferStatus::kError;
+            }
           } else {
             ALOGE("%s: Format %x with dataspace %x is TODO", __FUNCTION__,
                   (*b)->format, (*b)->dataSpace);
diff --git a/devices/EmulatedCamera/hwl/JpegCompressor.cpp b/devices/EmulatedCamera/hwl/JpegCompressor.cpp
index c727864..93c2f54 100644
--- a/devices/EmulatedCamera/hwl/JpegCompressor.cpp
+++ b/devices/EmulatedCamera/hwl/JpegCompressor.cpp
@@ -22,6 +22,7 @@
 #include <camera_blob.h>
 #include <cutils/properties.h>
 #include <libyuv.h>
+#include <ultrahdr/jpegr.h>
 #include <utils/Log.h>
 #include <utils/Trace.h>
 
@@ -194,7 +195,10 @@ status_t JpegCompressor::QueueYUV420(std::unique_ptr<JpegYUV420Job> job) {
 
   if ((job->input.get() == nullptr) || (job->output.get() == nullptr) ||
       (job->output->format != PixelFormat::BLOB) ||
-      (job->output->dataSpace != HAL_DATASPACE_V0_JFIF)) {
+      ((job->output->dataSpace !=
+        static_cast<android_dataspace_t>(
+            ::aidl::android::hardware::graphics::common::Dataspace::JPEG_R)) &&
+       (job->output->dataSpace != HAL_DATASPACE_V0_JFIF))) {
     ALOGE("%s: Unable to find buffers for JPEG source/destination",
           __FUNCTION__);
     return BAD_VALUE;
@@ -318,15 +322,22 @@ void JpegCompressor::CompressYUV420(std::unique_ptr<JpegYUV420Job> job) {
     }
   }
 
-  auto encoded_size = CompressYUV420Frame(
-      {.output_buffer = job->output->plane.img.img,
-       .output_buffer_size = job->output->plane.img.buffer_size,
-       .yuv_planes = job->input->yuv_planes,
-       .width = job->input->width,
-       .height = job->input->height,
-       .app1_buffer = app1_buffer,
-       .app1_buffer_size = app1_buffer_size,
-       .color_space = job->input->color_space});
+  size_t encoded_size = 0;
+  YUV420Frame frame = {.output_buffer = job->output->plane.img.img,
+                       .output_buffer_size = job->output->plane.img.buffer_size,
+                       .yuv_planes = job->input->yuv_planes,
+                       .width = job->input->width,
+                       .height = job->input->height,
+                       .app1_buffer = app1_buffer,
+                       .app1_buffer_size = app1_buffer_size,
+                       .color_space = job->input->color_space};
+  if (job->output->dataSpace ==
+      static_cast<android_dataspace_t>(
+          ::aidl::android::hardware::graphics::common::Dataspace::JPEG_R)) {
+    encoded_size = JpegRCompressYUV420Frame(frame);
+  } else {
+    encoded_size = CompressYUV420Frame(frame);
+  }
   if (encoded_size > 0) {
     job->output->stream_buffer.status = BufferStatus::kOk;
   } else {
@@ -348,6 +359,44 @@ void JpegCompressor::CompressYUV420(std::unique_ptr<JpegYUV420Job> job) {
   }
 }
 
+size_t JpegCompressor::JpegRCompressYUV420Frame(YUV420Frame p010_frame) {
+  ATRACE_CALL();
+
+  ultrahdr::jpegr_uncompressed_struct p010;
+  ultrahdr::jpegr_compressed_struct jpeg_r;
+  ultrahdr::JpegR jpeg_r_encoder;
+
+  p010.height = p010_frame.height;
+  p010.width = p010_frame.width;
+  p010.colorGamut = ultrahdr::ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
+  p010.data = p010_frame.yuv_planes.img_y;
+  p010.chroma_data = p010_frame.yuv_planes.img_cb;
+  // Strides are expected to be in pixels not bytes
+  p010.luma_stride = p010_frame.yuv_planes.y_stride / 2;
+  p010.chroma_stride = p010_frame.yuv_planes.cbcr_stride / 2;
+
+  jpeg_r.data = p010_frame.output_buffer;
+  jpeg_r.maxLength = p010_frame.output_buffer_size;
+
+  ultrahdr::ultrahdr_transfer_function transferFunction =
+      ultrahdr::ultrahdr_transfer_function::ULTRAHDR_TF_HLG;
+
+  ultrahdr::jpegr_exif_struct exif;
+  exif.data =
+      reinterpret_cast<void*>(const_cast<uint8_t*>(p010_frame.app1_buffer));
+  exif.length = p010_frame.app1_buffer_size;
+
+  auto res = jpeg_r_encoder.encodeJPEGR(&p010, transferFunction, &jpeg_r,
+                                        /*jpegQuality*/ 100, &exif);
+  if (res != OK) {
+    ALOGE("%s: Error trying to encode JPEG/R: %s (%d)", __FUNCTION__,
+          strerror(-res), res);
+    return 0;
+  }
+
+  return jpeg_r.length;
+}
+
 size_t JpegCompressor::CompressYUV420Frame(YUV420Frame frame) {
   ATRACE_CALL();
 
diff --git a/devices/EmulatedCamera/hwl/JpegCompressor.h b/devices/EmulatedCamera/hwl/JpegCompressor.h
index c373621..e836ca6 100644
--- a/devices/EmulatedCamera/hwl/JpegCompressor.h
+++ b/devices/EmulatedCamera/hwl/JpegCompressor.h
@@ -93,6 +93,7 @@ class JpegCompressor {
     int32_t color_space;
   };
   size_t CompressYUV420Frame(YUV420Frame frame);
+  size_t JpegRCompressYUV420Frame(YUV420Frame p010_frame);
   void ThreadLoop();
 
   JpegCompressor(const JpegCompressor&) = delete;
diff --git a/devices/EmulatedCamera/hwl/apex/Android.bp b/devices/EmulatedCamera/hwl/apex/Android.bp
index b864d72..a2f754f 100644
--- a/devices/EmulatedCamera/hwl/apex/Android.bp
+++ b/devices/EmulatedCamera/hwl/apex/Android.bp
@@ -46,7 +46,6 @@ apex_defaults {
     key: "com.google.emulated.camera.provider.hal.key",
     certificate: ":com.google.emulated.camera.provider.hal.certificate",
     file_contexts: "file_contexts",
-    use_vndk_as_stable: true,
     updatable: false,
     // Install the apex in /vendor/apex
     soc_specific: true,
diff --git a/devices/EmulatedCamera/hwl/apex/com.google.emulated.camera.provider.hal.rc b/devices/EmulatedCamera/hwl/apex/com.google.emulated.camera.provider.hal.rc
index 165c36f..730c62d 100644
--- a/devices/EmulatedCamera/hwl/apex/com.google.emulated.camera.provider.hal.rc
+++ b/devices/EmulatedCamera/hwl/apex/com.google.emulated.camera.provider.hal.rc
@@ -4,7 +4,7 @@ on property:apex.com.google.emulated.camera.provider.hal.ready=true
 
 service vendor.camera-provider-2-7-google /apex/com.google.emulated.camera.provider.hal/bin/hw/android.hardware.camera.provider@2.7-service-google
     class hal
-    user system
+    user cameraserver
     group system
     capabilities SYS_NICE
     rlimit rtprio 10 10
diff --git a/devices/EmulatedCamera/hwl/configs/emu_camera_back.json b/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
index bb7d701..a0ac5e1 100644
--- a/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
+++ b/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
@@ -112,6 +112,45 @@
   "1.0",
   "10.0"
  ],
+ "android.depth.availableDepthMinFrameDurations": [
+  "540422489",
+  "320",
+  "240",
+  "50000000"
+ ],
+ "android.depth.availableDepthStallDurations": [
+  "540422489",
+  "320",
+  "240",
+  "50000000"
+ ],
+ "android.depth.availableDepthStreamConfigurations": [
+  "540422489",
+  "320",
+  "240",
+  "OUTPUT"
+ ],
+ "android.depth.availableDynamicDepthMinFrameDurations": [
+  "33",
+  "320",
+  "240",
+  "50000000"
+ ],
+ "android.depth.availableDynamicDepthStallDurations": [
+  "33",
+  "320",
+  "240",
+  "50000000"
+ ],
+ "android.depth.availableDynamicDepthStreamConfigurations" : [
+  "33",
+  "320",
+  "240",
+  "OUTPUT"
+ ],
+ "android.depth.depthIsExclusive": [
+  "FALSE"
+ ],
  "android.edge.availableEdgeModes": [
   "0",
   "1",
@@ -158,9 +197,37 @@
  "android.jpeg.maxSize": [
   "300000"
  ],
+ "android.lens.distortion": [
+  "0.00000000",
+  "0.00000000",
+  "0.00000000",
+  "0.00000000",
+  "0.00000000"
+ ],
  "android.lens.facing": [
   "BACK"
  ],
+ "android.lens.intrinsicCalibration": [
+  "1914.00000",
+  "1914.00000",
+  "928.000000",
+  "696.000000",
+  "0.00000000"
+ ],
+ "android.lens.poseReference": [
+  "PRIMARY_CAMERA"
+ ],
+ "android.lens.poseRotation": [
+  "1.00000000",
+  "0.00000000",
+  "0.00000000",
+  "0.00000000"
+ ],
+ "android.lens.poseTranslation": [
+  "0.00000000",
+  "0.00000000",
+  "0.00000000"
+ ],
  "android.lens.info.availableApertures": [
   "2.79999995"
  ],
@@ -203,7 +270,8 @@
   "RAW",
   "DYNAMIC_RANGE_TEN_BIT",
   "STREAM_USE_CASE",
-  "COLOR_SPACE_PROFILES"
+  "COLOR_SPACE_PROFILES",
+  "DEPTH_OUTPUT"
  ],
  "android.sensor.referenceIlluminant1": [
   "D50"
@@ -265,7 +333,7 @@
   "2",
   "3",
   "4",
-  "5",
+  "5"
  ],
  "android.reprocess.maxCaptureStall": [
   "2"
@@ -350,7 +418,12 @@
   "917513",
   "1179654",
   "851984",
-  "-2080374781"
+  "-2080374781",
+  "524294",
+  "524298",
+  "524300",
+  "524295",
+  "524301"
  ],
  "android.request.availableRequestKeys": [
   "786435",
@@ -502,7 +575,12 @@
   "1114134",
   "1703939",
   "-2080374783",
-  "-2080374782"
+  "-2080374782",
+  "524294",
+  "524298",
+  "524300",
+  "524295",
+  "524301"
  ],
  "android.request.availableSessionKeys": [
   "786435",
@@ -804,6 +882,10 @@
   "320",
   "240",
   "OUTPUT",
+  "1768253795",
+  "320",
+  "240",
+  "OUTPUT",
   "34",
   "640",
   "480",
diff --git a/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.cpp b/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.cpp
index ce840a4..153552f 100644
--- a/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.cpp
+++ b/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.cpp
@@ -30,6 +30,11 @@ const uint32_t kDepthStreamConfigurations =
 const uint32_t kDepthStreamConfigurationsMaxRes =
     ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
 
+const uint32_t kDynamicDepthStreamConfigurations =
+    ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS;
+const uint32_t kDynamicDepthStreamConfigurationsMaxRes =
+    ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
+
 const uint32_t kScalerMinFrameDurations =
     ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS;
 const uint32_t kScalerMinFrameDurationsMaxRes =
@@ -54,6 +59,9 @@ const uint32_t kDepthStallDurations =
 const uint32_t kDepthStallDurationsMaxRes =
     ANDROID_DEPTH_AVAILABLE_DEPTH_STALL_DURATIONS_MAXIMUM_RESOLUTION;
 
+const uint32_t kJpegRStreamConfigurations =
+    ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS;
+
 void StreamConfigurationMap::AppendAvailableStreamConfigurations(
     const camera_metadata_ro_entry& entry) {
   for (size_t i = 0; i < entry.count; i += kStreamConfigurationSize) {
@@ -137,6 +145,14 @@ StreamConfigurationMap::StreamConfigurationMap(const HalCameraMetadata& chars,
     AppendAvailableStreamConfigurations(entry);
   }
 
+  ret = chars.Get(maxResolution ? kDynamicDepthStreamConfigurations
+                                : kDynamicDepthStreamConfigurationsMaxRes,
+                  &entry);
+
+  if (ret == OK) {
+    AppendAvailableStreamConfigurations(entry);
+  }
+
   ret = chars.Get(
       maxResolution ? kScalerMinFrameDurationsMaxRes : kScalerMinFrameDurations,
       &entry);
@@ -204,6 +220,25 @@ StreamConfigurationMap::StreamConfigurationMap(const HalCameraMetadata& chars,
   if (ret == OK) {
     AppendAvailableDynamicPhysicalStreamConfigurations(entry);
   }
+
+  ret = chars.Get(kJpegRStreamConfigurations, &entry);
+  if (ret == OK) {
+    AppendAvailableJpegRStreamConfigurations(entry);
+  }
 }
 
+void StreamConfigurationMap::AppendAvailableJpegRStreamConfigurations(
+    const camera_metadata_ro_entry& entry) {
+  for (size_t i = 0; i < entry.count; i += kStreamConfigurationSize) {
+    int32_t width = entry.data.i32[i + kStreamWidthOffset];
+    int32_t height = entry.data.i32[i + kStreamHeightOffset];
+    auto format = static_cast<android_pixel_format_t>(
+        entry.data.i32[i + kStreamFormatOffset]);
+    int32_t isInput = entry.data.i32[i + kStreamIsInputOffset];
+    if (!isInput) {
+      jpegr_stream_output_size_map_[format].insert(
+          std::make_pair(width, height));
+    }
+  }
+}
 }  // namespace android
diff --git a/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.h b/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.h
index f359f6a..6aafb7b 100644
--- a/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.h
+++ b/devices/EmulatedCamera/hwl/utils/StreamConfigurationMap.h
@@ -17,6 +17,8 @@
 #ifndef EMULATOR_STREAM_CONFIGURATION_MAP_H_
 #define EMULATOR_STREAM_CONFIGURATION_MAP_H_
 
+#include <Base.h>
+
 #include <memory>
 #include <set>
 #include <unordered_map>
@@ -61,7 +63,16 @@ class StreamConfigurationMap {
     return stream_output_formats_;
   }
 
-  const std::set<StreamSize>& GetOutputSizes(android_pixel_format_t format) {
+  const std::set<StreamSize>& GetOutputSizes(
+      android_pixel_format_t format,
+      android_dataspace_t dataSpace = HAL_DATASPACE_UNKNOWN) {
+    if ((format == HAL_PIXEL_FORMAT_BLOB) &&
+        (dataSpace ==
+         static_cast<android_dataspace_t>(
+             aidl::android::hardware::graphics::common::Dataspace::JPEG_R))) {
+      return jpegr_stream_output_size_map_[format];
+    }
+
     return stream_output_size_map_[format];
   }
 
@@ -104,6 +115,8 @@ class StreamConfigurationMap {
       const camera_metadata_ro_entry& entry);
   void AppendAvailableStreamMinDurations(const camera_metadata_ro_entry_t& entry);
   void AppendAvailableStreamStallDurations(const camera_metadata_ro_entry& entry);
+  void AppendAvailableJpegRStreamConfigurations(
+      const camera_metadata_ro_entry_t& entry);
 
   const size_t kStreamFormatOffset = 0;
   const size_t kStreamWidthOffset = 1;
@@ -127,6 +140,8 @@ class StreamConfigurationMap {
   std::set<android_pixel_format_t> dynamic_physical_stream_output_formats_;
   std::unordered_map<android_pixel_format_t, std::set<StreamSize>>
       dynamic_physical_stream_output_size_map_;
+  std::unordered_map<android_pixel_format_t, std::set<StreamSize>>
+      jpegr_stream_output_size_map_;
 };
 
 typedef std::unordered_map<uint32_t, std::unique_ptr<StreamConfigurationMap>>
```

