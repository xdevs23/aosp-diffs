```diff
diff --git a/common/apex_update_listener/apex_update_listener.cc b/common/apex_update_listener/apex_update_listener.cc
index 24f38bc..d450c65 100644
--- a/common/apex_update_listener/apex_update_listener.cc
+++ b/common/apex_update_listener/apex_update_listener.cc
@@ -147,6 +147,7 @@ void ApexUpdateListener::ThreadFunction() {
   // Maximum number of events to read at a time
   constexpr int event_number = 16;
   std::vector<struct inotify_event> events(event_number);
+  pthread_setname_np(pthread_self(), "ApexListener");
   do {
     auto length = read(file_descriptor_, events.data(),
                        event_number * sizeof(inotify_event));
diff --git a/common/hal/aidl_service/aidl_service.cc b/common/hal/aidl_service/aidl_service.cc
index 2739f46..8cbb352 100644
--- a/common/hal/aidl_service/aidl_service.cc
+++ b/common/hal/aidl_service/aidl_service.cc
@@ -31,6 +31,7 @@
 #include <utils/Errors.h>
 
 #include <cinttypes>
+#include <ctime>
 
 #include "aidl_camera_build_version.h"
 #include "aidl_camera_provider.h"
@@ -48,6 +49,8 @@ const std::string kProviderInstance = "/internal/0";
 
 int main() {
   ALOGI("Google camera provider service is starting.");
+  timespec start_time;
+  clock_gettime(CLOCK_BOOTTIME, &start_time);
   mallopt(M_DECAY_TIME, 1);
   android::hardware::configureRpcThreadpool(/*maxThreads=*/6,
                                             /*callerWillJoin=*/true);
@@ -98,6 +101,14 @@ int main() {
       return android::NO_INIT;
     }
   }
+  timespec end_time;
+  clock_gettime(CLOCK_BOOTTIME, &end_time);
+  const uint32_t timestamp_start = static_cast<uint32_t>(
+      start_time.tv_sec * 1000 + (start_time.tv_nsec / 1000000L));
+  const uint32_t timestamp_stop = static_cast<uint32_t>(
+      end_time.tv_sec * 1000 + (end_time.tv_nsec / 1000000L));
+  ALOGI("Google camera provider start time: %d ms",
+        timestamp_stop - timestamp_start);
   androidSetThreadName("google.camera.provider");
   ABinderProcess_joinThreadPool();
 
diff --git a/common/hal/common/hal_types.h b/common/hal/common/hal_types.h
index 39890fd..5255cd4 100644
--- a/common/hal/common/hal_types.h
+++ b/common/hal/common/hal_types.h
@@ -35,6 +35,9 @@ using ::android::status_t;
 // Used to identify an invalid buffer handle.
 static constexpr buffer_handle_t kInvalidBufferHandle = nullptr;
 
+// Used to identify an invalid stream group id.
+static constexpr int32_t kInvalidStreamGroupId = -1;
+
 // See the definition of
 // ::android::hardware::camera::common::V1_0::TorchMode
 enum class TorchMode : uint32_t {
diff --git a/common/hal/google_camera_hal/camera_device_session.cc b/common/hal/google_camera_hal/camera_device_session.cc
index 8b7ffd8..00b5924 100644
--- a/common/hal/google_camera_hal/camera_device_session.cc
+++ b/common/hal/google_camera_hal/camera_device_session.cc
@@ -1771,7 +1771,8 @@ status_t CameraDeviceSession::RegisterStreamsIntoCacheManagerLocked(
         .format = stream_format,
         .producer_flags = producer_usage,
         .consumer_flags = consumer_usage,
-        .num_buffers_to_cache = num_buffers_to_cache};
+        .num_buffers_to_cache = num_buffers_to_cache,
+        .group_id = stream.group_id};
 
     status_t res = stream_buffer_cache_manager_->RegisterStream(reg_info);
     if (res != OK) {
diff --git a/common/hal/google_camera_hal/camera_provider.cc b/common/hal/google_camera_hal/camera_provider.cc
index 9d5dba8..0602e1c 100644
--- a/common/hal/google_camera_hal/camera_provider.cc
+++ b/common/hal/google_camera_hal/camera_provider.cc
@@ -44,7 +44,7 @@ CameraProvider::~CameraProvider() {
 
 std::unique_ptr<CameraProvider> CameraProvider::Create(
     std::unique_ptr<CameraProviderHwl> camera_provider_hwl) {
-  ATRACE_CALL();
+  ATRACE_NAME("CameraProvider::Create");
   auto provider = std::unique_ptr<CameraProvider>(new CameraProvider());
   if (provider == nullptr) {
     ALOGE("%s: Creating CameraProvider failed.", __FUNCTION__);
@@ -63,7 +63,7 @@ std::unique_ptr<CameraProvider> CameraProvider::Create(
 
 status_t CameraProvider::Initialize(
     std::unique_ptr<CameraProviderHwl> camera_provider_hwl) {
-  ATRACE_CALL();
+  ATRACE_NAME("CameraProvider::Initialize");
   // Advertise the HAL vendor tags to the camera metadata framework before
   // creating a HWL provider.
   status_t res = VendorTagManager::GetInstance().AddTags(kHalVendorTagSections);
@@ -106,6 +106,7 @@ status_t CameraProvider::Initialize(
 }
 
 status_t CameraProvider::InitializeVendorTags() {
+  ATRACE_NAME("CameraProvider::InitializeVendorTags");
   std::vector<VendorTagSection> hwl_tag_sections;
   status_t res = camera_provider_hwl_->GetVendorTags(&hwl_tag_sections);
   if (res != OK) {
@@ -288,7 +289,7 @@ status_t CameraProvider::CreateCameraDevice(
 
 status_t CameraProvider::CreateHwl(
     std::unique_ptr<CameraProviderHwl>* camera_provider_hwl) {
-  ATRACE_CALL();
+  ATRACE_NAME("CameraProvider::CreateHwl");
 #if GCH_HWL_USE_DLOPEN
   CreateCameraProviderHwl_t create_hwl;
 
diff --git a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
index 627b7db..ac84c08 100644
--- a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
+++ b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
@@ -8,13 +8,6 @@ flag {
   bug: "341748497"
 }
 
-flag {
-  name: "disable_capture_request_timeout"
-  namespace: "camera_hal"
-  description: "Disable capture request timeout logic in GCH layer"
-  bug: "372255560"
-}
-
 flag {
   name: "batched_request_buffers"
   namespace: "camera_hal"
diff --git a/common/hal/google_camera_hal/pending_requests_tracker.cc b/common/hal/google_camera_hal/pending_requests_tracker.cc
index f9d0ff0..e1dd11a 100644
--- a/common/hal/google_camera_hal/pending_requests_tracker.cc
+++ b/common/hal/google_camera_hal/pending_requests_tracker.cc
@@ -22,8 +22,6 @@
 #include <log/log.h>
 #include <utils/Trace.h>
 
-#include "libgooglecamerahal_flags.h"
-
 namespace android {
 namespace google_camera_hal {
 
@@ -286,20 +284,9 @@ status_t PendingRequestsTracker::WaitAndTrackRequestBuffers(
   }
 
   std::unique_lock<std::mutex> lock(pending_requests_mutex_);
-  if (libgooglecamerahal::flags::disable_capture_request_timeout()) {
-    tracker_request_condition_.wait(lock, [this, &request] {
-      return DoStreamsHaveEnoughBuffersLocked(request.output_buffers);
-    });
-  } else {
-    constexpr uint32_t kTrackerTimeoutMs = 3000;
-    if (!tracker_request_condition_.wait_for(
-            lock, std::chrono::milliseconds(kTrackerTimeoutMs), [this, &request] {
-              return DoStreamsHaveEnoughBuffersLocked(request.output_buffers);
-            })) {
-      ALOGE("%s: Waiting for buffer ready timed out.", __FUNCTION__);
-      return TIMED_OUT;
-    }
-  }
+  tracker_request_condition_.wait(lock, [this, &request] {
+    return DoStreamsHaveEnoughBuffersLocked(request.output_buffers);
+  });
 
   ALOGV("%s: all streams are ready", __FUNCTION__);
 
diff --git a/common/hal/tests/internal_stream_manager_tests.cc b/common/hal/tests/internal_stream_manager_tests.cc
index 9877c05..a7bd33e 100644
--- a/common/hal/tests/internal_stream_manager_tests.cc
+++ b/common/hal/tests/internal_stream_manager_tests.cc
@@ -15,12 +15,11 @@
  */
 
 #define LOG_TAG "InternalStreamManagerTests"
-#include <log/log.h>
-
 #include <gtest/gtest.h>
 #include <hal_types.h>
 #include <hardware/gralloc.h>
 #include <internal_stream_manager.h>
+#include <log/log.h>
 
 namespace android {
 namespace google_camera_hal {
@@ -51,7 +50,7 @@ static constexpr Stream kVideoStreamTemplate{
 // Raw stream template used in the test.
 static constexpr Stream kRawStreamTemplate{
     .stream_type = StreamType::kOutput,
-    .width = 4022,
+    .width = 4032,
     .height = 3024,
     .format = HAL_PIXEL_FORMAT_RAW10,
     .usage = 0,
@@ -60,14 +59,14 @@ static constexpr Stream kRawStreamTemplate{
 
 // Preview HAL stream template used in the test.
 static constexpr HalStream kPreviewHalStreamTemplate{
-    .override_format = HAL_PIXEL_FORMAT_YV12,
+    .override_format = HAL_PIXEL_FORMAT_YCBCR_420_888,
     .producer_usage = GRALLOC_USAGE_HW_CAMERA_WRITE,
     .max_buffers = 4,
 };
 
 // Video HAL stream template used in the test.
 static constexpr HalStream kVideoHalStreamTemplate{
-    .override_format = HAL_PIXEL_FORMAT_YV12,
+    .override_format = HAL_PIXEL_FORMAT_YCBCR_420_888,
     .producer_usage = GRALLOC_USAGE_HW_CAMERA_WRITE,
     .max_buffers = 4,
 };
diff --git a/common/hal/tests/mock_device_session_hwl.cc b/common/hal/tests/mock_device_session_hwl.cc
index 91eed13..f07ede7 100644
--- a/common/hal/tests/mock_device_session_hwl.cc
+++ b/common/hal/tests/mock_device_session_hwl.cc
@@ -365,6 +365,11 @@ void MockDeviceSessionHwl::DelegateCallsToFakeSession() {
       .WillByDefault(Invoke(
           &fake_session_hwl_,
           &FakeCameraDeviceSessionHwl::GetPhysicalCameraCharacteristics));
+
+  ON_CALL(*this, IsFeatureCombinationSupported(_))
+      .WillByDefault(
+          Invoke(&fake_session_hwl_,
+                 &FakeCameraDeviceSessionHwl::IsFeatureCombinationSupported));
 }
 
 }  // namespace google_camera_hal
diff --git a/common/hal/tests/zsl_buffer_manager_tests.cc b/common/hal/tests/zsl_buffer_manager_tests.cc
index d72b250..248b3fc 100644
--- a/common/hal/tests/zsl_buffer_manager_tests.cc
+++ b/common/hal/tests/zsl_buffer_manager_tests.cc
@@ -14,10 +14,10 @@
  * limitations under the License.
  */
 
+#include "hardware/gralloc1.h"
 #define LOG_TAG "ZslBufferManagerTests"
-#include <log/log.h>
-
 #include <gtest/gtest.h>
+#include <log/log.h>
 #include <zsl_buffer_manager.h>
 
 namespace android {
@@ -31,6 +31,8 @@ static constexpr HalBufferDescriptor kRawBufferDescriptor = {
     .width = 4032,
     .height = 3024,
     .format = HAL_PIXEL_FORMAT_RAW10,
+    .producer_flags = GRALLOC1_PRODUCER_USAGE_CAMERA,
+    .consumer_flags = GRALLOC1_CONSUMER_USAGE_CAMERA,
     .immediate_num_buffers = kMaxBufferDepth,
     .max_num_buffers = kMaxBufferDepth,
 };
diff --git a/common/hal/utils/stream_buffer_cache_manager.cc b/common/hal/utils/stream_buffer_cache_manager.cc
index c2f0e65..aa38a19 100644
--- a/common/hal/utils/stream_buffer_cache_manager.cc
+++ b/common/hal/utils/stream_buffer_cache_manager.cc
@@ -371,6 +371,7 @@ status_t StreamBufferCacheManager::StreamBufferCache::GetBuffer(
   std::unique_lock<std::mutex> cache_lock(cache_access_mutex_);
 
   // 0. the buffer cache must be active
+  SetClientGetBufferStatusLocked(/*has_started=*/true);
   if (!is_active_) {
     ALOGW("%s: The buffer cache for stream %d is not active.", __FUNCTION__,
           cache_info_.stream_id);
@@ -437,6 +438,15 @@ bool StreamBufferCacheManager::StreamBufferCache::IsStreamDeactivated() {
 void StreamBufferCacheManager::StreamBufferCache::SetManagerState(bool active) {
   std::unique_lock<std::mutex> lock(cache_access_mutex_);
   is_active_ = active;
+  if (!active) {
+    // When the SBC is deactivated, we reset the client get buffer status.
+    SetClientGetBufferStatusLocked(/*has_started=*/false);
+  }
+}
+
+void StreamBufferCacheManager::StreamBufferCache::SetClientGetBufferStatusLocked(
+    bool has_started) {
+  has_started_get_buffer_ = has_started;
 }
 
 status_t StreamBufferCacheManager::StreamBufferCache::FlushLocked(
@@ -454,6 +464,7 @@ status_t StreamBufferCacheManager::StreamBufferCache::FlushLocked(
 
   if (cached_buffers_.empty()) {
     ALOGV("%s: Stream buffer cache is already empty.", __FUNCTION__);
+    SetClientGetBufferStatusLocked(/*has_started=*/false);
     ReleasePlaceholderBufferLocked();
     return OK;
   }
@@ -465,6 +476,7 @@ status_t StreamBufferCacheManager::StreamBufferCache::FlushLocked(
   }
 
   cached_buffers_.clear();
+  SetClientGetBufferStatusLocked(/*has_started=*/false);
   ReleasePlaceholderBufferLocked();
 
   return OK;
@@ -558,6 +570,15 @@ bool StreamBufferCacheManager::StreamBufferCache::RefillableLocked() const {
     return false;
   }
 
+  // For group streams, we would start refill buffer caches only after first
+  // get buffer from the client, to avoid cache buffer allocation before using.
+  if (cache_info_.group_id != kInvalidStreamGroupId &&
+      !has_started_get_buffer_) {
+    ALOGV("%s: skip refilling for group stream %d.", __FUNCTION__,
+          cache_info_.stream_id);
+    return false;
+  }
+
   // Need to refill if the cache is empty.
   return cached_buffers_.empty();
 }
diff --git a/common/hal/utils/stream_buffer_cache_manager.h b/common/hal/utils/stream_buffer_cache_manager.h
index 2d59448..cd3e8d8 100644
--- a/common/hal/utils/stream_buffer_cache_manager.h
+++ b/common/hal/utils/stream_buffer_cache_manager.h
@@ -73,6 +73,8 @@ struct StreamBufferCacheRegInfo {
   uint64_t consumer_flags = 0;
   // Number of buffers that the manager needs to cache
   uint32_t num_buffers_to_cache = 1;
+  // Group ID of the stream
+  int32_t group_id = kInvalidStreamGroupId;
 };
 
 //
@@ -202,6 +204,10 @@ class StreamBufferCacheManager {
                       IHalBufferAllocator* placeholder_buffer_allocator);
 
    private:
+    // Return whether the client has already started getting buffers.
+    // The cache_access_mutex_ must be locked when calling this function.
+    void SetClientGetBufferStatusLocked(bool has_started);
+
     // Flush all buffers acquired from the buffer provider. Return the acquired
     // buffers through the return_func.
     // The cache_access_mutex_ must be locked when calling this function.
@@ -255,9 +261,12 @@ class StreamBufferCacheManager {
     // BufferRequestResult must be set to true.
     StreamBuffer placeholder_buffer_;
     // StreamBufferCacheManager does not refill a StreamBufferCache until this
-    // is set true by the client. Client should set this flag to true after the
-    // buffer provider (e.g. framework) is ready to handle buffer requests, or
-    // when a new request is submitted for an idle camera device (no inflight
+    // is set true by the client. For group streams, we would
+    // start refill a StreamBufferCache only when client first get buffer, to
+    // avoid redundant cache buffer allocation of useless group streams, details
+    // can be found in b/420847957. Client should set this flag to true after
+    // the buffer provider (e.g. framework) is ready to handle buffer requests,
+    // or when a new request is submitted for an idle camera device (no inflight
     // requests).
     bool is_active_ = false;
     // Interface to notify the parent manager for new threadloop workload.
@@ -265,6 +274,11 @@ class StreamBufferCacheManager {
     // Allocator of the placeholder buffer for this stream. The stream buffer cache
     // manager owns this throughout the life cycle of this stream buffer cahce.
     IHalBufferAllocator* placeholder_buffer_allocator_ = nullptr;
+    // Whether the client has started getting buffer on the StreamBufferCache.
+    // The client should reset this flag to false when the stream buffer cache
+    // manager is deactivated or flush.
+    // Must be protected by cache_access_mutex_.
+    bool has_started_get_buffer_ = false;
   };
 
   // Add stream buffer cache. Lock caches_map_mutex_ before calling this func.
diff --git a/common/lib_depth_generator/Android.bp b/common/lib_depth_generator/Android.bp
deleted file mode 100644
index 01b816e..0000000
--- a/common/lib_depth_generator/Android.bp
+++ /dev/null
@@ -1,28 +0,0 @@
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
-package {
-    // See: http://go/android-license-faq
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_library_headers {
-    name: "lib_depth_generator_headers",
-    vendor: true,
-    export_include_dirs: [
-        ".",
-    ],
-}
diff --git a/common/lib_depth_generator/OWNERS b/common/lib_depth_generator/OWNERS
deleted file mode 100644
index b0dafd1..0000000
--- a/common/lib_depth_generator/OWNERS
+++ /dev/null
@@ -1 +0,0 @@
-donghuihan@google.com
diff --git a/common/lib_depth_generator/depth_generator.h b/common/lib_depth_generator/depth_generator.h
deleted file mode 100644
index 0009e95..0000000
--- a/common/lib_depth_generator/depth_generator.h
+++ /dev/null
@@ -1,45 +0,0 @@
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
-#ifndef HARDWARE_GOOGLE_CAMERA_LIB_DEPTH_GENERATOR_H_
-#define HARDWARE_GOOGLE_CAMERA_LIB_DEPTH_GENERATOR_H_
-
-#include <utils/Errors.h>
-#include "depth_types.h"
-
-namespace android {
-namespace depth_generator {
-
-// DepthGenerator is the basic interface for any provider that can generate
-// depth buffer from several NIR and YUV buffers.
-class DepthGenerator {
- public:
-  virtual ~DepthGenerator() = default;
-
-  // Enqueue a depth buffer request for asynchronous processing
-  virtual status_t EnqueueProcessRequest(const DepthRequestInfo&) = 0;
-
-  // Blocking call to execute the process request right way.
-  virtual status_t ExecuteProcessRequest(const DepthRequestInfo&) = 0;
-
-  // Set a callback function to allow the depth generator to asynchronously
-  // return the depth buffer.
-  virtual void SetResultCallback(DepthResultCallbackFunction) = 0;
-};
-typedef DepthGenerator* (*CreateDepthGenerator_t)();
-}  // namespace depth_generator
-}  // namespace android
-#endif  // HARDWARE_GOOGLE_CAMERA_LIB_DEPTH_GENERATOR_H_
\ No newline at end of file
diff --git a/common/lib_depth_generator/depth_types.h b/common/lib_depth_generator/depth_types.h
deleted file mode 100644
index 5ee7cf8..0000000
--- a/common/lib_depth_generator/depth_types.h
+++ /dev/null
@@ -1,97 +0,0 @@
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
-#ifndef HARDWARE_GOOGLE_CAMERA_LIB_DEPTH_TYPES_H_
-#define HARDWARE_GOOGLE_CAMERA_LIB_DEPTH_TYPES_H_
-
-#include <cutils/native_handle.h>
-#include <system/camera_metadata.h>
-#include <system/graphics-base-v1.0.h>
-#include <functional>
-#include <vector>
-
-namespace android {
-namespace depth_generator {
-
-enum class DepthResultStatus : uint32_t {
-  // Depth generator is able to successfully process the request
-  kOk = 0,
-  // Depth generator failed to process the request
-  kError,
-};
-
-struct StreamBuffer {
-  // TODO(b/126379504): Add handle to Framework/HAL stream if needed.
-  // The client owns the buffer and should guarantee that they are valid during
-  // the entire life cycle that this buffer is passed into the depth_generator.
-  buffer_handle_t* buffer = nullptr;
-};
-
-struct BufferPlane {
-  // The virtual address mapped to the UMD of the client process. The client
-  // should guarantee that this is valid and not unmapped during the entire life
-  // cycle that this buffer is passed into the depth_generator.
-  uint8_t* addr = nullptr;
-  // In bytes
-  uint32_t stride = 0;
-  // Number of lines actually allocated
-  uint32_t scanline = 0;
-};
-
-struct Buffer {
-  // Format of the image buffer
-  android_pixel_format_t format = HAL_PIXEL_FORMAT_RGBA_8888;
-  // Image planes mapped to UMD
-  std::vector<BufferPlane> planes;
-  // Dimension of this image buffer
-  uint32_t width = 0;
-  uint32_t height = 0;
-  // Information of the framework buffer
-  StreamBuffer framework_buffer;
-};
-
-struct DepthRequestInfo {
-  // Frame number used by the caller to identify this request
-  uint32_t frame_number = 0;
-  // Input buffers
-  // Sequence of buffers from color sensor
-  std::vector<Buffer> color_buffer;
-  // Sequence of buffers from multiple NIR sensors(e.g. {{d0, f0},{d1, f1}})
-  std::vector<std::vector<Buffer>> ir_buffer;
-  // Output buffer
-  Buffer depth_buffer;
-  // Place holder for input metadata(e.g. crop_region). The client should
-  // guarantee that the metadata is valid during the entire life cycle that this
-  // metadata is passed into the depth_generator.
-  const camera_metadata_t* settings = nullptr;
-  // input buffer metadata for the color_buffer. This metadata contains info on
-  // how the color_buffer is generated(e.g. crop info, FD result, etc.). The
-  // caller owns the data and guarantee that the data is valid during the func
-  // call. The callee should copy this if it still needs this after the call is
-  // returned.
-  const camera_metadata_t* color_buffer_metadata = nullptr;
-};
-
-// Callback function invoked to notify depth buffer readiness. This method must
-// be invoked by a thread different from the thread that enqueues the request to
-// avoid deadlock.
-using DepthResultCallbackFunction =
-    std::function<void(DepthResultStatus result, uint32_t frame_number)>;
-
-}  // namespace depth_generator
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_CAMERA_LIB_DEPTH_TYPES_H_
\ No newline at end of file
diff --git a/devices/EmulatedCamera/hwl/configs/Android.bp b/devices/EmulatedCamera/hwl/configs/Android.bp
index ca089b8..8939818 100644
--- a/devices/EmulatedCamera/hwl/configs/Android.bp
+++ b/devices/EmulatedCamera/hwl/configs/Android.bp
@@ -23,7 +23,6 @@ prebuilt_defaults {
     name: "emu_camera_config_defaults",
     relative_install_path: "config",
     soc_specific: true,
-    installable: false,
 }
 
 prebuilt_etc {
```

