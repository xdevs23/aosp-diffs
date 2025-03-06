```diff
diff --git a/common/hal/aidl_service/aidl_camera_provider.cc b/common/hal/aidl_service/aidl_camera_provider.cc
index be1ccc7..ef7e0d0 100644
--- a/common/hal/aidl_service/aidl_camera_provider.cc
+++ b/common/hal/aidl_service/aidl_camera_provider.cc
@@ -15,7 +15,7 @@
  */
 
 #define LOG_TAG "GCH_AidlCameraProvider"
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #include "aidl_camera_provider.h"
 
 #include <log/log.h>
@@ -187,23 +187,11 @@ ScopedAStatus AidlCameraProvider::setCallback(
         static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
   }
 
-  bool first_time = false;
   {
     std::unique_lock<std::mutex> lock(callbacks_lock_);
-    first_time = callbacks_ == nullptr;
     callbacks_ = callback;
   }
   google_camera_provider_->TriggerDeferredCallbacks();
-#ifdef __ANDROID_APEX__
-  if (first_time) {
-    std::string ready_property_name = "vendor.camera.hal.ready.count";
-    int ready_count = property_get_int32(ready_property_name.c_str(), 0);
-    property_set(ready_property_name.c_str(),
-                 std::to_string(++ready_count).c_str());
-    ALOGI("AidlCameraProvider::setCallback() first time ready count: %d ",
-          ready_count);
-  }
-#endif
   return ScopedAStatus::ok();
 }
 
@@ -258,6 +246,12 @@ ScopedAStatus AidlCameraProvider::getCameraIdList(
         "device@" + device::implementation::AidlCameraDevice::kDeviceVersion +
         "/" + kProviderName + "/" + std::to_string(camera_ids[i]);
   }
+#ifdef __ANDROID_APEX__
+  if (!camera_device_initialized_ && available_camera_ids_.empty()) {
+    available_camera_ids_ =
+        std::unordered_set<uint32_t>(camera_ids.begin(), camera_ids.end());
+  }
+#endif
   return ScopedAStatus::ok();
 }
 
@@ -369,8 +363,9 @@ ScopedAStatus AidlCameraProvider::getCameraDeviceInterface(
         static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
   }
 
+  int camera_id_int = atoi(camera_id.c_str());
   status_t res = google_camera_provider_->CreateCameraDevice(
-      atoi(camera_id.c_str()), &google_camera_device);
+      camera_id_int, &google_camera_device);
   if (res != OK) {
     ALOGE("%s: Creating CameraDevice failed: %s(%d)", __FUNCTION__,
           strerror(-res), res);
@@ -384,6 +379,22 @@ ScopedAStatus AidlCameraProvider::getCameraDeviceInterface(
     return ScopedAStatus::fromServiceSpecificError(
         static_cast<int32_t>(Status::INTERNAL_ERROR));
   }
+
+#ifdef __ANDROID_APEX__
+  available_camera_ids_.erase(camera_id_int);
+  if (!camera_device_initialized_ && available_camera_ids_.empty()) {
+    camera_device_initialized_ = true;
+
+    std::string ready_property_name = "vendor.camera.hal.ready.count";
+    int ready_count = property_get_int32(ready_property_name.c_str(), 0);
+    property_set(ready_property_name.c_str(),
+                 std::to_string(++ready_count).c_str());
+    ALOGI(
+        "AidlCameraProvider::getCameraDeviceInterface() first time ready "
+        "count: %d ",
+        ready_count);
+  }
+#endif
   return ScopedAStatus::ok();
 }
 
diff --git a/common/hal/aidl_service/aidl_camera_provider.h b/common/hal/aidl_service/aidl_camera_provider.h
index 7cd5bde..ecde170 100644
--- a/common/hal/aidl_service/aidl_camera_provider.h
+++ b/common/hal/aidl_service/aidl_camera_provider.h
@@ -21,6 +21,10 @@
 #include <aidl/android/hardware/camera/provider/ICameraProviderCallback.h>
 
 #include <regex>
+#include <string>
+#ifdef __ANDROID_APEX__
+#include <unordered_set>
+#endif
 
 #include "camera_provider.h"
 
@@ -88,6 +92,11 @@ class AidlCameraProvider : public BnCameraProvider {
 
   std::unique_ptr<CameraProvider> google_camera_provider_;
   google_camera_hal::CameraProviderCallback camera_provider_callback_;
+
+#ifdef __ANDROID_APEX__
+  std::unordered_set<uint32_t> available_camera_ids_;
+  bool camera_device_initialized_ = false;
+#endif
 };
 
 }  // namespace implementation
diff --git a/common/hal/google_camera_hal/Android.bp b/common/hal/google_camera_hal/Android.bp
index 7ef7f3e..ae96e8e 100644
--- a/common/hal/google_camera_hal/Android.bp
+++ b/common/hal/google_camera_hal/Android.bp
@@ -64,7 +64,6 @@ cc_library_shared {
     vendor: true,
     compile_multilib: "first",
     ldflags: [
-        "-Wl,--rpath,/system/${LIB}/camera/capture_sessions",
         "-Wl,--rpath,/vendor/${LIB}/camera/capture_sessions",
     ],
     srcs: [
diff --git a/common/hal/google_camera_hal/camera_device.cc b/common/hal/google_camera_hal/camera_device.cc
index 067d344..754be9c 100644
--- a/common/hal/google_camera_hal/camera_device.cc
+++ b/common/hal/google_camera_hal/camera_device.cc
@@ -162,6 +162,7 @@ static void LoadLibraries(google_camera_hal::HwlMemoryConfig memory_config,
     return true;
   };
   ProcMemInfo meminfo(getpid());
+  // TODO(b/376519437) - Restrict madvising to important VMAs.
   meminfo.ForEachVmaFromMaps(vmaCollectorCb);
 }
 
diff --git a/common/hal/google_camera_hal/camera_device_session.cc b/common/hal/google_camera_hal/camera_device_session.cc
index 22e0a3d..6dcc7b7 100644
--- a/common/hal/google_camera_hal/camera_device_session.cc
+++ b/common/hal/google_camera_hal/camera_device_session.cc
@@ -811,7 +811,7 @@ status_t CameraDeviceSession::ConfigureStreams(
     std::lock_guard<std::mutex> request_lock(request_record_lock_);
     pending_request_streams_.clear();
     error_notified_requests_.clear();
-    dummy_buffer_observed_.clear();
+    placeholder_buffer_observed_.clear();
     pending_results_.clear();
     ignore_shutters_.clear();
   }
@@ -1035,8 +1035,8 @@ void CameraDeviceSession::NotifyErrorMessage(uint32_t frame_number,
   session_callback_.notify(message);
 }
 
-status_t CameraDeviceSession::TryHandleDummyResult(CaptureResult* result,
-                                                   bool* result_handled) {
+status_t CameraDeviceSession::TryHandlePlaceholderResult(CaptureResult* result,
+                                                         bool* result_handled) {
   if (result == nullptr || result_handled == nullptr) {
     ALOGE("%s: result or result_handled is nullptr.", __FUNCTION__);
     return BAD_VALUE;
@@ -1051,8 +1051,8 @@ status_t CameraDeviceSession::TryHandleDummyResult(CaptureResult* result,
     if (error_notified_requests_.find(frame_number) ==
         error_notified_requests_.end()) {
       for (auto& stream_buffer : result->output_buffers) {
-        if (dummy_buffer_observed_.find(stream_buffer.buffer) !=
-            dummy_buffer_observed_.end()) {
+        if (placeholder_buffer_observed_.find(stream_buffer.buffer) !=
+            placeholder_buffer_observed_.end()) {
           error_notified_requests_.insert(frame_number);
           if (pending_results_.find(frame_number) != pending_results_.end()) {
             need_to_notify_error_result = true;
@@ -1076,7 +1076,7 @@ status_t CameraDeviceSession::TryHandleDummyResult(CaptureResult* result,
 
   if (need_to_handle_result) {
     for (auto& stream_buffer : result->output_buffers) {
-      bool is_dummy_buffer = false;
+      bool is_placeholder_buffer = false;
       if (hal_buffer_managed_stream_ids_.find(stream_buffer.stream_id) ==
           hal_buffer_managed_stream_ids_.end()) {
         // No need to handle non HAL buffer managed streams here
@@ -1084,12 +1084,14 @@ status_t CameraDeviceSession::TryHandleDummyResult(CaptureResult* result,
       }
       {
         std::lock_guard<std::mutex> lock(request_record_lock_);
-        is_dummy_buffer = (dummy_buffer_observed_.find(stream_buffer.buffer) !=
-                           dummy_buffer_observed_.end());
+        is_placeholder_buffer =
+            (placeholder_buffer_observed_.find(stream_buffer.buffer) !=
+             placeholder_buffer_observed_.end());
       }
 
-      uint64_t buffer_id = (is_dummy_buffer ? /*Use invalid for dummy*/ 0
-                                            : stream_buffer.buffer_id);
+      uint64_t buffer_id =
+          (is_placeholder_buffer ? /*Use invalid for placeholder*/ 0
+                                 : stream_buffer.buffer_id);
       // To avoid publishing duplicated error buffer message, only publish
       // it here when getting normal buffer status from HWL
       if (stream_buffer.status == BufferStatus::kOk) {
@@ -1117,8 +1119,8 @@ status_t CameraDeviceSession::TryHandleDummyResult(CaptureResult* result,
             // requests tracker
             continue;
           }
-          if (dummy_buffer_observed_.find(buffer.buffer) ==
-              dummy_buffer_observed_.end()) {
+          if (placeholder_buffer_observed_.find(buffer.buffer) ==
+              placeholder_buffer_observed_.end()) {
             acquired_buffers.push_back(buffer);
           }
         }
@@ -1798,27 +1800,28 @@ status_t CameraDeviceSession::RequestBuffersFromStreamBufferCacheManager(
 
   // This function fulfills requests from lower HAL level. It is hard for some
   // implementation of lower HAL level to handle the case of a request failure.
-  // In case a framework buffer can not be delivered to the lower level, a dummy
-  // buffer will be returned by the stream buffer cache manager.
-  // The client at lower level can use that dummy buffer as a normal buffer for
-  // writing and so forth. But that buffer will not be returned to the
+  // In case a framework buffer can not be delivered to the lower level, a
+  // placeholder buffer will be returned by the stream buffer cache manager. The
+  // client at lower level can use that placeholder buffer as a normal buffer
+  // for writing and so forth. But that buffer will not be returned to the
   // framework. This avoids the troublesome for lower level to handle such
   // situation. An ERROR_REQUEST needs to be returned to the framework according
-  // to ::android::hardware::camera::device::V3_5::StreamBufferRequestError.
-  if (buffer_request_result.is_dummy_buffer) {
-    ALOGI("%s: [sbc] Dummy buffer returned for stream: %d, frame: %d",
+  // to
+  // ::android::hardware::camera::device::V3_5::StreamBufferRequestError.
+  if (buffer_request_result.is_placeholder_buffer) {
+    ALOGI("%s: [sbc] Placeholder buffer returned for stream: %d, frame: %d",
           __FUNCTION__, stream_id, frame_number);
     {
       std::lock_guard<std::mutex> lock(request_record_lock_);
-      dummy_buffer_observed_.insert(buffer_request_result.buffer.buffer);
+      placeholder_buffer_observed_.insert(buffer_request_result.buffer.buffer);
     }
   }
 
   ALOGV("%s: [sbc] => HWL Acquired buf[%p] buf_id[%" PRIu64
-        "] strm[%d] frm[%u] dummy[%d]",
+        "] strm[%d] frm[%u] placeholder[%d]",
         __FUNCTION__, buffer_request_result.buffer.buffer,
         buffer_request_result.buffer.buffer_id, stream_id, frame_number,
-        buffer_request_result.is_dummy_buffer);
+        buffer_request_result.is_placeholder_buffer);
 
   buffers->push_back(buffer_request_result.buffer);
   return OK;
@@ -1980,7 +1983,7 @@ bool CameraDeviceSession::TryHandleCaptureResult(
   // If there is placeholder buffer or a placeholder buffer has been observed of
   // this frame, handle the capture result specifically.
   bool result_handled = false;
-  res = TryHandleDummyResult(result.get(), &result_handled);
+  res = TryHandlePlaceholderResult(result.get(), &result_handled);
   if (res != OK) {
     ALOGE("%s: Failed to handle placeholder result.", __FUNCTION__);
     return true;
diff --git a/common/hal/google_camera_hal/camera_device_session.h b/common/hal/google_camera_hal/camera_device_session.h
index 8dccacb..1f8778a 100644
--- a/common/hal/google_camera_hal/camera_device_session.h
+++ b/common/hal/google_camera_hal/camera_device_session.h
@@ -255,10 +255,11 @@ class CameraDeviceSession {
   void NotifyBufferError(uint32_t frame_number, int32_t stream_id,
                          uint64_t buffer_id);
 
-  // Try to check if result contains dummy buffer or dummy buffer from this
-  // result has been observed. If so, handle this result specifically. Set
-  // result_handled as true.
-  status_t TryHandleDummyResult(CaptureResult* result, bool* result_handled);
+  // Try to check if result contains placeholder buffer or placeholder buffer
+  // from this result has been observed. If so, handle this result specifically.
+  // Set result_handled as true.
+  status_t TryHandlePlaceholderResult(CaptureResult* result,
+                                      bool* result_handled);
 
   // Check if all streams in the current session are active in SBC manager
   status_t HandleSBCInactiveStreams(const CaptureRequest& request,
@@ -415,8 +416,8 @@ class CameraDeviceSession {
   // Protected by request_record_lock_;
   std::set<uint32_t> error_notified_requests_;
 
-  // Set of dummy buffer observed
-  std::set<buffer_handle_t> dummy_buffer_observed_;
+  // Set of placeholder buffer observed
+  std::set<buffer_handle_t> placeholder_buffer_observed_;
 
   // The last shutter timestamp in nanoseconds if systrace is enabled. Reset
   // after stream configuration.
diff --git a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
index d349bf2..f9bbad7 100644
--- a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
+++ b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
@@ -2,8 +2,15 @@ package: "libgooglecamerahal.flags"
 container: "vendor"
 
 flag {
-  name: "zsl_video_denoise_in_hwl"
+  name: "zsl_video_denoise_in_hwl_two"
   namespace: "camera_hal"
   description: "Enable HWL ZSL video processing and disable GCH processing"
   bug: "341748497"
 }
+
+flag {
+  name: "disable_capture_request_timeout"
+  namespace: "camera_hal"
+  description: "Disable capture request timeout logic in GCH layer"
+  bug: "372255560"
+}
diff --git a/common/hal/google_camera_hal/pending_requests_tracker.cc b/common/hal/google_camera_hal/pending_requests_tracker.cc
index a5cd02e..f9d0ff0 100644
--- a/common/hal/google_camera_hal/pending_requests_tracker.cc
+++ b/common/hal/google_camera_hal/pending_requests_tracker.cc
@@ -17,10 +17,12 @@
 // #define LOG_NDEBUG 0
 #define LOG_TAG "GCH_PendingRequestsTracker"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
+#include "pending_requests_tracker.h"
+
 #include <log/log.h>
 #include <utils/Trace.h>
 
-#include "pending_requests_tracker.h"
+#include "libgooglecamerahal_flags.h"
 
 namespace android {
 namespace google_camera_hal {
@@ -284,12 +286,19 @@ status_t PendingRequestsTracker::WaitAndTrackRequestBuffers(
   }
 
   std::unique_lock<std::mutex> lock(pending_requests_mutex_);
-  if (!tracker_request_condition_.wait_for(
-          lock, std::chrono::milliseconds(kTrackerTimeoutMs), [this, &request] {
-            return DoStreamsHaveEnoughBuffersLocked(request.output_buffers);
-          })) {
-    ALOGE("%s: Waiting for buffer ready timed out.", __FUNCTION__);
-    return TIMED_OUT;
+  if (libgooglecamerahal::flags::disable_capture_request_timeout()) {
+    tracker_request_condition_.wait(lock, [this, &request] {
+      return DoStreamsHaveEnoughBuffersLocked(request.output_buffers);
+    });
+  } else {
+    constexpr uint32_t kTrackerTimeoutMs = 3000;
+    if (!tracker_request_condition_.wait_for(
+            lock, std::chrono::milliseconds(kTrackerTimeoutMs), [this, &request] {
+              return DoStreamsHaveEnoughBuffersLocked(request.output_buffers);
+            })) {
+      ALOGE("%s: Waiting for buffer ready timed out.", __FUNCTION__);
+      return TIMED_OUT;
+    }
   }
 
   ALOGV("%s: all streams are ready", __FUNCTION__);
@@ -315,7 +324,8 @@ status_t PendingRequestsTracker::WaitAndTrackAcquiredBuffers(
   int32_t overridden_stream_id = OverrideStreamIdForGroup(stream_id);
   if (hal_buffer_managed_stream_ids_.find(stream_id) ==
       hal_buffer_managed_stream_ids_.end()) {
-    // Pending requests tracker doesn't track stream ids which aren't HAL buffer managed
+    // Pending requests tracker doesn't track stream ids which aren't HAL buffer
+    // managed
     return OK;
   }
   if (!IsStreamConfigured(overridden_stream_id)) {
@@ -352,7 +362,8 @@ void PendingRequestsTracker::TrackBufferAcquisitionFailure(int32_t stream_id,
   }
   if (hal_buffer_managed_stream_ids_.find(stream_id) ==
       hal_buffer_managed_stream_ids_.end()) {
-    // Pending requests tracker doesn't track stream ids which aren't HAL buffer managed
+    // Pending requests tracker doesn't track stream ids which aren't HAL buffer
+    // managed
     return;
   }
   std::unique_lock<std::mutex> lock(pending_acquisition_mutex_);
@@ -381,7 +392,8 @@ void PendingRequestsTracker::DumpStatus() {
   pending_acquisition_string += "}";
 
   ALOGI(
-      "%s: Buffers (including dummy) pending return from HWL: %s. Buffers "
+      "%s: Buffers (including placeholder) pending return from HWL: %s. "
+      "Buffers "
       "proactively acquired from the framework: %s.",
       __FUNCTION__, pending_requests_string.c_str(),
       pending_acquisition_string.c_str());
diff --git a/common/hal/google_camera_hal/pending_requests_tracker.h b/common/hal/google_camera_hal/pending_requests_tracker.h
index 475e920..ed553e7 100644
--- a/common/hal/google_camera_hal/pending_requests_tracker.h
+++ b/common/hal/google_camera_hal/pending_requests_tracker.h
@@ -74,9 +74,6 @@ class PendingRequestsTracker {
   PendingRequestsTracker() = default;
 
  private:
-  // Duration to wait for stream buffers to be available.
-  static constexpr uint32_t kTrackerTimeoutMs = 3000;
-
   // Duration to wait for when requesting buffer
   static constexpr uint32_t kAcquireBufferTimeoutMs = 50;
 
diff --git a/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc b/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
index 9bfbc2c..fec7326 100644
--- a/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
+++ b/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
@@ -734,7 +734,7 @@ status_t ZslSnapshotCaptureSession::Initialize(
   res = characteristics->Get(VendorTagIds::kVideoSwDenoiseEnabled,
                              &video_sw_denoise_entry);
   if (res == OK && video_sw_denoise_entry.data.u8[0] == 1) {
-    if (libgooglecamerahal::flags::zsl_video_denoise_in_hwl()) {
+    if (libgooglecamerahal::flags::zsl_video_denoise_in_hwl_two()) {
       ALOGI("%s: video sw denoise is enabled in HWL", __FUNCTION__);
     } else {
       video_sw_denoise_enabled_ = true;
diff --git a/common/hal/tests/camera_id_manager_tests.cc b/common/hal/tests/camera_id_manager_tests.cc
index 99393be..6026c20 100644
--- a/common/hal/tests/camera_id_manager_tests.cc
+++ b/common/hal/tests/camera_id_manager_tests.cc
@@ -93,14 +93,14 @@ TEST(CameraIdMangerTest, InvalidParameters) {
   auto id_manager = CameraIdManager::Create(cameras);
   ASSERT_NE(id_manager, nullptr);
 
-  uint32_t dummy = 0;
+  uint32_t invalid_id = 0;
   status_t res;
   // Test for invalid IDs or bad parameters
-  res = id_manager->GetInternalCameraId(cameras.size(), &dummy);
+  res = id_manager->GetInternalCameraId(cameras.size(), &invalid_id);
   EXPECT_NE(res, OK) << "GetInternalCameraId() succeeded with an invalid ID";
   res = id_manager->GetInternalCameraId(cameras.size(), nullptr);
   EXPECT_NE(res, OK) << "GetInternalCameraId() succeeded with a null parameter";
-  res = id_manager->GetPublicCameraId(cameras.size(), &dummy);
+  res = id_manager->GetPublicCameraId(cameras.size(), &invalid_id);
   EXPECT_NE(res, OK) << "GetPublicCameraId() succeeded with an invalid ID";
   res = id_manager->GetPublicCameraId(cameras.size(), nullptr);
   EXPECT_NE(res, OK) << "GetPublicCameraId() succeeded with a null parameter";
diff --git a/common/hal/tests/internal_stream_manager_tests.cc b/common/hal/tests/internal_stream_manager_tests.cc
index 6a6e277..9877c05 100644
--- a/common/hal/tests/internal_stream_manager_tests.cc
+++ b/common/hal/tests/internal_stream_manager_tests.cc
@@ -179,8 +179,8 @@ TEST(InternalStreamManagerTests, GetStreamBuffer) {
   HalStream preview_hal_stream = kPreviewHalStreamTemplate;
 
   // Get buffer from an invalid stream.
-  StreamBuffer dummy_buffer;
-  EXPECT_NE(stream_manager->GetStreamBuffer(/*stream_id=*/-1, &dummy_buffer), OK)
+  StreamBuffer invalid_buffer;
+  EXPECT_NE(stream_manager->GetStreamBuffer(/*stream_id=*/-1, &invalid_buffer), OK)
       << "Getting a buffer from an invalid stream should fail";
 
   // Register and allocate buffers.
diff --git a/common/hal/tests/mock_device_session_hwl.h b/common/hal/tests/mock_device_session_hwl.h
index 7ee4826..6b6657b 100644
--- a/common/hal/tests/mock_device_session_hwl.h
+++ b/common/hal/tests/mock_device_session_hwl.h
@@ -54,7 +54,7 @@ class FakeCameraDeviceSessionHwl : public CameraDeviceSessionHwl {
 
   status_t BuildPipelines() override;
 
-  // This fake method fills a few dummy streams to streams.
+  // This fake method fills a few placeholder streams to streams.
   // Currently only supports kOfflineSmoothTransitionRole.
   status_t GetRequiredIntputStreams(const StreamConfiguration& overall_config,
                                     HwlOfflinePipelineRole pipeline_role,
@@ -130,7 +130,7 @@ class MockDeviceSessionHwl : public CameraDeviceSessionHwl {
   // Initialize a mock camera device session HWL for a camera ID.
   // If physical_camera_ids is not empty, it will consist of the physical camera
   // IDs.
-  MockDeviceSessionHwl(uint32_t camera_id = 3,  // Dummy camera ID
+  MockDeviceSessionHwl(uint32_t camera_id = 3,
                        const std::vector<uint32_t>& physical_camera_ids =
                            std::vector<uint32_t>());
 
diff --git a/common/hal/tests/process_block_tests.cc b/common/hal/tests/process_block_tests.cc
index 20efe6b..a0613bc 100644
--- a/common/hal/tests/process_block_tests.cc
+++ b/common/hal/tests/process_block_tests.cc
@@ -198,7 +198,7 @@ TEST_F(ProcessBlockTest, RealtimeProcessBlockRequest) {
 
   ASSERT_EQ(block->SetResultProcessor(std::move(result_processor)), OK);
 
-  // Testing RealtimeProcessBlock with a dummy request.
+  // Testing RealtimeProcessBlock with an empty request.
   std::vector<ProcessBlockRequest> block_requests(1);
   ASSERT_EQ(block->ProcessRequests(block_requests, block_requests[0].request),
             OK);
@@ -238,7 +238,7 @@ TEST_F(ProcessBlockTest, MultiCameraRtProcessBlockRequest) {
 
   ASSERT_EQ(block->SetResultProcessor(std::move(result_processor)), OK);
 
-  // Testing RealtimeProcessBlock with dummy requests.
+  // Testing RealtimeProcessBlock with some requests.
   std::vector<ProcessBlockRequest> block_requests;
   CaptureRequest remaining_session_requests;
 
diff --git a/common/hal/tests/request_processor_tests.cc b/common/hal/tests/request_processor_tests.cc
index 1591cd9..a76806f 100644
--- a/common/hal/tests/request_processor_tests.cc
+++ b/common/hal/tests/request_processor_tests.cc
@@ -147,7 +147,7 @@ TEST_F(RequestProcessorTest, BasicRequestProcessorRequest) {
 
   EXPECT_EQ(request_processor->SetProcessBlock(std::move(process_block)), OK);
 
-  // Testing BasicRequestProcessorRequest with a dummy request.
+  // Testing BasicRequestProcessorRequest with an empty request.
   CaptureRequest request = {};
   ASSERT_EQ(request_processor->ProcessRequest(request), OK);
 }
diff --git a/common/hal/tests/result_processor_tests.cc b/common/hal/tests/result_processor_tests.cc
index 341b41b..6733e75 100644
--- a/common/hal/tests/result_processor_tests.cc
+++ b/common/hal/tests/result_processor_tests.cc
@@ -25,8 +25,8 @@
 namespace android {
 namespace google_camera_hal {
 
-static constexpr native_handle kDummyNativeHandle = {};
-static constexpr buffer_handle_t kDummyBufferHandle = &kDummyNativeHandle;
+static constexpr native_handle kTestNativeHandle = {};
+static constexpr buffer_handle_t kTestBufferHandle = &kTestNativeHandle;
 
 using ResultProcessorCreateFunc =
     std::function<std::unique_ptr<ResultProcessor>()>;
@@ -177,7 +177,7 @@ TEST(ResultProcessorTest, BasicResultProcessorAddPendingRequest) {
   requests[0].request.output_buffers = {StreamBuffer{}};
 
   CaptureRequest remaining_request;
-  remaining_request.output_buffers.push_back({.buffer = kDummyBufferHandle});
+  remaining_request.output_buffers.push_back({.buffer = kTestBufferHandle});
   EXPECT_NE(result_processor->AddPendingRequests(requests, remaining_request), OK)
       << "Adding a pending request with a remaining output buffer that's not"
       << "included in the request should fail.";
diff --git a/common/hal/tests/stream_buffer_cache_manager_tests.cc b/common/hal/tests/stream_buffer_cache_manager_tests.cc
index 4723e6e..3f555fe 100644
--- a/common/hal/tests/stream_buffer_cache_manager_tests.cc
+++ b/common/hal/tests/stream_buffer_cache_manager_tests.cc
@@ -68,7 +68,7 @@ class StreamBufferCacheManagerTests : public ::testing::Test {
     return OK;
   }
 
-  const StreamBufferCacheRegInfo kDummyCacheRegInfo{
+  const StreamBufferCacheRegInfo kTestCacheRegInfo{
       .request_func =
           [this](uint32_t num_buffer, std::vector<StreamBuffer>* buffers,
                  StreamBufferRequestError* status) {
@@ -100,7 +100,7 @@ class StreamBufferCacheManagerTests : public ::testing::Test {
     if (!product_support_test) {
       GTEST_SKIP();
     }
-    hal_buffer_managed_stream_ids_.insert(kDummyCacheRegInfo.stream_id);
+    hal_buffer_managed_stream_ids_.insert(kTestCacheRegInfo.stream_id);
     cache_manager_ =
         StreamBufferCacheManager::Create(hal_buffer_managed_stream_ids_);
     ASSERT_NE(cache_manager_, nullptr)
@@ -136,17 +136,17 @@ class StreamBufferCacheManagerTests : public ::testing::Test {
 // Test RegisterStream
 TEST_F(StreamBufferCacheManagerTests, RegisterStream) {
   // RegisterStream should succeed
-  status_t res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  status_t res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_EQ(res, OK) << " RegisterStream failed!" << strerror(res);
 
   // RegisterStream should fail when registering the same stream twice
-  res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_NE(res, OK) << " RegisterStream succeeded when registering the same "
                         "stream for more than once!";
 
   // RegisterStream should succeed when registering another stream
-  StreamBufferCacheRegInfo another_reg_info = kDummyCacheRegInfo;
-  another_reg_info.stream_id = kDummyCacheRegInfo.stream_id + 1;
+  StreamBufferCacheRegInfo another_reg_info = kTestCacheRegInfo;
+  another_reg_info.stream_id = kTestCacheRegInfo.stream_id + 1;
   res = cache_manager_->RegisterStream(another_reg_info);
   ASSERT_EQ(res, OK) << " RegisterStream another stream failed!"
                      << strerror(res);
@@ -156,15 +156,15 @@ TEST_F(StreamBufferCacheManagerTests, RegisterStream) {
 TEST_F(StreamBufferCacheManagerTests, NotifyProviderReadiness) {
   // Need to register stream before notifying provider readiness
   status_t res =
-      cache_manager_->NotifyProviderReadiness(kDummyCacheRegInfo.stream_id);
+      cache_manager_->NotifyProviderReadiness(kTestCacheRegInfo.stream_id);
   ASSERT_NE(res, OK) << " NotifyProviderReadiness succeeded without reigstering"
                         " the stream.";
 
-  res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_EQ(res, OK) << " RegisterStream failed!" << strerror(res);
 
   // Notify ProviderReadiness should succeed after the stream is registered
-  res = cache_manager_->NotifyProviderReadiness(kDummyCacheRegInfo.stream_id);
+  res = cache_manager_->NotifyProviderReadiness(kTestCacheRegInfo.stream_id);
   ASSERT_EQ(res, OK) << " NotifyProviderReadiness failed!" << strerror(res);
 }
 
@@ -172,28 +172,28 @@ TEST_F(StreamBufferCacheManagerTests, NotifyProviderReadiness) {
 TEST_F(StreamBufferCacheManagerTests, BasicGetStreamBuffer) {
   StreamBufferRequestResult req_result;
   // GetStreamBuffer should fail before the stream is registered.
-  status_t res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                                 &req_result);
+  status_t res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   ASSERT_NE(res, OK) << " GetStreamBuffer should fail before stream is "
                         "registered and provider readiness is notified.";
 
-  res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_EQ(res, OK) << " RegisterStream failed!" << strerror(res);
 
   // GetStreamBuffer should fail before the stream's provider is notified for
   // readiness.
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   ASSERT_NE(res, OK) << " GetStreamBuffer should fail before stream is "
                         "registered and provider readiness is notified.";
 
-  res = cache_manager_->NotifyProviderReadiness(kDummyCacheRegInfo.stream_id);
+  res = cache_manager_->NotifyProviderReadiness(kTestCacheRegInfo.stream_id);
   ASSERT_EQ(res, OK) << " NotifyProviderReadiness failed!" << strerror(res);
 
   // GetStreamBuffer should succeed after the stream is registered and its
   // provider's readiness is notified.
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   ASSERT_EQ(res, OK) << " Getting stream buffer failed!" << strerror(res);
 }
 
@@ -201,59 +201,60 @@ TEST_F(StreamBufferCacheManagerTests, BasicGetStreamBuffer) {
 TEST_F(StreamBufferCacheManagerTests, SequenceOfGetStreamBuffer) {
   const uint32_t kValidBufferRequests = 2;
   SetRemainingFulfillment(kValidBufferRequests);
-  status_t res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  status_t res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_EQ(res, OK) << " RegisterStream failed!" << strerror(res);
 
-  res = cache_manager_->NotifyProviderReadiness(kDummyCacheRegInfo.stream_id);
+  res = cache_manager_->NotifyProviderReadiness(kTestCacheRegInfo.stream_id);
   ASSERT_EQ(res, OK) << " NotifyProviderReadiness failed!" << strerror(res);
 
   // Allow enough time for the buffer allocator to refill the cache
   std::this_thread::sleep_for(kAllocateBufferFuncLatency);
 
-  // First GetStreamBuffer should succeed immediately with a non-dummy buffer
+  // First GetStreamBuffer should succeed immediately with a non-placeholder buffer
   StreamBufferRequestResult req_result;
   auto t_start = std::chrono::high_resolution_clock::now();
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   auto t_end = std::chrono::high_resolution_clock::now();
   ASSERT_EQ(res, OK) << " GetStreamBuffer failed!" << strerror(res);
   ASSERT_EQ(true, t_end - t_start < kBufferAcquireMinLatency)
       << " First buffer request should be fulfilled immediately.";
-  ASSERT_EQ(req_result.is_dummy_buffer, false)
-      << " First buffer request got dummy buffer.";
+  ASSERT_EQ(req_result.is_placeholder_buffer, false)
+      << " First buffer request got placeholder buffer.";
 
-  // Second GetStreamBuffer should succeed with a non-dummy buffer, but should
-  // happen after a gap longer than kBufferAcquireMinLatency.
+  // Second GetStreamBuffer should succeed with a non-placeholder buffer, but
+  // should happen after a gap longer than kBufferAcquireMinLatency.
   t_start = std::chrono::high_resolution_clock::now();
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   t_end = std::chrono::high_resolution_clock::now();
   ASSERT_EQ(res, OK) << " GetStreamBuffer failed!" << strerror(res);
   ASSERT_EQ(true, t_end - t_start > kBufferAcquireMinLatency)
       << " Buffer acquisition gap between two consecutive reqs is too small.";
-  ASSERT_EQ(req_result.is_dummy_buffer, false)
-      << " Second buffer request got dummy buffer.";
+  ASSERT_EQ(req_result.is_placeholder_buffer, false)
+      << " Second buffer request got placeholder buffer.";
 
   // Allow enough time for the buffer allocator to refill the cache
   std::this_thread::sleep_for(kAllocateBufferFuncLatency);
   // No more remaining fulfilment so StreamBufferCache should be either deactive
   // or inactive.
   bool is_active = false;
-  res = cache_manager_->IsStreamActive(kDummyCacheRegInfo.stream_id, &is_active);
+  res = cache_manager_->IsStreamActive(kTestCacheRegInfo.stream_id, &is_active);
   ASSERT_EQ(res, OK) << " IsStreamActive failed!" << strerror(res);
   ASSERT_EQ(is_active, false)
       << " StreamBufferCache should be either deactive or inactive!";
 
-  // Third GetStreamBuffer should succeed with a dummy buffer immediately
+  // Third GetStreamBuffer should succeed with a placeholder buffer immediately
   t_start = std::chrono::high_resolution_clock::now();
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   t_end = std::chrono::high_resolution_clock::now();
   ASSERT_EQ(res, OK) << " GetStreamBuffer failed!" << strerror(res);
   ASSERT_EQ(true, t_end - t_start < kBufferAcquireMinLatency)
-      << " Buffer acquisition gap for a dummy return should be negligible.";
-  ASSERT_EQ(req_result.is_dummy_buffer, true)
-      << " Third buffer request did not get dummy buffer.";
+      << " Buffer acquisition gap for a placeholder return should be "
+         "negligible.";
+  ASSERT_EQ(req_result.is_placeholder_buffer, true)
+      << " Third buffer request did not get placeholder buffer.";
 }
 
 // Test NotifyFlushingAll
@@ -262,26 +263,26 @@ TEST_F(StreamBufferCacheManagerTests, NotifyFlushingAll) {
   // GetStreamBuffer happens after the NotifyFlushingAll.
   const uint32_t kValidBufferRequests = 3;
   SetRemainingFulfillment(kValidBufferRequests);
-  status_t res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  status_t res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_EQ(res, OK) << " RegisterStream failed!" << strerror(res);
 
-  res = cache_manager_->NotifyProviderReadiness(kDummyCacheRegInfo.stream_id);
+  res = cache_manager_->NotifyProviderReadiness(kTestCacheRegInfo.stream_id);
   ASSERT_EQ(res, OK) << " NotifyProviderReadiness failed!" << strerror(res);
 
   // Allow enough time for the buffer allocator to refill the cache
   std::this_thread::sleep_for(kAllocateBufferFuncLatency);
 
-  // First GetStreamBuffer should succeed immediately with a non-dummy buffer
+  // First GetStreamBuffer should succeed immediately with a non-placeholder buffer
   StreamBufferRequestResult req_result;
   auto t_start = std::chrono::high_resolution_clock::now();
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   auto t_end = std::chrono::high_resolution_clock::now();
   ASSERT_EQ(res, OK) << " GetStreamBuffer failed!" << strerror(res);
   ASSERT_EQ(true, t_end - t_start < kBufferAcquireMinLatency)
       << " First buffer request should be fulfilled immediately.";
-  ASSERT_EQ(req_result.is_dummy_buffer, false)
-      << " First buffer request got dummy buffer.";
+  ASSERT_EQ(req_result.is_placeholder_buffer, false)
+      << " First buffer request got placeholder buffer.";
 
   // Allow enough time for the buffer allocator to refill the cache
   std::this_thread::sleep_for(kAllocateBufferFuncLatency);
@@ -296,41 +297,41 @@ TEST_F(StreamBufferCacheManagerTests, NotifyFlushingAll) {
 
   // GetStreamBuffer should still be able to re-trigger cache to refill after
   // NotifyFlushingAll is called.
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
   ASSERT_EQ(res, OK) << " GetStreamBuffer failed!" << strerror(res);
-  ASSERT_EQ(req_result.is_dummy_buffer, false)
-      << " Buffer request got dummy buffer.";
+  ASSERT_EQ(req_result.is_placeholder_buffer, false)
+      << " Buffer request got placeholder buffer.";
 }
 
 // Test IsStreamActive
 TEST_F(StreamBufferCacheManagerTests, IsStreamActive) {
   const uint32_t kValidBufferRequests = 1;
   SetRemainingFulfillment(kValidBufferRequests);
-  status_t res = cache_manager_->RegisterStream(kDummyCacheRegInfo);
+  status_t res = cache_manager_->RegisterStream(kTestCacheRegInfo);
   ASSERT_EQ(res, OK) << " RegisterStream failed!" << strerror(res);
 
-  res = cache_manager_->NotifyProviderReadiness(kDummyCacheRegInfo.stream_id);
+  res = cache_manager_->NotifyProviderReadiness(kTestCacheRegInfo.stream_id);
   ASSERT_EQ(res, OK) << " NotifyProviderReadiness failed!" << strerror(res);
 
   // Allow enough time for the buffer allocator to refill the cache
   std::this_thread::sleep_for(kAllocateBufferFuncLatency);
 
-  // StreamBufferCache should be valid before dummy buffer is used.
+  // StreamBufferCache should be valid before placeholder buffer is used.
   bool is_active = false;
-  res = cache_manager_->IsStreamActive(kDummyCacheRegInfo.stream_id, &is_active);
+  res = cache_manager_->IsStreamActive(kTestCacheRegInfo.stream_id, &is_active);
   ASSERT_EQ(res, OK) << " IsStreamActive failed!" << strerror(res);
   ASSERT_EQ(is_active, true) << " StreamBufferCache should be active!";
 
   StreamBufferRequestResult req_result;
-  res = cache_manager_->GetStreamBuffer(kDummyCacheRegInfo.stream_id,
-                                        &req_result);
+  res =
+      cache_manager_->GetStreamBuffer(kTestCacheRegInfo.stream_id, &req_result);
 
   // Allow enough time for buffer provider to finish its job
   std::this_thread::sleep_for(kAllocateBufferFuncLatency);
   // There is only one valid buffer request. So the stream will be deactive
   // after the GetStreamBuffer(when the cache tries the second buffer request).
-  res = cache_manager_->IsStreamActive(kDummyCacheRegInfo.stream_id, &is_active);
+  res = cache_manager_->IsStreamActive(kTestCacheRegInfo.stream_id, &is_active);
   ASSERT_EQ(res, OK) << " IsStreamActive failed!" << strerror(res);
   ASSERT_EQ(is_active, false) << " StreamBufferCache should be deactived!";
 }
diff --git a/common/hal/tests/test_utils.cc b/common/hal/tests/test_utils.cc
index 6ffc7dd..fe5d26a 100644
--- a/common/hal/tests/test_utils.cc
+++ b/common/hal/tests/test_utils.cc
@@ -26,10 +26,10 @@ namespace android {
 namespace google_camera_hal {
 namespace test_utils {
 
-void GetDummyPreviewStream(Stream* stream, uint32_t width, uint32_t height,
-                           bool is_physical_camera_stream = false,
-                           uint32_t physical_camera_id = 0,
-                           uint32_t stream_id = 0) {
+void GetTestPreviewStream(Stream* stream, uint32_t width, uint32_t height,
+                          bool is_physical_camera_stream = false,
+                          uint32_t physical_camera_id = 0,
+                          uint32_t stream_id = 0) {
   ASSERT_NE(stream, nullptr);
 
   *stream = {};
@@ -50,7 +50,7 @@ void GetPreviewOnlyStreamConfiguration(StreamConfiguration* config,
   ASSERT_NE(config, nullptr);
 
   Stream preview_stream = {};
-  GetDummyPreviewStream(&preview_stream, width, height);
+  GetTestPreviewStream(&preview_stream, width, height);
 
   *config = {};
   config->streams.push_back(preview_stream);
@@ -69,9 +69,9 @@ void GetPhysicalPreviewStreamConfiguration(
   int32_t stream_id = 0;
   for (auto& camera_id : physical_camera_ids) {
     Stream preview_stream;
-    GetDummyPreviewStream(&preview_stream, width, height,
-                          /*is_physical_camera_stream=*/true, camera_id,
-                          stream_id++);
+    GetTestPreviewStream(&preview_stream, width, height,
+                         /*is_physical_camera_stream=*/true, camera_id,
+                         stream_id++);
     config->streams.push_back(preview_stream);
   }
 }
diff --git a/common/hal/tests/vendor_tag_tests.cc b/common/hal/tests/vendor_tag_tests.cc
index 3502a01..99bdccd 100644
--- a/common/hal/tests/vendor_tag_tests.cc
+++ b/common/hal/tests/vendor_tag_tests.cc
@@ -35,26 +35,25 @@ TEST(CameraVendorTagTest, TestCharacteristics) {
   auto hal_metadata = HalCameraMetadata::Create(kNumEntries, kDataBytes);
   ASSERT_NE(hal_metadata, nullptr) << "Creating hal_metadata failed.";
 
-  std::vector<uint32_t> dummy_keys = {
-      VendorTagIds::kLogicalCamDefaultPhysicalId};
-  status_t res = hal_metadata->Set(
-      ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
-      reinterpret_cast<int32_t*>(dummy_keys.data()), dummy_keys.size());
+  std::vector<uint32_t> test_keys = {VendorTagIds::kLogicalCamDefaultPhysicalId};
+  status_t res = hal_metadata->Set(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
+                                   reinterpret_cast<int32_t*>(test_keys.data()),
+                                   test_keys.size());
   ASSERT_EQ(res, OK);
 
   res = hal_metadata->Set(ANDROID_REQUEST_AVAILABLE_RESULT_KEYS,
-                          reinterpret_cast<int32_t*>(dummy_keys.data()),
-                          dummy_keys.size());
+                          reinterpret_cast<int32_t*>(test_keys.data()),
+                          test_keys.size());
   ASSERT_EQ(res, OK);
 
   res = hal_metadata->Set(ANDROID_REQUEST_AVAILABLE_SESSION_KEYS,
-                          reinterpret_cast<int32_t*>(dummy_keys.data()),
-                          dummy_keys.size());
+                          reinterpret_cast<int32_t*>(test_keys.data()),
+                          test_keys.size());
   ASSERT_EQ(res, OK);
 
   res = hal_metadata->Set(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
-                          reinterpret_cast<int32_t*>(dummy_keys.data()),
-                          dummy_keys.size());
+                          reinterpret_cast<int32_t*>(test_keys.data()),
+                          test_keys.size());
   ASSERT_EQ(res, OK);
 
   res = hal_vendor_tag_utils::ModifyCharacteristicsKeys(hal_metadata.get());
diff --git a/common/hal/utils/stream_buffer_cache_manager.cc b/common/hal/utils/stream_buffer_cache_manager.cc
index 71a922e..7468046 100644
--- a/common/hal/utils/stream_buffer_cache_manager.cc
+++ b/common/hal/utils/stream_buffer_cache_manager.cc
@@ -83,8 +83,8 @@ std::unique_ptr<StreamBufferCacheManager> StreamBufferCacheManager::Create(
     return nullptr;
   }
 
-  manager->dummy_buffer_allocator_ = GrallocBufferAllocator::Create();
-  if (manager->dummy_buffer_allocator_ == nullptr) {
+  manager->placeholder_buffer_allocator_ = GrallocBufferAllocator::Create();
+  if (manager->placeholder_buffer_allocator_ == nullptr) {
     ALOGE("%s: Failed to create gralloc buffer allocator", __FUNCTION__);
     return nullptr;
   }
@@ -246,7 +246,7 @@ status_t StreamBufferCacheManager::AddStreamBufferCacheLocked(
     const StreamBufferCacheRegInfo& reg_info) {
   auto stream_buffer_cache = StreamBufferCacheManager::StreamBufferCache::Create(
       reg_info, [this] { this->NotifyThreadWorkload(); },
-      dummy_buffer_allocator_.get());
+      placeholder_buffer_allocator_.get());
   if (stream_buffer_cache == nullptr) {
     ALOGE("%s: Failed to create StreamBufferCache for stream %d", __FUNCTION__,
           reg_info.stream_id);
@@ -313,16 +313,16 @@ std::unique_ptr<StreamBufferCacheManager::StreamBufferCache>
 StreamBufferCacheManager::StreamBufferCache::Create(
     const StreamBufferCacheRegInfo& reg_info,
     NotifyManagerThreadWorkloadFunc notify,
-    IHalBufferAllocator* dummy_buffer_allocator) {
-  if (notify == nullptr || dummy_buffer_allocator == nullptr) {
-    ALOGE("%s: notify is nullptr or dummy_buffer_allocator is nullptr.",
+    IHalBufferAllocator* placeholder_buffer_allocator) {
+  if (notify == nullptr || placeholder_buffer_allocator == nullptr) {
+    ALOGE("%s: notify is nullptr or placeholder_buffer_allocator is nullptr.",
           __FUNCTION__);
     return nullptr;
   }
 
   auto cache = std::unique_ptr<StreamBufferCacheManager::StreamBufferCache>(
-      new StreamBufferCacheManager::StreamBufferCache(reg_info, notify,
-                                                      dummy_buffer_allocator));
+      new StreamBufferCacheManager::StreamBufferCache(
+          reg_info, notify, placeholder_buffer_allocator));
   if (cache == nullptr) {
     ALOGE("%s: Failed to create stream buffer cache.", __FUNCTION__);
     return nullptr;
@@ -334,11 +334,11 @@ StreamBufferCacheManager::StreamBufferCache::Create(
 StreamBufferCacheManager::StreamBufferCache::StreamBufferCache(
     const StreamBufferCacheRegInfo& reg_info,
     NotifyManagerThreadWorkloadFunc notify,
-    IHalBufferAllocator* dummy_buffer_allocator)
+    IHalBufferAllocator* placeholder_buffer_allocator)
     : cache_info_(reg_info) {
   std::lock_guard<std::mutex> lock(cache_access_mutex_);
   notify_for_workload_ = notify;
-  dummy_buffer_allocator_ = dummy_buffer_allocator;
+  placeholder_buffer_allocator_ = placeholder_buffer_allocator;
 }
 
 status_t StreamBufferCacheManager::StreamBufferCache::UpdateCache(
@@ -377,14 +377,14 @@ status_t StreamBufferCacheManager::StreamBufferCache::GetBuffer(
 
   // 1. check if the cache is deactived
   if (stream_deactived_) {
-    res->is_dummy_buffer = true;
-    res->buffer = dummy_buffer_;
+    res->is_placeholder_buffer = true;
+    res->buffer = placeholder_buffer_;
     return OK;
   }
 
   // 2. check if there is any buffer available in the cache. If not, try
   // to wait for a short period and check again. In case of timeout, use the
-  // dummy buffer instead.
+  // placeholder buffer instead.
   if (cached_buffers_.empty()) {
     // In case the GetStreamBufer is called after NotifyFlushingAll, this will
     // be the first event that should trigger the dedicated thread to restart
@@ -405,21 +405,21 @@ status_t StreamBufferCacheManager::StreamBufferCache::GetBuffer(
     }
   }
 
-  // 3. use dummy buffer if the cache is still empty
+  // 3. use placeholder buffer if the cache is still empty
   if (cached_buffers_.empty()) {
-    // Only allocate dummy buffer for the first time
-    if (dummy_buffer_.buffer == nullptr) {
-      status_t result = AllocateDummyBufferLocked();
+    // Only allocate placeholder buffer for the first time
+    if (placeholder_buffer_.buffer == nullptr) {
+      status_t result = AllocatePlaceholderBufferLocked();
       if (result != OK) {
-        ALOGE("%s: Allocate dummy buffer failed.", __FUNCTION__);
+        ALOGE("%s: Allocate placeholder buffer failed.", __FUNCTION__);
         return UNKNOWN_ERROR;
       }
     }
-    res->is_dummy_buffer = true;
-    res->buffer = dummy_buffer_;
+    res->is_placeholder_buffer = true;
+    res->buffer = placeholder_buffer_;
     return OK;
   } else {
-    res->is_dummy_buffer = false;
+    res->is_placeholder_buffer = false;
     res->buffer = cached_buffers_.back();
     cached_buffers_.pop_back();
   }
@@ -452,7 +452,7 @@ status_t StreamBufferCacheManager::StreamBufferCache::FlushLocked(
 
   if (cached_buffers_.empty()) {
     ALOGV("%s: Stream buffer cache is already empty.", __FUNCTION__);
-    ReleaseDummyBufferLocked();
+    ReleasePlaceholderBufferLocked();
     return OK;
   }
 
@@ -463,7 +463,7 @@ status_t StreamBufferCacheManager::StreamBufferCache::FlushLocked(
   }
 
   cached_buffers_.clear();
-  ReleaseDummyBufferLocked();
+  ReleasePlaceholderBufferLocked();
 
   return OK;
 }
@@ -497,9 +497,9 @@ status_t StreamBufferCacheManager::StreamBufferCache::Refill() {
   }
 
   // Requesting buffer from the provider can take long(e.g. even > 1sec),
-  // consumer should not be blocked by this procedure and can get dummy buffer
-  // to unblock other pipelines. Thus, cache_access_mutex_ doesn't need to be
-  // locked here.
+  // consumer should not be blocked by this procedure and can get placeholder
+  // buffer to unblock other pipelines. Thus, cache_access_mutex_ doesn't need
+  // to be locked here.
   std::vector<StreamBuffer> buffers;
   StreamBufferRequestError req_status = StreamBufferRequestError::kOk;
   status_t res =
@@ -507,9 +507,9 @@ status_t StreamBufferCacheManager::StreamBufferCache::Refill() {
 
   std::unique_lock<std::mutex> cache_lock(cache_access_mutex_);
   if (res != OK) {
-    status_t result = AllocateDummyBufferLocked();
+    status_t result = AllocatePlaceholderBufferLocked();
     if (result != OK) {
-      ALOGE("%s: Allocate dummy buffer failed.", __FUNCTION__);
+      ALOGE("%s: Allocate placeholder buffer failed.", __FUNCTION__);
       return UNKNOWN_ERROR;
     }
   }
@@ -531,7 +531,7 @@ status_t StreamBufferCacheManager::StreamBufferCache::Refill() {
             "%s: Stream %d is disconnected or unknown error observed."
             "This stream is marked as inactive.",
             __FUNCTION__, cache_info_.stream_id);
-        ALOGI("%s: Stream %d begin to use dummy buffer.", __FUNCTION__,
+        ALOGI("%s: Stream %d begin to use placeholder buffer.", __FUNCTION__,
               cache_info_.stream_id);
         stream_deactived_ = true;
         break;
@@ -560,9 +560,10 @@ bool StreamBufferCacheManager::StreamBufferCache::RefillableLocked() const {
   return cached_buffers_.size() < cache_info_.num_buffers_to_cache;
 }
 
-status_t StreamBufferCacheManager::StreamBufferCache::AllocateDummyBufferLocked() {
-  if (dummy_buffer_.buffer != nullptr) {
-    ALOGW("%s: Dummy buffer has already been allocated.", __FUNCTION__);
+status_t
+StreamBufferCacheManager::StreamBufferCache::AllocatePlaceholderBufferLocked() {
+  if (placeholder_buffer_.buffer != nullptr) {
+    ALOGW("%s: placeholder buffer has already been allocated.", __FUNCTION__);
     return OK;
   }
 
@@ -578,10 +579,11 @@ status_t StreamBufferCacheManager::StreamBufferCache::AllocateDummyBufferLocked(
   };
   std::vector<buffer_handle_t> buffers;
 
-  status_t res =
-      dummy_buffer_allocator_->AllocateBuffers(hal_buffer_descriptor, &buffers);
+  status_t res = placeholder_buffer_allocator_->AllocateBuffers(
+      hal_buffer_descriptor, &buffers);
   if (res != OK) {
-    ALOGE("%s: Dummy buffer allocator AllocateBuffers failed.", __FUNCTION__);
+    ALOGE("%s: placeholder buffer allocator AllocateBuffers failed.",
+          __FUNCTION__);
     return res;
   }
 
@@ -589,20 +591,20 @@ status_t StreamBufferCacheManager::StreamBufferCache::AllocateDummyBufferLocked(
     ALOGE("%s: Not enough buffers allocated.", __FUNCTION__);
     return NO_MEMORY;
   }
-  dummy_buffer_.stream_id = cache_info_.stream_id;
-  dummy_buffer_.buffer = buffers[0];
-  ALOGI("%s: [sbc] Dummy buffer allocated: strm %d buffer %p", __FUNCTION__,
-        dummy_buffer_.stream_id, dummy_buffer_.buffer);
+  placeholder_buffer_.stream_id = cache_info_.stream_id;
+  placeholder_buffer_.buffer = buffers[0];
+  ALOGI("%s: [sbc] placeholder buffer allocated: strm %d buffer %p",
+        __FUNCTION__, placeholder_buffer_.stream_id, placeholder_buffer_.buffer);
 
   return OK;
 }
 
-void StreamBufferCacheManager::StreamBufferCache::ReleaseDummyBufferLocked() {
-  // Release dummy buffer if ever acquired from the dummy_buffer_allocator_.
-  if (dummy_buffer_.buffer != nullptr) {
-    std::vector<buffer_handle_t> buffers(1, dummy_buffer_.buffer);
-    dummy_buffer_allocator_->FreeBuffers(&buffers);
-    dummy_buffer_.buffer = nullptr;
+void StreamBufferCacheManager::StreamBufferCache::ReleasePlaceholderBufferLocked() {
+  // Release placeholder buffer if ever acquired from the placeholder_buffer_allocator_.
+  if (placeholder_buffer_.buffer != nullptr) {
+    std::vector<buffer_handle_t> buffers(1, placeholder_buffer_.buffer);
+    placeholder_buffer_allocator_->FreeBuffers(&buffers);
+    placeholder_buffer_.buffer = nullptr;
   }
 }
 
diff --git a/common/hal/utils/stream_buffer_cache_manager.h b/common/hal/utils/stream_buffer_cache_manager.h
index 22e71a4..2d59448 100644
--- a/common/hal/utils/stream_buffer_cache_manager.h
+++ b/common/hal/utils/stream_buffer_cache_manager.h
@@ -81,11 +81,11 @@ struct StreamBufferCacheRegInfo {
 // Contains all information returned to the client by GetStreamBuffer function.
 //
 struct StreamBufferRequestResult {
-  // Whether the returned StreamBuffer is a dummy buffer or an actual buffer
-  // obtained from the buffer provider. Client should return the buffer from
-  // providers through the normal result processing functions. There is no need
-  // for clients to return or recycle a dummy buffer returned.
-  bool is_dummy_buffer = false;
+  // Whether the returned StreamBuffer is a placeholder buffer or an actual
+  // buffer obtained from the buffer provider. Client should return the buffer
+  // from providers through the normal result processing functions. There is no
+  // need for clients to return or recycle a placeholder buffer returned.
+  bool is_placeholder_buffer = false;
   // StreamBuffer obtained
   StreamBuffer buffer;
 };
@@ -97,9 +97,9 @@ struct StreamBufferRequestResult {
 // streams. A client needs to register a stream first. It then needs to signal
 // the manager to start caching buffers for that stream. It can then get stream
 // buffers from the manager. The buffers obtained, not matter buffers from buf
-// provider or a dummy buffer, do not need to be returned to the manager. The
-// client should notify the manager to flush all buffers cached before a session
-// can successfully end.
+// provider or a placeholder buffer, do not need to be returned to the manager.
+// The client should notify the manager to flush all buffers cached before a
+// session can successfully end.
 //
 // The manager uses a dedicated thread to asynchronously request/return buffers
 // while clients threads fetch buffers and notify for a change of state.
@@ -126,8 +126,8 @@ class StreamBufferCacheManager {
   // Caller owns the StreamBufferRequestResult and should keep it valid until
   // the function is returned. The ownership of the fences of the StreamBuffer
   // in the StreamBufferRequestResult is transferred to the caller after this
-  // function is returned. In case dummy buffer is returned, the fences are all
-  // nullptr.
+  // function is returned. In case placeholder buffer is returned, the fences
+  // are all nullptr.
   status_t GetStreamBuffer(int32_t stream_id, StreamBufferRequestResult* res);
 
   // Client calls this function to signal the manager to flush all buffers
@@ -138,9 +138,9 @@ class StreamBufferCacheManager {
 
   // Whether stream buffer cache manager can still acquire buffer from the
   // provider successfully(e.g. if a stream is abandoned by the framework, this
-  // returns false). Once a stream is inactive, dummy buffer will be used in all
-  // following GetStreamBuffer calling. Calling NotifyFlushingAll does not make
-  // a change in this case.
+  // returns false). Once a stream is inactive, placeholder buffer will be used
+  // in all following GetStreamBuffer calling. Calling NotifyFlushingAll does
+  // not make a change in this case.
   status_t IsStreamActive(int32_t stream_id, bool* is_active);
 
  protected:
@@ -164,12 +164,12 @@ class StreamBufferCacheManager {
     // for and interfaces for buffer return and request.
     // notify is the function for each stream buffer cache to notify the manager
     // for new thread loop work load.
-    // dummy_buffer_allocator allocates the dummy buffer needed when buffer
-    // provider can not fulfill a buffer request any more.
+    // placeholder_buffer_allocator allocates the placeholder buffer needed when
+    // buffer provider can not fulfill a buffer request any more.
     static std::unique_ptr<StreamBufferCache> Create(
         const StreamBufferCacheRegInfo& reg_info,
         NotifyManagerThreadWorkloadFunc notify,
-        IHalBufferAllocator* dummy_buffer_allocator);
+        IHalBufferAllocator* placeholder_buffer_allocator);
 
     virtual ~StreamBufferCache() = default;
 
@@ -179,8 +179,8 @@ class StreamBufferCacheManager {
     // is true.
     status_t UpdateCache(bool forced_flushing);
 
-    // Get a buffer for the client. The buffer returned can be a dummy buffer,
-    // in which case, the is_dummy_buffer field in res will be true.
+    // Get a buffer for the client. The buffer returned can be a placeholder
+    // buffer, in which case, the is_ field in res will be true.
     status_t GetBuffer(StreamBufferRequestResult* res);
 
     // Activate or deactivate the stream buffer cache manager. The stream
@@ -199,7 +199,7 @@ class StreamBufferCacheManager {
    protected:
     StreamBufferCache(const StreamBufferCacheRegInfo& reg_info,
                       NotifyManagerThreadWorkloadFunc notify,
-                      IHalBufferAllocator* dummy_buffer_allocator);
+                      IHalBufferAllocator* placeholder_buffer_allocator);
 
    private:
     // Flush all buffers acquired from the buffer provider. Return the acquired
@@ -210,7 +210,7 @@ class StreamBufferCacheManager {
     // Refill the cached buffers by trying to acquire buffers from the buffer
     // provider using request_func. If the provider can not fulfill the request
     // by returning an empty buffer vector. The stream buffer cache will be
-    // providing dummy buffer for all following requests.
+    // providing placeholder buffer for all following requests.
     // TODO(b/136107942): Only one thread(currently the manager's workload thread)
     //                    should call this function to avoid unexpected racing
     //                    condition. This will be fixed by taking advantage of
@@ -222,13 +222,13 @@ class StreamBufferCacheManager {
     // The cache_access_mutex_ must be locked when calling this function.
     bool RefillableLocked() const;
 
-    // Allocate dummy buffer for this stream buffer cache. The
+    // Allocate placeholder buffer for this stream buffer cache. The
     // cache_access_mutex_ needs to be locked before calling this function.
-    status_t AllocateDummyBufferLocked();
+    status_t AllocatePlaceholderBufferLocked();
 
-    // Release allocated dummy buffer when StreamBufferCache exiting.
+    // Release allocated placeholder buffer when StreamBufferCache exiting.
     // The cache_access_mutex_ needs to be locked before calling this function.
-    void ReleaseDummyBufferLocked();
+    void ReleasePlaceholderBufferLocked();
 
     // Any access to the cache content must be guarded by this mutex.
     std::mutex cache_access_mutex_;
@@ -241,19 +241,19 @@ class StreamBufferCacheManager {
     // Whether the stream this cache is for has been deactived. The stream is
     // labeled as deactived when kStreamDisconnected or kUnknownError is
     // returned by a request_func_. In this case, all following request_func_ is
-    // expected to raise the same error. So dummy buffer will be used directly
-    // without wasting the effort to call request_func_ again. Error code
-    // kNoBufferAvailable and kMaxBufferExceeded should not cause this to be
-    // labeled as true. The next UpdateCache status should still try to refill
-    // the cache.
+    // expected to raise the same error. So placeholder buffer will be used
+    // directly without wasting the effort to call request_func_ again. Error
+    // code kNoBufferAvailable and kMaxBufferExceeded should not cause this to
+    // be labeled as true. The next UpdateCache status should still try to
+    // refill the cache.
     bool stream_deactived_ = false;
-    // Dummy StreamBuffer reserved for errorneous situation. In case there is
-    // not available cached buffers, this dummy buffer is used to allow the
-    // client to continue its ongoing work without crashing. This dummy buffer
-    // is reused and should not be returned to the buf provider. If this buffer
-    // is returned, the is_dummy_buffer_ flag in the BufferRequestResult must be
-    // set to true.
-    StreamBuffer dummy_buffer_;
+    // Placeholder StreamBuffer reserved for errorneous situation. In case there
+    // is not available cached buffers, this placeholder buffer is used to allow
+    // the client to continue its ongoing work without crashing. This
+    // placeholder buffer is reused and should not be returned to the buf
+    // provider. If this buffer is returned, the is__ flag in the
+    // BufferRequestResult must be set to true.
+    StreamBuffer placeholder_buffer_;
     // StreamBufferCacheManager does not refill a StreamBufferCache until this
     // is set true by the client. Client should set this flag to true after the
     // buffer provider (e.g. framework) is ready to handle buffer requests, or
@@ -262,9 +262,9 @@ class StreamBufferCacheManager {
     bool is_active_ = false;
     // Interface to notify the parent manager for new threadloop workload.
     NotifyManagerThreadWorkloadFunc notify_for_workload_ = nullptr;
-    // Allocator of the dummy buffer for this stream. The stream buffer cache
+    // Allocator of the placeholder buffer for this stream. The stream buffer cache
     // manager owns this throughout the life cycle of this stream buffer cahce.
-    IHalBufferAllocator* dummy_buffer_allocator_ = nullptr;
+    IHalBufferAllocator* placeholder_buffer_allocator_ = nullptr;
   };
 
   // Add stream buffer cache. Lock caches_map_mutex_ before calling this func.
@@ -303,9 +303,10 @@ class StreamBufferCacheManager {
   // Whether a processing request has been notified. Change to this must be
   // guarded by request_return_mutex_;
   bool has_new_workload_ = false;
-  // The dummy buffer allocator allocates the dummy buffer. It only allocates
-  // the dummy buffer when a stream buffer cache is NotifyProviderReadiness.
-  std::unique_ptr<IHalBufferAllocator> dummy_buffer_allocator_;
+  // The placeholder buffer allocator allocates the placeholder buffer. It only
+  // allocates the placeholder buffer when a stream buffer cache is
+  // NotifyProviderReadiness.
+  std::unique_ptr<IHalBufferAllocator> placeholder_buffer_allocator_;
 
   // Guards NotifyFlushingAll. In case the workload thread is processing workload,
   // the NotifyFlushingAll calling should wait until workload loop is done. This
diff --git a/common/profiler/profiler.cc b/common/profiler/profiler.cc
index e68c22d..a8cafee 100644
--- a/common/profiler/profiler.cc
+++ b/common/profiler/profiler.cc
@@ -608,11 +608,11 @@ class ProfilerStopwatchImpl : public ProfilerImpl {
   }
 };
 
-// Dummpy profiler class.
-class ProfilerDummy : public Profiler {
+// Empty profiler class.
+class ProfilerNoop : public Profiler {
  public:
-  ProfilerDummy(){};
-  ~ProfilerDummy(){};
+  ProfilerNoop() {};
+  ~ProfilerNoop() {};
 
   void SetUseCase(std::string) override final{};
   void SetDumpFilePrefix(const std::string&) override final{};
@@ -635,7 +635,7 @@ std::shared_ptr<Profiler> Profiler::Create(int option) {
   SetPropFlag flag = static_cast<SetPropFlag>(option);
 
   if (flag == SetPropFlag::kDisable) {
-    return std::make_shared<ProfilerDummy>();
+    return std::make_shared<ProfilerNoop>();
   } else if (flag & SetPropFlag::kStopWatch) {
     return std::make_shared<ProfilerStopwatchImpl>(flag);
   } else {
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.cpp b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.cpp
index 4eac9cc..cca1740 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.cpp
@@ -583,6 +583,14 @@ status_t EmulatedCameraDeviceInfo::InitializeControlAEDefaults() {
     ALOGE("%s: No available AE modes!", __FUNCTION__);
     return BAD_VALUE;
   }
+
+  ret = static_metadata_->Get(ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES, &entry);
+  if (ret == OK) {
+    available_ae_priority_modes_.insert(entry.data.u8, entry.data.u8 + entry.count);
+  } else {
+    ALOGV("%s: No available AE priority modes!", __FUNCTION__);
+  }
+
   // On mode must always be present
   if (available_ae_modes_.find(ANDROID_CONTROL_AE_MODE_ON) ==
       available_ae_modes_.end()) {
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.h b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.h
index d203412..b6aea4b 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.h
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraDeviceInfo.h
@@ -165,6 +165,7 @@ struct EmulatedCameraDeviceInfo {
 
   std::set<uint8_t> available_control_modes_;
   std::set<uint8_t> available_ae_modes_;
+  std::set<uint8_t> available_ae_priority_modes_;
   std::set<uint8_t> available_af_modes_;
   std::set<uint8_t> available_awb_modes_;
   std::set<uint8_t> available_scenes_;
@@ -192,6 +193,7 @@ struct EmulatedCameraDeviceInfo {
   uint8_t sensor_pixel_mode_ = ANDROID_SENSOR_PIXEL_MODE_DEFAULT;
   uint8_t scene_mode_ = ANDROID_CONTROL_SCENE_MODE_DISABLED;
   uint8_t ae_mode_ = ANDROID_CONTROL_AE_MODE_ON;
+  uint8_t ae_priority_mode_ = ANDROID_CONTROL_AE_PRIORITY_MODE_OFF;
   uint8_t awb_mode_ = ANDROID_CONTROL_AWB_MODE_AUTO;
   uint8_t af_mode_ = ANDROID_CONTROL_AF_MODE_AUTO;
   uint8_t ae_lock_ = ANDROID_CONTROL_AE_LOCK_OFF;
diff --git a/devices/EmulatedCamera/hwl/EmulatedCameraProviderHWLImpl.cpp b/devices/EmulatedCamera/hwl/EmulatedCameraProviderHWLImpl.cpp
index 7eb7743..3126bea 100644
--- a/devices/EmulatedCamera/hwl/EmulatedCameraProviderHWLImpl.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedCameraProviderHWLImpl.cpp
@@ -851,7 +851,7 @@ void EmulatedCameraProviderHwlImpl::WaitForStatusCallbackFuture() {
   {
     std::lock_guard<std::mutex> lock(status_callback_future_lock_);
     if (!status_callback_future_.valid()) {
-      // If there is no future pending, construct a dummy one.
+      // If there is no future pending, construct an empty one.
       status_callback_future_ = std::async([]() { return; });
     }
   }
diff --git a/devices/EmulatedCamera/hwl/EmulatedRequestState.cpp b/devices/EmulatedCamera/hwl/EmulatedRequestState.cpp
index e9ad0be..d100d12 100644
--- a/devices/EmulatedCamera/hwl/EmulatedRequestState.cpp
+++ b/devices/EmulatedCamera/hwl/EmulatedRequestState.cpp
@@ -542,6 +542,19 @@ status_t EmulatedRequestState::ProcessAE() {
       ALOGE("%s: Failed during AE compensation: %d, (%s)", __FUNCTION__, ret,
             strerror(-ret));
     }
+    if (info.ae_priority_mode_ == ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY) {
+      auto ret = request_settings_->Get(ANDROID_SENSOR_EXPOSURE_TIME, &entry);
+      if ((ret == OK) && (entry.count == 1)) {
+        info.sensor_exposure_time_  = GetExposureTimeClampToRange(entry.data.i64[0]);
+      }
+    }
+
+    if (info.ae_priority_mode_ == ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY) {
+      auto ret = request_settings_->Get(ANDROID_SENSOR_SENSITIVITY, &entry);
+      if ((ret == OK) && (entry.count == 1)) {
+        info.sensor_sensitivity_ = GetSensitivityClampToRange(entry.data.i32[0]);
+      }
+    }
   } else {
     ALOGI(
         "%s: No emulation for current AE mode using previous sensor settings!",
@@ -582,6 +595,34 @@ status_t EmulatedRequestState::ProcessAE() {
   return OK;
 }
 
+int EmulatedRequestState::GetSensitivityClampToRange(uint32_t sensitivity) {
+  auto& info = *device_info_;
+  uint32_t min_sensitivity = info.sensor_sensitivity_range_.first;
+  uint32_t max_sensitivity = info.sensor_sensitivity_range_.second;
+
+  if ((sensitivity < min_sensitivity) ||
+      (sensitivity > max_sensitivity)) {
+    ALOGW("%s: Sensor sensitivity %d not within supported range[%d, %d]",
+        __FUNCTION__, sensitivity, min_sensitivity, max_sensitivity);
+  }
+
+  return std::max(min_sensitivity, std::min(max_sensitivity, sensitivity));
+}
+
+int EmulatedRequestState::GetExposureTimeClampToRange(uint32_t exposure) {
+  auto& info = *device_info_;
+  uint32_t min_exposure = info.sensor_exposure_time_range_.first;
+  uint32_t max_exposure = info.sensor_exposure_time_range_.second;
+
+  if ((exposure < min_exposure) ||
+      (exposure > max_exposure)) {
+    ALOGW("%s: Sensor exposure time %d not within supported range[%d, %d]",
+        __FUNCTION__, exposure, min_exposure, max_exposure);
+  }
+
+  return std::max(min_exposure, std::min(max_exposure, exposure));
+}
+
 status_t EmulatedRequestState::InitializeSensorSettings(
     std::unique_ptr<HalCameraMetadata> request_settings,
     uint32_t override_frame_number,
@@ -775,6 +816,16 @@ status_t EmulatedRequestState::InitializeSensorSettings(
       }
     }
 
+    ret = request_settings_->Get(ANDROID_CONTROL_AE_PRIORITY_MODE, &entry);
+    if ((ret == OK) && (entry.count == 1)) {
+      if (info.available_ae_priority_modes_.find(entry.data.u8[0]) !=
+          info.available_ae_priority_modes_.end()) {
+        info.ae_priority_mode_ = entry.data.u8[0];
+      } else {
+        ALOGE("%s: Unsupported AE priority mode! Using last valid mode!", __FUNCTION__);
+      }
+    }
+
     ret = request_settings_->Get(ANDROID_CONTROL_AWB_MODE, &entry);
     if ((ret == OK) && (entry.count == 1)) {
       if (info.available_awb_modes_.find(entry.data.u8[0]) !=
@@ -919,6 +970,17 @@ std::unique_ptr<HwlPipelineResult> EmulatedRequestState::InitializeResult(
   result->result_metadata->Set(ANDROID_CONTROL_AWB_MODE, &info.awb_mode_, 1);
   result->result_metadata->Set(ANDROID_CONTROL_AWB_STATE, &info.awb_state_, 1);
   result->result_metadata->Set(ANDROID_CONTROL_AE_MODE, &info.ae_mode_, 1);
+
+  if (info.ae_mode_ == ANDROID_CONTROL_AE_MODE_OFF) {
+    // AE Priority mode should not work with AE mode OFF
+    uint8_t ae_priority_mode_off = ANDROID_CONTROL_AE_PRIORITY_MODE_OFF;
+    result->result_metadata->Set(ANDROID_CONTROL_AE_PRIORITY_MODE,
+            &ae_priority_mode_off, 1);
+  } else {
+    result->result_metadata->Set(ANDROID_CONTROL_AE_PRIORITY_MODE,
+            &info.ae_priority_mode_, 1);
+  }
+
   result->result_metadata->Set(ANDROID_CONTROL_AE_STATE, &info.ae_state_, 1);
   // If the overriding frame number isn't larger than current frame number,
   // use 0.
diff --git a/devices/EmulatedCamera/hwl/EmulatedRequestState.h b/devices/EmulatedCamera/hwl/EmulatedRequestState.h
index 4900635..6f89403 100644
--- a/devices/EmulatedCamera/hwl/EmulatedRequestState.h
+++ b/devices/EmulatedCamera/hwl/EmulatedRequestState.h
@@ -69,6 +69,8 @@ class EmulatedRequestState {
   status_t Update3AMeteringRegion(uint32_t tag,
                                   const HalCameraMetadata& settings,
                                   int32_t* region /*out*/);
+  int GetSensitivityClampToRange(uint32_t sensitivity);
+  int GetExposureTimeClampToRange(uint32_t exposure);
 
   std::mutex request_state_mutex_;
   std::unique_ptr<HalCameraMetadata> request_settings_;
diff --git a/devices/EmulatedCamera/hwl/configs/emu_camera_back.json b/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
index a0ac5e1..00b9974 100644
--- a/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
+++ b/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
@@ -14,6 +14,11 @@
   "2",
   "3"
  ],
+ "android.control.aeAvailablePriorityModes": [
+  "0",
+  "1",
+  "2"
+ ],
  "android.control.aeAvailableTargetFpsRanges": [
   "15",
   "15",
@@ -426,6 +431,7 @@
   "524301"
  ],
  "android.request.availableRequestKeys": [
+  "65596",
   "786435",
   "786433",
   "786432",
@@ -494,6 +500,7 @@
   "2097152"
  ],
  "android.request.availableResultKeys": [
+  "65596",
   "786435",
   "786433",
   "786432",
diff --git a/devices/EmulatedCamera/hwl/configs/emu_camera_front.json b/devices/EmulatedCamera/hwl/configs/emu_camera_front.json
index db1a6cb..9edf76b 100644
--- a/devices/EmulatedCamera/hwl/configs/emu_camera_front.json
+++ b/devices/EmulatedCamera/hwl/configs/emu_camera_front.json
@@ -5,6 +5,16 @@
    "1",
    "2"
   ],
+  "android.colorCorrection.availableModes": [
+    "0",
+    "1",
+    "2",
+    "3"
+   ],
+   "android.colorCorrection.colorTemperatureRange": [
+    "2000",
+    "10000"
+   ],
   "android.control.aeAvailableAntibandingModes": [
    "0",
    "1",
@@ -1523,6 +1533,16 @@
    "1",
    "2"
   ],
+  "android.colorCorrection.availableModes": [
+    "0",
+    "1",
+    "2",
+    "3"
+   ],
+   "android.colorCorrection.colorTemperatureRange": [
+    "2000",
+    "10000"
+   ],
   "android.control.aeAvailableAntibandingModes": [
    "0",
    "1",
@@ -3006,6 +3026,16 @@
    "1",
    "2"
   ],
+  "android.colorCorrection.availableModes": [
+    "0",
+    "1",
+    "2",
+    "3"
+   ],
+   "android.colorCorrection.colorTemperatureRange": [
+    "2000",
+    "10000"
+   ],
   "android.control.aeAvailableAntibandingModes": [
    "0",
    "1",
```

