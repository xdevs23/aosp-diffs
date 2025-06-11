```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index c8dbf77..8aa2201 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,5 +1,6 @@
 [Builtin Hooks]
 clang_format = true
+bpfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
diff --git a/common/hal/OWNERS b/common/hal/OWNERS
index 7b8350f..cb90a47 100644
--- a/common/hal/OWNERS
+++ b/common/hal/OWNERS
@@ -10,5 +10,4 @@ ianchien@google.com
 blossomchiang@google.com
 khakisung@google.com
 vincechiu@google.com
-jasl@google.com
-owenkmg@google.com
\ No newline at end of file
+owenkmg@google.com
diff --git a/common/hal/aidl_service/aidl_camera_device_session.cc b/common/hal/aidl_service/aidl_camera_device_session.cc
index 90c9254..b95375a 100644
--- a/common/hal/aidl_service/aidl_camera_device_session.cc
+++ b/common/hal/aidl_service/aidl_camera_device_session.cc
@@ -33,6 +33,7 @@
 #include "aidl_profiler.h"
 #include "aidl_thermal_utils.h"
 #include "aidl_utils.h"
+#include "hal_types.h"
 #include "profiler_util.h"
 #include "tracked_profiler.h"
 
@@ -98,7 +99,6 @@ AidlCameraDeviceSession::~AidlCameraDeviceSession() {
 
 void AidlCameraDeviceSession::ProcessCaptureResult(
     std::unique_ptr<google_camera_hal::CaptureResult> hal_result) {
-  std::shared_lock lock(aidl_device_callback_lock_);
   if (aidl_device_callback_ == nullptr) {
     ALOGE("%s: aidl_device_callback_ is nullptr", __FUNCTION__);
     return;
@@ -161,7 +161,6 @@ void AidlCameraDeviceSession::ProcessCaptureResult(
 
 void AidlCameraDeviceSession::ProcessBatchCaptureResult(
     std::vector<std::unique_ptr<google_camera_hal::CaptureResult>> hal_results) {
-  std::shared_lock lock(aidl_device_callback_lock_);
   if (aidl_device_callback_ == nullptr) {
     ALOGE("%s: aidl_device_callback_ is nullptr", __FUNCTION__);
     return;
@@ -205,7 +204,6 @@ void AidlCameraDeviceSession::ProcessBatchCaptureResult(
 
 void AidlCameraDeviceSession::NotifyHalMessage(
     const google_camera_hal::NotifyMessage& hal_message) {
-  std::shared_lock lock(aidl_device_callback_lock_);
   if (aidl_device_callback_ == nullptr) {
     ALOGE("%s: aidl_device_callback_ is nullptr", __FUNCTION__);
     return;
@@ -213,7 +211,7 @@ void AidlCameraDeviceSession::NotifyHalMessage(
 
   std::vector<NotifyMsg> aidl_messages(1);
   status_t res =
-      aidl_utils::ConverToAidlNotifyMessage(hal_message, &aidl_messages[0]);
+      aidl_utils::ConvertToAidlNotifyMessage(hal_message, &aidl_messages[0]);
   if (res != OK) {
     ALOGE("%s: Converting to AIDL message failed: %s(%d)", __FUNCTION__,
           strerror(-res), res);
@@ -228,6 +226,32 @@ void AidlCameraDeviceSession::NotifyHalMessage(
   }
 }
 
+void AidlCameraDeviceSession::NotifyBatchHalMessage(
+    const std::vector<google_camera_hal::NotifyMessage>& hal_messages) {
+  if (aidl_device_callback_ == nullptr) {
+    ALOGE("%s: aidl_device_callback_ is nullptr", __FUNCTION__);
+    return;
+  }
+
+  std::vector<NotifyMsg> aidl_messages(hal_messages.size());
+  for (size_t i = 0; i < hal_messages.size(); ++i) {
+    status_t res = aidl_utils::ConvertToAidlNotifyMessage(hal_messages[i],
+                                                          &aidl_messages[i]);
+    if (res != OK) {
+      ALOGE("%s: Converting to AIDL message failed: %s(%d)", __FUNCTION__,
+            strerror(-res), res);
+      return;
+    }
+  }
+
+  auto aidl_res = aidl_device_callback_->notify(aidl_messages);
+  if (!aidl_res.isOk()) {
+    ALOGE("%s: notify transaction failed: %s.", __FUNCTION__,
+          aidl_res.getMessage());
+    return;
+  }
+}
+
 static void cleanupHandles(std::vector<native_handle_t*>& handles_to_delete) {
   for (auto& handle : handles_to_delete) {
     native_handle_delete(handle);
@@ -238,7 +262,6 @@ google_camera_hal::BufferRequestStatus
 AidlCameraDeviceSession::RequestStreamBuffers(
     const std::vector<google_camera_hal::BufferRequest>& hal_buffer_requests,
     std::vector<google_camera_hal::BufferReturn>* hal_buffer_returns) {
-  std::shared_lock lock(aidl_device_callback_lock_);
   if (aidl_device_callback_ == nullptr) {
     ALOGE("%s: aidl_device_callback_ is nullptr", __FUNCTION__);
     return google_camera_hal::BufferRequestStatus::kFailedUnknown;
@@ -342,7 +365,6 @@ AidlCameraDeviceSession::RequestStreamBuffers(
 
 void AidlCameraDeviceSession::ReturnStreamBuffers(
     const std::vector<google_camera_hal::StreamBuffer>& return_hal_buffers) {
-  std::shared_lock lock(aidl_device_callback_lock_);
   if (aidl_device_callback_ == nullptr) {
     ALOGE("%s: aidl_device_callback_ is nullptr", __FUNCTION__);
     return;
@@ -445,6 +467,10 @@ void AidlCameraDeviceSession::SetSessionCallbacks() {
           [this](const google_camera_hal::NotifyMessage& message) {
             NotifyHalMessage(message);
           }),
+      .notify_batch = google_camera_hal::NotifyBatchFunc(
+          [this](const std::vector<google_camera_hal::NotifyMessage>& messages) {
+            NotifyBatchHalMessage(messages);
+          }),
       .request_stream_buffers = google_camera_hal::RequestStreamBuffersFunc(
           [this](
               const std::vector<google_camera_hal::BufferRequest>&
diff --git a/common/hal/aidl_service/aidl_camera_device_session.h b/common/hal/aidl_service/aidl_camera_device_session.h
index 8d6539a..9972740 100644
--- a/common/hal/aidl_service/aidl_camera_device_session.h
+++ b/common/hal/aidl_service/aidl_camera_device_session.h
@@ -25,7 +25,6 @@
 #include <fmq/AidlMessageQueue.h>
 #include <utils/StrongPointer.h>
 
-#include <shared_mutex>
 #include <vector>
 
 #include "aidl_profiler.h"
@@ -165,6 +164,9 @@ class AidlCameraDeviceSession
       bool v2, aidl::android::hardware::camera::device::ConfigureStreamsRet*);
   // Invoked when receiving a message from HAL.
   void NotifyHalMessage(const google_camera_hal::NotifyMessage& hal_message);
+  // Invoked when receiving a batched message from HAL.
+  void NotifyBatchHalMessage(
+      const std::vector<google_camera_hal::NotifyMessage>& hal_messages);
 
   // Invoked when requesting stream buffers from HAL.
   google_camera_hal::BufferRequestStatus RequestStreamBuffers(
@@ -202,10 +204,8 @@ class AidlCameraDeviceSession
   // Metadata queue to write the result metadata to.
   std::unique_ptr<MetadataQueue> result_metadata_queue_;
 
-  // Assuming callbacks to framework is thread-safe, the shared mutex is only
-  // used to protect member variable writing and reading.
-  std::shared_mutex aidl_device_callback_lock_;
-  // Protected by aidl_device_callback_lock_
+  // Don't need to protect the callbacks to framework with a mutex, as they are
+  // thread-safe.
   std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceCallback>
       aidl_device_callback_;
 
diff --git a/common/hal/aidl_service/aidl_utils.cc b/common/hal/aidl_service/aidl_utils.cc
index 5be472e..9353f83 100644
--- a/common/hal/aidl_service/aidl_utils.cc
+++ b/common/hal/aidl_service/aidl_utils.cc
@@ -520,7 +520,7 @@ status_t ConvertToAidlShutterMessage(
   return OK;
 }
 
-status_t ConverToAidlNotifyMessage(
+status_t ConvertToAidlNotifyMessage(
     const google_camera_hal::NotifyMessage& hal_message,
     NotifyMsg* aidl_message) {
   if (aidl_message == nullptr) {
diff --git a/common/hal/aidl_service/aidl_utils.h b/common/hal/aidl_service/aidl_utils.h
index f8b23a0..80430b5 100644
--- a/common/hal/aidl_service/aidl_utils.h
+++ b/common/hal/aidl_service/aidl_utils.h
@@ -95,7 +95,7 @@ status_t ConvertToAidlHalStreamConfig(
     const google_camera_hal::ConfigureStreamsReturn& hal_config,
     ConfigureStreamsRet* aidl_config);
 
-status_t ConverToAidlNotifyMessage(
+status_t ConvertToAidlNotifyMessage(
     const google_camera_hal::NotifyMessage& hal_message,
     NotifyMsg* aidl_message);
 
diff --git a/common/hal/common/hal_types.h b/common/hal/common/hal_types.h
index f0b683c..39890fd 100644
--- a/common/hal/common/hal_types.h
+++ b/common/hal/common/hal_types.h
@@ -20,6 +20,7 @@
 #include <cutils/native_handle.h>
 #include <system/graphics-base-v1.0.h>
 
+#include <functional>
 #include <string>
 #include <unordered_map>
 #include <vector>
@@ -415,9 +416,13 @@ using ProcessCaptureResultFunc =
 using ProcessBatchCaptureResultFunc =
     std::function<void(std::vector<std::unique_ptr<CaptureResult>> /*results*/)>;
 
-// Callback function invoked to notify messages.
+// Callback function invoked to notify a message.
 using NotifyFunc = std::function<void(const NotifyMessage& /*message*/)>;
 
+// Callback function invoked to notify a batched message.
+using NotifyBatchFunc =
+    std::function<void(const std::vector<NotifyMessage>& /*messages*/)>;
+
 // HAL buffer allocation descriptor
 struct HalBufferDescriptor {
   int32_t stream_id = -1;
diff --git a/common/hal/google_camera_hal/basic_capture_session.cc b/common/hal/google_camera_hal/basic_capture_session.cc
index f77c6fb..f342f29 100644
--- a/common/hal/google_camera_hal/basic_capture_session.cc
+++ b/common/hal/google_camera_hal/basic_capture_session.cc
@@ -25,6 +25,7 @@
 #include "basic_request_processor.h"
 #include "basic_result_processor.h"
 #include "hal_types.h"
+#include "libgooglecamerahal_flags.h"
 #include "realtime_process_block.h"
 
 namespace android {
@@ -48,7 +49,8 @@ std::unique_ptr<CaptureSession> BasicCaptureSession::Create(
     const StreamConfiguration& stream_config,
     ProcessCaptureResultFunc process_capture_result,
     ProcessBatchCaptureResultFunc process_batch_capture_result,
-    NotifyFunc notify, HwlSessionCallback /*session_callback*/,
+    NotifyFunc notify, NotifyBatchFunc notify_batch,
+    HwlSessionCallback /*session_callback*/,
     std::vector<HalStream>* hal_configured_streams,
     CameraBufferAllocatorHwl* /*camera_allocator_hwl*/) {
   ATRACE_CALL();
@@ -59,8 +61,9 @@ std::unique_ptr<CaptureSession> BasicCaptureSession::Create(
   }
 
   status_t res = session->Initialize(
-      device_session_hwl, stream_config, process_capture_result,
-      process_batch_capture_result, notify, hal_configured_streams);
+      device_session_hwl, stream_config, std::move(process_capture_result),
+      std::move(process_batch_capture_result), std::move(notify),
+      std::move(notify_batch), hal_configured_streams);
   if (res != OK) {
     ALOGE("%s: Initializing BasicCaptureSession failed: %s (%d).", __FUNCTION__,
           strerror(-res), res);
@@ -190,7 +193,8 @@ status_t BasicCaptureSession::Initialize(
     const StreamConfiguration& stream_config,
     ProcessCaptureResultFunc process_capture_result,
     ProcessBatchCaptureResultFunc process_batch_capture_result,
-    NotifyFunc notify, std::vector<HalStream>* hal_configured_streams) {
+    NotifyFunc notify, NotifyBatchFunc notify_batch,
+    std::vector<HalStream>* hal_configured_streams) {
   ATRACE_CALL();
   if (!IsStreamConfigurationSupported(device_session_hwl, stream_config)) {
     ALOGE("%s: stream configuration is not supported.", __FUNCTION__);
@@ -222,10 +226,13 @@ status_t BasicCaptureSession::Initialize(
   std::string result_dispatcher_name =
       "Cam" + std::to_string(device_session_hwl_->GetCameraId()) +
       "_ResultDispatcher";
-  result_dispatcher_ =
-      ResultDispatcher::Create(partial_result_count, process_capture_result,
-                               process_batch_capture_result, notify,
-                               stream_config, result_dispatcher_name);
+  if (!libgooglecamerahal::flags::batched_shutter_notifications()) {
+    notify_batch = nullptr;
+  }
+  result_dispatcher_ = ResultDispatcher::Create(
+      partial_result_count, std::move(process_capture_result),
+      std::move(process_batch_capture_result), std::move(notify),
+      std::move(notify_batch), stream_config, result_dispatcher_name);
   if (result_dispatcher_ == nullptr) {
     ALOGE("Creating ResultDispatcher failed");
     return UNKNOWN_ERROR;
@@ -246,8 +253,12 @@ status_t BasicCaptureSession::Initialize(
       [this](std::vector<std::unique_ptr<CaptureResult>> results) {
         ProcessBatchCaptureResult(std::move(results));
       };
+  auto notify_batch_cb = [this](const std::vector<NotifyMessage>& messages) {
+    NotifyBatch(messages);
+  };
   result_processor->SetResultCallback(process_capture_result_cb, notify_cb,
-                                      process_batch_capture_result_cb);
+                                      process_batch_capture_result_cb,
+                                      notify_batch_cb);
 
   // Create process block.
   auto process_block = RealtimeProcessBlock::Create(device_session_hwl_);
@@ -315,9 +326,7 @@ void BasicCaptureSession::ProcessCaptureResult(
 
 void BasicCaptureSession::Notify(const NotifyMessage& message) {
   if (message.type == MessageType::kShutter) {
-    result_dispatcher_->AddShutter(message.message.shutter.frame_number,
-                                   message.message.shutter.timestamp_ns,
-                                   message.message.shutter.readout_timestamp_ns);
+    result_dispatcher_->AddShutter(message.message.shutter);
   } else {
     result_dispatcher_->AddError(message.message.error);
   }
@@ -328,5 +337,18 @@ void BasicCaptureSession::ProcessBatchCaptureResult(
   result_dispatcher_->AddBatchResult(std::move(results));
 }
 
+void BasicCaptureSession::NotifyBatch(const std::vector<NotifyMessage>& messages) {
+  std::vector<ShutterMessage> shutter_messages;
+  shutter_messages.reserve(messages.size());
+  for (const NotifyMessage& message : messages) {
+    if (message.type == MessageType::kShutter) {
+      shutter_messages.push_back(message.message.shutter);
+    } else {
+      result_dispatcher_->AddError(message.message.error);
+    }
+  }
+  result_dispatcher_->AddBatchShutter(shutter_messages);
+}
+
 }  // namespace google_camera_hal
 }  // namespace android
diff --git a/common/hal/google_camera_hal/basic_capture_session.h b/common/hal/google_camera_hal/basic_capture_session.h
index 3f58a9f..49567bc 100644
--- a/common/hal/google_camera_hal/basic_capture_session.h
+++ b/common/hal/google_camera_hal/basic_capture_session.h
@@ -61,7 +61,8 @@ class BasicCaptureSession : public CaptureSession {
       const StreamConfiguration& stream_config,
       ProcessCaptureResultFunc process_capture_result,
       ProcessBatchCaptureResultFunc process_batch_capture_result,
-      NotifyFunc notify, HwlSessionCallback session_callback,
+      NotifyFunc notify, NotifyBatchFunc notify_batch,
+      HwlSessionCallback session_callback,
       std::vector<HalStream>* hal_configured_streams,
       CameraBufferAllocatorHwl* camera_allocator_hwl = nullptr);
 
@@ -84,7 +85,7 @@ class BasicCaptureSession : public CaptureSession {
                       const StreamConfiguration& stream_config,
                       ProcessCaptureResultFunc process_capture_result,
                       ProcessBatchCaptureResultFunc process_batch_capture_result,
-                      NotifyFunc notify,
+                      NotifyFunc notify, NotifyBatchFunc notify_batch,
                       std::vector<HalStream>* hal_configured_streams);
 
   // Configure streams for request processor and process block.
@@ -105,6 +106,7 @@ class BasicCaptureSession : public CaptureSession {
   void Notify(const NotifyMessage& message);
   void ProcessBatchCaptureResult(
       std::vector<std::unique_ptr<CaptureResult>> results);
+  void NotifyBatch(const std::vector<NotifyMessage>& messages);
 
   std::unique_ptr<RequestProcessor> request_processor_;
 
diff --git a/common/hal/google_camera_hal/basic_result_processor.cc b/common/hal/google_camera_hal/basic_result_processor.cc
index bfd1493..988da5d 100644
--- a/common/hal/google_camera_hal/basic_result_processor.cc
+++ b/common/hal/google_camera_hal/basic_result_processor.cc
@@ -23,6 +23,9 @@
 #include <log/log.h>
 #include <utils/Trace.h>
 
+#include <vector>
+
+#include "hal_types.h"
 #include "hal_utils.h"
 
 namespace android {
@@ -55,12 +58,14 @@ std::unique_ptr<BasicResultProcessor> BasicResultProcessor::Create() {
 
 void BasicResultProcessor::SetResultCallback(
     ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc process_batch_capture_result) {
+    ProcessBatchCaptureResultFunc process_batch_capture_result,
+    NotifyBatchFunc notify_batch) {
   ATRACE_CALL();
   std::lock_guard<std::mutex> lock(callback_lock_);
   process_capture_result_ = process_capture_result;
   notify_ = notify;
   process_batch_capture_result_ = process_batch_capture_result;
+  notify_batch_ = notify_batch;
 }
 
 status_t BasicResultProcessor::AddPendingRequests(
@@ -129,6 +134,24 @@ void BasicResultProcessor::Notify(const ProcessBlockNotifyMessage& block_message
   notify_(block_message.message);
 }
 
+void BasicResultProcessor::NotifyBatch(
+    const std::vector<ProcessBlockNotifyMessage>& block_messages) {
+  ATRACE_CALL();
+  if (notify_batch_ == nullptr) {
+    ALOGE("%s: notify_batch_ is nullptr. Dropping messages.", __FUNCTION__);
+    return;
+  }
+
+  std::vector<NotifyMessage> notify_messages;
+  notify_messages.reserve(block_messages.size());
+  for (const ProcessBlockNotifyMessage& block_message : block_messages) {
+    notify_messages.push_back(block_message.message);
+  }
+
+  std::lock_guard<std::mutex> lock(callback_lock_);
+  notify_batch_(notify_messages);
+}
+
 status_t BasicResultProcessor::FlushPendingRequests() {
   ATRACE_CALL();
   return INVALID_OPERATION;
diff --git a/common/hal/google_camera_hal/basic_result_processor.h b/common/hal/google_camera_hal/basic_result_processor.h
index 2fa1e3b..1461bb5 100644
--- a/common/hal/google_camera_hal/basic_result_processor.h
+++ b/common/hal/google_camera_hal/basic_result_processor.h
@@ -19,6 +19,7 @@
 
 #include <vector>
 
+#include "hal_types.h"
 #include "result_processor.h"
 
 namespace android {
@@ -35,7 +36,8 @@ class BasicResultProcessor : public ResultProcessor {
   // Override functions of ResultProcessor start.
   void SetResultCallback(
       ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
+      ProcessBatchCaptureResultFunc process_batch_capture_result,
+      NotifyBatchFunc notify_batch) override;
 
   status_t AddPendingRequests(
       const std::vector<ProcessBlockRequest>& process_block_requests,
@@ -47,6 +49,9 @@ class BasicResultProcessor : public ResultProcessor {
 
   void Notify(const ProcessBlockNotifyMessage& block_message) override;
 
+  void NotifyBatch(
+      const std::vector<ProcessBlockNotifyMessage>& block_messages) override;
+
   status_t FlushPendingRequests() override;
   // Override functions of ResultProcessor end.
 
@@ -60,6 +65,7 @@ class BasicResultProcessor : public ResultProcessor {
   ProcessCaptureResultFunc process_capture_result_;
   ProcessBatchCaptureResultFunc process_batch_capture_result_;
   NotifyFunc notify_;
+  NotifyBatchFunc notify_batch_;
 };
 
 }  // namespace google_camera_hal
diff --git a/common/hal/google_camera_hal/camera_device_session.cc b/common/hal/google_camera_hal/camera_device_session.cc
index 6dcc7b7..8b7ffd8 100644
--- a/common/hal/google_camera_hal/camera_device_session.cc
+++ b/common/hal/google_camera_hal/camera_device_session.cc
@@ -24,12 +24,17 @@
 #include <system/graphics-base-v1.0.h>
 #include <utils/Trace.h>
 
+#include <optional>
+
 #include "basic_capture_session.h"
 #include "capture_session_utils.h"
 #include "hal_types.h"
 #include "hal_utils.h"
+#include "libgooglecamerahal_flags.h"
+#include "stream_buffer_cache_manager.h"
 #include "system/camera_metadata.h"
 #include "ui/GraphicBufferMapper.h"
+#include "utils.h"
 #include "vendor_tag_defs.h"
 #include "vendor_tag_types.h"
 #include "vendor_tags.h"
@@ -240,54 +245,25 @@ void CameraDeviceSession::ProcessBatchCaptureResult(
 }
 
 void CameraDeviceSession::Notify(const NotifyMessage& result) {
-  {
-    uint32_t frame_number = 0;
-    if (result.type == MessageType::kError) {
-      frame_number = result.message.error.frame_number;
-    } else if (result.type == MessageType::kShutter) {
-      frame_number = result.message.shutter.frame_number;
-    }
-    std::lock_guard<std::mutex> lock(request_record_lock_);
-    // Strip out results for frame number that has been notified
-    // ErrorCode::kErrorResult and ErrorCode::kErrorBuffer
-    if ((error_notified_requests_.find(frame_number) !=
-         error_notified_requests_.end()) &&
-        (result.type != MessageType::kShutter)) {
-      return;
-    }
+  if (ShouldSendNotifyMessage(result)) {
+    std::shared_lock lock(session_callback_lock_);
+    session_callback_.notify(result);
+  }
+}
 
-    if (result.type == MessageType::kError &&
-        result.message.error.error_code == ErrorCode::kErrorResult) {
-      pending_results_.erase(frame_number);
+void CameraDeviceSession::NotifyBatch(const std::vector<NotifyMessage>& results) {
+  std::vector<NotifyMessage> callback_results;
+  callback_results.reserve(results.size());
 
-      if (ignore_shutters_.find(frame_number) == ignore_shutters_.end()) {
-        ignore_shutters_.insert(frame_number);
-      }
-    }
-
-    if (result.type == MessageType::kShutter) {
-      if (ignore_shutters_.find(frame_number) != ignore_shutters_.end()) {
-        ignore_shutters_.erase(frame_number);
-        return;
-      }
+  for (const NotifyMessage& result : results) {
+    if (ShouldSendNotifyMessage(result)) {
+      callback_results.push_back(result);
     }
   }
-
-  if (ATRACE_ENABLED() && result.type == MessageType::kShutter) {
-    int64_t timestamp_ns_diff = 0;
-    int64_t current_timestamp_ns = result.message.shutter.timestamp_ns;
-    if (last_timestamp_ns_for_trace_ != 0) {
-      timestamp_ns_diff = current_timestamp_ns - last_timestamp_ns_for_trace_;
-    }
-
-    last_timestamp_ns_for_trace_ = current_timestamp_ns;
-
-    ATRACE_INT64("sensor_timestamp_diff", timestamp_ns_diff);
-    ATRACE_INT("timestamp_frame_number", result.message.shutter.frame_number);
+  if (!callback_results.empty()) {
+    std::shared_lock lock(session_callback_lock_);
+    session_callback_.notify_batch(callback_results);
   }
-
-  std::shared_lock lock(session_callback_lock_);
-  session_callback_.notify(result);
 }
 
 void CameraDeviceSession::InitializeCallbacks() {
@@ -328,7 +304,12 @@ void CameraDeviceSession::InitializeCallbacks() {
           });
 
   camera_device_session_callback_.notify =
-      NotifyFunc([this](const NotifyMessage& result) { Notify(result); });
+      NotifyFunc([this](const NotifyMessage& message) { Notify(message); });
+
+  camera_device_session_callback_.notify_batch =
+      NotifyBatchFunc([this](const std::vector<NotifyMessage>& messages) {
+        NotifyBatch(messages);
+      });
 
   hwl_session_callback_.request_stream_buffers = HwlRequestBuffersFunc(
       [this](int32_t stream_id, uint32_t num_buffers,
@@ -714,13 +695,24 @@ status_t CameraDeviceSession::ConfigureStreams(
       break;
     }
   }
+
+  // Check if the feature combination in the given StreamConfiguration is
+  // supported by current device.
+  // This is from the requirement that Feature Combination Query API should
+  // provide consistent output with the CreateCaptureSession result. b/401442279
+  if (!device_session_hwl_->IsFeatureCombinationSupported(stream_config)) {
+    ALOGE("%s: IsFeatureCombinationSupported returns false", __FUNCTION__);
+    return BAD_VALUE;
+  }
+
   capture_session_ = CreateCaptureSession(
       stream_config, kWrapperCaptureSessionEntries,
       external_capture_session_entries_, kCaptureSessionEntries,
       hwl_session_callback_, camera_allocator_hwl_, device_session_hwl_.get(),
       &hal_config, camera_device_session_callback_.process_capture_result,
       camera_device_session_callback_.notify,
-      camera_device_session_callback_.process_batch_capture_result);
+      camera_device_session_callback_.process_batch_capture_result,
+      camera_device_session_callback_.notify_batch);
 
   if (capture_session_ == nullptr) {
     ALOGE("%s: Cannot find a capture session compatible with stream config",
@@ -1682,6 +1674,21 @@ status_t CameraDeviceSession::RegisterStreamsIntoCacheManagerLocked(
     const std::vector<HalStream>& hal_streams) {
   ATRACE_CALL();
 
+  std::optional<uint32_t> hfr_batch_size;
+  camera_metadata_ro_entry entry;
+  if (stream_config.operation_mode ==
+          StreamConfigurationMode::kConstrainedHighSpeed &&
+      stream_config.session_params != nullptr &&
+      stream_config.session_params->Get(ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
+                                        &entry) == OK) {
+    uint32_t max_fps = entry.data.i32[1];
+    if (max_fps % 30 != 0) {
+      ALOGE("%s: max_fps(%u) must be multiple of 30", __FUNCTION__, max_fps);
+      return BAD_VALUE;
+    }
+    hfr_batch_size = max_fps / 30;
+  }
+
   for (auto& stream : stream_config.streams) {
     uint64_t producer_usage = 0;
     uint64_t consumer_usage = 0;
@@ -1749,15 +1756,22 @@ status_t CameraDeviceSession::RegisterStreamsIntoCacheManagerLocked(
           return OK;
         });
 
-    StreamBufferCacheRegInfo reg_info = {.request_func = session_request_func,
-                                         .return_func = session_return_func,
-                                         .stream_id = stream_id,
-                                         .width = stream.width,
-                                         .height = stream.height,
-                                         .format = stream_format,
-                                         .producer_flags = producer_usage,
-                                         .consumer_flags = consumer_usage,
-                                         .num_buffers_to_cache = 1};
+    const uint32_t num_buffers_to_cache =
+        libgooglecamerahal::flags::batched_request_buffers() &&
+                hfr_batch_size.has_value() && utils::IsVideoStream(stream)
+            ? *hfr_batch_size
+            : 1;
+
+    StreamBufferCacheRegInfo reg_info = {
+        .request_func = session_request_func,
+        .return_func = session_return_func,
+        .stream_id = stream_id,
+        .width = stream.width,
+        .height = stream.height,
+        .format = stream_format,
+        .producer_flags = producer_usage,
+        .consumer_flags = consumer_usage,
+        .num_buffers_to_cache = num_buffers_to_cache};
 
     status_t res = stream_buffer_cache_manager_->RegisterStream(reg_info);
     if (res != OK) {
@@ -2003,5 +2017,55 @@ void CameraDeviceSession::TrackReturnedBuffers(
   }
 }
 
+bool CameraDeviceSession::ShouldSendNotifyMessage(const NotifyMessage& result) {
+  {
+    uint32_t frame_number = 0;
+    if (result.type == MessageType::kError) {
+      frame_number = result.message.error.frame_number;
+    } else if (result.type == MessageType::kShutter) {
+      frame_number = result.message.shutter.frame_number;
+    }
+    std::lock_guard<std::mutex> lock(request_record_lock_);
+    // Strip out results for frame number that has been notified
+    // ErrorCode::kErrorResult and ErrorCode::kErrorBuffer
+    if ((error_notified_requests_.find(frame_number) !=
+         error_notified_requests_.end()) &&
+        (result.type != MessageType::kShutter)) {
+      return false;
+    }
+
+    if (result.type == MessageType::kError &&
+        result.message.error.error_code == ErrorCode::kErrorResult) {
+      pending_results_.erase(frame_number);
+
+      if (ignore_shutters_.find(frame_number) == ignore_shutters_.end()) {
+        ignore_shutters_.insert(frame_number);
+      }
+    }
+
+    if (result.type == MessageType::kShutter) {
+      if (ignore_shutters_.find(frame_number) != ignore_shutters_.end()) {
+        ignore_shutters_.erase(frame_number);
+        return false;
+      }
+    }
+  }
+
+  if (ATRACE_ENABLED() && result.type == MessageType::kShutter) {
+    int64_t timestamp_ns_diff = 0;
+    int64_t current_timestamp_ns = result.message.shutter.timestamp_ns;
+    if (last_timestamp_ns_for_trace_ != 0) {
+      timestamp_ns_diff = current_timestamp_ns - last_timestamp_ns_for_trace_;
+    }
+
+    last_timestamp_ns_for_trace_ = current_timestamp_ns;
+
+    ATRACE_INT64("sensor_timestamp_diff", timestamp_ns_diff);
+    ATRACE_INT("timestamp_frame_number", result.message.shutter.frame_number);
+  }
+
+  return true;
+}
+
 }  // namespace google_camera_hal
 }  // namespace android
diff --git a/common/hal/google_camera_hal/camera_device_session.h b/common/hal/google_camera_hal/camera_device_session.h
index 1f8778a..54cfb4e 100644
--- a/common/hal/google_camera_hal/camera_device_session.h
+++ b/common/hal/google_camera_hal/camera_device_session.h
@@ -46,9 +46,12 @@ struct CameraDeviceSessionCallback {
   // Callback to notify when a camera device produces a batched capture result.
   ProcessBatchCaptureResultFunc process_batch_capture_result;
 
-  // Callback to notify shutters or errors.
+  // Callback to notify a shutter or error.
   NotifyFunc notify;
 
+  // Callback to notify a batched shutter or error.
+  NotifyBatchFunc notify_batch;
+
   // Callback to request stream buffers.
   RequestStreamBuffersFunc request_stream_buffers;
 
@@ -236,6 +239,9 @@ class CameraDeviceSession {
   // Process the notification returned from the HWL
   void Notify(const NotifyMessage& result);
 
+  // Process the batched notification returned from the HWL
+  void NotifyBatch(const std::vector<NotifyMessage>& results);
+
   // Process the capture result returned from the HWL
   void ProcessCaptureResult(std::unique_ptr<CaptureResult> result);
 
@@ -301,6 +307,10 @@ class CameraDeviceSession {
   // Tracks the returned buffers in capture results.
   void TrackReturnedBuffers(const std::vector<StreamBuffer>& buffers);
 
+  // Checks if `message` should be sent to the framework. It also updates the
+  // last shutter timestamp if systrace is enabled.
+  bool ShouldSendNotifyMessage(const NotifyMessage& message);
+
   uint32_t camera_id_ = 0;
   std::unique_ptr<CameraDeviceSessionHwl> device_session_hwl_;
 
diff --git a/common/hal/google_camera_hal/capture_session_utils.cc b/common/hal/google_camera_hal/capture_session_utils.cc
index bdc26d4..1d7e49c 100644
--- a/common/hal/google_camera_hal/capture_session_utils.cc
+++ b/common/hal/google_camera_hal/capture_session_utils.cc
@@ -33,7 +33,8 @@ std::unique_ptr<CaptureSession> CreateCaptureSession(
     CameraDeviceSessionHwl* camera_device_session_hwl,
     std::vector<HalStream>* hal_config,
     ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc process_batch_capture_result) {
+    ProcessBatchCaptureResultFunc process_batch_capture_result,
+    NotifyBatchFunc notify_batch) {
   // first pass: check predefined wrapper capture session
   for (auto sessionEntry : wrapper_capture_session_entries) {
     if (sessionEntry.IsStreamConfigurationSupported(camera_device_session_hwl,
@@ -61,9 +62,11 @@ std::unique_ptr<CaptureSession> CreateCaptureSession(
     if (sessionEntry.IsStreamConfigurationSupported(camera_device_session_hwl,
                                                     stream_config)) {
       return sessionEntry.CreateSession(
-          camera_device_session_hwl, stream_config, process_capture_result,
-          process_batch_capture_result, notify, hwl_session_callback,
-          hal_config, camera_buffer_allocator_hwl);
+          camera_device_session_hwl, stream_config,
+          std::move(process_capture_result),
+          std::move(process_batch_capture_result), std::move(notify),
+          std::move(notify_batch), hwl_session_callback, hal_config,
+          camera_buffer_allocator_hwl);
     }
   }
   return nullptr;
diff --git a/common/hal/google_camera_hal/capture_session_utils.h b/common/hal/google_camera_hal/capture_session_utils.h
index e544276..a86189a 100644
--- a/common/hal/google_camera_hal/capture_session_utils.h
+++ b/common/hal/google_camera_hal/capture_session_utils.h
@@ -38,8 +38,8 @@ using CaptureSessionCreateFunc = std::function<std::unique_ptr<CaptureSession>(
     CameraDeviceSessionHwl* device_session_hwl,
     const StreamConfiguration& stream_config,
     ProcessCaptureResultFunc process_capture_result,
-    ProcessBatchCaptureResultFunc process_capture_batch_result,
-    NotifyFunc notify, HwlSessionCallback session_callback,
+    ProcessBatchCaptureResultFunc process_capture_batch_result, NotifyFunc notify,
+    NotifyBatchFunc notify_batch, HwlSessionCallback session_callback,
     std::vector<HalStream>* hal_configured_streams,
     CameraBufferAllocatorHwl* camera_allocator_hwl)>;
 
@@ -84,7 +84,8 @@ std::unique_ptr<CaptureSession> CreateCaptureSession(
     CameraDeviceSessionHwl* camera_device_session_hwl,
     std::vector<HalStream>* hal_config,
     ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc process_batch_capture_result = nullptr);
+    ProcessBatchCaptureResultFunc process_batch_capture_result = nullptr,
+    NotifyBatchFunc notify_batch = nullptr);
 
 }  // namespace google_camera_hal
 }  // namespace android
diff --git a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
index f9bbad7..627b7db 100644
--- a/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
+++ b/common/hal/google_camera_hal/libgooglecamerahal_flags.aconfig
@@ -14,3 +14,18 @@ flag {
   description: "Disable capture request timeout logic in GCH layer"
   bug: "372255560"
 }
+
+flag {
+  name: "batched_request_buffers"
+  namespace: "camera_hal"
+  description: "Request video buffers of batch size on HFR mode"
+  bug: "379919891"
+}
+
+flag {
+  name: "batched_shutter_notifications"
+  namespace: "camera_hal"
+  description: "Report shutter notifications of batch size on HFR mode"
+  bug: "305978343"
+}
+
diff --git a/common/hal/google_camera_hal/realtime_zsl_result_processor.cc b/common/hal/google_camera_hal/realtime_zsl_result_processor.cc
index 9534b05..07d50fd 100644
--- a/common/hal/google_camera_hal/realtime_zsl_result_processor.cc
+++ b/common/hal/google_camera_hal/realtime_zsl_result_processor.cc
@@ -63,7 +63,8 @@ RealtimeZslResultProcessor::RealtimeZslResultProcessor(
 
 void RealtimeZslResultProcessor::SetResultCallback(
     ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
+    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/,
+    NotifyBatchFunc /*notify_batch*/) {
   std::lock_guard<std::mutex> lock(callback_lock_);
   process_capture_result_ = process_capture_result;
   notify_ = notify;
diff --git a/common/hal/google_camera_hal/realtime_zsl_result_processor.h b/common/hal/google_camera_hal/realtime_zsl_result_processor.h
index fd63ec9..362462e 100644
--- a/common/hal/google_camera_hal/realtime_zsl_result_processor.h
+++ b/common/hal/google_camera_hal/realtime_zsl_result_processor.h
@@ -19,6 +19,7 @@
 
 #include <shared_mutex>
 
+#include "hal_types.h"
 #include "internal_stream_manager.h"
 #include "result_processor.h"
 
@@ -38,7 +39,8 @@ class RealtimeZslResultProcessor : public ResultProcessor {
   // Override functions of ResultProcessor start.
   void SetResultCallback(
       ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
+      ProcessBatchCaptureResultFunc process_batch_capture_result,
+      NotifyBatchFunc notify_batch) override;
 
   status_t AddPendingRequests(
       const std::vector<ProcessBlockRequest>& process_block_requests,
diff --git a/common/hal/google_camera_hal/snapshot_result_processor.cc b/common/hal/google_camera_hal/snapshot_result_processor.cc
index 19dcd8e..42aeaed 100644
--- a/common/hal/google_camera_hal/snapshot_result_processor.cc
+++ b/common/hal/google_camera_hal/snapshot_result_processor.cc
@@ -23,6 +23,7 @@
 #include <log/log.h>
 #include <utils/Trace.h>
 
+#include "hal_types.h"
 #include "hal_utils.h"
 
 namespace android {
@@ -53,7 +54,8 @@ SnapshotResultProcessor::SnapshotResultProcessor(
 }
 void SnapshotResultProcessor::SetResultCallback(
     ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/) {
+    ProcessBatchCaptureResultFunc /*process_batch_capture_result*/,
+    NotifyBatchFunc /*notify_batch*/) {
   ATRACE_CALL();
   std::lock_guard<std::mutex> lock(callback_lock_);
   process_capture_result_ = process_capture_result;
diff --git a/common/hal/google_camera_hal/snapshot_result_processor.h b/common/hal/google_camera_hal/snapshot_result_processor.h
index fbd976b..7e523d1 100644
--- a/common/hal/google_camera_hal/snapshot_result_processor.h
+++ b/common/hal/google_camera_hal/snapshot_result_processor.h
@@ -17,6 +17,7 @@
 #ifndef HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_SNAPSHOT_RESULT_PROCESSOR_H_
 #define HARDWARE_GOOGLE_CAMERA_HAL_GOOGLE_CAMERA_HAL_SNAPSHOT_RESULT_PROCESSOR_H_
 
+#include "hal_types.h"
 #include "internal_stream_manager.h"
 #include "result_processor.h"
 
@@ -36,7 +37,8 @@ class SnapshotResultProcessor : public ResultProcessor {
   // Override functions of ResultProcessor start.
   void SetResultCallback(
       ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) override;
+      ProcessBatchCaptureResultFunc process_batch_capture_result,
+      NotifyBatchFunc notify_batch) override;
 
   status_t AddPendingRequests(
       const std::vector<ProcessBlockRequest>& process_block_requests,
diff --git a/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc b/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
index fec7326..7bebf8c 100644
--- a/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
+++ b/common/hal/google_camera_hal/zsl_snapshot_capture_session.cc
@@ -444,7 +444,8 @@ status_t ZslSnapshotCaptureSession::ConfigureStreams(
     return UNKNOWN_ERROR;
   }
   realtime_result_processor->SetResultCallback(
-      process_capture_result, notify, /*process_batch_capture_result=*/nullptr);
+      process_capture_result, notify, /*process_batch_capture_result=*/nullptr,
+      /*notify_batch=*/nullptr);
 
   res = process_block->SetResultProcessor(std::move(realtime_result_processor));
   if (res != OK) {
@@ -494,7 +495,7 @@ status_t ZslSnapshotCaptureSession::ConfigureStreams(
     basic_result_processor_ = basic_result_processor.get();
     basic_result_processor->SetResultCallback(
         process_capture_result, notify,
-        /*process_batch_capture_result=*/nullptr);
+        /*process_batch_capture_result=*/nullptr, /*notify_batch=*/nullptr);
 
     res =
         denoise_processor->SetResultProcessor(std::move(basic_result_processor));
@@ -608,7 +609,8 @@ status_t ZslSnapshotCaptureSession::SetupSnapshotProcessChain(
       std::move(snapshot_result_processor));
 
   snapshot_result_processor_->SetResultCallback(
-      process_capture_result, notify, /*process_batch_capture_result=*/nullptr);
+      process_capture_result, notify, /*process_batch_capture_result=*/nullptr,
+      /*notify_batch=*/nullptr);
   res = ConfigureSnapshotStreams(stream_config);
   if (res != OK) {
     ALOGE("%s: Configuring snapshot stream failed: %s(%d)", __FUNCTION__,
@@ -923,10 +925,7 @@ void ZslSnapshotCaptureSession::NotifyHalMessage(const NotifyMessage& message) {
   }
 
   if (message.type == MessageType::kShutter) {
-    status_t res = result_dispatcher_->AddShutter(
-        message.message.shutter.frame_number,
-        message.message.shutter.timestamp_ns,
-        message.message.shutter.readout_timestamp_ns);
+    status_t res = result_dispatcher_->AddShutter(message.message.shutter);
     if (res != OK) {
       ALOGE("%s: AddShutter for frame %u failed: %s (%d).", __FUNCTION__,
             message.message.shutter.frame_number, strerror(-res), res);
diff --git a/common/hal/hwl_interface/camera_device_session_hwl.h b/common/hal/hwl_interface/camera_device_session_hwl.h
index 5cc6165..3a0c18a 100644
--- a/common/hal/hwl_interface/camera_device_session_hwl.h
+++ b/common/hal/hwl_interface/camera_device_session_hwl.h
@@ -179,6 +179,13 @@ class CameraDeviceSessionHwl : public PhysicalCameraInfoHwl {
       const HalCameraMetadata* old_session, const HalCameraMetadata* new_session,
       bool* reconfiguration_required) const = 0;
 
+  // Check if the feature combination contained within the given
+  // StreamConfiguration is supported by the current device.
+  virtual bool IsFeatureCombinationSupported(
+      const StreamConfiguration& /*stream_config*/) const {
+    return true;
+  }
+
   // Get zoom ratio mapper from HWL.
   virtual std::unique_ptr<ZoomRatioMapperHwl> GetZoomRatioMapperHwl() = 0;
 
diff --git a/common/hal/hwl_interface/hwl_types.h b/common/hal/hwl_interface/hwl_types.h
index fb92510..b643d96 100644
--- a/common/hal/hwl_interface/hwl_types.h
+++ b/common/hal/hwl_interface/hwl_types.h
@@ -18,6 +18,7 @@
 #define HARDWARE_GOOGLE_CAMERA_HAL_HWL_INTERFACE_HWL_TYPES_H_
 
 #include <cstdint>
+#include <functional>
 #include <limits>
 #include <string>
 #include <unordered_set>
@@ -104,6 +105,10 @@ using HwlProcessPipelineBatchResultFunc = std::function<void(
 using NotifyHwlPipelineMessageFunc = std::function<void(
     uint32_t /*pipeline_id*/, const NotifyMessage& /*message*/)>;
 
+// Callback to notify a batched message from HWL.
+using NotifyHwlPipelineBatchMessageFunc =
+    std::function<void(const std::vector<NotifyMessage>& /*messages*/)>;
+
 // Defines callbacks to notify from a HWL pipeline.
 struct HwlPipelineCallback {
   // Callback to notify when a HWL pipeline produces a capture result.
@@ -114,6 +119,9 @@ struct HwlPipelineCallback {
 
   // Callback to notify shutters or errors.
   NotifyHwlPipelineMessageFunc notify;
+
+  // Callback to notify batched shutters or errors.
+  NotifyHwlPipelineBatchMessageFunc notify_batch;
 };
 
 // Callback to invoke to request buffers from HAL. Only in case of HFR, there
diff --git a/common/hal/hwl_interface/result_processor.h b/common/hal/hwl_interface/result_processor.h
index 165f54d..2788713 100644
--- a/common/hal/hwl_interface/result_processor.h
+++ b/common/hal/hwl_interface/result_processor.h
@@ -38,7 +38,8 @@ class ResultProcessor {
   // calling ProcessResult.
   virtual void SetResultCallback(
       ProcessCaptureResultFunc process_capture_result, NotifyFunc notify,
-      ProcessBatchCaptureResultFunc process_batch_capture_result) = 0;
+      ProcessBatchCaptureResultFunc process_batch_capture_result,
+      NotifyBatchFunc notify_batch) = 0;
 
   // Add pending requests to the result processor.
   //
@@ -68,6 +69,14 @@ class ResultProcessor {
   // Called by a ProcessBlock to notify a message.
   virtual void Notify(const ProcessBlockNotifyMessage& block_message) = 0;
 
+  // Called by a ProcessBlock to notify multiple notify messages.
+  virtual void NotifyBatch(
+      const std::vector<ProcessBlockNotifyMessage>& block_messages) {
+    for (const auto& message : block_messages) {
+      Notify(message);
+    };
+  }
+
   // Flush all pending workload.
   virtual status_t FlushPendingRequests() = 0;
 };
diff --git a/common/hal/tests/camera_device_session_tests.cc b/common/hal/tests/camera_device_session_tests.cc
index fe79bf6..cb70782 100644
--- a/common/hal/tests/camera_device_session_tests.cc
+++ b/common/hal/tests/camera_device_session_tests.cc
@@ -206,6 +206,12 @@ class CameraDeviceSessionTests : public ::testing::Test {
     callback_condition_.notify_one();
   }
 
+  void NotifyBatch(const std::vector<NotifyMessage>& messages) {
+    for (const auto& message : messages) {
+      Notify(message);
+    }
+  }
+
   void ClearResultsAndMessages() {
     std::lock_guard<std::mutex> lock(callback_lock_);
     received_results_.clear();
@@ -405,6 +411,10 @@ TEST_F(CameraDeviceSessionTests, PreviewRequests) {
             ProcessBatchCaptureResult(std::move(results));
           },
       .notify = [&](const NotifyMessage& message) { Notify(message); },
+      .notify_batch =
+          [&](const std::vector<NotifyMessage>& messages) {
+            NotifyBatch(messages);
+          },
   };
 
   ThermalCallback thermal_callback = {
diff --git a/common/hal/tests/mock_device_session_hwl.h b/common/hal/tests/mock_device_session_hwl.h
index 6b6657b..6980b64 100644
--- a/common/hal/tests/mock_device_session_hwl.h
+++ b/common/hal/tests/mock_device_session_hwl.h
@@ -105,6 +105,12 @@ class FakeCameraDeviceSessionHwl : public CameraDeviceSessionHwl {
       const HalCameraMetadata* old_session, const HalCameraMetadata* new_session,
       bool* reconfiguration_required) const override;
 
+  bool IsFeatureCombinationSupported(
+      const android::google_camera_hal::StreamConfiguration& /*stream_config*/)
+      const {
+    return true;
+  }
+
   std::unique_ptr<ZoomRatioMapperHwl> GetZoomRatioMapperHwl() override;
 
   std::unique_ptr<google::camera_common::Profiler> GetProfiler(
@@ -171,6 +177,10 @@ class MockDeviceSessionHwl : public CameraDeviceSessionHwl {
               (int32_t frame_number, const std::vector<int32_t>& stream_ids),
               (override));
 
+  MOCK_CONST_METHOD1(
+      IsFeatureCombinationSupported,
+      bool(const android::google_camera_hal::StreamConfiguration& stream_config));
+
   MOCK_CONST_METHOD0(GetCameraId, uint32_t());
 
   MOCK_CONST_METHOD0(GetPhysicalCameraIds, std::vector<uint32_t>());
diff --git a/common/hal/tests/mock_result_processor.h b/common/hal/tests/mock_result_processor.h
index e3ed279..88d288c 100644
--- a/common/hal/tests/mock_result_processor.h
+++ b/common/hal/tests/mock_result_processor.h
@@ -20,16 +20,20 @@
 #include <gmock/gmock.h>
 #include <result_processor.h>
 
+#include "hal_types.h"
+
 namespace android {
 namespace google_camera_hal {
 
 // Defines a ResultProcessor mock using gmock.
 class MockResultProcessor : public ResultProcessor {
  public:
-  MOCK_METHOD3(SetResultCallback,
-               void(ProcessCaptureResultFunc process_capture_result,
-                    NotifyFunc notify,
-                    ProcessBatchCaptureResultFunc process_batch_capture_result));
+  MOCK_METHOD(void, SetResultCallback,
+              (ProcessCaptureResultFunc process_capture_result,
+               NotifyFunc notify,
+               ProcessBatchCaptureResultFunc process_batch_capture_result,
+               NotifyBatchFunc notify_batch),
+              (override));
 
   MOCK_METHOD2(
       AddPendingRequests,
diff --git a/common/hal/tests/result_dispatcher_tests.cc b/common/hal/tests/result_dispatcher_tests.cc
index 303dcb4..efbabcc 100644
--- a/common/hal/tests/result_dispatcher_tests.cc
+++ b/common/hal/tests/result_dispatcher_tests.cc
@@ -23,6 +23,7 @@
 #include <unordered_map>
 #include <unordered_set>
 
+#include "hal_types.h"
 #include "result_dispatcher.h"
 
 namespace android {
@@ -67,7 +68,7 @@ class ResultDispatcherTests : public ::testing::Test {
         },
         /*process_batch_capture_result=*/nullptr,
         [this](const NotifyMessage& message) { Notify(message); },
-        stream_config, "TestResultDispatcher");
+        /*notify_batch=*/nullptr, stream_config, "TestResultDispatcher");
 
     ASSERT_NE(result_dispatcher_, nullptr)
         << "Creating ResultDispatcher failed";
@@ -319,10 +320,10 @@ TEST_F(ResultDispatcherTests, ShutterOrder) {
 
   // Add unordered shutters to dispatcher.
   for (auto frame_number : unordered_frame_numbers) {
-    EXPECT_EQ(result_dispatcher_->AddShutter(
+    EXPECT_EQ(result_dispatcher_->AddShutter(ShutterMessage{
                   frame_number,
                   frame_number * kFrameDurationNs - kFrameExposureTimeNs,
-                  frame_number * kFrameDurationNs),
+                  frame_number * kFrameDurationNs}),
               OK);
   }
 
@@ -414,10 +415,10 @@ TEST_F(ResultDispatcherTests, ShutterOrderWithRemovePengingRequest) {
   // After erase iter, unordered_frame_numbers = {3, 1, 5, 4, 6};
   unordered_frame_numbers.erase(iter);
   for (auto frame_number : unordered_frame_numbers) {
-    EXPECT_EQ(result_dispatcher_->AddShutter(
+    EXPECT_EQ(result_dispatcher_->AddShutter(ShutterMessage{
                   frame_number,
                   frame_number * kFrameDurationNs - kFrameExposureTimeNs,
-                  frame_number * kFrameDurationNs),
+                  frame_number * kFrameDurationNs}),
               OK);
   }
 
diff --git a/common/hal/tests/result_processor_tests.cc b/common/hal/tests/result_processor_tests.cc
index 6733e75..61e61a4 100644
--- a/common/hal/tests/result_processor_tests.cc
+++ b/common/hal/tests/result_processor_tests.cc
@@ -61,7 +61,7 @@ TEST(ResultProcessorTest, SetResultCallback) {
 
     result_processor->SetResultCallback(
         process_capture_result, notify,
-        /*process_batch_capture_result=*/nullptr);
+        /*process_batch_capture_result=*/nullptr, /*notify_batch=*/nullptr);
   }
 }
 
@@ -120,7 +120,7 @@ TEST(ResultProcessorTest, ProcessResultAndNotify) {
     // Test again after setting result callback.
     result_processor->SetResultCallback(
         process_capture_result, notify,
-        /*process_batch_capture_result=*/nullptr);
+        /*process_batch_capture_result=*/nullptr, /*notify_batch=*/nullptr);
     SendResultsAndMessages(result_processor.get());
   }
 }
@@ -140,7 +140,8 @@ TEST(ResultProcessorTest, BasicResultProcessorResultAndNotify) {
       [&](const NotifyMessage& /*message*/) { message_received = true; });
 
   result_processor->SetResultCallback(process_capture_result, notify,
-                                      /*process_batch_capture_result=*/nullptr);
+                                      /*process_batch_capture_result=*/nullptr,
+                                      /*notify_batch=*/nullptr);
 
   ProcessBlockResult null_result;
   result_processor->ProcessResult(std::move(null_result));
@@ -171,7 +172,8 @@ TEST(ResultProcessorTest, BasicResultProcessorAddPendingRequest) {
   NotifyFunc notify = NotifyFunc([&](const NotifyMessage& /*message*/) {});
 
   result_processor->SetResultCallback(process_capture_result, notify,
-                                      /*process_batch_capture_result=*/nullptr);
+                                      /*process_batch_capture_result=*/nullptr,
+                                      /*notify_batch=*/nullptr);
 
   std::vector<ProcessBlockRequest> requests(1);
   requests[0].request.output_buffers = {StreamBuffer{}};
diff --git a/common/hal/utils/realtime_process_block.cc b/common/hal/utils/realtime_process_block.cc
index 5358704..cbf3451 100644
--- a/common/hal/utils/realtime_process_block.cc
+++ b/common/hal/utils/realtime_process_block.cc
@@ -75,6 +75,11 @@ RealtimeProcessBlock::RealtimeProcessBlock(
       [this](uint32_t pipeline_id, const NotifyMessage& message) {
         NotifyHwlPipelineMessage(pipeline_id, message);
       });
+
+  hwl_pipeline_callback_.notify_batch = NotifyHwlPipelineBatchMessageFunc(
+      [this](const std::vector<NotifyMessage>& messages) {
+        NotifyHwlPipelineBatchMessage(messages);
+      });
 }
 
 status_t RealtimeProcessBlock::SetResultProcessor(
@@ -256,5 +261,23 @@ void RealtimeProcessBlock::NotifyHwlPipelineMessage(
   result_processor_->Notify(block_message);
 }
 
+void RealtimeProcessBlock::NotifyHwlPipelineBatchMessage(
+    const std::vector<NotifyMessage>& messages) {
+  ATRACE_CALL();
+  if (result_processor_ == nullptr) {
+    ALOGE("%s: result processor is nullptr. Dropping messages", __FUNCTION__);
+    return;
+  }
+
+  std::vector<ProcessBlockNotifyMessage> block_messages;
+  block_messages.reserve(messages.size());
+  for (const auto& message : messages) {
+    block_messages.push_back(ProcessBlockNotifyMessage{.message = message});
+  }
+
+  std::lock_guard<std::mutex> lock(result_processor_lock_);
+  result_processor_->NotifyBatch(block_messages);
+}
+
 }  // namespace google_camera_hal
 }  // namespace android
diff --git a/common/hal/utils/realtime_process_block.h b/common/hal/utils/realtime_process_block.h
index 9aeadb6..6d1ae6c 100644
--- a/common/hal/utils/realtime_process_block.h
+++ b/common/hal/utils/realtime_process_block.h
@@ -80,6 +80,8 @@ class RealtimeProcessBlock : public ProcessBlock {
   void NotifyHwlPipelineMessage(uint32_t pipeline_id,
                                 const NotifyMessage& message);
 
+  void NotifyHwlPipelineBatchMessage(const std::vector<NotifyMessage>& messages);
+
   HwlPipelineCallback hwl_pipeline_callback_;
   CameraDeviceSessionHwl* device_session_hwl_ = nullptr;
 
diff --git a/common/hal/utils/result_dispatcher.cc b/common/hal/utils/result_dispatcher.cc
index 8ea872b..d817ee0 100644
--- a/common/hal/utils/result_dispatcher.cc
+++ b/common/hal/utils/result_dispatcher.cc
@@ -38,12 +38,13 @@ std::unique_ptr<ResultDispatcher> ResultDispatcher::Create(
     uint32_t partial_result_count,
     ProcessCaptureResultFunc process_capture_result,
     ProcessBatchCaptureResultFunc process_batch_capture_result,
-    NotifyFunc notify, const StreamConfiguration& stream_config,
-    std::string_view name) {
+    NotifyFunc notify, NotifyBatchFunc notify_batch,
+    const StreamConfiguration& stream_config, std::string_view name) {
   ATRACE_CALL();
   auto dispatcher = std::make_unique<ResultDispatcher>(
-      partial_result_count, process_capture_result,
-      process_batch_capture_result, notify, stream_config, name);
+      partial_result_count, std::move(process_capture_result),
+      std::move(process_batch_capture_result), std::move(notify),
+      std::move(notify_batch), stream_config, name);
   if (dispatcher == nullptr) {
     ALOGE("[%s] %s: Creating ResultDispatcher failed.",
           std::string(name).c_str(), __FUNCTION__);
@@ -57,13 +58,14 @@ ResultDispatcher::ResultDispatcher(
     uint32_t partial_result_count,
     ProcessCaptureResultFunc process_capture_result,
     ProcessBatchCaptureResultFunc process_batch_capture_result,
-    NotifyFunc notify, const StreamConfiguration& stream_config,
-    std::string_view name)
+    NotifyFunc notify, NotifyBatchFunc notify_batch,
+    const StreamConfiguration& stream_config, std::string_view name)
     : kPartialResultCount(partial_result_count),
       name_(name),
-      process_capture_result_(process_capture_result),
-      process_batch_capture_result_(process_batch_capture_result),
-      notify_(notify) {
+      process_capture_result_(std::move(process_capture_result)),
+      process_batch_capture_result_(std::move(process_batch_capture_result)),
+      notify_(std::move(notify)),
+      notify_batch_(std::move(notify_batch)) {
   ATRACE_CALL();
   pending_shutters_ = DispatchQueue<PendingShutter>(name_, "shutter");
   pending_early_metadata_ =
@@ -261,25 +263,55 @@ status_t ResultDispatcher::AddBatchResult(
   return last_error.value_or(OK);
 }
 
-status_t ResultDispatcher::AddShutter(uint32_t frame_number,
-                                      int64_t timestamp_ns,
-                                      int64_t readout_timestamp_ns) {
+status_t ResultDispatcher::AddShutterLocked(uint32_t frame_number,
+                                            int64_t timestamp_ns,
+                                            int64_t readout_timestamp_ns) {
+  status_t res = pending_shutters_.AddResult(
+      frame_number, PendingShutter{
+                        .timestamp_ns = timestamp_ns,
+                        .readout_timestamp_ns = readout_timestamp_ns,
+                        .ready = true,
+                    });
+  if (res != OK) {
+    ALOGE(
+        "[%s] %s: Failed to add shutter for frame %u , New timestamp "
+        "%" PRId64,
+        name_.c_str(), __FUNCTION__, frame_number, timestamp_ns);
+  }
+  return res;
+}
+
+status_t ResultDispatcher::AddShutter(const ShutterMessage& shutter) {
   ATRACE_CALL();
 
   {
-    std::lock_guard<std::mutex> lock(result_lock_);
-    status_t res = pending_shutters_.AddResult(
-        frame_number, PendingShutter{
-                          .timestamp_ns = timestamp_ns,
-                          .readout_timestamp_ns = readout_timestamp_ns,
-                          .ready = true,
-                      });
-    if (res != OK) {
-      ALOGE(
-          "[%s] %s: Failed to add shutter for frame %u , New timestamp "
-          "%" PRId64,
-          name_.c_str(), __FUNCTION__, frame_number, timestamp_ns);
-      return res;
+    std::lock_guard lock(result_lock_);
+    if (status_t ret =
+            AddShutterLocked(shutter.frame_number, shutter.timestamp_ns,
+                             shutter.readout_timestamp_ns);
+        ret != OK) {
+      return ret;
+    }
+  }
+  {
+    std::unique_lock<std::mutex> lock(notify_callback_lock_);
+    is_result_shutter_updated_ = true;
+    notify_callback_condition_.notify_one();
+  }
+  return OK;
+}
+
+status_t ResultDispatcher::AddBatchShutter(
+    const std::vector<ShutterMessage>& shutters) {
+  {
+    std::lock_guard lock(result_lock_);
+    for (const ShutterMessage& shutter : shutters) {
+      if (status_t ret =
+              AddShutterLocked(shutter.frame_number, shutter.timestamp_ns,
+                               shutter.readout_timestamp_ns);
+          ret != OK) {
+        return ret;
+      }
     }
   }
   {
@@ -388,7 +420,11 @@ void ResultDispatcher::NotifyCallbackThreadLoop() {
       name_.substr(/*pos=*/0, /*count=*/kPthreadNameLenMinusOne).c_str());
 
   while (1) {
-    NotifyShutters();
+    if (notify_batch_ == nullptr) {
+      NotifyShutters();
+    } else {
+      NotifyBatchShutters();
+    }
     NotifyResultMetadata();
     NotifyBuffers();
 
@@ -451,18 +487,12 @@ std::string ResultDispatcher::DumpStreamKey(const StreamKey& stream_key) const {
   }
 }
 
-void ResultDispatcher::NotifyShutters() {
-  ATRACE_CALL();
-  NotifyMessage message = {};
-  // TODO: b/347771898 - Update to not depend on running faster than data is
-  // ready
-  while (true) {
-    uint32_t frame_number = 0;
-    PendingShutter pending_shutter;
-    std::lock_guard<std::mutex> lock(result_lock_);
-    if (pending_shutters_.GetReadyData(frame_number, pending_shutter) != OK) {
-      break;
-    }
+status_t ResultDispatcher::GetPendingShutterNotificationLocked(
+    NotifyMessage& message) {
+  uint32_t frame_number = 0;
+  PendingShutter pending_shutter;
+  status_t ret = pending_shutters_.GetReadyData(frame_number, pending_shutter);
+  if (ret == OK) {
     message.type = MessageType::kShutter;
     message.message.shutter.frame_number = frame_number;
     message.message.shutter.timestamp_ns = pending_shutter.timestamp_ns;
@@ -473,10 +503,43 @@ void ResultDispatcher::NotifyShutters() {
           name_.c_str(), __FUNCTION__, message.message.shutter.frame_number,
           message.message.shutter.timestamp_ns,
           message.message.shutter.readout_timestamp_ns);
+  }
+  return ret;
+}
+
+void ResultDispatcher::NotifyShutters() {
+  ATRACE_CALL();
+  NotifyMessage message = {};
+  // TODO: b/347771898 - Update to not depend on running faster than data is
+  // ready
+  while (true) {
+    std::lock_guard<std::mutex> lock(result_lock_);
+    if (GetPendingShutterNotificationLocked(message) != OK) {
+      break;
+    }
     notify_(message);
   }
 }
 
+void ResultDispatcher::NotifyBatchShutters() {
+  ATRACE_CALL();
+  std::vector<NotifyMessage> messages;
+  NotifyMessage message = {};
+  // TODO: b/347771898 - Update to not depend on running faster than data is
+  // ready
+  std::lock_guard<std::mutex> lock(result_lock_);
+  while (true) {
+    if (GetPendingShutterNotificationLocked(message) != OK) {
+      break;
+    }
+    messages.push_back(message);
+  }
+
+  if (!messages.empty()) {
+    notify_batch_(messages);
+  }
+}
+
 void ResultDispatcher::NotifyCaptureResults(
     std::vector<std::unique_ptr<CaptureResult>> results) {
   ATRACE_CALL();
diff --git a/common/hal/utils/result_dispatcher.h b/common/hal/utils/result_dispatcher.h
index 33db7a7..298a7e8 100644
--- a/common/hal/utils/result_dispatcher.h
+++ b/common/hal/utils/result_dispatcher.h
@@ -46,13 +46,15 @@ class ResultDispatcher {
   // results at once.
   // stream_config is the session stream configuration.
   // notify is the function to notify shutter messages.
+  // notify_batch is the function to notify multiple shutter messages at once.
   // If process_batch_capture_result is not null, it has the priority over
   // process_capture_result.
   static std::unique_ptr<ResultDispatcher> Create(
       uint32_t partial_result_count,
       ProcessCaptureResultFunc process_capture_result,
       ProcessBatchCaptureResultFunc process_batch_capture_result,
-      NotifyFunc notify, const StreamConfiguration& stream_config,
+      NotifyFunc notify, NotifyBatchFunc notify_batch,
+      const StreamConfiguration& stream_config,
       std::string_view name = "ResultDispatcher");
 
   virtual ~ResultDispatcher();
@@ -73,8 +75,13 @@ class ResultDispatcher {
   // Add a shutter for a frame number. If the frame number doesn't belong to a
   // pending request that was previously added via AddPendingRequest(), an error
   // will be returned.
-  status_t AddShutter(uint32_t frame_number, int64_t timestamp_ns,
-                      int64_t readout_timestamp_ns) EXCLUDES(result_lock_);
+  status_t AddShutter(const ShutterMessage& shutter) EXCLUDES(result_lock_);
+
+  // Add multiple shutters for frames.  If the frame number of any frame doesn't
+  // belong to a pending request that was previously added via
+  // AddPendingRequest(), an error will be returned.
+  status_t AddBatchShutter(const std::vector<ShutterMessage>& shutters)
+      EXCLUDES(result_lock_);
 
   // Add an error notification for a frame number. When this is called, we no
   // longer wait for a shutter message or result metadata for the given frame.
@@ -86,7 +93,8 @@ class ResultDispatcher {
   ResultDispatcher(uint32_t partial_result_count,
                    ProcessCaptureResultFunc process_capture_result,
                    ProcessBatchCaptureResultFunc process_batch_capture_result,
-                   NotifyFunc notify, const StreamConfiguration& stream_config,
+                   NotifyFunc notify, NotifyBatchFunc notify_batch,
+                   const StreamConfiguration& stream_config,
                    std::string_view name = "ResultDispatcher");
 
  private:
@@ -198,6 +206,10 @@ class ResultDispatcher {
   // callback thread.
   status_t AddResultImpl(std::unique_ptr<CaptureResult> result);
 
+  // Add a shutter to `pending_shutters_`.
+  status_t AddShutterLocked(uint32_t frame_number, int64_t timestamp_ns,
+                            int64_t readout_timestamp_ns) REQUIRES(result_lock_);
+
   // Compose a capture result which contains a result metadata.
   std::unique_ptr<CaptureResult> MakeResultMetadata(
       uint32_t frame_number, std::unique_ptr<HalCameraMetadata> metadata,
@@ -219,6 +231,9 @@ class ResultDispatcher {
   // Check all pending shutters and invoke notify_ with shutters that are ready.
   void NotifyShutters() EXCLUDES(result_lock_);
 
+  // Check all pending shutters and invoke notify_batch_ with shutters that are ready.
+  void NotifyBatchShutters() EXCLUDES(result_lock_);
+
   // Check all pending result metadata and invoke the capture result callback
   // with the result metadata that are ready.
   void NotifyResultMetadata() EXCLUDES(result_lock_);
@@ -242,6 +257,10 @@ class ResultDispatcher {
   void InitializeGroupStreamIdsMap(const StreamConfiguration& stream_config)
       EXCLUDES(result_lock_);
 
+  // Gets the shutter data  from `pending_shutters_`, and fills out `message` with it.
+  status_t GetPendingShutterNotificationLocked(NotifyMessage& message)
+      REQUIRES(result_lock_);
+
   // Name used for debugging purpose to disambiguate multiple ResultDispatchers.
   std::string name_;
 
@@ -276,6 +295,7 @@ class ResultDispatcher {
   ProcessCaptureResultFunc process_capture_result_;
   ProcessBatchCaptureResultFunc process_batch_capture_result_;
   NotifyFunc notify_;
+  NotifyBatchFunc notify_batch_;
 
   // A thread to run NotifyCallbackThreadLoop().
   std::thread notify_callback_thread_;
diff --git a/common/hal/utils/stream_buffer_cache_manager.cc b/common/hal/utils/stream_buffer_cache_manager.cc
index 7468046..c2f0e65 100644
--- a/common/hal/utils/stream_buffer_cache_manager.cc
+++ b/common/hal/utils/stream_buffer_cache_manager.cc
@@ -14,10 +14,12 @@
  * limitations under the License.
  */
 
-//#define LOG_NDEBUG 0
+// #define LOG_NDEBUG 0
 #define LOG_TAG "StreamBufferCacheManager"
 #define ATRACE_TAG ATRACE_TAG_CAMERA
 
+#include "stream_buffer_cache_manager.h"
+
 #include <cutils/native_handle.h>
 #include <cutils/properties.h>
 #include <log/log.h>
@@ -27,7 +29,6 @@
 
 #include <chrono>
 
-#include "stream_buffer_cache_manager.h"
 #include "utils.h"
 
 using namespace std::chrono_literals;
@@ -112,8 +113,9 @@ status_t StreamBufferCacheManager::RegisterStream(
     return BAD_VALUE;
   }
 
-  if (reg_info.num_buffers_to_cache != 1) {
-    ALOGE("%s: Only support caching one buffer.", __FUNCTION__);
+  if (reg_info.num_buffers_to_cache < 1) {
+    ALOGE("%s: Number of buffers must be one at least, but got %u",
+          __FUNCTION__, reg_info.num_buffers_to_cache);
     return BAD_VALUE;
   }
 
@@ -551,13 +553,13 @@ status_t StreamBufferCacheManager::StreamBufferCache::Refill() {
 }
 
 bool StreamBufferCacheManager::StreamBufferCache::RefillableLocked() const {
-  // No need to refill if the buffer cache is not active
+  // No need to refill if the buffer cache is not active.
   if (!is_active_) {
     return false;
   }
 
-  // Need to refill if the cache is not full
-  return cached_buffers_.size() < cache_info_.num_buffers_to_cache;
+  // Need to refill if the cache is empty.
+  return cached_buffers_.empty();
 }
 
 status_t
diff --git a/common/hal/utils/zsl_result_dispatcher.cc b/common/hal/utils/zsl_result_dispatcher.cc
index 29e838a..c844e02 100644
--- a/common/hal/utils/zsl_result_dispatcher.cc
+++ b/common/hal/utils/zsl_result_dispatcher.cc
@@ -23,6 +23,7 @@
 #include <log/log.h>
 #include <utils/Trace.h>
 
+#include "hal_types.h"
 #include "utils.h"
 
 namespace android {
@@ -65,19 +66,21 @@ status_t ZslResultDispatcher::Initialize(
   notify_ = NotifyFunc(
       [this](const NotifyMessage& message) { NotifyHalMessage(message); });
 
-  normal_result_dispatcher_ = std::unique_ptr<ResultDispatcher>(
-      new ResultDispatcher(partial_result_count, process_capture_result_,
-                           /*process_batch_capture_result=*/nullptr, notify_,
-                           stream_config, "ZslNormalDispatcher"));
+  normal_result_dispatcher_ =
+      std::unique_ptr<ResultDispatcher>(new ResultDispatcher(
+          partial_result_count, process_capture_result_,
+          /*process_batch_capture_result=*/nullptr, notify_,
+          /*notify_batch=*/nullptr, stream_config, "ZslNormalDispatcher"));
   if (normal_result_dispatcher_ == nullptr) {
     ALOGE("%s: Creating normal_result_dispatcher_ failed.", __FUNCTION__);
     return BAD_VALUE;
   }
 
-  zsl_result_dispatcher_ = std::unique_ptr<ResultDispatcher>(
-      new ResultDispatcher(partial_result_count, process_capture_result_,
-                           /*process_batch_capture_result=*/nullptr, notify_,
-                           stream_config, "ZslZslDispatcher"));
+  zsl_result_dispatcher_ =
+      std::unique_ptr<ResultDispatcher>(new ResultDispatcher(
+          partial_result_count, process_capture_result_,
+          /*process_batch_capture_result=*/nullptr, notify_,
+          /*notify_batch=*/nullptr, stream_config, "ZslZslDispatcher"));
   if (zsl_result_dispatcher_ == nullptr) {
     ALOGE("%s: Creating zsl_result_dispatcher_ failed.", __FUNCTION__);
     return BAD_VALUE;
@@ -146,17 +149,13 @@ status_t ZslResultDispatcher::AddResult(std::unique_ptr<CaptureResult> result) {
   }
 }
 
-status_t ZslResultDispatcher::AddShutter(uint32_t frame_number,
-                                         int64_t timestamp_ns,
-                                         int64_t readout_timestamp_ns) {
+status_t ZslResultDispatcher::AddShutter(const ShutterMessage& shutter) {
   ATRACE_CALL();
-  bool is_zsl_request = IsZslFrame(frame_number);
+  bool is_zsl_request = IsZslFrame(shutter.frame_number);
   if (is_zsl_request) {
-    return zsl_result_dispatcher_->AddShutter(frame_number, timestamp_ns,
-                                              readout_timestamp_ns);
+    return zsl_result_dispatcher_->AddShutter(shutter);
   } else {
-    return normal_result_dispatcher_->AddShutter(frame_number, timestamp_ns,
-                                                 readout_timestamp_ns);
+    return normal_result_dispatcher_->AddShutter(shutter);
   }
 }
 
diff --git a/common/hal/utils/zsl_result_dispatcher.h b/common/hal/utils/zsl_result_dispatcher.h
index f75e216..499103a 100644
--- a/common/hal/utils/zsl_result_dispatcher.h
+++ b/common/hal/utils/zsl_result_dispatcher.h
@@ -65,8 +65,7 @@ class ZslResultDispatcher {
   // Add a shutter for a frame number. If the frame number doesn't belong to a
   // pending request that was previously added via AddPendingRequest(), an error
   // will be returned.
-  status_t AddShutter(uint32_t frame_number, int64_t timestamp_ns,
-                      int64_t readout_timestamp_ns);
+  status_t AddShutter(const ShutterMessage& shutter);
 
   // Add an error notification for a frame number. When this is called, we no
   // longer wait for a shutter message or result metadata for the given frame.
diff --git a/devices/EmulatedCamera/hwl/configs/emu_camera_back.json b/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
index 00b9974..f1d456c 100644
--- a/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
+++ b/devices/EmulatedCamera/hwl/configs/emu_camera_back.json
@@ -135,24 +135,6 @@
   "240",
   "OUTPUT"
  ],
- "android.depth.availableDynamicDepthMinFrameDurations": [
-  "33",
-  "320",
-  "240",
-  "50000000"
- ],
- "android.depth.availableDynamicDepthStallDurations": [
-  "33",
-  "320",
-  "240",
-  "50000000"
- ],
- "android.depth.availableDynamicDepthStreamConfigurations" : [
-  "33",
-  "320",
-  "240",
-  "OUTPUT"
- ],
  "android.depth.depthIsExclusive": [
   "FALSE"
  ],
@@ -428,7 +410,11 @@
   "524298",
   "524300",
   "524295",
-  "524301"
+  "524301",
+  "1638401",
+  "1638402",
+  "1638403",
+  "1638404"
  ],
  "android.request.availableRequestKeys": [
   "65596",
diff --git a/devices/EmulatedCamera/hwl/configs/emu_camera_front.json b/devices/EmulatedCamera/hwl/configs/emu_camera_front.json
index 9edf76b..7d30888 100644
--- a/devices/EmulatedCamera/hwl/configs/emu_camera_front.json
+++ b/devices/EmulatedCamera/hwl/configs/emu_camera_front.json
@@ -572,7 +572,8 @@
    "1441792",
    "851985",
    "917536",
-   "2097152"
+   "2097152",
+   "2293760"
   ],
   "android.request.availableResultKeys": [
    "0",
@@ -653,7 +654,8 @@
    "1703938",
    "917530",
    "851985",
-   "917536"
+   "917536",
+   "2293760"
   ],
   "android.request.maxNumOutputStreams": [
    "1",
@@ -4556,6 +4558,16 @@
   ],
   "android.tonemap.maxCurvePoints": [
    "64"
+  ],
+  "android.visualEffect.capabilities": [
+   "BACKGROUND_BLUR",
+   "FACE_RETOUCH",
+   "PORTRAIT_RELIGHT"
+  ],
+  "android.visualEffect.backgroundBlurModes": [
+    "0",
+    "1",
+    "2"
   ]
  }
 ]
```

